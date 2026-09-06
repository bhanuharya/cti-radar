//! Vuln-scan HTTP handlers — host-based lookup (passive default, active gated).
//! Port of the `/vuln-scan` endpoints in main.py.

use crate::error::{AppError, AppResult};
use crate::handlers::require_org;
use crate::vuln_scan::{self, VulnOptions};
use crate::AppState;
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::Json;
use serde_json::{json, Value};
use std::sync::Arc;

#[derive(serde::Deserialize, Default)]
pub struct VulnScanBody {
    #[serde(default)]
    pub targets: Vec<String>,
    #[serde(default)]
    pub checks: Vec<String>,
    #[serde(default = "default_true")]
    pub refresh: bool,
    #[serde(default)]
    pub include_nvd: bool,
    #[serde(default)]
    pub active: bool,
    #[serde(default)]
    pub engine: String,
    #[serde(default)]
    pub nuclei_severity: Vec<String>,
    #[serde(default)]
    pub nuclei_tags: Vec<String>,
}

fn default_true() -> bool {
    true
}

pub async fn api_vuln_engines(
    State(_s): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<Value>> {
    crate::auth::require_auth(&headers)?;
    Ok(Json(json!({
        "passive": {"available": true, "checks": ["cve", "version", "headers", "tls", "login"]},
        "nuclei": crate::nuclei::engine_status(),
    })))
}

pub async fn api_org_vuln_scan(
    State(_s): State<AppState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
    Json(body): Json<VulnScanBody>,
) -> AppResult<Json<Value>> {
    let org = require_org(&slug, &headers)?;
    let engine = if body.engine.trim().is_empty() {
        "passive".to_string()
    } else {
        body.engine.trim().to_lowercase()
    };
    if engine != "passive" && engine != "nuclei" {
        return Err(AppError::BadRequest("invalid engine (passive|nuclei)".into()));
    }
    // Fail-closed gate BEFORE acquiring a job or spawning anything: no
    // subprocess, no network, when the authorization is absent.
    if body.active || engine == "nuclei" {
        let mut orgv = org.clone();
        orgv["slug"] = json!(slug);
        if let Some(gate) = vuln_scan::authorization_error(&orgv) {
            return Err(AppError::Forbidden(format!(
                "active assessment denied: {}",
                gate
            )));
        }
    }
    if engine == "nuclei" {
        let sev = if body.nuclei_severity.is_empty() {
            None
        } else {
            Some(body.nuclei_severity.as_slice())
        };
        let tags = if body.nuclei_tags.is_empty() {
            None
        } else {
            Some(body.nuclei_tags.as_slice())
        };
        if let Err(e) = crate::nuclei::normalize_options(sev, tags) {
            return Err(AppError::BadRequest(e));
        }
        let st = crate::nuclei::engine_status();
        if st.get("available").and_then(|v| v.as_bool()) != Some(true) {
            let reason = st.get("reason").and_then(|v| v.as_str()).unwrap_or("unknown");
            return Err(AppError::Internal(format!(
                "nuclei engine unavailable: {}",
                reason
            )));
        }
    }

    let (ok, jid) = crate::jobs::try_acquire_job(&slug, "vuln");
    if !ok {
        return Err(AppError::Conflict("vuln lookup already running".into()));
    }
    let jid = jid.unwrap();
    let targets: Vec<String> = body
        .targets
        .into_iter()
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
        .take(20)
        .collect();
    let checks: Vec<String> = body
        .checks
        .into_iter()
        .map(|c| c.trim().to_lowercase())
        .take(10)
        .collect();
    let (refresh, include_nvd, active) = (body.refresh, body.include_nvd, body.active);
    let (nuc_sev, nuc_tags) = (body.nuclei_severity, body.nuclei_tags);
    let resp_checks = checks.clone();
    let resp_active = active;

    let (slug2, jid2, engine2) = (slug.clone(), jid.clone(), engine.clone());
    let (slug_pb, jid_pb) = (slug2.clone(), jid2.clone());
    tokio::spawn(async move {
        let opts = VulnOptions {
            targets: if targets.is_empty() { None } else { Some(targets) },
            checks: if checks.is_empty() { None } else { Some(checks) },
            refresh,
            include_nvd,
            active,
            engine: engine2,
            nuclei_severity: if nuc_sev.is_empty() { None } else { Some(nuc_sev) },
            nuclei_tags: if nuc_tags.is_empty() { None } else { Some(nuc_tags) },
            on_progress: Some(Arc::new(move |stage: String, msg: String| {
                crate::jobs::job_progress(&slug_pb, "vuln", &jid_pb, &stage, &msg);
            })),
        };
        let result = vuln_scan::vuln_scan_org(&slug2, opts).await;
        if let Some(err) = result.get("error").and_then(|v| v.as_str()) {
            // mirror structured failure: surface as a failed job with context
            crate::jobs::release_job(
                &slug2,
                "vuln",
                &jid2,
                Some(err.to_string()),
                Some(result),
            );
        } else {
            crate::jobs::release_job(&slug2, "vuln", &jid2, None, Some(result));
        }
    });

    Ok(Json(json!({
        "queued": true, "slug": slug, "job_id": jid,
        "checks": resp_checks,
        "engine": engine, "active": resp_active,
    })))
}

pub async fn api_vuln_status(
    State(_s): State<AppState>,
    Path((slug, job_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> AppResult<Json<Value>> {
    require_org(&slug, &headers)?;
    let running = crate::jobs::is_job_running(&slug, "vuln");
    Ok(Json(crate::jobs::job_status(
        &slug, "vuln", &job_id, running,
    )))
}
