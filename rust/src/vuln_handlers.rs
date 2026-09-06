//! Vulnerability lookup HTTP handlers.

use crate::error::{AppError, AppResult};
use crate::handlers::require_org;
use crate::handlers_mut::job_busy_error;
use crate::vuln_scan;
use crate::AppState;
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::Json;
use serde_json::{json, Value};

#[derive(serde::Deserialize, Default)]
pub struct VulnScanBody {
    pub engine: Option<String>,
    pub targets: Option<Vec<String>>,
    pub checks: Option<Vec<String>>,
    pub severity: Option<Vec<String>>,
    pub tags: Option<Vec<String>>,
    /// Python-parity aliases for the Nuclei-specific filters.
    pub nuclei_severity: Option<Vec<String>>,
    pub nuclei_tags: Option<Vec<String>>,
    pub refresh: Option<bool>,
    pub include_nvd: Option<bool>,
    pub active: Option<bool>,
}

pub async fn api_vuln_engines(headers: HeaderMap) -> AppResult<Json<Value>> {
    crate::auth::require_auth(&headers)?;
    let gate = vuln_scan::active_gate_from_env();
    // Status reports a generic reason only — gate specifics (ROE expiry,
    // domain scope shape) would disclose authorization state to any session.
    // The specific denial is still returned when a nuclei job is attempted.
    let (nuclei_available, nuclei_reason) =
        if vuln_scan::active_gate_setup_error(&gate, chrono::Utc::now()).is_some() {
            (false, "active engine disabled by configuration".to_string())
        } else {
            match vuln_scan::nuclei_runtime_from_env() {
                Ok(_) => (
                    true,
                    "authorized runtime configured; organization scope is checked per request"
                        .to_string(),
                ),
                Err(_) => (
                    false,
                    "active engine disabled: runner runtime not configured".to_string(),
                ),
            }
        };
    Ok(Json(json!({
        "passive": {
            "available": true,
            "active": false,
            "checks": vuln_scan::VALID_CHECKS,
            "note": "stored-fingerprint lookup only; no fresh network activity",
        },
        "nuclei": {
            "available": nuclei_available,
            "active": true,
            "reason": nuclei_reason,
            "severity": vuln_scan::DEFAULT_NUCLEI_SEVERITY,
        },
    })))
}

pub async fn api_org_vuln_scan(
    State(_state): State<AppState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
    body: Option<Json<VulnScanBody>>,
) -> AppResult<Json<Value>> {
    let org = require_org(&slug, &headers)?;
    let body = body.map(|value| value.0).unwrap_or_default();
    let engine = body.engine.as_deref().unwrap_or("passive");
    if body.severity.is_some() && body.nuclei_severity.is_some() {
        return Err(AppError::BadRequest(
            "provide only one of severity or nuclei_severity".to_string(),
        ));
    }
    if body.tags.is_some() && body.nuclei_tags.is_some() {
        return Err(AppError::BadRequest(
            "provide only one of tags or nuclei_tags".to_string(),
        ));
    }
    let severity_input = body.nuclei_severity.as_deref().or(body.severity.as_deref());
    let tags_input = body.nuclei_tags.as_deref().or(body.tags.as_deref());
    let options = vuln_scan::normalize_request_options(engine, severity_input, tags_input)
        .map_err(AppError::BadRequest)?;
    let request =
        vuln_scan::validate_passive_request(body.targets.as_deref(), body.checks.as_deref())
            .map_err(AppError::BadRequest)?;
    // Nuclei is active: authorization is deliberately before *any* binary or
    // templates lookup. Scope is checked again inside the background runner.
    if options.engine == "nuclei" {
        let gate = vuln_scan::active_gate_from_env();
        if let Some(error) = vuln_scan::authorization_error(&gate, &org, chrono::Utc::now()) {
            return Err(AppError::Forbidden(format!(
                "nuclei engine denied: {error}"
            )));
        }
        let runtime = vuln_scan::nuclei_runtime_from_env().map_err(AppError::ServiceUnavailable)?;
        let (_, cached) = vuln_scan::load_findings_document(&slug)
            .await
            .map_err(AppError::Internal)?;
        let targets = vuln_scan::active_nuclei_targets(&org, &cached, &request.targets)
            .map_err(AppError::BadRequest)?;
        let severity = if severity_input.is_some_and(|values| !values.is_empty()) {
            options.severity
        } else {
            runtime.severity.clone()
        };
        let tags = if tags_input.is_some_and(|values| !values.is_empty()) {
            options.tags
        } else {
            runtime.tags.clone()
        };
        let (ok, job_id) = crate::jobs::try_acquire_job(&slug, "vuln-scan");
        if !ok {
            return Err(job_busy_error(&slug, "vuln-scan", job_id));
        }
        let job_id = job_id.expect("job id on successful acquisition");
        crate::logs::log_event(
            "info",
            "vuln-scan",
            &slug,
            "Nuclei active run queued",
            Some(&job_id),
        )
        .await;
        let (slug2, job2, org2) = (slug.clone(), job_id.clone(), org.clone());
        tokio::spawn(async move {
            match vuln_scan::run_active_nuclei_lookup(
                &slug2, &org2, runtime, targets, severity, tags,
            )
            .await
            {
                Ok(result) => {
                    crate::jobs::release_job(&slug2, "vuln-scan", &job2, None, Some(result));
                    crate::logs::log_event(
                        "info",
                        "vuln-scan",
                        &slug2,
                        "Nuclei active run completed",
                        Some(&job2),
                    )
                    .await;
                }
                Err(error) => {
                    crate::jobs::release_job(&slug2, "vuln-scan", &job2, Some(error.clone()), None);
                    crate::logs::log_event("error", "vuln-scan", &slug2, &error, Some(&job2)).await;
                }
            }
        });
        return Ok(Json(
            json!({"queued": true, "slug": slug, "job_id": job_id, "engine": "nuclei"}),
        ));
    }
    let _ = (body.refresh, body.include_nvd, body.active);
    let (ok, job_id) = crate::jobs::try_acquire_job(&slug, "vuln-scan");
    if !ok {
        return Err(job_busy_error(&slug, "vuln-scan", job_id));
    }
    let job_id = job_id.expect("job id on successful acquisition");
    crate::logs::log_event(
        "info",
        "vuln-scan",
        &slug,
        "passive vulnerability lookup queued",
        Some(&job_id),
    )
    .await;
    let (slug2, job2, org2) = (slug.clone(), job_id.clone(), org.clone());
    tokio::spawn(async move {
        match vuln_scan::run_passive_lookup(&slug2, &org2, request).await {
            Ok(result) => {
                crate::jobs::release_job(&slug2, "vuln-scan", &job2, None, Some(result));
                crate::logs::log_event(
                    "info",
                    "vuln-scan",
                    &slug2,
                    "passive vulnerability lookup completed",
                    Some(&job2),
                )
                .await;
            }
            Err(error) => {
                crate::jobs::release_job(&slug2, "vuln-scan", &job2, Some(error.clone()), None);
                crate::logs::log_event("error", "vuln-scan", &slug2, &error, Some(&job2)).await;
            }
        }
    });
    Ok(Json(json!({
        "queued": true,
        "slug": slug,
        "job_id": job_id,
        "engine": "passive",
    })))
}

pub async fn api_vuln_scan_status(
    State(_state): State<AppState>,
    Path((slug, job_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> AppResult<Json<Value>> {
    require_org(&slug, &headers)?;
    Ok(Json(crate::jobs::job_status(&slug, "vuln-scan", &job_id)?))
}
