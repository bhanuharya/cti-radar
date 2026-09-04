//! OpenHack mutation handlers — opt-in config + fail-closed active scan trigger.
//! Port of the OpenHack endpoints in main.py.

use crate::correlation as cc;
use crate::error::{AppError, AppResult};
use crate::handlers::require_org;
use crate::handlers_mut::job_busy_error;
use crate::AppState;
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::Json;
use serde_json::{json, Value};

#[derive(serde::Deserialize)]
pub struct OpenhackConfigBody {
    pub enabled: Option<bool>,
    pub model: Option<String>,
}

fn valid_model_id(model: &str) -> bool {
    !model.is_empty()
        && model.len() <= 64
        && model
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '/' || c == '_')
}

pub async fn api_openhack_config(
    State(_s): State<AppState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
    Json(body): Json<OpenhackConfigBody>,
) -> AppResult<Json<Value>> {
    require_org(&slug, &headers)?;
    let model = body.model.clone().unwrap_or_default().trim().to_string();
    if !model.is_empty() && !valid_model_id(&model) {
        return Err(AppError::BadRequest("invalid model id".into()));
    }
    let enabled = body.enabled;

    // load registry, mutate the entry, persist
    let mut registry = crate::handlers_mut::load_registry_map()?;
    let entry = registry
        .get_mut(&slug)
        .ok_or_else(|| AppError::OrgNotFound(slug.clone()))?;
    let entry_obj = entry
        .as_object_mut()
        .ok_or_else(|| AppError::OrgNotFound(slug.clone()))?;
    if let Some(en) = enabled {
        if en {
            entry_obj.insert("openhack_enabled".to_string(), Value::Bool(true));
        } else {
            entry_obj.remove("openhack_enabled");
        }
    }
    if !model.is_empty() {
        entry_obj.insert("openhack_model".to_string(), Value::String(model.clone()));
    } else if body.model.is_some() {
        entry_obj.remove("openhack_model");
    }
    // capture what was written BEFORE the move (a re-read can hit a stale cache)
    let written_enabled = entry_obj
        .get("openhack_enabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let written_model = entry_obj
        .get("openhack_model")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let path = cc::cfg_path_orgs_json();
    cc::atomic_write_json(&path, &Value::Object(registry)).map_err(AppError::from)?;
    cc::reload_registry();

    crate::logs::log_event(
        "info",
        "system",
        &slug,
        &format!(
            "openhack config updated (enabled={}, model={})",
            written_enabled,
            if written_model.is_empty() { "default" } else { &written_model }
        ),
        None,
    );
    Ok(Json(
        json!({"slug": slug, "openhack_enabled": written_enabled, "openhack_model": written_model}),
    ))
}

#[derive(serde::Deserialize)]
pub struct OpenhackScanBody {
    pub mode: Option<String>,
    pub model: Option<String>,
}

pub async fn api_openhack_scan(
    State(_s): State<AppState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
    body: Option<Json<OpenhackScanBody>>,
) -> AppResult<Json<Value>> {
    let body = body.map(|b| b.0);
    let mode = body
        .as_ref()
        .and_then(|b| b.mode.clone())
        .unwrap_or_else(|| "quick".to_string());
    let model = body
        .as_ref()
        .and_then(|b| b.model.clone())
        .unwrap_or_default()
        .trim()
        .to_string();
    if !model.is_empty() && !valid_model_id(&model) {
        return Err(AppError::BadRequest("invalid model id".into()));
    }

    let org = require_org(&slug, &headers)?;

    // Gates mirror Python: opt-in 403, authorization 403, binary 503.
    if org.get("openhack_enabled").and_then(|v| v.as_bool()) != Some(true) {
        return Err(AppError::Forbidden(format!(
            "openhack source not enabled for this org — POST /api/orgs/{}/openhack-config {{\"enabled\": true}}",
            slug
        )));
    }
    if let Some(err) = crate::openhack::authorization_error(&org) {
        return Err(AppError::Forbidden(format!(
            "OpenHack active assessment authorization denied: {}",
            err
        )));
    }
    if crate::openhack::openhack_bin().is_none() {
        return Err(AppError::ServiceUnavailable(
            "openhack binary not available (set explicit absolute CTI_OPENHACK_BIN)".into(),
        ));
    }

    // job kind is "ohack" internally (mirrors Python `_try_acquire_job(slug, "ohack")`)
    let (ok, jid) = crate::jobs::try_acquire_job(&slug, "ohack");
    if !ok {
        return Err(job_busy_error(&slug, "openhack-scan", jid));
    }
    let jid = jid.unwrap();
    let domains: Vec<String> = org
        .get("domains")
        .and_then(|d| d.as_array())
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|v| v.as_str().map(|s| s.to_string()))
        .collect();
    crate::logs::log_event(
        "info",
        "openhack",
        &slug,
        &format!("openHack {} queued ({} domain(s))", mode, domains.len()),
        Some(&jid),
    );

    let (slug2, jid2, domains2, mode2) =
        (slug.clone(), jid.clone(), domains, mode.clone());
    tokio::spawn(async move {
        match crate::openhack::run_assessment(&slug2, &domains2).await {
            Some(result) => {
                let added = result.get("added").and_then(|v| v.as_u64()).unwrap_or(0);
                let graded = result.get("graded").and_then(|v| v.as_u64()).unwrap_or(0);
                crate::jobs::release_job(&slug2, "ohack", &jid2, None, None);
                crate::logs::log_event(
                    "info",
                    "openhack",
                    &slug2,
                    &format!(
                        "openHack {} done (+{} new, {} graded)",
                        mode2, added, graded
                    ),
                    Some(&jid2),
                );
            }
            None => {
                crate::jobs::release_job(
                    &slug2,
                    "ohack",
                    &jid2,
                    Some("openHack assessment failed".to_string()),
                    None,
                );
                crate::logs::log_event(
                    "error",
                    "openhack",
                    &slug2,
                    "openHack failed",
                    Some(&jid2),
                );
            }
        }
    });

    Ok(Json(
        json!({"queued": true, "slug": slug, "mode": mode, "job_id": jid}),
    ))
}

pub async fn api_openhack_status(
    State(_s): State<AppState>,
    Path((slug, job_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> AppResult<Json<Value>> {
    require_org(&slug, &headers)?;
    Ok(Json(crate::jobs::job_status(
        &slug, "ohack", &job_id,
    )?))
}
