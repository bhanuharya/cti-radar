//! OpenHack mutation handlers — opt-in config + fail-closed active scan trigger.
//! Port of the OpenHack endpoints in main.py.

use crate::correlation as cc;
use crate::error::{AppError, AppResult};
use crate::handlers::require_org;
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
    let mut registry = crate::handlers_mut::load_registry_map();
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
        entry_obj.insert("openhack_model".to_string(), Value::String(model));
    } else if body.model.is_some() {
        entry_obj.remove("openhack_model");
    }
    let path = cc::cfg_path_orgs_json();
    cc::atomic_write_json(&path, &Value::Object(registry)).map_err(AppError::from)?;
    cc::reload_registry();

    Ok(Json(
        json!({"org": slug, "openhack_enabled": enabled, "openhack_model": body.model}),
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
    Json(_body): Json<OpenhackScanBody>,
) -> AppResult<Json<Value>> {
    let org = require_org(&slug, &headers)?;

    // Fail-closed server-level authorization (exact allowlist + ROE + isolation).
    if let Some(err) = crate::openhack::authorization_error(&org) {
        return Err(AppError::BadRequest(err));
    }
    // org must be opted in
    if org.get("openhack_enabled").and_then(|v| v.as_bool()) != Some(true) {
        return Err(AppError::BadRequest(
            "organization is not opted in to OpenHack".into(),
        ));
    }

    let (ok, jid) = crate::jobs::try_acquire_job(&slug, "openhack");
    if !ok {
        return Err(AppError::Conflict("openhack scan already running".into()));
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

    let (slug2, jid2, domains2) = (slug.clone(), jid.clone(), domains);
    tokio::spawn(async move {
        let _ = crate::openhack::run_assessment(&slug2, &domains2).await;
        crate::jobs::release_job(
            &slug2,
            "openhack",
            &jid2,
            None,
            Some(json!({"queued": true})),
        );
    });

    Ok(Json(json!({"queued": true, "slug": slug, "job_id": jid})))
}

pub async fn api_openhack_status(
    State(_s): State<AppState>,
    Path((slug, job_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> AppResult<Json<Value>> {
    require_org(&slug, &headers)?;
    let running = crate::jobs::is_job_running(&slug, "openhack");
    Ok(Json(crate::jobs::job_status(
        &slug, "openhack", &job_id, running,
    )))
}
