//! Mutation handlers — register, scan, correlate, recheck, status, comment.
//! Appended to handlers.rs (module-level `use` shared from the same file).

use crate::correlation as cc;
use crate::error::{AppError, AppResult};
use crate::handlers::{require_org, valid_slug};
use crate::AppState;
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::Json;
use serde_json::{json, Map, Value};
use std::collections::HashMap;

#[derive(serde::Deserialize)]
pub struct RegisterBody {
    pub slug: String,
    pub name: Option<String>,
    pub domains: Option<Vec<String>>,
    pub ai_profile: Option<String>,
}

fn is_valid_domain(d: &str) -> bool {
    let d = d.trim().to_lowercase();
    if d.is_empty() || d.len() > 253 {
        return false;
    }
    d.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
            && !label.starts_with('-')
            && !label.ends_with('-')
    })
}

pub async fn api_org_register(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<RegisterBody>,
) -> AppResult<Json<Value>> {
    crate::auth::require_auth(&headers)?;
    let slug = body.slug.trim().to_string();
    if !valid_slug(&slug) {
        return Err(AppError::BadRequest(
            "invalid slug (^[a-z0-9-]{1,32}$)".into(),
        ));
    }
    if cc::org_get(&slug).is_some() {
        return Err(AppError::Conflict {
            error: "org already registered".into(),
            slug: Some(slug.clone()),
        });
    }
    let raw_name = body.name.unwrap_or_default();
    let name = {
        let t = raw_name.trim();
        if t.is_empty() {
            slug.clone()
        } else {
            t.to_string()
        }
    };
    if name.len() > 200 {
        return Err(AppError::BadRequest("name too long (max 200 chars)".into()));
    }
    let domains_in: Vec<String> = body.domains.unwrap_or_default();
    let valid_domains: Vec<String> = dedup(
        domains_in
            .iter()
            .map(|d| d.trim().to_lowercase().trim_end_matches('.').to_string())
            .filter(|d| is_valid_domain(d))
            .collect(),
    );
    if valid_domains.len() > 20 {
        return Err(AppError::BadRequest("too many domains (max 20)".into()));
    }
    if !domains_in.is_empty() && valid_domains.is_empty() {
        return Err(AppError::BadRequest(
            "no valid domains (strict DNS name required)".into(),
        ));
    }
    // validate ai_profile before any filesystem mutation
    let ai_profile = body.ai_profile.unwrap_or_default().trim().to_string();
    let (profiles, _) = crate::ai::load_profiles().await;
    if !ai_profile.is_empty() && !profiles.contains_key(&ai_profile) {
        return Err(invalid_profile_error(&profiles));
    }

    // locked registry read-check-write (re-check slug: concurrent
    // registrations must not lose each other)
    let mut registry = load_registry_map()?;
    if registry.contains_key(&slug) {
        return Err(AppError::Conflict {
            error: "org already registered".into(),
            slug: Some(slug.clone()),
        });
    }
    registry.insert(
        slug.clone(),
        json!({
            "name": name,
            "domains": valid_domains,
            "findings": format!("data/orgs/{}/findings.json", slug),
            "baseline": format!("data/orgs/{}/baseline.txt", slug),
        }),
    );
    save_registry_map(&registry, &state).await?;
    cc::reload_registry();

    // filesystem creation after successful registry commit (best-effort;
    // atomic writers create 0700 dirs / 0600 files)
    let org_dir = state.cfg.org_dir(&slug);
    let _ = cc::atomic_write_text(&org_dir.join("baseline.txt"), "").await;
    let _ = cc::atomic_write_json(&org_dir.join("findings.json"), &json!({"findings": []})).await;
    cc::invalidate_org_cache(&slug);
    if !ai_profile.is_empty() {
        crate::ai::set_org_profile(&slug, &ai_profile).await;
    }
    crate::logs::log_event(
        "info",
        "system",
        &slug,
        &format!(
            "workspace registered ({}, {} domain(s))",
            name,
            valid_domains.len()
        ),
        None,
    ).await;
    Ok(Json(json!({
        "slug": slug,
        "name": name,
        "domains": valid_domains,
        "ai_profile": if ai_profile.is_empty() { Value::Null } else { Value::String(ai_profile) },
    })))
}

/// 400 `{"error": "invalid ai_profile", "allowed": [...]}` (parity with Python).
pub(crate) fn invalid_profile_error(profiles: &HashMap<String, Value>) -> AppError {
    let mut allowed: Vec<String> = profiles.keys().cloned().collect();
    allowed.sort();
    let mut extra = Map::new();
    extra.insert("allowed".to_string(), json!(allowed));
    AppError::BadRequestExtra {
        error: "invalid ai_profile".into(),
        extra,
    }
}

/// Read the registry file. A corrupt or non-object registry fails closed
/// (500) instead of being silently overwritten (parity with Python).
pub fn load_registry_map() -> AppResult<Map<String, Value>> {
    let path = crate::correlation::cfg_path_orgs_json();
    match std::fs::read_to_string(&path) {
        Ok(txt) => match serde_json::from_str::<Value>(&txt) {
            Ok(Value::Object(m)) => Ok(m),
            _ => Err(AppError::Internal("registry corrupted, aborting".into())),
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Map::new()),
        Err(e) => Err(AppError::from(e)),
    }
}

async fn save_registry_map(registry: &Map<String, Value>, state: &AppState) -> AppResult<()> {
    let path = state.cfg.orgs_json();
    crate::correlation::atomic_write_json(&path, &Value::Object(registry.clone()))
        .await
        .map_err(AppError::from)
}

#[derive(serde::Deserialize, Default)]
pub struct ScanBody {
    pub mode: Option<String>,
    pub ai_profile: Option<String>,
}

/// Map a failed job acquisition to its error: 409 when this org owns the
/// running job, 429 when the global active-job cap is hit (mirrors Python
/// `_job_busy_response`).
pub(crate) fn job_busy_error(slug: &str, kind: &str, jid: Option<String>) -> AppError {
    match jid {
        Some(id) => AppError::Busy {
            error: format!("{} already running", kind),
            slug: slug.to_string(),
            job_id: Some(id),
        },
        None => AppError::Busy {
            error: format!(
                "{} rejected: server busy (max {} active jobs)",
                kind,
                crate::jobs::max_active_jobs()
            ),
            slug: slug.to_string(),
            job_id: None,
        },
    }
}

pub async fn api_org_scan(
    State(_state): State<AppState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
    body: Option<Json<ScanBody>>,
) -> AppResult<Json<Value>> {
    let org = require_org(&slug, &headers)?;
    let body = body.map(|b| b.0).unwrap_or_default();
    let mode = if body.mode.as_deref() == Some("ai") {
        "ai"
    } else {
        "fast"
    };
    // resolve ai_profile: request override > org's stored preference > default
    let ai_profile_req = body.ai_profile.clone().unwrap_or_default().trim().to_string();
    let (profiles, _) = crate::ai::load_profiles().await;
    if !ai_profile_req.is_empty() && !profiles.contains_key(&ai_profile_req) {
        return Err(invalid_profile_error(&profiles));
    }
    // AI fallback: deterministic scan always queues; a requested-but-unready
    // profile degrades silently (cron compatibility, mirrors Python).
    let req_opt = if ai_profile_req.is_empty() {
        None
    } else {
        Some(ai_profile_req.clone())
    };
    let effective = crate::ai::effective_ready_profile(&slug, req_opt.as_deref()).await;
    let _ = org;
    let (ok, jid) = crate::jobs::try_acquire_job(&slug, "scan");
    if !ok {
        return Err(job_busy_error(&slug, "scan", jid));
    }
    let jid = jid.unwrap();
    if mode == "ai" && effective.is_none() {
        crate::logs::log_event(
            "warn",
            "scan",
            &slug,
            "AI mode requested but no ready profile — falling back to deterministic scan",
            Some(&jid),
        ).await;
    }
    crate::logs::log_event(
        "info",
        "scan",
        &slug,
        &format!(
            "scan queued (mode={}, ai_profile={})",
            mode,
            effective.as_deref().unwrap_or("auto")
        ),
        Some(&jid),
    ).await;
    // pass the resolved-or-requested profile through (mirrors Python
    // `ai_profile=effective_profile or ai_profile_req`)
    let pass_profile = effective.clone().or(req_opt);
    let (slug2, jid2, mode2) = (slug.clone(), jid.clone(), mode.to_string());
    tokio::spawn(async move {
        let mut org_val = cc::org_get(&slug2).unwrap_or_else(|| json!({}));
        if let Value::Object(map) = &mut org_val {
            map.insert("slug".to_string(), Value::String(slug2.clone()));
        }
        let result = crate::scanner::generate_org(org_val, &mode2, pass_profile, None).await;
        // fatal scan failures surface an "error" key instead of raising
        let err_msg = result
            .get("error")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        if let Some(err) = err_msg {
            crate::jobs::release_job(&slug2, "scan", &jid2, Some(err.to_string()), Some(result));
            crate::logs::log_event(
                "error",
                "scan",
                &slug2,
                &format!("scan failed: {}", err),
                Some(&jid2),
            ).await;
        } else {
            crate::jobs::release_job(&slug2, "scan", &jid2, None, Some(result));
            crate::logs::log_event("info", "scan", &slug2, "scan completed", Some(&jid2)).await;
        }
    });
    Ok(Json(json!({
        "queued": true,
        "slug": slug,
        "mode": mode,
        "ai_profile": effective.map(Value::String).unwrap_or(Value::Null),
        "job_id": jid,
    })))
}

pub async fn api_scan_status(
    State(_s): State<AppState>,
    Path((slug, job_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> AppResult<Json<Value>> {
    require_org(&slug, &headers)?;
    Ok(Json(crate::jobs::job_status(&slug, "scan", &job_id)?))
}

pub async fn api_org_recheck(
    State(_s): State<AppState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
) -> AppResult<Json<Value>> {
    require_org(&slug, &headers)?;
    let (ok, jid) = crate::jobs::try_acquire_job(&slug, "recheck");
    if !ok {
        return Err(job_busy_error(&slug, "recheck", jid));
    }
    let jid = jid.unwrap();
    crate::logs::log_event("info", "recheck", &slug, "recheck queued", Some(&jid)).await;
    let (slug2, jid2) = (slug.clone(), jid.clone());
    tokio::spawn(async move {
        let changed = crate::scanner::recheck_findings(&slug2, 200).await;
        crate::jobs::release_job(
            &slug2,
            "recheck",
            &jid2,
            None,
            Some(json!({"changed": changed})),
        );
        crate::logs::log_event(
            "info",
            "recheck",
            &slug2,
            &format!("recheck completed ({} change(s))", changed),
            Some(&jid2),
        ).await;
    });
    Ok(Json(json!({"queued": true, "slug": slug, "job_id": jid})))
}

pub async fn api_org_correlate(
    State(_s): State<AppState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
) -> AppResult<Json<Value>> {
    require_org(&slug, &headers)?;
    let (ok, jid) = crate::jobs::try_acquire_job(&slug, "correlate");
    if !ok {
        return Err(job_busy_error(&slug, "correlate", jid));
    }
    let jid = jid.unwrap();
    crate::logs::log_event("info", "correlate", &slug, "correlation queued", Some(&jid)).await;
    let (slug2, jid2) = (slug.clone(), jid.clone());
    tokio::spawn(async move {
        let org = cc::org_get(&slug2).unwrap_or_else(|| json!({"slug": slug2.clone()}));
        let result = crate::scanner::correlate_org(org).await;
        // correlate_org surfaces fatal failures via an "error" key
        let err_msg = result
            .get("error")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        if let Some(err) = err_msg {
            crate::jobs::release_job(
                &slug2,
                "correlate",
                &jid2,
                Some(err.to_string()),
                Some(result),
            );
            crate::logs::log_event(
                "error",
                "correlate",
                &slug2,
                &format!("correlation failed: {}", err),
                Some(&jid2),
            ).await;
        } else {
            crate::jobs::release_job(&slug2, "correlate", &jid2, None, Some(result));
            crate::logs::log_event(
                "info",
                "correlate",
                &slug2,
                "correlation completed",
                Some(&jid2),
            ).await;
        }
    });
    Ok(Json(json!({"queued": true, "job_id": jid})))
}

pub async fn api_correlate_status(
    State(_s): State<AppState>,
    Path((slug, job_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> AppResult<Json<Value>> {
    require_org(&slug, &headers)?;
    let mut payload = crate::jobs::job_status(&slug, "correlate", &job_id)?;
    // enrich with the latest correlation report (mirrors Python)
    if let Some(obj) = payload.as_object_mut() {
        let report = cc::correlation_report(&slug);
        let added = report.get("added").and_then(|v| v.as_u64()).unwrap_or(0);
        obj.insert("correlated".to_string(), json!(added));
        obj.insert("report".to_string(), report);
    }
    Ok(Json(payload))
}

#[derive(serde::Deserialize)]
pub struct StatusBody {
    pub status: String,
    pub note: Option<String>,
}

pub async fn api_status_change(
    State(_s): State<AppState>,
    Path((slug, id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<StatusBody>,
) -> AppResult<Json<Value>> {
    require_org(&slug, &headers)?;
    let status = body.status.trim().to_uppercase();
    if !cc::CANONICAL_STATUSES.contains(&status.as_str()) {
        return Err(AppError::BadRequest("invalid status".into()));
    }
    let note = body.note.as_deref().unwrap_or("").trim().to_string();
    // load findings, mutate, persist (mirrors Python `set_finding_status`)
    let (mut fs, _) = cc::load_data(&slug);
    let idx = fs.iter().position(|f| {
        f.get("id").and_then(|v| v.as_str()) == Some(id.as_str())
    });
    let Some(i) = idx else {
        return Err(AppError::NotFound(format!("finding not found: {}", id)));
    };
    let f = &mut fs[i];
    cc::migrate_finding(f, &slug, None);
    let old = f
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("OPEN")
        .to_string();
    let now = cc::now_iso();
    let Some(map) = f.as_object_mut() else {
        return Err(AppError::NotFound(format!("finding not found: {}", id)));
    };
    map.insert("status".to_string(), Value::String(status.clone()));
    map.insert("last_seen".to_string(), Value::String(now.clone()));
    let mut hist = map
        .get("status_history")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    hist.push(json!({"at": now, "from": old, "to": status, "by": "user", "note": note}));
    map.insert("status_history".to_string(), Value::Array(hist));
    let findings_path = cc::org_findings_path(&slug)
        .ok_or_else(|| AppError::Internal(format!("bad findings path for org: {}", slug)))?;
    let payload = json!({"meta": cc::load_meta(&slug), "findings": fs});
    cc::atomic_write_json(&findings_path, &payload).await.map_err(AppError::from)?;
    cc::invalidate_org_cache(&slug);
    cc::append_history(
        &slug,
        json!({
            "ts": now,
            "kind": "status_change",
            "mode": Value::Null,
            "summary": {"subdomains": 0, "found": fs.len(), "new": 0, "resolved": 0, "changed": 1},
            "note": format!("{}: {} -> {}", id, old, status),
        }),
    )
    .await;
    crate::logs::log_event(
        "info",
        "status",
        &slug,
        &format!("finding {} status -> {}", id, status),
        None,
    ).await;
    match cc::find_finding(&slug, &id) {
        Some(updated) => Ok(Json(
            json!({"org": slug, "finding": cc::normalize_finding(&updated, &slug, None)}),
        )),
        None => Err(AppError::NotFound(format!("finding not found: {}", id))),
    }
}

#[derive(serde::Deserialize, Default)]
pub struct GradeBody {
    pub ai_profile: Option<String>,
}

pub async fn api_org_ai_grade(
    State(_s): State<AppState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
    body: Option<Json<GradeBody>>,
) -> AppResult<Json<Value>> {
    require_org(&slug, &headers)?;
    let ai_profile_req = body
        .map(|b| b.0.ai_profile.unwrap_or_default())
        .unwrap_or_default()
        .trim()
        .to_string();
    if !ai_profile_req.is_empty() {
        let (profiles, _) = crate::ai::load_profiles().await;
        if !profiles.contains_key(&ai_profile_req) {
            return Err(invalid_profile_error(&profiles));
        }
    }
    let (ok, jid) = crate::jobs::try_acquire_job(&slug, "grade");
    if !ok {
        return Err(job_busy_error(&slug, "grading", jid));
    }
    let jid = jid.unwrap();
    crate::logs::log_event(
        "info",
        "ai_grade",
        &slug,
        &format!(
            "AI grading queued (profile={})",
            if ai_profile_req.is_empty() { "auto" } else { &ai_profile_req }
        ),
        Some(&jid),
    ).await;
    let profile_opt = if ai_profile_req.is_empty() {
        None
    } else {
        Some(ai_profile_req)
    };
    let (slug2, jid2) = (slug.clone(), jid.clone());
    tokio::spawn(async move {
        let result = crate::scanner::ai_grade_org(&slug2, profile_opt).await;
        // ai_grade_org reports failure via {"result": "failed"} (never raises)
        if result.get("result").and_then(|v| v.as_str()) == Some("failed") {
            crate::jobs::release_job(
                &slug2,
                "grade",
                &jid2,
                Some("AI grading failed (provider or persistence error)".to_string()),
                None,
            );
            crate::logs::log_event("error", "ai_grade", &slug2, "AI grading failed", Some(&jid2)).await;
        } else {
            crate::jobs::release_job(&slug2, "grade", &jid2, None, None);
            crate::logs::log_event(
                "info",
                "ai_grade",
                &slug2,
                &format!(
                    "AI grading completed ({})",
                    result.get("result").and_then(|v| v.as_str()).unwrap_or("done")
                ),
                Some(&jid2),
            ).await;
        }
    });
    Ok(Json(json!({"queued": true, "slug": slug, "job_id": jid})))
}

// generic status-polling for recheck / grade
pub async fn api_recheck_status(
    State(_s): State<AppState>,
    Path((slug, job_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> AppResult<Json<Value>> {
    require_org(&slug, &headers)?;
    Ok(Json(crate::jobs::job_status(
        &slug, "recheck", &job_id,
    )?))
}

pub async fn api_ai_grade_status(
    State(_s): State<AppState>,
    Path((slug, job_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> AppResult<Json<Value>> {
    require_org(&slug, &headers)?;
    Ok(Json(crate::jobs::job_status(&slug, "grade", &job_id)?))
}

#[derive(serde::Deserialize)]
pub struct CommentBody {
    pub note: String,
    pub by: Option<String>,
}

pub async fn api_finding_comment(
    State(_s): State<AppState>,
    Path((slug, id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<CommentBody>,
) -> AppResult<Json<Value>> {
    require_org(&slug, &headers)?;
    let mut note = body.note.trim().to_string();
    if note.is_empty() {
        return Err(AppError::BadRequest("note is required".into()));
    }
    // truncate to countersign Python `add_finding_comment` (note[:2000])
    note.truncate(2000);
    let by_raw = body.by.as_deref().unwrap_or("").trim().to_string();
    let by = {
        let mut b = by_raw;
        b.truncate(60);
        if b.is_empty() {
            "analyst".to_string()
        } else {
            b
        }
    };
    // load findings, append feedback (capped at the 50 most recent), persist
    let (mut fs, _) = cc::load_data(&slug);
    let idx = fs.iter().position(|f| {
        f.get("id").and_then(|v| v.as_str()) == Some(id.as_str())
    });
    let Some(i) = idx else {
        return Err(AppError::NotFound(format!("finding not found: {}", id)));
    };
    let f = &mut fs[i];
    cc::migrate_finding(f, &slug, None);
    let Some(map) = f.as_object_mut() else {
        return Err(AppError::NotFound(format!("finding not found: {}", id)));
    };
    let mut fb = map
        .get("feedback")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    fb.push(json!({"at": cc::now_iso(), "by": by, "note": note}));
    if fb.len() > 50 {
        fb = fb[fb.len() - 50..].to_vec();
    }
    map.insert("feedback".to_string(), Value::Array(fb));
    let findings_path = cc::org_findings_path(&slug)
        .ok_or_else(|| AppError::Internal(format!("bad findings path for org: {}", slug)))?;
    let payload = json!({"meta": cc::load_meta(&slug), "findings": fs});
    cc::atomic_write_json(&findings_path, &payload).await.map_err(AppError::from)?;
    cc::invalidate_org_cache(&slug);
    let note_short: String = note.chars().take(120).collect();
    cc::append_history(
        &slug,
        json!({
            "ts": cc::now_iso(),
            "kind": "comment",
            "mode": Value::Null,
            "summary": {"found": fs.len()},
            "note": format!("comment on {}: {}", id, note_short),
        }),
    )
    .await;
    crate::logs::log_event(
        "info",
        "comment",
        &slug,
        &format!("finding {} commented (analyst feedback)", id),
        None,
    ).await;
    match cc::find_finding(&slug, &id) {
        Some(updated) => Ok(Json(
            json!({"org": slug, "finding": cc::normalize_finding(&updated, &slug, None)}),
        )),
        None => Err(AppError::NotFound(format!("finding not found: {}", id))),
    }
}

#[derive(serde::Deserialize)]
pub struct DomainsBody {
    pub domains: Vec<String>,
    pub action: Option<String>,
}

pub async fn api_org_domains(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
    Json(body): Json<DomainsBody>,
) -> AppResult<Json<Value>> {
    require_org(&slug, &headers)?;
    let action = body
        .action
        .clone()
        .unwrap_or_else(|| "add".to_string())
        .to_lowercase();
    if !matches!(action.as_str(), "add" | "remove" | "set") {
        return Err(AppError::BadRequest(
            "invalid action (add|remove|set)".into(),
        ));
    }
    let valid: Vec<String> = body
        .domains
        .iter()
        .map(|d| d.trim().to_lowercase().trim_end_matches('.').to_string())
        .filter(|d| is_valid_domain(d))
        .collect();
    if body.domains.iter().any(|d| !d.trim().is_empty()) && valid.is_empty() {
        return Err(AppError::BadRequest(
            "no valid domains (strict DNS name required)".into(),
        ));
    }

    let mut registry = load_registry_map()?;
    let entry = registry
        .get_mut(&slug)
        .ok_or_else(|| AppError::OrgNotFound(slug.clone()))?;
    let entry_obj = entry
        .as_object_mut()
        .ok_or_else(|| AppError::OrgNotFound(slug.clone()))?;
    let cur: Vec<String> = entry_obj
        .get("domains")
        .and_then(|d| d.as_array())
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|v| v.as_str().map(|s| s.to_string()))
        .collect();
    let new_domains = match action.as_str() {
        "add" => dedup(cur.into_iter().chain(valid).collect()),
        "remove" => cur.into_iter().filter(|d| !valid.contains(d)).collect(),
        _ => valid,
    };
    if new_domains.len() > 20 {
        return Err(AppError::BadRequest("too many domains (max 20)".into()));
    }
    entry_obj.insert(
        "domains".to_string(),
        Value::Array(
            new_domains
                .iter()
                .map(|d| Value::String(d.clone()))
                .collect(),
        ),
    );
    save_registry_map(&registry, &state).await?;
    cc::reload_registry();
    crate::logs::log_event(
        "info",
        "system",
        &slug,
        &format!(
            "domains updated ({}): {}",
            action,
            if new_domains.is_empty() {
                "(none)".to_string()
            } else {
                new_domains.join(", ")
            }
        ),
        None,
    ).await;
    Ok(Json(json!({"slug": slug, "domains": new_domains})))
}

#[derive(serde::Deserialize)]
pub struct AiProfileBody {
    pub ai_profile: Option<String>,
}

pub async fn api_set_ai_profile(
    State(_s): State<AppState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
    Json(body): Json<AiProfileBody>,
) -> AppResult<Json<Value>> {
    require_org(&slug, &headers)?;
    // empty string clears the preference (mirrors Python)
    let desired = body.ai_profile.unwrap_or_default().trim().to_string();
    let (profiles, _) = crate::ai::load_profiles().await;
    if !desired.is_empty() && !profiles.contains_key(&desired) {
        return Err(invalid_profile_error(&profiles));
    }
    // persist to the ignored runtime file (atomic, does not dirty orgs.json)
    crate::ai::set_org_profile(&slug, &desired).await;
    let effective = crate::ai::resolve_profile_for_org(&slug, None).await;
    Ok(Json(json!({
        "slug": slug,
        "ai_profile": if desired.is_empty() { Value::Null } else { Value::String(desired) },
        "effective": effective,
    })))
}

fn dedup(v: Vec<String>) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    v.into_iter().filter(|d| seen.insert(d.clone())).collect()
}
