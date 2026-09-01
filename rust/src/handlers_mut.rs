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

#[derive(serde::Deserialize)]
pub struct RegisterBody {
    pub name: String,
    pub domains: Vec<String>,
    pub slug: Option<String>,
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
    if body.name.trim().is_empty() || body.name.len() > 200 {
        return Err(AppError::BadRequest("name required (max 200 chars)".into()));
    }
    let valid_domains: Vec<String> = body
        .domains
        .iter()
        .map(|d| d.trim().to_lowercase().trim_end_matches('.').to_string())
        .filter(|d| is_valid_domain(d))
        .collect();
    if body.domains.is_empty() || valid_domains.is_empty() {
        return Err(AppError::BadRequest(
            "at least one valid domain required".into(),
        ));
    }
    if valid_domains.len() > 20 {
        return Err(AppError::BadRequest("too many domains (max 20)".into()));
    }
    let slug = body
        .slug
        .clone()
        .unwrap_or_else(|| slugify(&valid_domains[0]));
    if !valid_slug(&slug) {
        return Err(AppError::BadRequest("invalid slug".into()));
    }
    if cc::org_get(&slug).is_some() {
        return Err(AppError::Conflict("org already exists".into()));
    }

    // persist to orgs.json + reload registry
    let mut registry = load_registry_map();
    let findings_rel = format!("orgs/{}/findings.json", slug);
    let baseline_rel = format!("orgs/{}/baseline.txt", slug);
    registry.insert(
        slug.clone(),
        json!({
            "name": body.name.trim(),
            "domains": valid_domains,
            "findings": findings_rel,
            "baseline": baseline_rel,
        }),
    );
    save_registry_map(&registry, &state)?;
    cc::reload_registry();

    Ok(Json(
        json!({"slug": slug, "name": body.name.trim(), "domains": valid_domains}),
    ))
}

fn slugify(domain: &str) -> String {
    domain
        .replace('.', "-")
        .chars()
        .map(|c| {
            if c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .chars()
        .take(32)
        .collect()
}

pub fn load_registry_map() -> Map<String, Value> {
    let path = crate::correlation::cfg_path_orgs_json();
    match std::fs::read_to_string(&path) {
        Ok(txt) => serde_json::from_str(&txt).unwrap_or_default(),
        Err(_) => Map::new(),
    }
}

fn save_registry_map(registry: &Map<String, Value>, state: &AppState) -> AppResult<()> {
    let path = state.cfg.orgs_json();
    crate::correlation::atomic_write_json(&path, &Value::Object(registry.clone()))
        .map_err(AppError::from)
}

#[derive(serde::Deserialize)]
pub struct ScanBody {
    pub mode: Option<String>,
    pub ai_profile: Option<String>,
}

pub async fn api_org_scan(
    State(_state): State<AppState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
    Json(body): Json<ScanBody>,
) -> AppResult<Json<Value>> {
    require_org(&slug, &headers)?;
    let mode = if body.mode.as_deref() == Some("ai") {
        "ai"
    } else {
        "fast"
    };
    let (ok, jid) = crate::jobs::try_acquire_job(&slug, "scan");
    if !ok {
        return match jid {
            Some(id) => Err(AppError::Conflict(format!("scan already running: {}", id))),
            None => Err(AppError::Conflict("too many active jobs".into())),
        };
    }
    let jid = jid.unwrap();
    // spawn scan in background (stub scanner for now)
    let (slug2, jid2, mode2, ai_profile) = (
        slug.clone(),
        jid.clone(),
        mode.to_string(),
        body.ai_profile.clone(),
    );
    tokio::spawn(async move {
        let mut org_val = cc::org_get(&slug2).unwrap_or_else(|| json!({}));
        if let Value::Object(map) = &mut org_val {
            map.insert("slug".to_string(), Value::String(slug2.clone()));
        }
        let result = crate::scanner::generate_org(org_val, &mode2, ai_profile, None).await;
        crate::jobs::release_job(&slug2, "scan", &jid2, None, Some(result));
    });
    Ok(Json(
        json!({"queued": true, "slug": slug, "mode": mode, "job_id": jid}),
    ))
}

pub async fn api_scan_status(
    State(_s): State<AppState>,
    Path((slug, job_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> AppResult<Json<Value>> {
    require_org(&slug, &headers)?;
    let running = crate::jobs::is_job_running(&slug, "scan");
    Ok(Json(crate::jobs::job_status(
        &slug, "scan", &job_id, running,
    )))
}

pub async fn api_org_recheck(
    State(_s): State<AppState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
) -> AppResult<Json<Value>> {
    require_org(&slug, &headers)?;
    let (ok, jid) = crate::jobs::try_acquire_job(&slug, "recheck");
    if !ok {
        return Err(AppError::Conflict("recheck already running".into()));
    }
    let jid = jid.unwrap();
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
        return Err(AppError::Conflict("correlation already running".into()));
    }
    let jid = jid.unwrap();
    let (slug2, jid2) = (slug.clone(), jid.clone());
    tokio::spawn(async move {
        let org = cc::org_get(&slug2).unwrap_or_else(|| json!({"slug": slug2.clone()}));
        let result = crate::scanner::correlate_org(org).await;
        crate::jobs::release_job(&slug2, "correlate", &jid2, None, Some(result));
    });
    Ok(Json(json!({"queued": true, "job_id": jid})))
}

pub async fn api_correlate_status(
    State(_s): State<AppState>,
    Path((slug, job_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> AppResult<Json<Value>> {
    require_org(&slug, &headers)?;
    let running = crate::jobs::is_job_running(&slug, "correlate");
    Ok(Json(crate::jobs::job_status(
        &slug,
        "correlate",
        &job_id,
        running,
    )))
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
    // load findings, mutate, persist
    let (mut fs, baseline) = cc::load_data(&slug);
    let mut found = false;
    for f in fs.iter_mut() {
        if f.get("id").and_then(|v| v.as_str()) == Some(id.as_str()) {
            f.as_object_mut()
                .unwrap()
                .insert("status".to_string(), Value::String(status.clone()));
            if let Some(note) = body.note.as_deref() {
                if !note.trim().is_empty() {
                    let sh = f
                        .get("status_history")
                        .cloned()
                        .unwrap_or_else(|| json!([]));
                    let mut arr = match sh.as_array() {
                        Some(a) => a.clone(),
                        None => vec![],
                    };
                    arr.push(json!({"at": cc::now_iso(), "from": "", "to": status, "by": "analyst", "note": note.trim()}));
                    f.as_object_mut()
                        .unwrap()
                        .insert("status_history".to_string(), Value::Array(arr));
                }
            }
            found = true;
            break;
        }
    }
    if !found {
        return Err(AppError::NotFound(format!("finding not found: {}", id)));
    }
    let findings_path = cc::org_findings_path(&slug).unwrap();
    let payload = json!({"meta": cc::load_meta(&slug), "findings": fs});
    cc::atomic_write_json(&findings_path, &payload).map_err(AppError::from)?;
    cc::invalidate_org_cache(&slug);
    let _ = baseline;
    Ok(Json(
        json!({"org": slug, "finding": {"id": id, "status": status}}),
    ))
}

#[derive(serde::Deserialize)]
pub struct GradeBody {
    pub ai_profile: Option<String>,
}

pub async fn api_org_ai_grade(
    State(_s): State<AppState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
    Json(_body): Json<GradeBody>,
) -> AppResult<Json<Value>> {
    require_org(&slug, &headers)?;
    let (ok, jid) = crate::jobs::try_acquire_job(&slug, "grade");
    if !ok {
        return Err(AppError::Conflict("grading already running".into()));
    }
    let jid = jid.unwrap();
    let (slug2, jid2) = (slug.clone(), jid.clone());
    tokio::spawn(async move {
        let result = crate::scanner::ai_grade_org(&slug2).await;
        crate::jobs::release_job(&slug2, "grade", &jid2, None, Some(result));
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
    let running = crate::jobs::is_job_running(&slug, "recheck");
    Ok(Json(crate::jobs::job_status(
        &slug, "recheck", &job_id, running,
    )))
}

pub async fn api_ai_grade_status(
    State(_s): State<AppState>,
    Path((slug, job_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> AppResult<Json<Value>> {
    require_org(&slug, &headers)?;
    let running = crate::jobs::is_job_running(&slug, "grade");
    Ok(Json(crate::jobs::job_status(
        &slug, "grade", &job_id, running,
    )))
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
    let note = body.note.trim();
    if note.is_empty() {
        return Err(AppError::BadRequest("note is required".into()));
    }
    let (mut fs, _) = cc::load_data(&slug);
    let mut found = false;
    for f in fs.iter_mut() {
        if f.get("id").and_then(|v| v.as_str()) == Some(id.as_str()) {
            let comments = f.get("comments").cloned().unwrap_or_else(|| json!([]));
            let mut arr = match comments.as_array() {
                Some(a) => a.clone(),
                None => vec![],
            };
            arr.push(json!({
                "at": cc::now_iso(),
                "by": body.by.as_deref().unwrap_or("").trim(),
                "note": note,
            }));
            f.as_object_mut()
                .unwrap()
                .insert("comments".to_string(), Value::Array(arr));
            found = true;
            break;
        }
    }
    if !found {
        return Err(AppError::NotFound(format!("finding not found: {}", id)));
    }
    let findings_path = cc::org_findings_path(&slug).unwrap();
    let payload = json!({"meta": cc::load_meta(&slug), "findings": fs});
    cc::atomic_write_json(&findings_path, &payload).map_err(AppError::from)?;
    cc::invalidate_org_cache(&slug);
    Ok(Json(
        json!({"org": slug, "finding": {"id": id, "commented": true}}),
    ))
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

    let mut registry = load_registry_map();
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
    save_registry_map(&registry, &state)?;
    cc::reload_registry();
    Ok(Json(json!({"slug": slug, "domains": new_domains})))
}

#[derive(serde::Deserialize)]
pub struct AiProfileBody {
    pub ai_profile: String,
}

pub async fn api_set_ai_profile(
    State(_s): State<AppState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
    Json(body): Json<AiProfileBody>,
) -> AppResult<Json<Value>> {
    require_org(&slug, &headers)?;
    let profile = body.ai_profile.trim().to_string();
    let (profiles, _) = crate::ai::load_profiles();
    if !profiles.contains_key(&profile) {
        return Err(AppError::BadRequest("invalid ai_profile".into()));
    }
    // persist per-org profile preference (best-effort)
    Ok(Json(json!({"org": slug, "ai_profile": profile})))
}

fn dedup(v: Vec<String>) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    v.into_iter().filter(|d| seen.insert(d.clone())).collect()
}
