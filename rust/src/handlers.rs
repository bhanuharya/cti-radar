//! HTTP handlers — axum router + all /api endpoints (port of `main.py`).

use crate::correlation as cc;
use crate::error::{AppError, AppResult};
use crate::AppState;
use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::SocketAddr;

const DEFAULT_ORG: &str = "sample";

pub(crate) fn valid_slug(slug: &str) -> bool {
    !slug.is_empty()
        && slug.len() <= 32
        && slug
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

fn org_not_found(slug: &str) -> AppError {
    AppError::OrgNotFound(slug.to_string())
}

/// Validate slug + auth + org existence. Returns the org entry on success.
pub(crate) fn require_org(slug: &str, headers: &HeaderMap) -> AppResult<Value> {
    if !valid_slug(slug) {
        return Err(AppError::InvalidSlug);
    }
    crate::auth::require_auth(headers)?;
    cc::org_get(slug).ok_or_else(|| org_not_found(slug))
}

// ---------------------------------------------------------------------------
// session auth
// ---------------------------------------------------------------------------

const SESSION_TTL_SECS: u64 = 12 * 3600;

pub async fn api_login(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    // per-client rate limit (mirrors Python `req.client.host`)
    let ip = addr.ip().to_string();
    let (limited, retry) = crate::auth::login_limit(&ip);
    if limited {
        let mut resp = Json(json!({"error": "too many failed login attempts"})).into_response();
        resp.headers_mut()
            .insert("Retry-After", retry.to_string().parse().unwrap());
        return (axum::http::StatusCode::TOO_MANY_REQUESTS, resp).into_response();
    }
    match crate::auth::login_ok(&headers) {
        Some(sid) => {
            crate::auth::reset_login_failures(&ip);
            let secure = crate::auth::use_secure_cookie(&headers);
            let cookie = format!(
                "{}={}; Path=/; HttpOnly; SameSite=Lax; Max-Age={}{}",
                crate::auth::SESSION_COOKIE,
                sid,
                SESSION_TTL_SECS,
                if secure { "; Secure" } else { "" }
            );
            let mut resp = Json(json!({
                "ok": true,
                "expires_in": SESSION_TTL_SECS,
                "user": state.cfg.user,
            }))
            .into_response();
            resp.headers_mut()
                .insert("Set-Cookie", cookie.parse().unwrap());
            resp
        }
        None => {
            crate::auth::record_login_failure(&ip);
            (
                axum::http::StatusCode::UNAUTHORIZED,
                Json(json!({"error": "invalid username or password"})),
            )
                .into_response()
        }
    }
}

pub async fn api_logout(headers: HeaderMap) -> Response {
    // server-side invalidation first (a stolen cookie must stop working),
    // then clear the client cookie.
    crate::auth::invalidate_session(&headers);
    let cookie = format!(
        "{}={}; Path=/; HttpOnly; SameSite=Lax; Max-Age=0",
        crate::auth::SESSION_COOKIE,
        ""
    );
    let mut resp = Json(json!({"ok": true})).into_response();
    resp.headers_mut()
        .insert("Set-Cookie", cookie.parse().unwrap());
    resp
}

// ---------------------------------------------------------------------------
// read endpoints
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize, Default)]
pub struct OrgQuery {
    pub org: Option<String>,
    pub sort: Option<String>,
    pub status: Option<String>,
    pub limit: Option<usize>,
}

pub async fn api_graph(
    State(_s): State<AppState>,
    Query(q): Query<OrgQuery>,
    headers: HeaderMap,
) -> AppResult<Json<Value>> {
    let org = q.org.unwrap_or_else(|| DEFAULT_ORG.to_string());
    require_org(&org, &headers)?;
    Ok(Json(cc::build_graph(&org)))
}

pub async fn api_summary(
    State(_s): State<AppState>,
    Query(q): Query<OrgQuery>,
    headers: HeaderMap,
) -> AppResult<Json<Value>> {
    let org = q.org.unwrap_or_else(|| DEFAULT_ORG.to_string());
    require_org(&org, &headers)?;
    Ok(Json(cc::summary(&org)))
}

pub async fn api_fleet(
    State(_s): State<AppState>,
    Query(q): Query<OrgQuery>,
    headers: HeaderMap,
) -> AppResult<Json<Value>> {
    let org = q.org.unwrap_or_else(|| DEFAULT_ORG.to_string());
    require_org(&org, &headers)?;
    Ok(Json(Value::Array(cc::fleet_spread(&org))))
}

pub async fn api_ips(
    State(_s): State<AppState>,
    Query(q): Query<OrgQuery>,
    headers: HeaderMap,
) -> AppResult<Json<Value>> {
    let org = q.org.unwrap_or_else(|| DEFAULT_ORG.to_string());
    require_org(&org, &headers)?;
    Ok(Json(Value::Array(cc::ip_sharing(&org))))
}

pub async fn api_findings(
    State(_s): State<AppState>,
    Query(q): Query<OrgQuery>,
    headers: HeaderMap,
) -> AppResult<Json<Value>> {
    let org = q.org.unwrap_or_else(|| DEFAULT_ORG.to_string());
    require_org(&org, &headers)?;
    let (fs, _) = cc::load_data(&org);
    let mut out = cc::normalize_all_light(&fs, &org);
    out = cc::sort_findings(out, q.sort.as_deref());
    // status filter
    if let Some(status) = q.status.as_deref() {
        if status != "all" {
            out.retain(|f| {
                f.get("status")
                    .and_then(|s| s.as_str())
                    .map(|s| s.to_uppercase() == status.to_uppercase())
                    .unwrap_or(false)
            });
        }
    }
    Ok(Json(json!({"findings_total": out.len(), "findings": out})))
}

pub async fn api_dashboard(
    State(_s): State<AppState>,
    Query(q): Query<OrgQuery>,
    headers: HeaderMap,
) -> AppResult<Json<Value>> {
    let org = q.org.unwrap_or_else(|| DEFAULT_ORG.to_string());
    require_org(&org, &headers)?;
    build_dashboard_payload(&org, q.sort.as_deref(), q.status.as_deref())
}

pub async fn api_org_dashboard(
    State(_s): State<AppState>,
    Path(slug): Path<String>,
    Query(q): Query<OrgQuery>,
    headers: HeaderMap,
) -> AppResult<Json<Value>> {
    require_org(&slug, &headers)?;
    build_dashboard_payload(&slug, q.sort.as_deref(), q.status.as_deref())
}

fn build_dashboard_payload(
    org: &str,
    sort: Option<&str>,
    status: Option<&str>,
) -> AppResult<Json<Value>> {
    use serde_json::Map;
    let (fs, baseline) = cc::load_data(org);
    let mut norm = cc::normalize_all_light(&fs, org);
    norm = cc::sort_findings(norm, sort);
    if let Some(status) = status {
        if status != "all" {
            norm.retain(|f| {
                f.get("status")
                    .and_then(|s| s.as_str())
                    .map(|s| s.to_uppercase() == status.to_uppercase())
                    .unwrap_or(false)
            });
        }
    }
    let summary = cc::summary_from_data(&fs, &baseline);
    let graph = cc::build_graph(org);
    let fleet = cc::fleet_spread_from_data(&fs);
    let ips = cc::ip_sharing_from_data(&fs);
    let history: Vec<Value> = cc::load_history(org).iter().rev().take(100).cloned().collect();
    let domains = cc::org_get(org)
        .as_ref()
        .and_then(|o| o.get("domains"))
        .and_then(|d| d.as_array())
        .map(|a| a.len())
        .unwrap_or(0);
    let meta = cc::load_meta(org);
    let mut scan_info = Value::Null;
    if meta.get("date").is_some() {
        let mut stages = Map::new();
        for k in ["enum", "resolve", "probe", "services", "tls", "nvd", "total"] {
            if let Some(v) = meta.pointer(&format!("/scan_stats/{}", k)) {
                stages.insert(k.to_string(), v.clone());
            }
        }
        scan_info = json!({
            "date": meta.get("date"),
            "domains": domains,
            "subdomains": meta.get("subdomains"),
            "reachable": meta.get("reachable"),
            "reconcile": meta.get("reconcile").and_then(|r| r.get("observed")),
            "stages": stages,
        });
    }
    Ok(Json(json!({
        "org": org,
        "summary": summary,
        "graph": graph,
        "fleet": fleet,
        "ips": ips,
        "findings": {"findings_total": norm.len(), "findings": norm},
        "history": history,
        "scan_info": scan_info,
    })))
}

pub async fn api_finding_detail(
    State(_s): State<AppState>,
    Path(id): Path<String>,
    Query(q): Query<OrgQuery>,
    headers: HeaderMap,
) -> AppResult<Json<Value>> {
    let org = q.org.unwrap_or_else(|| DEFAULT_ORG.to_string());
    require_org(&org, &headers)?;
    match cc::find_finding(&org, &id) {
        Some(f) => Ok(Json(json!({
            "org": org,
            "finding": cc::normalize_finding(&f, &org, None),
        }))),
        None => Err(AppError::NotFound(format!("finding not found: {}", id))),
    }
}

pub async fn api_orgs(State(_s): State<AppState>, headers: HeaderMap) -> AppResult<Json<Value>> {
    crate::auth::require_auth(&headers)?;
    Ok(Json(json!({"orgs": cc::org_list()})))
}

pub async fn api_org_get(
    State(_s): State<AppState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
) -> AppResult<Json<Value>> {
    let org = require_org(&slug, &headers)?;
    let summary = cc::summary(&slug);
    let mut out = org.clone();
    if let Value::Object(map) = &mut out {
        map.insert("slug".to_string(), Value::String(slug.clone()));
        map.insert("summary".to_string(), summary);
    }
    Ok(Json(out))
}

pub async fn api_org_history(
    State(_s): State<AppState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
) -> AppResult<Json<Value>> {
    require_org(&slug, &headers)?;
    let events = cc::load_history(&slug);
    let mut by_kind: HashMap<String, usize> = HashMap::new();
    for e in &events {
        let k = e
            .get("kind")
            .and_then(|v| v.as_str())
            .unwrap_or("?")
            .to_string();
        *by_kind.entry(k).or_insert(0) += 1;
    }
    // newest-first, capped at 100 (mirrors Python `events[::-1][:100]`)
    let recent: Vec<Value> = events.iter().rev().take(100).cloned().collect();
    Ok(Json(json!({
        "org": slug,
        "events": recent,
        "summary": {"total": events.len(), "by_kind": by_kind},
    })))
}

pub async fn api_admin_logs(
    State(_s): State<AppState>,
    Query(q): Query<OrgQuery>,
    headers: HeaderMap,
) -> AppResult<Json<Value>> {
    crate::auth::require_auth(&headers)?;
    let (logs, total) = crate::logs::read_logs(q.org.as_deref(), q.limit.unwrap_or(200));
    Ok(Json(json!({"logs": logs, "total": total})))
}

pub async fn api_ai_capabilities(
    State(_s): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<Value>> {
    crate::auth::require_auth(&headers)?;
    Ok(Json(crate::ai::get_capabilities()))
}

pub async fn api_get_ai_profile(
    State(_s): State<AppState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
) -> AppResult<Json<Value>> {
    let org = require_org(&slug, &headers)?;
    // stored preference: runtime file first, legacy orgs.json ai_profile fallback
    let stored = crate::ai::get_org_profile(&slug).or_else(|| {
        org.get("ai_profile")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    });
    let effective = crate::ai::resolve_profile_for_org(&slug, None);
    Ok(Json(json!({
        "slug": slug,
        "ai_profile": stored,
        "effective": effective,
        "capabilities": crate::ai::get_capabilities(),
    })))
}

pub async fn api_openhack_models(
    State(_s): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<Value>> {
    crate::auth::require_auth(&headers)?;
    Ok(Json(crate::openhack::list_models(false)))
}

pub async fn api_report_pdf(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
) -> Response {
    use axum::response::IntoResponse;
    if let Err(e) = require_org(&slug, &headers) {
        return e.into_response();
    }
    let org = match cc::org_get(&slug) {
        Some(o) => o,
        None => return AppError::OrgNotFound(slug.clone()).into_response(),
    };
    let (fs, _) = cc::load_data(&slug);
    let domains: Vec<String> = org
        .get("domains")
        .and_then(|d| d.as_array())
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|v| v.as_str().map(|s| s.to_string()))
        .collect();
    // normalize (PII-masked) findings for the report
    let meta_date = cc::load_meta_date(&slug);
    let nfs: Vec<Value> = fs
        .iter()
        .map(|f| cc::normalize_finding(f, &slug, meta_date.as_deref()))
        .filter(|f| {
            f.get("status")
                .and_then(|s| s.as_str())
                .map(|s| s.to_uppercase() != "RESOLVED")
                .unwrap_or(true)
        })
        .collect();
    let html = crate::report::build_report_html(&slug, &org, &nfs, &domains);

    if let Some(chromium) = state.cfg.chromium_path.as_deref() {
        if let Some(pdf) = crate::report::render_pdf(&slug, &html, chromium).await {
            return ([(axum::http::header::CONTENT_TYPE, "application/pdf")], pdf).into_response();
        }
    }
    // fallback: printable HTML download
    (
        [
            (axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (
                axum::http::header::CONTENT_DISPOSITION,
                "attachment; filename=report.html",
            ),
        ],
        html,
    )
        .into_response()
}
