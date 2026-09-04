//! CTI Radar — Rust backend (axum + tokio). Port of the FastAPI implementation
//! with Rust-native concurrency (async I/O + rayon data-parallelism).

pub mod ai;
pub mod auth;
pub mod config;
pub mod correlation;
pub mod cve_match;
pub mod error;
pub mod handlers;
pub mod handlers_mut;
pub mod jobs;
pub mod logs;
pub mod net;
pub mod openhack;
pub mod openhack_handlers;
pub mod report;
pub mod scanner;

use axum::extract::Request;
use axum::http::HeaderValue;
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::{get, post};
use axum::Router;
use std::path::PathBuf;
use std::sync::Arc;

const DASHBOARD_HTML: &str = include_str!("../../app/dashboard.html");

async fn security_headers(req: Request, next: Next) -> Response {
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    let insert = |h: &mut axum::http::HeaderMap, k: &'static str, v: &'static str| {
        if let Ok(val) = HeaderValue::from_str(v) {
            h.insert(k, val);
        }
    };
    insert(h, "Content-Security-Policy",
        "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self' data:; base-uri 'self'; frame-ancestors 'none'");
    insert(h, "X-Content-Type-Options", "nosniff");
    insert(h, "X-Frame-Options", "DENY");
    insert(h, "Referrer-Policy", "no-referrer");
    insert(
        h,
        "Permissions-Policy",
        "camera=(), microphone=(), geolocation=()",
    );
    resp
}

/// Locate the vendored `app/static` dir: walk up from the executable (works
/// when installed), then fall back to CWD-relative dev layouts.
fn resolve_static_dir() -> PathBuf {
    if let Ok(exe) = std::env::current_exe() {
        let mut anc = exe.as_path();
        for _ in 0..6 {
            match anc.parent() {
                Some(parent) => {
                    let cand = parent.join("app/static");
                    if cand.is_dir() {
                        return cand;
                    }
                    anc = parent;
                }
                None => break,
            }
        }
    }
    for cand in ["../app/static", "app/static"] {
        let p = PathBuf::from(cand);
        if p.is_dir() {
            return p;
        }
    }
    PathBuf::from("../app/static")
}

/// Build the full router (shared by the binary and integration tests).
/// The login route expects `ConnectInfo<std::net::SocketAddr>`; serve with
/// `into_make_service_with_connect_info::<std::net::SocketAddr>()`.
pub fn build_router(state: AppState) -> Router {
    use handlers as h;
    use handlers_mut as hm;
    use openhack_handlers as oh;

    Router::new()
        // dashboard + static
        .route(
            "/",
            get(|| async {
                (
                    [(axum::http::header::CACHE_CONTROL, "no-cache")],
                    axum::response::Html(DASHBOARD_HTML),
                )
            }),
        )
        // vendored static assets (vis-network, etc.) from app/static
        .nest_service(
            "/static",
            tower_http::services::ServeDir::new(resolve_static_dir()),
        )
        // session auth
        .route("/api/login", post(h::api_login))
        .route("/api/logout", post(h::api_logout))
        // read endpoints
        .route("/api/graph", get(h::api_graph))
        .route("/api/summary", get(h::api_summary))
        .route("/api/fleet", get(h::api_fleet))
        .route("/api/ips", get(h::api_ips))
        .route("/api/findings", get(h::api_findings))
        .route("/api/dashboard", get(h::api_dashboard))
        .route("/api/orgs", get(h::api_orgs))
        .route("/api/admin/logs", get(h::api_admin_logs))
        .route("/api/ai/capabilities", get(h::api_ai_capabilities))
        .route("/api/openhack/models", get(h::api_openhack_models))
        .route("/api/orgs/{slug}/ai_profile", get(h::api_get_ai_profile))
        .route("/api/findings/{id}", get(h::api_finding_detail))
        .route("/api/orgs/{slug}", get(h::api_org_get))
        .route("/api/orgs/{slug}/dashboard", get(h::api_org_dashboard))
        .route("/api/orgs/{slug}/history", get(h::api_org_history))
        .route("/api/orgs/{slug}/report.pdf", get(h::api_report_pdf))
        // mutation endpoints
        .route("/api/orgs/register", post(hm::api_org_register))
        .route("/api/orgs/{slug}/scan", post(hm::api_org_scan))
        .route("/api/orgs/{slug}/scan/{job_id}", get(hm::api_scan_status))
        .route("/api/orgs/{slug}/recheck", post(hm::api_org_recheck))
        .route(
            "/api/orgs/{slug}/recheck/{job_id}",
            get(hm::api_recheck_status),
        )
        .route("/api/orgs/{slug}/correlate", post(hm::api_org_correlate))
        .route(
            "/api/orgs/{slug}/correlate/{job_id}",
            get(hm::api_correlate_status),
        )
        .route("/api/orgs/{slug}/ai-grade", post(hm::api_org_ai_grade))
        .route(
            "/api/orgs/{slug}/ai-grade/{job_id}",
            get(hm::api_ai_grade_status),
        )
        .route("/api/orgs/{slug}/domains", post(hm::api_org_domains))
        .route("/api/orgs/{slug}/ai_profile", post(hm::api_set_ai_profile))
        .route(
            "/api/orgs/{slug}/openhack-config",
            post(oh::api_openhack_config),
        )
        .route(
            "/api/orgs/{slug}/openhack-scan",
            post(oh::api_openhack_scan),
        )
        .route(
            "/api/orgs/{slug}/openhack-scan/{job_id}",
            get(oh::api_openhack_status),
        )
        .route(
            "/api/orgs/{slug}/findings/{id}/status",
            post(hm::api_status_change),
        )
        .route(
            "/api/orgs/{slug}/findings/{id}/comment",
            post(hm::api_finding_comment),
        )
        .layer(middleware::from_fn(security_headers))
        .with_state(state)
}

/// Application state shared across handlers.
#[derive(Clone)]
pub struct AppState {
    pub cfg: Arc<config::Config>,
}

impl AppState {
    pub fn new(cfg: config::Config) -> Self {
        Self { cfg: Arc::new(cfg) }
    }
}
