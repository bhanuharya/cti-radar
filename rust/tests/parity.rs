//! API parity tests — assert the Rust backend's HTTP surface matches the
//! Python backend's shapes (status codes + JSON envelopes).
//!
//! Auth uses `X-CTI-Token` (no session needed). Each test uses dedicated
//! orgs/findings so parallel tests never interfere.

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use cti_radar::{build_router, AppState};
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::OnceLock;
use tower::ServiceExt;

const TOKEN: &str = "test-scan-token-xyz";

fn setup() -> AppState {
    static INIT: OnceLock<AppState> = OnceLock::new();
    INIT.get_or_init(|| {
        let dir = std::env::temp_dir().join(format!("cti-parity-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let seed_org = |slug: &str, name: &str, domains: Vec<&str>, findings: Value| {
            let od = dir.join("orgs").join(slug);
            std::fs::create_dir_all(&od).unwrap();
            std::fs::write(
                od.join("findings.json"),
                serde_json::to_string(&json!({
                    "meta": {"date": "2026-09-01T00:00:00Z"},
                    "findings": findings,
                }))
                .unwrap(),
            )
            .unwrap();
            std::fs::write(od.join("baseline.txt"), "h1.example\nh2.example\n").unwrap();
            std::fs::write(od.join("history.json"), "[]").unwrap();
            json!({
                "name": name,
                "domains": domains,
                "findings": format!("data/orgs/{}/findings.json", slug),
                "baseline": format!("data/orgs/{}/baseline.txt", slug),
            })
        };
        let mut registry = serde_json::Map::new();
        let f = |id: &str, sev: &str, status: &str, target: &str| {
            json!({"id": id, "title": format!("T-{}", id), "target": target,
                   "severity": sev, "status": status})
        };
        registry.insert(
            "torg".to_string(),
            seed_org(
                "torg",
                "T Org",
                vec!["example.com"],
                json!([
                    f("p1", "HIGH", "OPEN", "h1.example"),
                    f("p2", "LOW", "MITIGATED", "h2.example")
                ]),
            ),
        );
        registry.insert(
            "lifeorg".to_string(),
            seed_org(
                "lifeorg",
                "Life Org",
                vec!["life.example"],
                json!([
                    f("l1", "HIGH", "OPEN", "lh1.example"),
                    f("l2", "MEDIUM", "OPEN", "lh2.example")
                ]),
            ),
        );
        registry.insert(
            "scanorg".to_string(),
            seed_org("scanorg", "Scan Org", vec![], json!([])),
        );
        std::fs::write(
            dir.join("orgs.json"),
            serde_json::to_string(&Value::Object(registry)).unwrap(),
        )
        .unwrap();
        std::env::set_var("CTI_USER", "tester");
        std::env::set_var("CTI_PASSWORD", "pw");
        std::env::set_var("CTI_SCAN_TOKEN", TOKEN);
        std::env::set_var("CTI_DATA_DIR", &dir);
        std::env::set_var("CTI_AI_CONFIG_FILE", dir.join("no-ai-config.json"));
        // The test contract is no configured AI profile. Do not inherit a
        // developer's optional Cline compatibility credential from the host.
        std::env::remove_var("HERMES_CUSTOM_API_CLINE_BOT_API_KEY");
        let cfg = cti_radar::config::Config::load();
        cti_radar::correlation::init(cfg.clone());
        cti_radar::auth::init(cfg.clone());
        cti_radar::jobs::init(cfg.clone());
        cti_radar::logs::init(&cfg.data_dir);
        AppState::new(cfg)
    })
    .clone()
}

fn app() -> axum::Router {
    build_router(setup())
}

async fn body_json(resp: axum::response::Response) -> (StatusCode, Value) {
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 8 * 1024 * 1024)
        .await
        .unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, v)
}

async fn get(uri: &str, token: bool) -> (StatusCode, Value) {
    let req = Request::builder()
        .uri(uri)
        .header("X-CTI-Token", if token { TOKEN } else { "wrong" })
        .body(Body::empty())
        .unwrap();
    body_json(app().oneshot(req).await.unwrap()).await
}

async fn post(uri: &str, body: Value) -> (StatusCode, Value) {
    let req = Request::builder()
        .uri(uri)
        .method("POST")
        .header("X-CTI-Token", TOKEN)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    body_json(app().oneshot(req).await.unwrap()).await
}

#[tokio::test]
async fn test_unauthorized_without_token() {
    let (s, _) = get("/api/orgs", false).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_orgs_envelope() {
    let (s, v) = get("/api/orgs", true).await;
    assert_eq!(s, StatusCode::OK);
    let orgs = v.get("orgs").and_then(|o| o.as_array()).expect("orgs key");
    assert!(orgs
        .iter()
        .any(|o| o.get("slug").and_then(|x| x.as_str()) == Some("torg")));
}

#[tokio::test]
async fn test_findings_envelope_and_filter() {
    let (s, v) = get("/api/findings?org=torg", true).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v.get("findings_total").and_then(|n| n.as_u64()), Some(2));
    assert_eq!(
        v.get("findings")
            .and_then(|f| f.as_array())
            .map(|a| a.len()),
        Some(2)
    );
    // status filter (case-insensitive, mirrors Python)
    let (s, v) = get("/api/findings?org=torg&status=mitigated", true).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v.get("findings_total").and_then(|n| n.as_u64()), Some(1));
    // severity sort: HIGH first
    let (s, v) = get("/api/findings?org=torg&sort=severity", true).await;
    assert_eq!(s, StatusCode::OK);
    let fs = v.get("findings").and_then(|f| f.as_array()).unwrap();
    assert_eq!(fs[0].get("severity").and_then(|x| x.as_str()), Some("HIGH"));
}

#[tokio::test]
async fn test_finding_detail_envelope() {
    let (s, v) = get("/api/findings/p1?org=torg", true).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v.get("org").and_then(|o| o.as_str()), Some("torg"));
    assert_eq!(
        v.get("finding")
            .and_then(|f| f.get("id"))
            .and_then(|i| i.as_str()),
        Some("p1")
    );
    let (s, _) = get("/api/findings/nope?org=torg", true).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_dashboard_envelope() {
    let (s, v) = get("/api/dashboard?org=torg", true).await;
    assert_eq!(s, StatusCode::OK);
    for k in [
        "org",
        "summary",
        "graph",
        "fleet",
        "ips",
        "findings",
        "history",
        "scan_info",
    ] {
        assert!(v.get(k).is_some(), "missing dashboard key {}", k);
    }
    let f = v.get("findings").unwrap();
    assert_eq!(f.get("findings_total").and_then(|n| n.as_u64()), Some(2));
    assert!(f.get("findings").and_then(|x| x.as_array()).is_some());
}

#[tokio::test]
async fn test_register_validation() {
    // invalid slug
    let (s, v) = post("/api/orgs/register", json!({"slug": "BAD!", "domains": []})).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert!(v.get("error").is_some());
    // empty name defaults to slug; empty domains allowed
    let (s, v) = post(
        "/api/orgs/register",
        json!({"slug": "regorg1", "name": "", "domains": []}),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v.get("slug").and_then(|x| x.as_str()), Some("regorg1"));
    assert_eq!(v.get("name").and_then(|x| x.as_str()), Some("regorg1"));
    assert_eq!(v.get("ai_profile"), Some(&Value::Null));
    // duplicate -> 409 with slug
    let (s, v) = post(
        "/api/orgs/register",
        json!({"slug": "regorg1", "domains": []}),
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT);
    assert_eq!(v.get("slug").and_then(|x| x.as_str()), Some("regorg1"));
    // invalid ai_profile -> 400 with allowed list
    let (s, v) = post(
        "/api/orgs/register",
        json!({"slug": "regorg2", "domains": [], "ai_profile": "nope"}),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert!(v.get("allowed").and_then(|a| a.as_array()).is_some());
}

#[tokio::test]
async fn test_status_lifecycle() {
    let (s, v) = post(
        "/api/orgs/lifeorg/findings/l1/status",
        json!({"status": "mitigated", "note": "patched Bulb"}),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v.get("org").and_then(|o| o.as_str()), Some("lifeorg"));
    let f = v.get("finding").expect("finding");
    assert_eq!(f.get("status").and_then(|x| x.as_str()), Some("MITIGATED"));
    let hist = f.get("status_history").and_then(|h| h.as_array()).unwrap();
    let last = hist.last().unwrap();
    assert_eq!(last.get("from").and_then(|x| x.as_str()), Some("OPEN"));
    assert_eq!(last.get("to").and_then(|x| x.as_str()), Some("MITIGATED"));
    assert_eq!(last.get("by").and_then(|x| x.as_str()), Some("user"));
    // invalid status + unknown id
    let (s, _) = post(
        "/api/orgs/lifeorg/findings/l1/status",
        json!({"status": "nope"}),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, _) = post(
        "/api/orgs/lifeorg/findings/zz/status",
        json!({"status": "RESOLVED"}),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_comment_feedback() {
    let (s, v) = post(
        "/api/orgs/lifeorg/findings/l2/comment",
        json!({"note": "looks fine"}),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let f = v.get("finding").expect("finding");
    let fb = f
        .get("feedback")
        .and_then(|x| x.as_array())
        .expect("feedback key");
    assert_eq!(
        fb.last().unwrap().get("by").and_then(|x| x.as_str()),
        Some("analyst")
    );
    assert_eq!(
        fb.last().unwrap().get("note").and_then(|x| x.as_str()),
        Some("looks fine")
    );
    // empty note + unknown id
    let (s, _) = post(
        "/api/orgs/lifeorg/findings/l2/comment",
        json!({"note": "  "}),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, _) = post(
        "/api/orgs/lifeorg/findings/zz/comment",
        json!({"note": "x"}),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_history_newest_first() {
    // generate two ordered events, then assert descending timestamps
    post(
        "/api/orgs/lifeorg/findings/l2/comment",
        json!({"note": "hist-a"}),
    )
    .await;
    post(
        "/api/orgs/lifeorg/findings/l2/status",
        json!({"status": "IN_PROGRESS"}),
    )
    .await;
    let (s, v) = get("/api/orgs/lifeorg/history", true).await;
    assert_eq!(s, StatusCode::OK);
    let evs = v.get("events").and_then(|e| e.as_array()).unwrap();
    assert!(evs.len() >= 2);
    let ts: Vec<&str> = evs
        .iter()
        .filter_map(|e| e.get("ts").and_then(|t| t.as_str()))
        .collect();
    let mut sorted = ts.clone();
    sorted.sort();
    sorted.reverse();
    assert_eq!(ts, sorted, "history must be newest-first");
    assert!(v.get("summary").and_then(|x| x.get("total")).is_some());
}

#[tokio::test]
async fn test_admin_logs_shape() {
    post(
        "/api/orgs/lifeorg/findings/l2/comment",
        json!({"note": "log-probe"}),
    )
    .await;
    let (s, v) = get("/api/admin/logs?limit=50", true).await;
    assert_eq!(s, StatusCode::OK);
    let logs = v.get("logs").and_then(|l| l.as_array()).expect("logs");
    assert!(v.get("total").and_then(|t| t.as_u64()).is_some());
    assert!(logs
        .iter()
        .any(|l| l.get("kind").and_then(|k| k.as_str()) == Some("comment")));
}

#[tokio::test]
async fn test_capabilities_shape() {
    let (s, v) = get("/api/ai/capabilities", true).await;
    assert_eq!(s, StatusCode::OK);
    assert!(v.get("default_profile").is_some());
    assert!(v.get("profiles").and_then(|p| p.as_array()).is_some());
    assert_eq!(
        v.get("prompt_version").and_then(|p| p.as_str()),
        Some("cti-v1")
    );
}

#[tokio::test]
async fn test_ai_profile_roundtrip() {
    let (s, v) = get("/api/orgs/lifeorg/ai_profile", true).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v.get("slug").and_then(|x| x.as_str()), Some("lifeorg"));
    assert!(v.get("ai_profile").is_some());
    assert!(v.get("effective").is_some());
    assert!(v.get("capabilities").is_some());
    // clear
    let (s, v) = post("/api/orgs/lifeorg/ai_profile", json!({"ai_profile": ""})).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v.get("ai_profile"), Some(&Value::Null));
    // invalid
    let (s, v) = post(
        "/api/orgs/lifeorg/ai_profile",
        json!({"ai_profile": "nope"}),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert!(v.get("allowed").is_some());
}

#[tokio::test]
async fn test_scan_queue_and_status() {
    // scanorg has no domains: deterministic fast path, no network
    let (s, v) = post("/api/orgs/scanorg/scan", json!({"mode": "fast"})).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v.get("queued").and_then(|q| q.as_bool()), Some(true));
    assert_eq!(v.get("mode").and_then(|m| m.as_str()), Some("fast"));
    assert_eq!(v.get("ai_profile"), Some(&Value::Null));
    let jid = v
        .get("job_id")
        .and_then(|j| j.as_str())
        .unwrap()
        .to_string();
    // poll to terminal state
    let mut terminal = String::new();
    for _ in 0..100 {
        let (s, v) = get(&format!("/api/orgs/scanorg/scan/{}", jid), true).await;
        assert_eq!(s, StatusCode::OK);
        let st = v
            .get("status")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        if st == "done" || st == "failed" {
            terminal = st;
            assert!(v.get("elapsed").is_some());
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(
        !terminal.is_empty(),
        "scan job never reached terminal state"
    );
    // unknown job -> 404 envelope
    let (s, v) = get("/api/orgs/scanorg/scan/does-not-exist", true).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert_eq!(v.get("error").and_then(|e| e.as_str()), Some("unknown job"));
    assert_eq!(v.get("kind").and_then(|k| k.as_str()), Some("scan"));
}

#[tokio::test]
async fn test_login_logout_session() {
    // login with injected peer addr (ConnectInfo)
    let mut req = Request::builder()
        .uri("/api/login")
        .method("POST")
        .header("authorization", "Basic dGVzdGVyOnB3") // tester:pw
        .body(Body::empty())
        .unwrap();
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 5001))));
    let resp = app().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let cookie = resp
        .headers()
        .get("set-cookie")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .split(';')
        .next()
        .unwrap_or("")
        .to_string();
    assert!(cookie.starts_with("cti_session="), "got {}", cookie);
    // bad password -> 401
    let mut bad = Request::builder()
        .uri("/api/login")
        .method("POST")
        .header("authorization", "Basic dGVzdGVyOndyb25n")
        .body(Body::empty())
        .unwrap();
    bad.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 5002))));
    let resp = app().oneshot(bad).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    // logout invalidates server-side
    let req = Request::builder()
        .uri("/api/logout")
        .method("POST")
        .header("cookie", cookie.clone())
        .body(Body::empty())
        .unwrap();
    let resp = app().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let req = Request::builder()
        .uri("/api/orgs")
        .header("cookie", cookie)
        .body(Body::empty())
        .unwrap();
    let (s, _) = body_json(app().oneshot(req).await.unwrap()).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_openhack_models_no_binary() {
    // CTI_OPENHACK_BIN is unset in tests -> 503 (mirrors Python)
    let (s, v) = get("/api/openhack/models", true).await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE);
    assert!(v.get("error").is_some());
}

#[tokio::test]
async fn test_openhack_config_shape() {
    let (s, v) = post(
        "/api/orgs/lifeorg/openhack-config",
        json!({"enabled": true, "model": "glm-5.3-flash"}),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v.get("slug").and_then(|x| x.as_str()), Some("lifeorg"));
    assert_eq!(
        v.get("openhack_enabled").and_then(|x| x.as_bool()),
        Some(true)
    );
    // gates: opt-out -> 403
    post(
        "/api/orgs/lifeorg/openhack-config",
        json!({"enabled": false}),
    )
    .await;
    let (s, _) = post("/api/orgs/lifeorg/openhack-scan", json!({"mode": "quick"})).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_static_and_security_headers() {
    let req = Request::builder().uri("/").body(Body::empty()).unwrap();
    let resp = app().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let h = resp.headers();
    assert_eq!(
        h.get("x-content-type-options")
            .and_then(|v| v.to_str().ok()),
        Some("nosniff")
    );
    assert_eq!(
        h.get("x-frame-options").and_then(|v| v.to_str().ok()),
        Some("DENY")
    );
    // dashboard must be served as HTML (mirrors Python HTMLResponse),
    // otherwise browsers render it as plain text
    let ct = h
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(ct.starts_with("text/html"), "got {}", ct);
    let req = Request::builder()
        .uri("/static/vis-network.min.js")
        .body(Body::empty())
        .unwrap();
    let resp = app().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let req = Request::builder().uri("/").body(Body::empty()).unwrap();
    let resp = app().oneshot(req).await.unwrap();
    let body = axum::body::to_bytes(resp.into_body(), 2 * 1024 * 1024)
        .await
        .unwrap();
    let html = String::from_utf8_lossy(&body);
    assert!(html.contains("value=\"glm-5.3-flash\""));
    assert!(!html.contains("ox-alpha"));
}

#[tokio::test]
async fn test_report_pdf_no_chromium() {
    // no chromium in test env -> 503 (mirrors Python); if one exists the
    // render path is exercised instead — either way the shape is asserted
    let (s, v) = get("/api/orgs/torg/report.pdf", true).await;
    if s == StatusCode::SERVICE_UNAVAILABLE {
        assert!(v.get("error").is_some());
    } else {
        assert_eq!(s, StatusCode::OK);
    }
}
