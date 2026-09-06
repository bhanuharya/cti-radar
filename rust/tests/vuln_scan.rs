//! Focused local-only security tests for the Rust vulnerability lookup/Nuclei port.

use chrono::{Duration, Utc};
use cti_radar::vuln_scan::{prepare_nuclei, ActiveGate};
use serde_json::json;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

#[test]
fn inactive_gate_rejects_before_binary_lookup() {
    let org = json!({"domains": ["example.com"]});
    let gate = ActiveGate {
        active: false,
        isolated: true,
        allowed_domains: "example.com".into(),
        roe_expires: (Utc::now() + Duration::hours(1)).to_rfc3339(),
    };
    let calls = AtomicUsize::new(0);

    let result = prepare_nuclei(&gate, &org, Utc::now(), || {
        calls.fetch_add(1, Ordering::SeqCst);
        Ok(PathBuf::from("/safe/nuclei"))
    });

    assert_eq!(result.unwrap_err(), "CTI_VULN_ACTIVE must equal 1");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "binary lookup must not run before the active gate"
    );
}

#[test]
fn active_gate_rejects_malformed_allowed_scope_and_expired_roe() {
    let org = json!({"domains": ["example.com"]});
    let now = Utc::now();
    let base = ActiveGate {
        active: true,
        isolated: true,
        allowed_domains: "example.com".into(),
        roe_expires: (now + Duration::hours(1)).to_rfc3339(),
    };

    let mut malformed = base.clone();
    malformed.allowed_domains = "example.com,https://evil.example".into();
    assert_eq!(
        cti_radar::vuln_scan::authorization_error(&malformed, &org, now),
        Some("CTI_VULN_ALLOWED_DOMAINS contains an invalid domain".into())
    );

    let mut out_of_scope = base.clone();
    out_of_scope.allowed_domains = "other.example".into();
    assert_eq!(
        cti_radar::vuln_scan::authorization_error(&out_of_scope, &org, now),
        Some("registered target domain outside CTI_VULN_ALLOWED_DOMAINS".into())
    );

    let mut expired = base;
    expired.roe_expires = (now - Duration::seconds(1)).to_rfc3339();
    assert_eq!(
        cti_radar::vuln_scan::authorization_error(&expired, &org, now),
        Some("CTI_VULN_ROE_EXPIRES is expired".into())
    );
}

#[test]
fn request_options_reject_bad_engine_severity_and_tags() {
    use cti_radar::vuln_scan::normalize_request_options;

    assert_eq!(
        normalize_request_options("other", None, None).unwrap_err(),
        "invalid engine (passive|nuclei)"
    );
    assert_eq!(
        normalize_request_options("nuclei", Some(&["critical".into(), "bad".into()]), None)
            .unwrap_err(),
        "invalid nuclei severity filter"
    );
    assert_eq!(
        normalize_request_options("nuclei", None, Some(&["bad tag!!".into()])).unwrap_err(),
        "invalid nuclei tag filter"
    );
    let many_tags: Vec<String> = (0..21).map(|n| format!("tag{}", n)).collect();
    assert_eq!(
        normalize_request_options("nuclei", None, Some(&many_tags)).unwrap_err(),
        "too many nuclei tags (max 20)"
    );
}

#[test]
fn nuclei_jsonl_filters_scope_caps_severity_and_builds_safe_argv() {
    use cti_radar::vuln_scan::{build_argv, canonical_runner_target, parse_jsonl, NucleiConfig};

    assert_eq!(
        canonical_runner_target(
            "app.example.com",
            &json!({"url": "http://app.example.com:8080/ignored?q=1"}),
        ),
        "http://app.example.com:8080"
    );
    assert_eq!(
        canonical_runner_target(
            "app.example.com",
            &json!({"url": "https://user@evil.example/"}),
        ),
        "https://app.example.com"
    );

    let lines = [
        json!({
            "template-id": "CVE-2021-41733",
            "matched-at": "https://app.example.com/cgi-bin/.%2e/",
            "matcher-name": "path",
            "info": {
                "name": "Apache traversal CVE-2021-41733",
                "severity": "critical",
                "tags": ["cve", "apache"],
                "classification": {"cve-id": ["CVE-2021-41733", "CVE-99"]}
            }
        }).to_string(),
        json!({"template-id": "bad id!!", "matched-at": "https://app.example.com/x", "info": {"name": "bad"}}).to_string(),
        json!({"template-id": "safe", "matched-at": "https://evil.example/x", "info": {"name": "external"}}).to_string(),
        json!({"template-id": "safe", "matched-at": "https://127.0.0.1/x", "info": {"name": "raw ip"}}).to_string(),
        "not-json".into(),
    ].join("\n");
    let findings = parse_jsonl(&lines, "acme", &["example.com".into()]);
    assert_eq!(findings.len(), 1);
    let finding = &findings[0];
    assert_eq!(finding["severity"], "HIGH");
    assert_eq!(finding["related_cves"], json!(["CVE-2021-41733"]));
    assert_eq!(
        finding["identity_key"],
        "nuclei|app.example.com|cve-2021-41733|/cgi-bin/.%2e/"
    );
    assert!(finding["status_detail"]
        .as_str()
        .unwrap()
        .starts_with("NUCLEI-MATCHED"));

    let config = NucleiConfig {
        binary: PathBuf::from("/safe/nuclei"),
        templates: PathBuf::from("/safe/templates"),
        rate_limit: 20,
        timeout_secs: 300,
        interactsh: false,
        exclude_tags: vec!["intrusive".into(), "dos".into(), "fuzz".into()],
    };
    let argv = build_argv(&config, "/tmp/targets", "/tmp/out", &["high".into()], &[]);
    assert_eq!(argv[0], "/safe/nuclei");
    for flag in ["-duc", "-ni", "-or", "-nm", "-silent"] {
        assert!(argv.iter().any(|a| a == flag), "missing {flag}");
    }
    assert!(argv
        .windows(2)
        .any(|w| w == ["-exclude-tags", "intrusive,dos,fuzz"]));
    assert!(!argv.iter().any(|a| a.contains("store-resp")));
}

#[test]
fn nuclei_parser_caps_processed_events_not_only_valid_findings() {
    let mut lines = vec!["not-json".to_string(); 500];
    lines.push(
        json!({
            "template-id": "late", "matched-at": "https://app.example.com/",
            "info": {"name": "must not be parsed", "severity": "low"}
        })
        .to_string(),
    );
    assert!(
        cti_radar::vuln_scan::parse_jsonl(&lines.join("\n"), "acme", &["example.com".into()])
            .is_empty()
    );
}

#[test]
fn nuclei_cves_reject_partial_tokens() {
    let event = json!({
        "template-id": "safe", "matched-at": "https://app.example.com/",
        "info": {"name": "CVE-2021-41733-extra", "severity": "low"}
    });
    let finding = cti_radar::vuln_scan::map_event("acme", &event, &["example.com".into()]).unwrap();
    assert_eq!(finding["related_cves"], json!([]));
}

fn route_test_app() -> axum::Router {
    let root = std::env::temp_dir().join(format!("cti-vuln-route-{}", uuid::Uuid::new_v4()));
    let org_dir = root.join("orgs/acme");
    std::fs::create_dir_all(&org_dir).unwrap();
    std::fs::write(
        root.join("orgs.json"),
        json!({"acme": {"name": "Acme", "domains": ["example.com"], "findings": "data/orgs/acme/findings.json", "baseline": "data/orgs/acme/baseline.txt"}}).to_string(),
    ).unwrap();
    std::fs::write(
        org_dir.join("findings.json"),
        json!({"meta": {"fingerprints": {"app.example.com": {"url": "https://app.example.com", "code": "200", "server": "nginx/1.18.0", "versions": [{"product": "nginx", "version": "1.18.0"}]}}}, "findings": []}).to_string(),
    ).unwrap();
    std::fs::write(org_dir.join("baseline.txt"), "app.example.com\n").unwrap();
    std::fs::write(org_dir.join("history.json"), "[]").unwrap();
    let cfg = cti_radar::config::Config {
        user: "tester".into(),
        password: "pw".into(),
        scan_token: "vuln-test-token".into(),
        data_dir: root.clone(),
        state_dir: root,
        host: "127.0.0.1".into(),
        port: 0,
        wildcard_filter: true,
        nvd_enrich: false,
        nvd_api_key: String::new(),
        nvd_max_lookups: 20,
        job_stale_secs: 1800,
        max_active_jobs: 8,
        resolve_after: 3,
        chromium_path: None,
        ai_config_file: None,
        opencode_go_b_api_key: String::new(),
        openhack_bin: None,
        openhack_active: false,
        openhack_isolated: false,
        openhack_allowed_domains: String::new(),
        openhack_roe_expires: String::new(),
        openhack_model: String::new(),
        openhack_scans_dir: None,
        openhack_quick_budget: 480,
    };
    cti_radar::correlation::init(cfg.clone());
    cti_radar::auth::init(cfg.clone());
    cti_radar::jobs::init(cfg.clone());
    cti_radar::logs::init(&cfg.data_dir);
    cti_radar::build_router(cti_radar::AppState::new(cfg))
}

async fn route_json(
    app: axum::Router,
    request: axum::http::Request<axum::body::Body>,
) -> (axum::http::StatusCode, serde_json::Value) {
    use tower::ServiceExt;
    let response = app.oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

#[tokio::test]
async fn vuln_routes_require_auth_validate_and_publish_job_status() {
    let request = axum::http::Request::builder()
        .uri("/api/vuln/engines")
        .body(axum::body::Body::empty())
        .unwrap();
    let (status, _) = route_json(route_test_app(), request).await;
    assert_eq!(status, axum::http::StatusCode::UNAUTHORIZED);

    let engines = axum::http::Request::builder()
        .uri("/api/vuln/engines")
        .header("X-CTI-Token", "vuln-test-token")
        .body(axum::body::Body::empty())
        .unwrap();
    let (status, engines) = route_json(route_test_app(), engines).await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert!(engines["passive"]["checks"]
        .as_array()
        .unwrap()
        .iter()
        .any(|value| value == "login"));

    let invalid = axum::http::Request::builder()
        .uri("/api/orgs/acme/vuln-scan")
        .method("POST")
        .header("X-CTI-Token", "vuln-test-token")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            json!({"engine": "invalid"}).to_string(),
        ))
        .unwrap();
    let (status, _) = route_json(route_test_app(), invalid).await;
    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);

    let bad_severity = axum::http::Request::builder()
        .uri("/api/orgs/acme/vuln-scan")
        .method("POST")
        .header("X-CTI-Token", "vuln-test-token")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            json!({"engine": "nuclei", "nuclei_severity": ["bogus"]}).to_string(),
        ))
        .unwrap();
    let (status, _) = route_json(route_test_app(), bad_severity).await;
    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);

    let queue = axum::http::Request::builder()
        .uri("/api/orgs/acme/vuln-scan").method("POST")
        .header("X-CTI-Token", "vuln-test-token").header("content-type", "application/json")
        .body(axum::body::Body::from(json!({"engine": "passive", "targets": ["app.example.com"], "checks": ["cve"], "refresh": false}).to_string())).unwrap();
    let (status, payload) = route_json(route_test_app(), queue).await;
    assert_eq!(status, axum::http::StatusCode::OK);
    let job_id = payload["job_id"].as_str().unwrap().to_string();
    for _ in 0..40 {
        let poll = axum::http::Request::builder()
            .uri(format!("/api/orgs/acme/vuln-scan/{job_id}"))
            .header("X-CTI-Token", "vuln-test-token")
            .body(axum::body::Body::empty())
            .unwrap();
        let (status, payload) = route_json(route_test_app(), poll).await;
        assert_eq!(status, axum::http::StatusCode::OK);
        if payload["status"] == "done" {
            assert_eq!(payload["result"]["engine"], "passive");
            return;
        }
        assert_ne!(payload["status"], "failed", "{payload}");
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    panic!("vuln-scan job did not become done");
}

#[test]
fn nuclei_scope_rejects_cached_external_host_before_execution() {
    let org = json!({"domains": ["example.com"]});
    let cached =
        json!({"meta": {"fingerprints": {"evil.example": {"url": "https://evil.example"}}}});
    assert_eq!(
        cti_radar::vuln_scan::active_nuclei_targets(&org, &cached, &["evil.example".into()],)
            .unwrap_err(),
        "nuclei target outside registered org domain: evil.example"
    );
}

#[test]
fn nuclei_child_environment_excludes_credentials_and_proxy_variables() {
    use std::ffi::OsString;

    let environment = vec![
        (OsString::from("PATH"), OsString::from("/usr/bin")),
        (OsString::from("HOME"), OsString::from("/home/cti")),
        (OsString::from("LANG"), OsString::from("C.UTF-8")),
        (
            OsString::from("CTI_SCAN_TOKEN"),
            OsString::from("must-not-reach-child"),
        ),
        (
            OsString::from("HERMES_CUSTOM_API_CLINE_BOT_API_KEY"),
            OsString::from("must-not-reach-child"),
        ),
        (
            OsString::from("HTTPS_PROXY"),
            OsString::from("http://proxy.invalid"),
        ),
        (
            OsString::from("UNRELATED_VALUE"),
            OsString::from("must-not-reach-child"),
        ),
    ];
    let cleaned = cti_radar::vuln_scan::safe_nuclei_child_env(&environment);
    let keys: Vec<String> = cleaned
        .iter()
        .map(|(key, _)| key.to_string_lossy().into_owned())
        .collect();
    assert_eq!(keys, vec!["PATH", "HOME", "LANG"]);
}

#[test]
fn engine_availability_is_true_only_after_generic_gate_and_runtime_checks() {
    use cti_radar::vuln_scan::{active_gate_setup_error, ActiveGate};
    let now = Utc::now();
    let gate = ActiveGate {
        active: true,
        isolated: true,
        allowed_domains: "example.com,api.example.com".into(),
        roe_expires: (now + Duration::hours(1)).to_rfc3339(),
    };
    assert!(active_gate_setup_error(&gate, now).is_none());

    let mut inactive = gate;
    inactive.active = false;
    assert_eq!(
        active_gate_setup_error(&inactive, now),
        Some("CTI_VULN_ACTIVE must equal 1".into())
    );
}

#[test]
fn nuclei_configuration_requires_absolute_binary_and_clamps_limits() {
    use cti_radar::vuln_scan::{resolve_nuclei_runtime, NucleiSettings};
    let templates = std::env::temp_dir().join(format!("nuclei-templates-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&templates).unwrap();
    let relative = NucleiSettings {
        bin: Some("nuclei".into()),
        templates: Some(templates.clone()),
        severity: None,
        tags: None,
        exclude_tags: None,
        rate_limit: Some("999".into()),
        timeout_secs: Some("10".into()),
        interactsh: false,
    };
    assert_eq!(
        resolve_nuclei_runtime(&relative, || Some(PathBuf::from("/bin/false"))).unwrap_err(),
        "CTI_NUCLEI_BIN must be an absolute executable"
    );
    let configured = NucleiSettings {
        bin: Some("/bin/false".into()),
        ..relative
    };
    let runtime = resolve_nuclei_runtime(&configured, || None).unwrap();
    assert_eq!(runtime.config.rate_limit, 150);
    assert_eq!(runtime.config.timeout_secs, 60);
    assert_eq!(runtime.severity, vec!["critical", "high", "medium"]);
    assert!(runtime.config.exclude_tags.iter().any(|tag| tag == "dos"));
    assert!(runtime.config.exclude_tags.iter().any(|tag| tag == "fuzz"));
    let _ = std::fs::remove_dir_all(templates);
}

#[test]
fn nuclei_runner_reports_child_failure_without_network() {
    use cti_radar::vuln_scan::{run_nuclei_blocking, NucleiConfig};
    let templates = std::env::temp_dir().join(format!("nuclei-run-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&templates).unwrap();
    let config = NucleiConfig {
        binary: PathBuf::from("/bin/false"),
        templates: templates.clone(),
        rate_limit: 1,
        timeout_secs: 60,
        interactsh: false,
        exclude_tags: vec!["dos".into(), "fuzz".into()],
    };
    let error = run_nuclei_blocking(
        &config,
        &["https://example.com".into()],
        &["high".into()],
        &[],
    )
    .unwrap_err();
    assert!(error.starts_with("nuclei exited"), "{error}");
    let _ = std::fs::remove_dir_all(templates);
}

#[cfg(unix)]
#[test]
fn nuclei_exit_one_with_jsonl_output_is_parsed_as_a_completed_run() {
    use cti_radar::vuln_scan::{run_nuclei_blocking, NucleiConfig};
    use std::os::unix::fs::PermissionsExt;
    let root = std::env::temp_dir().join(format!("nuclei-exit-one-{}", uuid::Uuid::new_v4()));
    let templates = root.join("templates");
    std::fs::create_dir_all(&templates).unwrap();
    let binary = root.join("nuclei-stub");
    std::fs::write(&binary, "#!/bin/sh\nwhile [ \"$1\" != \"-o\" ]; do shift; done\nprintf '%s\\n' '{\"template-id\":\"safe\"}' > \"$2\"\nexit 1\n").unwrap();
    std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700)).unwrap();
    let config = NucleiConfig {
        binary,
        templates,
        rate_limit: 1,
        timeout_secs: 60,
        interactsh: false,
        exclude_tags: vec!["dos".into(), "fuzz".into()],
    };
    let output = run_nuclei_blocking(
        &config,
        &["https://example.com".into()],
        &["high".into()],
        &[],
    )
    .unwrap();
    assert!(output.contains("template-id"));
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn nuclei_merge_deduplicates_by_identity() {
    let existing = vec![json!({"identity_key": "nuclei|app.example.com|one|/"})];
    let candidates = vec![
        json!({"identity_key": "nuclei|app.example.com|one|/"}),
        json!({"identity_key": "nuclei|app.example.com|two|/"}),
    ];
    let fresh = cti_radar::vuln_scan::dedup_nuclei_findings(&existing, candidates);
    assert_eq!(fresh.len(), 1);
    assert_eq!(fresh[0]["identity_key"], "nuclei|app.example.com|two|/");
}

#[test]
fn dashboard_exposes_vuln_controls_without_replacing_openhack_glm_control() {
    let html = include_str!("../../app/dashboard.html");
    assert!(html.contains("id=\"ws-vuln-scan\""));
    assert!(html.contains("id=\"vulnengine\""));
    assert!(html.contains("value=\"nuclei\""));
    assert!(html.contains("value=\"glm-5.3-flash\""));
}

#[test]
fn nuclei_template_path_expands_home_shorthand() {
    assert_eq!(
        cti_radar::vuln_scan::expand_tilde_path(
            std::path::Path::new("~/nuclei-templates"),
            std::path::Path::new("/home/tester"),
        ),
        PathBuf::from("/home/tester/nuclei-templates")
    );
}
