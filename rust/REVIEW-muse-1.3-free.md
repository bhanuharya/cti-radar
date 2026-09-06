[0m
> build · muse-spark-1.3-contributor-free
[0m
Fixing your audit — cross-checking the Rust port against the spec.
[0m→ [0mRead .
[0m→ [0mRead rust
[0m→ [0mRead app
[0m→ [0mRead rust/src
[0m→ [0mRead rust/PORT.md
[0m→ [0mRead rust/Cargo.toml
Spec and file map clear — now probing auth, API parity, and scanner internals.
[0m• [0maudit auth+security paths[90m General Agent[0m
[0m• [0maudit API correctness[90m General Agent[0m
[0m• [0maudit Rust quality+deps[90m General Agent[0m
[0m✓ [0maudit API correctness[90m General Agent[0m
[0m✓ [0maudit auth+security paths[90m General Agent[0m
[0m✓ [0maudit Rust quality+deps[90m General Agent[0m
Initial sweeps flagged gaps — now verifying the critical claims before ranking.
[0m
[0m$ [0mrg -n "unwrap|expect\(|panic!|lookup_host|Policy::none|valid_slug|from_fn|atomic_write|0\.0\.0\.0|X-CTI-Token|subtle|par_iter|std::fs|Command::|TooManyRequests|Conflict" rust/src --max-count=2 | head -n 120; echo ---; rg -n "route|/api/|/static" rust/src/main.rs | head -n 60
rust/src/handlers.rs:15:pub(crate) fn valid_slug(slug: &str) -> bool {
rust/src/handlers.rs:29:    if !valid_slug(slug) {
rust/src/handlers_mut.rs:6:use crate::handlers::{require_org, valid_slug};
rust/src/handlers_mut.rs:62:        .unwrap_or_else(|| slugify(&valid_domains[0]));
rust/src/main.rs:112:        .layer(middleware::from_fn(security_headers))
rust/src/main.rs:120:            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
rust/src/correlation.rs:15:use std::fs;
rust/src/correlation.rs:61:    CFG.get().expect("correlation::init must be called first")
rust/src/error.rs:21:    Conflict(String),
rust/src/error.rs:23:    TooManyRequests(u64),
rust/src/report.rs:12:    let name = org.get("name").and_then(|v| v.as_str()).unwrap_or(slug);
rust/src/report.rs:18:        let s = f.get("severity").and_then(|v| v.as_str()).unwrap_or("INFO");
rust/src/cve_match.rs:13:    RE.get_or_init(|| Regex::new(r"^(\d+)([A-Za-z]{0,3}\d*)$").unwrap())
rust/src/cve_match.rs:18:    RE.get_or_init(|| Regex::new(r"^(>=|<=|=|>|<)\s*(.+)$").unwrap())
rust/src/config.rs:44:    env::var(name).unwrap_or_default()
rust/src/config.rs:48:    match env::var(name).unwrap_or_default().trim() {
rust/src/openhack_handlers.rs:34:    let model = body.model.clone().unwrap_or_default().trim().to_string();
rust/src/openhack_handlers.rs:61:    cc::atomic_write_json(&path, &Value::Object(registry)).map_err(AppError::from)?;
rust/src/scanner.rs:52:    RE.get_or_init(|| fancy_regex::Regex::new(r"^[a-z0-9-]{1,32}$").unwrap())
rust/src/scanner.rs:61:        .unwrap()
rust/src/auth.rs:14:use subtle::ConstantTimeEq;
rust/src/auth.rs:26:    CFG.get().expect("auth::init must be called first")
rust/src/jobs.rs:22:    CFG.get().expect("jobs::init must be called first")
rust/src/jobs.rs:52:    let d = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
rust/src/openhack.rs:13:    let p = std::env::var("CTI_OPENHACK_BIN").unwrap_or_default();
rust/src/openhack.rs:21:        let meta = std::fs::metadata(p).ok()?;
rust/src/ai.rs:15:    RE.get_or_init(|| Regex::new(r"^[A-Za-z_][A-Za-z0-9_]*$").unwrap())
rust/src/ai.rs:126:    let raw = if raw.as_object().map(|o| o.is_empty()).unwrap_or(true)
---
35:fn build_router(state: AppState) -> Router {
42:        .route(
52:        .route("/api/login", post(h::api_login))
53:        .route("/api/logout", post(h::api_logout))
55:        .route("/api/graph", get(h::api_graph))
56:        .route("/api/summary", get(h::api_summary))
57:        .route("/api/fleet", get(h::api_fleet))
58:        .route("/api/ips", get(h::api_ips))
59:        .route("/api/findings", get(h::api_findings))
60:        .route("/api/dashboard", get(h::api_dashboard))
61:        .route("/api/orgs", get(h::api_orgs))
62:        .route("/api/admin/logs", get(h::api_admin_logs))
63:        .route("/api/ai/capabilities", get(h::api_ai_capabilities))
64:        .route("/api/openhack/models", get(h::api_openhack_models))
65:        .route("/api/orgs/{slug}/ai_profile", get(h::api_get_ai_profile))
66:        .route("/api/findings/{id}", get(h::api_finding_detail))
67:        .route("/api/orgs/{slug}", get(h::api_org_get))
68:        .route("/api/orgs/{slug}/dashboard", get(h::api_org_dashboard))
69:        .route("/api/orgs/{slug}/history", get(h::api_org_history))
70:        .route("/api/orgs/{slug}/report.pdf", get(h::api_report_pdf))
72:        .route("/api/orgs/register", post(hm::api_org_register))
73:        .route("/api/orgs/{slug}/scan", post(hm::api_org_scan))
74:        .route("/api/orgs/{slug}/scan/{job_id}", get(hm::api_scan_status))
75:        .route("/api/orgs/{slug}/recheck", post(hm::api_org_recheck))
76:        .route(
77:            "/api/orgs/{slug}/recheck/{job_id}",
80:        .route("/api/orgs/{slug}/correlate", post(hm::api_org_correlate))
81:        .route(
82:            "/api/orgs/{slug}/correlate/{job_id}",
85:        .route("/api/orgs/{slug}/ai-grade", post(hm::api_org_ai_grade))
86:        .route(
87:            "/api/orgs/{slug}/ai-grade/{job_id}",
90:        .route("/api/orgs/{slug}/domains", post(hm::api_org_domains))
91:        .route("/api/orgs/{slug}/ai_profile", post(hm::api_set_ai_profile))
92:        .route(
93:            "/api/orgs/{slug}/openhack-config",
96:        .route(
97:            "/api/orgs/{slug}/openhack-scan",
100:        .route(
101:            "/api/orgs/{slug}/openhack-scan/{job_id}",
104:        .route(
105:            "/api/orgs/{slug}/findings/{id}/status",
108:        .route(
109:            "/api/orgs/{slug}/findings/{id}/comment",
135:    let app = build_router(state);
[0m
# Verdict: NEEDS-WORK

## Critical findings (MUST-FIX)
1. **JSON shapes incompatible — drop-in swap broken.** `GET /api/findings` returns bare array `handlers.rs:139-161` vs Python `{findings_total,findings}` `app/main.py:584`; `GET /api/dashboard` returns `{org,findings,summary,graph}` `handlers.rs:183-209` vs `{org,summary,graph,fleet,ips,findings:{total,findings},history,scan_info}` `app/main.py:637-646`; `GET /api/findings/{id}` bare finding `handlers.rs:211-223` vs `{org,finding}` `app/main.py:674`; `GET /api/orgs` bare array `handlers.rs:225-228` vs `{orgs:[...]}` `app/main.py:681`. Fix: mirror Python envelopes exactly.
2. **Wrong status codes.** Global busy cap → `409` `handlers_mut.rs:141-146,189,213,312` + `openhack_handlers.rs:94-97` via `Conflict` `error.rs:42` vs Python `429` `app/main.py:130-136`; unknown `job_id` → `200 {status:unknown}` `jobs.rs:193-201` vs `404` `app/main.py:273-275`; OpenHack gates → `400` `openhack_handlers.rs:84-91` vs `403/503` `app/main.py:817-831`; empty POST body → `422` (axum `Json<ScanBody>` `handlers_mut.rs:129-134`) vs Python `body=None` proceeds. Fix: add `429` variant, `404` on unknown job, `403/503` gates, `Option<Json<..>>`.
3. **No `GET /static/*`.** Python mounts `app/static` `app/main.py:66-68`; `main.rs:40-50` serves only `GET /`. Dashboard sub-assets 404. Fix: `ServeDir`/`ServeFile`.
4. **`POST /api/logout` doesn't invalidate session.** Rust clears cookie only `handlers.rs:76-86`; Python deletes server-side `app/main.py:509-516`. Stolen cookie stays valid. Fix: remove session id from store.
5. **SSRF pinning missing (hickory declared, unused).** `Cargo.toml:52` + comment `scanner.rs:318` claim hickory, but `resolve()` uses `lookup_host` `scanner.rs:354-357`, `fetch_fingerprint` connects w/o IP pin `scanner.rs:577`, zero `hickory` imports. Fix: resolve via hickory, connect to pinned IP with `Host:` header, re-validate redirects (`Policy::none` `scanner.rs:326-327` alone is not TOCTOU-safe).
6. **`orgs.json` path + corruption handling diverge.** Register writes `orgs/{slug}/findings.json` `handlers_mut.rs:72-73` vs `data/orgs/...` `app/main.py:991-992`; corrupt registry → `unwrap_or_default(){}` overwrite `handlers_mut.rs:109-115` vs `500 registry corrupted` `app/main.py:984-985`. Fix: correct prefix, fail-closed on corrupt.
7. **Blocking fs/child on async paths (DoS).** `std::fs::write/read/remove` `report.rs:152,170,174-175`, `scanner.rs:1855,1864,1867,2669,3266,3372`, `correlation.rs:926,936,967` called from async handlers `handlers.rs:146,189,218`; `Command::wait_with_output` `openhack.rs:149-160` from async `handlers.rs:300-305`; no timeout on `lookup_host` `scanner.rs:354-362` or chromium `report.rs:154-167`. Fix: `tokio::fs`/`spawn_blocking`, `tokio::process` + `timeout(5-20s)`.
8. **Panics on external input.** `cve.as_object().unwrap()` `cve_match.rs:217`; `f.as_object_mut().unwrap()` `handlers_mut.rs:264,278,381`; `org_findings_path().unwrap()` `handlers_mut.rs:289,390`; corrupt `findings.json` entry kills task. Fix: `let Some(..) else continue` / `AppError::Internal`.
9. **Lock-poison DoS + error leakage.** `Mutex/RwLock::unwrap()` `auth.rs:65,92,115,136,141,192`, `jobs.rs:66,109,125,150,160,167`, `correlation.rs:103,120`; `Io/Json` → `500` echoing paths/serde internals `error.rs:47-55`. Fix: `unwrap_or_else(|e|e.into_inner())` or use declared `parking_lot` `Cargo.toml:42`; log full, return generic.
10. **Login rate-limit global.** `let ip="unknown"` `handlers.rs:41` vs per-IP `app/main.py:306-319,490`. One attacker locks out all logins. Fix: `ConnectInfo`/`X-Forwarded-For`.

## Major findings (MUST-FIX cont.)
- `GET /api/admin/logs` stub `{logs:[]}` `handlers.rs:270-277` vs `{logs,total}` newest-first + filter `app/main.py:684-694`. Fix: wire log ring. `handlers.rs:261-262` history order inverted (`rev().take().reverse()` oldest-first vs `[::-1][:100]` `app/main.py:1209`).
- `POST status/comment` return stubs `{id,status}`/`{id,commented}` `handlers_mut.rs:294-296,394-396` vs full finding `app/main.py:1237,1265`; `GET ai/capabilities` stub `{configured,providers}` `handlers.rs:279-288` vs `{default_profile,profiles, prompt_version}` `app/ai_providers.py:738-757`; `ai_profile` get/set wrong keys + no persist `handlers.rs:290-298`, `handlers_mut.rs:476-490`, `ai.rs:287-295` vs `app/main.py:900-925`, `app/ai_providers.py:772-828`.
- `openhack-scan` drops `mode`, ignores body `openhack_handlers.rs:75-80,120` vs `{queued,slug,mode,job_id}` `app/main.py:865`; `openhack-config` wrong key `{org,..}` `openhack_handlers.rs:64-66` vs `{slug,..}` `app/main.py:784-786`; job kind `"openhack"` `openhack_handlers.rs:94,129` vs `"ohack"` `app/main.py:837,878`.
- Env/config dead vars: `CTI_WILDCARD_FILTER` ignored (`scanner.rs:373-389` always filters), `CTI_NVD_MAX_LOOKUPS`/`RESOLVE_AFTER` hardcoded `scanner.rs:19-20,1903` though in `config.rs:21-28`; `CTI_NVD_MAX_LOOKUPS` unread in `cve_match.rs:296-388`; `CTI_OPENHACK_SCANS_DIR`/`CTI_OHACK_MODEL` absent from `config.rs` (read ad-hoc `openhack.rs:13`, `ai.rs:235`).
- Atomic-write exceptions: NVD cache plain `write/rename` no `0600` `cve_match.rs:328-342`; PDF temp `std::fs::write` umask-dependent `report.rs:152` vs `correlation.rs:874-919` (`0700` dir, `0600` tmp+rename — good).
- Unbounded `by`/`note` `handlers_mut.rs:362-379` (stored, rendered `report.rs`); add `by≤64`, `note≤4k` → `400`.

## Minor/nits (NICE-TO-HAVE)
- `tokio full` `Cargo.toml:15` bloat → `rt-multi-thread,macros,net,time,sync,io-util`; unused `futures`, `async-trait`, `parking_lot` (use or drop) `Cargo.toml:18-19,42`; dual `rand 0.8+0.10` in lock; `x509-parser 0.16` two behind `0.18` — run `cargo audit`.
- `fancy-regex 0.13` `Cargo.toml:48` backtracker on banners; mitigated by `chars().take(200-400)` truncation but prefer `regex`-only.
- `rayon par_iter` `correlation.rs:1591,1599` called from async `handlers.rs:147,189` steals Tokio workers; wrap in `spawn_blocking`.
- `correlate_org` checks only `is_empty()` `scanner.rs:2897-2899` (safe only via caller `require_org` `handlers_mut.rs:211`); `slugify` 48 vs 32 chars `scanner.rs:148-162` vs `handlers_mut.rs:91-107`; `is_global_ip` manual `scanner.rs:109-131` misses reserved/doc ranges vs `ip.is_global` `app/scanner.py:114-119`.
- `TooManyRequests(u64)` drops body value `error.rs:23`; axum `Json` rejects bypass `AppError` envelope → confirm `422` shape; `report.pdf` lacks `413/503` caps `app/main.py:1487-1498` (PORT.md `59` says HTML fallback — acceptable if documented).
- Safe unwraps need no change: `Regex::new().unwrap()` in `OnceCell`, `HeaderValue` statics, `expect` init `auth.rs:26,jobs.rs:22`, `main.rs:145` (prefer `expect`).

## Whats excellent
- Auth gate 1:1: `auth_ok` cookie-or-token + `subtle::ConstantTimeEq` `auth.rs:133-157,182-183` mirroring `secrets.compare_digest` `app/main.py:364,389`; `require_org` on every org route `handlers.rs:28-34`.
- Slug + traversal defense: `valid_slug` `handlers.rs:15-21` + `slug_re` `scanner.rs:50-53`, `resolve_registry_path` canonicalize+`starts_with` `correlation.rs:124-155`.
- PII mask parity: `mask_*` stack `correlation.rs:324-439`, `normalize_finding→mask_deep` `:1430-1474`, applied on findings/dashboard/detail/report `handlers.rs:147,189,220,334`.
- AI SSRF validator mirrors Python: `ai.rs:74-121` vs `app/ai_providers.py:96-133`; `Policy::none()+no_proxy` `scanner.rs:326-327`, `ai.rs:326-327`, `cve_match.rs:382-383`.
- Bind refusal `config.rs:163-171`+`main.rs:125-128`, headers middleware outer layer `main.rs:14-33,112` covering `AppError` `error.rs:32-66`, OpenHack fail-closed `openhack.rs:30-90` — all faithful.
- Deps: `reqwest default-features=false+rustls-tls` `Cargo.toml:22`, zero `openssl/native-tls` in lock, `rustls 0.23`/`tokio-rustls 0.26` pinned.
