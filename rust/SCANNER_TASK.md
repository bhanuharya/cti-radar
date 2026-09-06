# Task: Port scanner.py -> src/scanner.rs (async, Rust-native)

You are porting the CTI Radar passive scanner from Python to Rust. The Rust
crate is at `rust/` (cargo). The Python source of truth is
`/home/bhanuharya/code/cti-dashboard/app/scanner.py` (READ IT FIRST — it is
~4150 lines; read it in chunks via read_file with offset/limit).

## Existing Rust modules you build ON (do NOT rewrite them)
- `src/correlation.rs` — `load_data(org)`, `append_history(slug, event)`,
  `atomic_write_json`, `atomic_write_text`, `invalidate_org_cache`,
  `org_findings_path`, `ensure_identity`, `migrate_finding`, `identity_key`,
  `build_snapshot`, `diff_snapshot`, `now_iso`, `single_public_ip`,
  `CANONICAL_STATUSES`, `load_meta`. All `pub`.
- `src/cve_match.rs` — `match_cves(&[Value], cap) -> Vec<Value>`,
  `worst_confidence`, `nvd_enabled`, `nvd_lookup(cve, ttl).await`.
- `src/jobs.rs`, `src/config.rs` (Config has data_dir, state_dir, wildcard_filter,
  nvd_enrich, nvd_api_key, nvd_max_lookups, resolve_after, opencode_go_b_api_key).

## Current stub you REPLACE
`src/scanner.rs` currently only has `is_correlating` and a stub `generate_org`.
Replace with the full port. Keep the public signatures used by handlers_mut.rs:
- `pub fn is_correlating(slug: &str) -> bool`
- `pub async fn generate_org(org: Value, mode: &str, ai_profile: Option<String>, on_progress: Option<fn(&str,&str)>) -> Value`
  (NOTE: make on_progress a `Option<Arc<dyn Fn(&str,&str)+Send+Sync>>` if the
  current signature is inconvenient — but update handlers_mut.rs call site to match.)
- Also add: `pub async fn recheck_findings(slug: &str) -> usize`,
  `pub async fn correlate_org(org: Value) -> Value`,
  `pub async fn ai_grade_org(slug: &str) -> Value`,
  `pub fn read_history(slug: &str) -> Vec<Value>`,
  `pub fn append_history(slug: &str, event: Value)` (delegate to correlation).

## Scope (fast deterministic mode is the priority — it's what the benchmark measures)
Port faithfully, in order:
1. `_is_valid_domain`, `_is_global_ip` (SSRF: reject private/loopback/link-local/multicast).
2. Enum sources: `_subdomains_crtsh`, `_subdomains_certspotter`,
   `_subdomains_hackertarget`, `_subdomains_crtname`, `_subdomains_wayback`,
   `_subdomains_otx` + `_collect_names` + `_with_retries` + `enumerate_subdomains`.
   Use reqwest (rustls) with `--noproxy` equivalent (`.no_proxy()`), no redirects,
   size-limited body reads. Collect into a HashSet, cap ENUM_NAME_CAP.
3. DNS resolution: `_resolve` (A/AAAA), `_dns_pool` (shared resolver),
   `_detect_wildcard`, `_filter_wildcard_hosts`. Use hickory-resolver.
4. HTTP fingerprint: `_fetch_fingerprint` (GET/HEAD, capture status, server,
   x-powered-by, title via <title> regex, content-type). reqwest.
5. TCP service connect + banner: `_tcp_reachable`, `_grab_banner` (SSH/FTP/SMTP/
   MySQL greeting patterns -> {product, version} via `_banner_versions`).
   Use tokio::net::TcpStream + read with timeout.
6. TLS cert: `_tls_cert` (connect, capture cert expiry/self-signed via rustls).
7. InternetDB: `_internetdb` (GET https://internetdb.shodan.io/{ip}, cache in memory).
8. Findings synthesis — PORT ALL OF THESE faithfully, preserving the EXACT JSON
   field names, status_detail strings, severity, and dedup keys:
   `parse_versions`, `synthesize_surface_findings`, `synthesize_cert_findings`,
   `synthesize_login_findings`, `synthesize_version_findings`,
   `synthesize_cve_findings`, `synthesize_header_findings`,
   `_synthesize_diff_findings`, `_reconcile_findings`, `_refresh_finding_evidence`.
9. `generate_org` orchestration: enum -> resolve -> fingerprint -> TCP/TLS ->
   synthesize -> reconcile -> persist findings.json + baseline.txt (atomic,
   0600) + append_history. Return the SAME dict shape the Python returns
   ({"title","date","domains","subdomains","reachable","findings_total","..."}).
10. `recheck_findings`, `correlate_org`, `read_history`.

## Rust-native requirements (the whole point of the rewrite)
- ALL network I/O must be `async` on tokio, fan out with `futures::future::join_all`
  or `FuturesUnordered` (NOT spawn_blocking, NOT per-probe threads).
- Use a SINGLE shared reqwest::Client + ONE shared hickory resolver, cloned via
  Arc, across the whole scan.
- No `.unwrap()` on external input/network results — propagate as Option/Result
  and treat failures as empty/false (fail-open, same as Python).

## Data schema (EXACT — must match Python output byte-for-byte in JSON)
findings.json = `{"meta": {...}, "findings": [Finding]}`.
baseline.txt = newline-delimited "host" or "ip:port" strings.
Each Finding (serde_json::Value) fields mirror the Python dicts 1:1. Reuse
`correlation::identity_key`, `correlation::migrate_finding`,
`correlation::ensure_identity` for lifecycle/identity.

## Do NOT
- Touch dashboard.html, static/, cve_data.json, correlation.rs, cve_match.rs,
  auth.rs, jobs.rs, config.rs, error.rs, handlers*.rs, main.rs (except the
  generate_org call-site signature if needed).
- Change env var names or data JSON schema.
- Read the historical transcripts (for-pi*.md, pi-session-*.html, cti-*.md).
- Add new dependencies without checking Cargo.toml already has: reqwest(rustls),
  tokio(full), futures, hickory-resolver, tokio-rustls, rustls, serde_json, regex,
  fancy-regex, once_cell, uuid, chrono.

## Deliverable
- `src/scanner.rs` fully implemented, `cargo build` clean, `cargo test` green.
- Add unit tests in `#[cfg(test)]` for `_is_valid_domain`, `_is_global_ip`,
  `parse_versions`, and `_banner_versions` (copy the Python test expectations).
- Do NOT commit. Just leave the working tree; the parent reviews the diff.

## Verification you MUST run before finishing
```
. "$HOME/.cargo/env"
cd /home/bhanuharya/code/cti-dashboard/rust
cargo build 2>&1 | tail -20
cargo test 2>&1 | tail -20
```
Both must be clean before you report done.
