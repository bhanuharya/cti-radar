# CTI Radar — Rust Port Spec (feat/rust-rewrite)

Port the FastAPI+Python backend to Rust (axum + tokio + reqwest). The frontend
(`app/dashboard.html`), vendored static assets (`app/static/*`), and the offline
CVE map (`app/cve_data.json`) are REUSED AS-IS — only the backend is ported.

## Ground rules
- One crate at `rust/` (Cargo.toml + src/). Binary name `cti-radar`.
- Data dir + JSON schemas are IDENTICAL to the Python version — the Rust server
  must read/write the same `CTI_DATA_DIR/orgs.json` and
  `CTI_DATA_DIR/orgs/<slug>/{findings.json,baseline.txt,history.json}` so an
  existing deployment is a drop-in swap.
- Security invariants (secure-development skill) MUST be preserved 1:1:
  auth on every route, slug regex `^[a-z0-9-]{1,32}$`, constant-time token
  compare, PII masking on every read path, SSRF/DNS-rebinding protection,
  atomic 0600/0700 writes, refuse `0.0.0.0`/`::` bind, security headers.
- Env vars identical (CTI_USER, CTI_PASSWORD, CTI_SCAN_TOKEN, CTI_DATA_DIR,
  CTI_STATE_DIR, CTI_HOST, CTI_PORT, CTI_WILDCARD_FILTER, CTI_NVD_ENRICH,
  CTI_NVD_API_KEY, CTI_NVD_MAX_LOOKUPS, CTI_JOB_STALE_SECS,
  CTI_MAX_ACTIVE_JOBS, CTI_RESOLVE_AFTER, CTI_CHROMIUM_PATH, CTI_OPENHACK_*,
  CTI_AI_CONFIG_FILE, OPENCODE_GO_B_API_KEY, …).

## Module map (Python -> Rust)
| Python | Rust | Notes |
|---|---|---|
| app/main.py (1574) | src/main.rs + src/server/{auth,jobs,handlers,report}.rs | axum router, all routes, sessions, per-org job serialization |
| app/cti_correlation.py (1299) | src/correlation.rs | registry, normalize, PII mask, lifecycle, atomic writes, graph/summary/fleet/ips |
| app/cve_match.py (363) | src/cve_match.rs | offline version->CVE matching + optional NVD enrichment |
| app/scanner.py (4151) | src/scanner/*.rs | passive scan: 6 enum sources, DNS+pin, HTTP fingerprint, TCP banner, TLS certs, InternetDB, findings synthesis, reconcile, recheck, AI triage/grading, correlate |
| app/ai_providers.py (831) | src/ai.rs | multi-profile AI (ollama + openai-compatible), SSRF validation, JSON-fence stripping |
| app/openhack_source.py (788) | src/openhack.rs | fail-closed active-assessment wrapper |
| app/dashboard.html | (served as asset) | NO rewrite |
| app/static/* | (served as asset) | NO rewrite |
| app/cve_data.json | (embedded/served) | NO rewrite |

## API surface to reproduce exactly (status codes + JSON shapes)
- POST /api/login  (Basic auth -> HttpOnly session cookie; 429 on rate limit)
- POST /api/logout
- GET  /api/orgs
- GET  /api/orgs/{slug}
- GET  /api/graph?org=, /api/summary?org=, /api/fleet?org=, /api/ips?org=
- GET  /api/findings?org=&sort=&status=, /api/findings/{id}?org=
- GET  /api/dashboard?org=&sort=&status=, /api/orgs/{slug}/dashboard
- GET  /api/admin/logs
- GET  /api/orgs/{slug}/history
- GET  /api/orgs/{slug}/scan/{job_id}, /recheck/{job_id}, /correlate/{job_id},
       /ai-grade/{job_id}, /openhack-scan/{job_id}
- POST /api/orgs/register  (name, domains, slug)
- POST /api/orgs/{slug}/domains  (domains, action add|remove|set)
- POST /api/orgs/{slug}/scan  (mode fast|ai, ai_profile)
- POST /api/orgs/{slug}/recheck
- POST /api/orgs/{slug}/correlate
- POST /api/orgs/{slug}/ai-grade  (ai_profile)
- POST /api/orgs/{slug}/findings/{id}/status  (status, note)
- POST /api/orgs/{slug}/findings/{id}/comment  (note, by)
- POST /api/orgs/{slug}/openhack-config, /openhack-scan
- GET  /api/openhack/models, /api/ai/capabilities, /api/orgs/{slug}/ai_profile
- POST /api/orgs/{slug}/ai_profile
- GET  /api/orgs/{slug}/report.pdf  (Chromium HTML->PDF, HTML fallback)
- GET  /  (dashboard.html) and /static/*

## Data types (serde)
- OrgRegistry: `{ "<slug>": { name, domains, findings, baseline } }` in orgs.json
- Finding: id, title, target, ip, severity, category, status, status_detail,
  description, impact, evidence, proof_chain, remediation, related_cves,
  topics_exposed, discovery, found_date, cvss_estimate, cvss_vector, … (loose —
  use serde_json::Value for flexible fields, typed structs for stable ones).
- findings.json: `{ "meta": {...}, "findings": [ Finding ] }`
- baseline.txt: newline-delimited host:port or host strings.
- history.json: array of events `{ ts, kind, mode, note, summary }`.

## Verification (must pass before each slice is "done")
- `cargo build` clean (no warnings introduced by us is ideal, not mandatory)
- `cargo test` green
- Manual smoke: run the binary against `CTI_DATA_DIR=data`, login with env
  creds, GET /api/orgs returns the `sample` org.
- Secure-dev gates: `git grep` secret scan clean, security headers present.

## Rust-native design (where the rewrite EXCELS vs Python)
The point of this rewrite is to exploit Rust's strengths, not merely transliterate
Python. These are intentional architectural upgrades over the Python original
(same observable behavior + identical data output, faster + lower memory):

1. **Async scanner (tokio)** — Python fans out via threads + `curl` subprocesses
   (one process per probe). Rust does every enum/DNS/HTTP/TCP/TLS/InternetDB probe
   on a single tokio event loop via `reqwest` + `tokio::net`, thousands of
   concurrent in-flight probes, no thread/process-per-connection, no GIL.
2. **Data-parallel CPU (rayon)** — PII masking, finding normalization, graph
   building, CVE matching, JSON (de)serialization run in parallel across findings
   with `par_iter`/`par_bridge`. Python is GIL-locked here.
3. **No deep-copy** — Python `load_data()` does `copy.deepcopy` on every read.
   Rust borrows / uses `Arc<Value>`; findings are cloned only where a writer
   genuinely needs isolation.
4. **Zero-alloc hot paths** — `&str` slicing for masking (no per-field String
   churn), `BTreeSet`/`HashMap` for dedup, single-pass regex extraction.
5. **Bounded memory** — no per-probe thread stacks; resolver pool + HTTP client
   shared across the whole scan (Python builds/tears down repeatedly).

## Do NOT
- Rewrite dashboard.html, static assets, or cve_data.json.
- Change the data JSON schemas or env var names.
- Bind 0.0.0.0 / :: — refuse like the Python does.
- Use `unwrap()` on external input; propagate errors as 400/404/500.
- Read the historical transcripts (for-pi*.md, pi-session-*.html,
  cti-dahshboard-commit.md) — treat them as non-existent.
