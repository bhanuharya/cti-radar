# CTI Radar — Attack-Surface Correlation Dashboard

A lightweight, self-hosted **Cyber Threat Intelligence correlation dashboard**
with a **native Rust backend** (Axum + Tokio). It ingests per-organization
attack-surface/finding data, derives a **correlation graph**
(host ↔ IP ↔ CVE ↔ brand ↔ vulnerability-class), lets you **scan domains**
(deterministic or AI-assisted), runs **passive vulnerability lookups** with an
opt-in gated Nuclei engine, **tracks finding status** through a mitigation
lifecycle, and exports an **NVD-linked** PDF report — all local, auth-gated,
PII-masked, and $0.

> The backend ships as a **single static Rust binary** with JSON-file state and
> the dashboard UI embedded at build time. No Python runtime is required to
> serve it. A FastAPI implementation is retained under `app/` as a parity
> reference (see [Python backend](#python-backend-parity-reference)).

> **Intended use:** authorized security teams assessing **their own** external
> footprint. Scanning is **passive / non-intrusive by default** (certificate
> transparency — crt.name / crt.sh / certspotter / hackertarget — plus DNS
> resolution, HTTP header probe, a TCP connect scan of common service ports, and
> InternetDB enrichment). Active probing (Nuclei templates, OpenHack) is
> deny-by-default and gated behind `CTI_VULN_*` / `CTI_OPENHACK_*`
> authorization. Use it only on infrastructure you own or are explicitly
> authorized to test.

---

## Features

- **Multi-org / workspaces** — register any org (slug-validated), per-org data
  stays in `data/orgs/<slug>/`.
- **Correlation graph** — interactive host ↔ IP ↔ CVE ↔ brand ↔ vuln-class
  graph (vendored vis-network, no CDN), plus summary, fleet, and IP views.
- **Finding lifecycle** — OPEN → IN_PROGRESS → MITIGATED → RISK_ACCEPTED with
  comments, status history, and evidence-based AI re-grading.
- **Dual-mode scanning** — `fast` (deterministic, $0) or `ai` (after
  deterministic capture, an optional LLM triages only the interesting hosts
  into `AI-ASSESSED` findings, then re-grades existing findings'
  severity/impact). AI never fails a scan; it degrades to the deterministic
  result.
- **Vuln lookup (host-based)** — `Vuln scan` (org-wide) or `vuln: this host`
  reuses stored fingerprints: offline CVE map + version/header/TLS/login
  audit. Optional **Nuclei engine** runs community templates over in-scope
  URLs behind the fail-closed `CTI_VULN_*` gate (details below).
- **Model config without JSON** — dashboard **models** section (add/edit/test/
  delete, generic fields), single-profile `CTI_AI_*` env, or
  `python -m app.ai_setup --wizard`. All additive: existing profiles and the
  default are preserved; keys stay in server env. The AI scan option names its
  exact blocker (e.g. which key env is missing) instead of failing silently.
- **PDF reporting** — NVD-linked per-org report (headless Chromium, printable
  HTML fallback), PII-masked.
- **Bounded jobs** — scan, recheck, correlate, vuln-scan, AI-grade, and
  OpenHack jobs are serialized per org with a global active-job cap; terminal
  states (done/failed) are retained so status polling works reliably.
- **Responsive + mobile** — dark theme works on phones; graph is
  touch-friendly.

## Backend architecture (Rust)

```
Axum     HTTP router, typed handlers, JSON, security-header middleware
Tokio    concurrent DNS / HTTP / TCP / TLS / background-job I/O
Rayon    CPU-bound normalization, masking, graph preparation
Rustls   TLS support with no OpenSSL runtime dependency
```

Security invariants enforced in code:

- Auth on every route (session cookie or `X-CTI-Token`, constant-time compare).
- Slug regex `^[a-z0-9-]{1,32}$` before any filesystem use.
- PII masking on every read path; SSRF/DNS-rebinding guards on scanner and AI
  URLs.
- Atomic `0600`/`0700` writes; security headers on every response; per-org
  write locks.
- OpenHack and Nuclei are **fail-closed**: gate checks run before any binary
  lookup, process creation, or network-capable work.

## Project structure

```
rust/                  native backend (canonical)
  Cargo.toml           dependencies (rustls TLS, no OpenSSL dep)
  src/
    main.rs            serve + bind policy (refuses 0.0.0.0/::)
    lib.rs             module tree, router, embedded dashboard
    config.rs          env config (mirrors .env.example exactly)
    auth.rs            session cookie + X-CTI-Token (constant-time)
    handlers.rs        read endpoints
    handlers_mut.rs    mutation endpoints (register/scan/status/...)
    jobs.rs            per-org job serialization + global cap + TTL
    correlation.rs     registry, PII mask, lifecycle, graph/summary/fleet/ips
    scanner.rs         passive recon: enum/DNS/HTTP/TCP/TLS/InternetDB + findings
    cve_match.rs       offline version->CVE matching + NVD enrichment
    vuln_scan.rs       host vuln lookup + gated Nuclei runner (consolidated)
    vuln_handlers.rs   vuln-scan + engines HTTP handlers
    ai.rs              AI providers (ollama + openai-compatible), SSRF-validated
    openhack.rs        active-assessment wrapper (fail-closed)
    report.rs          PDF (Chromium) + HTML fallback
    net.rs / logs.rs / error.rs
  tests/               integration suites (API parity, vuln-scan security)
  PORT.md              full Python→Rust port spec (module map + API surface)
app/                   Python (FastAPI) parity implementation
  main.py              FastAPI server (legacy parity)
  vuln_scan.py / nuclei_scan.py   Python-side vuln lookup + Nuclei provider
  dashboard.html       single-file frontend (embedded into the Rust binary)
  static/              vendored vis-network (no CDN)
tests/                 Python test suite (parity reference)
bench/                 benchmark harness (API latency, scan, CPU/RSS)
data/                  state: orgs.json + per-org findings/history (gitignored)
```

## Requirements

- **Rust stable toolchain** to build; the resulting binary has no runtime
  language dependencies.
- **One process on one host.** State is JSON files guarded by process-local
  locks with in-memory sessions/jobs — multiple workers or two instances
  sharing a data directory can lose updates. See
  [DEPLOYMENT.md](DEPLOYMENT.md) for the supported shape, hardened systemd
  unit, and reverse-proxy/trusted-proxy notes.
- **curl** (used by the passive scanner / fingerprinting).
- **Optional — headless Chromium** for PDF export. If absent, the report
  falls back to a printable HTML download.

## Build & run

```bash
cd rust
cargo build --release

CTI_USER=admin \
CTI_PASSWORD=change-me-to-a-long-random-string-1 \
CTI_SCAN_TOKEN=change-me-to-a-long-random-string-2 \
CTI_DATA_DIR=/path/to/data \
CTI_HOST=127.0.0.1 CTI_PORT=8085 \
./target/release/cti-radar
```

The server binds `127.0.0.1` by default and **refuses** `0.0.0.0`/`::` — put a
reverse proxy in front for TLS. All state lives under `CTI_DATA_DIR`.

### Environment variables

| Variable | Purpose |
| --- | --- |
| `CTI_USER` / `CTI_PASSWORD` | dashboard login |
| `CTI_SCAN_TOKEN` | machine token (`X-CTI-Token`) |
| `CTI_DATA_DIR` / `CTI_HOST` / `CTI_PORT` | state dir and bind address |
| `CTI_AI_PROFILE_NAME/PROVIDER/BASE_URL/MODEL/API_KEY_ENV` | single AI profile override |
| `CTI_AI_CONFIG` / `CTI_AI_CONFIG_FILE` | multi-profile AI config (file shape: `data/ai_config.example.json`) |
| `CTI_VULN_ACTIVE` / `CTI_VULN_ISOLATED` / `CTI_VULN_ALLOWED_DOMAINS` / `CTI_VULN_ROE_EXPIRES` | active vuln-lookup gate (all four required, deny-by-default) |
| `CTI_NUCLEI_BIN` / `CTI_NUCLEI_TEMPLATES` / `CTI_NUCLEI_SEVERITY` / `CTI_NUCLEI_TAGS` / `CTI_NUCLEI_EXCLUDE_TAGS` / `CTI_NUCLEI_RATE_LIMIT` / `CTI_NUCLEI_TIMEOUT` / `CTI_NUCLEI_INTERACTSH` | Nuclei engine tuning (see `.env.example`) |
| `CTI_OPENHACK_ACTIVE` / `CTI_OPENHACK_ISOLATED` / `CTI_OPENHACK_ALLOWED_DOMAINS` / `CTI_OPENHACK_ROE_EXPIRES` | OpenHack active-assessment gate |

## API surface

```
GET  /api/graph · /api/summary · /api/fleet · /api/ips · /api/findings
GET  /api/dashboard · /api/orgs · /api/admin/logs · /api/findings/{id}
GET  /api/orgs/{slug} · /{slug}/dashboard · /{slug}/history · /{slug}/report.pdf
POST /api/login · /api/logout

POST /api/orgs/register
POST /api/orgs/{slug}/scan · /{slug}/recheck · /{slug}/correlate · /{slug}/ai-grade
GET  /api/orgs/{slug}/scan/{job_id} · /recheck/{job_id} · /correlate/{job_id} · /ai-grade/{job_id}
POST /api/orgs/{slug}/domains · /{slug}/findings/{id}/status · /{slug}/findings/{id}/comment

GET  /api/vuln/engines                        passive/nuclei availability
POST /api/orgs/{slug}/vuln-scan               vuln lookup queue (passive default)
GET  /api/orgs/{slug}/vuln-scan/{job_id}      vuln lookup status

GET  /api/ai/capabilities                     AI readiness + blockers
GET/POST /api/orgs/{slug}/ai_profile          per-org AI profile (read/set)

POST /api/orgs/{slug}/openhack-config · /{slug}/openhack-scan   (gated)
```

All routes are auth-gated; login is rate-limited and sessions expire. The
multi-profile AI CRUD (`/api/ai/profiles`, `/api/ai/default`, `/api/ai/test`)
currently exists in the Python parity implementation only — the Rust backend
covers single-profile env config and the per-org `ai_profile` endpoint.

## Vuln lookup (host-based, passive by default)

`Vuln scan` (org-wide, next to Correlate) or `vuln: this host` on any finding
reuses stored fingerprints — no re-enumeration, no exploits:

- `cve` — offline `cve_data.json` version→CVE match (`CORRELATED`, capped
  HIGH).
- `version` / `headers` / `tls` / `login` — config audit from captured data
  (version disclosure LOW, missing HSTS/CSP framing LOW/MEDIUM, expired cert
  MEDIUM).
- Targets must belong to the org (stored hosts or subdomains of registered
  domains); out-of-scope targets are rejected before any network. Genuinely
  new findings persist deduplicated (`source: vuln-scan`).
- `engine: "passive"` is local-only: it evaluates already stored fingerprints
  without fresh DNS, HTTP, TLS, or NVD requests.

### Nuclei engine (opt-in, fail-closed)

`engine: "nuclei"` is active and **never runs** unless all checks pass before
binary lookup or process creation:

- `CTI_VULN_ACTIVE=1` and `CTI_VULN_ISOLATED=1`;
- nonempty `CTI_VULN_ALLOWED_DOMAINS` containing every registered domain
  exactly (DNS names only; no URLs, paths, ports, wildcards, or IPs); and
- a future, timezone-aware RFC3339 `CTI_VULN_ROE_EXPIRES`.

The gate is re-checked at queue time **and** again inside the background
runner, so an expired ROE aborts mid-flight jobs. Hardened defaults: severity
`critical,high,medium`, rate limit 20/s (clamped 1–150), 300 s budget (clamped
60–1200), output bounded to 10 MiB / 500 events, `dos`/`fuzz`/`intrusive`
templates always excluded (`dos`/`fuzz` cannot be re-enabled), Interactsh/OAST
off unless `CTI_NUCLEI_INTERACTSH=1` exactly, child env reduced to a fixed
allowlist, private per-run workdir removed afterwards, and runner stderr
captured for failure diagnostics.

Nuclei inputs are canonical registered hostnames — stored fingerprint URLs can
supply only a matching scheme and a common web port. Findings are
`source: nuclei`, `NUCLEI-MATCHED`, severity capped at HIGH, identity
`nuclei|host|template|path`, validated CVE IDs only. Template matches are
evidence, not exploit proof.

## OpenHack active-assessment authorization

OpenHack is an **active external assessment**, separate from the passive CTI
scanner. It stays disabled unless all `CTI_OPENHACK_*` controls are set
(authorization flag, isolation flag, exact allowlist, unexpired ROE) — see
`.env.example` and [DEPLOYMENT.md](DEPLOYMENT.md). No exploit payloads; do not
enable it without written, time-bounded authorization.

## AI-assisted scanning (mode=ai)

Deterministic capture is the source of truth; the LLM is an optional
interpretive pass that adds vulnerability-context findings on top. Configure
profiles three ways — they merge additively and secrets are referenced by
env-var name only:

1. Dashboard **models** section (add/edit/test/delete, generic fields),
2. `CTI_AI_*` env vars (single profile), or
3. `python -m app.ai_setup --wizard` (file shape: `data/ai_config.example.json`).

Without AI config, `mode=ai` scans safely fall back to deterministic `fast`.
See `rust/PORT.md` for the prompt/concurrency/PII-mask details of the ported
implementation.

## Tests

```bash
cd rust && cargo test          # 63 tests: 27 unit + 18 API-parity + 18 vuln-scan
python -m pytest tests/ -q     # 221 tests (Python parity reference)
```

Rust coverage includes: gate fail-closed ordering (no binary lookup before
authorization), scope rejection of cached external hosts, child-env
allowlisting, output caps, exit-code semantics, JSONL event mapping (CVE
validation, severity cap, out-of-scope/IP drops), argv safety, web-port
allowlisting, job routing/auth, and API parity with the Python envelopes.

## Benchmarking

```bash
bash bench/bench.sh 5 api
bash bench/bench.sh 3 scan
python3 bench/compare.py bench/results/<timestamp>
```

Use one data directory and one fixed workload for every measured run; keep
network-heavy scan timing separate from local API timing.

## Python backend (parity reference)

The original FastAPI implementation is kept under `app/` for parity testing
and as the port specification's source of truth:

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python -m uvicorn app.main:app --host 127.0.0.1 --port 8084 --no-server-header
```

It mirrors the Rust API surface (same envelopes, codes, and job lifecycle) and
is covered by the `tests/` suite. New backend work should target the Rust
implementation; `rust/PORT.md` documents the module map and API contract
between the two.

## License & use

Self-hosted, auth-gated, PII-masked. Scan only what you own or are explicitly
authorized to test — passive by default, active only behind written,
time-bounded ROE gates.
