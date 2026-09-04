# CTI Radar — Rust backend

The CTI Radar backend is a Rust service for authenticated attack-surface
correlation, passive reconnaissance, finding lifecycle management, reporting,
and optional AI-assisted analysis. It is built with Axum, Tokio, Rayon, and
Rustls for a compact, asynchronous, and memory-conscious deployment.

## Runtime architecture

- **Axum** provides the HTTP router, typed handlers, JSON responses, and
  security-header middleware.
- **Tokio** handles concurrent DNS, HTTP, TCP, TLS, and background-job I/O
  without spawning a process for each probe.
- **Rayon** parallelizes independent CPU-bound normalization, masking, and
  graph-preparation work.
- **Serde JSON** preserves the dashboard data schema while keeping parsing and
  serialization explicit at API and storage boundaries.
- **Rustls** provides TLS support without an OpenSSL runtime dependency.

## Layout

```
rust/
  Cargo.toml           dependencies (rustls TLS, no OpenSSL dep)
  src/
    main.rs            axum router + security-headers middleware + serve
    lib.rs             module tree + AppState
    config.rs          env config (mirrors .env.example exactly)
    error.rs           AppError -> JSON HTTP responses
    auth.rs            session cookie + X-CTI-Token (constant-time compare)
    jobs.rs            per-org job serialization + global cap + TTL
    correlation.rs     registry, PII mask, lifecycle, graph/summary/fleet/ips
    cve_match.rs       offline version->CVE matching + NVD enrichment
    scanner.rs         passive recon: enum/DNS/HTTP/TCP/TLS/InternetDB + findings
    ai.rs              AI providers (ollama + openai-compatible), SSRF-validated
    openhack.rs        active-assessment wrapper (fail-closed)
    report.rs          PDF (Chromium) + HTML fallback
    handlers.rs        read endpoints
    handlers_mut.rs    mutation endpoints (register/scan/status/...)
  PORT.md              full port spec (module map + API surface + data schema)
```

## Build & test

```bash
cd rust
cargo build          # debug
cargo test           # unit tests
cargo build --release  # optimized (for benchmarking)
```

## Run

```bash
cd rust
CTI_USER=admin CTI_PASSWORD=... CTI_SCAN_TOKEN=... \
CTI_DATA_DIR=/path/to/data CTI_HOST=127.0.0.1 CTI_PORT=8085 \
./target/release/cti-radar
```

Binds `127.0.0.1` by default and refuses `0.0.0.0`/`::`.

## Security invariants

- Auth on every route (session cookie OR `X-CTI-Token`, constant-time compare).
- Slug regex `^[a-z0-9-]{1,32}$` before any filesystem use.
- PII masking on every read path; SSRF/DNS-rebinding guards on scanner + AI URLs.
- Atomic 0600/0700 writes; security headers on every response.
- OpenHack active assessment fail-closed (active+isolated+bin+allowlist+ROE).
- Nuclei active templates fail-closed before executable lookup or process spawn;
  passive vuln lookup reads stored fingerprints only.

## Nuclei vulnerability lookup (disabled by default)

Rust exposes authenticated `GET /api/vuln/engines`, `POST
/api/orgs/{slug}/vuln-scan`, and `GET
/api/orgs/{slug}/vuln-scan/{job_id}`. `engine: "passive"` is local-only:
it evaluates already stored fingerprints without new DNS, HTTP, TLS, or NVD
requests. `engine: "nuclei"` is active and never runs unless all checks below
pass **before** binary lookup or process creation:

- `CTI_VULN_ACTIVE=1` and `CTI_VULN_ISOLATED=1`;
- nonempty `CTI_VULN_ALLOWED_DOMAINS` containing every registered domain
  exactly (DNS names only; no URLs, paths, ports, wildcards, or IPs); and
- future, timezone-aware RFC3339 `CTI_VULN_ROE_EXPIRES`.

`CTI_NUCLEI_BIN`, when set, must be an absolute executable; otherwise the
runner may find `nuclei` on `PATH`. Templates must be an existing
`CTI_NUCLEI_TEMPLATES` directory or `~/nuclei-templates`. Defaults are
severity `critical,high,medium`, rate limit `20` (clamped `1..150`), and
run budget `300` seconds (clamped `60..1200`). `CTI_NUCLEI_TAGS` is an optional
strict tag allowlist (maximum 20). `dos`, `fuzz`, and `intrusive`
templates are excluded; `dos` and `fuzz` cannot be removed. Interactsh/OAST is
off unless `CTI_NUCLEI_INTERACTSH=1` exactly. Use only for written,
time-bounded authorization in an isolated environment.

Nuclei inputs are canonical registered hostnames (stored URLs can supply only
a matching scheme/non-default port), output is bounded to 10 MiB/500 events,
and temporary runner files are private and removed after each run.

## Benchmarking

The benchmark harness in `../bench/` measures authenticated API latency,
throughput, CPU, and resident memory. Run the API and scan workloads separately:

```bash
bash bench/bench.sh 5 api
bash bench/bench.sh 3 scan
python3 bench/compare.py bench/results/<timestamp>
```

Use one data directory and one fixed workload for every measured run. Treat
network-heavy scan timing separately from local API timing, because remote DNS,
TCP, TLS, and HTTP latency can dominate a scan.
