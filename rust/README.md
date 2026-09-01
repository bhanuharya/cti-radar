# CTI Radar — Rust backend

A Rust rewrite of the CTI Radar attack-surface correlation dashboard backend,
built to exploit Rust's native strengths over the original FastAPI+Python
implementation: async I/O, data-parallel CPU, zero deep-copies, and bounded
memory. **Same data schema, same env vars, same observable behavior** — a
drop-in swap that runs faster and lighter.

## Why Rust (what actually got faster)

| Concern | Python (FastAPI) | Rust (axum + tokio) |
|---|---|---|
| Scanner I/O | Threads + `curl` subprocess per probe | Single tokio event loop; thousands of in-flight `reqwest`/`tokio::net` probes |
| CPU-bound work (PII mask, normalize, graph) | GIL-locked, serial + `copy.deepcopy` | `rayon` `par_iter` across cores, borrowed data |
| Memory per scan | Per-probe thread stacks + process spawns | One shared client + resolver (Arc), no per-conn threads |
| Startup | Interpreter + imports (~1s) | Compiled binary (~ms) |

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
  SCANNER_TASK.md      delegated scanner-port brief
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

Binds `127.0.0.1` by default; refuses `0.0.0.0`/`::` (same as Python).

## Security invariants (preserved 1:1 from the Python)

- Auth on every route (session cookie OR `X-CTI-Token`, constant-time compare).
- Slug regex `^[a-z0-9-]{1,32}$` before any filesystem use.
- PII masking on every read path; SSRF/DNS-rebinding guards on scanner + AI URLs.
- Atomic 0600/0700 writes; security headers on every response.
- OpenHack active assessment fail-closed (active+isolated+bin+allowlist+ROE).

## Benchmark (vs Python)

```bash
bash bench/bench.sh 5 api      # HTTP endpoint latency / RSS / CPU
bash bench/bench.sh 3 scan     # full scan pipeline wall-clock
python3 bench/compare.py bench/results/<timestamp>
```

Both servers run against the same `CTI_DATA_DIR`, same `sample` org, same
workload — the harness reports median wall-clock, peak RSS, and CPU for each,
plus the rust/py ratio.
