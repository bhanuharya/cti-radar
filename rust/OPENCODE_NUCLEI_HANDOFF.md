# OpenCode Nuclei Handoff — Rust backend port (secret-free)

Status: **implemented, tested, verified — NOT deployed.**
Live Rust service (`:8085`, separate checkout) is untouched and still serves
the pre-Nuclei build. No `CTI_VULN_*` / OpenHack gates are enabled anywhere.
Cline/AI configuration was not touched.

## What was ported (Python -> Rust)

| Python | Rust | Notes |
|---|---|---|
| `app/vuln_scan.py` | `rust/src/vuln_scan.rs` | scope validation, passive builders, persist, history |
| `app/nuclei_scan.py` | `rust/src/nuclei.rs` | env contract, argv builder, runner, JSONL parser/mapper |
| `POST/GET .../vuln-scan`, `GET /api/vuln/engines` (main.py) | `rust/src/vuln_handlers.rs` | job `vuln`, fail-closed gates |
| `AppError` 400/404/409… (no 403 existed) | `rust/src/error.rs` + `Forbidden` | gate denials return **403** |

Routes registered in `rust/src/main.rs`; modules declared in `rust/src/lib.rs`.
Docs updated: `rust/PORT.md` (module map + API surface), `rust/README.md`
(layout). No new Cargo dependencies.

## Mandatory security properties (all implemented + tested)

1. **All four `CTI_VULN_*` gates mandatory before active execution**
   (`vuln_scan::authorization_error`): `CTI_VULN_ACTIVE=1`,
   `CTI_VULN_ISOLATED=1`, exact `CTI_VULN_ALLOWED_DOMAINS` (every registered
   org domain must be listed exactly), unexpired RFC3339
   `CTI_VULN_ROE_EXPIRES`. Applies to `active:true` AND `engine:nuclei`.
   Denial is checked in the HTTP handler **before** job acquisition — zero
   subprocess, zero network on the denial path (verified: no `nuclei`
   process observed during 403s).
2. **Egress-scope fix 1 (Hermes, ported): `canonical_nuclei_url`** —
   stored fingerprint URLs are evidence, never egress authority. Scheme and
   non-default port are kept only when the parsed host exactly matches the
   approved hostname; userinfo/path/query/fragment are discarded; anything
   else falls back to `https://<approved-host>`.
3. **Egress-scope fix 2 (Hermes, ported): `registered_org_domain`** —
   for `engine:nuclei`, every target must be the registered domain or a
   subdomain of it. Cached known-host state alone (`evil.example` sitting in
   fingerprints) is rejected with `nuclei target outside registered org
   domain` before any option parsing or subprocess.
4. Supporting hardening (ported 1:1): argv list only (never shell), child env
   strips `*_proxy`, `-duc -ni -or -nm`, `dos`/`fuzz` force-excluded,
   severity capped at HIGH, output capped 10 MiB / 500 events, workdir
   removed after parse, per-request severity/tags validated server-side.

## Known parity gap

- `include_nvd:true` is accepted but recorded as a note
  (`nvd enrichment not available in Rust backend`) — `src/cve_match.rs` has
  no `enrich_hosts` yet. Fail-open; passive local-map result stands.

## Verification evidence (2026-09-04)

- `cargo test`: **36 passed, 0 failed** (13 new: 8 `vuln_scan`, 5 `nuclei`,
  incl. both Hermes regression cases ported).
- `cargo build --release`: clean; `cargo clippy --all-targets`: zero
  warnings in new files.
- `cargo audit`: 1 vulnerability (`hickory-proto 0.24.4`, RUSTSEC-2026-0119)
  + 1 unmaintained warning (`rustls-pemfile`) — both **pre-existing**
  (`Cargo.toml`/`Cargo.lock` untouched, zero new deps). Upgrade is a
  separate owner decision.
- Live release binary on isolated port + isolated `CTI_DATA_DIR`:
  - `GET /api/vuln/engines` → 200, nuclei `available:true`
  - `POST .../vuln-scan {"engine":"nuclei"}` gates unset → **403**
    `active assessment denied: CTI_VULN_ACTIVE must equal 1`
  - `{"active":true}` → 403; `{"engine":"bogus"}` → 400;
    no auth → 401; unknown org → 404
  - passive `{"targets":[...]}` → queued → `status:done` with correct shape
- Python suite re-verified after Hermes' fixes: **221 passed**.

## Deployment preconditions (all still required)

1. This diff reviewed and merged; 2. `cargo build --release` on the deploy
   host; 3. `cargo audit` triage accepted by backend owner (pre-existing
   hickory item); 4. start against the real data dir on a staging port and
   re-verify the 403 matrix above; 5. only then replace the `:8085` binary.
   Never enable `CTI_VULN_*` outside a written ROE.
