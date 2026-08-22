# CTI Radar — Deployment Guide

This document describes the **supported deployment shape** and its hardening
notes. For day-to-day operation see the `README.md` setup section.

## Supported shape: single process, single host

CTI Radar is architected around **one server process on one host**:

- Registry, findings, baseline, and history are JSON files guarded by
  **process-local** locks (`cc._org_lock`). Two processes writing the same
  `CTI_DATA_DIR` can interleave read-modify-write cycles and lose updates —
  atomic writes prevent *corrupt* files, not *lost* changes.
- Sessions, the job table, and caches are **in memory**; a restart logs
  everyone out and drops in-flight job status (findings on disk are safe).

**Rules that follow from this:**

1. Run exactly **one** `uvicorn app.main:app` process per `CTI_DATA_DIR`
   (`--workers 1` is the default; never pass `--workers N>1`).
2. Never point two instances (e.g., a dev port and a prod port) at the same
   data directory. If you need a second instance, give it its own
   `CTI_DATA_DIR` and re-register the orgs you want there.
3. Long-running scans are bounded by per-org job serialization inside the
   process. Do not put the app behind a load balancer that spawns replicas.

If you ever need multi-worker/multi-host, migrate the JSON stores to
SQLite/PostgreSQL and move sessions/jobs to a shared store first — the API
surface already supports that transition.

## systemd unit (hardened)

`~/.config/systemd/user/cti-dashboard.service`:

```ini
[Unit]
Description=CTI Radar Correlation Dashboard (FastAPI, tailnet-only)
After=network.target

[Service]
Type=simple
# server.env holds CTI_HOST / CTI_PORT (read by the app entry point, which
# refuses to bind 0.0.0.0) and the credentials. Keep it mode 600.
# Paths below assume user "you" — adjust to your home.
EnvironmentFile=/home/you/.config/cti-radar/server.env
Environment=CTI_DATA_DIR=/home/you/.local/share/cti-radar
Environment=CTI_STATE_DIR=/home/you/.local/state/cti-radar
Environment=CTI_AI_CONFIG_FILE=/home/you/.config/cti-radar/ai_config.json
# NOTE: no host/port here on purpose — the entry point below reads
# CTI_HOST/CTI_PORT from server.env, so there is exactly one place to
# change the bind address.
WorkingDirectory=/home/you/code/cti-dashboard
ExecStart=/home/you/code/cti-dashboard/.venv/bin/python -m app.main
Restart=always
RestartSec=3

# hardening: /home is readable (checkout, venv, config) but only the
# data/state dirs are writable
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/home/you/.local/share/cti-radar /home/you/.local/state/cti-radar
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictSUIDSGID=true

[Install]
WantedBy=default.target
```

Changing the bind address means editing `CTI_HOST`/`CTI_PORT` in
`server.env` and restarting — the unit itself never hard-codes them.
Validate your edited unit with `systemd-analyze verify` before enabling.

Enable persistence across reboots (user services stop at logout otherwise):

```bash
loginctl enable-linger $USER
systemctl --user daemon-reload
systemctl --user enable --now cti-dashboard
```

## Reverse proxy (optional)

Direct tailnet access is the simplest and most secure exposure. If you must
put the dashboard behind TLS on a LAN/public host, the proxy must be the
*only* path to the app, and it must set the protocol header correctly — the
session cookie's `Secure` flag keys off `X-Forwarded-Proto`:

**nginx:**

```nginx
server {
    listen 443 ssl http2;
    server_name cti.example.com;
    ssl_certificate     /etc/letsencrypt/live/cti.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/cti.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8084;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto https;   # cookie Secure flag depends on this
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_read_timeout 120s;                    # report.pdf / scan polling
    }
}
```

**Trusted-proxy assumptions.** The app trusts `X-Forwarded-Proto` from its
immediate peer. That is safe only when clients cannot reach the app
directly — bind the app to `127.0.0.1` when a proxy fronts it (override
`CTI_HOST=127.0.0.1`), and never allow arbitrary clients to set these
headers via the proxy.

**Caddy (equivalent):**

```caddy
cti.example.com {
    reverse_proxy 127.0.0.1:8084
}
```

Caddy sets `X-Forwarded-Proto` automatically.

## Firewall

- The app binds a specific interface (`CTI_HOST`); the direct entry point
  refuses `0.0.0.0`.
- On a tailnet-only deployment, nothing else is required. Otherwise allow
  only the proxy/port you intend: `ufw allow 443/tcp` and deny the app port
  externally.

## Backup

Everything mutable lives under two directories — back them up together:

```text
~/.local/share/cti-radar/   registry, orgs (findings/baseline/history)
~/.local/state/cti-radar/   logs, reports, NVD cache
~/.config/cti-radar/        credentials (server.env mode 600), AI profiles
```

`cp -a` of those three while the service is stopped is a consistent backup.
