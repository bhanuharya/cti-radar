# CTI Radar — Deployment Guide

This document describes the **supported deployment shape** and its hardening
notes. For day-to-day operation see `app/HOW_TO_RUN.md`.

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
WorkingDirectory=/home/you/code/cti-dashboard
EnvironmentFile=/home/you/.config/cti-radar/server.env   # mode 600
Environment=CTI_DATA_DIR=/home/you/.local/share/cti-radar
Environment=CTI_STATE_DIR=/home/you/.local/state/cti-radar
Environment=CTI_AI_CONFIG_FILE=/home/you/.config/cti-radar/ai_config.json
Environment=CTI_HOST=100.x.y.z        # tailnet IP — NEVER 0.0.0.0
Environment=CTI_PORT=8084
ExecStart=/home/you/code/cti-dashboard/.venv/bin/python -m uvicorn app.main:app \
          --host 100.x.y.z --port 8084 --no-server-header --workers 1
Restart=always
RestartSec=3

# hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=tmpfs            # code lives in /home; tmpfs hides other homes —
                             # if the app cannot read its checkout, use
                             # ReadWritePaths= instead and drop ProtectHome
ReadWritePaths=/home/you/.local/share/cti-radar /home/you/.local/state/cti-radar
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictSUIDSGID=true

[Install]
WantedBy=default.target
```

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
