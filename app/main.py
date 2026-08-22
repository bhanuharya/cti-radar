"""cti-dashboard — FastAPI server for the multi-org CTI correlation dashboard.

Serves:
  /            — the dashboard HTML (graph + panels)
  /api/graph   — correlation graph (nodes + edges)   [?org=slug]
  /api/summary — KPI summary                         [?org=slug]
  /api/fleet   — CVE fleet-spread table              [?org=slug]
  /api/ips     — IP co-residency table               [?org=slug]
  /api/findings— full per-item findings              [?org=slug]
  /api/orgs    — registered orgs
  /api/orgs/{slug}       — org info + summary
  /api/findings/{id}     — full finding detail       [?org=slug]
   POST /api/orgs/register      — register a new org (token-gated)
   POST /api/orgs/{slug}/scan   — trigger passive scan (token-gated)
   POST /api/orgs/{slug}/ai-grade — AI grading of existing findings (token-gated)

Security (secure-dev gates):
  - binds loopback-only by default (HOST=127.0.0.1) — never 0.0.0.0
  - security headers on every response (CSP, nosniff, frame deny, referrer)
  - GETs are read-only; only POSTs that mutate are token-gated
  - slug validated against ^[a-z0-9-]{1,32}$ before ANY filesystem use
  - token read from env (CTI_SCAN_TOKEN) only — never stored in code
  - all request bodies are Pydantic-validated; no eval/exec
"""
import html as _html
import json, os, re, shutil, subprocess, sys, tempfile, threading, time
from datetime import datetime, timezone
# ensure this file's dir is importable regardless of launch cwd
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import Optional
import cti_correlation as cc
import scanner
import ai_providers
import openhack_source as oh
from fastapi.middleware.gzip import GZipMiddleware

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_ROOT = os.path.abspath(os.path.expanduser(
    os.environ.get("CTI_DATA_DIR", os.path.join(BASE, "data"))))
DATA_ORG_DIR = os.path.join(DATA_ROOT, "orgs")
ORGS_JSON = os.path.join(DATA_ROOT, "orgs.json")

_SLUG_RE = re.compile(r"^[a-z0-9-]{1,32}$")
_DEFAULT_ORG = "sample"

_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
_CHROMIUM = (os.environ.get("CTI_CHROMIUM_PATH") or shutil.which("chromium")
             or shutil.which("chromium-browser") or shutil.which("google-chrome"))

app = FastAPI(title="CTI Radar", docs_url=None, redoc_url=None)

# tighten runtime data permissions once at startup (0600 files / 0700 dirs);
# best-effort, never blocks boot
try:
    _migrated = cc.migrate_data_permissions()
    if _migrated:
        print(f"[cti] tightened permissions on {_migrated} data path(s)", file=sys.stderr)
except Exception as _perm_err:  # pragma: no cover
    print(f"[cti] permission migration skipped: {_perm_err}", file=sys.stderr)

# serve vendored static assets (vis-network) from app/static/
_STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
if os.path.isdir(_STATIC_DIR):
    app.mount("/static", StaticFiles(directory=_STATIC_DIR), name="static")

# thresholded gzip for sufficiently large responses — stdlib only, no extra dep
app.add_middleware(GZipMiddleware, minimum_size=1024)

# bounded executor + per-org job deduplication (P0: serialize mutations)
import uuid as _uuid
from concurrent.futures import ThreadPoolExecutor as _ThreadPoolExecutor


def _int_env(name, default):
    try:
        return int(os.environ.get(name, "") or default)
    except Exception:
        return default


_executor = _ThreadPoolExecutor(max_workers=4, thread_name_prefix="cti-job")
_jobs_lock = threading.Lock()
_jobs = {}  # (slug, kind) -> {id, started, kind, status, stage, progress, error}
_registry_lock = threading.Lock()
_JOB_TTL = 3600  # retain completed jobs for 1h

# runtime job/scan log (in-memory ring + persistent JSONL file)
_JOB_LOG_LOCK = threading.Lock()
_JOB_LOGS = []
_MAX_JOB_LOGS = 500
_LOG_FILE = os.path.join(DATA_ROOT, "logs", "cti-runtime.log")


def _job_key(slug, kind):
    return f"{slug}:{kind}"


_JOB_STALE_SECS = max(60, _int_env("CTI_JOB_STALE_SECS", 1800))     # running-job deadline
_MAX_ACTIVE_JOBS = max(1, _int_env("CTI_MAX_ACTIVE_JOBS", 8))       # global concurrency cap


def _try_acquire_job(slug, kind, stale_after=None):
    key = _job_key(slug, kind)
    prefix = f"{slug}:"
    now = time.time()
    with _jobs_lock:
        # Running entries are never reclaimed by age. A process restart clears
        # this in-memory table; while alive, the entry is the serialization fence.
        # per-org serialization: any running job for this org blocks new mutations
        for k, v in _jobs.items():
            if k.startswith(prefix) and v.get("status") == "running":
                return False, v["id"]
        # global active-job cap: bounded queue protection
        if sum(1 for v in _jobs.values() if v.get("status") == "running") >= _MAX_ACTIVE_JOBS:
            return False, None
        jid = f"{slug}-{kind}-{_uuid.uuid4().hex[:8]}"
        entry = {"id": jid, "started": time.time(), "kind": kind,
                 "status": "running", "stage": "queued", "progress": "",
                 "error": None}
        if stale_after:
            entry["stale_after"] = int(stale_after)
        _jobs[key] = entry
        return True, jid


def _job_busy_response(slug, kind, jid):
    """409 when this org has a running job; 429 when the global cap is hit."""
    if jid:
        return JSONResponse({"error": f"{kind} already running", "slug": slug,
                             "job_id": jid}, status_code=409)
    return JSONResponse({"error": f"{kind} rejected: server busy (max {_MAX_ACTIVE_JOBS} active jobs)",
                         "slug": slug, "job_id": None}, status_code=429)


def _release_job(slug, kind, jid, error=None, result=None):
    key = _job_key(slug, kind)
    with _jobs_lock:
        entry = _jobs.get(key)
        if entry and entry.get("id") == jid:
            entry["status"] = "failed" if error else "done"
            if error:
                entry["error"] = str(error)[:500]
                entry["stage"] = entry.get("stage") or "error"
            else:
                entry["stage"] = "done"
                entry["progress"] = "finished"
            if isinstance(result, dict):
                entry["result"] = {k: result.get(k) for k in result
                                   if isinstance(result.get(k), (str, int, float, bool,
                                                                 type(None)))}
            entry["finished"] = time.time()
            # retain for TTL so status polling works; prune old entries
            _prune_jobs()


def _prune_jobs():
    """Remove completed jobs older than _JOB_TTL."""
    now = time.time()
    to_del = [k for k, v in _jobs.items()
              if v.get("status") != "running" and now - v.get("finished", 0) > _JOB_TTL]
    for k in to_del:
        del _jobs[k]


def _is_job_running(slug, kind):
    key = _job_key(slug, kind)
    with _jobs_lock:
        entry = _jobs.get(key)
        return entry is not None and entry.get("status") == "running"


def _job_id(slug, kind):
    key = _job_key(slug, kind)
    with _jobs_lock:
        return _jobs.get(key, {}).get("id")


def _get_job(slug, kind, job_id):
    """Return the job entry if it matches slug/kind/job_id, else None."""
    key = _job_key(slug, kind)
    with _jobs_lock:
        entry = _jobs.get(key)
        if entry and entry.get("id") == job_id:
            return dict(entry)
    return None


def _now_iso():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _log_event(level, kind, slug, message, job_id=None, meta=None):
    """Append an event to the in-memory ring and the persisted JSONL log."""
    ev = {"ts": _now_iso(), "level": level, "kind": kind, "org": slug or "",
          "job_id": job_id or "", "message": message}
    if meta is not None:
        ev["meta"] = meta
    with _JOB_LOG_LOCK:
        _JOB_LOGS.append(ev)
        if len(_JOB_LOGS) > _MAX_JOB_LOGS:
            del _JOB_LOGS[:len(_JOB_LOGS) - _MAX_JOB_LOGS]
        try:
            os.makedirs(os.path.dirname(_LOG_FILE), exist_ok=True)
            with open(_LOG_FILE, "a") as f:
                f.write(json.dumps(ev) + "\n")
        except Exception:
            pass


def _ai_log_hook(level, message, meta=None):
    """Route low-level AI provider diagnostics into the runtime log ring."""
    _log_event(level, "ai", "", message, job_id=None, meta=meta)


ai_providers.set_log_hook(_ai_log_hook)


def _load_recent_logs(n=300):
    if not os.path.exists(_LOG_FILE):
        return []
    out = []
    try:
        with open(_LOG_FILE) as f:
            for line in f.readlines()[-n:]:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except Exception:
                    continue
    except Exception:
        pass
    return out


def _job_update(slug, kind, jid, **fields):
    key = _job_key(slug, kind)
    with _jobs_lock:
        entry = _jobs.get(key)
        if entry and entry.get("id") == jid:
            entry.update(fields)
            entry["updated"] = time.time()


def _job_progress(slug, kind, jid, stage, message):
    _job_update(slug, kind, jid, stage=stage, progress=message)
    _log_event("info", kind, slug, message, job_id=jid)


def _structured_job_failure(result):
    """Extract explicit failure from scanner's structured result."""
    if not isinstance(result, dict):
        return None
    if result.get("error"):
        return str(result["error"])
    status = str(result.get("status", "")).lower()
    if status in {"failed", "failure", "error"} or result.get("failed") is True or result.get("success") is False:
        return str(result.get("message") or result.get("status") or "scanner reported failure")
    report = result.get("report")
    if isinstance(report, dict) and report.get("error"):
        return str(report["error"])
    return None


def _job_status(slug, kind, job_id, running=None):
    """Return status only for this exact org, kind, and job id."""
    job = _get_job(slug, kind, job_id)
    if job is None:
        return JSONResponse({"error": "unknown job", "job_id": job_id,
                             "slug": slug, "kind": kind}, status_code=404)
    payload = {"status": job.get("status", "failed"), "job_id": job_id}
    for key in ("stage", "progress", "error", "started", "finished"):
        if job.get(key) is not None:
            payload[key] = job[key]
    if isinstance(job.get("result"), dict):
        payload["result"] = job["result"]
    if job.get("started"):
        end = job.get("finished") if job.get("status") != "running" else time.time()
        payload["elapsed"] = round(max(0, end - job["started"]), 1)
    return payload


# seed in-memory ring from persisted logs (survives server restarts)
_JOB_LOGS.extend(_load_recent_logs())


# --------------------------------------------------------------------------
# validation / auth helpers
# --------------------------------------------------------------------------
def _valid_slug(slug):
    return bool(slug) and bool(_SLUG_RE.match(slug))


_SESSIONS = {}   # cookie-session id -> expiry epoch (in-memory, single-user)
_SESSION_TTL = 12 * 3600   # 12h idle session
_SESSION_COOKIE = "cti_session"
_LOGIN_FAILS = {}  # source IP -> [failure timestamps]
_LOGIN_FAIL_LOCK = threading.Lock()
_LOGIN_FAIL_MAX = 4096

def _login_limit(ip):
    now = time.time()
    threshold = max(1, _int_env("CTI_LOGIN_FAIL_THRESHOLD", 5))
    window = max(1, _int_env("CTI_LOGIN_FAIL_WINDOW", 300))
    retry = max(1, _int_env("CTI_LOGIN_RETRY_AFTER", 60))
    with _LOGIN_FAIL_LOCK:
        for key, vals in list(_LOGIN_FAILS.items()):
            vals[:] = [t for t in vals if now - t < window]
            if not vals:
                _LOGIN_FAILS.pop(key, None)
        vals = _LOGIN_FAILS.get(ip, [])
        if len(vals) >= threshold:
            return True, retry
    return False, retry

def _record_login_failure(ip):
    now = time.time()
    window = max(1, _int_env("CTI_LOGIN_FAIL_WINDOW", 300))
    with _LOGIN_FAIL_LOCK:
        vals = [t for t in _LOGIN_FAILS.get(ip, []) if now - t < window]
        if len(_LOGIN_FAILS) >= _LOGIN_FAIL_MAX and ip not in _LOGIN_FAILS:
            oldest = min(_LOGIN_FAILS, key=lambda k: _LOGIN_FAILS[k][-1])
            _LOGIN_FAILS.pop(oldest, None)
        vals.append(now)
        _LOGIN_FAILS[ip] = vals

def _reset_login_failures(ip):
    with _LOGIN_FAIL_LOCK:
        _LOGIN_FAILS.pop(ip, None)


def _cookie_token(req):
    """Read the session id from an HTTP-only cookie, if present."""
    try:
        from http.cookies import SimpleCookie
        sc = SimpleCookie(req.headers.get("Cookie", ""))
        morsel = sc.get(_SESSION_COOKIE)
        return morsel.value if morsel else None
    except Exception:
        return None


def _auth_ok(req):
    """Auth is satisfied by EITHER a valid login session cookie OR the
    static API token (X-CTI-Token) so headless scans still work."""
    import time as _t
    # (1) session cookie
    sid = _cookie_token(req)
    if sid:
        exp = _SESSIONS.get(sid)
        if exp and _t.time() <= exp:
            return True
        if exp:
            _SESSIONS.pop(sid, None)
    # (2) static API token for scripted/CI scans (constant-time compare)
    import secrets as _s
    tok = os.environ.get("CTI_SCAN_TOKEN", "")
    supplied = req.headers.get("X-CTI-Token") or ""
    if tok and supplied and _s.compare_digest(tok, supplied):
        return True
    return False


def _login_ok(body_or_req):
    """Validate username/password; on success issue a session id (stored in
    _SESSIONS) which the login handler sets as an HttpOnly cookie."""
    import base64
    import secrets as _secrets
    import time as _t
    u = os.environ.get("CTI_USER", "")
    p = os.environ.get("CTI_PASSWORD", "")
    if not u or not p:
        return None
    auth = getattr(body_or_req, "headers", {}).get("Authorization", "") if hasattr(body_or_req, "headers") else ""
    if not auth.startswith("Basic "):
        return None
    try:
        raw = base64.b64decode(auth[6:].strip()).decode("utf-8", "replace")
    except Exception:
        return None
    if ":" not in raw:
        return None
    gu, gp = raw.split(":", 1)
    if not (_secrets.compare_digest(gu, u) and _secrets.compare_digest(gp, p)):
        return None
    sid = _secrets.token_urlsafe(32)
    _SESSIONS[sid] = _t.time() + _SESSION_TTL
    return sid


def _org_not_found(slug):
    return JSONResponse({"error": "org not found", "slug": slug}, status_code=404)


def _canonical_openhack_domain(value):
    """Return a strict DNS name, or None (never normalize unsafe syntax)."""
    if not isinstance(value, str):
        return None
    value = value.strip()
    if not value or value.endswith(".."):
        return None
    value = value.lower()
    if value.endswith("."):
        value = value[:-1]
    # Reuse the scanner's deliberately conservative DNS validator.  In
    # particular this excludes URLs, paths, ports, wildcards, and IPs.
    return value if scanner._is_valid_domain(value) else None


def _openhack_authorization_error(org):
    """Fail-closed server-level authorization for active external assessment."""
    if os.environ.get("CTI_OPENHACK_ACTIVE") != "1":
        return "CTI_OPENHACK_ACTIVE must equal 1"
    if os.environ.get("CTI_OPENHACK_ISOLATED") != "1":
        return "CTI_OPENHACK_ISOLATED must equal 1 (use a disposable-container wrapper)"
    bin_path = os.environ.get("CTI_OPENHACK_BIN", "").strip()
    if not bin_path or not os.path.isabs(bin_path) or not os.path.isfile(bin_path) or not os.access(bin_path, os.X_OK):
        return "CTI_OPENHACK_BIN must be an explicit absolute executable (disposable-container wrapper)"

    raw = os.environ.get("CTI_OPENHACK_ALLOWED_DOMAINS")
    if raw is None or not raw.strip():
        return "CTI_OPENHACK_ALLOWED_DOMAINS is missing or empty"
    entries = raw.split(",")
    allowed = set()
    for item in entries:
        domain = _canonical_openhack_domain(item)
        if domain is None:
            return "CTI_OPENHACK_ALLOWED_DOMAINS contains an invalid domain"
        allowed.add(domain)

    targets = org.get("domains") if isinstance(org, dict) else None
    if not isinstance(targets, list) or not targets:
        return "the organization has no registered target domains"
    canonical_targets = []
    for target in targets:
        domain = _canonical_openhack_domain(target)
        if domain is None:
            return "the organization has an invalid registered target domain"
        canonical_targets.append(domain)
    outside = [domain for domain in canonical_targets if domain not in allowed]
    if outside:
        return "registered target domain outside CTI_OPENHACK_ALLOWED_DOMAINS"

    raw_expiry = os.environ.get("CTI_OPENHACK_ROE_EXPIRES", "")
    try:
        stamp = raw_expiry.strip()
        if stamp.endswith(("Z", "z")):
            stamp = stamp[:-1] + "+00:00"
        expires = datetime.fromisoformat(stamp)
        if expires.tzinfo is None or expires.utcoffset() is None:
            return "CTI_OPENHACK_ROE_EXPIRES must be timezone-aware RFC3339/ISO-8601"
        if expires.astimezone(timezone.utc) <= datetime.now(timezone.utc):
            return "CTI_OPENHACK_ROE_EXPIRES is expired"
    except (TypeError, ValueError, OverflowError):
        return "CTI_OPENHACK_ROE_EXPIRES is not a valid RFC3339/ISO-8601 timestamp"
    return None


def _use_secure_cookie(req):
    """Set Secure flag on cookies when the request came over HTTPS."""
    if req and (req.headers.get("x-forwarded-proto", "") == "https" or
                req.url.scheme == "https"):
        return True
    return False


def _require_org(slug, req):
    """Validate slug, require auth, and verify org exists in registry.
    Returns (None, None) on success, or (JSONResponse, None) on failure."""
    if not _valid_slug(slug):
        return JSONResponse({"error": "invalid slug"}, status_code=400), None
    if not _auth_ok(req):
        return JSONResponse({"error": "unauthorized"}, status_code=401), None
    org = cc.org_get(slug)
    if org is None:
        return _org_not_found(slug), None
    return None, org


# --------------------------------------------------------------------------
# session auth endpoints
# --------------------------------------------------------------------------
@app.post("/api/login")
def api_login(req: Request):
    ip = req.client.host if req.client else "unknown"
    limited, retry = _login_limit(ip)
    if limited:
        return JSONResponse({"error": "too many failed login attempts"},
                            status_code=429, headers={"Retry-After": str(retry)})
    sid = _login_ok(req)
    if not sid:
        _record_login_failure(ip)
        return JSONResponse({"error": "invalid username or password"},
                            status_code=401)
    _reset_login_failures(ip)
    resp = JSONResponse({"ok": True, "expires_in": _SESSION_TTL,
                         "user": os.environ.get("CTI_USER", "")})
    resp.set_cookie(_SESSION_COOKIE, sid, max_age=_SESSION_TTL,
                    httponly=True, samesite="lax", secure=_use_secure_cookie(req),
                    path="/")
    return resp


@app.post("/api/logout")
def api_logout(req: Request):
    sid = _cookie_token(req)
    if sid:
        _SESSIONS.pop(sid, None)
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(_SESSION_COOKIE, path="/")
    return resp


# --------------------------------------------------------------------------
# read-only data access (org-parameterized, default "sample")
# --------------------------------------------------------------------------
def _read_auth(req, org):
    """Validate auth + org existence for read endpoints. Returns error Response or None."""
    if req is None or not _auth_ok(req):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    if not _valid_slug(org):
        return JSONResponse({"error": "invalid org"}, status_code=400)
    if cc.org_get(org) is None:
        return _org_not_found(org)
    return None


@app.get("/api/graph")
def api_graph(org: str = _DEFAULT_ORG, req: Request = None):
    err = _read_auth(req, org)
    if err:
        return err
    return cc.build_graph(org)


@app.get("/api/summary")
def api_summary(org: str = _DEFAULT_ORG, req: Request = None):
    err = _read_auth(req, org)
    if err:
        return err
    return cc.summary(org)


@app.get("/api/fleet")
def api_fleet(org: str = _DEFAULT_ORG, req: Request = None):
    err = _read_auth(req, org)
    if err:
        return err
    return cc.fleet_spread(org)


@app.get("/api/ips")
def api_ips(org: str = _DEFAULT_ORG, req: Request = None):
    err = _read_auth(req, org)
    if err:
        return err
    return cc.ip_sharing(org)


@app.get("/api/findings")
def api_findings(org: str = _DEFAULT_ORG, sort: str = None, status: str = "all", req: Request = None):
    err = _read_auth(req, org)
    if err:
        return err
    fs, _ = cc.load_data(org)
    meta_date = cc.load_meta_date(org)
    # This legacy endpoint intentionally returns the complete finding contract.
    nf = [cc.normalize_finding(f, org, meta_date=meta_date) for f in fs]
    if status and status != "all":
        nf = [f for f in nf if str(f.get("status", "OPEN")).upper() == status.upper()]
    if sort == "severity":
        nf.sort(key=lambda f: _SEV_ORDER.get(
            str(f.get("severity", "INFO")).upper(), 99))
    elif sort in ("newest", "oldest"):
        dated = [f for f in nf if f.get("found_date")]
        undated = [f for f in nf if not f.get("found_date")]
        dated.sort(key=lambda f: f.get("found_date"), reverse=(sort == "newest"))
        nf = dated + undated
    return {"findings_total": len(nf), "findings": nf}


def _build_dashboard_payload(org: str, sort: str = None, status: str = "all"):
    """Aggregate dashboard payload reusing ONE findings/correlation load per request.

    Returns shapes identical to /api/summary, /api/graph, /api/fleet, /api/ips,
    /api/findings (filtered/sorted), and /api/orgs/{slug}/history. Uses the
    read-through cache in cti_correlation so repeated views avoid disk reads.
    """
    fs, baseline = cc.load_data(org)
    meta_date = cc.load_meta_date(org)
    domains = (cc.REGISTRY.get(org) or {}).get("domains") or []

    # The aggregate endpoint intentionally uses the lightweight list projection;
    # callers fetch full details from /api/findings/{id} on demand.
    nf = [cc.normalize_finding_light(f, org, meta_date=meta_date) for f in fs]
    if status and status != "all":
        nf = [f for f in nf if str(f.get("status", "OPEN")).upper() == status.upper()]
    if sort == "severity":
        nf.sort(key=lambda f: _SEV_ORDER.get(str(f.get("severity", "INFO")).upper(), 99))
    elif sort in ("newest", "oldest"):
        dated = [f for f in nf if f.get("found_date")]
        undated = [f for f in nf if not f.get("found_date")]
        dated.sort(key=lambda f: f.get("found_date"), reverse=(sort == "newest"))
        nf = dated + undated

    # history (same shape as /api/orgs/{slug}/history)
    events = scanner.read_history(org) if _valid_slug(org) and cc.org_get(org) is not None else []
    by_kind = {}
    for e in events:
        k = e.get("kind", "?")
        by_kind[k] = by_kind.get(k, 0) + 1
    history = {"org": org, "events": events[::-1][:100], "summary": {"total": len(events), "by_kind": by_kind}}

    return {
        "org": org,
        "summary": cc.summary_from_data(fs, baseline),
        "graph": cc.build_graph_from_data(fs, baseline, domains),
        "fleet": cc.fleet_spread_from_data(fs),
        "ips": cc.ip_sharing_from_data(fs),
        "findings": {"findings_total": len(nf), "findings": nf},
        "history": history,
    }


@app.get("/api/dashboard")
def api_dashboard(org: str = _DEFAULT_ORG, sort: str = None, status: str = "all", req: Request = None):
    err = _read_auth(req, org)
    if err:
        return err
    return _build_dashboard_payload(org, sort=sort, status=status)


@app.get("/api/orgs/{slug}/dashboard")
def api_org_dashboard(slug: str, sort: str = None, status: str = "all", req: Request = None):
    err = _read_auth(req, slug)
    if err:
        return err
    return _build_dashboard_payload(slug, sort=sort, status=status)


@app.get("/api/findings/{id_}")
def api_finding_detail(id_: str, org: str = _DEFAULT_ORG, req: Request = None):
    err = _read_auth(req, org)
    if err:
        return err
    f = cc.find_finding(org, id_)
    if f is None:
        return JSONResponse({"error": "finding not found", "id": id_, "org": org},
                            status_code=404)
    return {"org": org, "finding": cc.normalize_finding(f, org)}


@app.get("/api/orgs")
def api_orgs(req: Request = None):
    if not _auth_ok(req):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    return {"orgs": cc.org_list()}


@app.get("/api/admin/logs")
def api_admin_logs(org: str = None, limit: int = 200, req: Request = None):
    """Recent runtime logs (scan/recheck/correlate/AI attempts + failures)."""
    if not _auth_ok(req):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    lim = max(1, min(int(limit or 200), 1000))
    with _JOB_LOG_LOCK:
        logs = list(_JOB_LOGS[-lim:])
    if org:
        logs = [l for l in logs if l.get("org") == org][-lim:]
    return {"logs": logs[::-1], "total": len(logs)}


@app.get("/api/orgs/{slug}")
def api_org_get(slug: str, req: Request = None):
    err, org = _require_org(slug, req)
    if err:
        return err
    caps = ai_providers.get_capabilities()
    effective = ai_providers.resolve_profile_for_org(slug)
    # per-org profile now stored in ignored runtime file; fallback to legacy orgs.json
    stored = ai_providers.get_org_profile(slug)
    if stored is None:
        stored = org.get("ai_profile")
    return {"slug": slug, "name": org.get("name"), "domains": org.get("domains", []),
            "ai_profile": stored,
            "effective_ai_profile": effective,
            "ai_capabilities": caps,
            "openhack_enabled": bool(org.get("openhack_enabled")),
            "openhack_model": org.get("openhack_model") or "",
            "summary": cc.summary(slug)}


# --------------------------------------------------------------------------
# OpenHack ingestion source (opt-in, ACTIVE testing)
# --------------------------------------------------------------------------
class OpenhackConfigBody(BaseModel):
    enabled: Optional[bool] = None
    model: Optional[str] = None


class OpenhackScanBody(BaseModel):
    mode: str = "quick"
    model: Optional[str] = None


_MODEL_RE = re.compile(r"^[\w.\-/]{1,64}$")   # provider-namespaced ids


@app.get("/api/openhack/models")
def api_openhack_models(req: Request = None):
    """Live model catalog from the OpenHack inference service."""
    if not _auth_ok(req):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    if not oh.openhack_bin():
        return JSONResponse({"error": "openhack binary not available"},
                            status_code=503)
    return oh.list_models()


@app.post("/api/orgs/{slug}/openhack-config")
def api_openhack_config(slug: str, body: OpenhackConfigBody, req: Request = None):
    """Opt this org in/out of the OpenHack source and/or pin a model override
    (empty string resets to the server default)."""
    if not _auth_ok(req):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    if not _valid_slug(slug):
        return JSONResponse({"error": "invalid slug"}, status_code=400)
    model = (body.model or "").strip() if body else ""
    if model and not _MODEL_RE.match(model):
        return JSONResponse({"error": "invalid model id"}, status_code=400)
    enabled = body.enabled if (body and body.enabled is not None) else None
    with _registry_lock:
        try:
            with open(ORGS_JSON) as f:
                reg = json.load(f)
            if not isinstance(reg, dict):
                raise ValueError("registry not a dict")
        except Exception:
            return JSONResponse({"error": "registry unreadable/corrupted"},
                                status_code=500)
        if slug not in reg:
            return _org_not_found(slug)
        entry = reg[slug]
        if not isinstance(entry, dict):
            return JSONResponse({"error": "corrupt registry entry"}, status_code=500)
        if enabled is not None:
            if enabled:
                entry["openhack_enabled"] = True
            else:
                entry.pop("openhack_enabled", None)
        if model:
            entry["openhack_model"] = model
        elif body is not None and body.model is not None:
            entry.pop("openhack_model", None)   # explicit "" resets to default
        cc._atomic_write_json(ORGS_JSON, reg)
    cc._reload_registry()
    _log_event("info", "system", slug,
               f"openhack config updated (enabled={enabled}, model={model or 'default'})")
    # reflect what was just WRITTEN — a re-read can hit a stale patched cache
    return {"slug": slug,
            "openhack_enabled": bool(entry.get("openhack_enabled")),
            "openhack_model": entry.get("openhack_model") or ""}


@app.post("/api/orgs/{slug}/openhack-scan")
def api_org_openhack_scan(slug: str, body: OpenhackScanBody = None,
                          req: Request = None):
    """Run an OpenHack assessment over the org's registered domains and
    ingest its findings into the standard lifecycle.

    mode="quick" (default): ~8-minute budgeted pass over a ref-keyed manifest
    of OPEN findings — verifies each, grades severity (verified full range /
    unverified ±1 clamp) and enriches evidence.
    mode="deep": full unbounded agentic run."""
    if not _auth_ok(req):
        return JSONResponse({"error": "unauthorized: missing or bad credentials"},
                            status_code=401)
    if not _valid_slug(slug):
        return JSONResponse({"error": "invalid slug"}, status_code=400)
    mode = (body.mode if body else "quick") or "quick"
    if mode not in ("quick", "deep"):
        return JSONResponse({"error": "mode must be 'quick' or 'deep'"},
                            status_code=400)
    model = (body.model or "").strip() if body else ""
    if model and not _MODEL_RE.match(model):
        return JSONResponse({"error": "invalid model id"}, status_code=400)
    model = (model
             or (cc.org_get(slug) or {}).get("openhack_model")
             or oh.OHACK_PREFERRED_MODEL)   # ox-alpha: proven runnable default
    org = cc.org_get(slug)
    if org is None:
        return _org_not_found(slug)
    if not org.get("openhack_enabled"):
        return JSONResponse(
            {"error": ("openhack source not enabled for this org — "
                       "POST /api/orgs/%s/openhack-config {\"enabled\": true}" % slug)},
            status_code=403)
    # This is immediately before acquisition: no binary lookup or worker can
    # occur until the operator gate, exact target scope, and live ROE pass.
    gate_error = _openhack_authorization_error(org)
    if gate_error:
        return JSONResponse(
            {"error": "OpenHack active assessment authorization denied: " + gate_error},
            status_code=403)
    if not oh.openhack_bin():
        return JSONResponse({"error": "openhack binary not available "
                                      "(set explicit absolute CTI_OPENHACK_BIN)"}, status_code=503)
    if mode == "quick":
        stale_after = oh.quick_budget() + 600
    else:
        stale_after = int(oh._env_float("CTI_OHACK_TIMEOUT", 1800, lo=60,
                                        hi=7200)) + 600
    ok, jid = _try_acquire_job(slug, "ohack", stale_after=stale_after)
    if not ok:
        return _job_busy_response(slug, "openhack-scan", jid)
    domains = list(org.get("domains") or [])
    _log_event("info", "openhack", slug,
               f"openHack {mode} queued ({len(domains)} domain(s))", job_id=jid)

    def _on_progress(stage, message):
        _job_progress(slug, "ohack", jid, stage, message)

    def _oh_wrap():
        try:
            result = oh.run_and_ingest(slug, domains, on_progress=_on_progress,
                                       mode=mode, model=model or None)
            err = result.get("error") if isinstance(result, dict) else None
            if err:
                _release_job(slug, "ohack", jid, error=err)
                _log_event("error", "openhack", slug, f"openHack failed: {err}", job_id=jid)
            else:
                _release_job(slug, "ohack", jid)
                _log_event("info", "openhack", slug,
                           f"openHack {mode} done (+{result.get('added', 0)} new,"
                           f" {result.get('graded', 0)} graded)", job_id=jid)
        except Exception as e:
            _release_job(slug, "ohack", jid, error=e)
            _log_event("error", "openhack", slug, f"openHack failed: {e}", job_id=jid)

    _executor.submit(_oh_wrap)
    return {"queued": True, "slug": slug, "mode": mode, "job_id": jid}


@app.get("/api/orgs/{slug}/openhack-scan/{job_id}")
def api_openhack_status(slug: str, job_id: str, req: Request = None):
    err, _ = _require_org(slug, req)
    if err:
        return err
    running = False
    key = _job_key(slug, "ohack")
    with _jobs_lock:
        v = _jobs.get(key)
        running = bool(v and v.get("status") == "running" and v.get("id") == job_id)
    return _job_status(slug, "ohack", job_id, running)


# --------------------------------------------------------------------------
# AI provider config
# --------------------------------------------------------------------------
@app.get("/api/ai/capabilities")
def api_ai_capabilities(req: Request = None):
    if not _auth_ok(req):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    return ai_providers.get_capabilities()


@app.get("/api/orgs/{slug}/ai_profile")
def api_get_ai_profile(slug: str, req: Request = None):
    err, org = _require_org(slug, req)
    if err:
        return err
    effective = ai_providers.resolve_profile_for_org(slug)
    stored = ai_providers.get_org_profile(slug)
    if stored is None:
        stored = org.get("ai_profile")
    return {"slug": slug, "ai_profile": stored, "effective": effective,
            "capabilities": ai_providers.get_capabilities()}


class AiProfileBody(BaseModel):
    ai_profile: str = ""


@app.post("/api/orgs/{slug}/ai_profile")
def api_set_ai_profile(slug: str, body: AiProfileBody, req: Request):
    if not _auth_ok(req):
        return JSONResponse({"error": "unauthorized: missing or bad credentials (username/password)"},
                            status_code=401)
    if not _valid_slug(slug):
        return JSONResponse({"error": "invalid slug"}, status_code=400)
    if cc.org_get(slug) is None:
        return _org_not_found(slug)
    profiles, _ = ai_providers.load_profiles()
    desired = str(body.ai_profile or "").strip()
    # allow clearing by empty string
    if desired and desired not in profiles:
        return JSONResponse({"error": "invalid ai_profile", "allowed": sorted(profiles.keys())}, status_code=400)
    # persist to ignored runtime file (atomic, does not dirty tracked registry)
    ai_providers.set_org_profile(slug, desired)
    effective = ai_providers.resolve_profile_for_org(slug)
    return {"slug": slug, "ai_profile": desired or None, "effective": effective}


# --------------------------------------------------------------------------
# token-gated mutations (register + scan)
# --------------------------------------------------------------------------
class RegisterOrg(BaseModel):
    slug: str
    name: str = ""
    domains: list = []
    ai_profile: str = ""


@app.post("/api/orgs/register")
def api_org_register(body: RegisterOrg, req: Request):
    if not _auth_ok(req):
        return JSONResponse({"error": "unauthorized: missing or bad credentials (username/password)"},
                            status_code=401)
    slug = (body.slug or "").strip()
    if not _valid_slug(slug):
        return JSONResponse({"error": "invalid slug (^[a-z0-9-]{1,32}$)"},
                            status_code=400)
    if cc.org_get(slug) is not None:
        return JSONResponse({"error": "org already registered", "slug": slug},
                            status_code=409)

    name = (body.name or "").strip() or slug
    if len(name) > 200:
        return JSONResponse({"error": "name too long (max 200 chars)"}, status_code=400)
    # strict DNS domain validation via scanner helper (reuse via import)
    import scanner as _scanner
    domains = []
    for d in body.domains or []:
        d = str(d).strip().lower().rstrip(".")
        if _scanner._is_valid_domain(d):
            domains.append(d)
    domains = list(dict.fromkeys(domains))  # dedup, order preserved
    if len(domains) > 20:
        return JSONResponse({"error": "too many domains (max 20)"}, status_code=400)
    if body.domains and not domains:
        return JSONResponse({"error": "no valid domains (strict DNS name required)"}, status_code=400)
    # validate ai_profile before any filesystem mutation
    ai_profile = str(getattr(body, "ai_profile", "") or "").strip()
    profiles, _ = ai_providers.load_profiles()
    if ai_profile and ai_profile not in profiles:
        return JSONResponse({"error": "invalid ai_profile", "allowed": sorted(profiles.keys())}, status_code=400)

    # locked registry read-check-write (prevents concurrent registrations losing each other)
    with _registry_lock:
        registry = {}
        corrupted = False
        if os.path.exists(ORGS_JSON):
            try:
                with open(ORGS_JSON) as f:
                    registry = json.load(f)
                if not isinstance(registry, dict):
                    corrupted = True
            except Exception:
                corrupted = True
        if corrupted:
            return JSONResponse({"error": "registry corrupted, aborting"}, status_code=500)
        if slug in registry:
            return JSONResponse({"error": "org already registered", "slug": slug}, status_code=409)
        registry[slug] = {
            "name": name,
            "domains": domains,
            "findings": f"data/orgs/{slug}/findings.json",
            "baseline": f"data/orgs/{slug}/baseline.txt",
        }
        cc._atomic_write_json(ORGS_JSON, registry)
    cc._reload_registry()

    # filesystem creation after successful registry commit (with cleanup on failure)
    try:
        org_dir = os.path.join(DATA_ORG_DIR, slug)
        os.makedirs(org_dir, mode=0o700, exist_ok=True)
        cc._atomic_write_text(os.path.join(org_dir, "baseline.txt"), "")
        cc._atomic_write_json(os.path.join(org_dir, "findings.json"), {"findings": []})
    except Exception:
        # cleanup partial registry on failure? keep registry but org will be empty
        pass
    if ai_profile:
        ai_providers.set_org_profile(slug, ai_profile)

    _log_event("info", "system", slug, f"workspace registered ({name}, {len(domains)} domain(s))")
    return {"slug": slug, "name": name, "domains": domains, "ai_profile": ai_profile or None}


class DomainsBody(BaseModel):
    domains: list = []
    action: str = "add"


@app.post("/api/orgs/{slug}/domains")
def api_org_domains(slug: str, body: DomainsBody, req: Request):
    """Add / remove / replace domains for an existing workspace.

    Lets operators grow a workspace's scan scope after registration without
    re-registering (which would 409) or hand-editing orgs.json.
    """
    if not _auth_ok(req):
        return JSONResponse({"error": "unauthorized: missing or bad credentials (username/password)"},
                            status_code=401)
    if not _valid_slug(slug):
        return JSONResponse({"error": "invalid slug"}, status_code=400)
    if cc.org_get(slug) is None:
        return _org_not_found(slug)
    action = str(getattr(body, "action", "add") or "add").strip().lower()
    if action not in ("add", "remove", "set"):
        return JSONResponse({"error": "invalid action (add|remove|set)"}, status_code=400)
    import scanner as _scanner
    domains = []
    for d in body.domains or []:
        d = str(d).strip().lower().rstrip(".")
        if _scanner._is_valid_domain(d):
            domains.append(d)
    domains = list(dict.fromkeys(domains))  # dedup, order preserved
    if body.domains and not domains:
        return JSONResponse({"error": "no valid domains (strict DNS name required)"}, status_code=400)

    with _registry_lock:
        registry = {}
        corrupted = False
        if os.path.exists(ORGS_JSON):
            try:
                with open(ORGS_JSON) as f:
                    registry = json.load(f)
                if not isinstance(registry, dict):
                    corrupted = True
            except Exception:
                corrupted = True
        if corrupted:
            return JSONResponse({"error": "registry corrupted, aborting"}, status_code=500)
        entry = registry.get(slug)
        if not isinstance(entry, dict):
            return _org_not_found(slug)
        cur = [str(d).strip() for d in (entry.get("domains") or []) if str(d).strip()]
        if action == "add":
            new_domains = list(dict.fromkeys(cur + domains))
        elif action == "remove":
            new_domains = [d for d in cur if d not in domains]
        else:
            new_domains = domains
        if len(new_domains) > 20:
            return JSONResponse({"error": "too many domains (max 20)"}, status_code=400)
        entry["domains"] = new_domains
        registry[slug] = entry
        cc._atomic_write_json(ORGS_JSON, registry)
    cc._reload_registry()
    _log_event("info", "system", slug,
               f"domains updated ({action}): {', '.join(new_domains) or '(none)'}")
    return {"slug": slug, "domains": new_domains}


class ScanBody(BaseModel):
    mode: str = "fast"
    ai_profile: str = ""


@app.post("/api/orgs/{slug}/scan")
def api_org_scan(slug: str, body: ScanBody = None, req: Request = None):
    if not _auth_ok(req):
        return JSONResponse({"error": "unauthorized: missing or bad credentials (username/password)"},
                            status_code=401)
    if not _valid_slug(slug):
        return JSONResponse({"error": "invalid slug"}, status_code=400)
    org = cc.org_get(slug)
    if org is None:
        return _org_not_found(slug)
    mode = "fast"
    if body is not None and getattr(body, "mode", "fast") == "ai":
        mode = "ai"
    # resolve ai_profile: request override > org's stored preference > default
    ai_profile_req = str(getattr(body, "ai_profile", "") or "").strip() if body else ""
    if ai_profile_req:
        profiles, _ = ai_providers.load_profiles()
        if ai_profile_req not in profiles:
            return JSONResponse({"error": "invalid ai_profile", "allowed": sorted(profiles.keys())}, status_code=400)
    effective_profile = ai_providers.resolve_profile_for_org(slug, override=ai_profile_req or None)
    # AI fallback: deterministic scan always queues; AI unavailability is recorded in history, not as 400
    # (preserves cron compatibility: mode=ai without config safely degrades to deterministic)
    if mode == "ai" and effective_profile:
        profiles, _ = ai_providers.load_profiles()
        prof = profiles.get(effective_profile)
        if prof and prof.get("provider") == "openai-compatible" and prof.get("api_key_env"):
            if not os.environ.get(prof["api_key_env"], "").strip():
                # mark as not ready but still queue deterministic scan; scanner will log AI failed
                effective_profile = None
        if effective_profile and not ai_providers.load_profiles()[0].get(effective_profile, {}).get("provider"):
            effective_profile = None
    ok, jid = _try_acquire_job(slug, "scan")
    if not ok:
        return _job_busy_response(slug, "scan", jid)
    org = dict(org, slug=slug)
    if mode == "ai" and not effective_profile:
        _log_event("warn", "scan", slug,
                   "AI mode requested but no ready profile — falling back to deterministic scan",
                   job_id=jid)
    _log_event("info", "scan", slug,
               f"scan queued (mode={mode}, ai_profile={effective_profile or 'auto'})",
               job_id=jid)

    def _on_progress(stage, message):
        _job_progress(slug, "scan", jid, stage, message)

    def _scan_wrap():
        try:
            result = scanner.generate_org(org, mode=mode, ai_profile=effective_profile or ai_profile_req,
                                          on_progress=_on_progress)
            # fatal scan failures (e.g. corrupted findings.json) return an
            # "error" key instead of raising — surface them as failed jobs.
            # Optional AI failure does NOT set this key: a good deterministic
            # scan still finishes "done".
            err = _structured_job_failure(result)
            if err:
                _release_job(slug, "scan", jid, error=err, result=result)
                _log_event("error", "scan", slug, f"scan failed: {err}", job_id=jid)
            else:
                _release_job(slug, "scan", jid, result=result if isinstance(result, dict) else None)
                _log_event("info", "scan", slug, "scan completed", job_id=jid)
        except Exception as e:
            _release_job(slug, "scan", jid, error=e)
            _log_event("error", "scan", slug, f"scan failed: {e}", job_id=jid)

    _executor.submit(_scan_wrap)
    return {"queued": True, "slug": slug, "mode": mode, "ai_profile": effective_profile, "job_id": jid}


@app.post("/api/orgs/{slug}/recheck")
def api_org_recheck(slug: str, req: Request):
    """Light remediation recheck: probe ONLY each finding's own IP/port."""
    if not _auth_ok(req):
        return JSONResponse({"error": "unauthorized: missing or bad credentials (username/password)"},
                            status_code=401)
    if not _valid_slug(slug):
        return JSONResponse({"error": "invalid slug"}, status_code=400)
    if cc.org_get(slug) is None:
        return _org_not_found(slug)

    ok, jid = _try_acquire_job(slug, "recheck")
    if not ok:
        return _job_busy_response(slug, "recheck", jid)
    _log_event("info", "recheck", slug, "recheck queued", job_id=jid)

    def _on_progress(stage, message):
        _job_progress(slug, "recheck", jid, stage, message)

    def _run():
        try:
            changed = scanner.recheck_findings(slug, on_progress=_on_progress)
            scanner.append_history(slug, {"kind": "recheck", "mode": "fast",
                                           "summary": {"changed": changed, "finding": "probe own ip/port"},
                                           "note": "light remediation recheck"})
            _release_job(slug, "recheck", jid)
            _log_event("info", "recheck", slug, f"recheck completed ({changed} change(s))", job_id=jid)
            return changed
        except Exception as e:
            _release_job(slug, "recheck", jid, error=e)
            _log_event("error", "recheck", slug, f"recheck failed: {e}", job_id=jid)
            return 0

    _executor.submit(_run)
    return {"queued": True, "slug": slug, "job_id": jid}


@app.get("/api/orgs/{slug}/recheck/{job_id}")
def api_recheck_status(slug: str, job_id: str, req: Request = None):
    err, _ = _require_org(slug, req)
    if err:
        return err
    running = _is_job_running(slug, "recheck")
    return _job_status(slug, "recheck", job_id, running)


@app.get("/api/orgs/{slug}/history")
def api_org_history(slug: str, req: Request = None):
    err, _ = _require_org(slug, req)
    if err:
        return err
    events = scanner.read_history(slug)
    by_kind = {}
    for e in events:
        k = e.get("kind", "?")
        by_kind[k] = by_kind.get(k, 0) + 1
    return {"org": slug, "events": events[::-1][:100],
            "summary": {"total": len(events), "by_kind": by_kind}}


class StatusBody(BaseModel):
    status: str
    note: str = ""


@app.post("/api/orgs/{slug}/findings/{id_}/status")
def api_status_change(slug: str, id_: str, body: StatusBody, req: Request):
    if not _auth_ok(req):
        return JSONResponse({"error": "unauthorized: missing or bad credentials (username/password)"},
                            status_code=401)
    if not _valid_slug(slug):
        return JSONResponse({"error": "invalid slug"}, status_code=400)
    if cc.org_get(slug) is None:
        return _org_not_found(slug)
    status = (body.status or "").strip().upper()
    if status not in cc.CANONICAL_STATUSES:
        return JSONResponse({"error": "invalid status", "allowed": list(cc.CANONICAL_STATUSES)},
                            status_code=400)
    finding, err = cc.set_finding_status(slug, id_, status, note=(body.note or "").strip())
    if err:
        if err == "not found":
            return JSONResponse({"error": "finding not found", "id": id_}, status_code=404)
        return JSONResponse({"error": err}, status_code=400)
    _log_event("info", "status", slug, f"finding {id_} status -> {status}")
    return {"org": slug, "finding": cc.normalize_finding(finding, slug)}


class CommentBody(BaseModel):
    note: str
    by: str = ""


@app.post("/api/orgs/{slug}/findings/{id_}/comment")
def api_finding_comment(slug: str, id_: str, body: CommentBody, req: Request):
    """Append an analyst comment to a finding; this feedback is weighed by the
    AI triage pass on the next `mode=ai` scan of the org."""
    if not _auth_ok(req):
        return JSONResponse({"error": "unauthorized: missing or bad credentials (username/password)"},
                            status_code=401)
    if not _valid_slug(slug):
        return JSONResponse({"error": "invalid slug"}, status_code=400)
    if cc.org_get(slug) is None:
        return _org_not_found(slug)
    note = (body.note or "").strip()
    if not note:
        return JSONResponse({"error": "note is required"}, status_code=400)
    finding, err = cc.add_finding_comment(slug, id_, note, by=(body.by or "").strip())
    if err:
        if err == "not found":
            return JSONResponse({"error": "finding not found", "id": id_}, status_code=404)
        return JSONResponse({"error": err}, status_code=400)
    _log_event("info", "comment", slug, f"finding {id_} commented (analyst feedback)")
    return {"org": slug, "finding": cc.normalize_finding(finding, slug)}


@app.post("/api/orgs/{slug}/correlate")
def api_org_correlate(slug: str, req: Request):
    if not _auth_ok(req):
        return JSONResponse({"error": "unauthorized: missing or bad credentials (username/password)"},
                            status_code=401)
    if not _valid_slug(slug):
        return JSONResponse({"error": "invalid slug"}, status_code=400)
    org = cc.org_get(slug)
    if org is None:
        return _org_not_found(slug)
    ok, jid = _try_acquire_job(slug, "correlate")
    if not ok:
        return _job_busy_response(slug, "correlate", jid)
    org = dict(org, slug=slug)
    _log_event("info", "correlate", slug, "correlation queued", job_id=jid)

    def _on_progress(stage, message):
        _job_progress(slug, "correlate", jid, stage, message)

    def _corr_wrap():
        try:
            result = scanner.correlate_org(org, on_progress=_on_progress)
            err = _structured_job_failure(result)
            if err:
                _release_job(slug, "correlate", jid, error=err, result=result)
                _log_event("error", "correlate", slug, f"correlation failed: {err}", job_id=jid)
            else:
                _release_job(slug, "correlate", jid, result=result if isinstance(result, dict) else None)
                _log_event("info", "correlate", slug, "correlation completed", job_id=jid)
        except Exception as e:
            _release_job(slug, "correlate", jid, error=e)
            _log_event("error", "correlate", slug, f"correlation failed: {e}", job_id=jid)

    _executor.submit(_corr_wrap)
    return {"queued": True, "job_id": jid}


@app.get("/api/orgs/{slug}/correlate/{job_id}")
def api_correlate_status(slug: str, job_id: str, req: Request = None):
    err, _ = _require_org(slug, req)
    if err:
        return err
    running = _is_job_running(slug, "correlate") or scanner.is_correlating(slug)
    payload = _job_status(slug, "correlate", job_id, running)
    if isinstance(payload, JSONResponse):
        return payload
    report = cc.correlation_report(slug) or {}
    payload["correlated"] = report.get("added", 0)
    payload["report"] = report
    return payload


@app.get("/api/orgs/{slug}/scan/{job_id}")
def api_scan_status(slug: str, job_id: str, req: Request = None):
    err, _ = _require_org(slug, req)
    if err:
        return err
    running = _is_job_running(slug, "scan")
    return _job_status(slug, "scan", job_id, running)


class GradeBody(BaseModel):
    ai_profile: str = ""


@app.post("/api/orgs/{slug}/ai-grade")
def api_org_ai_grade(slug: str, body: GradeBody = None, req: Request = None):
    """Standalone Stage-B AI grading: re-severity/impact existing OPEN findings
    by ID (judgment only — deterministic findings are never removed or invented)."""
    if not _auth_ok(req):
        return JSONResponse({"error": "unauthorized: missing or bad credentials (username/password)"},
                            status_code=401)
    if not _valid_slug(slug):
        return JSONResponse({"error": "invalid slug"}, status_code=400)
    if cc.org_get(slug) is None:
        return _org_not_found(slug)
    ai_profile_req = str(getattr(body, "ai_profile", "") or "").strip() if body else ""
    if ai_profile_req:
        profiles, _ = ai_providers.load_profiles()
        if ai_profile_req not in profiles:
            return JSONResponse({"error": "invalid ai_profile", "allowed": sorted(profiles.keys())}, status_code=400)
    ok, jid = _try_acquire_job(slug, "grade")
    if not ok:
        return _job_busy_response(slug, "grading", jid)
    _log_event("info", "ai_grade", slug, f"AI grading queued (profile={ai_profile_req or 'auto'})", job_id=jid)

    def _on_progress(stage, message):
        _job_progress(slug, "grade", jid, stage, message)

    def _grade_wrap():
        try:
            result = scanner.ai_grade_org(slug, profile_name=ai_profile_req or None, on_progress=_on_progress)
            # ai_grade_org never raises; "failed" means grading could not run
            if result == "failed":
                _release_job(slug, "grade", jid, error="AI grading failed (provider or persistence error)")
                _log_event("error", "ai_grade", slug, "AI grading failed", job_id=jid)
            else:
                _release_job(slug, "grade", jid)
                _log_event("info", "ai_grade", slug, f"AI grading completed ({result})", job_id=jid)
        except Exception as e:
            _release_job(slug, "grade", jid, error=e)
            _log_event("error", "ai_grade", slug, f"AI grading failed: {e}", job_id=jid)

    _executor.submit(_grade_wrap)
    return {"queued": True, "slug": slug, "job_id": jid}


@app.get("/api/orgs/{slug}/ai-grade/{job_id}")
def api_ai_grade_status(slug: str, job_id: str, req: Request = None):
    err, _ = _require_org(slug, req)
    if err:
        return err
    running = _is_job_running(slug, "grade")
    return _job_status(slug, "grade", job_id, running)


def _esc(s):
    return _html.escape(str(s), quote=True)


def _render_value(v):
    if v is None:
        return "<span class='na'>&mdash;</span>"
    if isinstance(v, bool):
        return _esc(str(v).lower())
    if isinstance(v, (list, tuple)):
        if not v:
            return "<span class='na'>&mdash;</span>"
        return "<ul>" + "".join(f"<li>{_render_value(x)}</li>" for x in v) + "</ul>"
    if isinstance(v, dict):
        if not v:
            return "<span class='na'>&mdash;</span>"
        pre = _esc(json.dumps(v, indent=2, ensure_ascii=False))
        return f"<pre>{pre}</pre>"
    return _esc(v)


def _build_report_html(slug, org, fs, domains):
    name = _esc(org.get("name") or slug)
    domains_s = ", ".join(_esc(d) for d in domains) or "&mdash;"
    date_s = _esc(time.strftime("%Y-%m-%d"))
    # use normalized (PII-masked) findings for report
    meta_date = cc.load_meta_date(slug)
    nfs = [cc.normalize_finding(f, slug, meta_date=meta_date) for f in fs]
    # resolved findings are lifecycle-noise in a point-in-time report: count
    # them, but keep sections focused on live items
    resolved_n = sum(1 for f in nfs
                     if str(f.get("status", "")).upper() == "RESOLVED")
    fs = [f for f in nfs if str(f.get("status", "")).upper() != "RESOLVED"]
    sev = {}
    for f in fs:
        s = str(f.get("severity", "INFO")).upper()
        sev[s] = sev.get(s, 0) + 1
    sev_rows = "".join(
        f"<tr><td>{_esc(k)}</td><td>{_esc(v)}</td></tr>"
        for k, v in sorted(sev.items(), key=lambda kv: _SEV_ORDER.get(kv[0], 99)))
    if resolved_n:
        sev_rows += (f"<tr><td>RESOLVED (excluded from sections)</td>"
                     f"<td>{resolved_n}</td></tr>")

    sections = []
    for i, f in enumerate(fs, 1):
        fields = []
        for key in ("id", "title", "severity", "cvss_estimate", "cvss_vector",
                    "target", "ip", "category", "status", "description", "impact",
                    "evidence", "proof_chain", "remediation", "related_cves",
                    "topics_exposed", "discovery"):
            if key in f:
                fields.append(f"<tr><th>{_esc(key)}</th><td>{_render_value(f[key])}</td></tr>")
        sections.append(
            f"<section class='finding'><h2>{i}. {_esc(f.get('title', f.get('id', '')))}</h2>"
            f"<table>{''.join(fields)}</table></section>")

    return f"""<!doctype html>
<html><head><meta charset='utf-8'>
<title>CTI Report — {name}</title>
<style>
 body {{ font-family: -apple-system, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
         color: #1a1a2e; margin: 0; }}
 .cover {{ padding: 80px 60px; page-break-after: always; }}
 .cover h1 {{ font-size: 34px; margin-bottom: 8px; }}
 .cover .sub {{ color: #555; font-size: 16px; margin-bottom: 40px; }}
 table {{ width: 100%; border-collapse: collapse; margin: 14px 0; font-size: 13px; }}
 th, td {{ border: 1px solid #ddd; padding: 8px 10px; text-align: left;
            vertical-align: top; word-break: break-word; }}
 th {{ background: #f4f4f8; width: 180px; }}
 h2 {{ font-size: 16px; margin: 26px 0 4px; border-bottom: 2px solid #eee;
       padding-bottom: 4px; }}
 .finding {{ padding: 0 24px; page-break-inside: avoid; }}
 pre {{ white-space: pre-wrap; font-size: 12px; margin: 0; }}
 .na {{ color: #999; }}
</style></head>
<body>
<div class='cover'>
  <h1>CTI Radar — Correlation Report</h1>
  <div class='sub'>{name} &middot; {date_s}</div>
  <p><strong>Domains:</strong> {domains_s}</p>
  <table>
    <tr><th>Severity</th><th>Count</th></tr>
    {sev_rows}
    <tr><th>Total findings</th><th>{_esc(len(fs))}</th></tr>
  </table>
</div>
{''.join(sections)}
</body></html>"""


_PDF_SEMAPHORE = threading.Semaphore(1)  # limit concurrent Chromium processes
_MAX_PDF_FINDINGS = 500
_MAX_PDF_HTML_SIZE = 5 * 1024 * 1024  # 5 MiB
_PDF_TIMEOUT = 45  # seconds


@app.get("/api/orgs/{slug}/report.pdf")
def api_org_report_pdf(slug: str, req: Request = None):
    err, org = _require_org(slug, req)
    if err:
        return err
    fs, _ = cc.load_data(slug)
    if len(fs) > _MAX_PDF_FINDINGS:
        return JSONResponse({"error": "too many findings for PDF", "max": _MAX_PDF_FINDINGS,
                             "count": len(fs)}, status_code=413)
    domains = org.get("domains") or []
    report_html = _build_report_html(slug, org, fs, domains)
    if len(report_html) > _MAX_PDF_HTML_SIZE:
        return JSONResponse({"error": "report too large", "max": _MAX_PDF_HTML_SIZE}, status_code=413)
    if not _CHROMIUM:
        return JSONResponse(
            {"error": "Chromium not found; set CTI_CHROMIUM_PATH"}, status_code=503)
    if not _PDF_SEMAPHORE.acquire(blocking=False):
        return JSONResponse({"error": "PDF generation busy, try again"}, status_code=503)

    fd, html_path = tempfile.mkstemp(suffix=".html", prefix="cti-report-")
    with os.fdopen(fd, "w") as fh:
        fh.write(report_html)
    fd, pdf_path = tempfile.mkstemp(suffix=".pdf", prefix="cti-report-")
    os.close(fd)

    try:
        r = subprocess.run(
            [_CHROMIUM, "--headless=new", "--no-sandbox", "--disable-gpu",
             f"--print-to-pdf={pdf_path}", "--no-pdf-header-footer",
             "file://" + html_path],
            capture_output=True, text=True, timeout=_PDF_TIMEOUT)
        if os.path.exists(pdf_path) and os.path.getsize(pdf_path) > 0:
            with open(pdf_path, "rb") as fh:
                pdf = fh.read()
            if len(pdf) > 20 * 1024 * 1024:
                return JSONResponse({"error": "PDF too large"}, status_code=413)
            return Response(
                content=pdf, media_type="application/pdf",
                headers={"Content-Disposition":
                         f'attachment; filename="{slug}-report.pdf"'})
    except Exception:
        pass
    finally:
        _PDF_SEMAPHORE.release()
        for p in (html_path, pdf_path):
            try:
                os.remove(p)
            except OSError:
                pass

    return Response(
        content=report_html, media_type="text/html",
        headers={"Content-Disposition":
                 f'attachment; filename="{slug}-report.html"'})


# --------------------------------------------------------------------------
# security headers middleware (OWASP A05)
# --------------------------------------------------------------------------
@app.middleware("http")
async def security_headers(request, call_next):
    resp = await call_next(request)
    resp.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self' data:; base-uri 'self'; frame-ancestors 'none'"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    return resp


# --------------------------------------------------------------------------
# dashboard page
# --------------------------------------------------------------------------
_DASHBOARD_HTML = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dashboard.html")


@app.get("/", response_class=HTMLResponse)
def dashboard():
    # no-cache: the UI ships in this single file — phones must revalidate so
    # deploys actually reach mobile browsers instead of serving stale HTML
    headers = {"Cache-Control": "no-cache"}
    if os.path.exists(_DASHBOARD_HTML):
        return HTMLResponse(open(_DASHBOARD_HTML).read(), headers=headers)
    return HTMLResponse("<h1>CTI Dashboard</h1><p>dashboard.html missing</p>",
                        status_code=500, headers=headers)


if __name__ == "__main__":
    import uvicorn
    host = os.environ.get("CTI_HOST", "127.0.0.1")
    if host in ("0.0.0.0", "::"):
        raise SystemExit("Refusing to bind 0.0.0.0 — set CTI_HOST to a specific tailnet/LAN IP")
    port = int(os.environ.get("CTI_PORT", "8084"))
    uvicorn.run(app, host=host, port=port, log_level="warning", server_header=False)
