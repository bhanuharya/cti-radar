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

Security (secure-dev gates):
  - binds tailnet-only by default (HOST=100.76.85.44) — never 0.0.0.0/LAN
  - security headers on every response (CSP, nosniff, frame deny, referrer)
  - GETs are read-only; only POSTs that mutate are token-gated
  - slug validated against ^[a-z0-9-]{1,32}$ before ANY filesystem use
  - token read from env (CTI_SCAN_TOKEN) only — never stored in code
  - all request bodies are Pydantic-validated; no eval/exec
"""
import html as _html
import json, os, re, subprocess, sys, tempfile, threading, time
# ensure this file's dir is importable regardless of launch cwd
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import cti_correlation as cc
import scanner
import ai_providers
from fastapi.middleware.gzip import GZipMiddleware

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_ROOT = os.path.abspath(os.path.expanduser(
    os.environ.get("CTI_DATA_DIR", os.path.join(BASE, "data"))))
DATA_ORG_DIR = os.path.join(DATA_ROOT, "orgs")
ORGS_JSON = os.path.join(DATA_ROOT, "orgs.json")

_SLUG_RE = re.compile(r"^[a-z0-9-]{1,32}$")
_DEFAULT_ORG = "sample"

_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
_CHROMIUM = "/home/bhanuharya/.cache/ms-playwright/chromium-1208/chrome-linux64/chrome"

app = FastAPI(title="CTI Radar", docs_url=None, redoc_url=None)

# serve vendored static assets (vis-network) from app/static/
_STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
if os.path.isdir(_STATIC_DIR):
    app.mount("/static", StaticFiles(directory=_STATIC_DIR), name="static")

# thresholded gzip for sufficiently large responses — stdlib only, no extra dep
app.add_middleware(GZipMiddleware, minimum_size=1024)

# bounded executor + per-org job deduplication (P0: serialize mutations)
import uuid as _uuid
from concurrent.futures import ThreadPoolExecutor as _ThreadPoolExecutor

_executor = _ThreadPoolExecutor(max_workers=4, thread_name_prefix="cti-job")
_jobs_lock = threading.Lock()
_jobs = {}  # (slug, kind) -> {id, started, kind, status, error}
_registry_lock = threading.Lock()
_JOB_TTL = 3600  # retain completed jobs for 1h


def _job_key(slug, kind):
    return f"{slug}:{kind}"


def _try_acquire_job(slug, kind):
    key = _job_key(slug, kind)
    prefix = f"{slug}:"
    with _jobs_lock:
        # per-org serialization: any running job for this org blocks new mutations
        for k, v in _jobs.items():
            if k.startswith(prefix) and v.get("status") == "running":
                return False, v["id"]
        jid = f"{slug}-{kind}-{_uuid.uuid4().hex[:8]}"
        _jobs[key] = {"id": jid, "started": time.time(), "kind": kind, "status": "running"}
        return True, jid


def _release_job(slug, kind, error=None):
    key = _job_key(slug, kind)
    with _jobs_lock:
        entry = _jobs.get(key)
        if entry:
            entry["status"] = "failed" if error else "done"
            if error:
                entry["error"] = str(error)[:500]
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
        # check if it was a completed job with matching id
        for k, v in _jobs.items():
            if v.get("id") == job_id and k.startswith(f"{slug}:"):
                return dict(v)
    return None


# --------------------------------------------------------------------------
# validation / auth helpers
# --------------------------------------------------------------------------
def _valid_slug(slug):
    return bool(slug) and bool(_SLUG_RE.match(slug))


_SESSIONS = {}   # cookie-session id -> expiry epoch (in-memory, single-user)
_SESSION_TTL = 12 * 3600   # 12h idle session
_SESSION_COOKIE = "cti_session"


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
    # (2) static API token for scripted/CI scans
    tok = os.environ.get("CTI_SCAN_TOKEN", "")
    if tok and req.headers.get("X-CTI-Token") == tok:
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
    import time as _t
    sid = _login_ok(req)
    if not sid:
        return JSONResponse({"error": "invalid username or password"},
                            status_code=401)
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
    /api/findings (filtered/sorted), and /api/orgs/{slug}/history. Avoids global
    or time-based caching — pure per-request reuse of in-memory data.
    """
    # single findings file read for fs + meta_date (avoids second open)
    fp, baseline_path = cc._org_paths(org)
    fs = []
    baseline = []
    meta_date = None
    if fp and os.path.exists(fp):
        try:
            with open(fp) as fh:
                d = json.load(fh)
            if isinstance(d, dict):
                fs = d.get("findings", []) if isinstance(d.get("findings"), list) else []
                meta = d.get("meta") if isinstance(d.get("meta"), dict) else None
                if isinstance(meta, dict):
                    m = re.search(r"20\d\d-\d\d-\d\d", str(meta.get("date") or meta.get("scan_date") or ""))
                    if m:
                        meta_date = m.group(0)
        except Exception:
            fs = []
    if baseline_path and os.path.exists(baseline_path):
        try:
            with open(baseline_path) as fh:
                baseline = [l.strip() for l in fh if l.strip() and not l.startswith("#")]
        except Exception:
            baseline = []
    domains = (cc.REGISTRY.get(org) or {}).get("domains") or []

    # findings: normalize once, then filter/sort (same semantics as /api/findings)
    nf = [cc.normalize_finding(f, org, meta_date=meta_date) for f in fs]
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
            "summary": cc.summary(slug)}


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
        tmp = ORGS_JSON + ".tmp"
        with open(tmp, "w") as f:
            json.dump(registry, f, indent=2)
            f.write("\n")
        os.replace(tmp, ORGS_JSON)
    cc._reload_registry()

    # filesystem creation after successful registry commit (with cleanup on failure)
    try:
        org_dir = os.path.join(DATA_ORG_DIR, slug)
        os.makedirs(org_dir, exist_ok=True)
        # use atomic writes for org files as well
        base_tmp = os.path.join(org_dir, "baseline.txt.tmp")
        with open(base_tmp, "w") as f:
            f.write("")
        os.replace(base_tmp, os.path.join(org_dir, "baseline.txt"))
        find_tmp = os.path.join(org_dir, "findings.json.tmp")
        with open(find_tmp, "w") as f:
            json.dump({"findings": []}, f, indent=2)
            f.write("\n")
        os.replace(find_tmp, os.path.join(org_dir, "findings.json"))
    except Exception:
        # cleanup partial registry on failure? keep registry but org will be empty
        pass
    if ai_profile:
        ai_providers.set_org_profile(slug, ai_profile)

    return {"slug": slug, "name": name, "domains": domains, "ai_profile": ai_profile or None}


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
        return JSONResponse({"error": "scan already running", "slug": slug, "job_id": jid}, status_code=409)
    org = dict(org, slug=slug)

    def _scan_wrap():
        try:
            scanner.generate_org(org, mode=mode, ai_profile=effective_profile or ai_profile_req)
            _release_job(slug, "scan")
        except Exception as e:
            _release_job(slug, "scan", error=e)

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
        return JSONResponse({"error": "recheck already running", "slug": slug, "job_id": jid}, status_code=409)

    def _run():
        try:
            changed = scanner.recheck_findings(slug)
            scanner.append_history(slug, {"kind": "recheck", "mode": "fast",
                                           "summary": {"changed": changed, "finding": "probe own ip/port"},
                                           "note": "light remediation recheck"})
            _release_job(slug, "recheck")
            return changed
        except Exception as e:
            _release_job(slug, "recheck", error=e)
            return 0

    _executor.submit(_run)
    return {"queued": True, "slug": slug, "job_id": jid}


@app.get("/api/orgs/{slug}/recheck/{job_id}")
def api_recheck_status(slug: str, job_id: str, req: Request = None):
    err, _ = _require_org(slug, req)
    if err:
        return err
    running = _is_job_running(slug, "recheck")
    status = "running" if running else "done"
    job = _get_job(slug, "recheck", job_id)
    if job and job.get("error"):
        status = "failed"
    return {"status": status, "job_id": job_id}


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
        return JSONResponse({"error": "correlate already running", "slug": slug, "job_id": jid}, status_code=409)
    org = dict(org, slug=slug)

    def _corr_wrap():
        try:
            scanner.correlate_org(org)
            _release_job(slug, "correlate")
        except Exception as e:
            _release_job(slug, "correlate", error=e)

    _executor.submit(_corr_wrap)
    return {"queued": True, "job_id": jid}


@app.get("/api/orgs/{slug}/correlate/{job_id}")
def api_correlate_status(slug: str, job_id: str, req: Request = None):
    err, _ = _require_org(slug, req)
    if err:
        return err
    running = _is_job_running(slug, "correlate") or scanner.is_correlating(slug)
    status = "running" if running else "done"
    job = _get_job(slug, "correlate", job_id)
    if job and job.get("error"):
        status = "failed"
    report = cc.correlation_report(slug) or {}
    return {"status": status, "correlated": report.get("added", 0),
            "report": report, "job_id": job_id}


@app.get("/api/orgs/{slug}/scan/{job_id}")
def api_scan_status(slug: str, job_id: str, req: Request = None):
    err, _ = _require_org(slug, req)
    if err:
        return err
    running = _is_job_running(slug, "scan")
    status = "running" if running else "done"
    job = _get_job(slug, "scan", job_id)
    if job and job.get("error"):
        status = "failed"
    return {"status": status, "job_id": job_id}


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
    fs = nfs
    sev = {}
    for f in fs:
        s = str(f.get("severity", "INFO")).upper()
        sev[s] = sev.get(s, 0) + 1
    sev_rows = "".join(
        f"<tr><td>{_esc(k)}</td><td>{_esc(v)}</td></tr>"
        for k, v in sorted(sev.items(), key=lambda kv: _SEV_ORDER.get(kv[0], 99)))

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
    if os.path.exists(_DASHBOARD_HTML):
        return HTMLResponse(open(_DASHBOARD_HTML).read())
    return HTMLResponse("<h1>CTI Dashboard</h1><p>dashboard.html missing</p>", status_code=500)


if __name__ == "__main__":
    import uvicorn
    host = os.environ.get("CTI_HOST", "100.76.85.44")
    if host in ("0.0.0.0", "::"):
        raise SystemExit("Refusing to bind 0.0.0.0 — set CTI_HOST to a specific tailnet/LAN IP")
    port = int(os.environ.get("CTI_PORT", "8084"))
    uvicorn.run(app, host=host, port=port, log_level="warning")
