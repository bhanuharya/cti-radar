"""openhack_source.py — OpenHack CLI ingestion source (Slice 2.5).

Runs the locally-installed `openhack` agentic CLI against an org's REGISTERED
domains (external, network-facing assessment) and maps its verified findings
into the standard findings.json lifecycle.

Trust model (OpenHack pipeline: recon -> hunt -> validate -> verify):
  - validated findings  -> status_detail "OHACK-VERIFIED"   (CONFIRMED-class
    evidence; full severity from cvssScore)
  - unvalidated         -> "OHACK-CANDIDATE" (CORRELATED-class); severity is
    CAPPED AT HIGH — only exploit-verified results may claim CRITICAL.

Identity: ohack|<host>|<normalized-url-path>|<category-lower> — computed from
repo-relative URL parts so it is stable across runs and relocatable paths.
Lifecycle: this module owns observation for the ohack family only (surface
scans never touch its streaks — see scanner._reconcile_findings).

Safety: opt-in per org (openhack_enabled in the registry entry), token-gated,
never scheduled by cron defaults. OpenHack verification performs ACTIVE
testing — the operator is responsible for authorization of every target.
"""

import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
import ipaddress
from urllib.parse import urlsplit

import cti_correlation as cc
import ai_providers

_REPORT_MAX_BYTES = 50 * 1024 * 1024


def _slugify(s):
    s = re.sub(r"[^a-z0-9]+", "-", str(s).lower()).strip("-")
    return s[:24] or "org"
_SNIPPET_MAX = 2048
_POC_MAX = 400
_DEFAULT_TIMEOUT = 1800
_MAX_TIMEOUT = 7200


def _env_float(name, default, lo=None, hi=None):
    try:
        v = float(os.environ.get(name, "") or default)
    except (TypeError, ValueError):
        v = float(default)
    if lo is not None:
        v = max(lo, v)
    if hi is not None:
        v = min(hi, v)
    return v


def openhack_bin():
    """Explicit absolute assessment executable; never use PATH fallback."""
    p = os.environ.get("CTI_OPENHACK_BIN", "").strip()
    if not p or not os.path.isabs(p) or not os.path.isfile(p) or not os.access(p, os.X_OK):
        return None
    return p


def _venv_python(binp=None):
    """Interpreter behind the console script (from its shebang)."""
    binp = binp or openhack_bin()
    try:
        with open(binp, "rb") as f:
            first = f.readline().decode("utf-8", "replace").strip()
        if first.startswith("#!") and "python" in first:
            return first[2:].strip()
    except Exception:
        pass
    return sys.executable


_MODELS_CACHE = {"at": 0.0, "data": None}


def list_models(force=False):
    """Live model catalog from the OpenHack inference service.

    Returns {"models": [{"id","label"}], "default": <configured model>}.
    Cached 10 minutes; on any failure falls back to the configured default
    as a single entry so the UI dropdown always works."""
    import cti_correlation as _cc
    now = time.time()
    if not force and _MODELS_CACHE["data"] and now - _MODELS_CACHE["at"] < 600:
        return _MODELS_CACHE["data"]
    models = []
    default = ""
    py = _venv_python()
    snippet = (
        "import json\n"
        "from openhack.agents.llm import fetch_available_model_catalog\n"
        "from openhack.config import load_user_config\n"
        "cfg = load_user_config()\n"
        "base = cfg.get('openhack_base_url') or None\n"
        "try:\n"
        "    from openhack.config import PROD_BASE_URL\n"
        "    base = base or PROD_BASE_URL\n"
        "except Exception:\n"
        "    pass\n"
        "ms = fetch_available_model_catalog(api_key=cfg.get('openhack_api_key'),\n"
        "                                   base_url=base) or []\n"
        "print(json.dumps({'models': ms, 'default': cfg.get('model') or ''}))\n")
    try:
        r = subprocess.run([py, "-c", snippet], capture_output=True, text=True,
                           timeout=20,
                           env={**os.environ, "HOME": os.path.expanduser("~")})
        if r.returncode == 0 and r.stdout.strip():
            d = json.loads(r.stdout.strip().splitlines()[-1])
            default = str(d.get("default") or "")
            for m in (d.get("models") or [])[:60]:
                if isinstance(m, dict) and m.get("id"):
                    models.append({"id": str(m["id"])[:64],
                                   "label": str(m.get("label") or m["id"])[:80]})
    except Exception:
        models = []
    if not models and default:
        models = [{"id": default, "label": default + " (configured default)"}]
    if OHACK_PREFERRED_MODEL and not any(m["id"] == OHACK_PREFERRED_MODEL
                                         for m in models):
        models.insert(0, {"id": OHACK_PREFERRED_MODEL,
                          "label": OHACK_PREFERRED_MODEL +
                                   " — unreleased GLM (recommended)"})
    models.sort(key=lambda m: 0 if m["id"] == OHACK_PREFERRED_MODEL else 1)
    data = {"models": models, "default": default,
            "preferred": OHACK_PREFERRED_MODEL}
    if models:
        _MODELS_CACHE.update(at=now, data=data)
    return data


# shim: run_task accepts a per-run model override the --hack CLI flag lacks
_RUN_SHIM = (
    "import sys\n"
    "from openhack.interactive_runner import run_task\n"
    "task, target = sys.argv[1], sys.argv[2]\n"
    "model = sys.argv[3] if len(sys.argv) > 3 and sys.argv[3] else None\n"
    "run_task(task, target_dir=target, model=model)\n")


def _spawn_argv(objective, scratch_dir, model=None):
    """Argv for the assessment run. With a model override we call run_task
    through the venv interpreter (the --hack flag cannot select a model);
    otherwise the plain console-script path is used."""
    if not model:
        return [openhack_bin(), "--hack", objective, scratch_dir]
    return [_venv_python(), "-c", _RUN_SHIM, objective, scratch_dir, str(model)]


# Preferred model when neither the request nor the org pins one. The hosted
# catalog's nominal default may be a model the account cannot run; ox-alpha
# is the proven-working unreleased GLM channel.
OHACK_PREFERRED_MODEL = os.environ.get("CTI_OHACK_MODEL", "ox-alpha")


def quick_budget():
    """Quick-pass wall-clock budget in seconds (default 480s, 300-1200)."""
    return int(_env_float("CTI_OHACK_QUICK_BUDGET", 480, lo=300, hi=1200))


_SEV_STEPS = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _sanitize_line(v, cap=120):
    """Single-line safe text for the agent objective (no newline/format games)."""
    s = str(v or "").replace("\r", " ").replace("\n", " ").replace("|", "/")
    s = re.sub(r"\s+", " ", s).strip()
    return s[:cap]


def build_manifest(slug, max_items=40):
    """Compact ref-keyed manifest of OPEN deterministic findings for quick-pass.

    Lines: `ref=<id> | host:port | sev=X | <fingerprint/banner summary>`.
    Severity-ordered, ohack/positive records excluded. Sanitized single-line.
    """
    import cti_correlation as _cc
    try:
        fs, _ = _cc.load_data(slug)
    except Exception:
        return []
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    rows = []
    for f in (fs or []):
        if not isinstance(f, dict) or not f.get("id"):
            continue
        if str(f.get("source", "")).startswith(("openhack", "ai-assess",
                                                "cve-share", "ip-co-residency",
                                                "internetdb")):
            continue
        if _cc.canonical_status(f) != "OPEN" or f.get("positive"):
            continue
        ev = f.get("evidence") if isinstance(f.get("evidence"), dict) else {}
        hint = " ".join(str(ev.get(k)) for k in ("server", "title") if ev.get(k))
        port = f.get("port")
        try:
            port = int(port)
        except (TypeError, ValueError):
            port = ""
        rows.append((order.get(str(f.get("severity", "")).upper(), 9), [
            f"ref={f['id']}",
            f"{_sanitize_line(f.get('target'), 100)}{':' + str(port) if port else ''}",
            f"sev={str(f.get('severity','')).upper()}",
            _sanitize_line(hint, 90),
        ]))
    rows.sort(key=lambda r: r[0])
    return [" | ".join(r[1]) for r in rows[:max_items]]


def build_quick_objective(domains, manifest_lines):
    doms = ", ".join(_sanitize_line(d, 100) for d in domains)
    lines = "\n".join(manifest_lines or [])
    return (
        "Authorized security assessment. In scope: the following domains AND "
        "any subdomains you discover that belong to them: " + doms + ". "
        "Do NOT touch hosts outside that scope. Budget: about 8 minutes — "
        "prioritize breadth over perfection.\n\n"
        "TASK\n"
        "1. For each listed finding below: verify it on its own target/port "
        "(probe the service, read banners/versions), decide a severity with "
        "brief CVSS-style reasoning, and collect any extra evidence you find "
        "(paths, tech versions, vuln details).\n"
        "2. Beyond the list, deep-enumerate in-scope hosts and vuln-scan what "
        "you find; report genuinely notable issues only.\n"
        "3. Record EVERY issue as a finding. When it corresponds to a listed "
        "item, add a field \"ref\" containing that item's exact ref id and "
        "set filePath to the probed URL. New issues omit \"ref\".\n\n"
        "FINDINGS TO VERIFY\n" + (lines if lines else "(none yet)")
    )


def _scans_dir():
    d = os.environ.get("CTI_OPENHACK_SCANS_DIR", "").strip()
    if d:
        return d
    return os.path.join(os.path.expanduser("~"), ".openhack", "scans")


def severity_from_finding(f, allow_critical_unverified=False):
    """Canonical severity: cvssScore bands first, reported string fallback.
    Unvalidated candidates are capped at HIGH — EXCEPT ref-tagged quick-pass
    results, whose raw proposal is kept for the ±1 grader clamp."""
    sev = None
    try:
        cvss = f.get("cvssScore")
        if cvss is not None:
            cvss = float(cvss)
            if cvss >= 9.0:
                sev = "CRITICAL"
            elif cvss >= 7.0:
                sev = "HIGH"
            elif cvss >= 4.0:
                sev = "MEDIUM"
            elif cvss > 0:
                sev = "LOW"
    except (TypeError, ValueError):
        sev = None
    if not sev:
        sev = ai_providers._normalize_severity(f.get("severity")) or "MEDIUM"
    validated = bool(f.get("validated"))
    if not validated and sev == "CRITICAL" and not allow_critical_unverified:
        sev = "HIGH"      # only exploit-verified findings may claim CRITICAL
    return sev


def _url_parts(raw):
    """(host, normalized_path) from a filePath that may be a URL or a path."""
    s = str(raw or "").strip()
    m = re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://([^/?#]+)([^#]*)", s)
    if m:
        try:
            host = (urlsplit(s).hostname or "").lower()
        except ValueError:
            host = ""
        path = (m.group(2) or "/").split("?")[0].rstrip("/").lower() or "/"
        return host, path
    # non-URL (file path): normalize separators, keep as-is lowercased
    norm = s.replace("\\", "/").strip().lower()
    if norm.startswith("./"):
        norm = norm[2:]
    return "", norm[:200]


def map_report_findings(slug, report, registered_domains=None):
    """Map findings, accepting only in-scope absolute HTTP(S) URLs."""
    scopes = {str(d).strip().lower().rstrip('.') for d in (registered_domains or [])}
    def in_scope(raw):
        try:
            u = urlsplit(str(raw).strip())
            host = (u.hostname or '').lower().rstrip('.')
            if u.scheme.lower() not in ('http', 'https') or not host or u.username or u.password:
                return False
            try:
                ipaddress.ip_address(host)
                return False
            except ValueError:
                pass
            return any(host == d or host.endswith('.' + d) for d in scopes)
        except ValueError:
            return False

    slug = str(slug)
    ts = time.strftime("%Y%m%d%H%M%S")
    today = time.strftime("%Y-%m-%d")
    out = []
    seq = 0
    for f in (report or {}).get("findings") or []:
        if not isinstance(f, dict) or not str(f.get("title", "")).strip():
            continue
        if not in_scope(f.get("filePath")):
            continue
        seq += 1
        validated = bool(f.get("validated"))
        raw_ref = str(f.get("ref", "") or "").strip()
        ref_ok = bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.\-]{0,63}", raw_ref))
        sev = severity_from_finding(f, allow_critical_unverified=ref_ok)
        host, path = _url_parts(f.get("filePath"))
        target = host or (str(f.get("filePath"))[:120] or "unknown-target")
        category = ("OpenHack · " + str(f.get("category", "")).strip())[:80]
        desc = str(f.get("title", "")).strip()
        long_desc = str(f.get("description", "")).strip()
        evidence = {
            "url": str(f.get("filePath", ""))[:500],
            "line": f.get("lineNumber"),
            "vulnerability_type": str(f.get("vulnerabilityType", ""))[:120],
            "cvss_score": f.get("cvssScore"),
            "confidence": str(f.get("confidence", ""))[:40],
            "validated": validated,
        }
        if f.get("verificationSource"):
            evidence["verification_source"] = str(f["verificationSource"])[:80]
        snippet = f.get("relevantCode")
        if snippet:
            evidence["relevant_code"] = str(snippet)[:_SNIPPET_MAX]
        rec = f.get("recommendation") or f.get("fix")
        poc = f.get("poc")
        proof = ["openhack --hack (domain-scoped assessment)",
                 "%s:%s" % (f.get("filePath"), f.get("lineNumber") or "-")]
        if poc:
            proof.append("poc: " + str(poc)[:_POC_MAX])
        rec = {
            "id": "OH-%s-%s-%02d" % (_slugify(slug), ts, seq),
            "title": str(f.get("title", ""))[:150],
            "target": target,
            "ip": None,
            "port": "",
            "severity": sev,
            "category": category,
            "status": "OPEN",
            "status_detail": "OHACK-VERIFIED" if validated else "OHACK-CANDIDATE",
            "positive": False,
            "mode": "fast",
            "source": "openhack",
            "description": ("%s %s" % (desc, long_desc))[:2000],
            "impact": ("Exploit-verified by OpenHack sandbox/browser verification."
                       if validated else
                       "OpenHack candidate finding (validation stage did not confirm)."),
            "evidence": evidence,
            "proof_chain": proof,
            "remediation": [str(rec)[:1000]] if rec else
                           ["Review finding and apply vendor guidance."],
            "related_cves": [],
            "found_date": today,
            "first_seen": today,
            "last_seen": today,
            "status_history": [{"at": today, "from": "", "to": "OPEN", "by": "openhack",
                                "note": "ingested from openhack report"}],
            "provenance": {"derived_from": ["openhack"],
                           "confidence": "verified" if validated else "candidate",
                           "evidence_timestamp": time.strftime(
                               "%Y-%m-%dT%H:%M:%SZ", time.gmtime())},
        }
        # identity per design: ohack|host|<path-or-empty>|category
        cat_core = str(f.get("category", "")).strip().lower()[:80]
        rec["identity_key"] = f"ohack|{target.lower()}|{(path if host else '')}|{cat_core}"
        # quick-pass: model may reference one of OUR finding ids for grading
        if ref_ok:
            rec["ref"] = raw_ref
        out.append(rec)
    return out


def _newest_report(since_ts, scratch_real):
    """Newest session report written after since_ts whose target_dir matches."""
    best = None
    best_mtime = -1
    sd = _scans_dir()
    if not os.path.isdir(sd):
        return None
    for name in os.listdir(sd):
        if not name.endswith(".json") or name.endswith(".events.jsonl"):
            continue
        p = os.path.join(sd, name)
        try:
            mt = os.stat(p).st_mtime
            if mt < since_ts - 2 or mt <= best_mtime:
                continue
            if os.path.getsize(p) > _REPORT_MAX_BYTES:
                continue
            with open(p) as fh:
                d = json.load(fh)
            if str(d.get("target_dir", "")) != scratch_real:
                continue
            best, best_mtime = d, mt
        except Exception:
            continue
    return best


def _log_tail(path, n=600):
    try:
        with open(path, "rb") as f:
            blob = f.read()[-n:]
        return blob.decode("utf-8", "replace").strip()
    except Exception:
        return ""


def _terminate_process_group(proc, graceful=True, grace=None):
    """Terminate a spawned assessment's whole process group.

    A shell/wrapper may exit on SIGINT while descendants keep running.  Probe
    the group itself for the full grace period and send SIGKILL if any member
    remains, regardless of the group leader's state.
    """
    pgid = proc.pid
    if grace is None:
        grace = _env_float("CTI_OPENHACK_KILL_GRACE", 5, lo=0.1, hi=30)
    if graceful:
        try:
            os.killpg(pgid, signal.SIGINT)
        except (ProcessLookupError, PermissionError):
            pass
        deadline = time.monotonic() + grace
        while time.monotonic() < deadline:
            try:
                os.killpg(pgid, 0)
            except ProcessLookupError:
                break
            except PermissionError:
                break
            time.sleep(0.05)
    try:
        os.killpg(pgid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)


def run_assessment(domains, scratch_dir, timeout=None, budget_s=None,
                   objective=None, model=None):
    """Spawn `openhack --hack "<objective>" <scratch_dir>` and return the
    parsed session report.

    Two modes:
      budget_s (quick-pass): Popen + graceful SIGINT at the deadline — the
        CLI persists a "cancelled" report with the findings gathered so far,
        so a partial run is still ingested. 30s grace, then hard kill.
      timeout (deep): blocking run to completion (legacy behavior).

    Child stdout/stderr stream to <scratch_dir>/last-run.log; failures raise
    RuntimeError with the log tail so CLI-side errors are never invisible.
    Raises RuntimeError on missing binary / timeout / no matching report."""
    binp = openhack_bin()
    if not binp:
        raise RuntimeError("openhack binary not found (set CTI_OPENHACK_BIN)")
    doms = [str(d).strip().lower() for d in (domains or []) if str(d).strip()]
    if not doms:
        raise RuntimeError("no domains configured for this org")
    os.makedirs(scratch_dir, mode=0o700, exist_ok=True)
    if objective is None:
        objective = (
            "Authorized external security assessment. Targets (ONLY these hosts, "
            "do not test anything else): " + ", ".join(doms) + ". "
            "Perform recon, hunt, validate, and verify findings against these "
            "targets. Record every confirmed issue as a finding with the target "
            "URL in the file path field.")
    t0 = time.time()
    log_path = os.path.join(scratch_dir, "last-run.log")
    rc = None
    with open(log_path, "ab") as logf:
        logf.write(("\n==== %s | bin=%s | argv-mode=%s ====\n"
                    % (time.strftime("%Y-%m-%dT%H:%M:%S"), binp,
                       "budget" if budget_s else "deep")).encode())
        logf.flush()
        report = None
        if budget_s:
            budget_s = int(budget_s)
            proc = subprocess.Popen(
                _spawn_argv(objective, scratch_dir, model),
                stdout=logf, stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                start_new_session=True,
            )
            try:
                proc.wait(timeout=budget_s)
            except subprocess.TimeoutExpired:
                # SIGINT lets the CLI persist a partial report; after a bounded
                # grace period the entire group is killed, including descendants.
                _terminate_process_group(proc, graceful=True)
            deadline = time.time() + 20
            while time.time() < deadline:
                report = _newest_report(t0, os.path.realpath(scratch_dir))
                if report is not None:
                    break
                time.sleep(0.5)
        else:
            timeout = int(_env_float("CTI_OHACK_TIMEOUT", _DEFAULT_TIMEOUT,
                                     lo=60, hi=_MAX_TIMEOUT))
            proc = subprocess.Popen(
                _spawn_argv(objective, scratch_dir, model),
                stdout=logf, stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL, start_new_session=True,
            )
            try:
                rc = proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                _terminate_process_group(proc, graceful=False, grace=0)
                raise RuntimeError(f"openhack exceeded {timeout}s runtime budget")
        if report is None:
            report = _newest_report(t0, os.path.realpath(scratch_dir))
    if report is None:
        tail = _log_tail(log_path, n=2000)
        low = tail.lower()
        if "insufficient openhack credits" in low or "purchase more" in low:
            raise RuntimeError("OpenHack account out of credits — top up at "
                               "https://app.openhack.com/settings/billing")
        if "permission_denied_message" in low or "not logged in" in low \
                or "unauthorized" in low:
            raise RuntimeError("OpenHack auth rejected — run `openhack --login` "
                               "on this host")
        detail = f" (exit code {rc})" if rc is not None else ""
        hint = f"; last-run.log tail: {tail}" if tail else \
               "; child produced no output — check auth with `openhack --sessions`"
        raise RuntimeError(f"no openhack session report matched this run{detail}"
                           f"{hint}")
    return report


def _grade_and_enrich(f, m, today, run_id):
    """Quick-pass grading of an EXISTING finding referenced via `ref`.

    Severity authority: verified results set severity directly (exploit-
    backed); unverified proposals clamp to +/-1 step of the stored
    ohack_grading.severity_baseline (anchored on first grade, never
    ratcheting — mirrors the Stage-B AI pattern). Evidence from the run is
    merged under evidence.openhack; last_seen/missing_streak refresh.
    Returns (graded=1, clamped 0/1)."""
    clamped = 0
    verified = bool((m.get("evidence") or {}).get("validated"))
    prev = f.get("ohack_grading") if isinstance(f.get("ohack_grading"), dict) else {}
    baseline = prev.get("severity_baseline")
    if baseline not in _SEV_STEPS:
        b0 = str(f.get("severity", "INFO")).upper()
        baseline = b0 if b0 in _SEV_STEPS else "MEDIUM"
    proposed = m.get("severity") if m.get("severity") in _SEV_STEPS else "MEDIUM"
    final = proposed
    if not verified:
        b, p = _SEV_STEPS[baseline], _SEV_STEPS[proposed]
        if abs(p - b) > 1:
            step = 1 if p > b else -1
            final = next(k for k, v in _SEV_STEPS.items() if v == b + step)
            clamped = 1
    f["severity"] = final
    f["ohack_grading"] = {"severity_baseline": baseline, "severity": final,
                          "verified": verified, "at": cc._now_iso(),
                          "run": run_id}
    # evidence enrichment under a namespaced key (analyst/AI keys preserved)
    ev = f.get("evidence") if isinstance(f.get("evidence"), dict) else {}
    oh_ev = {k: v for k, v in (m.get("evidence") or {}).items()
             if k in ("url", "line", "relevant_code", "vulnerability_type",
                      "cvss_score", "confidence")}
    poc_lines = [str(p) for p in (m.get("proof_chain") or [])
                 if str(p).startswith("poc:")]
    if poc_lines:
        oh_ev["poc"] = poc_lines[-1].split(":", 1)[1].strip()[:400]
    if oh_ev:
        cur_oh = ev.get("openhack") if isinstance(ev.get("openhack"), dict) else {}
        cur_oh.update(oh_ev)
        ev["openhack"] = cur_oh
        f["evidence"] = ev
    f["last_seen"] = today
    f["missing_streak"] = 0
    kind = ("verified" if verified else
            ("clamped from %s" % proposed if clamped else "within ±1 of %s" % baseline))
    sh = f.get("status_history") if isinstance(f.get("status_history"), list) else []
    st = str(f.get("status", ""))
    sh.append({"at": time.strftime("%Y-%m-%dT%H:%M:%S"), "from": st, "to": st,
               "by": "openhack",
               "note": "quick-pass grade: %s (%s)" % (final, kind)})
    f["status_history"] = sh[-50:]
    return 1, clamped


def ingest_report(slug, report, mode="deep"):
    """Merge mapped findings into the org's findings.json with ohack-family
    lifecycle bookkeeping (observed refresh / streak / tiered resolve /
    recurrence reopen). Quick-pass mode additionally grades existing findings
    referenced via `ref` and merges their enriched evidence.
    Returns a summary dict."""
    slug = str(slug)
    # scope is supplied by the registry, not by untrusted report output
    org = cc.org_get(slug) or {}
    mapped = map_report_findings(slug, report, org.get("domains") or [])
    now_ids = {}
    for m in mapped:
        now_ids[m["identity_key"]] = True
    fp = cc.org_findings_path(slug)
    added = updated = resolved = reopened = proposed = missed = 0
    graded = clamped = 0
    run_id = time.strftime("%Y%m%dT%H%M%S")
    resolve_after = max(1, scanner_resolve_after())
    today = time.strftime("%Y-%m-%d")
    with cc._org_lock(slug):
        data = {"findings": []}
        if fp and os.path.exists(fp):
            try:
                with open(fp) as fh:
                    d = json.load(fh)
                if isinstance(d, dict):
                    data = d
                else:
                    return {"error": "corrupted findings.json"}
            except Exception:
                return {"error": "corrupted findings.json"}
        fs = data.get("findings") or []
        index = {}
        by_id = {}
        for i, f in enumerate(fs):
            if isinstance(f, dict):
                index[cc.ensure_identity(f)] = i
                fid = str(f.get("id", ""))
                if fid:
                    by_id[fid] = i
        # merge observed
        for m in mapped:
            ref = m.pop("ref", None)
            tgt_i = by_id.get(ref) if (mode == "quick" and ref) else None
            if tgt_i is not None:
                g, c = _grade_and_enrich(fs[tgt_i], m, today, run_id)
                graded += g
                clamped += c
                continue
            ik = m["identity_key"]
            i = index.get(ik)
            if i is None:
                fs.append(m)
                index[ik] = len(fs) - 1
                added += 1
                continue
            cur = fs[i]
            updated += 1
            cur["last_seen"] = today
            cur["missing_streak"] = 0
            try:
                blob = json.dumps(m["evidence"], sort_keys=True, default=str)
                cur["evidence_hash"] = hashlib.sha256(
                    blob.encode("utf-8", "replace")).hexdigest()[:16]
            except Exception:
                pass
            cur["evidence"] = m["evidence"]
            cur["proof_chain"] = m["proof_chain"]
            cur["severity"] = m["severity"]
            cur["status_detail"] = m["status_detail"]
            if str(cur.get("status", "")).upper() == "RESOLVED":
                cur["status"] = "OPEN"
                sh = cur.get("status_history") if isinstance(cur.get("status_history"), list) else []
                sh.append({"at": today, "from": "RESOLVED", "to": "OPEN",
                           "by": "openhack", "note": "recurrence: still present in latest report"})
                cur["status_history"] = sh[-50:]
                reopened += 1
        # Only a complete deep assessment establishes family-wide absence.
        seen_targets_now = set(now_ids.keys())
        if mode != "deep" or not isinstance(report, dict) or report.get("complete") is False:
            seen_targets_now = None
        for f in fs:
            if not isinstance(f, dict):
                continue
            ik = cc.ensure_identity(f)
            if not ik.startswith("ohack|"):
                continue
            if seen_targets_now is None or ik in seen_targets_now:
                continue
            missed += 1
            streak = int(f.get("missing_streak") or 0) + 1
            f["missing_streak"] = streak
            status = str(f.get("status", "")).upper()
            if status != "OPEN" or f.get("positive"):
                continue
            sev = str(f.get("severity", "")).upper()
            sh = f.get("status_history") if isinstance(f.get("status_history"), list) else []
            if streak >= resolve_after:
                if sev in ("HIGH", "CRITICAL"):
                    sh.append({"at": today, "from": "OPEN", "to": "OPEN",
                               "by": "openhack",
                               "note": f"absent from {streak} consecutive reports — propose RESOLVED, analyst confirm"})
                    f["status_history"] = sh[-50:]
                    proposed += 1
                else:
                    f["status"] = "RESOLVED"
                    sh.append({"at": today, "from": "OPEN", "to": "RESOLVED",
                               "by": "openhack",
                               "note": f"auto-resolved: absent from {streak} consecutive reports"})
                    f["status_history"] = sh[-50:]
                    resolved += 1
        data["findings"] = fs
        meta = data.get("meta") if isinstance(data.get("meta"), dict) else {}
        meta["openhack_last_ingest"] = {
            "date": today, "mode": mode, "added": added, "updated": updated,
            "graded": graded, "clamped": clamped,
            "resolved": resolved, "reopened": reopened, "proposed": proposed,
            "missed": missed,
        }
        data["meta"] = meta
        cc._atomic_write_json(fp, data)
        cc.invalidate_org_cache(slug)
    return {"added": added, "updated": updated, "resolved": resolved,
            "reopened": reopened, "proposed": proposed, "missed": missed,
            "graded": graded, "clamped": clamped}


def scanner_resolve_after():
    # late import avoids a circular import at module load (scanner imports cc)
    import scanner
    return getattr(scanner, "RESOLVE_AFTER_MISSES", 3)


def run_and_ingest(slug, domains, on_progress=None, mode="deep", model=None):
    """Job entry point: run the assessment then ingest. NEVER raises.
    mode="quick" runs a budgeted (SIGINT-stopped) pass over a ref-keyed
    manifest of OPEN findings and grades/enriches matches; mode="deep" is
    the legacy full run. Returns {"status": "done"/"failed", ...}."""
    def emit(stage, msg):
        if on_progress:
            try:
                on_progress(stage, msg)
            except Exception:
                pass
    try:
        if mode == "quick":
            manifest = build_manifest(slug)
            emit("run", f"launching openhack quick-pass ({len(manifest)} finding(s) "
                        f"to verify, budget {quick_budget()}s)")
            report = run_assessment(
                domains, _scratch_dir(slug), budget_s=quick_budget(),
                objective=build_quick_objective(domains, manifest), model=model)
        else:
            emit("run", f"launching openhack deep assessment ({len(domains)} domain(s))")
            report = run_assessment(domains, _scratch_dir(slug), model=model)
        emit("ingest", "parsing + merging openhack report")
        summary = ingest_report(slug, report, mode=mode)
        if summary.get("error"):
            emit("error", f"ingest failed: {summary['error']}")
            return {"status": "failed", "error": summary["error"]}
        extra = ""
        if mode == "quick":
            extra = f", {summary.get('graded', 0)} graded" \
                    f" ({summary.get('clamped', 0)} clamped)"
        emit("done", f"openhack {mode} complete: +{summary['added']} new, "
                     f"{summary['updated']} refreshed{extra}, "
                     f"{summary['resolved']} resolved")
        return {"status": "done", **summary}
    except Exception as e:
        emit("error", f"openhack failed: {type(e).__name__}: {e}")
        return {"status": "failed", "error": f"{type(e).__name__}: {e}"}


_LOCK_GUARD = threading.Lock()


def _scratch_dir(slug):
    d = os.path.join(cc.ORG_ROOT, str(slug), "openhack")
    os.makedirs(d, mode=0o700, exist_ok=True)
    return d
