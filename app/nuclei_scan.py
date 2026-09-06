"""nuclei_scan.py — Nuclei template engine as an optional vuln-scan provider.

Nuclei is ACTIVE (real HTTP probes via community templates), so every run is
fail-closed behind the same CTI_VULN_* authorization gate as vuln_scan C3
(active assessment: CTI_VULN_ACTIVE=1, CTI_VULN_ISOLATED=1, exact
CTI_VULN_ALLOWED_DOMAINS, unexpired CTI_VULN_ROE_EXPIRES). Disabled by default.

Env contract (no presets, all validated, no free-form args — argv is built):
  CTI_NUCLEI_BIN            explicit absolute nuclei executable; else PATH lookup
  CTI_NUCLEI_TEMPLATES      templates dir (default ~/nuclei-templates)
  CTI_NUCLEI_SEVERITY       default severity filter (default critical,high,medium)
  CTI_NUCLEI_TAGS           optional tag allowlist (comma-separated)
  CTI_NUCLEI_EXCLUDE_TAGS   extra excludes (merged with defaults)
  CTI_NUCLEI_RATE_LIMIT     reqs/sec (default 20, 1-150)
  CTI_NUCLEI_TIMEOUT        per-run budget secs (default 300, 60-1200)
  CTI_NUCLEI_INTERACTSH     set to 1 to allow OAST templates (default: disabled)

Safety:
  - argv list only, never shell; child env strips *_proxy vars; -duc (no
    auto-update), -ni unless interactsh explicitly enabled, -or (no raw
    request/response stored), dos/fuzz tags force-excluded always.
  - matched URLs must be http(s), no userinfo, and strictly in-scope
    (host == or subdomain of a registered org domain). Anything else is dropped.
  - severity capped at HIGH (only exploit-verified pipelines may claim
    CRITICAL — mirrors openhack_source). status_detail NUCLEI-MATCHED.
  - output capped (10MB / 500 events); findings carry template provenance and
    validated CVE IDs only.
"""
import json
import os
import re
import shutil
import signal
import subprocess
import tempfile
import time
from urllib.parse import urlsplit

_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
_VALID_SEV = ("critical", "high", "medium", "low", "info", "unknown")
_DEFAULT_SEV = ("critical", "high", "medium")
_DEFAULT_EXCLUDE_TAGS = ("dos", "fuzz", "intrusive")
_FORCED_EXCLUDE_TAGS = ("dos", "fuzz")
_TAG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.\-]{0,63}$")
_TEMPLATE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.\-/]{0,127}$")
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")
_OUTPUT_MAX_BYTES = 10 * 1024 * 1024
_EVENTS_CAP = 500
_NAME_CAP = 150

# reported nuclei severity -> finding severity (capped at HIGH by policy)
_SEV_MAP = {"critical": "HIGH", "high": "HIGH", "medium": "MEDIUM",
            "low": "LOW", "info": "INFO", "unknown": "INFO"}


def _int_env(name, default, lo, hi):
    try:
        v = int(os.environ.get(name, "") or default)
    except (TypeError, ValueError):
        v = default
    return max(lo, min(v, hi))


def nuclei_bin():
    """Explicit absolute binary wins; else PATH lookup; else None."""
    p = (os.environ.get("CTI_NUCLEI_BIN", "") or "").strip()
    if p:
        if os.path.isabs(p) and os.path.isfile(p) and os.access(p, os.X_OK):
            return p
        return None  # explicitly set but invalid -> unavailable (fail closed)
    found = shutil.which("nuclei")
    return found or None


def templates_dir():
    d = (os.environ.get("CTI_NUCLEI_TEMPLATES", "") or "").strip()
    if d:
        d = os.path.expanduser(d)
        if os.path.isdir(d):
            return d
        return None
    cand = os.path.join(os.path.expanduser("~"), "nuclei-templates")
    return cand if os.path.isdir(cand) else None


def default_severity():
    raw = (os.environ.get("CTI_NUCLEI_SEVERITY", "") or "").strip().lower()
    if not raw:
        return list(_DEFAULT_SEV)
    out = [s for s in (x.strip() for x in raw.split(",")) if s in _VALID_SEV]
    return out or list(_DEFAULT_SEV)


def exclude_tags():
    raw = (os.environ.get("CTI_NUCLEI_EXCLUDE_TAGS", "") or "").strip().lower()
    extra = [t for t in (x.strip() for x in raw.split(",")) if _TAG_RE.match(t or "")]
    merged = list(dict.fromkeys(list(_DEFAULT_EXCLUDE_TAGS) + extra))
    for forced in _FORCED_EXCLUDE_TAGS:
        if forced not in merged:
            merged.append(forced)
    return merged


def allow_tags():
    raw = (os.environ.get("CTI_NUCLEI_TAGS", "") or "").strip().lower()
    if not raw:
        return []
    return [t for t in (x.strip() for x in raw.split(",")) if _TAG_RE.match(t or "")][:20]


def run_timeout():
    return _int_env("CTI_NUCLEI_TIMEOUT", 300, 60, 1200)


def rate_limit():
    return _int_env("CTI_NUCLEI_RATE_LIMIT", 20, 1, 150)


def interactsh_enabled():
    return (os.environ.get("CTI_NUCLEI_INTERACTSH", "") or "").strip() in ("1", "true", "yes", "on")


def engine_status():
    """Availability snapshot for the API/UI (no secrets, no probing)."""
    binp = nuclei_bin()
    tdir = templates_dir()
    reason = ""
    if not binp:
        reason = ("nuclei binary not found (set CTI_NUCLEI_BIN to an absolute "
                  "executable or install nuclei on PATH)")
    elif not tdir:
        reason = ("nuclei templates dir not found (set CTI_NUCLEI_TEMPLATES "
                  "or check out nuclei-templates)")
    return {"available": bool(binp and tdir), "reason": reason,
            "bin": bool(binp), "templates": bool(tdir),
            "severity": default_severity(), "exclude_tags": exclude_tags(),
            "timeout": run_timeout(), "rate_limit": rate_limit()}


def normalize_options(severity=None, tags=None):
    """Validate per-request severity/tags. Returns (sev_list, tag_list, error)."""
    if severity:
        sev = [str(s or "").strip().lower() for s in severity]
        sev = [s for s in sev if s in _VALID_SEV]
        if not sev:
            return None, None, "invalid nuclei severity filter"
    else:
        sev = default_severity()
    if tags:
        tg = [str(t or "").strip().lower() for t in tags]
        tg = [t for t in tg if _TAG_RE.match(t or "")]
        if len(tg) != len([str(t or "").strip() for t in tags if str(t or "").strip()]):
            return None, None, "invalid nuclei tag filter"
        tg = tg[:20]
    else:
        tg = allow_tags()
    return sev, tg, ""


def _host_in_scope(host, org_domains):
    h = (host or "").strip().lower().rstrip(".")
    if not h:
        return False
    for d in org_domains or []:
        dd = str(d or "").strip().lower().rstrip(".")
        if h == dd or h.endswith("." + dd):
            return True
    return False


def _valid_target_url(raw, org_domains):
    """Return (host, path) if raw is an in-scope http(s) URL, else (None, None)."""
    try:
        s = str(raw or "").strip()
        u = urlsplit(s)
        if u.scheme.lower() not in ("http", "https"):
            return None, None
        if u.username or u.password:
            return None, None
        host = (u.hostname or "").lower().rstrip(".")
        if not host or not _host_in_scope(host, org_domains):
            return None, None
        try:
            import ipaddress
            ipaddress.ip_address(host)
            return None, None  # templates matching raw IPs are out of scope model
        except ValueError:
            pass
        path = (u.path or "/").split("?")[0][:120] or "/"
        return host, path.lower()
    except (ValueError, AttributeError):
        return None, None


def _extract_cves(event):
    found = []
    try:
        info = event.get("info") or {}
        cls = info.get("classification") or {}
        for key in ("cve-id", "cve_id"):
            for c in (cls.get(key) or []):
                cc = str(c or "").strip().upper()
                if _CVE_RE.fullmatch(cc) and cc not in found:
                    found.append(cc)
    except Exception:
        pass
    for blob in (str(event.get("template-id", "")), str((event.get("info") or {}).get("name", ""))):
        for m in _CVE_RE.findall(blob.upper()):
            if m not in found:
                found.append(m)
    return found[:6]


def map_event(slug, event, org_domains):
    """Map one nuclei JSONL event to a finding dict, or None (dropped)."""
    if not isinstance(event, dict):
        return None
    tid = str(event.get("template-id", "") or "").strip()
    if not _TEMPLATE_ID_RE.match(tid):
        return None
    host, path = _valid_target_url(event.get("matched-at"), org_domains)
    if not host:
        return None
    info = event.get("info") if isinstance(event.get("info"), dict) else {}
    name = str(info.get("name", "") or tid).strip()[:_NAME_CAP]
    if not name:
        return None
    sev_raw = str(info.get("severity", "unknown") or "unknown").strip().lower()
    sev = _SEV_MAP.get(sev_raw, "INFO")
    tags = [str(t)[:40] for t in (info.get("tags") or []) if str(t).strip()][:10]
    category = ("nuclei " + (tags[0] if tags else "match"))[:80]
    cves = _extract_cves(event)
    matcher = str(event.get("matcher-name", "") or "")[:80]
    extracted = event.get("extracted-results")
    if isinstance(extracted, list):
        extracted_txt = "; ".join(str(x)[:200] for x in extracted[:5])
    else:
        extracted_txt = str(extracted or "")[:500]
    evidence = {
        "url": str(event.get("matched-at", ""))[:500],
        "template": tid,
        "template_severity": sev_raw,
        "matcher": matcher,
        "tags": tags,
    }
    if extracted_txt:
        evidence["extracted"] = extracted_txt
    refs = info.get("reference")
    if isinstance(refs, list) and refs:
        evidence["references"] = [str(r)[:300] for r in refs[:5]]
    desc = f"{name} matched on {host}{path} via nuclei template {tid}."
    if matcher:
        desc += f" Matcher: {matcher}."
    impact = ("A nuclei template matched this host. Template matches are strong "
              "signals but not exploit proofs — verify the affected component is "
              "present and reachable before prioritizing.")
    if cves:
        impact += f" Related: {', '.join(cves)}."
    today = time.strftime("%Y-%m-%d")
    ts = time.strftime("%Y%m%d%H%M%S")
    rec = {
        "id": "NUC-%s-%s" % (re.sub(r"[^a-z0-9]+", "-", str(slug).lower()).strip("-")[:24] or "org", ts),
        "title": name,
        "target": host,
        "ip": None,
        "port": 443 if str(event.get("matched-at", "")).startswith("https://") else 80,
        "severity": sev,
        "category": category,
        "status": "OPEN",
        "status_detail": f"NUCLEI-MATCHED (template {tid} — verify before acting)",
        "positive": False,
        "mode": "fast",
        "source": "nuclei",
        "description": desc[:2000],
        "impact": impact[:2000],
        "evidence": evidence,
        "proof_chain": [f"nuclei {tid} matched {event.get('matched-at', '')}"],
        "remediation": ["Verify the finding against the live host, then patch / "
                        "mitigate per vendor guidance for the matched template."],
        "related_cves": cves,
        "found_date": today,
        "first_seen": today,
        "last_seen": today,
        "status_history": [{"at": today, "from": "", "to": "OPEN",
                            "by": "nuclei", "note": f"template {tid} matched"}],
        "provenance": {"derived_from": ["nuclei"], "confidence": "template-match",
                       "evidence_timestamp": time.strftime("%Y-%m-%dT%H:%M:%S")},
    }
    rec["identity_key"] = f"nuclei|{host}|{tid.lower()}|{path}"
    return rec


def parse_output_file(path, slug, org_domains, cap=_EVENTS_CAP):
    """Parse nuclei JSONL output into validated finding dicts (bounded)."""
    out = []
    try:
        size = os.path.getsize(path)
    except OSError:
        return out
    if size > _OUTPUT_MAX_BYTES:
        return out  # fail open: oversized output is discarded, passive stands
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                if len(out) >= cap:
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    ev = json.loads(line[:65536])
                except Exception:
                    continue
                rec = map_event(slug, ev, org_domains)
                if rec:
                    out.append(rec)
    except OSError:
        pass
    return out


def build_argv(targets_file, output_file, severity, tags):
    """Argv list for the nuclei run (no shell, no free-form args)."""
    binp = nuclei_bin()
    tdir = templates_dir()
    if not binp or not tdir:
        raise RuntimeError("nuclei engine unavailable")
    argv = [binp, "-l", targets_file, "-t", tdir,
            "-severity", ",".join(severity),
            "-exclude-tags", ",".join(exclude_tags()),
            "-jsonl", "-o", output_file,
            "-silent", "-nc", "-duc", "-or", "-nm",
            "-rl", str(rate_limit()), "-retries", "1",
            "-timeout", "10", "-bulk-size", "10"]
    if tags:
        argv += ["-tags", ",".join(tags)]
    if not interactsh_enabled():
        argv += ["-ni"]
    return argv


def _child_env():
    env = {k: v for k, v in os.environ.items()
           if "_proxy" not in k.lower() and k.lower() not in ("http_proxy", "https_proxy",
                                                              "all_proxy", "no_proxy")}
    return env


def run_scan(target_urls, severity, tags, timeout_s, on_progress=None):
    """Run nuclei over target URLs.

    Returns (workdir, output_path_or_None, error_or_empty). The caller must
    parse output_path (if set) and then remove workdir with shutil.rmtree.
    """
    tmpd = tempfile.mkdtemp(prefix="nuclei-")
    try:
        os.chmod(tmpd, 0o700)
    except OSError:
        pass
    tfile = os.path.join(tmpd, "targets.txt")
    ofile = os.path.join(tmpd, "out.jsonl")
    try:
        with open(tfile, "w", encoding="utf-8") as f:
            for u in target_urls[:20]:
                f.write(str(u).strip() + "\n")
        os.chmod(tfile, 0o600)
    except OSError as e:
        return tmpd, None, f"cannot stage targets: {e}"
    try:
        argv = build_argv(tfile, ofile, severity, tags)
    except RuntimeError as e:
        return tmpd, None, str(e)
    if on_progress:
        try:
            on_progress("nuclei", f"running {len(target_urls)} target(s), budget {timeout_s}s")
        except Exception:
            pass
    try:
        proc = subprocess.Popen(argv, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL,
                                stdin=subprocess.DEVNULL,
                                start_new_session=True, env=_child_env())
    except (OSError, ValueError) as e:
        return tmpd, None, f"cannot spawn nuclei: {type(e).__name__}"
    try:
        proc.wait(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        try:
            proc.wait(timeout=10)
        except Exception:
            pass
        return tmpd, None, f"nuclei exceeded {timeout_s}s budget"
    if proc.returncode not in (0, 1):
        # nuclei exits 1 on some runs with findings/errors mixed; treat other
        # codes as failures but keep any output file for parsing attempt
        if not os.path.exists(ofile):
            return tmpd, None, f"nuclei exited {proc.returncode}"
    if not os.path.exists(ofile):
        return tmpd, None, "nuclei produced no output"
    return tmpd, ofile, ""
