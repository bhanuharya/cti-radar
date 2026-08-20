"""cti_correlation.py — derive a CTI correlation graph from org findings data.

Pure, deterministic, $0: reads an org's findings.json + baseline.txt
(from the data/orgs.json registry) and produces a graph of entities
(host, IP, CVE, brand/domain, severity-class) connected by shared-attribute
edges. No external calls, no secrets, no action.

Correlation axes:
  1. IP co-residency  — multiple hosts on the same IP (shared box / infra cluster)
  2. CVE fleet spread — same CVE hitting multiple hosts (shared remediation)
  3. Share of brand    — hosts grouped under their root domain (from org registry)
  4. Vuln-class        — findings sharing a category (e.g. all Pre-auth RCE)
  5. Confirmed status  — CONFIRMED / VERSION-CONFIRMED / clean triangulation
"""
import html as _html
import json, os, re, threading, time
from collections import defaultdict

BASE = os.path.dirname(os.path.abspath(__file__))
# Project root (one level above app/); runtime data may live elsewhere.
BASE = os.path.dirname(BASE)
DATA_ROOT = os.path.abspath(os.path.expanduser(
    os.environ.get("CTI_DATA_DIR", os.path.join(BASE, "data"))))

# per-org data dirs live under <data-root>/orgs/<slug>
ORG_ROOT = os.path.join(DATA_ROOT, "orgs")

# canonical lifecycle status per finding
CANONICAL_STATUSES = ("OPEN", "IN_PROGRESS", "MITIGATED", "ACCEPTED_RISK")

# Entity grouping is derived only from each registered org's configured domains.

DEFAULT_ORG = "sample"

_REGISTRY_FILE = os.path.join(DATA_ROOT, "orgs.json")


# entity types -> color (vis-friendly)
NODE_COLORS = {
    "host":  "#2ecc71",   # green
    "ip":    "#3498db",   # blue
    "cve":   "#e74c3c",   # red
    "brand": "#9b59b6",   # purple
    "class": "#f39c12",   # amber
}

_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def _load_registry():
    if not os.path.exists(_REGISTRY_FILE):
        return {}
    try:
        with open(_REGISTRY_FILE) as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except Exception:
        return {}


#: slug -> {name, domains, findings, baseline} from data/orgs.json
REGISTRY = _load_registry()


def _reload_registry():
    """Re-read data/orgs.json (call after registering a new org)."""
    global REGISTRY
    REGISTRY = _load_registry()


def org_list():
    """[{slug, name, domains}, ...] sorted by slug."""
    return [{"slug": slug, "name": (o.get("name") or slug),
             "domains": o.get("domains") or []}
            for slug, o in sorted(REGISTRY.items())]


def org_get(slug):
    """Registry entry for slug or None."""
    return REGISTRY.get(slug)


def _resolve_registry_path(value):
    """Resolve a registry path against DATA_ROOT.

    Existing registries may store paths as ``data/orgs/...``; newer external
    registries may use ``orgs/...``. Both resolve under the configured runtime
    data root. Absolute paths remain supported for backwards compatibility.
    """
    if not value:
        return None
    value = os.path.expanduser(str(value))
    if os.path.isabs(value):
        return os.path.abspath(value)
    norm = os.path.normpath(value)
    if norm == "data":
        norm = "."
    elif norm.startswith("data" + os.sep):
        norm = norm[len("data" + os.sep):]
    resolved = os.path.abspath(os.path.join(DATA_ROOT, norm))
    if os.path.commonpath([DATA_ROOT, resolved]) != DATA_ROOT:
        return None
    return resolved


def _org_paths(org):
    """Return (findings_path, baseline_path) for a registered org.

    Returns (None, None) for unknown orgs — callers must verify org existence
    via org_get() before calling. This prevents legacy fallback data leakage.
    """
    entry = REGISTRY.get(org)
    if entry:
        fp = _resolve_registry_path(entry.get("findings"))
        bp = _resolve_registry_path(entry.get("baseline"))
        if fp:
            return fp, bp
    return None, None


def _norm_cves(v):
    if isinstance(v, list):
        return [str(x).strip() for x in v if str(x).strip() and str(x).strip() != "None"]
    return [x.strip() for x in str(v).split(";") if x.strip() and x.strip() != "None"]


_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")
_DATE_RE = re.compile(r"20\d\d-\d\d-\d\d")
_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def extract_cves(v):
    """Return deduped real CVE IDs from a list/string value (ignores None /
    misconfiguration / placeholder text like 'CVE-... (CVSS 9.8)')."""
    if v is None:
        return []
    parts = v if isinstance(v, list) else [v]
    out, seen = [], set()
    for p in parts:
        for m in _CVE_RE.findall(str(p)):
            if m not in seen:
                seen.add(m)
                out.append(m)
    return out


def single_public_ip(v):
    """Return v if it is a single plausible public IPv4, else None.

    Skips invalid / private / reserved / loopback / link-local / CGNAT /
    multicast / placeholder / multi-IP values (e.g. 'multiple', '(GCS)',
    '10.0.0.1, 172.16.0.1').
    """
    s = str(v).strip() if v is not None else ""
    if not _IPV4_RE.match(s):
        return None
    a, b, c, d = s.split(".")
    a, b, c, d = int(a), int(b), int(c), int(d)
    if any(x > 255 for x in (a, b, c, d)):
        return None
    if a == 0 or a == 127 or a >= 224:
        return None
    if a == 10:
        return None
    if a == 172 and 16 <= b <= 31:
        return None
    if a == 192 and b == 168:
        return None
    if a == 169 and b == 254:
        return None
    if a == 100 and 64 <= b <= 127:
        return None
    return s


def load_meta_date(org=DEFAULT_ORG):
    """Return the org scan meta date (ISO 'YYYY-MM-DD') or None."""
    findings_path, _ = _org_paths(org)
    if findings_path and os.path.exists(findings_path):
        try:
            with open(findings_path) as f:
                d = json.load(f)
            meta = d.get("meta") if isinstance(d, dict) else None
            if isinstance(meta, dict):
                m = _DATE_RE.search(str(meta.get("date") or meta.get("scan_date") or ""))
                if m:
                    return m.group(0)
        except Exception:
            pass
    return None


# --------------------------------------------------------------------------
# evidence enrichment + PII masking helpers
# --------------------------------------------------------------------------
# keys whose values are treated as PII / confidential and must be masked
_PII_KEYS = {
    "password", "passwd", "secret", "token", "api_key", "apikey", "apisecret",
    "email", "mail", "phone", "mobile", "accountno", "account_number", "card",
    "cardno", "card_number", "pan", "cvv", "cif", "login", "username", "userid",
    "userId", "user_id", "clientip", "client_ip", "dest_ip", "sourceip",
    "deviceid", "device_id", "sessionid", "session_id", "authorization", "auth",
    "firstname", "lastname", "middlename", "fullname", "ssn", "nik", "npwp",
    "createdby", "modifiedby", "realm", "adUser", "fullname",
}

# value-level masks for common PII shapes appearing inside any string
def _mask_email(v):
    return re.sub(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
                  lambda m: m.group(0)[0:1] + "***@" + m.group(0).split("@")[1],
                  v)

def _mask_phone(v):
    # +62/08/number runs of >=8 digits -> keep country + area prefix, mask rest
    def repl(m):
        digits = m.group(0)
        if len(digits) <= 6:
            return "*" * len(digits)
        return digits[:4] + "*" * (len(digits) - 6) + digits[-2:]
    return re.sub(r"(?<![\d*])\d{8,}(?![\d*])", repl, v)

def _mask_big_number(v):
    # long digit runs (account/card/bank) -> keep first 2-3 + last 2, mask middle
    def repl(m):
        d = m.group(0)
        if len(d) <= 5:
            return d[0:1] + "*" * (len(d) - 1) if d else d
        return d[:2] + "*" * (len(d) - 4) + d[-2:]
    return re.sub(r"\d{6,}", repl, v)

def _mask_ip_in_text(v):
    # internal/private + full public IPs in prose -> mask the last 2 octets
    def repl(m):
        ip = m.group(0)
        parts = ip.split(".")
        if len(parts) != 4:
            return ip
        a, b = parts[0], parts[1]
        return f"{a}.{b}.*.*"
    # public IPs
    v = re.sub(r"(?<![0-9.])(\d{1,3}\.\d{1,3})\.\d{1,3}\.\d{1,3}(?!\d)",
               repl, v)
    return v

def _mask_value(key, value):
    """Mask a single value based on its key name / content. Key-insensitive."""
    k = key.lower().replace("_", "").replace("-", "")
    if value is None:
        return value
    if isinstance(value, bool) or isinstance(value, (int, float)):
        return value
    s = str(value)
    # direct PII-key match -> fully mask (keep 1st char + ***)
    if k in {x.lower().replace("_", "") for x in _PII_KEYS} and \
       len(s.strip()) > 0:
        if len(s) <= 2:
            return "***"
        return s[0] + "*" * min(len(s) - 1, 8)
    # content-level masks
    s = _mask_email(s)
    s = _mask_phone(s)
    s = _mask_big_number(s)
    s = _mask_ip_in_text(s)
    return s

def _mask_deep(obj, key="val"):
    """Recursively mask a nested structure of dict/list/str."""
    if isinstance(obj, dict):
        return {_mask_key(k): _mask_deep(v, k) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_mask_deep(x, key) for x in obj]
    if isinstance(obj, str):
        return _mask_value(key, obj)
    return obj

def _mask_key(k):
    """Mask obviously-sensitive KEY names too (e.g. silver into sil***)."""
    return k

def _mask_finding_deep(nf):
    """Apply PII masking to a finding's human-readable fields in-place (copy)."""
    out = dict(nf)
    for field in ("description", "impact", "status", "discovery", "title",
                  "category", "remediation", "proof_chain", "reproduction_steps",
                  "topics_exposed", "evidence", "status_detail",
                  "ai_provenance", "ai_suggestions", "status_history"):
        if field in out:
            out[field] = _mask_deep(out[field], field)
    return out

def enrich_finding_evidence(f):
    """Ensure finding has report-style reproduction_steps + evidence.commands.

    reproduction_steps: if missing, derive from proof_chain (real captured
    steps). evidence: if a dict and missing a 'commands' snapshot, build one
    from reproduction_steps as command->snippet pairs.
    """
    if not isinstance(f, dict):
        return f
    steps = f.get("reproduction_steps")
    pc = f.get("proof_chain")
    if not isinstance(steps, list) or not steps:
        if isinstance(pc, list) and pc:
            f["reproduction_steps"] = list(pc)
        else:
            f["reproduction_steps"] = []
    steps = f.get("reproduction_steps") or []
    ev = f.get("evidence")
    if isinstance(ev, dict) and "commands" not in ev and steps:
        ev["commands"] = {}
        for s in steps:
            label = str(s).split(" -> ")[0][:60]
            snippet = str(s)
            if " -> " in str(s):
                snippet = str(s).split(" -> ", 1)[1][:120]
            ev["commands"][label[:40]] = snippet
    return f


# --------------------------------------------------------------------------
# status lifecycle + history ledger
# --------------------------------------------------------------------------
def _now_iso():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _slug_from_org(org):
    if isinstance(org, str):
        return str(org).strip()
    return str((org or {}).get("slug") or "").strip()


def history_path(org):
    return os.path.join(ORG_ROOT, _slug_from_org(org), "history.json")


def canonical_status(f):
    """Derive the canonical lifecycle status from a finding's status string."""
    s = str(f.get("status", "") or "").strip()
    if not s:
        return "OPEN"
    u = s.upper()
    if u in CANONICAL_STATUSES:
        return u
    if "ACCEPTED" in u and "RISK" in u:
        return "ACCEPTED_RISK"
    if "IN_PROGRESS" in u or "IN PROGRESS" in u or "IN-PROGRESS" in u:
        return "IN_PROGRESS"
    if "MITIGATED" in u:
        return "MITIGATED"
    return "OPEN"


def _is_positive_status(s):
    u = str(s or "").upper()
    return ("SECURE" in u) or ("CLEAN" in u)


def _extract_found_date(f, org, meta_date):
    for key in ("status", "status_detail", "discovery"):
        m = _DATE_RE.search(str(f.get(key, "")))
        if m:
            return m.group(0)
    if meta_date is None:
        meta_date = load_meta_date(org)
    return meta_date


def ensure_lifecycle(f, org=DEFAULT_ORG, meta_date=None):
    """In-place: initialize first_seen / last_seen / status_history if absent."""
    fd = f.get("found_date")
    if not fd:
        fd = _extract_found_date(f, org, meta_date)
    if not fd:
        fd = _now_iso()
    if not f.get("first_seen"):
        f["first_seen"] = fd
    if not f.get("last_seen"):
        f["last_seen"] = fd
    sh = f.get("status_history")
    if not isinstance(sh, list) or not sh:
        f["status_history"] = [{
            "at": fd, "from": "", "to": f.get("status", "OPEN"),
            "by": "scan", "note": "initial",
        }]


def migrate_finding(f, org=DEFAULT_ORG, meta_date=None):
    """In-place: migrate legacy descriptive status -> canonical status (preserve
    the original descriptive text in status_detail), set the positive flag for
    SECURE/CLEAN findings, and initialize lifecycle metadata. Idempotent."""
    raw = f.get("status")
    s = str(raw or "").strip()
    u = s.upper()
    if u in CANONICAL_STATUSES:
        f["status"] = u or "OPEN"
    else:
        if "status_detail" not in f and s:
            f["status_detail"] = s
        f["status"] = canonical_status(f)
    if _is_positive_status(s) and not f.get("positive"):
        f["positive"] = True
    ensure_lifecycle(f, org=org, meta_date=meta_date)


# --- snapshot diffing (new / resolved / changed vs prior run) ---
def build_snapshot(fs):
    """Return {finding_id: {severity, status}} using canonical status."""
    snap = {}
    for f in fs:
        fid = str(f.get("id", "")).strip()
        if not fid:
            continue
        snap[fid] = {
            "severity": str(f.get("severity", "")).upper(),
            "status": canonical_status(f),
        }
    return snap


def diff_snapshot(prev, cur):
    """Return (new_ids, resolved_ids, changed_ids)."""
    prev = prev if isinstance(prev, dict) else {}
    cur = cur if isinstance(cur, dict) else {}
    new = sorted(k for k in cur if k not in prev)
    resolved = sorted(k for k in prev if k not in cur)
    changed = sorted(k for k in cur if k in prev and prev[k] != cur[k])
    return new, resolved, changed


# --- append-only history ledger (per-org lock + atomic append) ---
def _append_history_locked(hp, event):
    events = []
    if os.path.exists(hp):
        try:
            with open(hp) as fh:
                d = json.load(fh)
            if isinstance(d, list):
                events = d
        except Exception:
            events = []
    events.append(event)
    _atomic_write_json(hp, events)


def append_history(org, event):
    """Append one event to data/orgs/<slug>/history.json (append-only array)."""
    slug = _slug_from_org(org)
    if not slug:
        return
    hp = history_path(slug)
    os.makedirs(os.path.dirname(hp), exist_ok=True)
    with _org_lock(slug):
        _append_history_locked(hp, event)


def load_history(org=DEFAULT_ORG):
    """Return the list of history events for an org ([] if none)."""
    hp = history_path(org)
    events = []
    if os.path.exists(hp):
        try:
            with open(hp) as fh:
                d = json.load(fh)
            if isinstance(d, list):
                events = d
        except Exception:
            events = []
    return events


def history_summary(events):
    by_kind = {}
    for e in events:
        k = str(e.get("kind", "?"))
        by_kind[k] = by_kind.get(k, 0) + 1
    return {"total": len(events), "by_kind": by_kind}


def record_event_and_snapshot(org, kind, mode=None, note=""):
    """Lock, compute diff vs meta.last_snapshot, append a history event, update
    last_snapshot, and atomically persist. Returns the event summary dict."""
    slug = _slug_from_org(org)
    if not slug:
        return None
    fp = org_findings_path(slug)
    lock = _org_lock(slug)
    with lock:
        data = {"findings": []}
        if fp and os.path.exists(fp):
            try:
                with open(fp) as fh:
                    d = json.load(fh)
                if isinstance(d, dict):
                    data = d
            except Exception:
                data = {"findings": []}
        meta = data.get("meta")
        if not isinstance(meta, dict):
            meta = {}
        prev = meta.get("last_snapshot") or {}
        fs = data.get("findings") or []
        cur = build_snapshot(fs)
        new, resolved, changed = diff_snapshot(prev, cur)
        summary = {
            "subdomains": int(meta.get("subdomains", 0) or 0),
            "found": len(fs),
            "new": len(new),
            "resolved": len(resolved),
            "changed": len(changed),
        }
        event = {
            "ts": _now_iso(),
            "kind": kind,
            "mode": mode,
            "summary": summary,
            "note": note,
        }
        meta["last_snapshot"] = cur
        data["meta"] = meta
        if fp:
            _atomic_write_json(fp, data)
        hp = history_path(slug)
        os.makedirs(os.path.dirname(hp), exist_ok=True)
        _append_history_locked(hp, event)
        return summary


def _id_slug(s):
    return re.sub(r"[^a-z0-9-]+", "-", str(s).lower()).strip("-")[:32]


def _ai_merge(existing, af):
    """Merge AI fields into an existing finding without duplicating identity."""
    for k, v in af.items():
        if k in ("id", "status", "status_detail", "mode", "target", "title"):
            continue
        if v is None or v == "" or v == [] or v == {}:
            continue
        existing[k] = v
    existing["status_detail"] = "AI-ASSESSED"
    existing["mode"] = "ai"
    existing["status"] = "OPEN"
    existing["last_seen"] = _now_iso()


def persist_ai_findings(org, ai_findings):
    """Merge AI assessment findings into findings.json, deduped by target+title.

    New AI findings get status OPEN + status_detail AI-ASSESSED + mode ai;
    existing matches have AI fields merged in place. Per-org lock + atomic
    write. Returns the number of newly added records.
    """
    slug = _slug_from_org(org)
    if not slug:
        return 0
    fp = org_findings_path(slug)
    lock = _org_lock(slug)
    added = 0
    with lock:
        data = {"findings": []}
        if fp and os.path.exists(fp):
            try:
                with open(fp) as fh:
                    d = json.load(fh)
                if isinstance(d, dict):
                    data = d
            except Exception:
                data = {"findings": []}
        existing = data.get("findings") or []
        idx = {}
        for f in existing:
            key = (str(f.get("target", "")).strip().lower(),
                   str(f.get("title", "")).strip().lower())
            idx[key] = f
        seq = len(existing)
        for af in ai_findings:
            target = str(af.get("target", "")).strip()
            title = str(af.get("title", "")).strip()
            if not target or not title:
                continue
            key = (target.lower(), title.lower())
            if key in idx:
                _ai_merge(idx[key], af)
                continue
            seq += 1
            nf = dict(af)
            nf["id"] = "AI-" + _id_slug(slug) + "-" + str(seq)
            nf["status"] = "OPEN"
            nf["status_detail"] = "AI-ASSESSED"
            nf["mode"] = "ai"
            nf["severity"] = str(af.get("severity", "INFO")).upper()
            nf["related_cves"] = [str(c) for c in (af.get("related_cves") or [])
                                  if isinstance(c, str) and str(c).strip()]
            ensure_lifecycle(nf, org=slug, meta_date=None)
            existing.append(nf)
            idx[key] = nf
            added += 1
        data["findings"] = existing
        if fp:
            _atomic_write_json(fp, data)
    return added


def set_finding_status(org, id_, new_status, note=""):
    """Token-gated mutation helper: update a finding's canonical status, append
    status_history, and log a status_change history event. Returns (finding, err).
    """
    slug = _slug_from_org(org)
    if new_status not in CANONICAL_STATUSES:
        return None, "invalid status"
    fp = org_findings_path(slug)
    if not fp or not os.path.exists(fp):
        return None, "not found"
    lock = _org_lock(slug)
    with lock:
        data = {"findings": []}
        try:
            with open(fp) as fh:
                d = json.load(fh)
            if isinstance(d, dict):
                data = d
        except Exception:
            data = {"findings": []}
        fs = data.get("findings") or []
        target = None
        for f in fs:
            if str(f.get("id")) == str(id_):
                target = f
                break
        if target is None:
            return None, "not found"
        migrate_finding(target, org=slug)
        old = str(target.get("status", "OPEN"))
        now = _now_iso()
        target["status_history"].append({
            "at": now, "from": old, "to": new_status, "by": "user", "note": note,
        })
        target["status"] = new_status
        target["last_seen"] = now
        _atomic_write_json(fp, data)
        event = {
            "ts": now,
            "kind": "status_change",
            "mode": None,
            "summary": {"subdomains": 0, "found": len(fs),
                        "new": 0, "resolved": 0, "changed": 1},
            "note": "%s: %s -> %s" % (id_, old, new_status),
        }
        hp = history_path(slug)
        os.makedirs(os.path.dirname(hp), exist_ok=True)
        _append_history_locked(hp, event)
        return target, None


def normalize_finding(f, org=DEFAULT_ORG, meta_date=None):
    """Return a copy of `f` enriched with derived fields.

    Adds: found_date (first ISO date in status/discovery, else org meta date,
    else None), tier (CONFIRMED / CORRELATED / OTHER from status), cve_links
    (canonical NVD links for real CVEs only), shodan_link and internetdb_link
    (when a single plausible public IP is present).

    Evidence enrichment + PII masking (always applies to stored/displayed data):
      - reproduction_steps: built from proof_chain when the finding has one but
        no reproduction_steps yet (so every finding gets the report-style
        numbered command/step list).
      - commands snapshot: added to evidence from the reproduction steps
        (command -> snippet pairs) when evidence lacks one.
      - PII masking: any PII/confidential values in evidence, description,
        proof_chain, etc. are masked (never raw).
    """
    nf = dict(f)
    if meta_date is None:
        meta_date = load_meta_date(org)
    nf["found_date"] = _extract_found_date(f, org, meta_date)

    # canonical status + status_detail preservation + lifecycle metadata
    migrate_finding(nf, org=org, meta_date=meta_date)

    st = str(nf.get("status", "")).upper()
    sd = str(nf.get("status_detail", "")).upper()
    if "AI-ASSESSED" in sd:
        tier = "AI"
    elif "CONFIRMED" in sd:
        tier = "CONFIRMED"
    elif "CORRELATED" in sd or "CORRELATED" in st:
        tier = "CORRELATED"
    else:
        tier = "OTHER"
    nf["tier"] = tier

    nf["cve_links"] = ["https://nvd.nist.gov/vuln/detail/" + c
                       for c in extract_cves(f.get("related_cves"))]
    ip = single_public_ip(f.get("ip"))
    nf["shodan_link"] = "https://www.shodan.io/host/" + ip if ip else None
    nf["internetdb_link"] = "https://internetdb.shodan.io/" + ip if ip else None

    # --- evidence enrichment (reproduction steps from proof chain) ---
    enrich_finding_evidence(nf)

    # --- PII / confidential masking on all displayed textual content ---
    nf = _mask_finding_deep(nf)
    return nf


# --------------------------------------------------------------------------
# persistence (per-org lock + atomic write + dedup)
# --------------------------------------------------------------------------
_locks_guard = threading.Lock()
_org_locks = {}


def _org_lock(slug):
    with _locks_guard:
        if slug not in _org_locks:
            _org_locks[slug] = threading.Lock()
        return _org_locks[slug]


def org_findings_path(org):
    """Absolute path to the org's findings.json (registered orgs only)."""
    fp, _ = _org_paths(org)
    return fp


def _atomic_write_json(path, data):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
    os.replace(tmp, path)


def _dedup_key(f):
    return "|".join([
        str(f.get("target", "")).strip().lower(),
        str(f.get("category", "")).strip().lower(),
        str(f.get("source", "")).strip().lower(),
    ])


def persist_correlated(org, new_findings, report=None):
    """Append deduplicated correlated findings to the org findings file.

    Existing findings are always preserved; only new ones (by stable
    target+category+source key) are appended. Write is atomic (tmp + replace)
    and guarded by a per-org lock. Returns the number of newly added records.
    """
    slug = org if isinstance(org, str) else str(org.get("slug") or org)
    fp = org_findings_path(slug)
    lock = _org_lock(slug)
    with lock:
        data = {"findings": []}
        if fp and os.path.exists(fp):
            try:
                with open(fp) as f:
                    d = json.load(f)
                if isinstance(d, dict):
                    data = d
            except Exception:
                data = {"findings": []}
        existing = data.get("findings") or []
        keys = {_dedup_key(f) for f in existing}
        added = 0
        for nf in new_findings:
            k = _dedup_key(nf)
            if k in keys:
                continue
            keys.add(k)
            existing.append(nf)
            added += 1
        data["findings"] = existing
        if report is not None:
            meta = data.get("meta")
            if not isinstance(meta, dict):
                meta = {}
            meta["correlation"] = report
            data["meta"] = meta
        if fp:
            _atomic_write_json(fp, data)
    return added


def correlation_report(org=DEFAULT_ORG):
    """Return the latest correlation report stored in meta, or None."""
    fp = org_findings_path(org)
    if fp and os.path.exists(fp):
        try:
            with open(fp) as f:
                d = json.load(f)
            if isinstance(d, dict) and isinstance(d.get("meta"), dict):
                return d["meta"].get("correlation")
        except Exception:
            pass
    return None


def _root_domain(host, domains=None):
    h = str(host).strip().lower().rstrip(".")
    roots = [str(d).strip().lower().rstrip(".")
             for d in (domains or []) if str(d).strip()]
    # No organization-specific fallback: grouping comes only from registry scope.
    # strip leading labels down to registrable-ish domain for the org's roots
    for root in roots:
        if h == root or h.endswith("." + root):
            return root
    # raw IP
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", h):
        return "raw-ip"
    return "other"


def load_data(org=DEFAULT_ORG):
    fs = []
    findings_path, baseline_path = _org_paths(org)
    if findings_path and os.path.exists(findings_path):
        try:
            with open(findings_path) as f:
                d = json.load(f)
            fs = d.get("findings", []) if isinstance(d, dict) else []
        except Exception:
            fs = []
    baseline = []
    if baseline_path and os.path.exists(baseline_path):
        try:
            with open(baseline_path) as f:
                baseline = [l.strip() for l in f if l.strip() and not l.startswith("#")]
        except Exception:
            baseline = []
    return fs, baseline


# --- reusable in-memory builders (for aggregate request reuse) ---
def summary_from_data(fs, baseline):
    """Build summary payload from in-memory findings/baseline without re-reading files."""
    sev = defaultdict(int)
    for f in (fs or []):
        sev[str(f.get("severity", "INFO")).upper()] += 1
    bl = baseline if isinstance(baseline, list) else []
    return {"findings_total": len(fs or []), "severity": dict(sev), "baseline": len(bl)}


def fleet_spread_from_data(fs):
    """CVE fleet spread from in-memory findings."""
    cve2hosts = defaultdict(set)
    for f in (fs or []):
        for c in _norm_cves(f.get("related_cves")):
            cve2hosts[c].add(str(f.get("target", "")))
    return [{"cve": c, "hosts": sorted(hs)} for c, hs in sorted(cve2hosts.items(), key=lambda x: -len(x[1]))]


def ip_sharing_from_data(fs):
    """IP co-residency from in-memory findings."""
    ip2hosts = defaultdict(set)
    for f in (fs or []):
        ip, tgt = str(f.get("ip", "")).strip(), str(f.get("target", "")).strip()
        if ip and ip != "None" and tgt:
            ip2hosts[ip].add(tgt)
    return [{"ip": ip, "hosts": sorted(hs)} for ip, hs in sorted(ip2hosts.items(), key=lambda x: -len(x[1]))]


def build_graph_from_data(fs, baseline, domains=None):
    """Correlation graph from in-memory findings/baseline/domains."""
    fs = fs or []
    baseline = baseline or []
    domains = domains or []
    nodes = {}
    edges = []

    def add_node(id_, label, type_, **kw):
        if id_ not in nodes:
            n = {"id": id_, "label": label, "type": type_,
                 "color": NODE_COLORS.get(type_, "#888"), **kw}
            nodes[id_] = n
        return nodes[id_]

    def add_edge(a, b, label, **kw):
        edges.append({"from": a, "to": b, "label": label, **kw})

    for f in fs:
        tgt = str(f.get("target", "")).strip() or "?"
        sev = str(f.get("severity", "INFO")).upper()
        cat = str(f.get("category", "")).strip()
        add_node("host:" + tgt, _html.escape(tgt), "host", sev=sev,
                 title=f"<b>{_html.escape(tgt)}</b><br>sev: {_html.escape(sev)} — {_html.escape(cat)}")

        ip = str(f.get("ip", "")).strip()
        if ip and ip != "None":
            add_node("ip:" + ip, _html.escape(ip), "ip", sev=sev,
                     title=_html.escape(f"IP: {ip}"))
            add_edge("ip:" + ip, "host:" + tgt, "resolves\u2192")

        root = _root_domain(tgt, domains)
        if root not in ("raw-ip", "other"):
            add_node("brand:" + root, _html.escape(root), "brand")
            add_edge("host:" + tgt, "brand:" + root, "part-of")

        if cat:
            add_node("class:" + cat, _html.escape(cat[:40]), "class",
                     title=_html.escape(f"Class: {cat[:80]}"))
            add_edge("host:" + tgt, "class:" + cat, "is")

        for c in _norm_cves(f.get("related_cves")):
            add_node("cve:" + c, _html.escape(c), "cve", sev=sev,
                     title=_html.escape(f"CVE: {c}"))
            add_edge("host:" + tgt, "cve:" + c, "has")

    for h in baseline:
        if f"host:{h}" not in nodes:
            ip = None
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", h):
                ip = h
            if ip:
                add_node("ip:" + ip, _html.escape(ip), "ip")
                add_node("host:" + h, _html.escape(h), "host", sev="INFO")
                add_edge("ip:" + ip, "host:" + h, "resolves\u2192")
            else:
                add_node("host:" + h, _html.escape(h), "host", sev="INFO")
                root = _root_domain(h, domains)
                if root not in ("raw-ip", "other"):
                    add_node("brand:" + root, _html.escape(root), "brand")
                    add_edge("host:" + h, "brand:" + root, "part-of")

    ip_clusters = defaultdict(list)
    for e in edges:
        if e.get("label") == "resolves\u2192" and e["from"].startswith("ip:"):
            ip_clusters[e["from"]].append(e["to"])
    cve_hosts = defaultdict(list)
    for e in edges:
        if e.get("label") == "has" and e["to"].startswith("cve:"):
            cve_hosts[e["to"]].append(e["from"])

    for ip, hosts in ip_clusters.items():
        if len(hosts) >= 2:
            add_node("ip:" + ip, _html.escape(ip.split(":", 1)[1]), "ip",
                     cluster=True, title=f"<b>Shared box</b><br>{len(hosts)} hosts")
            for h in hosts[1:]:
                add_edge(hosts[0], h, "co-resident", dashes=True, color="#7f8c8d")

    for cve, hosts in cve_hosts.items():
        if len(hosts) >= 2:
            pass

    return {"nodes": list(nodes.values()), "edges": edges,
            "meta": {"findings": len(fs), "baseline": len(baseline)}}


def find_finding(org, id_):
    """Return the full finding dict for (org, id_) or None."""
    fs, _ = load_data(org)
    for f in fs:
        if str(f.get("id")) == str(id_):
            return f
    return None


def build_graph(org=DEFAULT_ORG):
    """Return {nodes:[...], edges:[...]} for the correlation graph."""
    fs, baseline = load_data(org)
    domains = (REGISTRY.get(org) or {}).get("domains") or []
    return build_graph_from_data(fs, baseline, domains)


def fleet_spread(org=DEFAULT_ORG):
    """Same CVE across multiple hosts -> shared remediation priority."""
    fs, _ = load_data(org)
    return fleet_spread_from_data(fs)


def ip_sharing(org=DEFAULT_ORG):
    """Co-residency: same IP serving multiple hosts."""
    fs, _ = load_data(org)
    return ip_sharing_from_data(fs)


def summary(org=DEFAULT_ORG):
    fs, baseline = load_data(org)
    return summary_from_data(fs, baseline)


if __name__ == "__main__":
    g = build_graph()
    print("nodes:", len(g["nodes"]), "edges:", len(g["edges"]))
    print("summary:", summary())
