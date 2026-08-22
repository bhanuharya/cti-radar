"""cve_match.py — offline version→CVE matching against the vendored map.

Deterministic, $0, no network. Given the {product, version} pairs extracted
by scanner.parse_versions() from banners/headers/titles, match them against
app/cve_data.json (curated high-impact CVEs) and return advisory matches.

Matches are evidence, not confirmations: callers must tier resulting findings
as CORRELATED with an explicit "verify affected range" caveat. Confidence is
"medium" when the observed version carries two or more numeric components
(e.g. nginx/1.18.0) and "low" when only one (e.g. Apache/2), where a match is
plausible but the exact patch level is unknown.
"""
import json
import os
import re
import threading
import time

_CVE_ID_RE = re.compile(r"CVE-\d{4}-\d{4,7}")

_map_cache = None
_alias_index = None
_map_lock = threading.Lock()


def load_map():
    """Load and validate cve_data.json once per process."""
    global _map_cache
    if _map_cache is not None:
        return _map_cache
    with _map_lock:
        if _map_cache is not None:
            return _map_cache
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cve_data.json")
        with open(path) as f:
            data = json.load(f)
        products = data.get("products") or {}
        for key, entry in products.items():
            for cve in entry.get("cves", []):
                if not _CVE_ID_RE.fullmatch(str(cve.get("cve", ""))):
                    raise ValueError("invalid CVE id in cve_data.json: %r" % cve.get("cve"))
                if str(cve.get("severity", "")).upper() not in ("CRITICAL", "HIGH"):
                    raise ValueError("invalid severity for %s" % cve.get("cve"))
                if not cve.get("ranges"):
                    raise ValueError("missing ranges for %s" % cve.get("cve"))
        _map_cache = products
        return _map_cache


def reset_cache():
    """Test hook: force the next load_map() to re-read the file."""
    global _map_cache, _alias_index
    with _map_lock:
        _map_cache = None
        _alias_index = None


# canonical key -> product entry; alias (lowercased, trimmed) -> canonical key
_alias_index = None


def _aliases():
    global _alias_index
    if _alias_index is None:
        idx = {}

        def _norm(s):
            return re.sub(r"[\s_/-]+", " ", str(s).strip().lower())

        for key, entry in load_map().items():
            names = set([key] + [_norm(a) for a in entry.get("aliases", [])])
            for n in names:
                idx.setdefault(n, key)
        _alias_index = idx
    return _alias_index


def normalize_product(name):
    """Map an observed product token to a canonical map key (or None)."""
    if not name:
        return None
    n = str(name).strip().lower().rstrip(".")
    n = re.sub(r"[\s_/-]+", " ", n)
    idx = _aliases()
    if n in idx:
        return idx[n]
    # drop a vendor prefix by trying the last word ("apache tomcat" ->
    # "tomcat", "apache struts" -> "struts"); the FIRST word is the vendor
    # itself, so trying it would mis-map "apache struts" -> apache
    parts = [p for p in n.split(" ") if p]
    if len(parts) > 1:
        if parts[-1] in idx:
            return idx[parts[-1]]
        # trailing version token ("apache coyote 1.1" -> "apache coyote")
        if parts[-1][:1].isdigit():
            stem = " ".join(parts[:-1])
            if stem in idx:
                return idx[stem]
    return None


def _vkey(version):
    """Leading numeric components of a version string -> tuple of ints.

    '1.18.0' -> (1, 18, 0); '7.1p2' -> (7, 1); '2.4.49-1ubuntu2' -> (2, 4, 49);
    '1.3.5a' -> (1, 3, 5); '2' -> (2,). Short patch-level suffixes (p1, a, b,
    rc1) are dropped but keep their number; long distro suffixes ('1ubuntu2')
    end the numeric prefix entirely — packaging revisions are below this
    map's granularity.
    """
    parts = []
    for tok in re.split(r"[.\-_+ ]", str(version or "")):
        if tok.isdigit():
            parts.append(int(tok))
            continue
        m = re.match(r"^(\d+)([A-Za-z]{0,3}\d*)$", tok)
        if m and m.group(1):
            parts.append(int(m.group(1)))
        break  # first non-cleanly-numeric token ends the numeric prefix
    return tuple(parts)


def _cmp(a, b):
    """Compare two int tuples, right-padded with zeros to equal length."""
    n = max(len(a), len(b))
    a = a + (0,) * (n - len(a))
    b = b + (0,) * (n - len(b))
    return (a > b) - (a < b)


def version_satisfies(version, range_str):
    """True if `version` satisfies a constraint string like '>=2.4.49,<=2.4.50'.

    Operators: =, <, <=, >, >= (AND-combined, comma-separated).
    """
    v = _vkey(version)
    if not v:
        return False
    for clause in str(range_str or "").split(","):
        clause = clause.strip()
        if not clause:
            continue
        m = re.match(r"^(>=|<=|=|>|<)\s*(.+)$", clause)
        if not m:
            return False
        op, ref = m.group(1), _vkey(m.group(2))
        if not ref:
            return False
        c = _cmp(v, ref)
        ok = {"=": c == 0, "<": c < 0, "<=": c <= 0, ">": c > 0, ">=": c >= 0}[op]
        if not ok:
            return False
    return True


def _confidence_for(vkey):
    return "medium" if len(vkey) >= 2 else "low"


_SEV_RANK = {"CRITICAL": 0, "HIGH": 1}


def match_cves(versions, cap=12):
    """Match observed [{product, version}] pairs against the map.

    Returns a list of match dicts sorted most severe first:
    {product, version, cve, severity, cvss, summary, fix_version, range,
     confidence}. `confidence` is the weakest (lowest-information) confidence
    among the ranges that matched for that CVE.
    """
    out = []
    seen = set()
    for v in versions or []:
        if not isinstance(v, dict):
            continue
        key = normalize_product(v.get("product"))
        if not key:
            continue
        version = str(v.get("version") or "")
        vkey = _vkey(version)
        if not vkey:
            continue
        entry = load_map().get(key) or {}
        for cve in entry.get("cves", []):
            best_conf = None
            hit_range = None
            for rng in cve.get("ranges", []):
                if version_satisfies(version, rng):
                    hit_range = rng
                    best_conf = _confidence_for(vkey)
                    break
            if hit_range is None:
                continue
            cve_id = str(cve["cve"])
            if (key, cve_id) in seen:
                continue
            seen.add((key, cve_id))
            out.append({
                "product": key,
                "version": version,
                "cve": cve_id,
                "severity": str(cve.get("severity", "HIGH")).upper(),
                "cvss": cve.get("cvss"),
                "summary": cve.get("summary", ""),
                "fix_version": cve.get("fix_version"),
                "range": hit_range,
                "confidence": best_conf,
            })
        if len(out) >= cap:
            break
    out.sort(key=lambda m: (_SEV_RANK.get(m["severity"], 9), m["cve"]))
    return out[:cap]


def worst_confidence(matches):
    """'low' if any match is low-confidence, else 'medium'."""
    return "low" if any(m.get("confidence") == "low" for m in matches) else "medium"


# --------------------------------------------------------------------------
# optional NVD enrichment (CTI_NVD_ENRICH=1) — fail-open by design
# --------------------------------------------------------------------------

_NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="
_nvd_last_call = 0.0
_nvd_cache_lock = threading.Lock()


def nvd_enabled():
    return os.environ.get("CTI_NVD_ENRICH", "").strip().lower() in ("1", "true", "yes", "on")


def _state_dir():
    return os.environ.get(
        "CTI_STATE_DIR",
        os.path.join(os.path.expanduser("~"), ".local", "state", "cti-radar"))


def _http_get_json(url, timeout=15, headers=()):
    """Fetch JSON via curl (proxy bypassed, no redirects) — {} on any failure."""
    import subprocess
    import tempfile
    try:
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            tmp = tf.name
        cmd = ["curl", "-s", "--noproxy", "*", "--max-redirs", "0",
               "--max-time", str(timeout)]
        for h in headers:
            cmd += ["-H", h]
        cmd += ["-o", tmp, url]
        subprocess.run(cmd, timeout=timeout + 5, capture_output=True, text=True)
        with open(tmp) as f:
            body = f.read(2_000_000)
        os.unlink(tmp)
        return json.loads(body)
    except Exception:
        return {}


def _nvd_cache_path():
    return os.path.join(_state_dir(), "nvd_cache.json")


def _nvd_cache_load():
    try:
        with open(_nvd_cache_path()) as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except Exception:
        return {}


def _nvd_cache_store(entry):
    try:
        os.makedirs(_state_dir(), exist_ok=True)
        cache = _nvd_cache_load()
        cache.update(entry)
        tmp = _nvd_cache_path() + ".tmp"
        with open(tmp, "w") as f:
            json.dump(cache, f)
        os.replace(tmp, _nvd_cache_path())
    except Exception:
        pass


def nvd_lookup(cve, ttl=86400):
    """Enrich one CVE id from the NVD 2.0 API (disk-cached, rate-limited).

    Returns (data, network_used): data is {"cvss", "vector", "summary"} or
    None; network_used is False when a fresh cache entry answered. Any
    failure (network, JSON, missing fields) returns (None, network_used) —
    enrichment never blocks or fails a scan.
    """
    global _nvd_last_call
    now = time.time()
    with _nvd_cache_lock:
        cache = _nvd_cache_load()
        hit = cache.get(cve)
        if isinstance(hit, dict) and (now - hit.get("ts", 0)) < ttl:
            return (hit.get("data") or None), False

    # rate limit: NVD allows ~5 requests / 30s without a key, 50 with one
    gap = 0.6 if os.environ.get("CTI_NVD_API_KEY") else 6.0
    with _nvd_cache_lock:
        wait = _nvd_last_call + gap - now
        if wait > 0:
            time.sleep(min(wait, gap))
        _nvd_last_call = time.time()

    data = _http_get_json(_NVD_API + cve, headers=_nvd_headers())
    out = None
    try:
        item = ((data or {}).get("vulnerabilities") or [{}])[0].get("cve") or {}
        for metric in ("cvssMetricV31", "cvssMetricV30"):
            ms = item.get(metric) or []
            if ms:
                cd = ms[0].get("cvssData") or {}
                summary = ""
                for d in item.get("descriptions") or []:
                    if d.get("lang") == "en":
                        summary = str(d.get("value", ""))[:400]
                        break
                out = {"cvss": cd.get("baseScore"), "vector": cd.get("vectorString"),
                       "summary": summary}
                break
    except Exception:
        out = None
    with _nvd_cache_lock:
        _nvd_cache_store({cve: {"ts": time.time(), "data": out}})
    return out, True


def _nvd_headers():
    key = os.environ.get("CTI_NVD_API_KEY")
    if not key:
        return []
    return ["apiKey: " + key]


def nvd_enrich_hosts(snippets, cap, on_progress=None):
    """Enrich the CVEs matched across all host snippets, up to `cap` lookups.

    Returns {cve_id: {cvss, vector, summary}}. Only network lookups count
    against the cap — cache hits are free. Never raises.
    """
    out = {}
    try:
        cves = []
        for s in (snippets or {}).values():
            for m in match_cves((s or {}).get("versions") or []):
                if m["cve"] not in cves and m["cve"] not in out:
                    cves.append(m["cve"])
        lookups = 0
        for cve in cves:
            if lookups >= cap:
                break
            data, network_used = nvd_lookup(cve)
            lookups += 1 if network_used else 0
            if data:
                out[cve] = data
        return out
    except Exception:
        return out
