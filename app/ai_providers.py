"""ai_providers.py — configurable AI provider layer.

Supports two providers:
  - ollama (native): POST {base_url}/api/chat {model, messages, stream:false}
  - openai-compatible: POST {base_url}/chat/completions {model, messages, temperature:0}

Global profiles live in data/ai_config.json (or CTI_AI_CONFIG JSON / CTI_AI_CONFIG_FILE).
Secrets are referenced via env names (api_key_env) — never stored in the JSON.

Per-org selection is stored as `ai_profile` in data/orgs.json (server-managed).
Capabilities endpoint exposes only safe fields (no base_url/secrets).
"""
import ipaddress
import json
import os
import re
import tempfile
import threading
import time
import urllib.error
import urllib.parse as _urlparse
import urllib.request
from typing import Dict, List, Optional, Tuple

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_ROOT = os.path.abspath(os.path.expanduser(
    os.environ.get("CTI_DATA_DIR", os.path.join(BASE, "data"))))
DEFAULT_CONFIG_PATH = os.path.join(DATA_ROOT, "ai_config.json")
ORG_PROFILES_PATH = os.path.join(DATA_ROOT, "ai_org_profiles.json")

VALID_PROVIDERS = ("ollama", "openai-compatible")
SEVERITY_ALLOWED = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
PROMPT_VERSION = "cti-v1"

_ALLOWED_API_KEY_RE = re.compile(r"^(CTI_AI_[A-Z0-9_]+|OPENCODE_GO_B_API_KEY|OPENROUTER_API_KEY|[A-Z][A-Z0-9_]*_API_KEY)$")


def _is_loopback_host(host: str) -> bool:
    h = host.lower()
    if h in ("localhost", "127.0.0.1", "::1"):
        return True
    try:
        ip = ipaddress.ip_address(h)
        return ip.is_loopback
    except Exception:
        return False


def _dns_resolves_to_private(hostname: str) -> bool:
    """Check if a hostname resolves to any private/non-global address.
    Returns True if ANY resolved address is private (DNS rebinding risk).
    Returns True (block) on DNS resolution failure — fail closed for safety."""
    import socket
    infos = None
    try:
        infos = socket.getaddrinfo(hostname, None)
    except Exception:
        return True
    if not infos:
        return True
    for info in infos:
        ip_str = info[4][0]
        try:
            ip = ipaddress.ip_address(ip_str)
            if not ip.is_global:
                return True
        except Exception:
            return True
    return False


def _validate_base_url(base_url: str, provider: str, api_key_env: Optional[str]) -> bool:
    try:
        parsed = _urlparse.urlsplit(base_url)
        if parsed.scheme not in ("https", "http"):
            return False
        if not parsed.hostname:
            return False
        if parsed.username or parsed.password:
            return False
        if parsed.fragment:
            return False
        # http only allowed for loopback ollama/local
        if parsed.scheme == "http":
            if not _is_loopback_host(parsed.hostname):
                return False
        # https required when api_key present and not loopback
        if api_key_env and parsed.scheme != "https" and not _is_loopback_host(parsed.hostname):
            return False
        # hostname must be valid, not private metadata IP 169.254.169.254 etc
        try:
            ip = ipaddress.ip_address(parsed.hostname)
            # disallow private, link-local, multicast, reserved, unspecified
            if not ip.is_global and not ip.is_loopback:
                return False
        except Exception:
            # hostname, not IP — check not metadata-like, then DNS-resolve
            if parsed.hostname == "169.254.169.254":
                return False
            # DNS rebinding: reject if hostname resolves to any private address
            if not _is_loopback_host(parsed.hostname):
                if _dns_resolves_to_private(parsed.hostname):
                    return False
        # port must be numeric if present
        if parsed.port is not None and not (1 <= parsed.port <= 65535):
            return False
        return True
    except Exception:
        return False


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(newurl, code, "redirect blocked", headers, fp)


def _urlopen_no_redirect(req, timeout):
    # Disable proxy inheritance from environment to prevent SSRF via proxy
    proxy_handler = urllib.request.ProxyHandler({})
    opener = urllib.request.build_opener(_NoRedirect, proxy_handler)
    return opener.open(req, timeout=timeout)

# ---------------------------------------------------------------------------
# config loading
# ---------------------------------------------------------------------------
def _load_raw_config() -> dict:
    # 1. env JSON
    env_json = os.environ.get("CTI_AI_CONFIG", "").strip()
    if env_json:
        try:
            d = json.loads(env_json)
            if isinstance(d, dict):
                return d
        except Exception:
            pass
    # 2. file path from env or default
    cfg_path = os.environ.get("CTI_AI_CONFIG_FILE", DEFAULT_CONFIG_PATH)
    if os.path.exists(cfg_path):
        try:
            with open(cfg_path) as f:
                d = json.load(f)
            if isinstance(d, dict):
                return d
        except Exception:
            pass
    return {}

def _build_default_config() -> dict:
    """If OPENCODE_GO_B_API_KEY is set and no config exists, provide compat profile."""
    key = os.environ.get("OPENCODE_GO_B_API_KEY", "").strip()
    if not key:
        return {"default_profile": None, "profiles": {}}
    return {
        "default_profile": "opencode",
        "profiles": {
            "opencode": {
                "provider": "openai-compatible",
                "base_url": "https://opencode.ai/zen/go/v1",
                "model": "muse-spark-1.2-contributor",
                "api_key_env": "OPENCODE_GO_B_API_KEY",
                "timeout": 90,
                "max_hosts": 25,
            }
        }
    }

def load_profiles() -> Tuple[Dict[str, dict], Optional[str]]:
    """Return (profiles dict, default_profile name). Normalized."""
    raw = _load_raw_config()
    if not raw or not raw.get("profiles"):
        # fall back to legacy env compat
        raw = _build_default_config()
    profiles = raw.get("profiles") or {}
    default = raw.get("default_profile")
    # normalize each profile
    norm: Dict[str, dict] = {}
    for name, p in profiles.items():
        if not isinstance(p, dict):
            continue
        provider = str(p.get("provider", "")).strip().lower()
        if provider not in VALID_PROVIDERS:
            continue
        base_url = str(p.get("base_url") or p.get("endpoint") or "").strip().rstrip("/")
        model = str(p.get("model", "")).strip()
        if not base_url or not model:
            continue
        api_key_env_raw = str(p.get("api_key_env", "")).strip() or None
        if api_key_env_raw and not _ALLOWED_API_KEY_RE.match(api_key_env_raw):
            continue
        if not _validate_base_url(base_url, provider, api_key_env_raw):
            continue
        try:
            timeout = int(p.get("timeout", 90) or 90)
        except Exception:
            timeout = 90
        timeout = max(10, min(timeout, 300))
        try:
            max_hosts = int(p.get("max_hosts", 25) or 25)
        except Exception:
            max_hosts = 25
        max_hosts = max(1, min(max_hosts, 50))
        norm[name] = {
            "provider": provider,
            "base_url": base_url,
            "model": model,
            "api_key_env": api_key_env_raw,
            "timeout": timeout,
            "max_hosts": max_hosts,
            "options": p.get("options") if isinstance(p.get("options"), dict) else {},
        }
    # validate default
    if default not in norm:
        default = next(iter(norm), None) if norm else None
    return norm, default

# ---------------------------------------------------------------------------
# provider calls
# ---------------------------------------------------------------------------
def _limited_read(resp, limit=262144) -> bytes:
    # honor Content-Length if present, otherwise read limited
    try:
        cl = resp.headers.get("Content-Length") if hasattr(resp, "headers") else None
        if cl and int(cl) > limit:
            return b""
    except Exception:
        pass
    try:
        data = resp.read(limit + 1)
        if len(data) > limit:
            return b""
        return data
    except Exception:
        return b""


def _call_ollama(base_url: str, model: str, prompt: str, timeout: int, options: dict) -> Optional[str]:
    url = base_url.rstrip("/") + "/api/chat"
    body = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "stream": False,
        "options": {"temperature": 0, **(options or {})},
    }
    data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    try:
        with _urlopen_no_redirect(req, timeout=timeout) as r:
            d = json.loads(_limited_read(r).decode() or "{}")
        # Ollama returns {"message": {"content": "..."}, "done": true}
        msg = d.get("message", {}) if isinstance(d, dict) else {}
        content = msg.get("content")
        if content:
            return str(content)
        # fallback: some ollama wrappers return choices
        choices = d.get("choices") or []
        if choices and isinstance(choices[0], dict):
            return choices[0].get("message", {}).get("content")
        return None
    except Exception:
        return None

def _call_openai_compatible(base_url: str, model: str, prompt: str, timeout: int, api_key_env: Optional[str]) -> Optional[str]:
    key = os.environ.get(api_key_env or "", "") if api_key_env else ""
    # allow no key for local openai-compatible (e.g., vLLM without auth)
    url = base_url.rstrip("/") + "/chat/completions"
    body = {"model": model, "messages": [{"role": "user", "content": prompt}], "temperature": 0}
    data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    if key:
        req.add_header("Authorization", "Bearer " + key)
    # If api_key_env is set but missing, fail gracefully (return None -> fallback)
    if api_key_env and not key:
        return None
    try:
        with _urlopen_no_redirect(req, timeout=timeout) as r:
            d = json.loads(_limited_read(r).decode() or "{}")
        return (d.get("choices") or [{}])[0].get("message", {}).get("content") or None
    except Exception:
        return None

def call_ai(prompt: str, profile_name: Optional[str] = None) -> Tuple[Optional[str], Optional[dict]]:
    """Call configured AI profile. Returns (content_str or None, provenance dict or None)."""
    profiles, default = load_profiles()
    name = profile_name or default
    if not name or name not in profiles:
        return None, None
    prof = profiles[name]
    provider = prof["provider"]
    content = None
    if provider == "ollama":
        content = _call_ollama(prof["base_url"], prof["model"], prompt, prof["timeout"], prof["options"])
    elif provider == "openai-compatible":
        content = _call_openai_compatible(prof["base_url"], prof["model"], prompt, prof["timeout"], prof["api_key_env"])
    provenance = {
        "profile": name,
        "provider": provider,
        "model": prof["model"],
        "prompt_version": PROMPT_VERSION,
    }
    if content is None:
        return None, provenance
    return content, provenance

# ---------------------------------------------------------------------------
# validation helpers
# ---------------------------------------------------------------------------
def _normalize_severity(v) -> Optional[str]:
    s = str(v or "").strip().upper()
    return s if s in SEVERITY_ALLOWED else None

def validate_ai_finding(obj: dict, allowed_targets: set) -> Optional[dict]:
    """Strict validation + normalization. Returns cleaned dict or None."""
    if not isinstance(obj, dict):
        return None
    target = str(obj.get("target", "")).strip()
    title = str(obj.get("title", "")).strip()
    if not target or not title:
        return None
    # target must be in allowed fingerprints (case-insensitive)
    if allowed_targets and target.lower() not in {t.lower() for t in allowed_targets}:
        return None
    # basic hostname sanity (no path, no scheme)
    if re.search(r"[\\/\s?#]", target):
        return None
    severity = _normalize_severity(obj.get("severity"))
    if not severity:
        return None
    category = str(obj.get("category", "")).strip()[:80]
    if not category:
        category = "AI assessment"
    description = str(obj.get("description", "")).strip()
    impact = str(obj.get("impact", "")).strip()
    evidence = obj.get("evidence")
    # evidence: allow string or dict, normalize to string[:1000] or dict with string values
    if isinstance(evidence, dict):
        # cap each value
        ev = {str(k)[:40]: str(v)[:500] for k, v in list(evidence.items())[:10]}
    else:
        ev = str(evidence or "").strip()[:1000]
        if not ev:
            ev = description[:500] if description else ""
    remediation = obj.get("remediation")
    if isinstance(remediation, list):
        remediation = "; ".join(str(x).strip() for x in remediation if str(x).strip())[:1000]
    else:
        remediation = str(remediation or "").strip()[:1000]
    # related_cves: must be valid CVE IDs only
    raw_cves = obj.get("related_cves") or []
    if isinstance(raw_cves, str):
        raw_cves = [raw_cves]
    cves: List[str] = []
    if isinstance(raw_cves, list):
        for c in raw_cves:
            cc = str(c).strip().upper()
            if CVE_RE.match(cc) and cc not in cves:
                cves.append(cc)
    # caps
    title = title[:200]
    description = description[:2000]
    impact = impact[:2000]
    if not description or not impact:
        return None
    return {
        "target": target,
        "title": title,
        "severity": severity,
        "category": category,
        "description": description,
        "impact": impact,
        "evidence": ev,
        "remediation": remediation,
        "related_cves": cves,
    }

def parse_ai_response(raw: str, allowed_targets: set) -> Optional[List[dict]]:
    """Extract and validate AI response. Supports both array and {findings:[]} shapes."""
    if not raw:
        return None
    # Try to find JSON object/array. Prefer object with findings, fallback to array.
    raw = raw.strip()
    # 1. Try full JSON parse
    try:
        d = json.loads(raw)
        if isinstance(d, dict) and isinstance(d.get("findings"), list):
            arr = d["findings"]
        elif isinstance(d, list):
            arr = d
        else:
            # 2. Extract substring
            arr = None
            # look for {"findings": [ ... ]} or [ ... ]
            start_obj = raw.find('{"findings"')
            if start_obj != -1:
                # find matching bracket for findings array
                s = raw.find("[", start_obj)
                e = raw.rfind("]")
                if s != -1 and e != -1 and e > s:
                    try:
                        arr = json.loads(raw[s:e+1])
                    except Exception:
                        arr = None
            if arr is None:
                s, e = raw.find("["), raw.rfind("]")
                if s != -1 and e != -1 and e > s:
                    try:
                        arr = json.loads(raw[s:e+1])
                    except Exception:
                        return None
                else:
                    return None
        if not isinstance(arr, list):
            return None
        if len(arr) > 50:
            arr = arr[:50]
        out: List[dict] = []
        for item in arr:
            if len(out) >= 25:
                break
            cleaned = validate_ai_finding(item, allowed_targets)
            if cleaned:
                out.append(cleaned)
        return out
    except Exception:
        return None

def get_capabilities() -> dict:
    """Safe public view: no secrets, no base_urls."""
    profiles, default = load_profiles()
    caps = []
    for name, p in profiles.items():
        # readiness: openai-compatible requires api_key_env present if set
        ready = True
        if p["provider"] == "openai-compatible" and p["api_key_env"]:
            if not os.environ.get(p["api_key_env"], "").strip():
                ready = False
        caps.append({
            "name": name,
            "provider": p["provider"],
            "model": p["model"],
            "timeout": p["timeout"],
            "max_hosts": p["max_hosts"],
            "ready": ready,
            "default": name == default,
        })
    return {"default_profile": default, "profiles": caps, "prompt_version": PROMPT_VERSION}

_org_profiles_lock = threading.Lock()

def _load_org_profile_map() -> dict:
    try:
        if os.path.exists(ORG_PROFILES_PATH):
            with open(ORG_PROFILES_PATH) as f:
                d = json.load(f)
            return d if isinstance(d, dict) else {}
    except Exception:
        pass
    return {}


def resolve_profile_for_org(slug: str, override: Optional[str] = None) -> Optional[str]:
    """Resolve effective profile for an org: override > org's ai_profile > default."""
    profiles, default = load_profiles()
    if override and override in profiles:
        return override
    if slug:
        # 1. ignored runtime file (preferred, does not dirty tracked registry)
        try:
            m = _load_org_profile_map()
            pref = str(m.get(slug) or "").strip()
            if pref in profiles:
                return pref
        except Exception:
            pass
        # 2. fallback to legacy orgs.json ai_profile (backwards compat)
        try:
            reg_path = os.path.join(DATA_ROOT, "orgs.json")
            if os.path.exists(reg_path):
                with open(reg_path) as f:
                    reg = json.load(f)
                entry = reg.get(slug) if isinstance(reg, dict) else None
                if isinstance(entry, dict):
                    pref = str(entry.get("ai_profile") or "").strip()
                    if pref in profiles:
                        return pref
        except Exception:
            pass
    return default


def set_org_profile(slug: str, profile: str) -> None:
    """Persist per-org profile to ignored runtime file atomically (locked, unique tmp)."""
    import tempfile
    with _org_profiles_lock:
        m = _load_org_profile_map()
        if profile:
            m[slug] = profile
        else:
            m.pop(slug, None)
        # use unique tmp to avoid collision
        dirn = os.path.dirname(ORG_PROFILES_PATH) or "."
        os.makedirs(dirn, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=dirn, prefix=".ai_org_profiles.")
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(m, f, indent=2)
                f.write("\n")
            os.replace(tmp, ORG_PROFILES_PATH)
        finally:
            try:
                os.remove(tmp)
            except Exception:
                pass


def get_org_profile(slug: str) -> Optional[str]:
    return _load_org_profile_map().get(slug)

def is_ai_configured() -> bool:
    profiles, _ = load_profiles()
    return bool(profiles)
