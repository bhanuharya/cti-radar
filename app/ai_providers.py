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
import sys
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

_USER_AGENT = "cti-radar/1.0 (urllib)"

# Optional log hook so the web backend can route AI diagnostics into the
# persisted runtime log (JSONL) + in-memory ring. Falls back to stderr.
_LOG_HOOK = None


def set_log_hook(fn):
    """Install a logger: fn(level, message, meta_dict_or_None)."""
    global _LOG_HOOK
    _LOG_HOOK = fn


def _log(level, message, meta=None):
    try:
        if _LOG_HOOK is not None:
            _LOG_HOOK(level, message, meta)
            return
    except Exception:
        pass
    print(f"[ai:{level}] {message}", file=sys.stderr)


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
                "max_hosts": 10,
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
            max_hosts = int(p.get("max_hosts", 10) or 10)
        except Exception:
            max_hosts = 10
        max_hosts = max(1, min(max_hosts, 50))
        # generation cap (output tokens). Reasoning-style models burn the cap
        # on hidden reasoning and return empty content — a profile can raise
        # its budget explicitly instead of failing every call.
        try:
            max_tokens = int(p.get("max_tokens", 1024) or 1024)
        except Exception:
            max_tokens = 1024
        max_tokens = max(64, min(max_tokens, 8192))
        options = dict(p.get("options")) if isinstance(p.get("options"), dict) else {}
        # ollama spells the same knob num_predict; accept it at profile level
        try:
            np_ = int(p.get("num_predict", 0) or 0)
            if np_:
                options["num_predict"] = max(64, min(np_, 8192))
        except Exception:
            pass
        norm[name] = {
            "provider": provider,
            "base_url": base_url,
            "model": model,
            "api_key_env": api_key_env_raw,
            "timeout": timeout,
            "max_hosts": max_hosts,
            "max_tokens": max_tokens,
            # opt-out for the one-shot cap-exhaustion retry (see
            # _call_openai_compatible): max_tokens is per-request; the retry
            # may add ONE extra request at min(2x cap, 8192)
            "cap_retry": bool(p.get("cap_retry", True)),
            "options": options,
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


def _read_http_error_body(e):
    """Best-effort body read from an urllib HTTPError (size-limited)."""
    try:
        return (e.read(1000) or b"").decode(errors="replace")
    except Exception:
        return ""


def _extract_openai_content_reasoning(d):
    """Return (content, reasoning) from an OpenAI-compatible response dict.

    Handles both the standard shape ``{"choices": [...]}`` and the cline.bot
    wrapper ``{"data": {"choices": [...]}}``. Reasoning is read from
    ``reasoning`` / ``reasoning_content`` / ``reasoning_details[]`` fields and
    from array-style ``content`` parts.
    """
    if not isinstance(d, dict):
        return None, None
    choices = d.get("choices")
    if not isinstance(choices, list):
        data = d.get("data")
        if isinstance(data, dict):
            choices = data.get("choices")
    if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
        return None, None
    first = choices[0]
    msg = first.get("message") if isinstance(first.get("message"), dict) else {}
    content = msg.get("content")
    if isinstance(content, list):
        parts = []
        for p in content:
            if isinstance(p, dict):
                t = p.get("text")
                if isinstance(t, str) and t.strip():
                    parts.append(t.strip())
            elif isinstance(p, str) and p.strip():
                parts.append(p.strip())
        content = "\n".join(parts) if parts else None
    if content is not None and not isinstance(content, str):
        content = str(content)
    if isinstance(content, str):
        content = content.strip() or None
    reasoning = None
    for key in ("reasoning", "reasoning_content"):
        v = msg.get(key)
        if isinstance(v, str) and v.strip():
            reasoning = v.strip()
            break
    if reasoning is None:
        rd = msg.get("reasoning_details")
        if not isinstance(rd, list):
            rd = first.get("reasoning_details")
        if isinstance(rd, list):
            texts = []
            for item in rd:
                if isinstance(item, dict):
                    t = item.get("text") or item.get("content")
                    if isinstance(t, str) and t.strip():
                        texts.append(t.strip())
            if texts:
                reasoning = "\n".join(texts)
    return content, reasoning


def _call_ollama(base_url: str, model: str, prompt: str, timeout: int, options: dict):
    """Call Ollama. Returns (content, reasoning, diagnostics).

    Uses Ollama's native ``format: "json"`` (structured JSON mode) and a bounded
    ``num_predict`` ceiling so cheap models stay fast and well-formed. User
    profile ``options`` may override either.
    """
    url = base_url.rstrip("/") + "/api/chat"
    body = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "stream": False,
        "format": "json",
        "options": {"temperature": 0, "num_predict": 1024, **(options or {})},
    }
    data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("User-Agent", _USER_AGENT)
    try:
        with _urlopen_no_redirect(req, timeout=timeout) as r:
            resp_bytes = _limited_read(r)
            d = json.loads(resp_bytes.decode(errors="replace") or "{}")
        status = getattr(r, "status", None)
        msg = d.get("message", {}) if isinstance(d, dict) else {}
        content = msg.get("content")
        reasoning = msg.get("thinking") or msg.get("reasoning")
        if isinstance(reasoning, str) and not reasoning.strip():
            reasoning = None
        # fallback: some ollama wrappers return choices
        if not content:
            choices = d.get("choices") or []
            if choices and isinstance(choices[0], dict):
                content = choices[0].get("message", {}).get("content")
        if content is not None and not isinstance(content, str):
            content = str(content)
        if isinstance(content, str):
            content = content.strip() or None
        if content:
            _log("info", f"AI provider responded ({model}): {len(content)} chars"
                 + (f", reasoning {len(reasoning)} chars" if reasoning else ""))
            return content, (reasoning[:2000] if isinstance(reasoning, str) else None), {"status": status or 200}
        _log("warn", f"AI provider returned no content ({model})",
             {"body_excerpt": resp_bytes[:1000].decode(errors="replace")})
        return None, None, {"status": status or 200, "response_excerpt": resp_bytes[:1000].decode(errors="replace")}
    except urllib.error.HTTPError as e:
        body = _read_http_error_body(e)
        _log("error", f"AI provider HTTP {e.code} for {model}: {body[:300]}")
        return None, None, {"status": e.code, "error": f"HTTP {e.code}", "response_excerpt": body[:500]}
    except Exception as e:
        _log("error", f"AI provider request failed for {model}: {type(e).__name__}: {e}")
        return None, None, {"error": f"{type(e).__name__}: {e}"}


def _call_openai_compatible(base_url: str, model: str, prompt: str, timeout: int,
                            api_key_env: Optional[str], max_tokens: int = 1024,
                            cap_retry: bool = True):
    """Call an OpenAI-compatible endpoint. Returns (content, reasoning, diagnostics).

    Requests structured JSON output (``response_format: json_object``) and caps
    ``max_tokens`` so cheap models stay bounded. Endpoints that reject the
    ``response_format`` field are retried once without it. A response whose
    completion budget was consumed entirely by hidden reasoning (empty content,
    ``finish_reason`` null/length, ``completion_tokens`` at the cap) is retried
    once with a doubled cap — that is the classic failure signature of
    reasoning models (muse-spark, GLM) behind a small cap.
    """
    key = os.environ.get(api_key_env or "", "") if api_key_env else ""
    # allow no key for local openai-compatible (e.g., vLLM without auth)
    url = base_url.rstrip("/") + "/chat/completions"
    # If api_key_env is set but missing, fail gracefully (return None -> fallback)
    if api_key_env and not key:
        _log("warn", f"AI profile {model} requires {api_key_env} but it is not set")
        return None, None, {"error": f"missing API key ({api_key_env})"}
    cap = max(64, min(int(max_tokens or 1024), 8192))

    def _post(payload):
        data = json.dumps(payload).encode()
        req = urllib.request.Request(url, data=data, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("User-Agent", _USER_AGENT)
        if key:
            req.add_header("Authorization", "Bearer " + key)
        with _urlopen_no_redirect(req, timeout=timeout) as r:
            resp_bytes = _limited_read(r)
            status = getattr(r, "status", None)
            return status, resp_bytes

    def _payload(tok_cap):
        p = {"model": model, "messages": [{"role": "user", "content": prompt}],
             "temperature": 0, "max_tokens": tok_cap}
        return p

    base_payload = _payload(cap)
    with_format = dict(base_payload)
    with_format["response_format"] = {"type": "json_object"}

    def _finish(d, tok_cap, retried_cap=None):
        """Extract + classify. Returns (content, reasoning_out, diag)."""
        content, reasoning = _extract_openai_content_reasoning(d)
        reasoning_out = reasoning[:2000] if reasoning else None
        diag = {"status": status or 200}
        if retried_cap:
            diag["retried_with_cap"] = retried_cap
        if content:
            _log("info", f"AI provider responded ({model}): {len(content)} chars"
                 + (f", reasoning {len(reasoning)} chars" if reasoning else ""))
            return content, reasoning_out, diag
        # empty content — classify WHY (token cap exhausted by reasoning?)
        usage = d.get("usage") if isinstance(d, dict) else None
        comp = int(usage.get("completion_tokens") or 0) if isinstance(usage, dict) else 0
        finish = None
        choices = d.get("choices") if isinstance(d, dict) else None
        if isinstance(choices, list) and choices and isinstance(choices[0], dict):
            finish = choices[0].get("finish_reason")
        if comp >= tok_cap * 0.98 and finish in (None, "length"):
            diag["reason"] = "token_cap_exhausted"
            _log("warn", f"AI provider token cap exhausted by reasoning ({model}): "
                         f"{comp} completion tokens at cap {tok_cap}, no content")
        else:
            _log("warn", f"AI provider returned no content ({model})",
                 {"body_excerpt": resp_bytes[:1000].decode(errors="replace")})
            diag["response_excerpt"] = resp_bytes[:1000].decode(errors="replace")
        return None, reasoning_out, diag

    status, resp_bytes = None, b""
    try:
        status, resp_bytes = _post(with_format)
    except urllib.error.HTTPError as e:
        status = e.code
        resp_bytes = b""
        if e.code in (400, 404, 406, 415, 422, 500, 501):
            # Some OpenAI-compatible endpoints reject response_format (or
            # intermittently 500 on zen/go). Retry once without it.
            try:
                status, resp_bytes = _post(base_payload)
            except urllib.error.HTTPError as e2:
                body = _read_http_error_body(e2)
                _log("error", f"AI provider HTTP {e2.code} for {model}: {body[:300]}")
                return None, None, {"status": e2.code, "error": f"HTTP {e2.code}", "response_excerpt": body[:500]}
        else:
            body = _read_http_error_body(e)
            _log("error", f"AI provider HTTP {e.code} for {model}: {body[:300]}")
            return None, None, {"status": e.code, "error": f"HTTP {e.code}", "response_excerpt": body[:500]}
    except Exception as e:
        _log("error", f"AI provider request failed for {model}: {type(e).__name__}: {e}")
        return None, None, {"error": f"{type(e).__name__}: {e}"}

    try:
        d = json.loads(resp_bytes.decode(errors="replace") or "{}")
    except Exception:
        d = {}
    content, reasoning_out, diag = _finish(d, cap)
    if content is None and diag.get("reason") == "token_cap_exhausted" and cap_retry:
        # at most ONE extra request, only when the budget can actually grow
        # (a capped-at-8192 profile has no headroom — a duplicate request
        # would just double the spend), and only when the profile allows it.
        # max_tokens is the PER-REQUEST cap; this retry is the only place
        # total spend can exceed it, by at most one request.
        retry_cap = min(cap * 2, 8192)
        if retry_cap > cap:
            try:
                # keep structured output if the endpoint accepted it
                retry_fmt = dict(_payload(retry_cap))
                retry_fmt["response_format"] = {"type": "json_object"}
                try:
                    status, resp_bytes = _post(retry_fmt)
                except urllib.error.HTTPError as e:
                    if e.code in (400, 404, 406, 415, 422, 500, 501):
                        status, resp_bytes = _post(_payload(retry_cap))
                    else:
                        raise
                try:
                    d2 = json.loads(resp_bytes.decode(errors="replace") or "{}")
                except Exception:
                    d2 = {}
                content, reasoning_out, diag = _finish(d2, retry_cap, retried_cap=retry_cap)
            except Exception as e:
                _log("warn", f"AI provider cap-retry failed for {model}: {type(e).__name__}: {e}")
        else:
            _log("debug", f"AI provider cap retry skipped for {model}: "
                          f"cap {cap} already at ceiling, no headroom")
    return content, reasoning_out, diag


def call_ai(prompt: str, profile_name: Optional[str] = None) -> Tuple[Optional[str], Optional[dict]]:
    """Call configured AI profile. Returns (content_str or None, provenance dict or None)."""
    profiles, default = load_profiles()
    name = profile_name or default
    if not name or name not in profiles:
        return None, None
    prof = profiles[name]
    provider = prof["provider"]
    content = None
    reasoning = None
    diag = {}
    if provider == "ollama":
        content, reasoning, diag = _call_ollama(prof["base_url"], prof["model"], prompt, prof["timeout"], prof["options"])
    elif provider == "openai-compatible":
        content, reasoning, diag = _call_openai_compatible(
            prof["base_url"], prof["model"], prompt, prof["timeout"],
            prof["api_key_env"], max_tokens=prof.get("max_tokens", 1024),
            cap_retry=prof.get("cap_retry", True))
    provenance = {
        "profile": name,
        "provider": provider,
        "model": prof["model"],
        "prompt_version": PROMPT_VERSION,
    }
    if diag:
        provenance.update({k: v for k, v in diag.items() if v is not None})
    if reasoning:
        provenance["reasoning"] = reasoning[:2000]
    if content is None:
        return None, provenance
    # keep a bounded excerpt so operators can see model reasoning/JSON in logs
    # and history even when a provider folds reasoning into `content`.
    provenance["content_excerpt"] = content[:1000]
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

def strip_json_fences(raw):
    """Remove markdown code fences so json.loads sees the payload directly.

    Models frequently wrap JSON in ```json ... ``` or leave a stray opening
    fence; previously the first parse attempt failed on such output and the
    fallback bracket-slicing only rescued array-shaped payloads.
    """
    if not isinstance(raw, str):
        return ""
    s = raw.strip()
    m = re.match(r"^```[a-zA-Z0-9_-]*[ \t]*\r?\n?(.*?)\r?\n?[ \t]*```$",
                 s, re.S)
    if m:
        return m.group(1).strip()
    if s.startswith("```"):
        s = re.sub(r"^```[a-zA-Z0-9_-]*[ \t]*\r?\n?", "", s)
    if s.endswith("```"):
        s = s[:-3].rstrip()
    return s.strip()


def salvage_result_objects(raw, max_items=64):
    """Best-effort recovery of individual result objects from truncated JSON.

    A weak model that streams a verdict array can get cut off mid-item (cap,
    timeout, connection drop). Instead of losing the whole batch, scan for
    balanced {...} objects with raw_decode and return whatever parses.
    Per-item semantic validation stays with the caller — this only recovers
    syntax. Returns [] when nothing parses.
    """
    if not isinstance(raw, str) or not raw.strip():
        return []
    s = strip_json_fences(raw)
    dec = json.JSONDecoder()
    out = []
    i = 0
    while i < len(s) and len(out) < max_items:
        j = s.find("{", i)
        if j == -1:
            break
        try:
            obj, end = dec.raw_decode(s, j)
            if isinstance(obj, dict):
                out.append(obj)
            i = end
        except ValueError:
            i = j + 1  # unbalanced/truncated object — keep scanning
    return out


def parse_ai_response(raw: str, allowed_targets: set) -> Optional[List[dict]]:
    """Extract and validate AI response. Supports both array and {findings:[]} shapes."""
    if not raw:
        return None
    # Try to find JSON object/array. Prefer object with findings, fallback to array.
    raw = strip_json_fences(raw)
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
