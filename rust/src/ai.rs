//! AI provider abstraction — ollama + openai-compatible, SSRF-validated.
//! Port of `ai_providers.py`. Fail-open: any provider/parse failure returns
//! None, never blocks the deterministic scan.

use futures::FutureExt;
use once_cell::sync::OnceCell;
use regex::Regex;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::IpAddr;

const VALID_PROVIDERS: [&str; 2] = ["ollama", "openai-compatible"];

/// Prompt template version advertised via `get_capabilities` (parity with Python).
pub const PROMPT_VERSION: &str = "cti-v1";

fn data_root() -> String {
    std::env::var("CTI_DATA_DIR")
        .map(|d| d.trim_end_matches('/').to_string())
        .unwrap_or_else(|_| "data".to_string())
}

fn org_profiles_path() -> String {
    format!("{}/ai_org_profiles.json", data_root())
}

async fn load_org_profile_map() -> HashMap<String, String> {
    let path = org_profiles_path();
    tokio::fs::read_to_string(&path)
        .await
        .ok()
        .and_then(|txt| serde_json::from_str::<Value>(&txt).ok())
        .and_then(|v| v.as_object().cloned())
        .map(|o| {
            o.into_iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k, s.to_string())))
                .collect()
        })
        .unwrap_or_default()
}

/// Preferred per-org profile from the ignored runtime file (parity with Python
/// `get_org_profile`). Returns None when unset.
pub async fn get_org_profile(slug: &str) -> Option<String> {
    load_org_profile_map()
        .await
        .get(slug)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Persist a per-org profile preference to the ignored runtime file
/// (atomic; empty clears). Parity with Python `set_org_profile`.
pub async fn set_org_profile(slug: &str, profile: &str) {
    let mut m = load_org_profile_map().await;
    if profile.trim().is_empty() {
        m.remove(slug);
    } else {
        m.insert(slug.to_string(), profile.trim().to_string());
    }
    let mut obj = serde_json::Map::new();
    for (k, v) in m {
        obj.insert(k, Value::String(v));
    }
    let _ = crate::correlation::atomic_write_json(
        &std::path::PathBuf::from(org_profiles_path()),
        &Value::Object(obj),
    )
    .await;
}

fn allowed_api_key_re() -> &'static Regex {
    static RE: OnceCell<Regex> = OnceCell::new();
    RE.get_or_init(|| Regex::new(r"^[A-Za-z_][A-Za-z0-9_]*$").unwrap())
}

fn is_loopback_host(host: &str) -> bool {
    // parity with Python `_is_loopback_host` (case-insensitive)
    let h = host.to_lowercase();
    if h == "localhost" {
        return true;
    }
    match h.parse::<IpAddr>() {
        Ok(ip) => ip.is_loopback(),
        Err(_) => false,
    }
}

/// Global-reachability check — exact CPython `ip.is_global` semantics.
fn is_global_ip(ip: &IpAddr) -> bool {
    crate::net::is_global_ip(&ip.to_string())
}

/// DNS rebinding guard via the shared hickory resolver: reject hostnames
/// resolving to any non-global address. Fail-CLOSED on resolution failure
/// (parity with Python `_dns_resolves_to_private`).
async fn dns_resolves_to_private(hostname: &str) -> bool {
    match crate::scanner::dns_resolver().lookup_ip(hostname).await {
        Ok(lookup) => {
            let mut any = false;
            for ip in lookup.iter() {
                any = true;
                if !is_global_ip(&ip) {
                    return true;
                }
            }
            // empty answer = unresolvable -> block (fail closed)
            !any
        }
        Err(_) => true,
    }
}

/// Validate an AI provider base URL — pure syntactic checks only (no DNS).
/// Unit-test entry point; production validation MUST use
/// [`validate_base_url_live`], which adds the DNS-rebinding check.
pub fn validate_base_url(base_url: &str, provider: &str, api_key_env: Option<&str>) -> bool {
    validate_base_url_inner(base_url, provider, api_key_env, false)
        .now_or_never()
        .unwrap_or(false)
}

/// Full validation incl. async DNS-rebinding check via the shared hickory
/// resolver (SSRF protections mirror the Python).
pub async fn validate_base_url_live(
    base_url: &str,
    provider: &str,
    api_key_env: Option<&str>,
) -> bool {
    validate_base_url_inner(base_url, provider, api_key_env, true).await
}

async fn validate_base_url_inner(
    base_url: &str,
    provider: &str,
    api_key_env: Option<&str>,
    check_dns: bool,
) -> bool {
    let parsed = match url::Url::parse(base_url) {
        Ok(p) => p,
        Err(_) => return false,
    };
    if !matches!(parsed.scheme(), "https" | "http") {
        return false;
    }
    let host = match parsed.host_str() {
        Some(h) => h,
        None => return false,
    };
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return false;
    }
    if parsed.fragment().is_some() {
        return false;
    }
    // http only for loopback (ollama local)
    if parsed.scheme() == "http" && !is_loopback_host(host) {
        return false;
    }
    if api_key_env.is_some() && parsed.scheme() != "https" && !is_loopback_host(host) {
        return false;
    }
    match host.parse::<IpAddr>() {
        Ok(ip) => {
            if !is_global_ip(&ip) && !ip.is_loopback() {
                return false;
            }
        }
        Err(_) => {
            if host == "169.254.169.254" {
                return false;
            }
            if check_dns && !is_loopback_host(host) && dns_resolves_to_private(host).await {
                return false;
            }
        }
    }
    if let Some(port) = parsed.port() {
        if !(1..=65535).contains(&port) {
            return false;
        }
    }
    let _ = provider;
    true
}

/// Load normalized profiles -> (profiles map, default_profile name).
pub async fn load_profiles() -> (HashMap<String, Value>, Option<String>) {
    let raw = load_raw_config().await;
    let raw = if raw.as_object().map(|o| o.is_empty()).unwrap_or(true)
        || raw
            .get("profiles")
            .and_then(|p| p.as_object())
            .map(|o| o.is_empty())
            .unwrap_or(true)
    {
        build_default_config()
    } else {
        raw
    };
    let profiles = raw.get("profiles").cloned().unwrap_or_else(|| json!({}));
    let default = raw
        .get("default_profile")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let mut norm = HashMap::new();
    if let Some(map) = profiles.as_object() {
        for (name, p) in map {
            let obj = match p.as_object() {
                Some(o) => o,
                None => continue,
            };
            let provider = obj
                .get("provider")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_lowercase();
            if !VALID_PROVIDERS.contains(&provider.as_str()) {
                continue;
            }
            let base_url = obj
                .get("base_url")
                .or_else(|| obj.get("endpoint"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim_end_matches('/')
                .to_string();
            let model = obj
                .get("model")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim()
                .to_string();
            if base_url.is_empty() || model.is_empty() {
                continue;
            }
            let api_key_env = obj
                .get("api_key_env")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            if let Some(ref k) = api_key_env {
                if !allowed_api_key_re().is_match(k) {
                    continue;
                }
            }
            if !validate_base_url_live(&base_url, &provider, api_key_env.as_deref()).await {
                continue;
            }
            let timeout = clamp(
                obj.get("timeout").and_then(|v| v.as_i64()).unwrap_or(90),
                10,
                300,
            );
            let max_hosts = clamp(
                obj.get("max_hosts").and_then(|v| v.as_i64()).unwrap_or(10),
                1,
                50,
            );
            let max_tokens = clamp(
                obj.get("max_tokens")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(1024),
                64,
                8192,
            );
            let mut options = obj.get("options").cloned().unwrap_or_else(|| json!({}));
            if let Some(np) = obj.get("num_predict").and_then(|v| v.as_i64()) {
                if np > 0 {
                    if let Value::Object(o) = &mut options {
                        o.insert("num_predict".into(), json!(clamp(np, 64, 8192)));
                    }
                }
            }
            norm.insert(
                name.clone(),
                json!({
                    "provider": provider,
                    "base_url": base_url,
                    "model": model,
                    "api_key_env": api_key_env,
                    "timeout": timeout,
                    "max_hosts": max_hosts,
                    "max_tokens": max_tokens,
                    "options": options,
                }),
            );
        }
    }
    (norm, default)
}

fn clamp(v: i64, lo: i64, hi: i64) -> i64 {
    v.max(lo).min(hi)
}

async fn load_raw_config() -> Value {
    // 1. env JSON
    if let Ok(env_json) = std::env::var("CTI_AI_CONFIG") {
        if let Ok(d) = serde_json::from_str::<Value>(&env_json) {
            if d.is_object() {
                return d;
            }
        }
    }
    // 2. file path from env, else {CTI_DATA_DIR}/ai_config.json (parity with Python)
    let cfg_path = if let Ok(p) = std::env::var("CTI_AI_CONFIG_FILE") {
        p
    } else {
        let data_dir = std::env::var("CTI_DATA_DIR").unwrap_or_else(|_| "data".to_string());
        format!("{}/ai_config.json", data_dir.trim_end_matches('/'))
    };
    if std::path::Path::new(&cfg_path).exists() {
        if let Ok(txt) = tokio::fs::read_to_string(&cfg_path).await {
            if let Ok(d) = serde_json::from_str::<Value>(&txt) {
                if d.is_object() {
                    return d;
                }
            }
        }
    }
    json!({})
}

fn build_default_config() -> Value {
    let key = std::env::var("HERMES_CUSTOM_API_CLINE_BOT_API_KEY").unwrap_or_default();
    if key.trim().is_empty() {
        return json!({"default_profile": null, "profiles": {}});
    }
    json!({
        "default_profile": "cline",
        "profiles": {
            "cline": {
                "provider": "openai-compatible",
                "base_url": "https://api.cline.bot/api/v1",
                "model": "cline-pass/mimo-v2.5-pro",
                "api_key_env": "HERMES_CUSTOM_API_CLINE_BOT_API_KEY",
                "timeout": 90,
                "max_hosts": 10,
                "max_tokens": 3072,
            }
        }
    })
}

/// Resolve the effective profile for an org:
/// override > runtime-file preference > legacy orgs.json ai_profile > default.
/// Parity with Python `resolve_profile_for_org`.
pub async fn resolve_profile_for_org(slug: &str, override_: Option<&str>) -> Option<String> {
    let (profiles, default) = load_profiles().await;
    if let Some(o) = override_ {
        if profiles.contains_key(o) {
            return Some(o.to_string());
        }
    }
    if !slug.is_empty() {
        // 1. ignored runtime file (preferred, does not dirty tracked registry)
        if let Some(pref) = get_org_profile(slug).await {
            if profiles.contains_key(&pref) {
                return Some(pref);
            }
        }
        // 2. legacy orgs.json ai_profile (backwards compat)
        let reg_path = format!("{}/orgs.json", data_root());
        if let Ok(txt) = tokio::fs::read_to_string(&reg_path).await {
            if let Ok(reg) = serde_json::from_str::<Value>(&txt) {
                if let Some(pref) = reg
                    .get(slug)
                    .and_then(|e| e.get("ai_profile"))
                    .and_then(|v| v.as_str())
                {
                    let pref = pref.trim().to_string();
                    if profiles.contains_key(&pref) {
                        return Some(pref);
                    }
                }
            }
        }
    }
    default
}

/// Effective profile that is also *ready* (an openai-compatible profile whose
/// API key env var is missing degrades to None). Mirrors the scan-handler
/// fallback in Python `api_org_scan`: deterministic work always proceeds.
pub async fn effective_ready_profile(slug: &str, override_: Option<&str>) -> Option<String> {
    let eff = resolve_profile_for_org(slug, override_).await?;
    let (profiles, _) = load_profiles().await;
    let p = profiles.get(&eff)?;
    if p.get("provider").and_then(|v| v.as_str()) == Some("openai-compatible") {
        if let Some(k) = p.get("api_key_env").and_then(|v| v.as_str()) {
            if std::env::var(k).map(|v| v.trim().is_empty()).unwrap_or(true) {
                return None;
            }
        }
    }
    Some(eff)
}

/// Safe public view of provider capabilities: no secrets, no base URLs.
/// Parity with Python `get_capabilities`.
pub async fn get_capabilities() -> Value {
    let (profiles, default) = load_profiles().await;
    let mut names: Vec<&String> = profiles.keys().collect();
    names.sort();
    let mut caps = Vec::new();
    for name in names {
        let p = &profiles[name];
        let provider = p.get("provider").and_then(|v| v.as_str()).unwrap_or("");
        let mut ready = true;
        if provider == "openai-compatible" {
            if let Some(k) = p.get("api_key_env").and_then(|v| v.as_str()) {
                if std::env::var(k).map(|v| v.trim().is_empty()).unwrap_or(true) {
                    ready = false;
                }
            }
        }
        caps.push(json!({
            "name": name,
            "provider": provider,
            "model": p.get("model").cloned().unwrap_or(Value::Null),
            "timeout": p.get("timeout").cloned().unwrap_or(Value::Null),
            "max_hosts": p.get("max_hosts").cloned().unwrap_or(Value::Null),
            "ready": ready,
            "default": Some(name.as_str()) == default.as_deref(),
        }));
    }
    json!({
        "default_profile": default,
        "profiles": caps,
        "prompt_version": PROMPT_VERSION,
    })
}

/// Make a chat-completion call. Returns Some(text) or None (fail-open).
pub async fn call_ai(prompt: &str, profile_name: Option<&str>) -> Option<String> {
    let (profiles, default) = load_profiles().await;
    let name = profile_name
        .map(|s| s.to_string())
        .or(default)
        .or_else(|| profiles.keys().next().cloned())?;
    let profile = profiles.get(&name)?.clone();
    let provider = profile
        .get("provider")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let base_url = profile
        .get("base_url")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let model = profile.get("model").and_then(|v| v.as_str()).unwrap_or("");
    let timeout = profile
        .get("timeout")
        .and_then(|v| v.as_u64())
        .unwrap_or(90);

    let api_key = profile
        .get("api_key_env")
        .and_then(|v| v.as_str())
        .and_then(|env| std::env::var(env).ok())
        .filter(|k| !k.is_empty());

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .timeout(std::time::Duration::from_secs(timeout))
        .build()
        .ok()?;

    match provider {
        "ollama" => {
            let body = json!({
                "model": model,
                "prompt": prompt,
                "stream": false,
                "options": profile.get("options").cloned().unwrap_or_else(|| json!({})),
            });
            let resp = client
                .post(format!("{}/api/generate", base_url))
                .json(&body)
                .send()
                .await
                .ok()?;
            let d: Value = resp.json().await.ok()?;
            d.get("response")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        }
        "openai-compatible" => {
            let mut body = json!({
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": profile.get("max_tokens").and_then(|v| v.as_i64()).unwrap_or(1024),
            });
            if let Value::Object(o) = &mut body {
                o.insert("response_format".into(), json!({"type": "json_object"}));
            }
            let mut req = client
                .post(format!("{}/chat/completions", base_url))
                .json(&body);
            if let Some(key) = api_key {
                req = req.header("Authorization", format!("Bearer {}", key));
            }
            let resp = req.send().await.ok()?;
            let d: Value = resp.json().await.ok()?;
            extract_openai_content(&d)
        }
        _ => None,
    }
}

/// Extract assistant text from an OpenAI-compatible response, handling both
/// the standard {"choices":[...]} shape and the cline.bot wrapper
/// {"data":{"choices":[...]}}.
pub fn extract_openai_content(d: &Value) -> Option<String> {
    // standard shape first
    if let Some(s) = d
        .pointer("/choices/0/message/content")
        .and_then(|v| v.as_str())
    {
        return Some(s.to_string());
    }
    // cline.bot wrapper
    if let Some(s) = d
        .pointer("/data/choices/0/message/content")
        .and_then(|v| v.as_str())
    {
        return Some(s.to_string());
    }
    None
}

/// Strip ```json fences from a raw model response.
pub fn strip_json_fences(raw: &str) -> String {
    let s = raw.trim();
    let s = s.trim_start_matches("```json").trim_start_matches("```");
    s.trim_end_matches("```").trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_base_url_rejects_private() {
        assert!(!validate_base_url(
            "http://10.0.0.1/v1",
            "openai-compatible",
            None
        ));
        assert!(!validate_base_url(
            "https://169.254.169.254/v1",
            "openai-compatible",
            None
        ));
        assert!(!validate_base_url(
            "http://example.com/v1",
            "openai-compatible",
            Some("KEY")
        ));
    }

    #[test]
    fn test_validate_base_url_allows_loopback_http() {
        assert!(validate_base_url("http://127.0.0.1:11434", "ollama", None));
        assert!(validate_base_url("http://localhost:11434", "ollama", None));
    }

    #[test]
    fn test_validate_base_url_allows_public_https() {
        assert!(validate_base_url(
            "https://opencode.ai/zen/go/v1",
            "openai-compatible",
            Some("KEY")
        ));
    }

    #[test]
    fn test_strip_json_fences() {
        assert_eq!(strip_json_fences("```json\n{\"a\":1}\n```"), "{\"a\":1}");
        assert_eq!(strip_json_fences("{\"a\":1}"), "{\"a\":1}");
    }

    #[test]
    fn test_extract_openai_content_standard() {
        let d = json!({"choices": [{"message": {"content": "hello"}}]});
        assert_eq!(extract_openai_content(&d), Some("hello".to_string()));
    }

    #[test]
    fn test_extract_openai_content_cline_envelope() {
        let d = json!({"data": {"choices": [{"message": {"content": "{\"ok\":true}"}}]}, "success": true});
        assert_eq!(
            extract_openai_content(&d),
            Some("{\"ok\":true}".to_string())
        );
    }
}
