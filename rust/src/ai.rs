//! AI provider abstraction — ollama + openai-compatible, SSRF-validated.
//! Port of `ai_providers.py`. Fail-open: any provider/parse failure returns
//! None, never blocks the deterministic scan.

use once_cell::sync::OnceCell;
use regex::Regex;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::IpAddr;

const VALID_PROVIDERS: [&str; 2] = ["ollama", "openai-compatible"];

fn allowed_api_key_re() -> &'static Regex {
    static RE: OnceCell<Regex> = OnceCell::new();
    RE.get_or_init(|| Regex::new(r"^[A-Za-z_][A-Za-z0-9_]*$").unwrap())
}

fn is_loopback_host(host: &str) -> bool {
    match host.parse::<IpAddr>() {
        Ok(ip) => ip.is_loopback(),
        Err(_) => host == "localhost",
    }
}

fn is_global_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
                || v4.is_multicast()
                || is_cgnat(*v4))
        }
        IpAddr::V6(v6) => {
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || is_ipv6_private(*v6)
                || is_ipv6_link_local(*v6))
        }
    }
}

fn is_cgnat(v4: std::net::Ipv4Addr) -> bool {
    // 100.64.0.0/10 (shared address space)
    let o = v4.octets();
    o[0] == 100 && (64..=127).contains(&o[1])
}

fn dns_resolves_to_private(hostname: &str) -> bool {
    // DNS rebinding guard: reject hostnames resolving to any private address.
    use std::net::ToSocketAddrs;
    match (hostname, 443).to_socket_addrs() {
        Ok(addrs) => addrs.into_iter().any(|a| !is_global_ip(&a.ip())),
        Err(_) => false,
    }
}

fn is_ipv6_private(v6: std::net::Ipv6Addr) -> bool {
    // Conservative: treat ULA (fc00::/7) as private.
    let seg = v6.segments();
    seg[0] & 0xfe00 == 0xfc00
}

fn is_ipv6_link_local(v6: std::net::Ipv6Addr) -> bool {
    let seg = v6.segments();
    seg[0] & 0xffc0 == 0xfe80
}

/// Validate an AI provider base URL (SSRF protections mirror the Python).
pub fn validate_base_url(base_url: &str, provider: &str, api_key_env: Option<&str>) -> bool {
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
            if !is_loopback_host(host) && dns_resolves_to_private(host) {
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
pub fn load_profiles() -> (HashMap<String, Value>, Option<String>) {
    let raw = load_raw_config();
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
            if !validate_base_url(&base_url, &provider, api_key_env.as_deref()) {
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

fn load_raw_config() -> Value {
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
        if let Ok(txt) = std::fs::read_to_string(&cfg_path) {
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

pub fn is_ai_configured() -> bool {
    let (profiles, _) = load_profiles();
    !profiles.is_empty()
}

pub fn resolve_profile_for_org(_slug: &str, _override: Option<&str>) -> Option<String> {
    let (profiles, default) = load_profiles();
    if let Some(o) = _override {
        if profiles.contains_key(o) {
            return Some(o.to_string());
        }
    }
    default
}

/// Make a chat-completion call. Returns Some(text) or None (fail-open).
pub async fn call_ai(prompt: &str, profile_name: Option<&str>) -> Option<String> {
    let (profiles, default) = load_profiles();
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
