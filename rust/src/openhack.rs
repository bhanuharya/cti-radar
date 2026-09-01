//! OpenHack active-assessment wrapper — fail-closed by design.
//! Port of `openhack_source.py`. Requires CTI_OPENHACK_ACTIVE=1 + ISOLATED=1 +
//! explicit absolute CTI_OPENHACK_BIN (disposable-container wrapper) + exact
//! target allowlist + time-bounded ROE. Never falls back to a PATH lookup.

use serde_json::{json, Value};
use std::path::Path;
use std::process::Stdio;
use std::sync::Mutex;

/// Return the explicit absolute assessment executable, or None.
pub fn openhack_bin() -> Option<String> {
    let p = std::env::var("CTI_OPENHACK_BIN").unwrap_or_default();
    let p = p.trim();
    if p.is_empty() || !Path::new(p).is_absolute() || !Path::new(p).is_file() {
        return None;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(p).ok()?;
        if meta.permissions().mode() & 0o111 == 0 {
            return None;
        }
    }
    Some(p.to_string())
}

/// Fail-closed server-level authorization check. Returns an error string or None.
pub fn authorization_error(org: &Value) -> Option<String> {
    if std::env::var("CTI_OPENHACK_ACTIVE").unwrap_or_default() != "1" {
        return Some("CTI_OPENHACK_ACTIVE must equal 1".to_string());
    }
    if std::env::var("CTI_OPENHACK_ISOLATED").unwrap_or_default() != "1" {
        return Some(
            "CTI_OPENHACK_ISOLATED must equal 1 (use a disposable-container wrapper)".to_string(),
        );
    }
    let bin = openhack_bin();
    if bin.is_none() {
        return Some("CTI_OPENHACK_BIN must be an explicit absolute executable (disposable-container wrapper)".to_string());
    }
    let raw = std::env::var("CTI_OPENHACK_ALLOWED_DOMAINS").unwrap_or_default();
    if raw.trim().is_empty() {
        return Some("CTI_OPENHACK_ALLOWED_DOMAINS is missing or empty".to_string());
    }
    let mut allowed: Vec<String> = Vec::new();
    for item in raw.split(',') {
        let d = item.trim().trim_end_matches('.').to_lowercase();
        if d.is_empty() || d.contains("..") || !is_valid_domain(&d) {
            return Some("CTI_OPENHACK_ALLOWED_DOMAINS contains an invalid domain".to_string());
        }
        allowed.push(d);
    }
    let targets = org.get("domains").and_then(|v| v.as_array());
    let targets = match targets {
        Some(t) => t,
        None => return Some("the organization has no registered target domains".to_string()),
    };
    for t in targets {
        let d = t
            .as_str()
            .unwrap_or("")
            .trim()
            .trim_end_matches('.')
            .to_lowercase();
        if d.is_empty() || !is_valid_domain(&d) {
            return Some("the organization has an invalid registered target domain".to_string());
        }
        if !allowed.contains(&d) {
            return Some(
                "registered target domain outside CTI_OPENHACK_ALLOWED_DOMAINS".to_string(),
            );
        }
    }
    let raw_expiry = std::env::var("CTI_OPENHACK_ROE_EXPIRES").unwrap_or_default();
    match chrono::DateTime::parse_from_rfc3339(raw_expiry.trim()) {
        Ok(expires) => {
            if expires <= chrono::Utc::now() {
                return Some("CTI_OPENHACK_ROE_EXPIRES is expired".to_string());
            }
        }
        Err(_) => {
            return Some(
                "CTI_OPENHACK_ROE_EXPIRES is not a valid RFC3339/ISO-8601 timestamp".to_string(),
            )
        }
    }
    None
}

fn is_valid_domain(d: &str) -> bool {
    if d.is_empty() || d.len() > 253 || !d.contains('.') {
        return false;
    }
    // TLD must contain a letter (rejects numeric IP-like names).
    let tld = d.rsplit('.').next().unwrap_or("");
    if !tld.chars().any(|c| c.is_ascii_lowercase()) {
        return false;
    }
    d.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
            && !label.starts_with('-')
            && !label.ends_with('-')
    })
}

// Model catalog cache (10 min TTL).
struct ModelsCache {
    at: std::time::SystemTime,
    data: Option<Value>,
}
static CACHE: Mutex<Option<ModelsCache>> = Mutex::new(None);

/// Live model catalog from the OpenHack inference service (cached 10 min).
/// On failure, falls back to a single default entry so the UI always works.
pub fn list_models(force: bool) -> Value {
    {
        let guard = CACHE.lock().unwrap();
        if !force {
            if let Some(c) = guard.as_ref() {
                if c.data.is_some() && c.at.elapsed().map(|d| d.as_secs() < 600).unwrap_or(false) {
                    return c.data.clone().unwrap();
                }
            }
        }
    }
    let result = list_models_live();
    let mut guard = CACHE.lock().unwrap();
    *guard = Some(ModelsCache {
        at: std::time::SystemTime::now(),
        data: Some(result.clone()),
    });
    result
}

fn list_models_live() -> Value {
    // Shell out to the OpenHack Python inference service (disposable wrapper).
    let bin = match openhack_bin() {
        Some(b) => b,
        None => {
            return json!({"models": [{"id": "default", "label": "default"}], "default": "default"})
        }
    };
    let child = std::process::Command::new(&bin)
        .arg("--list-models")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn();
    let child = match child {
        Ok(c) => c,
        Err(_) => {
            return json!({"models": [{"id": "default", "label": "default"}], "default": "default"})
        }
    };
    let output = child.wait_with_output().ok();
    match output.and_then(|o| String::from_utf8(o.stdout).ok()) {
        Some(txt) => {
            serde_json::from_str(&txt).unwrap_or_else(|_| json!({"models": [], "default": ""}))
        }
        None => json!({"models": [{"id": "default", "label": "default"}], "default": "default"}),
    }
}

/// Spawn an assessment run (fail-closed). Returns None on gate failure.
pub async fn run_assessment(slug: &str, domains: &[String]) -> Option<Value> {
    let bin = openhack_bin()?;
    let _ = (slug, domains, bin);
    None // placeholder: full assessment orchestration deferred
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_valid_domain() {
        assert!(is_valid_domain("example.com"));
        assert!(!is_valid_domain("not a domain"));
        assert!(!is_valid_domain("*.example.com"));
        assert!(!is_valid_domain("192.168.1.1"));
    }
}
