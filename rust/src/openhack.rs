//! OpenHack active-assessment wrapper — fail-closed by design.
//! Port of `openhack_source.py`. Requires CTI_OPENHACK_ACTIVE=1 + ISOLATED=1 +
//! explicit absolute CTI_OPENHACK_BIN (disposable-container wrapper) + exact
//! target allowlist + time-bounded ROE. Never falls back to a PATH lookup.

use parking_lot::Mutex;
use serde_json::{json, Value};
use std::path::Path;
use std::process::Stdio;

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
pub async fn list_models(force: bool) -> Value {
    {
        let guard = CACHE.lock();
        if !force {
            if let Some(c) = guard.as_ref() {
                if c.data.is_some() && c.at.elapsed().map(|d| d.as_secs() < 600).unwrap_or(false) {
                    return c.data.clone().unwrap();
                }
            }
        }
    }
    let result = list_models_live().await;
    let mut guard = CACHE.lock();
    *guard = Some(ModelsCache {
        at: std::time::SystemTime::now(),
        data: Some(result.clone()),
    });
    result
}

/// Resolve the configured model or the verified OpenHack catalog default.
/// Kept pure so the fallback is deterministic under test.
fn preferred_model_from(configured: Option<&str>) -> String {
    let m = configured.unwrap_or("").trim();
    if m.is_empty() {
        "glm-5.3-flash".to_string()
    } else {
        m.to_string()
    }
}

/// Preferred model when neither the request nor the org pins one
/// (`CTI_OHACK_MODEL`, default `glm-5.3-flash` — parity with Python).
pub fn preferred_model() -> String {
    let configured = std::env::var("CTI_OHACK_MODEL").ok();
    preferred_model_from(configured.as_deref())
}

/// Scratch dir for assessment runs (`CTI_OPENHACK_SCANS_DIR` or
/// `~/.openhack/scans` — parity with Python).
pub fn scans_dir() -> String {
    let d = std::env::var("CTI_OPENHACK_SCANS_DIR").unwrap_or_default();
    let d = d.trim();
    if !d.is_empty() {
        return d.to_string();
    }
    std::env::var("HOME")
        .map(|h| format!("{}/.openhack/scans", h.trim_end_matches('/')))
        .unwrap_or_else(|_| ".openhack/scans".to_string())
}

/// Quick-pass wall-clock budget in seconds (`CTI_OHACK_QUICK_BUDGET`,
/// default 480, clamped 300-1200 — parity with Python).
pub fn quick_budget() -> u64 {
    std::env::var("CTI_OHACK_QUICK_BUDGET")
        .ok()
        .and_then(|v| v.trim().parse::<f64>().ok())
        .map(|f| f as u64)
        .unwrap_or(480)
        .clamp(300, 1200)
}

fn model_fallback() -> Value {
    json!({"models": [{"id": "default", "label": "default"}], "default": "default"})
}

/// Normalize a raw catalog into `{models, default, preferred}`: cap 60,
/// truncate id/label, pin the preferred model first (parity with Python
/// `list_models` post-processing).
fn normalize_models(d: Value, preferred: &str) -> Value {
    let default = d
        .get("default")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let mut models: Vec<Value> = d
        .get("models")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .take(60)
        .filter_map(|m| {
            let id = m.get("id").and_then(|v| v.as_str())?;
            if id.is_empty() {
                return None;
            }
            let label = m
                .get("label")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .unwrap_or(id);
            Some(json!({
                "id": id.chars().take(64).collect::<String>(),
                "label": label.chars().take(80).collect::<String>(),
            }))
        })
        .collect();
    if models.is_empty() && !default.is_empty() {
        models.push(json!({"id": default, "label": format!("{} (configured default)", default)}));
    }
    if !preferred.is_empty()
        && !models
            .iter()
            .any(|m| m.get("id").and_then(|v| v.as_str()) == Some(preferred))
    {
        models.insert(
            0,
            json!({"id": preferred, "label": format!("{} \u{2014} unreleased GLM (recommended)", preferred)}),
        );
    }
    models.sort_by_key(|m| {
        if m.get("id").and_then(|v| v.as_str()) == Some(preferred) {
            0
        } else {
            1
        }
    });
    json!({"models": models, "default": default, "preferred": preferred})
}

async fn list_models_live() -> Value {
    // Shell out to the OpenHack Python inference service (disposable wrapper).
    let bin = match openhack_bin() {
        Some(b) => b,
        None => return model_fallback(),
    };
    let mut child = match tokio::process::Command::new(&bin)
        .arg("--list-models")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(_) => return model_fallback(),
    };
    // take the piped stdout first; `wait()` borrows the child so a timeout
    // can still kill it (unlike `wait_with_output`, which moves it)
    let stdout = child.stdout.take();
    // bounded wait (20s): never hang a worker on a stuck helper
    let exited = match tokio::time::timeout(std::time::Duration::from_secs(20), child.wait()).await
    {
        Ok(Ok(s)) => Some(s),
        _ => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            None
        }
    };
    // the child has exited (or was killed): drain whatever it wrote
    let mut buf = Vec::new();
    if let Some(mut so) = stdout {
        use tokio::io::AsyncReadExt;
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), so.read_to_end(&mut buf))
            .await;
    }
    match exited {
        Some(s) if s.success() => match String::from_utf8(buf) {
            Ok(txt) => {
                // the binary may print logs: the catalog is the last line
                let last = txt.lines().last().unwrap_or("").trim();
                let d: Value =
                    serde_json::from_str(last).unwrap_or_else(|_| json!({"models": [], "default": ""}));
                normalize_models(d, &preferred_model())
            }
            Err(_) => model_fallback(),
        },
        _ => model_fallback(),
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

    #[test]
    fn preferred_model_uses_glm_flash_when_unset() {
        assert_eq!(preferred_model_from(None), "glm-5.3-flash");
    }
}
