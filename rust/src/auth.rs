//! Authentication: session cookies + static API token (constant-time compare).
//! Mirrors `main.py` `_auth_ok` / `_login_ok` / login rate-limiting exactly.

use crate::config::Config;
use crate::error::{AppError, AppResult};
use axum::http::header;
use axum::http::HeaderMap;
use base64::Engine;
use once_cell::sync::OnceCell;
use rand::RngCore;
use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;

pub const SESSION_COOKIE: &str = "cti_session";
const SESSION_TTL: u64 = 12 * 3600; // 12h

static CFG: OnceCell<Config> = OnceCell::new();

pub fn init(cfg: Config) {
    let _ = CFG.set(cfg);
}

fn cfg() -> &'static Config {
    CFG.get().expect("auth::init must be called first")
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

// session id -> expiry epoch (in-memory)
static SESSIONS: OnceCell<RwLock<HashMap<String, u64>>> = OnceCell::new();

fn sessions() -> &'static RwLock<HashMap<String, u64>> {
    SESSIONS.get_or_init(|| RwLock::new(HashMap::new()))
}

// source IP -> [failure timestamps]
static LOGIN_FAILS: OnceCell<RwLock<HashMap<String, Vec<u64>>>> = OnceCell::new();

fn login_fails() -> &'static RwLock<HashMap<String, Vec<u64>>> {
    LOGIN_FAILS.get_or_init(|| RwLock::new(HashMap::new()))
}

const LOGIN_FAIL_MAX: usize = 4096;

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(default)
}

pub fn login_limit(ip: &str) -> (bool, u64) {
    let now = now();
    let threshold = env_u64("CTI_LOGIN_FAIL_THRESHOLD", 5).max(1);
    let window = env_u64("CTI_LOGIN_FAIL_WINDOW", 300).max(1);
    let retry = env_u64("CTI_LOGIN_RETRY_AFTER", 60).max(1);

    let mut fails = login_fails().write().unwrap();
    // prune stale entries
    let keys: Vec<String> = fails.keys().cloned().collect();
    for key in keys {
        let keep: Vec<u64> = fails
            .get(&key)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter(|t| now - *t < window)
            .collect();
        if keep.is_empty() {
            fails.remove(&key);
        } else {
            fails.insert(key, keep);
        }
    }
    let vals = fails.get(ip).cloned().unwrap_or_default();
    if vals.len() as u64 >= threshold {
        return (true, retry);
    }
    (false, retry)
}

pub fn record_login_failure(ip: &str) {
    let now = now();
    let window = env_u64("CTI_LOGIN_FAIL_WINDOW", 300).max(1);
    let mut fails = login_fails().write().unwrap();
    let vals: Vec<u64> = fails
        .get(ip)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter(|t| now - *t < window)
        .collect();
    if fails.len() >= LOGIN_FAIL_MAX && !fails.contains_key(ip) {
        if let Some(oldest) = fails
            .iter()
            .min_by_key(|(_, v)| v.last().copied().unwrap_or(0))
            .map(|(k, _)| k.clone())
        {
            fails.remove(&oldest);
        }
    }
    let mut vals = vals;
    vals.push(now);
    fails.insert(ip.to_string(), vals);
}

pub fn reset_login_failures(ip: &str) {
    let mut fails = login_fails().write().unwrap();
    fails.remove(ip);
}

fn cookie_token(headers: &HeaderMap) -> Option<String> {
    let cookie = headers.get(header::COOKIE)?.to_str().ok()?;
    for part in cookie.split(';') {
        let part = part.trim();
        if let Some((k, v)) = part.split_once('=') {
            if k.trim() == SESSION_COOKIE {
                return Some(v.trim().to_string());
            }
        }
    }
    None
}

/// Drop the session id carried by the request cookie (server-side logout).
/// Mirrors Python `api_logout` (`_SESSIONS.pop(sid, None)`).
pub fn invalidate_session(headers: &HeaderMap) {
    if let Some(sid) = cookie_token(headers) {
        sessions().write().unwrap().remove(&sid);
    }
}

/// Auth is satisfied by EITHER a valid session cookie OR the static API token.
pub fn auth_ok(headers: &HeaderMap) -> bool {
    // (1) session cookie
    if let Some(sid) = cookie_token(headers) {
        let exp = sessions().read().unwrap().get(&sid).copied();
        if let Some(exp) = exp {
            if now() <= exp {
                return true;
            }
            sessions().write().unwrap().remove(&sid);
        }
    }
    // (2) static API token (constant-time compare)
    let tok = cfg().scan_token.clone();
    let supplied = headers
        .get("X-CTI-Token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    if !tok.is_empty() && !supplied.is_empty() {
        let a = tok.as_bytes();
        let b = supplied.as_bytes();
        if a.len() == b.len() && a.ct_eq(b).unwrap_u8() == 1 {
            return true;
        }
    }
    false
}

/// Validate Basic auth; on success return a new session id.
pub fn login_ok(headers: &HeaderMap) -> Option<String> {
    let u = cfg().user.clone();
    let p = cfg().password.clone();
    if u.is_empty() || p.is_empty() {
        return None;
    }
    let auth = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let encoded = auth.strip_prefix("Basic ")?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded.trim())
        .ok()?;
    let raw = String::from_utf8_lossy(&decoded);
    let (gu, gp) = raw.split_once(':')?;

    let gu_b = gu.as_bytes();
    let u_b = u.as_bytes();
    let gp_b = gp.as_bytes();
    let p_b = p.as_bytes();
    if gu_b.len() != u_b.len()
        || gp_b.len() != p_b.len()
        || gu_b.ct_eq(u_b).unwrap_u8() != 1
        || gp_b.ct_eq(p_b).unwrap_u8() != 1
    {
        return None;
    }

    let mut buf = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut buf);
    let sid = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf);
    let exp = now() + SESSION_TTL;
    sessions().write().unwrap().insert(sid.clone(), exp);
    Some(sid)
}

/// Whether to set the Secure flag on the session cookie.
pub fn use_secure_cookie(headers: &HeaderMap) -> bool {
    headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .map(|v| v == "https")
        .unwrap_or(false)
}

pub fn validate_credentials(body: &HeaderMap) -> AppResult<Option<String>> {
    Ok(login_ok(body))
}

/// Helper: require auth or return 401.
pub fn require_auth(headers: &HeaderMap) -> AppResult<()> {
    if auth_ok(headers) {
        Ok(())
    } else {
        Err(AppError::Unauthorized)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cookie_token_parses() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            "cti_session=abc123; other=1".parse().unwrap(),
        );
        assert_eq!(cookie_token(&headers), Some("abc123".to_string()));
    }
}
