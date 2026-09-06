//! Offline version→CVE matching against the vendored `cve_data.json` map.
//! Deterministic, $0, no network (NVD enrichment is a separate opt-in path).
//! Port of `cve_match.py`.

use once_cell::sync::OnceCell;
use parking_lot::Mutex;
use regex::Regex;
use serde_json::Value;
use std::collections::HashMap;

fn suffix_re() -> &'static Regex {
    static RE: OnceCell<Regex> = OnceCell::new();
    RE.get_or_init(|| Regex::new(r"^(\d+)([A-Za-z]{0,3}\d*)$").unwrap())
}

fn range_clause_re() -> &'static Regex {
    static RE: OnceCell<Regex> = OnceCell::new();
    RE.get_or_init(|| Regex::new(r"^(>=|<=|=|>|<)\s*(.+)$").unwrap())
}

fn split_re() -> &'static Regex {
    static RE: OnceCell<Regex> = OnceCell::new();
    RE.get_or_init(|| Regex::new(r"[.\-_+ ]").unwrap())
}

/// Loaded+validated product map (cached once per process).
static MAP: OnceCell<Value> = OnceCell::new();
static ALIAS_INDEX: OnceCell<Mutex<HashMap<String, String>>> = OnceCell::new();

fn norm(s: &str) -> String {
    static RE: OnceCell<Regex> = OnceCell::new();
    RE.get_or_init(|| Regex::new(r"[\s_/-]+").unwrap())
        .replace_all(s.trim().to_lowercase().as_str(), " ")
        .to_string()
}

/// Embed cve_data.json at compile time (single static binary).
const CVE_DATA: &str = include_str!("../../app/cve_data.json");

pub fn load_map() -> &'static Value {
    MAP.get_or_init(|| {
        let data: Value = serde_json::from_str(CVE_DATA).expect("cve_data.json must be valid");
        let products = data.get("products").and_then(|p| p.as_object()).cloned();
        products
            .map(Value::Object)
            .unwrap_or_else(|| serde_json::json!({}))
    })
}

/// Test hook: reset the alias index.
pub fn reset_cache() {
    if let Some(idx) = ALIAS_INDEX.get() {
        *idx.lock() = HashMap::new();
    }
}

fn aliases() -> HashMap<String, String> {
    let cell = ALIAS_INDEX.get_or_init(|| Mutex::new(HashMap::new()));
    let mut idx = cell.lock();
    if !idx.is_empty() {
        return idx.clone();
    }
    let map = load_map();
    if let Some(products) = map.as_object() {
        for (key, entry) in products {
            let mut names: Vec<String> = vec![key.clone()];
            if let Some(als) = entry.get("aliases").and_then(|a| a.as_array()) {
                for a in als {
                    if let Some(s) = a.as_str() {
                        names.push(norm(s));
                    }
                }
            }
            for n in names {
                idx.entry(n).or_insert_with(|| key.clone());
            }
        }
    }
    idx.clone()
}

pub fn normalize_product(name: &str) -> Option<String> {
    if name.is_empty() {
        return None;
    }
    let n = norm(name.trim_end_matches('.'));
    let idx = aliases();
    if let Some(k) = idx.get(&n) {
        return Some(k.clone());
    }
    let parts: Vec<&str> = n.split(' ').filter(|p| !p.is_empty()).collect();
    if parts.len() > 1 {
        if let Some(k) = idx.get(parts[parts.len() - 1]) {
            return Some(k.clone());
        }
        if parts[parts.len() - 1].starts_with(|c: char| c.is_ascii_digit()) {
            let stem = parts[..parts.len() - 1].join(" ");
            if let Some(k) = idx.get(&stem) {
                return Some(k.clone());
            }
        }
    }
    None
}

/// Leading numeric components of a version string -> Vec<i64>.
fn vkey(version: &str) -> Vec<i64> {
    let mut parts: Vec<i64> = vec![];
    for tok in split_re().split(version) {
        if let Ok(n) = tok.parse::<i64>() {
            parts.push(n);
            continue;
        }
        // short patch-level suffix: "7.1p2" -> 7,1 ; long distro suffix ends prefix
        if let Some(c) = suffix_re().captures(tok) {
            if let Ok(n) = c[1].parse::<i64>() {
                parts.push(n);
            }
        }
        break;
    }
    parts
}

fn cmp_tuples(a: &[i64], b: &[i64]) -> std::cmp::Ordering {
    let n = a.len().max(b.len());
    for i in 0..n {
        let av = a.get(i).copied().unwrap_or(0);
        let bv = b.get(i).copied().unwrap_or(0);
        match av.cmp(&bv) {
            std::cmp::Ordering::Equal => continue,
            other => return other,
        }
    }
    std::cmp::Ordering::Equal
}

pub fn version_satisfies(version: &str, range_str: &str) -> bool {
    let v = vkey(version);
    if v.is_empty() {
        return false;
    }
    for clause in range_str.split(',') {
        let clause = clause.trim();
        if clause.is_empty() {
            continue;
        }
        let caps = match range_clause_re().captures(clause) {
            Some(c) => c,
            None => return false,
        };
        let op = caps[1].to_string();
        let ref_v = vkey(&caps[2]);
        if ref_v.is_empty() {
            return false;
        }
        let c = cmp_tuples(&v, &ref_v);
        let ok = match op.as_str() {
            "=" => c == std::cmp::Ordering::Equal,
            "<" => c == std::cmp::Ordering::Less,
            "<=" => c != std::cmp::Ordering::Greater,
            ">" => c == std::cmp::Ordering::Greater,
            ">=" => c != std::cmp::Ordering::Less,
            _ => false,
        };
        if !ok {
            return false;
        }
    }
    true
}

fn confidence_for(vkey: &[i64]) -> &'static str {
    if vkey.len() >= 2 {
        "medium"
    } else {
        "low"
    }
}

fn sev_rank(sev: &str) -> u8 {
    match sev {
        "CRITICAL" => 0,
        _ => 1, // HIGH
    }
}

pub fn match_cves(versions: &[Value], cap: usize) -> Vec<Value> {
    let mut out: Vec<Value> = vec![];
    let mut seen: std::collections::HashSet<(String, String)> = std::collections::HashSet::new();
    for v in versions {
        let obj = match v.as_object() {
            Some(o) => o,
            None => continue,
        };
        let product = obj.get("product").and_then(|p| p.as_str()).unwrap_or("");
        let key = match normalize_product(product) {
            Some(k) => k,
            None => continue,
        };
        let version = obj.get("version").and_then(|p| p.as_str()).unwrap_or("");
        let vk = vkey(version);
        if vk.is_empty() {
            continue;
        }
        let map = load_map();
        let entry = map
            .get(&key)
            .cloned()
            .unwrap_or_else(|| serde_json::json!({}));
        let cves = entry
            .get("cves")
            .and_then(|c| c.as_array())
            .cloned()
            .unwrap_or_default();
        for cve in cves {
            let Some(cve_obj) = cve.as_object() else {
                continue;
            };
            let mut hit_range: Option<String> = None;
            let mut best_conf: Option<&'static str> = None;
            if let Some(ranges) = cve_obj.get("ranges").and_then(|r| r.as_array()) {
                for rng in ranges {
                    if let Some(rs) = rng.as_str() {
                        if version_satisfies(version, rs) {
                            hit_range = Some(rs.to_string());
                            best_conf = Some(confidence_for(&vk));
                            break;
                        }
                    }
                }
            }
            if hit_range.is_none() {
                continue;
            }
            let cve_id = cve_obj
                .get("cve")
                .and_then(|c| c.as_str())
                .unwrap_or("")
                .to_string();
            if seen.contains(&(key.clone(), cve_id.clone())) {
                continue;
            }
            seen.insert((key.clone(), cve_id.clone()));
            out.push(serde_json::json!({
                "product": key,
                "version": version,
                "cve": cve_id,
                "severity": cve_obj.get("severity").and_then(|s| s.as_str()).unwrap_or("HIGH").to_uppercase(),
                "cvss": cve_obj.get("cvss").cloned().unwrap_or(Value::Null),
                "summary": cve_obj.get("summary").and_then(|s| s.as_str()).unwrap_or(""),
                "fix_version": cve_obj.get("fix_version").cloned().unwrap_or(Value::Null),
                "range": hit_range.unwrap(),
                "confidence": best_conf.unwrap(),
            }));
            if out.len() >= cap {
                break;
            }
        }
        if out.len() >= cap {
            break;
        }
    }
    out.sort_by(|a, b| {
        let sa = a.get("severity").and_then(|s| s.as_str()).unwrap_or("HIGH");
        let sb = b.get("severity").and_then(|s| s.as_str()).unwrap_or("HIGH");
        let ca = a.get("cve").and_then(|s| s.as_str()).unwrap_or("");
        let cb = b.get("cve").and_then(|s| s.as_str()).unwrap_or("");
        sev_rank(sa).cmp(&sev_rank(sb)).then(ca.cmp(cb))
    });
    out.truncate(cap);
    out
}

pub fn worst_confidence(matches: &[Value]) -> &'static str {
    if matches
        .iter()
        .any(|m| m.get("confidence").and_then(|c| c.as_str()) == Some("low"))
    {
        "low"
    } else {
        "medium"
    }
}

// ---------------------------------------------------------------------------
// optional NVD enrichment (CTI_NVD_ENRICH=1) — fail-open by design
// ---------------------------------------------------------------------------

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const NVD_API: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=";

static NVD_LAST_CALL: AtomicU64 = AtomicU64::new(0);

pub fn nvd_enabled() -> bool {
    matches!(
        std::env::var("CTI_NVD_ENRICH")
            .unwrap_or_default()
            .trim()
            .to_lowercase()
            .as_str(),
        "1" | "true" | "yes" | "on"
    )
}

fn state_dir() -> PathBuf {
    std::env::var("CTI_STATE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            std::env::var("HOME")
                .map(|h| PathBuf::from(h).join(".local/state/cti-radar"))
                .unwrap_or_else(|_| PathBuf::from("."))
        })
}

fn nvd_cache_path() -> PathBuf {
    state_dir().join("nvd_cache.json")
}

async fn nvd_cache_load() -> Value {
    match tokio::fs::read_to_string(nvd_cache_path()).await {
        Ok(txt) => serde_json::from_str(&txt).unwrap_or_else(|_| serde_json::json!({})),
        Err(_) => serde_json::json!({}),
    }
}

async fn nvd_cache_store(entry: Value) {
    // atomic 0600 write (parity with the correlation writers)
    let mut cache = nvd_cache_load().await;
    if let (Value::Object(a), Value::Object(b)) = (&mut cache, &entry) {
        for (k, v) in b {
            a.insert(k.clone(), v.clone());
        }
    }
    let _ = crate::correlation::atomic_write_json(&nvd_cache_path(), &cache).await;
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Enrich one CVE from NVD 2.0 (disk-cached, rate-limited). Returns
/// (Some(data), network_used). Fail-open: any error returns (None, false).
pub async fn nvd_lookup(cve: &str, ttl: u64) -> (Option<Value>, bool) {
    let now = now_secs();
    {
        let cache = nvd_cache_load().await;
        if let Some(hit) = cache.get(cve) {
            let ts = hit.get("ts").and_then(|t| t.as_u64()).unwrap_or(0);
            if now - ts < ttl {
                return (hit.get("data").cloned().filter(|d| !d.is_null()), false);
            }
        }
    }

    // rate limit: ~5 req/30s without key, 50 with one
    let gap_ms = if std::env::var("CTI_NVD_API_KEY")
        .map(|v| !v.is_empty())
        .unwrap_or(false)
    {
        600u64
    } else {
        6000u64
    };
    let last = NVD_LAST_CALL.load(Ordering::SeqCst);
    let elapsed_ms = now.saturating_sub(last) * 1000;
    if elapsed_ms < gap_ms {
        tokio::time::sleep(std::time::Duration::from_millis(gap_ms - elapsed_ms)).await;
    }
    NVD_LAST_CALL.store(now_secs(), Ordering::SeqCst);

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()
        .unwrap_or_default();

    let mut req = client.get(format!("{}{}", NVD_API, cve));
    if let Ok(key) = std::env::var("CTI_NVD_API_KEY") {
        if !key.is_empty() {
            req = req.header("apiKey", key);
        }
    }

    let out = match req.timeout(std::time::Duration::from_secs(15)).send().await {
        Ok(resp) => match resp.json::<Value>().await {
            Ok(data) => parse_nvd(&data),
            Err(_) => None,
        },
        Err(_) => None,
    };

    nvd_cache_store(serde_json::json!({ cve: {"ts": now_secs(), "data": out} })).await;
    (out, true)
}

/// Enrich the CVEs matched across all host snippets, up to `cap` lookups.
///
/// Returns {cve_id: {cvss, vector, summary}}. Only network lookups count
/// against the cap — cache hits are free. Never raises (parity with Python
/// `nvd_enrich_hosts`).
pub async fn nvd_enrich_hosts(
    snippets: &std::collections::HashMap<String, Value>,
    cap: usize,
) -> std::collections::HashMap<String, Value> {
    use std::collections::{HashMap, HashSet};
    let mut out: HashMap<String, Value> = HashMap::new();
    let mut cves: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for s in snippets.values() {
        let versions: Vec<Value> = s
            .get("versions")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        for m in match_cves(&versions, 12) {
            if let Some(cve) = m.get("cve").and_then(|v| v.as_str()) {
                if seen.insert(cve.to_string()) {
                    cves.push(cve.to_string());
                }
            }
        }
    }
    let mut lookups = 0usize;
    for cve in cves {
        if lookups >= cap {
            break;
        }
        let (data, network_used) = nvd_lookup(&cve, 86400).await;
        if network_used {
            lookups += 1;
        }
        if let Some(d) = data {
            out.insert(cve, d);
        }
    }
    out
}

fn parse_nvd(data: &Value) -> Option<Value> {
    let item = data
        .get("vulnerabilities")?
        .as_array()?
        .first()?
        .get("cve")?;
    for metric in ["cvssMetricV31", "cvssMetricV30"] {
        if let Some(ms) = item.get(metric).and_then(|m| m.as_array()) {
            if let Some(cd) = ms.first().and_then(|m| m.get("cvssData")) {
                let mut summary = String::new();
                if let Some(descs) = item.get("descriptions").and_then(|d| d.as_array()) {
                    for d in descs {
                        if d.get("lang").and_then(|l| l.as_str()) == Some("en") {
                            summary = d
                                .get("value")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .chars()
                                .take(400)
                                .collect();
                            break;
                        }
                    }
                }
                return Some(serde_json::json!({
                    "cvss": cd.get("baseScore").cloned().unwrap_or(Value::Null),
                    "vector": cd.get("vectorString").cloned().unwrap_or(Value::Null),
                    "summary": summary,
                }));
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vkey() {
        assert_eq!(vkey("1.18.0"), vec![1, 18, 0]);
        assert_eq!(vkey("7.1p2"), vec![7, 1]);
        assert_eq!(vkey("2"), vec![2]);
        assert_eq!(vkey("2.4.49-1ubuntu2"), vec![2, 4, 49]);
    }

    #[test]
    fn test_version_satisfies() {
        assert!(version_satisfies("2.4.49", ">=2.4.49,<=2.4.50"));
        assert!(version_satisfies("2.4.50", ">=2.4.49,<=2.4.50"));
        assert!(!version_satisfies("2.4.51", ">=2.4.49,<=2.4.50"));
        assert!(!version_satisfies("2.4.48", ">=2.4.49,<=2.4.50"));
    }
}
