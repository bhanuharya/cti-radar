//! Correlation engine — pure, deterministic port of `cti_correlation.py`.
//!
//! Reads an org's findings.json + baseline.txt (from the orgs.json registry)
//! and produces graphs, summaries, PII-masked normalizations, and the status
//! lifecycle. No external calls, no secrets, no action.
//!
//! Rust-native: CPU-bound masking/normalization are data-parallel via rayon.

use crate::config::Config;
use once_cell::sync::OnceCell;
use rayon::prelude::*;
use regex::Regex;
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

pub const CANONICAL_STATUSES: [&str; 5] = [
    "OPEN",
    "IN_PROGRESS",
    "MITIGATED",
    "ACCEPTED_RISK",
    "RESOLVED",
];

pub const ANALYST_OWNED_STATUSES: [&str; 3] = ["IN_PROGRESS", "MITIGATED", "ACCEPTED_RISK"];

pub const DEFAULT_ORG: &str = "sample";

fn node_color(t: &str) -> &'static str {
    match t {
        "host" => "#50fa7b",
        "ip" => "#8be9fd",
        "cve" => "#ff5555",
        "brand" => "#bd93f9",
        "class" => "#ffb86c",
        _ => "#888",
    }
}

fn sev_order(s: &str) -> u8 {
    match s {
        "CRITICAL" => 0,
        "HIGH" => 1,
        "MEDIUM" => 2,
        "LOW" => 3,
        "INFO" => 4,
        _ => 99,
    }
}

static CFG: OnceCell<Config> = OnceCell::new();

pub fn init(cfg: Config) {
    let _ = CFG.set(cfg);
}

fn cfg() -> &'static Config {
    CFG.get().expect("correlation::init must be called first")
}

// ---------------------------------------------------------------------------
// registry
// ---------------------------------------------------------------------------

/// Global registry: slug -> {name, domains, findings, baseline}.
/// Backed by an RwLock so writes (register/domains) can reload it safely.
static REGISTRY: OnceCell<RwLock<Map<String, Value>>> = OnceCell::new();

fn registry() -> &'static RwLock<Map<String, Value>> {
    REGISTRY.get_or_init(|| {
        let m = load_registry_file();
        RwLock::new(m)
    })
}

fn load_registry_file() -> Map<String, Value> {
    let path = cfg().orgs_json();
    if !path.exists() {
        return Map::new();
    }
    match fs::read_to_string(&path) {
        Ok(txt) => match serde_json::from_str::<Map<String, Value>>(&txt) {
            Ok(m) => m,
            Err(_) => Map::new(),
        },
        Err(_) => Map::new(),
    }
}

pub fn reload_registry() {
    let m = load_registry_file();
    if let Some(reg) = REGISTRY.get() {
        if let Ok(mut w) = reg.write() {
            *w = m;
        }
    }
}

pub fn org_list() -> Vec<Value> {
    let reg = registry().read().unwrap();
    let mut slugs: Vec<&String> = reg.keys().collect();
    slugs.sort();
    slugs
        .into_iter()
        .map(|slug| {
            let o = &reg[slug];
            json!({
                "slug": slug,
                "name": o.get("name").and_then(|v| v.as_str()).unwrap_or(slug),
                "domains": o.get("domains").cloned().unwrap_or_else(|| json!([])),
            })
        })
        .collect()
}

pub fn org_get(slug: &str) -> Option<Value> {
    registry().read().unwrap().get(slug).cloned()
}

/// Resolve a registry path against the runtime data root, rejecting escapes.
fn resolve_registry_path(value: &str) -> Option<PathBuf> {
    if value.is_empty() {
        return None;
    }
    let root = cfg()
        .data_dir
        .canonicalize()
        .unwrap_or_else(|_| cfg().data_dir.clone());
    let p = PathBuf::from(value);
    if p.is_absolute() {
        let resolved = p.canonicalize().ok()?;
        return if resolved.starts_with(&root) {
            Some(resolved)
        } else {
            None
        };
    }
    // normalize "data/..." prefix -> relative to root
    let mut norm = value.to_string();
    if norm == "data" {
        norm = ".".to_string();
    } else if let Some(stripped) = norm.strip_prefix("data/") {
        norm = stripped.to_string();
    }
    let joined = root.join(&norm);
    let resolved = joined.canonicalize().ok()?;
    if resolved.starts_with(&root) {
        Some(resolved)
    } else {
        None
    }
}

/// (findings_path, baseline_path) for a registered org (None for unknown).
fn org_paths(org: &str) -> (Option<PathBuf>, Option<PathBuf>) {
    let entry = registry().read().unwrap().get(org).cloned();
    match entry {
        Some(entry) => {
            let fp = entry
                .get("findings")
                .and_then(|v| v.as_str())
                .and_then(resolve_registry_path);
            let bp = entry
                .get("baseline")
                .and_then(|v| v.as_str())
                .and_then(resolve_registry_path);
            if fp.is_some() {
                (fp, bp)
            } else {
                (None, None)
            }
        }
        None => (None, None),
    }
}

// ---------------------------------------------------------------------------
// CVE + IP helpers
// ---------------------------------------------------------------------------

fn cve_re() -> &'static Regex {
    static RE: OnceCell<Regex> = OnceCell::new();
    RE.get_or_init(|| Regex::new(r"CVE-\d{4}-\d{4,7}").unwrap())
}

fn date_re() -> &'static Regex {
    static RE: OnceCell<Regex> = OnceCell::new();
    RE.get_or_init(|| Regex::new(r"20\d\d-\d\d-\d\d").unwrap())
}

fn ipv4_re() -> &'static Regex {
    static RE: OnceCell<Regex> = OnceCell::new();
    RE.get_or_init(|| Regex::new(r"^\d{1,3}(\.\d{1,3}){3}$").unwrap())
}

fn norm_cves(v: &Value) -> Vec<String> {
    match v {
        Value::Array(arr) => arr
            .iter()
            .filter_map(|x| x.as_str())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty() && s != "None")
            .collect(),
        Value::String(s) => s
            .split(';')
            .map(|x| x.trim().to_string())
            .filter(|x| !x.is_empty() && x != "None")
            .collect(),
        _ => vec![],
    }
}

pub fn extract_cves(v: &Value) -> Vec<String> {
    let parts: Vec<&Value> = match v {
        Value::Array(arr) => arr.iter().collect(),
        other => vec![other],
    };
    let mut out: Vec<String> = vec![];
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for p in parts {
        let s = p.as_str().unwrap_or("");
        for m in cve_re().find_iter(s) {
            let cve = m.as_str().to_string();
            if seen.insert(cve.clone()) {
                out.push(cve);
            }
        }
    }
    out
}

pub fn single_public_ip(v: &Value) -> Option<String> {
    let s = v.as_str()?.trim();
    if !ipv4_re().is_match(s) {
        return None;
    }
    let octs: Vec<u32> = s.split('.').filter_map(|x| x.parse().ok()).collect();
    if octs.len() != 4 || octs.iter().any(|&x| x > 255) {
        return None;
    }
    let (a, b, c, d) = (octs[0], octs[1], octs[2], octs[3]);
    if a == 0 || a == 127 || a >= 224 {
        return None;
    }
    if a == 10 {
        return None;
    }
    if a == 172 && (16..=31).contains(&b) {
        return None;
    }
    if a == 192 && b == 168 {
        return None;
    }
    if a == 169 && b == 254 {
        return None;
    }
    if a == 100 && (64..=127).contains(&b) {
        return None;
    }
    let _ = (c, d);
    Some(s.to_string())
}

// ---------------------------------------------------------------------------
// PII masking
// ---------------------------------------------------------------------------

fn pii_keys() -> &'static std::collections::HashSet<String> {
    static KEYS: OnceCell<std::collections::HashSet<String>> = OnceCell::new();
    KEYS.get_or_init(|| {
        [
            "password",
            "passwd",
            "secret",
            "token",
            "apikey",
            "apisecret",
            "email",
            "mail",
            "phone",
            "mobile",
            "accountno",
            "accountnumber",
            "card",
            "cardno",
            "cardnumber",
            "pan",
            "cvv",
            "cif",
            "login",
            "username",
            "userid",
            "clientip",
            "client_ip",
            "dest_ip",
            "sourceip",
            "deviceid",
            "device_id",
            "sessionid",
            "session_id",
            "authorization",
            "auth",
            "firstname",
            "lastname",
            "middlename",
            "fullname",
            "ssn",
            "nik",
            "npwp",
            "createdby",
            "modifiedby",
            "realm",
            "aduser",
        ]
        .iter()
        .map(|s| s.replace(['_', '-'], ""))
        .collect()
    })
}

fn mask_email(v: &str) -> String {
    let re = Regex::new(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}").unwrap();
    re.replace_all(v, |caps: &regex::Captures| {
        let whole = &caps[0];
        let at = whole.find('@').unwrap();
        let first = &whole[..1];
        let domain = &whole[at..];
        format!("{}***{}", first, domain)
    })
    .to_string()
}

fn mask_phone(v: &str) -> String {
    let re = fancy_regex::Regex::new(r"(?<![\d*])\d{8,}(?![\d*])").unwrap();
    re.replace_all(v, |caps: &fancy_regex::Captures| {
        let digits = caps.get(0).map(|m| m.as_str()).unwrap_or("");
        if digits.len() <= 6 {
            "*".repeat(digits.len())
        } else {
            let head = &digits[..4];
            let tail = &digits[digits.len() - 2..];
            format!("{}{}{}", head, "*".repeat(digits.len() - 6), tail)
        }
    })
    .to_string()
}

fn mask_big_number(v: &str) -> String {
    let re = fancy_regex::Regex::new(r"\d{6,}").unwrap();
    re.replace_all(v, |caps: &fancy_regex::Captures| {
        let d = caps.get(0).map(|m| m.as_str()).unwrap_or("");
        if d.len() <= 5 {
            if d.is_empty() {
                d.to_string()
            } else {
                format!("{}{}", &d[..1], "*".repeat(d.len() - 1))
            }
        } else {
            format!(
                "{}{}{}",
                &d[..2],
                "*".repeat(d.len() - 4),
                &d[d.len() - 2..]
            )
        }
    })
    .to_string()
}

fn mask_ip_in_text(v: &str) -> String {
    let re =
        fancy_regex::Regex::new(r"(?<![0-9.])(\d{1,3}\.\d{1,3})\.\d{1,3}\.\d{1,3}(?!\d)").unwrap();
    re.replace_all(v, |caps: &fancy_regex::Captures| {
        let prefix = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        format!("{}.*.*", prefix)
    })
    .to_string()
}

fn mask_value(key: &str, value: &Value) -> Value {
    if value.is_null() || value.is_boolean() || value.is_number() {
        return value.clone();
    }
    let s = value.as_str().unwrap_or("");
    let k = key.to_lowercase().replace(['_', '-'], "");
    if pii_keys().contains(&k) && !s.trim().is_empty() {
        return Value::String(if s.len() <= 2 {
            "***".to_string()
        } else {
            let mask_len = (s.chars().count() - 1).min(8);
            format!("{}{}", &s[..1], "*".repeat(mask_len))
        });
    }
    let mut out = mask_email(s);
    out = mask_phone(&out);
    out = mask_big_number(&out);
    out = mask_ip_in_text(&out);
    Value::String(out)
}

fn mask_deep(obj: &Value, key: &str) -> Value {
    match obj {
        Value::Object(map) => {
            let mut out = Map::new();
            for (k, v) in map {
                out.insert(k.clone(), mask_deep(v, k));
            }
            Value::Object(out)
        }
        Value::Array(arr) => Value::Array(arr.iter().map(|x| mask_deep(x, key)).collect()),
        Value::String(_) => mask_value(key, obj),
        other => other.clone(),
    }
}

const MASK_FIELDS: [&str; 17] = [
    "description",
    "impact",
    "status",
    "discovery",
    "title",
    "category",
    "remediation",
    "proof_chain",
    "reproduction_steps",
    "topics_exposed",
    "evidence",
    "status_detail",
    "ai_provenance",
    "ai_suggestions",
    "ai_impact",
    "ai_grading",
    "status_history",
];

fn mask_finding_deep(nf: Value) -> Value {
    let mut out = nf;
    if let Value::Object(map) = &mut out {
        for field in MASK_FIELDS {
            if let Some(v) = map.get(field).cloned() {
                map.insert(field.to_string(), mask_deep(&v, field));
            }
        }
    }
    out
}

fn enrich_finding_evidence(f: &mut Value) {
    let obj = match f.as_object_mut() {
        Some(o) => o,
        None => return,
    };
    let pc = obj.get("proof_chain").cloned();
    let steps = obj.get("reproduction_steps").cloned();
    if !matches!(steps, Some(Value::Array(ref a)) if !a.is_empty()) {
        let new_steps = match pc {
            Some(Value::Array(a)) if !a.is_empty() => Value::Array(a.clone()),
            _ => json!([]),
        };
        obj.insert("reproduction_steps".to_string(), new_steps);
    }
    let steps = obj
        .get("reproduction_steps")
        .cloned()
        .unwrap_or_else(|| json!([]));
    if let Some(Value::Object(ev)) = obj.get_mut("evidence") {
        if !ev.contains_key("commands") && steps.is_array() {
            let mut commands = Map::new();
            for s in steps.as_array().unwrap() {
                let st = s.as_str().unwrap_or("");
                let label = st
                    .split(" -> ")
                    .next()
                    .unwrap_or("")
                    .chars()
                    .take(40)
                    .collect::<String>();
                let snippet = if st.contains(" -> ") {
                    st.split_once(" -> ")
                        .map(|x| x.1)
                        .unwrap_or("")
                        .chars()
                        .take(120)
                        .collect::<String>()
                } else {
                    st.chars().take(120).collect::<String>()
                };
                commands.insert(
                    label.chars().take(40).collect::<String>(),
                    Value::String(snippet),
                );
            }
            ev.insert("commands".to_string(), Value::Object(commands));
        }
    }
}

// ---------------------------------------------------------------------------
// lifecycle
// ---------------------------------------------------------------------------

pub fn now_iso() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    // UTC formatted as YYYY-MM-DDTHH:MM:SSZ
    let days = secs / 86400;
    let rem = secs % 86400;
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    // days since epoch -> civil date (algorithm: Howard Hinnant's days_to_civil)
    let z = days as i64 + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mth = if mp < 10 { mp + 3 } else { mp - 9 };
    let yr = if mth <= 2 { y + 1 } else { y };
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", yr, mth, d, h, m, s)
}

pub fn canonical_status(f: &Value) -> String {
    let s = f
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    if s.is_empty() {
        return "OPEN".to_string();
    }
    let u = s.to_uppercase();
    if CANONICAL_STATUSES.contains(&u.as_str()) {
        return u;
    }
    if u.contains("ACCEPTED") && u.contains("RISK") {
        return "ACCEPTED_RISK".to_string();
    }
    if u.contains("IN_PROGRESS") || u.contains("IN PROGRESS") || u.contains("IN-PROGRESS") {
        return "IN_PROGRESS".to_string();
    }
    if u.contains("MITIGATED") {
        return "MITIGATED".to_string();
    }
    "OPEN".to_string()
}

fn is_positive_status(s: &str) -> bool {
    let u = s.to_uppercase();
    u.contains("SECURE") || u.contains("CLEAN")
}

// ---------------------------------------------------------------------------
// identity + lifecycle
// ---------------------------------------------------------------------------

fn finding_port(f: &Value) -> Value {
    for v in [f.get("port"), f.get("evidence").and_then(|e| e.get("port"))]
        .into_iter()
        .flatten()
    {
        if let Some(n) = v.as_i64() {
            if (1..=65535).contains(&n) {
                return Value::Number(n.into());
            }
        }
        if let Some(s) = v.as_str() {
            if let Ok(n) = s.parse::<i64>() {
                if (1..=65535).contains(&n) {
                    return Value::Number(n.into());
                }
            }
        }
    }
    Value::String("".to_string())
}

pub fn identity_key(f: &Value) -> String {
    let tgt = f
        .get("target")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_lowercase();
    let src = f
        .get("source")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_lowercase();
    let cat = f
        .get("category")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_lowercase();
    let port = finding_port(f);

    let port_s = match &port {
        Value::Number(n) => n.to_string(),
        _ => String::new(),
    };

    if src == "scan-tls" {
        return format!("tls|{}|{}", tgt, port_s);
    }
    if src == "scan-login" {
        return format!("login|{}|", tgt);
    }
    if src == "scan-headers" {
        return format!("headers|{}|", tgt);
    }
    if src == "baseline-diff" {
        let p = f.get("port").and_then(|v| v.as_i64()).unwrap_or(0);
        return format!(
            "diff|{}|{}",
            tgt,
            if p > 0 { p.to_string() } else { "host".into() }
        );
    }
    if src == "scan-version" {
        let prods = f
            .get("evidence")
            .and_then(|e| e.get("versions"))
            .and_then(|v| v.as_array())
            .map(|vs| {
                let mut names: Vec<String> = vs
                    .iter()
                    .filter_map(|v| v.get("product").and_then(|p| p.as_str()))
                    .map(|p| p.to_string())
                    .collect();
                names.sort();
                names.join(",")
            })
            .unwrap_or_default();
        let prods = prods.chars().take(120).collect::<String>();
        return format!("version|{}|{}", tgt, prods);
    }
    if src == "scan-cve" {
        let cves = sorted_cves(f, 160);
        return format!("cve|{}|{}", tgt, if cves.is_empty() { cat } else { cves });
    }
    if src == "ai-assess" {
        return format!("ai|{}|{}", tgt, cat);
    }
    if src == "scan-enum" {
        return format!("surface-enum|{}|", tgt);
    }
    if src == "scan-surface" {
        return format!("surface-web|{}|{}", tgt, port_s);
    }
    if src == "scan-services" {
        return format!("surface-tcp|{}|{}", tgt, port_s);
    }
    if src == "cve-share"
        || src == "ip-co-residency"
        || src == "internetdb"
        || src.starts_with("corr")
    {
        let cves = sorted_cves(f, 160);
        let sig = if cves.is_empty() { cat } else { cves };
        return format!("corr|{}|{}|{}", src, tgt, sig);
    }
    if src.starts_with("ohack") {
        let target_url = f
            .get("evidence")
            .and_then(|e| e.get("url"))
            .and_then(|u| u.as_str())
            .unwrap_or("");
        let path = target_url
            .split("://")
            .nth(1)
            .unwrap_or("")
            .trim_end_matches('/')
            .to_lowercase();
        let path = path.chars().take(160).collect::<String>();
        return format!("ohack|{}|{}|{}", tgt, path, cat);
    }
    format!(
        "{}|{}|{}",
        if src.is_empty() { "unknown" } else { &src },
        tgt,
        cat
    )
}

fn sorted_cves(f: &Value, cap: usize) -> String {
    let mut cves: Vec<String> = f.get("related_cves").map(norm_cves).unwrap_or_default();
    cves.sort();
    cves.join(",").chars().take(cap).collect()
}

pub fn ensure_identity(f: &mut Value) -> String {
    let ik = f
        .get("identity_key")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    if ik.is_empty() {
        let new_ik = identity_key(f);
        if let Value::Object(map) = f {
            map.insert("identity_key".to_string(), Value::String(new_ik.clone()));
        }
        new_ik
    } else {
        ik
    }
}

fn extract_found_date(f: &Value, org: &str, meta_date: Option<&str>) -> Option<String> {
    for key in ["status", "status_detail", "discovery"] {
        if let Some(v) = f.get(key).and_then(|x| x.as_str()) {
            if let Some(m) = date_re().find(v) {
                return Some(m.as_str().to_string());
            }
        }
    }
    match meta_date {
        Some(d) => Some(d.to_string()),
        None => load_meta_date(org),
    }
}

pub fn load_meta_date(org: &str) -> Option<String> {
    let (_, _, meta_date, _) = read_org_files(org);
    meta_date
}

fn ensure_lifecycle(f: &mut Value, org: &str, meta_date: Option<&str>) {
    let mut fd = f
        .get("found_date")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    if fd.as_deref().unwrap_or("").is_empty() {
        fd = extract_found_date(f, org, meta_date);
    }
    if fd.as_deref().unwrap_or("").is_empty() {
        fd = Some(now_iso());
    }
    let fd = fd.unwrap();

    if f.get("first_seen").is_none() {
        if let Value::Object(map) = f {
            map.insert("first_seen".to_string(), Value::String(fd.clone()));
        }
    }
    if f.get("last_seen").is_none() {
        if let Value::Object(map) = f {
            map.insert("last_seen".to_string(), Value::String(fd.clone()));
        }
    }
    let sh = f.get("status_history").cloned();
    if !matches!(sh, Some(Value::Array(ref a)) if !a.is_empty()) {
        let status = f
            .get("status")
            .and_then(|s| s.as_str())
            .unwrap_or("OPEN")
            .to_string();
        if let Value::Object(map) = f {
            map.insert(
                "status_history".to_string(),
                json!([{
                    "at": fd,
                    "from": "",
                    "to": status,
                    "by": "scan",
                    "note": "initial"
                }]),
            );
        }
    }
}

pub fn migrate_finding(f: &mut Value, org: &str, meta_date: Option<&str>) {
    let raw = f
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    let u = raw.to_uppercase();
    if CANONICAL_STATUSES.contains(&u.as_str()) {
        if let Value::Object(map) = f {
            map.insert(
                "status".to_string(),
                Value::String(if u.is_empty() { "OPEN".into() } else { u }),
            );
        }
    } else {
        let has_detail = f.get("status_detail").is_some();
        let status = canonical_status(f);
        if let Value::Object(map) = f {
            if !has_detail && !raw.is_empty() {
                map.insert("status_detail".to_string(), Value::String(raw.clone()));
            }
            map.insert("status".to_string(), Value::String(status));
        }
    }
    let positive = is_positive_status(&raw);
    if positive && !f.get("positive").and_then(|v| v.as_bool()).unwrap_or(false) {
        if let Value::Object(map) = f {
            map.insert("positive".to_string(), Value::Bool(true));
        }
    }
    ensure_lifecycle(f, org, meta_date);
}

// ---------------------------------------------------------------------------
// snapshot diff
// ---------------------------------------------------------------------------

pub fn build_snapshot(fs: &[Value]) -> Map<String, Value> {
    let mut snap = Map::new();
    for f in fs {
        let fid = f
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .to_string();
        if fid.is_empty() {
            continue;
        }
        snap.insert(
            fid,
            json!({
                "severity": f.get("severity").and_then(|v| v.as_str()).unwrap_or("").to_uppercase(),
                "status": canonical_status(f),
            }),
        );
    }
    snap
}

pub fn diff_snapshot(
    prev: &Map<String, Value>,
    cur: &Map<String, Value>,
) -> (Vec<String>, Vec<String>, Vec<String>) {
    let mut new_ids: Vec<String> = cur
        .keys()
        .filter(|k| !prev.contains_key(*k))
        .cloned()
        .collect();
    let mut resolved: Vec<String> = prev
        .keys()
        .filter(|k| !cur.contains_key(*k))
        .cloned()
        .collect();
    let mut changed: Vec<String> = cur
        .keys()
        .filter(|k| prev.contains_key(*k) && prev[*k] != cur[*k])
        .cloned()
        .collect();
    new_ids.sort();
    resolved.sort();
    changed.sort();
    (new_ids, resolved, changed)
}

// ---------------------------------------------------------------------------
// history ledger
// ---------------------------------------------------------------------------

fn history_path(slug: &str) -> PathBuf {
    cfg().org_dir(slug).join("history.json")
}

fn atomic_write_bytes(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
    }
    let pid = std::process::id();
    let tmp = dir.join(format!(
        ".{}.tmp.{}.{}",
        path.file_name().and_then(|s| s.to_str()).unwrap_or("f"),
        pid,
        uuid::Uuid::new_v4().simple()
    ));
    let result = (|| -> std::io::Result<()> {
        {
            use std::io::Write;
            let mut f = fs::File::create(&tmp)?;
            f.write_all(data)?;
            f.flush()?;
            f.sync_all()?;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600));
        }
        fs::rename(&tmp, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

pub fn atomic_write_json(path: &Path, data: &Value) -> std::io::Result<()> {
    let mut buf = serde_json::to_vec_pretty(data).unwrap_or_default();
    buf.push(b'\n');
    atomic_write_bytes(path, &buf)
}

pub fn atomic_write_text(path: &Path, text: &str) -> std::io::Result<()> {
    atomic_write_bytes(path, text.as_bytes())
}

pub fn append_history(slug: &str, event: Value) {
    if slug.is_empty() {
        return;
    }
    let hp = history_path(slug);
    let mut events: Vec<Value> = match fs::read_to_string(&hp) {
        Ok(txt) => serde_json::from_str::<Vec<Value>>(&txt).unwrap_or_default(),
        Err(_) => vec![],
    };
    events.push(event);
    let _ = atomic_write_json(&hp, &Value::Array(events));
}

pub fn load_history(slug: &str) -> Vec<Value> {
    let hp = history_path(slug);
    match fs::read_to_string(&hp) {
        Ok(txt) => serde_json::from_str::<Vec<Value>>(&txt).unwrap_or_default(),
        Err(_) => vec![],
    }
}

// ---------------------------------------------------------------------------
// read-through cache + load_data
// ---------------------------------------------------------------------------

static DATA_CACHE: OnceCell<
    RwLock<HashMap<String, (SystemTime, (Vec<Value>, Vec<String>, Option<String>, Value))>>,
> = OnceCell::new();

fn data_cache(
) -> &'static RwLock<HashMap<String, (SystemTime, (Vec<Value>, Vec<String>, Option<String>, Value))>>
{
    DATA_CACHE.get_or_init(|| RwLock::new(HashMap::new()))
}

const DATA_CACHE_TTL_SECS: u64 = 15;

fn read_org_files(org: &str) -> (Vec<Value>, Vec<String>, Option<String>, Value) {
    let (findings_path, baseline_path) = org_paths(org);
    let mut fs: Vec<Value> = vec![];
    let mut baseline: Vec<String> = vec![];
    let mut meta_date: Option<String> = None;
    let mut meta = Value::Null;

    if let Some(fp) = findings_path {
        if fp.exists() {
            if let Ok(txt) = fs::read_to_string(&fp) {
                if let Ok(Value::Object(d)) = serde_json::from_str::<Value>(&txt) {
                    fs = d
                        .get("findings")
                        .and_then(|v| v.as_array())
                        .cloned()
                        .unwrap_or_default();
                    if let Some(m) = d.get("meta") {
                        if let Value::Object(_) = m {
                            let date_val = m
                                .get("date")
                                .or_else(|| m.get("scan_date"))
                                .and_then(|v| v.as_str())
                                .unwrap_or("");
                            if let Some(mt) = date_re().find(date_val) {
                                meta_date = Some(mt.as_str().to_string());
                            }
                            meta = m.clone();
                        } else {
                            meta = Value::Null;
                        }
                    }
                }
            }
        }
    }

    if let Some(bp) = baseline_path {
        if bp.exists() {
            if let Ok(txt) = fs::read_to_string(&bp) {
                baseline = txt
                    .lines()
                    .map(|l| l.trim().to_string())
                    .filter(|l| !l.is_empty() && !l.starts_with('#'))
                    .collect();
            }
        }
    }

    (fs, baseline, meta_date, meta)
}

fn cached_org_data(org: &str) -> (Vec<Value>, Vec<String>, Option<String>, Value) {
    let now = SystemTime::now();
    {
        let cache = data_cache().read().unwrap();
        if let Some((ts, data)) = cache.get(org) {
            if now.duration_since(*ts).unwrap_or_default().as_secs() < DATA_CACHE_TTL_SECS {
                return data.clone();
            }
        }
    }
    // read fresh under write lock to avoid stale-after-write race
    let data = read_org_files(org);
    {
        let mut cache = data_cache().write().unwrap();
        cache.insert(org.to_string(), (now, data.clone()));
    }
    data
}

pub fn invalidate_org_cache(org: &str) {
    let mut cache = data_cache().write().unwrap();
    cache.remove(org);
}

pub fn load_data(org: &str) -> (Vec<Value>, Vec<String>) {
    let (fs, baseline, _, _) = cached_org_data(org);
    (fs, baseline)
}

// ---------------------------------------------------------------------------
// summaries
// ---------------------------------------------------------------------------

pub fn org_findings_path(org: &str) -> Option<PathBuf> {
    let (fp, _) = org_paths(org);
    fp
}

/// Absolute path to the org's data dir under the runtime data root.
pub fn org_dir(slug: &str) -> PathBuf {
    cfg().org_dir(slug)
}

/// Expose the orgs.json path for registry writers.
pub fn cfg_path_orgs_json() -> PathBuf {
    cfg().orgs_json()
}

/// Return the raw meta dict (read-only).
pub fn load_meta(org: &str) -> Value {
    let (_, _, _, meta) = cached_org_data(org);
    meta
}

/// Latest correlation report stored in findings meta (parity with Python
/// `correlation_report`; Value::Null when absent).
pub fn correlation_report(org: &str) -> Value {
    load_meta(org)
        .get("correlation")
        .cloned()
        .unwrap_or(Value::Null)
}

pub fn summary_from_data(fs: &[Value], baseline: &[String]) -> Value {
    let mut sev: HashMap<String, usize> = HashMap::new();
    let mut live = 0usize;
    let mut resolved = 0usize;
    for f in fs {
        if canonical_status(f) == "RESOLVED" {
            resolved += 1;
            continue;
        }
        live += 1;
        let s = f
            .get("severity")
            .and_then(|v| v.as_str())
            .unwrap_or("INFO")
            .to_uppercase();
        *sev.entry(s).or_insert(0) += 1;
    }
    json!({
        "findings_total": live,
        "resolved_total": resolved,
        "severity": sev,
        "baseline": baseline.len(),
    })
}

pub fn fleet_spread_from_data(fs: &[Value]) -> Vec<Value> {
    let mut cve2hosts: HashMap<String, std::collections::BTreeSet<String>> = HashMap::new();
    for f in fs {
        for c in norm_cves(f.get("related_cves").unwrap_or(&Value::Null)) {
            let tgt = f
                .get("target")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            cve2hosts.entry(c).or_default().insert(tgt);
        }
    }
    let mut out: Vec<(String, Vec<String>)> = cve2hosts
        .into_iter()
        .map(|(c, hs)| (c, hs.into_iter().collect()))
        .collect();
    out.sort_by(|a, b| b.1.len().cmp(&a.1.len()).then(a.0.cmp(&b.0)));
    out.into_iter()
        .map(|(cve, hosts)| json!({"cve": cve, "hosts": hosts}))
        .collect()
}

pub fn ip_sharing_from_data(fs: &[Value]) -> Vec<Value> {
    let mut ip2hosts: HashMap<String, std::collections::BTreeSet<String>> = HashMap::new();
    for f in fs {
        let ip = f
            .get("ip")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .to_string();
        let tgt = f
            .get("target")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .to_string();
        if !ip.is_empty() && ip != "None" && !tgt.is_empty() {
            ip2hosts.entry(ip).or_default().insert(tgt);
        }
    }
    let mut out: Vec<(String, Vec<String>)> = ip2hosts
        .into_iter()
        .map(|(ip, hs)| (ip, hs.into_iter().collect()))
        .collect();
    out.sort_by(|a, b| b.1.len().cmp(&a.1.len()).then(a.0.cmp(&b.0)));
    out.into_iter()
        .map(|(ip, hosts)| json!({"ip": ip, "hosts": hosts}))
        .collect()
}

fn root_domain(host: &str, domains: &[String]) -> String {
    let h = host.trim().to_lowercase().trim_end_matches('.').to_string();
    let roots: Vec<String> = domains
        .iter()
        .map(|d| d.trim().to_lowercase().trim_end_matches('.').to_string())
        .filter(|d| !d.is_empty())
        .collect();
    for root in &roots {
        if h == *root || h.ends_with(&format!(".{}", root)) {
            return root.clone();
        }
    }
    if ipv4_re().is_match(&h) {
        return "raw-ip".to_string();
    }
    "other".to_string()
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

pub fn build_graph_from_data(fs: &[Value], baseline: &[String], domains: &[String]) -> Value {
    let mut nodes: Map<String, Value> = Map::new();
    let mut edges: Vec<Value> = vec![];

    let add_node = |nodes: &mut Map<String, Value>,
                    id: String,
                    label: String,
                    type_: String,
                    extra: Map<String, Value>| {
        if !nodes.contains_key(&id) {
            let mut n = Map::new();
            n.insert("id".into(), Value::String(id.clone()));
            n.insert("label".into(), Value::String(label));
            n.insert("type".into(), Value::String(type_.clone()));
            n.insert(
                "color".into(),
                Value::String(node_color(&type_).to_string()),
            );
            for (k, v) in extra {
                n.insert(k, v);
            }
            nodes.insert(id, Value::Object(n));
        }
    };

    for f in fs {
        let tgt = f
            .get("target")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .to_string();
        let tgt = if tgt.is_empty() { "?".to_string() } else { tgt };
        let sev = f
            .get("severity")
            .and_then(|v| v.as_str())
            .unwrap_or("INFO")
            .to_uppercase();
        let cat = f
            .get("category")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .to_string();

        let host_title = format!(
            "<b>{}</b><br>sev: {} — {}",
            html_escape(&tgt),
            html_escape(&sev),
            html_escape(&cat)
        );
        add_node(
            &mut nodes,
            format!("host:{}", tgt),
            html_escape(&tgt),
            "host".into(),
            {
                let mut m = Map::new();
                m.insert("sev".into(), Value::String(sev.clone()));
                m.insert("title".into(), Value::String(host_title));
                m
            },
        );

        let ip = f
            .get("ip")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .to_string();
        if !ip.is_empty() && ip != "None" {
            add_node(
                &mut nodes,
                format!("ip:{}", ip),
                html_escape(&ip),
                "ip".into(),
                {
                    let mut m = Map::new();
                    m.insert("sev".into(), Value::String(sev.clone()));
                    m.insert(
                        "title".into(),
                        Value::String(format!("IP: {}", html_escape(&ip))),
                    );
                    m
                },
            );
            edges.push(json!({"from": format!("ip:{}", ip), "to": format!("host:{}", tgt), "label": "resolves→"}));
        }

        let root = root_domain(&tgt, domains);
        if root != "raw-ip" && root != "other" {
            add_node(
                &mut nodes,
                format!("brand:{}", root),
                html_escape(&root),
                "brand".into(),
                Map::new(),
            );
            edges.push(json!({"from": format!("host:{}", tgt), "to": format!("brand:{}", root), "label": "part-of"}));
        }

        if !cat.is_empty() {
            let cat_label = cat.chars().take(40).collect::<String>();
            add_node(
                &mut nodes,
                format!("class:{}", cat),
                html_escape(&cat_label),
                "class".into(),
                {
                    let mut m = Map::new();
                    m.insert(
                        "title".into(),
                        Value::String(format!(
                            "Class: {}",
                            html_escape(&cat.chars().take(80).collect::<String>())
                        )),
                    );
                    m
                },
            );
            edges.push(json!({"from": format!("host:{}", tgt), "to": format!("class:{}", cat), "label": "is"}));
        }

        for c in norm_cves(f.get("related_cves").unwrap_or(&Value::Null)) {
            add_node(
                &mut nodes,
                format!("cve:{}", c),
                html_escape(&c),
                "cve".into(),
                {
                    let mut m = Map::new();
                    m.insert("sev".into(), Value::String(sev.clone()));
                    m.insert(
                        "title".into(),
                        Value::String(format!("CVE: {}", html_escape(&c))),
                    );
                    m
                },
            );
            edges.push(json!({"from": format!("host:{}", tgt), "to": format!("cve:{}", c), "label": "has"}));
        }
    }

    for h in baseline {
        if !nodes.contains_key(&format!("host:{}", h)) {
            let is_ip = ipv4_re().is_match(h);
            if is_ip {
                add_node(
                    &mut nodes,
                    format!("ip:{}", h),
                    html_escape(h),
                    "ip".into(),
                    Map::new(),
                );
                add_node(
                    &mut nodes,
                    format!("host:{}", h),
                    html_escape(h),
                    "host".into(),
                    {
                        let mut m = Map::new();
                        m.insert("sev".into(), Value::String("INFO".into()));
                        m
                    },
                );
                edges.push(json!({"from": format!("ip:{}", h), "to": format!("host:{}", h), "label": "resolves→"}));
            } else {
                add_node(
                    &mut nodes,
                    format!("host:{}", h),
                    html_escape(h),
                    "host".into(),
                    {
                        let mut m = Map::new();
                        m.insert("sev".into(), Value::String("INFO".into()));
                        m
                    },
                );
                let root = root_domain(h, domains);
                if root != "raw-ip" && root != "other" {
                    add_node(
                        &mut nodes,
                        format!("brand:{}", root),
                        html_escape(&root),
                        "brand".into(),
                        Map::new(),
                    );
                    edges.push(json!({"from": format!("host:{}", h), "to": format!("brand:{}", root), "label": "part-of"}));
                }
            }
        }
    }

    let mut ip_clusters: HashMap<String, Vec<String>> = HashMap::new();
    for e in &edges {
        let (from, to, label) = (
            e.get("from").and_then(|v| v.as_str()).unwrap_or(""),
            e.get("to").and_then(|v| v.as_str()).unwrap_or(""),
            e.get("label").and_then(|v| v.as_str()).unwrap_or(""),
        );
        if label == "resolves→" && from.starts_with("ip:") {
            ip_clusters
                .entry(from.to_string())
                .or_default()
                .push(to.to_string());
        }
    }

    for (ip, hosts) in &ip_clusters {
        if hosts.len() >= 2 {
            let ip_label = ip.strip_prefix("ip:").unwrap_or(ip);
            add_node(
                &mut nodes,
                format!("ip:{}", ip_label),
                html_escape(ip_label),
                "ip".into(),
                {
                    let mut m = Map::new();
                    m.insert("cluster".into(), Value::Bool(true));
                    m.insert(
                        "title".into(),
                        Value::String(format!("<b>Shared box</b><br>{} hosts", hosts.len())),
                    );
                    m
                },
            );
            for h in &hosts[1..] {
                edges.push(json!({"from": hosts[0].clone(), "to": h.clone(), "label": "co-resident", "dashes": true, "color": "#6a6a6a"}));
            }
        }
    }

    json!({
        "nodes": nodes.values().cloned().collect::<Vec<Value>>(),
        "edges": edges,
        "meta": {"findings": fs.len(), "baseline": baseline.len()},
    })
}

// ---------------------------------------------------------------------------
// normalization
// ---------------------------------------------------------------------------

fn tier_for(f: &Value) -> String {
    let st = f
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_uppercase();
    let sd = f
        .get("status_detail")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_uppercase();
    if sd.contains("AI-ASSESSED") {
        "AI".to_string()
    } else if sd.contains("CONFIRMED") {
        "CONFIRMED".to_string()
    } else if sd.contains("CORRELATED") || st.contains("CORRELATED") {
        "CORRELATED".to_string()
    } else {
        "OTHER".to_string()
    }
}

pub fn normalize_finding(f: &Value, org: &str, meta_date: Option<&str>) -> Value {
    let mut nf = f.clone();
    let meta_date = meta_date
        .map(|s| s.to_string())
        .or_else(|| load_meta_date(org));
    let fd = extract_found_date(f, org, meta_date.as_deref());
    if let Value::Object(map) = &mut nf {
        map.insert(
            "found_date".to_string(),
            fd.map(Value::String).unwrap_or(Value::Null),
        );
    }
    migrate_finding(&mut nf, org, meta_date.as_deref());

    let tier = tier_for(&nf);
    if let Value::Object(map) = &mut nf {
        map.insert("tier".to_string(), Value::String(tier));
    }

    let cve_links: Vec<String> = extract_cves(f.get("related_cves").unwrap_or(&Value::Null))
        .into_iter()
        .map(|c| format!("https://nvd.nist.gov/vuln/detail/{}", c))
        .collect();
    let ip = single_public_ip(f.get("ip").unwrap_or(&Value::Null));
    if let Value::Object(map) = &mut nf {
        map.insert(
            "cve_links".to_string(),
            Value::Array(cve_links.iter().map(|c| Value::String(c.clone())).collect()),
        );
        map.insert(
            "shodan_link".to_string(),
            ip.as_ref()
                .map(|i| Value::String(format!("https://www.shodan.io/host/{}", i)))
                .unwrap_or(Value::Null),
        );
        map.insert(
            "internetdb_link".to_string(),
            ip.map(|i| Value::String(format!("https://internetdb.shodan.io/{}", i)))
                .unwrap_or(Value::Null),
        );
    }

    enrich_finding_evidence(&mut nf);
    mask_finding_deep(nf)
}

pub fn normalize_finding_light(f: &Value, org: &str, meta_date: Option<&str>) -> Value {
    let mut nf = f.clone();
    let meta_date = meta_date
        .map(|s| s.to_string())
        .or_else(|| load_meta_date(org));
    let fd = extract_found_date(f, org, meta_date.as_deref());
    if let Value::Object(map) = &mut nf {
        map.insert(
            "found_date".to_string(),
            fd.map(Value::String).unwrap_or(Value::Null),
        );
    }
    migrate_finding(&mut nf, org, meta_date.as_deref());
    let tier = tier_for(&nf);
    let cves = extract_cves(f.get("related_cves").unwrap_or(&Value::Null));
    let ip = single_public_ip(f.get("ip").unwrap_or(&Value::Null));
    let confidence = nf
        .get("provenance")
        .and_then(|p| p.get("confidence"))
        .cloned();

    json!({
        "id": nf.get("id").cloned().unwrap_or(Value::Null),
        "title": mask_value("title", nf.get("title").unwrap_or(&Value::Null)),
        "severity": nf.get("severity").cloned().unwrap_or(Value::Null),
        "category": mask_value("category", nf.get("category").unwrap_or(&Value::Null)),
        "status": nf.get("status").cloned().unwrap_or(Value::Null),
        "status_detail": mask_value("status_detail", nf.get("status_detail").unwrap_or(&Value::Null)),
        "positive": nf.get("positive").and_then(|v| v.as_bool()).unwrap_or(false),
        "tier": tier,
        "confidence": confidence.unwrap_or(Value::Null),
        "target": nf.get("target").cloned().unwrap_or(Value::Null),
        "ip": nf.get("ip").cloned().unwrap_or(Value::Null),
        "found_date": nf.get("found_date").cloned().unwrap_or(Value::Null),
        "first_seen": nf.get("first_seen").cloned().unwrap_or(Value::Null),
        "last_seen": nf.get("last_seen").cloned().unwrap_or(Value::Null),
        "related_cves": f.get("related_cves").cloned().unwrap_or(Value::Null),
        "cve_links": cves.iter().map(|c| Value::String(format!("https://nvd.nist.gov/vuln/detail/{}", c))).collect::<Vec<Value>>(),
        "shodan_link": ip.as_ref().map(|i| Value::String(format!("https://www.shodan.io/host/{}", i))).unwrap_or(Value::Null),
        "internetdb_link": ip.map(|i| Value::String(format!("https://internetdb.shodan.io/{}", i))).unwrap_or(Value::Null),
    })
}

// ---------------------------------------------------------------------------
// top-level builders
// ---------------------------------------------------------------------------

pub fn find_finding(org: &str, id: &str) -> Option<Value> {
    let (fs, _) = load_data(org);
    fs.into_iter().find(|f| {
        f.get("id")
            .and_then(|v| v.as_str())
            .map(|s| s == id)
            .unwrap_or(false)
    })
}

pub fn build_graph(org: &str) -> Value {
    let (fs, baseline) = load_data(org);
    let domains: Vec<String> = org_get(org)
        .and_then(|o| o.get("domains").cloned())
        .and_then(|d| d.as_array().cloned())
        .unwrap_or_default()
        .into_iter()
        .filter_map(|v| v.as_str().map(|s| s.to_string()))
        .collect();
    build_graph_from_data(&fs, &baseline, &domains)
}

pub fn fleet_spread(org: &str) -> Vec<Value> {
    let (fs, _) = load_data(org);
    fleet_spread_from_data(&fs)
}

pub fn ip_sharing(org: &str) -> Vec<Value> {
    let (fs, _) = load_data(org);
    ip_sharing_from_data(&fs)
}

pub fn summary(org: &str) -> Value {
    let (fs, baseline) = load_data(org);
    summary_from_data(&fs, &baseline)
}

/// Sort findings by severity then recency, per the dashboard's sort param.
pub fn sort_findings(mut fs: Vec<Value>, sort: Option<&str>) -> Vec<Value> {
    match sort {
        Some("severity") => {
            fs.sort_by(|a, b| {
                let sa = a.get("severity").and_then(|v| v.as_str()).unwrap_or("INFO");
                let sb = b.get("severity").and_then(|v| v.as_str()).unwrap_or("INFO");
                sev_order(sa).cmp(&sev_order(sb)).then_with(|| {
                    let da = a.get("found_date").and_then(|v| v.as_str()).unwrap_or("");
                    let db = b.get("found_date").and_then(|v| v.as_str()).unwrap_or("");
                    db.cmp(da)
                })
            });
        }
        _ => {
            // default: recency
            fs.sort_by(|a, b| {
                let da = a.get("found_date").and_then(|v| v.as_str()).unwrap_or("");
                let db = b.get("found_date").and_then(|v| v.as_str()).unwrap_or("");
                db.cmp(da)
            });
        }
    }
    fs
}

/// Parallel bulk-normalize findings (rayon data-parallelism). This is the hot
/// path the dashboard hits on every list/graph load — Python did it serially
/// under the GIL with a `copy.deepcopy`; Rust splits across cores.
pub fn normalize_all(fs: &[Value], org: &str) -> Vec<Value> {
    let meta_date = load_meta_date(org);
    fs.par_iter()
        .map(|f| normalize_finding(f, org, meta_date.as_deref()))
        .collect()
}

/// Parallel light-normalize (list view) — short fields only.
pub fn normalize_all_light(fs: &[Value], org: &str) -> Vec<Value> {
    let meta_date = load_meta_date(org);
    fs.par_iter()
        .map(|f| normalize_finding_light(f, org, meta_date.as_deref()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_cves() {
        let v = json!(["CVE-2020-14871 (CVSS 10.0)", "CVE-2020-14871", "nothing"]);
        let out = extract_cves(&v);
        assert_eq!(out, vec!["CVE-2020-14871".to_string()]);
    }

    #[test]
    fn test_single_public_ip() {
        assert_eq!(
            single_public_ip(&json!("8.8.8.8")),
            Some("8.8.8.8".to_string())
        );
        assert_eq!(single_public_ip(&json!("10.0.0.1")), None);
        assert_eq!(single_public_ip(&json!("127.0.0.1")), None);
        assert_eq!(single_public_ip(&json!("192.168.1.1")), None);
        assert_eq!(single_public_ip(&json!("172.16.0.1")), None);
        assert_eq!(single_public_ip(&json!("100.64.0.1")), None);
        assert_eq!(single_public_ip(&json!("256.1.1.1")), None);
        assert_eq!(single_public_ip(&json!("not-an-ip")), None);
    }

    #[test]
    fn test_mask_email() {
        let out = mask_email("contact jane@example.com now");
        assert_eq!(out, "contact j***@example.com now");
    }

    #[test]
    fn test_mask_big_number() {
        let out = mask_big_number("account 123456789012");
        assert_eq!(out, "account 12********12");
    }

    #[test]
    fn test_mask_ip_in_text() {
        let out = mask_ip_in_text("host at 34.101.202.179:9000");
        assert_eq!(out, "host at 34.101.*.*:9000");
    }

    #[test]
    fn test_canonical_status() {
        assert_eq!(
            canonical_status(&json!({"status": "in_progress"})),
            "IN_PROGRESS"
        );
        assert_eq!(
            canonical_status(&json!({"status": "Accepted risk"})),
            "ACCEPTED_RISK"
        );
        assert_eq!(canonical_status(&json!({"status": ""})), "OPEN");
        assert_eq!(
            canonical_status(&json!({"status": "MITIGATED"})),
            "MITIGATED"
        );
    }

    #[test]
    fn test_identity_key_stable() {
        let f = json!({"target": "db.example.com", "source": "scan-tls", "port": 443});
        assert_eq!(identity_key(&f), "tls|db.example.com|443");
    }
}
