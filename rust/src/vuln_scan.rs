//! Passive vulnerability lookup and opt-in Nuclei adapter.
//!
//! Nuclei is an active engine.  Gate checks intentionally run before any
//! executable lookup, process creation, or network-capable work.

use chrono::{DateTime, Utc};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

pub const MAX_TARGETS: usize = 20;
pub const DEFAULT_NUCLEI_SEVERITY: [&str; 3] = ["critical", "high", "medium"];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NucleiOptions {
    pub engine: String,
    pub severity: Vec<String>,
    pub tags: Vec<String>,
}

/// Validate API-controlled engine filters before a job is queued. No request
/// string is ever turned into a Nuclei command-line fragment without this.
pub fn normalize_request_options(
    engine: &str,
    severity: Option<&[String]>,
    tags: Option<&[String]>,
) -> Result<NucleiOptions, String> {
    if engine != "passive" && engine != "nuclei" {
        return Err("invalid engine (passive|nuclei)".to_string());
    }
    let severity = match severity {
        Some(values) if !values.is_empty() => {
            let normalized: Vec<String> = values.iter().map(|s| s.trim().to_string()).collect();
            if normalized.iter().any(|s| {
                !matches!(
                    s.as_str(),
                    "critical" | "high" | "medium" | "low" | "info" | "unknown"
                )
            }) {
                return Err("invalid nuclei severity filter".to_string());
            }
            normalized
        }
        _ => DEFAULT_NUCLEI_SEVERITY
            .iter()
            .map(|s| (*s).to_string())
            .collect(),
    };
    let tags = tags.unwrap_or(&[]);
    if tags.len() > MAX_TARGETS {
        return Err("too many nuclei tags (max 20)".to_string());
    }
    let tag_re = regex::Regex::new(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$").expect("fixed tag regex");
    let mut normalized_tags = Vec::with_capacity(tags.len());
    for tag in tags {
        let tag = tag.trim();
        if !tag_re.is_match(tag) {
            return Err("invalid nuclei tag filter".to_string());
        }
        normalized_tags.push(tag.to_string());
    }
    Ok(NucleiOptions {
        engine: engine.to_string(),
        severity,
        tags: normalized_tags,
    })
}

#[derive(Clone, Debug)]
pub struct ActiveGate {
    pub active: bool,
    pub isolated: bool,
    pub allowed_domains: String,
    pub roe_expires: String,
}

pub fn active_gate_from_env() -> ActiveGate {
    ActiveGate {
        active: std::env::var("CTI_VULN_ACTIVE").ok().as_deref() == Some("1"),
        isolated: std::env::var("CTI_VULN_ISOLATED").ok().as_deref() == Some("1"),
        allowed_domains: std::env::var("CTI_VULN_ALLOWED_DOMAINS").unwrap_or_default(),
        roe_expires: std::env::var("CTI_VULN_ROE_EXPIRES").unwrap_or_default(),
    }
}

/// Validate the generic active-assessment controls without an organization-specific
/// scope check. This is used only for capability reporting; queue-time
/// authorization still checks every registered organization domain.
pub fn active_gate_setup_error(gate: &ActiveGate, now: DateTime<Utc>) -> Option<String> {
    if !gate.active {
        return Some("CTI_VULN_ACTIVE must equal 1".to_string());
    }
    if !gate.isolated {
        return Some("CTI_VULN_ISOLATED must equal 1".to_string());
    }
    if gate.allowed_domains.trim().is_empty() {
        return Some("CTI_VULN_ALLOWED_DOMAINS is missing or empty".to_string());
    }
    for item in gate.allowed_domains.split(',') {
        let domain = item.trim().trim_end_matches('.').to_lowercase();
        if !crate::scanner::is_valid_domain(&domain) {
            return Some("CTI_VULN_ALLOWED_DOMAINS contains an invalid domain".to_string());
        }
    }
    match DateTime::parse_from_rfc3339(gate.roe_expires.trim()) {
        Ok(expires) if expires.with_timezone(&Utc) > now => None,
        Ok(_) => Some("CTI_VULN_ROE_EXPIRES is expired".to_string()),
        Err(_) => Some(
            "CTI_VULN_ROE_EXPIRES is not a valid timezone-aware RFC3339/ISO-8601 timestamp"
                .to_string(),
        ),
    }
}

pub fn authorization_error(gate: &ActiveGate, org: &Value, now: DateTime<Utc>) -> Option<String> {
    if let Some(error) = active_gate_setup_error(gate, now) {
        return Some(error);
    }
    let Some(domains) = org.get("domains").and_then(Value::as_array) else {
        return Some("the organization has no registered target domains".to_string());
    };
    if domains.is_empty() {
        return Some("the organization has no registered target domains".to_string());
    }
    let allowed: Vec<String> = gate
        .allowed_domains
        .split(',')
        .map(|item| item.trim().trim_end_matches('.').to_lowercase())
        .collect();
    for value in domains {
        let domain = value
            .as_str()
            .unwrap_or("")
            .trim()
            .trim_end_matches('.')
            .to_lowercase();
        if !crate::scanner::is_valid_domain(&domain) {
            return Some("the organization has an invalid registered target domain".to_string());
        }
        if !allowed.contains(&domain) {
            return Some("registered target domain outside CTI_VULN_ALLOWED_DOMAINS".to_string());
        }
    }
    None
}

/// Testable pre-execution boundary: lookup is deferred until authorization
/// succeeds.  Production will pass the Nuclei executable resolver here.
pub fn prepare_nuclei<F>(
    gate: &ActiveGate,
    org: &Value,
    now: DateTime<Utc>,
    lookup: F,
) -> Result<PathBuf, String>
where
    F: FnOnce() -> Result<PathBuf, String>,
{
    if let Some(error) = authorization_error(gate, org, now) {
        return Err(error);
    }
    lookup()
}

pub const MAX_OUTPUT_BYTES: usize = 10 * 1024 * 1024;
pub const MAX_NUCLEI_EVENTS: usize = 500;

#[derive(Clone, Debug)]
pub struct NucleiConfig {
    pub binary: PathBuf,
    pub templates: PathBuf,
    pub rate_limit: u16,
    pub timeout_secs: u64,
    pub interactsh: bool,
    pub exclude_tags: Vec<String>,
}

#[derive(Clone, Debug, Default)]
pub struct NucleiSettings {
    pub bin: Option<String>,
    pub templates: Option<PathBuf>,
    pub severity: Option<String>,
    pub tags: Option<String>,
    pub exclude_tags: Option<String>,
    pub rate_limit: Option<String>,
    pub timeout_secs: Option<String>,
    pub interactsh: bool,
}

#[derive(Clone, Debug)]
pub struct NucleiRuntime {
    pub config: NucleiConfig,
    pub severity: Vec<String>,
    pub tags: Vec<String>,
}

pub fn expand_tilde_path(path: &std::path::Path, home: &std::path::Path) -> PathBuf {
    let raw = path.to_string_lossy();
    if raw == "~" {
        return home.to_path_buf();
    }
    if let Some(rest) = raw.strip_prefix("~/") {
        return home.join(rest);
    }
    path.to_path_buf()
}

fn executable_file(path: &std::path::Path) -> bool {
    if !path.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        return std::fs::metadata(path)
            .map(|metadata| metadata.permissions().mode() & 0o111 != 0)
            .unwrap_or(false);
    }
    #[cfg(not(unix))]
    {
        true
    }
}

fn split_valid_tags(raw: Option<&str>, cap: usize) -> Vec<String> {
    let re = regex::Regex::new(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$").expect("fixed tag regex");
    raw.unwrap_or("")
        .split(',')
        .map(str::trim)
        .filter(|value| re.is_match(value))
        .map(|value| value.to_lowercase())
        .take(cap)
        .collect()
}

fn severity_from_config(raw: Option<&str>) -> Vec<String> {
    let values: Vec<String> = raw
        .unwrap_or("")
        .split(',')
        .map(str::trim)
        .filter(|value| {
            matches!(
                *value,
                "critical" | "high" | "medium" | "low" | "info" | "unknown"
            )
        })
        .map(ToOwned::to_owned)
        .collect();
    if values.is_empty() {
        DEFAULT_NUCLEI_SEVERITY
            .iter()
            .map(|value| (*value).to_string())
            .collect()
    } else {
        values
    }
}

fn clamped_setting(raw: Option<&str>, default: u64, min: u64, max: u64) -> u64 {
    raw.unwrap_or("")
        .trim()
        .parse::<i64>()
        .ok()
        .and_then(|value| u64::try_from(value).ok())
        .unwrap_or(default)
        .clamp(min, max)
}

/// Resolve Nuclei configuration after active authorization has passed. An
/// explicitly configured binary never falls back to PATH on failure.
pub fn resolve_nuclei_runtime<F>(
    settings: &NucleiSettings,
    path_lookup: F,
) -> Result<NucleiRuntime, String>
where
    F: FnOnce() -> Option<PathBuf>,
{
    let binary = match settings
        .bin
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        Some(value) => {
            let path = PathBuf::from(value);
            if !path.is_absolute() || !executable_file(&path) {
                return Err("CTI_NUCLEI_BIN must be an absolute executable".to_string());
            }
            path
        }
        None => path_lookup()
            .filter(|path| executable_file(path))
            .ok_or_else(|| "nuclei binary not found".to_string())?,
    };
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    let templates = settings
        .templates
        .as_ref()
        .map(|path| expand_tilde_path(path, &home))
        .unwrap_or_else(|| home.join("nuclei-templates"));
    if !templates.is_dir() {
        return Err("nuclei templates dir not found".to_string());
    }
    let mut exclude_tags = split_valid_tags(settings.exclude_tags.as_deref(), 20);
    for required in ["intrusive", "dos", "fuzz"] {
        if !exclude_tags.iter().any(|tag| tag == required) {
            exclude_tags.push(required.to_string());
        }
    }
    Ok(NucleiRuntime {
        config: NucleiConfig {
            binary,
            templates,
            rate_limit: clamped_setting(settings.rate_limit.as_deref(), 20, 1, 150) as u16,
            timeout_secs: clamped_setting(settings.timeout_secs.as_deref(), 300, 60, 1200),
            interactsh: settings.interactsh,
            exclude_tags,
        },
        severity: severity_from_config(settings.severity.as_deref()),
        tags: split_valid_tags(settings.tags.as_deref(), MAX_TARGETS),
    })
}

fn path_lookup_nuclei() -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|path| {
        std::env::split_paths(&path)
            .map(|directory| directory.join("nuclei"))
            .find(|candidate| executable_file(candidate))
    })
}

pub fn nuclei_runtime_from_env() -> Result<NucleiRuntime, String> {
    let configured_templates = std::env::var_os("CTI_NUCLEI_TEMPLATES")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from);
    let settings = NucleiSettings {
        bin: std::env::var("CTI_NUCLEI_BIN").ok(),
        templates: configured_templates,
        severity: std::env::var("CTI_NUCLEI_SEVERITY").ok(),
        tags: std::env::var("CTI_NUCLEI_TAGS").ok(),
        exclude_tags: std::env::var("CTI_NUCLEI_EXCLUDE_TAGS").ok(),
        rate_limit: std::env::var("CTI_NUCLEI_RATE_LIMIT").ok(),
        timeout_secs: std::env::var("CTI_NUCLEI_TIMEOUT").ok(),
        interactsh: std::env::var("CTI_NUCLEI_INTERACTSH").ok().as_deref() == Some("1"),
    };
    resolve_nuclei_runtime(&settings, path_lookup_nuclei)
}

fn host_in_registered_scope(host: &str, domains: &[String]) -> bool {
    let host = host.trim().trim_end_matches('.').to_lowercase();
    crate::scanner::is_valid_domain(&host)
        && domains.iter().any(|domain| {
            let domain = domain.trim().trim_end_matches('.').to_lowercase();
            crate::scanner::is_valid_domain(&domain)
                && (host == domain || host.ends_with(&format!(".{domain}")))
        })
}

/// Stored fingerprint URLs are evidence only. The active runner target is
/// always rebuilt from the already-approved hostname. Ports other than the
/// scheme default are honored only when they are common web ports, so a
/// poisoned fingerprint cannot aim active probes at non-HTTP services.
pub const RUNNER_WEB_PORTS: [u16; 6] = [80, 443, 8000, 8080, 8443, 8888];

pub fn canonical_runner_target(host: &str, snippet: &Value) -> String {
    let host = host.trim().trim_end_matches('.').to_lowercase();
    let mut scheme = "https";
    let mut port = None;
    if let Some(raw) = snippet.get("url").and_then(Value::as_str) {
        if let Ok(url) = url::Url::parse(raw.trim()) {
            let parsed_host = url
                .host_str()
                .unwrap_or("")
                .trim_end_matches('.')
                .to_lowercase();
            let parsed_scheme = url.scheme().to_lowercase();
            if (parsed_scheme == "http" || parsed_scheme == "https")
                && parsed_host == host
                && url.username().is_empty()
                && url.password().is_none()
            {
                scheme = if parsed_scheme == "http" {
                    "http"
                } else {
                    "https"
                };
                let default_port = if scheme == "https" { 443 } else { 80 };
                if let Some(candidate) = url.port() {
                    if candidate != default_port && RUNNER_WEB_PORTS.contains(&candidate) {
                        port = Some(candidate);
                    }
                }
            }
        }
    }
    match port {
        Some(port) => format!("{scheme}://{host}:{port}"),
        None => format!("{scheme}://{host}"),
    }
}

fn template_id_valid(value: &str) -> bool {
    regex::Regex::new(r"^[A-Za-z0-9][A-Za-z0-9_.\-/]{0,127}$")
        .expect("fixed template id regex")
        .is_match(value)
}

fn cve_values(event: &Value) -> Vec<String> {
    let full = regex::Regex::new(r"^CVE-\d{4}-\d{4,7}$").expect("fixed CVE regex");
    let mut out = Vec::new();
    let mut add = |value: &str| {
        let value = value.trim().to_uppercase();
        if full.is_match(&value) && !out.contains(&value) && out.len() < 6 {
            out.push(value);
        }
    };
    if let Some(classification) = event
        .get("info")
        .and_then(|v| v.get("classification"))
        .and_then(Value::as_object)
    {
        for key in ["cve-id", "cve_id"] {
            match classification.get(key) {
                Some(Value::Array(values)) => {
                    for value in values.iter().filter_map(Value::as_str) {
                        add(value);
                    }
                }
                Some(Value::String(value)) => add(value),
                _ => {}
            }
        }
    }
    for value in [
        event
            .get("template-id")
            .and_then(Value::as_str)
            .unwrap_or(""),
        event
            .get("info")
            .and_then(|v| v.get("name"))
            .and_then(Value::as_str)
            .unwrap_or(""),
    ] {
        for token in value.split(|c: char| !(c.is_ascii_alphanumeric() || c == '-')) {
            add(token);
        }
    }
    out
}

fn cap(value: &str, max: usize) -> String {
    value.chars().take(max).collect()
}

/// Preserve the raw, validated path for identity/dedup. `url::Url` correctly
/// validates authority but normalizes encoded dot segments, which must not
/// silently merge distinct Nuclei template matches.
fn raw_url_path(raw: &str) -> String {
    let authority_and_tail = raw.split_once("://").map(|(_, tail)| tail).unwrap_or("");
    let Some(start) = authority_and_tail.find(|c| matches!(c, '/' | '?' | '#')) else {
        return "/".to_string();
    };
    let tail = &authority_and_tail[start..];
    let path = if tail.starts_with('/') {
        tail.split(|c| matches!(c, '?' | '#')).next().unwrap_or("/")
    } else {
        "/"
    };
    cap(&path.to_lowercase(), 120)
}

/// Convert one untrusted Nuclei JSONL event into a bounded, in-scope finding.
pub fn map_event(slug: &str, event: &Value, domains: &[String]) -> Option<Value> {
    let template = event.get("template-id")?.as_str()?.trim();
    if !template_id_valid(template) {
        return None;
    }
    let raw_url = event.get("matched-at")?.as_str()?.trim();
    let url = url::Url::parse(raw_url).ok()?;
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return None;
    }
    let host = url.host_str()?.trim_end_matches('.').to_lowercase();
    if host.parse::<std::net::IpAddr>().is_ok() || !host_in_registered_scope(&host, domains) {
        return None;
    }
    let path = raw_url_path(raw_url);
    let info = event.get("info").and_then(Value::as_object);
    let name = cap(
        info.and_then(|m| m.get("name"))
            .and_then(Value::as_str)
            .unwrap_or(template)
            .trim(),
        150,
    );
    if name.is_empty() {
        return None;
    }
    let severity_raw = info
        .and_then(|m| m.get("severity"))
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .trim()
        .to_lowercase();
    let severity = match severity_raw.as_str() {
        "critical" | "high" => "HIGH",
        "medium" => "MEDIUM",
        "low" => "LOW",
        _ => "INFO",
    };
    let tag_re = regex::Regex::new(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$").expect("fixed tag regex");
    let tags: Vec<String> = info
        .and_then(|m| m.get("tags"))
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|value| tag_re.is_match(value))
                .map(|value| cap(value, 40))
                .take(10)
                .collect()
        })
        .unwrap_or_default();
    let cves = cve_values(event);
    let matcher = cap(
        event
            .get("matcher-name")
            .and_then(Value::as_str)
            .unwrap_or(""),
        80,
    );
    let extracted = match event.get("extracted-results") {
        Some(Value::Array(values)) => cap(
            &values
                .iter()
                .filter_map(Value::as_str)
                .take(5)
                .map(|value| cap(value, 200))
                .collect::<Vec<_>>()
                .join("; "),
            500,
        ),
        Some(Value::String(value)) => cap(value, 500),
        _ => String::new(),
    };
    let mut evidence = serde_json::Map::new();
    evidence.insert("url".into(), Value::String(cap(raw_url, 500)));
    evidence.insert("template".into(), Value::String(template.to_string()));
    evidence.insert(
        "template_severity".into(),
        Value::String(cap(&severity_raw, 20)),
    );
    evidence.insert("matcher".into(), Value::String(matcher.clone()));
    evidence.insert("tags".into(), serde_json::json!(tags));
    if !extracted.is_empty() {
        evidence.insert("extracted".into(), Value::String(extracted));
    }
    if let Some(refs) = info
        .and_then(|m| m.get("reference"))
        .and_then(Value::as_array)
    {
        let values: Vec<String> = refs
            .iter()
            .filter_map(Value::as_str)
            .map(|value| cap(value, 300))
            .take(5)
            .collect();
        if !values.is_empty() {
            evidence.insert("references".into(), serde_json::json!(values));
        }
    }
    let category = cap(
        &format!(
            "nuclei {}",
            tags.first().map(String::as_str).unwrap_or("match")
        ),
        80,
    );
    let date = crate::correlation::now_iso()[..10].to_string();
    let scheme_port = url
        .port_or_known_default()
        .unwrap_or(if url.scheme() == "https" { 443 } else { 80 });
    let identity_key = format!("nuclei|{}|{}|{}", host, template.to_lowercase(), path);
    Some(serde_json::json!({
        "id": format!("NUC-{}-{}", crate::scanner::slugify(slug), uuid::Uuid::new_v4().simple()),
        "title": name,
        "target": host,
        "ip": Value::Null,
        "port": scheme_port,
        "severity": severity,
        "category": category,
        "status": "OPEN",
        "status_detail": format!("NUCLEI-MATCHED (template {} — verify before acting)", template),
        "positive": false,
        "mode": "fast",
        "source": "nuclei",
        "description": cap(&format!("{} matched on {}{} via nuclei template {}.", name, host, path, template), 2000),
        "impact": cap(&format!("A Nuclei template matched this host. Template matches are not exploit proof.{}", if cves.is_empty() { String::new() } else { format!(" Related: {}.", cves.join(", ")) }), 2000),
        "evidence": Value::Object(evidence),
        "proof_chain": [cap(&format!("nuclei {} matched {}", template, raw_url), 500)],
        "remediation": ["Verify the affected component, then patch or mitigate using vendor guidance."],
        "related_cves": cves,
        "found_date": date,
        "first_seen": date,
        "last_seen": date,
        "status_history": [{"at": date, "from": "", "to": "OPEN", "by": "nuclei", "note": format!("template {} matched", template)}],
        "provenance": {"derived_from": ["nuclei"], "confidence": "template-match"},
        "identity_key": identity_key,
    }))
}

/// Bounded in-memory JSONL parser. Oversized output is rejected as degraded
/// input with an error rather than silently parsed as "no matches".
pub fn parse_jsonl(contents: &str, slug: &str, domains: &[String]) -> Result<Vec<Value>, String> {
    if contents.len() > MAX_OUTPUT_BYTES {
        return Err("nuclei output exceeded 10MiB limit".to_string());
    }
    let mut findings = Vec::new();
    let mut events_seen = 0usize;
    for line in contents.lines() {
        if events_seen >= MAX_NUCLEI_EVENTS {
            break;
        }
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        events_seen += 1;
        let line: String = line.chars().take(65_536).collect();
        let Ok(event) = serde_json::from_str::<Value>(&line) else {
            continue;
        };
        if let Some(finding) = map_event(slug, &event, domains) {
            findings.push(finding);
        }
    }
    Ok(findings)
}

fn effective_exclude_tags(config: &NucleiConfig) -> Vec<String> {
    let tag_re = regex::Regex::new(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$").expect("fixed tag regex");
    let mut out = Vec::new();
    for tag in &config.exclude_tags {
        let tag = tag.trim().to_lowercase();
        if tag_re.is_match(&tag) && !out.contains(&tag) {
            out.push(tag);
        }
    }
    for required in ["intrusive", "dos", "fuzz"] {
        if !out.iter().any(|tag| tag == required) {
            out.push(required.to_string());
        }
    }
    out
}

/// Construct the complete Nuclei command without a shell or free-form args.
pub fn build_argv(
    config: &NucleiConfig,
    targets_file: impl AsRef<std::path::Path>,
    output_file: impl AsRef<std::path::Path>,
    severity: &[String],
    tags: &[String],
) -> Vec<String> {
    let mut argv = vec![
        config.binary.to_string_lossy().into_owned(),
        "-l".into(),
        targets_file.as_ref().to_string_lossy().into_owned(),
        "-t".into(),
        config.templates.to_string_lossy().into_owned(),
        "-severity".into(),
        severity.join(","),
        "-exclude-tags".into(),
        effective_exclude_tags(config).join(","),
        "-jsonl".into(),
        "-o".into(),
        output_file.as_ref().to_string_lossy().into_owned(),
        "-silent".into(),
        "-nc".into(),
        "-duc".into(),
        "-or".into(),
        "-nm".into(),
        "-rl".into(),
        config.rate_limit.clamp(1, 150).to_string(),
        "-retries".into(),
        "1".into(),
        "-timeout".into(),
        "10".into(),
        "-bulk-size".into(),
        "10".into(),
    ];
    if !tags.is_empty() {
        argv.extend(["-tags".into(), tags.join(",")]);
    }
    if !config.interactsh {
        argv.push("-ni".into());
    }
    argv
}

pub fn dedup_nuclei_findings(existing: &[Value], candidates: Vec<Value>) -> Vec<Value> {
    let mut seen = HashSet::new();
    for finding in existing {
        if let Some(identity) = finding.get("identity_key").and_then(Value::as_str) {
            seen.insert(identity.to_string());
        }
    }
    let mut fresh = Vec::new();
    for finding in candidates {
        let Some(identity) = finding.get("identity_key").and_then(Value::as_str) else {
            continue;
        };
        if seen.insert(identity.to_string()) {
            fresh.push(finding);
        }
    }
    fresh
}

fn private_work_dir() -> Result<PathBuf, String> {
    let parent = std::env::temp_dir();
    for _ in 0..8 {
        let path = parent.join(format!("cti-nuclei-{}", uuid::Uuid::new_v4().simple()));
        match std::fs::create_dir(&path) {
            Ok(()) => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
                        .map_err(|_| "cannot secure nuclei work directory".to_string())?;
                }
                return Ok(path);
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(_) => return Err("cannot create nuclei work directory".to_string()),
        }
    }
    Err("cannot create nuclei work directory".to_string())
}

fn write_private_targets(path: &std::path::Path, targets: &[String]) -> Result<(), String> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|_| "cannot stage nuclei targets".to_string())?;
    for target in targets.iter().take(MAX_TARGETS) {
        writeln!(file, "{target}").map_err(|_| "cannot stage nuclei targets".to_string())?;
    }
    file.sync_all()
        .map_err(|_| "cannot stage nuclei targets".to_string())
}

/// Keep the active child process on a minimal, non-secret environment. The
/// Nuclei binary is resolved before this boundary, so no provider/API,
/// credential, proxy, or arbitrary operator variable is needed by the child.
pub fn safe_nuclei_child_env(
    environment: &[(std::ffi::OsString, std::ffi::OsString)],
) -> Vec<(std::ffi::OsString, std::ffi::OsString)> {
    const ALLOWED: [&str; 6] = ["PATH", "HOME", "LANG", "LC_ALL", "LC_CTYPE", "TMPDIR"];
    environment
        .iter()
        .filter(|(key, _)| key.to_str().is_some_and(|name| ALLOWED.contains(&name)))
        .cloned()
        .collect()
}

fn terminate_child_group(child: &mut std::process::Child) {
    #[cfg(unix)]
    {
        // The child was placed in its own process group. Killing the negative
        // PID reaches helpers as well as the parent runner.
        unsafe {
            libc::kill(-(child.id() as i32), libc::SIGKILL);
        }
    }
    let _ = child.kill();
    let _ = child.wait();
}

/// Bounded first 8 KiB of the captured runner stderr, for job error detail.
fn bounded_stderr(path: &std::path::Path) -> String {
    use std::io::Read;
    let mut buffer = Vec::new();
    if let Ok(file) = std::fs::File::open(path) {
        let _ = file.take(8192).read_to_end(&mut buffer);
    }
    let text = String::from_utf8_lossy(&buffer);
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    format!(": {}", trimmed.chars().take(2000).collect::<String>())
}

/// Run a pre-authorized local Nuclei binary. This function contains no target
/// discovery; callers must pass canonical, registered-domain URLs only.
pub fn run_nuclei_blocking(
    config: &NucleiConfig,
    targets: &[String],
    severity: &[String],
    tags: &[String],
) -> Result<String, String> {
    if targets.is_empty() || targets.len() > MAX_TARGETS {
        return Err("invalid nuclei target count".to_string());
    }
    let work_dir = private_work_dir()?;
    let result = (|| {
        let targets_file = work_dir.join("targets.txt");
        let output_file = work_dir.join("out.jsonl");
        let stderr_file = work_dir.join("stderr.log");
        write_private_targets(&targets_file, targets)?;
        let argv = build_argv(config, &targets_file, &output_file, severity, tags);
        let stderr = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&stderr_file)
            .map_err(|_| "cannot stage nuclei stderr".to_string())?;
        let mut command = std::process::Command::new(&argv[0]);
        command.args(&argv[1..]);
        command.stdin(std::process::Stdio::null());
        command.stdout(std::process::Stdio::null());
        command.stderr(stderr);
        // Keep explicitly resolved executable/template paths but do not allow
        // ambient proxy variables to redirect active traffic.
        command.env_clear();
        let environment: Vec<_> = std::env::vars_os().collect();
        for (key, value) in safe_nuclei_child_env(&environment) {
            command.env(key, value);
        }
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
        }
        let mut child = command
            .spawn()
            .map_err(|_| "cannot spawn nuclei".to_string())?;
        let started = std::time::Instant::now();
        let status = loop {
            if let Some(status) = child
                .try_wait()
                .map_err(|_| "cannot wait for nuclei".to_string())?
            {
                break status;
            }
            if output_file
                .metadata()
                .map(|meta| meta.len() as usize > MAX_OUTPUT_BYTES)
                .unwrap_or(false)
            {
                terminate_child_group(&mut child);
                return Err("nuclei output exceeded 10MiB limit".to_string());
            }
            if started.elapsed()
                >= std::time::Duration::from_secs(config.timeout_secs.clamp(60, 1200))
            {
                terminate_child_group(&mut child);
                return Err(format!(
                    "nuclei exceeded {}s budget",
                    config.timeout_secs.clamp(60, 1200)
                ));
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        };
        // Nuclei can use exit 1 for a completed run with matches/errors mixed.
        // Accept that code only when it produced bounded JSONL; every other
        // non-zero exit remains a job failure.
        if !status.success() && status.code() != Some(1) {
            return Err(format!(
                "nuclei exited {}{}",
                status.code().unwrap_or(-1),
                bounded_stderr(&stderr_file)
            ));
        }
        let metadata = output_file
            .metadata()
            .map_err(|_| format!("nuclei exited {}", status.code().unwrap_or(-1)))?;
        if metadata.len() as usize > MAX_OUTPUT_BYTES {
            return Err("nuclei output exceeded 10MiB limit".to_string());
        }
        let output = std::fs::read_to_string(&output_file)
            .map_err(|_| format!("nuclei output unreadable{}", bounded_stderr(&stderr_file)))?;
        Ok(output)
    })();
    let _ = std::fs::remove_dir_all(&work_dir);
    result
}

pub const VALID_CHECKS: [&str; 5] = ["cve", "version", "headers", "tls", "login"];
pub const DEFAULT_CHECKS: [&str; 4] = ["cve", "version", "headers", "tls"];

#[derive(Clone, Debug)]
pub struct PassiveRequest {
    pub targets: Vec<String>,
    pub checks: Vec<String>,
}

pub fn validate_passive_request(
    raw_targets: Option<&[String]>,
    raw_checks: Option<&[String]>,
) -> Result<PassiveRequest, String> {
    let mut targets = Vec::new();
    for value in raw_targets.unwrap_or(&[]) {
        let target = value.trim().trim_end_matches('.').to_lowercase();
        if !crate::scanner::is_valid_domain(&target) {
            return Err("invalid target".to_string());
        }
        if !targets.contains(&target) {
            targets.push(target);
        }
    }
    if targets.len() > MAX_TARGETS {
        return Err("too many targets (max 20)".to_string());
    }
    let mut checks = Vec::new();
    for value in raw_checks.unwrap_or(&[]) {
        let check = value.trim().to_lowercase();
        if !VALID_CHECKS.contains(&check.as_str()) {
            return Err("invalid vuln check".to_string());
        }
        if !checks.contains(&check) {
            checks.push(check);
        }
    }
    if checks.is_empty() {
        checks = DEFAULT_CHECKS
            .iter()
            .map(|value| (*value).to_string())
            .collect();
    }
    Ok(PassiveRequest { targets, checks })
}

fn registered_domains(org: &Value) -> Vec<String> {
    org.get("domains")
        .and_then(Value::as_array)
        .map(|domains| {
            domains
                .iter()
                .filter_map(Value::as_str)
                .map(|value| value.trim().trim_end_matches('.').to_lowercase())
                .filter(|value| crate::scanner::is_valid_domain(value))
                .collect()
        })
        .unwrap_or_default()
}

fn known_hosts(doc: &Value) -> HashSet<String> {
    let mut known = HashSet::new();
    if let Some(fingerprints) = doc
        .get("meta")
        .and_then(|v| v.get("fingerprints"))
        .and_then(Value::as_object)
    {
        for host in fingerprints.keys() {
            let host = host.trim().trim_end_matches('.').to_lowercase();
            if crate::scanner::is_valid_domain(&host) {
                known.insert(host);
            }
        }
    }
    if let Some(findings) = doc.get("findings").and_then(Value::as_array) {
        for finding in findings {
            if let Some(host) = finding.get("target").and_then(Value::as_str) {
                let host = host.trim().trim_end_matches('.').to_lowercase();
                if crate::scanner::is_valid_domain(&host) {
                    known.insert(host);
                }
            }
        }
    }
    known
}

fn passive_target_in_scope(host: &str, domains: &[String], known: &HashSet<String>) -> bool {
    known.contains(host) || host_in_registered_scope(host, domains)
}

/// Active scope deliberately ignores cached host authority. Cached fingerprints
/// can choose a scheme/port only after the hostname has passed this check.
pub fn active_nuclei_targets(
    org: &Value,
    cached: &Value,
    requested: &[String],
) -> Result<Vec<String>, String> {
    let domains = registered_domains(org);
    if domains.is_empty() {
        return Err("the organization has no registered target domains".to_string());
    }
    let mut targets = if requested.is_empty() {
        let mut from_fingerprints: Vec<String> = cached
            .get("meta")
            .and_then(|meta| meta.get("fingerprints"))
            .and_then(Value::as_object)
            .map(|fingerprints| {
                fingerprints
                    .keys()
                    .map(|host| host.trim().trim_end_matches('.').to_lowercase())
                    .filter(|host| host_in_registered_scope(host, &domains))
                    .collect()
            })
            .unwrap_or_default();
        from_fingerprints.sort();
        from_fingerprints
    } else {
        requested
            .iter()
            .map(|host| host.trim().trim_end_matches('.').to_lowercase())
            .collect()
    };
    targets.sort();
    targets.dedup();
    targets.truncate(MAX_TARGETS);
    for target in &targets {
        if !crate::scanner::is_valid_domain(target) || !host_in_registered_scope(target, &domains) {
            return Err(format!(
                "nuclei target outside registered org domain: {target}"
            ));
        }
    }
    if targets.is_empty() {
        return Err("no registered fingerprinted targets for nuclei".to_string());
    }
    Ok(targets)
}

/// Purely local, observation-only lookup over fingerprints already stored by
/// the passive scanner. It intentionally performs no refresh, DNS, HTTP, TLS,
/// or NVD calls, so a `passive` job cannot create fresh egress.
pub async fn run_passive_lookup(
    slug: &str,
    org: &Value,
    request: PassiveRequest,
) -> Result<Value, String> {
    let _guard = crate::correlation::org_write_lock(slug).await;
    let path = crate::correlation::org_findings_path(slug)
        .ok_or_else(|| "findings store unavailable".to_string())?;
    let text = tokio::fs::read_to_string(&path)
        .await
        .map_err(|_| "findings store unreadable".to_string())?;
    let mut doc: Value =
        serde_json::from_str(&text).map_err(|_| "findings store corrupted".to_string())?;
    if !doc.is_object() {
        return Err("findings store corrupted".to_string());
    }
    let domains = registered_domains(org);
    let known = known_hosts(&doc);
    let mut scope = if request.targets.is_empty() {
        let mut targets: Vec<String> = known.into_iter().collect();
        targets.sort();
        targets
    } else {
        request.targets.clone()
    };
    scope.truncate(MAX_TARGETS);
    for target in &scope {
        if !passive_target_in_scope(target, &domains, &known_hosts(&doc)) {
            return Err(format!("target out of scope for org: {target}"));
        }
    }
    let snippets: HashMap<String, Value> = doc
        .get("meta")
        .and_then(|v| v.get("fingerprints"))
        .and_then(Value::as_object)
        .map(|items| {
            scope
                .iter()
                .filter_map(|host| {
                    items
                        .get(host)
                        .cloned()
                        .map(|snippet| (host.clone(), snippet))
                })
                .filter(|(_, snippet)| snippet.is_object())
                .collect()
        })
        .unwrap_or_default();
    if snippets.is_empty() {
        return Ok(serde_json::json!({
            "slug": slug, "engine": "passive", "targets": scope, "checks": request.checks,
            "new_findings": 0, "candidates": 0,
            "note": "no fingerprint data for targets — run Scan (full) first",
        }));
    }
    let mut candidates = Vec::new();
    if request.checks.iter().any(|check| check == "cve") {
        candidates.extend(
            crate::scanner::synthesize_cve_findings(slug, &snippets, &HashMap::new()).await,
        );
    }
    if request.checks.iter().any(|check| check == "version") {
        candidates.extend(crate::scanner::synthesize_version_findings(slug, &snippets).await);
    }
    if request.checks.iter().any(|check| check == "headers") {
        candidates.extend(crate::scanner::synthesize_header_findings(slug, &snippets).await);
    }
    if request.checks.iter().any(|check| check == "login") {
        candidates.extend(crate::scanner::synthesize_login_findings(slug, &snippets).await);
    }
    let certs: HashMap<String, Value> = doc
        .get("meta")
        .and_then(|v| v.get("certs"))
        .and_then(Value::as_object)
        .map(|items| {
            scope
                .iter()
                .filter_map(|host| items.get(host).cloned().map(|cert| (host.clone(), cert)))
                .collect()
        })
        .unwrap_or_default();
    if request.checks.iter().any(|check| check == "tls") {
        candidates.extend(crate::scanner::synthesize_cert_findings(slug, &certs).await);
    }
    for finding in &mut candidates {
        if let Some(map) = finding.as_object_mut() {
            if map
                .get("source")
                .and_then(Value::as_str)
                .is_some_and(|source| source.starts_with("scan-"))
            {
                map.insert("source".into(), Value::String("vuln-scan".into()));
            }
        }
        crate::correlation::ensure_identity(finding);
    }
    let existing = doc
        .get("findings")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut seen_identity = HashSet::new();
    let mut seen_category = HashSet::new();
    for mut finding in existing.clone() {
        seen_identity.insert(crate::correlation::ensure_identity(&mut finding));
        let target = finding
            .get("target")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_lowercase();
        let category = finding
            .get("category")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_lowercase();
        seen_category.insert((target, category));
    }
    let mut fresh = Vec::new();
    for mut finding in candidates.iter().cloned() {
        let identity = crate::correlation::ensure_identity(&mut finding);
        let target = finding
            .get("target")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_lowercase();
        let category = finding
            .get("category")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_lowercase();
        if seen_identity.insert(identity) && seen_category.insert((target, category)) {
            fresh.push(finding);
        }
    }
    let mut merged = existing;
    merged.extend(fresh.iter().cloned());
    let total = merged.len();
    let meta = doc
        .get("meta")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let mut meta = meta.as_object().cloned().unwrap_or_default();
    meta.insert(
        "vuln_scan".into(),
        serde_json::json!({
            "date": crate::correlation::now_iso(), "engine": "passive", "targets": scope,
            "checks": request.checks, "new": fresh.len(), "refresh": false,
        }),
    );
    doc = serde_json::json!({"meta": Value::Object(meta), "findings": merged});
    crate::correlation::atomic_write_json(&path, &doc)
        .await
        .map_err(|_| "persist failed".to_string())?;
    crate::correlation::invalidate_org_cache(slug);
    crate::correlation::append_history(
        slug,
        serde_json::json!({
            "ts": crate::correlation::now_iso(), "kind": "vuln-scan", "mode": "passive",
            "summary": {"targets": scope.len(), "new": fresh.len()},
            "note": format!("passive vulnerability lookup on {} host(s)", scope.len()),
        }),
    )
    .await;
    Ok(serde_json::json!({
        "slug": slug, "engine": "passive", "targets": scope, "checks": request.checks,
        "new_findings": fresh.len(), "candidates": candidates.len(), "total_findings": total,
        "active": false, "refresh": false,
    }))
}

pub async fn load_findings_document(slug: &str) -> Result<(PathBuf, Value), String> {
    let path = crate::correlation::org_findings_path(slug)
        .ok_or_else(|| "findings store unavailable".to_string())?;
    let text = tokio::fs::read_to_string(&path)
        .await
        .map_err(|_| "findings store unreadable".to_string())?;
    let doc: Value =
        serde_json::from_str(&text).map_err(|_| "findings store corrupted".to_string())?;
    if !doc.is_object() {
        return Err("findings store corrupted".to_string());
    }
    Ok((path, doc))
}

/// Execute a pre-authorized Nuclei run and atomically merge only validated,
/// registered-scope results. Availability or runner failures return `Err` so
/// the caller marks the job failed instead of reporting a clean scan.
pub async fn run_active_nuclei_lookup(
    slug: &str,
    org: &Value,
    runtime: NucleiRuntime,
    requested_targets: Vec<String>,
    severity: Vec<String>,
    tags: Vec<String>,
) -> Result<Value, String> {
    if let Some(error) = authorization_error(&active_gate_from_env(), org, Utc::now()) {
        return Err(format!("nuclei engine denied: {error}"));
    }
    let (_, initial) = load_findings_document(slug).await?;
    let targets = active_nuclei_targets(org, &initial, &requested_targets)?;
    let domains = registered_domains(org);
    let fingerprints = initial
        .get("meta")
        .and_then(|meta| meta.get("fingerprints"))
        .and_then(Value::as_object);
    let urls: Vec<String> = targets
        .iter()
        .map(|target| {
            let snippet = fingerprints
                .and_then(|items| items.get(target))
                .cloned()
                .unwrap_or(Value::Null);
            canonical_runner_target(target, &snippet)
        })
        .collect();
    let blocking_runtime = runtime.clone();
    let blocking_urls = urls.clone();
    let output = tokio::task::spawn_blocking(move || {
        run_nuclei_blocking(&blocking_runtime.config, &blocking_urls, &severity, &tags)
    })
    .await
    .map_err(|_| "nuclei runner task failed".to_string())??;
    let candidates = parse_jsonl(&output, slug, &domains)?;
    let _guard = crate::correlation::org_write_lock(slug).await;
    let (path, mut doc) = load_findings_document(slug).await?;
    let existing = doc
        .get("findings")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let fresh = dedup_nuclei_findings(&existing, candidates);
    let mut merged = existing;
    merged.extend(fresh.iter().cloned());
    let total = merged.len();
    let mut meta = doc
        .get("meta")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    meta.insert(
        "vuln_scan".into(),
        serde_json::json!({
            "date": crate::correlation::now_iso(), "engine": "nuclei", "targets": targets,
            "new": fresh.len(), "matched": fresh.len(), "rate_limit": runtime.config.rate_limit,
        }),
    );
    doc = serde_json::json!({"meta": Value::Object(meta), "findings": merged});
    crate::correlation::atomic_write_json(&path, &doc)
        .await
        .map_err(|_| "persist failed".to_string())?;
    crate::correlation::invalidate_org_cache(slug);
    crate::correlation::append_history(
        slug,
        serde_json::json!({
            "ts": crate::correlation::now_iso(), "kind": "vuln-scan", "mode": "nuclei",
            "summary": {"targets": urls.len(), "new": fresh.len()},
            "note": format!("Nuclei active template run on {} authorized host(s)", urls.len()),
        }),
    )
    .await;
    Ok(serde_json::json!({
        "slug": slug, "engine": "nuclei", "targets": targets, "urls": urls,
        "new_findings": fresh.len(), "candidates": fresh.len(), "total_findings": total,
        "active": true,
    }))
}
