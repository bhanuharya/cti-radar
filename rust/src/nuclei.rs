//! Nuclei template engine as an optional vuln-scan provider.
//! Port of `app/nuclei_scan.py`. Nuclei is ACTIVE (real HTTP probes), so every
//! run is fail-closed behind the `CTI_VULN_*` gate enforced by `vuln_scan`
//! before this module is ever invoked. Disabled by default.
//!
//! Safety: argv list only (never shell), child env strips `*_proxy` vars,
//! `-duc` (no auto-update), `-ni` unless interactsh is explicitly enabled,
//! `-or` (no raw request/response stored), `dos`/`fuzz` force-excluded,
//! severity capped at HIGH, output capped (10 MiB / 500 events).

use regex::Regex;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::BufRead;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::OnceLock;

const VALID_SEV: &[&str] = &["critical", "high", "medium", "low", "info", "unknown"];
const DEFAULT_SEV: &[&str] = &["critical", "high", "medium"];
const DEFAULT_EXCLUDE_TAGS: &[&str] = &["dos", "fuzz", "intrusive"];
const FORCED_EXCLUDE_TAGS: &[&str] = &["dos", "fuzz"];
const OUTPUT_MAX_BYTES: u64 = 10 * 1024 * 1024;
const EVENTS_CAP: usize = 500;

fn tag_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"^[A-Za-z0-9][A-Za-z0-9_.\-]{0,63}$").unwrap())
}

fn template_id_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"^[A-Za-z0-9][A-Za-z0-9_.\-/]{0,127}$").unwrap())
}

fn cve_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"CVE-\d{4}-\d{4,7}").unwrap())
}

fn int_env(name: &str, default: i64, lo: i64, hi: i64) -> i64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.trim().parse::<i64>().ok())
        .unwrap_or(default)
        .clamp(lo, hi)
}

/// Explicit absolute binary wins; else PATH lookup; else None.
pub fn nuclei_bin() -> Option<String> {
    let p = std::env::var("CTI_NUCLEI_BIN").unwrap_or_default();
    let p = p.trim();
    if !p.is_empty() {
        let path = Path::new(p);
        if !path.is_absolute() || !path.is_file() {
            return None; // explicitly set but invalid -> unavailable (fail closed)
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = std::fs::metadata(path).ok()?;
            if meta.permissions().mode() & 0o111 == 0 {
                return None;
            }
        }
        return Some(p.to_string());
    }
    lookup_path("nuclei")
}

fn lookup_path(name: &str) -> Option<String> {
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths).find_map(|dir| {
            let cand = dir.join(name);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                match std::fs::metadata(&cand) {
                    Ok(m) if m.is_file() && m.permissions().mode() & 0o111 != 0 => {
                        Some(cand.to_string_lossy().into_owned())
                    }
                    _ => None,
                }
            }
            #[cfg(not(unix))]
            {
                if cand.is_file() {
                    Some(cand.to_string_lossy().into_owned())
                } else {
                    None
                }
            }
        })
    })
}

pub fn templates_dir() -> Option<String> {
    let d = std::env::var("CTI_NUCLEI_TEMPLATES").unwrap_or_default();
    let d = d.trim();
    if !d.is_empty() {
        let expanded = shellexpand_tilde(d);
        return if Path::new(&expanded).is_dir() {
            Some(expanded)
        } else {
            None
        };
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
    let cand = format!("{}/nuclei-templates", home.trim_end_matches('/'));
    if Path::new(&cand).is_dir() {
        Some(cand)
    } else {
        None
    }
}

fn shellexpand_tilde(p: &str) -> String {
    if let Some(rest) = p.strip_prefix("~/") {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
        format!("{}/{}", home.trim_end_matches('/'), rest)
    } else {
        p.to_string()
    }
}

pub fn default_severity() -> Vec<String> {
    let raw = std::env::var("CTI_NUCLEI_SEVERITY").unwrap_or_default();
    let raw = raw.trim().to_lowercase();
    if raw.is_empty() {
        return DEFAULT_SEV.iter().map(|s| s.to_string()).collect();
    }
    let out: Vec<String> = raw
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| VALID_SEV.contains(&s.as_str()))
        .collect();
    if out.is_empty() {
        DEFAULT_SEV.iter().map(|s| s.to_string()).collect()
    } else {
        out
    }
}

pub fn exclude_tags() -> Vec<String> {
    let raw = std::env::var("CTI_NUCLEI_EXCLUDE_TAGS").unwrap_or_default();
    let mut merged: Vec<String> = DEFAULT_EXCLUDE_TAGS.iter().map(|s| s.to_string()).collect();
    for t in raw.to_lowercase().split(',') {
        let t = t.trim();
        if !t.is_empty() && tag_re().is_match(t) && !merged.contains(&t.to_string()) {
            merged.push(t.to_string());
        }
    }
    for forced in FORCED_EXCLUDE_TAGS {
        if !merged.contains(&forced.to_string()) {
            merged.push(forced.to_string());
        }
    }
    merged
}

pub fn allow_tags() -> Vec<String> {
    let raw = std::env::var("CTI_NUCLEI_TAGS").unwrap_or_default();
    if raw.trim().is_empty() {
        return Vec::new();
    }
    raw.to_lowercase()
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| tag_re().is_match(s))
        .take(20)
        .collect()
}

pub fn run_timeout() -> u64 {
    int_env("CTI_NUCLEI_TIMEOUT", 300, 60, 1200) as u64
}

pub fn rate_limit() -> u64 {
    int_env("CTI_NUCLEI_RATE_LIMIT", 20, 1, 150) as u64
}

pub fn interactsh_enabled() -> bool {
    matches!(
        std::env::var("CTI_NUCLEI_INTERACTSH")
            .unwrap_or_default()
            .trim(),
        "1" | "true" | "yes" | "on"
    )
}

/// Availability snapshot for the API/UI (no secrets, no probing).
pub fn engine_status() -> Value {
    let bin = nuclei_bin();
    let tdir = templates_dir();
    let mut reason = String::new();
    if bin.is_none() {
        reason = "nuclei binary not found (set CTI_NUCLEI_BIN to an absolute executable or install nuclei on PATH)".to_string();
    } else if tdir.is_none() {
        reason =
            "nuclei templates dir not found (set CTI_NUCLEI_TEMPLATES or check out nuclei-templates)"
                .to_string();
    }
    json!({
        "available": bin.is_some() && tdir.is_some(),
        "reason": reason,
        "bin": bin.is_some(),
        "templates": tdir.is_some(),
        "severity": default_severity(),
        "exclude_tags": exclude_tags(),
        "timeout": run_timeout(),
        "rate_limit": rate_limit(),
    })
}

/// Validate per-request severity/tags. Returns (severities, tags) or an error string.
pub fn normalize_options(
    severity: Option<&[String]>,
    tags: Option<&[String]>,
) -> Result<(Vec<String>, Vec<String>), String> {
    let sev = match severity {
        Some(list) if !list.is_empty() => {
            let ok: Vec<String> = list
                .iter()
                .map(|s| s.trim().to_lowercase())
                .filter(|s| VALID_SEV.contains(&s.as_str()))
                .collect();
            if ok.is_empty() {
                return Err("invalid nuclei severity filter".to_string());
            }
            ok
        }
        _ => default_severity(),
    };
    let tg = match tags {
        Some(list) if !list.is_empty() => {
            let mut out = Vec::new();
            for t in list {
                let tt = t.trim().to_lowercase();
                if tt.is_empty() {
                    continue;
                }
                if !tag_re().is_match(&tt) {
                    return Err("invalid nuclei tag filter".to_string());
                }
                out.push(tt);
            }
            out.truncate(20);
            out
        }
        _ => allow_tags(),
    };
    Ok((sev, tg))
}

fn host_in_scope(host: &str, org_domains: &[String]) -> bool {
    let h = host.trim().to_lowercase().trim_end_matches('.').to_string();
    if h.is_empty() {
        return false;
    }
    org_domains.iter().any(|d| {
        let dd = d.trim().to_lowercase();
        let dd = dd.trim_end_matches('.');
        h == dd || h.ends_with(&format!(".{}", dd))
    })
}

/// Strict scope check for a matched URL: http(s), no userinfo, host strictly
/// within registered org domains (raw IPs never qualify).
fn valid_target_url(raw: &str, org_domains: &[String]) -> Option<(String, String)> {
    let parsed = url::Url::parse(raw.trim()).ok()?;
    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        return None;
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return None;
    }
    let host = parsed.host_str()?.to_lowercase();
    let host = host.trim_end_matches('.').to_string();
    if host.parse::<std::net::IpAddr>().is_ok() {
        return None;
    }
    if !host_in_scope(&host, org_domains) {
        return None;
    }
    let mut path: String = parsed.path().chars().take(120).collect();
    if path.is_empty() {
        path = "/".to_string();
    }
    Some((host, path.to_lowercase()))
}

fn extract_cves(event: &Value) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    if let Some(cls) = event
        .get("info")
        .and_then(|i| i.get("classification"))
        .and_then(|c| c.as_object())
    {
        for key in ["cve-id", "cve_id"] {
            if let Some(list) = cls.get(key).and_then(|v| v.as_array()) {
                for c in list {
                    let cc = c.as_str().unwrap_or("").trim().to_uppercase();
                    let full = cve_re().find(&cc).map(|m| m.as_str() == cc).unwrap_or(false);
                    if full && !found.contains(&cc) {
                        found.push(cc);
                    }
                }
            }
        }
    }
    for blob in [
        event.get("template-id").and_then(|v| v.as_str()).unwrap_or(""),
        event
            .get("info")
            .and_then(|i| i.get("name"))
            .and_then(|v| v.as_str())
            .unwrap_or(""),
    ] {
        for m in cve_re().find_iter(&blob.to_uppercase()) {
            let cc = m.as_str().to_string();
            if !found.contains(&cc) {
                found.push(cc);
            }
        }
    }
    found.truncate(6);
    found
}

fn map_severity(raw: &str) -> &'static str {
    match raw.trim().to_lowercase().as_str() {
        "critical" | "high" => "HIGH", // capped: only exploit-verified pipelines claim CRITICAL
        "medium" => "MEDIUM",
        "low" => "LOW",
        _ => "INFO",
    }
}

fn slugify(s: &str) -> String {
    s.to_lowercase()
        .chars()
        .map(|c| {
            if c.is_ascii_lowercase() || c.is_ascii_digit() {
                c
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .chars()
        .take(24)
        .collect()
}

fn today() -> String {
    chrono::Utc::now().format("%Y-%m-%d").to_string()
}

fn now_ts() -> String {
    chrono::Utc::now().format("%Y%m%d%H%M%S").to_string()
}

/// Map one nuclei JSONL event to a finding, or None (dropped as invalid/out-of-scope).
pub fn map_event(slug: &str, event: &Value, org_domains: &[String]) -> Option<Value> {
    let obj = event.as_object()?;
    let tid = obj
        .get("template-id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    if !template_id_re().is_match(tid) {
        return None;
    }
    let matched_at = obj
        .get("matched-at")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let (host, path) = valid_target_url(matched_at, org_domains)?;
    let info = obj.get("info");
    let name: String = info
        .and_then(|i| i.get("name"))
        .and_then(|v| v.as_str())
        .unwrap_or(tid)
        .trim()
        .chars()
        .take(150)
        .collect::<String>();
    if name.is_empty() {
        return None;
    }
    let sev_raw = info
        .and_then(|i| i.get("severity"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let sev = map_severity(sev_raw);
    let tags: Vec<String> = info
        .and_then(|i| i.get("tags"))
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|t| t.as_str())
                .map(|t| t.trim().chars().take(40).collect::<String>())
                .filter(|t: &String| !t.is_empty())
                .take(10)
                .collect()
        })
        .unwrap_or_default();
    let category: String = format!("nuclei {}", tags.first().map(|s| s.as_str()).unwrap_or("match"))
        .chars()
        .take(80)
        .collect();
    let cves = extract_cves(event);
    let matcher = obj
        .get("matcher-name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .chars()
        .take(80)
        .collect::<String>();
    let extracted = match obj.get("extracted-results") {
        Some(Value::Array(arr)) => arr
            .iter()
            .take(5)
            .filter_map(|x| x.as_str().map(|s| s.chars().take(200).collect::<String>()))
            .collect::<Vec<_>>()
            .join("; "),
        Some(Value::String(s)) => s.chars().take(500).collect(),
        _ => String::new(),
    };
    let mut evidence = serde_json::Map::new();
    evidence.insert(
        "url".to_string(),
        Value::String(matched_at.chars().take(500).collect()),
    );
    evidence.insert("template".to_string(), Value::String(tid.to_string()));
    evidence.insert(
        "template_severity".to_string(),
        Value::String(sev_raw.to_string()),
    );
    evidence.insert("matcher".to_string(), Value::String(matcher.clone()));
    evidence.insert("tags".to_string(), Value::Array(tags.into_iter().map(Value::String).collect()));
    if !extracted.is_empty() {
        evidence.insert("extracted".to_string(), Value::String(extracted));
    }
    if let Some(refs) = info.and_then(|i| i.get("reference")).and_then(|v| v.as_array()) {
        let capped: Vec<Value> = refs
            .iter()
            .take(5)
            .filter_map(|r| r.as_str())
            .map(|r| Value::String(r.chars().take(300).collect()))
            .collect();
        if !capped.is_empty() {
            evidence.insert("references".to_string(), Value::Array(capped));
        }
    }
    let mut desc = format!("{} matched on {}{} via nuclei template {}.", name, host, path, tid);
    if !matcher.is_empty() {
        desc.push_str(&format!(" Matcher: {}.", matcher));
    }
    let mut impact = "A nuclei template matched this host. Template matches are strong signals but not exploit proofs — verify the affected component is present and reachable before prioritizing.".to_string();
    if !cves.is_empty() {
        impact.push_str(&format!(" Related: {}.", cves.join(", ")));
    }
    let port = if matched_at.starts_with("https://") { 443 } else { 80 };
    let mut rec = json!({
        "id": format!("NUC-{}-{}", slugify(slug), now_ts()),
        "title": name,
        "target": host,
        "ip": null,
        "port": port,
        "severity": sev,
        "category": category,
        "status": "OPEN",
        "status_detail": format!("NUCLEI-MATCHED (template {} — verify before acting)", tid),
        "positive": false,
        "mode": "fast",
        "source": "nuclei",
        "description": desc.chars().take(2000).collect::<String>(),
        "impact": impact.chars().take(2000).collect::<String>(),
        "evidence": evidence,
        "proof_chain": [format!("nuclei {} matched {}", tid, matched_at)],
        "remediation": ["Verify the finding against the live host, then patch / mitigate per vendor guidance for the matched template."],
        "related_cves": cves,
        "found_date": today(),
        "first_seen": today(),
        "last_seen": today(),
        "status_history": [{"at": today(), "from": "", "to": "OPEN", "by": "nuclei", "note": format!("template {} matched", tid)}],
        "provenance": {"derived_from": ["nuclei"], "confidence": "template-match",
                       "evidence_timestamp": chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S").to_string()},
    });
    rec["identity_key"] = json!(format!("nuclei|{}|{}|{}", host, tid.to_lowercase(), path));
    Some(rec)
}

/// Parse nuclei JSONL output into validated findings (bounded).
pub fn parse_output_file(path: &Path, slug: &str, org_domains: &[String]) -> Vec<Value> {
    let mut out = Vec::new();
    let meta = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(_) => return out,
    };
    if meta.len() > OUTPUT_MAX_BYTES {
        return out; // fail open: oversized output discarded, passive stands
    }
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return out,
    };
    for line in std::io::BufReader::new(file).lines() {
        if out.len() >= EVENTS_CAP {
            break;
        }
        let line = match line {
            Ok(l) => l,
            Err(_) => continue,
        };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let capped: String = line.chars().take(65536).collect();
        let ev: Value = match serde_json::from_str(&capped) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if let Some(rec) = map_event(slug, &ev, org_domains) {
            out.push(rec);
        }
    }
    out
}

/// Argv for the nuclei run (list form — never shell, no free-form args).
pub fn build_argv(
    targets_file: &str,
    output_file: &str,
    severity: &[String],
    tags: &[String],
) -> Result<Vec<String>, String> {
    let bin = nuclei_bin().ok_or_else(|| "nuclei engine unavailable".to_string())?;
    let tdir = templates_dir().ok_or_else(|| "nuclei engine unavailable".to_string())?;
    let mut argv = vec![
        bin,
        "-l".to_string(),
        targets_file.to_string(),
        "-t".to_string(),
        tdir,
        "-severity".to_string(),
        severity.join(","),
        "-exclude-tags".to_string(),
        exclude_tags().join(","),
        "-jsonl".to_string(),
        "-o".to_string(),
        output_file.to_string(),
        "-silent".to_string(),
        "-nc".to_string(),
        "-duc".to_string(),
        "-or".to_string(),
        "-nm".to_string(),
        "-rl".to_string(),
        rate_limit().to_string(),
        "-retries".to_string(),
        "1".to_string(),
        "-timeout".to_string(),
        "10".to_string(),
        "-bulk-size".to_string(),
        "10".to_string(),
    ];
    if !tags.is_empty() {
        argv.push("-tags".to_string());
        argv.push(tags.join(","));
    }
    if !interactsh_enabled() {
        argv.push("-ni".to_string());
    }
    Ok(argv)
}

fn child_env_filtered() -> HashMap<String, String> {
    std::env::vars()
        .filter(|(k, _)| {
            let kl = k.to_lowercase();
            !kl.contains("_proxy") && !matches!(kl.as_str(), "http_proxy" | "https_proxy" | "all_proxy" | "no_proxy")
        })
        .collect()
}

/// Run nuclei over target URLs. Returns (workdir, output_path?, error).
/// The caller must parse the output (if any) then remove the workdir.
pub fn run_scan(
    target_urls: &[String],
    severity: &[String],
    tags: &[String],
    timeout_s: u64,
) -> (PathBuf, Option<PathBuf>, String) {
    let workdir = std::env::temp_dir().join(format!(
        "nuclei-{}-{}",
        std::process::id(),
        chrono::Utc::now().format("%Y%m%d%H%M%S%f")
    ));
    if std::fs::create_dir_all(&workdir).is_err() {
        return (workdir, None, "cannot create nuclei workdir".to_string());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&workdir, std::fs::Permissions::from_mode(0o700));
    }
    let tfile = workdir.join("targets.txt");
    let ofile = workdir.join("out.jsonl");
    let body: String = target_urls
        .iter()
        .take(20)
        .map(|u| format!("{}\n", u.trim()))
        .collect();
    if std::fs::write(&tfile, body).is_err() {
        return (workdir, None, "cannot stage nuclei targets".to_string());
    }
    let argv = match build_argv(
        &tfile.to_string_lossy(),
        &ofile.to_string_lossy(),
        severity,
        tags,
    ) {
        Ok(a) => a,
        Err(e) => return (workdir, None, e),
    };
    let (bin, args) = argv.split_first().map(|(b, r)| (b.clone(), r.to_vec())).unwrap();
    let mut child = match std::process::Command::new(&bin)
        .args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .env_clear()
        .envs(child_env_filtered())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => return (workdir, None, format!("cannot spawn nuclei: {}", e.kind())),
    };
    // bounded wait with polling so the run can be killed on budget expiry
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_s);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let code = status.code().unwrap_or(1);
                if code != 0 && code != 1 && !ofile.exists() {
                    return (workdir, None, format!("nuclei exited {}", status));
                }
                break;
            }
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return (workdir, None, format!("nuclei exceeded {}s budget", timeout_s));
                }
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
            Err(e) => return (workdir, None, format!("cannot poll nuclei: {}", e.kind())),
        }
    }
    if !ofile.exists() {
        return (workdir, None, "nuclei produced no output".to_string());
    }
    (workdir, Some(ofile), String::new())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn domains() -> Vec<String> {
        vec!["example.com".to_string()]
    }

    fn sample_event() -> Value {
        json!({
            "template-id": "CVE-2021-41733",
            "matched-at": "https://app.example.com/cgi-bin/.%2e/%2e%2e/etc/passwd",
            "matcher-name": "path",
            "info": {
                "name": "Apache Path Traversal",
                "severity": "critical",
                "tags": ["cve", "apache"],
                "classification": {"cve-id": ["CVE-2021-41733"]},
                "reference": ["https://example.com/ref"]
            }
        })
    }

    #[test]
    fn test_map_event_ok_and_capped() {
        let rec = map_event("acme", &sample_event(), &domains()).expect("mapped");
        assert_eq!(rec["severity"], "HIGH"); // critical capped by policy
        assert_eq!(rec["source"], "nuclei");
        assert_eq!(rec["related_cves"], json!(["CVE-2021-41733"]));
        assert!(rec["status_detail"]
            .as_str()
            .unwrap()
            .starts_with("NUCLEI-MATCHED"));
    }

    #[test]
    fn test_map_event_drops_out_of_scope() {
        let mut ev = sample_event();
        ev["matched-at"] = json!("https://evil.com/x");
        assert!(map_event("acme", &ev, &domains()).is_none());
        let mut ev = sample_event();
        ev["matched-at"] = json!("http://1.2.3.4/x");
        assert!(map_event("acme", &ev, &domains()).is_none());
        let mut ev = sample_event();
        ev["matched-at"] = json!("ftp://app.example.com/x");
        assert!(map_event("acme", &ev, &domains()).is_none());
        let mut ev = sample_event();
        ev["template-id"] = json!("bad id!!");
        assert!(map_event("acme", &ev, &domains()).is_none());
    }

    #[test]
    fn test_normalize_options_rejects_garbage() {
        let sev_list = ["critical".to_string(), "bogus!".to_string()];
        let (sev, _, err) =
            match normalize_options(Some(&sev_list[..]), None) {
                Ok((s, t)) => (s, t, String::new()),
                Err(e) => (vec![], vec![], e),
            };
        assert!(err.is_empty() && sev == vec!["critical".to_string()]);
        assert!(normalize_options(Some(&["bogus".to_string()][..]), None).is_err());
        assert!(normalize_options(
            None,
            Some(&["cve".to_string(), "bad tag!!".to_string()][..])
        )
        .is_err());
    }

    #[test]
    fn test_exclude_tags_force_dos_fuzz() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::set_var("CTI_NUCLEI_EXCLUDE_TAGS", "intrusive");
        let ex = exclude_tags();
        assert!(ex.contains(&"dos".to_string()) && ex.contains(&"fuzz".to_string()));
        std::env::remove_var("CTI_NUCLEI_EXCLUDE_TAGS");
    }

    #[test]
    fn test_build_argv_safety_flags() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::set_var("CTI_NUCLEI_BIN", "/bin/false");
        let tmp = std::env::temp_dir();
        std::env::set_var("CTI_NUCLEI_TEMPLATES", tmp.to_string_lossy().to_string());
        let argv = build_argv("t.txt", "o.jsonl", &["high".to_string()], &[]).expect("argv");
        let joined = argv.join(" ");
        assert!(argv.contains(&"-or".to_string()));
        assert!(argv.contains(&"-ni".to_string()));
        assert!(argv.contains(&"-duc".to_string()));
        assert!(joined.contains("dos") && joined.contains("fuzz"));
        std::env::remove_var("CTI_NUCLEI_BIN");
        std::env::remove_var("CTI_NUCLEI_TEMPLATES");
    }
}
