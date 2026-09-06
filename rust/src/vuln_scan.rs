//! Host-based vulnerability lookup (passive default, active gated).
//! Port of `app/vuln_scan.py` including the two egress-scope hardening fixes:
//! (1) stored fingerprint URLs are evidence, never egress authority — Nuclei
//! input is canonicalized to the approved hostname; (2) cached known-host
//! state can never expand active Nuclei scope beyond registered org domains.

use crate::correlation as cc;
use crate::handlers::valid_slug;
use serde_json::{json, Map, Value};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

pub const MAX_TARGETS: usize = 20;
const VALID_CHECKS: &[&str] = &["cve", "version", "headers", "tls", "login"];
const DEFAULT_CHECKS: &[&str] = &["cve", "version", "headers", "tls"];

/// Fail-closed gate for active checks (mirrors the Python `CTI_VULN_*` gate
/// and the OpenHack authorization pattern). Returns an error string or None.
pub fn authorization_error(org: &Value) -> Option<String> {
    if std::env::var("CTI_VULN_ACTIVE").unwrap_or_default() != "1" {
        return Some("CTI_VULN_ACTIVE must equal 1".to_string());
    }
    if std::env::var("CTI_VULN_ISOLATED").unwrap_or_default() != "1" {
        return Some("CTI_VULN_ISOLATED must equal 1".to_string());
    }
    let raw = std::env::var("CTI_VULN_ALLOWED_DOMAINS").unwrap_or_default();
    if raw.trim().is_empty() {
        return Some("CTI_VULN_ALLOWED_DOMAINS is missing or empty".to_string());
    }
    let mut allowed: Vec<String> = Vec::new();
    for item in raw.split(',') {
        let d = item.trim().trim_end_matches('.').to_lowercase();
        if d.is_empty() || !crate::scanner::is_valid_domain(&d) {
            return Some("CTI_VULN_ALLOWED_DOMAINS contains an invalid domain".to_string());
        }
        allowed.push(d);
    }
    let targets = org.get("domains").and_then(|v| v.as_array());
    let targets = match targets {
        Some(t) if !t.is_empty() => t,
        _ => return Some("the organization has no registered target domains".to_string()),
    };
    for t in targets {
        let d = t
            .as_str()
            .unwrap_or("")
            .trim()
            .trim_end_matches('.')
            .to_lowercase();
        if d.is_empty() || !crate::scanner::is_valid_domain(&d) {
            return Some("the organization has an invalid registered target domain".to_string());
        }
        if !allowed.contains(&d) {
            return Some(
                "registered target domain outside CTI_VULN_ALLOWED_DOMAINS".to_string(),
            );
        }
    }
    let raw_expiry = std::env::var("CTI_VULN_ROE_EXPIRES").unwrap_or_default();
    match chrono::DateTime::parse_from_rfc3339(raw_expiry.trim()) {
        Ok(expires) => {
            if expires <= chrono::Utc::now() {
                return Some("CTI_VULN_ROE_EXPIRES is expired".to_string());
            }
        }
        Err(_) => {
            return Some(
                "CTI_VULN_ROE_EXPIRES is not a valid RFC3339/ISO-8601 timestamp".to_string(),
            );
        }
    }
    None
}

/// Strict active-scan scope: cached state never expands registered scope.
pub fn registered_org_domain(target: &str, org_domains: &[String]) -> bool {
    let t = target.trim().to_lowercase();
    let t = t.trim_end_matches('.');
    if t.is_empty() {
        return false;
    }
    org_domains.iter().any(|d| {
        let dd = d.trim().to_lowercase();
        let dd = dd.trim_end_matches('.');
        !dd.is_empty() && (t == dd || t.ends_with(&format!(".{}", dd)))
    })
}

fn in_scope(target: &str, org_domains: &[String], known: &HashSet<String>) -> bool {
    let t = target.trim().to_lowercase();
    if t.is_empty() || !crate::scanner::is_valid_domain(&t) {
        return false;
    }
    if known.contains(&t) {
        return true;
    }
    registered_org_domain(&t, org_domains)
}

/// Build a safe Nuclei input from an exact scoped hostname.
///
/// Stored fingerprint URLs are evidence, not egress authority: a scheme and
/// non-default port are preserved only when the parsed host exactly matches
/// the approved hostname; userinfo, path, query, and fragments are discarded.
pub fn canonical_nuclei_url(host: &str, snippet: &Value) -> String {
    let host = host.trim().to_lowercase();
    let host = host.trim_end_matches('.').to_string();
    let mut scheme = "https".to_string();
    let mut port: Option<u16> = None;
    if let Some(raw) = snippet.get("url").and_then(|v| v.as_str()) {
        if let Ok(parsed) = url::Url::parse(raw.trim()) {
            let ph = parsed.host_str().unwrap_or("").to_lowercase();
            let ph = ph.trim_end_matches('.').to_string();
            let ps = parsed.scheme().to_lowercase();
            if (ps == "http" || ps == "https")
                && ph == host
                && parsed.username().is_empty()
                && parsed.password().is_none()
            {
                scheme = ps;
                let default_port = if scheme == "https" { 443 } else { 80 };
                if let Some(p) = parsed.port() {
                    if p != default_port {
                        port = Some(p);
                    }
                }
            }
        }
    }
    match port {
        Some(p) => format!("{}://{}:{}", scheme, host, p),
        None => format!("{}://{}", scheme, host),
    }
}

fn today() -> String {
    chrono::Utc::now().format("%Y-%m-%d").to_string()
}

fn emit(
    cb: &Option<Arc<dyn Fn(String, String) + Send + Sync>>,
    stage: &str,
    msg: &str,
) {
    if let Some(f) = cb {
        f(stage.to_string(), msg.to_string());
    }
}

#[derive(Default)]
pub struct VulnOptions {
    pub targets: Option<Vec<String>>,
    pub checks: Option<Vec<String>>,
    pub refresh: bool,
    pub include_nvd: bool,
    pub active: bool,
    pub engine: String,
    pub nuclei_severity: Option<Vec<String>>,
    pub nuclei_tags: Option<Vec<String>>,
    pub on_progress: Option<Arc<dyn Fn(String, String) + Send + Sync>>,
}

fn err(slug: &str, msg: impl Into<String>) -> Value {
    json!({"slug": slug, "error": msg.into()})
}

/// Read-only banner grab on a finding's own IP/port (no bytes that look like
/// an exploit; read-only greeting capture with tight timeouts).
async fn grab_banner(ip: &str, port: u16) -> Option<String> {
    use tokio::io::AsyncReadExt;
    let addr = format!("{}:{}", ip, port);
    let mut stream = tokio::time::timeout(
        Duration::from_secs(4),
        tokio::net::TcpStream::connect(&addr),
    )
    .await
    .ok()?
    .ok()?;
    let mut buf = vec![0u8; 2048];
    let n = tokio::time::timeout(Duration::from_secs(4), stream.read(&mut buf))
        .await
        .ok()?
        .ok()?;
    if n == 0 {
        return None;
    }
    let txt: String = buf[..n]
        .iter()
        .map(|&b| {
            if b.is_ascii_graphic() || b == b' ' {
                b as char
            } else if b == b'\n' || b == b'\r' {
                ' '
            } else {
                '�'
            }
        })
        .collect();
    let clean = txt.split_whitespace().collect::<Vec<_>>().join(" ");
    if clean.is_empty() {
        None
    } else {
        Some(clean.chars().take(500).collect())
    }
}

/// Run a host-scoped vuln lookup. Returns a stats dict; errors are values,
/// never panics (mirrors the Python "never raises fatally" contract).
pub async fn vuln_scan_org(slug: &str, opts: VulnOptions) -> Value {
    let slug = slug.trim();
    if !valid_slug(slug) {
        return err(slug, "invalid slug");
    }
    let org = match cc::org_get(slug) {
        Some(o) => o,
        None => return err(slug, "org not found"),
    };
    let org_domains: Vec<String> = org
        .get("domains")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.trim().to_lowercase()))
                .collect()
        })
        .unwrap_or_default();

    // load store
    let fp = match cc::org_findings_path(slug) {
        Some(p) => p,
        None => return err(slug, "findings store unreadable: unknown org"),
    };
    let raw_txt = match std::fs::read_to_string(&fp) {
        Ok(t) => t,
        Err(e) => return err(slug, format!("findings store unreadable: {}", e.kind())),
    };
    let store: Value = match serde_json::from_str(&raw_txt) {
        Ok(v) => v,
        Err(_) => return err(slug, "findings store corrupted"),
    };
    let empty_map = Map::new();
    let meta = store.get("meta").and_then(|v| v.as_object()).unwrap_or(&empty_map);
    let snippets_src = meta
        .get("fingerprints")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();
    let findings_src: Vec<Value> = store
        .get("findings")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    // normalize checks
    let mut norm_checks: Vec<String> = Vec::new();
    if let Some(list) = opts.checks.as_ref() {
        for c in list {
            let cc_ = c.trim().to_lowercase();
            if VALID_CHECKS.contains(&cc_.as_str()) && !norm_checks.contains(&cc_) {
                norm_checks.push(cc_);
            }
        }
    }
    if norm_checks.is_empty() {
        norm_checks = DEFAULT_CHECKS.iter().map(|s| s.to_string()).collect();
    }

    // known hosts + scope
    let mut known: HashSet<String> = HashSet::new();
    for h in snippets_src.keys() {
        known.insert(h.trim().to_lowercase());
    }
    for f in &findings_src {
        if let Some(t) = f.get("target").and_then(|v| v.as_str()) {
            let t = t.trim().to_lowercase();
            if !t.is_empty() {
                known.insert(t);
            }
        }
    }
    let mut scope: Vec<String> = Vec::new();
    if let Some(list) = opts.targets.as_ref() {
        for t in list {
            let tt = t.trim().to_lowercase();
            let tt = tt.trim_end_matches('.').to_string();
            if tt.is_empty() || scope.contains(&tt) {
                continue;
            }
            if !crate::scanner::is_valid_domain(&tt) {
                return json!({"slug": slug, "error": format!("invalid target: {}", t)});
            }
            if !in_scope(&tt, &org_domains, &known) {
                return json!({"slug": slug, "error": format!("target out of scope for org: {}", tt)});
            }
            scope.push(tt);
        }
        scope.truncate(MAX_TARGETS);
        if scope.is_empty() {
            return err(slug, "no valid targets");
        }
    } else {
        let mut all: Vec<String> = known.iter().cloned().collect();
        all.sort();
        all.truncate(MAX_TARGETS);
        if all.is_empty() {
            return json!({"slug": slug, "error": "no fingerprinted hosts yet — run Scan (full) first",
                "targets": [], "checks": norm_checks, "new_findings": 0});
        }
        scope = all;
    }

    if opts.active {
        let mut orgv = org.clone();
        orgv["slug"] = json!(slug);
        if let Some(gate) = authorization_error(&orgv) {
            return json!({"slug": slug, "error": format!("active assessment denied: {}", gate),
                "targets": scope, "checks": norm_checks});
        }
    }

    // engine selection: nuclei is active probing -> same fail-closed gate
    // (empty defaults to passive for backward-compatible callers)
    let engine = {
        let e = opts.engine.trim().to_lowercase();
        if e.is_empty() { "passive".to_string() } else { e }
    };
    if engine != "passive" && engine != "nuclei" {
        return json!({"slug": slug, "error": "invalid engine (passive|nuclei)",
            "targets": scope, "checks": norm_checks});
    }
    let (mut nuc_sev, mut nuc_tags) = (Vec::new(), Vec::new());
    if engine == "nuclei" {
        let mut orgv = org.clone();
        orgv["slug"] = json!(slug);
        if let Some(gate) = authorization_error(&orgv) {
            return json!({"slug": slug, "error": format!("nuclei engine denied: {}", gate),
                "targets": scope, "checks": norm_checks, "engine": engine});
        }
        // Hermes fix 2: cached known-host state must not expand active scope.
        if let Some(outside) = scope
            .iter()
            .find(|h| !registered_org_domain(h, &org_domains))
        {
            return json!({"slug": slug,
                "error": format!("nuclei target outside registered org domain: {}", outside),
                "targets": scope, "checks": norm_checks, "engine": engine});
        }
        match crate::nuclei::normalize_options(
            opts.nuclei_severity.as_deref(),
            opts.nuclei_tags.as_deref(),
        ) {
            Ok((s, t)) => {
                nuc_sev = s;
                nuc_tags = t;
            }
            Err(e) => {
                return json!({"slug": slug, "error": e,
                    "targets": scope, "checks": norm_checks, "engine": engine});
            }
        }
        let st = crate::nuclei::engine_status();
        if st.get("available").and_then(|v| v.as_bool()) != Some(true) {
            let reason = st.get("reason").and_then(|v| v.as_str()).unwrap_or("unknown");
            return json!({"slug": slug, "error": format!("nuclei engine unavailable: {}", reason),
                "targets": scope, "checks": norm_checks, "engine": engine});
        }
    }

    let mut snippets: HashMap<String, Value> = snippets_src.into_iter().collect();
    let mut refreshed: Vec<String> = Vec::new();
    if opts.refresh && !scope.is_empty() {
        let need: Vec<String> = scope
            .iter()
            .filter(|h| match snippets.get(*h) {
                None => true,
                Some(s) => {
                    s.get("versions").is_none()
                        && s.get("server").is_none()
                        && s.get("code").is_none()
                }
            })
            .cloned()
            .collect();
        if !need.is_empty() {
            emit(
                &opts.on_progress,
                "fingerprint",
                &format!("refreshing {} host(s)", need.len()),
            );
            for h in need {
                let ips = crate::scanner::resolve(&h).await;
                let (_probe, snippet) = crate::scanner::fetch_fingerprint(&h, &ips).await;
                if let Some(s) = snippet {
                    snippets.insert(h.clone(), s);
                    refreshed.push(h);
                }
            }
        }
    }

    // active: read-only banner grab on each finding's own IP/port
    let mut active_evidence: HashMap<String, String> = HashMap::new();
    if opts.active {
        emit(
            &opts.on_progress,
            "active",
            &format!("light banner re-check on {} host(s)", scope.len()),
        );
        let mut by_target: HashMap<String, &Value> = HashMap::new();
        for f in &findings_src {
            if let Some(t) = f.get("target").and_then(|v| v.as_str()) {
                let t = t.trim().to_lowercase();
                if scope.contains(&t) && !by_target.contains_key(&t) {
                    by_target.insert(t, f);
                }
            }
        }
        for h in &scope {
            if let Some(f) = by_target.get(h) {
                let ip = f.get("ip").and_then(|v| v.as_str()).unwrap_or("");
                let port = f
                    .get("port")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0) as u16;
                if ip.is_empty() || port == 0 {
                    continue;
                }
                if let Some(banner) = grab_banner(ip, port).await {
                    active_evidence.insert(h.clone(), banner);
                }
            }
        }
    }

    let filt: HashMap<String, Value> = scope
        .iter()
        .filter_map(|h| snippets.get(h).map(|s| (h.clone(), s.clone())))
        .collect();
    if filt.is_empty() {
        return json!({"slug": slug, "targets": scope, "checks": norm_checks, "engine": engine,
            "new_findings": 0, "total_findings": findings_src.len(),
            "refreshed": refreshed,
            "note": "no fingerprint data for targets — run Scan (full) first"});
    }

    // NVD: not implemented in the Rust backend (fail-open, passive stands).
    let nvd_extra: HashMap<String, Value> = HashMap::new();
    let nvd_note = if opts.include_nvd && norm_checks.iter().any(|c| c == "cve") {
        Some("nvd enrichment not available in Rust backend (fail-open to local map)")
    } else {
        None
    };

    // TLS certs for https targets
    let mut certs: HashMap<String, Value> = HashMap::new();
    if norm_checks.iter().any(|c| c == "tls") {
        emit(
            &opts.on_progress,
            "tls",
            &format!("inspecting TLS on {} host(s)", filt.len()),
        );
        for (h, s) in &filt {
            let url = s.get("url").and_then(|v| v.as_str()).unwrap_or("");
            if !url.starts_with("https://") {
                continue;
            }
            let ips = crate::scanner::resolve(h).await;
            let ip = ips.first().map(|s| s.as_str()).unwrap_or(h.as_str());
            if let Some(mut c) = crate::scanner::tls_cert(h, ip, 443).await {
                c["port"] = json!(443);
                certs.insert(h.clone(), c);
            }
        }
    }

    emit(
        &opts.on_progress,
        "match",
        &format!("matching {} host(s): {}", filt.len(), norm_checks.join(",")),
    );
    let mut new_all: Vec<Value> = Vec::new();
    if norm_checks.iter().any(|c| c == "cve") {
        new_all.extend(crate::scanner::synthesize_cve_findings(slug, &filt, &nvd_extra));
    }
    if norm_checks.iter().any(|c| c == "version") {
        new_all.extend(crate::scanner::synthesize_version_findings(slug, &filt));
    }
    if norm_checks.iter().any(|c| c == "headers") {
        new_all.extend(crate::scanner::synthesize_header_findings(slug, &filt));
    }
    if norm_checks.iter().any(|c| c == "login") {
        new_all.extend(crate::scanner::synthesize_login_findings(slug, &filt));
    }
    if norm_checks.iter().any(|c| c == "tls") {
        new_all.extend(crate::scanner::synthesize_cert_findings(slug, &certs));
    }

    // retag scan-* sources to vuln-scan; nuclei findings keep their own.
    for f in new_all.iter_mut() {
        let src = f.get("source").and_then(|v| v.as_str()).unwrap_or("");
        if src.starts_with("scan-") {
            f["source"] = json!("vuln-scan");
        }
        if let Some(t) = f.get("target").and_then(|v| v.as_str()) {
            if let Some(banner) = active_evidence.get(&t.trim().to_lowercase()) {
                if let Some(ev) = f.get_mut("evidence").and_then(|v| v.as_object_mut()) {
                    ev.insert("active_banner".to_string(), json!(banner));
                }
                if let Some(pc) = f.get_mut("proof_chain").and_then(|v| v.as_array_mut()) {
                    pc.push(json!("vuln-scan active banner re-check (own IP/port only)"));
                }
            }
        }
        if f.get("identity_key").is_none() {
            let ik = cc::identity_key(f);
            f["identity_key"] = json!(ik);
        }
    }

    // nuclei phase (active, gated above)
    let mut nuc_summary = json!({});
    if engine == "nuclei" && !filt.is_empty() {
        let mut urls: Vec<String> = Vec::new();
        for h in &scope {
            let s = filt.get(h).cloned().unwrap_or(Value::Null);
            urls.push(canonical_nuclei_url(h, &s));
        }
        urls.truncate(MAX_TARGETS);
        emit(
            &opts.on_progress,
            "nuclei",
            &format!("probing {} target(s) with nuclei templates", urls.len()),
        );
        let timeout = crate::nuclei::run_timeout();
        let sev = nuc_sev.clone();
        let tags = nuc_tags.clone();
        let run_out = tokio::task::spawn_blocking(move || {
            crate::nuclei::run_scan(&urls, &sev, &tags, timeout)
        })
        .await;
        match run_out {
            Ok((workdir, ofile, run_err)) => {
                let parsed = if run_err.is_empty() {
                    match ofile {
                        Some(p) => crate::nuclei::parse_output_file(&p, slug, &org_domains),
                        None => Vec::new(),
                    }
                } else {
                    Vec::new()
                };
                if !run_err.is_empty() {
                    nuc_summary = json!({"error": run_err});
                } else {
                    nuc_summary = json!({"matched": parsed.len()});
                    new_all.extend(parsed);
                }
                let _ = std::fs::remove_dir_all(&workdir);
            }
            Err(e) => {
                nuc_summary = json!({"error": format!("nuclei task failed: {}", e)});
            }
        }
    }

    // persist genuinely new findings + refreshed fingerprints
    let persisted: usize;
    if !new_all.is_empty() || !refreshed.is_empty() {
        let current_txt = match std::fs::read_to_string(&fp) {
            Ok(t) => t,
            Err(e) => {
                return json!({"slug": slug, "targets": scope, "checks": norm_checks, "engine": engine,
                    "error": format!("persist failed: cannot re-read store: {}", e.kind()),
                    "candidates": new_all.len(), "refreshed": refreshed});
            }
        };
        let mut current: Value = match serde_json::from_str(&current_txt) {
            Ok(v) => v,
            Err(_) => {
                return json!({"slug": slug, "targets": scope, "checks": norm_checks, "engine": engine,
                    "error": "persist failed: corrupted findings store",
                    "candidates": new_all.len(), "refreshed": refreshed});
            }
        };
        let cur_list: Vec<Value> = current
            .get("findings")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let mut seen: HashSet<String> = HashSet::new();
        for x in &cur_list {
            seen.insert(cc::identity_key(x));
            let tk = format!(
                "{}|{}",
                x.get("target").and_then(|v| v.as_str()).unwrap_or("").trim().to_lowercase(),
                x.get("category").and_then(|v| v.as_str()).unwrap_or("").trim().to_lowercase()
            );
            seen.insert(tk);
        }
        let mut fresh: Vec<Value> = Vec::new();
        for f in new_all.iter() {
            let ik = f
                .get("identity_key")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .unwrap_or_else(|| cc::identity_key(f));
            let tk = format!(
                "{}|{}",
                f.get("target").and_then(|v| v.as_str()).unwrap_or("").trim().to_lowercase(),
                f.get("category").and_then(|v| v.as_str()).unwrap_or("").trim().to_lowercase()
            );
            if seen.contains(&ik) || seen.contains(&tk) {
                continue;
            }
            seen.insert(ik);
            seen.insert(tk);
            fresh.push(f.clone());
        }
        persisted = fresh.len();
        let mut combined = cur_list;
        combined.extend(fresh);
        current["findings"] = Value::Array(combined);
        if current.get("meta").and_then(|v| v.as_object()).is_none() {
            current["meta"] = json!({});
        }
        {
            let meta = current.get_mut("meta").unwrap().as_object_mut().unwrap();
            let mut fps: Map<String, Value> = meta
                .get("fingerprints")
                .and_then(|v| v.as_object())
                .cloned()
                .unwrap_or_default();
            for h in &refreshed {
                if let Some(s) = snippets.get(h) {
                    fps.insert(h.clone(), s.clone());
                }
            }
            meta.insert("fingerprints".to_string(), Value::Object(fps));
            meta.insert(
                "vuln_scan".to_string(),
                json!({"date": today(), "targets": scope, "checks": norm_checks,
                    "engine": engine, "new": persisted, "refreshed": refreshed,
                    "nuclei": nuc_summary}),
            );
        }
        if let Err(e) = cc::atomic_write_json(&fp, &current) {
            return json!({"slug": slug, "targets": scope, "checks": norm_checks, "engine": engine,
                "error": format!("persist failed: {}", e.kind()),
                "candidates": new_all.len(), "refreshed": refreshed});
        }
        cc::invalidate_org_cache(slug);
        let total_now = findings_src.len() + persisted;
        cc::append_history(
            slug,
            json!({"ts": chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S").to_string(),
                "kind": "vuln-scan",
                "summary": {"targets": scope.len(), "new": persisted,
                    "checks": norm_checks, "engine": engine, "nuclei": nuc_summary},
                "note": format!("vuln lookup on {} host(s) [{}]", scope.len(), engine)}),
        );
        let mut out = json!({"slug": slug, "targets": scope, "checks": norm_checks,
            "engine": engine, "new_findings": persisted, "candidates": new_all.len(),
            "total_findings": total_now, "refreshed": refreshed,
            "nuclei": nuc_summary, "active": opts.active});
        if let Some(note) = nvd_note {
            out["note"] = json!(note);
        }
        return out;
    }

    let mut out = json!({"slug": slug, "targets": scope, "checks": norm_checks,
        "engine": engine, "new_findings": 0, "candidates": new_all.len(),
        "total_findings": findings_src.len(), "refreshed": refreshed,
        "nuclei": nuc_summary, "active": opts.active});
    if let Some(note) = nvd_note {
        out["note"] = json!(note);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    static TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    static INIT_ONCE: std::sync::Once = std::sync::Once::new();

    fn test_root() -> std::path::PathBuf {
        let mut d = std::env::temp_dir();
        d.push(format!("cti-rust-vuln-test-{}", std::process::id()));
        d
    }

    /// Init correlation globals once per test process against an isolated dir.
    fn ensure_test_env() -> std::path::PathBuf {
        let root = test_root();
        INIT_ONCE.call_once(|| {
            let mut cfg = crate::config::Config::load();
            cfg.data_dir = root.clone();
            cfg.state_dir = root.join("state");
            cc::init(cfg);
        });
        std::fs::create_dir_all(root.join("orgs").join("acme")).ok();
        root
    }

    fn seed_org(name: &str, fingerprints: Value) {
        let root = ensure_test_env();
        let org_dir = root.join("orgs").join(name);
        std::fs::create_dir_all(&org_dir).ok();
        let store = json!({"findings": [], "meta": {"fingerprints": fingerprints}});
        std::fs::write(
            org_dir.join("findings.json"),
            serde_json::to_string_pretty(&store).unwrap(),
        )
        .ok();
        std::fs::write(org_dir.join("baseline.txt"), "seed\n").ok();
        let reg = json!({name: {"name": "Acme", "domains": ["example.com"],
            "findings": format!("orgs/{}/findings.json", name),
            "baseline": format!("orgs/{}/baseline.txt", name)}});
        std::fs::write(
            root.join("orgs.json"),
            serde_json::to_string_pretty(&reg).unwrap(),
        )
        .ok();
        cc::reload_registry();
    }

    fn clear_gate_env() {
        for k in [
            "CTI_VULN_ACTIVE",
            "CTI_VULN_ISOLATED",
            "CTI_VULN_ALLOWED_DOMAINS",
            "CTI_VULN_ROE_EXPIRES",
        ] {
            std::env::remove_var(k);
        }
    }

    fn set_gate_env() {
        std::env::set_var("CTI_VULN_ACTIVE", "1");
        std::env::set_var("CTI_VULN_ISOLATED", "1");
        std::env::set_var("CTI_VULN_ALLOWED_DOMAINS", "example.com");
        std::env::set_var("CTI_VULN_ROE_EXPIRES", "2999-01-01T00:00:00Z");
    }

    fn passive_opts(targets: Vec<&str>) -> VulnOptions {
        VulnOptions {
            targets: Some(targets.into_iter().map(|s| s.to_string()).collect()),
            refresh: false,
            engine: "passive".to_string(),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn test_gate_fail_closed_by_default() {
        let _g = TEST_LOCK.lock().await;
        ensure_test_env();
        clear_gate_env();
        let err = authorization_error(&json!({"domains": ["example.com"]}));
        assert!(err.is_some());
    }

    #[tokio::test]
    async fn test_canonical_url_ignores_poisoned_stored_url() {
        // Hermes fix 1: stored URL host mismatch -> approved host wins.
        assert_eq!(
            canonical_nuclei_url(
                "app.example.com",
                &json!({"url": "https://evil.example/not-in-scope"})
            ),
            "https://app.example.com"
        );
        assert_eq!(
            canonical_nuclei_url(
                "app.example.com",
                &json!({"url": "http://app.example.com:8080/path?q=1"})
            ),
            "http://app.example.com:8080"
        );
        assert_eq!(
            canonical_nuclei_url(
                "app.example.com",
                &json!({"url": "https://user@evil.example/x"})
            ),
            "https://app.example.com"
        );
        assert_eq!(
            canonical_nuclei_url("app.example.com", &json!({})),
            "https://app.example.com"
        );
    }

    #[tokio::test]
    async fn test_registered_domain_check() {
        let doms = vec!["example.com".to_string()];
        assert!(registered_org_domain("app.example.com", &doms));
        assert!(registered_org_domain("example.com", &doms));
        assert!(!registered_org_domain("evil.example", &doms));
        assert!(!registered_org_domain("example.com.evil.com", &doms));
    }

    #[tokio::test]
    async fn test_rejects_out_of_scope() {
        let _g = TEST_LOCK.lock().await;
        seed_org(
            "acme",
            json!({"app.example.com": {"url": "https://app.example.com", "code": "200"}}),
        );
        clear_gate_env();
        let r = vuln_scan_org("acme", passive_opts(vec!["evil.com"])).await;
        assert!(r.get("error").is_some());
        assert!(r["error"].as_str().unwrap().contains("scope"));
    }

    #[tokio::test]
    async fn test_nuclei_rejects_known_host_outside_registered_domains() {
        // Hermes fix 2: known-host state alone must not enlarge active scope.
        let _g = TEST_LOCK.lock().await;
        seed_org(
            "acme",
            json!({
                "app.example.com": {"url": "https://app.example.com", "code": "200"},
                "evil.example": {"url": "https://evil.example", "code": "200"}
            }),
        );
        set_gate_env();
        let mut opts = passive_opts(vec!["evil.example"]);
        opts.engine = "nuclei".to_string();
        let r = vuln_scan_org("acme", opts).await;
        assert!(r.get("error").is_some());
        assert!(r["error"].as_str().unwrap().contains("outside registered org domain"));
        clear_gate_env();
    }

    #[tokio::test]
    async fn test_nuclei_denied_without_gate_no_subprocess() {
        let _g = TEST_LOCK.lock().await;
        seed_org(
            "acme",
            json!({"app.example.com": {"url": "https://app.example.com", "code": "200"}}),
        );
        clear_gate_env();
        let mut opts = passive_opts(vec!["app.example.com"]);
        opts.engine = "nuclei".to_string();
        let r = vuln_scan_org("acme", opts).await;
        assert!(r.get("error").is_some());
        assert!(r["error"].as_str().unwrap().contains("denied"));
    }

    #[tokio::test]
    async fn test_passive_cve_match_persists_once() {
        let _g = TEST_LOCK.lock().await;
        seed_org(
            "acme",
            json!({"app.example.com": {
                "url": "https://app.example.com", "code": "200",
                "server": "nginx/1.18.0",
                "versions": [{"product": "nginx", "version": "1.18.0"}]}}),
        );
        clear_gate_env();
        let mut opts = passive_opts(vec!["app.example.com"]);
        opts.checks = Some(vec!["cve".to_string()]);
        let r1 = vuln_scan_org("acme", opts).await;
        assert!(r1.get("error").is_none(), "unexpected error: {}", r1);
        assert!(r1["candidates"].as_u64().unwrap_or(0) >= 1);
        assert!(r1["new_findings"].as_u64().unwrap_or(0) >= 1);
        // rescan dedups
        let mut opts2 = passive_opts(vec!["app.example.com"]);
        opts2.checks = Some(vec!["cve".to_string()]);
        let r2 = vuln_scan_org("acme", opts2).await;
        assert_eq!(r2["new_findings"], json!(0));
    }

    #[tokio::test]
    async fn test_invalid_engine_rejected() {
        let _g = TEST_LOCK.lock().await;
        seed_org(
            "acme",
            json!({"app.example.com": {"url": "https://app.example.com", "code": "200"}}),
        );
        clear_gate_env();
        let mut opts = passive_opts(vec!["app.example.com"]);
        opts.engine = "bogus".to_string();
        let r = vuln_scan_org("acme", opts).await;
        assert!(r["error"].as_str().unwrap().contains("engine"));
    }
}
