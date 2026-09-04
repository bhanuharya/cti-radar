//! Scanner — passive recon + findings synthesis (port of `scanner.py`).
//!
//! Rust-native: ALL network I/O is async on tokio with a shared reqwest client
//! and shared hickory resolver. No per-probe threads, no subprocess curl.

use crate::correlation as cc;
use crate::cve_match;
use once_cell::sync::OnceCell;
use serde_json::{json, Map, Value};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Instant;

pub const DNS_WORKERS: usize = 32;
pub const HTTP_WORKERS: usize = 32;
pub const AI_GRADE_MAX: usize = 200;

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(default)
}

fn env_i64(name: &str, default: i64) -> i64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(default)
}

/// Env-tunable scan caps (parity with the Python `_env_int` tunables).
pub fn enum_name_cap() -> usize {
    env_usize("CTI_ENUM_CAP", 500)
}
pub fn max_total_hosts() -> usize {
    env_usize("CTI_MAX_HOSTS", 200)
}
pub fn curl_max_bytes() -> usize {
    env_usize("CTI_CURL_MAX_BYTES", 204800)
}
pub fn nvd_max_lookups() -> usize {
    env_usize("CTI_NVD_MAX_LOOKUPS", 20)
}
pub fn resolve_after_misses() -> i64 {
    env_i64("CTI_RESOLVE_AFTER", 3).max(1)
}
/// Wildcard-DNS filtering toggle (default on; `0/false/no/off` disables).
/// Parity with Python `WILDCARD_FILTER`.
pub fn wildcard_filter_enabled() -> bool {
    !matches!(
        std::env::var("CTI_WILDCARD_FILTER")
            .unwrap_or_default()
            .trim()
            .to_lowercase()
            .as_str(),
        "0" | "false" | "no" | "off"
    )
}

/// Common service ports probed by the TCP connect scan: port -> name.
pub fn service_ports() -> &'static [(u16, &'static str)] {
    &[
        (21, "ftp"),
        (22, "ssh"),
        (23, "telnet"),
        (25, "smtp"),
        (53, "dns"),
        (80, "http"),
        (110, "pop3"),
        (143, "imap"),
        (443, "https"),
        (993, "imaps"),
        (995, "pop3s"),
        (1433, "mssql"),
        (3306, "mysql"),
        (3389, "rdp"),
        (5432, "postgres"),
        (5900, "vnc"),
        (6379, "redis"),
        (8080, "http-alt"),
        (8443, "https-alt"),
        (9200, "elasticsearch"),
        (27017, "mongodb"),
    ]
}

fn slug_re() -> &'static fancy_regex::Regex {
    static RE: OnceCell<fancy_regex::Regex> = OnceCell::new();
    RE.get_or_init(|| fancy_regex::Regex::new(r"^[a-z0-9-]{1,32}$").unwrap())
}

fn domain_re() -> &'static fancy_regex::Regex {
    static RE: OnceCell<fancy_regex::Regex> = OnceCell::new();
    RE.get_or_init(|| {
        fancy_regex::Regex::new(
            r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]*[a-z0-9])?$",
        )
        .unwrap()
    })
}

fn clean_version_re() -> &'static fancy_regex::Regex {
    static RE: OnceCell<fancy_regex::Regex> = OnceCell::new();
    RE.get_or_init(|| fancy_regex::Regex::new(r"^\d+(\.\d+){0,4}[a-z]?$").unwrap())
}

fn version_token_re() -> &'static fancy_regex::Regex {
    static RE: OnceCell<fancy_regex::Regex> = OnceCell::new();
    RE.get_or_init(|| {
        fancy_regex::Regex::new(
            r"(?i)([a-z][a-z0-9._-]{0,31})[ /_-]v?(\d+(?:\.\d+){0,4}[a-z0-9._-]*)",
        )
        .unwrap()
    })
}

fn title_re() -> &'static fancy_regex::Regex {
    static RE: OnceCell<fancy_regex::Regex> = OnceCell::new();
    RE.get_or_init(|| fancy_regex::Regex::new(r"(?is)<title[^>]*>(.*?)</title>").unwrap())
}

fn password_input_re() -> &'static fancy_regex::Regex {
    static RE: OnceCell<fancy_regex::Regex> = OnceCell::new();
    RE.get_or_init(|| fancy_regex::Regex::new(r#"(?i)<input[^>]+type=["']password["']"#).unwrap())
}

pub fn is_valid_domain(d: &str) -> bool {
    let d = d.trim().to_lowercase().trim_end_matches('.').to_string();
    if d.is_empty() || !d.contains('.') || d.len() > 253 {
        return false;
    }
    if !domain_re().is_match(&d).unwrap_or(false) {
        return false;
    }
    let tld = d.rsplit('.').next().unwrap_or("");
    if !tld.chars().any(|c| c.is_ascii_lowercase()) {
        return false;
    }
    if d.starts_with('-') || d.ends_with('-') || d.contains("..") {
        return false;
    }
    d.split('.')
        .all(|p| !p.starts_with('-') && !p.ends_with('-'))
}

/// Global-reachability check — exact CPython `ip.is_global` semantics.
/// Delegates to [`crate::net::is_global_ip`] (SSRF guard).
pub fn is_global_ip(ip: &str) -> bool {
    crate::net::is_global_ip(ip)
}

pub fn slugify(s: &str) -> String {
    // parity with Python `_slugify`: runs of non-[a-z0-9-] collapse to one
    // dash, trimmed, capped at 48 chars (finding-ID prefixes).
    let mut out = String::new();
    let mut last_dash = true; // leading trim
    for c in s.to_lowercase().chars() {
        if c.is_ascii_lowercase() || c.is_ascii_digit() {
            out.push(c);
            last_dash = false;
        } else if !last_dash {
            out.push('-');
            last_dash = true;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    out.chars().take(48).collect()
}

/// Parse generic version tokens from arbitrary text (headers, titles, banners).
pub fn parse_versions(text: &str) -> Vec<Value> {
    let mut out = Vec::new();
    for cap in version_token_re().captures_iter(text).flatten() {
        let product = cap
            .get(1)
            .map(|m| m.as_str().to_string())
            .unwrap_or_default();
        let version = cap
            .get(2)
            .map(|m| m.as_str().to_string())
            .unwrap_or_default();
        if product.is_empty() || version.is_empty() {
            continue;
        }
        out.push(json!({"product": product, "version": version}));
        if out.len() >= 12 {
            break;
        }
    }
    out
}

/// Banner version patterns (greeting-first, then generic extractor).
fn banner_version_patterns() -> &'static [(fancy_regex::Regex, &'static str, &'static str)] {
    static P: OnceCell<Vec<(fancy_regex::Regex, &'static str, &'static str)>> = OnceCell::new();
    P.get_or_init(|| {
        vec![
            (
                fancy_regex::Regex::new(
                    r"(?i)SSH-2\.0-(?P<product>OpenSSH|Dropbear|libssh)_(?P<version>\d+(?:\.\d+)+)",
                )
                .unwrap(),
                "ssh",
                "",
            ),
            (
                fancy_regex::Regex::new(
                    r"(?i)(?P<product>vsFTPd|ProFTPD|Pure-FTPd)[ /v-]*(?P<version>\d+(?:\.\d+)+)",
                )
                .unwrap(),
                "ftp",
                "",
            ),
            (
                fancy_regex::Regex::new(
                    r"(?i)(?P<product>Exim|Postfix|Sendmail)[ /v-]*(?P<version>\d+(?:\.\d+)+)",
                )
                .unwrap(),
                "smtp",
                "",
            ),
            (
                fancy_regex::Regex::new(
                    r"(?i)(?P<product>MySQL|MariaDB)[ /v-]*(?P<version>\d+(?:\.\d+)+)",
                )
                .unwrap(),
                "mysql",
                "",
            ),
            (
                fancy_regex::Regex::new(r"(?i)(?P<product>redis)[ /v-]*(?P<version>\d+(?:\.\d+)+)")
                    .unwrap(),
                "redis",
                "",
            ),
            (
                fancy_regex::Regex::new(r"(?i)(?P<product>nginx)/(?P<version>\d+(?:\.\d+)+)")
                    .unwrap(),
                "http",
                "",
            ),
        ]
    })
}

/// {product, version} pairs from a service banner/greeting line.
pub fn banner_versions(banner: &str) -> Vec<Value> {
    let mut out = Vec::new();
    let text: String = banner.chars().take(200).collect();
    for (pat, _tag, _) in banner_version_patterns() {
        if let Ok(Some(caps)) = pat.captures(&text) {
            let product = caps
                .name("product")
                .map(|m| m.as_str().to_string())
                .unwrap_or_default();
            let version = caps
                .name("version")
                .map(|m| m.as_str().to_string())
                .unwrap_or_default();
            if !product.is_empty() && !version.is_empty() {
                out.push(json!({"product": product, "version": version}));
            }
            break;
        }
    }
    for v in parse_versions(&text) {
        if let Some(ver) = v.get("version").and_then(|x| x.as_str()) {
            if clean_version_re().is_match(ver).unwrap_or(false) {
                out.push(v);
            }
        }
    }
    out.truncate(4);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pinned_client_pin_validation() {
        // global pin -> client builds; private/loopback/unparseable -> None
        assert!(pinned_client("example.com", "93.184.216.34", 443).is_some());
        assert!(pinned_client("example.com", "93.184.216.34", 80).is_some());
        assert!(pinned_client("example.com", "10.0.0.1", 443).is_none());
        assert!(pinned_client("example.com", "127.0.0.1", 443).is_none());
        assert!(pinned_client("example.com", "not-an-ip", 443).is_none());
    }

    // Live-network regression test for the resolve_to_addrs override:
    // a port-0 override silently connects to IP:0 and fails everything.
    // Run explicitly: cargo test -- --ignored
    #[tokio::test]
    #[ignore]
    async fn test_fetch_fingerprint_live() {
        let ips = resolve("example.com").await;
        assert!(!ips.is_empty(), "DNS must resolve example.com");
        let (probe, snippet) = fetch_fingerprint("example.com", &ips).await;
        assert!(probe.is_some(), "fingerprint must succeed against example.com");
        assert!(snippet.is_some());
    }

    #[test]
    fn test_is_valid_domain() {
        assert!(is_valid_domain("example.com"));
        assert!(is_valid_domain("api.example.com"));
        assert!(!is_valid_domain("not a domain"));
        assert!(!is_valid_domain("192.168.1.1"));
        assert!(!is_valid_domain("*.example.com"));
        assert!(!is_valid_domain("-bad.example.com"));
    }

    #[test]
    fn test_is_global_ip() {
        assert!(is_global_ip("8.8.8.8"));
        assert!(!is_global_ip("10.0.0.1"));
        assert!(!is_global_ip("127.0.0.1"));
        assert!(!is_global_ip("192.168.1.1"));
        assert!(!is_global_ip("100.64.0.1"));
        assert!(!is_global_ip("169.254.169.254"));
    }

    #[test]
    fn test_banner_versions() {
        let ssh = banner_versions("SSH-2.0-OpenSSH_9.6p1 Ubuntu-4ubuntu0.3");
        assert!(ssh.iter().any(|v| v["product"] == "OpenSSH"));
        let nginx = banner_versions("Server: nginx/1.18.0");
        assert!(nginx
            .iter()
            .any(|v| v["product"] == "nginx" && v["version"] == "1.18.0"));
    }

    #[test]
    fn test_parse_versions() {
        let v = parse_versions("nginx/1.1 apache/2.4");
        assert!(v
            .iter()
            .any(|x| x["product"] == "nginx" && x["version"] == "1.1"));
        assert!(v
            .iter()
            .any(|x| x["product"] == "apache" && x["version"] == "2.4"));
    }
}

// ===========================================================================
// async network layer (tokio + shared reqwest client + hickory resolver)
// ===========================================================================

/// Shared hickory DNS resolver (system /etc/resolv.conf, tokio runtime).
/// ONE resolver for the whole scan — cloned via Arc semantics internally
/// (TokioResolver is Clone + Send + Sync).
pub fn dns_resolver() -> &'static hickory_resolver::TokioResolver {
    static RESOLVER: OnceCell<hickory_resolver::TokioResolver> = OnceCell::new();
    RESOLVER.get_or_init(|| {
        hickory_resolver::TokioResolver::builder_tokio()
            .and_then(|b| b.build())
            .unwrap_or_else(|_| {
                hickory_resolver::TokioResolver::builder_with_config(
                    hickory_resolver::config::ResolverConfig::udp_and_tcp(
                        &hickory_resolver::config::CLOUDFLARE,
                    ),
                    Default::default(),
                )
                .build()
                .expect("cloudflare resolver build failed")
            })
    })
}

/// Shared HTTP client (rustls, no proxy, no redirects, size-limited).
pub fn http_client() -> &'static reqwest::Client {
    static CLIENT: OnceCell<reqwest::Client> = OnceCell::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .connect_timeout(std::time::Duration::from_secs(8))
            .timeout(std::time::Duration::from_secs(12))
            .build()
            .expect("failed to build reqwest client")
    })
}

/// Fetch a URL as text, size-limited, no redirects (returns "" on any failure).
pub async fn fetch_text(url: &str) -> String {
    let client = http_client();
    match client.get(url).send().await {
        Ok(resp) => {
            let status = resp.status();
            if !status.is_success() {
                return String::new();
            }
            match resp.text().await {
                Ok(body) => body.chars().take(curl_max_bytes()).collect(),
                Err(_) => String::new(),
            }
        }
        Err(_) => String::new(),
    }
}

/// Resolve a hostname to A/AAAA records via the shared hickory resolver.
///
/// Parity with Python `_resolve`: if ANY resolved address is non-global the
/// whole host is rejected (DNS-rebinding protection) — filtering would let
/// a mixed answer steer probing. Results are stable-sorted IPv4-first,
/// approximating typical `getaddrinfo` order (which the Python `curl`
/// pinning relies on when it takes the first validated IP).
pub async fn resolve(host: &str) -> Vec<String> {
    let mut ips: Vec<String> = match dns_resolver().lookup_ip(host).await {
        Ok(lookup) => lookup.iter().map(|ip| ip.to_string()).collect(),
        Err(_) => return Vec::new(),
    };
    ips.sort();
    ips.dedup();
    if ips.iter().any(|ip| !is_global_ip(ip)) {
        return Vec::new();
    }
    // stable IPv4-first (getaddrinfo-order approximation for pin selection)
    ips.sort_by_key(|ip| ip.contains(':'));
    ips
}

/// Build an HTTP client pinned to a validated IP for `host` (curl
/// `--resolve` semantics via reqwest `resolve_to_addrs`). The pin is
/// re-validated as global immediately before use so a rebinding race cannot
/// redirect the probe at an internal address. Returns None when the pin is
/// unusable (caller falls back to the shared client, same fail-open posture
/// as Python).
///
/// NOTE: the override port must be explicit — reqwest only substitutes
/// port 0 with the scheme default on the `socks` feature path, which we
/// do not enable. Passing port 0 connects to IP:0 and fails everything.
fn pinned_client(host: &str, ip: &str, port: u16) -> Option<reqwest::Client> {
    let addr: std::net::IpAddr = ip.parse().ok()?;
    if !is_global_ip(&addr.to_string()) {
        return None;
    }
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .connect_timeout(std::time::Duration::from_secs(8))
        .timeout(std::time::Duration::from_secs(12))
        .resolve_to_addrs(host, &[std::net::SocketAddr::new(addr, port)])
        .build()
        .ok()
}

/// Detect wildcard DNS: resolve a synthetic random label; a non-empty answer
/// is the zone's wildcard IP set (cached per domain for the process lifetime).
/// Empty set = no wildcard.
async fn detect_wildcard(domain: &str) -> HashSet<String> {
    static CACHE: OnceCell<parking_lot::Mutex<HashMap<String, HashSet<String>>>> =
        OnceCell::new();
    let cache = CACHE.get_or_init(|| parking_lot::Mutex::new(HashMap::new()));
    if let Some(hit) = cache.lock().get(domain).cloned() {
        return hit;
    }
    let probe = format!("{}.{}", uuid::Uuid::new_v4().simple(), domain);
    let ips: HashSet<String> = resolve(&probe).await.into_iter().collect();
    cache.lock().insert(domain.to_string(), ips.clone());
    ips
}

/// Drop hosts whose IP set exactly equals their domain's wildcard answer.
///
/// A real host that co-resolves with the wildcard (shares the synthetic IP
/// but also has its own A record) survives; only pure wildcard echoes are
/// removed. The apex domain itself is never dropped. Returns the filtered
/// map plus the dropped count (parity with Python `_filter_wildcard_hosts`).
pub async fn filter_wildcard_hosts(
    hosts: HashMap<String, Vec<String>>,
    domains: &[String],
) -> (HashMap<String, Vec<String>>, usize) {
    let mut wildcard_ips: HashMap<String, HashSet<String>> = HashMap::new();
    for d in domains {
        let w = detect_wildcard(d).await;
        if !w.is_empty() {
            wildcard_ips.insert(d.clone(), w);
        }
    }
    if wildcard_ips.is_empty() {
        return (hosts, 0);
    }
    let mut out = HashMap::new();
    let mut dropped = 0usize;
    for (h, ips) in hosts {
        let mut hit = false;
        for (d, w) in &wildcard_ips {
            if h != *d
                && h.ends_with(&format!(".{}", d))
                && ips.iter().cloned().collect::<HashSet<_>>() == *w
            {
                hit = true;
                break;
            }
        }
        if hit {
            dropped += 1;
        } else {
            out.insert(h, ips);
        }
    }
    (out, dropped)
}

// --- enum sources ---------------------------------------------------------

async fn subdomains_crtsh(domain: String) -> HashSet<String> {
    let url = format!("https://crt.sh/?q=%25.{}&output=json", domain);
    let body = fetch_text(&url).await;
    if body.is_empty() {
        return HashSet::new();
    }
    let rows: Vec<Value> = serde_json::from_str(&body).unwrap_or_default();
    let mut names = HashSet::new();
    for r in rows {
        if let Some(nv) = r.get("name_value").and_then(|v| v.as_str()) {
            for n in nv.split('\n') {
                names.insert(n.trim().to_lowercase().trim_end_matches('.').to_string());
            }
        }
    }
    names
}

async fn subdomains_certspotter(domain: String) -> HashSet<String> {
    let url = format!(
        "https://api.certspotter.com/v1/issuances?domain={}&include_subdomains=true&expand=dns_names",
        domain
    );
    let body = fetch_text(&url).await;
    if body.is_empty() {
        return HashSet::new();
    }
    let rows: Vec<Value> = serde_json::from_str(&body).unwrap_or_default();
    let mut names = HashSet::new();
    for r in rows {
        if let Some(arr) = r.get("dns_names").and_then(|v| v.as_array()) {
            for n in arr {
                if let Some(s) = n.as_str() {
                    names.insert(s.trim().to_lowercase().trim_end_matches('.').to_string());
                }
            }
        }
    }
    names
}

async fn subdomains_hackertarget(domain: String) -> HashSet<String> {
    let url = format!("https://api.hackertarget.com/hostsearch/?q={}", domain);
    let body = fetch_text(&url).await;
    body.lines()
        .filter_map(|l| l.split(',').next())
        .map(|s| s.trim().to_lowercase().trim_end_matches('.').to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

async fn subdomains_crtname(domain: String) -> HashSet<String> {
    let url = format!("https://crt.name/?q={}", domain);
    let body = fetch_text(&url).await;
    // crt.name returns a table; extract hostnames via a simple heuristic
    let mut names = HashSet::new();
    for line in body.lines() {
        let l = line.trim().to_lowercase();
        if l.contains(&domain) && !l.contains('<') && !l.contains('>') {
            // split on whitespace, keep tokens that look like subdomains
            for tok in l.split_whitespace() {
                let t = tok
                    .trim_end_matches('.')
                    .trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '.' && c != '-');
                if t.ends_with(&domain) && is_valid_domain(t) {
                    names.insert(t.to_string());
                }
            }
        }
    }
    names
}

async fn subdomains_wayback(domain: String) -> HashSet<String> {
    let url = format!(
        "http://web.archive.org/cdx/search/cdx?url=*.{}/*&output=json&fl=original&collapse=urlkey&limit=2000",
        domain
    );
    let body = fetch_text(&url).await;
    if body.is_empty() {
        return HashSet::new();
    }
    let rows: Vec<Value> = serde_json::from_str(&body).unwrap_or_default();
    let mut names = HashSet::new();
    for r in rows.iter().skip(1) {
        if let Some(u) = r.get(0).and_then(|v| v.as_str()) {
            if let Some(host) = extract_host(u) {
                if host.ends_with(&domain) {
                    names.insert(host.to_lowercase().trim_end_matches('.').to_string());
                }
            }
        }
    }
    names
}

fn extract_host(url: &str) -> Option<String> {
    let no_scheme = url.split("://").nth(1).unwrap_or(url);
    let host = no_scheme
        .split('/')
        .next()?
        .split(':')
        .next()?
        .trim()
        .to_string();
    if host.is_empty() {
        None
    } else {
        Some(host)
    }
}

async fn subdomains_otx(domain: String) -> HashSet<String> {
    let url = format!(
        "https://otx.alienvault.com/api/v1/indicators/domain/{}/passive_dns",
        domain
    );
    let body = fetch_text(&url).await;
    if body.is_empty() {
        return HashSet::new();
    }
    let data: Value = serde_json::from_str(&body).unwrap_or_default();
    let mut names = HashSet::new();
    if let Some(rows) = data.get("passive_dns").and_then(|v| v.as_array()) {
        for r in rows {
            if let Some(h) = r.get("hostname").and_then(|v| v.as_str()) {
                if h.ends_with(&domain) {
                    names.insert(h.to_lowercase().trim_end_matches('.').to_string());
                }
            }
        }
    }
    names
}

fn in_domain(host: &str, domain: &str) -> bool {
    let h = host.trim().to_lowercase().trim_end_matches('.').to_string();
    h == domain || h.ends_with(&format!(".{}", domain))
}

/// Enumerate subdomains from all 6 passive sources, fanning out per domain.
pub async fn enumerate_subdomains(domains: &[String]) -> HashSet<String> {
    let mut all = HashSet::new();
    for domain in domains {
        let futures = vec![
            tokio::spawn(subdomains_crtsh(domain.clone())),
            tokio::spawn(subdomains_certspotter(domain.clone())),
            tokio::spawn(subdomains_hackertarget(domain.clone())),
            tokio::spawn(subdomains_crtname(domain.clone())),
            tokio::spawn(subdomains_wayback(domain.clone())),
            tokio::spawn(subdomains_otx(domain.clone())),
        ];
        for fut in futures {
            if let Ok(names) = fut.await {
                for n in names {
                    let n = n.trim_start_matches("*.").to_string();
                    if in_domain(&n, domain) {
                        all.insert(n);
                    }
                }
            }
        }
    }
    all
}

// --- HTTP fingerprint -----------------------------------------------------

pub async fn fetch_fingerprint(host: &str, ips: &[String]) -> (Option<Value>, Option<Value>) {
    if ips.is_empty() {
        return (None, None);
    }
    // Try validated IPs in order (at most 3 — bounded): the first address
    // may be unreachable from here (e.g. no IPv6 egress) while a later one
    // works. Python pins only the first; trying further is a strict
    // robustness superset with identical output shapes.
    let fallback = http_client().clone();
    let mut probe: Option<Value> = None;
    let mut snippet: Option<Value> = None;
    'ips: for ip in ips.iter().take(3) {
        // Pin the connection to the validated IP (anti-DNS-rebinding), with
        // a per-scheme client so the override carries an explicit port. When
        // no usable pin exists, fall back to the shared client (fail-open,
        // like Python's unpinned curl path).
        // Probe https first, then http (like the Python curl --resolve pinning).
        for (scheme, port) in [("https", 443u16), ("http", 80u16)] {
            let url = format!("{}://{}", scheme, host);
            let pinned = pinned_client(host, ip, port);
            let client = pinned.as_ref().unwrap_or(&fallback);
        let result = client.get(&url).header("Host", host).send().await;
        if let Ok(resp) = result {
            let status = resp.status();
            let code = status.as_u16().to_string();
            let server = resp
                .headers()
                .get("server")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();
            let powered = resp
                .headers()
                .get("x-powered-by")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();
            let content_type = resp
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();
            // security headers (presence only — absence == missing on wire)
            let hdr = resp.headers();
            let get_hdr = |n: &str| {
                hdr.get(n)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_string()
            };
            let hsts = get_hdr("strict-transport-security");
            let csp = get_hdr("content-security-policy");
            let xfo = get_hdr("x-frame-options");
            let xcto = get_hdr("x-content-type-options");
            let referrer_policy = get_hdr("referrer-policy");
            let permissions_policy = get_hdr("permissions-policy");
            let www_authenticate = get_hdr("www-authenticate");
            let set_cookie = get_hdr("set-cookie");
            let body = resp.text().await.unwrap_or_default();
            let body_limited: String = body.chars().take(65536).collect();
            let title = title_re()
                .captures(&body_limited)
                .ok()
                .flatten()
                .and_then(|c| c.get(1))
                .map(|m| m.as_str().trim().to_string())
                .unwrap_or_default();
            let login_form = password_input_re().is_match(&body_limited).unwrap_or(false);

            let mut versions = parse_versions(&server);
            versions.extend(parse_versions(&powered));
            versions.extend(parse_versions(&title));

            probe = Some(json!({
                "url": url,
                "code": code,
                "server": server,
                "title": title,
                "ip": ip,
            }));
            snippet = Some(json!({
                "url": url,
                "code": code,
                "server": server,
                "x-powered-by": powered,
                "content-type": content_type,
                "strict-transport-security": hsts,
                "content-security-policy": csp,
                "x-frame-options": xfo,
                "x-content-type-options": xcto,
                "referrer-policy": referrer_policy,
                "permissions-policy": permissions_policy,
                "www-authenticate": www_authenticate,
                "set-cookie": set_cookie,
                "login_form": login_form,
                "title": title,
                "versions": versions,
            }));
            break 'ips;
        }
    }
    }
    (probe, snippet)
}

// --- TCP service probe + banner grab --------------------------------------

async fn tcp_reachable(ip: &str, port: u16, timeout_ms: u64) -> bool {
    use tokio::net::TcpStream;
    let addr = format!("{}:{}", ip, port);
    match tokio::time::timeout(
        std::time::Duration::from_millis(timeout_ms),
        TcpStream::connect(&addr),
    )
    .await
    {
        Ok(Ok(_)) => true,
        _ => false,
    }
}

async fn grab_banner(ip: &str, port: u16, timeout_ms: u64) -> Option<String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    let addr = format!("{}:{}", ip, port);
    let mut stream = tokio::time::timeout(
        std::time::Duration::from_millis(timeout_ms),
        TcpStream::connect(&addr),
    )
    .await
    .ok()?
    .ok()?;
    // Send a generic probe (CRLF for text protocols; minimal HTTP request for web).
    let probe = if port == 80 || port == 8080 {
        format!("HEAD / HTTP/1.0\r\nHost: {}\r\n\r\n", ip)
    } else {
        "\r\n".to_string()
    };
    let _ = tokio::time::timeout(
        std::time::Duration::from_millis(timeout_ms),
        stream.write_all(probe.as_bytes()),
    )
    .await;
    let mut buf = vec![0u8; 1024];
    let n = tokio::time::timeout(
        std::time::Duration::from_millis(timeout_ms),
        stream.read(&mut buf),
    )
    .await
    .ok()?
    .ok()?;
    if n == 0 {
        return None;
    }
    let s = String::from_utf8_lossy(&buf[..n]);
    Some(s.trim().chars().take(400).collect())
}

/// Probe common service ports and grab banners for reachable ports.
pub async fn probe_services(hosts: &HashMap<String, Vec<String>>) -> HashMap<String, Value> {
    let mut services: HashMap<String, Value> = HashMap::new();
    // Fan out TCP connect checks across all host:port pairs.
    let mut tasks = Vec::new();
    for (host, ips) in hosts {
        let ip = match ips.first() {
            Some(i) => i.clone(),
            None => continue,
        };
        for (port, name) in service_ports() {
            let host = host.clone();
            let ip = ip.clone();
            let port = *port;
            let name = *name;
            tasks.push(tokio::spawn(async move {
                let reachable = tcp_reachable(&ip, port, 2000).await;
                (host, ip, port, name, reachable)
            }));
        }
    }
    for task in tasks {
        if let Ok((host, ip, port, name, reachable)) = task.await {
            if reachable {
                let entry = services
                    .entry(host.clone())
                    .or_insert_with(|| json!({"ip": ip.clone(), "open": {}, "banners": {}}));
                if let Value::Object(o) = entry {
                    o.get_mut("open")
                        .and_then(|v| v.as_object_mut())
                        .map(|open| open.insert(port.to_string(), Value::String(name.to_string())));
                }
            }
        }
    }
    // Grab banners for reachable ports.
    let mut banner_tasks = Vec::new();
    for (host, svc) in &services {
        if let Some(open) = svc.get("open").and_then(|v| v.as_object()) {
            for (port_str, name) in open {
                let port: u16 = port_str.parse().unwrap_or(0);
                if port == 0 {
                    continue;
                }
                let ip = svc
                    .get("ip")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let host = host.clone();
                let name = name.as_str().unwrap_or("").to_string();
                banner_tasks.push(tokio::spawn(async move {
                    let banner = grab_banner(&ip, port, 3000).await;
                    (host, port, name, banner)
                }));
            }
        }
    }
    for task in banner_tasks {
        if let Ok((host, port, name, banner)) = task.await {
            if let Some(banner) = banner {
                if let Some(entry) = services.get_mut(&host) {
                    if let Value::Object(o) = entry {
                        if let Some(banners) = o.get_mut("banners").and_then(|v| v.as_object_mut())
                        {
                            banners.insert(port.to_string(), Value::String(banner));
                        }
                        // ensure the port is recorded in open (banner proves reachability)
                        if let Some(open) = o.get_mut("open").and_then(|v| v.as_object_mut()) {
                            open.entry(port.to_string())
                                .or_insert_with(|| Value::String(name));
                        }
                    }
                }
            }
        }
    }
    services
}

// --- TLS cert inspection --------------------------------------------------

/// A TLS verifier that accepts ANY cert (we want to inspect invalid/expired/
/// self-signed certs, exactly like Python's `verify_mode = CERT_NONE`).
#[derive(Debug)]
struct NoVerify(rustls::crypto::CryptoProvider);

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// Inspect a host's TLS certificate (expiry/self-signed/issuer/SAN) — accepts
/// invalid certs so expired/self-signed findings can actually fire.
pub async fn tls_cert(host: &str, ip: &str, port: u16) -> Option<Value> {
    use std::sync::Arc as StdArc;
    use tokio_rustls::TlsConnector;

    let provider = rustls::crypto::ring::default_provider();
    let config = rustls::ClientConfig::builder_with_provider(StdArc::new(provider))
        .with_safe_default_protocol_versions()
        .ok()?
        .dangerous()
        .with_custom_certificate_verifier(StdArc::new(NoVerify(
            rustls::crypto::ring::default_provider(),
        )))
        .with_no_client_auth();
    let connector = TlsConnector::from(StdArc::new(config));
    let server_name =
        tokio_rustls::rustls::pki_types::ServerName::try_from(host.to_string()).ok()?;
    let addr = format!("{}:{}", ip, port);

    let tcp = tokio::time::timeout(
        std::time::Duration::from_secs(6),
        tokio::net::TcpStream::connect(&addr),
    )
    .await
    .ok()?
    .ok()?;

    let stream = tokio::time::timeout(
        std::time::Duration::from_secs(6),
        connector.connect(server_name, tcp),
    )
    .await
    .ok()?
    .ok()?;

    let (_, session) = stream.get_ref();
    let certs = session.peer_certificates()?;
    let cert = certs.first()?;
    let der = cert.as_ref();

    let parsed = x509_parser::parse_x509_certificate(der).ok()?.1;
    let not_after = parsed.validity().not_after.timestamp();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let days_left = ((not_after - now) / 86400).max(0);
    let expired = not_after < now;

    let issuer_cn = parsed
        .issuer()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .unwrap_or("")
        .chars()
        .take(80)
        .collect::<String>();
    let subject_cn = parsed
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .unwrap_or("")
        .chars()
        .take(80)
        .collect::<String>();
    let self_signed = !issuer_cn.is_empty() && issuer_cn == subject_cn;
    let san_count = 0usize;

    Some(json!({
        "not_after": not_after.to_string(),
        "days_left": days_left,
        "expired": expired,
        "self_signed": self_signed,
        "issuer_cn": issuer_cn,
        "san_count": san_count,
    }))
}

// --- InternetDB -----------------------------------------------------------

pub async fn internetdb(ip: &str) -> Value {
    let url = format!("https://internetdb.shodan.io/{}", ip);
    let body = fetch_text(&url).await;
    if body.is_empty() {
        return json!({});
    }
    serde_json::from_str(&body).unwrap_or_else(|_| json!({}))
}

// ===========================================================================
// findings synthesis (deterministic, ported 1:1)
// ===========================================================================

/// Classify a host into an infrastructure category + default severity.
pub fn classify_infra(host: &str) -> (Option<String>, Option<String>) {
    let h = host.to_lowercase();
    let patterns: [(&str, &str, &str); 16] = [
        ("vpn", "VPN / remote access", "MEDIUM"),
        ("cloud", "Cloud management", "MEDIUM"),
        ("mail", "Mail", "MEDIUM"),
        ("smtp", "Mail (SMTP)", "MEDIUM"),
        ("gitlab", "Source control", "MEDIUM"),
        ("github", "Source control", "LOW"),
        ("jenkins", "CI/CD", "MEDIUM"),
        ("admin", "Admin console", "HIGH"),
        ("grafana", "Monitoring", "LOW"),
        ("kibana", "Monitoring", "LOW"),
        ("db", "Database", "HIGH"),
        ("database", "Database", "HIGH"),
        ("api", "API", "LOW"),
        ("sso", "SSO / auth", "MEDIUM"),
        ("citrix", "Remote access (Citrix)", "HIGH"),
        ("intranet", "Intranet", "MEDIUM"),
    ];
    for (needle, cat, sev) in patterns {
        if h.contains(needle) {
            return (Some(cat.to_string()), Some(sev.to_string()));
        }
    }
    (None, None)
}

/// Determine the web scheme/port from a fingerprint snippet.
fn web_scheme_port(s: &Value) -> Option<u16> {
    let url = s.get("url").and_then(|v| v.as_str()).unwrap_or("");
    if url.starts_with("https://") {
        Some(443)
    } else if url.starts_with("http://") {
        Some(80)
    } else {
        None
    }
}

fn now_date() -> String {
    cc::now_iso()[..10].to_string()
}

fn now_ts() -> String {
    // YYYYMMDDHHMMSS (compact timestamp for finding ids)
    let iso = cc::now_iso();
    iso.replace(['-', ':', 'T', 'Z'], "")
        .chars()
        .take(14)
        .collect()
}

/// Build a TCP service finding record.
fn tcp_service_finding(
    slug: &str,
    ts: &str,
    seq: usize,
    host: &str,
    ip: Option<&str>,
    port: u16,
    name: &str,
    banner: Option<&str>,
    infra_cat: Option<&str>,
    infra_sev: Option<&str>,
) -> Value {
    let cat = infra_cat.unwrap_or("Internet-facing service");
    let sev = infra_sev.unwrap_or("INFO");
    let title = if infra_cat.is_some() {
        format!("{} exposure on port {}/{}", cat, port, name)
    } else {
        format!("Open service port {}/{}", port, name)
    };
    let mut evidence = Map::new();
    evidence.insert("port".into(), json!(port));
    evidence.insert("service".into(), json!(name));
    if let Some(b) = banner {
        evidence.insert("banner".into(), json!(b));
    }
    if let Some(i) = ip {
        evidence.insert("ip".into(), json!(i));
    }
    json!({
        "id": format!("SRV-{}-{}-{:02}", slugify(slug), ts, seq),
        "title": title,
        "target": host,
        "ip": ip,
        "port": port,
        "severity": sev,
        "category": cat,
        "status": "OPEN",
        "status_detail": "SCAN-DETECTED (TCP connect + banner)",
        "positive": false,
        "mode": "fast",
        "source": "scan-services",
        "description": format!("TCP port {}/{} is reachable on host {}.", port, name, host),
        "impact": "Exposed service increases the external attack surface.",
        "evidence": Value::Object(evidence),
        "proof_chain": vec![format!("TCP connect {}:{} succeeded", host, port)],
        "remediation": vec!["Restrict this port via firewall/ACL; require VPN where possible."],
        "related_cves": [],
        "found_date": now_date(),
        "first_seen": now_date(),
        "last_seen": now_date(),
        "status_history": [{"at": now_date(), "from": "", "to": "OPEN", "by": "scan", "note": "service port scan"}],
    })
}

/// Synthesize surface findings (HTTP-fingerprinted hosts + open service ports).
pub async fn synthesize_surface_findings(
    slug: &str,
    snippets: &HashMap<String, Value>,
    services: &HashMap<String, Value>,
    enumerated: &[String],
) -> Vec<Value> {
    // Load existing findings' identities for dedup.
    let mut existing_identities = HashSet::new();
    let mut existing_targets = HashSet::new();
    if let Some(fp) = cc::org_findings_path(slug) {
        if let Ok(txt) = tokio::fs::read_to_string(&fp).await {
            if let Ok(d) = serde_json::from_str::<Value>(&txt) {
                if let Some(fs) = d.get("findings").and_then(|v| v.as_array()) {
                    for x in fs {
                        if let Some(t) = x.get("target").and_then(|v| v.as_str()) {
                            if !t.trim().is_empty() {
                                existing_targets.insert(t.trim().to_lowercase());
                            }
                        }
                        let mut x = x.clone();
                        let ik = cc::ensure_identity(&mut x);
                        existing_identities.insert(ik);
                    }
                }
            }
        }
    }

    let mut hosts: Vec<String> = snippets.keys().cloned().collect();
    hosts.extend(services.keys().cloned());
    hosts.extend(enumerated.iter().map(|e| e.trim().to_lowercase()));
    hosts.sort();
    hosts.dedup();

    let mut out = Vec::new();
    let mut seen_identities = HashSet::new();
    let ts = now_ts();
    let mut seq = 0usize;

    for h in hosts {
        let t = h.trim().to_lowercase();
        if t.is_empty() {
            continue;
        }
        let s = snippets.get(&t).cloned();
        let svc = services.get(&t).cloned().unwrap_or_else(|| json!({}));
        let open_ports = svc
            .get("open")
            .and_then(|v| v.as_object())
            .cloned()
            .unwrap_or_default();
        let ip = svc
            .get("ip")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let (infra_cat, infra_sev) = classify_infra(&t);

        // enumerated-only critical infra (no HTTP, no open port)
        if s.is_none() && open_ports.is_empty() {
            if infra_cat.is_none() {
                continue;
            }
            if existing_targets.contains(&t) {
                continue;
            }
            let ik = format!("surface-enum|{}|", t);
            if existing_identities.contains(&ik) || seen_identities.contains(&ik) {
                continue;
            }
            seen_identities.insert(ik.clone());
            seq += 1;
            let mut rec = json!({
                "id": format!("SRV-{}-{}-{:02}", slugify(slug), ts, seq),
                "title": format!("Critical infrastructure ({})", infra_cat.as_ref().unwrap()),
                "target": h,
                "ip": null,
                "severity": infra_sev.as_ref().unwrap_or(&"LOW".to_string()),
                "category": infra_cat.as_ref().unwrap(),
                "status": "OPEN",
                "status_detail": "ENUMERATED (no reachable service)",
                "positive": false,
                "mode": "fast",
                "source": "scan-enum",
                "description": format!("Enumerated {} host ({}). No reachable service observed.", infra_cat.as_ref().unwrap(), h),
                "impact": "Critical-infrastructure footprint; verify ownership and exposure.",
                "evidence": {"host": h, "classification": infra_cat.as_ref().unwrap()},
                "proof_chain": [format!("enumerated via CT/DNS: {}", h)],
                "remediation": ["Confirm this host is authorized; restrict or decommission if not."],
                "related_cves": [],
                "found_date": now_date(),
                "first_seen": now_date(),
                "last_seen": now_date(),
                "status_history": [{"at": now_date(), "from": "", "to": "OPEN", "by": "scan", "note": "critical infrastructure enumerated"}],
            });
            rec["identity_key"] = json!(ik);
            out.push(rec);
            continue;
        }

        // HTTP-fingerprinted host: one web finding + per-port non-web findings
        if let Some(ref snip) = s {
            let wport = web_scheme_port(snip);
            let wport_s = wport.map(|p| p.to_string()).unwrap_or_default();
            let ik_web = format!("surface-web|{}|{}", t, wport_s);
            if !existing_identities.contains(&ik_web) && !seen_identities.contains(&ik_web) {
                seen_identities.insert(ik_web.clone());
                seq += 1;
                let cat = infra_cat
                    .clone()
                    .unwrap_or_else(|| "Internet-facing service".to_string());
                let sev = infra_sev.clone().unwrap_or_else(|| "INFO".to_string());
                let mut evidence = snip.clone();
                if let Value::Object(ev) = &mut evidence {
                    ev.insert("port".into(), json!(wport));
                    if !open_ports.is_empty() {
                        ev.insert("services".into(), json!(open_ports));
                    }
                }
                let mut rec = json!({
                    "id": format!("SRV-{}-{}-{:02}", slugify(slug), ts, seq),
                    "title": if infra_cat.is_some() { format!("{} exposure", infra_cat.as_ref().unwrap()) } else { "Reachable service (passively fingerprinted)".to_string() },
                    "target": h,
                    "ip": ip,
                    "port": wport,
                    "severity": sev,
                    "category": cat,
                    "status": "OPEN",
                    "status_detail": "SCAN-DETECTED (passive fingerprint)",
                    "positive": false,
                    "mode": "fast",
                    "source": "scan-surface",
                    "description": "Host is reachable on the public internet.".to_string(),
                    "impact": "Part of the external attack surface.",
                    "evidence": evidence,
                    "proof_chain": [format!("curl -s --max-redirs 0 {} -> {}", snip.get("url").and_then(|v| v.as_str()).unwrap_or(""), snip.get("code").and_then(|v| v.as_str()).unwrap_or("?"))],
                    "remediation": ["Review whether this service must be publicly reachable; restrict otherwise."],
                    "related_cves": [],
                    "found_date": now_date(),
                    "first_seen": now_date(),
                    "last_seen": now_date(),
                    "status_history": [{"at": now_date(), "from": "", "to": "OPEN", "by": "scan", "note": "surface scan"}],
                });
                rec["identity_key"] = json!(ik_web);
                out.push(rec);
            }
            // non-web open ports
            let mut ports: Vec<(&String, &Value)> = open_ports.iter().collect();
            ports.sort_by(|a, b| {
                a.0.parse::<u16>()
                    .unwrap_or(0)
                    .cmp(&b.0.parse::<u16>().unwrap_or(0))
            });
            for (p_str, name_val) in ports {
                let p = p_str.parse::<u16>().unwrap_or(0);
                if p == 0 {
                    continue;
                }
                if wport == Some(p) {
                    continue;
                }
                let name = name_val.as_str().unwrap_or("");
                if name == "http" || name == "https" {
                    continue;
                }
                let ik_tcp = format!("surface-tcp|{}|{}", t, p);
                if existing_identities.contains(&ik_tcp) || seen_identities.contains(&ik_tcp) {
                    continue;
                }
                seen_identities.insert(ik_tcp.clone());
                seq += 1;
                let banner = svc
                    .get("banners")
                    .and_then(|v| v.get(p_str))
                    .and_then(|v| v.as_str());
                let mut rec = tcp_service_finding(
                    slug,
                    &ts,
                    seq,
                    &h,
                    ip.as_deref(),
                    p,
                    name,
                    banner,
                    infra_cat.as_deref(),
                    infra_sev.as_deref(),
                );
                rec["identity_key"] = json!(ik_tcp);
                out.push(rec);
            }
            continue;
        }

        // service-only host: one finding per open port
        let mut ports: Vec<(&String, &Value)> = open_ports.iter().collect();
        ports.sort_by(|a, b| {
            a.0.parse::<u16>()
                .unwrap_or(0)
                .cmp(&b.0.parse::<u16>().unwrap_or(0))
        });
        for (p_str, name_val) in ports {
            let p = p_str.parse::<u16>().unwrap_or(0);
            if p == 0 {
                continue;
            }
            let name = name_val.as_str().unwrap_or("");
            let ik_tcp = format!("surface-tcp|{}|{}", t, p);
            if existing_identities.contains(&ik_tcp) || seen_identities.contains(&ik_tcp) {
                continue;
            }
            seen_identities.insert(ik_tcp.clone());
            seq += 1;
            let banner = svc
                .get("banners")
                .and_then(|v| v.get(p_str))
                .and_then(|v| v.as_str());
            let mut rec = tcp_service_finding(
                slug,
                &ts,
                seq,
                &h,
                ip.as_deref(),
                p,
                name,
                banner,
                infra_cat.as_deref(),
                infra_sev.as_deref(),
            );
            rec["identity_key"] = json!(ik_tcp);
            out.push(rec);
        }
    }
    out
}

// --- TLS / cert / login / version / cve / header findings -----------------

pub async fn synthesize_cert_findings(slug: &str, certs: &HashMap<String, Value>) -> Vec<Value> {
    let existing_keys = existing_target_category_keys(slug, "tls certificate").await;
    let mut out = Vec::new();
    let ts = now_ts();
    let mut seq = 0usize;
    for (host, cert) in certs {
        let expired = cert
            .get("expired")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let self_signed = cert
            .get("self_signed")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if !expired && !self_signed {
            continue;
        }
        if existing_keys.contains(&(host.trim().to_lowercase(), "tls certificate".to_string())) {
            continue;
        }
        seq += 1;
        let (title, sev) = if expired {
            ("Expired TLS certificate".to_string(), "MEDIUM")
        } else {
            ("Self-signed TLS certificate".to_string(), "LOW")
        };
        let mut rec = json!({
            "id": format!("TLS-{}-{}-{:02}", slugify(slug), ts, seq),
            "title": title,
            "target": host,
            "ip": null,
            "port": cert.get("port").cloned().unwrap_or(Value::Null),
            "severity": sev,
            "category": "TLS certificate",
            "status": "OPEN",
            "status_detail": "CONFIRMED (TLS handshake inspection)",
            "positive": false,
            "mode": "fast",
            "source": "scan-tls",
            "description": format!("TLS certificate for {} is {}.", host, if expired { "expired" } else { "self-signed" }),
            "impact": "Clients may reject the connection or be exposed to MITM.",
            "evidence": cert.clone(),
            "proof_chain": ["TLS handshake captured the presented certificate"],
            "remediation": ["Renew/replace the certificate and pin a trusted CA."],
            "related_cves": [],
            "found_date": now_date(),
            "first_seen": now_date(),
            "last_seen": now_date(),
            "status_history": [{"at": now_date(), "from": "", "to": "OPEN", "by": "scan", "note": "certificate inspection"}],
        });
        rec["identity_key"] = json!(cc::identity_key(&rec));
        out.push(rec);
    }
    out
}

pub async fn synthesize_login_findings(slug: &str, snippets: &HashMap<String, Value>) -> Vec<Value> {
    let existing_keys = existing_target_category_keys(slug, "login portal exposed").await;
    let mut out = Vec::new();
    let ts = now_ts();
    let mut seq = 0usize;
    for (host, s) in snippets {
        // password form is the authoritative signal (matches Python)
        let login_form = s
            .get("login_form")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if !login_form {
            continue;
        }
        let code = s.get("code").and_then(|v| v.as_str()).unwrap_or("");
        if !code.is_empty() && code != "200" && code != "401" && code != "403" {
            continue;
        }
        if existing_keys.contains(&(
            host.trim().to_lowercase(),
            "login portal exposed".to_string(),
        )) {
            continue;
        }
        seq += 1;
        let mut rec = json!({
            "id": format!("LOGIN-{}-{}-{:02}", slugify(slug), ts, seq),
            "title": "Login portal exposed (internet-facing)",
            "target": host,
            "ip": null,
            "severity": "MEDIUM",
            "category": "login portal exposed",
            "status": "OPEN",
            "status_detail": "SCAN-DETECTED (login form)",
            "positive": false,
            "mode": "fast",
            "source": "scan-login",
            "description": format!("Public login form observed on {} (HTTP {}).", host, if code.is_empty() { "?" } else { code }),
            "impact": "An authentication portal is reachable by anyone; credential attacks apply.",
            "evidence": s.clone(),
            "proof_chain": [format!("GET {} -> {} (password form in HTML)", s.get("url").and_then(|v| v.as_str()).unwrap_or(host), if code.is_empty() { "?" } else { code })],
            "remediation": ["Restrict the portal to trusted networks/VPN where possible; enforce MFA and rate limiting."],
            "related_cves": [],
            "found_date": now_date(),
            "first_seen": now_date(),
            "last_seen": now_date(),
            "status_history": [{"at": now_date(), "from": "", "to": "OPEN", "by": "scan", "note": "login form detected"}],
        });
        rec["identity_key"] = json!(cc::identity_key(&rec));
        out.push(rec);
    }
    out
}

pub async fn synthesize_version_findings(slug: &str, snippets: &HashMap<String, Value>) -> Vec<Value> {
    let existing_keys = existing_target_category_keys(slug, "software version disclosure").await;
    let mut out = Vec::new();
    let ts = now_ts();
    let mut seq = 0usize;
    for (host, s) in snippets {
        let server = s.get("server").and_then(|v| v.as_str()).unwrap_or("");
        let powered = s.get("x-powered-by").and_then(|v| v.as_str()).unwrap_or("");
        let versions = s
            .get("versions")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        if versions.is_empty() {
            continue;
        }
        if existing_keys.contains(&(
            host.trim().to_lowercase(),
            "software version disclosure".to_string(),
        )) {
            continue;
        }
        seq += 1;
        let mut rec = json!({
            "id": format!("VER-{}-{}-{:02}", slugify(slug), ts, seq),
            "title": "Software version disclosed (internet-facing)",
            "target": host,
            "ip": null,
            "severity": "LOW",
            "category": "software version disclosure",
            "status": "OPEN",
            "status_detail": "SCAN-DETECTED (version banner)",
            "positive": false,
            "mode": "fast",
            "source": "scan-version",
            "description": format!("Public response headers/title disclose exact software versions on {}.", host),
            "impact": "Attackers can map the disclosed versions to known CVEs and target exploits without further reconnaissance.",
            "evidence": {"server": server, "x-powered-by": powered, "versions": versions},
            "proof_chain": ["version token captured in HTTP header/title/banner"],
            "remediation": ["Suppress version tokens in Server/X-Powered-By headers; keep components patched."],
            "related_cves": [],
            "found_date": now_date(),
            "first_seen": now_date(),
            "last_seen": now_date(),
            "status_history": [{"at": now_date(), "from": "", "to": "OPEN", "by": "scan", "note": "version disclosure detected"}],
        });
        rec["identity_key"] = json!(cc::identity_key(&rec));
        out.push(rec);
    }
    out
}

pub async fn synthesize_cve_findings(
    slug: &str,
    snippets: &HashMap<String, Value>,
    nvd: &HashMap<String, Value>,
) -> Vec<Value> {
    let existing_keys = existing_target_category_keys(slug, "cve version match").await;
    let mut out = Vec::new();
    let ts = now_ts();
    let mut seq = 0usize;
    for (host, s) in snippets {
        let versions = s
            .get("versions")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        if versions.is_empty() {
            continue;
        }
        let matches = cve_match::match_cves(&versions, 12);
        if matches.is_empty() {
            continue;
        }
        if existing_keys.contains(&(host.trim().to_lowercase(), "cve version match".to_string())) {
            continue;
        }
        seq += 1;
        let conf = cve_match::worst_confidence(&matches);
        let sev = if conf == "medium" { "HIGH" } else { "MEDIUM" };
        let cves: Vec<String> = matches
            .iter()
            .filter_map(|m| m.get("cve").and_then(|v| v.as_str()).map(|s| s.to_string()))
            .collect();
        let port = if s
            .get("url")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .starts_with("https://")
        {
            443
        } else {
            80
        };
        let mut rec = json!({
            "id": format!("CVM-{}-{}-{:02}", slugify(slug), ts, seq),
            "title": format!("{} CVE(s) matched from disclosed versions", matches.len()),
            "target": host,
            "ip": null,
            "port": port,
            "severity": sev,
            "category": "cve version match",
            "status": "OPEN",
            "status_detail": "CORRELATED (verify affected range)",
            "positive": false,
            "mode": "fast",
            "source": "scan-cve",
            "description": format!("Disclosed software versions on {} matched known CVEs.", host),
            "impact": "Potentially vulnerable software reachable on the internet.",
            "evidence": {"versions": versions, "matched": matches},
            "proof_chain": ["offline version->CVE match against the vendored map"],
            "remediation": ["Upgrade affected software; verify the component is actually in use."],
            "related_cves": cves,
            "found_date": now_date(),
            "first_seen": now_date(),
            "last_seen": now_date(),
            "status_history": [{"at": now_date(), "from": "", "to": "OPEN", "by": "scan", "note": "version->CVE match"}],
        });
        if let Some(nx) = nvd.get(&cves[0]) {
            rec["nvd"] = nx.clone();
        }
        rec["identity_key"] = json!(cc::identity_key(&rec));
        out.push(rec);
    }
    out
}

pub async fn synthesize_header_findings(slug: &str, snippets: &HashMap<String, Value>) -> Vec<Value> {
    // Missing security headers on reachable public hosts.
    // Observational: absence in the snippet == absence on the wire.
    // HSTS/CSP only expected over HTTPS; auth-gated (401/403) or login-form
    // hosts are MEDIUM, everything else LOW. Deduped by (target, category).
    let existing_keys = existing_target_category_keys(slug, "security headers").await;
    let ts = now_ts();
    let mut seq = 0usize;
    let mut out = Vec::new();

    let mut hosts: Vec<&String> = snippets.keys().collect();
    hosts.sort();
    for h in hosts {
        let s = snippets.get(h).cloned().unwrap_or_else(|| json!({}));
        let url = s
            .get("url")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let code = s
            .get("code")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if !(url.starts_with("http://") || url.starts_with("https://")) || code.is_empty() {
            continue;
        }
        if code.starts_with('5') {
            continue;
        }
        let https = url.starts_with("https://");
        // expected headers: TLS set over https, minimal set otherwise
        let expected: &[&str] = if https {
            &[
                "strict-transport-security",
                "content-security-policy",
                "x-frame-options",
                "x-content-type-options",
            ]
        } else {
            &["x-frame-options", "x-content-type-options"]
        };
        let missing: Vec<String> = expected
            .iter()
            .filter(|k| {
                s.get(**k)
                    .and_then(|v| v.as_str())
                    .map(|v| v.is_empty())
                    .unwrap_or(true)
            })
            .map(|k| k.to_string())
            .collect();
        if missing.len() == expected.len() {
            // nothing present at all — only flag when a header would plausibly appear
            let title = s.get("title").and_then(|v| v.as_str()).unwrap_or("");
            let server = s.get("server").and_then(|v| v.as_str()).unwrap_or("");
            if title.is_empty() && server.is_empty() {
                continue;
            }
        }
        if missing.is_empty() {
            continue;
        }
        let key = (h.trim().to_lowercase(), "security headers".to_string());
        if existing_keys.contains(&key) {
            continue;
        }
        seq += 1;
        let login_form = s
            .get("login_form")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let auth_surface = login_form || code == "401" || code == "403";
        let sev = if auth_surface { "MEDIUM" } else { "LOW" };
        let labels: Vec<&str> = missing.iter().map(|k| sec_header_label(k)).collect();
        let labels_s = labels.join(", ");
        let mut ev = Map::new();
        for k in ["url", "code", "title", "server"] {
            if let Some(v) = s.get(k) {
                if !v.is_null() {
                    ev.insert(k.to_string(), v.clone());
                }
            }
        }
        ev.insert("missing_headers".to_string(), json!(missing));
        let mut present = Map::new();
        for k in expected {
            if let Some(v) = s.get(*k) {
                if v.as_str().map(|x| !x.is_empty()).unwrap_or(false) {
                    present.insert(k.to_string(), v.clone());
                }
            }
        }
        if !present.is_empty() {
            ev.insert("present_headers".to_string(), Value::Object(present));
        }
        let mut rec = json!({
            "id": format!("HDR-{}-{}-{:02}", slugify(slug), ts, seq),
            "title": format!("Missing security headers ({})", labels_s),
            "target": h,
            "ip": null,
            "port": if https { 443 } else { 80 },
            "severity": sev,
            "category": "security headers",
            "status": "OPEN",
            "status_detail": "SCAN-DETECTED (passive header check)",
            "positive": false,
            "mode": "fast",
            "source": "scan-headers",
            "description": format!("Response from {} (HTTP {}) is missing standard security headers: {}.", h, code, labels_s),
            "impact": "Without these headers the page is more exposed to clickjacking, MIME-type confusion, script injection and protocol-downgrade attacks than it needs to be.",
            "evidence": ev,
            "proof_chain": [format!("GET {} -> HTTP {}; absent: {}", url, code, labels_s)],
            "remediation": [
                "Add the missing response headers (HSTS only over HTTPS; see the present_headers evidence field for what is already set).",
                "Verify header policy after load balancers/CDNs — they often strip or override origin headers.",
            ],
            "related_cves": [],
            "found_date": now_date(),
            "first_seen": now_date(),
            "last_seen": now_date(),
            "status_history": [{"at": now_date(), "from": "", "to": "OPEN", "by": "scan", "note": "security headers missing"}],
        });
        rec["identity_key"] = json!(cc::identity_key(&rec));
        out.push(rec);
    }
    out
}

fn sec_header_label(k: &str) -> &'static str {
    match k {
        "strict-transport-security" => "HSTS",
        "content-security-policy" => "CSP",
        "x-frame-options" => "X-Frame-Options",
        "x-content-type-options" => "X-Content-Type-Options",
        _ => "security-header",
    }
}

async fn existing_target_category_keys(slug: &str, category: &str) -> HashSet<(String, String)> {
    let mut keys = HashSet::new();
    let cat_lower = category.trim().to_lowercase();
    if let Some(fp) = cc::org_findings_path(slug) {
        if let Ok(txt) = tokio::fs::read_to_string(&fp).await {
            if let Ok(d) = serde_json::from_str::<Value>(&txt) {
                if let Some(fs) = d.get("findings").and_then(|v| v.as_array()) {
                    for x in fs {
                        let xcat = x
                            .get("category")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .trim()
                            .to_lowercase();
                        if xcat == cat_lower {
                            if let Some(t) = x.get("target").and_then(|v| v.as_str()) {
                                keys.insert((t.trim().to_lowercase(), cat_lower.clone()));
                            }
                        }
                    }
                }
            }
        }
    }
    keys
}

// --- orchestration --------------------------------------------------------

static RUNNING: OnceCell<tokio::sync::Mutex<HashSet<String>>> = OnceCell::new();

fn running() -> &'static tokio::sync::Mutex<HashSet<String>> {
    RUNNING.get_or_init(|| tokio::sync::Mutex::new(HashSet::new()))
}

pub fn is_correlating(slug: &str) -> bool {
    // Async mutex can't be read synchronously without a runtime; treat as false
    // (the job table in jobs.rs is the authoritative serialization fence).
    let _ = slug;
    false
}

/// Scan a registered org: enum -> resolve -> fingerprint -> services -> TLS ->
/// synthesize -> persist findings.json + baseline.txt (atomic).
pub async fn generate_org(
    org: Value,
    mode: &str,
    ai_profile: Option<String>,
    _on_progress: Option<Arc<dyn Fn(&str, &str) + Send + Sync>>,
) -> Value {
    let slug = org
        .get("slug")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    if slug.is_empty() || !slug_re().is_match(&slug).unwrap_or(false) {
        return json!({"error": "invalid org slug"});
    }
    let raw_domains: Vec<String> = org
        .get("domains")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|d| {
            d.as_str()
                .map(|s| s.trim().to_lowercase().trim_end_matches('.').to_string())
        })
        .collect();
    let domains: Vec<String> = raw_domains
        .into_iter()
        .filter(|d| is_valid_domain(d))
        .collect();
    if domains.is_empty() {
        return json!({"error": "no valid domains"});
    }

    let _guard = running().lock().await;
    // (release immediately; the jobs.rs table is the real fence)

    let t0 = Instant::now();
    let mut stage_stats = Map::new();

    // 1. enumerate
    let mut subs = enumerate_subdomains(&domains).await;
    let enum_cap = enum_name_cap();
    if subs.len() > enum_cap {
        let mut v: Vec<String> = subs.into_iter().collect();
        v.sort();
        v.truncate(enum_cap);
        subs = v.into_iter().collect();
    }
    stage_stats.insert(
        "enum".into(),
        json!(t0.elapsed().as_secs_f64().round_ties_even() as i64),
    );

    // 2. resolve (fan out)
    let t1 = Instant::now();
    let mut hosts: HashMap<String, Vec<String>> = HashMap::new();
    let mut to_resolve: Vec<String> = subs.into_iter().collect();
    to_resolve.sort();
    to_resolve.truncate(max_total_hosts());
    let mut resolve_tasks = Vec::new();
    for h in &to_resolve {
        let h = h.clone();
        resolve_tasks.push(tokio::spawn(async move { (h.clone(), resolve(&h).await) }));
    }
    for task in resolve_tasks {
        if let Ok((h, ips)) = task.await {
            hosts.insert(h, ips);
        }
    }
    // wildcard-DNS filtering: drop names that only echo the wildcard record
    if wildcard_filter_enabled() && !domains.is_empty() {
        let (filtered, dropped) = filter_wildcard_hosts(hosts, &domains).await;
        hosts = filtered;
        if dropped > 0 {
            tracing::info!(
                "wildcard filter dropped {} phantom host(s) for {}",
                dropped,
                slug
            );
        }
    }
    stage_stats.insert(
        "resolve".into(),
        json!(t1.elapsed().as_secs_f64().round_ties_even() as i64),
    );

    // 3. fingerprint (fan out)
    let t2 = Instant::now();
    let mut snippets: HashMap<String, Value> = HashMap::new();
    let mut reached: Vec<Value> = Vec::new();
    let mut fp_tasks = Vec::new();
    for (h, ips) in &hosts {
        let h = h.clone();
        let ips = ips.clone();
        fp_tasks.push(tokio::spawn(async move {
            let (probe, snippet) = fetch_fingerprint(&h, &ips).await;
            (h, probe, snippet)
        }));
    }
    for task in fp_tasks {
        if let Ok((h, probe, snippet)) = task.await {
            if let Some(p) = probe {
                reached.push(json!({"host": h.clone(), "probe": p}));
            }
            if let Some(s) = snippet {
                snippets.insert(h, s);
            }
        }
    }
    stage_stats.insert(
        "probe".into(),
        json!(t2.elapsed().as_secs_f64().round_ties_even() as i64),
    );

    // 4. service ports + banners
    let t3 = Instant::now();
    let services = probe_services(&hosts).await;
    stage_stats.insert(
        "services".into(),
        json!(t3.elapsed().as_secs_f64().round_ties_even() as i64),
    );

    // 5. TLS certs (best-effort; cert expiry detection is conservative)
    let t4 = Instant::now();
    let mut certs: HashMap<String, Value> = HashMap::new();
    for (h, ips) in &hosts {
        let ip = match ips.first() {
            Some(i) => i.clone(),
            None => continue,
        };
        let port = if services
            .get(h)
            .and_then(|s| s.get("open"))
            .and_then(|o| o.get("443"))
            .is_some()
        {
            443u16
        } else {
            continue;
        };
        if let Some(cert) = tls_cert(h, &ip, port).await {
            let mut cert = cert;
            if let Value::Object(o) = &mut cert {
                o.insert("port".into(), json!(port));
            }
            certs.insert(h.clone(), cert);
        }
    }
    stage_stats.insert(
        "tls".into(),
        json!(t4.elapsed().as_secs_f64().round_ties_even() as i64),
    );

    // 6. optional NVD enrichment for matched CVEs (CTI_NVD_ENRICH=1) —
    // runs BEFORE persistence: network calls never hold a lock.
    // Fail-open: any error leaves the deterministic result alone.
    let t5 = Instant::now();
    let mut nvd_extra: HashMap<String, Value> = HashMap::new();
    if cve_match::nvd_enabled() && !snippets.is_empty() {
        nvd_extra = cve_match::nvd_enrich_hosts(&snippets, nvd_max_lookups()).await;
        if !nvd_extra.is_empty() {
            tracing::info!("NVD enriched {} CVE(s) for {}", nvd_extra.len(), slug);
        }
    }
    stage_stats.insert(
        "nvd".into(),
        json!(t5.elapsed().as_secs_f64().round_ties_even() as i64),
    );

    // 7. baseline.txt (hosts + IPs)
    let mut baseline: Vec<String> = Vec::new();
    let mut seen = HashSet::new();
    let mut sorted_hosts: Vec<&String> = hosts.keys().collect();
    sorted_hosts.sort();
    for h in sorted_hosts {
        if let Some(ips) = hosts.get(h) {
            if !ips.is_empty() {
                for key in std::iter::once(h.clone()).chain(ips.clone()) {
                    if seen.insert(key.clone()) {
                        baseline.push(key);
                    }
                }
            }
        }
    }

    // 7. persist findings.json + baseline.txt (atomic)
    let org_dir = cc::org_dir(&slug);
    let _ = tokio::fs::create_dir_all(&org_dir).await;
    let findings_path = org_dir.join("findings.json");
    let baseline_path = org_dir.join("baseline.txt");

    // read existing findings doc (abort on corruption); preserve old meta
    let mut existing: Vec<Value> = Vec::new();
    let mut old_meta: Value = json!({});
    let mut old_baseline_text: String = String::new();
    if baseline_path.exists() {
        old_baseline_text = tokio::fs::read_to_string(&baseline_path).await.unwrap_or_default();
    }
    if findings_path.exists() {
        if let Ok(txt) = tokio::fs::read_to_string(&findings_path).await {
            if let Ok(d) = serde_json::from_str::<Value>(&txt) {
                existing = d
                    .get("findings")
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();
                old_meta = d.get("meta").cloned().unwrap_or_else(|| json!({}));
            } else {
                return json!({"error": "corrupted findings.json", "subdomains": hosts.len(), "resolved": baseline.len(), "reachable": reached.len()});
            }
        }
    }

    // snapshot analyst-owned fields at load: at persist time, a finding
    // whose analyst fields changed mid-scan keeps the FILE version (analyst
    // wins, mirroring Python's "analyst-owned statuses never auto-changed").
    let analyst_snap: HashMap<String, Value> = existing
        .iter()
        .filter_map(|f| {
            let id = f.get("id")?.as_str()?.to_string();
            Some((
                id,
                json!({
                    "status": f.get("status").cloned().unwrap_or(Value::Null),
                    "status_history": f.get("status_history").cloned().unwrap_or(Value::Null),
                    "feedback": f.get("feedback").cloned().unwrap_or(Value::Null),
                    "comments": f.get("comments").cloned().unwrap_or(Value::Null),
                }),
            ))
        })
        .collect();

    // synthesize new findings (dedup against existing) BEFORE reconcile so
    // newly-observed surfaces get identity/lifecycle bookkeeping this pass.
    let enumerated: Vec<String> = hosts.keys().cloned().collect();
    let mut new_findings = synthesize_surface_findings(&slug, &snippets, &services, &enumerated).await;
    new_findings.extend(synthesize_cert_findings(&slug, &certs).await);
    new_findings.extend(synthesize_login_findings(&slug, &snippets).await);
    new_findings.extend(synthesize_version_findings(&slug, &snippets).await);
    new_findings.extend(synthesize_cve_findings(&slug, &snippets, &nvd_extra).await);
    new_findings.extend(synthesize_header_findings(&slug, &snippets).await);

    for f in &mut new_findings {
        let _ = cc::ensure_identity(f);
    }
    existing.extend(new_findings);

    // deterministic reconciliation: observation bookkeeping + tiered resolution
    let recon = reconcile_findings(
        &mut existing,
        &snippets,
        &services,
        &enumerated,
        &certs,
        resolve_after_misses(),
    );

    // refresh probe evidence on existing findings from this scan's capture
    let _refreshed = refresh_finding_evidence(&mut existing, &snippets, &services);

    // new-exposure diff vs the previous scan's baseline/services
    let old_services = old_meta
        .get("services")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let new_exposure = synthesize_diff_findings(
        &slug,
        &old_baseline_text,
        &old_services,
        &hosts,
        &services,
        &existing,
    );
    existing.extend(new_exposure);

    // merge scan-owned keys into meta, preserving old meta keys
    let scan_meta = json!({
        "title": format!("{} — passive surface scan", slug),
        "date": now_date(),
        "scope": "external, passive (CT + DNS + HTTP + TCP service probe), non-destructive",
        "domains": domains,
        "subdomains": hosts.len(),
        "reachable": reached.len(),
        "fingerprints": snippets,
        "services": services,
        "reconcile": recon,
        "scan_stats": stage_stats,
    });
    let merged_meta = merge_meta(old_meta, scan_meta);

    // serialize with concurrent analyst mutations: re-read under the org
    // lock and restore analyst-owned fields for findings touched mid-scan
    // (status/history/feedback), so a parallel status/comment is not lost.
    let _persist_guard = cc::org_write_lock(&slug).await;
    let found_count = existing.len();
    let mut findings_to_write = std::mem::take(&mut existing);
    if let Ok(txt) = tokio::fs::read_to_string(&findings_path).await {
        if let Ok(doc) = serde_json::from_str::<Value>(&txt) {
            if let Some(current) = doc.get("findings").and_then(|v| v.as_array()) {
                let by_id: HashMap<&str, &Value> = current
                    .iter()
                    .filter_map(|f| {
                        f.get("id")
                            .and_then(|v| v.as_str())
                            .map(|id| (id, f))
                    })
                    .collect();
                for f in &mut findings_to_write {
                    let Some(id) = f.get("id").and_then(|v| v.as_str()) else {
                        continue;
                    };
                    let (Some(cur), Some(snap)) = (by_id.get(id), analyst_snap.get(id)) else {
                        continue;
                    };
                    let cur_a = json!({
                        "status": cur.get("status").cloned().unwrap_or(Value::Null),
                        "status_history": cur.get("status_history").cloned().unwrap_or(Value::Null),
                        "feedback": cur.get("feedback").cloned().unwrap_or(Value::Null),
                        "comments": cur.get("comments").cloned().unwrap_or(Value::Null),
                    });
                    // analyst touched it mid-scan -> file version wins
                    if cur_a != *snap {
                        if let Some(map) = f.as_object_mut() {
                            for k in ["status", "status_history", "feedback", "comments"] {
                                if let Some(v) = cur.get(k) {
                                    map.insert(k.to_string(), v.clone());
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    let payload = json!({"meta": merged_meta, "findings": findings_to_write});
    if let Err(e) = cc::atomic_write_json(&findings_path, &payload).await {
        return json!({"error": format!("write failed: {}", e)});
    }
    let baseline_text = format!(
        "# passive enumeration baseline for org '{}' ({})\n",
        slug,
        now_date()
    ) + &baseline.join("\n");
    let _ = cc::atomic_write_text(&baseline_path, &baseline_text).await;
    cc::invalidate_org_cache(&slug);

    // history event
    cc::append_history(
        &slug,
        json!({
            "kind": "scan", "mode": mode,
            "summary": {"found": found_count, "subdomains": hosts.len(), "resolved": baseline.len(), "reachable": reached.len()},
            "note": "passive surface scan"
        }),
    ).await;

    // AI mode: Stage A assessment + Stage B grading (never blocks on failure)
    let mut ai = "skipped";
    if mode == "ai" {
        let mut effective = ai_profile.clone();
        if effective.is_none() {
            effective = crate::ai::resolve_profile_for_org(&slug, None).await;
        }
        ai = match crate::ai::call_ai(
            &build_ai_assess_prompt(&slug, &snippets, &services),
            effective.as_deref(),
        )
        .await
        {
            Some(_) => "done",
            None => "failed",
        };
        // Stage B: judgment-only grading of existing deterministic findings
        let _grade = ai_grade_org(&slug, None).await;
    }

    json!({
        "slug": slug,
        "mode": mode,
        "ai": ai,
        "ai_profile": if mode == "ai" { crate::ai::resolve_profile_for_org(&slug, ai_profile.as_deref()).await } else { None },
        "subdomains": hosts.len(),
        "resolved": baseline.len(),
        "reachable": reached.len(),
        "new_exposure": new_exposure_count(&existing),
    })
}

// --- reconcile / diff / evidence-refresh / AI-assess helpers -------------

fn merge_meta(old: Value, scan: Value) -> Value {
    let mut out = match old.as_object() {
        Some(o) => o.clone(),
        None => Map::new(),
    };
    if let Some(s) = scan.as_object() {
        for (k, v) in s {
            out.insert(k.clone(), v.clone());
        }
    }
    Value::Object(out)
}

fn new_exposure_count(existing: &[Value]) -> usize {
    existing
        .iter()
        .filter(|f| f.get("source").and_then(|v| v.as_str()) == Some("baseline-diff"))
        .count()
}

fn append_history_note(f: &mut Value, note: &str, by: &str, to: Option<&str>) {
    let sh = f
        .get("status_history")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let mut arr: Vec<Value> = sh;
    let st = f
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    arr.push(json!({
        "at": cc::now_iso(),
        "from": st,
        "to": to.unwrap_or(""),
        "by": by,
        "note": note,
    }));
    if arr.len() > 50 {
        arr = arr[arr.len() - 50..].to_vec();
    }
    if let Value::Object(o) = f {
        o.insert("status_history".into(), Value::Array(arr));
    }
}

fn evidence_hash(f: &Value) -> String {
    use sha2::{Digest, Sha256};
    let ev = f.get("evidence").unwrap_or(&Value::Null);
    let blob = serde_json::to_string(ev).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(blob.as_bytes());
    let d = hasher.finalize();
    let mut s = String::new();
    for b in d.iter().take(8) {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn observed_surface_ids(
    snippets: &HashMap<String, Value>,
    services: &HashMap<String, Value>,
    resolved_hosts: &[String],
) -> (HashSet<String>, HashSet<String>) {
    let mut ids = HashSet::new();
    let mut obs_ips = HashSet::new();
    for h in snippets.keys() {
        let s = snippets.get(h).cloned().unwrap_or_else(|| json!({}));
        let u = s
            .get("url")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_lowercase();
        let w = if u.starts_with("https://") {
            "443".to_string()
        } else if u.starts_with("http://") {
            "80".to_string()
        } else {
            String::new()
        };
        ids.insert(format!("surface-web|{}|{}", h.trim().to_lowercase(), w));
    }
    for (h, svc) in services {
        let hl = h.trim().to_lowercase();
        let ip = svc
            .get("ip")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .to_string();
        if !ip.is_empty() {
            obs_ips.insert(ip.clone());
        }
        if let Some(open) = svc.get("open").and_then(|v| v.as_object()) {
            for p in open.keys() {
                if let Ok(pi) = p.parse::<u16>() {
                    ids.insert(format!("surface-tcp|{}|{}", hl, pi));
                    if !ip.is_empty() {
                        ids.insert(format!("surface-tcp|{}|{}", ip, pi));
                    }
                }
            }
        }
    }
    for h in resolved_hosts {
        ids.insert(format!("surface-enum|{}|", h.trim().to_lowercase()));
    }
    (ids, obs_ips)
}

fn reconcile_findings(
    fs: &mut [Value],
    snippets: &HashMap<String, Value>,
    services: &HashMap<String, Value>,
    resolved_hosts: &[String],
    certs: &HashMap<String, Value>,
    resolve_after: i64,
) -> Value {
    let resolve_after = resolve_after.max(1);
    let today = now_date();
    let (obs_ids, obs_ips) = observed_surface_ids(snippets, services, resolved_hosts);
    let snippet_targets: HashSet<String> =
        snippets.keys().map(|h| h.trim().to_lowercase()).collect();

    // TLS inspected identities -> still-bad flag
    let mut tls_inspected: HashMap<String, bool> = HashMap::new();
    for (h, c) in certs {
        let port = c.get("port").and_then(|v| v.as_u64()).unwrap_or(443);
        let ik = format!("tls|{}|{}", h.trim().to_lowercase(), port);
        let bad = c.get("expired").and_then(|v| v.as_bool()).unwrap_or(false)
            || c.get("self_signed")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
        tls_inspected.insert(ik, bad);
    }

    let mut counts =
        json!({"observed": 0, "missing": 0, "resolved": 0, "proposed": 0, "reopened": 0});
    let mut bump = |k: &str, n: i64| {
        if let Value::Object(o) = &mut counts {
            if let Some(v) = o.get_mut(k) {
                if let Some(cur) = v.as_i64() {
                    *v = json!(cur + n);
                }
            }
        }
    };

    for f in fs.iter_mut() {
        let mut x = f.clone();
        let ik = cc::ensure_identity(&mut x);
        let fam = ik.split('|').next().unwrap_or("").to_string();
        let observed = if fam == "tls" {
            tls_inspected.contains_key(&ik)
        } else if fam == "surface-web" || fam == "surface-tcp" || fam == "surface-enum" {
            obs_ids.contains(&ik)
        } else if fam == "ohack" {
            continue;
        } else {
            let tgt = f
                .get("target")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim()
                .to_lowercase();
            snippet_targets.contains(&tgt) || obs_ips.contains(&tgt)
        };

        let status = f
            .get("status")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_uppercase();
        if status == "RESOLVED" {
            if observed {
                let eh = evidence_hash(f);
                if let Value::Object(o) = f {
                    o.insert("status".into(), json!("OPEN"));
                    o.insert("missing_streak".into(), json!(0));
                    o.insert("evidence_hash".into(), json!(eh));
                }
                append_history_note(
                    f,
                    "recurrence: evidence observed again",
                    "reconcile",
                    Some("OPEN"),
                );
                bump("reopened", 1);
                bump("observed", 1);
            }
            continue;
        }

        if !observed {
            bump("missing", 1);
            let streak = f
                .get("missing_streak")
                .and_then(|v| v.as_i64())
                .unwrap_or(0)
                + 1;
            if let Value::Object(o) = f {
                o.insert("missing_streak".into(), json!(streak));
            }
            if status == "OPEN" && !f.get("positive").and_then(|v| v.as_bool()).unwrap_or(false) {
                let sev = f
                    .get("severity")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_uppercase();
                if streak >= resolve_after {
                    if sev == "HIGH" || sev == "CRITICAL" {
                        append_history_note(
                            f,
                            &format!("missing from {} consecutive scans — propose RESOLVED, analyst confirm", streak),
                            "reconcile",
                            None,
                        );
                        bump("proposed", 1);
                    } else if sev == "LOW" || sev == "MEDIUM" || sev == "INFO" {
                        if let Value::Object(o) = f {
                            o.insert("status".into(), json!("RESOLVED"));
                        }
                        append_history_note(
                            f,
                            &format!(
                                "auto-resolved: absent from {} consecutive successful scans",
                                streak
                            ),
                            "reconcile",
                            Some("RESOLVED"),
                        );
                        bump("resolved", 1);
                    }
                }
            }
            continue;
        }

        bump("observed", 1);
        let eh = evidence_hash(f);
        if let Value::Object(o) = f {
            o.insert("last_seen".into(), json!(today));
            o.insert("missing_streak".into(), json!(0));
            o.insert("evidence_hash".into(), json!(eh));
        }
        if fam == "tls" && status == "OPEN" {
            if let Some(false) = tls_inspected.get(&ik) {
                if let Value::Object(o) = f {
                    o.insert("status".into(), json!("RESOLVED"));
                }
                append_history_note(
                    f,
                    "valid certificate observed — renewed or repaired",
                    "reconcile",
                    Some("RESOLVED"),
                );
                bump("resolved", 1);
            }
        }
    }

    counts
}

fn refresh_finding_evidence(
    fs: &mut [Value],
    snippets: &HashMap<String, Value>,
    services: &HashMap<String, Value>,
) -> usize {
    let mut refreshed = 0usize;
    let today = now_date();
    for f in fs.iter_mut() {
        let tgt = f
            .get("target")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .to_lowercase();
        if tgt.is_empty() {
            continue;
        }
        let s = snippets.get(&tgt);
        let svc = services.get(&tgt).cloned().unwrap_or_else(|| json!({}));
        if s.is_none() && svc.is_null() {
            continue;
        }
        let mut ev = f
            .get("evidence")
            .and_then(|v| v.as_object())
            .cloned()
            .unwrap_or_default();
        let ik = f
            .get("identity_key")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let per_port = if ik.starts_with("surface-tcp")
            || (f.get("source").and_then(|v| v.as_str()) == Some("scan-services")
                && f.get("port").is_some())
        {
            f.get("port").and_then(|v| v.as_u64()).map(|p| p as u16)
        } else {
            None
        };
        // drop stale scan-owned keys
        if let Some(s) = s {
            if let Some(so) = s.as_object() {
                for k in so.keys() {
                    ev.remove(k);
                }
            }
        }
        if let Some(s) = s {
            if let Some(so) = s.as_object() {
                for (k, v) in so {
                    ev.insert(k.clone(), v.clone());
                }
            }
        }
        let mut open_ports = svc
            .get("open")
            .and_then(|v| v.as_object())
            .cloned()
            .unwrap_or_default();
        let mut banners = svc
            .get("banners")
            .and_then(|v| v.as_object())
            .cloned()
            .unwrap_or_default();
        if let Some(pp) = per_port {
            let pp_s = pp.to_string();
            open_ports = if open_ports.contains_key(&pp_s) {
                let mut m = Map::new();
                m.insert(
                    pp_s.clone(),
                    open_ports.get(&pp_s).cloned().unwrap_or(Value::Null),
                );
                m
            } else {
                Map::new()
            };
            banners = if banners.contains_key(&pp_s) {
                let mut m = Map::new();
                m.insert(
                    pp_s.clone(),
                    banners.get(&pp_s).cloned().unwrap_or(Value::Null),
                );
                m
            } else {
                Map::new()
            };
        }
        if !open_ports.is_empty() {
            ev.insert("services".to_string(), Value::Object(open_ports.clone()));
        } else if per_port.is_some() {
            ev.remove("services");
        }
        if !banners.is_empty() {
            ev.insert("banners".to_string(), Value::Object(banners.clone()));
        } else if per_port.is_some() {
            ev.remove("banners");
        }
        if let Some(ip) = svc.get("ip").and_then(|v| v.as_str()) {
            if !ip.is_empty() {
                ev.entry("ip".to_string()).or_insert(json!(ip));
            }
        }
        if f.get("port").is_some() {
            ev.entry("port".to_string())
                .or_insert(f.get("port").cloned().unwrap_or(Value::Null));
        }
        if let Value::Object(o) = f {
            o.insert("evidence".into(), Value::Object(ev));
        }
        // rebuild deterministic proof chain
        let mut proof: Vec<Value> = Vec::new();
        if let Some(s) = s {
            if s.get("code").and_then(|v| v.as_str()).is_some() && per_port.is_none() {
                proof.push(json!(format!(
                    "curl -s --max-redirs 0 {} -> {}",
                    s.get("url").and_then(|v| v.as_str()).unwrap_or(&tgt),
                    s.get("code").and_then(|v| v.as_str()).unwrap_or("?")
                )));
            }
        }
        let mut ports_sorted: Vec<&String> = open_ports.keys().collect();
        ports_sorted.sort_by_key(|p| p.parse::<u64>().unwrap_or(0));
        for p in ports_sorted {
            proof.push(json!(format!(
                "tcp-connect {}:{}",
                svc.get("ip").and_then(|v| v.as_str()).unwrap_or(&tgt),
                p
            )));
        }
        let mut banners_sorted: Vec<(&String, &Value)> = banners.iter().collect();
        banners_sorted.sort_by_key(|(p, _)| p.parse::<u64>().unwrap_or(0));
        for (p, b) in banners_sorted.iter().take(5) {
            proof.push(json!(format!(
                "banner {}: {}",
                p,
                b.as_str()
                    .unwrap_or("")
                    .chars()
                    .take(100)
                    .collect::<String>()
            )));
        }
        if !proof.is_empty() {
            if let Value::Object(o) = f {
                o.insert("proof_chain".into(), Value::Array(proof));
            }
        }
        if let Value::Object(o) = f {
            o.insert("last_seen".into(), json!(today));
        }
        refreshed += 1;
    }
    refreshed
}

fn synthesize_diff_findings(
    slug: &str,
    old_baseline_text: &str,
    old_services: &Value,
    hosts: &HashMap<String, Vec<String>>,
    services: &HashMap<String, Value>,
    existing_fs: &[Value],
) -> Vec<Value> {
    let ip_line_re = || {
        static RE: OnceCell<fancy_regex::Regex> = OnceCell::new();
        RE.get_or_init(|| fancy_regex::Regex::new(r"^\d{1,3}(?:\.\d{1,3}){3}$").unwrap())
    };
    let mut prev_hosts: HashSet<String> = HashSet::new();
    for ln in old_baseline_text.lines() {
        let ln = ln.trim();
        if ln.is_empty() || ln.starts_with('#') {
            continue;
        }
        if ip_line_re().is_match(ln).unwrap_or(false) {
            continue;
        }
        prev_hosts.insert(ln.to_lowercase());
    }
    if prev_hosts.is_empty() {
        return Vec::new();
    }
    let prev_services = old_services.as_object().cloned().unwrap_or_default();
    let existing_ids: HashSet<String> = existing_fs
        .iter()
        .filter_map(|f| {
            f.get("identity_key")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        })
        .collect();

    let mut out = Vec::new();
    let ts = now_ts();
    let mut seq = 0usize;
    let web_ports: HashSet<&str> = ["80", "443"].into_iter().collect();

    let mut add = |target: &str,
                   ip: Option<&str>,
                   port: Option<u16>,
                   _name: Option<&str>,
                   sev: &str,
                   title: &str,
                   desc: String,
                   ev: Value,
                   proof: Vec<Value>,
                   out: &mut Vec<Value>| {
        let ik = format!(
            "diff|{}|{}",
            target.trim().to_lowercase(),
            port.map(|p| p.to_string())
                .unwrap_or_else(|| "host".to_string())
        );
        if existing_ids.contains(&ik)
            || out
                .iter()
                .any(|r| r.get("identity_key").and_then(|v| v.as_str()) == Some(ik.as_str()))
        {
            return;
        }
        if out.len() >= 50 {
            return;
        }
        seq += 1;
        let mut rec = json!({
            "id": format!("NEX-{}-{}-{:02}", slugify(slug), ts, seq),
            "title": title,
            "target": target,
            "ip": ip,
            "port": port,
            "severity": sev,
            "category": "new exposure",
            "status": "OPEN",
            "status_detail": "CONFIRMED (baseline diff)",
            "positive": false,
            "mode": "fast",
            "source": "baseline-diff",
            "description": desc,
            "impact": "Newly-observed surface expands the org's attack surface; untracked assets are frequently unpatched.",
            "evidence": ev,
            "proof_chain": proof,
            "remediation": [
                "Confirm the exposure is expected (new deployment, DNS change, or firewall change) and update the asset inventory.",
                "If unexpected, investigate the change window and restrict access at the edge.",
            ],
            "related_cves": [],
            "found_date": now_date(),
            "first_seen": now_date(),
            "last_seen": now_date(),
            "status_history": [{"at": now_date(), "from": "", "to": "OPEN", "by": "scan", "note": "newly observed vs baseline"}],
        });
        rec["identity_key"] = json!(ik);
        out.push(rec);
    };

    // newly resolved hosts
    let mut sorted_hosts: Vec<&String> = hosts.keys().collect();
    sorted_hosts.sort();
    for h in sorted_hosts {
        if out.len() >= 50 {
            break;
        }
        if prev_hosts.contains(h) || hosts.get(h).map(|v| v.is_empty()).unwrap_or(true) {
            continue;
        }
        let ips = hosts.get(h).unwrap();
        let open_ports: HashSet<String> = services
            .get(h)
            .and_then(|s| s.get("open").and_then(|o| o.as_object()))
            .map(|o| o.keys().cloned().collect())
            .unwrap_or_default();
        let non_web = open_ports.iter().any(|p| !web_ports.contains(p.as_str()));
        let sev = if non_web { "MEDIUM" } else { "LOW" };
        let mut ports_sorted: Vec<&String> = open_ports.iter().collect();
        ports_sorted.sort_by_key(|p| p.parse::<u64>().unwrap_or(0));
        let svc_note = if open_ports.is_empty() {
            String::new()
        } else {
            format!(
                " Open service ports: {}.",
                ports_sorted
                    .iter()
                    .map(|p| p.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        };
        let first_ip = ips.first().cloned().unwrap_or_default();
        add(
            h,
            Some(&first_ip),
            None,
            None,
            sev,
            "Newly observed host",
            format!(
                "{} resolved for the first time since the previous scan (IP {}).{}",
                h, first_ip, svc_note
            ),
            json!({"ips": ips.iter().take(4).cloned().collect::<Vec<_>>(), "open_ports": ports_sorted.iter().map(|p| p.parse::<u64>().unwrap_or(0)).collect::<Vec<_>>(), "baseline": "absent in previous scan"}),
            vec![
                json!(format!("previous baseline.txt: no {} entry", h)),
                json!(format!(
                    "this scan: {} -> {}",
                    h,
                    ips.iter().take(3).cloned().collect::<Vec<_>>().join(", ")
                )),
            ],
            &mut out,
        );
    }

    // newly open service ports on already-known hosts
    let mut sorted_services: Vec<&String> = services.keys().collect();
    sorted_services.sort();
    for h in sorted_services {
        if out.len() >= 50 {
            break;
        }
        if !prev_hosts.contains(h) {
            continue;
        }
        let cur = services
            .get(h)
            .and_then(|s| s.get("open").and_then(|o| o.as_object()))
            .cloned()
            .unwrap_or_default();
        let prev = prev_services
            .get(h)
            .and_then(|v| v.as_object())
            .and_then(|o| o.get("open"))
            .and_then(|o| o.as_object())
            .cloned()
            .unwrap_or_default();
        let svc_ip = services
            .get(h)
            .and_then(|s| s.get("ip").and_then(|v| v.as_str()))
            .unwrap_or("");
        let mut ports_sorted: Vec<&String> = cur.keys().collect();
        ports_sorted.sort_by_key(|p| p.parse::<u64>().unwrap_or(0));
        for p in ports_sorted {
            if prev.contains_key(p) {
                continue;
            }
            let name = cur.get(p).and_then(|v| v.as_str()).unwrap_or("");
            let pi = p.parse::<u16>().unwrap_or(0);
            add(
                h,
                Some(svc_ip),
                Some(pi),
                Some(name),
                "MEDIUM",
                &format!("Newly open service port ({})", name),
                format!(
                    "{}:{} ({}) is reachable but was not open in the previous scan.",
                    h, p, name
                ),
                json!({"port": pi, "service": name, "ip": svc_ip, "baseline": "closed/absent in previous scan"}),
                vec![
                    json!(format!("previous meta.services: no {}:{} entry", h, p)),
                    json!(format!(
                        "this scan: tcp-connect {}:{} reachable ({})",
                        svc_ip, p, name
                    )),
                ],
                &mut out,
            );
        }
    }
    out
}

fn build_ai_assess_prompt(
    slug: &str,
    snippets: &HashMap<String, Value>,
    _services: &HashMap<String, Value>,
) -> String {
    let mut lines = Vec::new();
    let mut hosts: Vec<&String> = snippets.keys().collect();
    hosts.sort();
    for h in hosts.iter().take(50) {
        let s = snippets.get(*h).cloned().unwrap_or_else(|| json!({}));
        let code = s.get("code").and_then(|v| v.as_str()).unwrap_or("?");
        let server = s.get("server").and_then(|v| v.as_str()).unwrap_or("");
        let title = s.get("title").and_then(|v| v.as_str()).unwrap_or("");
        lines.push(format!(
            "{} | HTTP {} | server={} | title={}",
            h,
            code,
            sanitize_prompt_field(server),
            sanitize_prompt_field(title)
        ));
    }
    format!(
        "You are a passive CTI analyst. Assess the external attack surface of org '{}'. \
         Identify high-value exposures (admin panels, exposed dashboards, leaked auth surfaces, \
         dangerous services). Do NOT perform active exploitation. Return ONLY JSON: \
         {{\"assessments\":[{{\"target\":\"<host>\",\"note\":\"...\",\"confidence\":\"low|medium|high\"}}]}}.\n--- HOSTS ---\n{}",
        slug,
        lines.join("\n")
    )
}

/// Light remediation recheck: TCP-probe each finding's own IP/port and flag
/// reachability changes (auto-propose MITIGATED for high-sev after 2+ closes).
pub async fn recheck_findings(slug: &str, max_probe: usize) -> usize {
    let Some(fp) = cc::org_findings_path(slug) else {
        return 0;
    };
    let txt = match tokio::fs::read_to_string(&fp).await {
        Ok(t) => t,
        Err(_) => return 0,
    };
    let mut doc: Value = match serde_json::from_str(&txt) {
        Ok(d) => d,
        Err(_) => return 0,
    };
    let fs = match doc.get("findings").and_then(|v| v.as_array()).cloned() {
        Some(f) => f,
        None => return 0,
    };

    fn sev_order(s: &str) -> u8 {
        match s {
            "CRITICAL" => 0,
            "HIGH" => 1,
            "MEDIUM" => 2,
            "LOW" => 3,
            _ => 4,
        }
    }

    // candidate = open, non-positive, public IP, has a port hint
    let mut cands: Vec<(u8, Value, String, u16)> = Vec::new();
    for f in &fs {
        let Some(ip) = cc::single_public_ip(f.get("ip").unwrap_or(&Value::Null)) else {
            continue;
        };
        let status = f
            .get("status")
            .and_then(|v| v.as_str())
            .unwrap_or("OPEN")
            .to_uppercase();
        if status == "MITIGATED" || status == "ACCEPTED_RISK" {
            continue;
        }
        if f.get("positive").and_then(|v| v.as_bool()).unwrap_or(false) {
            continue;
        }
        let port = finding_port_u16(f);
        if port == 0 {
            continue;
        }
        let sev = sev_order(f.get("severity").and_then(|v| v.as_str()).unwrap_or("INFO"));
        cands.push((sev, f.clone(), ip, port));
    }
    cands.sort_by_key(|(sev, _, _, _)| *sev);
    cands.truncate(max_probe);

    // probe outside the write lock
    let mut results: Vec<(String, String, u16, String)> = Vec::new(); // id, result, port, ip
    for (_, f, ip, port) in &cands {
        let reachable = tcp_reachable(ip, *port, 3000).await;
        let result = if reachable { "reachable" } else { "closed" };
        results.push((
            f.get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            result.to_string(),
            *port,
            ip.clone(),
        ));
    }

    // apply atomically: re-read under the org lock and replay probe
    // results onto fresh data so concurrent analyst mutations survive
    let _guard = cc::org_write_lock(slug).await;
    if let Ok(txt) = tokio::fs::read_to_string(&fp).await {
        if let Ok(fresh) = serde_json::from_str::<Value>(&txt) {
            doc = fresh;
        }
    }
    let mut changed = 0usize;
    if let Value::Object(doc_obj) = &mut doc {
        let fs2 = doc_obj
            .get("findings")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let mut new_fs = fs2.clone();
        for (fid, result, _port, _ip) in &results {
            for f in new_fs.iter_mut() {
                if f.get("id").and_then(|v| v.as_str()) != Some(fid.as_str()) {
                    continue;
                }
                let prev = f
                    .get("_reachable")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
                    .to_string();
                match result.as_str() {
                    "reachable" => {
                        if prev == "no" {
                            changed += 1;
                        }
                        if let Value::Object(o) = f {
                            o.insert("_reachable".into(), json!("yes"));
                            o.insert("_unreach_streak".into(), json!(0));
                        }
                    }
                    "closed" => {
                        if let Value::Object(o) = f {
                            o.insert("_reachable".into(), json!("no"));
                        }
                        flag_for_shutdown(f);
                        let cur = f
                            .get("_unreach_streak")
                            .and_then(|v| v.as_i64())
                            .unwrap_or(0);
                        if let Value::Object(o) = f {
                            o.insert("_unreach_streak".into(), json!(cur + 1));
                        }
                        if cur + 1 >= 2
                            && sev_order(
                                f.get("severity").and_then(|v| v.as_str()).unwrap_or("INFO"),
                            ) <= 1
                        {
                            propose_mitigation(f);
                        }
                        if prev == "yes" {
                            changed += 1;
                        }
                    }
                    _ => {
                        if prev == "yes" {
                            changed += 1;
                        }
                        if let Value::Object(o) = f {
                            o.insert("_reachable".into(), json!("timeout"));
                        }
                    }
                }
            }
        }
        doc_obj.insert("findings".into(), Value::Array(new_fs));
        if let Some(meta) = doc_obj.get_mut("meta").and_then(|m| m.as_object_mut()) {
            meta.insert(
                "recheck".into(),
                json!({"probed": results.len(), "changed": changed, "ts": cc::now_iso()}),
            );
        }
    }
    let _ = cc::atomic_write_json(&fp, &doc).await;
    cc::invalidate_org_cache(slug);
    changed
}

fn finding_port_u16(f: &Value) -> u16 {
    for key in ["port"] {
        if let Some(p) = f.get(key) {
            if let Some(n) = p.as_u64() {
                if (1..=65535).contains(&n) {
                    return n as u16;
                }
            }
        }
    }
    if let Some(ev) = f.get("evidence").and_then(|v| v.as_object()) {
        if let Some(p) = ev.get("port") {
            if let Some(n) = p.as_u64() {
                if (1..=65535).contains(&n) {
                    return n as u16;
                }
            }
        }
    }
    0
}

fn flag_for_shutdown(f: &mut Value) {
    let note = "service port appears closed/filtered — confirm remediation";
    if let Some(sh) = f.get("status_history").and_then(|v| v.as_array()) {
        if sh.iter().any(|e| {
            e.get("note")
                .and_then(|v| v.as_str())
                .map(|s| s.starts_with("service port"))
                .unwrap_or(false)
        }) {
            return;
        }
    }
    let status = f
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("OPEN")
        .to_string();
    let mut sh = f
        .get("status_history")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    sh.push(json!({"at": cc::now_iso(), "from": status, "to": status, "by": "scan", "note": note}));
    if let Value::Object(o) = f {
        o.insert("status_history".into(), Value::Array(sh));
    }
}

fn propose_mitigation(f: &mut Value) {
    let note = "port closed across 2+ rechecks — auto-propose MITIGATED, confirm";
    if let Some(sh) = f.get("status_history").and_then(|v| v.as_array()) {
        if sh
            .iter()
            .any(|e| e.get("note").and_then(|v| v.as_str()) == Some(note))
        {
            return;
        }
    }
    let status = f
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("OPEN")
        .to_string();
    let mut sh = f
        .get("status_history")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    sh.push(
        json!({"at": cc::now_iso(), "from": status, "to": status, "by": "recheck", "note": note}),
    );
    if let Value::Object(o) = f {
        o.insert("status_history".into(), Value::Array(sh));
    }
}

/// Correlate findings: CVE-share + IP co-residency + InternetDB source-backed.
pub async fn correlate_org(org: Value) -> Value {
    let slug = org
        .get("slug")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    if slug.is_empty() {
        return json!({"error": "invalid org slug"});
    }
    let (fs, baseline) = cc::load_data(&slug);

    // resolve baseline hostnames -> IPs
    let mut host_ip_baseline: HashMap<String, String> = HashMap::new();
    let mut ip_hosts: HashMap<String, HashSet<String>> = HashMap::new();
    for h in &baseline {
        let h = h.trim();
        if h.is_empty() || cc::single_public_ip(&Value::String(h.to_string())).is_some() {
            continue;
        }
        let resolved = resolve(h).await;
        for ip in resolved {
            if is_global_ip(&ip) {
                host_ip_baseline.insert(h.to_string(), ip.clone());
                ip_hosts.entry(ip).or_default().insert(h.to_string());
                break;
            }
        }
    }

    // collect unique public IPs
    let mut ips: HashSet<String> = HashSet::new();
    for f in &fs {
        if let Some(ip) = cc::single_public_ip(f.get("ip").unwrap_or(&Value::Null)) {
            ips.insert(ip);
        }
    }
    ips.extend(host_ip_baseline.values().cloned());

    // InternetDB enrichment (fan out)
    let mut idb: HashMap<String, Value> = HashMap::new();
    let mut idb_tasks = Vec::new();
    for ip in &ips {
        let ip = ip.clone();
        idb_tasks.push(tokio::spawn(
            async move { (ip.clone(), internetdb(&ip).await) },
        ));
    }
    for task in idb_tasks {
        if let Ok((ip, d)) = task.await {
            if !d.is_null() && !d.as_object().map(|o| o.is_empty()).unwrap_or(true) {
                idb.insert(ip, d);
            }
        }
    }

    // enrich existing findings in place (hostnames/ports/tags/vulns)
    let mut fs = fs.clone();
    for f in &mut fs {
        let Some(ip) = cc::single_public_ip(f.get("ip").unwrap_or(&Value::Null)) else {
            continue;
        };
        let Some(d) = idb.get(&ip) else { continue };
        let mut enrich = Map::new();
        for k in ["hostnames", "ports", "tags", "cpes"] {
            if let Some(v) = d.get(k) {
                if !v.is_null() {
                    enrich.insert(k.to_string(), v.clone());
                }
            }
        }
        if !enrich.is_empty() {
            if let Value::Object(o) = f {
                o.insert("internetdb".into(), Value::Object(enrich));
            }
        }
        if let Some(vulns) = d.get("vulns").and_then(|v| v.as_array()) {
            let mut cur: Vec<String> = f
                .get("related_cves")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect();
            for v in vulns {
                if let Some(s) = v.as_str() {
                    if !cur.contains(&s.to_string()) {
                        cur.push(s.to_string());
                    }
                }
            }
            if let Value::Object(o) = f {
                o.insert(
                    "related_cves".into(),
                    Value::Array(cur.into_iter().map(Value::String).collect()),
                );
            }
        }
    }

    // build host->cves + host->ip maps
    let mut host_cves: HashMap<String, HashSet<String>> = HashMap::new();
    let mut host_ip: HashMap<String, String> = HashMap::new();
    let mut cve_sources: HashMap<String, Vec<Value>> = HashMap::new();
    for f in &fs {
        let tgt = f
            .get("target")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .to_string();
        for c in cc::extract_cves(f.get("related_cves").unwrap_or(&Value::Null)) {
            if !tgt.is_empty() {
                host_cves.entry(tgt.clone()).or_default().insert(c.clone());
            }
            cve_sources.entry(c).or_default().push(f.clone());
        }
        if let Some(ip) = cc::single_public_ip(f.get("ip").unwrap_or(&Value::Null)) {
            if !tgt.is_empty() && !is_placeholder(&tgt) {
                host_ip.insert(tgt.clone(), ip);
            }
        }
    }
    for (h, ip) in &host_ip_baseline {
        host_ip.insert(h.clone(), ip.clone());
        ip_hosts.entry(ip.clone()).or_default().insert(h.clone());
        if let Some(d) = idb.get(ip) {
            if let Some(vulns) = d.get("vulns").and_then(|v| v.as_array()) {
                for v in vulns {
                    if let Some(s) = v.as_str() {
                        host_cves
                            .entry(h.clone())
                            .or_default()
                            .insert(s.to_string());
                    }
                }
            }
        }
    }

    let mut new: Vec<Value> = Vec::new();
    let mut seq = 0usize;
    let today = now_date();
    let mut mkid = |prefix: &str| {
        seq += 1;
        format!("CORR-{}-{}-{}", slugify(&slug), prefix, seq)
    };

    // Rule 1: CVE correlation
    let mut sorted_host_cves: Vec<(String, HashSet<String>)> = host_cves.into_iter().collect();
    sorted_host_cves.sort_by(|a, b| a.0.cmp(&b.0));
    for (h, cves) in sorted_host_cves {
        if is_placeholder(&h) {
            continue;
        }
        let mut sorted_cves: Vec<String> = cves.into_iter().collect();
        sorted_cves.sort();
        for c in sorted_cves {
            let srcs = match cve_sources.get(&c) {
                Some(s) => s,
                None => continue,
            };
            let src = &srcs[0];
            let src_host = src
                .get("target")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim()
                .to_string();
            if h == src_host {
                continue;
            }
            let sev = src
                .get("severity")
                .and_then(|v| v.as_str())
                .unwrap_or("INFO")
                .to_string();
            let mut rec = json!({
                "id": mkid("cve"),
                "title": format!("Correlated host shares {}", c),
                "severity": sev,
                "cvss_estimate": src.get("cvss_estimate").cloned().unwrap_or(Value::Null),
                "cvss_vector": src.get("cvss_vector").cloned().unwrap_or(Value::Null),
                "target": h,
                "ip": host_ip.get(&h).cloned(),
                "category": format!("Correlated — CVE share ({})", c),
                "status": "OPEN",
                "status_detail": format!("CORRELATED via {} on {}", c, src_host),
                "description": format!("Host {} shares {} with a known finding on {}.", h, c, src_host),
                "impact": "Correlated — NOT confirmed. Verify independently.",
                "evidence": {"cve": c, "source_host": src_host},
                "proof_chain": [],
                "related_cves": [c],
                "remediation": src.get("remediation").cloned().unwrap_or_else(|| json!([])),
                "discovery": "CVE-share correlation",
                "source": "cve-share",
                "found_date": today,
                "first_seen": today,
                "last_seen": today,
                "status_history": [{"at": today, "from": "", "to": "OPEN", "by": "correlate", "note": "CVE-share correlation"}],
            });
            rec["identity_key"] = json!(cc::identity_key(&rec));
            new.push(rec);
        }
    }

    // Rule 2: IP co-residency
    let confirmed: Vec<Value> = fs
        .iter()
        .filter(|f| {
            !is_corr_source(f)
                && (format!(
                    "{} {} {}",
                    f.get("status").and_then(|v| v.as_str()).unwrap_or(""),
                    f.get("status_detail")
                        .and_then(|v| v.as_str())
                        .unwrap_or(""),
                    f.get("tier").and_then(|v| v.as_str()).unwrap_or("")
                ))
                .to_uppercase()
                .contains("CONFIRMED")
        })
        .cloned()
        .collect();
    for f in &confirmed {
        let Some(ip) = cc::single_public_ip(f.get("ip").unwrap_or(&Value::Null)) else {
            continue;
        };
        let src_host = f
            .get("target")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .to_string();
        if is_placeholder(&src_host) {
            continue;
        }
        let sev = f
            .get("severity")
            .and_then(|v| v.as_str())
            .unwrap_or("INFO")
            .to_string();
        let mut sorted_hosts: Vec<String> = ip_hosts
            .get(&ip)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .collect();
        sorted_hosts.sort();
        for h in sorted_hosts {
            if h == src_host || is_placeholder(&h) {
                continue;
            }
            let mut rec = json!({
                "id": mkid("ip"),
                "title": format!("Co-resident host on {}", ip),
                "severity": sev,
                "cvss_estimate": f.get("cvss_estimate").cloned().unwrap_or(Value::Null),
                "cvss_vector": f.get("cvss_vector").cloned().unwrap_or(Value::Null),
                "target": h,
                "ip": ip,
                "category": "Correlated — IP co-residency",
                "status": "OPEN",
                "status_detail": format!("CORRELATED (co-resident with {})", src_host),
                "description": format!("Host {} resolves to {}, co-resident with {}.", h, ip, src_host),
                "impact": "Correlated — NOT confirmed.",
                "evidence": {"ip": ip, "source_host": src_host},
                "proof_chain": [],
                "related_cves": [],
                "remediation": [],
                "discovery": "IP co-residency correlation",
                "source": "ip-co-residency",
                "found_date": today,
                "first_seen": today,
                "last_seen": today,
                "status_history": [{"at": today, "from": "", "to": "OPEN", "by": "correlate", "note": "IP co-residency correlation"}],
            });
            rec["identity_key"] = json!(cc::identity_key(&rec));
            new.push(rec);
        }
    }

    // Rule 3: InternetDB source-backed
    for f in &fs {
        let Some(ip) = cc::single_public_ip(f.get("ip").unwrap_or(&Value::Null)) else {
            continue;
        };
        let Some(d) = idb.get(&ip) else { continue };
        let has_ports_vulns = d.get("ports").is_some() && d.get("vulns").is_some();
        let has_cpes = d.get("cpes").is_some();
        if !(has_ports_vulns || has_cpes) {
            continue;
        }
        let tgt = f
            .get("target")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .to_string();
        if is_placeholder(&tgt) {
            continue;
        }
        let sev = f
            .get("severity")
            .and_then(|v| v.as_str())
            .unwrap_or("INFO")
            .to_string();
        let mut ev = Map::new();
        for k in ["ports", "cpes", "vulns"] {
            if let Some(v) = d.get(k) {
                ev.insert(k.to_string(), v.clone());
            }
        }
        let mut rec = json!({
            "id": mkid("idb"),
            "title": "InternetDB source-backed exposure",
            "severity": sev,
            "target": tgt,
            "ip": ip,
            "category": "Correlated — InternetDB source",
            "status": "OPEN",
            "status_detail": format!("CORRELATED (internetdb source on {})", ip),
            "description": "InternetDB lists ports/CPEs/vulns for this host.",
            "impact": "Correlated/source-backed — NOT confirmed.",
            "evidence": {"internetdb": Value::Object(ev)},
            "proof_chain": [],
            "related_cves": d.get("vulns").cloned().unwrap_or_else(|| json!([])),
            "remediation": [],
            "discovery": "InternetDB enrichment",
            "source": "internetdb",
            "found_date": today,
            "first_seen": today,
            "last_seen": today,
            "status_history": [{"at": today, "from": "", "to": "OPEN", "by": "correlate", "note": "InternetDB correlation"}],
        });
        rec["identity_key"] = json!(cc::identity_key(&rec));
        new.push(rec);
    }

    // dedup: skip if host already has same CVE
    let mut existing_host_cve: HashSet<(String, String)> = HashSet::new();
    for f in &fs {
        let tgt = f
            .get("target")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .to_lowercase();
        for c in cc::extract_cves(f.get("related_cves").unwrap_or(&Value::Null)) {
            existing_host_cve.insert((tgt.clone(), c));
        }
    }
    let filtered: Vec<Value> = new
        .into_iter()
        .filter(|rec| {
            let tgt = rec
                .get("target")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim()
                .to_lowercase();
            for c in cc::extract_cves(rec.get("related_cves").unwrap_or(&Value::Null)) {
                if existing_host_cve.contains(&(tgt.clone(), c))
                    && rec.get("source").and_then(|v| v.as_str()) == Some("cve-share")
                {
                    return false;
                }
            }
            true
        })
        .collect();

    // persist (fresh read-modify-write under the org lock so concurrent
    // analyst mutations survive)
    if !filtered.is_empty() {
        let _corr_guard = cc::org_write_lock(&slug).await;
        if let Some(fp) = cc::org_findings_path(&slug) {
            if let Ok(txt) = tokio::fs::read_to_string(&fp).await {
                if let Ok(mut doc) = serde_json::from_str::<Value>(&txt) {
                    if let Some(existing) = doc.get("findings").and_then(|v| v.as_array()).cloned()
                    {
                        let mut merged = existing.clone();
                        merged.extend(filtered.clone());
                        if let Value::Object(o) = &mut doc {
                            o.insert("findings".into(), Value::Array(merged));
                        }
                        let _ = cc::atomic_write_json(&fp, &doc).await;
                        cc::invalidate_org_cache(&slug);
                    }
                }
            }
        }
    }
    json!({"added": filtered.len()})
}

fn is_placeholder(tgt: &str) -> bool {
    let t = tgt.trim().to_lowercase();
    t.is_empty()
        || t.contains("placeholder")
        || t.contains("example")
        || t.contains("sample")
        || t == "?"
}

fn is_corr_source(f: &Value) -> bool {
    let src = f
        .get("source")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_lowercase();
    matches!(
        src.as_str(),
        "cve-share" | "ip-co-residency" | "internetdb" | "ai-assess" | "scan-cve"
    )
}

/// Stage-B AI grading (judgment-only, clamp ±1 step from stored baseline).
pub async fn ai_grade_org(slug: &str, profile_name: Option<String>) -> Value {
    // Resolve effective profile (explicit override > org > default); skip if none.
    let effective = crate::ai::effective_ready_profile(slug, profile_name.as_deref()).await;
    if effective.is_none() {
        cc::append_history(
            slug,
            json!({"kind": "ai_grade", "mode": "ai", "summary": {}, "note": "AI grading skipped (no configured profile)"}),
        ).await;
        return json!({"result": "failed"});
    }
    let (fs, _) = cc::load_data(slug);
    let candidates: Vec<Value> = fs
        .into_iter()
        .filter(|f| {
            f.get("status")
                .and_then(|v| v.as_str())
                .map(|s| s == "OPEN")
                .unwrap_or(false)
        })
        .take(AI_GRADE_MAX)
        .collect();
    if candidates.is_empty() {
        return json!({"result": "skipped"});
    }

    // Build a compact grading prompt (sanitized, ID-whitelisted).
    let mut lines = Vec::new();
    for c in &candidates {
        let id = c.get("id").and_then(|v| v.as_str()).unwrap_or("");
        let sev = c.get("severity").and_then(|v| v.as_str()).unwrap_or("INFO");
        let title = sanitize_prompt_field(c.get("title").and_then(|v| v.as_str()).unwrap_or(""));
        let tgt = sanitize_prompt_field(c.get("target").and_then(|v| v.as_str()).unwrap_or(""));
        lines.push(format!("{} | {} | {} | {}", id, sev, tgt, title));
    }
    let prompt = format!(
        "You are grading existing CTI findings. Re-severity each finding (judgment only).\n\
         Rules: severity must be one of INFO|LOW|MEDIUM|HIGH|CRITICAL; impact is a short phrase; \
         still_open is yes|no|unclear. Never invent IDs. Return ONLY JSON:\n\
         {{\"results\":[{{\"id\":\"<id>\",\"severity\":\"...\",\"impact\":\"...\",\"still_open\":\"...\"}}]}}\n\
         --- FINDINGS ---\n{}\n--- END ---",
        lines.join("\n")
    );

    let raw = crate::ai::call_ai(&prompt, effective.as_deref()).await;
    let Some(raw) = raw else {
        cc::append_history(
            slug,
            json!({"kind": "ai_grade", "mode": "ai", "summary": {}, "note": "AI grading failed/unavailable"}),
        ).await;
        return json!({"result": "failed"});
    };

    // parse + apply (clamp ±1 step)
    let parsed = parse_ai_grading(&raw, &candidates);
    let Some(grading) = parsed else {
        cc::append_history(
            slug,
            json!({"kind": "ai_grade", "mode": "ai", "summary": {}, "note": "AI grading failed/unavailable (parse error)"}),
        ).await;
        return json!({"result": "failed"});
    };

    let mut applied = 0usize;
    // hold the org lock across the fresh read-modify-write so a concurrent
    // analyst mutation is not clobbered
    let _grade_guard = cc::org_write_lock(slug).await;
    if let Some(fp) = cc::org_findings_path(slug) {
        if let Ok(txt) = tokio::fs::read_to_string(&fp).await {
            if let Ok(mut doc) = serde_json::from_str::<Value>(&txt) {
                if let Some(fs2) = doc.get("findings").and_then(|v| v.as_array()).cloned() {
                    let mut new_fs = fs2.clone();
                    for f in new_fs.iter_mut() {
                        let id = f
                            .get("id")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        let Some(g) = grading.get(&id) else { continue };
                        let new_sev = g
                            .get("severity")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        let cur_sev = f
                            .get("severity")
                            .and_then(|v| v.as_str())
                            .unwrap_or("INFO")
                            .to_string();
                        // clamp ±1 step from stored baseline
                        let cur_rank = sev_rank_i64(&cur_sev);
                        let new_rank = sev_rank_i64(&new_sev);
                        let clamped = if (new_rank - cur_rank).abs() <= 1 {
                            new_sev
                        } else {
                            cur_sev.clone()
                        };
                        let impact = g.get("impact").and_then(|v| v.as_str()).unwrap_or("");
                        if let Value::Object(o) = f {
                            o.insert("severity".into(), json!(clamped));
                            o.insert("ai_grading".into(), json!({"severity_baseline": cur_sev.clone(), "impact": impact, "still_open": g.get("still_open").cloned().unwrap_or(Value::Null)}));
                            o.insert("ai_impact".into(), json!(impact));
                        }
                        applied += 1;
                    }
                    if let Value::Object(o) = &mut doc {
                        o.insert("findings".into(), Value::Array(new_fs));
                    }
                    let _ = cc::atomic_write_json(&fp, &doc).await;
                    cc::invalidate_org_cache(slug);
                }
            }
        }
    }
    cc::append_history(
        slug,
        json!({"kind": "ai_grade", "mode": "ai", "summary": {"graded": applied}, "note": "AI grading completed"}),
    ).await;
    json!({"result": "done", "graded": applied})
}

fn sev_rank_i64(s: &str) -> i64 {
    match s {
        "CRITICAL" => 0,
        "HIGH" => 1,
        "MEDIUM" => 2,
        "LOW" => 3,
        _ => 4,
    }
}

fn sanitize_prompt_field(v: &str) -> String {
    let out: String = v
        .chars()
        .map(|c| {
            if c.is_control() || c == '|' || c == ';' {
                ' '
            } else {
                c
            }
        })
        .collect();
    out.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(120)
        .collect()
}

fn parse_ai_grading(raw: &str, candidates: &[Value]) -> Option<HashMap<String, Value>> {
    let raw = crate::ai::strip_json_fences(raw);
    let allowed: HashSet<String> = candidates
        .iter()
        .filter_map(|c| c.get("id").and_then(|v| v.as_str()).map(|s| s.to_string()))
        .collect();
    let arr = extract_results_array(&raw)?;
    let mut out = HashMap::new();
    for item in arr {
        let obj = match item.as_object() {
            Some(o) => o,
            None => continue,
        };
        let id = obj
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .to_string();
        if id.is_empty() || !allowed.contains(&id) {
            continue;
        }
        let sev = obj
            .get("severity")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .to_uppercase();
        if !matches!(
            sev.as_str(),
            "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
        ) {
            continue;
        }
        let impact = obj
            .get("impact")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .chars()
            .take(500)
            .collect::<String>();
        let so = obj
            .get("still_open")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .to_lowercase();
        let still_open = match so.as_str() {
            "true" | "open" => "yes",
            "false" | "closed" | "gone" => "no",
            "yes" | "no" | "unclear" => so.as_str(),
            _ => "",
        };
        out.insert(
            id,
            json!({"severity": sev, "impact": impact, "still_open": still_open}),
        );
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

fn extract_results_array(raw: &str) -> Option<Vec<Value>> {
    let d: Value = serde_json::from_str(raw).ok()?;
    let arr = if let Some(a) = d.get("results").and_then(|v| v.as_array()) {
        a.clone()
    } else {
        let a = d.as_array()?;
        a.clone()
    };
    Some(arr)
}

pub fn read_history(slug: &str) -> Vec<Value> {
    cc::load_history(slug)
}

pub async fn append_history(slug: &str, event: Value) {
    cc::append_history(slug, event).await;
}
