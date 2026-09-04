//! Runtime configuration, read once from the environment (env vars identical to
//! the Python implementation). Secrets are read from the environment only —
//! never stored in code or files.

use std::env;
use std::path::PathBuf;

/// Central config. All values mirror the Python env-var surface exactly.
#[derive(Debug, Clone)]
pub struct Config {
    pub user: String,
    pub password: String,
    pub scan_token: String,

    pub data_dir: PathBuf,
    pub state_dir: PathBuf,

    pub host: String,
    pub port: u16,

    pub wildcard_filter: bool,
    pub nvd_enrich: bool,
    pub nvd_api_key: String,
    pub nvd_max_lookups: usize,

    pub job_stale_secs: u64,
    pub max_active_jobs: usize,
    pub resolve_after: i64,

    pub chromium_path: Option<String>,

    pub ai_config_file: Option<String>,
    pub opencode_go_b_api_key: String,

    // OpenHack active-assessment gate (all must be set to be active)
    pub openhack_bin: Option<String>,
    pub openhack_active: bool,
    pub openhack_isolated: bool,
    pub openhack_allowed_domains: String,
    pub openhack_roe_expires: String,
    // OpenHack runner tunables (wired into openhack.rs helpers)
    pub openhack_model: String,
    pub openhack_scans_dir: Option<String>,
    pub openhack_quick_budget: u64,
}

fn env_str(name: &str) -> String {
    env::var(name).unwrap_or_default()
}

fn env_bool(name: &str, default: bool) -> bool {
    match env::var(name).unwrap_or_default().trim() {
        "1" | "true" | "yes" | "on" => true,
        "0" | "false" | "no" | "off" => false,
        "" => default,
        _ => default,
    }
}

fn env_usize(name: &str, default: usize) -> usize {
    env::var(name)
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(default)
}

fn env_u64(name: &str, default: u64) -> u64 {
    env::var(name)
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(default)
}

fn env_i64(name: &str, default: i64) -> i64 {
    env::var(name)
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(default)
}

impl Config {
    pub fn load() -> Self {
        let data_dir = env::var("CTI_DATA_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("data"));

        let state_dir = env::var("CTI_STATE_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                env::var("HOME")
                    .map(|h| PathBuf::from(h).join(".local/state/cti-radar"))
                    .unwrap_or_else(|_| data_dir.clone())
            });

        let chromium_path = env::var("CTI_CHROMIUM_PATH").ok().or_else(|| {
            ["chromium", "chromium-browser", "google-chrome"]
                .iter()
                .find_map(|c| {
                    let out = std::process::Command::new("sh")
                        .arg("-c")
                        .arg(format!("command -v {}", c))
                        .output()
                        .ok()?;
                    if out.status.success() {
                        Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
                    } else {
                        None
                    }
                })
        });

        Self {
            user: env_str("CTI_USER"),
            password: env_str("CTI_PASSWORD"),
            scan_token: env_str("CTI_SCAN_TOKEN"),

            data_dir,
            state_dir,

            host: env::var("CTI_HOST").unwrap_or_else(|_| "127.0.0.1".into()),
            port: env::var("CTI_PORT")
                .ok()
                .and_then(|v| v.trim().parse().ok())
                .unwrap_or(8084),

            wildcard_filter: env_bool("CTI_WILDCARD_FILTER", true),
            nvd_enrich: env_bool("CTI_NVD_ENRICH", false),
            nvd_api_key: env_str("CTI_NVD_API_KEY"),
            nvd_max_lookups: env_usize("CTI_NVD_MAX_LOOKUPS", 20),

            job_stale_secs: env_u64("CTI_JOB_STALE_SECS", 1800).max(60),
            max_active_jobs: env_usize("CTI_MAX_ACTIVE_JOBS", 8).max(1),
            resolve_after: env_i64("CTI_RESOLVE_AFTER", 3),

            chromium_path,

            ai_config_file: env::var("CTI_AI_CONFIG_FILE").ok(),
            opencode_go_b_api_key: env_str("OPENCODE_GO_B_API_KEY"),

            openhack_bin: env::var("CTI_OPENHACK_BIN")
                .ok()
                .filter(|s| !s.trim().is_empty()),
            openhack_active: env_bool("CTI_OPENHACK_ACTIVE", false),
            openhack_isolated: env_bool("CTI_OPENHACK_ISOLATED", false),
            openhack_allowed_domains: env_str("CTI_OPENHACK_ALLOWED_DOMAINS"),
            openhack_roe_expires: env_str("CTI_OPENHACK_ROE_EXPIRES"),

            openhack_model: {
                let m = env_str("CTI_OHACK_MODEL");
                if m.trim().is_empty() {
                    "ox-alpha".to_string()
                } else {
                    m.trim().to_string()
                }
            },
            openhack_scans_dir: env::var("CTI_OPENHACK_SCANS_DIR")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty()),
            openhack_quick_budget: env::var("CTI_OHACK_QUICK_BUDGET")
                .ok()
                .and_then(|v| v.trim().parse::<f64>().ok())
                .map(|f| f as u64)
                .unwrap_or(480)
                .clamp(300, 1200),
        }
    }

    pub fn orgs_json(&self) -> PathBuf {
        self.data_dir.join("orgs.json")
    }

    pub fn orgs_dir(&self) -> PathBuf {
        self.data_dir.join("orgs")
    }

    pub fn org_dir(&self, slug: &str) -> PathBuf {
        self.orgs_dir().join(slug)
    }

    pub fn logs_dir(&self) -> PathBuf {
        self.data_dir.join("logs")
    }

    /// Refuse to bind any wildcard address (mirrors Python).
    pub fn validate_bind(&self) -> Result<(), String> {
        if self.host == "0.0.0.0" || self.host == "::" {
            return Err(
                "Refusing to bind 0.0.0.0/:: — set CTI_HOST to a specific tailnet/LAN IP"
                    .to_string(),
            );
        }
        Ok(())
    }
}
