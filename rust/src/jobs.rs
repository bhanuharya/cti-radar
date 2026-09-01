//! Per-org job serialization + bounded background executor.
//! Mirrors `main.py` `_try_acquire_job` / `_release_job` / `_job_status` /
//! `_prune_jobs` semantics: running jobs block new mutations for the same org,
//! a global cap bounds total active jobs, and completed jobs are retained (1h)
//! so status polling works.

use crate::config::Config;
use once_cell::sync::OnceCell;
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

static CFG: OnceCell<Config> = OnceCell::new();

pub fn init(cfg: Config) {
    let _ = CFG.set(cfg);
}

fn cfg() -> &'static Config {
    CFG.get().expect("jobs::init must be called first")
}

#[derive(Clone, Debug)]
pub struct Job {
    pub id: String,
    pub started: f64,
    pub kind: String,
    pub status: String,
    pub stage: String,
    pub progress: String,
    pub error: Option<String>,
    pub result: Option<Value>,
}

#[derive(Clone, Default)]
struct JobTable {
    // key = "<slug>:<kind>"
    entries: HashMap<String, Job>,
}

static JOBS: OnceCell<Mutex<JobTable>> = OnceCell::new();

fn jobs() -> &'static Mutex<JobTable> {
    JOBS.get_or_init(|| Mutex::new(JobTable::default()))
}

const JOB_TTL_SECS: u64 = 3600;

fn now_f64() -> f64 {
    let d = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    d.as_secs_f64()
}

fn job_key(slug: &str, kind: &str) -> String {
    format!("{}:{}", slug, kind)
}

/// Try to acquire a job slot. Returns (ok, job_id).
/// - any *running* job for this org blocks new mutations (per-org serialization)
/// - global active-job cap bounds total concurrency
pub fn try_acquire_job(slug: &str, kind: &str) -> (bool, Option<String>) {
    let key = job_key(slug, kind);
    let prefix = format!("{}:", slug);
    let mut table = jobs().lock().unwrap();

    for (k, v) in table.entries.iter() {
        if k.starts_with(&prefix) && v.status == "running" {
            return (false, Some(v.id.clone()));
        }
    }
    let active = table
        .entries
        .values()
        .filter(|v| v.status == "running")
        .count();
    if active >= cfg().max_active_jobs {
        return (false, None);
    }
    let jid = format!(
        "{}-{}-{}",
        slug,
        kind,
        &Uuid::new_v4().simple().to_string()[..8]
    );
    let entry = Job {
        id: jid.clone(),
        started: now_f64(),
        kind: kind.to_string(),
        status: "running".to_string(),
        stage: "queued".to_string(),
        progress: String::new(),
        error: None,
        result: None,
    };
    table.entries.insert(key, entry);
    (true, Some(jid))
}

pub fn release_job(
    slug: &str,
    kind: &str,
    jid: &str,
    error: Option<String>,
    result: Option<Value>,
) {
    let key = job_key(slug, kind);
    let mut table = jobs().lock().unwrap();
    if let Some(j) = table.entries.get_mut(&key) {
        if j.id == jid {
            j.status = if error.is_some() {
                "failed".to_string()
            } else {
                "done".to_string()
            };
            j.error = error;
            j.result = result;
        }
    }
}

pub fn job_update(slug: &str, kind: &str, jid: &str, fields: Map<String, Value>) {
    let key = job_key(slug, kind);
    let mut table = jobs().lock().unwrap();
    if let Some(j) = table.entries.get_mut(&key) {
        if j.id != jid {
            return;
        }
        for (k, v) in fields {
            match k.as_str() {
                "stage" => j.stage = v.as_str().unwrap_or("").to_string(),
                "progress" => j.progress = v.as_str().unwrap_or("").to_string(),
                "status" => j.status = v.as_str().unwrap_or("").to_string(),
                _ => {}
            }
        }
    }
}

pub fn job_progress(slug: &str, kind: &str, jid: &str, stage: &str, message: &str) {
    let mut m = Map::new();
    m.insert("stage".into(), Value::String(stage.to_string()));
    m.insert("progress".into(), Value::String(message.to_string()));
    job_update(slug, kind, jid, m);
}

pub fn is_job_running(slug: &str, kind: &str) -> bool {
    let key = job_key(slug, kind);
    let table = jobs().lock().unwrap();
    table
        .entries
        .get(&key)
        .map(|j| j.status == "running")
        .unwrap_or(false)
}

pub fn get_job(slug: &str, kind: &str, job_id: &str) -> Option<Job> {
    let key = job_key(slug, kind);
    let table = jobs().lock().unwrap();
    table.entries.get(&key).filter(|j| j.id == job_id).cloned()
}

/// Prune completed jobs older than the TTL.
pub fn prune_jobs() {
    let now = now_f64();
    let mut table = jobs().lock().unwrap();
    table
        .entries
        .retain(|_, j| j.status == "running" || (now - j.started) < (JOB_TTL_SECS as f64));
}

/// Serialize a job into the API status payload shape.
pub fn job_status(slug: &str, kind: &str, job_id: &str, running: bool) -> Value {
    match get_job(slug, kind, job_id) {
        Some(j) => {
            let status = if j.status == "running" {
                "running"
            } else {
                j.status.as_str()
            };
            json!({
                "slug": slug,
                "kind": kind,
                "job_id": j.id,
                "status": status,
                "stage": j.stage,
                "progress": j.progress,
                "error": j.error,
                "result": j.result,
            })
        }
        None => {
            // unknown job id -> report running state so polling stays stable
            json!({
                "slug": slug,
                "kind": kind,
                "job_id": job_id,
                "status": if running { "running" } else { "unknown" },
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn test_cfg() -> Config {
        Config {
            max_active_jobs: 2,
            ..Config::load()
        }
    }

    fn reset() {
        *jobs().lock().unwrap() = JobTable::default();
    }

    #[test]
    fn test_acquire_and_serialize() {
        let _guard = TEST_LOCK.lock().unwrap();
        init(test_cfg());
        reset();
        let (ok1, id1) = try_acquire_job("orgA", "scan");
        assert!(ok1);
        let id1 = id1.unwrap();
        // same org, different kind -> still blocked (per-org serialization)
        let (ok2, _) = try_acquire_job("orgA", "recheck");
        assert!(!ok2);
        // release, then re-acquire works
        release_job("orgA", "scan", &id1, None, None);
        let (ok3, _) = try_acquire_job("orgA", "recheck");
        assert!(ok3);
    }

    #[test]
    fn test_global_cap() {
        let _guard = TEST_LOCK.lock().unwrap();
        init(test_cfg());
        reset();
        let (ok1, id1) = try_acquire_job("a", "scan");
        let (ok2, id2) = try_acquire_job("b", "scan");
        let (ok3, _) = try_acquire_job("c", "scan");
        assert!(ok1 && ok2);
        assert!(!ok3);
        release_job("a", "scan", &id1.unwrap(), None, None);
        release_job("b", "scan", &id2.unwrap(), None, None);
    }
}
