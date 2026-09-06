//! Per-org job serialization + bounded background executor.
//! Mirrors `main.py` `_try_acquire_job` / `_release_job` / `_job_status` /
//! `_prune_jobs` semantics: running jobs block new mutations for the same org,
//! a global cap bounds total active jobs, and completed jobs are retained (1h)
//! so status polling works.

use crate::config::Config;
use crate::error::{AppError, AppResult};
use once_cell::sync::OnceCell;
use parking_lot::Mutex;
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

static CFG: OnceCell<Config> = OnceCell::new();

pub fn init(cfg: Config) {
    let _ = CFG.set(cfg);
}

fn cfg() -> &'static Config {
    CFG.get().expect("jobs::init must be called first")
}

/// Global cap on concurrent active jobs (mirrors Python `_MAX_ACTIVE_JOBS`).
pub fn max_active_jobs() -> usize {
    cfg().max_active_jobs
}

#[derive(Clone, Debug)]
pub struct Job {
    pub id: String,
    pub started: f64,
    pub finished: Option<f64>,
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
    prune_jobs();
    let key = job_key(slug, kind);
    let prefix = format!("{}:", slug);
    let mut table = jobs().lock();

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
        finished: None,
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

/// Keep only scalar result fields (str/int/float/bool/null), mirroring
/// Python `_release_job` result filtering.
fn scalar_result(result: Value) -> Value {
    match result {
        Value::Object(map) => Value::Object(
            map.into_iter()
                .filter(|(_, v)| {
                    matches!(
                        v,
                        Value::String(_) | Value::Number(_) | Value::Bool(_) | Value::Null
                    )
                })
                .collect(),
        ),
        other => other,
    }
}

pub fn release_job(
    slug: &str,
    kind: &str,
    jid: &str,
    error: Option<String>,
    result: Option<Value>,
) {
    let key = job_key(slug, kind);
    let mut table = jobs().lock();
    if let Some(j) = table.entries.get_mut(&key) {
        if j.id == jid {
            j.status = if error.is_some() {
                "failed".to_string()
            } else {
                "done".to_string()
            };
            j.error = error;
            j.result = result.map(scalar_result);
            j.finished = Some(now_f64());
        }
    }
    drop(table);
    prune_jobs();
}

pub fn job_update(slug: &str, kind: &str, jid: &str, fields: Map<String, Value>) {
    let key = job_key(slug, kind);
    let mut table = jobs().lock();
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
    let table = jobs().lock();
    table
        .entries
        .get(&key)
        .map(|j| j.status == "running")
        .unwrap_or(false)
}

pub fn get_job(slug: &str, kind: &str, job_id: &str) -> Option<Job> {
    let key = job_key(slug, kind);
    let table = jobs().lock();
    table.entries.get(&key).filter(|j| j.id == job_id).cloned()
}

/// Prune completed jobs older than the TTL.
pub fn prune_jobs() {
    let now = now_f64();
    let mut table = jobs().lock();
    table.entries.retain(|_, j| {
        if j.status == "running" {
            return true;
        }
        // age from completion (mirrors Python `_prune_jobs` on `finished`)
        let end = j.finished.unwrap_or(j.started);
        now - end < (JOB_TTL_SECS as f64)
    });
}

/// Serialize a job into the API status payload shape.
/// Unknown job ids -> 404 (mirrors Python `_job_status`).
pub fn job_status(slug: &str, kind: &str, job_id: &str) -> AppResult<Value> {
    match get_job(slug, kind, job_id) {
        Some(j) => {
            // only non-None keys are emitted (mirrors Python `_job_status`)
            let end = if j.status == "running" {
                now_f64()
            } else {
                j.finished.unwrap_or_else(now_f64)
            };
            let mut m = Map::new();
            m.insert("status".into(), json!(j.status));
            m.insert("job_id".into(), json!(j.id));
            m.insert("stage".into(), json!(j.stage));
            m.insert("progress".into(), json!(j.progress));
            if let Some(e) = j.error {
                m.insert("error".into(), json!(e));
            }
            m.insert("started".into(), json!(j.started));
            if let Some(f) = j.finished {
                m.insert("finished".into(), json!(f));
            }
            if let Some(r) = j.result {
                m.insert("result".into(), r);
            }
            let elapsed = ((end - j.started).max(0.0) * 10.0).round() / 10.0;
            m.insert("elapsed".into(), json!(elapsed));
            Ok(Value::Object(m))
        }
        None => Err(AppError::UnknownJob {
            slug: slug.to_string(),
            kind: kind.to_string(),
            job_id: job_id.to_string(),
        }),
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
        *jobs().lock() = JobTable::default();
    }

    #[test]
    fn test_acquire_and_serialize() {
        let _guard = TEST_LOCK.lock();
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
        let _guard = TEST_LOCK.lock();
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
