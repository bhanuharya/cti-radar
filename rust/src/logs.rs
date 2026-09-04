//! Runtime log ring — in-memory (cap 500) + persisted JSONL.
//! Port of `main.py` `_JOB_LOGS` / `_log_event` / `_load_recent_logs` /
//! `api_admin_logs`: recent scan/recheck/correlate/AI attempts and failures.

use chrono::Utc;
use once_cell::sync::OnceCell;
use parking_lot::Mutex;
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::path::{Path, PathBuf};

const MAX_JOB_LOGS: usize = 500;
const SEED_LINES: usize = 300;

static LOGS: OnceCell<Mutex<VecDeque<Value>>> = OnceCell::new();
static LOG_FILE: OnceCell<PathBuf> = OnceCell::new();

fn logs() -> &'static Mutex<VecDeque<Value>> {
    LOGS.get_or_init(|| Mutex::new(VecDeque::new()))
}

/// Initialize the ring from the persisted JSONL log (survives restarts).
/// Mirrors Python `_JOB_LOGS.extend(_load_recent_logs())`.
pub fn init(data_dir: &Path) {
    let path = data_dir.join("logs").join("cti-runtime.log");
    let _ = LOG_FILE.set(path.clone());
    let mut seed = Vec::new();
    if let Ok(txt) = std::fs::read_to_string(&path) {
        let lines: Vec<&str> = txt.lines().collect();
        let start = lines.len().saturating_sub(SEED_LINES);
        for line in &lines[start..] {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if let Ok(v) = serde_json::from_str::<Value>(line) {
                seed.push(v);
            }
        }
    }
    let mut ring = logs().lock();
    for v in seed {
        if ring.len() >= MAX_JOB_LOGS {
            ring.pop_front();
        }
        ring.push_back(v);
    }
}

fn now_iso() -> String {
    Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

/// Append an event to the in-memory ring and the persisted JSONL log.
/// Failures are swallowed (logging must never break a request).
pub fn log_event(level: &str, kind: &str, slug: &str, message: &str, job_id: Option<&str>) {
    let ev = json!({
        "ts": now_iso(),
        "level": level,
        "kind": kind,
        "org": slug,
        "job_id": job_id.unwrap_or(""),
        "message": message,
    });
    {
        let mut ring = logs().lock();
        ring.push_back(ev.clone());
        while ring.len() > MAX_JOB_LOGS {
            ring.pop_front();
        }
    }
    if let Some(path) = LOG_FILE.get() {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
        {
            let _ = writeln!(f, "{}", serde_json::to_string(&ev).unwrap_or_default());
        }
    }
}

/// Read the ring: last `limit` entries, optional org filter, newest-first.
/// Returns (events_newest_first, total_in_window). Mirrors Python
/// `api_admin_logs`: `{"logs": logs[::-1], "total": len(logs)}`.
pub fn read_logs(org: Option<&str>, limit: usize) -> (Vec<Value>, usize) {
    let lim = limit.clamp(1, 1000);
    let ring = logs().lock();
    let len = ring.len();
    let start = len.saturating_sub(lim);
    let mut window: Vec<Value> = ring.iter().skip(start).cloned().collect();
    if let Some(o) = org {
        if !o.is_empty() {
            window = window
                .into_iter()
                .filter(|e| e.get("org").and_then(|v| v.as_str()) == Some(o))
                .collect();
            if window.len() > lim {
                window = window[window.len() - lim..].to_vec();
            }
        }
    }
    let total = window.len();
    window.reverse();
    (window, total)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_ring_newest_first_and_filter() {
        let logs = logs();
        logs.lock().clear();
        log_event("info", "scan", "a", "one", None);
        log_event("info", "scan", "b", "two", None);
        log_event("info", "scan", "a", "three", None);
        let (all, total) = read_logs(None, 200);
        assert_eq!(total, 3);
        assert_eq!(all[0].get("message").and_then(|v| v.as_str()), Some("three"));
        let (fa, ta) = read_logs(Some("a"), 200);
        assert_eq!(ta, 2);
        assert_eq!(fa[0].get("message").and_then(|v| v.as_str()), Some("three"));
        let (lim, _) = read_logs(None, 2);
        assert_eq!(lim.len(), 2);
        logs.lock().clear();
    }
}
