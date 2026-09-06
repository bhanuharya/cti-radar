//! CTI Radar — Rust backend (axum + tokio). Port of the FastAPI implementation
//! with Rust-native concurrency (async I/O + rayon data-parallelism).

pub mod ai;
pub mod auth;
pub mod config;
pub mod correlation;
pub mod cve_match;
pub mod error;
pub mod handlers;
pub mod handlers_mut;
pub mod jobs;
pub mod nuclei;
pub mod openhack;
pub mod openhack_handlers;
pub mod report;
pub mod scanner;
pub mod vuln_handlers;
pub mod vuln_scan;

use std::sync::Arc;

/// Application state shared across handlers.
#[derive(Clone)]
pub struct AppState {
    pub cfg: Arc<config::Config>,
}

impl AppState {
    pub fn new(cfg: config::Config) -> Self {
        Self { cfg: Arc::new(cfg) }
    }
}
