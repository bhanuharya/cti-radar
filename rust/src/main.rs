//! CTI Radar — binary entrypoint.

use cti_radar::config::Config;
use cti_radar::AppState;
use std::net::SocketAddr;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cfg = Config::load();
    if let Err(e) = cfg.validate_bind() {
        eprintln!("{}", e);
        std::process::exit(1);
    }

    cti_radar::correlation::init(cfg.clone());
    cti_radar::auth::init(cfg.clone());
    cti_radar::jobs::init(cfg.clone());
    cti_radar::logs::init(&cfg.data_dir);

    let state = AppState::new(cfg.clone());
    let app = cti_radar::build_router(state);

    let addr = format!("{}:{}", cfg.host, cfg.port);
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .unwrap_or_else(|e| {
            eprintln!("bind failed on {}: {}", addr, e);
            std::process::exit(1);
        });
    tracing::info!("cti-radar listening on {}", addr);
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .unwrap();
}
