//! Error types for the CTI Radar server.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{Map, Value};

/// Application error that maps to an HTTP response with a JSON error body.
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("unauthorized")]
    Unauthorized,
    #[error("invalid slug")]
    InvalidSlug,
    #[error("org not found")]
    OrgNotFound(String),
    #[error("bad request: {0}")]
    BadRequest(String),
    /// 400 with extra machine-readable fields merged into the body
    /// (e.g. `{"error": ..., "allowed": [...]}` for invalid ai_profile).
    #[error("bad request: {error}")]
    BadRequestExtra {
        error: String,
        extra: Map<String, Value>,
    },
    #[error("not found: {0}")]
    NotFound(String),
    #[error("conflict: {error}")]
    Conflict { error: String, slug: Option<String> },
    #[error("forbidden: {0}")]
    Forbidden(String),
    #[error("service unavailable: {0}")]
    ServiceUnavailable(String),
    #[error("too many requests: {0}")]
    TooManyRequests(String),
    #[error("unknown job")]
    UnknownJob {
        slug: String,
        kind: String,
        job_id: String,
    },
    /// Per-org job busy: 409 when the org owns the running job, 429 for the global cap.
    #[error("busy: {error}")]
    Busy {
        error: String,
        slug: String,
        job_id: Option<String>,
    },
    #[error("internal error: {0}")]
    Internal(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

fn err_map(msg: &str) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("error".to_string(), Value::String(msg.to_string()));
    m
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, body) = match &self {
            AppError::Unauthorized => (StatusCode::UNAUTHORIZED, err_map("unauthorized")),
            AppError::InvalidSlug => (StatusCode::BAD_REQUEST, err_map("invalid slug")),
            AppError::OrgNotFound(slug) => {
                let mut m = err_map(&format!("org not found: {}", slug));
                m.insert("slug".to_string(), Value::String(slug.clone()));
                (StatusCode::NOT_FOUND, m)
            }
            AppError::BadRequest(m) => (StatusCode::BAD_REQUEST, err_map(m)),
            AppError::BadRequestExtra { error, extra } => {
                let mut m = err_map(error);
                for (k, v) in extra {
                    m.insert(k.clone(), v.clone());
                }
                (StatusCode::BAD_REQUEST, m)
            }
            AppError::NotFound(m) => (StatusCode::NOT_FOUND, err_map(m)),
            AppError::Conflict { error, slug } => {
                let mut m = err_map(error);
                if let Some(s) = slug {
                    m.insert("slug".to_string(), Value::String(s.clone()));
                }
                (StatusCode::CONFLICT, m)
            }
            AppError::Forbidden(m) => (StatusCode::FORBIDDEN, err_map(m)),
            AppError::ServiceUnavailable(m) => (StatusCode::SERVICE_UNAVAILABLE, err_map(m)),
            AppError::TooManyRequests(m) => (StatusCode::TOO_MANY_REQUESTS, err_map(m)),
            AppError::UnknownJob { slug, kind, job_id } => {
                let mut m = err_map("unknown job");
                m.insert("job_id".to_string(), Value::String(job_id.clone()));
                m.insert("slug".to_string(), Value::String(slug.clone()));
                m.insert("kind".to_string(), Value::String(kind.clone()));
                (StatusCode::NOT_FOUND, m)
            }
            AppError::Busy {
                error,
                slug,
                job_id,
            } => {
                let mut m = err_map(error);
                m.insert("slug".to_string(), Value::String(slug.clone()));
                m.insert(
                    "job_id".to_string(),
                    job_id.clone().map(Value::String).unwrap_or(Value::Null),
                );
                let status = if job_id.is_some() {
                    StatusCode::CONFLICT
                } else {
                    StatusCode::TOO_MANY_REQUESTS
                };
                (status, m)
            }
            AppError::Internal(m) => (StatusCode::INTERNAL_SERVER_ERROR, err_map(m)),
            // Never echo filesystem paths or serde internals to clients;
            // the full error is logged by the caller via tracing.
            AppError::Io(e) => {
                tracing::warn!("io error: {}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, err_map("internal error"))
            }
            AppError::Json(e) => {
                tracing::warn!("json error: {}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, err_map("internal error"))
            }
        };
        (status, Json(Value::Object(body))).into_response()
    }
}

pub type AppResult<T> = Result<T, AppError>;
