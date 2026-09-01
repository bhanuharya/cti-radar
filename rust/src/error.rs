//! Error types for the CTI Radar server.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;

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
    #[error("not found: {0}")]
    NotFound(String),
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("too many requests")]
    TooManyRequests(u64),
    #[error("internal error: {0}")]
    Internal(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            AppError::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized".to_string()),
            AppError::InvalidSlug => (StatusCode::BAD_REQUEST, "invalid slug".to_string()),
            AppError::OrgNotFound(slug) => {
                (StatusCode::NOT_FOUND, format!("org not found: {}", slug))
            }
            AppError::BadRequest(m) => (StatusCode::BAD_REQUEST, m.clone()),
            AppError::NotFound(m) => (StatusCode::NOT_FOUND, m.clone()),
            AppError::Conflict(m) => (StatusCode::CONFLICT, m.clone()),
            AppError::TooManyRequests(_) => (
                StatusCode::TOO_MANY_REQUESTS,
                "too many requests".to_string(),
            ),
            AppError::Internal(m) => (StatusCode::INTERNAL_SERVER_ERROR, m.clone()),
            AppError::Io(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("io error: {}", e),
            ),
            AppError::Json(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("json error: {}", e),
            ),
        };

        let mut body = serde_json::Map::new();
        body.insert("error".to_string(), serde_json::Value::String(message));
        if let AppError::OrgNotFound(slug) = self {
            body.insert("slug".to_string(), serde_json::Value::String(slug));
        }

        (status, Json(serde_json::Value::Object(body))).into_response()
    }
}

pub type AppResult<T> = Result<T, AppError>;
