//! API error types.

use thiserror::Error;

/// Errors returned by the REST API layer.
#[derive(Debug, Error)]
pub enum ApiError {
    /// The endpoint exists, but the implementation is not ready yet.
    #[error("not implemented: {0}")]
    NotImplemented(String),

    /// A requested resource was not found.
    #[error("not found: {0}")]
    NotFound(String),

    /// The request was malformed.
    #[error("bad request: {0}")]
    BadRequest(String),

    /// An internal error occurred.
    #[error("internal error: {0}")]
    Internal(String),
}

impl axum::response::IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        use axum::http::StatusCode;
        let (status, message) = match &self {
            ApiError::NotImplemented(m) => (StatusCode::NOT_IMPLEMENTED, m.clone()),
            ApiError::NotFound(m) => (StatusCode::NOT_FOUND, m.clone()),
            ApiError::BadRequest(m) => (StatusCode::BAD_REQUEST, m.clone()),
            ApiError::Internal(m) => (StatusCode::INTERNAL_SERVER_ERROR, m.clone()),
        };
        (status, message).into_response()
    }
}
