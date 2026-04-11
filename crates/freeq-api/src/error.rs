//! API error types.

use thiserror::Error;

/// Errors returned by the REST API layer.
#[derive(Debug, Error)]
pub enum ApiError {
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
            ApiError::NotFound(m)    => (StatusCode::NOT_FOUND, m.clone()),
            ApiError::BadRequest(m)  => (StatusCode::BAD_REQUEST, m.clone()),
            ApiError::Internal(m)    => (StatusCode::INTERNAL_SERVER_ERROR, m.clone()),
        };
        (status, message).into_response()
    }
}
