//! Config error types.

use thiserror::Error;

/// Errors returned by configuration loading and validation.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// File could not be read.
    #[error("config file I/O error: {0}")]
    Io(String),

    /// TOML parse error.
    #[error("config parse error: {0}")]
    Parse(String),

    /// Config value is logically invalid.
    #[error("invalid configuration: {0}")]
    Invalid(String),
}
