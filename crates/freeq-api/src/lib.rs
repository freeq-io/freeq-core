//! # freeq-api
//!
//! Local REST API served by each FreeQ Core node at `127.0.0.1:6789`.
//!
//! **License**: Apache 2.0 (not AGPL). This crate is the integration boundary
//! between the AGPL core and the proprietary FreeQ Cloud agent. Keeping it
//! Apache 2.0 prevents AGPL copyleft from propagating into the Cloud backend.
//!
//! ## Endpoints
//!
//! | Method | Path                  | Description                          |
//! |--------|-----------------------|--------------------------------------|
//! | GET    | /v1/status            | Node health, uptime, algorithm info  |
//! | GET    | /v1/peers             | List all configured peers            |
//! | POST   | /v1/peers             | Add a peer                           |
//! | DELETE | /v1/peers/{name}      | Remove a peer                        |
//! | POST   | /v1/peers/{name}/rotate | Rotate keys for a peer             |
//! | GET    | /v1/tunnels           | List active tunnels + stats          |
//! | GET    | /v1/metrics           | Prometheus-compatible metrics        |
//! | POST   | /v1/algorithm         | Hot-swap the KEM/sign algorithm      |

#![forbid(unsafe_code)]
#![deny(missing_docs, clippy::unwrap_used)]

pub mod error;
pub mod handlers;
pub mod models;
pub mod router;
pub mod server;
pub mod state;

pub use error::ApiError;
pub use server::ApiServer;

/// Library-wide result type.
pub type Result<T> = std::result::Result<T, ApiError>;
