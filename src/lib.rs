//! Kepos-published Tact remote memory over local SQLite.
//!
//! The library exposes the Kepos identity authentication, the namespaced SQLite store, and
//! the axum router for the Tact remote-memory protocol. The binary wires them together.

pub mod auth;
pub mod config;
pub mod router;
pub mod store;
