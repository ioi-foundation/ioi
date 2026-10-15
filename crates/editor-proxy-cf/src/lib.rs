//! The compile-fail battery's build anchor (BUILD-DELTA #85 U1, DESIGN v2 (4)).
//!
//! This crate has no API. Its normal dependency graph (`ioi-proxy-digest`, `ioi-editor-proxy-ipc`,
//! `serde`) is exactly what the fixtures in `fixtures/` link; `tests/battery.rs` builds it and
//! compiles each fixture against the production rlibs, and `tests/api.rs` pins the trusted crates'
//! reviewed interfaces.
#![no_std]
#![forbid(unsafe_code)]

/// The production crates the fixtures link (named so the dependency edges are explicit).
pub use ioi_editor_proxy_ipc as codec;
pub use ioi_proxy_digest as digest;
