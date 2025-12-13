// Path: crates/services/src/ibc/mod.rs
#![allow(clippy::module_inception)] // Allow the module name to match its parent directory

//! Implements the core IBC services, restructured to align with ICS standards.

/// Core host machinery (ICS-24, ICS-26 dispatch).
pub mod core;

/// Light client implementations (ICS-02, ICS-07, etc.).
pub mod light_clients;

/// IBC application modules (e.g., ICS-20 token transfer).
pub mod apps;
