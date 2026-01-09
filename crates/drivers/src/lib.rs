// Path: crates/drivers/src/lib.rs
//! # IOI Hardware Drivers
//! 
//! This crate provides the "Body" for the IOI Kernel. It implements the
//! `ioi_api::vm::drivers` traits using native OS calls, replacing external
//! scripts like UI-TARS with secure, deterministic Rust code.

pub mod gui;
pub mod browser;