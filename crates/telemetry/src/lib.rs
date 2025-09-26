// Path: crates/telemetry/src/lib.rs
pub mod http;
pub mod init; // New module for initialization
pub mod prometheus;
pub mod sinks;
pub mod time; // New module for the RAII timer