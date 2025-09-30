// Path: crates/telemetry/src/lib.rs
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unimplemented,
        clippy::todo,
        clippy::indexing_slicing
    )
)]

pub mod http;
pub mod init; // New module for initialization
pub mod prometheus;
pub mod sinks;
pub mod time; // New module for the RAII timer
