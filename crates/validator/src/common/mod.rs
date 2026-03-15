// Path: crates/validator/src/common/mod.rs

//! Common validator components shared by all types

pub mod guardian;
/// Guardianized key-authority backends and selection logic.
pub mod key_authority;
/// Guardian witness-log abstractions and in-memory compatibility implementation.
pub mod transparency_log;
pub use guardian::*;
pub use key_authority::*;
pub use transparency_log::*;
