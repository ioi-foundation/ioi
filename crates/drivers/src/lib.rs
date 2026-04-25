// Path: crates/drivers/src/lib.rs
// Removed #![forbid(unsafe_code)] to allow terminal process detachment (setsid)

pub mod authority;
pub mod browser;
pub mod chat_render;
pub mod gui;
pub mod mcp;
pub mod os;
pub mod provisioning;
pub mod terminal;
pub mod ucp;
