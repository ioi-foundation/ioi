// Path: crates/drivers/src/lib.rs
// Removed #![forbid(unsafe_code)] to allow terminal process detachment (setsid)

pub mod gui;
pub mod browser;
pub mod ucp; 
pub mod os;  
pub mod terminal;
pub mod mcp;
pub mod provisioning;