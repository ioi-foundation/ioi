// apps/autopilot/src-tauri/src/kernel/mod.rs

pub mod data;
pub mod events;
pub mod governance;
pub mod graph;
pub mod session;
pub mod state;
pub mod task;
// [NEW] Linux specific logic
pub mod linux_blur;

pub use events::monitor_kernel_events;
