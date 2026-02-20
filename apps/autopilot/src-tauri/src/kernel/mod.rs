// apps/autopilot/src-tauri/src/kernel/mod.rs

pub mod artifacts;
pub mod connectors;
pub mod cosmic;
pub mod data;
pub mod events;
pub mod governance;
pub mod graph;
pub mod session;
pub mod state;
pub mod task;
pub mod thresholds;

pub use events::monitor_kernel_events;
