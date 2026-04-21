// apps/autopilot/src-tauri/src/kernel/mod.rs

pub mod artifacts;
pub mod branches;
pub mod capabilities;
pub mod chat;
pub mod connectors;
pub mod cosmic;
pub mod data;
pub mod dev;
pub mod events;
pub mod file_context;
pub mod governance;
pub mod graph;
pub mod hooks;
pub mod knowledge;
pub mod local_engine;
pub mod lsp;
pub mod notifications;
pub mod plugins;
pub mod remote_env;
pub mod runtime_parity;
pub mod server_mode;
pub mod session;
pub mod skill_sources;
pub mod state;
pub mod studio;
pub mod task;
pub mod thresholds;
pub mod voice;
pub mod workflows;
pub mod workspace_workflows;

pub use events::monitor_kernel_events;
