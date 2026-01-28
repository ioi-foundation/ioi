// apps/autopilot/src-tauri/src/kernel/mod.rs

pub mod data;
pub mod events;
pub mod governance;
pub mod graph;
pub mod session;
pub mod state; // Internal helpers shared among submodules
pub mod task;

// Re-export commands for flat access in lib.rs or internal use if needed.
// However, note that `generate_handler` now uses the module paths directly (e.g. `kernel::task::start_task`)
// to avoid ambiguity with the hidden `__cmd__` macros. 
// These re-exports are kept for convenience if you want to use `use kernel::*` inside other backend modules.

pub use data::{get_available_tools, get_context_blob};
pub use events::monitor_kernel_events;
pub use governance::{clear_gate_response, gate_respond, get_gate_response};
pub use graph::{check_node_cache, run_studio_graph, test_node_execution};
pub use session::{delete_session, get_session_history, load_session};
pub use task::{
    complete_task, dismiss_task, get_current_task, start_task, update_task,
};