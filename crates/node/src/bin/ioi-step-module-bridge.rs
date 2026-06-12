#![forbid(unsafe_code)]

#[path = "ioi_step_module_bridge/mod.rs"]
mod ioi_step_module_bridge;

fn main() {
    println!(
        "{}",
        ioi_services::agentic::runtime::kernel::command_dispatch::run_daemon_core_command_response_from_stdin()
    );
}
