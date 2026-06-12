#![forbid(unsafe_code)]

#[path = "ioi_step_module_bridge/mod.rs"]
mod ioi_step_module_bridge;

fn main() {
    println!(
        "{}",
        ioi_step_module_bridge::run_daemon_core_command_response_from_stdin()
    );
}
