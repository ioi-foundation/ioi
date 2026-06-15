#![forbid(unsafe_code)]

#[path = "ioi_step_module_bridge/mod.rs"]
mod ioi_step_module_bridge;

fn main() {
    println!(
        "{}",
        serde_json::json!({
            "ok": false,
            "error": {
                "code": "daemon_core_command_transport_retired",
                "message": "ioi-step-module-bridge is retired; use the Rust daemon-core workload API."
            }
        })
    );
}
