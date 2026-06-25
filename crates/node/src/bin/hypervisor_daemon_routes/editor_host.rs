//! Pre-applications WS-2 — OSS browser-IDE runtime host (openvscode-server).
//!
//! This is the runtime boundary the editor access service delegates to. WS-3 (objects/routes)
//! treats it as a black box that is either provisioned or not; WS-2 fills in the real pinned
//! launch. Until a reproducible OSS runtime is pinned + installed, `oss_runtime_present()` returns
//! false so the editor service fails CLOSED with `editor_runtime_not_provisioned` (honest skeleton).
//!
//! The runtime is provisioned reproducibly (pinned commit/version/sha256, fetch-once cache,
//! checksum-verified, fail-closed) by scripts/provision-hypervisor-vscode-browser-host.mjs into
//! the toolchain dir; a vendor VS Code Server variant may be license-gated, the OSS lane is not.
use std::path::PathBuf;

use serde_json::{json, Value};

use super::DaemonState;

/// The toolchain-owned install root for the OSS browser-IDE runtime (parallel to ~/.ioi/vm-toolchain).
pub(crate) fn runtime_root() -> PathBuf {
    std::env::var("IOI_HYPERVISOR_EDITOR_TOOLCHAIN_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| dirs_home().join(".ioi/editor-toolchain"))
}
fn dirs_home() -> PathBuf {
    std::env::var("HOME").map(PathBuf::from).unwrap_or_else(|_| PathBuf::from("/root"))
}

/// The pinned openvscode-server entrypoint (set by the WS-2 provisioner).
pub(crate) fn oss_server_bin() -> PathBuf {
    runtime_root().join("openvscode-server/bin/openvscode-server")
}

/// Is a reproducible OSS browser-IDE runtime installed + executable? Fail-closed: absent => false.
pub(crate) fn oss_runtime_present() -> bool {
    let bin = oss_server_bin();
    bin.exists() && std::fs::metadata(&bin).map(|m| {
        use std::os::unix::fs::PermissionsExt;
        m.permissions().mode() & 0o111 != 0
    }).unwrap_or(false)
}

/// Start the OSS runtime for a service. WS-2 wires the real launch + /version readiness; this stub
/// only runs once `oss_runtime_present()` is true (the route gates on that), so reaching here
/// without the WS-2 launcher is an honest not-yet-implemented error, never a fake ready.
pub(crate) fn start_oss_runtime(_st: &DaemonState, _service_id: &str, svc: &Value) -> Result<Value, String> {
    Err(format!(
        "openvscode-server present but the WS-2 launcher is not wired for service {} (target {})",
        svc.get("service_id").and_then(|v| v.as_str()).unwrap_or(""),
        svc.get("target_profile").and_then(|v| v.as_str()).unwrap_or("")
    ))
}

/// Stop the OSS runtime for a service (idempotent; no-op until WS-2 tracks live processes).
pub(crate) fn stop_oss_runtime(_st: &DaemonState, _service_id: &str) {}

/// Read the runtime install/launch log for a service.
pub(crate) fn read_runtime_log(data_dir: &str, service_id: &str) -> Value {
    let p = std::path::Path::new(data_dir).join("editor-services").join(format!("{service_id}.log"));
    match std::fs::read_to_string(&p) {
        Ok(s) => json!(s),
        Err(_) => json!(""),
    }
}
