//! WS-4 — `VmMonitor` abstraction + cloud-hypervisor microVM provider (real KVM isolation).
//!
//! The provider drives a monitor trait so lifecycle/status/recovery code is monitor-agnostic;
//! cloud-hypervisor is the primary implementation (WS-5 adds QEMU/Firecracker lanes). WorkRun
//! execution happens INSIDE the guest (real kernel boundary — the host kernel/process table is
//! uninvolved). The workspace is staged in/out as a tar stream over vsock into a guest tmpfs, so
//! the host checkout is never the workspace and stays untouched. The toolchain (cloud-hypervisor,
//! guest kernel, initramfs+guest-agent) is pinned + sha256-verified at boot (G2 supply chain):
//! a checksum mismatch fails closed. Provision it with scripts/phase1/provision-vm-toolchain.sh.
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use ioi_services::agentic::runtime::kernel::emergency_containment::{
    admit_guest_transfer_len, UNBOUNDED_GUEST_TRANSFER_GATE,
};
use ioi_types::app::generated::architecture_contracts::HypervisorVmEnforcementDeclarationV1;
use serde_json::Value;
use sha2::{Digest, Sha256};

pub(crate) struct VmSpec {
    pub monitor_bin: PathBuf,
    pub kernel: PathBuf,
    pub initramfs: PathBuf,
    pub vcpus: u32,
    pub mem_mib: u32,
    pub run_dir: PathBuf,
    /// Workload-bound hostile-guest profile: the guest receives no network device. A future
    /// brokered network lane must be a different, admitted profile; silently attaching a NIC to
    /// this one would turn direct provider egress back on.
    pub network_device_count: u32,
    /// Host filesystems and control sockets are never attached to this guest. Workspace bytes
    /// cross only through the bounded import/export protocol below.
    pub host_mount_count: u32,
    pub host_control_socket_count: u32,
    /// Present only for a VM minted for one admitted WorkRun. Generic environment VMs remain
    /// environment-scoped and must not claim fresh-per-workload containment.
    pub workload_binding: Option<WorkloadVmBinding>,
    // The vsock UDS path. MUST be short (≤108 bytes, SUN_LEN) regardless of how deep the data dir
    // is — the workspace/serial live under run_dir, but the socket rides a short path.
    pub sock_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub(crate) struct WorkloadVmBinding {
    pub workrun_ref: String,
    pub isolation_binding_ref: String,
    pub isolation_binding_hash: String,
    pub principal_ref: String,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub(crate) struct VmEnforcementDeclaration {
    pub schema_version: &'static str,
    pub backend: &'static str,
    pub guest_kernel_boundary: bool,
    pub fresh_instance: bool,
    pub instance_scope: &'static str,
    pub workrun_ref: Option<String>,
    pub isolation_binding_ref: Option<String>,
    pub isolation_binding_hash: Option<String>,
    pub principal_ref: Option<String>,
    pub network_policy: &'static str,
    pub network_device_count: u32,
    pub host_mount_count: u32,
    pub host_control_socket_count: u32,
    pub guest_channel: &'static str,
    pub output_policy: &'static str,
}

impl VmSpec {
    /// Refuse a weakened launch before the monitor process exists. These are observed launch
    /// inputs, not a caller-authored label.
    fn enforce_hostile_guest_floor(&self) -> Result<(), String> {
        if self.network_device_count != 0 {
            return Err("workload_boundary_network_device_refused".into());
        }
        if self.host_mount_count != 0 {
            return Err("workload_boundary_host_mount_refused".into());
        }
        if self.host_control_socket_count != 0 {
            return Err("workload_boundary_host_control_socket_refused".into());
        }
        Ok(())
    }

    pub(crate) fn enforcement_declaration(
        &self,
        backend: &'static str,
    ) -> Result<VmEnforcementDeclaration, String> {
        self.enforce_hostile_guest_floor()?;
        let binding = self.workload_binding.as_ref();
        let declaration = VmEnforcementDeclaration {
            schema_version: "ioi.components.hypervisor.vm-enforcement-declaration.v1",
            backend,
            guest_kernel_boundary: true,
            fresh_instance: binding.is_some(),
            instance_scope: if binding.is_some() {
                "fresh_per_workrun"
            } else {
                "environment_scoped"
            },
            workrun_ref: binding.map(|value| value.workrun_ref.clone()),
            isolation_binding_ref: binding.map(|value| value.isolation_binding_ref.clone()),
            isolation_binding_hash: binding.map(|value| value.isolation_binding_hash.clone()),
            principal_ref: binding.map(|value| value.principal_ref.clone()),
            network_policy: "deny_all_no_virtual_nic",
            network_device_count: self.network_device_count,
            host_mount_count: self.host_mount_count,
            host_control_socket_count: self.host_control_socket_count,
            guest_channel: "host_initiated_vsock_uds_bounded",
            output_policy: "bounded_regular_file_archive_quarantine",
        };
        let value = serde_json::to_value(&declaration)
            .map_err(|error| format!("VM enforcement declaration serialization: {error}"))?;
        serde_json::from_value::<HypervisorVmEnforcementDeclarationV1>(value)
            .map_err(|error| format!("VM enforcement declaration contract: {error}"))?;
        Ok(declaration)
    }

    pub(crate) fn bind_workload(
        &mut self,
        workrun_ref: &str,
        isolation_binding_ref: &str,
        isolation_binding_hash: &str,
        principal_ref: &str,
    ) -> Result<(), String> {
        if !workrun_ref.starts_with("workrun://")
            || !isolation_binding_ref.starts_with("workload-isolation-binding://")
            || !isolation_binding_hash.starts_with("sha256:")
            || isolation_binding_hash.len() != 71
            || !principal_ref.starts_with("principal://")
            || [
                workrun_ref,
                isolation_binding_ref,
                isolation_binding_hash,
                principal_ref,
            ]
            .iter()
            .any(|value| value.chars().any(char::is_whitespace))
        {
            return Err("workload_vm_binding_invalid".into());
        }
        self.workload_binding = Some(WorkloadVmBinding {
            workrun_ref: workrun_ref.to_string(),
            isolation_binding_ref: isolation_binding_ref.to_string(),
            isolation_binding_hash: isolation_binding_hash.to_string(),
            principal_ref: principal_ref.to_string(),
        });
        Ok(())
    }

    pub(crate) fn workload_bound_enforcement_declaration(
        &self,
        backend: &'static str,
    ) -> Result<VmEnforcementDeclaration, String> {
        if self.workload_binding.is_none() {
            return Err("workload_vm_binding_required".into());
        }
        self.enforcement_declaration(backend)
    }
}

/// A short, SUN_LEN-safe vsock socket path that still carries the env id (so orphan-VM detection
/// can match it). Falls back to a hash if the id would push the path over the limit.
pub(crate) fn short_sock_path(env_id: &str) -> Result<PathBuf, String> {
    let dir = std::env::var("IOI_VM_SOCK_DIR")
        .unwrap_or_else(|_| unsafe { format!("/tmp/ioi-vm-sockets-{}", libc::geteuid()) });
    let root = PathBuf::from(&dir);
    std::fs::create_dir_all(&root)
        .map_err(|e| format!("create private VM socket directory {}: {e}", root.display()))?;
    let metadata = std::fs::symlink_metadata(&root)
        .map_err(|e| format!("inspect VM socket directory {}: {e}", root.display()))?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(format!(
            "VM socket root is not a private directory: {}",
            root.display()
        ));
    }
    let euid = unsafe { libc::geteuid() };
    if metadata.uid() != euid {
        return Err(format!(
            "VM socket root owner mismatch: {} is uid {}, daemon is uid {euid}",
            root.display(),
            metadata.uid()
        ));
    }
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| format!("restrict VM socket directory {}: {e}", root.display()))?;
    let safe: String = env_id
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
        .collect();
    let candidate = Path::new(&dir).join(format!("ioivm-{safe}.sock"));
    if candidate.to_string_lossy().len() <= 100 {
        Ok(candidate)
    } else {
        let mut h = Sha256::new();
        h.update(env_id.as_bytes());
        Ok(Path::new(&dir).join(format!("ioivm-{}.sock", &hex::encode(h.finalize())[..16])))
    }
}

pub(crate) struct VmHandle {
    pub child: Child,
    pub uds: PathBuf,
    pub run_dir: PathBuf,
    pub serial_log: PathBuf,
    pub monitor: &'static str,
    pub pid: u32,
    // QEMU's kernel vhost-vsock uses a guest CID (global host resource); CH/FC use the UDS, where
    // cid=3 is per-socket and informational.
    pub cid: u32,
}

pub(crate) struct ExecOut {
    pub exit_code: i32,
    pub output: String,
}

/// A byte stream to the guest agent: the CH/Firecracker UDS hybrid, or a direct AF_VSOCK socket
/// (QEMU's kernel vhost-vsock). The binary guest-agent protocol is identical over both.
pub(crate) enum Conn {
    Uds(UnixStream),
    Vsock(VsockStream),
}
impl Read for Conn {
    fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Conn::Uds(s) => s.read(b),
            Conn::Vsock(s) => s.read(b),
        }
    }
}
impl Write for Conn {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        match self {
            Conn::Uds(s) => s.write(b),
            Conn::Vsock(s) => s.write(b),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Conn::Uds(s) => s.flush(),
            Conn::Vsock(s) => s.flush(),
        }
    }
}

/// A host-side AF_VSOCK stream (libc) for the QEMU lane (kernel vhost-vsock).
pub(crate) struct VsockStream {
    fd: std::os::unix::io::RawFd,
}
impl Read for VsockStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = unsafe { libc::read(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(n as usize)
        }
    }
}
impl Write for VsockStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = unsafe { libc::write(self.fd, buf.as_ptr() as *const libc::c_void, buf.len()) };
        if n < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(n as usize)
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl Drop for VsockStream {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}

/// Connect to the guest agent over AF_VSOCK (cid, port). Used by the QEMU lane.
fn af_vsock_connect(cid: u32, port: u32) -> Result<VsockStream, String> {
    unsafe {
        let fd = libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM, 0);
        if fd < 0 {
            return Err(format!(
                "socket(AF_VSOCK): {}",
                std::io::Error::last_os_error()
            ));
        }
        let tv = libc::timeval {
            tv_sec: 180,
            tv_usec: 0,
        };
        let tvp = &tv as *const libc::timeval as *const libc::c_void;
        let tvl = std::mem::size_of::<libc::timeval>() as libc::socklen_t;
        libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVTIMEO, tvp, tvl);
        libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_SNDTIMEO, tvp, tvl);
        let mut addr: libc::sockaddr_vm = std::mem::zeroed();
        addr.svm_family = libc::AF_VSOCK as libc::sa_family_t;
        addr.svm_cid = cid;
        addr.svm_port = port;
        let r = libc::connect(
            fd,
            &addr as *const libc::sockaddr_vm as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t,
        );
        if r < 0 {
            let e = std::io::Error::last_os_error();
            libc::close(fd);
            return Err(format!("AF_VSOCK connect cid={cid}: {e}"));
        }
        Ok(VsockStream { fd })
    }
}

/// Allocate a guest CID for a QEMU VM (vhost-vsock CIDs are a global host resource).
fn alloc_guest_cid() -> u32 {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    19 + (nanos % 4_000_000) as u32
}

/// The monitor trait — cloud-hypervisor / QEMU / Firecracker behind one seam (WS-5). Monitors
/// differ ONLY in how they boot a VM (`start`); the workspace/exec/teardown RPC is identical
/// (all three speak the same host<->guest vsock UDS protocol), so it lives in default methods.
pub(crate) trait VmMonitor {
    fn id(&self) -> &'static str;
    fn start(&self, spec: &VmSpec) -> Result<VmHandle, String>;

    /// Open a byte stream to the guest agent. Default = the CH/Firecracker UDS hybrid; QEMU
    /// overrides to a direct AF_VSOCK connection (kernel vhost-vsock).
    fn connect(&self, vm: &VmHandle) -> Result<Conn, String> {
        Ok(Conn::Uds(vsock_connect(&vm.uds)?))
    }

    fn import_workspace(&self, vm: &VmHandle, tar: &[u8]) -> Result<(), String> {
        let admitted_len = admit_guest_transfer_len(
            tar.len() as u64,
            std::env::var(UNBOUNDED_GUEST_TRANSFER_GATE).ok().as_deref(),
        )
        .map_err(|refusal| format!("{}: {}", refusal.reason, refusal.detail))?;
        if admitted_len != tar.len() as u64 {
            return Err("workspace import length was not admitted exactly".into());
        }
        let mut s = self.connect(vm)?;
        s.write_all(b"I").map_err(|e| e.to_string())?;
        s.write_all(&(tar.len() as u64).to_le_bytes())
            .map_err(|e| e.to_string())?;
        s.write_all(tar).map_err(|e| format!("import write: {e}"))?;
        let mut o = [0u8; 1];
        s.read_exact(&mut o)
            .map_err(|e| format!("import ack: {e}"))?;
        if o[0] != b'O' {
            return Err("import not acknowledged".into());
        }
        Ok(())
    }

    fn exec(&self, vm: &VmHandle, cmd: &str) -> Result<ExecOut, String> {
        let mut s = self.connect(vm)?;
        let cb = cmd.as_bytes();
        if cb.len() > 1024 * 1024 {
            return Err("guest command exceeds the 1 MiB protocol limit".into());
        }
        s.write_all(b"E").map_err(|e| e.to_string())?;
        s.write_all(&(cb.len() as u32).to_le_bytes())
            .map_err(|e| e.to_string())?;
        s.write_all(cb).map_err(|e| format!("exec write: {e}"))?;
        let mut code = [0u8; 4];
        s.read_exact(&mut code)
            .map_err(|e| format!("exec code: {e}"))?;
        let mut ol = [0u8; 4];
        s.read_exact(&mut ol)
            .map_err(|e| format!("exec outlen: {e}"))?;
        let outlen = admit_guest_transfer_len(
            u32::from_le_bytes(ol) as u64,
            std::env::var(UNBOUNDED_GUEST_TRANSFER_GATE).ok().as_deref(),
        )
        .map_err(|refusal| format!("{}: {}", refusal.reason, refusal.detail))?
            as usize;
        let mut out = vec![0u8; outlen];
        s.read_exact(&mut out)
            .map_err(|e| format!("exec out: {e}"))?;
        Ok(ExecOut {
            exit_code: i32::from_le_bytes(code),
            output: String::from_utf8_lossy(&out).into_owned(),
        })
    }

    fn export_workspace(&self, vm: &VmHandle) -> Result<Vec<u8>, String> {
        let mut s = self.connect(vm)?;
        s.write_all(b"X").map_err(|e| e.to_string())?;
        let mut l = [0u8; 8];
        s.read_exact(&mut l)
            .map_err(|e| format!("export len: {e}"))?;
        // CONTAINMENT: the guest is the untrusted party and it declares this length. The host
        // used to allocate it verbatim, so a malicious or broken guest returning u64::MAX aborted
        // the daemon — a guest-to-host denial of service straight across the isolation boundary.
        // The declaration is now bounded, with an explicit opt-in that defaults OFF.
        let len = admit_guest_transfer_len(
            u64::from_le_bytes(l),
            std::env::var(UNBOUNDED_GUEST_TRANSFER_GATE).ok().as_deref(),
        )
        .map_err(|refusal| format!("{}: {}", refusal.reason, refusal.detail))?
            as usize;
        let mut buf = vec![0u8; len];
        s.read_exact(&mut buf)
            .map_err(|e| format!("export read: {e}"))?;
        Ok(buf)
    }

    fn proto_version(&self, vm: &VmHandle) -> Result<u32, String> {
        let mut s = self.connect(vm)?;
        s.write_all(b"H").map_err(|e| e.to_string())?;
        let mut v = [0u8; 4];
        s.read_exact(&mut v).map_err(|e| format!("proto: {e}"))?;
        Ok(u32::from_le_bytes(v))
    }

    fn stop(&self, vm: &mut VmHandle) -> Result<(), String> {
        if let Ok(mut s) = self.connect(vm) {
            let _ = s.write_all(b"S");
        }
        let deadline = Instant::now() + Duration::from_secs(8);
        loop {
            match vm.child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) => {
                    if Instant::now() > deadline {
                        let _ = vm.child.kill();
                        let _ = vm.child.wait();
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
                Err(_) => {
                    let _ = vm.child.kill();
                    break;
                }
            }
        }
        let _ = std::fs::remove_file(&vm.uds);
        Ok(())
    }
}

/// Wait for the guest agent to announce readiness on the serial log (shared by all monitors).
fn wait_for_agent(vm: &mut VmHandle, secs: u64, mon: &dyn VmMonitor) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(secs);
    loop {
        if let Ok(txt) = std::fs::read_to_string(&vm.serial_log) {
            if txt.contains("GUEST_AGENT_READY") {
                return Ok(());
            }
            if txt.contains("GUEST_AGENT_VSOCK_FAIL") || txt.contains("GUEST_AGENT_BIND_FAIL") {
                let _ = mon.stop(vm);
                return Err("guest agent failed to initialize vsock".into());
            }
        }
        if let Ok(Some(status)) = vm.child.try_wait() {
            let tail = std::fs::read_to_string(&vm.serial_log).unwrap_or_default();
            let tail = tail.lines().rev().take(3).collect::<Vec<_>>().join(" | ");
            return Err(format!("{} exited early ({status}): {tail}", vm.monitor));
        }
        if Instant::now() > deadline {
            let _ = mon.stop(vm);
            return Err("timeout waiting for guest agent (GUEST_AGENT_READY)".into());
        }
        std::thread::sleep(Duration::from_millis(150));
    }
}

pub(crate) struct CloudHypervisorMonitor;
pub(crate) struct FirecrackerMonitor;
pub(crate) struct QemuMonitor;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MonitorKind {
    CloudHypervisor,
    Firecracker,
    Qemu,
}

impl MonitorKind {
    pub(crate) fn parse(value: &str) -> Result<Self, String> {
        match value {
            "cloud-hypervisor" => Ok(Self::CloudHypervisor),
            "firecracker" => Ok(Self::Firecracker),
            "qemu" => Ok(Self::Qemu),
            other => Err(format!("unsupported microVM backend: {other}")),
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::CloudHypervisor => "cloud-hypervisor",
            Self::Firecracker => "firecracker",
            Self::Qemu => "qemu",
        }
    }
}

/// Select the monitor for a recipe (the §12 doctrine: by requirements, not boot speed). Returns
/// (monitor_id, selection_reason). cloud-hypervisor is the default; an explicit `monitor` hint or
/// a profile requirement chooses another lane.
pub(crate) fn select_monitor(recipe: &Value) -> Result<(MonitorKind, String), String> {
    if let Some(m) = recipe.get("monitor").and_then(|v| v.as_str()) {
        let kind = MonitorKind::parse(m)?;
        return Ok((kind, format!("recipe requested monitor={m}")));
    }
    let profile = recipe
        .get("isolation_profile")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    match profile {
        "minimal_sealed" | "short_lived" => Ok((
            MonitorKind::Firecracker,
            format!("isolation_profile={profile} → Firecracker (minimal-device, sealed)"),
        )),
        "stock_cloud_image" | "full_device_model" | "qcow2_snapshot" => Err(format!(
            "isolation_profile={profile} requires disk/device/snapshot semantics that are not implemented"
        )),
        "" => Ok((
            MonitorKind::CloudHypervisor,
            "default primary monitor (Rust-aligned, rich virtio)".to_string(),
        )),
        other => Err(format!("unsupported isolation_profile: {other}")),
    }
}

/// Factory: build the selected monitor.
pub(crate) fn make_monitor(kind: MonitorKind) -> Box<dyn VmMonitor> {
    match kind {
        MonitorKind::Firecracker => Box::new(FirecrackerMonitor),
        MonitorKind::Qemu => Box::new(QemuMonitor),
        MonitorKind::CloudHypervisor => Box::new(CloudHypervisorMonitor),
    }
}

fn sha256_file(path: &Path) -> Result<String, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let mut h = Sha256::new();
    h.update(&bytes);
    Ok(hex::encode(h.finalize()))
}

/// Pinned, checksum-verified toolchain (G2). Resolves paths from supply-manifest.json and
/// re-hashes each artifact — a mismatch is a fail-closed supply-chain error.
pub(crate) struct Toolchain {
    pub ch_bin: PathBuf,
    pub kernel: PathBuf,
    pub initramfs: PathBuf,
    pub manifest: Value,
}

pub(crate) fn resolve_toolchain(home_dir: &str) -> Result<Toolchain, String> {
    let dir = std::env::var("IOI_VM_TOOLCHAIN_DIR")
        .unwrap_or_else(|_| format!("{home_dir}/.ioi/vm-toolchain"));
    let manifest_path = Path::new(&dir).join("supply-manifest.json");
    let raw = std::fs::read(&manifest_path).map_err(|e| {
        format!(
            "VM supply manifest missing at {} ({e}); run scripts/phase1/provision-vm-toolchain.sh",
            manifest_path.display()
        )
    })?;
    let manifest: Value =
        serde_json::from_slice(&raw).map_err(|e| format!("supply manifest parse: {e}"))?;
    let verify = |key: &str| -> Result<PathBuf, String> {
        let entry = &manifest[key];
        let path = entry["path"]
            .as_str()
            .ok_or_else(|| format!("manifest {key}.path"))?;
        let want = entry["sha256"]
            .as_str()
            .ok_or_else(|| format!("manifest {key}.sha256"))?;
        let got = sha256_file(Path::new(path))?;
        if got != want {
            return Err(format!(
                "supply-chain CHECKSUM MISMATCH for {key}: got {got}, pinned {want} — fail closed"
            ));
        }
        Ok(PathBuf::from(path))
    };
    Ok(Toolchain {
        ch_bin: verify("monitor")?,
        kernel: verify("kernel")?,
        initramfs: verify("initramfs")?,
        manifest,
    })
}

/// Build a checksum-verified `VmSpec` for the selected monitor (G2 fail-closed). cloud-hypervisor
/// uses the PVH/PCI Debian kernel; firecracker + qemu use the MMIO kernel. The initramfs (busybox
/// + guest-agent) is shared. QEMU's binary is resolved from PATH (host-installed lane).
pub(crate) fn build_vm_spec(
    home_dir: &str,
    monitor_id: &str,
    run_dir: PathBuf,
    vcpus: u32,
    mem_mib: u32,
) -> Result<VmSpec, String> {
    let tc = resolve_toolchain(home_dir)?; // verifies monitor (CH), kernel, initramfs
    let dir = std::env::var("IOI_VM_TOOLCHAIN_DIR")
        .unwrap_or_else(|_| format!("{home_dir}/.ioi/vm-toolchain"));
    let m = &tc.manifest;
    let verify = |key: &str| -> Result<PathBuf, String> {
        let path = m[key]["path"]
            .as_str()
            .ok_or_else(|| format!("manifest {key}.path"))?;
        let want = m[key]["sha256"]
            .as_str()
            .ok_or_else(|| format!("manifest {key}.sha256"))?;
        let got = sha256_file(Path::new(path))?;
        if got != want {
            return Err(format!(
                "supply-chain CHECKSUM MISMATCH for {key}: got {got}, pinned {want}"
            ));
        }
        Ok(PathBuf::from(path))
    };
    let (monitor_bin, kernel) = match monitor_id {
        "firecracker" => (verify("firecracker")?, verify("fc_kernel")?),
        "qemu" => {
            // QEMU lane: the relocatable wrapper from provision-qemu.sh, or IOI_QEMU_BIN, or PATH.
            // The MMIO (fc) kernel boots under qemu microvm (same kernel as Firecracker).
            let provisioned = format!("{dir}/qemu/qemu-system-x86_64");
            let monitor_bin = std::env::var("IOI_QEMU_BIN")
                .ok()
                .map(PathBuf::from)
                .filter(|p| p.exists())
                .or_else(|| Some(PathBuf::from(&provisioned)).filter(|p| p.exists()))
                .unwrap_or_else(|| PathBuf::from("qemu-system-x86_64"));
            (monitor_bin, verify("fc_kernel")?)
        }
        _ => (tc.ch_bin.clone(), tc.kernel.clone()),
    };
    // sock_path defaults under run_dir; provision_microvm overrides it with a SUN_LEN-safe path.
    let sock_path = run_dir.join("vsock.uds");
    Ok(VmSpec {
        monitor_bin,
        kernel,
        initramfs: tc.initramfs.clone(),
        vcpus,
        mem_mib,
        run_dir,
        network_device_count: 0,
        host_mount_count: 0,
        host_control_socket_count: 0,
        workload_binding: None,
        sock_path,
    })
}

fn vsock_connect(uds: &Path) -> Result<UnixStream, String> {
    let mut s =
        UnixStream::connect(uds).map_err(|e| format!("vsock connect {}: {e}", uds.display()))?;
    s.set_read_timeout(Some(Duration::from_secs(180))).ok();
    s.set_write_timeout(Some(Duration::from_secs(180))).ok();
    // cloud-hypervisor host->guest hybrid handshake: "CONNECT <port>\n" then "OK ...\n".
    s.write_all(b"CONNECT 1024\n")
        .map_err(|e| format!("vsock connect write: {e}"))?;
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let n = s
            .read(&mut byte)
            .map_err(|e| format!("vsock handshake read: {e}"))?;
        if n == 0 {
            return Err("vsock handshake closed".into());
        }
        if byte[0] == b'\n' {
            break;
        }
        line.push(byte[0]);
        if line.len() > 64 {
            break;
        }
    }
    if !line.starts_with(b"OK") {
        return Err(format!(
            "vsock handshake unexpected: {}",
            String::from_utf8_lossy(&line)
        ));
    }
    Ok(s)
}

impl VmMonitor for CloudHypervisorMonitor {
    fn id(&self) -> &'static str {
        "cloud-hypervisor"
    }

    fn start(&self, spec: &VmSpec) -> Result<VmHandle, String> {
        spec.enforce_hostile_guest_floor()?;
        std::fs::create_dir_all(&spec.run_dir).map_err(|e| format!("vm run_dir: {e}"))?;
        let uds = spec.sock_path.clone();
        let serial_log = spec.run_dir.join("serial.log");
        let _ = std::fs::remove_file(&uds);
        let log = std::fs::File::create(&serial_log).map_err(|e| format!("serial log: {e}"))?;
        let log2 = log
            .try_clone()
            .map_err(|e| format!("serial log clone: {e}"))?;
        let child = Command::new(&spec.monitor_bin)
            .arg("--kernel")
            .arg(&spec.kernel)
            .arg("--initramfs")
            .arg(&spec.initramfs)
            .arg("--cmdline")
            .arg("console=ttyS0 reboot=t panic=-1 rdinit=/init quiet")
            .arg("--vsock")
            .arg(format!("cid=3,socket={}", uds.display()))
            .arg("--serial")
            .arg("tty")
            .arg("--console")
            .arg("off")
            .arg("--cpus")
            .arg(format!("boot={}", spec.vcpus.max(1)))
            .arg("--memory")
            .arg(format!("size={}M", spec.mem_mib.max(256)))
            .stdin(Stdio::null())
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(log2))
            .spawn()
            .map_err(|e| format!("spawn cloud-hypervisor: {e}"))?;
        let pid = child.id();
        let mut vm = VmHandle {
            child,
            uds,
            run_dir: spec.run_dir.clone(),
            serial_log,
            monitor: self.id(),
            pid,
            cid: 3,
        };
        wait_for_agent(&mut vm, 40, self)?;
        Ok(vm)
    }
}

impl VmMonitor for FirecrackerMonitor {
    fn id(&self) -> &'static str {
        "firecracker"
    }

    fn start(&self, spec: &VmSpec) -> Result<VmHandle, String> {
        spec.enforce_hostile_guest_floor()?;
        std::fs::create_dir_all(&spec.run_dir).map_err(|e| format!("vm run_dir: {e}"))?;
        let uds = spec.sock_path.clone();
        let serial_log = spec.run_dir.join("serial.log");
        let config = spec.run_dir.join("fc-config.json");
        let _ = std::fs::remove_file(&uds);
        let cfg = serde_json::json!({
            "boot-source": {
                "kernel_image_path": spec.kernel.to_string_lossy(),
                "initrd_path": spec.initramfs.to_string_lossy(),
                "boot_args": "console=ttyS0 reboot=t panic=-1 rdinit=/init"
            },
            "drives": [],
            "machine-config": { "vcpu_count": spec.vcpus.max(1), "mem_size_mib": spec.mem_mib.max(256) },
            "vsock": { "guest_cid": 3, "uds_path": uds.to_string_lossy() }
        });
        std::fs::write(&config, serde_json::to_vec_pretty(&cfg).unwrap_or_default())
            .map_err(|e| format!("fc config: {e}"))?;
        let log = std::fs::File::create(&serial_log).map_err(|e| format!("serial log: {e}"))?;
        let log2 = log
            .try_clone()
            .map_err(|e| format!("serial log clone: {e}"))?;
        let child = Command::new(&spec.monitor_bin)
            .arg("--no-api")
            .arg("--config-file")
            .arg(&config)
            .stdin(Stdio::null())
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(log2))
            .spawn()
            .map_err(|e| format!("spawn firecracker: {e}"))?;
        let pid = child.id();
        let mut vm = VmHandle {
            child,
            uds,
            run_dir: spec.run_dir.clone(),
            serial_log,
            monitor: self.id(),
            pid,
            cid: 3,
        };
        wait_for_agent(&mut vm, 40, self)?;
        Ok(vm)
    }
}

impl VmMonitor for QemuMonitor {
    fn id(&self) -> &'static str {
        "qemu"
    }

    // QEMU speaks AF_VSOCK over the KERNEL vhost-vsock device (not the CH/FC UDS hybrid).
    fn connect(&self, vm: &VmHandle) -> Result<Conn, String> {
        Ok(Conn::Vsock(af_vsock_connect(vm.cid, 1024)?))
    }

    fn start(&self, spec: &VmSpec) -> Result<VmHandle, String> {
        spec.enforce_hostile_guest_floor()?;
        // QEMU compat/diagnostic lane — a REAL boot (microvm machine + qboot firmware + the MMIO
        // guest kernel + vhost-vsock-device). Fails CLOSED with a precise reason if the qemu binary
        // is absent or /dev/vhost-vsock is not openable (group kvm) — never a fake boot.
        if Command::new(&spec.monitor_bin)
            .arg("--version")
            .output()
            .map(|o| !o.status.success())
            .unwrap_or(true)
        {
            return Err(format!(
                "qemu host-gated: {} not runnable (provision with scripts/phase1/provision-qemu.sh; \
                 cloud-hypervisor + firecracker are the always-available lanes)",
                spec.monitor_bin.display()
            ));
        }
        // vhost-vsock must be openable (root:kvm 0660). The user needs the kvm group / an ACL.
        match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/vhost-vsock")
        {
            Ok(_) => {}
            Err(e) => {
                return Err(format!(
                    "qemu host-gated: /dev/vhost-vsock not openable ({e}) — grant access as root: \
                     `usermod -aG kvm $USER` (re-login) or `setfacl -m u:$USER:rw /dev/vhost-vsock`"
                ));
            }
        }
        // firmware: microvm needs qboot.rom (resolved next to the qemu binary's share/ or via env).
        let fw = std::env::var("IOI_QEMU_FIRMWARE")
            .ok()
            .map(PathBuf::from)
            .or_else(|| {
                spec.monitor_bin
                    .parent()
                    .map(|d| d.join("share/qboot.rom"))
                    .filter(|p| p.exists())
            });
        let cid = alloc_guest_cid();
        std::fs::create_dir_all(&spec.run_dir).map_err(|e| format!("vm run_dir: {e}"))?;
        let uds = spec.sock_path.clone();
        let serial_log = spec.run_dir.join("serial.log");
        let log = std::fs::File::create(&serial_log).map_err(|e| format!("serial log: {e}"))?;
        let log2 = log
            .try_clone()
            .map_err(|e| format!("serial log clone: {e}"))?;
        let mut cmd = Command::new(&spec.monitor_bin);
        cmd.arg("-M")
            .arg("microvm,x-option-roms=off,pic=off,rtc=off")
            .arg("-enable-kvm")
            .arg("-cpu")
            .arg("host")
            .arg("-m")
            .arg(format!("{}", spec.mem_mib.max(256)))
            .arg("-smp")
            .arg(format!("{}", spec.vcpus.max(1)));
        if let Some(fw) = &fw {
            cmd.arg("-bios").arg(fw);
        }
        cmd.arg("-kernel")
            .arg(&spec.kernel)
            .arg("-initrd")
            .arg(&spec.initramfs)
            .arg("-append")
            .arg("console=ttyS0 reboot=t panic=-1 rdinit=/init")
            .arg("-device")
            .arg(format!("vhost-vsock-device,guest-cid={cid}"))
            .arg("-nodefaults")
            .arg("-no-reboot")
            .arg("-display")
            .arg("none")
            .arg("-serial")
            .arg(format!("file:{}", serial_log.to_string_lossy()))
            .stdin(Stdio::null())
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(log2));
        let child = cmd.spawn().map_err(|e| format!("spawn qemu: {e}"))?;
        let pid = child.id();
        let mut vm = VmHandle {
            child,
            uds,
            run_dir: spec.run_dir.clone(),
            serial_log,
            monitor: self.id(),
            pid,
            cid,
        };
        wait_for_agent(&mut vm, 40, self)?;
        Ok(vm)
    }
}

/// tar a host directory into memory (for import). Uses the system tar (busybox-compatible format).
pub(crate) fn tar_dir(dir: &Path) -> Result<Vec<u8>, String> {
    let out = Command::new("tar")
        .arg("-cf")
        .arg("-")
        .arg("-C")
        .arg(dir)
        .arg(".")
        .output()
        .map_err(|e| format!("tar spawn: {e}"))?;
    if !out.status.success() {
        return Err(format!("tar: {}", String::from_utf8_lossy(&out.stderr)));
    }
    Ok(out.stdout)
}

fn parse_tar_octal(field: &[u8]) -> Result<u64, String> {
    if field.first().is_some_and(|byte| byte & 0x80 != 0) {
        return Err("base-256 tar numeric fields are not admitted".into());
    }
    let text = std::str::from_utf8(field)
        .map_err(|_| "tar numeric field is not UTF-8/ASCII".to_string())?
        .trim_matches(|c| c == '\0' || c == ' ');
    if text.is_empty() {
        return Ok(0);
    }
    u64::from_str_radix(text, 8).map_err(|_| "invalid tar octal field".into())
}

fn tar_path(header: &[u8]) -> Result<PathBuf, String> {
    fn field(bytes: &[u8]) -> Result<&str, String> {
        let end = bytes
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(bytes.len());
        std::str::from_utf8(&bytes[..end]).map_err(|_| "tar path is not UTF-8".into())
    }
    let name = field(&header[0..100])?;
    let prefix = field(&header[345..500])?;
    let joined = if prefix.is_empty() {
        name.to_string()
    } else {
        format!("{prefix}/{name}")
    };
    if joined.is_empty() {
        return Err("tar member has no path".into());
    }
    let path = PathBuf::from(joined);
    for component in path.components() {
        match component {
            std::path::Component::Normal(_) | std::path::Component::CurDir => {}
            _ => {
                return Err(format!(
                    "tar member escapes extraction root: {}",
                    path.display()
                ))
            }
        }
    }
    Ok(path)
}

/// Validate an archive at the host trust boundary. Only regular files and directories with
/// relative paths are admitted; links, devices, FIFOs, sparse/PAX/GNU extensions and traversal
/// are refused. This intentionally accepts a smaller format than the system extractor.
fn validate_tar_for_host_extract(tar: &[u8]) -> Result<(), String> {
    if tar.len() % 512 != 0 {
        return Err("tar length is not block-aligned".into());
    }
    admit_guest_transfer_len(
        tar.len() as u64,
        std::env::var(UNBOUNDED_GUEST_TRANSFER_GATE).ok().as_deref(),
    )
    .map_err(|refusal| format!("{}: {}", refusal.reason, refusal.detail))?;
    let mut offset = 0usize;
    let mut members = 0usize;
    while offset < tar.len() {
        let header = &tar[offset..offset + 512];
        if header.iter().all(|byte| *byte == 0) {
            if tar[offset..].iter().any(|byte| *byte != 0) {
                return Err("tar contains non-zero data after its end marker".into());
            }
            return Ok(());
        }
        members += 1;
        if members > 100_000 {
            return Err("tar member count exceeds 100000".into());
        }
        let path = tar_path(header)?;
        let kind = header[156];
        if !matches!(kind, 0 | b'0' | b'5') {
            return Err(format!(
                "tar member type {kind:#x} is not admitted for {}",
                path.display()
            ));
        }
        let size = parse_tar_octal(&header[124..136])?;
        if kind == b'5' && size != 0 {
            return Err(format!("tar directory carries payload: {}", path.display()));
        }
        let padded = size
            .checked_add(511)
            .ok_or_else(|| "tar member size overflow".to_string())?
            / 512
            * 512;
        let next = (offset as u64)
            .checked_add(512)
            .and_then(|value| value.checked_add(padded))
            .ok_or_else(|| "tar archive size overflow".to_string())?;
        if next > tar.len() as u64 {
            return Err(format!("truncated tar member: {}", path.display()));
        }
        offset = next as usize;
    }
    Ok(())
}

/// Extract a validated tar into a host directory.
pub(crate) fn untar_into(dir: &Path, tar: &[u8]) -> Result<(), String> {
    validate_tar_for_host_extract(tar)?;
    std::fs::create_dir_all(dir).map_err(|e| format!("mkdir: {e}"))?;
    let mut child = Command::new("tar")
        .arg("-xf")
        .arg("-")
        .arg("--no-same-owner")
        .arg("--no-same-permissions")
        .arg("-C")
        .arg(dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("tar -x spawn: {e}"))?;
    child
        .stdin
        .take()
        .unwrap()
        .write_all(tar)
        .map_err(|e| format!("tar -x write: {e}"))?;
    let status = child.wait().map_err(|e| format!("tar -x wait: {e}"))?;
    if !status.success() {
        return Err("tar -x failed".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn archive_with(name: &str, kind: u8, size: u64) -> Vec<u8> {
        let mut archive = vec![0u8; 1024 + (((size + 511) / 512) * 512) as usize];
        archive[..name.len()].copy_from_slice(name.as_bytes());
        archive[156] = kind;
        let encoded = format!("{size:011o}\0");
        archive[124..136].copy_from_slice(encoded.as_bytes());
        archive
    }

    #[test]
    fn monitor_selection_is_closed_and_unsupported_profiles_fail_closed() {
        assert_eq!(
            select_monitor(&serde_json::json!({ "monitor": "qemu" }))
                .expect("qemu is registered")
                .0,
            MonitorKind::Qemu
        );
        assert!(select_monitor(&serde_json::json!({ "monitor": "unknown" })).is_err());
        assert!(select_monitor(&serde_json::json!({
            "isolation_profile": "qcow2_snapshot"
        }))
        .is_err());
    }

    #[test]
    fn host_extract_accepts_only_relative_regular_files_and_directories() {
        assert!(validate_tar_for_host_extract(&archive_with("./safe.txt", b'0', 0)).is_ok());
        assert!(validate_tar_for_host_extract(&archive_with("./dir/", b'5', 0)).is_ok());
        assert!(validate_tar_for_host_extract(&archive_with("../escape", b'0', 0)).is_err());
        assert!(validate_tar_for_host_extract(&archive_with("/absolute", b'0', 0)).is_err());
        assert!(validate_tar_for_host_extract(&archive_with("./link", b'2', 0)).is_err());
        assert!(validate_tar_for_host_extract(&archive_with("./hardlink", b'1', 0)).is_err());
        assert!(validate_tar_for_host_extract(&archive_with("./fifo", b'6', 0)).is_err());
        assert!(validate_tar_for_host_extract(&archive_with("./device", b'3', 0)).is_err());
    }

    #[test]
    fn host_extract_rejects_truncated_or_extended_archives() {
        let mut truncated = archive_with("./payload", b'0', 513);
        truncated.truncate(1024);
        assert!(validate_tar_for_host_extract(&truncated).is_err());

        let mut trailing = archive_with("./safe", b'0', 0);
        *trailing.last_mut().expect("archive has end block") = 1;
        assert!(validate_tar_for_host_extract(&trailing).is_err());
    }

    fn test_spec() -> VmSpec {
        VmSpec {
            monitor_bin: PathBuf::from("/bin/false"),
            kernel: PathBuf::from("/dev/null"),
            initramfs: PathBuf::from("/dev/null"),
            vcpus: 1,
            mem_mib: 256,
            run_dir: PathBuf::from("/tmp/ioi-boundary-unit"),
            network_device_count: 0,
            host_mount_count: 0,
            host_control_socket_count: 0,
            workload_binding: None,
            sock_path: PathBuf::from("/tmp/ioi-boundary-unit.sock"),
        }
    }

    #[test]
    fn hostile_guest_floor_refuses_each_planted_bypass_before_launch() {
        let baseline = test_spec();
        let environment = baseline
            .enforcement_declaration("cloud-hypervisor")
            .unwrap();
        assert!(!environment.fresh_instance);
        assert_eq!(environment.instance_scope, "environment_scoped");
        assert_eq!(
            baseline
                .workload_bound_enforcement_declaration("cloud-hypervisor")
                .unwrap_err(),
            "workload_vm_binding_required"
        );

        let mut network = test_spec();
        network.network_device_count = 1;
        assert_eq!(
            network.enforce_hostile_guest_floor().unwrap_err(),
            "workload_boundary_network_device_refused"
        );

        let mut mount = test_spec();
        mount.host_mount_count = 1;
        assert_eq!(
            mount.enforce_hostile_guest_floor().unwrap_err(),
            "workload_boundary_host_mount_refused"
        );

        let mut socket = test_spec();
        socket.host_control_socket_count = 1;
        assert_eq!(
            socket.enforce_hostile_guest_floor().unwrap_err(),
            "workload_boundary_host_control_socket_refused"
        );
    }

    /// Real-host T2 probe. This is ignored in generic CI because it needs KVM and the pinned VM
    /// toolchain, but `check:workload-bound-effect-boundary -- --live` invokes it explicitly.
    /// The guest agent is PID 1/root, so these probes execute with the strongest guest-local
    /// privilege the selected `trusted_host_hostile_guest` profile promises to contain.
    #[test]
    #[ignore = "requires /dev/kvm and the checksum-pinned ~/.ioi/vm-toolchain"]
    fn root_guest_cannot_reach_a_host_canary_or_find_protected_material() {
        let home = std::env::var("HOME").expect("HOME selects the local pinned toolchain");
        let run = tempfile::tempdir().expect("probe run dir");
        let listener = TcpListener::bind("127.0.0.1:0").expect("host canary listener");
        listener.set_nonblocking(true).expect("nonblocking canary");
        let port = listener.local_addr().unwrap().port();

        let mut spec = build_vm_spec(&home, "cloud-hypervisor", run.path().join("vm"), 1, 384)
            .expect("verified VM spec");
        spec.bind_workload(
            "workrun://t2-live",
            "workload-isolation-binding://t2-live",
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "principal://hostile-root-guest",
        )
        .expect("exact workload VM binding");
        spec.sock_path = short_sock_path(&format!("t2-live-{}", std::process::id()))
            .expect("private short socket");
        let declaration = spec
            .workload_bound_enforcement_declaration("cloud-hypervisor")
            .expect("hostile guest floor");
        let monitor = CloudHypervisorMonitor;
        let mut vm = monitor.start(&spec).expect("real KVM guest boot");

        // Mint one exact guest-visible handle. It is authority to submit only the already-bound
        // request, not a provider credential and not a general signing primitive.
        let state_dir = run.path().join("state");
        let request = serde_json::json!({
            "operation": "test_protected_provider_effect",
            "provider": "host-canary",
            "maximum_invocations": 1
        });
        let proposal = crate::workload_effect_boundary::mint_guest_effect_capability(
            state_dir.to_str().unwrap(),
            "workload-isolation-binding://t2-live",
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "principal://hostile-root-guest",
            "nonce-t2-live",
            "hypervisor-final-invoker",
            "provider-resource://host-canary/protected",
            "result-destination://t2/quarantine",
            &request,
            1_000,
            61_000,
        )
        .expect("mint exact workload capability");
        let input = run.path().join("input");
        std::fs::create_dir_all(&input).unwrap();
        std::fs::write(
            input.join("proposal.json"),
            serde_jcs::to_vec(&proposal).unwrap(),
        )
        .unwrap();
        monitor
            .import_workspace(&vm, &tar_dir(&input).unwrap())
            .expect("bounded guest input");

        let root = monitor.exec(&vm, "id -u").expect("root probe");
        let network = monitor
            .exec(
                &vm,
                &format!(
                    "set +e; printf 'interfaces='; ls -1 /sys/class/net 2>/dev/null | tr '\\n' ','; echo; \
                     /bin/busybox wget -T 1 -qO- http://10.0.2.2:{port}/protected >/tmp/raw-ip 2>&1; echo raw_ip=$?; \
                     /bin/busybox wget -T 1 -qO- http://127.0.0.1:{port}/protected >/tmp/loopback 2>&1; echo loopback=$?; \
                     /bin/busybox wget -T 1 -qO- 'http://[::1]:{port}/protected' >/tmp/ipv6 2>&1; echo ipv6=$?; \
                     /bin/busybox wget -T 1 -qO- http://169.254.169.254/latest/meta-data/ >/tmp/metadata 2>&1; echo metadata=$?; \
                     /bin/busybox wget -T 1 -qO- https://console-api.akash.network/ >/tmp/dns 2>&1; echo dns=$?; \
                     /bin/busybox nc -u -w 1 10.0.2.2 {port} </dev/null >/tmp/udp 2>&1; echo udp=$?; \
                     /bin/busybox nc -w 1 10.0.2.2 {port} </dev/null >/tmp/tunnel 2>&1; echo tunnel=$?; \
                     http_proxy=http://10.0.2.2:{port} /bin/busybox wget -T 1 -qO- http://proxy-canary.invalid/ >/tmp/proxy 2>&1; echo proxy=$?; \
                     /bin/busybox nslookup t2-exfil-canary.invalid >/tmp/dns-exfil 2>&1; echo dns_exfil=$?; \
                     /bin/busybox wget -T 1 -qO- https://dl-cdn.alpinelinux.org/alpine/ >/tmp/package 2>&1; echo package=$?"
                ),
            )
            .expect("network probes");
        let material = monitor
            .exec(
                &vm,
                "set +e; for p in /dev/kvm /dev/vhost-vsock /var/run/docker.sock /run/docker.sock /host /wallet /secrets; do [ -e \"$p\" ] && echo exposed=$p; done; for f in /proc/1/fd/*; do printf 'pid1_fd=%s:' \"$f\"; /bin/busybox readlink \"$f\"; done; tr '\\000' '\\n' </proc/1/environ | /bin/busybox grep -E 'AKASH|IOI_C7|PASSWORD|RECOVERY|PRIVATE_KEY|TOKEN|http_proxy|https_proxy|ALL_PROXY' || echo no_protected_environment",
            )
            .expect("material probes");

        // The hostile guest submits through the sole data path it has: bounded output. The host
        // validates the archive into quarantine and then verifies every bound capability field
        // before entering the final invoker exactly once.
        let submitted = monitor
            .exec(&vm, "cp proposal.json submitted-proposal.json")
            .expect("guest proposal submission");
        assert_eq!(submitted.exit_code, 0);
        let exported = monitor.export_workspace(&vm).expect("bounded guest output");
        let quarantine = run.path().join("quarantine");
        untar_into(&quarantine, &exported).expect("transactional output quarantine");
        let returned_proposal = std::fs::read(quarantine.join("submitted-proposal.json")).unwrap();
        let final_invoker_calls = AtomicUsize::new(0);
        let consumption = crate::workload_effect_boundary::consume_guest_effect_proposal_bytes(
            state_dir.to_str().unwrap(),
            &returned_proposal,
            2_000,
            |exact| {
                final_invoker_calls.fetch_add(1, Ordering::SeqCst);
                assert_eq!(exact, &request);
                Ok(serde_json::json!({
                    "provider_receipt_ref": "provider-receipt://host-canary/one",
                    "outcome": "mock_effect_observed"
                }))
            },
        )
        .expect("legitimate syscall reaches final invoker");
        let replay = crate::workload_effect_boundary::consume_guest_effect_proposal_bytes(
            state_dir.to_str().unwrap(),
            &returned_proposal,
            3_000,
            |_| panic!("replay cannot enter final invoker"),
        )
        .unwrap_err();

        monitor.stop(&mut vm).expect("guest teardown request");
        let terminal = vm
            .child
            .try_wait()
            .expect("observe monitor process")
            .is_some();
        let host_canary_calls = usize::from(listener.accept().is_ok());

        assert_eq!(
            root.output.trim(),
            "0",
            "probe must actually have guest root"
        );
        assert!(
            network.output.contains("interfaces=lo,"),
            "the guest must expose loopback only: {}",
            network.output
        );
        for probe in [
            "raw_ip",
            "loopback",
            "ipv6",
            "metadata",
            "dns",
            "udp",
            "tunnel",
            "proxy",
            "dns_exfil",
            "package",
        ] {
            assert!(
                !network.output.contains(&format!("{probe}=0")),
                "{probe} unexpectedly reached a network target: {}",
                network.output
            );
        }
        assert_eq!(
            host_canary_calls, 0,
            "direct guest host/provider boundary calls"
        );
        assert_eq!(final_invoker_calls.load(Ordering::SeqCst), 1);
        assert_eq!(consumption["final_invoker_calls"], 1);
        assert_eq!(replay, "workload_effect_capability_already_consumed");
        assert!(
            !material.output.contains("exposed="),
            "protected host material crossed into guest: {}",
            material.output
        );
        assert!(material.output.contains("no_protected_environment"));
        assert!(material.output.contains("pid1_fd="));
        for forbidden_fd_target in ["docker.sock", "/wallet", "/secrets", "/dev/kvm"] {
            assert!(
                !material.output.contains(forbidden_fd_target),
                "protected inherited FD target crossed into guest: {}",
                material.output
            );
        }
        assert!(
            terminal,
            "the monitor must be observably terminal after teardown"
        );

        eprintln!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "schema_version": "ioi.hypervisor.workload-bound-effect-boundary-live-probe.v1",
                "guest_uid": 0,
                "enforcement_declaration": declaration,
                "attempted_paths": ["raw_ip", "loopback", "ipv6", "metadata", "dns", "udp", "proxy", "tunnel", "dns_exfil", "package_fetch", "host_device", "host_socket", "inherited_fd", "environment"],
                "direct_host_canary_invocations": host_canary_calls,
                "authenticated_final_invoker_calls": final_invoker_calls.load(Ordering::SeqCst),
                "capability_replay": "refused",
                "output_quarantine": "bounded_archive_validated",
                "monitor_terminal": terminal,
                "claim_boundary": "This probe establishes the named local KVM/no-NIC hostile-guest profile; it does not establish resistance to a compromised host kernel, VMM, daemon, firmware, or hardware."
            }))
            .unwrap()
        );
    }
}
