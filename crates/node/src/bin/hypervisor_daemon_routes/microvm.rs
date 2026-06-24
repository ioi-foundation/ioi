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
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::Value;
use sha2::{Digest, Sha256};

pub(crate) struct VmSpec {
    pub monitor_bin: PathBuf,
    pub kernel: PathBuf,
    pub initramfs: PathBuf,
    pub vcpus: u32,
    pub mem_mib: u32,
    pub run_dir: PathBuf,
    // The vsock UDS path. MUST be short (≤108 bytes, SUN_LEN) regardless of how deep the data dir
    // is — the workspace/serial live under run_dir, but the socket rides a short path.
    pub sock_path: PathBuf,
}

/// A short, SUN_LEN-safe vsock socket path that still carries the env id (so orphan-VM detection
/// can match it). Falls back to a hash if the id would push the path over the limit.
pub(crate) fn short_sock_path(env_id: &str) -> PathBuf {
    let dir = std::env::var("IOI_VM_SOCK_DIR").unwrap_or_else(|_| "/tmp".to_string());
    let safe: String = env_id.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-').collect();
    let candidate = Path::new(&dir).join(format!("ioivm-{safe}.sock"));
    if candidate.to_string_lossy().len() <= 100 {
        candidate
    } else {
        let mut h = Sha256::new();
        h.update(env_id.as_bytes());
        Path::new(&dir).join(format!("ioivm-{}.sock", &hex::encode(h.finalize())[..16]))
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
        match self { Conn::Uds(s) => s.read(b), Conn::Vsock(s) => s.read(b) }
    }
}
impl Write for Conn {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        match self { Conn::Uds(s) => s.write(b), Conn::Vsock(s) => s.write(b) }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self { Conn::Uds(s) => s.flush(), Conn::Vsock(s) => s.flush() }
    }
}

/// A host-side AF_VSOCK stream (libc) for the QEMU lane (kernel vhost-vsock).
pub(crate) struct VsockStream {
    fd: std::os::unix::io::RawFd,
}
impl Read for VsockStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = unsafe { libc::read(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n < 0 { Err(std::io::Error::last_os_error()) } else { Ok(n as usize) }
    }
}
impl Write for VsockStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = unsafe { libc::write(self.fd, buf.as_ptr() as *const libc::c_void, buf.len()) };
        if n < 0 { Err(std::io::Error::last_os_error()) } else { Ok(n as usize) }
    }
    fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
}
impl Drop for VsockStream {
    fn drop(&mut self) { unsafe { libc::close(self.fd); } }
}

/// Connect to the guest agent over AF_VSOCK (cid, port). Used by the QEMU lane.
fn af_vsock_connect(cid: u32, port: u32) -> Result<VsockStream, String> {
    unsafe {
        let fd = libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM, 0);
        if fd < 0 {
            return Err(format!("socket(AF_VSOCK): {}", std::io::Error::last_os_error()));
        }
        let tv = libc::timeval { tv_sec: 180, tv_usec: 0 };
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
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
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
        let mut s = self.connect(vm)?;
        s.write_all(b"I").map_err(|e| e.to_string())?;
        s.write_all(&(tar.len() as u64).to_le_bytes()).map_err(|e| e.to_string())?;
        s.write_all(tar).map_err(|e| format!("import write: {e}"))?;
        let mut o = [0u8; 1];
        s.read_exact(&mut o).map_err(|e| format!("import ack: {e}"))?;
        if o[0] != b'O' {
            return Err("import not acknowledged".into());
        }
        Ok(())
    }

    fn exec(&self, vm: &VmHandle, cmd: &str) -> Result<ExecOut, String> {
        let mut s = self.connect(vm)?;
        let cb = cmd.as_bytes();
        s.write_all(b"E").map_err(|e| e.to_string())?;
        s.write_all(&(cb.len() as u32).to_le_bytes()).map_err(|e| e.to_string())?;
        s.write_all(cb).map_err(|e| format!("exec write: {e}"))?;
        let mut code = [0u8; 4];
        s.read_exact(&mut code).map_err(|e| format!("exec code: {e}"))?;
        let mut ol = [0u8; 4];
        s.read_exact(&mut ol).map_err(|e| format!("exec outlen: {e}"))?;
        let outlen = u32::from_le_bytes(ol) as usize;
        let mut out = vec![0u8; outlen];
        s.read_exact(&mut out).map_err(|e| format!("exec out: {e}"))?;
        Ok(ExecOut {
            exit_code: i32::from_le_bytes(code),
            output: String::from_utf8_lossy(&out).into_owned(),
        })
    }

    fn export_workspace(&self, vm: &VmHandle) -> Result<Vec<u8>, String> {
        let mut s = self.connect(vm)?;
        s.write_all(b"X").map_err(|e| e.to_string())?;
        let mut l = [0u8; 8];
        s.read_exact(&mut l).map_err(|e| format!("export len: {e}"))?;
        let len = u64::from_le_bytes(l) as usize;
        let mut buf = vec![0u8; len];
        s.read_exact(&mut buf).map_err(|e| format!("export read: {e}"))?;
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

/// Select the monitor for a recipe (the §12 doctrine: by requirements, not boot speed). Returns
/// (monitor_id, selection_reason). cloud-hypervisor is the default; an explicit `monitor` hint or
/// a profile requirement chooses another lane.
pub(crate) fn select_monitor(recipe: &Value) -> (String, String) {
    if let Some(m) = recipe.get("monitor").and_then(|v| v.as_str()) {
        return (m.to_string(), format!("recipe requested monitor={m}"));
    }
    let profile = recipe.get("isolation_profile").and_then(|v| v.as_str()).unwrap_or("");
    match profile {
        "minimal_sealed" | "short_lived" => (
            "firecracker".to_string(),
            format!("isolation_profile={profile} → Firecracker (minimal-device, sealed)"),
        ),
        "stock_cloud_image" | "full_device_model" | "qcow2_snapshot" => (
            "qemu".to_string(),
            format!("isolation_profile={profile} → QEMU (compat/full-device lane)"),
        ),
        _ => (
            "cloud-hypervisor".to_string(),
            "default primary monitor (Rust-aligned, rich virtio)".to_string(),
        ),
    }
}

/// Factory: build the selected monitor.
pub(crate) fn make_monitor(id: &str) -> Box<dyn VmMonitor> {
    match id {
        "firecracker" => Box::new(FirecrackerMonitor),
        "qemu" => Box::new(QemuMonitor),
        _ => Box::new(CloudHypervisorMonitor),
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
    let dir = std::env::var("IOI_VM_TOOLCHAIN_DIR").unwrap_or_else(|_| format!("{home_dir}/.ioi/vm-toolchain"));
    let manifest_path = Path::new(&dir).join("supply-manifest.json");
    let raw = std::fs::read(&manifest_path).map_err(|e| {
        format!("VM supply manifest missing at {} ({e}); run scripts/phase1/provision-vm-toolchain.sh", manifest_path.display())
    })?;
    let manifest: Value = serde_json::from_slice(&raw).map_err(|e| format!("supply manifest parse: {e}"))?;
    let verify = |key: &str| -> Result<PathBuf, String> {
        let entry = &manifest[key];
        let path = entry["path"].as_str().ok_or_else(|| format!("manifest {key}.path"))?;
        let want = entry["sha256"].as_str().ok_or_else(|| format!("manifest {key}.sha256"))?;
        let got = sha256_file(Path::new(path))?;
        if got != want {
            return Err(format!("supply-chain CHECKSUM MISMATCH for {key}: got {got}, pinned {want} — fail closed"));
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
    let dir = std::env::var("IOI_VM_TOOLCHAIN_DIR").unwrap_or_else(|_| format!("{home_dir}/.ioi/vm-toolchain"));
    let m = &tc.manifest;
    let verify = |key: &str| -> Result<PathBuf, String> {
        let path = m[key]["path"].as_str().ok_or_else(|| format!("manifest {key}.path"))?;
        let want = m[key]["sha256"].as_str().ok_or_else(|| format!("manifest {key}.sha256"))?;
        let got = sha256_file(Path::new(path))?;
        if got != want {
            return Err(format!("supply-chain CHECKSUM MISMATCH for {key}: got {got}, pinned {want}"));
        }
        Ok(PathBuf::from(path))
    };
    let (monitor_bin, kernel) = match monitor_id {
        "firecracker" => (verify("firecracker")?, verify("fc_kernel")?),
        "qemu" => {
            // QEMU lane: the relocatable wrapper from provision-qemu.sh, or IOI_QEMU_BIN, or PATH.
            // The MMIO (fc) kernel boots under qemu microvm (same kernel as Firecracker).
            let provisioned = format!("{dir}/qemu/qemu-system-x86_64");
            let monitor_bin = std::env::var("IOI_QEMU_BIN").ok().map(PathBuf::from)
                .filter(|p| p.exists())
                .or_else(|| Some(PathBuf::from(&provisioned)).filter(|p| p.exists()))
                .unwrap_or_else(|| PathBuf::from("qemu-system-x86_64"));
            (monitor_bin, verify("fc_kernel")?)
        }
        _ => (tc.ch_bin.clone(), tc.kernel.clone()),
    };
    // sock_path defaults under run_dir; provision_microvm overrides it with a SUN_LEN-safe path.
    let sock_path = run_dir.join("vsock.uds");
    Ok(VmSpec { monitor_bin, kernel, initramfs: tc.initramfs.clone(), vcpus, mem_mib, run_dir, sock_path })
}

fn vsock_connect(uds: &Path) -> Result<UnixStream, String> {
    let mut s = UnixStream::connect(uds).map_err(|e| format!("vsock connect {}: {e}", uds.display()))?;
    s.set_read_timeout(Some(Duration::from_secs(180))).ok();
    s.set_write_timeout(Some(Duration::from_secs(180))).ok();
    // cloud-hypervisor host->guest hybrid handshake: "CONNECT <port>\n" then "OK ...\n".
    s.write_all(b"CONNECT 1024\n").map_err(|e| format!("vsock connect write: {e}"))?;
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let n = s.read(&mut byte).map_err(|e| format!("vsock handshake read: {e}"))?;
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
        return Err(format!("vsock handshake unexpected: {}", String::from_utf8_lossy(&line)));
    }
    Ok(s)
}

impl VmMonitor for CloudHypervisorMonitor {
    fn id(&self) -> &'static str {
        "cloud-hypervisor"
    }

    fn start(&self, spec: &VmSpec) -> Result<VmHandle, String> {
        std::fs::create_dir_all(&spec.run_dir).map_err(|e| format!("vm run_dir: {e}"))?;
        let uds = spec.sock_path.clone();
        let serial_log = spec.run_dir.join("serial.log");
        let _ = std::fs::remove_file(&uds);
        let log = std::fs::File::create(&serial_log).map_err(|e| format!("serial log: {e}"))?;
        let log2 = log.try_clone().map_err(|e| format!("serial log clone: {e}"))?;
        let child = Command::new(&spec.monitor_bin)
            .arg("--kernel").arg(&spec.kernel)
            .arg("--initramfs").arg(&spec.initramfs)
            .arg("--cmdline").arg("console=ttyS0 reboot=t panic=-1 rdinit=/init quiet")
            .arg("--vsock").arg(format!("cid=3,socket={}", uds.display()))
            .arg("--serial").arg("tty").arg("--console").arg("off")
            .arg("--cpus").arg(format!("boot={}", spec.vcpus.max(1)))
            .arg("--memory").arg(format!("size={}M", spec.mem_mib.max(256)))
            .stdin(Stdio::null())
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(log2))
            .spawn()
            .map_err(|e| format!("spawn cloud-hypervisor: {e}"))?;
        let pid = child.id();
        let mut vm = VmHandle { child, uds, run_dir: spec.run_dir.clone(), serial_log, monitor: self.id(), pid, cid: 3 };
        wait_for_agent(&mut vm, 40, self)?;
        Ok(vm)
    }
}

impl VmMonitor for FirecrackerMonitor {
    fn id(&self) -> &'static str {
        "firecracker"
    }

    fn start(&self, spec: &VmSpec) -> Result<VmHandle, String> {
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
        let log2 = log.try_clone().map_err(|e| format!("serial log clone: {e}"))?;
        let child = Command::new(&spec.monitor_bin)
            .arg("--no-api").arg("--config-file").arg(&config)
            .stdin(Stdio::null())
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(log2))
            .spawn()
            .map_err(|e| format!("spawn firecracker: {e}"))?;
        let pid = child.id();
        let mut vm = VmHandle { child, uds, run_dir: spec.run_dir.clone(), serial_log, monitor: self.id(), pid, cid: 3 };
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
        // QEMU compat/diagnostic lane — a REAL boot (microvm machine + qboot firmware + the MMIO
        // guest kernel + vhost-vsock-device). Fails CLOSED with a precise reason if the qemu binary
        // is absent or /dev/vhost-vsock is not openable (group kvm) — never a fake boot.
        if Command::new(&spec.monitor_bin).arg("--version").output().map(|o| !o.status.success()).unwrap_or(true) {
            return Err(format!(
                "qemu host-gated: {} not runnable (provision with scripts/phase1/provision-qemu.sh; \
                 cloud-hypervisor + firecracker are the always-available lanes)",
                spec.monitor_bin.display()
            ));
        }
        // vhost-vsock must be openable (root:kvm 0660). The user needs the kvm group / an ACL.
        match std::fs::OpenOptions::new().read(true).write(true).open("/dev/vhost-vsock") {
            Ok(_) => {}
            Err(e) => {
                return Err(format!(
                    "qemu host-gated: /dev/vhost-vsock not openable ({e}) — grant access as root: \
                     `usermod -aG kvm $USER` (re-login) or `setfacl -m u:$USER:rw /dev/vhost-vsock`"
                ));
            }
        }
        // firmware: microvm needs qboot.rom (resolved next to the qemu binary's share/ or via env).
        let fw = std::env::var("IOI_QEMU_FIRMWARE").ok().map(PathBuf::from).or_else(|| {
            spec.monitor_bin.parent().map(|d| d.join("share/qboot.rom")).filter(|p| p.exists())
        });
        let cid = alloc_guest_cid();
        std::fs::create_dir_all(&spec.run_dir).map_err(|e| format!("vm run_dir: {e}"))?;
        let uds = spec.sock_path.clone();
        let serial_log = spec.run_dir.join("serial.log");
        let log = std::fs::File::create(&serial_log).map_err(|e| format!("serial log: {e}"))?;
        let log2 = log.try_clone().map_err(|e| format!("serial log clone: {e}"))?;
        let mut cmd = Command::new(&spec.monitor_bin);
        cmd.arg("-M").arg("microvm,x-option-roms=off,pic=off,rtc=off")
            .arg("-enable-kvm").arg("-cpu").arg("host")
            .arg("-m").arg(format!("{}", spec.mem_mib.max(256)))
            .arg("-smp").arg(format!("{}", spec.vcpus.max(1)));
        if let Some(fw) = &fw {
            cmd.arg("-bios").arg(fw);
        }
        cmd.arg("-kernel").arg(&spec.kernel)
            .arg("-initrd").arg(&spec.initramfs)
            .arg("-append").arg("console=ttyS0 reboot=t panic=-1 rdinit=/init")
            .arg("-device").arg(format!("vhost-vsock-device,guest-cid={cid}"))
            .arg("-nodefaults").arg("-no-reboot").arg("-display").arg("none")
            .arg("-serial").arg(format!("file:{}", serial_log.to_string_lossy()))
            .stdin(Stdio::null())
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(log2));
        let child = cmd.spawn().map_err(|e| format!("spawn qemu: {e}"))?;
        let pid = child.id();
        let mut vm = VmHandle { child, uds, run_dir: spec.run_dir.clone(), serial_log, monitor: self.id(), pid, cid };
        wait_for_agent(&mut vm, 40, self)?;
        Ok(vm)
    }
}

/// tar a host directory into memory (for import). Uses the system tar (busybox-compatible format).
pub(crate) fn tar_dir(dir: &Path) -> Result<Vec<u8>, String> {
    let out = Command::new("tar")
        .arg("-cf").arg("-").arg("-C").arg(dir).arg(".")
        .output()
        .map_err(|e| format!("tar spawn: {e}"))?;
    if !out.status.success() {
        return Err(format!("tar: {}", String::from_utf8_lossy(&out.stderr)));
    }
    Ok(out.stdout)
}

/// Extract a tar (from export) into a host directory.
pub(crate) fn untar_into(dir: &Path, tar: &[u8]) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("mkdir: {e}"))?;
    let mut child = Command::new("tar")
        .arg("-xf").arg("-").arg("-C").arg(dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("tar -x spawn: {e}"))?;
    child.stdin.take().unwrap().write_all(tar).map_err(|e| format!("tar -x write: {e}"))?;
    let status = child.wait().map_err(|e| format!("tar -x wait: {e}"))?;
    if !status.success() {
        return Err("tar -x failed".into());
    }
    Ok(())
}
