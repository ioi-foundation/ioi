#!/usr/bin/env bash
# T2 — assemble a runnable, relocatable QEMU (system-x86_64) for the QEMU monitor lane.
#
# QEMU is the compat/diagnostic monitor. Unlike cloud-hypervisor/Firecracker (userspace vsock over
# a UDS), QEMU uses the KERNEL vhost-vsock device, so it needs /dev/vhost-vsock to be openable
# (group kvm). This script provisions the qemu binary + its runtime libs + the microvm firmware
# (qboot.rom) into $DEST/qemu and writes a wrapper that sets LD_LIBRARY_PATH and -L. It does NOT
# pin into the main supply-manifest (apt mirror URLs rotate); it is a best-effort host lane. The
# daemon resolves it via $DEST/qemu/qemu-system-x86_64, IOI_QEMU_BIN, or PATH, and fails CLOSED
# with a precise reason if qemu or /dev/vhost-vsock access is absent (never a fake boot).
set -euo pipefail
DEST="${IOI_VM_TOOLCHAIN_DIR:-$HOME/.ioi/vm-toolchain}"
[ "${1:-}" = "--dest" ] && DEST="$2"
Q="$DEST/qemu"
mkdir -p "$Q/lib" "$Q/share"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

# qemu + its firmware (data) + the runtime libs missing from a typical host (noble t64 names).
PKGS="qemu-system-x86 qemu-system-data libfdt1 libpmem1 libslirp0 liburing2 librdmacm1t64 libibverbs1 libndctl6 libdaxctl1"
echo "[qemu] downloading packages (apt-get download, no sudo)"
( cd "$WORK" && for p in $PKGS; do apt-get download "$p" >/dev/null 2>&1 || echo "  warn: $p not downloaded"; done )
echo "[qemu] extracting"
for d in "$WORK"/*.deb; do ( cd "$WORK" && mkdir -p ex && cd ex && ar x "$d" && tar -xf data.tar.* 2>/dev/null ); done
EX="$WORK/ex"
# binary
QBIN_SRC="$(find "$EX" -name qemu-system-x86_64 -type f | head -1)"
[ -n "$QBIN_SRC" ] || { echo "[qemu] qemu-system-x86_64 not found in packages" >&2; exit 4; }
cp "$QBIN_SRC" "$Q/qemu-system-x86_64.real"
# runtime libs (only the ones not already on the host get used via LD_LIBRARY_PATH)
find "$EX" -name '*.so*' -exec cp -a {} "$Q/lib/" \; 2>/dev/null || true
# firmware (qboot.rom, pvh.bin, vgabios, option roms)
QSHARE_SRC="$(find "$EX" -type d -name qemu -path '*share*' | head -1)"
[ -n "$QSHARE_SRC" ] && cp -a "$QSHARE_SRC/." "$Q/share/" 2>/dev/null || true

# wrapper: relocatable launcher that sets the lib path + firmware search path.
cat > "$Q/qemu-system-x86_64" <<EOF
#!/usr/bin/env bash
DIR="\$(cd "\$(dirname "\${BASH_SOURCE[0]}")" && pwd)"
exec env LD_LIBRARY_PATH="\$DIR/lib:\${LD_LIBRARY_PATH:-}" "\$DIR/qemu-system-x86_64.real" -L "\$DIR/share" "\$@"
EOF
chmod +x "$Q/qemu-system-x86_64" "$Q/qemu-system-x86_64.real"

VER="$("$Q/qemu-system-x86_64" --version 2>&1 | head -1 || echo "unknown")"
echo "[qemu] installed: $VER"
echo "[qemu] firmware: $(ls "$Q/share"/qboot.rom 2>/dev/null && echo qboot.rom || echo MISSING-qboot)"
echo "[qemu] vhost-vsock openable: $([ -r /dev/vhost-vsock ] && [ -w /dev/vhost-vsock ] && echo yes || echo 'NO (host-gated: user not in kvm group — root: usermod -aG kvm or setfacl -m u:$USER:rw /dev/vhost-vsock)')"
echo "OK: qemu lane provisioned at $Q/qemu-system-x86_64"
