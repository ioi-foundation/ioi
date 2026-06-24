#!/usr/bin/env bash
# Phase 1 microVM toolchain provisioner (G2 — monitor/image supply chain).
#
# Installs the pinned + checksummed VM toolchain into ~/.ioi/vm-toolchain and emits a
# supply-manifest.json. Every artifact is version-pinned and sha256-verified; a checksum
# mismatch FAILS CLOSED (provision refuses to proceed). Idempotent: re-runs verify and skip.
# Artifacts live outside the repo (.ioi is gitignored); this script + the guest-agent source
# are the committed, reviewable supply-chain definition.
set -euo pipefail

TC="${IOI_VM_TOOLCHAIN_DIR:-$HOME/.ioi/vm-toolchain}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
mkdir -p "$TC"

# ---- pinned versions + checksums (the supply manifest) ----
CH_VERSION="v52.0"
CH_URL="https://github.com/cloud-hypervisor/cloud-hypervisor/releases/download/${CH_VERSION}/cloud-hypervisor-static"
CH_SHA="829af01ff075bb96c4f183905134c453a88d68cbabdc6b87df21098842581ee9"
CHREMOTE_URL="https://github.com/cloud-hypervisor/cloud-hypervisor/releases/download/${CH_VERSION}/ch-remote-static"
CHREMOTE_SHA="d4e8709ed3ef8ba5c66d98770342a2d7c3c96174cfa9c5ae9e3e55de999869a3"
# Debian cloud kernel: PVH-bootable bzImage with VIRTIO_PCI built-in (cloud-hypervisor is
# PCI-only). virtio_blk + the vsock chain are modules — extracted from the same deb and loaded
# by the initramfs /init (version-matched). The Firecracker kernel is MMIO-only → incompatible.
KERNEL_VERSION="6.18.15+deb13-cloud-amd64"
KERNEL_DEB="linux-image-6.18.15+deb13-cloud-amd64-unsigned_6.18.15-1~bpo13+1_amd64.deb"
KERNEL_DEB_URL="https://deb.debian.org/debian/pool/main/l/linux/${KERNEL_DEB}"
KERNEL_DEB_SHA="38e4ed31979895fa43401b01e2a6ec256d3a7ff3850f6408cf638d5df617eb27"
# vsock chain (load order) + virtio_blk — extracted from the deb into the initramfs.
GUEST_MODULES="net/vmw_vsock/vsock net/vmw_vsock/vmw_vsock_virtio_transport_common net/vmw_vsock/vmw_vsock_virtio_transport drivers/block/virtio_blk"

verify() { echo "$2  $1" | sha256sum -c - >/dev/null 2>&1; }

fetch_pinned() {
  local url="$1" out="$2" sha="$3" name="$4"
  if [ -f "$out" ] && verify "$out" "$sha"; then echo "  $name: present + verified"; return 0; fi
  echo "  $name: downloading $url"
  curl -sSL -o "$out" "$url"
  if ! verify "$out" "$sha"; then
    echo "  $name: CHECKSUM MISMATCH (got $(sha256sum "$out" | cut -d' ' -f1), want $sha) — FAIL CLOSED" >&2
    rm -f "$out"; exit 3
  fi
  echo "  $name: downloaded + verified"
}

echo "[1/4] cloud-hypervisor + ch-remote (pinned $CH_VERSION)"
fetch_pinned "$CH_URL" "$TC/cloud-hypervisor" "$CH_SHA" "cloud-hypervisor"
fetch_pinned "$CHREMOTE_URL" "$TC/ch-remote" "$CHREMOTE_SHA" "ch-remote"
chmod +x "$TC/cloud-hypervisor" "$TC/ch-remote"

echo "[2/4] guest kernel + modules (Debian cloud $KERNEL_VERSION, PVH/PCI)"
fetch_pinned "$KERNEL_DEB_URL" "$TC/kernel.deb" "$KERNEL_DEB_SHA" "kernel.deb"
KX="$TC/kernel-extract"
if [ ! -f "$TC/guest-kernel.bin" ] || [ ! -d "$TC/guest-modules" ]; then
  rm -rf "$KX"; mkdir -p "$KX"
  ( cd "$KX" && ar x "$TC/kernel.deb" )
  DATA=$(ls "$KX"/data.tar.* | head -1)
  tar -xf "$DATA" -C "$KX"
  cp "$KX/boot/vmlinuz-$KERNEL_VERSION" "$TC/guest-kernel.bin"
  MD="$KX/usr/lib/modules/$KERNEL_VERSION"
  rm -rf "$TC/guest-modules"; mkdir -p "$TC/guest-modules"
  for m in $GUEST_MODULES; do
    xz -dc "$MD/kernel/$m.ko.xz" > "$TC/guest-modules/$(basename "$m").ko"
  done
  rm -rf "$KX"
  echo "  guest-kernel: extracted ($(du -h "$TC/guest-kernel.bin" | cut -f1)); $(ls "$TC/guest-modules" | wc -l) modules"
else
  echo "  guest-kernel + modules: present"
fi
KERNEL_SHA="$(sha256sum "$TC/guest-kernel.bin" | cut -d' ' -f1)"

echo "[3/4] guest agent (static, from scripts/phase1/guest-agent.c)"
if ! command -v gcc >/dev/null; then echo "  gcc required to build the guest agent" >&2; exit 4; fi
gcc -static -O2 -s -o "$TC/guest-agent" "$HERE/guest-agent.c"
AGENT_SHA="$(sha256sum "$TC/guest-agent" | cut -d' ' -f1)"
AGENT_SRC_SHA="$(sha256sum "$HERE/guest-agent.c" | cut -d' ' -f1)"
echo "  guest-agent: built (sha256 $AGENT_SHA)"

echo "[4/4] initramfs (static busybox + guest-agent as /init)"
BUSYBOX="${IOI_BUSYBOX:-/usr/bin/busybox}"
if [ ! -x "$BUSYBOX" ] || ! file "$BUSYBOX" 2>/dev/null | grep -q "statically linked"; then
  echo "  need a static busybox at $BUSYBOX (set IOI_BUSYBOX)" >&2; exit 5
fi
BUSYBOX_SHA="$(sha256sum "$BUSYBOX" | cut -d' ' -f1)"
RD="$TC/initramfs-build"; rm -rf "$RD"; mkdir -p "$RD/bin" "$RD/modules" "$RD/proc" "$RD/sys" "$RD/dev" "$RD/workspace"
cp "$BUSYBOX" "$RD/bin/busybox"
cp "$TC/guest-agent" "$RD/guest-agent"; chmod +x "$RD/guest-agent"
cp "$TC"/guest-modules/*.ko "$RD/modules/"
# /init: mount pseudo-fs, insmod the vsock chain + virtio_blk (load order), exec the agent.
cat > "$RD/init" <<'INIT'
#!/bin/busybox sh
/bin/busybox mount -t proc proc /proc
/bin/busybox mount -t sysfs sys /sys
/bin/busybox mount -t devtmpfs dev /dev
for m in vsock vmw_vsock_virtio_transport_common vmw_vsock_virtio_transport virtio_blk; do
  /bin/busybox insmod /modules/$m.ko 2>/dev/null
done
exec /guest-agent
INIT
chmod +x "$RD/init"
( cd "$RD" && find . | cpio -o -H newc 2>/dev/null | gzip -9 > "$TC/initramfs.cpio.gz" )
INITRAMFS_SHA="$(sha256sum "$TC/initramfs.cpio.gz" | cut -d' ' -f1)"
rm -rf "$RD"
echo "  initramfs: built ($(du -h "$TC/initramfs.cpio.gz" | cut -f1), sha256 $INITRAMFS_SHA)"

cat > "$TC/supply-manifest.json" <<EOF
{
  "schema_version": "ioi.hypervisor.vm-supply-manifest.v1",
  "monitor": { "name": "cloud-hypervisor", "version": "$CH_VERSION", "sha256": "$CH_SHA", "path": "$TC/cloud-hypervisor" },
  "ch_remote": { "version": "$CH_VERSION", "sha256": "$CHREMOTE_SHA", "path": "$TC/ch-remote" },
  "kernel": { "version": "$KERNEL_VERSION", "sha256": "$KERNEL_SHA", "path": "$TC/guest-kernel.bin" },
  "guest_agent": { "source_sha256": "$AGENT_SRC_SHA", "binary_sha256": "$AGENT_SHA", "path": "$TC/guest-agent" },
  "busybox": { "sha256": "$BUSYBOX_SHA", "path": "$BUSYBOX" },
  "initramfs": { "sha256": "$INITRAMFS_SHA", "path": "$TC/initramfs.cpio.gz" }
}
EOF
echo "supply manifest -> $TC/supply-manifest.json"
echo "OK: VM toolchain provisioned + verified."
