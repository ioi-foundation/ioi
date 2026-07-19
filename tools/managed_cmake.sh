#!/usr/bin/env sh
set -eu

VERSION="4.2.3"
ASSET_BASE="cmake-${VERSION}"
SHA_MANIFEST_URL="https://github.com/Kitware/CMake/releases/download/v${VERSION}/cmake-${VERSION}-SHA-256.txt"

OS_NAME=$(uname -s)
ARCH_NAME=$(uname -m)

case "${OS_NAME}:${ARCH_NAME}" in
  Linux:x86_64|Linux:amd64)
    ASSET_NAME="${ASSET_BASE}-linux-x86_64.tar.gz"
    ;;
  Linux:aarch64|Linux:arm64)
    ASSET_NAME="${ASSET_BASE}-linux-aarch64.tar.gz"
    ;;
  Darwin:x86_64|Darwin:arm64)
    ASSET_NAME="${ASSET_BASE}-macos-universal.tar.gz"
    ;;
  *)
    echo "managed_cmake: unsupported host ${OS_NAME}/${ARCH_NAME}" >&2
    exit 1
    ;;
esac

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

if [ -n "${IOI_MANAGED_BUILD_TOOL_HOME:-}" ]; then
  CACHE_ROOT="${IOI_MANAGED_BUILD_TOOL_HOME}"
elif [ -n "${XDG_CACHE_HOME:-}" ]; then
  CACHE_ROOT="${XDG_CACHE_HOME}/ioi/build_tools"
elif [ -n "${HOME:-}" ]; then
  CACHE_ROOT="${HOME}/.cache/ioi/build_tools"
else
  CACHE_ROOT="${SCRIPT_DIR}/../target/ioi-build-tools"
fi

PYTHON_BIN="${PYTHON3:-python3}"
if ! command -v "${PYTHON_BIN}" >/dev/null 2>&1; then
  echo "managed_cmake: python3 is required to provision the pinned CMake toolchain" >&2
  exit 1
fi

TOOL_ROOT="${CACHE_ROOT}/cmake/${VERSION}"
MANIFEST_PATH="${TOOL_ROOT}/cmake-bin-path.txt"

"${PYTHON_BIN}" - "$TOOL_ROOT" "$ASSET_NAME" "$SHA_MANIFEST_URL" "$MANIFEST_PATH" <<'PY'
import hashlib
import io
import os
import shutil
import sys
import tarfile
import tempfile
import urllib.request

tool_root, asset_name, sha_manifest_url, manifest_path = sys.argv[1:5]
asset_url = f"https://github.com/Kitware/CMake/releases/download/v4.2.3/{asset_name}"
asset_path = os.path.join(tool_root, asset_name)


def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def read_manifest() -> str | None:
    if not os.path.isfile(manifest_path):
        return None
    with open(manifest_path, "r", encoding="utf-8") as handle:
        path = handle.read().strip()
    if path and os.path.isfile(path) and os.access(path, os.X_OK):
        return path
    return None


def download_text(url: str) -> str:
    with urllib.request.urlopen(url, timeout=60) as response:
        return response.read().decode("utf-8")


def download_bytes(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=300) as response:
        return response.read()


def expected_sha256(manifest_text: str, wanted_name: str) -> str:
    for line in manifest_text.splitlines():
        parts = line.strip().split()
        if len(parts) >= 2 and parts[1] == wanted_name:
            value = parts[0].lower()
            if len(value) == 64 and all(ch in "0123456789abcdef" for ch in value):
                return value
    raise SystemExit(
        f"managed_cmake: sha256 manifest did not contain an entry for {wanted_name}"
    )


def sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def locate_cmake_binary(root: str) -> str:
    for current_root, _, files in os.walk(root):
        if "cmake" in files:
            candidate = os.path.join(current_root, "cmake")
            if candidate.endswith(os.path.join("bin", "cmake")) and os.access(candidate, os.X_OK):
                return candidate
    raise SystemExit(f"managed_cmake: extracted archive did not contain a usable cmake binary under {root}")


existing = read_manifest()
if existing is not None:
    raise SystemExit(0)

ensure_dir(tool_root)
manifest_text = download_text(sha_manifest_url)
expected = expected_sha256(manifest_text, asset_name)
needs_download = True
if os.path.isfile(asset_path):
    needs_download = sha256_file(asset_path) != expected

if needs_download:
    fd, temp_path = tempfile.mkstemp(prefix=f"{asset_name}.", suffix=".download", dir=tool_root)
    os.close(fd)
    try:
        payload = download_bytes(asset_url)
        observed = hashlib.sha256(payload).hexdigest()
        if observed != expected:
            raise SystemExit(
                f"managed_cmake: checksum mismatch for {asset_name}: expected {expected}, observed {observed}"
            )
        with open(temp_path, "wb") as handle:
            handle.write(payload)
        os.replace(temp_path, asset_path)
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)

extract_root = os.path.join(tool_root, "extracted")
if os.path.isdir(extract_root):
    shutil.rmtree(extract_root)
ensure_dir(extract_root)

with tarfile.open(asset_path, "r:gz") as archive:
    archive.extractall(extract_root)

binary_path = locate_cmake_binary(extract_root)
with open(manifest_path, "w", encoding="utf-8") as handle:
    handle.write(binary_path)
PY

if [ ! -s "${MANIFEST_PATH}" ]; then
  echo "managed_cmake: provisioning manifest missing at ${MANIFEST_PATH}" >&2
  exit 1
fi

CMAKE_BIN=$(cat "${MANIFEST_PATH}")
exec "${CMAKE_BIN}" "$@"
