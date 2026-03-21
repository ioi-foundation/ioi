#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
JAR_PATH="${ROOT_DIR}/.artifacts/tla/tla2tools.jar"
JAR_URL="https://github.com/tlaplus/tlaplus/releases/download/v1.8.0/tla2tools.jar"
TLAPS_DIR="${ROOT_DIR}/.artifacts/tlaps-pre"
TLAPS_INSTALL_DIR="${TLAPS_DIR}/install"
TLAPS_ARCHIVE="${TLAPS_DIR}/tlapm.tar.gz"
TLAPM_BIN="${TLAPS_INSTALL_DIR}/bin/tlapm"
TLAPS_STDLIB="${TLAPS_INSTALL_DIR}/lib/tlapm/stdlib/TLAPS.tla"

platform() {
  local os arch

  os="$(uname -s)"
  arch="$(uname -m)"

  case "${os}:${arch}" in
    Linux:x86_64)
      echo "x86_64-linux-gnu"
      ;;
    Darwin:arm64)
      echo "arm64-darwin"
      ;;
    *)
      echo "unsupported:${os}:${arch}"
      return 1
      ;;
  esac
}

TLAPS_PLATFORM="$(platform)"
TLAPS_URL="https://github.com/tlaplus/tlapm/releases/download/1.6.0-pre/tlapm-1.6.0-pre-${TLAPS_PLATFORM}.tar.gz"

mkdir -p "$(dirname "${JAR_PATH}")"
mkdir -p "${TLAPS_DIR}"

if [[ ! -f "${JAR_PATH}" ]]; then
  curl -L --fail --retry 3 -o "${JAR_PATH}" "${JAR_URL}"
fi

if [[ ! -x "${TLAPM_BIN}" ]]; then
  rm -rf "${TLAPS_INSTALL_DIR}"
  mkdir -p "${TLAPS_INSTALL_DIR}"
  if [[ ! -f "${TLAPS_ARCHIVE}" ]]; then
    curl -L --fail --retry 3 -o "${TLAPS_ARCHIVE}" "${TLAPS_URL}"
  fi
  tar -xzf "${TLAPS_ARCHIVE}" -C "${TLAPS_INSTALL_DIR}" --strip-components=1
fi

run_proof() {
  local model_dir="$1"
  local tla_file="$2"

  pushd "${ROOT_DIR}/${model_dir}" >/dev/null
  ln -sf "${TLAPS_STDLIB}" TLAPS.tla
  "${TLAPM_BIN}" --cleanfp "${tla_file}"
  popd >/dev/null
}

run_model() {
  local model_dir="$1"
  local config_file="$2"
  local tla_file="$3"

  pushd "${ROOT_DIR}/${model_dir}" >/dev/null
  ln -sf "${TLAPS_STDLIB}" TLAPS.tla
  java -cp "${JAR_PATH}" tlc2.TLC -cleanup -deadlock -config "${config_file}" "${tla_file}"
  popd >/dev/null
}

run_proof "formal/aft/guardian_majority" "GuardianMajorityProof.tla"
run_proof "formal/aft/nested_guardian" "NestedGuardianProof.tla"
run_proof "formal/aft" "AsymptoteProof.tla"
run_proof "formal/aft/canonical_ordering" "CanonicalOrderingProof.tla"
run_model "formal/aft/guardian_majority" "GuardianMajority.cfg" "GuardianMajority.tla"
run_model "formal/aft/nested_guardian" "NestedGuardian.cfg" "NestedGuardian.tla"
run_model "formal/aft" "Asymptote.cfg" "Asymptote.tla"
run_model "formal/aft/canonical_ordering" "CanonicalOrdering.cfg" "CanonicalOrdering.tla"
run_model "formal/aft/canonical_ordering" "CanonicalOrderingRetrievability.cfg" "CanonicalOrderingRetrievability.tla"
run_model "formal/aft/canonical_ordering" "CanonicalCollapseRecursiveContinuity.cfg" "CanonicalCollapseRecursiveContinuity.tla"
