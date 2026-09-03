#!/usr/bin/env bash
set -euo pipefail

export LC_ALL=C

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

M10_TAG="aft-pq-v1-review-candidate-2026-09-03"
M10_COMMIT="09aaf34b63c8fa8520c4de014a6d72f6360f7e16"
M10_TAG_OBJECT="3db5f4d08fb5819ab586982f0be60be626ed527b"

M12_TAG="aft-maximal-visibility-lower-bound-candidate-r2-2026-09-03"
M12_COMMIT="225f56992392054251d6337608c4695deb7d00e3"
M12_TAG_OBJECT="8f83ecfec1e9ba15213dea4a94d2d2b6394648dd"

usage() {
  echo "usage: $0 OUTPUT_DIRECTORY" >&2
  echo "OUTPUT_DIRECTORY must be absent or empty." >&2
}

if [[ $# -ne 1 || -z "${1}" ]]; then
  usage
  exit 2
fi

OUTPUT_DIR="$(realpath -m -- "${1}")"

case "${OUTPUT_DIR}" in
  /|"${ROOT_DIR}")
    echo "refusing unsafe output directory: ${OUTPUT_DIR}" >&2
    exit 2
    ;;
esac

if [[ -e "${OUTPUT_DIR}" && ! -d "${OUTPUT_DIR}" ]]; then
  echo "output path exists and is not a directory: ${OUTPUT_DIR}" >&2
  exit 2
fi

if [[ -d "${OUTPUT_DIR}" ]] &&
   [[ -n "$(find "${OUTPUT_DIR}" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
  echo "refusing non-empty output directory: ${OUTPUT_DIR}" >&2
  exit 2
fi

mkdir -p -- "${OUTPUT_DIR}"

verify_annotated_tag() {
  local tag="$1"
  local expected_commit="$2"
  local expected_tag_object="$3"
  local actual_type actual_commit actual_tag_object

  actual_type="$(git -C "${ROOT_DIR}" cat-file -t "refs/tags/${tag}")"
  if [[ "${actual_type}" != "tag" ]]; then
    echo "${tag} is not an annotated tag" >&2
    exit 1
  fi

  actual_commit="$(git -C "${ROOT_DIR}" rev-parse "refs/tags/${tag}^{}")"
  actual_tag_object="$(git -C "${ROOT_DIR}" rev-parse "refs/tags/${tag}^{tag}")"

  if [[ "${actual_commit}" != "${expected_commit}" ]]; then
    echo "${tag} resolves to ${actual_commit}, expected ${expected_commit}" >&2
    exit 1
  fi

  if [[ "${actual_tag_object}" != "${expected_tag_object}" ]]; then
    echo "${tag} object is ${actual_tag_object}, expected ${expected_tag_object}" >&2
    exit 1
  fi
}

verify_annotated_tag "${M10_TAG}" "${M10_COMMIT}" "${M10_TAG_OBJECT}"
verify_annotated_tag "${M12_TAG}" "${M12_COMMIT}" "${M12_TAG_OBJECT}"

M10_BUNDLE="aft-pq-v1-review-candidate-2026-09-03.bundle"
M12_BUNDLE="aft-maximal-visibility-lower-bound-candidate-r2-2026-09-03.bundle"

git -C "${ROOT_DIR}" -c pack.threads=1 bundle create \
  "${OUTPUT_DIR}/${M10_BUNDLE}" "refs/tags/${M10_TAG}"
git -C "${ROOT_DIR}" -c pack.threads=1 bundle create \
  "${OUTPUT_DIR}/${M12_BUNDLE}" "refs/tags/${M12_TAG}"

git -C "${ROOT_DIR}" bundle verify "${OUTPUT_DIR}/${M10_BUNDLE}" >/dev/null
git -C "${ROOT_DIR}" bundle verify "${OUTPUT_DIR}/${M12_BUNDLE}" >/dev/null

VERIFY_ROOT="$(mktemp -d)"
cleanup() {
  if [[ -n "${VERIFY_ROOT:-}" && -d "${VERIFY_ROOT}" &&
        "${VERIFY_ROOT}" == /tmp/* ]]; then
    rm -rf -- "${VERIFY_ROOT}"
  fi
}
trap cleanup EXIT

verify_bundle_checkout() {
  local bundle="$1"
  local tag="$2"
  local expected_commit="$3"
  local expected_tag_object="$4"
  local checkout="$5"
  local actual_commit actual_tag_object

  git clone --quiet --no-checkout "${bundle}" "${checkout}"
  git -C "${checkout}" checkout --quiet --detach "refs/tags/${tag}^{}"

  actual_commit="$(git -C "${checkout}" rev-parse HEAD)"
  actual_tag_object="$(git -C "${checkout}" rev-parse "refs/tags/${tag}^{tag}")"

  if [[ "${actual_commit}" != "${expected_commit}" ||
        "${actual_tag_object}" != "${expected_tag_object}" ]]; then
    echo "bundle checkout mismatch for ${tag}" >&2
    exit 1
  fi
}

verify_bundle_checkout \
  "${OUTPUT_DIR}/${M10_BUNDLE}" "${M10_TAG}" "${M10_COMMIT}" \
  "${M10_TAG_OBJECT}" "${VERIFY_ROOT}/m10"
verify_bundle_checkout \
  "${OUTPUT_DIR}/${M12_BUNDLE}" "${M12_TAG}" "${M12_COMMIT}" \
  "${M12_TAG_OBJECT}" "${VERIFY_ROOT}/m12"

M10_SHA256="$(sha256sum "${OUTPUT_DIR}/${M10_BUNDLE}" | awk '{print $1}')"
M12_SHA256="$(sha256sum "${OUTPUT_DIR}/${M12_BUNDLE}" | awk '{print $1}')"

{
  printf 'format=aft-review-bundle-manifest-v1\n'
  printf 'repository=ioi-foundation/ioi\n'
  printf 'm10.tag=%s\n' "${M10_TAG}"
  printf 'm10.commit=%s\n' "${M10_COMMIT}"
  printf 'm10.tag_object=%s\n' "${M10_TAG_OBJECT}"
  printf 'm10.bundle=%s\n' "${M10_BUNDLE}"
  printf 'm10.bundle_sha256=%s\n' "${M10_SHA256}"
  printf 'm10.packet=internal-docs/architecture/protocols/aft/packets/P4.5a-external-audit.md\n'
  printf 'm12.tag=%s\n' "${M12_TAG}"
  printf 'm12.commit=%s\n' "${M12_COMMIT}"
  printf 'm12.tag_object=%s\n' "${M12_TAG_OBJECT}"
  printf 'm12.bundle=%s\n' "${M12_BUNDLE}"
  printf 'm12.bundle_sha256=%s\n' "${M12_SHA256}"
  printf 'm12.packet=internal-docs/architecture/protocols/aft/packets/M12-maximal-visibility-theorem-review.md\n'
} >"${OUTPUT_DIR}/MANIFEST.txt"

(
  cd "${OUTPUT_DIR}"
  sha256sum "${M10_BUNDLE}" "${M12_BUNDLE}" MANIFEST.txt >SHA256SUMS
  sha256sum --check --strict SHA256SUMS >/dev/null
)

echo "AFT review bundles verified:"
echo "  output: ${OUTPUT_DIR}"
echo "  M10: ${M10_COMMIT} (${M10_TAG_OBJECT})"
echo "  M12: ${M12_COMMIT} (${M12_TAG_OBJECT})"
echo "  checksums: ${OUTPUT_DIR}/SHA256SUMS"
