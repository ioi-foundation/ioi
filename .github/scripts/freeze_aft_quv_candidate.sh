#!/usr/bin/env bash
# Freeze one immutable AFT QUV review/release candidate.
#
# Creates an annotated tag on the exact current HEAD (which must be clean and
# must already carry the retained clean M16Q run directory named below), writes
# a candidate manifest with the resolved tag object, peeled commit, source and
# artifact hashes, and prints the owner-only push commands. It never pushes.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT_DIR}"

usage() {
  echo "usage: $0 --tag <name> --run-dir <retained m16q run dir> --message-file <file> [--manifest-out <path>]" >&2
}

TAG=""
RUN_DIR=""
MESSAGE_FILE=""
MANIFEST_OUT=""
while (($#)); do
  case "$1" in
    --tag) TAG="$2"; shift 2 ;;
    --run-dir) RUN_DIR="$2"; shift 2 ;;
    --message-file) MESSAGE_FILE="$2"; shift 2 ;;
    --manifest-out) MANIFEST_OUT="$2"; shift 2 ;;
    *) usage; exit 2 ;;
  esac
done
[[ -n "${TAG}" && -n "${RUN_DIR}" && -n "${MESSAGE_FILE}" ]] || { usage; exit 2; }

if [[ -n "$(git status --porcelain=v1)" ]]; then
  echo "refusing to freeze: worktree is not clean" >&2
  exit 1
fi
if git rev-parse -q --verify "refs/tags/${TAG}" >/dev/null; then
  echo "refusing to freeze: tag ${TAG} already exists" >&2
  exit 1
fi
[[ -f "${RUN_DIR}/result.txt" && -f "${RUN_DIR}/artifact-sha256.txt" ]] || {
  echo "refusing to freeze: ${RUN_DIR} is not a complete retained run" >&2
  exit 1
}
if ! git ls-files --error-unmatch "${RUN_DIR}/result.txt" >/dev/null 2>&1; then
  echo "refusing to freeze: the retained run is not tracked by git" >&2
  exit 1
fi
COMMIT="$(git rev-parse HEAD)"
RUN_COMMIT="$(sed -n 's/^commit=//p' "${RUN_DIR}/result.txt" | head -1)"
RUN_RESULT="$(sed -n 's/^result=//p' "${RUN_DIR}/result.txt" | head -1)"
RUN_DIRTY="$(sed -n 's/^tree_dirty=//p' "${RUN_DIR}/result.txt" | head -1)"
RUN_QUICK="$(sed -n 's/^quick=//p' "${RUN_DIR}/result.txt" | head -1)"
if [[ "${RUN_RESULT}" != "PASS" || "${RUN_DIRTY}" != "false" || "${RUN_QUICK}" != "false" ]]; then
  echo "refusing to freeze: retained run is not a clean, non-quick PASS" >&2
  exit 1
fi
# The run was necessarily produced on the commit that precedes the commit that
# adds the run directory itself; require that relationship exactly.
if [[ "$(git rev-parse "${COMMIT}^")" != "${RUN_COMMIT}" ]]; then
  echo "refusing to freeze: run commit ${RUN_COMMIT} is not the parent of HEAD ${COMMIT}" >&2
  exit 1
fi
if [[ -n "$(git diff --name-only "${RUN_COMMIT}" "${COMMIT}" | grep -v "^${RUN_DIR#./}" | grep -Ev '^(internal-docs/architecture/protocols/aft/(IMPLEMENTATION_LEDGER\.md|MAXIMAL_CONSENSUS_ACTION_PLAN\.md|packets/|evidence/m16q-quv-qualification-)|docs/decisions/)' || true)" ]]; then
  echo "refusing to freeze: HEAD changes more than the retained run and its ledger/packet records relative to the run commit" >&2
  git diff --name-only "${RUN_COMMIT}" "${COMMIT}" >&2
  exit 1
fi

git tag -a "${TAG}" -F "${MESSAGE_FILE}" "${COMMIT}"
TAG_OBJECT="$(git rev-parse "refs/tags/${TAG}")"
PEELED="$(git rev-parse "refs/tags/${TAG}^{}")"
[[ "${PEELED}" == "${COMMIT}" ]]

MANIFEST_OUT="${MANIFEST_OUT:-${RUN_DIR}/../candidate-${TAG}.manifest.txt}"
{
  echo "schema=ioi.aft.quv.candidate-freeze.v1"
  echo "tag=${TAG}"
  echo "tag_object=${TAG_OBJECT}"
  echo "commit=${COMMIT}"
  echo "run_dir=${RUN_DIR}"
  echo "run_commit=${RUN_COMMIT}"
  echo "frozen_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "rustc=$(rustc --version)"
  echo "cargo=$(cargo --version)"
  echo "--- source-sha256 (from the retained run) ---"
  cat "${RUN_DIR}/source-sha256.txt"
  echo "--- artifact-sha256 (retained run, self-hash excluded) ---"
  sha256sum "${RUN_DIR}/artifact-sha256.txt"
} >"${MANIFEST_OUT}"
echo "frozen ${TAG} -> tag object ${TAG_OBJECT}, commit ${COMMIT}"
echo "manifest: ${MANIFEST_OUT} (untracked; commit it in a follow-up record, it does not alter the candidate)"
echo
echo "Owner-only actions (not performed):"
echo "  git push origin ${COMMIT}:refs/heads/master"
echo "  git push origin refs/tags/${TAG}"
