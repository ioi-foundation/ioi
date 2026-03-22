#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RUNNER="${ROOT_DIR}/ops/aft/run_release_benchmark_binary.sh"

if [[ ! -x "${RUNNER}" ]]; then
  echo "missing executable runner: ${RUNNER}" >&2
  exit 1
fi

timestamp="$(date +%s)"
unit_name="${IOI_AFT_BENCH_UNIT_NAME:-ioi-aft-direct-${timestamp}}"
log_file="${IOI_AFT_BENCH_LOG_FILE:-/tmp/${unit_name}.log}"
cpuset="${IOI_AFT_BENCH_CPUSET:-}"

forwarded_env_names=()
command="cd $(printf '%q' "${ROOT_DIR}") &&"
while IFS='=' read -r name value; do
  if [[ "${name}" == IOI_* ]]; then
    printf -v assignment '%q=%q' "${name}" "${value}"
    command+=" export ${assignment};"
    forwarded_env_names+=("${name}")
  fi
done < <(env)
if [[ -n "${cpuset}" ]]; then
  command+=" exec taskset -c $(printf '%q' "${cpuset}") $(printf '%q' "${RUNNER}")"
else
  command+=" exec $(printf '%q' "${RUNNER}")"
fi
for arg in "$@"; do
  command+=" $(printf '%q' "${arg}")"
done
command+=" > $(printf '%q' "${log_file}") 2>&1"

echo "unit: ${unit_name}"
echo "log: ${log_file}"
if [[ -n "${cpuset}" ]]; then
  echo "cpuset: ${cpuset}"
fi
if (( ${#forwarded_env_names[@]} > 0 )); then
  echo "forwarded_env: ${forwarded_env_names[*]}"
fi

exec systemd-run \
  --user \
  --collect \
  --same-dir \
  --wait \
  --unit="${unit_name}" \
  bash -lc "${command}"
