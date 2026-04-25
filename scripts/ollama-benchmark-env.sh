#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "${SCRIPT_DIR}/.." && pwd)
BACKEND_START="${REPO_ROOT}/apps/autopilot/src-tauri/dev/local-backends/ollama-openai/start.sh"

EIGHT_GB_CLASS_MAX_MIB=9000

detect_nvidia_total_memory_mib() {
  if [ -n "${AUTOPILOT_LOCAL_GPU_TOTAL_MEMORY_MIB:-}" ]; then
    printf '%s\n' "${AUTOPILOT_LOCAL_GPU_TOTAL_MEMORY_MIB}"
    return 0
  fi
  if ! command -v nvidia-smi >/dev/null 2>&1; then
    return 1
  fi
  nvidia-smi --query-gpu=memory.total --format=csv,noheader,nounits 2>/dev/null \
    | awk 'BEGIN { max = 0 } { value = $1 + 0; if (value > max) max = value } END { if (max > 0) print max }'
}

resolve_hardware_profile() {
  if [ -n "${AUTOPILOT_LOCAL_HARDWARE_PROFILE:-}" ]; then
    printf '%s\n' "${AUTOPILOT_LOCAL_HARDWARE_PROFILE}"
    return 0
  fi
  total_mib=$(detect_nvidia_total_memory_mib || true)
  if [ -n "${total_mib}" ] && [ "${total_mib}" -le "${EIGHT_GB_CLASS_MAX_MIB}" ]; then
    printf '%s\n' "nvidia-vram-8gb-class"
    return 0
  fi
  printf '%s\n' "generic"
}

apply_profile_defaults() {
  profile=$(resolve_hardware_profile)

  export OLLAMA_HOST="${OLLAMA_HOST:-127.0.0.1:11434}"
  export OLLAMA_FLASH_ATTENTION="${OLLAMA_FLASH_ATTENTION:-1}"
  export OLLAMA_KEEP_ALIVE="${OLLAMA_KEEP_ALIVE:-10m}"
  export OLLAMA_MAX_LOADED_MODELS="${OLLAMA_MAX_LOADED_MODELS:-1}"
  export OLLAMA_NUM_PARALLEL="${OLLAMA_NUM_PARALLEL:-1}"

  case "${profile}" in
    nvidia-vram-8gb-class)
      export OLLAMA_CONTEXT_LENGTH="${OLLAMA_CONTEXT_LENGTH:-4096}"
      export OLLAMA_KV_CACHE_TYPE="${OLLAMA_KV_CACHE_TYPE:-q8_0}"
      ;;
    *)
      export OLLAMA_CONTEXT_LENGTH="${OLLAMA_CONTEXT_LENGTH:-8192}"
      if [ -n "${OLLAMA_KV_CACHE_TYPE:-}" ]; then
        export OLLAMA_KV_CACHE_TYPE
      fi
      ;;
  esac
}

print_env() {
  profile=$(resolve_hardware_profile)
  total_mib=$(detect_nvidia_total_memory_mib || true)
  apply_profile_defaults
  printf 'profile=%s\n' "${profile}"
  if [ -n "${total_mib}" ]; then
    printf 'gpu_total_mib=%s\n' "${total_mib}"
  else
    printf 'gpu_total_mib=(unknown)\n'
  fi
  printf 'OLLAMA_HOST=%s\n' "${OLLAMA_HOST}"
  printf 'OLLAMA_CONTEXT_LENGTH=%s\n' "${OLLAMA_CONTEXT_LENGTH}"
  printf 'OLLAMA_MAX_LOADED_MODELS=%s\n' "${OLLAMA_MAX_LOADED_MODELS}"
  printf 'OLLAMA_NUM_PARALLEL=%s\n' "${OLLAMA_NUM_PARALLEL}"
  printf 'OLLAMA_KEEP_ALIVE=%s\n' "${OLLAMA_KEEP_ALIVE}"
  printf 'OLLAMA_FLASH_ATTENTION=%s\n' "${OLLAMA_FLASH_ATTENTION}"
  if [ -n "${OLLAMA_KV_CACHE_TYPE:-}" ]; then
    printf 'OLLAMA_KV_CACHE_TYPE=%s\n' "${OLLAMA_KV_CACHE_TYPE}"
  fi
}

stop_local_ollama() {
  if command -v pkill >/dev/null 2>&1; then
    pkill -u "$(id -u)" -f '(^|/)ollama serve' >/dev/null 2>&1 || true
  fi
}

warm_models() {
  apply_profile_defaults
  if [ "$#" -eq 0 ]; then
    set -- \
      "${OLLAMA_DEFAULT_MODEL:-${AUTOPILOT_LOCAL_RUNTIME_MODEL:-}}" \
      "${OLLAMA_ROUTING_MODEL:-${AUTOPILOT_CHAT_ARTIFACT_ROUTING_RUNTIME_MODEL:-}}" \
      "${OLLAMA_ACCEPTANCE_MODEL:-${AUTOPILOT_ACCEPTANCE_RUNTIME_MODEL:-}}" \
      "${OLLAMA_EMBEDDING_MODEL:-${AUTOPILOT_LOCAL_EMBEDDING_MODEL:-}}"
  fi

  seen=""
  for model in "$@"; do
    if [ -z "${model}" ]; then
      continue
    fi
    case " ${seen} " in
      *" ${model} "*) continue ;;
    esac
    seen="${seen} ${model}"
    curl -fsS "http://${OLLAMA_HOST#http://}/api/generate" \
      -H 'Content-Type: application/json' \
      -d "{\"model\":\"${model}\",\"prompt\":\"Reply with OK.\",\"stream\":false,\"keep_alive\":\"${OLLAMA_KEEP_ALIVE}\",\"options\":{\"num_predict\":1,\"temperature\":0}}"
    printf '\n'
  done
}

usage() {
  cat <<'EOF'
Usage:
  scripts/ollama-benchmark-env.sh print-env
  scripts/ollama-benchmark-env.sh start
  scripts/ollama-benchmark-env.sh start-clean
  scripts/ollama-benchmark-env.sh stop
  scripts/ollama-benchmark-env.sh status
  scripts/ollama-benchmark-env.sh warm [model...]

Environment:
  OLLAMA_HOST
  OLLAMA_CONTEXT_LENGTH
  OLLAMA_MAX_LOADED_MODELS
  OLLAMA_NUM_PARALLEL
  OLLAMA_KEEP_ALIVE
  OLLAMA_FLASH_ATTENTION
  OLLAMA_KV_CACHE_TYPE
  OLLAMA_DEFAULT_MODEL
  OLLAMA_ACCEPTANCE_MODEL
  OLLAMA_EMBEDDING_MODEL
  AUTOPILOT_LOCAL_GPU_TOTAL_MEMORY_MIB
  AUTOPILOT_LOCAL_HARDWARE_PROFILE
EOF
}

command_name="${1:-}"
if [ -z "${command_name}" ]; then
  usage
  exit 2
fi
shift || true

case "${command_name}" in
  print-env)
    print_env
    ;;
  start)
    apply_profile_defaults
    exec "${BACKEND_START}"
    ;;
  start-clean)
    apply_profile_defaults
    stop_local_ollama
    exec "${BACKEND_START}"
    ;;
  stop)
    stop_local_ollama
    ;;
  status)
    apply_profile_defaults
    print_env
    printf '\n'
    curl -fsS "http://${OLLAMA_HOST#http://}/api/tags"
    printf '\n\n'
    ollama ps
    ;;
  warm)
    warm_models "$@"
    ;;
  *)
    usage
    exit 2
    ;;
esac
