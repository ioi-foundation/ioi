#!/usr/bin/env sh
set -eu

HOST="${OLLAMA_HOST:-127.0.0.1:11434}"
MODELS_DIR="${AUTOPILOT_LOCAL_MODEL_CACHE_DIR:-${HOME}/.ollama/models}"
DEFAULT_MODEL="${OLLAMA_DEFAULT_MODEL:-${AUTOPILOT_LOCAL_RUNTIME_MODEL:-}}"
ROUTING_MODEL="${OLLAMA_ROUTING_MODEL:-${AUTOPILOT_CHAT_ARTIFACT_ROUTING_RUNTIME_MODEL:-}}"
ACCEPTANCE_MODEL="${OLLAMA_ACCEPTANCE_MODEL:-${AUTOPILOT_ACCEPTANCE_RUNTIME_MODEL:-}}"
EMBEDDING_MODEL="${OLLAMA_EMBEDDING_MODEL:-${AUTOPILOT_LOCAL_EMBEDDING_MODEL:-}}"
PULL_ON_START="${AUTOPILOT_LOCAL_GPU_PULL_MODEL_ON_START:-1}"
MAX_LOADED_MODELS="${OLLAMA_MAX_LOADED_MODELS:-2}"
NUM_PARALLEL="${OLLAMA_NUM_PARALLEL:-}"
KEEP_ALIVE="${OLLAMA_KEEP_ALIVE:-30m}"
FLASH_ATTENTION="${OLLAMA_FLASH_ATTENTION:-1}"
CONTEXT_LENGTH="${OLLAMA_CONTEXT_LENGTH:-8192}"

export PATH="${HOME}/.local/bin:${PATH}"

if command -v ollama >/dev/null 2>&1; then
  OLLAMA_BIN="$(command -v ollama)"
elif [ -x "${HOME}/.local/bin/ollama" ]; then
  OLLAMA_BIN="${HOME}/.local/bin/ollama"
else
  OLLAMA_BIN=""
fi

if [ -z "${OLLAMA_BIN}" ]; then
  printf '%s\n' "Autopilot local GPU preset requires 'ollama' on PATH." >&2
  exit 127
fi

mkdir -p "${MODELS_DIR}"
export OLLAMA_HOST="${HOST}"
export OLLAMA_MODELS="${MODELS_DIR}"
export OLLAMA_MAX_LOADED_MODELS="${MAX_LOADED_MODELS}"
export OLLAMA_KEEP_ALIVE="${KEEP_ALIVE}"
export OLLAMA_FLASH_ATTENTION="${FLASH_ATTENTION}"
export OLLAMA_CONTEXT_LENGTH="${CONTEXT_LENGTH}"
if [ -n "${NUM_PARALLEL}" ]; then
  export OLLAMA_NUM_PARALLEL="${NUM_PARALLEL}"
fi

"${OLLAMA_BIN}" serve &
SERVER_PID=$!

cleanup() {
  kill "${SERVER_PID}" >/dev/null 2>&1 || true
  wait "${SERVER_PID}" >/dev/null 2>&1 || true
}
trap cleanup INT TERM EXIT

ensure_model_ready() {
  model="$1"

  [ -n "${model}" ] || return 0
  if ! ollama_has_model "${model}"; then
    "${OLLAMA_BIN}" pull "${model}" || true
  fi
}

ollama_has_model() {
  model="$1"

  if "${OLLAMA_BIN}" list 2>/dev/null | awk 'NR>1 {print $1}' | grep -Fxq "${model}"; then
    return 0
  fi
  case "${model}" in
    *:*)
      return 1
      ;;
    *)
      "${OLLAMA_BIN}" list 2>/dev/null | awk 'NR>1 {print $1}' | grep -Fxq "${model}:latest"
      ;;
  esac
}

if [ "${PULL_ON_START}" = "1" ] && { [ -n "${DEFAULT_MODEL}" ] || [ -n "${ROUTING_MODEL}" ] || [ -n "${ACCEPTANCE_MODEL}" ] || [ -n "${EMBEDDING_MODEL}" ]; }; then
  ready=0
  for _ in $(seq 1 30); do
    if curl -fsS "http://${HOST}/api/tags" >/dev/null 2>&1; then
      ready=1
      break
    fi
    sleep 1
  done

  if [ "${ready}" = "1" ]; then
    ensure_model_ready "${DEFAULT_MODEL}"
    if [ "${ROUTING_MODEL}" != "${DEFAULT_MODEL}" ]; then
      ensure_model_ready "${ROUTING_MODEL}"
    fi
    if [ "${ACCEPTANCE_MODEL}" != "${DEFAULT_MODEL}" ]; then
      ensure_model_ready "${ACCEPTANCE_MODEL}"
    fi
    if [ "${EMBEDDING_MODEL}" != "${DEFAULT_MODEL}" ]; then
      ensure_model_ready "${EMBEDDING_MODEL}"
    fi
  fi
fi

wait "${SERVER_PID}"
