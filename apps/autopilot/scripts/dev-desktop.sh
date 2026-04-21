#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
MODE="${1:-x11}"
if [[ $# -gt 0 ]]; then
  shift
fi
EXTRA_TAURI_ARGS=("$@")

default_local_gpu_dev_artifact_specialist_model() {
  local runtime_model="${1:-}"
  if [[ -n "$runtime_model" ]]; then
    printf '%s\n' "$runtime_model"
  else
    printf '%s\n' "qwen3.5:9b"
  fi
}

REQUESTED_DEV_URL="${DEV_URL:-http://127.0.0.1:1428}"
AUTO_START_DEV_SERVER="${AUTO_START_DEV_SERVER:-1}"
TAURI_WATCH="${AUTOPILOT_TAURI_WATCH:-0}"
REUSE_DEV_SERVER="${AUTOPILOT_REUSE_DEV_SERVER:-1}"
DEV_CLEAN_INSTANCE="${AUTOPILOT_DEV_CLEAN_INSTANCE:-0}"
LOCAL_GPU_DEV="${AUTOPILOT_LOCAL_GPU_DEV:-0}"
LOCAL_KERNEL_AUTOSTART="${AUTOPILOT_LOCAL_KERNEL_AUTOSTART:-$LOCAL_GPU_DEV}"
LOCAL_KERNEL_STACK_SIZE_BYTES="${IOI_LOCAL_TOKIO_STACK_SIZE_BYTES:-33554432}"

if [[ "$DEV_CLEAN_INSTANCE" == "1" ]]; then
  export AUTOPILOT_DATA_PROFILE="${AUTOPILOT_DATA_PROFILE:-desktop-clean}"
  export AUTOPILOT_RESET_DATA_ON_BOOT="${AUTOPILOT_RESET_DATA_ON_BOOT:-1}"
fi

if [[ "$LOCAL_GPU_DEV" == "1" ]]; then
  export AUTOPILOT_LOCAL_GPU_DEV=1
  # Local GPU desktop profiles encrypt the kernel identity with a fixed local
  # passphrase on first boot. Re-export it on subsequent boots so retained
  # profiles can restart non-interactively.
  export IOI_GUARDIAN_KEY_PASS="${IOI_GUARDIAN_KEY_PASS:-local-mode}"
  export IOI_STUDIO_PROOF_TRACE="${IOI_STUDIO_PROOF_TRACE:-1}"
  export AUTOPILOT_DATA_PROFILE="${AUTOPILOT_DATA_PROFILE:-desktop-localgpu}"
  export AUTOPILOT_RESET_DATA_ON_BOOT="${AUTOPILOT_RESET_DATA_ON_BOOT:-1}"
  export AUTOPILOT_CONNECTOR_WALLET_BOOTSTRAP="${AUTOPILOT_CONNECTOR_WALLET_BOOTSTRAP:-0}"
  export IOI_WORKLOAD_GRPC_TIMEOUT_MS="${IOI_WORKLOAD_GRPC_TIMEOUT_MS:-15000}"
  export AUTOPILOT_INFERENCE_HTTP_TIMEOUT_SECS="${AUTOPILOT_INFERENCE_HTTP_TIMEOUT_SECS:-600}"
  # Keep local-dev desktop_agent traffic on the direct mempool admission path by default.
  # The ingestion firewall path is stronger, but it is not yet stable enough to be the
  # default bootstrap route for interactive Studio sessions.
  export IOI_RPC_FAST_ADMIT_MAX_MEMPOOL="${IOI_RPC_FAST_ADMIT_MAX_MEMPOOL:-512}"
  export AUTOPILOT_LOCAL_DEV_PRESET="${AUTOPILOT_LOCAL_DEV_PRESET:-ollama-openai}"
  export AUTOPILOT_LOCAL_RUNTIME_URL="${AUTOPILOT_LOCAL_RUNTIME_URL:-http://127.0.0.1:11434/v1/chat/completions}"
  # Keep the default local desktop lane on one warmed model so Studio routing,
  # drafting, and acceptance avoid cross-model residency churn.
  export AUTOPILOT_LOCAL_RUNTIME_MODEL="${AUTOPILOT_LOCAL_RUNTIME_MODEL:-qwen3.5:9b}"
  export AUTOPILOT_LOCAL_RUNTIME_HEALTH_URL="${AUTOPILOT_LOCAL_RUNTIME_HEALTH_URL:-http://127.0.0.1:11434/api/tags}"
  # Local Studio HTML materialization can legitimately need longer than the
  # default capped local timeout, especially on retained follow-up edits where
  # the prompt carries forward artifact context and repair evidence.
  export AUTOPILOT_STUDIO_MATERIALIZATION_TIMEOUT_MS="${AUTOPILOT_STUDIO_MATERIALIZATION_TIMEOUT_MS:-300000}"
  export AUTOPILOT_STUDIO_MATERIALIZATION_FOLLOWUP_TIMEOUT_MS="${AUTOPILOT_STUDIO_MATERIALIZATION_FOLLOWUP_TIMEOUT_MS:-360000}"
  # Direct-author HTML continuations can stream a large partial document and
  # then need extra local inference time to finish the suffix cleanly.
  export AUTOPILOT_STUDIO_DIRECT_AUTHOR_FOLLOWUP_TIMEOUT_MS="${AUTOPILOT_STUDIO_DIRECT_AUTHOR_FOLLOWUP_TIMEOUT_MS:-180000}"
  export AUTOPILOT_STUDIO_ROUTING_RUNTIME_URL="${AUTOPILOT_STUDIO_ROUTING_RUNTIME_URL:-$AUTOPILOT_LOCAL_RUNTIME_URL}"
  export AUTOPILOT_STUDIO_ROUTING_RUNTIME_MODEL="${AUTOPILOT_STUDIO_ROUTING_RUNTIME_MODEL:-$AUTOPILOT_LOCAL_RUNTIME_MODEL}"
  export AUTOPILOT_STUDIO_ROUTING_RUNTIME_HEALTH_URL="${AUTOPILOT_STUDIO_ROUTING_RUNTIME_HEALTH_URL:-$AUTOPILOT_LOCAL_RUNTIME_HEALTH_URL}"
  export AUTOPILOT_ACCEPTANCE_RUNTIME_URL="${AUTOPILOT_ACCEPTANCE_RUNTIME_URL:-$AUTOPILOT_LOCAL_RUNTIME_URL}"
  export AUTOPILOT_ACCEPTANCE_RUNTIME_MODEL="${AUTOPILOT_ACCEPTANCE_RUNTIME_MODEL:-$(default_local_gpu_dev_artifact_specialist_model "${AUTOPILOT_LOCAL_RUNTIME_MODEL:-}")}"
  # Prefer a single local model by default for Studio HTML work. If callers
  # explicitly configure a different acceptance runtime, preserve it.
  if [[ -z "${AUTOPILOT_STUDIO_MODEL_ROUTING_PROFILE:-}" ]]; then
    if [[ "${AUTOPILOT_ACCEPTANCE_RUNTIME_MODEL:-}" != "${AUTOPILOT_LOCAL_RUNTIME_MODEL:-}" ]] \
      || [[ "${AUTOPILOT_ACCEPTANCE_RUNTIME_URL:-}" != "${AUTOPILOT_LOCAL_RUNTIME_URL:-}" ]]; then
      export AUTOPILOT_STUDIO_MODEL_ROUTING_PROFILE="local_generation_remote_acceptance"
    else
      export AUTOPILOT_STUDIO_MODEL_ROUTING_PROFILE="fully_local"
    fi
  fi
  export AUTOPILOT_LOCAL_EMBEDDING_MODEL="${AUTOPILOT_LOCAL_EMBEDDING_MODEL:-nomic-embed-text}"
  export AUTOPILOT_LOCAL_MODEL_CACHE_DIR="${AUTOPILOT_LOCAL_MODEL_CACHE_DIR:-$HOME/.ollama/models}"
  export OLLAMA_MAX_LOADED_MODELS="${OLLAMA_MAX_LOADED_MODELS:-1}"
  export OLLAMA_NUM_PARALLEL="${OLLAMA_NUM_PARALLEL:-1}"
  export OLLAMA_KEEP_ALIVE="${OLLAMA_KEEP_ALIVE:-10m}"
  export OLLAMA_FLASH_ATTENTION="${OLLAMA_FLASH_ATTENTION:-1}"
  export OLLAMA_CONTEXT_LENGTH="${OLLAMA_CONTEXT_LENGTH:-4096}"
  export AUTOPILOT_LOCAL_BACKEND_AUTOSTART="${AUTOPILOT_LOCAL_BACKEND_AUTOSTART:-1}"
  export LOCAL_LLM_URL="${LOCAL_LLM_URL:-$AUTOPILOT_LOCAL_RUNTIME_URL}"
  export LOCAL_LLM_MODEL="${LOCAL_LLM_MODEL:-$AUTOPILOT_LOCAL_RUNTIME_MODEL}"
  export LOCAL_LLM_EMBEDDING_MODEL="${LOCAL_LLM_EMBEDDING_MODEL:-$AUTOPILOT_LOCAL_EMBEDDING_MODEL}"
  if [[ -n "${AUTOPILOT_LOCAL_RUNTIME_MODEL:-}" && -z "${OPENAI_MODEL:-}" ]]; then
    export OPENAI_MODEL="$AUTOPILOT_LOCAL_RUNTIME_MODEL"
  fi
  if [[ -n "${AUTOPILOT_LOCAL_EMBEDDING_MODEL:-}" && -z "${OPENAI_EMBEDDING_MODEL:-}" ]]; then
    export OPENAI_EMBEDDING_MODEL="$AUTOPILOT_LOCAL_EMBEDDING_MODEL"
  fi
  if command -v ollama >/dev/null 2>&1 || [[ -x "${HOME}/.local/bin/ollama" ]]; then
    ollama_status="ollama available"
  else
    ollama_status="ollama missing; Studio will surface inference_unavailable until a local runtime is installed or configured"
  fi
  echo "Autopilot local GPU dev profile: ${AUTOPILOT_DATA_PROFILE} (reset_on_boot=${AUTOPILOT_RESET_DATA_ON_BOOT}, preset=${AUTOPILOT_LOCAL_DEV_PRESET}, model=${AUTOPILOT_LOCAL_RUNTIME_MODEL}, routing_model=${AUTOPILOT_STUDIO_ROUTING_RUNTIME_MODEL}, routing_profile=${AUTOPILOT_STUDIO_MODEL_ROUTING_PROFILE}, acceptance_model=${AUTOPILOT_ACCEPTANCE_RUNTIME_MODEL}, embeddings=${AUTOPILOT_LOCAL_EMBEDDING_MODEL}, http_timeout_secs=${AUTOPILOT_INFERENCE_HTTP_TIMEOUT_SECS}, max_loaded_models=${OLLAMA_MAX_LOADED_MODELS}, num_parallel=${OLLAMA_NUM_PARALLEL}, keep_alive=${OLLAMA_KEEP_ALIVE}, flash_attention=${OLLAMA_FLASH_ATTENTION}, context_length=${OLLAMA_CONTEXT_LENGTH}, proof_trace=${IOI_STUDIO_PROOF_TRACE})"
  echo "Local GPU dev cache: ${AUTOPILOT_LOCAL_MODEL_CACHE_DIR} (${ollama_status})"
fi

DEV_URL="$REQUESTED_DEV_URL"
TAURI_CONFIG=""
KERNEL_RPC_URL=""
KERNEL_DATA_DIR=""
PROFILE_DIR=""
kernel_pid=""
kernel_log=""
kernel_build_log=""
backend_pid=""
backend_log=""

if [[ "$MODE" == "x11" ]]; then
  mode_prefix=(env -u WAYLAND_DISPLAY XDG_SESSION_TYPE=x11 GDK_BACKEND=x11 WINIT_UNIX_BACKEND=x11)
elif [[ "$MODE" == "wayland" ]]; then
  mode_prefix=(env)
else
  echo "Unknown mode '$MODE' (expected: x11|wayland)"
  exit 1
fi

dev_server_pid=""
cleanup() {
  if [[ -n "$backend_pid" ]] && kill -0 "$backend_pid" >/dev/null 2>&1; then
    kill "$backend_pid" >/dev/null 2>&1 || true
    wait "$backend_pid" >/dev/null 2>&1 || true
  fi
  if [[ -n "$kernel_pid" ]] && kill -0 "$kernel_pid" >/dev/null 2>&1; then
    kill "$kernel_pid" >/dev/null 2>&1 || true
    wait "$kernel_pid" >/dev/null 2>&1 || true
  fi
  if [[ -n "$dev_server_pid" ]] && kill -0 "$dev_server_pid" >/dev/null 2>&1; then
    kill "$dev_server_pid" >/dev/null 2>&1 || true
    wait "$dev_server_pid" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

dev_server_ready() {
  local url="$1"
  curl -fsS "$url" >/dev/null 2>&1
}

monaco_assets_ready() {
  local url="$1"
  local headers=""
  headers="$(curl -fsSI "${url}/monaco/vs/loader.js" 2>/dev/null || true)"
  [[ "$headers" =~ Content-Type:\ (application|text)/(javascript|x-javascript) ]]
}

local_runtime_ready() {
  local url="${AUTOPILOT_LOCAL_RUNTIME_HEALTH_URL:-}"
  [[ -n "$url" ]] || return 1
  curl -fsS "$url" >/dev/null 2>&1
}

local_runtime_model_available() {
  local url="${AUTOPILOT_LOCAL_RUNTIME_HEALTH_URL:-}"
  local model="$1"
  local body=""

  [[ -n "$url" ]] || return 1
  body="$(curl -fsS "$url" 2>/dev/null || true)"
  [[ -n "$body" ]] || return 1

  if [[ -z "$model" || "${AUTOPILOT_LOCAL_DEV_PRESET:-}" != "ollama-openai" ]]; then
    return 0
  fi

  grep -Fq "\"name\":\"${model}\"" <<<"$body" \
    || grep -Fq "\"model\":\"${model}\"" <<<"$body" \
    || { [[ "$model" != *:* ]] && grep -Fq "\"name\":\"${model}:latest\"" <<<"$body"; } \
    || { [[ "$model" != *:* ]] && grep -Fq "\"model\":\"${model}:latest\"" <<<"$body"; }
}

local_runtime_model_ready() {
  local runtime_model="${AUTOPILOT_LOCAL_RUNTIME_MODEL:-}"
  local routing_model="${AUTOPILOT_STUDIO_ROUTING_RUNTIME_MODEL:-}"
  local acceptance_model="${AUTOPILOT_ACCEPTANCE_RUNTIME_MODEL:-}"
  local embedding_model="${AUTOPILOT_LOCAL_EMBEDDING_MODEL:-}"

  local_runtime_model_available "$runtime_model" || return 1
  if [[ -n "$routing_model" && "$routing_model" != "$runtime_model" ]]; then
    local_runtime_model_available "$routing_model" || return 1
  fi
  if [[ -n "$acceptance_model" && "$acceptance_model" != "$runtime_model" && "$acceptance_model" != "$routing_model" ]]; then
    local_runtime_model_available "$acceptance_model" || return 1
  fi
  if [[ -n "$embedding_model" && "$embedding_model" != "$runtime_model" ]]; then
    local_runtime_model_available "$embedding_model" || return 1
  fi
  return 0
}

local_runtime_generate_url() {
  local runtime_health_url="${AUTOPILOT_LOCAL_RUNTIME_HEALTH_URL:-}"
  local runtime_url="${AUTOPILOT_LOCAL_RUNTIME_URL:-}"

  if [[ -n "$runtime_health_url" && "$runtime_health_url" == */api/tags ]]; then
    printf '%s\n' "${runtime_health_url%/api/tags}/api/generate"
    return 0
  fi

  if [[ -n "$runtime_url" && "$runtime_url" == */v1/chat/completions ]]; then
    printf '%s\n' "${runtime_url%/v1/chat/completions}/api/generate"
    return 0
  fi

  return 1
}

warm_local_runtime_model() {
  local model="$1"
  local generate_url=""
  local max_time_secs="${AUTOPILOT_LOCAL_GPU_WARM_MAX_TIME_SECS:-20}"

  [[ -n "$model" ]] || return 0
  generate_url="$(local_runtime_generate_url)" || return 0

  curl -fsS \
    --connect-timeout 2 \
    --max-time "$max_time_secs" \
    -X POST "$generate_url" \
    -H 'Content-Type: application/json' \
    -d "{\"model\":\"${model}\",\"prompt\":\"warm\",\"stream\":false,\"keep_alive\":\"${OLLAMA_KEEP_ALIVE:-30m}\"}" \
    >/dev/null 2>&1 || true
}

warm_local_runtime_models() {
  local runtime_model="${AUTOPILOT_LOCAL_RUNTIME_MODEL:-}"
  local routing_model="${AUTOPILOT_STUDIO_ROUTING_RUNTIME_MODEL:-}"
  local acceptance_model="${AUTOPILOT_ACCEPTANCE_RUNTIME_MODEL:-}"

  [[ "$LOCAL_GPU_DEV" == "1" ]] || return 0
  [[ "${AUTOPILOT_LOCAL_DEV_PRESET:-}" == "ollama-openai" ]] || return 0
  [[ "${AUTOPILOT_LOCAL_GPU_WARM_MODELS_ON_START:-1}" == "1" ]] || return 0
  local_runtime_ready || return 0

  # Model warming is a startup optimization; it should never block the desktop shell.
  echo "Warming local runtime models for Studio routing, drafting, and acceptance in background..."
  (
    warm_local_runtime_model "$runtime_model"
    if [[ -n "$routing_model" && "$routing_model" != "$runtime_model" ]]; then
      warm_local_runtime_model "$routing_model"
    fi
    if [[ -n "$acceptance_model" && "$acceptance_model" != "$runtime_model" && "$acceptance_model" != "$routing_model" ]]; then
      warm_local_runtime_model "$acceptance_model"
    fi
  ) >/dev/null 2>&1 &
}

resolve_ollama_bin() {
  if command -v ollama >/dev/null 2>&1; then
    command -v ollama
    return 0
  fi
  if [[ -x "${HOME}/.local/bin/ollama" ]]; then
    printf '%s\n' "${HOME}/.local/bin/ollama"
    return 0
  fi
  return 1
}

pull_local_runtime_model_if_needed() {
  local model="$1"
  local ollama_bin="${2:-}"

  [[ -n "$model" ]] || return 0
  local_runtime_model_available "$model" && return 0
  [[ -n "$ollama_bin" ]] || return 1
  "${ollama_bin}" pull "$model"
}

ensure_local_runtime_models_ready() {
  local ollama_bin=""
  ollama_bin="$(resolve_ollama_bin)" || return 1

  pull_local_runtime_model_if_needed "${AUTOPILOT_LOCAL_RUNTIME_MODEL:-}" "$ollama_bin" || return 1
  if [[ "${AUTOPILOT_STUDIO_ROUTING_RUNTIME_MODEL:-}" != "${AUTOPILOT_LOCAL_RUNTIME_MODEL:-}" ]]; then
    pull_local_runtime_model_if_needed "${AUTOPILOT_STUDIO_ROUTING_RUNTIME_MODEL:-}" "$ollama_bin" || return 1
  fi
  if [[ "${AUTOPILOT_ACCEPTANCE_RUNTIME_MODEL:-}" != "${AUTOPILOT_LOCAL_RUNTIME_MODEL:-}" && "${AUTOPILOT_ACCEPTANCE_RUNTIME_MODEL:-}" != "${AUTOPILOT_STUDIO_ROUTING_RUNTIME_MODEL:-}" ]]; then
    pull_local_runtime_model_if_needed "${AUTOPILOT_ACCEPTANCE_RUNTIME_MODEL:-}" "$ollama_bin" || return 1
  fi
  if [[ "${AUTOPILOT_LOCAL_EMBEDDING_MODEL:-}" != "${AUTOPILOT_LOCAL_RUNTIME_MODEL:-}" && "${AUTOPILOT_LOCAL_EMBEDDING_MODEL:-}" != "${AUTOPILOT_STUDIO_ROUTING_RUNTIME_MODEL:-}" ]]; then
    pull_local_runtime_model_if_needed "${AUTOPILOT_LOCAL_EMBEDDING_MODEL:-}" "$ollama_bin" || return 1
  fi
}

port_in_use() {
  local port="$1"
  ss -ltn "sport = :${port}" | tail -n +2 | grep -q .
}

resolve_autopilot_profile_dir() {
  if [[ -n "${AUTOPILOT_DATA_DIR:-}" ]]; then
    printf '%s\n' "$AUTOPILOT_DATA_DIR"
    return
  fi

  local base_dir="${XDG_DATA_HOME:-$HOME/.local/share}/ai.ioi.autopilot"
  if [[ -n "${AUTOPILOT_DATA_PROFILE:-}" ]]; then
    printf '%s\n' "${base_dir}/profiles/${AUTOPILOT_DATA_PROFILE}"
  else
    printf '%s\n' "$base_dir"
  fi
}

stop_processes_matching() {
  local pattern="$1"
  local label="$2"
  mapfile -t pids < <(pgrep -f "$pattern" || true)
  if [[ "${#pids[@]}" -eq 0 ]]; then
    return
  fi

  echo "Stopping stale ${label}: ${pids[*]}"
  kill "${pids[@]}" >/dev/null 2>&1 || true
  for _ in $(seq 1 20); do
    local still_running=0
    for pid in "${pids[@]}"; do
      if kill -0 "$pid" >/dev/null 2>&1; then
        still_running=1
        break
      fi
    done
    if [[ "$still_running" == "0" ]]; then
      return
    fi
    sleep 0.5
  done

  echo "Force-stopping stale ${label}: ${pids[*]}"
  kill -9 "${pids[@]}" >/dev/null 2>&1 || true
}

stop_stale_local_dev_stack() {
  local kernel_pattern="${ROOT_DIR}/target/debug/ioi-local --data-dir ${KERNEL_DATA_DIR}"
  stop_processes_matching "$kernel_pattern" "local kernel companion"

  if [[ "${AUTOPILOT_DATA_PROFILE:-}" == "desktop-localgpu" || "${AUTOPILOT_DATA_PROFILE:-}" == "desktop-clean" ]]; then
    local autopilot_pattern="${ROOT_DIR}/target/debug/autopilot"
    stop_processes_matching "$autopilot_pattern" "Autopilot desktop app"
  fi

  if [[ "${AUTOPILOT_LOCAL_DEV_PRESET:-}" == "ollama-openai" ]]; then
    local backend_pattern="${ROOT_DIR}/apps/autopilot/src-tauri/dev/local-backends/ollama-openai/start.sh"
    stop_processes_matching "$backend_pattern" "local runtime preset"
  fi
}

select_kernel_rpc_url() {
  if [[ -n "${AUTOPILOT_KERNEL_RPC_URL:-}" ]]; then
    KERNEL_RPC_URL="$AUTOPILOT_KERNEL_RPC_URL"
    return
  fi

  for candidate_port in $(seq 9000 9010); do
    if ! port_in_use "$candidate_port"; then
      KERNEL_RPC_URL="http://127.0.0.1:${candidate_port}"
      return
    fi
  done

  echo "Unable to find a free kernel RPC port near 9000."
  exit 1
}

kernel_rpc_port() {
  local url="$1"
  local authority="${url#http://}"
  authority="${authority#https://}"
  authority="${authority%%/*}"
  printf '%s\n' "${authority##*:}"
}

kernel_ready() {
  local rpc_url="$1"
  local port
  local ready_signal
  local cli_bin
  local probe_key
  port="$(kernel_rpc_port "$rpc_url")"
  ready_signal="ORCHESTRATION_RPC_LISTENING_ON_127.0.0.1:${port}"
  probe_key="00"

  if ! port_in_use "$port"; then
    return 1
  fi

  if [[ -n "${kernel_log:-}" && -f "${kernel_log}" ]] && grep -Fq "$ready_signal" "${kernel_log}"; then
    return 0
  fi

  cli_bin="${ROOT_DIR}/target/debug/cli"
  if [[ -x "$cli_bin" ]] && timeout 2 "$cli_bin" query --ipc-addr "127.0.0.1:${port}" state "$probe_key" >/dev/null 2>&1; then
    return 0
  fi

  return 1
}

prepare_local_kernel_profile() {
  PROFILE_DIR="$(resolve_autopilot_profile_dir)"
  KERNEL_DATA_DIR="${AUTOPILOT_KERNEL_DATA_DIR:-${PROFILE_DIR}/kernel}"
  kernel_log="${KERNEL_DATA_DIR}/ioi-local.log"
  kernel_build_log="${KERNEL_DATA_DIR}/ioi-local-build.log"
  backend_log="${PROFILE_DIR}/local-backend.log"

  stop_stale_local_dev_stack

  if [[ "${AUTOPILOT_RESET_DATA_ON_BOOT:-0}" == "1" ]]; then
    rm -rf "$PROFILE_DIR"
    export AUTOPILOT_RESET_DATA_ON_BOOT=0
    echo "Reset Autopilot dev profile before launch: ${PROFILE_DIR}"
  fi
  mkdir -p "$KERNEL_DATA_DIR"
}

start_local_backend() {
  if [[ "$LOCAL_GPU_DEV" != "1" || "${AUTOPILOT_LOCAL_BACKEND_AUTOSTART:-0}" != "1" ]]; then
    return
  fi

  if local_runtime_ready && ! local_runtime_model_ready; then
    if [[ "${AUTOPILOT_LOCAL_DEV_PRESET:-}" == "ollama-openai" ]] && ensure_local_runtime_models_ready; then
      echo "Local runtime already running; pulled any missing required models at ${AUTOPILOT_LOCAL_RUNTIME_HEALTH_URL}"
      warm_local_runtime_models
      return
    fi
  fi

  if local_runtime_model_ready; then
    echo "Local runtime already ready at ${AUTOPILOT_LOCAL_RUNTIME_HEALTH_URL}"
    warm_local_runtime_models
    return
  fi

  local backend_entrypoint="${ROOT_DIR}/apps/autopilot/src-tauri/dev/local-backends/${AUTOPILOT_LOCAL_DEV_PRESET}/start.sh"
  if [[ ! -f "$backend_entrypoint" ]]; then
    echo "Local runtime preset entrypoint missing: ${backend_entrypoint}"
    exit 1
  fi

  echo "Starting local runtime preset '${AUTOPILOT_LOCAL_DEV_PRESET}'..."
  (
    cd "$ROOT_DIR"
    env \
      AUTOPILOT_LOCAL_MODEL_CACHE_DIR="${AUTOPILOT_LOCAL_MODEL_CACHE_DIR:-}" \
      AUTOPILOT_LOCAL_GPU_PULL_MODEL_ON_START="${AUTOPILOT_LOCAL_GPU_PULL_MODEL_ON_START:-1}" \
      OLLAMA_DEFAULT_MODEL="${AUTOPILOT_LOCAL_RUNTIME_MODEL:-}" \
      OLLAMA_ROUTING_MODEL="${AUTOPILOT_STUDIO_ROUTING_RUNTIME_MODEL:-}" \
      OLLAMA_EMBEDDING_MODEL="${AUTOPILOT_LOCAL_EMBEDDING_MODEL:-}" \
      AUTOPILOT_LOCAL_EMBEDDING_MODEL="${AUTOPILOT_LOCAL_EMBEDDING_MODEL:-}" \
      sh "$backend_entrypoint"
  ) >"$backend_log" 2>&1 &
  backend_pid=$!

  local wait_for_model="${AUTOPILOT_LOCAL_GPU_PULL_MODEL_ON_START:-1}"
  local ready=0
  for _ in $(seq 1 180); do
    if [[ -n "$backend_pid" ]] && ! kill -0 "$backend_pid" >/dev/null 2>&1; then
      echo "Local runtime preset exited during startup."
      echo "See ${backend_log}"
      exit 1
    fi
    if [[ "$wait_for_model" == "1" ]]; then
      if local_runtime_model_ready; then
        ready=1
        break
      fi
    elif local_runtime_ready; then
      ready=1
      break
    fi
    sleep 1
  done

  if [[ "$ready" != "1" ]]; then
    echo "Timed out waiting for local runtime at ${AUTOPILOT_LOCAL_RUNTIME_HEALTH_URL}"
    echo "See ${backend_log}"
    exit 1
  fi

  echo "Local runtime ready: ${AUTOPILOT_LOCAL_RUNTIME_HEALTH_URL}"
  warm_local_runtime_models
}

start_local_kernel() {
  if [[ "$LOCAL_KERNEL_AUTOSTART" != "1" ]]; then
    return
  fi

  prepare_local_kernel_profile
  start_local_backend
  select_kernel_rpc_url
  export AUTOPILOT_KERNEL_RPC_URL="$KERNEL_RPC_URL"
  export ORCHESTRATION_RPC_LISTEN_ADDRESS="${ORCHESTRATION_RPC_LISTEN_ADDRESS:-127.0.0.1:$(kernel_rpc_port "$KERNEL_RPC_URL")}"

  echo "Building local kernel companion (first run may take a few minutes)..."
  (
    cd "$ROOT_DIR"
    cargo build -p ioi-node --bin ioi-local --features 'local-mode,consensus-poa'
  ) >"$kernel_build_log" 2>&1 || {
    echo "Failed to build local kernel companion."
    echo "See ${kernel_build_log}"
    exit 1
  }

  echo "Starting local kernel companion at ${AUTOPILOT_KERNEL_RPC_URL}..."
  (
    cd "$ROOT_DIR"
    env \
      LOCAL_LLM_URL="${LOCAL_LLM_URL:-}" \
      LOCAL_LLM_MODEL="${LOCAL_LLM_MODEL:-}" \
      LOCAL_LLM_EMBEDDING_MODEL="${LOCAL_LLM_EMBEDDING_MODEL:-}" \
      AUTOPILOT_LOCAL_RUNTIME_MODEL="${AUTOPILOT_LOCAL_RUNTIME_MODEL:-}" \
      AUTOPILOT_LOCAL_EMBEDDING_MODEL="${AUTOPILOT_LOCAL_EMBEDDING_MODEL:-}" \
      OPENAI_EMBEDDING_MODEL="${OPENAI_EMBEDDING_MODEL:-}" \
      IOI_LOCAL_TOKIO_STACK_SIZE_BYTES="${IOI_LOCAL_TOKIO_STACK_SIZE_BYTES:-$LOCAL_KERNEL_STACK_SIZE_BYTES}" \
      RUST_MIN_STACK="${RUST_MIN_STACK:-$LOCAL_KERNEL_STACK_SIZE_BYTES}" \
      ORCHESTRATION_RPC_LISTEN_ADDRESS="${ORCHESTRATION_RPC_LISTEN_ADDRESS}" \
      "${ROOT_DIR}/target/debug/ioi-local" \
      --data-dir "$KERNEL_DATA_DIR"
  ) >"$kernel_log" 2>&1 &
  kernel_pid=$!

  local ready=0
  for _ in $(seq 1 90); do
    if ! kill -0 "$kernel_pid" >/dev/null 2>&1; then
      echo "Local kernel companion exited during startup."
      echo "See ${kernel_log}"
      exit 1
    fi
    if kernel_ready "$AUTOPILOT_KERNEL_RPC_URL"; then
      ready=1
      break
    fi
    sleep 1
  done

  if [[ "$ready" != "1" ]]; then
    echo "Timed out waiting for local kernel companion at ${AUTOPILOT_KERNEL_RPC_URL}"
    echo "See ${kernel_log}"
    exit 1
  fi

  echo "Local kernel companion ready: ${AUTOPILOT_KERNEL_RPC_URL}"
}

select_dev_url() {
  local requested_url="$1"
  local requested_port="${requested_url##*:}"

  if [[ "$REUSE_DEV_SERVER" == "1" ]] && dev_server_ready "$requested_url" && monaco_assets_ready "$requested_url"; then
    DEV_URL="$requested_url"
    return
  fi

  if [[ "$REUSE_DEV_SERVER" == "1" ]] && dev_server_ready "$requested_url"; then
    echo "Existing dev server at $requested_url is missing Monaco workspace assets; starting a fresh isolated server instead."
  fi

  for candidate_port in $(seq "$requested_port" $((requested_port + 10))); do
    if ! port_in_use "$candidate_port"; then
      DEV_URL="http://127.0.0.1:${candidate_port}"
      return
    fi
  done

  echo "Unable to find a free dev server port near ${requested_port}."
  exit 1
}

select_dev_url "$REQUESTED_DEV_URL"
TAURI_CONFIG="{\"build\":{\"beforeDevCommand\":\"\",\"devUrl\":\"${DEV_URL}\"}}"

start_local_kernel

if ! dev_server_ready "$DEV_URL"; then
  if [[ "$AUTO_START_DEV_SERVER" != "1" ]]; then
    echo "Dev server not reachable at $DEV_URL"
    echo "Set AUTO_START_DEV_SERVER=1 or start the frontend manually."
    exit 1
  fi

  dev_port="${DEV_URL##*:}"
  echo "Starting isolated Vite dev server on port ${dev_port}..."
  (
    cd "$ROOT_DIR"
    npm run dev --workspace=apps/autopilot -- --host 127.0.0.1 --port "$dev_port" --strictPort
  ) >/tmp/autopilot-dev-server.log 2>&1 &
  dev_server_pid=$!

  ready=0
  for _ in $(seq 1 90); do
    if curl -fsS "$DEV_URL" >/dev/null 2>&1; then
      ready=1
      break
    fi
    sleep 1
  done

  if [[ "$ready" != "1" ]]; then
    echo "Timed out waiting for dev server at $DEV_URL"
    echo "See /tmp/autopilot-dev-server.log"
    exit 1
  fi
fi

tauri_args=(dev --config "$TAURI_CONFIG")
if [[ "$TAURI_WATCH" != "1" ]]; then
  tauri_args+=(--no-watch)
fi
tauri_args+=("${EXTRA_TAURI_ARGS[@]}")

(
  cd "$ROOT_DIR"
  # COSMIC/X11 dev defaults:
  # - unmanaged right-dock avoids compositor recenter/tiling overrides
  # - shell-dock fullscreen stays off unless explicitly requested
  "${mode_prefix[@]}" \
    AUTOPILOT_COSMIC_UNMANAGED_RIGHT_DOCK="${AUTOPILOT_COSMIC_UNMANAGED_RIGHT_DOCK:-1}" \
    AUTOPILOT_COSMIC_SHELL_DOCK="${AUTOPILOT_COSMIC_SHELL_DOCK:-0}" \
    npm run tauri --workspace=apps/autopilot -- "${tauri_args[@]}"
)
