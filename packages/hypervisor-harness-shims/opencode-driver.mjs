#!/usr/bin/env node
// OpenCode harness adapter driver — daemon Lane A host-spawn contract.
//
// Wraps `opencode run` non-interactively against the admitted local model route
// (OpenAI-compatible / Ollama). Hermetic: provider + permissions come from a
// driver-generated OPENCODE_CONFIG (never the user's ambient config, never a
// workspace file). Streams opencode's raw JSON events as normalized
// HarnessAdapterEvent records; files_written is a real snapshot diff.
//
// Usage:
//   node opencode-driver.mjs --model qwen2.5:7b --cd <workspace> --model-endpoint http://127.0.0.1:11434/v1

import {
  parseArgs, emitEvent, emitResult, snapshotWorkspace, diffSnapshots,
  writeTempConfig, runAdapterChild, truncate, scopedTask, driverMain,
  IMPLEMENTATION_RESULT_SCHEMA,
} from "./harness-adapter-driver-lib.mjs";

const HARNESS = "opencode";
const options = parseArgs(process.argv.slice(2));
const model = String(options.model || "qwen2.5:7b");
const workspace = String(options.cd || process.cwd());
const endpointRaw = String(
  options["model-endpoint"] || process.env.IOI_HYPERVISOR_MODEL_UPSTREAM || "http://127.0.0.1:11434/v1",
).replace(/\/+$/, "");
// opencode's openai-compatible provider needs the /v1 base.
const endpoint = endpointRaw.endsWith("/v1") ? endpointRaw : `${endpointRaw}/v1`;
const childTimeoutMs = Number(options["task-timeout-ms"] || 270000);

// Hermetic provider + permission config, outside the workspace.
const configPath = writeTempConfig("ioi-opencode-", "opencode.json", JSON.stringify({
  $schema: "https://opencode.ai/config.json",
  provider: {
    ollama: {
      npm: "@ai-sdk/openai-compatible",
      name: "Hypervisor local route",
      options: { baseURL: endpoint },
      models: { [model]: { name: model } },
    },
  },
  permission: { edit: "allow", bash: "allow", webfetch: "deny" },
}, null, 2));

function mapLine(line) {
  let event;
  try { event = JSON.parse(line); } catch {
    emitEvent(HARNESS, "adapter_raw", { line: truncate(line, 400) });
    return null;
  }
  const part = event.part || {};
  switch (event.type) {
    case "step_start":
      emitEvent(HARNESS, "step_started", { session_id: event.sessionID });
      break;
    case "tool":
    case "tool_use": {
      const state = part.state || {};
      emitEvent(HARNESS, "tool_call", {
        tool: part.tool,
        status: state.status,
        input: state.input !== undefined ? truncate(JSON.stringify(state.input), 600) : undefined,
        error: state.error ? truncate(state.error, 300) : undefined,
      });
      break;
    }
    case "text":
      emitEvent(HARNESS, "assistant_output", { text: truncate(part.text, 800) });
      break;
    case "step_finish":
      emitEvent(HARNESS, "step_finished", { reason: part.reason, tokens: part.tokens });
      break;
    default:
      emitEvent(HARNESS, "adapter_raw", { type: event.type });
  }
  return event;
}

async function runTask(intent) {
  const before = snapshotWorkspace(workspace);
  const counts = { tool_call: 0, assistant_output: 0, step_finished: 0 };
  let sessionId = null;
  let lastText = "";
  let toolErrors = 0;
  const started = Date.now();
  emitEvent(HARNESS, "run_started", { model, endpoint, workspace });
  const outcome = await runAdapterChild({
    harness: HARNESS,
    command: "opencode",
    args: ["run", "-m", `ollama/${model}`, "--format", "json", "--auto", "--dir", workspace, scopedTask(workspace, intent)],
    env: { PATH: process.env.PATH, HOME: process.env.HOME, OPENCODE_CONFIG: configPath },
    cwd: workspace,
    timeoutMs: childTimeoutMs,
    mapLine: (line) => {
      const event = mapLine(line);
      if (!event) return;
      const part = event.part || {};
      if (event.type === "step_start" && event.sessionID) sessionId = event.sessionID;
      if (event.type === "tool" || event.type === "tool_use") {
        counts.tool_call += 1;
        if ((part.state || {}).status === "error") toolErrors += 1;
      }
      if (event.type === "text") { counts.assistant_output += 1; lastText = part.text || lastText; }
      if (event.type === "step_finish") counts.step_finished += 1;
    },
  });
  const after = snapshotWorkspace(workspace);
  const filesWritten = diffSnapshots(before, after);
  const ok = !outcome.timedOut && !outcome.spawnError && outcome.exitCode === 0;
  const error = outcome.spawnError
    ? `adapter_spawn_failed: ${outcome.spawnError}`
    : outcome.timedOut
      ? "adapter_timed_out"
      : outcome.exitCode !== 0
        ? `adapter_exit_${outcome.exitCode}${outcome.stderrTail?.length ? `: ${truncate(outcome.stderrTail.join(" | "), 300)}` : ""}`
        : null;
  const implementationResult = {
    schema_version: IMPLEMENTATION_RESULT_SCHEMA,
    harness: HARNESS,
    adapter: "opencode run (json events)",
    adapter_session_id: sessionId,
    model,
    model_endpoint: endpoint,
    files_written: filesWritten,
    event_counts: counts,
    tool_errors: toolErrors,
    duration_ms: Date.now() - started,
    exit_code: outcome.exitCode,
    summary: truncate(lastText, 400),
  };
  emitEvent(HARNESS, "run_finished", { ok, files_written: filesWritten.length, error });
  emitResult({
    ok,
    files_written: filesWritten,
    summary: truncate(lastText, 400) || (ok ? `opencode completed (${filesWritten.length} file(s) changed)` : ""),
    ...(error ? { error } : {}),
    implementation_result: implementationResult,
  });
}

driverMain({ harness: HARNESS, label: "OpenCode", runTask });
