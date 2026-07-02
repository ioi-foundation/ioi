#!/usr/bin/env node
// DeepSeek TUI harness adapter driver — daemon Lane A host-spawn contract.
//
// Wraps `deepseek exec` non-interactively against the admitted local model route through the
// TUI's native `ollama` provider. Hermetic: provider/model/base-url come from a driver-generated
// --config TOML (never the user's ~/.deepseek/config.toml). Streams the TUI's stream-json output
// as normalized HarnessAdapterEvent records (content chunks are coalesced); files_written is a
// real snapshot diff.
//
// Usage:
//   node deepseek-tui-driver.mjs --model qwen2.5:7b --cd <workspace> --model-endpoint http://127.0.0.1:11434

import {
  parseArgs, emitEvent, emitResult, snapshotWorkspace, diffSnapshots,
  writeTempConfig, runAdapterChild, truncate, scopedTask, driverMain,
  IMPLEMENTATION_RESULT_SCHEMA,
} from "./harness-adapter-driver-lib.mjs";

const HARNESS = "deepseek_tui";
const options = parseArgs(process.argv.slice(2));
const model = String(options.model || "qwen2.5:7b");
const workspace = String(options.cd || process.cwd());
// The TUI's ollama provider wants the PROVIDER ROOT (it appends its own API paths).
const endpoint = String(
  options["model-endpoint"] || process.env.IOI_HYPERVISOR_MODEL_UPSTREAM || "http://127.0.0.1:11434",
).replace(/\/+$/, "").replace(/\/v1$/, "");
const childTimeoutMs = Number(options["task-timeout-ms"] || 270000);

const configPath = writeTempConfig("ioi-deepseek-", "config.toml", [
  `provider = "ollama"`,
  `model = "${model}"`,
  `ollama.base_url = "${endpoint}"`,
  "",
].join("\n"));

async function runTask(intent) {
  const before = snapshotWorkspace(workspace);
  const counts = { assistant_output: 0, tool_call: 0 };
  let sessionId = null;
  let metadata = null;
  let contentBuf = "";
  let lastFlush = "";
  const started = Date.now();
  const flushContent = () => {
    if (!contentBuf.trim()) { contentBuf = ""; return; }
    counts.assistant_output += 1;
    lastFlush = contentBuf;
    emitEvent(HARNESS, "assistant_output", { text: truncate(contentBuf, 800) });
    contentBuf = "";
  };
  emitEvent(HARNESS, "run_started", { model, endpoint, workspace });
  const outcome = await runAdapterChild({
    harness: HARNESS,
    command: "deepseek",
    args: ["--config", configPath, "exec", "--auto", "--output-format", "stream-json", scopedTask(workspace, intent)],
    env: {
      PATH: process.env.PATH,
      HOME: process.env.HOME,
      // Ollama requires no key; the TUI's provider layer expects one to exist.
      OLLAMA_API_KEY: "ollama-local",
    },
    cwd: workspace,
    timeoutMs: childTimeoutMs,
    mapLine: (line) => {
      let event;
      try { event = JSON.parse(line); } catch {
        emitEvent(HARNESS, "adapter_raw", { line: truncate(line, 400) });
        return;
      }
      switch (event.type) {
        case "content":
          contentBuf += String(event.content ?? "");
          if (contentBuf.length > 2000) flushContent();
          break;
        case "tool_call":
        case "tool":
        case "tool_result": {
          flushContent();
          counts.tool_call += 1;
          emitEvent(HARNESS, "tool_call", {
            tool: event.tool || event.name,
            status: event.status,
            input: event.input !== undefined ? truncate(JSON.stringify(event.input), 600) : undefined,
          });
          break;
        }
        case "session_capture":
          sessionId = event.content || sessionId;
          emitEvent(HARNESS, "adapter_session", { session_id: sessionId });
          break;
        case "metadata":
          flushContent();
          metadata = event.meta || null;
          emitEvent(HARNESS, "run_metadata", { meta: metadata });
          break;
        case "done":
          flushContent();
          emitEvent(HARNESS, "completed", {});
          break;
        default:
          emitEvent(HARNESS, "adapter_raw", { type: event.type });
      }
    },
  });
  flushContent();
  const after = snapshotWorkspace(workspace);
  const filesWritten = diffSnapshots(before, after);
  const completed = metadata?.status === "completed";
  const ok = !outcome.timedOut && !outcome.spawnError && outcome.exitCode === 0 && completed;
  const error = outcome.spawnError
    ? `adapter_spawn_failed: ${outcome.spawnError}`
    : outcome.timedOut
      ? "adapter_timed_out"
      : outcome.exitCode !== 0
        ? `adapter_exit_${outcome.exitCode}${outcome.stderrTail?.length ? `: ${truncate(outcome.stderrTail.join(" | "), 300)}` : ""}`
        : !completed
          ? `adapter_incomplete: status=${metadata?.status ?? "unknown"}`
          : null;
  const implementationResult = {
    schema_version: IMPLEMENTATION_RESULT_SCHEMA,
    harness: HARNESS,
    adapter: "deepseek exec (stream-json)",
    adapter_session_id: sessionId,
    model: metadata?.model || model,
    model_endpoint: endpoint,
    files_written: filesWritten,
    event_counts: counts,
    tokens: metadata ? { input: metadata.input_tokens, output: metadata.output_tokens } : undefined,
    duration_ms: Date.now() - started,
    exit_code: outcome.exitCode,
    summary: truncate(lastFlush, 400),
  };
  emitEvent(HARNESS, "run_finished", { ok, files_written: filesWritten.length, error });
  emitResult({
    ok,
    files_written: filesWritten,
    summary: truncate(lastFlush, 400) || (ok ? `deepseek tui completed (${filesWritten.length} file(s) changed)` : ""),
    ...(error ? { error } : {}),
    implementation_result: implementationResult,
  });
}

driverMain({ harness: HARNESS, label: "DeepSeek TUI", runTask });
