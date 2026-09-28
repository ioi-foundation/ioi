#!/usr/bin/env node
// DeepSeek TUI harness adapter driver — daemon Lane A host-spawn contract.
//
// Wraps `deepseek exec` non-interactively against the admitted local model route through the
// TUI's native `ollama` provider. Hermetic: provider/model/base-url come from a driver-generated
// --config TOML (never the user's ~/.deepseek/config.toml). Streams the TUI's stream-json output
// as normalized HarnessAdapterEvent records (content chunks are coalesced); files_written is a
// real snapshot diff.
//
// TOOL POSTURE (MASTER-GUIDE G9 / W0.5): the TUI runs WITHOUT `--auto`. `exec --auto` auto-approves
// every tool, shell included, with network access; this driver never passes it. What the TUI does
// now when the model asks for a tool (measured against deepseek-tui 0.8.40):
//   - read-only tools (read_file, list_dir, grep_files, file_search, ...) run;
//   - approval-gated tools (task_shell_start, task_gate_run, task_create, ...) are DENIED: exec
//     without --auto has no approver, so the TUI answers "denied by user" and hands the denial back
//     to the model. A workspace `.deepseek/config.toml` (approval_policy / yolo / default_mode)
//     does not change this;
//   - write/edit/patch tools are not offered at all, so this lane cannot change workspace files
//     (files_written stays empty; a request to edit ends as an honest completed run with no change);
//   - code_execution / js_execution / rlm_* (which run Python or Node WITHOUT asking) are only
//     advertised when an interpreter is on PATH, so the TUI is launched by absolute path with an
//     interpreter-free PATH and those tools are neither offered nor runnable.
// The daemon's bwrap cell remains the hard boundary around all of it.
//
// Usage:
//   node deepseek-tui-driver.mjs --model qwen2.5:7b --cd <workspace> --model-endpoint http://127.0.0.1:11434

import { accessSync, constants as fsConstants, openSync, readSync, closeSync, realpathSync } from "node:fs";
import path from "node:path";
import {
  parseArgs, emitEvent, emitResult, snapshotWorkspace, diffSnapshots,
  writeTempConfig, runAdapterChild, truncate, scopedTask, driverMain,
  IMPLEMENTATION_RESULT_SCHEMA,
} from "./harness-adapter-driver-lib.mjs";

// No --auto, ever (G9). Named so the fail-closed battery (deepseek-tui-driver.test.mjs) pins it.
export const DEEPSEEK_EXEC_FLAGS = Object.freeze(["exec", "--output-format", "stream-json"]);
// A PATH with no interpreters on it: the TUI only offers its unapproved code_execution /
// js_execution / rlm tools when python or node resolves on PATH.
export const INTERPRETER_FREE_PATH = "/nonexistent/ioi-deepseek-no-interpreters";

// Resolve the `deepseek` launcher on the driver's PATH and return how to start it WITHOUT a PATH:
// the npm launcher is a `#!/usr/bin/env node` script, so it is started with this node by absolute
// path; a native binary is started directly.
export function resolveDeepseekLaunch(searchPath = process.env.PATH || "") {
  for (const dir of searchPath.split(path.delimiter)) {
    if (!dir) continue;
    const candidate = path.join(dir, "deepseek");
    try { accessSync(candidate, fsConstants.X_OK); } catch { continue; }
    const real = realpathSync(candidate);
    const head = Buffer.alloc(128);
    const fd = openSync(real, "r");
    let read = 0;
    try { read = readSync(fd, head, 0, head.length, 0); } finally { closeSync(fd); }
    const firstLine = head.subarray(0, read).toString("utf8").split("\n", 1)[0];
    if (firstLine.startsWith("#!") && /\bnode\b/.test(firstLine)) {
      return { command: process.execPath, prefixArgs: [real] };
    }
    return { command: real, prefixArgs: [] };
  }
  return null;
}

const HARNESS = "deepseek_tui";
const options = parseArgs(process.argv.slice(2));
const model = String(options.model || "qwen2.5:7b");
const workspace = String(options.cd || process.cwd());
// The TUI's ollama provider wants the PROVIDER ROOT (it appends its own API paths).
const endpoint = String(
  options["model-endpoint"] || process.env.IOI_HYPERVISOR_MODEL_UPSTREAM || "http://127.0.0.1:11434",
).replace(/\/+$/, "").replace(/\/v1$/, "");
// HOT-HOST INFERENCE BUDGET (paired-budget invariant — keep these aligned):
//   shim task budget (here, 600s)  <  daemon HOST_SPAWN_LANE_TIMEOUT_SECS (660s)  <  any
//   composite/per-suite ceiling. The shim must emit its honest timeout/result BEFORE the
//   daemon lane reaps the child, or the invocation loses its result entirely. CPU-only
//   local-model gates treat inference latency and stop-discipline as STOCHASTIC (bounded
//   real retries, honest-completion break conditions) — never as deterministic constants.
const childTimeoutMs = Number(options["task-timeout-ms"] || 600000);

const configPath = writeTempConfig("ioi-deepseek-", "config.toml", [
  `provider = "ollama"`,
  `model = "${model}"`,
  `ollama.base_url = "${endpoint}"`,
  // Defense in depth only: exec without --auto already denies shell (measured).
  "allow_shell = false",
  "",
  "[features]",
  "shell_tool = false",
  "subagents = false",
  "web_search = false",
  "apply_patch = false",
  "mcp = false",
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
  emitEvent(HARNESS, "run_started", { model, endpoint, workspace, tool_posture: "no_auto_approve" });
  const launch = resolveDeepseekLaunch();
  const outcome = launch ? await runAdapterChild({
    harness: HARNESS,
    command: launch.command,
    args: [...launch.prefixArgs, "--config", configPath, ...DEEPSEEK_EXEC_FLAGS, scopedTask(workspace, intent)],
    env: {
      PATH: INTERPRETER_FREE_PATH,
      HOME: process.env.HOME,
      // Ollama requires no key; the TUI's provider layer expects one to exist.
      OLLAMA_API_KEY: "ollama-local",
      // The TUI ignores `ollama.base_url` in --config (measured: it dials localhost:11434), but
      // honours this, so the admitted route is the one actually used.
      OLLAMA_BASE_URL: endpoint,
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
            // A denied tool comes back as status=error with "denied by user" here.
            output: event.output !== undefined ? truncate(String(event.output), 300) : undefined,
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
  }) : { exitCode: null, timedOut: false, spawnError: "deepseek launcher not found on PATH", stderrTail: [] };
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
