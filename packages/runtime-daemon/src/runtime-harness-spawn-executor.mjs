import { spawn as nodeSpawn } from "node:child_process";

import { runtimeError } from "./runtime-http-utils.mjs";
import { normalizeArray, objectRecord, optionalString, safeId } from "./runtime-value-helpers.mjs";

export const HARNESS_SPAWN_LANE_RESULT_SCHEMA_VERSION =
  "ioi.hypervisor.harness_spawn_lane_result.v1";

const SPAWN_SCHEMA_VERSION = "ioi.runtime.harness_session_spawn.v1";
const RESULT_SENTINEL = "__HYPERVISOR_HARNESS_RESULT__";
const DEFAULT_TIMEOUT_MS = 60_000;

function laneError({ status, code, message, details }) {
  return runtimeError({ status, code, message, details });
}

function requireSpawn(value) {
  const spawn = objectRecord(value);
  if (!spawn || spawn.schema_version !== SPAWN_SCHEMA_VERSION) {
    throw laneError({
      status: 400,
      code: "harness_spawn_lane_spawn_required",
      message: "Harness spawn lane requires an admitted spawn contract.",
      details: { expected_schema_version: SPAWN_SCHEMA_VERSION },
    });
  }
  if (spawn.decision !== "admitted" || spawn.runtimeTruthSource !== "daemon-runtime") {
    throw laneError({
      status: 403,
      code: "harness_spawn_lane_spawn_boundary_invalid",
      message: "Harness spawn lane requires a daemon-admitted spawn contract.",
      details: {
        decision: spawn.decision ?? null,
        runtimeTruthSource: spawn.runtimeTruthSource ?? null,
      },
    });
  }
  const argv = normalizeArray(spawn.command_contract?.resolved_argv).map(String);
  if (argv.length < 1) {
    throw laneError({
      status: 400,
      code: "harness_spawn_lane_argv_required",
      message: "Harness spawn lane requires a resolved command argv.",
      details: {},
    });
  }
  const workspaceRoot = optionalString(spawn.workspace_root);
  if (!workspaceRoot) {
    throw laneError({
      status: 400,
      code: "harness_spawn_lane_workspace_root_required",
      message: "Harness spawn lane requires a provisioned workspace root.",
      details: {},
    });
  }
  return { spawn, argv, workspaceRoot };
}

/**
 * Run one real execution lane: spawn the admitted harness over its resolved
 * argv in the provisioned workspace, write the user intent to stdin, stream the
 * harness's real stdout, and report the files it wrote. This is Lane A — the
 * harness drives the model and edits the workspace; the daemon owns the spawn
 * and watches the output. No PTY dependency (piped stdio); node-pty is optional.
 *
 * The harness is expected to emit a final `__HYPERVISOR_HARNESS_RESULT__ {json}`
 * line describing { ok, summary, files_written }. When the model route is
 * unreachable the harness emits an honest no-model result (no faked work).
 */
export async function executeHarnessSpawnLane(input = {}, deps = {}) {
  const { spawn, argv, workspaceRoot } = requireSpawn(input.spawn);
  const intent = optionalString(input.intent) ?? "";
  if (!intent) {
    throw laneError({
      status: 400,
      code: "harness_spawn_lane_intent_required",
      message: "Harness spawn lane requires a task intent to run.",
      details: {},
    });
  }

  const nowIso = deps.nowIso ?? (() => new Date().toISOString());
  const onChunk = typeof deps.onChunk === "function" ? deps.onChunk : null;
  const timeoutMs = Number.isFinite(deps.timeoutMs)
    ? deps.timeoutMs
    : DEFAULT_TIMEOUT_MS;
  const spawnImpl = deps.spawn ?? nodeSpawn;
  const modelEndpoint =
    optionalString(input.model_endpoint) ??
    optionalString(deps.modelEndpoint) ??
    optionalString(process.env.IOI_HYPERVISOR_MODEL_UPSTREAM);

  // Minimal, secret-free child env: enough to run node + reach the local model.
  const childEnv = { PATH: process.env.PATH, HOME: process.env.HOME };
  if (modelEndpoint) childEnv.IOI_HYPERVISOR_MODEL_UPSTREAM = modelEndpoint;

  const startedAt = nowIso();
  const transcriptLines = [];
  let stderr = "";
  let result = null;

  const child = spawnImpl(argv[0], argv.slice(1), {
    cwd: workspaceRoot,
    stdio: ["pipe", "pipe", "pipe"],
    env: childEnv,
  });

  const finished = new Promise((resolve) => {
    let settled = false;
    let exitSent = false;
    let stdoutBuffer = "";
    const settle = (payload) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(payload);
    };
    const timer = setTimeout(() => {
      try {
        child.kill("SIGKILL");
      } catch {
        // already gone
      }
      settle({ exit_code: null, timed_out: true });
    }, timeoutMs);

    const handleLine = (line) => {
      transcriptLines.push(line);
      if (onChunk) onChunk(line);
      if (line.startsWith(RESULT_SENTINEL)) {
        const json = line.slice(RESULT_SENTINEL.length).trim();
        try {
          result = JSON.parse(json);
        } catch {
          result = { ok: false, error: "unparseable_result", files_written: [] };
        }
        // The task is done; close the interactive session.
        if (!exitSent) {
          exitSent = true;
          try {
            child.stdin.write("/exit\n");
          } catch {
            // stdin may already be closed
          }
        }
      } else if (line.includes("ready:") && !intentSent) {
        intentSent = true;
        try {
          child.stdin.write(`${intent}\n`);
        } catch {
          // stdin may already be closed
        }
      }
    };

    let intentSent = false;
    child.stdout.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      stdoutBuffer += chunk;
      const lines = stdoutBuffer.split("\n");
      stdoutBuffer = lines.pop() ?? "";
      for (const line of lines) handleLine(line.replace(/\r$/, ""));
    });
    child.stderr.setEncoding("utf8");
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });
    child.on("error", (error) => {
      settle({ exit_code: null, spawn_error: String(error) });
    });
    child.on("close", (code) => {
      if (stdoutBuffer.trim()) handleLine(stdoutBuffer.replace(/\r$/, ""));
      settle({ exit_code: code });
    });

    // Fallback: if the harness never prints a ready line, still deliver the
    // intent shortly after start so the lane makes progress.
    setTimeout(() => {
      if (!intentSent) {
        intentSent = true;
        try {
          child.stdin.write(`${intent}\n`);
        } catch {
          // stdin may already be closed
        }
      }
    }, 250);
  });

  const closeInfo = await finished;
  const finishedAt = nowIso();
  const filesWritten = normalizeArray(result?.files_written).map(String);
  const ok = Boolean(result?.ok) && !closeInfo.timed_out && !closeInfo.spawn_error;
  const laneId = `harness-spawn-lane:${safeId(spawn.spawn_id ?? "session")}`;

  return {
    schema_version: HARNESS_SPAWN_LANE_RESULT_SCHEMA_VERSION,
    lane_id: laneId,
    lane: "host_spawn_session",
    spawn_id: spawn.spawn_id ?? null,
    session_route_ref: spawn.session_route_ref ?? null,
    workspace_root: workspaceRoot,
    model_name: spawn.model_name ?? null,
    exit_status: ok ? "success" : "failure",
    exit_code: closeInfo.exit_code ?? null,
    timed_out: Boolean(closeInfo.timed_out),
    spawn_error: closeInfo.spawn_error ?? null,
    error: ok ? null : (result?.error ?? "harness_lane_incomplete"),
    summary: optionalString(result?.summary) ?? "",
    files_written: filesWritten,
    transcript_lines: transcriptLines,
    stdout: transcriptLines.join("\n"),
    stderr,
    started_at: startedAt,
    finished_at: finishedAt,
    receipt_refs: [`receipt://harness-spawn-lane/${safeId(laneId)}`],
    agentgres_operation_refs: [
      `agentgres://operation/harness-spawn-lane/${safeId(laneId)}`,
    ],
    state_root: `agentgres://state-root/harness-spawn-lane/${safeId(laneId)}`,
    requiresDaemonGate: true,
    runtimeTruthSource: "daemon-runtime",
  };
}
