import { execFile } from "node:child_process";
import { promisify } from "node:util";

import { runtimeError } from "./runtime-http-utils.mjs";
import {
  normalizeArray,
  objectRecord,
  optionalString,
  safeId,
  uniqueStrings,
} from "./runtime-value-helpers.mjs";

export const HARNESS_SESSION_READINESS_SCHEMA_VERSION =
  "ioi.runtime.harness_session_readiness.v1";

const SPAWN_SCHEMA_VERSION = "ioi.runtime.harness_session_spawn.v1";
const execFileAsync = promisify(execFile);

export async function buildHarnessSessionReadiness(request = {}, deps = {}) {
  const nowIso = deps.nowIso ?? (() => new Date().toISOString());
  const runCommand = deps.runCommand ?? runHostCommand;
  const spawn = requireSpawn(request.session_spawn);
  const commandContract = objectRecord(spawn.command_contract);
  const modelMountContract = objectRecord(spawn.model_mount_contract);
  const modelName =
    optionalString(request.model_name) ??
    optionalString(spawn.model_name) ??
    optionalString(modelMountContract?.model_default) ??
    "qwen";
  const requestedHarnessBinary =
    optionalString(request.harness_binary) ??
    optionalString(normalizeArray(commandContract?.resolved_argv)[0]) ??
    optionalString(commandContract?.binary_name) ??
    "codex";
  const readinessProbeArgv = normalizeArray(
    commandContract?.readiness_probe_argv,
  );
  const readinessProbeCommand =
    optionalString(readinessProbeArgv[0]) ?? requestedHarnessBinary;
  const readinessProbeArgs =
    readinessProbeArgv.length > 0
      ? readinessProbeArgv.slice(1).map((arg) => String(arg))
      : ["--help"];
  const providerBinary =
    optionalString(request.provider_binary) ??
    optionalString(modelMountContract?.provider) ??
    "ollama";
  const readinessId =
    optionalString(request.readiness_id) ??
    `harness-session-readiness:${safeId(spawn.spawn_id)}`;
  const receiptRef =
    optionalString(request.readiness_receipt_ref) ??
    `receipt://harness-session-readiness/${safeId(readinessId)}`;

  const harnessBinary = requestedHarnessBinary;
  const harnessBinaryName =
    optionalString(commandContract?.binary_name) ?? harnessBinary;
  const help = await commandResult(
    runCommand,
    readinessProbeCommand,
    readinessProbeArgs,
  );
  const probeEvidenceRef = `host-command:${safeId(
    readinessProbeCommand,
  )}:${safeId(readinessProbeArgs.join("-") || "help")}`;
  const harnessBinaryCheck = help.ok
    ? passCheck(
        "harness_binary",
        `Harness binary resolved through ${readinessProbeCommand}.`,
        [probeEvidenceRef],
      )
    : failCheck(
        "harness_binary",
        `Harness binary is not runnable through ${readinessProbeCommand}.`,
        [probeEvidenceRef],
      );
  const helpText = `${help.stdout}\n${help.stderr}`;
  const requiredFlags = requiredLocalModelFlagsForBinary(harnessBinaryName);
  const localModelFlagsCheck =
    help.ok &&
    requiredFlags.every((flag) => helpText.includes(flag))
      ? passCheck(
          "harness_local_model_flags",
          `${harnessBinaryName} supports the local-provider model mounting flags required by this route.`,
          [probeEvidenceRef],
        )
      : failCheck(
          "harness_local_model_flags",
          `${harnessBinaryName} does not expose the local-provider flags required by this harness route.`,
          [probeEvidenceRef],
        );

  const providerList = await commandResult(runCommand, providerBinary, ["list"]);
  const providerCheck = providerList.ok
    ? passCheck(
        "ollama_provider",
        `Ollama provider answered ${providerBinary} list.`,
        [`host-command:${safeId(providerBinary)}:list`],
      )
    : failCheck(
        "ollama_provider",
        `Ollama provider is not reachable through ${providerBinary} list.`,
        [`host-command:${safeId(providerBinary)}:list`],
      );
  const availableModels = providerList.ok
    ? parseOllamaModelList(providerList.stdout)
    : [];
  const modelCheck =
    providerList.ok && modelNameAvailable(availableModels, modelName)
      ? passCheck(
          "qwen_model_available",
          `Local model ${modelName} is available through Ollama.`,
          [`model:${safeId(modelName)}`],
        )
      : failCheck(
          "qwen_model_available",
          `Local model ${modelName} is not listed by Ollama.`,
          [`model:${safeId(modelName)}`],
        );

  const checks = [
    harnessBinaryCheck,
    localModelFlagsCheck,
    providerCheck,
    modelCheck,
  ];
  const failedCheck = checks.find((check) => check.status === "fail");
  const decision = failedCheck ? "blocked" : "ready";
  const readinessState = failedCheck
    ? readinessStateForCheck(failedCheck.id)
    : "ready_for_harness_pty_attach";

  return {
    schema_version: HARNESS_SESSION_READINESS_SCHEMA_VERSION,
    readiness_id: readinessId,
    decision,
    readiness_state: readinessState,
    spawn_id: spawn.spawn_id,
    launch_id: spawn.launch_id,
    session_binding_ref: spawn.session_binding_ref,
    session_route_ref: spawn.session_route_ref,
    harness_selection_ref: spawn.harness_selection_ref,
    agent_harness_adapter_id: spawn.agent_harness_adapter_id ?? null,
    model_configuration_ref: spawn.model_configuration_ref,
    model_route_ref: spawn.model_route_ref,
    model_name: modelName,
    provider: "ollama",
    harness_binary: harnessBinary,
    provider_binary: providerBinary,
    available_model_names: availableModels,
    checks,
    operator_next_action: failedCheck
      ? nextActionForReadinessState(readinessState, modelName)
      : "Attach the client PTY using the daemon-resolved command contract.",
    receipt_refs: uniqueStrings([
      ...normalizeArray(spawn.receipt_refs),
      receiptRef,
    ]),
    agentgres_operation_refs: uniqueStrings([
      ...normalizeArray(spawn.agentgres_operation_refs),
      `agentgres://operation/harness-session-readiness/${safeId(
        readinessId,
      )}`,
    ]),
    state_root: `agentgres://state-root/harness-session-readiness/${safeId(
      readinessId,
    )}`,
    checked_at: optionalString(request.checked_at) ?? nowIso(),
    requiresDaemonGate: true,
    runtimeTruthSource: "daemon-runtime",
    readiness_invariant:
      "A spawned harness session may attach to a host PTY only after the daemon verifies the selected harness command, Ollama provider, and requested local model route are runnable on this host.",
  };
}

function requireSpawn(value) {
  const spawn = objectRecord(value);
  if (!spawn || spawn.schema_version !== SPAWN_SCHEMA_VERSION) {
    throw readinessError({
      status: 400,
      code: "harness_session_readiness_spawn_required",
      message: "Harness session readiness requires an admitted spawn contract.",
      details: { expected_schema_version: SPAWN_SCHEMA_VERSION },
    });
  }
  if (
    spawn.decision !== "admitted" ||
    spawn.spawn_state !== "ready_for_client_pty_attach" ||
    spawn.requiresDaemonGate !== true ||
    spawn.runtimeTruthSource !== "daemon-runtime"
  ) {
    throw readinessError({
      status: 403,
      code: "harness_session_readiness_spawn_boundary_invalid",
      message:
        "Harness session readiness requires a daemon-gated spawn ready for client PTY attach.",
      details: {
        decision: spawn.decision ?? null,
        spawn_state: spawn.spawn_state ?? null,
        requiresDaemonGate: spawn.requiresDaemonGate ?? null,
        runtimeTruthSource: spawn.runtimeTruthSource ?? null,
      },
    });
  }
  if (
    !["codex", "deepseek", "claude-code-example"].includes(
      spawn.command_contract?.binary_name,
    ) ||
    spawn.model_mount_contract?.provider !== "ollama" ||
    spawn.command_contract?.secret_release_policy !== "none"
  ) {
    throw readinessError({
      status: 403,
      code: "harness_session_readiness_route_unsupported",
      message:
        "Only secret-free Codex OSS, DeepSeek TUI, or Claude Code example sessions over local Ollama model mounts can be readiness-checked in this slice.",
      details: {
        binary_name: spawn.command_contract?.binary_name ?? null,
        provider: spawn.model_mount_contract?.provider ?? null,
        secret_release_policy:
          spawn.command_contract?.secret_release_policy ?? null,
      },
    });
  }
  return spawn;
}

async function commandResult(runCommand, command, args) {
  try {
    const result = await runCommand(command, args);
    const status =
      typeof result?.status === "number"
        ? result.status
        : typeof result?.exitCode === "number"
          ? result.exitCode
          : 0;
    return {
      ok: status === 0,
      status,
      stdout: String(result?.stdout ?? ""),
      stderr: String(result?.stderr ?? ""),
    };
  } catch (error) {
    return {
      ok: false,
      status:
        typeof error?.code === "number"
          ? error.code
          : typeof error?.status === "number"
            ? error.status
            : 127,
      stdout: String(error?.stdout ?? ""),
      stderr:
        String(error?.stderr ?? "") ||
        (error instanceof Error ? error.message : String(error ?? "")),
    };
  }
}

async function runHostCommand(command, args) {
  const result = await execFileAsync(command, args, {
    timeout: 5000,
    maxBuffer: 512 * 1024,
    env: process.env,
  });
  return { status: 0, stdout: result.stdout, stderr: result.stderr };
}

function passCheck(id, summary, evidenceRefs) {
  return {
    id,
    status: "pass",
    required: true,
    summary,
    evidence_refs: normalizeArray(evidenceRefs),
  };
}

function failCheck(id, summary, evidenceRefs) {
  return {
    id,
    status: "fail",
    required: true,
    summary,
    evidence_refs: normalizeArray(evidenceRefs),
  };
}

function parseOllamaModelList(stdout) {
  return String(stdout ?? "")
    .split(/\r?\n/)
    .slice(1)
    .map((line) => line.trim().split(/\s+/)[0])
    .filter((name) => name && name !== "NAME");
}

function modelNameAvailable(availableModels, modelName) {
  return availableModels.some(
    (name) =>
      name === modelName ||
      name.startsWith(`${modelName}:`) ||
      modelName.startsWith(`${name}:`),
  );
}

function requiredLocalModelFlagsForBinary(binaryName) {
  if (binaryName === "deepseek") {
    return ["--provider", "--model"];
  }
  if (binaryName === "claude-code-example") {
    return ["--provider", "--model", "--cd"];
  }
  return ["--oss", "--local-provider", "--model"];
}

function readinessStateForCheck(checkId) {
  switch (checkId) {
    case "harness_binary":
      return "harness_binary_unavailable";
    case "harness_local_model_flags":
      return "harness_local_model_flags_unavailable";
    case "ollama_provider":
      return "ollama_provider_unavailable";
    case "qwen_model_available":
      return "qwen_model_unavailable";
    default:
      return "host_readiness_blocked";
  }
}

function nextActionForReadinessState(state, modelName) {
  switch (state) {
    case "harness_binary_unavailable":
      return "Install or expose the selected harness CLI before attaching this harness session.";
    case "harness_local_model_flags_unavailable":
      return "Upgrade or configure the selected harness CLI to support the local Ollama model route.";
    case "ollama_provider_unavailable":
      return "Start the Ollama server before attaching this harness session.";
    case "qwen_model_unavailable":
      return `Pull or load ${modelName} in Ollama before attaching this harness session.`;
    default:
      return "Resolve the blocked host readiness check before attaching this harness session.";
  }
}

function readinessError({ status, code, message, details }) {
  return runtimeError({
    status,
    code,
    message,
    details,
  });
}
