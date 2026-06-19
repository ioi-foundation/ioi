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
  const codexBinary =
    optionalString(request.codex_binary) ??
    optionalString(normalizeArray(commandContract?.resolved_argv)[0]) ??
    optionalString(commandContract?.binary_name) ??
    "codex";
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

  const codexHelp = await commandResult(runCommand, codexBinary, ["--help"]);
  const codexBinaryCheck = codexHelp.ok
    ? passCheck(
        "codex_binary",
        `Codex binary resolved through ${codexBinary}.`,
        [`host-command:${safeId(codexBinary)}:--help`],
      )
    : failCheck(
        "codex_binary",
        `Codex binary is not runnable through ${codexBinary}.`,
        [`host-command:${safeId(codexBinary)}:--help`],
      );
  const codexHelpText = `${codexHelp.stdout}\n${codexHelp.stderr}`;
  const codexOssFlagsCheck =
    codexHelp.ok &&
    ["--oss", "--local-provider", "--model", "--cd"].every((flag) =>
      codexHelpText.includes(flag),
    )
      ? passCheck(
          "codex_oss_flags",
          "Codex supports OSS local-provider model mounting flags.",
          [`host-command:${safeId(codexBinary)}:oss-flags`],
        )
      : failCheck(
          "codex_oss_flags",
          "Codex does not expose the OSS local-provider flags required by this harness route.",
          [`host-command:${safeId(codexBinary)}:oss-flags`],
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
    codexBinaryCheck,
    codexOssFlagsCheck,
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
    codex_binary: codexBinary,
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
      "A spawned harness session may attach to a host PTY only after the daemon verifies the local Codex OSS binary, Ollama provider, and requested local model route are runnable on this host.",
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
    spawn.command_contract?.binary_name !== "codex" ||
    spawn.model_mount_contract?.provider !== "ollama" ||
    spawn.command_contract?.secret_release_policy !== "none"
  ) {
    throw readinessError({
      status: 403,
      code: "harness_session_readiness_route_unsupported",
      message:
        "Only secret-free Codex OSS over local Ollama model mounts can be readiness-checked in this slice.",
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

function readinessStateForCheck(checkId) {
  switch (checkId) {
    case "codex_binary":
      return "codex_binary_unavailable";
    case "codex_oss_flags":
      return "codex_oss_flags_unavailable";
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
    case "codex_binary_unavailable":
      return "Install or expose the Codex CLI before attaching this harness session.";
    case "codex_oss_flags_unavailable":
      return "Upgrade the Codex CLI to a build that supports OSS local-provider sessions.";
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
