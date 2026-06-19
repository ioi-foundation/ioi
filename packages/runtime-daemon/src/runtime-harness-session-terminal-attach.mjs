import { runtimeError } from "./runtime-http-utils.mjs";
import {
  normalizeArray,
  objectRecord,
  optionalString,
  safeId,
  uniqueStrings,
} from "./runtime-value-helpers.mjs";

export const HARNESS_SESSION_TERMINAL_ATTACH_SCHEMA_VERSION =
  "ioi.runtime.harness_session_terminal_attach.v1";

const SPAWN_SCHEMA_VERSION = "ioi.runtime.harness_session_spawn.v1";
const READINESS_SCHEMA_VERSION = "ioi.runtime.harness_session_readiness.v1";

export function admitHarnessSessionTerminalAttach(request = {}, deps = {}) {
  const nowIso = deps.nowIso ?? (() => new Date().toISOString());
  const spawn = requireSpawn(request.session_spawn);
  const readiness = requireReadiness(request.session_readiness, spawn);
  const attachId =
    optionalString(request.attach_id) ??
    `harness-session-terminal-attach:${safeId(readiness.readiness_id)}`;
  const receiptRef =
    optionalString(request.attach_receipt_ref) ??
    `receipt://harness-session-terminal-attach/${safeId(attachId)}`;
  const transcriptId =
    optionalString(request.transcript_id) ??
    `harness-terminal-transcript:${safeId(attachId)}`;
  const transcriptStreamRef =
    optionalString(request.transcript_stream_ref) ??
    `agentgres://trace/harness-terminal-transcript/${safeId(transcriptId)}`;
  const commandLine = optionalString(
    spawn.terminal_attach_contract?.command_line,
  );

  if (!commandLine) {
    throw terminalAttachError({
      status: 400,
      code: "harness_session_terminal_attach_command_required",
      message:
        "Harness session terminal attach requires a daemon-resolved command line.",
      details: { spawn_id: spawn.spawn_id },
    });
  }

  return {
    schema_version: HARNESS_SESSION_TERMINAL_ATTACH_SCHEMA_VERSION,
    attach_id: attachId,
    decision: "admitted",
    attach_state: "client_pty_attach_admitted",
    attach_lane: "hypervisor_client_terminal_adapter",
    spawn_id: spawn.spawn_id,
    readiness_id: readiness.readiness_id,
    launch_id: spawn.launch_id,
    session_binding_ref: spawn.session_binding_ref,
    session_route_ref: spawn.session_route_ref,
    harness_selection_ref: spawn.harness_selection_ref,
    agent_harness_adapter_id: spawn.agent_harness_adapter_id ?? null,
    model_configuration_ref: spawn.model_configuration_ref,
    model_route_ref: spawn.model_route_ref,
    model_name: spawn.model_name,
    workspace_ref: spawn.workspace_ref,
    workspace_root: spawn.workspace_root,
    terminal_session_ref: spawn.terminal_session_ref,
    command_contract_ref: spawn.command_contract_ref,
    command_contract: spawn.command_contract,
    client_attach_contract: {
      ...spawn.terminal_attach_contract,
      command_line: commandLine,
      initial_write: `${commandLine}\n`,
      transcript_stream_ref: transcriptStreamRef,
      pty_transport: "hypervisor_client_terminal_adapter",
      process_custody: "client_host_pty_after_daemon_attach_admission",
    },
    terminal_transcript_projection: {
      schema_version: "ioi.runtime.harness_terminal_transcript_projection.v1",
      transcript_id: transcriptId,
      transcript_state: "awaiting_client_stream",
      transcript_stream_ref: transcriptStreamRef,
      cursor: 0,
      lines: [
        {
          stream: "system",
          text:
            "Daemon admitted client PTY attach after harness spawn and host readiness checks.",
        },
        {
          stream: "stdin",
          text: commandLine,
        },
      ],
      runtimeTruthSource: "daemon-runtime",
    },
    workspace_mount_policy: spawn.workspace_mount_policy,
    privacy_posture_ref: spawn.privacy_posture_ref,
    authority_scope_refs: normalizeArray(spawn.authority_scope_refs),
    receipt_policy_ref: spawn.receipt_policy_ref,
    receipt_refs: uniqueStrings([
      ...normalizeArray(readiness.receipt_refs),
      ...normalizeArray(spawn.receipt_refs),
      receiptRef,
    ]),
    agentgres_operation_refs: uniqueStrings([
      ...normalizeArray(readiness.agentgres_operation_refs),
      ...normalizeArray(spawn.agentgres_operation_refs),
      `agentgres://operation/harness-session-terminal-attach/${safeId(
        attachId,
      )}`,
    ]),
    state_root: `agentgres://state-root/harness-session-terminal-attach/${safeId(
      attachId,
    )}`,
    attached_at: optionalString(request.attached_at) ?? nowIso(),
    requiresDaemonGate: true,
    runtimeTruthSource: "daemon-runtime",
    terminal_attach_invariant:
      "The client may create and write to the host PTY only after the daemon binds the spawned command, readiness proof, authority scopes, receipt refs, transcript stream, and workspace root in this attach object.",
  };
}

function requireSpawn(value) {
  const spawn = objectRecord(value);
  if (!spawn || spawn.schema_version !== SPAWN_SCHEMA_VERSION) {
    throw terminalAttachError({
      status: 400,
      code: "harness_session_terminal_attach_spawn_required",
      message: "Harness session terminal attach requires an admitted spawn.",
      details: { expected_schema_version: SPAWN_SCHEMA_VERSION },
    });
  }
  if (
    spawn.decision !== "admitted" ||
    spawn.spawn_state !== "ready_for_client_pty_attach" ||
    spawn.requiresDaemonGate !== true ||
    spawn.runtimeTruthSource !== "daemon-runtime" ||
    spawn.command_contract?.pty_transport !==
      "hypervisor_client_terminal_adapter"
  ) {
    throw terminalAttachError({
      status: 403,
      code: "harness_session_terminal_attach_spawn_boundary_invalid",
      message:
        "Harness session terminal attach requires a daemon-gated spawn ready for client PTY attach.",
      details: {
        decision: spawn.decision ?? null,
        spawn_state: spawn.spawn_state ?? null,
        requiresDaemonGate: spawn.requiresDaemonGate ?? null,
        runtimeTruthSource: spawn.runtimeTruthSource ?? null,
        pty_transport: spawn.command_contract?.pty_transport ?? null,
      },
    });
  }
  return spawn;
}

function requireReadiness(value, spawn) {
  const readiness = objectRecord(value);
  if (!readiness || readiness.schema_version !== READINESS_SCHEMA_VERSION) {
    throw terminalAttachError({
      status: 400,
      code: "harness_session_terminal_attach_readiness_required",
      message: "Harness session terminal attach requires host readiness.",
      details: { expected_schema_version: READINESS_SCHEMA_VERSION },
    });
  }
  if (
    readiness.decision !== "ready" ||
    readiness.readiness_state !== "ready_for_harness_pty_attach" ||
    readiness.spawn_id !== spawn.spawn_id ||
    readiness.launch_id !== spawn.launch_id ||
    readiness.session_binding_ref !== spawn.session_binding_ref ||
    readiness.requiresDaemonGate !== true ||
    readiness.runtimeTruthSource !== "daemon-runtime"
  ) {
    throw terminalAttachError({
      status: 403,
      code: "harness_session_terminal_attach_readiness_boundary_invalid",
      message:
        "Harness session terminal attach requires readiness for the same daemon-gated spawn.",
      details: {
        decision: readiness.decision ?? null,
        readiness_state: readiness.readiness_state ?? null,
        readiness_spawn_id: readiness.spawn_id ?? null,
        spawn_id: spawn.spawn_id ?? null,
        readiness_launch_id: readiness.launch_id ?? null,
        launch_id: spawn.launch_id ?? null,
      },
    });
  }
  return readiness;
}

function terminalAttachError({ status, code, message, details }) {
  return runtimeError({ status, code, message, details });
}
