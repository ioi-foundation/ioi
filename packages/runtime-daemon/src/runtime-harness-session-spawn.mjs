import path from "node:path";

import { runtimeError } from "./runtime-http-utils.mjs";
import {
  normalizeArray,
  objectRecord,
  optionalString,
  safeId,
  uniqueStrings,
} from "./runtime-value-helpers.mjs";
import {
  buildHypervisorEnvironmentStatus,
  deriveWorkspaceInitializer,
} from "./runtime-environment-status-projection.mjs";

export const HARNESS_SESSION_SPAWN_SCHEMA_VERSION =
  "ioi.runtime.harness_session_spawn.v1";

const LAUNCH_SCHEMA_VERSION = "ioi.runtime.harness_session_launch.v1";

export function buildHarnessSessionSpawn(request = {}, deps = {}) {
  const nowIso = deps.nowIso ?? (() => new Date().toISOString());
  const launch = requireLaunch(request.session_launch);
  const workspaceRoot = resolveWorkspaceRoot({
    workspaceRoot: optionalString(request.workspace_root),
    defaultWorkspaceRoot: optionalString(deps.defaultWorkspaceRoot),
    baseWorkspaceRoot: optionalString(deps.baseWorkspaceRoot),
  });
  const modelName = resolveModelName({
    requestedModelName: optionalString(request.model_name),
    modelEnv: launch.command_contract.model_env,
    modelDefault: launch.model_mount_contract.model_default,
    env: deps.env ?? process.env,
  });
  const exampleScriptPath = resolveExampleScriptPath({
    exampleScriptRef: optionalString(launch.command_contract.example_script_ref),
    baseWorkspaceRoot: optionalString(deps.baseWorkspaceRoot),
  });
  const argv = resolveArgvTemplate({
    argvTemplate: normalizeArray(launch.command_contract.argv_template),
    workspaceEnv: launch.command_contract.workspace_env,
    workspaceRoot,
    modelEnv: launch.command_contract.model_env,
    modelName,
    exampleScriptEnv: launch.command_contract.example_script_env,
    exampleScriptPath,
  });
  const readinessProbeArgv = resolveArgvTemplate({
    argvTemplate: normalizeArray(
      launch.command_contract.readiness_probe_argv_template,
    ),
    workspaceEnv: launch.command_contract.workspace_env,
    workspaceRoot,
    modelEnv: launch.command_contract.model_env,
    modelName,
    exampleScriptEnv: launch.command_contract.example_script_env,
    exampleScriptPath,
  });
  const spawnId =
    optionalString(request.spawn_id) ??
    `harness-session-spawn:${safeId(launch.launch_id)}`;
  const receiptRef =
    optionalString(request.spawn_receipt_ref) ??
    `receipt://harness-session-spawn/${safeId(spawnId)}`;

  // Phase 1: project the canonical environment status object. When the route
  // injected a real workspace provision, its transitions + artifact ref drive
  // the status; otherwise a ready snapshot is derived from the resolved
  // workspace root and custody posture. The flat environment_lifecycle_steps
  // remain in the session-operations projection; this is the structured object.
  const provision = objectRecord(request.workspace_provision);
  const workspaceInitializer =
    objectRecord(provision?.initializer) ??
    deriveWorkspaceInitializer({
      workspaceMountPolicy: launch.workspace_mount_policy,
      authorityScopeRefs: launch.authority_scope_refs,
    });
  const workspaceArtifactRef =
    optionalString(provision?.workspace_artifact_ref) ??
    `agentgres://artifact/workspace/${safeId(spawnId)}`;
  const environmentStatus = buildHypervisorEnvironmentStatus({
    environmentRef: `environment:${safeId(launch.session_route_ref)}`,
    workspaceRoot,
    workspaceMountPolicy: launch.workspace_mount_policy,
    initializerRef: workspaceInitializer.initializer_ref,
    modelRouteRef: launch.model_route_ref,
    harnessSessionRef: spawnId,
    stateRootRef: `agentgres://state-root/environment-status/${safeId(spawnId)}`,
    workspaceArtifactRef,
    componentPhases: objectRecord(provision?.components),
  });

  return {
    schema_version: HARNESS_SESSION_SPAWN_SCHEMA_VERSION,
    spawn_id: spawnId,
    decision: "admitted",
    spawn_state: "ready_for_client_pty_attach",
    spawn_lane: "host_terminal_session",
    launch_id: launch.launch_id,
    session_binding_ref: launch.session_binding_ref,
    session_route_ref: launch.session_route_ref,
    harness_selection_ref: launch.harness_selection_ref,
    agent_harness_adapter_id: launch.agent_harness_adapter_id,
    model_configuration_ref: launch.model_configuration_ref,
    model_route_ref: launch.model_route_ref,
    model_name: modelName,
    workspace_ref: launch.workspace_ref,
    workspace_root: workspaceRoot,
    workspace_initializer: workspaceInitializer,
    workspace_artifact_ref: workspaceArtifactRef,
    environment_status: environmentStatus,
    terminal_session_ref: launch.terminal_session_ref,
    command_contract_ref: launch.command_contract.command_ref,
    command_contract: {
      ...launch.command_contract,
      resolved_argv: argv,
      readiness_probe_argv:
        readinessProbeArgv.length > 0
          ? readinessProbeArgv
          : [launch.command_contract.binary_name, "--help"],
      resolved_command_line: shellQuote(argv),
      pty_transport: "hypervisor_client_terminal_adapter",
      process_custody: "client_host_pty_after_daemon_spawn_admission",
    },
    terminal_attach_contract: {
      root: workspaceRoot,
      cols: 120,
      rows: 32,
      command_line: shellQuote(argv),
      requires_pty: true,
      launch_after_attach: true,
    },
    model_mount_contract: launch.model_mount_contract,
    workspace_mount_policy: launch.workspace_mount_policy,
    privacy_posture_ref: launch.privacy_posture_ref,
    authority_scope_refs: normalizeArray(launch.authority_scope_refs),
    receipt_policy_ref: launch.receipt_policy_ref,
    receipt_refs: uniqueStrings([
      ...normalizeArray(launch.receipt_refs),
      receiptRef,
    ]),
    agentgres_operation_refs: uniqueStrings([
      ...normalizeArray(launch.agentgres_operation_refs),
      `agentgres://operation/harness-session-spawn/${safeId(spawnId)}`,
    ]),
    state_root: `agentgres://state-root/harness-session-spawn/${safeId(
      spawnId,
    )}`,
    spawned_at: optionalString(request.spawned_at) ?? nowIso(),
    requiresDaemonGate: true,
    runtimeTruthSource: "daemon-runtime",
    spawn_invariant:
      "A host harness process may attach only through the daemon-resolved command contract, local model mount, workspace root, authority scopes, receipts, and client PTY transport recorded in this spawn object.",
  };
}

function requireLaunch(value) {
  const launch = objectRecord(value);
  if (!launch || launch.schema_version !== LAUNCH_SCHEMA_VERSION) {
    throw spawnError({
      status: 400,
      code: "harness_session_spawn_launch_required",
      message: "Harness session spawn requires an admitted launch contract.",
      details: { expected_schema_version: LAUNCH_SCHEMA_VERSION },
    });
  }
  if (
    launch.decision !== "admitted" ||
    launch.launch_state !== "ready_to_spawn" ||
    launch.requiresDaemonGate !== true ||
    launch.runtimeTruthSource !== "daemon-runtime"
  ) {
    throw spawnError({
      status: 403,
      code: "harness_session_spawn_launch_boundary_invalid",
      message:
        "Harness session spawn requires a daemon-gated launch contract ready to spawn.",
      details: {
        decision: launch.decision ?? null,
        launch_state: launch.launch_state ?? null,
        requiresDaemonGate: launch.requiresDaemonGate ?? null,
        runtimeTruthSource: launch.runtimeTruthSource ?? null,
      },
    });
  }
  const supportedBinaryNames = [
    "codex",
    "deepseek",
    "claude-code-example",
    "generic-cli-local",
  ];
  if (
    launch.launch_lane !== "host_dev_pty" ||
    !supportedBinaryNames.includes(launch.command_contract?.binary_name) ||
    launch.command_contract?.requires_pty !== true ||
    launch.command_contract?.secret_release_policy !== "none"
  ) {
    throw spawnError({
      status: 403,
      code: "harness_session_spawn_contract_unsupported",
      message:
        "Only secret-free Codex OSS, DeepSeek TUI, Claude Code example, and generic CLI host PTY launch contracts can be spawned in this slice.",
      details: {
        launch_lane: launch.launch_lane ?? null,
        binary_name: launch.command_contract?.binary_name ?? null,
        requires_pty: launch.command_contract?.requires_pty ?? null,
        secret_release_policy:
          launch.command_contract?.secret_release_policy ?? null,
      },
    });
  }
  return launch;
}

function resolveWorkspaceRoot({
  workspaceRoot,
  defaultWorkspaceRoot,
  baseWorkspaceRoot,
}) {
  const requested = workspaceRoot ?? defaultWorkspaceRoot;
  if (!requested) {
    throw spawnError({
      status: 400,
      code: "harness_session_spawn_workspace_root_required",
      message: "Harness session spawn requires a workspace root.",
      details: {},
    });
  }
  const root = path.isAbsolute(requested)
    ? path.normalize(requested)
    : path.resolve(baseWorkspaceRoot ?? process.cwd(), requested);
  if (root === path.parse(root).root) {
    throw spawnError({
      status: 403,
      code: "harness_session_spawn_workspace_root_forbidden",
      message: "Harness session spawn cannot attach to a filesystem root.",
      details: { workspace_root: root },
    });
  }
  return root;
}

function resolveModelName({ requestedModelName, modelEnv, modelDefault, env }) {
  const value =
    requestedModelName ??
    optionalString(env?.[modelEnv]) ??
    optionalString(modelDefault) ??
    "qwen";
  if (!/^[A-Za-z0-9._:/@+-]+$/.test(value)) {
    throw spawnError({
      status: 403,
      code: "harness_session_spawn_model_name_forbidden",
      message:
        "Harness session spawn model names must be shell-token safe and secret-free.",
      details: { model_name: value },
    });
  }
  return value;
}

function resolveArgvTemplate({
  argvTemplate,
  workspaceEnv,
  workspaceRoot,
  modelEnv,
  modelName,
  exampleScriptEnv,
  exampleScriptPath,
}) {
  if (argvTemplate.length === 0) {
    throw spawnError({
      status: 400,
      code: "harness_session_spawn_argv_required",
      message: "Harness session spawn requires a command argv template.",
      details: {},
    });
  }
  return argvTemplate.map((arg) => {
    const text = String(arg);
    if (text === `\${${workspaceEnv}}`) return workspaceRoot;
    if (text === `\${${modelEnv}}`) return modelName;
    if (exampleScriptEnv && text === `\${${exampleScriptEnv}}`) {
      return exampleScriptPath;
    }
    const modelDefaultPattern = new RegExp(
      `^\\$\\{${escapeRegex(modelEnv)}:-([^}]+)\\}$`,
    );
    const match = text.match(modelDefaultPattern);
    if (match) return modelName || match[1];
    return text;
  });
}

function resolveExampleScriptPath({ exampleScriptRef, baseWorkspaceRoot }) {
  if (!exampleScriptRef) return "";
  const scriptPath = path.isAbsolute(exampleScriptRef)
    ? path.normalize(exampleScriptRef)
    : path.resolve(baseWorkspaceRoot ?? process.cwd(), exampleScriptRef);
  if (scriptPath === path.parse(scriptPath).root) {
    throw spawnError({
      status: 403,
      code: "harness_session_spawn_example_script_forbidden",
      message: "Harness session spawn cannot use a filesystem root as a script.",
      details: { example_script_ref: exampleScriptRef },
    });
  }
  return scriptPath;
}

function shellQuote(argv) {
  return argv
    .map((arg) => {
      const text = String(arg);
      if (/^[A-Za-z0-9_./:@%+=,-]+$/.test(text)) return text;
      return `'${text.replaceAll("'", "'\\''")}'`;
    })
    .join(" ");
}

function escapeRegex(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function spawnError({ status, code, message, details }) {
  return runtimeError({
    status,
    code,
    message,
    details,
  });
}
