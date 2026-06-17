import crypto from "node:crypto";

import { runtimeError } from "./runtime-http-utils.mjs";
import { normalizeArray, objectRecord, optionalString, safeId } from "./runtime-value-helpers.mjs";

export const HARNESS_CONTAINER_LANE_PLAN_SCHEMA_VERSION =
  "ioi.hypervisor.harness_container_lane_plan.v1";
export const HARNESS_CONTAINER_LANE_RECEIPT_SCHEMA_VERSION =
  "ioi.hypervisor.harness_container_lane_receipt.v1";

const ALLOWED_RUNTIMES = new Set(["docker", "podman"]);
const ALLOWED_NETWORK_POLICIES = new Set(["disabled", "allowlist"]);
const ALLOWED_MOUNT_ACCESS = new Set(["read_only", "read_write_scratch"]);
const ALLOWED_MOUNT_CUSTODY = new Set(["public_trunk", "redacted_projection"]);
const BLOCKED_MOUNT_CUSTODY = new Set(["plain_workspace", "ctee_private_workspace"]);

export function planHarnessAdapterContainerLane(request = {}, deps = {}) {
  const nowIso = deps.nowIso ?? (() => new Date().toISOString());
  const createdAt = optionalString(request.created_at) ?? nowIso();
  const selectionRef = requiredString(request.selection_ref, "selection_ref");
  const adapterId = optionalString(request.adapter_id) ?? selectionRef.replace(/^agent-harness-adapter:/, "");
  const runtime = normalizeRuntime(request.runtime);
  const containerImageRef = requiredString(request.container_image_ref, "container_image_ref");
  const commandArgv = normalizeCommandArgv(request.command_argv);
  const commandArgvHash = hashHarnessCommandArgv(commandArgv);
  const mounts = normalizeMounts(request.mounts);
  const networkPolicy = normalizeNetworkPolicy(request.network_policy);
  const envPolicyRef = requiredString(request.env_policy_ref, "env_policy_ref");
  const authorityScopeRefs = uniqueStringRefs(request.authority_scope_refs);
  const privacyPostureRef =
    optionalString(request.privacy_posture_ref) ?? "privacy-posture:container-lane-pending-review";

  assertNoPlaintextEnv(request);
  assertNoContainerEscapeMount(mounts);

  const plan = {
    schema_version: HARNESS_CONTAINER_LANE_PLAN_SCHEMA_VERSION,
    plan_id: `harness-container-plan:${safeId(selectionRef)}:${commandArgvHash.slice(7, 23)}`,
    selection_ref: selectionRef,
    adapter_id: adapterId,
    runtime,
    container_image_ref: containerImageRef,
    command_argv_hash: commandArgvHash,
    command_argv_preview: redactCommandArgv(commandArgv),
    mounts,
    network_policy: networkPolicy,
    env_policy_ref: envPolicyRef,
    authority_scope_refs: authorityScopeRefs,
    privacy_posture_ref: privacyPostureRef,
    receipt_policy_ref:
      optionalString(request.receipt_policy_ref) ?? "receipt-policy:harness-adapter/container",
    created_at: createdAt,
    requiresDaemonGate: true,
    runtimeTruthSource: "daemon-runtime",
  };

  return {
    ...plan,
    receipt: buildHarnessContainerLaneReceipt(plan, {
      exit_status: "not_executed",
      created_at: createdAt,
      receipt_id: request.receipt_id,
    }),
  };
}

export function buildHarnessContainerLaneReceipt(plan, input = {}) {
  const record = objectRecord(plan);
  if (!record || record.schema_version !== HARNESS_CONTAINER_LANE_PLAN_SCHEMA_VERSION) {
    throw runtimeError({
      status: 400,
      code: "harness_container_lane_plan_required",
      message: "A HarnessContainerLaneReceipt requires a canonical container lane plan.",
      details: { expected_schema_version: HARNESS_CONTAINER_LANE_PLAN_SCHEMA_VERSION },
    });
  }
  const exitStatus = normalizeExitStatus(input.exit_status);
  const receiptId =
    optionalString(input.receipt_id) ??
    `receipt:harness-container-lane:${safeId(record.selection_ref)}:${record.command_argv_hash.slice(7, 23)}`;
  return {
    schema_version: HARNESS_CONTAINER_LANE_RECEIPT_SCHEMA_VERSION,
    receipt_id: receiptId,
    plan_id: record.plan_id,
    selection_ref: record.selection_ref,
    adapter_id: record.adapter_id,
    runtime: record.runtime,
    container_image_ref: record.container_image_ref,
    command_argv_hash: record.command_argv_hash,
    mounts: record.mounts,
    network_policy: record.network_policy,
    env_policy_ref: record.env_policy_ref,
    exit_status: exitStatus,
    exit_code: input.exit_code ?? null,
    authority_scope_refs: normalizeArray(record.authority_scope_refs),
    privacy_posture_ref: record.privacy_posture_ref,
    agentgres_operation_refs: normalizeArray(input.agentgres_operation_refs),
    artifact_refs: normalizeArray(input.artifact_refs),
    created_at: optionalString(input.created_at) ?? new Date().toISOString(),
    runtimeTruthSource: "daemon-runtime",
  };
}

function normalizeRuntime(value) {
  const runtime = optionalString(value) ?? "docker";
  if (!ALLOWED_RUNTIMES.has(runtime)) {
    throw runtimeError({
      status: 400,
      code: "harness_container_lane_runtime_invalid",
      message: "Harness container lanes currently support only Docker or Podman.",
      details: { runtime, allowed_runtimes: [...ALLOWED_RUNTIMES] },
    });
  }
  return runtime;
}

function normalizeNetworkPolicy(value) {
  const policy = optionalString(value) ?? "disabled";
  if (!ALLOWED_NETWORK_POLICIES.has(policy)) {
    throw runtimeError({
      status: 400,
      code: "harness_container_lane_network_policy_invalid",
      message: "Harness container lanes require an explicit disabled or allowlist network policy.",
      details: { network_policy: policy, allowed_network_policies: [...ALLOWED_NETWORK_POLICIES] },
    });
  }
  return policy;
}

function normalizeExitStatus(value) {
  const status = optionalString(value) ?? "not_executed";
  if (!["not_executed", "success", "failure", "blocked"].includes(status)) {
    throw runtimeError({
      status: 400,
      code: "harness_container_lane_exit_status_invalid",
      message: "Harness container lane receipts require a known exit status.",
      details: { exit_status: status },
    });
  }
  return status;
}

function normalizeCommandArgv(value) {
  const argv = normalizeArray(value).map((part) => String(part));
  if (argv.length === 0) {
    throw runtimeError({
      status: 400,
      code: "harness_container_lane_argv_required",
      message: "Harness container lanes require a non-empty command argv array.",
      details: {},
    });
  }
  for (const part of argv) {
    if (!part.trim()) {
      throw runtimeError({
        status: 400,
        code: "harness_container_lane_argv_invalid",
        message: "Harness container argv entries must be non-empty strings.",
        details: {},
      });
    }
    if (/token|secret|password|authorization|api[-_]?key/i.test(part)) {
      throw runtimeError({
        status: 400,
        code: "harness_container_lane_plaintext_secret_argv_blocked",
        message: "Harness container lanes must pass secrets by policy refs, not plaintext argv.",
        details: { blocked_arg_pattern: "secret-like argv" },
      });
    }
  }
  return argv;
}

function normalizeMounts(value) {
  const mounts = normalizeArray(value);
  if (mounts.length === 0) {
    throw runtimeError({
      status: 400,
      code: "harness_container_lane_mount_required",
      message: "Harness container lanes require explicit public or redacted mounts.",
      details: {},
    });
  }
  return mounts.map((mount, index) => normalizeMount(mount, index));
}

function normalizeMount(value, index) {
  const mount = objectRecord(value);
  if (!mount) {
    throw runtimeError({
      status: 400,
      code: "harness_container_lane_mount_invalid",
      message: "Harness container lane mounts must be objects.",
      details: { index },
    });
  }
  if (optionalString(mount.source_path)) {
    throw runtimeError({
      status: 400,
      code: "harness_container_lane_host_path_blocked",
      message: "Harness container lane mounts must use source refs, not raw host paths.",
      details: { index },
    });
  }
  const sourceRef = requiredString(mount.source_ref, `mounts[${index}].source_ref`);
  const targetPath = requiredString(mount.target_path, `mounts[${index}].target_path`);
  if (!targetPath.startsWith("/") || targetPath === "/") {
    throw runtimeError({
      status: 400,
      code: "harness_container_lane_target_path_invalid",
      message: "Harness container mount target paths must be absolute non-root paths.",
      details: { index, target_path: targetPath },
    });
  }
  const access = optionalString(mount.access) ?? "read_only";
  if (!ALLOWED_MOUNT_ACCESS.has(access)) {
    throw runtimeError({
      status: 400,
      code: "harness_container_lane_mount_access_invalid",
      message: "Harness container mounts may be read-only or scratch-write only.",
      details: { index, access, allowed_access: [...ALLOWED_MOUNT_ACCESS] },
    });
  }
  const custody = optionalString(mount.custody) ?? "public_trunk";
  if (BLOCKED_MOUNT_CUSTODY.has(custody)) {
    throw runtimeError({
      status: 403,
      code: "harness_container_lane_private_mount_blocked",
      message: "External container harnesses cannot mount plaintext or cTEE private workspace custody by default.",
      details: {
        index,
        custody,
        allowed_custody: [...ALLOWED_MOUNT_CUSTODY],
      },
    });
  }
  if (!ALLOWED_MOUNT_CUSTODY.has(custody)) {
    throw runtimeError({
      status: 400,
      code: "harness_container_lane_mount_custody_invalid",
      message: "Harness container lane mount custody must be public trunk or redacted projection.",
      details: { index, custody, allowed_custody: [...ALLOWED_MOUNT_CUSTODY] },
    });
  }
  return {
    mount_ref: optionalString(mount.mount_ref) ?? `mount:${safeId(sourceRef)}:${index}`,
    source_ref: sourceRef,
    target_path: targetPath,
    access,
    custody,
  };
}

function assertNoContainerEscapeMount(mounts) {
  const blockedTargets = new Set([
    "/var/run/docker.sock",
    "/run/podman/podman.sock",
    "/run/docker.sock",
  ]);
  for (const mount of mounts) {
    if (blockedTargets.has(mount.target_path)) {
      throw runtimeError({
        status: 403,
        code: "harness_container_lane_escape_mount_blocked",
        message: "Harness container lanes cannot mount host container sockets.",
        details: { target_path: mount.target_path },
      });
    }
  }
}

function assertNoPlaintextEnv(request) {
  const env = objectRecord(request.env);
  if (env && Object.keys(env).length > 0) {
    throw runtimeError({
      status: 400,
      code: "harness_container_lane_plaintext_env_blocked",
      message: "Harness container lanes must pass environment by env_policy_ref, not plaintext env maps.",
      details: { env_keys: Object.keys(env).sort() },
    });
  }
}

function requiredString(value, field) {
  const text = optionalString(value);
  if (!text) {
    throw runtimeError({
      status: 400,
      code: "harness_container_lane_required_field_missing",
      message: `Harness container lane is missing required field: ${field}.`,
      details: { field },
    });
  }
  return text;
}

function uniqueStringRefs(values) {
  return [...new Set(normalizeArray(values).map((value) => String(value)).filter(Boolean))];
}

export function hashHarnessCommandArgv(argv) {
  return `sha256:${crypto.createHash("sha256").update(JSON.stringify(argv)).digest("hex")}`;
}

function redactCommandArgv(argv) {
  return argv.map((part) =>
    /token|secret|password|authorization|api[-_]?key/i.test(part) ? "[REDACTED]" : part,
  );
}
