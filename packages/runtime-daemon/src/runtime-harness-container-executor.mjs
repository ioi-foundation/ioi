import crypto from "node:crypto";
import { spawn } from "node:child_process";
import path from "node:path";

import {
  buildHarnessContainerLaneReceipt,
  HARNESS_CONTAINER_LANE_PLAN_SCHEMA_VERSION,
  hashHarnessCommandArgv,
} from "./runtime-harness-container-lane.mjs";
import { runtimeError } from "./runtime-http-utils.mjs";
import { normalizeArray, objectRecord, optionalString, safeId } from "./runtime-value-helpers.mjs";

export const HARNESS_CONTAINER_INVOCATION_SCHEMA_VERSION =
  "ioi.hypervisor.harness_container_invocation.v1";

const MAX_OUTPUT_BYTES = 64 * 1024;

export function buildHarnessContainerInvocation(input = {}, deps = {}) {
  const plan = requireContainerLanePlan(input.plan);
  const commandArgv = normalizeExecutionArgv(input.command_argv);
  const commandArgvHash = hashHarnessCommandArgv(commandArgv);

  if (commandArgvHash !== plan.command_argv_hash) {
    throw runtimeError({
      status: 409,
      code: "harness_container_executor_command_hash_mismatch",
      message:
        "Harness container execution command argv must match the daemon-planned argv hash.",
      details: {
        plan_id: plan.plan_id,
        expected: plan.command_argv_hash,
        actual: commandArgvHash,
      },
    });
  }

  if (plan.network_policy !== "disabled") {
    throw runtimeError({
      status: 403,
      code: "harness_container_executor_network_policy_not_mounted",
      message:
        "Live harness container execution currently requires disabled networking unless a daemon egress proxy is mounted.",
      details: {
        plan_id: plan.plan_id,
        network_policy: plan.network_policy,
        required_mount: "daemon_egress_proxy",
      },
    });
  }

  const runtimeBinary = resolveRuntimeBinary(plan.runtime, deps);
  const image = resolveContainerImageRef(plan.container_image_ref, deps);
  const mounts = plan.mounts.map((mount) => resolveMount(mount, deps));
  const args = [
    "run",
    "--rm",
    "--network",
    "none",
    "--label",
    `ioi.hypervisor.plan_id=${plan.plan_id}`,
    "--label",
    `ioi.hypervisor.adapter_id=${plan.adapter_id}`,
    "--label",
    `ioi.hypervisor.runtime_truth=daemon-runtime`,
  ];

  for (const mount of mounts) {
    args.push("--mount", mount.docker_mount_spec);
  }

  args.push(image, ...commandArgv);

  return {
    schema_version: HARNESS_CONTAINER_INVOCATION_SCHEMA_VERSION,
    plan_id: plan.plan_id,
    selection_ref: plan.selection_ref,
    adapter_id: plan.adapter_id,
    runtime: plan.runtime,
    runtime_binary: runtimeBinary,
    container_image_ref: plan.container_image_ref,
    resolved_image: image,
    command_argv_hash: commandArgvHash,
    mount_refs: mounts.map((mount) => mount.mount_ref),
    network_policy: plan.network_policy,
    argv: [runtimeBinary, ...args],
    requiresDaemonGate: true,
    runtimeTruthSource: "daemon-runtime",
  };
}

export async function executeHarnessContainerLane(input = {}, deps = {}) {
  const invocation = buildHarnessContainerInvocation(input, deps);
  const nowIso = deps.nowIso ?? (() => new Date().toISOString());
  const runProcess = deps.runProcess ?? runProcessWithSpawn;
  const startedAt = nowIso();
  const result = await runProcess(invocation.argv[0], invocation.argv.slice(1), {
    timeout_ms: input.timeout_ms ?? deps.timeout_ms ?? 120_000,
    max_output_bytes: input.max_output_bytes ?? deps.max_output_bytes ?? MAX_OUTPUT_BYTES,
    plan_id: invocation.plan_id,
  });
  const exitCode = Number.isFinite(result?.exit_code)
    ? Number(result.exit_code)
    : Number.isFinite(result?.status)
      ? Number(result.status)
      : 1;
  const stdoutHash = hashOutput(result?.stdout ?? "");
  const stderrHash = hashOutput(result?.stderr ?? "");
  const finishedAt = nowIso();
  const receipt = buildHarnessContainerLaneReceipt(input.plan, {
    exit_status: exitCode === 0 ? "success" : "failure",
    exit_code: exitCode,
    agentgres_operation_refs: [
      `agentgres://operation/harness-container/${safeId(invocation.plan_id)}`,
    ],
    artifact_refs: [
      `artifact://harness-container/${safeId(invocation.plan_id)}/stdout/${stdoutHash}`,
      `artifact://harness-container/${safeId(invocation.plan_id)}/stderr/${stderrHash}`,
    ],
    created_at: finishedAt,
  });

  return {
    exit_status: receipt.exit_status,
    exit_code: receipt.exit_code,
    started_at: startedAt,
    finished_at: finishedAt,
    stdout_sha256: stdoutHash,
    stderr_sha256: stderrHash,
    agentgres_operation_refs: receipt.agentgres_operation_refs,
    artifact_refs: receipt.artifact_refs,
    invocation,
    receipt,
  };
}

function requireContainerLanePlan(value) {
  const plan = objectRecord(value);
  if (!plan || plan.schema_version !== HARNESS_CONTAINER_LANE_PLAN_SCHEMA_VERSION) {
    throw runtimeError({
      status: 400,
      code: "harness_container_executor_plan_required",
      message: "Harness container execution requires a canonical daemon-planned lane.",
      details: { expected_schema_version: HARNESS_CONTAINER_LANE_PLAN_SCHEMA_VERSION },
    });
  }
  return plan;
}

function normalizeExecutionArgv(value) {
  const argv = normalizeArray(value).map((part) => String(part));
  if (argv.length === 0) {
    throw runtimeError({
      status: 400,
      code: "harness_container_executor_argv_required",
      message: "Harness container execution requires the planned command argv.",
      details: {},
    });
  }
  for (const part of argv) {
    if (!part.trim() || /token|secret|password|authorization|api[-_]?key/i.test(part)) {
      throw runtimeError({
        status: 400,
        code: "harness_container_executor_argv_invalid",
        message: "Harness container execution argv must be non-empty and secret-free.",
        details: {},
      });
    }
  }
  return argv;
}

function resolveRuntimeBinary(runtime, deps) {
  const resolver = deps.resolveRuntimeBinary;
  const resolved = typeof resolver === "function" ? resolver(runtime) : runtime;
  const binary = optionalString(resolved);
  if (
    !binary ||
    binary.includes("/") ||
    binary.includes("\\") ||
    !["docker", "podman"].includes(binary)
  ) {
    throw runtimeError({
      status: 400,
      code: "harness_container_executor_runtime_binary_invalid",
      message: "Harness container runtime must resolve to a docker/podman binary name.",
      details: { runtime },
    });
  }
  return binary;
}

function resolveContainerImageRef(containerImageRef, deps) {
  const resolver = deps.resolveContainerImageRef;
  if (typeof resolver !== "function") {
    throw runtimeError({
      status: 424,
      code: "harness_container_executor_image_resolver_required",
      message:
        "Harness container execution requires a daemon image resolver; abstract image refs are not executable.",
      details: { container_image_ref: containerImageRef },
    });
  }
  const image = optionalString(resolver(containerImageRef));
  if (!image || image.startsWith("container-image:")) {
    throw runtimeError({
      status: 424,
      code: "harness_container_executor_image_unresolved",
      message: "Harness container image refs must resolve to a concrete runtime image.",
      details: { container_image_ref: containerImageRef },
    });
  }
  return image;
}

function resolveMount(mount, deps) {
  const resolver = deps.resolveMountSourceRef;
  if (typeof resolver !== "function") {
    throw runtimeError({
      status: 424,
      code: "harness_container_executor_mount_resolver_required",
      message: "Harness container execution requires a daemon source-ref mount resolver.",
      details: { mount_ref: mount.mount_ref, source_ref: mount.source_ref },
    });
  }
  const hostPath = optionalString(resolver(mount.source_ref, mount));
  if (!hostPath || !path.isAbsolute(hostPath) || hostPath === "/") {
    throw runtimeError({
      status: 424,
      code: "harness_container_executor_mount_unresolved",
      message: "Harness container source refs must resolve to non-root absolute paths.",
      details: { mount_ref: mount.mount_ref, source_ref: mount.source_ref },
    });
  }
  if (isContainerSocketPath(hostPath)) {
    throw runtimeError({
      status: 403,
      code: "harness_container_executor_socket_mount_blocked",
      message: "Harness container execution cannot mount host container sockets.",
      details: { mount_ref: mount.mount_ref },
    });
  }
  const readonly = mount.access === "read_only" ? ",readonly" : "";
  return {
    mount_ref: mount.mount_ref,
    docker_mount_spec: `type=bind,source=${hostPath},target=${mount.target_path}${readonly}`,
  };
}

function isContainerSocketPath(value) {
  return [
    "/var/run/docker.sock",
    "/run/docker.sock",
    "/run/podman/podman.sock",
  ].includes(value);
}

function hashOutput(value) {
  return crypto.createHash("sha256").update(String(value)).digest("hex");
}

function runProcessWithSpawn(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      stdio: ["ignore", "pipe", "pipe"],
      env: {},
    });
    let stdout = "";
    let stderr = "";
    const maxOutputBytes = options.max_output_bytes ?? MAX_OUTPUT_BYTES;
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(
        runtimeError({
          status: 504,
          code: "harness_container_executor_timeout",
          message: "Harness container execution exceeded the daemon timeout.",
          details: { plan_id: options.plan_id },
        }),
      );
    }, options.timeout_ms ?? 120_000);
    const append = (current, chunk) =>
      `${current}${chunk.toString("utf8")}`.slice(-maxOutputBytes);
    child.stdout.on("data", (chunk) => {
      stdout = append(stdout, chunk);
    });
    child.stderr.on("data", (chunk) => {
      stderr = append(stderr, chunk);
    });
    child.on("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.on("close", (exitCode) => {
      clearTimeout(timer);
      resolve({ exit_code: exitCode ?? 1, stdout, stderr });
    });
  });
}
