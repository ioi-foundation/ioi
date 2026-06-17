import assert from "node:assert/strict";
import test from "node:test";

import {
  buildHarnessContainerInvocation,
  executeHarnessContainerLane,
} from "./runtime-harness-container-executor.mjs";
import { planHarnessAdapterContainerLane } from "./runtime-harness-container-lane.mjs";

function containerLaneRequest(overrides = {}) {
  return {
    selection_ref: "agent-harness-adapter:generic_cli",
    adapter_id: "generic_cli",
    runtime: "docker",
    container_image_ref: "container-image:generic-cli:local",
    command_argv: [
      "harness-adapter",
      "run",
      "generic_cli",
      "--fixture",
      "harness-testbed:public-code-edit-fixture",
    ],
    mounts: [
      {
        mount_ref: "mount:public-trunk",
        source_ref: "artifact://workspace/public-trunk",
        target_path: "/workspace",
        access: "read_only",
        custody: "public_trunk",
      },
      {
        mount_ref: "mount:scratch",
        source_ref: "artifact://workspace/scratch",
        target_path: "/scratch",
        access: "read_write_scratch",
        custody: "redacted_projection",
      },
    ],
    network_policy: "disabled",
    env_policy_ref: "env-policy:harness-adapter/no-plaintext-env",
    authority_scope_refs: ["scope:workspace.read", "scope:workspace.patch"],
    privacy_posture_ref: "privacy-posture:public-trunk",
    receipt_policy_ref: "receipt-policy:harness-adapter/container",
    ...overrides,
  };
}

function executorDeps(overrides = {}) {
  return {
    resolveContainerImageRef: (imageRef) =>
      imageRef === "container-image:generic-cli:local"
        ? "ghcr.io/ioi/harness-generic-cli:test"
        : null,
    resolveMountSourceRef: (sourceRef) => {
      if (sourceRef === "artifact://workspace/public-trunk") {
        return "/tmp/ioi-harness/public-trunk";
      }
      if (sourceRef === "artifact://workspace/scratch") {
        return "/tmp/ioi-harness/scratch";
      }
      return null;
    },
    ...overrides,
  };
}

test("container executor builds a docker invocation only from daemon-resolved source refs", () => {
  const command_argv = containerLaneRequest().command_argv;
  const plan = planHarnessAdapterContainerLane(containerLaneRequest(), {
    nowIso: () => "2026-06-17T14:00:00.000Z",
  });
  const invocation = buildHarnessContainerInvocation(
    { plan, command_argv },
    executorDeps(),
  );

  assert.equal(
    invocation.schema_version,
    "ioi.hypervisor.harness_container_invocation.v1",
  );
  assert.equal(invocation.runtimeTruthSource, "daemon-runtime");
  assert.equal(invocation.requiresDaemonGate, true);
  assert.deepEqual(invocation.argv.slice(0, 5), [
    "docker",
    "run",
    "--rm",
    "--network",
    "none",
  ]);
  assert.ok(invocation.argv.includes("ghcr.io/ioi/harness-generic-cli:test"));
  assert.ok(
    invocation.argv.includes(
      "type=bind,source=/tmp/ioi-harness/public-trunk,target=/workspace,readonly",
    ),
  );
  assert.ok(
    invocation.argv.includes(
      "type=bind,source=/tmp/ioi-harness/scratch,target=/scratch",
    ),
  );
  assert.equal(invocation.command_argv_hash, plan.command_argv_hash);
});

test("container executor rejects command hash mismatch, unresolved images, unresolved mounts, and live allowlist networking", () => {
  const command_argv = containerLaneRequest().command_argv;
  const plan = planHarnessAdapterContainerLane(containerLaneRequest(), {
    nowIso: () => "2026-06-17T14:00:00.000Z",
  });

  assert.throws(
    () =>
      buildHarnessContainerInvocation(
        { plan, command_argv: ["harness-adapter", "run", "generic_cli"] },
        executorDeps(),
      ),
    /must match the daemon-planned argv hash/,
  );

  assert.throws(
    () =>
      buildHarnessContainerInvocation(
        { plan, command_argv },
        executorDeps({ resolveContainerImageRef: () => "container-image:still-abstract" }),
      ),
    /must resolve to a concrete runtime image/,
  );

  assert.throws(
    () =>
      buildHarnessContainerInvocation(
        { plan, command_argv },
        executorDeps({ resolveMountSourceRef: () => null }),
      ),
    /source refs must resolve to non-root absolute paths/,
  );

  assert.throws(
    () =>
      buildHarnessContainerInvocation(
        { plan, command_argv },
        executorDeps({ resolveRuntimeBinary: () => "sh" }),
      ),
    /must resolve to a docker\/podman binary name/,
  );

  const allowlistPlan = planHarnessAdapterContainerLane(
    containerLaneRequest({ network_policy: "allowlist" }),
    { nowIso: () => "2026-06-17T14:00:00.000Z" },
  );
  assert.throws(
    () =>
      buildHarnessContainerInvocation(
        { plan: allowlistPlan, command_argv },
        executorDeps(),
      ),
    /requires disabled networking/,
  );
});

test("container executor returns daemon receipts with output hashes, not plaintext output", async () => {
  const command_argv = containerLaneRequest().command_argv;
  const plan = planHarnessAdapterContainerLane(containerLaneRequest(), {
    nowIso: () => "2026-06-17T14:00:00.000Z",
  });
  const calls = [];
  const result = await executeHarnessContainerLane(
    { plan, command_argv },
    executorDeps({
      nowIso: (() => {
        const times = [
          "2026-06-17T14:01:00.000Z",
          "2026-06-17T14:02:00.000Z",
        ];
        return () => times.shift() ?? "2026-06-17T14:03:00.000Z";
      })(),
      runProcess: async (command, args, options) => {
        calls.push({ command, args, options });
        return {
          exit_code: 0,
          stdout: "fixture output with no secrets",
          stderr: "",
        };
      },
    }),
  );

  assert.equal(calls.length, 1);
  assert.equal(calls[0].command, "docker");
  assert.equal(result.exit_status, "success");
  assert.equal(result.exit_code, 0);
  assert.match(result.stdout_sha256, /^[0-9a-f]{64}$/);
  assert.equal(result.receipt.exit_status, "success");
  assert.equal(result.receipt.runtimeTruthSource, "daemon-runtime");
  assert.deepEqual(result.receipt.agentgres_operation_refs, [
    `agentgres://operation/harness-container/${plan.plan_id.replace(/[^a-zA-Z0-9_.-]+/g, "_")}`,
  ]);
  assert.ok(
    result.receipt.artifact_refs.every((ref) =>
      ref.startsWith("artifact://harness-container/"),
    ),
  );
  assert.doesNotMatch(
    JSON.stringify(result.receipt),
    /fixture output with no secrets/,
  );
});
