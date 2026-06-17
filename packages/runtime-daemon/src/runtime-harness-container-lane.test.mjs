import assert from "node:assert/strict";
import test from "node:test";

import {
  HARNESS_CONTAINER_LANE_PLAN_SCHEMA_VERSION,
  HARNESS_CONTAINER_LANE_RECEIPT_SCHEMA_VERSION,
  buildHarnessContainerLaneReceipt,
  planHarnessAdapterContainerLane,
} from "./runtime-harness-container-lane.mjs";

function containerLaneRequest(overrides = {}) {
  return {
    selection_ref: "agent-harness-adapter:deepseek_tui",
    adapter_id: "deepseek_tui",
    runtime: "docker",
    container_image_ref: "container-image:deepseek-tui:local",
    command_argv: [
      "harness-adapter",
      "run",
      "deepseek_tui",
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

test("container lane plan produces a not-executed receipt with image, argv hash, mounts, network policy, and exit status", () => {
  const plan = planHarnessAdapterContainerLane(containerLaneRequest(), {
    nowIso: () => "2026-06-17T12:00:00.000Z",
  });

  assert.equal(plan.schema_version, HARNESS_CONTAINER_LANE_PLAN_SCHEMA_VERSION);
  assert.equal(plan.selection_ref, "agent-harness-adapter:deepseek_tui");
  assert.equal(plan.runtime, "docker");
  assert.equal(plan.container_image_ref, "container-image:deepseek-tui:local");
  assert.match(plan.command_argv_hash, /^sha256:[0-9a-f]{64}$/);
  assert.deepEqual(plan.mounts.map((mount) => mount.mount_ref), [
    "mount:public-trunk",
    "mount:scratch",
  ]);
  assert.equal(plan.network_policy, "disabled");
  assert.equal(plan.requiresDaemonGate, true);
  assert.equal(plan.runtimeTruthSource, "daemon-runtime");

  assert.equal(
    plan.receipt.schema_version,
    HARNESS_CONTAINER_LANE_RECEIPT_SCHEMA_VERSION,
  );
  assert.equal(plan.receipt.container_image_ref, plan.container_image_ref);
  assert.equal(plan.receipt.command_argv_hash, plan.command_argv_hash);
  assert.deepEqual(plan.receipt.mounts, plan.mounts);
  assert.equal(plan.receipt.network_policy, "disabled");
  assert.equal(plan.receipt.exit_status, "not_executed");
  assert.equal(plan.receipt.exit_code, null);
  assert.deepEqual(plan.receipt.authority_scope_refs, [
    "scope:workspace.read",
    "scope:workspace.patch",
  ]);
});

test("container lane receipt can record executed exit status without changing the plan hash", () => {
  const plan = planHarnessAdapterContainerLane(containerLaneRequest(), {
    nowIso: () => "2026-06-17T12:00:00.000Z",
  });
  const receipt = buildHarnessContainerLaneReceipt(plan, {
    exit_status: "success",
    exit_code: 0,
    agentgres_operation_refs: ["agentgres://operation/harness-container-run"],
    artifact_refs: ["artifact://harness-container/stdout"],
    created_at: "2026-06-17T12:01:00.000Z",
  });

  assert.equal(receipt.plan_id, plan.plan_id);
  assert.equal(receipt.command_argv_hash, plan.command_argv_hash);
  assert.equal(receipt.exit_status, "success");
  assert.equal(receipt.exit_code, 0);
  assert.deepEqual(receipt.agentgres_operation_refs, [
    "agentgres://operation/harness-container-run",
  ]);
  assert.deepEqual(receipt.artifact_refs, ["artifact://harness-container/stdout"]);
});

test("container lane argv hash is deterministic and changes when argv changes", () => {
  const first = planHarnessAdapterContainerLane(containerLaneRequest(), {
    nowIso: () => "2026-06-17T12:00:00.000Z",
  });
  const second = planHarnessAdapterContainerLane(containerLaneRequest(), {
    nowIso: () => "2026-06-17T12:02:00.000Z",
  });
  const changed = planHarnessAdapterContainerLane(
    containerLaneRequest({
      command_argv: [
        "harness-adapter",
        "run",
        "deepseek_tui",
        "--fixture",
        "harness-testbed:different",
      ],
    }),
    { nowIso: () => "2026-06-17T12:00:00.000Z" },
  );

  assert.equal(first.command_argv_hash, second.command_argv_hash);
  assert.notEqual(first.command_argv_hash, changed.command_argv_hash);
});

test("container lane blocks cTEE/private, plaintext, host path, socket, env, and secret argv shortcuts", () => {
  assert.throws(
    () =>
      planHarnessAdapterContainerLane(
        containerLaneRequest({
          mounts: [
            {
              source_ref: "artifact://workspace/private",
              target_path: "/workspace",
              access: "read_only",
              custody: "ctee_private_workspace",
            },
          ],
        }),
      ),
    /External container harnesses cannot mount plaintext or cTEE private workspace custody/,
  );

  assert.throws(
    () =>
      planHarnessAdapterContainerLane(
        containerLaneRequest({
          mounts: [
            {
              source_path: "/home/user/project",
              source_ref: "artifact://workspace/public-trunk",
              target_path: "/workspace",
              access: "read_only",
              custody: "public_trunk",
            },
          ],
        }),
      ),
    /source refs, not raw host paths/,
  );

  assert.throws(
    () =>
      planHarnessAdapterContainerLane(
        containerLaneRequest({
          mounts: [
            {
              source_ref: "artifact://workspace/public-trunk",
              target_path: "/var/run/docker.sock",
              access: "read_only",
              custody: "public_trunk",
            },
          ],
        }),
      ),
    /cannot mount host container sockets/,
  );

  assert.throws(
    () =>
      planHarnessAdapterContainerLane(
        containerLaneRequest({
          env: { API_TOKEN: "secret" },
        }),
      ),
    /must pass environment by env_policy_ref/,
  );

  assert.throws(
    () =>
      planHarnessAdapterContainerLane(
        containerLaneRequest({
          command_argv: ["harness-adapter", "--api-key", "secret"],
        }),
      ),
    /must pass secrets by policy refs/,
  );
});

test("container lane allows Podman and rejects host-network style policies", () => {
  const podman = planHarnessAdapterContainerLane(
    containerLaneRequest({ runtime: "podman", network_policy: "allowlist" }),
    { nowIso: () => "2026-06-17T12:00:00.000Z" },
  );
  assert.equal(podman.runtime, "podman");
  assert.equal(podman.network_policy, "allowlist");

  assert.throws(
    () => planHarnessAdapterContainerLane(containerLaneRequest({ network_policy: "host" })),
    /disabled or allowlist network policy/,
  );
});
