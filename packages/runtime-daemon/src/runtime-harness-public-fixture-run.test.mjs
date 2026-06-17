import assert from "node:assert/strict";
import test from "node:test";

import {
  HARNESS_PUBLIC_FIXTURE_RUN_SCHEMA_VERSION,
  runHarnessPublicFixtureRun,
} from "./runtime-harness-public-fixture-run.mjs";

function fixtureRequest(overrides = {}) {
  return {
    installed_adapter_ids: ["deepseek_tui", "generic_cli"],
    candidate_lanes: [
      {
        adapter_id: "deepseek_tui",
        selection_ref: "agent-harness-adapter:deepseek_tui",
        runtime: "docker",
        container_image_ref: "container-image:deepseek-tui:local",
      },
      {
        adapter_id: "generic_cli",
        selection_ref: "agent-harness-adapter:generic_cli",
        runtime: "docker",
        container_image_ref: "container-image:generic-cli:local",
      },
      {
        adapter_id: "aider_cli",
        selection_ref: "agent-harness-adapter:aider_cli",
        runtime: "docker",
        container_image_ref: "container-image:aider-cli:local",
      },
    ],
    ...overrides,
  };
}

test("public fixture run executes the same fixture through two installed adapters under daemon gates", async () => {
  const executed = [];
  const run = await runHarnessPublicFixtureRun(fixtureRequest(), {
    nowIso: () => "2026-06-17T13:00:00.000Z",
    executeContainerLane: async ({ plan, fixture_id, task_ref }) => {
      executed.push({ plan, fixture_id, task_ref });
      return {
        exit_status: "success",
        exit_code: 0,
        agentgres_operation_refs: [
          `agentgres://operation/${plan.adapter_id}/public-fixture`,
        ],
        artifact_refs: [`artifact://harness-fixture/${plan.adapter_id}/stdout`],
        created_at: "2026-06-17T13:01:00.000Z",
      };
    },
  });

  assert.equal(run.schema_version, HARNESS_PUBLIC_FIXTURE_RUN_SCHEMA_VERSION);
  assert.equal(run.fixture_id, "harness-testbed:public-code-edit-fixture");
  assert.equal(run.task_ref, "task:fixture/public-code-edit-fixture");
  assert.equal(run.requiresDaemonGate, true);
  assert.equal(run.runtimeTruthSource, "daemon-runtime");
  assert.deepEqual(run.candidate_selection_refs, [
    "agent-harness-adapter:deepseek_tui",
    "agent-harness-adapter:generic_cli",
  ]);
  assert.equal(executed.length, 2);
  assert.deepEqual(
    executed.map((item) => item.fixture_id),
    [
      "harness-testbed:public-code-edit-fixture",
      "harness-testbed:public-code-edit-fixture",
    ],
  );
  assert.deepEqual(
    run.attempts.map((attempt) => attempt.exit_status),
    ["success", "success"],
  );
  assert.deepEqual(
    run.attempts.map((attempt) => attempt.network_policy),
    ["disabled", "disabled"],
  );
  assert.ok(
    run.attempts.every((attempt) =>
      attempt.mounts.every((mount) =>
        ["public_trunk", "redacted_projection"].includes(mount.custody),
      ),
    ),
  );
  assert.deepEqual(run.receipt_refs, run.attempts.map((attempt) => attempt.receipt_id));
  assert.equal(
    run.attempts[0].receipt.agentgres_operation_refs[0],
    "agentgres://operation/deepseek_tui/public-fixture",
  );
});

test("public fixture run blocks when fewer than two adapters are installed", async () => {
  await assert.rejects(
    runHarnessPublicFixtureRun(
      fixtureRequest({ installed_adapter_ids: ["deepseek_tui"] }),
    ),
    /requires enough installed adapters/,
  );
});

test("public fixture run preserves container lane private-mount guard", async () => {
  await assert.rejects(
    runHarnessPublicFixtureRun(
      fixtureRequest({
        candidate_lanes: [
          {
            adapter_id: "deepseek_tui",
            runtime: "docker",
            container_image_ref: "container-image:deepseek-tui:local",
            mounts: [
              {
                source_ref: "artifact://workspace/private",
                target_path: "/workspace",
                access: "read_only",
                custody: "ctee_private_workspace",
              },
            ],
          },
          {
            adapter_id: "generic_cli",
            runtime: "docker",
            container_image_ref: "container-image:generic-cli:local",
          },
        ],
      }),
    ),
    /cannot mount plaintext or cTEE private workspace custody/,
  );
});

test("public fixture run can produce dry-run receipts before executor wiring", async () => {
  const run = await runHarnessPublicFixtureRun(fixtureRequest(), {
    nowIso: () => "2026-06-17T13:00:00.000Z",
  });
  assert.deepEqual(
    run.attempts.map((attempt) => attempt.exit_status),
    ["not_executed", "not_executed"],
  );
  assert.ok(run.attempts.every((attempt) => attempt.receipt.exit_code === null));
});
