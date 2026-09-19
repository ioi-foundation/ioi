// R-195 S5-3 — GoalRun composed over the orchestration. The composer is driven over a fake
// substrate that behaves like the seam, and the record it admits is pinned against the REGISTERED
// goal-run/v2 member set so the composer and the schema cannot drift apart unnoticed.
//
// The assertions that matter are the ones about where a resolution COMES FROM. A GoalRun's profile
// revision, component set and skill set are read off the admitted resolution receipt and copied;
// a caller supplies the receipt ref and nothing else about the closure. Before this composer
// existed the daemon took all of it from the request.
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import { GOAL_RUN_CONTRACTS, GoalRuns } from "../dist/index.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const schemas = path.resolve(here, "../../../../docs/architecture/_meta/schemas");
const readJson = (rel) => JSON.parse(fs.readFileSync(path.join(schemas, rel), "utf8"));

const SCOPE = "app-scope://ioi-ai/orchestration/orc_demo";
const RECEIPT = readJson("fixtures/goal-run-profile-resolution-receipt-v1/positive-minimal.json");

function fakeOrchestration({ records = {}, admitted = [] } = {}) {
  return {
    thread_id: "thread_root",
    scope_ref: SCOPE,
    system_id: "system://ioi/orchestration/demo",
    async recordChain(contract, id) {
      const key = `${contract}|${id}`;
      const current = records[key];
      if (!current) {
        const error = new Error("out of scope");
        error.status = 404;
        throw error;
      }
      return { current, head: "sha256:head" };
    },
    async record(input) {
      admitted.push(input);
      return { record: input.record, head: "sha256:next" };
    },
    admitted,
  };
}

const draft = (over = {}) => ({
  goal_run_id: "gr_demo",
  goal_ref: "goal://demo",
  owner_ref: "user://operator-7",
  profile_resolution_receipt_ref: RECEIPT.receipt_id,
  origin_surface: "api",
  normalized_goal: "carry one bounded unit of work",
  source_context_binding: { target_session_ref: null, project_ref: "project://acme/p1" },
  receipt_obligations: [],
  admitted_state_root_ref: "artifact://goal-run/demo/admitted-state",
  authority_scope_refs: ["scope:goal.run.create"],
  created_at: "2026-09-19T12:00:00Z",
  ...over,
});

test("the admitted GoalRun copies its whole resolution off the receipt, and the caller supplies none of it", async () => {
  const admitted = [];
  const orchestration = fakeOrchestration({
    records: { [`${GOAL_RUN_CONTRACTS.profileResolutionReceipt}|${RECEIPT.receipt_id}`]: RECEIPT },
    admitted,
  });
  const result = await new GoalRuns(orchestration).admit(draft());
  const record = result.record;

  assert.equal(record.goal_run_profile_revision_ref, RECEIPT.goal_run_profile_revision_ref);
  assert.equal(record.goal_run_profile_content_hash, RECEIPT.goal_run_profile_content_hash);
  assert.equal(record.resolved_component_set_snapshot_ref, RECEIPT.resolved_component_set_snapshot_ref);
  assert.equal(record.resolved_component_set_hash, RECEIPT.resolved_component_set_hash);
  assert.equal(record.active_skill_set_snapshot_ref, RECEIPT.active_skill_set_snapshot_ref);
  assert.equal(record.active_skill_set_hash, RECEIPT.active_skill_set_hash);
  assert.equal(record.goal_run_profile_resolution_receipt_ref, RECEIPT.receipt_id);
  assert.equal(record.orchestration_ref, SCOPE);
  assert.equal(record.status, "draft");
  assert.equal(record.continuation_state, "open");
  assert.equal(admitted[0].contract_id, GOAL_RUN_CONTRACTS.goalRun);
  assert.equal(admitted[0].expected_head, null);
});

test("and a caller CANNOT pass a resolution: the draft has no field for one, so a hostile extra is dropped rather than admitted", async () => {
  const orchestration = fakeOrchestration({
    records: { [`${GOAL_RUN_CONTRACTS.profileResolutionReceipt}|${RECEIPT.receipt_id}`]: RECEIPT },
  });
  const hostile = draft({
    goal_run_profile_revision_ref: "goal-run-profile://attacker/revision/9",
    goal_run_profile_content_hash: `sha256:${"9".repeat(64)}`,
  });
  const record = (await new GoalRuns(orchestration).admit(hostile)).record;
  assert.equal(record.goal_run_profile_revision_ref, RECEIPT.goal_run_profile_revision_ref);
  assert.notEqual(record.goal_run_profile_revision_ref, "goal-run-profile://attacker/revision/9");
  assert.equal(record.goal_run_profile_content_hash, RECEIPT.goal_run_profile_content_hash);
});

test("the record the composer admits is exactly the registered v2 member set — no invented field, every required one present", async () => {
  const schema = readJson("goal-run.v2.schema.json");
  const orchestration = fakeOrchestration({
    records: { [`${GOAL_RUN_CONTRACTS.profileResolutionReceipt}|${RECEIPT.receipt_id}`]: RECEIPT },
  });
  const record = (await new GoalRuns(orchestration).admit(draft())).record;
  const known = new Set(Object.keys(schema.properties));
  const invented = Object.keys(record).filter((key) => !known.has(key));
  assert.deepEqual(invented, [], `the composer invented fields the contract does not have: ${invented.join(", ")}`);
  const missing = schema.required.filter((key) => !(key in record));
  assert.deepEqual(missing, [], `the composer omitted required fields: ${missing.join(", ")}`);
  assert.equal(record.schema_version, schema.properties.schema_version.const);
});

test("a run with no admitted receipt, a receipt outside this orchestration, and a malformed ref are each refused by name", async () => {
  const empty = fakeOrchestration();
  const runs = new GoalRuns(empty);
  await assert.rejects(runs.admit(draft()), (e) => e.code === "goal_run_profile_resolution_receipt_unknown");
  await assert.rejects(
    runs.admit(draft({ profile_resolution_receipt_ref: "goal-run-profile://not-a-receipt" })),
    (e) => e.code === "goal_run_profile_resolution_receipt_ref_malformed",
  );
  await assert.rejects(runs.admit(draft({ goal_ref: "gr_demo" })), (e) => e.code === "goal_run_ref_malformed");
});

test("a receipt missing a closure member is refused rather than filled in by the run", async () => {
  const gap = { ...RECEIPT };
  delete gap.active_skill_set_hash;
  const orchestration = fakeOrchestration({
    records: { [`${GOAL_RUN_CONTRACTS.profileResolutionReceipt}|${RECEIPT.receipt_id}`]: gap },
  });
  await assert.rejects(
    new GoalRuns(orchestration).admit(draft()),
    (e) => e.code === "goal_run_profile_closure_incomplete" && e.detail.field === "active_skill_set_hash",
  );
});

test("the same goal run is admitted once: a second admission is refused before the receipt is read", async () => {
  const orchestration = fakeOrchestration({
    records: {
      [`${GOAL_RUN_CONTRACTS.profileResolutionReceipt}|${RECEIPT.receipt_id}`]: RECEIPT,
      [`${GOAL_RUN_CONTRACTS.goalRun}|gr_demo`]: { goal_run_id: "gr_demo" },
    },
  });
  await assert.rejects(new GoalRuns(orchestration).admit(draft()), (e) => e.code === "goal_run_already_admitted");
});
