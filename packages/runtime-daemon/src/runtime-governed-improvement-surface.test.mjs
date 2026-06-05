import assert from "node:assert/strict";
import test from "node:test";

import {
  GOVERNED_IMPROVEMENT_ADMISSION_RESPONSE_SCHEMA_VERSION,
  createRuntimeGovernedImprovementSurface,
} from "./runtime-governed-improvement-surface.mjs";

function proposal() {
  return {
    schema_version: "ioi.governed_runtime_improvement.v1",
    proposal_id: "proposal://runtime-improvement/surface",
    target_ref: "skill://runtime-auditor/current",
    candidate_ref: "skill-candidate://runtime-auditor/from-trace",
    surface: "skill",
    source_trace_ref: "trace://runtime-improvement/high-fitness",
    eval_receipt_refs: ["receipt://eval/surface-holdout-pass"],
    verifier_receipt_refs: ["receipt://verifier/surface-regression-pass"],
    approval_ref: "approval://wallet/runtime-improvement/surface",
    rollback_ref: "rollback://skill/runtime-auditor/current",
    agentgres_operation_ref: "agentgres://runtime-improvement/operations/surface",
    expected_heads: ["agentgres://runtime-improvement/head/before"],
    state_root_before: "sha256:runtime-improvement-before",
    state_root_after: "sha256:runtime-improvement-after",
    resulting_head: "agentgres://runtime-improvement/head/after",
  };
}

function store() {
  const calls = [];
  return {
    calls,
    agentForThread(threadId) {
      calls.push({ name: "agentForThread", threadId });
      return { id: "agent_surface" };
    },
    governedImprovementRunner: {
      admitProposal(input) {
        calls.push({ name: "admitProposal", input });
        return {
          source: "rust_governed_meta_improvement_command",
          backend: "rust_governed_evolution",
          record: {
            ...input,
            admission_hash: "sha256:surface-admission",
          },
          proposal_id: input.proposal_id,
          admission_hash: "sha256:surface-admission",
          agentgres_operation_ref: input.agentgres_operation_ref,
          state_root_before: input.state_root_before,
          state_root_after: input.state_root_after,
          resulting_head: input.resulting_head,
          approval_ref: input.approval_ref,
          rollback_ref: input.rollback_ref,
        };
      },
    },
  };
}

const GOVERNED_IMPROVEMENT_ADMISSION_CAMEL_ALIASES = [
  "schemaVersion",
  "proposalAdmitted",
  "mutationExecuted",
  "threadId",
  "agentId",
  "proposalId",
  "admissionHash",
  "agentgresOperationRef",
  "stateRootBefore",
  "stateRootAfter",
  "resultingHead",
  "approvalRef",
  "rollbackRef",
];

test("governed improvement surface admits nested proposal through Rust runner", () => {
  const runtimeStore = store();
  const surface = createRuntimeGovernedImprovementSurface();

  const result = surface.admitGovernedImprovementProposal(runtimeStore, "thread_surface", {
    proposal: proposal(),
  });

  assert.equal(result.schema_version, GOVERNED_IMPROVEMENT_ADMISSION_RESPONSE_SCHEMA_VERSION);
  assert.equal(result.status, "admitted");
  assert.equal(result.proposal_admitted, true);
  assert.equal(result.mutation_executed, false);
  assert.equal(result.thread_id, "thread_surface");
  assert.equal(result.agent_id, "agent_surface");
  assert.equal(result.proposal_id, "proposal://runtime-improvement/surface");
  assert.equal(result.admission_hash, "sha256:surface-admission");
  assert.equal(result.agentgres_operation_ref, "agentgres://runtime-improvement/operations/surface");
  assert.equal(result.state_root_before, "sha256:runtime-improvement-before");
  assert.equal(result.state_root_after, "sha256:runtime-improvement-after");
  assert.equal(result.resulting_head, "agentgres://runtime-improvement/head/after");
  assert.equal(result.approval_ref, "approval://wallet/runtime-improvement/surface");
  assert.equal(result.rollback_ref, "rollback://skill/runtime-auditor/current");
  assert.deepEqual(runtimeStore.calls.map((call) => call.name), ["agentForThread", "admitProposal"]);
});

test("governed improvement surface exposes only canonical snake_case admission fields", () => {
  const result = createRuntimeGovernedImprovementSurface().admitGovernedImprovementProposal(
    store(),
    "thread_surface",
    { proposal: proposal() },
  );

  for (const key of GOVERNED_IMPROVEMENT_ADMISSION_CAMEL_ALIASES) {
    assert.equal(Object.hasOwn(result, key), false, `${key} must not be emitted`);
  }
});

test("governed improvement surface fails closed without proposal payload", () => {
  const surface = createRuntimeGovernedImprovementSurface();

  assert.throws(
    () => surface.admitGovernedImprovementProposal(store(), "thread_surface", {}),
    (error) => error.code === "governed_improvement_proposal_required",
  );
});
