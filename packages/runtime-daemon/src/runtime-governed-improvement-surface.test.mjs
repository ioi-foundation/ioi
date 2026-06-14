import assert from "node:assert/strict";
import test from "node:test";

import {
  createRuntimeGovernedImprovementSurface,
} from "./runtime-governed-improvement-surface.mjs";

const GOVERNED_IMPROVEMENT_ADMISSION_RESPONSE_SCHEMA_VERSION =
  "ioi.runtime.governed_improvement_admission.v1";

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
    governedImprovementCore: {
      admitProposal(input, context) {
        calls.push({ name: "admitProposal", input, context });
        return {
          schema_version: GOVERNED_IMPROVEMENT_ADMISSION_RESPONSE_SCHEMA_VERSION,
          object: "ioi.runtime_governed_improvement_admission",
          status: "admitted",
          proposal_admitted: true,
          mutation_executed: false,
          source: "rust_governed_meta_improvement_protocol",
          backend: "rust_governed_evolution",
          thread_id: context.thread_id,
          agent_id: context.agent_id,
          record: {
            ...input,
            admission_hash: "sha256:surface-admission",
            agentgres_operation_ref: "agentgres://runtime-improvement/operations/rust-derived",
            expected_heads: ["agentgres://runtime-improvement/head/current"],
            state_root_before: "sha256:rust-derived-before",
            state_root_after: "sha256:rust-derived-after",
            resulting_head: "agentgres://runtime-improvement/head/rust-derived",
          },
          proposal_id: input.proposal_id,
          admission_hash: "sha256:surface-admission",
          agentgres_operation_ref: "agentgres://runtime-improvement/operations/rust-derived",
          state_root_before: "sha256:rust-derived-before",
          state_root_after: "sha256:rust-derived-after",
          resulting_head: "agentgres://runtime-improvement/head/rust-derived",
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

test("governed improvement surface rejects retired request aliases before agent lookup or Rust core", () => {
  const runtimeStore = store();
  const surface = createRuntimeGovernedImprovementSurface();

  assert.throws(
    () =>
      surface.admitGovernedImprovementProposal(runtimeStore, "thread_surface", {
        proposal_payload: proposal(),
        proposalPayload: proposal(),
      }),
    (error) => {
      assert.equal(error.status, 400);
      assert.equal(error.code, "governed_improvement_proposal_request_aliases_retired");
      assert.deepEqual(error.details.retired_aliases, ["proposalPayload", "proposal_payload"]);
      assert.deepEqual(error.details.canonical_fields, ["proposal"]);
      return true;
    },
  );
  assert.deepEqual(runtimeStore.calls, []);
});

test("governed improvement surface rejects client supplied Agentgres truth before Rust core", () => {
  const runtimeStore = store();
  const surface = createRuntimeGovernedImprovementSurface();

  assert.throws(
    () =>
      surface.admitGovernedImprovementProposal(runtimeStore, "thread_surface", {
        proposal: {
          ...proposal(),
          agentgres_operation_ref: "agentgres://runtime-improvement/operations/client",
          expected_heads: ["agentgres://runtime-improvement/head/client"],
          state_root_before: "sha256:client-before",
          state_root_after: "sha256:client-after",
          resulting_head: "agentgres://runtime-improvement/head/client-after",
        },
      }),
    (error) => {
      assert.equal(error.status, 400);
      assert.equal(error.code, "governed_improvement_agentgres_truth_fields_retired");
      assert.deepEqual(error.details.retired_fields, [
        "agentgres_operation_ref",
        "expected_heads",
        "state_root_before",
        "state_root_after",
        "resulting_head",
      ]);
      assert.equal(error.details.derived_by, "rust_governed_evolution");
      return true;
    },
  );
  assert.deepEqual(runtimeStore.calls, []);
});

test("governed improvement surface admits nested proposal through Rust core", () => {
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
  assert.equal(result.agentgres_operation_ref, "agentgres://runtime-improvement/operations/rust-derived");
  assert.equal(result.state_root_before, "sha256:rust-derived-before");
  assert.equal(result.state_root_after, "sha256:rust-derived-after");
  assert.equal(result.resulting_head, "agentgres://runtime-improvement/head/rust-derived");
  assert.equal(result.approval_ref, "approval://wallet/runtime-improvement/surface");
  assert.equal(result.rollback_ref, "rollback://skill/runtime-auditor/current");
  assert.deepEqual(runtimeStore.calls.map((call) => call.name), ["agentForThread", "admitProposal"]);
  assert.deepEqual(runtimeStore.calls.at(-1).context, {
    thread_id: "thread_surface",
    agent_id: "agent_surface",
  });
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

test("governed improvement surface rejects retired proposal payload aliases before agent lookup or Rust core", () => {
  const runtimeStore = store();

  assert.throws(
    () =>
      createRuntimeGovernedImprovementSurface().admitGovernedImprovementProposal(
        runtimeStore,
        "thread_surface",
        {
          proposal: {
            ...proposal(),
            proposalId: "proposal://retired/alias",
            sourceTraceRef: "trace://runtime-improvement/retired-alias",
          },
        },
      ),
    (error) => {
      assert.equal(error.status, 400);
      assert.equal(error.code, "governed_improvement_proposal_payload_aliases_retired");
      assert.deepEqual(error.details.retired_aliases, [
        "proposalId",
        "sourceTraceRef",
      ]);
      assert.deepEqual(error.details.canonical_fields, ["proposal"]);
      return true;
    },
  );
  assert.deepEqual(runtimeStore.calls, []);
});

test("governed improvement surface fails closed without proposal payload", () => {
  const surface = createRuntimeGovernedImprovementSurface();

  assert.throws(
    () => surface.admitGovernedImprovementProposal(store(), "thread_surface", {}),
    (error) => error.code === "governed_improvement_proposal_required",
  );
});
