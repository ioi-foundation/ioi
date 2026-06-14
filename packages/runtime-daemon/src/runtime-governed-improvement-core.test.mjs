import assert from "node:assert/strict";
import test from "node:test";

import {
  GOVERNED_IMPROVEMENT_CORE_SCHEMA_VERSION,
  RUNTIME_GOVERNED_IMPROVEMENT_BACKEND,
  RuntimeGovernedImprovementCore,
  RuntimeGovernedImprovementCoreError,
  createRuntimeGovernedImprovementCore,
} from "./runtime-governed-improvement-core.mjs";

function governedProposal() {
  return {
    schema_version: "ioi.governed_runtime_improvement.v1",
    proposal_id: "proposal://runtime-improvement/daemon-core",
    target_ref: "skill://runtime-auditor/current",
    candidate_ref: "skill-candidate://runtime-auditor/from-trace",
    surface: "skill",
    source_trace_ref: "trace://runtime-improvement/high-fitness",
    eval_receipt_refs: ["receipt://eval/daemon-core-holdout-pass"],
    verifier_receipt_refs: ["receipt://verifier/daemon-core-regression-pass"],
    approval_ref: "approval://wallet/runtime-improvement/daemon-core",
    rollback_ref: "rollback://skill/runtime-auditor/current",
  };
}

function admittedResult(request) {
  return {
    schema_version: "ioi.runtime.governed_improvement_admission.v1",
    object: "ioi.runtime_governed_improvement_admission",
    status: "admitted",
    proposal_admitted: true,
    mutation_executed: false,
    source: "rust_governed_meta_improvement_command",
    backend: RUNTIME_GOVERNED_IMPROVEMENT_BACKEND,
    thread_id: request.thread_id,
    agent_id: request.agent_id,
    record: {
      ...request.proposal,
      admission_hash: "sha256:governed-improvement-admission",
      agentgres_operation_ref: "agentgres://runtime-improvement/operations/rust-derived",
      expected_heads: ["agentgres://runtime-improvement/head/current"],
      state_root_before: "sha256:rust-derived-before",
      state_root_after: "sha256:rust-derived-after",
      resulting_head: "agentgres://runtime-improvement/head/rust-derived",
    },
    admission_hash: "sha256:governed-improvement-admission",
    agentgres_operation_ref: "agentgres://runtime-improvement/operations/rust-derived",
    expected_heads: ["agentgres://runtime-improvement/head/current"],
    state_root_before: "sha256:rust-derived-before",
    state_root_after: "sha256:rust-derived-after",
    resulting_head: "agentgres://runtime-improvement/head/rust-derived",
    eval_receipt_refs: request.proposal.eval_receipt_refs,
    verifier_receipt_refs: request.proposal.verifier_receipt_refs,
    approval_ref: request.proposal.approval_ref,
    rollback_ref: request.proposal.rollback_ref,
  };
}

test("governed improvement core calls direct Rust daemon-core proposal API", () => {
  const calls = [];
  const core = createRuntimeGovernedImprovementCore({
    daemonCoreInvoker(request) {
      calls.push(request);
      return admittedResult(request);
    },
  });

  const result = core.admitProposal(governedProposal(), {
    thread_id: "thread:governed-core",
    agent_id: "agent:governed-core",
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].schema_version, GOVERNED_IMPROVEMENT_CORE_SCHEMA_VERSION);
  assert.equal(calls[0].operation, "admit_governed_runtime_improvement_proposal");
  assert.equal(calls[0].backend, RUNTIME_GOVERNED_IMPROVEMENT_BACKEND);
  assert.equal(calls[0].thread_id, "thread:governed-core");
  assert.equal(calls[0].agent_id, "agent:governed-core");
  assert.equal(calls[0].proposal.proposal_id, "proposal://runtime-improvement/daemon-core");
  assert.equal(Object.hasOwn(calls[0].proposal, "proposalId"), false);
  assert.equal(Object.hasOwn(calls[0].proposal, "agentgres_operation_ref"), false);
  assert.equal(result.schema_version, "ioi.runtime.governed_improvement_admission.v1");
  assert.equal(result.object, "ioi.runtime_governed_improvement_admission");
  assert.equal(result.status, "admitted");
  assert.equal(result.proposal_admitted, true);
  assert.equal(result.mutation_executed, false);
  assert.equal(result.thread_id, "thread:governed-core");
  assert.equal(result.agent_id, "agent:governed-core");
  assert.equal(result.admission_hash, "sha256:governed-improvement-admission");
  assert.deepEqual(result.expected_heads, ["agentgres://runtime-improvement/head/current"]);
  assert.deepEqual(result.eval_receipt_refs, ["receipt://eval/daemon-core-holdout-pass"]);
  assert.deepEqual(result.verifier_receipt_refs, [
    "receipt://verifier/daemon-core-regression-pass",
  ]);
});

test("governed improvement core returns the Rust envelope without JS normalization", () => {
  const rustEnvelope = {
    schema_version: "ioi.runtime.governed_improvement_admission.v1",
    record: {},
  };
  const core = createRuntimeGovernedImprovementCore({
    daemonCoreInvoker() {
      return rustEnvelope;
    },
  });

  const result = core.admitProposal(governedProposal());

  assert.equal(result, rustEnvelope);
  assert.equal(Object.hasOwn(result, "expected_heads"), false);
  assert.equal(Object.hasOwn(result, "eval_receipt_refs"), false);
  assert.equal(Object.hasOwn(result, "verifier_receipt_refs"), false);
  assert.equal(Object.hasOwn(result, "source"), false);
  assert.equal(Object.hasOwn(result, "backend"), false);
});

test("governed improvement core rejects retired compatibility options", () => {
  assert.throws(
    () => new RuntimeGovernedImprovementCore({ command: "ioi-runtime-daemon-core" }),
    (error) =>
      error instanceof RuntimeGovernedImprovementCoreError &&
      error.code === "governed_improvement_core_compatibility_option_retired",
  );
  assert.throws(
    () => new RuntimeGovernedImprovementCore({ args: ["--governed"] }),
    (error) =>
      error instanceof RuntimeGovernedImprovementCoreError &&
      error.code === "governed_improvement_core_compatibility_option_retired",
  );
});

test("governed improvement core rejects retired proposal fields before Rust invocation", () => {
  const calls = [];
  const core = createRuntimeGovernedImprovementCore({
    daemonCoreInvoker() {
      calls.push("invoked");
      return {};
    },
  });
  const proposal = governedProposal();

  assert.throws(
    () =>
      core.admitProposal({
        ...proposal,
        proposalId: proposal.proposal_id,
        sourceTraceRef: proposal.source_trace_ref,
        agentgres_operation_ref: "agentgres://runtime-improvement/operations/client",
        expected_heads: ["agentgres://runtime-improvement/head/client"],
      }),
    (error) =>
      error.code === "governed_improvement_core_proposal_fields_retired" &&
      error.details.status === 400 &&
      error.details.retired_aliases.includes("proposalId") &&
      error.details.retired_aliases.includes("sourceTraceRef") &&
      error.details.retired_truth_fields.includes("agentgres_operation_ref") &&
      error.details.retired_truth_fields.includes("expected_heads"),
  );
  assert.deepEqual(calls, []);
});

test("governed improvement core fails closed without direct daemon-core API", () => {
  const core = createRuntimeGovernedImprovementCore({});

  assert.throws(
    () => core.admitProposal(governedProposal()),
    (error) => error.code === "governed_improvement_core_direct_invoker_unconfigured",
  );
});

test("governed improvement core surfaces Rust proposal rejection", () => {
  const core = createRuntimeGovernedImprovementCore({
    daemonCoreInvoker() {
      return {
        ok: false,
        error: {
          code: "governed_runtime_improvement_invalid",
          message: "missing approval_ref",
        },
      };
    },
  });

  assert.throws(
    () => core.admitProposal(governedProposal()),
    (error) =>
      error.code === "governed_runtime_improvement_invalid" &&
      error.message === "missing approval_ref",
  );
});
