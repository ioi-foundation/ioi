import assert from "node:assert/strict";
import test from "node:test";

import {
  GOVERNED_IMPROVEMENT_COMMAND_SCHEMA_VERSION,
  GovernedImprovementRunnerError,
  RUST_GOVERNED_IMPROVEMENT_BACKEND,
  RustGovernedImprovementRunner,
  createGovernedImprovementRunnerFromEnv,
} from "./runtime-governed-improvement-runner.mjs";

function governedProposal() {
  return {
    schema_version: "ioi.governed_runtime_improvement.v1",
    proposal_id: "proposal://runtime-improvement/daemon-runner",
    target_ref: "skill://runtime-auditor/current",
    candidate_ref: "skill-candidate://runtime-auditor/from-trace",
    surface: "skill",
    source_trace_ref: "trace://runtime-improvement/high-fitness",
    eval_receipt_refs: ["receipt://eval/daemon-runner-holdout-pass"],
    verifier_receipt_refs: ["receipt://verifier/daemon-runner-regression-pass"],
    approval_ref: "approval://wallet/runtime-improvement/daemon-runner",
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
    source: "direct_daemon_core_api",
    backend: RUST_GOVERNED_IMPROVEMENT_BACKEND,
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
    eval_receipt_refs: request.proposal.eval_receipt_refs,
    verifier_receipt_refs: request.proposal.verifier_receipt_refs,
    approval_ref: request.proposal.approval_ref,
    rollback_ref: request.proposal.rollback_ref,
  };
}

test("governed improvement runner sends proposal admission request through direct daemon-core invoker", () => {
  const calls = [];
  const runner = new RustGovernedImprovementRunner({
    daemonCoreInvoker(request) {
      calls.push(request);
      return admittedResult(request);
    },
  });

  const result = runner.admitProposal(governedProposal(), {
    thread_id: "thread:governed-runner",
    agent_id: "agent:governed-runner",
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].schema_version, GOVERNED_IMPROVEMENT_COMMAND_SCHEMA_VERSION);
  assert.equal(calls[0].operation, "admit_governed_runtime_improvement_proposal");
  assert.equal(calls[0].backend, RUST_GOVERNED_IMPROVEMENT_BACKEND);
  assert.equal(calls[0].thread_id, "thread:governed-runner");
  assert.equal(calls[0].agent_id, "agent:governed-runner");
  assert.equal(calls[0].proposal.proposal_id, "proposal://runtime-improvement/daemon-runner");
  assert.equal(result.schema_version, "ioi.runtime.governed_improvement_admission.v1");
  assert.equal(result.object, "ioi.runtime_governed_improvement_admission");
  assert.equal(result.status, "admitted");
  assert.equal(result.proposal_admitted, true);
  assert.equal(result.mutation_executed, false);
  assert.equal(result.thread_id, "thread:governed-runner");
  assert.equal(result.agent_id, "agent:governed-runner");
  assert.equal(result.source, "direct_daemon_core_api");
  assert.equal(result.backend, RUST_GOVERNED_IMPROVEMENT_BACKEND);
  assert.equal(result.admission_hash, "sha256:governed-improvement-admission");
  assert.equal(result.agentgres_operation_ref, "agentgres://runtime-improvement/operations/rust-derived");
  assert.deepEqual(result.expected_heads, ["agentgres://runtime-improvement/head/current"]);
  assert.deepEqual(result.eval_receipt_refs, ["receipt://eval/daemon-runner-holdout-pass"]);
  assert.deepEqual(result.verifier_receipt_refs, ["receipt://verifier/daemon-runner-regression-pass"]);
  assert.equal(result.approval_ref, "approval://wallet/runtime-improvement/daemon-runner");
  assert.equal(result.rollback_ref, "rollback://skill/runtime-auditor/current");
});

test("governed improvement runner does not synthesize Rust-owned heads or receipt refs", () => {
  const runner = new RustGovernedImprovementRunner({
    daemonCoreInvoker() {
      return { record: {} };
    },
  });

  const result = runner.admitProposal(governedProposal());

  assert.equal(result.expected_heads, null);
  assert.equal(result.eval_receipt_refs, null);
  assert.equal(result.verifier_receipt_refs, null);
});

test("governed improvement runner env uses daemon-level direct invoker", () => {
  const calls = [];
  const runner = createGovernedImprovementRunnerFromEnv({
    IOI_GOVERNED_IMPROVEMENT_COMMAND_ARGS: "--retired-governed",
    IOI_STEP_MODULE_COMMAND: "retired-step-module-bridge",
    IOI_STEP_MODULE_COMMAND_ARGS: "--retired-step",
  }, {
    daemonCoreInvoker(request) {
      calls.push(request);
      return admittedResult(request);
    },
  });

  const result = runner.admitProposal(governedProposal());

  assert.equal(calls[0].operation, "admit_governed_runtime_improvement_proposal");
  assert.equal(result.source, "direct_daemon_core_api");
});

test("governed improvement runner rejects retired binary command env", () => {
  assert.throws(
    () =>
      createGovernedImprovementRunnerFromEnv({
        IOI_RUNTIME_DAEMON_CORE_COMMAND: "ioi-runtime-daemon-core",
      }, {
        daemonCoreInvoker() {},
      }),
    (error) =>
      error instanceof GovernedImprovementRunnerError &&
      error.code === "governed_improvement_command_selection_retired",
  );
});

test("governed improvement runner rejects retired governed command env", () => {
  assert.throws(
    () =>
      createGovernedImprovementRunnerFromEnv({
        IOI_GOVERNED_IMPROVEMENT_COMMAND: "retired-governed-improvement-bridge",
      }, {
        daemonCoreInvoker() {},
      }),
    (error) =>
      error instanceof GovernedImprovementRunnerError &&
      error.code === "governed_improvement_command_selection_retired",
  );
});

test("governed improvement runner command args env fails closed", () => {
  assert.throws(
    () =>
      createGovernedImprovementRunnerFromEnv({
        IOI_RUNTIME_DAEMON_CORE_COMMAND_ARGS: "--json",
      }),
    (error) =>
      error instanceof GovernedImprovementRunnerError &&
      error.code === "governed_improvement_command_args_retired",
  );
});

test("governed improvement runner command constructor option fails closed", () => {
  assert.throws(
    () => new RustGovernedImprovementRunner({ command: "ioi-runtime-daemon-core" }),
    (error) =>
      error instanceof GovernedImprovementRunnerError &&
      error.code === "governed_improvement_command_selection_retired",
  );
});

test("governed improvement runner command args constructor option fails closed", () => {
  assert.throws(
    () => new RustGovernedImprovementRunner({ args: ["--json"] }),
    (error) =>
      error instanceof GovernedImprovementRunnerError &&
      error.code === "governed_improvement_command_args_retired",
  );
});

test("governed improvement runner fails closed without direct invoker", () => {
  const runner = new RustGovernedImprovementRunner();

  assert.throws(
    () => runner.admitProposal(governedProposal()),
    (error) =>
      error instanceof GovernedImprovementRunnerError &&
      error.code === "governed_improvement_direct_invoker_unconfigured",
  );
});

test("governed improvement runner surfaces Rust proposal rejection", () => {
  const runner = new RustGovernedImprovementRunner({
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
    () => runner.admitProposal(governedProposal()),
    (error) =>
      error instanceof GovernedImprovementRunnerError &&
      error.code === "governed_runtime_improvement_invalid" &&
      error.message === "missing approval_ref",
  );
});
