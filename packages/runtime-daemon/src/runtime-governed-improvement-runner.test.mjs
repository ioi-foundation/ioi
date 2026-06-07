import assert from "node:assert/strict";
import test from "node:test";

import {
  GOVERNED_IMPROVEMENT_COMMAND_ENV,
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

test("governed improvement runner sends proposal admission bridge request", () => {
  const calls = [];
  const runner = new RustGovernedImprovementRunner({
    command: "mock-governed-improvement-bridge",
    args: ["--json"],
    spawnSyncImpl(command, args, options) {
      const request = JSON.parse(options.input);
      calls.push({ command, args, request });
      return {
        status: 0,
        stdout: JSON.stringify({
          ok: true,
          result: {
            source: "rust_governed_meta_improvement_command",
            backend: RUST_GOVERNED_IMPROVEMENT_BACKEND,
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
          },
        }),
        stderr: "",
      };
    },
  });

  const result = runner.admitProposal(governedProposal());

  assert.equal(calls.length, 1);
  assert.equal(calls[0].command, "mock-governed-improvement-bridge");
  assert.deepEqual(calls[0].args, ["--json"]);
  assert.equal(calls[0].request.schema_version, GOVERNED_IMPROVEMENT_COMMAND_SCHEMA_VERSION);
  assert.equal(calls[0].request.operation, "admit_governed_runtime_improvement_proposal");
  assert.equal(calls[0].request.backend, RUST_GOVERNED_IMPROVEMENT_BACKEND);
  assert.equal(calls[0].request.proposal.proposal_id, "proposal://runtime-improvement/daemon-runner");
  assert.equal(result.source, "rust_governed_meta_improvement_command");
  assert.equal(result.backend, RUST_GOVERNED_IMPROVEMENT_BACKEND);
  assert.equal(result.admission_hash, "sha256:governed-improvement-admission");
  assert.equal(result.agentgres_operation_ref, "agentgres://runtime-improvement/operations/rust-derived");
  assert.deepEqual(result.expected_heads, ["agentgres://runtime-improvement/head/current"]);
  assert.deepEqual(result.eval_receipt_refs, ["receipt://eval/daemon-runner-holdout-pass"]);
  assert.deepEqual(result.verifier_receipt_refs, ["receipt://verifier/daemon-runner-regression-pass"]);
  assert.equal(result.approval_ref, "approval://wallet/runtime-improvement/daemon-runner");
  assert.equal(result.rollback_ref, "rollback://skill/runtime-auditor/current");
});

test("governed improvement runner can be configured from env", () => {
  const runner = createGovernedImprovementRunnerFromEnv({
    [GOVERNED_IMPROVEMENT_COMMAND_ENV]: "mock-governed-improvement-bridge",
  });

  assert.equal(runner.command, "mock-governed-improvement-bridge");
});

test("governed improvement runner fails closed without command", () => {
  const runner = new RustGovernedImprovementRunner();

  assert.throws(
    () => runner.admitProposal(governedProposal()),
    (error) =>
      error instanceof GovernedImprovementRunnerError &&
      error.code === "governed_improvement_bridge_unconfigured",
  );
});

test("governed improvement runner surfaces Rust proposal rejection", () => {
  const runner = new RustGovernedImprovementRunner({
    command: "mock-governed-improvement-bridge",
    spawnSyncImpl() {
      return {
        status: 0,
        stdout: JSON.stringify({
          ok: false,
          error: {
            code: "governed_runtime_improvement_invalid",
            message: "missing approval_ref",
          },
        }),
        stderr: "",
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
