import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { AgentgresRuntimeStateStore } from "./index.mjs";

function modelMountCore() {
  return {
    planReadProjection(request) {
      return {
        source: "rust_daemon_core.model_mount.read_projection",
        projection_kind: request.projection_kind,
        projection: {
          source: "agentgres_model_mounting_projection",
        },
        evidence_refs: [
          "rust_daemon_core_model_mount_projection",
          "agentgres_model_mount_read_truth",
          "model_mount_js_read_projection_authoring_retired",
        ],
      };
    },
  };
}

test("runtime store mounts governed improvement core from options", () => {
  const stateDir = mkdtempSync(join(tmpdir(), "ioi-governed-improvement-core-store-"));
  const governedImprovementCore = {
    admitProposal() {
      throw new Error("not invoked in constructor test");
    },
  };

  try {
    const store = new AgentgresRuntimeStateStore(stateDir, {
      cwd: stateDir,
      modelMountCore: modelMountCore(),
      governedImprovementCore,
    });
    try {
      assert.equal(store.governedImprovementCore, governedImprovementCore);
      assert.equal(Object.hasOwn(store, "governedImprovementRunner"), false);
    } finally {
      store.close();
    }
  } finally {
    rmSync(stateDir, { recursive: true, force: true });
  }
});

test("runtime store wires governed improvement to typed Rust governed-admission API", () => {
  const stateDir = mkdtempSync(join(tmpdir(), "ioi-governed-improvement-typed-core-store-"));
  const calls = [];
  try {
    const store = new AgentgresRuntimeStateStore(stateDir, {
      cwd: stateDir,
      modelMountCore: modelMountCore(),
      daemonCoreGovernedAdmissionApi: {
        admitGovernedRuntimeImprovementProposal(proposal, context) {
          calls.push({ proposal, context });
          return {
            schema_version: "ioi.runtime.governed_improvement_admission.v1",
            source: "rust_governed_meta_improvement_protocol",
            backend: "rust_governed_evolution",
            thread_id: context.thread_id,
            agent_id: context.agent_id,
            proposal_id: proposal.proposal_id,
            proposal_admitted: true,
            mutation_executed: false,
          };
        },
      },
    });
    try {
      const result = store.governedImprovementCore.admitProposal(
        {
          schema_version: "ioi.governed_runtime_improvement.v1",
          proposal_id: "proposal://runtime-improvement/store-typed-api",
          target_ref: "skill://runtime-auditor/current",
          candidate_ref: "skill-candidate://runtime-auditor/store-typed-api",
          surface: "skill",
          source_trace_ref: "trace://runtime-improvement/store-typed-api",
          eval_receipt_refs: ["receipt://eval/store-typed-api"],
          verifier_receipt_refs: ["receipt://verifier/store-typed-api"],
          approval_ref: "approval://wallet/store-typed-api",
          rollback_ref: "rollback://skill/runtime-auditor/current",
        },
        {
          thread_id: "thread_governed_store",
          agent_id: "agent_governed_store",
        },
      );

      assert.equal(result.source, "rust_governed_meta_improvement_protocol");
      assert.equal(calls.length, 1);
      assert.equal(
        calls[0].proposal.proposal_id,
        "proposal://runtime-improvement/store-typed-api",
      );
      assert.deepEqual(calls[0].context, {
        thread_id: "thread_governed_store",
        agent_id: "agent_governed_store",
      });
      assert.equal(Object.hasOwn(calls[0], "operation"), false);
    } finally {
      store.close();
    }
  } finally {
    rmSync(stateDir, { recursive: true, force: true });
  }
});
