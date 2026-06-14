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
        source: "rust_model_mount_read_projection_command",
        backend: "rust_model_mount_read_projection",
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

test("runtime store mounts external capability authority core from options", () => {
  const stateDir = mkdtempSync(join(tmpdir(), "ioi-external-capability-authority-core-store-"));
  const externalCapabilityAuthorityCore = {
    authorizeExit() {
      throw new Error("not invoked in constructor test");
    },
  };

  try {
    const store = new AgentgresRuntimeStateStore(stateDir, {
      externalCapabilityAuthorityCore,
      modelMountCore: modelMountCore(),
    });
    try {
      assert.equal(store.externalCapabilityAuthorityCore, externalCapabilityAuthorityCore);
      assert.equal(Object.hasOwn(store, "externalCapabilityAuthorityRunner"), false);
    } finally {
      store.close();
    }
  } finally {
    rmSync(stateDir, { recursive: true, force: true });
  }
});

test("runtime store wires external capability authority to typed Rust authority API", () => {
  const stateDir = mkdtempSync(join(tmpdir(), "ioi-external-capability-authority-core-store-"));
  const calls = [];

  try {
    const store = new AgentgresRuntimeStateStore(stateDir, {
      modelMountCore: modelMountCore(),
      daemonCoreInvoker() {
        throw new Error("generic daemonCoreInvoker must not authorize external capability exits");
      },
      daemonCoreAuthorityApi: {
        authorizeExternalCapabilityExit(request, context) {
          calls.push({ request, context });
          return {
            schema_version: "ioi.runtime.external_capability_authority.v1",
            object: "ioi.runtime_external_capability_authority",
            status: "authorized",
            exit_authorized: true,
            direct_truth_write_allowed: false,
            thread_id: context.thread_id,
            agent_id: context.agent_id,
            source: "rust_external_capability_exit_authority_protocol",
            authority: request,
          };
        },
      },
    });
    try {
      const result = store.externalCapabilityAuthorityCore.authorizeExit(
        {
          schema_version: "ioi.external_capability_exit_authority.v1",
          exit_ref: "exit://aiip/slack-post-message",
          capability_ref: "capability://connector/slack.postMessage",
          target_ref: "aiip://workspace/channel/runtime",
          policy_hash: "sha256:external-capability-policy",
          idempotency_key: "idem:external-capability-exit",
          authority_grant_refs: [
            "wallet.network://grant/external-capability/slack-post-message",
          ],
          authority_receipt_refs: [
            "receipt://wallet.network/authority/slack-post-message",
          ],
        },
        {
          thread_id: "thread_external_capability_core",
          agent_id: "agent_external_capability_core",
        },
      );

      assert.equal(result.source, "rust_external_capability_exit_authority_protocol");
      assert.equal(calls.length, 1);
      assert.equal(calls[0].request.exit_ref, "exit://aiip/slack-post-message");
      assert.deepEqual(calls[0].context, {
        thread_id: "thread_external_capability_core",
        agent_id: "agent_external_capability_core",
      });
      assert.equal(Object.hasOwn(calls[0], "operation"), false);
    } finally {
      store.close();
    }
  } finally {
    rmSync(stateDir, { recursive: true, force: true });
  }
});
