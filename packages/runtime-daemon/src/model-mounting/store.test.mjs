import assert from "node:assert/strict";
import fs from "node:fs";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import { AgentgresModelMountingStore } from "./store.mjs";

function testStore() {
  const appended = [];
  const stateDir = mkdtempSync(path.join(tmpdir(), "ioi-model-mounting-store-"));
  const store = new AgentgresModelMountingStore({
    stateDir,
    appendOperation: (kind, payload) => appended.push({ kind, payload }),
  });
  return { appended, stateDir, store };
}

function boundModelInvocationReceipt(overrides = {}) {
  const operationRef = "agentgres://model-mounting/operation-log/op_00000001_model_invocation";
  const resultingHead = "agentgres://model-mounting/operation-log/head/1";
  return {
    id: "receipt.model-invocation",
    kind: "model_invocation",
    redaction: "redacted",
    evidenceRefs: ["rust_receipt_binder_core", "rust_agentgres_admission"],
    details: {
      modelMountReceiptBindingRef: "sha256:binding",
      modelMountAcceptedReceiptAppendHash: "sha256:append",
      modelMountAgentgresOperationRef: operationRef,
      modelMountAgentgresAdmissionHash: "sha256:agentgres",
      modelMountAgentgresStateRootBefore: "sha256:before",
      modelMountAgentgresStateRootAfter: "sha256:after",
      modelMountAgentgresResultingHead: resultingHead,
      modelMountAgentgresAdmission: {
        operation_ref: operationRef,
      },
      modelMountStepModuleInvocation: {
        input: {
          state_root_before: "sha256:before",
        },
      },
      modelMountStepModuleResult: {
        agentgres_operation_refs: [operationRef],
        state_root_after: "sha256:after",
        resulting_head: resultingHead,
      },
    },
    ...overrides,
  };
}

function modelLifecycleReceipt(details = {}) {
  return {
    id: details.id ?? "receipt.model-lifecycle",
    kind: "model_lifecycle",
    redaction: "redacted",
    evidenceRefs: ["model_registry", "agentgres_canonical_operation_log", details.operation ?? "model_load"],
    details: {
      operation: "model_load",
      instanceId: "instance.local",
      modelId: "model.local",
      providerId: "provider.local",
      providerKind: "ioi_native_local",
      ...details,
    },
  };
}

test("model invocation receipt writes fail closed without Rust receipt and Agentgres admission", () => {
  const { appended, stateDir, store } = testStore();

  assert.throws(
    () =>
      store.writeReceipt({
        id: "receipt.direct",
        kind: "model_invocation",
        redaction: "redacted",
        evidenceRefs: ["daemon_js_direct_write"],
        details: {},
      }),
    (error) =>
      error.code === "model_mount_invocation_receipt_direct_append_forbidden" &&
      error.details.missing.includes("modelMountReceiptBindingRef") &&
      error.details.missing.includes("modelMountStepModuleResult.state_root_after"),
  );
  assert.equal(fs.existsSync(path.join(stateDir, "receipts", "receipt.direct.json")), false);
  assert.deepEqual(appended, []);
});

test("stream completion receipt writes fail closed without Rust receipt and Agentgres admission", () => {
  const { appended, stateDir, store } = testStore();

  assert.throws(
    () =>
      store.writeReceipt({
        id: "receipt.stream-direct",
        kind: "model_invocation_stream_completed",
        redaction: "redacted",
        evidenceRefs: ["daemon_js_direct_write"],
        details: {},
      }),
    (error) =>
      error.code === "model_mount_invocation_receipt_direct_append_forbidden" &&
      error.details.missing.includes("modelMountAgentgresOperationRef"),
  );
  assert.equal(fs.existsSync(path.join(stateDir, "receipts", "receipt.stream-direct.json")), false);
  assert.deepEqual(appended, []);
});

test("model invocation receipt writes reject mismatched Agentgres operation refs", () => {
  const { appended, stateDir, store } = testStore();
  const receipt = boundModelInvocationReceipt({
    id: "receipt.mismatch",
    details: {
      ...boundModelInvocationReceipt().details,
      modelMountAgentgresAdmission: {
        operation_ref: "agentgres://model-mounting/operation-log/op_00000002_model_invocation",
      },
    },
  });

  assert.throws(
    () => store.writeReceipt(receipt),
    (error) =>
      error.code === "model_mount_invocation_receipt_direct_append_forbidden" &&
      error.details.mismatches.includes("modelMountAgentgresAdmission.operation_ref"),
  );
  assert.equal(fs.existsSync(path.join(stateDir, "receipts", "receipt.mismatch.json")), false);
  assert.deepEqual(appended, []);
});

test("model invocation receipt writes append only after Rust receipt and Agentgres admission", () => {
  const { appended, stateDir, store } = testStore();
  const receipt = boundModelInvocationReceipt();

  store.writeReceipt(receipt);

  assert.equal(fs.existsSync(path.join(stateDir, "receipts", "receipt.model-invocation.json")), true);
  assert.equal(appended.length, 1);
  assert.equal(appended[0].kind, "model_invocation");
  assert.equal(appended[0].payload.receiptId, "receipt.model-invocation");
  assert.equal(
    appended[0].payload.details.modelMountAgentgresOperationRef,
    "agentgres://model-mounting/operation-log/op_00000001_model_invocation",
  );
});

test("model lifecycle receipt writes fail closed without provider kind and Rust instance lifecycle binding", () => {
  const { appended, stateDir, store } = testStore();

  assert.throws(
    () =>
      store.writeReceipt(modelLifecycleReceipt({
        providerKind: undefined,
      })),
    (error) =>
      error.code === "model_mount_instance_lifecycle_receipt_direct_append_forbidden" &&
      error.details.missing.includes("providerKind"),
  );
  assert.throws(
    () => store.writeReceipt(modelLifecycleReceipt()),
    (error) =>
      error.code === "model_mount_instance_lifecycle_receipt_direct_append_forbidden" &&
      error.details.missing.includes("instance.local:modelMountInstanceLifecycleHash"),
  );
  assert.equal(fs.existsSync(path.join(stateDir, "receipts", "receipt.model-lifecycle.json")), false);
  assert.deepEqual(appended, []);
});

test("model lifecycle receipt writes allow Rust-bound local and remote provider records", () => {
  const { appended, stateDir, store } = testStore();
  const localReceipt = modelLifecycleReceipt({
    id: "receipt.local-bound",
    providerLifecycleHash: "sha256:provider-lifecycle",
    modelMountInstanceLifecycleAction: "load",
    modelMountInstanceLifecycleStatus: "loaded",
    modelMountInstanceLifecycleHash: "sha256:instance-lifecycle",
    modelMountInstanceLifecycleEvidenceRefs: ["rust_model_mount_instance_lifecycle"],
  });
  const remoteReceipt = modelLifecycleReceipt({
    id: "receipt.remote",
    providerId: "provider.remote",
    providerKind: "openai_compatible",
  });

  store.writeReceipt(localReceipt);
  store.writeReceipt(remoteReceipt);

  assert.equal(fs.existsSync(path.join(stateDir, "receipts", "receipt.local-bound.json")), true);
  assert.equal(fs.existsSync(path.join(stateDir, "receipts", "receipt.remote.json")), true);
  assert.deepEqual(appended.map((item) => item.payload.receiptId), ["receipt.local-bound", "receipt.remote"]);
});
