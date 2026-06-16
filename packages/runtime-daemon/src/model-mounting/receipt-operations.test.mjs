import assert from "node:assert/strict";
import test from "node:test";

import { ModelMountingState } from "../model-mounting.mjs";

function captureError(fn) {
  try {
    fn();
  } catch (error) {
    return error;
  }
  throw new Error("Expected function to throw.");
}

test("receipt operations delegate receipt reads to the canonical store", () => {
  const receipts = [{ id: "receipt-one" }];
  const state = {
    store: {
      listReceipts: () => receipts,
      getReceipt: (receiptId) => receipts.find((item) => item.id === receiptId),
    },
  };

  assert.equal(ModelMountingState.prototype.listReceipts.call(state), receipts);
  assert.equal(ModelMountingState.prototype.getReceipt.call(state, "receipt-one"), receipts[0]);
});

test("lifecycleReceipt fails closed before JS model_lifecycle receipt creation", () => {
  const created = [];
  const state = {
    receipt(kind, payload) {
      const record = { kind, ...payload };
      created.push(record);
      return record;
    },
  };

  assert.throws(
    () =>
      ModelMountingState.prototype.lifecycleReceipt.call(state, "model_mount", {
        model_id: "model.local",
        endpoint_id: "endpoint.local",
      }),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "model_mount_lifecycle_receipt_rust_core_required");
      assert.equal(error.details.rust_core_boundary, "model_mount.lifecycle_receipt");
      assert.equal(error.details.operation, "model_mount");
      assert.equal(error.details.model_id, "model.local");
      assert.equal(error.details.endpoint_id, "endpoint.local");
      assert.ok(error.details.evidence_refs.includes("model_mount_lifecycle_receipt_js_facade_retired"));
      assert.ok(error.details.evidence_refs.includes("rust_daemon_core_model_lifecycle_receipt_required"));
      assert.ok(error.details.evidence_refs.includes("agentgres_model_lifecycle_receipt_truth_required"));
      return true;
    },
  );

  assert.deepEqual(created, []);
});

test("lifecycleReceipt fails closed for canonical backend lifecycle receipt details", () => {
  const created = [];
  const state = {
    receipt(kind, payload) {
      const record = { kind, ...payload };
      created.push(record);
      return record;
    },
  };

  assert.throws(
    () =>
      ModelMountingState.prototype.lifecycleReceipt.call(state, "backend_health", {
        model_id: "Native backend",
        backend_id: "backend.native",
      }),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "model_mount_lifecycle_receipt_rust_core_required");
      assert.equal(error.details.operation, "backend_health");
      assert.equal(error.details.model_id, "Native backend");
      assert.equal(error.details.backend_id, "backend.native");
      return true;
    },
  );

  assert.deepEqual(created, []);
});

test("lifecycle receipt subject aliases are retired", () => {
  const created = [];
  const state = {
    receipt(kind, payload) {
      const record = { kind, ...payload };
      created.push(record);
      return record;
    },
  };

  assert.throws(
    () => ModelMountingState.prototype.lifecycleReceipt.call(state, "model_mount", {
      modelId: "model.legacy",
      endpointId: "endpoint.legacy",
    }),
    (error) =>
      error.code === "model_lifecycle_receipt_detail_aliases_retired" &&
      error.details.retired_aliases.includes("modelId") &&
      error.details.retired_aliases.includes("endpointId") &&
      Object.hasOwn(error.details, "modelId") === false &&
      Object.hasOwn(error.details, "endpointId") === false,
  );

  assert.equal(created.length, 0);
});

test("model instance lifecycle receipt helper fails closed even with Rust binding details", () => {
  const created = [];
  const state = {
    providers: new Map([["provider.local", { id: "provider.local", kind: "ioi_native_local" }]]),
    receipt(kind, payload) {
      const record = { kind, ...payload };
      created.push(record);
      return record;
    },
  };

  assert.throws(
    () => ModelMountingState.prototype.lifecycleReceipt.call(state, "model_load", {
      instance_id: "instance.local",
      model_id: "model.local",
      provider_id: "provider.local",
    }),
    (error) => {
      assert.equal(error.code, "model_mount_lifecycle_receipt_rust_core_required");
      assert.equal(error.details.provider_id, "provider.local");
      assert.equal(Object.hasOwn(error.details, "providerId"), false);
      return true;
    },
  );

  assert.throws(
    () =>
      ModelMountingState.prototype.lifecycleReceipt.call(state, "model_load", {
        instance_id: "instance.local",
        model_id: "model.local",
        provider_id: "provider.local",
        model_mount_provider_lifecycle_hash: "sha256:provider-lifecycle",
        model_mount_instance_lifecycle_action: "load",
        model_mount_instance_lifecycle_status: "loaded",
        model_mount_instance_lifecycle_hash: "sha256:instance-lifecycle",
        model_mount_instance_lifecycle_evidence_refs: ["rust_model_mount_instance_lifecycle"],
      }),
    (error) => {
      assert.equal(error.code, "model_mount_lifecycle_receipt_rust_core_required");
      assert.equal(error.details.operation, "model_load");
      assert.equal(error.details.provider_id, "provider.local");
      return true;
    },
  );

  assert.deepEqual(created, []);
});

test("receipt operations persist Rust-authored receipts without projection cache refresh", () => {
  const writes = [];
  const state = {
    store: {
      writeReceipt(record) {
        writes.push(record);
      },
    },
  };

  const rustRecord = {
    id: "receipt-route",
    runId: null,
    kind: "model_route_selection",
    summary: "Route route.local-first selected model.local.",
    redaction: "none",
    evidenceRefs: ["rust_model_mount_core"],
    createdAt: "unix:1",
    details: {
      rust_daemon_core_receipt_author: "ModelMountCore.admit_route_decision",
      model_mount_route_decision_ref: "model_mount://route_decision/test",
    },
    schemaVersion: "ioi.model-mounting.runtime.v1",
  };

  const result = ModelMountingState.prototype.persistRustAuthoredReceiptWithCommit.call(state, rustRecord);

  assert.equal(result.receipt, rustRecord);
  assert.equal(writes[0], rustRecord);
  assert.equal(typeof state.writeProjection, "undefined");
});

test("receipt operations reject JS receipt creation after Rust receipt authoring cut", () => {
  const error = captureError(
    () =>
      ModelMountingState.prototype.receipt.call({}, "provider_health", {
        summary: "Provider checked.",
        redaction: "redacted",
        evidenceRefs: ["provider.health"],
        details: { provider_id: "provider.local" },
      }),
  );

  assert.equal(error.code, "model_mount_js_receipt_creation_retired");
  assert.ok(error.details.evidence_refs.includes("rust_daemon_core_model_mount_receipt_authoring_required"));
});

test("receipt operations reject non-Rust-authored receipt persistence", () => {
  const error = captureError(
    () =>
      ModelMountingState.prototype.persistRustAuthoredReceiptWithCommit.call(
        { store: { writeReceipt() {} } },
        {
          id: "receipt-route",
          kind: "model_route_selection",
          createdAt: "unix:1",
          schemaVersion: "ioi.model-mounting.runtime.v1",
          evidenceRefs: [],
          details: {},
        },
      ),
  );

  assert.equal(error.code, "model_mount_rust_authored_receipt_required");
  assert.deepEqual(error.details.missing, [
    "evidenceRefs.rust_model_mount_core",
    "details.rust_daemon_core_receipt_author",
    "details.model_mount_route_decision_ref",
  ]);
});
