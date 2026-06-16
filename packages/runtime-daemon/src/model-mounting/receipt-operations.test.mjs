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

test("mounted receipt authoring facades are deleted before JS receipt creation", () => {
  const writes = [];
  const state = {
    store: {
      writeReceipt(record) {
        writes.push(record);
      },
    },
  };

  assert.equal(Object.hasOwn(ModelMountingState.prototype, "lifecycleReceipt"), false);
  assert.equal(Object.hasOwn(ModelMountingState.prototype, "receipt"), false);
  assert.equal(Object.hasOwn(state, "lifecycleReceipt"), false);
  assert.equal(Object.hasOwn(state, "receipt"), false);
  assert.equal(typeof ModelMountingState.prototype.persistRustAuthoredReceiptWithCommit, "function");
  assert.deepEqual(writes, []);
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
