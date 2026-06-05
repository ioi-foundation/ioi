import assert from "node:assert/strict";
import test from "node:test";

import {
  getReceipt,
  lifecycleReceipt,
  listReceipts,
  receipt,
} from "./receipt-operations.mjs";

test("receipt operations delegate receipt reads to the canonical store", () => {
  const receipts = [{ id: "receipt-one" }];
  const state = {
    store: {
      listReceipts: () => receipts,
      getReceipt: (receiptId) => receipts.find((item) => item.id === receiptId),
    },
  };

  assert.equal(listReceipts(state), receipts);
  assert.equal(getReceipt(state, "receipt-one"), receipts[0]);
});

test("receipt operations create lifecycle receipt envelopes through the state delegate", () => {
  const created = [];
  const state = {
    receipt(kind, payload) {
      const record = { kind, ...payload };
      created.push(record);
      return record;
    },
  };

  const record = lifecycleReceipt(state, "model_mount", {
    model_id: "model.local",
    endpoint_id: "endpoint.local",
  });

  assert.equal(record.kind, "model_lifecycle");
  assert.equal(record.summary, "model_mount recorded for model.local.");
  assert.deepEqual(record.evidenceRefs, ["model_registry", "agentgres_receipt_projection_boundary", "model_mount"]);
  assert.deepEqual(created[0].details, {
    operation: "model_mount",
    model_id: "model.local",
    endpoint_id: "endpoint.local",
  });
});

test("lifecycle receipt summary accepts canonical snake_case subject fields", () => {
  const state = {
    receipt(kind, payload) {
      return { kind, ...payload };
    },
  };

  const record = lifecycleReceipt(state, "backend_health", {
    model_id: "Native backend",
    backend_id: "backend.native",
  });

  assert.equal(record.kind, "model_lifecycle");
  assert.equal(record.summary, "backend_health recorded for Native backend.");
  assert.deepEqual(record.details, {
    operation: "backend_health",
    model_id: "Native backend",
    backend_id: "backend.native",
  });
});

test("model instance lifecycle receipts require Rust binding for migrated local providers", () => {
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
    () => lifecycleReceipt(state, "model_load", {
      instance_id: "instance.local",
      model_id: "model.local",
      provider_id: "provider.local",
    }),
    (error) =>
      error.code === "model_mount_instance_lifecycle_receipt_direct_write_forbidden" &&
      error.details.provider_id === "provider.local" &&
      Object.hasOwn(error.details, "providerId") === false &&
      error.details.missing.includes("instance.local:model_mount_instance_lifecycle_hash"),
  );

  assert.throws(
    () => lifecycleReceipt(state, "model_load", {
      instance_id: "instance.local",
      model_id: "model.local",
      provider_id: "provider.local",
      providerLifecycleHash: "sha256:provider-lifecycle",
      modelMountInstanceLifecycleAction: "load",
      modelMountInstanceLifecycleStatus: "loaded",
      modelMountInstanceLifecycleHash: "sha256:instance-lifecycle",
      modelMountInstanceLifecycleEvidenceRefs: ["rust_model_mount_instance_lifecycle"],
    }),
    (error) =>
      error.code === "model_mount_instance_lifecycle_receipt_direct_write_forbidden" &&
      error.details.missing.includes("instance.local:model_mount_provider_lifecycle_hash") &&
      error.details.missing.includes("instance.local:model_mount_instance_lifecycle_hash") &&
      error.details.missing.includes("instance.local:model_mount_instance_lifecycle_evidence_refs"),
  );

  const record = lifecycleReceipt(state, "model_load", {
    instance_id: "instance.local",
    model_id: "model.local",
    provider_id: "provider.local",
    model_mount_provider_lifecycle_hash: "sha256:provider-lifecycle",
    model_mount_instance_lifecycle_action: "load",
    model_mount_instance_lifecycle_status: "loaded",
    model_mount_instance_lifecycle_hash: "sha256:instance-lifecycle",
    model_mount_instance_lifecycle_evidence_refs: ["rust_model_mount_instance_lifecycle"],
  });

  assert.equal(record.kind, "model_lifecycle");
  assert.equal(created.length, 1);
});

test("receipt operations write redacted receipts and refresh projection", () => {
  const writes = [];
  const state = {
    projectionWrites: 0,
    nowIso: () => "2026-06-04T12:00:00.000Z",
    store: {
      writeReceipt(record) {
        writes.push(record);
      },
    },
    writeProjection() {
      this.projectionWrites += 1;
    },
  };

  const record = receipt(state, "provider_health", {
    summary: "Provider checked.",
    redaction: "redacted",
    evidenceRefs: ["provider.health"],
    details: {
      provider_id: "provider.local",
      apiKey: "secret",
    },
  }, {
    randomUUID: () => "uuid-1",
    redact: (value) => ({ ...value, apiKey: "[REDACTED]" }),
    schemaVersion: "schema.v1",
  });

  assert.equal(record.id, "receipt_provider_health_uuid-1");
  assert.equal(record.createdAt, "2026-06-04T12:00:00.000Z");
  assert.equal(record.schemaVersion, "schema.v1");
  assert.deepEqual(record.details, {
    provider_id: "provider.local",
    apiKey: "[REDACTED]",
  });
  assert.equal(writes[0], record);
  assert.equal(state.projectionWrites, 1);
});
