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
      model_mount_receipt_binding_ref: "sha256:binding",
      model_mount_accepted_receipt_append_hash: "sha256:append",
      model_mount_agentgres_operation_ref: operationRef,
      model_mount_agentgres_admission_hash: "sha256:agentgres",
      model_mount_agentgres_state_root_before: "sha256:before",
      model_mount_agentgres_state_root_after: "sha256:after",
      model_mount_agentgres_resulting_head: resultingHead,
      model_mount_agentgres_admission: {
        operation_ref: operationRef,
      },
      model_mount_step_module_invocation: {
        input: {
          state_root_before: "sha256:before",
        },
      },
      model_mount_step_module_result: {
        agentgres_operation_refs: [operationRef],
        state_root_after: "sha256:after",
        resulting_head: resultingHead,
      },
    },
    ...overrides,
  };
}

function legacyCamelBoundModelInvocationReceipt() {
  const operationRef = "agentgres://model-mounting/operation-log/op_00000001_model_invocation";
  const resultingHead = "agentgres://model-mounting/operation-log/head/1";
  return {
    id: "receipt.legacy-camel",
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
  };
}

function modelLifecycleReceipt(details = {}) {
  return {
    id: details.id ?? "receipt.model-lifecycle",
    kind: "model_lifecycle",
    redaction: "redacted",
    evidenceRefs: ["model_registry", "agentgres_receipt_projection_boundary", details.operation ?? "model_load"],
    details: {
      operation: "model_load",
      instance_id: "instance.local",
      model_id: "model.local",
      provider_id: "provider.local",
      provider_kind: "ioi_native_local",
      ...details,
    },
  };
}

function providerInventoryReceipt(details = {}) {
  return {
    id: details.id ?? "receipt.provider-inventory",
    kind: "model_lifecycle",
    redaction: "redacted",
    evidenceRefs: ["model_registry", "agentgres_receipt_projection_boundary", details.operation ?? "provider_models_list"],
    details: {
      operation: "provider_models_list",
      provider_id: "provider.local",
      provider_kind: "ioi_native_local",
      model_id: "Local",
      model_count: 1,
      ...details,
    },
  };
}

function providerHealthReceipt(details = {}) {
  return {
    id: details.id ?? "receipt.provider-health",
    kind: "provider_health",
    redaction: "redacted",
    evidenceRefs: ["provider_health_check"],
    details: {
      provider_id: "provider.local",
      provider_kind: "ioi_native_local",
      status: "available",
      ...details,
    },
  };
}

function providerControlReceipt(details = {}) {
  return {
    id: details.id ?? "receipt.provider-control",
    kind: "model_lifecycle",
    redaction: "redacted",
    evidenceRefs: ["model_registry", "agentgres_receipt_projection_boundary", details.operation ?? "provider_start"],
    details: {
      operation: "provider_start",
      provider_id: "provider.local",
      provider_kind: "ioi_native_local",
      model_id: "Local",
      state: "available",
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
      error.details.missing.includes("model_mount_receipt_binding_ref") &&
      error.details.missing.includes("model_mount_step_module_result.state_root_after"),
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
      error.details.missing.includes("model_mount_agentgres_operation_ref"),
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
      model_mount_agentgres_admission: {
        operation_ref: "agentgres://model-mounting/operation-log/op_00000002_model_invocation",
      },
    },
  });

  assert.throws(
    () => store.writeReceipt(receipt),
    (error) =>
      error.code === "model_mount_invocation_receipt_direct_append_forbidden" &&
      error.details.mismatches.includes("model_mount_agentgres_admission.operation_ref"),
  );
  assert.equal(fs.existsSync(path.join(stateDir, "receipts", "receipt.mismatch.json")), false);
  assert.deepEqual(appended, []);
});

test("model invocation receipt writes reject legacy camelCase binding details", () => {
  const { appended, stateDir, store } = testStore();

  assert.throws(
    () => store.writeReceipt(legacyCamelBoundModelInvocationReceipt()),
    (error) =>
      error.code === "model_mount_invocation_receipt_direct_append_forbidden" &&
      error.details.missing.includes("model_mount_receipt_binding_ref") &&
      error.details.missing.includes("model_mount_agentgres_operation_ref"),
  );
  assert.equal(fs.existsSync(path.join(stateDir, "receipts", "receipt.legacy-camel.json")), false);
  assert.deepEqual(appended, []);
});

test("model invocation receipt writes persist only after Rust receipt and Agentgres admission without operation append", () => {
  const { appended, stateDir, store } = testStore();
  const receipt = boundModelInvocationReceipt();

  store.writeReceipt(receipt);

  assert.equal(fs.existsSync(path.join(stateDir, "receipts", "receipt.model-invocation.json")), true);
  assert.deepEqual(appended, []);
});

test("receipt lookup returns persisted receipts and fails closed with canonical details", () => {
  const { store } = testStore();
  const receipt = boundModelInvocationReceipt();

  store.writeReceipt(receipt);

  assert.equal(store.getReceipt("receipt.model-invocation").id, "receipt.model-invocation");
  assert.throws(
    () => store.getReceipt("receipt.missing"),
    (error) => {
      assert.equal(error.status, 404);
      assert.equal(error.details.receipt_id, "receipt.missing");
      assert.equal(Object.hasOwn(error.details, "receiptId"), false);
      return true;
    },
  );
});

test("model lifecycle receipt writes fail closed without provider kind and Rust instance lifecycle binding", () => {
  const { appended, stateDir, store } = testStore();

  assert.throws(
    () =>
      store.writeReceipt(modelLifecycleReceipt({
        provider_kind: undefined,
      })),
    (error) =>
      error.code === "model_mount_instance_lifecycle_receipt_direct_append_forbidden" &&
      error.details.missing.includes("provider_kind"),
  );
  assert.throws(
    () =>
      store.writeReceipt(modelLifecycleReceipt({
        id: "receipt.legacy-model-lifecycle",
        provider_id: undefined,
        provider_kind: undefined,
        providerId: "provider.local",
        providerKind: "ioi_native_local",
    })),
    (error) =>
      error.code === "model_mount_instance_lifecycle_receipt_direct_append_forbidden" &&
      error.details.retired_aliases.includes("providerId") &&
      error.details.retired_aliases.includes("providerKind") &&
      Object.hasOwn(error.details, "providerKind") === false,
  );
  assert.throws(
    () => store.writeReceipt(modelLifecycleReceipt()),
    (error) =>
      error.code === "model_mount_instance_lifecycle_receipt_direct_append_forbidden" &&
      error.details.missing.includes("instance.local:model_mount_instance_lifecycle_hash"),
  );
  assert.equal(fs.existsSync(path.join(stateDir, "receipts", "receipt.model-lifecycle.json")), false);
  assert.deepEqual(appended, []);
});

test("model lifecycle receipt writes allow Rust-bound local and remote provider records", () => {
  const { appended, stateDir, store } = testStore();
  const localReceipt = modelLifecycleReceipt({
    id: "receipt.local-bound",
    model_mount_provider_lifecycle_hash: "sha256:provider-lifecycle",
    model_mount_instance_lifecycle_action: "load",
    model_mount_instance_lifecycle_status: "loaded",
    model_mount_instance_lifecycle_hash: "sha256:instance-lifecycle",
    model_mount_instance_lifecycle_evidence_refs: ["rust_model_mount_instance_lifecycle"],
  });
  const remoteReceipt = modelLifecycleReceipt({
    id: "receipt.remote",
    provider_id: "provider.remote",
    provider_kind: "openai_compatible",
  });

  store.writeReceipt(localReceipt);
  store.writeReceipt(remoteReceipt);

  assert.equal(fs.existsSync(path.join(stateDir, "receipts", "receipt.local-bound.json")), true);
  assert.equal(fs.existsSync(path.join(stateDir, "receipts", "receipt.remote.json")), true);
  assert.deepEqual(appended, []);
});

test("provider inventory receipt writes fail closed without provider kind and Rust inventory binding", () => {
  const { appended, stateDir, store } = testStore();

  assert.throws(
    () => store.writeReceipt(providerInventoryReceipt({ provider_kind: undefined })),
    (error) =>
      error.code === "model_mount_provider_inventory_receipt_direct_append_forbidden" &&
      error.details.missing.includes("provider_kind"),
  );
  assert.throws(
    () =>
      store.writeReceipt(providerInventoryReceipt({
        provider_id: undefined,
        provider_kind: undefined,
        providerId: "provider.local",
        providerKind: "ioi_native_local",
      })),
    (error) =>
      error.code === "model_mount_provider_inventory_receipt_direct_append_forbidden" &&
      error.details.retired_aliases.includes("providerId") &&
      error.details.retired_aliases.includes("providerKind") &&
      Object.hasOwn(error.details, "providerKind") === false,
  );
  assert.throws(
    () => store.writeReceipt(providerInventoryReceipt()),
    (error) =>
      error.code === "model_mount_provider_inventory_receipt_direct_append_forbidden" &&
      error.details.missing.includes("model_mount_provider_inventory_hash"),
  );
  assert.throws(
    () => store.writeReceipt(providerInventoryReceipt({
      modelMountProviderInventoryAction: "list_models",
      modelMountProviderInventoryStatus: "listed",
      modelMountProviderInventoryHash: "sha256:inventory",
      modelMountProviderInventoryEvidenceRefs: ["rust_model_mount_provider_inventory"],
    })),
    (error) =>
      error.code === "model_mount_provider_inventory_receipt_direct_append_forbidden" &&
      error.details.missing.includes("model_mount_provider_inventory_hash") &&
      error.details.missing.includes("model_mount_provider_inventory_evidence_refs"),
  );
  assert.equal(fs.existsSync(path.join(stateDir, "receipts", "receipt.provider-inventory.json")), false);
  assert.deepEqual(appended, []);
});

test("provider inventory receipt writes allow Rust-bound local and remote provider records", () => {
  const { appended, stateDir, store } = testStore();
  const localReceipt = providerInventoryReceipt({
    id: "receipt.inventory-local-bound",
    model_mount_provider_inventory_action: "list_models",
    model_mount_provider_inventory_status: "listed",
    model_mount_provider_inventory_hash: "sha256:inventory",
    model_mount_provider_inventory_evidence_refs: ["rust_model_mount_provider_inventory"],
  });
  const remoteReceipt = providerInventoryReceipt({
    id: "receipt.inventory-remote",
    provider_id: "provider.remote",
    provider_kind: "openai_compatible",
  });

  store.writeReceipt(localReceipt);
  store.writeReceipt(remoteReceipt);

  assert.equal(fs.existsSync(path.join(stateDir, "receipts", "receipt.inventory-local-bound.json")), true);
  assert.equal(fs.existsSync(path.join(stateDir, "receipts", "receipt.inventory-remote.json")), true);
  assert.deepEqual(appended, []);
});

test("provider health receipt writes fail closed without provider kind and Rust lifecycle binding", () => {
  const { appended, stateDir, store } = testStore();

  assert.throws(
    () => store.writeReceipt(providerHealthReceipt({ provider_kind: undefined })),
    (error) =>
      error.code === "model_mount_provider_health_receipt_direct_append_forbidden" &&
      error.details.missing.includes("provider_kind"),
  );
  assert.throws(
    () =>
      store.writeReceipt(providerHealthReceipt({
        provider_id: undefined,
        provider_kind: undefined,
        providerId: "provider.local",
        providerKind: "ioi_native_local",
      })),
    (error) =>
      error.code === "model_mount_provider_health_receipt_direct_append_forbidden" &&
      error.details.retired_aliases.includes("providerId") &&
      error.details.retired_aliases.includes("providerKind") &&
      Object.hasOwn(error.details, "providerKind") === false,
  );
  assert.throws(
    () => store.writeReceipt(providerHealthReceipt()),
    (error) =>
      error.code === "model_mount_provider_health_receipt_direct_append_forbidden" &&
      error.details.missing.includes("model_mount_provider_lifecycle_hash"),
  );
  assert.throws(
    () => store.writeReceipt(providerHealthReceipt({
      providerLifecycleHash: "sha256:health",
      modelMountProviderLifecycleAction: "health",
      modelMountProviderLifecycleStatus: "available",
      modelMountProviderLifecycleEvidenceRefs: ["rust_model_mount_provider_lifecycle"],
    })),
    (error) =>
      error.code === "model_mount_provider_health_receipt_direct_append_forbidden" &&
      error.details.missing.includes("model_mount_provider_lifecycle_hash") &&
      error.details.missing.includes("model_mount_provider_lifecycle_evidence_refs"),
  );
  assert.equal(fs.existsSync(path.join(stateDir, "receipts", "receipt.provider-health.json")), false);
  assert.deepEqual(appended, []);
});

test("provider health receipt writes allow Rust-bound local and remote provider records", () => {
  const { appended, stateDir, store } = testStore();
  const localReceipt = providerHealthReceipt({
    id: "receipt.health-local-bound",
    model_mount_provider_lifecycle_hash: "sha256:health",
    model_mount_provider_lifecycle_action: "health",
    model_mount_provider_lifecycle_status: "available",
    model_mount_provider_lifecycle_evidence_refs: ["rust_model_mount_provider_lifecycle"],
  });
  const remoteReceipt = providerHealthReceipt({
    id: "receipt.health-remote",
    provider_id: "provider.remote",
    provider_kind: "openai_compatible",
  });

  store.writeReceipt(localReceipt);
  store.writeReceipt(remoteReceipt);

  assert.equal(fs.existsSync(path.join(stateDir, "receipts", "receipt.health-local-bound.json")), true);
  assert.equal(fs.existsSync(path.join(stateDir, "receipts", "receipt.health-remote.json")), true);
  assert.deepEqual(appended, []);
});

test("provider control receipt writes fail closed without provider kind and Rust lifecycle binding", () => {
  const { appended, stateDir, store } = testStore();

  assert.throws(
    () => store.writeReceipt(providerControlReceipt({ provider_kind: undefined })),
    (error) =>
      error.code === "model_mount_provider_control_receipt_direct_append_forbidden" &&
      error.details.missing.includes("provider_kind"),
  );
  assert.throws(
    () =>
      store.writeReceipt(providerControlReceipt({
        provider_id: undefined,
        provider_kind: undefined,
        providerId: "provider.local",
        providerKind: "ioi_native_local",
      })),
    (error) =>
      error.code === "model_mount_provider_control_receipt_direct_append_forbidden" &&
      error.details.retired_aliases.includes("providerId") &&
      error.details.retired_aliases.includes("providerKind") &&
      Object.hasOwn(error.details, "providerKind") === false,
  );
  assert.throws(
    () => store.writeReceipt(providerControlReceipt()),
    (error) =>
      error.code === "model_mount_provider_control_receipt_direct_append_forbidden" &&
      error.details.missing.includes("model_mount_provider_lifecycle_hash"),
  );
  assert.equal(fs.existsSync(path.join(stateDir, "receipts", "receipt.provider-control.json")), false);
  assert.deepEqual(appended, []);
});

test("provider control receipt writes allow Rust-bound local and remote provider records", () => {
  const { appended, stateDir, store } = testStore();
  const localReceipt = providerControlReceipt({
    id: "receipt.control-local-bound",
    model_mount_provider_lifecycle_hash: "sha256:start",
    model_mount_provider_lifecycle_action: "start",
    model_mount_provider_lifecycle_status: "available",
    model_mount_provider_lifecycle_evidence_refs: ["rust_model_mount_provider_lifecycle"],
  });
  const remoteReceipt = providerControlReceipt({
    id: "receipt.control-remote",
    provider_id: "provider.remote",
    provider_kind: "openai_compatible",
  });

  store.writeReceipt(localReceipt);
  store.writeReceipt(remoteReceipt);

  assert.equal(fs.existsSync(path.join(stateDir, "receipts", "receipt.control-local-bound.json")), true);
  assert.equal(fs.existsSync(path.join(stateDir, "receipts", "receipt.control-remote.json")), true);
  assert.deepEqual(appended, []);
});
