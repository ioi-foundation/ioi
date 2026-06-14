import assert from "node:assert/strict";
import fs from "node:fs";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import { AgentgresModelMountingStore } from "./store.mjs";

function testStore() {
  const appended = [];
  const commits = [];
  const stateDir = mkdtempSync(path.join(tmpdir(), "ioi-model-mounting-store-"));
  const store = new AgentgresModelMountingStore({
    stateDir,
    commitRuntimeModelMountReceiptState: fakeReceiptCommitter(stateDir, commits),
    appendOperation: (kind, payload) => appended.push({ kind, payload }),
  });
  return { appended, commits, stateDir, store };
}

function fakeReceiptCommitter(stateDir, commits) {
  return function commitRuntimeModelMountReceiptState(request) {
    commits.push(request);
    const recordPath = path.join("receipts", `${request.receipt_id}.json`);
    const targetPath = path.join(stateDir, recordPath);
    fs.mkdirSync(path.dirname(targetPath), { recursive: true });
    fs.writeFileSync(targetPath, `${JSON.stringify(request.receipt, null, 2)}\n`);
    return {
      source: "rust_agentgres_runtime_model_mount_receipt_state_commit_command",
      backend: "rust_agentgres_storage",
      record: {
        schema_version: "ioi.runtime_model_mount_receipt_state_commit.v1",
        receipt_id: request.receipt_id,
        operation_kind: request.operation_kind,
        storage_backend_ref: request.storage_backend_ref,
        record: {
          record_path: recordPath,
          object_ref: `agentgres://model-mounting/receipts/${request.receipt_id}/records/${recordPath}`,
          content_hash: "sha256:receipt-content",
          payload_refs: [`payload://model-mounting/receipts/${request.receipt_id}/records/${recordPath}`],
          receipt_refs: request.receipt_refs,
          admission: { admission_hash: "sha256:receipt-admission" },
        },
        commit_hash: "sha256:receipt-commit",
      },
      storage_record: {
        record_path: recordPath,
        object_ref: `agentgres://model-mounting/receipts/${request.receipt_id}/records/${recordPath}`,
        content_hash: "sha256:receipt-content",
        payload_refs: [`payload://model-mounting/receipts/${request.receipt_id}/records/${recordPath}`],
        receipt_refs: request.receipt_refs,
        admission: { admission_hash: "sha256:receipt-admission" },
      },
      receipt_id: request.receipt_id,
      object_ref: `agentgres://model-mounting/receipts/${request.receipt_id}/records/${recordPath}`,
      content_hash: "sha256:receipt-content",
      admission_hash: "sha256:receipt-admission",
      commit_hash: "sha256:receipt-commit",
      written_record: { record_path: recordPath },
      evidence_refs: ["rust_agentgres_runtime_model_mount_receipt_state_commit"],
    };
  };
}

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function boundModelInvocationReceipt(overrides = {}) {
  const operationRef = "agentgres://model-mounting/accepted-receipts/op_00000001_model_invocation";
  const resultingHead = "agentgres://model-mounting/accepted-receipts/head/1";
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

function boundMcpExecutionReceipt(overrides = {}) {
  const operationRef = "agentgres://model-mounting/mcp-workflow/mcp_tool_alpha";
  const resultingHead = "agentgres://model-mounting/mcp-workflow/head/mcp_tool_alpha";
  return {
    id: "receipt.mcp-tool",
    kind: "mcp_tool_invocation",
    schemaVersion: "ioi.model_mount.mcp_workflow_receipt.v1",
    redaction: "redacted",
    evidenceRefs: [
      "rust_model_mount_core",
      "rust_daemon_core_model_mount_mcp_workflow",
      "model_mount_mcp_execution_content_receipt_rust_owned",
      "agentgres_mcp_content_receipt_truth_required",
    ],
    details: {
      rust_daemon_core_receipt_author: "model_mount.mcp_workflow",
      operation_kind: "model_mount.mcp_tool.invoke",
      model_mount_mcp_workflow_ref: "model_mount://mcp_workflow/mcp_tool.alpha",
      model_mount_mcp_content_receipt_id: "receipt.mcp-tool",
      model_mount_mcp_content_hash: "sha256:mcp-content",
      model_mount_mcp_result_materialized: false,
      model_mount_mcp_result_materialization_status: "rust_admitted_pending_transport_backend",
      workflow_hash: "sha256:mcp-workflow",
      authority_hash: "sha256:mcp-authority",
      model_mount_agentgres_operation_ref: operationRef,
      model_mount_agentgres_state_root_before: "sha256:mcp-before",
      model_mount_agentgres_state_root_after: "sha256:mcp-after",
      model_mount_agentgres_resulting_head: resultingHead,
      model_mount_step_module_result: {
        status: "admitted",
        agentgres_operation_refs: [operationRef],
        state_root_after: "sha256:mcp-after",
        resulting_head: resultingHead,
        content_hash: "sha256:mcp-content",
        result_materialized: false,
      },
    },
    createdAt: "2026-06-14T00:00:00.000Z",
    ...overrides,
  };
}

function legacyCamelBoundModelInvocationReceipt() {
  const operationRef = "agentgres://model-mounting/accepted-receipts/op_00000001_model_invocation";
  const resultingHead = "agentgres://model-mounting/accepted-receipts/head/1";
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

test("MCP execution receipt writes fail closed without Rust workflow binding", () => {
  const { appended, stateDir, store } = testStore();

  assert.throws(
    () =>
      store.writeReceipt({
        id: "receipt.mcp-direct",
        kind: "mcp_tool_invocation",
        schemaVersion: "ioi.model_mount.mcp_workflow_receipt.v1",
        redaction: "redacted",
        evidenceRefs: ["daemon_js_direct_write"],
        details: {},
      }),
    (error) =>
      error.code === "model_mount_mcp_execution_receipt_direct_append_forbidden" &&
      error.details.missing.includes("evidenceRefs.model_mount_mcp_execution_content_receipt_rust_owned") &&
      error.details.missing.includes("model_mount_step_module_result.state_root_after"),
  );
  assert.equal(fs.existsSync(path.join(stateDir, "receipts", "receipt.mcp-direct.json")), false);
  assert.deepEqual(appended, []);
});

test("MCP execution receipt writes persist only after Rust content receipt and Agentgres admission", () => {
  const { appended, commits, stateDir, store } = testStore();
  const receipt = boundMcpExecutionReceipt();

  const commit = store.writeReceipt(receipt);

  assert.equal(commit.receipt_id, "receipt.mcp-tool");
  assert.equal(commits.length, 1);
  assert.equal(commits[0].operation_kind, "model_mount.receipt.write");
  assert.deepEqual(commits[0].receipt_refs, ["receipt.mcp-tool"]);
  assert.equal(
    readJson(path.join(stateDir, "receipts", "receipt.mcp-tool.json")).details
      .rust_daemon_core_receipt_author,
    "model_mount.mcp_workflow",
  );
  assert.deepEqual(appended, []);
});

test("model invocation receipt writes reject mismatched Agentgres operation refs", () => {
  const { appended, stateDir, store } = testStore();
  const receipt = boundModelInvocationReceipt({
    id: "receipt.mismatch",
    details: {
      ...boundModelInvocationReceipt().details,
      model_mount_agentgres_admission: {
        operation_ref: "agentgres://model-mounting/accepted-receipts/op_00000002_model_invocation",
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

test("model invocation receipt writes reject retired model-mounting operation-log refs", () => {
  const { appended, stateDir, store } = testStore();
  const operationRef = "agentgres://model-mounting/operation-log/op_00000001_model_invocation";
  const resultingHead = "agentgres://model-mounting/operation-log/head/1";
  const receipt = boundModelInvocationReceipt({
    id: "receipt.retired-operation-log",
    details: {
      ...boundModelInvocationReceipt().details,
      model_mount_agentgres_operation_ref: operationRef,
      model_mount_agentgres_resulting_head: resultingHead,
      model_mount_agentgres_admission: {
        operation_ref: operationRef,
      },
      model_mount_step_module_result: {
        agentgres_operation_refs: [operationRef],
        state_root_after: "sha256:after",
        resulting_head: resultingHead,
      },
    },
  });

  assert.throws(
    () => store.writeReceipt(receipt),
    (error) =>
      error.code === "model_mount_invocation_receipt_direct_append_forbidden" &&
      error.details.mismatches.includes("model_mount_agentgres_operation_ref_namespace") &&
      error.details.mismatches.includes("model_mount_agentgres_resulting_head_namespace"),
  );
  assert.equal(fs.existsSync(path.join(stateDir, "receipts", "receipt.retired-operation-log.json")), false);
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
  const { appended, commits, stateDir, store } = testStore();
  const receipt = boundModelInvocationReceipt();

  store.writeReceipt(receipt);

  assert.equal(fs.existsSync(path.join(stateDir, "receipts", "receipt.model-invocation.json")), true);
  assert.equal(commits.length, 1);
  assert.equal(commits[0].schema_version, "ioi.runtime_model_mount_receipt_state_commit.v1");
  assert.equal(commits[0].receipt_id, "receipt.model-invocation");
  assert.equal(commits[0].operation_kind, "model_mount.receipt.write");
  assert.deepEqual(commits[0].receipt_refs, ["receipt.model-invocation"]);
  assert.deepEqual(appended, []);
});

test("model invocation receipt writes fail closed without Rust receipt-state commit", () => {
  const stateDir = mkdtempSync(path.join(tmpdir(), "ioi-model-mounting-store-"));
  const store = new AgentgresModelMountingStore({ stateDir });

  assert.throws(
    () => store.writeReceipt(boundModelInvocationReceipt({ id: "receipt.unconfigured" })),
    (error) =>
      error.code === "model_mount_receipt_state_commit_unconfigured" &&
      error.details.receipt_id === "receipt.unconfigured",
  );
  assert.equal(fs.existsSync(path.join(stateDir, "receipts", "receipt.unconfigured.json")), false);
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

test("store map writes fail closed as a retired direct persistence path", () => {
  const { stateDir, store } = testStore();
  const map = new Map([["artifact.direct", { id: "artifact.direct" }]]);

  assert.throws(
    () => store.writeMap("model-artifacts", map),
    (error) =>
      error.code === "model_mount_store_map_write_retired" &&
      error.details.dir === "model-artifacts" &&
      error.details.record_count === 1 &&
      error.details.canonical_persistence === "rust_agentgres_record_state_commit",
  );
  assert.equal(
    fs.existsSync(path.join(stateDir, "model-artifacts", "artifact.direct.json")),
    false,
  );
});

test("canonical projection writes fail closed without Rust projection plan evidence", () => {
  const { appended, stateDir, store } = testStore();
  const projection = {
    schemaVersion: "model.mount.schema",
    source: "agentgres_model_mounting_projection",
    watermark: 1,
  };

  assert.throws(
    () => store.writeProjection("model-mounting-canonical", projection),
    (error) =>
      error.code === "model_mount_projection_direct_write_forbidden" &&
      error.details.missing.includes("rust_projection_plan") &&
      error.details.missing.includes("evidence_refs.rust_daemon_core_model_mount_projection"),
  );
  assert.equal(
    fs.existsSync(path.join(stateDir, "projections", "model-mounting-canonical.json")),
    false,
  );
  assert.deepEqual(appended, []);
});

test("canonical projection writes persist only after Rust projection planning", () => {
  const { appended, stateDir, store } = testStore();
  const projection = {
    schemaVersion: "model.mount.schema",
    source: "agentgres_model_mounting_projection",
    watermark: 1,
  };
  const rustProjection = {
    source: "rust_model_mount_read_projection_command",
    backend: "rust_model_mount_read_projection",
    projection_kind: "projection",
    projection,
    evidence_refs: [
      "rust_daemon_core_model_mount_projection",
      "agentgres_model_mount_read_truth",
      "model_mount_js_read_projection_authoring_retired",
    ],
  };

  store.writeProjection("model-mounting-canonical", projection, { rustProjection });

  assert.deepEqual(
    JSON.parse(fs.readFileSync(path.join(stateDir, "projections", "model-mounting-canonical.json"), "utf8")),
    projection,
  );
  assert.deepEqual(appended, []);
});

test("projection cache reads fail closed as a retired direct read path", () => {
  const { store } = testStore();

  assert.throws(
    () => store.readProjection("model-mounting-canonical"),
    (error) =>
      error.code === "model_mount_projection_cache_read_retired" &&
      error.details.projection === "model-mounting-canonical" &&
      error.details.canonical_projection === "rust_daemon_core_model_mount_projection_plan",
  );
});

test("adapter status identifies Rust-plan-gated projection ownership", () => {
  const { store } = testStore();
  const status = store.adapterStatus();

  assert.equal(status.implementation, "rust_plan_gated_receipt_projection_adapter");
  assert.equal(status.evidenceRefs.includes("model_mount_projection_cache_read_retired"), true);
  assert.equal(status.evidenceRefs.includes("rust_daemon_core_model_mount_projection_required"), true);
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
