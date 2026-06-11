import assert from "node:assert/strict";
import test from "node:test";

import { ModelMountingState } from "../model-mounting.mjs";

function callMounted(method, state, ...args) {
  return ModelMountingState.prototype[method].call(state, ...args);
}

function fakeState() {
  const state = {
    serverControlRequiredRequests: [],
    serverControlRequired(operationKind, details = {}) {
      return ModelMountingState.prototype.serverControlRequired.call(this, operationKind, details);
    },
  };
  state.modelMountAdmissionRunner = {
    planServerControlRequired(request) {
      state.serverControlRequiredRequests.push(request);
      return {
        status: "rust_core_required",
        status_code: 501,
        code: "model_mount_server_control_rust_core_required",
        message: "Server-control facade requires Rust daemon-core model_mount server-control ownership.",
        rust_core_boundary: "model_mount.server_control",
        operation_kind: request.operation_kind,
        evidence_refs: request.evidence_refs,
        details: {
          operation: request.operation,
          ...request.details,
          operation_kind: request.operation_kind,
          rust_core_boundary: "model_mount.server_control",
          source: request.source,
          evidence_refs: request.evidence_refs,
        },
      };
    },
  };
  return state;
}

function assertServerControlRustCoreRequired(error, operationKind, details = {}) {
  assert.equal(error.status, 501);
  assert.equal(error.code, "model_mount_server_control_rust_core_required");
  assert.equal(error.details.operation_kind, operationKind);
  assert.equal(error.details.rust_core_boundary, "model_mount.server_control");
  assert.deepEqual(error.details.evidence_refs, [
    "public_server_control_js_facade_retired",
    "rust_daemon_core_server_control_required",
    "agentgres_server_control_truth_required",
  ]);
  for (const [key, value] of Object.entries(details)) {
    assert.equal(error.details[key], value);
  }
  assert.equal(Object.hasOwn(error.details, "operationKind"), false);
  assert.equal(Object.hasOwn(error.details, "rustCoreBoundary"), false);
  assert.equal(Object.hasOwn(error.details, "evidenceRefs"), false);
  return true;
}

test("mounted server control state is volatile input only", () => {
  const state = fakeState();

  const controlState = callMounted("serverControlState", state);

  assert.deepEqual(controlState, {
    id: "server-control.default",
    schemaVersion: "ioi.model-mounting.runtime.v1",
    status: "running",
    gatewayStatus: "running",
    operation: "server_status",
    updatedAt: null,
    receiptId: null,
    evidenceRefs: ["ioi_daemon_public_runtime_api"],
  });
  assert.equal(Object.hasOwn(controlState, "schema_version"), false);
});

test("mounted server control mutation/log facades fail closed before JS state or log writes", () => {
  const state = fakeState();
  const cases = [
    [() => callMounted("serverStart", state, null), "model_mount.server_control.start"],
    [() => callMounted("serverStop", state, null), "model_mount.server_control.stop"],
    [() => callMounted("serverRestart", state, "http://daemon.test"), "model_mount.server_control.restart"],
    [() => callMounted("serverLogs", state, { limit: "500" }), "model_mount.server_control.logs_read"],
    [() => callMounted("serverEvents", state, { limit: 1 }), "model_mount.server_control.events_read"],
    [() => callMounted("serverLogRecords", state, { limit: 2 }), "model_mount.server_control.log_projection"],
    [() => callMounted("writeServerLog", state, { event: "provider_probe", authorization: "Bearer secret-token" }), "model_mount.server_control.log_append"],
  ];

  for (const [run, operationKind] of cases) {
    assert.throws(run, (error) => assertServerControlRustCoreRequired(error, operationKind));
  }

  assert.equal(state.serverControlRequiredRequests.length, cases.length);
  assert.equal(
    state.serverControlRequiredRequests[0].schema_version,
    "ioi.model_mount.server_control_required.v1",
  );
  assert.equal(state.serverControlRequiredRequests[0].operation, "model_mount.server_control");
  assert.equal(state.serverControlRequiredRequests[0].operation_kind, "model_mount.server_control.start");
  assert.equal(
    state.serverControlRequiredRequests.at(-1).operation_kind,
    "model_mount.server_control.log_append",
  );
  assert.equal(Object.hasOwn(state.serverControlRequiredRequests[0], "operationKind"), false);
});

test("mounted server control state writes and operation recording fail closed", () => {
  const state = fakeState();

  assert.throws(
    () =>
      callMounted("writeServerControlState", state, {
        schemaVersion: "schema.retired",
        status: "stopped",
        operation: "server_stop",
        receiptId: "receipt.server_stop.1",
      }),
    (error) =>
      assertServerControlRustCoreRequired(error, "model_mount.server_control.write", {
        server_control_id: "server-control.default",
        receipt_id: "receipt.server_stop.1",
      }),
  );
  assert.equal(state.serverControlRequiredRequests[0].operation_kind, "model_mount.server_control.write");
  assert.equal(state.serverControlRequiredRequests[0].details.server_control_id, "server-control.default");
  assert.equal(state.serverControlRequiredRequests[0].details.receipt_id, "receipt.server_stop.1");
  assert.equal(Object.hasOwn(state.serverControlRequiredRequests[0].details, "receiptId"), false);

  assert.throws(
    () =>
      callMounted("recordServerOperation", state, "server_stop", "blocked", "http://daemon.test", {
        reason: "test",
      }),
    (error) =>
      assertServerControlRustCoreRequired(error, "model_mount.server_control.record_operation", {
        operation: "server_stop",
        status: "blocked",
        base_url: "http://daemon.test",
        reason: "test",
      }),
  );
  assert.equal(
    state.serverControlRequiredRequests[1].operation_kind,
    "model_mount.server_control.record_operation",
  );
  assert.equal(state.serverControlRequiredRequests[1].details.base_url, "http://daemon.test");
  assert.equal(Object.hasOwn(state.serverControlRequiredRequests[1].details, "baseUrl"), false);
});
