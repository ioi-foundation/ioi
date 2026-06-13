import assert from "node:assert/strict";
import test from "node:test";

import { ModelMountingState } from "../model-mounting.mjs";

function callMounted(method, state, ...args) {
  return ModelMountingState.prototype[method].call(state, ...args);
}

function fakeState() {
  const state = {
    serverControlPlans: [],
    recordStateCommits: [],
    readProjectionCalls: [],
    nowIso: () => "2026-06-13T12:00:00.000Z",
    readProjectionFacade: {
      serverLogs(target, query) {
        state.readProjectionCalls.push({ projection_kind: "server_logs", query, sameState: target === state });
        return serverProjectionResponse("server_logs", { records: [{ event: "server_restart" }] });
      },
      serverEvents(target, query) {
        state.readProjectionCalls.push({ projection_kind: "server_events", query, sameState: target === state });
        return serverProjectionResponse("server_events", { events: [{ event: "server_restart" }] });
      },
      serverLogRecords(target, query) {
        state.readProjectionCalls.push({ projection_kind: "server_log_records", query, sameState: target === state });
        return serverProjectionResponse("server_log_records", { records: [{ event: "server_restart" }] });
      },
    },
    planServerControl(request) {
      state.serverControlPlans.push(request);
      const hash = `sha256:${request.operation_kind.replaceAll(".", "_")}`;
      const recordId = `server-control:${state.serverControlPlans.length}`;
      return {
        source: "rust_model_mount_server_control_command",
        backend: "rust_model_mount_server_control",
        schema_version: "ioi.model_mount.server_control_plan.v1",
        object: "ioi.model_mount_server_control_plan",
        status: "planned",
        rust_core_boundary: "model_mount.server_control",
        operation_kind: request.operation_kind,
        source_request: request.source,
        record_dir: "model-server-controls",
        record_id: recordId,
        record: {
          id: recordId,
          object: "ioi.model_mount_server_control_record",
          rust_core_boundary: "model_mount.server_control",
          operation_kind: request.operation_kind,
          public_response: {
            object: "ioi.model_mount_server_control",
            status: "planned",
            operation_kind: request.operation_kind,
            server_control_id: request.server_control_id,
          },
          evidence_refs: [
            "public_server_control_js_facade_retired",
            "rust_daemon_core_server_control",
            "agentgres_server_control_truth_required",
          ],
        },
        public_response: {
          object: "ioi.model_mount_server_control",
          status: "planned",
          operation_kind: request.operation_kind,
          server_control_id: request.server_control_id,
          js_state_write: false,
          js_log_write: false,
          js_transport_execution: false,
        },
        receipt_refs: request.receipt_refs ?? [],
        evidence_refs: [
          "public_server_control_js_facade_retired",
          "rust_daemon_core_server_control",
          "agentgres_server_control_truth_required",
        ],
        control_hash: hash,
      };
    },
    commitRuntimeModelMountRecordState(request) {
      state.recordStateCommits.push(request);
      return {
        record_id: request.record_id,
        object_ref: `model-server-controls/${request.record_id}`,
        content_hash: "sha256:content",
        admission_hash: "sha256:admission",
        commit_hash: "sha256:commit",
        written_record: request.record,
        storage_record: {
          object_ref: `model-server-controls/${request.record_id}`,
          content_hash: "sha256:content",
          admission: { admission_hash: "sha256:admission" },
        },
      };
    },
  };
  return state;
}

function serverProjectionResponse(projectionKind, payload) {
  return {
    object: "ioi.model_mount_server_logs",
    status: "projected",
    projectionKind,
    rustCoreBoundary: "model_mount.server_control_log_projection",
    evidenceRefs: [
      "rust_daemon_core_server_control_log_projection",
      "agentgres_server_control_log_replay_required",
      "model_mount_server_log_read_js_control_path_retired",
    ],
    ...payload,
  };
}

function fakeStateWithoutPlanner() {
  const state = fakeState();
  delete state.planServerControl;
  return state;
}

function assertServerControlRustCoreRequired(error, operationKind, details = {}) {
  assert.equal(error.status, 501);
  assert.equal(error.code, "model_mount_server_control_rust_core_required");
  assert.equal(error.details.operation_kind, operationKind);
  assert.equal(error.details.rust_core_boundary, "model_mount.server_control");
  assert.deepEqual(error.details.evidence_refs, [
    "public_server_control_js_facade_retired",
    "rust_daemon_core_server_control",
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

test("mounted server control mutation facades commit Rust-authored records", () => {
  const state = fakeState();
  const cases = [
    [() => callMounted("serverStart", state, null), "model_mount.server_control.start"],
    [() => callMounted("serverStop", state, null), "model_mount.server_control.stop"],
    [() => callMounted("serverRestart", state, "http://daemon.test"), "model_mount.server_control.restart"],
    [() => callMounted("writeServerLog", state, { event: "provider_probe", authorization: "Bearer secret-token" }), "model_mount.server_control.log_append"],
  ];

  for (const [run, operationKind] of cases) {
    const response = run();
    assert.equal(response.operation_kind, operationKind);
    assert.equal(response.rust_core_boundary, "model_mount.server_control");
    assert.equal(response.evidence_refs.includes("rust_daemon_core_server_control"), true);
    assert.equal(response.commit.record_id, response.record_id);
  }

  assert.equal(state.serverControlPlans.length, cases.length);
  assert.equal(state.recordStateCommits.length, cases.length);
  assert.equal(
    state.serverControlPlans[0].schema_version,
    "ioi.model_mount.server_control.v1",
  );
  assert.equal(state.serverControlPlans[0].operation_kind, "model_mount.server_control.start");
  assert.equal(
    state.serverControlPlans.at(-1).operation_kind,
    "model_mount.server_control.log_append",
  );
  assert.equal(state.serverControlPlans.at(-1).body.authorization, undefined);
  assert.equal(Object.hasOwn(state.serverControlPlans[0], "operationKind"), false);
});

test("mounted server log and event reads use Rust read projection", () => {
  const state = fakeState();

  const logs = callMounted("serverLogs", state, { limit: "500", authorization: "Bearer secret-token" });
  const events = callMounted("serverEvents", state, { limit: 1 });
  const records = callMounted("serverLogRecords", state, { limit: 2 });

  assert.equal(logs.rustCoreBoundary, "model_mount.server_control_log_projection");
  assert.equal(events.rustCoreBoundary, "model_mount.server_control_log_projection");
  assert.equal(records.rustCoreBoundary, "model_mount.server_control_log_projection");
  assert.deepEqual(state.readProjectionCalls.map((call) => call.projection_kind), [
    "server_logs",
    "server_events",
    "server_log_records",
  ]);
  assert.equal(state.readProjectionCalls.every((call) => call.sameState), true);
  assert.deepEqual(state.readProjectionCalls[0].query, { limit: "500", authorization: "Bearer secret-token" });
  assert.equal(state.serverControlPlans.length, 0);
  assert.equal(state.recordStateCommits.length, 0);
});

test("mounted server control state writes and operation recording commit Rust truth", () => {
  const state = fakeState();

  const written = callMounted("writeServerControlState", state, {
    schemaVersion: "schema.retired",
    status: "stopped",
    operation: "server_stop",
    receiptId: "receipt.server_stop.1",
  });
  assert.equal(written.operation_kind, "model_mount.server_control.write");
  assert.equal(state.serverControlPlans[0].server_control_id, "server-control.default");
  assert.equal(state.serverControlPlans[0].receipt_refs[0], "receipt.server_stop.1");
  assert.equal(Object.hasOwn(state.serverControlPlans[0].body, "receiptId"), false);

  const recorded = callMounted("recordServerOperation", state, "server_stop", "blocked", "http://daemon.test", {
    reason: "test",
  });
  assert.equal(recorded.operation_kind, "model_mount.server_control.record_operation");
  assert.equal(
    state.serverControlPlans[1].operation_kind,
    "model_mount.server_control.record_operation",
  );
  assert.equal(state.serverControlPlans[1].body.base_url, "http://daemon.test");
  assert.equal(Object.hasOwn(state.serverControlPlans[1].body, "baseUrl"), false);
  assert.equal(state.recordStateCommits.length, 2);
});

test("mounted server control fails closed before JS writes when Rust planner is missing", () => {
  const state = fakeStateWithoutPlanner();

  assert.throws(
    () => callMounted("serverStart", state, null),
    (error) => assertServerControlRustCoreRequired(error, "model_mount.server_control.start"),
  );
  assert.equal(state.serverControlPlans.length, 0);
  assert.equal(state.recordStateCommits.length, 0);
});
