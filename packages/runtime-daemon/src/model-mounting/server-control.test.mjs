import assert from "node:assert/strict";
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  serverEvents,
  serverLogRecords,
  serverLogs,
  serverRestart,
  serverStart,
  serverStatusProjectionInput,
  serverStop,
  writeServerControlState,
  writeServerLog,
} from "./server-control.mjs";

const SCHEMA = "schema.server-control.test";

function fakeState({ stateDir = mkdtempSync(join(tmpdir(), "ioi-server-control-")) } = {}) {
  const receipts = [];
  const recordStateCommits = [];
  const state = {
    stateDir,
    recordStateCommits,
    providers: new Map([
      ["provider.local", { id: "provider.local", status: "available" }],
      ["provider.remote", { id: "provider.remote", status: "blocked" }],
    ]),
    endpoints: new Map([["endpoint.local", { id: "endpoint.local" }]]),
    instances: new Map([["instance.loaded", { id: "instance.loaded", status: "loaded" }]]),
    backends: [
      { id: "backend.ok", status: "running" },
      { id: "backend.bad", status: "degraded" },
    ],
    evicted: 0,
    coalesced: 0,
    now: "2026-06-03T20:45:00.000Z",
    evictExpiredInstances() {
      this.evicted += 1;
    },
    coalesceLoadedInstances() {
      this.coalesced += 1;
    },
    listBackends() {
      return this.backends;
    },
    lifecycleReceipt(kind, details) {
      const receipt = { id: `receipt.${kind}.${receipts.length + 1}`, kind, details };
      receipts.push(receipt);
      return receipt;
    },
    commitRuntimeModelMountRecordState(request) {
      recordStateCommits.push(JSON.parse(JSON.stringify(request)));
      return {
        record_id: request.record_id,
        object_ref: `agentgres://model-mounting/records/${request.record_dir}/${request.record_id}`,
        content_hash: `sha256:${request.record_id}`,
        admission_hash: `admit:${request.record_id}`,
        commit_hash: `commit:${request.record_id}`,
        written_record: request.record,
        storage_record: {
          object_ref: `agentgres://model-mounting/records/${request.record_dir}/${request.record_id}`,
          content_hash: `sha256:${request.record_id}`,
          admission: { admission_hash: `admit:${request.record_id}` },
        },
      };
    },
    nowIso() {
      return this.now;
    },
    receipts,
  };
  return state;
}

test("server control builds primitive server-status projection input", () => {
  const state = fakeState();
  try {
    const input = serverStatusProjectionInput(state, "http://127.0.0.1:3200", { schema_version: SCHEMA });

    assert.equal(input.schema_version, SCHEMA);
    assert.equal(input.base_url, "http://127.0.0.1:3200");
    assert.equal(input.loaded_instances, 1);
    assert.equal(input.mounted_endpoints, 1);
    assert.deepEqual(input.provider_statuses, ["available", "blocked"]);
    assert.deepEqual(input.backend_statuses, ["running", "degraded"]);
    assert.deepEqual(input.control_state, {
      status: "running",
      gateway_status: "running",
      operation: "server_status",
      updated_at: null,
      receipt_id: null,
    });
    assert.equal(input.checked_at, "2026-06-03T20:45:00.000Z");
    assert.equal(Object.hasOwn(input, "status"), false);
    assert.equal(Object.hasOwn(input, "schemaVersion"), false);
    assert.equal(state.evicted, 1);
    assert.equal(state.coalesced, 1);
  } finally {
    rmSync(state.stateDir, { recursive: true, force: true });
  }
});

test("server control status ignores retired local server-state cache", () => {
  const state = fakeState();
  try {
    writeFileSync(
      join(state.stateDir, "server-state.json"),
      JSON.stringify({
        id: "server-control.default",
        status: "stopped",
        operation: "server_stop",
        updatedAt: "2026-01-01T00:00:00.000Z",
        receiptId: "receipt.legacy.server_stop",
      }),
    );

    const input = serverStatusProjectionInput(state, "http://127.0.0.1:3200", { schema_version: SCHEMA });

    assert.equal(input.control_state.status, "running");
    assert.equal(input.control_state.operation, "server_status");
    assert.equal(input.control_state.updated_at, null);
    assert.equal(input.control_state.receipt_id, null);
  } finally {
    rmSync(state.stateDir, { recursive: true, force: true });
  }
});

test("server control facade operations fail closed until Rust core owns control", () => {
  const state = fakeState();
  try {
    const cases = [
      [() => serverStart(state, null, { schema_version: SCHEMA }), "model_mount.server_control.start"],
      [() => serverStop(state, null, { schema_version: SCHEMA }), "model_mount.server_control.stop"],
      [() => serverRestart(state, "http://daemon.test", { schema_version: SCHEMA }), "model_mount.server_control.restart"],
    ];

    for (const [run, operationKind] of cases) {
      assert.throws(run, (error) => {
        assert.equal(error.status, 501);
        assert.equal(error.code, "model_mount_server_control_rust_core_required");
        assert.equal(error.details.operation_kind, operationKind);
        assert.equal(error.details.rust_core_boundary, "model_mount.server_control");
        assert.deepEqual(error.details.evidence_refs, [
          "public_server_control_js_facade_retired",
          "rust_daemon_core_server_control_required",
        ]);
        assert.equal(Object.hasOwn(error.details, "operationKind"), false);
        assert.equal(Object.hasOwn(error.details, "rustCoreBoundary"), false);
        assert.equal(Object.hasOwn(error.details, "evidenceRefs"), false);
        return true;
      });
    }

    assert.deepEqual(state.receipts, []);
    assert.deepEqual(state.recordStateCommits, []);
    assert.equal(existsSync(join(state.stateDir, "server-state.json")), false);
    assert.equal(existsSync(join(state.stateDir, "server-logs", "server.jsonl")), false);
  } finally {
    rmSync(state.stateDir, { recursive: true, force: true });
  }
});

test("server control ignores retired schemaVersion option before record-state commit", () => {
  const state = fakeState();
  try {
    assert.throws(
      () => serverStop(state, null, {
        schema_version: SCHEMA,
        schemaVersion: "schema.retired",
      }),
      (error) => {
        assert.equal(error.code, "model_mount_server_control_rust_core_required");
        assert.equal(error.details.operation_kind, "model_mount.server_control.stop");
        return true;
      },
    );
    assert.deepEqual(state.recordStateCommits, []);
  } finally {
    rmSync(state.stateDir, { recursive: true, force: true });
  }

  const aliasOnlyState = fakeState();
  try {
    const aliasOnly = serverStatusProjectionInput(aliasOnlyState, null, { schemaVersion: "schema.retired.only" });
    assert.equal(aliasOnly.schema_version, undefined);
  } finally {
    rmSync(aliasOnlyState.stateDir, { recursive: true, force: true });
  }
});

test("server control state writes fail closed before Rust admission or local cache writes", () => {
  const state = fakeState();
  try {
    assert.throws(
      () => writeServerControlState(state, {
        schemaVersion: SCHEMA,
        status: "stopped",
        operation: "server_stop",
        receiptId: "receipt.server_stop.1",
      }),
      (error) => {
        assert.equal(error.status, 501);
        assert.equal(error.code, "model_mount_server_control_rust_core_required");
        assert.equal(error.details.operation_kind, "model_mount.server_control.write");
        assert.equal(error.details.server_control_id, "server-control.default");
        assert.equal(error.details.receipt_id, "receipt.server_stop.1");
        return true;
      },
    );
    assert.deepEqual(state.recordStateCommits, []);
    assert.equal(existsSync(join(state.stateDir, "server-state.json")), false);
  } finally {
    rmSync(state.stateDir, { recursive: true, force: true });
  }
});

test("server control logs and events fail closed before local ring-buffer reads or appends", () => {
  const state = fakeState();
  try {
    const cases = [
      [() => writeServerLog(state, { event: "provider_probe", authorization: "Bearer secret-token" }), "model_mount.server_control.log_append"],
      [() => serverLogRecords(state, { limit: 2 }), "model_mount.server_control.log_projection"],
      [() => serverLogs(state, { limit: "500" }, { schema_version: SCHEMA }), "model_mount.server_control.logs_read"],
      [() => serverEvents(state, { limit: 1 }, { schema_version: SCHEMA }), "model_mount.server_control.events_read"],
    ];

    for (const [run, operationKind] of cases) {
      assert.throws(run, (error) => {
        assert.equal(error.status, 501);
        assert.equal(error.code, "model_mount_server_control_rust_core_required");
        assert.equal(error.details.operation_kind, operationKind);
        return true;
      });
    }

    assert.deepEqual(state.receipts, []);
    assert.equal(existsSync(join(state.stateDir, "server-logs", "server.jsonl")), false);
  } finally {
    rmSync(state.stateDir, { recursive: true, force: true });
  }
});
