import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  serverEvents,
  serverLogRecords,
  serverLogs,
  serverRestart,
  serverStart,
  serverStatus,
  serverStop,
  writeServerLog,
} from "./server-control.mjs";

const SCHEMA = "schema.server-control.test";

function fakeState({ stateDir = mkdtempSync(join(tmpdir(), "ioi-server-control-")) } = {}) {
  const receipts = [];
  const state = {
    stateDir,
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
    nowIso() {
      return this.now;
    },
    receipts,
  };
  return state;
}

test("server control projects gateway status from mounted state", () => {
  const state = fakeState();
  try {
    const status = serverStatus(state, "http://127.0.0.1:3200", { schemaVersion: SCHEMA });

    assert.equal(status.schemaVersion, SCHEMA);
    assert.equal(status.status, "running");
    assert.equal(status.controlStatus, "running");
    assert.equal(status.nativeBaseUrl, "http://127.0.0.1:3200/api/v1");
    assert.equal(status.openAiCompatibleBaseUrl, "http://127.0.0.1:3200/v1");
    assert.equal(status.loadedInstances, 1);
    assert.equal(status.mountedEndpoints, 1);
    assert.deepEqual(status.providerStates, { available: 1, degraded: 1 });
    assert.deepEqual(status.backendStates, { available: 1, degraded: 1 });
    assert.equal(state.evicted, 1);
    assert.equal(state.coalesced, 1);
  } finally {
    rmSync(state.stateDir, { recursive: true, force: true });
  }
});

test("server control records lifecycle operations, state, and log ids", () => {
  const state = fakeState();
  try {
    const stopped = serverStop(state, null, { schemaVersion: SCHEMA });
    assert.equal(stopped.controlStatus, "stopped");
    assert.equal(stopped.lastServerOperation, "server_stop");
    assert.equal(stopped.receiptId, "receipt.server_stop.1");
    assert.match(stopped.logId, /^server_log_/);

    const restarted = serverRestart(state, "http://daemon.test", { schemaVersion: SCHEMA });
    assert.equal(restarted.controlStatus, "running");
    assert.equal(restarted.lastServerOperation, "server_restart");
    assert.equal(state.receipts.at(-1).details.previousControlStatus, "stopped");
    assert.equal(state.receipts.at(-1).details.previousReceiptId, "receipt.server_stop.1");

    const started = serverStart(state, null, { schemaVersion: SCHEMA });
    assert.equal(started.lastServerOperation, "server_start");
    assert.equal(serverLogRecords(state, { limit: 10 }).length, 3);
  } finally {
    rmSync(state.stateDir, { recursive: true, force: true });
  }
});

test("server control logs and events are redacted and limit bounded", () => {
  const state = fakeState();
  try {
    for (let index = 0; index < 4; index += 1) {
      state.now = `2026-06-03T20:45:0${index}.000Z`;
      writeServerLog(state, {
        event: "provider_probe",
        status: "ok",
        authorization: "Bearer secret-token",
        nested: { apiKey: "secret-key" },
      });
    }

    const records = serverLogRecords(state, { limit: 2 });
    assert.equal(records.length, 2);
    assert.equal(records[0].authorization, "[REDACTED]");
    assert.equal(records[0].nested.apiKey, "[REDACTED]");

    const logs = serverLogs(state, { limit: "500" }, { schemaVersion: SCHEMA });
    assert.equal(logs.kind, "server_logs");
    assert.equal(logs.redaction, "redacted");
    assert.equal(logs.records.length, 5);
    assert.equal(state.receipts.at(-1).details.limit, 200);

    const events = serverEvents(state, { limit: 1 }, { schemaVersion: SCHEMA });
    assert.equal(events.kind, "server_events");
    assert.equal(events.events.length, 1);
    assert.equal(events.events[0].event, "server_events_read");
  } finally {
    rmSync(state.stateDir, { recursive: true, force: true });
  }
});
