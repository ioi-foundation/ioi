import assert from "node:assert/strict";
import test from "node:test";

import {
  createAgentgresAdmissionClient,
  requireCapabilityLease,
  assertCapabilityLease,
  OPERATION_REQUIRED_SCOPE,
} from "./runtime-agentgres-admission-client.mjs";
import { createHarnessReceiptSink } from "./runtime-harness-receipt-sink.mjs";

test("authorizes an operation whose required scope is leased", () => {
  const verdict = requireCapabilityLease({
    operationKind: "workspace_write",
    authorityScopeRefs: ["scope:workspace.read", "scope:workspace.patch"],
  });
  assert.equal(verdict.authorized, true);
  assert.equal(verdict.required_scope, OPERATION_REQUIRED_SCOPE.workspace_write);
  assert.equal(verdict.gated, true);
});

test("blocks (step-up) an operation whose scope is not leased", () => {
  const verdict = requireCapabilityLease({
    operationKind: "port_expose",
    authorityScopeRefs: ["scope:workspace.patch"],
  });
  assert.equal(verdict.authorized, false);
  assert.equal(verdict.step_up_required, true);
  assert.equal(verdict.missing_scope, "scope:network.expose");
});

test("assertCapabilityLease throws a 403 step-up when the lease is missing", () => {
  assert.throws(
    () =>
      assertCapabilityLease({
        operationKind: "model_invoke",
        authorityScopeRefs: [],
      }),
    (error) => {
      assert.equal(error.status, 403);
      assert.equal(error.code, "harness_operation_capability_lease_required");
      return true;
    },
  );
});

test("admits a consequential operation into an Agentgres-shaped record", async () => {
  const client = createAgentgresAdmissionClient({
    nowIso: () => "2026-06-19T00:00:00.000Z",
  });
  const admitted = await client.admitOperation({
    operation_kind: "workspace_write",
    session_ref: "session-route:demo",
    authority_scope_refs: ["scope:workspace.patch"],
    payload: { workspace_root: "/tmp/ws", file: "index.html" },
  });
  assert.equal(admitted.decision, "admitted");
  assert.match(admitted.operation_ref, /^agentgres:\/\/operation\//);
  assert.match(admitted.receipt_ref, /^receipt:\/\/agentgres\//);
  assert.match(admitted.state_root, /^agentgres:\/\/state-root\//);
  assert.equal(admitted.capability_verdict.authorized, true);
  assert.match(admitted.payload_hash, /^[a-f0-9]{64}$/);
});

test("admitOperation refuses an unleased operation (no silent admit)", async () => {
  const client = createAgentgresAdmissionClient();
  await assert.rejects(
    () =>
      client.admitOperation({
        operation_kind: "port_expose",
        authority_scope_refs: ["scope:workspace.patch"],
        payload: { port: 4173 },
      }),
    (error) => {
      assert.equal(error.code, "harness_operation_capability_lease_required");
      return true;
    },
  );
});

test("receipt sink projects admitted operations for the Receipts surface", async () => {
  const client = createAgentgresAdmissionClient({
    nowIso: () => "2026-06-19T00:00:00.000Z",
  });
  const sink = createHarnessReceiptSink("session-route:demo");
  for (const file of ["index.html", "styles.css"]) {
    sink.record(
      await client.admitOperation({
        operation_kind: "workspace_write",
        session_ref: "session-route:demo",
        authority_scope_refs: ["scope:workspace.patch"],
        payload: { file },
      }),
    );
  }
  const projection = sink.projection();
  assert.equal(projection.operations.length, 2);
  assert.equal(projection.latest_receipt_refs.length, 2);
  assert.equal(projection.agentgres_operation_refs.length, 2);
  assert.equal(projection.operations[0].gated, true);
  assert.equal(projection.operations[0].required_scope, "scope:workspace.patch");
});
