#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { startRuntimeDaemonService } from "../../packages/runtime-daemon/src/index.mjs";

const outputPath = process.argv[2];
if (!outputPath) {
  throw new Error("usage: workflow-receipt-gate-panel-proof.mjs <output-path>");
}

const { buildWorkflowReceiptGatePanel } = await import(
  "../../packages/hypervisor-workbench/src/runtime/workflow-receipt-gate-panel.ts"
);

async function requestJson(baseUrl, route, { method = "GET", token, body } = {}) {
  const response = await fetch(`${baseUrl}${route}`, {
    method,
    headers: {
      accept: "application/json",
      ...(body === undefined ? {} : { "content-type": "application/json" }),
      ...(token ? { authorization: `Bearer ${token}` } : {}),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const json = await response.json().catch(() => ({}));
  return { response, json };
}

async function expectOk(baseUrl, route, options = {}) {
  const result = await requestJson(baseUrl, route, options);
  assert.ok(
    result.response.ok,
    `${result.response.status} ${result.response.statusText} for ${route}: ${JSON.stringify(result.json)}`,
  );
  return result.json;
}

const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-stage23-workspace-"));
const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-stage23-state-"));
const daemon = await startRuntimeDaemonService({ cwd, stateDir });

try {
  const grant = await expectOk(daemon.endpoint, "/v1/model-mount/tokens", {
    method: "POST",
    body: {
      audience: "hypervisor-local-server",
      allowed: ["model.chat:*", "route.use:*"],
    },
  });

  const workflowCall = await expectOk(daemon.endpoint, "/v1/model-mount/workflows/nodes/execute", {
    method: "POST",
    token: grant.token,
    body: {
      node: "Model Call",
      input: "Receipt gate proof: local model call should produce a downstream prerequisite receipt.",
      model_policy: { privacy: "local_only" },
      workflow_graph_id: "workflow.react-flow.receipt-gate",
      workflow_node_id: "node.model-call.source",
    },
  });
  assert.equal(workflowCall.status, "executed");
  assert.equal(workflowCall.receipt.kind, "model_invocation");
  assert.equal(workflowCall.receipt.details.routeId, "route.local-first");

  const passedGate = await expectOk(daemon.endpoint, "/v1/model-mount/workflows/receipt-gate", {
    method: "POST",
    body: {
      receipt_id: workflowCall.receipt.id,
      redaction: workflowCall.receipt.redaction,
      route_id: workflowCall.receipt.details.routeId,
      selected_model: workflowCall.receipt.details.selectedModel,
      selected_endpoint: workflowCall.receipt.details.endpointId,
      selected_backend: workflowCall.receipt.details.backendId ?? workflowCall.receipt.details.selectedBackend,
    },
  });
  assert.equal(passedGate.status, "passed");
  assert.equal(passedGate.gateReceipt.kind, "workflow_receipt_gate");

  const blockedGate = await requestJson(daemon.endpoint, "/v1/model-mount/workflows/receipt-gate", {
    method: "POST",
    body: {
      receipt_id: workflowCall.receipt.id,
      route_id: "route.mismatch",
    },
  });
  assert.equal(blockedGate.response.status, 412);
  assert.equal(blockedGate.json.error.code, "policy");
  assert.deepEqual(blockedGate.json.error.details.failures, ["route:route.local-first"]);

  const blockedReceipt = await expectOk(
    daemon.endpoint,
    `/v1/model-mount/receipts/${blockedGate.json.error.details.gateReceiptId}`,
  );
  assert.equal(blockedReceipt.kind, "workflow_receipt_gate_blocked");

  const panel = buildWorkflowReceiptGatePanel({
    gates: [
      {
        status: "passed",
        receipt: workflowCall.receipt,
        gateReceipt: passedGate.gateReceipt,
      },
      {
        status: "blocked",
        receipt: workflowCall.receipt,
        blocked: blockedGate.json.error,
        blockedReceipt,
      },
    ],
  });

  assert.equal(panel.status, "ready");
  assert.equal(panel.passedCount, 1);
  assert.equal(panel.blockedCount, 1);
  assert.equal(panel.missingReceiptCount, 0);
  assert.ok(panel.rows.some((row) => row.status === "passed" && row.routeId === "route.local-first"));
  assert.ok(panel.rows.some((row) => row.status === "blocked" && row.failures.includes("route:route.local-first")));
  assert.ok(panel.rows.every((row) => row.receiptId && row.gateReceiptId));

  const receipts = await expectOk(daemon.endpoint, "/v1/model-mount/receipts");
  assert.ok(receipts.some((receipt) => receipt.id === passedGate.gateReceipt.id));
  assert.ok(receipts.some((receipt) => receipt.id === blockedReceipt.id));

  const proof = {
    schemaVersion: "ioi.autopilot.stage23.receipt-gate-panel-proof.v1",
    passed: true,
    cwd,
    stateDir,
    endpoint: daemon.endpoint,
    sourceReceiptId: workflowCall.receipt.id,
    passedGateReceiptId: passedGate.gateReceipt.id,
    blockedGateReceiptId: blockedReceipt.id,
    checks: {
      sourceModelInvocationReceiptExists: workflowCall.receipt.kind === "model_invocation",
      matchingGatePassed: passedGate.status === "passed",
      mismatchedGateBlocked: blockedGate.response.status === 412,
      blockedGateReceiptPersisted: blockedReceipt.kind === "workflow_receipt_gate_blocked",
      panelReady: panel.status === "ready",
      downstreamPrerequisiteRowsReceipted: panel.rows.every((row) => row.receiptId && row.gateReceiptId),
    },
    panel,
  };

  fs.mkdirSync(path.dirname(outputPath), { recursive: true });
  fs.writeFileSync(outputPath, `${JSON.stringify(proof, null, 2)}\n`);
} finally {
  await daemon.close();
}
