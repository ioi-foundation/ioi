import assert from "node:assert/strict";
import test from "node:test";

import { buildWorkflowReceiptGatePanel } from "./workflow-receipt-gate-panel";

test("receipt gate panel reads canonical receipt and route details", () => {
  const panel = buildWorkflowReceiptGatePanel({
    gates: [
      {
        status: "passed",
        receipt_id: "receipt-canonical",
        receipt: {
          id: "receipt-source",
          details: {
            route_id: "route-canonical",
            selected_model: "model-canonical",
            endpoint_id: "endpoint-canonical",
            backend_id: "backend-canonical",
            tool_receipt_ids: ["tool-receipt-source"],
          },
        },
        gate_receipt: {
          id: "gate-receipt-canonical",
          details: {
            route_id: "route-gate-canonical",
            selected_model: "model-gate-canonical",
            endpoint_id: "endpoint-gate-canonical",
            selected_backend: "backend-gate-canonical",
            required_tool_receipt_ids: ["tool-receipt-gate"],
          },
          evidence_refs: ["evidence-gate-canonical"],
        },
      },
      {
        blocked: {
          details: {
            receipt_id: "receipt-blocked-canonical",
            gate_receipt_id: "gate-receipt-blocked-canonical",
            failures: ["route:route-failure-canonical", "receipt:missing"],
          },
        },
        blocked_receipt: {
          id: "blocked-receipt-canonical",
          details: {
            receipt_id: "receipt-blocked-details-canonical",
            selected_model: "model-blocked-canonical",
            endpoint_id: "endpoint-blocked-canonical",
            backend_id: "backend-blocked-canonical",
          },
          evidence_refs: ["evidence-blocked-canonical"],
        },
      },
    ],
  });

  assert.equal(panel.status, "ready");
  assert.equal(panel.passedCount, 1);
  assert.equal(panel.blockedCount, 1);
  assert.equal(panel.missingReceiptCount, 0);
  assert.equal(panel.rows[0]?.receiptId, "receipt-canonical");
  assert.equal(panel.rows[0]?.gateReceiptId, "gate-receipt-canonical");
  assert.equal(panel.rows[0]?.routeId, "route-gate-canonical");
  assert.equal(panel.rows[0]?.selectedModel, "model-gate-canonical");
  assert.equal(panel.rows[0]?.endpointId, "endpoint-gate-canonical");
  assert.equal(panel.rows[0]?.backendId, "backend-gate-canonical");
  assert.deepEqual(panel.rows[0]?.requiredToolReceiptIds, [
    "tool-receipt-gate",
    "tool-receipt-source",
  ]);
  assert.ok(panel.evidenceRefs.includes("evidence-gate-canonical"));
  assert.equal(panel.rows[1]?.receiptId, "receipt-blocked-canonical");
  assert.equal(panel.rows[1]?.gateReceiptId, "gate-receipt-blocked-canonical");
  assert.equal(panel.rows[1]?.routeId, "route-failure-canonical");
  assert.ok(panel.evidenceRefs.includes("evidence-blocked-canonical"));
});

test("receipt gate panel ignores retired receipt and route detail aliases", () => {
  const panel = buildWorkflowReceiptGatePanel({
    gates: [
      {
        status: "passed",
        receiptId: "receipt-retired",
        receipt: {
          details: {
            receiptId: "receipt-details-retired",
            routeId: "route-retired",
            selectedModel: "model-retired",
            endpointId: "endpoint-retired",
            backendId: "backend-retired",
            selectedBackend: "selected-backend-retired",
            toolReceiptIds: ["tool-receipt-retired"],
          },
        },
        gateReceipt: {
          id: "gate-receipt-retired-object",
          details: {
            routeId: "route-gate-retired",
            selectedModel: "model-gate-retired",
            endpointId: "endpoint-gate-retired",
            backendId: "backend-gate-retired",
            requiredToolReceiptIds: ["tool-receipt-gate-retired"],
          },
          evidenceRefs: ["evidence-gate-retired"],
        },
        blockedReceipt: {
          id: "blocked-receipt-retired-object",
          details: {
            receiptId: "receipt-blocked-retired",
          },
          evidenceRefs: ["evidence-blocked-retired"],
        },
      },
      {
        blocked: {
          details: {
            receiptId: "receipt-blocked-detail-retired",
            gateReceiptId: "gate-receipt-blocked-detail-retired",
            failures: ["route:route-canonical-failure"],
          },
        },
      },
    ],
  });

  assert.equal(panel.status, "needs_evidence");
  assert.equal(panel.rows[0]?.receiptId, null);
  assert.equal(panel.rows[0]?.gateReceiptId, null);
  assert.equal(panel.rows[0]?.routeId, null);
  assert.equal(panel.rows[0]?.selectedModel, null);
  assert.equal(panel.rows[0]?.endpointId, null);
  assert.equal(panel.rows[0]?.backendId, null);
  assert.deepEqual(panel.rows[0]?.requiredToolReceiptIds, []);
  assert.ok(!panel.evidenceRefs.includes("evidence-gate-retired"));
  assert.ok(!panel.evidenceRefs.includes("evidence-blocked-retired"));
  assert.equal(panel.rows[1]?.receiptId, null);
  assert.equal(panel.rows[1]?.gateReceiptId, null);
  assert.equal(panel.rows[1]?.routeId, "route-canonical-failure");
});
