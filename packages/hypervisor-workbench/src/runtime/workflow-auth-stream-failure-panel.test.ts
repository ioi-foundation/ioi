import assert from "node:assert/strict";
import test from "node:test";

import { buildWorkflowAuthStreamFailurePanel } from "./workflow-auth-stream-failure-panel";

test("auth stream failure panel reads canonical stream receipt details", () => {
  const panel = buildWorkflowAuthStreamFailurePanel({
    authFailures: [
      {
        surface: "provider.openai",
        status: 401,
        code: "auth_missing",
        message: "API key missing",
      },
    ],
    receipts: [
      {
        id: "receipt-stream-canceled",
        kind: "model_invocation_stream_canceled",
        summary: "client disconnected",
        details: {
          reason: "client_disconnect",
          invocation_receipt_id: "receipt-invocation",
          stream_kind: "sse",
          route_id: "route-canonical",
          selected_model: "model-canonical",
          frames_written: 7,
        },
      },
      {
        id: "receipt-stream-completed",
        kind: "model_invocation_stream_completed",
        details: {
          invocation_receipt_id: "receipt-invocation-completed",
          stream_kind: "chunked_json",
          route_id: "route-completed",
          selected_model: "model-completed",
          chunks_forwarded: "11",
        },
      },
    ],
  });

  assert.equal(panel.status, "ready");
  assert.equal(panel.authFailureCount, 1);
  assert.equal(panel.streamCanceledCount, 1);
  assert.equal(panel.streamCompletedCount, 1);
  assert.deepEqual(panel.receiptIds, ["receipt-stream-canceled", "receipt-stream-completed"]);
  assert.deepEqual(panel.invocationReceiptIds, [
    "receipt-invocation",
    "receipt-invocation-completed",
  ]);
  assert.equal(panel.rows[1]?.routeId, "route-canonical");
  assert.equal(panel.rows[1]?.selectedModel, "model-canonical");
  assert.equal(panel.rows[1]?.streamKind, "sse");
  assert.equal(panel.rows[1]?.framesWritten, 7);
  assert.equal(panel.rows[2]?.routeId, "route-completed");
  assert.equal(panel.rows[2]?.selectedModel, "model-completed");
  assert.equal(panel.rows[2]?.streamKind, "chunked_json");
  assert.equal(panel.rows[2]?.framesWritten, 11);
});

test("auth stream failure panel ignores retired stream receipt detail aliases", () => {
  const panel = buildWorkflowAuthStreamFailurePanel({
    receipts: [
      {
        id: "receipt-stream-retired",
        kind: "model_invocation_stream_canceled",
        details: {
          invocationReceiptId: "receipt-invocation-retired",
          streamKind: "sse-retired",
          routeId: "route-retired",
          selectedModel: "model-retired",
          framesWritten: 13,
          chunksForwarded: 17,
        },
      },
    ],
  });

  assert.equal(panel.status, "blocked");
  assert.deepEqual(panel.invocationReceiptIds, []);
  assert.equal(panel.rows[0]?.invocationReceiptId, null);
  assert.equal(panel.rows[0]?.streamKind, null);
  assert.equal(panel.rows[0]?.routeId, null);
  assert.equal(panel.rows[0]?.selectedModel, null);
  assert.equal(panel.rows[0]?.framesWritten, null);
});
