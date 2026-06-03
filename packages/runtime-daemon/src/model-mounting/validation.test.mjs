import assert from "node:assert/strict";
import test from "node:test";

import {
  validateContinuationSafety,
  validateReceiptGate,
} from "./validation.mjs";

function runtimeError({ status, code, message, details }) {
  const error = new Error(message);
  error.status = status;
  error.code = code;
  error.details = details;
  return error;
}

function normalizeScopes(value, fallback = []) {
  return Array.isArray(value) ? value : fallback;
}

function requiredString(value, field) {
  if (typeof value !== "string" || value.length === 0) {
    throw runtimeError({
      status: 400,
      code: "bad_request",
      message: `${field} is required.`,
      details: { field },
    });
  }
  return value;
}

function captureError(fn) {
  try {
    fn();
  } catch (error) {
    return error;
  }
  throw new Error("Expected function to throw.");
}

test("model mounting validation preserves continuation safety modes", () => {
  const selection = {
    route: { id: "route.local-first" },
    endpoint: { id: "endpoint.local", modelId: "model.local" },
  };

  assert.deepEqual(validateContinuationSafety({
    previousState: null,
    selection,
    body: {},
    runtimeError,
    truthy: Boolean,
  }), { mode: "new", previousResponseId: null, fallbackAllowed: false, mismatchFields: [] });

  assert.deepEqual(validateContinuationSafety({
    previousState: {
      id: "resp-1",
      routeId: "route.local-first",
      endpointId: "endpoint.local",
      selectedModel: "model.local",
    },
    selection,
    body: {},
    runtimeError,
    truthy: Boolean,
  }), { mode: "matched", previousResponseId: "resp-1", fallbackAllowed: false, mismatchFields: [] });

  assert.deepEqual(validateContinuationSafety({
    previousState: {
      id: "resp-1",
      routeId: "route.other",
      endpointId: "endpoint.other",
      selectedModel: "model.other",
    },
    selection,
    body: { allow_continuation_fallback: true },
    runtimeError,
    truthy: Boolean,
  }), {
    mode: "fallback_allowed",
    previousResponseId: "resp-1",
    fallbackAllowed: true,
    mismatchFields: ["route_id", "endpoint_id", "model"],
  });
});

test("model mounting validation rejects unsafe continuation route changes", () => {
  const error = captureError(() => validateContinuationSafety({
    previousState: {
      id: "resp-1",
      routeId: "route.other",
      endpointId: "endpoint.local",
      selectedModel: "model.local",
    },
    selection: {
      route: { id: "route.local-first" },
      endpoint: { id: "endpoint.local", modelId: "model.local" },
    },
    body: {},
    runtimeError,
    truthy: Boolean,
  }));

  assert.equal(error.status, 409);
  assert.equal(error.code, "continuation_route_mismatch");
  assert.deepEqual(error.details.mismatch_fields, ["route_id"]);
});

test("model mounting validation accepts matching receipt gates", () => {
  const receipts = new Map([
    ["receipt-route", {
      id: "receipt-route",
      kind: "model_invocation",
      redaction: "redacted",
      details: {
        routeId: "route.local-first",
        selectedModel: "model.local",
        endpointId: "endpoint.local",
        backendId: "backend.local",
        toolReceiptIds: ["receipt-tool"],
      },
    }],
    ["receipt-tool", {
      id: "receipt-tool",
      kind: "mcp_tool_invocation",
      redaction: "redacted",
      details: {},
    }],
  ]);
  const createdReceipts = [];

  const result = validateReceiptGate({
    body: {
      receipt_id: "receipt-route",
      redaction: "redacted",
      route_id: "route.local-first",
      selected_model: "model.local",
      endpoint_id: "endpoint.local",
      backend_id: "backend.local",
      required_tool_receipt_ids: ["receipt-tool"],
    },
    getReceipt: (id) => receipts.get(id),
    normalizeScopes,
    receipt: (kind, payload) => {
      const receipt = { id: `created-${createdReceipts.length + 1}`, kind, ...payload };
      createdReceipts.push(receipt);
      return receipt;
    },
    requiredString,
    runtimeError,
  });

  assert.equal(result.status, "passed");
  assert.equal(result.gateReceipt.kind, "workflow_receipt_gate");
  assert.equal(createdReceipts[0].details.backendId, "backend.local");
});

test("model mounting validation blocks receipt gates with mismatches", () => {
  const receipts = new Map([
    ["receipt-route", {
      id: "receipt-route",
      kind: "model_invocation",
      redaction: "redacted",
      details: {
        routeId: "route.local-first",
        selectedModel: "model.local",
        endpointId: "endpoint.local",
        selectedBackend: "backend.local",
        toolReceiptIds: ["receipt-tool"],
      },
    }],
    ["receipt-tool", {
      id: "receipt-tool",
      kind: "model_invocation",
      redaction: "redacted",
      details: {},
    }],
  ]);
  const createdReceipts = [];

  const error = captureError(() => validateReceiptGate({
    body: {
      receipt_id: "receipt-route",
      route_id: "route.other",
      backend_id: "backend.other",
      required_tool_receipt_ids: ["receipt-tool", "receipt-missing-link"],
    },
    getReceipt: (id) => receipts.get(id) ?? {
      id,
      kind: "mcp_tool_invocation",
      redaction: "redacted",
      details: {},
    },
    normalizeScopes,
    receipt: (kind, payload) => {
      const receipt = { id: `created-${createdReceipts.length + 1}`, kind, ...payload };
      createdReceipts.push(receipt);
      return receipt;
    },
    requiredString,
    runtimeError,
  }));

  assert.equal(error.status, 412);
  assert.equal(error.code, "policy");
  assert.deepEqual(error.details.failures, [
    "route:route.local-first",
    "backend:backend.local",
    "tool_receipt_kind:receipt-tool",
    "tool_receipt_link:receipt-missing-link",
  ]);
  assert.equal(createdReceipts[0].kind, "workflow_receipt_gate_blocked");
});
