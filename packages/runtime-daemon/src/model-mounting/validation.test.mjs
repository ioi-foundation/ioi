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
  }), { mode: "new", previous_response_id: null, fallback_allowed: false, mismatch_fields: [] });

  assert.deepEqual(validateContinuationSafety({
    previousState: {
      id: "resp-1",
      route_id: "route.local-first",
      endpoint_id: "endpoint.local",
      selected_model: "model.local",
    },
    selection,
    body: {},
    runtimeError,
    truthy: Boolean,
  }), { mode: "matched", previous_response_id: "resp-1", fallback_allowed: false, mismatch_fields: [] });

  assert.deepEqual(validateContinuationSafety({
    previousState: {
      id: "resp-1",
      route_id: "route.other",
      endpoint_id: "endpoint.other",
      selected_model: "model.other",
    },
    selection,
    body: { allow_continuation_fallback: true },
    runtimeError,
    truthy: Boolean,
  }), {
    mode: "fallback_allowed",
    previous_response_id: "resp-1",
    fallback_allowed: true,
    mismatch_fields: ["route_id", "endpoint_id", "model"],
  });
});

test("model mounting validation rejects unsafe continuation route changes", () => {
  const error = captureError(() => validateContinuationSafety({
    previousState: {
      id: "resp-1",
      route_id: "route.other",
      endpoint_id: "endpoint.local",
      selected_model: "model.local",
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

test("model mounting validation fails closed on retired continuation fallback aliases", () => {
  const selection = {
    route: { id: "route.local-first" },
    endpoint: { id: "endpoint.local", modelId: "model.local" },
  };
  const previousState = {
    id: "resp-1",
    route_id: "route.other",
    endpoint_id: "endpoint.other",
    selected_model: "model.other",
  };
  const retiredAliases = ["allowContinuationFallback", "allow_route_fallback", "allowRouteFallback"];

  for (const retiredAlias of retiredAliases) {
    const error = captureError(() => validateContinuationSafety({
      previousState,
      selection,
      body: { [retiredAlias]: true },
      runtimeError,
      truthy: Boolean,
    }));

    assert.equal(error.status, 409);
    assert.equal(error.code, "continuation_route_mismatch");
    assert.deepEqual(error.details, {
      previous_response_id: "resp-1",
      mismatch_fields: ["route_id", "endpoint_id", "model"],
      required: "allow_continuation_fallback",
    });
  }
});

test("model mounting validation accepts matching receipt gates", () => {
  const receipts = new Map([
    ["receipt-route", {
      id: "receipt-route",
      kind: "model_invocation",
      redaction: "redacted",
      details: {
        route_id: "route.local-first",
        selected_model: "model.local",
        endpoint_id: "endpoint.local",
        backend_id: "backend.local",
        tool_receipt_ids: ["receipt-tool"],
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
  assert.equal(createdReceipts[0].details.receipt_id, "receipt-route");
  assert.equal(createdReceipts[0].details.route_id, "route.local-first");
  assert.equal(createdReceipts[0].details.selected_model, "model.local");
  assert.equal(createdReceipts[0].details.endpoint_id, "endpoint.local");
  assert.equal(createdReceipts[0].details.backend_id, "backend.local");
  assert.deepEqual(createdReceipts[0].details.required_tool_receipt_ids, ["receipt-tool"]);
  assert.equal(Object.hasOwn(createdReceipts[0].details, "receiptId"), false);
  assert.equal(Object.hasOwn(createdReceipts[0].details, "routeId"), false);
  assert.equal(Object.hasOwn(createdReceipts[0].details, "selectedModel"), false);
  assert.equal(Object.hasOwn(createdReceipts[0].details, "endpointId"), false);
  assert.equal(Object.hasOwn(createdReceipts[0].details, "backendId"), false);
  assert.equal(Object.hasOwn(createdReceipts[0].details, "requiredToolReceiptIds"), false);
});

test("model mounting validation blocks receipt gates with mismatches", () => {
  const receipts = new Map([
    ["receipt-route", {
      id: "receipt-route",
      kind: "model_invocation",
      redaction: "redacted",
      details: {
        route_id: "route.local-first",
        selected_model: "model.local",
        endpoint_id: "endpoint.local",
        selected_backend: "backend.local",
        tool_receipt_ids: ["receipt-tool"],
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
  assert.equal(error.details.receipt_id, "receipt-route");
  assert.equal(error.details.gate_receipt_id, "created-1");
  assert.equal(Object.hasOwn(error.details, "receiptId"), false);
  assert.equal(Object.hasOwn(error.details, "gateReceiptId"), false);
  assert.deepEqual(error.details.failures, [
    "route:route.local-first",
    "backend:backend.local",
    "tool_receipt_kind:receipt-tool",
    "tool_receipt_link:receipt-missing-link",
  ]);
  assert.equal(createdReceipts[0].kind, "workflow_receipt_gate_blocked");
  assert.equal(createdReceipts[0].details.receipt_id, "receipt-route");
  assert.equal(createdReceipts[0].details.route_id, "route.local-first");
  assert.equal(createdReceipts[0].details.backend_id, "backend.local");
  assert.deepEqual(createdReceipts[0].details.required_tool_receipt_ids, ["receipt-tool", "receipt-missing-link"]);
  assert.equal(Object.hasOwn(createdReceipts[0].details, "receiptId"), false);
  assert.equal(Object.hasOwn(createdReceipts[0].details, "routeId"), false);
  assert.equal(Object.hasOwn(createdReceipts[0].details, "backendId"), false);
  assert.equal(Object.hasOwn(createdReceipts[0].details, "requiredToolReceiptIds"), false);
});
