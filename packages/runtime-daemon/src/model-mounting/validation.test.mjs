import assert from "node:assert/strict";
import test from "node:test";

import {
  MODEL_RECEIPT_GATE_RUST_CORE_REQUIRED_EVIDENCE_REFS,
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

test("model mounting validation matching receipt gate fails closed before JS receipt creation", () => {
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
  const calls = [];

  const error = captureError(() => validateReceiptGate({
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
      calls.push({ kind, payload });
      throw new Error("JS workflow_receipt_gate receipt should not be created");
    },
    requiredString,
    runtimeError,
  }));

  assert.equal(error.status, 409);
  assert.equal(error.code, "model_mount_receipt_gate_rust_core_required");
  assert.equal(error.details.boundary, "model_mount.receipt_gate");
  assert.equal(error.details.operation_kind, "workflow_receipt_gate");
  assert.deepEqual(error.details.evidence_refs, MODEL_RECEIPT_GATE_RUST_CORE_REQUIRED_EVIDENCE_REFS);
  assert.equal(error.details.receipt_id, "receipt-route");
  assert.equal(error.details.gate_status, "passed");
  assert.deepEqual(error.details.failures, []);
  assert.equal(error.details.route_id, "route.local-first");
  assert.equal(error.details.selected_model, "model.local");
  assert.equal(error.details.endpoint_id, "endpoint.local");
  assert.equal(error.details.backend_id, "backend.local");
  assert.deepEqual(error.details.required_tool_receipt_ids, ["receipt-tool"]);
  assert.equal(Object.hasOwn(error.details, "receiptId"), false);
  assert.equal(Object.hasOwn(error.details, "routeId"), false);
  assert.equal(Object.hasOwn(error.details, "selectedModel"), false);
  assert.equal(Object.hasOwn(error.details, "endpointId"), false);
  assert.equal(Object.hasOwn(error.details, "backendId"), false);
  assert.equal(Object.hasOwn(error.details, "requiredToolReceiptIds"), false);
  assert.deepEqual(calls, []);
});

test("model mounting validation mismatch gate fails closed before JS blocked receipt creation", () => {
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
  const calls = [];

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
      calls.push({ kind, payload });
      throw new Error("JS workflow_receipt_gate_blocked receipt should not be created");
    },
    requiredString,
    runtimeError,
  }));

  assert.equal(error.status, 409);
  assert.equal(error.code, "model_mount_receipt_gate_rust_core_required");
  assert.equal(error.details.boundary, "model_mount.receipt_gate");
  assert.equal(error.details.operation_kind, "workflow_receipt_gate");
  assert.equal(error.details.receipt_id, "receipt-route");
  assert.equal(error.details.gate_status, "blocked");
  assert.equal(error.details.route_id, "route.local-first");
  assert.equal(error.details.backend_id, "backend.local");
  assert.deepEqual(error.details.required_tool_receipt_ids, ["receipt-tool", "receipt-missing-link"]);
  assert.equal(Object.hasOwn(error.details, "receiptId"), false);
  assert.equal(Object.hasOwn(error.details, "gateReceiptId"), false);
  assert.equal(Object.hasOwn(error.details, "routeId"), false);
  assert.equal(Object.hasOwn(error.details, "backendId"), false);
  assert.equal(Object.hasOwn(error.details, "requiredToolReceiptIds"), false);
  assert.deepEqual(error.details.failures, [
    "route:route.local-first",
    "backend:backend.local",
    "tool_receipt_kind:receipt-tool",
    "tool_receipt_link:receipt-missing-link",
  ]);
  assert.deepEqual(calls, []);
});
