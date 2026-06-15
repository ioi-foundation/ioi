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

function receiptGatePlan(request, status = "passed", failures = []) {
  const kind = status === "passed" ? "workflow_receipt_gate" : "workflow_receipt_gate_blocked";
  return {
    source: "rust_daemon_core.model_mount.receipt_gate",
    backend: "rust_model_mount_receipt_gate",
    operation_kind: request.operation_kind,
    rust_core_boundary: "model_mount.receipt_gate",
    gate_status: status,
    gate_hash: `sha256:gate:${status}`,
    receipt_refs: [request.receipt_id, ...request.required_tool_receipt_ids],
    evidence_refs: [
      "model_mount_receipt_gate_rust_owned",
      "model_mount_receipt_gate_js_facade_retired",
      "rust_receipt_binder_core",
      "agentgres_model_receipt_gate_truth_required",
    ],
    public_response: {
      object: "ioi.model_mount_receipt_gate_result",
      status,
      receipt_id: request.receipt_id,
      gate_receipt_id: `receipt.${kind}.test`,
      failures,
    },
    plan: {
      failures,
    },
    receipt: {
      id: `receipt.${kind}.test`,
      kind,
      redaction: "redacted",
      evidenceRefs: [
        "model_mount_receipt_gate_rust_owned",
        "model_mount_receipt_gate_js_facade_retired",
        "rust_receipt_binder_core",
        "agentgres_model_receipt_gate_truth_required",
      ],
      details: {
        boundary: "model_mount.receipt_gate",
        operation_kind: request.operation_kind,
        receipt_id: request.receipt_id,
        gate_status: status,
        failures,
        route_id: request.receipt.details?.route_id ?? null,
        selected_model: request.receipt.details?.selected_model ?? null,
        endpoint_id: request.receipt.details?.endpoint_id ?? null,
        backend_id: request.receipt.details?.backend_id ?? null,
        required_tool_receipt_ids: request.required_tool_receipt_ids,
        model_mount_receipt_gate_hash: `sha256:gate:${status}`,
        model_mount_receipt_binding_ref: "sha256:receipt-binding",
        model_mount_agentgres_operation_ref: "agentgres://model-mounting/receipt-gates/test",
      },
    },
  };
}

test("model mounting validation commits Rust-planned matching receipt gate", () => {
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
  const plans = [];
  const persisted = [];

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
    persistRustAuthoredReceipt: (record) => {
      persisted.push(record);
      return { ...record, committed: true };
    },
    planReceiptGate: (request) => {
      plans.push(request);
      return receiptGatePlan(request);
    },
    requiredString,
    runtimeError,
    nowIso: () => "2026-06-13T12:00:00.000Z",
  });

  assert.equal(result.status, "passed");
  assert.equal(result.gate_status, "passed");
  assert.equal(result.receipt.kind, "workflow_receipt_gate");
  assert.equal(result.receipt.committed, true);
  assert.equal(result.gate_hash, "sha256:gate:passed");
  assert.equal(plans.length, 1);
  assert.equal(plans[0].schema_version, "ioi.model_mount.receipt_gate.v1");
  assert.equal(plans[0].operation_kind, "workflow_receipt_gate");
  assert.equal(plans[0].receipt_id, "receipt-route");
  assert.equal(plans[0].required_redaction, "redacted");
  assert.equal(plans[0].required_route_id, "route.local-first");
  assert.equal(plans[0].required_selected_model, "model.local");
  assert.equal(plans[0].required_endpoint_id, "endpoint.local");
  assert.equal(plans[0].required_backend_id, "backend.local");
  assert.deepEqual(plans[0].required_tool_receipt_ids, ["receipt-tool"]);
  assert.equal(plans[0].tool_receipts[0].id, "receipt-tool");
  assert.equal(plans[0].generated_at, "2026-06-13T12:00:00.000Z");
  assert.equal(persisted.length, 1);
  assert.equal(persisted[0].details.model_mount_receipt_binding_ref, "sha256:receipt-binding");
});

test("model mounting validation commits Rust-planned blocked receipt gate", () => {
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
  const plans = [];
  const persisted = [];

  const result = validateReceiptGate({
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
    persistRustAuthoredReceipt: (record) => {
      persisted.push(record);
      return record;
    },
    planReceiptGate: (request) => {
      plans.push(request);
      return receiptGatePlan(request, "blocked", [
        "route:route.local-first",
        "backend:backend.local",
        "tool_receipt_kind:receipt-tool",
        "tool_receipt_link:receipt-missing-link",
      ]);
    },
    requiredString,
    runtimeError,
  });

  assert.equal(result.status, "blocked");
  assert.equal(result.receipt.kind, "workflow_receipt_gate_blocked");
  assert.deepEqual(result.failures, [
    "route:route.local-first",
    "backend:backend.local",
    "tool_receipt_kind:receipt-tool",
    "tool_receipt_link:receipt-missing-link",
  ]);
  assert.equal(plans.length, 1);
  assert.deepEqual(plans[0].required_tool_receipt_ids, ["receipt-tool", "receipt-missing-link"]);
  assert.equal(plans[0].tool_receipts.length, 2);
  assert.equal(persisted.length, 1);
  assert.equal(persisted[0].details.model_mount_agentgres_operation_ref, "agentgres://model-mounting/receipt-gates/test");
});

test("model mounting validation fails closed before JS gate decision when Rust planner is missing", () => {
  const receipts = new Map([
    ["receipt-route", {
      id: "receipt-route",
      kind: "model_invocation",
      redaction: "redacted",
      details: {
        route_id: "route.local-first",
        tool_receipt_ids: [],
      },
    }],
  ]);

  const error = captureError(() => validateReceiptGate({
    body: {
      receipt_id: "receipt-route",
      route_id: "route.other",
    },
    getReceipt: (id) => receipts.get(id),
    normalizeScopes,
    persistRustAuthoredReceipt: () => {
      throw new Error("receipt persistence should not run without Rust gate planning");
    },
    requiredString,
    runtimeError,
  }));

  assert.equal(error.status, 409);
  assert.equal(error.code, "model_mount_receipt_gate_rust_core_required");
  assert.equal(error.details.rust_core_boundary, "model_mount.receipt_gate");
  assert.equal(error.details.operation_kind, "workflow_receipt_gate");
  assert.deepEqual(error.details.evidence_refs, MODEL_RECEIPT_GATE_RUST_CORE_REQUIRED_EVIDENCE_REFS);
  assert.equal(error.details.receipt_id, "receipt-route");
  assert.equal(Object.hasOwn(error.details, "failures"), false);
  assert.equal(Object.hasOwn(error.details, "gateStatus"), false);
});
