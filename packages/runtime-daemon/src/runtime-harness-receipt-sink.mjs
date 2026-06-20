import { normalizeArray, objectRecord, optionalString, uniqueStrings } from "./runtime-value-helpers.mjs";

export const HARNESS_RECEIPT_PROJECTION_SCHEMA_VERSION =
  "ioi.hypervisor.harness_receipt_projection.v1";

/**
 * Collect the admitted operations + receipts emitted across a session's
 * consequential steps (workspace write, command exec, port exposure, model
 * invocation) and project them for the Receipts/Replay surface. The sink holds
 * projection state only; the admitted truth lives in Agentgres.
 */
export function createHarnessReceiptSink(sessionRef) {
  const session = optionalString(sessionRef) ?? "session";
  const operations = [];

  function record(admittedOperation) {
    const op = objectRecord(admittedOperation);
    if (!op) return null;
    operations.push(op);
    return op;
  }

  function recordMany(admittedOperations) {
    return normalizeArray(admittedOperations).map(record).filter(Boolean);
  }

  function receiptRefs() {
    return uniqueStrings(
      operations
        .map((op) => optionalString(op.receipt_ref))
        .filter(Boolean),
    );
  }

  function operationRefs() {
    return uniqueStrings(
      operations
        .map((op) => optionalString(op.operation_ref))
        .filter(Boolean),
    );
  }

  function stateRoots() {
    return uniqueStrings(
      operations.map((op) => optionalString(op.state_root)).filter(Boolean),
    );
  }

  function projection() {
    return {
      schema_version: HARNESS_RECEIPT_PROJECTION_SCHEMA_VERSION,
      session_ref: session,
      operations: operations.map((op) => ({
        operation_ref: op.operation_ref ?? null,
        operation_kind: op.operation_kind ?? null,
        receipt_ref: op.receipt_ref ?? null,
        state_root: op.state_root ?? null,
        payload_hash: op.payload_hash ?? null,
        gated: Boolean(op.capability_verdict?.gated),
        required_scope: op.capability_verdict?.required_scope ?? null,
        admitted_at: op.admitted_at ?? null,
      })),
      latest_receipt_refs: receiptRefs(),
      agentgres_operation_refs: operationRefs(),
      state_roots: stateRoots(),
      runtimeTruthSource: "daemon-runtime",
    };
  }

  return { record, recordMany, receiptRefs, operationRefs, stateRoots, projection };
}
