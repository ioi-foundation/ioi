import { runtimeError } from "./runtime-http-utils.mjs";
import { objectRecord, optionalString } from "./runtime-value-helpers.mjs";

export const L1_SETTLEMENT_ADMISSION_RESPONSE_SCHEMA_VERSION =
  "ioi.runtime.l1_settlement_admission.v1";

export function createRuntimeL1SettlementSurface(deps = {}) {
  const {
    runtimeError: runtimeErrorDep = runtimeError,
  } = deps;

  function attemptForRequest(request = {}) {
    const body = objectRecord(request) ?? {};
    const nested =
      objectRecord(body.attempt ?? body.settlement_attempt ?? body.settlementAttempt) ?? {};
    const attempt = Object.keys(nested).length > 0 ? nested : body;
    if (Object.keys(attempt).length === 0) {
      throw runtimeErrorDep({
        status: 400,
        code: "l1_settlement_attempt_required",
        message: "L1 settlement admission requires a settlement attempt payload.",
      });
    }
    return attempt;
  }

  function admitL1SettlementAttempt(store, threadId, request = {}) {
    const agent = store.agentForThread(threadId);
    const attempt = attemptForRequest(request);
    const admission = store.l1SettlementRunner.admitAttempt(attempt);
    const record = objectRecord(admission.record) ?? {};
    return {
      schema_version: L1_SETTLEMENT_ADMISSION_RESPONSE_SCHEMA_VERSION,
      object: "ioi.runtime_l1_settlement_admission",
      status: "admitted",
      settlement_admitted: true,
      thread_id: threadId,
      agent_id: agent.id,
      settlement_ref:
        admission.settlement_ref ?? record.settlement_ref ?? optionalString(attempt.settlement_ref),
      domain_ref:
        admission.domain_ref ?? record.domain_ref ?? optionalString(attempt.domain_ref),
      state_root_ref:
        admission.state_root_ref ?? record.state_root_ref ?? optionalString(attempt.state_root_ref),
      trigger_refs: admission.trigger_refs ?? record.trigger_refs ?? [],
      receipt_refs: admission.receipt_refs ?? record.receipt_refs ?? [],
      admission_hash: admission.admission_hash ?? record.admission_hash ?? null,
      admission,
      record,
    };
  }

  return {
    admitL1SettlementAttempt,
    attemptForRequest,
  };
}
