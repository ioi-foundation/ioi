import { runtimeError } from "./runtime-http-utils.mjs";
import { objectRecord } from "./runtime-value-helpers.mjs";

const RETIRED_L1_SETTLEMENT_REQUEST_ALIASES = [
  "settlementAttempt",
  "settlement_attempt",
];

const CANONICAL_L1_SETTLEMENT_REQUEST_FIELDS = [
  "attempt",
];

const RETIRED_L1_SETTLEMENT_TRUTH_FIELDS = [
  "stateRootRef",
  "state_root_ref",
];

export function createRuntimeL1SettlementApi(deps = {}) {
  const {
    runtimeError: runtimeErrorDep = runtimeError,
  } = deps;

  function attemptForRequest(request = {}) {
    const body = objectRecord(request) ?? {};
    assertCanonicalL1SettlementRequestBody(body);
    const nested = objectRecord(body.attempt) ?? {};
    const attempt = Object.keys(nested).length > 0 ? nested : body;
    if (Object.keys(attempt).length === 0) {
      throw runtimeErrorDep({
        status: 400,
        code: "l1_settlement_attempt_required",
        message: "L1 settlement admission requires a settlement attempt payload.",
      });
    }
    assertNoClientSuppliedL1SettlementTruth(attempt);
    return attempt;
  }

  function assertCanonicalL1SettlementRequestBody(body = {}) {
    const retiredAliases = RETIRED_L1_SETTLEMENT_REQUEST_ALIASES.filter((field) =>
      Object.hasOwn(body, field),
    );
    if (retiredAliases.length === 0) return;
    throw runtimeErrorDep({
      status: 400,
      code: "l1_settlement_attempt_request_aliases_retired",
      message: "L1 settlement attempt request aliases are retired; use attempt.",
      details: {
        retired_aliases: retiredAliases,
        canonical_fields: CANONICAL_L1_SETTLEMENT_REQUEST_FIELDS,
      },
    });
  }

  function assertNoClientSuppliedL1SettlementTruth(attempt = {}) {
    const retiredTruthFields = RETIRED_L1_SETTLEMENT_TRUTH_FIELDS.filter((field) =>
      Object.hasOwn(attempt, field),
    );
    if (retiredTruthFields.length === 0) return;
    throw runtimeErrorDep({
      status: 400,
      code: "l1_settlement_state_root_truth_fields_retired",
      message:
        "L1 settlement state-root truth is derived by the Rust core and cannot be supplied by clients.",
      details: {
        retired_fields: retiredTruthFields,
        derived_by: "rust_l1_settlement_guard",
      },
    });
  }

  function admitL1SettlementAttempt(store, threadId, request = {}) {
    const attempt = attemptForRequest(request);
    const agent = store.agentForThread(threadId);
    return store.l1SettlementCore.admitAttempt(attempt, {
      thread_id: threadId,
      agent_id: agent.id,
    });
  }

  return {
    admitL1SettlementAttempt,
    attemptForRequest,
  };
}
