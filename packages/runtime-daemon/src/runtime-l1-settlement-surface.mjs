import { runtimeError } from "./runtime-http-utils.mjs";
import { objectRecord } from "./runtime-value-helpers.mjs";

const RETIRED_L1_SETTLEMENT_REQUEST_ALIASES = [
  "settlementAttempt",
  "settlement_attempt",
];

const CANONICAL_L1_SETTLEMENT_REQUEST_FIELDS = [
  "attempt",
];

export function createRuntimeL1SettlementSurface(deps = {}) {
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
