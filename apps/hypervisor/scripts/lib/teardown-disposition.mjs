// The provider TEARDOWN OUTCOME CONTRACT, shared by every provider done-bar.
//
// Before the emergency containment cut (PR #129) all eight provider adapters emitted a
// hardcoded `cleanup_verified: true` and an unconditional `teardown_state: "torn_down"`,
// even when the provider-native destroy explicitly reported `destroyed: false` or the
// remote-workspace cleanup half was unreachable. Every provider bar asserted exactly that
// constant, so the bars were PINNING THE OVERCLAIM: they could not have failed.
//
// Teardown now derives its outcome from what was OBSERVED:
//
//   torn_down            — the provider confirmed destruction AND the remote cleanup half
//                          was reachable. cleanup_verified true, nothing owed.
//   teardown_failed      — the provider explicitly reported it did not destroy. Presumed
//                          live; a durable cleanup obligation is open.
//   torn_down_unverified — the delete call returned but absence could NOT be re-observed
//                          (remote half unreachable). This is the `Unknown` class. It is
//                          never coerced to success and never to failure; a durable cleanup
//                          obligation is open.
//
// The carve-out that makes this safe: deletion of an EXISTING resource stays CALLABLE in
// every branch. Containment never strands an operator with a resource they cannot delete.
//
// This module owns the invariant so no bar can restate a weaker version of it, and it
// self-tests its own rejections against synthetic inputs on every run — an assertion that
// cannot fail is not an assertion.
export const TEARDOWN_STATES = ["torn_down", "teardown_failed", "torn_down_unverified"];
const OUTCOME_FOR_STATE = {
  torn_down: "succeeded",
  teardown_failed: "failed",
  torn_down_unverified: "unknown",
};
const CONTAINMENT_SCHEMA = "ioi.runtime.emergency_containment.v1";
const OBLIGATION_PREFIX = "cleanup-obligation://";

/**
 * Every way the observed teardown evidence violates the contract, as strings.
 * Empty array === the contract holds. `expectedState` is optional; when supplied the
 * observed state must be exactly it (so a bar that INTENDS to reach the unverified branch
 * fails if the runtime quietly succeeded instead of proving the branch).
 */
export function teardownContractViolations(evidence, expectedState = null) {
  const violations = [];
  const state = evidence?.teardown_state;
  const verified = evidence?.cleanup_verified;
  const disposition = evidence?.deletion_disposition ?? null;

  if (!TEARDOWN_STATES.includes(state)) {
    violations.push(`teardown_state ${JSON.stringify(state)} is not exactly one of ${TEARDOWN_STATES.join(" | ")}`);
    return violations;
  }
  if (expectedState !== null && state !== expectedState) {
    violations.push(`expected the ${expectedState} branch; the runtime reported ${state}`);
  }
  if (disposition === null || typeof disposition !== "object") {
    violations.push("no deletion_disposition accompanies the teardown outcome");
    return violations;
  }
  if (disposition.schema_version !== CONTAINMENT_SCHEMA) {
    violations.push(`deletion_disposition carries schema_version ${JSON.stringify(disposition.schema_version)}, not ${CONTAINMENT_SCHEMA}`);
  }
  if (typeof disposition.resource_ref !== "string" || disposition.resource_ref === "") {
    violations.push("deletion_disposition names no resource, so no obligation could ever be reconciled against it");
  }
  if (typeof disposition.detail !== "string" || disposition.detail.trim() === "") {
    violations.push("deletion_disposition states no detail");
  }
  if (disposition.outcome !== OUTCOME_FOR_STATE[state]) {
    violations.push(`teardown_state ${state} must carry outcome ${OUTCOME_FOR_STATE[state]}, observed ${JSON.stringify(disposition.outcome)}`);
  }
  if (state === "torn_down") {
    if (verified !== true) violations.push("a PROVEN-ABSENT teardown must report cleanup_verified true");
    if (disposition.cleanup_obligation_ref !== null) {
      violations.push("a proven-absent teardown owes nothing, so it must open no cleanup obligation");
    }
  } else {
    if (verified !== false) {
      violations.push(`${state} must NEVER be reported as verified — cleanup_verified was ${JSON.stringify(verified)}`);
    }
    if (typeof disposition.cleanup_obligation_ref !== "string"
      || !disposition.cleanup_obligation_ref.startsWith(OBLIGATION_PREFIX)) {
      violations.push(`${state} must open a durable ${OBLIGATION_PREFIX} cleanup obligation; got ${JSON.stringify(disposition.cleanup_obligation_ref)}`);
    }
  }
  return violations;
}

/** Deletion must remain CALLABLE in every branch — it may report a bad outcome, never refuse. */
export function deletionRemainedCallable(response) {
  return response?.status === 200 && response?.j?.ok === true;
}

/** One assertion covering both halves: the call was answered AND the outcome is honest. */
export function teardownFindings(response, expectedState = null) {
  const findings = deletionRemainedCallable(response)
    ? []
    : [`deletion did not remain callable: status ${response?.status}, ok ${JSON.stringify(response?.j?.ok)}, reason ${JSON.stringify(response?.j?.reason)}`];
  return [...findings, ...teardownContractViolations(response?.j?.evidence, expectedState)];
}

const OK_SUCCEEDED = {
  teardown_state: "torn_down",
  cleanup_verified: true,
  deletion_disposition: {
    schema_version: CONTAINMENT_SCHEMA,
    resource_ref: "provider-account://acct/resource/env",
    outcome: "succeeded",
    cleanup_obligation_ref: null,
    detail: "resource observed absent after delete; nothing further is owed",
  },
};
const OK_UNKNOWN = {
  teardown_state: "torn_down_unverified",
  cleanup_verified: false,
  deletion_disposition: {
    schema_version: CONTAINMENT_SCHEMA,
    resource_ref: "provider-account://acct/resource/env",
    outcome: "unknown",
    cleanup_obligation_ref: `${OBLIGATION_PREFIX}containment/unknown/env`,
    detail: "delete attempted but absence could not be confirmed",
  },
};

/**
 * Self-test: every rejection is exercised against a synthetic bad input on every run, so a
 * bar can never pass because the checker lost its teeth. Returns violation strings (empty
 * === the checker still rejects everything it claims to reject).
 */
export function selfTestTeardownContract() {
  const failures = [];
  const mustAccept = (evidence, expected, label) => {
    const v = teardownContractViolations(evidence, expected);
    if (v.length !== 0) failures.push(`self-test: honest ${label} evidence was REJECTED (${v.join("; ")})`);
  };
  const mustReject = (evidence, expected, label) => {
    if (teardownContractViolations(evidence, expected).length === 0) {
      failures.push(`self-test: ${label} was ACCEPTED; that rejection has no teeth`);
    }
  };
  mustAccept(OK_SUCCEEDED, "torn_down", "succeeded");
  mustAccept(OK_UNKNOWN, "torn_down_unverified", "unknown");
  // The exact overclaim the containment cut removed.
  mustReject({ ...OK_UNKNOWN, cleanup_verified: true }, null, "an UNVERIFIED teardown reported as cleanup_verified");
  mustReject(
    { ...OK_UNKNOWN, deletion_disposition: { ...OK_UNKNOWN.deletion_disposition, cleanup_obligation_ref: null } },
    null,
    "an unverified teardown that opened NO cleanup obligation",
  );
  mustReject({ ...OK_SUCCEEDED, teardown_state: "torn_down", cleanup_verified: false }, null, "a proven-absent teardown claiming cleanup_verified false");
  mustReject(
    { ...OK_SUCCEEDED, deletion_disposition: { ...OK_SUCCEEDED.deletion_disposition, cleanup_obligation_ref: `${OBLIGATION_PREFIX}x` } },
    null,
    "a proven-absent teardown that still owes an obligation",
  );
  mustReject({ ...OK_SUCCEEDED, deletion_disposition: { ...OK_SUCCEEDED.deletion_disposition, outcome: "unknown" } }, null, "a state/outcome mismatch");
  mustReject({ teardown_state: "cleaned_up", cleanup_verified: true }, null, "a teardown_state outside the three-way contract");
  mustReject({ teardown_state: "torn_down", cleanup_verified: true }, null, "a teardown with no deletion_disposition at all");
  mustReject(OK_SUCCEEDED, "torn_down_unverified", "a succeeded teardown presented as proof of the unverified branch");
  return failures;
}
