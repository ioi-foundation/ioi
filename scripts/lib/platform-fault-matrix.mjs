import crypto from "node:crypto";

export const PLATFORM_FAULT_MATRIX_ID = "ioi.platform-fault-matrix.v1";
export const PLATFORM_FAULT_MATRIX_HASH_PROFILE =
  "ioi.platform-fault-matrix-jcs-sha256.v1";
export const PLATFORM_FAULT_REVIEWED_SCENARIO_IDS = Object.freeze([
  "authority-unavailable-blocks-external-effect",
  "agentgres-split-brain-blocks-truth-mutation",
  "operation-specific-degraded-contract-allows-local-proposal",
  "degraded-contract-for-different-operation-fails-closed",
  "bounded-cache-read-survives-provider-outage",
  "expired-cache-fails-closed",
  "cache-without-source-head-fails-closed",
  "local-physical-continuation-during-control-plane-partition",
  "missing-local-supervisor-blocks-physical-continuation",
  "billing-outage-blocks-paid-work-start",
  "public-settlement-outage-does-not-block-local-proposal",
  "stale-attestation-blocks-portable-assurance-export",
  "clock-staleness-blocks-external-effect",
  "unknown-effect-never-converts-to-success",
  "provider-outage-blocks-provider-required-effect",
  "temporal-uncertainty-overlaps-expiry",
  "whole-state-rollback-without-outside-domain-floor",
  "bounded-offline-physical-continuation-with-established-holdover",
  "historical-checkpoint-does-not-prove-current-assurance",
  "whole-state-rollback-with-outside-domain-floor",
  "bounded-offline-holdover-exhaustion-fails-closed",
  "fresh-challenge-does-not-refresh-stale-source-fact",
  "reboot-breaks-same-boot-elapsed-continuity",
  "suspend-pause-and-drift-exceed-elapsed-profile",
  "fresh-temporal-evidence-does-not-replace-final-resource-fence",
  "provider-unreachable-cleanup-obligation-persists",
  "unknown-deletion-outcome-requires-cleanup-reconciliation",
  "ambiguous-provider-not-found-does-not-close-cleanup",
  "failed-activation-cannot-advance-active-head",
  "partial-activation-without-adjudication-cannot-advance-active-head",
  "unknown-activation-cannot-advance-active-head",
  "late-superseded-activation-cannot-reclaim-active-head",
]);
export const PLATFORM_FAULT_REVIEWED_SCENARIO_COUNT =
  PLATFORM_FAULT_REVIEWED_SCENARIO_IDS.length;
export const CPO_REQUIREMENT_IDS = Object.freeze(
  Array.from({ length: 12 }, (_, index) => (
    `CPO-${String(index + 1)}`
  )),
);

const ROOT_KEYS = Object.freeze([
  "schema_version",
  "matrix_id",
  "hash_profile",
  "status",
  "scenarios",
]);
const OPERATION_DISPOSITIONS = new Set([
  "available",
  "degraded",
  "fail_closed",
]);
const ASSURANCE_POSTURES = new Set([
  "trusted_operator",
  "software_only",
  "measured_boot",
  "hardware_attested",
]);
const ACTIVATION_CASES = Object.freeze({
  "failed-activation-cannot-advance-active-head": {
    observed: "failed",
    expected: "refused_failed",
  },
  "partial-activation-without-adjudication-cannot-advance-active-head": {
    observed: "partial",
    expected: "refused_partial",
  },
  "unknown-activation-cannot-advance-active-head": {
    observed: "unknown",
    expected: "refused_unknown",
  },
  "late-superseded-activation-cannot-reclaim-active-head": {
    observed: "superseded",
    expected: "refused_superseded",
  },
});

const REVIEWED_MATRIX_HASH =
  "sha256:36d9e756f5335c7083f968ebff5e25b413de732fa49e11558d62da95848c175e";

function isRecord(value) {
  return value !== null
    && typeof value === "object"
    && !Array.isArray(value);
}

function exactStringArray(actual, expected) {
  return Array.isArray(actual)
    && actual.length === expected.length
    && actual.every((value, index) => value === expected[index]);
}

function uniqueStrings(value) {
  return Array.isArray(value)
    && value.length > 0
    && value.every((entry) => typeof entry === "string" && entry.length > 0)
    && new Set(value).size === value.length;
}

function assertWellFormedUnicodeString(value) {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) {
        throw new TypeError("JCS values must not contain lone Unicode surrogates");
      }
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      throw new TypeError("JCS values must not contain lone Unicode surrogates");
    }
  }
}

function canonicalJson(value) {
  if (
    value === null
    || typeof value === "boolean"
    || typeof value === "string"
  ) {
    if (typeof value === "string") assertWellFormedUnicodeString(value);
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new TypeError("JCS values must contain only finite numbers");
    }
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(",")}]`;
  }
  if (isRecord(value)) {
    return `{${Object.keys(value)
      .sort()
      .map((key) => {
        assertWellFormedUnicodeString(key);
        return `${JSON.stringify(key)}:${canonicalJson(value[key])}`;
      })
      .join(",")}}`;
  }
  throw new TypeError(`unsupported JCS value type: ${typeof value}`);
}

function skipJsonWhitespace(source, state) {
  while (/\s/u.test(source[state.index] ?? "")) state.index += 1;
}

function scanJsonString(source, state) {
  const start = state.index;
  state.index += 1;
  while (state.index < source.length) {
    const character = source[state.index];
    if (character === "\\") {
      state.index += source[state.index + 1] === "u" ? 6 : 2;
      continue;
    }
    state.index += 1;
    if (character === '"') {
      return JSON.parse(source.slice(start, state.index));
    }
  }
  throw new SyntaxError("unterminated JSON string");
}

function scanJsonValue(source, state) {
  skipJsonWhitespace(source, state);
  const character = source[state.index];
  if (character === "{") {
    state.index += 1;
    skipJsonWhitespace(source, state);
    const keys = new Set();
    if (source[state.index] === "}") {
      state.index += 1;
      return;
    }
    while (state.index < source.length) {
      if (source[state.index] !== '"') {
        throw new SyntaxError("JSON object key must be a string");
      }
      const key = scanJsonString(source, state);
      if (keys.has(key)) throw new SyntaxError(`duplicate JSON key ${key}`);
      keys.add(key);
      skipJsonWhitespace(source, state);
      if (source[state.index] !== ":") {
        throw new SyntaxError("JSON object lacks colon");
      }
      state.index += 1;
      scanJsonValue(source, state);
      skipJsonWhitespace(source, state);
      if (source[state.index] === "}") {
        state.index += 1;
        return;
      }
      if (source[state.index] !== ",") {
        throw new SyntaxError("JSON object lacks comma");
      }
      state.index += 1;
      skipJsonWhitespace(source, state);
    }
    throw new SyntaxError("unterminated JSON object");
  }
  if (character === "[") {
    state.index += 1;
    skipJsonWhitespace(source, state);
    if (source[state.index] === "]") {
      state.index += 1;
      return;
    }
    while (state.index < source.length) {
      scanJsonValue(source, state);
      skipJsonWhitespace(source, state);
      if (source[state.index] === "]") {
        state.index += 1;
        return;
      }
      if (source[state.index] !== ",") {
        throw new SyntaxError("JSON array lacks comma");
      }
      state.index += 1;
    }
    throw new SyntaxError("unterminated JSON array");
  }
  if (character === '"') {
    scanJsonString(source, state);
    return;
  }
  const scalar =
    /^(?:-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?|true|false|null)/u
      .exec(source.slice(state.index));
  if (!scalar) throw new SyntaxError("invalid JSON scalar");
  state.index += scalar[0].length;
}

function assertJcsUnicode(value) {
  if (typeof value === "string") {
    assertWellFormedUnicodeString(value);
  } else if (Array.isArray(value)) {
    for (const entry of value) assertJcsUnicode(entry);
  } else if (isRecord(value)) {
    for (const [key, entry] of Object.entries(value)) {
      assertWellFormedUnicodeString(key);
      assertJcsUnicode(entry);
    }
  }
}

export function parsePlatformFaultMatrixJson(source) {
  const parsed = JSON.parse(source);
  const state = { index: 0 };
  scanJsonValue(source, state);
  skipJsonWhitespace(source, state);
  if (state.index !== source.length) {
    throw new SyntaxError("trailing JSON content");
  }
  assertJcsUnicode(parsed);
  return parsed;
}

export function hashPlatformFaultMatrixValue(value) {
  const body = canonicalJson({
    domain: PLATFORM_FAULT_MATRIX_HASH_PROFILE,
    value,
  });
  return `sha256:${crypto
    .createHash("sha256")
    .update(body, "utf8")
    .digest("hex")}`;
}

function scenarioMap(entries, failures) {
  const result = new Map();
  if (!Array.isArray(entries)) {
    failures.push("scenarios must be an array");
    return result;
  }
  for (const [index, scenario] of entries.entries()) {
    const id = scenario?.scenario_id;
    if (typeof id !== "string" || id.length === 0) {
      failures.push(`scenarios[${index}] lacks scenario_id`);
      continue;
    }
    if (result.has(id)) failures.push(`scenarios duplicates ${id}`);
    result.set(id, scenario);
  }
  return result;
}

function hasObservation(input, plane, state) {
  return input?.observations?.some((observation) => (
    observation?.plane === plane && observation?.state === state
  )) === true;
}

function validateCleanupCases(scenarios, failures) {
  const unreachable = scenarios.get(
    "provider-unreachable-cleanup-obligation-persists",
  );
  if (
    unreachable?.input?.operation !== "provider_resource_cleanup"
    || !hasObservation(unreachable?.input, "provider", "unavailable")
    || unreachable?.input?.originating_owner_deleted !== true
    || unreachable?.input?.cleanup_obligation?.cause !== "provider_unreachable"
    || unreachable?.input?.cleanup_obligation?.status !== "retry_scheduled"
    || unreachable?.expected_cleanup_status !== "retry_scheduled"
    || !unreachable?.forbidden_observations?.includes(
      "cleanup_obligation_deleted_with_owner",
    )
  ) {
    failures.push(
      "provider-unreachable cleanup must retain a retry-scheduled obligation after owner teardown",
    );
  }

  const unknown = scenarios.get(
    "unknown-deletion-outcome-requires-cleanup-reconciliation",
  );
  if (
    unknown?.input?.operation !== "provider_resource_cleanup"
    || unknown?.input?.deletion_attempt?.effect_outcome !== "unknown"
    || unknown?.input?.cleanup_obligation?.cause !== "unknown_effect"
    || unknown?.input?.cleanup_obligation?.status !== "reconciling"
    || unknown?.expected_cleanup_status !== "reconciling"
    || !unknown?.required_obligations?.includes(
      "reconcile_before_retry_or_completion",
    )
  ) {
    failures.push(
      "unknown cleanup deletion outcome must remain reconciling before retry or completion",
    );
  }

  const ambiguous = scenarios.get(
    "ambiguous-provider-not-found-does-not-close-cleanup",
  );
  const absence = ambiguous?.input?.provider_absence_observation;
  if (
    ambiguous?.input?.operation !== "provider_resource_cleanup"
    || absence?.result !== "not_found"
    || absence?.exact_identity_binding !== false
    || absence?.queried_provider_namespace_ref !== null
    || absence?.queried_resource_identity_commitment !== null
    || ambiguous?.input?.cleanup_obligation?.status !== "blocked"
    || ambiguous?.expected_cleanup_status !== "blocked"
    || !ambiguous?.forbidden_observations?.includes(
      "cleanup_closed_from_ambiguous_not_found",
    )
  ) {
    failures.push(
      "provider not-found without exact namespace and identity must not close cleanup",
    );
  }
}

function validateActivationCases(scenarios, failures) {
  for (const [id, expected] of Object.entries(ACTIVATION_CASES)) {
    const scenario = scenarios.get(id);
    if (
      scenario?.input?.operation !== "activation_head_transition"
      || scenario?.input?.observed_execution_outcome !== expected.observed
      || scenario?.expected_activation_outcome !== expected.expected
      || scenario?.expected_disposition !== "fail_closed"
      || scenario?.expected_active_head_ref
        !== scenario?.input?.active_head_before_ref
      || scenario?.expected_active_generation
        !== scenario?.input?.active_generation_before
      || !uniqueStrings(scenario?.forbidden_observations)
    ) {
      failures.push(
        `${id} must preserve the exact prior active head with a typed refusal`,
      );
    }
  }

  const partial = scenarios.get(
    "partial-activation-without-adjudication-cannot-advance-active-head",
  );
  if (partial?.input?.adjudication_ref !== null) {
    failures.push("unadjudicated partial activation must not carry adjudication");
  }

  const superseded = scenarios.get(
    "late-superseded-activation-cannot-reclaim-active-head",
  );
  if (
    superseded?.input?.late_success_observation !== true
    || !(superseded?.input?.candidate_generation
      < superseded?.input?.active_generation_before)
    || !superseded?.required_reason_codes?.includes(
      "activation_head_reclaim_refused",
    )
  ) {
    failures.push(
      "late superseded activation must not reclaim a newer active head",
    );
  }
}

export function validatePlatformFaultMatrix(matrix) {
  const failures = [];
  if (!isRecord(matrix)) return ["matrix root must be an object"];
  if (!exactStringArray(Object.keys(matrix).sort(), [...ROOT_KEYS].sort())) {
    failures.push("matrix root keys do not match the closed v1 contract");
  }
  if (matrix.schema_version !== "ioi.platform-fault-scenario.v1") {
    failures.push("matrix schema_version is not canonical");
  }
  if (matrix.matrix_id !== PLATFORM_FAULT_MATRIX_ID) {
    failures.push("matrix_id is not canonical");
  }
  if (matrix.hash_profile !== PLATFORM_FAULT_MATRIX_HASH_PROFILE) {
    failures.push("matrix hash_profile is not canonical");
  }
  if (matrix.status !== "target_fixture_only") {
    failures.push("matrix status must remain target_fixture_only");
  }

  const scenarios = scenarioMap(matrix.scenarios, failures);
  if (scenarios.size !== PLATFORM_FAULT_REVIEWED_SCENARIO_COUNT) {
    failures.push(
      `matrix must contain exactly the reviewed ${PLATFORM_FAULT_REVIEWED_SCENARIO_COUNT} scenarios`,
    );
  }
  if (!exactStringArray(
    [...scenarios.keys()].sort(),
    [...PLATFORM_FAULT_REVIEWED_SCENARIO_IDS].sort(),
  )) {
    failures.push("reviewed scenario ids do not match the canonical roster");
  }

  for (const [id, scenario] of scenarios) {
    if (!isRecord(scenario?.input)) {
      failures.push(`scenario ${id} lacks an input object`);
      continue;
    }
    if (
      typeof scenario.input.operation !== "string"
      || scenario.input.operation.length === 0
    ) {
      failures.push(`scenario ${id} lacks an operation`);
    }
    if (!OPERATION_DISPOSITIONS.has(scenario.expected_disposition)) {
      failures.push(`scenario ${id} has unknown expected_disposition`);
    }
    if (!ASSURANCE_POSTURES.has(scenario.expected_effective_assurance)) {
      failures.push(`scenario ${id} has unknown expected_effective_assurance`);
    }
    if (!uniqueStrings(scenario.required_reason_codes)) {
      failures.push(`scenario ${id} lacks unique required_reason_codes`);
    }
    if (!uniqueStrings(scenario.required_obligations)) {
      failures.push(`scenario ${id} lacks unique required_obligations`);
    }
    if (
      scenario.required_evidence !== undefined
      && !uniqueStrings(scenario.required_evidence)
    ) {
      failures.push(`scenario ${id} has invalid required_evidence`);
    }
    if (
      scenario.forbidden_observations !== undefined
      && !uniqueStrings(scenario.forbidden_observations)
    ) {
      failures.push(`scenario ${id} has invalid forbidden_observations`);
    }
  }

  validateCleanupCases(scenarios, failures);
  validateActivationCases(scenarios, failures);

  try {
    if (hashPlatformFaultMatrixValue(matrix) !== REVIEWED_MATRIX_HASH) {
      failures.push(
        "matrix does not match the reviewed semantic fingerprint; update the fixture and validator together through review",
      );
    }
  } catch (error) {
    failures.push(`matrix is not valid RFC 8785 input: ${error.message}`);
  }
  return failures;
}
