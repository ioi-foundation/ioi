import crypto from "node:crypto";

export const SLC_MATRIX_ID =
  "ioi.sovereign-local-completeness-matrix.v1";
export const SLC_MATRIX_HASH_PROFILE =
  "ioi.sovereign-local-completeness-matrix-jcs-sha256.v1";

const ROOT_KEYS = Object.freeze([
  "schema_version",
  "matrix_id",
  "hash_profile",
  "status",
  "claim_profiles",
  "external_conditional_nonclaims",
  "evaluation_rules",
  "operation_disposition_vocabulary",
  "case_verdict_vocabulary",
  "report_verdict_vocabulary",
  "fixture_profiles",
  "overlays",
  "scenarios",
]);
const CLAIM_PROFILE_IDS = Object.freeze([
  "minimum_l0_local_completeness",
  "production_self_hosted",
  "managed_optionality",
  "identity_preserving_migration",
]);
const FIXTURE_PROFILE_IDS = Object.freeze([
  "embedded_single_operator_offline",
  "self_hosted_org_single_node",
]);
const OVERLAY_IDS = Object.freeze([
  "managed_attach_detach_overlay",
  "identity_preserving_migration_overlay",
]);
const REVIEWED_SCENARIO_IDS = Object.freeze([
  "slc-01-network-disabled-cold-boot",
  "slc-01-required-managed-dependency-is-typed-unavailable",
  "slc-02-local-exact-effect-admitted",
  "slc-02-authenticated-without-authority-refused",
  "slc-03-complete-bounded-system-journey",
  "slc-03-missing-verification-cannot-complete",
  "slc-04-zero-undeclared-egress",
  "slc-04-blocked-diagnostics-preserve-local-operation",
  "slc-05-crash-restart-idempotent-replay",
  "slc-05-changed-body-replay-is-refused",
  "slc-05-unknown-effect-requires-reconciliation",
  "slc-06-backup-clean-restore-checkpoint-equivalence",
  "slc-06-tampered-export-refused",
  "slc-06-authentic-stale-restore-cannot-reactivate-authority",
  "slc-07-embedded-server-semantic-parity",
  "slc-07-semantic-mismatch-refused",
  "slc-08-connected-identity-and-portable-authority",
  "slc-08-attach-without-transfer-or-charge",
  "slc-08-explicitly-leased-managed-use-is-receipted",
  "slc-08-mismatched-connected-grant-is-refused",
  "slc-08-managed-use-requires-explicit-lease",
  "slc-09-detach-preserves-local-continuity",
  "slc-09-detached-managed-dependency-typed-unavailable",
  "slc-10-connect-does-not-migrate",
  "slc-10-migration-without-plan-is-refused",
  "slc-10-authorized-fenced-migration",
  "slc-10-interrupted-cutover-retains-one-writer",
  "slc-10-continuity-denial-requires-fork-or-successor",
  "slc-11-local-byo-supplier-cost-excluded",
  "slc-11-explicit-managed-fee-requires-use-evidence",
  "slc-12-unsupported-assurance-claims-withheld",
  "slc-12-missing-evidence-produces-incomplete-report",
]);
const REVIEWED_MATRIX_HASH =
  "sha256:2e69fd4b8cb15817d625a3b41d1c0f7076353f5eb179f54e005634b06aa1b5ea";
export const SLC_REQUIREMENT_IDS = Object.freeze(
  Array.from({ length: 12 }, (_, index) => (
    `SLC-${String(index + 1).padStart(2, "0")}`
  )),
);
const OPERATION_DISPOSITIONS = Object.freeze([
  "available",
  "unavailable",
  "fail_closed",
  "reconciliation_required",
  "not_applicable",
]);
const CASE_VERDICTS = Object.freeze(["pass", "fail"]);
const REPORT_VERDICTS = Object.freeze(["pass", "fail", "incomplete"]);
const SCENARIO_KINDS = new Set(["positive", "adversarial"]);
const HASH_KINDS = new Set([
  "matrix",
  "claim-profile",
  "fixture-profile",
  "overlay",
  "network-policy",
  "execution-case",
]);
const CHANGED_BODY_SCENARIO_ID =
  "slc-05-changed-body-replay-is-refused";
const LOCAL_EFFECT_EVIDENCE = Object.freeze([
  "identity_session_ref",
  "authority_provider_ref_and_snapshot_hash",
  "authority_decision_ref_and_hash",
  "authority_grant_ref_and_hash",
  "authority_lease_ref_and_hash_or_explicit_null",
  "effect_admission_receipt_ref_and_hash",
]);

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
      if (source[state.index] !== ":") throw new SyntaxError("JSON object lacks colon");
      state.index += 1;
      scanJsonValue(source, state);
      skipJsonWhitespace(source, state);
      if (source[state.index] === "}") {
        state.index += 1;
        return;
      }
      if (source[state.index] !== ",") throw new SyntaxError("JSON object lacks comma");
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
      if (source[state.index] !== ",") throw new SyntaxError("JSON array lacks comma");
      state.index += 1;
    }
    throw new SyntaxError("unterminated JSON array");
  }
  if (character === '"') {
    scanJsonString(source, state);
    return;
  }
  const scalar = /^(?:-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?|true|false|null)/u
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

export function parseSovereignLocalCompletenessJson(source) {
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

function idMap(entries, field, failures, label) {
  const result = new Map();
  if (!Array.isArray(entries)) {
    failures.push(`${label} must be an array`);
    return result;
  }
  for (const [index, entry] of entries.entries()) {
    const id = entry?.[field];
    if (typeof id !== "string" || id.length === 0) {
      failures.push(`${label}[${index}] lacks ${field}`);
      continue;
    }
    if (result.has(id)) failures.push(`${label} duplicates ${id}`);
    result.set(id, entry);
  }
  return result;
}

function exactIdSet(observed, expected, failures, label) {
  const actual = [...observed.keys()].sort();
  const wanted = [...expected].sort();
  if (!exactStringArray(actual, wanted)) {
    failures.push(`${label} must equal ${wanted.join(", ")}`);
  }
}

function addUnknownRefs(refs, known, failures, label) {
  if (!Array.isArray(refs)) {
    failures.push(`${label} must be an array`);
    return;
  }
  for (const ref of refs) {
    if (!known.has(ref)) failures.push(`${label} references unknown ${ref}`);
  }
}

function claimGraphIsAcyclic(claims, failures) {
  const visiting = new Set();
  const visited = new Set();
  function visit(id) {
    if (visiting.has(id)) {
      failures.push(`claim prerequisite cycle reaches ${id}`);
      return;
    }
    if (visited.has(id)) return;
    visiting.add(id);
    for (const dependency of (
      claims.get(id)?.required_prerequisite_claim_profile_ids ?? []
    )) {
      if (claims.has(dependency)) visit(dependency);
    }
    visiting.delete(id);
    visited.add(id);
  }
  for (const id of claims.keys()) visit(id);
}

function validateChangedBodyScenario(scenario, failures) {
  if (!scenario) {
    failures.push(`matrix omits ${CHANGED_BODY_SCENARIO_ID}`);
    return;
  }
  const input = scenario.input;
  if (
    scenario.requirement_id !== "SLC-05"
    || scenario.scenario_kind !== "adversarial"
    || scenario.expected_operation_disposition !== "fail_closed"
    || !isRecord(input)
    || typeof input.idempotency_key !== "string"
    || !isRecord(input.first_body)
    || !isRecord(input.changed_body)
    || canonicalJson(input.first_body) === canonicalJson(input.changed_body)
    || input.fault_point !== "after_effect_before_response"
  ) {
    failures.push(
      `${CHANGED_BODY_SCENARIO_ID} lacks its same-key/different-body replay contract`,
    );
  }
  for (const value of [
    "idempotency_key_body_mismatch",
    "first_request_body_hash",
    "changed_request_body_hash",
    "same_body_replay_receipt",
    "changed_body_refusal_receipt",
    "effect_invocation_count_one",
    "changed_body_invocation_count_zero",
  ]) {
    const source = value === "idempotency_key_body_mismatch"
      ? scenario.required_reason_codes
      : scenario.required_evidence;
    if (!source?.includes(value)) {
      failures.push(`${CHANGED_BODY_SCENARIO_ID} omits ${value}`);
    }
  }
}

export function hashSovereignLocalCompletenessValue(kind, value) {
  if (!HASH_KINDS.has(kind)) {
    throw new TypeError(`unknown sovereign-local hash kind: ${kind}`);
  }
  const domain =
    `ioi.sovereign-local-completeness-${kind}-jcs-sha256.v1`;
  const body = canonicalJson({ domain, value });
  return `sha256:${crypto.createHash("sha256").update(body, "utf8").digest("hex")}`;
}

export function validateSovereignLocalCompletenessMatrix(matrix) {
  const failures = [];
  if (!isRecord(matrix)) return ["matrix root must be an object"];
  if (!exactStringArray(Object.keys(matrix).sort(), [...ROOT_KEYS].sort())) {
    failures.push("matrix root keys do not match the closed v1 contract");
  }
  if (
    matrix.schema_version
      !== "ioi.sovereign-local-completeness-scenario.v1"
  ) {
    failures.push("matrix schema_version is not canonical");
  }
  if (matrix.matrix_id !== SLC_MATRIX_ID) {
    failures.push("matrix_id is not canonical");
  }
  if (matrix.hash_profile !== SLC_MATRIX_HASH_PROFILE) {
    failures.push("matrix hash_profile is not canonical");
  }
  if (matrix.status !== "target_fixture_only") {
    failures.push("matrix status must remain target_fixture_only");
  }
  if (!exactStringArray(
    matrix.operation_disposition_vocabulary,
    OPERATION_DISPOSITIONS,
  )) {
    failures.push("operation disposition vocabulary changed");
  }
  if (!exactStringArray(matrix.case_verdict_vocabulary, CASE_VERDICTS)) {
    failures.push("case verdict vocabulary changed");
  }
  if (!exactStringArray(matrix.report_verdict_vocabulary, REPORT_VERDICTS)) {
    failures.push("report verdict vocabulary changed");
  }

  const claims = idMap(
    matrix.claim_profiles,
    "claim_profile_id",
    failures,
    "claim_profiles",
  );
  const fixtures = idMap(
    matrix.fixture_profiles,
    "fixture_profile_id",
    failures,
    "fixture_profiles",
  );
  const overlays = idMap(
    matrix.overlays,
    "overlay_id",
    failures,
    "overlays",
  );
  const scenarios = idMap(
    matrix.scenarios,
    "scenario_id",
    failures,
    "scenarios",
  );
  if (scenarios.size !== 32) {
    failures.push("matrix must contain exactly the reviewed 32 scenarios");
  }
  exactIdSet(claims, CLAIM_PROFILE_IDS, failures, "claim profile ids");
  exactIdSet(fixtures, FIXTURE_PROFILE_IDS, failures, "fixture profile ids");
  exactIdSet(overlays, OVERLAY_IDS, failures, "overlay ids");
  exactIdSet(
    scenarios,
    REVIEWED_SCENARIO_IDS,
    failures,
    "reviewed scenario ids",
  );

  for (const [id, claim] of claims) {
    addUnknownRefs(
      claim.required_prerequisite_claim_profile_ids,
      claims,
      failures,
      `claim ${id} prerequisites`,
    );
    addUnknownRefs(
      claim.required_fixture_profile_ids,
      fixtures,
      failures,
      `claim ${id} fixtures`,
    );
    addUnknownRefs(
      claim.required_overlay_ids,
      overlays,
      failures,
      `claim ${id} overlays`,
    );
  }
  claimGraphIsAcyclic(claims, failures);

  const externalClaims = idMap(
    matrix.external_conditional_nonclaims,
    "claim_id",
    failures,
    "external_conditional_nonclaims",
  );
  for (const id of externalClaims.keys()) {
    if (claims.has(id)) {
      failures.push(`out-of-scope claim ${id} was promoted to claim_profiles`);
    }
  }

  const coverage = new Map(
    SLC_REQUIREMENT_IDS.map((id) => [id, new Set()]),
  );
  for (const [id, scenario] of scenarios) {
    if (!SLC_REQUIREMENT_IDS.includes(scenario.requirement_id)) {
      failures.push(`scenario ${id} has unknown requirement_id`);
    } else {
      coverage.get(scenario.requirement_id).add(scenario.scenario_kind);
    }
    if (!SCENARIO_KINDS.has(scenario.scenario_kind)) {
      failures.push(`scenario ${id} has unknown scenario_kind`);
    }
    addUnknownRefs(
      scenario.fixture_profile_ids,
      fixtures,
      failures,
      `scenario ${id} fixtures`,
    );
    addUnknownRefs(
      scenario.overlay_ids ?? [],
      overlays,
      failures,
      `scenario ${id} overlays`,
    );
    addUnknownRefs(
      scenario.required_for_claims,
      claims,
      failures,
      `scenario ${id} claims`,
    );
    for (const claimId of (
      Array.isArray(scenario.required_for_claims)
        ? scenario.required_for_claims
        : []
    )) {
      if (externalClaims.has(claimId)) {
        failures.push(`scenario ${id} promotes out-of-scope claim ${claimId}`);
      }
    }
    if (
      !OPERATION_DISPOSITIONS.includes(
        scenario.expected_operation_disposition,
      )
    ) {
      failures.push(`scenario ${id} has unknown operation disposition`);
    }
    if (!REPORT_VERDICTS.includes(scenario.expected_report_verdict)) {
      failures.push(`scenario ${id} has unknown report verdict`);
    }
    if (!uniqueStrings(scenario.required_evidence)) {
      failures.push(`scenario ${id} lacks unique required_evidence`);
    }
    if (
      scenario.required_reason_codes !== undefined
      && !uniqueStrings(scenario.required_reason_codes)
    ) {
      failures.push(`scenario ${id} has invalid required_reason_codes`);
    }
  }
  for (const [requirement, kinds] of coverage) {
    if (!kinds.has("positive") || !kinds.has("adversarial")) {
      failures.push(`${requirement} lacks positive and adversarial coverage`);
    }
  }

  const slc07 = [...scenarios.values()].filter(
    (scenario) => scenario.requirement_id === "SLC-07",
  );
  for (const scenario of slc07) {
    if (
      scenario.fixture_binding !== "joint_all_listed_fixtures"
      || !exactStringArray(
        scenario.fixture_profile_ids,
        FIXTURE_PROFILE_IDS,
      )
    ) {
      failures.push(
        `${scenario.scenario_id} must jointly bind embedded and server fixtures`,
      );
    }
  }
  if (
    fixtures.get("embedded_single_operator_offline")?.agentgres_mode
      !== "embedded"
    || fixtures.get("self_hosted_org_single_node")?.agentgres_mode
      !== "server"
  ) {
    failures.push("SLC-07 fixtures do not preserve distinct Agentgres modes");
  }

  validateChangedBodyScenario(
    scenarios.get(CHANGED_BODY_SCENARIO_ID),
    failures,
  );
  if (!exactStringArray(
    scenarios.get("slc-02-local-exact-effect-admitted")?.required_evidence,
    LOCAL_EFFECT_EVIDENCE,
  )) {
    failures.push(
      "slc-02-local-exact-effect-admitted must bind the exact provider, decision, mandatory grant, optional lease pair, and receipt ref/hash evidence",
    );
  }
  if (
    !scenarios
      .get("slc-08-connected-identity-and-portable-authority")
      ?.required_evidence
      ?.includes("authority_grant_envelope_v3_ref_and_hash")
  ) {
    failures.push(
      "slc-08-connected-identity-and-portable-authority lacks its grant ref/hash pair",
    );
  }
  try {
    if (
      hashSovereignLocalCompletenessValue("matrix", matrix)
        !== REVIEWED_MATRIX_HASH
    ) {
      failures.push(
        "matrix does not match the reviewed semantic fingerprint; update the fixture and validator together through review",
      );
    }
  } catch (error) {
    failures.push(`matrix is not valid RFC 8785 input: ${error.message}`);
  }
  return failures;
}
