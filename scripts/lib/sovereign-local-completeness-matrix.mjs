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
  "slc-01-untrusted-installer-refused-before-execution",
  "slc-01-required-managed-dependency-is-typed-unavailable",
  "slc-02-local-exact-effect-admitted",
  "slc-02-route-and-mcp-authorization-surface-closed",
  "slc-02-authenticated-without-authority-refused",
  "slc-02-unclassified-route-or-mcp-authorization-fork-refused",
  "slc-03-complete-bounded-system-journey",
  "slc-03-untrusted-update-refused-and-previous-build-preserved",
  "slc-03-missing-verification-cannot-complete",
  "slc-04-zero-undeclared-egress",
  "slc-04-blocked-diagnostics-preserve-local-operation",
  "slc-05-crash-restart-idempotent-replay",
  "slc-05-changed-body-replay-is-refused",
  "slc-05-unknown-effect-requires-reconciliation",
  "slc-06-backup-clean-restore-checkpoint-equivalence",
  "slc-06-default-export-excludes-secret-material-and-rebinds",
  "slc-06-foreign-ciphertext-or-loose-secret-refused-before-write",
  "slc-06-same-size-artifact-substitution-zero-target-mutation",
  "slc-06-tampered-export-refused",
  "slc-06-authentic-stale-restore-cannot-reactivate-authority",
  "slc-07-embedded-server-semantic-parity",
  "slc-07-semantic-mismatch-refused",
  "slc-08-connected-identity-and-portable-authority",
  "slc-08-attach-without-transfer-or-charge",
  "slc-08-attachment-drift-explicit-no-implicit-reconciliation",
  "slc-08-explicitly-leased-managed-use-is-receipted",
  "slc-08-mismatched-connected-grant-is-refused",
  "slc-08-managed-use-requires-explicit-lease",
  "slc-09-detach-preserves-local-continuity",
  "slc-09-detached-managed-dependency-typed-unavailable",
  "slc-10-connect-does-not-migrate",
  "slc-10-migration-without-plan-is-refused",
  "slc-10-authorized-fenced-migration",
  "slc-10-all-writer-classes-quiesced-during-migration",
  "slc-10-fence-observation-failure-or-timeout-only-takeover-refused",
  "slc-10-interrupted-cutover-retains-one-writer",
  "slc-10-continuity-denial-requires-fork-or-successor",
  "slc-11-local-byo-supplier-cost-excluded",
  "slc-11-explicit-managed-fee-requires-use-evidence",
  "slc-12-unsupported-assurance-claims-withheld",
  "slc-12-missing-evidence-produces-incomplete-report",
]);
const REVIEWED_MATRIX_HASH =
  "sha256:e079eb1bff1c41e5dc03b5ed259170f999585a68146c1b4d222d3ea831bfbc8e";
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

function includesEvery(actual, expected) {
  return Array.isArray(actual)
    && expected.every((value) => actual.includes(value));
}

function hasScenarioBase(scenario, {
  requirementId,
  scenarioKind,
  disposition,
  fixtures = FIXTURE_PROFILE_IDS,
  overlays = [],
  claims = [
    "minimum_l0_local_completeness",
    "production_self_hosted",
  ],
}) {
  return isRecord(scenario)
    && scenario.requirement_id === requirementId
    && scenario.scenario_kind === scenarioKind
    && scenario.expected_operation_disposition === disposition
    && scenario.expected_report_verdict === "pass"
    && exactStringArray(scenario.fixture_profile_ids, fixtures)
    && exactStringArray(scenario.overlay_ids ?? [], overlays)
    && exactStringArray(scenario.required_for_claims, claims);
}

function validateReleaseIntegrityScenarios(scenarios, failures) {
  const coldBoot = scenarios.get("slc-01-network-disabled-cold-boot");
  if (
    !hasScenarioBase(coldBoot, {
      requirementId: "SLC-01",
      scenarioKind: "positive",
      disposition: "available",
    })
    || coldBoot.input?.release_manifest !== "preloaded_signed"
    || coldBoot.input?.trusted_key_and_revocation_snapshot !== "pinned_local"
    || coldBoot.input?.update_discovery !== "disabled"
    || !includesEvery(coldBoot.required_evidence, [
      "signed_release_manifest_ref_and_hash",
      "release_artifact_digest_verification",
      "trusted_key_set_and_revocation_snapshot_ref_and_hash",
      "installed_build_hash",
      "remote_update_discovery_count_zero",
    ])
  ) {
    failures.push(
      "slc-01-network-disabled-cold-boot lacks its signed offline release proof contract",
    );
  }

  const installer = scenarios.get(
    "slc-01-untrusted-installer-refused-before-execution",
  );
  if (
    !hasScenarioBase(installer, {
      requirementId: "SLC-01",
      scenarioKind: "adversarial",
      disposition: "fail_closed",
    })
    || installer.input?.installation_state !== "empty_or_prior_admitted"
    || installer.input?.network_fallback !== "blocked"
    || !exactStringArray(installer.input?.release_faults_under_test, [
      "unsigned",
      "revoked_signer",
      "digest_mismatch",
      "manifest_substitution",
    ])
    || !installer.required_reason_codes?.includes("untrusted_release_refused")
    || !includesEvery(installer.required_evidence, [
      "release_verification_refusal_receipts",
      "installer_execution_count_zero",
      "installation_state_root_before_after_equal",
      "remote_release_discovery_count_zero",
    ])
  ) {
    failures.push(
      "slc-01-untrusted-installer-refused-before-execution lacks its pre-execution installer integrity contract",
    );
  }

  const journey = scenarios.get("slc-03-complete-bounded-system-journey");
  if (
    !hasScenarioBase(journey, {
      requirementId: "SLC-03",
      scenarioKind: "positive",
      disposition: "available",
    })
    || journey.input?.lifecycle_change
      !== "signed_authorized_canary_activation_with_rollback_or_recall"
    || !includesEvery(journey.required_evidence, [
      "signed_successor_release_manifest_ref_and_hash",
      "authorized_hypervisor_change_plan_ref_and_hash",
      "canary_and_readiness_evidence",
      "exact_update_activation_receipt",
      "previous_build_rollback_state_proof",
    ])
  ) {
    failures.push(
      "slc-03-complete-bounded-system-journey lacks its signed update lifecycle proof contract",
    );
  }

  const update = scenarios.get(
    "slc-03-untrusted-update-refused-and-previous-build-preserved",
  );
  if (
    !hasScenarioBase(update, {
      requirementId: "SLC-03",
      scenarioKind: "adversarial",
      disposition: "fail_closed",
    })
    || update.input?.prior_build_state !== "admitted_and_active"
    || !exactStringArray(update.input?.update_faults_under_test, [
      "unsigned",
      "tampered",
      "revoked_signer",
      "downgrade",
      "artifact_substitution",
    ])
    || !update.required_reason_codes?.includes(
      "untrusted_or_unauthorized_update_refused",
    )
    || !includesEvery(update.required_evidence, [
      "update_verification_refusal_receipts",
      "update_activation_count_zero",
      "previous_admitted_build_active_hash",
      "rollback_state_before_after_equal",
    ])
  ) {
    failures.push(
      "slc-03-untrusted-update-refused-and-previous-build-preserved lacks its previous-build-preserving update refusal contract",
    );
  }
}

function validateRouteAndMcpAuthorizationScenarios(scenarios, failures) {
  const closedSurface = scenarios.get(
    "slc-02-route-and-mcp-authorization-surface-closed",
  );
  if (
    !hasScenarioBase(closedSurface, {
      requirementId: "SLC-02",
      scenarioKind: "positive",
      disposition: "available",
    })
    || closedSurface.input?.route_surface !== "all_externally_reachable"
    || closedSurface.input?.route_classification
      !== "authenticated_policy_explicit_public_or_internal_only"
    || closedSurface.input?.mcp_surface
      !== "opt_in_subset_or_typed_unavailable"
    || closedSurface.input?.mcp_authorization
      !== "same_policy_enforcement_and_final_invoker_path"
    || !includesEvery(closedSurface.required_evidence, [
      "authorization_surface_mount_manifest_ref_and_hash",
      "externally_reachable_route_count",
      "classified_route_count_equal_to_reachable_count",
      "mcp_exposure_manifest_or_typed_unavailable_receipt",
      "mcp_runtime_tool_contract_refs_or_explicit_empty",
      "native_and_mcp_same_policy_enforcement_trace",
      "native_and_mcp_same_final_invoker_trace",
      "mcp_call_time_authorization_receipt_or_explicit_unavailable",
    ])
  ) {
    failures.push(
      "slc-02-route-and-mcp-authorization-surface-closed lacks its complete same-PEP route and MCP contract",
    );
  }

  const fork = scenarios.get(
    "slc-02-unclassified-route-or-mcp-authorization-fork-refused",
  );
  if (
    !hasScenarioBase(fork, {
      requirementId: "SLC-02",
      scenarioKind: "adversarial",
      disposition: "fail_closed",
    })
    || !exactStringArray(fork.input?.authorization_surface_faults_under_test, [
      "unclassified_mutation_route",
      "mcp_only_authorization_path",
    ])
    || !fork.required_reason_codes?.includes(
      "authorization_surface_unclassified_or_forked",
    )
    || !includesEvery(fork.required_evidence, [
      "startup_or_admission_refusal_receipts",
      "route_or_tool_unavailable_observations",
      "final_invoker_call_count_zero",
    ])
  ) {
    failures.push(
      "slc-02-unclassified-route-or-mcp-authorization-fork-refused lacks its zero-invoker authorization-fork refusal contract",
    );
  }
}

function validateRestoreAndSecretBoundaryScenarios(scenarios, failures) {
  const restore = scenarios.get(
    "slc-06-backup-clean-restore-checkpoint-equivalence",
  );
  if (
    !hasScenarioBase(restore, {
      requirementId: "SLC-06",
      scenarioKind: "positive",
      disposition: "available",
    })
    || restore.input?.artifact_verification
      !== "complete_byte_stream_before_mutation"
    || restore.input?.destination_preflight
      !== "write_read_delete_and_path_confinement"
    || restore.input?.publication !== "atomic"
    || restore.input?.secret_portability
      !== "default_export_excludes_and_destination_rebinds"
    || !includesEvery(restore.required_evidence, [
      "destination_write_read_delete_preflight",
      "local_path_and_symlink_confinement_or_not_applicable",
      "complete_byte_stream_hash_verification",
      "atomic_publication_receipt",
      "default_secret_scrub_and_exclusion_report",
      "destination_local_credential_reresolution",
    ])
  ) {
    failures.push(
      "slc-06-backup-clean-restore-checkpoint-equivalence lacks its pre-write atomic restore contract",
    );
  }

  const safeExport = scenarios.get(
    "slc-06-default-export-excludes-secret-material-and-rebinds",
  );
  if (
    !hasScenarioBase(safeExport, {
      requirementId: "SLC-06",
      scenarioKind: "positive",
      disposition: "available",
    })
    || safeExport.input?.export_mode !== "default_backup_and_evidence"
    || safeExport.input?.restore_credential_posture
      !== "destination_local_reresolution"
    || !includesEvery(safeExport.input?.secret_classes_populated, [
      "plaintext_credentials",
      "source_instance_ciphertext",
      "provider_tokens",
      "local_signing_material",
    ])
    || !includesEvery(safeExport.required_evidence, [
      "source_secret_inventory_commitment",
      "exhaustive_secret_scrub_and_exclusion_report",
      "export_plaintext_secret_scan_count_zero",
      "export_source_instance_ciphertext_scan_count_zero",
      "destination_local_credential_reresolution_refs",
      "post_rebind_restored_operation_receipt",
    ])
  ) {
    failures.push(
      "slc-06-default-export-excludes-secret-material-and-rebinds lacks its default secret-exclusion and destination-rebind contract",
    );
  }

  const unsafeSecret = scenarios.get(
    "slc-06-foreign-ciphertext-or-loose-secret-refused-before-write",
  );
  if (
    !hasScenarioBase(unsafeSecret, {
      requirementId: "SLC-06",
      scenarioKind: "adversarial",
      disposition: "fail_closed",
    })
    || !exactStringArray(unsafeSecret.input?.import_secret_faults_under_test, [
      "loose_plaintext_secret",
      "source_instance_ciphertext",
    ])
    || !unsafeSecret.required_reason_codes?.includes(
      "unsafe_or_foreign_secret_material_refused",
    )
    || !includesEvery(unsafeSecret.required_evidence, [
      "secret_boundary_refusal_receipts",
      "target_state_root_before_after_equal",
      "first_target_write_count_zero",
    ])
  ) {
    failures.push(
      "slc-06-foreign-ciphertext-or-loose-secret-refused-before-write lacks its zero-write secret-boundary refusal contract",
    );
  }

  const substitution = scenarios.get(
    "slc-06-same-size-artifact-substitution-zero-target-mutation",
  );
  if (
    !hasScenarioBase(substitution, {
      requirementId: "SLC-06",
      scenarioKind: "adversarial",
      disposition: "fail_closed",
    })
    || substitution.input?.declared_and_substituted_byte_length !== "equal"
    || substitution.input?.declared_and_substituted_content_hash !== "different"
    || !substitution.required_reason_codes?.includes(
      "artifact_full_stream_hash_mismatch",
    )
    || !includesEvery(substitution.required_evidence, [
      "complete_byte_stream_hash_mismatch",
      "target_state_root_before_after_equal",
      "target_stop_call_count_zero",
      "target_wipe_call_count_zero",
      "target_copy_call_count_zero",
      "target_apply_call_count_zero",
    ])
  ) {
    failures.push(
      "slc-06-same-size-artifact-substitution-zero-target-mutation lacks its full-stream zero-mutation refusal contract",
    );
  }
}

function validateAttachmentDriftScenarios(scenarios, failures) {
  const attachment = scenarios.get("slc-08-attach-without-transfer-or-charge");
  if (
    !hasScenarioBase(attachment, {
      requirementId: "SLC-08",
      scenarioKind: "positive",
      disposition: "available",
      fixtures: ["embedded_single_operator_offline"],
      overlays: ["managed_attach_detach_overlay"],
      claims: ["managed_optionality"],
    })
    || attachment.input?.attachment_projection
      !== "explicit_linked_local_only_managed_only_or_unreachable"
    || attachment.input?.drift_inspection !== "read_only"
    || !includesEvery(attachment.required_evidence, [
      "explicit_attachment_inventory_and_drift_state",
      "implicit_reconciliation_effect_count_zero",
    ])
  ) {
    failures.push(
      "slc-08-attach-without-transfer-or-charge lacks its explicit read-only attachment-state contract",
    );
  }

  const drift = scenarios.get(
    "slc-08-attachment-drift-explicit-no-implicit-reconciliation",
  );
  if (
    !hasScenarioBase(drift, {
      requirementId: "SLC-08",
      scenarioKind: "adversarial",
      disposition: "available",
      fixtures: ["embedded_single_operator_offline"],
      overlays: ["managed_attach_detach_overlay"],
      claims: ["managed_optionality"],
    })
    || drift.input?.action !== "inspect_attachment_drift"
    || drift.input?.reconciliation_authority !== "absent"
    || !exactStringArray(drift.input?.attachment_states_under_test, [
      "linked",
      "local_only",
      "managed_only",
      "unreachable",
    ])
    || !includesEvery(drift.required_evidence, [
      "attachment_inventory_ref_and_hash",
      "local_and_managed_state_comparison",
      "linked_local_only_managed_only_unreachable_state_observations",
      "drift_report_ref_and_hash",
      "reconciliation_effect_call_count_zero",
      "custody_and_writer_before_after_equal",
    ])
  ) {
    failures.push(
      "slc-08-attachment-drift-explicit-no-implicit-reconciliation lacks its explicit no-reconciliation drift contract",
    );
  }
}

function validateMigrationWriterSafetyScenarios(scenarios, failures) {
  const migration = scenarios.get("slc-10-authorized-fenced-migration");
  if (
    !hasScenarioBase(migration, {
      requirementId: "SLC-10",
      scenarioKind: "positive",
      disposition: "available",
      fixtures: ["embedded_single_operator_offline"],
      overlays: ["identity_preserving_migration_overlay"],
      claims: ["identity_preserving_migration"],
    })
    || migration.input?.quiescence_scope
      !== "foreground_background_and_identity_membership_writers"
    || migration.input?.fence_observation !== "available_and_current"
    || !includesEvery(migration.required_evidence, [
      "foreground_writer_quiescence_ref",
      "background_queue_writer_quiescence_ref",
      "identity_membership_writer_quiescence_ref",
      "post_checkpoint_source_write_count_zero",
      "writer_guard_and_fence_availability_proof",
    ])
  ) {
    failures.push(
      "slc-10-authorized-fenced-migration lacks its all-writer quiescence and observable-fence contract",
    );
  }

  const quiescence = scenarios.get(
    "slc-10-all-writer-classes-quiesced-during-migration",
  );
  if (
    !hasScenarioBase(quiescence, {
      requirementId: "SLC-10",
      scenarioKind: "adversarial",
      disposition: "fail_closed",
      fixtures: ["embedded_single_operator_offline"],
      overlays: ["identity_preserving_migration_overlay"],
      claims: ["identity_preserving_migration"],
    })
    || !exactStringArray(quiescence.input?.concurrent_writer_attempts, [
      "foreground_mutation",
      "background_queue_work",
      "identity_or_membership_mutation",
    ])
    || quiescence.input?.migration_phase
      !== "after_quiescence_before_cutover"
    || !quiescence.required_reason_codes?.includes(
      "mutation_refused_during_writer_quiescence",
    )
    || !includesEvery(quiescence.required_evidence, [
      "foreground_mutation_blocked_or_durably_held",
      "background_queue_work_blocked_or_durably_held",
      "identity_membership_mutation_blocked_or_durably_held",
      "post_checkpoint_source_write_count_zero",
      "writer_guard_and_fence_observation",
      "target_writer_not_yet_admitted",
    ])
  ) {
    failures.push(
      "slc-10-all-writer-classes-quiesced-during-migration lacks its post-checkpoint writer-refusal contract",
    );
  }

  const fenceFailure = scenarios.get(
    "slc-10-fence-observation-failure-or-timeout-only-takeover-refused",
  );
  if (
    !hasScenarioBase(fenceFailure, {
      requirementId: "SLC-10",
      scenarioKind: "adversarial",
      disposition: "fail_closed",
      fixtures: ["embedded_single_operator_offline"],
      overlays: ["identity_preserving_migration_overlay"],
      claims: ["identity_preserving_migration"],
    })
    || !exactStringArray(fenceFailure.input?.fence_faults_under_test, [
      "fence_observation_unavailable",
      "timeout_only_takeover",
    ])
    || fenceFailure.input?.source_liveness !== "not_proven_absent"
    || !fenceFailure.required_reason_codes?.includes(
      "writer_fence_not_safely_observable",
    )
    || !includesEvery(fenceFailure.required_evidence, [
      "fence_observation_failure_receipt",
      "timeout_only_takeover_refusal_receipt",
      "target_writer_admission_count_zero",
      "source_writer_retained_observation",
      "source_deposition_count_zero",
    ])
  ) {
    failures.push(
      "slc-10-fence-observation-failure-or-timeout-only-takeover-refused lacks its no-age-only-takeover contract",
    );
  }
}

function validatePortableSecretExportNonclaim(externalClaims, failures) {
  const portableSecretExport = externalClaims.get("portable_secret_export");
  if (
    portableSecretExport?.conformance_status !== "out_of_scope_unavailable"
    || !exactStringArray(
      portableSecretExport?.required_external_evidence,
      [
        "explicit_secret_export_authority",
        "independently_sealed_secret_bundle",
        "wrong_passphrase_and_tamper_refusal_before_first_write",
        "destination_rekey",
        "merge_non_clobber",
      ],
    )
  ) {
    failures.push(
      "portable_secret_export must remain an external conditional nonclaim with sealed-bundle, pre-write refusal, rekey, and non-clobber evidence",
    );
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
  if (scenarios.size !== 42) {
    failures.push("matrix must contain exactly the reviewed 42 scenarios");
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
  validatePortableSecretExportNonclaim(externalClaims, failures);

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
  validateReleaseIntegrityScenarios(scenarios, failures);
  validateRouteAndMcpAuthorizationScenarios(scenarios, failures);
  validateRestoreAndSecretBoundaryScenarios(scenarios, failures);
  validateAttachmentDriftScenarios(scenarios, failures);
  validateMigrationWriterSafetyScenarios(scenarios, failures);
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
