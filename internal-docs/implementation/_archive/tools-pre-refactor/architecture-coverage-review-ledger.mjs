import { sha256, stableJson } from "./lib.mjs";

export const ARCHITECTURE_COVERAGE_REVIEW_LEDGER_SCHEMA =
  "ioi.program.architecture-coverage-review-ledger.v1";

const HASH_PATTERN = /^[a-f0-9]{64}$/u;
const MAPPING_ID_PATTERN = /^AZ-[0-9]{2}:LOC-[0-9]{3}$/u;

export const REVIEWED_WORK_ITEM_SCOPE_FIELDS = [
  "work_item_id",
  "stage_id",
  "record_role",
  "objective",
  "falsifiable_claim",
  "selected_profile",
  "canon_owners",
  "contract_families",
  "private_artifacts",
  "dependency_work_item_ids",
  "aggregate_child_ids",
  "in_scope",
  "out_of_scope",
  "consequential_effects_and_final_invokers",
  "remaining_nonclaims",
  "rollback_or_stop_rule",
];

function selectedWorkItemScope(record) {
  return Object.fromEntries(
    REVIEWED_WORK_ITEM_SCOPE_FIELDS.map((field) => [field, record?.[field] ?? null]),
  );
}

export function buildReviewedAssignmentEntry({ obligation, assignment, records }) {
  const identity = {
    assignment_id: obligation.obligation_id,
    obligation_id: obligation.obligation_id,
    obligation_target: obligation.target,
    stage_id: assignment.stage,
    bounded_work_item_ids: [...assignment.workItemIds],
    contract_applicability:
      assignment.contractApplicability ?? "canonical_or_pending_contracts",
    required_private_artifact_class:
      assignment.requiredPrivateArtifactClass ?? null,
    work_item_scopes: assignment.workItemIds.map((workItemId) => {
      const record = records.get(workItemId);
      return {
        work_item_id: workItemId,
        stage_id: record?.stage_id ?? null,
        record_role: record?.record_role ?? null,
        scope_sha256: sha256(stableJson(selectedWorkItemScope(record))),
      };
    }),
  };
  return {
    ...identity,
    assignment_identity_sha256: sha256(stableJson(identity)),
  };
}

export function reviewedAssignmentSetSha256(entries) {
  return sha256(stableJson(entries));
}

export function reviewedAcceptedAdrSetSha256(entries) {
  return sha256(stableJson(entries));
}

export function reviewedPlanningInputSetSha256(entries) {
  return sha256(stableJson(entries));
}

function mappingIdentity(entry) {
  return {
    mapping_id: entry.mapping_id,
    obligation_id: entry.obligation_id,
    obligation_target: entry.obligation_target,
    locator_ordinal: entry.locator_ordinal,
    locator: entry.locator,
    owner_path: entry.owner_path,
    owner_kind: entry.owner_kind,
    fragment_kind: entry.fragment_kind,
    fragment: entry.fragment,
    heading_level: entry.heading_level ?? null,
    heading_text: entry.heading_text ?? null,
  };
}

function reviewedDigestIdentity(entry) {
  return {
    ...mappingIdentity(entry),
    owner_sha256: entry.owner_sha256,
    fragment_sha256: entry.fragment_sha256,
  };
}

export function buildReviewedLocatorEntry({
  obligationId,
  obligationTarget,
  locatorOrdinal,
  resolvedLocator,
}) {
  const identity = {
    mapping_id: `${obligationId}:LOC-${String(locatorOrdinal).padStart(3, "0")}`,
    obligation_id: obligationId,
    obligation_target: obligationTarget,
    locator_ordinal: locatorOrdinal,
    locator: resolvedLocator.locator,
    owner_path: resolvedLocator.owner_path,
    owner_kind: resolvedLocator.owner_kind,
    fragment_kind: resolvedLocator.fragment_kind,
    fragment: resolvedLocator.fragment,
    heading_level: resolvedLocator.heading_level ?? null,
    heading_text: resolvedLocator.heading_text ?? null,
  };
  return {
    ...identity,
    mapping_identity_sha256: sha256(stableJson(identity)),
    owner_sha256: resolvedLocator.owner_sha256,
    fragment_sha256: resolvedLocator.fragment_sha256,
  };
}

export function reviewedLocatorSetDigests(entries) {
  return {
    mapping_identity_set_sha256: sha256(
      stableJson(entries.map((entry) => mappingIdentity(entry))),
    ),
    locator_digest_set_sha256: sha256(
      stableJson(entries.map((entry) => reviewedDigestIdentity(entry))),
    ),
  };
}

function entryShapeErrors(entry, at) {
  const errors = [];
  const stringFields = [
    "mapping_id",
    "obligation_id",
    "obligation_target",
    "locator",
    "owner_path",
    "owner_kind",
    "fragment_kind",
    "fragment",
    "mapping_identity_sha256",
    "owner_sha256",
    "fragment_sha256",
  ];
  for (const field of stringFields) {
    if (typeof entry?.[field] !== "string" || entry[field].length === 0) {
      errors.push(`${at}.${field} must be a nonempty string`);
    }
  }
  if (!MAPPING_ID_PATTERN.test(entry?.mapping_id ?? "")) {
    errors.push(`${at}.mapping_id has an invalid form`);
  }
  if (!/^AZ-[0-9]{2}$/u.test(entry?.obligation_id ?? "")) {
    errors.push(`${at}.obligation_id has an invalid form`);
  }
  if (!Number.isInteger(entry?.locator_ordinal) || entry.locator_ordinal < 1) {
    errors.push(`${at}.locator_ordinal must be a positive integer`);
  }
  if (
    entry?.mapping_id !==
    `${entry?.obligation_id}:LOC-${String(entry?.locator_ordinal).padStart(3, "0")}`
  ) {
    errors.push(`${at}.mapping_id does not bind its obligation and ordinal`);
  }
  for (const field of [
    "mapping_identity_sha256",
    "owner_sha256",
    "fragment_sha256",
  ]) {
    if (!HASH_PATTERN.test(entry?.[field] ?? "")) {
      errors.push(`${at}.${field} must be a lowercase SHA-256`);
    }
  }
  if (
    entry?.heading_level !== null &&
    (!Number.isInteger(entry?.heading_level) || entry.heading_level < 1 || entry.heading_level > 6)
  ) {
    errors.push(`${at}.heading_level must be null or an integer from 1 through 6`);
  }
  if (entry?.heading_text !== null && typeof entry?.heading_text !== "string") {
    errors.push(`${at}.heading_text must be null or a string`);
  }
  return errors;
}

function compareField(errors, mappingId, field, reviewed, current) {
  if (reviewed[field] !== current[field]) {
    errors.push(
      `${mappingId}: reviewed ${field} ${JSON.stringify(reviewed[field])} differs from current ${JSON.stringify(current[field])}; a separate review transaction must publish and select a new dated ledger`,
    );
  }
}

function validateExactReviewedSet({
  errors,
  label,
  keyField,
  reviewedEntries,
  currentEntries,
  declaredSetSha256,
  digest,
}) {
  if (!Array.isArray(reviewedEntries)) {
    errors.push(`${label} reviewed entries must be an array`);
    return;
  }
  if (!Array.isArray(currentEntries)) {
    errors.push(`${label} current entries must be an array`);
    return;
  }
  const computedDigest = digest(reviewedEntries);
  if (declaredSetSha256 !== computedDigest) {
    errors.push(`${label} declared set SHA-256 does not bind its reviewed entries`);
  }
  const reviewedByKey = new Map();
  for (const entry of reviewedEntries) {
    const key = entry?.[keyField];
    if (typeof key !== "string" || key.length === 0) {
      errors.push(`${label} reviewed entry lacks ${keyField}`);
      continue;
    }
    if (reviewedByKey.has(key)) {
      errors.push(`${label} has duplicate reviewed ${keyField} ${key}`);
    } else {
      reviewedByKey.set(key, entry);
    }
  }
  const currentByKey = new Map();
  for (const entry of currentEntries) {
    const key = entry?.[keyField];
    if (typeof key !== "string" || key.length === 0) {
      errors.push(`${label} current entry lacks ${keyField}`);
      continue;
    }
    if (currentByKey.has(key)) {
      errors.push(`${label} has duplicate current ${keyField} ${key}`);
      continue;
    }
    currentByKey.set(key, entry);
    const reviewed = reviewedByKey.get(key);
    if (!reviewed) {
      errors.push(`${label} ${key} is unreviewed`);
    } else if (stableJson(reviewed) !== stableJson(entry)) {
      errors.push(
        `${label} ${key} changed from its reviewed identity/digest; a separate review transaction must publish and select a new dated ledger`,
      );
    }
  }
  for (const key of reviewedByKey.keys()) {
    if (!currentByKey.has(key)) {
      errors.push(`${label} reviewed ${key} is missing from the current input set`);
    }
  }
}

export function validateArchitectureCoverageReviewLedger({
  ledger,
  currentEntries,
  currentAssignments,
  currentAcceptedAdrs,
  currentPlanningInputs,
  currentOwnerSubjectSetSha256,
  expectedObligationCount,
  expectedLocatorCount,
  expectedAcceptedAdrCount,
  expectedPlanningInputCount,
}) {
  const errors = [];
  if (ledger?.schema_version !== ARCHITECTURE_COVERAGE_REVIEW_LEDGER_SCHEMA) {
    errors.push(`unknown review-ledger schema ${ledger?.schema_version ?? "missing"}`);
  }
  if (ledger?.document_class !== "architecture_coverage_review_ledger") {
    errors.push("review ledger has an invalid document_class");
  }
  if (ledger?.generated !== false) {
    errors.push("review ledger must declare generated=false");
  }
  for (const field of [
    "architecture_authority",
    "implementation_status_authority",
    "sequencer_authority",
    "product_authority",
  ]) {
    if (ledger?.[field] !== false) {
      errors.push(`review ledger must declare ${field}=false`);
    }
  }
  if (ledger?.review_transaction?.automatic_update_permitted !== false) {
    errors.push("review ledger must prohibit automatic updates");
  }
  if (
    typeof ledger?.review_transaction?.review_transaction_id !== "string" ||
    ledger.review_transaction.review_transaction_id.length === 0
  ) {
    errors.push("review ledger lacks a review_transaction_id");
  }
  if (!/^20[0-9]{2}-[0-9]{2}-[0-9]{2}$/u.test(ledger?.review_transaction?.reviewed_at ?? "")) {
    errors.push("review ledger reviewed_at must be an ISO calendar date");
  }
  if (
    typeof ledger?.review_transaction?.update_rule !== "string" ||
    ledger.review_transaction.update_rule.length === 0
  ) {
    errors.push("review ledger lacks an explicit update rule");
  }
  if (ledger?.expected_counts?.obligation_count !== expectedObligationCount) {
    errors.push(
      `review ledger obligation count is ${ledger?.expected_counts?.obligation_count ?? "missing"}; expected ${expectedObligationCount}`,
    );
  }
  if (ledger?.expected_counts?.locator_occurrence_count !== expectedLocatorCount) {
    errors.push(
      `review ledger locator count is ${ledger?.expected_counts?.locator_occurrence_count ?? "missing"}; expected ${expectedLocatorCount}`,
    );
  }
  if (
    ledger?.expected_counts?.assignment_count !== expectedObligationCount
  ) {
    errors.push(
      `review ledger assignment count is ${ledger?.expected_counts?.assignment_count ?? "missing"}; expected ${expectedObligationCount}`,
    );
  }
  if (
    ledger?.expected_counts?.accepted_adr_count !== expectedAcceptedAdrCount
  ) {
    errors.push(
      `review ledger accepted ADR count is ${ledger?.expected_counts?.accepted_adr_count ?? "missing"}; expected ${expectedAcceptedAdrCount}`,
    );
  }
  if (
    ledger?.expected_counts?.authoritative_planning_input_count !==
    expectedPlanningInputCount
  ) {
    errors.push(
      `review ledger planning-input count is ${ledger?.expected_counts?.authoritative_planning_input_count ?? "missing"}; expected ${expectedPlanningInputCount}`,
    );
  }
  if (
    stableJson(ledger?.work_item_scope_digest_fields) !==
    stableJson(REVIEWED_WORK_ITEM_SCOPE_FIELDS)
  ) {
    errors.push("review ledger work-item scope digest fields do not match the checker contract");
  }
  if (!HASH_PATTERN.test(ledger?.reviewed_owner_subject_set_sha256 ?? "")) {
    errors.push("review ledger lacks a reviewed owner-subject-set SHA-256");
  } else if (
    ledger.reviewed_owner_subject_set_sha256 !== currentOwnerSubjectSetSha256
  ) {
    errors.push(
      `source-of-truth owner-subject registry changed: reviewed ${ledger.reviewed_owner_subject_set_sha256}, current ${currentOwnerSubjectSetSha256}; every changed subject must be classified in a separate review transaction`,
    );
  }

  const reviewedEntries = Array.isArray(ledger?.reviewed_locators)
    ? ledger.reviewed_locators
    : [];
  if (!Array.isArray(ledger?.reviewed_locators)) {
    errors.push("review ledger reviewed_locators must be an array");
  }
  if (reviewedEntries.length !== expectedLocatorCount) {
    errors.push(
      `review ledger contains ${reviewedEntries.length} locator occurrences; expected ${expectedLocatorCount}`,
    );
  }
  if (!Array.isArray(currentEntries)) {
    errors.push("current locator review entries must be an array");
    return errors;
  }
  if (currentEntries.length !== expectedLocatorCount) {
    errors.push(
      `current coverage resolves ${currentEntries.length} locator occurrences; expected ${expectedLocatorCount}`,
    );
  }

  const reviewedById = new Map();
  for (let index = 0; index < reviewedEntries.length; index += 1) {
    const entry = reviewedEntries[index];
    errors.push(...entryShapeErrors(entry, `reviewed_locators[${index}]`));
    if (reviewedById.has(entry?.mapping_id)) {
      errors.push(`duplicate reviewed mapping identity ${entry?.mapping_id ?? "missing"}`);
    } else {
      reviewedById.set(entry?.mapping_id, entry);
    }
    const expectedIdentityDigest = sha256(stableJson(mappingIdentity(entry ?? {})));
    if (entry?.mapping_identity_sha256 !== expectedIdentityDigest) {
      errors.push(
        `${entry?.mapping_id ?? `reviewed_locators[${index}]`}: mapping_identity_sha256 does not bind the declared mapping identity`,
      );
    }
  }

  const reviewedSetDigests = reviewedLocatorSetDigests(reviewedEntries);
  if (
    ledger?.reviewed_mapping_identity_set_sha256 !==
    reviewedSetDigests.mapping_identity_set_sha256
  ) {
    errors.push("reviewed_mapping_identity_set_sha256 does not bind reviewed_locators");
  }
  if (
    ledger?.reviewed_locator_digest_set_sha256 !==
    reviewedSetDigests.locator_digest_set_sha256
  ) {
    errors.push("reviewed_locator_digest_set_sha256 does not bind reviewed_locators");
  }

  const currentById = new Map();
  for (let index = 0; index < currentEntries.length; index += 1) {
    const current = currentEntries[index];
    errors.push(...entryShapeErrors(current, `current_entries[${index}]`));
    if (currentById.has(current?.mapping_id)) {
      errors.push(`duplicate current mapping identity ${current?.mapping_id ?? "missing"}`);
      continue;
    }
    currentById.set(current?.mapping_id, current);
    const reviewed = reviewedById.get(current?.mapping_id);
    if (!reviewed) {
      errors.push(
        `${current?.mapping_id ?? `current_entries[${index}]`}: current locator mapping is unreviewed`,
      );
      continue;
    }
    for (const field of [
      "obligation_id",
      "obligation_target",
      "locator_ordinal",
      "locator",
      "owner_path",
      "owner_kind",
      "fragment_kind",
      "fragment",
      "heading_level",
      "heading_text",
      "mapping_identity_sha256",
      "owner_sha256",
      "fragment_sha256",
    ]) {
      compareField(errors, current.mapping_id, field, reviewed, current);
    }
  }
  for (const mappingId of reviewedById.keys()) {
    if (!currentById.has(mappingId)) {
      errors.push(
        `${mappingId}: reviewed locator mapping is missing from current coverage; a separate review transaction must publish and select a new dated ledger`,
      );
    }
  }

  validateExactReviewedSet({
    errors,
    label: "architecture assignment",
    keyField: "assignment_id",
    reviewedEntries: ledger?.reviewed_assignments,
    currentEntries: currentAssignments,
    declaredSetSha256: ledger?.reviewed_assignment_set_sha256,
    digest: reviewedAssignmentSetSha256,
  });
  if (
    Array.isArray(ledger?.reviewed_assignments) &&
    ledger.reviewed_assignments.length !== expectedObligationCount
  ) {
    errors.push(
      `review ledger contains ${ledger.reviewed_assignments.length} assignments; expected ${expectedObligationCount}`,
    );
  }

  validateExactReviewedSet({
    errors,
    label: "accepted ADR",
    keyField: "path",
    reviewedEntries: ledger?.reviewed_accepted_adrs,
    currentEntries: currentAcceptedAdrs,
    declaredSetSha256: ledger?.reviewed_accepted_adr_set_sha256,
    digest: reviewedAcceptedAdrSetSha256,
  });
  if (
    Array.isArray(ledger?.reviewed_accepted_adrs) &&
    ledger.reviewed_accepted_adrs.length !== expectedAcceptedAdrCount
  ) {
    errors.push(
      `review ledger contains ${ledger.reviewed_accepted_adrs.length} accepted ADRs; expected ${expectedAcceptedAdrCount}`,
    );
  }

  validateExactReviewedSet({
    errors,
    label: "authoritative planning input",
    keyField: "input_id",
    reviewedEntries: ledger?.reviewed_authoritative_planning_inputs,
    currentEntries: currentPlanningInputs,
    declaredSetSha256:
      ledger?.reviewed_authoritative_planning_input_set_sha256,
    digest: reviewedPlanningInputSetSha256,
  });
  if (
    Array.isArray(ledger?.reviewed_authoritative_planning_inputs) &&
    ledger.reviewed_authoritative_planning_inputs.length !==
      expectedPlanningInputCount
  ) {
    errors.push(
      `review ledger contains ${ledger.reviewed_authoritative_planning_inputs.length} authoritative planning inputs; expected ${expectedPlanningInputCount}`,
    );
  }

  return errors;
}
