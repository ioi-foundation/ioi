#!/usr/bin/env node

import assert from "node:assert/strict";
import fs from "node:fs";
import {
  ARCHITECTURE_COVERAGE_REVIEW_LEDGER_SCHEMA,
  REVIEWED_WORK_ITEM_SCOPE_FIELDS,
  buildReviewedAssignmentEntry,
  buildReviewedLocatorEntry,
  reviewedAcceptedAdrSetSha256,
  reviewedAssignmentSetSha256,
  reviewedLocatorSetDigests,
  reviewedPlanningInputSetSha256,
  validateArchitectureCoverageReviewLedger,
} from "./architecture-coverage-review-ledger.mjs";

const HASH_A = "a".repeat(64);
const HASH_B = "b".repeat(64);
const HASH_C = "c".repeat(64);
const OWNER_SUBJECT_HASH = "d".repeat(64);

function record(overrides = {}) {
  return {
    work_item_id: "m1-example",
    stage_id: "M1",
    record_role: "implementation_cut",
    status: "proposed",
    objective: "Bounded example",
    falsifiable_claim: "The example can fail",
    selected_profile: "sovereign_local",
    canon_owners: ["docs/architecture/example.md"],
    contract_families: [],
    private_artifacts: [],
    dependency_work_item_ids: [],
    aggregate_child_ids: [],
    in_scope: ["example"],
    out_of_scope: ["everything else"],
    consequential_effects_and_final_invokers: [],
    remaining_nonclaims: ["No runtime claim"],
    rollback_or_stop_rule: "Stop on mismatch",
    ...overrides,
  };
}

function locator(overrides = {}) {
  return buildReviewedLocatorEntry({
    obligationId: "AZ-01",
    obligationTarget: "Example obligation",
    locatorOrdinal: 1,
    resolvedLocator: {
      locator: "docs/architecture/example.md#contract",
      owner_path: "docs/architecture/example.md",
      owner_kind: "architecture_canon",
      owner_sha256: HASH_A,
      fragment_kind: "exact_markdown_heading",
      fragment: "contract",
      heading_level: 2,
      heading_text: "Contract",
      fragment_sha256: HASH_B,
      ...overrides,
    },
  });
}

function assignment(exampleRecord = record()) {
  return buildReviewedAssignmentEntry({
    obligation: {
      obligation_id: "AZ-01",
      target: "Example obligation",
    },
    assignment: {
      stage: "M1",
      workItemIds: ["m1-example"],
    },
    records: new Map([["m1-example", exampleRecord]]),
  });
}

function fixture() {
  const currentEntries = [locator()];
  const currentAssignments = [assignment()];
  const currentAcceptedAdrs = [
    {
      path: "docs/decisions/0001-example.md",
      title: "ADR 0001: Example",
      sha256: HASH_C,
      index_disposition: "accepted_decision_control",
      mapped_obligation_ids: ["AZ-01"],
      coverage_disposition: "mapped_accepted_decision_control",
    },
  ];
  const currentPlanningInputs = [
    {
      input_id: "execution_horizons",
      path: "docs/architecture/_meta/execution-horizons.md",
      sha256: HASH_C,
      coverage_disposition:
        "reviewed_stage_horizon_input_not_an_independent_build_target",
    },
  ];
  const locatorDigests = reviewedLocatorSetDigests(currentEntries);
  const ledger = {
    schema_version: ARCHITECTURE_COVERAGE_REVIEW_LEDGER_SCHEMA,
    document_class: "architecture_coverage_review_ledger",
    generated: false,
    architecture_authority: false,
    implementation_status_authority: false,
    sequencer_authority: false,
    product_authority: false,
    review_transaction: {
      review_transaction_id: "fixture-review",
      reviewed_at: "2026-07-23",
      automatic_update_permitted: false,
      update_rule: "A separate review publishes a new dated ledger.",
    },
    expected_counts: {
      obligation_count: 1,
      locator_occurrence_count: 1,
      assignment_count: 1,
      accepted_adr_count: 1,
      authoritative_planning_input_count: 1,
    },
    work_item_scope_digest_fields: REVIEWED_WORK_ITEM_SCOPE_FIELDS,
    reviewed_owner_subject_set_sha256: OWNER_SUBJECT_HASH,
    reviewed_mapping_identity_set_sha256:
      locatorDigests.mapping_identity_set_sha256,
    reviewed_locator_digest_set_sha256:
      locatorDigests.locator_digest_set_sha256,
    reviewed_assignment_set_sha256:
      reviewedAssignmentSetSha256(currentAssignments),
    reviewed_accepted_adr_set_sha256:
      reviewedAcceptedAdrSetSha256(currentAcceptedAdrs),
    reviewed_authoritative_planning_input_set_sha256:
      reviewedPlanningInputSetSha256(currentPlanningInputs),
    reviewed_locators: structuredClone(currentEntries),
    reviewed_assignments: structuredClone(currentAssignments),
    reviewed_accepted_adrs: structuredClone(currentAcceptedAdrs),
    reviewed_authoritative_planning_inputs:
      structuredClone(currentPlanningInputs),
  };
  return {
    ledger,
    currentEntries,
    currentAssignments,
    currentAcceptedAdrs,
    currentPlanningInputs,
    currentOwnerSubjectSetSha256: OWNER_SUBJECT_HASH,
  };
}

function validate(value) {
  return validateArchitectureCoverageReviewLedger({
    ...value,
    expectedObligationCount: 1,
    expectedLocatorCount: 1,
    expectedAcceptedAdrCount: 1,
    expectedPlanningInputCount: 1,
  });
}

function expectFailure(label, mutate, expectedMessage) {
  const value = fixture();
  mutate(value);
  const errors = validate(value);
  assert.ok(
    errors.some((error) => error.includes(expectedMessage)),
    `${label}: expected ${JSON.stringify(expectedMessage)} in ${JSON.stringify(errors)}`,
  );
}

assert.deepEqual(validate(fixture()), []);

expectFailure(
  "owner bytes",
  (value) => {
    value.currentEntries = [locator({ owner_sha256: HASH_C })];
  },
  "owner_sha256",
);
expectFailure(
  "fragment bytes",
  (value) => {
    value.currentEntries = [locator({ fragment_sha256: HASH_C })];
  },
  "fragment_sha256",
);
expectFailure(
  "mapping identity",
  (value) => {
    value.currentEntries = [locator({ fragment: "renamed-contract" })];
  },
  "reviewed fragment",
);
expectFailure(
  "missing locator",
  (value) => {
    value.currentEntries = [];
  },
  "reviewed locator mapping is missing",
);
expectFailure(
  "tampered locator set hash",
  (value) => {
    value.ledger.reviewed_locator_digest_set_sha256 = HASH_A;
  },
  "does not bind reviewed_locators",
);
expectFailure(
  "work-item scope",
  (value) => {
    value.currentAssignments = [assignment(record({ in_scope: ["repurposed"] }))];
  },
  "architecture assignment AZ-01 changed",
);
expectFailure(
  "accepted ADR digest",
  (value) => {
    value.currentAcceptedAdrs[0].sha256 = HASH_A;
  },
  "accepted ADR docs/decisions/0001-example.md changed",
);
expectFailure(
  "planning-input digest",
  (value) => {
    value.currentPlanningInputs[0].sha256 = HASH_A;
  },
  "authoritative planning input execution_horizons changed",
);
expectFailure(
  "owner-subject set",
  (value) => {
    value.currentOwnerSubjectSetSha256 = HASH_A;
  },
  "owner-subject registry changed",
);
expectFailure(
  "automatic review mutation",
  (value) => {
    value.ledger.review_transaction.automatic_update_permitted = true;
  },
  "prohibit automatic updates",
);

assert.deepEqual(
  assignment(record({ status: "proposed" })),
  assignment(record({ status: "verified" })),
  "work-item status must not participate in reviewed assignment scope",
);

const generatorSource = fs.readFileSync(
  new URL("./generate-architecture-coverage.mjs", import.meta.url),
  "utf8",
);
const buildBeforeModeBranch = generatorSource.indexOf(
  "const projection = buildProjection();",
);
const modeBranch = generatorSource.indexOf('if (modes[0] === "--write")');
assert.ok(
  buildBeforeModeBranch >= 0 && modeBranch > buildBeforeModeBranch,
  "both --write and --check must build and validate before their mode branch",
);
assert.doesNotMatch(
  generatorSource,
  /writeDeterministic\(reviewLedgerPath/u,
  "the projection writer must never update the non-generated review ledger",
);
assert.doesNotMatch(
  generatorSource,
  /\brecord\.status\b/u,
  "architecture coverage must not inspect mapped work-item status",
);

process.stdout.write(
  "architecture-coverage review-ledger tests passed: owner, fragment, mapping, scope, ADR, planning-input, owner-subject, and non-generated update controls fail closed in both modes; status is excluded from assignment identity and generator admission\n",
);
