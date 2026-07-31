#!/usr/bin/env node

// Deterministic private projection of the sole sequencer, work-item status
// records, and retained literal-exit evidence. This tool grants no authority,
// mints no evidence, and cannot close a stage.

import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import {
  checkDeterministic,
  failWith,
  git,
  implementationRoot,
  readJson,
  repoRelative,
  repoRoot,
  sha256,
  sha256File,
  stableJson,
  STATUS_VALUES,
  writeDeterministic,
} from "./lib.mjs";
import {
  contentBoundLiteralEvidence,
  refsContainingArtifactHash,
} from "./content-bound-literal.mjs";

export const PROGRAM_STATE_PATH = path.join(implementationRoot, "program-state.json");
export const GUIDE_PATH = path.join(
  implementationRoot,
  "ioi-target-end-state-master-implementation-guide.md",
);
export const WORK_ITEMS_PATH = path.join(implementationRoot, "work-items");
export const STATUS_PRESERVATION_PATH = path.join(
  implementationRoot,
  "audits/reconciliation/work-item-status-preservation.v1.json",
);
export const STATUS_PRESERVATION_BASELINE_PATH = path.join(
  implementationRoot,
  "_archive/pre-unification-baseline/work-items",
);
export const M0_EXIT_PATH = path.join(
  repoRoot,
  "docs/evidence/m0-program-control/m0-exit-report.json",
);
export const M0_LITERAL_PATH = path.join(implementationRoot, "evidence/m0-exit.v1.txt");

const PROGRAM_FORMAT = "ioi.program.live_state.v1";
const WORK_ITEM_FORMAT = "ioi.program.work_item.v1";
const ONGOING_STATUSES = new Set(["active", "evidence_ready"]);
const ACTIVE_AGGREGATE_CHILD_SELECTIONS = new Set([
  "unconditional_active",
  "conditional_selected",
]);
const INACTIVE_AGGREGATE_CHILD_SELECTIONS = new Set(["conditional_not_selected"]);
const ISO_DATE = /^\d{4}-\d{2}-\d{2}$/u;
const LITERAL_EXIT = /^[A-Z][A-Z0-9_]*_EXIT=0$/u;
const EXPECTED_STAGE_IDS = Array.from({ length: 15 }, (_, index) => `M${index}`);
const STAGE_AGGREGATE = {
  M0: "m0-program-control-selected-profile-exit-proof",
  M1: "m1-selected-profile-exit-proof",
  M2: "m2-selected-profile-exit-proof",
  M3: "m3-direct-path-and-exit-proof",
  M4: "m4-outcome-room-system-spine",
  M5: "m5-selected-profile-exit-proof",
  M6: "m6-product-surface-and-typed-workspaces",
  M7: "m7-semantic-definition-action-plane",
  M8: "m8-model-supply-route-substitution-and-selected-exit",
  M9: "m9-selected-profile-aggregate-exit-and-claim-publication",
  M10: "m10-two-failure-domain-continuity",
  M11: "m11-selected-profile-exit-proof",
  M12: "m12-selected-profile-exit-proof",
  M13: "m13-selected-profile-aggregate-exit",
  M14: "m14-selected-profile-aggregate-exit",
};

function fail(message) {
  throw new Error(message);
}

function oneLineValue(source, key) {
  const pattern = new RegExp(`^${key}=(.*)$`, "gmu");
  const values = [...source.matchAll(pattern)].map((match) => match[1]);
  return values.length === 1 ? values[0] : null;
}

function resolveGitRef(candidates) {
  for (const candidate of candidates) {
    const result = git(["rev-parse", candidate]);
    if (result.status === 0 && /^[0-9a-f]{40}$/u.test(result.stdout.trim())) {
      return { ref: candidate, commit: result.stdout.trim() };
    }
  }
  return { ref: "unresolved", commit: null };
}

export function readGuideStages() {
  const source = fs.readFileSync(GUIDE_PATH, "utf8");
  const stages = [...source.matchAll(/^### (M(?:[0-9]|1[0-4])) — (.+)$/gmu)].map(
    (match) => ({ stage_id: match[1], title: match[2].trim() }),
  );
  const actual = stages.map((stage) => stage.stage_id);
  if (JSON.stringify(actual) !== JSON.stringify(EXPECTED_STAGE_IDS)) {
    fail(
      `${repoRelative(GUIDE_PATH)} must contain exactly one M0-M14 heading in order (got ${actual.join(", ") || "none"})`,
    );
  }
  return stages;
}

export function readWorkItems() {
  const files = fs
    .readdirSync(WORK_ITEMS_PATH, { withFileTypes: true })
    .filter((entry) => entry.isFile() && entry.name.endsWith(".v1.json"))
    .map((entry) => path.join(WORK_ITEMS_PATH, entry.name))
    .sort((left, right) => left.localeCompare(right));
  const seen = new Set();
  const records = files.map((file) => {
    const record = readJson(file);
    if (record.evidence_format !== WORK_ITEM_FORMAT) {
      fail(`${repoRelative(file)} is not an ${WORK_ITEM_FORMAT} record`);
    }
    if (typeof record.work_item_id !== "string" || record.work_item_id.length === 0) {
      fail(`${repoRelative(file)} has no work_item_id`);
    }
    if (seen.has(record.work_item_id)) {
      fail(`duplicate work_item_id ${record.work_item_id}`);
    }
    seen.add(record.work_item_id);
    if (!/^(?:M(?:[0-9]|1[0-4])|FUTURE)$/u.test(record.stage_id ?? "")) {
      fail(`${repoRelative(file)} has invalid stage_id ${record.stage_id}`);
    }
    if (!STATUS_VALUES.has(record.status)) {
      fail(`${repoRelative(file)} has invalid status ${record.status}`);
    }
    if (!ISO_DATE.test(record.last_status_transaction ?? "")) {
      fail(`${repoRelative(file)} has invalid last_status_transaction`);
    }
    return {
      file,
      record,
      record_ref: repoRelative(file),
      record_sha256: sha256File(file),
    };
  });
  return records.sort((left, right) => {
    const stageOrder = (value) => value === "FUTURE" ? 15 : Number(value.slice(1));
    return stageOrder(left.record.stage_id) - stageOrder(right.record.stage_id)
      || left.record.work_item_id.localeCompare(right.record.work_item_id);
  });
}

export function verifyStatusPreservation(records) {
  const ledger = readJson(STATUS_PRESERVATION_PATH);
  if (ledger.schema_version !== "ioi.program.work-item-status-preservation.v1") {
    fail(`${repoRelative(STATUS_PRESERVATION_PATH)} has an unknown schema_version`);
  }
  if (!ISO_DATE.test(ledger.captured_at ?? "")) {
    fail(`${repoRelative(STATUS_PRESERVATION_PATH)} has an invalid captured_at date`);
  }
  if (!Array.isArray(ledger.before) || ledger.before_count !== ledger.before.length) {
    fail(`${repoRelative(STATUS_PRESERVATION_PATH)} has an inconsistent before set`);
  }
  const current = new Map(records.map((entry) => [entry.record.work_item_id, entry]));
  const baseline = new Map();
  const currentComparison = [];
  for (const entry of ledger.before) {
    if (typeof entry.work_item_id !== "string" || entry.work_item_id.length === 0) {
      fail(`${repoRelative(STATUS_PRESERVATION_PATH)} has a baseline entry without work_item_id`);
    }
    if (!STATUS_VALUES.has(entry.status)) {
      fail(`${repoRelative(STATUS_PRESERVATION_PATH)} has invalid historical status for ${entry.work_item_id}`);
    }
    if (!/^[0-9a-f]{64}$/u.test(entry.sha256 ?? "")) {
      fail(`${repoRelative(STATUS_PRESERVATION_PATH)} has invalid historical digest for ${entry.work_item_id}`);
    }
    if (baseline.has(entry.work_item_id)) fail(`status-preservation ledger duplicates ${entry.work_item_id}`);
    const archivedPath = path.join(
      STATUS_PRESERVATION_BASELINE_PATH,
      `${entry.work_item_id}.v1.json`,
    );
    if (!fs.existsSync(archivedPath) || !fs.statSync(archivedPath).isFile()) {
      fail(`historical status audit is missing immutable baseline ${repoRelative(archivedPath)}`);
    }
    const archivedSha256 = sha256File(archivedPath);
    if (archivedSha256 !== entry.sha256) {
      fail(`immutable baseline digest changed for ${entry.work_item_id}: ${entry.sha256} -> ${archivedSha256}`);
    }
    const archived = readJson(archivedPath);
    if (
      archived.evidence_format !== WORK_ITEM_FORMAT
      || archived.work_item_id !== entry.work_item_id
      || archived.status !== entry.status
    ) {
      fail(`immutable baseline identity/status differs for ${entry.work_item_id}`);
    }
    baseline.set(entry.work_item_id, {
      status: entry.status,
      sha256: entry.sha256,
      archived_ref: repoRelative(archivedPath),
    });

    const currentEntry = current.get(entry.work_item_id);
    currentComparison.push({
      work_item_id: entry.work_item_id,
      historical_status: entry.status,
      current_status: currentEntry?.record.status ?? null,
      comparison: currentEntry === undefined
        ? "current_record_absent"
        : currentEntry.record.status === entry.status
          ? "status_unchanged"
          : "status_transition_observed",
      current_record_ref: currentEntry?.record_ref ?? null,
      current_record_sha256: currentEntry?.record_sha256 ?? null,
    });
  }
  const introducedRecords = records.filter(({ record }) => !baseline.has(record.work_item_id));
  const statuses = {};
  for (const { record } of records) statuses[record.status] = (statuses[record.status] ?? 0) + 1;
  const introducedStatuses = {};
  for (const { record } of introducedRecords) {
    introducedStatuses[record.status] = (introducedStatuses[record.status] ?? 0) + 1;
  }
  const transitioned = currentComparison.filter((entry) => entry.comparison === "status_transition_observed");
  const absent = currentComparison.filter((entry) => entry.comparison === "current_record_absent");
  const unchanged = currentComparison.filter((entry) => entry.comparison === "status_unchanged");
  return {
    audit_role: "dated_historical_reconciliation_audit",
    captured_at: ledger.captured_at,
    preservation_ledger: repoRelative(STATUS_PRESERVATION_PATH),
    preservation_ledger_sha256: sha256File(STATUS_PRESERVATION_PATH),
    immutable_archived_baseline_root: repoRelative(STATUS_PRESERVATION_BASELINE_PATH),
    immutable_archived_baseline_count: baseline.size,
    immutable_archived_baseline_set_sha256: sha256(stableJson(ledger.before)),
    immutable_archived_baseline_result: "PASS",
    total_record_count: records.length,
    statuses,
    current_comparison: {
      historical_record_count: currentComparison.length,
      present_count: currentComparison.length - absent.length,
      status_unchanged_count: unchanged.length,
      status_transition_count: transitioned.length,
      absent_count: absent.length,
      introduced_after_audit_count: introducedRecords.length,
      introduced_after_audit_statuses: introducedStatuses,
      historical_statuses_unchanged_now: transitioned.length === 0 && absent.length === 0,
      introduced_records_all_proposed_now: introducedRecords.every(
        ({ record }) => record.status === "proposed",
      ),
      changed_or_absent_records: [...transitioned, ...absent],
      comparison_rows: currentComparison,
    },
    result: "PASS",
    note: "PASS validates the immutable 2026-07-22 reconciliation baseline. The current comparison is observational, not a rule that freezes baseline statuses or requires later records to remain proposed; legitimate transitions remain owned by current work-item records and retained evidence.",
  };
}

export function inspectM0Evidence() {
  const source = fs.readFileSync(M0_LITERAL_PATH, "utf8");
  const literal = oneLineValue(source, "M0_EXIT");
  const bar = oneLineValue(source, "BAR");
  const artifactRef = oneLineValue(source, "ARTIFACT");
  const declaredSha256 = oneLineValue(source, "ARTIFACT_SHA256");
  const expectedArtifactRef = repoRelative(M0_EXIT_PATH);
  const artifactExists = fs.existsSync(M0_EXIT_PATH);
  const checkoutSha256 = artifactExists ? sha256File(M0_EXIT_PATH) : null;
  let artifact = null;
  let artifactParseError = null;
  if (artifactExists) {
    try {
      artifact = readJson(M0_EXIT_PATH);
    } catch (error) {
      artifactParseError = error.message;
    }
  }
  const exactLiteral = bar === "M0" && literal === "0";
  const exactArtifactRef = artifactRef === expectedArtifactRef;
  const exactBinding = /^[0-9a-f]{64}$/u.test(declaredSha256 ?? "")
    && declaredSha256 === checkoutSha256;
  const exactArtifact = artifact?.evidence_format === "ioi.m0.exit_report.v1"
    && artifact?.m0_exit_state === "verified"
    && artifact?.architecture_or_production_capability_closure === false;
  const declaredBindingRefs = exactArtifactRef
    ? refsContainingArtifactHash(expectedArtifactRef, declaredSha256)
    : [];
  let retainedArtifact = null;
  if (declaredBindingRefs.length > 0) {
    const shown = git(["show", `${declaredBindingRefs[0]}:${expectedArtifactRef}`]);
    if (shown.status === 0) {
      try {
        retainedArtifact = JSON.parse(shown.stdout);
      } catch {
        // The exact retained bytes are classified invalid below.
      }
    }
  }
  const exactRetainedArtifact = retainedArtifact?.evidence_format === "ioi.m0.exit_report.v1"
    && retainedArtifact?.m0_exit_state === "verified"
    && retainedArtifact?.architecture_or_production_capability_closure === false;
  const retainedProofVerified = exactLiteral
    && exactArtifactRef
    && declaredBindingRefs.length > 0
    && exactRetainedArtifact;
  const verifiedInCheckout = retainedProofVerified && exactBinding && exactArtifact;
  let result = "FAIL";
  let reasonCode = "retained_exit_evidence_invalid";
  if (verifiedInCheckout) {
    result = "PASS";
    reasonCode = "content_bound_literal_exit_verified";
  } else if (retainedProofVerified && !verifiedInCheckout) {
    result = "SKIP";
    reasonCode = artifactExists
      ? "retained_literal_artifact_hash_mismatch_in_checkout"
      : "retained_literal_artifact_absent_from_checkout";
  }
  return {
    result,
    reason_code: reasonCode,
    literal_ref: repoRelative(M0_LITERAL_PATH),
    literal_observed: literal === null ? null : `M0_EXIT=${literal}`,
    artifact_ref: artifactRef,
    expected_artifact_ref: expectedArtifactRef,
    declared_artifact_sha256: declaredSha256,
    checkout_artifact_sha256: checkoutSha256,
    declared_binding_refs: declaredBindingRefs,
    artifact_parse_error: artifactParseError,
    retained_proof_result: retainedProofVerified ? "PASS" : "FAIL",
    retained_exit_verified: retainedProofVerified,
    retained_exit_verified_in_checkout: verifiedInCheckout,
    note: verifiedInCheckout
      ? "The retained literal exit is content-bound to the artifact in this checkout."
      : retainedProofVerified
        ? "The pre-existing verified state is preserved from an exact content-bound artifact on the named committed refs; validation against this checkout is SKIP and proves no new status."
        : "No stage verification is inferred because no exact content-bound retained artifact could be resolved.",
    artifact,
  };
}

function projectRecord(entry) {
  return {
    work_item_id: entry.record.work_item_id,
    status: entry.record.status,
    applicable_pg_ids: entry.record.applicable_pg_ids ?? [],
    pg_gate_states: entry.record.pg_gate_states ?? [],
    record_ref: entry.record_ref,
    record_sha256: entry.record_sha256,
  };
}

export function evidenceBindingForEntry(entry) {
  const expectedLiteral = entry.record.evidence_index?.literal_exit ?? null;
  const evidenceFiles = [...new Set(entry.record.evidence_refs ?? [])].sort().map((ref) => {
    const absolute = path.join(repoRoot, ref);
    const exists = fs.existsSync(absolute) && fs.statSync(absolute).isFile();
    return {
      path: ref,
      exists,
      sha256: exists ? sha256File(absolute) : null,
      exact_literal_line_count: exists && typeof expectedLiteral === "string"
        ? Number(contentBoundLiteralEvidence(ref, expectedLiteral))
        : 0,
    };
  });
  const body = {
    expected_literal: expectedLiteral,
    evidence_files: evidenceFiles,
    exact_literal_line_count: evidenceFiles.reduce(
      (total, file) => total + file.exact_literal_line_count,
      0,
    ),
  };
  return {
    ...body,
    literal_valid: body.exact_literal_line_count === 1,
    evidence_bundle_sha256: sha256(stableJson(body)),
  };
}

function boundRecordProjection(entry, relation, selectionState = null) {
  return {
    work_item_id: entry.record.work_item_id,
    relation,
    selection_state: selectionState,
    record_sha256: entry.record_sha256,
    status_at_binding: entry.record.status,
    evidence_binding: evidenceBindingForEntry(entry),
  };
}

export function validateAggregateVerificationBinding(entry, recordsById) {
  const aggregate = entry.record;
  const binding = aggregate.aggregate_verification_binding;
  const errors = [];
  if (aggregate.record_role !== "aggregate_exit") {
    return {
      valid: binding === null && (aggregate.aggregate_child_dispositions ?? []).length === 0,
      errors: binding === null && (aggregate.aggregate_child_dispositions ?? []).length === 0
        ? []
        : ["non_aggregate_carries_aggregate_binding"],
    };
  }
  if (!binding || binding.schema_version !== "ioi.program.aggregate-verification-binding.v1") {
    return { valid: false, errors: ["missing_or_unknown_aggregate_binding"] };
  }
  const dispositions = aggregate.aggregate_child_dispositions ?? [];
  const dispositionByChild = new Map(
    dispositions.map((disposition) => [disposition.child_work_item_id, disposition]),
  );
  const expectedChildBindings = [];
  for (const childId of aggregate.aggregate_child_ids ?? []) {
    const child = recordsById.get(childId);
    if (!child) {
      errors.push(`missing_child:${childId}`);
      continue;
    }
    expectedChildBindings.push(boundRecordProjection(
      child,
      "aggregate_child",
      dispositionByChild.get(childId)?.selection_state ?? null,
    ));
  }
  const expectedDependencyBindings = [];
  for (const dependencyId of aggregate.dependency_work_item_ids ?? []) {
    const dependency = recordsById.get(dependencyId);
    if (!dependency) {
      errors.push(`missing_dependency:${dependencyId}`);
      continue;
    }
    expectedDependencyBindings.push(boundRecordProjection(
      dependency,
      "unconditional_dependency",
    ));
  }
  const expectedAggregateEvidenceBinding = evidenceBindingForEntry(entry);
  const expectedPayload = {
    child_dispositions: dispositions,
    child_bindings: expectedChildBindings,
    dependency_bindings: expectedDependencyBindings,
    aggregate_evidence_binding: expectedAggregateEvidenceBinding,
  };
  if (stableJson(binding.child_dispositions) !== stableJson(dispositions)) {
    errors.push("stale_child_dispositions");
  }
  if (stableJson(binding.child_bindings) !== stableJson(expectedChildBindings)) {
    errors.push("stale_child_bindings");
  }
  if (stableJson(binding.dependency_bindings) !== stableJson(expectedDependencyBindings)) {
    errors.push("stale_dependency_bindings");
  }
  if (stableJson(binding.aggregate_evidence_binding) !== stableJson(expectedAggregateEvidenceBinding)) {
    errors.push("stale_aggregate_evidence_binding");
  }
  if (binding.binding_payload_sha256 !== sha256(stableJson(expectedPayload))) {
    errors.push("stale_binding_payload_sha256");
  }
  if (typeof binding.nonclaim !== "string" || !binding.nonclaim.includes("does not promote")) {
    errors.push("missing_non_promotion_nonclaim");
  }
  return { valid: errors.length === 0, errors };
}

export function evaluateContentBoundRecordExit(
  entry,
  { literalEvidence = contentBoundLiteralEvidence } = {},
) {
  const expectedLiteral = entry.record.evidence_index?.literal_exit ?? null;
  const expectedOutputPaths = new Set(entry.record.evidence_index?.expected_output_paths ?? []);
  const successfulRefs = [...new Set(entry.record.evidence_refs ?? [])].filter((ref) => (
    typeof expectedLiteral === "string"
    && LITERAL_EXIT.test(expectedLiteral)
    && expectedOutputPaths.has(ref)
    && literalEvidence(ref, expectedLiteral)
  ));
  return {
    work_item_id: entry.record.work_item_id,
    status: entry.record.status,
    declared_literal_exit: expectedLiteral,
    retained_successful_literal_refs: successfulRefs,
    status_verified: entry.record.status === "verified",
    literal_valid: successfulRefs.length === 1,
    satisfied: entry.record.status === "verified" && successfulRefs.length === 1,
  };
}

function stageRank(stageId) {
  if (stageId === "FUTURE") return 15;
  if (!/^M(?:[0-9]|1[0-4])$/u.test(stageId ?? "")) return null;
  return Number(stageId.slice(1));
}

export function proofGateClosureForStage(
  stageId,
  rows,
  { literalEvidence = contentBoundLiteralEvidence } = {},
) {
  const rank = stageRank(stageId);
  if (rank === null) fail(`cannot evaluate proof gates for invalid stage ${stageId}`);
  const required = rows.filter((row) => {
    const closureRank = stageRank(row.closure_stage_id);
    if (closureRank === null || closureRank > rank) return false;
    return row.applicability === "required_now"
      || (row.applicability === "conditional" && row.profile_selection === "selected");
  }).map((row) => {
    const successfulRefs = [...new Set(row.evidence_refs ?? [])].filter((ref) => (
      LITERAL_EXIT.test(row.literal_exit ?? "")
      && literalEvidence(ref, row.literal_exit)
    ));
    const satisfied = row.closure_status === "closed" && successfulRefs.length === 1;
    return {
      pg_id: row.pg_id,
      closure_owner_work_item_id: row.closure_owner_work_item_id,
      closure_stage_id: row.closure_stage_id,
      applicability: row.applicability,
      profile_selection: row.profile_selection,
      closure_status: row.closure_status,
      literal_exit: row.literal_exit,
      retained_successful_literal_refs: successfulRefs,
      satisfied,
    };
  });
  return {
    required_gate_count: required.length,
    required_gate_ids: required.map((row) => row.pg_id),
    unsatisfied_gate_ids: required.filter((row) => !row.satisfied).map((row) => row.pg_id),
    rows: required,
    satisfied: required.every((row) => row.satisfied),
  };
}

export function evaluateAggregateRecordClosure(
  rootId,
  recordsById,
  { literalEvidence = contentBoundLiteralEvidence } = {},
) {
  const visited = new Set();
  const visiting = new Set();
  const requiredRecordIds = [];
  const inactiveConditionalChildIds = [];
  const unknownSelectionRows = [];
  const missingRecordIds = [];
  const dependencyCycles = [];
  const bindingResults = [];
  const recordExitResults = [];

  const visit = (recordId, trail = []) => {
    if (visiting.has(recordId)) {
      dependencyCycles.push([...trail, recordId].join(" -> "));
      return;
    }
    if (visited.has(recordId)) return;
    const entry = recordsById.get(recordId);
    if (!entry) {
      missingRecordIds.push(recordId);
      return;
    }
    visiting.add(recordId);
    visited.add(recordId);
    requiredRecordIds.push(recordId);
    recordExitResults.push(evaluateContentBoundRecordExit(entry, { literalEvidence }));

    if (entry.record.record_role === "aggregate_exit") {
      bindingResults.push({
        aggregate_work_item_id: recordId,
        ...validateAggregateVerificationBinding(entry, recordsById),
      });
      const dispositions = entry.record.aggregate_child_dispositions ?? [];
      const expectedChildren = entry.record.aggregate_child_ids ?? [];
      if (
        dispositions.length !== expectedChildren.length
        || dispositions.some((row, index) => row.child_work_item_id !== expectedChildren[index])
      ) {
        unknownSelectionRows.push({
          aggregate_work_item_id: recordId,
          child_work_item_id: null,
          selection_state: "disposition_census_mismatch",
        });
      }
      for (const disposition of dispositions) {
        if (ACTIVE_AGGREGATE_CHILD_SELECTIONS.has(disposition.selection_state)) {
          visit(disposition.child_work_item_id, [...trail, recordId]);
        } else if (INACTIVE_AGGREGATE_CHILD_SELECTIONS.has(disposition.selection_state)) {
          inactiveConditionalChildIds.push(disposition.child_work_item_id);
        } else {
          unknownSelectionRows.push({
            aggregate_work_item_id: recordId,
            child_work_item_id: disposition.child_work_item_id,
            selection_state: disposition.selection_state ?? null,
          });
        }
      }
    }
    for (const dependencyId of entry.record.dependency_work_item_ids ?? []) {
      visit(dependencyId, [...trail, recordId]);
    }
    visiting.delete(recordId);
  };
  visit(rootId);

  const nonVerifiedRecordIds = recordExitResults
    .filter((result) => !result.status_verified)
    .map((result) => result.work_item_id);
  const literalInvalidRecordIds = recordExitResults
    .filter((result) => !result.literal_valid)
    .map((result) => result.work_item_id);
  const staleAggregateBindingIds = bindingResults
    .filter((result) => !result.valid)
    .map((result) => result.aggregate_work_item_id);
  return {
    root_work_item_id: rootId,
    required_record_count: requiredRecordIds.length,
    required_record_ids: requiredRecordIds,
    required_child_and_dependency_ids: requiredRecordIds.filter((id) => id !== rootId),
    inactive_conditional_child_ids: [...new Set(inactiveConditionalChildIds)].sort(),
    non_verified_record_ids: nonVerifiedRecordIds,
    literal_invalid_record_ids: literalInvalidRecordIds,
    stale_aggregate_binding_ids: staleAggregateBindingIds,
    aggregate_binding_results: bindingResults,
    record_exit_results: recordExitResults,
    unknown_selection_rows: unknownSelectionRows,
    missing_record_ids: [...new Set(missingRecordIds)].sort(),
    dependency_cycles: dependencyCycles,
    satisfied: nonVerifiedRecordIds.length === 0
      && literalInvalidRecordIds.length === 0
      && staleAggregateBindingIds.length === 0
      && unknownSelectionRows.length === 0
      && missingRecordIds.length === 0
      && dependencyCycles.length === 0,
  };
}

export function currentAggregateExit(
  stageId,
  recordsById,
  proofGateRows,
  { literalEvidence = contentBoundLiteralEvidence } = {},
) {
  const aggregateId = STAGE_AGGREGATE[stageId];
  const entry = recordsById.get(aggregateId);
  if (!entry) fail(`${stageId} is missing current aggregate ${aggregateId}`);
  if (entry.record.record_role !== "aggregate_exit") {
    fail(`${stageId} current aggregate ${aggregateId} is not an aggregate_exit record`);
  }
  const recordClosure = evaluateAggregateRecordClosure(
    aggregateId,
    recordsById,
    { literalEvidence },
  );
  const proofGateClosure = proofGateClosureForStage(
    stageId,
    proofGateRows,
    { literalEvidence },
  );
  const aggregateExit = recordClosure.record_exit_results.find(
    (result) => result.work_item_id === aggregateId,
  );
  const aggregateClosureSatisfied = recordClosure.satisfied && proofGateClosure.satisfied;
  let reasonCode = "current_aggregate_closure_satisfied";
  if (entry.record.status !== "verified") reasonCode = "current_aggregate_not_verified";
  else if (aggregateExit?.literal_valid !== true) reasonCode = "current_aggregate_lacks_exact_content_bound_literal";
  else if (recordClosure.stale_aggregate_binding_ids.length > 0) reasonCode = "current_aggregate_binding_stale";
  else if (recordClosure.non_verified_record_ids.length > 0) reasonCode = "active_child_or_dependency_not_verified";
  else if (recordClosure.literal_invalid_record_ids.length > 0) reasonCode = "active_child_or_dependency_lacks_exact_content_bound_literal";
  else if (!proofGateClosure.satisfied) reasonCode = "required_or_selected_proof_gate_not_closed";
  else if (!recordClosure.satisfied) reasonCode = "current_aggregate_record_closure_invalid";
  return {
    aggregate_work_item_id: aggregateId,
    aggregate_status: entry.record.status,
    aggregate_record_ref: entry.record_ref,
    declared_literal_exit: aggregateExit?.declared_literal_exit ?? null,
    retained_successful_literal_refs: aggregateExit?.retained_successful_literal_refs ?? [],
    aggregate_verification_binding_valid: recordClosure.stale_aggregate_binding_ids.length === 0,
    record_closure: recordClosure,
    proof_gate_closure: proofGateClosure,
    aggregate_closure_satisfied: aggregateClosureSatisfied,
    predecessor_chain_satisfied: null,
    satisfied: false,
    reason_code: reasonCode,
    nonclaim: "An aggregate joins exact current child/dependency/gate evidence but cannot promote any record or manufacture status. Historical proof, a declaration, or a process exit code cannot satisfy this current exit.",
  };
}

function buildProofGateProjection(records) {
  const rows = [];
  const seen = new Set();
  for (const entry of records) {
    for (const gate of entry.record.pg_gate_states ?? []) {
      if (seen.has(gate.pg_id)) fail(`duplicate proof-gate closure owner for ${gate.pg_id}`);
      seen.add(gate.pg_id);
      rows.push({
        pg_id: gate.pg_id,
        closure_owner_work_item_id: entry.record.work_item_id,
        closure_owner_stage_id: entry.record.stage_id,
        applicability: gate.applicability,
        profile_selection: gate.profile_selection,
        closure_stage_id: gate.closure_stage_id,
        closure_status: gate.closure_status,
        evidence_refs: gate.evidence_refs,
        literal_exit: gate.literal_exit,
        status_basis: gate.status_basis,
        ...(gate.scope_review ? { scope_review: gate.scope_review } : {}),
      });
    }
  }
  rows.sort((left, right) => left.pg_id.localeCompare(right.pg_id, undefined, { numeric: true }));
  if (rows.length !== 58) fail(`proof-gate projection requires 58 exact-one closure owners (got ${rows.length})`);
  const m0Census = records.find(({ record }) => record.work_item_id === STAGE_AGGREGATE.M0)?.record.proof_gate_census;
  if (!m0Census || m0Census.role !== "oversight_projection_only_not_closure_authority") fail("M0 aggregate lacks its non-authoritative 58-gate census");
  const expectedCensus = rows.map((row) => ({
    pg_id: row.pg_id,
    closure_owner_work_item_id: row.closure_owner_work_item_id,
    applicability: row.applicability,
    ...(row.scope_review ? { scope_review: row.scope_review } : {}),
  }));
  const actualCensus = [...m0Census.dispositions].sort((left, right) => left.pg_id.localeCompare(right.pg_id, undefined, { numeric: true }));
  if (stableJson(actualCensus) !== stableJson(expectedCensus)) fail("M0 proof-gate oversight census differs from the exact-one owner projection");
  const closureCounts = rows.reduce((counts, row) => {
    counts[row.closure_status] = (counts[row.closure_status] ?? 0) + 1;
    return counts;
  }, {});
  return {
    registry_ref: "internal-docs/implementation/proof-gates/mechanism-gate-registry.md",
    registry_sha256: sha256File(path.join(implementationRoot, "proof-gates/mechanism-gate-registry.md")),
    gate_count: rows.length,
    exact_one_closure_owner_count: rows.length,
    closure_counts: closureCounts,
    m0_oversight_census_role: m0Census.role,
    rows,
    nonclaim: "This projection assigns closure responsibility but closes no gate; aggregates join evidence and own no gate closure.",
  };
}

function deriveAsOfDate(records, m0Evidence, requestedDate) {
  if (requestedDate !== null) {
    if (!ISO_DATE.test(requestedDate)) fail(`--as-of must be YYYY-MM-DD (got ${requestedDate})`);
    return requestedDate;
  }
  const dates = records.map(({ record }) => record.last_status_transaction);
  if (ISO_DATE.test(m0Evidence.artifact?.as_of_date ?? "")) {
    dates.push(m0Evidence.artifact.as_of_date);
  }
  if (dates.length === 0) fail("cannot derive program-state as-of date");
  return dates.sort().at(-1);
}

export function deriveP0Protocol({
  ownerEntry,
  stages,
  recordsById,
  proofGateRows,
  literalEvidence = contentBoundLiteralEvidence,
}) {
  if (ownerEntry?.record.work_item_id !== "m5-p0-readiness-verifier") {
    fail("P0 readiness-verifier owner m5-p0-readiness-verifier is missing");
  }
  if (ownerEntry.record.stage_id !== "M5" || !STATUS_VALUES.has(ownerEntry.record.status)) {
    fail("P0 readiness-verifier owner must be an M5 record with a valid lifecycle status");
  }
  const stageById = new Map(stages.map((stage) => [stage.stage_id, stage]));
  const prerequisiteStages = ["M3", "M4", "M5"].map((stageId) => ({
    stage_id: stageId,
    current_sequencer_exit_satisfied:
      stageById.get(stageId)?.current_sequencer_exit?.satisfied === true,
    aggregate_work_item_id: STAGE_AGGREGATE[stageId],
  }));
  const ownerExit = evaluateContentBoundRecordExit(ownerEntry, { literalEvidence });
  const ownerDependencyClosure = evaluateAggregateRecordClosure(
    ownerEntry.record.work_item_id,
    recordsById,
    { literalEvidence },
  );
  const relevantProofGates = proofGateClosureForStage(
    "M5",
    proofGateRows,
    { literalEvidence },
  );
  const directPathExit = stageById.get("M3")?.current_sequencer_exit ?? null;
  const readinessConditions = {
    owner_status_verified: ownerEntry.record.status === "verified",
    owner_exact_content_bound_literal: ownerExit.literal_valid,
    owner_dependency_closure_satisfied: ownerDependencyClosure.satisfied,
    current_m3_m5_aggregate_chain_satisfied: prerequisiteStages.every(
      (stage) => stage.current_sequencer_exit_satisfied,
    ),
    direct_path_preservation_proved: directPathExit?.satisfied === true
      && directPathExit.aggregate_work_item_id === "m3-direct-path-and-exit-proof"
      && directPathExit.retained_successful_literal_refs.length === 1,
    relevant_proof_gates_closed: relevantProofGates.satisfied,
  };
  const readinessVerified = Object.values(readinessConditions).every(Boolean);
  const lifecycleState = readinessVerified
    ? "readiness_verified"
    : {
      proposed: "planned_not_activated",
      scoped: "scoped_not_activated",
      active: "owner_active_readiness_not_verified",
      evidence_ready: "evidence_ready_awaiting_verification",
      verified: "verification_invalid",
      blocked: "blocked_not_activated",
      superseded: "superseded_not_activated",
      rejected: "rejected_not_activated",
    }[ownerEntry.record.status];
  return {
    state: lifecycleState,
    readiness_verified: readinessVerified,
    owner_work_item_id: ownerEntry.record.work_item_id,
    owner_status: ownerEntry.record.status,
    owner_record_ref: ownerEntry.record_ref,
    owner_literal_exit: ownerExit,
    owner_dependency_closure: ownerDependencyClosure,
    readiness_prerequisite_stages: prerequisiteStages,
    direct_path_preservation_required: true,
    relevant_proof_gate_closure: relevantProofGates,
    readiness_conditions: readinessConditions,
    claim_gate_stage_id: "M9",
    note: readinessVerified
      ? "Readiness is projected from the verified owner record plus exact current M3-M5, direct-path, dependency, literal, and proof-gate evidence; this projection emits no activation or exit artifact."
      : "P0 is not readiness-verified. Owner lifecycle progress alone cannot substitute for current M3-M5 aggregates, direct-path preservation, exact owner evidence, dependencies, or required proof-gate closure.",
  };
}

export function buildProgramState({ asOf = null } = {}) {
  const guideStages = readGuideStages();
  const records = readWorkItems();
  const statusIntegrity = verifyStatusPreservation(records);
  const m0Evidence = inspectM0Evidence();
  const recordsById = new Map(records.map((entry) => [entry.record.work_item_id, entry]));
  const proofGateProjection = buildProofGateProjection(records);
  const checkout = resolveGitRef(["HEAD"]);
  const master = resolveGitRef(["origin/master", "master"]);
  const current = records.filter(({ record }) => ONGOING_STATUSES.has(record.status));
  const p0Owner = records.find(({ record }) => record.work_item_id === "m5-p0-readiness-verifier");
  if (p0Owner === undefined) fail("P0 readiness-verifier owner m5-p0-readiness-verifier is missing");
  if (p0Owner.record.stage_id !== "M5" || !STATUS_VALUES.has(p0Owner.record.status)) {
    fail("P0 readiness-verifier owner must remain an M5 record with a valid lifecycle status");
  }

  const stages = guideStages.map(({ stage_id: stageId, title }) => {
    const stageRecords = records.filter(({ record }) => record.stage_id === stageId);
    return {
      stage_id: stageId,
      title,
      state: "pending",
      state_scope: "current_sequencer_projection",
      status_basis: {
        kind: "no_verified_stage_exit",
        note: "Work-item status and successful task exit codes do not verify a stage.",
      },
      current_sequencer_exit: currentAggregateExit(
        stageId,
        recordsById,
        proofGateProjection.rows,
      ),
      work_item_refs: stageRecords.map(projectRecord),
    };
  });
  for (const [index, stage] of stages.entries()) {
    const predecessorSatisfied = index === 0
      || stages[index - 1]?.current_sequencer_exit?.satisfied === true;
    stage.current_sequencer_exit.predecessor_chain_satisfied = predecessorSatisfied;
    stage.current_sequencer_exit.satisfied =
      stage.current_sequencer_exit.aggregate_closure_satisfied === true
      && predecessorSatisfied;
    if (
      stage.current_sequencer_exit.aggregate_closure_satisfied === true
      && !predecessorSatisfied
    ) {
      stage.current_sequencer_exit.reason_code = "predecessor_current_aggregate_chain_not_satisfied";
    } else if (stage.current_sequencer_exit.satisfied) {
      stage.current_sequencer_exit.reason_code =
        "current_aggregate_and_predecessor_chain_satisfied";
    }
    stage.sequencer_admission = index === 0
      ? "program_control_stage_not_downstream_admission"
      : predecessorSatisfied
        ? "predecessor_current_aggregate_satisfied"
        : "predecessor_current_aggregate_not_verified";

    const stageRecords = records.filter(({ record }) => record.stage_id === stage.stage_id);
    const currentRecords = stageRecords.filter(({ record }) => ONGOING_STATUSES.has(record.status));
    if (stage.current_sequencer_exit.satisfied) {
      stage.state = "verified";
      stage.state_scope = "current_sequencer_projection";
      stage.status_basis = {
        kind: "current_aggregate_content_bound_stage_exit",
        result: "PASS",
        aggregate_work_item_id: stage.current_sequencer_exit.aggregate_work_item_id,
        aggregate_record_ref: stage.current_sequencer_exit.aggregate_record_ref,
        literal_observed: stage.current_sequencer_exit.declared_literal_exit,
        retained_successful_literal_refs:
          stage.current_sequencer_exit.retained_successful_literal_refs,
        note: "The current stage is derived from the verified current aggregate, its exact bound active child/dependency chain, required proof-gate closure, and the predecessor sequencer chain. The projection did not promote a record or emit an exit.",
      };
    } else if (stage.stage_id === "M0" && m0Evidence.retained_exit_verified_in_checkout) {
      stage.state = "verified";
      stage.state_scope = "historical_pre_2026_07_22_scope";
      stage.status_basis = {
        kind: "historical_pre_current_aggregate_content_bound_stage_exit",
        result: "PASS",
        artifact_ref: m0Evidence.expected_artifact_ref,
        literal_ref: m0Evidence.literal_ref,
        literal_observed: m0Evidence.literal_observed,
        artifact_sha256: m0Evidence.checkout_artifact_sha256,
        note: "This retained proof verifies only the pre-2026-07-22 M0 scope. It does not satisfy the amended current M0 aggregate or any newly selected child.",
      };
    } else if (stage.stage_id === "M0" && m0Evidence.retained_exit_verified) {
      stage.state = "verified";
      stage.state_scope = "historical_pre_2026_07_22_scope";
      stage.status_basis = {
        kind: "historical_pre_current_aggregate_retained_stage_exit",
        proof_result: "PASS",
        checkout_validation: "SKIP",
        reason_code: m0Evidence.reason_code,
        artifact_ref: m0Evidence.expected_artifact_ref,
        literal_ref: m0Evidence.literal_ref,
        literal_observed: m0Evidence.literal_observed,
        artifact_sha256: m0Evidence.declared_artifact_sha256,
        committed_artifact_refs: m0Evidence.declared_binding_refs,
        checkout_artifact_sha256: m0Evidence.checkout_artifact_sha256,
        note: `${m0Evidence.note} This retained proof verifies only the pre-2026-07-22 M0 scope and cannot satisfy the amended current M0 aggregate or any newly selected child.`,
      };
    } else if (stage.stage_id === "M0") {
      stage.state = "verification_invalid";
      stage.status_basis = {
        kind: "retained_stage_exit_invalid",
        result: m0Evidence.result,
        reason_code: m0Evidence.reason_code,
        artifact_ref: m0Evidence.expected_artifact_ref,
        literal_ref: m0Evidence.literal_ref,
        declared_artifact_sha256: m0Evidence.declared_artifact_sha256,
        checkout_artifact_sha256: m0Evidence.checkout_artifact_sha256,
        note: m0Evidence.note,
      };
    } else if (currentRecords.length > 0) {
      stage.state = currentRecords.some(({ record }) => record.status === "active")
        ? "active"
        : "evidence_ready";
      stage.status_basis = {
        kind: "current_work_items",
        work_items: currentRecords.map(({ record }) => ({
          work_item_id: record.work_item_id,
          status: record.status,
        })),
        note: "This is cut activity only and is not a stage-exit claim.",
      };
    }
  }

  const p0Protocol = deriveP0Protocol({
    ownerEntry: p0Owner,
    stages,
    recordsById,
    proofGateRows: proofGateProjection.rows,
  });

  const statusInput = records.map(({ record, record_ref, record_sha256 }) => ({
    work_item_id: record.work_item_id,
    stage_id: record.stage_id,
    status: record.status,
    record_ref,
    record_sha256,
  }));
  const guideRelative = repoRelative(GUIDE_PATH);
  const asOfDate = deriveAsOfDate(records, m0Evidence, asOf);
  return {
    evidence_format: PROGRAM_FORMAT,
    projection_role: "derived_private_session_orientation",
    authority: guideRelative,
    status_owners: {
      durable_cut_status: `${repoRelative(WORK_ITEMS_PATH)}/*.v1.json`,
      stage_verification: "content-bound retained stage-exit artifacts and their literal *_EXIT= values",
      projection: repoRelative(PROGRAM_STATE_PATH),
      selected_status_layer: {
        kind: "private_workspace",
        record_count: records.length,
      },
    },
    rule: "This projection is not a second sequencer, grants nothing, changes no status, and emits no exit or stage closure. Work-item records own cut status. Historical proof remains scoped to the obligations it actually bound; it cannot satisfy a later amended aggregate. A current stage projection requires a verified current aggregate, exact content-bound aggregate/active-child/dependency literals, fresh aggregate bindings, required proof-gate closure, and the predecessor chain. Task process exit codes are never evidence. Development-workflow evidence is an unsigned hash chain with honest nonclaims; product authority remains wallet grants, sealed intents, and receipts.",
    generator: {
      path: repoRelative(fileURLToPath(import.meta.url)),
      version: "1",
      write_command: "node internal-docs/implementation/tools/generate-program-state.mjs --write",
      check_command: "node internal-docs/implementation/tools/generate-program-state.mjs --check",
      compatibility_check_command: "node internal-docs/implementation/check-program-state.mjs",
    },
    as_of: {
      date: asOfDate,
      checkout_ref: checkout.ref,
      checkout_commit: checkout.commit,
      master_ref: master.ref,
      master_commit: master.commit,
      guide_sha256: sha256File(GUIDE_PATH),
      status_input_sha256: sha256(stableJson(statusInput)),
      retained_m0_literal_sha256: sha256File(M0_LITERAL_PATH),
      retained_m0_artifact_sha256: m0Evidence.checkout_artifact_sha256,
    },
    status_integrity: statusIntegrity,
    evidence_validation: {
      m0: Object.fromEntries(
        Object.entries(m0Evidence).filter(([key]) => key !== "artifact"),
      ),
    },
    proof_gate_projection: proofGateProjection,
    stages,
    current_cuts: current.map(({ record, record_ref, record_sha256 }) => ({
      work_item_id: record.work_item_id,
      stage_id: record.stage_id,
      status: record.status,
      objective: record.objective,
      record_ref,
      record_sha256,
      pr: record.pr ?? null,
      branch: "private-workspace",
      evidence_refs: record.evidence_refs ?? [],
      applicable_pg_ids: record.applicable_pg_ids ?? [],
      pg_gate_states: record.pg_gate_states ?? [],
      remaining_nonclaims: record.remaining_nonclaims ?? [],
      last_status_transaction: record.last_status_transaction,
    })),
    conditional_future_work_items: records
      .filter(({ record }) => record.stage_id === "FUTURE")
      .map(projectRecord),
    p0_protocol: p0Protocol,
    status_inventory_by_stage: stages.map((stage) => ({
      stage_id: stage.stage_id,
      sequencer_admission: stage.sequencer_admission,
      candidate_record_ids: records
        .filter(({ record }) => record.stage_id === stage.stage_id && ["active", "evidence_ready", "scoped", "proposed"].includes(record.status))
        .map(({ record }) => record.work_item_id),
      nonclaim: "Inventory is not activation, priority, readiness, or permission to bypass predecessor/current-aggregate gates.",
    })),
    session_start_ritual: [
      "Regenerate with node internal-docs/implementation/tools/generate-program-state.mjs --write and validate with node internal-docs/implementation/check-program-state.mjs.",
      "Read current private work-item records and the owning master-guide stage and exit definition.",
      "Treat verified work items as cut evidence only; never infer stage verification without content-bound retained exit evidence.",
      "Keep multi-node, federation, claim-bearing cohort, connected-service, and L1 language gated to their sequencer owners.",
    ],
    nonclaims: [
      "Generation and validation do not change a work-item status, emit a literal exit, or close a stage.",
      "A SKIP is not success, status regression, or permission to bypass the sequencer.",
      "No product authority is derived from workflow hashes, review labels, task exit codes, or this projection.",
    ],
  };
}

export function validateProgramState(state) {
  const errors = [];
  const expected = buildProgramState({ asOf: state?.as_of?.date ?? null });
  const freshness = checkDeterministic(PROGRAM_STATE_PATH, expected);
  if (!freshness.ok) errors.push(freshness.reason);
  if (state?.evidence_format !== PROGRAM_FORMAT) errors.push("unknown program-state evidence_format");
  const m0Stage = (state?.stages ?? []).find((stage) => stage.stage_id === "M0");
  if (
    state?.evidence_validation?.m0?.result === "FAIL"
    && m0Stage?.current_sequencer_exit?.satisfied !== true
  ) {
    errors.push(`M0 retained evidence is invalid: ${state.evidence_validation.m0.reason_code ?? "unknown reason"}`);
  }
  const stageIds = (state?.stages ?? []).map((stage) => stage.stage_id);
  if (JSON.stringify(stageIds) !== JSON.stringify(EXPECTED_STAGE_IDS)) {
    errors.push(`stages must list exactly M0-M14 in order (got ${stageIds.join(", ")})`);
  }
  for (const [index, stage] of (state?.stages ?? []).entries()) {
    const currentExit = stage.current_sequencer_exit ?? {};
    const predecessorSatisfied = index === 0
      || state.stages[index - 1]?.current_sequencer_exit?.satisfied === true;
    if (currentExit.satisfied === true) {
      if (currentExit.aggregate_status !== "verified") {
        errors.push(`${stage.stage_id} current sequencer exit is satisfied without a verified aggregate`);
      }
      if ((currentExit.retained_successful_literal_refs ?? []).length !== 1) {
        errors.push(`${stage.stage_id} current sequencer exit lacks exactly one content-bound aggregate literal`);
      }
      if (currentExit.aggregate_verification_binding_valid !== true) {
        errors.push(`${stage.stage_id} current sequencer exit has a stale aggregate binding`);
      }
      if (currentExit.record_closure?.satisfied !== true) {
        errors.push(`${stage.stage_id} current sequencer exit has an unsatisfied active child/dependency closure`);
      }
      if (currentExit.proof_gate_closure?.satisfied !== true) {
        errors.push(`${stage.stage_id} current sequencer exit has an unsatisfied required proof gate`);
      }
      if (!predecessorSatisfied || currentExit.predecessor_chain_satisfied !== true) {
        errors.push(`${stage.stage_id} current sequencer exit bypasses its predecessor chain`);
      }
      if (
        stage.state !== "verified"
        || stage.state_scope !== "current_sequencer_projection"
        || stage.status_basis?.kind !== "current_aggregate_content_bound_stage_exit"
        || stage.status_basis?.result !== "PASS"
      ) {
        errors.push(`${stage.stage_id} satisfied current exit is not projected as current verified state`);
      }
    } else if (stage.state === "verified") {
      if (
        stage.stage_id !== "M0"
        || currentExit.satisfied === true
        || stage.state_scope !== "historical_pre_2026_07_22_scope"
        || ![
          "historical_pre_current_aggregate_content_bound_stage_exit",
          "historical_pre_current_aggregate_retained_stage_exit",
        ].includes(stage.status_basis?.kind)
        || ![
          stage.status_basis?.result,
          stage.status_basis?.proof_result,
        ].includes("PASS")
      ) {
        errors.push(`${stage.stage_id} is verified without a current full-chain exit or narrower historical M0 proof`);
      }
    }
    if (currentExit.satisfied === true && currentExit.aggregate_closure_satisfied !== true) {
      errors.push(`${stage.stage_id} current sequencer exit is satisfied without aggregate closure`);
    }
    if (currentExit.satisfied === true && !predecessorSatisfied) {
      errors.push(`${stage.stage_id} current sequencer exit is satisfied before its predecessor`);
    }
  }
  const pgRows = state?.proof_gate_projection?.rows ?? [];
  if (state?.proof_gate_projection?.gate_count !== 58 || pgRows.length !== 58) errors.push("proof-gate projection must contain 58 rows");
  if (new Set(pgRows.map((row) => row.pg_id)).size !== pgRows.length) errors.push("proof-gate projection has duplicate closure owners");
  for (const row of pgRows) {
    if (row.closure_status === "closed" && (!LITERAL_EXIT.test(row.literal_exit ?? "") || (row.evidence_refs ?? []).length === 0)) errors.push(`${row.pg_id} is closed without literal/evidence binding`);
    if (row.closure_status !== "closed" && row.literal_exit !== null) errors.push(`${row.pg_id} has a successful literal without closure`);
    if (stageRank(row.closure_stage_id) === null) errors.push(`${row.pg_id} has invalid closure_stage_id`);
  }
  const currentStatuses = (state?.current_cuts ?? []).map((cut) => cut.status);
  if (currentStatuses.some((status) => !ONGOING_STATUSES.has(status))) {
    errors.push("current_cuts contains a non-ongoing work-item status");
  }
  if (
    state?.status_integrity?.result !== "PASS"
    || state?.status_integrity?.immutable_archived_baseline_result !== "PASS"
    || state?.status_integrity?.audit_role !== "dated_historical_reconciliation_audit"
  ) {
    errors.push("historical work-item reconciliation audit did not pass");
  }
  const p0Conditions = Object.values(state?.p0_protocol?.readiness_conditions ?? {});
  const p0Ready = p0Conditions.length === 6 && p0Conditions.every(Boolean);
  if (state?.p0_protocol?.readiness_verified !== p0Ready) {
    errors.push("P0 readiness projection differs from its complete condition chain");
  }
  if (p0Ready && state?.p0_protocol?.state !== "readiness_verified") {
    errors.push("P0 satisfies its full evidence chain but is not projected readiness_verified");
  }
  if (!p0Ready && state?.p0_protocol?.state === "readiness_verified") {
    errors.push("P0 is projected readiness_verified without its full evidence chain");
  }
  if (!STATUS_VALUES.has(state?.p0_protocol?.owner_status)) {
    errors.push("P0 owner has an invalid lifecycle status");
  }
  failWith("program-state check", errors);
  return expected;
}

export function writeProgramState({ asOf = null } = {}) {
  const state = buildProgramState({ asOf });
  writeDeterministic(PROGRAM_STATE_PATH, state);
  return state;
}

export function checkProgramState() {
  let state;
  try {
    state = readJson(PROGRAM_STATE_PATH);
  } catch (error) {
    fail(`cannot read ${repoRelative(PROGRAM_STATE_PATH)}: ${error.message}`);
  }
  return validateProgramState(state);
}

function parseArgs(argv) {
  let mode = null;
  let asOf = null;
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--write" || argument === "--check") {
      if (mode !== null) fail("choose exactly one of --write or --check");
      mode = argument.slice(2);
    } else if (argument === "--as-of") {
      asOf = argv[index + 1] ?? null;
      index += 1;
    } else {
      fail(`unknown argument: ${argument}`);
    }
  }
  if (mode === null) fail("choose exactly one of --write or --check");
  if (asOf !== null && !ISO_DATE.test(asOf)) fail(`--as-of must be YYYY-MM-DD (got ${asOf})`);
  return { mode, asOf };
}

export function runProgramStateCli(argv) {
  const { mode, asOf } = parseArgs(argv);
  if (mode === "write") {
    const state = writeProgramState({ asOf });
    process.stdout.write(
      `program-state projection written: ${state.status_integrity.total_record_count} records, ${state.stages.length} stages, M0 evidence ${state.evidence_validation.m0.result}. The projection emitted no status transaction, literal exit, or stage-close artifact.\n`,
    );
    return;
  }
  const state = checkProgramState();
  process.stdout.write(
    `program-state check passed: ${state.status_integrity.total_record_count} records, ${state.stages.length} stages, M0 evidence ${state.evidence_validation.m0.result}. The projection emitted no status transaction, literal exit, or stage-close artifact.\n`,
  );
}

const isMain = process.argv[1] !== undefined
  && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  try {
    runProgramStateCli(process.argv.slice(2));
  } catch (error) {
    process.stderr.write(`program-state ${process.argv.includes("--write") ? "generation" : "check"} failed: ${error.message}\n`);
    process.exit(1);
  }
}
