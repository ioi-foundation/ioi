#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import {
  failWith,
  implementationRelative,
  implementationRoot,
  listTreeFiles,
  readJson,
  sha256,
  sha256File,
  stableJson,
  writeDeterministic,
} from "./lib.mjs";

const args = process.argv.slice(2);
const mode = args[0] ?? "--check";
if (!new Set(["--check", "--write-successor-v2"]).has(mode)) {
  process.stderr.write("usage: check-source-dispositions.mjs [--check|--write-successor-v2 --report-sha256 SHA256 --review-sha256 SHA256]\n");
  process.exit(2);
}

const registryPath = path.join(implementationRoot, "source-dispositions.v1.json");
const errors = [];
const SEALED_ROOT_SOURCE_REGISTRY_SHA256 = "c1c5b333aeeb7e99b2d874897a8bd7c7d9abf2a05ce26ae609c0c9ec4b2c6b02";

const SUCCESSOR_V2_TRANSACTION_ID = "phase6-verifier-correction-successor-2026-07-23";
const SUCCESSOR_V2_REVIEW_INPUTS = Object.freeze({
  correction_report: Object.freeze({
    path: "audits/reconciliation/2026-07-23-phase6-verifier-correction-report.md",
    digest_flag: "--report-sha256",
  }),
  delegated_review: Object.freeze({
    path: "audits/reconciliation/2026-07-23-phase6-verifier-correction-review.md",
    digest_flag: "--review-sha256",
  }),
});
const SUCCESSOR_V2_APPROVAL_SNAPSHOT_PATH = "audits/reconciliation/source-disposition-approvals/approved-source-dispositions.v2.json";
const SUCCESSOR_V2_APPROVAL_ATTESTATION_PATH = "audits/reconciliation/source-disposition-approvals/approval-attestation.v2.json";
const SUCCESSOR_V2_POST_SNAPSHOT_PATH = "audits/reconciliation/source-manifests/post-migration-successor.v2.source-manifest.v1.json";
const SUCCESSOR_V2_POST_ATTESTATION_PATH = "audits/reconciliation/source-manifests/post-migration-successor-snapshot.attestation.v2.json";
const SUCCESSOR_V2_ROWS = Object.freeze([
  Object.freeze({
    path: SUCCESSOR_V2_REVIEW_INPUTS.correction_report.path,
    document_class: "audit",
    disposition: "KEEP_WORK_RECORD",
    owner: "private implementation estate",
    source_path: null,
    destination_path: SUCCESSOR_V2_REVIEW_INPUTS.correction_report.path,
    tombstone_required: false,
    approving_amendment: "goal-reconciliation-audit",
    schedules_work: false,
    carries_status: false,
  }),
  Object.freeze({
    path: SUCCESSOR_V2_REVIEW_INPUTS.delegated_review.path,
    document_class: "audit",
    disposition: "KEEP_WORK_RECORD",
    owner: "private implementation estate",
    source_path: null,
    destination_path: SUCCESSOR_V2_REVIEW_INPUTS.delegated_review.path,
    tombstone_required: false,
    approving_amendment: "goal-reconciliation-audit",
    schedules_work: false,
    carries_status: false,
  }),
  Object.freeze({
    path: SUCCESSOR_V2_APPROVAL_SNAPSHOT_PATH,
    document_class: "audit",
    disposition: "KEEP_WORK_RECORD",
    owner: "private implementation estate",
    source_path: null,
    destination_path: SUCCESSOR_V2_APPROVAL_SNAPSHOT_PATH,
    tombstone_required: false,
    approving_amendment: "goal-reconciliation-audit",
    schedules_work: false,
    carries_status: false,
  }),
  Object.freeze({
    path: SUCCESSOR_V2_APPROVAL_ATTESTATION_PATH,
    document_class: "audit",
    disposition: "KEEP_WORK_RECORD",
    owner: "private implementation estate",
    source_path: null,
    destination_path: SUCCESSOR_V2_APPROVAL_ATTESTATION_PATH,
    tombstone_required: false,
    approving_amendment: "goal-reconciliation-audit",
    schedules_work: false,
    carries_status: false,
  }),
  Object.freeze({
    path: SUCCESSOR_V2_POST_SNAPSHOT_PATH,
    document_class: "audit",
    disposition: "KEEP_WORK_RECORD",
    owner: "private implementation estate",
    source_path: null,
    destination_path: SUCCESSOR_V2_POST_SNAPSHOT_PATH,
    tombstone_required: false,
    approving_amendment: "goal-phase-6-projections",
    schedules_work: false,
    carries_status: false,
  }),
  Object.freeze({
    path: SUCCESSOR_V2_POST_ATTESTATION_PATH,
    document_class: "audit",
    disposition: "KEEP_WORK_RECORD",
    owner: "private implementation estate",
    source_path: null,
    destination_path: SUCCESSOR_V2_POST_ATTESTATION_PATH,
    tombstone_required: false,
    approving_amendment: "goal-phase-6-projections",
    schedules_work: false,
    carries_status: false,
  }),
]);

// This is the independent selection oracle. A future reviewed update appends a
// new immutable snapshot + attestation pair and a new hard-coded entry here. It
// must not replace an earlier pair. The checker derives and verifies the exact
// row delta and predecessor identity for every successor.
const SEALED_APPROVAL_CHAIN = Object.freeze([
  Object.freeze({
    revision: 1,
    snapshot_path: "audits/reconciliation/source-disposition-approvals/approved-source-dispositions.v1.json",
    snapshot_sha256: "e1aa9149495c0d943d852265991df106ef89f2332e6d79c4954552f58a5c0cec",
    attestation_path: "audits/reconciliation/source-disposition-approvals/approval-attestation.v1.json",
    attestation_sha256: "16a1dc1ddc4a7f53ac3d4f8059093fb72dae596e6452bc066082b82579b29870",
    complete_current_disposition_rows_sha256: "c342c46e0494f3ebd1dc197fe68cec5f3137fcc4b99c8bc11a698ca3ee7455eb",
    approved_disposition_decisions_sha256: "9494c9b55e1426a7dc869f7a327810cf10bfa42f104d31454ef16d06fcd2dea2",
  }),
  Object.freeze({
    revision: 2,
    snapshot_path: "audits/reconciliation/source-disposition-approvals/approved-source-dispositions.v2.json",
    snapshot_sha256: "48837874bd364358d2c7e5c0816c0ab9c40981049cbbbcd1b5a0af889436341f",
    attestation_path: "audits/reconciliation/source-disposition-approvals/approval-attestation.v2.json",
    attestation_sha256: "3063200984e8917a6391ab7d7e96f53b358be3bbcdd2b04bc47e1fc314d322e2",
    complete_current_disposition_rows_sha256: "72de4f9d7464e1bf9ddeb27d42cb0b06724a3aed1c2b8b20b0bf6d2ef9f8119a",
    approved_disposition_decisions_sha256: "9494c9b55e1426a7dc869f7a327810cf10bfa42f104d31454ef16d06fcd2dea2",
  }),
]);

const allowedClasses = new Set([
  "sequencer", "source_registry", "module", "work_item", "projection",
  "evidence", "audit", "archive", "pointer", "tool", "navigation",
  "work_record", "archive_source",
]);
const allowedDispositions = new Set([
  "KEEP_AUTHORITY", "KEEP_PROJECTION", "KEEP_WORK_RECORD",
  "EXTRACT_MODULE_DETAIL", "COLLAPSE_TO_POINTER", "ARCHIVE_AFTER_APPROVAL",
  "RENAME_OR_REHOME_AFTER_APPROVAL", "GENERATED",
]);
const currentRowKeys = Object.freeze([
  "path",
  "document_class",
  "disposition",
  "owner",
  "source_path",
  "destination_path",
  "tombstone_required",
  "approving_amendment",
  "schedules_work",
  "carries_status",
]);
const sourceRowKeys = Object.freeze([
  "source_path",
  "baseline_sha256",
  "document_class",
  "disposition",
  "owner",
  "destination_path",
  "tombstone_required",
  "approving_amendment",
  "compatibility_hold",
  "delete_permitted",
  "preserved_body_path",
]);
const expectedRegistryKeys = Object.freeze([
  "schema_version",
  "document_class",
  "status_fields_permitted",
  "owns",
  "does_not_own",
  "approved_amendments",
  "baseline",
  "sources",
  "current_paths",
  "approved_disposition_decisions",
  "migration_finalized",
  "finalized_current_path_set_sha256",
  "finalized_current_disposition_rows_sha256",
  "source_disposition_approval_chain",
]);

function sameKeys(value, expected) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  return stableJson(Object.keys(value).sort()) === stableJson([...expected].sort());
}

function canonicalDecisions(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  return Object.fromEntries(Object.entries(value).sort(([left], [right]) => left.localeCompare(right)));
}

function canonicalCurrentRows(rows, label) {
  if (!Array.isArray(rows)) {
    errors.push(`${label} must be an array`);
    return [];
  }
  const normalized = [];
  for (const [index, row] of rows.entries()) {
    if (!sameKeys(row, currentRowKeys)) {
      errors.push(`${label}[${index}] must contain exactly the complete current-disposition row fields`);
      continue;
    }
    normalized.push(Object.fromEntries(currentRowKeys.map((key) => [key, row[key]])));
  }
  return normalized.sort((left, right) => String(left.path).localeCompare(String(right.path)));
}

function approvalChainIdentity(entry) {
  return {
    revision: entry.revision,
    snapshot_path: entry.snapshot_path,
    snapshot_sha256: entry.snapshot_sha256,
    attestation_path: entry.attestation_path,
    attestation_sha256: entry.attestation_sha256,
    complete_current_disposition_rows_sha256: entry.complete_current_disposition_rows_sha256,
    approved_disposition_decisions_sha256: entry.approved_disposition_decisions_sha256,
  };
}

function predecessorIdentity(entry) {
  if (!entry) return null;
  return approvalChainIdentity(entry);
}

function derivedChangeSet(previousRows, currentRows) {
  const previous = new Map(previousRows.map((row) => [row.path, row]));
  const current = new Map(currentRows.map((row) => [row.path, row]));
  const addedPaths = [...current.keys()].filter((entryPath) => !previous.has(entryPath)).sort();
  const removedPaths = [...previous.keys()].filter((entryPath) => !current.has(entryPath)).sort();
  const changedPaths = [...current.keys()].filter((entryPath) => (
    previous.has(entryPath)
      && stableJson(previous.get(entryPath)) !== stableJson(current.get(entryPath))
  )).sort();
  return {
    kind: "reviewed_append_only_successor",
    added_paths: addedPaths,
    removed_paths: removedPaths,
    changed_paths: changedPaths,
  };
}

function optionDigest(flag) {
  const index = args.indexOf(flag);
  const value = index >= 0 ? args[index + 1] : null;
  if (!/^[a-f0-9]{64}$/u.test(value ?? "")) {
    errors.push(`${flag} must be followed by the exact lowercase SHA-256 of the final reviewed file`);
    return null;
  }
  return value;
}

function reviewedInputsFromFiles({ requireFlags = false } = {}) {
  const reviewedInputs = {};
  for (const [name, specification] of Object.entries(SUCCESSOR_V2_REVIEW_INPUTS)) {
    const absolute = path.join(implementationRoot, specification.path);
    if (!fs.existsSync(absolute) || !fs.lstatSync(absolute).isFile()) {
      errors.push(`successor-v2 reviewed input is missing or not a regular file: ${specification.path}`);
      continue;
    }
    const actualSha256 = sha256File(absolute);
    if (requireFlags) {
      const selectedSha256 = optionDigest(specification.digest_flag);
      if (selectedSha256 && selectedSha256 !== actualSha256) {
        errors.push(`${specification.digest_flag} does not match ${specification.path}; expected ${actualSha256}`);
      }
    }
    reviewedInputs[name] = {
      path: specification.path,
      sha256: actualSha256,
    };
  }
  return reviewedInputs;
}

function readJsonChecked(absolute, label) {
  try {
    return readJson(absolute);
  } catch (error) {
    errors.push(`${label} is not valid JSON: ${error.message}`);
    return null;
  }
}

function validateSealedApprovalChain() {
  if (SEALED_APPROVAL_CHAIN.length === 0) {
    errors.push("checker has no independently sealed source-disposition approval chain");
    return null;
  }
  const seenSnapshots = new Set();
  const seenAttestations = new Set();
  let previous = null;
  let previousRows = [];
  let latest = null;

  for (const [index, sealed] of SEALED_APPROVAL_CHAIN.entries()) {
    const expectedRevision = index + 1;
    if (sealed.revision !== expectedRevision) errors.push(`approval-chain revision ${sealed.revision} must be ${expectedRevision}`);
    for (const [field, value] of Object.entries(sealed)) {
      if (field.endsWith("sha256") && !/^[a-f0-9]{64}$/u.test(value)) {
        errors.push(`approval-chain revision ${sealed.revision} has an unsealed ${field}`);
      }
    }
    if (seenSnapshots.has(sealed.snapshot_path)) errors.push(`approval-chain snapshot is reused in place: ${sealed.snapshot_path}`);
    if (seenAttestations.has(sealed.attestation_path)) errors.push(`approval-chain attestation is reused in place: ${sealed.attestation_path}`);
    seenSnapshots.add(sealed.snapshot_path);
    seenAttestations.add(sealed.attestation_path);

    const snapshotAbsolute = path.join(implementationRoot, sealed.snapshot_path);
    const attestationAbsolute = path.join(implementationRoot, sealed.attestation_path);
    if (!fs.existsSync(snapshotAbsolute)) errors.push(`sealed approval snapshot is missing: ${sealed.snapshot_path}`);
    if (!fs.existsSync(attestationAbsolute)) errors.push(`sealed approval attestation is missing: ${sealed.attestation_path}`);
    if (!fs.existsSync(snapshotAbsolute) || !fs.existsSync(attestationAbsolute)) {
      previous = sealed;
      previousRows = [];
      continue;
    }

    const snapshotFileSha256 = sha256File(snapshotAbsolute);
    const attestationFileSha256 = sha256File(attestationAbsolute);
    if (snapshotFileSha256 !== sealed.snapshot_sha256) errors.push(`approval snapshot ${sealed.snapshot_path} differs from checker-pinned SHA-256 ${sealed.snapshot_sha256}; found ${snapshotFileSha256}`);
    if (attestationFileSha256 !== sealed.attestation_sha256) errors.push(`approval attestation ${sealed.attestation_path} differs from checker-pinned SHA-256 ${sealed.attestation_sha256}; found ${attestationFileSha256}`);

    const snapshot = readJsonChecked(snapshotAbsolute, `approval snapshot ${sealed.snapshot_path}`);
    const attestation = readJsonChecked(attestationAbsolute, `approval attestation ${sealed.attestation_path}`);
    if (!snapshot || !attestation) {
      previous = sealed;
      previousRows = [];
      continue;
    }

    if (snapshot.schema_version !== "ioi.program.approved-source-dispositions.v1" || snapshot.document_class !== "work_record") errors.push(`approval snapshot ${sealed.snapshot_path} has an invalid schema or document_class`);
    if (snapshot.revision !== sealed.revision || typeof snapshot.transaction_id !== "string" || snapshot.transaction_id.length === 0) errors.push(`approval snapshot ${sealed.snapshot_path} has an invalid revision or transaction_id`);
    if (stableJson(snapshot.predecessor) !== stableJson(predecessorIdentity(previous))) errors.push(`approval snapshot ${sealed.snapshot_path} does not cite its exact immutable predecessor`);

    const rows = canonicalCurrentRows(snapshot.current_paths, `approval snapshot ${sealed.snapshot_path}.current_paths`);
    const rowsSha256 = sha256(stableJson(rows));
    if (snapshot.current_path_count !== rows.length) errors.push(`approval snapshot ${sealed.snapshot_path} current_path_count does not match its rows`);
    if (snapshot.complete_current_disposition_rows_sha256 !== rowsSha256 || sealed.complete_current_disposition_rows_sha256 !== rowsSha256) errors.push(`approval snapshot ${sealed.snapshot_path} complete-row digest mismatch: found ${rowsSha256}`);
    if (new Set(rows.map((row) => row.path)).size !== rows.length) errors.push(`approval snapshot ${sealed.snapshot_path} contains duplicate current paths`);

    const decisions = canonicalDecisions(snapshot.approved_disposition_decisions);
    if (!decisions || Object.keys(decisions).length === 0) errors.push(`approval snapshot ${sealed.snapshot_path} has no closed approval-decision map`);
    const decisionsSha256 = sha256(stableJson(decisions ?? {}));
    if (snapshot.approved_disposition_decisions_sha256 !== decisionsSha256 || sealed.approved_disposition_decisions_sha256 !== decisionsSha256) errors.push(`approval snapshot ${sealed.snapshot_path} approval-decision digest mismatch: found ${decisionsSha256}`);

    const expectedChangeSet = previous
      ? derivedChangeSet(previousRows, rows)
      : { kind: "reviewed_root_finalization", predecessor: null };
    if (stableJson(snapshot.change_set) !== stableJson(expectedChangeSet)) errors.push(`approval snapshot ${sealed.snapshot_path} does not contain its exact derived change set`);

    let expectedReviewedInputs = null;
    if (sealed.revision === 2) {
      const requiredChangeSet = {
        kind: "reviewed_append_only_successor",
        added_paths: SUCCESSOR_V2_ROWS.map((row) => row.path).sort(),
        removed_paths: [],
        changed_paths: [],
      };
      if (stableJson(expectedChangeSet) !== stableJson(requiredChangeSet)) {
        errors.push(`approval snapshot ${sealed.snapshot_path} is not the exact bounded phase-6 verifier-correction successor delta`);
      }
      expectedReviewedInputs = reviewedInputsFromFiles();
      if (stableJson(snapshot.reviewed_inputs) !== stableJson(expectedReviewedInputs)) {
        errors.push(`approval snapshot ${sealed.snapshot_path} does not bind the current final correction report and delegated review`);
      }
    }

    if (attestation.schema_version !== "ioi.program.source-disposition-approval-attestation.v1" || attestation.document_class !== "work_record") errors.push(`approval attestation ${sealed.attestation_path} has an invalid schema or document_class`);
    if (attestation.revision !== sealed.revision || attestation.transaction_id !== snapshot.transaction_id) errors.push(`approval attestation ${sealed.attestation_path} does not identify the same revision and transaction`);
    if (stableJson(attestation.predecessor) !== stableJson(predecessorIdentity(previous))) errors.push(`approval attestation ${sealed.attestation_path} does not cite its exact immutable predecessor`);
    if (attestation.approved_snapshot_path !== sealed.snapshot_path || attestation.approved_snapshot_sha256 !== sealed.snapshot_sha256) errors.push(`approval attestation ${sealed.attestation_path} does not select the checker-pinned snapshot`);
    if (attestation.current_path_count !== rows.length || attestation.complete_current_disposition_rows_sha256 !== rowsSha256) errors.push(`approval attestation ${sealed.attestation_path} does not bind the complete approved row set`);
    if (attestation.approved_disposition_decisions_sha256 !== decisionsSha256) errors.push(`approval attestation ${sealed.attestation_path} does not bind the closed approval decisions`);
    if (sealed.revision === 2) {
      if (stableJson(attestation.derived_change_set) !== stableJson(expectedChangeSet)) {
        errors.push(`approval attestation ${sealed.attestation_path} does not bind the exact derived successor delta`);
      }
      if (stableJson(attestation.reviewed_inputs) !== stableJson(expectedReviewedInputs)) {
        errors.push(`approval attestation ${sealed.attestation_path} does not bind the final correction report and delegated review`);
      }
    }
    if (attestation.reviewed_successor_protocol?.mode !== "append_only_content_addressed_successor"
      || attestation.reviewed_successor_protocol?.auto_discovery_permitted !== false
      || attestation.reviewed_successor_protocol?.in_place_replacement_permitted !== false
      || attestation.reviewed_successor_protocol?.checker_pin_required !== true) {
      errors.push(`approval attestation ${sealed.attestation_path} does not require reviewed append-only successor semantics`);
    }

    latest = { sealed, snapshot, attestation, rows, decisions };
    previous = sealed;
    previousRows = rows;
  }
  return latest;
}

function writeSuccessorV2(registry, approval) {
  if (args.length !== 5) {
    errors.push("--write-successor-v2 requires exactly --report-sha256 SHA256 and --review-sha256 SHA256");
  }
  if (SEALED_APPROVAL_CHAIN.length !== 1 || approval?.sealed?.revision !== 1) {
    errors.push("successor-v2 approval pins are already present; the one-time approval writer is disabled");
  }
  if (sha256File(registryPath) !== SEALED_ROOT_SOURCE_REGISTRY_SHA256) {
    errors.push(`successor-v2 preparation requires the exact immutable revision-1 source registry SHA-256 ${SEALED_ROOT_SOURCE_REGISTRY_SHA256}`);
  }
  if (!sameKeys(registry, expectedRegistryKeys)) {
    errors.push("source registry must contain exactly the sealed schema fields before successor preparation");
  }

  const rootRows = canonicalCurrentRows(registry.current_paths, "registry.current_paths");
  const expectedRootChain = SEALED_APPROVAL_CHAIN.map(approvalChainIdentity);
  if (approval && stableJson(rootRows) !== stableJson(approval.rows)) {
    errors.push("successor-v2 preparation requires the exact checker-pinned revision-1 rows");
  }
  if (stableJson(registry.source_disposition_approval_chain) !== stableJson(expectedRootChain)) {
    errors.push("successor-v2 preparation requires the exact checker-pinned revision-1 approval identity");
  }
  if (registry.finalized_current_path_set_sha256
    !== pathSetDigestForRows(rootRows)) {
    errors.push("successor-v2 preparation requires the intact revision-1 path-set digest");
  }
  if (registry.finalized_current_disposition_rows_sha256
    !== sha256(stableJson(rootRows))) {
    errors.push("successor-v2 preparation requires the intact revision-1 complete-row digest");
  }

  const outputPaths = [
    SUCCESSOR_V2_APPROVAL_SNAPSHOT_PATH,
    SUCCESSOR_V2_APPROVAL_ATTESTATION_PATH,
    SUCCESSOR_V2_POST_SNAPSHOT_PATH,
    SUCCESSOR_V2_POST_ATTESTATION_PATH,
  ];
  for (const relative of outputPaths) {
    if (fs.existsSync(path.join(implementationRoot, relative))) {
      errors.push(`append-only successor output already exists: ${relative}`);
    }
  }

  const registeredPaths = new Set(rootRows.map((row) => row.path));
  const actualPaths = listTreeFiles(implementationRoot).map(implementationRelative).sort();
  const unregisteredPaths = actualPaths.filter((relative) => !registeredPaths.has(relative));
  const missingRegisteredPaths = [...registeredPaths].filter((relative) => !actualPaths.includes(relative));
  const requiredUnregisteredPaths = Object.values(SUCCESSOR_V2_REVIEW_INPUTS)
    .map((entry) => entry.path)
    .sort();
  if (stableJson(unregisteredPaths) !== stableJson(requiredUnregisteredPaths)) {
    errors.push(`successor-v2 preparation requires exactly the two final reviewed inputs as its pre-write path delta; found ${unregisteredPaths.join(", ") || "none"}`);
  }
  if (missingRegisteredPaths.length > 0) {
    errors.push(`successor-v2 preparation found missing revision-1 paths: ${missingRegisteredPaths.join(", ")}`);
  }

  const reviewedInputs = reviewedInputsFromFiles({ requireFlags: true });
  failWith("source-disposition successor-v2 preparation", errors);

  const successorRows = canonicalCurrentRows(
    [...rootRows, ...SUCCESSOR_V2_ROWS],
    "successor-v2 current_paths",
  );
  const successorRowsSha256 = sha256(stableJson(successorRows));
  const decisions = canonicalDecisions(registry.approved_disposition_decisions);
  const decisionsSha256 = sha256(stableJson(decisions));
  const predecessor = predecessorIdentity(SEALED_APPROVAL_CHAIN.at(-1));
  const changeSet = derivedChangeSet(rootRows, successorRows);
  const snapshot = {
    schema_version: "ioi.program.approved-source-dispositions.v1",
    document_class: "work_record",
    revision: 2,
    transaction_id: SUCCESSOR_V2_TRANSACTION_ID,
    predecessor,
    approval_scope: "exact complete current private source-disposition rows after the bounded phase-6 verifier-correction transaction",
    approved_disposition_decisions: decisions,
    approved_disposition_decisions_sha256: decisionsSha256,
    current_path_count: successorRows.length,
    complete_current_disposition_rows_sha256: successorRowsSha256,
    current_paths: successorRows,
    reviewed_inputs: reviewedInputs,
    change_set: changeSet,
    owns: "the immutable reviewed revision-2 disposition row set and its exact predecessor/delta",
    does_not_own: [
      "stage order",
      "work activation",
      "implementation status",
      "architecture doctrine",
    ],
    nonclaim: "This approval successor classifies the bounded private verifier-correction files only; it proves no implementation, product behavior, work status, or stage closure.",
  };
  const snapshotSha256 = sha256(stableJson(snapshot));
  const attestation = {
    schema_version: "ioi.program.source-disposition-approval-attestation.v1",
    document_class: "work_record",
    revision: 2,
    transaction_id: SUCCESSOR_V2_TRANSACTION_ID,
    predecessor,
    approval_scope: "the exact complete revision-2 source-disposition successor; no filesystem discovery or prefix rule grants approval",
    approval_basis: "Explicit final correction-report and delegated-review digests supplied to the one-time append-only successor writer; this records artifact identity and does not claim a cryptographic signature.",
    approved_snapshot_path: SUCCESSOR_V2_APPROVAL_SNAPSHOT_PATH,
    approved_snapshot_sha256: snapshotSha256,
    current_path_count: successorRows.length,
    complete_current_disposition_rows_sha256: successorRowsSha256,
    approved_disposition_decisions_sha256: decisionsSha256,
    reviewed_inputs: reviewedInputs,
    derived_change_set: changeSet,
    reviewed_successor_protocol: {
      mode: "append_only_content_addressed_successor",
      auto_discovery_permitted: false,
      in_place_replacement_permitted: false,
      checker_pin_required: true,
      rule: "Retain revision 1 unchanged; pin this exact revision-2 snapshot and attestation in the checker before sealing the current-estate source-manifest successor.",
    },
    nonclaim: "This attestation records review scope, predecessor, delta, and artifact identity only; it proves no implementation, product behavior, work status, or stage closure.",
  };
  const attestationSha256 = sha256(stableJson(attestation));
  const successorIdentity = {
    revision: 2,
    snapshot_path: SUCCESSOR_V2_APPROVAL_SNAPSHOT_PATH,
    snapshot_sha256: snapshotSha256,
    attestation_path: SUCCESSOR_V2_APPROVAL_ATTESTATION_PATH,
    attestation_sha256: attestationSha256,
    complete_current_disposition_rows_sha256: successorRowsSha256,
    approved_disposition_decisions_sha256: decisionsSha256,
  };
  const successorRegistry = {
    ...registry,
    // Preserve the exact revision-1 registry row order so its full file hash
    // remains reconstructable after filtering the six append-only v2 rows.
    // Approval snapshots and row digests remain canonically path-sorted.
    current_paths: [...registry.current_paths, ...SUCCESSOR_V2_ROWS],
    finalized_current_path_set_sha256: pathSetDigestForRows(successorRows),
    finalized_current_disposition_rows_sha256: successorRowsSha256,
    source_disposition_approval_chain: [...expectedRootChain, successorIdentity],
  };

  writeDeterministic(path.join(implementationRoot, SUCCESSOR_V2_APPROVAL_SNAPSHOT_PATH), snapshot);
  writeDeterministic(path.join(implementationRoot, SUCCESSOR_V2_APPROVAL_ATTESTATION_PATH), attestation);
  writeDeterministic(path.join(implementationRoot, SUCCESSOR_V2_POST_SNAPSHOT_PATH), {});
  writeDeterministic(path.join(implementationRoot, SUCCESSOR_V2_POST_ATTESTATION_PATH), {});
  writeDeterministic(registryPath, successorRegistry);
  process.stdout.write(stableJson({
    revision: 2,
    transaction_id: SUCCESSOR_V2_TRANSACTION_ID,
    snapshot_path: SUCCESSOR_V2_APPROVAL_SNAPSHOT_PATH,
    snapshot_sha256: snapshotSha256,
    attestation_path: SUCCESSOR_V2_APPROVAL_ATTESTATION_PATH,
    attestation_sha256: attestationSha256,
    current_path_count: successorRows.length,
    current_path_set_sha256: successorRegistry.finalized_current_path_set_sha256,
    complete_current_disposition_rows_sha256: successorRowsSha256,
    approved_disposition_decisions_sha256: decisionsSha256,
    reviewed_inputs: reviewedInputs,
    change_set: changeSet,
  }));
  process.stdout.write("Revision-2 approval artifacts and current registry were prepared. Pin the printed approval identity in SEALED_APPROVAL_CHAIN and freeze-source-manifest.mjs before sealing the source-manifest successor.\n");
}

function pathSetDigestForRows(rows) {
  return sha256(stableJson(rows.map((row) => row.path).sort()));
}

if (!fs.existsSync(registryPath)) {
  errors.push("source-dispositions.v1.json is missing");
  failWith("source-disposition check", errors);
}
const registry = readJsonChecked(registryPath, "source-dispositions.v1.json");
if (!registry) failWith("source-disposition check", errors);
const approval = validateSealedApprovalChain();
if (mode === "--write-successor-v2") {
  writeSuccessorV2(registry, approval);
  process.exit(0);
}

if (!sameKeys(registry, expectedRegistryKeys)) errors.push("source registry must contain exactly the sealed schema fields");
if (registry.schema_version !== "ioi.program.source-dispositions.v1") errors.push("unknown registry schema_version");
if (registry.status_fields_permitted !== false) errors.push("source registry must prohibit status fields");
if (!Array.isArray(registry.sources) || registry.sources.length === 0) errors.push("sources must be nonempty");
if (!Array.isArray(registry.current_paths) || registry.current_paths.length === 0) errors.push("current_paths must be nonempty");
if (registry.migration_finalized !== true) errors.push("one-time source migration is not finalized");

const registryDecisions = canonicalDecisions(registry.approved_disposition_decisions);
if (!registryDecisions || Object.keys(registryDecisions).length === 0) errors.push("approved_disposition_decisions must be a closed nonempty map");
if (approval && stableJson(registryDecisions) !== stableJson(approval.decisions)) errors.push("registry approval decisions differ from the independently sealed approval snapshot");
const approvalIds = new Set(Object.keys(approval?.decisions ?? {}));
const citedApprovalIds = new Set();

const seenSources = new Set();
const destinations = new Map();
for (const [index, entry] of (registry.sources ?? []).entries()) {
  if (!sameKeys(entry, sourceRowKeys)) errors.push(`sources[${index}] must contain exactly the baseline source-disposition fields`);
  if (seenSources.has(entry.source_path)) errors.push(`duplicate source disposition: ${entry.source_path}`);
  seenSources.add(entry.source_path);
  if (!allowedClasses.has(entry.document_class)) errors.push(`${entry.source_path} has unknown class ${entry.document_class}`);
  if (!allowedDispositions.has(entry.disposition)) errors.push(`${entry.source_path} has unknown disposition ${entry.disposition}`);
  if (entry.delete_permitted !== false) errors.push(`${entry.source_path} permits deletion`);
  if (!/^[a-f0-9]{64}$/u.test(entry.baseline_sha256 ?? "")) errors.push(`${entry.source_path} lacks a baseline SHA-256`);
  if (!entry.owner || !entry.destination_path || !entry.approving_amendment) errors.push(`${entry.source_path} lacks owner/destination/approval`);
  if (!approvalIds.has(entry.approving_amendment)) errors.push(`${entry.source_path} cites unknown approval decision ${entry.approving_amendment}`);
  citedApprovalIds.add(entry.approving_amendment);
  const collision = destinations.get(entry.destination_path);
  if (collision && collision !== entry.source_path) errors.push(`destination collision: ${collision} and ${entry.source_path} -> ${entry.destination_path}`);
  destinations.set(entry.destination_path, entry.source_path);
  if (entry.compatibility_hold && (!entry.compatibility_hold.reason || !entry.compatibility_hold.approval_needed)) errors.push(`${entry.source_path} has an incomplete compatibility hold`);
  const sourceAbsolute = path.join(implementationRoot, entry.source_path);
  const destinationAbsolute = path.join(implementationRoot, entry.destination_path);
  if (!fs.existsSync(destinationAbsolute)) errors.push(`${entry.source_path} destination is missing: ${entry.destination_path}`);
  if (entry.tombstone_required) {
    if (!fs.existsSync(sourceAbsolute)) {
      errors.push(`${entry.source_path} requires a stable tombstone but the path is missing`);
    } else if (fs.lstatSync(sourceAbsolute).isSymbolicLink()) {
      const resolved = path.resolve(path.dirname(sourceAbsolute), fs.readlinkSync(sourceAbsolute));
      if (!fs.existsSync(resolved)) errors.push(`${entry.source_path} has a broken compatibility symlink`);
    } else {
      const tombstone = fs.readFileSync(sourceAbsolute, "utf8");
      if (tombstone.split(/\r?\n/u).length > 40) errors.push(`${entry.source_path} tombstone exceeds the one-screen 40-line limit`);
      if (!tombstone.includes(path.basename(entry.destination_path))) errors.push(`${entry.source_path} tombstone does not point at ${entry.destination_path}`);
    }
  }
}

const registryRows = canonicalCurrentRows(registry.current_paths, "registry.current_paths");
const seenCurrent = new Set();
for (const entry of registryRows) {
  if (seenCurrent.has(entry.path)) errors.push(`duplicate current-path disposition: ${entry.path}`);
  seenCurrent.add(entry.path);
  if (!allowedClasses.has(entry.document_class)) errors.push(`${entry.path} has unknown class ${entry.document_class}`);
  if (!allowedDispositions.has(entry.disposition)) errors.push(`${entry.path} has unknown disposition ${entry.disposition}`);
  if (typeof entry.path !== "string" || entry.path.length === 0 || path.isAbsolute(entry.path) || entry.path.startsWith("../")) errors.push(`${entry.path} is not a safe implementation-relative path`);
  if (typeof entry.owner !== "string" || entry.owner.length === 0) errors.push(`${entry.path} lacks an owner`);
  if (entry.source_path !== null && (typeof entry.source_path !== "string" || entry.source_path.length === 0)) errors.push(`${entry.path} has an invalid source_path`);
  if (typeof entry.destination_path !== "string" || entry.destination_path.length === 0) {
    errors.push(`${entry.path} lacks a current destination_path`);
  } else if (!fs.existsSync(path.join(implementationRoot, entry.destination_path))) {
    errors.push(`${entry.path} current destination is missing: ${entry.destination_path}`);
  }
  if (typeof entry.tombstone_required !== "boolean") errors.push(`${entry.path} lacks an explicit tombstone_required rule`);
  if (entry.tombstone_required && entry.document_class !== "pointer") errors.push(`${entry.path} requires a tombstone but is not classified as a pointer`);
  if (!approvalIds.has(entry.approving_amendment)) errors.push(`${entry.path} cites unknown approval decision ${entry.approving_amendment}`);
  citedApprovalIds.add(entry.approving_amendment);
  if (entry.schedules_work !== (entry.document_class === "sequencer")) errors.push(`${entry.path} has invalid schedules_work boundary`);
  const mayCarryStatus = entry.document_class === "work_item" || entry.path === "program-state.json";
  if (entry.carries_status !== mayCarryStatus) errors.push(`${entry.path} has invalid carries_status boundary`);
}
for (const approvalId of approvalIds) {
  if (!citedApprovalIds.has(approvalId)) errors.push(`closed approval decision is not cited by any exact disposition row: ${approvalId}`);
}

const actual = listTreeFiles(implementationRoot).map(implementationRelative).sort();
for (const currentPath of actual) {
  if (!seenCurrent.has(currentPath)) errors.push(`unclassified current private path: ${currentPath}`);
}
for (const currentPath of seenCurrent) {
  if (!actual.includes(currentPath)) errors.push(`registered current path is missing: ${currentPath}`);
}

const pathSetSha256 = sha256(stableJson([...seenCurrent].sort()));
const completeRowsSha256 = sha256(stableJson(registryRows));
if (registry.finalized_current_path_set_sha256 !== pathSetSha256) errors.push(`finalized current-path digest mismatch: expected ${registry.finalized_current_path_set_sha256}, found ${pathSetSha256}`);
if (registry.finalized_current_disposition_rows_sha256 !== completeRowsSha256) errors.push(`finalized complete-row digest mismatch: expected ${registry.finalized_current_disposition_rows_sha256}, found ${completeRowsSha256}`);
if (approval) {
  if (stableJson(registryRows) !== stableJson(approval.rows)) errors.push("registry current disposition rows differ from the independently sealed approval snapshot");
  if (completeRowsSha256 !== approval.sealed.complete_current_disposition_rows_sha256) errors.push(`registry complete-row digest differs from checker-pinned approval ${approval.sealed.complete_current_disposition_rows_sha256}`);
  const expectedChain = SEALED_APPROVAL_CHAIN.map(approvalChainIdentity);
  if (stableJson(registry.source_disposition_approval_chain) !== stableJson(expectedChain)) errors.push("registry approval-chain identity differs from the independently checker-pinned chain");
}

const statusKeys = /^(status|stage_status|work_status|next_action|active_cut)$/u;
const walk = (value, at) => {
  if (Array.isArray(value)) return value.forEach((child, index) => walk(child, `${at}[${index}]`));
  if (!value || typeof value !== "object") return;
  for (const [key, child] of Object.entries(value)) {
    if (statusKeys.test(key)) errors.push(`${at}.${key} is a forbidden status/sequence field`);
    walk(child, `${at}.${key}`);
  }
};
walk(registry, "registry");
if (approval) {
  walk(approval.snapshot, "approved_snapshot");
  walk(approval.attestation, "approval_attestation");
}

failWith("source-disposition check", errors);
process.stdout.write(`source-disposition check passed: ${registry.sources.length} preserved sources, ${actual.length} exactly approved current paths, revision ${approval.sealed.revision}, complete rows sha256 ${completeRowsSha256}\n`);
