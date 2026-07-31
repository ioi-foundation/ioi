#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import {
  checkDeterministic,
  implementationRelative,
  implementationRoot,
  listTreeFiles,
  readJson,
  sha256,
  sha256File,
  stableJson,
  writeDeterministic,
} from "./lib.mjs";

const mode = process.argv[2];
if (!new Set(["--write", "--check", "--seal-post-migration", "--seal-successor-v2"]).has(mode)) {
  process.stderr.write("usage: freeze-source-manifest.mjs --write|--check|--seal-post-migration|--seal-successor-v2\n");
  process.exit(2);
}

const registryPath = path.join(implementationRoot, "source-dispositions.v1.json");
const sourceDispositionCheckerPath = path.join(
  implementationRoot,
  "tools/check-source-dispositions.mjs",
);
const outputPath = path.join(implementationRoot, "generated/source-manifest.v1.json");
const historyRoot = path.join(implementationRoot, "audits/reconciliation/source-manifests");
const preMigrationAttestationPath = path.join(historyRoot, "pre-migration-snapshot.attestation.v1.json");
const postMigrationSnapshotPath = path.join(historyRoot, "post-migration.source-manifest.v1.json");
const postMigrationAttestationPath = path.join(
  historyRoot,
  "post-migration-snapshot.attestation.v1.json",
);
const postMigrationSuccessorV2SnapshotPath = path.join(
  historyRoot,
  "post-migration-successor.v2.source-manifest.v1.json",
);
const postMigrationSuccessorV2AttestationPath = path.join(
  historyRoot,
  "post-migration-successor-snapshot.attestation.v2.json",
);
const approvalOraclePath = path.join(
  implementationRoot,
  "audits/reconciliation/approved-sequencer-amendments/sa-1-through-sa-9.approval-oracle.v1.json",
);
const preLinkRepairManifestPath = path.join(
  implementationRoot,
  "_archive/pre-link-repair/2026-07-23/manifest.v1.json",
);
const SEALED_PRE_MIGRATION_SNAPSHOT_SHA256 = "4136450a9d07a134c6ef6c64be133d0902b6dad022a1c2d67110c6a8af64fca8";
const SEALED_PRE_LINK_REPAIR_MANIFEST_SHA256 = "688bec67a5ada80ae334a8a0f763ec361635c25a4ce8c356a67af2b1bb7c6a17";
const SEALED_BASELINE = {
  branch: "feat/estate-camera-pipeline",
  commit: "a894b25054cdb45f27deb3163793773d6449dd2b",
  captured_on: "2026-07-22",
  source_count: 73,
};
const POST_MIGRATION_TRANSACTION_ID = "SA-1-through-SA-9";
const POST_MIGRATION_RECURSIVE_OUTPUT_EXCLUSIONS = Object.freeze([
  "generated/source-manifest.v1.json",
  "audits/reconciliation/source-manifests/post-migration.source-manifest.v1.json",
  "audits/reconciliation/source-manifests/post-migration-snapshot.attestation.v1.json",
]);
const POST_MIGRATION_TRUST_ROOT_EXCLUSIONS = Object.freeze([
  "tools/freeze-source-manifest.mjs",
]);
const POST_MIGRATION_RECURSION_EXCLUSIONS = Object.freeze([
  ...POST_MIGRATION_RECURSIVE_OUTPUT_EXCLUSIONS,
  ...POST_MIGRATION_TRUST_ROOT_EXCLUSIONS,
]);
const SOURCE_DISPOSITION_APPROVAL_V1 = Object.freeze({
  revision: 1,
  snapshot_path: "audits/reconciliation/source-disposition-approvals/approved-source-dispositions.v1.json",
  snapshot_sha256: "e1aa9149495c0d943d852265991df106ef89f2332e6d79c4954552f58a5c0cec",
  attestation_path: "audits/reconciliation/source-disposition-approvals/approval-attestation.v1.json",
  attestation_sha256: "16a1dc1ddc4a7f53ac3d4f8059093fb72dae596e6452bc066082b82579b29870",
  complete_current_disposition_rows_sha256: "c342c46e0494f3ebd1dc197fe68cec5f3137fcc4b99c8bc11a698ca3ee7455eb",
  approved_disposition_decisions_sha256: "9494c9b55e1426a7dc869f7a327810cf10bfa42f104d31454ef16d06fcd2dea2",
  transaction_id: "source-disposition-root-finalization-2026-07-23",
});
// Filled only after the final correction report/review digests select the exact
// append-only approval successor. Until then, --seal-successor-v2 and --check
// fail closed rather than treating a discovered file as approved.
const SOURCE_DISPOSITION_APPROVAL_V2 = Object.freeze({
  revision: 2,
  snapshot_path: "audits/reconciliation/source-disposition-approvals/approved-source-dispositions.v2.json",
  snapshot_sha256: "48837874bd364358d2c7e5c0816c0ab9c40981049cbbbcd1b5a0af889436341f",
  attestation_path: "audits/reconciliation/source-disposition-approvals/approval-attestation.v2.json",
  attestation_sha256: "3063200984e8917a6391ab7d7e96f53b358be3bbcdd2b04bc47e1fc314d322e2",
  complete_current_disposition_rows_sha256: "72de4f9d7464e1bf9ddeb27d42cb0b06724a3aed1c2b8b20b0bf6d2ef9f8119a",
  approved_disposition_decisions_sha256: "9494c9b55e1426a7dc869f7a327810cf10bfa42f104d31454ef16d06fcd2dea2",
  transaction_id: "phase6-verifier-correction-successor-2026-07-23",
});
const POST_MIGRATION_SUCCESSOR_V2_TRANSACTION_ID = "phase6-verifier-correction-successor-2026-07-23";
const POST_MIGRATION_SUCCESSOR_V2_RECURSIVE_OUTPUT_EXCLUSIONS = Object.freeze([
  "generated/source-manifest.v1.json",
  "audits/reconciliation/source-manifests/post-migration-successor.v2.source-manifest.v1.json",
  "audits/reconciliation/source-manifests/post-migration-successor-snapshot.attestation.v2.json",
]);
const POST_MIGRATION_SUCCESSOR_V2_TRUST_ROOT_EXCLUSIONS = Object.freeze([
  "tools/freeze-source-manifest.mjs",
]);
const POST_MIGRATION_SUCCESSOR_V2_RECURSION_EXCLUSIONS = Object.freeze([
  ...POST_MIGRATION_SUCCESSOR_V2_RECURSIVE_OUTPUT_EXCLUSIONS,
  ...POST_MIGRATION_SUCCESSOR_V2_TRUST_ROOT_EXCLUSIONS,
]);
// These independently embedded pins close the reviewed post-migration transaction.
// The checker is excluded from the sealed path census because embedding the snapshot
// hashes in a file that the snapshot itself hashes would require an impossible fixed
// point. --seal-post-migration is permanently disabled once these values are present.
const SEALED_POST_MIGRATION = Object.freeze({
  snapshot_sha256: "876e2518a8206f10f15401037bcec67e994901ac9fdd3000c7d014aea5014578",
  attestation_sha256: "b35d52f388af2369a891610c38856d8d5ff09b3263822173276beb84784bf255",
  source_registry_sha256: "c1c5b333aeeb7e99b2d874897a8bd7c7d9abf2a05ce26ae609c0c9ec4b2c6b02",
  full_disposition_rows_sha256: "c342c46e0494f3ebd1dc197fe68cec5f3137fcc4b99c8bc11a698ca3ee7455eb",
  registry_current_path_set_sha256: "97e78da03f31fdb7111c35affe75aaa1a38ed10dcf93615dada48c101e848c31",
  registry_current_path_count: 309,
  snapshot_path_set_sha256: "ea5c09a854c2562d364b41491b314f7bbcd47b88dff527e9e498e4ac98265031",
  snapshot_materialization_count: 305,
  approval_oracle_sha256: "e5fdfa39fba49d7e5f5ecb1ff3dd60d18a750b08d256fe8c9b655527b5be2b34",
  approval_oracle_metadata_sha256: "02f25b68cae52beca3ec48e8ae14b704386e7c408cd0d5d100ee84d3c021bbb2",
  source_disposition_approval_revision: 1,
  source_disposition_approved_snapshot_sha256: "e1aa9149495c0d943d852265991df106ef89f2332e6d79c4954552f58a5c0cec",
  source_disposition_approval_attestation_sha256: "16a1dc1ddc4a7f53ac3d4f8059093fb72dae596e6452bc066082b82579b29870",
  source_disposition_transaction_id: "source-disposition-root-finalization-2026-07-23",
});
const SUCCESSOR_V2_REVIEW_PATHS = Object.freeze({
  correction_report: "audits/reconciliation/2026-07-23-phase6-verifier-correction-report.md",
  delegated_review: "audits/reconciliation/2026-07-23-phase6-verifier-correction-review.md",
});
// This successor is deliberately unsealed until the report and fresh delegated
// review are final. The one-time writer prints every value that must replace a
// null below; once all pins are populated, the writer permanently refuses.
const SEALED_POST_MIGRATION_SUCCESSOR_V2 = Object.freeze({
  snapshot_sha256: "2496cb9b1a04a1727d7413129750a7a22351cb49af745826c11705c73f0d47b3",
  attestation_sha256: "44e101be64c11b9c9d41f50bb58a150cce4d231d651ed0d3b6900ccef7379c33",
  source_registry_sha256: "8b2ad71b3e128f04a0c286166d81657d2b6f1afdf9c18b8585aaceaa20ae7522",
  full_disposition_rows_sha256: "72de4f9d7464e1bf9ddeb27d42cb0b06724a3aed1c2b8b20b0bf6d2ef9f8119a",
  registry_current_path_set_sha256: "63215588942a05c89a9e7e05ba49abd055efe683386601844c79f4f9a7cae3f4",
  registry_current_path_count: 315,
  snapshot_path_set_sha256: "e3a27682e3326ed886b504dc8f00c5b60ccb74e361898d3c19e5fd529150ce16",
  snapshot_materialization_count: 311,
  approval_oracle_sha256: "e5fdfa39fba49d7e5f5ecb1ff3dd60d18a750b08d256fe8c9b655527b5be2b34",
  approval_oracle_metadata_sha256: "02f25b68cae52beca3ec48e8ae14b704386e7c408cd0d5d100ee84d3c021bbb2",
  source_disposition_approval_revision: 2,
  source_disposition_approved_snapshot_sha256: "48837874bd364358d2c7e5c0816c0ab9c40981049cbbbcd1b5a0af889436341f",
  source_disposition_approval_attestation_sha256: "3063200984e8917a6391ab7d7e96f53b358be3bbcdd2b04bc47e1fc314d322e2",
  source_disposition_transaction_id: POST_MIGRATION_SUCCESSOR_V2_TRANSACTION_ID,
  predecessor_snapshot_sha256: "876e2518a8206f10f15401037bcec67e994901ac9fdd3000c7d014aea5014578",
  predecessor_attestation_sha256: "b35d52f388af2369a891610c38856d8d5ff09b3263822173276beb84784bf255",
  correction_report_sha256: "ef5b57d095866cbbbedc898783ebfc8439bfe78e98a051e33829e7dbc446ddb4",
  delegated_review_sha256: "72c5d9092361e4e3ce0e9a09bf34d67bf2ba7cdb187114678976e2d0ac3a4d7c",
});
const existingSnapshots = fs.existsSync(historyRoot)
  ? fs.readdirSync(historyRoot).filter((name) => /^[a-f0-9]{64}\.source-manifest\.v1\.json$/u.test(name))
  : [];
const registry = readJson(registryPath);

function fail(message) {
  process.stderr.write(`source manifest check failed: ${message}\n`);
  process.exit(1);
}

function requirePinnedSourceDispositionChecker() {
  const result = spawnSync(process.execPath, [sourceDispositionCheckerPath, "--check"], {
    cwd: implementationRoot,
    encoding: "utf8",
  });
  if (result.status !== 0) {
    const detail = (result.stderr || result.stdout || "no checker output").trim();
    fail(`source-disposition checker does not accept the independently pinned successor: ${detail}`);
  }
}

function dispositionRowsDigest(value) {
  const rows = Array.isArray(value) ? value : value.current_paths;
  return sha256(stableJson(
    [...rows].sort((left, right) => left.path.localeCompare(right.path)),
  ));
}

function pathSetDigest(paths) {
  return sha256(stableJson([...new Set(paths)].sort()));
}

function approvalOracleMetadata(oracle) {
  return {
    schema_version: oracle.schema_version,
    document_class: oracle.document_class,
    transaction: oracle.transaction,
    approval_source: oracle.approval_source,
    approval_source_sha256: oracle.approval_source_sha256,
    approved_amendments: oracle.approved_amendments,
    baseline_master: oracle.baseline_master,
    approval_oracle: oracle.approval_oracle,
    expected_current_master_sha256: oracle.expected_current_master_sha256,
  };
}

function readAndValidateApprovalOracle() {
  if (!fs.existsSync(approvalOraclePath)) fail("SA-1-through-SA-9 approval oracle is missing");
  const oracle = readJson(approvalOraclePath);
  if (
    oracle.schema_version !== "ioi.program.sequencer-amendment-approval-oracle.v1"
    || oracle.document_class !== "work_record"
    || oracle.transaction !== POST_MIGRATION_TRANSACTION_ID
    || stableJson(oracle.approved_amendments) !== stableJson(
      Array.from({ length: 9 }, (_, index) => `SA-${index + 1}`),
    )
  ) {
    fail("SA approval oracle has an invalid schema, role, transaction, or amendment set");
  }
  return {
    oracle,
    path: implementationRelative(approvalOraclePath),
    sha256: sha256File(approvalOraclePath),
    metadata_sha256: sha256(stableJson(approvalOracleMetadata(oracle))),
  };
}

function approvalPinsAreComplete(pins) {
  return Number.isInteger(pins.revision)
    && pins.revision > 0
    && /^[0-9a-f]{64}$/u.test(pins.snapshot_sha256 ?? "")
    && /^[0-9a-f]{64}$/u.test(pins.attestation_sha256 ?? "")
    && /^[0-9a-f]{64}$/u.test(pins.complete_current_disposition_rows_sha256 ?? "")
    && /^[0-9a-f]{64}$/u.test(pins.approved_disposition_decisions_sha256 ?? "")
    && typeof pins.snapshot_path === "string"
    && typeof pins.attestation_path === "string"
    && typeof pins.transaction_id === "string";
}

function approvalIdentity(pins) {
  return {
    revision: pins.revision,
    snapshot_path: pins.snapshot_path,
    snapshot_sha256: pins.snapshot_sha256,
    attestation_path: pins.attestation_path,
    attestation_sha256: pins.attestation_sha256,
    complete_current_disposition_rows_sha256:
      pins.complete_current_disposition_rows_sha256,
    approved_disposition_decisions_sha256:
      pins.approved_disposition_decisions_sha256,
  };
}

function readAndValidatePinnedSourceDispositionApproval(pins, predecessor = null) {
  if (!approvalPinsAreComplete(pins)) {
    fail(`source-disposition approval revision ${pins.revision} is not independently pinned`);
  }
  const snapshotPath = path.join(implementationRoot, pins.snapshot_path);
  const attestationPath = path.join(implementationRoot, pins.attestation_path);
  if (!fs.existsSync(snapshotPath) || !fs.existsSync(attestationPath)) {
    fail(`source-disposition approval revision ${pins.revision} snapshot or attestation is missing`);
  }
  if (sha256File(snapshotPath) !== pins.snapshot_sha256
    || sha256File(attestationPath) !== pins.attestation_sha256) {
    fail(`source-disposition approval revision ${pins.revision} differs from its independent pins`);
  }
  const snapshot = readJson(snapshotPath);
  const attestation = readJson(attestationPath);
  const rows = [...(snapshot.current_paths ?? [])]
    .sort((left, right) => left.path.localeCompare(right.path));
  const rowsSha256 = dispositionRowsDigest(rows);
  const decisionsSha256 = sha256(stableJson(Object.fromEntries(
    Object.entries(snapshot.approved_disposition_decisions ?? {})
      .sort(([left], [right]) => left.localeCompare(right)),
  )));
  if (
    snapshot.schema_version !== "ioi.program.approved-source-dispositions.v1"
    || snapshot.document_class !== "work_record"
    || attestation.schema_version
      !== "ioi.program.source-disposition-approval-attestation.v1"
    || attestation.document_class !== "work_record"
    || snapshot.revision !== pins.revision
    || attestation.revision !== pins.revision
    || snapshot.transaction_id !== pins.transaction_id
    || attestation.transaction_id !== pins.transaction_id
    || stableJson(snapshot.predecessor) !== stableJson(predecessor)
    || stableJson(attestation.predecessor) !== stableJson(predecessor)
    || snapshot.current_path_count !== rows.length
    || attestation.current_path_count !== rows.length
    || rowsSha256 !== pins.complete_current_disposition_rows_sha256
    || snapshot.complete_current_disposition_rows_sha256 !== rowsSha256
    || attestation.complete_current_disposition_rows_sha256 !== rowsSha256
    || decisionsSha256 !== pins.approved_disposition_decisions_sha256
    || snapshot.approved_disposition_decisions_sha256 !== decisionsSha256
    || attestation.approved_disposition_decisions_sha256 !== decisionsSha256
    || attestation.approved_snapshot_path !== pins.snapshot_path
    || attestation.approved_snapshot_sha256 !== pins.snapshot_sha256
  ) {
    fail(`source-disposition approval revision ${pins.revision} has invalid identity, predecessor, rows, or decisions`);
  }
  return {
    revision: pins.revision,
    snapshot_path: pins.snapshot_path,
    snapshot_sha256: pins.snapshot_sha256,
    attestation_path: pins.attestation_path,
    attestation_sha256: pins.attestation_sha256,
    transaction_id: pins.transaction_id,
    rows,
    snapshot,
    attestation,
  };
}

function readAndValidateSourceDispositionApproval() {
  if (registry.migration_finalized !== true) {
    fail("source-disposition registry is not marked migration_finalized");
  }
  const chain = registry.source_disposition_approval_chain;
  if (!Array.isArray(chain) || chain.length !== 2) {
    fail("current estate requires the exact two-revision source-disposition approval chain");
  }
  const root = readAndValidatePinnedSourceDispositionApproval(
    SOURCE_DISPOSITION_APPROVAL_V1,
    null,
  );
  const successor = readAndValidatePinnedSourceDispositionApproval(
    SOURCE_DISPOSITION_APPROVAL_V2,
    approvalIdentity(SOURCE_DISPOSITION_APPROVAL_V1),
  );
  const expectedChain = [
    approvalIdentity(SOURCE_DISPOSITION_APPROVAL_V1),
    approvalIdentity(SOURCE_DISPOSITION_APPROVAL_V2),
  ];
  if (stableJson(chain) !== stableJson(expectedChain)) {
    fail("registry source-disposition approval chain differs from the two independent pins");
  }
  if (stableJson(successor.rows) !== stableJson(
    [...registry.current_paths].sort((left, right) => left.path.localeCompare(right.path)),
  )
    || successor.snapshot.current_path_count !== registry.current_paths.length
    || successor.snapshot.complete_current_disposition_rows_sha256
      !== registry.finalized_current_disposition_rows_sha256) {
    fail("latest source-disposition approval does not bind the finalized current registry");
  }
  return { ...successor, root };
}

function compactApprovalReference(approval) {
  return {
    revision: approval.revision,
    snapshot_path: approval.snapshot_path,
    snapshot_sha256: approval.snapshot_sha256,
    attestation_path: approval.attestation_path,
    attestation_sha256: approval.attestation_sha256,
    transaction_id: approval.transaction_id,
  };
}

function validatePreMigrationSnapshot() {
  if (!fs.existsSync(preMigrationAttestationPath)) fail("pre-migration snapshot attestation is missing");
  const attestation = readJson(preMigrationAttestationPath);
  if (attestation.schema_version !== "ioi.program.source-manifest-snapshot-attestation.v1"
    || attestation.document_class !== "work_record"
    || attestation.migration_role !== "pre_migration") {
    fail("pre-migration snapshot attestation has an invalid role or schema");
  }
  const expectedBaseline = SEALED_BASELINE;
  if (stableJson(registry.baseline) !== stableJson(SEALED_BASELINE)) fail("source-registry baseline differs from the checker-sealed pre-migration identity");
  if (stableJson(attestation.baseline) !== stableJson(expectedBaseline)) fail("pre-migration attestation baseline differs from the sealed source-registry baseline");
  if (existingSnapshots.length !== 1) fail(`expected exactly one content-addressed pre-migration manifest, found ${existingSnapshots.length}`);
  const snapshotName = existingSnapshots[0];
  const snapshotPath = path.join(historyRoot, snapshotName);
  const contentDigest = sha256File(snapshotPath);
  const filenameDigest = snapshotName.slice(0, 64);
  if (!/^[a-f0-9]{64}\.source-manifest\.v1\.json$/u.test(snapshotName) || filenameDigest !== contentDigest) {
    fail(`${snapshotName} is not named by its exact content SHA-256 ${contentDigest}`);
  }
  if (contentDigest !== SEALED_PRE_MIGRATION_SNAPSHOT_SHA256) fail(`pre-migration manifest differs from checker-sealed SHA-256 ${SEALED_PRE_MIGRATION_SNAPSHOT_SHA256}`);
  if (attestation.sealed_manifest_path !== implementationRelative(snapshotPath)
    || attestation.sealed_manifest_sha256 !== contentDigest) {
    fail("pre-migration snapshot identity differs from its attestation");
  }
  const snapshot = readJson(snapshotPath);
  if (snapshot.schema_version !== "ioi.program.source-manifest.v1" || snapshot.document_class !== "projection") fail("pre-migration manifest has an invalid schema or document class");
  if (stableJson(snapshot.baseline) !== stableJson(expectedBaseline)) fail("pre-migration manifest baseline differs from the sealed source-registry baseline");
  if (snapshot.counts?.baseline_sources !== expectedBaseline.source_count
    || snapshot.counts?.preserved_baseline_sources !== expectedBaseline.source_count
    || snapshot.sources?.length !== expectedBaseline.source_count
    || snapshot.sources?.some((entry) => entry.preserved !== true)) {
    fail("pre-migration manifest does not preserve all 73 baseline sources");
  }
  if (snapshot.counts?.current_materializations_excluding_self !== attestation.expected_pre_migration_materializations_excluding_self
    || snapshot.current_entries?.length !== attestation.expected_pre_migration_materializations_excluding_self) {
    fail("pre-migration materialization census differs from its attestation");
  }
  const sourceDigestRows = (snapshot.sources ?? []).map(({ source_path, baseline_sha256 }) => ({ source_path, baseline_sha256 }));
  const registryDigestRows = registry.sources.map(({ source_path, baseline_sha256 }) => ({ source_path, baseline_sha256 }));
  if (stableJson(sourceDigestRows) !== stableJson(registryDigestRows)) fail("pre-migration source paths/digests differ from the sealed baseline registry");
  if (new Set(snapshot.current_entries.map((entry) => entry.path)).size !== snapshot.current_entries.length) fail("pre-migration manifest contains duplicate current paths");
  return contentDigest;
}

function validatePreLinkRepairManifest() {
  if (!fs.existsSync(preLinkRepairManifestPath)) {
    fail("sealed pre-link-repair preservation manifest is missing");
  }
  const manifestSha256 = sha256File(preLinkRepairManifestPath);
  if (manifestSha256 !== SEALED_PRE_LINK_REPAIR_MANIFEST_SHA256) {
    fail(`pre-link-repair manifest differs from checker-sealed SHA-256 ${SEALED_PRE_LINK_REPAIR_MANIFEST_SHA256}`);
  }
  const repairManifest = readJson(preLinkRepairManifestPath);
  if (
    repairManifest.schema_version
      !== "ioi.program.pre-link-repair-snapshot-manifest.v1"
    || repairManifest.document_class !== "archive"
    || repairManifest.snapshot_date !== "2026-07-23"
    || !Array.isArray(repairManifest.entries)
    || repairManifest.entries.length !== 6
  ) {
    fail("pre-link-repair manifest has an invalid schema, role, date, or entry census");
  }
  const byDestinationAndDigest = new Map();
  const seenSnapshots = new Set();
  for (const entry of repairManifest.entries) {
    if (
      typeof entry.source_path !== "string"
      || typeof entry.snapshot_path !== "string"
      || !/^[0-9a-f]{64}$/u.test(entry.sha256 ?? "")
      || !Number.isInteger(entry.bytes)
      || entry.bytes < 0
      || path.isAbsolute(entry.source_path)
      || path.isAbsolute(entry.snapshot_path)
      || !entry.snapshot_path.startsWith("_archive/pre-link-repair/2026-07-23/")
    ) {
      fail("pre-link-repair manifest contains a malformed preservation row");
    }
    const key = `${entry.source_path}\0${entry.sha256}`;
    if (byDestinationAndDigest.has(key) || seenSnapshots.has(entry.snapshot_path)) {
      fail("pre-link-repair manifest contains duplicate source/digest or snapshot identities");
    }
    const snapshotAbsolute = path.resolve(implementationRoot, entry.snapshot_path);
    const snapshotRelative = path.relative(implementationRoot, snapshotAbsolute);
    if (
      snapshotRelative.startsWith("..")
      || path.isAbsolute(snapshotRelative)
      || !fs.existsSync(snapshotAbsolute)
      || !fs.statSync(snapshotAbsolute).isFile()
      || fs.statSync(snapshotAbsolute).size !== entry.bytes
      || sha256File(snapshotAbsolute) !== entry.sha256
    ) {
      fail(`pre-link-repair preservation row is not byte-exact: ${entry.snapshot_path}`);
    }
    byDestinationAndDigest.set(key, entry);
    seenSnapshots.add(entry.snapshot_path);
  }
  return {
    path: implementationRelative(preLinkRepairManifestPath),
    sha256: manifestSha256,
    entry_count: repairManifest.entries.length,
    by_destination_and_digest: byDestinationAndDigest,
  };
}

const preMigrationSnapshotSha256 = validatePreMigrationSnapshot();
const preLinkRepairManifest = validatePreLinkRepairManifest();
const currentByPath = new Map(registry.current_paths.map((entry) => [entry.path, entry]));

const markdownFiles = listTreeFiles(implementationRoot).filter((file) => {
  const relative = implementationRelative(file);
  return file.endsWith(".md")
    && !relative.startsWith("_archive/pre-unification-baseline/")
    && !relative.startsWith("_archive/originals/");
});
const inboundCounts = new Map();
for (const file of markdownFiles) {
  const resolutionBase = path.dirname(file);
  const source = fs.readFileSync(file, "utf8");
  for (const match of source.matchAll(/\[[^\]]*\]\(([^)]+)\)/gu)) {
    let target = match[1].trim();
    if (target.startsWith("<") && target.endsWith(">")) target = target.slice(1, -1);
    if (!target || /^(?:https?:|mailto:|data:|javascript:)/u.test(target)) continue;
    const [rawPath] = target.split("#", 1);
    const decodedPath = decodeURIComponent(rawPath || "");
    const targetFile = decodedPath ? path.resolve(resolutionBase, decodedPath) : file;
    const relativeTarget = path.relative(implementationRoot, targetFile).split(path.sep).join("/");
    if (relativeTarget.startsWith("../") || !currentByPath.has(relativeTarget) || !fs.existsSync(targetFile)) continue;
    inboundCounts.set(relativeTarget, (inboundCounts.get(relativeTarget) ?? 0) + 1);
  }
}

function buildCurrentEntries(exclusions) {
  const excluded = new Set(exclusions);
  return listTreeFiles(implementationRoot)
    .map((file) => ({ file, relative: implementationRelative(file) }))
    .filter(({ relative }) => !excluded.has(relative))
    .map(({ file, relative }) => {
    const stat = fs.lstatSync(file);
    const disposition = currentByPath.get(relative);
    return {
      path: relative,
      sha256: stat.isSymbolicLink() ? sha256(`symlink:${fs.readlinkSync(file)}`) : sha256File(file),
      bytes: stat.isSymbolicLink() ? Buffer.byteLength(fs.readlinkSync(file)) : stat.size,
      materialization: stat.isSymbolicLink() ? "symlink" : "file",
      document_class: disposition?.document_class ?? null,
      disposition: disposition?.disposition ?? null,
      owner: disposition?.owner ?? null,
      source_path: disposition?.source_path ?? null,
      destination_path: disposition?.destination_path ?? null,
      tombstone_required: disposition?.tombstone_required ?? null,
      inbound_markdown_links: inboundCounts.get(relative) ?? 0,
    };
  });
}

const entries = buildCurrentEntries(["generated/source-manifest.v1.json"]);
function assertCompleteCurrentEntries(candidateEntries, label) {
  const incomplete = candidateEntries.filter((entry) => (
    entry.document_class === null
    || entry.disposition === null
    || entry.owner === null
    || entry.destination_path === null
    || typeof entry.tombstone_required !== "boolean"
  ));
  if (incomplete.length > 0) {
    fail(`${label} has incomplete current-path joins: ${incomplete.map((entry) => entry.path).join(", ")}`);
  }
}
assertCompleteCurrentEntries(entries, "ordinary source manifest");

const preservedSources = registry.sources.map((source) => {
  const preLinkRepairEntry = preLinkRepairManifest.by_destination_and_digest.get(
    `${source.destination_path}\0${source.baseline_sha256}`,
  );
  const candidates = [
    source.source_path,
    source.destination_path,
    source.preserved_body_path,
    preLinkRepairEntry?.snapshot_path,
  ]
    .filter((value, index, array) => value && array.indexOf(value) === index)
    .map((relative) => path.join(implementationRoot, relative))
    .filter((absolute) => fs.existsSync(absolute));
  const exactBody = candidates.find((candidate) => fs.statSync(candidate).isFile() && sha256File(candidate) === source.baseline_sha256);
  const exactBodyPath = exactBody ? implementationRelative(exactBody) : null;
  const preservedByPreLinkManifest = Boolean(
    exactBodyPath
      && preLinkRepairEntry
      && exactBodyPath === preLinkRepairEntry.snapshot_path,
  );
  return {
    source_path: source.source_path,
    baseline_sha256: source.baseline_sha256,
    exact_body_path: exactBodyPath,
    preservation_basis: exactBodyPath
      ? preservedByPreLinkManifest
        ? "sealed_pre_link_repair_manifest"
        : "registry_declared_path"
      : null,
    preservation_manifest_ref: preservedByPreLinkManifest
      ? preLinkRepairManifest.path
      : null,
    preservation_manifest_sha256: preservedByPreLinkManifest
      ? preLinkRepairManifest.sha256
      : null,
    destination_path: source.destination_path,
    tombstone_required: source.tombstone_required,
    compatibility_hold: source.compatibility_hold,
    preserved: Boolean(exactBody),
  };
});

const manifest = {
  schema_version: "ioi.program.source-manifest.v1",
  document_class: "projection",
  generated_by: "node internal-docs/implementation/tools/freeze-source-manifest.mjs --write",
  checked_by: "node internal-docs/implementation/tools/freeze-source-manifest.mjs --check",
  inputs: {
    source_registry: "source-dispositions.v1.json",
    source_registry_sha256: sha256File(registryPath),
    pre_migration_snapshot_attestation: "audits/reconciliation/source-manifests/pre-migration-snapshot.attestation.v1.json",
    pre_migration_snapshot_sha256: preMigrationSnapshotSha256,
    pre_link_repair_manifest: preLinkRepairManifest.path,
    pre_link_repair_manifest_sha256: preLinkRepairManifest.sha256,
    pre_link_repair_manifest_entry_count: preLinkRepairManifest.entry_count,
    self_exclusion: "generated/source-manifest.v1.json is excluded to avoid a recursive digest",
  },
  baseline: registry.baseline,
  counts: {
    current_materializations_excluding_self: entries.length,
    preserved_baseline_sources: preservedSources.filter((entry) => entry.preserved).length,
    baseline_sources: preservedSources.length,
    compatibility_holds: preservedSources.filter((entry) => entry.compatibility_hold).length,
  },
  sources: preservedSources,
  current_entries: entries,
};

function postMigrationPinsAreComplete() {
  const hashKeys = [
    "snapshot_sha256",
    "attestation_sha256",
    "source_registry_sha256",
    "full_disposition_rows_sha256",
    "registry_current_path_set_sha256",
    "snapshot_path_set_sha256",
    "approval_oracle_sha256",
    "approval_oracle_metadata_sha256",
    "source_disposition_approved_snapshot_sha256",
    "source_disposition_approval_attestation_sha256",
  ];
  return hashKeys.every((key) => /^[0-9a-f]{64}$/u.test(SEALED_POST_MIGRATION[key] ?? ""))
    && Number.isInteger(SEALED_POST_MIGRATION.registry_current_path_count)
    && SEALED_POST_MIGRATION.registry_current_path_count > 0
    && Number.isInteger(SEALED_POST_MIGRATION.snapshot_materialization_count)
    && SEALED_POST_MIGRATION.snapshot_materialization_count > 0
    && Number.isInteger(SEALED_POST_MIGRATION.source_disposition_approval_revision)
    && SEALED_POST_MIGRATION.source_disposition_approval_revision > 0
    && typeof SEALED_POST_MIGRATION.source_disposition_transaction_id === "string"
    && SEALED_POST_MIGRATION.source_disposition_transaction_id.length > 0;
}

function validateRecursionExclusionRegistryCoverageFor(exclusions, label) {
  const missing = exclusions.filter((relative) => (
    !currentByPath.has(relative)
  ));
  if (missing.length > 0) {
    fail(`${label} recursion exclusions lack source-registry coverage: ${missing.join(", ")}`);
  }
  return exclusions.map((relative) => {
    const row = currentByPath.get(relative);
    return {
      path: relative,
      document_class: row.document_class,
      disposition: row.disposition,
      owner: row.owner,
    };
  });
}

function validateRecursionExclusionRegistryCoverage() {
  return validateRecursionExclusionRegistryCoverageFor(
    POST_MIGRATION_RECURSION_EXCLUSIONS,
    "post-migration",
  );
}

function buildPostMigrationSnapshot() {
  const oracle = readAndValidateApprovalOracle();
  const sourceDispositionApproval = readAndValidateSourceDispositionApproval();
  const exclusionRegistryRows = validateRecursionExclusionRegistryCoverage();
  const postEntries = buildCurrentEntries(POST_MIGRATION_RECURSION_EXCLUSIONS);
  assertCompleteCurrentEntries(postEntries, "post-migration source snapshot");
  if (new Set(postEntries.map((entry) => entry.path)).size !== postEntries.length) {
    fail("post-migration source snapshot contains duplicate materialization paths");
  }
  if (postEntries.some((entry) => POST_MIGRATION_RECURSION_EXCLUSIONS.includes(entry.path))) {
    fail("post-migration source snapshot contains a declared recursion exclusion");
  }
  const dispositionRows = [...registry.current_paths]
    .sort((left, right) => left.path.localeCompare(right.path));
  const sourcePreservationRows = preservedSources.map((entry) => ({
    source_path: entry.source_path,
    baseline_sha256: entry.baseline_sha256,
    exact_body_path: entry.exact_body_path,
    preserved: entry.preserved,
  }));
  return {
    schema_version: "ioi.program.source-manifest.v1",
    document_class: "projection",
    migration_role: "post_migration_sealed_snapshot",
    transaction_id: POST_MIGRATION_TRANSACTION_ID,
    generated_by: "node internal-docs/implementation/tools/freeze-source-manifest.mjs --seal-post-migration",
    checked_by: "node internal-docs/implementation/tools/freeze-source-manifest.mjs --check",
    inputs: {
      source_registry: implementationRelative(registryPath),
      source_registry_sha256: sha256File(registryPath),
      full_disposition_rows_sha256: dispositionRowsDigest(registry),
      registry_current_path_count: registry.current_paths.length,
      registry_current_path_set_sha256: pathSetDigest(
        registry.current_paths.map((entry) => entry.path),
      ),
      source_disposition_approval: sourceDispositionApproval,
      pre_link_repair_manifest: preLinkRepairManifest.path,
      pre_link_repair_manifest_sha256: preLinkRepairManifest.sha256,
      pre_link_repair_manifest_entry_count: preLinkRepairManifest.entry_count,
      approval_oracle: oracle.path,
      approval_oracle_sha256: oracle.sha256,
      approval_oracle_metadata_sha256: oracle.metadata_sha256,
      recursion_exclusions: {
        reason: "The ordinary generated manifest and post snapshot/attestation prevent direct or mutual recursion; the checker is the minimal independently pinned trust root whose embedded seal constants would otherwise create an impossible fixed-point hash.",
        paths: POST_MIGRATION_RECURSION_EXCLUSIONS,
        recursive_output_paths: POST_MIGRATION_RECURSIVE_OUTPUT_EXCLUSIONS,
        independent_pin_trust_root_paths: POST_MIGRATION_TRUST_ROOT_EXCLUSIONS,
        source_registry_coverage_required: true,
        source_registry_rows: exclusionRegistryRows,
      },
    },
    baseline: registry.baseline,
    counts: {
      current_materializations_excluding_exact_recursion_set: postEntries.length,
      filesystem_materializations_including_exact_recursion_set:
        postEntries.length + POST_MIGRATION_RECURSION_EXCLUSIONS.length,
      excluded_recursive_materializations: POST_MIGRATION_RECURSION_EXCLUSIONS.length,
      registered_current_paths: registry.current_paths.length,
      preserved_baseline_sources: preservedSources.filter((entry) => entry.preserved).length,
      baseline_sources: preservedSources.length,
      compatibility_holds: preservedSources.filter((entry) => entry.compatibility_hold).length,
    },
    integrity: {
      current_entry_path_set_sha256: pathSetDigest(postEntries.map((entry) => entry.path)),
      preserved_source_body_rows_sha256: sha256(stableJson(sourcePreservationRows)),
    },
    sealed_disposition_rows: dispositionRows,
    sources: preservedSources,
    current_entries: postEntries,
  };
}

function buildPostMigrationAttestation(snapshot, snapshotSha256) {
  return {
    schema_version: "ioi.program.source-manifest-snapshot-attestation.v1",
    document_class: "work_record",
    migration_role: "post_migration",
    transaction_id: POST_MIGRATION_TRANSACTION_ID,
    sealed_manifest_path: implementationRelative(postMigrationSnapshotPath),
    sealed_manifest_sha256: snapshotSha256,
    baseline: snapshot.baseline,
    source_registry_seal: {
      path: snapshot.inputs.source_registry,
      sha256: snapshot.inputs.source_registry_sha256,
      full_disposition_rows_sha256: snapshot.inputs.full_disposition_rows_sha256,
      baseline_source_count: snapshot.sources.length,
      current_path_count: snapshot.inputs.registry_current_path_count,
      current_path_set_sha256: snapshot.inputs.registry_current_path_set_sha256,
      approval_revision: snapshot.inputs.source_disposition_approval.revision,
      approved_snapshot_path: snapshot.inputs.source_disposition_approval.snapshot_path,
      approved_snapshot_sha256: snapshot.inputs.source_disposition_approval.snapshot_sha256,
      approval_attestation_path:
        snapshot.inputs.source_disposition_approval.attestation_path,
      approval_attestation_sha256:
        snapshot.inputs.source_disposition_approval.attestation_sha256,
      source_disposition_transaction_id:
        snapshot.inputs.source_disposition_approval.transaction_id,
    },
    approval_oracle_seal: {
      path: snapshot.inputs.approval_oracle,
      sha256: snapshot.inputs.approval_oracle_sha256,
      metadata_sha256: snapshot.inputs.approval_oracle_metadata_sha256,
      transaction_id: POST_MIGRATION_TRANSACTION_ID,
    },
    path_census: {
      snapshot_materializations_excluding_recursion:
        snapshot.counts.current_materializations_excluding_exact_recursion_set,
      snapshot_path_set_sha256: snapshot.integrity.current_entry_path_set_sha256,
      exact_recursion_exclusions: POST_MIGRATION_RECURSION_EXCLUSIONS,
      recursive_output_exclusions: POST_MIGRATION_RECURSIVE_OUTPUT_EXCLUSIONS,
      independent_pin_trust_root_exclusions: POST_MIGRATION_TRUST_ROOT_EXCLUSIONS,
      excluded_path_count: POST_MIGRATION_RECURSION_EXCLUSIONS.length,
      exclusions_remain_source_registry_covered: true,
    },
    preserved_baseline: {
      expected_source_count: SEALED_BASELINE.source_count,
      observed_source_count: snapshot.counts.baseline_sources,
      preserved_source_count: snapshot.counts.preserved_baseline_sources,
      all_exact_bodies_preserved:
        snapshot.counts.preserved_baseline_sources === SEALED_BASELINE.source_count,
      preserved_source_body_rows_sha256:
        snapshot.integrity.preserved_source_body_rows_sha256,
    },
    owns: "the immutable post-migration path, disposition, preservation, approval-oracle, and recursion-exclusion snapshot for the SA-1-through-SA-9 directory transaction",
    does_not_own: [
      "source disposition",
      "stage order",
      "work activation",
      "implementation status",
      "architecture doctrine",
      "future ordinary source-manifest projections",
    ],
    nonclaim: "This attestation proves only the sealed private migration inventory and its named inputs. It implements no runtime behavior and closes no work item or stage.",
  };
}

function postMigrationV1Identity() {
  return {
    revision: 1,
    snapshot_path: implementationRelative(postMigrationSnapshotPath),
    snapshot_sha256: SEALED_POST_MIGRATION.snapshot_sha256,
    attestation_path: implementationRelative(postMigrationAttestationPath),
    attestation_sha256: SEALED_POST_MIGRATION.attestation_sha256,
    transaction_id: POST_MIGRATION_TRANSACTION_ID,
  };
}

function currentSuccessorV2ReviewedInputs() {
  return Object.fromEntries(Object.entries(SUCCESSOR_V2_REVIEW_PATHS).map(([name, relative]) => {
    const absolute = path.join(implementationRoot, relative);
    if (!fs.existsSync(absolute) || !fs.lstatSync(absolute).isFile()) {
      fail(`successor-v2 reviewed input is missing or not a regular file: ${relative}`);
    }
    return [name, { path: relative, sha256: sha256File(absolute) }];
  }));
}

function successorV2PinsAreComplete() {
  const hashKeys = [
    "snapshot_sha256",
    "attestation_sha256",
    "source_registry_sha256",
    "full_disposition_rows_sha256",
    "registry_current_path_set_sha256",
    "snapshot_path_set_sha256",
    "approval_oracle_sha256",
    "approval_oracle_metadata_sha256",
    "source_disposition_approved_snapshot_sha256",
    "source_disposition_approval_attestation_sha256",
    "predecessor_snapshot_sha256",
    "predecessor_attestation_sha256",
    "correction_report_sha256",
    "delegated_review_sha256",
  ];
  return hashKeys.every((key) => (
    /^[0-9a-f]{64}$/u.test(SEALED_POST_MIGRATION_SUCCESSOR_V2[key] ?? "")
  ))
    && Number.isInteger(SEALED_POST_MIGRATION_SUCCESSOR_V2.registry_current_path_count)
    && SEALED_POST_MIGRATION_SUCCESSOR_V2.registry_current_path_count > 0
    && Number.isInteger(SEALED_POST_MIGRATION_SUCCESSOR_V2.snapshot_materialization_count)
    && SEALED_POST_MIGRATION_SUCCESSOR_V2.snapshot_materialization_count > 0
    && SEALED_POST_MIGRATION_SUCCESSOR_V2.source_disposition_approval_revision === 2
    && SEALED_POST_MIGRATION_SUCCESSOR_V2.source_disposition_transaction_id
      === POST_MIGRATION_SUCCESSOR_V2_TRANSACTION_ID;
}

function buildPostMigrationSuccessorV2Snapshot() {
  const oracle = readAndValidateApprovalOracle();
  const sourceDispositionApproval = readAndValidateSourceDispositionApproval();
  const reviewedInputs = currentSuccessorV2ReviewedInputs();
  if (stableJson(sourceDispositionApproval.snapshot.reviewed_inputs)
    !== stableJson(reviewedInputs)
    || stableJson(sourceDispositionApproval.attestation.reviewed_inputs)
      !== stableJson(reviewedInputs)) {
    fail("source-disposition successor does not bind the current final correction report and delegated review");
  }
  const exclusionRegistryRows = validateRecursionExclusionRegistryCoverageFor(
    POST_MIGRATION_SUCCESSOR_V2_RECURSION_EXCLUSIONS,
    "post-migration successor-v2",
  );
  const successorEntries = buildCurrentEntries(
    POST_MIGRATION_SUCCESSOR_V2_RECURSION_EXCLUSIONS,
  );
  assertCompleteCurrentEntries(successorEntries, "post-migration successor-v2 snapshot");
  if (new Set(successorEntries.map((entry) => entry.path)).size
    !== successorEntries.length) {
    fail("post-migration successor-v2 snapshot contains duplicate materialization paths");
  }
  if (successorEntries.some((entry) => (
    POST_MIGRATION_SUCCESSOR_V2_RECURSION_EXCLUSIONS.includes(entry.path)
  ))) {
    fail("post-migration successor-v2 snapshot contains a declared recursion exclusion");
  }
  const dispositionRows = [...registry.current_paths]
    .sort((left, right) => left.path.localeCompare(right.path));
  const sourcePreservationRows = preservedSources.map((entry) => ({
    source_path: entry.source_path,
    baseline_sha256: entry.baseline_sha256,
    exact_body_path: entry.exact_body_path,
    preserved: entry.preserved,
  }));
  return {
    schema_version: "ioi.program.source-manifest.v1",
    document_class: "projection",
    revision: 2,
    migration_role: "post_migration_successor_sealed_snapshot",
    transaction_id: POST_MIGRATION_SUCCESSOR_V2_TRANSACTION_ID,
    predecessor: postMigrationV1Identity(),
    generated_by: "node internal-docs/implementation/tools/freeze-source-manifest.mjs --seal-successor-v2",
    checked_by: "node internal-docs/implementation/tools/freeze-source-manifest.mjs --check",
    inputs: {
      source_registry: implementationRelative(registryPath),
      source_registry_sha256: sha256File(registryPath),
      full_disposition_rows_sha256: dispositionRowsDigest(registry),
      registry_current_path_count: registry.current_paths.length,
      registry_current_path_set_sha256: pathSetDigest(
        registry.current_paths.map((entry) => entry.path),
      ),
      source_disposition_approval: compactApprovalReference(sourceDispositionApproval),
      reviewed_inputs: reviewedInputs,
      pre_link_repair_manifest: preLinkRepairManifest.path,
      pre_link_repair_manifest_sha256: preLinkRepairManifest.sha256,
      pre_link_repair_manifest_entry_count: preLinkRepairManifest.entry_count,
      approval_oracle: oracle.path,
      approval_oracle_sha256: oracle.sha256,
      approval_oracle_metadata_sha256: oracle.metadata_sha256,
      recursion_exclusions: {
        reason: "The ordinary generated manifest and revision-2 successor snapshot/attestation prevent direct or mutual recursion; the checker remains the minimal independently pinned trust root whose embedded successor hashes would otherwise require an impossible fixed point.",
        paths: POST_MIGRATION_SUCCESSOR_V2_RECURSION_EXCLUSIONS,
        recursive_output_paths:
          POST_MIGRATION_SUCCESSOR_V2_RECURSIVE_OUTPUT_EXCLUSIONS,
        independent_pin_trust_root_paths:
          POST_MIGRATION_SUCCESSOR_V2_TRUST_ROOT_EXCLUSIONS,
        source_registry_coverage_required: true,
        source_registry_rows: exclusionRegistryRows,
      },
    },
    baseline: registry.baseline,
    counts: {
      current_materializations_excluding_exact_recursion_set:
        successorEntries.length,
      filesystem_materializations_including_exact_recursion_set:
        successorEntries.length
          + POST_MIGRATION_SUCCESSOR_V2_RECURSION_EXCLUSIONS.length,
      excluded_recursive_materializations:
        POST_MIGRATION_SUCCESSOR_V2_RECURSION_EXCLUSIONS.length,
      registered_current_paths: registry.current_paths.length,
      preserved_baseline_sources: preservedSources.filter((entry) => entry.preserved).length,
      baseline_sources: preservedSources.length,
      compatibility_holds: preservedSources.filter((entry) => entry.compatibility_hold).length,
    },
    integrity: {
      current_entry_path_set_sha256: pathSetDigest(
        successorEntries.map((entry) => entry.path),
      ),
      current_entry_rows_sha256: sha256(stableJson(successorEntries)),
      preserved_source_body_rows_sha256: sha256(stableJson(sourcePreservationRows)),
    },
    sealed_disposition_rows: dispositionRows,
    sources: preservedSources,
    current_entries: successorEntries,
  };
}

function buildPostMigrationSuccessorV2Attestation(snapshot, snapshotSha256) {
  return {
    schema_version: "ioi.program.source-manifest-snapshot-attestation.v1",
    document_class: "work_record",
    revision: 2,
    migration_role: "post_migration_successor",
    transaction_id: POST_MIGRATION_SUCCESSOR_V2_TRANSACTION_ID,
    predecessor: postMigrationV1Identity(),
    sealed_manifest_path: implementationRelative(postMigrationSuccessorV2SnapshotPath),
    sealed_manifest_sha256: snapshotSha256,
    baseline: snapshot.baseline,
    source_registry_seal: {
      path: snapshot.inputs.source_registry,
      sha256: snapshot.inputs.source_registry_sha256,
      full_disposition_rows_sha256: snapshot.inputs.full_disposition_rows_sha256,
      baseline_source_count: snapshot.sources.length,
      current_path_count: snapshot.inputs.registry_current_path_count,
      current_path_set_sha256: snapshot.inputs.registry_current_path_set_sha256,
      approval_revision: snapshot.inputs.source_disposition_approval.revision,
      approved_snapshot_path: snapshot.inputs.source_disposition_approval.snapshot_path,
      approved_snapshot_sha256: snapshot.inputs.source_disposition_approval.snapshot_sha256,
      approval_attestation_path:
        snapshot.inputs.source_disposition_approval.attestation_path,
      approval_attestation_sha256:
        snapshot.inputs.source_disposition_approval.attestation_sha256,
      source_disposition_transaction_id:
        snapshot.inputs.source_disposition_approval.transaction_id,
    },
    reviewed_input_seal: snapshot.inputs.reviewed_inputs,
    approval_oracle_seal: {
      path: snapshot.inputs.approval_oracle,
      sha256: snapshot.inputs.approval_oracle_sha256,
      metadata_sha256: snapshot.inputs.approval_oracle_metadata_sha256,
      transaction_id: POST_MIGRATION_TRANSACTION_ID,
    },
    path_census: {
      snapshot_materializations_excluding_recursion:
        snapshot.counts.current_materializations_excluding_exact_recursion_set,
      snapshot_path_set_sha256: snapshot.integrity.current_entry_path_set_sha256,
      snapshot_entry_rows_sha256: snapshot.integrity.current_entry_rows_sha256,
      exact_recursion_exclusions:
        POST_MIGRATION_SUCCESSOR_V2_RECURSION_EXCLUSIONS,
      recursive_output_exclusions:
        POST_MIGRATION_SUCCESSOR_V2_RECURSIVE_OUTPUT_EXCLUSIONS,
      independent_pin_trust_root_exclusions:
        POST_MIGRATION_SUCCESSOR_V2_TRUST_ROOT_EXCLUSIONS,
      excluded_path_count:
        POST_MIGRATION_SUCCESSOR_V2_RECURSION_EXCLUSIONS.length,
      exclusions_remain_source_registry_covered: true,
    },
    preserved_baseline: {
      expected_source_count: SEALED_BASELINE.source_count,
      observed_source_count: snapshot.counts.baseline_sources,
      preserved_source_count: snapshot.counts.preserved_baseline_sources,
      all_exact_bodies_preserved:
        snapshot.counts.preserved_baseline_sources === SEALED_BASELINE.source_count,
      preserved_source_body_rows_sha256:
        snapshot.integrity.preserved_source_body_rows_sha256,
    },
    owns: "the immutable current-estate successor to the retained revision-1 post-migration seal after bounded phase-6 verifier corrections",
    does_not_own: [
      "source disposition",
      "stage order",
      "work activation",
      "implementation status",
      "architecture doctrine",
      "future ordinary source-manifest projections",
    ],
    nonclaim: "This successor attestation proves only the named private inventory and reviewed verifier-correction inputs. It implements no runtime behavior and closes no work item or stage.",
  };
}

function sealPostMigrationPlaceholders() {
  if (postMigrationPinsAreComplete()) {
    fail("post-migration pins are already populated; the one-time seal writer is disabled");
  }
  for (const candidate of [postMigrationSnapshotPath, postMigrationAttestationPath]) {
    if (!fs.existsSync(candidate) || stableJson(readJson(candidate)) !== stableJson({})) {
      fail(`${implementationRelative(candidate)} is not the empty reviewed seal placeholder`);
    }
  }
  const ordinaryFreshness = checkDeterministic(outputPath, manifest);
  if (!ordinaryFreshness.ok) {
    fail(`ordinary source manifest must be fresh before sealing: ${ordinaryFreshness.reason}`);
  }
  if (manifest.counts.preserved_baseline_sources !== SEALED_BASELINE.source_count) {
    fail("cannot seal before all 73 exact baseline bodies are preserved");
  }
  const snapshot = buildPostMigrationSnapshot();
  const snapshotSha256 = sha256(stableJson(snapshot));
  const attestation = buildPostMigrationAttestation(snapshot, snapshotSha256);
  const attestationSha256 = sha256(stableJson(attestation));
  writeDeterministic(postMigrationSnapshotPath, snapshot);
  writeDeterministic(postMigrationAttestationPath, attestation);
  process.stdout.write(`${stableJson({
    snapshot_sha256: snapshotSha256,
    attestation_sha256: attestationSha256,
    source_registry_sha256: snapshot.inputs.source_registry_sha256,
    full_disposition_rows_sha256: snapshot.inputs.full_disposition_rows_sha256,
    registry_current_path_set_sha256: snapshot.inputs.registry_current_path_set_sha256,
    registry_current_path_count: snapshot.inputs.registry_current_path_count,
    snapshot_path_set_sha256: snapshot.integrity.current_entry_path_set_sha256,
    snapshot_materialization_count:
      snapshot.counts.current_materializations_excluding_exact_recursion_set,
    approval_oracle_sha256: snapshot.inputs.approval_oracle_sha256,
    approval_oracle_metadata_sha256: snapshot.inputs.approval_oracle_metadata_sha256,
    source_disposition_approval_revision:
      snapshot.inputs.source_disposition_approval.revision,
    source_disposition_approved_snapshot_sha256:
      snapshot.inputs.source_disposition_approval.snapshot_sha256,
    source_disposition_approval_attestation_sha256:
      snapshot.inputs.source_disposition_approval.attestation_sha256,
    source_disposition_transaction_id:
      snapshot.inputs.source_disposition_approval.transaction_id,
  })}`);
  process.stdout.write("Post-migration placeholders were sealed. Pin the printed values in SEALED_POST_MIGRATION, refresh only the ordinary manifest, and run --check.\n");
}

function sealPostMigrationSuccessorV2Placeholders() {
  if (successorV2PinsAreComplete()) {
    fail("post-migration successor-v2 pins are already populated; the one-time successor writer is disabled");
  }
  if (!approvalPinsAreComplete(SOURCE_DISPOSITION_APPROVAL_V2)) {
    fail("source-disposition approval revision 2 must be checker-pinned before sealing the post-migration successor");
  }
  requirePinnedSourceDispositionChecker();
  validateHistoricalPostMigrationSealV1();
  for (const candidate of [
    postMigrationSuccessorV2SnapshotPath,
    postMigrationSuccessorV2AttestationPath,
  ]) {
    if (!fs.existsSync(candidate) || stableJson(readJson(candidate)) !== stableJson({})) {
      fail(`${implementationRelative(candidate)} is not the empty reviewed successor-seal placeholder`);
    }
  }
  const ordinaryFreshness = checkDeterministic(outputPath, manifest);
  if (!ordinaryFreshness.ok) {
    fail(`ordinary source manifest must be fresh before successor sealing: ${ordinaryFreshness.reason}`);
  }
  if (manifest.counts.preserved_baseline_sources !== SEALED_BASELINE.source_count) {
    fail("cannot seal the successor before all 73 exact baseline bodies are preserved");
  }
  const snapshot = buildPostMigrationSuccessorV2Snapshot();
  const snapshotSha256 = sha256(stableJson(snapshot));
  const attestation = buildPostMigrationSuccessorV2Attestation(snapshot, snapshotSha256);
  const attestationSha256 = sha256(stableJson(attestation));
  writeDeterministic(postMigrationSuccessorV2SnapshotPath, snapshot);
  writeDeterministic(postMigrationSuccessorV2AttestationPath, attestation);
  process.stdout.write(stableJson({
    snapshot_sha256: snapshotSha256,
    attestation_sha256: attestationSha256,
    source_registry_sha256: snapshot.inputs.source_registry_sha256,
    full_disposition_rows_sha256: snapshot.inputs.full_disposition_rows_sha256,
    registry_current_path_set_sha256: snapshot.inputs.registry_current_path_set_sha256,
    registry_current_path_count: snapshot.inputs.registry_current_path_count,
    snapshot_path_set_sha256: snapshot.integrity.current_entry_path_set_sha256,
    snapshot_materialization_count:
      snapshot.counts.current_materializations_excluding_exact_recursion_set,
    approval_oracle_sha256: snapshot.inputs.approval_oracle_sha256,
    approval_oracle_metadata_sha256: snapshot.inputs.approval_oracle_metadata_sha256,
    source_disposition_approval_revision:
      snapshot.inputs.source_disposition_approval.revision,
    source_disposition_approved_snapshot_sha256:
      snapshot.inputs.source_disposition_approval.snapshot_sha256,
    source_disposition_approval_attestation_sha256:
      snapshot.inputs.source_disposition_approval.attestation_sha256,
    source_disposition_transaction_id:
      snapshot.inputs.source_disposition_approval.transaction_id,
    predecessor_snapshot_sha256: snapshot.predecessor.snapshot_sha256,
    predecessor_attestation_sha256: snapshot.predecessor.attestation_sha256,
    correction_report_sha256:
      snapshot.inputs.reviewed_inputs.correction_report.sha256,
    delegated_review_sha256:
      snapshot.inputs.reviewed_inputs.delegated_review.sha256,
  }));
  process.stdout.write("Post-migration successor-v2 placeholders were sealed. Pin every printed value in SEALED_POST_MIGRATION_SUCCESSOR_V2, refresh only the ordinary manifest, and run --check.\n");
}

function validateHistoricalPostMigrationSealV1() {
  if (!postMigrationPinsAreComplete()) {
    fail("post-migration snapshot pins are intentionally unsealed pending final source-registry confirmation");
  }
  if (!fs.existsSync(postMigrationSnapshotPath) || !fs.existsSync(postMigrationAttestationPath)) {
    fail("post-migration snapshot or attestation is missing");
  }
  const actualSnapshotSha256 = sha256File(postMigrationSnapshotPath);
  const actualAttestationSha256 = sha256File(postMigrationAttestationPath);
  if (actualSnapshotSha256 !== SEALED_POST_MIGRATION.snapshot_sha256) {
    fail(`post-migration snapshot differs from independently pinned SHA-256 ${SEALED_POST_MIGRATION.snapshot_sha256}`);
  }
  if (actualAttestationSha256 !== SEALED_POST_MIGRATION.attestation_sha256) {
    fail(`post-migration attestation differs from independently pinned SHA-256 ${SEALED_POST_MIGRATION.attestation_sha256}`);
  }

  const oracle = readAndValidateApprovalOracle();
  const sourceDispositionApproval = readAndValidatePinnedSourceDispositionApproval(
    SOURCE_DISPOSITION_APPROVAL_V1,
    null,
  );
  const revisionOnePathSet = new Set(
    sourceDispositionApproval.rows.map((entry) => entry.path),
  );
  const revisionOneRowsByPath = new Map(
    sourceDispositionApproval.rows.map((entry) => [entry.path, entry]),
  );
  const reconstructedV1Registry = {
    ...registry,
    // The revision-2 writer appends rows without reordering the root registry,
    // so filtering its additions reproduces the exact revision-1 file bytes.
    current_paths: registry.current_paths.filter((entry) => (
      revisionOnePathSet.has(entry.path)
    )).map((entry) => revisionOneRowsByPath.get(entry.path)),
    finalized_current_path_set_sha256:
      SEALED_POST_MIGRATION.registry_current_path_set_sha256,
    finalized_current_disposition_rows_sha256:
      SEALED_POST_MIGRATION.full_disposition_rows_sha256,
    source_disposition_approval_chain: [approvalIdentity(SOURCE_DISPOSITION_APPROVAL_V1)],
  };
  const historicalPins = {
    source_registry_sha256: sha256(stableJson(reconstructedV1Registry)),
    full_disposition_rows_sha256: dispositionRowsDigest(sourceDispositionApproval.rows),
    registry_current_path_set_sha256: pathSetDigest(
      sourceDispositionApproval.rows.map((entry) => entry.path),
    ),
    registry_current_path_count: sourceDispositionApproval.rows.length,
    approval_oracle_sha256: oracle.sha256,
    approval_oracle_metadata_sha256: oracle.metadata_sha256,
    source_disposition_approval_revision: sourceDispositionApproval.revision,
    source_disposition_approved_snapshot_sha256:
      sourceDispositionApproval.snapshot_sha256,
    source_disposition_approval_attestation_sha256:
      sourceDispositionApproval.attestation_sha256,
    source_disposition_transaction_id: sourceDispositionApproval.transaction_id,
  };
  for (const [key, value] of Object.entries(historicalPins)) {
    if (value !== SEALED_POST_MIGRATION[key]) {
      fail(`reconstructed historical revision-1 ${key} differs from the independent pin`);
    }
  }
  const snapshot = readJson(postMigrationSnapshotPath);
  const attestation = readJson(postMigrationAttestationPath);
  const sealedRowsByPath = new Map(
    (snapshot.sealed_disposition_rows ?? []).map((entry) => [entry.path, entry]),
  );
  const exclusionRegistryRows = POST_MIGRATION_RECURSION_EXCLUSIONS.map((relative) => {
    const row = sealedRowsByPath.get(relative);
    if (!row) fail(`historical post-migration revision-1 exclusion lacks a sealed row: ${relative}`);
    return {
      path: relative,
      document_class: row.document_class,
      disposition: row.disposition,
      owner: row.owner,
    };
  });
  if (
    snapshot.schema_version !== "ioi.program.source-manifest.v1"
    || snapshot.document_class !== "projection"
    || snapshot.migration_role !== "post_migration_sealed_snapshot"
    || snapshot.transaction_id !== POST_MIGRATION_TRANSACTION_ID
  ) {
    fail("post-migration snapshot has an invalid schema, role, or transaction ID");
  }
  if (stableJson(snapshot.baseline) !== stableJson(SEALED_BASELINE)) {
    fail("post-migration snapshot baseline differs from the checker-sealed migration baseline");
  }
  if (
    attestation.schema_version !== "ioi.program.source-manifest-snapshot-attestation.v1"
    || attestation.document_class !== "work_record"
    || attestation.migration_role !== "post_migration"
    || attestation.transaction_id !== POST_MIGRATION_TRANSACTION_ID
  ) {
    fail("post-migration attestation has an invalid schema, role, or transaction ID");
  }
  if (
    snapshot.inputs.source_registry_sha256 !== SEALED_POST_MIGRATION.source_registry_sha256
    || snapshot.inputs.full_disposition_rows_sha256
      !== SEALED_POST_MIGRATION.full_disposition_rows_sha256
    || snapshot.inputs.registry_current_path_set_sha256
      !== SEALED_POST_MIGRATION.registry_current_path_set_sha256
    || snapshot.inputs.registry_current_path_count
      !== SEALED_POST_MIGRATION.registry_current_path_count
    || snapshot.inputs.pre_link_repair_manifest !== preLinkRepairManifest.path
    || snapshot.inputs.pre_link_repair_manifest_sha256 !== preLinkRepairManifest.sha256
    || snapshot.inputs.pre_link_repair_manifest_entry_count
      !== preLinkRepairManifest.entry_count
    || snapshot.inputs.approval_oracle_sha256
      !== SEALED_POST_MIGRATION.approval_oracle_sha256
    || snapshot.inputs.approval_oracle_metadata_sha256
      !== SEALED_POST_MIGRATION.approval_oracle_metadata_sha256
    || stableJson(snapshot.inputs.source_disposition_approval)
      !== stableJson(compactApprovalReference(sourceDispositionApproval))
  ) {
    fail("post-migration snapshot input pins differ from the independent checker pins");
  }
  if (dispositionRowsDigest(snapshot.sealed_disposition_rows ?? {})
    !== SEALED_POST_MIGRATION.full_disposition_rows_sha256) {
    fail("post-migration snapshot full disposition rows differ from their pinned digest");
  }
  if (stableJson(snapshot.sealed_disposition_rows) !== stableJson(sourceDispositionApproval.rows)) {
    fail("historical post-migration revision-1 rows differ from the immutable revision-1 approval snapshot");
  }
  if (stableJson(snapshot.inputs.recursion_exclusions?.paths)
    !== stableJson(POST_MIGRATION_RECURSION_EXCLUSIONS)
    || stableJson(attestation.path_census?.exact_recursion_exclusions)
      !== stableJson(POST_MIGRATION_RECURSION_EXCLUSIONS)) {
    fail("post-migration snapshot or attestation changes the exact recursion-exclusion set");
  }
  if (
    stableJson(snapshot.inputs.recursion_exclusions?.recursive_output_paths)
      !== stableJson(POST_MIGRATION_RECURSIVE_OUTPUT_EXCLUSIONS)
    || stableJson(snapshot.inputs.recursion_exclusions?.independent_pin_trust_root_paths)
      !== stableJson(POST_MIGRATION_TRUST_ROOT_EXCLUSIONS)
    || stableJson(attestation.path_census?.recursive_output_exclusions)
      !== stableJson(POST_MIGRATION_RECURSIVE_OUTPUT_EXCLUSIONS)
    || stableJson(attestation.path_census?.independent_pin_trust_root_exclusions)
      !== stableJson(POST_MIGRATION_TRUST_ROOT_EXCLUSIONS)
  ) {
    fail("post-migration snapshot or attestation blurs recursive outputs and the independent checker trust root");
  }
  if (stableJson(snapshot.inputs.recursion_exclusions?.source_registry_rows)
    !== stableJson(exclusionRegistryRows)) {
    fail("post-migration recursion exclusions differ from their source-registry rows");
  }
  const snapshotPaths = (snapshot.current_entries ?? []).map((entry) => entry.path);
  if (new Set(snapshotPaths).size !== snapshotPaths.length) {
    fail("post-migration snapshot contains duplicate materialization paths");
  }
  if (snapshotPaths.some((entry) => POST_MIGRATION_RECURSION_EXCLUSIONS.includes(entry))) {
    fail("post-migration snapshot contains a recursive self/peer hash path");
  }
  if (
    snapshotPaths.length !== SEALED_POST_MIGRATION.snapshot_materialization_count
    || snapshot.counts?.current_materializations_excluding_exact_recursion_set
      !== SEALED_POST_MIGRATION.snapshot_materialization_count
    || snapshot.integrity?.current_entry_path_set_sha256
      !== SEALED_POST_MIGRATION.snapshot_path_set_sha256
    || pathSetDigest(snapshotPaths) !== SEALED_POST_MIGRATION.snapshot_path_set_sha256
  ) {
    fail("post-migration snapshot path census differs from its independent pins");
  }
  if (
    snapshot.counts?.excluded_recursive_materializations
      !== POST_MIGRATION_RECURSION_EXCLUSIONS.length
    || snapshot.counts?.filesystem_materializations_including_exact_recursion_set
      !== snapshotPaths.length + POST_MIGRATION_RECURSION_EXCLUSIONS.length
    || snapshot.inputs.recursion_exclusions?.source_registry_coverage_required !== true
    || attestation.path_census?.excluded_path_count
      !== POST_MIGRATION_RECURSION_EXCLUSIONS.length
    || attestation.path_census?.exclusions_remain_source_registry_covered !== true
  ) {
    fail("post-migration snapshot has an invalid recursion-exclusion census or coverage claim");
  }
  if (
    snapshot.counts?.baseline_sources !== SEALED_BASELINE.source_count
    || snapshot.counts?.preserved_baseline_sources !== SEALED_BASELINE.source_count
    || snapshot.sources?.length !== SEALED_BASELINE.source_count
    || snapshot.sources.some((entry) => entry.preserved !== true)
  ) {
    fail("post-migration snapshot does not preserve all 73 exact baseline bodies");
  }
  const snapshotSourceRows = snapshot.sources.map(({ source_path, baseline_sha256 }) => ({
    source_path,
    baseline_sha256,
  }));
  const registrySourceRows = registry.sources.map(({ source_path, baseline_sha256 }) => ({
    source_path,
    baseline_sha256,
  }));
  if (stableJson(snapshotSourceRows) !== stableJson(registrySourceRows)) {
    fail("historical post-migration snapshot baseline source identities differ from the retained registry baseline");
  }
  const snapshotPreservationRows = snapshot.sources.map((entry) => ({
    source_path: entry.source_path,
    baseline_sha256: entry.baseline_sha256,
    exact_body_path: entry.exact_body_path,
    preserved: entry.preserved,
  }));
  if (sha256(stableJson(snapshotPreservationRows))
    !== snapshot.integrity?.preserved_source_body_rows_sha256) {
    fail("post-migration snapshot preserved-body rows differ from their sealed digest");
  }
  if (preservedSources.some((entry) => entry.preserved !== true)) {
    fail("a baseline body preserved by the post-migration seal is no longer available exactly");
  }
  const expectedAttestation = buildPostMigrationAttestation(
    snapshot,
    actualSnapshotSha256,
  );
  if (stableJson(attestation) !== stableJson(expectedAttestation)) {
    fail("historical post-migration revision-1 attestation differs from its deterministic sealed form");
  }
}

function validatePostMigrationSuccessorV2Seal() {
  if (!successorV2PinsAreComplete()) {
    fail("post-migration successor-v2 pins are intentionally unsealed pending the final correction report and delegated review");
  }
  if (!approvalPinsAreComplete(SOURCE_DISPOSITION_APPROVAL_V2)) {
    fail("source-disposition approval revision 2 is not independently pinned");
  }
  requirePinnedSourceDispositionChecker();
  if (!fs.existsSync(postMigrationSuccessorV2SnapshotPath)
    || !fs.existsSync(postMigrationSuccessorV2AttestationPath)) {
    fail("post-migration successor-v2 snapshot or attestation is missing");
  }
  const actualSnapshotSha256 = sha256File(postMigrationSuccessorV2SnapshotPath);
  const actualAttestationSha256 = sha256File(postMigrationSuccessorV2AttestationPath);
  if (actualSnapshotSha256
    !== SEALED_POST_MIGRATION_SUCCESSOR_V2.snapshot_sha256) {
    fail(`post-migration successor-v2 snapshot differs from independently pinned SHA-256 ${SEALED_POST_MIGRATION_SUCCESSOR_V2.snapshot_sha256}`);
  }
  if (actualAttestationSha256
    !== SEALED_POST_MIGRATION_SUCCESSOR_V2.attestation_sha256) {
    fail(`post-migration successor-v2 attestation differs from independently pinned SHA-256 ${SEALED_POST_MIGRATION_SUCCESSOR_V2.attestation_sha256}`);
  }

  const oracle = readAndValidateApprovalOracle();
  const sourceDispositionApproval = readAndValidateSourceDispositionApproval();
  const reviewedInputs = currentSuccessorV2ReviewedInputs();
  const currentPins = {
    source_registry_sha256: sha256File(registryPath),
    full_disposition_rows_sha256: dispositionRowsDigest(registry),
    registry_current_path_set_sha256: pathSetDigest(
      registry.current_paths.map((entry) => entry.path),
    ),
    registry_current_path_count: registry.current_paths.length,
    approval_oracle_sha256: oracle.sha256,
    approval_oracle_metadata_sha256: oracle.metadata_sha256,
    source_disposition_approval_revision: sourceDispositionApproval.revision,
    source_disposition_approved_snapshot_sha256:
      sourceDispositionApproval.snapshot_sha256,
    source_disposition_approval_attestation_sha256:
      sourceDispositionApproval.attestation_sha256,
    source_disposition_transaction_id: sourceDispositionApproval.transaction_id,
    predecessor_snapshot_sha256: SEALED_POST_MIGRATION.snapshot_sha256,
    predecessor_attestation_sha256: SEALED_POST_MIGRATION.attestation_sha256,
    correction_report_sha256: reviewedInputs.correction_report.sha256,
    delegated_review_sha256: reviewedInputs.delegated_review.sha256,
  };
  for (const [key, value] of Object.entries(currentPins)) {
    if (value !== SEALED_POST_MIGRATION_SUCCESSOR_V2[key]) {
      fail(`current successor-v2 ${key} differs from its independent pin`);
    }
  }

  const snapshot = readJson(postMigrationSuccessorV2SnapshotPath);
  const attestation = readJson(postMigrationSuccessorV2AttestationPath);
  if (
    snapshot.schema_version !== "ioi.program.source-manifest.v1"
    || snapshot.document_class !== "projection"
    || snapshot.revision !== 2
    || snapshot.migration_role !== "post_migration_successor_sealed_snapshot"
    || snapshot.transaction_id !== POST_MIGRATION_SUCCESSOR_V2_TRANSACTION_ID
    || stableJson(snapshot.predecessor) !== stableJson(postMigrationV1Identity())
  ) {
    fail("post-migration successor-v2 snapshot has an invalid schema, role, transaction, revision, or predecessor");
  }
  if (
    attestation.schema_version !== "ioi.program.source-manifest-snapshot-attestation.v1"
    || attestation.document_class !== "work_record"
    || attestation.revision !== 2
    || attestation.migration_role !== "post_migration_successor"
    || attestation.transaction_id !== POST_MIGRATION_SUCCESSOR_V2_TRANSACTION_ID
    || stableJson(attestation.predecessor) !== stableJson(postMigrationV1Identity())
  ) {
    fail("post-migration successor-v2 attestation has an invalid schema, role, transaction, revision, or predecessor");
  }
  if (snapshot.integrity?.current_entry_rows_sha256
    !== sha256(stableJson(snapshot.current_entries ?? []))) {
    fail("post-migration successor-v2 current-entry rows differ from their sealed digest");
  }
  if (snapshot.integrity?.current_entry_path_set_sha256
    !== pathSetDigest((snapshot.current_entries ?? []).map((entry) => entry.path))) {
    fail("post-migration successor-v2 path set differs from its sealed digest");
  }
  if (snapshot.integrity.current_entry_path_set_sha256
    !== SEALED_POST_MIGRATION_SUCCESSOR_V2.snapshot_path_set_sha256
    || snapshot.current_entries.length
      !== SEALED_POST_MIGRATION_SUCCESSOR_V2.snapshot_materialization_count) {
    fail("post-migration successor-v2 path census differs from its independent pins");
  }

  const expectedSnapshot = buildPostMigrationSuccessorV2Snapshot();
  if (stableJson(snapshot) !== stableJson(expectedSnapshot)) {
    fail("post-migration successor-v2 snapshot no longer matches the exact current private estate");
  }
  const expectedAttestation = buildPostMigrationSuccessorV2Attestation(
    snapshot,
    actualSnapshotSha256,
  );
  if (stableJson(attestation) !== stableJson(expectedAttestation)) {
    fail("post-migration successor-v2 attestation differs from its deterministic sealed form");
  }
}

if (mode === "--seal-post-migration") {
  sealPostMigrationPlaceholders();
} else if (mode === "--seal-successor-v2") {
  sealPostMigrationSuccessorV2Placeholders();
} else if (mode === "--write") {
  writeDeterministic(outputPath, manifest);
  process.stdout.write(`source manifest written: ${manifest.counts.preserved_baseline_sources}/${manifest.counts.baseline_sources} baseline bodies preserved\n`);
} else {
  const result = checkDeterministic(outputPath, manifest);
  if (!result.ok) {
    process.stderr.write(`${result.reason}\n`);
    process.exit(1);
  }
  if (manifest.counts.preserved_baseline_sources !== manifest.counts.baseline_sources) {
    const missing = preservedSources.filter((entry) => !entry.preserved).map((entry) => entry.source_path);
    fail(`missing exact baseline bodies: ${missing.join(", ")}`);
  }
  validateHistoricalPostMigrationSealV1();
  validatePostMigrationSuccessorV2Seal();
  process.stdout.write(`source manifest check passed: ${entries.length} ordinary materializations, ${preservedSources.length} exact baseline bodies, immutable revision-1 history, and the independently pinned current successor-v2 snapshot/attestation\n`);
}
