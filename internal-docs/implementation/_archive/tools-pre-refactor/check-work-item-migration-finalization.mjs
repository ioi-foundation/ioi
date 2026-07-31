#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import {
  failWith,
  implementationRoot,
  readJson,
  repoRoot,
  sha256,
  sha256File,
  stableJson,
  STATUS_VALUES,
} from "./lib.mjs";
import { contentBoundLiteralEvidence } from "./content-bound-literal.mjs";

const FINALIZATION_SCHEMA = "ioi.program.work-item-migration-finalization.v1";
const MANIFEST_SCHEMA = "ioi.program.work-item-migration-final-records.v1";
const PRESERVATION_SCHEMA = "ioi.program.work-item-status-preservation.v1";
const TRANSACTION_SCHEMA = "ioi.program.work-item-status-transaction.v1";
const FINALIZATION_RELATIVE = "audits/reconciliation/work-item-migration-finalization.v1.json";
const MANIFEST_RELATIVE = "audits/reconciliation/work-item-migration-final-records.v1.json";
const PRESERVATION_RELATIVE = "audits/reconciliation/work-item-status-preservation.v1.json";
const ARCHIVED_REPLAY_RELATIVE = "_archive/reconciliation-tools/migrate-work-items.replay-approved-transaction.mjs";
const LIVE_MIGRATOR_RELATIVE = "tools/migrate-work-items.mjs";
const BASELINE_ROOT_RELATIVE = "_archive/pre-unification-baseline/work-items";
const RECORD_DIGEST_ALGORITHM = "SHA-256 over pretty JSON plus final newline for the work_item_id-sorted array of {work_item_id,status,sha256(file_bytes)} rows";
const ISO_DATE = /^\d{4}-\d{2}-\d{2}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const WORK_ITEM_ID = /^[a-z0-9]+(?:-[a-z0-9]+)*$/u;
const FINALIZATION_KEYS = [
  "schema_version", "document_class", "transaction", "finalized_on",
  "one_time_replay_command", "migration_tool_sha256",
  "status_preservation_audit", "final_record_set", "future_maintenance_rule",
  "owns", "does_not_own", "nonclaim",
].sort();
const PRESERVATION_AUDIT_KEYS = [
  "path", "sha256", "pre_existing_record_count",
  "pre_existing_status_values_changed", "added_proposed_record_count",
  "successful_exit_logs_created",
].sort();
const FINAL_RECORD_SET_KEYS = [
  "record_count", "status_counts_at_finalization", "digest_algorithm", "sha256",
].sort();
const PRESERVATION_KEYS = [
  "schema_version", "captured_at", "before_count", "before", "rule",
  "after_count", "added_count", "after_statuses", "existing_statuses_unchanged",
  "new_records_all_proposed", "no_exit_logs_created", "nonclaims",
].sort();
const MANIFEST_KEYS = [
  "schema_version", "document_class", "transaction", "finalized_on",
  "digest_algorithm", "record_count", "status_counts_at_finalization",
  "record_rows", "sha256", "owns", "nonclaim",
].sort();
const TRANSACTION_KEYS = [
  "schema_version",
  "sequence",
  "work_item_id",
  "transaction_on",
  "from_status",
  "to_status",
  "prior_record_sha256",
  "current_record_payload_sha256",
  "previous_transaction_sha256",
  "evidence_refs",
  "literal_exit",
  "transaction_sha256",
].sort();

function sorted(value) {
  return [...value].sort((left, right) => left.localeCompare(right));
}

function equalJson(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function statusCounts(rows) {
  return rows.reduce((counts, row) => {
    counts[row.status] = (counts[row.status] ?? 0) + 1;
    return counts;
  }, {});
}

function recordRowsDigest(rows) {
  return sha256(stableJson(rows.map(({ work_item_id, status, sha256: fileSha256 }) => ({
    work_item_id,
    status,
    sha256: fileSha256,
  }))));
}

function recordPayloadSha256(record) {
  const payload = { ...record };
  delete payload.status_transaction_chain;
  return sha256(stableJson(payload));
}

function transactionDigest(transaction) {
  const payload = { ...transaction };
  delete payload.transaction_sha256;
  return sha256(stableJson(payload));
}

function safeReadJson(relative, errors, label) {
  const absolute = path.join(implementationRoot, relative);
  try {
    return readJson(absolute);
  } catch (error) {
    errors.push(`${label} is missing or invalid JSON at ${relative}: ${error.message}`);
    return null;
  }
}

function validateStatusChain(record, baseline, finalizedOn, errors) {
  const label = record.work_item_id ?? "unknown-work-item";
  const chain = record.status_transaction_chain;
  const isFinalizedRecord = baseline !== undefined;
  if (chain === undefined) {
    if (isFinalizedRecord && record.status !== baseline.status) {
      errors.push(`${label}: status changed from finalized ${baseline.status} to ${record.status} without status_transaction_chain`);
    }
    if (!isFinalizedRecord) {
      errors.push(`${label}: post-finalization work item requires a genesis status_transaction_chain`);
    }
    return;
  }
  if (!Array.isArray(chain) || chain.length === 0) {
    errors.push(`${label}: status_transaction_chain must be a nonempty array when present`);
    return;
  }

  let previous = null;
  for (let index = 0; index < chain.length; index += 1) {
    const transaction = chain[index];
    const txLabel = `${label}: status_transaction_chain[${index}]`;
    if (!transaction || typeof transaction !== "object" || Array.isArray(transaction)) {
      errors.push(`${txLabel} must be an object`);
      continue;
    }
    if (!equalJson(sorted(Object.keys(transaction)), TRANSACTION_KEYS)) {
      errors.push(`${txLabel} must contain exactly ${TRANSACTION_KEYS.join(", ")}`);
    }
    if (transaction.schema_version !== TRANSACTION_SCHEMA) errors.push(`${txLabel} has wrong schema_version`);
    if (transaction.sequence !== index + 1) errors.push(`${txLabel} sequence must equal ${index + 1}`);
    if (transaction.work_item_id !== label) errors.push(`${txLabel} work_item_id does not bind its owner record`);
    if (!ISO_DATE.test(transaction.transaction_on ?? "")) errors.push(`${txLabel} transaction_on must be an ISO date`);
    else if (transaction.transaction_on < finalizedOn) errors.push(`${txLabel} predates migration finalization ${finalizedOn}`);
    if (!STATUS_VALUES.has(transaction.to_status)) errors.push(`${txLabel} has unknown to_status ${transaction.to_status}`);
    if (transaction.from_status !== null && !STATUS_VALUES.has(transaction.from_status)) errors.push(`${txLabel} has unknown from_status ${transaction.from_status}`);
    if (transaction.from_status === transaction.to_status) errors.push(`${txLabel} must record an actual status transition`);
    if (!SHA256.test(transaction.current_record_payload_sha256 ?? "")) errors.push(`${txLabel} has malformed current_record_payload_sha256`);
    if (!Array.isArray(transaction.evidence_refs)) errors.push(`${txLabel} evidence_refs must be an array`);
    const evidenceRefs = Array.isArray(transaction.evidence_refs) ? transaction.evidence_refs : [];
    if (new Set(evidenceRefs).size !== evidenceRefs.length) errors.push(`${txLabel} evidence_refs must be unique`);
    if (transaction.from_status !== null && evidenceRefs.length === 0) errors.push(`${txLabel} status transition requires retained evidence_refs`);
    for (const ref of evidenceRefs) {
      if (typeof ref !== "string" || ref.length === 0 || path.isAbsolute(ref)) {
        errors.push(`${txLabel} has malformed repository-relative evidence ref ${String(ref)}`);
        continue;
      }
      const absolute = path.resolve(repoRoot, ref);
      const relative = path.relative(repoRoot, absolute);
      if (relative.startsWith("..") || path.isAbsolute(relative)) errors.push(`${txLabel} evidence ref escapes the repository: ${ref}`);
      else if (!(record.evidence_refs ?? []).includes(ref)) errors.push(`${txLabel} evidence ref is not retained by the owning record: ${ref}`);
      else if (!fs.existsSync(absolute) || !fs.statSync(absolute).isFile()) errors.push(`${txLabel} retained evidence ref is unavailable: ${ref}`);
    }

    if (index === 0 && isFinalizedRecord) {
      if (transaction.from_status !== baseline.status) errors.push(`${txLabel} must start from finalized status ${baseline.status}`);
      if (transaction.prior_record_sha256 !== baseline.sha256) errors.push(`${txLabel} must anchor the finalized record SHA`);
      if (transaction.previous_transaction_sha256 !== null) errors.push(`${txLabel} first transaction must have null previous_transaction_sha256`);
    } else if (index === 0) {
      if (transaction.from_status !== null) errors.push(`${txLabel} post-finalization genesis must start from null`);
      if (transaction.prior_record_sha256 !== null) errors.push(`${txLabel} post-finalization genesis must have null prior_record_sha256`);
      if (transaction.previous_transaction_sha256 !== null) errors.push(`${txLabel} post-finalization genesis must have null previous_transaction_sha256`);
    } else {
      if (transaction.from_status !== previous.to_status) errors.push(`${txLabel} from_status does not continue the preceding to_status`);
      if (transaction.prior_record_sha256 !== previous.current_record_payload_sha256) errors.push(`${txLabel} prior_record_sha256 does not continue the preceding payload`);
      if (transaction.previous_transaction_sha256 !== previous.transaction_sha256) errors.push(`${txLabel} previous_transaction_sha256 does not continue the hash chain`);
      if (ISO_DATE.test(transaction.transaction_on ?? "") && transaction.transaction_on < previous.transaction_on) errors.push(`${txLabel} transaction date moves backward`);
    }

    const expectedTransactionSha256 = transactionDigest(transaction);
    if (transaction.transaction_sha256 !== expectedTransactionSha256) errors.push(`${txLabel} transaction_sha256 does not bind the exact transaction payload`);
    if (transaction.to_status === "verified") {
      const expectedLiteral = record.evidence_index?.literal_exit;
      if (transaction.literal_exit !== expectedLiteral) errors.push(`${txLabel} verified transition must bind the owning exact literal exit`);
      const expectedPaths = new Set(record.evidence_index?.expected_output_paths ?? []);
      const strictLiteralRefs = evidenceRefs.filter((ref) => (
        expectedPaths.has(ref) && contentBoundLiteralEvidence(ref, expectedLiteral)
      ));
      if (strictLiteralRefs.length !== 1) errors.push(`${txLabel} verified transition requires exactly one expected-path content-bound literal exit`);
    } else if (transaction.literal_exit !== null) {
      errors.push(`${txLabel} non-verified transition must use null literal_exit`);
    }
    previous = transaction;
  }

  const last = chain.at(-1);
  if (last?.to_status !== record.status) errors.push(`${label}: current status does not equal the chain head to_status`);
  if (last?.transaction_on !== record.last_status_transaction) errors.push(`${label}: last_status_transaction does not equal the chain head date`);
  if (last?.current_record_payload_sha256 !== recordPayloadSha256(record)) errors.push(`${label}: chain head does not bind the current record payload excluding the chain`);
}

export function validateWorkItemMigrationFinalization() {
  const errors = [];
  const finalization = safeReadJson(FINALIZATION_RELATIVE, errors, "migration finalization");
  const manifest = safeReadJson(MANIFEST_RELATIVE, errors, "final record manifest");
  const preservation = safeReadJson(PRESERVATION_RELATIVE, errors, "status preservation ledger");
  if (!finalization || !manifest || !preservation) return { errors, record_count: 0, chain_count: 0 };

  if (!equalJson(sorted(Object.keys(finalization)), FINALIZATION_KEYS)) errors.push("migration finalization has unexpected or missing fields");
  if (finalization.schema_version !== FINALIZATION_SCHEMA) errors.push("migration finalization schema_version mismatch");
  if (finalization.document_class !== "work_record") errors.push("migration finalization must remain a work_record");
  if (!ISO_DATE.test(finalization.finalized_on ?? "")) errors.push("migration finalization finalized_on must be an ISO date");
  if (typeof finalization.transaction !== "string" || finalization.transaction.length === 0) errors.push("migration finalization transaction must be nonempty");
  if (finalization.one_time_replay_command !== "node internal-docs/implementation/tools/migrate-work-items.mjs --replay-approved-transaction") errors.push("migration finalization historical replay command changed");
  if (!equalJson(sorted(Object.keys(finalization.status_preservation_audit ?? {})), PRESERVATION_AUDIT_KEYS)) errors.push("migration finalization preservation-audit schema mismatch");
  if (!equalJson(sorted(Object.keys(finalization.final_record_set ?? {})), FINAL_RECORD_SET_KEYS)) errors.push("migration finalization record-set schema mismatch");
  if (finalization.final_record_set?.digest_algorithm !== RECORD_DIGEST_ALGORITHM) errors.push("migration finalization record digest algorithm changed");
  if (!SHA256.test(finalization.migration_tool_sha256 ?? "")) errors.push("migration finalization has malformed migration_tool_sha256");
  if (!SHA256.test(finalization.final_record_set?.sha256 ?? "")) errors.push("migration finalization has malformed final record-set SHA");
  if (typeof finalization.future_maintenance_rule !== "string"
    || !finalization.future_maintenance_rule.includes("permanently refuses replay independent")
    || !finalization.future_maintenance_rule.includes("archived replay-capable bytes are audit evidence only")
    || !finalization.future_maintenance_rule.includes("status_transaction_chain")) {
    errors.push("migration finalization retains a sentinel-deletion replay premise or lacks append-only maintenance terms");
  }
  if (!Array.isArray(finalization.does_not_own) || !finalization.does_not_own.includes("live work-item status")) errors.push("migration finalization must disclaim live status ownership");
  if (typeof finalization.nonclaim !== "string" || !finalization.nonclaim.includes("close no work item or stage")) errors.push("migration finalization lacks its closure nonclaim");

  const archivedReplayPath = path.join(implementationRoot, ARCHIVED_REPLAY_RELATIVE);
  if (!fs.existsSync(archivedReplayPath)) errors.push(`archived replay tool is missing: ${ARCHIVED_REPLAY_RELATIVE}`);
  else if (sha256File(archivedReplayPath) !== finalization.migration_tool_sha256) errors.push("archived replay tool bytes differ from the finalized migration-tool SHA");
  const liveMigratorPath = path.join(implementationRoot, LIVE_MIGRATOR_RELATIVE);
  if (!fs.existsSync(liveMigratorPath)) errors.push(`live migration entry point is missing: ${LIVE_MIGRATOR_RELATIVE}`);
  else {
    const liveSource = fs.readFileSync(liveMigratorPath, "utf8");
    for (const writerToken of ["writeFileSync", "appendFileSync", "renameSync", "copyFileSync"]) {
      if (liveSource.includes(writerToken)) errors.push(`live migration entry point retains forbidden writer primitive ${writerToken}`);
    }
    if (!liveSource.includes("--check-finalization") || !liveSource.includes("permanently refused")) errors.push("live migration entry point lacks permanent refusal/check-finalization behavior");
  }

  if (!equalJson(sorted(Object.keys(preservation)), PRESERVATION_KEYS)) errors.push("status preservation ledger has unexpected or missing fields");
  if (preservation.schema_version !== PRESERVATION_SCHEMA) errors.push("status preservation ledger schema_version mismatch");
  if (!ISO_DATE.test(preservation.captured_at ?? "")) errors.push("status preservation ledger captured_at must be an ISO date");
  if (!Number.isInteger(preservation.before_count) || preservation.before_count < 1) errors.push("status preservation ledger before_count must be a positive integer");
  if (!Array.isArray(preservation.before) || preservation.before.length !== preservation.before_count) errors.push("status preservation ledger before rows do not match before_count");
  const preservationRows = Array.isArray(preservation.before) ? preservation.before : [];
  const preservationIds = preservationRows.map((row) => row.work_item_id);
  if (new Set(preservationIds).size !== preservationIds.length) errors.push("status preservation ledger has duplicate baseline identities");
  if (!equalJson(preservationIds, sorted(preservationIds))) errors.push("status preservation ledger baseline identities must be sorted");
  for (const row of preservationRows) {
    if (!row || !equalJson(sorted(Object.keys(row ?? {})), ["sha256", "status", "work_item_id"])) errors.push(`status preservation row ${row?.work_item_id ?? "unknown"} has unexpected schema`);
    if (!WORK_ITEM_ID.test(row?.work_item_id ?? "")) errors.push(`status preservation row has malformed work_item_id ${row?.work_item_id}`);
    if (!STATUS_VALUES.has(row?.status)) errors.push(`status preservation row ${row?.work_item_id} has unknown status ${row?.status}`);
    if (!SHA256.test(row?.sha256 ?? "")) errors.push(`status preservation row ${row?.work_item_id} has malformed SHA`);
    const baselinePath = path.join(implementationRoot, BASELINE_ROOT_RELATIVE, `${row?.work_item_id}.v1.json`);
    if (!fs.existsSync(baselinePath)) errors.push(`status preservation baseline is missing for ${row?.work_item_id}`);
    else if (sha256File(baselinePath) !== row.sha256) errors.push(`status preservation baseline SHA mismatch for ${row.work_item_id}`);
  }
  const preservationPath = path.join(implementationRoot, PRESERVATION_RELATIVE);
  if (finalization.status_preservation_audit?.path !== PRESERVATION_RELATIVE) {
    errors.push("migration finalization points at the wrong preservation ledger");
  }
  if (finalization.status_preservation_audit?.sha256 !== sha256File(preservationPath)) errors.push("status preservation ledger bytes differ from the finalized SHA");
  if (finalization.status_preservation_audit?.pre_existing_record_count !== preservation.before_count) errors.push("finalization pre-existing record count differs from preservation ledger");
  if (finalization.status_preservation_audit?.pre_existing_status_values_changed !== 0 || preservation.existing_statuses_unchanged !== true) errors.push("finalization must retain zero baseline status changes");
  if (finalization.status_preservation_audit?.added_proposed_record_count !== preservation.added_count || preservation.new_records_all_proposed !== true) errors.push("finalization added-record facts differ from preservation ledger");
  if (finalization.status_preservation_audit?.successful_exit_logs_created !== 0 || preservation.no_exit_logs_created !== true) errors.push("migration finalization must retain the zero-exit-log nonclaim");
  if (preservation.after_count !== preservation.before_count + preservation.added_count) errors.push("status preservation ledger before/added/after counts do not balance");
  if (preservation.after_count !== finalization.final_record_set?.record_count) errors.push("status preservation ledger after_count differs from finalization");
  if (!equalJson(preservation.after_statuses, finalization.final_record_set?.status_counts_at_finalization)) errors.push("status preservation ledger status counts differ from finalization");
  if (!Array.isArray(preservation.nonclaims) || preservation.nonclaims.length === 0) errors.push("status preservation ledger must retain nonclaims");

  if (!equalJson(sorted(Object.keys(manifest)), MANIFEST_KEYS)) errors.push("final record manifest has unexpected or missing fields");
  if (manifest.schema_version !== MANIFEST_SCHEMA) errors.push("final record manifest schema_version mismatch");
  if (manifest.document_class !== "work_record") errors.push("final record manifest must remain a work_record");
  if (manifest.transaction !== finalization.transaction) errors.push("final record manifest transaction differs from finalization");
  if (manifest.finalized_on !== finalization.finalized_on) errors.push("final record manifest date differs from finalization");
  if (manifest.digest_algorithm !== RECORD_DIGEST_ALGORITHM) errors.push("final record manifest digest algorithm changed");
  if (typeof manifest.owns !== "string" || manifest.owns.length === 0) errors.push("final record manifest must declare its bounded ownership");
  if (typeof manifest.nonclaim !== "string" || !manifest.nonclaim.includes("closes no work item or stage")) errors.push("final record manifest lacks its closure nonclaim");
  const rows = Array.isArray(manifest.record_rows) ? manifest.record_rows : [];
  if (!Array.isArray(manifest.record_rows)) errors.push("final record manifest record_rows must be an array");
  if (manifest.record_count !== rows.length || manifest.record_count !== finalization.final_record_set?.record_count) errors.push("final record manifest count differs from its rows or finalization");
  const rowIds = rows.map((row) => row.work_item_id);
  if (new Set(rowIds).size !== rowIds.length) errors.push("final record manifest has duplicate work_item_id values");
  if (!equalJson(rowIds, sorted(rowIds))) errors.push("final record manifest rows must be work_item_id-sorted");
  for (const row of rows) {
    if (!row || !equalJson(sorted(Object.keys(row ?? {})), ["sha256", "status", "work_item_id"])) errors.push(`final record manifest row ${row?.work_item_id ?? "unknown"} has unexpected schema`);
    if (!WORK_ITEM_ID.test(row?.work_item_id ?? "")) errors.push(`final record manifest has malformed work_item_id ${row?.work_item_id}`);
    if (!STATUS_VALUES.has(row?.status)) errors.push(`final record manifest row ${row?.work_item_id} has unknown status ${row?.status}`);
    if (!SHA256.test(row?.sha256 ?? "")) errors.push(`final record manifest row ${row?.work_item_id} has malformed SHA`);
  }
  const counts = statusCounts(rows);
  if (!equalJson(counts, manifest.status_counts_at_finalization)) errors.push("final record manifest status counts do not equal its rows");
  if (!equalJson(counts, finalization.final_record_set?.status_counts_at_finalization)) errors.push("final record manifest status counts differ from finalization");
  const digest = recordRowsDigest(rows);
  if (manifest.sha256 !== digest) errors.push("final record manifest SHA does not bind its exact rows");
  if (finalization.final_record_set?.sha256 !== digest) errors.push("final record manifest rows do not match the finalized record-set SHA");

  const rowById = new Map(rows.map((row) => [row.work_item_id, row]));
  for (const baseline of preservationRows) {
    const finalized = rowById.get(baseline.work_item_id);
    if (!finalized) errors.push(`final record manifest omits preserved baseline identity ${baseline.work_item_id}`);
    else if (finalized.status !== baseline.status) errors.push(`final record manifest changed preserved status for ${baseline.work_item_id}`);
  }
  const addedRows = rows.filter((row) => !preservationIds.includes(row.work_item_id));
  if (addedRows.length !== preservation.added_count) errors.push("final record manifest added identity count differs from preservation ledger");
  if (addedRows.some((row) => row.status !== "proposed")) errors.push("final record manifest contains a non-proposed migration-added record");

  const workItemsRoot = path.join(implementationRoot, "work-items");
  const currentFiles = fs.existsSync(workItemsRoot)
    ? fs.readdirSync(workItemsRoot).filter((name) => name.endsWith(".v1.json")).sort()
    : [];
  const currentRecords = new Map();
  for (const name of currentFiles) {
    try {
      const record = readJson(path.join(workItemsRoot, name));
      if (currentRecords.has(record.work_item_id)) errors.push(`current work-item set has duplicate identity ${record.work_item_id}`);
      currentRecords.set(record.work_item_id, record);
    } catch (error) {
      errors.push(`current work item ${name} is invalid JSON: ${error.message}`);
    }
  }
  for (const row of rows) if (!currentRecords.has(row.work_item_id)) errors.push(`finalized work-item identity was removed: ${row.work_item_id}`);
  for (const record of currentRecords.values()) validateStatusChain(record, rowById.get(record.work_item_id), finalization.finalized_on, errors);

  return {
    errors,
    record_count: rows.length,
    current_record_count: currentRecords.size,
    chain_count: [...currentRecords.values()].filter((record) => Array.isArray(record.status_transaction_chain)).length,
    archived_replay_sha256: fs.existsSync(archivedReplayPath) ? sha256File(archivedReplayPath) : null,
    final_record_set_sha256: digest,
  };
}

export function printWorkItemMigrationFinalizationResult(result) {
  failWith("work-item migration finalization check", result.errors);
  process.stdout.write(
    `work-item migration finalization check passed: ${result.record_count} sealed records; ${result.current_record_count} current records; ${result.chain_count} post-finalization status chain(s); archived replay ${result.archived_replay_sha256}; final set ${result.final_record_set_sha256}\n`,
  );
}

const isMain = process.argv[1] !== undefined
  && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) printWorkItemMigrationFinalizationResult(validateWorkItemMigrationFinalization());
