// Exact aggregate-child/dependency/evidence binding shared by the refresher and
// the stage-certification gate.
//
// An aggregate record is not allowed to summarize child status or proof by
// prose. Its binding is a reproducible projection of:
//   * each selected child's and unconditional dependency's current record bytes;
//   * their current status;
//   * every retained evidence ref plus the declared literal-exit path; and
//   * the aggregate's own retained literal-exit evidence.
//
// The projection is deliberately independent of the aggregate record's own
// digest, avoiding a self-hash. Its own evidence binding is still exact: adding,
// removing, or changing retained aggregate evidence changes the payload digest.
import fs from "node:fs";
import path from "node:path";
import {
  ESTATE_ROOT,
  REPO_ROOT,
  sha256File,
  sha256Text,
} from "./estate.mjs";
import { refuseUnlessConformingLiteralExitLog } from "./literal-exit.mjs";

export const AGGREGATE_BINDING_SCHEMA =
  "ioi.program.aggregate-verification-binding.v1";

export const AGGREGATE_BINDING_NONCLAIM =
  "This exact-digest binding is a private closure precondition. It does not promote a child, dependency, proof gate, aggregate, work item, or stage and cannot substitute for literal-valid retained evidence.";

function stableJson(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function indexFor(record) {
  const index = record.evidence_index;
  return index && !Array.isArray(index) ? index : null;
}

function uniqueSortedStrings(values) {
  return [...new Set(values.filter((value) => typeof value === "string"))]
    .sort();
}

// Include both evidence carriers used by the estate. expected_output_paths is
// included even before it exists, so a missing promised exit log is represented
// explicitly instead of disappearing from the digest projection.
export function retainedEvidencePaths(record) {
  const index = indexFor(record);
  return uniqueSortedStrings([
    ...(record.evidence_refs ?? []),
    ...(index?.retained_refs ?? []),
    ...(index?.expected_output_paths ?? []),
  ]);
}

function exactLineCount(absolute, expected) {
  if (!expected || !fs.existsSync(absolute)) return 0;
  return fs.readFileSync(absolute, "utf8")
    .split(/\r?\n/u)
    .filter((line) => line === expected).length;
}

export function deriveEvidenceBinding(record, { repoRoot = REPO_ROOT } = {}) {
  const index = indexFor(record);
  const expectedLiteral = index?.literal_exit ?? null;
  const expectedPaths = uniqueSortedStrings(index?.expected_output_paths ?? []);
  const expectedSet = new Set(expectedPaths);
  const evidenceFiles = retainedEvidencePaths(record).map((relative) => {
    const absolute = path.resolve(repoRoot, relative);
    const inside = absolute === repoRoot || absolute.startsWith(`${repoRoot}${path.sep}`);
    const exists = inside && fs.existsSync(absolute);
    return {
      path: relative,
      exists,
      sha256: exists ? sha256File(absolute) : null,
      exact_literal_line_count: exists && expectedSet.has(relative)
        ? exactLineCount(absolute, expectedLiteral)
        : 0,
    };
  });
  const exactLiteralLineCount = evidenceFiles.reduce(
    (total, file) => total + file.exact_literal_line_count,
    0,
  );

  // Every object-shaped record in the governed estate declares one literal
  // output path. Validate that exact file through the same shared contract used
  // by transition.mjs and certify-stage.mjs; counting a string is not proof.
  const literalContractValid = Boolean(expectedLiteral) && expectedPaths.length === 1 &&
    refuseUnlessConformingLiteralExitLog(expectedPaths[0], {
      expectLiteral: expectedLiteral,
      repoRoot,
    }).length === 0;
  const body = {
    expected_literal: expectedLiteral,
    evidence_files: evidenceFiles,
    exact_literal_line_count: exactLiteralLineCount,
  };
  return {
    ...body,
    literal_valid: exactLiteralLineCount === 1 && literalContractValid,
    evidence_bundle_sha256: sha256Text(stableJson(body)),
  };
}

function recordsById(records) {
  return records instanceof Map
    ? records
    : new Map(records.map((record) => [record.work_item_id, record]));
}

function defaultRecordPath(record) {
  if (!record?.file) {
    throw new Error(`${record?.work_item_id ?? "record"} has no estate-relative file`);
  }
  return path.join(ESTATE_ROOT, record.file);
}

export function deriveAggregateVerificationBinding(
  aggregate,
  { records, recordPath = defaultRecordPath, repoRoot = REPO_ROOT } = {},
) {
  if (!aggregate || aggregate.record_role !== "aggregate_exit") {
    throw new Error("aggregate verification binding requires an aggregate_exit record");
  }
  if (!records) throw new Error("aggregate verification binding requires current records");
  const byId = recordsById(records);
  const resolve = (id) => {
    const record = byId.get(id);
    if (!record) throw new Error(`${aggregate.work_item_id} names missing record ${id}`);
    const absolute = recordPath(record);
    if (!fs.existsSync(absolute)) {
      throw new Error(`${aggregate.work_item_id} record path does not exist for ${id}: ${absolute}`);
    }
    return { record, sha256: sha256File(absolute) };
  };
  const dispositions = aggregate.aggregate_child_dispositions ?? [];
  const dispositionByChild = new Map(
    dispositions.map((entry) => [entry.child_work_item_id, entry]),
  );
  const bind = (id, relation, selectionState) => {
    const target = resolve(id);
    return {
      work_item_id: id,
      relation,
      selection_state: selectionState,
      record_sha256: target.sha256,
      status_at_binding: target.record.status,
      evidence_binding: deriveEvidenceBinding(target.record, { repoRoot }),
    };
  };
  const payload = {
    child_dispositions: dispositions,
    child_bindings: (aggregate.aggregate_child_ids ?? []).map((id) =>
      bind(
        id,
        "aggregate_child",
        dispositionByChild.get(id)?.selection_state ?? null,
      )
    ),
    dependency_bindings: (aggregate.dependency_work_item_ids ?? []).map((id) =>
      bind(id, "unconditional_dependency", null)
    ),
    aggregate_evidence_binding: deriveEvidenceBinding(aggregate, { repoRoot }),
  };
  return {
    schema_version: AGGREGATE_BINDING_SCHEMA,
    ...payload,
    binding_payload_sha256: sha256Text(stableJson(payload)),
    nonclaim: AGGREGATE_BINDING_NONCLAIM,
  };
}

// Pure record projection used by both transition admission and verified
// re-certification. Keeping this as a non-mutating helper makes the atomic
// caller testable without hand-editing a closure record in place.
export function reboundAggregateVerificationRecord(
  aggregate,
  options = {},
) {
  return {
    ...aggregate,
    aggregate_verification_binding: deriveAggregateVerificationBinding(
      aggregate,
      options,
    ),
  };
}

function same(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

export function validateRequiredNowPgGates(record) {
  const refusals = [];
  for (const gate of record?.pg_gate_states ?? []) {
    if (gate.applicability !== "required_now") continue;
    const where = `${record.work_item_id} ${gate.pg_id}`;
    if (gate.closure_status !== "closed") {
      refusals.push({
        check: "required-pg-gate-open",
        message: `${where} is required_now but ${gate.closure_status ?? "has no closure status"}`,
      });
      continue;
    }
    if (!gate.literal_exit || !Array.isArray(gate.evidence_refs)) {
      refusals.push({
        check: "required-pg-gate-evidence",
        message: `${where} is marked closed without a literal_exit and evidence_refs`,
      });
      continue;
    }
    const exact = gate.evidence_refs.filter((relative) => {
      const absolute = path.join(REPO_ROOT, relative);
      if (!fs.existsSync(absolute)) return false;
      return exactLineCount(absolute, gate.literal_exit) === 1;
    });
    if (exact.length !== 1) {
      refusals.push({
        check: "required-pg-gate-evidence",
        message: `${where} requires exactly one retained standalone ${gate.literal_exit}, found ${exact.length}`,
      });
      continue;
    }
    for (const refusal of refuseUnlessConformingLiteralExitLog(exact[0], {
      expectLiteral: gate.literal_exit,
    })) {
      refusals.push({
        check: refusal.check,
        message: `${where}: ${refusal.message}`,
      });
    }
  }
  return refusals;
}

// Returns stable named refusals. The caller decides how to render them.
export function validateAggregateVerificationBinding(
  aggregate,
  { records, recordPath = defaultRecordPath, repoRoot = REPO_ROOT } = {},
) {
  const refusals = [];
  let expected;
  try {
    expected = deriveAggregateVerificationBinding(aggregate, {
      records,
      recordPath,
      repoRoot,
    });
  } catch (error) {
    return [{
      check: "aggregate-binding-derivation",
      message: error.message,
    }];
  }
  const actual = aggregate.aggregate_verification_binding;
  if (!actual || typeof actual !== "object") {
    refusals.push({
      check: "aggregate-binding-missing",
      message: `${aggregate.work_item_id} has no aggregate_verification_binding`,
    });
    return refusals;
  }
  if (actual.schema_version !== AGGREGATE_BINDING_SCHEMA) {
    refusals.push({
      check: "aggregate-binding-schema",
      message: `${aggregate.work_item_id} aggregate binding schema is ${actual.schema_version ?? "absent"}, expected ${AGGREGATE_BINDING_SCHEMA}`,
    });
  }
  if (!same(actual.child_dispositions, expected.child_dispositions)) {
    refusals.push({
      check: "aggregate-binding-child-dispositions-stale",
      message: `${aggregate.work_item_id} aggregate child dispositions are stale`,
    });
  }
  if (!same(actual.child_bindings, expected.child_bindings)) {
    refusals.push({
      check: "aggregate-binding-child-stale",
      message: `${aggregate.work_item_id} child record/status/evidence bindings do not match current bytes`,
    });
  }
  if (!same(actual.dependency_bindings, expected.dependency_bindings)) {
    refusals.push({
      check: "aggregate-binding-dependency-stale",
      message: `${aggregate.work_item_id} dependency record/status/evidence bindings do not match current bytes`,
    });
  }
  if (!same(actual.aggregate_evidence_binding, expected.aggregate_evidence_binding)) {
    refusals.push({
      check: "aggregate-binding-own-evidence-stale",
      message: `${aggregate.work_item_id} aggregate evidence binding does not match current retained evidence`,
    });
  }
  if (actual.binding_payload_sha256 !== expected.binding_payload_sha256) {
    refusals.push({
      check: "aggregate-binding-payload-stale",
      message: `${aggregate.work_item_id} aggregate binding payload digest is stale`,
    });
  }
  if (actual.nonclaim !== AGGREGATE_BINDING_NONCLAIM) {
    refusals.push({
      check: "aggregate-binding-nonclaim",
      message: `${aggregate.work_item_id} aggregate binding lacks the exact non-promotion nonclaim`,
    });
  }

  for (const child of expected.child_bindings) {
    if (child.status_at_binding !== "verified") {
      refusals.push({
        check: "aggregate-binding-child-status",
        message: `${aggregate.work_item_id} child ${child.work_item_id} is ${child.status_at_binding}, not verified`,
      });
    }
    if (!child.evidence_binding.literal_valid) {
      refusals.push({
        check: "aggregate-binding-child-literal-invalid",
        message: `${aggregate.work_item_id} child ${child.work_item_id} lacks one conforming content-bound literal exit`,
      });
    }
    if (child.evidence_binding.evidence_files.some((file) => !file.exists)) {
      refusals.push({
        check: "aggregate-binding-child-evidence-missing",
        message: `${aggregate.work_item_id} child ${child.work_item_id} names retained evidence that is missing`,
      });
    }
  }
  for (const dependency of expected.dependency_bindings) {
    if (dependency.status_at_binding !== "verified") {
      refusals.push({
        check: "aggregate-binding-dependency-status",
        message: `${aggregate.work_item_id} dependency ${dependency.work_item_id} is ${dependency.status_at_binding}, not verified`,
      });
    }
    if (!dependency.evidence_binding.literal_valid) {
      refusals.push({
        check: "aggregate-binding-dependency-literal-invalid",
        message: `${aggregate.work_item_id} dependency ${dependency.work_item_id} lacks one conforming content-bound literal exit`,
      });
    }
    if (dependency.evidence_binding.evidence_files.some((file) => !file.exists)) {
      refusals.push({
        check: "aggregate-binding-dependency-evidence-missing",
        message: `${aggregate.work_item_id} dependency ${dependency.work_item_id} names retained evidence that is missing`,
      });
    }
  }
  if (!expected.aggregate_evidence_binding.literal_valid) {
    refusals.push({
      check: "aggregate-binding-own-literal-invalid",
      message: `${aggregate.work_item_id} lacks one conforming content-bound aggregate literal exit`,
    });
  }
  if (expected.aggregate_evidence_binding.evidence_files.some((file) => !file.exists)) {
    refusals.push({
      check: "aggregate-binding-own-evidence-missing",
      message: `${aggregate.work_item_id} names retained aggregate evidence that is missing`,
    });
  }
  const byId = recordsById(records);
  const pgRecords = [
    ...new Set([
      ...(aggregate.aggregate_child_ids ?? []),
      ...(aggregate.dependency_work_item_ids ?? []),
    ]),
  ].map((id) => byId.get(id)).filter(Boolean);
  for (const record of [...pgRecords, aggregate]) {
    refusals.push(...validateRequiredNowPgGates(record));
  }
  return refusals;
}

const UNVERIFIED_AGGREGATE_OWN_EVIDENCE_REFUSALS = new Set([
  "aggregate-binding-own-literal-invalid",
  "aggregate-binding-own-evidence-missing",
]);

// Refreshing an active/proposed aggregate before its own proof is retained is
// necessary to bind an already-verified child.  Only the aggregate's own two
// pre-proof defects may be deferred.  Child/dependency status, literals,
// evidence, PG gates, and every stale-binding defect remain hard refusals.
export function blockingAggregateBindingRefreshRefusals(
  aggregateStatus,
  refusals,
) {
  if (aggregateStatus === "verified") return [...refusals];
  return refusals.filter(
    (refusal) =>
      !UNVERIFIED_AGGREGATE_OWN_EVIDENCE_REFUSALS.has(refusal.check),
  );
}
