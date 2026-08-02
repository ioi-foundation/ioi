#!/usr/bin/env node
// One-time bootstrap for program/canon-map.v1.json.
//
// Derives a first classification for every discovered canon subject from
// evidence already in the estate — which work-item records cite the subject as a
// canon owner, and which stage those records belong to — then marks everything
// that nothing cites. The residue it marks `missing_implementation_coverage` IS
// the honest gap list; it is not a defect of this script.
//
// This is a bootstrap, not a routine writer. After it runs once, entries are
// edited by hand or by tools/transition.mjs.
//
//   node tools/bootstrap-canon-map.mjs --write
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import {
  ESTATE_ROOT,
  readJson,
  REPO_ROOT,
  writeJsonDeterministic,
} from "./lib/estate.mjs";
import {
  discoverCanonSubjects,
  mappableSubjects,
  readAdrStatus,
} from "./lib/canon-universe.mjs";

const sequence = readJson(path.join(ESTATE_ROOT, "program", "sequence.v1.json"));

// A stage is "activated" when it or any predecessor already owns a record that
// has moved past `proposed`. Everything downstream of the frontier is `planned`.
function activatedStages(records) {
  const advanced = new Set(
    records
      .filter((r) => r.status && r.status !== "proposed")
      .map((r) => r.stage_id),
  );
  return advanced;
}

function loadWorkItems() {
  const out = [];
  const roots = ["work-items", "work-items/active", "work-items/proposed"];
  const seen = new Set();
  for (const rel of roots) {
    const dir = path.join(ESTATE_ROOT, rel);
    if (!fs.existsSync(dir)) continue;
    for (const f of fs.readdirSync(dir)) {
      if (!f.endsWith(".v1.json")) continue;
      if (seen.has(f)) continue;
      seen.add(f);
      out.push(readJson(path.join(dir, f)));
    }
  }
  return out;
}

function canonOwnerPaths(record) {
  const out = [];
  for (const owner of record.canon_owners ?? []) {
    if (typeof owner === "string") out.push(owner.split("#")[0]);
    else if (owner && typeof owner === "object") {
      const p = owner.path ?? owner.ref ?? owner.owner ?? null;
      if (p) out.push(String(p).split("#")[0]);
    }
  }
  return out;
}

const NON_BUILD_KINDS = new Set([
  "archived_canon",
  "retained_evidence",
  "adr_index",
  "non_canon_communication",
  "schema_support",
  "tracked_status_record",
]);

// Canonical indexes and doctrine that describe rather than oblige. Each is named
// explicitly so the exemption is reviewable, never a wildcard.
const DECLARED_NON_BUILD = new Map([
  ["docs/architecture/README.md", "Canonical navigation and source-of-authority index."],
  ["docs/architecture/START_HERE.md", "Canonical reader entry point."],
  ["docs/architecture/_meta/start-here.md", "Canonical reader entry point."],
  ["docs/architecture/_meta/doc-classes.md", "Canonical documentation-class vocabulary."],
  ["docs/architecture/_meta/vocabulary.md", "Canonical term vocabulary."],
  ["docs/architecture/_meta/source-of-truth-map.md", "Canonical subject-ownership map."],
  ["docs/architecture/_meta/implementation-matrix.md", "Canonical implementation index; owns concept ownership, not sequence."],
  ["docs/architecture/_meta/canon-to-code-delta.md", "Canonical object-level delta index."],
  ["docs/architecture/_meta/execution-horizons.md", "Canonical horizon framing and build order; sequence.v1.json operationalises it."],
  ["docs/architecture/_meta/current-canon-defaults.md", "Canonical cross-owner defaults digest."],
  ["docs/architecture/_meta/canon-readability-audit.md", "Dated readability audit."],
  ["docs/architecture/_meta/refactor-baseline.md", "Dated refactor evidence snapshot."],
  ["docs/architecture/_meta/public-web-estate.md", "Public communication estate index."],
  ["docs/architecture/_meta/hypervisor-kernel-substrate-migration-matrix.md", "Archived terminal migration record."],
  ["docs/architecture/_meta/hypervisor-kernel-substrate-unification-master-guide.md", "Archived terminal migration record."],
  ["docs/architecture/_meta/wallet-protocol-sdk-packaging-plan.md", "Packaging plan retained as reference."],
  ["docs/architecture/whitepaper.tex", "Public communication artifact."],
  ["docs/conformance/README.md", "Conformance index."],
  ["docs/templates/mcp-connector-authoring-template.md", "Authoring template."],
  ["docs/templates/runtime-tool-contract-template.md", "Authoring template."],
  ["docs/commitment/README.md", "Empty placeholder index."],
]);

function main() {
  const write = process.argv.includes("--write");
  const subjects = discoverCanonSubjects();
  const mappable = mappableSubjects(subjects);
  const records = loadWorkItems();
  const advanced = activatedStages(records);

  // A schema file is covered when a work item names the contract family the
  // registry binds to that schema. Joining only on canon_owners paths would
  // report all 51 schemas as gaps, because records cite the doctrine owner
  // (common-objects-and-envelopes.md) rather than the schema file.
  const registryPath = path.join(
    REPO_ROOT,
    "docs/architecture/_meta/schemas/architecture-contract-registry.v1.json",
  );
  const schemaByFamily = new Map();
  const familyBySchema = new Map();
  if (fs.existsSync(registryPath)) {
    for (const contract of readJson(registryPath).contracts ?? []) {
      if (!contract.schema_ref || !contract.canonical_name) continue;
      const rel = `docs/architecture/_meta/schemas/${contract.schema_ref}`;
      schemaByFamily.set(contract.canonical_name, rel);
      const list = familyBySchema.get(rel) ?? [];
      list.push({
        name: contract.canonical_name,
        contract_id: contract.contract_id,
      });
      familyBySchema.set(rel, list);
    }
  }

  // subject path -> { stages:Set, work_items:Set, families:Set }
  const citations = new Map();
  const cite = (subjectPath, record, family = null) => {
    if (!citations.has(subjectPath)) {
      citations.set(subjectPath, {
        stages: new Set(),
        work_items: new Set(),
        families: new Set(),
      });
    }
    const c = citations.get(subjectPath);
    if (record.stage_id) c.stages.add(record.stage_id);
    if (record.work_item_id) c.work_items.add(record.work_item_id);
    if (family) c.families.add(family);
  };

  for (const record of records) {
    for (const owner of canonOwnerPaths(record)) cite(owner, record);
    for (const family of record.contract_families ?? []) {
      const name = typeof family === "string" ? family : family?.name;
      if (!name) continue;
      const schema = schemaByFamily.get(name);
      if (schema) cite(schema, record, name);
      const ownerPath = typeof family === "object"
        ? family.owner_path
        : null;
      if (ownerPath) cite(String(ownerPath).split("#")[0], record, name);
    }
  }

  const moduleByStage = new Map(
    sequence.stages.map((s) => [s.id, s.pulled_modules ?? []]),
  );

  const entries = [];
  for (const subject of mappable) {
    const cited = citations.get(subject.id);
    const stages = cited ? [...cited.stages].sort() : [];
    const workItems = cited ? [...cited.work_items].sort() : [];
    const modules = [
      ...new Set(stages.flatMap((s) => moduleByStage.get(s) ?? [])),
    ].sort();

    let classification;
    let reason;

    if (NON_BUILD_KINDS.has(subject.kind)) {
      classification = "non_build_doctrine";
      reason = `kind ${subject.kind} states no build obligation of its own`;
    } else if (subject.kind === "adr" && !readAdrStatus(subject.id).accepted) {
      classification = "non_build_doctrine";
      reason = "superseded ADR; its obligations migrated to the superseding ADR";
    } else if (DECLARED_NON_BUILD.has(subject.id)) {
      classification = "non_build_doctrine";
      reason = DECLARED_NON_BUILD.get(subject.id);
    } else if (stages.length === 0) {
      classification = "missing_implementation_coverage";
      reason =
        "obligation-bearing canon subject that no work-item record cites as a canon owner";
    } else if (stages.every((s) => s === "FUTURE")) {
      classification = "future_gated";
      reason = "owned only by conditional future work";
    } else if (stages.some((s) => advanced.has(s))) {
      classification = "actively_sequenced";
      reason = `cited by ${workItems.length} work item(s) in stage(s) ${
        stages.join(", ")
      }, at least one of which has advanced past proposed`;
    } else {
      classification = "planned";
      reason = `cited by ${workItems.length} work item(s) in stage(s) ${
        stages.join(", ")
      }, none yet advanced past proposed`;
    }

    if (
      subject.kind === "conformance_target" &&
      classification === "missing_implementation_coverage"
    ) {
      classification = "conformance_only";
      reason =
        "conformance contract with no owning work item; conformance is proven by the tracked hypervisor-conformance aggregate, not by a private cut";
    }

    entries.push({
      id: subject.id,
      kind: subject.kind,
      classification,
      stages,
      modules,
      work_items: workItems,
      contract_families: cited
        ? [...cited.families].sort()
        : (familyBySchema.get(subject.id) ?? []).map((f) => f.name),
      conformance_targets: [],
      code_anchors: [],
      proof_gates: [],
      reason,
    });
  }

  const counts = {};
  for (const e of entries) {
    counts[e.classification] = (counts[e.classification] ?? 0) + 1;
  }

  const map = {
    format: "ioi.program.canon_map.v1",
    role:
      "One entry per discovered canon subject. Declares that subject's implementation classification and its bindings to stages, modules, work items, contract families, conformance targets, code anchors, and proof gates.",
    authority:
      "This file assigns implementation coverage. It never overrides canon and never states or changes status.",
    insertion_rule:
      "Adding a canon file adds one entry here. No generator constant, index file, or stage module changes.",
    classification_vocabulary: {
      actively_sequenced:
        "Bound to a stage that has already advanced past proposed, with at least one owning work item.",
      planned:
        "Bound to a stage and work item that have not yet started. Scope is preserved; activation waits on the sequence.",
      future_gated:
        "Canonically required, activated only by a named external condition rather than a stage predecessor.",
      non_build_doctrine:
        "Index, vocabulary, template, archived record, retained evidence, or superseded decision. States no build obligation of its own.",
      conformance_only:
        "Proven by the tracked conformance aggregate rather than by a private implementation cut.",
      unresolved_canon_gap:
        "Canon is ambiguous, contradictory, or silent where an implementer needs an answer. Must name the canon owner that should resolve it.",
      missing_implementation_coverage:
        "Obligation-bearing canon with no owning stage or work item. An honest gap, not a pass.",
    },
    generated_by:
      "node internal-docs/implementation/tools/bootstrap-canon-map.mjs --write (one-time bootstrap; entries are maintained by hand afterwards)",
    subject_count: entries.length,
    classification_counts: counts,
    subjects: entries,
  };

  if (write) {
    writeJsonDeterministic(
      path.join(ESTATE_ROOT, "program", "canon-map.v1.json"),
      map,
    );
  }
  process.stdout.write(`${JSON.stringify(counts, null, 2)}\n`);
  process.stdout.write(`subjects: ${entries.length}\n`);
  const gaps = entries.filter((e) =>
    e.classification === "missing_implementation_coverage"
  );
  process.stdout.write(`\nGAPS (${gaps.length}):\n`);
  for (const g of gaps) process.stdout.write(`  ${g.kind}  ${g.id}\n`);
}

main();
