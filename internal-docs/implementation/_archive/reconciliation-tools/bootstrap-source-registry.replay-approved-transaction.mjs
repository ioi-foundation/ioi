#!/usr/bin/env node

// One-time, status-free migration control. It materializes the user-approved
// file-by-file disposition table exactly once and then becomes read-only. New
// paths after finalization must receive an explicit reviewed registry entry;
// this helper must never auto-approve routine estate growth.

import fs from "node:fs";
import path from "node:path";
import {
  implementationRelative,
  implementationRoot,
  listTreeFiles,
  readJson,
  sha256,
  sha256File,
  stableJson,
} from "./lib.mjs";

const registryPath = path.join(implementationRoot, "source-dispositions.v1.json");
const mode = process.argv[2];
if (!new Set(["--finalize-approved-transaction", "--check"]).has(mode) || process.argv.length !== 3) {
  process.stderr.write("usage: bootstrap-source-registry.mjs --finalize-approved-transaction|--check\n");
  process.exit(2);
}
const baselineExclusions = [
  "source-dispositions.v1.json",
  "tools/",
  "generated/",
  "audits/",
  "_archive/",
  "stage-guides/",
  "proof-gates/",
  "work-items/logs/",
];

const exactMoves = new Map(Object.entries({
  "architecture-to-implementation-coverage-audit.md": "audits/2026-07-22-architecture-coverage.md",
  "implementation-directory-unification-action-plan.md": "audits/2026-07-22-directory-unification-plan.md",
  "bounded-recursive-improvement-campaign-discovery-plan.md": "_archive/plans/bounded-recursive-improvement-campaign-discovery-plan.md",
  "canon-mechanism-hardening-action-plan.md": "_archive/plans/canon-mechanism-hardening-action-plan.md",
  "canon-sota-improvement-review.md": "audits/history/2026-07-16-canon-sota-improvement-review.md",
  "hypervisor-bounded-das-application-taxonomy-winning-state-plan.md": "_archive/plans/hypervisor-bounded-das-application-taxonomy-winning-state-plan.md",
  "hypervisor-model-mount-rust-consolidation-and-deadcode-retirement.md": "audits/history/2026-06-hypervisor-model-mount-rust-consolidation.md",
  "implementation-plan-estate-reconciliation.md": "audits/reconciliation/2026-07-22-estate-reconciliation.md",
  "implementation-plan-reconciliation-review.md": "audits/reconciliation/2026-07-22-reconciliation-review.md",
  "ioi-design-system-portable-package-plan.md": "_archive/plans/ioi-design-system-portable-package-plan.md",
  "ioi-undeniable-product-proof-implementation-guide.md": "_archive/guides/ioi-undeniable-product-proof-implementation-guide.md",
  "m0-m14-plan-gap-audit.md": "audits/2026-07-22-m0-m14-plan-gap-audit.md",
  "reconciliation/stateless-master-guide.v1.json": "audits/reconciliation/stateless-master-guide/manifest.v1.json",
  "reconciliation/stateless-master-guide.v1.patch": "audits/reconciliation/stateless-master-guide/stateless-master-guide.v1.patch",
  "refine-architecture.md": "_archive/guides/refine-architecture.md",
  "runtime-action-schema.json": "generated/runtime-action-schema.json",
  "runtime-kernel-namespace-residual.v1.json": "generated/runtime-kernel-namespace-residual.v1.json",
  "runtime-kernel-service-trust-boundary-audit.md": "audits/history/2026-07-21-runtime-kernel-service-trust-boundary-audit.md",
  "runtime-module-map.md": "_archive/maps/runtime-module-map.md",
  "runtime-package-boundaries.md": "_archive/maps/runtime-package-boundaries.md",
  "work-item-m1-5-protected-transitions.md": "work-items/logs/m1-5-protected-transitions.md",
  "work-item-m1-5c-amendment-execution.md": "work-items/logs/m1-5c-amendment-execution.md"
}));

const extractSources = new Set([
  "bounded-recursive-improvement-campaign-discovery-plan.md",
  "canon-mechanism-hardening-action-plan.md",
  "hypervisor-bounded-das-application-taxonomy-winning-state-plan.md",
  "runtime-kernel-service-trust-boundary-audit.md",
]);

const compatibilityHolds = {};

const preservedBodyOverrides = {
  "canon-sota-improvement-review.md": "_archive/originals/2026-07-16-canon-sota-improvement-review.pre-link-repair.md",
  "hypervisor-unified-rust-daemon-lifecycle-migration.md": "_archive/pre-unification-baseline/hypervisor-unified-rust-daemon-lifecycle-migration.md",
  "runtime-kernel-namespace-residual.v1.json": "_archive/pre-unification-baseline/runtime-kernel-namespace-residual.v1.json",
};

function baselineClass(sourcePath) {
  if (sourcePath === "ioi-target-end-state-master-implementation-guide.md") return "sequencer";
  if (sourcePath === "README.md") return "navigation";
  if (sourcePath === "program-state.json" || sourcePath.endsWith("runtime-action-schema.json") || sourcePath.endsWith("residual.v1.json")) return "projection";
  if (sourcePath === "check-program-state.mjs") return "tool";
  if (sourcePath.startsWith("work-items/") && sourcePath.endsWith(".v1.json")) return "work_item";
  if (sourcePath.startsWith("evidence/")) return "evidence";
  if (sourcePath.startsWith("reconciliation/")) return "work_record";
  if (sourcePath.startsWith("work-item-")) return "work_record";
  if (sourcePath === "low-level-implementation-milestones.md" || sourcePath === "hypervisor-unified-rust-daemon-lifecycle-migration.md") return "pointer";
  if (sourcePath.includes("audit") || sourcePath.includes("review") || sourcePath.includes("reconciliation")) return "audit";
  return "archive_source";
}

function dispositionFor(sourcePath) {
  if (extractSources.has(sourcePath)) return "EXTRACT_MODULE_DETAIL";
  if (exactMoves.has(sourcePath)) {
    if (sourcePath.endsWith(".json") && sourcePath.includes("runtime-")) return "GENERATED";
    if (sourcePath.includes("guide") || sourcePath === "refine-architecture.md" || sourcePath.includes("module-map") || sourcePath.includes("package-boundaries") || sourcePath.includes("design-system")) return "ARCHIVE_AFTER_APPROVAL";
    return "RENAME_OR_REHOME_AFTER_APPROVAL";
  }
  if (sourcePath.startsWith("work-items/") || sourcePath.startsWith("work-item-") || sourcePath.startsWith("evidence/")) return "KEEP_WORK_RECORD";
  if (sourcePath === "program-state.json") return "GENERATED";
  if (sourcePath === "README.md" || sourcePath.includes("master-implementation-guide")) return "KEEP_AUTHORITY";
  if (sourcePath.endsWith(".mjs")) return "KEEP_PROJECTION";
  if (baselineClass(sourcePath) === "pointer") return "COLLAPSE_TO_POINTER";
  return "KEEP_WORK_RECORD";
}

function ownerFor(sourcePath) {
  if (sourcePath === "ioi-target-end-state-master-implementation-guide.md") return "sole master sequencer";
  if (sourcePath.startsWith("work-items/") && sourcePath.endsWith(".v1.json")) return `work item ${path.basename(sourcePath, ".v1.json")}`;
  if (sourcePath === "program-state.json") return "tools/generate-program-state.mjs";
  if (sourcePath.startsWith("evidence/")) return "owning work-item evidence index";
  return "master §14 source-disposition policy";
}

function currentPathClass(currentPath) {
  if (currentPath === "ioi-target-end-state-master-implementation-guide.md") return ["sequencer", "KEEP_AUTHORITY"];
  if (currentPath === "README.md") return ["navigation", "KEEP_AUTHORITY"];
  if (currentPath === "source-dispositions.v1.json") return ["source_registry", "KEEP_AUTHORITY"];
  if (currentPath === "program-state.json" || currentPath.startsWith("generated/")) return ["projection", "GENERATED"];
  if (currentPath.startsWith("tools/") || currentPath === "check-program-state.mjs") return ["tool", "KEEP_PROJECTION"];
  if (currentPath.startsWith("stage-guides/") || currentPath.startsWith("proof-gates/")) return ["module", "KEEP_AUTHORITY"];
  if (currentPath.startsWith("work-items/") && currentPath.endsWith(".v1.json")) return ["work_item", "KEEP_WORK_RECORD"];
  if (currentPath.startsWith("work-items/logs/") || currentPath.startsWith("evidence/")) return ["evidence", "KEEP_WORK_RECORD"];
  if (currentPath.startsWith("audits/")) return ["audit", "KEEP_WORK_RECORD"];
  if (currentPath.startsWith("_archive/")) return ["archive", "KEEP_WORK_RECORD"];
  if (compatibilityHolds[currentPath]) return [baselineClass(currentPath), dispositionFor(currentPath)];
  if (exactMoves.has(currentPath)) return ["pointer", "COLLAPSE_TO_POINTER"];
  const sourceClass = baselineClass(currentPath);
  return [sourceClass, dispositionFor(currentPath)];
}

const approvalDecisions = {
  "master-14": "Master §14 baseline authority or retained stable-path decision.",
  "SA-1": "Approved subordinate-module and stale-authority cleanup.",
  "SA-4": "Approved archive, rehome, preservation, and tombstone decision.",
  "SA-5": "Approved status-free mechanism-gate extraction.",
  "goal-phase-1-tools": "User-approved private schema, checker, and writer layer.",
  "goal-phase-3-modules": "User-approved reusable non-sequencing module extraction.",
  "goal-phase-4-work-items": "User-approved SA-2/SA-7/SA-9 work-item migration and gap-record materialization.",
  "goal-phase-6-projections": "User-approved deterministic private projection and retained verification evidence.",
  "goal-reconciliation-audit": "User-approved reconciliation, before/after, review, and execution-report evidence.",
  "goal-reader-journey": "User-approved private README and compatibility navigation.",
};

function approvalFor(currentPath, source, documentClass) {
  if (source?.approving_amendment === "SA-4") return "SA-4";
  if (currentPath === "ioi-target-end-state-master-implementation-guide.md" || currentPath === "source-dispositions.v1.json") return "master-14";
  if (currentPath === "README.md" || documentClass === "navigation" || documentClass === "pointer") return "goal-reader-journey";
  if (currentPath.startsWith("stage-guides/")) return "goal-phase-3-modules";
  if (currentPath.startsWith("proof-gates/")) return "SA-5";
  if (currentPath.startsWith("tools/") || currentPath === "check-program-state.mjs") return "goal-phase-1-tools";
  if (currentPath.startsWith("work-items/")) return "goal-phase-4-work-items";
  if (currentPath === "program-state.json" || currentPath.startsWith("generated/") || currentPath.startsWith("evidence/")) return "goal-phase-6-projections";
  if (currentPath.startsWith("audits/")) return "goal-reconciliation-audit";
  if (currentPath.startsWith("_archive/")) return "SA-4";
  return source ? "master-14" : "goal-reconciliation-audit";
}

let registry;
if (fs.existsSync(registryPath)) {
  registry = readJson(registryPath);
} else {
  const baselineFiles = listTreeFiles(implementationRoot)
    .map(implementationRelative)
    .filter((sourcePath) => !baselineExclusions.some((prefix) => sourcePath === prefix || sourcePath.startsWith(prefix)));
  registry = {
    schema_version: "ioi.program.source-dispositions.v1",
    document_class: "source_registry",
    status_fields_permitted: false,
    owns: "exact approved private source role and destination facts delegated by master §14",
    does_not_own: ["stage order", "work activation", "implementation status", "architecture doctrine"],
    approved_amendments: ["SA-1", "SA-2", "SA-3", "SA-4", "SA-5", "SA-6", "SA-7", "SA-8", "SA-9"],
    baseline: {
      branch: "feat/estate-camera-pipeline",
      commit: "a894b25054cdb45f27deb3163793773d6449dd2b",
      captured_on: "2026-07-22",
      source_count: baselineFiles.length,
    },
    sources: baselineFiles.map((sourcePath) => ({
      source_path: sourcePath,
      baseline_sha256: sha256File(path.join(implementationRoot, sourcePath)),
      document_class: baselineClass(sourcePath),
      disposition: dispositionFor(sourcePath),
      owner: ownerFor(sourcePath),
      destination_path: exactMoves.get(sourcePath) ?? sourcePath,
      tombstone_required: exactMoves.has(sourcePath) && !compatibilityHolds[sourcePath],
      approving_amendment: exactMoves.has(sourcePath) ? "SA-4" : "master §14",
      compatibility_hold: compatibilityHolds[sourcePath] ?? null,
      delete_permitted: false,
    })),
    current_paths: [],
  };
}

if (mode === "--check") {
  if (!registry.migration_finalized) {
    process.stderr.write("source registry check failed: approved migration has not been finalized\n");
    process.exit(1);
  }
  const actualPaths = listTreeFiles(implementationRoot).map(implementationRelative).sort();
  const registeredPaths = registry.current_paths.map((entry) => entry.path).sort();
  if (stableJson(actualPaths) !== stableJson(registeredPaths)) {
    process.stderr.write("source registry check failed: current path set differs from the finalized registry; add a reviewed exact disposition instead of rerunning bootstrap\n");
    process.exit(1);
  }
  const setDigest = sha256(stableJson(registeredPaths));
  if (registry.finalized_current_path_set_sha256 !== setDigest) {
    process.stderr.write(`source registry check failed: finalized path-set digest mismatch (expected ${registry.finalized_current_path_set_sha256}, found ${setDigest})\n`);
    process.exit(1);
  }
  process.stdout.write(`source registry finalization check passed: ${registeredPaths.length} sealed current paths, sha256 ${setDigest}\n`);
  process.exit(0);
}

if (registry.migration_finalized) {
  process.stderr.write("source registry finalization refused: the one-time approved transaction is already sealed; add any future path through explicit reviewed registry editing\n");
  process.exit(1);
}

for (const source of registry.sources) {
  if (source.approving_amendment === "master §14") source.approving_amendment = "master-14";
  source.compatibility_hold = compatibilityHolds[source.source_path] ?? null;
  if (exactMoves.has(source.source_path)) {
    source.tombstone_required = compatibilityHolds[source.source_path] === undefined;
  }
  const baselineArchive = `_archive/pre-unification-baseline/${source.source_path}`;
  source.preserved_body_path = preservedBodyOverrides[source.source_path]
    ?? (fs.existsSync(path.join(implementationRoot, baselineArchive)) ? baselineArchive : null)
    ?? source.preserved_body_path
    ?? null;
}

const currentPaths = listTreeFiles(implementationRoot).map(implementationRelative);
if (!currentPaths.includes("source-dispositions.v1.json")) currentPaths.push("source-dispositions.v1.json");
registry.current_paths = [...new Set(currentPaths)].sort().map((currentPath) => {
  const [documentClass, disposition] = currentPathClass(currentPath);
  const source = registry.sources.find((candidate) => candidate.source_path === currentPath || candidate.destination_path === currentPath);
  return {
    path: currentPath,
    document_class: documentClass,
    disposition,
    owner: source?.owner ?? (documentClass === "work_item" ? `work item ${path.basename(currentPath, ".v1.json")}` : "private implementation estate"),
    source_path: source?.source_path ?? null,
    destination_path: source?.destination_path ?? currentPath,
    tombstone_required: source?.source_path === currentPath ? Boolean(source.tombstone_required) : false,
    approving_amendment: approvalFor(currentPath, source, documentClass),
    schedules_work: documentClass === "sequencer",
    carries_status: documentClass === "work_item" || currentPath === "program-state.json",
  };
});

registry.approved_disposition_decisions = approvalDecisions;
registry.migration_finalized = true;
registry.finalized_current_path_set_sha256 = sha256(stableJson(registry.current_paths.map((entry) => entry.path).sort()));

fs.writeFileSync(registryPath, stableJson(registry));
process.stdout.write(`source registry finalized once: ${registry.sources.length} baseline sources, ${registry.current_paths.length} current paths, sha256 ${registry.finalized_current_path_set_sha256}\n`);
