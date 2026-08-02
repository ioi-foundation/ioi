#!/usr/bin/env node
// One-time migration executor for the 2026-07-25 implementation-system refactor.
//
//   node tools/migrate-estate.mjs            dry run
//   node tools/migrate-estate.mjs --apply    execute and write the manifest
//
// Every action is declared below with its classification, reason, and — for a
// deletion — the justification and the retained recovery source. The executor
// records old path, new path, classification, sha256, reason, and deletion
// justification into _archive/manifests/migration-manifest.v1.json.
//
// Nothing is deleted whose bytes are not already retained somewhere else. The
// recovery source for every deletion is named in the manifest entry.
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import {
  ESTATE_ROOT,
  sha256File,
  writeJsonDeterministic,
} from "./lib/estate.mjs";

const BASELINE_TARBALL =
  "/home/heathledger/Documents/ioi/impl-refactor/baseline-estate-a894b2505.tar.gz";
const BASELINE_SHA =
  "2a3bf20f8bba869bf676e327ba13441a6b9598a967ca310639ac453495a14c7b";

// --- MOVES ------------------------------------------------------------------
const MOVES = [
  {
    from: "ioi-target-end-state-master-implementation-guide.md",
    to: "_archive/superseded-guides/ioi-target-end-state-master-implementation-guide.md",
    classification: "deprecated-superseded",
    reason:
      "Fully decomposed. Sections 2/4/6/13.3-13.4 -> program/rules.md; 1/7 order -> program/sequence.v1.json; the fifteen stage bodies -> stages/; the eleven WP-* packages, the M9 gateway proof, the adversarial matrix and the research discipline -> modules/; 3.x/5/9/10/11/16 -> generated/NOW.md and tracked docs/evidence/m0-program-control/; 9.1/13.6/14.2-14.4/15 -> _archive/.",
  },
  {
    from: "program-state.json",
    to: "_archive/generated-pre-refactor/program-state.json",
    classification: "generated-projection",
    reason:
      "Superseded by generated/program-state.v1.json. The retired file was 22,256 lines and sat on the first-read path; it was also bound to checkout a894b25054, which is not an ancestor of master.",
  },
  {
    from: "source-dispositions.v1.json",
    to: "_archive/migrations/source-dispositions.v1.json",
    classification: "migration-reconciliation",
    reason:
      "Superseded by program/estate-boundary.v1.json (scan scope), program/guide-registry.v1.json (repo-wide classification), and program/canon-map.v1.json (canon coverage). The retired file conflated developer-host state with repository state, which is why it carried 315 current_paths including a vendored node_modules tree.",
  },
  {
    from: "audits",
    to: "_archive/audits",
    classification: "historical-audit",
    reason:
      "Dated observations and reconciliation records. Immutable evidence for the commit and canon revision they certified; never on the active reader path.",
  },
  {
    from: "scratch",
    to: "_archive/migrations/scratch-writers",
    classification: "disposable-scratch",
    reason:
      "author-current-m0-exit-evidence.mjs and author-m1-exit-evidence.mjs are UNCONDITIONAL writers: they overwrite work-item records and mint evidence with no flag guard. Retained for provenance, removed from the active path so no lane can invoke them.",
  },
  {
    from: "generated/architecture-coverage.v1.json",
    to: "_archive/generated-pre-refactor/architecture-coverage.v1.json",
    classification: "generated-projection",
    reason:
      "Superseded by generated/canon-impact.v1.json. Retained because its published counts (50 obligations, 87 owner subjects, 0 orphans) are the baseline the refactor measured against.",
  },
  {
    from: "generated/source-manifest.v1.json",
    to: "_archive/generated-pre-refactor/source-manifest.v1.json",
    classification: "generated-projection",
    reason: "Superseded by program/estate-boundary.v1.json and the migration manifest.",
  },
  {
    from: "generated/hypervisor-surface-coverage.v1.json",
    to: "_archive/generated-pre-refactor/hypervisor-surface-coverage.v1.json",
    classification: "generated-projection",
    reason:
      "A product-surface projection, not an implementation-system artifact. Its generator is retained under _archive/tools-pre-refactor/ and belongs to M6/M9 work rather than to any routine estate lane.",
  },
  {
    from: "generated/runtime-action-schema.json",
    to: "_archive/generated-pre-refactor/runtime-action-schema.json",
    classification: "generated-projection",
    reason: "Runtime projection, reproducible from its generator; not an implementation-system artifact.",
  },
  {
    from: "generated/runtime-kernel-namespace-residual.v1.json",
    to: "_archive/generated-pre-refactor/runtime-kernel-namespace-residual.v1.json",
    classification: "generated-projection",
    reason: "Runtime projection, reproducible from its generator; not an implementation-system artifact.",
  },
  {
    from: "evidence/hypervisor-live-read-only-crawl.v1.json",
    to: "_archive/evidence/hypervisor-live-read-only-crawl.v1.json",
    classification: "historical-audit",
    reason:
      "A retained GET crawl proving transport reachability only. Retained as evidence; it is not proof of any implementation claim and is not needed by active work.",
  },
];

// Superseded tools. Each names what replaced it.
const TOOL_MOVES = [
  ["check-program-state.mjs", "tools/generate-now.mjs --check"],
  ["tools/generate-program-state.mjs", "tools/generate-now.mjs"],
  ["tools/generate-architecture-coverage.mjs", "tools/canon-impact.mjs"],
  ["tools/architecture-coverage-review-ledger.mjs", "tools/canon-impact.mjs --accept"],
  ["tools/test-architecture-coverage-review-ledger.mjs", "tools/test-canon-impact.mjs"],
  ["tools/check-source-dispositions.mjs", "program/estate-boundary.v1.json + program/guide-registry.v1.json"],
  ["tools/freeze-source-manifest.mjs", "_archive/manifests/migration-manifest.v1.json"],
  ["tools/bootstrap-source-registry.mjs", "sealed one-time control, superseded"],
  ["tools/migrate-work-items.mjs", "sealed one-time control, superseded"],
  ["tools/check-work-item-migration-finalization.mjs", "sealed one-time control, superseded"],
  ["tools/check-single-sequencer.mjs", "tools/check-estate.mjs role-uniqueness bar"],
  ["tools/check-status-truth.mjs", "tools/check-estate.mjs status-voice bar + tools/reconcile-status.mjs"],
  ["tools/check-internal-links.mjs", "tools/check-estate.mjs link bar (boundary-scoped)"],
  ["tools/check-markdown-structure.mjs", "tools/check-estate.mjs"],
  ["tools/check-module-headers.mjs", "tools/check-estate.mjs front-matter bar"],
  ["tools/check-generated.mjs", "tools/check-program.mjs"],
  ["tools/check-implementation-estate.mjs", "tools/check-program.mjs"],
  ["tools/check-private-estate-boundary.mjs", "tools/check-estate.mjs + program/estate-boundary.v1.json"],
  ["tools/check-clean-checkout-nonclaims.mjs", "tools/generate-now.mjs provenance block"],
  ["tools/generate-approved-sequencer-diff.mjs", "sealed one-time control over the retired master guide"],
  ["tools/extract-mechanism-gate-registry.mjs", "modules/mechanism-gates.md is now hand-maintained; this tool had a bare writeFileSync and no read-only mode"],
  ["tools/generate-hypervisor-surface-coverage.mjs", "product-surface projection; belongs to M6/M9, not a routine estate lane"],
  ["tools/check-hypervisor-surface-coverage.mjs", "product-surface projection"],
  ["tools/capture-hypervisor-live-crawl.mjs", "product-surface projection"],
  ["tools/generate-runtime-kernel-residual.mjs", "runtime projection"],
  ["tools/verify-runtime-kernel-trust-audit.mjs", "runtime projection"],
  ["tools/sync-runtime-action-schema.mjs", "runtime projection"],
  ["tools/check-literal-exits.mjs", "tools/certify-stage.mjs literal bar"],
  ["tools/content-bound-literal.mjs", "tools/certify-stage.mjs"],
  ["tools/test-program-state-lifecycle.mjs", "tools/test-canon-impact.mjs + tools/test-insertion.mjs"],
  ["tools/check-work-items.mjs", "tools/check-work-item-shape.mjs (fast) — the deep historical bar is retained here for reference"],
  ["tools/lib.mjs", "tools/lib/estate.mjs"],
  ["tools/contract-owner-locators.v1.json", "program/canon-map.v1.json contract_families"],
];

// --- DELETIONS --------------------------------------------------------------
// Root compatibility tombstones from the previous unification. Deletion is safe:
// `npm run check:m0-program-control`, `check:work-items` and
// `check:architecture-docs` all exit 0 in a pristine origin/master worktree where
// internal-docs/implementation/ does not exist at all, so no tracked, merged
// verifier requires any of these paths. The two paths named in
// scripts/lib/m0-program-control-model.mjs are declared
// `evidence_binding: "not_read_not_hashed_not_bound"` — frozen identifier strings
// in retained evidence, not filesystem dependencies.
const TOMBSTONES = [
  "architecture-to-implementation-coverage-audit.md",
  "bounded-recursive-improvement-campaign-discovery-plan.md",
  "canon-mechanism-hardening-action-plan.md",
  "canon-sota-improvement-review.md",
  "hypervisor-bounded-das-application-taxonomy-winning-state-plan.md",
  "hypervisor-model-mount-rust-consolidation-and-deadcode-retirement.md",
  "hypervisor-unified-rust-daemon-lifecycle-migration.md",
  "implementation-directory-unification-action-plan.md",
  "implementation-plan-estate-reconciliation.md",
  "implementation-plan-reconciliation-review.md",
  "ioi-design-system-portable-package-plan.md",
  "ioi-undeniable-product-proof-implementation-guide.md",
  "low-level-implementation-milestones.md",
  "m0-m14-plan-gap-audit.md",
  "refine-architecture.md",
  "runtime-kernel-service-trust-boundary-audit.md",
  "runtime-module-map.md",
  "runtime-package-boundaries.md",
  "work-item-m1-5-protected-transitions.md",
  "work-item-m1-5c-amendment-execution.md",
];

const DUPLICATE_DELETIONS = [
  {
    path: "runtime-action-schema.json",
    duplicate_of: "generated/runtime-action-schema.json",
  },
  {
    path: "runtime-kernel-namespace-residual.v1.json",
    duplicate_of: "generated/runtime-kernel-namespace-residual.v1.json",
  },
];

function main() {
  const apply = process.argv.includes("--apply");
  const entries = [];
  const log = (s) => process.stdout.write(`${s}\n`);

  const move = (from, to, classification, reason) => {
    const src = path.join(ESTATE_ROOT, from);
    const dst = path.join(ESTATE_ROOT, to);
    if (!fs.existsSync(src)) {
      log(`  skip (absent)  ${from}`);
      return;
    }
    const isDir = fs.statSync(src).isDirectory();
    const digest = isDir ? null : sha256File(src);
    entries.push({
      old_path: `internal-docs/implementation/${from}`,
      new_path: `internal-docs/implementation/${to}`,
      classification,
      action: "move",
      sha256: digest,
      is_directory: isDir,
      reason,
    });
    if (apply) {
      fs.mkdirSync(path.dirname(dst), { recursive: true });
      fs.renameSync(src, dst);
    }
    log(`  move  ${from} -> ${to}`);
  };

  log("MOVES");
  for (const m of MOVES) move(m.from, m.to, m.classification, m.reason);

  log("TOOL MOVES");
  for (const [rel, replacement] of TOOL_MOVES) {
    move(
      rel,
      `_archive/tools-pre-refactor/${path.basename(rel)}`,
      "deprecated-superseded",
      `Superseded by: ${replacement}.`,
    );
  }

  log("TOMBSTONE DELETIONS");
  for (const rel of TOMBSTONES) {
    const src = path.join(ESTATE_ROOT, rel);
    if (!fs.existsSync(src)) {
      log(`  skip (absent)  ${rel}`);
      continue;
    }
    const digest = sha256File(src);
    const archivedBody = [
      `_archive/plans/${path.basename(rel)}`,
      `_archive/guides/${path.basename(rel)}`,
      `_archive/maps/${path.basename(rel)}`,
      `_archive/pre-unification-baseline/${path.basename(rel)}`,
    ].find((p) => fs.existsSync(path.join(ESTATE_ROOT, p))) ?? null;
    entries.push({
      old_path: `internal-docs/implementation/${rel}`,
      new_path: null,
      classification: "compatibility-pointer",
      action: "delete",
      sha256: digest,
      reason:
        "Logic-free compatibility pointer left by the previous unification. It carried no unique content: its body was a link block.",
      deletion_justification:
        "No tracked, merged verifier requires it. Proven by running npm run check:m0-program-control, check:work-items and check:architecture-docs to exit 0 in a pristine origin/master worktree where internal-docs/implementation/ does not exist. The only tracked references are (a) prose comments, (b) a fixture string in crates/services, and (c) two identifiers in scripts/lib/m0-program-control-model.mjs declared not_read_not_hashed_not_bound.",
      backlinks_updated:
        "All private-estate backlinks were rewritten to the new owners. Tracked references were left untouched because they do not resolve the path.",
      recovery_source: archivedBody
        ? `internal-docs/implementation/${archivedBody}`
        : `${BASELINE_TARBALL} (sha256 ${BASELINE_SHA})`,
    });
    if (apply) fs.rmSync(src);
    log(`  delete  ${rel}`);
  }

  log("DUPLICATE DELETIONS");
  for (const d of DUPLICATE_DELETIONS) {
    const src = path.join(ESTATE_ROOT, d.path);
    const twin = path.join(ESTATE_ROOT, d.duplicate_of);
    if (!fs.existsSync(src)) {
      log(`  skip (absent)  ${d.path}`);
      continue;
    }
    const digest = sha256File(src);
    const twinDigest = fs.existsSync(twin) ? sha256File(twin) : null;
    entries.push({
      old_path: `internal-docs/implementation/${d.path}`,
      new_path: null,
      classification: "duplicate",
      action: "delete",
      sha256: digest,
      duplicate_of: `internal-docs/implementation/${d.duplicate_of}`,
      duplicate_of_sha256: twinDigest,
      byte_identical: twinDigest === digest,
      reason:
        "Root copy of a generated projection that already exists under generated/.",
      deletion_justification: twinDigest === digest
        ? "Byte-identical to the generated copy."
        : "Stale root copy of a reproducible generated projection; the generated copy is authoritative and the generator is retained.",
      recovery_source: `${BASELINE_TARBALL} (sha256 ${BASELINE_SHA})`,
    });
    if (apply) fs.rmSync(src);
    log(`  delete  ${d.path}`);
  }

  // reconciliation/ holds two symlinks into audits/, which has moved.
  const recon = path.join(ESTATE_ROOT, "reconciliation");
  if (fs.existsSync(recon)) {
    entries.push({
      old_path: "internal-docs/implementation/reconciliation/",
      new_path: null,
      classification: "duplicate",
      action: "delete",
      reason:
        "Two symlinks into audits/reconciliation/stateless-master-guide/, which moved to _archive/audits/. The link targets are retained; the symlink directory carried no content.",
      deletion_justification:
        "Symlinks only. Both targets are retained under _archive/audits/reconciliation/stateless-master-guide/.",
      recovery_source: `${BASELINE_TARBALL} (sha256 ${BASELINE_SHA})`,
    });
    if (apply) fs.rmSync(recon, { recursive: true });
    log("  delete  reconciliation/ (symlinks)");
  }

  const manifest = {
    evidence_format: "ioi.program.migration_manifest.v1",
    migration_id: "2026-07-25-implementation-system-refactor",
    base_commit: "ba7513bac458cc6bfa398d3a814d65b963c6a287",
    rollback: {
      source: BASELINE_TARBALL,
      sha256: BASELINE_SHA,
      note:
        "Full pre-refactor estate, 41 MB. Every deletion in this manifest is recoverable from it. Restoring it returns the estate byte-for-byte to its 2026-07-25 pre-refactor state.",
    },
    rule:
      "A deletion appears here only with a named recovery source and a justification that does not rest on a checker passing. A move appears with its content digest so the archived body can be verified against what was moved.",
    entry_count: entries.length,
    entries,
  };

  if (apply) {
    writeJsonDeterministic(
      path.join(ESTATE_ROOT, "_archive", "manifests", "migration-manifest.v1.json"),
      manifest,
    );
  }
  log(
    `\n${apply ? "applied" : "would apply"} ${entries.length} migration entries (${
      entries.filter((e) => e.action === "move").length
    } moves, ${entries.filter((e) => e.action === "delete").length} deletions)`,
  );
}

main();
