import assert from "node:assert/strict";
import test from "node:test";

import {
  collectStudioArtifactDistillationLedger,
} from "./studio-artifact-distillation.mjs";

function buildEntry(id, dateRoot, overrides = {}) {
  return {
    id,
    dateRoot,
    renderer: "html_iframe",
    classification: "repairable",
    effectiveClassification: "repairable",
    validationScore: 0.42,
    firstPaintEvidenceScore: 0.38,
    shimDependent: true,
    blueprintPresent: false,
    artifactIrPresent: false,
    selectedSkillCount: 0,
    retrievedExemplarCount: 0,
    summaryPath: `/tmp/${dateRoot}/${id}/case-summary.json`,
    strongestContradiction: "Needs work.",
    ...overrides,
  };
}

test("distillation ledger promotes typed upgrade targets from case history deltas", () => {
  const corpusSummary = {
    cases: [
      buildEntry("html-ai-tools-editorial", "2026-03-28", {
        classification: "blocked",
        effectiveClassification: "blocked",
        validationScore: 0.21,
        firstPaintEvidenceScore: 0.16,
        shimDependent: true,
      }),
      buildEntry("html-ai-tools-editorial", "2026-03-30", {
        classification: "pass",
        effectiveClassification: "pass",
        validationScore: 0.88,
        firstPaintEvidenceScore: 0.81,
        shimDependent: false,
        blueprintPresent: true,
        artifactIrPresent: true,
        selectedSkillCount: 1,
        retrievedExemplarCount: 2,
      }),
    ],
  };
  const benchmarkCatalog = {
    version: 1,
    cases: [
      {
        benchmarkId: "html-editorial-launch-page",
        title: "Editorial launch page",
        prompt: "Create an interactive HTML artifact for an AI tools editorial launch page",
        caseBindings: ["html-ai-tools-editorial"],
        categories: ["interactive_html", "editorial"],
        trackedParityTarget: false,
      },
    ],
  };

  const ledger = collectStudioArtifactDistillationLedger({
    corpusSummary,
    benchmarkCatalog,
    now: "2026-03-31T00:00:00.000Z",
  });

  assert.equal(ledger.proposalCount, 1);
  const proposal = ledger.proposals[0];
  assert.equal(proposal.sourceKind, "case_history");
  assert.equal(proposal.benchmarkId, "html-editorial-launch-page");
  assert.deepEqual(
    proposal.targetUpgrades.sort(),
    [
      "component_pack_upgrade",
      "ir_compiler_rule",
      "validation_calibration_example",
      "scaffold_upgrade",
      "skill_guidance_upgrade",
      "taste_memory_default",
    ].sort(),
  );
  assert.ok(proposal.typedReasons.includes("shim_dependency_removed"));
  assert.ok(proposal.typedReasons.includes("typed_contract_coverage_improved"));
  assert.equal(proposal.before.caseId, "html-ai-tools-editorial");
  assert.equal(proposal.after.caseId, "html-ai-tools-editorial");
});

test("distillation ledger skips groups without material structural gain", () => {
  const corpusSummary = {
    cases: [
      buildEntry("svg-ai-tools-hero", "2026-03-28", {
        classification: "pass",
        effectiveClassification: "pass",
        validationScore: 0.7,
        firstPaintEvidenceScore: 0.67,
        shimDependent: false,
        blueprintPresent: true,
        artifactIrPresent: true,
      }),
      buildEntry("svg-ai-tools-hero", "2026-03-30", {
        classification: "pass",
        effectiveClassification: "pass",
        validationScore: 0.71,
        firstPaintEvidenceScore: 0.68,
        shimDependent: false,
        blueprintPresent: true,
        artifactIrPresent: true,
      }),
    ],
  };

  const ledger = collectStudioArtifactDistillationLedger({
    corpusSummary,
    benchmarkCatalog: { version: 1, cases: [] },
    now: "2026-03-31T00:00:00.000Z",
  });

  assert.equal(ledger.proposalCount, 0);
  assert.equal(ledger.measuredGain, null);
});
