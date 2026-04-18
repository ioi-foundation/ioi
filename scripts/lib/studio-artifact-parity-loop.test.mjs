import assert from "node:assert/strict";
import fs from "fs";
import os from "os";
import path from "path";
import test from "node:test";

import {
  collectStudioArtifactParitySnapshot,
  createEmptyStudioArtifactParityLedger,
  loadStudioArtifactParityLoopLedger,
  planStudioArtifactParityIteration,
} from "./studio-artifact-parity-loop.mjs";

function buildValidation(classification = "repairable", overrides = {}) {
  return {
    classification,
    requestFaithfulness: 4,
    conceptCoverage: 4,
    interactionRelevance: 4,
    layoutCoherence: 4,
    visualHierarchy: 4,
    completeness: 4,
    genericShellDetected: false,
    trivialShellDetected: false,
    deservesPrimaryArtifactView: classification === "pass",
    patchedExistingArtifact: null,
    continuityRevisionUx: null,
    strongestContradiction:
      classification === "pass" ? null : "Needs another parity pass.",
    rationale: classification === "pass" ? "Ready." : "Needs work.",
    ...overrides,
  };
}

function buildCase(id, classification = "repairable", overrides = {}) {
  return {
    id,
    classification,
    blueprint: {},
    artifactIr: {},
    selectedSkills: [],
    validation: buildValidation(classification),
    fallbackUsed: false,
    failure: null,
    manifest: { renderer: "html_iframe" },
    inspect: { renderer: "html_iframe" },
    strongestContradiction:
      classification === "pass" ? null : "Needs another parity pass.",
    ...overrides,
  };
}

function buildCorpusSummary(overrides = {}) {
  const base = {
    generatedAt: "2026-03-31T00:00:00.000Z",
    totals: { pass: 0, repairable: 1, blocked: 0 },
    cases: [buildCase("html-quantum-explainer")],
    lanes: {
      liveStudio: {
        status: "pass",
        strongestContradiction: null,
        cases: [{ id: "html-quantum-explainer" }],
      },
    },
    parityChecks: {
      htmlDistinctness: {
        allDistinct: true,
        failingCaseIds: [],
      },
      refinementPatchFlow: {
        allPatched: true,
        failingCaseIds: [],
      },
      targetedEditFlow: {
        caseId: "html-quantum-explainer",
        passed: true,
      },
      styleSteeringFlow: {
        caseId: "html-quantum-explainer",
        passed: true,
      },
      revisionFlow: {
        compare: {
          classification: "pass",
          baseCaseId: "html-quantum-explainer",
          refinedCaseId: "html-quantum-explainer-refined",
          changedPaths: ["index.html"],
        },
        restore: {
          classification: "pass",
          sourceCaseId: "html-quantum-explainer",
        },
        branch: {
          classification: "pass",
          caseId: "html-quantum-explainer",
        },
      },
      repeatedRunVariationFlow: {
        classification: "pass",
        sourceCaseId: "html-quantum-explainer",
        failingRunIds: [],
      },
    },
    benchmarkSuite: {
      executedBenchmarks: 1,
      totalBenchmarks: 1,
      metrics: {
        readyRate: { available: true, value: 0.5 },
        averageValidationScore: { available: true, value: 240 },
        firstPaintEvidenceScore: { available: true, value: 180 },
      },
    },
  };

  return {
    ...base,
    ...overrides,
    lanes: {
      ...base.lanes,
      ...(overrides.lanes ?? {}),
    },
    parityChecks: {
      ...base.parityChecks,
      ...(overrides.parityChecks ?? {}),
    },
    benchmarkSuite: {
      ...base.benchmarkSuite,
      ...(overrides.benchmarkSuite ?? {}),
      metrics: {
        ...base.benchmarkSuite.metrics,
        ...(overrides.benchmarkSuite?.metrics ?? {}),
      },
    },
  };
}

test("parity loop selects scaffold for html distinctness failure", () => {
  const corpusSummary = buildCorpusSummary({
    parityChecks: {
      htmlDistinctness: {
        allDistinct: false,
        failingCaseIds: ["html-quantum-explainer"],
      },
    },
  });

  const receipt = planStudioArtifactParityIteration({
    corpusSummary,
    ledger: createEmptyStudioArtifactParityLedger(),
    now: "2026-03-31T12:00:00.000Z",
  });

  assert.equal(receipt.decision.kind, "continue");
  assert.equal(receipt.selectedInterventionFamily, "scaffold");
  assert.deepEqual(receipt.allowedInterventionFamilies, ["scaffold"]);
  assert.deepEqual(receipt.relevantCaseIds, ["html-quantum-explainer"]);
});

test("parity loop keeps improving changes and resets no-improvement streak", () => {
  const previousCorpus = buildCorpusSummary({
    totals: { pass: 0, repairable: 1, blocked: 1 },
    cases: [
      buildCase("html-quantum-explainer", "repairable"),
      buildCase("svg-ai-tools-hero", "blocked", {
        blueprint: null,
        artifactIr: null,
        validation: buildValidation("blocked"),
      }),
    ],
    benchmarkSuite: {
      executedBenchmarks: 1,
      totalBenchmarks: 2,
      metrics: {
        readyRate: { available: true, value: 0.25 },
        averageValidationScore: { available: true, value: 190 },
        firstPaintEvidenceScore: { available: true, value: 140 },
      },
    },
  });
  const currentCorpus = buildCorpusSummary({
    totals: { pass: 2, repairable: 0, blocked: 0 },
    cases: [
      buildCase("html-quantum-explainer", "pass", {
        selectedSkills: [{ name: "frontend" }],
        validation: buildValidation("pass"),
      }),
      buildCase("svg-ai-tools-hero", "pass", {
        selectedSkills: [{ name: "frontend" }],
        validation: buildValidation("pass"),
      }),
    ],
    benchmarkSuite: {
      executedBenchmarks: 2,
      totalBenchmarks: 2,
      metrics: {
        readyRate: { available: true, value: 1 },
        averageValidationScore: { available: true, value: 382 },
        firstPaintEvidenceScore: { available: true, value: 244 },
      },
    },
  });
  const ledger = createEmptyStudioArtifactParityLedger();
  ledger.receipts.push({
    createdAt: "2026-03-31T11:00:00.000Z",
    snapshot: collectStudioArtifactParitySnapshot(previousCorpus),
    noImprovementStreak: 2,
  });

  const receipt = planStudioArtifactParityIteration({
    corpusSummary: currentCorpus,
    ledger,
    now: "2026-03-31T12:00:00.000Z",
  });

  assert.equal(receipt.keepChange, true);
  assert.equal(receipt.noImprovementStreak, 0);
  assert.equal(receipt.decision.kind, "stop_parity");
  assert.ok(receipt.comparison.improvedMetrics.includes("pass_cases"));
  assert.ok(receipt.comparison.improvedMetrics.includes("blocked_cases"));
});

test("parity loop stops after the configured no-improvement plateau", () => {
  const corpusSummary = buildCorpusSummary();
  const snapshot = collectStudioArtifactParitySnapshot(corpusSummary);
  const ledger = createEmptyStudioArtifactParityLedger({
    budgets: { maxNoImprovementStreak: 2 },
  });
  ledger.receipts.push({
    createdAt: "2026-03-31T11:00:00.000Z",
    snapshot,
    noImprovementStreak: 2,
  });

  const receipt = planStudioArtifactParityIteration({
    corpusSummary,
    ledger,
    now: "2026-03-31T12:00:00.000Z",
  });

  assert.equal(receipt.keepChange, false);
  assert.equal(receipt.noImprovementStreak, 3);
  assert.equal(receipt.decision.kind, "stop_plateau");
  assert.equal(receipt.selectedInterventionFamily, null);
});

test("parity loop anchors wall-clock budget to the first recorded intervention", () => {
  const corpusSummary = buildCorpusSummary();
  const ledger = createEmptyStudioArtifactParityLedger({
    createdAt: "2026-03-30T00:00:00.000Z",
    budgets: { maxWallClockMs: 60 * 60 * 1000 },
  });

  const firstReceipt = planStudioArtifactParityIteration({
    corpusSummary,
    ledger,
    now: "2026-03-31T12:00:00.000Z",
  });

  assert.equal(firstReceipt.decision.kind, "continue");

  ledger.receipts.push({
    createdAt: "2026-03-31T11:00:00.000Z",
    snapshot: collectStudioArtifactParitySnapshot(corpusSummary),
    noImprovementStreak: 0,
  });

  const secondReceipt = planStudioArtifactParityIteration({
    corpusSummary,
    ledger,
    now: "2026-03-31T13:30:00.000Z",
  });

  assert.equal(secondReceipt.decision.kind, "stop_budget");
  assert.equal(secondReceipt.decision.reason, "Wall-clock budget reached.");
});

test("parity loop stops immediately when thresholds are already met", () => {
  const corpusSummary = buildCorpusSummary({
    totals: { pass: 1, repairable: 0, blocked: 0 },
    cases: [
      buildCase("html-quantum-explainer", "pass", {
        selectedSkills: [{ name: "frontend" }],
        validation: buildValidation("pass"),
      }),
    ],
    benchmarkSuite: {
      executedBenchmarks: 1,
      totalBenchmarks: 1,
      metrics: {
        readyRate: { available: true, value: 1 },
        averageValidationScore: { available: true, value: 392 },
        firstPaintEvidenceScore: { available: true, value: 250 },
      },
    },
  });

  const receipt = planStudioArtifactParityIteration({
    corpusSummary,
    ledger: createEmptyStudioArtifactParityLedger(),
    now: "2026-03-31T12:00:00.000Z",
  });

  assert.equal(receipt.decision.kind, "stop_parity");
  assert.equal(receipt.selectedInterventionFamily, null);
  assert.deepEqual(receipt.allowedInterventionFamilies, []);
});

test("parity loop normalizes legacy live studio lane receipts on load", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "studio-artifact-parity-ledger-"));
  try {
    const ledgerPath = path.join(
      root,
      "docs",
      "evidence",
      "studio-artifact-surface",
      "parity-loop",
      "ledger.json",
    );
    fs.mkdirSync(path.dirname(ledgerPath), { recursive: true });
    fs.writeFileSync(
      ledgerPath,
      JSON.stringify(
        {
          version: 1,
          createdAt: "2026-03-31T00:00:00.000Z",
          budgets: {},
          thresholds: {},
          receipts: [
            {
              createdAt: "2026-03-31T01:00:00.000Z",
              snapshot: {
                invariantFailures: [
                  {
                    id: "live_studio_lane",
                    label: "Live Studio lane",
                    summary: "Live Studio lane is not yet passing.",
                    family: "evidence_ux",
                    caseIds: [],
                  },
                ],
                weakestTarget: {
                  id: "live_studio_lane",
                  label: "Live Studio lane",
                  summary: "Live Studio lane is not yet passing.",
                  family: "evidence_ux",
                  caseIds: [],
                },
              },
              weakestTarget: {
                id: "live_studio_lane",
                label: "Live Studio lane",
                summary: "Live Studio lane is not yet passing.",
                family: "evidence_ux",
                caseIds: [],
              },
              decision: {
                kind: "continue",
                reason: "Address Live Studio lane.",
              },
            },
          ],
        },
        null,
        2,
      ),
    );

    const { ledger } = loadStudioArtifactParityLoopLedger({
      repoRoot: root,
      ledgerPath,
    });

    assert.equal(ledger.receipts[0].snapshot.invariantFailures[0].id, "live_studio");
    assert.equal(ledger.receipts[0].snapshot.invariantFailures[0].label, "Live Studio");
    assert.equal(ledger.receipts[0].weakestTarget.id, "live_studio");
    assert.equal(ledger.receipts[0].decision.reason, "Address Live Studio.");
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
