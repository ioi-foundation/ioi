import assert from "node:assert/strict";
import fs from "fs";
import os from "os";
import path from "path";
import test from "node:test";

import {
  collectChatArtifactArenaLedger,
  collectChatArtifactArenaView,
  writeChatArtifactArenaLedger,
} from "./chat-artifact-arena.mjs";

function buildCase(id, overrides = {}) {
  return {
    id,
    dateRoot: "2026-03-30",
    summaryPath: `/tmp/${id}/case-summary.json`,
    effectiveClassification: "pass",
    classification: "pass",
    validationScore: 0.84,
    firstPaintEvidenceScore: 0.8,
    screenshotQualityScore: 0.82,
    responsivenessScore: 0.78,
    shimDependent: false,
    blueprintPresent: true,
    artifactIrPresent: true,
    selectedSkillCount: 1,
    selectedSkillNames: ["frontend-skill"],
    retrievedExemplarCount: 1,
    productionProvenanceKind: "chat_runtime",
    productionModel: "gpt-5.4",
    acceptanceProvenanceKind: "validation_runtime",
    acceptanceModel: "gpt-5.4",
    scaffoldFamily: "editorial_explainer",
    componentFamilies: ["comparison_table", "timeline"],
    sortTimestampMs: Date.parse("2026-03-30T12:00:00.000Z"),
    ...overrides,
  };
}

test("arena ledger derives benchmark leaders, pairwise winners, and pending blind matches", () => {
  const corpusSummary = {
    cases: [
      buildCase("html-quantum-explainer-a"),
      buildCase("html-quantum-explainer-b", {
        validationScore: 0.62,
        firstPaintEvidenceScore: 0.58,
        screenshotQualityScore: 0.57,
        responsivenessScore: 0.61,
        shimDependent: true,
        scaffoldFamily: "guided_tutorial",
        componentFamilies: ["guided_stepper", "distribution_comparator"],
      }),
    ],
  };
  const benchmarkCatalog = {
    version: 1,
    cases: [
      {
        benchmarkId: "html-quantum-explainer",
        title: "Quantum explainer",
        prompt: "Create an interactive HTML artifact that explains quantum computers",
        caseBindings: ["html-quantum-explainer-a", "html-quantum-explainer-b"],
      },
    ],
  };

  const ledger = collectChatArtifactArenaLedger({
    repoRoot: "/tmp/repo",
    evidenceRoot: "/tmp/repo/docs/evidence/chat-artifact-surface",
    corpusSummary,
    benchmarkCatalog,
    externalReferences: {
      references: [
        {
          benchmarkId: "html-quantum-explainer",
          participant: "reference:external_quantum_a",
          label: "External reference quantum A",
          generatorStackId: "generator:claude_opus",
          validationStackId: "validation:claude_opus",
          scaffoldFamilyId: "scaffold:editorial_explainer",
          componentPackProfileId: "component_profile:comparison_table_timeline",
          skillSpineId: "skill_spine:frontend_skill",
        },
      ],
    },
    pairwiseMatches: {
      matches: [
        {
          benchmarkId: "html-quantum-explainer",
          leftParticipant: "stack:generator_chat_runtime_gpt_5_4__validation_validation_runtime_gpt_5_4__scaffold_editorial_explainer__component_profile_comparison_table_timeline__skill_spine_frontend_skill",
          leftExecutionId: "html-quantum-explainer:html-quantum-explainer-a:2026_03_30",
          rightParticipant: "reference:external_quantum_a",
          winner: "left",
          blind: true,
        },
      ],
    },
    now: "2026-03-31T00:00:00.000Z",
  });

  assert.equal(ledger.status, "pending_blind_comparisons");
  assert.equal(ledger.internalExecutionCount, 2);
  assert.equal(ledger.externalReferenceCount, 1);
  assert.equal(ledger.pairwiseMatchCount, 1);
  assert.equal(ledger.pendingBlindMatchCount, 2);
  assert.equal(ledger.dimensionRatings.compositeStacks.available, true);
  assert.equal(ledger.dimensionRatings.generatorStacks.available, true);

  const benchmark = ledger.benchmarks[0];
  assert.equal(benchmark.provisionalLeader.caseId, "html-quantum-explainer-a");
  assert.equal(benchmark.blindWinner.unique, true);
  assert.equal(benchmark.blindWinner.caseId, "html-quantum-explainer-a");
  assert.equal(benchmark.pendingBlindMatchCount, 2);
  assert.equal(benchmark.executions.length, 2);
});

test("arena writer persists a ledger that the arena view can surface", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "chat-artifact-arena-"));
  try {
    const evidenceRoot = path.join(root, "docs", "evidence", "chat-artifact-surface");
    const summaryPath = path.join(evidenceRoot, "corpus-summary.json");
    const benchmarkCatalogPath = path.join(evidenceRoot, "benchmark-suite.catalog.json");
    const pairwiseMatchesPath = path.join(evidenceRoot, "arena", "pairwise-matches.json");
    const externalReferencesPath = path.join(
      evidenceRoot,
      "arena",
      "external-references.json",
    );
    fs.mkdirSync(path.dirname(summaryPath), { recursive: true });
    fs.mkdirSync(path.dirname(pairwiseMatchesPath), { recursive: true });
    fs.writeFileSync(
      summaryPath,
      JSON.stringify(
        {
          cases: [buildCase("html-editorial-launch")],
        },
        null,
        2,
      ),
    );
    fs.writeFileSync(
      benchmarkCatalogPath,
      JSON.stringify(
        {
          version: 1,
          cases: [
            {
              benchmarkId: "html-editorial-launch-page",
              title: "Editorial launch page",
              prompt: "Create an interactive editorial launch page",
              caseBindings: ["html-editorial-launch"],
            },
          ],
        },
        null,
        2,
      ),
    );
    fs.writeFileSync(pairwiseMatchesPath, JSON.stringify({ matches: [] }, null, 2));
    fs.writeFileSync(
      externalReferencesPath,
      JSON.stringify(
        {
          references: [
            {
              benchmarkId: "html-editorial-launch-page",
              participant: "reference:external_launch_a",
              label: "External launch page A",
            },
          ],
        },
        null,
        2,
      ),
    );

    const { ledgerPath, ledger } = writeChatArtifactArenaLedger({
      repoRoot: root,
      evidenceRoot,
      now: "2026-03-31T05:00:00.000Z",
    });

    assert.equal(fs.existsSync(ledgerPath), true);
    assert.equal(ledger.externalReferenceCount, 1);
    assert.equal(ledger.pendingBlindMatchCount, 1);

    const view = collectChatArtifactArenaView({
      repoRoot: root,
      evidenceRoot,
      ledgerPath,
    });

    assert.equal(view.status, "pending_blind_comparisons");
    assert.equal(view.internalExecutionCount, 1);
    assert.equal(view.externalReferenceCount, 1);
    assert.equal(view.pendingBlindMatchCount, 1);
    assert.equal(view.benchmarkLeaders[0].title, "Editorial launch page");
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
