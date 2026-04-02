import test from "node:test";
import assert from "node:assert/strict";
import fs from "fs";
import os from "os";
import path from "path";

import {
  collectStudioArtifactBenchmarkSuite,
  collectStudioArtifactCorpusIndex,
  writeStudioArtifactCorpusIndex,
} from "./studio-artifact-corpus.mjs";

function writeJson(targetPath, value) {
  fs.mkdirSync(path.dirname(targetPath), { recursive: true });
  fs.writeFileSync(targetPath, JSON.stringify(value, null, 2));
}

function fixtureCaseSummary(caseId, artifactDir, summaryPath, overrides = {}) {
  return {
    id: caseId,
    prompt: `Prompt for ${caseId}`,
    artifactDir,
    manifestPath: path.join(artifactDir, "artifact-manifest.json"),
    route: {
      outcomeKind: "artifact",
      artifact: {
        renderer: "html_iframe",
        artifactClass: "interactive_single_file",
      },
    },
    artifactBrief: {
      audience: "operators",
      jobToBeDone: "inspect parity",
      subjectDomain: caseId,
      artifactThesis: `${caseId} thesis`,
      requiredConcepts: ["concept"],
      requiredInteractions: ["interaction"],
      visualTone: [],
      factualAnchors: [],
      styleDirectives: [],
      referenceHints: [],
    },
    editIntent: null,
    candidateSetMetadata: [
      {
        candidateId: "candidate-1",
        selected: true,
        model: "fixture-model",
        renderEvaluation: null,
        judge: {
          classification: "repairable",
        },
      },
    ],
    winningCandidateId: "candidate-1",
    winningCandidateRationale: "Needs repair",
    renderEvaluation: null,
    manifest: {
      artifactId: caseId,
      title: caseId,
      artifactClass: "interactive_single_file",
      renderer: "html_iframe",
      primaryTab: "render",
      verification: {
        status: "partial",
        lifecycleState: "partial",
        productionProvenance: {
          kind: "fixture_runtime",
          label: "fixture",
        },
        acceptanceProvenance: {
          kind: "fixture_runtime",
          label: "fixture",
        },
      },
      files: [
        {
          path: "index.html",
          mime: "text/html",
          role: "primary",
          renderable: true,
          downloadable: false,
        },
      ],
    },
    verifiedReply: {
      status: "partial",
      lifecycleState: "partial",
      title: caseId,
      summary: `${caseId} summary`,
      evidence: ["index.html"],
    },
    rendererOutput: {
      primaryFile: "index.html",
      capturePaths: [path.join(path.dirname(summaryPath), "captures", "render-capture.html")],
    },
    materializedFiles: ["index.html"],
    inspect: {
      inspection: {
        artifact_id: caseId,
        title: caseId,
        artifact_class: "interactive_single_file",
        renderer: "html_iframe",
        verification_status: "partial",
        lifecycle_state: "partial",
        verification_summary: "Partial",
        primary_tab: "render",
        tab_count: 3,
        file_count: 1,
        renderable_file_count: 1,
        downloadable_file_count: 0,
        repo_centric_package: false,
        render_surface_available: true,
        preferred_stage_mode: "render",
      },
      valid: true,
      validation_errors: [],
    },
    validate: { args: [], status: 0, stdout: "ok", stderr: "" },
    materialize: { args: [], status: 0, stdout: "ok", stderr: "" },
    composeReply: {
      status: "partial",
      lifecycleState: "partial",
      title: caseId,
      summary: `${caseId} summary`,
      evidence: ["index.html"],
    },
    judge: {
      classification: "repairable",
      requestFaithfulness: 2,
      conceptCoverage: 2,
      interactionRelevance: 2,
      layoutCoherence: 2,
      visualHierarchy: 2,
      completeness: 2,
      genericShellDetected: false,
      trivialShellDetected: false,
      deservesPrimaryArtifactView: false,
      patchedExistingArtifact: null,
      continuityRevisionUx: null,
      strongestContradiction: "Needs repair.",
      rationale: "Needs repair.",
    },
    rubric: null,
    classification: "pass",
    strongestContradiction: null,
    outputOrigin: "fixture_runtime",
    productionProvenance: {
      kind: "fixture_runtime",
      label: "fixture",
    },
    acceptanceProvenance: {
      kind: "fixture_runtime",
      label: "fixture",
    },
    fallbackUsed: false,
    uxLifecycle: "judged",
    failure: null,
    notes: [],
    proofPath: "full_studio_path",
    fullStudioPath: true,
    ...overrides,
  };
}

function writeBenchmarkCatalog(targetPath, cases) {
  writeJson(targetPath, { version: 1, cases });
}

test("collectStudioArtifactCorpusIndex detects shim dependency and excludes auxiliary flows", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "studio-artifact-corpus-"));
  try {
    const evidenceRoot = path.join(root, "docs", "evidence", "studio-artifact-surface");
    const primarySummaryPath = path.join(
      evidenceRoot,
      "2026-03-30",
      "live-studio-lane",
      "html-quantum-explainer-baseline",
      "case-summary.json",
    );
    const primaryArtifactDir = path.join(path.dirname(primarySummaryPath), "artifact");
    const auxiliarySummaryPath = path.join(
      evidenceRoot,
      "2026-03-28",
      "live-studio-lane",
      "repeated-run-variation",
      "svg-ai-tools-hero-variation-2",
      "case-summary.json",
    );
    const auxiliaryArtifactDir = path.join(path.dirname(auxiliarySummaryPath), "artifact");

    writeJson(
      primarySummaryPath,
      fixtureCaseSummary("html-quantum-explainer-baseline", primaryArtifactDir, primarySummaryPath),
    );
    writeJson(
      auxiliarySummaryPath,
      fixtureCaseSummary("svg-ai-tools-hero-variation-2", auxiliaryArtifactDir, auxiliarySummaryPath, {
        manifest: {
          artifactId: "svg-ai-tools-hero-variation-2",
          title: "svg-ai-tools-hero-variation-2",
          artifactClass: "visual",
          renderer: "svg",
          primaryTab: "render",
          verification: {
            status: "ready",
            lifecycleState: "ready",
          },
          files: [
            {
              path: "hero.svg",
              mime: "image/svg+xml",
              role: "primary",
              renderable: true,
              downloadable: false,
            },
          ],
        },
        rendererOutput: {
          primaryFile: "hero.svg",
          capturePaths: [],
        },
      }),
    );

    fs.mkdirSync(primaryArtifactDir, { recursive: true });
    fs.writeFileSync(
      path.join(primaryArtifactDir, "index.html"),
      "<!doctype html><main data-studio-normalized=\"true\">shimmed</main>",
    );
    fs.mkdirSync(auxiliaryArtifactDir, { recursive: true });
    fs.writeFileSync(path.join(auxiliaryArtifactDir, "hero.svg"), "<svg />");

    const summary = collectStudioArtifactCorpusIndex({ repoRoot: root, evidenceRoot });

    assert.equal(summary.cases.length, 1);
    assert.equal(summary.auxiliaryCases.length, 1);
    assert.equal(summary.cases[0].id, "html-quantum-explainer-baseline");
    assert.equal(
      summary.cases[0].caseDir,
      "2026-03-30/live_studio/html-quantum-explainer-baseline",
    );
    assert.equal(
      summary.cases[0].summaryPath,
      "2026-03-30/live_studio/html-quantum-explainer-baseline/case-summary.json",
    );
    assert.equal(summary.cases[0].effectiveClassification, "repairable");
    assert.equal(summary.cases[0].shimDependent, true);
    assert.equal(summary.totals.caseCount, 1);
    assert.equal(summary.totals.repairableCount, 1);
    assert.equal(summary.totals.shimDependentCount, 1);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("collectStudioArtifactBenchmarkSuite reports applied distillation gain when ledger evidence exists", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "studio-artifact-distillation-"));
  try {
    const evidenceRoot = path.join(root, "docs", "evidence", "studio-artifact-surface");
    const summaryPath = path.join(
      evidenceRoot,
      "2026-03-30",
      "live-studio-lane",
      "html-ai-tools-editorial",
      "case-summary.json",
    );
    const artifactDir = path.join(path.dirname(summaryPath), "artifact");
    writeJson(
      summaryPath,
      fixtureCaseSummary("html-ai-tools-editorial", artifactDir, summaryPath, {
        manifest: {
          artifactId: "html-ai-tools-editorial",
          title: "html-ai-tools-editorial",
          artifactClass: "interactive_single_file",
          renderer: "html_iframe",
          primaryTab: "render",
          verification: {
            status: "ready",
            lifecycleState: "ready",
          },
          files: [
            {
              path: "index.html",
              mime: "text/html",
              role: "primary",
              renderable: true,
              downloadable: false,
            },
          ],
        },
        verifiedReply: {
          status: "ready",
          lifecycleState: "ready",
          title: "html-ai-tools-editorial",
          summary: "ready summary",
          evidence: ["index.html"],
        },
        inspect: {
          inspection: {
            artifact_id: "html-ai-tools-editorial",
            title: "html-ai-tools-editorial",
            artifact_class: "interactive_single_file",
            renderer: "html_iframe",
            verification_status: "ready",
            lifecycle_state: "ready",
          },
          valid: true,
          validation_errors: [],
        },
        classification: "pass",
        judge: {
          classification: "pass",
          requestFaithfulness: 5,
          conceptCoverage: 5,
          interactionRelevance: 4,
          layoutCoherence: 4,
          visualHierarchy: 4,
          completeness: 4,
          genericShellDetected: false,
          trivialShellDetected: false,
          deservesPrimaryArtifactView: true,
          patchedExistingArtifact: null,
          continuityRevisionUx: null,
          strongestContradiction: null,
          rationale: "Ready.",
        },
      }),
    );
    const catalogPath = path.join(evidenceRoot, "benchmark-suite.catalog.json");
    writeBenchmarkCatalog(catalogPath, [
      {
        benchmarkId: "html-editorial-launch-page",
        title: "Editorial launch page",
        prompt: "Create an interactive HTML artifact for an AI tools editorial launch page",
        outcomeRequest: {
          artifactClass: "interactive_single_file",
          renderer: "html_iframe",
        },
        caseBindings: ["html-ai-tools-editorial"],
        categories: ["interactive_html", "editorial"],
        requiredInteractionContracts: [],
        goldenEvaluationCriteria: [],
        trackedParityTarget: false,
        referenceMode: "external_pairwise_optional",
      },
    ]);
    const distillationPath = path.join(evidenceRoot, "distillation", "ledger.json");
    writeJson(distillationPath, {
      version: 1,
      generatedAt: "2026-03-31T00:00:00.000Z",
      proposalCount: 1,
      appliedCount: 1,
      measuredGain: 0.22,
      proposals: [
        {
          proposalId: "case_history:html-ai-tools-editorial",
          status: "applied",
          targetUpgrades: ["scaffold_upgrade"],
          measuredGain: { judgeScoreDelta: 0.22 },
        },
      ],
    });

    const suite = collectStudioArtifactBenchmarkSuite({
      repoRoot: root,
      evidenceRoot,
      benchmarkCatalogPath: catalogPath,
      distillationLedgerPath: distillationPath,
    });

    assert.equal(suite.distillation.proposalCount, 1);
    assert.equal(suite.distillation.appliedCount, 1);
    assert.equal(suite.metrics.distillationGain.available, true);
    assert.equal(suite.metrics.distillationGain.value, 0.22);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("collectStudioArtifactBenchmarkSuite derives screenshot and responsiveness metrics from render evaluation", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "studio-artifact-render-metrics-"));
  try {
    const evidenceRoot = path.join(root, "docs", "evidence", "studio-artifact-surface");
    const summaryPath = path.join(
      evidenceRoot,
      "2026-03-31",
      "live-studio-lane",
      "html-quantum-explainer",
      "case-summary.json",
    );
    const artifactDir = path.join(path.dirname(summaryPath), "artifact");
    writeJson(
      summaryPath,
      fixtureCaseSummary("html-quantum-explainer", artifactDir, summaryPath, {
        renderEvaluation: {
          supported: true,
          firstPaintCaptured: true,
          interactionCaptureAttempted: true,
          captures: [
            {
              viewport: "desktop",
              width: 1440,
              height: 960,
              screenshotSha256: "desktop",
              screenshotByteCount: 4096,
              visibleElementCount: 40,
              visibleTextChars: 400,
              interactiveElementCount: 5,
            },
            {
              viewport: "mobile",
              width: 390,
              height: 844,
              screenshotSha256: "mobile",
              screenshotByteCount: 3980,
              visibleElementCount: 38,
              visibleTextChars: 390,
              interactiveElementCount: 5,
            },
          ],
          layoutDensityScore: 4,
          spacingAlignmentScore: 4,
          typographyContrastScore: 4,
          visualHierarchyScore: 4,
          blueprintConsistencyScore: 4,
          overallScore: 20,
          findings: [],
          summary: "Render evaluation cleared desktop/mobile capture with an overall score of 20/25.",
        },
      }),
    );
    const catalogPath = path.join(evidenceRoot, "benchmark-suite.catalog.json");
    writeBenchmarkCatalog(catalogPath, [
      {
        benchmarkId: "html-quantum-explainer",
        title: "Quantum explainer",
        prompt: "Create an interactive HTML artifact that explains quantum computers",
        outcomeRequest: {
          artifactClass: "interactive_single_file",
          renderer: "html_iframe",
        },
        caseBindings: ["html-quantum-explainer"],
        categories: ["interactive_html", "parity_target"],
        requiredInteractionContracts: [],
        goldenEvaluationCriteria: [],
        trackedParityTarget: true,
        referenceMode: "external_pairwise_optional",
      },
    ]);

    const suite = collectStudioArtifactBenchmarkSuite({
      repoRoot: root,
      evidenceRoot,
      benchmarkCatalogPath: catalogPath,
    });

    assert.equal(suite.cases[0].screenshotQualityScore, 0.8);
    assert.equal(suite.cases[0].responsivenessScore, 0.981);
    assert.equal(suite.metrics.screenshotQualityScore.available, true);
    assert.equal(suite.metrics.screenshotQualityScore.value, 0.8);
    assert.equal(suite.metrics.responsivenessScore.available, true);
    assert.equal(suite.metrics.responsivenessScore.value, 0.981);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("writeStudioArtifactCorpusIndex persists the aggregated summary", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "studio-artifact-corpus-write-"));
  try {
    const evidenceRoot = path.join(root, "docs", "evidence", "studio-artifact-surface");
    const summaryPath = path.join(
      evidenceRoot,
      "2026-03-30",
      "contract-lane",
      "markdown-checklist",
      "case-summary.json",
    );
    const artifactDir = path.join(path.dirname(summaryPath), "artifact");
    writeJson(summaryPath, fixtureCaseSummary("markdown-checklist", artifactDir, summaryPath, {
      manifest: {
        artifactId: "markdown-checklist",
        title: "markdown-checklist",
        artifactClass: "document",
        renderer: "markdown",
        primaryTab: "render",
        verification: {
          status: "ready",
          lifecycleState: "ready",
        },
        files: [
          {
            path: "checklist.md",
            mime: "text/markdown",
            role: "primary",
            renderable: true,
            downloadable: true,
          },
        ],
      },
      rendererOutput: {
        primaryFile: "checklist.md",
        capturePaths: [],
      },
      inspect: {
        inspection: {
          artifact_id: "markdown-checklist",
          title: "markdown-checklist",
          artifact_class: "document",
          renderer: "markdown",
          verification_status: "ready",
          lifecycle_state: "ready",
          verification_summary: "Ready",
          primary_tab: "render",
          tab_count: 3,
          file_count: 1,
          renderable_file_count: 1,
          downloadable_file_count: 1,
          repo_centric_package: false,
          render_surface_available: true,
          preferred_stage_mode: "render",
        },
      },
      judge: {
        classification: "pass",
        requestFaithfulness: 5,
        conceptCoverage: 5,
        interactionRelevance: 5,
        layoutCoherence: 5,
        visualHierarchy: 5,
        completeness: 5,
        genericShellDetected: false,
        trivialShellDetected: false,
        deservesPrimaryArtifactView: true,
        patchedExistingArtifact: null,
        continuityRevisionUx: null,
        strongestContradiction: null,
        rationale: "Good",
      },
    }));
    fs.mkdirSync(artifactDir, { recursive: true });
    fs.writeFileSync(path.join(artifactDir, "checklist.md"), "# Checklist\n");

    const outputPath = path.join(evidenceRoot, "corpus-summary.json");
    const { summary } = writeStudioArtifactCorpusIndex({
      repoRoot: root,
      evidenceRoot,
      outputPath,
    });

    const persisted = JSON.parse(fs.readFileSync(outputPath, "utf8"));
    assert.equal(persisted.totals.caseCount, 1);
    assert.equal(summary.totals.caseCount, 1);
    assert.equal(persisted.cases[0].id, "markdown-checklist");
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("collectStudioArtifactBenchmarkSuite joins the catalog to retained evidence and pairwise arena data", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "studio-artifact-benchmark-suite-"));
  try {
    const evidenceRoot = path.join(root, "docs", "evidence", "studio-artifact-surface");
    const summaryPath = path.join(
      evidenceRoot,
      "2026-03-30",
      "fixture-lane",
      "html-quantum-explainer-baseline",
      "case-summary.json",
    );
    const artifactDir = path.join(path.dirname(summaryPath), "artifact");
    writeJson(
      summaryPath,
      fixtureCaseSummary(
        "html-quantum-explainer-baseline",
        artifactDir,
        summaryPath,
        {
          blueprint: { scaffoldFamily: "editorial_explainer" },
          artifactIr: { evidenceSurfaces: [{ id: "surface-1" }] },
          selectedSkills: [{ skillId: "frontend-skill" }],
          judge: {
            classification: "pass",
            requestFaithfulness: 5,
            conceptCoverage: 4,
            interactionRelevance: 5,
            layoutCoherence: 4,
            visualHierarchy: 5,
            completeness: 4,
            genericShellDetected: false,
            trivialShellDetected: false,
            deservesPrimaryArtifactView: true,
            patchedExistingArtifact: null,
            continuityRevisionUx: null,
            strongestContradiction: null,
            rationale: "Strong artifact",
          },
          classification: "pass",
          manifest: {
            artifactId: "html-quantum-explainer-baseline",
            title: "Quantum explainer",
            artifactClass: "interactive_single_file",
            renderer: "html_iframe",
            primaryTab: "render",
            verification: {
              status: "ready",
              lifecycleState: "ready",
              productionProvenance: {
                kind: "fixture_runtime",
                label: "fixture",
              },
              acceptanceProvenance: {
                kind: "fixture_runtime",
                label: "fixture",
              },
            },
            files: [
              {
                path: "index.html",
                mime: "text/html",
                role: "primary",
                renderable: true,
                downloadable: false,
              },
            ],
          },
          verifiedReply: {
            status: "ready",
            lifecycleState: "ready",
            title: "Quantum explainer",
            summary: "Ready",
            evidence: ["index.html"],
          },
          inspect: {
            inspection: {
              artifact_id: "html-quantum-explainer-baseline",
              title: "Quantum explainer",
              artifact_class: "interactive_single_file",
              renderer: "html_iframe",
              verification_status: "ready",
              lifecycle_state: "ready",
              verification_summary: "Ready",
              primary_tab: "render",
              tab_count: 3,
              file_count: 1,
              renderable_file_count: 1,
              downloadable_file_count: 0,
              repo_centric_package: false,
              render_surface_available: true,
              preferred_stage_mode: "render",
            },
            valid: true,
            validation_errors: [],
          },
          rendererOutput: {
            primaryFile: "index.html",
            capturePaths: [path.join(path.dirname(summaryPath), "captures", "render-capture.html")],
          },
        },
      ),
    );
    fs.mkdirSync(artifactDir, { recursive: true });
    fs.writeFileSync(path.join(artifactDir, "index.html"), "<!doctype html><main><section>quantum</section></main>");

    const catalogPath = path.join(evidenceRoot, "benchmark-suite.catalog.json");
    writeBenchmarkCatalog(catalogPath, [
      {
        benchmarkId: "html-quantum-explainer",
        title: "Interactive HTML quantum explainer",
        prompt: "Create an interactive HTML artifact that explains quantum computers",
        outcomeRequest: {
          artifactClass: "interactive_single_file",
          renderer: "html_iframe",
        },
        caseBindings: ["html-quantum-explainer-baseline"],
        categories: ["interactive_html", "parity_target"],
        requiredInteractionContracts: ["detail panel updates"],
        goldenEvaluationCriteria: ["no shims"],
        trackedParityTarget: true,
        referenceMode: "external_pairwise_optional",
      },
      {
        benchmarkId: "html-guided-onboarding-explainer",
        title: "Guided onboarding explainer",
        prompt: "Create an interactive HTML artifact that guides onboarding",
        outcomeRequest: {
          artifactClass: "interactive_single_file",
          renderer: "html_iframe",
        },
        caseBindings: [],
        categories: ["interactive_html", "guided_onboarding"],
        requiredInteractionContracts: ["sequence browsing"],
        goldenEvaluationCriteria: ["visible progress"],
        trackedParityTarget: false,
        referenceMode: "external_pairwise_optional",
      },
    ]);
    const arenaPath = path.join(evidenceRoot, "arena", "pairwise-matches.json");
    writeJson(arenaPath, {
      matches: [
        {
          benchmarkId: "html-quantum-explainer",
          leftParticipant: "generator:default",
          rightParticipant: "reference:external_quantum_a",
          winner: "left",
          externalReferenceParticipant: "reference:external_quantum_a",
          blind: true,
        },
      ],
    });
    const externalReferencesPath = path.join(
      evidenceRoot,
      "arena",
      "external-references.json",
    );
    writeJson(externalReferencesPath, {
      references: [
        {
          benchmarkId: "html-quantum-explainer",
          participant: "reference:external_quantum_a",
          label: "External reference artifact A",
          artifactPath: path.join(
            evidenceRoot,
            "arena",
            "references",
            "external-quantum-a",
            "artifact",
          ),
        },
      ],
    });

    const suite = collectStudioArtifactBenchmarkSuite({
      repoRoot: root,
      evidenceRoot,
      benchmarkCatalogPath: catalogPath,
      pairwiseMatchesPath: arenaPath,
      externalReferencesPath,
    });

    assert.equal(suite.totalBenchmarks, 2);
    assert.equal(suite.executedBenchmarks, 1);
    assert.deepEqual(suite.parityTargets, ["html-quantum-explainer"]);
    assert.equal(suite.cases[0].matchedCaseId, "html-quantum-explainer-baseline");
    assert.equal(suite.cases[0].blueprintPresent, true);
    assert.equal(suite.cases[0].artifactIrPresent, true);
    assert.equal(suite.cases[1].caseAvailable, false);
    assert.equal(suite.cases[0].externalReferenceCount, 1);
    assert.deepEqual(suite.cases[0].externalReferenceParticipants, ["reference:external_quantum_a"]);
    assert.equal(suite.metrics.readyRate.value, 1);
    assert.equal(suite.arena.available, true);
    assert.equal(suite.arena.winRateVsExternalReference, 1);
    assert.equal(suite.arena.ratings[0].participant, "generator:default");
    assert.equal(suite.externalReferences.available, true);
    assert.equal(suite.externalReferences.count, 1);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("collectStudioArtifactCorpusIndex derives variance across retained repeated runs", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "studio-artifact-repeat-variance-"));
  try {
    const evidenceRoot = path.join(root, "docs", "evidence", "studio-artifact-surface");
    const sourceSummaryPath = path.join(
      evidenceRoot,
      "2026-03-31",
      "live-studio-lane",
      "svg-ai-tools-hero",
      "case-summary.json",
    );
    const variationOnePath = path.join(
      evidenceRoot,
      "2026-03-31",
      "live-studio-lane",
      "repeated-run-variation",
      "svg-ai-tools-hero-variation-2",
      "case-summary.json",
    );
    const variationTwoPath = path.join(
      evidenceRoot,
      "2026-03-31",
      "live-studio-lane",
      "repeated-run-variation",
      "svg-ai-tools-hero-variation-3",
      "case-summary.json",
    );
    const sourceArtifactDir = path.join(path.dirname(sourceSummaryPath), "artifact");
    const variationOneDir = path.join(path.dirname(variationOnePath), "artifact");
    const variationTwoDir = path.join(path.dirname(variationTwoPath), "artifact");

    writeJson(
      sourceSummaryPath,
      fixtureCaseSummary("svg-ai-tools-hero", sourceArtifactDir, sourceSummaryPath, {
        manifest: {
          artifactId: "svg-ai-tools-hero",
          title: "svg-ai-tools-hero",
          artifactClass: "visual",
          renderer: "svg",
          primaryTab: "render",
          verification: { status: "ready", lifecycleState: "ready" },
          files: [
            {
              path: "hero.svg",
              mime: "image/svg+xml",
              role: "primary",
              renderable: true,
              downloadable: false,
            },
          ],
        },
        rendererOutput: {
          primaryFile: "hero.svg",
          capturePaths: [path.join(path.dirname(sourceSummaryPath), "captures", "render-capture.svg")],
        },
        inspect: {
          inspection: {
            artifact_id: "svg-ai-tools-hero",
            title: "svg-ai-tools-hero",
            artifact_class: "visual",
            renderer: "svg",
            verification_status: "ready",
            lifecycle_state: "ready",
            verification_summary: "Ready",
            primary_tab: "render",
            tab_count: 2,
            file_count: 1,
            renderable_file_count: 1,
            downloadable_file_count: 0,
            repo_centric_package: false,
            render_surface_available: true,
            preferred_stage_mode: "render",
          },
          valid: true,
          validation_errors: [],
        },
        classification: "pass",
        judge: {
          classification: "pass",
          requestFaithfulness: 5,
          conceptCoverage: 4,
          interactionRelevance: 4,
          layoutCoherence: 4,
          visualHierarchy: 4,
          completeness: 4,
          genericShellDetected: false,
          trivialShellDetected: false,
          deservesPrimaryArtifactView: true,
          patchedExistingArtifact: null,
          continuityRevisionUx: null,
          strongestContradiction: null,
          rationale: "Strong source artifact.",
        },
      }),
    );
    writeJson(
      variationOnePath,
      fixtureCaseSummary(
        "svg-ai-tools-hero-variation-2",
        variationOneDir,
        variationOnePath,
        {
          manifest: {
            artifactId: "svg-ai-tools-hero-variation-2",
            title: "svg-ai-tools-hero-variation-2",
            artifactClass: "visual",
            renderer: "svg",
            primaryTab: "render",
            verification: { status: "ready", lifecycleState: "ready" },
            files: [
              {
                path: "hero.svg",
                mime: "image/svg+xml",
                role: "primary",
                renderable: true,
                downloadable: false,
              },
            ],
          },
          rendererOutput: {
            primaryFile: "hero.svg",
            capturePaths: [path.join(path.dirname(variationOnePath), "captures", "render-capture.svg")],
          },
          inspect: {
            inspection: {
              artifact_id: "svg-ai-tools-hero-variation-2",
              title: "svg-ai-tools-hero-variation-2",
              artifact_class: "visual",
              renderer: "svg",
              verification_status: "ready",
              lifecycle_state: "ready",
              verification_summary: "Ready",
              primary_tab: "render",
              tab_count: 2,
              file_count: 1,
              renderable_file_count: 1,
              downloadable_file_count: 0,
              repo_centric_package: false,
              render_surface_available: true,
              preferred_stage_mode: "render",
            },
            valid: true,
            validation_errors: [],
          },
          classification: "pass",
          judge: {
            classification: "pass",
            requestFaithfulness: 4,
            conceptCoverage: 4,
            interactionRelevance: 4,
            layoutCoherence: 4,
            visualHierarchy: 3,
            completeness: 4,
            genericShellDetected: false,
            trivialShellDetected: false,
            deservesPrimaryArtifactView: true,
            patchedExistingArtifact: null,
            continuityRevisionUx: null,
            strongestContradiction: null,
            rationale: "Strong variation one.",
          },
        },
      ),
    );
    writeJson(
      variationTwoPath,
      fixtureCaseSummary(
        "svg-ai-tools-hero-variation-3",
        variationTwoDir,
        variationTwoPath,
        {
          manifest: {
            artifactId: "svg-ai-tools-hero-variation-3",
            title: "svg-ai-tools-hero-variation-3",
            artifactClass: "visual",
            renderer: "svg",
            primaryTab: "render",
            verification: { status: "ready", lifecycleState: "ready" },
            files: [
              {
                path: "hero.svg",
                mime: "image/svg+xml",
                role: "primary",
                renderable: true,
                downloadable: false,
              },
            ],
          },
          rendererOutput: {
            primaryFile: "hero.svg",
            capturePaths: [path.join(path.dirname(variationTwoPath), "captures", "render-capture.svg")],
          },
          inspect: {
            inspection: {
              artifact_id: "svg-ai-tools-hero-variation-3",
              title: "svg-ai-tools-hero-variation-3",
              artifact_class: "visual",
              renderer: "svg",
              verification_status: "ready",
              lifecycle_state: "ready",
              verification_summary: "Ready",
              primary_tab: "render",
              tab_count: 2,
              file_count: 1,
              renderable_file_count: 1,
              downloadable_file_count: 0,
              repo_centric_package: false,
              render_surface_available: true,
              preferred_stage_mode: "render",
            },
            valid: true,
            validation_errors: [],
          },
          classification: "pass",
          judge: {
            classification: "pass",
            requestFaithfulness: 5,
            conceptCoverage: 4,
            interactionRelevance: 5,
            layoutCoherence: 4,
            visualHierarchy: 4,
            completeness: 5,
            genericShellDetected: false,
            trivialShellDetected: false,
            deservesPrimaryArtifactView: true,
            patchedExistingArtifact: null,
            continuityRevisionUx: null,
            strongestContradiction: null,
            rationale: "Strong variation two.",
          },
        },
      ),
    );

    writeBenchmarkCatalog(path.join(evidenceRoot, "benchmark-suite.catalog.json"), [
      {
        benchmarkId: "svg-concept-poster",
        title: "SVG concept poster",
        prompt: "Create an SVG hero concept for an AI tools brand",
        outcomeRequest: { artifactClass: "visual", renderer: "svg" },
        caseBindings: ["svg-ai-tools-hero"],
        categories: ["svg"],
        requiredInteractionContracts: [],
        goldenEvaluationCriteria: ["visual density"],
        trackedParityTarget: false,
        referenceMode: "external_pairwise_optional",
      },
    ]);
    writeJson(path.join(evidenceRoot, "2026-03-31", "corpus-summary.json"), {
      parityChecks: {
        repeatedRunVariationFlow: {
          renderer: "svg",
          sourceCaseId: "svg-ai-tools-hero",
          prompt: "Create an SVG hero concept for an AI tools brand",
          runCount: 3,
          uniqueSignatureCount: 3,
          classification: "pass",
          strongestContradiction: null,
          failingRunIds: [],
          runs: [
            { caseId: "svg-ai-tools-hero" },
            { caseId: "svg-ai-tools-hero-variation-2" },
            { caseId: "svg-ai-tools-hero-variation-3" },
          ],
        },
      },
    });

    const summary = collectStudioArtifactCorpusIndex({ repoRoot: root, evidenceRoot });

    assert.equal(
      summary.benchmarkSuite.metrics.varianceAcrossRepeatedRuns.available,
      true,
    );
    assert.ok(summary.benchmarkSuite.metrics.varianceAcrossRepeatedRuns.value < 0.15);
    assert.deepEqual(
      summary.benchmarkSuite.metrics.varianceAcrossRepeatedRuns.supportingBenchmarkIds,
      ["svg-concept-poster"],
    );
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
