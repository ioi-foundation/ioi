import test from "node:test";
import assert from "node:assert/strict";
import os from "node:os";
import path from "node:path";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";

import {
  buildHtmlDistinctnessCheck,
  buildRepeatedRunVariationCheck,
  caseRetainsStyleSteering,
  deriveCaseClassification,
  runtimeProvenanceMatches,
} from "./classification";
import type {
  CaseSummary,
  CorpusCase,
  GeneratedArtifactEvidence,
  WorkspaceBuildProof,
} from "./types";

function baseCaseConfig(id: string): CorpusCase {
  return {
    id,
    prompt: id,
    expectedRenderer: "html_iframe",
    expectedKeywords: ["unused lexical keyword"],
  };
}

function baseEvidence(): GeneratedArtifactEvidence {
  return {
    prompt: "prompt",
    title: "title",
    route: {
      artifact: {
        renderer: "html_iframe",
        artifactClass: "interactive_single_file",
      },
    },
    artifactBrief: {
      audience: "audience",
      jobToBeDone: "job",
      subjectDomain: "domain",
      artifactThesis: "thesis",
      requiredConcepts: ["concept"],
      requiredInteractions: ["interaction"],
      visualTone: [],
      factualAnchors: [],
      styleDirectives: [],
      referenceHints: [],
    },
    candidateSummaries: [],
    winningCandidateId: "candidate-1",
    winningCandidateRationale: "rationale",
    validation: {
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
      rationale: "good",
    },
    outputOrigin: "live_inference",
    productionProvenance: {
      kind: "real_local_runtime",
      label: "openai-compatible",
      model: "qwen2.5:7b",
      endpoint: "http://127.0.0.1:11434/v1/chat/completions",
    },
    acceptanceProvenance: {
      kind: "real_local_runtime",
      label: "openai-compatible",
      model: "qwen2.5:14b",
      endpoint: "http://127.0.0.1:11434/v1/chat/completions?lane=acceptance",
    },
    fallbackUsed: false,
    uxLifecycle: "validated",
    manifest: {
      artifactId: "artifact-id",
      title: "title",
      renderer: "html_iframe",
      artifactClass: "interactive_single_file",
      primaryTab: "render",
      verification: {
        status: "ready",
        lifecycleState: "ready",
        productionProvenance: {
          kind: "real_local_runtime",
          label: "openai-compatible",
        },
        acceptanceProvenance: {
          kind: "real_local_runtime",
          label: "openai-compatible",
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
      title: "title",
      summary: "summary",
      evidence: ["index.html"],
    },
    materializedFiles: ["index.html"],
    renderableFiles: ["index.html"],
  };
}

function baseSummary(
  id: string,
  artifactDir: string,
  primaryFile: string,
  renderer: CaseSummary["manifest"]["renderer"] = "html_iframe",
  classification: "pass" | "repairable" | "blocked" = "pass",
): CaseSummary {
  return {
    id,
    prompt: id,
    artifactDir,
    manifestPath: path.join(artifactDir, "artifact-manifest.json"),
    route: {},
    artifactBrief: {
      audience: "audience",
      jobToBeDone: "job",
      subjectDomain: id,
      artifactThesis: `${id} thesis`,
      requiredConcepts: ["concept"],
      requiredInteractions: ["interaction"],
      visualTone: [],
      factualAnchors: [],
      styleDirectives: [],
      referenceHints: [],
    },
    editIntent: null,
    candidateSetMetadata: [],
    winningCandidateId: "candidate-1",
    winningCandidateRationale: "rationale",
    manifest: {
      artifactId: id,
      title: id,
      renderer,
      artifactClass: "interactive_single_file",
      primaryTab: "render",
      files: [],
    },
    verifiedReply: {
      status: "ready",
      lifecycleState: "ready",
      title: id,
      summary: `${id} summary`,
      evidence: [primaryFile],
    },
    rendererOutput: {
      primaryFile,
      capturePaths: [],
    },
    materializedFiles: [primaryFile],
    inspect: {
      artifactId: id,
      title: id,
      artifactClass: "interactive_single_file",
      renderer,
      verificationStatus: "ready",
      lifecycleState: "ready",
      verificationSummary: "ready",
      primaryTab: "render",
      tabCount: 3,
      fileCount: 1,
      renderableFileCount: 1,
      downloadableFileCount: 0,
      repoCentricPackage: false,
      renderSurfaceAvailable: true,
      preferredStageMode: "render",
    },
    validate: {
      args: [],
      status: 0,
      stdout: "",
      stderr: "",
    },
    materialize: {
      args: [],
      status: 0,
      stdout: "",
      stderr: "",
    },
    composeReply: {
      status: "ready",
      lifecycleState: "ready",
      title: id,
      summary: `${id} summary`,
      evidence: [primaryFile],
    },
    validation: {
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
      rationale: "good",
    },
    rubric: {
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
      rationale: "good",
    },
    classification,
    strongestContradiction: null,
    outputOrigin: "live_inference",
    productionProvenance: null,
    acceptanceProvenance: null,
    fallbackUsed: false,
    uxLifecycle: "validated",
    failure: null,
    notes: [],
    proofPath: "contract_path",
    fullStudioPath: false,
  };
}

test("runtime provenance matching ignores lane-only endpoint tags", () => {
  const production = {
    kind: "real_local_runtime",
    label: "openai-compatible",
    model: "qwen3:8b",
    endpoint: "http://127.0.0.1:11434/v1/chat/completions",
  } as const;
  const acceptance = {
    kind: "real_local_runtime",
    label: "openai-compatible",
    model: "qwen3:8b",
    endpoint: "http://127.0.0.1:11434/v1/chat/completions?lane=acceptance",
  } as const;

  assert.equal(runtimeProvenanceMatches(production, acceptance), true);
});

test("deriveCaseClassification falls back to blocked manifest summary", () => {
  const evidence = baseEvidence();
  evidence.manifest.verification = {
    ...evidence.manifest.verification,
    status: "blocked",
    lifecycleState: "blocked",
    summary:
      "Studio materialized files, but blocked the primary presentation: repair shims still dominate the artifact.",
  };
  evidence.verifiedReply = {
    ...evidence.verifiedReply,
    status: "blocked",
    lifecycleState: "blocked",
    summary:
      "Studio materialized files, but blocked the primary presentation: repair shims still dominate the artifact.",
  };
  evidence.validation = {
    ...evidence.validation,
    strongestContradiction: null,
  };

  const result = deriveCaseClassification(
    baseCaseConfig("html-ai-tools-editorial"),
    evidence,
    "<html></html>",
    { args: [], status: 0, stdout: "", stderr: "" },
    undefined,
  );

  assert.equal(result.classification, "blocked");
  assert.equal(
    result.contradiction,
    "Studio materialized files, but blocked the primary presentation: repair shims still dominate the artifact.",
  );
});

test("deriveCaseClassification does not downgrade pass output with keyword heuristics", () => {
  const result = deriveCaseClassification(
    baseCaseConfig("html-dog-shampoo"),
    baseEvidence(),
    "artifact output without the exact configured keyword phrase",
    { args: [], status: 0, stdout: "", stderr: "" },
    undefined as WorkspaceBuildProof | undefined,
  );

  assert.equal(result.classification, "pass");
  assert.equal(result.contradiction, null);
});

test("caseRetainsStyleSteering accepts summary-level steering evidence", () => {
  assert.equal(
    caseRetainsStyleSteering(
      {
        editIntent: {
          mode: "patch",
          summary: "Refine the artifact to better align with enterprise stakeholders.",
          patchExistingArtifact: true,
          preserveStructure: true,
          targetScope: "index.html",
          targetPaths: ["index.html"],
          requestedOperations: ["updateContent"],
          toneDirectives: ["professional"],
          selectedTargets: [],
          styleDirectives: ["authoritative"],
          branchRequested: false,
        },
      },
      ["enterprise"],
    ),
    true,
  );
});

test("buildHtmlDistinctnessCheck flags duplicate html outputs instead of relying on keywords", () => {
  const root = mkdtempSync(path.join(os.tmpdir(), "ioi-classification-"));
  const summaries = new Map<string, CaseSummary>();
  const sharedHtml = "<html><body><main><h1>same shell</h1></main></body></html>";

  for (const id of ["html-dog-shampoo", "html-instacart-mcp"]) {
    const artifactDir = path.join(root, id);
    mkdirSync(artifactDir, { recursive: true });
    writeFileSync(path.join(artifactDir, "index.html"), sharedHtml, "utf8");
    summaries.set(id, baseSummary(id, artifactDir, "index.html"));
  }

  const editorialDir = path.join(root, "html-ai-tools-editorial");
  mkdirSync(editorialDir, { recursive: true });
  writeFileSync(
    path.join(editorialDir, "index.html"),
    "<html><body><main><h1>editorial artifact</h1></main></body></html>",
    "utf8",
  );
  summaries.set(
    "html-ai-tools-editorial",
    baseSummary("html-ai-tools-editorial", editorialDir, "index.html"),
  );

  const result = buildHtmlDistinctnessCheck(summaries);

  assert.equal(result.allDistinct, false);
  assert.deepEqual(
    result.failingCaseIds.sort(),
    ["html-dog-shampoo", "html-instacart-mcp"],
  );
});

test("buildRepeatedRunVariationCheck fails when repeated runs collapse to one signature", () => {
  const root = mkdtempSync(path.join(os.tmpdir(), "ioi-variation-"));
  const sharedSvg = "<svg><text>same hero shell</text></svg>";
  const runs: CaseSummary[] = [];

  for (const id of [
    "svg-ai-tools-hero",
    "svg-ai-tools-hero-variation-2",
    "svg-ai-tools-hero-variation-3",
  ]) {
    const artifactDir = path.join(root, id);
    mkdirSync(artifactDir, { recursive: true });
    writeFileSync(path.join(artifactDir, "hero.svg"), sharedSvg, "utf8");
    runs.push(baseSummary(id, artifactDir, "hero.svg", "svg"));
  }

  const result = buildRepeatedRunVariationCheck(
    "svg",
    "svg-ai-tools-hero",
    "Create an SVG hero concept for an AI tools brand",
    runs,
  );

  assert.equal(result.classification, "repairable");
  assert.equal(result.uniqueSignatureCount, 1);
  assert.deepEqual(
    result.failingRunIds.sort(),
    [
      "svg-ai-tools-hero",
      "svg-ai-tools-hero-variation-2",
      "svg-ai-tools-hero-variation-3",
    ],
  );
});

test("buildRepeatedRunVariationCheck passes when repeated runs stay faithful but diverge", () => {
  const root = mkdtempSync(path.join(os.tmpdir(), "ioi-variation-pass-"));
  const runs = [
    {
      id: "svg-ai-tools-hero",
      body: "<svg><text>grid launch motif</text></svg>",
    },
    {
      id: "svg-ai-tools-hero-variation-2",
      body: "<svg><text>radial signal rings</text></svg>",
    },
    {
      id: "svg-ai-tools-hero-variation-3",
      body: "<svg><text>stacked banner lattice</text></svg>",
    },
  ].map(({ id, body }) => {
    const artifactDir = path.join(root, id);
    mkdirSync(artifactDir, { recursive: true });
    writeFileSync(path.join(artifactDir, "hero.svg"), body, "utf8");
    return baseSummary(id, artifactDir, "hero.svg", "svg");
  });

  const result = buildRepeatedRunVariationCheck(
    "svg",
    "svg-ai-tools-hero",
    "Create an SVG hero concept for an AI tools brand",
    runs,
  );

  assert.equal(result.classification, "pass");
  assert.equal(result.uniqueSignatureCount, 3);
  assert.deepEqual(result.failingRunIds, []);
});
