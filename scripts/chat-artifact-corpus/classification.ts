import fs from "node:fs";
import path from "node:path";

import { corpusCases } from "./config";
import type {
  CaseSummary,
  CaseTotals,
  CommandCapture,
  ComposedArtifactReply,
  CorpusCase,
  FailureEnvelope,
  GeneratedArtifactEvidence,
  ValidationClassification,
  RepeatedRunVariationFlowSummary,
  RendererKind,
  RuntimeProvenance,
  WorkspaceBuildProof,
} from "./types";

export function summarizeCaseTotals(cases: CaseSummary[]): CaseTotals {
  return {
    pass: cases.filter((entry) => entry.classification === "pass").length,
    repairable: cases.filter((entry) => entry.classification === "repairable").length,
    blocked: cases.filter((entry) => entry.classification === "blocked").length,
  };
}

export function effectiveProductionProvenance(
  evidence: GeneratedArtifactEvidence,
  composeReply?: ComposedArtifactReply,
): RuntimeProvenance | null {
  return (
    evidence.productionProvenance ??
    evidence.verifiedReply.productionProvenance ??
    evidence.manifest.verification?.productionProvenance ??
    composeReply?.productionProvenance ??
    null
  );
}

export function effectiveAcceptanceProvenance(
  evidence: GeneratedArtifactEvidence,
  composeReply?: ComposedArtifactReply,
): RuntimeProvenance | null {
  return (
    evidence.acceptanceProvenance ??
    evidence.verifiedReply.acceptanceProvenance ??
    evidence.manifest.verification?.acceptanceProvenance ??
    composeReply?.acceptanceProvenance ??
    null
  );
}

export function normalizedRuntimeEndpoint(
  endpoint: string | null | undefined,
): string | null {
  const trimmed = endpoint?.trim();
  if (!trimmed) {
    return null;
  }

  const [withoutFragment, fragment = ""] = trimmed.split("#", 2);
  const queryIndex = withoutFragment.indexOf("?");
  if (queryIndex === -1) {
    return trimmed;
  }

  const base = withoutFragment.slice(0, queryIndex);
  const query = withoutFragment.slice(queryIndex + 1);
  const filteredPairs = query
    .split("&")
    .map((pair) => pair.trim())
    .filter((pair) => pair.length > 0)
    .filter((pair) => pair.split("=", 1)[0]?.trim().toLowerCase() !== "lane");

  let normalized = base;
  if (filteredPairs.length > 0) {
    normalized += `?${filteredPairs.join("&")}`;
  }
  if (fragment.length > 0) {
    normalized += `#${fragment}`;
  }

  return normalized;
}

export function runtimeProvenanceMatches(
  left: RuntimeProvenance | null | undefined,
  right: RuntimeProvenance | null | undefined,
): boolean {
  if (!left || !right) {
    return false;
  }

  return (
    left.kind === right.kind &&
    left.label === right.label &&
    left.model === right.model &&
    normalizedRuntimeEndpoint(left.endpoint) ===
      normalizedRuntimeEndpoint(right.endpoint)
  );
}

export function effectiveFailure(
  evidence: GeneratedArtifactEvidence,
  composeReply?: ComposedArtifactReply,
): FailureEnvelope | null {
  return (
    evidence.failure ??
    evidence.verifiedReply.failure ??
    evidence.manifest.verification?.failure ??
    composeReply?.failure ??
    null
  );
}

export function effectiveUxLifecycle(
  evidence: GeneratedArtifactEvidence,
  composeReply?: ComposedArtifactReply,
): string | null {
  return (
    evidence.uxLifecycle ??
    evidence.manifest.verification?.lifecycleState ??
    evidence.verifiedReply.lifecycleState ??
    composeReply?.lifecycleState ??
    null
  );
}

export function caseRetainsStyleSteering(
  summary: Pick<CaseSummary, "editIntent"> | null | undefined,
  expectedStyleTerms: string[],
): boolean {
  if (!summary?.editIntent) {
    return false;
  }
  const steeringText = [
    summary.editIntent.summary ?? "",
    ...(summary.editIntent.toneDirectives ?? []),
    ...(summary.editIntent.styleDirectives ?? []),
  ]
    .join(" ")
    .toLowerCase();
  return expectedStyleTerms.some((term) =>
    steeringText.includes(term.toLowerCase()),
  );
}

export function deriveCaseClassification(
  caseConfig: CorpusCase,
  evidence: GeneratedArtifactEvidence,
  artifactText: string,
  validate: CommandCapture,
  workspaceBuild: WorkspaceBuildProof | undefined,
): { classification: ValidationClassification; contradiction: string | null; notes: string[] } {
  const notes: string[] = [];
  const failure = effectiveFailure(evidence);
  const surfacedStatus =
    evidence.manifest.verification?.status ?? evidence.verifiedReply.status;
  const surfacedSummary =
    evidence.manifest.verification?.summary ??
    evidence.verifiedReply.summary ??
    null;
  const surfacedReady =
    surfacedStatus === "ready" &&
    evidence.verifiedReply.status === "ready" &&
    validate.status === 0 &&
    !failure;
  const surfacedBlocked =
    surfacedStatus === "blocked" ||
    evidence.verifiedReply.status === "blocked" ||
    failure != null;
  let classification: ValidationClassification = surfacedReady
    ? "pass"
    : surfacedBlocked
      ? "blocked"
      : (evidence.validation?.classification ?? "blocked");
  let contradiction = surfacedReady
    ? null
    : (evidence.validation?.strongestContradiction ??
      failure?.message ??
      (surfacedBlocked ? surfacedSummary : null));

  if (surfacedReady && evidence.validation?.classification !== "pass") {
    notes.push("surfaced lifecycle cleared a soft raw validation finding");
  }

  if (evidence.route.artifact?.renderer !== caseConfig.expectedRenderer) {
    classification = "blocked";
    contradiction = `Route returned ${evidence.route.artifact?.renderer ?? "null"} instead of ${caseConfig.expectedRenderer}.`;
  }

  if (validate.status !== 0) {
    classification = classification === "blocked" ? "blocked" : "repairable";
    contradiction ??= "Artifact validation did not pass.";
    notes.push("cli validate failed");
  }

  if (caseConfig.refinementFrom) {
    if (!evidence.editIntent) {
      classification = "repairable";
      contradiction ??= "Refinement case is missing typed edit intent evidence.";
    } else {
      if (caseConfig.expectedEditMode && evidence.editIntent.mode !== caseConfig.expectedEditMode) {
        classification = "repairable";
        contradiction ??= `Expected edit mode ${caseConfig.expectedEditMode} but saw ${evidence.editIntent.mode}.`;
      }
      if (
        caseConfig.expectedEditMode === "patch" &&
        !evidence.editIntent.patchExistingArtifact
      ) {
        classification = "repairable";
        contradiction ??= "Refinement restarted instead of patching the current artifact.";
      }
      if (
        caseConfig.requiresSelection &&
        (!evidence.editIntent.selectedTargets || evidence.editIntent.selectedTargets.length === 0)
      ) {
        classification = "repairable";
        contradiction ??= "Targeted partial edit did not preserve artifact-local selection.";
      }
      if (
        caseConfig.expectedEditMode === "patch" &&
        evidence.validation?.patchedExistingArtifact === false
      ) {
        classification = "repairable";
        contradiction ??= "Validation reported that refinement did not patch the existing artifact.";
      }
    }
  }

  if (caseConfig.styleSteering) {
    const steeringTerms =
      caseConfig.expectedStyleTerms && caseConfig.expectedStyleTerms.length > 0
        ? caseConfig.expectedStyleTerms
        : ["enterprise"];
    if (
      !caseRetainsStyleSteering(
        { editIntent: evidence.editIntent ?? null },
        steeringTerms,
      )
    ) {
      classification = "repairable";
      contradiction ??=
        "Style steering intent did not retain the requested tone directive.";
    }
  }

  if (workspaceBuild && !workspaceBuild.buildOk) {
    classification = "blocked";
    contradiction ??= "Workspace artifact did not complete the install/build proof.";
    notes.push("workspace build failed");
  }

  return { classification, contradiction, notes };
}

function normalizeArtifactDistinctnessText(text: string): string {
  return text.toLowerCase().replace(/\s+/g, " ").trim();
}

export function artifactDistinctnessSignature(summary: CaseSummary): string | null {
  const primaryFile = summary.rendererOutput.primaryFile;
  if (!primaryFile) {
    return null;
  }

  const artifactPath = path.join(summary.artifactDir, primaryFile);
  if (!fs.existsSync(artifactPath)) {
    return null;
  }

  return normalizeArtifactDistinctnessText(fs.readFileSync(artifactPath, "utf8"));
}

export function buildHtmlDistinctnessCheck(cases: Map<string, CaseSummary>) {
  const htmlCaseIds = [
    "html-dog-shampoo",
    "html-instacart-mcp",
    "html-ai-tools-editorial",
  ];
  const failingCaseIds = new Set<string>();
  const signatures = new Map<string, string>();

  for (const caseId of htmlCaseIds) {
    const summary = cases.get(caseId);
    if (!summary || summary.classification !== "pass") {
      failingCaseIds.add(caseId);
      continue;
    }

    const signature = artifactDistinctnessSignature(summary);
    if (!signature) {
      failingCaseIds.add(caseId);
      continue;
    }

    signatures.set(caseId, signature);
  }

  for (let index = 0; index < htmlCaseIds.length; index += 1) {
    for (let nextIndex = index + 1; nextIndex < htmlCaseIds.length; nextIndex += 1) {
      const leftId = htmlCaseIds[index];
      const rightId = htmlCaseIds[nextIndex];
      const leftSignature = signatures.get(leftId);
      const rightSignature = signatures.get(rightId);
      if (!leftSignature || !rightSignature) {
        continue;
      }
      if (leftSignature === rightSignature) {
        failingCaseIds.add(leftId);
        failingCaseIds.add(rightId);
      }
    }
  }

  return {
    caseIds: htmlCaseIds,
    allDistinct: failingCaseIds.size === 0,
    failingCaseIds: Array.from(failingCaseIds),
  };
}

export function buildRepeatedRunVariationCheck(
  renderer: RendererKind,
  sourceCaseId: string,
  prompt: string,
  runs: CaseSummary[],
): RepeatedRunVariationFlowSummary {
  const failingRunIds = new Set<string>();
  const signatures = new Set<string>();

  for (const run of runs) {
    if (run.classification !== "pass") {
      failingRunIds.add(run.id);
    }

    const signature = artifactDistinctnessSignature(run);
    if (!signature) {
      failingRunIds.add(run.id);
      continue;
    }
    signatures.add(signature);
  }

  const uniqueSignatureCount = signatures.size;
  let classification: ValidationClassification = runs.some(
    (run) => run.classification === "blocked",
  )
    ? "blocked"
    : failingRunIds.size > 0
      ? "repairable"
      : "pass";
  let strongestContradiction =
    runs.find((run) => run.classification === "blocked")?.strongestContradiction ??
    runs.find((run) => run.classification === "repairable")?.strongestContradiction ??
    null;

  if (uniqueSignatureCount < 2) {
    classification = classification === "blocked" ? "blocked" : "repairable";
    strongestContradiction ??=
      "Repeated runs collapsed onto one surfaced artifact signature.";
    for (const run of runs) {
      failingRunIds.add(run.id);
    }
  }

  return {
    renderer,
    sourceCaseId,
    prompt,
    runCount: runs.length,
    uniqueSignatureCount,
    classification,
    strongestContradiction,
    failingRunIds: Array.from(failingRunIds),
    runs: runs.map((run) => ({
      caseId: run.id,
      artifactDir: run.artifactDir,
      stateRoot: run.stateRoot,
      classification: run.classification,
      strongestContradiction: run.strongestContradiction,
      signature: artifactDistinctnessSignature(run),
    })),
  };
}

export function buildRefinementPatchCheck(cases: Map<string, CaseSummary>) {
  const refinementIds = [
    "html-dog-shampoo-enterprise",
    "html-dog-shampoo-technical",
    "html-dog-shampoo-targeted-chart",
  ];
  const failingCaseIds = refinementIds.filter((caseId) => {
    const summary = cases.get(caseId);
    return (
      !summary ||
      summary.editIntent?.patchExistingArtifact !== true ||
      summary.validation?.patchedExistingArtifact === false
    );
  });
  return {
    caseIds: refinementIds,
    allPatched: failingCaseIds.length === 0,
    failingCaseIds,
  };
}
