import { cp, mkdir } from "node:fs/promises";
import path from "node:path";

import {
  cliBinary,
  contractEvidenceRoot,
  corpusCases,
  inferenceUnavailableLiveCase,
  liveEvidenceRoot,
  chatArtifactProofBinary,
} from "./config";
import {
  captureRendererOutput,
  collectArtifactText,
  diffArtifactFiles,
  ensureCleanDirectory,
  loadGenerationEvidence,
  primaryFilePath,
  readJsonIfPresent,
  writeJson,
  writeText,
} from "./artifact-files";
import { restoredMatchesRevisionSource } from "./revision-parity";
import {
  autoConfiguredRuntime,
  configuredLiveRuntimeEndpoint,
  ensureChatRuntimeProofBinary,
  runtimeEnvOverridesForRenderer,
  runCliJson,
  runCommand,
  runChatRuntimeProofJson,
} from "./runtime";
import {
  buildRepeatedRunVariationCheck,
  buildHtmlDistinctnessCheck,
  buildRefinementPatchCheck,
  deriveCaseClassification,
  effectiveAcceptanceProvenance,
  effectiveFailure,
  effectiveProductionProvenance,
  effectiveUxLifecycle,
  runtimeProvenanceMatches,
  summarizeCaseTotals,
} from "./classification";
import type {
  ArtifactInspection,
  CaseSummary,
  CommandCapture,
  ComposedArtifactReply,
  CorpusCase,
  GeneratedArtifactEvidence,
  ValidationClassification,
  LiveChatRuntimeLaneSummary,
  RepeatedRunVariationFlowSummary,
  RevisionFlowSummary,
  ChatRuntimeValidationResult,
} from "./types";

const INFERENCE_RUNTIME_ENV_KEYS = [
  "AUTOPILOT_LOCAL_RUNTIME_URL",
  "LOCAL_LLM_URL",
  "AUTOPILOT_LOCAL_RUNTIME_HEALTH_URL",
  "AUTOPILOT_LOCAL_RUNTIME_MODEL",
  "LOCAL_LLM_MODEL",
  "OPENAI_MODEL",
  "AUTOPILOT_ACCEPTANCE_RUNTIME_URL",
  "AUTOPILOT_ACCEPTANCE_RUNTIME_HEALTH_URL",
  "AUTOPILOT_ACCEPTANCE_RUNTIME_MODEL",
  "AUTOPILOT_INFERENCE_HTTP_TIMEOUT_SECS",
  "OLLAMA_CONTEXT_LENGTH",
] as const;

function clearedInferenceRuntimeEnv() {
  return Object.fromEntries(
    INFERENCE_RUNTIME_ENV_KEYS.map((key) => [key, undefined]),
  );
}

function missingArtifactInspection(): ArtifactInspection {
  return {
    artifactId: "",
    title: "missing",
    artifactClass: "missing",
    renderer: "missing",
    verificationStatus: "blocked",
    lifecycleState: "blocked",
    verificationSummary: "Required revision-flow evidence is missing.",
    primaryTab: "evidence",
    tabCount: 0,
    fileCount: 0,
    renderableFileCount: 0,
    downloadableFileCount: 0,
    repoCentricPackage: false,
    renderSurfaceAvailable: false,
    preferredStageMode: "evidence",
  };
}

function liveParityContradiction(
  liveCaseSummaries: CaseSummary[],
  htmlDistinctness: ReturnType<typeof buildHtmlDistinctnessCheck>,
  refinementPatchFlow: ReturnType<typeof buildRefinementPatchCheck>,
  targetedEditFlowCase: CaseSummary | undefined,
  styleSteeringCase: CaseSummary | undefined,
  revisionFlow: RevisionFlowSummary,
  repeatedRunVariationFlow: RepeatedRunVariationFlowSummary,
) {
  const caseContradiction = liveCaseSummaries.find(
    (caseSummary) => caseSummary.classification !== "pass",
  )?.strongestContradiction;
  if (caseContradiction) {
    return caseContradiction;
  }
  if (!htmlDistinctness.allDistinct) {
    return "Repeated HTML runs collapsed into the same renderer shell.";
  }
  if (!refinementPatchFlow.allPatched) {
    return "Refinement flow restarted instead of patching the current artifact.";
  }
  if (targetedEditFlowCase?.classification !== "pass") {
    return (
      targetedEditFlowCase?.strongestContradiction ??
      "Targeted edit flow did not preserve artifact-local selection."
    );
  }
  if (styleSteeringCase?.classification !== "pass") {
    return (
      styleSteeringCase?.strongestContradiction ??
      "Style steering flow did not preserve the requested tone."
    );
  }
  if (revisionFlow.compare.classification !== "pass") {
    return "Revision compare did not surface changed artifact paths.";
  }
  if (revisionFlow.restore.classification !== "pass") {
    return "Revision restore did not return the saved base artifact state.";
  }
  if (revisionFlow.branch.classification !== "pass") {
    return "Revision branch did not preserve a distinct branch edit mode.";
  }
  if (repeatedRunVariationFlow.classification !== "pass") {
    return (
      repeatedRunVariationFlow.strongestContradiction ??
      "Repeated creative runs collapsed into the same artifact shell."
    );
  }
  return null;
}

function missingJudgeResult(reason: string): ChatRuntimeValidationResult {
  return {
    classification: "blocked",
    requestFaithfulness: 1,
    conceptCoverage: 1,
    interactionRelevance: 1,
    layoutCoherence: 1,
    visualHierarchy: 1,
    completeness: 1,
    genericShellDetected: true,
    trivialShellDetected: true,
    deservesPrimaryArtifactView: false,
    patchedExistingArtifact: null,
    continuityRevisionUx: 1,
    strongestContradiction: reason,
    rationale: reason,
  };
}

function missingRevisionFlowSummary(reason: string): RevisionFlowSummary {
  return {
    compare: {
      baseCaseId: "html-dog-shampoo",
      refinedCaseId: "html-dog-shampoo-technical",
      changedPaths: [],
      classification: "blocked",
    },
    restore: {
      sourceCaseId: "html-dog-shampoo",
      restoredDir: "",
      restoredMatchesSource: false,
      validate: {
        args: [],
        status: 1,
        stdout: "",
        stderr: reason,
      },
      inspect: missingArtifactInspection(),
      validation: missingJudgeResult(reason),
      classification: "blocked",
    },
    branch: {
      caseId: "html-dog-shampoo-branch-editorial",
      editMode: null,
      classification: "blocked",
    },
  };
}

function missingVariationFlowSummary(
  renderer: RepeatedRunVariationFlowSummary["renderer"],
  sourceCaseId: string,
  prompt: string,
  reason: string,
): RepeatedRunVariationFlowSummary {
  return {
    renderer,
    sourceCaseId,
    prompt,
    runCount: 0,
    uniqueSignatureCount: 0,
    classification: "blocked",
    strongestContradiction: reason,
    failingRunIds: [],
    runs: [],
  };
}

export async function loadPersistedCaseSummaries(
  root: string,
  cases: CorpusCase[],
): Promise<Map<string, CaseSummary>> {
  const loaded = new Map<string, CaseSummary>();
  for (const caseConfig of cases) {
    const summary = await readJsonIfPresent<CaseSummary>(
      path.join(root, caseConfig.id, "case-summary.json"),
    );
    if (summary) {
      loaded.set(caseConfig.id, summary);
    }
  }
  return loaded;
}

async function summarizeLiveChatRuntimeResults(
  liveCases: Map<string, CaseSummary>,
  runtimeEndpoint: string | null,
  runtimeConfigured: boolean,
  unavailableProof: CommandCapture | null,
): Promise<LiveChatRuntimeLaneSummary> {
  const liveCaseSummaries = corpusCases
    .map((caseConfig) => liveCases.get(caseConfig.id))
    .filter((value): value is CaseSummary => Boolean(value));
  const fullLiveMatrixExecuted = liveCaseSummaries.length === corpusCases.length;
  const totals = summarizeCaseTotals(liveCaseSummaries);
  const revisionFlow = await buildLiveRevisionFlow(liveCases);
  const repeatedRunVariationFlow =
    await buildLiveRepeatedRunVariationFlow(liveCases);
  const htmlDistinctness = buildHtmlDistinctnessCheck(liveCases);
  const refinementPatchFlow = buildRefinementPatchCheck(liveCases);
  const targetedEditFlowCase = liveCases.get("html-dog-shampoo-targeted-chart");
  const styleSteeringCase = liveCases.get("html-dog-shampoo-enterprise");
  const parityFailures = fullLiveMatrixExecuted
    ? [
        !htmlDistinctness.allDistinct,
        !refinementPatchFlow.allPatched,
        targetedEditFlowCase?.classification !== "pass",
        styleSteeringCase?.classification !== "pass",
        revisionFlow.compare.classification !== "pass",
        revisionFlow.restore.classification !== "pass",
        revisionFlow.branch.classification !== "pass",
        repeatedRunVariationFlow.classification !== "pass",
      ].some(Boolean)
    : false;
  const strongestContradiction = fullLiveMatrixExecuted
    ? liveParityContradiction(
        liveCaseSummaries,
        htmlDistinctness,
        refinementPatchFlow,
        targetedEditFlowCase,
        styleSteeringCase,
        revisionFlow,
        repeatedRunVariationFlow,
      )
    : liveCaseSummaries.find((caseSummary) => caseSummary.classification !== "pass")
        ?.strongestContradiction ?? null;

  const autoRuntime = autoConfiguredRuntime();
  return {
    status:
      !runtimeConfigured || totals.blocked > 0 || parityFailures
        ? "blocked"
        : totals.repairable > 0
          ? "repairable"
          : "pass",
    fullChatRuntimePath: true,
    runtimeConfigured,
    runtimeEndpoint,
    totals,
    strongestContradiction:
      parityFailures || totals.blocked > 0 || totals.repairable > 0
        ? strongestContradiction
        : null,
    notes: [
      `Executed ${liveCaseSummaries.length} live Chat-runtime-path cases through the kernel-owned proof runner.`,
      ...(autoRuntime && runtimeConfigured
        ? [
            `Auto-configured the live lane against local Ollama at ${autoRuntime.endpoint} using production=${autoRuntime.productionModel} and acceptance=${autoRuntime.acceptanceModel}.`,
          ]
        : []),
      ...(!fullLiveMatrixExecuted
        ? ["Skipped cross-case live parity checks because this was a partial live run."]
        : []),
      `Live lane totals: pass=${totals.pass}, repairable=${totals.repairable}, blocked=${totals.blocked}.`,
    ],
    unavailableProof,
    evidenceRoot: liveEvidenceRoot,
    cases: liveCaseSummaries,
    revisionFlow,
    repeatedRunVariationFlow,
  };
}

async function summarizeArtifactCase(
  caseConfig: CorpusCase,
  caseDir: string,
  artifactDir: string,
  materializedDir: string,
  evidence: GeneratedArtifactEvidence,
  options: {
    stateRoot?: string;
    proofPath: "contract_path" | "full_chat_artifact_path";
    fullChatRuntimePath: boolean;
  },
): Promise<CaseSummary> {
  await writeJson(path.join(caseDir, "route.json"), evidence.route);

  const manifestPath = path.join(artifactDir, "artifact-manifest.json");
  const inspect = runCliJson([
    "artifact",
    "inspect",
    manifestPath,
    "--json",
  ]) as ArtifactInspection;
  await writeJson(path.join(caseDir, "inspect.json"), inspect);

  const validation = runCliJson([
    "artifact",
    "validation",
    artifactDir,
    "--json",
  ]) as ChatRuntimeValidationResult;
  await writeJson(path.join(caseDir, "validation.json"), validation);

  const composeReply = runCliJson([
    "artifact",
    "compose-reply",
    manifestPath,
    "--json",
  ]) as ComposedArtifactReply;
  await writeJson(path.join(caseDir, "compose-reply.json"), composeReply);

  const validate = runCommand(
    cliBinary,
    [
      "artifact",
      "validate",
      manifestPath,
      "--source-root",
      artifactDir,
    ],
    { allowFailure: true },
  );
  await writeText(
    path.join(caseDir, "validate.txt"),
    [validate.stdout, validate.stderr].filter(Boolean).join("\n"),
  );

  const materialize = runCommand(
    cliBinary,
    [
      "artifact",
      "materialize",
      manifestPath,
      "--source-root",
      artifactDir,
      "--output",
      materializedDir,
      "--force",
    ],
    { allowFailure: true },
  );
  await writeText(
    path.join(caseDir, "materialize.txt"),
    [materialize.stdout, materialize.stderr].filter(Boolean).join("\n"),
  );

  const rendererOutput = await captureRendererOutput(
    caseConfig,
    evidence,
    artifactDir,
    caseDir,
  );
  const artifactText = await collectArtifactText(evidence, artifactDir);
  const derived = deriveCaseClassification(
    caseConfig,
    {
      ...evidence,
      validation,
    },
    artifactText,
    validate,
    rendererOutput.workspaceBuild,
  );
  const productionProvenance = effectiveProductionProvenance(evidence, composeReply);
  const acceptanceProvenance = effectiveAcceptanceProvenance(evidence, composeReply);
  const failure = effectiveFailure(evidence, composeReply);
  const uxLifecycle = effectiveUxLifecycle(evidence, composeReply);

  return {
    id: caseConfig.id,
    prompt: caseConfig.prompt,
    artifactDir,
    stateRoot: options.stateRoot,
    manifestPath,
    route: evidence.route,
    artifactBrief: evidence.artifactBrief,
    blueprint: evidence.blueprint ?? null,
    artifactIr: evidence.artifactIr ?? null,
    selectedSkills: evidence.selectedSkills ?? [],
    retrievedExemplars: evidence.retrievedExemplars ?? [],
    editIntent: evidence.editIntent ?? null,
    candidateSetMetadata: evidence.candidateSummaries,
    winningCandidateId: evidence.winningCandidateId,
    winningCandidateRationale: evidence.winningCandidateRationale,
    renderEvaluation:
      evidence.renderEvaluation ??
      evidence.candidateSummaries.find((candidate) => candidate.selected)?.renderEvaluation ??
      null,
    manifest: evidence.manifest,
    verifiedReply: evidence.verifiedReply,
    rendererOutput: {
      primaryFile: primaryFilePath(evidence),
      capturePaths: rendererOutput.capturePaths,
      workspaceBuild: rendererOutput.workspaceBuild,
    },
    materializedFiles: evidence.materializedFiles,
    inspect,
    validate,
    materialize,
    composeReply,
    validation,
    rubric: validation,
    classification: derived.classification,
    strongestContradiction: derived.contradiction,
    outputOrigin: evidence.outputOrigin,
    productionProvenance,
    acceptanceProvenance,
    fallbackUsed: evidence.fallbackUsed,
    uxLifecycle,
    failure,
    notes: derived.notes,
    proofPath: options.proofPath,
    fullChatRuntimePath: options.fullChatRuntimePath,
  };
}

export async function executeCase(
  caseConfig: CorpusCase,
  priorCases: Map<string, CaseSummary>,
): Promise<CaseSummary> {
  const caseDir = path.join(contractEvidenceRoot, caseConfig.id);
  const artifactDir = path.join(caseDir, "artifact");
  const materializedDir = path.join(caseDir, "materialized");
  await ensureCleanDirectory(caseDir);

  const refinement = caseConfig.refinementFrom
    ? priorCases.get(caseConfig.refinementFrom)
    : undefined;
  const envOverrides = runtimeEnvOverridesForRenderer(
    caseConfig.expectedRenderer,
    "contract",
  );

  const route = runCliJson([
    "artifact",
    caseConfig.useQueryAlias ? "query" : "route",
    "--local",
    "--json",
    ...(refinement ? ["--refinement", refinement.artifactDir] : []),
    ...(refinement ? ["--active-artifact-id", refinement.manifest.artifactId] : []),
    ...(caseConfig.selectedTargets?.flatMap((target) => [
      "--selected-target-json",
      JSON.stringify(target),
    ]) ?? []),
    caseConfig.prompt,
  ], undefined, { envOverrides }) as GeneratedArtifactEvidence["route"];
  await writeJson(path.join(caseDir, "route.json"), route);

  const evidence = runCliJson([
    "artifact",
    "generate",
    "--local",
    "--output",
    artifactDir,
    "--force",
    ...(refinement ? ["--refinement", refinement.artifactDir] : []),
    ...(refinement ? ["--active-artifact-id", refinement.manifest.artifactId] : []),
    ...(caseConfig.selectedTargets?.flatMap((target) => [
      "--selected-target-json",
      JSON.stringify(target),
    ]) ?? []),
    "--json",
    caseConfig.prompt,
  ], undefined, { envOverrides }) as GeneratedArtifactEvidence;
  const summary = await summarizeArtifactCase(
    caseConfig,
    caseDir,
    artifactDir,
    materializedDir,
    evidence,
    {
      proofPath: "contract_path",
      fullChatRuntimePath: false,
    },
  );
  await writeJson(path.join(caseDir, "case-summary.json"), summary);
  return summary;
}

export async function executeLiveCase(
  caseConfig: CorpusCase,
  priorCases: Map<string, CaseSummary>,
): Promise<CaseSummary> {
  const caseDir = path.join(liveEvidenceRoot, caseConfig.id);
  const artifactDir = path.join(caseDir, "artifact");
  const materializedDir = path.join(caseDir, "materialized");
  const stateRoot = path.join(caseDir, "state");
  await ensureCleanDirectory(caseDir);

  const refinement = caseConfig.refinementFrom
    ? priorCases.get(caseConfig.refinementFrom)
    : undefined;
  if (refinement?.stateRoot) {
    await cp(refinement.stateRoot, stateRoot, { recursive: true });
  } else {
    await mkdir(stateRoot, { recursive: true });
  }
  const envOverrides = runtimeEnvOverridesForRenderer(
    caseConfig.expectedRenderer,
    "live",
  );

  const evidence = runChatRuntimeProofJson(
    [
      "run-turn",
      "--state-root",
      stateRoot,
      "--output",
      artifactDir,
      ...(caseConfig.selectedTargets?.flatMap((target) => [
        "--selected-target-json",
        JSON.stringify(target),
      ]) ?? []),
      "--prompt",
      caseConfig.prompt,
    ],
    { envOverrides },
  ) as GeneratedArtifactEvidence;
  return summarizeLiveCase(caseConfig, caseDir, artifactDir, materializedDir, stateRoot, evidence);
}

export async function summarizeLiveCase(
  caseConfig: CorpusCase,
  caseDir: string,
  artifactDir: string,
  materializedDir: string,
  stateRoot: string,
  evidence: GeneratedArtifactEvidence,
): Promise<CaseSummary> {
  const summary = await summarizeArtifactCase(
    caseConfig,
    caseDir,
    artifactDir,
    materializedDir,
    evidence,
    {
      stateRoot,
      proofPath: "full_chat_artifact_path",
      fullChatRuntimePath: true,
    },
  );

  const notes = [...summary.notes];
  let classification = summary.classification;
  let contradiction = summary.strongestContradiction;
  const productionProvenance = summary.productionProvenance;
  const acceptanceProvenance = summary.acceptanceProvenance;

  if (evidence.fullChatRuntimePath !== true) {
    classification = "blocked";
    contradiction ??= "Live case did not record full Chat-runtime-path provenance.";
  }

  if (!productionProvenance || !acceptanceProvenance) {
    classification = "blocked";
    contradiction ??= "Live case is missing production or acceptance provenance.";
  }

  if (evidence.fallbackUsed) {
    classification = "blocked";
    contradiction ??=
      "A fallback was surfaced as the primary artifact in the live Chat runtime lane.";
  }

  const disallowedKinds = new Set([
    "fixture_runtime",
    "mock_runtime",
    "deterministic_continuity_fallback",
    "inference_unavailable",
  ]);
  if (
    disallowedKinds.has(productionProvenance?.kind ?? "") ||
    disallowedKinds.has(acceptanceProvenance?.kind ?? "")
  ) {
    classification = "blocked";
    contradiction ??=
      "Live parity case used a disallowed runtime provenance in the primary artifact path.";
  }

  if (
    productionProvenance &&
    acceptanceProvenance &&
    runtimeProvenanceMatches(productionProvenance, acceptanceProvenance)
  ) {
    notes.push(
      "production and acceptance validation shared the same runtime provenance for this live run",
    );
  }

  const finalized: CaseSummary = {
    ...summary,
    classification,
    strongestContradiction: contradiction,
    notes,
  };
  await writeJson(path.join(caseDir, "case-summary.json"), finalized);
  return finalized;
}

export async function executeInferenceUnavailableLiveCase(): Promise<CaseSummary> {
  const caseDir = path.join(liveEvidenceRoot, inferenceUnavailableLiveCase.id);
  const artifactDir = path.join(caseDir, "artifact");
  const materializedDir = path.join(caseDir, "materialized");
  const stateRoot = path.join(caseDir, "state");
  await ensureCleanDirectory(caseDir);
  await mkdir(stateRoot, { recursive: true });

  const evidence = runChatRuntimeProofJson(
    [
      "run-turn",
      "--state-root",
      stateRoot,
      "--output",
      artifactDir,
      "--prompt",
      inferenceUnavailableLiveCase.prompt,
    ],
    {
      disableAutoRuntime: true,
      envOverrides: clearedInferenceRuntimeEnv(),
    },
  ) as GeneratedArtifactEvidence;
  await writeJson(path.join(caseDir, "route.json"), evidence.route);

  const summary = await summarizeArtifactCase(
    inferenceUnavailableLiveCase,
    caseDir,
    artifactDir,
    materializedDir,
    evidence,
    {
      stateRoot,
      proofPath: "full_chat_artifact_path",
      fullChatRuntimePath: true,
    },
  );
  const truthfullyBlocked =
    evidence.fullChatRuntimePath === true &&
    evidence.fallbackUsed === false &&
    summary.failure?.code === "inference_unavailable" &&
    summary.productionProvenance?.kind === "inference_unavailable" &&
    summary.acceptanceProvenance?.kind === "inference_unavailable" &&
    summary.validation?.classification === "blocked";

  const notes = [
    "This case intentionally verifies the product-path fail-fast contract when inference is unavailable.",
  ];
  if (!truthfullyBlocked) {
    notes.push(
      "The blocked artifact did not preserve the expected typed inference-unavailable provenance and failure envelope.",
    );
  }

  const finalized: CaseSummary = {
    ...summary,
    classification: truthfullyBlocked ? "pass" : "repairable",
    strongestContradiction: truthfullyBlocked
      ? null
      : "Inference-unavailable proof did not surface a truthful typed blocked artifact.",
    notes,
  };
  await writeJson(path.join(caseDir, "case-summary.json"), finalized);
  return finalized;
}

export async function buildRevisionFlow(
  cases: Map<string, CaseSummary>,
): Promise<RevisionFlowSummary> {
  const restoreDiffIgnorePaths = [
    "chat-artifact-session.json",
    "revision-history.json",
  ];
  const base = cases.get("html-dog-shampoo");
  const refined = cases.get("html-dog-shampoo-technical");
  const branch = cases.get("html-dog-shampoo-branch-editorial");
  if (!base || !refined || !branch) {
    return missingRevisionFlowSummary(
      "Revision flow cases are missing from the executed corpus.",
    );
  }

  const changedPaths = await diffArtifactFiles(base.artifactDir, refined.artifactDir);
  const compareClassification: ValidationClassification =
    changedPaths.length > 0 ? "pass" : "repairable";

  const restoreRoot = path.join(contractEvidenceRoot, "revision-restore");
  await ensureCleanDirectory(restoreRoot);
  const restoreDir = path.join(restoreRoot, "artifact");
  await cp(base.artifactDir, restoreDir, { recursive: true });
  const restoreManifestPath = path.join(restoreDir, "artifact-manifest.json");
  const restoreValidate = runCommand(
    cliBinary,
    ["artifact", "validate", restoreManifestPath, "--source-root", restoreDir],
    { allowFailure: true },
  );
  const restoreInspect = runCliJson([
    "artifact",
    "inspect",
    restoreManifestPath,
    "--json",
  ]) as ArtifactInspection;
  const restoreJudge = runCliJson([
    "artifact",
    "validation",
    restoreDir,
    "--json",
  ]) as ChatRuntimeValidationResult;
  const restoredMatchesSource =
    (
      await diffArtifactFiles(base.artifactDir, restoreDir, {
        ignorePaths: restoreDiffIgnorePaths,
      })
    ).length === 0;

  const summary: RevisionFlowSummary = {
    compare: {
      baseCaseId: base.id,
      refinedCaseId: refined.id,
      changedPaths,
      classification: compareClassification,
    },
    restore: {
      sourceCaseId: base.id,
      restoredDir: restoreDir,
      restoredMatchesSource,
      validate: restoreValidate,
      inspect: restoreInspect,
      validation: restoreJudge,
      classification:
        restoreValidate.status === 0 && restoredMatchesSource ? "pass" : "repairable",
    },
    branch: {
      caseId: branch.id,
      editMode: branch.editIntent?.mode ?? null,
      classification:
        branch.editIntent?.mode === "branch" && branch.classification === "pass"
          ? "pass"
          : "repairable",
    },
  };

  await writeJson(path.join(contractEvidenceRoot, "revision-flow.json"), summary);
  return summary;
}

export async function buildLiveRevisionFlow(
  cases: Map<string, CaseSummary>,
): Promise<RevisionFlowSummary> {
  const restoreDiffIgnorePaths = [
    "chat-artifact-session.json",
    "revision-history.json",
  ];
  const base = cases.get("html-dog-shampoo");
  const refined = cases.get("html-dog-shampoo-technical");
  const branch = cases.get("html-dog-shampoo-branch-editorial");
  if (!base || !refined || !branch || !refined.stateRoot || !branch.stateRoot) {
    return missingRevisionFlowSummary(
      "Live revision flow cases are missing from the executed corpus.",
    );
  }

  const refinedEvidence = await loadGenerationEvidence(refined.artifactDir);
  const baseRevisionId =
    refinedEvidence.revisions?.find((revision) => revision.parentRevisionId == null)?.revisionId ??
    refinedEvidence.revisions?.[0]?.revisionId;
  const refinedRevisionId =
    refinedEvidence.activeRevisionId ?? refinedEvidence.revisions?.at(-1)?.revisionId;
  if (!baseRevisionId || !refinedRevisionId) {
    return missingRevisionFlowSummary(
      "Live revision comparison is missing revision ids.",
    );
  }

  const htmlEnvOverrides = runtimeEnvOverridesForRenderer("html_iframe", "live");
  const compare = runChatRuntimeProofJson([
    "compare",
    "--state-root",
    refined.stateRoot,
    "--base-revision-id",
    baseRevisionId,
    "--target-revision-id",
    refinedRevisionId,
  ], { envOverrides: htmlEnvOverrides }) as RevisionFlowSummary["compare"] & { changedPaths: string[] };
  const compareClassification: ValidationClassification =
    compare.changedPaths.length > 0 ? "pass" : "repairable";

  const restoreRoot = path.join(liveEvidenceRoot, "revision-restore");
  const restoreArtifactDir = path.join(restoreRoot, "artifact");
  const restoreStateRoot = path.join(restoreRoot, "state");
  await ensureCleanDirectory(restoreRoot);
  await cp(refined.stateRoot, restoreStateRoot, { recursive: true });
  const restoreEvidence = runChatRuntimeProofJson(
    [
      "restore",
      "--state-root",
      restoreStateRoot,
      "--revision-id",
      baseRevisionId,
      "--output",
      restoreArtifactDir,
    ],
    { envOverrides: htmlEnvOverrides },
  ) as GeneratedArtifactEvidence;
  const restoreManifestPath = path.join(restoreArtifactDir, "artifact-manifest.json");
  const restoreValidate = runCommand(
    cliBinary,
    ["artifact", "validate", restoreManifestPath, "--source-root", restoreArtifactDir],
    { allowFailure: true },
  );
  const restoreInspect = runCliJson([
    "artifact",
    "inspect",
    restoreManifestPath,
    "--json",
  ]) as ArtifactInspection;
  const restoreJudge = runCliJson([
    "artifact",
    "validation",
    restoreArtifactDir,
    "--json",
  ]) as ChatRuntimeValidationResult;
  const restoredMatchesSource = await restoredMatchesRevisionSource(
    base,
    refined.artifactDir,
    baseRevisionId,
    restoreArtifactDir,
    restoreEvidence,
    restoreDiffIgnorePaths,
  );

  const branchRoot = path.join(liveEvidenceRoot, "revision-branch");
  const branchArtifactDir = path.join(branchRoot, "artifact");
  const branchStateRoot = path.join(branchRoot, "state");
  await ensureCleanDirectory(branchRoot);
  await cp(branch.stateRoot, branchStateRoot, { recursive: true });
  const branchSourceEvidence = await loadGenerationEvidence(branch.artifactDir);
  const branchRevisionId =
    branchSourceEvidence.activeRevisionId ??
    branchSourceEvidence.revisions?.at(-1)?.revisionId;
  if (!branchRevisionId) {
    return missingRevisionFlowSummary(
      "Live branch flow is missing the active revision id.",
    );
  }
  const branchEvidence = runChatRuntimeProofJson(
    [
      "branch",
      "--state-root",
      branchStateRoot,
      "--revision-id",
      branchRevisionId,
      "--output",
      branchArtifactDir,
    ],
    { envOverrides: htmlEnvOverrides },
  ) as GeneratedArtifactEvidence;

  const summary: RevisionFlowSummary = {
    compare: {
      baseCaseId: base.id,
      refinedCaseId: refined.id,
      changedPaths: compare.changedPaths,
      classification: compareClassification,
    },
    restore: {
      sourceCaseId: base.id,
      restoredDir: restoreArtifactDir,
      restoredMatchesSource,
      validate: restoreValidate,
      inspect: restoreInspect,
      validation: restoreJudge,
      classification:
        restoreValidate.status === 0 && restoredMatchesSource ? "pass" : "repairable",
    },
    branch: {
      caseId: branch.id,
      editMode: branchEvidence.editIntent?.mode ?? null,
      classification:
        branchEvidence.editIntent?.mode === "branch" ||
        (branchEvidence.revisions?.length ?? 0) > 1
          ? "pass"
          : "repairable",
    },
  };

  await writeJson(path.join(liveEvidenceRoot, "revision-flow.json"), summary);
  return summary;
}

export async function buildLiveRepeatedRunVariationFlow(
  cases: Map<string, CaseSummary>,
): Promise<RepeatedRunVariationFlowSummary> {
  const sourceCaseConfig = corpusCases.find(
    (caseConfig) => caseConfig.id === "svg-ai-tools-hero",
  );
  const sourceCase = sourceCaseConfig
    ? cases.get(sourceCaseConfig.id)
    : undefined;
  if (!sourceCaseConfig || !sourceCase) {
    return missingVariationFlowSummary(
      "svg",
      "svg-ai-tools-hero",
      "Create an SVG hero concept for an AI tools brand",
      "Repeated-run variation source case is missing from the live corpus.",
    );
  }

  const variationRoot = path.join(liveEvidenceRoot, "repeated-run-variation");
  await ensureCleanDirectory(variationRoot);
  const runSummaries = [sourceCase];
  const envOverrides = runtimeEnvOverridesForRenderer(
    sourceCaseConfig.expectedRenderer,
    "live",
  );

  for (let runIndex = 2; runIndex <= 3; runIndex += 1) {
    const variationCaseConfig: CorpusCase = {
      ...sourceCaseConfig,
      id: `${sourceCaseConfig.id}-variation-${runIndex}`,
    };
    const caseDir = path.join(variationRoot, variationCaseConfig.id);
    const artifactDir = path.join(caseDir, "artifact");
    const materializedDir = path.join(caseDir, "materialized");
    const stateRoot = path.join(caseDir, "state");
    await ensureCleanDirectory(caseDir);
    await mkdir(stateRoot, { recursive: true });

    const evidence = runChatRuntimeProofJson(
      [
        "run-turn",
        "--state-root",
        stateRoot,
        "--output",
        artifactDir,
        "--prompt",
        variationCaseConfig.prompt,
      ],
      { envOverrides },
    ) as GeneratedArtifactEvidence;
    const summary = await summarizeLiveCase(
      variationCaseConfig,
      caseDir,
      artifactDir,
      materializedDir,
      stateRoot,
      evidence,
    );
    runSummaries.push(summary);
  }

  const variationFlow = buildRepeatedRunVariationCheck(
    sourceCaseConfig.expectedRenderer,
    sourceCaseConfig.id,
    sourceCaseConfig.prompt,
    runSummaries,
  );
  await writeJson(path.join(variationRoot, "variation-flow.json"), variationFlow);
  return variationFlow;
}

export async function runLiveChatRuntimeLane(options?: {
  seedCases?: Map<string, CaseSummary>;
  selectedCases?: CorpusCase[];
}): Promise<LiveChatRuntimeLaneSummary> {
  const runtimeEndpoint = configuredLiveRuntimeEndpoint();
  let unavailableProof = null;
  const liveCases = new Map<string, CaseSummary>(options?.seedCases ?? []);
  const selectedCases = options?.selectedCases ?? corpusCases;

  if (selectedCases.length === 0) {
    return summarizeLiveChatRuntimeResults(
      liveCases,
      runtimeEndpoint,
      Boolean(runtimeEndpoint),
      unavailableProof,
    );
  }

  if (!runtimeEndpoint) {
    ensureChatRuntimeProofBinary();
    const unavailableCaseDir = path.join(liveEvidenceRoot, "inference-unavailable-case");
    await ensureCleanDirectory(unavailableCaseDir);
    unavailableProof = runCommand(
      chatArtifactProofBinary,
      [
        "run-turn",
        "--state-root",
        path.join(unavailableCaseDir, "state"),
        "--output",
        path.join(unavailableCaseDir, "artifact"),
        "--prompt",
        inferenceUnavailableLiveCase.prompt,
        "--json",
      ],
      { allowFailure: true },
    );
    await writeText(
      path.join(liveEvidenceRoot, "inference-unavailable-proof.txt"),
      [unavailableProof.stdout, unavailableProof.stderr].filter(Boolean).join("\n"),
    );
    const unavailableCase = await executeInferenceUnavailableLiveCase();
    liveCases.set(unavailableCase.id, unavailableCase);

    return {
      status: "blocked",
      fullChatRuntimePath: true,
      runtimeConfigured: false,
      runtimeEndpoint: null,
      totals: summarizeCaseTotals(Array.from(liveCases.values())),
      strongestContradiction:
        "No LOCAL_LLM_URL or AUTOPILOT_LOCAL_RUNTIME_URL is configured for the live Chat runtime parity lane.",
      notes: [
        "The contract lane still ran and produced evidence, but it cannot certify desktop parity.",
        "The live Chat runtime lane exercised the kernel-owned failure path and surfaced a blocked artifact instead of substituting mock output.",
      ],
      unavailableProof,
      evidenceRoot: liveEvidenceRoot,
      cases: Array.from(liveCases.values()),
    };
  }

  for (const caseConfig of selectedCases) {
    const summary = await executeLiveCase(caseConfig, liveCases);
    liveCases.set(caseConfig.id, summary);
  }

  const unavailableCase = await executeInferenceUnavailableLiveCase();
  liveCases.set(unavailableCase.id, unavailableCase);

  return summarizeLiveChatRuntimeResults(liveCases, runtimeEndpoint, true, unavailableProof);
}
