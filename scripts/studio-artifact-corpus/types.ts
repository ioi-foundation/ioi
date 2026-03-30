export type JudgeClassification = "pass" | "repairable" | "blocked";

export type RendererKind =
  | "markdown"
  | "html_iframe"
  | "jsx_sandbox"
  | "svg"
  | "mermaid"
  | "pdf_embed"
  | "download_card"
  | "workspace_surface";

export interface StudioJudgeResult {
  classification: JudgeClassification;
  requestFaithfulness: number;
  conceptCoverage: number;
  interactionRelevance: number;
  layoutCoherence: number;
  visualHierarchy: number;
  completeness: number;
  genericShellDetected: boolean;
  trivialShellDetected: boolean;
  deservesPrimaryArtifactView: boolean;
  patchedExistingArtifact: boolean | null;
  continuityRevisionUx: number | null;
  strongestContradiction: string | null;
  rationale: string;
}

export type RuntimeProvenance = {
  kind: string;
  label: string;
  model?: string | null;
  endpoint?: string | null;
};

export type FailureEnvelope = {
  kind: string;
  code: string;
  message: string;
};

export interface ComposedArtifactReply {
  status: string;
  lifecycleState?: string | null;
  title?: string;
  summary?: string;
  evidence?: string[];
  productionProvenance?: RuntimeProvenance | null;
  acceptanceProvenance?: RuntimeProvenance | null;
  failure?: FailureEnvelope | null;
}

export interface GeneratedArtifactEvidence {
  prompt: string;
  title: string;
  route: {
    artifact: {
      renderer: RendererKind;
      artifactClass: string;
    } | null;
  } & Record<string, unknown>;
  artifactBrief: {
    audience: string;
    jobToBeDone: string;
    subjectDomain: string;
    artifactThesis: string;
    requiredConcepts: string[];
    requiredInteractions: string[];
    visualTone: string[];
    factualAnchors: string[];
    styleDirectives: string[];
    referenceHints: string[];
  };
  editIntent?: {
    mode: "create" | "patch" | "replace" | "branch";
    summary: string;
    patchExistingArtifact: boolean;
    preserveStructure: boolean;
    targetScope: string;
    targetPaths: string[];
    requestedOperations: string[];
    toneDirectives: string[];
    selectedTargets: Array<{
      sourceSurface: string;
      path: string | null;
      label: string;
      snippet: string;
    }>;
    styleDirectives: string[];
    branchRequested: boolean;
  } | null;
  candidateSummaries: Array<{
    candidateId: string;
    seed: number;
    model: string;
    temperature: number;
    strategy: string;
    origin: string;
    summary: string;
    renderablePaths: string[];
    selected: boolean;
    fallback: boolean;
    failure?: string | null;
    rawOutputPreview?: string | null;
    judge: StudioJudgeResult;
  }>;
  winningCandidateId: string | null;
  winningCandidateRationale: string | null;
  judge: StudioJudgeResult | null;
  outputOrigin: string | null;
  productionProvenance?: RuntimeProvenance | null;
  acceptanceProvenance?: RuntimeProvenance | null;
  fallbackUsed: boolean;
  uxLifecycle: string | null;
  failure?: FailureEnvelope | null;
  manifest: {
    artifactId: string;
    title: string;
    renderer: RendererKind;
    artifactClass: string;
    primaryTab: string;
    verification?: {
      status?: string;
      lifecycleState?: string;
      productionProvenance?: RuntimeProvenance | null;
      acceptanceProvenance?: RuntimeProvenance | null;
      failure?: FailureEnvelope | null;
    };
    files: Array<{
      path: string;
      mime: string;
      role: string;
      renderable: boolean;
      downloadable: boolean;
      externalUrl?: string | null;
    }>;
  };
  verifiedReply: {
    status: string;
    lifecycleState: string;
    title: string;
    summary: string;
    evidence: string[];
    productionProvenance?: RuntimeProvenance | null;
    acceptanceProvenance?: RuntimeProvenance | null;
    failure?: FailureEnvelope | null;
  };
  materializedFiles: string[];
  renderableFiles: string[];
  selectedTargets?: Array<{
    sourceSurface: string;
    path: string | null;
    label: string;
    snippet: string;
  }>;
  tasteMemory?: {
    directives: string[];
    summary: string;
  } | null;
  revisions?: Array<{
    revisionId: string;
    parentRevisionId?: string | null;
    branchId: string;
    branchLabel: string;
    prompt: string;
    createdAt: string;
  }>;
  activeRevisionId?: string | null;
  fullStudioPath?: boolean;
  refinement?: {
    artifactId?: string | null;
    revisionId?: string | null;
    title: string;
    summary: string;
    renderer: RendererKind;
    selectedTargets: Array<{
      sourceSurface: string;
      path: string | null;
      label: string;
      snippet: string;
    }>;
    tasteMemory?: {
      directives: string[];
      summary: string;
    } | null;
  } | null;
}

export interface ArtifactInspection {
  artifactId: string;
  title: string;
  artifactClass: string;
  renderer: string;
  verificationStatus: string;
  lifecycleState: string;
  verificationSummary: string;
  primaryTab: string;
  tabCount: number;
  fileCount: number;
  renderableFileCount: number;
  downloadableFileCount: number;
  repoCentricPackage: boolean;
  renderSurfaceAvailable: boolean;
  preferredStageMode: string;
}

export interface ArtifactSelectionTarget {
  sourceSurface: string;
  path: string | null;
  label: string;
  snippet: string;
}

export interface CorpusCase {
  id: string;
  prompt: string;
  expectedRenderer: RendererKind;
  expectedKeywords: string[];
  expectedStyleTerms?: string[];
  useQueryAlias?: boolean;
  refinementFrom?: string;
  expectedEditMode?: "patch" | "branch";
  requiresSelection?: boolean;
  selectedTargets?: ArtifactSelectionTarget[];
  styleSteering?: boolean;
  workspaceBuild?: boolean;
}

export interface CommandCapture {
  args: string[];
  status: number;
  stdout: string;
  stderr: string;
}

export type StudioRuntimeEnv = {
  endpoint: string;
  healthEndpoint: string;
  productionModel: string;
  acceptanceEndpoint: string;
  acceptanceHealthEndpoint: string;
  acceptanceModel: string;
};

export interface WorkspaceBuildProof {
  install: CommandCapture;
  build: CommandCapture | null;
  buildOk: boolean;
  capturePath: string;
}

export interface CaseTotals {
  pass: number;
  repairable: number;
  blocked: number;
}

export interface CaseSummary {
  id: string;
  prompt: string;
  artifactDir: string;
  stateRoot?: string;
  manifestPath: string;
  route: unknown;
  artifactBrief: GeneratedArtifactEvidence["artifactBrief"];
  editIntent: GeneratedArtifactEvidence["editIntent"];
  candidateSetMetadata: GeneratedArtifactEvidence["candidateSummaries"];
  winningCandidateId: string | null;
  winningCandidateRationale: string | null;
  manifest: GeneratedArtifactEvidence["manifest"];
  verifiedReply: GeneratedArtifactEvidence["verifiedReply"];
  rendererOutput: {
    primaryFile: string | null;
    capturePaths: string[];
    workspaceBuild?: WorkspaceBuildProof;
  };
  materializedFiles: string[];
  inspect: ArtifactInspection;
  validate: CommandCapture;
  materialize: CommandCapture;
  composeReply: ComposedArtifactReply;
  judge: StudioJudgeResult | null;
  rubric: StudioJudgeResult | null;
  classification: JudgeClassification;
  strongestContradiction: string | null;
  outputOrigin: string | null;
  productionProvenance: RuntimeProvenance | null;
  acceptanceProvenance: RuntimeProvenance | null;
  fallbackUsed: boolean;
  uxLifecycle: string | null;
  failure: FailureEnvelope | null;
  notes: string[];
  proofPath: "contract_path" | "full_studio_path";
  fullStudioPath: boolean;
}

export interface LiveStudioLaneSummary {
  status: JudgeClassification;
  fullStudioPath: true;
  runtimeConfigured: boolean;
  runtimeEndpoint: string | null;
  totals: CaseTotals;
  strongestContradiction: string | null;
  notes: string[];
  unavailableProof: CommandCapture | null;
  evidenceRoot: string;
  cases: CaseSummary[];
  revisionFlow?: RevisionFlowSummary;
  repeatedRunVariationFlow?: RepeatedRunVariationFlowSummary;
}

export interface RevisionFlowSummary {
  compare: {
    baseCaseId: string;
    refinedCaseId: string;
    changedPaths: string[];
    classification: JudgeClassification;
  };
  restore: {
    sourceCaseId: string;
    restoredDir: string;
    restoredMatchesSource: boolean;
    validate: CommandCapture;
    inspect: ArtifactInspection;
    judge: StudioJudgeResult;
    classification: JudgeClassification;
  };
  branch: {
    caseId: string;
    editMode: string | null;
    classification: JudgeClassification;
  };
}

export interface RepeatedRunVariationFlowSummary {
  renderer: RendererKind;
  sourceCaseId: string;
  prompt: string;
  runCount: number;
  uniqueSignatureCount: number;
  classification: JudgeClassification;
  strongestContradiction: string | null;
  failingRunIds: string[];
  runs: Array<{
    caseId: string;
    artifactDir: string;
    stateRoot?: string;
    classification: JudgeClassification;
    strongestContradiction: string | null;
    signature: string | null;
  }>;
}

export interface CorpusSummary {
  generatedAt: string;
  evidenceRoot: string;
  cases: CaseSummary[];
  lanes: {
    contract: {
      evidenceRoot: string;
      status: JudgeClassification;
    };
    liveStudio: LiveStudioLaneSummary;
  };
  parityChecks: {
    htmlDistinctness: {
      caseIds: string[];
      allDistinct: boolean;
      failingCaseIds: string[];
    };
    refinementPatchFlow: {
      caseIds: string[];
      allPatched: boolean;
      failingCaseIds: string[];
    };
    targetedEditFlow: {
      caseId: string;
      passed: boolean;
    };
    styleSteeringFlow: {
      caseId: string;
      passed: boolean;
    };
    revisionFlow: RevisionFlowSummary;
    repeatedRunVariationFlow: RepeatedRunVariationFlowSummary;
  };
  totals: {
    pass: number;
    repairable: number;
    blocked: number;
  };
}
