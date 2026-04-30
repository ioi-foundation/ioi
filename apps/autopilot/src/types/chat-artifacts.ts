import type {
  ChatExecutionModeDecision,
  ChatExecutionStrategy,
  ChatRuntimeProvenance,
  ExecutionEnvelope,
  ExecutionStage,
  SwarmChangeReceipt,
  SwarmExecutionSummary,
  SwarmMergeReceipt,
  SwarmPlan,
  SwarmVerificationReceipt,
  SwarmWorkItem,
  SwarmWorkItemStatus,
  SwarmWorkerReceipt,
  SwarmWorkerRole,
} from "./execution";

export interface ChatArtifactNavigatorNode {
  id: string;
  label: string;
  kind: string;
  description?: string | null;
  badge?: string | null;
  status?: string | null;
  lens?: string | null;
  path?: string | null;
  children: ChatArtifactNavigatorNode[];
}

export interface ChatArtifactMaterializationFileWrite {
  path: string;
  kind: string;
  contentPreview?: string | null;
}

export interface ChatArtifactMaterializationCommandIntent {
  id: string;
  kind: string;
  label: string;
  command: string;
}

export interface ChatArtifactMaterializationPreviewIntent {
  label: string;
  url?: string | null;
  status: string;
}

export interface ChatArtifactPipelineStep {
  id: string;
  stage: ExecutionStage;
  label: string;
  status: string;
  summary: string;
  outputs: string[];
  verificationGate?: string | null;
}

export type ChatArtifactEditMode = "create" | "patch" | "replace" | "branch";

export type ChatArtifactValidationStatus =
  | "pass"
  | "repairable"
  | "blocked";

export type ChatArtifactOutputOrigin =
  | "live_inference"
  | "mock_inference"
  | "deterministic_fallback"
  | "fixture_runtime"
  | "inference_unavailable"
  | "opaque_runtime";

export type ChatArtifactFailureKind =
  | "inference_unavailable"
  | "routing_failure"
  | "generation_failure"
  | "verification_failure";

export interface ChatArtifactFailure {
  kind: ChatArtifactFailureKind;
  code: string;
  message: string;
}

export type ChatArtifactRenderCaptureViewport =
  | "desktop"
  | "mobile"
  | "interaction";

export type ChatArtifactRenderFindingSeverity =
  | "info"
  | "warning"
  | "blocked";

export interface ChatArtifactRenderCapture {
  viewport: ChatArtifactRenderCaptureViewport;
  width: number;
  height: number;
  screenshotSha256: string;
  screenshotByteCount: number;
  visibleElementCount: number;
  visibleTextChars: number;
  interactiveElementCount: number;
  screenshotChangedFromPrevious: boolean;
}

export interface ChatArtifactRenderFinding {
  code: string;
  severity: ChatArtifactRenderFindingSeverity;
  summary: string;
}

export type ChatArtifactExecutionWitnessStatus =
  | "passed"
  | "failed"
  | "blocked"
  | "not_applicable";

export type ChatArtifactAcceptanceObligationStatus =
  | "passed"
  | "failed"
  | "blocked"
  | "not_applicable";

export interface ChatArtifactExecutionWitness {
  witnessId: string;
  obligationId?: string | null;
  actionKind: string;
  status: ChatArtifactExecutionWitnessStatus;
  summary: string;
  detail?: string | null;
  selector?: string | null;
  consoleErrors: string[];
  stateChanged: boolean;
}

export interface ChatArtifactAcceptanceObligation {
  obligationId: string;
  family: string;
  required: boolean;
  status: ChatArtifactAcceptanceObligationStatus;
  summary: string;
  detail?: string | null;
  witnessIds: string[];
}

export type ChatArtifactRenderPolicyMode =
  | "balanced"
  | "observation_only"
  | "strict";

export interface ChatArtifactRenderObservation {
  primaryRegionPresent: boolean;
  firstPaintVisibleTextChars: number;
  mobileVisibleTextChars: number;
  semanticRegionCount: number;
  evidenceSurfaceCount: number;
  responseRegionCount: number;
  actionableAffordanceCount: number;
  activeAffordanceCount: number;
  runtimeErrorCount: number;
  interactionStateChanged: boolean;
}

export interface ChatArtifactRenderAcceptancePolicy {
  mode: ChatArtifactRenderPolicyMode;
  minimumFirstPaintTextChars: number;
  minimumSemanticRegions: number;
  minimumEvidenceSurfaces: number;
  minimumActionableAffordances: number;
  blockedScoreThreshold: number;
  primaryViewScoreThreshold: number;
  requirePrimaryRegion: boolean;
  requireResponseRegionWhenInteractive: boolean;
  requireStateChangeWhenInteractive: boolean;
}

export interface ChatArtifactRenderEvaluation {
  supported: boolean;
  firstPaintCaptured: boolean;
  interactionCaptureAttempted: boolean;
  captures: ChatArtifactRenderCapture[];
  observation?: ChatArtifactRenderObservation | null;
  acceptancePolicy?: ChatArtifactRenderAcceptancePolicy | null;
  layoutDensityScore: number;
  spacingAlignmentScore: number;
  typographyContrastScore: number;
  visualHierarchyScore: number;
  blueprintConsistencyScore: number;
  overallScore: number;
  findings: ChatArtifactRenderFinding[];
  acceptanceObligations: ChatArtifactAcceptanceObligation[];
  executionWitnesses: ChatArtifactExecutionWitness[];
  summary: string;
}

export type ChatArtifactUxLifecycle =
  | "draft"
  | "refining"
  | "validated"
  | "locked";

export interface ChatArtifactSelectionTarget {
  sourceSurface: string;
  path?: string | null;
  label: string;
  snippet: string;
}

export interface ChatArtifactTasteMemory {
  directives: string[];
  summary: string;
  typographyPreferences: string[];
  densityPreference?: string | null;
  toneFamily: string[];
  motionTolerance?: string | null;
  preferredScaffoldFamilies: string[];
  preferredComponentPatterns: string[];
  antiPatterns: string[];
}

export interface ChatArtifactExemplar {
  recordId: number;
  title: string;
  summary: string;
  renderer: ChatRendererKind;
  scaffoldFamily: string;
  thesis: string;
  qualityRationale: string;
  scoreTotal: number;
  designCues: string[];
  componentPatterns: string[];
  antiPatterns: string[];
  sourceRevisionId?: string | null;
}

export interface ChatArtifactBrief {
  audience: string;
  jobToBeDone: string;
  subjectDomain: string;
  artifactThesis: string;
  requiredConcepts: string[];
  requiredInteractions: string[];
  queryProfile?: ChatArtifactQueryProfile | null;
  visualTone: string[];
  factualAnchors: string[];
  styleDirectives: string[];
  referenceHints: string[];
}

export type ChatArtifactContentGoalKind =
  | "orient"
  | "explain"
  | "compare"
  | "evidence"
  | "example"
  | "summary"
  | "implementation";

export type ChatArtifactInteractionGoalKind =
  | "state_switch"
  | "detail_inspect"
  | "sequence_browse"
  | "state_adjust"
  | "guided_response";

export type ChatArtifactEvidenceGoalKind =
  | "primary_surface"
  | "comparison_surface"
  | "detail_surface"
  | "supporting_surface";

export type ChatArtifactPresentationConstraintKind =
  | "semantic_structure"
  | "first_paint_evidence"
  | "response_region"
  | "keyboard_affordances"
  | "runtime_self_containment"
  | "typography_separation";

export interface ChatArtifactContentGoal {
  kind: ChatArtifactContentGoalKind;
  summary: string;
  required: boolean;
}

export interface ChatArtifactInteractionGoal {
  kind: ChatArtifactInteractionGoalKind;
  summary: string;
  required: boolean;
}

export interface ChatArtifactEvidenceGoal {
  kind: ChatArtifactEvidenceGoalKind;
  summary: string;
  required: boolean;
}

export interface ChatArtifactPresentationConstraint {
  kind: ChatArtifactPresentationConstraintKind;
  summary: string;
  required: boolean;
}

export interface ChatArtifactQueryProfile {
  contentGoals: ChatArtifactContentGoal[];
  interactionGoals: ChatArtifactInteractionGoal[];
  evidenceGoals: ChatArtifactEvidenceGoal[];
  presentationConstraints: ChatArtifactPresentationConstraint[];
}

export type ChatArtifactSkillNeedKind =
  | "visual_art_direction"
  | "editorial_layout"
  | "motion_hierarchy"
  | "interaction_copy_discipline"
  | "accessibility_review"
  | "data_storytelling";

export type ChatArtifactSkillNeedPriority = "required" | "recommended";

export interface ChatArtifactSkillNeed {
  kind: ChatArtifactSkillNeedKind;
  priority: ChatArtifactSkillNeedPriority;
  rationale: string;
}

export interface ChatArtifactPreparationNeeds {
  renderer: ChatRendererKind;
  requiredConcepts: string[];
  requiredInteractions: string[];
  skillNeeds: ChatArtifactSkillNeed[];
  requireBlueprint: boolean;
  requireArtifactIr: boolean;
  exemplarDiscoveryEnabled: boolean;
}

export interface ChatArtifactPreparedContextResolution {
  status: string;
  renderer: ChatRendererKind;
  requireBlueprint: boolean;
  requireArtifactIr: boolean;
  skillNeedCount: number;
  selectedSkillCount: number;
  exemplarCount: number;
  selectedSkillNames: string[];
}

export interface ChatArtifactSkillDiscoveryResolution {
  status: string;
  guidanceStatus?: string;
  guidanceEvaluated: boolean;
  guidanceRecommended: boolean;
  guidanceFound: boolean;
  guidanceAttached: boolean;
  skillNeedCount: number;
  selectedSkillCount: number;
  selectedSkillNames: string[];
  searchScope: string;
  rationale: string;
  failureReason?: string | null;
}

export interface ChatArtifactSectionPlan {
  id: string;
  role: string;
  visiblePurpose: string;
  contentRequirements: string[];
  interactionHooks: string[];
  firstPaintRequirements: string[];
}

export interface ChatArtifactInteractionPlan {
  id: string;
  family: string;
  sourceControls: string[];
  targetSurfaces: string[];
  defaultState: string;
  requiredFirstPaintAffordances: string[];
}

export interface ChatArtifactEvidencePlanEntry {
  id: string;
  kind: string;
  purpose: string;
  conceptBindings: string[];
  firstPaintElements: string[];
  detailTargets: string[];
}

export interface ChatArtifactDesignSystem {
  colorStrategy: string;
  typographyStrategy: string;
  density: string;
  motionStyle: string;
  emphasisModes: string[];
}

export interface ChatArtifactComponentPlanEntry {
  id: string;
  componentFamily: string;
  role: string;
  sectionIds: string[];
  interactionIds: string[];
}

export interface ChatArtifactAccessibilityPlan {
  obligations: string[];
  focusOrder: string[];
  ariaExpectations: string[];
}

export interface ChatArtifactAcceptanceTargets {
  minimumSectionCount: number;
  minimumInteractiveRegions: number;
  requireFirstPaintEvidence: boolean;
  requirePersistentDetailRegion: boolean;
  requireDistinctTypography: boolean;
  requireKeyboardAffordances: boolean;
}

export interface ChatArtifactBlueprint {
  version: number;
  renderer: ChatRendererKind;
  narrativeArc: string;
  sectionPlan: ChatArtifactSectionPlan[];
  interactionPlan: ChatArtifactInteractionPlan[];
  evidencePlan: ChatArtifactEvidencePlanEntry[];
  designSystem: ChatArtifactDesignSystem;
  componentPlan: ChatArtifactComponentPlanEntry[];
  accessibilityPlan: ChatArtifactAccessibilityPlan;
  acceptanceTargets: ChatArtifactAcceptanceTargets;
  scaffoldFamily: string;
  variationStrategy: string;
  skillNeeds: ChatArtifactSkillNeed[];
}

export interface ChatArtifactIRNode {
  id: string;
  kind: string;
  parentId?: string | null;
  sectionId?: string | null;
  label: string;
  bindings: string[];
}

export interface ChatArtifactIRInteractionEdge {
  id: string;
  family: string;
  controlNodeIds: string[];
  targetNodeIds: string[];
  defaultState: string;
}

export interface ChatArtifactIREvidenceSurface {
  id: string;
  kind: string;
  sectionId: string;
  boundConcepts: string[];
  firstPaintExpectations: string[];
}

export interface ChatArtifactDesignToken {
  name: string;
  category: string;
  value: string;
}

export interface ChatArtifactIR {
  version: number;
  renderer: ChatRendererKind;
  scaffoldFamily: string;
  semanticStructure: ChatArtifactIRNode[];
  interactionGraph: ChatArtifactIRInteractionEdge[];
  evidenceSurfaces: ChatArtifactIREvidenceSurface[];
  designTokens: ChatArtifactDesignToken[];
  motionPlan: string[];
  accessibilityObligations: string[];
  responsiveLayoutRules: string[];
  componentBindings: string[];
  staticAuditExpectations: string[];
  renderEvalChecklist: string[];
}

export interface ChatArtifactSelectedSkill {
  skillHash: string;
  name: string;
  description: string;
  lifecycleState: string;
  sourceType: string;
  reliabilityBps: number;
  semanticScoreBps: number;
  adjustedScoreBps: number;
  relativePath?: string | null;
  matchedNeedIds: string[];
  matchedNeedKinds: ChatArtifactSkillNeedKind[];
  matchRationale: string;
  guidanceMarkdown?: string | null;
}

export interface ChatArtifactEditIntent {
  mode: ChatArtifactEditMode;
  summary: string;
  patchExistingArtifact: boolean;
  preserveStructure: boolean;
  targetScope: string;
  targetPaths: string[];
  requestedOperations: string[];
  toneDirectives: string[];
  selectedTargets: ChatArtifactSelectionTarget[];
  styleDirectives: string[];
  branchRequested: boolean;
}

export interface ChatArtifactValidationResult {
  classification: ChatArtifactValidationStatus;
  requestFaithfulness: number;
  conceptCoverage: number;
  interactionRelevance: number;
  layoutCoherence: number;
  visualHierarchy: number;
  completeness: number;
  genericShellDetected: boolean;
  trivialShellDetected: boolean;
  deservesPrimaryArtifactView: boolean;
  patchedExistingArtifact?: boolean | null;
  continuityRevisionUx?: number | null;
  scoreTotal: number;
  proofKind: string;
  primaryViewCleared: boolean;
  validatedPaths: string[];
  issueCodes: string[];
  issueClasses: string[];
  repairHints: string[];
  strengths: string[];
  blockedReasons: string[];
  fileFindings: string[];
  aestheticVerdict: string;
  interactionVerdict: string;
  truthfulnessWarnings: string[];
  recommendedNextPass?: string | null;
  strongestContradiction?: string | null;
  summary: string;
  rationale: string;
}

export interface ChatArtifactCandidateSummary {
  candidateId: string;
  seed: number;
  model: string;
  temperature: number;
  strategy: string;
  origin: ChatArtifactOutputOrigin;
  provenance?: ChatRuntimeProvenance | null;
  summary: string;
  renderablePaths: string[];
  selected: boolean;
  fallback: boolean;
  failure?: string | null;
  rawOutputPreview?: string | null;
  convergence?: ChatArtifactCandidateConvergenceTrace | null;
  renderEvaluation?: ChatArtifactRenderEvaluation | null;
  validation: ChatArtifactValidationResult;
}

export interface ChatArtifactCandidateConvergenceTrace {
  lineageRootId: string;
  parentCandidateId?: string | null;
  passKind: string;
  passIndex: number;
  scoreTotal: number;
  scoreDeltaFromParent?: number | null;
  terminatedReason?: string | null;
}

export type ChatArtifactWorkerRole = SwarmWorkerRole;
export type ChatArtifactWorkItemStatus = SwarmWorkItemStatus;
export type ChatArtifactWorkItem = SwarmWorkItem;
export type ChatArtifactSwarmPlan = SwarmPlan;
export type ChatArtifactSwarmExecutionSummary = SwarmExecutionSummary;
export type ChatArtifactWorkerReceipt = SwarmWorkerReceipt;
export type ChatArtifactPatchReceipt = SwarmChangeReceipt;
export type ChatArtifactMergeReceipt = SwarmMergeReceipt;
export type ChatArtifactVerificationReceipt = SwarmVerificationReceipt;

export interface ChatArtifactRuntimePreviewSnapshot {
  label: string;
  content: string;
  status: string;
  kind?: string | null;
  language?: string | null;
  originPromptEventId?: string | null;
  isFinal: boolean;
}

export type ArtifactOperatorRunMode = "create" | "edit";
export type ChatArtifactOperatorRunMode = ArtifactOperatorRunMode;

export type ArtifactOperatorRunStatus =
  | "pending"
  | "active"
  | "complete"
  | "blocked"
  | "failed"
  | "other";
export type ChatArtifactOperatorRunStatus = ArtifactOperatorRunStatus;

export type ArtifactOperatorPhase =
  | "understand_request"
  | "route_artifact"
  | "reopen_artifact_context"
  | "search_sources"
  | "read_sources"
  | "author_artifact"
  | "inspect_artifact"
  | "verify_artifact"
  | "repair_artifact"
  | "present_artifact"
  | "other";
export type ChatArtifactOperatorPhase = ArtifactOperatorPhase;

export interface ChatArtifactOperatorPreview {
  originPromptEventId?: string;
  label: string;
  content: string;
  status: string;
  kind?: string | null;
  language?: string | null;
  isFinal?: boolean;
}

export interface ArtifactSourceReference {
  sourceId: string;
  originPromptEventId?: string;
  title: string;
  url?: string | null;
  domain?: string | null;
  excerpt?: string | null;
  retrievedAtMs?: number | null;
  freshness?: string | null;
  reason: string;
}
export type ChatArtifactSourceReference = ArtifactSourceReference;

export interface ArtifactSourcePack {
  summary: string;
  items: ArtifactSourceReference[];
}
export type ChatArtifactSourcePack = ArtifactSourcePack;

export interface ArtifactFileRef {
  fileId: string;
  originPromptEventId?: string;
  path: string;
  role: ChatArtifactFileRole;
  mime: string;
  summary: string;
}
export type ChatArtifactFileRef = ArtifactFileRef;

export interface ArtifactVerificationRef {
  verificationId: string;
  originPromptEventId?: string;
  family: string;
  status: string;
  summary: string;
  detail?: string | null;
  selector?: string | null;
}
export type ChatArtifactVerificationRef = ArtifactVerificationRef;

export interface ArtifactVerificationOutcome {
  status?: ArtifactOperatorRunStatus | null;
  summary: string;
  requiredObligationCount: number;
  clearedObligationCount: number;
  failedObligationCount: number;
}
export type ChatArtifactVerificationOutcome = ArtifactVerificationOutcome;

export interface ArtifactOperatorStep {
  stepId: string;
  originPromptEventId?: string;
  phase?: ArtifactOperatorPhase | null;
  engine: string;
  status?: ArtifactOperatorRunStatus | null;
  label: string;
  detail: string;
  startedAtMs: number;
  finishedAtMs?: number | null;
  preview?: ChatArtifactOperatorPreview | null;
  fileRefs: ArtifactFileRef[];
  sourceRefs: ArtifactSourceReference[];
  verificationRefs: ArtifactVerificationRef[];
  attempt: number;
}
export type ChatArtifactOperatorStep = ArtifactOperatorStep;

export interface ArtifactOperatorRun {
  runId: string;
  originPromptEventId?: string;
  artifactSessionId: string;
  mode?: ArtifactOperatorRunMode | null;
  status?: ArtifactOperatorRunStatus | null;
  startedAtMs: number;
  finishedAtMs?: number | null;
  engineSummary: string;
  sourcePack: ArtifactSourcePack;
  steps: ArtifactOperatorStep[];
  finalArtifacts: ArtifactFileRef[];
  verificationOutcome?: ArtifactVerificationOutcome | null;
  repairCount: number;
}
export type ChatArtifactOperatorRun = ArtifactOperatorRun;

export type ChatArtifactRuntimeEventType =
  | "understand_request"
  | "artifact_route_committed"
  | "skill_discovery"
  | "skill_read"
  | "artifact_brief"
  | "author_artifact"
  | "author_preview"
  | "replan_execution"
  | "verify_artifact"
  | "present_artifact"
  | "other";

export type ChatArtifactRuntimeStepId =
  | "understand_request"
  | "artifact_route_committed"
  | "skill_discovery"
  | "skill_read"
  | "artifact_brief"
  | "author_artifact"
  | "replan_execution"
  | "verify_artifact"
  | "present_artifact"
  | "other";

export type ChatArtifactRuntimeStepKind =
  | "intake"
  | "routing"
  | "guidance"
  | "planning"
  | "authoring"
  | "strategy"
  | "verification"
  | "presentation"
  | "other";

export type ChatArtifactRuntimeEventKind = "step" | "preview";

export type ChatArtifactRuntimeEventStatus =
  | "pending"
  | "active"
  | "complete"
  | "failed"
  | "blocked"
  | "interrupted"
  | "other";

export interface ChatArtifactMaterializationContract {
  version: number;
  requestKind: string;
  normalizedIntent: string;
  summary: string;
  artifactBrief?: ChatArtifactBrief | null;
  preparationNeeds?: ChatArtifactPreparationNeeds | null;
  preparedContextResolution?: ChatArtifactPreparedContextResolution | null;
  skillDiscoveryResolution?: ChatArtifactSkillDiscoveryResolution | null;
  blueprint?: ChatArtifactBlueprint | null;
  artifactIr?: ChatArtifactIR | null;
  selectedSkills: ChatArtifactSelectedSkill[];
  retrievedExemplars: ChatArtifactExemplar[];
  editIntent?: ChatArtifactEditIntent | null;
  candidateSummaries: ChatArtifactCandidateSummary[];
  winningCandidateId?: string | null;
  winningCandidateRationale?: string | null;
  executionEnvelope?: ExecutionEnvelope | null;
  swarmPlan?: SwarmPlan | null;
  swarmExecution?: SwarmExecutionSummary | null;
  swarmWorkerReceipts: SwarmWorkerReceipt[];
  swarmChangeReceipts: SwarmChangeReceipt[];
  swarmMergeReceipts: SwarmMergeReceipt[];
  swarmVerificationReceipts: SwarmVerificationReceipt[];
  renderEvaluation?: ChatArtifactRenderEvaluation | null;
  validation?: ChatArtifactValidationResult | null;
  outputOrigin?: ChatArtifactOutputOrigin | null;
  productionProvenance?: ChatRuntimeProvenance | null;
  acceptanceProvenance?: ChatRuntimeProvenance | null;
  degradedPathUsed: boolean;
  uxLifecycle?: ChatArtifactUxLifecycle | null;
  failure?: ChatArtifactFailure | null;
  navigatorNodes: ChatArtifactNavigatorNode[];
  fileWrites: ChatArtifactMaterializationFileWrite[];
  commandIntents: ChatArtifactMaterializationCommandIntent[];
  previewIntent?: ChatArtifactMaterializationPreviewIntent | null;
  pipelineSteps: ChatArtifactPipelineStep[];
  notes: string[];
}

export interface ChatBuildReceipt {
  receiptId: string;
  kind: string;
  title: string;
  status: string;
  summary: string;
  startedAt: string;
  finishedAt?: string | null;
  artifactIds: string[];
  command?: string | null;
  exitCode?: number | null;
  durationMs?: number | null;
  failureClass?: string | null;
  replayClassification?: string | null;
}

export interface ChatCodeWorkerLease {
  backend: string;
  plannerAuthority: string;
  allowedMutationScope: string[];
  allowedCommandClasses: string[];
  executionState: string;
  retryClassification?: string | null;
  lastSummary?: string | null;
}

export type ChatOutcomeKind =
  | "conversation"
  | "tool_widget"
  | "visualizer"
  | "artifact";

export type ChatArtifactClass =
  | "document"
  | "visual"
  | "interactive_single_file"
  | "downloadable_file"
  | "workspace_project"
  | "compound_bundle"
  | "code_patch"
  | "report_bundle";

export type ChatArtifactDeliverableShape =
  | "single_file"
  | "file_set"
  | "workspace_project";

export type ChatRendererKind =
  | "markdown"
  | "html_iframe"
  | "jsx_sandbox"
  | "svg"
  | "mermaid"
  | "pdf_embed"
  | "download_card"
  | "workspace_surface"
  | "bundle_manifest";

export type ChatPresentationSurface =
  | "inline"
  | "side_panel"
  | "overlay"
  | "tabbed_panel";

export type ChatArtifactPersistenceMode =
  | "ephemeral"
  | "artifact_scoped"
  | "shared_artifact_scoped"
  | "workspace_filesystem";

export type ChatExecutionSubstrate =
  | "none"
  | "client_sandbox"
  | "binary_generator"
  | "workspace_runtime";

export type ChatArtifactTabKind =
  | "render"
  | "source"
  | "download"
  | "evidence"
  | "workspace";

export type ChatArtifactFileRole =
  | "primary"
  | "source"
  | "export"
  | "supporting";

export type ChatArtifactVerificationStatus =
  | "pending"
  | "ready"
  | "blocked"
  | "failed"
  | "partial";

export type ChatArtifactLifecycleState =
  | "draft"
  | "planned"
  | "materializing"
  | "rendering"
  | "implementing"
  | "verifying"
  | "ready"
  | "partial"
  | "blocked"
  | "failed";

export interface ChatOutcomeArtifactScope {
  targetProject?: string | null;
  createNewWorkspace: boolean;
  mutationBoundary: string[];
}

export interface ChatOutcomeArtifactVerificationRequest {
  requireRender: boolean;
  requireBuild: boolean;
  requirePreview: boolean;
  requireExport: boolean;
  requireDiffReview: boolean;
}

export interface ChatOutcomeArtifactRequest {
  artifactClass: ChatArtifactClass;
  deliverableShape: ChatArtifactDeliverableShape;
  renderer: ChatRendererKind;
  presentationSurface: ChatPresentationSurface;
  persistence: ChatArtifactPersistenceMode;
  executionSubstrate: ChatExecutionSubstrate;
  workspaceRecipeId?: string | null;
  presentationVariantId?: string | null;
  scope: ChatOutcomeArtifactScope;
  verification: ChatOutcomeArtifactVerificationRequest;
}

export interface ChatOutcomeRequest {
  requestId: string;
  rawPrompt: string;
  activeArtifactId?: string | null;
  outcomeKind: ChatOutcomeKind;
  executionStrategy: ChatExecutionStrategy;
  executionModeDecision?: ChatExecutionModeDecision | null;
  confidence: number;
  needsClarification: boolean;
  clarificationQuestions: string[];
  decisionEvidence?: string[];
  artifact?: ChatOutcomeArtifactRequest | null;
}

export interface ChatOutcomePlanningPayload {
  outcomeKind: ChatOutcomeKind;
  executionStrategy: ChatExecutionStrategy;
  executionModeDecision?: ChatExecutionModeDecision | null;
  confidence: number;
  needsClarification: boolean;
  clarificationQuestions: string[];
  decisionEvidence?: string[];
  artifact?: ChatOutcomeArtifactRequest | null;
}

export interface ChatArtifactManifestTab {
  id: string;
  label: string;
  kind: ChatArtifactTabKind;
  renderer?: ChatRendererKind | null;
  filePath?: string | null;
  lens?: string | null;
}

export interface ChatArtifactManifestFile {
  path: string;
  mime: string;
  role: ChatArtifactFileRole;
  renderable: boolean;
  downloadable: boolean;
  artifactId?: string | null;
  externalUrl?: string | null;
}

export interface ChatArtifactManifestVerification {
  status: ChatArtifactVerificationStatus;
  lifecycleState: ChatArtifactLifecycleState;
  summary: string;
  productionProvenance?: ChatRuntimeProvenance | null;
  acceptanceProvenance?: ChatRuntimeProvenance | null;
  failure?: ChatArtifactFailure | null;
}

export interface ChatRetainedWidgetState {
  widgetFamily?: string | null;
  bindings: {
    key: string;
    value: string;
    source: string;
  }[];
  lastUpdatedAt?: string | null;
}

export interface ChatArtifactManifestStorage {
  mode: ChatArtifactPersistenceMode;
  apiLabel?: string | null;
}

export interface ChatArtifactManifest {
  artifactId: string;
  title: string;
  artifactClass: ChatArtifactClass;
  renderer: ChatRendererKind;
  primaryTab: string;
  tabs: ChatArtifactManifestTab[];
  files: ChatArtifactManifestFile[];
  verification: ChatArtifactManifestVerification;
  storage?: ChatArtifactManifestStorage | null;
}

export interface ChatVerifiedReply {
  status: ChatArtifactVerificationStatus;
  lifecycleState: ChatArtifactLifecycleState;
  title: string;
  summary: string;
  evidence: string[];
  productionProvenance?: ChatRuntimeProvenance | null;
  acceptanceProvenance?: ChatRuntimeProvenance | null;
  failure?: ChatArtifactFailure | null;
  updatedAt: string;
}

export interface ChatRendererSession {
  sessionId: string;
  chatSessionId: string;
  renderer: ChatRendererKind;
  workspaceRoot: string;
  entryDocument: string;
  previewUrl?: string | null;
  previewProcessId?: number | null;
  scaffoldRecipeId?: string | null;
  presentationVariantId?: string | null;
  packageManager?: string | null;
  status: string;
  verificationStatus: string;
  receipts: ChatBuildReceipt[];
  currentWorkerExecution?: ChatCodeWorkerLease | null;
  currentTab: string;
  availableTabs: string[];
  readyTabs: string[];
  retryCount: number;
  lastFailureSummary?: string | null;
}

export interface ChatArtifactRevision {
  revisionId: string;
  parentRevisionId?: string | null;
  branchId: string;
  branchLabel: string;
  prompt: string;
  createdAt: string;
  uxLifecycle: ChatArtifactUxLifecycle;
  artifactManifest: ChatArtifactManifest;
  artifactBrief?: ChatArtifactBrief | null;
  preparationNeeds?: ChatArtifactPreparationNeeds | null;
  preparedContextResolution?: ChatArtifactPreparedContextResolution | null;
  skillDiscoveryResolution?: ChatArtifactSkillDiscoveryResolution | null;
  blueprint?: ChatArtifactBlueprint | null;
  artifactIr?: ChatArtifactIR | null;
  selectedSkills: ChatArtifactSelectedSkill[];
  editIntent?: ChatArtifactEditIntent | null;
  candidateSummaries: ChatArtifactCandidateSummary[];
  winningCandidateId?: string | null;
  executionEnvelope?: ExecutionEnvelope | null;
  swarmPlan?: SwarmPlan | null;
  swarmExecution?: SwarmExecutionSummary | null;
  swarmWorkerReceipts: SwarmWorkerReceipt[];
  swarmChangeReceipts: SwarmChangeReceipt[];
  swarmMergeReceipts: SwarmMergeReceipt[];
  swarmVerificationReceipts: SwarmVerificationReceipt[];
  renderEvaluation?: ChatArtifactRenderEvaluation | null;
  validation?: ChatArtifactValidationResult | null;
  outputOrigin?: ChatArtifactOutputOrigin | null;
  productionProvenance?: ChatRuntimeProvenance | null;
  acceptanceProvenance?: ChatRuntimeProvenance | null;
  failure?: ChatArtifactFailure | null;
  fileWrites: ChatArtifactMaterializationFileWrite[];
  tasteMemory?: ChatArtifactTasteMemory | null;
  retrievedExemplars: ChatArtifactExemplar[];
  selectedTargets: ChatArtifactSelectionTarget[];
}

export interface ChatArtifactSession {
  sessionId: string;
  threadId: string;
  artifactId: string;
  originPromptEventId?: string | null;
  title: string;
  summary: string;
  currentLens: string;
  navigatorBackingMode: string;
  navigatorNodes: ChatArtifactNavigatorNode[];
  attachedArtifactIds: string[];
  availableLenses: string[];
  materialization: ChatArtifactMaterializationContract;
  outcomeRequest: ChatOutcomeRequest;
  artifactManifest: ChatArtifactManifest;
  verifiedReply: ChatVerifiedReply;
  lifecycleState: ChatArtifactLifecycleState;
  status: string;
  activeRevisionId?: string | null;
  revisions: ChatArtifactRevision[];
  tasteMemory?: ChatArtifactTasteMemory | null;
  retrievedExemplars: ChatArtifactExemplar[];
  selectedTargets: ChatArtifactSelectionTarget[];
  widgetState?: ChatRetainedWidgetState | null;
  uxLifecycle?: ChatArtifactUxLifecycle | null;
  activeOperatorRun?: ArtifactOperatorRun | null;
  operatorRunHistory?: ArtifactOperatorRun[];
  createdAt: string;
  updatedAt: string;
  buildSessionId?: string | null;
  workspaceRoot?: string | null;
  rendererSessionId?: string | null;
}

export interface BuildArtifactSession {
  sessionId: string;
  chatSessionId: string;
  workspaceRoot: string;
  entryDocument: string;
  previewUrl?: string | null;
  previewProcessId?: number | null;
  scaffoldRecipeId: string;
  presentationVariantId?: string | null;
  packageManager: string;
  buildStatus: string;
  verificationStatus: string;
  receipts: ChatBuildReceipt[];
  currentWorkerExecution: ChatCodeWorkerLease;
  currentLens: string;
  availableLenses: string[];
  readyLenses: string[];
  retryCount: number;
  lastFailureSummary?: string | null;
}
