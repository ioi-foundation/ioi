// apps/autopilot/src/types.ts

// Import Graph Types from the shared package
import type {
  Node,
  Edge,
  NodeLogic,
  FirewallPolicy,
  GraphGlobalConfig,
  AgentConfiguration,
  AssistantWorkbenchSession,
  CalendarAttendeeDetail,
  CalendarEventDetail,
  ConnectorSummary,
  GmailThreadDetail,
  GmailThreadMessageDetail,
  SessionClarificationOption as SharedSessionClarificationOption,
  SessionClarificationRequest as SharedSessionClarificationRequest,
  SessionCredentialRequest as SharedSessionCredentialRequest,
  SessionGateInfo as SharedSessionGateInfo,
  ChatCapabilityDetailSection,
} from "@ioi/agent-ide";
import type {
  ExecutionEnvelope,
  ExecutionStage,
  ChatExecutionModeDecision,
  ChatExecutionStrategy,
  ChatRuntimeProvenance,
  SwarmChangeReceipt,
  SwarmExecutionSummary,
  SwarmMergeReceipt,
  SwarmPlan,
  SwarmVerificationReceipt,
  SwarmWorkItem,
  SwarmWorkItemStatus,
  SwarmWorkerReceipt,
  SwarmWorkerRole,
} from "./types/execution";

// Re-export for local consumption if needed, or update imports in Autopilot components
export type {
  Node,
  Edge,
  NodeLogic,
  FirewallPolicy,
  GraphGlobalConfig,
  AgentConfiguration,
  AssistantWorkbenchSession,
  CalendarAttendeeDetail,
  CalendarEventDetail,
  ConnectorSummary,
  GmailThreadDetail,
  GmailThreadMessageDetail,
  SharedSessionClarificationOption as SessionClarificationOption,
  SharedSessionClarificationRequest as SessionClarificationRequest,
  SharedSessionCredentialRequest as SessionCredentialRequest,
  SharedSessionGateInfo as SessionGateInfo,
  ChatCapabilityDetailSection,
};
export type {
  ChatExecutionBudgetEnvelope,
  ChatExecutionBudgetExpansionPolicy,
  ChatExecutionModeDecision,
  ChatExecutionStrategy,
  ChatRuntimeProvenance,
  ChatRuntimeProvenanceKind,
  ExecutionBudgetSummary,
  ExecutionCompletionInvariant,
  ExecutionCompletionInvariantStatus,
  ExecutionDispatchBatch,
  ExecutionDomainKind,
  ExecutionEnvelope,
  ExecutionGraphMutationReceipt,
  ExecutionLivePreview,
  ExecutionLivePreviewKind,
  ExecutionRepairReceipt,
  ExecutionReplanReceipt,
  ExecutionStage,
  SwarmChangeReceipt,
  SwarmLeaseMode,
  SwarmLeaseRequirement,
  SwarmLeaseScopeKind,
  SwarmExecutionSummary,
  SwarmMergeReceipt,
  SwarmPlan,
  SwarmVerificationPolicy,
  SwarmVerificationReceipt,
  SwarmWorkItem,
  SwarmWorkItemStatus,
  SwarmWorkerResultKind,
  SwarmWorkerReceipt,
  SwarmWorkerRole,
} from "./types/execution";
export { executionStageForCurrentStage } from "./types/execution";

// ============================================
// OS / Shell Types (Specific to Autopilot)
// ============================================

export type ExecutionMode = "local" | "session" | "settlement";

export type LiabilityLevel = "none" | "auditable" | "insured" | "proven";

export interface ChatMessage {
  role: string;
  text: string;
  timestamp: number;
}

import type {
  ActiveContextItem as GeneratedActiveContextItem,
  ActiveContextSnapshot as GeneratedActiveContextSnapshot,
  AgentEvent as GeneratedAgentEvent,
  Artifact as GeneratedArtifact,
  ArtifactRef as GeneratedArtifactRef,
  ArtifactType as GeneratedArtifactType,
  AssistantNotificationClass as GeneratedAssistantNotificationClass,
  AssistantNotificationRecord as GeneratedAssistantNotificationRecord,
  AssistantNotificationStatus as GeneratedAssistantNotificationStatus,
  AtlasEdge as GeneratedAtlasEdge,
  AtlasNeighborhood as GeneratedAtlasNeighborhood,
  AtlasNode as GeneratedAtlasNode,
  ContextConstraint as GeneratedContextConstraint,
  EventStatus as GeneratedEventStatus,
  EventType as GeneratedEventType,
  InterventionRecord as GeneratedInterventionRecord,
  InterventionStatus as GeneratedInterventionStatus,
  InterventionType as GeneratedInterventionType,
  NotificationAction as GeneratedNotificationAction,
  NotificationActionStyle as GeneratedNotificationActionStyle,
  NotificationDeliveryState as GeneratedNotificationDeliveryState,
  NotificationPolicyRefs as GeneratedNotificationPolicyRefs,
  NotificationPreviewMode as GeneratedNotificationPreviewMode,
  NotificationPrivacy as GeneratedNotificationPrivacy,
  NotificationRail as GeneratedNotificationRail,
  NotificationSeverity as GeneratedNotificationSeverity,
  NotificationSource as GeneratedNotificationSource,
  ObservationTier as GeneratedObservationTier,
  SkillCatalogEntry as GeneratedSkillCatalogEntry,
  SubstrateProofReceipt as GeneratedSubstrateProofReceipt,
  SubstrateProofView as GeneratedSubstrateProofView,
} from "./generated/autopilot-contracts";

type JsonRecord = Record<string, unknown>;

export type ActiveContextItem = GeneratedActiveContextItem;
export type ArtifactType = GeneratedArtifactType;
export type ArtifactRef = GeneratedArtifactRef;
export type AssistantNotificationClass = GeneratedAssistantNotificationClass;
export type AssistantNotificationStatus = GeneratedAssistantNotificationStatus;
export type ContextConstraint = GeneratedContextConstraint;
export type EventStatus = GeneratedEventStatus;
export type EventType = GeneratedEventType | "BROWSER_EXTRACT";
export type InterventionStatus = GeneratedInterventionStatus;
export type InterventionType = GeneratedInterventionType;
export type NotificationActionStyle = GeneratedNotificationActionStyle;
export type NotificationPreviewMode = GeneratedNotificationPreviewMode;
export type NotificationRail = GeneratedNotificationRail;
export type NotificationSeverity = GeneratedNotificationSeverity;
export type ObservationTier = GeneratedObservationTier;
export type SkillCatalogEntry = GeneratedSkillCatalogEntry;

export type AgentEvent = Omit<
  GeneratedAgentEvent,
  "event_type" | "digest" | "details"
> & {
  event_type: EventType;
  digest: JsonRecord;
  details: JsonRecord;
};

export type Artifact = Omit<GeneratedArtifact, "metadata"> & {
  metadata: JsonRecord;
};

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
  swarmPatchReceipts?: SwarmChangeReceipt[];
  swarmMergeReceipts: SwarmMergeReceipt[];
  swarmVerificationReceipts: SwarmVerificationReceipt[];
  renderEvaluation?: ChatArtifactRenderEvaluation | null;
  validation?: ChatArtifactValidationResult | null;
  outputOrigin?: ChatArtifactOutputOrigin | null;
  productionProvenance?: ChatRuntimeProvenance | null;
  acceptanceProvenance?: ChatRuntimeProvenance | null;
  fallbackUsed: boolean;
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
  routingHints?: string[];
  artifact?: ChatOutcomeArtifactRequest | null;
}

export interface ChatOutcomePlanningPayload {
  outcomeKind: ChatOutcomeKind;
  executionStrategy: ChatExecutionStrategy;
  executionModeDecision?: ChatExecutionModeDecision | null;
  confidence: number;
  needsClarification: boolean;
  clarificationQuestions: string[];
  routingHints?: string[];
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
  swarmPatchReceipts?: SwarmChangeReceipt[];
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

export type AtlasEdge = GeneratedAtlasEdge;

export type AtlasNode = Omit<GeneratedAtlasNode, "metadata"> & {
  metadata: JsonRecord;
};

export type AtlasNeighborhood = Omit<
  GeneratedAtlasNeighborhood,
  "focus_id" | "nodes" | "edges"
> & {
  focus_id?: string | null;
  nodes: AtlasNode[];
  edges: AtlasEdge[];
};

export interface SkillMacroStepView {
  index: number;
  tool_name: string;
  target: string;
  params_json:
    | Record<string, unknown>
    | string
    | number
    | boolean
    | null
    | Array<unknown>;
}

export interface SkillBenchmarkView {
  sample_size: number;
  success_rate_bps: number;
  intervention_rate_bps: number;
  policy_incident_rate_bps: number;
  avg_cost: number;
  avg_latency_ms: number;
  passed: boolean;
  last_evaluated_height: number;
}

export interface SkillDetailView {
  skill_hash: string;
  name: string;
  description: string;
  lifecycle_state: string;
  source_type: string;
  archival_record_id: number;
  success_rate_bps: number;
  sample_size: number;
  source_session_id?: string | null;
  source_evidence_hash?: string | null;
  relative_path?: string | null;
  source_registry_id?: string | null;
  source_registry_label?: string | null;
  source_registry_uri?: string | null;
  source_registry_kind?: string | null;
  source_registry_sync_status?: string | null;
  source_registry_relative_path?: string | null;
  stale: boolean;
  used_tools: string[];
  steps: SkillMacroStepView[];
  benchmark: SkillBenchmarkView;
  markdown?: string | null;
  neighborhood: AtlasNeighborhood;
}

export type SubstrateProofReceipt = GeneratedSubstrateProofReceipt;

export type SubstrateProofView = Omit<
  GeneratedSubstrateProofView,
  "neighborhood" | "receipts"
> & {
  neighborhood: AtlasNeighborhood;
  receipts: SubstrateProofReceipt[];
};

export type ActiveContextSnapshot = Omit<
  GeneratedActiveContextSnapshot,
  "neighborhood" | "substrate"
> & {
  neighborhood: AtlasNeighborhood;
  substrate?: SubstrateProofView | null;
};

export interface BenchmarkTraceArtifactLink {
  label: string;
  path: string;
  href: string;
}

export interface BenchmarkTraceSpan {
  id: string;
  lane: string;
  parentSpanId?: string | null;
  stepIndex?: number | null;
  status: string;
  summary: string;
  startMs: number;
  endMs: number;
  durationMs?: number | null;
  capabilityTags: string[];
  attributesSummary: string;
  artifactLinks: BenchmarkTraceArtifactLink[];
}

export interface BenchmarkTraceLane {
  lane: string;
  spans: BenchmarkTraceSpan[];
}

export interface BenchmarkTraceBookmark {
  id: string;
  label: string;
  spanId: string;
  kind: string;
}

export interface BenchmarkTraceReplay {
  source: string;
  rangeStartMs: number;
  rangeEndMs: number;
  spanCount: number;
  lanes: BenchmarkTraceLane[];
  bookmarks: BenchmarkTraceBookmark[];
}

export interface BenchmarkTraceMetric {
  metricId: string;
  label: string;
  status: string;
  summary: string;
  supportingSpanIds: string[];
}

export interface BenchmarkTraceLinks {
  traceBundle?: string | null;
  traceAnalysis?: string | null;
  benchmarkSummary?: string | null;
  diagnosticSummary?: string | null;
}

export interface BenchmarkTraceSummary {
  env_id: string;
  model?: string | null;
  provider_calls: number;
  reward: number;
  terminated: boolean;
  query_text: string;
}

export interface BenchmarkTraceCaseView {
  suite: string;
  caseId: string;
  runId: string;
  runSort: number;
  result: string;
  summary: BenchmarkTraceSummary;
  findings: string[];
  traceMetrics: BenchmarkTraceMetric[];
  trace: BenchmarkTraceReplay | null;
  links: BenchmarkTraceLinks;
}

export interface BenchmarkTraceFeed {
  generatedAt?: string | null;
  repoRoot?: string | null;
  cases: BenchmarkTraceCaseView[];
}

export type NotificationAction = Omit<GeneratedNotificationAction, "style"> & {
  style?: NotificationActionStyle | null;
};

export type NotificationDeliveryState = Omit<
  GeneratedNotificationDeliveryState,
  "lastToastAtMs"
> & {
  lastToastAtMs?: number | null;
};

export type NotificationPrivacy = GeneratedNotificationPrivacy;
export type NotificationSource = GeneratedNotificationSource;

export type NotificationPolicyRefs = Omit<
  GeneratedNotificationPolicyRefs,
  "policyHash" | "requestHash"
> & {
  policyHash?: string | null;
  requestHash?: string | null;
};

export type NotificationTarget =
  | {
      kind: "gmail_thread";
      connectorId?: string;
      connector_id?: string;
      threadId?: string;
      thread_id?: string;
      messageId?: string | null;
      message_id?: string | null;
    }
  | {
      kind: "calendar_event";
      connectorId?: string;
      connector_id?: string;
      calendarId?: string;
      calendar_id?: string;
      eventId?: string;
      event_id?: string;
    }
  | {
      kind: "connector_auth";
      connectorId?: string;
      connector_id?: string;
    }
  | {
      kind: "connector_subscription";
      connectorId?: string;
      connector_id?: string;
      subscriptionId?: string;
      subscription_id?: string;
    };

export type InterventionRecord = Omit<GeneratedInterventionRecord, "target"> & {
  target?: NotificationTarget | null;
};

export type AssistantNotificationRecord = Omit<
  GeneratedAssistantNotificationRecord,
  "target"
> & {
  target?: NotificationTarget | null;
};

export interface AtlasSearchResult {
  id: string;
  kind: string;
  title: string;
  summary: string;
  score: number;
  lens: string;
}

export interface ResetAutopilotDataResult {
  dataDir: string;
  removedPaths: string[];
  identityPreserved: boolean;
  remoteHistoryMayPersist: boolean;
}

export type ContextAtlasLens = "Context" | "Skills" | "Substrate";
export type ContextAtlasMode = "List" | "Split" | "3D";

export interface ContextAtlasFocusRequest {
  sessionId?: string | null;
  focusId?: string | null;
  lens?: ContextAtlasLens;
  mode?: ContextAtlasMode;
}

export interface ArtifactContentPayload {
  artifact_id: string;
  encoding: "utf-8" | "base64" | string;
  content: string;
}

export type AgentStatus =
  | "requisition"
  | "pending"
  | "negotiating"
  | "running"
  | "paused"
  | "reviewing"
  | "completed"
  | "failed";

export type GateInfo = SharedSessionGateInfo & {
  pii?: PiiReviewInfo;
};

export interface PiiTargetServiceCall {
  kind: "service_call";
  service_id: string;
  method: string;
}

export interface PiiTargetCloudInference {
  kind: "cloud_inference";
  provider: string;
  model: string;
}

export interface PiiTargetAction {
  kind: "action";
  // Action target is tagged in Rust; we treat as opaque for UI rendering.
  [key: string]: unknown;
}

export type PiiTarget =
  | PiiTargetServiceCall
  | PiiTargetCloudInference
  | PiiTargetAction
  | Record<string, unknown>;

export interface PiiReviewInfo {
  decision_hash: string;
  target_label: string;
  span_summary: string;
  class_counts?: Record<string, number>;
  severity_counts?: Record<string, number>;
  stage2_prompt: string;
  deadline_ms: number;
  target_id?: PiiTarget | null;
}

export interface Receipt {
  duration: string;
  actions: number;
  cost?: string;
}

export type CredentialRequest = SharedSessionCredentialRequest;

export type ClarificationOption = SharedSessionClarificationOption;

export type ClarificationRequest = SharedSessionClarificationRequest;

export interface SessionChecklistItem {
  item_id: string;
  label: string;
  status: string;
  detail?: string | null;
  updated_at_ms: number;
}

export interface SessionBackgroundTaskRecord {
  task_id: string;
  session_id?: string | null;
  label: string;
  status: string;
  detail?: string | null;
  latest_output?: string | null;
  can_stop?: boolean;
  updated_at_ms: number;
}

export interface SessionFileContext {
  session_id?: string | null;
  workspace_root: string;
  pinned_files: string[];
  recent_files: string[];
  explicit_includes: string[];
  explicit_excludes: string[];
  updated_at_ms: number;
}

export interface PolicyContext {
  name: string;
  mode: "strict" | "standard" | "elevated";
  constraints: string[];
}

export interface SwarmAgent {
  id: string;
  parentId: string | null;
  name: string;
  role: string;
  status: AgentStatus;
  budget_used: number;
  budget_cap: number;
  policy_hash: string;
  estimated_cost?: number;
  current_thought?: string;
  artifacts_produced: number;
  generation?: number;
}

export interface AgentTask {
  id: string;
  intent: string;
  agent: string;
  phase: "Idle" | "Running" | "Gate" | "Complete" | "Failed";
  progress: number;
  total_steps: number;
  current_step: string;
  receipt?: Receipt;
  gate_info?: GateInfo;
  history: ChatMessage[];
  events: AgentEvent[];
  artifacts: Artifact[];
  run_bundle_id?: string;
  liability_level?: LiabilityLevel;
  generation: number;
  lineage_id: string;
  fitness_score: number;
  swarm_tree: SwarmAgent[];
  processed_steps: Set<string>;
  visual_hash?: string;
  pending_request_hash?: string;
  session_id?: string;
  policy?: PolicyContext;
  is_secure_session?: boolean;
  credential_request?: CredentialRequest;
  clarification_request?: ClarificationRequest;
  session_checklist: SessionChecklistItem[];
  background_tasks: SessionBackgroundTaskRecord[];
  chat_session?: ChatArtifactSession | null;
  chat_outcome?: ChatOutcomeRequest | null;
  renderer_session?: ChatRendererSession | null;
  build_session?: BuildArtifactSession | null;
}

export type AgentTaskModelInput = Omit<AgentTask, "processed_steps"> & {
  processed_steps?: Set<string> | string[] | null;
};

export function normalizeAgentTaskModel(task: AgentTaskModelInput): AgentTask {
  const processedSteps =
    task.processed_steps instanceof Set
      ? task.processed_steps
      : new Set(
          Array.isArray(task.processed_steps) ? task.processed_steps : [],
        );

  return {
    ...task,
    processed_steps: processedSteps,
    session_checklist: Array.isArray(task.session_checklist)
      ? task.session_checklist
      : [],
    background_tasks: Array.isArray(task.background_tasks)
      ? task.background_tasks
      : [],
  };
}

export interface WalletConnectorAuthRecordView {
  connectorId: string;
  providerFamily: string;
  authProtocol: string;
  state: string;
  accountLabel?: string | null;
  mailbox?: string | null;
  grantedScopes: string[];
  credentialAliases: Record<string, string>;
  metadata: Record<string, string>;
  updatedAtMs: number;
  expiresAtMs?: number | null;
  lastValidatedAtMs?: number | null;
}

export interface WalletConnectorAuthGetResult {
  fetchedAtMs: number;
  record: WalletConnectorAuthRecordView;
}

export interface DetectorPolicyConfig {
  enabled: boolean;
  minScore?: number | null;
  minAgeMinutes?: number | null;
  leadTimeMinutes?: number | null;
  toastMinScore?: number | null;
}

export interface AssistantAttentionGlobalPolicy {
  toastsEnabled: boolean;
  badgeEnabled: boolean;
  digestEnabled: boolean;
  hostedInferenceAllowed: boolean;
}

export interface ConnectorAttentionPolicy {
  scanMode?: string | null;
}

export interface AssistantAttentionPolicy {
  version: number;
  global: AssistantAttentionGlobalPolicy;
  detectors: Record<string, DetectorPolicyConfig>;
  connectors: Record<string, ConnectorAttentionPolicy>;
}

export interface AssistantAttentionProfile {
  version: number;
  preferredSurfaces: string[];
  highValueContacts: string[];
  focusWindows: string[];
  notificationFeedback: Record<string, Record<string, number>>;
}

export interface AssistantUserProfile {
  version: number;
  displayName: string;
  preferredName?: string | null;
  roleLabel?: string | null;
  timezone: string;
  locale: string;
  primaryEmail?: string | null;
  avatarSeed: string;
  groundingAllowed: boolean;
}

export interface KnowledgeCollectionSourceRecord {
  sourceId: string;
  kind: string;
  uri: string;
  pollIntervalMinutes?: number | null;
  enabled: boolean;
  syncStatus: string;
  lastSyncedAtMs?: number | null;
  lastError?: string | null;
}

export interface KnowledgeCollectionEntryRecord {
  entryId: string;
  title: string;
  kind: string;
  scope: string;
  artifactId: string;
  byteCount: number;
  chunkCount: number;
  archivalRecordIds: number[];
  createdAtMs: number;
  updatedAtMs: number;
  contentPreview: string;
}

export interface KnowledgeCollectionRecord {
  collectionId: string;
  label: string;
  description: string;
  createdAtMs: number;
  updatedAtMs: number;
  active: boolean;
  entries: KnowledgeCollectionEntryRecord[];
  sources: KnowledgeCollectionSourceRecord[];
}

export interface KnowledgeCollectionEntryContent {
  collectionId: string;
  entryId: string;
  title: string;
  kind: string;
  artifactId: string;
  byteCount: number;
  content: string;
}

export interface KnowledgeCollectionSearchHit {
  collectionId: string;
  entryId: string;
  title: string;
  scope: string;
  score: number;
  lexicalScore: number;
  semanticScore?: number | null;
  trustLevel: string;
  snippet: string;
  archivalRecordId: number;
  inspectId?: number | null;
}

export interface SkillSourceDiscoveredSkill {
  name: string;
  description?: string | null;
  relativePath: string;
}

export interface SkillSourceRecord {
  sourceId: string;
  label: string;
  uri: string;
  kind: string;
  enabled: boolean;
  syncStatus: string;
  lastSyncedAtMs?: number | null;
  lastError?: string | null;
  discoveredSkills: SkillSourceDiscoveredSkill[];
}

export interface CapabilityAuthorityDescriptor {
  tierId: string;
  tierLabel: string;
  governedProfileId?: string | null;
  governedProfileLabel?: string | null;
  summary: string;
  detail: string;
  signals: string[];
}

export interface CapabilityLeaseDescriptor {
  availability: string;
  availabilityLabel: string;
  runtimeTargetId?: string | null;
  runtimeTargetLabel?: string | null;
  modeId?: string | null;
  modeLabel?: string | null;
  summary: string;
  detail: string;
  requiresAuth: boolean;
  signals: string[];
}

export interface CapabilityRegistryEntry {
  entryId: string;
  kind: string;
  label: string;
  summary: string;
  sourceKind: string;
  sourceLabel: string;
  sourceUri?: string | null;
  trustPosture: string;
  governedProfile?: string | null;
  availability: string;
  statusLabel: string;
  whySelectable: string;
  governingFamilyId?: string | null;
  relatedGoverningEntryIds: string[];
  governingFamilyHints: string[];
  runtimeTarget?: string | null;
  leaseMode?: string | null;
  authority: CapabilityAuthorityDescriptor;
  lease: CapabilityLeaseDescriptor;
}

export interface CapabilityRegistrySummary {
  generatedAtMs: number;
  totalEntries: number;
  connectorCount: number;
  connectedConnectorCount: number;
  runtimeSkillCount: number;
  trackedSourceCount: number;
  filesystemSkillCount: number;
  extensionCount: number;
  modelCount: number;
  backendCount: number;
  nativeFamilyCount: number;
  pendingEngineControlCount: number;
  activeIssueCount: number;
  authoritativeSourceCount: number;
}

export interface ExtensionContributionRecord {
  kind: string;
  label: string;
  path?: string | null;
  itemCount?: number | null;
  detail?: string | null;
}

export interface ExtensionManifestRecord {
  extensionId: string;
  manifestKind: string;
  manifestPath: string;
  rootPath: string;
  sourceLabel: string;
  sourceUri: string;
  sourceKind: string;
  enabled: boolean;
  name: string;
  displayName?: string | null;
  version?: string | null;
  description?: string | null;
  developerName?: string | null;
  authorName?: string | null;
  authorEmail?: string | null;
  authorUrl?: string | null;
  category?: string | null;
  trustPosture: string;
  governedProfile: string;
  homepage?: string | null;
  repository?: string | null;
  license?: string | null;
  keywords: string[];
  capabilities: string[];
  defaultPrompts: string[];
  contributions: ExtensionContributionRecord[];
  filesystemSkills: SkillSourceDiscoveredSkill[];
  marketplaceName?: string | null;
  marketplaceDisplayName?: string | null;
  marketplaceCategory?: string | null;
  marketplaceInstallationPolicy?: string | null;
  marketplaceAuthenticationPolicy?: string | null;
  marketplaceProducts: string[];
  marketplaceAvailableVersion?: string | null;
  marketplaceCatalogIssuedAtMs?: number | null;
  marketplaceCatalogExpiresAtMs?: number | null;
  marketplaceCatalogRefreshedAtMs?: number | null;
  marketplaceCatalogRefreshSource?: string | null;
  marketplaceCatalogChannel?: string | null;
  marketplaceCatalogSourceId?: string | null;
  marketplaceCatalogSourceLabel?: string | null;
  marketplaceCatalogSourceUri?: string | null;
  marketplacePackageUrl?: string | null;
  marketplaceCatalogRefreshBundleId?: string | null;
  marketplaceCatalogRefreshBundleLabel?: string | null;
  marketplaceCatalogRefreshBundleIssuedAtMs?: number | null;
  marketplaceCatalogRefreshBundleExpiresAtMs?: number | null;
  marketplaceCatalogRefreshAvailableVersion?: string | null;
  marketplaceVerificationStatus?: string | null;
  marketplaceSignatureAlgorithm?: string | null;
  marketplaceSignerIdentity?: string | null;
  marketplacePublisherId?: string | null;
  marketplaceSigningKeyId?: string | null;
  marketplacePublisherLabel?: string | null;
  marketplacePublisherTrustStatus?: string | null;
  marketplacePublisherTrustSource?: string | null;
  marketplacePublisherRootId?: string | null;
  marketplacePublisherRootLabel?: string | null;
  marketplaceAuthorityBundleId?: string | null;
  marketplaceAuthorityBundleLabel?: string | null;
  marketplaceAuthorityBundleIssuedAtMs?: number | null;
  marketplaceAuthorityTrustBundleId?: string | null;
  marketplaceAuthorityTrustBundleLabel?: string | null;
  marketplaceAuthorityTrustBundleIssuedAtMs?: number | null;
  marketplaceAuthorityTrustBundleExpiresAtMs?: number | null;
  marketplaceAuthorityTrustBundleStatus?: string | null;
  marketplaceAuthorityTrustIssuerId?: string | null;
  marketplaceAuthorityTrustIssuerLabel?: string | null;
  marketplaceAuthorityId?: string | null;
  marketplaceAuthorityLabel?: string | null;
  marketplacePublisherStatementIssuedAtMs?: number | null;
  marketplacePublisherTrustDetail?: string | null;
  marketplacePublisherRevokedAtMs?: number | null;
  marketplaceVerificationError?: string | null;
  marketplaceVerifiedAtMs?: number | null;
  marketplaceVerificationSource?: string | null;
  marketplaceVerifiedDigestSha256?: string | null;
  marketplaceTrustScoreLabel?: string | null;
  marketplaceTrustScoreSource?: string | null;
  marketplaceTrustRecommendation?: string | null;
}

export interface LocalEngineCapabilityFamily {
  id: string;
  label: string;
  description: string;
  status: string;
  availableCount: number;
  toolNames: string[];
  operatorSummary: string;
}

export interface LocalEngineControlAction {
  itemId: string;
  title: string;
  summary: string;
  status: string;
  severity: string;
  requestedAtMs: number;
  dueAtMs?: number | null;
  approvalScope?: string | null;
  sensitiveActionType?: string | null;
  recommendedAction?: string | null;
  recoveryHint?: string | null;
  requestHash?: string | null;
}

export interface LocalEngineActivityRecord {
  eventId: string;
  sessionId: string;
  family: string;
  title: string;
  toolName: string;
  timestampMs: number;
  success: boolean;
  operation?: string | null;
  subjectKind?: string | null;
  subjectId?: string | null;
  backendId?: string | null;
  errorClass?: string | null;
}

export interface LocalEngineCompatRoute {
  id: string;
  label: string;
  path: string;
  url: string;
  enabled: boolean;
  compatibilityTier: string;
  notes?: string | null;
}

export interface LocalEngineJobRecord {
  jobId: string;
  title: string;
  summary: string;
  status: string;
  origin: string;
  subjectKind: string;
  operation: string;
  createdAtMs: number;
  updatedAtMs: number;
  progressPercent: number;
  sourceUri?: string | null;
  subjectId?: string | null;
  backendId?: string | null;
  severity?: string | null;
  approvalScope?: string | null;
}

export interface LocalEngineModelRecord {
  modelId: string;
  status: string;
  residency: string;
  installedAtMs: number;
  updatedAtMs: number;
  sourceUri?: string | null;
  backendId?: string | null;
  hardwareProfile?: string | null;
  jobId?: string | null;
  bytesTransferred?: number | null;
}

export interface LocalEngineBackendRecord {
  backendId: string;
  status: string;
  health: string;
  installedAtMs: number;
  updatedAtMs: number;
  sourceUri?: string | null;
  alias?: string | null;
  hardwareProfile?: string | null;
  jobId?: string | null;
  installPath?: string | null;
  entrypoint?: string | null;
  healthEndpoint?: string | null;
  pid?: number | null;
  lastStartedAtMs?: number | null;
  lastHealthCheckAtMs?: number | null;
}

export interface LocalEngineGalleryEntryPreview {
  entryId: string;
  label: string;
  summary: string;
  sourceUri?: string | null;
}

export interface LocalEngineGalleryCatalogRecord {
  galleryId: string;
  kind: string;
  label: string;
  sourceUri: string;
  syncStatus: string;
  compatibilityTier: string;
  enabled: boolean;
  entryCount: number;
  updatedAtMs: number;
  lastJobId?: string | null;
  lastSyncedAtMs?: number | null;
  catalogPath?: string | null;
  sampleEntries: LocalEngineGalleryEntryPreview[];
  lastError?: string | null;
}

export interface LocalEngineWorkerCompletionContract {
  successCriteria: string;
  expectedOutput: string;
  mergeMode: string;
  verificationHint?: string | null;
}

export interface LocalEngineWorkerWorkflowRecord {
  workflowId: string;
  label: string;
  summary: string;
  goalTemplate: string;
  triggerIntents: string[];
  defaultBudget?: number | null;
  maxRetries?: number | null;
  allowedTools: string[];
  completionContract?: LocalEngineWorkerCompletionContract | null;
}

export interface LocalEngineWorkerTemplateRecord {
  templateId: string;
  label: string;
  role: string;
  summary: string;
  defaultBudget: number;
  maxRetries: number;
  allowedTools: string[];
  completionContract: LocalEngineWorkerCompletionContract;
  workflows: LocalEngineWorkerWorkflowRecord[];
}

export interface LocalEngineAgentPlaybookStepRecord {
  stepId: string;
  label: string;
  summary: string;
  workerTemplateId: string;
  workerWorkflowId: string;
  goalTemplate: string;
  dependsOn: string[];
}

export interface LocalEngineAgentPlaybookRecord {
  playbookId: string;
  label: string;
  summary: string;
  goalTemplate: string;
  triggerIntents: string[];
  recommendedFor: string[];
  defaultBudget: number;
  completionContract: LocalEngineWorkerCompletionContract;
  steps: LocalEngineAgentPlaybookStepRecord[];
}

export interface LocalEngineParentPlaybookReceiptRecord {
  eventId: string;
  timestampMs: number;
  phase: string;
  status: string;
  success: boolean;
  summary: string;
  receiptRef?: string | null;
  childSessionId?: string | null;
  templateId?: string | null;
  workflowId?: string | null;
  errorClass?: string | null;
  artifactIds: string[];
}

export interface LocalEngineParentPlaybookStepRunRecord {
  stepId: string;
  label: string;
  summary: string;
  status: string;
  childSessionId?: string | null;
  templateId?: string | null;
  workflowId?: string | null;
  updatedAtMs?: number | null;
  completedAtMs?: number | null;
  errorClass?: string | null;
  receipts: LocalEngineParentPlaybookReceiptRecord[];
}

export interface LocalEngineParentPlaybookRunRecord {
  runId: string;
  parentSessionId: string;
  playbookId: string;
  playbookLabel: string;
  status: string;
  latestPhase: string;
  summary: string;
  currentStepId?: string | null;
  currentStepLabel?: string | null;
  activeChildSessionId?: string | null;
  startedAtMs: number;
  updatedAtMs: number;
  completedAtMs?: number | null;
  errorClass?: string | null;
  steps: LocalEngineParentPlaybookStepRunRecord[];
}

export interface LocalEngineRuntimeProfile {
  mode: string;
  endpoint: string;
  defaultModel: string;
  baselineRole: string;
  kernelAuthority: string;
}

export interface LocalEngineStorageConfig {
  modelsPath: string;
  backendsPath: string;
  artifactsPath: string;
  cachePath: string;
}

export interface LocalEngineWatchdogConfig {
  enabled: boolean;
  idleCheckEnabled: boolean;
  idleTimeout: string;
  busyCheckEnabled: boolean;
  busyTimeout: string;
  checkInterval: string;
  forceEvictionWhenBusy: boolean;
  lruEvictionMaxRetries: number;
  lruEvictionRetryInterval: string;
}

export interface LocalEngineMemoryConfig {
  reclaimerEnabled: boolean;
  thresholdPercent: number;
  preferGpu: boolean;
  targetResource: string;
}

export interface LocalEngineBackendPolicyConfig {
  maxConcurrency: number;
  maxQueuedRequests: number;
  parallelBackendLoads: number;
  allowParallelRequests: boolean;
  healthProbeInterval: string;
  logLevel: string;
  autoShutdownOnIdle: boolean;
}

export interface LocalEngineResponseConfig {
  retainReceiptsDays: number;
  persistArtifacts: boolean;
  allowStreaming: boolean;
  storeRequestPreviews: boolean;
}

export interface LocalEngineApiConfig {
  bindAddress: string;
  remoteAccessEnabled: boolean;
  exposeCompatRoutes: boolean;
  corsMode: string;
  authMode: string;
}

export interface LocalEngineLauncherConfig {
  autoStartOnBoot: boolean;
  reopenChatOnLaunch: boolean;
  autoCheckUpdates: boolean;
  releaseChannel: string;
  showKernelConsole: boolean;
}

export interface LocalEngineGallerySource {
  id: string;
  kind: string;
  label: string;
  uri: string;
  enabled: boolean;
  syncStatus: string;
  compatibilityTier: string;
}

export interface LocalEngineEnvironmentBinding {
  key: string;
  value: string;
  secret: boolean;
}

export interface LocalEngineControlPlane {
  runtime: LocalEngineRuntimeProfile;
  storage: LocalEngineStorageConfig;
  watchdog: LocalEngineWatchdogConfig;
  memory: LocalEngineMemoryConfig;
  backendPolicy: LocalEngineBackendPolicyConfig;
  responses: LocalEngineResponseConfig;
  api: LocalEngineApiConfig;
  launcher: LocalEngineLauncherConfig;
  galleries: LocalEngineGallerySource[];
  environment: LocalEngineEnvironmentBinding[];
  notes: string[];
}

export interface LocalEngineConfigMigrationRecord {
  migrationId: string;
  fromVersion: number;
  toVersion: number;
  appliedAtMs: number;
  summary: string;
  details: string[];
}

export interface LocalEngineStagedOperation {
  operationId: string;
  subjectKind: string;
  operation: string;
  title: string;
  sourceUri?: string | null;
  subjectId?: string | null;
  notes?: string | null;
  createdAtMs: number;
  status: string;
}

export interface LocalEngineManagedSettingsChannelRecord {
  channelId: string;
  label: string;
  sourceUri: string;
  status: string;
  verificationStatus: string;
  summary: string;
  precedence: number;
  authorityLabel?: string | null;
  signatureAlgorithm?: string | null;
  profileId?: string | null;
  schemaVersion?: number | null;
  issuedAtMs?: number | null;
  expiresAtMs?: number | null;
  refreshedAtMs?: number | null;
  localOverrideCount: number;
  overriddenFields: string[];
}

export interface LocalEngineManagedSettingsSnapshot {
  syncStatus: string;
  summary: string;
  activeChannelId?: string | null;
  activeChannelLabel?: string | null;
  activeSourceUri?: string | null;
  lastRefreshedAtMs?: number | null;
  lastSuccessfulRefreshAtMs?: number | null;
  lastFailedRefreshAtMs?: number | null;
  refreshError?: string | null;
  localOverrideCount: number;
  localOverrideFields: string[];
  channels: LocalEngineManagedSettingsChannelRecord[];
}

export interface LocalEngineSnapshot {
  generatedAtMs: number;
  totalNativeTools: number;
  pendingControlCount: number;
  pendingApprovalCount: number;
  activeIssueCount: number;
  capabilities: LocalEngineCapabilityFamily[];
  compatibilityRoutes: LocalEngineCompatRoute[];
  pendingControls: LocalEngineControlAction[];
  jobs: LocalEngineJobRecord[];
  recentActivity: LocalEngineActivityRecord[];
  registryModels: LocalEngineModelRecord[];
  managedBackends: LocalEngineBackendRecord[];
  galleryCatalogs: LocalEngineGalleryCatalogRecord[];
  workerTemplates: LocalEngineWorkerTemplateRecord[];
  agentPlaybooks: LocalEngineAgentPlaybookRecord[];
  parentPlaybookRuns: LocalEngineParentPlaybookRunRecord[];
  controlPlaneSchemaVersion: number;
  controlPlaneProfileId: string;
  controlPlaneMigrations: LocalEngineConfigMigrationRecord[];
  controlPlane: LocalEngineControlPlane;
  managedSettings: LocalEngineManagedSettingsSnapshot;
  stagedOperations: LocalEngineStagedOperation[];
}

export interface CapabilityRegistrySnapshot {
  generatedAtMs: number;
  summary: CapabilityRegistrySummary;
  entries: CapabilityRegistryEntry[];
  connectors: ConnectorSummary[];
  skillCatalog: SkillCatalogEntry[];
  skillSources: SkillSourceRecord[];
  extensionManifests: ExtensionManifestRecord[];
  localEngine: LocalEngineSnapshot;
}

export interface SessionSummary {
  session_id: string;
  title: string;
  timestamp: number;
  phase?: string | null;
  current_step?: string | null;
  resume_hint?: string | null;
  workspace_root?: string | null;
}

export type SessionMemoryClass =
  | "ephemeral"
  | "carry_forward"
  | "pinned"
  | "governance_critical";

export type SessionCompactionMode = "manual" | "auto";

export interface SessionCompactionPolicy {
  carryPinnedOnly: boolean;
  preserveChecklistState: boolean;
  preserveBackgroundTasks: boolean;
  preserveLatestOutputExcerpt: boolean;
  preserveGovernanceBlockers: boolean;
  aggressiveTranscriptPruning: boolean;
}

export type SessionCompactionDisposition =
  | "carry_forward"
  | "retained_summary"
  | "pruned";

export type SessionCompactionResumeSafetyStatus = "protected" | "degraded";

export interface SessionCompactionResumeSafetyReceipt {
  status: SessionCompactionResumeSafetyStatus;
  reasons: string[];
}

export interface SessionCompactionMemoryItem {
  key: string;
  label: string;
  memoryClass: SessionMemoryClass;
  values: string[];
}

export interface SessionCompactionPruneDecision {
  key: string;
  label: string;
  disposition: SessionCompactionDisposition;
  detailCount: number;
  rationale: string;
  summary: string;
  examples: string[];
}

export interface SessionCompactionCarryForwardState {
  workspaceRoot?: string | null;
  pinnedFiles: string[];
  explicitIncludes: string[];
  explicitExcludes: string[];
  checklistLabels: string[];
  backgroundTaskLabels: string[];
  blockedOn?: string | null;
  pendingDecisionContext?: string | null;
  latestArtifactOutcome?: string | null;
  executionTargets: string[];
  latestOutputExcerpt?: string | null;
  memoryItems: SessionCompactionMemoryItem[];
}

export interface SessionCompactionPreview {
  sessionId: string;
  title: string;
  phase?: string | null;
  policy: SessionCompactionPolicy;
  preCompactionSpan: string;
  summary: string;
  resumeAnchor: string;
  carriedForwardState: SessionCompactionCarryForwardState;
  resumeSafety: SessionCompactionResumeSafetyReceipt;
  pruneDecisions: SessionCompactionPruneDecision[];
}

export interface SessionCompactionRecord {
  compactionId: string;
  sessionId: string;
  title: string;
  compactedAtMs: number;
  mode: SessionCompactionMode;
  phase?: string | null;
  policy: SessionCompactionPolicy;
  preCompactionSpan: string;
  summary: string;
  resumeAnchor: string;
  carriedForwardState: SessionCompactionCarryForwardState;
  resumeSafety: SessionCompactionResumeSafetyReceipt;
  pruneDecisions: SessionCompactionPruneDecision[];
}

export interface SessionCompactionRecommendation {
  shouldCompact: boolean;
  reasonLabels: string[];
  recommendedPolicy: SessionCompactionPolicy;
  recommendedPolicyLabel: string;
  recommendedPolicyReasonLabels: string[];
  resumeSafeguardLabels: string[];
  historyCount: number;
  eventCount: number;
  artifactCount: number;
  pinnedFileCount: number;
  explicitIncludeCount: number;
  idleAgeMs: number;
  blockedAgeMs?: number | null;
}

export interface SessionDurabilityPortfolio {
  retainedSessionCount: number;
  compactedSessionCount: number;
  replayReadySessionCount: number;
  uncompactedSessionCount: number;
  staleCompactionCount: number;
  degradedCompactionCount: number;
  recommendedCompactionCount: number;
  compactedWithoutTeamMemoryCount: number;
  teamMemoryEntryCount: number;
  teamMemoryCoveredSessionCount: number;
  teamMemoryRedactedSessionCount: number;
  teamMemoryReviewRequiredSessionCount: number;
  coverageSummary: string;
  teamMemorySummary: string;
  attentionSummary: string;
  attentionLabels: string[];
}

export interface SessionCompactionSnapshot {
  generatedAtMs: number;
  activeSessionId?: string | null;
  activeSessionTitle?: string | null;
  policyForActive: SessionCompactionPolicy;
  recordCount: number;
  latestForActive?: SessionCompactionRecord | null;
  previewForActive?: SessionCompactionPreview | null;
  recommendationForActive?: SessionCompactionRecommendation | null;
  durabilityPortfolio?: SessionDurabilityPortfolio;
  records: SessionCompactionRecord[];
}

export type TeamMemoryScopeKind = "workspace" | "session";

export type TeamMemorySyncStatus = "synced" | "redacted" | "review_required";

export interface TeamMemoryRedactionSummary {
  redactionCount: number;
  redactedFields: string[];
  redactionVersion: string;
}

export interface TeamMemorySyncEntry {
  entryId: string;
  sessionId: string;
  sessionTitle: string;
  syncedAtMs: number;
  scopeKind: TeamMemoryScopeKind;
  scopeId: string;
  scopeLabel: string;
  actorId: string;
  actorLabel: string;
  actorRole: string;
  syncStatus: TeamMemorySyncStatus;
  reviewSummary: string;
  omittedGovernanceItemCount: number;
  resumeAnchor: string;
  preCompactionSpan: string;
  summary: string;
  sharedMemoryItems: SessionCompactionMemoryItem[];
  redaction: TeamMemoryRedactionSummary;
}

export interface TeamMemorySyncSnapshot {
  generatedAtMs: number;
  activeSessionId?: string | null;
  activeScopeId?: string | null;
  activeScopeKind?: TeamMemoryScopeKind | null;
  activeScopeLabel?: string | null;
  entryCount: number;
  redactedEntryCount: number;
  reviewRequiredCount: number;
  summary: string;
  entries: TeamMemorySyncEntry[];
}

export interface SessionRewindCandidate {
  sessionId: string;
  title: string;
  timestamp: number;
  phase?: string | null;
  currentStep?: string | null;
  resumeHint?: string | null;
  workspaceRoot?: string | null;
  isCurrent: boolean;
  isLastStable: boolean;
  actionLabel: string;
  previewHeadline: string;
  previewDetail: string;
  discardSummary: string;
}

export interface SessionRewindSnapshot {
  activeSessionId?: string | null;
  activeSessionTitle?: string | null;
  lastStableSessionId?: string | null;
  candidates: SessionRewindCandidate[];
}

export interface SessionHookReceiptSummary {
  title: string;
  timestampMs: number;
  toolName: string;
  status: string;
  summary: string;
}

export interface SessionHookRecord {
  hookId: string;
  entryId?: string | null;
  label: string;
  ownerLabel: string;
  sourceLabel: string;
  sourceKind: string;
  sourceUri?: string | null;
  contributionPath?: string | null;
  triggerLabel: string;
  enabled: boolean;
  statusLabel: string;
  trustPosture: string;
  governedProfile: string;
  authorityTierLabel: string;
  availabilityLabel: string;
  sessionScopeLabel: string;
  whyActive: string;
}

export interface SessionHookSnapshot {
  generatedAtMs: number;
  sessionId?: string | null;
  workspaceRoot?: string | null;
  activeHookCount: number;
  disabledHookCount: number;
  runtimeReceiptCount: number;
  approvalReceiptCount: number;
  hooks: SessionHookRecord[];
  recentReceipts: SessionHookReceiptSummary[];
}

export interface SessionBranchRecord {
  branchName: string;
  upstreamBranch?: string | null;
  isCurrent: boolean;
  aheadCount: number;
  behindCount: number;
  lastCommit?: string | null;
}

export interface SessionWorktreeRecord {
  path: string;
  branchName?: string | null;
  head?: string | null;
  lastCommit?: string | null;
  changedFileCount: number;
  dirty: boolean;
  isCurrent: boolean;
  locked: boolean;
  lockReason?: string | null;
  prunable: boolean;
  pruneReason?: string | null;
  statusLabel: string;
  statusDetail: string;
}

export interface SessionBranchSnapshot {
  generatedAtMs: number;
  sessionId?: string | null;
  workspaceRoot?: string | null;
  isRepo: boolean;
  repoLabel?: string | null;
  currentBranch?: string | null;
  upstreamBranch?: string | null;
  lastCommit?: string | null;
  aheadCount: number;
  behindCount: number;
  changedFileCount: number;
  dirty: boolean;
  worktreeRiskLabel: string;
  worktreeRiskDetail: string;
  recentBranches: SessionBranchRecord[];
  worktrees: SessionWorktreeRecord[];
}

export interface SessionRemoteEnvBinding {
  key: string;
  valuePreview: string;
  sourceLabel: string;
  scopeLabel: string;
  provenanceLabel: string;
  secret: boolean;
  redacted: boolean;
}

export interface SessionRemoteEnvSnapshot {
  generatedAtMs: number;
  sessionId?: string | null;
  workspaceRoot?: string | null;
  focusedScopeLabel: string;
  governingSourceLabel: string;
  postureLabel: string;
  postureDetail: string;
  bindingCount: number;
  controlPlaneBindingCount: number;
  processBindingCount: number;
  overlappingBindingCount: number;
  secretBindingCount: number;
  redactedBindingCount: number;
  notes: string[];
  bindings: SessionRemoteEnvBinding[];
}

export interface SessionServerSessionRecord {
  sessionId: string;
  title: string;
  timestamp: number;
  sourceLabel: string;
  presenceState: string;
  presenceLabel: string;
  resumeHint?: string | null;
  workspaceRoot?: string | null;
}

export interface SessionServerSnapshot {
  generatedAtMs: number;
  sessionId?: string | null;
  workspaceRoot?: string | null;
  rpcUrl: string;
  rpcSourceLabel: string;
  continuityModeLabel: string;
  continuityStatusLabel: string;
  continuityDetail: string;
  kernelConnectionLabel: string;
  kernelConnectionDetail: string;
  explicitRpcTarget: boolean;
  remoteKernelTarget: boolean;
  kernelReachable: boolean;
  remoteHistoryAvailable: boolean;
  localSessionCount: number;
  remoteSessionCount: number;
  mergedSessionCount: number;
  remoteOnlySessionCount: number;
  overlappingSessionCount: number;
  remoteAttachableSessionCount: number;
  remoteHistoryOnlySessionCount: number;
  currentSessionVisibleRemotely: boolean;
  currentSessionContinuityState: string;
  currentSessionContinuityLabel: string;
  currentSessionContinuityDetail: string;
  notes: string[];
  recentRemoteSessions: SessionServerSessionRecord[];
}

export interface VoiceInputTranscriptionResult {
  text: string;
  mimeType: string;
  fileName?: string | null;
  language?: string | null;
  modelId?: string | null;
}

export interface SessionPluginRecord {
  pluginId: string;
  entryId?: string | null;
  label: string;
  description?: string | null;
  version?: string | null;
  sourceEnabled: boolean;
  enabled: boolean;
  statusLabel: string;
  sourceLabel: string;
  sourceKind: string;
  sourceUri?: string | null;
  category?: string | null;
  marketplaceDisplayName?: string | null;
  marketplaceInstallationPolicy?: string | null;
  marketplaceAuthenticationPolicy?: string | null;
  marketplaceProducts: string[];
  authenticityState: string;
  authenticityLabel: string;
  authenticityDetail: string;
  operatorReviewState: string;
  operatorReviewLabel: string;
  operatorReviewReason: string;
  catalogStatus: string;
  catalogStatusLabel: string;
  catalogStatusDetail: string;
  catalogIssuedAtMs?: number | null;
  catalogExpiresAtMs?: number | null;
  catalogRefreshedAtMs?: number | null;
  catalogRefreshSource?: string | null;
  catalogChannel?: string | null;
  catalogSourceId?: string | null;
  catalogSourceLabel?: string | null;
  catalogSourceUri?: string | null;
  marketplacePackageUrl?: string | null;
  catalogRefreshBundleId?: string | null;
  catalogRefreshBundleLabel?: string | null;
  catalogRefreshBundleIssuedAtMs?: number | null;
  catalogRefreshBundleExpiresAtMs?: number | null;
  catalogRefreshAvailableVersion?: string | null;
  catalogRefreshError?: string | null;
  lastCatalogRefreshAtMs?: number | null;
  verificationError?: string | null;
  verificationAlgorithm?: string | null;
  publisherLabel?: string | null;
  publisherId?: string | null;
  signerIdentity?: string | null;
  signingKeyId?: string | null;
  verificationTimestampMs?: number | null;
  verificationSource?: string | null;
  verifiedDigestSha256?: string | null;
  publisherTrustState?: string | null;
  publisherTrustLabel?: string | null;
  publisherTrustDetail?: string | null;
  publisherTrustSource?: string | null;
  publisherRootId?: string | null;
  publisherRootLabel?: string | null;
  authorityBundleId?: string | null;
  authorityBundleLabel?: string | null;
  authorityBundleIssuedAtMs?: number | null;
  authorityTrustBundleId?: string | null;
  authorityTrustBundleLabel?: string | null;
  authorityTrustBundleIssuedAtMs?: number | null;
  authorityTrustBundleExpiresAtMs?: number | null;
  authorityTrustBundleStatus?: string | null;
  authorityTrustIssuerId?: string | null;
  authorityTrustIssuerLabel?: string | null;
  authorityId?: string | null;
  authorityLabel?: string | null;
  publisherStatementIssuedAtMs?: number | null;
  publisherRevokedAtMs?: number | null;
  trustScoreLabel?: string | null;
  trustScoreSource?: string | null;
  trustRecommendation?: string | null;
  updateSeverity?: string | null;
  updateSeverityLabel?: string | null;
  updateDetail?: string | null;
  requestedCapabilities: string[];
  trustPosture: string;
  governedProfile: string;
  authorityTierLabel: string;
  availabilityLabel: string;
  sessionScopeLabel: string;
  reloadable: boolean;
  reloadabilityLabel: string;
  contributionCount: number;
  hookContributionCount: number;
  filesystemSkillCount: number;
  capabilityCount: number;
  runtimeTrustState: string;
  runtimeTrustLabel: string;
  runtimeLoadState: string;
  runtimeLoadLabel: string;
  runtimeStatusDetail: string;
  loadError?: string | null;
  lastTrustedAtMs?: number | null;
  lastReloadedAtMs?: number | null;
  lastInstalledAtMs?: number | null;
  lastUpdatedAtMs?: number | null;
  lastRemovedAtMs?: number | null;
  trustRemembered: boolean;
  packageManaged: boolean;
  packageInstallState: string;
  packageInstallLabel: string;
  packageInstallDetail: string;
  packageInstallSource?: string | null;
  packageInstallSourceLabel?: string | null;
  packageRootPath?: string | null;
  packageManifestPath?: string | null;
  installedVersion?: string | null;
  availableVersion?: string | null;
  updateAvailable: boolean;
  packageError?: string | null;
  whyAvailable: string;
}

export interface SessionPluginLifecycleReceipt {
  receiptId: string;
  timestampMs: number;
  pluginId: string;
  pluginLabel: string;
  action: string;
  status: string;
  summary: string;
}

export interface SessionPluginCatalogChannelRecord {
  catalogId: string;
  label: string;
  sourceUri: string;
  refreshSource?: string | null;
  channel?: string | null;
  status: string;
  statusLabel: string;
  statusDetail: string;
  issuedAtMs?: number | null;
  expiresAtMs?: number | null;
  refreshedAtMs?: number | null;
  pluginCount: number;
  validPluginCount: number;
  invalidPluginCount: number;
  refreshBundleCount: number;
  refreshError?: string | null;
  conformanceStatus: string;
  conformanceLabel: string;
  conformanceError?: string | null;
}

export interface SessionPluginSnapshot {
  generatedAtMs: number;
  sessionId?: string | null;
  workspaceRoot?: string | null;
  pluginCount: number;
  enabledPluginCount: number;
  disabledPluginCount: number;
  trustedPluginCount: number;
  untrustedPluginCount: number;
  blockedPluginCount: number;
  reloadablePluginCount: number;
  managedPackageCount: number;
  updateAvailableCount: number;
  installablePackageCount: number;
  verifiedPluginCount: number;
  unverifiedPluginCount: number;
  signatureMismatchPluginCount: number;
  recommendedPluginCount: number;
  reviewRequiredPluginCount: number;
  staleCatalogCount: number;
  expiredCatalogCount: number;
  criticalUpdateCount: number;
  refreshAvailableCount: number;
  refreshFailedCount: number;
  catalogChannelCount: number;
  nonconformantChannelCount: number;
  catalogSourceCount: number;
  localCatalogSourceCount: number;
  remoteCatalogSourceCount: number;
  failedCatalogSourceCount: number;
  nonconformantSourceCount: number;
  hookContributionCount: number;
  filesystemSkillCount: number;
  recentReceiptCount: number;
  recentReceipts: SessionPluginLifecycleReceipt[];
  catalogSources: SessionPluginCatalogSourceRecord[];
  catalogChannels: SessionPluginCatalogChannelRecord[];
  plugins: SessionPluginRecord[];
}

export interface SessionPluginCatalogSourceRecord {
  sourceId: string;
  label: string;
  sourceUri: string;
  transportKind: string;
  channel?: string | null;
  authorityBundleId?: string | null;
  authorityBundleLabel?: string | null;
  status: string;
  statusLabel: string;
  statusDetail: string;
  lastSuccessfulRefreshAtMs?: number | null;
  lastFailedRefreshAtMs?: number | null;
  refreshError?: string | null;
  conformanceStatus: string;
  conformanceLabel: string;
  conformanceError?: string | null;
  catalogCount: number;
  validCatalogCount: number;
  invalidCatalogCount: number;
}

export interface AssistantWorkbenchActivityRecord {
  activityId: string;
  sessionKind: string;
  surface: string;
  action: string;
  status: string;
  message: string;
  timestampMs: number;
  sourceNotificationId?: string | null;
  connectorId?: string | null;
  threadId?: string | null;
  eventId?: string | null;
  evidenceThreadId?: string | null;
  detail?: string | null;
}

export interface TraceBundleStats {
  eventCount: number;
  receiptCount: number;
  artifactCount: number;
  runBundleCount: number;
  reportArtifactCount: number;
  interventionCount: number;
  assistantNotificationCount: number;
  assistantWorkbenchActivityCount: number;
  includedArtifactPayloads: boolean;
  includedArtifactPayloadCount: number;
}

export interface TraceBundleArtifactPayloadEntry {
  artifactId: string;
  artifactType: ArtifactType;
  path: string;
}

export interface CanonicalTraceBundle {
  schemaVersion: number;
  exportedAtUtc: string;
  threadId: string;
  sessionId: string;
  latestAnswerMarkdown: string;
  stats: TraceBundleStats;
  sessionSummary?: SessionSummary | null;
  task?: AgentTask | null;
  history: ChatMessage[];
  events: AgentEvent[];
  receipts: AgentEvent[];
  artifacts: Artifact[];
  artifactPayloads: TraceBundleArtifactPayloadEntry[];
  interventions: InterventionRecord[];
  assistantNotifications: AssistantNotificationRecord[];
  assistantWorkbenchActivities: AssistantWorkbenchActivityRecord[];
}

export interface TraceBundleDiffStat {
  label: string;
  leftValue: string;
  rightValue: string;
}

export interface TraceBundleDiffSection {
  key: string;
  label: string;
  changed: boolean;
  summary: string;
  leftValue?: string | null;
  rightValue?: string | null;
  details: string[];
}

export interface TraceBundleDiffResult {
  schemaVersion: number;
  comparedAtUtc: string;
  leftThreadId: string;
  rightThreadId: string;
  leftSessionSummary?: SessionSummary | null;
  rightSessionSummary?: SessionSummary | null;
  firstDivergenceKey?: string | null;
  firstDivergenceSummary?: string | null;
  changedSectionCount: number;
  stats: TraceBundleDiffStat[];
  sections: TraceBundleDiffSection[];
}

export interface MutationLogEntry {
  generation: number;
  parent_hash: string;
  child_hash: string;
  diff_summary: string;
  rationale: string;
  score_delta: number;
  timestamp: number;
}

export type ActivityKind =
  | "primary_answer_event"
  | "receipt_event"
  | "reasoning_event"
  | "workload_event"
  | "system_event";

export interface ActivityEventRef {
  key: string;
  event: AgentEvent;
  kind: ActivityKind;
  toolName?: string;
  normalizedOutputHash?: string;
}

export interface ActivitySummary {
  searchCount: number;
  readCount: number;
  receiptCount: number;
  reasoningCount: number;
  systemCount: number;
  artifactCount: number;
}

export interface ActivityGroup {
  stepIndex: number;
  title: string;
  events: ActivityEventRef[];
}

export type ToolActivityKind =
  | "search"
  | "read"
  | "write"
  | "verify"
  | "preview"
  | "inspect"
  | "route"
  | "understand"
  | "guidance"
  | "present"
  | "other";

export type ToolActivityStatus = "complete" | "active" | "blocked";

export interface ToolActivityRow {
  key: string;
  kind: ToolActivityKind;
  status: ToolActivityStatus;
  stepIndex: number;
  label: string;
  detail: string | null;
  preview: string | null;
  sourceUrl?: string | null;
  sourceSummary?: SourceSummary | null;
}

export interface ToolActivityGroupPresentation {
  key: string;
  label: string;
  rows: ToolActivityRow[];
  defaultOpen: boolean;
  presentation?: "default" | "inline_transcript";
}

export type ChatContractScalar = string | number | boolean | null;
export type ChatContractValue = ChatContractScalar | ChatContractScalar[];
export type ChatContractSchemaVersion = "chat_contract_v1";
export type ChatContractOutcomeStatus = "success" | "partial" | "failed";

export interface ChatContractOutcome {
  status: ChatContractOutcomeStatus;
  summary?: string;
  count?: number;
}

export interface ChatContractResultColumn {
  key: string;
  label: string;
}

export interface ChatContractAction {
  id: string;
  label: string;
}

export type ChatContractResultRow = Record<string, ChatContractScalar>;
export type ChatContractInterpretation = Record<string, ChatContractValue>;

export interface ChatContractEnvelopeV1 {
  schema_version: ChatContractSchemaVersion;
  intent_id: string;
  outcome: ChatContractOutcome;
  interpretation: ChatContractInterpretation;
  result_rows: ChatContractResultRow[];
  result_columns?: ChatContractResultColumn[];
  actions?: ChatContractAction[];
  artifact_ref?: string;
  answer_markdown?: string;
}

export interface ChatContractValidationIssue {
  path: string;
  code: string;
  message: string;
}

export interface AnswerPresentation {
  message: ChatMessage;
  displayText: string;
  copyText: string;
  contract: ChatContractEnvelopeV1 | null;
  contractValidationIssues: ChatContractValidationIssue[];
  citations: string[];
  sourceUrls: string[];
}

export interface SourceDomainPreview {
  domain: string;
  faviconUrl: string;
  count: number;
}

export interface SourceSearchRow {
  query: string;
  resultCount: number;
  stepIndex: number;
}

export interface SourceBrowseRow {
  url: string;
  domain: string;
  title?: string;
  stepIndex: number;
}

export interface SourceSummary {
  totalSources: number;
  sourceUrls: string[];
  domains: SourceDomainPreview[];
  searches: SourceSearchRow[];
  browses: SourceBrowseRow[];
}

export type ThoughtAgentKind =
  | "worker"
  | "verifier"
  | "patch_synthesizer"
  | "artifact_generator"
  | "computer_use_operator";

export interface ThoughtAgentSummary {
  agentLabel: string;
  agentRole: string | null;
  agentKind: ThoughtAgentKind;
  stepIndex: number;
  notes: string[];
}

export interface ThoughtSummary {
  agents: ThoughtAgentSummary[];
}

export type ExecutionMomentKind =
  | "branch"
  | "approval"
  | "pause"
  | "verification";

export type ExecutionMomentStatus =
  | "info"
  | "pending"
  | "passed"
  | "warning"
  | "blocked";

export interface ExecutionMoment {
  key: string;
  kind: ExecutionMomentKind;
  status: ExecutionMomentStatus;
  stepIndex: number;
  title: string;
  summary: string;
}

export type PlanRouteFamily =
  | "general"
  | "research"
  | "coding"
  | "integrations"
  | "communication"
  | "user_input"
  | "tool_widget"
  | "computer_use"
  | "artifacts";

export type PlanLaneFamily =
  | "general"
  | "research"
  | "coding"
  | "integrations"
  | "conversation"
  | "tool_widget"
  | "visualizer"
  | "artifact"
  | "communication"
  | "user_input";

export type PlanSourceFamily =
  | "user_directed"
  | "conversation_context"
  | "memory"
  | "conversation_retrieval"
  | "connector"
  | "specialized_tool"
  | "web_search"
  | "direct_answer"
  | "workspace"
  | "artifact_context";

export type PlanClarificationMode =
  | "assume_from_retained_state"
  | "clarify_on_missing_slots"
  | "block_until_clarified";

export type PlanFallbackMode =
  | "stay_in_specialized_lane"
  | "allow_ranked_fallbacks"
  | "block_until_clarified";

export type PlanRiskSensitivity = "low" | "medium" | "high";

export type PlanWorkStatus =
  | "pending"
  | "in_progress"
  | "complete"
  | "blocked";

export type PlanLaneTransitionKind = "planned" | "reactive";

export type PlanRouteTopology =
  | "single_agent"
  | "planner_specialist"
  | "planner_specialist_verifier";

export type PlanPlannerAuthority = "kernel" | "primary_agent";

export type PlanVerifierState =
  | "not_engaged"
  | "queued"
  | "active"
  | "passed"
  | "blocked";

export type PlanVerifierRole =
  | "verifier"
  | "citation_verifier"
  | "test_verifier"
  | "postcondition_verifier"
  | "artifact_validation_verifier";

export type PlanVerifierOutcome = "pass" | "warning" | "blocked";

export type PlanApprovalState = "clear" | "pending" | "approved" | "denied";

export interface PlanComputerUsePerceptionSummary {
  surfaceStatus: string;
  uiState: string;
  target: string | null;
  approvalRisk: string;
  nextAction: string | null;
  notes: string | null;
}

export interface PlanResearchVerificationSummary {
  verdict: string;
  sourceCount: number;
  distinctDomainCount: number;
  sourceCountFloorMet: boolean;
  sourceIndependenceFloorMet: boolean;
  freshnessStatus: string;
  quoteGroundingStatus: string;
  notes: string | null;
}

export interface PlanArtifactGenerationSummary {
  status: string;
  producedFileCount: number;
  verificationSignalStatus: string;
  presentationStatus: string;
  notes: string | null;
}

export interface PlanCodingVerificationSummary {
  verdict: string;
  targetedCommandCount: number;
  targetedPassCount: number;
  wideningStatus: string;
  regressionStatus: string;
  notes: string | null;
}

export interface PlanArtifactQualitySummary {
  verdict: string;
  fidelityStatus: string;
  presentationStatus: string;
  repairStatus: string;
  notes: string | null;
}

export interface PlanPatchSynthesisSummary {
  status: string;
  touchedFileCount: number;
  verificationReady: boolean;
  notes: string | null;
}

export interface PlanComputerUseVerificationSummary {
  verdict: string;
  postconditionStatus: string;
  approvalState: string;
  recoveryStatus: string;
  observedPostcondition: string | null;
  notes: string | null;
}

export interface PlanComputerUseRecoverySummary {
  status: string;
  reason: string | null;
  nextStep: string | null;
}

export interface PlanArtifactRepairSummary {
  status: string;
  reason: string | null;
  nextStep: string | null;
}

export interface PlanSelectedSkill {
  id: string;
  entryId: string;
  label: string;
}

export type PlanOutputIntent =
  | "direct_inline"
  | "file"
  | "artifact"
  | "inline_visual"
  | "delegated"
  | "tool_execution";

export interface PlanEffectiveToolSurfaceSummary {
  projectedTools: string[];
  primaryTools: string[];
  broadFallbackTools: string[];
  diagnosticTools: string[];
}

export interface PlanLaneFrameSummary {
  primaryLane: PlanLaneFamily;
  secondaryLanes: PlanLaneFamily[];
  primaryGoal: string;
  toolWidgetFamily: string | null;
  currentnessPressure: boolean;
  workspaceGroundingRequired: boolean;
  persistentDeliverableRequested: boolean;
  activeArtifactFollowUp: boolean;
  laneConfidence: number;
}

export interface PlanSourceSelectionSummary {
  candidateSources: PlanSourceFamily[];
  selectedSource: PlanSourceFamily;
  explicitUserSource: boolean;
  fallbackReason: string | null;
}

export interface PlanClarificationPolicySummary {
  mode: PlanClarificationMode;
  assumedBindings: string[];
  blockingSlots: string[];
  rationale: string;
}

export interface PlanFallbackPolicySummary {
  mode: PlanFallbackMode;
  primaryLane: PlanLaneFamily;
  fallbackLanes: PlanLaneFamily[];
  triggerSignals: string[];
  rationale: string;
}

export interface PlanPresentationPolicySummary {
  primarySurface: string;
  widgetFamily: string | null;
  renderer: ChatRendererKind | null;
  tabPriority: string[];
  rationale: string;
}

export interface PlanTransformationPolicySummary {
  outputShape: string;
  orderedSteps: string[];
  rationale: string;
}

export interface PlanRiskProfileSummary {
  sensitivity: PlanRiskSensitivity;
  reasons: string[];
  approvalRequired: boolean;
  userVisibleGuardrails: string[];
}

export interface PlanVerificationContractSummary {
  strategy: string;
  requiredChecks: string[];
  completionGate: string;
}

export interface PlanSourceRankingEntrySummary {
  source: PlanSourceFamily;
  rank: number;
  rationale: string;
}

export interface PlanWidgetStateBindingSummary {
  key: string;
  value: string;
  source: string;
}

export interface PlanRetainedWidgetStateSummary {
  widgetFamily: string | null;
  bindings: PlanWidgetStateBindingSummary[];
  lastUpdatedAt: string | null;
}

export interface PlanPolicyContractSummary {
  bindings: string[];
  hiddenInstructionDependency: boolean;
  rationale: string;
}

export interface PlanDomainPolicyBundleSummary {
  clarificationPolicy: PlanClarificationPolicySummary | null;
  fallbackPolicy: PlanFallbackPolicySummary | null;
  presentationPolicy: PlanPresentationPolicySummary | null;
  transformationPolicy: PlanTransformationPolicySummary | null;
  riskProfile: PlanRiskProfileSummary | null;
  verificationContract: PlanVerificationContractSummary | null;
  policyContract: PlanPolicyContractSummary | null;
  sourceRanking: PlanSourceRankingEntrySummary[];
  retainedWidgetState: PlanRetainedWidgetStateSummary | null;
}

export interface PlanWeatherRequestFrameSummary {
  kind: "weather";
  inferredLocations: string[];
  assumedLocation: string | null;
  temporalScope: string | null;
  missingSlots: string[];
  clarificationRequiredSlots: string[];
}

export interface PlanSportsRequestFrameSummary {
  kind: "sports";
  league: string | null;
  teamOrTarget: string | null;
  dataScope: string | null;
  missingSlots: string[];
  clarificationRequiredSlots: string[];
}

export interface PlanPlacesRequestFrameSummary {
  kind: "places";
  searchAnchor: string | null;
  category: string | null;
  locationScope: string | null;
  missingSlots: string[];
  clarificationRequiredSlots: string[];
}

export interface PlanRecipeRequestFrameSummary {
  kind: "recipe";
  dish: string | null;
  servings: string | null;
  missingSlots: string[];
  clarificationRequiredSlots: string[];
}

export interface PlanMessageComposeRequestFrameSummary {
  kind: "message_compose";
  channel: string | null;
  recipientContext: string | null;
  purpose: string | null;
  missingSlots: string[];
  clarificationRequiredSlots: string[];
}

export interface PlanUserInputRequestFrameSummary {
  kind: "user_input";
  interactionKind: string | null;
  explicitOptionsPresent: boolean;
  missingSlots: string[];
  clarificationRequiredSlots: string[];
}

export type PlanNormalizedRequestFrameSummary =
  | PlanWeatherRequestFrameSummary
  | PlanSportsRequestFrameSummary
  | PlanPlacesRequestFrameSummary
  | PlanRecipeRequestFrameSummary
  | PlanMessageComposeRequestFrameSummary
  | PlanUserInputRequestFrameSummary;

export interface PlanRetainedLaneStateSummary {
  activeLane: PlanLaneFamily;
  activeToolWidgetFamily: string | null;
  activeArtifactId: string | null;
  unresolvedClarificationQuestion: string | null;
  selectedProviderFamily: string | null;
  selectedProviderRouteLabel: string | null;
  selectedSourceFamily: PlanSourceFamily | null;
}

export interface PlanLaneTransitionSummary {
  transitionKind: PlanLaneTransitionKind;
  fromLane: PlanLaneFamily | null;
  toLane: PlanLaneFamily;
  reason: string;
  evidence: string[];
}

export interface PlanObjectiveStateSummary {
  objectiveId: string;
  title: string;
  status: PlanWorkStatus;
  successCriteria: string[];
}

export interface PlanTaskUnitStateSummary {
  taskId: string;
  label: string;
  status: PlanWorkStatus;
  laneFamily: PlanLaneFamily;
  dependsOn: string[];
  summary: string | null;
}

export interface PlanCheckpointStateSummary {
  checkpointId: string;
  label: string;
  status: PlanWorkStatus;
  summary: string;
}

export interface PlanCompletionInvariantSummary {
  summary: string;
  satisfied: boolean;
  outstandingRequirements: string[];
}

export interface PlanOrchestrationStateSummary {
  objective: PlanObjectiveStateSummary | null;
  tasks: PlanTaskUnitStateSummary[];
  checkpoints: PlanCheckpointStateSummary[];
  completionInvariant: PlanCompletionInvariantSummary | null;
}

export interface PlanRouteDecisionSummary {
  routeFamily: PlanRouteFamily;
  directAnswerAllowed: boolean;
  directAnswerBlockers: string[];
  currentnessOverride: boolean;
  connectorCandidateCount: number;
  selectedProviderFamily: string | null;
  selectedProviderRouteLabel: string | null;
  connectorFirstPreference: boolean;
  narrowToolPreference: boolean;
  fileOutputIntent: boolean;
  artifactOutputIntent: boolean;
  inlineVisualIntent: boolean;
  skillPrepRequired: boolean;
  outputIntent: PlanOutputIntent;
  effectiveToolSurface: PlanEffectiveToolSurfaceSummary;
  laneFrame: PlanLaneFrameSummary | null;
  requestFrame: PlanNormalizedRequestFrameSummary | null;
  sourceSelection: PlanSourceSelectionSummary | null;
  retainedLaneState: PlanRetainedLaneStateSummary | null;
  laneTransitions: PlanLaneTransitionSummary[];
  orchestrationState: PlanOrchestrationStateSummary | null;
  domainPolicyBundle: PlanDomainPolicyBundleSummary | null;
}

export interface PlanSummary {
  selectedRoute: string;
  routeFamily: PlanRouteFamily;
  topology: PlanRouteTopology;
  plannerAuthority: PlanPlannerAuthority;
  status: string;
  currentStage: string | null;
  progressSummary: string | null;
  pauseSummary: string | null;
  workerCount: number;
  branchCount: number;
  evidenceCount: number;
  activeWorkerLabel: string | null;
  activeWorkerRole: string | null;
  verifierState: PlanVerifierState;
  verifierRole: PlanVerifierRole | null;
  verifierOutcome: PlanVerifierOutcome | null;
  approvalState: PlanApprovalState;
  selectedSkills: PlanSelectedSkill[];
  prepSummary: string | null;
  artifactGeneration: PlanArtifactGenerationSummary | null;
  computerUsePerception: PlanComputerUsePerceptionSummary | null;
  researchVerification: PlanResearchVerificationSummary | null;
  artifactQuality: PlanArtifactQualitySummary | null;
  computerUseVerification: PlanComputerUseVerificationSummary | null;
  codingVerification: PlanCodingVerificationSummary | null;
  patchSynthesis: PlanPatchSynthesisSummary | null;
  artifactRepair: PlanArtifactRepairSummary | null;
  computerUseRecovery: PlanComputerUseRecoverySummary | null;
  policyBindings: string[];
  routeDecision?: PlanRouteDecisionSummary | null;
}

export type ArtifactHubViewKey =
  | "active_context"
  | "doctor"
  | "compact"
  | "branch"
  | "commit"
  | "review"
  | "pr_comments"
  | "mobile"
  | "voice"
  | "server"
  | "repl"
  | "export"
  | "share"
  | "remote_env"
  | "mcp"
  | "plugins"
  | "vim"
  | "privacy"
  | "keybindings"
  | "hooks"
  | "permissions"
  | "rewind"
  | "tasks"
  | "replay"
  | "compare"
  | "thoughts"
  | "substrate"
  | "sources"
  | "kernel_logs"
  | "security_policy"
  | "files"
  | "revisions"
  | "screenshots";

export interface RunPresentation {
  prompt: ChatMessage | null;
  finalAnswer: AnswerPresentation | null;
  sourceSummary: SourceSummary | null;
  thoughtSummary: ThoughtSummary | null;
  planSummary: PlanSummary | null;
  activitySummary: ActivitySummary;
  activityGroups: ActivityGroup[];
  artifactRefs: ArtifactRef[];
}

export interface ExportBundleManifest {
  schema_version: number;
  exported_at_utc: string;
  thread_id: string;
  answer_present: boolean;
  event_count: number;
  artifact_count: number;
  included_artifact_payloads: boolean;
  files: string[];
}
