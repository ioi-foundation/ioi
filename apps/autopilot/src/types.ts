// apps/autopilot/src/types.ts

// Import Graph Types from the shared package
import type {
  Node,
  Edge,
  NodeLogic,
  FirewallPolicy,
  GraphGlobalConfig,
  AgentConfiguration,
} from "@ioi/agent-ide";

// Re-export for local consumption if needed, or update imports in Autopilot components
export type {
  Node,
  Edge,
  NodeLogic,
  FirewallPolicy,
  GraphGlobalConfig,
  AgentConfiguration,
};

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

export interface StudioArtifactNavigatorNode {
  id: string;
  label: string;
  kind: string;
  description?: string | null;
  badge?: string | null;
  status?: string | null;
  lens?: string | null;
  path?: string | null;
  children: StudioArtifactNavigatorNode[];
}

export interface StudioArtifactMaterializationFileWrite {
  path: string;
  kind: string;
  contentPreview?: string | null;
}

export interface StudioArtifactMaterializationCommandIntent {
  id: string;
  kind: string;
  label: string;
  command: string;
}

export interface StudioArtifactMaterializationPreviewIntent {
  label: string;
  url?: string | null;
  status: string;
}

export interface StudioArtifactMaterializationVerificationStep {
  id: string;
  label: string;
  kind: string;
  status: string;
}

export type StudioArtifactPipelineStage =
  | "intake"
  | "routing"
  | "requirements"
  | "specification"
  | "materialization"
  | "execution"
  | "verification"
  | "presentation"
  | "reply";

export interface StudioArtifactPipelineStep {
  id: string;
  stage: StudioArtifactPipelineStage;
  label: string;
  status: string;
  summary: string;
  outputs: string[];
  verificationGate?: string | null;
}

export type StudioArtifactEditMode = "create" | "patch" | "replace" | "branch";

export type StudioArtifactJudgeClassification =
  | "pass"
  | "repairable"
  | "blocked";

export type StudioArtifactOutputOrigin =
  | "live_inference"
  | "mock_inference"
  | "deterministic_fallback"
  | "fixture_runtime"
  | "inference_unavailable"
  | "opaque_runtime";

export type StudioRuntimeProvenanceKind =
  | "real_remote_model_runtime"
  | "real_local_runtime"
  | "fixture_runtime"
  | "mock_runtime"
  | "deterministic_continuity_fallback"
  | "inference_unavailable"
  | "opaque_runtime";

export interface StudioRuntimeProvenance {
  kind: StudioRuntimeProvenanceKind;
  label: string;
  model?: string | null;
  endpoint?: string | null;
}

export type StudioArtifactFailureKind =
  | "inference_unavailable"
  | "routing_failure"
  | "generation_failure"
  | "verification_failure";

export interface StudioArtifactFailure {
  kind: StudioArtifactFailureKind;
  code: string;
  message: string;
}

export type StudioArtifactUxLifecycle =
  | "draft"
  | "refining"
  | "judged"
  | "locked";

export interface StudioArtifactSelectionTarget {
  sourceSurface: string;
  path?: string | null;
  label: string;
  snippet: string;
}

export interface StudioArtifactTasteMemory {
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

export interface StudioArtifactExemplar {
  recordId: number;
  title: string;
  summary: string;
  renderer: StudioRendererKind;
  scaffoldFamily: string;
  thesis: string;
  qualityRationale: string;
  scoreTotal: number;
  designCues: string[];
  componentPatterns: string[];
  antiPatterns: string[];
  sourceRevisionId?: string | null;
}

export interface StudioArtifactBrief {
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
}

export type StudioArtifactSkillNeedKind =
  | "visual_art_direction"
  | "editorial_layout"
  | "motion_hierarchy"
  | "interaction_copy_discipline"
  | "accessibility_review"
  | "data_storytelling";

export type StudioArtifactSkillNeedPriority = "required" | "recommended";

export interface StudioArtifactSkillNeed {
  kind: StudioArtifactSkillNeedKind;
  priority: StudioArtifactSkillNeedPriority;
  rationale: string;
}

export interface StudioArtifactSectionPlan {
  id: string;
  role: string;
  visiblePurpose: string;
  contentRequirements: string[];
  interactionHooks: string[];
  firstPaintRequirements: string[];
}

export interface StudioArtifactInteractionPlan {
  id: string;
  family: string;
  sourceControls: string[];
  targetSurfaces: string[];
  defaultState: string;
  requiredFirstPaintAffordances: string[];
}

export interface StudioArtifactEvidencePlanEntry {
  id: string;
  kind: string;
  purpose: string;
  conceptBindings: string[];
  firstPaintElements: string[];
  detailTargets: string[];
}

export interface StudioArtifactDesignSystem {
  colorStrategy: string;
  typographyStrategy: string;
  density: string;
  motionStyle: string;
  emphasisModes: string[];
}

export interface StudioArtifactComponentPlanEntry {
  id: string;
  componentFamily: string;
  role: string;
  sectionIds: string[];
  interactionIds: string[];
}

export interface StudioArtifactAccessibilityPlan {
  obligations: string[];
  focusOrder: string[];
  ariaExpectations: string[];
}

export interface StudioArtifactAcceptanceTargets {
  minimumSectionCount: number;
  minimumInteractiveRegions: number;
  requireFirstPaintEvidence: boolean;
  requirePersistentDetailRegion: boolean;
  requireDistinctTypography: boolean;
  requireKeyboardAffordances: boolean;
}

export interface StudioArtifactBlueprint {
  version: number;
  renderer: StudioRendererKind;
  narrativeArc: string;
  sectionPlan: StudioArtifactSectionPlan[];
  interactionPlan: StudioArtifactInteractionPlan[];
  evidencePlan: StudioArtifactEvidencePlanEntry[];
  designSystem: StudioArtifactDesignSystem;
  componentPlan: StudioArtifactComponentPlanEntry[];
  accessibilityPlan: StudioArtifactAccessibilityPlan;
  acceptanceTargets: StudioArtifactAcceptanceTargets;
  scaffoldFamily: string;
  variationStrategy: string;
  skillNeeds: StudioArtifactSkillNeed[];
}

export interface StudioArtifactIRNode {
  id: string;
  kind: string;
  parentId?: string | null;
  sectionId?: string | null;
  label: string;
  bindings: string[];
}

export interface StudioArtifactIRInteractionEdge {
  id: string;
  family: string;
  controlNodeIds: string[];
  targetNodeIds: string[];
  defaultState: string;
}

export interface StudioArtifactIREvidenceSurface {
  id: string;
  kind: string;
  sectionId: string;
  boundConcepts: string[];
  firstPaintExpectations: string[];
}

export interface StudioArtifactDesignToken {
  name: string;
  category: string;
  value: string;
}

export interface StudioArtifactIR {
  version: number;
  renderer: StudioRendererKind;
  scaffoldFamily: string;
  semanticStructure: StudioArtifactIRNode[];
  interactionGraph: StudioArtifactIRInteractionEdge[];
  evidenceSurfaces: StudioArtifactIREvidenceSurface[];
  designTokens: StudioArtifactDesignToken[];
  motionPlan: string[];
  accessibilityObligations: string[];
  responsiveLayoutRules: string[];
  componentBindings: string[];
  staticAuditExpectations: string[];
  renderEvalChecklist: string[];
}

export interface StudioArtifactSelectedSkill {
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
  matchedNeedKinds: StudioArtifactSkillNeedKind[];
  matchRationale: string;
  guidanceMarkdown?: string | null;
}

export interface StudioArtifactEditIntent {
  mode: StudioArtifactEditMode;
  summary: string;
  patchExistingArtifact: boolean;
  preserveStructure: boolean;
  targetScope: string;
  targetPaths: string[];
  requestedOperations: string[];
  toneDirectives: string[];
  selectedTargets: StudioArtifactSelectionTarget[];
  styleDirectives: string[];
  branchRequested: boolean;
}

export interface StudioArtifactJudgeResult {
  classification: StudioArtifactJudgeClassification;
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
  rationale: string;
}

export interface StudioArtifactCandidateSummary {
  candidateId: string;
  seed: number;
  model: string;
  temperature: number;
  strategy: string;
  origin: StudioArtifactOutputOrigin;
  provenance?: StudioRuntimeProvenance | null;
  summary: string;
  renderablePaths: string[];
  selected: boolean;
  fallback: boolean;
  failure?: string | null;
  rawOutputPreview?: string | null;
  convergence?: StudioArtifactCandidateConvergenceTrace | null;
  judge: StudioArtifactJudgeResult;
}

export interface StudioArtifactCandidateConvergenceTrace {
  lineageRootId: string;
  parentCandidateId?: string | null;
  passKind: string;
  passIndex: number;
  scoreTotal: number;
  scoreDeltaFromParent?: number | null;
  terminatedReason?: string | null;
}

export interface StudioArtifactMaterializationContract {
  version: number;
  requestKind: string;
  normalizedIntent: string;
  summary: string;
  artifactBrief?: StudioArtifactBrief | null;
  blueprint?: StudioArtifactBlueprint | null;
  artifactIr?: StudioArtifactIR | null;
  selectedSkills: StudioArtifactSelectedSkill[];
  retrievedExemplars: StudioArtifactExemplar[];
  editIntent?: StudioArtifactEditIntent | null;
  candidateSummaries: StudioArtifactCandidateSummary[];
  winningCandidateId?: string | null;
  winningCandidateRationale?: string | null;
  judge?: StudioArtifactJudgeResult | null;
  outputOrigin?: StudioArtifactOutputOrigin | null;
  productionProvenance?: StudioRuntimeProvenance | null;
  acceptanceProvenance?: StudioRuntimeProvenance | null;
  fallbackUsed: boolean;
  uxLifecycle?: StudioArtifactUxLifecycle | null;
  failure?: StudioArtifactFailure | null;
  navigatorNodes: StudioArtifactNavigatorNode[];
  fileWrites: StudioArtifactMaterializationFileWrite[];
  commandIntents: StudioArtifactMaterializationCommandIntent[];
  previewIntent?: StudioArtifactMaterializationPreviewIntent | null;
  verificationSteps: StudioArtifactMaterializationVerificationStep[];
  pipelineSteps: StudioArtifactPipelineStep[];
  notes: string[];
}

export interface StudioBuildReceipt {
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

export interface StudioCodeWorkerLease {
  backend: string;
  plannerAuthority: string;
  allowedMutationScope: string[];
  allowedCommandClasses: string[];
  executionState: string;
  retryClassification?: string | null;
  lastSummary?: string | null;
}

export type StudioOutcomeKind =
  | "conversation"
  | "tool_widget"
  | "visualizer"
  | "artifact";

export type StudioArtifactClass =
  | "document"
  | "visual"
  | "interactive_single_file"
  | "downloadable_file"
  | "workspace_project"
  | "compound_bundle"
  | "code_patch"
  | "report_bundle";

export type StudioArtifactDeliverableShape =
  | "single_file"
  | "file_set"
  | "workspace_project";

export type StudioRendererKind =
  | "markdown"
  | "html_iframe"
  | "jsx_sandbox"
  | "svg"
  | "mermaid"
  | "pdf_embed"
  | "download_card"
  | "workspace_surface"
  | "bundle_manifest";

export type StudioPresentationSurface =
  | "inline"
  | "side_panel"
  | "overlay"
  | "tabbed_panel";

export type StudioArtifactPersistenceMode =
  | "ephemeral"
  | "artifact_scoped"
  | "shared_artifact_scoped"
  | "workspace_filesystem";

export type StudioExecutionSubstrate =
  | "none"
  | "client_sandbox"
  | "binary_generator"
  | "workspace_runtime";

export type StudioArtifactTabKind =
  | "render"
  | "source"
  | "download"
  | "evidence"
  | "workspace";

export type StudioArtifactFileRole =
  | "primary"
  | "source"
  | "export"
  | "supporting";

export type StudioArtifactVerificationStatus =
  | "ready"
  | "blocked"
  | "failed"
  | "partial";

export type StudioArtifactLifecycleState =
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

export interface StudioOutcomeArtifactScope {
  targetProject?: string | null;
  createNewWorkspace: boolean;
  mutationBoundary: string[];
}

export interface StudioOutcomeArtifactVerificationRequest {
  requireRender: boolean;
  requireBuild: boolean;
  requirePreview: boolean;
  requireExport: boolean;
  requireDiffReview: boolean;
}

export interface StudioOutcomeArtifactRequest {
  artifactClass: StudioArtifactClass;
  deliverableShape: StudioArtifactDeliverableShape;
  renderer: StudioRendererKind;
  presentationSurface: StudioPresentationSurface;
  persistence: StudioArtifactPersistenceMode;
  executionSubstrate: StudioExecutionSubstrate;
  workspaceRecipeId?: string | null;
  presentationVariantId?: string | null;
  scope: StudioOutcomeArtifactScope;
  verification: StudioOutcomeArtifactVerificationRequest;
}

export interface StudioOutcomeRequest {
  requestId: string;
  rawPrompt: string;
  activeArtifactId?: string | null;
  outcomeKind: StudioOutcomeKind;
  confidence: number;
  needsClarification: boolean;
  clarificationQuestions: string[];
  artifact?: StudioOutcomeArtifactRequest | null;
}

export interface StudioOutcomePlanningPayload {
  outcomeKind: StudioOutcomeKind;
  confidence: number;
  needsClarification: boolean;
  clarificationQuestions: string[];
  artifact?: StudioOutcomeArtifactRequest | null;
}

export interface StudioArtifactManifestTab {
  id: string;
  label: string;
  kind: StudioArtifactTabKind;
  renderer?: StudioRendererKind | null;
  filePath?: string | null;
  lens?: string | null;
}

export interface StudioArtifactManifestFile {
  path: string;
  mime: string;
  role: StudioArtifactFileRole;
  renderable: boolean;
  downloadable: boolean;
  artifactId?: string | null;
  externalUrl?: string | null;
}

export interface StudioArtifactManifestVerification {
  status: StudioArtifactVerificationStatus;
  lifecycleState: StudioArtifactLifecycleState;
  summary: string;
  productionProvenance?: StudioRuntimeProvenance | null;
  acceptanceProvenance?: StudioRuntimeProvenance | null;
  failure?: StudioArtifactFailure | null;
}

export interface StudioArtifactManifestStorage {
  mode: StudioArtifactPersistenceMode;
  apiLabel?: string | null;
}

export interface StudioArtifactManifest {
  artifactId: string;
  title: string;
  artifactClass: StudioArtifactClass;
  renderer: StudioRendererKind;
  primaryTab: string;
  tabs: StudioArtifactManifestTab[];
  files: StudioArtifactManifestFile[];
  verification: StudioArtifactManifestVerification;
  storage?: StudioArtifactManifestStorage | null;
}

export interface StudioVerifiedReply {
  status: StudioArtifactVerificationStatus;
  lifecycleState: StudioArtifactLifecycleState;
  title: string;
  summary: string;
  evidence: string[];
  productionProvenance?: StudioRuntimeProvenance | null;
  acceptanceProvenance?: StudioRuntimeProvenance | null;
  failure?: StudioArtifactFailure | null;
  updatedAt: string;
}

export interface StudioRendererSession {
  sessionId: string;
  studioSessionId: string;
  renderer: StudioRendererKind;
  workspaceRoot: string;
  entryDocument: string;
  previewUrl?: string | null;
  previewProcessId?: number | null;
  scaffoldRecipeId?: string | null;
  presentationVariantId?: string | null;
  packageManager?: string | null;
  status: string;
  verificationStatus: string;
  receipts: StudioBuildReceipt[];
  currentWorkerExecution?: StudioCodeWorkerLease | null;
  currentTab: string;
  availableTabs: string[];
  readyTabs: string[];
  retryCount: number;
  lastFailureSummary?: string | null;
}

export interface StudioArtifactRevision {
  revisionId: string;
  parentRevisionId?: string | null;
  branchId: string;
  branchLabel: string;
  prompt: string;
  createdAt: string;
  uxLifecycle: StudioArtifactUxLifecycle;
  artifactManifest: StudioArtifactManifest;
  artifactBrief?: StudioArtifactBrief | null;
  blueprint?: StudioArtifactBlueprint | null;
  artifactIr?: StudioArtifactIR | null;
  selectedSkills: StudioArtifactSelectedSkill[];
  editIntent?: StudioArtifactEditIntent | null;
  candidateSummaries: StudioArtifactCandidateSummary[];
  winningCandidateId?: string | null;
  judge?: StudioArtifactJudgeResult | null;
  outputOrigin?: StudioArtifactOutputOrigin | null;
  productionProvenance?: StudioRuntimeProvenance | null;
  acceptanceProvenance?: StudioRuntimeProvenance | null;
  failure?: StudioArtifactFailure | null;
  fileWrites: StudioArtifactMaterializationFileWrite[];
  tasteMemory?: StudioArtifactTasteMemory | null;
  retrievedExemplars: StudioArtifactExemplar[];
  selectedTargets: StudioArtifactSelectionTarget[];
}

export interface StudioArtifactSession {
  sessionId: string;
  threadId: string;
  artifactId: string;
  title: string;
  summary: string;
  currentLens: string;
  navigatorBackingMode: string;
  navigatorNodes: StudioArtifactNavigatorNode[];
  attachedArtifactIds: string[];
  availableLenses: string[];
  materialization: StudioArtifactMaterializationContract;
  outcomeRequest: StudioOutcomeRequest;
  artifactManifest: StudioArtifactManifest;
  verifiedReply: StudioVerifiedReply;
  lifecycleState: StudioArtifactLifecycleState;
  status: string;
  activeRevisionId?: string | null;
  revisions: StudioArtifactRevision[];
  tasteMemory?: StudioArtifactTasteMemory | null;
  retrievedExemplars: StudioArtifactExemplar[];
  selectedTargets: StudioArtifactSelectionTarget[];
  uxLifecycle?: StudioArtifactUxLifecycle | null;
  createdAt: string;
  updatedAt: string;
  buildSessionId?: string | null;
  workspaceRoot?: string | null;
  rendererSessionId?: string | null;
}

export interface BuildArtifactSession {
  sessionId: string;
  studioSessionId: string;
  workspaceRoot: string;
  entryDocument: string;
  previewUrl?: string | null;
  previewProcessId?: number | null;
  scaffoldRecipeId: string;
  presentationVariantId?: string | null;
  packageManager: string;
  buildStatus: string;
  verificationStatus: string;
  receipts: StudioBuildReceipt[];
  currentWorkerExecution: StudioCodeWorkerLease;
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

export interface GmailThreadMessageDetail {
  id: string;
  from?: string;
  to?: string;
  subject?: string;
  date?: string;
  snippet?: string;
  rfcMessageId?: string;
  references?: string;
  labelIds: string[];
}

export interface GmailThreadDetail {
  threadId: string;
  historyId?: string;
  snippet?: string;
  messages: GmailThreadMessageDetail[];
}

export interface CalendarAttendeeDetail {
  email?: string;
  displayName?: string;
  responseStatus?: string;
  organizer?: boolean;
}

export interface CalendarEventDetail {
  calendarId: string;
  eventId: string;
  summary?: string;
  description?: string;
  location?: string;
  status?: string;
  start?: string;
  end?: string;
  htmlLink?: string;
  attendees: CalendarAttendeeDetail[];
}

export type AssistantWorkbenchSession =
  | {
      kind: "gmail_reply";
      connectorId: string;
      thread: GmailThreadDetail;
      sourceNotificationId?: string | null;
    }
  | {
      kind: "meeting_prep";
      connectorId: string;
      event: CalendarEventDetail;
      sourceNotificationId?: string | null;
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

export interface GateInfo {
  title: string;
  description: string;
  risk: "low" | "medium" | "high";
  approve_label?: string;
  deny_label?: string;
  deadline_ms?: number;
  surface_label?: string;
  scope_label?: string;
  operation_label?: string;
  target_label?: string;
  operator_note?: string;
  pii?: PiiReviewInfo;
}

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

export interface CredentialRequest {
  kind: string;
  prompt: string;
  one_time?: boolean;
}

export interface ClarificationOption {
  id: string;
  label: string;
  description: string;
  recommended?: boolean;
}

export interface ClarificationRequest {
  kind: string;
  question: string;
  tool_name?: string;
  failure_class?: string;
  evidence_snippet?: string;
  context_hint?: string;
  options: ClarificationOption[];
  allow_other?: boolean;
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
  credential_request?: CredentialRequest;
  clarification_request?: ClarificationRequest;
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
  reopenStudioOnLaunch: boolean;
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
  controlPlane: LocalEngineControlPlane;
  stagedOperations: LocalEngineStagedOperation[];
}

export interface SessionSummary {
  session_id: string;
  title: string;
  timestamp: number;
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
  | "computer_use"
  | "artifacts";

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
  | "artifact_quality_verifier";

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
  selectedSkills: string[];
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
}

export type ArtifactHubViewKey =
  | "active_context"
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
