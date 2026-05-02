import type { ChatMessage } from "./base";
import type { ChatRendererKind } from "./chat-artifacts";
import type { AgentEvent } from "./events";
import type { ArtifactRef } from "./generated";

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
  | "command"
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
  | "command_execution"
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
  degradationReason: string | null;
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
  laneRequest: PlanLaneFrameSummary | null;
  normalizedRequest: PlanNormalizedRequestFrameSummary | null;
  sourceDecision: PlanSourceSelectionSummary | null;
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
  | "process"
  | "tools"
  | "runtime_details"
  | "trace_export"
  | "active_context"
  | "capability_inventory"
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

export type {
  ArtifactOperatorPhase,
  ArtifactOperatorRun,
  ArtifactOperatorRunMode,
  ArtifactOperatorRunStatus,
  ArtifactOperatorStep,
  ArtifactSourcePack,
  ArtifactSourceReference,
  ArtifactVerificationOutcome,
  ArtifactVerificationRef,
  ChatArtifactSession,
  ChatVerifiedReply,
} from "./chat-artifacts";
