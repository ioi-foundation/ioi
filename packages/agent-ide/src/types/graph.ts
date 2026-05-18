// packages/agent-ide/src/types/graph.ts

// ============================================
// Node Configuration Schemas
// ============================================

export interface WorkflowTestAssertion {
  kind: "node_exists" | "schema_matches" | "output_contains" | "custom";
  expected?: unknown;
  expression?: string;
}

export interface WorkflowSkillContextPinnedSkill {
  skillHash?: string;
  name?: string;
  required?: boolean;
}

export interface WorkflowSkillContextConfig {
  mode: "discover" | "pinned";
  goalSource?: "workflow_goal" | "node_input" | "static";
  goal?: string;
  minScoreBps?: number;
  maxSkills?: number;
  onNoMatch?: "warn" | "block";
  allowDraftForBenchmark?: boolean;
  pinnedSkills?: WorkflowSkillContextPinnedSkill[];
  onMissingPinned?: "warn" | "block";
  includeMarkdown?: boolean;
  guidanceMaxChars?: number;
}

export interface WorkflowSkillContextSelectedSkill {
  skillHash: string;
  name: string;
  description: string;
  lifecycleState: string;
  sourceType: string;
  stale: boolean;
  relativePath?: string | null;
  score: number;
  guidanceHash: string;
  guidanceMarkdown?: string;
}

export interface WorkflowSkillContextArtifact {
  schemaVersion: "workflow.skill-context.v1";
  status: "attached" | "unavailable" | "blocked";
  mode: "discover" | "pinned";
  goal?: string;
  selectedSkills: WorkflowSkillContextSelectedSkill[];
  promptContext: string;
  evidenceRefs: string[];
}

export interface WorkflowSkillCatalogEntry {
  skillHash: string;
  name: string;
  description: string;
  lifecycleState: string;
  sourceType: string;
  successRateBps?: number;
  sampleSize?: number;
  relativePath?: string | null;
  stale: boolean;
  markdown?: string | null;
  sourceId?: string | null;
  sourceLabel?: string | null;
  sourceUri?: string | null;
  contentHash?: string | null;
  importedAtMs?: number | null;
  license?: string | null;
  phaseTags?: WorkflowCodingRoutePhaseId[];
  routeTags?: WorkflowCodingRouteId[];
  promotionEvidenceRefs?: string[];
}

export type WorkflowCodingRouteId =
  | "coding.template.build"
  | "coding.template.debug"
  | "coding.template.review"
  | "coding.template.ship"
  | string;

export type WorkflowCodingRoutePhaseId =
  | "coding.intake"
  | "coding.context"
  | "coding.define"
  | "coding.plan"
  | "coding.build"
  | "coding.verify"
  | "coding.review"
  | "coding.ship"
  | "coding.closeout"
  | string;

export type WorkflowCodingRouteEvidenceKind =
  | "coding.route.classification.v1"
  | "coding.route.phase.start.v1"
  | "coding.route.phase.complete.v1"
  | "coding.route.skill_selection.v1"
  | "coding.route.gate.v1"
  | "coding.route.benchmark.v1"
  | "coding.route.promotion.v1";

export type WorkflowCodingRouteGateStatus =
  | "pass"
  | "warn"
  | "block"
  | "skipped";

export interface WorkflowCodingRoutePhase {
  phaseId: WorkflowCodingRoutePhaseId;
  label: string;
  componentKind:
    | "context"
    | "planner"
    | "builder"
    | "verifier"
    | "reviewer"
    | "merge_verdict"
    | string;
  required: boolean;
  gateIds: string[];
}

export interface WorkflowCodingRouteSkillSelector {
  mode: "discover" | "pinned";
  names?: string[];
  skillHashes?: string[];
  required?: boolean;
}

export interface WorkflowCodingRouteGate {
  gateId: string;
  label: string;
  phaseId: WorkflowCodingRoutePhaseId;
  evidenceKind: string;
  required: boolean;
  status?: WorkflowCodingRouteGateStatus | "pending";
  operatorOverrideAllowed?: boolean;
  blockingRequirements?: string[];
}

export interface WorkflowCodingRouteContract {
  schemaVersion: "workflow.coding-route.v1";
  routeId: WorkflowCodingRouteId;
  label: string;
  taskClass: "build" | "debug" | "review" | "ship" | string;
  riskLevel: "low" | "normal" | "high";
  phases: WorkflowCodingRoutePhaseId[];
  phaseDetails?: WorkflowCodingRoutePhase[];
  requiredSkillSelectors: WorkflowCodingRouteSkillSelector[];
  optionalSkillSelectors?: WorkflowCodingRouteSkillSelector[];
  evidenceRequirements: string[];
  gates: WorkflowCodingRouteGate[];
  skipRules?: string[];
  failureBehavior?: "warn" | "block";
}

export interface WorkflowCodingRouteGateResult {
  gateId: string;
  phaseId: WorkflowCodingRoutePhaseId;
  status: WorkflowCodingRouteGateStatus;
  reason: string;
  evidenceRefs: string[];
  blockingRequirements: string[];
  operatorOverrideAllowed: boolean;
  overrideEvidenceRefs: string[];
}

export interface WorkflowCodingRouteSkillSelection {
  skillHash: string;
  name: string;
  lifecycleState: string;
  phaseId: WorkflowCodingRoutePhaseId;
  routeId: WorkflowCodingRouteId;
  score: number;
  sourceType: string;
  stale: boolean;
  phaseTags: WorkflowCodingRoutePhaseId[];
  routeTags: WorkflowCodingRouteId[];
  evidenceRefs: string[];
}

export interface WorkflowCodingRouteBenchmarkResult {
  benchmarkId: string;
  routeId: WorkflowCodingRouteId;
  phaseId: WorkflowCodingRoutePhaseId;
  selectedSkillHash: string;
  skillLifecycleState: string;
  inputDescriptor: string;
  status: WorkflowCodingRouteGateStatus;
  gateStatus: WorkflowCodingRouteGateStatus;
  verifierResult?: string;
  confidenceBeforeBps: number;
  confidenceAfterBps: number;
  promotionDecision: string;
  evidenceRefs: string[];
  createdAtMs: number;
}

export interface WorkflowCodingRoutePromotionDecision {
  decisionId: string;
  skillHash: string;
  skillName: string;
  routeId: WorkflowCodingRouteId;
  phaseId: WorkflowCodingRoutePhaseId;
  fromLifecycleState: string;
  toLifecycleState: string;
  stale: boolean;
  confidenceBeforeBps: number;
  confidenceAfterBps: number;
  decision:
    | "promote"
    | "retain_promoted"
    | "demote"
    | "mark_stale"
    | "no_change"
    | string;
  reason: string;
  evidenceRefs: string[];
  createdAtMs: number;
}

export interface WorkflowCodingRouteRunSummary {
  schemaVersion: "workflow.coding-route-run-summary.v1";
  routeId: WorkflowCodingRouteId;
  routePreset: WorkflowCodingRouteId;
  currentPhase?: WorkflowCodingRoutePhaseId;
  completedPhases: WorkflowCodingRoutePhaseId[];
  selectedSkills: WorkflowCodingRouteSkillSelection[];
  gateResults: WorkflowCodingRouteGateResult[];
  benchmarkResults: WorkflowCodingRouteBenchmarkResult[];
  promotionDecisions: WorkflowCodingRoutePromotionDecision[];
  evidenceRefs: string[];
  createdAtMs: number;
}

export interface WorkflowCodingRouteEvidence {
  schemaVersion: "workflow.coding-route-evidence.v1";
  evidenceKind: WorkflowCodingRouteEvidenceKind;
  routeId: WorkflowCodingRouteId;
  phaseId?: WorkflowCodingRoutePhaseId;
  status: WorkflowCodingRouteGateStatus | "passed" | "blocked" | "warning";
  summary: string;
  evidenceRefs: string[];
  selectedSkillHashes?: string[];
  gateId?: string;
  phaseComponent?: string;
  gateResult?: WorkflowCodingRouteGateResult;
  skillSelections?: WorkflowCodingRouteSkillSelection[];
  benchmarkResults?: WorkflowCodingRouteBenchmarkResult[];
  promotionDecisions?: WorkflowCodingRoutePromotionDecision[];
  createdAtMs: number;
}

export interface WorkflowSkillPackImportRequest {
  uri: string;
  label?: string | null;
  draft?: boolean;
  provenance?: {
    sourceType?: "local_path" | "git" | "archive" | string;
    sourceRef?: string;
    notes?: string;
  };
}

export interface WorkflowSkillPackImportResult {
  sourceId: string;
  uri: string;
  label: string;
  status: "draft" | "synced" | "blocked" | string;
  discoveredSkillCount: number;
  draftSkills?: WorkflowSkillCatalogEntry[];
  provenance: {
    sourceType: string;
    sourceRef: string;
    importedAs: "draft" | string;
  };
  syncedAtMs?: number | null;
  message: string;
}

export interface WorkflowNodeViewMacro {
  macroId: string;
  macroLabel: string;
  role:
    | "input"
    | "model"
    | "memory"
    | "tool"
    | "parser"
    | "decision"
    | "gate"
    | "output";
  expandedFrom: "agent_loop_macro" | string;
}

export interface WorkflowHarnessGroupView {
  groupId: WorkflowHarnessPromotionClusterId | string;
  label: string;
  collapsed: boolean;
  innerNodeIds: string[];
  componentKinds: WorkflowHarnessComponentKind[];
  boundaryPorts: WorkflowPortDefinition[];
  statusRollup: {
    executionMode: WorkflowHarnessExecutionMode;
    readiness: WorkflowHarnessComponentReadiness | "mixed";
    liveReadyCount: number;
    shadowReadyCount: number;
    simulatedCount: number;
    projectionOnlyCount: number;
    blockedCount: number;
    warningCount: number;
    receiptKindCount: number;
    replayFixtureCount: number;
    replayGateStatus: WorkflowHarnessPromotionClusterReplayGateStatus;
    replayGateImpact: "pending" | "passed" | "blocked";
    replayGateTotalFixtures: number;
    replayGateBlockingFixtureCount: number;
    replayGateId?: string;
    divergenceCount: number;
    activationState?: WorkflowHarnessActivationState;
  };
  deepLinks: {
    groupId: string;
    componentIds: string[];
    receiptRefs: string[];
    replayFixtureRefs: string[];
    runId?: string;
  };
}

export interface WorkflowFieldMapping {
  source: string;
  path: string;
  type?: string;
}

export interface WorkflowRuntimeUiStringEntry {
  defaultMessage: string;
  description: string;
  translations?: Record<string, string>;
}

export interface WorkflowRuntimeUiStringCatalog {
  schemaVersion: string;
  catalogId: string;
  scope: "workflow_chrome" | "runtime_chrome" | string;
  defaultLocale: string;
  supportedLocales: string[];
  modelOutputLocalized: boolean;
  modelOutputBoundary?: string;
  strings: Record<string, WorkflowRuntimeUiStringEntry>;
}

export interface WorkflowRuntimeNodeLocalization {
  catalogId: string;
  localeKey: string;
  labelKey: string;
  ariaLabelKey: string;
  statusAnnouncementKey: string;
  modelOutputLocalized: boolean;
}

export interface WorkflowRuntimeNodeAccessibility {
  ariaLabelKey: string;
  statusAnnouncementKey: string;
  accessibleStatusField: string;
  statusTextByValue: Record<string, string>;
  colorIndependentStatus: boolean;
}

export interface NodeLogic {
  // --- Source / output ---
  payload?: unknown;
  sourceKind?: "manual" | "file" | "media" | "dataset" | "api_payload";
  sourcePath?: string;
  fileExtension?: string;
  mediaKind?: "image" | "audio" | "video" | "document";
  sanitizeInput?: boolean;
  stripMetadata?: boolean;
  validateMime?: boolean;
  format?: string;
  path?: string;
  rendererRef?: WorkflowRendererRef;
  materialization?: WorkflowMaterializationConfig;
  deliveryTarget?: WorkflowDeliveryTarget;
  retentionPolicy?: WorkflowOutputRetentionPolicy;
  versioning?: WorkflowOutputVersioning;

  // --- Model Nodes ---
  modelRef?: string;
  modelCapabilityRef?: string;
  provider?: string;
  model?: string;
  modelId?: string | null;
  routeId?: string;
  reasoningEffort?: "low" | "medium" | "high" | "xhigh" | string;
  modelPolicy?: Record<string, unknown>;
  capability?:
    | "chat"
    | "responses"
    | "structured_output"
    | "embeddings"
    | "vision"
    | "rerank"
    | "mcp"
    | "receipt_gate";
  receiptRequired?: boolean;
  selectedEndpointId?: string;
  receiptId?: string;
  requiredToolReceiptIds?: string[];
  modelHash?: string;
  temperature?: number;
  systemPrompt?: string;
  prompt?: string;
  text?: string;
  modelBinding?: WorkflowModelBinding;
  toolUseMode?: "none" | "explicit" | "auto";
  parserRef?: string;
  parserBinding?: WorkflowParserBinding;
  memoryKey?: string;
  memoryScope?: "global" | "workspace" | "thread" | "workflow" | "subagent" | string;
  memoryInjectionEnabled?: boolean;
  memoryReadOnly?: boolean;
  memoryWriteRequiresApproval?: boolean;
  memorySubagentInheritance?: "none" | "explicit" | "read_only" | "full";
  memoryRetention?: string;
  memoryRedaction?: "none" | "redacted" | string;
  validateStructuredOutput?: boolean;
  jsonMode?: boolean;
  maxTokens?: number;
  stream?: boolean;

  // --- Tool Nodes ---
  endpoint?: string;
  method?: "GET" | "POST" | "PUT" | "DELETE";
  headers?: Record<string, string>;
  bodyTemplate?: string;
  timeoutMs?: number;

  // --- Dynamic MCP Tools ---
  tool_name?: string;
  mcpServerId?: string;
  mcpServerLabel?: string;
  mcpTransport?: "stdio" | "http" | "sse" | string;
  mcpServerUrl?: string;
  // HTTP/SSE auth headers should use vault:// refs; runtime status exposes hashes only.
  mcpServerHeadersJson?: string;
  mcpServerConfigJson?: string;
  mcpImportJson?: string;
  mcpConfigSourceMode?: "workspace_and_global" | "workspace" | "global" | string;
  mcpCatalogMode?: "summary" | "full" | string;
  mcpToolSearchQuery?: string;
  mcpToolCatalogPreviewLimit?: number;
  mcpServeEndpoint?: string;
  mcpServeAllowedToolsJson?: string;
  mcpToolName?: string;
  mcpToolInputJson?: string;
  mcpVaultHeaderRefsJson?: string;
  mcpContainmentMode?: "read_only" | "sandboxed" | "review_required" | string;
  mcpAllowNetworkEgress?: boolean;
  arguments?: Record<string, unknown>;
  toolBinding?: WorkflowToolBinding;

  // --- Runtime Subagents ---
  subagentId?: string;
  subagentRole?:
    | "general"
    | "explore"
    | "plan"
    | "review"
    | "implementer"
    | "verifier"
    | "custom"
    | "browser_operator"
    | "gui_operator"
    | "security_reviewer"
    | "policy_reviewer"
    | "workflow_designer"
    | "connector_author"
    | "model_router"
    | "receipt_auditor"
    | string;
  subagentPrompt?: string;
  subagentInput?: string;
  subagentParentTurnId?: string;
  subagentModelRoute?: string;
  subagentToolPack?: string;
  subagentForkContext?: boolean;
  subagentMaxConcurrency?: number;
  subagentWaitTimeoutMs?: number;
  subagentBudgetJson?: string;
  subagentBudgetUsageField?: string;
  subagentOutputContractJson?: string;
  subagentMergePolicy?:
    | "manual"
    | "manual_review"
    | "append"
    | "replace"
    | "merge"
    | "evidence_only"
    | string;
  subagentCancellationInheritance?:
    | "propagate"
    | "isolate"
    | "detach"
    | "manual"
    | string;

  // --- Code / Function ---
  language?: string;
  code?: string;
  functionBinding?: WorkflowFunctionBinding;

  // --- Flow Control ---
  routes?: string[];
  defaultRoute?: string;
  routerInstruction?: string;
  durationMs?: number; // Wait block
  retry?: {
    maxAttempts?: number;
    backoffMs?: number;
  };

  // --- Context ---
  variables?: Record<string, string>;
  skillContext?: WorkflowSkillContextConfig;
  skillEndpoint?: string;
  skillSource?: string;
  includeCursorImports?: boolean;
  requireSkillMd?: boolean;
  packSources?: string[];
  activationMode?: string;
  hookEndpoint?: string;
  eventKinds?: string[];
  failurePolicy?: string;
  authorityScopes?: string[];
  toolContracts?: string[];
  allowMutationWithoutContract?: boolean;
  requireAuthorityScopes?: boolean;
  dryRun?: boolean;
  previewOnly?: boolean;
  hookDryRunOnly?: boolean;
  requireHookDryRunPlan?: boolean;
  hookDryRunPlan?: unknown;
  hookExecutionEnabled?: boolean;
  hookCommandExecutionEnabled?: boolean;
  hookDryRunPlanField?: string;
  hookDryRunDecisionField?: string;
  hookPolicyDecisionField?: string;
  hookPolicyPassedRoute?: string;
  hookPolicyBlockedRoute?: string;
  hookInvocationLedger?: unknown;
  hookInvocationLedgerField?: string;
  hookInvocationStateField?: string;
  hookEscalationCountField?: string;
  hookEscalationDetailsField?: string;
  hookEscalationReceiptField?: string;

  // --- Triggers ---
  triggerKind?: "manual" | "scheduled" | "event";
  runtimeReady?: boolean;
  rssUrl?: string;
  cronSchedule?: string;
  eventSourceRef?: string;
  dedupeKey?: string;

  // --- State ---
  stateKey?: string;
  stateOperation?:
    | "read"
    | "write"
    | "append"
    | "merge"
    | "mcp_status"
    | "mcp_tool_search"
    | "mcp_tool_fetch"
    | "mcp_tool_invoke"
    | "mcp_import"
    | "mcp_add"
    | "mcp_serve"
    | "mcp_remove"
    | "mcp_enable"
    | "mcp_disable"
    | "memory_status"
    | "memory_policy"
    | "memory_search"
    | "memory_list"
    | "memory_remember"
    | "memory_edit"
    | "memory_delete"
    | "subagent_list"
    | "subagent_spawn"
    | "subagent_wait"
    | "subagent_result"
    | "subagent_send_input"
    | "subagent_cancel"
    | "subagent_cancel_propagation"
    | "subagent_resume"
    | "subagent_assign"
    | "usage_meter"
    | "context_budget"
    | "compaction_policy";
  reducer?: "replace" | "append" | "merge";
  initialValue?: unknown;
  memoryRecordId?: string;
  memoryText?: string;
  doctorEndpoint?: string;
  blockOnRequiredFailures?: boolean;
  allowOptionalDegraded?: boolean;
  redactionProfile?: string;
  nodeTypeLabel?: string;
  runtimeUiStringCatalogRef?: string;
  runtimeUiStringCatalog?: WorkflowRuntimeUiStringCatalog;
  workflowChromeLocale?: string;
  localeKey?: string;
  ariaLabelKey?: string;
  statusAnnouncementKey?: string;
  accessibleStatusField?: string;
  accessibleStatusText?: Record<string, string>;
  colorIndependentStatus?: boolean;
  runtimeTaskEndpoint?: string;
  runtimeTask?: unknown;
  runtimeTaskField?: string;
  runtimeTaskStatusField?: string;
  runtimeTaskCancelEndpoint?: string;
  runtimeTaskCancelable?: boolean;
  runtimeTaskCancelRoute?: string;
  runtimeTaskReceiptField?: string;
  runtimeJobEndpoint?: string;
  runtimeJob?: unknown;
  runtimeJobField?: string;
  runtimeJobStatusField?: string;
  runtimeJobLifecycleField?: string;
  runtimeJobQueueField?: string;
  runtimeJobCancelEndpoint?: string;
  runtimeJobCancelable?: boolean;
  runtimeJobCancelRoute?: string;
  runtimeJobReceiptField?: string;
  runtimeChecklistEndpoint?: string;
  runtimeChecklist?: unknown;
  runtimeChecklistField?: string;
  runtimeChecklistStatusField?: string;
  runtimeChecklistItemsField?: string;
  runtimeChecklistReceiptField?: string;
  runtimeThreadForkEndpoint?: string;
  runtimeThreadFork?: unknown;
  runtimeThreadForkField?: string;
  runtimeThreadForkEventField?: string;
  runtimeThreadForkStatusField?: string;
  runtimeThreadForkReceiptField?: string;
  runtimeThreadForkPolicyField?: string;
  runtimeThreadForkThreadId?: string;
  runtimeThreadForkThreadIdField?: string;
  runtimeThreadForkReason?: string;
  runtimeThreadForkReasonField?: string;
  runtimeThreadForkWorkflowNodeId?: string;
  runtimeThreadForkSource?: "react_flow" | "sdk_client" | "cli_tui" | string;
  runtimeThreadForkActor?: string;
  runtimeOperatorInterruptEndpoint?: string;
  runtimeOperatorInterrupt?: unknown;
  runtimeOperatorInterruptField?: string;
  runtimeOperatorInterruptEventField?: string;
  runtimeOperatorInterruptStatusField?: string;
  runtimeOperatorInterruptReceiptField?: string;
  runtimeOperatorInterruptPolicyField?: string;
  runtimeOperatorInterruptThreadId?: string;
  runtimeOperatorInterruptThreadIdField?: string;
  runtimeOperatorInterruptTurnId?: string;
  runtimeOperatorInterruptTurnIdField?: string;
  runtimeOperatorInterruptReason?: string;
  runtimeOperatorInterruptReasonField?: string;
  runtimeOperatorInterruptWorkflowNodeId?: string;
  runtimeOperatorInterruptSource?: "react_flow" | "sdk_client" | "cli_tui" | string;
  runtimeOperatorInterruptActor?: string;
  runtimeOperatorSteerEndpoint?: string;
  runtimeOperatorSteer?: unknown;
  runtimeOperatorSteerField?: string;
  runtimeOperatorSteerEventField?: string;
  runtimeOperatorSteerStatusField?: string;
  runtimeOperatorSteerReceiptField?: string;
  runtimeOperatorSteerPolicyField?: string;
  runtimeOperatorSteerThreadId?: string;
  runtimeOperatorSteerThreadIdField?: string;
  runtimeOperatorSteerTurnId?: string;
  runtimeOperatorSteerTurnIdField?: string;
  runtimeOperatorSteerGuidance?: string;
  runtimeOperatorSteerGuidanceField?: string;
  runtimeOperatorSteerWorkflowNodeId?: string;
  runtimeOperatorSteerSource?: "react_flow" | "sdk_client" | "cli_tui" | string;
  runtimeOperatorSteerActor?: string;
  runtimeThreadModeEndpoint?: string;
  runtimeThreadMode?: unknown;
  runtimeThreadModeField?: string;
  runtimeThreadModeEventField?: string;
  runtimeThreadModeStatusField?: string;
  runtimeThreadModeTrustField?: string;
  runtimeThreadModeReceiptField?: string;
  runtimeThreadModePolicyField?: string;
  runtimeThreadModeThreadId?: string;
  runtimeThreadModeThreadIdField?: string;
  runtimeThreadModeMode?: string;
  runtimeThreadModeModeField?: string;
  runtimeThreadModeApprovalMode?: string;
  runtimeThreadModeApprovalModeField?: string;
  runtimeThreadModeTrustProfile?: string;
  runtimeThreadModeTrustProfileField?: string;
  runtimeThreadModeWorkspaceTrustWorkflowNodeId?: string;
  runtimeThreadModeWorkspaceTrustWorkflowNodeIdField?: string;
  runtimeThreadModeRequestWarningAcknowledgement?: boolean;
  runtimeThreadModeRequestWarningAcknowledgementField?: string;
  runtimeThreadModeWorkflowNodeId?: string;
  runtimeThreadModeSource?: "react_flow" | "sdk_client" | "cli_tui" | string;
  runtimeThreadModeActor?: string;
  runtimeWorkspaceTrustGate?: unknown;
  runtimeWorkspaceTrustGateField?: string;
  runtimeWorkspaceTrustGateStatusField?: string;
  runtimeWorkspaceTrustGateWarningId?: string;
  runtimeWorkspaceTrustGateWarningIdField?: string;
  runtimeWorkspaceTrustGateWarningWorkflowNodeId?: string;
  runtimeWorkspaceTrustGateWarningWorkflowNodeIdField?: string;
  runtimeWorkspaceTrustGateModeNodeId?: string;
  runtimeWorkspaceTrustGateModeNodeIdField?: string;
  runtimeWorkspaceTrustGateSourceEventIdField?: string;
  runtimeWorkspaceTrustGateAcknowledgementEventField?: string;
  runtimeWorkspaceTrustGateReceiptField?: string;
  runtimeWorkspaceTrustGatePolicyField?: string;
  runtimeWorkspaceTrustGateRequireAcknowledgement?: boolean;
  runtimeWorkspaceTrustGateMode?: string;
  runtimeWorkspaceTrustGateModeField?: string;
  runtimeWorkspaceTrustGateWorkflowNodeId?: string;
  runtimeContextCompactEndpoint?: string;
  runtimeContextCompact?: unknown;
  runtimeContextCompactField?: string;
  runtimeContextCompactEventField?: string;
  runtimeContextCompactStatusField?: string;
  runtimeContextCompactReceiptField?: string;
  runtimeContextCompactPolicyField?: string;
  runtimeContextCompactThreadId?: string;
  runtimeContextCompactThreadIdField?: string;
  runtimeContextCompactTurnId?: string;
  runtimeContextCompactTurnIdField?: string;
  runtimeContextCompactReason?: string;
  runtimeContextCompactReasonField?: string;
  runtimeContextCompactScope?: string;
  runtimeContextCompactScopeField?: string;
  runtimeContextCompactWorkflowNodeId?: string;
  runtimeContextCompactSource?: "react_flow" | "sdk_client" | "cli_tui" | string;
  runtimeContextCompactActor?: string;
  runtimeApprovalRequestEndpoint?: string;
  runtimeApprovalRequest?: unknown;
  runtimeApprovalRequestField?: string;
  runtimeApprovalRequestEventField?: string;
  runtimeApprovalRequestStatusField?: string;
  runtimeApprovalRequestReceiptField?: string;
  runtimeApprovalRequestPolicyField?: string;
  runtimeApprovalRequestThreadId?: string;
  runtimeApprovalRequestThreadIdField?: string;
  runtimeApprovalRequestTurnId?: string;
  runtimeApprovalRequestTurnIdField?: string;
  runtimeApprovalRequestApprovalId?: string;
  runtimeApprovalRequestApprovalIdField?: string;
  runtimeApprovalRequestReason?: string;
  runtimeApprovalRequestReasonField?: string;
  runtimeApprovalRequestScope?: string;
  runtimeApprovalRequestScopeField?: string;
  runtimeApprovalRequestPressureStatus?: string;
  runtimeApprovalRequestPressureField?: string;
  runtimeApprovalRequestPressureStatusField?: string;
  runtimeApprovalRequestAlertId?: string;
  runtimeApprovalRequestAlertIdField?: string;
  runtimeApprovalRequestSourceEventId?: string;
  runtimeApprovalRequestSourceEventIdField?: string;
  runtimeApprovalRequestReceiptRefsField?: string;
  runtimeApprovalRequestPolicyDecisionRefsField?: string;
  runtimeApprovalRequestWorkflowNodeId?: string;
  runtimeApprovalRequestSource?: "react_flow" | "sdk_client" | "cli_tui" | string;
  runtimeApprovalRequestActor?: string;
  runtimeRollbackSnapshotEndpoint?: string;
  runtimeRollbackSnapshot?: unknown;
  runtimeRollbackSnapshotField?: string;
  runtimeRollbackSnapshotEventField?: string;
  runtimeRollbackSnapshotStatusField?: string;
  runtimeRollbackSnapshotReceiptField?: string;
  runtimeRollbackSnapshotPolicyField?: string;
  runtimeRollbackSnapshotThreadId?: string;
  runtimeRollbackSnapshotThreadIdField?: string;
  runtimeRollbackSnapshotWorkflowNodeId?: string;
  runtimeRollbackSnapshotSource?: "react_flow" | "sdk_client" | "cli_tui" | string;
  runtimeRollbackSnapshotActor?: string;
  runtimeRestoreGateEndpoint?: string;
  runtimeRestoreGate?: unknown;
  runtimeRestoreGateField?: string;
  runtimeRestoreGateEventField?: string;
  runtimeRestoreGateStatusField?: string;
  runtimeRestoreGateReceiptField?: string;
  runtimeRestoreGatePolicyField?: string;
  runtimeRestoreGateThreadId?: string;
  runtimeRestoreGateThreadIdField?: string;
  runtimeRestoreGateSnapshotId?: string;
  runtimeRestoreGateSnapshotIdField?: string;
  runtimeRestoreGateMode?: "preview" | "apply" | string;
  runtimeRestoreGateModeField?: string;
  runtimeRestoreGateConflictPolicy?: "block" | "allow_override" | string;
  runtimeRestoreGateConflictPolicyField?: string;
  runtimeRestoreGateApprovalGranted?: boolean;
  runtimeRestoreGateApprovalGrantedField?: string;
  runtimeRestoreGateWorkflowNodeId?: string;
  runtimeRestoreGateSource?: "react_flow" | "sdk_client" | "cli_tui" | string;
  runtimeRestoreGateActor?: string;
  runtimeDiagnosticsRepairEndpoint?: string;
  runtimeDiagnosticsRepair?: unknown;
  runtimeDiagnosticsRepairField?: string;
  runtimeDiagnosticsRepairEventField?: string;
  runtimeDiagnosticsRepairStatusField?: string;
  runtimeDiagnosticsRepairReceiptField?: string;
  runtimeDiagnosticsRepairPolicyField?: string;
  runtimeDiagnosticsRepairThreadId?: string;
  runtimeDiagnosticsRepairThreadIdField?: string;
  runtimeDiagnosticsRepairDecisionId?: string;
  runtimeDiagnosticsRepairDecisionIdField?: string;
  runtimeDiagnosticsRepairAction?:
    | "repair_retry"
    | "restore_preview"
    | "restore_apply"
    | "operator_override"
    | string;
  runtimeDiagnosticsRepairActionField?: string;
  runtimeDiagnosticsRepairMessage?: string;
  runtimeDiagnosticsRepairMessageField?: string;
  runtimeDiagnosticsRepairApprovalGranted?: boolean;
  runtimeDiagnosticsRepairApprovalGrantedField?: string;
  runtimeDiagnosticsRepairAllowConflicts?: boolean;
  runtimeDiagnosticsRepairAllowConflictsField?: string;
  runtimeDiagnosticsRepairWorkflowNodeId?: string;
  runtimeDiagnosticsRepairSource?: "react_flow" | "sdk_client" | "cli_tui" | string;
  runtimeDiagnosticsRepairActor?: string;
  runtimeCodingToolBudgetRecoveryEndpoint?: string;
  runtimeCodingToolBudgetRecovery?: unknown;
  runtimeCodingToolBudgetRecoveryField?: string;
  runtimeCodingToolBudgetRecoveryEventField?: string;
  runtimeCodingToolBudgetRecoveryStatusField?: string;
  runtimeCodingToolBudgetRecoveryReceiptField?: string;
  runtimeCodingToolBudgetRecoveryPolicyField?: string;
  runtimeCodingToolBudgetRecoveryPolicy?: unknown;
  runtimeCodingToolBudgetRecoveryPolicyInputField?: string;
  runtimeCodingToolBudgetRecoveryRunId?: string;
  runtimeCodingToolBudgetRecoveryRunIdField?: string;
  runtimeCodingToolBudgetRecoveryThreadId?: string;
  runtimeCodingToolBudgetRecoveryThreadIdField?: string;
  runtimeCodingToolBudgetRecoveryAction?:
    | "request_approval"
    | "approve_override"
    | "reject_override"
    | "retry_approved"
    | string;
  runtimeCodingToolBudgetRecoveryActionField?: string;
  runtimeCodingToolBudgetRecoveryApprovalId?: string;
  runtimeCodingToolBudgetRecoveryApprovalIdField?: string;
  runtimeCodingToolBudgetRecoverySourceEventId?: string;
  runtimeCodingToolBudgetRecoverySourceEventIdField?: string;
  runtimeCodingToolBudgetRecoveryBlockedEventId?: string;
  runtimeCodingToolBudgetRecoveryBlockedEventIdField?: string;
  runtimeCodingToolBudgetRecoveryApprovalRequestEventId?: string;
  runtimeCodingToolBudgetRecoveryApprovalRequestEventIdField?: string;
  runtimeCodingToolBudgetRecoveryApprovalDecisionEventId?: string;
  runtimeCodingToolBudgetRecoveryApprovalDecisionEventIdField?: string;
  runtimeCodingToolBudgetRecoveryTargetNodeIds?: string[] | string;
  runtimeCodingToolBudgetRecoveryTargetNodeIdsField?: string;
  runtimeCodingToolBudgetRecoveryReason?: string;
  runtimeCodingToolBudgetRecoveryReasonField?: string;
  runtimeCodingToolBudgetRecoveryReceiptRefsField?: string;
  runtimeCodingToolBudgetRecoveryPolicyDecisionRefsField?: string;
  runtimeCodingToolBudgetRecoveryWorkflowNodeId?: string;
  runtimeCodingToolBudgetRecoverySource?: "react_flow" | "sdk_client" | "cli_tui" | string;
  runtimeCodingToolBudgetRecoveryActor?: string;
  runtimeTerminalCodingLoopSchemaVersion?: string;
  runtimeTerminalCodingLoopWorkflowNodeId?: string;
  runtimeTerminalCodingLoopWorkflowGraphId?: string | null;
  runtimeTerminalCodingLoopStepId?: string;
  runtimeTerminalCodingLoopCommand?: string;
  runtimeTerminalCodingLoopThreadIdField?: string;
  runtimeTerminalCodingLoopTurnIdField?: string;
  runtimeTerminalCodingLoopCursorField?: string;
  runtimeTerminalCodingLoopLastEventIdField?: string;
  runtimeTerminalCodingLoopToolCallIdField?: string;
  runtimeTerminalCodingLoopArtifactIdField?: string;
  runtimeTerminalCodingLoopSource?: "react_flow" | "sdk_client" | "cli_tui" | string;
  runtimeTerminalCodingLoopActor?: string;
  runtimeTerminalCodingLoopTuiReopen?: Record<string, unknown>;
  runtimeTerminalCodingLoopEvidence?: unknown;
  workflowNodeId?: string;
  workflow_node_id?: string;
  runtimeTelemetrySummary?: unknown;
  runtimeTelemetrySourceBinding?: unknown;
  runtimeUsageMeterEndpoint?: string;
  runtimeUsageMeter?: unknown;
  runtimeUsageMeterField?: string;
  runtimeUsageMeterStatusField?: string;
  runtimeUsageMeterThreadId?: string;
  runtimeUsageMeterThreadIdField?: string;
  runtimeUsageMeterRunId?: string;
  runtimeUsageMeterRunIdField?: string;
  runtimeUsageMeterScope?: "run" | "thread" | "workflow" | string;
  runtimeUsageMeterScopeField?: string;
  runtimeUsageMeterGroupBy?: "run" | "thread" | string;
  runtimeUsageMeterSimulationMode?: boolean;
  runtimeUsageMeterWorkflowNodeId?: string;
  runtimeUsageMeterSource?: "react_flow" | "sdk_client" | "cli_tui" | string;
  runtimeUsageMeterActor?: string;
  runtimeContextBudgetEndpoint?: string;
  runtimeContextBudget?: unknown;
  runtimeContextBudgetField?: string;
  runtimeContextBudgetUsageField?: string;
  runtimeContextBudgetStatusField?: string;
  runtimeContextBudgetPolicyField?: string;
  runtimeContextBudgetThreadId?: string;
  runtimeContextBudgetThreadIdField?: string;
  runtimeContextBudgetRunId?: string;
  runtimeContextBudgetRunIdField?: string;
  runtimeContextBudgetScope?: "run" | "thread" | "workflow" | string;
  runtimeContextBudgetScopeField?: string;
  runtimeContextBudgetMode?: "simulate" | "warn" | "block" | string;
  runtimeContextBudgetModeField?: string;
  runtimeContextBudgetMaxTotalTokens?: number | string;
  runtimeContextBudgetMaxTotalTokensField?: string;
  runtimeContextBudgetMaxCostUsd?: number | string;
  runtimeContextBudgetMaxCostUsdField?: string;
  runtimeContextBudgetMaxContextPressure?: number | string;
  runtimeContextBudgetMaxContextPressureField?: string;
  runtimeContextBudgetWarnAtRatio?: number | string;
  runtimeContextBudgetWarnAtRatioField?: string;
  runtimeContextBudgetSimulationMode?: boolean;
  runtimeContextBudgetWorkflowNodeId?: string;
  runtimeContextBudgetSource?: "react_flow" | "sdk_client" | "cli_tui" | string;
  runtimeContextBudgetActor?: string;
  runtimeCompactionPolicyEndpoint?: string;
  runtimeCompactionPolicy?: unknown;
  runtimeCompactionPolicyField?: string;
  runtimeCompactionPolicyActionField?: string;
  runtimeCompactionPolicyEventField?: string;
  runtimeCompactionPolicyStatusField?: string;
  runtimeCompactionPolicyThreadId?: string;
  runtimeCompactionPolicyThreadIdField?: string;
  runtimeCompactionPolicyTurnId?: string;
  runtimeCompactionPolicyTurnIdField?: string;
  runtimeCompactionPolicyContextBudget?: unknown;
  runtimeCompactionPolicyContextBudgetField?: string;
  runtimeCompactionPolicyContextBudgetStatus?: string;
  runtimeCompactionPolicyContextBudgetStatusField?: string;
  runtimeCompactionPolicyOkAction?:
    | "noop"
    | "warn"
    | "compact"
    | "stop"
    | "approval_required"
    | string;
  runtimeCompactionPolicyOkActionField?: string;
  runtimeCompactionPolicyWarnAction?:
    | "noop"
    | "warn"
    | "compact"
    | "stop"
    | "approval_required"
    | string;
  runtimeCompactionPolicyWarnActionField?: string;
  runtimeCompactionPolicyBlockedAction?:
    | "noop"
    | "warn"
    | "compact"
    | "stop"
    | "approval_required"
    | string;
  runtimeCompactionPolicyBlockedActionField?: string;
  runtimeCompactionPolicyApprovalRequired?: boolean;
  runtimeCompactionPolicyApprovalRequiredField?: string;
  runtimeCompactionPolicyApprovalGranted?: boolean;
  runtimeCompactionPolicyApprovalGrantedField?: string;
  runtimeCompactionPolicyExecuteCompaction?: boolean;
  runtimeCompactionPolicyExecuteCompactionField?: string;
  runtimeCompactionPolicyCompactReason?: string;
  runtimeCompactionPolicyCompactReasonField?: string;
  runtimeCompactionPolicyCompactScope?: string;
  runtimeCompactionPolicyCompactScopeField?: string;
  runtimeCompactionPolicyCompactWorkflowNodeId?: string;
  runtimeCompactionPolicyWorkflowNodeId?: string;
  runtimeCompactionPolicySource?: "react_flow" | "sdk_client" | "cli_tui" | string;
  runtimeCompactionPolicyActor?: string;
  workflowPackageExportEndpoint?: string;
  workflowPackageExport?: unknown;
  workflowPackageExportField?: string;
  workflowPackagePath?: string;
  workflowPackageOutputDir?: string;
  workflowPackageManifestField?: string;
  workflowPackageReadinessStatusField?: string;
  workflowPackagePortableField?: string;
  workflowPackageLocaleField?: string;
  workflowPackageEvidenceReadyField?: string;
  workflowPackageImportEndpoint?: string;
  workflowPackageImport?: unknown;
  workflowPackageImportRequest?: unknown;
  workflowPackageImportField?: string;
  workflowPackageImportReview?: unknown;
  workflowPackageImportReviewField?: string;
  workflowPackageImportEvidenceReadyField?: string;
  workflowPackageImportLocalePreservedField?: string;
  workflowPackageImportedWorkflowPathField?: string;
  workflowPackageImportName?: string;
  workflowPackageProjectRoot?: string;
  repositoryEndpoint?: string;
  repositoryContext?: unknown;
  repositoryContextField?: string;
  repositoryBranchField?: string;
  repositoryHeadField?: string;
  repositoryDirtyField?: string;
  readOnly?: boolean;
  mutationExecuted?: boolean;
  branchPolicy?: unknown;
  branchPolicyField?: string;
  branchPolicyStatusField?: string;
  branchPolicyBlockersField?: string;
  branchPolicyWarningsField?: string;
  branchPolicyReceiptField?: string;
  protectedBranchNames?: string[];
  blockProtectedBranches?: boolean;
  allowDirtyWorktree?: boolean;
  requireUpstream?: boolean;
  requireReviewForWarnings?: boolean;
  githubContextEndpoint?: string;
  githubContext?: unknown;
  githubContextField?: string;
  githubRemoteField?: string;
  githubOwnerField?: string;
  githubRepoField?: string;
  githubDefaultBranchField?: string;
  githubPrPreconditionsField?: string;
  githubContextReceiptField?: string;
  issueContextEndpoint?: string;
  issueContext?: unknown;
  issueContextField?: string;
  issueContextStatusField?: string;
  issueContextBoundField?: string;
  issueContextIssueNumberField?: string;
  issueContextSourceUrlField?: string;
  issueContextReceiptField?: string;
  prAttemptEndpoint?: string;
  prAttempt?: unknown;
  prAttemptField?: string;
  prAttemptStatusField?: string;
  prAttemptBlockersField?: string;
  prAttemptAuthorityField?: string;
  prAttemptBranchArtifactField?: string;
  prAttemptDiffArtifactField?: string;
  prAttemptReceiptField?: string;
  reviewGateEndpoint?: string;
  reviewGate?: unknown;
  reviewGateField?: string;
  reviewGateStatusField?: string;
  reviewGateBlockersField?: string;
  reviewGateReviewersField?: string;
  reviewGateChecksField?: string;
  reviewGateReceiptField?: string;
  githubPrCreatePlanEndpoint?: string;
  githubPrCreatePlan?: unknown;
  githubPrCreatePlanField?: string;
  githubPrCreatePlanStatusField?: string;
  githubPrCreatePlanBlockersField?: string;
  githubPrCreatePlanRequestHashField?: string;
  githubPrCreatePlanAuthorityField?: string;
  githubPrCreatePlanReceiptField?: string;
  activationGate?: {
    consumesDoctorReport?: boolean;
    consumesRuntimeTask?: boolean;
    consumesRuntimeJob?: boolean;
    consumesRuntimeChecklist?: boolean;
    consumesRuntimeThreadFork?: boolean;
    consumesRuntimeOperatorInterrupt?: boolean;
    consumesRuntimeOperatorSteer?: boolean;
    consumesRuntimeThreadMode?: boolean;
    consumesRuntimeContextCompact?: boolean;
    consumesRuntimeUsageMeter?: boolean;
    consumesRuntimeContextBudget?: boolean;
    consumesRuntimeCompactionPolicy?: boolean;
    consumesRuntimeRollbackSnapshot?: boolean;
    consumesRuntimeRestoreGate?: boolean;
    consumesRuntimeDiagnosticsRepair?: boolean;
    consumesWorkflowPackageExport?: boolean;
    consumesWorkflowPackageImportReview?: boolean;
    consumesRepositoryContext?: boolean;
    consumesBranchPolicy?: boolean;
    consumesGithubContext?: boolean;
    consumesIssueContext?: boolean;
    consumesPrAttempt?: boolean;
    consumesReviewGate?: boolean;
    consumesGithubPrCreatePlan?: boolean;
    consumesSkillHookManifest?: boolean;
    blockerField?: string;
    optionalWarningsField?: string;
    runtimeTaskField?: string;
    runtimeTaskStatusField?: string;
    runtimeJobField?: string;
    runtimeJobStatusField?: string;
    runtimeChecklistField?: string;
    runtimeChecklistStatusField?: string;
    runtimeThreadForkField?: string;
    runtimeThreadForkStatusField?: string;
    runtimeOperatorInterruptField?: string;
    runtimeOperatorInterruptStatusField?: string;
    runtimeOperatorSteerField?: string;
    runtimeOperatorSteerStatusField?: string;
    runtimeThreadModeField?: string;
    runtimeThreadModeStatusField?: string;
    consumesRuntimeWorkspaceTrustGate?: boolean;
    consumesRuntimeWorkspaceTrustAcknowledgement?: boolean;
    runtimeWorkspaceTrustGateField?: string;
    runtimeWorkspaceTrustGateStatusField?: string;
    runtimeWorkspaceTrustAcknowledgementField?: string;
    runtimeWorkspaceTrustAcknowledgementStatusField?: string;
    runtimeContextCompactField?: string;
    runtimeContextCompactStatusField?: string;
    consumesRuntimeApprovalRequest?: boolean;
    runtimeApprovalRequestField?: string;
    runtimeApprovalRequestStatusField?: string;
    runtimeUsageMeterField?: string;
    runtimeUsageMeterStatusField?: string;
    runtimeContextBudgetField?: string;
    runtimeContextBudgetStatusField?: string;
    runtimeCompactionPolicyField?: string;
    runtimeCompactionPolicyStatusField?: string;
    runtimeRollbackSnapshotField?: string;
    runtimeRollbackSnapshotStatusField?: string;
  runtimeRestoreGateField?: string;
  runtimeRestoreGateStatusField?: string;
  runtimeDiagnosticsRepairField?: string;
  runtimeDiagnosticsRepairStatusField?: string;
  consumesRuntimeCodingToolBudgetRecovery?: boolean;
  runtimeCodingToolBudgetRecoveryField?: string;
  runtimeCodingToolBudgetRecoveryStatusField?: string;
  workflowPackageExportField?: string;
    workflowPackageReadinessStatusField?: string;
    workflowPackagePortableField?: string;
    workflowPackageImportReviewField?: string;
    workflowPackageImportEvidenceReadyField?: string;
    workflowPackageImportLocalePreservedField?: string;
    githubPrCreatePlanField?: string;
    githubPrCreatePlanStatusField?: string;
    githubPrCreatePlanBlockersField?: string;
    skillSetHashField?: string;
    hookSetHashField?: string;
    hookDryRunPlanField?: string;
    hookDryRunDecisionField?: string;
    hookPolicyDecisionField?: string;
    hookInvocationLedgerField?: string;
    hookInvocationStateField?: string;
    hookEscalationCountField?: string;
    hookEscalationDetailsField?: string;
    hookEscalationReceiptField?: string;
    branchPolicyField?: string;
    branchPolicyStatusField?: string;
    branchPolicyBlockersField?: string;
    branchPolicyWarningsField?: string;
    githubContextField?: string;
    githubPrPreconditionsField?: string;
    issueContextField?: string;
    issueContextStatusField?: string;
    issueContextBoundField?: string;
    prAttemptField?: string;
    prAttemptStatusField?: string;
    prAttemptBlockersField?: string;
    prAttemptAuthorityField?: string;
    reviewGateField?: string;
    reviewGateStatusField?: string;
    reviewGateBlockersField?: string;
    manifestValidationField?: string;
    requireValidationPass?: boolean;
  };

  // --- Retrieval ---
  query?: string;
  limit?: number;
  url?: string;
  max_chars?: number;
  topK?: number;
  candidatesText?: string;

  // --- Media ---
  mimeType?: string;
  audioPath?: string;
  imagePath?: string;
  maskImagePath?: string;
  audioLanguage?: string;
  voice?: string;

  // --- Logic ---
  conditionScript?: string;
  loopCondition?: string;
  maxIterations?: number;
  barrierStrategy?: "all" | "any";
  subgraphRef?: WorkflowSubgraphRef;
  proposalAction?: WorkflowProposalAction;
  assertion?: WorkflowTestAssertion;
  assertionKind?: WorkflowTestAssertion["kind"];
  expected?: unknown;
  expression?: string;

  // --- Connector / adapter binding ---
  connectorBinding?: WorkflowConnectorBinding;

  // --- Runtime validation ---
  schema?: WorkflowJsonSchema;
  inputMapping?: Record<string, string>;
  fieldMappings?: Record<string, WorkflowFieldMapping>;
  inputSchema?: WorkflowJsonSchema;
  outputSchema?: WorkflowJsonSchema;
  testInput?: unknown;
  mockBinding?: boolean;

  // --- View-only composition helpers ---
  viewMacro?: WorkflowNodeViewMacro;
  harnessGroup?: WorkflowHarnessGroupView;
  harnessComponent?: WorkflowHarnessComponentSpec;
  harnessSlots?: string[];
}

export interface FirewallPolicy {
  budgetCap?: number;
  networkAllowlist?: string[];
  requireHumanGate?: boolean;
  privilegedActions?: string[];
  privacyLevel?: "none" | "masked" | "zero-knowledge";
  retryPolicy?: {
    maxAttempts: number;
    backoffMs: number;
  };
  sandboxPolicy?: WorkflowSandboxPolicy;
}

export type WorkflowSideEffectClass =
  | "none"
  | "read"
  | "write"
  | "external_write"
  | "financial_write"
  | "admin";

export interface WorkflowJsonSchema {
  type?: string;
  required?: string[];
  properties?: Record<string, unknown>;
  additionalProperties?: boolean;
}

export interface WorkflowSandboxPolicy {
  timeoutMs?: number;
  memoryMb?: number;
  outputLimitBytes?: number;
  permissions?: Array<"filesystem" | "network" | "process">;
}

export interface WorkflowFunctionBinding {
  language: "javascript" | "typescript" | "python";
  code: string;
  functionRef?: WorkflowFunctionRef;
  inputSchema?: WorkflowJsonSchema;
  outputSchema?: WorkflowJsonSchema;
  sandboxPolicy?: WorkflowSandboxPolicy;
  testInput?: unknown;
}

export type WorkflowToolBindingKind =
  | "plugin_tool"
  | "mcp_tool"
  | "native_tool"
  | "workflow_tool"
  | "coding_tool_pack";

export interface WorkflowCapabilityCredentialReadiness {
  status: "not_required" | "ready" | "missing" | "degraded" | "unknown" | string;
  checkedAt?: string | null;
  evidenceRefs?: string[];
  reason?: string | null;
}

export interface WorkflowCapabilityAvailability {
  available: boolean;
  reason?: string | null;
  nodeType?: string | null;
  configFields?: string[];
  evidenceRefs?: string[];
}

export interface WorkflowCapabilityContractMetadata {
  toolCapabilityRef?: string;
  connectorCapabilityRef?: string;
  riskClass?: string;
  primitiveCapabilities?: string[];
  authorityScopes?: string[];
  authorityScopeRequirements?: string[];
  inputSchema?: WorkflowJsonSchema | Record<string, unknown>;
  outputSchema?: WorkflowJsonSchema | Record<string, unknown>;
  evidenceRequirements?: string[];
  approvalRequirement?: Record<string, unknown>;
  grantReadiness?: WorkflowCapabilityCredentialReadiness | Record<string, unknown>;
  policyPosture?: Record<string, unknown>;
  credentialReadiness?: WorkflowCapabilityCredentialReadiness;
  rateLimitProfile?: Record<string, unknown>;
  idempotencyBehavior?: Record<string, unknown>;
  receiptBehavior?: Record<string, unknown>;
  workflowAvailability?: WorkflowCapabilityAvailability;
  agentAvailability?: WorkflowCapabilityAvailability;
  marketplaceExposure?: Record<string, unknown>;
  runtimeToolContract?: Record<string, unknown>;
}

export interface WorkflowModelCapabilityContractMetadata {
  modelCapabilityRef?: string;
  routeId?: string;
  credentialReadiness?: WorkflowCapabilityCredentialReadiness;
  receiptBehavior?: Record<string, unknown>;
  workflowAvailability?: WorkflowCapabilityAvailability;
  agentAvailability?: WorkflowCapabilityAvailability;
  privacyTier?: string;
  providerPriority?: string[];
  fallbackPolicy?: Record<string, unknown>;
  fallbackEvidence?: Array<Record<string, unknown>>;
  costEstimateVisibility?: Record<string, unknown>;
  authorityScopes?: string[];
  authorityScopeRequirements?: string[];
  grantReadiness?: WorkflowCapabilityCredentialReadiness | Record<string, unknown>;
  policyPosture?: Record<string, unknown>;
  vaultReadiness?: Record<string, unknown>;
  byokRequired?: boolean;
}

export interface WorkflowToolBinding {
  toolRef: string;
  toolCapabilityRef?: string;
  bindingKind?: WorkflowToolBindingKind;
  mockBinding: boolean;
  credentialReady?: boolean;
  credentialReadiness?: WorkflowCapabilityCredentialReadiness;
  riskClass?: string;
  primitiveCapabilities?: string[];
  authorityScopes?: string[];
  authorityScopeRequirements?: string[];
  inputSchema?: WorkflowJsonSchema | Record<string, unknown>;
  outputSchema?: WorkflowJsonSchema | Record<string, unknown>;
  evidenceRequirements?: string[];
  approvalRequirement?: Record<string, unknown>;
  grantReadiness?: WorkflowCapabilityCredentialReadiness | Record<string, unknown>;
  policyPosture?: Record<string, unknown>;
  rateLimitProfile?: Record<string, unknown>;
  idempotencyBehavior?: Record<string, unknown>;
  receiptBehavior?: Record<string, unknown>;
  workflowAvailability?: WorkflowCapabilityAvailability;
  agentAvailability?: WorkflowCapabilityAvailability;
  marketplaceExposure?: Record<string, unknown>;
  runtimeToolContract?: Record<string, unknown>;
  capabilityScope: string[];
  sideEffectClass: WorkflowSideEffectClass;
  requiresApproval: boolean;
  arguments?: Record<string, unknown>;
  mcp?: {
    serverId?: string;
    toolName?: string;
    catalogRef?: string;
    catalogMode?: "deferred" | "full" | string;
    catalogSearchQuery?: string;
    configSourceMode?: "workspace_and_global" | "workspace" | "global" | string;
    validateBeforeInvoke?: boolean;
    containmentMode?: "read_only" | "sandboxed" | "review_required";
  };
  toolPack?: {
    pack: string;
    workspaceStatusEnabled?: boolean;
    gitEnabled?: boolean;
    filesystemEnabled?: boolean;
    writeEnabled?: boolean;
    testEnabled?: boolean;
    diagnosticsEnabled?: boolean;
    artifactEnabled?: boolean;
    resultRetrievalEnabled?: boolean;
    allowedTestCommandIds?: string[];
    allowedDiagnosticCommandIds?: string[];
    diagnosticsMode?: "advisory" | "blocking" | "skip";
    defaultDiagnosticCommandId?: string;
    budgetMode?: "simulate" | "warn" | "block" | string;
    budgetUsageField?: string;
    maxTotalTokens?: number | null;
    maxCostUsd?: number | null;
    maxContextPressure?: number | null;
    warnAtRatio?: number;
    budgetRecoveryApprovalScope?: "workflow" | "target_nodes" | "evidence_nodes" | string;
    budgetRecoveryTargetNodeIds?: string[];
    budgetRecoveryRetryLimit?: number;
    budgetRecoveryTtlMs?: number;
    budgetRecoveryOperatorRole?: string;
    budgetRecoveryRequiresApproval?: boolean;
    budgetRecoveryAllowOverride?: boolean;
    restorePolicy?: "disabled" | "preview_only" | "apply_with_approval";
    restoreConflictPolicy?: "block" | "require_approval" | "allow_override";
    diagnosticsRepairDefault?:
      | "repair_retry"
      | "restore_preview"
      | "restore_apply"
      | "operator_override";
    operatorOverrideRequiresApproval?: boolean;
    approvalMode?:
      | "suggest"
      | "auto_local"
      | "never_prompt"
      | "human_required"
      | "policy_required";
    trustProfile?: "local_private" | "untrusted" | "restricted" | "review_required" | string;
    nodeApprovalOverride?: "inherit" | "require_approval" | "never_prompt" | string;
    requiresApproval?: boolean;
    timeoutMs?: number;
    dryRun?: boolean;
    allowedPaths?: string[];
    [key: string]: unknown;
  };
  workflowTool?: {
    workflowPath: string;
    argumentSchema?: WorkflowJsonSchema;
    resultSchema?: WorkflowJsonSchema;
    timeoutMs?: number;
    maxAttempts?: number;
  };
}

export interface WorkflowConnectorBinding {
  connectorRef: string;
  connectorCapabilityRef?: string;
  mockBinding: boolean;
  credentialReady?: boolean;
  credentialReadiness?: WorkflowCapabilityCredentialReadiness;
  riskClass?: string;
  primitiveCapabilities?: string[];
  authorityScopes?: string[];
  authorityScopeRequirements?: string[];
  inputSchema?: WorkflowJsonSchema | Record<string, unknown>;
  outputSchema?: WorkflowJsonSchema | Record<string, unknown>;
  evidenceRequirements?: string[];
  approvalRequirement?: Record<string, unknown>;
  grantReadiness?: WorkflowCapabilityCredentialReadiness | Record<string, unknown>;
  policyPosture?: Record<string, unknown>;
  rateLimitProfile?: Record<string, unknown>;
  idempotencyBehavior?: Record<string, unknown>;
  receiptBehavior?: Record<string, unknown>;
  workflowAvailability?: WorkflowCapabilityAvailability;
  agentAvailability?: WorkflowCapabilityAvailability;
  marketplaceExposure?: Record<string, unknown>;
  runtimeToolContract?: Record<string, unknown>;
  capabilityScope: string[];
  sideEffectClass: WorkflowSideEffectClass;
  requiresApproval: boolean;
  operation?: string;
}

export interface WorkflowNodeExecutor {
  nodeType: WorkflowNodeKind | string;
  executorId: string;
  sandboxed: boolean;
  supportsDryRun: boolean;
}

export interface WorkflowVerificationEvidence {
  nodeId: string;
  evidenceType:
    | "execution"
    | "schema_validation"
    | "approval"
    | "output"
    | "materialized_asset"
    | "test";
  status: "passed" | "failed" | "blocked";
  summary: string;
  createdAtMs: number;
}

export interface WorkflowCompletionRequirement {
  id: string;
  nodeId?: string;
  requirementType:
    | "execution"
    | "verification"
    | "approval"
    | "output_created"
    | "asset_materialized"
    | "test";
  status: "satisfied" | "missing" | "failed";
  summary: string;
}

export type WorkflowOutputFormat =
  | "markdown"
  | "json"
  | "svg"
  | "image"
  | "chart"
  | "diff"
  | "patch"
  | "dataset"
  | "message"
  | "report";

export interface WorkflowRendererRef {
  rendererId: string;
  displayMode:
    | "inline"
    | "canvas_preview"
    | "table"
    | "json"
    | "media"
    | "diff"
    | "report"
    | "artifact_panel";
  dependencies?: string[];
}

export interface WorkflowMaterializationConfig {
  enabled: boolean;
  assetPath?: string;
  assetKind?:
    | "file"
    | "blob"
    | "report"
    | "svg"
    | "chart"
    | "patch"
    | "dataset";
}

export interface WorkflowDeliveryTarget {
  targetKind:
    | "none"
    | "chat_inline"
    | "local_file"
    | "repo_patch"
    | "ticket_draft"
    | "message_draft"
    | "connector_write"
    | "deploy";
  targetRef?: string;
  requiresApproval?: boolean;
}

export interface WorkflowOutputRetentionPolicy {
  retentionKind: "ephemeral" | "run_scoped" | "workflow_scoped" | "versioned";
  ttlMs?: number;
}

export interface WorkflowOutputVersioning {
  enabled: boolean;
  versionRef?: string;
  hash?: string;
}

export interface WorkflowOutputNodeConfig {
  format: WorkflowOutputFormat;
  schema?: WorkflowJsonSchema;
  rendererRef?: WorkflowRendererRef;
  materialization?: WorkflowMaterializationConfig;
  deliveryTarget?: WorkflowDeliveryTarget;
  retentionPolicy?: WorkflowOutputRetentionPolicy;
  versioning?: WorkflowOutputVersioning;
  sideEffectClass?: WorkflowSideEffectClass;
}

export interface WorkflowMaterializedAsset {
  id: string;
  nodeId: string;
  assetKind: NonNullable<WorkflowMaterializationConfig["assetKind"]>;
  path?: string;
  hash?: string;
  createdAtMs: number;
}

export interface WorkflowOutputBundle {
  id: string;
  nodeId: string;
  format: WorkflowOutputFormat | string;
  value: unknown;
  rendererRef?: WorkflowRendererRef;
  materializedAssets?: WorkflowMaterializedAsset[];
  deliveryTarget?: WorkflowDeliveryTarget;
  dependencyRefs?: string[];
  evidenceRefs?: string[];
  version?: WorkflowOutputVersioning;
  createdAtMs: number;
}

export interface WorkflowFunctionRef {
  runtime: "javascript" | "typescript";
  entrypoint: string;
  sourcePath: string;
  codeHash?: string;
  dependencyManifest?: Record<string, unknown>;
  inputSchema?: WorkflowJsonSchema;
  outputSchema?: WorkflowJsonSchema;
  fixtureSet?: unknown[];
  sandboxPolicy?: WorkflowSandboxPolicy;
}

export interface WorkflowModelBinding {
  modelRef: string;
  modelCapabilityRef?: string;
  modelId?: string | null;
  routeId?: string;
  reasoningEffort?: "low" | "medium" | "high" | "xhigh" | string;
  modelPolicy?: Record<string, unknown>;
  capability?:
    | "chat"
    | "responses"
    | "structured_output"
    | "embeddings"
    | "vision"
    | "rerank";
  receiptRequired?: boolean;
  daemonApi?: string;
  selectedEndpointId?: string | null;
  lastReceiptId?: string | null;
  mockBinding: boolean;
  capabilityScope: string[];
  argumentSchema?: WorkflowJsonSchema;
  resultSchema?: WorkflowJsonSchema;
  sideEffectClass: WorkflowSideEffectClass;
  requiresApproval: boolean;
  credentialReady?: boolean;
  credentialReadiness?: WorkflowCapabilityCredentialReadiness;
  receiptBehavior?: Record<string, unknown>;
  workflowAvailability?: WorkflowCapabilityAvailability;
  agentAvailability?: WorkflowCapabilityAvailability;
  privacyTier?: string;
  providerPriority?: string[];
  fallbackPolicy?: Record<string, unknown>;
  fallbackEvidence?: Array<Record<string, unknown>>;
  costEstimateVisibility?: Record<string, unknown>;
  authorityScopes?: string[];
  authorityScopeRequirements?: string[];
  grantReadiness?: WorkflowCapabilityCredentialReadiness | Record<string, unknown>;
  policyPosture?: Record<string, unknown>;
  vaultReadiness?: Record<string, unknown>;
  byokRequired?: boolean;
  toolUseMode?: "none" | "explicit" | "auto";
}

export interface WorkflowParserBinding {
  parserRef: string;
  parserKind: "json_schema" | "structured_output" | "text";
  resultSchema?: WorkflowJsonSchema;
  mockBinding?: boolean;
}

export interface WorkflowTriggerConfig {
  triggerKind: "manual" | "scheduled" | "event";
  schedule?: string;
  eventSourceRef?: string;
  dedupeKey?: string;
}

export interface WorkflowStateOperation {
  key: string;
  operation: "read" | "write" | "append" | "merge";
  reducer: "replace" | "append" | "merge";
  initialValue?: unknown;
}

export interface WorkflowSubgraphRef {
  workflowPath: string;
  inputMapping?: Record<string, string>;
  outputMapping?: Record<string, string>;
}

export interface WorkflowProposalAction {
  actionKind: "create" | "preview" | "apply";
  boundedTargets: string[];
  requiresApproval: boolean;
}

export type WorkflowPortDataType =
  | "none"
  | "payload"
  | "prompt"
  | "message"
  | "request"
  | "response"
  | "args"
  | "result"
  | "branch"
  | "decision"
  | "approval"
  | "state"
  | "run"
  | "output_bundle"
  | "test_result"
  | "proposal";

export type WorkflowConnectionClass =
  | "control"
  | "data"
  | "model"
  | "memory"
  | "tool"
  | "parser"
  | "state"
  | "approval"
  | "error"
  | "retry"
  | "delivery"
  | "subgraph";

export interface WorkflowPortDefinition {
  id: string;
  label: string;
  direction: "input" | "output";
  dataType: WorkflowPortDataType;
  connectionClass: WorkflowConnectionClass;
  cardinality: "one" | "many";
  required: boolean;
  semanticRole:
    | "input"
    | "context"
    | "output"
    | "error"
    | "retry"
    | "branch"
    | "approval"
    | "delivery"
    | "model"
    | "tool"
    | "parser"
    | "state"
    | "proposal"
    | "memory"
    | "subgraph"
    | "trigger";
  connectableNodeKinds?: WorkflowNodeKind[];
}

export type WorkflowNodeFamily =
  | "sources"
  | "triggers"
  | "functions"
  | "models"
  | "context"
  | "tools"
  | "connectors"
  | "state"
  | "flow_control"
  | "gates"
  | "outputs"
  | "tests"
  | "proposals"
  | "subgraphs";

export interface WorkflowPolicyProfile {
  sideEffectClass: WorkflowSideEffectClass;
  requiresApproval: boolean;
  sandboxed: boolean;
  privilegedBoundary?: boolean;
}

export interface WorkflowEvidenceProfile {
  requiredEvidence: Array<WorkflowVerificationEvidence["evidenceType"]>;
  completionRequirements: Array<
    WorkflowCompletionRequirement["requirementType"]
  >;
}

export interface WorkflowNodeConfigBase<
  TKind extends WorkflowNodeKind,
  TLogic extends NodeLogic = NodeLogic,
> {
  kind?: TKind;
  logic: TLogic;
  law: FirewallPolicy;
}

export type WorkflowNodeConfig =
  | WorkflowNodeConfigBase<"source">
  | WorkflowNodeConfigBase<"trigger">
  | WorkflowNodeConfigBase<"task_state">
  | WorkflowNodeConfigBase<"uncertainty_gate">
  | WorkflowNodeConfigBase<"probe">
  | WorkflowNodeConfigBase<"budget_gate">
  | WorkflowNodeConfigBase<"capability_sequence">
  | WorkflowNodeConfigBase<"runtime_doctor">
  | WorkflowNodeConfigBase<"runtime_task">
  | WorkflowNodeConfigBase<"runtime_job">
  | WorkflowNodeConfigBase<"runtime_checklist">
  | WorkflowNodeConfigBase<"runtime_thread_fork">
  | WorkflowNodeConfigBase<"runtime_operator_interrupt">
  | WorkflowNodeConfigBase<"runtime_operator_steer">
  | WorkflowNodeConfigBase<"runtime_thread_mode">
  | WorkflowNodeConfigBase<"runtime_context_compact">
  | WorkflowNodeConfigBase<"runtime_approval_request">
  | WorkflowNodeConfigBase<"runtime_usage_meter">
  | WorkflowNodeConfigBase<"runtime_context_budget">
  | WorkflowNodeConfigBase<"runtime_compaction_policy">
  | WorkflowNodeConfigBase<"runtime_rollback_snapshot">
  | WorkflowNodeConfigBase<"runtime_restore_gate">
  | WorkflowNodeConfigBase<"runtime_diagnostics_repair">
  | WorkflowNodeConfigBase<"runtime_coding_tool_budget_recovery">
  | WorkflowNodeConfigBase<"workflow_package_export">
  | WorkflowNodeConfigBase<"workflow_package_import">
  | WorkflowNodeConfigBase<"repository_context">
  | WorkflowNodeConfigBase<"branch_policy">
  | WorkflowNodeConfigBase<"github_context">
  | WorkflowNodeConfigBase<"issue_context">
  | WorkflowNodeConfigBase<"pr_attempt">
  | WorkflowNodeConfigBase<"review_gate">
  | WorkflowNodeConfigBase<"github_pr_create">
  | WorkflowNodeConfigBase<"function">
  | WorkflowNodeConfigBase<"model_binding">
  | WorkflowNodeConfigBase<"model_call">
  | WorkflowNodeConfigBase<"skill_context">
  | WorkflowNodeConfigBase<"skill">
  | WorkflowNodeConfigBase<"skill_pack">
  | WorkflowNodeConfigBase<"hook">
  | WorkflowNodeConfigBase<"hook_policy">
  | WorkflowNodeConfigBase<"parser">
  | WorkflowNodeConfigBase<"adapter">
  | WorkflowNodeConfigBase<"plugin_tool">
  | WorkflowNodeConfigBase<"dry_run">
  | WorkflowNodeConfigBase<"state">
  | WorkflowNodeConfigBase<"decision">
  | WorkflowNodeConfigBase<"loop">
  | WorkflowNodeConfigBase<"barrier">
  | WorkflowNodeConfigBase<"subgraph">
  | WorkflowNodeConfigBase<"human_gate">
  | WorkflowNodeConfigBase<"semantic_impact">
  | WorkflowNodeConfigBase<"postcondition_synthesis">
  | WorkflowNodeConfigBase<"verifier">
  | WorkflowNodeConfigBase<"drift_detector">
  | WorkflowNodeConfigBase<"quality_ledger">
  | WorkflowNodeConfigBase<"handoff">
  | WorkflowNodeConfigBase<"gui_harness_validation">
  | WorkflowNodeConfigBase<"output">
  | WorkflowNodeConfigBase<"test_assertion">
  | WorkflowNodeConfigBase<"proposal">;

export interface WorkflowNodeDefinitionContract {
  type: WorkflowNodeKind;
  family: WorkflowNodeFamily;
  label: string;
  ports: WorkflowPortDefinition[];
  configSchema: WorkflowJsonSchema;
  policyProfile: WorkflowPolicyProfile;
  evidenceProfile: WorkflowEvidenceProfile;
  executor: WorkflowNodeExecutor;
  localization?: WorkflowRuntimeNodeLocalization;
  accessibility?: WorkflowRuntimeNodeAccessibility;
}

export interface WorkflowScaffoldDefinition {
  scaffoldId: string;
  nodeType: WorkflowNodeKind;
  family: WorkflowNodeFamily;
  label: string;
  description: string;
  defaultName: string;
  connectionClasses?: WorkflowConnectionClass[];
  relatedNodeTypes?: WorkflowNodeKind[];
  keywords?: string[];
}

export interface WorkflowNodeActionDefinition {
  actionId: string;
  nodeType: WorkflowNodeKind;
  family: WorkflowNodeFamily;
  label: string;
  description: string;
  category: string;
  requiredBinding?:
    | "model"
    | "function"
    | "connector"
    | "tool"
    | "parser"
    | "subgraph"
    | "proposal";
  bindingMode: "none" | "optional" | "required";
  supportsMockBinding: boolean;
  sideEffectClass: WorkflowSideEffectClass;
  requiresApproval: boolean;
  sandboxed: boolean;
  supportsDryRun: boolean;
  schemaRequired: boolean;
  connectionClasses: WorkflowConnectionClass[];
  compatibleNodeTypes: WorkflowNodeKind[];
  keywords: string[];
}

// ============================================
// Graph Topology
// ============================================

export interface Node extends Record<string, unknown> {
  id: string;
  type: string;
  name: string;
  x: number;
  y: number;

  config?: WorkflowNodeConfig;

  schema?: string; // JSON Schema for dynamic tools

  // Execution State (Visual feedback)
  status?: "idle" | "running" | "success" | "error" | "blocked";
  metrics?: { records: number; time: string };
  metricLabel?: string;
  metricValue?: string;

  inputs?: string[];
  outputs?: string[];
  ports?: WorkflowPortDefinition[];
  ioTypes?: { in: string; out: string };
  runtimeBinding?: WorkflowHarnessNodeBinding;

  isGhost?: boolean;
  attested?: boolean;
}

export interface Edge {
  id: string;
  from: string;
  to: string;
  fromPort: string;
  toPort: string;
  type: "data" | "control";
  connectionClass?: WorkflowConnectionClass;
  label?: string;
  active?: boolean;
  volume?: number;
  data?: Record<string, unknown>;
}

// ============================================
// File Format
// ============================================

export type GraphCapabilityId =
  | "reasoning"
  | "vision"
  | "embedding"
  | "image"
  | "speech"
  | "video";

export interface GraphCapabilityRequirement {
  required?: boolean;
  bindingKey?: string;
  notes?: string;
}

export interface GraphGlobalConfig {
  env: string;
  workflowChromeLocale?: string;
  environmentProfile?: GraphEnvironmentProfile;
  modelBindings: Record<string, GraphModelBinding>;
  requiredCapabilities: Record<string, GraphCapabilityRequirement>;
  codingRoute?: WorkflowCodingRouteContract;
  policy: {
    maxBudget: number;
    maxSteps: number;
    timeoutMs: number;
  };
  contract: {
    developerBond: number;
    adjudicationRubric: string;
    validationSchema?: string;
  };
  meta: {
    name: string;
    description: string;
  };
  production?: GraphProductionProfile;
}

export type GraphEnvironmentTarget =
  | "local"
  | "sandbox"
  | "staging"
  | "production";

export type GraphMockBindingPolicy = "allow" | "warn" | "block";

export interface GraphEnvironmentProfile {
  target: GraphEnvironmentTarget;
  credentialScope?: string;
  mockBindingPolicy?: GraphMockBindingPolicy;
}

export type WorkflowBindingCheckStatus = "passed" | "blocked" | "warning";

export interface WorkflowBindingCheckResult {
  id: string;
  rowId: string;
  nodeId: string;
  bindingKind: string;
  reference: string;
  mode: "mock" | "live" | "local";
  status: WorkflowBindingCheckStatus;
  summary: string;
  detail: string;
  createdAtMs: number;
}

export interface WorkflowBindingManifestEntry {
  id: string;
  nodeId: string;
  nodeName: string;
  nodeType: WorkflowNodeKind | string;
  bindingKind: string;
  reference: string;
  mode: "mock" | "live" | "local";
  credentialReady: boolean;
  mockBinding: boolean;
  sideEffectClass: string;
  requiresApproval: boolean;
  capabilityScope: string[];
  modelCapabilityRef?: string | null;
  toolCapabilityRef?: string | null;
  connectorCapabilityRef?: string | null;
  routeId?: string | null;
  riskClass?: string | null;
  approvalRequirement?: Record<string, unknown> | null;
  authorityScopes?: string[];
  authorityScopeRequirements?: string[];
  rateLimitProfile?: Record<string, unknown> | null;
  idempotencyBehavior?: Record<string, unknown> | null;
  receiptBehavior?: Record<string, unknown> | null;
  readiness?: Record<string, unknown> | null;
  grantReadiness?: Record<string, unknown> | null;
  policyPosture?: Record<string, unknown> | null;
  status: WorkflowBindingCheckStatus;
  statusReason: string;
}

export interface WorkflowBindingManifestSummary {
  total: number;
  live: number;
  mock: number;
  local: number;
  ready: number;
  blocked: number;
  approvalRequired: number;
}

export interface WorkflowBindingManifest {
  schemaVersion: "workflow.bindings.v1" | string;
  workflowId: string;
  workflowSlug: string;
  generatedAtMs: number;
  environmentProfile: GraphEnvironmentProfile;
  bindings: WorkflowBindingManifestEntry[];
  summary: WorkflowBindingManifestSummary;
}

export interface GraphModelBinding {
  modelId: string;
  modelHash?: string;
  required?: boolean;
  modelRef?: string;
  modelCapabilityRef?: string;
  routeId?: string;
  mockBinding?: boolean;
  credentialReadiness?: WorkflowCapabilityCredentialReadiness;
  receiptBehavior?: Record<string, unknown>;
  workflowAvailability?: WorkflowCapabilityAvailability;
  agentAvailability?: WorkflowCapabilityAvailability;
  privacyTier?: string;
  providerPriority?: string[];
  fallbackPolicy?: Record<string, unknown>;
  fallbackEvidence?: Array<Record<string, unknown>>;
  costEstimateVisibility?: Record<string, unknown>;
  authorityScopes?: string[];
  authorityScopeRequirements?: string[];
  grantReadiness?: WorkflowCapabilityCredentialReadiness | Record<string, unknown>;
  policyPosture?: Record<string, unknown>;
  vaultReadiness?: Record<string, unknown>;
  byokRequired?: boolean;
}

export interface GraphProductionProfile {
  errorWorkflowPath?: string;
  evaluationSetPath?: string;
  expectedTimeSavedMinutes?: number;
  mcpAccessReviewed?: boolean;
  requireReplayFixtures?: boolean;
}

export interface ProjectFile {
  version: string;
  nodes: Node[];
  edges: Edge[];
  global_config: GraphGlobalConfig;
  metadata?: WorkflowProjectMetadata;
  tests?: WorkflowTestCase[];
  proposals?: WorkflowProposal[];
  runs?: WorkflowRunSummary[];
}

export interface AgentConfiguration {
  name: string;
  description: string;
  instructions: string;
  model: string;
  temperature: number;
  tools: { id: string; name: string; desc: string; icon: string }[];
}

export type WorkflowKind =
  | "agent_workflow"
  | "scheduled_workflow"
  | "event_workflow"
  | "evaluation_workflow";

export type WorkflowExecutionMode = "local" | "external_adapter" | "hybrid";

export type WorkflowHarnessExecutionMode =
  | "projection"
  | "shadow"
  | "gated"
  | "live";

export type WorkflowHarnessComponentReadiness =
  | "projection_only"
  | "simulated"
  | "shadow_ready"
  | "live_ready";

export type WorkflowHarnessReplayDeterminism =
  | "deterministic"
  | "nondeterministic"
  | "redacted"
  | "disabled";

export interface WorkflowHarnessReplayEnvelope {
  deterministicEnvelope: boolean;
  capturesInput: boolean;
  capturesOutput: boolean;
  capturesPolicyDecision: boolean;
  fixtureRef?: string;
  determinism: WorkflowHarnessReplayDeterminism;
  nondeterminismReason?: string;
  redactionPolicy: string;
}

export type WorkflowHarnessNodeAttemptStatus =
  | "projection"
  | "shadow"
  | "gated"
  | "live"
  | "succeeded"
  | "failed"
  | "blocked";

export interface WorkflowHarnessNodeAttemptRecord {
  attemptId: string;
  harnessWorkflowId: string;
  harnessActivationId: string;
  harnessHash: string;
  workflowNodeId: string;
  componentId: string;
  componentKind: WorkflowHarnessComponentKind;
  executionMode: WorkflowHarnessExecutionMode;
  readiness: WorkflowHarnessComponentReadiness;
  attemptIndex: number;
  status: WorkflowHarnessNodeAttemptStatus;
  inputHash?: string;
  outputHash?: string;
  errorClass?: string;
  policyDecision?: string;
  startedAtMs?: number;
  durationMs?: number;
  receiptIds: string[];
  evidenceRefs: string[];
  replay: WorkflowHarnessReplayEnvelope;
}

export interface WorkflowHarnessActionFrame {
  workflowId: string;
  workflowVersion: string;
  workflowHash: string;
  executionMode: WorkflowHarnessExecutionMode;
  nodeId: string;
  componentId: string;
  componentVersion: string;
  componentKind: WorkflowHarnessComponentKind;
  readiness: WorkflowHarnessComponentReadiness;
  kernelRef: string;
  slotIds: string[];
  deterministicEnvelope: boolean;
  replay: WorkflowHarnessReplayEnvelope;
  eventKinds: string[];
  evidenceKeys: string[];
}

export interface WorkflowHarnessComponentInvocation {
  invocationId: string;
  componentKind: WorkflowHarnessComponentKind;
  executionMode: WorkflowHarnessExecutionMode;
  attemptIndex: number;
  inputHash?: string;
  outputHash?: string;
  policyDecision?: string;
  receiptIds: string[];
  evidenceRefs: string[];
  replayFixtureRef?: string;
  startedAtMs?: number;
  durationMs?: number;
}

export interface WorkflowHarnessComponentAdapterResult {
  schemaVersion: "workflow.harness.component-adapter-result.v1" | string;
  invocationId: string;
  actionFrame: WorkflowHarnessActionFrame;
  nodeAttempt: WorkflowHarnessNodeAttemptRecord;
  slotIds: string[];
  resultHash?: string;
  errorClass?: string;
  readiness: WorkflowHarnessComponentReadiness;
  receiptIds: string[];
  replay: WorkflowHarnessReplayEnvelope;
}

export type WorkflowHarnessDivergenceClass =
  | "none"
  | "harmless_metadata"
  | "missing_receipt"
  | "policy_divergence"
  | "routing_divergence"
  | "output_divergence"
  | "behavioral_regression"
  | "unclassified";

export interface WorkflowHarnessShadowComparison {
  workflowNodeId: string;
  componentKind: WorkflowHarnessComponentKind;
  liveAttemptId: string;
  shadowAttemptId: string;
  divergence: WorkflowHarnessDivergenceClass;
  blocking: boolean;
  summary: string;
  evidenceRefs: string[];
  liveReceiptRefs?: string[];
  shadowReceiptRefs?: string[];
  liveReplayFixtureRef?: string;
  shadowReplayFixtureRef?: string;
  liveInputHash?: string;
  shadowInputHash?: string;
  liveOutputHash?: string;
  shadowOutputHash?: string;
}

export interface WorkflowHarnessShadowRun {
  schemaVersion: string;
  runId: string;
  harnessWorkflowId: string;
  harnessActivationId: string;
  harnessHash: string;
  sourceSessionId?: string;
  liveTurnId?: string;
  executionMode: Extract<WorkflowHarnessExecutionMode, "shadow">;
  runner?: string;
  nodeAttempts: WorkflowHarnessNodeAttemptRecord[];
  comparisons: WorkflowHarnessShadowComparison[];
  blockingDivergenceCount: number;
  unclassifiedDivergenceCount: number;
  promotionBlocked: boolean;
  evidenceRefs: string[];
}

export type WorkflowHarnessPromotionClusterId =
  | "cognition"
  | "routing_model"
  | "verification_output"
  | "authority_tooling";

export type WorkflowHarnessClusterPromotionStatus =
  | "shadow_ready"
  | "gated"
  | "blocked"
  | "live";

export interface WorkflowHarnessPromotionCluster {
  clusterId: WorkflowHarnessPromotionClusterId;
  label: string;
  activationOrder: number;
  componentKinds: WorkflowHarnessComponentKind[];
  requiredExecutionMode: WorkflowHarnessExecutionMode;
  minimumReadiness: WorkflowHarnessComponentReadiness;
  promotionRule: string;
  rollbackTarget: string;
  blocksLiveActivation: boolean;
  promotionStatus?: WorkflowHarnessClusterPromotionStatus;
  replayGateProof?: WorkflowHarnessPromotionClusterReplayGateProof;
}

export interface WorkflowHarnessGatedClusterRun {
  schemaVersion: string;
  runId: string;
  clusterId: WorkflowHarnessPromotionClusterId;
  clusterLabel: string;
  harnessWorkflowId: string;
  harnessActivationId: string;
  harnessHash: string;
  executionMode: Extract<WorkflowHarnessExecutionMode, "gated">;
  status: WorkflowHarnessClusterPromotionStatus;
  componentKinds: WorkflowHarnessComponentKind[];
  shadowRunId: string;
  nodeAttemptIds: string[];
  receiptIds: string[];
  replayFixtureRefs: string[];
  activationBlockers: string[];
  gateDecision: string;
  rollbackTarget: string;
  canaryStatus: string;
  promotionBlocked: boolean;
  evidenceRefs: string[];
}

export interface WorkflowHarnessLiveShadowComparisonGate {
  schemaVersion: "workflow.harness.live-shadow-comparison-gate.v1" | string;
  gateId: string;
  workflowId: string;
  activationId: string;
  harnessHash: string;
  targetExecutionMode: Extract<WorkflowHarnessExecutionMode, "live">;
  requiredComponentKinds: WorkflowHarnessComponentKind[];
  componentKinds: WorkflowHarnessComponentKind[];
  comparisonCount: number;
  requiredComparisonCount: number;
  allRequiredComponentsPresent: boolean;
  receiptReady: boolean;
  replayReady: boolean;
  divergenceReady: boolean;
  blockingDivergenceCount: number;
  unclassifiedDivergenceCount: number;
  ready: boolean;
  policyDecision: string;
  blockers: string[];
  evidenceRefs: string[];
}

export type WorkflowHarnessPromotionTransitionTarget = Extract<
  WorkflowHarnessExecutionMode,
  "gated" | "live"
>;

export interface WorkflowHarnessPromotionTransitionEligibility {
  schemaVersion:
    | "workflow.harness.promotion-transition-eligibility.v1"
    | string;
  clusterId: WorkflowHarnessPromotionClusterId;
  targetExecutionMode: WorkflowHarnessPromotionTransitionTarget;
  currentStatus: WorkflowHarnessClusterPromotionStatus;
  eligible: boolean;
  readinessReady: boolean;
  receiptReady: boolean;
  replayGateReady: boolean;
  canaryReady: boolean;
  rollbackReady: boolean;
  componentIds: string[];
  receiptRefs: string[];
  replayFixtureRefs: string[];
  canaryBoundaryId?: string;
  rollbackTarget?: string;
  blockers: string[];
  evidenceRefs: string[];
  createdAtMs: number;
}

export interface WorkflowHarnessPromotionTransitionAttempt {
  schemaVersion: "workflow.harness.promotion-transition-attempt.v1" | string;
  transitionId: string;
  workflowId: string;
  activationId?: string;
  clusterId: WorkflowHarnessPromotionClusterId;
  clusterLabel: string;
  targetExecutionMode: WorkflowHarnessPromotionTransitionTarget;
  previousStatus: WorkflowHarnessClusterPromotionStatus;
  nextStatus: WorkflowHarnessClusterPromotionStatus;
  attemptStatus: "blocked" | "promoted";
  gateDecision:
    | "block_promotion_transition"
    | "allow_promotion_transition"
    | string;
  eligibility: WorkflowHarnessPromotionTransitionEligibility;
  blockers: string[];
  receiptRefs: string[];
  replayFixtureRefs: string[];
  evidenceRefs: string[];
  createdAtMs: number;
}

export interface WorkflowHarnessLivePromotionClusterReadiness {
  clusterId: WorkflowHarnessPromotionClusterId;
  label: string;
  currentStatus: WorkflowHarnessClusterPromotionStatus;
  targetExecutionMode: Extract<WorkflowHarnessExecutionMode, "live">;
  componentKinds: WorkflowHarnessComponentKind[];
  readinessReady: boolean;
  receiptReady: boolean;
  replayGateReady: boolean;
  canaryReady: boolean;
  rollbackReady: boolean;
  divergenceReady: boolean;
  blockingDivergenceCount: number;
  unclassifiedDivergenceCount: number;
  attemptIds: string[];
  receiptRefs: string[];
  replayFixtureRefs: string[];
  actionFrameIds: string[];
  divergenceClasses: WorkflowHarnessDivergenceClass[];
  rollbackTarget: string;
  blockers: string[];
  decision: string;
}

export interface WorkflowHarnessLivePromotionReadinessProof {
  schemaVersion: "workflow.harness.live-promotion-readiness.v1" | string;
  proofId: string;
  dispatchId: string;
  workflowId: string;
  activationId: string;
  harnessHash: string;
  targetExecutionMode: Extract<WorkflowHarnessExecutionMode, "live">;
  requiredClusterIds: WorkflowHarnessPromotionClusterId[];
  clusterReadiness: WorkflowHarnessLivePromotionClusterReadiness[];
  liveShadowComparisonGate: WorkflowHarnessLiveShadowComparisonGate;
  liveShadowComparisonGateReady: boolean;
  allClustersReady: boolean;
  promotionEligible: boolean;
  defaultLiveActivationReady: boolean;
  invalidForkLiveActivationBlocked: boolean;
  rollbackAvailable: boolean;
  rollbackTarget: string;
  activationBlockers: string[];
  policyDecision: string;
  evidenceRefs: string[];
}

export type WorkflowHarnessActivationState =
  | "read_only"
  | "draft"
  | "blocked"
  | "validated"
  | "active";

export type WorkflowHarnessActivationCanaryStatus =
  | "not_run"
  | "blocked"
  | "passed"
  | "failed";

export type WorkflowRevisionSource = "git" | "file_hash_only" | string;

export interface WorkflowRevisionBinding {
  schemaVersion: "workflow.revision-binding.v1" | string;
  workflowPath: string;
  repoRoot?: string;
  branch?: string;
  baseRevision?: string;
  activatedRevision?: string;
  workflowContentHash: string;
  proposalId?: string;
  activationId?: string;
  rollbackActivationId?: string;
  rollbackRevision?: string;
  revisionSource: WorkflowRevisionSource;
  createdAtMs: number;
}

export interface WorkflowRevisionRestoreRequest {
  workflowPath: string;
  revisionBinding: WorkflowRevisionBinding;
  expectedWorkflowContentHash?: string;
  dryRun?: boolean;
}

export interface WorkflowRevisionRestoreResult {
  restored: boolean;
  dryRun?: boolean;
  blockers: string[];
  workflowPath: string;
  repoRoot?: string;
  relativeWorkflowPath?: string;
  revisionSource: WorkflowRevisionSource;
  restoredRevision?: string;
  restoreStrategy: "git_show_file_restore" | "unsupported" | string;
  expectedWorkflowContentHash?: string;
  actualWorkflowContentHash?: string;
  hashVerified?: boolean;
  receiptBindingRef?: string;
  fileSha256?: string;
  bundle?: WorkflowWorkbenchBundle;
}

export type WorkflowHarnessRollbackRestoreCanaryStatus =
  | "passed"
  | "blocked"
  | "not_required"
  | "not_run"
  | string;

export interface WorkflowHarnessRollbackRestoreCanary {
  schemaVersion: "workflow.harness.rollback-restore-canary.v1" | string;
  canaryId: string;
  status: WorkflowHarnessRollbackRestoreCanaryStatus;
  revisionSource: WorkflowRevisionSource;
  restoreStrategy:
    | "git_show_file_restore"
    | "file_hash_only_metadata_restore"
    | string;
  workflowPath: string;
  repoRoot?: string;
  relativeWorkflowPath?: string;
  restoredRevision?: string;
  restoredFileSha256?: string;
  expectedWorkflowContentHash?: string;
  actualWorkflowContentHash?: string;
  hashVerified: boolean;
  receiptBindingRef?: string;
  blockers: string[];
  evidenceRefs: string[];
  createdAtMs: number;
}

export type WorkflowHarnessForkMutationCanaryStatus =
  | "passed"
  | "blocked"
  | "not_run"
  | string;

export type WorkflowHarnessForkMutationKind =
  | "budget_gate_limit"
  | "retry_bound"
  | "verifier_threshold"
  | string;

export interface WorkflowHarnessForkMutationCanary {
  schemaVersion: "workflow.harness.fork-mutation-canary.v1" | string;
  canaryId: string;
  mutationId: string;
  mutationKind: WorkflowHarnessForkMutationKind;
  mutationScope: "workflow_policy" | "component_config" | string;
  workflowId: string;
  harnessWorkflowId: string;
  componentId: string;
  workflowNodeId: string;
  targetPath: string;
  beforeValue: string;
  afterValue: string;
  diffHash: string;
  proposalId: string;
  status: WorkflowHarnessForkMutationCanaryStatus;
  canaryStatus: WorkflowHarnessActivationCanaryStatus;
  replayFixtureRefs: string[];
  receiptRefs: string[];
  nodeAttemptIds: string[];
  nodeAttempts?: WorkflowHarnessNodeAttemptRecord[];
  evidenceRefs: string[];
  policyDecision: string;
  rollbackTarget: string;
  rollbackAvailable: boolean;
  blockers: string[];
  createdAtMs: number;
}

export interface WorkflowHarnessPackageEvidenceLink {
  kind:
    | "activation"
    | "fork_mutation_canary"
    | "canary_boundary"
    | "rollback_drill"
    | "rollback_restore"
    | "worker_handoff"
    | string;
  ref: string;
  hash: string;
}

export interface WorkflowHarnessPackageEvidenceManifest {
  schemaVersion: "workflow.harness.package-evidence-manifest.v1" | string;
  packageName: string;
  workflowId: string;
  harnessWorkflowId: string;
  activationId?: string;
  activationState?: WorkflowHarnessActivationState;
  harnessHash: string;
  workflowContentHash: string;
  reviewedPackageSnapshotHash?: string | null;
  rollbackTarget?: string;
  policyPosture?: WorkflowHarnessForkActivationRecord["policyPosture"];
  componentVersionSet: Record<string, string>;
  evidenceRefs: string[];
  receiptRefs: string[];
  replayFixtureRefs: string[];
  nodeAttemptIds: string[];
  forkMutationCanary?: WorkflowHarnessForkMutationCanary;
  forkMutationCanaryReceiptRefs: string[];
  forkMutationCanaryReplayFixtureRefs: string[];
  forkMutationCanaryNodeAttemptIds: string[];
  canaryBoundaryIds: string[];
  rollbackDrillIds: string[];
  workerHandoffNodeAttemptIds: string[];
  workerHandoffReceiptIds: string[];
  rollbackRestoreReceiptRefs: string[];
  deepLinks: WorkflowHarnessPackageEvidenceLink[];
  createdAtMs: number;
}

export interface WorkflowHarnessForkActivationRecord {
  schemaVersion: "workflow.harness.activation.v1" | string;
  workflowId: string;
  harnessWorkflowId: string;
  activationId?: string;
  harnessHash: string;
  activationState: WorkflowHarnessActivationState;
  activationBlockers: string[];
  componentVersionSet: Record<string, string>;
  policyPosture: "proposal_only" | "sandbox" | "canary" | "live";
  canaryStatus: WorkflowHarnessActivationCanaryStatus;
  rollbackTarget: string;
  rollbackAvailable: boolean;
  liveAuthorityTransferred: boolean;
  evidenceRefs: string[];
  workerBinding?: WorkflowHarnessWorkerBinding;
  workerBindingRegistryRecord?: WorkflowHarnessWorkerBindingRegistryRecord;
  workerAttachReceipt?: WorkflowHarnessWorkerAttachReceipt;
  workerAttachLifecycle?: WorkflowHarnessWorkerAttachLifecycleEvent[];
  workerSessionRecord?: WorkflowHarnessWorkerSessionRecord;
  workerLaunchEnvelopes?: WorkflowHarnessWorkerLaunchEnvelope[];
  workerHandoffReceipts?: WorkflowHarnessWorkerHandoffReceipt[];
  workerHandoffNodeAttemptIds?: string[];
  workerHandoffNodeAttempts?: WorkflowHarnessNodeAttemptRecord[];
  workerHandoffReplayFixtureRefs?: string[];
  revisionBinding?: WorkflowRevisionBinding;
  rollbackRevisionBinding?: WorkflowRevisionBinding;
  rollbackRestoreCanary?: WorkflowHarnessRollbackRestoreCanary;
  forkMutationCanary?: WorkflowHarnessForkMutationCanary;
  packageManifest?: WorkflowHarnessPackageEvidenceManifest;
  mintedAtMs?: number;
}

export type WorkflowHarnessActivationAuditEventType =
  | "dry_run_blocked"
  | "dry_run_mintable"
  | "activation_mint_blocked"
  | "activation_minted"
  | "promotion_transition_blocked"
  | "promotion_transition_promoted"
  | "replay_drill_blocked"
  | "replay_drill_passed"
  | "replay_gate_blocked"
  | "replay_gate_passed"
  | "rollback_target_selected"
  | "rollback_drill_blocked"
  | "rollback_drill_passed"
  | "rollback_execution_blocked"
  | "rollback_executed"
  | "active_runtime_rollback_apply_blocked"
  | "active_runtime_rollback_applied";

export type WorkflowHarnessActivationAuditEventStatus =
  | "blocked"
  | "passed"
  | "applied";

export interface WorkflowHarnessActivationAuditEvent {
  schemaVersion: "workflow.harness.activation-audit.v1" | string;
  eventId: string;
  eventType: WorkflowHarnessActivationAuditEventType;
  status: WorkflowHarnessActivationAuditEventStatus;
  workflowId: string;
  candidateId?: string;
  activationId?: string;
  previousActivationId?: string;
  nextActivationId?: string;
  previousWorkerBinding?: WorkflowHarnessWorkerBinding;
  nextWorkerBinding?: WorkflowHarnessWorkerBinding;
  previousRevisionBinding?: WorkflowRevisionBinding;
  nextRevisionBinding?: WorkflowRevisionBinding;
  rollbackTarget?: string;
  rollbackExecuted?: boolean;
  blockers: string[];
  evidenceRefs: string[];
  receiptRefs: string[];
  summary: string;
  createdAtMs: number;
}

export interface WorkflowHarnessActivationRollbackProof {
  schemaVersion: "workflow.harness.activation-rollback-proof.v1" | string;
  drillId: string;
  workflowId: string;
  activationId?: string;
  rollbackTarget: string;
  rollbackAvailable: boolean;
  rollbackExecuted: boolean;
  activeWorkerBinding?: WorkflowHarnessWorkerBinding;
  restoredWorkerBinding?: WorkflowHarnessWorkerBinding;
  activeRevisionBinding?: WorkflowRevisionBinding;
  restoredRevisionBinding?: WorkflowRevisionBinding;
  drillStatus: "not_run" | "passed" | "blocked" | "failed" | string;
  policyDecision: string;
  blockers: string[];
  evidenceRefs: string[];
  receiptRefs: string[];
  createdAtMs: number;
}

export interface WorkflowHarnessActivationRollbackExecution {
  schemaVersion: "workflow.harness.activation-rollback-execution.v1" | string;
  executionId: string;
  workflowId: string;
  activationId?: string;
  rollbackTarget: string;
  rollbackAvailable: boolean;
  rollbackExecuted: boolean;
  activeWorkerBinding?: WorkflowHarnessWorkerBinding;
  restoredWorkerBinding?: WorkflowHarnessWorkerBinding;
  activeRevisionBinding?: WorkflowRevisionBinding;
  restoredRevisionBinding?: WorkflowRevisionBinding;
  restoreStrategy:
    | "file_hash_only_metadata_restore"
    | "git_show_file_restore"
    | "worker_binding_restore"
    | string;
  restoreRepoRoot?: string;
  restoreRelativeWorkflowPath?: string;
  restoredRevision?: string;
  restoredFileSha256?: string;
  restoreBlockers?: string[];
  workflowPath: string;
  expectedWorkflowContentHash?: string;
  actualWorkflowContentHash?: string;
  hashVerified: boolean;
  executionStatus: "applied" | "blocked" | "failed" | string;
  policyDecision: string;
  blockers: string[];
  evidenceRefs: string[];
  receiptRefs: string[];
  restoreReceiptBindingRef?: string;
  createdAtMs: number;
}

export interface WorkflowHarnessActiveRuntimeRollbackExecutionProof {
  schemaVersion:
    | "workflow.harness.active-runtime-rollback-execution-proof.v1"
    | string;
  method: string;
  generatedAtMs: number;
  workflowId: string;
  activationId: string;
  rollbackTarget: string;
  readinessProofId: string;
  liveShadowComparisonGateId: string;
  liveShadowComparisonGateReady: boolean;
  harnessHash: string;
  policyDecision: string;
  launchEnvelopeId?: string | null;
  handoffReceiptId?: string | null;
  nodeAttemptId?: string | null;
  replayFixtureRef?: string | null;
  dryRun: {
    clicked: boolean;
    passed: boolean;
    canaryResultId?: string | null;
    canaryStatus: "passed" | "blocked" | string;
    canaryHashVerified: boolean;
    policyDecision: string;
    receiptRefs: string[];
    replayFixtureRefs: string[];
    blockers: string[];
  };
  apply: {
    attempted: boolean;
    disabled: boolean;
    readiness: "ready" | "blocked" | string;
    applied: boolean;
    policyDecision: string;
    executionId?: string | null;
    rollbackReceiptId?: string | null;
    auditEventId?: string | null;
    rollbackTargetVerified?: boolean;
    hashVerified?: boolean;
    receiptRefs?: string[];
    evidenceRefs?: string[];
    replayFixtureRefs?: string[];
    appliedAtMs?: number | null;
    blockers: string[];
  };
  routeRestore?: {
    hash?: string | null;
    selectedRailTestId?: string | null;
    rollbackProofBound: boolean;
    dryRunStatus?: string | null;
    applyDisabled: boolean;
    canaryResultId?: string | null;
    observedSelectedState?: Record<string, string>;
  };
  passed: boolean;
  blockers: string[];
}

export interface WorkflowHarnessActiveRuntimeRollbackApplyProof {
  schemaVersion:
    | "workflow.harness.active-runtime-rollback-apply-proof.v1"
    | string;
  method: string;
  generatedAtMs: number;
  workflowId: string;
  activationId: string;
  previousActivationId?: string | null;
  nextActivationId?: string | null;
  rollbackTarget: string;
  readinessProofId: string;
  liveShadowComparisonGateId: string;
  liveShadowComparisonGateReady: boolean;
  harnessHash: string;
  launchEnvelopeId?: string | null;
  handoffReceiptId?: string | null;
  nodeAttemptId?: string | null;
  replayFixtureRef?: string | null;
  dryRunCanaryResultId?: string | null;
  executionId: string;
  rollbackReceiptId: string;
  auditEventId: string;
  applyStatus: "applied" | "blocked" | string;
  rollbackApplied: boolean;
  rollbackTargetVerified: boolean;
  hashVerified: boolean;
  policyDecision: string;
  receiptRefs: string[];
  evidenceRefs: string[];
  replayFixtureRefs: string[];
  staleProofBlocked: boolean;
  detachedProofBlocked: boolean;
  blockers: string[];
  passed: boolean;
}

export interface WorkflowHarnessActiveRuntimeRollbackNegativeApplyProof {
  schemaVersion:
    | "workflow.harness.active-runtime-rollback-negative-apply-proof.v1"
    | string;
  method: string;
  generatedAtMs: number;
  workflowId: string;
  cases: Array<{
    caseId: string;
    mutationKind: "stale_proof" | "detached_proof" | string;
    expectedBlockers: string[];
    observedRailBlockers: string[];
    runtimeBlockers: string[];
    selectedRailTestId?: string | null;
    applyButtonDisabled: boolean;
    applyStatus: "blocked" | "applied" | string;
    staleProofBlocked: boolean;
    detachedProofBlocked: boolean;
    rollbackApplied: boolean;
    rollbackTargetVerified: boolean;
    hashVerified: boolean;
    rollbackReceiptId?: string | null;
    auditEventId?: string | null;
    passed: boolean;
  }>;
  passed: boolean;
  blockers: string[];
}

export type WorkflowHarnessReplayDrillDivergenceClass =
  | "none"
  | "harmless_metadata_drift"
  | "missing_receipt"
  | "policy_divergence"
  | "routing_divergence"
  | "output_divergence"
  | "behavioral_regression"
  | "fixture_unresolved";

export interface WorkflowHarnessReplayDrillResult {
  schemaVersion: "workflow.harness.replay-drill-result.v1" | string;
  drillId: string;
  workflowId: string;
  activationId?: string;
  replayFixtureRef: string;
  sourceKind: string;
  sourceLabel: string;
  drillStatus: "passed" | "blocked" | "failed" | string;
  divergenceClass: WorkflowHarnessReplayDrillDivergenceClass;
  componentId: string;
  producerComponent: string;
  attemptId: string;
  receiptRef: string;
  runId: string;
  executionMode: WorkflowHarnessExecutionMode | string;
  readiness: WorkflowHarnessComponentReadiness | string;
  policyDecision: string;
  expectedInputHash: string;
  actualInputHash: string;
  expectedOutputHash: string;
  actualOutputHash: string;
  deterministicEnvelope: boolean;
  capturesInput: boolean;
  capturesOutput: boolean;
  capturesPolicyDecision: boolean;
  determinism: WorkflowHarnessReplayDeterminism | string;
  redactionPolicy: string;
  blockers: string[];
  evidenceRefs: string[];
  receiptRefs: string[];
  createdAtMs: number;
}

export type WorkflowHarnessReplayGateScope =
  | "harness_group"
  | "activation_candidate"
  | "workflow";

export interface WorkflowHarnessReplayGateResult {
  schemaVersion: "workflow.harness.replay-gate-result.v1" | string;
  gateId: string;
  workflowId: string;
  activationId?: string;
  scopeKind: WorkflowHarnessReplayGateScope;
  targetId: string;
  gateStatus: "passed" | "blocked" | "failed" | string;
  totalFixtures: number;
  passedCount: number;
  blockedCount: number;
  failedCount: number;
  divergenceCounts: Record<string, number>;
  replayFixtureRefs: string[];
  blockingReplayFixtureRefs: string[];
  drillIds: string[];
  receiptRefs: string[];
  evidenceRefs: string[];
  activationGateImpact: "passed" | "blocked";
  blockers: string[];
  createdAtMs: number;
}

export type WorkflowHarnessPromotionClusterReplayGateStatus =
  | "not_run"
  | "passed"
  | "blocked"
  | "failed"
  | string;

export interface WorkflowHarnessPromotionClusterReplayGateProof {
  schemaVersion:
    | "workflow.harness.promotion-cluster-replay-gate-proof.v1"
    | string;
  clusterId: WorkflowHarnessPromotionClusterId;
  gateId?: string;
  gateStatus: WorkflowHarnessPromotionClusterReplayGateStatus;
  activationGateImpact: "pending" | "passed" | "blocked";
  totalFixtures: number;
  passedCount: number;
  blockedCount: number;
  failedCount: number;
  blockingDivergenceCount: number;
  replayFixtureRefs: string[];
  blockingReplayFixtureRefs: string[];
  receiptRefs: string[];
  evidenceRefs: string[];
  blockers: string[];
  verifiedAtMs?: number;
}

export type WorkflowHarnessActivationCandidateDecision = "blocked" | "mintable";

export type WorkflowHarnessActivationCandidateGateStatus = "passed" | "blocked";

export interface WorkflowHarnessActivationCandidateGateResult {
  gateId: string;
  label: string;
  status: WorkflowHarnessActivationCandidateGateStatus;
  value: string;
  detail: string;
  evidenceRefs: string[];
}

export interface WorkflowHarnessForkActivationCandidate {
  schemaVersion: "workflow.harness.activation-candidate.v1" | string;
  candidateId: string;
  workflowId: string;
  harnessWorkflowId: string;
  harnessHash: string;
  decision: WorkflowHarnessActivationCandidateDecision;
  activationId?: string;
  activationIdPreview?: string;
  dryRunOnly: true;
  activationBlockers: string[];
  blockerCodes: string[];
  gateResults: WorkflowHarnessActivationCandidateGateResult[];
  componentVersionSet: Record<string, string>;
  policyPosture: WorkflowHarnessForkActivationRecord["policyPosture"];
  canaryStatus: WorkflowHarnessActivationCanaryStatus;
  rollbackTarget: string;
  rollbackAvailable: boolean;
  rollbackRestoreCanary: WorkflowHarnessRollbackRestoreCanary;
  forkMutationCanary: WorkflowHarnessForkMutationCanary;
  workerBindingPreview: WorkflowHarnessWorkerBinding;
  revisionBindingPreview: WorkflowRevisionBinding;
  evidenceRefs: string[];
  createdAtMs: number;
}

export type WorkflowHarnessLiveHandoffSelector =
  | "workflow_recovery_blocked"
  | "blessed_workflow_gated"
  | "blessed_workflow_live_canary"
  | "blessed_workflow_live_default";

export type WorkflowHarnessRecoveryMode =
  | "fail_closed"
  | "restore_prior_workflow_activation";

export interface WorkflowHarnessDefaultPromotionGate {
  configKey: string;
  enabled: boolean;
  eligible: boolean;
  nonMutatingOnly: boolean;
  selector: WorkflowHarnessLiveHandoffSelector;
  productionDefaultSelector: WorkflowHarnessLiveHandoffSelector;
  defaultAuthorityTransferred: boolean;
  rollbackTarget: string;
  requiredInvariantIds?: string[];
  invariantBlockers?: string[];
  activationBlockers: string[];
  policyDecision: string;
}

export interface WorkflowHarnessLiveHandoffProof {
  schemaVersion: "workflow.harness.live-handoff.v1" | string;
  selector: WorkflowHarnessLiveHandoffSelector;
  availableSelectors: WorkflowHarnessLiveHandoffSelector[];
  productionDefaultSelector: WorkflowHarnessLiveHandoffSelector;
  workflowId: string;
  activationId: string;
  harnessHash: string;
  componentVersionSet: Record<string, string>;
  canaryStatus: WorkflowHarnessActivationCanaryStatus;
  canaryTurnRoutedThroughWorkflow: boolean;
  executionBoundaryId?: string;
  executionBoundaryIds?: string[];
  executionBoundaryClusterIds?: WorkflowHarnessPromotionClusterId[];
  executionBoundaryStatus?: string;
  executionBoundaryExecutor?: string;
  defaultAuthorityTransferred: boolean;
  runtimeAuthority:
    | "workflow_recovery_fail_closed"
    | "blessed_workflow_activation_canary"
    | string;
  recoveryMode: WorkflowHarnessRecoveryMode;
  recoveryTarget: string;
  recoveryAvailable: boolean;
  recoveryBlockers: string[];
  rollbackTarget: string;
  rollbackAvailable: boolean;
  policyDecision: string;
  gatedClusterIds: WorkflowHarnessPromotionClusterId[];
  nodeTimelineAttemptIds: string[];
  receiptIds: string[];
  replayFixtureRefs: string[];
  livePromotionReadinessProof?: WorkflowHarnessLivePromotionReadinessProof | null;
  livePromotionReadinessReady: boolean;
  livePromotionReadinessBlockers: string[];
  livePromotionReadinessPolicyDecision: string;
  defaultLivePromotionInvariantIds: string[];
  defaultLivePromotionInvariantBlockers: string[];
  reviewedImportActivationApplyProofPresent: boolean;
  reviewedImportActivationApplyProofPassed: boolean;
  reviewedImportActivationApplyProofBlockers: string[];
  reviewedImportActivationApplyActivationId: string | null;
  activationBlockers: string[];
  defaultPromotionGate?: WorkflowHarnessDefaultPromotionGate;
  evidenceRefs: string[];
}

export interface WorkflowHarnessRuntimeSelectorDecision {
  schemaVersion: "workflow.harness.runtime-selector.v1" | string;
  decisionId: string;
  requestedSelector: WorkflowHarnessLiveHandoffSelector | "auto_canary";
  selectedSelector: WorkflowHarnessLiveHandoffSelector;
  productionDefaultSelector: WorkflowHarnessLiveHandoffSelector;
  canaryEligible: boolean;
  canaryBlockers: string[];
  workflowId: string;
  activationId: string;
  harnessHash: string;
  executionMode: WorkflowHarnessExecutionMode;
  actualRuntimeAuthority:
    | "workflow_recovery_fail_closed"
    | "blessed_workflow_activation_canary"
    | string;
  recoveryMode: WorkflowHarnessRecoveryMode;
  recoveryTarget: string;
  recoveryAvailable: boolean;
  recoveryBlockers: string[];
  rollbackTarget: string;
  rollbackAvailable: boolean;
  policyDecision: string;
  routeReason: string;
  livePromotionReadinessProof?: WorkflowHarnessLivePromotionReadinessProof | null;
  livePromotionReadinessReady: boolean;
  livePromotionReadinessBlockers: string[];
  livePromotionReadinessPolicyDecision: string;
  defaultLivePromotionInvariantIds: string[];
  defaultLivePromotionInvariantBlockers: string[];
  reviewedImportActivationApplyProofPresent: boolean;
  reviewedImportActivationApplyProofPassed: boolean;
  reviewedImportActivationApplyProofBlockers: string[];
  reviewedImportActivationApplyActivationId: string | null;
  defaultPromotionGate?: WorkflowHarnessDefaultPromotionGate;
  evidenceRefs: string[];
}

export interface WorkflowHarnessCognitionNodeAuthorityGate {
  schemaVersion:
    | "workflow.harness.default-runtime-dispatch.cognition-node-authority.v1"
    | string;
  gateId: "cognition-node-authority" | string;
  authorityMode: "node_authoritative" | string;
  authoritative: boolean;
  workflowId: string;
  activationId: string;
  harnessHash: string;
  requiredExecutionMode: "live" | string;
  runtimeAuthority:
    | "workflow_recovery_fail_closed"
    | "blessed_workflow_activation_default"
    | string;
  adapterMode: "workflow_component_adapter_live" | string;
  componentKinds: WorkflowHarnessComponentKind[];
  liveReadyComponentKinds: WorkflowHarnessComponentKind[];
  actionFrameIds: string[];
  attemptIds: string[];
  receiptIds: string[];
  replayFixtureRefs: string[];
  recoveryMode: WorkflowHarnessRecoveryMode;
  recoveryTarget: string;
  recoveryAvailable: boolean;
  recoveryBlockers: string[];
  blockers: string[];
  policyDecision:
    | "allow_node_authoritative_cognition"
    | "block_node_authoritative_cognition"
    | string;
}

export interface WorkflowHarnessRoutingModelNodeAuthorityGate {
  schemaVersion:
    | "workflow.harness.default-runtime-dispatch.routing-model-node-authority.v1"
    | string;
  gateId: "routing-model-node-authority" | string;
  authorityMode: "gated_node_authoritative" | string;
  authoritative: boolean;
  workflowId: string;
  activationId: string;
  harnessHash: string;
  requiredExecutionMode: "gated" | string;
  runtimeAuthority:
    | "workflow_recovery_fail_closed"
    | "blessed_workflow_activation_default"
    | string;
  adapterMode: "workflow_component_adapter_gated" | string;
  componentKinds: WorkflowHarnessComponentKind[];
  shadowReadyComponentKinds: WorkflowHarnessComponentKind[];
  actionFrameIds: string[];
  attemptIds: string[];
  receiptIds: string[];
  replayFixtureRefs: string[];
  shadowAttemptIds: string[];
  shadowReceiptIds: string[];
  shadowReplayFixtureRefs: string[];
  divergenceClasses: WorkflowHarnessDivergenceClass[];
  shadowDivergenceClasses: WorkflowHarnessDivergenceClass[];
  providerCanaryReady: boolean;
  visibleOutputSelected: boolean;
  visibleOutputAuthority: "workflow_model_provider_call" | string;
  readOnlyCapabilityRoutingReady: boolean;
  rollbackAvailable: boolean;
  recoveryMode: WorkflowHarnessRecoveryMode;
  recoveryTarget: string;
  recoveryAvailable: boolean;
  recoveryBlockers: string[];
  blockers: string[];
  policyDecision:
    | "allow_gated_node_authoritative_routing_model"
    | "block_gated_node_authoritative_routing_model"
    | string;
}

export interface WorkflowHarnessVerificationOutputNodeAuthorityGate {
  schemaVersion:
    | "workflow.harness.default-runtime-dispatch.verification-output-node-authority.v1"
    | string;
  gateId: "verification-output-node-authority" | string;
  authorityMode: "gated_node_authoritative" | string;
  authoritative: boolean;
  workflowId: string;
  activationId: string;
  harnessHash: string;
  requiredExecutionMode: "gated" | string;
  runtimeAuthority:
    | "workflow_recovery_fail_closed"
    | "blessed_workflow_activation_default"
    | string;
  adapterMode: "workflow_component_adapter_gated" | string;
  componentKinds: WorkflowHarnessComponentKind[];
  shadowReadyComponentKinds: WorkflowHarnessComponentKind[];
  actionFrameIds: string[];
  attemptIds: string[];
  receiptIds: string[];
  replayFixtureRefs: string[];
  shadowAttemptIds: string[];
  shadowReceiptIds: string[];
  shadowReplayFixtureRefs: string[];
  divergenceClasses: WorkflowHarnessDivergenceClass[];
  shadowDivergenceClasses: WorkflowHarnessDivergenceClass[];
  outputWriterHandoffReady: boolean;
  outputWriterMaterializationCanaryReady: boolean;
  outputWriterStagedWriteCanaryReady: boolean;
  outputWriterVisibleWriteReady: boolean;
  outputWriterVisibleWriteCommitted: boolean;
  rollbackAvailable: boolean;
  recoveryMode: WorkflowHarnessRecoveryMode;
  recoveryTarget: string;
  recoveryAvailable: boolean;
  recoveryBlockers: string[];
  blockers: string[];
  policyDecision:
    | "allow_gated_node_authoritative_verification_output"
    | "block_gated_node_authoritative_verification_output"
    | string;
}

export interface WorkflowHarnessAuthorityToolingNodeAuthorityGate {
  schemaVersion:
    | "workflow.harness.default-runtime-dispatch.authority-tooling-node-authority.v1"
    | string;
  gateId: "authority-tooling-node-authority" | string;
  authorityMode: "gated_node_authoritative" | string;
  authoritative: boolean;
  workflowId: string;
  activationId: string;
  harnessHash: string;
  requiredExecutionMode: "gated" | string;
  runtimeAuthority:
    | "workflow_recovery_fail_closed"
    | "blessed_workflow_activation_default"
    | string;
  adapterMode: "workflow_component_adapter_gated" | string;
  componentKinds: WorkflowHarnessComponentKind[];
  shadowReadyComponentKinds: WorkflowHarnessComponentKind[];
  actionFrameIds: string[];
  attemptIds: string[];
  receiptIds: string[];
  replayFixtureRefs: string[];
  shadowAttemptIds: string[];
  shadowReceiptIds: string[];
  shadowReplayFixtureRefs: string[];
  divergenceClasses: WorkflowHarnessDivergenceClass[];
  shadowDivergenceClasses: WorkflowHarnessDivergenceClass[];
  readOnlyRouteAccepted: boolean;
  destructiveRouteDenied: boolean;
  mutatingToolCallsBlocked: boolean;
  sideEffectsExecuted: boolean;
  policyGateReady: boolean;
  toolRouterReady: boolean;
  dryRunSimulatorReady: boolean;
  approvalGateReady: boolean;
  gateLiveReady: boolean;
  readOnlyAuthorityCanaryReady: boolean;
  rollbackAvailable: boolean;
  recoveryMode: WorkflowHarnessRecoveryMode;
  recoveryTarget: string;
  recoveryAvailable: boolean;
  recoveryBlockers: string[];
  blockers: string[];
  policyDecision:
    | "allow_gated_node_authoritative_authority_tooling"
    | "block_gated_node_authoritative_authority_tooling"
    | string;
}

export interface WorkflowHarnessDefaultRuntimeDispatchProof {
  schemaVersion: "workflow.harness.default-runtime-dispatch.v1" | string;
  dispatchId: string;
  selectorDecisionId: string;
  selectedSelector: WorkflowHarnessLiveHandoffSelector;
  productionDefaultSelector: WorkflowHarnessLiveHandoffSelector;
  workflowId: string;
  activationId: string;
  harnessHash: string;
  executionMode: WorkflowHarnessExecutionMode;
  runtimeAuthority:
    | "workflow_recovery_fail_closed"
    | "blessed_workflow_activation_default"
    | string;
  dispatchScope:
    | "read_only_cognition_routing"
    | "read_only_cognition_routing_verification_completion"
    | "read_only_cognition_routing_verification_completion_authority_tooling"
    | string;
  acceptedClusterIds: WorkflowHarnessPromotionClusterId[];
  componentKinds: WorkflowHarnessComponentKind[];
  deferredComponentKinds: WorkflowHarnessComponentKind[];
  handoffValidatedComponentKinds: WorkflowHarnessComponentKind[];
  materializationCanaryComponentKinds: WorkflowHarnessComponentKind[];
  sourceBoundaryIds: string[];
  dispatchNodeAttemptIds: string[];
  dispatchNodeAttempts?: WorkflowHarnessNodeAttemptRecord[];
  cognitionExecutionAttemptIds: string[];
  cognitionExecutionReceiptIds: string[];
  cognitionExecutionReplayFixtureRefs: string[];
  cognitionExecutionAdapterMode: "workflow_component_adapter_live" | string;
  cognitionExecutionAdapterResults: WorkflowHarnessComponentAdapterResult[];
  cognitionExecutionActionFrameIds: string[];
  cognitionExecutionLiveReadyComponentKinds: WorkflowHarnessComponentKind[];
  cognitionExecutionShadowAdapterMode?:
    | "workflow_component_adapter_shadow"
    | string;
  cognitionExecutionShadowAttemptIds?: string[];
  cognitionExecutionShadowReceiptIds?: string[];
  cognitionExecutionShadowReplayFixtureRefs?: string[];
  cognitionExecutionShadowAdapterResults?: WorkflowHarnessComponentAdapterResult[];
  cognitionExecutionShadowActionFrameIds?: string[];
  cognitionExecutionShadowComponentKinds?: WorkflowHarnessComponentKind[];
  cognitionExecutionShadowDivergenceClasses?: WorkflowHarnessDivergenceClass[];
  liveShadowComparisons?: WorkflowHarnessShadowComparison[];
  liveShadowComparisonCount?: number;
  liveShadowComparisonGate?: WorkflowHarnessLiveShadowComparisonGate;
  liveShadowComparisonGateReady?: boolean;
  liveShadowBlockingDivergenceCount?: number;
  liveShadowUnclassifiedDivergenceCount?: number;
  cognitionExecutionGateAdapterMode:
    | "workflow_component_adapter_gated"
    | string;
  cognitionExecutionGateAttemptIds: string[];
  cognitionExecutionGateReceiptIds: string[];
  cognitionExecutionGateReplayFixtureRefs: string[];
  cognitionExecutionGateAdapterResults: WorkflowHarnessComponentAdapterResult[];
  cognitionExecutionGateActionFrameIds: string[];
  cognitionExecutionGateComponentKinds: WorkflowHarnessComponentKind[];
  cognitionExecutionGateDivergenceClasses: WorkflowHarnessDivergenceClass[];
  routingModelAdapterMode: "workflow_component_adapter_gated" | string;
  routingModelAttemptIds: string[];
  routingModelReceiptIds: string[];
  routingModelReplayFixtureRefs: string[];
  routingModelAdapterResults: WorkflowHarnessComponentAdapterResult[];
  routingModelActionFrameIds: string[];
  routingModelComponentKinds: WorkflowHarnessComponentKind[];
  routingModelDivergenceClasses: WorkflowHarnessDivergenceClass[];
  routingModelShadowAdapterMode?: "workflow_component_adapter_shadow" | string;
  routingModelShadowAttemptIds?: string[];
  routingModelShadowReceiptIds?: string[];
  routingModelShadowReplayFixtureRefs?: string[];
  routingModelShadowAdapterResults?: WorkflowHarnessComponentAdapterResult[];
  routingModelShadowActionFrameIds?: string[];
  routingModelShadowComponentKinds?: WorkflowHarnessComponentKind[];
  routingModelShadowDivergenceClasses?: WorkflowHarnessDivergenceClass[];
  routingModelAuthorityProof?: Record<string, unknown>;
  verificationOutputAdapterMode: "workflow_component_adapter_gated" | string;
  verificationOutputAttemptIds: string[];
  verificationOutputReceiptIds: string[];
  verificationOutputReplayFixtureRefs: string[];
  verificationOutputAdapterResults: WorkflowHarnessComponentAdapterResult[];
  verificationOutputActionFrameIds: string[];
  verificationOutputComponentKinds: WorkflowHarnessComponentKind[];
  verificationOutputDivergenceClasses: WorkflowHarnessDivergenceClass[];
  verificationOutputShadowAdapterMode?:
    | "workflow_component_adapter_shadow"
    | string;
  verificationOutputShadowAttemptIds?: string[];
  verificationOutputShadowReceiptIds?: string[];
  verificationOutputShadowReplayFixtureRefs?: string[];
  verificationOutputShadowAdapterResults?: WorkflowHarnessComponentAdapterResult[];
  verificationOutputShadowActionFrameIds?: string[];
  verificationOutputShadowComponentKinds?: WorkflowHarnessComponentKind[];
  verificationOutputShadowDivergenceClasses?: WorkflowHarnessDivergenceClass[];
  verificationOutputAuthorityProof?: Record<string, unknown>;
  authorityToolingAuthorityProof?: Record<string, unknown>;
  authorityToolingAdapterMode: "workflow_component_adapter_gated" | string;
  authorityToolingAttemptIds: string[];
  authorityToolingReceiptIds: string[];
  authorityToolingReplayFixtureRefs: string[];
  authorityToolingAdapterResults: WorkflowHarnessComponentAdapterResult[];
  authorityToolingActionFrameIds: string[];
  authorityToolingComponentKinds: WorkflowHarnessComponentKind[];
  authorityToolingDivergenceClasses: WorkflowHarnessDivergenceClass[];
  authorityToolingShadowAdapterMode?:
    | "workflow_component_adapter_shadow"
    | string;
  authorityToolingShadowAttemptIds?: string[];
  authorityToolingShadowReceiptIds?: string[];
  authorityToolingShadowReplayFixtureRefs?: string[];
  authorityToolingShadowAdapterResults?: WorkflowHarnessComponentAdapterResult[];
  authorityToolingShadowActionFrameIds?: string[];
  authorityToolingShadowComponentKinds?: WorkflowHarnessComponentKind[];
  authorityToolingShadowDivergenceClasses?: WorkflowHarnessDivergenceClass[];
  modelExecutionAttemptIds: string[];
  modelExecutionReceiptIds: string[];
  modelExecutionReplayFixtureRefs: string[];
  modelProviderCanaryAttemptIds: string[];
  modelProviderCanaryReceiptIds: string[];
  modelProviderCanaryReplayFixtureRefs: string[];
  modelProviderGatedVisibleOutputAttemptIds: string[];
  modelProviderGatedVisibleOutputReceiptIds: string[];
  modelProviderGatedVisibleOutputReplayFixtureRefs: string[];
  modelProviderGatedVisibleOutputRollbackDrillAttemptIds: string[];
  modelProviderGatedVisibleOutputRollbackDrillReceiptIds: string[];
  modelProviderGatedVisibleOutputRollbackDrillReplayFixtureRefs: string[];
  readOnlyCapabilityRoutingAttemptIds: string[];
  readOnlyCapabilityRoutingReceiptIds: string[];
  readOnlyCapabilityRoutingReplayFixtureRefs: string[];
  outputWriterHandoffAttemptIds: string[];
  outputWriterMaterializationCanaryAttemptIds: string[];
  outputWriterStagedWriteCanaryAttemptIds: string[];
  outputWriterVisibleWriteAttemptIds: string[];
  authorityToolingLiveDryRunAttemptIds: string[];
  authorityToolingReadOnlyLiveAttemptIds: string[];
  authorityToolingReadOnlyReceiptIds: string[];
  authorityToolingReadOnlyReplayFixtureRefs: string[];
  authorityToolingProviderCatalogLiveAttemptIds: string[];
  authorityToolingProviderCatalogLiveReceiptIds: string[];
  authorityToolingProviderCatalogLiveReplayFixtureRefs: string[];
  authorityToolingMcpToolCatalogLiveAttemptIds: string[];
  authorityToolingMcpToolCatalogLiveReceiptIds: string[];
  authorityToolingMcpToolCatalogLiveReplayFixtureRefs: string[];
  authorityToolingNativeToolCatalogLiveAttemptIds: string[];
  authorityToolingNativeToolCatalogLiveReceiptIds: string[];
  authorityToolingNativeToolCatalogLiveReplayFixtureRefs: string[];
  authorityToolingConnectorCatalogLiveAttemptIds: string[];
  authorityToolingConnectorCatalogLiveReceiptIds: string[];
  authorityToolingConnectorCatalogLiveReplayFixtureRefs: string[];
  authorityToolingWalletCapabilityLiveDryRunAttemptIds: string[];
  authorityToolingWalletCapabilityLiveDryRunReceiptIds: string[];
  authorityToolingWalletCapabilityLiveDryRunReplayFixtureRefs: string[];
  authorityToolingGateLiveAttemptIds: string[];
  authorityToolingGateLiveReceiptIds: string[];
  authorityToolingGateLiveReplayFixtureRefs: string[];
  authorityToolingPolicyGateLiveAttemptIds: string[];
  authorityToolingPolicyGateLiveReceiptIds: string[];
  authorityToolingPolicyGateLiveReplayFixtureRefs: string[];
  authorityToolingDestructiveDenialLiveAttemptIds: string[];
  authorityToolingDestructiveDenialLiveReceiptIds: string[];
  authorityToolingDestructiveDenialLiveReplayFixtureRefs: string[];
  authorityToolingApprovalGateLiveAttemptIds: string[];
  authorityToolingApprovalGateLiveReceiptIds: string[];
  authorityToolingApprovalGateLiveReplayFixtureRefs: string[];
  authorityToolingReadOnlyComponentKinds: WorkflowHarnessComponentKind[];
  authorityToolingMutationDeferredComponentKinds: WorkflowHarnessComponentKind[];
  authorityToolingDenialReceiptIds: string[];
  acceptedNodeAttemptIds: string[];
  nodeAttemptIds: string[];
  receiptIds: string[];
  replayFixtureRefs: string[];
  executorKind: "workflow_node_executor" | string;
  executorRef: string;
  synchronous: boolean;
  drivesRuntimeDecision: boolean;
  activationIdGateClickProofPresent: boolean;
  activationIdGateClickProofPassed: boolean;
  activationIdGateClickProofBlockers: string[];
  defaultLivePromotionInvariantIds: string[];
  defaultLivePromotionInvariantBlockers: string[];
  reviewedImportActivationApplyProofPresent: boolean;
  reviewedImportActivationApplyProofPassed: boolean;
  reviewedImportActivationApplyProofBlockers: string[];
  reviewedImportActivationApplyActivationId: string | null;
  defaultDispatchActivationBlockers: string[];
  activationIdGate?: {
    schemaVersion:
      | "workflow.harness.default-runtime-dispatch.activation-id-gate.v1"
      | string;
    gateId: "activation-id" | string;
    proofPresent: boolean;
    proofPassed: boolean;
    proofBlockers: string[];
    workflowId: string;
    activationId: string;
    workerBindingActivationId: string;
    defaultDispatchActivationBlockers: string[];
  };
  reviewedImportActivationApplyGate?: {
    schemaVersion:
      | "workflow.harness.default-runtime-dispatch.reviewed-import-activation-apply-gate.v1"
      | string;
    gateId: "reviewed-import-activation-apply" | string;
    invariantId: "reviewed_import_activation_apply" | string;
    proofPresent: boolean;
    proofPassed: boolean;
    proofBlockers: string[];
    activationId: string | null;
    workerBindingActivationId: string | null;
    rollbackTarget: string | null;
    reviewedPackageSnapshotHash: string | null;
    reviewedWorkflowContentHash: string | null;
    reviewedHarnessWorkflowId: string | null;
  reviewedReplayFixtureRefs: string[];
  reviewedWorkerHandoffNodeAttemptIds: string[];
  reviewedWorkerHandoffReceiptIds: string[];
  reviewedForkMutationCanaryId?: string | null;
  reviewedForkMutationCanaryStatus?: string | null;
  reviewedForkMutationCanaryDiffHash?: string | null;
  reviewedForkMutationCanaryReceiptRefs?: string[];
  reviewedForkMutationCanaryReplayFixtureRefs?: string[];
  reviewedForkMutationCanaryNodeAttemptIds?: string[];
  reviewedForkMutationCanaryRollbackTarget?: string | null;
  reviewedPolicyPosture: string | null;
  defaultDispatchActivationBlockers: string[];
  };
  cognitionNodeAuthorityGate?: WorkflowHarnessCognitionNodeAuthorityGate;
  routingModelNodeAuthorityGate?: WorkflowHarnessRoutingModelNodeAuthorityGate;
  verificationOutputNodeAuthorityGate?: WorkflowHarnessVerificationOutputNodeAuthorityGate;
  authorityToolingNodeAuthorityGate?: WorkflowHarnessAuthorityToolingNodeAuthorityGate;
  cognitionExecutionMode: "workflow_synchronous_envelope" | string;
  cognitionExecutionReady: boolean;
  promptAssemblyMode: "workflow_synchronous_envelope" | string;
  promptAssemblyPromptHash: string;
  promptAssemblyPromptHashMatches: boolean;
  cognitionExecutionProof?: Record<string, unknown>;
  modelExecutionMode: "workflow_synchronous_envelope" | string;
  modelExecutionEnvelopeReady: boolean;
  modelExecutionBindingId: string;
  modelExecutionBindingReady: boolean;
  modelExecutionPromptHash: string;
  modelExecutionPromptHashMatches: boolean;
  modelExecutionOutputHash: string;
  modelExecutionOutputHashMatches: boolean;
  modelExecutionProviderInvocationMode:
    | "workflow_recovery_fail_closed_invocation"
    | "workflow_provider_canary"
    | string;
  modelExecutionLowLevelInvocationDeferred: boolean;
  modelExecutionRecoveryMode: WorkflowHarnessRecoveryMode;
  modelExecutionLatencyMs: number;
  modelProviderCanaryMode: "workflow_provider_canary" | string;
  modelProviderCanaryReady: boolean;
  modelProviderCanaryCandidateOutputHash: string;
  modelProviderCanaryPriorWorkflowOutputHash: string;
  modelProviderCanaryOutputHashMatches: boolean;
  modelProviderCanaryTranscriptMatches: boolean;
  modelProviderCanaryRecoveryReady: boolean;
  modelProviderCanaryRollbackAvailable: boolean;
  modelProviderCanaryProof?: Record<string, unknown>;
  modelProviderGatedVisibleOutputMode:
    | "workflow_provider_gated_visible_output"
    | string;
  modelProviderGatedVisibleOutputEnabled: boolean;
  modelProviderGatedVisibleOutputReady: boolean;
  modelProviderGatedVisibleOutputSelected: boolean;
  modelProviderGatedVisibleOutputEligible: boolean;
  modelProviderGatedVisibleOutputScenario:
    | "retained_no_tool_answer"
    | "retained_repo_grounded_answer"
    | "retained_planning_without_mutation"
    | "retained_mermaid_rendering"
    | "retained_source_heavy_synthesis"
    | "retained_probe_behavior"
    | "retained_harness_dogfooding"
    | string;
  modelProviderGatedVisibleOutputCohort:
    | "retained_read_only_no_tool"
    | "default_promoted_read_only_no_tool"
    | string;
  modelProviderGatedVisibleOutputRetainedReadOnlyNoTool: boolean;
  modelProviderGatedVisibleOutputRequiredScenarioSet: string[];
  modelProviderGatedVisibleOutputScenarioCoverageKey?: string | null;
  modelProviderGatedVisibleOutputActivationFlag: string;
  modelProviderGatedVisibleOutputActivationId: string;
  modelProviderGatedVisibleOutputAuthority:
    | "workflow_model_provider_call"
    | string;
  modelProviderGatedVisibleOutputRollbackTarget: string;
  modelProviderGatedVisibleOutputRollbackAvailable: boolean;
  selectedVisibleOutputAuthority: "workflow_model_provider_call" | string;
  selectedVisibleOutputHash: string;
  workflowProviderVisibleOutputHash: string;
  priorWorkflowVisibleOutputHash: string;
  priorWorkflowVisibleOutputComputed: boolean;
  priorWorkflowVisibleOutputHashMatchesSelected: boolean;
  selectedVisibleOutputAuthorityMatchesTranscript: boolean;
  visibleOutputDivergenceClass?: string | null;
  modelProviderGatedVisibleOutputProof?: Record<string, unknown>;
  modelProviderGatedVisibleOutputRollbackDrillEnabled: boolean;
  modelProviderGatedVisibleOutputRollbackDrillReady: boolean;
  modelProviderGatedVisibleOutputRollbackDrillFailureInjected: boolean;
  modelProviderGatedVisibleOutputRollbackDrillInjectedOutputHash: string;
  modelProviderGatedVisibleOutputRollbackDrillOutputHashDiverges: boolean;
  modelProviderGatedVisibleOutputRollbackDrillDivergenceClass:
    | "provider_output_hash_divergence"
    | string;
  modelProviderGatedVisibleOutputRollbackDrillRecoveryMode: WorkflowHarnessRecoveryMode;
  modelProviderGatedVisibleOutputRollbackDrillSelectedAuthority:
    | "workflow_model_recovery_fail_closed"
    | string;
  modelProviderGatedVisibleOutputRollbackDrillTranscriptUnchanged: boolean;
  modelProviderGatedVisibleOutputRollbackDrillRollbackExecuted: boolean;
  modelProviderGatedVisibleOutputRollbackDrillActivationBlockers: string[];
  modelProviderGatedVisibleOutputRollbackDrillProof?: Record<string, unknown>;
  readOnlyCapabilityRoutingMode:
    | "workflow_read_only_capability_routing"
    | string;
  readOnlyCapabilityRoutingReady: boolean;
  readOnlyCapabilityRoutingSelected: boolean;
  readOnlyCapabilityRoutingEligible: boolean;
  readOnlyCapabilityRoutingScenario:
    | "retained_repo_grounded_answer"
    | "retained_source_heavy_synthesis"
    | "retained_probe_behavior"
    | string;
  readOnlyCapabilityRoutingRequiredScenarioSet: string[];
  readOnlyCapabilityRoutingScenarioCoverageKey?: string | null;
  readOnlyCapabilityRoutingSourceMaterialReady: boolean;
  readOnlyCapabilityRoutingNoMutationReady: boolean;
  readOnlyCapabilityRoutingWorkflowOwnedNodeKinds: WorkflowHarnessComponentKind[];
  readOnlyCapabilityRoutingProof?: Record<string, unknown>;
  verificationOutputProof?: Record<string, unknown>;
  authorityToolingAdapterProof?: Record<string, unknown>;
  livePromotionReadinessProof: WorkflowHarnessLivePromotionReadinessProof;
  workerBindingRegistryRecord: WorkflowHarnessWorkerBindingRegistryRecord;
  workerAttachReceipt: WorkflowHarnessWorkerAttachReceipt;
  workerAttachResumeReceipt: WorkflowHarnessWorkerAttachReceipt;
  workerAttachRollbackReceipt: WorkflowHarnessWorkerAttachReceipt;
  workerAttachLifecycle: WorkflowHarnessWorkerAttachLifecycleEvent[];
  workerAttachLifecycleAttemptIds: string[];
  workerAttachLifecycleStatuses: WorkflowHarnessWorkerAttachStatus[];
  workerAttachLifecycleComplete: boolean;
  workerSessionRecord: WorkflowHarnessWorkerSessionRecord;
  workerLaunchEnvelopes: WorkflowHarnessWorkerLaunchEnvelope[];
  workerHandoffReceipts: WorkflowHarnessWorkerHandoffReceipt[];
  workerLaunchEnvelopeIds: string[];
  workerHandoffReceiptIds: string[];
  workerHandoffNodeAttemptIds: string[];
  workerHandoffNodeAttempts: WorkflowHarnessNodeAttemptRecord[];
  workerHandoffReplayFixtureRefs: string[];
  modelExecutionProof?: Record<string, unknown>;
  outputAuthority: "workflow_recovery_fail_closed" | string;
  outputWriterDeferred: boolean;
  outputWriterStatus:
    | "deferred"
    | "handoff_validated"
    | "materialization_canary_ready"
    | "staged_write_canary_ready"
    | "visible_write_committed"
    | "blocked"
    | string;
  outputWriterHandoffReady: boolean;
  outputWriterAuthorityTransferred: boolean;
  outputWriterMaterializationMode:
    | "guarded_canary"
    | "isolated_staging_canary"
    | "workflow_visible_transcript_write"
    | string;
  outputWriterMaterializationCanaryReady: boolean;
  outputWriterMaterializationCommitted: boolean;
  outputWriterStagedWriteMode: "isolated_checkpoint_blob" | string;
  outputWriterStagedWriteCanaryReady: boolean;
  outputWriterStagedWritePersisted: boolean;
  outputWriterStagedWriteCommitted: boolean;
  outputWriterStagedWriteVisible: boolean;
  outputWriterStagedWriteExcludedFromVisibleTranscript: boolean;
  outputWriterStagedWriteRollbackStatus:
    | "deleted"
    | "not_deleted"
    | "missing"
    | string;
  outputWriterStagedWriteRollbackVerified: boolean;
  outputWriterVisibleWriteMode: "workflow_visible_transcript_write" | string;
  outputWriterVisibleWriteReady: boolean;
  outputWriterVisibleWritePersisted: boolean;
  outputWriterVisibleWriteCommitted: boolean;
  outputWriterVisibleWriteVisible: boolean;
  outputWriterVisibleWriteIdentityCheckpointPersisted: boolean;
  outputWriterVisibleWriteRecoveryDuplicateSuppressed: boolean;
  authorityToolingMode: "workflow_live_dry_run" | string;
  authorityToolingReady: boolean;
  authorityToolingPolicyGateReady: boolean;
  authorityToolingToolRouterReady: boolean;
  authorityToolingDryRunSimulatorReady: boolean;
  authorityToolingApprovalGateReady: boolean;
  authorityToolingGateLiveReady: boolean;
  authorityToolingPolicyGateLiveReady: boolean;
  authorityToolingDestructiveDenialLiveReady: boolean;
  authorityToolingApprovalGateLiveReady: boolean;
  authorityToolingReadOnlyAuthorityCanaryReady: boolean;
  authorityToolingProviderCatalogLiveReady: boolean;
  authorityToolingProviderCatalogLiveComponentKind:
    | WorkflowHarnessComponentKind
    | string;
  authorityToolingMcpToolCatalogLiveReady: boolean;
  authorityToolingMcpToolCatalogLiveComponentKind:
    | WorkflowHarnessComponentKind
    | string;
  authorityToolingNativeToolCatalogLiveReady: boolean;
  authorityToolingNativeToolCatalogLiveComponentKind:
    | WorkflowHarnessComponentKind
    | string;
  authorityToolingConnectorCatalogLiveReady: boolean;
  authorityToolingConnectorCatalogLiveComponentKind:
    | WorkflowHarnessComponentKind
    | string;
  authorityToolingWalletCapabilityLiveDryRunReady: boolean;
  authorityToolingWalletCapabilityLiveDryRunComponentKind:
    | WorkflowHarnessComponentKind
    | string;
  authorityToolingReadOnlyRouteAccepted: boolean;
  authorityToolingDestructiveRouteDenied: boolean;
  authorityToolingMutatingToolCallsBlocked: boolean;
  authorityToolingSideEffectsExecuted: boolean;
  authorityToolingRollbackAvailable: boolean;
  authorityToolingProof?: Record<string, unknown>;
  workflowTranscriptRecoveryAuthorityRetained: boolean;
  workflowTranscriptRecoveryAvailable?: boolean;
  proposedVisibleOutputHash: string;
  actualVisibleOutputHash: string;
  outputHashAlgorithm: "runtime_prompt_hash:v1" | string;
  outputHashMatches: boolean;
  outputHashDivergence: boolean;
  outputHashDivergenceCount: number;
  workflowTranscriptWriteCandidate?: Record<string, unknown>;
  workflowTranscriptWriteRecord?: Record<string, unknown>;
  visibleTranscriptWriteProof?: Record<string, unknown>;
  workflowTranscriptRecoveryProof?: Record<string, unknown>;
  workflowTranscriptRecoveryRecord?: Record<string, unknown>;
  stagedTranscriptWriteRecord?: Record<string, unknown>;
  stagedTranscriptWriteProof?: Record<string, unknown>;
  transcriptMaterializationContentHashMatches: boolean;
  transcriptMaterializationOrderMatches: boolean;
  transcriptMaterializationReceiptBindingMatches: boolean;
  transcriptMaterializationTargetMatches: boolean;
  transcriptMaterializationMatches: boolean;
  transcriptMaterializationDivergenceCount: number;
  stagedTranscriptWriteContentHashMatches: boolean;
  stagedTranscriptWriteOrderMatches: boolean;
  stagedTranscriptWriteReceiptBindingMatches: boolean;
  stagedTranscriptWriteTargetMatches: boolean;
  stagedTranscriptWriteMatches: boolean;
  stagedTranscriptWriteDivergenceCount: number;
  visibleTranscriptWriteContentHashMatches: boolean;
  visibleTranscriptWriteOrderMatches: boolean;
  visibleTranscriptWriteReceiptBindingMatches: boolean;
  visibleTranscriptWriteTargetMatches: boolean;
  visibleTranscriptWriteMatches: boolean;
  visibleTranscriptWriteDivergenceCount: number;
  stagedTranscriptWriteComparison?: {
    contentHashMatches: boolean;
    orderMatches: boolean;
    receiptBindingMatches: boolean;
    targetMatches: boolean;
    stagedWritePersisted: boolean;
    stagedWriteCommitted: boolean;
    stagedWriteVisible: boolean;
    excludedFromVisibleTranscript: boolean;
    rollbackStatus: string;
    rollbackVerified: boolean;
    matches: boolean;
    divergenceClass?: "staged_transcript_write_divergence" | null | string;
  };
  transcriptMaterializationComparison?: {
    contentHashMatches: boolean;
    orderMatches: boolean;
    receiptBindingMatches: boolean;
    targetMatches: boolean;
    candidateCommitted: boolean;
    priorWorkflowCommitted: boolean;
    recoveryDuplicateSuppressed?: boolean;
    matches: boolean;
    divergenceClass?: "transcript_materialization_divergence" | null | string;
  };
  visibleTranscriptWriteComparison?: {
    contentHashMatches: boolean;
    orderMatches: boolean;
    receiptBindingMatches: boolean;
    targetMatches: boolean;
    workflowWritePersisted: boolean;
    workflowWriteCommitted: boolean;
    workflowWriteVisible: boolean;
    identityCheckpointPersisted: boolean;
    recoveryDuplicateSuppressed: boolean;
    matches: boolean;
    divergenceClass?: "visible_transcript_write_divergence" | null | string;
  };
  outputHashComparison?: {
    proposedVisibleOutputHash: string;
    actualVisibleOutputHash: string;
    hashAlgorithm: "runtime_prompt_hash:v1" | string;
    matches: boolean;
    divergenceClass?: "output_hash_divergence" | null | string;
  };
  workflowOutputRecoveryAuthorityRetained: boolean;
  workflowOutputRecoveryAvailable?: boolean;
  mutatingTurnsBlocked: boolean;
  rollbackTarget: string;
  rollbackAvailable: boolean;
  activationBlockers: string[];
  policyDecision: string;
  evidenceRefs: string[];
}

export interface WorkflowHarnessDeepLinkReplayCase {
  id:
    | "selector"
    | "dispatch"
    | "worker"
    | "rollback"
    | "receipt"
    | "replay"
    | "revision"
    | "activation-blocker"
    | "activation-audit"
    | "activation-gate"
    | "activation-gate-evidence"
    | "activation-gate-canary-boundary"
    | "activation-gate-canary-rollback-drill"
    | "activation-gate-node-attempt"
    | "activation-gate-receipt"
    | "activation-gate-replay"
    | "live-turn-node-inspector"
    | string;
  hash: string;
  expectedPanel: WorkflowRightPanel;
  expectedAttribute: string;
  expectedValue: string;
  selectedRailTestId: string;
  openedHash: string;
  parsedMatches: boolean;
  historyMatches: boolean;
  observedValue: string | null;
  observedSelectedState: Record<string, string>;
  passed: boolean;
}

export interface WorkflowHarnessDeepLinkReplayProof {
  schemaVersion: "workflow.harness.deep-link-replay-proof.v1" | string;
  method: string;
  generatedAtMs: number;
  cases: WorkflowHarnessDeepLinkReplayCase[];
  passed: boolean;
  blockers: string[];
}

export interface WorkflowHarnessActivationGateActionClickProof {
  schemaVersion:
    | "workflow.harness.activation-gate-action-click-proof.v1"
    | string;
  method: string;
  generatedAtMs: number;
  gateId: string | null;
  action: {
    id: string | null;
    kind: string | null;
    impact: string | null;
    command: string | null;
    disabled: boolean;
  };
  before: {
    hash: string | null;
    railTestId: string | null;
    selectedState: Record<string, string>;
  };
  after: {
    railTestId: string | null;
    statusMessage: string | null;
    readinessPanelVisible: boolean;
    readinessSummaryVisible: boolean;
  };
  clicked: boolean;
  passed: boolean;
  blockers: string[];
}

export interface WorkflowHarnessPackageEvidenceGateClickProof {
  schemaVersion:
    | "workflow.harness.package-evidence-gate-click-proof.v1"
    | string;
  method: string;
  generatedAtMs: number;
  gateId: string | null;
  manifest: {
    present: boolean;
    schemaVersion: string | null;
    status: string | null;
    evidenceRefCount: number;
    receiptRefCount: number;
    replayFixtureRefCount: number;
    rollbackRestoreReceiptRefCount: number;
    forkMutationCanaryReceiptRefCount: number;
    forkMutationCanaryReplayFixtureRefCount: number;
    forkMutationCanaryNodeAttemptCount: number;
    workerHandoffNodeAttemptCount: number;
    workerHandoffReceiptCount: number;
    deepLinkCount: number;
    blockerCount: number;
  };
  selectedRefs: {
    evidenceRef: string | null;
	    receiptRef: string | null;
	    replayFixtureRef: string | null;
	    nodeAttemptId: string | null;
	    mutationCanaryId?: string | null;
	    mutationCanaryReceiptRef?: string | null;
	    mutationCanaryReplayFixtureRef?: string | null;
	    mutationCanaryNodeAttemptId?: string | null;
	    mutationCanaryDiffHash?: string | null;
	    mutationCanaryRollbackTarget?: string | null;
	    packageDeepLinkRef: string | null;
	    packageDeepLinkHash: string | null;
	  };
  before: {
    hash: string | null;
    railTestId: string | null;
    selectedState: Record<string, string>;
  };
  restored: {
    evidenceState: Record<string, string>;
	    receiptState: Record<string, string>;
	    replayState: Record<string, string>;
	    nodeAttemptState: Record<string, string>;
	    mutationCanaryState?: Record<string, string>;
	    mutationCanaryNodeAttemptState?: Record<string, string>;
	    mutationCanaryTimelineAttemptId?: string | null;
	    packageDeepLinkState: Record<string, string>;
	  };
  clicked: boolean;
  passed: boolean;
  blockers: string[];
}

export interface WorkflowHarnessPackageEvidenceImportRoundTripProof {
  schemaVersion:
    | "workflow.harness.package-evidence-import-roundtrip-proof.v1"
    | string;
  method: string;
  generatedAtMs: number;
  exportedPackagePath: string | null;
  exportedManifestPath: string | null;
  importedWorkflowPath: string | null;
  validImport: {
    workflowId: string | null;
    workflowSlug: string | null;
    gateId: string | null;
    activationReadinessStatus: string | null;
    manifest: WorkflowHarnessPackageEvidenceGateClickProof["manifest"];
    rowStatuses: Record<string, string>;
    selectedRefs: WorkflowHarnessPackageEvidenceGateClickProof["selectedRefs"];
    restored: WorkflowHarnessPackageEvidenceGateClickProof["restored"];
    clicked: boolean;
  };
  incompleteImport: {
    workflowId: string | null;
    gateId: string | null;
    activationReadinessStatus: string | null;
    readinessBlockerCodes: string[];
    manifest: WorkflowHarnessPackageEvidenceGateClickProof["manifest"];
    rowStatuses: Record<string, string>;
    missingRows: string[];
  };
  passed: boolean;
  blockers: string[];
}

export interface WorkflowHarnessPackageImportReviewProof {
  schemaVersion:
    | "workflow.harness.package-import-review-proof.v1"
    | string;
  method: string;
  generatedAtMs: number;
  review: WorkflowPackageImportReview | null;
  railState: Record<string, string>;
  gateId: string | null;
  activationAction: {
    valid: {
      present: boolean;
      disabled: boolean;
      evidenceReady: boolean;
      blockerCount: number;
      integrityBlockerCount?: number;
    };
    incomplete: {
      present: boolean;
      disabled: boolean;
      evidenceReady: boolean;
      blockerCount: number;
      integrityBlockerCount?: number;
    };
  };
  sourceWorkflowPath: string | null;
  importedWorkflowPath: string | null;
  passed: boolean;
  blockers: string[];
}

export interface WorkflowHarnessPackageImportActivationHandoffProof {
  schemaVersion:
    | "workflow.harness.package-import-activation-handoff-proof.v1"
    | string;
  method: string;
  generatedAtMs: number;
  review: WorkflowPackageImportReview | null;
  railState: Record<string, string>;
  activationAction: {
    valid: {
      present: boolean;
      disabled: boolean;
      evidenceReady: boolean;
      blockerCount: number;
      handoffPresent: boolean;
      handoffDecision: string | null;
      activationIdPreview: string | null;
      canaryStatus: string | null;
      mutationCanaryId?: string | null;
      mutationCanaryStatus?: string | null;
      mutationCanaryDiffHash?: string | null;
      mutationCanaryReceiptRef?: string | null;
      mutationCanaryReplayFixtureRef?: string | null;
      mutationCanaryNodeAttemptId?: string | null;
      mutationCanaryRollbackTarget?: string | null;
      rollbackTarget: string | null;
      workerBindingId: string | null;
      mintable: boolean;
    };
    incomplete: {
      present: boolean;
      disabled: boolean;
      evidenceReady: boolean;
      blockerCount: number;
      handoffPresent: boolean;
      handoffDecision: string | null;
      activationIdPreview: string | null;
      canaryStatus: string | null;
      mutationCanaryId?: string | null;
      mutationCanaryStatus?: string | null;
      mutationCanaryDiffHash?: string | null;
      mutationCanaryReceiptRef?: string | null;
      mutationCanaryReplayFixtureRef?: string | null;
      mutationCanaryNodeAttemptId?: string | null;
      mutationCanaryRollbackTarget?: string | null;
      rollbackTarget: string | null;
      workerBindingId: string | null;
      mintable: boolean;
    };
  };
  deepLinks: {
    activationId: Record<string, string>;
    canary: Record<string, string>;
    mutationCanary?: Record<string, string>;
    rollbackRestore: Record<string, string>;
    workerBinding: Record<string, string>;
  };
  passed: boolean;
  blockers: string[];
}

export interface WorkflowHarnessPackageImportActivationApplyProof {
  schemaVersion:
    | "workflow.harness.package-import-activation-apply-proof.v1"
    | string;
  method: string;
  generatedAtMs: number;
  review: WorkflowPackageImportReview | null;
  clicked: boolean;
  beforeState: Record<string, string>;
  afterState: Record<string, string>;
  activationAction: {
    present: boolean;
    disabled: boolean;
    evidenceReady: boolean;
    blockerCount: number;
    handoffPresent: boolean;
    handoffDecision: string | null;
    activationIdPreview: string | null;
    canaryStatus: string | null;
    mutationCanaryId?: string | null;
    mutationCanaryStatus?: string | null;
    mutationCanaryDiffHash?: string | null;
    mutationCanaryReceiptRef?: string | null;
    mutationCanaryReplayFixtureRef?: string | null;
    mutationCanaryNodeAttemptId?: string | null;
    mutationCanaryRollbackTarget?: string | null;
    rollbackTarget: string | null;
    workerBindingId: string | null;
    mintable: boolean;
  };
  activationResult: {
    applied: boolean;
    activationId: string | null;
    blockers: string[];
    workflowActivationId: string | null;
    workflowActivationState: string | null;
    workerBindingActivationId: string | null;
    activationRecordWorkerBindingActivationId: string | null;
    rollbackTarget: string | null;
    revisionBindingActivationId: string | null;
    activationRecordRevisionBindingHash: string | null;
    rollbackRevisionBindingHash: string | null;
    activationAuditEventCount: number;
    latestAuditEventId: string | null;
    latestAuditEventType: string | null;
    latestAuditStatus: string | null;
    receiptRefs: string[];
    evidenceRefs: string[];
    workerHandoffReceiptIds: string[];
    workerHandoffNodeAttemptIds: string[];
    workerHandoffReplayFixtureRefs: string[];
    reviewedPackageSnapshotHash: string | null;
    reviewedWorkflowContentHash: string | null;
    reviewedActivationId: string | null;
    reviewedHarnessWorkflowId: string | null;
    reviewedWorkerBindingActivationId: string | null;
    reviewedRollbackTarget: string | null;
    reviewedReplayFixtureRefs: string[];
    reviewedWorkerHandoffNodeAttemptIds: string[];
    reviewedWorkerHandoffReceiptIds: string[];
    reviewedForkMutationCanaryId?: string | null;
    reviewedForkMutationCanaryStatus?: string | null;
    reviewedForkMutationCanaryDiffHash?: string | null;
    reviewedForkMutationCanaryReceiptRefs?: string[];
    reviewedForkMutationCanaryReplayFixtureRefs?: string[];
    reviewedForkMutationCanaryNodeAttemptIds?: string[];
    reviewedForkMutationCanaryRollbackTarget?: string | null;
    reviewedPolicyPosture: string | null;
    statusMessage: string;
  } | null;
  workerHandoff: {
    deepLinkHash: string | null;
    selectedState: Record<string, string>;
    timelineVisible: boolean;
    selectedAttemptId: string | null;
  };
  mutationCanary?: {
    deepLinkHash: string | null;
    selectedState: Record<string, string>;
    nodeAttemptState: Record<string, string>;
    timelineVisible: boolean;
    selectedAttemptId: string | null;
  };
  incompleteAction: {
    present: boolean;
    disabled: boolean;
    evidenceReady: boolean;
    blockerCount: number;
    handoffPresent: boolean;
    handoffDecision: string | null;
    activationIdPreview: string | null;
    canaryStatus: string | null;
    mutationCanaryId?: string | null;
    mutationCanaryStatus?: string | null;
    mutationCanaryDiffHash?: string | null;
    mutationCanaryReceiptRef?: string | null;
    mutationCanaryReplayFixtureRef?: string | null;
    mutationCanaryNodeAttemptId?: string | null;
    mutationCanaryRollbackTarget?: string | null;
    rollbackTarget: string | null;
    workerBindingId: string | null;
    mintable: boolean;
  };
  passed: boolean;
  blockers: string[];
}

export interface WorkflowHarnessPackageImportActivationReplayIntegrityProof {
  schemaVersion:
    | "workflow.harness.package-import-activation-replay-integrity-proof.v1"
    | string;
  method: string;
  generatedAtMs: number;
  sourceWorkflowPath: string | null;
  importedWorkflowPath: string | null;
  cases: Array<{
    caseId: string;
    mutationKind:
      | "snapshot_hash_mismatch"
      | "workflow_hash_mismatch"
      | "activation_id_mismatch"
      | "worker_binding_mismatch"
      | "rollback_target_mismatch"
      | "replay_fixture_mismatch"
      | "fork_mutation_canary_mismatch"
      | "policy_posture_mismatch"
      | string;
    expectedBlocker: string;
    railState: Record<string, string>;
    action: {
      present: boolean;
      disabled: boolean;
      evidenceReady: boolean;
      blockerCount: number;
      integrityBlockerCount: number;
      handoffPresent: boolean;
      handoffDecision: string | null;
      activationIdPreview: string | null;
      canaryStatus: string | null;
      mutationCanaryId?: string | null;
      mutationCanaryStatus?: string | null;
      mutationCanaryDiffHash?: string | null;
      mutationCanaryReceiptRef?: string | null;
      mutationCanaryReplayFixtureRef?: string | null;
      mutationCanaryNodeAttemptId?: string | null;
      mutationCanaryRollbackTarget?: string | null;
      rollbackTarget: string | null;
      workerBindingId: string | null;
      mintable: boolean;
    };
    runtimeBlockers: string[];
    defaultLivePromotionBlockers: string[];
    passed: boolean;
  }>;
  passed: boolean;
  blockers: string[];
}

export interface WorkflowHarnessActivationGateCollectEvidenceClickProof {
  schemaVersion:
    | "workflow.harness.activation-gate-collect-evidence-click-proof.v1"
    | string;
  method: string;
  generatedAtMs: number;
  gateId: string | null;
  action: {
    id: string | null;
    kind: string | null;
    impact: string | null;
    command: string | null;
    disabled: boolean;
  };
  before: {
    hash: string | null;
    railTestId: string | null;
    selectedState: Record<string, string>;
  };
  replayGate: {
    gateId: string | null;
    gateStatus: string | null;
    activationGateImpact: string | null;
    scopeKind: string | null;
    targetId: string | null;
    totalFixtures: number;
    replayFixtureRefs: string[];
    receiptRefs: string[];
    evidenceRefs: string[];
    persistedReplayGateCount: number;
    persistedReplayDrillCount: number;
  };
  after: {
    railTestId: string | null;
    statusMessage: string | null;
    inspectorState: Record<string, string>;
  };
  clicked: boolean;
  passed: boolean;
  blockers: string[];
}

export interface WorkflowHarnessActivationGateRollbackRestoreClickProof {
  schemaVersion:
    | "workflow.harness.activation-gate-rollback-restore-click-proof.v1"
    | string;
  method: string;
  generatedAtMs: number;
  gateId: string | null;
  action: {
    id: string | null;
    kind: string | null;
    impact: string | null;
    command: string | null;
    disabled: boolean;
  };
  before: {
    hash: string | null;
    railTestId: string | null;
    selectedState: Record<string, string>;
  };
  dryRun: {
    candidateId: string | null;
    decision: string | null;
    activationBlockerCount: number;
    rollbackRestoreCanaryId: string | null;
    rollbackRestoreStatus: string | null;
    rollbackRestoreRevisionSource: string | null;
    rollbackRestoreStrategy: string | null;
    rollbackRestoreHashVerified: boolean;
    rollbackRestoreReceiptBindingRef: string | null;
    rollbackRestoreEvidenceRefs: string[];
    rollbackRestoreBlockers: string[];
    rollbackRestoreGateStatus: string | null;
    persistedActivationAuditEventCount: number;
    latestAuditEventId: string | null;
    latestAuditEventType: string | null;
    latestAuditStatus: string | null;
  };
  after: {
    railTestId: string | null;
    statusMessage: string | null;
    inspectorState: Record<string, string>;
  };
  rollbackRestoreDeepLink?: string | null;
  rollbackRestoreDeepLinkState?: Record<string, string>;
  clicked: boolean;
  passed: boolean;
  blockers: string[];
}

export interface WorkflowHarnessActivationIdGateClickProof {
  schemaVersion: "workflow.harness.activation-id-gate-click-proof.v1" | string;
  method: string;
  generatedAtMs: number;
  blockedDryRun: {
    gateId: string | null;
    action: {
      id: string | null;
      kind: string | null;
      impact: string | null;
      command: string | null;
      disabled: boolean;
    };
    beforeState: Record<string, string>;
    afterState: Record<string, string>;
    clicked: boolean;
    candidateId: string | null;
    decision: string | null;
    activationBlockerCount: number;
    workflowActivationId: string | null;
    workflowActivationState: string | null;
    latestAuditEventType: string | null;
    latestAuditStatus: string | null;
  };
  mintedActivation: {
    gateId: string | null;
    action: {
      id: string | null;
      kind: string | null;
      impact: string | null;
      command: string | null;
      disabled: boolean;
    };
    beforeState: Record<string, string>;
    afterState: Record<string, string>;
    clicked: boolean;
    applied: boolean;
    activationId: string | null;
    workflowActivationId: string | null;
    workflowActivationState: string | null;
    workerBindingActivationId: string | null;
    activationRecordWorkerBindingActivationId: string | null;
    rollbackTarget: string | null;
    revisionBindingActivationId: string | null;
    activationRecordRevisionBindingHash: string | null;
    rollbackRevisionBindingHash: string | null;
    latestAuditEventType: string | null;
    latestAuditStatus: string | null;
    receiptRefs: string[];
    evidenceRefs: string[];
    workerHandoffReceiptIds?: string[];
    workerHandoffNodeAttemptIds?: string[];
    workerHandoffReplayFixtureRefs?: string[];
    workerHandoffDeepLink?: string | null;
    workerHandoffDeepLinkState?: Record<string, string>;
    workerHandoffTimelineVisible?: boolean;
    workerHandoffTimelineAttemptId?: string | null;
  };
  passed: boolean;
  blockers: string[];
}

export interface WorkflowHarnessWorkerInvariantNegativeEnforcementProof {
  schemaVersion:
    | "workflow.harness.worker-invariant-negative-enforcement-proof.v1"
    | string;
  method: string;
  generatedAtMs: number;
  forkWorkflowId: string;
  invalidCandidate: {
    candidateId: string | null;
    decision: string | null;
    activationIdPreview: string | null;
    activationBlockers: string[];
  };
  deepLink: {
    hash: string | null;
    selectedRailTestId: string;
    gateId: string | null;
    status: string | null;
    requiredInvariantIds: string[];
    invariantBlockers: string[];
    invariantBlockerCount: number;
    action: {
      id: string | null;
      kind: string | null;
      impact: string | null;
      command: string | null;
      disabled: boolean;
    };
    inspectorState: Record<string, string>;
  };
  activationApply: {
    attempted: boolean;
    applied: boolean;
    activationId: string | null;
    blockers: string[];
    workflowActivationId: string | null;
    workflowActivationState: string | null;
    workerBindingAuthorityReady: boolean;
    workerSessionLive: boolean;
    workerLaunchEnvelopeCount: number;
    workerHandoffReceiptCount: number;
    workerHandoffNodeAttemptCount: number;
    latestAuditEventType: string | null;
    latestAuditStatus: string | null;
  };
  passed: boolean;
  blockers: string[];
}

export interface WorkflowHarnessColdStartDeepLinkRestoreCase extends WorkflowHarnessDeepLinkReplayCase {
  initialHash: string;
  workflowReloaded: boolean;
  restoredFromInitialHash: boolean;
}

export interface WorkflowHarnessColdStartDeepLinkRestoreProof {
  schemaVersion:
    | "workflow.harness.cold-start-deep-link-restore-proof.v1"
    | string;
  method: string;
  generatedAtMs: number;
  cases: WorkflowHarnessColdStartDeepLinkRestoreCase[];
  passed: boolean;
  blockers: string[];
}

export interface WorkflowHarnessCanaryRollbackDrill {
  schemaVersion: "workflow.harness.canary-rollback-drill.v1" | string;
  drillId: string;
  selectorDecisionId: string;
  failureInjected: boolean;
  failedNodeId?: string;
  clusterId?: WorkflowHarnessPromotionClusterId;
  failureClass?: string;
  observedFailure?: boolean;
  rollbackExecuted: boolean;
  rollbackSelector: WorkflowHarnessLiveHandoffSelector;
  recoveryMode: WorkflowHarnessRecoveryMode;
  recoveryTarget: string;
  recoveryAvailable: boolean;
  recoveryBlockers: string[];
  rollbackTarget: string;
  rollbackAvailable: boolean;
  drillStatus: "not_run" | "passed" | "failed" | string;
  policyDecision: string;
  evidenceRefs?: string[];
}

export interface WorkflowHarnessCanaryExecutionBoundary {
  schemaVersion: "workflow.harness.canary-execution-boundary.v1" | string;
  boundaryId: string;
  clusterId: WorkflowHarnessPromotionClusterId;
  clusterLabel: string;
  selectorDecisionId: string;
  selectedSelector: WorkflowHarnessLiveHandoffSelector;
  productionDefaultSelector: WorkflowHarnessLiveHandoffSelector;
  workflowId: string;
  activationId: string;
  harnessHash: string;
  executionMode: WorkflowHarnessExecutionMode;
  runtimeAuthority:
    | "workflow_recovery_fail_closed"
    | "blessed_workflow_activation_canary"
    | string;
  executorKind: "workflow_node_executor" | string;
  executorRef: string;
  synchronous: boolean;
  enforcedBeforeVisibleOutput: boolean;
  canaryEligible: boolean;
  status: "blocked" | "passed" | "rolled_back" | string;
  componentKinds: WorkflowHarnessComponentKind[];
  executedComponentKinds: WorkflowHarnessComponentKind[];
  workflowNodeIds: string[];
  nodeAttemptIds: string[];
  nodeAttempts?: unknown[];
  receiptIds: string[];
  replayFixtureRefs: string[];
  activationBlockers: string[];
  rollbackTarget: string;
  rollbackAvailable: boolean;
  rollbackDrill: WorkflowHarnessCanaryRollbackDrill;
  policyDecision: string;
  evidenceRefs: string[];
}

export type WorkflowHarnessComponentKind =
  | "planner"
  | "prompt_assembler"
  | "task_state"
  | "uncertainty_gate"
  | "probe_runner"
  | "budget_gate"
  | "capability_sequencer"
  | "model_router"
  | "model_call"
  | "tool_router"
  | "tool_call"
  | "dry_run_simulator"
  | "mcp_provider"
  | "mcp_tool_call"
  | "connector_call"
  | "policy_gate"
  | "approval_gate"
  | "wallet_capability"
  | "memory_read"
  | "memory_search"
  | "memory_list"
  | "memory_write"
  | "memory_subagent_inheritance"
  | "runtime_doctor"
  | "runtime_task"
  | "runtime_job"
  | "runtime_checklist"
  | "runtime_thread_fork"
  | "runtime_operator_interrupt"
  | "runtime_operator_steer"
  | "runtime_thread_mode"
  | "runtime_workspace_trust_gate"
  | "runtime_context_compact"
  | "runtime_approval_request"
  | "runtime_usage_meter"
  | "runtime_context_budget"
  | "runtime_compaction_policy"
  | "runtime_rollback_snapshot"
  | "runtime_restore_gate"
  | "runtime_diagnostics_repair"
  | "runtime_coding_tool_budget_recovery"
  | "workflow_package_export"
  | "workflow_package_import"
  | "repository_context"
  | "branch_policy"
  | "github_context"
  | "issue_context"
  | "pr_attempt"
  | "review_gate"
  | "github_pr_create"
  | "skill_registry"
  | "hook_registry"
  | "hook_policy"
  | "verifier"
  | "semantic_impact_analyzer"
  | "postcondition_synthesizer"
  | "drift_detector"
  | "quality_ledger"
  | "handoff_bridge"
  | "gui_harness_validator"
  | "output_writer"
  | "receipt_writer"
  | "retry_policy"
  | "repair_loop"
  | "merge_judge"
  | "completion_gate";

export type WorkflowHarnessSlotKind =
  | "model_policy"
  | "tool_grant_policy"
  | "state_policy"
  | "budget_policy"
  | "dry_run_policy"
  | "verifier_policy"
  | "approval_policy"
  | "output_policy"
  | "memory_policy"
  | "quality_ledger_policy"
  | "handoff_policy"
  | "retry_repair_policy";

export interface WorkflowHarnessRetryBehavior {
  maxAttempts: number;
  backoffMs: number;
  retryableErrors: string[];
}

export interface WorkflowHarnessTimeoutBehavior {
  timeoutMs: number;
  cancellation: "cooperative" | "hard" | "none";
}

export interface WorkflowHarnessApprovalSemantics {
  required: boolean;
  mode: "none" | "policy_gate" | "human_gate" | "wallet_capability";
  reason: string;
}

export interface WorkflowHarnessComponentSpec {
  componentId: string;
  version: string;
  kind: WorkflowHarnessComponentKind;
  readiness: WorkflowHarnessComponentReadiness;
  label: string;
  description: string;
  kernelRef: string;
  inputSchema: unknown;
  outputSchema: unknown;
  errorSchema: unknown;
  timeout: WorkflowHarnessTimeoutBehavior;
  retry: WorkflowHarnessRetryBehavior;
  requiredCapabilityScope: string[];
  approval: WorkflowHarnessApprovalSemantics;
  emittedEvents: string[];
  evidence: string[];
  ui: {
    icon: string;
    group: string;
    summary: string;
    localeKey?: string;
    ariaLabelKey?: string;
    statusAnnouncementKey?: string;
    accessibleStatusField?: string;
    colorIndependentStatus?: boolean;
  };
}

export interface WorkflowHarnessSlotSpec {
  slotId: string;
  kind: WorkflowHarnessSlotKind;
  label: string;
  description: string;
  required: boolean;
  allowedComponentKinds: WorkflowHarnessComponentKind[];
  defaultComponentId?: string;
  validation: {
    blocksActivation: boolean;
    reason: string;
  };
}

export interface WorkflowHarnessNodeBinding {
  componentId: string;
  componentVersion: string;
  componentKind: WorkflowHarnessComponentKind;
  executionMode: WorkflowHarnessExecutionMode;
  readiness: WorkflowHarnessComponentReadiness;
  kernelRef: string;
  slotIds?: string[];
  evidenceEventKinds: string[];
  receiptKinds: string[];
  replayEnvelope: WorkflowHarnessReplayEnvelope;
  replay: {
    deterministicEnvelope: boolean;
    capturesInput: boolean;
    capturesOutput: boolean;
    capturesPolicyDecision: boolean;
  };
}

export interface WorkflowHarnessLiveGuiProbeDiagnostics {
  schemaVersion: "workflow.harness.live-gui-probe-diagnostics.v1" | string;
  status: "blocked" | "passed" | string;
  phase: string;
  error?: string;
  proofWorkflowPath?: string;
  generatedAtMs: number;
}

export interface WorkflowHarnessMetadata {
  schemaVersion: "workflow.harness.v1" | string;
  harnessWorkflowId: string;
  harnessVersion: string;
  harnessHash: string;
  executionMode: WorkflowHarnessExecutionMode;
  templateName: string;
  blessed: boolean;
  forkable: boolean;
  forkedFrom?: {
    harnessWorkflowId: string;
    harnessVersion: string;
    harnessHash: string;
  };
  packageName?: string;
  packageManifest?: WorkflowHarnessPackageEvidenceManifest;
  activationId?: string;
  activationState?: WorkflowHarnessActivationState;
  activationRecord?: WorkflowHarnessForkActivationRecord;
  activationAudit?: WorkflowHarnessActivationAuditEvent[];
  activationRollbackProof?: WorkflowHarnessActivationRollbackProof;
  activationRollbackExecution?: WorkflowHarnessActivationRollbackExecution;
  promotionTransitions?: WorkflowHarnessPromotionTransitionAttempt[];
  replayDrills?: WorkflowHarnessReplayDrillResult[];
  replayGates?: WorkflowHarnessReplayGateResult[];
  forkMutationCanary?: WorkflowHarnessForkMutationCanary;
  revisionBinding?: WorkflowRevisionBinding;
  liveHandoffProof?: WorkflowHarnessLiveHandoffProof;
  runtimeSelectorDecision?: WorkflowHarnessRuntimeSelectorDecision;
  defaultRuntimeDispatchProof?: WorkflowHarnessDefaultRuntimeDispatchProof;
  liveGuiProbeDiagnostics?: WorkflowHarnessLiveGuiProbeDiagnostics;
  workerBindingRegistryRecord?: WorkflowHarnessWorkerBindingRegistryRecord;
  workerAttachReceipt?: WorkflowHarnessWorkerAttachReceipt;
  workerAttachLifecycle?: WorkflowHarnessWorkerAttachLifecycleEvent[];
  workerSessionRecord?: WorkflowHarnessWorkerSessionRecord;
  workerLaunchEnvelopes?: WorkflowHarnessWorkerLaunchEnvelope[];
  workerHandoffReceipts?: WorkflowHarnessWorkerHandoffReceipt[];
  workerHandoffNodeAttemptIds?: string[];
  workerHandoffNodeAttempts?: WorkflowHarnessNodeAttemptRecord[];
  workerHandoffReplayFixtureRefs?: string[];
  deepLinkReplayProof?: WorkflowHarnessDeepLinkReplayProof;
  coldStartDeepLinkRestoreProof?: WorkflowHarnessColdStartDeepLinkRestoreProof;
  activationBlockerDeepLinkProof?: WorkflowHarnessDeepLinkReplayProof;
  activationGateDeepLinkProof?: WorkflowHarnessDeepLinkReplayProof;
  liveActivationGateDeepLinkProof?: WorkflowHarnessDeepLinkReplayProof;
  liveTurnNodeInspectorDeepLinkProof?: WorkflowHarnessDeepLinkReplayProof;
  liveShadowComparisonDeepLinkProof?: WorkflowHarnessDeepLinkReplayProof;
  activeRuntimeRollbackProofWorkbenchProof?: WorkflowHarnessDeepLinkReplayProof;
  activeRuntimeRollbackExecutionProof?: WorkflowHarnessActiveRuntimeRollbackExecutionProof;
  activeRuntimeRollbackApplyProof?: WorkflowHarnessActiveRuntimeRollbackApplyProof;
  activeRuntimeRollbackNegativeApplyProof?: WorkflowHarnessActiveRuntimeRollbackNegativeApplyProof;
  activationGateActionClickProof?: WorkflowHarnessActivationGateActionClickProof;
  packageEvidenceGateClickProof?: WorkflowHarnessPackageEvidenceGateClickProof;
  packageEvidenceImportRoundTripProof?: WorkflowHarnessPackageEvidenceImportRoundTripProof;
  packageImportReviewProof?: WorkflowHarnessPackageImportReviewProof;
  packageImportActivationHandoffProof?: WorkflowHarnessPackageImportActivationHandoffProof;
  packageImportActivationApplyProof?: WorkflowHarnessPackageImportActivationApplyProof;
  packageImportActivationReplayIntegrityProof?: WorkflowHarnessPackageImportActivationReplayIntegrityProof;
  activationGateCollectEvidenceClickProof?: WorkflowHarnessActivationGateCollectEvidenceClickProof;
  activationGateRollbackRestoreClickProof?: WorkflowHarnessActivationGateRollbackRestoreClickProof;
  activationIdGateClickProof?: WorkflowHarnessActivationIdGateClickProof;
  workerInvariantNegativeEnforcementProof?: WorkflowHarnessWorkerInvariantNegativeEnforcementProof;
  canaryExecutionBoundary?: WorkflowHarnessCanaryExecutionBoundary;
  canaryExecutionBoundaries?: WorkflowHarnessCanaryExecutionBoundary[];
  validationGates: string[];
  aiMutationMode: "proposal_only";
  componentIds: string[];
  slotIds: string[];
  componentReadiness?: Record<string, WorkflowHarnessComponentReadiness>;
  promotionClusters?: WorkflowHarnessPromotionCluster[];
}

export interface WorkflowHarnessWorkerBinding {
  harnessWorkflowId: string;
  harnessActivationId?: string;
  harnessHash: string;
  executionMode?: WorkflowHarnessExecutionMode;
  source: "default" | "fork" | "recovery";
  selectorDecisionId?: string;
  defaultDispatchId?: string;
  rollbackTarget?: string;
  authorityBindingReady?: boolean;
  authorityBindingBlockers?: string[];
  livePromotionReadinessProofId?: string;
  liveShadowComparisonGateId?: string;
  liveShadowComparisonGateReady?: boolean;
  rollbackPolicyDecision?: string;
  policyDecision?: string;
  requiredInvariantIds?: string[];
  invariantBlockers?: string[];
}

export type WorkflowHarnessWorkerBindingStatus =
  | "projection"
  | "blocked"
  | "canary"
  | "bound"
  | string;

export interface WorkflowHarnessWorkerBindingRegistryRecord {
  schemaVersion: "workflow.harness.worker-binding-registry.v1" | string;
  registryRecordId: string;
  workflowId: string;
  activationId: string;
  activationHash: string;
  harnessHash: string;
  reviewedPackageSnapshotHash: string | null;
  reviewedWorkflowContentHash: string | null;
  reviewedActivationId: string | null;
  reviewedHarnessWorkflowId: string | null;
  reviewedWorkerBindingActivationId: string | null;
  reviewedRollbackTarget: string | null;
  reviewedReplayFixtureRefs: string[];
  reviewedWorkerHandoffNodeAttemptIds: string[];
  reviewedWorkerHandoffReceiptIds: string[];
  reviewedForkMutationCanaryId?: string | null;
  reviewedForkMutationCanaryStatus?: string | null;
  reviewedForkMutationCanaryDiffHash?: string | null;
  reviewedForkMutationCanaryReceiptRefs?: string[];
  reviewedForkMutationCanaryReplayFixtureRefs?: string[];
  reviewedForkMutationCanaryNodeAttemptIds?: string[];
  reviewedForkMutationCanaryRollbackTarget?: string | null;
  reviewedPolicyPosture: string | null;
  componentVersionSet: Record<string, string>;
  rollbackTarget: string;
  readinessProofId: string;
  rollbackReadinessProofId: string;
  rollbackLiveShadowComparisonGateId: string;
  rollbackLiveShadowComparisonGateReady: boolean;
  rollbackActivationId: string;
  rollbackHarnessHash: string;
  rollbackPolicyDecision: string;
  canaryResultId: string;
  policyDecision: string;
  bindingStatus: WorkflowHarnessWorkerBindingStatus;
  blockers: string[];
  requiredInvariantIds?: string[];
  invariantBlockers?: string[];
  workerBinding: WorkflowHarnessWorkerBinding;
  createdAtMs?: number;
}

export type WorkflowHarnessWorkerAttachStatus =
  | "unbound"
  | "blocked"
  | "canary"
  | "bound"
  | "resumed"
  | "rolled_back"
  | string;

export interface WorkflowHarnessWorkerAttachRequest {
  schemaVersion: "workflow.harness.worker-attach-request.v1" | string;
  requestId: string;
  workerId: string;
  workflowId: string;
  activationId: string;
  activationHash: string;
  harnessHash: string;
  reviewedPackageSnapshotHash: string | null;
  reviewedWorkflowContentHash: string | null;
  reviewedActivationId: string | null;
  reviewedHarnessWorkflowId: string | null;
  reviewedWorkerBindingActivationId: string | null;
  reviewedRollbackTarget: string | null;
  reviewedReplayFixtureRefs: string[];
  reviewedWorkerHandoffNodeAttemptIds: string[];
  reviewedWorkerHandoffReceiptIds: string[];
  reviewedForkMutationCanaryId?: string | null;
  reviewedForkMutationCanaryStatus?: string | null;
  reviewedForkMutationCanaryDiffHash?: string | null;
  reviewedForkMutationCanaryReceiptRefs?: string[];
  reviewedForkMutationCanaryReplayFixtureRefs?: string[];
  reviewedForkMutationCanaryNodeAttemptIds?: string[];
  reviewedForkMutationCanaryRollbackTarget?: string | null;
  reviewedPolicyPosture: string | null;
  componentVersionSet: Record<string, string>;
  rollbackTarget: string;
  readinessProofId: string;
  rollbackReadinessProofId: string;
  rollbackLiveShadowComparisonGateId: string;
  rollbackLiveShadowComparisonGateReady: boolean;
  rollbackActivationId: string;
  rollbackHarnessHash: string;
  rollbackPolicyDecision: string;
  requiredInvariantIds?: string[];
  requestedStatus: WorkflowHarnessWorkerAttachStatus;
}

export interface WorkflowHarnessWorkerAttachReceipt {
  schemaVersion: "workflow.harness.worker-attach-receipt.v1" | string;
  receiptId: string;
  workerId: string;
  workflowId: string;
  activationId: string;
  activationHash: string;
  harnessHash: string;
  reviewedPackageSnapshotHash: string | null;
  reviewedWorkflowContentHash: string | null;
  reviewedActivationId: string | null;
  reviewedHarnessWorkflowId: string | null;
  reviewedWorkerBindingActivationId: string | null;
  reviewedRollbackTarget: string | null;
  reviewedReplayFixtureRefs: string[];
  reviewedWorkerHandoffNodeAttemptIds: string[];
  reviewedWorkerHandoffReceiptIds: string[];
  reviewedForkMutationCanaryId?: string | null;
  reviewedForkMutationCanaryStatus?: string | null;
  reviewedForkMutationCanaryDiffHash?: string | null;
  reviewedForkMutationCanaryReceiptRefs?: string[];
  reviewedForkMutationCanaryReplayFixtureRefs?: string[];
  reviewedForkMutationCanaryNodeAttemptIds?: string[];
  reviewedForkMutationCanaryRollbackTarget?: string | null;
  reviewedPolicyPosture: string | null;
  componentVersionSet: Record<string, string>;
  rollbackTarget: string;
  rollbackAvailable: boolean;
  readinessProofId: string;
  rollbackReadinessProofId: string;
  rollbackLiveShadowComparisonGateId: string;
  rollbackLiveShadowComparisonGateReady: boolean;
  rollbackActivationId: string;
  rollbackHarnessHash: string;
  rollbackPolicyDecision: string;
  registryRecordId: string;
  bindingStatus: WorkflowHarnessWorkerBindingStatus;
  attachStatus: WorkflowHarnessWorkerAttachStatus;
  accepted: boolean;
  blockers: string[];
  workerBinding: WorkflowHarnessWorkerBinding;
  policyDecision: string;
  requiredInvariantIds?: string[];
  invariantBlockers?: string[];
  evidenceRefs: string[];
  createdAtMs?: number;
}

export type WorkflowHarnessWorkerAttachLifecyclePhase =
  | "attach"
  | "resume"
  | "rollback"
  | string;

export interface WorkflowHarnessWorkerAttachLifecycleEvent {
  schemaVersion: "workflow.harness.worker-attach-lifecycle.v1" | string;
  eventId: string;
  sequence: number;
  phase: WorkflowHarnessWorkerAttachLifecyclePhase;
  attemptId: string;
  workflowNodeId: string;
  componentKind: WorkflowHarnessComponentKind;
  attachStatus: WorkflowHarnessWorkerAttachStatus;
  receiptId: string;
  receipt: WorkflowHarnessWorkerAttachReceipt;
  registryRecordId: string;
  accepted: boolean;
  rollbackAvailable: boolean;
  rollbackReadinessProofId: string;
  rollbackLiveShadowComparisonGateId: string;
  rollbackLiveShadowComparisonGateReady: boolean;
  rollbackActivationId: string;
  rollbackHarnessHash: string;
  rollbackPolicyDecision: string;
  policyDecision: string;
  blockers: string[];
  requiredInvariantIds?: string[];
  invariantBlockers?: string[];
  evidenceRefs: string[];
  createdAtMs?: number;
}

export type WorkflowHarnessWorkerSessionStatus =
  | "attached"
  | "resumed"
  | "rollback_ready"
  | "rolled_back"
  | "blocked"
  | string;

export interface WorkflowHarnessWorkerSessionRecord {
  schemaVersion: "workflow.harness.worker-session.v1" | string;
  sessionRecordId: string;
  sessionId: string;
  workerId: string;
  workflowId: string;
  activationId: string;
  activationHash: string;
  harnessHash: string;
  componentVersionSet: Record<string, string>;
  rollbackTarget: string;
  readinessProofId: string;
  rollbackReadinessProofId: string;
  rollbackLiveShadowComparisonGateId: string;
  rollbackLiveShadowComparisonGateReady: boolean;
  rollbackActivationId: string;
  rollbackHarnessHash: string;
  rollbackPolicyDecision: string;
  registryRecordId: string;
  currentStatus: WorkflowHarnessWorkerSessionStatus;
  currentEventId?: string;
  currentAttemptId?: string;
  currentReceiptId?: string;
  attachEventId?: string;
  resumeEventId?: string;
  rollbackEventId?: string;
  lifecycleEventIds: string[];
  lifecycleAttemptIds: string[];
  receiptIds: string[];
  lifecycleStatuses: WorkflowHarnessWorkerAttachStatus[];
  resumed: boolean;
  rollbackAvailable: boolean;
  rollbackTargetReady: boolean;
  accepted: boolean;
  blockers: string[];
  policyDecision: string;
  requiredInvariantIds?: string[];
  invariantBlockers?: string[];
  evidenceRefs: string[];
  persistenceKey: string;
  recordPersistenceKey: string;
  persistedInRuntimeCheckpoint: boolean;
  restoredFromPersistedSession: boolean;
  runtimeCheckpointSource: string;
  persistenceBlockers: string[];
  launchAuthorityReady: boolean;
  launchAuthorityBlockers: string[];
  launchAuthorityInvariantIds?: string[];
  launchAuthorityInvariantBlockers?: string[];
  launchAuthoritySource: string;
  rollbackHandoffReady: boolean;
  rollbackHandoffBlockers: string[];
  rollbackHandoffTarget: string;
  createdAtMs?: number;
}

export type WorkflowHarnessWorkerLaunchPhase =
  | "launch"
  | "resume"
  | "rollback"
  | string;

export interface WorkflowHarnessWorkerLaunchEnvelope {
  schemaVersion: "workflow.harness.worker-launch-envelope.v1" | string;
  envelopeId: string;
  phase: WorkflowHarnessWorkerLaunchPhase;
  workflowNodeId: string;
  componentKind: WorkflowHarnessComponentKind;
  sessionRecordId: string;
  sessionId: string;
  workerId: string;
  workflowId: string;
  activationId: string;
  activationHash: string;
  harnessHash: string;
  componentVersionSet: Record<string, string>;
  registryRecordId: string;
  readinessProofId: string;
  rollbackReadinessProofId: string;
  rollbackLiveShadowComparisonGateId: string;
  rollbackLiveShadowComparisonGateReady: boolean;
  rollbackActivationId: string;
  rollbackHarnessHash: string;
  rollbackPolicyDecision: string;
  rollbackTarget: string;
  persistenceKey: string;
  recordPersistenceKey: string;
  launchAuthoritySource: string;
  launchAuthorityReady: boolean;
  launchAuthorityInvariantIds?: string[];
  launchAuthorityInvariantBlockers?: string[];
  rollbackHandoffReady: boolean;
  accepted: boolean;
  blockers: string[];
  policyDecision: string;
  evidenceRefs: string[];
  createdAtMs?: number;
}

export interface WorkflowHarnessWorkerHandoffReceipt {
  schemaVersion: "workflow.harness.worker-handoff-receipt.v1" | string;
  receiptId: string;
  envelopeId: string;
  phase: WorkflowHarnessWorkerLaunchPhase;
  workflowNodeId: string;
  componentKind: WorkflowHarnessComponentKind;
  sessionRecordId: string;
  sessionId: string;
  workerId: string;
  workflowId: string;
  activationId: string;
  activationHash: string;
  harnessHash: string;
  registryRecordId: string;
  readinessProofId: string;
  rollbackReadinessProofId: string;
  rollbackLiveShadowComparisonGateId: string;
  rollbackLiveShadowComparisonGateReady: boolean;
  rollbackActivationId: string;
  rollbackHarnessHash: string;
  rollbackPolicyDecision: string;
  rollbackTarget: string;
  rollbackAvailable: boolean;
  launchAuthoritySource: string;
  accepted: boolean;
  handoffStatus: "launched" | "resumed" | "rollback_handoff_ready" | "blocked" | string;
  blockers: string[];
  requiredInvariantIds?: string[];
  invariantBlockers?: string[];
  policyDecision: string;
  receiptRefs: string[];
  evidenceRefs: string[];
  createdAtMs?: number;
}

export type WorkflowNodeKind =
  | "source"
  | "trigger"
  | "task_state"
  | "uncertainty_gate"
  | "probe"
  | "budget_gate"
  | "capability_sequence"
  | "runtime_doctor"
  | "runtime_task"
  | "runtime_job"
  | "runtime_checklist"
  | "runtime_thread_fork"
  | "runtime_operator_interrupt"
  | "runtime_operator_steer"
  | "runtime_thread_mode"
  | "runtime_workspace_trust_gate"
  | "runtime_context_compact"
  | "runtime_approval_request"
  | "runtime_usage_meter"
  | "runtime_context_budget"
  | "runtime_compaction_policy"
  | "runtime_rollback_snapshot"
  | "runtime_restore_gate"
  | "runtime_diagnostics_repair"
  | "runtime_coding_tool_budget_recovery"
  | "workflow_package_export"
  | "workflow_package_import"
  | "repository_context"
  | "branch_policy"
  | "github_context"
  | "issue_context"
  | "pr_attempt"
  | "review_gate"
  | "github_pr_create"
  | "function"
  | "model_binding"
  | "model_call"
  | "skill_context"
  | "skill"
  | "skill_pack"
  | "hook"
  | "hook_policy"
  | "parser"
  | "adapter"
  | "plugin_tool"
  | "dry_run"
  | "state"
  | "decision"
  | "loop"
  | "barrier"
  | "subgraph"
  | "human_gate"
  | "semantic_impact"
  | "postcondition_synthesis"
  | "verifier"
  | "drift_detector"
  | "quality_ledger"
  | "handoff"
  | "gui_harness_validation"
  | "output"
  | "test_assertion"
  | "proposal";

export type WorkflowWorkbenchTab = "graph" | "proposals" | "executions";

export type WorkflowRightPanel =
  | "outputs"
  | "unit_tests"
  | "sources"
  | "search"
  | "changes"
  | "runs"
  | "readiness"
  | "schedules"
  | "files"
  | "settings";

export type WorkflowBottomPanel =
  | "selection"
  | "data"
  | "suggestions"
  | "warnings"
  | "fixtures"
  | "checkpoints"
  | "proposal_diff"
  | "test_output"
  | "run_output";

export interface WorkflowProjectMetadata {
  id: string;
  name: string;
  slug: string;
  workflowKind: WorkflowKind;
  executionMode: WorkflowExecutionMode;
  gitLocation?: string;
  branch?: string;
  dirty?: boolean;
  readOnly?: boolean;
  harness?: WorkflowHarnessMetadata;
  workerHarnessBinding?: WorkflowHarnessWorkerBinding;
  createdAtMs?: number;
  updatedAtMs?: number;
}

export interface WorkflowProject extends ProjectFile {
  metadata: WorkflowProjectMetadata;
}

export interface WorkflowNode extends Node {
  type: WorkflowNodeKind;
}

export type WorkflowEdge = Edge;

export type WorkflowTestStatus =
  | "idle"
  | "passed"
  | "failed"
  | "blocked"
  | "skipped";

export interface WorkflowTestCase {
  id: string;
  name: string;
  targetNodeIds: string[];
  targetSubgraphId?: string;
  assertion: WorkflowTestAssertion;
  status?: WorkflowTestStatus;
  lastMessage?: string;
}

export interface WorkflowNodeFixture {
  id: string;
  nodeId: string;
  name: string;
  input?: unknown;
  output?: unknown;
  schemaHash?: string;
  nodeConfigHash?: string;
  sourceRunId?: string;
  pinned?: boolean;
  stale?: boolean;
  validationStatus?: "passed" | "failed" | "not_declared" | "stale";
  validationMessage?: string;
  createdAtMs: number;
}

export interface WorkflowTestRunResult {
  runId: string;
  status: WorkflowTestStatus;
  startedAtMs: number;
  finishedAtMs: number;
  passed: number;
  failed: number;
  blocked: number;
  skipped: number;
  results: Array<{
    testId: string;
    status: WorkflowTestStatus;
    message: string;
    coveredNodeIds: string[];
  }>;
}

export interface WorkflowProposal {
  id: string;
  title: string;
  summary: string;
  status: "open" | "applied" | "rejected";
  createdAtMs: number;
  boundedTargets: string[];
  graphDiff?: {
    addedNodeIds?: string[];
    removedNodeIds?: string[];
    changedNodeIds?: string[];
  };
  configDiff?: {
    changedNodeIds?: string[];
    changedGlobalKeys?: string[];
    changedMetadataKeys?: string[];
  };
  sidecarDiff?: {
    testsChanged?: boolean;
    fixturesChanged?: boolean;
    functionsChanged?: boolean;
    bindingsChanged?: boolean;
    proposalsChanged?: boolean;
    changedRoles?: string[];
  };
  codeDiff?: string;
  workflowPatch?: WorkflowProject;
}

export type WorkflowRunStatus =
  | "queued"
  | "running"
  | "passed"
  | "failed"
  | "blocked"
  | "interrupted";

export interface WorkflowRunSummary {
  id: string;
  threadId?: string;
  status: WorkflowRunStatus;
  startedAtMs: number;
  finishedAtMs?: number;
  nodeCount: number;
  testCount?: number;
  checkpointCount?: number;
  interruptId?: string;
  summary: string;
  evidencePath?: string;
}

export interface WorkflowThread {
  id: string;
  workflowPath: string;
  status: WorkflowRunStatus;
  createdAtMs: number;
  latestCheckpointId?: string;
  input?: unknown;
}

export interface WorkflowStateUpdate {
  nodeId: string;
  key: string;
  value: unknown;
  reducer: "replace" | "append" | "merge";
}

export interface WorkflowStateSnapshot {
  threadId: string;
  checkpointId: string;
  runId: string;
  stepIndex: number;
  values: Record<string, unknown>;
  nodeOutputs: Record<string, unknown>;
  completedNodeIds: string[];
  blockedNodeIds: string[];
  interruptedNodeIds: string[];
  activeNodeIds: string[];
  branchDecisions: Record<string, string>;
  pendingWrites: WorkflowStateUpdate[];
}

export interface WorkflowCheckpoint {
  id: string;
  threadId: string;
  runId: string;
  createdAtMs: number;
  stepIndex: number;
  nodeId?: string;
  status: WorkflowRunStatus;
  summary: string;
}

export interface WorkflowNodeRun {
  nodeId: string;
  nodeType: WorkflowNodeKind | string;
  status:
    | "queued"
    | "running"
    | "success"
    | "error"
    | "blocked"
    | "interrupted";
  startedAtMs: number;
  finishedAtMs?: number;
  attempt: number;
  input?: unknown;
  output?: unknown;
  error?: string;
  checkpointId?: string;
  lifecycle?: string[];
  harnessAttempt?: WorkflowHarnessNodeAttemptRecord;
}

export interface WorkflowInterrupt {
  id: string;
  runId: string;
  threadId: string;
  nodeId: string;
  status: "pending" | "approved" | "rejected" | "edited";
  createdAtMs: number;
  resolvedAtMs?: number;
  prompt: string;
  allowedOutcomes: Array<"approve" | "reject" | "edit">;
  response?: unknown;
}

export interface WorkflowStreamEvent {
  id: string;
  runId: string;
  threadId: string;
  sequence: number;
  kind:
    | "run_started"
    | "node_started"
    | "node_succeeded"
    | "node_failed"
    | "node_blocked"
    | "node_interrupted"
    | "model_invocation_succeeded"
    | "policy_blocked"
    | "approval_required"
    | "approval_decision"
    | "state_updated"
    | "output_created"
    | "asset_materialized"
    | "test_result"
    | "child_run_completed"
    | "run_completed";
  createdAtMs: number;
  nodeId?: string;
  status?: string;
  message?: string;
  stateDelta?: WorkflowStateUpdate[];
}

export interface WorkflowRunResult {
  summary: WorkflowRunSummary;
  thread: WorkflowThread;
  finalState: WorkflowStateSnapshot;
  nodeRuns: WorkflowNodeRun[];
  checkpoints: WorkflowCheckpoint[];
  events: WorkflowStreamEvent[];
  runtimeThreadEvents?: unknown[];
  tuiControlState?: unknown;
  harnessAttempts?: WorkflowHarnessNodeAttemptRecord[];
  harnessShadowComparisons?: WorkflowHarnessShadowComparison[];
  harnessGatedClusterRuns?: WorkflowHarnessGatedClusterRun[];
  verificationEvidence: WorkflowVerificationEvidence[];
  completionRequirements: WorkflowCompletionRequirement[];
  routeEvidence?: WorkflowCodingRouteEvidence[];
  routeRunSummary?: WorkflowCodingRouteRunSummary;
  interrupt?: WorkflowInterrupt;
}

export interface WorkflowRunNodeComparison {
  nodeId: string;
  baselineStatus?: string;
  targetStatus?: string;
  inputChanged: boolean;
  outputChanged: boolean;
  errorChanged: boolean;
}

export interface WorkflowRunStateComparison {
  key: string;
  change: "added" | "removed" | "changed" | string;
  baselineValue?: unknown;
  targetValue?: unknown;
}

export interface WorkflowRunComparison {
  baselineRunId: string;
  targetRunId: string;
  statusChanged: boolean;
  checkpointDelta: number;
  nodeChanges: WorkflowRunNodeComparison[];
  stateChanges: WorkflowRunStateComparison[];
}

export interface WorkflowResumeRequest {
  runId?: string;
  threadId: string;
  nodeId?: string;
  interruptId?: string;
  checkpointId?: string;
  outcome: "approve" | "reject" | "edit" | "retry" | "repair";
  editedState?: Record<string, unknown>;
}

export interface WorkflowCheckpointForkRequest {
  checkpointId: string;
  name?: string;
  input?: unknown;
}

export interface WorkflowProjectSummary {
  id: string;
  name: string;
  slug: string;
  workflowKind: WorkflowKind;
  executionMode: WorkflowExecutionMode;
  workflowPath: string;
  testsPath: string;
  proposalsDir: string;
  nodeCount: number;
  updatedAtMs?: number;
  branch?: string;
  dirty?: boolean;
}

export interface WorkflowWorkbenchBundle {
  workflowPath: string;
  testsPath: string;
  proposalsDir: string;
  workflow: WorkflowProject;
  tests: WorkflowTestCase[];
  proposals: WorkflowProposal[];
  runs: WorkflowRunSummary[];
  importedPackage?: WorkflowPortablePackage;
}

export interface CreateWorkflowProjectRequest {
  projectRoot: string;
  name: string;
  workflowKind: WorkflowKind;
  executionMode: WorkflowExecutionMode;
  templateId?: string;
}

export interface CreateWorkflowFromTemplateRequest {
  projectRoot: string;
  templateId: string;
  name?: string;
}

export interface CreateWorkflowProposalRequest {
  title: string;
  summary: string;
  boundedTargets: string[];
  workflowPatch?: WorkflowProject;
  codeDiff?: string;
}

export interface WorkflowValidationIssue {
  nodeId?: string;
  code: string;
  message: string;
  technicalDetail?: string;
  repairActionId?: string;
  repairLabel?: string;
  configSection?: string;
  fieldPath?: string;
  suggestedCreatorId?: string;
}

export type WorkflowSchedulerLaneCapabilityId =
  | "scheduler"
  | "scheduler.finalization"
  | "terminalResult"
  | "nodeExecution"
  | "nodeOutcome"
  | "nodeStateUpdate"
  | "nodeSuccessEvent"
  | "nodeFailureOutcome"
  | "interrupt"
  | "validation";

export type WorkflowSchedulerLaneReadinessStatus =
  | "ready"
  | "warning"
  | "blocked";

export interface WorkflowSchedulerLaneReadiness {
  id: WorkflowSchedulerLaneCapabilityId;
  label: string;
  capabilityScope: string;
  proofCheckKey: string;
  status: WorkflowSchedulerLaneReadinessStatus;
  detail: string;
  evidenceRefs: string[];
  blockerCode?: string;
}

export interface WorkflowValidationResult {
  status: "passed" | "failed" | "blocked";
  errors: WorkflowValidationIssue[];
  warnings: WorkflowValidationIssue[];
  blockedNodes: string[];
  missingConfig: WorkflowValidationIssue[];
  unsupportedRuntimeNodes: string[];
  policyRequiredNodes: string[];
  coverageByNodeId: Record<string, string[]>;
  connectorBindingIssues: WorkflowValidationIssue[];
  executionReadinessIssues?: WorkflowValidationIssue[];
  verificationIssues?: WorkflowValidationIssue[];
  schedulerLaneReadiness?: WorkflowSchedulerLaneReadiness[];
}

export interface WorkflowEvidenceSummary {
  id: string;
  kind:
    | "validation"
    | "readiness"
    | "test_run"
    | "run"
    | "proposal"
    | "bundle"
    | "fixture"
    | "package"
    | "binding_check"
    | "binding_manifest";
  createdAtMs: number;
  summary: string;
  path?: string;
}

export interface WorkflowPortablePackageFile {
  role: string;
  relativePath: string;
  bytes: number;
  sha256: string;
}

export interface WorkflowPortablePackageManifest {
  schemaVersion: "workflow.portable-package.v1" | string;
  exportedAtMs: number;
  workflowName: string;
  workflowSlug: string;
  sourceWorkflowPath: string;
  workflowChromeLocale?: string | null;
  harness?: WorkflowHarnessMetadata;
  harnessPackageManifest?: WorkflowHarnessPackageEvidenceManifest;
  workerHarnessBinding?: WorkflowHarnessWorkerBinding;
  readinessStatus: WorkflowValidationResult["status"];
  portable: boolean;
  blockers: WorkflowValidationIssue[];
  files: WorkflowPortablePackageFile[];
}

export interface WorkflowPortablePackage {
  packagePath: string;
  manifestPath: string;
  manifest: WorkflowPortablePackageManifest;
  importedWorkflowPath?: string;
}

export interface WorkflowPackageImportActivationHandoff {
  schemaVersion: "workflow.package-import-activation-handoff.v1" | string;
  candidateId: string | null;
  decision: WorkflowHarnessActivationCandidateDecision | string | null;
  activationIdPreview: string | null;
  canaryStatus: string | null;
  rollbackTarget: string | null;
  rollbackAvailable: boolean;
  rollbackRestoreCanaryStatus: string | null;
  forkMutationCanaryId?: string | null;
  forkMutationCanaryStatus?: string | null;
  forkMutationCanaryDiffHash?: string | null;
  forkMutationCanaryReceiptRefs?: string[];
  forkMutationCanaryReplayFixtureRefs?: string[];
  forkMutationCanaryNodeAttemptIds?: string[];
  forkMutationCanaryRollbackTarget?: string | null;
  workerBinding: WorkflowHarnessWorkerBinding | null;
  workflowContentHash: string | null;
  reviewedPackageSnapshotHash: string | null;
  policyPosture: WorkflowHarnessForkActivationRecord["policyPosture"] | null;
  replayFixtureRefs: string[];
  workerHandoffNodeAttemptIds: string[];
  workerHandoffReceiptIds: string[];
  gateCount: number;
  passedGateCount: number;
  blockerCount: number;
  blockerCodes: string[];
  packageEvidenceReady: boolean;
  mintable: boolean;
  deepLinkTargets: {
    activationId: string | null;
    canary: string | null;
    mutationCanary?: string | null;
    rollbackRestore: string | null;
    rollbackTarget: string | null;
    workerBindingId: string | null;
  };
}

export interface WorkflowPackageImportReview {
  schemaVersion: "workflow.package-import-review.v1" | string;
  packagePath: string;
  manifestPath: string | null;
  importedAtMs: number;
  source: {
    workflowName: string | null;
    workflowSlug: string | null;
    workflowId: string | null;
    sourceWorkflowPath: string | null;
    workflowContentHash: string | null;
    activationId: string | null;
    harnessWorkflowId: string | null;
    harnessHash: string | null;
    reviewedPackageSnapshotHash: string | null;
    workerBindingActivationId: string | null;
    workerBindingWorkflowId: string | null;
    policyPosture: WorkflowHarnessForkActivationRecord["policyPosture"] | null;
    rollbackTarget: string | null;
    workflowChromeLocale: string | null;
    forkMutationCanaryId?: string | null;
    forkMutationCanaryStatus?: string | null;
    forkMutationCanaryDiffHash?: string | null;
    forkMutationCanaryReceiptRefs?: string[];
    forkMutationCanaryReplayFixtureRefs?: string[];
    forkMutationCanaryNodeAttemptIds?: string[];
    forkMutationCanaryRollbackTarget?: string | null;
    replayFixtureRefs: string[];
    workerHandoffNodeAttemptIds: string[];
    workerHandoffReceiptIds: string[];
    portable: boolean;
    readinessStatus: WorkflowValidationResult["status"] | null;
    fileCount: number;
    blockerCount: number;
  };
  imported: {
    workflowId: string;
    workflowName: string;
    workflowSlug: string;
    workflowPath: string;
    testsPath: string;
    projectRoot: string;
    activationReadinessStatus: WorkflowValidationResult["status"] | null;
    workflowChromeLocale: string | null;
  };
  evidence: {
    harnessPackageManifestPresent: boolean;
    packageEvidenceReady: boolean;
    workflowChromeLocalePreserved: boolean;
    blockerCount: number;
    evidenceRefCount: number;
    receiptRefCount: number;
    replayFixtureRefCount: number;
    rollbackRestoreReceiptRefCount: number;
    forkMutationCanaryReceiptRefCount?: number;
    forkMutationCanaryReplayFixtureRefCount?: number;
    forkMutationCanaryNodeAttemptCount?: number;
    workerHandoffNodeAttemptCount: number;
    workerHandoffReceiptCount: number;
    deepLinkCount: number;
    missingRows: string[];
  };
  activationHandoff?: WorkflowPackageImportActivationHandoff;
}

export interface ImportWorkflowPackageRequest {
  packagePath: string;
  projectRoot: string;
  name?: string;
}

export interface WorkflowTemplateMetadata {
  templateId: string;
  name: string;
  description: string;
  workflowKind: WorkflowKind;
  executionMode: WorkflowExecutionMode;
  requiredConnectors: string[];
  optionalConnectors: string[];
  guardrailProfile: string;
  seedNodes: WorkflowNode[];
  seedEdges: WorkflowEdge[];
  seedTests: WorkflowTestCase[];
}

export interface WorkflowDogfoodRun {
  id: string;
  suiteId: string;
  startedAtMs: number;
  finishedAtMs?: number;
  status: "passed" | "failed" | "blocked";
  outputDir: string;
  workflowPaths: string[];
  gapLedgerPath: string;
}

export interface WorkflowGapLedgerEntry {
  id: string;
  workflowId: string;
  severity: "info" | "warning" | "blocking";
  area: "gui" | "runtime" | "validation" | "sandbox" | "proposal";
  summary: string;
  status: "open" | "closed";
}
