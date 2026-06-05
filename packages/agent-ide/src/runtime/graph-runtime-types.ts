import type {
  CreateWorkflowProjectRequest,
  CreateWorkflowFromTemplateRequest,
  CreateWorkflowProposalRequest,
  GraphGlobalConfig,
  ImportWorkflowPackageRequest,
  ProjectFile,
  WorkflowBindingCheckResult,
  WorkflowBindingManifest,
  WorkflowEvidenceSummary,
  WorkflowConnectorBinding,
  WorkflowCheckpoint,
  WorkflowCheckpointForkRequest,
  WorkflowCodingRouteContract,
  WorkflowRunComparison,
  WorkflowDeliveryTarget,
  WorkflowDogfoodRun,
  WorkflowModelBinding,
  WorkflowNodeFixture,
  WorkflowPortablePackage,
  WorkflowProject,
  WorkflowProjectSummary,
  WorkflowRevisionRestoreRequest,
  WorkflowRevisionRestoreResult,
  WorkflowResumeRequest,
  WorkflowRunResult,
  WorkflowRunSummary,
  WorkflowScaffoldDefinition,
  WorkflowSkillCatalogEntry,
  WorkflowSkillPackImportRequest,
  WorkflowSkillPackImportResult,
  WorkflowStateSnapshot,
  WorkflowStreamEvent,
  WorkflowTestCase,
  WorkflowTestRunResult,
  WorkflowToolBinding,
  WorkflowThread,
  WorkflowValidationResult,
  WorkflowWorkbenchBundle,
} from "../types/graph";
import type { WorkflowRuntimeThreadEventLike } from "./workflow-runtime-event-projection";
import type {
  RuntimeApprovalRequestControlRequest,
  RuntimeContextCompactControlRequest,
  RuntimeDiagnosticsRepairControlRequest,
  RuntimeOperatorInterruptControlRequest,
  RuntimeThreadModeControlRequest,
  RuntimeWorkspaceTrustAcknowledgementControlRequest,
} from "./workflow-runtime-control-nodes";
import type { RuntimeCodingToolControlRequest } from "./workflow-runtime-coding-tool-control-nodes";
import type { RuntimeCodingToolBudgetRecoveryControlRequest } from "./workflow-runtime-coding-tool-budget-recovery-control-nodes";
import type { RuntimeCteePrivateWorkspaceControlRequest } from "./workflow-runtime-ctee-private-workspace-control-nodes";
import type { RuntimeGovernedImprovementControlRequest } from "./workflow-runtime-governed-improvement-control-nodes";
import type { RuntimeWorkerServicePackageControlRequest } from "./workflow-runtime-worker-service-package-control-nodes";
import type { RuntimeSubagentControlRequest } from "./workflow-runtime-subagent-control-nodes";
import type { WorkflowCapabilityRunLaunchAnnotation } from "./workflow-capability-preflight";
import type {
  WorkflowCapabilityGrantApplyRequest,
  WorkflowCapabilityGrantRequest,
  WorkflowCapabilityGrantRequestResult,
  WorkflowCapabilityGrantResolutionRequest,
} from "./workflow-capability-grant-request";
import type { WorkflowCodingToolBudgetRunLaunchAnnotation } from "./workflow-readiness-model";
import type { WorkflowRuntimeToolContractLike } from "./workflow-tool-connector-capability-binding";

export type WorkflowRuntimeControlRequest =
  | RuntimeApprovalRequestControlRequest
  | RuntimeCodingToolBudgetRecoveryControlRequest
  | RuntimeCodingToolControlRequest
  | RuntimeCteePrivateWorkspaceControlRequest
  | RuntimeContextCompactControlRequest
  | RuntimeDiagnosticsRepairControlRequest
  | RuntimeGovernedImprovementControlRequest
  | RuntimeWorkerServicePackageControlRequest
  | RuntimeOperatorInterruptControlRequest
  | RuntimeThreadModeControlRequest
  | RuntimeWorkspaceTrustAcknowledgementControlRequest
  | RuntimeSubagentControlRequest;

// Wire-format payload for graph execution requests.
export interface GraphPayload {
  nodes: any[];
  edges: any[];
  global_config: GraphGlobalConfig;
  session_id?: string;
}

// Wire-format event emitted while a graph is running.
export interface GraphEvent {
  node_id: string;
  status: string;
  result?: {
    output: string;
    metrics?: any;
    input_snapshot?: any;
  };
  fitness_score?: number;
  generation?: number;
}

export interface CacheResult {
  output: string;
  metrics?: any;
  input_snapshot?: any;
}

export interface GraphRuntimeModelOption {
  modelId: string;
  status: string;
  residency?: string;
  backendId?: string | null;
}

export interface GraphModelBindingCatalog {
  refreshedAtMs: number;
  models: GraphRuntimeModelOption[];
}

export interface GraphRuntimeCapabilityOption {
  capabilityId: string;
  familyId: string;
  label: string;
  status: string;
  availableCount: number;
  operatorSummary: string;
}

export interface WorkflowRuntimeThreadEventLoadOptions {
  limit?: number;
  cursor?: number;
}

export interface GraphCapabilityCatalog {
  refreshedAtMs: number;
  capabilities: GraphRuntimeCapabilityOption[];
  activeIssueCount?: number;
}

export type WorkflowToolCatalogEntry =
  | Partial<WorkflowToolBinding>
  | WorkflowRuntimeToolContractLike;

export interface WorkflowRunRequestOptions extends Record<string, unknown> {
  threadId?: string;
  liveTelemetryHydration?: boolean;
  source?: string;
  stopAtNodeId?: string;
  capabilityPreflight?: WorkflowCapabilityRunLaunchAnnotation;
  codingToolBudgetPreflight?: WorkflowCodingToolBudgetRunLaunchAnnotation;
  codingToolBudgetRecovery?: Record<string, unknown>;
}

export interface GraphExecutionRuntime {
  runGraph(payload: GraphPayload): Promise<void>;
  stopExecution(): Promise<void>;
  getAvailableTools(): Promise<any[]>;
  checkNodeCache(
    nodeId: string,
    config: any,
    input: string,
  ): Promise<CacheResult | null>;
  getGraphModelBindingCatalog?(): Promise<GraphModelBindingCatalog>;
  getGraphCapabilityCatalog?(): Promise<GraphCapabilityCatalog>;
  runNode(
    nodeType: string,
    config: any,
    input: string,
    globalConfig?: GraphGlobalConfig,
  ): Promise<any>;
  loadProject(path?: string): Promise<ProjectFile | null>;
  saveProject(path: string, project: ProjectFile): Promise<void>;
  listWorkflowProjects?(
    projectRoot: string,
  ): Promise<WorkflowProjectSummary[]>;
  createWorkflowProject?(
    request: CreateWorkflowProjectRequest,
  ): Promise<WorkflowWorkbenchBundle>;
  loadWorkflowBundle?(path: string): Promise<WorkflowWorkbenchBundle>;
  saveWorkflowProject?(path: string, workflow: WorkflowProject): Promise<void>;
  restoreWorkflowRevision?(
    request: WorkflowRevisionRestoreRequest,
  ): Promise<WorkflowRevisionRestoreResult>;
  saveWorkflowTests?(path: string, tests: WorkflowTestCase[]): Promise<void>;
  runWorkflowTests?(
    path: string,
    testIds?: string[],
  ): Promise<WorkflowTestRunResult>;
  createWorkflowThread?(
    path: string,
    input?: Record<string, unknown>,
  ): Promise<WorkflowThread>;
  runWorkflowProject?(
    path: string,
    options?: WorkflowRunRequestOptions,
  ): Promise<WorkflowRunResult>;
  runWorkflowNode?(
    path: string,
    nodeId: string,
    input?: unknown,
    options?: WorkflowRunRequestOptions,
  ): Promise<WorkflowRunResult>;
  dryRunWorkflowFunction?(
    path: string,
    nodeId: string,
    input?: unknown,
  ): Promise<WorkflowRunResult>;
  listWorkflowScaffolds?(
    projectRoot: string,
  ): Promise<WorkflowScaffoldDefinition[]>;
  createWorkflowNodeFromScaffold?(
    path: string,
    request: {
      scaffoldId: string;
      nodeId?: string;
      name?: string;
      x?: number;
      y?: number;
    },
  ): Promise<WorkflowWorkbenchBundle>;
  validateWorkflowNodeConfig?(
    path: string,
    nodeId: string,
  ): Promise<WorkflowValidationResult>;
  dryRunWorkflowNode?(
    path: string,
    nodeId: string,
    input?: unknown,
    options?: Record<string, unknown>,
  ): Promise<WorkflowRunResult>;
  materializeWorkflowFunction?(
    path: string,
    nodeId: string,
    options?: Record<string, unknown>,
  ): Promise<WorkflowWorkbenchBundle>;
  listWorkflowModelBindings?(
    projectRoot: string,
  ): Promise<WorkflowModelBinding[]>;
  listWorkflowDeliveryTargets?(
    projectRoot: string,
  ): Promise<WorkflowDeliveryTarget[]>;
  listWorkflowToolCatalog?(
    projectRoot: string,
  ): Promise<WorkflowToolCatalogEntry[]>;
  listWorkflowConnectorCatalog?(
    projectRoot: string,
  ): Promise<WorkflowConnectorBinding[]>;
  listWorkflowSkillCatalog?(
    projectRoot: string,
  ): Promise<WorkflowSkillCatalogEntry[]>;
  listWorkflowCodingRoutes?(
    projectRoot: string,
  ): Promise<WorkflowCodingRouteContract[]>;
  importWorkflowSkillPack?(
    request: WorkflowSkillPackImportRequest,
  ): Promise<WorkflowSkillPackImportResult>;
  streamWorkflowRun?(
    path: string,
    runId: string,
  ): AsyncIterable<WorkflowStreamEvent>;
  loadWorkflowRuntimeThreadEvents?<T = WorkflowRuntimeThreadEventLike>(
    threadId: string,
    options?: WorkflowRuntimeThreadEventLoadOptions,
  ): Promise<T[]>;
  executeWorkflowRuntimeControlRequest?(
    request: WorkflowRuntimeControlRequest,
  ): Promise<unknown>;
  createWorkflowCapabilityGrantRequest?(
    path: string,
    request: WorkflowCapabilityGrantRequest,
  ): Promise<WorkflowCapabilityGrantRequestResult>;
  listWorkflowCapabilityGrantRequests?(
    path: string,
  ): Promise<WorkflowCapabilityGrantRequestResult[]>;
  resolveWorkflowCapabilityGrantRequest?(
    path: string,
    request: WorkflowCapabilityGrantResolutionRequest,
  ): Promise<WorkflowCapabilityGrantRequestResult>;
  applyWorkflowCapabilityGrantRequest?(
    path: string,
    request: WorkflowCapabilityGrantApplyRequest,
  ): Promise<WorkflowWorkbenchBundle>;
  loadWorkflowRun?(
    path: string,
    runId: string,
  ): Promise<WorkflowRunResult>;
  resumeWorkflowRun?(
    path: string,
    request: WorkflowResumeRequest,
  ): Promise<WorkflowRunResult>;
  listWorkflowRuns?(path: string): Promise<WorkflowRunSummary[]>;
  listWorkflowCheckpoints?(
    path: string,
    threadId: string,
  ): Promise<WorkflowCheckpoint[]>;
  loadWorkflowCheckpoint?(
    path: string,
    checkpointId: string,
  ): Promise<WorkflowStateSnapshot>;
  forkWorkflowCheckpoint?(
    path: string,
    request: WorkflowCheckpointForkRequest,
  ): Promise<WorkflowThread>;
  compareWorkflowRuns?(
    path: string,
    baselineRunId: string,
    targetRunId: string,
  ): Promise<WorkflowRunComparison>;
  validateWorkflowBundle?(path: string): Promise<WorkflowValidationResult>;
  validateWorkflowExecutionReadiness?(path: string): Promise<WorkflowValidationResult>;
  checkWorkflowBinding?(
    path: string,
    nodeId: string,
    bindingId?: string,
  ): Promise<WorkflowBindingCheckResult>;
  generateWorkflowBindingManifest?(path: string): Promise<WorkflowBindingManifest>;
  loadWorkflowBindingManifest?(path: string): Promise<WorkflowBindingManifest | null>;
  exportWorkflowPackage?(
    path: string,
    outputDir?: string,
  ): Promise<WorkflowPortablePackage>;
  importWorkflowPackage?(
    request: ImportWorkflowPackageRequest,
  ): Promise<WorkflowWorkbenchBundle>;
  listWorkflowEvidence?(path: string): Promise<WorkflowEvidenceSummary[]>;
  listWorkflowNodeFixtures?(
    path: string,
    nodeId?: string,
  ): Promise<WorkflowNodeFixture[]>;
  saveWorkflowNodeFixture?(
    path: string,
    fixture: WorkflowNodeFixture,
  ): Promise<WorkflowNodeFixture[]>;
  createWorkflowFromTemplate?(
    request: CreateWorkflowFromTemplateRequest,
  ): Promise<WorkflowWorkbenchBundle>;
  createWorkflowProposal?(
    path: string,
    request: CreateWorkflowProposalRequest,
  ): Promise<WorkflowWorkbenchBundle>;
  createWorkflowRepairProposal?(
    path: string,
    validationIssueIds: string[],
  ): Promise<WorkflowWorkbenchBundle>;
  applyWorkflowProposal?(
    path: string,
    proposalId: string,
  ): Promise<WorkflowWorkbenchBundle>;
  runWorkflowDogfoodSuite?(
    projectRoot: string,
    suiteId: string,
    options?: Record<string, unknown>,
  ): Promise<WorkflowDogfoodRun>;
  onEvent(callback: (event: GraphEvent) => void): () => void;
}
