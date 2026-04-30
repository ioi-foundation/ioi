import type { AgentWorkbenchRuntime } from "./agent-runtime";
import type {
  CreateWorkflowFromTemplateRequest,
  CreateWorkflowProjectRequest,
  CreateWorkflowProposalRequest,
  ImportWorkflowPackageRequest,
  WorkflowCheckpointForkRequest,
  WorkflowProject,
  WorkflowResumeRequest,
  WorkflowWorkbenchBundle,
} from "../types/graph";

export type WorkflowHarnessToolName =
  | "workflow.bundle.create"
  | "workflow.bundle.update"
  | "workflow.bundle.validate"
  | "workflow.template.instantiate"
  | "workflow.proposal.create"
  | "workflow.proposal.apply"
  | "workflow.run.start"
  | "workflow.run.resume"
  | "workflow.node.run"
  | "workflow.node.scaffold"
  | "workflow.node.validate_config"
  | "workflow.node.dry_run"
  | "workflow.function.materialize"
  | "workflow.function.dry_run"
  | "workflow.catalog.scaffolds"
  | "workflow.catalog.models"
  | "workflow.catalog.tools"
  | "workflow.catalog.connectors"
  | "workflow.catalog.delivery_targets"
  | "workflow.proposal.repair"
  | "workflow.dogfood.run"
  | "workflow.checkpoint.fork"
  | "workflow.package.export"
  | "workflow.package.import";

export interface WorkflowHarnessToolEvidence {
  toolName: WorkflowHarnessToolName;
  usedRuntimeApi: string;
  workflowPath?: string;
  status: "ok" | "blocked";
  message: string;
}

export interface WorkflowHarnessToolResult<T> {
  value: T;
  evidence: WorkflowHarnessToolEvidence;
}

function requireApi<T extends keyof AgentWorkbenchRuntime>(
  runtime: AgentWorkbenchRuntime,
  apiName: T,
): NonNullable<AgentWorkbenchRuntime[T]> {
  const api = runtime[apiName];
  if (!api) {
    throw new Error(`Workflow runtime API '${String(apiName)}' is not available.`);
  }
  return api as NonNullable<AgentWorkbenchRuntime[T]>;
}

export function createWorkflowHarnessTools(runtime: AgentWorkbenchRuntime) {
  return {
    async createBundle(
      request: CreateWorkflowProjectRequest,
    ): Promise<WorkflowHarnessToolResult<WorkflowWorkbenchBundle>> {
      const createWorkflowProject = requireApi(runtime, "createWorkflowProject");
      const value = await createWorkflowProject(request);
      return {
        value,
        evidence: {
          toolName: "workflow.bundle.create",
          usedRuntimeApi: "createWorkflowProject",
          workflowPath: value.workflowPath,
          status: "ok",
          message: "Workflow bundle created through runtime API.",
        },
      };
    },

    async updateBundle(
      path: string,
      workflow: WorkflowProject,
    ): Promise<WorkflowHarnessToolResult<void>> {
      const saveWorkflowProject = requireApi(runtime, "saveWorkflowProject");
      await saveWorkflowProject(path, workflow);
      return {
        value: undefined,
        evidence: {
          toolName: "workflow.bundle.update",
          usedRuntimeApi: "saveWorkflowProject",
          workflowPath: path,
          status: "ok",
          message: "Workflow bundle updated through runtime API.",
        },
      };
    },

    async validateBundle(path: string) {
      const validateWorkflowBundle = requireApi(runtime, "validateWorkflowBundle");
      const value = await validateWorkflowBundle(path);
      return {
        value,
        evidence: {
          toolName: "workflow.bundle.validate",
          usedRuntimeApi: "validateWorkflowBundle",
          workflowPath: path,
          status: value.status === "passed" ? "ok" : "blocked",
          message: `Workflow validation ${value.status}.`,
        },
      };
    },

    async instantiateTemplate(
      request: CreateWorkflowFromTemplateRequest,
    ): Promise<WorkflowHarnessToolResult<WorkflowWorkbenchBundle>> {
      const createWorkflowFromTemplate = requireApi(runtime, "createWorkflowFromTemplate");
      const value = await createWorkflowFromTemplate(request);
      return {
        value,
        evidence: {
          toolName: "workflow.template.instantiate",
          usedRuntimeApi: "createWorkflowFromTemplate",
          workflowPath: value.workflowPath,
          status: "ok",
          message: "Workflow template instantiated through runtime API.",
        },
      };
    },

    async createProposal(path: string, request: CreateWorkflowProposalRequest) {
      const createWorkflowProposal = requireApi(runtime, "createWorkflowProposal");
      const value = await createWorkflowProposal(path, request);
      return {
        value,
        evidence: {
          toolName: "workflow.proposal.create",
          usedRuntimeApi: "createWorkflowProposal",
          workflowPath: path,
          status: "ok",
          message: "Workflow proposal created through runtime API.",
        },
      };
    },

    async applyProposal(path: string, proposalId: string) {
      const applyWorkflowProposal = requireApi(runtime, "applyWorkflowProposal");
      const value = await applyWorkflowProposal(path, proposalId);
      return {
        value,
        evidence: {
          toolName: "workflow.proposal.apply",
          usedRuntimeApi: "applyWorkflowProposal",
          workflowPath: path,
          status: "ok",
          message: "Workflow proposal applied through runtime API.",
        },
      };
    },

    async runWorkflow(path: string, options?: Record<string, unknown>) {
      const runWorkflowProject = requireApi(runtime, "runWorkflowProject");
      const value = await runWorkflowProject(path, options);
      return {
        value,
        evidence: {
          toolName: "workflow.run.start" as const,
          usedRuntimeApi: "runWorkflowProject",
          workflowPath: path,
          status: value.summary.status === "passed" ? "ok" : "blocked",
          message: `Workflow run ${value.summary.status} through runtime API.`,
        },
      };
    },

    async runWorkflowNode(path: string, nodeId: string, input?: unknown) {
      const runWorkflowNode = requireApi(runtime, "runWorkflowNode");
      const value = await runWorkflowNode(path, nodeId, input);
      return {
        value,
        evidence: {
          toolName: "workflow.node.run" as const,
          usedRuntimeApi: "runWorkflowNode",
          workflowPath: path,
          status: value.summary.status === "passed" ? "ok" : "blocked",
          message: `Workflow node run ${value.summary.status} through runtime API.`,
        },
      };
    },

    async createNodeFromScaffold(
      path: string,
      request: { scaffoldId: string; nodeId?: string; name?: string; x?: number; y?: number },
    ) {
      const createWorkflowNodeFromScaffold = requireApi(runtime, "createWorkflowNodeFromScaffold");
      const value = await createWorkflowNodeFromScaffold(path, request);
      return {
        value,
        evidence: {
          toolName: "workflow.node.scaffold" as const,
          usedRuntimeApi: "createWorkflowNodeFromScaffold",
          workflowPath: path,
          status: "ok" as const,
          message: "Workflow node scaffolded through runtime API.",
        },
      };
    },

    async validateNodeConfig(path: string, nodeId: string) {
      const validateWorkflowNodeConfig = requireApi(runtime, "validateWorkflowNodeConfig");
      const value = await validateWorkflowNodeConfig(path, nodeId);
      return {
        value,
        evidence: {
          toolName: "workflow.node.validate_config" as const,
          usedRuntimeApi: "validateWorkflowNodeConfig",
          workflowPath: path,
          status: value.status === "passed" ? "ok" : "blocked",
          message: `Workflow node config validation ${value.status}.`,
        },
      };
    },

    async dryRunNode(path: string, nodeId: string, input?: unknown) {
      const dryRunWorkflowNode = requireApi(runtime, "dryRunWorkflowNode");
      const value = await dryRunWorkflowNode(path, nodeId, input);
      return {
        value,
        evidence: {
          toolName: "workflow.node.dry_run" as const,
          usedRuntimeApi: "dryRunWorkflowNode",
          workflowPath: path,
          status: value.summary.status === "passed" ? "ok" : "blocked",
          message: `Workflow node dry run ${value.summary.status}.`,
        },
      };
    },

    async dryRunFunction(path: string, nodeId: string, input?: unknown) {
      const dryRunWorkflowFunction = requireApi(runtime, "dryRunWorkflowFunction");
      const value = await dryRunWorkflowFunction(path, nodeId, input);
      return {
        value,
        evidence: {
          toolName: "workflow.function.dry_run" as const,
          usedRuntimeApi: "dryRunWorkflowFunction",
          workflowPath: path,
          status: value.summary.status === "passed" ? "ok" : "blocked",
          message: `Workflow function dry run ${value.summary.status} through runtime API.`,
        },
      };
    },

    async materializeFunction(path: string, nodeId: string, options?: Record<string, unknown>) {
      const materializeWorkflowFunction = requireApi(runtime, "materializeWorkflowFunction");
      const value = await materializeWorkflowFunction(path, nodeId, options);
      return {
        value,
        evidence: {
          toolName: "workflow.function.materialize" as const,
          usedRuntimeApi: "materializeWorkflowFunction",
          workflowPath: path,
          status: "ok" as const,
          message: "Workflow function materialized through runtime API.",
        },
      };
    },

    async listScaffolds(projectRoot: string) {
      const listWorkflowScaffolds = requireApi(runtime, "listWorkflowScaffolds");
      const value = await listWorkflowScaffolds(projectRoot);
      return {
        value,
        evidence: {
          toolName: "workflow.catalog.scaffolds" as const,
          usedRuntimeApi: "listWorkflowScaffolds",
          status: "ok" as const,
          message: "Workflow scaffold catalog loaded through runtime API.",
        },
      };
    },

    async listModelBindings(projectRoot: string) {
      const listWorkflowModelBindings = requireApi(runtime, "listWorkflowModelBindings");
      const value = await listWorkflowModelBindings(projectRoot);
      return {
        value,
        evidence: {
          toolName: "workflow.catalog.models" as const,
          usedRuntimeApi: "listWorkflowModelBindings",
          status: "ok" as const,
          message: "Workflow model binding catalog loaded through runtime API.",
        },
      };
    },

    async listToolCatalog(projectRoot: string) {
      const listWorkflowToolCatalog = requireApi(runtime, "listWorkflowToolCatalog");
      const value = await listWorkflowToolCatalog(projectRoot);
      return {
        value,
        evidence: {
          toolName: "workflow.catalog.tools" as const,
          usedRuntimeApi: "listWorkflowToolCatalog",
          status: "ok" as const,
          message: "Workflow tool catalog loaded through runtime API.",
        },
      };
    },

    async listConnectorCatalog(projectRoot: string) {
      const listWorkflowConnectorCatalog = requireApi(runtime, "listWorkflowConnectorCatalog");
      const value = await listWorkflowConnectorCatalog(projectRoot);
      return {
        value,
        evidence: {
          toolName: "workflow.catalog.connectors" as const,
          usedRuntimeApi: "listWorkflowConnectorCatalog",
          status: "ok" as const,
          message: "Workflow connector catalog loaded through runtime API.",
        },
      };
    },

    async listDeliveryTargets(projectRoot: string) {
      const listWorkflowDeliveryTargets = requireApi(runtime, "listWorkflowDeliveryTargets");
      const value = await listWorkflowDeliveryTargets(projectRoot);
      return {
        value,
        evidence: {
          toolName: "workflow.catalog.delivery_targets" as const,
          usedRuntimeApi: "listWorkflowDeliveryTargets",
          status: "ok" as const,
          message: "Workflow delivery target catalog loaded through runtime API.",
        },
      };
    },

    async createRepairProposal(path: string, validationIssueIds: string[]) {
      const createWorkflowRepairProposal = requireApi(runtime, "createWorkflowRepairProposal");
      const value = await createWorkflowRepairProposal(path, validationIssueIds);
      return {
        value,
        evidence: {
          toolName: "workflow.proposal.repair" as const,
          usedRuntimeApi: "createWorkflowRepairProposal",
          workflowPath: path,
          status: "ok" as const,
          message: "Workflow repair proposal created through runtime API.",
        },
      };
    },

    async runDogfoodSuite(projectRoot: string, suiteId: string, options?: Record<string, unknown>) {
      const runWorkflowDogfoodSuite = requireApi(runtime, "runWorkflowDogfoodSuite");
      const value = await runWorkflowDogfoodSuite(projectRoot, suiteId, options);
      return {
        value,
        evidence: {
          toolName: "workflow.dogfood.run" as const,
          usedRuntimeApi: "runWorkflowDogfoodSuite",
          status: value.status === "passed" ? "ok" : "blocked",
          message: `Workflow dogfood suite ${value.status} through runtime API.`,
        },
      };
    },

    async resumeWorkflow(path: string, request: WorkflowResumeRequest) {
      const resumeWorkflowRun = requireApi(runtime, "resumeWorkflowRun");
      const value = await resumeWorkflowRun(path, request);
      return {
        value,
        evidence: {
          toolName: "workflow.run.resume" as const,
          usedRuntimeApi: "resumeWorkflowRun",
          workflowPath: path,
          status: value.summary.status === "passed" ? "ok" : "blocked",
          message: `Workflow resume ${value.summary.status} through runtime API.`,
        },
      };
    },

    async forkCheckpoint(path: string, request: WorkflowCheckpointForkRequest) {
      const forkWorkflowCheckpoint = requireApi(runtime, "forkWorkflowCheckpoint");
      const value = await forkWorkflowCheckpoint(path, request);
      return {
        value,
        evidence: {
          toolName: "workflow.checkpoint.fork" as const,
          usedRuntimeApi: "forkWorkflowCheckpoint",
          workflowPath: path,
          status: "ok" as const,
          message: "Workflow checkpoint forked through runtime API.",
        },
      };
    },

    async exportPackage(path: string, outputDir?: string) {
      const exportWorkflowPackage = requireApi(runtime, "exportWorkflowPackage");
      const value = await exportWorkflowPackage(path, outputDir);
      return {
        value,
        evidence: {
          toolName: "workflow.package.export" as const,
          usedRuntimeApi: "exportWorkflowPackage",
          workflowPath: path,
          status: value.manifest.portable ? "ok" as const : "blocked" as const,
          message: `Workflow package exported with readiness ${value.manifest.readinessStatus}.`,
        },
      };
    },

    async importPackage(request: ImportWorkflowPackageRequest) {
      const importWorkflowPackage = requireApi(runtime, "importWorkflowPackage");
      const value = await importWorkflowPackage(request);
      return {
        value,
        evidence: {
          toolName: "workflow.package.import" as const,
          usedRuntimeApi: "importWorkflowPackage",
          workflowPath: value.workflowPath,
          status: "ok" as const,
          message: "Workflow package imported through runtime API.",
        },
      };
    },
  };
}
