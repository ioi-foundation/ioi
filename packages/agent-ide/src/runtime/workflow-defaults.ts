import type { GraphGlobalConfig, WorkflowProject } from "../types/graph";

export const DEFAULT_MODEL_BINDINGS = {
  reasoning: { modelId: "", required: false },
  vision: { modelId: "", required: false },
  embedding: { modelId: "", required: false },
  image: { modelId: "", required: false },
};

export const DEFAULT_CAPABILITY_REQUIREMENTS = {
  reasoning: { required: false, bindingKey: "reasoning" },
  vision: { required: false, bindingKey: "vision" },
  embedding: { required: false, bindingKey: "embedding" },
  image: { required: false, bindingKey: "image" },
  speech: { required: false },
  video: { required: false },
};

export const DEFAULT_GLOBAL_CONFIG: GraphGlobalConfig = {
  env: "{}",
  environmentProfile: {
    target: "local",
    credentialScope: "local",
    mockBindingPolicy: "block",
  },
  modelBindings: DEFAULT_MODEL_BINDINGS,
  requiredCapabilities: DEFAULT_CAPABILITY_REQUIREMENTS,
  policy: { maxBudget: 5, maxSteps: 50, timeoutMs: 30000 },
  contract: { developerBond: 0, adjudicationRubric: "" },
  meta: {
    name: "Agent workflow",
    description: "Git-backed workflow composer project.",
  },
  production: {
    errorWorkflowPath: "",
    evaluationSetPath: "",
    expectedTimeSavedMinutes: 0,
    mcpAccessReviewed: false,
  },
};

export function slugify(value: string): string {
  const slug = value
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
  return slug || "agent-workflow";
}

export function normalizeGlobalConfig(config?: Partial<GraphGlobalConfig> | null): GraphGlobalConfig {
  return {
    ...DEFAULT_GLOBAL_CONFIG,
    ...(config ?? {}),
    modelBindings: {
      ...DEFAULT_MODEL_BINDINGS,
      ...(config?.modelBindings ?? {}),
    },
    environmentProfile: {
      target: config?.environmentProfile?.target ?? DEFAULT_GLOBAL_CONFIG.environmentProfile!.target,
      credentialScope:
        config?.environmentProfile?.credentialScope ?? DEFAULT_GLOBAL_CONFIG.environmentProfile!.credentialScope,
      mockBindingPolicy:
        config?.environmentProfile?.mockBindingPolicy ?? DEFAULT_GLOBAL_CONFIG.environmentProfile!.mockBindingPolicy,
    },
    requiredCapabilities: {
      ...DEFAULT_CAPABILITY_REQUIREMENTS,
      ...(config?.requiredCapabilities ?? {}),
    },
    policy: {
      ...DEFAULT_GLOBAL_CONFIG.policy,
      ...(config?.policy ?? {}),
    },
    contract: {
      ...DEFAULT_GLOBAL_CONFIG.contract,
      ...(config?.contract ?? {}),
    },
    meta: {
      ...DEFAULT_GLOBAL_CONFIG.meta,
      ...(config?.meta ?? {}),
    },
    production: {
      ...DEFAULT_GLOBAL_CONFIG.production,
      ...(config?.production ?? {}),
    },
  };
}

export function makeDefaultWorkflow(name = "Agent workflow"): WorkflowProject {
  const slug = slugify(name);
  return {
    version: "workflow.v1",
    metadata: {
      id: slug,
      name,
      slug,
      workflowKind: "agent_workflow",
      executionMode: "local",
      gitLocation: `.agents/workflows/${slug}.workflow.json`,
      readOnly: false,
      dirty: false,
      createdAtMs: Date.now(),
      updatedAtMs: Date.now(),
    },
    nodes: [],
    edges: [],
    global_config: {
      ...DEFAULT_GLOBAL_CONFIG,
      meta: {
        name,
        description: "Git-backed visual workflow.",
      },
    },
  };
}
