import type {
  GraphEnvironmentProfile,
  GraphModelBinding,
  Node,
  WorkflowProject,
  WorkflowTestCase,
  WorkflowValidationIssue,
  WorkflowValidationResult,
} from "../types/graph";
import { workflowModelBindingIsReady } from "./workflow-model-capability-binding";
import {
  normalizeWorkflowConnectorBinding,
  normalizeWorkflowToolBinding,
  workflowConnectorBindingIsReady,
  workflowToolBindingIsReady,
} from "./workflow-tool-connector-capability-binding";
import { validateWorkflowProject } from "./workflow-validation";

export const AUTONOMOUS_SYSTEM_MANIFEST_SCHEMA_VERSION =
  "ioi.autonomous-system-manifest.v1" as const;

export const WORKFLOW_LIFECYCLE_READINESS_SCHEMA_VERSION =
  "ioi.workflow.lifecycle-readiness.v1" as const;

export const WORKFLOW_LIFECYCLE_LOOP = [
  "compose",
  "bind",
  "simulate",
  "authorize",
  "run",
  "verify",
  "inspect_receipts",
  "package",
  "deploy",
  "promote",
  "improve",
] as const;

export type WorkflowLifecycleStage = (typeof WORKFLOW_LIFECYCLE_LOOP)[number];

export type WorkflowLifecycleReadinessKind =
  | "run"
  | "authority"
  | "package"
  | "evaluation"
  | "deployment"
  | "promotion";

export type WorkflowLifecycleReadinessStatus =
  | "ready"
  | "blocked"
  | "warning";

export interface AutonomousSystemManifestProfile {
  schemaVersion: typeof AUTONOMOUS_SYSTEM_MANIFEST_SCHEMA_VERSION;
  systemId: string;
  manifestId: string;
  displayName: string;
  description: string;
  version: string;
  status:
    | "draft"
    | "runnable"
    | "package_ready"
    | "deployable"
    | "promoted"
    | "revoked";
  worker: {
    workerRef: string;
    responsibility: string;
    ownerRef: string;
  };
  workflow: {
    workflowManifestRef: string;
    harnessRef: string | null;
    topologyHash: string;
  };
  capabilities: {
    modelCapabilityRefs: string[];
    toolCapabilityRefs: string[];
    connectorRefs: string[];
    primitiveCapabilitiesRequired: string[];
  };
  authority: {
    authorityScopeRequirements: string[];
    grantRequirements: string[];
    approvalProfileRef: string | null;
    policyProfileRef: string | null;
    revocationPosture: "fail_closed" | "pause" | "degrade_read_only";
  };
  runtimeProfiles: Array<{
    profileId: string;
    kind:
      | "local_daemon"
      | "task_browser"
      | "local_container"
      | "hosted_daemon"
      | "cloud_vm"
      | "tee"
      | "depin"
      | "customer_vpc";
    readiness: "ready" | "degraded" | "missing" | "external";
    cleanupPolicyRef: string | null;
  }>;
  sessionStateMemoryArtifacts: {
    sessionProfileRef: string | null;
    stateProfileRef: string | null;
    memoryProfileRef: string | null;
    artifactRetentionProfileRef: string | null;
    observationRetentionMode:
      | "summary_only"
      | "local_redacted"
      | "local_raw"
      | "encrypted_local_raw"
      | "no_persistence";
  };
  evaluation: {
    evalProfileRefs: string[];
    benchmarkRefs: string[];
    qualityGateRefs: string[];
    replayProfileRef: string | null;
  };
  promotion: {
    promotionProfileRef: string | null;
    marketplaceExposureEligibility:
      | "none"
      | "internal"
      | "review_required"
      | "eligible";
    foundryLineageRefs: string[];
    workerCardPreviewRef: string | null;
  };
  receipts: {
    packageReadinessReceiptRef: string | null;
    latestRunReceiptRefs: string[];
    latestEvalReceiptRefs: string[];
  };
}

export interface WorkflowLifecycleReadinessCategory {
  kind: WorkflowLifecycleReadinessKind;
  label: string;
  status: WorkflowLifecycleReadinessStatus;
  blockingScope: string;
  summary: string;
  blockers: WorkflowValidationIssue[];
  warnings: WorkflowValidationIssue[];
  evidenceRefs: string[];
}

export interface WorkflowLifecycleReadinessProjection {
  schemaVersion: typeof WORKFLOW_LIFECYCLE_READINESS_SCHEMA_VERSION;
  lifecycleLoop: readonly WorkflowLifecycleStage[];
  workflowId: string;
  packageArtifact: "Autonomous System Package";
  manifest: AutonomousSystemManifestProfile;
  categories: WorkflowLifecycleReadinessCategory[];
  status: WorkflowLifecycleReadinessStatus;
  blockers: WorkflowValidationIssue[];
  warnings: WorkflowValidationIssue[];
  compatibility: {
    projectedFromLegacyWorkflow: boolean;
    source: "workflow_metadata" | "compatibility_projection";
    notes: string[];
  };
}

export function workflowLifecycleReadinessProjection({
  workflow,
  tests = workflow.tests ?? [],
  validationResult = validateWorkflowProject(workflow, tests),
}: {
  workflow: WorkflowProject;
  tests?: WorkflowTestCase[];
  validationResult?: WorkflowValidationResult;
}): WorkflowLifecycleReadinessProjection {
  const projectedFromLegacyWorkflow = !workflowHasAutonomousSystemPackage(workflow);
  const manifest = autonomousSystemManifestFromWorkflow(workflow, {
    tests,
    validationResult,
    projectedFromLegacyWorkflow,
  });
  const run = runReadinessCategory(validationResult);
  const authority = authorityReadinessCategory(workflow);
  const packageReadiness = packageReadinessCategory(workflow, manifest);
  const evaluation = evaluationReadinessCategory(workflow, tests);
  const deployment = deploymentReadinessCategory(workflow);
  const promotion = promotionReadinessCategory(workflow, evaluation, manifest);
  const categories = [
    run,
    authority,
    packageReadiness,
    evaluation,
    deployment,
    promotion,
  ];
  const blockers = categories.flatMap((category) => category.blockers);
  const warnings = categories.flatMap((category) => category.warnings);
  const status =
    blockers.length > 0
      ? "blocked"
      : warnings.length > 0
        ? "warning"
        : "ready";

  return {
    schemaVersion: WORKFLOW_LIFECYCLE_READINESS_SCHEMA_VERSION,
    lifecycleLoop: WORKFLOW_LIFECYCLE_LOOP,
    workflowId: workflow.metadata.id || workflow.metadata.slug,
    packageArtifact: "Autonomous System Package",
    manifest,
    categories,
    status,
    blockers,
    warnings,
    compatibility: {
      projectedFromLegacyWorkflow,
      source: projectedFromLegacyWorkflow
        ? "compatibility_projection"
        : "workflow_metadata",
      notes: projectedFromLegacyWorkflow
        ? [
            "Workflow has no explicit Autonomous System Package metadata; lifecycle readiness was projected deterministically from existing workflow fields.",
          ]
        : [],
    },
  };
}

export function autonomousSystemManifestFromWorkflow(
  workflow: WorkflowProject,
  {
    tests = workflow.tests ?? [],
    validationResult = validateWorkflowProject(workflow, tests),
  }: {
    tests?: WorkflowTestCase[];
    validationResult?: WorkflowValidationResult;
    projectedFromLegacyWorkflow?: boolean;
  } = {},
): AutonomousSystemManifestProfile {
  const packageMetadata = workflowPackageMetadata(workflow);
  const workflowId = workflow.metadata.id || workflow.metadata.slug;
  const slug = safeId(workflow.metadata.slug || workflowId || "workflow");
  const displayName =
    text(packageMetadata.displayName) ||
    workflow.global_config.meta?.name ||
    workflow.metadata.name ||
    "Autonomous System Package";
  const description =
    text(packageMetadata.description) ||
    workflow.global_config.meta?.description ||
    "Workflow projected into an Autonomous System Package.";
  const modelCapabilityRefs = workflowModelCapabilityRefs(workflow);
  const toolCapabilityRefs = workflowToolCapabilityRefs(workflow);
  const connectorRefs = workflowConnectorRefs(workflow);
  const primitiveCapabilitiesRequired = unique([
    ...workflowPrimitiveCapabilities(workflow),
    ...(modelCapabilityRefs.length > 0 ? ["prim:model.invoke"] : []),
  ]);
  const authorityScopeRequirements = workflowAuthorityScopeRequirements(workflow);
  const evalProfileRefs = workflowEvaluationRefs(workflow, tests);
  const runtimeProfiles = workflowRuntimeProfiles(workflow);
  const runReady = validationResult.status === "passed";
  const packageReady =
    modelCapabilityRefs.length > 0 &&
    toolCapabilityRefs.length + connectorRefs.length > 0 &&
    authorityScopeRequirements.length > 0 &&
    workflow.nodes.some((node) => node.type === "output");
  const evaluationReady = evalProfileRefs.length > 0;
  const deploymentReady = runtimeProfiles.some(
    (profile) => profile.readiness === "ready" || profile.readiness === "degraded",
  );
  const status =
    packageMetadata.status ??
    (runReady && packageReady && evaluationReady && deploymentReady
      ? "deployable"
      : runReady && packageReady
        ? "package_ready"
        : runReady
          ? "runnable"
          : "draft");

  return {
    schemaVersion: AUTONOMOUS_SYSTEM_MANIFEST_SCHEMA_VERSION,
    systemId: text(packageMetadata.systemId) || `system://${slug}`,
    manifestId: text(packageMetadata.manifestId) || `ai://autonomous-system/${slug}`,
    displayName,
    description,
    version: text(packageMetadata.version) || workflow.version || "workflow.v1",
    status,
    worker: {
      workerRef:
        text(packageMetadata.workerRef) ||
        text(record(workflow.metadata.workerHarnessBinding)?.workerRef) ||
        `worker://${slug}`,
      responsibility:
        text(packageMetadata.responsibility) ||
        `Run and verify ${displayName}.`,
      ownerRef: text(packageMetadata.ownerRef) || "ioi://publisher/local",
    },
    workflow: {
      workflowManifestRef:
        text(packageMetadata.workflowManifestRef) ||
        workflow.metadata.gitLocation ||
        `artifact://workflow/${slug}`,
      harnessRef:
        text(packageMetadata.harnessRef) ||
        text(record(workflow.metadata.harness)?.harnessId) ||
        null,
      topologyHash:
        text(packageMetadata.topologyHash) ||
        workflowTopologyHash(workflow),
    },
    capabilities: {
      modelCapabilityRefs,
      toolCapabilityRefs,
      connectorRefs,
      primitiveCapabilitiesRequired,
    },
    authority: {
      authorityScopeRequirements,
      grantRequirements: workflowGrantRequirements(workflow),
      approvalProfileRef:
        text(packageMetadata.approvalProfileRef) ||
        (workflow.nodes.some(nodeRequiresApproval) ? `policy://approval/${slug}` : null),
      policyProfileRef:
        text(packageMetadata.policyProfileRef) ||
        (authorityScopeRequirements.length ? `policy://workflow/${slug}` : null),
      revocationPosture: "fail_closed",
    },
    runtimeProfiles,
    sessionStateMemoryArtifacts: {
      sessionProfileRef: text(packageMetadata.sessionProfileRef) || null,
      stateProfileRef: text(packageMetadata.stateProfileRef) || null,
      memoryProfileRef:
        text(packageMetadata.memoryProfileRef) ||
        (workflow.nodes.some((node) => node.type === "state") ? `profile://memory/${slug}` : null),
      artifactRetentionProfileRef:
        text(packageMetadata.artifactRetentionProfileRef) ||
        (workflow.nodes.some((node) => node.type === "output") ? `profile://artifacts/${slug}` : null),
      observationRetentionMode:
        packageMetadata.observationRetentionMode ?? "local_redacted",
    },
    evaluation: {
      evalProfileRefs,
      benchmarkRefs: stringList(packageMetadata.benchmarkRefs),
      qualityGateRefs:
        stringList(packageMetadata.qualityGateRefs).length > 0
          ? stringList(packageMetadata.qualityGateRefs)
          : evaluationReady
            ? [`gate://quality/${slug}`]
            : [],
      replayProfileRef:
        text(packageMetadata.replayProfileRef) ||
        (workflow.global_config.production?.requireReplayFixtures
          ? `profile://replay/${slug}`
          : null),
    },
    promotion: {
      promotionProfileRef: text(packageMetadata.promotionProfileRef) || null,
      marketplaceExposureEligibility:
        packageMetadata.marketplaceExposureEligibility ?? "review_required",
      foundryLineageRefs: stringList(packageMetadata.foundryLineageRefs),
      workerCardPreviewRef: text(packageMetadata.workerCardPreviewRef) || null,
    },
    receipts: {
      packageReadinessReceiptRef:
        text(packageMetadata.packageReadinessReceiptRef) || null,
      latestRunReceiptRefs: workflowRunReceiptRefs(workflow),
      latestEvalReceiptRefs: evaluationReady
        ? [`receipt://eval/${slug}`]
        : [],
    },
  };
}

function runReadinessCategory(
  validationResult: WorkflowValidationResult,
): WorkflowLifecycleReadinessCategory {
  const blockers = [
    ...validationResult.errors,
    ...validationResult.missingConfig,
    ...validationResult.connectorBindingIssues,
    ...(validationResult.executionReadinessIssues ?? []),
    ...(validationResult.verificationIssues ?? []),
  ];
  return category({
    kind: "run",
    label: "Run readiness",
    blockingScope: "Blocks Run",
    blockers,
    warnings: validationResult.warnings,
    readySummary: "Workflow can execute in the selected runtime profile.",
    blockedSummary: "Workflow has graph, binding, verification, or execution blockers.",
  });
}

function authorityReadinessCategory(
  workflow: WorkflowProject,
): WorkflowLifecycleReadinessCategory {
  const blockers: WorkflowValidationIssue[] = [];
  const warnings: WorkflowValidationIssue[] = [];
  workflow.nodes.forEach((node) => {
    const logic = node.config?.logic ?? {};
    const modelBinding = modelBindingForNode(workflow, node);
    const toolBinding = logic.toolBinding
      ? normalizeWorkflowToolBinding(logic.toolBinding)
      : null;
    const connectorBinding = logic.connectorBinding
      ? normalizeWorkflowConnectorBinding(logic.connectorBinding)
      : null;
    if (modelBinding && !workflowModelBindingIsReady(modelBinding)) {
      blockers.push(issue(node, "model_authority_not_ready", "Model capability needs readiness, grant posture, policy posture, and receipt behavior before live execution."));
    }
    if (toolBinding && !workflowToolBindingIsReady(toolBinding)) {
      blockers.push(issue(node, "tool_authority_not_ready", "Tool capability needs credential/grant readiness, policy posture, and receipt behavior before live execution."));
    }
    if (connectorBinding && !workflowConnectorBindingIsReady(connectorBinding)) {
      blockers.push(issue(node, "connector_authority_not_ready", "Connector capability needs credential/grant readiness, policy posture, and receipt behavior before live execution."));
    }
    if ((toolBinding?.requiresApproval || connectorBinding?.requiresApproval) && !nodeHasApprovalBoundary(workflow, node)) {
      warnings.push(issue(node, "approval_boundary_missing", "Approval-required capability should connect through a human or policy gate before promotion."));
    }
  });
  return category({
    kind: "authority",
    label: "Authority readiness",
    blockingScope: "Blocks live effects",
    blockers,
    warnings,
    readySummary: "Capability grants, policy posture, and receipt behavior are live-ready or explicitly mock/local.",
    blockedSummary: "One or more capabilities lack grant, policy, credential, or receipt readiness.",
  });
}

function packageReadinessCategory(
  workflow: WorkflowProject,
  manifest: AutonomousSystemManifestProfile,
): WorkflowLifecycleReadinessCategory {
  const blockers: WorkflowValidationIssue[] = [];
  if (!manifest.worker.workerRef) blockers.push(globalIssue("package_worker_missing", "Autonomous System Package needs a worker responsibility."));
  if (!manifest.workflow.workflowManifestRef) blockers.push(globalIssue("package_workflow_missing", "Autonomous System Package needs a workflow manifest reference."));
  if (manifest.capabilities.modelCapabilityRefs.length === 0) blockers.push(globalIssue("package_model_capability_missing", "Autonomous System Package needs at least one model capability reference."));
  if (manifest.capabilities.toolCapabilityRefs.length + manifest.capabilities.connectorRefs.length === 0) blockers.push(globalIssue("package_tool_capability_missing", "Autonomous System Package needs at least one tool or connector capability reference."));
  if (manifest.authority.authorityScopeRequirements.length === 0) blockers.push(globalIssue("package_authority_scope_missing", "Autonomous System Package needs explicit authority scope requirements, even when the list is empty by policy."));
  if (!workflow.nodes.some((node) => node.type === "output")) blockers.push(globalIssue("package_output_missing", "Autonomous System Package needs an output or artifact node."));
  return category({
    kind: "package",
    label: "Package readiness",
    blockingScope: "Blocks package/publish",
    blockers,
    warnings: [],
    readySummary: "Workflow projects into a complete Autonomous System Package.",
    blockedSummary: "Workflow can project into a draft package but is missing package fields.",
  });
}

function evaluationReadinessCategory(
  workflow: WorkflowProject,
  tests: WorkflowTestCase[],
): WorkflowLifecycleReadinessCategory {
  const blockers: WorkflowValidationIssue[] = [];
  const production = workflow.global_config.production ?? {};
  if (tests.length === 0 && !production.evaluationSetPath?.trim()) {
    blockers.push(globalIssue("evaluation_profile_missing", "Autonomous System Package needs fixture evals or an evaluation set before promotion."));
  }
  return category({
    kind: "evaluation",
    label: "Evaluation readiness",
    blockingScope: "Blocks promotion",
    blockers,
    warnings: [],
    readySummary: "Eval fixtures or evaluation profile are present.",
    blockedSummary: "No eval fixtures, scorecard, or evaluation profile is bound.",
  });
}

function deploymentReadinessCategory(
  workflow: WorkflowProject,
): WorkflowLifecycleReadinessCategory {
  const environmentProfile = workflow.global_config.environmentProfile;
  const blockers = environmentProfile
    ? []
    : [globalIssue("deployment_profile_missing", "Autonomous System Package needs at least one runtime/deployment profile slot.")];
  return category({
    kind: "deployment",
    label: "Deployment readiness",
    blockingScope: "Blocks deploy",
    blockers,
    warnings: [],
    readySummary: "Runtime/deployment profile slot is present.",
    blockedSummary: "No runtime/deployment profile slot is present.",
  });
}

function promotionReadinessCategory(
  workflow: WorkflowProject,
  evaluation: WorkflowLifecycleReadinessCategory,
  manifest: AutonomousSystemManifestProfile,
): WorkflowLifecycleReadinessCategory {
  const blockers: WorkflowValidationIssue[] = [
    ...evaluation.blockers.map((item) => ({
      ...item,
      code: `promotion_${item.code}`,
    })),
  ];
  if (!manifest.promotion.promotionProfileRef && manifest.evaluation.qualityGateRefs.length === 0) {
    blockers.push(globalIssue("promotion_profile_missing", "Promotion needs a promotion profile or quality gate report reference."));
  }
  if (workflow.global_config.production?.expectedTimeSavedMinutes === undefined) {
    blockers.push(globalIssue("promotion_value_missing", "Promotion needs an expected value baseline."));
  }
  return category({
    kind: "promotion",
    label: "Promotion readiness",
    blockingScope: "Blocks promotion",
    blockers,
    warnings: [],
    readySummary: "Package has eval evidence and promotion profile slots.",
    blockedSummary: "Package is not yet qualified for reuse, marketplace, service, or Foundry feedback.",
  });
}

function category({
  kind,
  label,
  blockingScope,
  blockers,
  warnings,
  readySummary,
  blockedSummary,
}: {
  kind: WorkflowLifecycleReadinessKind;
  label: string;
  blockingScope: string;
  blockers: WorkflowValidationIssue[];
  warnings: WorkflowValidationIssue[];
  readySummary: string;
  blockedSummary: string;
}): WorkflowLifecycleReadinessCategory {
  const status =
    blockers.length > 0 ? "blocked" : warnings.length > 0 ? "warning" : "ready";
  return {
    kind,
    label,
    status,
    blockingScope,
    summary: status === "ready" ? readySummary : blockedSummary,
    blockers,
    warnings,
    evidenceRefs: [],
  };
}

function workflowHasAutonomousSystemPackage(workflow: WorkflowProject): boolean {
  return Boolean(workflowPackageMetadata(workflow).systemId);
}

type PackageMetadata = Record<string, unknown> & {
  status?: AutonomousSystemManifestProfile["status"];
  observationRetentionMode?: AutonomousSystemManifestProfile["sessionStateMemoryArtifacts"]["observationRetentionMode"];
  marketplaceExposureEligibility?: AutonomousSystemManifestProfile["promotion"]["marketplaceExposureEligibility"];
};

function workflowPackageMetadata(workflow: WorkflowProject): PackageMetadata {
  const metadata = workflow.metadata as unknown as Record<string, unknown>;
  const globalConfig = workflow.global_config as unknown as Record<string, unknown>;
  const fromMetadata = record(metadata.autonomousSystemPackage) ?? record(metadata.autonomousSystem);
  const fromGlobal = record(globalConfig.autonomousSystemPackage) ?? record(globalConfig.autonomousSystem);
  return {
    ...(fromGlobal ?? {}),
    ...(fromMetadata ?? {}),
  } as PackageMetadata;
}

function workflowModelCapabilityRefs(workflow: WorkflowProject): string[] {
  const refs = new Set<string>();
  Object.entries(workflow.global_config.modelBindings ?? {}).forEach(([, binding]) => {
    if (binding.modelCapabilityRef) refs.add(binding.modelCapabilityRef);
  });
  workflow.nodes.forEach((node) => {
    const logic = node.config?.logic ?? {};
    if (logic.modelCapabilityRef) refs.add(logic.modelCapabilityRef);
    if (logic.modelBinding?.modelCapabilityRef) refs.add(logic.modelBinding.modelCapabilityRef);
  });
  return Array.from(refs).sort();
}

function workflowToolCapabilityRefs(workflow: WorkflowProject): string[] {
  return unique(
    workflow.nodes.flatMap((node) => {
      const binding = node.config?.logic?.toolBinding;
      if (!binding) return [];
      return [normalizeWorkflowToolBinding(binding).toolCapabilityRef].filter(Boolean) as string[];
    }),
  );
}

function workflowConnectorRefs(workflow: WorkflowProject): string[] {
  return unique(
    workflow.nodes.flatMap((node) => {
      const binding = node.config?.logic?.connectorBinding;
      if (!binding) return [];
      const normalized = normalizeWorkflowConnectorBinding(binding);
      return [
        normalized.connectorRef,
        normalized.connectorCapabilityRef,
      ].filter(Boolean) as string[];
    }),
  );
}

function workflowPrimitiveCapabilities(workflow: WorkflowProject): string[] {
  return unique(
    workflow.nodes.flatMap((node) => {
      const logic = node.config?.logic ?? {};
      const tool = logic.toolBinding ? normalizeWorkflowToolBinding(logic.toolBinding) : null;
      const connector = logic.connectorBinding
        ? normalizeWorkflowConnectorBinding(logic.connectorBinding)
        : null;
      return [
        ...(tool?.primitiveCapabilities ?? []),
        ...(connector?.primitiveCapabilities ?? []),
      ];
    }),
  );
}

function workflowAuthorityScopeRequirements(workflow: WorkflowProject): string[] {
  return unique(
    workflow.nodes.flatMap((node) => {
      const logic = node.config?.logic ?? {};
      const model = modelBindingForNode(workflow, node);
      const tool = logic.toolBinding ? normalizeWorkflowToolBinding(logic.toolBinding) : null;
      const connector = logic.connectorBinding
        ? normalizeWorkflowConnectorBinding(logic.connectorBinding)
        : null;
      return [
        ...(model?.authorityScopeRequirements ?? model?.authorityScopes ?? []),
        ...(tool?.authorityScopeRequirements ?? tool?.authorityScopes ?? []),
        ...(connector?.authorityScopeRequirements ?? connector?.authorityScopes ?? []),
        ...(logic.authorityScopes ?? []),
      ];
    }),
  );
}

function workflowGrantRequirements(workflow: WorkflowProject): string[] {
  return workflowAuthorityScopeRequirements(workflow).map((scope) => `grant://${safeId(scope)}`);
}

function workflowEvaluationRefs(
  workflow: WorkflowProject,
  tests: WorkflowTestCase[],
): string[] {
  const refs = new Set<string>();
  const evaluationSetPath = workflow.global_config.production?.evaluationSetPath?.trim();
  if (evaluationSetPath) refs.add(evaluationSetPath);
  tests.forEach((test) => refs.add(`dataset://workflow-test/${safeId(test.id)}`));
  return Array.from(refs).sort();
}

function workflowRuntimeProfiles(workflow: WorkflowProject): AutonomousSystemManifestProfile["runtimeProfiles"] {
  const environmentProfile = workflow.global_config.environmentProfile;
  return [
    {
      profileId: `profile://runtime/${safeId(workflow.metadata.slug || workflow.metadata.id || "workflow")}`,
      kind: runtimeProfileKind(environmentProfile),
      readiness: environmentProfile ? "ready" : "missing",
      cleanupPolicyRef: null,
    },
  ];
}

function workflowRunReceiptRefs(workflow: WorkflowProject): string[] {
  return unique(
    (workflow.runs ?? []).flatMap((run) => {
      const candidate = run as unknown as Record<string, unknown>;
      return [
        ...stringList(candidate.receiptRefs),
        text(candidate.receiptRef),
      ].filter(Boolean);
    }),
  );
}

function modelBindingForNode(
  workflow: WorkflowProject,
  node: Node,
): GraphModelBinding | null {
  const logic = node.config?.logic ?? {};
  if (logic.modelBinding) return logic.modelBinding as unknown as GraphModelBinding;
  const modelRef = text(logic.modelRef);
  if (!modelRef) return null;
  return workflow.global_config.modelBindings?.[modelRef] ?? null;
}

function nodeRequiresApproval(node: Node): boolean {
  const logic = node.config?.logic ?? {};
  const law = node.config?.law ?? {};
  return Boolean(
    logic.toolBinding?.requiresApproval ||
      logic.connectorBinding?.requiresApproval ||
      law.requireHumanGate,
  );
}

function nodeHasApprovalBoundary(workflow: WorkflowProject, node: Node): boolean {
  const law = node.config?.law ?? {};
  if (law.requireHumanGate) return true;
  return workflow.edges.some((edge) => {
    if (edge.to !== node.id) return false;
    const source = workflow.nodes.find((item) => item.id === edge.from);
    return source?.type === "human_gate";
  });
}

function runtimeProfileKind(
  profile?: GraphEnvironmentProfile,
): AutonomousSystemManifestProfile["runtimeProfiles"][number]["kind"] {
  switch (profile?.target) {
    case "sandbox":
      return "local_container";
    case "staging":
    case "production":
      return "hosted_daemon";
    case "local":
    default:
      return "local_daemon";
  }
}

function workflowTopologyHash(workflow: WorkflowProject): string {
  return `topology:${workflow.nodes.length}:${workflow.edges.length}:${safeId(workflow.metadata.slug || workflow.metadata.id)}`;
}

function issue(node: Node, code: string, message: string): WorkflowValidationIssue {
  return {
    nodeId: node.id,
    code,
    message,
  };
}

function globalIssue(code: string, message: string): WorkflowValidationIssue {
  return {
    code,
    message,
  };
}

function record(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function text(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}

function stringList(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.map((item) => text(item)).filter(Boolean);
}

function unique(values: string[]): string[] {
  return Array.from(new Set(values.filter(Boolean))).sort();
}

function safeId(value: string): string {
  return (
    value
      .trim()
      .toLowerCase()
      .replace(/[^a-z0-9_.:-]+/g, "-")
      .replace(/^-+|-+$/g, "") || "workflow"
  );
}
