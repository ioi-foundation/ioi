import type {
  GraphCapabilityRequirement,
  GraphGlobalConfig,
  GraphModelBinding,
  WorkflowPortablePackage,
  WorkflowProject,
  WorkflowValidationResult,
} from "../types/graph";
import {
  workflowBindingRegistrySummary,
  workflowEnvironmentProfile,
  type WorkflowBindingRegistrySummary,
  type WorkflowBindingRegistryRow,
} from "./workflow-rail-model";
import { normalizeWorkflowRuntimeLocale } from "./workflow-runtime-ui-strings";

export interface WorkflowSettingsSummaryItem {
  label: string;
  value: string;
}

export interface WorkflowSettingsMetadata {
  name: string;
  workflowPath: string;
  branch: string;
  dirty: boolean;
}

export interface WorkflowSettingsProductionSummary {
  errorPath: string;
  evaluations: string;
  valueEstimate: string;
  mcpAccess: string;
}

export interface WorkflowSettingsModel {
  summaryItems: WorkflowSettingsSummaryItem[];
  metadata: WorkflowSettingsMetadata;
  workflowReadOnly: boolean;
  chromeLocale: string;
  environmentProfile: NonNullable<GraphGlobalConfig["environmentProfile"]>;
  bindingRegistrySummary: WorkflowBindingRegistrySummary;
  modelBindingItems: Array<[string, GraphModelBinding]>;
  requiredCapabilityItems: Array<[string, GraphCapabilityRequirement]>;
  policy: GraphGlobalConfig["policy"];
  productionProfile: NonNullable<GraphGlobalConfig["production"]>;
  productionSummary: WorkflowSettingsProductionSummary;
  packageReadinessStatus: string;
}

export interface WorkflowSettingsModelInput {
  workflow: WorkflowProject;
  validationResult?: WorkflowValidationResult | null;
  readinessResult?: WorkflowValidationResult | null;
  bindingRegistryRows?: WorkflowBindingRegistryRow[];
  portablePackage?: WorkflowPortablePackage | null;
  criticalAiNodeCount: number;
  mcpToolNodeCount: number;
  hasErrorOrRetryPath: boolean;
}

function workflowLifecycleNextAction({
  validationStatus,
  readinessStatus,
  packageStatus,
  bindingSummary,
}: {
  validationStatus: string;
  readinessStatus: string;
  packageStatus: string;
  bindingSummary: WorkflowBindingRegistrySummary;
}): string {
  if (bindingSummary.total > 0 && bindingSummary.ready < bindingSummary.total) {
    return "Bind capabilities";
  }

  if (validationStatus !== "passed") {
    return "Validate graph";
  }

  if (readinessStatus !== "passed") {
    return "Check readiness";
  }

  if (packageStatus !== "passed") {
    return "Export package";
  }

  return "Ready to promote";
}

export function workflowSettingsModel({
  workflow,
  validationResult,
  readinessResult,
  bindingRegistryRows = [],
  portablePackage,
  criticalAiNodeCount,
  mcpToolNodeCount,
  hasErrorOrRetryPath,
}: WorkflowSettingsModelInput): WorkflowSettingsModel {
  const environmentProfile = workflowEnvironmentProfile(workflow);
  const productionProfile = workflow.global_config.production ?? {};
  const bindingRegistrySummary =
    workflowBindingRegistrySummary(bindingRegistryRows);
  const validationStatus = validationResult?.status ?? "not checked";
  const readinessStatus = readinessResult?.status ?? "not checked";
  const packageReadinessStatus =
    portablePackage?.manifest.readinessStatus ?? "not exported";
  const expectedTimeSavedMinutes =
    productionProfile.expectedTimeSavedMinutes ?? 0;

  return {
    summaryItems: [
      {
        label: "Build artifact",
        value:
          packageReadinessStatus === "not exported"
            ? "Draft workflow"
            : "Autonomous package",
      },
      {
        label: "Run readiness",
        value: readinessStatus,
      },
      {
        label: "Authority",
        value:
          bindingRegistrySummary.total === 0
            ? "No bindings"
            : `${bindingRegistrySummary.ready}/${bindingRegistrySummary.total} ready`,
      },
      {
        label: "Next action",
        value: workflowLifecycleNextAction({
          validationStatus,
          readinessStatus,
          packageStatus: packageReadinessStatus,
          bindingSummary: bindingRegistrySummary,
        }),
      },
    ],
    metadata: {
      name: workflow.metadata.name,
      workflowPath:
        workflow.metadata.gitLocation ??
        `.agents/workflows/${workflow.metadata.slug}.workflow.json`,
      branch: workflow.metadata.branch ?? "main",
      dirty: workflow.metadata.dirty === true,
    },
    workflowReadOnly: workflow.metadata.readOnly === true,
    chromeLocale: normalizeWorkflowRuntimeLocale(
      workflow.global_config.workflowChromeLocale,
    ),
    environmentProfile,
    bindingRegistrySummary,
    modelBindingItems: Object.entries(workflow.global_config.modelBindings ?? {}),
    requiredCapabilityItems: Object.entries(
      workflow.global_config.requiredCapabilities ?? {},
    ).filter(([, requirement]) => requirement.required),
    policy: workflow.global_config.policy,
    productionProfile,
    productionSummary: {
      errorPath:
        productionProfile.errorWorkflowPath ??
        (hasErrorOrRetryPath ? "graph path" : "not set"),
      evaluations:
        productionProfile.evaluationSetPath ??
        `${criticalAiNodeCount} model node${criticalAiNodeCount === 1 ? "" : "s"}`,
      valueEstimate: expectedTimeSavedMinutes
        ? `${expectedTimeSavedMinutes} min/run`
        : "not set",
      mcpAccess:
        mcpToolNodeCount === 0
          ? "not used"
          : productionProfile.mcpAccessReviewed
            ? "reviewed"
            : "needs review",
    },
    packageReadinessStatus,
  };
}
