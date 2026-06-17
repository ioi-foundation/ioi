import type { AgentTask, PlanRouteDecisionSummary, PlanSummary } from "../../../types";

const INSTALL_WORKFLOW_TOOL_IDS = new Set([
  "host_discovery",
  "software_install_resolver",
  "software_install__resolve",
  "software_install__execute_plan",
]);

const INFRASTRUCTURE_STEP_MARKERS = [
  "connecting to kernel",
  "submitting session start",
  "waiting for session start to commit",
  "waiting for session state",
  "scheduling first step",
  "waiting for first step",
  "session queued",
  "session state is reconciling",
  "session start committed",
  "session start commit is delayed",
  "bootstrap is continuing",
  "did not commit within",
  "last tx status",
  "preparing the outcome surface",
  "routing the request",
  "working the conversation route",
  "working the outcome surface",
  "routingreceipt(",
  "routing:",
  "workload receipt:",
  "chat verified candidate-",
  "required obligations",
  "cleared obligations",
  "completion gate",
  "execution ledger",
  "route receipt",
  "receipt::",
  "postcondition::",
  "verification contract",
];

function normalizedText(value: string | null | undefined): string | null {
  const trimmed = (value || "").trim();
  return trimmed.length > 0 ? trimmed : null;
}

function normalizedLookup(value: string | null | undefined): string {
  return (value || "").trim().toLowerCase();
}

function looksLikeRawRuntimeReceipt(value: string): boolean {
  const normalized = normalizedLookup(value);
  return (
    normalized.includes("error_class=") ||
    normalized.includes("\"install_event\"") ||
    normalized.includes("install_resolution_stage=")
  );
}

export function runtimeExecutionFailureDetail(
  task: AgentTask | null | undefined,
): string | null {
  if (task?.phase !== "Failed") {
    return null;
  }
  const currentStep = normalizedText(task?.current_step);
  if (!currentStep) {
    return null;
  }
  return userFacingRuntimeStep(currentStep);
}

function projectedToolSet(summary: PlanSummary | null | undefined): Set<string> {
  const surface = summary?.routeDecision?.effectiveToolSurface;
  const entries = [
    ...(surface?.projectedTools ?? []),
    ...(surface?.primaryTools ?? []),
    ...(surface?.broadFallbackTools ?? []),
  ];
  return new Set(entries.map((entry) => normalizedLookup(entry)).filter(Boolean));
}

function projectedToolIncludes(
  summary: PlanSummary | null | undefined,
  ...needles: string[]
): boolean {
  const tools = projectedToolSet(summary);
  if (tools.size === 0) {
    return false;
  }

  return [...tools].some((tool) =>
    needles.some((needle) => tool.includes(needle)),
  );
}

function routeDecision(
  summary: PlanSummary | null | undefined,
): PlanRouteDecisionSummary | null {
  return summary?.routeDecision ?? null;
}

function installTargetLabel(task: AgentTask | null | undefined): string | null {
  return normalizedText(task?.gate_info?.target_label);
}

function hasInstallRuntimeEvent(task: AgentTask | null | undefined): boolean {
  return (task?.events ?? []).some((event) => {
    const details = event.details || {};
    const digest = event.digest || {};
    const toolName = normalizedLookup(
      String(digest.tool_name || details.tool_name || ""),
    );
    return (
      Boolean(details.install_payload) ||
      Boolean(details.install_event) ||
      Boolean(details.install_final_receipt) ||
      Boolean(details.install_resolution) ||
      INSTALL_WORKFLOW_TOOL_IDS.has(toolName)
    );
  });
}

function isInstallWorkflow(
  summary: PlanSummary | null | undefined,
  task: AgentTask | null | undefined = null,
): boolean {
  void summary;
  return (
    task?.gate_info?.title === "Approve software install" ||
    task?.gate_info?.scope_label === "Software install" ||
    hasInstallRuntimeEvent(task)
  );
}

export function isInfrastructureCurrentStep(
  value: string | null | undefined,
): boolean {
  const normalized = normalizedLookup(value);
  if (!normalized) {
    return false;
  }

  return INFRASTRUCTURE_STEP_MARKERS.some((marker) =>
    normalized.includes(marker),
  );
}

export function userFacingRuntimeStep(
  value: string | null | undefined,
  fallback: string | null = null,
): string | null {
  const normalized = normalizedText(value);
  if (!normalized || isInfrastructureCurrentStep(normalized)) {
    return fallback;
  }
  if (looksLikeRawRuntimeReceipt(normalized)) {
    return fallback;
  }
  return normalized;
}

export function defaultRunActivityTitle(
  summary: PlanSummary | null | undefined,
  task: AgentTask | null | undefined = null,
): string {
  const decision = routeDecision(summary);

  if (isInstallWorkflow(summary, task)) {
    const target = installTargetLabel(task);
    return target ? `Install ${target}` : "Local software install";
  }

  if (decision?.directAnswerAllowed && decision.outputIntent === "direct_inline") {
    return "Preparing answer";
  }

  if (decision?.artifactOutputIntent || decision?.outputIntent === "artifact") {
    return "Working on the artifact";
  }

  if (decision?.fileOutputIntent || decision?.outputIntent === "file") {
    return "Preparing your file";
  }

  if (decision?.inlineVisualIntent || decision?.outputIntent === "inline_visual") {
    return "Preparing an inline visual";
  }

  if (decision?.currentnessOverride) {
    return "Checking current sources";
  }

  if (decision?.connectorFirstPreference && decision.selectedProviderFamily) {
    return "Checking connected sources";
  }

  switch (summary?.routeFamily) {
    case "research":
      return "Researching sources";
    case "coding":
      return "Working in the codebase";
    case "integrations":
      return "Checking connected systems";
    case "communication":
      return "Drafting the message";
    case "user_input":
      return "Preparing the decision surface";
    case "tool_widget":
      return "Preparing the specialized tool";
    case "computer_use":
      return "Working in the current app";
    case "artifacts":
      return "Working on the artifact";
    case "general":
      return "Preparing answer";
    default:
      return "Preparing answer";
  }
}

export function operatorFacingRunTitle(
  summary: PlanSummary | null | undefined,
  task: AgentTask | null | undefined = null,
): string {
  return defaultRunActivityTitle(summary, task);
}

export function defaultRunActivityDetail(
  summary: PlanSummary | null | undefined,
  task: AgentTask | null | undefined = null,
): string {
  const decision = routeDecision(summary);

  if (isInstallWorkflow(summary, task)) {
    const target = installTargetLabel(task);
    if (target) {
      return `Resolving ${target} install route before host mutation.`;
    }
    return "Resolving host, source, approval, execution, and verification for the install route.";
  }

  if (decision?.currentnessOverride) {
    return "Checking fresh public information before answering.";
  }

  if (decision?.connectorFirstPreference && decision.selectedProviderFamily) {
    return "Using the best connected source first, then falling back only if needed.";
  }

  if (decision?.artifactOutputIntent || decision?.outputIntent === "artifact") {
    return "Shaping the requested artifact before presenting it.";
  }

  if (decision?.fileOutputIntent || decision?.outputIntent === "file") {
    return "Preparing the requested file output.";
  }

  if (decision?.inlineVisualIntent || decision?.outputIntent === "inline_visual") {
    return "Preparing an inline visual that is easier to scan than prose alone.";
  }

  if (decision?.directAnswerAllowed && decision.outputIntent === "direct_inline") {
    return "Drafting the answer inline.";
  }

  if (
    summary?.routeFamily === "research" ||
    projectedToolIncludes(summary, "web", "search", "fetch")
  ) {
    return "Checking the most relevant sources before answering.";
  }

  if (
    summary?.routeFamily === "integrations" ||
    projectedToolIncludes(summary, "connector:", "provider_route:")
  ) {
    return "Using the connected provider first, then widening only if needed.";
  }

  if (summary?.routeFamily === "communication") {
    return "Shaping the communication task and preserving the requested tone.";
  }

  if (summary?.routeFamily === "user_input") {
    return "Preparing a structured choice surface before continuing.";
  }

  if (summary?.routeFamily === "tool_widget") {
    return "Projecting the right specialized tool surface for the request.";
  }

  if (
    summary?.routeFamily === "computer_use" ||
    projectedToolIncludes(summary, "browser__", "screen__", "ui__")
  ) {
    return "Reading the current UI state before taking the next action.";
  }

  if (
    summary?.routeFamily === "coding" ||
    projectedToolIncludes(summary, "bash", "edit", "workspace", "repo")
  ) {
    return "Inspecting the workspace and lining up the next code change.";
  }

  if (summary?.routeFamily === "artifacts") {
    return "Shaping the requested artifact before presenting it.";
  }

  return "Drafting the answer inline.";
}

export function operatorFacingCurrentStep(
  task: AgentTask | null | undefined,
  summary: PlanSummary | null | undefined,
): string | null {
  if (isInstallWorkflow(summary, task)) {
    const target = installTargetLabel(task);
    return target
      ? `Resolving ${target} install route before host mutation.`
      : "Resolving install route before host mutation.";
  }

  const candidates = [
    normalizedText(task?.current_step),
    normalizedText(summary?.progressSummary),
    normalizedText(summary?.pauseSummary),
  ];

  for (const candidate of candidates) {
    if (!candidate || isInfrastructureCurrentStep(candidate)) {
      continue;
    }
    return candidate;
  }

  return defaultRunActivityDetail(summary, task);
}
