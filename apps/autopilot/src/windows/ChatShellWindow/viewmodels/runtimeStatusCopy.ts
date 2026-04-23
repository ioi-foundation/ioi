import type { AgentTask, PlanRouteDecisionSummary, PlanSummary } from "../../../types";

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
  "preparing the outcome surface",
  "routing the request",
  "working the conversation route",
  "working the outcome surface",
  "routingreceipt(",
  "routing:",
  "workload receipt:",
];

function normalizedText(value: string | null | undefined): string | null {
  const trimmed = (value || "").trim();
  return trimmed.length > 0 ? trimmed : null;
}

function normalizedLookup(value: string | null | undefined): string {
  return (value || "").trim().toLowerCase();
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

export function defaultRunActivityTitle(
  summary: PlanSummary | null | undefined,
): string {
  const decision = routeDecision(summary);

  if (decision?.directAnswerAllowed && decision.outputIntent === "direct_inline") {
    return "Drafting the direct answer";
  }

  if (decision?.artifactOutputIntent || decision?.outputIntent === "artifact") {
    return "Preparing your artifact";
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
      return "Preparing your artifact";
    case "general":
      return "Preparing the reply";
    default:
      return "Preparing the reply";
  }
}

export function defaultRunActivityDetail(
  summary: PlanSummary | null | undefined,
): string {
  const decision = routeDecision(summary);

  if (decision?.currentnessOverride) {
    return "Checking fresh public information before answering.";
  }

  if (decision?.connectorFirstPreference && decision.selectedProviderFamily) {
    return "Using the best connected source first, then falling back only if needed.";
  }

  if (decision?.artifactOutputIntent || decision?.outputIntent === "artifact") {
    return "Shaping the requested artifact surface before presenting it.";
  }

  if (decision?.fileOutputIntent || decision?.outputIntent === "file") {
    return "Preparing the requested file output.";
  }

  if (decision?.inlineVisualIntent || decision?.outputIntent === "inline_visual") {
    return "Preparing an inline visual that is easier to scan than prose alone.";
  }

  if (decision?.directAnswerAllowed && decision.outputIntent === "direct_inline") {
    return "Answering inline and only widening the route if outside data becomes necessary.";
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
    return "Preparing the next usable surface before presenting it.";
  }

  return "Preparing the next usable answer.";
}

export function operatorFacingCurrentStep(
  task: AgentTask | null | undefined,
  summary: PlanSummary | null | undefined,
): string | null {
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

  return defaultRunActivityDetail(summary);
}
