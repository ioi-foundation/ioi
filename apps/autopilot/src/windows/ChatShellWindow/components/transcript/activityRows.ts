import type {
  ChatArtifactSession,
  ToolActivityKind,
  ToolActivityRow,
  ToolActivityStatus,
} from "../../../../types";
import { firstStringValue, normalizedDomain } from "../../viewmodels/contentPipeline.helpers";
import { operatorStepSourceSummary, sourceQueryFromReason } from "./sourceSummary";

export type TurnActivityEntry = ToolActivityRow & {
  sortOrder: number;
  phaseOrder: number;
  source: "receipt" | "runtime" | "artifact" | "operator";
};

const OPERATOR_PHASE_ORDER: Record<string, number> = {
  understand_request: 100,
  route_artifact: 200,
  search_sources: 300,
  read_sources: 400,
  author_artifact: 500,
  repair_artifact: 550,
  inspect_artifact: 600,
  verify_artifact: 700,
  present_artifact: 800,
};

export function operatorPhaseOrder(phase: string | null | undefined): number {
  const normalized = String(phase || "").trim().toLowerCase();
  return OPERATOR_PHASE_ORDER[normalized] ?? 9_000;
}

export function operatorStepStatus(value: string | null | undefined): ToolActivityStatus {
  const normalized = String(value || "").trim().toLowerCase();
  if (
    normalized === "active"
    || normalized === "pending"
    || normalized === "other"
  ) {
    return "active";
  }
  if (normalized === "blocked" || normalized === "failed") {
    return "blocked";
  }
  return "complete";
}

export function operatorStepKind(phase: string | null | undefined): ToolActivityKind {
  switch (String(phase || "").trim().toLowerCase()) {
    case "understand_request":
      return "understand";
    case "route_artifact":
      return "route";
    case "search_sources":
      return "search";
    case "read_sources":
      return "read";
    case "author_artifact":
    case "repair_artifact":
      return "write";
    case "inspect_artifact":
      return "inspect";
    case "verify_artifact":
      return "verify";
    case "present_artifact":
      return "present";
    default:
      return "other";
  }
}

export function operatorStepPreview(
  step: NonNullable<ChatArtifactSession["activeOperatorRun"]>["steps"][number],
): string | null {
  if (step.preview?.content?.trim()) {
    return step.preview.content.trim();
  }

  if (step.sourceRefs.length > 0) {
    const lines = step.sourceRefs
      .slice(0, 6)
      .map((source) => source.excerpt?.trim() || source.title.trim())
      .filter((line) => line.length > 0);
    if (lines.length > 0) {
      return lines.join("\n");
    }
  }

  if (step.verificationRefs.length > 0) {
    const lines = step.verificationRefs
      .slice(0, 6)
      .map((verification) =>
        verification.detail?.trim()
          ? `${verification.summary}\n${verification.detail}`
          : verification.summary,
      )
      .filter((line) => line.trim().length > 0);
    if (lines.length > 0) {
      return lines.join("\n\n");
    }
  }

  return null;
}

export function buildOperatorActivityRows(
  chatSession: ChatArtifactSession | null | undefined,
): TurnActivityEntry[] {
  const operatorRun = chatSession?.activeOperatorRun;
  if (!chatSession || !operatorRun) {
    return [];
  }

  const rows: TurnActivityEntry[] = [];
  operatorRun.steps.forEach((step, index) => {
    const sourceSummary =
      operatorStepStatus(step.status) === "active"
        ? operatorStepSourceSummary(step, index)
        : null;
    const phase = String(step.phase || "").trim().toLowerCase();
    const phaseOrder = operatorPhaseOrder(phase);
    if (phase === "search_sources") {
      const query =
        step.sourceRefs
          .map((source) => sourceQueryFromReason(source.reason))
          .find((value): value is string => !!value)
        || sourceQueryFromReason(step.detail)
        || sourceQueryFromReason(step.label);
      rows.push({
        key: step.stepId,
        kind: operatorStepKind(step.phase),
        status: operatorStepStatus(step.status),
        stepIndex: index,
        label: query ? `Searched "${query}"` : (step.label.trim() || "Search sources"),
        detail: step.detail?.trim() || null,
        preview: operatorStepPreview(step),
        sourceUrl: step.sourceRefs.find((source) => !!source.url)?.url || null,
        sourceSummary,
        sortOrder: step.startedAtMs || index,
        phaseOrder,
        source: "operator",
      });
      return;
    }

    if (phase === "read_sources" && step.sourceRefs.length > 0) {
      step.sourceRefs.forEach((source, sourceIndex) => {
        const url = firstStringValue(source.url);
        const domain =
          (url ? normalizedDomain(url) : null)
          || firstStringValue(source.domain)
          || source.title.trim()
          || "source";
        rows.push({
          key: `${step.stepId}:source:${source.sourceId || sourceIndex}`,
          kind: "read",
          status: operatorStepStatus(step.status),
          stepIndex: index,
          label: `Read ${domain}`,
          detail: url || null,
          preview: source.excerpt?.trim() || source.title.trim() || null,
          sourceUrl: url || null,
          sourceSummary: null,
          sortOrder: (step.startedAtMs || index) + (sourceIndex / 100),
          phaseOrder: phaseOrder + (sourceIndex / 100),
          source: "operator",
        });
      });
      return;
    }

    rows.push({
      key: step.stepId,
      kind: operatorStepKind(step.phase),
      status: operatorStepStatus(step.status),
      stepIndex: index,
      label: step.label.trim() || "Artifact step",
      detail: step.detail?.trim() || null,
      preview: operatorStepPreview(step),
      sourceUrl: step.sourceRefs.find((source) => !!source.url)?.url || null,
      sourceSummary,
      sortOrder: step.startedAtMs || index,
      phaseOrder,
      source: "operator",
    });
  });
  return rows;
}

export function toolGroupLabel(
  rows: TurnActivityEntry[],
  chatSession: ChatArtifactSession | null,
): string {
  if (chatSession) {
    const hasActiveRow = rows.some((row) => row.status === "active");
    if (hasActiveRow) {
      return `Thinking through ${chatSession.title}`;
    }
    return `${chatSession.title} activity`;
  }

  return `${rows.length} ${rows.length === 1 ? "tool call" : "tool calls"}`;
}
