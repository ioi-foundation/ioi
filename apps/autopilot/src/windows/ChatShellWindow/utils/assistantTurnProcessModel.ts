import type {
  AgentTask,
  AnswerPresentation,
  EvidenceTier,
  PlanSummary,
  SourceSummary,
  ThoughtSummary,
  ToolActivityGroupPresentation,
  ToolActivityRow,
} from "../../../types";

export type AssistantTurnStatus =
  | "thinking"
  | "running"
  | "complete"
  | "failed"
  | "blocked";

export type AssistantProcessItemKind =
  | "thought_summary"
  | "plan_step"
  | "tool_call"
  | "source_read"
  | "evidence_ref"
  | "validation_check"
  | "approval_gate"
  | "retry"
  | "error";

export type AssistantSourceKind =
  | "file"
  | "url"
  | "screenshot"
  | "trace"
  | "receipt"
  | "command";

export interface AssistantProcessItem {
  id: string;
  kind: AssistantProcessItemKind;
  status: "pending" | "running" | "complete" | "blocked" | "failed";
  label: string;
  detail?: string | null;
  preview?: string | null;
  sourceId?: string | null;
  authority?: "runtime" | "model_note" | "projection";
}

export interface AssistantSourceRef {
  id: string;
  kind: AssistantSourceKind;
  label: string;
  detail?: string | null;
  href?: string | null;
  faviconUrl?: string | null;
  iconFallback: "file" | "globe" | "image" | "terminal" | "shield" | "check";
}

export interface AssistantTurnProcess {
  status: AssistantTurnStatus;
  summaryLine: string;
  items: AssistantProcessItem[];
  sources: AssistantSourceRef[];
  finalAnswer: AnswerPresentation | null;
}

export interface BuildAssistantTurnProcessInput {
  task?: AgentTask | null;
  planSummary?: PlanSummary | null;
  runtimeModelLabel?: string | null;
  sourceSummary?: SourceSummary | null;
  thoughtSummary?: ThoughtSummary | null;
  toolActivityGroup?: ToolActivityGroupPresentation | null;
  finalAnswer?: AnswerPresentation | null;
  isRunning?: boolean;
  currentStep?: string | null;
}

const SECRET_KEY_RE = /(token|secret|password|api[_-]?key|credential|authorization)/i;
const MAX_PROCESS_ITEMS = 8;
const MAX_SOURCES = 8;

function compactWhitespace(value: string | null | undefined): string {
  return String(value || "").replace(/\s+/g, " ").trim();
}

function labelFromUrl(url: string): string {
  try {
    const parsed = new URL(url);
    return parsed.hostname.replace(/^www\./i, "");
  } catch {
    return url;
  }
}

export function redactProcessText(value: string | null | undefined): string | null {
  const compact = compactWhitespace(value);
  if (!compact) {
    return null;
  }

  const redacted = compact
    .split(/\s+/g)
    .map((token) => {
      if (SECRET_KEY_RE.test(token)) {
        return "[redacted]";
      }
      if (/^(bearer|basic)$/i.test(token)) {
        return "[redacted]";
      }
      if (/^[A-Za-z0-9_\-]{32,}$/.test(token)) {
        return "[redacted]";
      }
      return token;
    })
    .join(" ");

  return redacted.length <= 220 ? redacted : `${redacted.slice(0, 217).trim()}...`;
}

export function sourceIconFallbackForKind(
  kind: AssistantSourceKind,
): AssistantSourceRef["iconFallback"] {
  switch (kind) {
    case "file":
      return "file";
    case "screenshot":
      return "image";
    case "command":
      return "terminal";
    case "trace":
      return "shield";
    case "receipt":
      return "check";
    case "url":
    default:
      return "globe";
  }
}

function hasSettlementRefs(task: AgentTask | null | undefined): boolean {
  const materialization = task?.chat_session?.materialization as
    | Record<string, unknown>
    | undefined;
  const executionEnvelope = materialization?.executionEnvelope as
    | Record<string, unknown>
    | undefined;
  if (!executionEnvelope) {
    return false;
  }

  return [
    "settlementRefs",
    "settlement_refs",
    "settlementReceipts",
    "settlement_receipts",
  ].some((key) => Array.isArray(executionEnvelope[key]));
}

function evidenceTier(task: AgentTask | null | undefined): EvidenceTier {
  if (!task) {
    return "Projection";
  }
  if (hasSettlementRefs(task)) {
    return "Settlement receipt";
  }
  if ((task.events?.length ?? 0) > 0) {
    return "Runtime event receipt";
  }
  if ((task.artifacts?.length ?? 0) > 0) {
    return "Artifact promotion";
  }
  return "Projection";
}

function runtimeFailureDetail(task: AgentTask | null | undefined): string | null {
  const detail = redactProcessText(task?.current_step);
  if (!detail) {
    return null;
  }
  if (/error_class=|failed to parse tool call|invalid_tool_call/i.test(detail)) {
    return detail;
  }
  return null;
}

function taskStatus(
  task: AgentTask | null | undefined,
  isRunning: boolean,
): AssistantTurnStatus {
  if (task?.phase === "Gate") {
    return "blocked";
  }
  if (task?.phase === "Failed" || runtimeFailureDetail(task)) {
    return "failed";
  }
  if (isRunning || task?.phase === "Running") {
    return "running";
  }
  return "complete";
}

function statusForToolRow(row: ToolActivityRow): AssistantProcessItem["status"] {
  if (row.status === "active") {
    return "running";
  }
  if (row.status === "blocked") {
    return "blocked";
  }
  return "complete";
}

function sourceRefFromUrl(
  url: string,
  label: string | null | undefined,
  faviconUrl: string | null | undefined,
  index: number,
): AssistantSourceRef {
  const displayLabel = compactWhitespace(label) || labelFromUrl(url);
  return {
    id: `url:${url}:${index}`,
    kind: "url",
    label: displayLabel,
    detail: url,
    href: url,
    faviconUrl: faviconUrl || null,
    iconFallback: sourceIconFallbackForKind("url"),
  };
}

function sourceRefsFromSummary(sourceSummary: SourceSummary | null | undefined) {
  if (!sourceSummary) {
    return [];
  }
  const refs: AssistantSourceRef[] = [];
  const seen = new Set<string>();

  sourceSummary.browses.forEach((browse, index) => {
    const key = browse.url.toLowerCase();
    if (seen.has(key)) {
      return;
    }
    seen.add(key);
    const faviconUrl =
      sourceSummary.domains.find((domain) => domain.domain === browse.domain)
        ?.faviconUrl || null;
    refs.push(sourceRefFromUrl(browse.url, browse.title || browse.domain, faviconUrl, index));
  });

  if (refs.length === 0) {
    sourceSummary.domains.forEach((domain, index) => {
      const key = domain.domain.toLowerCase();
      if (seen.has(key)) {
        return;
      }
      seen.add(key);
      refs.push({
        id: `domain:${domain.domain}:${index}`,
        kind: "url",
        label: domain.domain.replace(/^www\./i, ""),
        detail: `${domain.count} ${domain.count === 1 ? "source" : "sources"}`,
        faviconUrl: domain.faviconUrl || null,
        iconFallback: sourceIconFallbackForKind("url"),
      });
    });
  }

  return refs.slice(0, MAX_SOURCES);
}

function sourceRefsFromToolRows(
  rows: ToolActivityRow[],
  existing: AssistantSourceRef[],
): AssistantSourceRef[] {
  const refs = [...existing];
  const seen = new Set(
    refs.map((source) =>
      (source.href || `${source.kind}:${source.label}`).toLowerCase(),
    ),
  );

  rows.forEach((row, index) => {
    if (!row.sourceUrl) {
      return;
    }
    const key = row.sourceUrl.toLowerCase();
    if (seen.has(key)) {
      return;
    }
    seen.add(key);
    refs.push(sourceRefFromUrl(row.sourceUrl, row.label, null, index));
  });

  return refs.slice(0, MAX_SOURCES);
}

function toolRowsFromGroup(
  group: ToolActivityGroupPresentation | null | undefined,
): ToolActivityRow[] {
  return group?.rows ?? [];
}

function thoughtItems(
  thoughtSummary: ThoughtSummary | null | undefined,
): AssistantProcessItem[] {
  if (!thoughtSummary?.agents.length) {
    return [];
  }

  const items: AssistantProcessItem[] = [];
  thoughtSummary.agents.forEach((agent, agentIndex) => {
    agent.notes.slice(0, 2).forEach((note, noteIndex) => {
      const detail = redactProcessText(note);
      if (!detail) {
        return;
      }
      items.push({
        id: `thought:${agentIndex}:${noteIndex}`,
        kind: "thought_summary",
        status: "complete",
        label: agent.agentLabel || "Work note",
        detail,
        authority: "model_note",
      });
    });
  });

  return items.slice(0, 3);
}

function planItem(
  planSummary: PlanSummary | null | undefined,
  currentStep: string | null | undefined,
  status: AssistantTurnStatus,
): AssistantProcessItem | null {
  const activeText = redactProcessText(currentStep);
  if (status === "running" && activeText) {
    return {
      id: "plan:current",
      kind: "plan_step",
      status: "running",
      label: activeText,
      authority: "runtime",
    };
  }

  const stage = redactProcessText(planSummary?.currentStage);
  if (!stage || planSummary?.routeDecision?.outputIntent === "direct_inline") {
    return null;
  }

  return {
    id: "plan:stage",
    kind: "plan_step",
    status: "complete",
    label: stage,
    authority: "runtime",
  };
}

function validationItems(planSummary: PlanSummary | null | undefined) {
  const items: AssistantProcessItem[] = [];
  if (
    planSummary?.verifierOutcome &&
    planSummary.verifierOutcome !== "pass"
  ) {
    items.push({
      id: `validation:${planSummary.verifierOutcome}`,
      kind: "validation_check",
      status: planSummary.verifierOutcome === "blocked" ? "blocked" : "complete",
      label:
        planSummary.verifierOutcome === "blocked"
          ? "Validation blocked"
          : "Validation warning",
      detail: redactProcessText(planSummary.progressSummary),
      authority: "runtime",
    });
  }

  if (planSummary?.approvalState && planSummary.approvalState !== "clear") {
    items.push({
      id: `approval:${planSummary.approvalState}`,
      kind: "approval_gate",
      status:
        planSummary.approvalState === "denied"
          ? "blocked"
          : planSummary.approvalState === "pending"
            ? "running"
            : "complete",
      label: `Approval ${planSummary.approvalState}`,
      detail: redactProcessText(planSummary.pauseSummary),
      authority: "runtime",
    });
  }

  return items;
}

function taskGateItems(task: AgentTask | null | undefined): AssistantProcessItem[] {
  const failureDetail = runtimeFailureDetail(task);
  if (task?.phase === "Failed" || failureDetail) {
    return [
      {
        id: "task:failed",
        kind: "error",
        status: "failed",
        label: failureDetail ? "Tool call rejected" : "Run failed",
        detail: failureDetail || redactProcessText(task?.current_step),
        authority: "runtime",
      },
    ];
  }
  if (task?.phase === "Gate" || task?.pending_request_hash || task?.gate_info) {
    return [
      {
        id: "task:gate",
        kind: "approval_gate",
        status: "blocked",
        label: "Approval required",
        detail: redactProcessText(
          task.gate_info?.description ||
            task.gate_info?.operator_note ||
            task.gate_info?.title ||
            task.current_step,
        ),
        authority: "runtime",
      },
    ];
  }
  return [];
}

function processItems(input: BuildAssistantTurnProcessInput): AssistantProcessItem[] {
  const status = taskStatus(input.task, Boolean(input.isRunning));
  const rows = toolRowsFromGroup(input.toolActivityGroup);
  const items: AssistantProcessItem[] = [];
  const maybePlan = planItem(input.planSummary, input.currentStep, status);
  if (maybePlan) {
    items.push(maybePlan);
  }

  items.push(...taskGateItems(input.task));
  items.push(...validationItems(input.planSummary));

  for (const row of rows) {
    items.push({
      id: `tool:${row.key}`,
      kind: "tool_call",
      status: statusForToolRow(row),
      label: row.label,
      detail: redactProcessText(row.detail),
      preview: redactProcessText(row.preview),
      sourceId: row.sourceUrl ? `url:${row.sourceUrl}` : null,
      authority: "runtime",
    });
  }

  if (rows.length === 0 && status !== "complete") {
    items.push(...thoughtItems(input.thoughtSummary));
  }

  if (input.task?.visual_hash) {
    items.push({
      id: `evidence:screenshot:${input.task.visual_hash}`,
      kind: "evidence_ref",
      status: "complete",
      label: "Captured visual context",
      detail: input.task.visual_hash,
      authority: "runtime",
    });
  }

  const seen = new Set<string>();
  return items
    .filter((item) => {
      const label = compactWhitespace(item.label);
      if (!label) {
        return false;
      }
      const key = `${item.kind}:${label}:${item.detail || ""}`.toLowerCase();
      if (seen.has(key)) {
        return false;
      }
      seen.add(key);
      return true;
    })
    .slice(0, MAX_PROCESS_ITEMS);
}

function summaryLine(
  status: AssistantTurnStatus,
  items: AssistantProcessItem[],
  sources: AssistantSourceRef[],
  input: BuildAssistantTurnProcessInput,
): string {
  if (status === "running" || status === "thinking") {
    return compactWhitespace(input.currentStep) || "Thinking";
  }
  if (status === "blocked") {
    return "Needs operator attention";
  }
  if (status === "failed") {
    return "Run failed";
  }

  const toolCount = items.filter((item) => item.kind === "tool_call").length;
  const useful: string[] = [];
  if (toolCount > 0) {
    useful.push(`${toolCount} ${toolCount === 1 ? "tool call" : "tool calls"}`);
  }
  if (sources.length > 0) {
    useful.push(`${sources.length} ${sources.length === 1 ? "source" : "sources"}`);
  }
  const validationCount = items.filter(
    (item) => item.kind === "validation_check",
  ).length;
  if (validationCount > 0) {
    useful.push(`${validationCount} validation ${validationCount === 1 ? "check" : "checks"}`);
  }
  return useful.length > 0 ? `Worked with ${useful.join(" · ")}` : "Ready";
}

export function buildAssistantTurnProcess(
  input: BuildAssistantTurnProcessInput,
): AssistantTurnProcess {
  const status = taskStatus(input.task, Boolean(input.isRunning));
  const rows = toolRowsFromGroup(input.toolActivityGroup);
  const sources = sourceRefsFromToolRows(
    rows,
    sourceRefsFromSummary(input.sourceSummary),
  );
  const items = processItems(input);

  return {
    status,
    summaryLine: summaryLine(status, items, sources, input),
    items,
    sources,
    finalAnswer: input.finalAnswer ?? null,
  };
}

export function hasMeaningfulProcess(process: AssistantTurnProcess): boolean {
  return process.items.length > 0 || process.status === "running" || process.status === "blocked" || process.status === "failed";
}

export function testOnlySourceRefsFromSummary(
  sourceSummary: SourceSummary | null | undefined,
): AssistantSourceRef[] {
  return sourceRefsFromSummary(sourceSummary);
}

export function testOnlyEvidenceTier(task: AgentTask | null | undefined): EvidenceTier {
  return evidenceTier(task);
}
