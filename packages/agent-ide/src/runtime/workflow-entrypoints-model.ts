import type { Node, NodeLogic, WorkflowProject } from "../types/graph";

export type WorkflowEntrypointKind = "source" | "trigger";
export type WorkflowTriggerKind = "manual" | "scheduled" | "event";

export interface WorkflowSourceEntrypointRow {
  node: Node;
  kind: WorkflowEntrypointKind;
  status: string;
  detail: string;
  ready: boolean;
}

export interface WorkflowScheduleEntrypointRow {
  node: Node;
  triggerKind: WorkflowTriggerKind;
  ready: boolean;
  status: "ready" | "blocked";
  detail: string;
}

export interface WorkflowEntrypointsModel {
  sourceRows: WorkflowSourceEntrypointRow[];
  triggerRows: WorkflowScheduleEntrypointRow[];
  totalStartPoints: number;
  totalTriggers: number;
  readyStartPoints: number;
  blockedStartPoints: number;
  readyTriggers: number;
  blockedTriggers: number;
}

function nodeLogic(node: Node): NodeLogic {
  return node.config?.logic ?? {};
}

function triggerKind(logic: NodeLogic): WorkflowTriggerKind {
  return logic.triggerKind ?? "manual";
}

function triggerReady(kind: WorkflowTriggerKind, logic: NodeLogic): boolean {
  if (kind === "scheduled") return Boolean(logic.cronSchedule);
  if (kind === "event") return Boolean(logic.eventSourceRef);
  return true;
}

function triggerDetail(kind: WorkflowTriggerKind, logic: NodeLogic): string {
  if (kind === "scheduled") return String(logic.cronSchedule ?? "No schedule");
  if (kind === "event") return String(logic.eventSourceRef ?? "No event source");
  return "Manual invocation";
}

function sourceRow(node: Node): WorkflowSourceEntrypointRow | null {
  if (node.type !== "source" && node.type !== "trigger") return null;

  const logic = nodeLogic(node);
  if (node.type === "trigger") {
    const kind = triggerKind(logic);
    const ready = triggerReady(kind, logic);
    const status =
      kind === "scheduled"
        ? ready
          ? "scheduled"
          : "needs schedule"
        : kind === "event"
          ? ready
            ? "event"
            : "needs event source"
          : "manual";
    return {
      node,
      kind: "trigger",
      status,
      detail: String(logic.eventSourceRef ?? logic.cronSchedule ?? kind),
      ready,
    };
  }

  const ready = logic.payload !== undefined;
  return {
    node,
    kind: "source",
    status: ready ? "payload ready" : "needs payload",
    detail:
      typeof logic.payload === "string"
        ? logic.payload
        : ready
          ? "Structured payload configured"
          : "No payload configured",
    ready,
  };
}

function scheduleRow(node: Node): WorkflowScheduleEntrypointRow | null {
  if (node.type !== "trigger") return null;
  const logic = nodeLogic(node);
  const kind = triggerKind(logic);
  const ready = triggerReady(kind, logic);
  return {
    node,
    triggerKind: kind,
    ready,
    status: ready ? "ready" : "blocked",
    detail: triggerDetail(kind, logic),
  };
}

export function workflowEntrypointsModel(
  workflow: WorkflowProject,
): WorkflowEntrypointsModel {
  const sourceRows = workflow.nodes
    .map(sourceRow)
    .filter((row): row is WorkflowSourceEntrypointRow => Boolean(row));
  const triggerRows = workflow.nodes
    .map(scheduleRow)
    .filter((row): row is WorkflowScheduleEntrypointRow => Boolean(row));
  const readyStartPoints = sourceRows.filter((row) => row.ready).length;
  const readyTriggers = triggerRows.filter((row) => row.ready).length;

  return {
    sourceRows,
    triggerRows,
    totalStartPoints: sourceRows.length,
    totalTriggers: triggerRows.length,
    readyStartPoints,
    blockedStartPoints: sourceRows.length - readyStartPoints,
    readyTriggers,
    blockedTriggers: triggerRows.length - readyTriggers,
  };
}
