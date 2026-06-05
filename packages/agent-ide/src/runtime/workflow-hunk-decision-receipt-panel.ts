import type { WorkflowRuntimeThreadEventLike } from "./workflow-runtime-event-projection";
import {
  workflowRuntimeEventId,
  workflowRuntimeEventKind,
} from "./workflow-runtime-event-identity";

export const WORKFLOW_HUNK_DECISION_RECEIPT_PANEL_SCHEMA_VERSION =
  "ioi.workflow.hunk-decision-receipt-panel.v1" as const;

export type WorkflowHunkDecisionReceiptStatus =
  | "proposed"
  | "waiting_for_decision"
  | "approved"
  | "rejected"
  | "applied"
  | "blocked";

export interface WorkflowHunkDecisionReceiptPanelInput {
  events: readonly WorkflowRuntimeThreadEventLike[];
  hunkDecisions?: readonly unknown[];
  applyResults?: readonly unknown[];
}

export interface WorkflowHunkDecisionReceiptRow {
  id: string;
  status: WorkflowHunkDecisionReceiptStatus;
  proposalId: string | null;
  approvalId: string | null;
  threadId: string | null;
  turnId: string | null;
  workflowGraphId: string | null;
  workflowNodeId: string | null;
  targetWorkflowNodeIds: string[];
  filePath: string | null;
  hunkIndex: number;
  hunkHeader: string;
  oldStart: number | null;
  oldLines: number | null;
  newStart: number | null;
  newLines: number | null;
  addedLineCount: number;
  removedLineCount: number;
  previewLines: string[];
  decision: "approve" | "reject" | null;
  bridgeRequestType: string | null;
  bridgeOwnsRuntimeState: boolean | null;
  proposalEventId: string | null;
  approvalDecisionEventId: string | null;
  applyEventId: string | null;
  blockedReason: string | null;
  patchHash: string | null;
  receiptRefs: string[];
  proposalReceiptRefs: string[];
  decisionReceiptRefs: string[];
  applyReceiptRefs: string[];
  policyDecisionRefs: string[];
  approveEndpoint: string | null;
  rejectEndpoint: string | null;
  applyEndpoint: string | null;
}

export interface WorkflowHunkDecisionReceiptPanel {
  schemaVersion: typeof WORKFLOW_HUNK_DECISION_RECEIPT_PANEL_SCHEMA_VERSION;
  status: "ready" | "needs_evidence" | "blocked";
  hunkCount: number;
  proposedCount: number;
  approvedCount: number;
  rejectedCount: number;
  appliedCount: number;
  blockedCount: number;
  missingDecisionReceiptCount: number;
  rows: WorkflowHunkDecisionReceiptRow[];
  evidenceRefs: string[];
}

interface ParsedDiffHunk {
  filePath: string | null;
  hunkIndex: number;
  hunkHeader: string;
  oldStart: number | null;
  oldLines: number | null;
  newStart: number | null;
  newLines: number | null;
  addedLineCount: number;
  removedLineCount: number;
  previewLines: string[];
}

export function buildWorkflowHunkDecisionReceiptPanel(
  input: WorkflowHunkDecisionReceiptPanelInput,
): WorkflowHunkDecisionReceiptPanel {
  const events = normalizeArray(input.events).sort((a, b) => eventSeq(a) - eventSeq(b));
  const proposalEvents = events.filter(isWorkflowEditProposalEvent);
  const rows = proposalEvents.flatMap((proposalEvent) =>
    rowsForProposal({
      proposalEvent,
      events,
      hunkDecisions: normalizeUnknownArray(input.hunkDecisions),
      applyResults: normalizeUnknownArray(input.applyResults),
    }),
  );
  const hunkCount = rows.length;
  const proposedCount = rows.filter((row) => row.status === "proposed").length;
  const approvedCount = rows.filter((row) => row.status === "approved").length;
  const rejectedCount = rows.filter((row) => row.status === "rejected").length;
  const appliedCount = rows.filter((row) => row.status === "applied").length;
  const blockedCount = rows.filter((row) => row.status === "blocked").length;
  const missingDecisionReceiptCount = rows.filter(
    (row) => row.decision && row.decisionReceiptRefs.length === 0,
  ).length;
  return {
    schemaVersion: WORKFLOW_HUNK_DECISION_RECEIPT_PANEL_SCHEMA_VERSION,
    status:
      hunkCount === 0 || missingDecisionReceiptCount > 0
        ? "needs_evidence"
        : blockedCount > 0 && appliedCount === 0 && approvedCount === 0
          ? "blocked"
          : "ready",
    hunkCount,
    proposedCount,
    approvedCount,
    rejectedCount,
    appliedCount,
    blockedCount,
    missingDecisionReceiptCount,
    rows,
    evidenceRefs: uniqueStrings(rows.flatMap((row) => row.receiptRefs)),
  };
}

function rowsForProposal({
  proposalEvent,
  events,
  hunkDecisions,
  applyResults,
}: {
  proposalEvent: WorkflowRuntimeThreadEventLike;
  events: WorkflowRuntimeThreadEventLike[];
  hunkDecisions: unknown[];
  applyResults: unknown[];
}): WorkflowHunkDecisionReceiptRow[] {
  const proposalPayload = payloadForEvent(proposalEvent);
  const proposalId = proposalIdForEvent(proposalEvent);
  const approvalId =
    stringField(proposalEvent, "approvalId", "approval_id") ??
    stringField(proposalPayload, "approvalId", "approval_id");
  const threadId = stringField(proposalEvent, "threadId", "thread_id");
  const workflowGraphId =
    stringField(proposalEvent, "workflowGraphId", "workflow_graph_id") ??
    stringField(proposalPayload, "workflowGraphId", "workflow_graph_id");
  const workflowNodeId =
    stringField(proposalEvent, "workflowNodeId", "workflow_node_id") ??
    stringField(proposalPayload, "workflowNodeId", "workflow_node_id");
  const workflowRelativePath =
    stringField(proposalPayload, "workflowRelativePath", "workflow_relative_path") ??
    stringField(proposalPayload, "workflowPath", "workflow_path");
  const patchHash = stringField(proposalPayload, "patchHash", "patch_hash");
  const codeDiff = stringField(proposalPayload, "codeDiff", "code_diff");
  const targetWorkflowNodeIds = uniqueStrings([
    ...arrayField(proposalPayload, "targetWorkflowNodeIds", "target_workflow_node_ids"),
    ...arrayField(proposalPayload, "boundedTargets", "bounded_targets"),
  ]);
  const hunks = parseUnifiedDiff(codeDiff ?? "", workflowRelativePath);
  const approvalDecisionEvent = latestEvent(events, (event) =>
    isApprovalDecisionEvent(event, proposalEvent, approvalId),
  );
  const applyEvent = latestEvent(events, (event) =>
    isWorkflowEditApplyEvent(event, proposalEvent, proposalId, approvalDecisionEvent),
  );
  const blockedApply = latestApplyResult(applyResults, proposalId, approvalId, "blocked");
  const proposalReceiptRefs = receiptRefsForEvent(proposalEvent);
  const decisionReceiptRefs = approvalDecisionEvent
    ? receiptRefsForEvent(approvalDecisionEvent)
    : receiptRefsForBridgeDecision(hunkDecisions, approvalId);
  const applyReceiptRefs = applyEvent ? receiptRefsForEvent(applyEvent) : receiptRefsForValue(blockedApply);
  const policyDecisionRefs = uniqueStrings([
    ...policyRefsForEvent(proposalEvent),
    ...policyRefsForEvent(approvalDecisionEvent),
    ...policyRefsForEvent(applyEvent),
    ...policyRefsForValue(blockedApply),
  ]);
  const decision = decisionForEvents(approvalDecisionEvent, hunkDecisions, approvalId);
  const status = statusForHunk({ decision, approvalDecisionEvent, applyEvent, blockedApply });
  return hunks.map((hunk) => {
    const bridgeDecision = matchingBridgeDecision(hunkDecisions, {
      proposalId,
      approvalId,
      filePath: hunk.filePath,
      hunkIndex: hunk.hunkIndex,
    });
    return {
      id: `hunk-decision-${safeId(proposalId ?? "proposal")}-${hunk.hunkIndex}`,
      status,
      proposalId,
      approvalId,
      threadId,
      turnId: stringField(proposalEvent, "turnId", "turn_id"),
      workflowGraphId,
      workflowNodeId,
      targetWorkflowNodeIds,
      filePath: hunk.filePath,
      hunkIndex: hunk.hunkIndex,
      hunkHeader: hunk.hunkHeader,
      oldStart: hunk.oldStart,
      oldLines: hunk.oldLines,
      newStart: hunk.newStart,
      newLines: hunk.newLines,
      addedLineCount: hunk.addedLineCount,
      removedLineCount: hunk.removedLineCount,
      previewLines: hunk.previewLines,
      decision,
      bridgeRequestType: stringField(bridgeDecision, "requestType", "request_type"),
      bridgeOwnsRuntimeState: booleanField(objectField(bridgeDecision, "payload"), "ownsRuntimeState", "owns_runtime_state"),
      proposalEventId: eventId(proposalEvent),
      approvalDecisionEventId: eventId(approvalDecisionEvent),
      applyEventId: eventId(applyEvent),
      blockedReason: stringField(blockedApply, "reason") ?? stringField(objectField(blockedApply, "error", "details"), "reason"),
      patchHash,
      receiptRefs: uniqueStrings([
        ...proposalReceiptRefs,
        ...decisionReceiptRefs,
        ...applyReceiptRefs,
        ...receiptRefsForValue(bridgeDecision),
      ]),
      proposalReceiptRefs,
      decisionReceiptRefs,
      applyReceiptRefs,
      policyDecisionRefs,
      approveEndpoint: approvalId && threadId
        ? `/v1/threads/${encodeURIComponent(threadId)}/approvals/${encodeURIComponent(approvalId)}/decision`
        : null,
      rejectEndpoint: approvalId && threadId
        ? `/v1/threads/${encodeURIComponent(threadId)}/approvals/${encodeURIComponent(approvalId)}/decision`
        : null,
      applyEndpoint: proposalId && threadId
        ? `/v1/threads/${encodeURIComponent(threadId)}/workflow-edit-proposals/${encodeURIComponent(proposalId)}/apply`
        : null,
    };
  });
}

function parseUnifiedDiff(diff: string, fallbackFilePath: string | null): ParsedDiffHunk[] {
  const hunks: ParsedDiffHunk[] = [];
  let currentFilePath = fallbackFilePath;
  let active: ParsedDiffHunk | null = null;
  const pushActive = () => {
    if (active) hunks.push(active);
    active = null;
  };
  for (const line of diff.split(/\r?\n/)) {
    if (line.startsWith("diff --git ")) {
      pushActive();
      currentFilePath = diffGitPath(line) ?? currentFilePath;
      continue;
    }
    if (line.startsWith("+++ ")) {
      currentFilePath = cleanDiffPath(line.slice(4)) ?? currentFilePath;
      continue;
    }
    if (line.startsWith("@@ ")) {
      pushActive();
      const parsed = parseHunkHeader(line);
      active = {
        filePath: currentFilePath,
        hunkIndex: hunks.length,
        hunkHeader: line,
        oldStart: parsed.oldStart,
        oldLines: parsed.oldLines,
        newStart: parsed.newStart,
        newLines: parsed.newLines,
        addedLineCount: 0,
        removedLineCount: 0,
        previewLines: [],
      };
      continue;
    }
    if (!active) continue;
    if (line.startsWith("+") && !line.startsWith("+++")) active.addedLineCount += 1;
    if (line.startsWith("-") && !line.startsWith("---")) active.removedLineCount += 1;
    if (active.previewLines.length < 12) active.previewLines.push(line);
  }
  pushActive();
  return hunks;
}

function parseHunkHeader(line: string): {
  oldStart: number | null;
  oldLines: number | null;
  newStart: number | null;
  newLines: number | null;
} {
  const match = /^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@/.exec(line);
  return {
    oldStart: match ? Number(match[1]) : null,
    oldLines: match ? Number(match[2] ?? "1") : null,
    newStart: match ? Number(match[3]) : null,
    newLines: match ? Number(match[4] ?? "1") : null,
  };
}

function diffGitPath(line: string): string | null {
  const parts = line.trim().split(/\s+/);
  return cleanDiffPath(parts[3] ?? parts[2] ?? null);
}

function cleanDiffPath(value: string | null): string | null {
  if (!value) return null;
  const trimmed = value.trim();
  if (!trimmed || trimmed === "/dev/null") return null;
  return trimmed.replace(/^[ab]\//, "");
}

function statusForHunk({
  decision,
  approvalDecisionEvent,
  applyEvent,
  blockedApply,
}: {
  decision: "approve" | "reject" | null;
  approvalDecisionEvent: WorkflowRuntimeThreadEventLike | null;
  applyEvent: WorkflowRuntimeThreadEventLike | null;
  blockedApply: Record<string, unknown> | null;
}): WorkflowHunkDecisionReceiptStatus {
  if (applyEvent) return "applied";
  if (blockedApply) return "blocked";
  if (decision === "reject") return "rejected";
  if (decision === "approve") return "approved";
  return approvalDecisionEvent ? "waiting_for_decision" : "proposed";
}

function isWorkflowEditProposalEvent(event: WorkflowRuntimeThreadEventLike): boolean {
  return eventKind(event) === "workflow.edit_proposed" || eventType(event) === "workflow_edit_proposed";
}

function isWorkflowEditApplyEvent(
  event: WorkflowRuntimeThreadEventLike,
  proposalEvent: WorkflowRuntimeThreadEventLike,
  proposalId: string | null,
  approvalDecisionEvent: WorkflowRuntimeThreadEventLike | null,
): boolean {
  if (!approvalDecisionEvent || eventSeq(event) <= eventSeq(approvalDecisionEvent)) return false;
  if (eventKind(event) !== "workflow.edit_applied" && eventType(event) !== "workflow_edit_applied") {
    return false;
  }
  const payload = payloadForEvent(event);
  const eventProposalId = proposalIdForEvent(event);
  const proposalEventId = stringField(payload, "proposalEventId", "proposal_event_id");
  return (
    (!proposalId || eventProposalId === proposalId) &&
    (!proposalEventId || proposalEventId === eventId(proposalEvent))
  );
}

function isApprovalDecisionEvent(
  event: WorkflowRuntimeThreadEventLike,
  proposalEvent: WorkflowRuntimeThreadEventLike,
  approvalId: string | null,
): boolean {
  if (eventSeq(event) <= eventSeq(proposalEvent)) return false;
  const kind = eventKind(event);
  if (kind !== "approval.approved" && kind !== "approval.rejected" && kind !== "approval.revoked") {
    return false;
  }
  const eventApprovalId =
    stringField(event, "approvalId", "approval_id") ??
    stringField(payloadForEvent(event), "approvalId", "approval_id");
  return !approvalId || eventApprovalId === approvalId;
}

function decisionForEvents(
  event: WorkflowRuntimeThreadEventLike | null,
  hunkDecisions: unknown[],
  approvalId: string | null,
): "approve" | "reject" | null {
  const payload = payloadForEvent(event);
  const eventDecision = stringField(payload, "decision");
  if (eventDecision === "approve" || eventKind(event) === "approval.approved") return "approve";
  if (eventDecision === "reject" || eventKind(event) === "approval.rejected") return "reject";
  const bridgeDecision = matchingBridgeDecision(hunkDecisions, { proposalId: null, approvalId, filePath: null, hunkIndex: null });
  const bridgeValue = stringField(objectField(bridgeDecision, "payload"), "decision");
  return bridgeValue === "approve" || bridgeValue === "reject" ? bridgeValue : null;
}

function matchingBridgeDecision(
  hunkDecisions: unknown[],
  match: {
    proposalId: string | null;
    approvalId: string | null;
    filePath: string | null;
    hunkIndex: number | null;
  },
): Record<string, unknown> | null {
  return (
    hunkDecisions
      .map(objectValue)
      .filter((value): value is Record<string, unknown> => Boolean(value))
      .find((value) => {
        const payload = objectField(value, "payload");
        if (stringField(value, "requestType", "request_type") && stringField(value, "requestType", "request_type") !== "chat.hunkDecision") {
          return false;
        }
        const approvalId = stringField(payload, "approvalId", "approval_id") ?? stringField(value, "approvalId", "approval_id");
        const proposalId = stringField(payload, "proposalId", "proposal_id") ?? stringField(value, "proposalId", "proposal_id");
        const hunkFile =
          stringField(payload, "hunkFile", "hunk_file", "filePath", "file_path", "file") ??
          stringField(value, "hunkFile", "hunk_file", "filePath", "file_path", "file");
        const hunkIndex = numberField(payload, "hunkIndex", "hunk_index") ?? numberField(value, "hunkIndex", "hunk_index");
        return (
          (!match.approvalId || !approvalId || approvalId === match.approvalId) &&
          (!match.proposalId || !proposalId || proposalId === match.proposalId) &&
          (!match.filePath || !hunkFile || cleanDiffPath(hunkFile) === match.filePath) &&
          (match.hunkIndex === null || hunkIndex === null || hunkIndex === match.hunkIndex)
        );
      }) ?? null
  );
}

function latestApplyResult(
  values: unknown[],
  proposalId: string | null,
  approvalId: string | null,
  status: string,
): Record<string, unknown> | null {
  return (
    values
      .map(objectValue)
      .filter((value): value is Record<string, unknown> => Boolean(value))
      .reverse()
      .find((value) => {
        const valueProposalId = stringField(value, "proposalId", "proposal_id");
        const valueApprovalId = stringField(value, "approvalId", "approval_id");
        return (
          stringField(value, "status") === status &&
          (!proposalId || !valueProposalId || valueProposalId === proposalId) &&
          (!approvalId || !valueApprovalId || valueApprovalId === approvalId)
        );
      }) ?? null
  );
}

function latestEvent(
  events: WorkflowRuntimeThreadEventLike[],
  predicate: (event: WorkflowRuntimeThreadEventLike) => boolean,
): WorkflowRuntimeThreadEventLike | null {
  return [...events].reverse().find(predicate) ?? null;
}

function proposalIdForEvent(event: WorkflowRuntimeThreadEventLike | null): string | null {
  return stringField(payloadForEvent(event), "proposalId", "proposal_id");
}

function payloadForEvent(event: WorkflowRuntimeThreadEventLike | null): Record<string, unknown> {
  return objectField(event, "payload_summary", "payload");
}

function eventId(event: WorkflowRuntimeThreadEventLike | null): string | null {
  return workflowRuntimeEventId(event);
}

function eventKind(event: WorkflowRuntimeThreadEventLike | null): string | null {
  return workflowRuntimeEventKind(event);
}

function eventType(event: WorkflowRuntimeThreadEventLike | null): string | null {
  return stringField(event, "type");
}

function eventSeq(event: WorkflowRuntimeThreadEventLike | null): number {
  return numberField(event, "seq") ?? 0;
}

function receiptRefsForEvent(event: WorkflowRuntimeThreadEventLike | null): string[] {
  return arrayField(event, "receiptRefs", "receipt_refs").map(String);
}

function receiptRefsForValue(value: unknown): string[] {
  return arrayField(value, "receiptRefs", "receipt_refs").map(String);
}

function receiptRefsForBridgeDecision(values: unknown[], approvalId: string | null): string[] {
  return receiptRefsForValue(matchingBridgeDecision(values, { proposalId: null, approvalId, filePath: null, hunkIndex: null }));
}

function policyRefsForEvent(event: WorkflowRuntimeThreadEventLike | null): string[] {
  return arrayField(event, "policyDecisionRefs", "policy_decision_refs").map(String);
}

function policyRefsForValue(value: unknown): string[] {
  return arrayField(value, "policyDecisionRefs", "policy_decision_refs").map(String);
}

function objectValue(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function objectField(record: unknown, ...keys: string[]): Record<string, unknown> {
  const object = objectValue(record);
  for (const key of keys) {
    const value = objectValue(object?.[key]);
    if (value) return value;
  }
  return {};
}

function stringField(record: unknown, ...keys: string[]): string | null {
  const object = objectValue(record);
  for (const key of keys) {
    const value = object?.[key];
    if (typeof value === "string" && value.trim()) return value.trim();
    if (typeof value === "number" && Number.isFinite(value)) return String(value);
  }
  return null;
}

function numberField(record: unknown, ...keys: string[]): number | null {
  const object = objectValue(record);
  for (const key of keys) {
    const value = object?.[key];
    if (typeof value === "number" && Number.isFinite(value)) return value;
    if (typeof value === "string" && value.trim() && Number.isFinite(Number(value))) {
      return Number(value);
    }
  }
  return null;
}

function booleanField(record: unknown, ...keys: string[]): boolean | null {
  const object = objectValue(record);
  for (const key of keys) {
    const value = object?.[key];
    if (typeof value === "boolean") return value;
  }
  return null;
}

function arrayField(record: unknown, ...keys: string[]): unknown[] {
  const object = objectValue(record);
  for (const key of keys) {
    const value = object?.[key];
    if (Array.isArray(value)) return value;
  }
  return [];
}

function normalizeArray(
  value: readonly WorkflowRuntimeThreadEventLike[] | undefined,
): WorkflowRuntimeThreadEventLike[] {
  return Array.isArray(value) ? [...value] : [];
}

function normalizeUnknownArray(value: readonly unknown[] | undefined): unknown[] {
  return Array.isArray(value) ? [...value] : [];
}

function uniqueStrings(values: readonly unknown[]): string[] {
  return Array.from(
    new Set(
      values
        .map((value) => (value === undefined || value === null ? null : String(value).trim()))
        .filter((value): value is string => Boolean(value)),
    ),
  );
}

function safeId(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9._:-]+/g, "-").replace(/^-+|-+$/g, "") || "item";
}
