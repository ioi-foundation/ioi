export const WORKFLOW_SESSION_BRAIN_PANEL_SCHEMA_VERSION =
  "ioi.workflow.session-brain-panel.v1" as const;

export type WorkflowSessionBrainArtifactKind =
  | "implementation_plan"
  | "task"
  | "walkthrough"
  | "scratch";

export interface WorkflowSessionBrainPanelInput {
  memoryProjection: Record<string, unknown>;
  memoryPath?: Record<string, unknown>;
  events?: unknown[];
  completion?: {
    completed?: boolean;
    completedAt?: string | null;
    receiptRefs?: unknown[];
  };
}

export interface WorkflowSessionBrainArtifactRow {
  id: string;
  artifactKind: WorkflowSessionBrainArtifactKind;
  status: "present" | "missing";
  label: string;
  artifactPath: string | null;
  memoryRecordId: string | null;
  memoryKey: string | null;
  preview: string | null;
  receiptRefs: string[];
  evidenceRefs: string[];
}

export interface WorkflowSessionBrainPanel {
  schemaVersion: typeof WORKFLOW_SESSION_BRAIN_PANEL_SCHEMA_VERSION;
  status: "ready" | "needs_artifacts" | "blocked";
  threadId: string | null;
  workspace: string | null;
  brainRoot: string | null;
  policiesPath: string | null;
  effectivePolicyId: string | null;
  brainOutsideWorkspace: boolean;
  readOnlyAuditMode: boolean;
  completed: boolean;
  artifactCount: number;
  scratchCount: number;
  missingArtifactKinds: WorkflowSessionBrainArtifactKind[];
  rows: WorkflowSessionBrainArtifactRow[];
  evidenceRefs: string[];
}

const REQUIRED_ARTIFACT_KINDS: WorkflowSessionBrainArtifactKind[] = [
  "implementation_plan",
  "task",
  "walkthrough",
  "scratch",
];

export function buildWorkflowSessionBrainPanel(
  input: WorkflowSessionBrainPanelInput,
): WorkflowSessionBrainPanel {
  const projection = objectValue(input.memoryProjection) ?? {};
  const paths = {
    ...objectField(projection, "paths"),
    ...(objectValue(input.memoryPath) ?? {}),
  };
  const policy = objectField(projection, "policy");
  const records = normalizeArray(projection.records)
    .map(objectValue)
    .filter((record): record is Record<string, unknown> => Boolean(record));
  const events = normalizeArray(input.events);
  const workspace = stringField(projection, "workspace") ?? stringField(paths, "workspace");
  const brainRoot = stringField(paths, "recordsPath");
  const policiesPath = stringField(paths, "policiesPath");
  const effectivePolicyId = stringField(paths, "effectivePolicyId") ?? stringField(policy, "id");
  const rows = artifactRowsForRecords({
    records,
    events,
    brainRoot,
  });
  const presentKinds = new Set(rows.filter((row) => row.status === "present").map((row) => row.artifactKind));
  const missingArtifactKinds = REQUIRED_ARTIFACT_KINDS.filter((kind) => !presentKinds.has(kind));
  rows.push(
    ...missingArtifactKinds.map((kind) => missingArtifactRow(kind, brainRoot)),
  );

  const completed = input.completion?.completed === true;
  const readOnlyAuditMode = completed && booleanField(policy, "readOnly");
  const brainOutsideWorkspace = pathOutsideWorkspace(brainRoot, workspace);
  const status =
    missingArtifactKinds.length > 0
      ? "needs_artifacts"
      : brainOutsideWorkspace && (!completed || readOnlyAuditMode)
        ? "ready"
        : "blocked";

  return {
    schemaVersion: WORKFLOW_SESSION_BRAIN_PANEL_SCHEMA_VERSION,
    status,
    threadId: stringField(projection, "threadId") ?? stringField(paths, "threadId"),
    workspace,
    brainRoot,
    policiesPath,
    effectivePolicyId,
    brainOutsideWorkspace,
    readOnlyAuditMode,
    completed,
    artifactCount: rows.filter((row) => row.status === "present").length,
    scratchCount: rows.filter((row) => row.status === "present" && row.artifactKind === "scratch").length,
    missingArtifactKinds,
    rows,
    evidenceRefs: uniqueStrings([
      "runtime_memory_manager",
      "session_brain_panel",
      effectivePolicyId,
      ...rows.flatMap((row) => row.receiptRefs),
      ...normalizeArray(input.completion?.receiptRefs),
    ]),
  };
}

function artifactRowsForRecords({
  records,
  events,
  brainRoot,
}: {
  records: Record<string, unknown>[];
  events: unknown[];
  brainRoot: string | null;
}): WorkflowSessionBrainArtifactRow[] {
  const rows: Array<WorkflowSessionBrainArtifactRow | null> = records
    .map((record): WorkflowSessionBrainArtifactRow | null => {
      const artifactKind = artifactKindForRecord(record);
      if (!artifactKind) return null;
      const recordId = stringField(record, "id");
      const memoryKey = stringField(record, "memoryKey");
      return {
        id: `session-brain-${artifactKind}-${safeId(memoryKey ?? recordId ?? "record")}`,
        artifactKind,
        status: "present" as const,
        label: labelForArtifactKind(artifactKind),
        artifactPath: artifactPathForKind({ artifactKind, brainRoot, memoryKey, recordId }),
        memoryRecordId: recordId,
        memoryKey,
        preview: previewText(stringField(record, "fact")),
        receiptRefs: receiptRefsForRecord(events, recordId),
        evidenceRefs: uniqueStrings([
          ...normalizeArray(record.evidenceRefs),
          ...normalizeArray(record.evidence_refs),
          recordId,
        ]),
      };
    });
  return rows.filter((row): row is WorkflowSessionBrainArtifactRow => Boolean(row));
}

function missingArtifactRow(
  artifactKind: WorkflowSessionBrainArtifactKind,
  brainRoot: string | null,
): WorkflowSessionBrainArtifactRow {
  return {
    id: `session-brain-${artifactKind}-missing`,
    artifactKind,
    status: "missing",
    label: labelForArtifactKind(artifactKind),
    artifactPath: artifactPathForKind({ artifactKind, brainRoot, memoryKey: null, recordId: null }),
    memoryRecordId: null,
    memoryKey: null,
    preview: null,
    receiptRefs: [],
    evidenceRefs: ["session_brain_required_artifact"],
  };
}

function artifactKindForRecord(
  record: Record<string, unknown>,
): WorkflowSessionBrainArtifactKind | null {
  const key = (stringField(record, "memoryKey") ?? "").toLowerCase();
  if (/^(implementation[_-]?plan|plan)([./:-]|$)/.test(key)) return "implementation_plan";
  if (/^(task|checklist)([./:-]|$)/.test(key)) return "task";
  if (/^(walkthrough|verification[_-]?summary|summary)([./:-]|$)/.test(key)) return "walkthrough";
  if (/^scratch([./:-]|$)/.test(key)) return "scratch";
  return null;
}

function artifactPathForKind({
  artifactKind,
  brainRoot,
  memoryKey,
  recordId,
}: {
  artifactKind: WorkflowSessionBrainArtifactKind;
  brainRoot: string | null;
  memoryKey: string | null;
  recordId: string | null;
}): string | null {
  if (!brainRoot) return null;
  if (artifactKind === "scratch") {
    const scratchName = (memoryKey ?? recordId ?? "scratch").replace(/^scratch[./:-]?/, "") || "scratch";
    return `${trimTrailingSlash(brainRoot)}/scratch/${safePathSegment(scratchName)}.md`;
  }
  return `${trimTrailingSlash(brainRoot)}/${artifactKind}.md`;
}

function receiptRefsForRecord(events: unknown[], recordId: string | null): string[] {
  if (!recordId) return [];
  const refs: unknown[] = [];
  for (const event of events) {
    let eventText = "";
    try {
      eventText = JSON.stringify(event);
    } catch {
      eventText = "";
    }
    if (!eventText.includes(recordId)) continue;
    const eventObject = objectValue(event) ?? {};
    const eventData = objectField(eventObject, "data");
    const payload = objectField(eventData, "payload");
    const receipt = objectField(payload, "receipt");
    refs.push(
      ...normalizeArray(eventObject.receipt_refs),
      ...normalizeArray(eventObject.receiptRefs),
      ...normalizeArray(eventData.receipt_refs),
      ...normalizeArray(eventData.receiptRefs),
      ...normalizeArray(payload.receipt_refs),
      ...normalizeArray(payload.receiptRefs),
      stringField(receipt, "id"),
    );
  }
  return uniqueStrings(refs);
}

function pathOutsideWorkspace(pathValue: string | null, workspace: string | null): boolean {
  if (!pathValue || !workspace) return false;
  const normalizedPath = trimTrailingSlash(pathValue);
  const normalizedWorkspace = trimTrailingSlash(workspace);
  return normalizedPath !== normalizedWorkspace && !normalizedPath.startsWith(`${normalizedWorkspace}/`);
}

function labelForArtifactKind(kind: WorkflowSessionBrainArtifactKind): string {
  switch (kind) {
    case "implementation_plan":
      return "Implementation plan";
    case "task":
      return "Task checklist";
    case "walkthrough":
      return "Walkthrough";
    case "scratch":
      return "Scratch";
  }
}

function previewText(value: string | null): string | null {
  if (!value) return null;
  const compact = value.replace(/\s+/g, " ").trim();
  return compact.length > 180 ? `${compact.slice(0, 177)}...` : compact;
}

function objectValue(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function objectField(record: unknown, key: string): Record<string, unknown> {
  const object = objectValue(record);
  return objectValue(object?.[key]) ?? {};
}

function stringField(record: unknown, key: string): string | null {
  const object = objectValue(record);
  const value = object?.[key];
  if (typeof value === "string" && value.trim()) return value.trim();
  if (typeof value === "number" && Number.isFinite(value)) return String(value);
  return null;
}

function booleanField(record: unknown, key: string): boolean {
  const object = objectValue(record);
  return object?.[key] === true;
}

function normalizeArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
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

function safePathSegment(value: string): string {
  return safeId(value).replace(/[.:]+/g, "-");
}

function trimTrailingSlash(value: string): string {
  return value.replace(/\/+$/, "");
}
