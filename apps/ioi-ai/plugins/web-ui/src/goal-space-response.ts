import { activationId, canonicalTail, goalRunId, outcomeRoomId, type JsonRecord } from "./goal-space-contract.ts";

export class GoalSpaceResponseContractError extends Error {
  constructor(path: string) {
    super(`The daemon response violates the required Goal Space contract at ${path}.`);
    this.name = "GoalSpaceResponseContractError";
  }
}

function fail(path: string): never {
  throw new GoalSpaceResponseContractError(path);
}

function record(value: unknown, path: string): JsonRecord {
  if (value === null || typeof value !== "object" || Array.isArray(value)) fail(path);
  return value as JsonRecord;
}

function array(value: unknown, path: string): unknown[] {
  if (!Array.isArray(value)) fail(path);
  return value;
}

function exact(value: unknown, expected: unknown, path: string): void {
  if (value !== expected) fail(path);
}

function boundedString(value: unknown, path: string): string {
  if (typeof value !== "string" || value.length === 0 || value.length > 2048 || /[\s\u0000-\u001f\u007f]/.test(value))
    fail(path);
  return value;
}

function canonicalRef(value: unknown, scheme: "receipt" | "work-result" | "agentgres", path: string): string {
  const candidate = boundedString(value, path);
  const prefix = `${scheme}://`;
  if (!candidate.startsWith(prefix)) fail(path);
  const tail = candidate.slice(prefix.length);
  if (!/^[A-Za-z0-9][A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]*$/.test(tail)) fail(path);
  return candidate;
}

function stringArray(value: unknown, path: string): string[] {
  return array(value, path).map((entry, index) => boundedString(entry, `${path}[${index}]`));
}

function recordArray(value: unknown, path: string): JsonRecord[] {
  return array(value, path).map((entry, index) => record(entry, `${path}[${index}]`));
}

function refArray(value: unknown, scheme: "receipt" | "work-result", path: string): string[] {
  return array(value, path).map((entry, index) => canonicalRef(entry, scheme, `${path}[${index}]`));
}

function roomRef(value: unknown, expectedId: string, path: string): void {
  if (canonicalTail(value, "outcome-room", "or_") !== expectedId) fail(path);
}

export function validateGoalRun(value: unknown, path = "goal_run"): JsonRecord {
  const run = record(value, path);
  exact(run.schema_version, "ioi.goal-run.v1", `${path}.schema_version`);
  if (!goalRunId(run)) fail(`${path}.goal_run_id`);
  refArray(run.receipt_refs, "receipt", `${path}.receipt_refs`);
  refArray(run.work_result_refs, "work-result", `${path}.work_result_refs`);
  return run;
}

export function validateGoalRunList(value: unknown): JsonRecord[] {
  const envelope = record(value, "response");
  exact(envelope.ok, true, "response.ok");
  return array(envelope.goal_runs, "response.goal_runs").map((entry, index) =>
    validateGoalRun(entry, `response.goal_runs[${index}]`),
  );
}

export function validateGoalRunCreate(value: unknown): JsonRecord {
  const envelope = record(value, "response");
  exact(envelope.ok, true, "response.ok");
  const run = validateGoalRun(envelope.goal_run, "response.goal_run");
  exact(run.status, "draft", "response.goal_run.status");
  return run;
}

export function validateGoalRunStart(value: unknown, expectedId: string): { run: JsonRecord; response: JsonRecord } {
  const response = record(value, "response");
  exact(response.ok, true, "response.ok");
  const run = validateGoalRun(response.goal_run, "response.goal_run");
  if (goalRunId(run) !== expectedId) fail("response.goal_run.goal_run_id");
  recordArray(response.invocations, "response.invocations");
  recordArray(response.blockers, "response.blockers");
  if (typeof response.partial_result !== "boolean") fail("response.partial_result");
  if (run.status !== "active") fail("response.goal_run.status");
  return { run, response };
}

export function validateGoalRunReconcile(
  value: unknown,
  expectedId: string,
): { run: JsonRecord; response: JsonRecord } {
  const response = record(value, "response");
  exact(response.ok, true, "response.ok");
  const run = validateGoalRun(response.goal_run, "response.goal_run");
  if (goalRunId(run) !== expectedId) fail("response.goal_run.goal_run_id");
  record(response.reconciliation, "response.reconciliation");
  if (run.status !== "complete" && run.status !== "blocked") fail("response.goal_run.status");
  return { run, response };
}

export function validateOutcomeRoomList(value: unknown): JsonRecord[] {
  const envelope = record(value, "response");
  exact(envelope.schema_version, "ioi.applications.ioi-ai.outcome-room.v2", "response.schema_version");
  return array(envelope.outcome_rooms, "response.outcome_rooms").map((entry, index) => {
    const room = record(entry, `response.outcome_rooms[${index}]`);
    if (!outcomeRoomId(room)) fail(`response.outcome_rooms[${index}].outcome_room_id`);
    return room;
  });
}

export function validateGoalDetail(value: unknown, expectedId: string): JsonRecord {
  const envelope = record(value, "response");
  exact(envelope.ok, true, "response.ok");
  const run = validateGoalRun(envelope.goal_run);
  if (goalRunId(run) !== expectedId) fail("response.goal_run.goal_run_id");
  return run;
}

export function validateGoalEvents(value: unknown, expectedId: string): JsonRecord {
  const envelope = record(value, "response");
  exact(envelope.ok, true, "response.ok");
  if (canonicalTail(envelope.goal_ref, "goal", "gr_") !== expectedId) fail("response.goal_ref");
  recordArray(envelope.events, "response.events");
  recordArray(envelope.invocations, "response.invocations");
  recordArray(envelope.verifications, "response.verifications");
  return envelope;
}

export function validateOutcomeRoomDetail(value: unknown, expectedId: string): JsonRecord {
  const envelope = record(value, "response");
  const room = record(envelope.outcome_room, "response.outcome_room");
  exact(room.schema_version, "ioi.applications.ioi-ai.outcome-room.v2", "response.outcome_room.schema_version");
  if (outcomeRoomId(room) !== expectedId) fail("response.outcome_room.outcome_room_id");
  return room;
}

function validateAgentgresAdmission(value: unknown, path: string): JsonRecord {
  const admission = record(value, path);
  canonicalRef(admission.receipt_ref, "receipt", `${path}.receipt_ref`);
  canonicalRef(admission.operation_ref, "agentgres", `${path}.operation_ref`);
  return admission;
}

export function validateOutcomeRoomCreate(value: unknown): JsonRecord {
  const response = record(value, "response");
  const room = record(response.outcome_room, "response.outcome_room");
  exact(room.schema_version, "ioi.applications.ioi-ai.outcome-room.v2", "response.outcome_room.schema_version");
  if (!outcomeRoomId(room)) fail("response.outcome_room.outcome_room_id");
  exact(room.status, "open", "response.outcome_room.status");
  if (response.replayed === true) return room;
  exact(response.replayed, false, "response.replayed");
  validateAgentgresAdmission(response.agentgres_admission, "response.agentgres_admission");
  return room;
}

export function validateOutcomeRoomMembership(
  value: unknown,
  expectedRoomId: string,
  expectedGoalRunId: string,
  action: "attach" | "detach",
): { room: JsonRecord; run: JsonRecord; response: JsonRecord } {
  const response = record(value, "response");
  exact(response.membership_transition, action, "response.membership_transition");
  const room = record(response.outcome_room, "response.outcome_room");
  exact(room.schema_version, "ioi.applications.ioi-ai.outcome-room.v2", "response.outcome_room.schema_version");
  if (outcomeRoomId(room) !== expectedRoomId) fail("response.outcome_room.outcome_room_id");
  exact(room.status, "open", "response.outcome_room.status");
  const run = validateGoalRun(response.goal_run, "response.goal_run");
  if (goalRunId(run) !== expectedGoalRunId) fail("response.goal_run.goal_run_id");
  const expectedRoomRef = `outcome-room://${expectedRoomId}`;
  const expectedGoalRef = `goal://${expectedGoalRunId}`;
  const members = stringArray(room.member_goal_run_refs, "response.outcome_room.member_goal_run_refs");
  if (action === "attach" && run.outcome_room_ref !== expectedRoomRef) fail("response.goal_run.outcome_room_ref");
  if (action === "detach" && run.outcome_room_ref !== null) fail("response.goal_run.outcome_room_ref");
  if (action === "attach" && !members.includes(expectedGoalRef)) fail("response.outcome_room.member_goal_run_refs");
  if (action === "detach" && members.includes(expectedGoalRef)) fail("response.outcome_room.member_goal_run_refs");
  validateAgentgresAdmission(response.agentgres_admission, "response.agentgres_admission");
  return { room, run, response };
}

export function validateCollaborativeWorkGraph(value: unknown, expectedId: string): JsonRecord {
  const envelope = record(value, "response");
  const graph = record(envelope.collaborative_work_graph, "response.collaborative_work_graph");
  exact(
    graph.schema_version,
    "ioi.applications.ioi-ai.collaborative-work-graph.v1",
    "response.collaborative_work_graph.schema_version",
  );
  roomRef(graph.outcome_room_ref, expectedId, "response.collaborative_work_graph.outcome_room_ref");
  for (const key of [
    "member_goal_run_refs",
    "participant_refs",
    "frontier_item_refs",
    "work_claim_refs",
    "attempt_refs",
    "finding_refs",
    "verifier_challenge_refs",
    "outcome_delta_refs",
    "information_flow_label_refs",
  ])
    stringArray(graph[key], `response.collaborative_work_graph.${key}`);
  refArray(graph.work_result_refs, "work-result", "response.collaborative_work_graph.work_result_refs");
  refArray(
    graph.source_admission_receipt_refs,
    "receipt",
    "response.collaborative_work_graph.source_admission_receipt_refs",
  );
  return graph;
}

export function validateDiscussionProjection(value: unknown, expectedId: string): JsonRecord {
  const envelope = record(value, "response");
  const projection = record(envelope.discussion_projection, "response.discussion_projection");
  exact(
    projection.schema_version,
    "ioi.applications.ioi-ai.outcome-room-discussion-projection.v1",
    "response.discussion_projection.schema_version",
  );
  roomRef(projection.outcome_room_ref, expectedId, "response.discussion_projection.outcome_room_ref");
  for (const key of ["information_flow_label_refs", "permitted_subject_refs", "message_refs", "redaction_summary_refs"])
    stringArray(projection[key], `response.discussion_projection.${key}`);
  refArray(
    projection.source_admission_receipt_refs,
    "receipt",
    "response.discussion_projection.source_admission_receipt_refs",
  );
  return projection;
}

export function validateProductProjection(value: unknown, expectedId: string): JsonRecord {
  const projection = record(value, "response");
  exact(projection.schema_version, "ioi.hypervisor.outcome-room-product-projection.v1", "response.schema_version");
  const room = record(projection.outcome_room, "response.outcome_room");
  roomRef(room.outcome_room_ref, expectedId, "response.outcome_room.outcome_room_ref");
  recordArray(projection.member_goal_runs, "response.member_goal_runs");
  refArray(projection.work_result_refs, "work-result", "response.work_result_refs");
  stringArray(projection.outcome_delta_refs, "response.outcome_delta_refs");
  recordArray(projection.work_results, "response.work_results");
  recordArray(projection.outcome_deltas, "response.outcome_deltas");
  refArray(projection.source_admission_receipt_refs, "receipt", "response.source_admission_receipt_refs");
  return projection;
}

export function validateRoomReplay(value: unknown, expectedId: string): JsonRecord {
  const replay = record(value, "response");
  exact(replay.schema_version, "ioi.outcome-room-replay-projection.v2", "response.schema_version");
  roomRef(replay.outcome_room_ref, expectedId, "response.outcome_room_ref");
  recordArray(replay.operations, "response.operations");
  return replay;
}

export interface ValidatedActivationResponse {
  response: JsonRecord;
  goalRun: JsonRecord | null;
}

function validateActivationCore(
  value: unknown,
  expectedId?: string,
  expectedHash?: string,
): ValidatedActivationResponse {
  const response = record(value, "response");
  exact(response.ok, true, "response.ok");
  const activation = record(response.activation, "response.activation");
  const id = activationId(activation);
  if (!id || (expectedId !== undefined && id !== expectedId)) fail("response.activation.activation_id");
  if (!/^sha256:[0-9a-f]{64}$/.test(String(response.activation_hash ?? ""))) fail("response.activation_hash");
  if (expectedHash !== undefined && response.activation_hash !== expectedHash) fail("response.activation_hash");
  record(response.goal_draft, "response.goal_draft");
  record(response.authority_decision, "response.authority_decision");
  record(response.resolved_profile, "response.resolved_profile");
  const goalRun =
    response.goal_run === undefined || response.goal_run === null ? null : validateGoalRun(response.goal_run);
  if (activation.status === "admitted" && !goalRun) fail("response.goal_run");
  return { response, goalRun };
}

function validateAdmittedReceipts(response: JsonRecord): void {
  const receipts = record(response.receipts, "response.receipts");
  const activationReceipt = record(receipts.activation, "response.receipts.activation");
  canonicalRef(activationReceipt.receipt_ref, "receipt", "response.receipts.activation.receipt_ref");
}

export function validateActivationResponse(value: unknown, expectedId?: string): ValidatedActivationResponse {
  const validated = validateActivationCore(value, expectedId);
  if (validated.goalRun) {
    if ((validated.goalRun.receipt_refs as unknown[]).length === 0) fail("response.goal_run.receipt_refs");
    validateAdmittedReceipts(validated.response);
  }
  return validated;
}

export function validateAdmittedActivationResponse(
  value: unknown,
  expectedId?: string,
  expectedHash?: string,
): ValidatedActivationResponse {
  const validated = validateActivationCore(value, expectedId, expectedHash);
  if (!validated.goalRun) fail("response.goal_run");
  if ((validated.goalRun.receipt_refs as unknown[]).length === 0) fail("response.goal_run.receipt_refs");
  validateAdmittedReceipts(validated.response);
  return validated;
}

export function isCanonicalReceiptRef(value: unknown): boolean {
  try {
    canonicalRef(value, "receipt", "receipt_ref");
    return true;
  } catch {
    return false;
  }
}

export function isCanonicalWorkResultRef(value: unknown): boolean {
  try {
    canonicalRef(value, "work-result", "work_result_ref");
    return true;
  } catch {
    return false;
  }
}
