import { normalizeArray, objectRecord, optionalString, safeId } from "./runtime-value-helpers.mjs";

export const SESSION_LIVE_PROJECTION_SCHEMA_VERSION =
  "ioi.hypervisor.session_live_projection.v1";

// Turn a harness's real stdout transcript into terminal_events. Each non-empty
// line is an executed command/output summary backed by a receipt ref. This is
// the PTY-reader signal: the transcript is the harness's real output, not canned.
export function terminalEventsFromTranscript(transcriptLines, sessionRef) {
  const ref = optionalString(sessionRef) ?? "session";
  return normalizeArray(transcriptLines)
    .map((line) => optionalString(line))
    .filter(Boolean)
    .map((line, index) => ({
      event_ref: `terminal-event:${safeId(ref)}/${index}`,
      command_summary: line.slice(0, 400),
      status: line.includes("no model route") ? "blocked" : "executed",
      receipt_ref: `receipt://terminal/${safeId(ref)}/${index}`,
    }));
}

/**
 * Assemble a live session-operations projection slice from real signals:
 * - environment_status: the daemon-projected component sub-phases
 * - terminal_events: from the lane's real stdout transcript
 * - changed_file_groups: from the real workspace diff projection
 * - environment_ports: wallet-gated ports from the registry
 * No fixtures: every field is fed by a real signal once its phase lands.
 */
export function assembleSessionOperationsLiveProjection(input = {}) {
  const sessionRef = optionalString(input.sessionRef) ?? "session";
  const laneResult = objectRecord(input.laneResult) ?? {};
  const diffProjection = objectRecord(input.diffProjection) ?? {};
  const environmentStatus = objectRecord(input.environmentStatus) ?? null;
  const ports = normalizeArray(input.ports);

  const terminalEvents = terminalEventsFromTranscript(
    laneResult.transcript_lines,
    sessionRef,
  );
  const changedFileGroups = normalizeArray(diffProjection.changed_file_groups);
  const receiptRefs = [
    ...normalizeArray(laneResult.receipt_refs),
    ...normalizeArray(input.receiptRefs),
  ].map(String);

  return {
    schema_version: SESSION_LIVE_PROJECTION_SCHEMA_VERSION,
    session_ref: sessionRef,
    environment_status: environmentStatus,
    terminal_events: terminalEvents,
    changed_file_groups: changedFileGroups,
    environment_ports: ports,
    files_written: normalizeArray(laneResult.files_written).map(String),
    latest_receipt_refs: receiptRefs,
    runtimeTruthSource: "daemon-runtime",
  };
}

/**
 * Project a live session-operations slice into the canonical session-events SSE
 * envelope: environment_status | workspace_change | terminal_chunk |
 * receipt_projection | readiness. The app subscribes to this stream and folds
 * each event into its projection.
 */
export function sessionOperationsEvents(liveProjection) {
  const projection = objectRecord(liveProjection) ?? {};
  const events = [];
  if (projection.environment_status) {
    events.push({
      event: "environment_status",
      data: projection.environment_status,
    });
  }
  if (normalizeArray(projection.changed_file_groups).length > 0) {
    events.push({
      event: "workspace_change",
      data: {
        changed_file_groups: projection.changed_file_groups,
        files_written: projection.files_written ?? [],
      },
    });
  }
  for (const event of normalizeArray(projection.terminal_events)) {
    events.push({ event: "terminal_chunk", data: event });
  }
  if (normalizeArray(projection.latest_receipt_refs).length > 0) {
    events.push({
      event: "receipt_projection",
      data: { latest_receipt_refs: projection.latest_receipt_refs },
    });
  }
  const aggregate = objectRecord(projection.environment_status)?.phase ?? null;
  events.push({
    event: "readiness",
    data: {
      session_ref: projection.session_ref ?? null,
      environment_phase: aggregate,
      ready: aggregate === "running",
    },
  });
  return events;
}
