import assert from "node:assert/strict";
import type { CanonicalTraceBundle } from "../../../types";
import { buildReplayTimelineRows } from "./ArtifactHubReplayModel";

function baseBundle(): CanonicalTraceBundle {
  return {
    schemaVersion: 1,
    exportedAtUtc: "2026-04-04T12:00:00.000Z",
    threadId: "thread-1",
    sessionId: "thread-1",
    latestAnswerMarkdown: "",
    stats: {
      eventCount: 1,
      receiptCount: 1,
      artifactCount: 1,
      runBundleCount: 0,
      reportArtifactCount: 1,
      interventionCount: 1,
      assistantNotificationCount: 1,
      assistantWorkbenchActivityCount: 1,
      includedArtifactPayloads: false,
      includedArtifactPayloadCount: 0,
    },
    sessionSummary: {
      session_id: "thread-1",
      title: "Replay proof",
      timestamp: Date.parse("2026-04-04T12:00:00.000Z"),
    },
    task: null,
    history: [
      {
        role: "user",
        text: "Please summarize the run.",
        timestamp: Date.parse("2026-04-04T12:00:01.000Z"),
      },
    ],
    events: [
      {
        event_id: "event-1",
        timestamp: "2026-04-04T12:00:03.000Z",
        thread_id: "thread-1",
        step_index: 2,
        event_type: "RECEIPT",
        title: "Routing receipt",
        digest: {
          tool_name: "agent__delegate",
          policy_decision: "approved",
          incident_stage: "review",
          resolution_action: "continue",
        },
        details: {
          output: "Delegation approved and child session attached.",
        },
        artifact_refs: [
          {
            artifact_id: "report-1",
            artifact_type: "REPORT",
          },
        ],
        receipt_ref: null,
        input_refs: [],
        status: "SUCCESS",
        duration_ms: 1200,
      },
    ],
    receipts: [],
    artifacts: [
      {
        artifact_id: "artifact-1",
        created_at: "2026-04-04T12:00:05.000Z",
        thread_id: "thread-1",
        artifact_type: "REPORT",
        title: "Trace report",
        description: "Replay evidence bundle",
        content_ref: "ioi-memory://artifact/artifact-1",
        metadata: {},
        version: 1,
        parent_artifact_id: null,
      },
    ],
    artifactPayloads: [],
    interventions: [
      {
        itemId: "gate-1",
        rail: "control",
        interventionType: "approval_gate",
        status: "pending",
        severity: "medium",
        blocking: true,
        title: "Approve delegation",
        summary: "A governed delegation requires approval.",
        reason: null,
        recommendedAction: "Approve the child task",
        consequenceIfIgnored: null,
        createdAtMs: Date.parse("2026-04-04T12:00:02.000Z"),
        updatedAtMs: Date.parse("2026-04-04T12:00:02.000Z"),
        dueAtMs: null,
        expiresAtMs: null,
        snoozedUntilMs: null,
        dedupeKey: "gate-1",
        threadId: "thread-1",
        sessionId: "thread-1",
        workflowId: null,
        runId: null,
        deliveryState: {
          toastSent: false,
          inboxVisible: true,
          badgeCounted: true,
          pillVisible: false,
          lastToastAtMs: null,
        },
        privacy: {
          previewMode: "full",
          containsSensitiveData: false,
          observationTier: "workflow_state",
        },
        source: {
          serviceName: "kernel",
          workflowName: "delegation",
          stepName: "gate",
        },
        artifactRefs: [
          {
            artifact_id: "report-1",
            artifact_type: "REPORT",
          },
        ],
        sourceEventIds: ["event-1"],
        policyRefs: {
          policyHash: "policy-1",
          requestHash: "request-1",
        },
        actions: [],
        target: null,
        requestHash: "request-1",
        policyHash: "policy-1",
        approvalScope: "session",
        sensitiveActionType: "agent__delegate",
        errorClass: null,
        blockedStage: "review",
        retryAvailable: true,
        recoveryHint: null,
      },
    ],
    assistantNotifications: [
      {
        itemId: "assistant-1",
        rail: "control",
        notificationClass: "valuable_completion",
        status: "new",
        severity: "low",
        title: "Worker result ready",
        summary: "The delegated worker produced a reviewable result.",
        reason: null,
        recommendedAction: "Review worker output",
        consequenceIfIgnored: null,
        createdAtMs: Date.parse("2026-04-04T12:00:04.000Z"),
        updatedAtMs: Date.parse("2026-04-04T12:00:04.000Z"),
        dueAtMs: null,
        expiresAtMs: null,
        snoozedUntilMs: null,
        dedupeKey: "assistant-1",
        threadId: "thread-1",
        sessionId: "thread-1",
        workflowId: null,
        runId: null,
        deliveryState: {
          toastSent: false,
          inboxVisible: true,
          badgeCounted: true,
          pillVisible: true,
          lastToastAtMs: null,
        },
        privacy: {
          previewMode: "full",
          containsSensitiveData: false,
          observationTier: "workflow_state",
        },
        source: {
          serviceName: "kernel",
          workflowName: "delegation",
          stepName: "worker-review",
        },
        artifactRefs: [],
        sourceEventIds: ["event-1"],
        policyRefs: {
          policyHash: null,
          requestHash: null,
        },
        actions: [],
        target: null,
        priorityScore: 0.8,
        confidenceScore: 0.9,
        rankingReason: ["recent result"],
      },
    ],
    assistantWorkbenchActivities: [
      {
        activityId: "activity-1",
        sessionKind: "gmail_reply",
        surface: "gate",
        action: "save_draft",
        status: "succeeded",
        message: "Reply workbench draft saved.",
        timestampMs: Date.parse("2026-04-04T12:00:06.000Z"),
      },
    ],
  };
}

function replayRowsUseCanonicalTraceBundleSources(): void {
  const rows = buildReplayTimelineRows(baseBundle());

  assert.deepEqual(
    rows.map((row) => [row.kind, row.kindLabel, row.title]),
    [
      ["action", "Prompt", "User prompt"],
      ["policy", "Intervention", "Approve delegation"],
      ["policy", "Policy", "Approved · agent__delegate"],
      ["action", "Assistant", "Worker result ready"],
      ["artifact", "Artifact", "Trace report"],
      ["receipt", "Workbench receipt", "Gmail Reply · Save Draft"],
    ],
  );

  assert.equal(rows[1]?.artifactLabel, "Open report");
  assert.ok(rows[2]?.meta.includes("Stage Review"));
  assert.ok(rows[3]?.meta.some((value) => value.startsWith("Suggested ")));
}

replayRowsUseCanonicalTraceBundleSources();
