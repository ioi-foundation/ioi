import assert from "node:assert/strict";
import { buildRemoteContinuityGovernanceOverview } from "./artifactHubRemoteContinuityGovernanceModel.ts";

{
  const overview = buildRemoteContinuityGovernanceOverview(null);
  assert.equal(overview.tone, "setup");
  assert.equal(overview.primaryAction, null);
}

{
  const overview = buildRemoteContinuityGovernanceOverview({
    generatedAtMs: 42,
    sessionId: "session-1",
    workspaceRoot: "/tmp/repo",
    rpcUrl: "https://kernel.example.com",
    rpcSourceLabel: "AUTOPILOT_KERNEL_RPC_URL",
    continuityModeLabel: "Explicit remote kernel",
    continuityStatusLabel: "Remote history merged",
    continuityDetail: "Remote continuity is available.",
    kernelConnectionLabel: "Reachable",
    kernelConnectionDetail: "reachable",
    explicitRpcTarget: true,
    remoteKernelTarget: true,
    kernelReachable: true,
    remoteHistoryAvailable: true,
    localSessionCount: 2,
    remoteSessionCount: 3,
    mergedSessionCount: 2,
    remoteOnlySessionCount: 1,
    overlappingSessionCount: 1,
    remoteAttachableSessionCount: 2,
    remoteHistoryOnlySessionCount: 1,
    currentSessionVisibleRemotely: true,
    currentSessionContinuityState: "mirrored_attachable",
    currentSessionContinuityLabel: "Current session mirrored remotely",
    currentSessionContinuityDetail: "mirrored",
    notes: [],
    recentRemoteSessions: [
      {
        sessionId: "history-1",
        title: "History only",
        timestamp: Date.parse("2026-04-05T23:45:00.000Z"),
        sourceLabel: "remote kernel",
        presenceState: "remote_only_history_only",
        presenceLabel: "History only",
        resumeHint: "Review only",
        workspaceRoot: null,
      },
      {
        sessionId: "attach-2",
        title: "Attach newer",
        timestamp: Date.parse("2026-04-05T23:50:00.000Z"),
        sourceLabel: "remote kernel",
        presenceState: "remote_only_attachable",
        presenceLabel: "Attachable",
        resumeHint: "Resume newer",
        workspaceRoot: "/srv/repo-b",
      },
      {
        sessionId: "attach-1",
        title: "Attach older",
        timestamp: Date.parse("2026-04-05T23:40:00.000Z"),
        sourceLabel: "remote kernel",
        presenceState: "merged_attachable",
        presenceLabel: "Merged attachable",
        resumeHint: "Resume older",
        workspaceRoot: "/srv/repo-a",
      },
    ],
  });

  assert.equal(overview.tone, "ready");
  assert.equal(overview.primaryAction?.launchRequest.mode, "attach");
  assert.deepEqual(overview.primaryAction?.launchRequest.queueSessionIds, [
    "attach-2",
    "attach-1",
  ]);
  assert.equal(
    overview.secondaryAction?.launchRequest.queueSessionIds?.[0],
    "history-1",
  );
}

{
  const overview = buildRemoteContinuityGovernanceOverview({
    generatedAtMs: 42,
    sessionId: null,
    workspaceRoot: null,
    rpcUrl: "https://kernel.example.com",
    rpcSourceLabel: "AUTOPILOT_KERNEL_RPC_URL",
    continuityModeLabel: "Explicit remote kernel",
    continuityStatusLabel: "Remote history only",
    continuityDetail: "Only review continuity is available.",
    kernelConnectionLabel: "Reachable",
    kernelConnectionDetail: "reachable",
    explicitRpcTarget: true,
    remoteKernelTarget: true,
    kernelReachable: true,
    remoteHistoryAvailable: true,
    localSessionCount: 1,
    remoteSessionCount: 2,
    mergedSessionCount: 1,
    remoteOnlySessionCount: 1,
    overlappingSessionCount: 0,
    remoteAttachableSessionCount: 0,
    remoteHistoryOnlySessionCount: 2,
    currentSessionVisibleRemotely: false,
    currentSessionContinuityState: "local_only",
    currentSessionContinuityLabel: "Current session local only",
    currentSessionContinuityDetail: "local only",
    notes: [],
    recentRemoteSessions: [
      {
        sessionId: "history-2",
        title: "Review newer",
        timestamp: Date.parse("2026-04-05T23:55:00.000Z"),
        sourceLabel: "remote kernel",
        presenceState: "merged_history_only",
        presenceLabel: "Merged history only",
        resumeHint: "Review newer",
        workspaceRoot: null,
      },
      {
        sessionId: "history-1",
        title: "Review older",
        timestamp: Date.parse("2026-04-05T23:45:00.000Z"),
        sourceLabel: "remote kernel",
        presenceState: "remote_only_history_only",
        presenceLabel: "Remote-only history",
        resumeHint: "Review older",
        workspaceRoot: null,
      },
    ],
  });

  assert.equal(overview.tone, "review");
  assert.equal(overview.primaryAction?.launchRequest.mode, "review");
  assert.deepEqual(overview.primaryAction?.launchRequest.queueSessionIds, [
    "history-2",
    "history-1",
  ]);
  assert.equal(overview.secondaryAction, null);
}
