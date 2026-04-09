import assert from "node:assert/strict";
import { buildServerOverview } from "./artifactHubServerModel.ts";

{
  const overview = buildServerOverview(null);
  assert.equal(overview.tone, "setup");
  assert.equal(overview.statusLabel, "Server posture loading");
}

{
  const overview = buildServerOverview({
    generatedAtMs: 42,
    sessionId: "session-1",
    workspaceRoot: "/tmp/repo",
    rpcUrl: "https://kernel.example.com",
    rpcSourceLabel: "AUTOPILOT_KERNEL_RPC_URL",
    continuityModeLabel: "Explicit remote kernel",
    continuityStatusLabel: "Remote history merged",
    continuityDetail: "Remote-only retained sessions are flowing into the shared projection.",
    kernelConnectionLabel: "Reachable",
    kernelConnectionDetail: "reachable",
    explicitRpcTarget: true,
    remoteKernelTarget: true,
    kernelReachable: true,
    remoteHistoryAvailable: true,
    localSessionCount: 3,
    remoteSessionCount: 2,
    mergedSessionCount: 4,
    remoteOnlySessionCount: 1,
    overlappingSessionCount: 1,
    remoteAttachableSessionCount: 1,
    remoteHistoryOnlySessionCount: 1,
    currentSessionVisibleRemotely: true,
    currentSessionContinuityState: "mirrored_attachable",
    currentSessionContinuityLabel: "Current session mirrored remotely",
    currentSessionContinuityDetail:
      "The active session is visible in remote retained history and still carries a workspace root.",
    notes: [],
    recentRemoteSessions: [],
  });

  assert.equal(overview.tone, "ready");
  assert.equal(overview.statusLabel, "Remote history merged");
  assert.deepEqual(overview.historyMeta, [
    "3 local",
    "2 remote",
    "4 merged",
    "1 remote attachable",
    "1 remote history-only",
  ]);
  assert.equal(overview.currentSessionLabel, "Current session mirrored remotely");
}

{
  const overview = buildServerOverview({
    generatedAtMs: 42,
    sessionId: null,
    workspaceRoot: null,
    rpcUrl: "https://kernel.example.com",
    rpcSourceLabel: "AUTOPILOT_KERNEL_RPC_URL",
    continuityModeLabel: "Explicit remote kernel",
    continuityStatusLabel: "Configured but unreachable",
    continuityDetail: "The configured target timed out.",
    kernelConnectionLabel: "Unavailable",
    kernelConnectionDetail: "timed out",
    explicitRpcTarget: true,
    remoteKernelTarget: true,
    kernelReachable: false,
    remoteHistoryAvailable: false,
    localSessionCount: 2,
    remoteSessionCount: 0,
    mergedSessionCount: 2,
    remoteOnlySessionCount: 0,
    overlappingSessionCount: 0,
    remoteAttachableSessionCount: 0,
    remoteHistoryOnlySessionCount: 0,
    currentSessionVisibleRemotely: false,
    currentSessionContinuityState: "local_only",
    currentSessionContinuityLabel: "Current session local only",
    currentSessionContinuityDetail:
      "The active session is not visible in remote retained history yet.",
    notes: [],
    recentRemoteSessions: [],
  });

  assert.equal(overview.tone, "attention");
  assert.equal(overview.statusLabel, "Configured but unreachable");
}
