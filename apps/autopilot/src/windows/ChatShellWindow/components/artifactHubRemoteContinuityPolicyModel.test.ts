import assert from "node:assert/strict";
import {
  buildMobileRemoteContinuityPolicyOverview,
  buildServerRemoteContinuityPolicyOverview,
} from "./artifactHubRemoteContinuityPolicyModel.ts";

const attachableServerSnapshot = {
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
};

{
  const overview = buildServerRemoteContinuityPolicyOverview({
    serverSnapshot: attachableServerSnapshot,
    remoteEnvSnapshot: {
      generatedAtMs: 10,
      sessionId: "session-1",
      workspaceRoot: "/tmp/repo",
      focusedScopeLabel: "Remote runtime",
      governingSourceLabel: "Runtime",
      postureLabel: "Read-only environment projection",
      postureDetail: "Inspect remote bindings.",
      bindingCount: 5,
      controlPlaneBindingCount: 2,
      processBindingCount: 3,
      overlappingBindingCount: 0,
      secretBindingCount: 2,
      redactedBindingCount: 1,
      notes: [],
      bindings: [],
    },
    managedSettings: {
      syncStatus: "synced",
      summary: "Signed settings verified.",
      activeChannelId: "managed.settings.primary",
      activeChannelLabel: "Primary",
      activeSourceUri: "fixture://managed-settings/primary",
      lastRefreshedAtMs: 1,
      lastSuccessfulRefreshAtMs: 1,
      lastFailedRefreshAtMs: null,
      refreshError: null,
      localOverrideCount: 0,
      localOverrideFields: [],
      channels: [],
    },
    mobileOverview: {
      status: "retained",
      statusLabel: "Retained handoff evidence",
      statusDetail: "retained",
      activityCount: 1,
      evidenceReady: true,
      evidenceLabel: "1 event",
      sessionHistoryCount: 1,
    },
    mobileAction: {
      available: true,
      attachable: true,
      chatShellLabel: "Attach in Chat REPL",
      studioLabel: "Open in Chat",
      detail: "Mobile continuity is attachable.",
      launchRequest: {
        sessionId: "mobile-1",
        source: "mobile",
        mode: "attach",
        notice: "mobile",
      },
    },
  });

  assert.equal(overview.tone, "review");
  assert.equal(overview.primaryAction?.kind, "open_view");
  assert.equal(overview.secondaryAction?.kind, "launch_repl");
  if (!overview.primaryAction || overview.primaryAction.kind !== "open_view") {
    throw new Error("expected a remote-env review action");
  }
  if (!overview.secondaryAction || overview.secondaryAction.kind !== "launch_repl") {
    throw new Error("expected a server continuity launch action");
  }
  assert.equal(overview.primaryAction.view, "remote_env");
  assert.equal(overview.secondaryAction.launchRequest.sessionId, "attach-2");
  assert.deepEqual(
    overview.queuedActions.map((action) => action.kind),
    ["open_view", "launch_repl", "launch_repl", "launch_repl"],
  );
}

{
  const overview = buildServerRemoteContinuityPolicyOverview({
    serverSnapshot: attachableServerSnapshot,
    remoteEnvSnapshot: {
      generatedAtMs: 10,
      sessionId: "session-1",
      workspaceRoot: "/tmp/repo",
      focusedScopeLabel: "Remote runtime",
      governingSourceLabel: "Runtime",
      postureLabel: "Source drift requires review",
      postureDetail: "Inspect remote env drift.",
      bindingCount: 4,
      controlPlaneBindingCount: 2,
      processBindingCount: 2,
      overlappingBindingCount: 1,
      secretBindingCount: 0,
      redactedBindingCount: 0,
      notes: [],
      bindings: [],
    },
    managedSettings: {
      syncStatus: "synced",
      summary: "Signed settings verified.",
      activeChannelId: "managed.settings.primary",
      activeChannelLabel: "Primary",
      activeSourceUri: "fixture://managed-settings/primary",
      lastRefreshedAtMs: 1,
      lastSuccessfulRefreshAtMs: 1,
      lastFailedRefreshAtMs: null,
      refreshError: null,
      localOverrideCount: 0,
      localOverrideFields: [],
      channels: [],
    },
    mobileOverview: null,
    mobileAction: null,
  });

  assert.equal(overview.tone, "review");
  assert.equal(overview.primaryAction?.kind, "open_view");
  if (!overview.primaryAction || overview.primaryAction.kind !== "open_view") {
    throw new Error("expected a remote-env review action");
  }
  assert.equal(overview.primaryAction.view, "remote_env");
}

{
  const overview = buildServerRemoteContinuityPolicyOverview({
    serverSnapshot: attachableServerSnapshot,
    remoteEnvSnapshot: null,
    managedSettings: {
      syncStatus: "degraded",
      summary: "Refresh failed.",
      activeChannelId: "managed.settings.primary",
      activeChannelLabel: "Primary",
      activeSourceUri: "fixture://managed-settings/primary",
      lastRefreshedAtMs: 1,
      lastSuccessfulRefreshAtMs: 1,
      lastFailedRefreshAtMs: 2,
      refreshError: "channel unreachable",
      localOverrideCount: 0,
      localOverrideFields: [],
      channels: [],
    },
    mobileOverview: null,
    mobileAction: null,
  });

  assert.equal(overview.tone, "attention");
  assert.equal(overview.primaryAction?.kind, "open_studio_settings");
  assert.equal(overview.secondaryAction?.kind, "launch_repl");
  assert.deepEqual(
    overview.queuedActions.map((action) => action.kind),
    ["open_studio_settings", "launch_repl", "launch_repl"],
  );
}

{
  const overview = buildMobileRemoteContinuityPolicyOverview({
    mobileOverview: {
      status: "active",
      statusLabel: "Handoff active",
      statusDetail: "active",
      activityCount: 2,
      evidenceReady: true,
      evidenceLabel: "2 events",
      sessionHistoryCount: 3,
    },
    mobileAction: {
      available: true,
      attachable: true,
      chatShellLabel: "Attach in Chat REPL",
      studioLabel: "Resume in Chat",
      detail: "The retained handoff target is attachable.",
      launchRequest: {
        sessionId: "mobile-1",
        source: "mobile",
        mode: "attach",
        notice: "mobile",
      },
    },
    serverSnapshot: null,
    remoteEnvSnapshot: {
      generatedAtMs: 10,
      sessionId: "session-1",
      workspaceRoot: "/tmp/repo",
      focusedScopeLabel: "Remote runtime",
      governingSourceLabel: "Runtime",
      postureLabel: "Read-only environment projection",
      postureDetail: "Inspect remote bindings.",
      bindingCount: 2,
      controlPlaneBindingCount: 1,
      processBindingCount: 1,
      overlappingBindingCount: 0,
      secretBindingCount: 0,
      redactedBindingCount: 0,
      notes: [],
      bindings: [],
    },
    managedSettings: {
      syncStatus: "synced",
      summary: "Signed settings verified.",
      activeChannelId: "managed.settings.primary",
      activeChannelLabel: "Primary",
      activeSourceUri: "fixture://managed-settings/primary",
      lastRefreshedAtMs: 1,
      lastSuccessfulRefreshAtMs: 1,
      lastFailedRefreshAtMs: null,
      refreshError: null,
      localOverrideCount: 0,
      localOverrideFields: [],
      channels: [],
    },
  });

  assert.equal(overview.tone, "ready");
  assert.equal(overview.primaryAction?.kind, "launch_repl");
  assert.equal(overview.secondaryAction?.kind, "open_view");
  if (!overview.primaryAction || overview.primaryAction.kind !== "launch_repl") {
    throw new Error("expected a mobile continuity launch action");
  }
  if (!overview.secondaryAction || overview.secondaryAction.kind !== "open_view") {
    throw new Error("expected a server continuity fallback action");
  }
  assert.equal(overview.primaryAction.launchRequest.sessionId, "mobile-1");
  assert.equal(overview.secondaryAction.view, "server");
  assert.deepEqual(
    overview.queuedActions.map((action) => action.kind),
    ["launch_repl", "open_view"],
  );
}
