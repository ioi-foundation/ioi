import assert from "node:assert/strict";
import { buildMobileOverview } from "./artifactHubMobileModel.ts";

{
  const overview = buildMobileOverview({
    hasActiveWorkbench: false,
    activeWorkbenchTitle: null,
    activityCount: 0,
    evidenceThreadId: null,
    traceLoading: false,
    traceError: null,
    eventCount: 0,
    artifactCount: 0,
    sessionHistoryCount: 3,
  });

  assert.equal(overview.status, "idle");
  assert.equal(overview.statusLabel, "No mobile handoff active");
  assert.equal(overview.sessionHistoryCount, 3);
}

{
  const overview = buildMobileOverview({
    hasActiveWorkbench: true,
    activeWorkbenchTitle: "Active reply composer",
    activityCount: 4,
    evidenceThreadId: "assistant-workbench:gmail_reply:thread:abc",
    traceLoading: false,
    traceError: null,
    eventCount: 5,
    artifactCount: 2,
    sessionHistoryCount: 7,
  });

  assert.equal(overview.status, "active");
  assert.equal(overview.evidenceReady, true);
  assert.equal(overview.evidenceLabel, "5 events · 2 artifacts");
  assert.match(overview.statusDetail, /Active reply composer/i);
}

{
  const overview = buildMobileOverview({
    hasActiveWorkbench: true,
    activeWorkbenchTitle: "Meeting prep workbench",
    activityCount: 2,
    evidenceThreadId: "assistant-workbench:meeting_prep:event:def",
    traceLoading: false,
    traceError: "load failed",
    eventCount: 0,
    artifactCount: 0,
    sessionHistoryCount: 5,
  });

  assert.equal(overview.status, "attention");
  assert.equal(overview.evidenceReady, false);
  assert.equal(overview.evidenceLabel, "Retained evidence unavailable");
}

{
  const overview = buildMobileOverview({
    hasActiveWorkbench: false,
    activeWorkbenchTitle: null,
    activityCount: 3,
    evidenceThreadId: "assistant-workbench:gmail_reply:thread:ghi",
    traceLoading: false,
    traceError: null,
    eventCount: 1,
    artifactCount: 1,
    sessionHistoryCount: 5,
  });

  assert.equal(overview.status, "retained");
  assert.equal(overview.evidenceReady, true);
}
