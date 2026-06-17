import assert from "node:assert/strict";
import type {
  SessionRewindCandidate,
  SessionRewindSnapshot,
} from "../../../types.ts";
import {
  canCompareFocusedRewindCandidate,
  selectFocusedRewindCandidate,
} from "./artifactHubRewindModel.ts";

function candidate(
  overrides: Partial<SessionRewindCandidate> = {},
): SessionRewindCandidate {
  return {
    sessionId: "session-current",
    title: "Current session",
    timestamp: 100,
    phase: "Running",
    currentStep: "Active turn",
    resumeHint: "Resume current turn",
    workspaceRoot: "/repo",
    isCurrent: true,
    isLastStable: false,
    actionLabel: "Open checkpoint",
    previewHeadline: "Current retained checkpoint",
    previewDetail: "Preview detail",
    discardSummary: "Would discard 0 later turns.",
    ...overrides,
  };
}

function snapshot(
  overrides: Partial<SessionRewindSnapshot> = {},
): SessionRewindSnapshot {
  return {
    activeSessionId: "session-current",
    activeSessionTitle: "Current session",
    lastStableSessionId: "session-stable",
    candidates: [
      candidate(),
      candidate({
        sessionId: "session-stable",
        title: "Stable checkpoint",
        timestamp: 80,
        isCurrent: false,
        isLastStable: true,
        previewHeadline: "Stable rewind point",
        discardSummary: "Would discard the active draft turn.",
      }),
    ],
    ...overrides,
  };
}

{
  assert.equal(selectFocusedRewindCandidate(null, null), null);
}

{
  const focused = selectFocusedRewindCandidate(snapshot(), null);
  assert.equal(focused?.sessionId, "session-stable");
}

{
  const focused = selectFocusedRewindCandidate(snapshot(), "session-current");
  assert.equal(focused?.sessionId, "session-current");
}

{
  const focused = selectFocusedRewindCandidate(
    snapshot({
      candidates: [
        candidate({
          sessionId: "session-older",
          title: "Older checkpoint",
          timestamp: 50,
          isCurrent: false,
          isLastStable: false,
        }),
      ],
    }),
    null,
  );
  assert.equal(focused?.sessionId, "session-older");
}

{
  const focused = selectFocusedRewindCandidate(snapshot(), "session-stable");
  assert.equal(
    canCompareFocusedRewindCandidate("session-current", focused),
    true,
  );
  assert.equal(
    canCompareFocusedRewindCandidate("session-current", candidate()),
    false,
  );
}
