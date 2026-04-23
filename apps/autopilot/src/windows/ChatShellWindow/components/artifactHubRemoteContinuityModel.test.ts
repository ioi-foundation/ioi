import assert from "node:assert/strict";
import type { SessionServerSessionRecord } from "../../../types";
import {
  buildMobileEvidenceContinuityAction,
  buildRemoteSessionContinuityAction,
} from "./artifactHubRemoteContinuityModel.ts";

const attachableSession: SessionServerSessionRecord = {
  sessionId: "remote-session-1",
  title: "Remote workspace session",
  timestamp: Date.parse("2026-04-05T23:45:00.000Z"),
  sourceLabel: "remote kernel",
  presenceState: "remote_only_attachable",
  presenceLabel: "Remote-only attachable",
  resumeHint: "Resume from server-backed task state",
  workspaceRoot: "/srv/ioi/project",
};

const historyOnlySession: SessionServerSessionRecord = {
  sessionId: "remote-session-2",
  title: "History-only session",
  timestamp: Date.parse("2026-04-05T23:46:00.000Z"),
  sourceLabel: "remote kernel",
  presenceState: "merged_history_only",
  presenceLabel: "Merged history only",
  resumeHint: "History merged from server",
  workspaceRoot: null,
};

{
  const action = buildRemoteSessionContinuityAction(attachableSession);

  assert.equal(action.attachable, true);
  assert.equal(action.chatShellLabel, "Attach in Chat REPL");
  assert.equal(action.launchRequest.mode, "attach");
  assert.equal(action.launchRequest.source, "server");
  assert.match(action.detail, /exists only in remote history/i);
}

{
  const action = buildRemoteSessionContinuityAction(historyOnlySession);

  assert.equal(action.attachable, false);
  assert.equal(action.chatShellLabel, "Review in Chat REPL");
  assert.equal(action.launchRequest.mode, "review");
  assert.match(action.detail, /merged into local shell history/i);
}

{
  const action = buildMobileEvidenceContinuityAction({
    evidenceThreadId: "session-evidence-1",
    hasActiveWorkbench: false,
    hasAttachableSessionTarget: true,
  });

  assert.equal(action.available, true);
  assert.equal(action.attachable, true);
  assert.equal(action.chatShellLabel, "Attach in Chat REPL");
  assert.equal(action.launchRequest?.mode, "attach");
  assert.match(action.detail, /attachable retained session target/i);
}

{
  const action = buildMobileEvidenceContinuityAction({
    evidenceThreadId: null,
    hasActiveWorkbench: false,
    hasAttachableSessionTarget: false,
  });

  assert.equal(action.available, false);
  assert.equal(action.attachable, false);
  assert.equal(action.launchRequest, null);
  assert.match(action.detail, /No retained evidence thread/i);
}
