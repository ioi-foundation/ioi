import assert from "node:assert/strict";
import type { SessionControllerReplTarget } from "@ioi/agent-ide";
import type { AgentTask } from "../types";
import {
  buildSessionContinuityOverview,
  mergeCurrentTaskRootIntoTargets,
} from "./sessionContinuity.ts";

function makeTask(overrides: Partial<AgentTask>): AgentTask {
  return {
    id: "session-current",
    session_id: "session-current",
    phase: "Running",
    current_step: "Routing the request",
    history: [],
    events: [],
    artifacts: [],
    generation: 0,
    fitness_score: 0,
    lineage_id: "genesis",
    ...overrides,
  } as AgentTask;
}

function makeTarget(
  overrides: Partial<SessionControllerReplTarget>,
): SessionControllerReplTarget {
  return {
    sessionId: "session-a",
    title: "Session A",
    timestamp: 1,
    phase: "Complete",
    currentStep: null,
    resumeHint: null,
    workspaceRoot: null,
    isCurrent: false,
    attachable: false,
    priorityLabel: "Session history",
    ...overrides,
  };
}

{
  const targets = [
    makeTarget({
      sessionId: "session-current",
      isCurrent: true,
      priorityLabel: "Current session",
    }),
  ];
  const task = makeTask({
    build_session: {
      workspaceRoot: "/tmp/current-workspace",
    } as AgentTask["build_session"],
  });

  const merged = mergeCurrentTaskRootIntoTargets(
    targets,
    task,
    "session-current",
  );

  assert.equal(merged[0]?.workspaceRoot, "/tmp/current-workspace");
  assert.equal(merged[0]?.attachable, true);
}

{
  const targets = [makeTarget({ sessionId: "session-a", workspaceRoot: "/tmp/a", attachable: true })];
  const task = makeTask({
    session_id: "session-current",
    intent: "Continue artifact repair",
    build_session: {
      workspaceRoot: "/tmp/current-workspace",
    } as AgentTask["build_session"],
  });

  const merged = mergeCurrentTaskRootIntoTargets(
    targets,
    task,
    "session-current",
  );

  assert.equal(merged[0]?.sessionId, "session-current");
  assert.equal(merged[0]?.title, "Continue artifact repair");
  assert.equal(merged[0]?.workspaceRoot, "/tmp/current-workspace");
  assert.equal(merged[0]?.attachable, true);
}

{
  const overview = buildSessionContinuityOverview(
    [
      makeTarget({
        sessionId: "session-current",
        isCurrent: true,
        attachable: true,
        workspaceRoot: "/tmp/current-workspace",
        priorityLabel: "Current session",
      }),
      makeTarget({
        sessionId: "session-a",
        attachable: true,
        workspaceRoot: "/tmp/a",
        priorityLabel: "Recent workspace",
      }),
    ],
    "session-current",
  );

  assert.equal(overview.statusLabel, "Current session ready");
  assert.equal(overview.attachableCount, 2);
  assert.equal(overview.liveCount, 1);
}

{
  const overview = buildSessionContinuityOverview(
    [makeTarget({ sessionId: "session-a", attachable: false, workspaceRoot: null })],
    null,
  );

  assert.equal(overview.statusLabel, "History retained without workspace roots");
  assert.equal(overview.attachableCount, 0);
}
