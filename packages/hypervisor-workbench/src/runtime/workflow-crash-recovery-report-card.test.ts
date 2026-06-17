import assert from "node:assert/strict";
import test from "node:test";

import { buildWorkflowCrashRecoveryReportCard } from "./workflow-crash-recovery-report-card";

test("crash recovery report card reads canonical proof fields", () => {
  const reportCard = buildWorkflowCrashRecoveryReportCard({
    proof: {
      thread_id: "thread-canonical",
      workflow_graph_id: "workflow-canonical",
      state_dir: "/tmp/ioi-state-canonical",
      first_daemon: {
        pid: 101,
        crash_exit: { signal: "SIGKILL" },
      },
      second_daemon: {
        pid: 202,
        endpoint: "http://127.0.0.1:2020",
      },
      first_turn: {
        turn_id: "turn-before",
        run_id: "run-before",
        terminal_events: ["event-before-terminal"],
      },
      second_turn: {
        turn_id: "turn-after",
        run_id: "run-after",
        seq_start: 8,
        seq_end: 11,
        terminal_events: ["event-after-terminal"],
      },
      replay: {
        before_crash_event_count: 7,
        after_restart_event_count: 7,
        final_event_count: 11,
        before_crash_last_seq: 7,
        replay_from_last_seq_count: 0,
      },
      checks: {
        child_daemon_was_actually_killed: true,
        event_ids_replay_exactly_after_restart: true,
        replay_from_last_seq_is_empty_after_restart: true,
        post_restart_turn_continues_sequence: true,
      },
    },
  });

  assert.equal(reportCard.status, "ready");
  assert.equal(reportCard.threadId, "thread-canonical");
  assert.equal(reportCard.workflowGraphId, "workflow-canonical");
  assert.equal(reportCard.stateDir, "/tmp/ioi-state-canonical");
  assert.equal(reportCard.firstDaemonPid, 101);
  assert.equal(reportCard.secondDaemonPid, 202);
  assert.equal(reportCard.crashSignal, "SIGKILL");
  assert.equal(reportCard.beforeCrashEventCount, 7);
  assert.equal(reportCard.afterRestartEventCount, 7);
  assert.equal(reportCard.replayFromLastSeqCount, 0);
  assert.equal(reportCard.continuationSeqStart, 8);
  assert.equal(reportCard.continuationSeqEnd, 11);
  assert.equal(reportCard.duplicateTerminalEvents, 0);
  assert.ok(reportCard.rows.every((row) => row.status === "passed"));
});

test("crash recovery report card ignores retired proof aliases", () => {
  const reportCard = buildWorkflowCrashRecoveryReportCard({
    proof: {
      threadId: "thread-retired",
      workflowGraphId: "workflow-retired",
      stateDir: "/tmp/ioi-state-retired",
      firstDaemon: {
        pid: 101,
        crashExit: { signal: "SIGKILL" },
      },
      secondDaemon: {
        pid: 202,
        endpoint: "http://127.0.0.1:2020",
      },
      firstTurn: {
        turnId: "turn-before-retired",
        runId: "run-before-retired",
        terminalEvents: ["event-before-terminal"],
      },
      secondTurn: {
        turnId: "turn-after-retired",
        runId: "run-after-retired",
        seqStart: 8,
        seqEnd: 11,
        terminalEvents: ["event-after-terminal"],
      },
      replay: {
        beforeCrashEventCount: 7,
        afterRestartEventCount: 7,
        finalEventCount: 11,
        beforeCrashLastSeq: 7,
        replayFromLastSeqCount: 0,
      },
      checks: {
        childDaemonWasActuallyKilled: true,
        eventIdsReplayExactlyAfterRestart: true,
        replayFromLastSeqIsEmptyAfterRestart: true,
        postRestartTurnContinuesSequence: true,
      },
    },
  });

  assert.equal(reportCard.status, "blocked");
  assert.equal(reportCard.threadId, null);
  assert.equal(reportCard.workflowGraphId, null);
  assert.equal(reportCard.stateDir, null);
  assert.equal(reportCard.firstDaemonPid, null);
  assert.equal(reportCard.secondDaemonPid, null);
  assert.equal(reportCard.crashSignal, null);
  assert.equal(reportCard.beforeCrashEventCount, null);
  assert.equal(reportCard.afterRestartEventCount, null);
  assert.equal(reportCard.replayFromLastSeqCount, null);
  assert.equal(reportCard.continuationSeqStart, null);
  assert.equal(reportCard.continuationSeqEnd, null);
  assert.equal(reportCard.duplicateTerminalEvents, 0);
  assert.ok(reportCard.rows.some((row) => row.status === "blocked"));
});
