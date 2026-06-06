import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { AgentgresRuntimeStateStore, startRuntimeDaemonService } from "./index.mjs";

async function fetchJson(url, options = {}) {
  const { headers, ...rest } = options;
  const response = await fetch(url, {
    ...rest,
    headers: { "content-type": "application/json", ...(headers ?? {}) },
  });
  const text = await response.text();
  const body = text ? JSON.parse(text) : null;
  assert.ok(response.ok, `${response.status} ${response.statusText} for ${url}: ${text}`);
  return body;
}

function runtimeControlBridge(calls, hooks = {}) {
  return {
    bridgeId: "runtime-control-test-bridge",
    async startThread(input) {
      calls.push({ operation: "start_thread", input });
      return {
        session_id: "session_runtime_control_test",
        status: "active",
        source: "runtime_service",
        events: [
          {
            event_id: "evt_thread_started_runtime_control_test",
            event_kind: "thread.started",
            status: "completed",
            created_at: new Date().toISOString(),
            payload: {},
          },
        ],
      };
    },
    async controlThread(input) {
      calls.push({ operation: "control_thread", input });
      return {
        schema_version: "ioi.runtime.control-thread.test.v1",
        action: input.action,
        status: input.action === "resume" ? "running" : "paused",
        input,
      };
    },
    async submitTurn(input, callbacks = {}) {
      calls.push({ operation: "submit_turn", input });
      if (hooks.submitTurn) {
        return hooks.submitTurn(input, callbacks);
      }
      return {
        turn_id: "turn_runtime_control_test",
        status: "completed",
        result: "Runtime control test completed.",
        events: [
          {
            event_id: "evt_turn_started_runtime_control_test",
            event_kind: "turn.started",
            status: "running",
            created_at: new Date().toISOString(),
            payload: {},
          },
          {
            event_id: "evt_turn_completed_runtime_control_test",
            event_kind: "turn.completed",
            status: "completed",
            created_at: new Date().toISOString(),
            payload: { result: "Runtime control test completed." },
          },
        ],
      };
    },
  };
}

function managedSessionReconnectBridge(calls, managedState) {
  function sessionCard(input = {}) {
    return {
      id: managedState.managedSessionId,
      kind: "sandbox_browser",
      surface_label: "Sandbox browser",
      status: "waiting_for_user",
      status_label: "Waiting for user",
      control_state: managedState.controlState,
      waiting_for_user: true,
      waiting_reason: "manual_auth_handoff",
      replay_ready: true,
      session_id: managedState.managedSessionId,
      thread_id: input.threadId,
      runtime_session_id: input.sessionId,
    };
  }

  function inspection(input = {}) {
    return {
      bridge_id: "managed-session-reconnect-bridge",
      source: "runtime_service",
      status: "active",
      thread_id: input.threadId,
      session_id: input.sessionId,
      managed_sessions: {
        schema_version: "ioi.runtime.managed-session.v1",
        thread_id: input.threadId,
        sessions: [sessionCard(input)],
        product_lane: [],
        replay: {
          available: true,
          replayable: true,
          source: "persisted_runtime_service_state",
        },
      },
    };
  }

  return {
    bridgeId: "managed-session-reconnect-bridge",
    async startThread(input) {
      calls.push({ operation: "start_thread", input });
      return {
        session_id: managedState.runtimeSessionId,
        status: "active",
        source: "runtime_service",
        events: [
          {
            event_id: "evt_thread_started_managed_session_reconnect",
            event_kind: "thread.started",
            status: "completed",
            created_at: new Date().toISOString(),
            payload: {},
          },
        ],
      };
    },
    async inspectThread(input) {
      calls.push({ operation: "inspect_thread", input });
      return inspection(input);
    },
    async controlThread(input) {
      calls.push({ operation: "control_thread", input });
      if (input.action === "take_over_session") {
        managedState.controlState = "take_over";
      } else if (input.action === "return_agent") {
        managedState.controlState = "return_agent";
      } else if (input.action === "observe_session") {
        managedState.controlState = "observe";
      }
      return {
        schema_version: "ioi.runtime.managed-session-control.test.v1",
        action: input.action,
        status: "completed",
        inspection: inspection(input),
      };
    },
  };
}

function contextPolicyRunner(calls = []) {
  return {
    planOperatorInterruptStateUpdate(request = {}) {
      calls.push({ operation: "plan_operator_interrupt_state_update", input: request });
      const control = {
        control: "interrupt",
        source: request.source,
        reason: request.reason,
        eventId: request.event_id,
        seq: request.seq,
        createdAt: request.created_at,
      };
      const run = request.run ?? {};
      const traceControls = appendOperatorControlForTest(run.trace?.operatorControls, control);
      const runControls = appendOperatorControlForTest(run.operatorControls, control);
      return {
        status: "planned",
        operation_kind: "turn.interrupt",
        run: {
          ...run,
          status: ["queued", "running", "blocked"].includes(run.status) ? "canceled" : run.status,
          turnStatus: "interrupted",
          updatedAt: request.created_at,
          result: `Turn interrupted by operator: ${request.reason}`,
          trace: {
            ...run.trace,
            status: "interrupted",
            stopCondition: {
              reason: "operator_interrupt",
              evidenceSufficient: true,
              rationale: `Operator interrupt accepted from ${request.source}: ${request.reason}`,
            },
            operatorControls: traceControls,
            qualityLedger: {
              ...run.trace?.qualityLedger,
              failureOntologyLabels: [
                ...new Set([
                  ...(Array.isArray(run.trace?.qualityLedger?.failureOntologyLabels)
                    ? run.trace.qualityLedger.failureOntologyLabels
                    : []),
                  "operator_interrupt",
                ]),
              ],
            },
          },
          operatorControls: runControls,
        },
      };
    },
    planOperatorSteerStateUpdate(request = {}) {
      calls.push({ operation: "plan_operator_steer_state_update", input: request });
      const control = {
        control: "steer",
        source: request.source,
        guidance: request.guidance,
        eventId: request.event_id,
        seq: request.seq,
        createdAt: request.created_at,
      };
      const run = request.run ?? {};
      const traceControls = appendOperatorControlForTest(run.trace?.operatorControls, control);
      const runControls = appendOperatorControlForTest(run.operatorControls, control);
      return {
        status: "planned",
        operation_kind: "turn.steer",
        run: {
          ...run,
          updatedAt: request.created_at,
          trace: {
            ...run.trace,
            operatorControls: traceControls,
          },
          operatorControls: runControls,
        },
      };
    },
  };
}

function runtimeAgentgresAdmissionRunner(calls = []) {
  return {
    commitRuntimeRunState(stateDir, request) {
      calls.push({ operation: "commit_runtime_run_state", stateDir, input: request });
      const operationRef = `agentgres://runtime-state/runs/${request.run_id}/operations/${request.operation_kind}_test`;
      return {
        source: "rust_agentgres_runtime_run_state_commit_command",
        operation_ref: operationRef,
        state_root_after: "sha256:test-state-root-after",
        resulting_head: `agentgres://runtime-state/runs/${request.run_id}/head/test`,
        transition_hash: "sha256:test-transition",
        materialization_hash: "sha256:test-materialization",
        write_set_hash: "sha256:test-write-set",
        persistence_hash: "sha256:test-persistence",
        commit_hash: "sha256:test-commit",
        written_records: [`runs/${request.run_id}.json`],
        evidence_refs: [operationRef],
      };
    },
  };
}

function appendOperatorControlForTest(value, control) {
  const entries = Array.isArray(value) ? [...value] : [];
  if (!entries.some((entry) => entry?.eventId === control.eventId)) {
    entries.push(control);
  }
  return entries;
}

async function seedRuntimeControlModelRoute(store) {
  store.modelMounting.importModel({
    model_id: "runtime-control-test-model",
    provider_id: "provider.local.folder",
    capabilities: ["chat"],
  });
  store.modelMounting.mountEndpoint({
    id: "endpoint.runtime-control-test",
    model_id: "runtime-control-test-model",
    provider_id: "provider.local.folder",
    capabilities: ["chat"],
  });
  await store.modelMounting.loadModel({
    endpoint_id: "endpoint.runtime-control-test",
    load_policy: { mode: "eager" },
  });
  store.modelMounting.upsertRoute({
    id: "route.local-first",
    role: "chat",
    fallback: ["endpoint.runtime-control-test"],
    provider_eligibility: ["local_folder"],
  });
}

test("managed browser session inspect and control survive daemon store reconnect", async () => {
  const stateDir = mkdtempSync(join(tmpdir(), "ioi-runtime-managed-session-reconnect-"));
  const calls = [];
  const managedState = {
    runtimeSessionId: "session_managed_reconnect",
    managedSessionId: "sandbox_browser:manual_auth_handoff",
    controlState: "observe",
  };
  let store = new AgentgresRuntimeStateStore(stateDir, {
    cwd: stateDir,
    runtimeBridge: managedSessionReconnectBridge(calls, managedState),
  });
  try {
    await seedRuntimeControlModelRoute(store);

    const thread = await store.createThread({
      runtime_profile: "runtime_service",
      options: {
        runtime_profile: "runtime_service",
        local: { cwd: stateDir },
      },
    });

    const initialInspection = await store.inspectManagedSessionsForThread(thread.thread_id);
    assert.equal(initialInspection.session_id, managedState.runtimeSessionId);
    assert.equal(initialInspection.managed_sessions.replay.replayable, true);
    assert.equal(initialInspection.managed_sessions.sessions[0].waiting_for_user, true);
    assert.equal(initialInspection.managed_sessions.sessions[0].control_state, "observe");

    const takeover = await store.controlManagedSessionForThread(thread.thread_id, {
      managedSessionId: managedState.managedSessionId,
      action: "take_over",
      reason: "operator takes over manual authentication handoff fixture",
    });
    assert.equal(takeover.action, "take_over_session");
    assert.equal(takeover.inspection.managed_sessions.sessions[0].control_state, "take_over");

    store.close();
    store = new AgentgresRuntimeStateStore(stateDir, {
      cwd: stateDir,
      runtimeBridge: managedSessionReconnectBridge(calls, managedState),
    });

    const replayedAfterReconnect = await store.inspectManagedSessionsForThread(thread.thread_id);
    assert.equal(replayedAfterReconnect.session_id, managedState.runtimeSessionId);
    assert.equal(replayedAfterReconnect.managed_sessions.sessions[0].id, managedState.managedSessionId);
    assert.equal(replayedAfterReconnect.managed_sessions.sessions[0].control_state, "take_over");
    assert.equal(replayedAfterReconnect.managed_sessions.sessions[0].waiting_for_user, true);
    assert.equal(replayedAfterReconnect.managed_sessions.replay.source, "persisted_runtime_service_state");

    const returned = await store.controlManagedSessionForThread(thread.thread_id, {
      managedSessionId: managedState.managedSessionId,
      action: "return-agent",
      reason: "operator returns control after reconnect",
    });
    assert.equal(returned.action, "return_agent");
    assert.equal(returned.inspection.managed_sessions.sessions[0].control_state, "return_agent");

    const startCalls = calls.filter((call) => call.operation === "start_thread");
    const inspectCalls = calls.filter((call) => call.operation === "inspect_thread");
    const controlCalls = calls.filter((call) => call.operation === "control_thread");
    assert.equal(startCalls.length, 1);
    assert.equal(inspectCalls.length, 2);
    assert.equal(controlCalls.length, 2);
    assert.ok(inspectCalls.every((call) => call.input.sessionId === managedState.runtimeSessionId));
    assert.ok(controlCalls.every((call) => call.input.managedSessionId === managedState.managedSessionId));
  } finally {
    store?.close?.();
    rmSync(stateDir, { recursive: true, force: true });
  }
});

test("managed browser session HTTP routes survive daemon service reconnect", async () => {
  const stateDir = mkdtempSync(join(tmpdir(), "ioi-runtime-managed-session-http-reconnect-"));
  const calls = [];
  const managedState = {
    runtimeSessionId: "session_managed_http_reconnect",
    managedSessionId: "sandbox_browser:http_manual_auth_handoff",
    controlState: "observe",
  };
  let daemon;
  try {
    daemon = await startRuntimeDaemonService({
      cwd: stateDir,
      stateDir,
      runtimeBridge: managedSessionReconnectBridge(calls, managedState),
    });
    await seedRuntimeControlModelRoute(daemon.store);

    const thread = await daemon.store.createThread({
      runtime_profile: "runtime_service",
      options: {
        runtime_profile: "runtime_service",
        local: { cwd: stateDir },
      },
    });
    const sessionRoute = `${daemon.endpoint}/v1/threads/${thread.thread_id}/managed-sessions`;

    const initialInspection = await fetchJson(sessionRoute);
    assert.equal(initialInspection.session_id, managedState.runtimeSessionId);
    assert.equal(initialInspection.managed_sessions.sessions[0].id, managedState.managedSessionId);
    assert.equal(initialInspection.managed_sessions.sessions[0].control_state, "observe");
    assert.equal(initialInspection.managed_sessions.sessions[0].waiting_for_user, true);

    const takeover = await fetchJson(`${sessionRoute}/control`, {
      method: "POST",
      body: JSON.stringify({
        managedSessionId: managedState.managedSessionId,
        action: "take_over",
        reason: "operator takes over manual authentication handoff fixture through HTTP route",
      }),
    });
    assert.equal(takeover.action, "take_over_session");
    assert.equal(takeover.inspection.managed_sessions.sessions[0].control_state, "take_over");

    await daemon.close();
    daemon = await startRuntimeDaemonService({
      cwd: stateDir,
      stateDir,
      runtimeBridge: managedSessionReconnectBridge(calls, managedState),
    });
    const reconnectedSessionRoute = `${daemon.endpoint}/v1/threads/${thread.thread_id}/managed-sessions`;

    const replayedAfterReconnect = await fetchJson(reconnectedSessionRoute);
    assert.equal(replayedAfterReconnect.session_id, managedState.runtimeSessionId);
    assert.equal(replayedAfterReconnect.managed_sessions.sessions[0].id, managedState.managedSessionId);
    assert.equal(replayedAfterReconnect.managed_sessions.sessions[0].control_state, "take_over");
    assert.equal(replayedAfterReconnect.managed_sessions.replay.source, "persisted_runtime_service_state");

    const returned = await fetchJson(`${reconnectedSessionRoute}/control`, {
      method: "POST",
      body: JSON.stringify({
        managedSessionId: managedState.managedSessionId,
        action: "return-agent",
        reason: "operator returns control after HTTP reconnect",
      }),
    });
    assert.equal(returned.action, "return_agent");
    assert.equal(returned.inspection.managed_sessions.sessions[0].control_state, "return_agent");

    const startCalls = calls.filter((call) => call.operation === "start_thread");
    const inspectCalls = calls.filter((call) => call.operation === "inspect_thread");
    const controlCalls = calls.filter((call) => call.operation === "control_thread");
    assert.equal(startCalls.length, 1);
    assert.equal(inspectCalls.length, 2);
    assert.equal(controlCalls.length, 2);
    assert.ok(inspectCalls.every((call) => call.input.sessionId === managedState.runtimeSessionId));
    assert.ok(controlCalls.every((call) => call.input.managedSessionId === managedState.managedSessionId));
  } finally {
    if (daemon) await daemon.close();
    rmSync(stateDir, { recursive: true, force: true });
  }
});

test("runtime-backed interrupt and resume route through control_thread", async () => {
  const stateDir = mkdtempSync(join(tmpdir(), "ioi-runtime-thread-control-"));
  const calls = [];
  const store = new AgentgresRuntimeStateStore(stateDir, {
    cwd: stateDir,
    contextPolicyRunner: contextPolicyRunner(calls),
    runtimeAgentgresAdmissionRunner: runtimeAgentgresAdmissionRunner(calls),
    runtimeBridge: runtimeControlBridge(calls),
  });
  try {
    await seedRuntimeControlModelRoute(store);

    const thread = await store.createThread({
      runtime_profile: "runtime_service",
      options: {
        runtime_profile: "runtime_service",
        local: { cwd: stateDir },
      },
    });
    const run = store.createRun(thread.agent_id, {
      mode: "send",
      prompt: "exercise runtime control",
    });
    const turnId = `turn_${run.id.slice("run_".length)}`;

    const interrupted = await store.interruptTurn(thread.thread_id, turnId, {
      source: "agent_studio",
      reason: "operator_stop",
    });
    const resumed = await store.resumeThread(thread.thread_id, {
      source: "agent_studio",
      reason: "operator_resume",
    });

    const controls = calls.filter((call) => call.operation === "control_thread");
    assert.equal(controls.length, 2);
    assert.equal(controls[0].input.action, "stop");
    assert.equal(controls[0].input.sessionId, "session_runtime_control_test");
    assert.equal(controls[0].input.threadId, thread.thread_id);
    assert.equal(controls[1].input.action, "resume");
    assert.equal(controls[1].input.sessionId, "session_runtime_control_test");
    assert.equal(interrupted.runtime_control.action, "stop");
    assert.equal(resumed.runtime_control.action, "resume");
  } finally {
    store.close();
    rmSync(stateDir, { recursive: true, force: true });
  }
});

test("runtime-backed steering routes run update through Rust policy planner", async () => {
  const stateDir = mkdtempSync(join(tmpdir(), "ioi-runtime-thread-steer-"));
  const calls = [];
  const store = new AgentgresRuntimeStateStore(stateDir, {
    cwd: stateDir,
    contextPolicyRunner: contextPolicyRunner(calls),
    runtimeAgentgresAdmissionRunner: runtimeAgentgresAdmissionRunner(calls),
    runtimeBridge: runtimeControlBridge(calls),
  });
  try {
    await seedRuntimeControlModelRoute(store);

    const thread = await store.createThread({
      runtime_profile: "runtime_service",
      options: {
        runtime_profile: "runtime_service",
        local: { cwd: stateDir },
      },
    });
    const run = store.createRun(thread.agent_id, {
      mode: "send",
      prompt: "exercise runtime steering",
    });
    const turnId = `turn_${run.id.slice("run_".length)}`;

    const steered = store.steerTurn(thread.thread_id, turnId, {
      source: "agent_studio",
      guidance: "focus on the failing bridge assertion",
    });

    const plannerCalls = calls.filter((call) => call.operation === "plan_operator_steer_state_update");
    assert.equal(plannerCalls.length, 1);
    assert.equal(plannerCalls[0].input.thread_id, thread.thread_id);
    assert.equal(plannerCalls[0].input.turn_id, turnId);
    assert.equal(plannerCalls[0].input.run_id, run.id);
    assert.equal(plannerCalls[0].input.guidance, "focus on the failing bridge assertion");
    assert.equal(steered.events.at(-1).event_kind, "turn.steered");

    const steerCommits = calls.filter(
      (call) =>
        call.operation === "commit_runtime_run_state" &&
        call.input.operation_kind === "turn.steer",
    );
    assert.equal(steerCommits.length, 1);
    assert.equal(
      steerCommits[0].input.run.trace.operatorControls.at(-1).guidance,
      "focus on the failing bridge assertion",
    );
  } finally {
    store.close();
    rmSync(stateDir, { recursive: true, force: true });
  }
});

test("runtime-backed in-flight turn can be interrupted before durable run projection exists", async () => {
  const stateDir = mkdtempSync(join(tmpdir(), "ioi-runtime-thread-control-inflight-"));
  const calls = [];
  const turnId = "turn_inflight_runtime_control_test";
  let releaseSubmit;
  const submitRelease = new Promise((resolve) => {
    releaseSubmit = resolve;
  });
  let markLiveStarted;
  const liveStarted = new Promise((resolve) => {
    markLiveStarted = resolve;
  });
  const store = new AgentgresRuntimeStateStore(stateDir, {
    cwd: stateDir,
    contextPolicyRunner: contextPolicyRunner(calls),
    runtimeAgentgresAdmissionRunner: runtimeAgentgresAdmissionRunner(calls),
    runtimeBridge: runtimeControlBridge(calls, {
      async submitTurn(input, { onRuntimeEvent } = {}) {
        const startedEvent = {
          event_id: "evt_turn_started_inflight_runtime_control_test",
          event_kind: "turn.started",
          turn_id: turnId,
          status: "running",
          created_at: new Date().toISOString(),
          payload: { summary: "in-flight runtime turn started" },
        };
        onRuntimeEvent?.(startedEvent);
        markLiveStarted();
        await submitRelease;
        return {
          turn_id: turnId,
          status: "completed",
          result: "In-flight runtime control test completed.",
          events: [
            startedEvent,
            {
              event_id: "evt_turn_completed_inflight_runtime_control_test",
              event_kind: "turn.completed",
              turn_id: turnId,
              status: "completed",
              created_at: new Date().toISOString(),
              payload: { result: "In-flight runtime control test completed." },
            },
          ],
        };
      },
    }),
  });
  try {
    await seedRuntimeControlModelRoute(store);

    const thread = await store.createThread({
      runtime_profile: "runtime_service",
      options: {
        runtime_profile: "runtime_service",
        local: { cwd: stateDir },
      },
    });
    const turnPromise = store.createTurn(thread.thread_id, {
      prompt: "exercise in-flight runtime control",
      runtime_profile: "runtime_service",
      options: {
        runtime_profile: "runtime_service",
        local: { cwd: stateDir },
      },
    });

    await liveStarted;
    assert.equal(store.runs.has("run_inflight_runtime_control_test"), false);
    const interrupted = await store.interruptTurn(thread.thread_id, turnId, {
      source: "agent_studio",
      reason: "operator_stop",
    });
    releaseSubmit();
    const completed = await turnPromise;

    const controls = calls.filter((call) => call.operation === "control_thread");
    assert.equal(controls.length, 1);
    assert.equal(controls[0].input.action, "stop");
    assert.equal(controls[0].input.threadId, thread.thread_id);
    assert.equal(interrupted.status, "interrupted");
    assert.equal(interrupted.runtime_control.action, "stop");
    assert.equal(completed.turn_id, turnId);
    assert.equal(store.runs.has("run_inflight_runtime_control_test"), true);
  } finally {
    store.close();
    rmSync(stateDir, { recursive: true, force: true });
  }
});

test("subagent budget block can be resumed and recovered after store reload", async () => {
  const stateDir = mkdtempSync(join(tmpdir(), "ioi-runtime-subagent-recovery-"));
  const store = new AgentgresRuntimeStateStore(stateDir, { cwd: stateDir });
  try {
    await seedRuntimeControlModelRoute(store);

    const thread = await store.createThread({
      source: "runtime-subagent-recovery-test",
      goal: "exercise subagent budget recovery",
      options: {
        local: { cwd: stateDir },
        model: { id: "auto", routeId: "route.local-first" },
      },
    });
    const parentTurn = store.createRun(thread.agent_id, {
      mode: "send",
      prompt: "parent turn for subagent recovery",
    });

    let blockedError;
    try {
      store.spawnSubagent(thread.thread_id, {
        source: "runtime-subagent-recovery-test",
        role: "failed-child",
        prompt: "This child intentionally exceeds a tiny token budget.",
        parentTurnId: `turn_${parentTurn.id.slice("run_".length)}`,
        budget: { maxTokens: 1 },
      });
    } catch (error) {
      blockedError = error;
    }

    assert.equal(blockedError?.details?.reason, "subagent_budget_exceeded");
    const blockedChild = store
      .listSubagents(thread.thread_id)
      .subagents.find((record) => record.role === "failed-child");
    assert.ok(blockedChild?.subagent_id);
    assert.equal(blockedChild.lifecycle_status, "blocked");

    const resumed = store.resumeSubagent(thread.thread_id, blockedChild.subagent_id, {
      source: "runtime-subagent-recovery-test",
      prompt: "Resume the failed child with a repaired budget.",
      budget: { maxTokens: 10000 },
    });
    assert.equal(resumed.subagent.restart_status, "restarted");
    assert.notEqual(resumed.subagent.lifecycle_status, "blocked");

    const reloaded = new AgentgresRuntimeStateStore(stateDir, { cwd: stateDir });
    try {
      const recovered = reloaded
        .listSubagents(thread.thread_id)
        .subagents.find((record) => record.subagent_id === blockedChild.subagent_id);
      assert.equal(recovered?.restart_status, "restarted");
      assert.notEqual(recovered?.lifecycle_status, "blocked");
    } finally {
      reloaded.close();
    }
  } finally {
    store.close();
    rmSync(stateDir, { recursive: true, force: true });
  }
});
