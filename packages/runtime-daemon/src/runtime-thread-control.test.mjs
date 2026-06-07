import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
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

function contextPolicyRunner(calls = [], overrides = {}) {
  return {
    planAgentCreateStateUpdate(request = {}) {
      calls.push({ operation: "plan_agent_create_state_update", input: request });
      if (overrides.agentCreateStateUpdate) {
        return overrides.agentCreateStateUpdate;
      }
      return {
        status: "planned",
        operation_kind: "agent.create",
        agent: request.agent,
      };
    },
    planRunCreateStateUpdate(request = {}) {
      calls.push({ operation: "plan_run_create_state_update", input: request });
      if (overrides.runCreateStateUpdate) {
        return overrides.runCreateStateUpdate;
      }
      return {
        status: "planned",
        operation_kind: "run.create",
        run: request.run,
      };
    },
    planRuntimeBridgeThreadStartAgentStateUpdate(request = {}) {
      calls.push({ operation: "plan_runtime_bridge_thread_start_agent_state_update", input: request });
      if (overrides.runtimeBridgeThreadStartStateUpdate) {
        return overrides.runtimeBridgeThreadStartStateUpdate;
      }
      return {
        status: "planned",
        operation_kind: "thread.runtime_bridge.start",
        agent: {
          ...request.agent,
          runtimeSessionId: request.session_id,
          runtimeBridgeId: request.bridge_id,
          runtimeProfile: request.runtime_profile ?? request.agent?.runtimeProfile ?? request.agent?.runtime ?? "runtime_service",
          status: request.status === "active" ? "running" : request.status,
          updatedAt: request.updated_at,
        },
      };
    },
    planAgentStatusStateUpdate(request = {}) {
      calls.push({ operation: "plan_agent_status_state_update", input: request });
      if (overrides.agentStatusStateUpdate) {
        return overrides.agentStatusStateUpdate;
      }
      return {
        status: "planned",
        operation_kind: request.operation_kind,
        agent: {
          ...request.agent,
          status: request.status,
          updatedAt: request.updated_at,
        },
      };
    },
    planRuntimeBridgeTurnRunStateUpdate(request = {}) {
      calls.push({ operation: "plan_runtime_bridge_turn_run_state_update", input: request });
      if (overrides.runtimeBridgeTurnRunStateUpdate) {
        return overrides.runtimeBridgeTurnRunStateUpdate;
      }
      return {
        status: "planned",
        operation_kind: "turn.runtime_bridge.submit",
        run: request.run,
      };
    },
    planOperatorInterruptStateUpdate(request = {}) {
      calls.push({ operation: "plan_operator_interrupt_state_update", input: request });
      if (overrides.interruptStateUpdate) {
        return overrides.interruptStateUpdate;
      }
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
      if (overrides.steerStateUpdate) {
        return overrides.steerStateUpdate;
      }
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
  function writeCommittedRecord(stateDir, recordPath, value) {
    const targetPath = join(stateDir, recordPath);
    mkdirSync(join(targetPath, ".."), { recursive: true });
    writeFileSync(targetPath, `${JSON.stringify(value, null, 2)}\n`);
  }

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
    commitRuntimeAgentState(stateDir, request) {
      calls.push({ operation: "commit_runtime_agent_state", stateDir, input: request });
      const recordPath = `agents/${request.agent_id}.json`;
      writeCommittedRecord(stateDir, recordPath, request.agent ?? request);
      return {
        source: "rust_agentgres_runtime_agent_state_commit_command",
        record: {
          schema_version: "ioi.runtime_agent_state_commit.v1",
          agent_id: request.agent_id,
          operation_kind: request.operation_kind,
          record: {
            record_path: recordPath,
            object_ref: `agentgres://runtime-state/agents/${request.agent_id}/records/${recordPath}`,
            content_hash: "sha256:agent-content",
            payload_refs: [`payload://runtime/agents/${request.agent_id}/records/${recordPath}`],
            receipt_refs: request.agent?.receipt_refs ?? [],
            admission: { admission_hash: "sha256:agent-admission" },
          },
          commit_hash: "sha256:agent-commit",
        },
        agent_id: request.agent_id,
        object_ref: `agentgres://runtime-state/agents/${request.agent_id}/records/${recordPath}`,
        content_hash: "sha256:agent-content",
        admission_hash: "sha256:agent-admission",
        commit_hash: "sha256:agent-commit",
        written_record: { record_path: recordPath },
        evidence_refs: ["rust_agentgres_runtime_agent_state_commit"],
      };
    },
    commitRuntimeSubagentState(stateDir, request) {
      calls.push({ operation: "commit_runtime_subagent_state", stateDir, input: request });
      const recordPath = `subagents/${request.subagent_id}.json`;
      writeCommittedRecord(stateDir, recordPath, request.subagent ?? request);
      return {
        source: "rust_agentgres_runtime_subagent_state_commit_command",
        record: {
          schema_version: "ioi.runtime_subagent_state_commit.v1",
          subagent_id: request.subagent_id,
          operation_kind: request.operation_kind,
          record: {
            record_path: recordPath,
            object_ref: `agentgres://runtime-state/subagents/${request.subagent_id}/records/${recordPath}`,
            content_hash: "sha256:subagent-content",
            payload_refs: [`payload://runtime/subagents/${request.subagent_id}/records/${recordPath}`],
            receipt_refs: request.subagent?.receipt_refs ?? [],
            admission: { admission_hash: "sha256:subagent-admission" },
          },
          commit_hash: "sha256:subagent-commit",
        },
        subagent_id: request.subagent_id,
        object_ref: `agentgres://runtime-state/subagents/${request.subagent_id}/records/${recordPath}`,
        content_hash: "sha256:subagent-content",
        admission_hash: "sha256:subagent-admission",
        commit_hash: "sha256:subagent-commit",
        written_record: { record_path: recordPath },
        evidence_refs: ["rust_agentgres_runtime_subagent_state_commit"],
      };
    },
    commitRuntimeModelMountRecordState(stateDir, request) {
      calls.push({ operation: "commit_runtime_model_mount_record_state", stateDir, input: request });
      const recordPath = request.record_path ?? `${request.record_kind ?? "records"}/${request.record_id ?? "record"}.json`;
      writeCommittedRecord(stateDir, recordPath, request.record ?? request);
      return {
        source: "rust_agentgres_runtime_model_mount_record_state_commit_command",
        backend: "rust_agentgres_storage",
        record: {
          schema_version: "ioi.runtime_model_mount_record_state_commit.v1",
          record_id: request.record_id ?? "record",
          record_kind: request.record_kind ?? "record",
          record_path: recordPath,
          commit_hash: "sha256:model-mount-record-commit",
        },
        storage_record: {
          record_path: recordPath,
          object_ref: `agentgres://model-mounting/records/${recordPath}`,
          content_hash: "sha256:model-mount-record-content",
          payload_refs: [`payload://model-mounting/records/${recordPath}`],
          receipt_refs: request.receipt_refs ?? [],
          admission: { admission_hash: "sha256:model-mount-record-admission" },
        },
        record_id: request.record_id ?? "record",
        object_ref: `agentgres://model-mounting/records/${recordPath}`,
        content_hash: "sha256:model-mount-record-content",
        admission_hash: "sha256:model-mount-record-admission",
        commit_hash: "sha256:model-mount-record-commit",
        written_record: { record_path: recordPath },
        evidence_refs: ["rust_agentgres_runtime_model_mount_record_state_commit"],
      };
    },
    commitRuntimeModelMountReceiptState(stateDir, request) {
      calls.push({ operation: "commit_runtime_model_mount_receipt_state", stateDir, input: request });
      const receiptId = request.receipt_id ?? "receipt";
      const recordPath = `receipts/${receiptId}.json`;
      writeCommittedRecord(stateDir, recordPath, request.receipt ?? request);
      return {
        source: "rust_agentgres_runtime_model_mount_receipt_state_commit_command",
        backend: "rust_agentgres_storage",
        record: {
          schema_version: "ioi.runtime_model_mount_receipt_state_commit.v1",
          receipt_id: receiptId,
          operation_kind: request.operation_kind,
          record: {
            record_path: recordPath,
            object_ref: `agentgres://model-mounting/receipts/${receiptId}/records/${recordPath}`,
            content_hash: "sha256:model-mount-receipt-content",
            payload_refs: [`payload://model-mounting/receipts/${receiptId}/records/${recordPath}`],
            receipt_refs: request.receipt_refs ?? [],
            admission: { admission_hash: "sha256:model-mount-receipt-admission" },
          },
          commit_hash: "sha256:model-mount-receipt-commit",
        },
        storage_record: {
          record_path: recordPath,
          object_ref: `agentgres://model-mounting/receipts/${receiptId}/records/${recordPath}`,
          content_hash: "sha256:model-mount-receipt-content",
          payload_refs: [`payload://model-mounting/receipts/${receiptId}/records/${recordPath}`],
          receipt_refs: request.receipt_refs ?? [],
          admission: { admission_hash: "sha256:model-mount-receipt-admission" },
        },
        receipt_id: receiptId,
        object_ref: `agentgres://model-mounting/receipts/${receiptId}/records/${recordPath}`,
        content_hash: "sha256:model-mount-receipt-content",
        admission_hash: "sha256:model-mount-receipt-admission",
        commit_hash: "sha256:model-mount-receipt-commit",
        written_record: { record_path: recordPath },
        evidence_refs: ["rust_agentgres_runtime_model_mount_receipt_state_commit"],
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

function modelMountAdmissionRunnerForTest(calls) {
  return {
    admitRouteDecision(request) {
      calls.push({ operation: "admit_model_mount_route_decision", input: request });
      return {
        source: "rust_model_mount_route_decision_test",
        backend: "rust_model_mount_live",
        record: {
          ...request,
          route_decision_ref: `model_mount://route_decision/${request.route_ref ?? "route"}`,
          route_decision_hash: `sha256:route-decision:${request.route_ref ?? "route"}`,
          receipt_refs: request.receipt_refs ?? [],
        },
        route_decision_ref: `model_mount://route_decision/${request.route_ref ?? "route"}`,
        route_decision_hash: `sha256:route-decision:${request.route_ref ?? "route"}`,
        receipt_refs: request.receipt_refs ?? [],
        evidence_refs: ["rust_model_mount_core"],
      };
    },
    planProviderLifecycle(request) {
      calls.push({ operation: "plan_model_mount_provider_lifecycle", input: request });
      const action = request.action ?? "load";
      const status = request.target_status ?? (action === "unload" ? "unloaded" : "loaded");
      return {
        source: "rust_model_mount_provider_lifecycle_test",
        backend: request.execution_backend ?? "rust_model_mount_fixture_lifecycle",
        status,
        backendId: request.backend_ref ?? "backend.runtime-control-test",
        providerBackend: request.provider_backend ?? "local_folder",
        driver: request.driver ?? "fixture",
        executionBackend: request.execution_backend ?? "rust_model_mount_fixture_lifecycle",
        lifecycle_hash: `provider_lifecycle_${action}_${status}`,
        evidence_refs: [`model_mount://provider_lifecycle/${action}/${status}`],
        backendEvidenceRefs: [`model_mount://provider_lifecycle/${action}/${status}`],
        result: {
          action,
          status,
          backend_id: request.backend_ref ?? "backend.runtime-control-test",
          backend: request.provider_backend ?? "local_folder",
          driver: request.driver ?? "fixture",
          execution_backend: request.execution_backend ?? "rust_model_mount_fixture_lifecycle",
          lifecycle_hash: `provider_lifecycle_${action}_${status}`,
          evidence_refs: [`model_mount://provider_lifecycle/${action}/${status}`],
        },
      };
    },
    planInstanceLifecycle(request) {
      calls.push({ operation: "plan_model_mount_instance_lifecycle", input: request });
      const action = request.action ?? "load";
      const status = request.target_status ?? (action === "unload" ? "unloaded" : "loaded");
      return {
        source: "rust_model_mount_instance_lifecycle_test",
        backend: request.execution_backend ?? "rust_model_mount_instance_lifecycle",
        action,
        status,
        backendId: request.backend_ref ?? "backend.runtime-control-test",
        driver: request.driver ?? "fixture",
        executionBackend: request.execution_backend ?? "rust_model_mount_instance_lifecycle",
        provider_lifecycle_hash: request.provider_lifecycle_hash ?? `provider_lifecycle_${action}_${status}`,
        instance_lifecycle_hash: `instance_lifecycle_${action}_${status}`,
        evidence_refs: [
          "rust_model_mount_instance_lifecycle",
          `model_mount://instance_lifecycle/${action}/${status}`,
        ],
        backendEvidenceRefs: [
          "rust_model_mount_instance_lifecycle",
          `model_mount://instance_lifecycle/${action}/${status}`,
        ],
        result: {
          action,
          status,
          backend_id: request.backend_ref ?? "backend.runtime-control-test",
          driver: request.driver ?? "fixture",
          execution_backend: request.execution_backend ?? "rust_model_mount_instance_lifecycle",
          provider_lifecycle_hash: request.provider_lifecycle_hash ?? `provider_lifecycle_${action}_${status}`,
          instance_lifecycle_hash: `instance_lifecycle_${action}_${status}`,
          evidence_refs: [
            "rust_model_mount_instance_lifecycle",
            `model_mount://instance_lifecycle/${action}/${status}`,
          ],
        },
      };
    },
  };
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
    contextPolicyRunner: contextPolicyRunner(calls),
    runtimeAgentgresAdmissionRunner: runtimeAgentgresAdmissionRunner(calls),
    modelMountAdmissionRunner: modelMountAdmissionRunnerForTest(calls),
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
      managed_session_id: managedState.managedSessionId,
      action: "take_over",
      reason: "operator takes over manual authentication handoff fixture",
    });
    assert.equal(takeover.action, "take_over_session");
    assert.equal(takeover.inspection.managed_sessions.sessions[0].control_state, "take_over");

    store.close();
    store = new AgentgresRuntimeStateStore(stateDir, {
      cwd: stateDir,
      contextPolicyRunner: contextPolicyRunner(calls),
      runtimeAgentgresAdmissionRunner: runtimeAgentgresAdmissionRunner(calls),
      modelMountAdmissionRunner: modelMountAdmissionRunnerForTest(calls),
      runtimeBridge: managedSessionReconnectBridge(calls, managedState),
    });

    const replayedAfterReconnect = await store.inspectManagedSessionsForThread(thread.thread_id);
    assert.equal(replayedAfterReconnect.session_id, managedState.runtimeSessionId);
    assert.equal(replayedAfterReconnect.managed_sessions.sessions[0].id, managedState.managedSessionId);
    assert.equal(replayedAfterReconnect.managed_sessions.sessions[0].control_state, "take_over");
    assert.equal(replayedAfterReconnect.managed_sessions.sessions[0].waiting_for_user, true);
    assert.equal(replayedAfterReconnect.managed_sessions.replay.source, "persisted_runtime_service_state");

    const returned = await store.controlManagedSessionForThread(thread.thread_id, {
      managed_session_id: managedState.managedSessionId,
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
      contextPolicyRunner: contextPolicyRunner(calls),
      runtimeAgentgresAdmissionRunner: runtimeAgentgresAdmissionRunner(calls),
      modelMountAdmissionRunner: modelMountAdmissionRunnerForTest(calls),
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
        managed_session_id: managedState.managedSessionId,
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
      contextPolicyRunner: contextPolicyRunner(calls),
      runtimeAgentgresAdmissionRunner: runtimeAgentgresAdmissionRunner(calls),
      modelMountAdmissionRunner: modelMountAdmissionRunnerForTest(calls),
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
        managed_session_id: managedState.managedSessionId,
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
    modelMountAdmissionRunner: modelMountAdmissionRunnerForTest(calls),
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
      workflowGraphId: "graph_retired",
      workflowNodeId: "node_retired",
      requestedBy: "operator_retired",
      runtimeControlAction: "cancel",
      controlAction: "cancel",
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
    const interruptEvent = interrupted.events.find((event) => event.event_kind === "turn.interrupted");
    assert.equal(interruptEvent.workflow_graph_id, null);
    assert.equal(interruptEvent.workflow_node_id, "runtime.operator-interrupt");
    assert.equal(interruptEvent.payload.requested_by, "operator");
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
    modelMountAdmissionRunner: modelMountAdmissionRunnerForTest(calls),
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
      idempotencyKey: "operator_steer_idempotency_retired",
      workflowGraphId: "graph_retired",
      workflowNodeId: "node_retired",
      requestedBy: "operator_retired",
    });

    const plannerCalls = calls.filter((call) => call.operation === "plan_operator_steer_state_update");
    assert.equal(plannerCalls.length, 1);
    assert.equal(plannerCalls[0].input.thread_id, thread.thread_id);
    assert.equal(plannerCalls[0].input.turn_id, turnId);
    assert.equal(plannerCalls[0].input.run_id, run.id);
    assert.equal(plannerCalls[0].input.guidance, "focus on the failing bridge assertion");
    const steerEvent = steered.events.find((event) => event.event_kind === "turn.steered");
    assert.ok(steerEvent);
    assert.equal(
      steerEvent.idempotency_key,
      `turn:${turnId}:operator.steer:1edfd37d46c5349e`,
    );
    assert.equal(steerEvent.workflow_graph_id, null);
    assert.equal(steerEvent.workflow_node_id, "runtime.operator-steer");
    assert.equal(steerEvent.payload.requested_by, "operator");

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

test("runtime-backed operator controls fail closed without Rust-planned runs", async () => {
  const interruptStateDir = mkdtempSync(join(tmpdir(), "ioi-runtime-thread-interrupt-plan-"));
  const interruptCalls = [];
  const interruptStore = new AgentgresRuntimeStateStore(interruptStateDir, {
    cwd: interruptStateDir,
    contextPolicyRunner: contextPolicyRunner(interruptCalls, {
      interruptStateUpdate: { status: "planned", operation_kind: "turn.interrupt", run: null },
    }),
    runtimeAgentgresAdmissionRunner: runtimeAgentgresAdmissionRunner(interruptCalls),
    modelMountAdmissionRunner: modelMountAdmissionRunnerForTest(interruptCalls),
    runtimeBridge: runtimeControlBridge(interruptCalls),
  });
  try {
    await seedRuntimeControlModelRoute(interruptStore);
    const thread = await interruptStore.createThread({
      runtime_profile: "runtime_service",
      options: { runtime_profile: "runtime_service", local: { cwd: interruptStateDir } },
    });
    const run = interruptStore.createRun(thread.agent_id, {
      mode: "send",
      prompt: "exercise failed interrupt planner",
    });
    const turnId = `turn_${run.id.slice("run_".length)}`;

    await assert.rejects(
      () => interruptStore.interruptTurn(thread.thread_id, turnId, { reason: "operator_stop" }),
      (error) => error.code === "operator_control_state_update_planner_invalid",
    );
    assert.equal(
      interruptCalls.some(
        (call) => call.operation === "commit_runtime_run_state" && call.input.operation_kind === "turn.interrupt",
      ),
      false,
    );
  } finally {
    interruptStore.close();
    rmSync(interruptStateDir, { recursive: true, force: true });
  }

  const steerStateDir = mkdtempSync(join(tmpdir(), "ioi-runtime-thread-steer-plan-"));
  const steerCalls = [];
  const steerStore = new AgentgresRuntimeStateStore(steerStateDir, {
    cwd: steerStateDir,
    contextPolicyRunner: contextPolicyRunner(steerCalls, {
      steerStateUpdate: { status: "planned", operation_kind: "turn.steer", run: null },
    }),
    runtimeAgentgresAdmissionRunner: runtimeAgentgresAdmissionRunner(steerCalls),
    modelMountAdmissionRunner: modelMountAdmissionRunnerForTest(steerCalls),
    runtimeBridge: runtimeControlBridge(steerCalls),
  });
  try {
    await seedRuntimeControlModelRoute(steerStore);
    const thread = await steerStore.createThread({
      runtime_profile: "runtime_service",
      options: { runtime_profile: "runtime_service", local: { cwd: steerStateDir } },
    });
    const run = steerStore.createRun(thread.agent_id, {
      mode: "send",
      prompt: "exercise failed steer planner",
    });
    const turnId = `turn_${run.id.slice("run_".length)}`;

    assert.throws(
      () => steerStore.steerTurn(thread.thread_id, turnId, { guidance: "stay fail-closed" }),
      (error) => error.code === "operator_control_state_update_planner_invalid",
    );
    assert.equal(
      steerCalls.some(
        (call) => call.operation === "commit_runtime_run_state" && call.input.operation_kind === "turn.steer",
      ),
      false,
    );
  } finally {
    steerStore.close();
    rmSync(steerStateDir, { recursive: true, force: true });
  }
});

test("runtime-backed operator controls fail closed without Rust-planned operation kinds", async () => {
  const interruptStateDir = mkdtempSync(join(tmpdir(), "ioi-runtime-thread-interrupt-kind-"));
  const interruptCalls = [];
  const interruptStore = new AgentgresRuntimeStateStore(interruptStateDir, {
    cwd: interruptStateDir,
    contextPolicyRunner: contextPolicyRunner(interruptCalls, {
      interruptStateUpdate: {
        status: "planned",
        operation_kind: null,
        run: {
          id: "run_interrupt_missing_kind",
          agentId: "agent_missing_kind",
          status: "canceled",
          turnStatus: "interrupted",
        },
      },
    }),
    runtimeAgentgresAdmissionRunner: runtimeAgentgresAdmissionRunner(interruptCalls),
    modelMountAdmissionRunner: modelMountAdmissionRunnerForTest(interruptCalls),
    runtimeBridge: runtimeControlBridge(interruptCalls),
  });
  try {
    await seedRuntimeControlModelRoute(interruptStore);
    const thread = await interruptStore.createThread({
      runtime_profile: "runtime_service",
      options: { runtime_profile: "runtime_service", local: { cwd: interruptStateDir } },
    });
    const run = interruptStore.createRun(thread.agent_id, {
      mode: "send",
      prompt: "exercise missing interrupt operation kind",
    });
    const turnId = `turn_${run.id.slice("run_".length)}`;

    await assert.rejects(
      () => interruptStore.interruptTurn(thread.thread_id, turnId, { reason: "operator_stop" }),
      (error) => {
        assert.equal(error.code, "operator_control_state_update_operation_kind_missing");
        assert.equal(error.details.operationKind, "turn.interrupt");
        return true;
      },
    );
    assert.equal(
      interruptCalls.some(
        (call) => call.operation === "commit_runtime_run_state" && call.input.operation_kind === "turn.interrupt",
      ),
      false,
    );
    assert.equal(interruptStore.getRun(run.id).id, run.id);
    assert.equal(interruptStore.runs.has("run_interrupt_missing_kind"), false);
  } finally {
    interruptStore.close();
    rmSync(interruptStateDir, { recursive: true, force: true });
  }

  const steerStateDir = mkdtempSync(join(tmpdir(), "ioi-runtime-thread-steer-kind-"));
  const steerCalls = [];
  const steerStore = new AgentgresRuntimeStateStore(steerStateDir, {
    cwd: steerStateDir,
    contextPolicyRunner: contextPolicyRunner(steerCalls, {
      steerStateUpdate: {
        status: "planned",
        operation_kind: null,
        run: {
          id: "run_steer_missing_kind",
          agentId: "agent_missing_kind",
          status: "running",
          turnStatus: "running",
        },
      },
    }),
    runtimeAgentgresAdmissionRunner: runtimeAgentgresAdmissionRunner(steerCalls),
    modelMountAdmissionRunner: modelMountAdmissionRunnerForTest(steerCalls),
    runtimeBridge: runtimeControlBridge(steerCalls),
  });
  try {
    await seedRuntimeControlModelRoute(steerStore);
    const thread = await steerStore.createThread({
      runtime_profile: "runtime_service",
      options: { runtime_profile: "runtime_service", local: { cwd: steerStateDir } },
    });
    const run = steerStore.createRun(thread.agent_id, {
      mode: "send",
      prompt: "exercise missing steer operation kind",
    });
    const turnId = `turn_${run.id.slice("run_".length)}`;

    assert.throws(
      () => steerStore.steerTurn(thread.thread_id, turnId, { guidance: "stay fail-closed" }),
      (error) => {
        assert.equal(error.code, "operator_control_state_update_operation_kind_missing");
        assert.equal(error.details.operationKind, "turn.steer");
        return true;
      },
    );
    assert.equal(
      steerCalls.some(
        (call) => call.operation === "commit_runtime_run_state" && call.input.operation_kind === "turn.steer",
      ),
      false,
    );
    assert.equal(steerStore.getRun(run.id).id, run.id);
    assert.equal(steerStore.runs.has("run_steer_missing_kind"), false);
  } finally {
    steerStore.close();
    rmSync(steerStateDir, { recursive: true, force: true });
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
    modelMountAdmissionRunner: modelMountAdmissionRunnerForTest(calls),
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
    const agent = store.getAgent(thread.agent_id);
    agent.runtimeControls = {
      ...agent.runtimeControls,
      approvalMode: "never_prompt",
      approval_mode: "human_required",
    };
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
    assert.equal(interrupted.approval_mode, "human_required");
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
  const calls = [];
  const store = new AgentgresRuntimeStateStore(stateDir, {
    cwd: stateDir,
    contextPolicyRunner: contextPolicyRunner(calls),
    runtimeAgentgresAdmissionRunner: runtimeAgentgresAdmissionRunner(calls),
    modelMountAdmissionRunner: modelMountAdmissionRunnerForTest(calls),
  });
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
        budget: { max_input_tokens: 1 },
        budget_usage_telemetry: { cumulative_input_tokens: 10 },
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
      budget: { max_input_tokens: 10000 },
    });
    assert.equal(resumed.subagent.restart_status, "restarted");
    assert.notEqual(resumed.subagent.lifecycle_status, "blocked");

    const reloaded = new AgentgresRuntimeStateStore(stateDir, {
      cwd: stateDir,
      contextPolicyRunner: contextPolicyRunner(calls),
      runtimeAgentgresAdmissionRunner: runtimeAgentgresAdmissionRunner(calls),
      modelMountAdmissionRunner: modelMountAdmissionRunnerForTest(calls),
    });
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
