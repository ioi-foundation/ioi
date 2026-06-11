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

function assertNoRetiredOperatorControlDetailAliases(details) {
  for (const key of ["threadId", "runId", "operationKind", "expectedOperationKind"]) {
    assert.equal(Object.hasOwn(details ?? {}, key), false, `${key} detail alias must be absent`);
  }
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
    planReadProjection(request) {
      calls.push({ operation: "plan_model_mount_read_projection", input: request });
      return {
        source: "rust_model_mount_read_projection_command",
        backend: "rust_model_mount_read_projection",
        projection_kind: request.projection_kind,
        projection: { source: "agentgres_model_mounting_projection" },
        evidence_refs: [
          "rust_daemon_core_model_mount_projection",
          "agentgres_model_mount_read_truth",
          "model_mount_js_read_projection_authoring_retired",
        ],
      };
    },
    planRouteControlRequired(request) {
      calls.push({ operation: "plan_model_mount_route_control_required", input: request });
      return {
        source: "rust_model_mount_route_control_required_command",
        backend: "rust_model_mount_route_control_required",
        status: "rust_core_required",
        status_code: 501,
        code: "model_mount_route_control_rust_core_required",
        message: "Model mount route control requires direct Rust daemon-core admission.",
        details: {
          rust_core_boundary: "model_mount.route_control",
          operation: request.operation,
          operation_kind: request.operation_kind,
          evidence_refs: request.evidence_refs ?? [],
        },
      };
    },
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

    const thread = await store.agentRunLifecycleSurface.createThread(store, {
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

    const thread = await daemon.store.agentRunLifecycleSurface.createThread(daemon.store, {
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

test("runtime-backed resume routes through mounted turn surface control_thread", async () => {
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

    const thread = await store.agentRunLifecycleSurface.createThread(store, {
      runtime_profile: "runtime_service",
      options: {
        runtime_profile: "runtime_service",
        local: { cwd: stateDir },
      },
    });
    const resumed = await store.threadTurnSurface.resumeThread(store, thread.thread_id, {
      source: "agent_studio",
      reason: "operator_resume",
    });

    const controls = calls.filter((call) => call.operation === "control_thread");
    assert.equal(controls.length, 1);
    assert.equal(controls[0].input.action, "resume");
    assert.equal(controls[0].input.sessionId, "session_runtime_control_test");
    assert.equal(controls[0].input.threadId, thread.thread_id);
    assert.equal(resumed.runtime_control.action, "resume");
  } finally {
    store.close();
    rmSync(stateDir, { recursive: true, force: true });
  }
});

test("operator turn controls fail closed through mounted turn surface before store delegates or JS planning", async () => {
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

    const thread = await store.agentRunLifecycleSurface.createThread(store, {
      runtime_profile: "runtime_service",
      options: {
        runtime_profile: "runtime_service",
        local: { cwd: stateDir },
      },
    });
    const turnId = "turn_operator_control_required";

    await assert.rejects(
      () => store.threadTurnSurface.interruptTurn(store, thread.thread_id, turnId, {
        runtime_control_action: "cancel",
        controlAction: "cancel",
      }),
      (error) => {
        assert.equal(error.code, "runtime_operator_turn_control_rust_core_required");
        assert.equal(error.details.operation_kind, "turn.interrupt");
        assert.equal(error.details.thread_id, thread.thread_id);
        assert.equal(error.details.turn_id, turnId);
        assertNoRetiredOperatorControlDetailAliases(error.details);
        return true;
      },
    );

    assert.throws(
      () => store.threadTurnSurface.steerTurn(store, thread.thread_id, turnId, {
        guidance: "focus on Rust admission",
      }),
      (error) => {
        assert.equal(error.code, "runtime_operator_turn_control_rust_core_required");
        assert.equal(error.details.operation_kind, "turn.steer");
        assert.equal(error.details.thread_id, thread.thread_id);
        assert.equal(error.details.turn_id, turnId);
        assertNoRetiredOperatorControlDetailAliases(error.details);
        return true;
      },
    );

    assert.equal(typeof store.interruptTurn, "undefined");
    assert.equal(typeof store.steerTurn, "undefined");
    assert.equal(
      calls.some((call) => call.operation === "plan_operator_interrupt_state_update"),
      false,
    );
    assert.equal(
      calls.some((call) => call.operation === "plan_operator_steer_state_update"),
      false,
    );
  } finally {
    store.close();
    rmSync(stateDir, { recursive: true, force: true });
  }
});

test("runtime-backed in-flight turn submission uses mounted turn surface before durable run projection exists", async () => {
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

    const thread = await store.agentRunLifecycleSurface.createThread(store, {
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
    const turnPromise = store.threadTurnSurface.createTurn(store, thread.thread_id, {
      prompt: "exercise in-flight runtime control",
      runtime_profile: "runtime_service",
      options: {
        runtime_profile: "runtime_service",
        local: { cwd: stateDir },
      },
    });

    await liveStarted;
    assert.equal(store.runs.has("run_inflight_runtime_control_test"), false);
    releaseSubmit();
    const completed = await turnPromise;

    const controls = calls.filter((call) => call.operation === "control_thread");
    assert.equal(controls.length, 0);
    assert.equal(completed.turn_id, turnId);
    assert.equal(store.runs.has("run_inflight_runtime_control_test"), true);
    assert.equal(typeof store.createTurn, "undefined");
    assert.equal(typeof store.interruptTurn, "undefined");
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

    const thread = await store.agentRunLifecycleSurface.createThread(store, {
      runtime_profile: "runtime_service",
      options: {
        runtime_profile: "runtime_service",
        local: { cwd: stateDir },
        model: { id: "auto", routeId: "route.local-first" },
      },
    });
    const parentTurnId = "turn_subagent_recovery_parent";

    let blockedError;
    try {
      store.spawnSubagent(thread.thread_id, {
        source: "runtime-subagent-recovery-test",
        role: "failed-child",
        prompt: "This child intentionally exceeds a tiny token budget.",
        parentTurnId,
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
