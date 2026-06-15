import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { startRuntimeDaemonService } from "./index.mjs";

async function fetchJson(url, options = {}) {
  const response = await fetch(url, {
    headers: { "content-type": "application/json" },
    ...options,
  });
  const text = await response.text();
  const body = text ? JSON.parse(text) : null;
  assert.ok(response.ok, `${response.status} ${response.statusText} for ${url}: ${text}`);
  return body;
}

function wait(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function restoreEnv(name, value) {
  if (value === undefined) {
    delete process.env[name];
  } else {
    process.env[name] = value;
  }
}

function modelMountCoreForApprovalLeaseTest() {
  return {
    planReadProjection(request) {
      const projection = { source: "agentgres_model_mounting_projection" };
      return {
        source: "rust_daemon_core.model_mount.read_projection",
        projection_kind: request.projection_kind,
        projection,
        evidence_refs: [
          "rust_daemon_core_model_mount_projection",
          "agentgres_model_mount_read_truth",
          "model_mount_js_read_projection_authoring_retired",
        ],
      };
    },
  };
}

function runtimeAgentgresAdmissionCoreForApprovalLeaseTest() {
  function writeCommittedRecord(stateDir, recordPath, value) {
    const targetPath = path.join(stateDir, recordPath);
    fs.mkdirSync(path.dirname(targetPath), { recursive: true });
    fs.writeFileSync(targetPath, `${JSON.stringify(value, null, 2)}\n`);
  }

  return {
    projectRuntimeThreadEvents(request) {
      return {
        source: "rust_runtime_thread_event_projection_protocol",
        backend: "rust_runtime_agentgres",
        projected: true,
        projection_kind: request.projection_kind,
        events: [],
        admissions: [],
        event_count: 0,
        skipped_count: 0,
        projection_hash: "sha256:approval-lease-thread-projection",
      };
    },
    projectRuntimeThreadTurnProjection(request) {
      return {
        source: "rust_runtime_thread_turn_projection_protocol",
        backend: "rust_runtime_agentgres",
        projected: true,
        record: {
          thread_id: request.thread_id,
          turn_id: request.turn_id,
          status: "projected",
        },
        projection_hash: "sha256:approval-lease-turn-projection",
      };
    },
    admitRuntimeThreadEvent(request) {
      return {
        source: "rust_runtime_thread_event_admission_protocol",
        backend: "rust_runtime_agentgres",
        admitted: true,
        event: {
          ...(request.event ?? {}),
          event_id: request.event?.event_id ?? `event_${Date.now()}`,
          seq: request.latest_seq + 1,
        },
        admission_hash: "sha256:approval-lease-thread-event-admission",
      };
    },
    admitCodingToolResultEvent(request) {
      return {
        source: "rust_coding_tool_result_event_admission_protocol",
        backend: "rust_runtime_agentgres",
        admitted: true,
        event: {
          ...(request.event ?? {}),
          event_id: request.event?.event_id ?? `event_${Date.now()}`,
          seq: request.latest_seq + 1,
        },
        admission_hash: "sha256:approval-lease-coding-tool-event-admission",
      };
    },
    commitRuntimeAgentState(stateDir, request) {
      const recordPath = `agents/${request.agent_id}.json`;
      writeCommittedRecord(stateDir, recordPath, request.agent ?? request);
      return {
        source: "rust_agentgres_runtime_agent_state_commit_protocol",
        agent_id: request.agent_id,
        object_ref: `agentgres://runtime-state/agents/${request.agent_id}/records/${recordPath}`,
        content_hash: "sha256:approval-lease-agent-content",
        admission_hash: "sha256:approval-lease-agent-admission",
        commit_hash: "sha256:approval-lease-agent-commit",
        written_record: { record_path: recordPath },
        evidence_refs: ["rust_agentgres_runtime_agent_state_commit"],
      };
    },
    commitRuntimeRunState(stateDir, request) {
      const recordPath = `runs/${request.run_id}.json`;
      writeCommittedRecord(stateDir, recordPath, request.run ?? request);
      return {
        source: "rust_agentgres_runtime_run_state_commit_protocol",
        operation_ref: `agentgres://runtime-state/runs/${request.run_id}/operations/${request.operation_kind}_approval_lease_test`,
        state_root_after: "sha256:approval-lease-state-root-after",
        resulting_head: `agentgres://runtime-state/runs/${request.run_id}/head/approval-lease-test`,
        transition_hash: "sha256:approval-lease-transition",
        materialization_hash: "sha256:approval-lease-materialization",
        write_set_hash: "sha256:approval-lease-write-set",
        persistence_hash: "sha256:approval-lease-persistence",
        commit_hash: "sha256:approval-lease-run-commit",
        written_records: [recordPath],
        evidence_refs: ["rust_agentgres_runtime_run_state_commit"],
      };
    },
  };
}

function daemonCoreFixtureForApprovalLeaseTest() {
  const approvalLeases = new Map();

  function approvalIdFor(request = {}) {
    return (
      optionalString(request.approval_id) ??
      optionalString(request.approval_manifest?.approval_id) ??
      `approval_${safeId(request.tool_call_id ?? "coding_tool")}`
    );
  }

  function leaseForApproval(approvalId) {
    const existing = approvalLeases.get(approvalId);
    if (existing) return existing;
    const lease = {
      schema_version: "ioi.runtime.approval-lease.v1",
      lease_id: `approval_lease_${safeId(approvalId)}`,
      approval_id: approvalId,
      status: "active",
      expires_at: new Date(Date.now() + 1200).toISOString(),
    };
    approvalLeases.set(approvalId, lease);
    return lease;
  }

  function approvalStateRecord(operationKind, request = {}) {
    const approvalId = approvalIdFor(request);
    const lease = leaseForApproval(approvalId);
    const decision = request.decision ?? "approve";
    const runId = request.run_id ?? request.approval_request?.run_id ?? "run_approval_lease_expiry";
    return {
      source: "rust_approval_control_api",
      backend: "rust_authority",
      record: {
        object: "ioi.runtime_approval_control",
        status: decision === "approve" ? "approved" : "rejected",
        operation_kind: operationKind,
        target_kind: request.target_kind ?? "run",
        thread_id: request.thread_id,
        run_id: runId,
        approval_id: approvalId,
        decision,
        lease_id: lease.lease_id,
        lease_status: decision === "approve" ? "active" : "denied",
        approval_lease: lease,
        operator_control: {
          control: "approval_decision",
          approval_id: approvalId,
          event_id: request.event_id,
          seq: request.seq,
          lease_id: lease.lease_id,
          lease_status: decision === "approve" ? "active" : "denied",
          approval_lease: lease,
          authority_hash: request.authority_hash ?? null,
          authority_grant_refs: request.authority_grant_refs ?? [],
          authority_receipt_refs: request.authority_receipt_refs ?? [],
          created_at: request.created_at,
        },
        run: {
          id: runId,
          ...(request.run ?? {}),
          trace: {
            ...(request.run?.trace ?? {}),
            approvalDecisions: [
              {
                approval_id: approvalId,
                event_id: request.event_id,
                decision,
                approval_lease: lease,
              },
            ],
          },
        },
      },
    };
  }

  const daemonCoreApprovalApi = {
    planCodingToolApprovalManifest(request = {}) {
        const approvalId = approvalIdFor(request);
        return {
          source: "rust_coding_tool_approval_protocol",
          backend: "rust_authority",
          approval_required: true,
          manifest: {
            schema_version: "ioi.runtime.coding-tool-approval-manifest.v1",
            approval_id: approvalId,
            thread_id: request.thread_id,
            turn_id: request.turn_id ?? null,
            tool_id: request.tool_id,
            tool_call_id: request.tool_call_id,
            effect_class: request.effect_class,
            workflow_graph_id: request.workflow_graph_id,
            workflow_node_id: request.workflow_node_id,
            input_hash: `sha256:${safeId(request.tool_call_id ?? "approval")}`,
            workflow_policy: request.workflow_policy ?? null,
          },
        };
    },
    projectCodingToolApprovalSatisfaction(request = {}) {
        const approvalId = approvalIdFor(request);
        const lease = approvalLeases.get(approvalId) ?? null;
        const expired = lease ? Date.parse(lease.expires_at) <= Date.now() : false;
        return {
          source: "rust_coding_tool_approval_satisfaction_projection_protocol",
          backend: "rust_authority",
          operation_kind: "coding_tool.approval.satisfaction_projection",
          thread_id: request.thread_id,
          approval_id: approvalId,
          approval_request: lease
            ? {
                approval_id: approvalId,
                approval_lease: lease,
              }
            : null,
          latest_decision: lease
            ? {
                approval_id: approvalId,
                event_kind: "approval.approved",
                payload_summary: { approval_lease: lease },
              }
            : null,
          lease_state: lease
            ? {
                ...lease,
                expired,
                status: expired ? "expired" : "active",
              }
            : null,
        };
    },
    planCodingToolApprovalSatisfaction(request = {}) {
        const approvalId = approvalIdFor(request);
        const lease = approvalLeases.get(approvalId) ?? null;
        const expired = lease ? Date.parse(lease.expires_at) <= Date.now() : false;
        const satisfied = Boolean(lease && !expired);
        return {
          source: "rust_coding_tool_approval_satisfaction_protocol",
          backend: "rust_authority",
          operation_kind: "coding_tool.approval.satisfaction",
          status: satisfied ? "satisfied" : "blocked",
          satisfied,
          approval_id: approvalId,
          lease_id: lease?.lease_id ?? null,
          expires_at: lease?.expires_at ?? null,
          reason: satisfied ? "approval_approved" : "approval_required",
          receipt_refs: satisfied ? [`receipt_${safeId(approvalId)}_approved`] : [],
          policy_decision_refs: satisfied ? ["policy_approval_lease_active"] : ["policy_approval_required"],
          record: {
            operation_kind: "coding_tool.approval.satisfaction",
            status: satisfied ? "satisfied" : "blocked",
            satisfied,
            approval_id: approvalId,
            lease_state: lease
              ? {
                  ...lease,
                  expired,
                  status: expired ? "expired" : "active",
                }
              : null,
          },
        };
    },
    planCodingToolApprovalBlock(request = {}) {
        const approvalId = approvalIdFor(request);
        leaseForApproval(approvalId);
        const error = {
          code: "coding_tool_approval_required",
          message: "Coding tool approval is required.",
        };
        return {
          source: "rust_coding_tool_approval_block_protocol",
          backend: "rust_authority",
          status: "blocked",
          operation_kind: "coding_tool.approval.block",
          thread_id: request.thread_id,
          turn_id: request.turn_id ?? null,
          tool_id: request.tool_id,
          tool_call_id: request.tool_call_id,
          workflow_graph_id: request.workflow_graph_id,
          workflow_node_id: request.workflow_node_id,
          approval_id: approvalId,
          reason: "approval_required",
          receipt_refs: [`receipt_${safeId(approvalId)}_block`],
          policy_decision_refs: ["policy_approval_required"],
          result: {
            schema_version: "ioi.runtime.coding-tool-result.v1",
            status: "blocked",
            approval_required: true,
            approval_satisfied: false,
            approval_id: approvalId,
            error,
          },
          event: {
            event_stream_id: `${request.thread_id}:events`,
            thread_id: request.thread_id,
            turn_id: request.turn_id ?? null,
            tool_call_id: request.tool_call_id,
            event_kind: "tool.blocked",
            status: "blocked",
            payload_schema_version: "ioi.runtime.coding-tool-result.v1",
            payload_summary: {
              schema_version: "ioi.runtime.coding-tool-result.v1",
              event_kind: "CodingToolResult",
              tool_name: request.tool_id,
              tool_call_id: request.tool_call_id,
              status: "blocked",
              approval_required: true,
              approval_satisfied: false,
              approval_id: approvalId,
              error,
            },
            receipt_refs: [`receipt_${safeId(approvalId)}_block`],
            artifact_refs: [],
            rollback_refs: [],
          },
          record: {
            schema_version: "ioi.runtime.coding-tool-approval-block-result.v1",
            status: "blocked",
            operation_kind: "coding_tool.approval.block",
            approval_id: approvalId,
          },
        };
    },
    authorizeApprovalRequest(request = {}) {
      const approvalId = approvalIdFor(request);
      return {
        source: "rust_approval_request_authority_protocol",
        backend: "rust_authority",
        status: "issued",
        operation_kind: "approval.request.authority",
        thread_id: request.thread_id,
        approval_id: approvalId,
        target_kind: request.target_kind,
        run_id: request.run_id,
        receipt_refs: request.receipt_refs ?? [],
        authority_receipt_refs: [`receipt://authority/approval-request/${approvalId}`],
        policy_decision_refs: request.policy_decision_refs ?? [],
        direct_truth_write_allowed: false,
        authority_hash: `sha256:${safeId(approvalId)}_request_authority`,
        authority: {
          schema_version: "ioi.runtime.approval-request-authority.v1",
          status: "issued",
          operation_kind: "approval.request.authority",
          approval_id: approvalId,
          authority_receipt_refs: [`receipt://authority/approval-request/${approvalId}`],
          policy_decision_refs: request.policy_decision_refs ?? [],
          direct_truth_write_allowed: false,
          authority_hash: `sha256:${safeId(approvalId)}_request_authority`,
        },
      };
    },
    authorizeApprovalDecision(request = {}) {
        const approvalId = approvalIdFor(request);
        return {
          source: "rust_approval_decision_authority_protocol",
          backend: "rust_authority",
          status: "authorized",
          operation_kind: "approval.decision.authority",
          thread_id: request.thread_id,
          approval_id: approvalId,
          decision: request.decision,
          wallet_network_grant_refs: [`wallet.network://grant/approval/${approvalId}`],
          authority_receipt_refs: [`receipt://wallet.network/approval/${approvalId}`],
          policy_decision_refs: ["policy_wallet_approval"],
          direct_truth_write_allowed: false,
          authority_hash: `sha256:${safeId(approvalId)}_authority`,
          authority: {
            schema_version: "ioi.runtime.approval-decision-authority.v1",
            status: "authorized",
            operation_kind: "approval.decision.authority",
            approval_id: approvalId,
          },
        };
    },
    planApprovalDecisionStateUpdate(request = {}) {
      return approvalStateRecord(`approval.${request.decision ?? "approve"}`, request);
    },
    planApprovalRequestStateUpdate(request = {}) {
      return approvalStateRecord("approval.required", request);
    },
    projectApprovalQueue(request = {}) {
        return {
          source: "rust_approval_queue_projection_protocol",
          backend: "rust_authority",
          operation_kind: "approval.queue_projection",
          thread_id: request.thread_id,
          approvals: [],
          pending_count: 0,
          resolved_count: 0,
        };
    },
  };

  const daemonCoreRuntimeControlApi = {
    planCodingToolResultEnvelope(request = {}) {
      return codingToolResultEnvelopeForApprovalLease(request);
    },
    planPostEditDiagnosticsFeedback() {
      return {
        source: "rust_post_edit_diagnostics_feedback_plan_api",
        backend: "rust_runtime_diagnostics_feedback",
        operation_kind: "runtime.post_edit_diagnostics_feedback",
        status: "skipped",
        skipped: true,
      };
    },
  };

  const daemonCoreWorkloadApi = {
    runCodingToolStepModule(request = {}) {
      return codingToolStepModuleResultForApprovalLease(request);
    },
  };

  return { daemonCoreRuntimeControlApi, daemonCoreWorkloadApi, daemonCoreApprovalApi };
}

function codingToolResultEnvelopeForApprovalLease(request = {}) {
  if (request.phase === "step_module_context") {
    return {
      source: "rust_coding_tool_result_envelope_plan_command",
      backend: "rust_runtime_coding_tool_event",
      operation_kind: "runtime.coding_tool.result_envelope",
      status: "planned",
      phase: "step_module_context",
      step_module_context: {
        workflow_projection_status: "live",
        thread_id: request.thread_id,
        turn_id: request.turn_id ?? null,
        tool_id: request.tool_id,
        tool_call_id: request.tool_call_id,
        workspace_root: request.workspace_root,
        workflow_graph_id: request.workflow_graph_id,
        workflow_node_id: request.workflow_node_id,
        approval_ref: request.approval_id ?? null,
        receipt_refs: request.receipt_refs ?? [],
        artifact_refs: request.artifact_refs ?? [],
      },
      envelope_hash: `sha256:${safeId(request.tool_call_id ?? "step_module_context")}`,
    };
  }
  const status = request.status ?? "completed";
  return {
    source: "rust_coding_tool_result_envelope_plan_command",
    backend: "rust_runtime_coding_tool_event",
    operation_kind: "runtime.coding_tool.result_envelope",
    status: "planned",
    phase: "result_event",
    event: {
      event_stream_id: request.event_stream_id,
      thread_id: request.thread_id,
      turn_id: request.turn_id ?? null,
      tool_call_id: request.tool_call_id,
      event_kind: status === "completed" ? "tool.completed" : "tool.failed",
      status,
      payload_schema_version: "ioi.runtime.coding-tool-result.v1",
      payload_summary: {
        schema_version: "ioi.runtime.coding-tool-result.v1",
        event_kind: "CodingToolResult",
        tool_name: request.tool_id,
        tool_call_id: request.tool_call_id,
        status,
        approval_required: request.approval_required,
        approval_satisfied: request.approval_satisfied,
        approval_id: request.approval_id,
        error: request.error ?? null,
      },
      receipt_refs: request.receipt_refs ?? [],
      artifact_refs: request.artifact_refs ?? [],
      rollback_refs: request.rollback_refs ?? [],
    },
    envelope_hash: `sha256:${safeId(request.tool_call_id ?? "result_event")}`,
  };
}

function codingToolStepModuleResultForApprovalLease(request = {}) {
  return {
    source: "rust_workload_api",
    invocation: {
      schema_version: "ioi.step_module_invocation.v1",
      invocation_id: `invocation://approval-lease/${safeId(request.tool_id)}`,
      module_ref: {
        kind: "workload_job",
        id: request.tool_id,
        version: "ioi.runtime.coding-tool-pack.v1",
      },
      execution: { backend: "workload_grpc" },
    },
    result: {
      schema_version: "ioi.step_module_result.v1",
      status: "success",
      execution_result_ref: `result://approval-lease/${safeId(request.tool_id)}`,
      normalized_observation_ref: `observation://approval-lease/${safeId(request.tool_id)}`,
      receipt_refs: [`receipt_${safeId(request.tool_id)}_step_module`],
      artifact_refs: [],
      payload_refs: [],
    },
    workload_observation: {
      tool_id: request.tool_id,
      result: {
        schema_version: "ioi.runtime.coding-tool-result.v1",
        tool_name: request.tool_id,
        status: "completed",
        applied: false,
        dry_run: true,
        changed_files: [],
        receipt_refs: [`receipt_${safeId(request.tool_id)}_step_module`],
        artifact_refs: [],
      },
    },
    receipt_refs: [`receipt_${safeId(request.tool_id)}_step_module`],
    evidence_refs: ["rust_workload_step_module_fixture"],
  };
}

function optionalString(value) {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return trimmed || null;
}

function safeId(value) {
  return String(value ?? "runtime").replace(/[^a-zA-Z0-9_.-]+/g, "_");
}

test("coding tool approval leases stop satisfying retries after expiry", async () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-approval-lease-expiry-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-approval-lease-expiry-state-"));
  const targetPath = path.join(cwd, "lease.txt");
  fs.writeFileSync(targetPath, "lease before\n", "utf8");
  const previousFixtureEnv = process.env.IOI_EXPOSE_INTERNAL_FIXTURE_MODELS;
  process.env.IOI_EXPOSE_INTERNAL_FIXTURE_MODELS = "1";
  let daemon;

  try {
    const {
      daemonCoreRuntimeControlApi,
      daemonCoreWorkloadApi,
      daemonCoreApprovalApi,
    } = daemonCoreFixtureForApprovalLeaseTest();
    daemon = await startRuntimeDaemonService({
      cwd,
      stateDir,
      daemonCoreRuntimeControlApi,
      daemonCoreWorkloadApi,
      daemonCoreApprovalApi,
      modelMountCore: modelMountCoreForApprovalLeaseTest(),
      runtimeAgentgresAdmissionCore: runtimeAgentgresAdmissionCoreForApprovalLeaseTest(),
    });
    const now = new Date().toISOString();
    const agent = {
      id: "agent_approval_lease_expiry",
      status: "active",
      runtime: "agent",
      cwd,
      modelId: "autopilot:native-fixture",
      requestedModelId: "auto",
      modelRouteId: "route.native-local",
      modelRouteEndpointId: null,
      modelRouteProviderId: null,
      modelRouteReceiptId: null,
      modelRouteDecision: null,
      runtimeControls: {
        mode: "yolo",
        approvalMode: "never_prompt",
        model: { id: "auto", routeId: "route.native-local" },
      },
      mcpRegistry: null,
      createdAt: now,
      updatedAt: now,
      options: { local: { cwd }, model: { id: "auto", routeId: "route.native-local" } },
    };
    daemon.store.agents.set(agent.id, agent);
    daemon.store.writeAgent(agent, "agent.create.approval-lease-expiry-test");
    const thread = daemon.store.threadForAgent(agent);
    const run = {
      id: "run_approval_lease_expiry",
      agentId: agent.id,
      status: "running",
      mode: "send",
      objective: "Approval lease expiry probe",
      createdAt: now,
      updatedAt: now,
      trace: {},
      events: [],
      receipts: [],
      artifacts: [],
      runtimeTurnId: "turn_approval_lease_expiry",
    };
    daemon.store.runs.set(run.id, run);
    daemon.store.writeRun(run, "run.create.approval-lease-expiry-test");
    const toolEndpoint = `${daemon.endpoint}/v1/threads/${thread.thread_id}/tools/file.apply_patch/invoke`;
    const ttlMs = 1200;
    const request = {
      source: "react_flow",
      workflow_graph_id: "workflow.runtime-daemon.approval-lease-expiry",
      workflow_node_id: "workflow.approval-lease.file.apply-patch",
      tool_call_id: "coding_tool_approval_lease_expiry_probe",
      ttl_ms: ttlMs,
      requires_approval: true,
      approval_mode: "human_required",
      node_approval_override: "require_approval",
      trust_profile: "review_required",
      tool_pack: {
        coding: {
          requires_approval: true,
          approval_mode: "human_required",
          node_approval_override: "require_approval",
          trust_profile: "review_required",
        },
      },
      input: {
        path: "lease.txt",
        old_text: "lease before",
        new_text: "lease after",
        dry_run: true,
      },
    };

    const blocked = await fetchJson(toolEndpoint, {
      method: "POST",
      body: JSON.stringify({
        ...request,
        idempotency_key: "approval-lease-expiry-blocked",
      }),
    });
    assert.equal(blocked.status, "blocked");
    assert.equal(blocked.approval_required, true);
    assert.equal(fs.readFileSync(targetPath, "utf8"), "lease before\n");

    const approved = await fetchJson(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/approvals/${blocked.approval_id}/approve`,
      {
        method: "POST",
        body: JSON.stringify({
          source: "react_flow",
          workflowGraphId: request.workflowGraphId,
          workflowNodeId: request.workflowNodeId,
          reason: "Approve short-lived lease before expiry.",
        }),
      },
    );
    assert.equal(approved.decision, "approve");
    assert.equal(approved.lease_status, "active");

    const executedBeforeExpiry = await fetchJson(toolEndpoint, {
      method: "POST",
      body: JSON.stringify({
        ...request,
        idempotency_key: "approval-lease-expiry-before",
        approval_id: blocked.approval_id,
      }),
    });
    assert.equal(executedBeforeExpiry.status, "completed");
    assert.equal(executedBeforeExpiry.event.payload_summary.approval_satisfied, true);
    assert.equal(fs.readFileSync(targetPath, "utf8"), "lease before\n");

    const expiresAtMs = Date.parse(approved.approval_lease.expires_at);
    assert.ok(Number.isFinite(expiresAtMs));
    await wait(Math.max(0, expiresAtMs - Date.now()) + 80);

    const blockedAfterExpiry = await fetchJson(toolEndpoint, {
      method: "POST",
      body: JSON.stringify({
        ...request,
        idempotency_key: "approval-lease-expiry-after",
        approval_id: blocked.approval_id,
      }),
    });
    assert.equal(blockedAfterExpiry.status, "blocked");
    assert.equal(blockedAfterExpiry.approval_required, true);
    assert.equal(blockedAfterExpiry.error?.code, "coding_tool_approval_required");
    assert.equal(fs.readFileSync(targetPath, "utf8"), "lease before\n");
  } finally {
    if (daemon) await daemon.close();
    restoreEnv("IOI_EXPOSE_INTERNAL_FIXTURE_MODELS", previousFixtureEnv);
  }
});
