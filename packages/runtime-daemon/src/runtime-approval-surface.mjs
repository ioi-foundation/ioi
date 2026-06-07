import crypto from "node:crypto";

import {
  eventStreamIdForThread,
  fixtureProfileForAgent,
  runIdForTurn,
  runtimeSessionIdForAgent,
  turnIdForRun,
} from "./runtime-identifiers.mjs";
import { createRuntimeApprovalStateRunnerFromEnv } from "./runtime-approval-state-runner.mjs";
import {
  normalizeArray,
  operatorControlSource,
  optionalString,
  safeId,
  uniqueStrings,
} from "./runtime-value-helpers.mjs";
import { contextBudgetNumber } from "./threads/context-budget-policy.mjs";

function approvalRequiredError(runtimeError, threadId) {
  return runtimeError({
    status: 400,
    code: "approval_id_required",
    message: "Approval decisions require an approval id.",
    details: { threadId },
  });
}

function approvalRevokeRequiredError(runtimeError, threadId) {
  return runtimeError({
    status: 400,
    code: "approval_id_required",
    message: "Approval revocation requires an approval id.",
    details: { threadId },
  });
}

function resolveApprovalTarget(store, agent, threadId, request = {}, fallbackTurnId = "", deps = {}) {
  const { notFound } = deps;
  const runs = store.listRuns(agent.id);
  const requestedTurnId = optionalString(request.turn_id);
  let turnId = requestedTurnId ?? fallbackTurnId ?? "";
  let run = null;
  if (turnId) {
    run = store.getRun(runIdForTurn(turnId));
    if (run.agentId !== agent.id) {
      throw notFound(`Turn not found: ${turnId}`, { threadId, turnId, runId: run.id });
    }
  } else {
    run = runs.at(-1) ?? null;
    turnId = run ? turnIdForRun(run.id) : "";
  }
  return { run, turnId };
}

function requestApprovalManifest(request = {}) {
  if (request.approval_manifest && typeof request.approval_manifest === "object") return request.approval_manifest;
  return null;
}

export function createRuntimeApprovalSurface(deps = {}) {
  const {
    approvalDecisionForRequest,
    approvalLeaseMetadataForRequest,
    approvalLeaseMetadataFromPayload,
    approvalStateRunner: approvalStateRunnerDep = createRuntimeApprovalStateRunnerFromEnv(),
    notFound,
    runtimeError,
  } = deps;

  function latestApprovalRequestEvent(store, threadId, approvalId) {
    const normalizedApprovalId = optionalString(approvalId);
    if (!normalizedApprovalId) return null;
    const stream = store.runtimeEventStream(eventStreamIdForThread(threadId));
    return (
      stream.events
        .filter(
          (event) =>
            event.approval_id === normalizedApprovalId &&
            event.event_kind === "approval.required",
        )
        .at(-1) ?? null
    );
  }

  function latestApprovalDecisionEvent(store, threadId, approvalId) {
    const normalizedApprovalId = optionalString(approvalId);
    if (!normalizedApprovalId) return null;
    const stream = store.runtimeEventStream(eventStreamIdForThread(threadId));
    return (
      stream.events
        .filter(
          (event) =>
            event.approval_id === normalizedApprovalId &&
            (event.event_kind === "approval.approved" ||
              event.event_kind === "approval.rejected" ||
              event.event_kind === "approval.revoked"),
        )
        .at(-1) ?? null
    );
  }

  function plannedApprovalAgentRecord(stateUpdate, threadId, operationKind) {
    const updatedAgent = stateUpdate.agent;
    if (!updatedAgent?.id) {
      throw runtimeError({
        status: 502,
        code: "approval_agent_state_update_planner_invalid",
        message: "Rust approval state planning did not return an agent record.",
        details: { threadId, operationKind },
      });
    }
    return updatedAgent;
  }

  function plannedApprovalRunRecord(stateUpdate, threadId, runId, operationKind) {
    const updatedRun = stateUpdate.run;
    if (!updatedRun?.id) {
      throw runtimeError({
        status: 502,
        code: "approval_run_state_update_planner_invalid",
        message: "Rust approval state planning did not return a run record.",
        details: { threadId, runId, operationKind },
      });
    }
    return updatedRun;
  }

  function requiredApprovalOperationKind(stateUpdate, expectedOperationKind, details = {}) {
    const operationKind = optionalString(stateUpdate.operation_kind);
    if (!operationKind) {
      throw runtimeError({
        status: 502,
        code: "approval_state_update_operation_kind_missing",
        message: "Rust approval state planning did not return an operation kind.",
        details: { ...details, operationKind: expectedOperationKind },
      });
    }
    if (operationKind !== expectedOperationKind) {
      throw runtimeError({
        status: 502,
        code: "approval_state_update_operation_kind_mismatch",
        message: "Rust approval state planning returned an unexpected operation kind.",
        details: {
          ...details,
          expectedOperationKind,
          operationKind,
        },
      });
    }
    return operationKind;
  }

  function requestThreadApproval(store, threadId, request = {}) {
    const agent = store.agentForThread(threadId);
    const { run, turnId } = resolveApprovalTarget(store, agent, threadId, request, "", { notFound });
    const source = operatorControlSource(request.source);
    const requestedBy = optionalString(request.actor ?? request.requested_by) ?? "operator";
    const reason =
      optionalString(request.reason ?? request.message ?? request.input) ??
      "operator requested approval";
    const action =
      optionalString(request.action ?? request.approval_action) ??
      "request_approval";
    const toolId =
      optionalString(request.tool_id ?? request.tool_name) ??
      null;
    const effectClass = optionalString(request.effect_class) ?? null;
    const riskDomain = optionalString(request.risk_domain) ?? null;
    const runOrAgentId = run?.id ?? agent.id;
    const approvalSeed = `${threadId}:${turnId || "thread"}:${reason}`;
    const approvalHash = crypto.createHash("sha256").update(approvalSeed).digest("hex").slice(0, 16);
    const approvalId =
      optionalString(request.approval_id) ??
      `approval_context_pressure_${safeId(threadId)}_${safeId(turnId || "thread")}_${approvalHash}`;
    const workflowNodeId =
      optionalString(request.workflow_node_id) ??
      `runtime.approval.${safeId(approvalId)}`;
    const scope = optionalString(request.scope) ?? "thread";
    const pressure = contextBudgetNumber(
      request.pressure,
      request.context_pressure,
    );
    const pressureStatus =
      optionalString(
        request.pressure_status ??
          request.context_pressure_status,
      ) ?? null;
    const alertId =
      optionalString(request.alert_id ?? request.alert_event_id) ??
      null;
    const sourceEventId = optionalString(request.source_event_id) ?? null;
    const leaseMetadata = approvalLeaseMetadataForRequest({
      request,
      approval_id: approvalId,
      action,
      scope,
      now: new Date().toISOString(),
      thread_id: threadId,
    });
    const receiptRefs = uniqueStrings([
      ...normalizeArray(request.receipt_refs),
      `receipt_${runOrAgentId}_approval_required_${safeId(approvalId)}`,
    ]);
    const policyDecisionRefs = uniqueStrings([
      ...normalizeArray(request.policy_decision_refs),
      `policy_${runOrAgentId}_approval_required`,
    ]);
    const now = leaseMetadata.created_at;
    const event = store.appendRuntimeEvent({
      event_stream_id: eventStreamIdForThread(threadId),
      thread_id: threadId,
      turn_id: turnId,
      item_id: `${turnId || threadId}:item:approval-required:${safeId(approvalId)}`,
      idempotency_key:
        request.idempotency_key ??
        `thread:${threadId}:approval.required:${approvalId}`,
      source,
      source_event_kind: "OperatorApproval.Request",
      event_kind: "approval.required",
      status: "waiting_for_approval",
      actor: "user",
      created_at: now,
      workspace_root: agent.cwd,
      workflow_graph_id: request.workflow_graph_id ?? null,
      workflow_node_id: workflowNodeId,
      component_kind: "approval_gate",
      approval_id: approvalId,
      payload_schema_version: "ioi.runtime.approval-request.v1",
      payload: {
        event_kind: "OperatorApproval.Request",
        approval_id: approvalId,
        approval_required: true,
        reason,
        requested_by: requestedBy,
        control_surface: source,
        action,
        scope,
        tool_id: toolId,
        effect_class: effectClass,
        risk_domain: riskDomain,
        authority_scope_requirements: normalizeArray(
          request.authority_scope_requirements,
        ),
        expected_receipt_refs: leaseMetadata.expected_receipt_refs,
        policy_hash: leaseMetadata.policy_hash,
        ttl_ms: leaseMetadata.ttl_ms,
        expires_at: leaseMetadata.expires_at,
        lease_id: leaseMetadata.lease_id,
        revoke_endpoint: leaseMetadata.revoke_endpoint,
        approval_lease: leaseMetadata,
        approval_manifest: requestApprovalManifest(request),
        pressure: pressure ?? null,
        pressure_status: pressureStatus,
        alert_id: alertId,
        source_event_id: sourceEventId,
        agent_id: agent.id,
        thread_id: threadId,
        turn_id: turnId || null,
        run_id: run?.id ?? null,
        session_id: runtimeSessionIdForAgent(agent),
      },
      receipt_refs: receiptRefs,
      policy_decision_refs: policyDecisionRefs,
      artifact_refs: [],
      rollback_refs: [],
      redaction_profile: "internal",
      fixture_profile: fixtureProfileForAgent(agent),
    });
    if (run) {
      const stateUpdate = approvalStateRunnerDep.planApprovalRequestStateUpdate({
        thread_id: threadId,
        run_id: run.id,
        run,
        event_id: event.event_id,
        seq: event.seq,
        created_at: event.created_at,
        approval_id: approvalId,
        source,
        reason,
        receipt_refs: event.receipt_refs,
        policy_decision_refs: event.policy_decision_refs,
      });
      const operationKind = requiredApprovalOperationKind(stateUpdate, "approval.required", {
        threadId,
        runId: run.id,
        targetKind: "run",
      });
      const updated = plannedApprovalRunRecord(stateUpdate, threadId, run.id, operationKind);
      store.runs.set(run.id, updated);
      store.writeRun(updated, operationKind);
      return {
        ...store.turnForRun(updated),
        approval_id: approvalId,
        approval_required: true,
        event_id: event.event_id,
        seq: event.seq,
        receipt_refs: event.receipt_refs,
        policy_decision_refs: event.policy_decision_refs,
      };
    }

    const stateUpdate = approvalStateRunnerDep.planApprovalRequestStateUpdate({
      target_kind: "agent",
      thread_id: threadId,
      run_id: null,
      run: null,
      agent,
      event_id: event.event_id,
      seq: event.seq,
      created_at: event.created_at,
      approval_id: approvalId,
      source,
      reason,
      receipt_refs: event.receipt_refs,
      policy_decision_refs: event.policy_decision_refs,
    });
    const operationKind = requiredApprovalOperationKind(stateUpdate, "approval.required", {
      threadId,
      agentId: agent.id,
      targetKind: "agent",
    });
    const updatedAgent = plannedApprovalAgentRecord(stateUpdate, threadId, operationKind);
    store.agents.set(updatedAgent.id, updatedAgent);
    store.writeAgent(updatedAgent, operationKind);
    return {
      ...store.threadForAgent(updatedAgent),
      approval_id: approvalId,
      approval_required: true,
      event_id: event.event_id,
      seq: event.seq,
      receipt_refs: event.receipt_refs,
      policy_decision_refs: event.policy_decision_refs,
    };
  }

  function decideThreadApproval(store, threadId, approvalId, request = {}) {
    const agent = store.agentForThread(threadId);
    const normalizedApprovalId =
      optionalString(approvalId ?? request.approval_id) ??
      (() => {
        throw approvalRequiredError(runtimeError, threadId);
      })();
    const decision = approvalDecisionForRequest(request.decision ?? request.action ?? request.status);
    const source = operatorControlSource(request.source);
    const requestedBy = optionalString(request.actor ?? request.requested_by) ?? "operator";
    const reason = optionalString(request.reason ?? request.message ?? request.input) ?? null;
    const { run, turnId } = resolveApprovalTarget(store, agent, threadId, request, "", { notFound });
    const now = new Date().toISOString();
    const status = decision === "approve" ? "approved" : "rejected";
    const decisionVerb = decision === "approve" ? "Approve" : "Reject";
    const approvalRequestEvent = latestApprovalRequestEvent(store, threadId, normalizedApprovalId);
    const approvalRequestPayload = approvalRequestEvent?.payload_summary ?? approvalRequestEvent?.payload ?? {};
    const leaseMetadata = approvalLeaseMetadataFromPayload(
      approvalRequestPayload,
      normalizedApprovalId,
      threadId,
    );
    const leaseStatus = decision === "approve" ? "active" : "denied";
    const approvalLease = {
      ...leaseMetadata,
      status: leaseStatus,
      decision,
      approval_request_event_id: approvalRequestEvent?.event_id ?? null,
      decided_at: now,
    };
    const decisionHash = crypto
      .createHash("sha256")
      .update(`${normalizedApprovalId}:${decision}:${reason ?? ""}:${requestedBy}`)
      .digest("hex")
      .slice(0, 16);
    const workflowNodeId = request.workflow_node_id ?? `runtime.approval.${safeId(normalizedApprovalId)}`;
    const runOrAgentId = run?.id ?? agent.id;
    const event = store.appendRuntimeEvent({
      event_stream_id: eventStreamIdForThread(threadId),
      thread_id: threadId,
      turn_id: turnId,
      item_id: `${turnId || threadId}:item:approval-${decision}:${safeId(normalizedApprovalId)}`,
      idempotency_key:
        request.idempotency_key ??
        `thread:${threadId}:approval.${decision}:${normalizedApprovalId}:${decisionHash}`,
      source,
      source_event_kind: `OperatorApproval.${decisionVerb}`,
      event_kind: `approval.${status}`,
      status,
      actor: "user",
      created_at: now,
      workspace_root: agent.cwd,
      workflow_graph_id: request.workflow_graph_id ?? null,
      workflow_node_id: workflowNodeId,
      component_kind: "approval_gate",
      approval_id: normalizedApprovalId,
      payload_schema_version: "ioi.runtime.approval-decision.v1",
      payload: {
        event_kind: `OperatorApproval.${decisionVerb}`,
        approval_id: normalizedApprovalId,
        decision,
        status,
        reason,
        requested_by: requestedBy,
        control_surface: source,
        action: approvalRequestPayload.action ?? null,
        scope: approvalRequestPayload.scope ?? null,
        tool_id: approvalRequestPayload.tool_id ?? null,
        effect_class: approvalRequestPayload.effect_class ?? null,
        risk_domain: approvalRequestPayload.risk_domain ?? null,
        approval_request_event_id: approvalRequestEvent?.event_id ?? null,
        lease_id: leaseMetadata.lease_id,
        lease_status: leaseStatus,
        policy_hash: leaseMetadata.policy_hash,
        ttl_ms: leaseMetadata.ttl_ms,
        expires_at: leaseMetadata.expires_at,
        expected_receipt_refs: leaseMetadata.expected_receipt_refs,
        authority_scope_requirements: leaseMetadata.authority_scope_requirements,
        revoke_endpoint: leaseMetadata.revoke_endpoint,
        approval_lease: approvalLease,
        approval_manifest: approvalRequestPayload.approval_manifest ?? null,
        agent_id: agent.id,
        thread_id: threadId,
        turn_id: turnId || null,
        run_id: run?.id ?? null,
        session_id: runtimeSessionIdForAgent(agent),
      },
      receipt_refs: [`receipt_${runOrAgentId}_approval_${decision}_${safeId(normalizedApprovalId)}_${decisionHash}`],
      policy_decision_refs: [`policy_${runOrAgentId}_approval_${decision}_allow`],
      artifact_refs: [],
      rollback_refs: [],
      redaction_profile: "internal",
      fixture_profile: fixtureProfileForAgent(agent),
    });
    if (run) {
      const stateUpdate = approvalStateRunnerDep.planApprovalDecisionStateUpdate({
        thread_id: threadId,
        run_id: run.id,
        run,
        event_id: event.event_id,
        seq: event.seq,
        created_at: event.created_at,
        approval_id: normalizedApprovalId,
        lease_id: leaseMetadata.lease_id,
        lease_status: leaseStatus,
        decision,
        status,
        source,
        reason,
        receipt_refs: event.receipt_refs,
        policy_decision_refs: event.policy_decision_refs,
      });
      const expectedOperationKind = `approval.${decision}`;
      const operationKind = requiredApprovalOperationKind(stateUpdate, expectedOperationKind, {
        threadId,
        runId: run.id,
        targetKind: "run",
      });
      const updated = plannedApprovalRunRecord(stateUpdate, threadId, run.id, operationKind);
      store.runs.set(run.id, updated);
      store.writeRun(updated, operationKind);
      return {
        ...store.turnForRun(updated),
        approval_id: normalizedApprovalId,
        lease_id: leaseMetadata.lease_id,
        lease_status: leaseStatus,
        approval_lease: approvalLease,
        decision,
        event_id: event.event_id,
        seq: event.seq,
        receipt_refs: event.receipt_refs,
        policy_decision_refs: event.policy_decision_refs,
      };
    }
    const stateUpdate = approvalStateRunnerDep.planApprovalDecisionStateUpdate({
      target_kind: "agent",
      thread_id: threadId,
      run_id: null,
      run: null,
      agent,
      event_id: event.event_id,
      seq: event.seq,
      created_at: event.created_at,
      approval_id: normalizedApprovalId,
      lease_id: leaseMetadata.lease_id,
      lease_status: leaseStatus,
      decision,
      status,
      source,
      reason,
      receipt_refs: event.receipt_refs,
      policy_decision_refs: event.policy_decision_refs,
    });
    const expectedOperationKind = `approval.${decision}`;
    const operationKind = requiredApprovalOperationKind(stateUpdate, expectedOperationKind, {
      threadId,
      agentId: agent.id,
      targetKind: "agent",
    });
    const updatedAgent = plannedApprovalAgentRecord(stateUpdate, threadId, operationKind);
    store.agents.set(updatedAgent.id, updatedAgent);
    store.writeAgent(updatedAgent, operationKind);
    return {
      ...store.threadForAgent(updatedAgent),
      approval_id: normalizedApprovalId,
      lease_id: leaseMetadata.lease_id,
      lease_status: leaseStatus,
      approval_lease: approvalLease,
      decision,
      event_id: event.event_id,
      seq: event.seq,
      receipt_refs: event.receipt_refs,
      policy_decision_refs: event.policy_decision_refs,
    };
  }

  function revokeThreadApproval(store, threadId, approvalId, request = {}) {
    const agent = store.agentForThread(threadId);
    const normalizedApprovalId =
      optionalString(approvalId ?? request.approval_id) ??
      (() => {
        throw approvalRevokeRequiredError(runtimeError, threadId);
      })();
    const approvalRequestEvent = latestApprovalRequestEvent(store, threadId, normalizedApprovalId);
    if (!approvalRequestEvent) {
      throw notFound(`Approval request not found: ${normalizedApprovalId}`, {
        threadId,
        approvalId: normalizedApprovalId,
      });
    }
    const approvalRequestPayload = approvalRequestEvent.payload_summary ?? approvalRequestEvent.payload ?? {};
    const stream = store.runtimeEventStream(eventStreamIdForThread(threadId));
    const priorDecisionEvent =
      stream.events
        .filter(
          (event) =>
            event.approval_id === normalizedApprovalId &&
            event.seq > approvalRequestEvent.seq &&
            (event.event_kind === "approval.approved" || event.event_kind === "approval.rejected"),
        )
        .at(-1) ?? null;
    const source = operatorControlSource(request.source);
    const requestedBy = optionalString(request.actor ?? request.requested_by) ?? "operator";
    const reason =
      optionalString(request.reason ?? request.message ?? request.input) ??
      "operator revoked approval lease";
    const { run, turnId } = resolveApprovalTarget(
      store,
      agent,
      threadId,
      request,
      approvalRequestEvent.turn_id ?? "",
      { notFound },
    );
    const now = new Date().toISOString();
    const leaseMetadata = approvalLeaseMetadataFromPayload(
      approvalRequestPayload,
      normalizedApprovalId,
      threadId,
    );
    const approvalLease = {
      ...leaseMetadata,
      status: "revoked",
      approval_request_event_id: approvalRequestEvent.event_id,
      approval_decision_event_id: priorDecisionEvent?.event_id ?? null,
      revoked_at: now,
    };
    const revokeHash = crypto
      .createHash("sha256")
      .update(`${normalizedApprovalId}:revoke:${reason}:${requestedBy}`)
      .digest("hex")
      .slice(0, 16);
    const workflowNodeId =
      request.workflow_node_id ??
      approvalRequestEvent.workflow_node_id ??
      `runtime.approval.${safeId(normalizedApprovalId)}`;
    const workflowGraphId =
      request.workflow_graph_id ??
      approvalRequestEvent.workflow_graph_id ??
      null;
    const runOrAgentId = run?.id ?? agent.id;
    const event = store.appendRuntimeEvent({
      event_stream_id: eventStreamIdForThread(threadId),
      thread_id: threadId,
      turn_id: turnId,
      item_id: `${turnId || threadId}:item:approval-revoke:${safeId(normalizedApprovalId)}`,
      idempotency_key:
        request.idempotency_key ??
        `thread:${threadId}:approval.revoke:${normalizedApprovalId}:${revokeHash}`,
      source,
      source_event_kind: "OperatorApproval.Revoke",
      event_kind: "approval.revoked",
      status: "revoked",
      actor: "user",
      created_at: now,
      workspace_root: agent.cwd,
      workflow_graph_id: workflowGraphId,
      workflow_node_id: workflowNodeId,
      component_kind: "approval_gate",
      approval_id: normalizedApprovalId,
      payload_schema_version: "ioi.runtime.approval-revoke.v1",
      payload: {
        event_kind: "OperatorApproval.Revoke",
        approval_id: normalizedApprovalId,
        decision: "revoke",
        status: "revoked",
        reason,
        requested_by: requestedBy,
        control_surface: source,
        action: approvalRequestPayload.action ?? null,
        scope: approvalRequestPayload.scope ?? null,
        tool_id: approvalRequestPayload.tool_id ?? null,
        effect_class: approvalRequestPayload.effect_class ?? null,
        risk_domain: approvalRequestPayload.risk_domain ?? null,
        approval_request_event_id: approvalRequestEvent.event_id,
        approval_decision_event_id: priorDecisionEvent?.event_id ?? null,
        lease_id: leaseMetadata.lease_id,
        lease_status: "revoked",
        policy_hash: leaseMetadata.policy_hash,
        ttl_ms: leaseMetadata.ttl_ms,
        expires_at: leaseMetadata.expires_at,
        expected_receipt_refs: leaseMetadata.expected_receipt_refs,
        authority_scope_requirements: leaseMetadata.authority_scope_requirements,
        revoke_endpoint: leaseMetadata.revoke_endpoint,
        approval_lease: approvalLease,
        approval_manifest: approvalRequestPayload.approval_manifest ?? null,
        agent_id: agent.id,
        thread_id: threadId,
        turn_id: turnId || null,
        run_id: run?.id ?? null,
        session_id: runtimeSessionIdForAgent(agent),
      },
      receipt_refs: [`receipt_${runOrAgentId}_approval_revoke_${safeId(normalizedApprovalId)}_${revokeHash}`],
      policy_decision_refs: [`policy_${runOrAgentId}_approval_revoke`],
      artifact_refs: [],
      rollback_refs: [],
      redaction_profile: "internal",
      fixture_profile: fixtureProfileForAgent(agent),
    });
    if (run) {
      const stateUpdate = approvalStateRunnerDep.planApprovalRevokeStateUpdate({
        thread_id: threadId,
        run_id: run.id,
        run,
        event_id: event.event_id,
        seq: event.seq,
        created_at: event.created_at,
        approval_id: normalizedApprovalId,
        lease_id: leaseMetadata.lease_id,
        source,
        reason,
        receipt_refs: event.receipt_refs,
        policy_decision_refs: event.policy_decision_refs,
      });
      const operationKind = requiredApprovalOperationKind(stateUpdate, "approval.revoke", {
        threadId,
        runId: run.id,
        targetKind: "run",
      });
      const updated = plannedApprovalRunRecord(stateUpdate, threadId, run.id, operationKind);
      store.runs.set(run.id, updated);
      store.writeRun(updated, operationKind);
      return {
        ...store.turnForRun(updated),
        approval_id: normalizedApprovalId,
        lease_id: leaseMetadata.lease_id,
        lease_status: "revoked",
        approval_lease: approvalLease,
        decision: "revoke",
        status: "revoked",
        event_id: event.event_id,
        seq: event.seq,
        receipt_refs: event.receipt_refs,
        policy_decision_refs: event.policy_decision_refs,
      };
    }
    const stateUpdate = approvalStateRunnerDep.planApprovalRevokeStateUpdate({
      target_kind: "agent",
      thread_id: threadId,
      run_id: null,
      run: null,
      agent,
      event_id: event.event_id,
      seq: event.seq,
      created_at: event.created_at,
      approval_id: normalizedApprovalId,
      lease_id: leaseMetadata.lease_id,
      source,
      reason,
      receipt_refs: event.receipt_refs,
      policy_decision_refs: event.policy_decision_refs,
    });
    const operationKind = requiredApprovalOperationKind(stateUpdate, "approval.revoke", {
      threadId,
      agentId: agent.id,
      targetKind: "agent",
    });
    const updatedAgent = plannedApprovalAgentRecord(stateUpdate, threadId, operationKind);
    store.agents.set(updatedAgent.id, updatedAgent);
    store.writeAgent(updatedAgent, operationKind);
    return {
      ...store.threadForAgent(updatedAgent),
      approval_id: normalizedApprovalId,
      lease_id: leaseMetadata.lease_id,
      lease_status: "revoked",
      approval_lease: approvalLease,
      decision: "revoke",
      status: "revoked",
      event_id: event.event_id,
      seq: event.seq,
      receipt_refs: event.receipt_refs,
      policy_decision_refs: event.policy_decision_refs,
    };
  }

  return {
    decideThreadApproval,
    latestApprovalDecisionEvent,
    latestApprovalRequestEvent,
    requestThreadApproval,
    revokeThreadApproval,
  };
}
