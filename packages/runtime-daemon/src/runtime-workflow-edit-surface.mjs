import path from "node:path";

import {
  eventStreamIdForThread,
  fixtureProfileForAgent,
  runIdForTurn,
  runtimeSessionIdForAgent,
  turnIdForRun,
} from "./runtime-identifiers.mjs";
import { notFound, policyError, runtimeError, writeJson } from "./runtime-http-utils.mjs";
import {
  doctorHash,
  normalizeArray,
  operatorControlSource,
  optionalString,
  relativePathForWorkspace,
  safeId,
  uniqueStrings,
} from "./runtime-value-helpers.mjs";

function defaultApprovalReasonForDecisionEvent(event) {
  const payload = event?.payload_summary ?? event?.payload ?? {};
  return optionalString(payload.reason ?? event?.reason) ?? "approval_not_satisfied";
}

export function createRuntimeWorkflowEditSurface(deps = {}) {
  const {
    approvalReasonForDecisionEvent = defaultApprovalReasonForDecisionEvent,
    notFound: notFoundDep = notFound,
    policyError: policyErrorDep = policyError,
    runtimeError: runtimeErrorDep = runtimeError,
    writeJson: writeJsonDep = writeJson,
  } = deps;

  function workflowEditThreadContext(store, threadId, request = {}) {
    const agent = store.agentForThread(threadId);
    const runs = store.listRuns(agent.id);
    const requestedTurnId = optionalString(request.turn_id);
    let turnId = requestedTurnId ?? "";
    let run = null;
    if (turnId) {
      run = store.getRun(runIdForTurn(turnId));
      if (run.agentId !== agent.id) {
        throw notFoundDep(`Turn not found: ${turnId}`, { threadId, turnId, runId: run.id });
      }
    } else {
      run = runs.at(-1) ?? null;
      turnId = run ? turnIdForRun(run.id) : "";
    }
    return { agent, run, turnId };
  }

  function resolveWorkflowEditTarget(agent, request = {}) {
    const rawPath = optionalString(request.workflow_path);
    if (!rawPath) return { workflow_path: null, workflow_relative_path: null };
    const workflowPath = path.resolve(agent.cwd, rawPath);
    const workflowRelativePath = relativePathForWorkspace(workflowPath, agent.cwd);
    if (!workflowRelativePath) {
      throw policyErrorDep("Workflow edit proposals can only target files inside the runtime workspace.", {
        workspaceRoot: agent.cwd,
        workflow_path: workflowPath,
      });
    }
    return { workflow_path: workflowPath, workflow_relative_path: workflowRelativePath };
  }

  function proposeWorkflowEdit(store, threadId, request = {}) {
    const { agent, run, turnId } = workflowEditThreadContext(store, threadId, request);
    const source = operatorControlSource(request.source);
    const requestedBy = optionalString(request.actor ?? request.requested_by) ?? "workflow-author";
    const workflowGraphId = optionalString(request.workflow_graph_id) ?? null;
    const targetWorkflowNodeIds = uniqueStrings(
      [
        ...normalizeArray(request.target_workflow_node_ids),
        ...normalizeArray(request.bounded_targets),
      ]
        .map((value) => optionalString(value))
        .filter(Boolean),
    );
    const title =
      optionalString(request.title) ??
      "Review workflow edit proposal";
    const summary =
      optionalString(request.summary) ??
      "Proposal-only workflow edit staged for daemon-owned approval.";
    const {
      workflow_path: workflowPath,
      workflow_relative_path: workflowRelativePath,
    } = resolveWorkflowEditTarget(agent, request);
    const workflowPatch =
      request.workflow_patch && typeof request.workflow_patch === "object"
        ? request.workflow_patch
        : null;
    const codeDiff = optionalString(request.code_diff) ?? null;
    const editIntentHash = doctorHash(
      JSON.stringify({
        title,
        summary,
        workflow_graph_id: workflowGraphId,
        target_workflow_node_ids: targetWorkflowNodeIds,
        workflow_relative_path: workflowRelativePath,
        workflow_patch: workflowPatch,
        code_diff: codeDiff,
      }),
    ).slice(0, 16);
    const editIntentId =
      optionalString(request.edit_intent_id) ??
      `workflow_edit_intent_${editIntentHash}`;
    const proposalId =
      optionalString(request.proposal_id) ??
      `workflow_edit_proposal_${editIntentHash}`;
    const approvalId =
      optionalString(request.approval_id) ??
      `approval_workflow_edit_${safeId(proposalId)}`;
    const workflowNodeId =
      optionalString(request.workflow_node_id) ??
      `runtime.workflow-edit-proposal.${safeId(proposalId)}`;
    const patchHash = doctorHash(
      JSON.stringify({
        workflow_relative_path: workflowRelativePath,
        workflow_patch: workflowPatch,
        target_workflow_node_ids: targetWorkflowNodeIds,
        code_diff: codeDiff,
      }),
    );
    const runOrAgentId = run?.id ?? agent.id;
    const approvalManifest = {
      schema_version: "ioi.runtime.workflow-edit-proposal-approval.v1",
      proposal_id: proposalId,
      edit_intent_id: editIntentId,
      workflow_graph_id: workflowGraphId,
      workflow_node_id: workflowNodeId,
      target_workflow_node_ids: targetWorkflowNodeIds,
      workflow_path: workflowPath,
      workflow_relative_path: workflowRelativePath,
      patch_hash: patchHash,
      proposal_only: true,
      mutation_allowed: false,
      mutation_executed: false,
      effect_class: "workflow_mutation",
      risk_domain: "workflow_graph",
      policy_reason: "workflow_edit_proposal_only_requires_operator_approval",
      thread_mode: agent.runtimeControls?.mode ?? "agent",
      approval_mode: "human_required",
      authority_scope_requirements: ["workflow.edit.apply"],
    };
    const receiptRefs = uniqueStrings([
      ...normalizeArray(request.receipt_refs),
      `receipt_${runOrAgentId}_workflow_edit_proposed_${safeId(proposalId)}`,
    ]);
    const policyDecisionRefs = uniqueStrings([
      ...normalizeArray(request.policy_decision_refs),
      `policy_${runOrAgentId}_workflow_edit_proposal_only`,
    ]);
    const now = new Date().toISOString();
    const event = store.appendRuntimeEvent({
      event_stream_id: eventStreamIdForThread(threadId),
      thread_id: threadId,
      turn_id: turnId,
      item_id: `${turnId || threadId}:item:workflow-edit-proposed:${safeId(proposalId)}`,
      idempotency_key:
        request.idempotency_key ??
        `thread:${threadId}:workflow.edit.proposed:${proposalId}`,
      source,
      source_event_kind: "WorkflowEdit.Proposed",
      event_kind: "workflow.edit_proposed",
      status: "waiting_for_approval",
      actor: "runtime",
      created_at: now,
      workspace_root: agent.cwd,
      workflow_graph_id: workflowGraphId,
      workflow_node_id: workflowNodeId,
      component_kind: "workflow_edit_proposal",
      approval_id: approvalId,
      payload_schema_version: "ioi.runtime.workflow-edit-proposal.v1",
      payload: {
        event_kind: "WorkflowEdit.Proposed",
        proposal_id: proposalId,
        edit_intent_id: editIntentId,
        approval_id: approvalId,
        approval_required: true,
        title,
        summary,
        requested_by: requestedBy,
        control_surface: source,
        workflow_graph_id: workflowGraphId,
        workflow_node_id: workflowNodeId,
        target_workflow_node_ids: targetWorkflowNodeIds,
        bounded_targets: targetWorkflowNodeIds,
        workflow_path: workflowPath,
        workflow_relative_path: workflowRelativePath,
        workflow_patch: workflowPatch,
        workflow_patch_present: Boolean(workflowPatch),
        code_diff: codeDiff,
        patch_hash: patchHash,
        proposal_only: true,
        mutation_allowed: false,
        mutation_executed: false,
        approval_manifest: approvalManifest,
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
    const approval = store.requestThreadApproval(threadId, {
      source,
      turn_id: turnId,
      workflow_graph_id: workflowGraphId,
      workflow_node_id: workflowNodeId,
      action: "workflow.edit.apply",
      actor: "runtime",
      reason: `Workflow edit proposal ${proposalId} requires approval before apply.`,
      scope: "workflow_edit_proposal",
      approval_id: approvalId,
      tool_id: "workflow.edit.apply",
      effect_class: "workflow_mutation",
      risk_domain: "workflow_graph",
      authority_scope_requirements: ["workflow.edit.apply"],
      approval_manifest: approvalManifest,
      receipt_refs: receiptRefs,
      policy_decision_refs: [`policy_${runOrAgentId}_workflow_edit_approval_required`],
    });
    const approvalEvent = store.latestApprovalRequestEvent(threadId, approval.approval_id);
    return {
      schema_version: "ioi.runtime.workflow-edit-proposal-result.v1",
      status: "waiting_for_approval",
      proposal_id: proposalId,
      edit_intent_id: editIntentId,
      approval_id: approval.approval_id,
      approval_required: true,
      mutation_allowed: false,
      mutation_executed: false,
      workflow_path: workflowPath,
      workflow_relative_path: workflowRelativePath,
      patch_hash: patchHash,
      event_id: event.event_id,
      approval_event_id: approval.event_id,
      receipt_refs: uniqueStrings([...event.receipt_refs, ...normalizeArray(approval.receipt_refs)]),
      policy_decision_refs: uniqueStrings([
        ...event.policy_decision_refs,
        ...normalizeArray(approval.policy_decision_refs),
      ]),
      proposal_event: event,
      approval_event: approvalEvent,
    };
  }

  function latestWorkflowEditProposalEvent(store, threadId, proposalId) {
    const normalizedProposalId = optionalString(proposalId);
    if (!normalizedProposalId) return null;
    const stream = store.runtimeEventStream(eventStreamIdForThread(threadId));
    return (
      stream.events
        .filter((event) => {
          const payload = event.payload_summary ?? event.payload ?? {};
          return (
            event.event_kind === "workflow.edit_proposed" &&
            payload.proposal_id === normalizedProposalId
          );
        })
        .at(-1) ?? null
    );
  }

  function latestWorkflowEditApplyEvent(store, threadId, proposalId) {
    const normalizedProposalId = optionalString(proposalId);
    if (!normalizedProposalId) return null;
    const stream = store.runtimeEventStream(eventStreamIdForThread(threadId));
    return (
      stream.events
        .filter((event) => {
          const payload = event.payload_summary ?? event.payload ?? {};
          return (
            event.event_kind === "workflow.edit_applied" &&
            payload.proposal_id === normalizedProposalId
          );
        })
        .at(-1) ?? null
    );
  }

  function workflowEditApprovalSatisfaction(store, { threadId, approval_id: approvalId, proposal_event: proposalEvent }) {
    const normalizedApprovalId = optionalString(approvalId);
    if (!normalizedApprovalId) return { satisfied: false, reason: "approval_id_missing" };
    const approvalRequestEvent = store.latestApprovalRequestEvent(threadId, normalizedApprovalId);
    if (!approvalRequestEvent) return { satisfied: false, approval_id: normalizedApprovalId, reason: "approval_request_missing" };
    const proposalPayload = proposalEvent?.payload_summary ?? proposalEvent?.payload ?? {};
    const approvalPayload = approvalRequestEvent.payload_summary ?? approvalRequestEvent.payload ?? {};
    const requestedManifest = approvalPayload.approval_manifest ?? {};
    const proposalId = proposalPayload.proposal_id ?? null;
    const manifestProposalId = requestedManifest.proposal_id ?? null;
    if (proposalId && manifestProposalId && proposalId !== manifestProposalId) {
      return { satisfied: false, approval_id: normalizedApprovalId, reason: "approval_manifest_mismatch" };
    }
    const stream = store.runtimeEventStream(eventStreamIdForThread(threadId));
    const latestDecision = stream.events
      .filter(
        (event) =>
          event.approval_id === normalizedApprovalId &&
          event.seq > approvalRequestEvent.seq &&
          (event.event_kind === "approval.approved" ||
            event.event_kind === "approval.rejected" ||
            event.event_kind === "approval.revoked"),
      )
      .at(-1);
    if (!latestDecision) return { satisfied: false, approval_id: normalizedApprovalId, reason: "approval_decision_missing" };
    return {
      satisfied: latestDecision.event_kind === "approval.approved",
      approval_id: normalizedApprovalId,
      decision_event_id: latestDecision.event_id,
      decision_seq: latestDecision.seq,
      reason: approvalReasonForDecisionEvent(latestDecision),
    };
  }

  function applyWorkflowEditProposal(store, threadId, proposalId, request = {}) {
    const { agent, run, turnId } = workflowEditThreadContext(store, threadId, request);
    const normalizedProposalId =
      optionalString(proposalId ?? request.proposal_id) ??
      (() => {
        throw runtimeErrorDep({
          status: 400,
          code: "workflow_edit_proposal_id_required",
          message: "Workflow edit proposal apply requires a proposal id.",
          details: { thread_id: threadId },
        });
      })();
    const proposalEvent = latestWorkflowEditProposalEvent(store, threadId, normalizedProposalId);
    if (!proposalEvent) {
      throw notFoundDep(`Workflow edit proposal not found: ${normalizedProposalId}`, {
        thread_id: threadId,
        proposal_id: normalizedProposalId,
      });
    }
    const proposalPayload = proposalEvent.payload_summary ?? proposalEvent.payload ?? {};
    const approvalId =
      optionalString(request.approval_id) ??
      optionalString(proposalPayload.approval_id);
    const approvalSatisfaction = workflowEditApprovalSatisfaction(store, {
      threadId,
      approval_id: approvalId,
      proposal_event: proposalEvent,
    });
    if (!approvalSatisfaction.satisfied) {
      return {
        schema_version: "ioi.runtime.workflow-edit-apply-result.v1",
        status: "blocked",
        proposal_id: normalizedProposalId,
        approval_id: approvalSatisfaction.approval_id ?? approvalId ?? null,
        approval_required: true,
        approval_satisfied: false,
        mutation_allowed: false,
        mutation_executed: false,
        reason: approvalSatisfaction.reason,
        error: {
          code: "workflow_edit_approval_required",
          message: `Workflow edit proposal ${normalizedProposalId} requires approval before apply.`,
          details: {
            proposal_id: normalizedProposalId,
            approval_id: approvalSatisfaction.approval_id ?? approvalId ?? null,
            reason: approvalSatisfaction.reason,
          },
        },
      };
    }
    const duplicateApply = latestWorkflowEditApplyEvent(store, threadId, normalizedProposalId);
    if (duplicateApply) {
      return {
        schema_version: "ioi.runtime.workflow-edit-apply-result.v1",
        status: "completed",
        proposal_id: normalizedProposalId,
        approval_id: approvalSatisfaction.approval_id,
        approval_satisfied: true,
        mutation_allowed: true,
        mutation_executed: Boolean(duplicateApply.payload_summary?.mutation_executed),
        idempotent_replay: true,
        event: duplicateApply,
      };
    }
    const source = operatorControlSource(request.source);
    const requestedBy = optionalString(request.actor ?? request.requested_by) ?? "workflow-author";
    const workflowGraphId =
      optionalString(request.workflow_graph_id) ??
      optionalString(proposalEvent.workflow_graph_id) ??
      null;
    const workflowNodeId =
      optionalString(request.workflow_node_id) ??
      optionalString(proposalEvent.workflow_node_id) ??
      `runtime.workflow-edit-proposal.${safeId(normalizedProposalId)}`;
    const workflowPath = optionalString(proposalPayload.workflow_path);
    const workflowPatch = proposalPayload.workflow_patch ?? null;
    let workflowRelativePath = optionalString(proposalPayload.workflow_relative_path);
    let mutationExecuted = false;
    if (workflowPath && workflowPatch && typeof workflowPatch === "object") {
      const resolvedWorkflowPath = path.resolve(agent.cwd, workflowPath);
      workflowRelativePath = relativePathForWorkspace(resolvedWorkflowPath, agent.cwd);
      if (!workflowRelativePath) {
        throw policyErrorDep("Workflow edit apply blocked outside the runtime workspace.", {
          workspaceRoot: agent.cwd,
          workflow_path: resolvedWorkflowPath,
          proposal_id: normalizedProposalId,
        });
      }
      writeJsonDep(resolvedWorkflowPath, workflowPatch);
      mutationExecuted = true;
    }
    const runOrAgentId = run?.id ?? agent.id;
    const now = new Date().toISOString();
    const event = store.appendRuntimeEvent({
      event_stream_id: eventStreamIdForThread(threadId),
      thread_id: threadId,
      turn_id: turnId,
      item_id: `${turnId || threadId}:item:workflow-edit-applied:${safeId(normalizedProposalId)}`,
      idempotency_key:
        request.idempotency_key ??
        `thread:${threadId}:workflow.edit.applied:${normalizedProposalId}:${approvalSatisfaction.approval_id}`,
      source,
      source_event_kind: "WorkflowEdit.Applied",
      event_kind: "workflow.edit_applied",
      status: "completed",
      actor: "runtime",
      created_at: now,
      workspace_root: agent.cwd,
      workflow_graph_id: workflowGraphId,
      workflow_node_id: workflowNodeId,
      component_kind: "workflow_edit_proposal",
      approval_id: approvalSatisfaction.approval_id,
      payload_schema_version: "ioi.runtime.workflow-edit-apply.v1",
      payload: {
        event_kind: "WorkflowEdit.Applied",
        proposal_id: normalizedProposalId,
        proposal_event_id: proposalEvent.event_id,
        approval_id: approvalSatisfaction.approval_id,
        approval_satisfied: true,
        approval_decision_event_id: approvalSatisfaction.decision_event_id,
        requested_by: requestedBy,
        control_surface: source,
        workflow_path: workflowPath,
        workflow_relative_path: workflowRelativePath,
        patch_hash: proposalPayload.patch_hash ?? null,
        mutation_allowed: true,
        mutation_executed: mutationExecuted,
        proposal_only: true,
        agent_id: agent.id,
        thread_id: threadId,
        turn_id: turnId || null,
        run_id: run?.id ?? null,
        session_id: runtimeSessionIdForAgent(agent),
      },
      receipt_refs: [
        ...normalizeArray(proposalEvent.receipt_refs),
        `receipt_${runOrAgentId}_workflow_edit_applied_${safeId(normalizedProposalId)}`,
      ],
      policy_decision_refs: [
        `policy_${runOrAgentId}_workflow_edit_apply_approval_satisfied`,
      ],
      artifact_refs: [],
      rollback_refs: [],
      redaction_profile: "internal",
      fixture_profile: fixtureProfileForAgent(agent),
    });
    return {
      schema_version: "ioi.runtime.workflow-edit-apply-result.v1",
      status: "completed",
      proposal_id: normalizedProposalId,
      approval_id: approvalSatisfaction.approval_id,
      approval_satisfied: true,
      mutation_allowed: true,
      mutation_executed: mutationExecuted,
      idempotent_replay: false,
      event,
    };
  }

  return {
    workflowEditThreadContext,
    resolveWorkflowEditTarget,
    proposeWorkflowEdit,
    latestWorkflowEditProposalEvent,
    latestWorkflowEditApplyEvent,
    workflowEditApprovalSatisfaction,
    applyWorkflowEditProposal,
  };
}
