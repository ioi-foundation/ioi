function defaultObjectRecord(value) {
  return value && typeof value === "object" && !Array.isArray(value) ? value : null;
}

function defaultOptionalString(value) {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return trimmed || null;
}

function defaultSafeId(value) {
  return String(value || "unknown")
    .replace(/[^a-z0-9]+/gi, "_")
    .replace(/^_+|_+$/g, "")
    .toLowerCase() || "unknown";
}

function defaultUniqueStrings(values = []) {
  return [...new Set((Array.isArray(values) ? values : []).map((value) => String(value)).filter(Boolean))];
}

export function createRuntimeInvocationResultProjections(deps = {}) {
  const CODING_TOOL_PACK_ID = deps.CODING_TOOL_PACK_ID || "coding";
  const CODING_TOOL_RESULT_SCHEMA_VERSION =
    deps.CODING_TOOL_RESULT_SCHEMA_VERSION || "ioi.runtime.coding-tool-result.v1";
  const objectRecord = deps.objectRecord || defaultObjectRecord;
  const optionalString = deps.optionalString || defaultOptionalString;
  const safeId = deps.safeId || defaultSafeId;
  const uniqueStrings = deps.uniqueStrings || defaultUniqueStrings;

  function codingToolInvocationResultFromEvent(event, context = {}) {
    const payload = event.payload_summary ?? event.payload ?? {};
    const result = payload.result ?? null;
    return {
      schema_version: CODING_TOOL_RESULT_SCHEMA_VERSION,
      object: "ioi.runtime_coding_tool_result",
      tool_pack: CODING_TOOL_PACK_ID,
      tool_name: payload.tool_name ?? context.toolId ?? null,
      tool_call_id: payload.tool_call_id ?? context.toolCallId ?? event.tool_call_id ?? null,
      thread_id: payload.thread_id ?? context.threadId ?? event.thread_id ?? null,
      turn_id: payload.turn_id ?? context.turnId ?? event.turn_id ?? null,
      status: event.status ?? payload.status ?? "completed",
      workspace_root: payload.workspace_root ?? context.agent?.cwd ?? event.workspace_root ?? null,
      workflow_graph_id: payload.workflow_graph_id ?? context.workflowGraphId ?? event.workflow_graph_id ?? null,
      workflow_node_id: payload.workflow_node_id ?? context.workflowNodeId ?? event.workflow_node_id ?? null,
      shell_fallback_used: Boolean(payload.shell_fallback_used),
      receipt_refs: event.receipt_refs,
      artifact_refs: event.artifact_refs,
      rollback_refs: event.rollback_refs,
      event,
      idempotent_replay: true,
      workspace_snapshot: result?.workspace_snapshot ?? null,
      workspace_snapshot_event: null,
      auto_diagnostics: null,
      result,
      error: payload.error ?? null,
    };
  }

  function computerUseBrowserDiscoveryInvocationResultFromEvent(event, context = {}) {
    const payload = event.payload_summary ?? event.payload ?? {};
    const result = objectRecord(
      payload.browser_discovery_report ?? payload.browserDiscoveryReport,
    );
    return {
      schema_version: "ioi.runtime.computer-use-browser-discovery-result.v1",
      object: "ioi.runtime_computer_use_browser_discovery_result",
      tool_pack: "computer_use",
      tool_name: payload.tool_ref ?? payload.toolRef ?? context.toolId ?? null,
      tool_call_id: event.tool_call_id ?? context.toolCallId ?? null,
      thread_id: event.thread_id ?? context.threadId ?? null,
      turn_id: event.turn_id ?? context.turnId ?? null,
      status: event.status ?? payload.status ?? "completed",
      workspace_root: event.workspace_root ?? context.agent?.cwd ?? null,
      workflow_graph_id: payload.workflow_graph_id ?? context.workflowGraphId ?? event.workflow_graph_id ?? null,
      workflow_node_id: payload.workflow_node_id ?? context.workflowNodeId ?? event.workflow_node_id ?? null,
      shell_fallback_used: false,
      receipt_refs: event.receipt_refs,
      artifact_refs: event.artifact_refs,
      rollback_refs: event.rollback_refs,
      event,
      idempotent_replay: true,
      workspace_snapshot: null,
      workspace_snapshot_event: null,
      auto_diagnostics: null,
      result,
      error: payload.error ?? null,
    };
  }

  function computerUseControlInvocationResultFromEvent(event, context = {}) {
    const payload = event.payload_summary ?? event.payload ?? {};
    const result = objectRecord(payload.control_receipt);
    return {
      schema_version: "ioi.runtime.computer-use-control-result.v1",
      object: "ioi.runtime_computer_use_control_result",
      tool_pack: "computer_use",
      tool_name: payload.tool_ref ?? payload.toolRef ?? context.toolId ?? null,
      tool_call_id: event.tool_call_id ?? context.toolCallId ?? null,
      thread_id: event.thread_id ?? context.threadId ?? null,
      turn_id: event.turn_id ?? context.turnId ?? null,
      status: event.status ?? payload.status ?? "completed",
      workspace_root: event.workspace_root ?? context.agent?.cwd ?? null,
      workflow_graph_id: payload.workflow_graph_id ?? context.workflowGraphId ?? event.workflow_graph_id ?? null,
      workflow_node_id: payload.workflow_node_id ?? context.workflowNodeId ?? event.workflow_node_id ?? null,
      shell_fallback_used: false,
      receipt_refs: event.receipt_refs,
      artifact_refs: event.artifact_refs,
      rollback_refs: event.rollback_refs,
      event,
      idempotent_replay: true,
      result: {
        control_receipt: result,
        human_handoff_state: payload.human_handoff_state ?? null,
        cleanup_receipt: payload.cleanup_receipt ?? null,
      },
      error: null,
    };
  }

  function computerUseNativeBrowserInvocationResultFromEvents(events, context = {}) {
    const orderedEvents = [...events].sort((left, right) => (left.seq ?? 0) - (right.seq ?? 0));
    const payloads = orderedEvents.map((event) => event.payload_summary ?? event.payload ?? {});
    const firstPayload = payloads[0] ?? {};
    const resultLane = optionalString(
      context.computerUseLane ??
        context.computer_use_lane ??
        firstPayload.computer_use_lane ??
        firstPayload.computerUseLane,
    ) ?? "native_browser";
    const resultObjectLane = safeId(resultLane);
    const resultSchemaLane = resultObjectLane.replace(/_/g, "-");
    const observationPayload =
      payloads.find((payload) => payload.observation_bundle || payload.observationBundle) ?? {};
    const actionPayload =
      payloads.find((payload) => payload.computer_action || payload.computerAction) ?? {};
    const verificationPayload =
      payloads.find((payload) => payload.verification_receipt || payload.verificationReceipt) ?? {};
    const cleanupPayload =
      payloads.find((payload) => payload.cleanup_receipt || payload.cleanupReceipt) ?? {};
    const adapterPayload =
      payloads.find((payload) => payload.adapter_contract || payload.adapterContract) ?? {};
    const controlledRelaunchLaunchPayload =
      payloads.find((payload) => (
        payload.controlled_relaunch_launch_receipt ||
        payload.controlledRelaunchLaunchReceipt
      )) ?? {};
    const affordancePayload =
      payloads.find((payload) => payload.affordance_graph || payload.affordanceGraph) ?? {};
    const proposalPayload =
      payloads.find((payload) => payload.action_proposal || payload.actionProposal) ?? {};
    const policyDecisionPayload =
      payloads.find((payload) => payload.policy_decision_receipt || payload.policyDecisionReceipt) ?? {};
    const runStatePayload =
      payloads.find((payload) => payload.computer_use_run_state || payload.computerUseRunState) ?? {};
    const outcomePayload =
      payloads.find((payload) => payload.outcome_contract || payload.outcomeContract) ?? {};
    const commitGatePayload =
      payloads.find((payload) => payload.commit_gate || payload.commitGate) ?? {};
    const trajectoryPayload =
      payloads.find((payload) => payload.trajectory_bundle || payload.trajectoryBundle) ?? {};
    const projection = context.projection ?? {};
    const receiptRefs = uniqueStrings(orderedEvents.flatMap((event) => event.receipt_refs ?? []));
    const artifactRefs = uniqueStrings(orderedEvents.flatMap((event) => event.artifact_refs ?? []));
    return {
      schema_version: `ioi.runtime.computer-use-${resultSchemaLane}-result.v1`,
      object: `ioi.runtime_computer_use_${resultObjectLane}_result`,
      tool_pack: "computer_use",
      tool_name: context.toolId ?? firstPayload.tool_ref ?? firstPayload.toolRef ?? null,
      tool_call_id: context.toolCallId ?? orderedEvents[0]?.tool_call_id ?? null,
      thread_id: context.threadId ?? orderedEvents[0]?.thread_id ?? null,
      turn_id: context.turnId ?? orderedEvents[0]?.turn_id ?? null,
      status: orderedEvents.every((event) => event.status !== "failed") ? "completed" : "failed",
      workspace_root: context.agent?.cwd ?? orderedEvents[0]?.workspace_root ?? null,
      workflow_graph_id:
        context.workflowGraphId ?? firstPayload.workflow_graph_id ?? firstPayload.workflowGraphId ?? null,
      workflow_node_id:
        context.workflowNodeId ?? firstPayload.workflow_node_id ?? firstPayload.workflowNodeId ?? null,
      shell_fallback_used: false,
      receipt_refs: receiptRefs,
      artifact_refs: artifactRefs,
      rollback_refs: uniqueStrings(orderedEvents.flatMap((event) => event.rollback_refs ?? [])),
      event_count: orderedEvents.length,
      event_refs: orderedEvents.map((event) => event.event_id),
      events: orderedEvents,
      idempotent_replay: true,
      idempotentReplay: true,
      result: {
        environmentSelection:
          projection.environmentSelection ??
          firstPayload.environment_selection_receipt ??
          firstPayload.environmentSelectionReceipt ??
          null,
        lease: projection.lease ?? firstPayload.lease ?? null,
        observation:
          projection.observation ??
          observationPayload.observation_bundle ??
          observationPayload.observationBundle ??
          null,
        targetIndex:
          projection.targetIndex ??
          observationPayload.target_index ??
          observationPayload.targetIndex ??
          null,
        affordanceGraph:
          projection.affordanceGraph ??
          affordancePayload.affordance_graph ??
          affordancePayload.affordanceGraph ??
          null,
        actionProposal:
          projection.actionProposal ??
          proposalPayload.action_proposal ??
          proposalPayload.actionProposal ??
          null,
        runState:
          projection.runState ??
          runStatePayload.computer_use_run_state ??
          runStatePayload.computerUseRunState ??
          null,
        action:
          projection.action ??
          actionPayload.computer_action ??
          actionPayload.computerAction ??
          null,
        actionReceipt:
          projection.actionReceipt ??
          actionPayload.action_receipt ??
          actionPayload.actionReceipt ??
          null,
        verification:
          projection.verification ??
          verificationPayload.verification_receipt ??
          verificationPayload.verificationReceipt ??
          null,
        outcomeContract:
          projection.outcomeContract ??
          outcomePayload.outcome_contract ??
          outcomePayload.outcomeContract ??
          null,
        policyDecision:
          projection.policyDecision ??
          policyDecisionPayload.policy_decision_receipt ??
          policyDecisionPayload.policyDecisionReceipt ??
          null,
        commitGate:
          projection.commitGate ??
          commitGatePayload.commit_gate ??
          commitGatePayload.commitGate ??
          null,
        trajectory:
          projection.trajectory ??
          trajectoryPayload.trajectory_bundle ??
          trajectoryPayload.trajectoryBundle ??
          null,
        cleanup:
          projection.cleanup ??
          cleanupPayload.cleanup_receipt ??
          cleanupPayload.cleanupReceipt ??
          null,
        adapterContract:
          projection.adapterContract ??
          adapterPayload.adapter_contract ??
          adapterPayload.adapterContract ??
          null,
        controlledRelaunchLaunch:
          projection.controlledRelaunchLaunchReceipt ??
          controlledRelaunchLaunchPayload.controlled_relaunch_launch_receipt ??
          controlledRelaunchLaunchPayload.controlledRelaunchLaunchReceipt ??
          null,
        contractIngest:
          projection.contractIngest ??
          firstPayload.computer_use_contract_ingest ??
          firstPayload.contractIngest ??
          null,
        contract_ingest:
          projection.contractIngest ??
          firstPayload.computer_use_contract_ingest ??
          firstPayload.contractIngest ??
          null,
      },
      error: null,
    };
  }

  return {
    codingToolInvocationResultFromEvent,
    computerUseBrowserDiscoveryInvocationResultFromEvent,
    computerUseControlInvocationResultFromEvent,
    computerUseNativeBrowserInvocationResultFromEvents,
  };
}
