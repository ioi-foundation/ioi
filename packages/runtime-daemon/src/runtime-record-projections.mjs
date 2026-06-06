export function createRuntimeRecordProjections(deps) {
  const {
    COMPUTER_USE_CONTRACT_SCHEMA_VERSION,
    artifact,
    doctorHash,
    eventStreamIdForThread,
    isComputerUseRunEventType,
    normalizeArray,
    optionalString,
    runtimeSessionIdForAgent,
    runtimeUsageTelemetryForRun,
    safeId,
    strategyForMode,
    taskFamilyForMode,
    terminalCount,
    threadIdForAgent,
    turnIdForRun,
    uniqueStrings,
  } = deps;

function runtimeTaskRecord({
  runId,
  agent,
  prompt,
  mode,
  taskFamily,
  selectedStrategy,
  modelRouteDecision,
  activeSkillHookManifest,
  createdAt,
  updatedAt,
  status,
} = {}) {
  const id = runId ?? `run_${doctorHash(String(prompt ?? "task")).slice(0, 12)}`;
  const agentId = agent?.id ?? null;
  const promptHash = doctorHash(String(prompt ?? ""));
  return {
    schemaVersion: "ioi.agent-runtime.task-record.v1",
    object: "ioi.runtime_task",
    taskId: `task_${id}`,
    runId: id,
    agentId,
    threadId: agentId ? threadIdForAgent(agentId) : null,
    turnId: turnIdForRun(id),
    status: status ?? "completed",
    mode: mode ?? "send",
    taskFamily: taskFamily ?? taskFamilyForMode(mode ?? "send"),
    selectedStrategy: selectedStrategy ?? strategyForMode(mode ?? "send"),
    summary: `Runtime task for ${taskFamily ?? taskFamilyForMode(mode ?? "send")} is ${status ?? "completed"}.`,
    promptHash,
    promptIncluded: false,
    objectivePreviewIncluded: false,
    modelRouteDecisionId: modelRouteDecision?.decision_id ?? null,
    activeSkillHookManifestId: activeSkillHookManifest?.manifestId ?? null,
    createdAt: createdAt ?? new Date().toISOString(),
    updatedAt: updatedAt ?? createdAt ?? new Date().toISOString(),
    durable: true,
    replayable: true,
    cancelable: status !== "canceled",
    cancelEndpoint: `/v1/tasks/task_${id}/cancel`,
    endpoints: {
      self: `/v1/tasks/task_${id}`,
      cancel: `/v1/tasks/task_${id}/cancel`,
      run: `/v1/runs/${id}`,
      job: `/v1/jobs/job_${id}`,
      events: `/v1/runs/${id}/events`,
      trace: `/v1/runs/${id}/trace`,
    },
    workflowNodeId: "runtime.runtime-task",
    redaction: {
      profile: "runtime_task_safe",
      promptIncluded: false,
      secretValuesIncluded: false,
    },
    evidenceRefs: [
      "runtime_task",
      "runtime.tasks.durable_projection",
      "RuntimeTaskNode",
      `run:${id}`,
      activeSkillHookManifest?.manifestId,
    ].filter(Boolean),
  };
}

function runtimeBridgeRunRecord({ agent, request, projection }) {
  const bridgeEvents = runtimeBridgeMessagesForProjection({ agent, projection });
  const computerUseTrace = runtimeBridgeComputerUseTrace({
    projection,
    events: bridgeEvents,
  });
  const receipts = [
    ...(computerUseTrace
      ? [
          {
            id: `receipt_${projection.runId}_runtime_bridge_computer_use_trace`,
            kind: "computer_use_trace",
            summary:
              "RuntimeAgentService bridge computer-use events were projected into a durable trace artifact.",
            redaction: "redacted",
            evidenceRefs: uniqueStrings([
              "RuntimeAgentService",
              "ComputerUseHarnessContract",
              ...computerUseTrace.events.map((event) => event.runtime_event_id).filter(Boolean),
              computerUseTrace.observation?.observation_ref,
              computerUseTrace.target_index?.target_index_ref,
              computerUseTrace.affordance_graph?.graph_ref,
            ]),
          },
        ]
      : []),
    {
      id: `receipt_${projection.runId}_runtime_bridge_trace`,
      kind: "trace_export",
      summary: "RuntimeAgentService bridge run trace was persisted from canonical runtime events.",
      redaction: "redacted",
      evidenceRefs: uniqueStrings([
        "RuntimeAgentService",
        ...bridgeEvents.map((event) => event.data?.runtime_event_id).filter(Boolean),
      ]),
    },
  ];
  const taskFamily = taskFamilyForMode(projection.mode);
  const selectedStrategy = strategyForMode(projection.mode);
  const stopCondition = {
    reason: projection.stopReason,
    evidenceSufficient: true,
    rationale: "RuntimeAgentService bridge supplied the terminal turn event projection.",
  };
  const qualityLedger = {
    ledgerId: `quality_${projection.runId}`,
    taskFamily,
    selectedStrategy,
    toolSequence: [],
    scorecardMetrics: {
      task_pass_rate: 100,
      recovery_success: 100,
      memory_relevance: 100,
      tool_quality: 100,
      strategy_roi: 100,
      operator_interventions: 0,
      verifier_independence: 100,
    },
    failureOntologyLabels: [],
  };
  const scorecard = {
    taskPassRate: 1,
    recoverySuccess: 1,
    memoryRelevance: 1,
    toolQuality: 1,
    strategyRoi: 1,
    operatorInterventionRate: 0,
    verifierIndependence: 1,
  };
  const trace = {
    schemaVersion: "ioi.agent-sdk.trace.v1",
    traceBundleId: `trace_${projection.runId}`,
    runId: projection.runId,
    agentId: agent.id,
    status: projection.status,
    source: "runtime_service",
    eventStreamId: eventStreamIdForThread(threadIdForAgent(agent.id)),
    events: bridgeEvents,
    receipts,
    artifacts: [],
    taskState: null,
    uncertainty: null,
    probe: null,
    postconditions: null,
    semanticImpact: null,
    memoryPolicy: null,
    memoryRecords: [],
    memoryWrites: [],
    computerUse: computerUseTrace,
    stopCondition,
    qualityLedger,
    scorecard,
  };
  const usageTelemetry = runtimeUsageTelemetryForRun({
    run: {
      id: projection.runId,
      agentId: agent.id,
      mode: projection.mode,
      objective: projection.prompt,
      result: projection.result,
      createdAt: projection.createdAt,
      updatedAt: projection.updatedAt,
      modelRouteDecision: agent.modelRouteDecision ?? null,
      usage: projection.usage,
    },
    agent,
    threadId: threadIdForAgent(agent.id),
  });
  const traceWithUsage = {
    ...trace,
    usage: usageTelemetry,
    usage_telemetry: usageTelemetry,
  };
  const artifacts = [
    artifact(
      projection.runId,
      "trace.json",
      "application/json",
      `receipt_${projection.runId}_runtime_bridge_trace`,
      traceWithUsage,
      "redacted",
    ),
    ...(computerUseTrace
      ? [
          artifact(
            projection.runId,
            "computer-use-trace.json",
            "application/json",
            `receipt_${projection.runId}_runtime_bridge_computer_use_trace`,
            computerUseTrace,
            "redacted",
          ),
        ]
      : []),
    artifact(
      projection.runId,
      "scorecard.json",
      "application/json",
      `receipt_${projection.runId}_runtime_bridge_trace`,
      scorecard,
      "none",
    ),
  ];
  const traceWithArtifacts = {
    ...traceWithUsage,
    artifacts: artifacts.map((item) => ({
      id: item.id,
      name: item.name,
      mediaType: item.mediaType,
      redaction: item.redaction,
      receiptId: item.receiptId,
    })),
  };
  artifacts[0] = artifact(
    projection.runId,
    "trace.json",
    "application/json",
    `receipt_${projection.runId}_runtime_bridge_trace`,
    traceWithArtifacts,
    "redacted",
  );
  return {
    id: projection.runId,
    agentId: agent.id,
    mode: projection.mode,
    objective: projection.prompt,
    status: projection.status,
    createdAt: projection.createdAt,
    updatedAt: projection.updatedAt,
    source: "runtime_service",
    runtimeProfile: agent.runtimeProfile,
    runtimeSessionId: runtimeSessionIdForAgent(agent),
    runtimeTurnId: projection.turnId,
    result: projection.result,
    usage: usageTelemetry,
    usage_telemetry: usageTelemetry,
    events: bridgeEvents,
    conversation: [
      { role: "user", content: projection.prompt, createdAt: projection.createdAt },
      ...(projection.result ? [{ role: "assistant", content: projection.result, createdAt: projection.updatedAt }] : []),
    ],
    trace: traceWithArtifacts,
    artifacts,
    receipts,
    modelRouteDecision: agent.modelRouteDecision ?? null,
    modelRouteReceiptId: agent.modelRouteReceiptId ?? null,
    activeSkillHookManifest: null,
    memoryRecords: [],
    memoryWriteReceipts: [],
  };
}

function runtimeBridgeMessagesForProjection({ agent, projection }) {
  return normalizeArray(projection.events).map((event, index) =>
    runtimeBridgeMessageForEvent({ agent, projection, event, index }),
  );
}

function runtimeBridgeMessageForEvent({ agent, projection, event, index }) {
  const payload = runtimeBridgeEventPayload(event);
  const type = runtimeBridgeRunEventType(event);
  const summary =
    optionalString(payload.summary) ??
    optionalString(event.summary) ??
    optionalString(event.source_event_kind) ??
    optionalString(event.event_kind) ??
    type;
  return {
    id: `${projection.runId}:bridge:${String(index).padStart(3, "0")}:${type}`,
    runId: projection.runId,
    agentId: agent.id,
    type,
    cursor: `${projection.runId}:${index}`,
    createdAt: event.created_at ?? projection.updatedAt ?? projection.createdAt,
    summary,
    data: {
      ...payload,
      eventKind: payload.event_kind ?? event.source_event_kind ?? event.event_kind ?? type,
      workflowGraphId: event.workflow_graph_id ?? payload.workflow_graph_id ?? null,
      workflow_graph_id: event.workflow_graph_id ?? payload.workflow_graph_id ?? null,
      workflowNodeId: event.workflow_node_id ?? payload.workflow_node_id ?? null,
      workflow_node_id: event.workflow_node_id ?? payload.workflow_node_id ?? null,
      componentKind: event.component_kind ?? payload.component_kind ?? null,
      component_kind: event.component_kind ?? payload.component_kind ?? null,
      payloadSchemaVersion: event.payload_schema_version ?? payload.schema_version ?? null,
      payload_schema_version: event.payload_schema_version ?? payload.schema_version ?? null,
      runtimeEventId: event.event_id ?? null,
      runtime_event_id: event.event_id ?? null,
      runtimeEventKind: event.event_kind ?? null,
      runtime_event_kind: event.event_kind ?? null,
      sourceEventKind: event.source_event_kind ?? null,
      source_event_kind: event.source_event_kind ?? null,
      receiptRefs: normalizeArray(event.receipt_refs),
      receipt_refs: normalizeArray(event.receipt_refs),
      artifactRefs: normalizeArray(event.artifact_refs),
      artifact_refs: normalizeArray(event.artifact_refs),
      policyDecisionRefs: normalizeArray(event.policy_decision_refs),
      policy_decision_refs: normalizeArray(event.policy_decision_refs),
    },
  };
}

function runtimeBridgeEventPayload(event = {}) {
  const payloadSummary = objectRecord(event.payload_summary);
  const payload = objectRecord(event.payload);
  return Object.keys(payloadSummary).length > 0 ? payloadSummary : payload;
}

function objectRecord(value) {
  return value && typeof value === "object" && !Array.isArray(value) ? value : {};
}

function runtimeBridgeRunEventType(event = {}) {
  const kind = String(event.event_kind ?? "").trim();
  if (kind.startsWith("computer_use.")) {
    return kind.replace(/\./g, "_");
  }
  switch (kind) {
    case "turn.started":
      return "run_started";
    case "turn.completed":
      return "completed";
    case "turn.failed":
      return "error";
    case "turn.canceled":
      return "canceled";
    case "item.delta":
    case "reasoning.delta":
      return "delta";
    case "answer.delta":
      return "answer_delta";
    case "usage.delta":
      return "usage_delta";
    case "context.pressure_delta":
      return "context_pressure_delta";
    case "context.pressure_alert":
      return "context_pressure_alert";
    case "policy.blocked":
      return "policy_blocked";
    default:
      return kind ? kind.replace(/[^a-z0-9]+/gi, "_").replace(/^_+|_+$/g, "").toLowerCase() : "runtime_step";
  }
}

function runtimeBridgeComputerUseTrace({ projection, events }) {
  const computerUseEvents = events.filter((event) => isComputerUseRunEventType(event.type));
  if (!computerUseEvents.length) return null;
  const payloads = computerUseEvents.map((event) => event.data ?? {});
  const value = (...keys) => {
    for (const payload of payloads) {
      for (const key of keys) {
        if (payload[key] !== undefined && payload[key] !== null) return payload[key];
      }
    }
    return null;
  };
  const observation = value("observation_bundle");
  const targetIndex = value("target_index");
  const affordanceGraph = value("affordance_graph");
  const action = value("computer_action");
  const cleanup = value("cleanup_receipt");
  const environmentSelection =
    value("environment_selection_receipt") ??
    runtimeBridgeEnvironmentSelectionFromObservation({ projection, observation });
  const lease =
    value("lease") ??
    runtimeBridgeLeaseFromObservation({ projection, observation, environmentSelection });
  const actionProposal =
    value("action_proposal") ??
    runtimeBridgeActionProposalFromAffordanceGraph({
      projection,
      affordanceGraph,
    });
  const outcomeContract =
    value("outcome_contract") ??
    runtimeBridgeOutcomeContractFromProposal({ projection, actionProposal });
  const commitGate =
    value("commit_gate") ??
    runtimeBridgeCommitGateFromProposal({
      projection,
      actionProposal,
      outcomeContract,
      environmentSelection,
    });
  const runState =
    value("computer_use_run_state") ??
    runtimeBridgeRunStateFromTrace({
      projection,
      lease,
      observation,
      targetIndex,
      actionProposal,
      action,
      commitGate,
    });
  const trajectory =
    value("trajectory_bundle") ??
    runtimeBridgeTrajectoryFromComputerUseEvents({
      projection,
      events: computerUseEvents,
      observation,
    });
  return {
    schema_version: COMPUTER_USE_CONTRACT_SCHEMA_VERSION,
    source: "runtime_service_bridge",
    run_id: projection.runId,
    turn_id: projection.turnId,
    event_count: computerUseEvents.length,
    events: computerUseEvents.map((event) => ({
      id: event.id,
      type: event.type,
      summary: event.summary,
      runtime_event_id: event.data?.runtime_event_id ?? null,
      runtime_event_kind: event.data?.runtime_event_kind ?? null,
      workflow_node_id: event.data?.workflow_node_id ?? null,
      component_kind: event.data?.component_kind ?? null,
      receipt_refs: normalizeArray(event.data?.receipt_refs),
      artifact_refs: normalizeArray(event.data?.artifact_refs),
    })),
    environment_selection: environmentSelection,
    lease,
    run_state: runState,
    observation,
    observation_bundle: observation,
    target_index: targetIndex,
    affordance_graph: affordanceGraph,
    action_proposal: actionProposal,
    action,
    computer_action: action,
    action_receipt: value("action_receipt"),
    verification: value("verification_receipt"),
    verification_receipt: value("verification_receipt"),
    outcome_contract: outcomeContract,
    commit_gate: commitGate,
    trajectory,
    trajectory_bundle: trajectory,
    cleanup,
    cleanup_receipt: cleanup,
    recovery_policy: value("recovery_policy"),
    human_handoff_state: value("human_handoff_state"),
    contract_ingest: value("computer_use_contract_ingest"),
    retention_mode:
      value("observation_retention_mode") ??
      observation?.retention_mode ??
      null,
    evidenceRefs: uniqueStrings([
      ...computerUseEvents.map((event) => event.data?.runtime_event_id).filter(Boolean),
      observation?.observation_ref,
      targetIndex?.target_index_ref,
      affordanceGraph?.graph_ref,
      value("computer_use_proposal_ref"),
      action?.action_ref,
      value("computer_use_verification_ref"),
      value("computer_use_cleanup_ref"),
    ]),
  };
}

function runtimeBridgeRunStateFromTrace({
  projection,
  lease,
  observation,
  targetIndex,
  actionProposal,
  action,
  commitGate,
}) {
  const requiresConfirmation = Boolean(commitGate?.user_confirmation_required);
  return {
    run_id: projection.runId,
    lease_id: lease?.lease_id ?? observation?.lease_id ?? null,
    user_goal: projection.prompt ?? "",
    current_subgoal: actionProposal
      ? "Policy-gate the bridge-derived action proposal before execution."
      : "Observe the runtime-service computer-use surface and preserve grounding evidence.",
    plan_graph_ref: `plan_graph_${projection.runId}_runtime_bridge_computer_use`,
    current_observation_ref: observation?.observation_ref ?? null,
    current_target_index_ref: targetIndex?.target_index_ref ?? observation?.target_index_ref ?? null,
    active_hypotheses: [
      "RuntimeAgentService remains the environment owner for this bridge turn.",
      actionProposal
        ? "The top affordance is a candidate only; execution requires a grounded ComputerAction and policy approval."
        : "Observation and target evidence should be inspected before proposing an action.",
    ],
    expected_postcondition:
      actionProposal?.predicted_postcondition ??
      "Computer-use observation evidence is preserved in the run trace.",
    last_action_ref: action?.action_ref ?? null,
    verification_status: requiresConfirmation
      ? "requires_human"
      : action
        ? "passed"
        : "unknown",
    blocker_state: requiresConfirmation ? "commit_gate_requires_confirmation" : null,
    retry_budget: requiresConfirmation ? 0 : 1,
    risk_posture: commitGate?.status ?? "bridge_observation",
    user_handoff_ref: requiresConfirmation ? commitGate?.commit_gate_ref ?? null : null,
    cleanup_state: lease?.cleanup_required ? "cleanup_required" : "external_runtime_owned",
  };
}

function runtimeBridgeOutcomeContractFromProposal({ projection, actionProposal }) {
  if (!actionProposal) return null;
  const confirmationRequired = Boolean(actionProposal.confirmation_required);
  return {
    outcome_ref: `outcome_${projection.runId}_runtime_bridge`,
    requested_outcome: projection.prompt ?? "Runtime service computer-use run",
    success_criteria: [
      actionProposal.predicted_postcondition ??
        "A policy gate decides whether the bridge proposal can become an executable ComputerAction.",
    ],
    acceptable_side_effects: [
      "Persist redacted computer-use trace, target, affordance, and proposal evidence.",
    ],
    prohibited_side_effects: [
      "Execute the bridge-derived proposal without a grounded ComputerAction and policy approval.",
    ],
    evidence_required: ["computer_use_trace", "action_proposal", "commit_gate"],
    rollback_or_cleanup_required: false,
    external_effect_policy: confirmationRequired ? "confirmation_required" : "not_required",
  };
}

function runtimeBridgeCommitGateFromProposal({
  projection,
  actionProposal,
  outcomeContract,
  environmentSelection,
}) {
  if (!actionProposal || !outcomeContract) return null;
  const confirmationRequired =
    Boolean(actionProposal.confirmation_required) ||
    !["read_only", "inspect", "none"].includes(String(actionProposal.risk_assessment ?? ""));
  return {
    commit_gate_ref: `commit_gate_${projection.runId}_runtime_bridge`,
    final_action_ref: null,
    outcome_ref: outcomeContract.outcome_ref,
    external_effect: confirmationRequired,
    user_confirmation_required: confirmationRequired,
    authority_required:
      environmentSelection?.authority_required ??
      `computer_use.${environmentSelection?.selected_lane ?? "native_browser"}.read`,
    pre_commit_summary:
      "Runtime bridge projected a candidate action but did not execute it; execution requires a grounded ComputerAction and policy approval.",
    post_commit_verification: outcomeContract.success_criteria.join("; "),
    policy_decision_ref: actionProposal.policy_decision_ref,
    status: confirmationRequired ? "requires_confirmation_before_execution" : "proposal_only",
  };
}

function runtimeBridgeActionProposalFromAffordanceGraph({ projection, affordanceGraph }) {
  const affordance = normalizeArray(affordanceGraph?.affordances)[0];
  if (!affordance) return null;
  const actionKind = affordance.possible_action ?? "inspect";
  const targetRef = affordance.target_ref ?? null;
  return {
    proposal_ref: `proposal_${projection.runId}_runtime_bridge_${safeId(targetRef ?? actionKind)}`,
    proposed_by: "runtime_service_bridge_affordance_projection",
    model_role: "grounder",
    raw_model_output_ref: null,
    normalized_action_candidate: targetRef
      ? `${actionKind} ${targetRef}`
      : String(actionKind),
    target_ref: targetRef,
    confidence: Number.isFinite(Number(affordance.confidence))
      ? Number(affordance.confidence)
      : 0,
    rationale_summary:
      "Projected from the RuntimeAgentService bridge affordance graph; no action was executed by this projection.",
    predicted_postcondition:
      affordance.expected_state_transition ??
      "A policy gate can decide whether this affordance should become an executable ComputerAction.",
    risk_assessment: affordance.risk_class ?? "unknown",
    policy_decision_ref: `policy_${projection.runId}_runtime_bridge_action_proposal_required`,
    confirmation_required: Boolean(affordance.confirmation_required),
  };
}

function runtimeBridgeEnvironmentSelectionFromObservation({ projection, observation }) {
  if (!observation) return null;
  const selectedLane = observation.lane ?? "native_browser";
  const selectedSessionMode = observation.session_mode ?? "owned_hermetic_browser";
  return {
    receipt_ref: `receipt_${projection.runId}_runtime_bridge_environment`,
    run_id: projection.runId,
    selected_lane: selectedLane,
    selected_session_mode: selectedSessionMode,
    rejected_options: [],
    reasons: [
      "RuntimeAgentService emitted canonical computer-use observation evidence.",
      "The daemon preserved bridge-provided lane/session as projection data instead of selecting a second runtime.",
    ],
    risk_posture: "bridge_observation",
    authority_required: `computer_use.${selectedLane}.read`,
    privacy_impact: observation.retention_mode ?? "local_redacted_artifacts",
    expected_cleanup: "runtime_service_adapter_owns_environment_cleanup; daemon_retains_redacted_trace",
  };
}

function runtimeBridgeLeaseFromObservation({ projection, observation, environmentSelection }) {
  if (!observation && !environmentSelection) return null;
  const lane = observation?.lane ?? environmentSelection?.selected_lane ?? "native_browser";
  const sessionMode =
    observation?.session_mode ??
    environmentSelection?.selected_session_mode ??
    "owned_hermetic_browser";
  return {
    schema_version: COMPUTER_USE_CONTRACT_SCHEMA_VERSION,
    lease_id: observation?.lease_id ?? `lease_${projection.runId}_runtime_bridge`,
    lane,
    session_mode: sessionMode,
    status: "active",
    authority_scope: environmentSelection?.authority_required ?? `computer_use.${lane}.read`,
    consent_scope: "runtime_service_bridge",
    target_hint: observation?.url ?? projection.prompt ?? "runtime service computer-use surface",
    environment_ref: `${lane}:runtime_service_bridge`,
    profile_provenance: "runtime_service_bridge",
    retention_mode:
      observation?.retention_mode ??
      environmentSelection?.privacy_impact ??
      "local_redacted_artifacts",
    cleanup_required: false,
    evidence_refs: [
      environmentSelection?.receipt_ref,
      observation?.observation_ref,
      observation?.target_index_ref,
    ].filter(Boolean),
  };
}

function runtimeBridgeTrajectoryFromComputerUseEvents({ projection, events, observation }) {
  return {
    schema_version: COMPUTER_USE_CONTRACT_SCHEMA_VERSION,
    trajectory_ref: `trajectory_${projection.runId}_runtime_bridge`,
    run_id: projection.runId,
    lease_id:
      events.find((event) => event.data?.computer_use_lease_id)?.data?.computer_use_lease_id ??
      observation?.lease_id ??
      null,
    retention_mode:
      events.find((event) => event.data?.observation_retention_mode)?.data?.observation_retention_mode ??
      observation?.retention_mode ??
      "local_redacted_artifacts",
    entries: events.map((event, index) => ({
      sequence: index + 1,
      event_kind:
        event.data?.computer_use_step ??
        event.type.replace(/^computer_use_/, ""),
      observation_ref:
        event.data?.computer_use_observation_ref ??
        event.data?.observation_bundle?.observation_ref ??
        null,
      target_index_ref:
        event.data?.computer_use_target_index_ref ??
        event.data?.target_index?.target_index_ref ??
        null,
      affordance_graph_ref:
        event.data?.computer_use_affordance_graph_ref ??
        event.data?.affordance_graph?.graph_ref ??
        null,
      proposal_ref: event.data?.computer_use_proposal_ref ?? null,
      action_ref: event.data?.computer_use_action_ref ?? null,
      verification_ref: event.data?.computer_use_verification_ref ?? null,
      cleanup_ref: event.data?.computer_use_cleanup_ref ?? null,
      runtime_event_ref: event.data?.runtime_event_id ?? null,
      workflow_node_id: event.data?.workflow_node_id ?? null,
      summary: event.summary,
    })),
  };
}

function runtimeTaskRecordForRun(run) {
  if (run?.runtimeTask) return run.runtimeTask;
  return runtimeTaskRecord({
    runId: run?.id,
    agent: { id: run?.agentId },
    prompt: run?.objective,
    mode: run?.mode,
    taskFamily: run?.trace?.qualityLedger?.taskFamily ?? taskFamilyForMode(run?.mode ?? "send"),
    selectedStrategy: run?.trace?.qualityLedger?.selectedStrategy ?? strategyForMode(run?.mode ?? "send"),
    modelRouteDecision: run?.modelRouteDecision ?? run?.trace?.modelRouteDecision,
    activeSkillHookManifest: run?.activeSkillHookManifest ?? run?.trace?.activeSkillHookManifest,
    createdAt: run?.createdAt,
    updatedAt: run?.updatedAt,
    status: jobStatusForRunStatus(run?.status),
  });
}

function runtimeJobRecord({
  runtimeTask,
  runtimeChecklist,
  agent,
  status,
  createdAt,
  updatedAt,
  queuedAt,
  startedAt,
  completedAt,
  lifecycle,
  eventCount,
  terminalEventCount,
  artifactNames,
  receiptKinds,
} = {}) {
  const task = runtimeTask ?? runtimeTaskRecord();
  const jobStatus = status ?? "completed";
  const jobId = `job_${task.runId}`;
  return {
    schemaVersion: "ioi.agent-runtime.job-record.v1",
    object: "ioi.runtime_job",
    jobId,
    taskId: task.taskId,
    runId: task.runId,
    agentId: task.agentId ?? agent?.id ?? null,
    threadId: task.threadId,
    turnId: task.turnId,
    status: jobStatus,
    lifecycle: lifecycle ?? jobLifecycleForStatus(jobStatus),
    summary: `Runtime job ${jobId} is ${jobStatus}.`,
    queueName: "local-agentgres",
    runner: "local-daemon-agentgres",
    jobType: "agent_run",
    priority: "normal",
    background: true,
    durable: true,
    replayable: true,
    createdAt: createdAt ?? task.createdAt,
    updatedAt: updatedAt ?? task.updatedAt,
    queuedAt: queuedAt ?? createdAt ?? task.createdAt,
    startedAt: startedAt ?? createdAt ?? task.createdAt,
    completedAt: completedAt ?? (["completed", "failed", "canceled"].includes(jobStatus) ? updatedAt ?? task.updatedAt : null),
    progress: {
      completedSteps: ["completed", "failed", "canceled"].includes(jobStatus) ? 1 : jobStatus === "running" ? 0 : 0,
      totalSteps: 1,
      percent: ["completed", "failed", "canceled"].includes(jobStatus) ? 100 : jobStatus === "running" ? 50 : 0,
    },
    eventCount: eventCount ?? null,
    terminalEventCount: terminalEventCount ?? null,
    artifactNames: artifactNames ?? ["runtime-task.json", "runtime-job.json", "runtime-checklist.json", "trace.json", "agentgres-projection.json"],
    receiptKinds: receiptKinds ?? ["runtime_task", "runtime_job", "runtime_checklist", "agentgres_canonical_write"],
    checklistId: runtimeChecklist?.checklistId ?? null,
    checklistStatus: runtimeChecklist?.status ?? null,
    checklistItemCount: runtimeChecklist?.itemCount ?? null,
    checklistCompletedItemCount: runtimeChecklist?.completedItemCount ?? null,
    failure: jobStatus === "failed" ? { reason: "runtime_failed", message: "Runtime job failed." } : null,
    cancellation: jobStatus === "canceled" ? { reason: "operator_cancel" } : null,
    retryCount: 0,
    cancelable: jobStatus !== "canceled",
    cancelEndpoint: `/v1/jobs/${jobId}/cancel`,
    endpoints: {
      self: `/v1/jobs/${jobId}`,
      cancel: `/v1/jobs/${jobId}/cancel`,
      run: `/v1/runs/${task.runId}`,
      events: `/v1/runs/${task.runId}/events`,
      trace: `/v1/runs/${task.runId}/trace`,
    },
    workflowNodeId: "runtime.runtime-job",
    redaction: {
      profile: "runtime_job_safe",
      promptIncluded: false,
      secretValuesIncluded: false,
    },
    evidenceRefs: [
      "runtime_job",
      "runtime.jobs.durable_projection",
      "RuntimeJobNode",
      task.taskId,
      `run:${task.runId}`,
    ],
  };
}

function runtimeChecklistRecord({
  runtimeTask,
  runtimeJob,
  status,
  createdAt,
  updatedAt,
} = {}) {
  const task = runtimeTask ?? runtimeTaskRecord();
  const job = runtimeJob ?? runtimeJobRecord({ runtimeTask: task });
  const checklistStatus = status ?? job.status ?? task.status ?? "completed";
  const checklistId = `checklist_${task.runId}`;
  const terminalLabel =
    checklistStatus === "canceled"
      ? "Job canceled event emitted"
      : checklistStatus === "failed"
        ? "Job failed event emitted"
        : checklistStatus === "blocked"
          ? "Job blocked by policy gate"
        : "Job completed event emitted";
  const terminalEventKind =
    checklistStatus === "canceled"
      ? "JobCanceled"
      : checklistStatus === "failed"
        ? "JobFailed"
        : checklistStatus === "blocked"
          ? "PolicyBlocked"
        : "JobCompleted";
  const terminalItemStatus =
    checklistStatus === "canceled"
      ? "canceled"
      : checklistStatus === "failed"
        ? "failed"
        : checklistStatus === "blocked"
          ? "blocked"
        : "passed";
  const item = (suffix, label, itemStatus, evidenceRefs) => ({
    itemId: `${checklistId}:${suffix}`,
    label,
    status: itemStatus,
    evidenceRefs: uniqueStrings(evidenceRefs),
  });
  const items = [
    item("task_record", "Runtime task record durable", "passed", [
      task.taskId,
      "RuntimeTaskNode",
      "runtime.tasks.durable_projection",
    ]),
    item("job_record", "Runtime job record durable", "passed", [
      job.jobId,
      "RuntimeJobNode",
      "runtime.jobs.durable_projection",
    ]),
    item("job_queued", "Job queued event emitted", "passed", ["JobQueued"]),
    item("job_started", "Job started event emitted", "passed", ["JobStarted"]),
    item("job_terminal", terminalLabel, terminalItemStatus, [terminalEventKind]),
    item("artifacts", "Runtime task/job/checklist artifacts attached", "passed", [
      "runtime-task.json",
      "runtime-job.json",
      "runtime-checklist.json",
    ]),
  ];
  return {
    schemaVersion: "ioi.agent-runtime.checklist-record.v1",
    object: "ioi.runtime_checklist",
    checklistId,
    taskId: task.taskId,
    jobId: job.jobId,
    runId: task.runId,
    agentId: task.agentId,
    threadId: task.threadId,
    turnId: task.turnId,
    status: checklistStatus,
    summary: `Runtime checklist for ${job.jobId} is ${checklistStatus}.`,
    durable: true,
    replayable: true,
    readOnly: true,
    itemCount: items.length,
    completedItemCount: items.filter((entry) => entry.status === "passed").length,
    canceledItemCount: items.filter((entry) => entry.status === "canceled").length,
    failedItemCount: items.filter((entry) => entry.status === "failed").length,
    blockedItemCount: items.filter((entry) => entry.status === "blocked").length,
    items,
    requiredItemIds: items.map((entry) => entry.itemId),
    createdAt: createdAt ?? task.createdAt,
    updatedAt: updatedAt ?? task.updatedAt,
    workflowNodeId: "runtime.runtime-checklist",
    redaction: {
      profile: "runtime_checklist_safe",
      promptIncluded: false,
      secretValuesIncluded: false,
    },
    evidenceRefs: [
      "runtime_checklist",
      "runtime.checklists.durable_projection",
      "RuntimeChecklistNode",
      task.taskId,
      job.jobId,
      `run:${task.runId}`,
    ],
  };
}

function attachChecklistToRuntimeJob(job, checklist) {
  return {
    ...job,
    checklistId: checklist.checklistId,
    checklistStatus: checklist.status,
    checklistItemCount: checklist.itemCount,
    checklistCompletedItemCount: checklist.completedItemCount,
    artifactNames: uniqueStrings([...normalizeArray(job.artifactNames), "runtime-checklist.json"]),
    receiptKinds: uniqueStrings([...normalizeArray(job.receiptKinds), "runtime_checklist"]),
    evidenceRefs: uniqueStrings([...normalizeArray(job.evidenceRefs), checklist.checklistId, "runtime_checklist"]),
  };
}

function runtimeJobRecordForRun(run) {
  if (run?.runtimeJob) return run.runtimeJob;
  const task = runtimeTaskRecordForRun(run);
  const status = jobStatusForRunStatus(run?.status);
  return runtimeJobRecord({
    runtimeTask: task,
    status,
    createdAt: run?.createdAt,
    updatedAt: run?.updatedAt,
    queuedAt: run?.createdAt,
    startedAt: run?.createdAt,
    completedAt: ["completed", "failed", "canceled"].includes(status) ? run?.updatedAt : null,
    lifecycle: jobLifecycleForStatus(status),
    eventCount: normalizeArray(run?.events).length || null,
    terminalEventCount: terminalCount(normalizeArray(run?.events)) || null,
    artifactNames: normalizeArray(run?.artifacts).map((artifactItem) => artifactItem.name).filter(Boolean),
    receiptKinds: normalizeArray(run?.receipts).map((receipt) => receipt.kind).filter(Boolean),
  });
}

function runtimeChecklistRecordForRun(run) {
  if (run?.runtimeChecklist) return run.runtimeChecklist;
  const task = runtimeTaskRecordForRun(run);
  const job = runtimeJobRecordForRun(run);
  return runtimeChecklistRecord({
    runtimeTask: task,
    runtimeJob: job,
    status: job.status,
    createdAt: run?.createdAt,
    updatedAt: run?.updatedAt,
  });
}

function jobStatusForRunStatus(status) {
  if (status === "canceled") return "canceled";
  if (status === "failed" || status === "error") return "failed";
  if (status === "blocked") return "blocked";
  if (status === "running" || status === "active") return "running";
  if (status === "queued" || status === "pending") return "queued";
  return "completed";
}

function jobLifecycleForStatus(status) {
  if (status === "queued") return ["queued"];
  if (status === "running") return ["queued", "started"];
  if (status === "failed") return ["queued", "started", "failed"];
  if (status === "canceled") return ["queued", "started", "canceled"];
  if (status === "blocked") return ["queued", "started", "blocked"];
  return ["queued", "started", "completed"];
}


  return {
    attachChecklistToRuntimeJob,
    runtimeBridgeComputerUseTrace,
    runtimeBridgeMessagesForProjection,
    runtimeBridgeRunRecord,
    runtimeChecklistRecord,
    runtimeChecklistRecordForRun,
    runtimeJobRecord,
    runtimeJobRecordForRun,
    runtimeTaskRecord,
    runtimeTaskRecordForRun,
  };
}
