import {
  LSP_DIAGNOSTICS_BLOCKING_GATE_NODE_ID,
  LSP_DIAGNOSTICS_BLOCKING_GATE_SCHEMA_VERSION,
  LSP_DIAGNOSTICS_INJECTION_NODE_ID,
  LSP_DIAGNOSTICS_INJECTION_SCHEMA_VERSION,
} from "./runtime-contract-constants.mjs";

export function createDiagnosticsFeedbackHelpers({
  diagnosticsRepairContextForPayload,
  diagnosticsRepairPolicyConfig,
  diagnosticsRepairPolicyConfigForContexts,
  diagnosticsRollbackRepairPolicy,
  doctorHash,
  eventStreamIdForThread,
  maxInjectedFindings,
  maxInjectedMessageChars,
  normalizeArray,
  normalizeDiagnosticsMode,
  optionalString,
  uniqueStrings,
} = {}) {
  function postEditDiagnosticsConfig(request = {}, input = {}) {
    const packRoot = request.tool_pack ?? request.options?.tool_pack ?? {};
    const pack = packRoot?.coding ?? packRoot;
    const repairPolicyConfig = diagnosticsRepairPolicyConfig(request, input);
    const mode = normalizeDiagnosticsMode(
      request.diagnostics_mode ??
        input.diagnostics_mode ??
        pack.diagnostics_mode ??
        pack.diagnostic_mode ??
        "advisory",
    );
    return {
      mode,
      commandId: optionalString(
        request.diagnostic_command_id ??
          input.diagnostic_command_id ??
          pack.default_diagnostic_command_id,
      ) ?? "auto",
      cwd: optionalString(input.cwd ?? request.cwd) ?? ".",
      timeoutMs:
        input.diagnostic_timeout_ms ??
        request.diagnostic_timeout_ms ??
        pack.timeout_ms ??
        30000,
      maxOutputBytes:
        input.diagnostic_max_output_bytes ??
        request.diagnostic_max_output_bytes ??
        4096,
      repairPolicyConfig,
    };
  }

  function diagnosticsRepairRetryFeedback({
    threadId,
    request = {},
    gateEvent,
    repairPolicy,
    snapshotId = null,
  } = {}) {
    const payload = gateEvent?.payload_summary ?? gateEvent?.payload ?? {};
    const findings = normalizeArray(payload.findings);
    const diagnosticStatus = optionalString(payload.diagnostic_status) ?? "findings";
    const diagnosticCount = Number(payload.diagnostic_count ?? findings.length) || findings.length;
    const injectedFindingCount =
      Number(payload.injected_finding_count ?? findings.length) || findings.length;
    const omittedFindingCount = Number(payload.omitted_finding_count ?? 0) || 0;
    const rollbackRefs = uniqueStrings([
      snapshotId,
      ...normalizeArray(payload.rollback_refs),
      ...normalizeArray(repairPolicy?.rollback_refs),
    ]);
    const workspaceSnapshotRefs = uniqueStrings([
      snapshotId,
      ...normalizeArray(payload.workspace_snapshot_refs),
      ...normalizeArray(repairPolicy?.workspace_snapshot_refs),
    ]);
    const diagnosticEventIds = uniqueStrings(normalizeArray(payload.diagnostic_event_ids));
    const promptText =
      optionalString(request.repair_prompt_text) ??
      diagnosticsPromptText({
        diagnosticStatus,
        mode: "repair_retry",
        visibleFindings: findings.slice(0, maxInjectedFindings),
        omittedCount: omittedFindingCount,
      });
    return {
      schema_version: LSP_DIAGNOSTICS_INJECTION_SCHEMA_VERSION,
      object: "ioi.runtime_lsp_diagnostics_injection",
      injection_id: `lsp_diagnostics_repair_retry_${doctorHash(
        `${threadId}:${gateEvent?.event_id ?? ""}:${diagnosticEventIds.join(",")}`,
      ).slice(0, 16)}`,
      thread_id: threadId,
      mode: "repair_retry",
      blocking: false,
      diagnostic_status: diagnosticStatus,
      diagnostic_count: diagnosticCount,
      injected_finding_count: injectedFindingCount,
      omitted_finding_count: omittedFindingCount,
      findings,
      diagnostic_event_ids: diagnosticEventIds,
      rollback_refs: rollbackRefs,
      workspace_snapshot_refs: workspaceSnapshotRefs,
      source_tool_call_ids: uniqueStrings(normalizeArray(payload.source_tool_call_ids)),
      repair_policy: repairPolicy,
      receipt_refs: uniqueStrings(normalizeArray(payload.receipt_refs)),
      receipt_id: null,
      summary: `Repair retry injected ${injectedFindingCount} diagnostic finding(s) into a new turn.`,
      prompt_text: promptText,
    };
  }

  function compactDiagnosticsFeedback({ threadId, mode, diagnosticEvents }) {
    const findings = [];
    const statuses = [];
    const diagnosticEventIds = [];
    const receiptRefs = [];
    const rollbackRefs = [];
    const diagnosticsRepairContexts = [];
    for (const event of diagnosticEvents) {
      const payload = event.payload_summary ?? event.payload ?? {};
      const result = payload.result ?? {};
      const repairContext = diagnosticsRepairContextForPayload(payload);
      diagnosticEventIds.push(event.event_id);
      receiptRefs.push(...normalizeArray(event.receipt_refs));
      rollbackRefs.push(...normalizeArray(event.rollback_refs));
      if (repairContext) {
        diagnosticsRepairContexts.push(repairContext);
        rollbackRefs.push(...normalizeArray(repairContext.rollback_refs));
        const contextSnapshotId = optionalString(repairContext.workspace_snapshot_id);
        if (contextSnapshotId) rollbackRefs.push(contextSnapshotId);
      }
      statuses.push(result.diagnostic_status ?? payload.result_summary?.diagnostic_status ?? "clean");
      for (const diagnostic of normalizeArray(result.diagnostics)) {
        findings.push(compactDiagnosticFinding(diagnostic, event));
      }
    }
    const visibleFindings = findings.slice(0, maxInjectedFindings);
    const diagnosticStatus = statuses.includes("findings")
      ? "findings"
      : statuses.includes("degraded")
        ? "degraded"
        : "clean";
    const omittedCount = Math.max(0, findings.length - visibleFindings.length);
    const summary =
      diagnosticStatus === "findings"
        ? `Injected ${visibleFindings.length}${omittedCount ? ` of ${findings.length}` : ""} post-edit diagnostic finding(s).`
        : `Injected post-edit diagnostics status: ${diagnosticStatus}.`;
    const injectionId = `lsp_diagnostics_injection_${doctorHash(
      `${threadId}:${diagnosticEventIds.join(",")}:${mode}`,
    ).slice(0, 16)}`;
    const uniqueRollbackRefs = uniqueStrings(rollbackRefs);
    const workspaceSnapshotRefs = uniqueStrings([
      ...uniqueRollbackRefs,
      ...diagnosticsRepairContexts.map((context) =>
        optionalString(context.workspace_snapshot_id),
      ),
    ]);
    const sourceToolCallIds = uniqueStrings(
      diagnosticsRepairContexts.map((context) =>
        optionalString(context.source_tool_call_id),
      ),
    );
    const repairPolicyConfig = diagnosticsRepairPolicyConfigForContexts(diagnosticsRepairContexts);
    const repairPolicy = diagnosticsRollbackRepairPolicy({
      threadId,
      injectionId,
      mode,
      diagnosticStatus,
      diagnosticCount: findings.length,
      workspaceSnapshotRefs,
      rollbackRefs: uniqueRollbackRefs,
      sourceToolCallIds,
      restorePolicy: repairPolicyConfig.restore_policy,
      restoreConflictPolicy: repairPolicyConfig.restore_conflict_policy,
      diagnosticsRepairDefault: repairPolicyConfig.diagnostics_repair_default,
      operatorOverrideRequiresApproval: repairPolicyConfig.operator_override_requires_approval,
    });
    return {
      schema_version: LSP_DIAGNOSTICS_INJECTION_SCHEMA_VERSION,
      object: "ioi.runtime_lsp_diagnostics_injection",
      injection_id: injectionId,
      thread_id: threadId,
      mode,
      blocking: mode === "blocking",
      diagnostic_status: diagnosticStatus,
      diagnostic_count: findings.length,
      injected_finding_count: visibleFindings.length,
      omitted_finding_count: omittedCount,
      findings: visibleFindings,
      diagnostic_event_ids: diagnosticEventIds,
      rollback_refs: uniqueRollbackRefs,
      workspace_snapshot_refs: workspaceSnapshotRefs,
      source_tool_call_ids: sourceToolCallIds,
      diagnostics_repair_contexts: diagnosticsRepairContexts,
      repair_policy_config: repairPolicyConfig,
      repair_policy: repairPolicy,
      receipt_refs: uniqueStrings(receiptRefs),
      receipt_id: null,
      summary,
      prompt_text: diagnosticsPromptText({ diagnosticStatus, mode, visibleFindings, omittedCount }),
    };
  }

  function compactDiagnosticFinding(diagnostic = {}, event = {}) {
    const location = [
      optionalString(diagnostic.path) ?? "workspace",
      diagnostic.line ? String(diagnostic.line) : null,
      diagnostic.column ? String(diagnostic.column) : null,
    ].filter(Boolean).join(":");
    const message = String(diagnostic.message ?? "Diagnostic finding.").slice(
      0,
      maxInjectedMessageChars,
    );
    return {
      path: optionalString(diagnostic.path) ?? null,
      line: Number(diagnostic.line ?? 0) || null,
      column: Number(diagnostic.column ?? 0) || null,
      severity: optionalString(diagnostic.severity) ?? "warning",
      source: optionalString(diagnostic.source) ?? "lsp.diagnostics",
      code: optionalString(diagnostic.code) ?? null,
      message,
      location,
      diagnostic_event_id: event.event_id ?? null,
    };
  }

  function diagnosticsPromptText({ diagnosticStatus, mode, visibleFindings, omittedCount }) {
    const header = `Post-edit diagnostics (${mode}, ${diagnosticStatus})`;
    if (!visibleFindings.length) return `${header}: no findings were reported.`;
    const lines = visibleFindings.map((finding) =>
      `- ${finding.location} [${finding.severity}${finding.code ? ` ${finding.code}` : ""}] ${finding.message}`,
    );
    if (omittedCount > 0) lines.push(`- ${omittedCount} additional finding(s) omitted from compact context.`);
    return `${header}:\n${lines.join("\n")}`;
  }

  function promptWithDiagnosticsFeedback(prompt, diagnosticsFeedback) {
    if (!diagnosticsFeedback?.prompt_text) return prompt;
    return `${diagnosticsFeedback.prompt_text}\n\nUser request:\n${prompt}`;
  }

  function diagnosticsFeedbackBlocksContinuation(diagnosticsFeedback) {
    return Boolean(
      diagnosticsFeedback?.blocking &&
        diagnosticsFeedback?.diagnostic_status === "findings" &&
        Number(diagnosticsFeedback?.diagnostic_count ?? 0) > 0,
    );
  }

  function diagnosticsBlockingGateForFeedback(diagnosticsFeedback) {
    if (!diagnosticsFeedbackBlocksContinuation(diagnosticsFeedback)) return null;
    const injectionId = diagnosticsFeedback.injection_id ?? `diagnostics_${doctorHash(JSON.stringify(diagnosticsFeedback)).slice(0, 16)}`;
    const gateId = `lsp_diagnostics_gate_${doctorHash(injectionId).slice(0, 16)}`;
    const diagnosticCount = Number(diagnosticsFeedback.diagnostic_count ?? 0) || 0;
    const injectedFindingCount = Number(diagnosticsFeedback.injected_finding_count ?? diagnosticCount) || 0;
    const repairPolicy =
      diagnosticsFeedback.repair_policy ??
      diagnosticsRollbackRepairPolicy({
        threadId: diagnosticsFeedback.thread_id ?? null,
        injectionId,
        mode: diagnosticsFeedback.mode ?? "blocking",
        diagnosticStatus: diagnosticsFeedback.diagnostic_status,
        diagnosticCount,
        workspaceSnapshotRefs: uniqueStrings(normalizeArray(diagnosticsFeedback.workspace_snapshot_refs)),
        rollbackRefs: uniqueStrings(normalizeArray(diagnosticsFeedback.rollback_refs)),
        sourceToolCallIds: uniqueStrings(normalizeArray(diagnosticsFeedback.source_tool_call_ids)),
        restorePolicy: diagnosticsFeedback.repair_policy_config?.restore_policy,
        restoreConflictPolicy: diagnosticsFeedback.repair_policy_config?.restore_conflict_policy,
        diagnosticsRepairDefault: diagnosticsFeedback.repair_policy_config?.diagnostics_repair_default,
        operatorOverrideRequiresApproval: diagnosticsFeedback.repair_policy_config?.operator_override_requires_approval,
      });
    const rollbackRefs = uniqueStrings(normalizeArray(repairPolicy.rollback_refs));
    const workspaceSnapshotRefs = uniqueStrings(normalizeArray(repairPolicy.workspace_snapshot_refs));
    const summary = `Blocking diagnostics gate paused model continuation after ${diagnosticCount} finding(s).`;
    return {
      schema_version: LSP_DIAGNOSTICS_BLOCKING_GATE_SCHEMA_VERSION,
      object: "ioi.runtime_lsp_diagnostics_blocking_gate",
      gate_id: gateId,
      policy_decision_id: null,
      policy_decision_refs: [],
      receipt_id: null,
      status: "blocked",
      decision: "block_model_continuation",
      reason: "post_edit_diagnostics_findings",
      mode: diagnosticsFeedback.mode ?? "blocking",
      blocking: true,
      requires_input: true,
      diagnostic_status: diagnosticsFeedback.diagnostic_status,
      diagnostic_count: diagnosticCount,
      injected_finding_count: injectedFindingCount,
      omitted_finding_count: Number(diagnosticsFeedback.omitted_finding_count ?? 0) || 0,
      injection_id: injectionId,
      diagnostics_receipt_id: diagnosticsFeedback.receipt_id ?? null,
      diagnostic_event_ids: uniqueStrings(normalizeArray(diagnosticsFeedback.diagnostic_event_ids)),
      rollback_refs: rollbackRefs,
      workspace_snapshot_refs: workspaceSnapshotRefs,
      source_tool_call_ids: uniqueStrings(normalizeArray(diagnosticsFeedback.source_tool_call_ids)),
      findings: normalizeArray(diagnosticsFeedback.findings).slice(0, maxInjectedFindings),
      repair_policy: repairPolicy,
      repair_decisions: normalizeArray(repairPolicy.decisions),
      summary,
      message:
        `Blocking diagnostics mode found ${diagnosticCount} post-edit diagnostic finding(s). ` +
        "Model continuation is paused until the findings are repaired, a snapshot restore is previewed/applied with approval, or an operator override is granted.",
      recommended_next_actions: normalizeArray(repairPolicy.decisions)
        .filter((decision) => ["available", "requires_approval"].includes(decision?.status))
        .map((decision) =>
          decision?.action === "restore_apply" ? "restore_apply_with_approval" : decision?.action,
        )
        .filter(Boolean),
      workflow_node_id: LSP_DIAGNOSTICS_BLOCKING_GATE_NODE_ID,
      component_kind: "lsp_diagnostics_gate",
      redaction: "lsp_diagnostics_safe",
    };
  }

  function requestWithDiagnosticsFeedback(request = {}, diagnosticsFeedback = null) {
    if (!diagnosticsFeedback) return request;
    return {
      ...request,
      diagnostics_feedback: diagnosticsFeedback,
      context: {
        ...(request.context ?? {}),
        diagnostics_feedback: diagnosticsFeedback,
      },
    };
  }

  function insertRuntimeBridgeDiagnosticsInjectionEvent({
    projection,
    agent,
    threadId,
    diagnosticsFeedback,
  }) {
    const event = {
      event_stream_id: eventStreamIdForThread(threadId),
      thread_id: threadId,
      turn_id: projection.turnId,
      item_id: `${projection.turnId}:item:lsp-diagnostics-injection`,
      idempotency_key: `turn:${projection.turnId}:lsp-diagnostics-injected:${diagnosticsFeedback.injection_id}`,
      source: "runtime_auto",
      source_event_kind: "LspDiagnostics.Injected",
      event_kind: "lsp.diagnostics.injected",
      status: diagnosticsFeedback.blocking && diagnosticsFeedback.diagnostic_status === "findings" ? "blocked" : "completed",
      actor: "runtime",
      created_at: projection.createdAt,
      workspace_root: agent.cwd,
      workflow_node_id: LSP_DIAGNOSTICS_INJECTION_NODE_ID,
      component_kind: "lsp_diagnostics",
      payload_schema_version: LSP_DIAGNOSTICS_INJECTION_SCHEMA_VERSION,
      payload: {
        ...diagnosticsFeedback,
        event_kind: "LspDiagnosticsInjected",
        run_id: projection.runId,
        turn_id: projection.turnId,
      },
      receipt_refs: uniqueStrings(normalizeArray(diagnosticsFeedback.receipt_refs)),
      artifact_refs: [],
    };
    const events = [...normalizeArray(projection.events)];
    const turnStartedIndex = events.findIndex((candidate) => candidate?.event_kind === "turn.started");
    if (turnStartedIndex >= 0) {
      events.splice(turnStartedIndex + 1, 0, event);
      return events;
    }
    return [event, ...events];
  }

  return {
    compactDiagnosticFinding,
    compactDiagnosticsFeedback,
    diagnosticsBlockingGateForFeedback,
    diagnosticsFeedbackBlocksContinuation,
    diagnosticsPromptText,
    diagnosticsRepairRetryFeedback,
    insertRuntimeBridgeDiagnosticsInjectionEvent,
    postEditDiagnosticsConfig,
    promptWithDiagnosticsFeedback,
    requestWithDiagnosticsFeedback,
  };
}
