import {
  LSP_DIAGNOSTICS_BLOCKING_GATE_NODE_ID,
  LSP_DIAGNOSTICS_BLOCKING_GATE_SCHEMA_VERSION,
  LSP_DIAGNOSTICS_INJECTION_NODE_ID,
  LSP_DIAGNOSTICS_INJECTION_SCHEMA_VERSION,
} from "./runtime-contract-constants.mjs";

export function createDiagnosticsFeedbackHelpers({
  diagnosticsRepairContextForPayload,
  doctorHash,
  eventStreamIdForThread,
  maxInjectedFindings,
  maxInjectedMessageChars,
  normalizeArray,
  normalizeDiagnosticsMode,
  optionalString,
  uniqueStrings,
} = {}) {
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

  function compactDiagnosticsFeedback({
    threadId,
    mode,
    diagnosticEvents,
    diagnosticsRepairPolicyProjector = null,
  }) {
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
    const policyProjection = projectDiagnosticsRepairPolicy({
      diagnosticsRepairPolicyProjector,
      request: {
        thread_id: threadId,
        injection_id: injectionId,
        mode,
        diagnostic_status: diagnosticStatus,
        diagnostic_count: findings.length,
        workspace_snapshot_refs: workspaceSnapshotRefs,
        rollback_refs: uniqueRollbackRefs,
        source_tool_call_ids: sourceToolCallIds,
        diagnostics_repair_contexts: diagnosticsRepairContexts,
        receipt_refs: uniqueStrings(receiptRefs),
      },
    });
    const repairPolicyConfig = policyProjection.repair_policy_config;
    const repairPolicy = policyProjection.repair_policy;
    const projectedReceiptRefs = uniqueStrings([
      ...receiptRefs,
      ...normalizeArray(policyProjection.receipt_refs),
    ]);
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
      receipt_refs: projectedReceiptRefs,
      receipt_id: null,
      policy_projection_hash: policyProjection.projection_hash,
      policy_projection_evidence_refs: uniqueStrings(normalizeArray(policyProjection.evidence_refs)),
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
    const repairPolicy = objectRecord(diagnosticsFeedback.repair_policy);
    if (!repairPolicy) {
      throwDiagnosticsRepairPolicyProjectionRequired({
        operation: "diagnostics_blocking_gate",
        operation_kind: "runtime.diagnostics_repair_policy.blocking_gate",
        thread_id: diagnosticsFeedback.thread_id ?? null,
        injection_id: injectionId,
        evidence_refs: [
          "runtime_diagnostics_repair_policy_projection_rust_owned",
          "rust_daemon_core_diagnostics_repair_policy_required",
        ],
      });
    }
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

  function projectDiagnosticsRepairPolicy({
    diagnosticsRepairPolicyProjector,
    request,
  } = {}) {
    if (
      !diagnosticsRepairPolicyProjector ||
      typeof diagnosticsRepairPolicyProjector.projectRuntimeDiagnosticsRepairPolicy !== "function"
    ) {
      throwDiagnosticsRepairPolicyProjectionRequired({
        operation: "runtime_diagnostics_repair_policy_projection",
        operation_kind: "runtime.diagnostics_repair_policy.projection",
        thread_id: request?.thread_id ?? null,
        injection_id: request?.injection_id ?? null,
        evidence_refs: [
          "runtime_diagnostics_repair_policy_projection_rust_owned",
          "rust_daemon_core_diagnostics_repair_policy_required",
        ],
      });
    }
    const projected = diagnosticsRepairPolicyProjector.projectRuntimeDiagnosticsRepairPolicy(request);
    const repairPolicy = objectRecord(projected?.repair_policy ?? projected?.policy);
    const repairPolicyConfig = objectRecord(projected?.repair_policy_config);
    if (
      !repairPolicy ||
      repairPolicy.object !== "ioi.runtime_diagnostics_rollback_repair_policy" ||
      !Array.isArray(repairPolicy.decisions) ||
      !Array.isArray(repairPolicy.decision_refs) ||
      !repairPolicyConfig
    ) {
      throwDiagnosticsRepairPolicyProjectionRequired({
        operation: "runtime_diagnostics_repair_policy_projection",
        operation_kind: "runtime.diagnostics_repair_policy.projection",
        thread_id: request?.thread_id ?? null,
        injection_id: request?.injection_id ?? null,
        evidence_refs: [
          "runtime_diagnostics_repair_policy_projection_invalid",
          "rust_daemon_core_diagnostics_repair_policy_required",
        ],
      });
    }
    return {
      repair_policy: repairPolicy,
      repair_policy_config: repairPolicyConfig,
      receipt_refs: uniqueStrings(normalizeArray(projected?.receipt_refs)),
      evidence_refs: uniqueStrings(normalizeArray(projected?.evidence_refs)),
      projection_hash: optionalString(projected?.projection_hash) ?? null,
    };
  }

  function objectRecord(value) {
    return value && typeof value === "object" && !Array.isArray(value) ? value : null;
  }

  function throwDiagnosticsRepairPolicyProjectionRequired(details = {}) {
    const error = new Error(
      "Diagnostics repair policy projection requires Rust daemon-core ownership.",
    );
    error.code = "runtime_diagnostics_repair_policy_projection_required";
    error.details = {
      rust_core_boundary: "runtime.diagnostics_repair_policy",
      ...details,
    };
    throw error;
  }

  return {
    compactDiagnosticFinding,
    compactDiagnosticsFeedback,
    diagnosticsBlockingGateForFeedback,
    diagnosticsFeedbackBlocksContinuation,
    diagnosticsPromptText,
    diagnosticsRepairRetryFeedback,
    insertRuntimeBridgeDiagnosticsInjectionEvent,
    promptWithDiagnosticsFeedback,
    requestWithDiagnosticsFeedback,
  };
}
