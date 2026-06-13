import { eventStreamIdForThread } from "./runtime-identifiers.mjs";

const RETIRED_PENDING_DIAGNOSTICS_FEEDBACK_REQUEST_ALIASES = [
  "diagnosticsMode",
  "options.diagnosticsMode",
];

export function createRuntimeDiagnosticsFeedbackSurface(deps = {}) {
  const {
    compactDiagnosticsFeedback,
    diagnosticsFeedbackPlanner,
    diagnosticsRepairPolicyProjector,
    normalizeDiagnosticsMode,
  } = deps;

  function maybeRunPostEditDiagnostics(
    store,
    {
      threadId,
      turnId,
      patchToolCallId,
      patchResult,
      request = {},
      input = {},
      workflowGraphId = null,
    } = {},
  ) {
    if (
      !diagnosticsFeedbackPlanner ||
      typeof diagnosticsFeedbackPlanner.planPostEditDiagnosticsFeedback !== "function"
    ) {
      throw runtimeDiagnosticsFeedbackRustCoreRequired({
        operation: "post_edit_diagnostics_feedback_plan",
        operation_kind: "runtime.post_edit_diagnostics_feedback",
        thread_id: threadId ?? null,
        turn_id: turnId || null,
        patch_tool_call_id: patchToolCallId ?? null,
        workflow_graph_id: workflowGraphId ?? null,
        evidence_refs: [
          "post_edit_diagnostics_feedback_js_planner_retired",
          "rust_daemon_core_post_edit_diagnostics_feedback_plan_required",
        ],
      });
    }
    const plan = diagnosticsFeedbackPlanner.planPostEditDiagnosticsFeedback({
      thread_id: threadId,
      turn_id: turnId || null,
      patch_tool_call_id: patchToolCallId,
      workflow_graph_id: workflowGraphId,
      request,
      input,
      patch_result: patchResult ?? null,
    });
    if (plan?.skipped || plan?.status === "skipped" || plan?.record?.status === "skipped") {
      return null;
    }
    const diagnosticsRequest = plan?.request ?? plan?.record?.request ?? null;
    if (!diagnosticsRequest || typeof diagnosticsRequest !== "object" || Array.isArray(diagnosticsRequest)) {
      throw runtimeDiagnosticsFeedbackRustCoreRequired({
        operation: "post_edit_diagnostics_feedback_plan",
        operation_kind: "runtime.post_edit_diagnostics_feedback",
        thread_id: threadId ?? null,
        turn_id: turnId || null,
        patch_tool_call_id: patchToolCallId ?? null,
        workflow_graph_id: workflowGraphId ?? null,
        evidence_refs: [
          "post_edit_diagnostics_feedback_missing_rust_plan_request",
          "rust_daemon_core_post_edit_diagnostics_feedback_plan_required",
        ],
      });
    }
    const toolId = plan?.tool_id ?? plan?.record?.tool_id ?? "lsp.diagnostics";
    return store.codingToolInvocationSurface.invokeThreadTool(
      store,
      threadId,
      toolId,
      diagnosticsRequest,
    );
  }

  function pendingDiagnosticsFeedbackForNextTurn(store, threadId, request = {}) {
    assertCanonicalPendingDiagnosticsFeedbackRequest(request);
    const injectionMode = normalizeDiagnosticsMode(
      request.diagnostics_mode ??
        request.options?.diagnostics_mode ??
        "advisory",
    );
    if (injectionMode === "skip") return null;
    const stream = store.runtimeEventStream(eventStreamIdForThread(threadId));
    const lastInjectedSeq = Math.max(
      0,
      ...stream.events
        .filter((event) => event.event_kind === "lsp.diagnostics.injected")
        .map((event) => Number(event.seq) || 0),
    );
    const diagnosticEvents = stream.events.filter((event) => {
      const payload = event.payload_summary ?? event.payload ?? {};
      return (
        event.seq > lastInjectedSeq &&
        event.event_kind === "tool.completed" &&
        event.source === "runtime_auto" &&
        payload.tool_name === "lsp.diagnostics"
      );
    });
    if (!diagnosticEvents.length) return null;
    if (
      !diagnosticsRepairPolicyProjector ||
      typeof diagnosticsRepairPolicyProjector.projectRuntimeDiagnosticsRepairPolicy !== "function"
    ) {
      throw runtimeDiagnosticsFeedbackRustCoreRequired({
        operation: "runtime_diagnostics_repair_policy_projection",
        operation_kind: "runtime.diagnostics_repair_policy.projection",
        thread_id: threadId,
        evidence_refs: [
          "runtime_diagnostics_repair_policy_projection_rust_owned",
          "rust_daemon_core_diagnostics_repair_policy_required",
        ],
      });
    }
    return compactDiagnosticsFeedback({
      threadId,
      mode: injectionMode,
      diagnosticEvents,
      stateDir: store?.stateDir ?? null,
      diagnosticsRepairPolicyProjector,
    });
  }

  return {
    maybeRunPostEditDiagnostics,
    pendingDiagnosticsFeedbackForNextTurn,
  };
}

function runtimeDiagnosticsFeedbackRustCoreRequired(details = {}) {
  const error = new Error(
    "Post-edit diagnostics feedback requires direct Rust daemon-core planning.",
  );
  error.code = "runtime_diagnostics_feedback_rust_core_required";
  error.details = {
    rust_core_boundary: "runtime.post_edit_diagnostics_feedback",
    ...details,
  };
  throw error;
}

function assertCanonicalPendingDiagnosticsFeedbackRequest(request = {}) {
  const retiredAliases = [];
  if (Object.hasOwn(request, "diagnosticsMode")) {
    retiredAliases.push("diagnosticsMode");
  }
  if (
    request.options &&
    typeof request.options === "object" &&
    !Array.isArray(request.options) &&
    Object.hasOwn(request.options, "diagnosticsMode")
  ) {
    retiredAliases.push("options.diagnosticsMode");
  }
  if (retiredAliases.length === 0) return;
  const error = new Error(
    "Pending diagnostics feedback request aliases are retired; use canonical diagnostics_mode.",
  );
  error.code = "pending_diagnostics_feedback_request_aliases_retired";
  error.details = {
    retired_aliases: retiredAliases,
    canonical_fields: ["diagnostics_mode", "options.diagnostics_mode"],
  };
  throw error;
}
