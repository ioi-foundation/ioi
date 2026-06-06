export function createRuntimeRunEventHelpers({
  isComputerUseRunEventType,
  normalizeArray,
  objectRecord,
  uniqueStrings,
} = {}) {
  function runtimeEventStatusForRunEvent(event) {
    if (isComputerUseRunEventType(event.type)) {
      if (event.type === "computer_use_environment_unavailable") return "blocked";
      return [
        "computer_use_action_executed",
        "computer_use_verification",
        "computer_use_commit_gate",
        "computer_use_trajectory_written",
        "computer_use_cleanup",
      ].includes(event.type)
        ? "completed"
        : "running";
    }
    if (event.type === "job_queued") return "queued";
    if (
      event.type === "job_started" ||
      event.type === "run_started" ||
      event.type === "delta" ||
      event.type === "usage_delta" ||
      event.type === "context_pressure_delta"
    ) return "running";
    if (event.type === "context_pressure_alert") {
      return event.data?.alert_level === "blocked" ? "blocked" : "warning";
    }
    if (event.type === "lsp_diagnostics_injected") {
      return event.data?.blocking && event.data?.diagnosticStatus === "findings" ? "blocked" : "completed";
    }
    if (event.type === "policy_blocked") return "blocked";
    if (event.type === "canceled" || event.type === "job_canceled") return "canceled";
    if (event.type === "failed" || event.type === "error" || event.type === "job_failed") return "failed";
    return "completed";
  }

  function policyDecisionRefsForRunEvent(event) {
    return uniqueStrings([
      event.data?.policyDecisionId,
      event.data?.policy_decision_id,
      event.data?.policyDecisionRef,
      event.data?.policy_decision_ref,
      event.data?.computer_use_policy_decision_ref,
      event.data?.policyDecisionReceipt?.policy_decision_ref,
      event.data?.policy_decision_receipt?.policy_decision_ref,
      ...normalizeArray(event.data?.policyDecisionRefs),
      ...normalizeArray(event.data?.policy_decision_refs),
    ]);
  }

  function stringRecord(value) {
    if (!value || typeof value !== "object" || Array.isArray(value)) return {};
    return Object.fromEntries(
      Object.entries(value).map(([key, item]) => [
        key,
        typeof item === "string" ? item : JSON.stringify(item),
      ]),
    );
  }

  function componentKindForRunEvent(eventOrType) {
    const type = typeof eventOrType === "string" ? eventOrType : eventOrType?.type;
    if (isComputerUseRunEventType(type)) return "computer_use_harness";
    switch (type) {
      case "runtime_task":
        return "runtime_task";
      case "runtime_checklist":
        return "runtime_checklist";
      case "job_queued":
      case "job_started":
      case "job_completed":
      case "job_failed":
      case "job_canceled":
        return "runtime_job";
      case "repository_context":
        return "repository_context";
      case "branch_policy":
        return "branch_policy";
      case "github_context":
        return "github_context";
      case "issue_context":
        return "issue_context";
      case "pr_attempt":
        return "pr_attempt";
      case "review_gate":
        return "review_gate";
      case "github_pr_create_plan":
        return "github_pr_create";
      case "model_route_decision":
        return "model_router";
      case "skill_hook_manifest":
        return "skill_registry";
      case "hook_dry_run_plan":
        return "hook_policy";
      case "hook_invocation_ledger":
        return "hook_runtime";
      case "memory_update":
        if (typeof eventOrType !== "string" && eventOrType?.data?.operation === "subagent_inheritance") {
          return "subagent_memory";
        }
        if (typeof eventOrType !== "string" && eventOrType?.data?.operation === "policy_update") {
          return "memory_policy";
        }
        return "memory_write";
      case "lsp_diagnostics_injected":
        return "lsp_diagnostics";
      case "policy_blocked":
        if (typeof eventOrType !== "string" && eventOrType?.data?.componentKind) {
          return eventOrType.data.componentKind;
        }
        return "policy_gate";
      case "task_state":
        return "task_state";
      case "uncertainty":
        return "uncertainty_gate";
      case "probe":
        return "probe_runner";
      case "postcondition_synthesized":
        return "postcondition_synthesizer";
      case "semantic_impact":
        return "semantic_impact_analyzer";
      case "usage_delta":
      case "usage_final":
        return "usage_telemetry";
      case "context_pressure_delta":
        return "context_pressure";
      case "context_pressure_alert":
        return "context_pressure_alert";
      case "quality_ledger":
        return "quality_ledger";
      case "artifact":
        return "artifact_store";
      case "completed":
      case "canceled":
        return "completion_gate";
      case "delta":
        return "output_writer";
      case "run_started":
      default:
        return "runtime_thread";
    }
  }

  function workflowNodeForRunEvent(eventOrType) {
    if (
      typeof eventOrType !== "string" &&
      (eventOrType?.type === "model_route_decision" ||
        eventOrType?.type === "runtime_task" ||
        eventOrType?.type === "runtime_checklist" ||
        eventOrType?.type === "job_queued" ||
        eventOrType?.type === "job_started" ||
        eventOrType?.type === "job_completed" ||
        eventOrType?.type === "job_failed" ||
        eventOrType?.type === "job_canceled" ||
        eventOrType?.type === "repository_context" ||
        eventOrType?.type === "branch_policy" ||
        eventOrType?.type === "github_context" ||
        eventOrType?.type === "issue_context" ||
        eventOrType?.type === "pr_attempt" ||
        eventOrType?.type === "review_gate" ||
        eventOrType?.type === "github_pr_create_plan" ||
        eventOrType?.type === "memory_update" ||
        eventOrType?.type === "lsp_diagnostics_injected" ||
        eventOrType?.type === "policy_blocked" ||
        eventOrType?.type === "skill_hook_manifest" ||
        eventOrType?.type === "hook_dry_run_plan" ||
        eventOrType?.type === "hook_invocation_ledger" ||
        eventOrType?.type === "usage_delta" ||
        eventOrType?.type === "context_pressure_delta" ||
        eventOrType?.type === "context_pressure_alert" ||
        eventOrType?.type === "usage_final" ||
        isComputerUseRunEventType(eventOrType?.type)) &&
      eventOrType.data?.workflowNodeId
    ) {
      return eventOrType.data.workflowNodeId;
    }
    return `runtime.${componentKindForRunEvent(eventOrType).replace(/_/g, "-")}`;
  }

  function receiptRefsForRunEvent(event) {
    if (event.type === "run_started") return [`receipt_${event.runId}_policy`];
    if (isComputerUseRunEventType(event.type)) {
      return [event.data?.receiptId ?? event.data?.receipt_id].filter(Boolean);
    }
    if (event.type === "model_route_decision") {
      return [event.data?.receiptId ?? event.data?.receipt_id].filter(Boolean);
    }
    if (event.type === "runtime_task") {
      return [event.data?.receiptId ?? event.data?.receipt_id].filter(Boolean);
    }
    if (event.type === "runtime_checklist") {
      return [event.data?.receiptId ?? event.data?.receipt_id].filter(Boolean);
    }
    if (event.type === "job_queued" || event.type === "job_started" || event.type === "job_completed" || event.type === "job_failed" || event.type === "job_canceled") {
      return [event.data?.receiptId ?? event.data?.receipt_id].filter(Boolean);
    }
    if (event.type === "repository_context") {
      return [event.data?.receiptId ?? event.data?.receipt_id].filter(Boolean);
    }
    if (event.type === "branch_policy") {
      return [event.data?.receiptId ?? event.data?.receipt_id].filter(Boolean);
    }
    if (event.type === "github_context") {
      return [event.data?.receiptId ?? event.data?.receipt_id].filter(Boolean);
    }
    if (event.type === "issue_context") {
      return [event.data?.receiptId ?? event.data?.receipt_id].filter(Boolean);
    }
    if (event.type === "pr_attempt") {
      return [event.data?.receiptId ?? event.data?.receipt_id].filter(Boolean);
    }
    if (event.type === "review_gate") {
      return [event.data?.receiptId ?? event.data?.receipt_id].filter(Boolean);
    }
    if (event.type === "github_pr_create_plan") {
      return [event.data?.receiptId ?? event.data?.receipt_id].filter(Boolean);
    }
    if (event.type === "skill_hook_manifest") {
      return [event.data?.receiptId ?? event.data?.receipt_id].filter(Boolean);
    }
    if (event.type === "hook_dry_run_plan") {
      return [
        event.data?.receiptId ?? event.data?.receipt_id,
        event.data?.policyReceiptId ?? event.data?.policy_receipt_id,
      ].filter(Boolean);
    }
    if (event.type === "hook_invocation_ledger") {
      return [
        event.data?.receiptId ?? event.data?.receipt_id,
        ...normalizeArray(event.data?.escalationReceiptIds),
      ].filter(Boolean);
    }
    if (event.type === "memory_update") {
      return [event.data?.receiptId ?? event.data?.receipt_id].filter(Boolean);
    }
    if (event.type === "lsp_diagnostics_injected") {
      return [
        event.data?.receiptId ?? event.data?.receipt_id,
        ...normalizeArray(event.data?.receiptRefs),
      ].filter(Boolean);
    }
    if (event.type === "policy_blocked") {
      return [
        event.data?.receiptId ?? event.data?.receipt_id,
        ...normalizeArray(event.data?.receiptRefs),
      ].filter(Boolean);
    }
    if (event.type === "context_pressure_alert") {
      return [
        event.data?.receiptId ?? event.data?.receipt_id,
        ...normalizeArray(event.data?.receiptRefs ?? event.data?.receipt_refs),
      ].filter(Boolean);
    }
    if (event.type === "completed" || event.type === "canceled") return [`receipt_${event.runId}_agentgres`];
    return [];
  }

  function artifactRefsForRunEvent(event) {
    if (isComputerUseRunEventType(event.type)) {
      return computerUseArtifactRefsForRunEvent(event);
    }
    if (event.type === "runtime_task") return ["runtime-task.json"];
    if (event.type === "runtime_checklist") return ["runtime-checklist.json"];
    if (event.type === "job_queued" || event.type === "job_started" || event.type === "job_completed" || event.type === "job_failed" || event.type === "job_canceled") return ["runtime-job.json"];
    if (event.type === "repository_context") return ["repository-context.json"];
    if (event.type === "branch_policy") return ["branch-policy.json"];
    if (event.type === "github_context") return ["github-context.json"];
    if (event.type === "issue_context") return ["issue-context.json"];
    if (event.type === "pr_attempt") return ["pr-attempt.json", "pr-branch.json", "pr-diff.patch"];
    if (event.type === "review_gate") return ["review-gate.json"];
    if (event.type === "github_pr_create_plan") return ["github-pr-create-plan.json"];
    if (event.type === "skill_hook_manifest") return ["active-skill-hook-manifest.json"];
    if (event.type === "hook_dry_run_plan") return ["hook-dry-run-plan.json"];
    if (event.type === "hook_invocation_ledger") return ["hook-invocations.json"];
    if (event.type === "policy_blocked" && event.data?.reason === "post_edit_diagnostics_findings") return ["diagnostics-blocking-gate.json"];
    if (event.type === "artifact") return event.data?.artifactNames ?? [];
    return [];
  }

  function computerUseArtifactRefsForRunEvent(event) {
    const data = objectRecord(event.data);
    const observation = objectRecord(data?.observation_bundle);
    const cleanup = objectRecord(data?.cleanup_receipt);
    return uniqueStrings([
      "computer-use-trace.json",
      observation?.screenshot_ref,
      observation?.som_ref,
      observation?.ax_ref,
      ...normalizeArray(cleanup?.retained_artifact_refs),
      ...normalizeArray(data?.computer_use_visual_artifact_refs),
    ]);
  }

  return {
    artifactRefsForRunEvent,
    componentKindForRunEvent,
    computerUseArtifactRefsForRunEvent,
    policyDecisionRefsForRunEvent,
    receiptRefsForRunEvent,
    runtimeEventStatusForRunEvent,
    stringRecord,
    workflowNodeForRunEvent,
  };
}
