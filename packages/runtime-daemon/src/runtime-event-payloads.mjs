export function createRuntimeEventPayloadHelpers({
  COMPUTER_USE_CONTRACT_SCHEMA_VERSION,
  LSP_DIAGNOSTICS_INJECTION_NODE_ID,
  RUNTIME_CONTEXT_PRESSURE_ALERT_SCHEMA_VERSION,
  RUNTIME_CONTEXT_PRESSURE_DELTA_SCHEMA_VERSION,
  RUNTIME_USAGE_DELTA_SCHEMA_VERSION,
  RUNTIME_USAGE_TELEMETRY_SCHEMA_VERSION,
  computerUseSourceEventKind,
  isComputerUseRunEventType,
  memoryEventKind,
  normalizeArray,
  uniqueStrings,
} = {}) {
  function payloadSummaryForRunEvent(event) {
    const summary = {
      run_id: event.run_id,
      agent_id: event.agent_id,
      summary: event.summary,
    };
    if (isComputerUseRunEventType(event.type)) {
      return {
        ...summary,
        event_kind: event.data?.event_kind ?? computerUseSourceEventKind(event.type),
        schema_version:
          event.data?.schema_version ??
          COMPUTER_USE_CONTRACT_SCHEMA_VERSION,
        computer_use_step: event.data?.computer_use_step ?? null,
        computer_use_lane: event.data?.computer_use_lane ?? null,
        computer_use_session_mode: event.data?.computer_use_session_mode ?? null,
        computer_use_lease_id: event.data?.computer_use_lease_id ?? null,
        computer_use_contract_ingest: event.data?.computer_use_contract_ingest ?? null,
        computer_use_observation_ref: event.data?.computer_use_observation_ref ?? null,
        computer_use_target_index_ref: event.data?.computer_use_target_index_ref ?? null,
        computer_use_affordance_graph_ref: event.data?.computer_use_affordance_graph_ref ?? null,
        computer_use_proposal_ref: event.data?.computer_use_proposal_ref ?? null,
        computer_use_action_ref: event.data?.computer_use_action_ref ?? null,
        computer_use_target_ref: event.data?.computer_use_target_ref ?? null,
        computer_use_policy_decision_ref: event.data?.computer_use_policy_decision_ref ?? null,
        computer_use_verification_ref: event.data?.computer_use_verification_ref ?? null,
        computer_use_commit_gate_ref: event.data?.computer_use_commit_gate_ref ?? null,
        computer_use_trajectory_ref: event.data?.computer_use_trajectory_ref ?? null,
        computer_use_cleanup_ref: event.data?.computer_use_cleanup_ref ?? null,
        computer_use_blocker: event.data?.computer_use_blocker ?? null,
        computer_use_executor_ref: event.data?.computer_use_executor_ref ?? null,
        computer_use_executor_status: event.data?.computer_use_executor_status ?? null,
        computer_use_executor_error_class: event.data?.computer_use_executor_error_class ?? null,
        computer_use_execution_result: event.data?.computer_use_execution_result ?? null,
        native_browser_execution_result: event.data?.native_browser_execution_result ?? null,
        computer_use_controlled_relaunch_launch_ref:
          event.data?.computer_use_controlled_relaunch_launch_ref ?? null,
        controlled_relaunch_launch_receipt:
          event.data?.controlled_relaunch_launch_receipt ?? null,
        controlled_relaunch_broker: event.data?.controlled_relaunch_broker ?? null,
        controlled_relaunch_handoff_ref: event.data?.controlled_relaunch_handoff_ref ?? null,
        environment_selection_receipt: event.data?.environment_selection_receipt ?? null,
        lease: event.data?.lease ?? null,
        adapter_contract: event.data?.adapter_contract ?? null,
        recovery_policy: event.data?.recovery_policy ?? null,
        computer_use_run_state: event.data?.computer_use_run_state ?? null,
        observation_bundle: event.data?.observation_bundle ?? null,
        target_index: event.data?.target_index ?? null,
        affordance_graph: event.data?.affordance_graph ?? null,
        action_proposal: event.data?.action_proposal ?? null,
        computer_action: event.data?.computer_action ?? null,
        action_receipt: event.data?.action_receipt ?? null,
        policy_gate: event.data?.policy_gate ?? null,
        policy_decision_receipt: event.data?.policy_decision_receipt ?? null,
        verification_receipt: event.data?.verification_receipt ?? null,
        outcome_contract: event.data?.outcome_contract ?? null,
        commit_gate: event.data?.commit_gate ?? null,
        human_handoff_state: event.data?.human_handoff_state ?? null,
        trajectory_bundle: event.data?.trajectory_bundle ?? null,
        cleanup_receipt: event.data?.cleanup_receipt ?? null,
        workflow_graph_id: event.data?.workflow_graph_id ?? null,
        workflow_node_id: event.data?.workflow_node_id ?? null,
        workflow_node_ids: event.data?.workflow_node_ids ?? [],
        tool_ref: event.data?.tool_ref ?? null,
        authority_scopes: event.data?.authority_scopes ?? [],
        observation_retention_mode: event.data?.observation_retention_mode ?? null,
        fail_closed_when_unavailable: Boolean(event.data?.fail_closed_when_unavailable),
        redaction: "computer_use_trace_safe",
      };
    }
    if (event.type === "memory_update") {
      return {
        ...summary,
        event_kind: event.data?.event_kind ?? memoryEventKind(event.data?.operation),
        memory_operation: event.data?.operation ?? "write",
        memory_record_id:
          event.data?.memory_record_id ??
          (event.data?.object === "ioi.agent_memory_record" ? event.data?.id : null),
        memory_policy_id:
          event.data?.memory_policy_id ??
          (event.data?.object === "ioi.agent_memory_policy" ? event.data?.id : null),
        subagent_name: event.data?.subagent_name ?? null,
        subagent_inheritance_mode: event.data?.mode ?? null,
        inherited_memory_count: normalizeArray(event.data?.inherited_record_ids).length,
        write_allowed: event.data?.write_allowed ?? null,
        write_block_reason: event.data?.write_block_reason ?? null,
        memory_scope: event.data?.scope ?? null,
        memory_thread_id: event.data?.thread_id ?? null,
        workflow_node_id: event.data?.workflow_node_id ?? null,
        redaction: event.data?.redaction ?? "none",
      };
    }
    if (event.type === "lsp_diagnostics_injected") {
      return {
        ...summary,
        event_kind: event.data?.event_kind ?? "LspDiagnosticsInjected",
        injection_id: event.data?.injection_id ?? null,
        diagnostic_status: event.data?.diagnostic_status ?? null,
        diagnostic_count: event.data?.diagnostic_count ?? 0,
        injected_finding_count: event.data?.injected_finding_count ?? 0,
        omitted_finding_count: event.data?.omitted_finding_count ?? 0,
        diagnostic_event_ids: normalizeArray(event.data?.diagnostic_event_ids),
        mode: event.data?.mode ?? "advisory",
        blocking: Boolean(event.data?.blocking),
        prompt_text: event.data?.prompt_text ?? null,
        rollback_refs: normalizeArray(event.data?.rollback_refs),
        workspace_snapshot_refs: normalizeArray(event.data?.workspace_snapshot_refs),
        source_tool_call_ids: normalizeArray(event.data?.source_tool_call_ids),
        repair_policy: event.data?.repair_policy ?? null,
        findings: normalizeArray(event.data?.findings),
        workflow_node_id: event.data?.workflow_node_id ?? LSP_DIAGNOSTICS_INJECTION_NODE_ID,
        redaction: "lsp_diagnostics_safe",
      };
    }
    if (event.type === "policy_blocked") {
      return {
        ...summary,
        event_kind: event.data?.event_kind ?? "PolicyBlocked",
        gate_id: event.data?.gate_id ?? null,
        policy_decision_id: event.data?.policy_decision_id ?? null,
        policy_decision_refs: uniqueStrings([
          event.data?.policy_decision_id,
          ...normalizeArray(event.data?.policy_decision_refs),
        ]),
        receipt_id: event.data?.receipt_id ?? null,
        decision: event.data?.decision ?? "blocked",
        reason: event.data?.reason ?? null,
        status: event.data?.status ?? "blocked",
        diagnostic_status: event.data?.diagnostic_status ?? null,
        diagnostic_count: event.data?.diagnostic_count ?? 0,
        injected_finding_count: event.data?.injected_finding_count ?? 0,
        omitted_finding_count: event.data?.omitted_finding_count ?? 0,
        mode: event.data?.mode ?? null,
        blocking: Boolean(event.data?.blocking),
        requires_input: Boolean(event.data?.requires_input),
        injection_id: event.data?.injection_id ?? null,
        diagnostics_receipt_id: event.data?.diagnostics_receipt_id ?? null,
        diagnostic_event_ids: normalizeArray(event.data?.diagnostic_event_ids),
        rollback_refs: normalizeArray(event.data?.rollback_refs),
        workspace_snapshot_refs: normalizeArray(event.data?.workspace_snapshot_refs),
        source_tool_call_ids: normalizeArray(event.data?.source_tool_call_ids),
        repair_policy: event.data?.repair_policy ?? null,
        repair_decisions: normalizeArray(event.data?.repair_decisions),
        recommended_next_actions: normalizeArray(event.data?.recommended_next_actions),
        findings: normalizeArray(event.data?.findings),
        workflow_node_id: event.data?.workflow_node_id ?? null,
        component_kind: event.data?.component_kind ?? "policy_gate",
        redaction: event.data?.redaction ?? "policy_safe",
      };
    }
    if (event.type === "repository_context") {
      return {
        ...summary,
        event_kind: event.data?.event_kind ?? "RepositoryContext",
        context_id: event.data?.context_id ?? null,
        is_git_repository: Boolean(event.data?.is_git_repository),
        repo_root_hash: event.data?.repo_root_hash ?? null,
        branch: event.data?.branch ?? null,
        detached_head: Boolean(event.data?.detached_head),
        head_short_sha: event.data?.head_short_sha ?? null,
        upstream: event.data?.upstream ?? null,
        remote_count: event.data?.remote_count ?? 0,
        is_dirty: Boolean(event.data?.status?.is_dirty),
        staged_count: event.data?.status?.counts?.staged ?? 0,
        unstaged_count: event.data?.status?.counts?.unstaged ?? 0,
        untracked_count: event.data?.status?.counts?.untracked ?? 0,
        conflicted_count: event.data?.status?.counts?.conflicted ?? 0,
        mutation_executed: Boolean(event.data?.mutation_executed),
        workflow_node_id: event.data?.workflow_node_id ?? null,
        redaction: event.data?.redaction?.profile ?? "repository_context_safe",
      };
    }
    if (event.type === "runtime_task") {
      return {
        ...summary,
        event_kind: event.data?.event_kind ?? "RuntimeTaskRecord",
        task_id: event.data?.task_id ?? null,
        run_id: event.data?.run_id ?? null,
        agent_id: event.data?.agent_id ?? null,
        thread_id: event.data?.thread_id ?? null,
        turn_id: event.data?.turn_id ?? null,
        status: event.data?.status ?? null,
        mode: event.data?.mode ?? null,
        task_family: event.data?.task_family ?? null,
        selected_strategy: event.data?.selected_strategy ?? null,
        durable: Boolean(event.data?.durable),
        replayable: Boolean(event.data?.replayable),
        prompt_included: Boolean(event.data?.prompt_included),
        workflow_node_id: event.data?.workflow_node_id ?? null,
        redaction: event.data?.redaction?.profile ?? "runtime_task_safe",
      };
    }
    if (event.type === "runtime_checklist") {
      return {
        ...summary,
        event_kind: event.data?.event_kind ?? "RuntimeChecklistRecord",
        checklist_id: event.data?.checklist_id ?? null,
        task_id: event.data?.task_id ?? null,
        job_id: event.data?.job_id ?? null,
        run_id: event.data?.run_id ?? null,
        status: event.data?.status ?? null,
        item_count: event.data?.item_count ?? 0,
        completed_item_count: event.data?.completed_item_count ?? 0,
        failed_item_count: event.data?.failed_item_count ?? 0,
        canceled_item_count: event.data?.canceled_item_count ?? 0,
        blocked_item_count: event.data?.blocked_item_count ?? 0,
        required_item_ids: normalizeArray(event.data?.required_item_ids),
        durable: Boolean(event.data?.durable),
        replayable: Boolean(event.data?.replayable),
        workflow_node_id: event.data?.workflow_node_id ?? null,
        redaction: event.data?.redaction?.profile ?? "runtime_checklist_safe",
      };
    }
    if (event.type === "job_queued" || event.type === "job_started" || event.type === "job_completed" || event.type === "job_failed" || event.type === "job_canceled") {
      return {
        ...summary,
        event_kind: event.data?.event_kind ?? "RuntimeJobLifecycle",
        job_id: event.data?.job_id ?? null,
        task_id: event.data?.task_id ?? null,
        run_id: event.data?.run_id ?? null,
        agent_id: event.data?.agent_id ?? null,
        thread_id: event.data?.thread_id ?? null,
        turn_id: event.data?.turn_id ?? null,
        status: event.data?.status ?? null,
        lifecycle_status: event.data?.lifecycle_status ?? null,
        queue_name: event.data?.queue_name ?? null,
        runner: event.data?.runner ?? null,
        job_type: event.data?.job_type ?? null,
        background: Boolean(event.data?.background),
        durable: Boolean(event.data?.durable),
        replayable: Boolean(event.data?.replayable),
        queued_at: event.data?.queued_at ?? null,
        started_at: event.data?.started_at ?? null,
        completed_at: event.data?.completed_at ?? null,
        progress_percent: event.data?.progress?.percent ?? null,
        workflow_node_id: event.data?.workflow_node_id ?? null,
        redaction: event.data?.redaction?.profile ?? "runtime_job_safe",
      };
    }
    if (event.type === "branch_policy") {
      return {
        ...summary,
        event_kind: event.data?.event_kind ?? "BranchPolicyDecision",
        policy_id: event.data?.policy_id ?? null,
        repository_context_id: event.data?.repository_context_id ?? null,
        status: event.data?.status ?? null,
        branch: event.data?.branch ?? null,
        default_branch: event.data?.default_branch ?? null,
        protected_branch: Boolean(event.data?.protected_branch),
        detached_head: Boolean(event.data?.detached_head),
        dirty: Boolean(event.data?.dirty),
        upstream: event.data?.upstream ?? null,
        ahead: event.data?.ahead ?? 0,
        behind: event.data?.behind ?? 0,
        blocker_count: normalizeArray(event.data?.blockers).length,
        warning_count: normalizeArray(event.data?.warnings).length,
        mutation_allowed: Boolean(event.data?.mutation_allowed),
        pr_creation_allowed: Boolean(event.data?.pr_creation_allowed),
        review_required: Boolean(event.data?.review_required),
        mutation_executed: Boolean(event.data?.mutation_executed),
        workflow_node_id: event.data?.workflow_node_id ?? null,
        redaction: event.data?.redaction?.profile ?? "branch_policy_safe",
      };
    }
    if (event.type === "github_context") {
      return {
        ...summary,
        event_kind: event.data?.event_kind ?? "GitHubContext",
        context_id: event.data?.context_id ?? null,
        repository_context_id: event.data?.repository_context_id ?? null,
        branch_policy_id: event.data?.branch_policy_id ?? null,
        status: event.data?.status ?? null,
        github_remote_present: Boolean(event.data?.github_remote_present),
        default_remote_name: event.data?.default_remote_name ?? null,
        owner: event.data?.owner ?? null,
        repo: event.data?.repo ?? null,
        repo_full_name: event.data?.repo_full_name ?? null,
        branch: event.data?.branch ?? null,
        default_branch: event.data?.default_branch ?? null,
        branch_policy_status: event.data?.branch_policy_status ?? null,
        token_available: Boolean(event.data?.credentials?.token_available),
        pr_creation_eligible: Boolean(event.data?.pr_creation_eligible),
        network_lookup_performed: Boolean(event.data?.network_lookup_performed),
        mutation_executed: Boolean(event.data?.mutation_executed),
        workflow_node_id: event.data?.workflow_node_id ?? null,
        redaction: event.data?.redaction?.profile ?? "github_context_safe",
      };
    }
    if (event.type === "issue_context") {
      return {
        ...summary,
        event_kind: event.data?.event_kind ?? "IssueContext",
        context_id: event.data?.context_id ?? null,
        repository_context_id: event.data?.repository_context_id ?? null,
        github_context_id: event.data?.github_context_id ?? null,
        pr_attempt_id: event.data?.pr_attempt_id ?? null,
        review_gate_id: event.data?.review_gate_id ?? null,
        status: event.data?.status ?? null,
        repo_full_name: event.data?.repo_full_name ?? null,
        bound: Boolean(event.data?.bound),
        issue_provided: Boolean(event.data?.issue_provided),
        issue_number: event.data?.issue_number ?? null,
        source_kind: event.data?.source_kind ?? null,
        warning_count: normalizeArray(event.data?.warnings).length,
        network_lookup_performed: Boolean(event.data?.network_lookup_performed),
        mutation_executed: Boolean(event.data?.mutation_executed),
        workflow_node_id: event.data?.workflow_node_id ?? null,
        redaction: event.data?.redaction?.profile ?? "issue_context_safe",
      };
    }
    if (event.type === "pr_attempt") {
      return {
        ...summary,
        event_kind: event.data?.event_kind ?? "PrAttemptRecord",
        attempt_id: event.data?.attempt_id ?? null,
        repository_context_id: event.data?.repository_context_id ?? null,
        branch_policy_id: event.data?.branch_policy_id ?? null,
        github_context_id: event.data?.github_context_id ?? null,
        status: event.data?.status ?? null,
        outcome: event.data?.outcome ?? null,
        repo_full_name: event.data?.repo_full_name ?? null,
        branch: event.data?.branch ?? null,
        default_branch: event.data?.default_branch ?? null,
        head_short_sha: event.data?.head_short_sha ?? null,
        blocker_count: normalizeArray(event.data?.blockers).length,
        warning_count: normalizeArray(event.data?.warnings).length,
        required_authority_scopes: normalizeArray(event.data?.authority?.required_scopes),
        missing_authority_scopes: normalizeArray(event.data?.authority?.missing_scopes),
        authority_scope_granted: Boolean(event.data?.authority?.scope_granted),
        branch_artifact_name: event.data?.branch_artifact?.artifact_name ?? null,
        diff_artifact_name: event.data?.diff_artifact?.artifact_name ?? null,
        diff_hash: event.data?.diff_artifact?.diff_hash ?? null,
        diff_file_count: event.data?.diff_artifact?.file_count ?? 0,
        mutation_attempted: Boolean(event.data?.mutation_attempted),
        mutation_executed: Boolean(event.data?.mutation_executed),
        network_lookup_performed: Boolean(event.data?.network_lookup_performed),
        workflow_node_id: event.data?.workflow_node_id ?? null,
        redaction: event.data?.redaction?.profile ?? "pr_attempt_safe",
      };
    }
    if (event.type === "review_gate") {
      return {
        ...summary,
        event_kind: event.data?.event_kind ?? "ReviewGateDecision",
        gate_id: event.data?.gate_id ?? null,
        repository_context_id: event.data?.repository_context_id ?? null,
        branch_policy_id: event.data?.branch_policy_id ?? null,
        github_context_id: event.data?.github_context_id ?? null,
        pr_attempt_id: event.data?.pr_attempt_id ?? null,
        status: event.data?.status ?? null,
        decision: event.data?.decision ?? null,
        repo_full_name: event.data?.repo_full_name ?? null,
        branch: event.data?.branch ?? null,
        default_branch: event.data?.default_branch ?? null,
        review_required: Boolean(event.data?.review_required),
        review_satisfied: Boolean(event.data?.review_satisfied),
        approval_required: Boolean(event.data?.approval_required),
        approval_satisfied: Boolean(event.data?.approval_satisfied),
        required_reviewers: normalizeArray(event.data?.required_reviewers),
        required_checks: normalizeArray(event.data?.required_checks),
        blocker_count: normalizeArray(event.data?.blockers).length,
        warning_count: normalizeArray(event.data?.warnings).length,
        mutation_allowed: Boolean(event.data?.mutation_allowed),
        pr_creation_allowed: Boolean(event.data?.pr_creation_allowed),
        mutation_executed: Boolean(event.data?.mutation_executed),
        network_lookup_performed: Boolean(event.data?.network_lookup_performed),
        workflow_node_id: event.data?.workflow_node_id ?? null,
        redaction: event.data?.redaction?.profile ?? "review_gate_safe",
      };
    }
    if (event.type === "github_pr_create_plan") {
      return {
        ...summary,
        event_kind: event.data?.event_kind ?? "GitHubPrCreatePlan",
        plan_id: event.data?.plan_id ?? null,
        repository_context_id: event.data?.repository_context_id ?? null,
        branch_policy_id: event.data?.branch_policy_id ?? null,
        github_context_id: event.data?.github_context_id ?? null,
        issue_context_id: event.data?.issue_context_id ?? null,
        pr_attempt_id: event.data?.pr_attempt_id ?? null,
        review_gate_id: event.data?.review_gate_id ?? null,
        status: event.data?.status ?? null,
        decision: event.data?.decision ?? null,
        dry_run: Boolean(event.data?.dry_run),
        tool_name: event.data?.tool_name ?? null,
        repo_full_name: event.data?.repo_full_name ?? null,
        base_branch: event.data?.base_branch ?? null,
        head_branch: event.data?.head_branch ?? null,
        issue_number: event.data?.issue_number ?? null,
        review_gate_status: event.data?.review_gate_status ?? null,
        review_satisfied: Boolean(event.data?.review_satisfied),
        request_payload_hash: event.data?.request?.payload_hash ?? null,
        request_body_included: Boolean(event.data?.request?.body_included),
        request_token_included: Boolean(event.data?.request?.token_included),
        required_authority_scopes: normalizeArray(event.data?.authority?.required_scopes),
        missing_authority_scopes: normalizeArray(event.data?.authority?.missing_scopes),
        authority_scope_granted: Boolean(event.data?.authority?.scope_granted),
        blocker_count: normalizeArray(event.data?.blockers).length,
        warning_count: normalizeArray(event.data?.warnings).length,
        mutation_attempted: Boolean(event.data?.mutation_attempted),
        mutation_executed: Boolean(event.data?.mutation_executed),
        network_lookup_performed: Boolean(event.data?.network_lookup_performed),
        workflow_node_id: event.data?.workflow_node_id ?? null,
        redaction: event.data?.redaction?.profile ?? "github_pr_create_plan_safe",
      };
    }
    if (event.type === "skill_hook_manifest") {
      return {
        ...summary,
        event_kind: event.data?.event_kind ?? "ActiveSkillHookManifest",
        manifest_id: event.data?.manifest_id ?? null,
        active_skill_set_hash: event.data?.active_skill_set_hash ?? null,
        active_hook_set_hash: event.data?.active_hook_set_hash ?? null,
        selected_skill_count: normalizeArray(event.data?.selected_skill_ids).length,
        selected_hook_count: normalizeArray(event.data?.selected_hook_ids).length,
        mutation_blocked_hook_count: normalizeArray(event.data?.mutation_blocked_hook_ids).length,
        hook_execution_enabled: Boolean(event.data?.hook_execution?.enabled),
        workflow_node_id: event.data?.workflow_node_id ?? null,
        redaction: event.data?.redaction?.profile ?? "active_skill_hook_manifest_safe",
      };
    }
    if (event.type === "hook_dry_run_plan") {
      return {
        ...summary,
        event_kind: event.data?.event_kind ?? "HookDryRunPlan",
        plan_id: event.data?.plan_id ?? null,
        manifest_id: event.data?.manifest_id ?? null,
        decision_count: event.data?.decision_count ?? 0,
        would_run_count: event.data?.would_run_count ?? 0,
        blocked_count: event.data?.blocked_count ?? 0,
        skipped_count: event.data?.skipped_count ?? 0,
        policy_status: event.data?.policy_decision?.status ?? null,
        hook_execution_enabled: Boolean(event.data?.hook_execution_enabled),
        command_execution_enabled: Boolean(event.data?.command_execution_enabled),
        workflow_node_id: event.data?.workflow_node_id ?? null,
        redaction: event.data?.redaction?.profile ?? "hook_dry_run_safe",
      };
    }
    if (event.type === "hook_invocation_ledger") {
      return {
        ...summary,
        event_kind: event.data?.event_kind ?? "HookInvocationLedger",
        ledger_id: event.data?.ledger_id ?? null,
        manifest_id: event.data?.manifest_id ?? null,
        dry_run_plan_id: event.data?.dry_run_plan_id ?? null,
        emitted_event_kinds: normalizeArray(event.data?.emitted_event_kinds),
        invocation_count: event.data?.invocation_count ?? 0,
        would_run_count: event.data?.would_run_count ?? 0,
        blocked_count: event.data?.blocked_count ?? 0,
        skipped_count: event.data?.skipped_count ?? 0,
        escalation_count: event.data?.escalation_count ?? 0,
        hook_execution_enabled: Boolean(event.data?.hook_execution_enabled),
        command_execution_enabled: Boolean(event.data?.command_execution_enabled),
        workflow_node_id: event.data?.workflow_node_id ?? null,
        redaction: event.data?.redaction?.profile ?? "hook_invocation_ledger_safe",
      };
    }
    if (event.type === "usage_delta") {
      return {
        ...summary,
        event_kind: "RuntimeUsageTelemetry.Delta",
        schema_version:
          event.data?.schema_version ??
          RUNTIME_USAGE_DELTA_SCHEMA_VERSION,
        stage: event.data?.stage ?? null,
        delta_index: event.data?.delta_index ?? null,
        delta_total: event.data?.delta_total ?? null,
        run_id: event.data?.run_id ?? null,
        thread_id: event.data?.thread_id ?? null,
        turn_id: event.data?.turn_id ?? null,
        total_tokens: event.data?.total_tokens ?? 0,
        input_tokens: event.data?.input_tokens ?? 0,
        output_tokens: event.data?.output_tokens ?? 0,
        total_tokens_delta: event.data?.total_tokens_delta ?? 0,
        input_tokens_delta: event.data?.input_tokens_delta ?? 0,
        output_tokens_delta: event.data?.output_tokens_delta ?? 0,
        estimated_cost_usd: event.data?.estimated_cost_usd ?? 0,
        context_pressure: event.data?.context_pressure ?? 0,
        context_pressure_status: event.data?.context_pressure_status ?? "nominal",
        workflow_node_id: event.data?.workflow_node_id ?? "runtime.usage-telemetry",
        component_kind: event.data?.component_kind ?? "usage_telemetry",
        redaction: "usage_telemetry_safe",
      };
    }
    if (event.type === "context_pressure_delta") {
      return {
        ...summary,
        event_kind: "RuntimeContextPressure.Delta",
        schema_version:
          event.data?.schema_version ??
          RUNTIME_CONTEXT_PRESSURE_DELTA_SCHEMA_VERSION,
        stage: event.data?.stage ?? null,
        delta_index: event.data?.delta_index ?? null,
        delta_total: event.data?.delta_total ?? null,
        run_id: event.data?.run_id ?? null,
        thread_id: event.data?.thread_id ?? null,
        turn_id: event.data?.turn_id ?? null,
        usage_total_tokens: event.data?.usage_total_tokens ?? 0,
        usage_cost_estimate_usd: event.data?.usage_cost_estimate_usd ?? 0,
        usage_context_pressure: event.data?.usage_context_pressure ?? 0,
        usage_context_pressure_status:
          event.data?.usage_context_pressure_status ?? "nominal",
        workflow_node_id: event.data?.workflow_node_id ?? "runtime.context-budget",
        component_kind: event.data?.component_kind ?? "context_pressure",
        redaction: "usage_telemetry_safe",
      };
    }
    if (event.type === "context_pressure_alert") {
      return {
        ...summary,
        event_kind: "RuntimeContextPressure.Alert",
        schema_version:
          event.data?.schema_version ??
          RUNTIME_CONTEXT_PRESSURE_ALERT_SCHEMA_VERSION,
        alert_id: event.data?.alert_id ?? null,
        alert_level: event.data?.alert_level ?? null,
        scope: event.data?.scope ?? "turn",
        pressure: event.data?.pressure ?? null,
        pressure_status: event.data?.pressure_status ?? null,
        recommended_action: event.data?.recommended_action ?? null,
        actions: normalizeArray(event.data?.actions),
        run_id: event.data?.run_id ?? null,
        thread_id: event.data?.thread_id ?? null,
        turn_id: event.data?.turn_id ?? null,
        workflow_node_id:
          event.data?.workflow_node_id ?? "runtime.context-pressure-alert",
        component_kind: event.data?.component_kind ?? "context_pressure_alert",
        redaction: "usage_telemetry_safe",
      };
    }
    if (event.type === "usage_final") {
      return {
        ...summary,
        event_kind: "RuntimeUsageTelemetry",
        schema_version:
          event.data?.schema_version ??
          RUNTIME_USAGE_TELEMETRY_SCHEMA_VERSION,
        scope: event.data?.scope ?? "run",
        thread_id: event.data?.thread_id ?? null,
        turn_id: event.data?.turn_id ?? null,
        total_tokens: event.data?.total_tokens ?? 0,
        input_tokens: event.data?.input_tokens ?? 0,
        output_tokens: event.data?.output_tokens ?? 0,
        estimated_cost_usd: event.data?.estimated_cost_usd ?? null,
        context_pressure: event.data?.context_pressure ?? null,
        context_pressure_status: event.data?.context_pressure_status ?? null,
        workflow_node_id: event.data?.workflow_node_id ?? "runtime.usage-telemetry",
        redaction: "usage_telemetry_safe",
      };
    }
    if (event.type !== "model_route_decision") return summary;
    return {
      ...summary,
      event_kind: event.data?.event_kind ?? "ModelRouteDecision",
      model_route_decision_id: event.data?.decision_id ?? null,
      route_id: event.data?.route_id ?? null,
      requested_model: event.data?.requested_model ?? null,
      requested_model_mode: event.data?.requested_model_mode ?? null,
      selected_model: event.data?.selected_model ?? null,
      endpoint_id: event.data?.endpoint_id ?? null,
      provider_id: event.data?.provider_id ?? null,
      provider_kind: event.data?.provider_kind ?? null,
      reasoning_effort: event.data?.reasoning_effort ?? null,
      local_remote_placement: event.data?.local_remote_placement ?? null,
      privacy_posture: event.data?.privacy_posture ?? null,
      cost_estimate_usd: event.data?.cost_estimate_usd ?? null,
      fallback_triggered: Boolean(event.data?.fallback_triggered),
    };
  }
  

  return {
    payloadSummaryForRunEvent,
  };
}
