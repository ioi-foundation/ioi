fn summarize_kernel_event(kernel_event: &ioi_types::app::KernelEvent) -> String {
    use ioi_types::app::KernelEvent as Ev;

    match kernel_event {
        Ev::AgentThought { session_id, token } => format!(
            "AgentThought session={} {}",
            prefix_hex_4(session_id),
            text_fingerprint(token)
        ),
        Ev::AgentStep(step) => format!(
            "AgentStep session={} step_index={} visual_hash={} raw_output_{} full_prompt_{}",
            prefix_hex_4(&step.session_id),
            step.step_index,
            hex::encode(&step.visual_hash[..4]),
            text_fingerprint(&step.raw_output),
            text_fingerprint(&step.full_prompt)
        ),
        Ev::BlockCommitted { height, tx_count } => {
            format!("BlockCommitted height={} tx_count={}", height, tx_count)
        }
        Ev::GhostInput {
            device,
            description,
        } => format!(
            "GhostInput device={} {}",
            device,
            text_fingerprint(description)
        ),
        Ev::FirewallInterception {
            verdict,
            target,
            request_hash,
            session_id,
        } => format!(
            "FirewallInterception session={} verdict={} target={} request_hash={}",
            session_id
                .as_ref()
                .map(prefix_hex_4)
                .unwrap_or_else(|| "none".to_string()),
            verdict,
            target,
            hex::encode(request_hash)
        ),
        Ev::AgentActionResult {
            session_id,
            step_index,
            tool_name,
            output,
            error_class,
            agent_status,
        } => format!(
            "AgentActionResult session={} step_index={} tool_name={} agent_status={} error_class={} output_{}",
            prefix_hex_4(session_id),
            step_index,
            tool_name,
            agent_status,
            error_class.as_deref().unwrap_or("none"),
            text_fingerprint(output)
        ),
        Ev::AgentSpawn {
            parent_session_id,
            new_session_id,
            name,
            role,
            budget,
            goal,
        } => format!(
            "AgentSpawn parent_session={} new_session={} name={} role={} budget={} goal_{}",
            prefix_hex_4(parent_session_id),
            prefix_hex_4(new_session_id),
            name,
            role,
            budget,
            text_fingerprint(goal)
        ),
        Ev::WorkloadActivity(activity) => match &activity.kind {
            ioi_types::app::WorkloadActivityKind::Lifecycle { phase, exit_code } => format!(
                "WorkloadActivity(Lifecycle) session={} step_index={} workload_id={} phase={} exit_code={}",
                prefix_hex_4(&activity.session_id),
                activity.step_index,
                activity.workload_id,
                phase,
                exit_code
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "none".to_string())
            ),
            ioi_types::app::WorkloadActivityKind::Stdio {
                stream,
                chunk,
                seq,
                is_final,
                exit_code,
            } => format!(
                "WorkloadActivity(Stdio) session={} step_index={} workload_id={} stream={} seq={} is_final={} exit_code={} chunk_{}",
                prefix_hex_4(&activity.session_id),
                activity.step_index,
                activity.workload_id,
                stream,
                seq,
                is_final,
                exit_code
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "none".to_string()),
                text_fingerprint(chunk)
            ),
        },
        Ev::WorkloadReceipt(receipt) => match &receipt.receipt {
            ioi_types::app::WorkloadReceipt::Exec(exec) => format!(
                "WorkloadReceipt(Exec) session={} step_index={} workload_id={} tool_name={} command_preview_{} success={} exit_code={} error_class={}",
                prefix_hex_4(&receipt.session_id),
                receipt.step_index,
                receipt.workload_id,
                exec.tool_name,
                text_fingerprint(&exec.command_preview),
                exec.success,
                exec.exit_code
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "none".to_string()),
                exec.error_class.as_deref().unwrap_or("none")
            ),
            ioi_types::app::WorkloadReceipt::FsWrite(fs) => format!(
                "WorkloadReceipt(FsWrite) session={} step_index={} workload_id={} tool_name={} operation={} target_path_{} has_destination_path={} destination_path_{} has_bytes_written={} bytes_written={} success={} error_class={}",
                prefix_hex_4(&receipt.session_id),
                receipt.step_index,
                receipt.workload_id,
                fs.tool_name,
                fs.operation,
                text_fingerprint(&fs.target_path),
                fs.destination_path.is_some(),
                text_fingerprint(fs.destination_path.as_deref().unwrap_or("")),
                fs.bytes_written.is_some(),
                fs.bytes_written
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "none".to_string()),
                fs.success,
                fs.error_class.as_deref().unwrap_or("none")
            ),
            ioi_types::app::WorkloadReceipt::NetFetch(net) => format!(
                "WorkloadReceipt(NetFetch) session={} step_index={} workload_id={} method={} has_status_code={} status_code={} truncated={} success={} requested_url_{} has_final_url={} final_url_{} error_class={}",
                prefix_hex_4(&receipt.session_id),
                receipt.step_index,
                receipt.workload_id,
                net.method,
                net.status_code.is_some(),
                net.status_code
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "none".to_string()),
                net.truncated,
                net.success,
                text_fingerprint(&net.requested_url),
                net.final_url.is_some(),
                text_fingerprint(net.final_url.as_deref().unwrap_or("")),
                net.error_class.as_deref().unwrap_or("none")
            ),
            ioi_types::app::WorkloadReceipt::WebRetrieve(web) => format!(
                "WorkloadReceipt(WebRetrieve) session={} step_index={} workload_id={} tool_name={} backend={} has_query={} query_{} has_url={} url_{} sources_count={} documents_count={} success={} error_class={}",
                prefix_hex_4(&receipt.session_id),
                receipt.step_index,
                receipt.workload_id,
                web.tool_name,
                web.backend,
                web.query.is_some(),
                text_fingerprint(web.query.as_deref().unwrap_or("")),
                web.url.is_some(),
                text_fingerprint(web.url.as_deref().unwrap_or("")),
                web.sources_count,
                web.documents_count,
                web.success,
                web.error_class.as_deref().unwrap_or("none")
            ),
            ioi_types::app::WorkloadReceipt::ScsRetrieve(scs) => format!(
                "WorkloadReceipt(ScsRetrieve) session={} step_index={} workload_id={} tool_name={} backend={} query_hash={} index_root={} k={} ef_search={} candidate_limit={} candidate_count_total={} candidate_count_reranked={} candidate_truncated={} metric={} embedding_normalized={} success={} error_class={}",
                prefix_hex_4(&receipt.session_id),
                receipt.step_index,
                receipt.workload_id,
                scs.tool_name,
                scs.backend,
                scs.query_hash,
                scs.index_root,
                scs.k,
                scs.ef_search,
                scs.candidate_limit,
                scs.candidate_count_total,
                scs.candidate_count_reranked,
                scs.candidate_truncated,
                scs.distance_metric,
                scs.embedding_normalized,
                scs.success,
                scs.error_class.as_deref().unwrap_or("none")
            ),
        },
        Ev::RoutingReceipt(receipt) => format!(
            "RoutingReceipt session={} step_index={} tool_name={} policy_decision={} success={} action_json_{}",
            prefix_hex_4(&receipt.session_id),
            receipt.step_index,
            receipt.tool_name,
            receipt.policy_decision,
            receipt.post_state.success,
            text_fingerprint(&receipt.action_json)
        ),
        Ev::SystemUpdate { component, status } => format!(
            "SystemUpdate component={} status_{}",
            component,
            text_fingerprint(status)
        ),
        Ev::PiiDecisionReceipt(receipt) => format!(
            "PiiDecisionReceipt session={} target={} risk_surface={} decision={:?} decision_hash={} span_count={} ambiguous={}",
            receipt
                .session_id
                .as_ref()
                .map(prefix_hex_4)
                .unwrap_or_else(|| "none".to_string()),
            receipt.target,
            receipt.risk_surface,
            receipt.decision,
            hex::encode(receipt.decision_hash),
            receipt.span_count,
            receipt.ambiguous
        ),
        Ev::PiiReviewRequested {
            decision_hash,
            summary,
            session_id,
            ..
        } => format!(
            "PiiReviewRequested session={} decision_hash={} target={} span_summary_{}",
            session_id
                .as_ref()
                .map(prefix_hex_4)
                .unwrap_or_else(|| "none".to_string()),
            hex::encode(decision_hash),
            summary.target_label,
            text_fingerprint(&summary.span_summary)
        ),
        Ev::IntentResolutionReceipt(receipt) => format!(
            "IntentResolutionReceipt session={} intent_id={} scope={:?} band={:?} score={:.3} constrained={} receipt_hash={}",
            receipt
                .session_id
                .as_ref()
                .map(prefix_hex_4)
                .unwrap_or_else(|| "none".to_string()),
            receipt.intent_id,
            receipt.scope,
            receipt.band,
            receipt.score,
            receipt.constrained,
            hex::encode(receipt.receipt_hash)
        ),
        Ev::ExecutionContractReceipt(receipt) => format!(
            "ExecutionContractReceipt session={} step_index={} intent_id={} stage={} key={} satisfied={} evidence_commit_hash={}",
            prefix_hex_4(&receipt.session_id),
            receipt.step_index,
            receipt.intent_id,
            receipt.stage,
            receipt.key,
            receipt.satisfied,
            receipt.evidence_commit_hash
        ),
        Ev::PlanReceipt(receipt) => format!(
            "PlanReceipt session={} selected_route={} plan_hash={} worker_count={} policy_bindings={}",
            receipt
                .session_id
                .as_ref()
                .map(prefix_hex_4)
                .unwrap_or_else(|| "none".to_string()),
            receipt.selected_route,
            hex::encode(receipt.plan_hash),
            receipt.worker_graph.len(),
            receipt.policy_bindings.len()
        ),
    }
}
