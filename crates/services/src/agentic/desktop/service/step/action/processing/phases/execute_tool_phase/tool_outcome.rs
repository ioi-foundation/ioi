use super::events::{
    emit_completion_gate_status_event, emit_completion_gate_violation_events,
    emit_execution_contract_receipt_event, emit_execution_contract_receipt_event_with_observation,
};
use super::system_fail::handle_system_fail_outcome;
use super::web_followup::apply_web_research_followups;
use super::*;
use crate::agentic::desktop::service::step::action::command_contract::WEB_PIPELINE_TERMINAL_RECEIPT;
use crate::agentic::desktop::service::step::queue::handle_web_search_result;

pub(super) struct ToolOutcomeContext<'a, 's> {
    pub service: &'a DesktopAgentService,
    pub state: &'s mut dyn StateAccess,
    pub agent_state: &'a mut AgentState,
    pub rules: &'a ActionRules,
    pub tool: &'a AgentTool,
    pub tool_args: &'a serde_json::Value,
    pub session_id: [u8; 32],
    pub block_height: u64,
    pub block_timestamp_ns: u64,
    pub step_index: u32,
    pub resolved_intent_id: &'a str,
    pub synthesized_payload_hash: Option<String>,
    pub command_scope: bool,
    pub success: &'a mut bool,
    pub error_msg: &'a mut Option<String>,
    pub history_entry: &'a mut Option<String>,
    pub action_output: &'a mut Option<String>,
    pub is_lifecycle_action: &'a mut bool,
    pub current_tool_name: &'a mut String,
    pub terminal_chat_reply_output: &'a mut Option<String>,
    pub verification_checks: &'a mut Vec<String>,
    pub command_probe_completed: &'a mut bool,
}

async fn crystallize_successful_session(
    service: &DesktopAgentService,
    state: &mut dyn StateAccess,
    agent_state: &AgentState,
    session_id: [u8; 32],
    block_height: u64,
) {
    evaluate_and_crystallize(service, state, agent_state, session_id).await;
    let _ = service
        .update_skill_reputation(state, session_id, true, block_height)
        .await;
}

pub(super) async fn apply_tool_outcome_and_followups(
    ctx: ToolOutcomeContext<'_, '_>,
) -> Result<(), TransactionError> {
    let ToolOutcomeContext {
        service,
        state,
        agent_state,
        rules,
        tool,
        tool_args,
        session_id,
        block_height,
        block_timestamp_ns,
        step_index,
        resolved_intent_id,
        synthesized_payload_hash,
        command_scope,
        success,
        error_msg,
        history_entry,
        action_output,
        is_lifecycle_action,
        current_tool_name,
        terminal_chat_reply_output,
        verification_checks,
        command_probe_completed,
    } = ctx;

    match tool {
        AgentTool::AgentComplete { result } => {
            let missing_contract_markers =
                missing_execution_contract_markers_with_rules(agent_state, rules);
            if !missing_contract_markers.is_empty() {
                let missing = missing_contract_markers.join(",");
                let contract_error = execution_contract_violation_error(&missing);
                *success = false;
                *error_msg = Some(contract_error.clone());
                *history_entry = Some(contract_error.clone());
                *action_output = Some(contract_error);
                agent_state.status = AgentStatus::Running;
                verification_checks.push("execution_contract_gate_blocked=true".to_string());
                verification_checks.push(format!("execution_contract_missing_keys={}", missing));
                emit_completion_gate_violation_events(
                    service,
                    session_id,
                    step_index,
                    resolved_intent_id,
                    &missing,
                );
            } else {
                let completed_result =
                    if is_system_clock_read_intent(agent_state.resolved_intent.as_ref()) {
                        summarize_system_clock_or_plain_output(result)
                            .unwrap_or_else(|| result.clone())
                    } else {
                        result.clone()
                    };
                let completed_result = enrich_command_scope_summary(&completed_result, agent_state);
                agent_state.status = AgentStatus::Completed(Some(completed_result.clone()));
                *is_lifecycle_action = true;
                *action_output = Some(completed_result.clone());
                if !completed_result.trim().is_empty() {
                    *terminal_chat_reply_output = Some(completed_result.clone());
                    verification_checks.push("terminal_chat_reply_ready=true".to_string());
                }
                crystallize_successful_session(
                    service,
                    state,
                    agent_state,
                    session_id,
                    block_height,
                )
                .await;
                emit_completion_gate_status_event(
                    service,
                    session_id,
                    step_index,
                    resolved_intent_id,
                    true,
                    "agent_complete_contract_gate_passed",
                );
            }
        }
        AgentTool::SysChangeDir { .. } => {
            if *success {
                if let Some(new_cwd) = history_entry.as_ref() {
                    agent_state.working_directory = new_cwd.clone();
                }
            }
        }
        AgentTool::MathEval { .. } => {
            if *success {
                if let Some(observed_result) = history_entry
                    .as_deref()
                    .or(action_output.as_deref())
                    .and_then(summarize_math_eval_output)
                {
                    let evidence = format!("math_result={}", observed_result);
                    emit_execution_contract_receipt_event_with_observation(
                        service,
                        session_id,
                        step_index,
                        resolved_intent_id,
                        "verification",
                        "math_result",
                        true,
                        &evidence,
                        Some("tool_output"),
                        Some(observed_result.as_str()),
                        Some("number"),
                        None,
                        None,
                        synthesized_payload_hash.clone(),
                    );
                }
            }
        }
        AgentTool::ChatReply { message } => {
            if let Some(pending) = agent_state.pending_search_completion.clone() {
                if let Some(reason) =
                    web_pipeline_completion_reason(&pending, web_pipeline_now_ms())
                {
                    append_final_web_completion_receipts(&pending, reason, verification_checks);
                    let summary = if let Some(hybrid_summary) =
                        synthesize_web_pipeline_reply_hybrid(service, &pending, reason).await
                    {
                        hybrid_summary
                    } else {
                        synthesize_web_pipeline_reply(&pending, reason)
                    };
                    let summary = enrich_command_scope_summary(&summary, agent_state);
                    mark_execution_receipt(
                        &mut agent_state.tool_execution_log,
                        WEB_PIPELINE_TERMINAL_RECEIPT,
                    );
                    verification_checks.push(receipt_marker(WEB_PIPELINE_TERMINAL_RECEIPT));
                    verification_checks.push("web_pipeline_active=false".to_string());
                    verification_checks.push("terminal_chat_reply_ready=true".to_string());
                    agent_state.status = AgentStatus::Completed(Some(summary.clone()));
                    agent_state.pending_search_completion = None;
                    *is_lifecycle_action = true;
                    *history_entry = Some(summary.clone());
                    *action_output = Some(summary.clone());
                    *terminal_chat_reply_output = Some(summary.clone());
                    crystallize_successful_session(
                        service,
                        state,
                        agent_state,
                        session_id,
                        block_height,
                    )
                    .await;
                    emit_completion_gate_status_event(
                        service,
                        session_id,
                        step_index,
                        resolved_intent_id,
                        true,
                        "chat_reply_web_pipeline_contract_gate_passed",
                    );
                    emit_execution_contract_receipt_event(
                        service,
                        session_id,
                        step_index,
                        resolved_intent_id,
                        "completion_gate",
                        WEB_PIPELINE_TERMINAL_RECEIPT,
                        true,
                        "pending_web_pipeline_terminalized",
                        None,
                        None,
                        synthesized_payload_hash.clone(),
                    );
                    return Ok(());
                }
            }
            let missing_contract_markers =
                missing_execution_contract_markers_with_rules(agent_state, rules);
            if !missing_contract_markers.is_empty() {
                let missing = missing_contract_markers.join(",");
                let contract_error = execution_contract_violation_error(&missing);
                *success = false;
                *error_msg = Some(contract_error.clone());
                *history_entry = Some(contract_error.clone());
                *action_output = Some(contract_error);
                agent_state.status = AgentStatus::Running;
                verification_checks.push("execution_contract_gate_blocked=true".to_string());
                verification_checks.push(format!("execution_contract_missing_keys={}", missing));
                emit_completion_gate_violation_events(
                    service,
                    session_id,
                    step_index,
                    resolved_intent_id,
                    &missing,
                );
            } else {
                let message = enrich_command_scope_summary(message, agent_state);
                agent_state.status = AgentStatus::Completed(Some(message.clone()));
                *is_lifecycle_action = true;
                *action_output = Some(message.clone());
                *terminal_chat_reply_output = Some(message.clone());
                crystallize_successful_session(
                    service,
                    state,
                    agent_state,
                    session_id,
                    block_height,
                )
                .await;
                emit_completion_gate_status_event(
                    service,
                    session_id,
                    step_index,
                    resolved_intent_id,
                    true,
                    "chat_reply_contract_gate_passed",
                );
            }
        }
        AgentTool::OsLaunchApp { app_name } => {
            if *success
                && should_auto_complete_open_app_goal(
                    &agent_state.goal,
                    app_name,
                    agent_state
                        .target
                        .as_ref()
                        .and_then(|target| target.app_hint.as_deref()),
                )
            {
                let summary = format!("Opened {}.", app_name);
                agent_state.status = AgentStatus::Completed(Some(summary.clone()));
                *is_lifecycle_action = true;
                *action_output = Some(summary.clone());
                *terminal_chat_reply_output = Some(summary);
                verification_checks.push("terminal_chat_reply_ready=true".to_string());
                agent_state.execution_queue.clear();
                agent_state.pending_search_completion = None;
                crystallize_successful_session(
                    service,
                    state,
                    agent_state,
                    session_id,
                    block_height,
                )
                .await;
                log::info!(
                    "Auto-completed app-launch session {} after successful os__launch_app.",
                    hex::encode(&session_id[..4])
                );
            }
        }
        AgentTool::MediaExtractTranscript { url, language, .. } => {
            if *success {
                if let Some(bundle) = history_entry
                    .as_deref()
                    .or(action_output.as_deref())
                    .and_then(parse_media_transcript_bundle)
                {
                    let provider_id = bundle.provider_id.clone();
                    let duration_value = bundle.duration_seconds.map(|value| value.to_string());
                    let transcript_char_count_value = bundle.transcript_char_count.to_string();
                    let transcript_segment_count_value = bundle.segment_count.to_string();
                    let provider_candidates = if bundle.provider_candidates.is_empty() {
                        vec![crate::agentic::web::media_provider_candidate_receipt(
                            &provider_id,
                            url,
                            true,
                            true,
                            None,
                        )]
                    } else {
                        bundle.provider_candidates.clone()
                    };

                    mark_execution_receipt(&mut agent_state.tool_execution_log, "host_discovery");
                    mark_execution_receipt(
                        &mut agent_state.tool_execution_log,
                        "provider_selection",
                    );
                    mark_execution_receipt(&mut agent_state.tool_execution_log, "execution");
                    mark_execution_receipt(&mut agent_state.tool_execution_log, "verification");
                    mark_execution_postcondition(
                        &mut agent_state.tool_execution_log,
                        "media_transcript_available",
                    );

                    verification_checks.push(receipt_marker("host_discovery"));
                    verification_checks.push(receipt_marker("provider_selection"));
                    verification_checks.push(receipt_marker("execution"));
                    verification_checks.push(receipt_marker("verification"));
                    verification_checks.push(postcondition_marker("media_transcript_available"));

                    emit_execution_contract_receipt_event_with_observation(
                        service,
                        session_id,
                        step_index,
                        resolved_intent_id,
                        "discovery",
                        "host_discovery",
                        true,
                        "managed_media_provider_discovered",
                        Some("media__extract_transcript.runtime"),
                        Some(bundle.provider_version.as_str()),
                        Some("version"),
                        None,
                        Some(provider_id.clone()),
                        synthesized_payload_hash.clone(),
                    );
                    for provider_candidate in provider_candidates {
                        let provider_candidate_provider_id = provider_candidate.provider_id.clone();
                        let provider_candidate_json =
                            serde_json::to_string(&provider_candidate).unwrap_or_default();
                        emit_execution_contract_receipt_event_with_observation(
                            service,
                            session_id,
                            step_index,
                            resolved_intent_id,
                            "discovery",
                            "provider_candidate",
                            provider_candidate.success,
                            "managed_media_provider_candidate",
                            Some("media__extract_transcript.discovery"),
                            Some(provider_candidate_json.as_str()),
                            Some("json"),
                            None,
                            Some(provider_candidate_provider_id),
                            synthesized_payload_hash.clone(),
                        );
                    }
                    emit_execution_contract_receipt_event_with_observation(
                        service,
                        session_id,
                        step_index,
                        resolved_intent_id,
                        "provider_selection",
                        "provider_selection",
                        true,
                        "managed_media_provider_selected",
                        Some("media__extract_transcript.selection"),
                        Some(provider_id.as_str()),
                        Some("provider_id"),
                        None,
                        Some(provider_id.clone()),
                        synthesized_payload_hash.clone(),
                    );
                    emit_execution_contract_receipt_event_with_observation(
                        service,
                        session_id,
                        step_index,
                        resolved_intent_id,
                        "execution",
                        "execution",
                        true,
                        "media_transcript_executed",
                        Some("media__extract_transcript.execution"),
                        Some(bundle.canonical_url.as_str()),
                        Some("url"),
                        None,
                        Some(provider_id.clone()),
                        synthesized_payload_hash.clone(),
                    );
                    emit_execution_contract_receipt_event_with_observation(
                        service,
                        session_id,
                        step_index,
                        resolved_intent_id,
                        "verification",
                        "verification",
                        true,
                        "media_transcript_verified",
                        Some("media__extract_transcript.verification"),
                        Some(bundle.transcript_hash.as_str()),
                        Some("sha256"),
                        None,
                        Some(provider_id.clone()),
                        synthesized_payload_hash.clone(),
                    );
                    emit_execution_contract_receipt_event_with_observation(
                        service,
                        session_id,
                        step_index,
                        resolved_intent_id,
                        "verification",
                        "media_title",
                        bundle.title.as_deref().is_some(),
                        "media_title_observed",
                        Some("media__extract_transcript.bundle"),
                        bundle.title.as_deref(),
                        Some("text"),
                        None,
                        Some(provider_id.clone()),
                        synthesized_payload_hash.clone(),
                    );
                    emit_execution_contract_receipt_event_with_observation(
                        service,
                        session_id,
                        step_index,
                        resolved_intent_id,
                        "verification",
                        "media_duration_seconds",
                        bundle.duration_seconds.unwrap_or_default() > 0,
                        "media_duration_observed",
                        Some("media__extract_transcript.bundle"),
                        duration_value.as_deref(),
                        Some("seconds"),
                        None,
                        Some(provider_id.clone()),
                        synthesized_payload_hash.clone(),
                    );
                    emit_execution_contract_receipt_event_with_observation(
                        service,
                        session_id,
                        step_index,
                        resolved_intent_id,
                        "verification",
                        "media_transcript_char_count",
                        bundle.transcript_char_count > 0,
                        "media_transcript_chars_observed",
                        Some("media__extract_transcript.bundle"),
                        Some(transcript_char_count_value.as_str()),
                        Some("char_count"),
                        None,
                        Some(provider_id.clone()),
                        synthesized_payload_hash.clone(),
                    );
                    emit_execution_contract_receipt_event_with_observation(
                        service,
                        session_id,
                        step_index,
                        resolved_intent_id,
                        "verification",
                        "media_transcript_segment_count",
                        bundle.segment_count > 0,
                        "media_transcript_segments_observed",
                        Some("media__extract_transcript.bundle"),
                        Some(transcript_segment_count_value.as_str()),
                        Some("segment_count"),
                        None,
                        Some(provider_id.clone()),
                        synthesized_payload_hash.clone(),
                    );
                    emit_execution_contract_receipt_event_with_observation(
                        service,
                        session_id,
                        step_index,
                        resolved_intent_id,
                        "verification",
                        "media_transcript_source_kind",
                        true,
                        "media_transcript_source_kind_observed",
                        Some("media__extract_transcript.bundle"),
                        Some(bundle.transcript_source_kind.as_str()),
                        Some("enum"),
                        None,
                        Some(provider_id.clone()),
                        synthesized_payload_hash.clone(),
                    );
                    emit_execution_contract_receipt_event_with_observation(
                        service,
                        session_id,
                        step_index,
                        resolved_intent_id,
                        "verification",
                        "media_transcript_language",
                        true,
                        "media_transcript_language_observed",
                        Some("media__extract_transcript.bundle"),
                        Some(bundle.transcript_language.as_str()),
                        Some("language"),
                        None,
                        Some(provider_id.clone()),
                        synthesized_payload_hash.clone(),
                    );
                    emit_execution_contract_receipt_event_with_observation(
                        service,
                        session_id,
                        step_index,
                        resolved_intent_id,
                        "verification",
                        "selected_source_url",
                        true,
                        "media_canonical_url_selected",
                        Some("media__extract_transcript.bundle"),
                        Some(bundle.canonical_url.as_str()),
                        Some("url"),
                        None,
                        Some(provider_id.clone()),
                        synthesized_payload_hash.clone(),
                    );
                    emit_execution_contract_receipt_event_with_observation(
                        service,
                        session_id,
                        step_index,
                        resolved_intent_id,
                        "verification",
                        "selected_source_total",
                        true,
                        "media_selected_source_total_observed",
                        Some("media__extract_transcript.bundle"),
                        Some("1"),
                        Some("scalar"),
                        None,
                        Some(provider_id.clone()),
                        synthesized_payload_hash.clone(),
                    );
                    emit_execution_contract_receipt_event_with_observation(
                        service,
                        session_id,
                        step_index,
                        resolved_intent_id,
                        "verification",
                        "selected_source_distinct_domains",
                        true,
                        "media_selected_source_distinct_domains_observed",
                        Some("media__extract_transcript.bundle"),
                        Some("1"),
                        Some("scalar"),
                        None,
                        Some(provider_id.clone()),
                        synthesized_payload_hash.clone(),
                    );
                    emit_execution_contract_receipt_event_with_observation(
                        service,
                        session_id,
                        step_index,
                        resolved_intent_id,
                        "verification",
                        "selected_source_quality_floor",
                        true,
                        "media_selected_source_quality_floor_met",
                        Some("media__extract_transcript.bundle"),
                        Some("selected_total=1;distinct_domains=1"),
                        Some("summary"),
                        None,
                        Some(provider_id.clone()),
                        synthesized_payload_hash.clone(),
                    );
                    emit_execution_contract_receipt_event_with_observation(
                        service,
                        session_id,
                        step_index,
                        resolved_intent_id,
                        "verification",
                        "media_transcript_available",
                        true,
                        "media_transcript_postcondition_met",
                        Some("media__extract_transcript.bundle"),
                        Some("true"),
                        Some("bool"),
                        None,
                        Some(provider_id),
                        synthesized_payload_hash.clone(),
                    );
                    verification_checks.push(format!(
                        "media_requested_language={}",
                        language.as_deref().unwrap_or("en")
                    ));
                }
            }
        }
        AgentTool::MediaExtractMultimodalEvidence { url, language, .. } => {
            if *success {
                if let Some(bundle) = history_entry
                    .as_deref()
                    .or(action_output.as_deref())
                    .and_then(parse_media_multimodal_bundle)
                {
                    let selected_provider_ids = if bundle.selected_provider_ids.is_empty() {
                        bundle
                            .transcript
                            .as_ref()
                            .map(|transcript| vec![transcript.provider_id.clone()])
                            .unwrap_or_default()
                    } else {
                        bundle.selected_provider_ids.clone()
                    };
                    let primary_provider_id = selected_provider_ids
                        .first()
                        .cloned()
                        .or_else(|| {
                            bundle
                                .transcript
                                .as_ref()
                                .map(|transcript| transcript.provider_id.clone())
                        })
                        .or_else(|| {
                            bundle
                                .visual
                                .as_ref()
                                .map(|visual| visual.provider_id.clone())
                        })
                        .unwrap_or_else(|| "media.multimodal".to_string());
                    let duration_value = bundle.duration_seconds.map(|value| value.to_string());
                    let selected_modalities_value = if bundle.selected_modalities.is_empty() {
                        String::new()
                    } else {
                        bundle.selected_modalities.join(",")
                    };
                    let selected_providers_value = selected_provider_ids.join(",");
                    let provider_candidates = bundle.provider_candidates.clone();

                    mark_execution_receipt(&mut agent_state.tool_execution_log, "host_discovery");
                    mark_execution_receipt(
                        &mut agent_state.tool_execution_log,
                        "provider_selection",
                    );
                    mark_execution_receipt(&mut agent_state.tool_execution_log, "execution");
                    mark_execution_receipt(&mut agent_state.tool_execution_log, "verification");
                    mark_execution_postcondition(
                        &mut agent_state.tool_execution_log,
                        "media_multimodal_evidence_available",
                    );
                    if bundle.transcript.is_some() {
                        mark_execution_postcondition(
                            &mut agent_state.tool_execution_log,
                            "media_transcript_available",
                        );
                    }
                    if bundle.visual.is_some() {
                        mark_execution_postcondition(
                            &mut agent_state.tool_execution_log,
                            "media_visual_evidence_available",
                        );
                    }

                    verification_checks.push(receipt_marker("host_discovery"));
                    verification_checks.push(receipt_marker("provider_selection"));
                    verification_checks.push(receipt_marker("execution"));
                    verification_checks.push(receipt_marker("verification"));
                    verification_checks
                        .push(postcondition_marker("media_multimodal_evidence_available"));
                    if bundle.transcript.is_some() {
                        verification_checks
                            .push(postcondition_marker("media_transcript_available"));
                    }
                    if bundle.visual.is_some() {
                        verification_checks
                            .push(postcondition_marker("media_visual_evidence_available"));
                    }

                    emit_execution_contract_receipt_event_with_observation(
                        service,
                        session_id,
                        step_index,
                        resolved_intent_id,
                        "discovery",
                        "host_discovery",
                        true,
                        "managed_media_multimodal_provider_discovered",
                        Some("media__extract_multimodal_evidence.runtime"),
                        Some(selected_providers_value.as_str()),
                        Some("provider_ids"),
                        None,
                        Some(primary_provider_id.clone()),
                        synthesized_payload_hash.clone(),
                    );
                    for provider_candidate in provider_candidates {
                        let provider_candidate_provider_id = provider_candidate.provider_id.clone();
                        let provider_candidate_json =
                            serde_json::to_string(&provider_candidate).unwrap_or_default();
                        emit_execution_contract_receipt_event_with_observation(
                            service,
                            session_id,
                            step_index,
                            resolved_intent_id,
                            "discovery",
                            "provider_candidate",
                            provider_candidate.success,
                            "managed_media_provider_candidate",
                            Some("media__extract_multimodal_evidence.discovery"),
                            Some(provider_candidate_json.as_str()),
                            Some("json"),
                            None,
                            Some(provider_candidate_provider_id),
                            synthesized_payload_hash.clone(),
                        );
                    }
                    emit_execution_contract_receipt_event_with_observation(
                        service,
                        session_id,
                        step_index,
                        resolved_intent_id,
                        "provider_selection",
                        "provider_selection",
                        true,
                        "managed_media_multimodal_provider_selected",
                        Some("media__extract_multimodal_evidence.selection"),
                        Some(selected_providers_value.as_str()),
                        Some("provider_ids"),
                        None,
                        Some(primary_provider_id.clone()),
                        synthesized_payload_hash.clone(),
                    );
                    emit_execution_contract_receipt_event_with_observation(
                        service,
                        session_id,
                        step_index,
                        resolved_intent_id,
                        "provider_selection",
                        "selected_modalities",
                        !selected_modalities_value.trim().is_empty(),
                        "media_modalities_selected",
                        Some("media__extract_multimodal_evidence.selection"),
                        Some(selected_modalities_value.as_str()),
                        Some("csv"),
                        None,
                        Some(primary_provider_id.clone()),
                        synthesized_payload_hash.clone(),
                    );
                    emit_execution_contract_receipt_event_with_observation(
                        service,
                        session_id,
                        step_index,
                        resolved_intent_id,
                        "execution",
                        "execution",
                        true,
                        "media_multimodal_executed",
                        Some("media__extract_multimodal_evidence.execution"),
                        Some(bundle.canonical_url.as_str()),
                        Some("url"),
                        None,
                        Some(primary_provider_id.clone()),
                        synthesized_payload_hash.clone(),
                    );
                    emit_execution_contract_receipt_event_with_observation(
                        service,
                        session_id,
                        step_index,
                        resolved_intent_id,
                        "verification",
                        "verification",
                        true,
                        "media_multimodal_verified",
                        Some("media__extract_multimodal_evidence.verification"),
                        Some(bundle.canonical_url.as_str()),
                        Some("url"),
                        None,
                        Some(primary_provider_id.clone()),
                        synthesized_payload_hash.clone(),
                    );
                    emit_execution_contract_receipt_event_with_observation(
                        service,
                        session_id,
                        step_index,
                        resolved_intent_id,
                        "verification",
                        "media_title",
                        bundle.title.as_deref().is_some(),
                        "media_title_observed",
                        Some("media__extract_multimodal_evidence.bundle"),
                        bundle.title.as_deref(),
                        Some("text"),
                        None,
                        Some(primary_provider_id.clone()),
                        synthesized_payload_hash.clone(),
                    );
                    emit_execution_contract_receipt_event_with_observation(
                        service,
                        session_id,
                        step_index,
                        resolved_intent_id,
                        "verification",
                        "media_duration_seconds",
                        bundle.duration_seconds.unwrap_or_default() > 0,
                        "media_duration_observed",
                        Some("media__extract_multimodal_evidence.bundle"),
                        duration_value.as_deref(),
                        Some("seconds"),
                        None,
                        Some(primary_provider_id.clone()),
                        synthesized_payload_hash.clone(),
                    );
                    emit_execution_contract_receipt_event_with_observation(
                        service,
                        session_id,
                        step_index,
                        resolved_intent_id,
                        "verification",
                        "selected_source_url",
                        true,
                        "media_canonical_url_selected",
                        Some("media__extract_multimodal_evidence.bundle"),
                        Some(bundle.canonical_url.as_str()),
                        Some("url"),
                        None,
                        Some(primary_provider_id.clone()),
                        synthesized_payload_hash.clone(),
                    );
                    emit_execution_contract_receipt_event_with_observation(
                        service,
                        session_id,
                        step_index,
                        resolved_intent_id,
                        "verification",
                        "selected_source_total",
                        true,
                        "media_selected_source_total_observed",
                        Some("media__extract_multimodal_evidence.bundle"),
                        Some("1"),
                        Some("scalar"),
                        None,
                        Some(primary_provider_id.clone()),
                        synthesized_payload_hash.clone(),
                    );
                    emit_execution_contract_receipt_event_with_observation(
                        service,
                        session_id,
                        step_index,
                        resolved_intent_id,
                        "verification",
                        "selected_source_distinct_domains",
                        true,
                        "media_selected_source_distinct_domains_observed",
                        Some("media__extract_multimodal_evidence.bundle"),
                        Some("1"),
                        Some("scalar"),
                        None,
                        Some(primary_provider_id.clone()),
                        synthesized_payload_hash.clone(),
                    );
                    emit_execution_contract_receipt_event_with_observation(
                        service,
                        session_id,
                        step_index,
                        resolved_intent_id,
                        "verification",
                        "selected_source_quality_floor",
                        true,
                        "media_selected_source_quality_floor_met",
                        Some("media__extract_multimodal_evidence.bundle"),
                        Some("selected_total=1;distinct_domains=1"),
                        Some("summary"),
                        None,
                        Some(primary_provider_id.clone()),
                        synthesized_payload_hash.clone(),
                    );
                    emit_execution_contract_receipt_event_with_observation(
                        service,
                        session_id,
                        step_index,
                        resolved_intent_id,
                        "verification",
                        "media_multimodal_evidence_available",
                        true,
                        "media_multimodal_postcondition_met",
                        Some("media__extract_multimodal_evidence.bundle"),
                        Some("true"),
                        Some("bool"),
                        None,
                        Some(primary_provider_id.clone()),
                        synthesized_payload_hash.clone(),
                    );

                    if let Some(transcript) = bundle.transcript.as_ref() {
                        let transcript_char_count_value =
                            transcript.transcript_char_count.to_string();
                        let transcript_segment_count_value = transcript.segment_count.to_string();
                        emit_execution_contract_receipt_event_with_observation(
                            service,
                            session_id,
                            step_index,
                            resolved_intent_id,
                            "verification",
                            "media_transcript_char_count",
                            transcript.transcript_char_count > 0,
                            "media_transcript_chars_observed",
                            Some("media__extract_multimodal_evidence.bundle"),
                            Some(transcript_char_count_value.as_str()),
                            Some("char_count"),
                            None,
                            Some(transcript.provider_id.clone()),
                            synthesized_payload_hash.clone(),
                        );
                        emit_execution_contract_receipt_event_with_observation(
                            service,
                            session_id,
                            step_index,
                            resolved_intent_id,
                            "verification",
                            "media_transcript_segment_count",
                            transcript.segment_count > 0,
                            "media_transcript_segments_observed",
                            Some("media__extract_multimodal_evidence.bundle"),
                            Some(transcript_segment_count_value.as_str()),
                            Some("segment_count"),
                            None,
                            Some(transcript.provider_id.clone()),
                            synthesized_payload_hash.clone(),
                        );
                        emit_execution_contract_receipt_event_with_observation(
                            service,
                            session_id,
                            step_index,
                            resolved_intent_id,
                            "verification",
                            "media_transcript_source_kind",
                            true,
                            "media_transcript_source_kind_observed",
                            Some("media__extract_multimodal_evidence.bundle"),
                            Some(transcript.transcript_source_kind.as_str()),
                            Some("enum"),
                            None,
                            Some(transcript.provider_id.clone()),
                            synthesized_payload_hash.clone(),
                        );
                        emit_execution_contract_receipt_event_with_observation(
                            service,
                            session_id,
                            step_index,
                            resolved_intent_id,
                            "verification",
                            "media_transcript_language",
                            true,
                            "media_transcript_language_observed",
                            Some("media__extract_multimodal_evidence.bundle"),
                            Some(transcript.transcript_language.as_str()),
                            Some("language"),
                            None,
                            Some(transcript.provider_id.clone()),
                            synthesized_payload_hash.clone(),
                        );
                        emit_execution_contract_receipt_event_with_observation(
                            service,
                            session_id,
                            step_index,
                            resolved_intent_id,
                            "verification",
                            "media_transcript_available",
                            true,
                            "media_transcript_postcondition_met",
                            Some("media__extract_multimodal_evidence.bundle"),
                            Some("true"),
                            Some("bool"),
                            None,
                            Some(transcript.provider_id.clone()),
                            synthesized_payload_hash.clone(),
                        );
                    }
                    if let Some(visual) = bundle.visual.as_ref() {
                        let visual_frame_count_value = visual.frame_count.to_string();
                        let visual_char_count_value = visual.visual_char_count.to_string();
                        emit_execution_contract_receipt_event_with_observation(
                            service,
                            session_id,
                            step_index,
                            resolved_intent_id,
                            "verification",
                            "media_visual_frame_count",
                            visual.frame_count > 0,
                            "media_visual_frames_observed",
                            Some("media__extract_multimodal_evidence.bundle"),
                            Some(visual_frame_count_value.as_str()),
                            Some("frame_count"),
                            None,
                            Some(visual.provider_id.clone()),
                            synthesized_payload_hash.clone(),
                        );
                        emit_execution_contract_receipt_event_with_observation(
                            service,
                            session_id,
                            step_index,
                            resolved_intent_id,
                            "verification",
                            "media_visual_char_count",
                            visual.visual_char_count > 0,
                            "media_visual_chars_observed",
                            Some("media__extract_multimodal_evidence.bundle"),
                            Some(visual_char_count_value.as_str()),
                            Some("char_count"),
                            None,
                            Some(visual.provider_id.clone()),
                            synthesized_payload_hash.clone(),
                        );
                        emit_execution_contract_receipt_event_with_observation(
                            service,
                            session_id,
                            step_index,
                            resolved_intent_id,
                            "verification",
                            "media_visual_hash",
                            !visual.visual_hash.trim().is_empty(),
                            "media_visual_hash_observed",
                            Some("media__extract_multimodal_evidence.bundle"),
                            Some(visual.visual_hash.as_str()),
                            Some("sha256"),
                            None,
                            Some(visual.provider_id.clone()),
                            synthesized_payload_hash.clone(),
                        );
                        emit_execution_contract_receipt_event_with_observation(
                            service,
                            session_id,
                            step_index,
                            resolved_intent_id,
                            "verification",
                            "media_visual_evidence_available",
                            true,
                            "media_visual_postcondition_met",
                            Some("media__extract_multimodal_evidence.bundle"),
                            Some("true"),
                            Some("bool"),
                            None,
                            Some(visual.provider_id.clone()),
                            synthesized_payload_hash.clone(),
                        );
                    }
                    verification_checks.push(format!(
                        "media_requested_language={}",
                        language.as_deref().unwrap_or("en")
                    ));
                }
            }
        }
        AgentTool::SysInstallPackage { package, .. } => {
            if *success && command_scope {
                let summary = history_entry
                    .as_deref()
                    .map(str::trim)
                    .filter(|entry| !entry.is_empty())
                    .map(str::to_string)
                    .unwrap_or_else(|| format!("Installed package '{}'.", package));
                let summary = enrich_command_scope_summary(&summary, agent_state);
                let missing_contract_markers =
                    missing_execution_contract_markers_with_rules(agent_state, rules);
                if missing_contract_markers.is_empty() {
                    *error_msg = None;
                    agent_state.status = AgentStatus::Completed(Some(summary.clone()));
                    *is_lifecycle_action = true;
                    *action_output = Some(summary.clone());
                    *terminal_chat_reply_output = None;
                    verification_checks.push("install_dependency_terminalized=true".to_string());
                    agent_state.execution_queue.clear();
                    agent_state.pending_search_completion = None;
                    crystallize_successful_session(
                        service,
                        state,
                        agent_state,
                        session_id,
                        block_height,
                    )
                    .await;
                    emit_completion_gate_status_event(
                        service,
                        session_id,
                        step_index,
                        resolved_intent_id,
                        true,
                        "install_dependency_completion_gate_passed",
                    );
                } else {
                    let missing = missing_contract_markers.join(",");
                    let contract_error = execution_contract_violation_error(&missing);
                    *success = false;
                    *error_msg = Some(contract_error.clone());
                    *history_entry = Some(contract_error.clone());
                    *action_output = Some(contract_error);
                    agent_state.status = AgentStatus::Running;
                    verification_checks.push("execution_contract_gate_blocked=true".to_string());
                    verification_checks
                        .push(format!("execution_contract_missing_keys={}", missing));
                    emit_completion_gate_violation_events(
                        service,
                        session_id,
                        step_index,
                        resolved_intent_id,
                        &missing,
                    );
                }
            }
        }
        AgentTool::AutomationCreateMonitor { title, .. } => {
            if *success && command_scope {
                let summary = history_entry
                    .as_deref()
                    .map(str::trim)
                    .filter(|entry| !entry.is_empty())
                    .map(str::to_string)
                    .unwrap_or_else(|| {
                        format!(
                            "Installed automation monitor '{}'.",
                            title.as_deref().unwrap_or("workflow")
                        )
                    });
                let summary = enrich_command_scope_summary(&summary, agent_state);
                let missing_contract_markers =
                    missing_execution_contract_markers_with_rules(agent_state, rules);
                if missing_contract_markers.is_empty() {
                    *error_msg = None;
                    agent_state.status = AgentStatus::Completed(Some(summary.clone()));
                    *is_lifecycle_action = true;
                    *action_output = Some(summary.clone());
                    *terminal_chat_reply_output = Some(summary);
                    verification_checks.push("automation_monitor_terminalized=true".to_string());
                    verification_checks.push("terminal_chat_reply_ready=true".to_string());
                    agent_state.execution_queue.clear();
                    agent_state.pending_search_completion = None;
                    crystallize_successful_session(
                        service,
                        state,
                        agent_state,
                        session_id,
                        block_height,
                    )
                    .await;
                    emit_completion_gate_status_event(
                        service,
                        session_id,
                        step_index,
                        resolved_intent_id,
                        true,
                        "automation_monitor_completion_gate_passed",
                    );
                } else {
                    let missing = missing_contract_markers.join(",");
                    let contract_error = execution_contract_violation_error(&missing);
                    *success = false;
                    *error_msg = Some(contract_error.clone());
                    *history_entry = Some(contract_error.clone());
                    *action_output = Some(contract_error);
                    agent_state.status = AgentStatus::Running;
                    verification_checks.push("execution_contract_gate_blocked=true".to_string());
                    verification_checks
                        .push(format!("execution_contract_missing_keys={}", missing));
                    emit_completion_gate_violation_events(
                        service,
                        session_id,
                        step_index,
                        resolved_intent_id,
                        &missing,
                    );
                }
            }
        }
        AgentTool::SysExec { .. } | AgentTool::SysExecSession { .. } => {
            if is_command_probe_intent(agent_state.resolved_intent.as_ref()) {
                if let Some(raw) = history_entry.as_deref() {
                    if let Some(summary) = summarize_command_probe_output(tool, raw) {
                        // Probe markers are deterministic completion signals even
                        // when the underlying command exits non-zero.
                        *command_probe_completed = true;
                        *success = true;
                        *error_msg = None;
                        agent_state.status = AgentStatus::Completed(Some(summary.clone()));
                        *is_lifecycle_action = true;
                        *action_output = Some(summary);
                        agent_state.execution_queue.clear();
                        agent_state.pending_search_completion = None;
                        crystallize_successful_session(
                            service,
                            state,
                            agent_state,
                            session_id,
                            block_height,
                        )
                        .await;
                    }
                }
            } else if is_system_clock_read_intent(agent_state.resolved_intent.as_ref()) {
                if let Some(summary) = history_entry
                    .as_deref()
                    .and_then(summarize_system_clock_or_plain_output)
                {
                    let summary = enrich_command_scope_summary(&summary, agent_state);
                    mark_execution_postcondition(
                        &mut agent_state.tool_execution_log,
                        CLOCK_TIMESTAMP_POSTCONDITION,
                    );
                    verification_checks.push(postcondition_marker(CLOCK_TIMESTAMP_POSTCONDITION));
                    emit_execution_contract_receipt_event_with_observation(
                        service,
                        session_id,
                        step_index,
                        resolved_intent_id,
                        "verification",
                        CLOCK_TIMESTAMP_POSTCONDITION,
                        true,
                        "clock_timestamp_observed=true",
                        Some("command_history"),
                        Some(summary.as_str()),
                        Some("rfc3339_utc"),
                        None,
                        None,
                        synthesized_payload_hash.clone(),
                    );
                    *success = true;
                    *error_msg = None;
                    agent_state.status = AgentStatus::Completed(Some(summary.clone()));
                    *is_lifecycle_action = true;
                    *action_output = Some(summary.clone());
                    *terminal_chat_reply_output = Some(summary);
                    agent_state.execution_queue.clear();
                    agent_state.pending_search_completion = None;
                    crystallize_successful_session(
                        service,
                        state,
                        agent_state,
                        session_id,
                        block_height,
                    )
                    .await;
                } else {
                    let missing = postcondition_marker(CLOCK_TIMESTAMP_POSTCONDITION);
                    let contract_error = execution_contract_violation_error(&missing);
                    *success = false;
                    *error_msg = Some(contract_error.clone());
                    *history_entry = Some(contract_error.clone());
                    *action_output = Some(contract_error);
                    agent_state.status = AgentStatus::Running;
                    verification_checks.push("execution_contract_gate_blocked=true".to_string());
                    verification_checks
                        .push(format!("execution_contract_missing_keys={}", missing));
                    emit_execution_contract_receipt_event_with_observation(
                        service,
                        session_id,
                        step_index,
                        resolved_intent_id,
                        "verification",
                        CLOCK_TIMESTAMP_POSTCONDITION,
                        false,
                        "clock_timestamp_observed=false",
                        Some("command_history"),
                        None,
                        Some("rfc3339_utc"),
                        None,
                        None,
                        synthesized_payload_hash.clone(),
                    );
                }
            } else if command_scope {
                if let Some(summary) = history_entry.as_deref().and_then(|raw| {
                    summarize_structured_command_receipt_output(
                        raw,
                        agent_state
                            .command_history
                            .back()
                            .map(|entry| entry.timestamp_ms),
                    )
                }) {
                    let summary = enrich_command_scope_summary(&summary, agent_state);
                    let missing_contract_markers =
                        missing_execution_contract_markers_with_rules(agent_state, rules);
                    if missing_contract_markers.is_empty() {
                        *success = true;
                        *error_msg = None;
                        agent_state.status = AgentStatus::Completed(Some(summary.clone()));
                        *is_lifecycle_action = true;
                        *action_output = Some(summary.clone());
                        *terminal_chat_reply_output = Some(summary);
                        agent_state.execution_queue.clear();
                        agent_state.pending_search_completion = None;
                        verification_checks
                            .push("structured_command_receipt_terminalized=true".to_string());
                        verification_checks.push("terminal_chat_reply_ready=true".to_string());
                        crystallize_successful_session(
                            service,
                            state,
                            agent_state,
                            session_id,
                            block_height,
                        )
                        .await;
                        emit_completion_gate_status_event(
                            service,
                            session_id,
                            step_index,
                            resolved_intent_id,
                            true,
                            "command_scope_structured_receipt_completion_gate_passed",
                        );
                    } else {
                        let missing = missing_contract_markers.join(",");
                        let contract_error = execution_contract_violation_error(&missing);
                        *success = false;
                        *error_msg = Some(contract_error.clone());
                        *history_entry = Some(contract_error.clone());
                        *action_output = Some(contract_error);
                        verification_checks
                            .push("execution_contract_gate_blocked=true".to_string());
                        verification_checks
                            .push(format!("execution_contract_missing_keys={}", missing));
                        emit_completion_gate_violation_events(
                            service,
                            session_id,
                            step_index,
                            resolved_intent_id,
                            &missing,
                        );
                    }
                } else if let Some(summary) =
                    duplicate_command_completion_summary(tool, agent_state.command_history.back())
                {
                    let missing_contract_markers =
                        missing_execution_contract_markers_with_rules(agent_state, rules);
                    if missing_contract_markers.is_empty() {
                        *success = true;
                        *error_msg = None;
                        agent_state.status = AgentStatus::Completed(Some(summary.clone()));
                        *is_lifecycle_action = true;
                        *action_output = Some(summary.clone());
                        *terminal_chat_reply_output = Some(summary);
                        agent_state.execution_queue.clear();
                        agent_state.pending_search_completion = None;
                        verification_checks.push("timer_schedule_terminalized=true".to_string());
                        verification_checks.push("terminal_chat_reply_ready=true".to_string());
                        crystallize_successful_session(
                            service,
                            state,
                            agent_state,
                            session_id,
                            block_height,
                        )
                        .await;
                        emit_completion_gate_status_event(
                            service,
                            session_id,
                            step_index,
                            resolved_intent_id,
                            true,
                            "command_scope_completion_gate_passed",
                        );
                    } else {
                        let missing = missing_contract_markers.join(",");
                        let contract_error = execution_contract_violation_error(&missing);
                        *success = false;
                        *error_msg = Some(contract_error.clone());
                        *history_entry = Some(contract_error.clone());
                        *action_output = Some(contract_error);
                        verification_checks
                            .push("execution_contract_gate_blocked=true".to_string());
                        verification_checks
                            .push(format!("execution_contract_missing_keys={}", missing));
                        emit_completion_gate_violation_events(
                            service,
                            session_id,
                            step_index,
                            resolved_intent_id,
                            &missing,
                        );
                    }
                } else if let Some(summary) =
                    verified_command_probe_completion_summary(tool, &agent_state.command_history)
                {
                    let summary = enrich_command_scope_summary(&summary, agent_state);
                    let missing_contract_markers =
                        missing_execution_contract_markers_with_rules(agent_state, rules);
                    if missing_contract_markers.is_empty() {
                        *success = true;
                        *error_msg = None;
                        agent_state.status = AgentStatus::Completed(Some(summary.clone()));
                        *is_lifecycle_action = true;
                        *action_output = Some(summary.clone());
                        *terminal_chat_reply_output = Some(summary);
                        agent_state.execution_queue.clear();
                        agent_state.pending_search_completion = None;
                        verification_checks
                            .push("verified_command_probe_terminalized=true".to_string());
                        verification_checks.push("terminal_chat_reply_ready=true".to_string());
                        crystallize_successful_session(
                            service,
                            state,
                            agent_state,
                            session_id,
                            block_height,
                        )
                        .await;
                        emit_completion_gate_status_event(
                            service,
                            session_id,
                            step_index,
                            resolved_intent_id,
                            true,
                            "command_scope_verified_probe_completion_gate_passed",
                        );
                    } else {
                        let missing = missing_contract_markers.join(",");
                        let contract_error = execution_contract_violation_error(&missing);
                        *success = false;
                        *error_msg = Some(contract_error.clone());
                        *history_entry = Some(contract_error.clone());
                        *action_output = Some(contract_error);
                        verification_checks
                            .push("execution_contract_gate_blocked=true".to_string());
                        verification_checks
                            .push(format!("execution_contract_missing_keys={}", missing));
                        emit_completion_gate_violation_events(
                            service,
                            session_id,
                            step_index,
                            resolved_intent_id,
                            &missing,
                        );
                    }
                }
            }
        }
        AgentTool::MemorySearch { query } => {
            let mut completion_summary = None;
            let effective_tool_name = current_tool_name.clone();
            handle_web_search_result(
                service,
                agent_state,
                session_id,
                step_index,
                effective_tool_name.as_str(),
                tool,
                false,
                success,
                history_entry,
                error_msg,
                &mut completion_summary,
                verification_checks,
            )
            .await?;
            if let Some(summary) = completion_summary {
                if history_entry.is_none() {
                    *history_entry = Some(summary.clone());
                }
                *action_output = Some(summary.clone());
                *terminal_chat_reply_output = Some(summary);
                *is_lifecycle_action = true;
            }
            let promoted_memory_search = *success
                && current_tool_name.eq_ignore_ascii_case("web__search")
                && verification_checks
                    .iter()
                    .any(|check| check == "memory_search_promoted_to_web_search=true");

            if !promoted_memory_search
                && *success
                && should_use_web_research_path(agent_state)
                && agent_state.pending_search_completion.is_none()
                && history_entry
                    .as_deref()
                    .map(is_empty_memory_search_output)
                    .unwrap_or(true)
            {
                let bootstrap_query = if query.trim().is_empty() {
                    agent_state.goal.clone()
                } else {
                    query.clone()
                };
                let queued = queue_web_search_bootstrap(agent_state, session_id, &bootstrap_query)?;
                verification_checks.push("web_search_bootstrap_from_memory=true".to_string());
                let note = if queued {
                    "No memory hits for this news query; queued deterministic web__search."
                        .to_string()
                } else {
                    "No memory hits for this news query; deterministic web__search was already queued."
                        .to_string()
                };
                *history_entry = Some(note.clone());
                *action_output = Some(note);
                agent_state.status = AgentStatus::Running;
            }
        }
        AgentTool::WebSearch { .. } => {
            let mut completion_summary = None;
            handle_web_search_result(
                service,
                agent_state,
                session_id,
                step_index,
                current_tool_name.as_str(),
                tool,
                false,
                success,
                history_entry,
                error_msg,
                &mut completion_summary,
                verification_checks,
            )
            .await?;
            if let Some(summary) = completion_summary {
                if history_entry.is_none() {
                    *history_entry = Some(summary.clone());
                }
                *action_output = Some(summary.clone());
                *terminal_chat_reply_output = Some(summary);
                *is_lifecycle_action = true;
            }
        }
        AgentTool::SystemFail { reason, .. } => {
            handle_system_fail_outcome(
                agent_state,
                reason,
                block_timestamp_ns,
                success,
                error_msg,
                history_entry,
                action_output,
                terminal_chat_reply_output,
                current_tool_name,
                is_lifecycle_action,
                verification_checks,
            );
        }
        _ => {}
    }

    apply_web_research_followups(
        agent_state,
        *success,
        current_tool_name.as_str(),
        session_id,
        step_index,
        tool_args,
        history_entry,
        action_output,
        verification_checks,
    )?;
    Ok(())
}

fn parse_media_transcript_bundle(
    raw: &str,
) -> Option<ioi_types::app::agentic::MediaTranscriptBundle> {
    serde_json::from_str(raw).ok()
}

fn parse_media_multimodal_bundle(
    raw: &str,
) -> Option<ioi_types::app::agentic::MediaMultimodalBundle> {
    serde_json::from_str(raw).ok()
}
