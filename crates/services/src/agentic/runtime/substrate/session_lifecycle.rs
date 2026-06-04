use super::*;

pub(super) fn session_trace_bundle_for_state(
    state: &AgentState,
    envelope: &RuntimeExecutionEnvelope,
    prompt_assembly: &PromptAssemblyContract,
    postconditions: &PostconditionSynthesis,
    stop_condition: &StopConditionRecord,
) -> SessionTraceBundle {
    SessionTraceBundle {
        bundle_id: envelope.trace_bundle_id.clone(),
        config_snapshot_ref: "EffectiveAgentConfig:default".to_string(),
        prompt_section_hashes: prompt_assembly
            .sections
            .iter()
            .map(|section| section.content_hash.clone())
            .collect(),
        model_call_refs: state
            .command_history
            .iter()
            .map(|command| format!("command:{}:{}", command.step_index, command.timestamp_ms))
            .collect(),
        model_output_refs: Vec::new(),
        tool_proposal_refs: state.recent_actions.clone(),
        policy_decision_refs: state
            .pending_tool_hash
            .map(|hash| vec![format!("pending_tool_hash:{}", hex::encode(hash))])
            .unwrap_or_default(),
        approval_refs: if state.pending_approval.is_some() {
            vec!["pending_approval".to_string()]
        } else {
            Vec::new()
        },
        execution_receipt_refs: state
            .execution_ledger
            .attempts
            .iter()
            .map(|attempt| format!("execution_attempt:{}", attempt.attempt_id))
            .collect(),
        memory_retrieval_refs: state
            .resolved_intent
            .as_ref()
            .map(|intent| vec![format!("intent:{}", intent.intent_id)])
            .unwrap_or_default(),
        child_agent_state_refs: state
            .child_session_ids
            .iter()
            .map(hex::encode)
            .map(|sid| format!("child_agent:{sid}"))
            .collect(),
        final_outcome_ref: format!("{:?}:{}", stop_condition.reason, stop_condition.rationale),
        redaction_manifest_ref: "runtime_redaction:default".to_string(),
        verification_result_ref: if postconditions.all_required_checks_proven() {
            "postconditions:passed".to_string()
        } else {
            "postconditions:unknown_or_pending".to_string()
        },
        reconstructs_final_state: !envelope.envelope_id.trim().is_empty()
            && !prompt_assembly.final_prompt_hash.trim().is_empty()
            && !stop_condition.rationale.trim().is_empty(),
        evidence_refs: vec![EvidenceRef::new(
            "runtime_snapshot",
            format!("{}:{}", envelope.session_id, state.step_count),
        )],
    }
}

pub(super) fn workflow_envelope_adapter_for_surface(
    surface: RuntimeSurface,
) -> WorkflowEnvelopeAdapter {
    WorkflowEnvelopeAdapter {
        workflow_surface: RuntimeSurface::Workflow,
        target_surface: surface,
        evidence_refs: vec![EvidenceRef {
            kind: "runtime_substrate_port".to_string(),
            reference: "RuntimeSubstratePortContract".to_string(),
            summary: "workflow execution maps into the public runtime envelope".to_string(),
        }],
        ..WorkflowEnvelopeAdapter::default()
    }
}

pub(super) fn harness_trace_adapter_for_surface(surface: RuntimeSurface) -> HarnessTraceAdapter {
    HarnessTraceAdapter {
        fixture_scope: match surface {
            RuntimeSurface::Harness | RuntimeSurface::Benchmark => {
                "validation_trace_and_scorecard".to_string()
            }
            _ => "runtime_trace_projection".to_string(),
        },
        evidence_refs: vec![EvidenceRef {
            kind: "runtime_trace".to_string(),
            reference: "exported_trace_bundle".to_string(),
            summary: "harness validation consumes exported substrate evidence".to_string(),
        }],
        ..HarnessTraceAdapter::default()
    }
}

pub(super) fn operator_interruption_contract_for_state(
    state: &AgentState,
) -> OperatorInterruptionContract {
    OperatorInterruptionContract {
        evidence_refs: vec![EvidenceRef {
            kind: "agent_status".to_string(),
            reference: format!("agent_state:{}", hex::encode(state.session_id)),
            summary: format!("status:{:?};pause:{:?}", state.status, state.pause_reason()),
        }],
        ..OperatorInterruptionContract::default()
    }
}
