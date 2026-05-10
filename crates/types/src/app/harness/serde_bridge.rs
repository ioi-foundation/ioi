use super::*;

fn harness_enum_from_str<T>(value: &str) -> Option<T>
where
    T: DeserializeOwned,
{
    serde_json::from_value(Value::String(value.to_string())).ok()
}

fn harness_optional_string(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(Value::as_str).map(str::to_string)
}

fn harness_string_array(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

pub fn harness_replay_envelope_from_camel_value(value: Option<&Value>) -> HarnessReplayEnvelope {
    let replay = value.unwrap_or(&Value::Null);
    let deterministic = replay
        .get("deterministicEnvelope")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let determinism = replay
        .get("determinism")
        .and_then(Value::as_str)
        .and_then(harness_enum_from_str)
        .unwrap_or(if deterministic {
            HarnessReplayDeterminism::Deterministic
        } else {
            HarnessReplayDeterminism::Nondeterministic
        });
    HarnessReplayEnvelope {
        deterministic_envelope: deterministic,
        captures_input: replay
            .get("capturesInput")
            .and_then(Value::as_bool)
            .unwrap_or(true),
        captures_output: replay
            .get("capturesOutput")
            .and_then(Value::as_bool)
            .unwrap_or(true),
        captures_policy_decision: replay
            .get("capturesPolicyDecision")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        fixture_ref: harness_optional_string(replay, "fixtureRef"),
        determinism,
        nondeterminism_reason: harness_optional_string(replay, "nondeterminismReason"),
        redaction_policy: harness_optional_string(replay, "redactionPolicy")
            .unwrap_or_else(|| "runtime_redacted".to_string()),
    }
}

pub fn harness_node_attempt_record_from_camel_value(
    attempt: &Value,
) -> Option<HarnessNodeAttemptRecord> {
    let component_kind: HarnessComponentKind = attempt
        .get("componentKind")
        .and_then(Value::as_str)
        .and_then(harness_enum_from_str)?;
    let execution_mode: HarnessExecutionMode = attempt
        .get("executionMode")
        .and_then(Value::as_str)
        .and_then(harness_enum_from_str)?;
    let readiness: HarnessComponentReadiness = attempt
        .get("readiness")
        .and_then(Value::as_str)
        .and_then(harness_enum_from_str)?;
    let status: HarnessNodeAttemptStatus = attempt
        .get("status")
        .and_then(Value::as_str)
        .and_then(harness_enum_from_str)?;
    let attempt_index = attempt
        .get("attemptIndex")
        .and_then(Value::as_u64)
        .unwrap_or(0)
        .min(u32::MAX as u64) as u32;
    Some(HarnessNodeAttemptRecord {
        attempt_id: harness_optional_string(attempt, "attemptId")?,
        harness_workflow_id: harness_optional_string(attempt, "harnessWorkflowId")
            .unwrap_or_else(|| DEFAULT_AGENT_HARNESS_WORKFLOW_ID.to_string()),
        harness_activation_id: harness_optional_string(attempt, "harnessActivationId")
            .unwrap_or_else(|| DEFAULT_AGENT_HARNESS_ACTIVATION_ID.to_string()),
        harness_hash: harness_optional_string(attempt, "harnessHash")
            .unwrap_or_else(|| DEFAULT_AGENT_HARNESS_HASH.to_string()),
        workflow_node_id: harness_optional_string(attempt, "workflowNodeId")?,
        component_id: harness_optional_string(attempt, "componentId")
            .unwrap_or_else(|| component_kind.component_id()),
        component_kind,
        execution_mode,
        readiness,
        attempt_index,
        status,
        input_hash: harness_optional_string(attempt, "inputHash"),
        output_hash: harness_optional_string(attempt, "outputHash"),
        error_class: harness_optional_string(attempt, "errorClass"),
        policy_decision: harness_optional_string(attempt, "policyDecision"),
        started_at_ms: attempt.get("startedAtMs").and_then(Value::as_u64),
        duration_ms: attempt.get("durationMs").and_then(Value::as_u64),
        receipt_ids: harness_string_array(attempt.get("receiptIds")),
        evidence_refs: harness_string_array(attempt.get("evidenceRefs")),
        replay: harness_replay_envelope_from_camel_value(attempt.get("replay")),
    })
}

pub fn harness_replay_envelope_camel_value(replay: &HarnessReplayEnvelope) -> Value {
    json!({
        "deterministicEnvelope": replay.deterministic_envelope,
        "capturesInput": replay.captures_input,
        "capturesOutput": replay.captures_output,
        "capturesPolicyDecision": replay.captures_policy_decision,
        "fixtureRef": &replay.fixture_ref,
        "determinism": replay.determinism.as_str(),
        "nondeterminismReason": &replay.nondeterminism_reason,
        "redactionPolicy": &replay.redaction_policy,
    })
}

pub fn harness_node_attempt_record_camel_value(attempt: &HarnessNodeAttemptRecord) -> Value {
    json!({
        "attemptId": &attempt.attempt_id,
        "harnessWorkflowId": &attempt.harness_workflow_id,
        "harnessActivationId": &attempt.harness_activation_id,
        "harnessHash": &attempt.harness_hash,
        "workflowNodeId": &attempt.workflow_node_id,
        "componentId": &attempt.component_id,
        "componentKind": attempt.component_kind.as_str(),
        "executionMode": attempt.execution_mode.as_str(),
        "readiness": attempt.readiness.as_str(),
        "attemptIndex": attempt.attempt_index,
        "status": attempt.status.as_str(),
        "inputHash": &attempt.input_hash,
        "outputHash": &attempt.output_hash,
        "errorClass": &attempt.error_class,
        "policyDecision": &attempt.policy_decision,
        "startedAtMs": attempt.started_at_ms,
        "durationMs": attempt.duration_ms,
        "receiptIds": &attempt.receipt_ids,
        "evidenceRefs": &attempt.evidence_refs,
        "replay": harness_replay_envelope_camel_value(&attempt.replay),
    })
}

pub fn harness_action_frame_camel_value(frame: &HarnessActionFrame) -> Value {
    json!({
        "workflowId": &frame.workflow_id,
        "workflowVersion": &frame.workflow_version,
        "workflowHash": &frame.workflow_hash,
        "executionMode": frame.execution_mode.as_str(),
        "nodeId": &frame.node_id,
        "componentId": &frame.component_id,
        "componentVersion": &frame.component_version,
        "componentKind": frame.component_kind.as_str(),
        "readiness": frame.readiness.as_str(),
        "kernelRef": &frame.kernel_ref,
        "slotIds": &frame.slot_ids,
        "deterministicEnvelope": frame.deterministic_envelope,
        "replay": harness_replay_envelope_camel_value(&frame.replay),
        "eventKinds": &frame.event_kinds,
        "evidenceKeys": &frame.evidence_keys,
    })
}

pub fn harness_component_adapter_result_camel_value(
    result: &HarnessComponentAdapterResult,
) -> Value {
    json!({
        "schemaVersion": &result.schema_version,
        "invocationId": &result.invocation_id,
        "actionFrame": harness_action_frame_camel_value(&result.action_frame),
        "nodeAttempt": harness_node_attempt_record_camel_value(&result.node_attempt),
        "slotIds": &result.slot_ids,
        "resultHash": &result.result_hash,
        "errorClass": &result.error_class,
        "readiness": result.readiness.as_str(),
        "receiptIds": &result.receipt_ids,
        "replay": harness_replay_envelope_camel_value(&result.replay),
    })
}

pub fn harness_shadow_comparison_camel_value(comparison: &HarnessShadowComparison) -> Value {
    json!({
        "workflowNodeId": &comparison.workflow_node_id,
        "componentKind": comparison.component_kind.as_str(),
        "liveAttemptId": &comparison.live_attempt_id,
        "shadowAttemptId": &comparison.shadow_attempt_id,
        "divergence": comparison.divergence.as_str(),
        "blocking": comparison.blocking,
        "summary": &comparison.summary,
        "evidenceRefs": &comparison.evidence_refs,
    })
}

pub fn harness_gated_cluster_status_as_str(status: HarnessClusterPromotionStatus) -> &'static str {
    match status {
        HarnessClusterPromotionStatus::ShadowReady => "shadow_ready",
        HarnessClusterPromotionStatus::Gated => "gated",
        HarnessClusterPromotionStatus::Blocked => "blocked",
        HarnessClusterPromotionStatus::Live => "live",
    }
}

pub fn harness_gated_cluster_run_camel_value(run: &HarnessGatedClusterRun) -> Value {
    let component_kinds = run
        .component_kinds
        .iter()
        .map(|component_kind| component_kind.as_str())
        .collect::<Vec<_>>();
    json!({
        "schemaVersion": &run.schema_version,
        "runId": &run.run_id,
        "clusterId": run.cluster_id.as_str(),
        "clusterLabel": &run.cluster_label,
        "harnessWorkflowId": &run.harness_workflow_id,
        "harnessActivationId": &run.harness_activation_id,
        "harnessHash": &run.harness_hash,
        "executionMode": run.execution_mode.as_str(),
        "status": harness_gated_cluster_status_as_str(run.status),
        "componentKinds": component_kinds,
        "shadowRunId": &run.shadow_run_id,
        "nodeAttemptIds": &run.node_attempt_ids,
        "receiptIds": &run.receipt_ids,
        "replayFixtureRefs": &run.replay_fixture_refs,
        "activationBlockers": &run.activation_blockers,
        "gateDecision": &run.gate_decision,
        "rollbackTarget": &run.rollback_target,
        "rollbackAvailable": true,
        "canaryStatus": &run.canary_status,
        "promotionBlocked": run.promotion_blocked,
        "evidenceRefs": &run.evidence_refs,
    })
}
