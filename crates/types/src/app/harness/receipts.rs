use super::*;

#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct HarnessReceiptBinding {
    pub harness_workflow_id: String,
    pub harness_activation_id: String,
    pub harness_hash: String,
    pub workflow_node_id: String,
    pub component_id: String,
    pub component_kind: HarnessComponentKind,
    pub event_kind: String,
    pub receipt_id: String,
    pub step_index: Option<u32>,
    pub evidence_refs: Vec<String>,
    pub decision_reason: String,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum HarnessBindingError {
    #[error("harness workflow id is missing")]
    MissingWorkflowId,
    #[error("harness activation id is missing")]
    MissingActivationId,
    #[error("harness hash is missing")]
    MissingHash,
    #[error("harness activation hash is missing")]
    MissingActivationHash,
    #[error("harness worker binding registry record is blocked")]
    RegistryBlocked,
    #[error("harness worker binding registry identity does not match worker binding")]
    RegistryWorkerBindingMismatch,
}
pub fn harness_component_kind_for_action_target(target: &ActionTarget) -> HarnessComponentKind {
    match target {
        ActionTarget::ModelRespond | ActionTarget::ModelEmbed | ActionTarget::ModelRerank => {
            HarnessComponentKind::ModelCall
        }
        ActionTarget::WalletSign | ActionTarget::WalletSend => {
            HarnessComponentKind::WalletCapability
        }
        ActionTarget::FsRead | ActionTarget::WebRetrieve | ActionTarget::BrowserInspect => {
            HarnessComponentKind::ToolCall
        }
        ActionTarget::FsWrite | ActionTarget::ClipboardWrite => HarnessComponentKind::ToolCall,
        ActionTarget::Custom(name) => harness_component_kind_for_tool_name(name),
        _ => HarnessComponentKind::ToolCall,
    }
}

pub fn harness_component_kind_for_tool_name(tool_name: &str) -> HarnessComponentKind {
    let normalized = tool_name.trim().to_ascii_lowercase();
    if normalized.starts_with("mcp__") || normalized.contains("__mcp_") {
        return HarnessComponentKind::McpToolCall;
    }
    if normalized.starts_with("memory__") {
        return if normalized.contains("write") || normalized.contains("save") {
            HarnessComponentKind::MemoryWrite
        } else {
            HarnessComponentKind::MemoryRead
        };
    }
    if normalized.starts_with("model__")
        || normalized.starts_with("llm__")
        || normalized.starts_with("inference__")
    {
        return HarnessComponentKind::ModelCall;
    }
    if normalized.starts_with("wallet__") {
        return HarnessComponentKind::WalletCapability;
    }
    if normalized.starts_with("connector__")
        || normalized.starts_with("gmail__")
        || normalized.starts_with("calendar__")
        || normalized.starts_with("mail__")
        || normalized.starts_with("google_workspace__")
    {
        return HarnessComponentKind::ConnectorCall;
    }
    HarnessComponentKind::ToolCall
}

pub fn harness_component_kind_for_policy_decision(
    policy_decision: &str,
    gate_state: &str,
) -> HarnessComponentKind {
    let decision = policy_decision.to_ascii_lowercase();
    let gate = gate_state.to_ascii_lowercase();
    if decision.contains("approval")
        || gate.contains("pending")
        || gate.contains("approved")
        || gate.contains("denied")
        || gate.contains("required")
    {
        HarnessComponentKind::ApprovalGate
    } else {
        HarnessComponentKind::PolicyGate
    }
}

fn workload_tool_name(receipt: &WorkloadReceipt) -> &str {
    match receipt {
        WorkloadReceipt::Exec(receipt) => &receipt.tool_name,
        WorkloadReceipt::FsWrite(receipt) => &receipt.tool_name,
        WorkloadReceipt::NetFetch(receipt) => &receipt.tool_name,
        WorkloadReceipt::WebRetrieve(receipt) => &receipt.tool_name,
        WorkloadReceipt::MemoryRetrieve(receipt) => &receipt.tool_name,
        WorkloadReceipt::Inference(receipt) => &receipt.tool_name,
        WorkloadReceipt::Media(receipt) => &receipt.tool_name,
        WorkloadReceipt::ModelLifecycle(receipt) => &receipt.tool_name,
        WorkloadReceipt::Worker(receipt) => &receipt.tool_name,
        WorkloadReceipt::ParentPlaybook(receipt) => &receipt.tool_name,
        WorkloadReceipt::Adapter(receipt) => &receipt.tool_name,
    }
}

fn workload_component_kind(receipt: &WorkloadReceipt) -> HarnessComponentKind {
    match receipt {
        WorkloadReceipt::Inference(_) => HarnessComponentKind::ModelCall,
        WorkloadReceipt::ModelLifecycle(_) => HarnessComponentKind::ModelRouter,
        WorkloadReceipt::MemoryRetrieve(_) => HarnessComponentKind::MemoryRead,
        WorkloadReceipt::Worker(_) => HarnessComponentKind::MergeJudge,
        WorkloadReceipt::ParentPlaybook(_) => HarnessComponentKind::Planner,
        WorkloadReceipt::Adapter(receipt) => match &receipt.kind {
            AdapterKind::Mcp => HarnessComponentKind::McpToolCall,
            AdapterKind::Connector => HarnessComponentKind::ConnectorCall,
            _ => harness_component_kind_for_tool_name(&receipt.tool_name),
        },
        other => harness_component_kind_for_tool_name(workload_tool_name(other)),
    }
}

fn receipt_binding(
    component_kind: HarnessComponentKind,
    event_kind: impl Into<String>,
    receipt_id: impl Into<String>,
    step_index: Option<u32>,
    evidence_refs: Vec<String>,
    decision_reason: impl Into<String>,
) -> HarnessReceiptBinding {
    HarnessReceiptBinding {
        harness_workflow_id: DEFAULT_AGENT_HARNESS_WORKFLOW_ID.to_string(),
        harness_activation_id: DEFAULT_AGENT_HARNESS_ACTIVATION_ID.to_string(),
        harness_hash: DEFAULT_AGENT_HARNESS_HASH.to_string(),
        workflow_node_id: component_kind.workflow_node_id(),
        component_id: component_kind.component_id(),
        component_kind,
        event_kind: event_kind.into(),
        receipt_id: receipt_id.into(),
        step_index,
        evidence_refs,
        decision_reason: decision_reason.into(),
    }
}

pub fn default_harness_receipt_binding_for_workload(
    event: &WorkloadReceiptEvent,
) -> HarnessReceiptBinding {
    let component_kind = workload_component_kind(&event.receipt);
    receipt_binding(
        component_kind,
        "KernelEvent::WorkloadReceipt",
        format!("workload:{}:{}", event.step_index, event.workload_id),
        Some(event.step_index),
        vec![
            format!("workload_id:{}", event.workload_id),
            format!("tool:{}", workload_tool_name(&event.receipt)),
        ],
        "typed workload receipt mapped to default harness component",
    )
}

pub fn default_harness_receipt_binding_for_routing(
    receipt: &RoutingReceiptEvent,
) -> HarnessReceiptBinding {
    let component_kind =
        harness_component_kind_for_policy_decision(&receipt.policy_decision, &receipt.gate_state);
    receipt_binding(
        component_kind,
        "KernelEvent::RoutingReceipt",
        format!("routing:{}:{}", receipt.step_index, receipt.intent_hash),
        Some(receipt.step_index),
        vec![
            format!("intent_hash:{}", receipt.intent_hash),
            format!("policy_decision:{}", receipt.policy_decision),
            format!("tool:{}", receipt.tool_name),
        ],
        "routing decision mapped to policy or approval gate",
    )
}

pub fn default_harness_receipt_binding_for_execution_contract(
    receipt: &ExecutionContractReceiptEvent,
) -> HarnessReceiptBinding {
    let stage = receipt.stage.to_ascii_lowercase();
    let component_kind = match stage.as_str() {
        "provider_selection" => HarnessComponentKind::ToolRouter,
        "verification" => HarnessComponentKind::Verifier,
        "completion_gate" => HarnessComponentKind::CompletionGate,
        "execution" => HarnessComponentKind::ToolCall,
        _ => HarnessComponentKind::ReceiptWriter,
    };
    receipt_binding(
        component_kind,
        "KernelEvent::ExecutionContractReceipt",
        format!(
            "cec:{}:{}:{}",
            receipt.step_index, receipt.stage, receipt.key
        ),
        Some(receipt.step_index),
        vec![
            format!("intent_id:{}", receipt.intent_id),
            format!("evidence_commit_hash:{}", receipt.evidence_commit_hash),
        ],
        "execution contract receipt mapped by lifecycle stage",
    )
}

pub fn default_harness_receipt_binding_for_plan(
    receipt: &PlanReceiptEvent,
) -> HarnessReceiptBinding {
    let plan_hash = receipt
        .plan_hash
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    receipt_binding(
        HarnessComponentKind::Planner,
        "KernelEvent::PlanReceipt",
        format!("plan:{plan_hash}"),
        None,
        vec![
            format!("selected_route:{}", receipt.selected_route),
            format!("workers:{}", receipt.worker_graph.len()),
        ],
        "planner receipt mapped to planner component",
    )
}

fn harness_node_attempt_receipt_hash(prefix: &str, binding: &HarnessReceiptBinding) -> String {
    harness_stable_fnv1a32(&format!(
        "{}:{}:{}:{}:{}",
        prefix,
        binding.receipt_id,
        binding.workflow_node_id,
        binding.component_id,
        harness_stable_json_string_array(&binding.evidence_refs)
    ))
}

pub fn default_harness_node_attempt_for_receipt(
    binding: &HarnessReceiptBinding,
    execution_mode: HarnessExecutionMode,
    attempt_index: u32,
    status: HarnessNodeAttemptStatus,
) -> HarnessNodeAttemptRecord {
    let component = default_harness_component_spec(binding.component_kind);
    HarnessNodeAttemptRecord {
        attempt_id: format!(
            "{}:{}:{}",
            binding.workflow_node_id, attempt_index, binding.receipt_id
        ),
        harness_workflow_id: binding.harness_workflow_id.clone(),
        harness_activation_id: binding.harness_activation_id.clone(),
        harness_hash: binding.harness_hash.clone(),
        workflow_node_id: binding.workflow_node_id.clone(),
        component_id: binding.component_id.clone(),
        component_kind: binding.component_kind,
        execution_mode,
        readiness: component.readiness,
        attempt_index,
        status,
        input_hash: Some(harness_node_attempt_receipt_hash("input", binding)),
        output_hash: Some(harness_node_attempt_receipt_hash("output", binding)),
        error_class: None,
        policy_decision: binding
            .evidence_refs
            .iter()
            .find_map(|entry| entry.strip_prefix("policy_decision:").map(str::to_string)),
        started_at_ms: None,
        duration_ms: None,
        receipt_ids: vec![binding.receipt_id.clone()],
        evidence_refs: binding.evidence_refs.clone(),
        replay: default_harness_replay_envelope(binding.component_kind),
    }
}

pub fn default_harness_shadow_run_for_attempts(
    run_id: impl Into<String>,
    source_session_id: Option<String>,
    live_turn_id: Option<String>,
    node_attempts: Vec<HarnessNodeAttemptRecord>,
    comparisons: Vec<HarnessShadowComparison>,
    evidence_refs: Vec<String>,
) -> HarnessShadowRun {
    let blocking_divergence_count = comparisons
        .iter()
        .filter(|comparison| comparison.blocking)
        .count() as u32;
    let unclassified_divergence_count = comparisons
        .iter()
        .filter(|comparison| comparison.divergence == HarnessDivergenceClass::Unclassified)
        .count() as u32;
    HarnessShadowRun {
        schema_version: "ioi.agent-harness.shadow-run.v1".to_string(),
        run_id: run_id.into(),
        harness_workflow_id: DEFAULT_AGENT_HARNESS_WORKFLOW_ID.to_string(),
        harness_activation_id: DEFAULT_AGENT_HARNESS_ACTIVATION_ID.to_string(),
        harness_hash: DEFAULT_AGENT_HARNESS_HASH.to_string(),
        source_session_id,
        live_turn_id,
        execution_mode: HarnessExecutionMode::Shadow,
        node_attempts,
        comparisons,
        blocking_divergence_count,
        unclassified_divergence_count,
        promotion_blocked: blocking_divergence_count > 0 || unclassified_divergence_count > 0,
        evidence_refs,
    }
}

pub fn default_harness_gated_cluster_run_for_shadow_run(
    cluster_id: HarnessPromotionClusterId,
    shadow_run: &HarnessShadowRun,
) -> HarnessGatedClusterRun {
    let component_kinds = promotion_cluster_components(cluster_id);
    let mut node_attempt_ids = Vec::new();
    let mut receipt_ids = Vec::new();
    let mut replay_fixture_refs = Vec::new();
    let mut activation_blockers = Vec::new();

    for component_kind in &component_kinds {
        let attempts = shadow_run
            .node_attempts
            .iter()
            .filter(|attempt| attempt.component_kind == *component_kind)
            .collect::<Vec<_>>();
        if attempts.is_empty() {
            activation_blockers.push(format!("missing_attempt:{}", component_kind.as_str()));
            continue;
        }
        for attempt in attempts {
            node_attempt_ids.push(attempt.attempt_id.clone());
            receipt_ids.extend(attempt.receipt_ids.clone());
            if let Some(fixture_ref) = attempt.replay.fixture_ref.clone() {
                replay_fixture_refs.push(fixture_ref);
            } else {
                activation_blockers.push(format!(
                    "missing_replay_fixture:{}",
                    component_kind.as_str()
                ));
            }
            if !matches!(
                attempt.readiness,
                HarnessComponentReadiness::ShadowReady | HarnessComponentReadiness::LiveReady
            ) {
                activation_blockers.push(format!(
                    "readiness_below_shadow:{}",
                    component_kind.as_str()
                ));
            }
            if attempt.receipt_ids.is_empty() {
                activation_blockers.push(format!("missing_receipt:{}", component_kind.as_str()));
            }
        }
    }

    if shadow_run.blocking_divergence_count > 0 {
        activation_blockers.push("blocking_shadow_divergence".to_string());
    }
    if shadow_run.unclassified_divergence_count > 0 {
        activation_blockers.push("unclassified_shadow_divergence".to_string());
    }

    node_attempt_ids.sort();
    node_attempt_ids.dedup();
    receipt_ids.sort();
    receipt_ids.dedup();
    replay_fixture_refs.sort();
    replay_fixture_refs.dedup();
    activation_blockers.sort();
    activation_blockers.dedup();

    let promotion_blocked = !activation_blockers.is_empty();
    HarnessGatedClusterRun {
        schema_version: "ioi.agent-harness.gated-cluster-run.v1".to_string(),
        run_id: format!("{}:{}:gated", shadow_run.run_id, cluster_id.as_str()),
        cluster_id,
        cluster_label: cluster_id.label().to_string(),
        harness_workflow_id: shadow_run.harness_workflow_id.clone(),
        harness_activation_id: shadow_run.harness_activation_id.clone(),
        harness_hash: shadow_run.harness_hash.clone(),
        execution_mode: HarnessExecutionMode::Gated,
        status: if promotion_blocked {
            HarnessClusterPromotionStatus::Blocked
        } else {
            HarnessClusterPromotionStatus::Gated
        },
        component_kinds,
        shadow_run_id: shadow_run.run_id.clone(),
        node_attempt_ids,
        receipt_ids,
        replay_fixture_refs,
        activation_blockers,
        gate_decision: if promotion_blocked {
            "block_promotion".to_string()
        } else {
            "allow_live_runtime_passthrough".to_string()
        },
        rollback_target: "shadow".to_string(),
        canary_status: if promotion_blocked {
            "not_started".to_string()
        } else {
            "passed".to_string()
        },
        promotion_blocked,
        evidence_refs: shadow_run.evidence_refs.clone(),
    }
}

pub fn compare_harness_live_shadow_attempts(
    live: &HarnessNodeAttemptRecord,
    shadow: &HarnessNodeAttemptRecord,
) -> HarnessShadowComparison {
    let mut evidence_refs = live.evidence_refs.clone();
    evidence_refs.extend(shadow.evidence_refs.clone());
    evidence_refs.sort();
    evidence_refs.dedup();

    let (divergence, blocking, summary) = if live.workflow_node_id != shadow.workflow_node_id
        || live.component_kind != shadow.component_kind
    {
        (
            HarnessDivergenceClass::BehavioralRegression,
            true,
            "live and shadow attempts resolved to different harness components".to_string(),
        )
    } else if live.receipt_ids.is_empty() || shadow.receipt_ids.is_empty() {
        (
            HarnessDivergenceClass::MissingReceipt,
            true,
            "live or shadow attempt is missing receipt binding".to_string(),
        )
    } else if live.policy_decision != shadow.policy_decision {
        (
            HarnessDivergenceClass::PolicyDivergence,
            true,
            "live and shadow attempts disagreed on policy decision".to_string(),
        )
    } else if live.output_hash != shadow.output_hash {
        (
            HarnessDivergenceClass::OutputDivergence,
            true,
            "live and shadow attempts disagreed on output hash".to_string(),
        )
    } else {
        (
            HarnessDivergenceClass::None,
            false,
            "live and shadow attempts match for harness promotion purposes".to_string(),
        )
    };

    HarnessShadowComparison {
        workflow_node_id: live.workflow_node_id.clone(),
        component_kind: live.component_kind,
        live_attempt_id: live.attempt_id.clone(),
        shadow_attempt_id: shadow.attempt_id.clone(),
        divergence,
        blocking,
        summary,
        evidence_refs,
    }
}
