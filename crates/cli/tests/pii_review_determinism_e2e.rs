// Path: crates/cli/tests/pii_review_determinism_e2e.rs
#![cfg(all(
    feature = "consensus-admft",
    feature = "vm-wasm",
    feature = "state-iavl"
))]

use anyhow::Result;
use async_trait::async_trait;
use ioi_api::crypto::{SerializableKey, SigningKeyPair};
use ioi_api::services::{access::ServiceDirectory, BlockchainService};
use ioi_api::state::{service_namespace_prefix, StateAccess};
use ioi_api::transaction::context::TxContext;
use ioi_api::vm::drivers::gui::{GuiDriver, InputEvent};
use ioi_api::vm::drivers::os::{OsDriver, WindowInfo};
use ioi_api::vm::inference::InferenceRuntime;
use ioi_crypto::algorithms::hash::sha256;
use ioi_crypto::sign::eddsa::Ed25519KeyPair;
use ioi_drivers::browser::BrowserDriver;
use ioi_drivers::terminal::TerminalDriver;
use ioi_pii::{
    build_decision_material, build_review_summary, compute_decision_hash,
    route_pii_decision_for_target, validate_review_request_compat, RiskSurface,
    REVIEW_REQUEST_VERSION,
};
use ioi_scs::{SovereignContextStore, StoreConfig};
use ioi_services::agentic::desktop::keys::{get_incident_key, get_state_key, pii};
use ioi_services::agentic::desktop::service::step::helpers::default_safe_policy;
use ioi_services::agentic::desktop::service::step::incident::{
    action_fingerprint_from_tool_jcs, load_incident_state, register_pending_approval,
};
use ioi_services::agentic::desktop::{AgentMode, AgentState, AgentStatus, DesktopAgentService};
use ioi_services::agentic::rules::{ActionRules, DefaultPolicy};
use ioi_state::primitives::hash::HashCommitmentScheme;
use ioi_state::tree::iavl::IAVLTree;
use ioi_types::app::action::{ApprovalScope, ApprovalToken, PiiApprovalAction};
use ioi_types::app::agentic::{
    AgentTool, EvidenceGraph, EvidenceSpan, InferenceOptions, PiiClass, PiiConfidenceBucket,
    PiiControls, PiiReviewRequest, PiiSeverity, PiiTarget,
};
use ioi_types::app::{
    account_id_from_key_material, AccountId, ActionRequest, ChainId, ChainTransaction,
    ContextSlice, SignHeader, SignatureProof, SignatureSuite, SystemPayload, SystemTransaction,
};
use ioi_types::codec;
use ioi_types::error::VmError;
use ioi_types::keys::active_service_key;
use ioi_types::service_configs::{ActiveServiceMeta, Capabilities, MethodPermission};
use ioi_validator::firewall::{enforce_firewall, inference::MockBitNet};
use serde_json::json;
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct DummyGui;

#[async_trait]
impl GuiDriver for DummyGui {
    async fn capture_screen(
        &self,
        _crop_rect: Option<(i32, i32, u32, u32)>,
    ) -> Result<Vec<u8>, VmError> {
        Ok(vec![])
    }

    async fn capture_raw_screen(&self) -> Result<Vec<u8>, VmError> {
        Ok(vec![])
    }

    async fn capture_tree(&self) -> Result<String, VmError> {
        Ok(String::new())
    }

    async fn capture_context(&self, _intent: &ActionRequest) -> Result<ContextSlice, VmError> {
        Ok(ContextSlice {
            slice_id: [0u8; 32],
            frame_id: 0,
            chunks: vec![],
            mhnsw_root: [0u8; 32],
            traversal_proof: None,
            intent_id: [0u8; 32],
        })
    }

    async fn inject_input(&self, _event: InputEvent) -> Result<(), VmError> {
        Ok(())
    }

    async fn get_element_center(&self, _id: u32) -> Result<Option<(u32, u32)>, VmError> {
        Ok(None)
    }
}

#[derive(Default)]
struct DummyOs;

#[async_trait]
impl OsDriver for DummyOs {
    async fn get_active_window_title(&self) -> Result<Option<String>, VmError> {
        Ok(None)
    }

    async fn get_active_window_info(&self) -> Result<Option<WindowInfo>, VmError> {
        Ok(None)
    }

    async fn focus_window(&self, _title_query: &str) -> Result<bool, VmError> {
        Ok(true)
    }

    async fn set_clipboard(&self, _content: &str) -> Result<(), VmError> {
        Ok(())
    }

    async fn get_clipboard(&self) -> Result<String, VmError> {
        Ok(String::new())
    }
}

#[derive(Default)]
struct NoopRuntime;

#[async_trait]
impl InferenceRuntime for NoopRuntime {
    async fn execute_inference(
        &self,
        _model_hash: [u8; 32],
        _input_context: &[u8],
        _options: InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        Ok(json!({ "ok": true }).to_string().into_bytes())
    }

    async fn load_model(&self, _model_hash: [u8; 32], _path: &Path) -> Result<(), VmError> {
        Ok(())
    }

    async fn unload_model(&self, _model_hash: [u8; 32]) -> Result<(), VmError> {
        Ok(())
    }
}

fn build_agent_state(session_id: [u8; 32], tool_jcs: Vec<u8>, tool_hash: [u8; 32]) -> AgentState {
    AgentState {
        session_id,
        goal: "copy value to clipboard".to_string(),
        transcript_root: [0u8; 32],
        status: AgentStatus::Running,
        step_count: 1,
        max_steps: 16,
        last_action_type: None,
        parent_session_id: None,
        child_session_ids: vec![],
        budget: 1000,
        tokens_used: 0,
        consecutive_failures: 0,
        pending_approval: None,
        pending_tool_call: None,
        pending_tool_jcs: Some(tool_jcs),
        pending_tool_hash: Some(tool_hash),
        pending_visual_hash: Some([0u8; 32]),
        recent_actions: vec![],
        mode: AgentMode::Agent,
        current_tier: Default::default(),
        last_screen_phash: None,
        execution_queue: vec![],
        pending_search_completion: None,
        active_skill_hash: None,
        tool_execution_log: BTreeMap::new(),
        visual_som_map: None,
        visual_semantic_map: None,
        swarm_context: None,
        target: None,
        resolved_intent: None,

        awaiting_intent_clarification: false,

        working_directory: ".".to_string(),
        command_history: Default::default(),
        active_lens: None,
    }
}

fn desktop_service_meta() -> ActiveServiceMeta {
    let mut methods = BTreeMap::new();
    methods.insert("start@v1".to_string(), MethodPermission::User);
    methods.insert("step@v1".to_string(), MethodPermission::User);
    methods.insert("resume@v1".to_string(), MethodPermission::User);
    methods.insert("post_message@v1".to_string(), MethodPermission::User);

    ActiveServiceMeta {
        id: "desktop_agent".to_string(),
        abi_version: 1,
        state_schema: "v1".to_string(),
        caps: Capabilities::empty(),
        artifact_hash: [0u8; 32],
        activated_at: 0,
        methods,
        allowed_system_prefixes: vec![],
        generation_id: 0,
        parent_hash: None,
        author: None,
        context_filter: None,
    }
}

fn insert_raw_and_namespaced(
    state: &mut IAVLTree<HashCommitmentScheme>,
    local_key: Vec<u8>,
    value: Vec<u8>,
) -> Result<()> {
    state.insert(&local_key, &value)?;
    let namespaced_key = [
        service_namespace_prefix("desktop_agent").as_slice(),
        local_key.as_slice(),
    ]
    .concat();
    state.insert(&namespaced_key, &value)?;
    Ok(())
}

async fn run_golden_pii_review_determinism_desktop_validator_desktop() -> Result<()> {
    let chain_id = ChainId(7);
    let session_id = [0x11u8; 32];
    let now_ms: u64 = 1_725_000_000_000;
    let now_secs = now_ms / 1000;

    let runtime = Arc::new(NoopRuntime);
    let gui = Arc::new(DummyGui);

    let temp_dir = tempfile::tempdir()?;
    let scs_path = temp_dir.path().join("review.scs");
    let scs = SovereignContextStore::create(
        &scs_path,
        StoreConfig {
            chain_id: chain_id.0,
            owner_id: [0xAB; 32],
            identity_key: [0xCD; 32],
        },
    )?;
    let scs_arc = Arc::new(Mutex::new(scs));

    let service = DesktopAgentService::new_hybrid(
        gui,
        Arc::new(TerminalDriver::new()),
        Arc::new(BrowserDriver::new()),
        runtime.clone(),
        runtime.clone(),
    )
    .with_scs(scs_arc)
    .with_os_driver(Arc::new(DummyOs));

    let tool = AgentTool::OsCopy {
        content: "john@example.com".to_string(),
    };
    let tool_jcs = serde_json::to_vec(&tool)?;
    let tool_hash_digest = sha256(&tool_jcs)?;
    let mut tool_hash = [0u8; 32];
    tool_hash.copy_from_slice(tool_hash_digest.as_ref());

    let graph = EvidenceGraph {
        version: 1,
        source_hash: [0x33; 32],
        ambiguous: false,
        spans: vec![EvidenceSpan {
            start_index: 0,
            end_index: "john@example.com".len() as u32,
            pii_class: PiiClass::Email,
            severity: PiiSeverity::Low,
            confidence_bucket: PiiConfidenceBucket::High,
            pattern_id: "test/email".to_string(),
            validator_passed: true,
            context_keywords: vec!["email".to_string()],
            evidence_source: "test".to_string(),
        }],
    };
    let target = PiiTarget::Action(ioi_types::app::ActionTarget::ClipboardWrite);
    let routed = route_pii_decision_for_target(
        &graph,
        &PiiControls::default(),
        RiskSurface::Egress,
        &target,
        true,
    );
    let material = build_decision_material(
        &graph,
        &routed.decision,
        routed.transform_plan.as_ref(),
        routed.stage2_decision.as_ref(),
        RiskSurface::Egress,
        &target,
        true,
        &routed.assist,
    );
    let summary = build_review_summary(&graph, &target, routed.stage2_decision.as_ref());
    let decision_hash = compute_decision_hash(&material);
    assert_eq!(decision_hash, routed.decision_hash);

    let request = PiiReviewRequest {
        request_version: REVIEW_REQUEST_VERSION,
        decision_hash,
        material: material.clone(),
        summary,
        session_id: Some(session_id),
        created_at_ms: now_ms,
        deadline_ms: now_ms + 30_000,
    };
    assert_eq!(
        request.decision_hash,
        compute_decision_hash(&request.material)
    );
    validate_review_request_compat(&request).expect("review request compat");

    let mut state = IAVLTree::new(HashCommitmentScheme::new());

    let agent_state = build_agent_state(session_id, tool_jcs.clone(), tool_hash);
    let rules: ActionRules = default_safe_policy();
    let action_fingerprint = action_fingerprint_from_tool_jcs(&tool_jcs);
    register_pending_approval(
        &mut state,
        &rules,
        &agent_state,
        session_id,
        &hex::encode(tool_hash),
        "os__copy",
        &tool_jcs,
        &action_fingerprint,
        &hex::encode(decision_hash),
    )?;

    insert_raw_and_namespaced(
        &mut state,
        get_state_key(&session_id),
        codec::to_bytes_canonical(&agent_state).map_err(anyhow::Error::msg)?,
    )?;
    let incident_local_key = get_incident_key(&session_id);
    let incident_bytes = state.get(&incident_local_key)?.expect("incident state");
    insert_raw_and_namespaced(&mut state, incident_local_key, incident_bytes)?;
    insert_raw_and_namespaced(
        &mut state,
        pii::review::request(&decision_hash),
        codec::to_bytes_canonical(&request).map_err(anyhow::Error::msg)?,
    )?;
    let mut permissive_rules = ActionRules::default();
    permissive_rules.defaults = DefaultPolicy::AllowAll;
    insert_raw_and_namespaced(
        &mut state,
        [b"agent::policy::".as_slice(), session_id.as_slice()].concat(),
        codec::to_bytes_canonical(&permissive_rules).map_err(anyhow::Error::msg)?,
    )?;
    state.insert(
        &active_service_key("desktop_agent"),
        &codec::to_bytes_canonical(&desktop_service_meta()).map_err(anyhow::Error::msg)?,
    )?;

    let namespaced_request_key = [
        service_namespace_prefix("desktop_agent").as_slice(),
        pii::review::request(&decision_hash).as_slice(),
    ]
    .concat();
    let validator_visible_request: PiiReviewRequest = codec::from_bytes_canonical(
        &state
            .get(&namespaced_request_key)?
            .expect("namespaced review request"),
    )
    .map_err(anyhow::Error::msg)?;
    assert_eq!(
        validator_visible_request.decision_hash,
        compute_decision_hash(&validator_visible_request.material)
    );

    let approval_token = ApprovalToken {
        schema_version: 2,
        request_hash: decision_hash,
        audience: [1u8; 32],
        revocation_epoch: 0,
        nonce: [2u8; 32],
        counter: 1,
        scope: ApprovalScope {
            expires_at: now_secs + 3_600,
            max_usages: Some(1),
        },
        visual_hash: Some([0u8; 32]),
        pii_action: Some(PiiApprovalAction::Deny),
        scoped_exception: None,
        approver_sig: vec![],
        approver_suite: SignatureSuite::ED25519,
    };
    let resume_params = ioi_services::agentic::desktop::ResumeAgentParams {
        session_id,
        approval_token: Some(approval_token.clone()),
    };
    let resume_bytes = codec::to_bytes_canonical(&resume_params).map_err(anyhow::Error::msg)?;

    let signer = Ed25519KeyPair::generate()?;
    let signer_pub = signer.public_key();
    let signer_pub_bytes = signer_pub.to_bytes();
    let account_id = AccountId(account_id_from_key_material(
        SignatureSuite::ED25519,
        &signer_pub_bytes,
    )?);

    let mut tx = SystemTransaction {
        header: SignHeader {
            account_id,
            nonce: 0,
            chain_id,
            tx_version: 1,
            session_auth: None,
        },
        payload: SystemPayload::CallService {
            service_id: "desktop_agent".to_string(),
            method: "resume@v1".to_string(),
            params: resume_bytes.clone(),
        },
        signature_proof: SignatureProof::default(),
    };
    let sign_bytes = tx.to_sign_bytes().map_err(anyhow::Error::msg)?;
    let sig = signer.sign(&sign_bytes)?;
    tx.signature_proof = SignatureProof {
        suite: SignatureSuite::ED25519,
        public_key: signer_pub_bytes,
        signature: sig.to_bytes(),
    };
    let chain_tx = ChainTransaction::System(Box::new(tx));

    let services_dir = ServiceDirectory::new(vec![]);
    let no_events: Option<tokio::sync::broadcast::Sender<ioi_types::app::KernelEvent>> = None;
    enforce_firewall(
        &mut state,
        &services_dir,
        &chain_tx,
        chain_id,
        10,
        now_secs,
        false,
        true,
        Arc::new(MockBitNet),
        Arc::new(DummyOs),
        &no_events,
    )
    .await?;

    let mut ctx = TxContext {
        block_height: 10,
        block_timestamp: now_ms.saturating_mul(1_000_000),
        chain_id,
        signer_account_id: account_id,
        services: &services_dir,
        simulation: false,
        is_internal: false,
    };

    service
        .handle_service_call(&mut state, "resume@v1", &resume_bytes, &mut ctx)
        .await?;

    let step_params = ioi_services::agentic::desktop::StepAgentParams { session_id };
    service
        .handle_service_call(
            &mut state,
            "step@v1",
            &codec::to_bytes_canonical(&step_params).map_err(anyhow::Error::msg)?,
            &mut ctx,
        )
        .await?;

    let final_agent_state: AgentState = codec::from_bytes_canonical(
        &state
            .get(&get_state_key(&session_id))?
            .expect("final agent state"),
    )
    .map_err(anyhow::Error::msg)?;
    assert!(final_agent_state.pending_approval.is_none());
    assert!(final_agent_state.pending_tool_jcs.is_none());
    assert!(final_agent_state.pending_tool_hash.is_none());
    assert!(final_agent_state.pending_visual_hash.is_none());
    assert_eq!(final_agent_state.status, AgentStatus::Running);

    let incident = load_incident_state(&state, &session_id)?.expect("incident state");
    assert!(incident.pending_gate.is_none());
    assert_eq!(incident.gate_state, "Denied");

    let persisted_request: PiiReviewRequest = codec::from_bytes_canonical(
        &state
            .get(&pii::review::request(&decision_hash))?
            .expect("persisted review request"),
    )
    .map_err(anyhow::Error::msg)?;
    assert_eq!(
        persisted_request.decision_hash,
        compute_decision_hash(&persisted_request.material)
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn golden_pii_review_determinism_desktop_validator_desktop() -> Result<()> {
    run_golden_pii_review_determinism_desktop_validator_desktop().await
}
