// Path: crates/cli/tests/agent_rag_and_policy_e2e.rs
#![cfg(all(
    feature = "consensus-admft",
    feature = "vm-wasm",
    feature = "state-iavl"
))]

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use ioi_api::services::access::ServiceDirectory;
use ioi_api::services::BlockchainService;
use ioi_api::state::StateAccess;
use ioi_api::transaction::context::TxContext;
use ioi_api::vm::drivers::gui::{GuiDriver, InputEvent};
use ioi_api::vm::drivers::os::OsDriver;
use ioi_api::vm::inference::{
    InferenceRuntime, LocalSafetyModel, PiiInspection, PiiRiskSurface, SafetyVerdict,
};
use ioi_cli::testing::build_test_artifacts;
use ioi_scs::{FrameType, SovereignContextStore, StoreConfig, VectorIndex};
use ioi_services::agentic::desktop::{DesktopAgentService, StartAgentParams, StepAgentParams};
use ioi_state::primitives::hash::HashCommitmentScheme;
use ioi_state::tree::iavl::IAVLTree;
use ioi_types::app::agentic::{EvidenceGraph, InferenceOptions};
use ioi_types::app::{ActionContext, ActionRequest, ContextSlice};
use ioi_types::codec;
use ioi_types::error::VmError;
use serde_json::json;
use std::path::Path;
use std::sync::{Arc, Mutex};
use tempfile::tempdir;

// [FIX] Imports for valid PNG generation
use image::{ImageBuffer, ImageFormat, Rgba};
use std::io::Cursor;

// [FIX] Imports for valid transaction construction
use ioi_types::app::{account_id_from_key_material, AccountId, SignatureSuite};
use libp2p::identity::Keypair;

// [FIX] Imports for service registration
use ioi_types::keys::active_service_key;
use ioi_types::service_configs::{ActiveServiceMeta, Capabilities, MethodPermission};
use std::collections::BTreeMap;

// --- Mocks ---

#[derive(Clone)]
struct MockGuiDriver;
#[async_trait]
impl GuiDriver for MockGuiDriver {
    async fn capture_screen(&self) -> Result<Vec<u8>, VmError> {
        // [FIX] Generate a valid 1x1 PNG image to satisfy image::load_from_memory
        let mut img = ImageBuffer::<Rgba<u8>, Vec<u8>>::new(1, 1);
        img.put_pixel(0, 0, Rgba([255, 0, 0, 255]));

        let mut bytes: Vec<u8> = Vec::new();
        img.write_to(&mut Cursor::new(&mut bytes), ImageFormat::Png)
            .map_err(|e| VmError::HostError(format!("Mock PNG encoding failed: {}", e)))?;

        Ok(bytes)
    }
    async fn capture_tree(&self) -> Result<String, VmError> {
        Ok("<root/>".into())
    }
    async fn capture_context(&self, _: &ActionRequest) -> Result<ContextSlice, VmError> {
        Ok(ContextSlice {
            slice_id: [0; 32],
            frame_id: 0,
            chunks: vec![],
            mhnsw_root: [0; 32],
            traversal_proof: None,
            intent_id: [0; 32],
        })
    }
    async fn inject_input(&self, _: InputEvent) -> Result<(), VmError> {
        Ok(())
    }
}

struct MockOsDriver {
    active_window: Arc<Mutex<String>>,
}
#[async_trait]
impl OsDriver for MockOsDriver {
    async fn get_active_window_title(&self) -> Result<Option<String>, VmError> {
        let title = self.active_window.lock().unwrap().clone();
        Ok(Some(title))
    }
}

struct MockRagBrain {
    // Capture the last prompt received to verify RAG injection
    last_prompt: Arc<Mutex<String>>,
}
#[async_trait]
impl InferenceRuntime for MockRagBrain {
    async fn execute_inference(
        &self,
        _: [u8; 32],
        input: &[u8],
        _: InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        let prompt = String::from_utf8_lossy(input).to_string();
        *self.last_prompt.lock().unwrap() = prompt.clone();

        // Simple heuristic response
        let response = if prompt.contains("favorite color") {
            // Agent "knows" this because it was in the RAG context
            json!({
                "name": "gui__type", // Just an action to indicate success
                "arguments": { "text": "Blue" }
            })
        } else {
            json!({
                "name": "gui__click",
                "arguments": { "x": 100, "y": 100, "button": "left" }
            })
        };
        Ok(response.to_string().into_bytes())
    }

    async fn embed_text(&self, text: &str) -> Result<Vec<f32>, VmError> {
        // Deterministic mock embedding:
        // "favorite color" -> [0.9, 0.1, ...]
        // "memory: Blue" -> [0.85, 0.15, ...] (High similarity)
        // "irrelevant" -> [0.1, 0.9, ...] (Low similarity)

        let mut vec = vec![0.0; 384];
        if text.contains("color") || text.contains("Blue") {
            vec[0] = 0.9;
        } else {
            vec[0] = 0.1;
        }
        Ok(vec)
    }

    async fn load_model(&self, _: [u8; 32], _: &Path) -> Result<(), VmError> {
        Ok(())
    }
    async fn unload_model(&self, _: [u8; 32]) -> Result<(), VmError> {
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_agent_rag_and_policy_enforcement() -> Result<()> {
    build_test_artifacts();

    // 1. Setup SCS (Sovereign Memory)
    let temp_dir = tempdir()?;
    let scs_path = temp_dir.path().join("context.scs");
    let scs_config = StoreConfig {
        chain_id: 1,
        owner_id: [0u8; 32],
    };
    let mut scs = SovereignContextStore::create(&scs_path, scs_config)?;

    // 2. Inject Memory
    // "The user's favorite color is Blue"
    let memory_content = b"User Preference: Favorite color is Blue.";
    let frame_id = scs.append_frame(FrameType::Observation, memory_content, 1, [0u8; 32])?;

    // Index the memory
    // Embedding for "Blue" / "color" => [0.9, 0.0, ...]
    let mut vec = vec![0.0; 384];
    vec[0] = 0.9;

    let mut index = VectorIndex::new(16, 100);
    index.insert(frame_id, vec)?;
    scs.commit_index(&index)?;

    // Close and re-open to ensure persistence worked and Arc<Mutex> can be shared
    drop(scs);
    let scs = SovereignContextStore::open(&scs_path)?;
    let scs_arc = Arc::new(Mutex::new(scs));

    // 3. Setup Components
    let active_window = Arc::new(Mutex::new("VS Code".to_string()));
    let os_driver = Arc::new(MockOsDriver {
        active_window: active_window.clone(),
    });

    let last_prompt = Arc::new(Mutex::new(String::new()));
    let brain = Arc::new(MockRagBrain {
        last_prompt: last_prompt.clone(),
    });
    let gui = Arc::new(MockGuiDriver);

    // 4. Setup Service
    let mut service = DesktopAgentService::new_hybrid(gui, brain.clone(), brain.clone());
    service = service.with_scs(scs_arc.clone());

    // 5. Setup Chain State
    let mut state = IAVLTree::new(HashCommitmentScheme::new());
    let services_dir = ServiceDirectory::new(vec![]);
    let mut ctx = TxContext {
        block_height: 2,
        block_timestamp: ibc_primitives::Timestamp::now(),
        chain_id: ioi_types::app::ChainId(1),
        signer_account_id: ioi_types::app::AccountId::default(),
        services: &services_dir,
        simulation: false,
        is_internal: false,
    };

    let session_id = [1u8; 32];

    // --- TEST 1: RAG Memory Recall ---
    // Start Agent
    let start_params = StartAgentParams {
        session_id,
        goal: "Recall favorite color".into(),
        max_steps: 5,
        parent_session_id: None,
        initial_budget: 1000,
    };
    service
        .handle_service_call(
            &mut state,
            "start@v1",
            &codec::to_bytes_canonical(&start_params).map_err(|e| anyhow!(e))?,
            &mut ctx,
        )
        .await?;

    // Step Agent
    let step_params = StepAgentParams { session_id };
    service
        .handle_service_call(
            &mut state,
            "step@v1",
            &codec::to_bytes_canonical(&step_params).map_err(|e| anyhow!(e))?,
            &mut ctx,
        )
        .await?;

    // Verify Prompt contained the memory
    let prompt = last_prompt.lock().unwrap().clone();
    assert!(
        prompt.contains("Favorite color is Blue"),
        "RAG failed: Memory not found in prompt"
    );
    println!("✅ RAG Memory Recall Test Passed");

    // --- TEST 2: Policy Enforcement (Window Context) ---
    // Note: In a full integration test, this would go through `enforce_firewall`.
    // Here we are unit-testing the components interacting via the service logic,
    // but the Policy check happens *before* the service call in the Orchestrator.
    // So to test Policy, we need to invoke `enforce_firewall` manually or trust `ingestion_e2e`.

    // Let's use `enforce_firewall` directly here to prove the OS driver integration works.

    use ioi_types::app::{
        ChainTransaction, SignHeader, SignatureProof, SystemPayload, SystemTransaction,
    };
    use ioi_validator::firewall::enforce_firewall;

    // Set Forbidden Window
    *active_window.lock().unwrap() = "Calculator".to_string(); // Assume policy blocks Calculator

    // Mock Safety Model (Always Safe)
    struct SafeModel;
    #[async_trait]
    impl LocalSafetyModel for SafeModel {
        async fn classify_intent(&self, _: &str) -> Result<SafetyVerdict> {
            Ok(SafetyVerdict::Safe)
        }
        async fn detect_pii(&self, _: &str) -> Result<Vec<(usize, usize, String)>> {
            Ok(vec![])
        }
        async fn inspect_pii(&self, _: &str, _: PiiRiskSurface) -> Result<PiiInspection> {
            Ok(PiiInspection {
                evidence: EvidenceGraph::default(),
                ambiguous: false,
                stage2_status: None,
            })
        }
    }

    // [FIX] Register the 'agentic' service metadata in the state so enforce_firewall passes the existence check
    {
        let mut methods = BTreeMap::new();
        methods.insert("execute_task@v1".to_string(), MethodPermission::User);

        let meta = ActiveServiceMeta {
            id: "agentic".to_string(),
            abi_version: 1,
            state_schema: "v1".to_string(),
            caps: Capabilities::empty(),
            artifact_hash: [0u8; 32],
            activated_at: 0,
            methods,
            allowed_system_prefixes: vec![],
        };

        let meta_bytes = codec::to_bytes_canonical(&meta).unwrap();
        let key = active_service_key("agentic");
        state.insert(&key, &meta_bytes).unwrap();
    }

    // [FIX] Generate a valid identity for the transaction to pass stateful authorization
    let keypair = Keypair::generate_ed25519();
    let public_key = keypair.public().encode_protobuf();
    let account_id =
        AccountId(account_id_from_key_material(SignatureSuite::ED25519, &public_key).unwrap());

    // Construct Tx
    let payload = SystemPayload::CallService {
        service_id: "agentic".into(),
        method: "execute_task@v1".into(),
        params: b"click".to_vec(),
    };

    let mut sys_tx = SystemTransaction {
        header: SignHeader {
            account_id,
            nonce: 0,
            chain_id: 1.into(),
            tx_version: 1,
            session_auth: None,
        },
        payload,
        signature_proof: SignatureProof::default(),
    };

    // Sign transaction (required even if stateless checks are skipped, to pass auth logic structure)
    // Note: We don't strictly need a valid signature for this test since we pass skip_stateless_checks=true,
    // but we DO need valid keys in the proof matching the header.
    sys_tx.signature_proof = SignatureProof {
        suite: SignatureSuite::ED25519,
        public_key,
        signature: vec![], // Signature content ignored by skip_stateless_checks
    };

    let tx = ChainTransaction::System(Box::new(sys_tx));

    // Define Rules (Mocked via code injection or assumption)
    // The `enforce_firewall` function loads rules from `ActionRules::default()` if `agentic`.
    // The default rules are empty (DenyAll).
    // So this should fail by default unless we modify `ActionRules::default` or inject a policy.
    // For this test, we rely on the fact that `DenyAll` + no Allow rule for "Calculator" means BLOCK.

    let res = enforce_firewall(
        &mut state,
        &services_dir,
        &tx,
        1.into(),
        3,
        0,
        true, // skip sig check
        false,
        Arc::new(SafeModel),
        os_driver.clone(), // Pass our mock OS driver
    )
    .await;

    assert!(
        res.is_err(),
        "Firewall should block action in Calculator window (Default Deny)"
    );
    let err = res.unwrap_err().to_string();
    assert!(
        err.contains("Blocked by Policy"),
        "Unexpected error: {}",
        err
    );

    println!("✅ Policy Enforcement (Window Context) Test Passed");

    Ok(())
}
