#![cfg(all(feature = "consensus-aft", feature = "vm-wasm", feature = "state-iavl"))]

//! Long-lived real wallet.network fixture used by the Hypervisor room-participation verifier.
//!
//! This is deliberately a real one-validator cluster. Setup is performed through signed
//! `CallService` transactions: configure the control root, register Hypervisor's capability
//! client, register the approval authorities, and install root-signed principal bindings. The
//! JavaScript verifier only receives the public RPC coordinates and encrypted capability-key
//! path; it never receives a resolver-shaped response fixture.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use ioi_api::crypto::{SerializableKey, SigningKey, SigningKeyPair};
use ioi_cli::testing::{build_test_artifacts, submit_transaction, wait_for_height, TestCluster};
use ioi_crypto::sign::eddsa::{Ed25519KeyPair, Ed25519PrivateKey};
use ioi_services::wallet_network::RegisterApprovalAuthorityParams;
use ioi_types::app::wallet_network::{
    IssuePrincipalAuthorityBindingParams, PrincipalAuthorityBindingProofV1,
    PrincipalAuthorityBindingStatementV1, PrincipalAuthorityBindingStatus, PrincipalAuthorityKind,
    VaultSurface, WalletClientRole, WalletClientState, WalletConfigureControlRootParams,
    WalletControlPlaneRootRecord, WalletRegisterClientParams, WalletRegisteredClientRecord,
    PRINCIPAL_AUTHORITY_BINDING_SCHEMA_VERSION,
};
use ioi_types::app::{
    account_id_from_key_material, action::ApprovalAuthority, AccountId, ChainId, ChainTransaction,
    SignHeader, SignatureProof, SignatureSuite, SystemPayload, SystemTransaction,
};
use ioi_types::codec;
use ioi_types::config::ServicePolicy;
use ioi_types::service_configs::MethodPermission;
use ioi_validator::common::GuardianContainer;
use parity_scale_codec::Encode;

const HOST_SEED: [u8; 32] = [0x07; 32];
const PARTICIPANT_SEED: [u8; 32] = [0x09; 32];
const PARTICIPANT_TWO_SEED: [u8; 32] = [0x0a; 32];
const PARTICIPANT_THREE_SEED: [u8; 32] = [0x0b; 32];
const SCOPE_LIMITED_PARTICIPANT_SEED: [u8; 32] = [0x0c; 32];
const ROOT_SEED: [u8; 32] = [0x41; 32];
const CAPABILITY_SEED: [u8; 32] = [0x31; 32];
const EXPIRES_AT_MS: u64 = 1_850_000_000_000;

fn keypair(seed: &[u8; 32]) -> Result<Ed25519KeyPair> {
    let private =
        Ed25519PrivateKey::from_bytes(seed).map_err(|error| anyhow!(error.to_string()))?;
    Ed25519KeyPair::from_private_key(&private).map_err(|error| anyhow!(error.to_string()))
}

fn wallet_policy() -> ServicePolicy {
    let methods = [
        "configure_control_root@v1",
        "register_client@v1",
        "register_approval_authority@v1",
        "issue_principal_authority_binding@v1",
        "resolve_principal_authority@v1",
    ]
    .into_iter()
    .map(|method| (method.to_string(), MethodPermission::User))
    .collect();
    ServicePolicy {
        methods,
        allowed_system_prefixes: Vec::new(),
    }
}

fn create_call<P: Encode>(
    signer: &Ed25519KeyPair,
    chain_id: ChainId,
    nonce: u64,
    method: &str,
    params: &P,
) -> Result<ChainTransaction> {
    let public_key = signer.public_key().to_bytes();
    let account_id = AccountId(account_id_from_key_material(
        SignatureSuite::ED25519,
        &public_key,
    )?);
    let mut transaction = SystemTransaction {
        header: SignHeader {
            account_id,
            nonce,
            chain_id,
            tx_version: 1,
            session_auth: None,
        },
        payload: SystemPayload::CallService {
            service_id: "wallet_network".to_string(),
            method: method.to_string(),
            params: codec::to_bytes_canonical(params).map_err(|error| anyhow!(error))?,
        },
        signature_proof: SignatureProof::default(),
    };
    let signing_bytes = transaction
        .to_sign_bytes()
        .map_err(|error| anyhow!(error))?;
    transaction.signature_proof = SignatureProof {
        suite: SignatureSuite::ED25519,
        public_key,
        signature: signer
            .private_key()
            .sign(&signing_bytes)
            .map_err(|error| anyhow!(error.to_string()))?
            .to_bytes(),
    };
    Ok(ChainTransaction::System(Box::new(transaction)))
}

async fn submit<P: Encode>(
    rpc_addr: &str,
    signer: &Ed25519KeyPair,
    chain_id: ChainId,
    nonce: u64,
    method: &str,
    params: &P,
) -> Result<()> {
    let transaction = create_call(signer, chain_id, nonce, method, params)?;
    submit_transaction(rpc_addr, &transaction)
        .await
        .with_context(|| format!("wallet.network {method} nonce {nonce}"))
}

fn approval_authority(seed: &[u8; 32]) -> Result<ApprovalAuthority> {
    approval_authority_with_scopes(
        seed,
        vec![
            "room_participation.*".to_string(),
            "work_frontier.*".to_string(),
            "work_claim.*".to_string(),
            "resource_offer.*".to_string(),
            "capability_offer.*".to_string(),
            "work_eligibility.*".to_string(),
            "attempt.*".to_string(),
            "finding.*".to_string(),
        ],
    )
}

fn approval_authority_with_scopes(
    seed: &[u8; 32],
    scope_allowlist: Vec<String>,
) -> Result<ApprovalAuthority> {
    let signer = keypair(seed)?;
    let public_key = signer.public_key().to_bytes();
    Ok(ApprovalAuthority {
        schema_version: 1,
        authority_id: account_id_from_key_material(SignatureSuite::ED25519, &public_key)?,
        public_key,
        signature_suite: SignatureSuite::ED25519,
        expires_at: EXPIRES_AT_MS,
        revoked: false,
        scope_allowlist,
    })
}

fn signed_binding(
    root: &Ed25519KeyPair,
    root_record: &WalletControlPlaneRootRecord,
    principal_ref: &str,
    authority: &ApprovalAuthority,
) -> Result<PrincipalAuthorityBindingProofV1> {
    let statement = PrincipalAuthorityBindingStatementV1 {
        schema_version: PRINCIPAL_AUTHORITY_BINDING_SCHEMA_VERSION,
        principal_ref: principal_ref.to_string(),
        authority_kind: PrincipalAuthorityKind::Approval,
        binding_version: 1,
        status: PrincipalAuthorityBindingStatus::Active,
        authority_id: authority.authority_id,
        authority_public_key: authority.public_key.clone(),
        authority_signature_suite: authority.signature_suite,
        approval_authority_snapshot_hash: authority.artifact_hash()?,
        previous_binding_ref: None,
        previous_binding_hash: None,
        // TestCluster's deterministic genesis clock can precede host wall time. Version 1 is
        // intentionally ancient-but-active; expiry and local proof verification still use the
        // real future bound below.
        signed_at_ms: 1,
        expires_at_ms: Some(EXPIRES_AT_MS),
        issuer_root_account_id: root_record.account_id,
        reason: Some("Hypervisor held-bar principal binding".to_string()),
    };
    let message = statement.signing_bytes()?;
    PrincipalAuthorityBindingProofV1::new(
        statement,
        SignatureProof {
            suite: SignatureSuite::ED25519,
            public_key: root_record.public_key.clone(),
            signature: root
                .private_key()
                .sign(&message)
                .map_err(|error| anyhow!(error.to_string()))?
                .to_bytes(),
        },
    )
    .map_err(|error| anyhow!(error.to_string()))
}

#[tokio::test]
#[ignore = "spawned by verify-hypervisor-room-participation-plane.mjs"]
async fn wallet_network_principal_authority_fixture() -> Result<()> {
    let fixture_dir = PathBuf::from(
        std::env::var("IOI_HYPERVISOR_WALLET_FIXTURE_DIR")
            .context("IOI_HYPERVISOR_WALLET_FIXTURE_DIR is required")?,
    );
    std::fs::create_dir_all(&fixture_dir)?;
    build_test_artifacts();
    let cluster = TestCluster::builder()
        .with_validators(1)
        .with_consensus_type("Aft")
        .with_state_tree("IAVL")
        .with_service_policy("wallet_network", wallet_policy())
        .build()
        .await?;

    let setup: Result<()> = async {
        let node = cluster.validators[0].validator();
        let rpc_addr = node.rpc_addr.clone();
        let chain_id = ChainId(1);
        wait_for_height(&rpc_addr, 1, Duration::from_secs(30)).await?;

        let root = keypair(&ROOT_SEED)?;
        let root_public_key = root.public_key().to_bytes();
        let root_record = WalletControlPlaneRootRecord {
            account_id: account_id_from_key_material(SignatureSuite::ED25519, &root_public_key)?,
            signature_suite: SignatureSuite::ED25519,
            public_key: root_public_key,
            registered_at_ms: 0,
            updated_at_ms: 0,
            metadata: BTreeMap::from([(
                "fixture".to_string(),
                "hypervisor-room-participation".to_string(),
            )]),
        };
        submit(
            &rpc_addr,
            &root,
            chain_id,
            0,
            "configure_control_root@v1",
            &WalletConfigureControlRootParams {
                root: root_record.clone(),
            },
        )
        .await?;

        let capability = keypair(&CAPABILITY_SEED)?;
        let capability_public_key = capability.public_key().to_bytes();
        submit(
            &rpc_addr,
            &root,
            chain_id,
            1,
            "register_client@v1",
            &WalletRegisterClientParams {
                client: WalletRegisteredClientRecord {
                    client_id: account_id_from_key_material(
                        SignatureSuite::ED25519,
                        &capability_public_key,
                    )?,
                    label: "Hypervisor room participation".to_string(),
                    surface: VaultSurface::Desktop,
                    signature_suite: SignatureSuite::ED25519,
                    public_key: capability_public_key,
                    role: WalletClientRole::Capability,
                    state: WalletClientState::Active,
                    registered_at_ms: 0,
                    updated_at_ms: 0,
                    expires_at_ms: Some(EXPIRES_AT_MS),
                    allowed_provider_families: Vec::new(),
                    metadata: BTreeMap::new(),
                },
            },
        )
        .await?;

        let host_authority = approval_authority(&HOST_SEED)?;
        let participant_bindings = [
            (
                "worker://independent-alloy-lab",
                approval_authority(&PARTICIPANT_SEED)?,
            ),
            (
                "worker://replication-lab-two",
                approval_authority(&PARTICIPANT_TWO_SEED)?,
            ),
            (
                "worker://replication-lab-three",
                approval_authority(&PARTICIPANT_THREE_SEED)?,
            ),
            (
                "worker://frontier-only-lab",
                approval_authority_with_scopes(
                    &SCOPE_LIMITED_PARTICIPANT_SEED,
                    vec!["work_frontier.*".to_string()],
                )?,
            ),
        ];
        submit(
            &rpc_addr,
            &root,
            chain_id,
            2,
            "register_approval_authority@v1",
            &RegisterApprovalAuthorityParams {
                authority: host_authority.clone(),
            },
        )
        .await?;
        let mut nonce = 3;
        for (_, authority) in &participant_bindings {
            submit(
                &rpc_addr,
                &root,
                chain_id,
                nonce,
                "register_approval_authority@v1",
                &RegisterApprovalAuthorityParams {
                    authority: authority.clone(),
                },
            )
            .await?;
            nonce += 1;
        }
        submit(
            &rpc_addr,
            &root,
            chain_id,
            nonce,
            "issue_principal_authority_binding@v1",
            &IssuePrincipalAuthorityBindingParams {
                proof: signed_binding(&root, &root_record, "domain://acme-host", &host_authority)?,
            },
        )
        .await?;
        nonce += 1;
        for (principal_ref, authority) in &participant_bindings {
            submit(
                &rpc_addr,
                &root,
                chain_id,
                nonce,
                "issue_principal_authority_binding@v1",
                &IssuePrincipalAuthorityBindingParams {
                    proof: signed_binding(&root, &root_record, principal_ref, authority)?,
                },
            )
            .await?;
            nonce += 1;
        }

        std::env::set_var("IOI_GUARDIAN_KEY_PASS", "hypervisor-held-bar");
        let capability_key_path = fixture_dir.join("hypervisor-capability.key");
        GuardianContainer::save_encrypted_file(&capability_key_path, &CAPABILITY_SEED)?;
        let root_record_path = fixture_dir.join("wallet-control-root.json");
        std::fs::write(&root_record_path, serde_json::to_vec_pretty(&root_record)?)?;
        let manifest = serde_json::json!({
            "rpc_addr": rpc_addr,
            "chain_id": chain_id.0,
            "capability_key_path": capability_key_path,
            "root_record_path": root_record_path,
            "guardian_key_pass": "hypervisor-held-bar",
        });
        std::fs::write(
            fixture_dir.join("ready.json"),
            serde_json::to_vec_pretty(&manifest)?,
        )?;

        let shutdown = fixture_dir.join("shutdown");
        while !shutdown.exists() {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        Ok(())
    }
    .await;

    let shutdown_result = cluster.shutdown().await;
    shutdown_result?;
    setup
}
