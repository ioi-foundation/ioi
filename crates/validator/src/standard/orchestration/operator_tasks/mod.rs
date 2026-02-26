// Path: crates/validator/src/standard/orchestration/operator_tasks.rs

use super::context::MainLoopContext;
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use ioi_api::{
    chain::WorkloadClientApi,
    commitment::CommitmentScheme,
    consensus::ConsensusEngine,
    crypto::{SerializableKey, VerifyingKey},
    state::{service_namespace_prefix, StateManager, Verifier},
};
use ioi_crypto::algorithms::hash::sha256;
use ioi_crypto::sign::eddsa::{Ed25519PublicKey, Ed25519Signature};
use ioi_services::market::{JobTicket, ProvisioningReceipt};
use ioi_types::{
    app::{
        account_id_from_key_material, AccountId, ActionTarget, ChainTransaction, KernelEvent,
        SignHeader, SignatureProof, SignatureSuite, StateEntry, SystemPayload, SystemTransaction,
        WalletInterceptionContext,
    },
    codec,
    keys::{active_service_key, ACCOUNT_NONCE_PREFIX},
};
use lru::LruCache;
use once_cell::sync::Lazy;
use parity_scale_codec::{Decode, Encode};
use std::collections::BTreeMap;
use std::fmt::Debug;
use std::num::NonZeroUsize;
use std::sync::Mutex;
use std::time::Duration;
use std::time::Instant;

use reqwest::Client;

use ioi_services::agentic::desktop::{AgentState, AgentStatus, StepAgentParams};
use tokio::sync::{watch, Mutex as TokioMutex};

mod agent_driver;
mod infra_solver;
mod oracle;
mod provider_client;
mod wallet_audit;

pub use agent_driver::{run_agent_driver_task, run_agent_driver_task_with_handles};
pub use infra_solver::run_infra_solver_task;
pub use oracle::{run_oracle_operator_task, run_oracle_operator_task_with_client};
pub use provider_client::{HttpProviderClient, ProviderClient, ProvisioningReceiptData};
pub use wallet_audit::run_wallet_network_audit_bridge_task;

// --- Compute Market Canonical Definitions ---

/// Data required to reconstruct the provider's signature payload for verification.
#[derive(Encode, Decode, Debug, Clone)]
pub struct ProviderAckPayload {
    /// The root hash of the ticket being acknowledged.
    pub ticket_root: [u8; 32],
    /// The unique identifier for the compute instance.
    pub instance_id: Vec<u8>,
    /// The hash of the provider's endpoint URI.
    pub endpoint_uri_hash: [u8; 32],
    /// The block height at which the lease expires.
    pub expiry_height: u64,
    /// The hash of the lease identifier.
    pub lease_id_hash: [u8; 32],
}

/// On-chain representation of a registered provider in the market.
#[derive(Encode, Decode, Debug, Clone)]
pub struct ProviderInfo {
    /// The provider's public key.
    pub public_key: Vec<u8>,
    /// The provider's service endpoint URL.
    pub endpoint: String,
    /// The service tier of the provider.
    pub tier: u8,
    /// List of regions where the provider operates.
    pub allowed_regions: Vec<String>,
    /// The type of provider (e.g., "bare-metal", "cloud").
    pub provider_type: String,
}

const COMPUTE_MARKET_TICKET_PREFIX: &[u8] = b"tickets::";
const COMPUTE_MARKET_PROVIDER_PREFIX: &[u8] = b"providers::";
const DCPP_ACK_DOMAIN_BASE: &[u8] = b"IOI_DCPP_PROVIDER_ACK_V1";

// Helper to compute typed hash
fn sha256_32(data: &[u8]) -> Result<[u8; 32]> {
    let digest = sha256(data)?;
    let mut arr = [0u8; 32];
    arr.copy_from_slice(digest.as_ref());
    Ok(arr)
}

fn decode_state_value<T>(bytes: &[u8]) -> Result<T>
where
    T: Decode,
{
    if let Ok(value) = codec::from_bytes_canonical::<T>(bytes) {
        return Ok(value);
    }
    let entry: StateEntry = codec::from_bytes_canonical(bytes)
        .map_err(|e| anyhow!("StateEntry decode failed: {}", e))?;
    codec::from_bytes_canonical(&entry.value)
        .map_err(|e| anyhow!("StateEntry inner decode failed: {}", e))
}

fn decode_account_nonce(bytes: &[u8]) -> u64 {
    if let Ok(value) = decode_state_value::<u64>(bytes) {
        return value;
    }
    if bytes.len() == 8 {
        let mut raw = [0u8; 8];
        raw.copy_from_slice(bytes);
        return u64::from_le_bytes(raw);
    }
    0
}

fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

async fn reserve_nonce_for_account(
    workload_client: &std::sync::Arc<dyn WorkloadClientApi>,
    nonce_manager: &std::sync::Arc<TokioMutex<BTreeMap<AccountId, u64>>>,
    account_id: AccountId,
) -> u64 {
    let nonce_key = [ACCOUNT_NONCE_PREFIX, account_id.as_ref()].concat();
    let state_nonce = match workload_client.query_raw_state(&nonce_key).await {
        Ok(Some(bytes)) => decode_account_nonce(&bytes),
        _ => 0,
    };

    let mut guard = nonce_manager.lock().await;
    let entry = guard.entry(account_id).or_insert(state_nonce);
    if *entry < state_nonce {
        *entry = state_nonce;
    }
    let nonce = *entry;
    *entry = entry.saturating_add(1);
    nonce
}

async fn submit_wallet_interception_record(
    workload_client: &std::sync::Arc<dyn WorkloadClientApi>,
    tx_pool: &std::sync::Arc<crate::standard::orchestration::mempool::Mempool>,
    consensus_kick_tx: &tokio::sync::mpsc::UnboundedSender<()>,
    nonce_manager: &std::sync::Arc<TokioMutex<BTreeMap<AccountId, u64>>>,
    keypair: &libp2p::identity::Keypair,
    chain_id: ioi_types::app::ChainId,
    interception: WalletInterceptionContext,
) -> Result<()> {
    let public_key = keypair.public().encode_protobuf();
    let account_id = AccountId(account_id_from_key_material(
        SignatureSuite::ED25519,
        &public_key,
    )?);

    let nonce = reserve_nonce_for_account(workload_client, nonce_manager, account_id).await;
    let nonce_key = [ACCOUNT_NONCE_PREFIX, account_id.as_ref()].concat();
    let committed_nonce = match workload_client.query_raw_state(&nonce_key).await {
        Ok(Some(bytes)) => decode_account_nonce(&bytes),
        _ => 0,
    };

    let payload = SystemPayload::CallService {
        service_id: "wallet_network".to_string(),
        method: "record_interception@v1".to_string(),
        params: codec::to_bytes_canonical(&interception).map_err(|e| anyhow!(e))?,
    };
    let mut sys_tx = SystemTransaction {
        header: SignHeader {
            account_id,
            nonce,
            chain_id,
            tx_version: 1,
            session_auth: None,
        },
        payload,
        signature_proof: SignatureProof::default(),
    };

    let sign_bytes = sys_tx.to_sign_bytes().map_err(|e| anyhow!(e))?;
    let signature = keypair.sign(&sign_bytes)?;
    sys_tx.signature_proof = SignatureProof {
        suite: SignatureSuite::ED25519,
        public_key,
        signature,
    };

    let tx = ChainTransaction::System(Box::new(sys_tx));
    let tx_hash = tx.hash()?;
    match tx_pool.add(tx, tx_hash, Some((account_id, nonce)), committed_nonce) {
        crate::standard::orchestration::mempool::AddResult::Rejected(reason) => Err(anyhow!(
            "wallet_network interception tx rejected: {}",
            reason
        )),
        _ => {
            let _ = consensus_kick_tx.send(());
            Ok(())
        }
    }
}
