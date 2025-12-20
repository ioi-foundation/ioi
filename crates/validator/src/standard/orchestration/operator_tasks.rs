// Path: crates/validator/src/standard/orchestration/operator_tasks.rs

use super::context::MainLoopContext;
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use ioi_api::{
    commitment::CommitmentScheme,
    consensus::ConsensusEngine,
    crypto::{SerializableKey, SigningKeyPair, VerifyingKey},
    state::{service_namespace_prefix, StateManager, Verifier},
};
use ioi_crypto::algorithms::hash::sha256;
use ioi_crypto::sign::eddsa::{Ed25519PublicKey, Ed25519Signature};
use ioi_networking::libp2p::SwarmCommand;
use ioi_services::oracle::OracleService;
use ioi_types::{
    app::{
        account_id_from_key_material, AccountId, ChainTransaction, OracleAttestation, SignHeader,
        SignatureProof, SignatureSuite, StateEntry, SystemPayload, SystemTransaction,
    },
    codec,
    keys::{active_service_key, ORACLE_PENDING_REQUEST_PREFIX},
};
use once_cell::sync::Lazy;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt::Debug;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::time::interval;

// --- DCPP Canonical Definitions ---

#[derive(Encode, Decode, Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct HardwareSpecs {
    pub provider_type: String, // e.g. "akash", "aws"
    pub region: String,
    pub instance_type: String, // e.g. "gpu-h100"
    pub image: String,         // Docker image hash
}

#[derive(Encode, Decode, Serialize, Deserialize, Debug, Clone)]
pub struct JobTicket {
    pub request_id: u64,
    pub owner: AccountId,
    pub specs: HardwareSpecs,
    pub max_bid: u64,
    pub expiry_height: u64,
    pub security_tier: u8,
    pub nonce: u64,
}

#[derive(Encode, Decode, Serialize, Deserialize, Debug, Clone)]
pub struct ProvisioningReceipt {
    pub request_id: u64,
    pub ticket_root: [u8; 32],
    pub provider_id: Vec<u8>,
    pub endpoint_uri: String,
    pub machine_id: String,
    pub expiry_height: u64,
    pub lease_id: String,
    pub provider_signature: Vec<u8>,
}

#[derive(Encode, Decode, Debug, Clone)]
pub struct ProviderAckPayload {
    pub ticket_root: [u8; 32],
    pub machine_id: Vec<u8>,
    pub endpoint_uri_hash: [u8; 32],
    pub expiry_height: u64,
    pub lease_id_hash: [u8; 32],
}

// On-chain representation of a registered provider
#[derive(Encode, Decode, Debug, Clone)]
pub struct ProviderInfo {
    pub public_key: Vec<u8>,
    pub endpoint: String,
    pub tier: u8,
    pub allowed_regions: Vec<String>,
    pub provider_type: String,
}

const DECENTRALIZED_CLOUD_TICKET_PREFIX: &[u8] = b"tickets::";
const DECENTRALIZED_CLOUD_PROVIDER_PREFIX: &[u8] = b"providers::";
const DCPP_ACK_DOMAIN_BASE: &[u8] = b"IOI_DCPP_PROVIDER_ACK_V1";

// Helper to compute typed hash
fn sha256_32(data: &[u8]) -> Result<[u8; 32]> {
    let digest = sha256(data)?;
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&digest);
    Ok(arr)
}

// --- Provider Client Abstraction ---
pub struct ProvisioningReceiptData {
    pub machine_id: String,
    pub endpoint_uri: String,
    pub lease_id: String,
    pub signature: Vec<u8>,
}

#[async_trait]
pub trait ProviderClient: Send + Sync {
    async fn request_provisioning(
        &self,
        endpoint: &str,
        ticket: &JobTicket,
        domain: &[u8],
        ticket_root: &[u8; 32],
    ) -> Result<ProvisioningReceiptData>;
}

// Mock Implementation for simulation/testing
pub struct MockProviderClient;
#[async_trait]
impl ProviderClient for MockProviderClient {
    async fn request_provisioning(
        &self,
        _endpoint: &str,
        _ticket: &JobTicket,
        _domain: &[u8],
        _ticket_root: &[u8; 32],
    ) -> Result<ProvisioningReceiptData> {
        // Fail explicitly until real HTTP backend is wired in via feature flag or dependency update.
        // This prevents misleading "success" logs in production/testing without actual provisioning.
        Err(anyhow!(
            "ProviderClient not implemented (HTTP backend required)"
        ))
    }
}

// ... [Oracle Operator Task - Unchanged] ...
// Re-inserting to keep file complete for output
pub async fn run_oracle_operator_task<CS, ST, CE, V>(
    context: &MainLoopContext<CS, ST, CE, V>,
) -> Result<()>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug
        + Clone,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
    V: Verifier<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug,
    <CS as CommitmentScheme>::Proof:
        serde::Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static + Debug,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
{
    let workload_client = context.view_resolver.workload_client();

    // --- STATE GATE ---
    let oracle_active_key = active_service_key("oracle");
    if workload_client
        .query_raw_state(&oracle_active_key)
        .await?
        .is_none()
    {
        return Ok(());
    }

    let oracle_service = OracleService::new();
    let ns_prefix = service_namespace_prefix("oracle");
    let pending_prefix: Vec<u8> = [ns_prefix.as_slice(), ORACLE_PENDING_REQUEST_PREFIX].concat();

    let pending_requests = match workload_client.prefix_scan(&pending_prefix).await {
        Ok(kvs) => kvs,
        Err(e) => {
            log::error!(
                "Oracle Operator: Failed to scan for pending requests: {}",
                e
            );
            return Ok(());
        }
    };

    if pending_requests.is_empty() {
        return Ok(());
    }

    let validator_stakes = match workload_client.get_staked_validators().await {
        Ok(vs) => vs,
        Err(e) => {
            log::error!("Oracle Operator: Could not get validator stakes: {}", e);
            return Ok(());
        }
    };
    let validator_account_ids: HashSet<AccountId> = validator_stakes.keys().cloned().collect();

    let our_account_id = AccountId(account_id_from_key_material(
        SignatureSuite::Ed25519,
        &context.local_keypair.public().encode_protobuf(),
    )?);

    if !validator_account_ids.contains(&our_account_id) {
        return Ok(());
    }

    for (key, value_bytes) in &pending_requests {
        let suffix = key.get(pending_prefix.len()..);
        let request_id = match suffix
            .and_then(|s| s.try_into().ok())
            .map(u64::from_le_bytes)
        {
            Some(id) => id,
            None => continue,
        };

        let entry: StateEntry = match codec::from_bytes_canonical(value_bytes) {
            Ok(e) => e,
            Err(_) => continue,
        };

        let url = match codec::from_bytes_canonical::<String>(&entry.value) {
            Ok(s) => s,
            Err(_) => continue,
        };

        log::info!(
            "Oracle Operator: Found task for request_id {} (URL: {})",
            request_id,
            url
        );

        match oracle_service.fetch(&url).await {
            Ok(value) => {
                let mut domain = b"ioi/oracle-attest/v1".to_vec();
                domain.extend_from_slice(&context.chain_id.0.to_le_bytes());
                domain.extend_from_slice(&context.genesis_hash);

                let mut attestation = OracleAttestation {
                    request_id,
                    value,
                    timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
                    signature: vec![],
                };

                let payload_to_sign = attestation.to_signing_payload(&domain)?;
                let signature_bytes = context.local_keypair.sign(&payload_to_sign)?;

                let raw_pubkey_bytes = context
                    .local_keypair
                    .public()
                    .try_into_ed25519()
                    .map_err(|_| anyhow!("Local keypair is not Ed25519"))?
                    .to_bytes();

                attestation.signature = [raw_pubkey_bytes.as_ref(), &signature_bytes].concat();

                let attestation_bytes =
                    codec::to_bytes_canonical(&attestation).map_err(|e| anyhow!(e))?;
                context
                    .swarm_commander
                    .send(SwarmCommand::GossipOracleAttestation(attestation_bytes))
                    .await
                    .ok();
                log::info!(
                    "Oracle Operator: Gossiped attestation for request_id {}",
                    request_id
                );
            }
            Err(e) => log::error!(
                "Oracle Operator: Failed to fetch data for request {}: {}",
                request_id,
                e
            ),
        }
    }

    Ok(())
}

// Helper for selecting a provider
fn select_provider(
    providers: &[(Vec<u8>, ProviderInfo)],
    ticket: &JobTicket,
) -> Option<(Vec<u8>, ProviderInfo)> {
    providers
        .iter()
        .find(|(_, p)| {
            p.tier >= ticket.security_tier
                && p.allowed_regions.contains(&ticket.specs.region)
                && p.provider_type == ticket.specs.provider_type
        })
        .cloned()
}

// Global in-memory cursor for ticket scanning.
static LAST_SEEN_TICKET_KEY: Lazy<Mutex<Option<Vec<u8>>>> = Lazy::new(|| Mutex::new(None));

// Global in-memory timestamp for throttling the solver task.
static LAST_SOLVER_RUN: Lazy<Mutex<Option<Instant>>> = Lazy::new(|| Mutex::new(None));
const SOLVER_PERIOD: Duration = Duration::from_secs(2);

fn should_run_solver() -> bool {
    let mut last = LAST_SOLVER_RUN.lock().unwrap();
    let now = Instant::now();
    match *last {
        Some(t) if now.duration_since(t) < SOLVER_PERIOD => false,
        _ => {
            *last = Some(now);
            true
        }
    }
}

/// The Infrastructure Solver Task.
/// This runs periodically (throttled) to process new compute requests.
pub async fn run_infra_solver_task<CS, ST, CE, V>(
    context: &MainLoopContext<CS, ST, CE, V>,
) -> Result<()>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug
        + Clone,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
    V: Verifier<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug,
    <CS as CommitmentScheme>::Proof:
        serde::Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static + Debug,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
{
    // [DoS Protection] Throttle execution frequency
    if !should_run_solver() {
        return Ok(());
    }

    let workload_client = context.view_resolver.workload_client();

    // 1. Check if the service is active
    let cloud_service_key = active_service_key("decentralized_cloud");
    if workload_client
        .query_raw_state(&cloud_service_key)
        .await?
        .is_none()
    {
        return Ok(());
    }

    let ns_prefix = service_namespace_prefix("decentralized_cloud");

    // 2. Fetch Provider Registry
    let provider_prefix = [ns_prefix.as_slice(), DECENTRALIZED_CLOUD_PROVIDER_PREFIX].concat();
    let provider_kvs = match workload_client.prefix_scan(&provider_prefix).await {
        Ok(kvs) => kvs,
        Err(_) => return Ok(()),
    };

    let mut providers = Vec::new();
    for (k, v) in provider_kvs {
        if k.len() <= provider_prefix.len() {
            continue;
        }
        let provider_id = k[provider_prefix.len()..].to_vec();
        // Enforce 32-byte ID constraint (sha256 hash)
        if provider_id.len() != 32 {
            continue;
        }

        if let Ok(info) = codec::from_bytes_canonical::<ProviderInfo>(&v) {
            providers.push((provider_id, info));
        }
    }

    if providers.is_empty() {
        return Ok(());
    }

    // 3. Scan Tickets with Cursor
    // WARNING: Ticket keys MUST use fixed-width big-endian request_ids (u64_be)
    // to ensure lexicographical order matches numeric order.
    let ticket_prefix = [ns_prefix.as_slice(), DECENTRALIZED_CLOUD_TICKET_PREFIX].concat();
    let all_tickets = match workload_client.prefix_scan(&ticket_prefix).await {
        Ok(kvs) => kvs,
        Err(_) => return Ok(()),
    };

    let cursor = LAST_SEEN_TICKET_KEY.lock().unwrap().clone();

    // Filter by cursor (forward progress)
    let pending_tickets: Vec<_> = all_tickets
        .into_iter()
        .filter(|(k, _)| if let Some(c) = &cursor { k > c } else { true })
        .take(10) // Batch limit
        .collect();

    // WRAP-AROUND LOGIC: If no tickets found after cursor, reset cursor to None to retry old items.
    if pending_tickets.is_empty() {
        if cursor.is_some() {
            *LAST_SEEN_TICKET_KEY.lock().unwrap() = None;
            log::debug!("Infra Solver: Cursor wrapped around, rescanning from start.");
        }
        return Ok(());
    }

    // This can be swapped for a real client implementation later
    let provider_client = MockProviderClient;

    for (key, val_bytes) in pending_tickets {
        // ALWAYS update cursor to ensure progress, even on failure/skip
        *LAST_SEEN_TICKET_KEY.lock().unwrap() = Some(key.clone());

        let ticket: JobTicket = match codec::from_bytes_canonical(&val_bytes) {
            Ok(t) => t,
            Err(_) => continue,
        };

        log::info!("Infra Solver: Processing job {}", ticket.request_id);

        // 4. Select Provider
        let (provider_id, provider_info) = match select_provider(&providers, &ticket) {
            Some(p) => p,
            None => {
                log::warn!("No suitable provider found for job {}", ticket.request_id);
                continue;
            }
        };

        log::info!(
            "Infra Solver: selected provider {} at {} for job {}",
            hex::encode(&provider_id),
            provider_info.endpoint,
            ticket.request_id
        );

        // 5. Construct Canonical Payload for Signing
        // TicketRoot = H(canonical_ticket)
        let canonical_ticket = codec::to_bytes_canonical(&ticket).map_err(|e| anyhow!(e))?;
        let ticket_root = sha256_32(&canonical_ticket)?;

        // Prepare domain prefix
        let mut domain = DCPP_ACK_DOMAIN_BASE.to_vec();
        domain.extend_from_slice(&context.chain_id.0.to_le_bytes());
        domain.extend_from_slice(&context.genesis_hash);

        // 6. Request Provisioning & Signature
        let provider_response = match provider_client
            .request_provisioning(&provider_info.endpoint, &ticket, &domain, &ticket_root)
            .await
        {
            Ok(r) => r,
            Err(e) => {
                log::warn!("Provider request failed: {}", e);
                continue;
            }
        };

        // 7. Local Verification (Sanity Check)
        let payload = ProviderAckPayload {
            ticket_root,
            machine_id: provider_response.machine_id.as_bytes().to_vec(),
            endpoint_uri_hash: sha256_32(provider_response.endpoint_uri.as_bytes())?,
            expiry_height: ticket.expiry_height,
            lease_id_hash: sha256_32(provider_response.lease_id.as_bytes())?,
        };

        // Verify that the signature we got matches the provider we selected.
        // This prevents us from submitting bad transactions and wasting gas.
        let payload_bytes = codec::to_bytes_canonical(&payload).map_err(|e| anyhow!(e))?;
        let mut signing_input = Vec::new();
        signing_input.extend_from_slice(&domain);
        signing_input.extend_from_slice(&payload_bytes);

        // Robust parsing of Ed25519 key bytes
        let pk_bytes_arr: [u8; 32] = match provider_info.public_key.as_slice().try_into() {
            Ok(b) => b,
            Err(_) => {
                log::warn!("Infra Solver: Provider pubkey is not 32 bytes");
                continue;
            }
        };

        let sig_bytes_arr: [u8; 64] = match provider_response.signature.as_slice().try_into() {
            Ok(b) => b,
            Err(_) => {
                log::warn!("Infra Solver: Provider signature is not 64 bytes");
                continue;
            }
        };

        if let Ok(pk) = Ed25519PublicKey::from_bytes(&pk_bytes_arr) {
            if let Ok(sig) = Ed25519Signature::from_bytes(&sig_bytes_arr) {
                if pk.verify(&signing_input, &sig).is_err() {
                    log::warn!(
                        "Infra Solver: Provider signature verification failed for job {}",
                        ticket.request_id
                    );
                    continue;
                }
            } else {
                log::warn!("Infra Solver: Invalid signature format from provider");
                continue;
            }
        } else {
            log::warn!("Infra Solver: Unsupported provider key type");
            continue;
        }

        // 8. Submit Receipt
        let receipt = ProvisioningReceipt {
            request_id: ticket.request_id,
            ticket_root,
            provider_id,
            endpoint_uri: provider_response.endpoint_uri,
            machine_id: provider_response.machine_id,
            expiry_height: ticket.expiry_height,
            lease_id: provider_response.lease_id,
            provider_signature: provider_response.signature,
        };

        // 9. Submit Transaction
        let our_pk = context.local_keypair.public().encode_protobuf();
        let our_account_id = AccountId(account_id_from_key_material(
            SignatureSuite::Ed25519,
            &our_pk,
        )?);

        let nonce_key = [
            ioi_types::keys::ACCOUNT_NONCE_PREFIX,
            our_account_id.as_ref(),
        ]
        .concat();
        let nonce = match workload_client.query_raw_state(&nonce_key).await {
            Ok(Some(b)) => codec::from_bytes_canonical::<u64>(&b).unwrap_or(0),
            _ => 0,
        };

        let sys_payload = SystemPayload::CallService {
            service_id: "decentralized_cloud".into(),
            method: "finalize_provisioning@v1".into(),
            params: codec::to_bytes_canonical(&receipt).map_err(|e| anyhow!(e))?,
        };

        let mut sys_tx = SystemTransaction {
            header: SignHeader {
                account_id: our_account_id,
                nonce,
                chain_id: context.chain_id,
                tx_version: 1,
            },
            payload: sys_payload,
            signature_proof: SignatureProof::default(),
        };

        let sign_bytes = sys_tx.to_sign_bytes().map_err(|e| anyhow!(e))?;
        let signature = context.local_keypair.sign(&sign_bytes)?;

        sys_tx.signature_proof = SignatureProof {
            suite: SignatureSuite::Ed25519,
            public_key: our_pk,
            signature,
        };

        let tx = ChainTransaction::System(Box::new(sys_tx));
        let tx_hash = tx.hash()?;

        context
            .tx_pool_ref
            .add(tx, tx_hash, Some((our_account_id, nonce)), 0);

        log::info!(
            "Infra Solver: Submitted receipt for job {}, provider {}",
            ticket.request_id,
            hex::encode(&receipt.provider_id)
        );
    }

    Ok(())
}
