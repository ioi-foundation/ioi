// Path: crates/validator/src/standard/orchestration/operator_tasks.rs
//! Contains off-chain, state-gated operator tasks for native services.

use super::context::MainLoopContext;
use anyhow::{anyhow, Result};
use depin_sdk_api::{
    commitment::CommitmentScheme,
    consensus::ConsensusEngine,
    state::{StateManager, Verifier},
};
use depin_sdk_network::libp2p::SwarmCommand;
use depin_sdk_services::oracle::OracleService;
use depin_sdk_types::{
    app::{
        account_id_from_key_material, AccountId, ChainTransaction, OracleAttestation,
        SignatureSuite, StateEntry,
    },
    codec,
    keys::{active_service_key, ORACLE_PENDING_REQUEST_PREFIX},
};
use std::collections::HashSet;
use std::fmt::Debug;
use std::time::{SystemTime, UNIX_EPOCH};

/// The state-gated operator task for the native Oracle service.
/// It scans the chain state for pending oracle requests, fetches data from external
/// URLs, creates signed attestations, and gossips them to other validators.
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
    V: Verifier<Commitment = CS::Commitment, Proof = CS::Proof> + Clone + Send + Sync + 'static,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
    <CS as CommitmentScheme>::Proof:
        serde::Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static,
{
    let workload_client = match context
        .view_resolver
        .as_any()
        .downcast_ref::<super::view_resolver::DefaultViewResolver<V>>()
    {
        Some(resolver) => resolver.workload_client(),
        None => {
            log::error!("Oracle Operator: Could not downcast ViewResolver to get WorkloadClient.");
            return Ok(());
        }
    };

    // --- STATE GATE ---
    // The operator task only runs if the 'oracle' service is marked as active on-chain.
    let oracle_active_key = active_service_key("oracle");
    if workload_client
        .query_raw_state(&oracle_active_key)
        .await?
        .is_none()
    {
        // Service is not active, do nothing and return.
        return Ok(());
    }

    // --- EGRESS ALLOWLIST (Future Enhancement) ---
    // Here, an on-chain allowlist of permitted domains would be fetched before making HTTP requests.

    let oracle_service = OracleService::new();

    let pending_requests = match workload_client
        .prefix_scan(ORACLE_PENDING_REQUEST_PREFIX)
        .await
    {
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
        return Ok(()); // This node is not a staked validator, do nothing.
    }

    for (key, value_bytes) in &pending_requests {
        let suffix = key.get(ORACLE_PENDING_REQUEST_PREFIX.len()..);
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
                let mut domain = b"depinsdk/oracle-attest/v1".to_vec();
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
                    .swarm_commander // <-- CORRECTED FIELD NAME
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
