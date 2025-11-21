// Path: crates/validator/src/standard/orchestration/operator_tasks.rs

use super::context::MainLoopContext;
use anyhow::{anyhow, Result};
use ioi_api::{
    commitment::CommitmentScheme,
    consensus::ConsensusEngine,
    state::{service_namespace_prefix, StateManager, Verifier},
};
use ioi_networking::libp2p::SwarmCommand;
use ioi_services::oracle::OracleService;
use ioi_types::{
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
    // CHANGED: Use trait method instead of downcasting
    let workload_client = context.view_resolver.workload_client();

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

    // Pending requests are written by OracleService *under its namespace* via NamespacedStateAccess.
    // The actual stored keys look like:
    //   _service_data::oracle::ORACLE_PENDING_REQUEST_PREFIX || request_id_le
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
        return Ok(()); // This node is not a staked validator, do nothing.
    }

    for (key, value_bytes) in &pending_requests {
        // Strip the full namespaced prefix to recover the raw request_id bytes.
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
