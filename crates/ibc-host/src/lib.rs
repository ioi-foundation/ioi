// Path: crates/ibc-host/src/lib.rs
#![forbid(unsafe_code)]

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use depin_sdk_api::state::Verifier;
use depin_sdk_client::WorkloadClient;
use depin_sdk_crypto::algorithms::hash::sha256;
use depin_sdk_network::libp2p::SwarmCommand;
use depin_sdk_types::{
    app::{
        account_id_from_key_material, AccountId, ChainId, ChainTransaction, SignHeader,
        SignatureProof, SignatureSuite, SystemPayload, SystemTransaction,
    },
    codec,
};
use libp2p::identity::Keypair;
use lru::LruCache;
use std::{collections::BTreeMap, num::NonZeroUsize, sync::Arc};
use tokio::sync::{mpsc, Mutex};
use tracing;

#[derive(Debug, Clone)]
pub struct QueryHostResponse {
    pub value: Vec<u8>,
    pub proof: Option<Vec<u8>>,
    pub height: u64,
}

#[async_trait]
pub trait IbcHost: Send + Sync {
    async fn query(
        &self,
        path: &str,
        height: Option<u64>,
        latest: bool,
    ) -> Result<QueryHostResponse>;
    async fn submit_ibc_messages(&self, msgs_pb: Vec<u8>) -> Result<[u8; 32]>;
}

pub struct DefaultIbcHost<V: Verifier> {
    workload_client: Arc<WorkloadClient>,
    _verifier: V, // Keep verifier for type parameter matching, though not used directly here
    tx_pool: Arc<Mutex<std::collections::VecDeque<ChainTransaction>>>,
    swarm_commander: mpsc::Sender<SwarmCommand>,
    signer: Keypair,
    nonce_manager: Arc<Mutex<BTreeMap<AccountId, u64>>>,
    chain_id: ChainId,
    idempotency_cache: Arc<Mutex<LruCache<[u8; 32], [u8; 32]>>>,
}

impl<V: Verifier + 'static> DefaultIbcHost<V> {
    pub fn new(
        workload_client: Arc<WorkloadClient>,
        verifier: V,
        tx_pool: Arc<Mutex<std::collections::VecDeque<ChainTransaction>>>,
        swarm_commander: mpsc::Sender<SwarmCommand>,
        signer: Keypair,
        nonce_manager: Arc<Mutex<BTreeMap<AccountId, u64>>>,
        chain_id: ChainId,
    ) -> Self {
        tracing::debug!(
            target = "mempool",
            "host tx_pool ptr = {:p}",
            Arc::as_ptr(&tx_pool)
        );
        Self {
            workload_client,
            _verifier: verifier,
            tx_pool,
            swarm_commander,
            signer,
            nonce_manager,
            chain_id,
            idempotency_cache: Arc::new(Mutex::new(LruCache::new(
                NonZeroUsize::new(1024).unwrap(),
            ))),
        }
    }
}

#[async_trait]
impl<V: Verifier + Send + Sync + 'static> IbcHost for DefaultIbcHost<V> {
    async fn query(
        &self,
        path: &str,
        height: Option<u64>,
        latest: bool,
    ) -> Result<QueryHostResponse> {
        if (height.is_some() && latest) || (height.is_none() && !latest) {
            return Err(anyhow!(
                "Exactly one of 'height' or 'latest' must be specified"
            ));
        }

        let (query_height, state_root) = if latest {
            let status = self.workload_client.get_status().await?;
            let root = self.workload_client.get_state_root().await?;
            (status.height, root)
        } else {
            let h = height.unwrap();
            let header = self
                .workload_client
                .get_block_by_height(h)
                .await?
                .ok_or_else(|| anyhow!("Block at height {} not found", h))?;
            (h, header.state_root)
        };

        let response = self
            .workload_client
            .query_state_at(state_root, path.as_bytes())
            .await?;

        Ok(QueryHostResponse {
            value: response.membership.into_option().unwrap_or_default(),
            proof: Some(response.proof_bytes),
            height: query_height,
        })
    }

    async fn submit_ibc_messages(&self, msgs_pb: Vec<u8>) -> Result<[u8; 32]> {
        let msgs_hash = sha256(&msgs_pb)?;
        if let Some(tx_hash) = self.idempotency_cache.lock().await.get(&msgs_hash) {
            return Ok(*tx_hash);
        }

        // The account_id MUST be derived from the keypair that is present in the genesis state.
        // For the test setup, the orchestrator's identity keypair IS the validator.
        let account_id = AccountId(account_id_from_key_material(
            SignatureSuite::Ed25519,
            &self.signer.public().encode_protobuf(),
        )?);

        let nonce = {
            let mut manager = self.nonce_manager.lock().await;
            let n = manager.entry(account_id).or_insert(0); // Use the correct account_id here.
            let current = *n;
            *n += 1;
            current
        };

        let tx = ChainTransaction::System(Box::new(SystemTransaction {
            header: SignHeader {
                account_id,
                nonce,
                chain_id: self.chain_id,
                tx_version: 1,
            },
            payload: SystemPayload::CallService {
                service_id: "ibc".to_string(),
                method: "msg_dispatch@v1".to_string(),
                params: msgs_pb,
            },
            signature_proof: SignatureProof::default(), // Will be filled in
        }));

        // A proper implementation would use a signer trait here.
        // For now, we manually sign.
        let (signed_tx, tx_bytes) = {
            if let ChainTransaction::System(mut sys_tx) = tx {
                let sign_bytes = sys_tx.to_sign_bytes().map_err(|e| anyhow!(e))?;
                sys_tx.signature_proof = SignatureProof {
                    suite: SignatureSuite::Ed25519,
                    public_key: self.signer.public().encode_protobuf(),
                    signature: self.signer.sign(&sign_bytes)?,
                };
                let final_tx = ChainTransaction::System(sys_tx);
                let bytes = codec::to_bytes_canonical(&final_tx).map_err(|e| anyhow!(e))?;
                (final_tx, bytes)
            } else {
                unreachable!();
            }
        };
        let tx_hash = sha256(&tx_bytes)?;

        {
            let mut pool = self.tx_pool.lock().await;
            let before = pool.len();
            pool.push_back(signed_tx);
            let after = pool.len();
            tracing::debug!(
                target = "mempool",
                "pushed IBC tx: account_id={}, before={}, after={}, nonce={}",
                hex::encode(account_id.as_ref()),
                before,
                after,
                nonce
            );
        }
        self.swarm_commander
            .send(SwarmCommand::PublishTransaction(tx_bytes))
            .await?;
        tracing::debug!(target = "mempool", "gossiped IBC tx to swarm");

        self.idempotency_cache.lock().await.put(msgs_hash, tx_hash);
        Ok(tx_hash)
    }
}
