// Path: crates/validator/src/standard/orchestration/events.rs

use super::context::MainLoopContext;
use super::{gossip, oracle, peer_management, sync as sync_handlers};
use ioi_api::{
    commitment::CommitmentScheme,
    consensus::ConsensusEngine,
    crypto::{SerializableKey, SigningKeyPair},
    state::{StateManager, Verifier},
};

// [FIX] REMOVED unused MldsaKeyPair import
// use ioi_crypto::sign::dilithium::MldsaKeyPair;

use ioi_networking::libp2p::NetworkEvent;
use ioi_networking::traits::NodeState;
use ioi_types::app::{account_id_from_key_material, ChainTransaction, SignatureSuite};
use serde::Serialize;
use std::fmt::Debug;
use std::sync::Arc;
use tokio::sync::Mutex;
use parity_scale_codec::{Decode, Encode};

pub async fn handle_network_event<CS, ST, CE, V>(
    event: NetworkEvent,
    context_arc: &Arc<Mutex<MainLoopContext<CS, ST, CE, V>>>,
) where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    <CS as CommitmentScheme>::Proof:
        Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static + Debug + Encode + Decode,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug
        + Clone,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
    V: Verifier<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug,
{
    match event {
        NetworkEvent::GossipTransaction(tx) => {
            let tx_hash = match tx.hash() {
                Ok(h) => h,
                Err(e) => {
                    tracing::warn!(target: "gossip", "Failed to hash gossiped transaction: {}", e);
                    return;
                }
            };

            let (tx_pool_ref, kick_tx) = {
                let ctx = context_arc.lock().await;
                (ctx.tx_pool_ref.clone(), ctx.consensus_kick_tx.clone())
            };

            let tx_info = match tx.as_ref() {
                ChainTransaction::System(s) => Some((s.header.account_id, s.header.nonce)),
                ChainTransaction::Settlement(s) => Some((s.header.account_id, s.header.nonce)),
                ChainTransaction::Application(a) => match a {
                    ioi_types::app::ApplicationTransaction::DeployContract { header, .. } => {
                        Some((header.account_id, header.nonce))
                    }
                    ioi_types::app::ApplicationTransaction::CallContract { header, .. } => {
                        Some((header.account_id, header.nonce))
                    }
                },
                _ => None,
            };

            {
                tx_pool_ref.add(*tx, tx_hash, tx_info, 0);
                log::debug!("[Orchestrator] Mempool size is now {}", tx_pool_ref.len());
                let _ = kick_tx.send(());
            }
        }
        NetworkEvent::GossipBlock { block, mirror_id } => {
            let node_state = { context_arc.lock().await.node_state.lock().await.clone() };
            if node_state == NodeState::Syncing {
                tracing::debug!(
                    target: "gossip",
                    event = "block_ignored",
                    height = block.header.height,
                    reason = "Node is currently syncing"
                );
                return;
            }

            let (our_ed_id, our_pqc_id_opt, kick_tx) = {
                let ctx = context_arc.lock().await;

                let ed_pk = ctx.local_keypair.public().encode_protobuf();
                let ed_id = account_id_from_key_material(SignatureSuite::ED25519, &ed_pk)
                    .unwrap_or_default();

                let pqc_id_opt = ctx.pqc_signer.as_ref().map(|kp| {
                    // [FIX] Explicit generic typing for public_key if needed, but remove if MldsaKeyPair is not imported
                    // MldsaKeyPair was unused in imports, so we need to access trait method via fully qualified path or rely on inference.
                    // Since MldsaKeyPair impls SigningKeyPair, we can use that trait.
                    // But we removed the import. If `pqc_signer` is `Option<MldsaKeyPair>`, we need `MldsaKeyPair` in scope or `SigningKeyPair`.
                    // We kept `SigningKeyPair` in imports.
                    let pqc_pk: Vec<u8> = SigningKeyPair::public_key(kp).to_bytes();
                    account_id_from_key_material(SignatureSuite::ML_DSA_44, &pqc_pk)
                        .unwrap_or_default()
                });

                (ed_id, pqc_id_opt, ctx.consensus_kick_tx.clone())
            };

            let producer_id = block.header.producer_pubkey_hash;
            let is_ours = producer_id == our_ed_id
                || our_pqc_id_opt
                    .map(|id: [u8; 32]| id == producer_id)
                    .unwrap_or(false);

            if is_ours {
                tracing::info!(target: "orchestration",
                    "[Orchestrator] Skipping verification of our own gossiped block #{}.",
                    block.header.height
                );
                let _ = kick_tx.send(());
                return;
            }

            let mut ctx = context_arc.lock().await;
            gossip::handle_gossip_block(&mut ctx, block, mirror_id).await
        }
        NetworkEvent::ConnectionEstablished(peer_id) => {
            let mut ctx = context_arc.lock().await;
            peer_management::handle_connection_established(&mut ctx, peer_id).await
        }
        NetworkEvent::ConnectionClosed(peer_id) => {
            let mut ctx = context_arc.lock().await;
            peer_management::handle_connection_closed(&mut ctx, peer_id).await
        }
        NetworkEvent::StatusRequest(peer, channel) => {
            let mut ctx = context_arc.lock().await;
            sync_handlers::handle_status_request(&mut ctx, peer, channel).await
        }
        NetworkEvent::BlocksRequest {
            peer,
            since,
            max_blocks,
            max_bytes,
            channel,
        } => {
            let mut ctx = context_arc.lock().await;
            sync_handlers::handle_blocks_request(
                &mut ctx, peer, since, max_blocks, max_bytes, channel,
            )
            .await
        }
        NetworkEvent::StatusResponse {
            peer,
            height,
            head_hash,
            chain_id,
            genesis_root,
        } => {
            let mut ctx = context_arc.lock().await;
            sync_handlers::handle_status_response(
                &mut ctx,
                peer,
                height,
                head_hash,
                chain_id,
                genesis_root,
            )
            .await
        }
        NetworkEvent::BlocksResponse(peer, blocks) => {
            let mut ctx = context_arc.lock().await;
            sync_handlers::handle_blocks_response(&mut ctx, peer, blocks).await
        }
        NetworkEvent::OracleAttestationReceived { from, attestation } => {
            let mut ctx = context_arc.lock().await;
            oracle::handle_oracle_attestation_received(&mut ctx, from, attestation).await
        }
        NetworkEvent::OutboundFailure(peer) => {
            let mut ctx = context_arc.lock().await;
            sync_handlers::handle_outbound_failure(&mut ctx, peer).await
        }
        _ => {}
    }
}