// Path: crates/validator/src/standard/orchestration/consensus.rs
use super::context::MainLoopContext;
use super::oracle::handle_newly_processed_block;
use depin_sdk_api::{
    commitment::CommitmentScheme,
    state::{StateCommitment, StateManager},
    transaction::TransactionModel,
};
use depin_sdk_consensus::{ConsensusDecision, ConsensusEngine};
use depin_sdk_network::libp2p::SwarmCommand;
use depin_sdk_network::traits::NodeState;
use depin_sdk_transaction_models::unified::UnifiedTransactionModel;
use depin_sdk_types::app::{Block, BlockHeader, ChainTransaction};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use std::time::{SystemTime, UNIX_EPOCH};

/// Handles the consensus timer tick, deciding whether to produce a block.
pub async fn handle_consensus_tick<CS, ST, CE>(context: &mut MainLoopContext<CS, ST, CE>)
where
    CS: CommitmentScheme + Clone + Default + Send + Sync + 'static,
    <CS as CommitmentScheme>::Proof:
        Serialize + for<'de> Deserialize<'de> + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + StateCommitment<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
{
    if *context.node_state.lock().await != NodeState::Synced {
        return;
    }

    let decision = {
        let mut engine = context.consensus_engine_ref.lock().await;
        let known_peers = context.known_peers_ref.lock().await;
        let target_height = context
            .workload_client
            .get_status()
            .await
            .map_or(0, |s| s.height)
            + 1;
        let current_view = 0;
        let consensus_data = match engine.get_validator_data(&context.workload_client).await {
            Ok(data) => data,
            Err(e) => {
                log::error!("[Orch] Could not get validator data for consensus: {e}");
                return;
            }
        };
        engine
            .decide(
                &context.local_peer_id,
                target_height,
                current_view,
                &consensus_data,
                &known_peers,
            )
            .await
    };

    if let ConsensusDecision::ProduceBlock(_) = decision {
        let target_height = context
            .workload_client
            .get_status()
            .await
            .map_or(0, |s| s.height)
            + 1;
        log::info!("Consensus decision: Produce block for height {target_height}.");
        let header_data = match context.workload_client.get_validator_set().await {
            Ok(data) => data,
            Err(e) => {
                log::error!("[Orch] Could not get validator set for block header: {e}");
                return;
            }
        };
        let mut transactions_to_include = context
            .tx_pool_ref
            .lock()
            .await
            .drain(..)
            .collect::<Vec<_>>();
        let coinbase = UnifiedTransactionModel::new(CS::default())
            .create_coinbase_transaction(target_height, &context.local_peer_id.to_bytes())
            .unwrap();
        transactions_to_include.insert(0, coinbase);
        let prev_hash = context
            .workload_client
            .get_last_block_hash()
            .await
            .unwrap_or_else(|_| vec![0; 32]);

        let new_block_template = Block {
            header: BlockHeader {
                height: target_height,
                prev_hash,
                state_root: vec![],
                transactions_root: vec![0; 32],
                timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                validator_set: header_data,
                producer: context.local_keypair.public().encode_protobuf(),
                signature: vec![],
            },
            transactions: transactions_to_include,
        };

        match context
            .workload_client
            .process_block(new_block_template)
            .await
        {
            Ok((mut final_block, _)) => {
                let block_height = final_block.header.height;
                log::info!("Produced and processed new block #{}", block_height);
                // --- FIX: Add explicit generic arguments to the function call ---
                handle_newly_processed_block::<CS, ST, CE>(
                    context,
                    block_height,
                    &context.external_data_service,
                )
                .await;
                let header_hash = final_block.header.hash();
                final_block.header.signature = context.local_keypair.sign(&header_hash).unwrap();
                let data = serde_json::to_vec(&final_block).unwrap();
                context
                    .swarm_commander
                    .send(SwarmCommand::PublishBlock(data))
                    .await
                    .ok();
                context
                    .consensus_engine_ref
                    .lock()
                    .await
                    .reset(block_height);
                if let Ok(outcomes) = context
                    .workload_client
                    .check_and_tally_proposals(block_height)
                    .await
                {
                    for outcome in outcomes {
                        log::info!("{}", outcome);
                    }
                }
            }
            Err(e) => log::error!("Workload failed to process new block: {}", e),
        }
    }
}
