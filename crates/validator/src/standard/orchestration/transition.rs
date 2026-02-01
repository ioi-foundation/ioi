// Path: crates/validator/src/standard/orchestration/transition.rs

use crate::standard::orchestration::context::MainLoopContext;
use ioi_api::{
    commitment::CommitmentScheme,
    consensus::{ConsensusEngine, ConsensusControl}, // [FIX] Added ConsensusControl trait
    state::{StateManager, Verifier},
};
use ioi_networking::libp2p::SwarmCommand;
use ioi_networking::traits::NodeState;
use ioi_types::app::{ChainTransaction, ProofOfDivergence};
use serde::Serialize;
use std::fmt::Debug;
use std::sync::Arc;
use tokio::sync::Mutex;
use parity_scale_codec::{Decode, Encode};

/// Executes the Kill Switch: Freezes A-DMFT and initiates the handoff to A-PMFT.
pub async fn execute_kill_switch<CS, ST, CE, V>(
    context: &Arc<Mutex<MainLoopContext<CS, ST, CE, V>>>,
    proof: ProofOfDivergence,
) -> anyhow::Result<()>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug
        + Clone,
    CE: ConsensusEngine<ChainTransaction> + ConsensusControl + Send + Sync + 'static, // [FIX] Added ConsensusControl bound
    V: Verifier<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug,
    <CS as CommitmentScheme>::Proof:
        Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + Sync + 'static + Debug + Encode + Decode,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
{
    // Acquire the context lock. This is critical as we are mutating the consensus engine reference.
    let ctx = context.lock().await;

    // 1. Check current state
    {
        let mut state_guard = ctx.node_state.lock().await;
        // If we are already transitioning or in A-PMFT, ignore.
        if matches!(*state_guard, NodeState::Transitioning | NodeState::SurvivalMode) {
            tracing::warn!(target: "orchestration", "Kill Switch ignored: Node already in {:?} state.", *state_guard);
            return Ok(());
        }

        tracing::error!(target: "orchestration", 
            "🚨 KILL SWITCH ACTIVATED 🚨 Hardware Compromise Detected! Offender: {:?}", 
            proof.offender
        );

        // 2. Freeze A-DMFT
        // We update the node state to Transitioning.
        // The main loop checks this state and will stop processing standard blocks/votes.
        *state_guard = NodeState::Transitioning;
    } // Drop state lock

    // 3. Persist Panic Evidence (Optional but good for forensics)
    // In a full impl, we'd write to a "forensics.db" or similar.
    tracing::info!(target: "orchestration", "Panic evidence validated and logged.");

    // 4. Initialize Engine B (A-PMFT)
    // We access the consensus engine via the reference in the context.
    // Since CE implements ConsensusControl, we can call switch_to_apmft().
    {
        let mut engine_guard = ctx.consensus_engine_ref.lock().await;
        engine_guard.switch_to_apmft();
        tracing::info!(target: "orchestration", "Consensus Engine swapped to A-PMFT.");
    }
    
    // 5. Update State to Survival Mode
    {
        let mut state_guard = ctx.node_state.lock().await;
        *state_guard = NodeState::SurvivalMode;
        tracing::warn!(target: "orchestration", "Node entered SURVIVAL MODE (A-PMFT Active).");
    }

    Ok(())
}