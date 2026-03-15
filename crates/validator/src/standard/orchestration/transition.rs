// Path: crates/validator/src/standard/orchestration/transition.rs

use crate::standard::orchestration::context::MainLoopContext;
use ioi_api::{
    commitment::CommitmentScheme,
    consensus::ConsensusEngine,
    state::{StateManager, Verifier},
};
use ioi_types::app::{ChainTransaction, ProofOfDivergence};
use parity_scale_codec::{Decode, Encode};
use serde::Serialize;
use std::fmt::Debug;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Quarantines the local node after validated divergence evidence.
pub async fn execute_divergence_response<CS, ST, CE, V>(
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
    CE: ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
    V: Verifier<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug,
    <CS as CommitmentScheme>::Proof: Serialize
        + for<'de> serde::Deserialize<'de>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug
        + Encode
        + Decode,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
{
    let ctx = context.lock().await;

    if ctx.is_quarantined.swap(true, Ordering::SeqCst) {
        tracing::warn!(
            target: "orchestration",
            "Divergence response ignored: node already quarantined."
        );
        return Ok(());
    }

    tracing::error!(
        target: "orchestration",
        "Validated divergence evidence for offender {:?}; local validator is quarantined.",
        proof.offender
    );
    tracing::info!(
        target: "orchestration",
        "Divergence evidence logged; guardianized consensus remains in place and no fallback engine is started."
    );

    Ok(())
}
