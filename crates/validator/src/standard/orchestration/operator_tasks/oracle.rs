use super::*;

/// Runs oracle activation checks using only a detached workload client handle.
pub async fn run_oracle_operator_task_with_client(
    workload_client: std::sync::Arc<dyn WorkloadClientApi>,
) -> Result<()> {
    // --- STATE GATE ---
    let oracle_active_key = active_service_key("oracle");
    if workload_client
        .query_raw_state(&oracle_active_key)
        .await?
        .is_none()
    {
        return Ok(());
    }

    Ok(())
}

/// Runs the background task for the Oracle operator.
/// Checks if the oracle service is active and performs necessary duties.
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
    run_oracle_operator_task_with_client(context.view_resolver.workload_client().clone()).await
}
