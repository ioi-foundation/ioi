// crates/consensus/src/solo/mod.rs

use crate::{ConsensusDecision, ConsensusEngine, PenaltyEngine, PenaltyMechanism};
use async_trait::async_trait;
use ioi_api::chain::{AnchoredStateView, ChainView};
use ioi_api::commitment::CommitmentScheme;
use ioi_api::consensus::ConsensusControl; // [NEW] Import trait
use ioi_api::state::{StateAccess, StateManager};
use ioi_system::SystemState;
use ioi_types::app::{
    compute_next_timestamp_ms, timestamp_millis_to_legacy_seconds, AccountId, Block,
    BlockTimingParams, BlockTimingRuntime, ChainStatus, ConsensusVote, FailureReport,
    QuorumCertificate,
};
use ioi_types::codec;
use ioi_types::error::{ConsensusError, TransactionError};
use ioi_types::keys::{BLOCK_TIMING_PARAMS_KEY, BLOCK_TIMING_RUNTIME_KEY, STATUS_KEY};
use libp2p::PeerId;
use std::collections::HashSet;

/// A consensus engine for local/solo mode.
/// It always decides to produce a block immediately, acting as a single dictator.
#[derive(Debug, Clone, Default)]
pub struct SoloEngine {
    latest_parent_qc: Option<QuorumCertificate>,
}

impl SoloEngine {
    pub fn new() -> Self {
        Self {
            latest_parent_qc: None,
        }
    }
}

impl ConsensusControl for SoloEngine {
    fn experimental_sample_tip(&self) -> Option<([u8; 32], u32)> {
        None
    }

    fn observe_experimental_sample(&mut self, _hash: [u8; 32]) {}
}

#[async_trait]
impl PenaltyMechanism for SoloEngine {
    async fn apply_penalty(
        &self,
        _state: &mut dyn StateAccess,
        _report: &FailureReport,
    ) -> Result<(), TransactionError> {
        // In local mode, the user owns the node; no penalties are applied.
        Ok(())
    }
}

impl PenaltyEngine for SoloEngine {
    fn apply(
        &self,
        _sys: &mut dyn SystemState,
        _report: &FailureReport,
    ) -> Result<(), TransactionError> {
        Ok(())
    }
}

#[async_trait]
impl<T: Clone + Send + 'static + parity_scale_codec::Encode> ConsensusEngine<T> for SoloEngine {
    async fn decide(
        &mut self,
        _our_account_id: &AccountId,
        height: u64,
        view: u64,
        parent_view: &dyn AnchoredStateView,
        _known_peers: &HashSet<PeerId>,
    ) -> ConsensusDecision<T> {
        // TIMESTAMP PARITY WITH AFT.
        //
        // Solo derives its block timestamp from the SAME on-chain
        // `BlockTimingParams`/`BlockTimingRuntime` abstraction, through the same
        // `compute_next_timestamp_ms`, with the same (parent_height,
        // parent_timestamp_ms, parent_gas_used) inputs AFT uses in
        // `aft::guardian_majority::runtime`.
        //
        // This previously read `max(now_secs, parent_secs + 1)` off the wall
        // clock: whole-second, unconfigurable, and independent of chain state.
        // That made block timestamping a SECOND varying dimension between the
        // two engines, so any Solo-vs-AFT delta was co-produced by the ordering
        // profile and by second-quantized timestamping with nothing separating
        // them. It also put the sub-second floor out of reach of Solo entirely.
        //
        // FAIL CLOSED. Missing timing state stalls rather than substituting a
        // wall clock: a timestamp not entailed by chain state is one a verifier
        // re-deriving it from that state would reject.
        let timing_params = match parent_view.get(BLOCK_TIMING_PARAMS_KEY).await {
            Ok(Some(bytes)) => {
                codec::from_bytes_canonical::<BlockTimingParams>(&bytes).unwrap_or_default()
            }
            _ => return ConsensusDecision::Stall,
        };
        let timing_runtime = match parent_view.get(BLOCK_TIMING_RUNTIME_KEY).await {
            Ok(Some(bytes)) => {
                codec::from_bytes_canonical::<BlockTimingRuntime>(&bytes).unwrap_or_default()
            }
            _ => return ConsensusDecision::Stall,
        };
        let mut parent_status: ChainStatus = match parent_view.get(STATUS_KEY).await {
            Ok(Some(bytes)) => codec::from_bytes_canonical(&bytes).unwrap_or_default(),
            Ok(None) if height == 1 => ChainStatus::default(),
            _ => return ConsensusDecision::Stall,
        };

        // The same testing initial-tip bridge AFT carries, for the same reason:
        // an externally composed fixture can hold signed wall-clock evidence
        // before its fresh chain has produced height one, and genesis may carry
        // either no status or a default zero-timestamp status. Keeping the two
        // engines on the same bridge is part of the parity; production chains
        // stay on their state-derived clock because the namespace is explicit.
        if height == 1 && parent_status.latest_timestamp_ms_or_legacy() == 0 {
            if let Some(timestamp_ms) = std::env::var("IOI_TESTING_INITIAL_TIP_TIMESTAMP_MS")
                .ok()
                .and_then(|value| value.parse::<u64>().ok())
                .filter(|value| *value > 0)
            {
                parent_status.set_latest_timestamp_ms(timestamp_ms);
            }
        }

        let expected_timestamp_ms = compute_next_timestamp_ms(
            &timing_params,
            &timing_runtime,
            height.saturating_sub(1),
            parent_status.latest_timestamp_ms_or_legacy(),
            0,
        )
        .unwrap_or_else(|| parent_status.latest_timestamp_ms_or_legacy());

        ConsensusDecision::ProduceBlock {
            transactions: vec![], // Transactions are injected by the Orchestrator mempool logic
            expected_timestamp_secs: timestamp_millis_to_legacy_seconds(expected_timestamp_ms),
            expected_timestamp_ms,
            view,
            parent_qc: self.latest_parent_qc.clone().unwrap_or_default(),
            previous_canonical_collapse_commitment_hash: [0u8; 32],
            canonical_collapse_extension_certificate: None,
            timeout_certificate: None,
            aft_timeout_certificate: None,
        }
    }

    async fn handle_block_proposal<CS, ST>(
        &mut self,
        _block: Block<T>,
        _chain_view: &dyn ChainView<CS, ST>,
    ) -> Result<(), ConsensusError>
    where
        CS: CommitmentScheme + Send + Sync,
        ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof> + Send + Sync + 'static,
    {
        // Solo engine accepts everything valid, but typically won't receive gossip in Mode 0.
        Ok(())
    }

    async fn handle_vote(&mut self, _vote: ConsensusVote) -> Result<(), ConsensusError> {
        // Solo mode does not process votes from peers.
        Ok(())
    }

    async fn handle_view_change(
        &mut self,
        _from: PeerId,
        _proof_bytes: &[u8],
    ) -> Result<(), ConsensusError> {
        Ok(())
    }

    fn reset(&mut self, _height: u64) {}

    fn observe_committed_block(
        &mut self,
        header: &ioi_types::app::BlockHeader,
        _collapse: Option<&ioi_types::app::CanonicalCollapseObject>,
    ) -> bool {
        let Some(block_hash) = header
            .hash()
            .ok()
            .and_then(|hash| hash.as_slice().try_into().ok())
        else {
            return false;
        };

        self.latest_parent_qc = Some(QuorumCertificate {
            height: header.height,
            view: header.view,
            block_hash,
            signatures: vec![],
            aggregated_signature: vec![],
            signers_bitfield: vec![],
        });
        true
    }
}

#[cfg(test)]
mod timing_parity_tests {
    use super::*;
    use ioi_api::chain::RemoteStateView;
    use ioi_types::error::ChainError;
    use std::collections::HashMap;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::task::{Context, Poll, Wake, Waker};

    /// Drives a future that never awaits anything pending.
    ///
    /// `decide`'s only awaits are on `StubView`, whose futures are ready on
    /// first poll, so one poll completes it. A `Pending` here means that
    /// assumption stopped holding and the test says so instead of hanging.
    fn poll_once<F: Future>(future: F) -> F::Output {
        struct NoopWake;
        impl Wake for NoopWake {
            fn wake(self: Arc<Self>) {}
        }
        let waker = Waker::from(Arc::new(NoopWake));
        let mut cx = Context::from_waker(&waker);
        let mut future = Box::pin(future);
        match Pin::new(&mut future).poll(&mut cx) {
            Poll::Ready(value) => value,
            Poll::Pending => {
                panic!("solo decide awaited something pending; the stub view is ready")
            }
        }
    }

    /// A parent state view holding exactly the keys a test puts in it, so a
    /// MISSING key is genuinely missing rather than defaulted somewhere.
    struct StubView {
        entries: HashMap<Vec<u8>, Vec<u8>>,
        height: u64,
    }

    impl StubView {
        fn new(height: u64) -> Self {
            Self {
                entries: HashMap::new(),
                height,
            }
        }

        fn with(mut self, key: &[u8], value: Vec<u8>) -> Self {
            self.entries.insert(key.to_vec(), value);
            self
        }

        fn with_timing(self, params: &BlockTimingParams, runtime: &BlockTimingRuntime) -> Self {
            self.with(
                BLOCK_TIMING_PARAMS_KEY,
                codec::to_bytes_canonical(params).expect("encode params"),
            )
            .with(
                BLOCK_TIMING_RUNTIME_KEY,
                codec::to_bytes_canonical(runtime).expect("encode runtime"),
            )
        }

        fn with_status(self, status: &ChainStatus) -> Self {
            self.with(
                STATUS_KEY,
                codec::to_bytes_canonical(status).expect("encode status"),
            )
        }
    }

    #[async_trait]
    impl RemoteStateView for StubView {
        async fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, ChainError> {
            Ok(self.entries.get(key).cloned())
        }
        fn height(&self) -> u64 {
            self.height
        }
        fn state_root(&self) -> &[u8] {
            &[]
        }
    }

    #[async_trait]
    impl AnchoredStateView for StubView {
        async fn gas_used(&self) -> Result<u64, ChainError> {
            Ok(0)
        }
    }

    /// Fixed-interval timing: base = min = max = effective, retarget disabled.
    /// This is the shape the parity fixture pins so a requested cadence IS the
    /// production floor rather than a starting point an adaptive retarget moves.
    fn fixed_interval(interval_ms: u64) -> (BlockTimingParams, BlockTimingRuntime) {
        (
            BlockTimingParams {
                base_interval_ms: interval_ms,
                min_interval_ms: interval_ms,
                max_interval_ms: interval_ms,
                target_gas_per_block: 10_000_000,
                retarget_every_blocks: 0,
                ..Default::default()
            },
            BlockTimingRuntime {
                effective_interval_ms: interval_ms,
                ..Default::default()
            },
        )
    }

    fn status_at_ms(timestamp_ms: u64) -> ChainStatus {
        let mut status = ChainStatus::default();
        status.set_latest_timestamp_ms(timestamp_ms);
        status
    }

    fn decide_at(height: u64, view: &StubView) -> ConsensusDecision<u32> {
        let mut engine = SoloEngine::new();
        poll_once(engine.decide(&AccountId([7u8; 32]), height, 0, view, &HashSet::new()))
    }

    fn produced_timestamp_ms(decision: &ConsensusDecision<u32>) -> u64 {
        match decision {
            ConsensusDecision::ProduceBlock {
                expected_timestamp_ms,
                ..
            } => *expected_timestamp_ms,
            other => panic!("expected ProduceBlock, got {other:?}"),
        }
    }

    #[test]
    fn solo_derives_subsecond_timestamps_from_on_chain_timing_state() {
        // The whole point of the parity repair: at a 50ms on-chain interval Solo
        // must produce parent+50ms. The previous wall-clock rule could not
        // express anything finer than a whole second.
        let (params, runtime) = fixed_interval(50);
        let parent_ms = 1_772_000_000_000;
        let view = StubView::new(5)
            .with_timing(&params, &runtime)
            .with_status(&status_at_ms(parent_ms));

        let produced = produced_timestamp_ms(&decide_at(6, &view));
        assert_eq!(
            produced,
            parent_ms + 50,
            "solo must advance the parent timestamp by the on-chain interval"
        );
        // Not merely sub-second by luck: it is exactly what the SHARED
        // abstraction returns for the same inputs AFT feeds it.
        assert_eq!(
            produced,
            compute_next_timestamp_ms(&params, &runtime, 5, parent_ms, 0).expect("shared timing"),
            "solo must agree with compute_next_timestamp_ms, not merely resemble it"
        );
        assert!(
            produced % 1_000 != 0,
            "a whole-second result would mean the second-quantized rule is still in force"
        );
    }

    #[test]
    fn solo_timestamps_are_state_derived_not_wall_clock() {
        // The mutation this exists to catch: restoring `max(now, parent + 1s)`.
        // A state-derived timestamp is a pure function of the state, so it is
        // reproducible and stays anchored to the parent no matter what the host
        // clock reads.
        let (params, runtime) = fixed_interval(250);
        let parent_ms = 1_000_000;
        let build = || {
            StubView::new(9)
                .with_timing(&params, &runtime)
                .with_status(&status_at_ms(parent_ms))
        };

        let first = produced_timestamp_ms(&decide_at(10, &build()));
        let second = produced_timestamp_ms(&decide_at(10, &build()));
        assert_eq!(
            first, second,
            "the same state must yield the same timestamp"
        );
        assert_eq!(first, parent_ms + 250);

        // A wall-clock rule would land near the epoch-now, which is many orders
        // of magnitude above this deliberately ancient parent.
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock after epoch")
            .as_millis() as u64;
        assert!(
            first < now_ms / 2,
            "timestamp {first} tracks the wall clock ({now_ms}), not the parent state"
        );
    }

    #[test]
    fn solo_scales_with_the_configured_on_chain_interval() {
        // Guards the 50ms case from passing for an accidental reason: the
        // produced spacing must FOLLOW the on-chain interval, not be a constant.
        let parent_ms = 5_000_000;
        for interval_ms in [1, 50, 250, 1_000, 4_000] {
            let (params, runtime) = fixed_interval(interval_ms);
            let view = StubView::new(3)
                .with_timing(&params, &runtime)
                .with_status(&status_at_ms(parent_ms));
            assert_eq!(
                produced_timestamp_ms(&decide_at(4, &view)),
                parent_ms + interval_ms,
                "interval {interval_ms} must be honoured exactly"
            );
        }
    }

    #[test]
    fn solo_refuses_to_produce_without_on_chain_timing_state() {
        // FAIL CLOSED, matching AFT's stall arms. A timestamp not entailed by
        // chain state is one a verifier re-deriving it from that state rejects,
        // so substituting a wall clock here would manufacture an unverifiable
        // block rather than report the missing state.
        let (params, runtime) = fixed_interval(50);
        let status = status_at_ms(1_000_000);

        let missing_params = StubView::new(5)
            .with(
                BLOCK_TIMING_RUNTIME_KEY,
                codec::to_bytes_canonical(&runtime).expect("encode runtime"),
            )
            .with_status(&status);
        assert!(
            matches!(decide_at(6, &missing_params), ConsensusDecision::Stall),
            "absent BlockTimingParams must stall"
        );

        let missing_runtime = StubView::new(5)
            .with(
                BLOCK_TIMING_PARAMS_KEY,
                codec::to_bytes_canonical(&params).expect("encode params"),
            )
            .with_status(&status);
        assert!(
            matches!(decide_at(6, &missing_runtime), ConsensusDecision::Stall),
            "absent BlockTimingRuntime must stall"
        );

        let missing_status = StubView::new(5).with_timing(&params, &runtime);
        assert!(
            matches!(decide_at(6, &missing_status), ConsensusDecision::Stall),
            "absent ChainStatus above height one must stall"
        );

        // Guards the three negatives from passing vacuously: the complete state
        // still produces.
        let complete = StubView::new(5)
            .with_timing(&params, &runtime)
            .with_status(&status);
        assert!(matches!(
            decide_at(6, &complete),
            ConsensusDecision::ProduceBlock { .. }
        ));
    }

    /// The initial-tip bridge reads PROCESS-WIDE env, so any height-1 test that
    /// does not control it races every other one.
    ///
    /// This is not hypothetical: without the lock,
    /// `the_testing_initial_tip_bridge_is_preserved_for_height_one` leaked its
    /// pinned tip into `height_one_tolerates_an_absent_status_exactly_as_aft_does`
    /// running concurrently, which then saw `1772000000050` instead of `50`.
    /// It reproduced under `--features aft` and hid under other feature sets,
    /// purely on thread scheduling. Every height-1 test therefore states the
    /// value it wants -- including `None` for "absent" -- and holds the lock
    /// while it does.
    static INITIAL_TIP_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn with_initial_tip_ms<R>(pinned_ms: Option<u64>, body: impl FnOnce() -> R) -> R {
        const NAME: &str = "IOI_TESTING_INITIAL_TIP_TIMESTAMP_MS";
        // A panicking sibling poisons the lock but leaves the env recoverable,
        // so the guard is taken either way rather than cascading the failure.
        let _guard = INITIAL_TIP_ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match pinned_ms {
            Some(value) => std::env::set_var(NAME, value.to_string()),
            None => std::env::remove_var(NAME),
        }
        let result = body();
        std::env::remove_var(NAME);
        result
    }

    #[test]
    fn height_one_tolerates_an_absent_status_exactly_as_aft_does() {
        // Genesis may carry no ChainStatus at all. AFT admits that at height 1
        // only; Solo must draw the line in the same place or the two engines
        // bootstrap differently.
        let (params, runtime) = fixed_interval(50);

        with_initial_tip_ms(None, || {
            let genesis = StubView::new(0).with_timing(&params, &runtime);
            // parent_height 0 takes compute_next_timestamp_ms's genesis arm,
            // which uses the BASE interval.
            assert_eq!(
                produced_timestamp_ms(&decide_at(1, &genesis)),
                params.base_interval_ms_or_legacy(),
                "height one with a zero parent timestamp advances by the base interval"
            );
            assert!(
                matches!(decide_at(2, &genesis), ConsensusDecision::Stall),
                "the absent-status tolerance must not extend above height one"
            );
        });
    }

    #[test]
    fn the_testing_initial_tip_bridge_is_preserved_for_height_one() {
        // The fixture bridge AFT carries, kept identical so a composed fixture
        // bootstraps both engines the same way. Height 1 with a zero parent
        // timestamp adopts the pinned tip; the value is read from the explicit
        // testing namespace so production chains never see it.
        let (params, runtime) = fixed_interval(50);
        let pinned_ms = 1_772_000_000_000_u64;
        let produced = with_initial_tip_ms(Some(pinned_ms), || {
            produced_timestamp_ms(&decide_at(
                1,
                &StubView::new(0)
                    .with_timing(&params, &runtime)
                    .with_status(&ChainStatus::default()),
            ))
        });

        assert_eq!(
            produced,
            pinned_ms + params.base_interval_ms_or_legacy(),
            "the pinned tip must anchor height one"
        );
    }
}
