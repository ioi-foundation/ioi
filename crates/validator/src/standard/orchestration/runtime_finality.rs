//! Production ordering/finality boundary shared by both runnable profiles.
//!
//! Blocks are first persisted as inert staged material. A staged block may be
//! propagated as an AFT proposal, but it grants no canonical authority. Only a
//! complete profile-specific v3 bundle admitted by the Agentgres profile spine
//! makes the transition canonical. Every externally visible consequence is
//! then redriven from the committed outbox in its registered order.

use agentgres::cutover::{
    GovernanceEvidence, GovernanceValidator, GovernanceVerdict, ProfileCutoverRequest,
    ProfileFreezeRequest, RollbackKind, RollbackPlan, SpineGenesis, SpineState, WeakeningReview,
    WriterClaim,
};
use agentgres::profile::{
    FinalityProfile, GuaranteeDelta, GuaranteeDirection, ProfileBindingsDigest, ProfileIdentity,
};
use agentgres::recognized_effect::{
    AuthorityRevalidator, AuthoritySnapshot, CommitDisposition, CommitResult, OutboxIntent,
    RecognizedEffectStore,
};
use anyhow::{anyhow, Context, Result};
use ioi_api::chain::{
    block_execution_receipt_journal_key, BlockExecutionReceipt, BlockExecutionReceiptJournal,
};
use ioi_api::commitment::CommitmentScheme;
use ioi_api::consensus::{ConsensusEngine, NativeAftFinalizedEvidence};
use ioi_api::crypto::SerializableKey;
use ioi_api::state::{StateManager, Verifier};
use ioi_crypto::sign::eddsa::Ed25519PrivateKey;
use ioi_finality::{
    emit_runtime_bundle_v3, NativeAftFinalizedBlock, NativeAftMember, RuntimeBundleV3Input,
    RUNTIME_PROFILE_CONTRACT_V1,
};
use ioi_ipc::public::TxStatus;
use ioi_services::wallet_network::{
    AuthorizeFinalityProfileCutoverParamsV1, GovernedFinalityProfileCutoverV1,
    GovernedRollbackKindV1, AUTHORIZE_FINALITY_PROFILE_CUTOVER_METHOD,
};
use ioi_types::app::{Block, ChainTransaction, KernelEvent, SignatureSuite, SystemPayload};
use ioi_types::codec::{from_bytes_canonical, to_bytes_canonical};
use ioi_types::config::RuntimeFinalityProfile;
use parity_scale_codec::{Decode, Encode};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::fmt::Debug;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::context::MainLoopContext;
use super::ingestion::ChainTipInfo;

const STAGED_BLOCK_SCHEMA: &str = "ioi.validator-finality-staged-block.v1";
const INITIAL_FENCE_TOKEN: u64 = 1;

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
struct StagedBlock {
    schema: String,
    block: Block<ChainTransaction>,
    receipts: Vec<BlockExecutionReceipt>,
    stage_hash: [u8; 32],
}

#[derive(Clone, Debug)]
pub(crate) struct RuntimeAdmission {
    pub effect_id: String,
    pub block: Block<ChainTransaction>,
    pub commit: CommitResult,
}

#[derive(Clone)]
struct ExactAuthority(AuthoritySnapshot);

impl AuthorityRevalidator for ExactAuthority {
    fn current_snapshot(&self, _prepared: &AuthoritySnapshot) -> Result<AuthoritySnapshot, String> {
        Ok(self.0.clone())
    }
}

struct ExactGovernance {
    evidence_digest: String,
    approvals: u32,
}

impl GovernanceValidator for ExactGovernance {
    fn validate_weakening(
        &self,
        review: &WeakeningReview<'_>,
    ) -> Result<GovernanceVerdict, String> {
        if review.governance.evidence_digest != self.evidence_digest
            || review.governance.approvals() != self.approvals
            || self.approvals < review.governance.approval_threshold
        {
            return Err("wallet governance evidence/threshold substitution".into());
        }
        Ok(GovernanceVerdict {
            approved: true,
            approvals: self.approvals,
            evidence_digest: self.evidence_digest.clone(),
            detail: "exact Agentgres-admitted wallet authorization".into(),
        })
    }
}

pub(crate) struct RuntimeFinalityCoordinator {
    root: PathBuf,
    domain_id: String,
    local_writer_root: String,
    writer_identity: String,
    issuer_key_id: String,
    signing_key: Ed25519PrivateKey,
    store: RecognizedEffectStore,
    /// Transaction hashes already durably executed into staged blocks.
    ///
    /// A native AFT block is not Agentgres-admissible until its descendant QC
    /// proves finality.  During that interval the transaction must remain in
    /// the mempool (only the admitted outbox may prune it), but it must not be
    /// selected against the advanced workload state a second time.  This set
    /// is rebuilt from device-flushed staged bytes on restart and therefore is
    /// an exclusion fence, not a second source of canonical truth.
    staged_transaction_hashes: BTreeSet<[u8; 32]>,
}

pub(crate) async fn stage_runtime_block<CS, ST, CE, V>(
    context: &MainLoopContext<CS, ST, CE, V>,
    block: Block<ChainTransaction>,
    receipts: Vec<BlockExecutionReceipt>,
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
    <CS as CommitmentScheme>::Proof: serde::Serialize
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
    context
        .runtime_finality
        .lock()
        .await
        .stage_block(block, receipts)
}

pub(crate) async fn admit_available<CS, ST, CE, V>(
    context: &mut MainLoopContext<CS, ST, CE, V>,
    single_authority_block: Option<&Block<ChainTransaction>>,
) -> Result<Vec<String>>
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
    <CS as CommitmentScheme>::Proof: serde::Serialize
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
    let coordinator_ref = Arc::clone(&context.runtime_finality);
    let profile = coordinator_ref.lock().await.active_profile()?;
    let recorded_at_ms = runtime_wall_clock_ms();
    let admissions = match profile {
        RuntimeFinalityProfile::SingleAuthorityV1 => {
            let Some(block) = single_authority_block else {
                return Ok(Vec::new());
            };
            let hash = block_hash(block)?;
            vec![coordinator_ref
                .lock()
                .await
                .admit_single_authority(hash, recorded_at_ms)?]
        }
        RuntimeFinalityProfile::BftConsensusAftV1 => {
            let mut evidence = context
                .consensus_engine_ref
                .lock()
                .await
                .drain_finalized_native_quorums();
            // The Agentgres head is a linear chain. Consensus callbacks can
            // enqueue more than one newly ready commit in one tick, so impose
            // canonical height/view/hash order before crossing the atomic
            // recognized-effect boundary. A missing predecessor still refuses;
            // sorting never manufactures evidence or skips a gap.
            sort_native_aft_evidence(&mut evidence);
            let mut admissions = Vec::with_capacity(evidence.len());
            for proof in evidence {
                admissions.push(
                    coordinator_ref
                        .lock()
                        .await
                        .admit_native_aft(proof, recorded_at_ms)?,
                );
            }
            admissions
        }
    };
    let mut admitted = Vec::with_capacity(admissions.len());
    for admission in admissions {
        admitted.push(admission.effect_id.clone());
        deliver_runtime_admission_with_terminal_policy(context, admission).await?;
    }
    let cutovers = coordinator_ref
        .lock()
        .await
        .apply_due_governed_cutovers(recorded_at_ms)?;
    for cutover_id in cutovers {
        tracing::info!(
            target: "consensus",
            cutover_id = %cutover_id,
            "Wallet-authorized Agentgres profile cutover activated"
        );
    }
    Ok(admitted)
}

fn sort_native_aft_evidence(evidence: &mut [NativeAftFinalizedEvidence]) {
    evidence.sort_by(|left, right| {
        left.quorum_certificate
            .height
            .cmp(&right.quorum_certificate.height)
            .then_with(|| {
                left.quorum_certificate
                    .view
                    .cmp(&right.quorum_certificate.view)
            })
            .then_with(|| {
                left.quorum_certificate
                    .block_hash
                    .cmp(&right.quorum_certificate.block_hash)
            })
    });
}

/// Redrive committed consequences after restart. Prepared/staged material is
/// never considered: only effects already rooted in the Agentgres spine are
/// eligible.
pub(crate) async fn redrive_pending<CS, ST, CE, V>(
    context: &mut MainLoopContext<CS, ST, CE, V>,
) -> Result<Vec<String>>
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
    <CS as CommitmentScheme>::Proof: serde::Serialize
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
    let coordinator_ref = Arc::clone(&context.runtime_finality);
    let effect_ids = coordinator_ref.lock().await.recovered_pending_effects()?;
    for effect_id in &effect_ids {
        let admission = coordinator_ref.lock().await.recover_admission(effect_id)?;
        deliver_runtime_admission_with_terminal_policy(context, admission).await?;
    }
    coordinator_ref
        .lock()
        .await
        .apply_due_governed_cutovers(runtime_wall_clock_ms())?;
    Ok(effect_ids)
}

/// Reconstruct staging for workload blocks whose atomic execution commit won
/// the crash race but whose receipts never reached the validator process.
/// Receipt bytes are accepted only from the state-rooted per-height journal;
/// an RPC retry or a re-execution is never used to invent the lost result.
pub(crate) async fn recover_workload_gap<CS, ST, CE, V>(
    context: &mut MainLoopContext<CS, ST, CE, V>,
) -> Result<Vec<u64>>
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
    <CS as CommitmentScheme>::Proof: serde::Serialize
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
    let admitted_height = context
        .last_committed_block
        .as_ref()
        .map(|block| block.header.height)
        .unwrap_or(0);
    let workload = context.view_resolver.workload_client().clone();
    let workload_height = workload.get_status().await?.height;
    if workload_height < admitted_height {
        return Err(anyhow!(
            "workload height {workload_height} is behind Agentgres-admitted height {admitted_height}"
        ));
    }
    let mut recovered = Vec::new();
    for height in admitted_height.saturating_add(1)..=workload_height {
        let block = workload
            .get_block_by_height(height)
            .await?
            .ok_or_else(|| anyhow!("workload receipt recovery is missing block {height}"))?;
        let journal_bytes = workload
            .query_raw_state(&block_execution_receipt_journal_key(height))
            .await?
            .ok_or_else(|| {
                anyhow!("workload receipt recovery is missing rooted journal {height}")
            })?;
        let journal: BlockExecutionReceiptJournal =
            from_bytes_canonical(&journal_bytes).map_err(anyhow::Error::msg)?;
        journal
            .validate_against(&block)
            .map_err(|error| anyhow!(error.to_string()))?;
        stage_runtime_block(context, block.clone(), journal.receipts).await?;
        context.last_executed_block = Some(block.clone());

        if context.runtime_finality.lock().await.active_profile()?
            == RuntimeFinalityProfile::BftConsensusAftV1
        {
            let observed = super::aft_collapse::observe_live_committed_chain_through_block(
                &context.consensus_engine_ref,
                context.config.consensus_type,
                workload.as_ref(),
                &block,
            )
            .await?;
            if !observed {
                return Err(anyhow!(
                    "consensus refused recovered committed block {height}"
                ));
            }
        }
        admit_available(context, Some(&block)).await?;
        recovered.push(height);
    }
    Ok(recovered)
}

async fn deliver_runtime_admission<CS, ST, CE, V>(
    context: &mut MainLoopContext<CS, ST, CE, V>,
    admission: RuntimeAdmission,
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
    <CS as CommitmentScheme>::Proof: serde::Serialize
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
    let coordinator_ref = Arc::clone(&context.runtime_finality);
    let intents = coordinator_ref
        .lock()
        .await
        .pending_outbox(&admission.effect_id)?;
    let durable_commit_ms = runtime_wall_clock_ms();
    let mut published_hashes = None;
    for intent in intents {
        match intent.kind.as_str() {
            "projection_materialization" => coordinator_ref
                .lock()
                .await
                .materialize_projection(&admission.effect_id)?,
            "root_publication" => publish_root(context, &admission.block).await,
            "committed_status_publication" => {
                if let Some(delay) = ioi_types::app::bench_planted_delay::planted_delay_for(
                    ioi_types::app::bench_planted_delay::PlantedPhase::DurableAckPublication,
                )? {
                    tokio::time::sleep(delay).await;
                }
                published_hashes = Some(
                    publish_statuses(
                        &context.receipt_map,
                        &context.tx_status_cache,
                        &admission.block,
                    )
                    .await,
                );
            }
            "transaction_committed" => {
                let hashes = match published_hashes.as_ref() {
                    Some(hashes) => hashes.clone(),
                    None => client_visible_hashes(&context.receipt_map, &admission.block).await,
                };
                let published_at_ms = runtime_wall_clock_ms().max(durable_commit_ms);
                for tx_hash in hashes {
                    let _ = context
                        .event_broadcaster
                        .send(KernelEvent::TransactionCommitted {
                            tx_hash,
                            height: admission.block.header.height,
                            durable_commit_ms,
                            published_at_ms,
                        });
                }
            }
            "ack_publication" => {
                super::gossip::prune_mempool(context.tx_pool_ref.as_ref(), &admission.block)?;
            }
            other => {
                return Err(anyhow!(
                    "unknown runtime finality outbox consequence {other}"
                ))
            }
        }
        coordinator_ref
            .lock()
            .await
            .record_delivery(&admission.effect_id, &intent)?;
    }
    tracing::info!(
        target: "consensus",
        effect_id = %admission.effect_id,
        height = admission.block.header.height,
        disposition = ?admission.commit.disposition,
        "Agentgres-admitted runtime finality effect published"
    );
    Ok(())
}

/// A committed effect whose ordered consequences cannot be recovered is a
/// terminal runtime failure, not permission to keep accepting new effects.
/// Execute an exact cutover's pre-authorized freeze policy when one exists;
/// successor-only rollback plans remain active for an explicit governed
/// transition and the original delivery error is still returned.
async fn deliver_runtime_admission_with_terminal_policy<CS, ST, CE, V>(
    context: &mut MainLoopContext<CS, ST, CE, V>,
    admission: RuntimeAdmission,
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
    <CS as CommitmentScheme>::Proof: serde::Serialize
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
    let coordinator_ref = Arc::clone(&context.runtime_finality);
    if let Err(delivery_error) = deliver_runtime_admission(context, admission).await {
        let freeze = coordinator_ref
            .lock()
            .await
            .freeze_active_if_declared("runtime-outbox-terminal-failure", runtime_wall_clock_ms());
        return match freeze {
            Ok(true) => Err(delivery_error.context(
                "runtime finality outbox failed terminally; declared rollback froze admission",
            )),
            Ok(false) => Err(delivery_error),
            Err(freeze_error) => Err(anyhow!(
                "runtime finality outbox failed: {delivery_error:#}; declared freeze also failed: {freeze_error:#}"
            )),
        };
    }
    Ok(())
}

async fn publish_root<CS, ST, CE, V>(
    context: &mut MainLoopContext<CS, ST, CE, V>,
    block: &Block<ChainTransaction>,
) where
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
    <CS as CommitmentScheme>::Proof: serde::Serialize
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
    let previous_height = context
        .last_committed_block
        .as_ref()
        .map(|previous| previous.header.height)
        .unwrap_or(0);
    if block.header.height >= previous_height {
        context.last_committed_block = Some(block.clone());
    }
    {
        let mut chain = context.chain_ref.lock().await;
        let status = chain.status_mut();
        if block.header.height > status.height {
            status.total_transactions = status
                .total_transactions
                .saturating_add(block.transactions.len() as u64);
        }
        status.height = status.height.max(block.header.height);
        if status.height == block.header.height {
            status.latest_timestamp = block.header.timestamp;
        }
    }
    let _ = context.tip_sender.send(ChainTipInfo {
        height: block.header.height,
        timestamp: block.header.timestamp,
        timestamp_ms: block.header.timestamp_ms_or_legacy(),
        gas_used: block.header.gas_used,
        state_root: block.header.state_root.0.clone(),
        genesis_root: context.genesis_root.clone(),
        validator_set: block.header.validator_set.clone(),
    });
}

async fn publish_statuses(
    receipt_map: &Arc<tokio::sync::Mutex<lru::LruCache<ioi_types::app::TxHash, String>>>,
    tx_status_cache: &Arc<tokio::sync::Mutex<lru::LruCache<String, super::context::TxStatusEntry>>>,
    block: &Block<ChainTransaction>,
) -> Vec<String> {
    let hashes = client_visible_hashes(receipt_map, block).await;
    let mut statuses = tx_status_cache.lock().await;
    for tx_hash in &hashes {
        if let Some(entry) = statuses.get_mut(tx_hash) {
            entry.status = TxStatus::Committed;
            entry.block_height = Some(block.header.height);
        } else {
            statuses.put(
                tx_hash.clone(),
                super::context::TxStatusEntry {
                    status: TxStatus::Committed,
                    error: None,
                    block_height: Some(block.header.height),
                },
            );
        }
    }
    hashes
}

async fn client_visible_hashes(
    receipt_map: &Arc<tokio::sync::Mutex<lru::LruCache<ioi_types::app::TxHash, String>>>,
    block: &Block<ChainTransaction>,
) -> Vec<String> {
    let receipts = receipt_map.lock().await;
    block
        .transactions
        .iter()
        .filter_map(|transaction| transaction.hash().ok())
        .map(|hash| {
            receipts
                .peek(&hash)
                .cloned()
                .unwrap_or_else(|| hex::encode(hash))
        })
        .collect()
}

fn runtime_wall_clock_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}

impl RuntimeFinalityCoordinator {
    pub(crate) fn open(
        root: PathBuf,
        domain_id: String,
        configured_profile: RuntimeFinalityProfile,
        writer_identity: String,
        initial_canonical_head: String,
        issuer_key_id: String,
        signing_seed: &[u8],
    ) -> Result<Self> {
        let signing_key = Ed25519PrivateKey::from_bytes(signing_seed)
            .context("invalid runtime finality Ed25519 signing seed")?;
        fs::create_dir_all(root.join("staged"))?;
        let bindings = production_bindings()?;
        let authority = AuthoritySnapshot {
            domain_id: domain_id.clone(),
            authority_epoch: 1,
            revocation_epoch: 0,
            issuer_key_id: issuer_key_id.clone(),
            admission_permitted: true,
        };
        let existing = RecognizedEffectStore::open_existing(&root, domain_id.clone())?;
        let mut store = match existing {
            Some(store) => store,
            None => RecognizedEffectStore::open(
                &root,
                domain_id.clone(),
                SpineGenesis {
                    identity: profile_identity(configured_profile)?,
                    writer_identity: writer_identity.clone(),
                    fence_token: INITIAL_FENCE_TOKEN,
                    initial_canonical_head,
                    bindings,
                    authority,
                },
            )?,
        };
        let (runtime_writer, rooted_issuer, writer_claim) = match store.spine_state() {
            SpineState::Active(active) => (
                active.writer_identity.clone(),
                active.authority.issuer_key_id.clone(),
                Some(WriterClaim::new(
                    active.writer_identity.clone(),
                    active.fence_token,
                )),
            ),
            SpineState::Frozen(frozen) => (
                frozen.retired_writer_identity.clone(),
                frozen.authority.issuer_key_id.clone(),
                None,
            ),
        };
        if !local_writer_matches(&writer_identity, &runtime_writer) {
            return Err(anyhow!(
                "local runtime writer root {} does not own Agentgres-rooted writer namespace {}",
                writer_identity,
                runtime_writer
            ));
        }
        if rooted_issuer != issuer_key_id {
            return Err(anyhow!(
                "local finality issuer {} does not match rooted authority {}",
                issuer_key_id,
                rooted_issuer
            ));
        }
        if let Some(claim) = writer_claim {
            store.bind_writer(claim)?;
        }
        let mut coordinator = Self {
            root,
            domain_id,
            local_writer_root: writer_identity,
            writer_identity: runtime_writer,
            issuer_key_id,
            signing_key,
            store,
            staged_transaction_hashes: BTreeSet::new(),
        };
        coordinator.staged_transaction_hashes = coordinator.verify_all_staged()?;
        Ok(coordinator)
    }

    pub(crate) fn active_profile(&self) -> Result<RuntimeFinalityProfile> {
        let active = self
            .store
            .spine_state()
            .active()
            .map_err(|error| anyhow!(error.to_string()))?;
        runtime_profile(active.identity.profile)
    }

    /// Recovers the last Agentgres-admitted block from the exact staged bytes
    /// named by the rooted canonical head. The genesis head intentionally has
    /// no staged envelope and therefore returns `None`.
    pub(crate) fn last_admitted_block(&self) -> Result<Option<Block<ChainTransaction>>> {
        let Some(encoded) = self.store.canonical_head().strip_prefix("sha256:") else {
            return Err(anyhow!("Agentgres canonical head is not sha256-prefixed"));
        };
        let bytes = hex::decode(encoded).context("Agentgres canonical head is not hexadecimal")?;
        let hash: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("Agentgres canonical head is not 32 bytes"))?;
        let path = self.staged_path(&hash);
        if !path.exists() {
            return Ok(None);
        }
        Ok(Some(self.read_staged(&hash)?.block))
    }

    pub(crate) fn stage_block(
        &mut self,
        block: Block<ChainTransaction>,
        receipts: Vec<BlockExecutionReceipt>,
    ) -> Result<()> {
        validate_receipts(&block, &receipts)?;
        let transaction_hashes = block
            .transactions
            .iter()
            .map(ChainTransaction::hash)
            .collect::<Result<Vec<_>, _>>()?;
        let mut staged = StagedBlock {
            schema: STAGED_BLOCK_SCHEMA.into(),
            block,
            receipts,
            stage_hash: [0; 32],
        };
        staged.stage_hash = staged_hash(&staged)?;
        let bytes = to_bytes_canonical(&staged).map_err(anyhow::Error::msg)?;
        let path = self.staged_path(&block_hash(&staged.block)?);
        persist_exact_device_flushed(&path, &bytes)?;
        self.staged_transaction_hashes.extend(transaction_hashes);
        Ok(())
    }

    /// Returns the restart-recovered exclusion fence for proposal selection.
    /// Hashes leave the mempool only through an Agentgres-admitted ACK; keeping
    /// old staged hashes here is harmless because transaction hashes are exact
    /// byte identities and must never be executed twice.
    pub(crate) fn staged_transaction_hashes(&self) -> BTreeSet<[u8; 32]> {
        self.staged_transaction_hashes.clone()
    }

    pub(crate) fn admit_single_authority(
        &mut self,
        block_hash: [u8; 32],
        recorded_at_ms: u64,
    ) -> Result<RuntimeAdmission> {
        if self.active_profile()? != RuntimeFinalityProfile::SingleAuthorityV1 {
            return Err(anyhow!(
                "single-authority admission requested under a different active profile"
            ));
        }
        self.admit_staged(block_hash, None, recorded_at_ms)
    }

    pub(crate) fn admit_native_aft(
        &mut self,
        evidence: NativeAftFinalizedEvidence,
        recorded_at_ms: u64,
    ) -> Result<RuntimeAdmission> {
        if self.active_profile()? != RuntimeFinalityProfile::BftConsensusAftV1 {
            return Err(anyhow!(
                "native AFT evidence arrived under a different active profile"
            ));
        }
        validate_native_evidence(&evidence)?;
        let hash = evidence.quorum_certificate.block_hash;
        let staged = self.read_staged(&hash)?;
        let native = native_finalized_block(&self.domain_id, &staged.block, evidence)?;
        self.admit_material(staged, Some(native), recorded_at_ms)
    }

    pub(crate) fn pending_outbox(&self, effect_id: &str) -> Result<Vec<OutboxIntent>> {
        Ok(self.store.pending_outbox(effect_id)?)
    }

    pub(crate) fn recovered_pending_effects(&self) -> Result<Vec<String>> {
        let mut pending = Vec::new();
        for effect in self.store.committed_effects_in_order() {
            if !self
                .store
                .pending_outbox(&effect.record.effect_id)?
                .is_empty()
            {
                pending.push(effect.record.effect_id.clone());
            }
        }
        Ok(pending)
    }

    pub(crate) fn recover_admission(&self, effect_id: &str) -> Result<RuntimeAdmission> {
        let committed = self
            .store
            .committed(effect_id)
            .ok_or_else(|| anyhow!("unknown committed runtime effect {effect_id}"))?
            .clone();
        let head = committed
            .record
            .bundle
            .pointer("/checkpoint/resulting_canonical_head")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("committed runtime effect lost resulting canonical head"))?;
        let encoded = head
            .strip_prefix("sha256:")
            .ok_or_else(|| anyhow!("committed runtime effect head is not sha256-prefixed"))?;
        let bytes =
            hex::decode(encoded).context("committed runtime effect head is not hexadecimal")?;
        let hash: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("committed runtime effect head is not 32 bytes"))?;
        let staged = self.read_staged(&hash)?;
        Ok(RuntimeAdmission {
            effect_id: effect_id.to_owned(),
            block: staged.block,
            commit: CommitResult {
                disposition: CommitDisposition::Replayed,
                effect: committed,
            },
        })
    }

    /// Admit every due wallet-authorized cutover whose authorization
    /// transaction is already a rooted recognized effect. Early authorization
    /// remains inert and is deterministically rediscovered from Agentgres on
    /// every later admission/restart; no side file grants authority.
    pub(crate) fn apply_due_governed_cutovers(
        &mut self,
        recorded_at_ms: u64,
    ) -> Result<Vec<String>> {
        let committed_effects = self
            .store
            .committed_effects_in_order()
            .into_iter()
            .cloned()
            .collect::<Vec<_>>();
        let current_height = self
            .last_admitted_block()?
            .map(|block| block.header.height)
            .unwrap_or(0);
        let mut applied = Vec::new();
        for effect in committed_effects {
            let head = effect
                .record
                .bundle
                .pointer("/checkpoint/resulting_canonical_head")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("committed runtime effect lost resulting head"))?;
            let hash = parse_hash_label(head)?;
            let staged = self.read_staged(&hash)?;
            for (index, transaction) in staged.block.transactions.iter().enumerate() {
                let Some(operation) = governed_cutover_operation(transaction)? else {
                    continue;
                };
                if let Some(existing) = self.store.committed_cutover(&operation.cutover_id) {
                    let operation_ref = format!("sha256:{}", hex::encode(operation.operation_hash));
                    if existing.record.authorization_operation_ref != operation_ref
                        || existing.record.authorization_effect_ref != effect.record.effect_id
                        || existing.record.authorization_effect_agentgres_head
                            != effect.agentgres_head
                    {
                        return Err(anyhow!(
                            "duplicate cutover id is bound to different authorization bytes"
                        ));
                    }
                    continue;
                }
                operation
                    .verify_shape()
                    .map_err(|error| anyhow!(error.to_string()))?;
                if staged.receipts.get(index).is_none() {
                    return Err(anyhow!(
                        "governed cutover authorization lacks its individual execution receipt"
                    ));
                }
                if recorded_at_ms < operation.activation_not_before_ms
                    || current_height < operation.activation_checkpoint_height
                {
                    continue;
                }
                self.apply_governed_cutover(&effect, &staged.block, &operation, recorded_at_ms)?;
                applied.push(operation.cutover_id);
            }
        }
        Ok(applied)
    }

    fn apply_governed_cutover(
        &mut self,
        authorization_effect: &agentgres::recognized_effect::CommittedRecognizedEffect,
        authorization_block: &Block<ChainTransaction>,
        operation: &GovernedFinalityProfileCutoverV1,
        recorded_at_ms: u64,
    ) -> Result<()> {
        let active = self
            .store
            .spine_state()
            .active()
            .map_err(|error| anyhow!(error.to_string()))?
            .clone();
        let authorization_prior_head = format!(
            "sha256:{}",
            hex::encode(authorization_block.header.parent_hash)
        );
        let bindings = [
            ("domain", operation.domain_id == self.domain_id),
            (
                "from_profile",
                operation.expected_from_profile == active.identity.profile.profile(),
            ),
            (
                "profile_contract_version",
                operation.expected_from_profile_contract_version
                    == active.identity.profile_contract_version,
            ),
            (
                "from_writer",
                operation.expected_from_writer_identity == active.writer_identity,
            ),
            (
                "profile_epoch",
                operation.expected_from_profile_epoch == active.profile_epoch,
            ),
            (
                "fence_token",
                operation.expected_from_fence_token == active.fence_token,
            ),
            (
                "prior_canonical_head",
                operation.expected_prior_canonical_head == authorization_prior_head,
            ),
            (
                "authority_epoch",
                operation.authority_epoch == active.authority.authority_epoch,
            ),
            (
                "revocation_epoch",
                operation.revocation_epoch == active.authority.revocation_epoch,
            ),
            (
                "authorization_effect_profile",
                authorization_effect.record.profile == operation.expected_from_profile,
            ),
            (
                "authorization_effect_profile_epoch",
                authorization_effect.record.profile_epoch == operation.expected_from_profile_epoch,
            ),
            (
                "authorization_effect_writer",
                authorization_effect.record.writer_identity
                    == operation.expected_from_writer_identity,
            ),
            (
                "authorization_effect_fence",
                authorization_effect.record.fence_token == operation.expected_from_fence_token,
            ),
        ];
        if let Some((coordinate, _)) = bindings.into_iter().find(|(_, valid)| !valid) {
            return Err(anyhow!(
                "wallet cutover authorization does not bind active Agentgres coordinate {coordinate}"
            ));
        }
        if !local_writer_matches(&self.local_writer_root, &operation.to_writer_identity) {
            return Err(anyhow!(
                "wallet cutover targets a writer this runtime process cannot own"
            ));
        }
        if operation.to_profile_contract_version != RUNTIME_PROFILE_CONTRACT_V1 {
            return Err(anyhow!(
                "wallet cutover names an unsupported profile contract"
            ));
        }
        let target = FinalityProfile::resolve_label(&operation.to_profile)?;
        let direction = active
            .identity
            .profile
            .direction_to(target)
            .ok_or_else(|| anyhow!("wallet cutover is a no-op"))?;
        let guarantee_delta = runtime_guarantee_delta(direction);
        let authority_refs = governed_authority_refs(authorization_block, operation)?;
        let evidence_digest = hash_json(&json!({
            "schema_version": "ioi.agentgres-wallet-cutover-evidence.v1",
            "operation_hash": hex::encode(operation.operation_hash),
            "authorization_effect_id": authorization_effect.record.effect_id,
            "authorization_agentgres_head": authorization_effect.agentgres_head,
            "authorization_agentgres_batch_sequence": authorization_effect.agentgres_batch_sequence,
            "authorization_block_hash": hex::encode(block_hash(authorization_block)?),
            "authority_refs": authority_refs,
        }))?;
        let (anchor_batch_seq, anchor_root) = self.store.governance_anchor();
        let guarantee_delta_digest = agentgres::cutover::guarantee_delta_digest(&guarantee_delta)
            .map_err(|error| anyhow!(error.to_string()))?;
        let governance = (direction == GuaranteeDirection::Weakening).then(|| GovernanceEvidence {
            governance_id: format!(
                "wallet-governance://{}",
                hex::encode(operation.operation_hash)
            ),
            evidence_digest: evidence_digest.clone(),
            approval_threshold: operation.approval_threshold,
            authorization_refs: authority_refs.clone(),
            effective_after_ms: operation.activation_not_before_ms,
            anchor_batch_seq,
            anchor_root,
            guarantee_delta_digest,
        });
        let rollback = runtime_rollback_plan(operation)?;
        let authority_owner = ExactAuthority(active.authority.clone());
        let governance_owner = ExactGovernance {
            evidence_digest,
            approvals: u32::try_from(authority_refs.len()).unwrap_or(u32::MAX),
        };
        let request = ProfileCutoverRequest {
            cutover_id: operation.cutover_id.clone(),
            to_profile: operation.to_profile.clone(),
            to_profile_contract_version: operation.to_profile_contract_version.clone(),
            to_writer_identity: operation.to_writer_identity.clone(),
            to_fence_token: operation.to_fence_token,
            authorization_operation_ref: format!(
                "sha256:{}",
                hex::encode(operation.operation_hash)
            ),
            authorization_effect_ref: authorization_effect.record.effect_id.clone(),
            authorization_effect_agentgres_head: authorization_effect.agentgres_head.clone(),
            authorization_refs: authority_refs,
            activation_not_before_ms: operation.activation_not_before_ms,
            activation_checkpoint_height: operation.activation_checkpoint_height,
            authority: active.authority,
            bindings: production_bindings()?,
            guarantee_delta,
            governance,
            rollback,
        };
        let prepared = self.store.prepare_cutover(
            request,
            &authority_owner,
            &governance_owner,
            recorded_at_ms,
        )?;
        let committed = self.store.commit_cutover(
            prepared,
            &authority_owner,
            &governance_owner,
            recorded_at_ms,
        )?;
        self.store.bind_writer(WriterClaim::new(
            committed.record.to_writer_identity.clone(),
            committed.record.to_fence_token,
        ))?;
        self.writer_identity = committed.record.to_writer_identity;
        Ok(())
    }

    /// Execute the freeze rollback pre-authorized by a committed cutover.
    ///
    /// This is deliberately not caller-shaped: the executor identity and
    /// authorization references come only from the rooted cutover record, and
    /// it is available only while that exact cutover still owns the active
    /// epoch. Effects already admitted by the new profile remain in history.
    pub(crate) fn freeze_active_from_declared_rollback(
        &mut self,
        cutover_id: &str,
        reason: &str,
        recorded_at_ms: u64,
    ) -> Result<()> {
        let committed = self
            .store
            .committed_cutover(cutover_id)
            .ok_or_else(|| anyhow!("unknown committed cutover rollback declaration"))?
            .clone();
        if committed.record.rollback.kind != RollbackKind::Freeze {
            return Err(anyhow!(
                "committed cutover declares successor rollback, not freeze"
            ));
        }
        let active = self
            .store
            .spine_state()
            .active()
            .map_err(|error| anyhow!(error.to_string()))?
            .clone();
        if active.installed_by.as_deref() != Some(cutover_id)
            || active.writer_identity != committed.record.to_writer_identity
            || active.profile_epoch != committed.record.to_profile_epoch
            || active.fence_token != committed.record.to_fence_token
        {
            return Err(anyhow!(
                "declared freeze cannot target a successor or substituted active epoch"
            ));
        }
        if !local_writer_matches(
            &self.local_writer_root,
            &committed.record.rollback.executor_writer_identity,
        ) {
            return Err(anyhow!(
                "declared freeze executor is outside this runtime writer namespace"
            ));
        }
        let authority_owner = ExactAuthority(active.authority.clone());
        self.store.freeze(
            ProfileFreezeRequest {
                freeze_id: format!("{cutover_id}/declared-freeze"),
                authority: active.authority,
                reason: reason.to_owned(),
                authorization_refs: committed.record.rollback.executor_authorization_refs,
            },
            &authority_owner,
            recorded_at_ms,
        )?;
        Ok(())
    }

    fn freeze_active_if_declared(&mut self, reason: &str, recorded_at_ms: u64) -> Result<bool> {
        let cutover_id = match self.store.spine_state() {
            SpineState::Frozen(_) => return Ok(false),
            SpineState::Active(active) => match &active.installed_by {
                Some(cutover_id) => cutover_id.clone(),
                None => return Ok(false),
            },
        };
        let rollback_kind = self
            .store
            .committed_cutover(&cutover_id)
            .ok_or_else(|| anyhow!("active profile names an unknown installing cutover"))?
            .record
            .rollback
            .kind;
        if rollback_kind != RollbackKind::Freeze {
            return Ok(false);
        }
        self.freeze_active_from_declared_rollback(&cutover_id, reason, recorded_at_ms)?;
        Ok(true)
    }

    pub(crate) fn materialize_projection(&mut self, effect_id: &str) -> Result<()> {
        self.store.materialize_projection(effect_id)?;
        Ok(())
    }

    pub(crate) fn record_delivery(&mut self, effect_id: &str, intent: &OutboxIntent) -> Result<()> {
        self.store
            .record_delivery(effect_id, &intent.consequence_id, &intent.payload)?;
        Ok(())
    }

    fn admit_staged(
        &mut self,
        hash: [u8; 32],
        native: Option<NativeAftFinalizedBlock>,
        recorded_at_ms: u64,
    ) -> Result<RuntimeAdmission> {
        let staged = self.read_staged(&hash)?;
        self.admit_material(staged, native, recorded_at_ms)
    }

    fn admit_material(
        &mut self,
        staged: StagedBlock,
        native: Option<NativeAftFinalizedBlock>,
        recorded_at_ms: u64,
    ) -> Result<RuntimeAdmission> {
        let active = self
            .store
            .spine_state()
            .active()
            .map_err(|error| anyhow!(error.to_string()))?
            .clone();
        if active.writer_identity != self.writer_identity {
            return Err(anyhow!(
                "runtime writer was fenced before finality admission"
            ));
        }
        let authority_owner = ExactAuthority(active.authority.clone());
        let profile = runtime_profile(active.identity.profile)?;
        match (profile, native.as_ref()) {
            (RuntimeFinalityProfile::BftConsensusAftV1, None) => {
                return Err(anyhow!("AFT admission has no finalized native quorum"))
            }
            (RuntimeFinalityProfile::SingleAuthorityV1, Some(_)) => {
                return Err(anyhow!(
                    "single-authority admission carried peer quorum evidence"
                ))
            }
            _ => {}
        }
        let hash = block_hash(&staged.block)?;
        let suffix = hex::encode(hash);
        let (operation_first, receipt_first, previous_ref, previous_hash) =
            next_material_coordinates(&self.store)?;
        let location = self.staged_path(&hash).display().to_string();
        let bundle = emit_runtime_bundle_v3(
            RuntimeBundleV3Input {
                bundle_id: &format!("proof://ioi/runtime/{suffix}"),
                checkpoint_id: &format!("receipt-checkpoint://ioi/runtime/{suffix}"),
                certificate_id: &format!("finality-certificate://ioi/runtime/{suffix}"),
                availability_manifest_id: &format!("availability-manifest://ioi/runtime/{suffix}"),
                block_payload_ref: &format!("payload://ioi/runtime/block/{suffix}"),
                domain_id: &self.domain_id,
                authority_epoch: active.authority.authority_epoch,
                authority_revocation_epoch: active.authority.revocation_epoch,
                profile,
                profile_epoch: active.profile_epoch,
                writer_identity: &active.writer_identity,
                fence_token: active.fence_token,
                operation_sequence_first: operation_first,
                receipt_sequence_first: receipt_first,
                previous_checkpoint_ref: previous_ref.as_deref(),
                previous_checkpoint_hash: previous_hash.as_deref(),
                authority_policy_root: &active.bindings.policy_digest,
                governance_policy_root: &active.bindings.governance_policy_digest,
                availability_policy_root: &active.bindings.availability_policy_digest,
                retention_policy_root: &active.bindings.retention_policy_digest,
                location_ref: &location,
                failure_domain_ref: &format!("failure-domain://ioi/local/{}", self.domain_id),
                verifier_contract_hash: &active.bindings.verifier_contract_digest,
                issuer_key_id: &self.issuer_key_id,
                block: &staged.block,
                receipts: &staged.receipts,
                native_aft: native.as_ref(),
            },
            &self.signing_key,
        )?;
        let effect_id = format!("runtime-effect-{suffix}");
        let outbox = build_outbox(&effect_id, &staged.block, &bundle)?;
        let prepared = self.store.prepare_runtime_bundle(
            effect_id.clone(),
            bundle,
            active.authority,
            &authority_owner,
            outbox,
        )?;
        let commit = self
            .store
            .commit(prepared, &authority_owner, recorded_at_ms)?;
        Ok(RuntimeAdmission {
            effect_id,
            block: staged.block,
            commit,
        })
    }

    fn staged_path(&self, hash: &[u8; 32]) -> PathBuf {
        self.root
            .join("staged")
            .join(format!("{}.scale", hex::encode(hash)))
    }

    fn read_staged(&self, hash: &[u8; 32]) -> Result<StagedBlock> {
        let path = self.staged_path(hash);
        let bytes = fs::read(&path)
            .with_context(|| format!("missing staged finality block {}", path.display()))?;
        let staged: StagedBlock = from_bytes_canonical(&bytes).map_err(anyhow::Error::msg)?;
        validate_staged(&staged)?;
        if block_hash(&staged.block)? != *hash {
            return Err(anyhow!("staged block filename/hash substitution"));
        }
        Ok(staged)
    }

    fn verify_all_staged(&self) -> Result<BTreeSet<[u8; 32]>> {
        let mut transaction_hashes = BTreeSet::new();
        for entry in fs::read_dir(self.root.join("staged"))? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|value| value.to_str()) != Some("scale") {
                continue;
            }
            let bytes = fs::read(&path)?;
            let staged: StagedBlock = from_bytes_canonical(&bytes).map_err(anyhow::Error::msg)?;
            validate_staged(&staged)
                .with_context(|| format!("invalid staged finality bytes at {}", path.display()))?;
            if path != self.staged_path(&block_hash(&staged.block)?) {
                return Err(anyhow!(
                    "staged finality filename does not bind its block hash"
                ));
            }
            for transaction in &staged.block.transactions {
                transaction_hashes.insert(transaction.hash()?);
            }
        }
        Ok(transaction_hashes)
    }
}

fn agentgres_profile(profile: RuntimeFinalityProfile) -> FinalityProfile {
    match profile {
        RuntimeFinalityProfile::BftConsensusAftV1 => FinalityProfile::BftConsensus,
        RuntimeFinalityProfile::SingleAuthorityV1 => FinalityProfile::SingleAuthority,
    }
}

fn runtime_profile(profile: FinalityProfile) -> Result<RuntimeFinalityProfile> {
    match profile {
        FinalityProfile::BftConsensus => Ok(RuntimeFinalityProfile::BftConsensusAftV1),
        FinalityProfile::SingleAuthority => Ok(RuntimeFinalityProfile::SingleAuthorityV1),
    }
}

fn profile_identity(profile: RuntimeFinalityProfile) -> Result<ProfileIdentity> {
    Ok(ProfileIdentity::new(
        agentgres_profile(profile),
        RUNTIME_PROFILE_CONTRACT_V1,
    )?)
}

fn hash_label(bytes: &[u8]) -> Result<String> {
    Ok(format!(
        "sha256:{}",
        hex::encode(ioi_crypto::algorithms::hash::sha256(bytes)?)
    ))
}

fn production_bindings() -> Result<ProfileBindingsDigest> {
    Ok(ProfileBindingsDigest {
        policy_digest: hash_label(b"ioi.wallet-network.runtime-finality-authority-policy.v1")?,
        verifier_contract_digest: hash_label(b"ioi.runtime-receipt-proof-verifier.v3")?,
        availability_policy_digest: hash_label(b"ioi.agentgres.local-device-availability.v1")?,
        retention_policy_digest: hash_label(b"ioi.agentgres.runtime-block-retention.v1")?,
        governance_policy_digest: hash_label(b"ioi.profile-cutover.inv42-governance.v1")?,
    })
}

fn local_writer_matches(root: &str, candidate: &str) -> bool {
    candidate == root
        || candidate
            .strip_prefix(root)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn parse_hash_label(value: &str) -> Result<[u8; 32]> {
    let encoded = value
        .strip_prefix("sha256:")
        .ok_or_else(|| anyhow!("hash is not sha256-prefixed"))?;
    let bytes = hex::decode(encoded).context("hash is not hexadecimal")?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("hash is not 32 bytes"))
}

fn hash_json(value: &Value) -> Result<String> {
    let bytes = serde_jcs::to_vec(value)?;
    Ok(format!(
        "sha256:{}",
        hex::encode(ioi_crypto::algorithms::hash::sha256(&bytes)?)
    ))
}

fn governed_cutover_operation(
    transaction: &ChainTransaction,
) -> Result<Option<GovernedFinalityProfileCutoverV1>> {
    let ChainTransaction::System(system) = transaction else {
        return Ok(None);
    };
    let SystemPayload::CallService {
        service_id,
        method,
        params,
    } = &system.payload;
    if service_id != "wallet_network" || method != AUTHORIZE_FINALITY_PROFILE_CUTOVER_METHOD {
        return Ok(None);
    }
    let request: AuthorizeFinalityProfileCutoverParamsV1 =
        from_bytes_canonical(params).map_err(anyhow::Error::msg)?;
    Ok(Some(request.operation))
}

fn governed_authority_refs(
    block: &Block<ChainTransaction>,
    operation: &GovernedFinalityProfileCutoverV1,
) -> Result<Vec<String>> {
    for transaction in &block.transactions {
        let ChainTransaction::System(system) = transaction else {
            continue;
        };
        let SystemPayload::CallService {
            service_id,
            method,
            params,
        } = &system.payload;
        if service_id != "wallet_network" || method != AUTHORIZE_FINALITY_PROFILE_CUTOVER_METHOD {
            continue;
        }
        let request: AuthorizeFinalityProfileCutoverParamsV1 =
            from_bytes_canonical(params).map_err(anyhow::Error::msg)?;
        if request.operation.operation_hash != operation.operation_hash {
            continue;
        }
        let refs = request
            .approvals
            .iter()
            .map(|approval| {
                format!(
                    "wallet-approval-authority://{}",
                    hex::encode(
                        approval
                            .expected_principal_authority
                            .approval_authority
                            .authority_id
                    )
                )
            })
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        if refs.len() < operation.approval_threshold as usize {
            return Err(anyhow!(
                "wallet cutover distinct-authority threshold is unmet"
            ));
        }
        return Ok(refs);
    }
    Err(anyhow!(
        "wallet cutover authorization transaction disappeared"
    ))
}

fn runtime_guarantee_delta(direction: GuaranteeDirection) -> GuaranteeDelta {
    let quorum_guarantees = vec![
        "authenticated_peer_quorum_ordering".into(),
        "one_byzantine_fault_tolerance_under_partial_synchrony".into(),
    ];
    let retained = vec![
        "agentgres_atomic_recognized_effect".into(),
        "durable_individual_receipts".into(),
        "availability_and_offline_verifier_binding".into(),
    ];
    match direction {
        GuaranteeDirection::Weakening => GuaranteeDelta {
            direction,
            lost_guarantees: quorum_guarantees,
            retained_guarantees: retained,
            gained_guarantees: Vec::new(),
        },
        GuaranteeDirection::Strengthening => GuaranteeDelta {
            direction,
            lost_guarantees: Vec::new(),
            retained_guarantees: retained,
            gained_guarantees: quorum_guarantees,
        },
    }
}

fn runtime_rollback_plan(operation: &GovernedFinalityProfileCutoverV1) -> Result<RollbackPlan> {
    let (kind, target) = match operation.rollback_kind {
        GovernedRollbackKindV1::SuccessorCutover => {
            let label = operation
                .rollback_target_profile
                .as_deref()
                .ok_or_else(|| anyhow!("successor rollback has no target profile"))?;
            (
                RollbackKind::SuccessorCutover,
                Some(ProfileIdentity::new(
                    FinalityProfile::resolve_label(label)?,
                    RUNTIME_PROFILE_CONTRACT_V1,
                )?),
            )
        }
        GovernedRollbackKindV1::Freeze => (RollbackKind::Freeze, None),
    };
    Ok(RollbackPlan {
        kind,
        executor_writer_identity: operation.rollback_executor_writer_identity.clone(),
        executor_authorization_refs: operation.rollback_authorization_refs.clone(),
        target,
        independent_of_new_authority: true,
    })
}

fn block_hash(block: &Block<ChainTransaction>) -> Result<[u8; 32]> {
    block
        .header
        .hash()
        .map_err(|error| anyhow!(error.to_string()))?
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("block header hash is not 32 bytes"))
}

pub(crate) fn canonical_block_head(block: &Block<ChainTransaction>) -> Result<String> {
    Ok(format!("sha256:{}", hex::encode(block_hash(block)?)))
}

/// Selects the Agentgres canonical head from which runtime admission begins.
///
/// On a fresh chain, height one names the all-zero protocol parent rather than
/// the separately stored genesis-state container. On recovery without an
/// existing Agentgres spine, the durable chain tip is the next effect's exact
/// parent. `RecognizedEffectStore::open_existing` remains authoritative when a
/// spine already exists; this value can only seed a new one.
pub(crate) fn runtime_finality_initial_head(
    durable_tip: Option<&Block<ChainTransaction>>,
) -> Result<String> {
    match durable_tip {
        Some(block) => canonical_block_head(block),
        None => Ok(format!("sha256:{}", hex::encode([0_u8; 32]))),
    }
}

fn validate_receipts(
    block: &Block<ChainTransaction>,
    receipts: &[BlockExecutionReceipt],
) -> Result<()> {
    if receipts.len() != block.transactions.len() {
        return Err(anyhow!(
            "staged block must carry one receipt per transaction"
        ));
    }
    for (index, (transaction, receipt)) in
        block.transactions.iter().zip(receipts.iter()).enumerate()
    {
        if receipt.block_height != block.header.height
            || receipt.transaction_index != index as u64
            || receipt.transaction_hash != transaction.hash()?
        {
            return Err(anyhow!(
                "staged receipt {index} does not bind its transaction"
            ));
        }
    }
    Ok(())
}

fn staged_hash(staged: &StagedBlock) -> Result<[u8; 32]> {
    let mut preimage = staged.clone();
    preimage.stage_hash = [0; 32];
    let bytes = to_bytes_canonical(&preimage).map_err(anyhow::Error::msg)?;
    Ok(ioi_crypto::algorithms::hash::sha256(&bytes)?)
}

fn validate_staged(staged: &StagedBlock) -> Result<()> {
    if staged.schema != STAGED_BLOCK_SCHEMA || staged.stage_hash != staged_hash(staged)? {
        return Err(anyhow!("staged block envelope hash mismatch"));
    }
    validate_receipts(&staged.block, &staged.receipts)
}

fn persist_exact_device_flushed(path: &Path, bytes: &[u8]) -> Result<()> {
    if path.exists() {
        if fs::read(path)? == bytes {
            return Ok(());
        }
        return Err(anyhow!(
            "changed-byte replay for staged block {}",
            path.display()
        ));
    }
    let tmp = path.with_extension("scale.tmp");
    if tmp.exists() {
        if fs::read(&tmp)? != bytes {
            return Err(anyhow!(
                "changed-byte replay for staged temporary block {}",
                tmp.display()
            ));
        }
    } else {
        let mut file = OpenOptions::new().write(true).create_new(true).open(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    File::open(
        path.parent()
            .ok_or_else(|| anyhow!("staged path has no parent"))?,
    )?
    .sync_all()?;
    Ok(())
}

fn validate_native_evidence(evidence: &NativeAftFinalizedEvidence) -> Result<()> {
    if !evidence.bft_consensus_aft_v1_qualified {
        return Err(anyhow!(
            "native quorum is not qualified for bft_consensus_aft_v1"
        ));
    }
    let n = evidence.members.len() as u64;
    let f = evidence.byzantine_fault_tolerance;
    let q = evidence.quorum_threshold;
    if n != evidence.total_voting_members
        || f == 0
        || n < f.saturating_mul(3).saturating_add(1)
        || q < f.saturating_mul(2).saturating_add(1)
        || evidence.distinct_member_signatures_verified != evidence.signers.len() as u64
        || (evidence.signers.len() as u64) < q
        || evidence.membership_effective_from_height > evidence.quorum_certificate.height
    {
        return Err(anyhow!(
            "native AFT n/f/q or authenticated membership mismatch"
        ));
    }
    let members = evidence
        .members
        .iter()
        .map(|member| member.account_id)
        .collect::<BTreeSet<_>>();
    if members.len() != evidence.members.len()
        || evidence
            .members
            .iter()
            .any(|member| member.suite != SignatureSuite::ED25519 || member.public_key.len() != 32)
    {
        return Err(anyhow!("native AFT membership is duplicate or not Ed25519"));
    }
    for signer in &evidence.signers {
        let member = evidence
            .members
            .iter()
            .find(|member| member.account_id == signer.account_id)
            .ok_or_else(|| anyhow!("authenticated signer is outside complete membership"))?;
        let signature = evidence
            .quorum_certificate
            .signatures
            .iter()
            .find(|(account, _)| *account == signer.account_id)
            .map(|(_, signature)| signature)
            .ok_or_else(|| anyhow!("authenticated signer is absent from quorum certificate"))?;
        if member.public_key != signer.public_key || signature != &signer.signature {
            return Err(anyhow!("native AFT signer/key/certificate substitution"));
        }
    }
    Ok(())
}

fn native_finalized_block(
    domain_id: &str,
    block: &Block<ChainTransaction>,
    evidence: NativeAftFinalizedEvidence,
) -> Result<NativeAftFinalizedBlock> {
    let mut members = evidence
        .members
        .iter()
        .map(|member| {
            let public_key: [u8; 32] = member
                .public_key
                .as_slice()
                .try_into()
                .map_err(|_| anyhow!("native AFT member key is not 32 bytes"))?;
            Ok(NativeAftMember {
                member_ref: format!(
                    "node://ioi/{}/{}",
                    domain_id,
                    hex::encode(member.account_id.0)
                ),
                public_key,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    members.sort_by(|left, right| left.member_ref.cmp(&right.member_ref));
    let membership_bytes = serde_jcs::to_vec(&json!({
        "domain_id": domain_id,
        "effective_from_height": evidence.membership_effective_from_height,
        "members": members.iter().map(|member| json!({
            "member_ref": member.member_ref,
            "public_key": hex::encode(member.public_key),
        })).collect::<Vec<_>>(),
    }))?;
    Ok(NativeAftFinalizedBlock {
        block_header_bytes: to_bytes_canonical(&block.header).map_err(anyhow::Error::msg)?,
        quorum_certificate: evidence.quorum_certificate,
        members,
        membership_ref: format!(
            "node-membership://ioi/{}",
            hex::encode(ioi_crypto::algorithms::hash::sha256(&membership_bytes)?)
        ),
        membership_epoch: evidence.membership_effective_from_height,
        consensus_protocol_ref: "protocol://ioi/aft/classic-bft/v1".into(),
        byzantine_fault_tolerance: evidence.byzantine_fault_tolerance,
    })
}

fn next_material_coordinates(
    store: &RecognizedEffectStore,
) -> Result<(u64, u64, Option<String>, Option<String>)> {
    let Some(effect) = store.last_committed_effect() else {
        return Ok((1, 1, None, None));
    };
    let checkpoint = effect
        .record
        .bundle
        .get("checkpoint")
        .ok_or_else(|| anyhow!("committed runtime effect lost checkpoint"))?;
    let operation_last = checkpoint
        .pointer("/operation_range/last")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("committed runtime effect lost operation range"))?;
    let receipt_last = checkpoint
        .pointer("/receipt_range/last")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("committed runtime effect lost receipt range"))?;
    let checkpoint_id = checkpoint
        .get("checkpoint_id")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("committed runtime effect lost checkpoint id"))?;
    let checkpoint_hash = checkpoint
        .get("body_hash")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("committed runtime effect lost checkpoint hash"))?;
    Ok((
        operation_last
            .checked_add(1)
            .ok_or_else(|| anyhow!("operation sequence overflow"))?,
        receipt_last
            .checked_add(1)
            .ok_or_else(|| anyhow!("receipt sequence overflow"))?,
        Some(checkpoint_id.into()),
        Some(checkpoint_hash.into()),
    ))
}

fn build_outbox(
    effect_id: &str,
    block: &Block<ChainTransaction>,
    bundle: &Value,
) -> Result<Vec<OutboxIntent>> {
    let tx_hashes = block
        .transactions
        .iter()
        .map(|transaction| {
            transaction
                .hash()
                .map(hex::encode)
                .map_err(anyhow::Error::from)
        })
        .collect::<Result<Vec<_>>>()?;
    let common = json!({
        "effect_id": effect_id,
        "height": block.header.height,
        "block_hash": hex::encode(block_hash(block)?),
        "transaction_hashes": tx_hashes,
        "checkpoint_id": bundle.pointer("/checkpoint/checkpoint_id"),
        "checkpoint_hash": bundle.pointer("/checkpoint/body_hash"),
        "operation_root": bundle.pointer("/checkpoint/operation_root"),
        "receipt_root": bundle.pointer("/checkpoint/receipt_root"),
    });
    [
        "projection_materialization",
        "root_publication",
        "committed_status_publication",
        "transaction_committed",
        "ack_publication",
    ]
    .into_iter()
    .map(|kind| {
        OutboxIntent::new(
            format!("{kind}-{effect_id}"),
            kind,
            json!({"kind": kind, "effect": common}),
        )
        .map_err(anyhow::Error::from)
    })
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ioi_api::chain::BlockExecutionReceipt;
    use ioi_api::consensus::{NativeAftMembershipMember, NativeAftQuorumSigner};
    use ioi_api::crypto::SigningKey;
    use ioi_services::wallet_network::governed_cutover_approval_request_hash;
    use ioi_services::wallet_network::{
        ConsumeApprovalGrantForEffectV2Params, ExpectedPrincipalAuthorityBinding,
        FINALITY_PROFILE_CUTOVER_SCOPE,
    };
    use ioi_types::app::action::ApprovalAuthority;
    use ioi_types::app::wallet_network::PrincipalAuthorityBindingCoordinates;
    use ioi_types::app::{
        account_id_from_key_material, AccountId, BlockHeader, QuorumCertificate, SignHeader,
        SignatureProof, StateRoot, SystemTransaction,
    };
    use tempfile::tempdir;

    fn empty_block(parent: [u8; 32], height: u64) -> Block<ChainTransaction> {
        block_with_transactions(parent, height, Vec::new())
    }

    fn block_with_transactions(
        parent: [u8; 32],
        height: u64,
        transactions: Vec<ChainTransaction>,
    ) -> Block<ChainTransaction> {
        Block {
            header: BlockHeader {
                height,
                view: height,
                parent_hash: parent,
                parent_state_root: StateRoot(vec![2; 32]),
                state_root: StateRoot(vec![3; 32]),
                transactions_root: ioi_types::app::canonical_transactions_root(&transactions)
                    .unwrap(),
                timestamp: 1_700_000_000 + height,
                timestamp_ms: 1_700_000_000_000 + height,
                gas_used: 0,
                validator_set: vec![vec![5; 32]],
                producer_account_id: AccountId([6; 32]),
                producer_key_suite: SignatureSuite::ED25519,
                producer_pubkey_hash: [7; 32],
                producer_pubkey: vec![8; 32],
                oracle_counter: 0,
                oracle_trace_hash: [0; 32],
                guardian_certificate: None,
                sealed_finality_proof: None,
                canonical_order_certificate: None,
                timeout_certificate: None,
                parent_qc: QuorumCertificate::default(),
                previous_canonical_collapse_commitment_hash: [0; 32],
                canonical_collapse_extension_certificate: None,
                publication_frontier: None,
                signature: Vec::new(),
            },
            transactions,
        }
    }

    fn governed_cutover_transaction(
        mut operation: GovernedFinalityProfileCutoverV1,
        authority_ids: &[[u8; 32]],
    ) -> ChainTransaction {
        operation.operation_hash = operation.compute_operation_hash().unwrap();
        let approvals = authority_ids
            .iter()
            .enumerate()
            .map(|(index, authority_id)| {
                let expected_principal_authority = ExpectedPrincipalAuthorityBinding {
                    principal_ref: format!("principal://test/{index}"),
                    required_scope: FINALITY_PROFILE_CUTOVER_SCOPE.into(),
                    coordinates: PrincipalAuthorityBindingCoordinates {
                        binding_ref: format!("principal-authority-binding://test/{index}"),
                        binding_version: operation.authority_epoch,
                        binding_hash: [80 + index as u8; 32],
                    },
                    approval_authority: ApprovalAuthority {
                        schema_version: 1,
                        authority_id: *authority_id,
                        public_key: vec![100 + index as u8; 32],
                        signature_suite: SignatureSuite::ED25519,
                        expires_at: u64::MAX,
                        revoked: false,
                        scope_allowlist: vec![FINALITY_PROFILE_CUTOVER_SCOPE.into()],
                    },
                    approval_authority_snapshot_hash: [120 + index as u8; 32],
                };
                ConsumeApprovalGrantForEffectV2Params {
                    request_hash: governed_cutover_approval_request_hash(
                        operation.operation_hash,
                        &expected_principal_authority,
                    )
                    .unwrap(),
                    grant_hash: [40 + index as u8; 32],
                    consumption_id: [60 + index as u8; 32],
                    expected_principal_authority,
                    expected_target_label: FINALITY_PROFILE_CUTOVER_SCOPE.into(),
                    expected_max_usages: 1,
                }
            })
            .collect();
        let request = AuthorizeFinalityProfileCutoverParamsV1 {
            operation,
            approvals,
        };
        ChainTransaction::System(Box::new(SystemTransaction {
            header: SignHeader::default(),
            payload: SystemPayload::CallService {
                service_id: "wallet_network".into(),
                method: AUTHORIZE_FINALITY_PROFILE_CUTOVER_METHOD.into(),
                params: to_bytes_canonical(&request).unwrap(),
            },
            signature_proof: SignatureProof::default(),
        }))
    }

    fn cutover_operation(
        cutover_id: &str,
        domain_id: &str,
        from: RuntimeFinalityProfile,
        from_writer: &str,
        from_epoch: u64,
        from_fence: u64,
        prior_head: [u8; 32],
        to: RuntimeFinalityProfile,
        to_writer: &str,
        to_fence: u64,
        activation_ms: u64,
        checkpoint_height: u64,
    ) -> GovernedFinalityProfileCutoverV1 {
        GovernedFinalityProfileCutoverV1 {
            schema_version: 1,
            operation_hash: [0; 32],
            cutover_id: cutover_id.into(),
            domain_id: domain_id.into(),
            expected_from_profile: profile_identity(from).unwrap().profile.profile().into(),
            expected_from_profile_contract_version: RUNTIME_PROFILE_CONTRACT_V1.into(),
            expected_from_writer_identity: from_writer.into(),
            expected_from_profile_epoch: from_epoch,
            expected_from_fence_token: from_fence,
            expected_prior_canonical_head: format!("sha256:{}", hex::encode(prior_head)),
            to_profile: profile_identity(to).unwrap().profile.profile().into(),
            to_profile_contract_version: RUNTIME_PROFILE_CONTRACT_V1.into(),
            to_writer_identity: to_writer.into(),
            to_fence_token: to_fence,
            authority_epoch: 1,
            revocation_epoch: 0,
            approval_threshold: 2,
            activation_not_before_ms: activation_ms,
            activation_checkpoint_height: checkpoint_height,
            rollback_kind: GovernedRollbackKindV1::Freeze,
            rollback_executor_writer_identity: format!("{from_writer}/rollback"),
            rollback_authorization_refs: vec!["wallet-governance://test/rollback".into()],
            rollback_target_profile: None,
        }
    }

    fn native_aft_evidence(block: &mut Block<ChainTransaction>) -> NativeAftFinalizedEvidence {
        let keys = (0_u8..4)
            .map(|index| Ed25519PrivateKey::from_bytes(&[150 + index; 32]).unwrap())
            .collect::<Vec<_>>();
        let members = keys
            .iter()
            .map(|key| {
                let public_key = key.public_key().unwrap().as_bytes().to_vec();
                let account_id = AccountId(
                    account_id_from_key_material(SignatureSuite::ED25519, &public_key).unwrap(),
                );
                NativeAftMembershipMember {
                    account_id,
                    suite: SignatureSuite::ED25519,
                    public_key,
                }
            })
            .collect::<Vec<_>>();
        block.header.validator_set = members
            .iter()
            .map(|member| member.account_id.0.to_vec())
            .collect();
        let hash = block_hash(block).unwrap();
        let message =
            ioi_finality::native_aft_vote_message(block.header.height, block.header.view, &hash)
                .unwrap();
        let signers = keys
            .iter()
            .zip(members.iter())
            .take(3)
            .map(|(key, member)| NativeAftQuorumSigner {
                account_id: member.account_id,
                suite: SignatureSuite::ED25519,
                public_key: member.public_key.clone(),
                signature: key.sign(&message).unwrap().to_bytes().to_vec(),
            })
            .collect::<Vec<_>>();
        NativeAftFinalizedEvidence {
            quorum_certificate: QuorumCertificate {
                height: block.header.height,
                view: block.header.view,
                block_hash: hash,
                signatures: signers
                    .iter()
                    .map(|signer| (signer.account_id, signer.signature.clone()))
                    .collect(),
                aggregated_signature: Vec::new(),
                signers_bitfield: Vec::new(),
            },
            signers,
            members,
            membership_effective_from_height: 1,
            total_voting_members: 4,
            byzantine_fault_tolerance: 1,
            quorum_threshold: 3,
            distinct_member_signatures_verified: 3,
            bft_consensus_aft_v1_qualified: true,
        }
    }

    #[test]
    fn staged_bytes_are_device_flushed_idempotent_and_changed_bytes_refuse() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("block.scale");
        persist_exact_device_flushed(&path, b"one").unwrap();
        persist_exact_device_flushed(&path, b"one").unwrap();
        assert!(persist_exact_device_flushed(&path, b"two").is_err());
    }

    #[test]
    fn empty_staged_block_recovers_and_binds_hash() {
        let dir = tempdir().unwrap();
        let seed = [9_u8; 32];
        let key = Ed25519PrivateKey::from_bytes(&seed).unwrap();
        let issuer = format!(
            "key://test/{}",
            hex::encode(key.public_key().unwrap().as_bytes())
        );
        let block = empty_block([1; 32], 1);
        let initial = format!("sha256:{}", hex::encode(block.header.parent_hash));
        let mut coordinator = RuntimeFinalityCoordinator::open(
            dir.path().to_path_buf(),
            "chain://test/1".into(),
            RuntimeFinalityProfile::SingleAuthorityV1,
            "writer://test/1".into(),
            initial,
            issuer,
            &seed,
        )
        .unwrap();
        coordinator
            .stage_block(block.clone(), Vec::<BlockExecutionReceipt>::new())
            .unwrap();
        let recovered = coordinator
            .read_staged(&block_hash(&block).unwrap())
            .unwrap();
        assert_eq!(recovered.block, block);
    }

    #[test]
    fn fresh_runtime_spine_starts_at_the_first_blocks_protocol_parent() {
        let dir = tempdir().unwrap();
        let seed = [29_u8; 32];
        let key = Ed25519PrivateKey::from_bytes(&seed).unwrap();
        let issuer = format!(
            "key://test/{}",
            hex::encode(key.public_key().unwrap().as_bytes())
        );
        let block = empty_block([0; 32], 1);
        let initial = runtime_finality_initial_head(None).unwrap();
        assert_eq!(initial, format!("sha256:{}", hex::encode([0_u8; 32])));
        let mut coordinator = RuntimeFinalityCoordinator::open(
            dir.path().to_path_buf(),
            "chain://test/fresh".into(),
            RuntimeFinalityProfile::SingleAuthorityV1,
            "writer://test/fresh".into(),
            initial,
            issuer,
            &seed,
        )
        .unwrap();
        let hash = block_hash(&block).unwrap();
        coordinator.stage_block(block, Vec::new()).unwrap();
        coordinator.admit_single_authority(hash, 1).unwrap();
    }

    #[test]
    fn missing_spine_on_nonempty_chain_seeds_the_exact_durable_tip() {
        let block = empty_block([3; 32], 7);
        assert_eq!(
            runtime_finality_initial_head(Some(&block)).unwrap(),
            canonical_block_head(&block).unwrap()
        );
    }

    #[test]
    fn drained_native_finality_is_ordered_before_agentgres_admission() {
        let mut first = empty_block([0; 32], 1);
        let first_evidence = native_aft_evidence(&mut first);
        let mut second = empty_block(block_hash(&first).unwrap(), 2);
        let second_evidence = native_aft_evidence(&mut second);
        let mut drained = vec![second_evidence, first_evidence];

        sort_native_aft_evidence(&mut drained);

        assert_eq!(drained[0].quorum_certificate.height, 1);
        assert_eq!(drained[1].quorum_certificate.height, 2);
    }

    #[test]
    fn staged_transaction_exclusion_fence_recovers_from_durable_bytes() {
        let dir = tempdir().unwrap();
        let seed = [19_u8; 32];
        let key = Ed25519PrivateKey::from_bytes(&seed).unwrap();
        let issuer = format!(
            "key://test/{}",
            hex::encode(key.public_key().unwrap().as_bytes())
        );
        let transaction = ChainTransaction::System(Box::new(SystemTransaction {
            header: SignHeader::default(),
            payload: SystemPayload::CallService {
                service_id: "test".into(),
                method: "staged@v1".into(),
                params: Vec::new(),
            },
            signature_proof: SignatureProof::default(),
        }));
        let transaction_hash = transaction.hash().unwrap();
        let block = block_with_transactions([1; 32], 1, vec![transaction]);
        let receipt = BlockExecutionReceipt::for_success(1, 0, transaction_hash, 0, &[]);
        let initial = format!("sha256:{}", hex::encode(block.header.parent_hash));
        let mut coordinator = RuntimeFinalityCoordinator::open(
            dir.path().to_path_buf(),
            "chain://test/staged-fence".into(),
            RuntimeFinalityProfile::BftConsensusAftV1,
            "writer://test/staged-fence".into(),
            initial.clone(),
            issuer.clone(),
            &seed,
        )
        .unwrap();
        coordinator.stage_block(block, vec![receipt]).unwrap();
        assert!(coordinator
            .staged_transaction_hashes()
            .contains(&transaction_hash));
        drop(coordinator);

        let recovered = RuntimeFinalityCoordinator::open(
            dir.path().to_path_buf(),
            "chain://test/staged-fence".into(),
            RuntimeFinalityProfile::BftConsensusAftV1,
            "writer://test/staged-fence".into(),
            initial,
            issuer,
            &seed,
        )
        .unwrap();
        assert!(recovered
            .staged_transaction_hashes()
            .contains(&transaction_hash));
    }

    #[test]
    fn single_authority_runtime_admission_is_rooted_verified_and_restart_redrivable() {
        let dir = tempdir().unwrap();
        let seed = [10_u8; 32];
        let key = Ed25519PrivateKey::from_bytes(&seed).unwrap();
        let issuer = format!(
            "key://test/{}",
            hex::encode(key.public_key().unwrap().as_bytes())
        );
        let block = empty_block([1; 32], 1);
        let initial = format!("sha256:{}", hex::encode(block.header.parent_hash));
        let mut coordinator = RuntimeFinalityCoordinator::open(
            dir.path().to_path_buf(),
            "chain://test/1".into(),
            RuntimeFinalityProfile::SingleAuthorityV1,
            "writer://test/1".into(),
            initial,
            issuer.clone(),
            &seed,
        )
        .unwrap();
        let hash = block_hash(&block).unwrap();
        coordinator.stage_block(block.clone(), Vec::new()).unwrap();
        let admission = coordinator
            .admit_single_authority(hash, 1_700_000_000_001)
            .unwrap();
        let claim =
            ioi_finality::verify_runtime_bundle_v3(&admission.commit.effect.record.bundle).unwrap();
        assert_eq!(claim.profile, "single_authority");
        assert_eq!(
            claim.resulting_canonical_head,
            canonical_block_head(&block).unwrap()
        );
        assert_eq!(
            coordinator
                .pending_outbox(&admission.effect_id)
                .unwrap()
                .len(),
            5
        );
        drop(coordinator);

        let reopened = RuntimeFinalityCoordinator::open(
            dir.path().to_path_buf(),
            "chain://test/1".into(),
            RuntimeFinalityProfile::SingleAuthorityV1,
            "writer://test/1".into(),
            "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".into(),
            issuer,
            &seed,
        )
        .unwrap();
        assert_eq!(reopened.last_admitted_block().unwrap(), Some(block));
        assert_eq!(
            reopened.recovered_pending_effects().unwrap(),
            vec![admission.effect_id]
        );
    }

    #[test]
    fn rooted_single_to_aft_cutover_delays_fences_and_survives_config_downgrade() {
        let dir = tempdir().unwrap();
        let seed = [11_u8; 32];
        let key = Ed25519PrivateKey::from_bytes(&seed).unwrap();
        let issuer = format!(
            "key://test/{}",
            hex::encode(key.public_key().unwrap().as_bytes())
        );
        let domain = "chain://test/cutover";
        let writer = "writer://test/cutover";
        let next_writer = "writer://test/cutover/profile/aft/epoch/2";
        let parent = [1; 32];
        let operation = cutover_operation(
            "profile-cutover://test/single-to-aft/1",
            domain,
            RuntimeFinalityProfile::SingleAuthorityV1,
            writer,
            0,
            1,
            parent,
            RuntimeFinalityProfile::BftConsensusAftV1,
            next_writer,
            2,
            1_700_000_000_100,
            2,
        );
        let transaction = governed_cutover_transaction(operation, &[[31; 32], [32; 32]]);
        let block = block_with_transactions(parent, 1, vec![transaction.clone()]);
        let receipt = BlockExecutionReceipt::for_success(1, 0, transaction.hash().unwrap(), 0, &[]);
        let initial = format!("sha256:{}", hex::encode(parent));
        let mut coordinator = RuntimeFinalityCoordinator::open(
            dir.path().to_path_buf(),
            domain.into(),
            RuntimeFinalityProfile::SingleAuthorityV1,
            writer.into(),
            initial,
            issuer.clone(),
            &seed,
        )
        .unwrap();
        let hash = block_hash(&block).unwrap();
        coordinator
            .stage_block(block.clone(), vec![receipt])
            .unwrap();
        coordinator.admit_single_authority(hash, 10).unwrap();
        assert!(coordinator
            .apply_due_governed_cutovers(1_700_000_000_099)
            .unwrap()
            .is_empty());
        assert_eq!(
            coordinator.active_profile().unwrap(),
            RuntimeFinalityProfile::SingleAuthorityV1
        );
        let checkpoint = empty_block(hash, 2);
        let checkpoint_hash = block_hash(&checkpoint).unwrap();
        coordinator.stage_block(checkpoint, Vec::new()).unwrap();
        coordinator
            .admit_single_authority(checkpoint_hash, 11)
            .unwrap();
        let mut stale_processes = (0..3)
            .map(|_| {
                RuntimeFinalityCoordinator::open(
                    dir.path().to_path_buf(),
                    domain.into(),
                    RuntimeFinalityProfile::SingleAuthorityV1,
                    writer.into(),
                    format!("sha256:{}", hex::encode(parent)),
                    issuer.clone(),
                    &seed,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        assert_eq!(
            coordinator
                .apply_due_governed_cutovers(1_700_000_000_100)
                .unwrap(),
            vec!["profile-cutover://test/single-to-aft/1"]
        );
        assert_eq!(
            coordinator.active_profile().unwrap(),
            RuntimeFinalityProfile::BftConsensusAftV1
        );

        let mut successor = empty_block(checkpoint_hash, 3);
        let evidence = native_aft_evidence(&mut successor);
        let successor_hash = block_hash(&successor).unwrap();
        coordinator
            .stage_block(successor.clone(), Vec::new())
            .unwrap();
        for (index, stale) in stale_processes.iter_mut().enumerate() {
            let error = stale
                .admit_single_authority(successor_hash, 21 + index as u64)
                .expect_err("a live pre-cutover process must be fenced");
            assert!(
                error.to_string().contains("writer")
                    || error.to_string().contains("profile")
                    || error.to_string().contains("fence"),
                "unexpected stale-process refusal: {error}"
            );
        }
        assert!(coordinator
            .admit_single_authority(successor_hash, 21)
            .unwrap_err()
            .to_string()
            .contains("different active profile"));
        coordinator.admit_native_aft(evidence, 22).unwrap();
        coordinator
            .freeze_active_from_declared_rollback(
                "profile-cutover://test/single-to-aft/1",
                "terminal-qualification-failure",
                23,
            )
            .unwrap();
        let frozen = coordinator.active_profile().unwrap_err();
        assert!(frozen.to_string().contains("frozen"));
        assert!(coordinator
            .admit_native_aft(native_aft_evidence(&mut empty_block(successor_hash, 4)), 24)
            .unwrap_err()
            .to_string()
            .contains("frozen"));
        drop(coordinator);

        let reopened = RuntimeFinalityCoordinator::open(
            dir.path().to_path_buf(),
            domain.into(),
            RuntimeFinalityProfile::SingleAuthorityV1,
            writer.into(),
            "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".into(),
            issuer,
            &seed,
        )
        .unwrap();
        let frozen = reopened.active_profile().unwrap_err();
        assert!(frozen.to_string().contains("frozen"));
        assert_eq!(reopened.last_admitted_block().unwrap(), Some(successor));
    }

    #[test]
    fn governed_aft_to_single_weakening_requires_delay_checkpoint_and_rollback() {
        let dir = tempdir().unwrap();
        let seed = [12_u8; 32];
        let key = Ed25519PrivateKey::from_bytes(&seed).unwrap();
        let issuer = format!(
            "key://test/{}",
            hex::encode(key.public_key().unwrap().as_bytes())
        );
        let domain = "chain://test/inv42";
        let writer = "writer://test/inv42";
        let next_writer = "writer://test/inv42/profile/single/epoch/2";
        let parent = [2; 32];
        let mut operation = cutover_operation(
            "profile-cutover://test/aft-to-single/1",
            domain,
            RuntimeFinalityProfile::BftConsensusAftV1,
            writer,
            0,
            1,
            parent,
            RuntimeFinalityProfile::SingleAuthorityV1,
            next_writer,
            2,
            1_700_000_000_200,
            2,
        );
        operation.rollback_kind = GovernedRollbackKindV1::SuccessorCutover;
        operation.rollback_target_profile = Some("bft_consensus".into());
        let transaction = governed_cutover_transaction(operation, &[[41; 32], [42; 32]]);
        let mut block = block_with_transactions(parent, 1, vec![transaction.clone()]);
        let evidence = native_aft_evidence(&mut block);
        let receipt = BlockExecutionReceipt::for_success(1, 0, transaction.hash().unwrap(), 0, &[]);
        let mut coordinator = RuntimeFinalityCoordinator::open(
            dir.path().to_path_buf(),
            domain.into(),
            RuntimeFinalityProfile::BftConsensusAftV1,
            writer.into(),
            format!("sha256:{}", hex::encode(parent)),
            issuer.clone(),
            &seed,
        )
        .unwrap();
        coordinator
            .stage_block(block.clone(), vec![receipt])
            .unwrap();
        coordinator.admit_native_aft(evidence, 10).unwrap();
        assert!(coordinator
            .apply_due_governed_cutovers(1_700_000_000_199)
            .unwrap()
            .is_empty());
        assert_eq!(
            coordinator.active_profile().unwrap(),
            RuntimeFinalityProfile::BftConsensusAftV1
        );
        let mut checkpoint = empty_block(block_hash(&block).unwrap(), 2);
        let checkpoint_evidence = native_aft_evidence(&mut checkpoint);
        let checkpoint_hash = block_hash(&checkpoint).unwrap();
        coordinator.stage_block(checkpoint, Vec::new()).unwrap();
        coordinator
            .admit_native_aft(checkpoint_evidence, 11)
            .unwrap();
        assert_eq!(
            coordinator
                .apply_due_governed_cutovers(1_700_000_000_200)
                .unwrap(),
            vec!["profile-cutover://test/aft-to-single/1"]
        );
        assert_eq!(
            coordinator.active_profile().unwrap(),
            RuntimeFinalityProfile::SingleAuthorityV1
        );
        let committed = coordinator
            .store
            .committed_cutover("profile-cutover://test/aft-to-single/1")
            .unwrap();
        let governance = committed.record.governance.as_ref().unwrap();
        assert_eq!(governance.approval_threshold, 2);
        assert_eq!(governance.effective_after_ms, 1_700_000_000_200);
        assert_eq!(
            committed.record.rollback.kind,
            RollbackKind::SuccessorCutover
        );
        assert_eq!(
            committed.record.rollback.target.as_ref().unwrap().profile,
            FinalityProfile::BftConsensus
        );

        let next_effect = empty_block(checkpoint_hash, 3);
        let next_effect_hash = block_hash(&next_effect).unwrap();
        coordinator
            .stage_block(next_effect.clone(), Vec::new())
            .unwrap();
        coordinator
            .admit_single_authority(next_effect_hash, 12)
            .unwrap();
        let rollback_writer = "writer://test/inv42/profile/aft/epoch/3";
        let rollback_operation = cutover_operation(
            "profile-cutover://test/aft-to-single/rollback/2",
            domain,
            RuntimeFinalityProfile::SingleAuthorityV1,
            next_writer,
            1,
            2,
            next_effect_hash,
            RuntimeFinalityProfile::BftConsensusAftV1,
            rollback_writer,
            3,
            1_700_000_000_300,
            4,
        );
        let rollback_tx = governed_cutover_transaction(rollback_operation, &[[51; 32], [52; 32]]);
        let rollback_block =
            block_with_transactions(next_effect_hash, 4, vec![rollback_tx.clone()]);
        let rollback_hash = block_hash(&rollback_block).unwrap();
        coordinator
            .stage_block(
                rollback_block,
                vec![BlockExecutionReceipt::for_success(
                    4,
                    0,
                    rollback_tx.hash().unwrap(),
                    0,
                    &[],
                )],
            )
            .unwrap();
        coordinator
            .admit_single_authority(rollback_hash, 13)
            .unwrap();
        assert_eq!(
            coordinator
                .apply_due_governed_cutovers(1_700_000_000_300)
                .unwrap(),
            vec!["profile-cutover://test/aft-to-single/rollback/2"]
        );
        assert_eq!(
            coordinator.active_profile().unwrap(),
            RuntimeFinalityProfile::BftConsensusAftV1
        );
        assert!(coordinator
            .store
            .committed_cutover("profile-cutover://test/aft-to-single/1")
            .is_some());
        assert!(coordinator
            .store
            .committed_cutover("profile-cutover://test/aft-to-single/rollback/2")
            .is_some());
        assert!(coordinator
            .store
            .committed(&format!("runtime-effect-{}", hex::encode(next_effect_hash)))
            .is_some());
        drop(coordinator);

        let reopened = RuntimeFinalityCoordinator::open(
            dir.path().to_path_buf(),
            domain.into(),
            RuntimeFinalityProfile::SingleAuthorityV1,
            writer.into(),
            format!("sha256:{}", hex::encode(parent)),
            issuer,
            &seed,
        )
        .unwrap();
        assert_eq!(
            reopened.active_profile().unwrap(),
            RuntimeFinalityProfile::BftConsensusAftV1
        );
        assert_eq!(reopened.writer_identity, rollback_writer);
    }
}
