//! Production ordering/finality boundary shared by both runnable profiles.
//!
//! Blocks are first persisted as inert staged material. A staged block may be
//! propagated as an AFT proposal, but it grants no canonical authority. Only a
//! complete profile-specific v3 bundle admitted by the Agentgres profile spine
//! makes the transition canonical. Every externally visible consequence is
//! then redriven from the committed outbox in its registered order.

use agentgres::cutover::{SpineGenesis, WriterClaim};
use agentgres::profile::{FinalityProfile, ProfileBindingsDigest, ProfileIdentity};
use agentgres::recognized_effect::{
    AuthorityRevalidator, AuthoritySnapshot, CommitDisposition, CommitResult, OutboxIntent,
    RecognizedEffectStore,
};
use anyhow::{anyhow, Context, Result};
use ioi_api::chain::BlockExecutionReceipt;
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
use ioi_types::app::{Block, ChainTransaction, KernelEvent, SignatureSuite};
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

pub(crate) struct RuntimeFinalityCoordinator {
    root: PathBuf,
    domain_id: String,
    writer_identity: String,
    issuer_key_id: String,
    signing_key: Ed25519PrivateKey,
    store: RecognizedEffectStore,
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
            let evidence = context
                .consensus_engine_ref
                .lock()
                .await
                .drain_finalized_native_quorums();
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
        deliver_runtime_admission(context, admission).await?;
    }
    Ok(admitted)
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
        deliver_runtime_admission(context, admission).await?;
    }
    Ok(effect_ids)
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
        let mut store = match RecognizedEffectStore::open_existing(&root, domain_id.clone())? {
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
        let active = store
            .spine_state()
            .active()
            .map_err(|error| anyhow!(error.to_string()))?;
        if active.identity.profile != agentgres_profile(configured_profile) {
            return Err(anyhow!(
                "configured runtime profile {} does not match Agentgres-active profile {} at epoch {}",
                configured_profile.certificate_variant(),
                active.identity.certificate_variant,
                active.profile_epoch
            ));
        }
        if active.writer_identity != writer_identity {
            return Err(anyhow!(
                "local runtime writer {} is fenced; Agentgres authorizes {}",
                writer_identity,
                active.writer_identity
            ));
        }
        if active.authority.issuer_key_id != issuer_key_id {
            return Err(anyhow!(
                "local finality issuer {} does not match rooted authority {}",
                issuer_key_id,
                active.authority.issuer_key_id
            ));
        }
        store.bind_writer(WriterClaim::new(
            writer_identity.clone(),
            active.fence_token,
        ))?;
        let coordinator = Self {
            root,
            domain_id,
            writer_identity,
            issuer_key_id,
            signing_key,
            store,
        };
        coordinator.verify_all_staged()?;
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

    pub(crate) fn canonical_head(&self) -> &str {
        self.store.canonical_head()
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
        &self,
        block: Block<ChainTransaction>,
        receipts: Vec<BlockExecutionReceipt>,
    ) -> Result<()> {
        validate_receipts(&block, &receipts)?;
        let mut staged = StagedBlock {
            schema: STAGED_BLOCK_SCHEMA.into(),
            block,
            receipts,
            stage_hash: [0; 32],
        };
        staged.stage_hash = staged_hash(&staged)?;
        let bytes = to_bytes_canonical(&staged).map_err(anyhow::Error::msg)?;
        let path = self.staged_path(&block_hash(&staged.block)?);
        persist_exact_device_flushed(&path, &bytes)
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

    fn verify_all_staged(&self) -> Result<()> {
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
        }
        Ok(())
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
    use ioi_types::app::{AccountId, BlockHeader, QuorumCertificate, StateRoot};
    use tempfile::tempdir;

    fn empty_block(parent: [u8; 32], height: u64) -> Block<ChainTransaction> {
        Block {
            header: BlockHeader {
                height,
                view: height,
                parent_hash: parent,
                parent_state_root: StateRoot(vec![2; 32]),
                state_root: StateRoot(vec![3; 32]),
                transactions_root: ioi_types::app::canonical_transactions_root(&[]).unwrap(),
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
            transactions: Vec::new(),
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
        let coordinator = RuntimeFinalityCoordinator::open(
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
}
