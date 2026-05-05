use crate::app::consensus::{
    canonical_collapse_object_hash, CanonicalCollapseKind, CanonicalCollapseObject,
    RecoveryWitnessCertificate,
};
use crate::app::{AccountId, BlockHeader, SignatureProof, SignatureSuite, ValidatorSetV1};
use dcrypt::algorithms::hash::{HashFunction, Sha256 as DcryptSha256};
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// State key prefix for registered guardian committee manifests.
pub const GUARDIAN_REGISTRY_COMMITTEE_PREFIX: &[u8] = b"guardian::committee::";
/// State key prefix for guardian measurement allowlists.
pub const GUARDIAN_REGISTRY_MEASUREMENT_PREFIX: &[u8] = b"guardian::measurement::";
/// State key prefix for anchored guardian transparency checkpoints.
pub const GUARDIAN_REGISTRY_CHECKPOINT_PREFIX: &[u8] = b"guardian::checkpoint::";
/// State key prefix for registered guardian transparency-log descriptors.
pub const GUARDIAN_REGISTRY_LOG_PREFIX: &[u8] = b"guardian::log::";
/// State key prefix for persisted guardian equivocation proofs.
pub const GUARDIAN_REGISTRY_EQUIVOCATION_PREFIX: &[u8] = b"guardian::equivocation::";
/// State key prefix for registered experimental witness committee manifests.
pub const GUARDIAN_REGISTRY_WITNESS_PREFIX: &[u8] = b"guardian::witness::";
/// State key prefix for active witness committee sets by epoch.
pub const GUARDIAN_REGISTRY_WITNESS_SET_PREFIX: &[u8] = b"guardian::witness_set::";
/// State key prefix for deterministic witness assignment seeds by epoch.
pub const GUARDIAN_REGISTRY_WITNESS_SEED_PREFIX: &[u8] = b"guardian::witness_seed::";
/// State key prefix for epoch-scoped asymptote policy.
pub const GUARDIAN_REGISTRY_ASYMPTOTE_POLICY_PREFIX: &[u8] = b"guardian::asymptote_policy::";
/// State key prefix for registered effect-proof verifiers.
pub const GUARDIAN_REGISTRY_EFFECT_VERIFIER_PREFIX: &[u8] = b"guardian::effect_verifier::";
/// State key prefix for recorded sealed-effect nullifiers.
pub const GUARDIAN_REGISTRY_EFFECT_NULLIFIER_PREFIX: &[u8] = b"guardian::effect_nullifier::";
/// State key prefix for recorded sealed-effect envelopes.
pub const GUARDIAN_REGISTRY_SEALED_EFFECT_PREFIX: &[u8] = b"guardian::sealed_effect::";
/// State key prefix for persisted witness fault evidence.
pub const GUARDIAN_REGISTRY_WITNESS_FAULT_PREFIX: &[u8] = b"guardian::witness_fault::";
/// State key prefix mapping validator accounts to their registered guardian committee manifest.
pub const GUARDIAN_REGISTRY_COMMITTEE_ACCOUNT_PREFIX: &[u8] = b"guardian::committee_account::";
/// State key prefix for public asymptote observer transcript commitments.
pub const GUARDIAN_REGISTRY_OBSERVER_TRANSCRIPT_COMMITMENT_PREFIX: &[u8] =
    b"guardian::observer_transcript_commitment::";
/// State key prefix for public asymptote observer transcripts.
pub const GUARDIAN_REGISTRY_OBSERVER_TRANSCRIPT_PREFIX: &[u8] = b"guardian::observer_transcript::";
/// State key prefix for public asymptote observer challenge commitments.
pub const GUARDIAN_REGISTRY_OBSERVER_CHALLENGE_COMMITMENT_PREFIX: &[u8] =
    b"guardian::observer_challenge_commitment::";
/// State key prefix for public asymptote observer challenges.
pub const GUARDIAN_REGISTRY_OBSERVER_CHALLENGE_PREFIX: &[u8] = b"guardian::observer_challenge::";
/// State key prefix for canonical observer close objects.
pub const GUARDIAN_REGISTRY_OBSERVER_CANONICAL_CLOSE_PREFIX: &[u8] =
    b"guardian::observer_canonical_close::";
/// State key prefix for canonical observer abort objects.
pub const GUARDIAN_REGISTRY_OBSERVER_CANONICAL_ABORT_PREFIX: &[u8] =
    b"guardian::observer_canonical_abort::";

/// Builds the canonical state key for a guardian committee manifest hash.
pub fn guardian_registry_committee_key(manifest_hash: &[u8; 32]) -> Vec<u8> {
    [GUARDIAN_REGISTRY_COMMITTEE_PREFIX, manifest_hash.as_ref()].concat()
}

/// Builds the canonical state key for looking up a validator's guardian committee manifest hash.
pub fn guardian_registry_committee_account_key(account_id: &AccountId) -> Vec<u8> {
    [
        GUARDIAN_REGISTRY_COMMITTEE_ACCOUNT_PREFIX,
        account_id.as_ref(),
    ]
    .concat()
}

/// Builds the canonical state key for an experimental witness committee manifest hash.
pub fn guardian_registry_witness_key(manifest_hash: &[u8; 32]) -> Vec<u8> {
    [GUARDIAN_REGISTRY_WITNESS_PREFIX, manifest_hash.as_ref()].concat()
}

/// Builds the canonical state key for the active witness committee set of an epoch.
pub fn guardian_registry_witness_set_key(epoch: u64) -> Vec<u8> {
    [GUARDIAN_REGISTRY_WITNESS_SET_PREFIX, &epoch.to_be_bytes()].concat()
}

/// Builds the canonical state key for the deterministic witness assignment seed of an epoch.
pub fn guardian_registry_witness_seed_key(epoch: u64) -> Vec<u8> {
    [GUARDIAN_REGISTRY_WITNESS_SEED_PREFIX, &epoch.to_be_bytes()].concat()
}

/// Builds the canonical state key for the asymptote policy of an epoch.
pub fn guardian_registry_asymptote_policy_key(epoch: u64) -> Vec<u8> {
    [
        GUARDIAN_REGISTRY_ASYMPTOTE_POLICY_PREFIX,
        &epoch.to_be_bytes(),
    ]
    .concat()
}

/// Builds the canonical state key for a registered effect-proof verifier.
pub fn guardian_registry_effect_verifier_key(verifier_id: &str) -> Vec<u8> {
    [
        GUARDIAN_REGISTRY_EFFECT_VERIFIER_PREFIX,
        verifier_id.as_bytes(),
    ]
    .concat()
}

/// Builds the canonical state key for a sealed-effect nullifier.
pub fn guardian_registry_effect_nullifier_key(nullifier: &[u8; 32]) -> Vec<u8> {
    [
        GUARDIAN_REGISTRY_EFFECT_NULLIFIER_PREFIX,
        nullifier.as_ref(),
    ]
    .concat()
}

/// Builds the canonical state key for a sealed-effect intent hash.
pub fn guardian_registry_sealed_effect_key(intent_hash: &[u8; 32]) -> Vec<u8> {
    [GUARDIAN_REGISTRY_SEALED_EFFECT_PREFIX, intent_hash.as_ref()].concat()
}

/// Builds the canonical state key for witness fault evidence.
pub fn guardian_registry_witness_fault_key(evidence_id: &[u8; 32]) -> Vec<u8> {
    [GUARDIAN_REGISTRY_WITNESS_FAULT_PREFIX, evidence_id.as_ref()].concat()
}

/// Builds the canonical state key for an anchored transparency checkpoint.
pub fn guardian_registry_checkpoint_key(log_id: &str) -> Vec<u8> {
    [GUARDIAN_REGISTRY_CHECKPOINT_PREFIX, log_id.as_bytes()].concat()
}

/// Builds the canonical state key for a registered transparency-log descriptor.
pub fn guardian_registry_log_key(log_id: &str) -> Vec<u8> {
    [GUARDIAN_REGISTRY_LOG_PREFIX, log_id.as_bytes()].concat()
}

/// Builds the canonical state key for a public observer transcript commitment.
pub fn guardian_registry_observer_transcript_commitment_key(
    epoch: u64,
    height: u64,
    view: u64,
) -> Vec<u8> {
    [
        GUARDIAN_REGISTRY_OBSERVER_TRANSCRIPT_COMMITMENT_PREFIX,
        &epoch.to_be_bytes(),
        &height.to_be_bytes(),
        &view.to_be_bytes(),
    ]
    .concat()
}

/// Builds the canonical state key for one public observer transcript.
pub fn guardian_registry_observer_transcript_key(
    epoch: u64,
    height: u64,
    view: u64,
    round: u16,
    observer_account_id: &AccountId,
) -> Vec<u8> {
    [
        GUARDIAN_REGISTRY_OBSERVER_TRANSCRIPT_PREFIX,
        &epoch.to_be_bytes(),
        &height.to_be_bytes(),
        &view.to_be_bytes(),
        &round.to_be_bytes(),
        observer_account_id.as_ref(),
    ]
    .concat()
}

/// Builds the canonical state key for a public observer challenge commitment.
pub fn guardian_registry_observer_challenge_commitment_key(
    epoch: u64,
    height: u64,
    view: u64,
) -> Vec<u8> {
    [
        GUARDIAN_REGISTRY_OBSERVER_CHALLENGE_COMMITMENT_PREFIX,
        &epoch.to_be_bytes(),
        &height.to_be_bytes(),
        &view.to_be_bytes(),
    ]
    .concat()
}

/// Builds the canonical state key for one public observer challenge.
pub fn guardian_registry_observer_challenge_key(
    epoch: u64,
    height: u64,
    view: u64,
    challenge_id: &[u8; 32],
) -> Vec<u8> {
    [
        GUARDIAN_REGISTRY_OBSERVER_CHALLENGE_PREFIX,
        &epoch.to_be_bytes(),
        &height.to_be_bytes(),
        &view.to_be_bytes(),
        challenge_id.as_ref(),
    ]
    .concat()
}

/// Builds the canonical state key for a canonical observer close object.
pub fn guardian_registry_observer_canonical_close_key(
    epoch: u64,
    height: u64,
    view: u64,
) -> Vec<u8> {
    [
        GUARDIAN_REGISTRY_OBSERVER_CANONICAL_CLOSE_PREFIX,
        &epoch.to_be_bytes(),
        &height.to_be_bytes(),
        &view.to_be_bytes(),
    ]
    .concat()
}

/// Builds the canonical state key for a canonical observer abort object.
pub fn guardian_registry_observer_canonical_abort_key(
    epoch: u64,
    height: u64,
    view: u64,
) -> Vec<u8> {
    [
        GUARDIAN_REGISTRY_OBSERVER_CANONICAL_ABORT_PREFIX,
        &epoch.to_be_bytes(),
        &height.to_be_bytes(),
        &view.to_be_bytes(),
    ]
    .concat()
}

/// Deterministically derives the assigned witness committee for a slot.
pub fn derive_guardian_witness_assignment(
    seed: &GuardianWitnessEpochSeed,
    witness_set: &GuardianWitnessSet,
    producer_account_id: AccountId,
    height: u64,
    view: u64,
    reassignment_depth: u8,
) -> Result<GuardianWitnessAssignment, String> {
    if seed.epoch != witness_set.epoch {
        return Err("witness epoch seed and active witness set epoch mismatch".into());
    }
    if witness_set.manifest_hashes.is_empty() {
        return Err("no active witness committees registered for epoch".into());
    }
    if reassignment_depth > seed.max_reassignment_depth {
        return Err(format!(
            "witness reassignment depth {} exceeds configured maximum {}",
            reassignment_depth, seed.max_reassignment_depth
        ));
    }

    let mut material = Vec::with_capacity(32 + 32 + 8 + 8 + 1);
    material.extend_from_slice(&seed.seed);
    material.extend_from_slice(producer_account_id.as_ref());
    material.extend_from_slice(&height.to_be_bytes());
    material.extend_from_slice(&view.to_be_bytes());
    material.push(reassignment_depth);
    let digest = DcryptSha256::digest(&material).map_err(|e| e.to_string())?;
    let slot = u64::from_be_bytes(
        digest[..8]
            .try_into()
            .map_err(|_| "invalid witness-assignment digest".to_string())?,
    );
    let assigned_index = usize::try_from(slot % (witness_set.manifest_hashes.len() as u64))
        .map_err(|_| "witness assignment index conversion failed".to_string())?;

    Ok(GuardianWitnessAssignment {
        epoch: seed.epoch,
        producer_account_id,
        height,
        view,
        reassignment_depth,
        stratum_id: String::new(),
        manifest_hash: witness_set.manifest_hashes[assigned_index],
        checkpoint_interval_blocks: witness_set.checkpoint_interval_blocks,
    })
}

/// Deterministically derives a unique set of witness committees for asymptote sealing.
pub fn derive_guardian_witness_assignments(
    seed: &GuardianWitnessEpochSeed,
    witness_set: &GuardianWitnessSet,
    producer_account_id: AccountId,
    height: u64,
    view: u64,
    reassignment_depth: u8,
    required_confirmations: u16,
) -> Result<Vec<GuardianWitnessAssignment>, String> {
    if required_confirmations == 0 {
        return Err("asymptote sealing requires at least one witness confirmation".into());
    }
    if seed.epoch != witness_set.epoch {
        return Err("witness epoch seed and active witness set epoch mismatch".into());
    }
    if witness_set.manifest_hashes.len() < usize::from(required_confirmations) {
        return Err(format!(
            "active witness set has {} committees but sealing requires {} confirmations",
            witness_set.manifest_hashes.len(),
            required_confirmations
        ));
    }
    if reassignment_depth > seed.max_reassignment_depth {
        return Err(format!(
            "witness reassignment depth {} exceeds configured maximum {}",
            reassignment_depth, seed.max_reassignment_depth
        ));
    }

    let mut ranked = Vec::with_capacity(witness_set.manifest_hashes.len());
    for manifest_hash in &witness_set.manifest_hashes {
        let mut material = Vec::with_capacity(32 + 32 + 8 + 8 + 1 + 32);
        material.extend_from_slice(&seed.seed);
        material.extend_from_slice(producer_account_id.as_ref());
        material.extend_from_slice(&height.to_be_bytes());
        material.extend_from_slice(&view.to_be_bytes());
        material.push(reassignment_depth);
        material.extend_from_slice(manifest_hash);
        let digest = DcryptSha256::digest(&material).map_err(|e| e.to_string())?;
        let mut score = [0u8; 32];
        score.copy_from_slice(&digest);
        ranked.push((score, *manifest_hash));
    }
    ranked.sort_unstable_by(|left, right| left.0.cmp(&right.0).then(left.1.cmp(&right.1)));

    Ok(ranked
        .into_iter()
        .take(usize::from(required_confirmations))
        .map(|(_, manifest_hash)| GuardianWitnessAssignment {
            epoch: seed.epoch,
            producer_account_id,
            height,
            view,
            reassignment_depth,
            stratum_id: String::new(),
            manifest_hash,
            checkpoint_interval_blocks: witness_set.checkpoint_interval_blocks,
        })
        .collect())
}

/// Deterministically derives exactly one witness committee per required certification stratum.
#[allow(clippy::too_many_arguments)]
pub fn derive_guardian_witness_assignments_for_strata(
    seed: &GuardianWitnessEpochSeed,
    witness_set: &GuardianWitnessSet,
    witness_manifests: &[GuardianWitnessCommitteeManifest],
    producer_account_id: AccountId,
    height: u64,
    view: u64,
    reassignment_depth: u8,
    required_strata: &[String],
) -> Result<Vec<GuardianWitnessAssignment>, String> {
    if required_strata.is_empty() {
        return Err("asymptote sealing requires at least one witness stratum".into());
    }
    if seed.epoch != witness_set.epoch {
        return Err("witness epoch seed and active witness set epoch mismatch".into());
    }
    if reassignment_depth > seed.max_reassignment_depth {
        return Err(format!(
            "witness reassignment depth {} exceeds configured maximum {}",
            reassignment_depth, seed.max_reassignment_depth
        ));
    }

    let active_manifest_hashes = witness_set
        .manifest_hashes
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let mut manifests_by_stratum = BTreeMap::<String, Vec<[u8; 32]>>::new();
    for manifest in witness_manifests {
        if manifest.epoch != seed.epoch {
            continue;
        }
        if manifest.stratum_id.trim().is_empty() {
            return Err(format!(
                "witness committee '{}' is missing a certification stratum",
                manifest.committee_id
            ));
        }
        let digest = DcryptSha256::digest(&manifest.encode()).map_err(|e| e.to_string())?;
        let mut manifest_hash = [0u8; 32];
        manifest_hash.copy_from_slice(&digest);
        if active_manifest_hashes.contains(&manifest_hash) {
            manifests_by_stratum
                .entry(manifest.stratum_id.clone())
                .or_default()
                .push(manifest_hash);
        }
    }

    let mut seen_required = BTreeSet::new();
    let mut assignments = Vec::with_capacity(required_strata.len());
    for stratum_id in required_strata {
        if !seen_required.insert(stratum_id.clone()) {
            return Err(format!(
                "asymptote policy contains duplicate required stratum '{}'",
                stratum_id
            ));
        }
        let candidates = manifests_by_stratum.get(stratum_id).ok_or_else(|| {
            format!(
                "active witness set has no committee for required stratum '{}'",
                stratum_id
            )
        })?;
        let mut ranked = Vec::with_capacity(candidates.len());
        for manifest_hash in candidates {
            let mut material = Vec::with_capacity(32 + 32 + 8 + 8 + 1 + stratum_id.len() + 32);
            material.extend_from_slice(&seed.seed);
            material.extend_from_slice(producer_account_id.as_ref());
            material.extend_from_slice(&height.to_be_bytes());
            material.extend_from_slice(&view.to_be_bytes());
            material.push(reassignment_depth);
            material.extend_from_slice(stratum_id.as_bytes());
            material.extend_from_slice(manifest_hash);
            let digest = DcryptSha256::digest(&material).map_err(|e| e.to_string())?;
            let mut score = [0u8; 32];
            score.copy_from_slice(&digest);
            ranked.push((score, *manifest_hash));
        }
        ranked.sort_unstable_by(|left, right| left.0.cmp(&right.0).then(left.1.cmp(&right.1)));
        let (_, manifest_hash) = ranked.into_iter().next().ok_or_else(|| {
            format!(
                "required stratum '{}' has no eligible witnesses",
                stratum_id
            )
        })?;
        assignments.push(GuardianWitnessAssignment {
            epoch: seed.epoch,
            producer_account_id,
            height,
            view,
            reassignment_depth,
            stratum_id: stratum_id.clone(),
            manifest_hash,
            checkpoint_interval_blocks: witness_set.checkpoint_interval_blocks,
        });
    }

    Ok(assignments)
}

/// Deterministically derives equal-authority observer assignments for asymptote veto-collapse.
///
/// Every validator in the active set is equally eligible ex ante. The producer is excluded from
/// the observer pool for its own slot to keep observation external to the proposing authority.
pub fn derive_asymptote_observer_assignments(
    seed: &GuardianWitnessEpochSeed,
    validator_set: &ValidatorSetV1,
    producer_account_id: AccountId,
    height: u64,
    view: u64,
    observer_rounds: u16,
    observer_committee_size: u16,
) -> Result<Vec<AsymptoteObserverAssignment>, String> {
    if observer_rounds == 0 {
        return Err("asymptote observer sampling requires at least one round".into());
    }
    if observer_committee_size == 0 {
        return Err("asymptote observer sampling requires a non-zero committee size".into());
    }

    let eligible = validator_set
        .validators
        .iter()
        .map(|validator| validator.account_id)
        .filter(|account_id| *account_id != producer_account_id)
        .collect::<Vec<_>>();
    let required = usize::from(observer_rounds) * usize::from(observer_committee_size);
    if eligible.len() < required {
        return Err(format!(
            "active validator set has {} eligible observers but asymptote policy requires {}",
            eligible.len(),
            required
        ));
    }

    let mut globally_selected = BTreeSet::new();
    let mut assignments = Vec::with_capacity(required);
    for round in 0..observer_rounds {
        let mut ranked = Vec::with_capacity(eligible.len());
        for observer_account_id in &eligible {
            if globally_selected.contains(observer_account_id) {
                continue;
            }
            let mut material = Vec::with_capacity(32 + 32 + 8 + 8 + 2 + 32);
            material.extend_from_slice(&seed.seed);
            material.extend_from_slice(producer_account_id.as_ref());
            material.extend_from_slice(&height.to_be_bytes());
            material.extend_from_slice(&view.to_be_bytes());
            material.extend_from_slice(&round.to_be_bytes());
            material.extend_from_slice(observer_account_id.as_ref());
            let digest = DcryptSha256::digest(&material).map_err(|e| e.to_string())?;
            let mut score = [0u8; 32];
            score.copy_from_slice(&digest);
            ranked.push((score, *observer_account_id));
        }
        ranked.sort_unstable_by(|left, right| left.0.cmp(&right.0).then(left.1.cmp(&right.1)));
        let selected = ranked
            .into_iter()
            .take(usize::from(observer_committee_size))
            .collect::<Vec<_>>();
        if selected.len() != usize::from(observer_committee_size) {
            return Err(format!(
                "observer round {} could only assign {} observers out of {} required",
                round,
                selected.len(),
                observer_committee_size
            ));
        }
        for (_, observer_account_id) in selected {
            globally_selected.insert(observer_account_id);
            assignments.push(AsymptoteObserverAssignment {
                epoch: seed.epoch,
                producer_account_id,
                height,
                view,
                round,
                observer_account_id,
            });
        }
    }

    Ok(assignments)
}

fn asymptote_key_authority_label(kind: KeyAuthorityKind) -> &'static str {
    match kind {
        KeyAuthorityKind::DevMemory => "dev_memory",
        KeyAuthorityKind::Tpm2 => "tpm2",
        KeyAuthorityKind::Pkcs11 => "pkcs11",
        KeyAuthorityKind::CloudKms => "cloud_kms",
    }
}

#[derive(Default)]
struct ObserverCorrelationCounters {
    provider: BTreeMap<String, u16>,
    region: BTreeMap<String, u16>,
    host_class: BTreeMap<String, u16>,
    key_authority: BTreeMap<String, u16>,
}

#[derive(Default)]
struct ObserverCorrelationLabels {
    provider: BTreeSet<String>,
    region: BTreeSet<String>,
    host_class: BTreeSet<String>,
    key_authority: BTreeSet<String>,
}

fn observer_correlation_labels(manifest: &GuardianCommitteeManifest) -> ObserverCorrelationLabels {
    let mut labels = ObserverCorrelationLabels::default();
    for member in &manifest.members {
        if let Some(provider) = member
            .provider
            .as_ref()
            .filter(|value| !value.trim().is_empty())
        {
            labels.provider.insert(provider.clone());
        }
        if let Some(region) = member
            .region
            .as_ref()
            .filter(|value| !value.trim().is_empty())
        {
            labels.region.insert(region.clone());
        }
        if let Some(host_class) = member
            .host_class
            .as_ref()
            .filter(|value| !value.trim().is_empty())
        {
            labels.host_class.insert(host_class.clone());
        }
        if let Some(kind) = member.key_authority_kind {
            labels
                .key_authority
                .insert(asymptote_key_authority_label(kind).to_string());
        }
    }
    labels
}

fn observer_budget_allows_labels(
    counters: &ObserverCorrelationCounters,
    labels: &ObserverCorrelationLabels,
    budget: &AsymptoteObserverCorrelationBudget,
) -> bool {
    let label_fits = |counts: &BTreeMap<String, u16>, values: &BTreeSet<String>, limit: u16| {
        limit == 0
            || values
                .iter()
                .all(|value| counts.get(value).copied().unwrap_or_default() < limit)
    };
    label_fits(
        &counters.provider,
        &labels.provider,
        budget.max_per_provider,
    ) && label_fits(&counters.region, &labels.region, budget.max_per_region)
        && label_fits(
            &counters.host_class,
            &labels.host_class,
            budget.max_per_host_class,
        )
        && label_fits(
            &counters.key_authority,
            &labels.key_authority,
            budget.max_per_key_authority,
        )
}

fn observe_budget_record_labels(
    counters: &mut ObserverCorrelationCounters,
    labels: &ObserverCorrelationLabels,
) {
    let bump = |counts: &mut BTreeMap<String, u16>, values: &BTreeSet<String>| {
        for value in values {
            *counts.entry(value.clone()).or_default() += 1;
        }
    };
    bump(&mut counters.provider, &labels.provider);
    bump(&mut counters.region, &labels.region);
    bump(&mut counters.host_class, &labels.host_class);
    bump(&mut counters.key_authority, &labels.key_authority);
}

/// Deterministically derives equal-authority observer plan entries with correlation-budgeted
/// sampling over the active validator set.
#[allow(clippy::too_many_arguments)]
pub fn derive_asymptote_observer_plan_entries(
    seed: &GuardianWitnessEpochSeed,
    validator_set: &ValidatorSetV1,
    observer_manifests: &BTreeMap<AccountId, GuardianCommitteeManifest>,
    producer_account_id: AccountId,
    height: u64,
    view: u64,
    observer_rounds: u16,
    observer_committee_size: u16,
    correlation_budget: &AsymptoteObserverCorrelationBudget,
) -> Result<Vec<AsymptoteObserverPlanEntry>, String> {
    if observer_rounds == 0 {
        return Err("asymptote observer sampling requires at least one round".into());
    }
    if observer_committee_size == 0 {
        return Err("asymptote observer sampling requires a non-zero committee size".into());
    }

    let mut eligible = Vec::new();
    for validator in &validator_set.validators {
        if validator.account_id == producer_account_id {
            continue;
        }
        let manifest = observer_manifests
            .get(&validator.account_id)
            .ok_or_else(|| {
                "active validator is missing a registered guardian committee manifest".to_string()
            })?
            .clone();
        eligible.push((validator.account_id, manifest));
    }

    let required = usize::from(observer_rounds) * usize::from(observer_committee_size);
    if eligible.len() < required {
        return Err(format!(
            "active validator set has {} eligible observers but asymptote policy requires {}",
            eligible.len(),
            required
        ));
    }

    let mut globally_selected = BTreeSet::new();
    let mut assignments = Vec::with_capacity(required);
    let mut counters = ObserverCorrelationCounters::default();

    for round in 0..observer_rounds {
        let mut ranked = Vec::with_capacity(eligible.len());
        for (observer_account_id, manifest) in &eligible {
            if globally_selected.contains(observer_account_id) {
                continue;
            }
            let labels = observer_correlation_labels(manifest);
            let mut material = Vec::with_capacity(32 + 32 + 8 + 8 + 2 + 32);
            material.extend_from_slice(&seed.seed);
            material.extend_from_slice(producer_account_id.as_ref());
            material.extend_from_slice(&height.to_be_bytes());
            material.extend_from_slice(&view.to_be_bytes());
            material.extend_from_slice(&round.to_be_bytes());
            material.extend_from_slice(observer_account_id.as_ref());
            let digest = DcryptSha256::digest(&material).map_err(|e| e.to_string())?;
            let mut score = [0u8; 32];
            score.copy_from_slice(&digest);
            ranked.push((score, *observer_account_id, manifest.clone(), labels));
        }
        ranked.sort_unstable_by(|left, right| left.0.cmp(&right.0).then(left.1.cmp(&right.1)));

        let mut round_selected = 0usize;
        for (_, observer_account_id, manifest, labels) in ranked {
            if !observer_budget_allows_labels(&counters, &labels, correlation_budget) {
                continue;
            }
            globally_selected.insert(observer_account_id);
            observe_budget_record_labels(&mut counters, &labels);
            assignments.push(AsymptoteObserverPlanEntry {
                assignment: AsymptoteObserverAssignment {
                    epoch: seed.epoch,
                    producer_account_id,
                    height,
                    view,
                    round,
                    observer_account_id,
                },
                manifest,
            });
            round_selected += 1;
            if round_selected == usize::from(observer_committee_size) {
                break;
            }
        }

        if round_selected != usize::from(observer_committee_size) {
            return Err(format!(
                "observer round {} could only assign {} observers out of {} required under the configured correlation budget",
                round,
                round_selected,
                observer_committee_size
            ));
        }
    }

    Ok(assignments)
}

/// Canonical hash of the deterministic equal-authority observer assignment set for one slot.
pub fn canonical_asymptote_observer_assignments_hash(
    assignments: &[AsymptoteObserverAssignment],
) -> Result<[u8; 32], String> {
    let bytes = parity_scale_codec::Encode::encode(assignments);
    let digest = DcryptSha256::digest(&bytes).map_err(|e| e.to_string())?;
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&digest);
    Ok(hash)
}

/// Canonical hash of one deterministic equal-authority observer assignment.
pub fn canonical_asymptote_observer_assignment_hash(
    assignment: &AsymptoteObserverAssignment,
) -> Result<[u8; 32], String> {
    let bytes = parity_scale_codec::Encode::encode(assignment);
    let digest = DcryptSha256::digest(&bytes).map_err(|e| e.to_string())?;
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&digest);
    Ok(hash)
}

/// Deployment profile for guardianized signing and egress.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
#[serde(rename_all = "snake_case")]
pub enum GuardianProductionMode {
    /// Development profile with permissive local fallbacks.
    Development,
    /// Compatibility profile for staged migrations.
    #[default]
    Compatibility,
    /// Production profile with hardware-backed key authority requirements.
    Production,
}

/// Backend used to resolve a signing or secret authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
#[serde(rename_all = "snake_case")]
pub enum KeyAuthorityKind {
    /// Development-only in-memory secret material.
    #[default]
    DevMemory,
    /// TPM2-backed signing or unseal flow.
    Tpm2,
    /// PKCS#11 / HSM backed flow.
    Pkcs11,
    /// Cloud KMS backed flow.
    CloudKms,
}

/// Resolved authority handle used by guardianized runtimes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
pub struct KeyAuthorityDescriptor {
    /// The backend used for the authority.
    pub kind: KeyAuthorityKind,
    /// Logical key or secret identifier.
    pub key_id: String,
    /// Optional backend endpoint or URI.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// Optional backend-specific metadata.
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
}

/// Declares a single guardian committee member.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
pub struct GuardianCommitteeMember {
    /// Stable member identifier.
    pub member_id: String,
    /// Public key suite used by this member for quorum signatures.
    pub signature_suite: SignatureSuite,
    /// Full public key bytes.
    #[serde(default)]
    pub public_key: Vec<u8>,
    /// Optional routable endpoint for remote committee RPC.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// Optional provider label for diversity checks.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    /// Optional region label for diversity checks.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    /// Optional host class label for diversity checks.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_class: Option<String>,
    /// Optional root authority class expected for this member.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_authority_kind: Option<KeyAuthorityKind>,
}

/// Immutable manifest describing a validator's guardian committee.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
pub struct GuardianCommitteeManifest {
    /// Validator identity this committee protects.
    pub validator_account_id: AccountId,
    /// Committee epoch.
    pub epoch: u64,
    /// Threshold required for a valid certificate.
    pub threshold: u16,
    /// Members participating in the committee.
    #[serde(default)]
    pub members: Vec<GuardianCommitteeMember>,
    /// Measurement profile root accepted for this epoch.
    pub measurement_profile_root: [u8; 32],
    /// Policy hash constraining committee behavior.
    pub policy_hash: [u8; 32],
    /// Transparency log identifier used by this committee.
    #[serde(default)]
    pub transparency_log_id: String,
}

/// On-chain allowlist of accepted runtime measurement roots.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
pub struct GuardianMeasurementProfile {
    /// Stable profile identifier.
    pub profile_id: String,
    /// Measurement roots accepted for this profile.
    #[serde(default)]
    pub allowed_measurement_roots: Vec<[u8; 32]>,
    /// Policy hash associated with the profile.
    pub policy_hash: [u8; 32],
}

/// Signed checkpoint published by the guardian witness log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
pub struct GuardianTransparencyLogDescriptor {
    /// Logical log identifier.
    pub log_id: String,
    /// Signature suite used by the log signer.
    pub signature_suite: SignatureSuite,
    /// Encoded public key bytes for checkpoint verification.
    #[serde(default)]
    pub public_key: Vec<u8>,
}

/// Append-only proof material for a signed transparency-log checkpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
pub struct GuardianLogProof {
    /// Tree size of the base checkpoint used to derive this proof.
    #[serde(default)]
    pub base_tree_size: u64,
    /// Index of the certified entry within the logical tree.
    #[serde(default)]
    pub leaf_index: u64,
    /// Canonical hash of the certified leaf entry.
    pub leaf_hash: [u8; 32],
    /// Ordered leaf hashes needed to recompute the checkpoint root.
    #[serde(default)]
    pub extension_leaf_hashes: Vec<[u8; 32]>,
}

/// Signed checkpoint published by the guardian witness log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
pub struct GuardianLogCheckpoint {
    /// Logical log identifier.
    pub log_id: String,
    /// Tree size at this checkpoint.
    pub tree_size: u64,
    /// Merkle root of the append-only log.
    pub root_hash: [u8; 32],
    /// Millisecond timestamp of checkpoint issuance.
    pub timestamp_ms: u64,
    /// Signature over the checkpoint payload.
    #[serde(default)]
    pub signature: Vec<u8>,
    /// Append-only proof material for this checkpoint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<GuardianLogProof>,
}

/// Immutable manifest describing an external witness committee for research-only nested guardian mode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
pub struct GuardianWitnessCommitteeManifest {
    /// Stable witness committee identifier.
    pub committee_id: String,
    /// Stable certification-domain / stratum identifier this witness committee belongs to.
    #[serde(default)]
    pub stratum_id: String,
    /// Committee epoch.
    pub epoch: u64,
    /// Threshold required for a valid witness certificate.
    pub threshold: u16,
    /// Members participating in the witness committee.
    #[serde(default)]
    pub members: Vec<GuardianCommitteeMember>,
    /// Policy hash constraining witness behavior.
    pub policy_hash: [u8; 32],
    /// Transparency log identifier used by this witness committee.
    #[serde(default)]
    pub transparency_log_id: String,
}

/// Active witness set for a specific epoch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
pub struct GuardianWitnessSet {
    /// Epoch whose witness committees are active.
    pub epoch: u64,
    /// Sorted registered witness manifest hashes active in this epoch.
    #[serde(default)]
    pub manifest_hashes: Vec<[u8; 32]>,
    /// Required checkpoint cadence for witness evidence.
    #[serde(default)]
    pub checkpoint_interval_blocks: u64,
}

/// Deterministic seed used for witness assignment in a specific epoch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
pub struct GuardianWitnessEpochSeed {
    /// Witness-assignment epoch.
    pub epoch: u64,
    /// Seed committed on-chain for deterministic witness assignment.
    pub seed: [u8; 32],
    /// Required checkpoint cadence for witness evidence.
    #[serde(default)]
    pub checkpoint_interval_blocks: u64,
    /// Maximum number of deterministic witness reassignments permitted.
    #[serde(default)]
    pub max_reassignment_depth: u8,
}

/// Deterministically assigned witness committee for a slot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
pub struct GuardianWitnessAssignment {
    /// Assignment epoch.
    pub epoch: u64,
    /// Validator whose slot is being witnessed.
    pub producer_account_id: AccountId,
    /// Block height of the assignment.
    pub height: u64,
    /// Consensus view of the assignment.
    pub view: u64,
    /// Deterministic reassignment depth used to derive the witness committee.
    #[serde(default)]
    pub reassignment_depth: u8,
    /// Certification stratum satisfied by this assignment when sealing under asymptote.
    #[serde(default)]
    pub stratum_id: String,
    /// Assigned witness manifest hash.
    pub manifest_hash: [u8; 32],
    /// Required checkpoint cadence for witness evidence.
    #[serde(default)]
    pub checkpoint_interval_blocks: u64,
}

/// Deterministically sampled equal-authority observer for an asymptote slot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
pub struct AsymptoteObserverAssignment {
    /// Assignment epoch.
    pub epoch: u64,
    /// Validator whose slot is being observed.
    pub producer_account_id: AccountId,
    /// Block height of the observed slot.
    pub height: u64,
    /// Consensus view of the observed slot.
    pub view: u64,
    /// Deterministic observation round.
    #[serde(default)]
    pub round: u16,
    /// Observer validator assigned to this slot and round.
    pub observer_account_id: AccountId,
}

/// Observer assignment plus the registered guardian committee manifest that must certify it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
pub struct AsymptoteObserverPlanEntry {
    /// Deterministic assignment this plan entry satisfies.
    pub assignment: AsymptoteObserverAssignment,
    /// Registered guardian committee manifest for the assigned observer.
    pub manifest: GuardianCommitteeManifest,
}

/// Correlation limits applied when selecting equal-authority asymptote observers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
pub struct AsymptoteObserverCorrelationBudget {
    /// Maximum number of selected observers that may share any single provider label.
    /// Zero disables provider correlation filtering.
    #[serde(default)]
    pub max_per_provider: u16,
    /// Maximum number of selected observers that may share any single region label.
    /// Zero disables region correlation filtering.
    #[serde(default)]
    pub max_per_region: u16,
    /// Maximum number of selected observers that may share any single host-class label.
    /// Zero disables host-class correlation filtering.
    #[serde(default)]
    pub max_per_host_class: u16,
    /// Maximum number of selected observers that may share any single key-authority class.
    /// Zero disables key-authority correlation filtering.
    #[serde(default)]
    pub max_per_key_authority: u16,
}

/// Canonical summary proving the observer sample for an asymptote slot is complete.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
pub struct AsymptoteObserverCloseCertificate {
    /// Observation epoch.
    pub epoch: u64,
    /// Block height of the observed slot.
    pub height: u64,
    /// Consensus view of the observed slot.
    pub view: u64,
    /// Canonical hash of the deterministic observer assignment set.
    pub assignments_hash: [u8; 32],
    /// Number of observer assignments expected by policy.
    #[serde(default)]
    pub expected_assignments: u16,
    /// Number of `ok` observer certificates attached to the proof.
    #[serde(default)]
    pub ok_count: u16,
    /// Number of attached veto proofs.
    #[serde(default)]
    pub veto_count: u16,
}

/// Observer sealing mode for the asymptote equal-authority lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
#[serde(rename_all = "snake_case")]
pub enum AsymptoteObserverSealingMode {
    /// Current sampled close-and-veto flow.
    #[default]
    SampledCloseV1,
    /// Target deterministic flow over public transcripts, public challenges, and a canonical close.
    CanonicalChallengeV1,
}

/// Canonical observer observation request sent to an assigned validator in the deterministic lane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
pub struct AsymptoteObserverObservationRequest {
    /// Observation epoch.
    pub epoch: u64,
    /// Deterministic observer assignment for this request.
    pub assignment: AsymptoteObserverAssignment,
    /// Block hash of the observed slot.
    pub block_hash: [u8; 32],
    /// Guardian committee manifest hash of the observed producer slot certificate.
    pub guardian_manifest_hash: [u8; 32],
    /// Guardian decision hash of the observed slot certificate.
    pub guardian_decision_hash: [u8; 32],
    /// Guardian counter bound into the observed slot certificate.
    pub guardian_counter: u64,
    /// Guardian trace root bound into the observed slot certificate.
    pub guardian_trace_hash: [u8; 32],
    /// Guardian measurement root bound into the observed slot certificate.
    pub guardian_measurement_root: [u8; 32],
    /// Guardian checkpoint root anchoring the observed slot certificate.
    pub guardian_checkpoint_root: [u8; 32],
}

/// Public transcript published for one observer assignment in the deterministic observer lane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
pub struct AsymptoteObserverTranscript {
    /// Canonical observer statement for the assignment.
    pub statement: AsymptoteObserverStatement,
    /// Guardian-backed certificate authenticating the statement.
    pub guardian_certificate: GuardianQuorumCertificate,
}

/// Commitment over the public observer transcript surface for one slot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
pub struct AsymptoteObserverTranscriptCommitment {
    /// Observation epoch.
    pub epoch: u64,
    /// Block height of the observed slot.
    pub height: u64,
    /// Consensus view of the observed slot.
    pub view: u64,
    /// Canonical hash of the deterministic observer assignment set.
    pub assignments_hash: [u8; 32],
    /// Canonical root of the published observer transcripts.
    pub transcripts_root: [u8; 32],
    /// Number of published observer transcripts.
    #[serde(default)]
    pub transcript_count: u16,
}

/// Challenge kind for deterministic observer sealing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
#[serde(rename_all = "snake_case")]
pub enum AsymptoteObserverChallengeKind {
    /// A required observer transcript was not published by close time.
    #[default]
    MissingTranscript,
    /// A published transcript conflicts with the deterministic assignment or slot binding.
    TranscriptMismatch,
    /// A published transcript contains an admissible veto.
    VetoTranscriptPresent,
    /// Conflicting published observer transcripts exist for one assignment.
    ConflictingTranscript,
    /// The canonical close object binds the wrong slot surface.
    InvalidCanonicalClose,
}

/// Public challenge object for deterministic observer sealing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
pub struct AsymptoteObserverChallenge {
    /// Stable challenge identifier.
    pub challenge_id: [u8; 32],
    /// Observation epoch.
    pub epoch: u64,
    /// Block height of the observed slot.
    pub height: u64,
    /// Consensus view of the observed slot.
    pub view: u64,
    /// Kind of challenge being raised.
    #[serde(default)]
    pub kind: AsymptoteObserverChallengeKind,
    /// Challenger account that published the object.
    pub challenger_account_id: AccountId,
    /// Assignment implicated by the challenge, when the challenge is assignment-scoped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assignment: Option<AsymptoteObserverAssignment>,
    /// Offending observation request when the challenge is proving a transcript mismatch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observation_request: Option<AsymptoteObserverObservationRequest>,
    /// Offending published transcript when the challenge is proving a conflicting or vetoed response.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transcript: Option<AsymptoteObserverTranscript>,
    /// Offending canonical close object when the challenge is proving an invalid close path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canonical_close: Option<AsymptoteObserverCanonicalClose>,
    /// Stable digest of the supporting evidence bundle.
    #[serde(default)]
    pub evidence_hash: [u8; 32],
    /// Human-readable operator detail for audit and telemetry.
    #[serde(default)]
    pub details: String,
}

/// Native observer response for the deterministic observer lane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
pub struct AsymptoteObserverObservation {
    /// Published transcript when the request is admissible and the observer signs it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transcript: Option<AsymptoteObserverTranscript>,
    /// Dominant public challenge when the observer rejects the request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub challenge: Option<AsymptoteObserverChallenge>,
}

/// Commitment over the public observer challenge surface for one slot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
pub struct AsymptoteObserverChallengeCommitment {
    /// Observation epoch.
    pub epoch: u64,
    /// Block height of the observed slot.
    pub height: u64,
    /// Consensus view of the observed slot.
    pub view: u64,
    /// Canonical root of the published observer challenges.
    pub challenges_root: [u8; 32],
    /// Number of published observer challenges.
    #[serde(default)]
    pub challenge_count: u16,
}

/// Canonical close object for deterministic observer sealing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
pub struct AsymptoteObserverCanonicalClose {
    /// Observation epoch.
    pub epoch: u64,
    /// Block height of the observed slot.
    pub height: u64,
    /// Consensus view of the observed slot.
    pub view: u64,
    /// Canonical hash of the deterministic observer assignment set.
    pub assignments_hash: [u8; 32],
    /// Canonical root of the observer transcript surface.
    pub transcripts_root: [u8; 32],
    /// Canonical root of the observer challenge surface.
    pub challenges_root: [u8; 32],
    /// Number of transcripts bound into the close.
    #[serde(default)]
    pub transcript_count: u16,
    /// Number of challenges bound into the close.
    #[serde(default)]
    pub challenge_count: u16,
    /// Public close cutoff for challenges against this slot.
    pub challenge_cutoff_timestamp_ms: u64,
}

/// Canonical abort object for deterministic observer sealing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
pub struct AsymptoteObserverCanonicalAbort {
    /// Observation epoch.
    pub epoch: u64,
    /// Block height of the observed slot.
    pub height: u64,
    /// Consensus view of the observed slot.
    pub view: u64,
    /// Canonical hash of the deterministic observer assignment set.
    pub assignments_hash: [u8; 32],
    /// Canonical root of the observer transcript surface.
    pub transcripts_root: [u8; 32],
    /// Canonical root of the observer challenge surface.
    pub challenges_root: [u8; 32],
    /// Number of transcripts bound into the abort object.
    #[serde(default)]
    pub transcript_count: u16,
    /// Number of challenges bound into the abort object.
    #[serde(default)]
    pub challenge_count: u16,
    /// Public cutoff used to decide the abort surface.
    pub challenge_cutoff_timestamp_ms: u64,
}

/// Finality tier requested or returned by aft consensus and effect receipts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
#[serde(rename_all = "snake_case")]
pub enum FinalityTier {
    /// Fast optimistic guardian-backed finality for chain progression.
    #[default]
    BaseFinal,
    /// Stronger sealed finality with witness/log confirmation.
    SealedFinal,
}

/// Deterministic reduction state of a slot's aft evidence set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
#[serde(rename_all = "snake_case")]
pub enum CollapseState {
    /// Not enough admissible evidence has been gathered.
    #[default]
    Pending,
    /// Base guardian-majority finality has been established.
    BaseFinal,
    /// Sealing is actively collecting witness/log evidence.
    Sealing,
    /// An admissible veto proof deterministically aborted the slot's sealed effects.
    Abort,
    /// Sealed finality has been established.
    SealedFinal,
    /// Divergence or missing evidence has triggered a stronger policy level.
    Escalated,
    /// Conflicting admissible evidence invalidated the slot.
    Invalid,
}

/// Cause for escalation in the asymptote sealing plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
#[serde(rename_all = "snake_case")]
pub enum DivergenceSignalKind {
    /// Conflicting guardian-backed evidence was observed.
    #[default]
    ConflictingGuardianCertificate,
    /// Required witness evidence was not produced in time.
    WitnessOmission,
    /// Registry or epoch state did not match the expected slot context.
    StaleRegistry,
    /// Checkpoint freshness or append-only proofs failed policy.
    StaleCheckpoint,
    /// Transparency-log proofs failed verification.
    LogConsistencyFailure,
}

/// Canonical escalation signal bound into asymptote sealing state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
pub struct DivergenceSignal {
    /// Kind of divergence being reported.
    pub kind: DivergenceSignalKind,
    /// Slot height at which the divergence was observed.
    pub height: u64,
    /// Slot view at which the divergence was observed.
    pub view: u64,
    /// Optional stable digest of supporting evidence.
    #[serde(default)]
    pub evidence_hash: [u8; 32],
    /// Human-readable operator detail.
    #[serde(default)]
    pub details: String,
}

/// Epoch-scoped policy controlling the asymptote sealing plane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
pub struct AsymptotePolicy {
    /// Epoch to which this policy applies.
    pub epoch: u64,
    /// Finality tier required for high-risk external effects.
    #[serde(default)]
    pub high_risk_effect_tier: FinalityTier,
    /// Certification strata that must each contribute one deterministic witness committee
    /// for sealed finality on the common path.
    #[serde(default)]
    pub required_witness_strata: Vec<String>,
    /// Certification strata required after escalation is triggered.
    #[serde(default)]
    pub escalation_witness_strata: Vec<String>,
    /// Number of deterministic equal-authority observer rounds used by veto-collapse when enabled.
    #[serde(default)]
    pub observer_rounds: u16,
    /// Number of equal-authority observers sampled per observation round.
    #[serde(default)]
    pub observer_committee_size: u16,
    /// Correlation budget constraining equal-authority observer selection.
    #[serde(default)]
    pub observer_correlation_budget: AsymptoteObserverCorrelationBudget,
    /// Observer-lane sealing mode.
    #[serde(default)]
    pub observer_sealing_mode: AsymptoteObserverSealingMode,
    /// Public challenge window for canonical observer close, in milliseconds.
    #[serde(default)]
    pub observer_challenge_window_ms: u64,
    /// Maximum witness reassignment depth permitted by the sealing plane.
    #[serde(default)]
    pub max_reassignment_depth: u8,
    /// Maximum checkpoint staleness admitted by sealing policy.
    #[serde(default)]
    pub max_checkpoint_staleness_ms: u64,
}

/// Optional constructive recovery payload carried inside a signed witness statement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
pub struct GuardianWitnessRecoveryBinding {
    /// Canonical hash of the exploratory recovery capsule bound to this witnessed slot.
    #[serde(default)]
    pub recovery_capsule_hash: [u8; 32],
    /// Commitment to the coded share this witness committee is certifying for the slot.
    #[serde(default)]
    pub share_commitment_hash: [u8; 32],
}

/// Internal request payload pairing one witness committee with one recovery binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
pub struct GuardianWitnessRecoveryBindingAssignment {
    /// Hash of the witness committee manifest that should sign this recovery binding.
    #[serde(default)]
    pub witness_manifest_hash: [u8; 32],
    /// Recovery binding that committee should carry on its witness statement/certificate.
    #[serde(default)]
    pub recovery_binding: GuardianWitnessRecoveryBinding,
}

/// Statement cross-signed by external witness committees in research-only nested guardian mode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
pub struct GuardianWitnessStatement {
    /// Validator identity whose slot is being witnessed.
    pub producer_account_id: AccountId,
    /// Block height of the witnessed slot.
    pub height: u64,
    /// Consensus view of the witnessed slot.
    pub view: u64,
    /// Guardian committee manifest hash for the witnessed slot certificate.
    pub guardian_manifest_hash: [u8; 32],
    /// Canonical decision hash of the witnessed guardian certificate.
    pub guardian_decision_hash: [u8; 32],
    /// Monotonic guardian counter bound into the witnessed certificate.
    pub guardian_counter: u64,
    /// Guardian trace root bound into the witnessed certificate.
    pub guardian_trace_hash: [u8; 32],
    /// Guardian runtime measurement root bound into the witnessed certificate.
    pub guardian_measurement_root: [u8; 32],
    /// Witness-log checkpoint root anchoring the guardian certificate when available.
    pub guardian_checkpoint_root: [u8; 32],
    /// Optional signed recovery binding for constructive lower-bound variants.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_binding: Option<GuardianWitnessRecoveryBinding>,
}

/// Aggregated witness certificate for research-only nested guardian mode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
pub struct GuardianWitnessCertificate {
    /// Hash of the registered witness committee manifest.
    pub manifest_hash: [u8; 32],
    /// Certification stratum satisfied by this witness certificate.
    #[serde(default)]
    pub stratum_id: String,
    /// Witness committee epoch.
    pub epoch: u64,
    /// Canonical hash of the signed witness statement payload.
    pub statement_hash: [u8; 32],
    /// Bitfield of witness committee members who signed.
    #[serde(default)]
    pub signers_bitfield: Vec<u8>,
    /// Aggregated BLS signature over the witness statement hash.
    #[serde(default)]
    pub aggregated_signature: Vec<u8>,
    /// Deterministic reassignment depth used to derive the assigned witness committee.
    #[serde(default)]
    pub reassignment_depth: u8,
    /// Optional signed recovery binding mirrored from the witness statement for verification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_binding: Option<GuardianWitnessRecoveryBinding>,
    /// Optional witness-log checkpoint anchoring this witness certificate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_checkpoint: Option<GuardianLogCheckpoint>,
}

/// Reconstructs the signed witness statement for a header-certified guardian slot.
pub fn guardian_witness_statement_for_header_with_recovery_binding(
    header: &BlockHeader,
    certificate: &GuardianQuorumCertificate,
    recovery_binding: Option<GuardianWitnessRecoveryBinding>,
) -> GuardianWitnessStatement {
    GuardianWitnessStatement {
        producer_account_id: header.producer_account_id,
        height: header.height,
        view: header.view,
        guardian_manifest_hash: certificate.manifest_hash,
        guardian_decision_hash: certificate.decision_hash,
        guardian_counter: certificate.counter,
        guardian_trace_hash: certificate.trace_hash,
        guardian_measurement_root: certificate.measurement_root,
        guardian_checkpoint_root: certificate
            .log_checkpoint
            .as_ref()
            .map(|checkpoint| checkpoint.root_hash)
            .unwrap_or([0u8; 32]),
        recovery_binding,
    }
}

/// Reconstructs the signed witness statement for the primary header-carried witness pair.
pub fn guardian_witness_statement_for_header(
    header: &BlockHeader,
    certificate: &GuardianQuorumCertificate,
) -> GuardianWitnessStatement {
    guardian_witness_statement_for_header_with_recovery_binding(
        header,
        certificate,
        certificate
            .experimental_witness_certificate
            .as_ref()
            .and_then(|witness_certificate| witness_certificate.recovery_binding.clone()),
    )
}

/// Derives the exploratory recovery witness certificate carried by a signed witness pair.
pub fn derive_recovery_witness_certificate(
    statement: &GuardianWitnessStatement,
    certificate: &GuardianWitnessCertificate,
) -> Result<Option<RecoveryWitnessCertificate>, String> {
    match (
        statement.recovery_binding.as_ref(),
        certificate.recovery_binding.as_ref(),
    ) {
        (None, None) => Ok(None),
        (Some(_), None) | (None, Some(_)) => Err(
            "guardian witness recovery binding must be present on both statement and certificate"
                .into(),
        ),
        (Some(statement_binding), Some(certificate_binding)) => {
            if statement_binding != certificate_binding {
                return Err(
                    "guardian witness recovery binding must match between statement and certificate"
                        .into(),
                );
            }
            if statement.height == 0
                || certificate.epoch == 0
                || certificate.manifest_hash == [0u8; 32]
                || statement_binding.recovery_capsule_hash == [0u8; 32]
                || statement_binding.share_commitment_hash == [0u8; 32]
            {
                return Err(
                    "guardian witness recovery binding must produce a non-zero recovery witness certificate"
                        .into(),
                );
            }
            Ok(Some(RecoveryWitnessCertificate {
                height: statement.height,
                epoch: certificate.epoch,
                witness_manifest_hash: certificate.manifest_hash,
                recovery_capsule_hash: statement_binding.recovery_capsule_hash,
                share_commitment_hash: statement_binding.share_commitment_hash,
            }))
        }
    }
}

/// Derives the exploratory recovery witness certificate bound to a guardian-certified header.
pub fn derive_recovery_witness_certificate_for_header(
    header: &BlockHeader,
    certificate: &GuardianQuorumCertificate,
) -> Result<Option<RecoveryWitnessCertificate>, String> {
    let witness_certificate = match certificate.experimental_witness_certificate.as_ref() {
        Some(witness_certificate) => witness_certificate,
        None => return Ok(None),
    };
    let statement = guardian_witness_statement_for_header(header, certificate);
    derive_recovery_witness_certificate(&statement, witness_certificate)
}

/// Observer verdict for an equal-authority asymptote observation assignment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
#[serde(rename_all = "snake_case")]
pub enum AsymptoteObserverVerdict {
    /// The observer found no objective reason to abort the effect.
    #[default]
    Ok,
    /// The observer found objective evidence that must abort the effect.
    Veto,
}

/// Objective veto reason emitted by equal-authority asymptote observers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
#[serde(rename_all = "snake_case")]
pub enum AsymptoteVetoKind {
    /// Conflicting guardian-backed certificates were observed for the same slot.
    #[default]
    ConflictingGuardianCertificate,
    /// Checkpoint or transparency-log proofs failed verification.
    InvalidCheckpoint,
    /// The block or attached evidence failed policy binding.
    InvalidPolicy,
    /// Epoch or registry state does not match the observed slot.
    InvalidEpoch,
    /// The observed block hash does not match the guardianized slot evidence.
    ConflictingBlockHash,
}

/// Canonical equal-authority observation statement bound into an observer guardian certificate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
pub struct AsymptoteObserverStatement {
    /// Observation epoch.
    pub epoch: u64,
    /// Deterministic observer assignment for this statement.
    pub assignment: AsymptoteObserverAssignment,
    /// Block hash of the observed slot.
    pub block_hash: [u8; 32],
    /// Guardian committee manifest hash of the observed producer slot certificate.
    pub guardian_manifest_hash: [u8; 32],
    /// Guardian decision hash of the observed slot certificate.
    pub guardian_decision_hash: [u8; 32],
    /// Guardian counter bound into the observed slot certificate.
    pub guardian_counter: u64,
    /// Guardian trace root bound into the observed slot certificate.
    pub guardian_trace_hash: [u8; 32],
    /// Guardian measurement root bound into the observed slot certificate.
    pub guardian_measurement_root: [u8; 32],
    /// Guardian checkpoint root anchoring the observed slot certificate.
    pub guardian_checkpoint_root: [u8; 32],
    /// Observer verdict.
    #[serde(default)]
    pub verdict: AsymptoteObserverVerdict,
    /// Optional objective veto classification when the verdict is `Veto`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub veto_kind: Option<AsymptoteVetoKind>,
    /// Stable digest of the supporting evidence bundle for veto or audit replay.
    #[serde(default)]
    pub evidence_hash: [u8; 32],
}

/// Guardian-backed observer certificate emitted by a sampled equal-authority validator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
pub struct AsymptoteObserverCertificate {
    /// Deterministic observer assignment this certificate satisfies.
    pub assignment: AsymptoteObserverAssignment,
    /// Verdict produced by the observer.
    #[serde(default)]
    pub verdict: AsymptoteObserverVerdict,
    /// Optional objective veto classification when the verdict is `Veto`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub veto_kind: Option<AsymptoteVetoKind>,
    /// Stable digest of the supporting evidence bundle for veto or audit replay.
    #[serde(default)]
    pub evidence_hash: [u8; 32],
    /// Guardian committee certificate emitted by the observer's own guardian committee.
    pub guardian_certificate: GuardianQuorumCertificate,
}

/// Self-contained abort proof emitted by an equal-authority observer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
pub struct AsymptoteVetoProof {
    /// Guardian-backed observer certificate that issued the veto.
    pub observer_certificate: AsymptoteObserverCertificate,
    /// Human-readable operator detail for audit and telemetry.
    #[serde(default)]
    pub details: String,
}

/// Witness-fault classification for research-only nested guardian mode.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
#[serde(rename_all = "snake_case")]
pub enum GuardianWitnessFaultKind {
    /// Conflicting witness certificates were issued for the same slot.
    #[default]
    ConflictingCertificate,
    /// An assigned witness failed to issue a certificate before reassignment.
    Omission,
    /// A witness signed using stale registry or epoch state.
    StaleRegistryParticipation,
    /// The witness certificate or checkpoint is inconsistent with the assigned checkpoint policy.
    CheckpointInconsistency,
}

/// Evidence envelope for witness-specific slashing and operator response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
pub struct GuardianWitnessFaultEvidence {
    /// Stable evidence identifier.
    pub evidence_id: [u8; 32],
    /// Type of witnessed fault.
    pub kind: GuardianWitnessFaultKind,
    /// Witness epoch in which the fault occurred.
    pub epoch: u64,
    /// Validator whose slot was impacted.
    pub producer_account_id: AccountId,
    /// Block height of the slot.
    pub height: u64,
    /// Consensus view of the slot.
    pub view: u64,
    /// Witness committee expected for this slot.
    pub expected_manifest_hash: [u8; 32],
    /// Witness committee actually observed, when applicable.
    pub observed_manifest_hash: [u8; 32],
    /// Optional checkpoint root tied to the fault.
    #[serde(default)]
    pub checkpoint_root: [u8; 32],
    /// Optional witness certificate bytes relevant to the evidence.
    #[serde(default)]
    pub witness_certificate: Option<GuardianWitnessCertificate>,
    /// Human-readable operator detail.
    #[serde(default)]
    pub details: String,
}

/// Stronger finality proof emitted by the asymptote sealing plane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
pub struct SealedFinalityProof {
    /// Guardian epoch for the sealed slot.
    pub epoch: u64,
    /// Finality tier achieved by this proof.
    #[serde(default)]
    pub finality_tier: FinalityTier,
    /// Deterministic collapse state produced for the slot.
    #[serde(default)]
    pub collapse_state: CollapseState,
    /// Guardian committee manifest hash for the base slot certificate.
    pub guardian_manifest_hash: [u8; 32],
    /// Guardian decision hash of the slot being sealed.
    pub guardian_decision_hash: [u8; 32],
    /// Guardian counter bound into the sealed slot.
    pub guardian_counter: u64,
    /// Guardian trace root bound into the sealed slot.
    pub guardian_trace_hash: [u8; 32],
    /// Guardian measurement root bound into the sealed slot.
    pub guardian_measurement_root: [u8; 32],
    /// Policy hash used to decide the sealing requirements.
    pub policy_hash: [u8; 32],
    /// Witness certificates satisfying the sealing policy.
    #[serde(default)]
    pub witness_certificates: Vec<GuardianWitnessCertificate>,
    /// Equal-authority observer certificates satisfying the veto-collapse observation rounds.
    #[serde(default)]
    pub observer_certificates: Vec<AsymptoteObserverCertificate>,
    /// Canonical close certificate summarizing the expected observer sample and verdict counts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observer_close_certificate: Option<AsymptoteObserverCloseCertificate>,
    /// Full deterministic observer transcript surface carried by the proof.
    #[serde(default)]
    pub observer_transcripts: Vec<AsymptoteObserverTranscript>,
    /// Full deterministic observer challenge surface carried by the proof.
    #[serde(default)]
    pub observer_challenges: Vec<AsymptoteObserverChallenge>,
    /// Public transcript commitment for deterministic observer sealing, when that mode is used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observer_transcript_commitment: Option<AsymptoteObserverTranscriptCommitment>,
    /// Public challenge commitment for deterministic observer sealing, when that mode is used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observer_challenge_commitment: Option<AsymptoteObserverChallengeCommitment>,
    /// Canonical close object for deterministic observer sealing, when that mode is used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observer_canonical_close: Option<AsymptoteObserverCanonicalClose>,
    /// Canonical abort object for deterministic observer sealing, when the observer lane aborts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observer_canonical_abort: Option<AsymptoteObserverCanonicalAbort>,
    /// Objective veto proofs that deterministically collapse the slot to `Abort` if admitted.
    #[serde(default)]
    pub veto_proofs: Vec<AsymptoteVetoProof>,
    /// Optional divergence signals observed while collecting the proof.
    #[serde(default)]
    pub divergence_signals: Vec<DivergenceSignal>,
    /// Producer signature authenticating the exact sealing-evidence surface.
    #[serde(default)]
    pub proof_signature: SignatureProof,
}

/// Class of irreversible effect to be sealed by the proof-carrying asymptote lane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
#[serde(rename_all = "snake_case")]
pub enum SealedEffectClass {
    /// Outbound HTTPS egress authorized by the guardian.
    #[default]
    HttpEgress,
    /// Secret injection into a deterministic external sink.
    SecretInjection,
    /// Cross-system settlement or bridge release.
    BridgeSettlement,
}

/// Compact verifier family used by the proof-carrying effect lane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
#[serde(rename_all = "snake_case")]
pub enum EffectProofSystem {
    /// Reference verifier: proof bytes are a canonical hash over verifier and public-input data.
    #[default]
    HashBindingV1,
}

/// Registry-backed metadata describing a verifier accepted for sealed effects.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
pub struct EffectProofVerifierDescriptor {
    /// Stable verifier identifier.
    pub verifier_id: String,
    /// Effect class this verifier may authorize.
    #[serde(default)]
    pub effect_class: SealedEffectClass,
    /// Proof system implemented by the verifier.
    #[serde(default)]
    pub proof_system: EffectProofSystem,
    /// Stable hash of the verifying key or verifier program.
    #[serde(default)]
    pub verifying_key_hash: [u8; 32],
    /// Whether the verifier is currently enabled.
    #[serde(default)]
    pub enabled: bool,
}

/// Canonical intent committed by the fast lane before an irreversible effect is released.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
pub struct EffectIntent {
    /// Guardian epoch in which the intent was committed.
    pub epoch: u64,
    /// Type of effect to be externalized.
    #[serde(default)]
    pub effect_class: SealedEffectClass,
    /// Finality tier required by the caller.
    #[serde(default)]
    pub finality_tier: FinalityTier,
    /// Hash of the outbound request without secret material.
    #[serde(default)]
    pub request_hash: [u8; 32],
    /// Canonical server name or target identifier.
    #[serde(default)]
    pub target: String,
    /// HTTP method or protocol action.
    #[serde(default)]
    pub action: String,
    /// Path or route within the target system.
    #[serde(default)]
    pub path: String,
    /// Guardian manifest authorizing the base slot.
    #[serde(default)]
    pub guardian_manifest_hash: [u8; 32],
    /// Guardian decision hash authorizing the base slot.
    #[serde(default)]
    pub guardian_decision_hash: [u8; 32],
    /// Policy hash authorizing this effect.
    #[serde(default)]
    pub policy_hash: [u8; 32],
}

/// Public inputs all validators can verify cheaply when checking a sealed effect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
pub struct EffectPublicInputs {
    /// Canonical hash of the effect intent.
    #[serde(default)]
    pub intent_hash: [u8; 32],
    /// Guardian counter bound into the slot that committed the intent.
    pub guardian_counter: u64,
    /// Guardian trace root bound into the slot that committed the intent.
    #[serde(default)]
    pub guardian_trace_hash: [u8; 32],
    /// Guardian measurement root bound into the slot that committed the intent.
    #[serde(default)]
    pub guardian_measurement_root: [u8; 32],
    /// Canonical root of the observer transcript surface bound into the sealing proof.
    #[serde(default)]
    pub observer_transcripts_root: [u8; 32],
    /// Canonical root of the observer challenge surface bound into the sealing proof.
    #[serde(default)]
    pub observer_challenges_root: [u8; 32],
    /// Canonical hash of the observer close object authorizing sealed release.
    #[serde(default)]
    pub observer_resolution_hash: [u8; 32],
    /// Canonical hash of the protocol-wide collapse object authorizing irreversible release.
    #[serde(default)]
    pub canonical_collapse_hash: [u8; 32],
    /// One-time nullifier preventing replay of the external effect.
    #[serde(default)]
    pub nullifier: [u8; 32],
}

/// Canonical observer-surface binding carried into proof-carrying sealed effects.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
pub struct ObserverSurfaceBinding {
    /// Canonical root of the observer transcript surface.
    #[serde(default)]
    pub transcripts_root: [u8; 32],
    /// Canonical root of the observer challenge surface.
    #[serde(default)]
    pub challenges_root: [u8; 32],
    /// Canonical hash of the authoritative close object.
    #[serde(default)]
    pub resolution_hash: [u8; 32],
}

/// Compact proof envelope for a sealed effect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
pub struct EffectProofEnvelope {
    /// Verifier family used to check the proof.
    #[serde(default)]
    pub proof_system: EffectProofSystem,
    /// Stable verifier identifier to resolve on-chain policy.
    #[serde(default)]
    pub verifier_id: String,
    /// Hash of the verifying key or verifier artifact.
    #[serde(default)]
    pub verifying_key_hash: [u8; 32],
    /// Canonical hash of the encoded public inputs.
    #[serde(default)]
    pub public_inputs_hash: [u8; 32],
    /// Opaque proof bytes.
    #[serde(default)]
    pub proof_bytes: Vec<u8>,
}

/// Self-contained proof-carrying seal object for an irreversible effect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
pub struct SealObject {
    /// Effect epoch.
    pub epoch: u64,
    /// Effect class being authorized.
    #[serde(default)]
    pub effect_class: SealedEffectClass,
    /// Registry-backed verifier metadata.
    #[serde(default)]
    pub verifier: EffectProofVerifierDescriptor,
    /// Canonical committed effect intent.
    #[serde(default)]
    pub intent: EffectIntent,
    /// Compact public inputs verified by all validators / gateways.
    #[serde(default)]
    pub public_inputs: EffectPublicInputs,
    /// Proof envelope binding the effect to the committed slot.
    #[serde(default)]
    pub proof: EffectProofEnvelope,
}

/// Persisted nullifier record for replay-safe sealed effects.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
pub struct SealedEffectRecord {
    /// Stable nullifier key.
    #[serde(default)]
    pub nullifier: [u8; 32],
    /// Canonical intent hash released by this seal.
    #[serde(default)]
    pub intent_hash: [u8; 32],
    /// Effect epoch.
    pub epoch: u64,
    /// Effect class that consumed the nullifier.
    #[serde(default)]
    pub effect_class: SealedEffectClass,
    /// Verifier identifier used for the seal.
    #[serde(default)]
    pub verifier_id: String,
    /// Stable hash of the encoded seal object.
    #[serde(default)]
    pub seal_hash: [u8; 32],
}

fn hash_guardianized_bytes<T: Encode>(value: &T) -> Result<[u8; 32], String> {
    let bytes = value.encode();
    let digest = DcryptSha256::digest(&bytes).map_err(|e| e.to_string())?;
    digest
        .as_ref()
        .try_into()
        .map_err(|_| "invalid sha256 digest length".into())
}

/// Returns the canonical hash of an effect intent.
pub fn canonical_effect_intent_hash(intent: &EffectIntent) -> Result<[u8; 32], String> {
    hash_guardianized_bytes(intent)
}

/// Returns the canonical hash of a sealed-effect public-input set.
pub fn canonical_effect_public_inputs_hash(
    public_inputs: &EffectPublicInputs,
) -> Result<[u8; 32], String> {
    hash_guardianized_bytes(public_inputs)
}

/// Returns the canonical message bytes signed over the sealing-evidence surface.
pub fn canonical_sealed_finality_proof_signing_bytes(
    proof: &SealedFinalityProof,
) -> Result<Vec<u8>, String> {
    let mut normalized = proof.clone();
    normalized.proof_signature = SignatureProof::default();
    Ok(normalized.encode())
}

/// Returns the canonical hash of a sealed-effect envelope.
pub fn canonical_seal_object_hash(seal_object: &SealObject) -> Result<[u8; 32], String> {
    hash_guardianized_bytes(seal_object)
}

/// Returns a deterministic one-time nullifier for an effect intent and committed guardian slot.
pub fn derive_effect_nullifier(
    request_hash: [u8; 32],
    guardian_decision_hash: [u8; 32],
    guardian_counter: u64,
) -> Result<[u8; 32], String> {
    let mut material = Vec::with_capacity(32 + 32 + 8);
    material.extend_from_slice(&request_hash);
    material.extend_from_slice(&guardian_decision_hash);
    material.extend_from_slice(&guardian_counter.to_be_bytes());
    let digest = DcryptSha256::digest(&material).map_err(|e| e.to_string())?;
    digest
        .as_ref()
        .try_into()
        .map_err(|_| "invalid sha256 digest length".into())
}

/// Returns the canonical collapse-object hash required to authorize a sealed effect release.
pub fn canonical_collapse_hash_for_sealed_effect(
    canonical_collapse_object: &CanonicalCollapseObject,
    sealed_finality_proof: &SealedFinalityProof,
) -> Result<[u8; 32], String> {
    if sealed_finality_proof.finality_tier != FinalityTier::SealedFinal
        || sealed_finality_proof.collapse_state != CollapseState::SealedFinal
    {
        return Err("sealed effects require a SealedFinal proof-bound collapse state".into());
    }
    if canonical_collapse_object.height == 0 {
        return Err("sealed-effect canonical collapse object height must be non-zero".into());
    }
    if canonical_collapse_object.transactions_root_hash == [0u8; 32]
        || canonical_collapse_object.resulting_state_root_hash == [0u8; 32]
    {
        return Err(
            "sealed-effect canonical collapse object must bind committed transaction and state roots"
                .into(),
        );
    }
    let sealing = canonical_collapse_object.sealing.as_ref().ok_or_else(|| {
        "sealed-effect canonical collapse object is missing the sealing branch".to_string()
    })?;
    if sealing.kind != CanonicalCollapseKind::Close
        || sealing.finality_tier != FinalityTier::SealedFinal
        || sealing.collapse_state != CollapseState::SealedFinal
    {
        return Err(
            "sealed-effect canonical collapse object does not authorize the SealedFinal close path"
                .into(),
        );
    }
    if sealing.height != canonical_collapse_object.height {
        return Err(
            "sealed-effect canonical collapse object height does not match the sealing branch"
                .into(),
        );
    }
    if sealing.epoch != sealed_finality_proof.epoch {
        return Err(
            "sealed-effect canonical collapse epoch does not match the sealed proof".into(),
        );
    }
    let observer_binding = sealed_finality_proof_observer_binding(sealed_finality_proof)?;
    if sealing.transcripts_root != observer_binding.transcripts_root
        || sealing.challenges_root != observer_binding.challenges_root
        || sealing.resolution_hash != observer_binding.resolution_hash
    {
        return Err(
            "sealed-effect canonical collapse object does not match the proof-bound observer surface"
                .into(),
        );
    }
    canonical_collapse_object_hash(canonical_collapse_object)
}

/// Builds the reference proof bytes for the `HashBindingV1` proof family.
pub fn build_reference_effect_proof_bytes(
    verifier: &EffectProofVerifierDescriptor,
    intent_hash: [u8; 32],
    public_inputs_hash: [u8; 32],
) -> Result<Vec<u8>, String> {
    let mut material = Vec::with_capacity(
        verifier.verifier_id.len() + 32 + 32 + b"aft::effect-proof::hash-binding::v1".len(),
    );
    material.extend_from_slice(b"aft::effect-proof::hash-binding::v1");
    material.extend_from_slice(verifier.verifier_id.as_bytes());
    material.extend_from_slice(&verifier.verifying_key_hash);
    material.extend_from_slice(&intent_hash);
    material.extend_from_slice(&public_inputs_hash);
    Ok(DcryptSha256::digest(&material)
        .map_err(|e| e.to_string())?
        .to_vec())
}

/// Builds the default verifier descriptor for proof-carrying HTTP egress seals.
pub fn default_http_egress_effect_verifier() -> Result<EffectProofVerifierDescriptor, String> {
    let verifying_key_hash = DcryptSha256::digest(b"aft::effect-verifier::http-egress::v1")
        .map_err(|e| e.to_string())?;
    Ok(EffectProofVerifierDescriptor {
        verifier_id: "aft-http-egress-hash-binding-v1".into(),
        effect_class: SealedEffectClass::HttpEgress,
        proof_system: EffectProofSystem::HashBindingV1,
        verifying_key_hash: verifying_key_hash
            .as_ref()
            .try_into()
            .map_err(|_| "invalid sha256 digest length".to_string())?,
        enabled: true,
    })
}

/// Builds a canonical proof-carrying seal object for guardian-authorized HTTP egress.
pub fn build_http_egress_seal_object(
    request_hash: [u8; 32],
    target: &str,
    method: &str,
    path: &str,
    policy_hash: [u8; 32],
    sealed_finality_proof: &SealedFinalityProof,
    canonical_collapse_object: &CanonicalCollapseObject,
) -> Result<SealObject, String> {
    if sealed_finality_proof.finality_tier != FinalityTier::SealedFinal
        || sealed_finality_proof.collapse_state != CollapseState::SealedFinal
    {
        return Err("sealed-effect seal objects require a SealedFinal collapse state".into());
    }
    let verifier = default_http_egress_effect_verifier()?;
    let observer_binding = sealed_finality_proof_observer_binding(sealed_finality_proof)?;
    let canonical_collapse_hash = canonical_collapse_hash_for_sealed_effect(
        canonical_collapse_object,
        sealed_finality_proof,
    )?;
    let intent = EffectIntent {
        epoch: sealed_finality_proof.epoch,
        effect_class: SealedEffectClass::HttpEgress,
        finality_tier: sealed_finality_proof.finality_tier,
        request_hash,
        target: target.to_string(),
        action: method.to_string(),
        path: path.to_string(),
        guardian_manifest_hash: sealed_finality_proof.guardian_manifest_hash,
        guardian_decision_hash: sealed_finality_proof.guardian_decision_hash,
        policy_hash,
    };
    let intent_hash = canonical_effect_intent_hash(&intent)?;
    let public_inputs = EffectPublicInputs {
        intent_hash,
        guardian_counter: sealed_finality_proof.guardian_counter,
        guardian_trace_hash: sealed_finality_proof.guardian_trace_hash,
        guardian_measurement_root: sealed_finality_proof.guardian_measurement_root,
        observer_transcripts_root: observer_binding.transcripts_root,
        observer_challenges_root: observer_binding.challenges_root,
        observer_resolution_hash: observer_binding.resolution_hash,
        canonical_collapse_hash,
        nullifier: derive_effect_nullifier(
            request_hash,
            sealed_finality_proof.guardian_decision_hash,
            sealed_finality_proof.guardian_counter,
        )?,
    };
    let public_inputs_hash = canonical_effect_public_inputs_hash(&public_inputs)?;
    let proof = EffectProofEnvelope {
        proof_system: verifier.proof_system.clone(),
        verifier_id: verifier.verifier_id.clone(),
        verifying_key_hash: verifier.verifying_key_hash,
        public_inputs_hash,
        proof_bytes: build_reference_effect_proof_bytes(
            &verifier,
            intent_hash,
            public_inputs_hash,
        )?,
    };
    Ok(SealObject {
        epoch: sealed_finality_proof.epoch,
        effect_class: SealedEffectClass::HttpEgress,
        verifier,
        intent,
        public_inputs,
        proof,
    })
}

/// Verifies a seal object against its self-contained verifier metadata.
pub fn verify_seal_object(seal_object: &SealObject) -> Result<(), String> {
    if !seal_object.verifier.enabled {
        return Err("sealed-effect verifier is disabled".into());
    }
    if seal_object.effect_class != seal_object.intent.effect_class
        || seal_object.effect_class != seal_object.verifier.effect_class
    {
        return Err("sealed-effect class does not match verifier or intent".into());
    }
    if seal_object.epoch != seal_object.intent.epoch {
        return Err("sealed-effect epoch does not match canonical intent".into());
    }
    if seal_object.intent.finality_tier != FinalityTier::SealedFinal {
        return Err("sealed-effect intent must require SealedFinal".into());
    }
    let intent_hash = canonical_effect_intent_hash(&seal_object.intent)?;
    if seal_object.public_inputs.intent_hash != intent_hash {
        return Err("sealed-effect public inputs are not bound to the canonical intent".into());
    }
    if seal_object.public_inputs.nullifier == [0u8; 32] {
        return Err("sealed-effect nullifier must be non-zero".into());
    }
    if seal_object.public_inputs.canonical_collapse_hash == [0u8; 32] {
        return Err("sealed-effect canonical collapse hash must be non-zero".into());
    }
    if seal_object.public_inputs.observer_resolution_hash == [0u8; 32]
        && (seal_object.public_inputs.observer_transcripts_root != [0u8; 32]
            || seal_object.public_inputs.observer_challenges_root != [0u8; 32])
    {
        return Err("sealed-effect observer surface is missing its canonical close binding".into());
    }
    let public_inputs_hash = canonical_effect_public_inputs_hash(&seal_object.public_inputs)?;
    if seal_object.proof.public_inputs_hash != public_inputs_hash {
        return Err("sealed-effect proof does not match the canonical public inputs".into());
    }
    if seal_object.proof.proof_system != seal_object.verifier.proof_system {
        return Err("sealed-effect proof system does not match verifier descriptor".into());
    }
    if seal_object.proof.verifier_id != seal_object.verifier.verifier_id {
        return Err("sealed-effect proof verifier id does not match verifier descriptor".into());
    }
    if seal_object.proof.verifying_key_hash != seal_object.verifier.verifying_key_hash {
        return Err(
            "sealed-effect proof verifying key hash does not match verifier descriptor".into(),
        );
    }
    match seal_object.proof.proof_system {
        EffectProofSystem::HashBindingV1 => {
            let expected = build_reference_effect_proof_bytes(
                &seal_object.verifier,
                intent_hash,
                public_inputs_hash,
            )?;
            if seal_object.proof.proof_bytes != expected {
                return Err("sealed-effect hash-binding proof bytes are invalid".into());
            }
        }
    }
    Ok(())
}

/// Returns the canonical observer binding carried by a `SealedFinalityProof`.
pub fn sealed_finality_proof_observer_binding(
    proof: &SealedFinalityProof,
) -> Result<ObserverSurfaceBinding, String> {
    let has_observer_surface = !proof.observer_transcripts.is_empty()
        || !proof.observer_challenges.is_empty()
        || proof.observer_transcript_commitment.is_some()
        || proof.observer_challenge_commitment.is_some()
        || proof.observer_canonical_close.is_some()
        || proof.observer_canonical_abort.is_some();
    if !has_observer_surface {
        return Ok(ObserverSurfaceBinding::default());
    }
    if proof.collapse_state != CollapseState::SealedFinal
        || proof.finality_tier != FinalityTier::SealedFinal
    {
        return Err("sealed-effect observer binding requires a SealedFinal proof".into());
    }
    let transcript_commitment = proof
        .observer_transcript_commitment
        .as_ref()
        .ok_or_else(|| {
            "sealed final proof is missing an observer transcript commitment".to_string()
        })?;
    let challenge_commitment = proof
        .observer_challenge_commitment
        .as_ref()
        .ok_or_else(|| {
            "sealed final proof is missing an observer challenge commitment".to_string()
        })?;
    let canonical_close = proof
        .observer_canonical_close
        .as_ref()
        .ok_or_else(|| "sealed final proof is missing a canonical observer close".to_string())?;
    if proof.observer_canonical_abort.is_some() {
        return Err("sealed final proof may not carry a canonical observer abort object".into());
    }
    let transcripts_root =
        canonical_asymptote_observer_transcripts_hash(&proof.observer_transcripts)?;
    let challenges_root = canonical_asymptote_observer_challenges_hash(&proof.observer_challenges)?;
    if transcript_commitment.transcripts_root != transcripts_root
        || canonical_close.transcripts_root != transcripts_root
    {
        return Err("sealed final proof transcript surface does not match its commitments".into());
    }
    if challenge_commitment.challenges_root != challenges_root
        || canonical_close.challenges_root != challenges_root
    {
        return Err("sealed final proof challenge surface does not match its commitments".into());
    }
    if challenge_commitment.challenge_count != 0
        || canonical_close.challenge_count != 0
        || !proof.observer_challenges.is_empty()
    {
        return Err("sealed final proof observer surface is challenge-dominated".into());
    }
    Ok(ObserverSurfaceBinding {
        transcripts_root,
        challenges_root,
        resolution_hash: canonical_asymptote_observer_canonical_close_hash(canonical_close)?,
    })
}

/// Canonical hash of the published observer transcript surface for one slot.
pub fn canonical_asymptote_observer_transcripts_hash(
    transcripts: &[AsymptoteObserverTranscript],
) -> Result<[u8; 32], String> {
    let mut normalized = transcripts
        .iter()
        .map(|transcript| {
            (
                (
                    transcript.statement.assignment.epoch,
                    transcript.statement.assignment.height,
                    transcript.statement.assignment.view,
                    transcript.statement.assignment.round,
                    transcript.statement.assignment.observer_account_id,
                ),
                transcript.encode(),
            )
        })
        .collect::<Vec<_>>();
    normalized.sort_unstable_by(|left, right| left.0.cmp(&right.0).then(left.1.cmp(&right.1)));
    for window in normalized.windows(2) {
        if window[0].0 == window[1].0 {
            return Err(
                "canonical observer transcript surface must not contain duplicate assignments"
                    .into(),
            );
        }
    }
    let digest = DcryptSha256::digest(&normalized.encode()).map_err(|e| e.to_string())?;
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&digest);
    Ok(hash)
}

/// Canonical hash of one observer observation request.
pub fn canonical_asymptote_observer_observation_request_hash(
    request: &AsymptoteObserverObservationRequest,
) -> Result<[u8; 32], String> {
    hash_guardianized_bytes(request)
}

/// Canonical hash of one observer transcript.
pub fn canonical_asymptote_observer_transcript_hash(
    transcript: &AsymptoteObserverTranscript,
) -> Result<[u8; 32], String> {
    hash_guardianized_bytes(transcript)
}

/// Canonical hash of the published observer challenge surface for one slot.
pub fn canonical_asymptote_observer_challenges_hash(
    challenges: &[AsymptoteObserverChallenge],
) -> Result<[u8; 32], String> {
    let mut normalized = challenges
        .iter()
        .map(|challenge| (challenge.challenge_id, challenge.encode()))
        .collect::<Vec<_>>();
    normalized.sort_unstable_by(|left, right| left.0.cmp(&right.0).then(left.1.cmp(&right.1)));
    for window in normalized.windows(2) {
        if window[0].0 == window[1].0 {
            return Err(
                "canonical observer challenge surface must not contain duplicate challenge ids"
                    .into(),
            );
        }
    }
    let digest = DcryptSha256::digest(&normalized.encode()).map_err(|e| e.to_string())?;
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&digest);
    Ok(hash)
}

/// Canonical hash of a canonical observer close object.
pub fn canonical_asymptote_observer_canonical_close_hash(
    close: &AsymptoteObserverCanonicalClose,
) -> Result<[u8; 32], String> {
    hash_guardianized_bytes(close)
}

/// Canonical hash of a canonical observer abort object.
pub fn canonical_asymptote_observer_canonical_abort_hash(
    abort: &AsymptoteObserverCanonicalAbort,
) -> Result<[u8; 32], String> {
    hash_guardianized_bytes(abort)
}

/// Aggregated committee certificate for a guardian decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
pub struct GuardianQuorumCertificate {
    /// Hash of the registered committee manifest.
    pub manifest_hash: [u8; 32],
    /// Committee epoch.
    pub epoch: u64,
    /// Canonical hash of the signed decision payload.
    pub decision_hash: [u8; 32],
    /// Monotonic counter for the decision stream.
    pub counter: u64,
    /// Trace root chaining this decision to prior committee history.
    pub trace_hash: [u8; 32],
    /// Runtime measurement root bound to this decision.
    pub measurement_root: [u8; 32],
    /// Bitfield of committee members who signed.
    #[serde(default)]
    pub signers_bitfield: Vec<u8>,
    /// Aggregated BLS signature over the decision hash.
    #[serde(default)]
    pub aggregated_signature: Vec<u8>,
    /// Optional witness-log checkpoint anchoring this decision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_checkpoint: Option<GuardianLogCheckpoint>,
    /// Optional external witness committee certificate for research-only nested guardian mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub experimental_witness_certificate: Option<GuardianWitnessCertificate>,
}

/// Result of a guardianized signing operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
pub struct GuardianCertificate {
    /// Compatibility signature bytes for legacy call sites.
    #[serde(default)]
    pub signature: Vec<u8>,
    /// Monotonic counter value.
    pub counter: u64,
    /// Trace hash for the signing history.
    pub trace_hash: [u8; 32],
    /// Optional quorum certificate when operating in guardianized mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quorum: Option<GuardianQuorumCertificate>,
}

/// Domain of a guardianized decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
#[serde(rename_all = "snake_case")]
pub enum GuardianDecisionDomain {
    /// Decision to certify a consensus proposal slot.
    ConsensusSlot,
    /// Decision to authorize and receipt an outbound network effect.
    SecureEgress,
    /// Decision to certify an equal-authority asymptote observation verdict.
    AsymptoteObserve,
}

/// Canonical decision payload issued to guardian committee members.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
pub struct GuardianDecision {
    /// Decision domain.
    pub domain: u8,
    /// Validator or runtime subject.
    #[serde(default)]
    pub subject: Vec<u8>,
    /// Canonical payload hash for the requested decision.
    pub payload_hash: [u8; 32],
    /// Monotonic counter checkpoint expected by the caller.
    pub counter: u64,
    /// Prior trace root expected by the caller.
    pub trace_hash: [u8; 32],
    /// Measurement root to bind into the certificate.
    pub measurement_root: [u8; 32],
    /// Optional policy hash for egress / runtime constraints.
    pub policy_hash: [u8; 32],
}

/// Verifier family used to validate guardian attestation evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
#[serde(rename_all = "snake_case")]
pub enum GuardianAttestationVerifierKind {
    /// Legacy structural checks only.
    #[default]
    Structural,
    /// Hardware quote verification through tee-driver.
    TeeDriver,
    /// Software guardian verification through committee/log policy.
    SoftwareGuardian,
}

/// Rich evidence attached to guardian attestations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
pub struct GuardianAttestationEvidence {
    /// Verifier used for the evidence.
    pub verifier: GuardianAttestationVerifierKind,
    /// Hash of the committee manifest bound to this runtime.
    pub manifest_hash: [u8; 32],
    /// Measurement root of the attested runtime.
    pub measurement_root: [u8; 32],
    /// Optional transparency checkpoint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint: Option<GuardianLogCheckpoint>,
    /// Optional inclusion proof bytes.
    #[serde(default)]
    pub inclusion_proof: Vec<u8>,
    /// Opaque verifier evidence (quote blob, signed statement, etc.).
    #[serde(default)]
    pub evidence: Vec<u8>,
}

/// Canonical receipt for guardian-authorized egress.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
pub struct EgressReceipt {
    /// Canonical hash of the outbound request without secret bytes.
    pub request_hash: [u8; 32],
    /// Canonical TLS server name bound to the session.
    #[serde(default)]
    pub server_name: String,
    /// Receipt schema version for transcript binding semantics.
    #[serde(default)]
    pub transcript_version: u32,
    /// Redacted transcript root for request/response exchange.
    pub transcript_root: [u8; 32],
    /// TLS-session-bound handshake transcript digest.
    #[serde(default)]
    pub handshake_transcript_hash: [u8; 32],
    /// Hash of the HTTP request transcript sent over the TLS channel.
    #[serde(default)]
    pub request_transcript_hash: [u8; 32],
    /// Hash of the HTTP response transcript received over the TLS channel.
    #[serde(default)]
    pub response_transcript_hash: [u8; 32],
    /// Hash of the peer certificate chain, when available.
    pub peer_certificate_chain_hash: [u8; 32],
    /// Hash of the peer leaf certificate, when available.
    #[serde(default)]
    pub peer_leaf_certificate_hash: [u8; 32],
    /// Hash of the response body returned to the workload.
    pub response_hash: [u8; 32],
    /// Policy hash that authorized this egress.
    pub policy_hash: [u8; 32],
    /// Finality tier required by the caller and attested by the guardian.
    #[serde(default)]
    pub finality_tier: FinalityTier,
    /// Guardian certificate authorizing the effect.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guardian_certificate: Option<GuardianQuorumCertificate>,
    /// Optional sealed finality proof authorizing a stronger effect tier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sealed_finality_proof: Option<SealedFinalityProof>,
    /// Optional proof-carrying seal object authorizing the irreversible effect itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seal_object: Option<SealObject>,
    /// Optional protocol-wide canonical collapse object bound to a sealed effect.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canonical_collapse_object: Option<CanonicalCollapseObject>,
    /// Optional witness-log checkpoint anchoring the receipt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_checkpoint: Option<GuardianLogCheckpoint>,
}

#[cfg(test)]
#[path = "guardianized/tests.rs"]
mod tests;
