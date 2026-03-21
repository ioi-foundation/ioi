/// The state key for the single, canonical `ValidatorSetBlob` structure.
pub const VALIDATOR_SET_KEY: &[u8] = b"system::validators::current";
/// State key prefix for published AFT bulletin-board commitments by height.
pub const AFT_BULLETIN_COMMITMENT_PREFIX: &[u8] = b"aft::ordering::bulletin::";
/// State key prefix for published AFT bulletin-board entries by height and tx hash.
pub const AFT_BULLETIN_ENTRY_PREFIX: &[u8] = b"aft::ordering::bulletin_entry::";
/// State key prefix for published AFT bulletin availability certificates by height.
pub const AFT_BULLETIN_AVAILABILITY_PREFIX: &[u8] = b"aft::ordering::bulletin_availability::";
/// State key prefix for published AFT bulletin retrievability profiles by height.
pub const AFT_BULLETIN_RETRIEVABILITY_PROFILE_PREFIX: &[u8] =
    b"aft::ordering::bulletin_retrievability_profile::";
/// State key prefix for published AFT bulletin shard manifests by height.
pub const AFT_BULLETIN_SHARD_MANIFEST_PREFIX: &[u8] =
    b"aft::ordering::bulletin_shard_manifest::";
/// State key prefix for published AFT bulletin custody assignments by height.
pub const AFT_BULLETIN_CUSTODY_ASSIGNMENT_PREFIX: &[u8] =
    b"aft::ordering::bulletin_custody_assignment::";
/// State key prefix for published AFT bulletin custody receipts by height.
pub const AFT_BULLETIN_CUSTODY_RECEIPT_PREFIX: &[u8] =
    b"aft::ordering::bulletin_custody_receipt::";
/// State key prefix for published AFT bulletin custody responses by height.
pub const AFT_BULLETIN_CUSTODY_RESPONSE_PREFIX: &[u8] =
    b"aft::ordering::bulletin_custody_response::";
/// State key prefix for objective endogenous-retrievability challenges by height.
pub const AFT_BULLETIN_RETRIEVABILITY_CHALLENGE_PREFIX: &[u8] =
    b"aft::ordering::bulletin_retrievability_challenge::";
/// State key prefix for protocol-visible bulletin reconstruction certificates by height.
pub const AFT_BULLETIN_RECONSTRUCTION_CERTIFICATE_PREFIX: &[u8] =
    b"aft::ordering::bulletin_reconstruction_certificate::";
/// State key prefix for protocol-visible bulletin reconstruction-abort objects by height.
pub const AFT_BULLETIN_RECONSTRUCTION_ABORT_PREFIX: &[u8] =
    b"aft::ordering::bulletin_reconstruction_abort::";
/// State key prefix for published AFT canonical bulletin-close objects by height.
pub const AFT_BULLETIN_CLOSE_PREFIX: &[u8] = b"aft::ordering::bulletin_close::";
/// State key prefix for published AFT canonical-order certificates by height.
pub const AFT_ORDER_CERTIFICATE_PREFIX: &[u8] = b"aft::ordering::certificate::";
/// State key prefix for published AFT canonical-order abort objects by height.
pub const AFT_ORDER_ABORT_PREFIX: &[u8] = b"aft::ordering::abort::";
/// State key prefix for published compact publication-frontier summaries by height.
pub const AFT_PUBLICATION_FRONTIER_PREFIX: &[u8] = b"aft::publication::frontier::";
/// State key prefix for published publication-frontier contradiction objects by height.
pub const AFT_PUBLICATION_CONTRADICTION_PREFIX: &[u8] = b"aft::publication::contradiction::";
/// State key prefix for exploratory recovery capsules by height.
pub const AFT_RECOVERY_CAPSULE_PREFIX: &[u8] = b"aft::recovery::capsule::";
/// State key prefix for exploratory recovery witness certificates by height and witness account.
pub const AFT_RECOVERY_WITNESS_CERTIFICATE_PREFIX: &[u8] = b"aft::recovery::witness_certificate::";
/// State key prefix for exploratory recovery share receipts by height, witness account, and block commitment.
pub const AFT_RECOVERY_SHARE_RECEIPT_PREFIX: &[u8] = b"aft::recovery::share_receipt::";
/// State key prefix for exploratory recovery share-reveal material by height, witness account, and block commitment.
pub const AFT_RECOVERY_SHARE_MATERIAL_PREFIX: &[u8] = b"aft::recovery::share_material::";
/// State key prefix for compact recovered-publication bundle objects by height, block, and witness-support set.
pub const AFT_RECOVERED_PUBLICATION_BUNDLE_PREFIX: &[u8] =
    b"aft::recovery::recovered_publication_bundle::";
/// State key prefix for archived recovered-history segment descriptors by covered range.
pub const AFT_ARCHIVED_RECOVERED_HISTORY_SEGMENT_PREFIX: &[u8] =
    b"aft::recovery::archived_history_segment::";
/// State key prefix for content-addressed archived recovered-history segment descriptors.
pub const AFT_ARCHIVED_RECOVERED_HISTORY_SEGMENT_HASH_PREFIX: &[u8] =
    b"aft::recovery::archived_history_segment_hash::";
/// State key prefix for content-addressed archived recovered-history profiles.
pub const AFT_ARCHIVED_RECOVERED_HISTORY_PROFILE_HASH_PREFIX: &[u8] =
    b"aft::recovery::archived_history_profile_hash::";
/// State key prefix for archived recovered-history profile activations by profile hash.
pub const AFT_ARCHIVED_RECOVERED_HISTORY_PROFILE_ACTIVATION_PREFIX: &[u8] =
    b"aft::recovery::archived_history_profile_activation::";
/// State key prefix for archived recovered-history profile activations by activation end height.
pub const AFT_ARCHIVED_RECOVERED_HISTORY_PROFILE_ACTIVATION_HEIGHT_PREFIX: &[u8] =
    b"aft::recovery::archived_history_profile_activation_height::";
/// State key prefix for content-addressed archived recovered-history profile activations.
pub const AFT_ARCHIVED_RECOVERED_HISTORY_PROFILE_ACTIVATION_HASH_PREFIX: &[u8] =
    b"aft::recovery::archived_history_profile_activation_hash::";
/// State key prefix for content-addressed archived recovered restart-page payloads.
pub const AFT_ARCHIVED_RECOVERED_RESTART_PAGE_PREFIX: &[u8] =
    b"aft::recovery::archived_restart_page::";
/// State key prefix for archived recovered-history checkpoint descriptors by covered range.
pub const AFT_ARCHIVED_RECOVERED_HISTORY_CHECKPOINT_PREFIX: &[u8] =
    b"aft::recovery::archived_history_checkpoint::";
/// State key prefix for content-addressed archived recovered-history checkpoints.
pub const AFT_ARCHIVED_RECOVERED_HISTORY_CHECKPOINT_HASH_PREFIX: &[u8] =
    b"aft::recovery::archived_history_checkpoint_hash::";
/// State key prefix for archived recovered-history retention receipts by checkpoint hash.
pub const AFT_ARCHIVED_RECOVERED_HISTORY_RETENTION_RECEIPT_PREFIX: &[u8] =
    b"aft::recovery::archived_history_retention_receipt::";
/// State key for the latest archived recovered-history checkpoint tip.
pub const AFT_LATEST_ARCHIVED_RECOVERED_HISTORY_CHECKPOINT_KEY: &[u8] =
    b"aft::recovery::archived_history_checkpoint::latest";
/// State key for the active archived recovered-history profile.
pub const AFT_ACTIVE_ARCHIVED_RECOVERED_HISTORY_PROFILE_KEY: &[u8] =
    b"aft::recovery::archived_history_profile::active";
/// State key for the latest archived recovered-history profile activation.
pub const AFT_LATEST_ARCHIVED_RECOVERED_HISTORY_PROFILE_ACTIVATION_KEY: &[u8] =
    b"aft::recovery::archived_history_profile_activation::latest";
/// State key prefix for exploratory missing recovery-share claims by height and witness account.
pub const AFT_MISSING_RECOVERY_SHARE_PREFIX: &[u8] = b"aft::recovery::missing_share::";
/// State key prefix for the protocol-wide canonical collapse object by height.
pub const AFT_COLLAPSE_OBJECT_PREFIX: &[u8] = b"aft::collapse::";
/// State key prefix for recorded AFT omission proofs by height and transaction hash.
pub const AFT_OMISSION_PROOF_PREFIX: &[u8] = b"aft::ordering::omission::";

/// Builds the canonical state key for a published AFT bulletin-board commitment.
pub fn aft_bulletin_commitment_key(height: u64) -> Vec<u8> {
    [AFT_BULLETIN_COMMITMENT_PREFIX, &height.to_be_bytes()].concat()
}

/// Builds the canonical state key for a published AFT bulletin-board entry.
pub fn aft_bulletin_entry_key(height: u64, tx_hash: &[u8; 32]) -> Vec<u8> {
    [
        AFT_BULLETIN_ENTRY_PREFIX,
        &height.to_be_bytes(),
        tx_hash.as_ref(),
    ]
    .concat()
}

/// Builds the canonical state key for a published AFT bulletin availability certificate.
pub fn aft_bulletin_availability_certificate_key(height: u64) -> Vec<u8> {
    [AFT_BULLETIN_AVAILABILITY_PREFIX, &height.to_be_bytes()].concat()
}

/// Builds the canonical state key for a published AFT bulletin retrievability profile.
pub fn aft_bulletin_retrievability_profile_key(height: u64) -> Vec<u8> {
    [AFT_BULLETIN_RETRIEVABILITY_PROFILE_PREFIX, &height.to_be_bytes()].concat()
}

/// Builds the canonical state key for a published AFT bulletin shard manifest.
pub fn aft_bulletin_shard_manifest_key(height: u64) -> Vec<u8> {
    [AFT_BULLETIN_SHARD_MANIFEST_PREFIX, &height.to_be_bytes()].concat()
}

/// Builds the canonical state key for a published AFT bulletin custody assignment.
pub fn aft_bulletin_custody_assignment_key(height: u64) -> Vec<u8> {
    [AFT_BULLETIN_CUSTODY_ASSIGNMENT_PREFIX, &height.to_be_bytes()].concat()
}

/// Builds the canonical state key for a published AFT bulletin custody receipt.
pub fn aft_bulletin_custody_receipt_key(height: u64) -> Vec<u8> {
    [AFT_BULLETIN_CUSTODY_RECEIPT_PREFIX, &height.to_be_bytes()].concat()
}

/// Builds the canonical state key for a published AFT bulletin custody response.
pub fn aft_bulletin_custody_response_key(height: u64) -> Vec<u8> {
    [AFT_BULLETIN_CUSTODY_RESPONSE_PREFIX, &height.to_be_bytes()].concat()
}

/// Builds the canonical state key for an objective AFT bulletin retrievability challenge.
pub fn aft_bulletin_retrievability_challenge_key(height: u64) -> Vec<u8> {
    [AFT_BULLETIN_RETRIEVABILITY_CHALLENGE_PREFIX, &height.to_be_bytes()].concat()
}

/// Builds the canonical state key for a published bulletin reconstruction-certificate object.
pub fn aft_bulletin_reconstruction_certificate_key(height: u64) -> Vec<u8> {
    [AFT_BULLETIN_RECONSTRUCTION_CERTIFICATE_PREFIX, &height.to_be_bytes()].concat()
}

/// Builds the canonical state key for a published bulletin reconstruction-abort object.
pub fn aft_bulletin_reconstruction_abort_key(height: u64) -> Vec<u8> {
    [AFT_BULLETIN_RECONSTRUCTION_ABORT_PREFIX, &height.to_be_bytes()].concat()
}

/// Builds the canonical state key for a published AFT canonical bulletin close.
pub fn aft_canonical_bulletin_close_key(height: u64) -> Vec<u8> {
    [AFT_BULLETIN_CLOSE_PREFIX, &height.to_be_bytes()].concat()
}

/// Builds the canonical state key for a published AFT canonical-order certificate.
pub fn aft_order_certificate_key(height: u64) -> Vec<u8> {
    [AFT_ORDER_CERTIFICATE_PREFIX, &height.to_be_bytes()].concat()
}

/// Builds the canonical state key for a published AFT canonical-order abort object.
pub fn aft_canonical_order_abort_key(height: u64) -> Vec<u8> {
    [AFT_ORDER_ABORT_PREFIX, &height.to_be_bytes()].concat()
}

/// Builds the canonical state key for a published compact AFT publication frontier.
pub fn aft_publication_frontier_key(height: u64) -> Vec<u8> {
    [AFT_PUBLICATION_FRONTIER_PREFIX, &height.to_be_bytes()].concat()
}

/// Builds the canonical state key for a published AFT publication-frontier contradiction object.
pub fn aft_publication_frontier_contradiction_key(height: u64) -> Vec<u8> {
    [AFT_PUBLICATION_CONTRADICTION_PREFIX, &height.to_be_bytes()].concat()
}

/// Builds the canonical state key for an exploratory AFT recovery capsule.
pub fn aft_recovery_capsule_key(height: u64) -> Vec<u8> {
    [AFT_RECOVERY_CAPSULE_PREFIX, &height.to_be_bytes()].concat()
}

/// Builds the canonical state key for an exploratory AFT recovery witness certificate.
pub fn aft_recovery_witness_certificate_key(
    height: u64,
    witness_manifest_hash: &[u8; 32],
) -> Vec<u8> {
    [
        AFT_RECOVERY_WITNESS_CERTIFICATE_PREFIX,
        &height.to_be_bytes(),
        witness_manifest_hash.as_ref(),
    ]
    .concat()
}

/// Builds the prefix for exploratory AFT recovery share receipts for one witness at one height.
pub fn aft_recovery_share_receipt_prefix(height: u64, witness_manifest_hash: &[u8; 32]) -> Vec<u8> {
    [
        AFT_RECOVERY_SHARE_RECEIPT_PREFIX,
        &height.to_be_bytes(),
        witness_manifest_hash.as_ref(),
    ]
    .concat()
}

/// Builds the canonical state key for an exploratory AFT recovery share receipt.
pub fn aft_recovery_share_receipt_key(
    height: u64,
    witness_manifest_hash: &[u8; 32],
    block_commitment_hash: &[u8; 32],
) -> Vec<u8> {
    [
        AFT_RECOVERY_SHARE_RECEIPT_PREFIX,
        &height.to_be_bytes(),
        witness_manifest_hash.as_ref(),
        block_commitment_hash.as_ref(),
    ]
    .concat()
}

/// Builds the prefix for exploratory AFT recovery share-reveal material for one witness at one height.
pub fn aft_recovery_share_material_prefix(
    height: u64,
    witness_manifest_hash: &[u8; 32],
) -> Vec<u8> {
    [
        AFT_RECOVERY_SHARE_MATERIAL_PREFIX,
        &height.to_be_bytes(),
        witness_manifest_hash.as_ref(),
    ]
    .concat()
}

/// Builds the canonical state key for exploratory AFT recovery share-reveal material.
pub fn aft_recovery_share_material_key(
    height: u64,
    witness_manifest_hash: &[u8; 32],
    block_commitment_hash: &[u8; 32],
) -> Vec<u8> {
    [
        AFT_RECOVERY_SHARE_MATERIAL_PREFIX,
        &height.to_be_bytes(),
        witness_manifest_hash.as_ref(),
        block_commitment_hash.as_ref(),
    ]
    .concat()
}

/// Builds the prefix for compact recovered-publication bundle objects for one slot surface.
pub fn aft_recovered_publication_bundle_prefix(
    height: u64,
    block_commitment_hash: &[u8; 32],
) -> Vec<u8> {
    [
        AFT_RECOVERED_PUBLICATION_BUNDLE_PREFIX,
        &height.to_be_bytes(),
        block_commitment_hash.as_ref(),
    ]
    .concat()
}

/// Builds the canonical state key for one compact recovered-publication bundle object.
pub fn aft_recovered_publication_bundle_key(
    height: u64,
    block_commitment_hash: &[u8; 32],
    supporting_witness_manifest_hashes: &[[u8; 32]],
) -> Result<Vec<u8>, String> {
    let support_hash =
        canonical_recovered_publication_bundle_support_hash(supporting_witness_manifest_hashes)?;
    Ok([
        AFT_RECOVERED_PUBLICATION_BUNDLE_PREFIX,
        &height.to_be_bytes(),
        block_commitment_hash.as_ref(),
        support_hash.as_ref(),
    ]
    .concat())
}

/// Builds the prefix for archived recovered-history segment descriptors that start at one height.
pub fn aft_archived_recovered_history_segment_prefix(start_height: u64) -> Vec<u8> {
    [
        AFT_ARCHIVED_RECOVERED_HISTORY_SEGMENT_PREFIX,
        &start_height.to_be_bytes(),
    ]
    .concat()
}

/// Builds the canonical state key for one archived recovered-history segment descriptor.
pub fn aft_archived_recovered_history_segment_key(start_height: u64, end_height: u64) -> Vec<u8> {
    [
        AFT_ARCHIVED_RECOVERED_HISTORY_SEGMENT_PREFIX,
        &start_height.to_be_bytes(),
        &end_height.to_be_bytes(),
    ]
    .concat()
}

/// Builds the canonical state key for one content-addressed archived recovered-history segment descriptor.
pub fn aft_archived_recovered_history_segment_hash_key(segment_hash: &[u8; 32]) -> Vec<u8> {
    [
        AFT_ARCHIVED_RECOVERED_HISTORY_SEGMENT_HASH_PREFIX,
        segment_hash.as_ref(),
    ]
    .concat()
}

/// Builds the canonical state key for one content-addressed archived recovered-history profile.
pub fn aft_archived_recovered_history_profile_hash_key(profile_hash: &[u8; 32]) -> Vec<u8> {
    [
        AFT_ARCHIVED_RECOVERED_HISTORY_PROFILE_HASH_PREFIX,
        profile_hash.as_ref(),
    ]
    .concat()
}

/// Builds the canonical state key for one archived recovered-history profile activation by
/// profile hash.
pub fn aft_archived_recovered_history_profile_activation_key(profile_hash: &[u8; 32]) -> Vec<u8> {
    [
        AFT_ARCHIVED_RECOVERED_HISTORY_PROFILE_ACTIVATION_PREFIX,
        profile_hash.as_ref(),
    ]
    .concat()
}

/// Builds the canonical state key for one archived recovered-history profile activation by
/// activation end height.
pub fn aft_archived_recovered_history_profile_activation_height_key(
    activation_end_height: u64,
) -> Vec<u8> {
    [
        AFT_ARCHIVED_RECOVERED_HISTORY_PROFILE_ACTIVATION_HEIGHT_PREFIX,
        &activation_end_height.to_be_bytes(),
    ]
    .concat()
}

/// Builds the canonical state key for one content-addressed archived recovered-history profile
/// activation.
pub fn aft_archived_recovered_history_profile_activation_hash_key(
    activation_hash: &[u8; 32],
) -> Vec<u8> {
    [
        AFT_ARCHIVED_RECOVERED_HISTORY_PROFILE_ACTIVATION_HASH_PREFIX,
        activation_hash.as_ref(),
    ]
    .concat()
}

/// Builds the canonical state key for one content-addressed archived recovered restart-page payload.
pub fn aft_archived_recovered_restart_page_key(segment_hash: &[u8; 32]) -> Vec<u8> {
    [
        AFT_ARCHIVED_RECOVERED_RESTART_PAGE_PREFIX,
        segment_hash.as_ref(),
    ]
    .concat()
}

/// Builds the canonical state key for one archived recovered-history checkpoint descriptor.
pub fn aft_archived_recovered_history_checkpoint_key(
    start_height: u64,
    end_height: u64,
) -> Vec<u8> {
    [
        AFT_ARCHIVED_RECOVERED_HISTORY_CHECKPOINT_PREFIX,
        &start_height.to_be_bytes(),
        &end_height.to_be_bytes(),
    ]
    .concat()
}

/// Builds the canonical state key for one content-addressed archived recovered-history checkpoint.
pub fn aft_archived_recovered_history_checkpoint_hash_key(checkpoint_hash: &[u8; 32]) -> Vec<u8> {
    [
        AFT_ARCHIVED_RECOVERED_HISTORY_CHECKPOINT_HASH_PREFIX,
        checkpoint_hash.as_ref(),
    ]
    .concat()
}

/// Builds the canonical state key for one archived recovered-history retention receipt.
pub fn aft_archived_recovered_history_retention_receipt_key(checkpoint_hash: &[u8; 32]) -> Vec<u8> {
    [
        AFT_ARCHIVED_RECOVERED_HISTORY_RETENTION_RECEIPT_PREFIX,
        checkpoint_hash.as_ref(),
    ]
    .concat()
}

/// Builds the canonical state key for an exploratory missing AFT recovery share claim.
pub fn aft_missing_recovery_share_key(height: u64, witness_manifest_hash: &[u8; 32]) -> Vec<u8> {
    [
        AFT_MISSING_RECOVERY_SHARE_PREFIX,
        &height.to_be_bytes(),
        witness_manifest_hash.as_ref(),
    ]
    .concat()
}

/// Builds the canonical state key for the protocol-wide AFT collapse object.
pub fn aft_canonical_collapse_object_key(height: u64) -> Vec<u8> {
    [AFT_COLLAPSE_OBJECT_PREFIX, &height.to_be_bytes()].concat()
}

/// Builds the canonical state key for an AFT omission proof.
pub fn aft_omission_proof_key(height: u64, tx_hash: &[u8; 32]) -> Vec<u8> {
    [
        AFT_OMISSION_PROOF_PREFIX,
        &height.to_be_bytes(),
        tx_hash.as_ref(),
    ]
    .concat()
}
