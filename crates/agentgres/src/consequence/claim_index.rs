//! Durable per-store conflict-slot claim index.
//!
//! One `online_query_unanimity_v0` conflict domain/slot is one QUV operation,
//! and its stable key deliberately excludes the manifest's `resource_id`.
//! The external register, however, namespaces its physical record by
//! `resource_id`, so two admitted manifests for one slot with distinct
//! resource identities would otherwise each reach `Claimed` and each mint a
//! register record. This index is the store-local witness that a slot has
//! been claimed by exactly one effect. It is written durably immediately
//! before the `Claimed` receipt is persisted and never removed: a claim file
//! whose effect has no receipt or a still-`Authorized` receipt is the crash
//! window between the two writes and is treated as claimed by that effect.
//!
//! The file grants no execution authority. It only refuses a second effect.
use super::*;

pub(super) const SCHEMA: &str = "ioi.aft-consequence-claim-index.v1";
const DOMAIN: &[u8] = b"ioi::aft::consequence-claim-index::v1\0";
/// Fixed reserved size of one claim file. The record holds two bounded
/// tokens (each at most 512 bytes before JSON escaping), two 32-byte hashes
/// and fixed syntax, and stays far below one allocation unit.
pub(super) const MAX_BYTES: usize = StorageProfile::ALLOCATION_UNIT_BYTES as usize;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ClaimIndexRecordV1 {
    pub schema: String,
    pub idempotency_key: String,
    pub effect_id: String,
    pub manifest_root: ConsequenceHash,
    pub record_root: ConsequenceHash,
}

/// The stable slot key for an online manifest; `None` for portable effects,
/// which never take part in the index.
pub(super) fn key_for(manifest: &EffectManifestV1) -> Result<Option<String>, ConsequenceError> {
    if manifest.authorization_mode != EffectAuthorizationModeV1::OnlineQueryUnanimityV0 {
        return Ok(None);
    }
    manifest
        .query_unanimity_idempotency_key()
        .map(Some)
        .map_err(type_error)
}

pub(super) fn path_for(root: &Path, key: &str) -> PathBuf {
    root.join("claims")
        .join(format!("{}.claim", hex_hash(key.as_bytes())))
}

fn record_root(record: &ClaimIndexRecordV1) -> Result<ConsequenceHash, ConsequenceError> {
    let mut view = record.clone();
    view.record_root = [0; 32];
    canonical_hash(DOMAIN, &view)
}

pub(super) fn record_for(
    key: &str,
    effect_id: &str,
    manifest_root: ConsequenceHash,
) -> Result<ClaimIndexRecordV1, ConsequenceError> {
    let mut record = ClaimIndexRecordV1 {
        schema: SCHEMA.into(),
        idempotency_key: key.into(),
        effect_id: effect_id.into(),
        manifest_root,
        record_root: [0; 32],
    };
    record.record_root = record_root(&record)?;
    Ok(record)
}

/// Canonical bytes, checked against the fixed reservation before any live
/// operation so the claim boundary can never discover an oversize record.
pub(super) fn encode(record: &ClaimIndexRecordV1) -> Result<Vec<u8>, ConsequenceError> {
    let bytes =
        serde_jcs::to_vec(record).map_err(|error| ConsequenceError::Invalid(error.to_string()))?;
    if bytes.len() > MAX_BYTES {
        return Err(ConsequenceError::Invalid(
            "claim index record exceeds its fixed reservation".into(),
        ));
    }
    Ok(bytes)
}

/// Read and fully validate the active claim for `key`. Only an absent
/// directory entry is absent state; an alias, hard link, oversize,
/// non-canonical, mis-keyed or hash-mismatched file refuses as corruption
/// and is never treated as either claimed or unclaimed.
pub(super) fn read(
    path: &Path,
    expected_key: &str,
) -> Result<Option<ClaimIndexRecordV1>, ConsequenceError> {
    let file = match resource_reservation::private_open(path, false) {
        Ok(file) => file,
        Err(ConsequenceError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(None)
        }
        Err(ConsequenceError::Io(error)) if error.raw_os_error() == Some(libc::ELOOP) => {
            return Err(ConsequenceError::CorruptClaimIndex)
        }
        Err(ConsequenceError::CorruptReceipt) => return Err(ConsequenceError::CorruptClaimIndex),
        Err(error) => return Err(error),
    };
    if file.metadata()?.len() > MAX_BYTES as u64 {
        return Err(ConsequenceError::CorruptClaimIndex);
    }
    let mut bytes = Vec::new();
    file.take(MAX_BYTES as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > MAX_BYTES {
        return Err(ConsequenceError::CorruptClaimIndex);
    }
    let record: ClaimIndexRecordV1 =
        serde_json::from_slice(&bytes).map_err(|_| ConsequenceError::CorruptClaimIndex)?;
    let canonical = serde_jcs::to_vec(&record).map_err(|_| ConsequenceError::CorruptClaimIndex)?;
    let initialized_padding = bytes.len() == MAX_BYTES
        && bytes.starts_with(&canonical)
        && bytes[canonical.len()..].iter().all(|byte| *byte == b' ');
    if canonical != bytes && !initialized_padding {
        return Err(ConsequenceError::CorruptClaimIndex);
    }
    if record.schema != SCHEMA
        || record.idempotency_key != expected_key
        || record.effect_id.is_empty()
        || record.effect_id.len() > 512
        || record.manifest_root == [0; 32]
        || record_root(&record)? != record.record_root
    {
        return Err(ConsequenceError::CorruptClaimIndex);
    }
    Ok(Some(record))
}

/// Reserve the space-padded staging file for the reserved storage profile.
/// Called only before the executor's live operation.
pub(super) fn prepare(path: &Path) -> Result<(), ConsequenceError> {
    resource_reservation::prepare_charged(path, MAX_BYTES as u64)
}

/// Publish the claim without allocation. The reserved profile overwrites
/// its initialized staging in place; adapters outside that profile use the
/// ordinary write/fsync/rename path, exactly as their receipts already do.
pub(super) fn commit(path: &Path, bytes: &[u8], reserved: bool) -> Result<(), ConsequenceError> {
    if reserved {
        resource_reservation::commit_charged(path, bytes, MAX_BYTES as u64)
    } else {
        atomic_write(path, bytes)
    }
}
