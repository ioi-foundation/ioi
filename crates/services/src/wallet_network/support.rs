// Path: crates/services/src/wallet_network/support.rs

use crate::wallet_network::keys::{
    audit_key, AUDIT_HEAD_HASH_KEY, AUDIT_NEXT_SEQ_KEY, IDENTITY_KEY, REVOCATION_EPOCH_KEY,
};
use dcrypt::algorithms::hash::{HashFunction, Sha256};
use ioi_api::state::StateAccess;
use ioi_api::transaction::context::TxContext;
use ioi_types::app::wallet_network::{VaultAuditEvent, VaultAuditEventKind, VaultIdentity};
use ioi_types::codec;
use ioi_types::error::TransactionError;
use parity_scale_codec::{Decode, Encode};
use std::collections::BTreeMap;

pub(super) fn load_revocation_epoch(state: &dyn StateAccess) -> Result<u64, TransactionError> {
    Ok(load_typed(state, REVOCATION_EPOCH_KEY)?.unwrap_or(0))
}

pub(super) fn require_identity(state: &dyn StateAccess) -> Result<VaultIdentity, TransactionError> {
    load_typed(state, IDENTITY_KEY)?.ok_or_else(|| {
        TransactionError::Invalid("wallet identity has not been created".to_string())
    })
}

pub(super) fn append_audit_event(
    state: &mut dyn StateAccess,
    ctx: &TxContext<'_>,
    kind: VaultAuditEventKind,
    metadata: BTreeMap<String, String>,
) -> Result<VaultAuditEvent, TransactionError> {
    let seq: u64 = load_typed(state, AUDIT_NEXT_SEQ_KEY)?.unwrap_or(0);
    let prev_hash: [u8; 32] = load_typed(state, AUDIT_HEAD_HASH_KEY)?.unwrap_or([0u8; 32]);
    let timestamp_ms = block_timestamp_ms(ctx);

    let event_hash = hash_audit_material(&prev_hash, seq, timestamp_ms, &kind, &metadata)?;
    let mut event_id_material = Vec::with_capacity(40);
    event_id_material.extend_from_slice(&seq.to_le_bytes());
    event_id_material.extend_from_slice(&event_hash);
    let event_id = hash_bytes(&event_id_material)?;

    let mut event_metadata = metadata;
    event_metadata.insert("seq".to_string(), seq.to_string());
    event_metadata.insert("prev_hash".to_string(), hex::encode(prev_hash));

    let event = VaultAuditEvent {
        event_id,
        kind,
        timestamp_ms,
        event_hash,
        metadata: event_metadata,
    };
    let key = audit_key(seq);
    store_typed(state, &key, &event)?;
    store_typed(state, AUDIT_NEXT_SEQ_KEY, &seq.saturating_add(1))?;
    store_typed(state, AUDIT_HEAD_HASH_KEY, &event_hash)?;
    Ok(event)
}

fn hash_audit_material(
    prev_hash: &[u8; 32],
    seq: u64,
    timestamp_ms: u64,
    kind: &VaultAuditEventKind,
    metadata: &BTreeMap<String, String>,
) -> Result<[u8; 32], TransactionError> {
    let mut material = Vec::new();
    material.extend_from_slice(prev_hash);
    material.extend_from_slice(&seq.to_le_bytes());
    material.extend_from_slice(&timestamp_ms.to_le_bytes());
    material.extend_from_slice(&codec::to_bytes_canonical(kind)?);
    material.extend_from_slice(&codec::to_bytes_canonical(metadata)?);
    hash_bytes(&material)
}

pub(super) fn hash_bytes(input: &[u8]) -> Result<[u8; 32], TransactionError> {
    let digest = Sha256::digest(input).map_err(|e| TransactionError::Invalid(e.to_string()))?;
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_ref());
    Ok(out)
}

pub(super) fn load_typed<T: Decode>(
    state: &dyn StateAccess,
    key: &[u8],
) -> Result<Option<T>, TransactionError> {
    let Some(raw) = state.get(key)? else {
        return Ok(None);
    };
    Ok(Some(codec::from_bytes_canonical(&raw)?))
}

pub(super) fn store_typed<T: Encode>(
    state: &mut dyn StateAccess,
    key: &[u8],
    value: &T,
) -> Result<(), TransactionError> {
    let bytes = codec::to_bytes_canonical(value)?;
    state.insert(key, &bytes)?;
    Ok(())
}

pub(super) fn base_audit_metadata(ctx: &TxContext<'_>) -> BTreeMap<String, String> {
    let mut metadata = BTreeMap::new();
    metadata.insert(
        "signer_account_id".to_string(),
        hex::encode(ctx.signer_account_id.as_ref()),
    );
    metadata
}

pub(super) fn block_timestamp_ms(ctx: &TxContext<'_>) -> u64 {
    ctx.block_timestamp / 1_000_000
}
