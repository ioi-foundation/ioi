// Path: crates/services/src/wallet_network/support.rs

use crate::wallet_network::keys::{
    audit_key, AUDIT_HEAD_HASH_KEY, AUDIT_NEXT_SEQ_KEY, IDENTITY_KEY, REVOCATION_EPOCH_KEY,
};
use dcrypt::algorithms::hash::{HashFunction, Sha256};
use ioi_api::state::StateAccess;
use ioi_api::transaction::context::TxContext;
use ioi_crypto::key_store::{decrypt_key, encrypt_key};
use ioi_types::app::wallet_network::{VaultAuditEvent, VaultAuditEventKind, VaultIdentity};
use ioi_types::codec;
use ioi_types::error::TransactionError;
use parity_scale_codec::{Decode, Encode};
use std::collections::BTreeMap;

const WALLET_SECRET_PASS_ENV: &str = "IOI_WALLET_SECRET_PASS";
const GUARDIAN_SECRET_PASS_ENV: &str = "IOI_GUARDIAN_KEY_PASS";
const ENCRYPTED_SECRET_MAGIC: &[u8; 8] = b"IOI-GKEY";

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

/// Append an audit event and caller-provided state records in one state batch.
///
/// Security-sensitive transitions use this to keep their immutable record,
/// current-head pointer, and audit-chain advance in the same storage commit.
/// The closure runs after the event id/hash are known so records may bind them
/// without a second mutation or a circular hash dependency.
pub(super) fn append_audit_event_with_records<F>(
    state: &mut dyn StateAccess,
    ctx: &TxContext<'_>,
    kind: VaultAuditEventKind,
    metadata: BTreeMap<String, String>,
    build_records: F,
) -> Result<VaultAuditEvent, TransactionError>
where
    F: FnOnce(&VaultAuditEvent) -> Result<Vec<(Vec<u8>, Vec<u8>)>, TransactionError>,
{
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
    let mut inserts = build_records(&event)?;
    inserts.push((audit_key(seq), codec::to_bytes_canonical(&event)?));
    inserts.push((
        AUDIT_NEXT_SEQ_KEY.to_vec(),
        codec::to_bytes_canonical(&seq.saturating_add(1))?,
    ));
    inserts.push((
        AUDIT_HEAD_HASH_KEY.to_vec(),
        codec::to_bytes_canonical(&event_hash)?,
    ));
    state.batch_apply(&inserts, &[])?;
    Ok(event)
}

/// Recompute the canonical hash/id of a stored audit event at its exact
/// sequence key. This verifies the event's local chain commitment without
/// mutating or broadening the legacy append path.
pub(super) fn verify_audit_event_at_seq(
    event: &VaultAuditEvent,
    seq: u64,
) -> Result<(), TransactionError> {
    if event.metadata.get("seq").map(String::as_str) != Some(seq.to_string().as_str()) {
        return Err(TransactionError::Invalid(
            "wallet_audit_event_invalid: event sequence metadata does not match its state key"
                .to_string(),
        ));
    }
    let prev_hash_hex = event.metadata.get("prev_hash").ok_or_else(|| {
        TransactionError::Invalid(
            "wallet_audit_event_invalid: event is missing prev_hash metadata".to_string(),
        )
    })?;
    let prev_hash_bytes = hex::decode(prev_hash_hex).map_err(|error| {
        TransactionError::Invalid(format!(
            "wallet_audit_event_invalid: prev_hash is not canonical hex: {error}"
        ))
    })?;
    if prev_hash_bytes.len() != 32 || prev_hash_hex.len() != 64 {
        return Err(TransactionError::Invalid(
            "wallet_audit_event_invalid: prev_hash must be exactly 32 bytes".to_string(),
        ));
    }
    let mut prev_hash = [0u8; 32];
    prev_hash.copy_from_slice(&prev_hash_bytes);

    let mut hash_metadata = event.metadata.clone();
    hash_metadata.remove("seq");
    hash_metadata.remove("prev_hash");
    let expected_hash = hash_audit_material(
        &prev_hash,
        seq,
        event.timestamp_ms,
        &event.kind,
        &hash_metadata,
    )?;
    if event.event_hash != expected_hash {
        return Err(TransactionError::Invalid(
            "wallet_audit_event_invalid: event_hash does not match canonical event material"
                .to_string(),
        ));
    }
    let mut event_id_material = Vec::with_capacity(40);
    event_id_material.extend_from_slice(&seq.to_le_bytes());
    event_id_material.extend_from_slice(&expected_hash);
    if event.event_id != hash_bytes(&event_id_material)? {
        return Err(TransactionError::Invalid(
            "wallet_audit_event_invalid: event_id does not match sequence and event_hash"
                .to_string(),
        ));
    }
    Ok(())
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

fn wallet_secret_passphrase() -> String {
    std::env::var(WALLET_SECRET_PASS_ENV)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .or_else(|| {
            std::env::var(GUARDIAN_SECRET_PASS_ENV)
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
        })
        .unwrap_or_else(|| "local-mode".to_string())
}

pub(super) fn is_encrypted_secret_payload(payload: &[u8]) -> bool {
    payload.starts_with(ENCRYPTED_SECRET_MAGIC)
}

pub(super) fn encrypt_secret_payload(plaintext: &[u8]) -> Result<Vec<u8>, TransactionError> {
    encrypt_key(plaintext, &wallet_secret_passphrase())
        .map_err(|e| TransactionError::Invalid(format!("wallet secret encryption failed: {}", e)))
}

pub(super) fn decrypt_secret_payload(payload: &[u8]) -> Result<Vec<u8>, TransactionError> {
    if is_encrypted_secret_payload(payload) {
        return decrypt_key(payload, &wallet_secret_passphrase())
            .map(|value| value.0.clone())
            .map_err(|e| {
                TransactionError::Invalid(format!("wallet secret decryption failed: {}", e))
            });
    }
    Ok(payload.to_vec())
}
