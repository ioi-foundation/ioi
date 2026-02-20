// Path: crates/services/src/wallet_network/handlers/channel.rs

use crate::wallet_network::keys::{
    channel_key, channel_key_state_key, receipt_commit_key, receipt_window_key,
};
use crate::wallet_network::support::{
    append_audit_event, base_audit_metadata, block_timestamp_ms, hash_bytes, load_typed,
    store_typed,
};
use crate::wallet_network::validation::{
    validate_channel_close_hybrid_signature, validate_channel_open_ack_hybrid_signature,
    validate_channel_open_confirm_hybrid_signature, validate_channel_open_init,
    validate_channel_open_init_hybrid_signature, validate_channel_open_try_hybrid_signature,
    validate_receipt_commit_hybrid_signature,
};
use crate::wallet_network::ReceiptReplayWindowState;
use ioi_api::state::StateAccess;
use ioi_api::transaction::context::TxContext;
use ioi_types::app::wallet_network::{
    SessionChannelClose, SessionChannelKeyState, SessionChannelOpenAck, SessionChannelOpenConfirm,
    SessionChannelOpenInit, SessionChannelOpenTry, SessionChannelRecord, SessionChannelState,
    SessionReceiptCommit, VaultAuditEventKind,
};
use ioi_types::codec;
use ioi_types::error::TransactionError;

const KEM_TRANSCRIPT_VERSION: u16 = 1;
const UNORDERED_RECEIPT_REPLAY_WINDOW: u64 = 512;

pub(crate) fn open_channel_init(
    state: &mut dyn StateAccess,
    ctx: &TxContext<'_>,
    open: SessionChannelOpenInit,
) -> Result<(), TransactionError> {
    let now_ms = block_timestamp_ms(ctx);
    validate_channel_open_init(&open, now_ms)?;
    validate_channel_open_init_hybrid_signature(&open)?;

    let channel_id = open.envelope.channel_id;
    let channel_state_key = channel_key(&channel_id);
    if state.get(&channel_state_key)?.is_some() {
        return Err(TransactionError::Invalid(
            "channel already exists".to_string(),
        ));
    }

    let envelope_hash = hash_channel_envelope(&open)?;
    let channel = SessionChannelRecord {
        envelope: open.envelope.clone(),
        state: SessionChannelState::OpenInit,
        envelope_hash,
        opened_at_ms: None,
        closed_at_ms: None,
        last_seq: 0,
        close_reason: None,
    };
    store_typed(state, &channel_state_key, &channel)?;

    let key_state = SessionChannelKeyState {
        channel_id,
        envelope_hash,
        transcript_version: KEM_TRANSCRIPT_VERSION,
        kem_transcript_hash: hash_open_init_kem_transcript(envelope_hash, &open)?,
        lc_kem_ephemeral_pub_classical_hash: hash_bytes(&open.lc_kem_ephemeral_pub_classical)?,
        lc_kem_ephemeral_pub_pq_hash: hash_bytes(&open.lc_kem_ephemeral_pub_pq)?,
        rc_kem_ephemeral_pub_classical_hash: None,
        rc_kem_ciphertext_pq_hash: None,
        nonce_lc: open.nonce_lc,
        nonce_rc: None,
        nonce_lc2: None,
        nonce_rc2: None,
        derived_channel_secret_hash: None,
        key_epoch: 0,
        ready: false,
        updated_at_ms: now_ms,
    };
    let channel_key_state = channel_key_state_key(&channel_id);
    store_typed(state, &channel_key_state, &key_state)?;

    let mut meta = base_audit_metadata(ctx);
    meta.insert("channel_id".to_string(), hex::encode(channel_id));
    meta.insert("envelope_hash".to_string(), hex::encode(envelope_hash));
    meta.insert(
        "kem_transcript_hash".to_string(),
        hex::encode(key_state.kem_transcript_hash),
    );
    append_audit_event(
        state,
        ctx,
        VaultAuditEventKind::ChannelOpenInitAccepted,
        meta,
    )?;
    Ok(())
}

pub(crate) fn open_channel_try(
    state: &mut dyn StateAccess,
    ctx: &TxContext<'_>,
    open_try: SessionChannelOpenTry,
) -> Result<(), TransactionError> {
    if open_try.channel_id == [0u8; 32] {
        return Err(TransactionError::Invalid(
            "channel_id must not be all zeroes".to_string(),
        ));
    }
    if open_try.envelope_hash == [0u8; 32] {
        return Err(TransactionError::Invalid(
            "envelope_hash must not be all zeroes".to_string(),
        ));
    }
    if open_try.nonce_rc == [0u8; 32] {
        return Err(TransactionError::Invalid(
            "nonce_rc must not be all zeroes".to_string(),
        ));
    }

    let channel_state_key = channel_key(&open_try.channel_id);
    let mut channel: SessionChannelRecord = load_typed(state, &channel_state_key)?
        .ok_or_else(|| TransactionError::Invalid("channel does not exist".to_string()))?;
    if channel.state != SessionChannelState::OpenInit {
        return Err(TransactionError::Invalid(
            "channel is not awaiting open_try".to_string(),
        ));
    }
    if channel.envelope_hash != open_try.envelope_hash {
        return Err(TransactionError::Invalid(
            "open_try envelope_hash does not match channel envelope".to_string(),
        ));
    }
    let channel_key_state = channel_key_state_key(&open_try.channel_id);
    let mut key_state: SessionChannelKeyState = load_typed(state, &channel_key_state)?
        .ok_or_else(|| TransactionError::Invalid("channel key state is missing".to_string()))?;
    if key_state.envelope_hash != open_try.envelope_hash {
        return Err(TransactionError::Invalid(
            "open_try envelope_hash does not match key-state envelope hash".to_string(),
        ));
    }
    validate_channel_open_try_hybrid_signature(&open_try, channel.envelope.rc_id)?;

    key_state.rc_kem_ephemeral_pub_classical_hash =
        Some(hash_bytes(&open_try.rc_kem_ephemeral_pub_classical)?);
    key_state.rc_kem_ciphertext_pq_hash = Some(hash_bytes(&open_try.rc_kem_ciphertext_pq)?);
    key_state.nonce_rc = Some(open_try.nonce_rc);
    key_state.kem_transcript_hash = roll_kem_transcript(
        key_state.kem_transcript_hash,
        b"open_try",
        &[
            &open_try.rc_kem_ephemeral_pub_classical,
            &open_try.rc_kem_ciphertext_pq,
            open_try.nonce_rc.as_slice(),
        ],
    )?;
    key_state.updated_at_ms = block_timestamp_ms(ctx);
    store_typed(state, &channel_key_state, &key_state)?;

    channel.state = SessionChannelState::OpenTry;
    store_typed(state, &channel_state_key, &channel)?;

    let mut meta = base_audit_metadata(ctx);
    meta.insert("channel_id".to_string(), hex::encode(open_try.channel_id));
    meta.insert(
        "envelope_hash".to_string(),
        hex::encode(open_try.envelope_hash),
    );
    append_audit_event(
        state,
        ctx,
        VaultAuditEventKind::ChannelOpenTryAccepted,
        meta,
    )?;
    Ok(())
}

pub(crate) fn open_channel_ack(
    state: &mut dyn StateAccess,
    ctx: &TxContext<'_>,
    open_ack: SessionChannelOpenAck,
) -> Result<(), TransactionError> {
    if open_ack.channel_id == [0u8; 32] {
        return Err(TransactionError::Invalid(
            "channel_id must not be all zeroes".to_string(),
        ));
    }
    if open_ack.envelope_hash == [0u8; 32] {
        return Err(TransactionError::Invalid(
            "envelope_hash must not be all zeroes".to_string(),
        ));
    }

    let channel_state_key = channel_key(&open_ack.channel_id);
    let mut channel: SessionChannelRecord = load_typed(state, &channel_state_key)?
        .ok_or_else(|| TransactionError::Invalid("channel does not exist".to_string()))?;
    if channel.state != SessionChannelState::OpenTry {
        return Err(TransactionError::Invalid(
            "channel is not awaiting open_ack".to_string(),
        ));
    }
    if channel.envelope_hash != open_ack.envelope_hash {
        return Err(TransactionError::Invalid(
            "open_ack envelope_hash does not match channel envelope".to_string(),
        ));
    }
    let channel_key_state = channel_key_state_key(&open_ack.channel_id);
    let mut key_state: SessionChannelKeyState = load_typed(state, &channel_key_state)?
        .ok_or_else(|| TransactionError::Invalid("channel key state is missing".to_string()))?;
    if key_state.envelope_hash != open_ack.envelope_hash {
        return Err(TransactionError::Invalid(
            "open_ack envelope_hash does not match key-state envelope hash".to_string(),
        ));
    }
    validate_channel_open_ack_hybrid_signature(&open_ack, channel.envelope.lc_id)?;

    key_state.nonce_lc2 = Some(open_ack.nonce_lc2);
    key_state.kem_transcript_hash = roll_kem_transcript(
        key_state.kem_transcript_hash,
        b"open_ack",
        &[open_ack.nonce_lc2.as_slice()],
    )?;
    key_state.updated_at_ms = block_timestamp_ms(ctx);
    store_typed(state, &channel_key_state, &key_state)?;

    channel.state = SessionChannelState::OpenAck;
    store_typed(state, &channel_state_key, &channel)?;
    Ok(())
}

pub(crate) fn open_channel_confirm(
    state: &mut dyn StateAccess,
    ctx: &TxContext<'_>,
    open_confirm: SessionChannelOpenConfirm,
) -> Result<(), TransactionError> {
    if open_confirm.channel_id == [0u8; 32] {
        return Err(TransactionError::Invalid(
            "channel_id must not be all zeroes".to_string(),
        ));
    }
    if open_confirm.envelope_hash == [0u8; 32] {
        return Err(TransactionError::Invalid(
            "envelope_hash must not be all zeroes".to_string(),
        ));
    }

    let channel_state_key = channel_key(&open_confirm.channel_id);
    let mut channel: SessionChannelRecord = load_typed(state, &channel_state_key)?
        .ok_or_else(|| TransactionError::Invalid("channel does not exist".to_string()))?;
    if channel.state != SessionChannelState::OpenAck {
        return Err(TransactionError::Invalid(
            "channel is not awaiting open_confirm".to_string(),
        ));
    }
    if channel.envelope_hash != open_confirm.envelope_hash {
        return Err(TransactionError::Invalid(
            "open_confirm envelope_hash does not match channel envelope".to_string(),
        ));
    }
    let channel_key_state = channel_key_state_key(&open_confirm.channel_id);
    let mut key_state: SessionChannelKeyState = load_typed(state, &channel_key_state)?
        .ok_or_else(|| TransactionError::Invalid("channel key state is missing".to_string()))?;
    if key_state.envelope_hash != open_confirm.envelope_hash {
        return Err(TransactionError::Invalid(
            "open_confirm envelope_hash does not match key-state envelope hash".to_string(),
        ));
    }
    validate_channel_open_confirm_hybrid_signature(&open_confirm, channel.envelope.rc_id)?;

    key_state.nonce_rc2 = Some(open_confirm.nonce_rc2);
    key_state.kem_transcript_hash = roll_kem_transcript(
        key_state.kem_transcript_hash,
        b"open_confirm",
        &[open_confirm.nonce_rc2.as_slice()],
    )?;
    key_state.derived_channel_secret_hash = Some(derive_channel_secret_hash(&channel, &key_state)?);
    key_state.key_epoch = key_state.key_epoch.max(1);
    key_state.ready = true;
    key_state.updated_at_ms = block_timestamp_ms(ctx);
    store_typed(state, &channel_key_state, &key_state)?;

    channel.state = SessionChannelState::Open;
    channel.opened_at_ms = Some(block_timestamp_ms(ctx));
    store_typed(state, &channel_state_key, &channel)?;

    let mut meta = base_audit_metadata(ctx);
    meta.insert(
        "channel_id".to_string(),
        hex::encode(open_confirm.channel_id),
    );
    meta.insert(
        "envelope_hash".to_string(),
        hex::encode(open_confirm.envelope_hash),
    );
    meta.insert(
        "kem_transcript_hash".to_string(),
        hex::encode(key_state.kem_transcript_hash),
    );
    meta.insert("key_epoch".to_string(), key_state.key_epoch.to_string());
    append_audit_event(state, ctx, VaultAuditEventKind::ChannelOpened, meta)?;
    Ok(())
}

pub(crate) fn close_channel(
    state: &mut dyn StateAccess,
    ctx: &TxContext<'_>,
    close: SessionChannelClose,
) -> Result<(), TransactionError> {
    if close.channel_id == [0u8; 32] {
        return Err(TransactionError::Invalid(
            "channel_id must not be all zeroes".to_string(),
        ));
    }

    let channel_state_key = channel_key(&close.channel_id);
    let mut channel: SessionChannelRecord = load_typed(state, &channel_state_key)?
        .ok_or_else(|| TransactionError::Invalid("channel does not exist".to_string()))?;
    if channel.state == SessionChannelState::Closed {
        return Err(TransactionError::Invalid(
            "channel already closed".to_string(),
        ));
    }
    if close.final_seq < channel.last_seq {
        return Err(TransactionError::Invalid(
            "final_seq must be >= channel last_seq".to_string(),
        ));
    }
    validate_channel_close_hybrid_signature(
        &close,
        channel.envelope.lc_id,
        channel.envelope.rc_id,
    )?;

    channel.state = SessionChannelState::Closed;
    channel.closed_at_ms = Some(block_timestamp_ms(ctx));
    channel.last_seq = close.final_seq;
    channel.close_reason = Some(close.reason);
    store_typed(state, &channel_state_key, &channel)?;

    let channel_key_state = channel_key_state_key(&close.channel_id);
    if let Some(mut key_state) = load_typed::<SessionChannelKeyState>(state, &channel_key_state)? {
        key_state.ready = false;
        key_state.updated_at_ms = block_timestamp_ms(ctx);
        store_typed(state, &channel_key_state, &key_state)?;
    }

    let mut meta = base_audit_metadata(ctx);
    meta.insert("channel_id".to_string(), hex::encode(close.channel_id));
    meta.insert("reason".to_string(), format!("{:?}", close.reason));
    meta.insert("final_seq".to_string(), close.final_seq.to_string());
    append_audit_event(state, ctx, VaultAuditEventKind::ChannelClosed, meta)?;
    Ok(())
}

pub(crate) fn commit_receipt_root(
    state: &mut dyn StateAccess,
    ctx: &TxContext<'_>,
    mut receipt_commit: SessionReceiptCommit,
) -> Result<(), TransactionError> {
    if receipt_commit.channel_id == [0u8; 32] {
        return Err(TransactionError::Invalid(
            "channel_id must not be all zeroes".to_string(),
        ));
    }
    if receipt_commit.end_seq < receipt_commit.start_seq {
        return Err(TransactionError::Invalid(
            "receipt commit end_seq must be >= start_seq".to_string(),
        ));
    }
    if receipt_commit.merkle_root == [0u8; 32] {
        return Err(TransactionError::Invalid(
            "receipt commit merkle_root must not be all zeroes".to_string(),
        ));
    }

    let channel_state_key = channel_key(&receipt_commit.channel_id);
    let mut channel: SessionChannelRecord = load_typed(state, &channel_state_key)?
        .ok_or_else(|| TransactionError::Invalid("channel does not exist".to_string()))?;
    if !matches!(
        channel.state,
        SessionChannelState::Open | SessionChannelState::Closed
    ) {
        return Err(TransactionError::Invalid(
            "channel is not active for receipt commits".to_string(),
        ));
    }
    validate_receipt_commit_hybrid_signature(
        &receipt_commit,
        channel.envelope.lc_id,
        channel.envelope.rc_id,
    )?;
    if receipt_commit.committed_at_ms == 0 {
        receipt_commit.committed_at_ms = block_timestamp_ms(ctx);
    }
    if receipt_commit.commit_id == [0u8; 32] {
        receipt_commit.commit_id = derive_receipt_commit_id(&receipt_commit)?;
    }

    let window_key = receipt_window_key(&receipt_commit.channel_id, receipt_commit.direction);
    let mut replay_window = load_typed::<ReceiptReplayWindowState>(state, &window_key)?.unwrap_or(
        ReceiptReplayWindowState {
            channel_id: receipt_commit.channel_id,
            direction: receipt_commit.direction,
            ordering: channel.envelope.ordering,
            highest_end_seq: 0,
            seen_end_seqs: Default::default(),
        },
    );
    if replay_window.channel_id != receipt_commit.channel_id
        || replay_window.direction != receipt_commit.direction
    {
        return Err(TransactionError::Invalid(
            "receipt replay window binding mismatch".to_string(),
        ));
    }
    if replay_window.ordering != channel.envelope.ordering {
        return Err(TransactionError::Invalid(
            "receipt replay ordering mismatch with channel envelope".to_string(),
        ));
    }
    enforce_receipt_replay_window(&mut replay_window, &receipt_commit)?;

    let key = receipt_commit_key(
        &receipt_commit.channel_id,
        receipt_commit.direction,
        receipt_commit.end_seq,
    );
    if state.get(&key)?.is_some() {
        return Err(TransactionError::Invalid(
            "receipt commit already exists for direction/end_seq".to_string(),
        ));
    }
    store_typed(state, &key, &receipt_commit)?;
    store_typed(state, &window_key, &replay_window)?;

    channel.last_seq = channel.last_seq.max(receipt_commit.end_seq);
    store_typed(state, &channel_state_key, &channel)?;

    let mut meta = base_audit_metadata(ctx);
    meta.insert(
        "channel_id".to_string(),
        hex::encode(receipt_commit.channel_id),
    );
    meta.insert(
        "commit_id".to_string(),
        hex::encode(receipt_commit.commit_id),
    );
    meta.insert(
        "direction".to_string(),
        format!("{:?}", receipt_commit.direction),
    );
    meta.insert(
        "ordering".to_string(),
        format!("{:?}", replay_window.ordering),
    );
    meta.insert(
        "start_seq".to_string(),
        receipt_commit.start_seq.to_string(),
    );
    meta.insert("end_seq".to_string(), receipt_commit.end_seq.to_string());
    meta.insert(
        "highest_end_seq".to_string(),
        replay_window.highest_end_seq.to_string(),
    );
    append_audit_event(state, ctx, VaultAuditEventKind::ReceiptCommitted, meta)?;
    Ok(())
}

fn enforce_receipt_replay_window(
    replay_window: &mut ReceiptReplayWindowState,
    receipt_commit: &SessionReceiptCommit,
) -> Result<(), TransactionError> {
    match replay_window.ordering {
        ioi_types::app::wallet_network::SessionChannelOrdering::Ordered => {
            let expected_start =
                if replay_window.seen_end_seqs.is_empty() && replay_window.highest_end_seq == 0 {
                    0
                } else {
                    replay_window.highest_end_seq.saturating_add(1)
                };
            if receipt_commit.start_seq != expected_start {
                return Err(TransactionError::Invalid(format!(
                    "ordered receipt commit start_seq {} does not match expected {}",
                    receipt_commit.start_seq, expected_start
                )));
            }
            if receipt_commit.end_seq < expected_start {
                return Err(TransactionError::Invalid(
                    "ordered receipt commit end_seq is below expected start".to_string(),
                ));
            }
            replay_window.highest_end_seq = receipt_commit.end_seq;
            replay_window.seen_end_seqs.clear();
            replay_window.seen_end_seqs.insert(receipt_commit.end_seq);
            Ok(())
        }
        ioi_types::app::wallet_network::SessionChannelOrdering::Unordered => {
            if replay_window
                .seen_end_seqs
                .contains(&receipt_commit.end_seq)
            {
                return Err(TransactionError::Invalid(
                    "unordered receipt replay detected for end_seq".to_string(),
                ));
            }
            if receipt_commit
                .end_seq
                .saturating_add(UNORDERED_RECEIPT_REPLAY_WINDOW)
                < replay_window.highest_end_seq
            {
                return Err(TransactionError::Invalid(
                    "unordered receipt commit is outside replay window".to_string(),
                ));
            }
            replay_window.highest_end_seq =
                replay_window.highest_end_seq.max(receipt_commit.end_seq);
            replay_window.seen_end_seqs.insert(receipt_commit.end_seq);
            let min_allowed = replay_window
                .highest_end_seq
                .saturating_sub(UNORDERED_RECEIPT_REPLAY_WINDOW);
            replay_window
                .seen_end_seqs
                .retain(|seq| *seq >= min_allowed);
            Ok(())
        }
    }
}

pub(crate) fn hash_channel_envelope(
    open: &SessionChannelOpenInit,
) -> Result<[u8; 32], TransactionError> {
    let bytes = codec::to_bytes_canonical(&open.envelope)?;
    hash_bytes(&bytes)
}

fn hash_open_init_kem_transcript(
    envelope_hash: [u8; 32],
    open: &SessionChannelOpenInit,
) -> Result<[u8; 32], TransactionError> {
    hash_labeled_transcript_material(
        b"wallet_network.kem_transcript.v1.open_init",
        &[
            envelope_hash.as_slice(),
            &open.lc_kem_ephemeral_pub_classical,
            &open.lc_kem_ephemeral_pub_pq,
            open.nonce_lc.as_slice(),
        ],
    )
}

fn roll_kem_transcript(
    previous_hash: [u8; 32],
    stage: &[u8],
    components: &[&[u8]],
) -> Result<[u8; 32], TransactionError> {
    let mut material = Vec::new();
    material.extend_from_slice(&previous_hash);
    material.extend_from_slice(&(stage.len() as u64).to_le_bytes());
    material.extend_from_slice(stage);
    for component in components {
        material.extend_from_slice(&(component.len() as u64).to_le_bytes());
        material.extend_from_slice(component);
    }
    hash_labeled_transcript_material(b"wallet_network.kem_transcript.v1.roll", &[&material])
}

fn hash_labeled_transcript_material(
    label: &[u8],
    components: &[&[u8]],
) -> Result<[u8; 32], TransactionError> {
    let mut material = Vec::new();
    material.extend_from_slice(&(label.len() as u64).to_le_bytes());
    material.extend_from_slice(label);
    for component in components {
        material.extend_from_slice(&(component.len() as u64).to_le_bytes());
        material.extend_from_slice(component);
    }
    hash_bytes(&material)
}

fn derive_channel_secret_hash(
    channel: &SessionChannelRecord,
    key_state: &SessionChannelKeyState,
) -> Result<[u8; 32], TransactionError> {
    let mut material = Vec::new();
    material.extend_from_slice(b"wallet_network.channel_secret.v1");
    material.extend_from_slice(&channel.envelope_hash);
    material.extend_from_slice(&key_state.kem_transcript_hash);
    material.extend_from_slice(&channel.envelope.policy_hash);
    material.extend_from_slice(&channel.envelope.policy_version.to_le_bytes());
    material.extend_from_slice(&channel.envelope.lc_id);
    material.extend_from_slice(&channel.envelope.rc_id);
    material.extend_from_slice(&key_state.lc_kem_ephemeral_pub_classical_hash);
    material.extend_from_slice(&key_state.lc_kem_ephemeral_pub_pq_hash);
    material.extend_from_slice(&key_state.nonce_lc);
    if let Some(value) = key_state.rc_kem_ephemeral_pub_classical_hash {
        material.extend_from_slice(&value);
    }
    if let Some(value) = key_state.rc_kem_ciphertext_pq_hash {
        material.extend_from_slice(&value);
    }
    if let Some(value) = key_state.nonce_rc {
        material.extend_from_slice(&value);
    }
    if let Some(value) = key_state.nonce_lc2 {
        material.extend_from_slice(&value);
    }
    if let Some(value) = key_state.nonce_rc2 {
        material.extend_from_slice(&value);
    }
    hash_bytes(&material)
}

fn derive_receipt_commit_id(commit: &SessionReceiptCommit) -> Result<[u8; 32], TransactionError> {
    let bytes = codec::to_bytes_canonical(commit)?;
    hash_bytes(&bytes)
}
