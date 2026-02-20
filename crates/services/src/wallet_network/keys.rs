// Path: crates/services/src/wallet_network/keys.rs

use ioi_types::app::wallet_network::SessionReceiptCommitDirection;

pub(super) const IDENTITY_KEY: &[u8] = b"identity";
pub(super) const SECRET_PREFIX: &[u8] = b"secret::";
pub(super) const SECRET_ALIAS_PREFIX: &[u8] = b"secret_alias::";
pub(super) const POLICY_PREFIX: &[u8] = b"policy::";
pub(super) const SESSION_PREFIX: &[u8] = b"session::";
pub(super) const SESSION_DELEGATION_PREFIX: &[u8] = b"session_delegation::";
pub(super) const INJECTION_GRANT_PREFIX: &[u8] = b"injection_grant::";
pub(super) const INJECTION_REQUEST_PREFIX: &[u8] = b"injection_request::";
pub(super) const INJECTION_ATTESTATION_PREFIX: &[u8] = b"injection_attestation::";
pub(super) const INTERCEPTION_PREFIX: &[u8] = b"interception::";
pub(super) const APPROVAL_PREFIX: &[u8] = b"approval::";
pub(super) const APPROVAL_CONSUMPTION_PREFIX: &[u8] = b"approval_consumption::";
pub(super) const CHANNEL_PREFIX: &[u8] = b"channel::";
pub(super) const CHANNEL_KEY_STATE_PREFIX: &[u8] = b"channel_key_state::";
pub(super) const LEASE_PREFIX: &[u8] = b"lease::";
pub(super) const LEASE_REPLAY_PREFIX: &[u8] = b"lease_replay::";
pub(super) const LEASE_COUNTER_WINDOW_PREFIX: &[u8] = b"lease_counter_window::";
pub(super) const RECEIPT_COMMIT_PREFIX: &[u8] = b"receipt_commit::";
pub(super) const RECEIPT_WINDOW_PREFIX: &[u8] = b"receipt_window::";
pub(super) const AUDIT_PREFIX: &[u8] = b"audit::";
pub(super) const AUDIT_NEXT_SEQ_KEY: &[u8] = b"audit::next_seq";
pub(super) const AUDIT_HEAD_HASH_KEY: &[u8] = b"audit::head_hash";
pub(super) const REVOCATION_EPOCH_KEY: &[u8] = b"revocation_epoch";
pub(super) const PANIC_FLAG_KEY: &[u8] = b"panic";

pub(super) fn secret_key(secret_id: &str) -> Vec<u8> {
    [SECRET_PREFIX, secret_id.as_bytes()].concat()
}

pub(super) fn secret_alias_key(alias: &str) -> Vec<u8> {
    let normalized = alias.trim().to_ascii_lowercase();
    [SECRET_ALIAS_PREFIX, normalized.as_bytes()].concat()
}

pub(super) fn policy_key(rule_id: &str) -> Vec<u8> {
    [POLICY_PREFIX, rule_id.as_bytes()].concat()
}

pub(super) fn session_key(session_id: &[u8; 32]) -> Vec<u8> {
    [SESSION_PREFIX, session_id.as_slice()].concat()
}

pub(super) fn session_delegation_key(session_id: &[u8; 32]) -> Vec<u8> {
    [SESSION_DELEGATION_PREFIX, session_id.as_slice()].concat()
}

pub(super) fn injection_request_key(request_id: &[u8; 32]) -> Vec<u8> {
    [INJECTION_REQUEST_PREFIX, request_id.as_slice()].concat()
}

pub(super) fn injection_attestation_key(request_id: &[u8; 32]) -> Vec<u8> {
    [INJECTION_ATTESTATION_PREFIX, request_id.as_slice()].concat()
}

pub(super) fn injection_grant_key(request_id: &[u8; 32]) -> Vec<u8> {
    [INJECTION_GRANT_PREFIX, request_id.as_slice()].concat()
}

pub(super) fn interception_key(request_hash: &[u8; 32]) -> Vec<u8> {
    [INTERCEPTION_PREFIX, request_hash.as_slice()].concat()
}

pub(super) fn approval_key(request_hash: &[u8; 32]) -> Vec<u8> {
    [APPROVAL_PREFIX, request_hash.as_slice()].concat()
}

pub(super) fn approval_consumption_key(request_hash: &[u8; 32]) -> Vec<u8> {
    [APPROVAL_CONSUMPTION_PREFIX, request_hash.as_slice()].concat()
}

pub(super) fn channel_key(channel_id: &[u8; 32]) -> Vec<u8> {
    [CHANNEL_PREFIX, channel_id.as_slice()].concat()
}

pub(super) fn channel_key_state_key(channel_id: &[u8; 32]) -> Vec<u8> {
    [CHANNEL_KEY_STATE_PREFIX, channel_id.as_slice()].concat()
}

pub(super) fn lease_key(channel_id: &[u8; 32], lease_id: &[u8; 32]) -> Vec<u8> {
    [
        LEASE_PREFIX,
        channel_id.as_slice(),
        b"::",
        lease_id.as_slice(),
    ]
    .concat()
}

pub(super) fn lease_replay_key(channel_id: &[u8; 32], issuer_id: &[u8; 32]) -> Vec<u8> {
    [
        LEASE_REPLAY_PREFIX,
        channel_id.as_slice(),
        b"::",
        issuer_id.as_slice(),
    ]
    .concat()
}

pub(super) fn lease_counter_window_key(channel_id: &[u8; 32], issuer_id: &[u8; 32]) -> Vec<u8> {
    [
        LEASE_COUNTER_WINDOW_PREFIX,
        channel_id.as_slice(),
        b"::",
        issuer_id.as_slice(),
    ]
    .concat()
}

pub(super) fn receipt_commit_key(
    channel_id: &[u8; 32],
    direction: SessionReceiptCommitDirection,
    end_seq: u64,
) -> Vec<u8> {
    let direction_label = match direction {
        SessionReceiptCommitDirection::LocalToRemote => b"l2r".as_slice(),
        SessionReceiptCommitDirection::RemoteToLocal => b"r2l".as_slice(),
    };
    [
        RECEIPT_COMMIT_PREFIX,
        channel_id.as_slice(),
        b"::",
        direction_label,
        b"::",
        &end_seq.to_be_bytes(),
    ]
    .concat()
}

pub(super) fn receipt_window_key(
    channel_id: &[u8; 32],
    direction: SessionReceiptCommitDirection,
) -> Vec<u8> {
    let direction_label = match direction {
        SessionReceiptCommitDirection::LocalToRemote => b"l2r".as_slice(),
        SessionReceiptCommitDirection::RemoteToLocal => b"r2l".as_slice(),
    };
    [
        RECEIPT_WINDOW_PREFIX,
        channel_id.as_slice(),
        b"::",
        direction_label,
    ]
    .concat()
}

pub(super) fn audit_key(seq: u64) -> Vec<u8> {
    [AUDIT_PREFIX, &seq.to_be_bytes()].concat()
}
