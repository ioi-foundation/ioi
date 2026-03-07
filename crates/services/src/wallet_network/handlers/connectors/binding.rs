// Path: crates/services/src/wallet_network/handlers/connectors/binding.rs

use super::shared::{
    contains_mail_delete_capability, contains_mail_list_capability, contains_mail_read_capability,
    contains_mail_reply_capability, load_mail_connector_record, normalize_mailbox,
};
use crate::wallet_network::keys::{
    channel_key, lease_key, mail_connector_binding_receipt_key, LEASE_PREFIX,
};
use crate::wallet_network::support::{
    append_audit_event, base_audit_metadata, block_timestamp_ms, hash_bytes, load_revocation_epoch,
    load_typed, store_typed,
};
use ioi_api::state::StateAccess;
use ioi_api::transaction::context::TxContext;
use ioi_types::app::wallet_network::{
    MailConnectorEnsureBindingParams, MailConnectorEnsureBindingReceipt,
    SessionChannelDelegationRules, SessionChannelEnvelope, SessionChannelMode,
    SessionChannelOrdering, SessionChannelRecord, SessionChannelState, SessionLease,
    SessionLeaseMode, VaultAuditEventKind,
};
use ioi_types::codec;
use ioi_types::error::TransactionError;
use std::collections::BTreeMap;

const CHANNEL_TTL_MS: u64 = 24 * 60 * 60 * 1_000;
const LEASE_TTL_MS_DEFAULT: u64 = 12 * 60 * 60 * 1_000;
const LEASE_TTL_MS_MIN: u64 = 60 * 1_000;
const LEASE_TTL_MS_MAX: u64 = CHANNEL_TTL_MS;

fn default_mail_capability_set() -> Vec<String> {
    vec![
        "mail.read.latest".to_string(),
        "mail.read".to_string(),
        "email:read".to_string(),
        "mail.list.recent".to_string(),
        "mail.list".to_string(),
        "email:list".to_string(),
        "mail.delete.spam".to_string(),
        "mail.delete".to_string(),
        "mail.reply".to_string(),
        "mail.send".to_string(),
        "email:send".to_string(),
        "mail.write".to_string(),
        "email:write".to_string(),
        "mail.compose".to_string(),
        "email:compose".to_string(),
        "mail.modify".to_string(),
        "email:modify".to_string(),
    ]
}

fn binding_has_required_mail_capabilities(capabilities: &[String]) -> bool {
    contains_mail_read_capability(capabilities)
        && contains_mail_list_capability(capabilities)
        && contains_mail_delete_capability(capabilities)
        && contains_mail_reply_capability(capabilities)
}

fn mailbox_constraint_matches(constraint: Option<&String>, mailbox: &str) -> bool {
    constraint
        .map(|value| normalize_mailbox(value) == mailbox)
        .unwrap_or(true)
}

fn normalize_requested_lease_ttl_ms(lease_ttl_ms: Option<u64>) -> u64 {
    lease_ttl_ms
        .unwrap_or(LEASE_TTL_MS_DEFAULT)
        .clamp(LEASE_TTL_MS_MIN, LEASE_TTL_MS_MAX)
}

fn derive_seeded_id(
    tag: &[u8],
    request_id: &[u8; 32],
    audience: &[u8; 32],
    mailbox: &str,
    attempt: u8,
) -> Result<[u8; 32], TransactionError> {
    let mut seed = Vec::with_capacity(tag.len() + request_id.len() + audience.len() + 80);
    seed.extend_from_slice(tag);
    seed.extend_from_slice(request_id);
    seed.extend_from_slice(audience);
    seed.extend_from_slice(mailbox.as_bytes());
    seed.push(attempt);
    let mut out = hash_bytes(&seed)?;
    if out == [0u8; 32] {
        out[0] = 1;
    }
    Ok(out)
}

fn find_existing_binding(
    state: &dyn StateAccess,
    mailbox: &str,
    audience: [u8; 32],
    now_ms: u64,
) -> Result<Option<(SessionLease, SessionChannelRecord)>, TransactionError> {
    let mut best: Option<(SessionLease, SessionChannelRecord)> = None;
    let scan = state.prefix_scan(LEASE_PREFIX)?;
    for row in scan {
        let Ok((_, value)) = row else {
            continue;
        };
        let Ok(lease) = codec::from_bytes_canonical::<SessionLease>(&value) else {
            continue;
        };
        if lease.audience != audience || now_ms > lease.expires_at_ms {
            continue;
        }
        if !binding_has_required_mail_capabilities(&lease.capability_subset) {
            continue;
        }
        if !mailbox_constraint_matches(lease.constraints_subset.get("mailbox"), mailbox) {
            continue;
        }

        let Some(channel) =
            load_typed::<SessionChannelRecord>(state, &channel_key(&lease.channel_id))?
        else {
            continue;
        };
        if channel.state != SessionChannelState::Open || now_ms > channel.envelope.expires_at_ms {
            continue;
        }
        if !binding_has_required_mail_capabilities(&channel.envelope.capability_set) {
            continue;
        }
        if !mailbox_constraint_matches(channel.envelope.constraints.get("mailbox"), mailbox) {
            continue;
        }

        let replace = best
            .as_ref()
            .map(|(current_lease, _)| lease.issued_at_ms >= current_lease.issued_at_ms)
            .unwrap_or(true);
        if replace {
            best = Some((lease, channel));
        }
    }
    Ok(best)
}

pub(crate) fn mail_connector_ensure_binding(
    state: &mut dyn StateAccess,
    ctx: &TxContext<'_>,
    params: MailConnectorEnsureBindingParams,
) -> Result<(), TransactionError> {
    if params.request_id == [0u8; 32] {
        return Err(TransactionError::Invalid(
            "request_id must not be all zeroes".to_string(),
        ));
    }

    let mailbox = normalize_mailbox(&params.mailbox);
    let audience = params.audience.unwrap_or(ctx.signer_account_id.0);
    if audience != ctx.signer_account_id.0 {
        return Err(TransactionError::Invalid(
            "mail connector binding audience must match transaction signer".to_string(),
        ));
    }
    let now_ms = block_timestamp_ms(ctx);

    let receipt_key = mail_connector_binding_receipt_key(&params.request_id);
    if state.get(&receipt_key)?.is_some() {
        return Err(TransactionError::Invalid(
            "mail connector binding request_id replay detected".to_string(),
        ));
    }

    // Connector must exist before a channel/lease can be bound.
    let _connector = load_mail_connector_record(state, &mailbox)?;

    let capability_set = default_mail_capability_set();
    if let Some((lease, channel)) = find_existing_binding(state, &mailbox, audience, now_ms)? {
        let receipt = MailConnectorEnsureBindingReceipt {
            request_id: params.request_id,
            mailbox: mailbox.clone(),
            audience,
            channel_id: lease.channel_id,
            lease_id: lease.lease_id,
            reused_existing: true,
            issued_at_ms: lease.issued_at_ms,
            channel_expires_at_ms: channel.envelope.expires_at_ms,
            lease_expires_at_ms: lease.expires_at_ms,
            capability_set: capability_set.clone(),
        };
        store_typed(state, &receipt_key, &receipt)?;

        let mut meta = base_audit_metadata(ctx);
        meta.insert(
            "operation".to_string(),
            "mail_connector_ensure_binding@v1".to_string(),
        );
        meta.insert("request_id".to_string(), hex::encode(params.request_id));
        meta.insert("mailbox".to_string(), mailbox);
        meta.insert("audience".to_string(), hex::encode(audience));
        meta.insert("channel_id".to_string(), hex::encode(lease.channel_id));
        meta.insert("lease_id".to_string(), hex::encode(lease.lease_id));
        meta.insert("reused_existing".to_string(), "true".to_string());
        append_audit_event(
            state,
            ctx,
            VaultAuditEventKind::ConnectorOperationExecuted,
            meta,
        )?;
        return Ok(());
    }

    let active_revocation_epoch = load_revocation_epoch(state)?;
    let channel_expires_at_ms = now_ms.saturating_add(CHANNEL_TTL_MS);
    let lease_expires_at_ms =
        now_ms.saturating_add(normalize_requested_lease_ttl_ms(params.lease_ttl_ms));

    let mut selected = None;
    for attempt in 0u8..=16u8 {
        let channel_id = derive_seeded_id(
            b"mail_connector_binding.channel",
            &params.request_id,
            &audience,
            &mailbox,
            attempt,
        )?;
        let lease_id = derive_seeded_id(
            b"mail_connector_binding.lease",
            &params.request_id,
            &audience,
            &mailbox,
            attempt,
        )?;
        let channel_exists = state.get(&channel_key(&channel_id))?.is_some();
        let lease_exists = state.get(&lease_key(&channel_id, &lease_id))?.is_some();
        if !channel_exists && !lease_exists {
            selected = Some((channel_id, lease_id, attempt));
            break;
        }
    }
    let Some((channel_id, lease_id, attempt)) = selected else {
        return Err(TransactionError::Invalid(
            "unable to allocate unique channel/lease binding ids".to_string(),
        ));
    };

    let issuer_id = audience;
    let subject_id = derive_seeded_id(
        b"mail_connector_binding.subject",
        &params.request_id,
        &audience,
        &mailbox,
        attempt,
    )?;
    let policy_hash = derive_seeded_id(
        b"mail_connector_binding.policy",
        &params.request_id,
        &audience,
        &mailbox,
        attempt,
    )?;
    let grant_id = derive_seeded_id(
        b"mail_connector_binding.grant",
        &params.request_id,
        &audience,
        &mailbox,
        attempt,
    )?;
    let lease_nonce = derive_seeded_id(
        b"mail_connector_binding.lease_nonce",
        &params.request_id,
        &audience,
        &mailbox,
        attempt,
    )?;

    let mut constraints = BTreeMap::new();
    constraints.insert("mailbox".to_string(), mailbox.clone());

    let envelope = SessionChannelEnvelope {
        channel_id,
        lc_id: issuer_id,
        rc_id: subject_id,
        ordering: SessionChannelOrdering::Ordered,
        mode: SessionChannelMode::AttestedRemoteExecution,
        policy_hash,
        policy_version: 1,
        root_grant_id: grant_id,
        capability_set: capability_set.clone(),
        constraints: constraints.clone(),
        delegation_rules: SessionChannelDelegationRules {
            max_depth: 0,
            can_redelegate: false,
            issuance_budget: Some(0),
        },
        revocation_epoch: active_revocation_epoch,
        expires_at_ms: channel_expires_at_ms,
    };
    let envelope_hash = hash_bytes(&codec::to_bytes_canonical(&envelope)?)?;
    let channel = SessionChannelRecord {
        envelope,
        state: SessionChannelState::Open,
        envelope_hash,
        opened_at_ms: Some(now_ms),
        closed_at_ms: None,
        last_seq: 0,
        close_reason: None,
    };
    store_typed(state, &channel_key(&channel_id), &channel)?;

    let lease = SessionLease {
        lease_id,
        channel_id,
        issuer_id,
        subject_id,
        policy_hash,
        grant_id,
        capability_subset: capability_set.clone(),
        constraints_subset: constraints,
        mode: SessionLeaseMode::Lease,
        expires_at_ms: lease_expires_at_ms.min(channel_expires_at_ms),
        revocation_epoch: active_revocation_epoch,
        audience,
        nonce: lease_nonce,
        counter: 1,
        issued_at_ms: now_ms,
        sig_hybrid_lc: vec![1u8],
    };
    store_typed(state, &lease_key(&channel_id, &lease_id), &lease)?;

    let receipt = MailConnectorEnsureBindingReceipt {
        request_id: params.request_id,
        mailbox: mailbox.clone(),
        audience,
        channel_id,
        lease_id,
        reused_existing: false,
        issued_at_ms: now_ms,
        channel_expires_at_ms,
        lease_expires_at_ms: lease.expires_at_ms,
        capability_set: capability_set.clone(),
    };
    store_typed(state, &receipt_key, &receipt)?;

    let mut meta = base_audit_metadata(ctx);
    meta.insert(
        "operation".to_string(),
        "mail_connector_ensure_binding@v1".to_string(),
    );
    meta.insert("request_id".to_string(), hex::encode(params.request_id));
    meta.insert("mailbox".to_string(), mailbox);
    meta.insert("audience".to_string(), hex::encode(audience));
    meta.insert("channel_id".to_string(), hex::encode(channel_id));
    meta.insert("lease_id".to_string(), hex::encode(lease_id));
    meta.insert("reused_existing".to_string(), "false".to_string());
    append_audit_event(
        state,
        ctx,
        VaultAuditEventKind::ConnectorOperationExecuted,
        meta,
    )?;
    Ok(())
}
