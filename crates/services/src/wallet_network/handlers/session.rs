// Path: crates/services/src/wallet_network/handlers/session.rs

use crate::wallet_network::keys::{
    channel_key, lease_counter_window_key, lease_key, lease_replay_key, session_delegation_key,
    session_key,
};
use crate::wallet_network::support::{
    append_audit_event, base_audit_metadata, block_timestamp_ms, load_revocation_epoch, load_typed,
    store_typed,
};
use crate::wallet_network::validation::{
    is_constraint_subset, is_string_subset, validate_narrowing,
    validate_session_lease_hybrid_signature,
};
use crate::wallet_network::{
    IssueSessionGrantParams, LeaseCounterReplayWindowState, LeaseReplayState,
    SessionDelegationState,
};
use ioi_api::state::StateAccess;
use ioi_api::transaction::context::TxContext;
use ioi_types::app::wallet_network::{
    SessionChannelDelegationRules, SessionChannelRecord, SessionChannelState, SessionGrant,
    SessionLease, VaultAuditEventKind,
};
use ioi_types::error::TransactionError;

const LEASE_NONCE_TRACK_LIMIT: usize = 256;
const DEFAULT_DELEGATION_MAX_DEPTH: u8 = u8::MAX;
const UNORDERED_LEASE_COUNTER_REPLAY_WINDOW: u64 = 256;

pub(crate) fn issue_session_lease(
    state: &mut dyn StateAccess,
    ctx: &TxContext<'_>,
    lease: SessionLease,
) -> Result<(), TransactionError> {
    let now_ms = block_timestamp_ms(ctx);
    if lease.lease_id == [0u8; 32] || lease.channel_id == [0u8; 32] {
        return Err(TransactionError::Invalid(
            "lease_id and channel_id must not be all zeroes".to_string(),
        ));
    }
    if lease.capability_subset.is_empty() {
        return Err(TransactionError::Invalid(
            "lease must include at least one capability".to_string(),
        ));
    }
    if lease.nonce == [0u8; 32] {
        return Err(TransactionError::Invalid(
            "lease nonce must not be all zeroes".to_string(),
        ));
    }
    if lease.counter == 0 {
        return Err(TransactionError::Invalid(
            "lease counter must be >= 1".to_string(),
        ));
    }
    if lease.expires_at_ms <= now_ms {
        return Err(TransactionError::Invalid(
            "lease expiry must be in the future".to_string(),
        ));
    }

    let channel_state_key = channel_key(&lease.channel_id);
    let channel: SessionChannelRecord = load_typed(state, &channel_state_key)?
        .ok_or_else(|| TransactionError::Invalid("channel does not exist".to_string()))?;
    if channel.state != SessionChannelState::Open {
        return Err(TransactionError::Invalid(
            "channel must be open before issuing leases".to_string(),
        ));
    }
    if lease.expires_at_ms > channel.envelope.expires_at_ms {
        return Err(TransactionError::Invalid(
            "lease expiry must be <= channel expiry".to_string(),
        ));
    }
    if lease.policy_hash != channel.envelope.policy_hash {
        return Err(TransactionError::Invalid(
            "lease policy_hash must match channel policy_hash".to_string(),
        ));
    }

    let revocation_epoch = load_revocation_epoch(state)?;
    if lease.revocation_epoch < revocation_epoch {
        return Err(TransactionError::Invalid(
            "lease revocation_epoch is below active revocation epoch".to_string(),
        ));
    }
    if !is_string_subset(&lease.capability_subset, &channel.envelope.capability_set) {
        return Err(TransactionError::Invalid(
            "lease capabilities must be a subset of channel capability_set".to_string(),
        ));
    }
    if !is_constraint_subset(&lease.constraints_subset, &channel.envelope.constraints) {
        return Err(TransactionError::Invalid(
            "lease constraints must be a subset of channel constraints".to_string(),
        ));
    }
    validate_session_lease_hybrid_signature(&lease, channel.envelope.lc_id)?;

    let replay_key = lease_replay_key(&lease.channel_id, &lease.issuer_id);
    let mut replay =
        load_typed::<LeaseReplayState>(state, &replay_key)?.unwrap_or(LeaseReplayState {
            channel_id: lease.channel_id,
            issuer_id: lease.issuer_id,
            last_counter: 0,
            seen_nonces: Vec::new(),
        });
    if replay.channel_id != lease.channel_id || replay.issuer_id != lease.issuer_id {
        return Err(TransactionError::Invalid(
            "lease replay state binding mismatch".to_string(),
        ));
    }
    if replay.seen_nonces.iter().any(|seen| *seen == lease.nonce) {
        return Err(TransactionError::Invalid(
            "lease nonce replay detected".to_string(),
        ));
    }

    let counter_window_key = lease_counter_window_key(&lease.channel_id, &lease.issuer_id);
    let mut counter_window =
        load_typed::<LeaseCounterReplayWindowState>(state, &counter_window_key)?.unwrap_or(
            LeaseCounterReplayWindowState {
                channel_id: lease.channel_id,
                issuer_id: lease.issuer_id,
                ordering: channel.envelope.ordering,
                highest_counter: replay.last_counter,
                seen_counters: Default::default(),
            },
        );
    if counter_window.channel_id != lease.channel_id || counter_window.issuer_id != lease.issuer_id
    {
        return Err(TransactionError::Invalid(
            "lease counter replay window binding mismatch".to_string(),
        ));
    }
    if counter_window.ordering != channel.envelope.ordering {
        return Err(TransactionError::Invalid(
            "lease counter replay ordering mismatch with channel envelope".to_string(),
        ));
    }
    enforce_lease_counter_replay_window(&mut counter_window, &lease)?;

    let key = lease_key(&lease.channel_id, &lease.lease_id);
    if state.get(&key)?.is_some() {
        return Err(TransactionError::Invalid(
            "lease already exists".to_string(),
        ));
    }
    store_typed(state, &key, &lease)?;

    replay.last_counter = counter_window.highest_counter;
    replay.seen_nonces.push(lease.nonce);
    if replay.seen_nonces.len() > LEASE_NONCE_TRACK_LIMIT {
        let excess = replay.seen_nonces.len() - LEASE_NONCE_TRACK_LIMIT;
        replay.seen_nonces.drain(0..excess);
    }
    store_typed(state, &replay_key, &replay)?;
    store_typed(state, &counter_window_key, &counter_window)?;

    let mut meta = base_audit_metadata(ctx);
    meta.insert("channel_id".to_string(), hex::encode(lease.channel_id));
    meta.insert("lease_id".to_string(), hex::encode(lease.lease_id));
    meta.insert("lease_counter".to_string(), lease.counter.to_string());
    meta.insert(
        "lease_ordering".to_string(),
        format!("{:?}", counter_window.ordering),
    );
    meta.insert(
        "lease_counter_highest".to_string(),
        counter_window.highest_counter.to_string(),
    );
    meta.insert(
        "capability_count".to_string(),
        lease.capability_subset.len().to_string(),
    );
    append_audit_event(state, ctx, VaultAuditEventKind::LeaseIssued, meta)?;
    Ok(())
}

pub(crate) fn issue_session_grant(
    state: &mut dyn StateAccess,
    ctx: &TxContext<'_>,
    params: IssueSessionGrantParams,
) -> Result<(), TransactionError> {
    let now_ms = block_timestamp_ms(ctx);
    let parent_session_id = params.parent_session_id;
    let delegation_rules = params.delegation_rules;
    let grant = params.grant;
    if grant.session_id == [0u8; 32] {
        return Err(TransactionError::Invalid(
            "session_id must not be all zeroes".to_string(),
        ));
    }
    if grant.vault_id == [0u8; 32] {
        return Err(TransactionError::Invalid(
            "vault_id must not be all zeroes".to_string(),
        ));
    }
    if grant.agent_id.trim().is_empty() || grant.purpose.trim().is_empty() {
        return Err(TransactionError::Invalid(
            "session grant requires non-empty agent_id and purpose".to_string(),
        ));
    }
    if grant.scope.expires_at_ms <= now_ms {
        return Err(TransactionError::Invalid(
            "session grant expiry must be in the future".to_string(),
        ));
    }
    if grant.scope.action_allowlist.is_empty() {
        return Err(TransactionError::Invalid(
            "session grant requires at least one allowed action".to_string(),
        ));
    }

    let grant_session_key = session_key(&grant.session_id);
    if state.get(&grant_session_key)?.is_some() {
        return Err(TransactionError::Invalid(
            "session grant already exists".to_string(),
        ));
    }

    let mut parent_state_update: Option<([u8; 32], SessionDelegationState)> = None;
    let (depth, max_depth, remaining_budget, root_session_id, can_redelegate_base) =
        if let Some(parent_session_id) = parent_session_id {
            let parent_key = session_key(&parent_session_id);
            let parent: SessionGrant = load_typed(state, &parent_key)?.ok_or_else(|| {
                TransactionError::Invalid("parent session grant does not exist".to_string())
            })?;
            if parent.vault_id != grant.vault_id {
                return Err(TransactionError::Invalid(
                    "child grant vault_id must match parent vault_id".to_string(),
                ));
            }
            validate_narrowing(&parent.scope, &grant.scope)?;

            let parent_state_key = session_delegation_key(&parent_session_id);
            let parent_state = load_typed::<SessionDelegationState>(state, &parent_state_key)?
                .ok_or_else(|| {
                    TransactionError::Invalid(
                        "parent session delegation state does not exist".to_string(),
                    )
                })?;
            if parent_state.session_id != parent_session_id {
                return Err(TransactionError::Invalid(
                    "parent session delegation state session_id mismatch".to_string(),
                ));
            }
            if parent_state.depth > parent_state.max_depth {
                return Err(TransactionError::Invalid(
                    "parent session delegation state depth exceeds max_depth".to_string(),
                ));
            }

            if !parent_state.can_redelegate {
                return Err(TransactionError::Invalid(
                    "parent session delegation does not allow re-delegation".to_string(),
                ));
            }

            let child_depth_u16 = u16::from(parent_state.depth) + 1;
            if child_depth_u16 > u16::from(u8::MAX) {
                return Err(TransactionError::Invalid(
                    "session delegation depth overflow".to_string(),
                ));
            }
            let depth = child_depth_u16 as u8;
            if depth > parent_state.max_depth {
                return Err(TransactionError::Invalid(
                    "session delegation depth exceeds max_depth".to_string(),
                ));
            }

            if let Some(parent_remaining) = parent_state.remaining_issuance_budget {
                if parent_remaining == 0 {
                    return Err(TransactionError::Invalid(
                        "session delegation issuance budget exhausted".to_string(),
                    ));
                }
            }
            let parent_remaining_after = parent_state
                .remaining_issuance_budget
                .map(|parent_remaining| parent_remaining.saturating_sub(1));

            let child_rules = delegation_rules.unwrap_or(SessionChannelDelegationRules {
                max_depth: parent_state.max_depth,
                can_redelegate: parent_state.can_redelegate,
                issuance_budget: parent_remaining_after,
            });

            if child_rules.max_depth > parent_state.max_depth {
                return Err(TransactionError::Invalid(
                    "child delegation max_depth must be <= parent max_depth".to_string(),
                ));
            }
            if child_rules.max_depth < depth {
                return Err(TransactionError::Invalid(
                    "child delegation max_depth must be >= current depth".to_string(),
                ));
            }

            let remaining_budget = match (parent_remaining_after, child_rules.issuance_budget) {
                (Some(parent_remaining), Some(child_budget)) => {
                    if child_budget > parent_remaining {
                        return Err(TransactionError::Invalid(
                            "child issuance budget must be <= parent remaining budget".to_string(),
                        ));
                    }
                    Some(child_budget)
                }
                (Some(parent_remaining), None) => Some(parent_remaining),
                (None, Some(child_budget)) => Some(child_budget),
                (None, None) => None,
            };

            let mut parent_state_after = parent_state.clone();
            parent_state_after.remaining_issuance_budget = parent_remaining_after;
            parent_state_after.children_issued =
                parent_state_after.children_issued.saturating_add(1);
            parent_state_after.can_redelegate = can_delegate_further(
                parent_state_after.can_redelegate,
                parent_state_after.max_depth,
                parent_state_after.depth,
                parent_state_after.remaining_issuance_budget,
            );
            parent_state_update = Some((parent_session_id, parent_state_after));
            (
                depth,
                child_rules.max_depth,
                remaining_budget,
                parent_state.root_session_id,
                parent_state.can_redelegate && child_rules.can_redelegate,
            )
        } else {
            let root_rules = delegation_rules.unwrap_or(SessionChannelDelegationRules {
                max_depth: DEFAULT_DELEGATION_MAX_DEPTH,
                can_redelegate: true,
                issuance_budget: None,
            });
            (
                0,
                root_rules.max_depth,
                root_rules.issuance_budget,
                grant.session_id,
                root_rules.can_redelegate,
            )
        };

    store_typed(state, &grant_session_key, &grant)?;
    let delegation_state = SessionDelegationState {
        session_id: grant.session_id,
        root_session_id,
        depth,
        max_depth,
        can_redelegate: can_delegate_further(
            can_redelegate_base,
            max_depth,
            depth,
            remaining_budget,
        ),
        remaining_issuance_budget: remaining_budget,
        children_issued: 0,
    };
    let delegation_state_key = session_delegation_key(&grant.session_id);
    store_typed(state, &delegation_state_key, &delegation_state)?;
    if let Some((parent_id, parent_state)) = parent_state_update {
        let parent_state_key = session_delegation_key(&parent_id);
        store_typed(state, &parent_state_key, &parent_state)?;
    }

    let mut meta = base_audit_metadata(ctx);
    meta.insert("session_id".to_string(), hex::encode(grant.session_id));
    meta.insert(
        "action_allowlist_len".to_string(),
        grant.scope.action_allowlist.len().to_string(),
    );
    meta.insert("delegation_depth".to_string(), depth.to_string());
    meta.insert("delegation_max_depth".to_string(), max_depth.to_string());
    meta.insert("root_session_id".to_string(), hex::encode(root_session_id));
    meta.insert(
        "remaining_issuance_budget".to_string(),
        remaining_budget
            .map(|value| value.to_string())
            .unwrap_or_else(|| "unlimited".to_string()),
    );
    if let Some(parent_id) = parent_session_id {
        meta.insert("parent_session_id".to_string(), hex::encode(parent_id));
    }
    append_audit_event(state, ctx, VaultAuditEventKind::SessionIssued, meta)?;
    Ok(())
}

fn can_delegate_further(
    can_redelegate: bool,
    max_depth: u8,
    depth: u8,
    remaining_budget: Option<u32>,
) -> bool {
    can_redelegate && depth < max_depth && remaining_budget.map(|budget| budget > 0).unwrap_or(true)
}

fn enforce_lease_counter_replay_window(
    counter_window: &mut LeaseCounterReplayWindowState,
    lease: &SessionLease,
) -> Result<(), TransactionError> {
    match counter_window.ordering {
        ioi_types::app::wallet_network::SessionChannelOrdering::Ordered => {
            let expected_counter =
                if counter_window.seen_counters.is_empty() && counter_window.highest_counter == 0 {
                    1
                } else {
                    counter_window.highest_counter.saturating_add(1)
                };
            if lease.counter != expected_counter {
                return Err(TransactionError::Invalid(format!(
                    "ordered lease counter {} does not match expected {}",
                    lease.counter, expected_counter
                )));
            }
            counter_window.highest_counter = lease.counter;
            counter_window.seen_counters.clear();
            counter_window.seen_counters.insert(lease.counter);
            Ok(())
        }
        ioi_types::app::wallet_network::SessionChannelOrdering::Unordered => {
            if counter_window.seen_counters.contains(&lease.counter) {
                return Err(TransactionError::Invalid(
                    "unordered lease counter replay detected".to_string(),
                ));
            }
            if lease
                .counter
                .saturating_add(UNORDERED_LEASE_COUNTER_REPLAY_WINDOW)
                < counter_window.highest_counter
            {
                return Err(TransactionError::Invalid(
                    "unordered lease counter is outside replay window".to_string(),
                ));
            }
            counter_window.highest_counter = counter_window.highest_counter.max(lease.counter);
            counter_window.seen_counters.insert(lease.counter);
            let min_allowed = counter_window
                .highest_counter
                .saturating_sub(UNORDERED_LEASE_COUNTER_REPLAY_WINDOW);
            counter_window
                .seen_counters
                .retain(|counter| *counter >= min_allowed);
            Ok(())
        }
    }
}
