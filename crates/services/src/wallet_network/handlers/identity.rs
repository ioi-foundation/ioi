// Path: crates/services/src/wallet_network/handlers/identity.rs

use crate::wallet_network::keys::{policy_key, secret_alias_key, secret_key, IDENTITY_KEY};
use crate::wallet_network::support::{
    append_audit_event, base_audit_metadata, block_timestamp_ms, load_typed, require_identity,
    store_typed,
};
use ioi_api::state::StateAccess;
use ioi_api::transaction::context::TxContext;
use ioi_types::app::wallet_network::{
    OwnerAnchor, VaultAuditEventKind, VaultIdentity, VaultPolicyRule, VaultSecretRecord,
};
use ioi_types::error::TransactionError;

pub(crate) fn create_identity(
    state: &mut dyn StateAccess,
    ctx: &TxContext<'_>,
    mut identity: VaultIdentity,
) -> Result<(), TransactionError> {
    if identity.vault_id == [0u8; 32] {
        return Err(TransactionError::Invalid(
            "vault_id must not be all zeroes".to_string(),
        ));
    }
    let now_ms = block_timestamp_ms(ctx);
    let existing: Option<VaultIdentity> = load_typed(state, IDENTITY_KEY)?;
    if let Some(existing_identity) = existing {
        if existing_identity.vault_id != identity.vault_id {
            return Err(TransactionError::Invalid(
                "wallet identity already initialized".to_string(),
            ));
        }
    }
    if identity.created_at_ms == 0 {
        identity.created_at_ms = now_ms;
    }
    identity.updated_at_ms = now_ms;
    store_typed(state, IDENTITY_KEY, &identity)?;

    let mut meta = base_audit_metadata(ctx);
    meta.insert("vault_id".to_string(), hex::encode(identity.vault_id));
    append_audit_event(state, ctx, VaultAuditEventKind::IdentityCreated, meta)?;
    Ok(())
}

pub(crate) fn link_owner(
    state: &mut dyn StateAccess,
    ctx: &TxContext<'_>,
    owner: OwnerAnchor,
) -> Result<(), TransactionError> {
    if owner.network.trim().is_empty() || owner.address.trim().is_empty() {
        return Err(TransactionError::Invalid(
            "owner anchor requires non-empty network and address".to_string(),
        ));
    }
    let mut identity = require_identity(state)?;
    let mut replaced = false;
    for existing in &mut identity.owner_anchors {
        if existing.network.eq_ignore_ascii_case(&owner.network)
            && existing.address.eq_ignore_ascii_case(&owner.address)
        {
            *existing = owner.clone();
            replaced = true;
            break;
        }
    }
    if !replaced {
        identity.owner_anchors.push(owner.clone());
    }
    identity.updated_at_ms = block_timestamp_ms(ctx);
    store_typed(state, IDENTITY_KEY, &identity)?;

    let mut meta = base_audit_metadata(ctx);
    meta.insert("network".to_string(), owner.network.clone());
    meta.insert("address".to_string(), owner.address.clone());
    meta.insert("replaced".to_string(), replaced.to_string());
    append_audit_event(state, ctx, VaultAuditEventKind::OwnerLinked, meta)?;
    Ok(())
}

pub(crate) fn store_secret_record(
    state: &mut dyn StateAccess,
    ctx: &TxContext<'_>,
    secret: VaultSecretRecord,
) -> Result<(), TransactionError> {
    if secret.secret_id.trim().is_empty() || secret.alias.trim().is_empty() {
        return Err(TransactionError::Invalid(
            "secret record requires secret_id and alias".to_string(),
        ));
    }
    if secret.ciphertext.is_empty() {
        return Err(TransactionError::Invalid(
            "secret record ciphertext must not be empty".to_string(),
        ));
    }

    let key = secret_key(&secret.secret_id);
    let existed = state.get(&key)?.is_some();
    store_typed(state, &key, &secret)?;
    let alias_key = secret_alias_key(&secret.alias);
    store_typed(state, &alias_key, &secret.secret_id)?;

    let mut meta = base_audit_metadata(ctx);
    meta.insert("secret_id".to_string(), secret.secret_id.clone());
    meta.insert("alias".to_string(), secret.alias.clone());
    meta.insert("kind".to_string(), format!("{:?}", secret.kind));
    let kind = if existed || secret.rotated_at_ms.is_some() {
        VaultAuditEventKind::SecretRotated
    } else {
        VaultAuditEventKind::SecretStored
    };
    append_audit_event(state, ctx, kind, meta)?;
    Ok(())
}

pub(crate) fn upsert_policy_rule(
    state: &mut dyn StateAccess,
    ctx: &TxContext<'_>,
    policy: VaultPolicyRule,
) -> Result<(), TransactionError> {
    if policy.rule_id.trim().is_empty() || policy.label.trim().is_empty() {
        return Err(TransactionError::Invalid(
            "policy rule requires rule_id and label".to_string(),
        ));
    }
    let key = policy_key(&policy.rule_id);
    store_typed(state, &key, &policy)?;

    let mut meta = base_audit_metadata(ctx);
    meta.insert("rule_id".to_string(), policy.rule_id.clone());
    meta.insert(
        "target".to_string(),
        policy.target.canonical_label().to_string(),
    );
    meta.insert("auto_approve".to_string(), policy.auto_approve.to_string());
    append_audit_event(state, ctx, VaultAuditEventKind::PolicyUpserted, meta)?;
    Ok(())
}
