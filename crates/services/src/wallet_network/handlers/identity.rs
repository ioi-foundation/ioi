// Path: crates/services/src/wallet_network/handlers/identity.rs

use crate::wallet_network::keys::{policy_key, secret_alias_key, secret_key, IDENTITY_KEY};
use crate::wallet_network::support::{
    append_audit_event, base_audit_metadata, block_timestamp_ms, encrypt_secret_payload,
    is_encrypted_secret_payload, load_typed, require_identity, store_typed,
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

/// SUPERSEDED (W1.6 lane B, P0). This operation stored a caller-supplied `OwnerAnchor` — its
/// `link_signature` included — after checking only that network and address were non-empty. It
/// verified NOTHING: not the signature, the message, the chain, a nonce, the domain, expiry, or
/// replay state. That is exactly the standing-access defect INV-40 forbids ("an unverified
/// ownership claim is inadmissible as a factor"), and it is a P0 blocker to fix before any public
/// exposure.
///
/// Per the wallet-interoperability packet, the replacement is NOT a wrapper around this path: an
/// external wallet becomes a `web3_wallet` factor only through the verified challenge/proof
/// pipeline (`WalletAuthenticationChallenge` -> `WalletOwnershipProof`, registered contracts).
/// That verifying flow (EVM SIWE and ERC-1271/6492) lands in lane B steps 3-4. Until then this
/// operation FAILS CLOSED: it admits nothing, because admitting an unverified anchor is precisely
/// the defect being removed. Any owner anchor that predates verification is inert — a future
/// verified-linking flow must re-prove it; nothing here promotes it.
pub(crate) fn link_owner(
    state: &mut dyn StateAccess,
    ctx: &TxContext<'_>,
    owner: OwnerAnchor,
) -> Result<(), TransactionError> {
    // Emit an audit event for the refused attempt BEFORE refusing, so the invalidation of the
    // unverified path is observable in the same immutable trail every other vault action uses.
    let mut meta = base_audit_metadata(ctx);
    meta.insert("network".to_string(), owner.network.clone());
    meta.insert("address".to_string(), owner.address.clone());
    meta.insert("disposition".to_string(), "refused_unverified".to_string());
    meta.insert(
        "superseded_by".to_string(),
        "wallet-ownership-proof pipeline (INV-40)".to_string(),
    );
    append_audit_event(state, ctx, VaultAuditEventKind::OwnerLinked, meta)?;
    Err(TransactionError::Invalid(
        "link_owner@v1 is superseded and admits nothing: an external wallet becomes a web3_wallet \
         factor only through the verified WalletAuthenticationChallenge -> WalletOwnershipProof \
         pipeline (INV-40). An unverified owner anchor is inadmissible as a factor."
            .to_string(),
    ))
}

pub(crate) fn store_secret_record(
    state: &mut dyn StateAccess,
    ctx: &TxContext<'_>,
    mut secret: VaultSecretRecord,
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
    if !is_encrypted_secret_payload(&secret.ciphertext) {
        secret.ciphertext = encrypt_secret_payload(&secret.ciphertext)?;
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
