//! M03.7 — the EVM SIWE verifying handler: an external wallet becomes a `web3_wallet` factor and
//! NOTHING else.
//!
//! Canon: `wallet-network/doctrine.md` § *Wallet Interoperability*, INV-40. Registered contracts:
//! `schema://ioi/components/wallet-network/wallet-authentication-challenge/v1` and
//! `.../wallet-ownership-proof/v1`. This module is the verifying pipeline those contracts were
//! registered for; `link_owner@v1` next door is its superseded predecessor and admits nothing,
//! because it stored a caller-supplied anchor having verified neither signature, message, chain,
//! nonce, domain, expiry nor replay state.
//!
//! WHAT IS STRUCTURAL HERE, so that nothing later can quietly disagree:
//!
//! 1. THE SIGNED MESSAGE IS REBUILT FROM THE CHALLENGE, NEVER TAKEN FROM THE CALLER. A verifier
//!    that hashed a caller-supplied message would verify that the caller signed *something*, which
//!    is not the claim. The ERC-4361 text is reconstructed here from the stored challenge's own
//!    domain, uri, chain, nonce, account and timestamps, so "the signature is valid" and "the
//!    signature is over THIS challenge" are the same statement.
//!
//! 2. THE NONCE IS CONSUMED IN THE SAME STATE TRANSITION THAT VERIFIES. The contract requires
//!    atomic consumption. Here the challenge record's status moves to `consumed` before the proof
//!    is written, in one transaction over one single-writer state, so there is no window in which a
//!    verified challenge is still spendable. A second presentation finds `consumed` and refuses by
//!    name — replay is a typed refusal, not a duplicate factor.
//!
//! 3. IDENTITY IS NOT AUTHORITY (INV-40, and the whole point of the unit). A verified proof writes a
//!    `web3_wallet` factor record and touches no approval, no grant, no session delegation and no
//!    policy. `effect_authority_created` is recorded as `false` on the proof itself, so a consumer
//!    reading only the proof still cannot mistake it for an authorization. A consequential path is
//!    a separate, explicitly committed authority request, exactly as before this unit existed.
//!
//! 4. FACTOR IDENTITY IS CHAIN-QUALIFIED. The same address on two chains is two factors, because a
//!    CAIP-10 account names the chain. Collapsing them would let control proven on a test chain
//!    stand in for control on a production one.
//!
//! 5. CONTRACT ACCOUNTS FAIL CLOSED. `erc1271_contract` and `erc6492_counterfactual` require reading
//!    the wallet contract's own `isValidSignature` answer at an exact chain state, and this build
//!    binds no audited on-chain verifier. They are refused BY NAME rather than approximated: the
//!    proof contract requires `contract_wallet_state_ref` to record the exact state observed, and a
//!    state nobody observed cannot be recorded. Accepting them without that read would be inventing
//!    the observation the contract exists to carry.
//!
//! NONCLAIM. Verifying a signature proves control of a key at this instant. It does not prove who
//! holds that key, that the holder intended anything beyond signing this statement, or that the
//! account is safe to transact with. The factor is authentication evidence and is named as such.

use std::collections::BTreeMap;

use ioi_api::state::StateAccess;
use ioi_api::transaction::context::TxContext;
use ioi_types::app::wallet_network::VaultAuditEventKind;
use ioi_types::error::TransactionError;
use parity_scale_codec::{Decode, Encode};

use crate::wallet_network::keys::{
    WALLET_AUTH_CHALLENGE_PREFIX, WALLET_OWNERSHIP_PROOF_PREFIX, WEB3_WALLET_FACTOR_PREFIX,
};
use crate::wallet_network::support::{
    append_audit_event, base_audit_metadata, load_typed, store_typed,
};

/// The one SIWx adapter profile this build verifies under. A challenge issued under any other
/// profile is refused rather than verified by a different adapter's rules.
pub(crate) const SIWX_PROFILE_EVM_V1: &str = "siwx://evm/erc4361/v1";

/// Maximum life of a challenge. Short by construction: a challenge is anti-phishing material and a
/// long-lived one is a standing invitation to replay it somewhere else.
const CHALLENGE_MAX_TTL_MS: u64 = 10 * 60 * 1000;

#[derive(Clone, Debug, Encode, Decode, PartialEq, Eq)]
pub struct WalletAuthChallengeRecord {
    pub challenge_id: String,
    pub siwx_profile_ref: String,
    pub chain_id: String,
    pub requested_account: Option<String>,
    pub domain: String,
    pub uri: String,
    pub nonce: String,
    pub product_session_binding_hash: String,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub statement: String,
    /// `issued` | `consumed` | `expired` | `invalidated`, the contract's own lifecycle vocabulary.
    pub status: String,
}

#[derive(Clone, Debug, Encode, Decode, PartialEq, Eq)]
pub struct WalletOwnershipProofRecord {
    pub proof_id: String,
    pub challenge_ref: String,
    pub account: String,
    pub signature_kind: String,
    pub verified_at_ms: u64,
    pub verifier_profile_ref: String,
    pub contract_wallet_state_ref: Option<String>,
    pub yields_factor_id: String,
    /// Recorded on the proof so a consumer reading only the proof cannot mistake it for authority.
    pub effect_authority_created: bool,
}

#[derive(Clone, Debug, Encode, Decode, PartialEq, Eq)]
pub struct Web3WalletFactorRecord {
    pub factor_id: String,
    /// CAIP-10: the chain is part of the identity, so one address on two chains is two factors.
    pub account: String,
    pub chain_id: String,
    pub proof_ref: String,
    pub bound_product_session_binding_hash: String,
    pub established_at_ms: u64,
    pub effect_authority_created: bool,
}

#[derive(Clone, Debug, Encode, Decode)]
pub struct MintWalletAuthChallengeParams {
    pub challenge_id: String,
    pub siwx_profile_ref: String,
    pub chain_id: String,
    pub requested_account: Option<String>,
    pub domain: String,
    pub uri: String,
    pub nonce: String,
    pub product_session_binding_hash: String,
    pub expires_in_ms: u64,
    pub statement: String,
}

#[derive(Clone, Debug, Encode, Decode)]
pub struct VerifyWalletOwnershipProofParams {
    pub proof_id: String,
    pub challenge_ref: String,
    pub account: String,
    pub signature_kind: String,
    /// 65-byte EVM signature, hex with or without `0x`: r ‖ s ‖ v.
    pub signature: String,
}

fn invalid(message: impl Into<String>) -> TransactionError {
    TransactionError::Invalid(message.into())
}

fn challenge_key(challenge_id: &str) -> Vec<u8> {
    [WALLET_AUTH_CHALLENGE_PREFIX, challenge_id.as_bytes()].concat()
}

fn proof_key(proof_id: &str) -> Vec<u8> {
    [WALLET_OWNERSHIP_PROOF_PREFIX, proof_id.as_bytes()].concat()
}

fn factor_key(factor_id: &str) -> Vec<u8> {
    [WEB3_WALLET_FACTOR_PREFIX, factor_id.as_bytes()].concat()
}

fn now_ms(ctx: &TxContext<'_>) -> u64 {
    ctx.block_timestamp / 1_000_000
}

/// CAIP-2, exactly: `caip2:<namespace>:<reference>`.
fn parse_caip2(chain_id: &str) -> Result<(), TransactionError> {
    let rest = chain_id
        .strip_prefix("caip2:")
        .ok_or_else(|| invalid(format!("chain_id must be a CAIP-2 id; saw '{chain_id}'")))?;
    let mut parts = rest.split(':');
    let namespace = parts.next().unwrap_or_default();
    let reference = parts.next().unwrap_or_default();
    if parts.next().is_some()
        || namespace.is_empty()
        || reference.is_empty()
        || !namespace
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(invalid(format!(
            "chain_id must be 'caip2:<namespace>:<reference>'; saw '{chain_id}'"
        )));
    }
    Ok(())
}

/// CAIP-10, exactly: `caip10:<namespace>:<reference>:<address>`. Returns (chain_id, address).
fn parse_caip10(account: &str) -> Result<(String, String), TransactionError> {
    let rest = account.strip_prefix("caip10:").ok_or_else(|| {
        invalid(format!(
            "account must be a CAIP-10 account; saw '{account}'"
        ))
    })?;
    let parts: Vec<&str> = rest.split(':').collect();
    if parts.len() != 3 || parts.iter().any(|part| part.is_empty()) {
        return Err(invalid(format!(
            "account must be 'caip10:<namespace>:<reference>:<address>'; saw '{account}'"
        )));
    }
    Ok((
        format!("caip2:{}:{}", parts[0], parts[1]),
        parts[2].to_string(),
    ))
}

/// THE ERC-4361 MESSAGE, REBUILT FROM THE STORED CHALLENGE.
///
/// Field order and separators are the standard's, because the wallet that signed it built the same
/// text from the same fields. Nothing here is caller-supplied: that is what makes the recovered
/// address a statement about THIS challenge rather than about some message the caller chose.
fn erc4361_message(challenge: &WalletAuthChallengeRecord, address: &str) -> String {
    let chain_reference = challenge
        .chain_id
        .strip_prefix("caip2:")
        .and_then(|rest| rest.split(':').nth(1))
        .unwrap_or_default();
    format!(
        "{domain} wants you to sign in with your Ethereum account:\n{address}\n\n{statement}\n\nURI: {uri}\nVersion: 1\nChain ID: {chain}\nNonce: {nonce}\nIssued At: {issued}\nExpiration Time: {expires}",
        domain = challenge.domain,
        address = address,
        statement = challenge.statement,
        uri = challenge.uri,
        chain = chain_reference,
        nonce = challenge.nonce,
        issued = challenge.issued_at_ms,
        expires = challenge.expires_at_ms,
    )
}

/// EIP-191 `personal_sign` prehash: keccak256 over the prefixed message.
fn eip191_prehash(message: &str) -> [u8; 32] {
    use dcrypt::algorithms::hash::HashFunction;
    use dcrypt::algorithms::hash::Keccak256;
    let prefixed = format!(
        "\u{19}Ethereum Signed Message:\n{}{}",
        message.len(),
        message
    );
    let digest = Keccak256::digest(prefixed.as_bytes()).expect("keccak256 digest");
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_ref());
    out
}

/// The EVM address of a recovered public key: the low 20 bytes of keccak256 over the uncompressed
/// key with its 0x04 tag removed.
fn evm_address(key: &k256::ecdsa::VerifyingKey) -> String {
    use dcrypt::algorithms::hash::HashFunction;
    use dcrypt::algorithms::hash::Keccak256;
    let point = key.to_encoded_point(false);
    let digest = Keccak256::digest(&point.as_bytes()[1..]).expect("keccak256 digest");
    format!("0x{}", hex::encode(&digest.as_ref()[12..]))
}

fn decode_signature(signature: &str) -> Result<([u8; 64], u8), TransactionError> {
    let trimmed = signature.trim().trim_start_matches("0x");
    let bytes =
        hex::decode(trimmed).map_err(|_| invalid("signature must be hex-encoded r ‖ s ‖ v"))?;
    if bytes.len() != 65 {
        return Err(invalid(format!(
            "an EVM signature is 65 bytes (r ‖ s ‖ v); saw {}",
            bytes.len()
        )));
    }
    let mut rs = [0u8; 64];
    rs.copy_from_slice(&bytes[..64]);
    // Wallets emit v as 27/28 (or 0/1 raw); both name the same recovery id.
    let v = match bytes[64] {
        0 | 27 => 0,
        1 | 28 => 1,
        other => {
            return Err(invalid(format!(
                "signature recovery byte must be 0/1 or 27/28; saw {other}"
            )))
        }
    };
    Ok((rs, v))
}

/// Mint a single-use, domain/chain/session-bound challenge. Authentication material only.
pub(crate) fn mint_wallet_authentication_challenge(
    state: &mut dyn StateAccess,
    ctx: &TxContext<'_>,
    params: MintWalletAuthChallengeParams,
) -> Result<(), TransactionError> {
    if !params.challenge_id.starts_with("wallet-auth-challenge://") {
        return Err(invalid(
            "challenge_id must be a 'wallet-auth-challenge://' identity",
        ));
    }
    if params.siwx_profile_ref != SIWX_PROFILE_EVM_V1 {
        return Err(invalid(format!(
            "this build issues challenges under '{SIWX_PROFILE_EVM_V1}' only; '{}' names an adapter whose rules nothing here verifies",
            params.siwx_profile_ref
        )));
    }
    parse_caip2(&params.chain_id)?;
    if let Some(account) = params.requested_account.as_deref() {
        let (account_chain, _) = parse_caip10(account)?;
        if account_chain != params.chain_id {
            return Err(invalid(
                "requested_account names a different chain than chain_id; a challenge is scoped to exactly one chain",
            ));
        }
    }
    if params.domain.trim().is_empty() || params.uri.trim().is_empty() {
        return Err(invalid(
            "domain and uri are required: they are the anti-phishing and anti-replay bindings",
        ));
    }
    if params.nonce.len() < 8 {
        return Err(invalid(
            "nonce must be at least 8 characters and single-use",
        ));
    }
    if !params.product_session_binding_hash.starts_with("sha256:")
        || params.product_session_binding_hash.len() != "sha256:".len() + 64
    {
        return Err(invalid(
            "product_session_binding_hash must be a 'sha256:' digest binding the exact product session",
        ));
    }
    if params.statement.trim().is_empty() {
        return Err(invalid(
            "statement is required: it is what the human actually reads in the wallet",
        ));
    }
    if params.expires_in_ms == 0 || params.expires_in_ms > CHALLENGE_MAX_TTL_MS {
        return Err(invalid(format!(
            "expires_in_ms must be 1..={CHALLENGE_MAX_TTL_MS}; a long-lived challenge is a standing invitation to replay it"
        )));
    }
    let key = challenge_key(&params.challenge_id);
    if state.get(&key)?.is_some() {
        return Err(invalid(
            "challenge_id already exists; a challenge is single-use and is never re-minted under its own id",
        ));
    }
    let issued_at_ms = now_ms(ctx);
    let record = WalletAuthChallengeRecord {
        challenge_id: params.challenge_id.clone(),
        siwx_profile_ref: params.siwx_profile_ref,
        chain_id: params.chain_id.clone(),
        requested_account: params.requested_account.clone(),
        domain: params.domain,
        uri: params.uri,
        nonce: params.nonce,
        product_session_binding_hash: params.product_session_binding_hash,
        issued_at_ms,
        expires_at_ms: issued_at_ms.saturating_add(params.expires_in_ms),
        statement: params.statement,
        status: "issued".to_string(),
    };
    store_typed(state, &key, &record)?;

    let mut meta = base_audit_metadata(ctx);
    meta.insert("challenge_id".to_string(), params.challenge_id);
    meta.insert("chain_id".to_string(), params.chain_id);
    meta.insert("disposition".to_string(), "challenge_issued".to_string());
    append_audit_event(state, ctx, VaultAuditEventKind::OwnerLinked, meta)?;
    Ok(())
}

/// Verify a signature against an issued challenge and yield a `web3_wallet` factor — and nothing else.
pub(crate) fn verify_wallet_ownership_proof(
    state: &mut dyn StateAccess,
    ctx: &TxContext<'_>,
    params: VerifyWalletOwnershipProofParams,
) -> Result<(), TransactionError> {
    if !params.proof_id.starts_with("wallet-ownership-proof://") {
        return Err(invalid(
            "proof_id must be a 'wallet-ownership-proof://' identity",
        ));
    }
    // CONTRACT ACCOUNTS FAIL CLOSED, BEFORE THE CHALLENGE IS TOUCHED. Refusing after consuming the
    // nonce would burn a challenge on a path this build cannot complete.
    match params.signature_kind.as_str() {
        "eoa_secp256k1" => {}
        kind @ ("erc1271_contract" | "erc6492_counterfactual") => {
            return Err(invalid(format!(
                "'{kind}' requires reading the wallet contract's own isValidSignature answer at an exact chain state, and this build binds no audited on-chain verifier. The proof contract requires contract_wallet_state_ref to record the state observed, and a state nobody observed cannot be recorded"
            )))
        }
        other => {
            return Err(invalid(format!(
                "signature_kind must be one of eoa_secp256k1, erc1271_contract, erc6492_counterfactual; saw '{other}'"
            )))
        }
    }

    let key = challenge_key(&params.challenge_ref);
    let mut challenge: WalletAuthChallengeRecord = load_typed(state, &key)?
        .ok_or_else(|| invalid("challenge_ref names no issued challenge"))?;

    // REPLAY IS A TYPED REFUSAL. A consumed challenge is not a challenge.
    if challenge.status != "issued" {
        return Err(invalid(format!(
            "this challenge is '{}' and cannot be answered again; its nonce was consumed at verification",
            challenge.status
        )));
    }
    let now = now_ms(ctx);
    if now > challenge.expires_at_ms {
        challenge.status = "expired".to_string();
        store_typed(state, &key, &challenge)?;
        return Err(invalid(
            "this challenge has expired; mint a new one rather than extending an old proof window",
        ));
    }

    let (account_chain, address) = parse_caip10(&params.account)?;
    if account_chain != challenge.chain_id {
        return Err(invalid(format!(
            "the account names chain '{account_chain}' and the challenge is scoped to '{}'; a factor is chain-qualified and control on one chain is not control on another",
            challenge.chain_id
        )));
    }
    if let Some(requested) = challenge.requested_account.as_deref() {
        if requested != params.account {
            return Err(invalid(
                "this challenge targets a different account; a proof may not substitute the account the challenge named",
            ));
        }
    }

    // THE MESSAGE IS THIS CHALLENGE'S, REBUILT HERE.
    let message = erc4361_message(&challenge, &address);
    let prehash = eip191_prehash(&message);
    let (rs, recovery) = decode_signature(&params.signature)?;
    let signature = k256::ecdsa::Signature::from_slice(&rs)
        .map_err(|_| invalid("signature r ‖ s is not a valid secp256k1 signature"))?;
    let recovery_id = k256::ecdsa::RecoveryId::from_byte(recovery)
        .ok_or_else(|| invalid("signature recovery byte is not a valid recovery id"))?;
    let recovered =
        k256::ecdsa::VerifyingKey::recover_from_prehash(&prehash, &signature, recovery_id)
            .map_err(|_| {
                invalid("no public key recovers from this signature over this challenge's message")
            })?;
    let recovered_address = evm_address(&recovered);
    if !recovered_address.eq_ignore_ascii_case(&address) {
        return Err(invalid(format!(
            "the signature recovers {recovered_address}, not {address}: this proves control of a different key, which is not the claim"
        )));
    }

    // CONSUME THE NONCE IN THE SAME TRANSITION THAT VERIFIED IT. Written before the proof and the
    // factor, so there is no ordering in which a verified challenge is still spendable.
    challenge.status = "consumed".to_string();
    store_typed(state, &key, &challenge)?;

    let factor_id = format!("web3-wallet-factor://{}", params.account);
    let proof = WalletOwnershipProofRecord {
        proof_id: params.proof_id.clone(),
        challenge_ref: params.challenge_ref.clone(),
        account: params.account.clone(),
        signature_kind: params.signature_kind.clone(),
        verified_at_ms: now,
        verifier_profile_ref: SIWX_PROFILE_EVM_V1.to_string(),
        // NULL FOR EOA, as the contract says. There is no contract-wallet state here to observe.
        contract_wallet_state_ref: None,
        yields_factor_id: factor_id.clone(),
        effect_authority_created: false,
    };
    store_typed(state, &proof_key(&params.proof_id), &proof)?;

    let factor = Web3WalletFactorRecord {
        factor_id: factor_id.clone(),
        account: params.account.clone(),
        chain_id: challenge.chain_id.clone(),
        proof_ref: params.proof_id.clone(),
        bound_product_session_binding_hash: challenge.product_session_binding_hash.clone(),
        established_at_ms: now,
        effect_authority_created: false,
    };
    store_typed(state, &factor_key(&factor_id), &factor)?;

    let mut meta: BTreeMap<String, String> = base_audit_metadata(ctx);
    meta.insert("challenge_id".to_string(), params.challenge_ref);
    meta.insert("account".to_string(), params.account);
    meta.insert("factor_id".to_string(), factor_id);
    meta.insert("disposition".to_string(), "owner_verified".to_string());
    meta.insert("effect_authority_created".to_string(), "false".to_string());
    append_audit_event(state, ctx, VaultAuditEventKind::OwnerLinked, meta)?;
    Ok(())
}
