// M03.7 — the EVM SIWE verifying handler, driven with REAL secp256k1 signatures.
//
// Every positive below signs the exact ERC-4361 text the handler rebuilds from the stored
// challenge, with a key generated here, and the handler recovers the address independently. Nothing
// is stubbed: a test that handed the verifier a signature it had itself declared valid would prove
// only that two pieces of this file agree.
//
// The negatives are the unit. An externally owned account must be able to bind a product session
// WITHOUT becoming effect authority, and every way of getting a factor you should not have —
// replaying a consumed challenge, substituting the signature, the account, or the chain, answering
// an expired challenge, or claiming a contract-account kind this build cannot observe — is refused
// by its own name with nothing written.
use super::super::handlers::wallet_siwe::{
    mint_wallet_authentication_challenge, verify_wallet_ownership_proof,
    MintWalletAuthChallengeParams, VerifyWalletOwnershipProofParams, WalletAuthChallengeRecord,
    WalletOwnershipProofRecord, Web3WalletFactorRecord, SIWX_PROFILE_EVM_V1,
};
use super::super::support::load_typed;
use super::*;
use dcrypt::algorithms::hash::{HashFunction, Keccak256};
use k256::ecdsa::{signature::hazmat::PrehashSigner, SigningKey};

const CHAIN: &str = "caip2:eip155:1";
const OTHER_CHAIN: &str = "caip2:eip155:11155111";
const DOMAIN: &str = "app.ioi.ai";
const URI: &str = "https://app.ioi.ai/login";
const NONCE: &str = "n0nce-abcdef0123456789";
const SESSION_HASH: &str =
    "sha256:1111111111111111111111111111111111111111111111111111111111111111";
const CHALLENGE: &str = "wallet-auth-challenge://m037/test/1";
const PROOF: &str = "wallet-ownership-proof://m037/test/1";
const STATEMENT: &str =
    "Sign in to IOI. This proves you control this account and grants no authority.";

fn key_from(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32].into()).expect("a valid secp256k1 scalar")
}

fn address_of(key: &SigningKey) -> String {
    let point = key.verifying_key().to_encoded_point(false);
    let digest = Keccak256::digest(&point.as_bytes()[1..]).expect("keccak256");
    format!("0x{}", hex::encode(&digest.as_ref()[12..]))
}

fn caip10(chain: &str, address: &str) -> String {
    let rest = chain.strip_prefix("caip2:").expect("caip2 chain");
    format!("caip10:{rest}:{address}")
}

/// The exact ERC-4361 text the handler rebuilds — transcribed here, not imported, so a change to
/// either side is a disagreement these tests can see.
fn message_for(challenge: &WalletAuthChallengeRecord, address: &str) -> String {
    let chain_reference = challenge
        .chain_id
        .strip_prefix("caip2:")
        .and_then(|rest| rest.split(':').nth(1))
        .unwrap_or_default();
    format!(
        "{} wants you to sign in with your Ethereum account:\n{}\n\n{}\n\nURI: {}\nVersion: 1\nChain ID: {}\nNonce: {}\nIssued At: {}\nExpiration Time: {}",
        challenge.domain,
        address,
        challenge.statement,
        challenge.uri,
        chain_reference,
        challenge.nonce,
        challenge.issued_at_ms,
        challenge.expires_at_ms,
    )
}

fn sign(key: &SigningKey, message: &str) -> String {
    let prefixed = format!(
        "\u{19}Ethereum Signed Message:\n{}{}",
        message.len(),
        message
    );
    let digest = Keccak256::digest(prefixed.as_bytes()).expect("keccak256");
    let mut prehash = [0u8; 32];
    prehash.copy_from_slice(digest.as_ref());
    let (signature, recovery): (k256::ecdsa::Signature, k256::ecdsa::RecoveryId) =
        key.sign_prehash(&prehash).expect("sign the prehash");
    format!(
        "0x{}{:02x}",
        hex::encode(signature.to_bytes()),
        recovery.to_byte() + 27
    )
}

fn mint(state: &mut MockState, ctx: &TxContext<'_>, account: Option<String>) {
    mint_wallet_authentication_challenge(
        state,
        ctx,
        MintWalletAuthChallengeParams {
            challenge_id: CHALLENGE.to_string(),
            siwx_profile_ref: SIWX_PROFILE_EVM_V1.to_string(),
            chain_id: CHAIN.to_string(),
            requested_account: account,
            domain: DOMAIN.to_string(),
            uri: URI.to_string(),
            nonce: NONCE.to_string(),
            product_session_binding_hash: SESSION_HASH.to_string(),
            expires_in_ms: 300_000,
            statement: STATEMENT.to_string(),
        },
    )
    .expect("a well-formed challenge mints");
}

fn stored_challenge(state: &MockState) -> WalletAuthChallengeRecord {
    load_typed(
        state,
        &[b"wallet_auth_challenge::".as_slice(), CHALLENGE.as_bytes()].concat(),
    )
    .expect("state read")
    .expect("the challenge was stored")
}

fn stored_factor(state: &MockState, account: &str) -> Option<Web3WalletFactorRecord> {
    load_typed(
        state,
        &[
            b"web3_wallet_factor::".as_slice(),
            format!("web3-wallet-factor://{account}").as_bytes(),
        ]
        .concat(),
    )
    .expect("state read")
}

fn verify(
    state: &mut MockState,
    ctx: &TxContext<'_>,
    account: &str,
    signature: &str,
    kind: &str,
) -> Result<(), ioi_types::error::TransactionError> {
    verify_wallet_ownership_proof(
        state,
        ctx,
        VerifyWalletOwnershipProofParams {
            proof_id: PROOF.to_string(),
            challenge_ref: CHALLENGE.to_string(),
            account: account.to_string(),
            signature_kind: kind.to_string(),
            signature: signature.to_string(),
        },
    )
}

#[test]
fn a_real_signature_over_this_challenge_yields_a_web3_wallet_factor_and_nothing_else() {
    let mut state = MockState::default();
    with_ctx(|ctx| {
        let key = key_from(11);
        let address = address_of(&key);
        let account = caip10(CHAIN, &address);
        mint(&mut state, ctx, Some(account.clone()));
        let challenge = stored_challenge(&state);
        let signature = sign(&key, &message_for(&challenge, &address));

        verify(&mut state, ctx, &account, &signature, "eoa_secp256k1")
            .expect("a real signature over this exact challenge verifies");

        let proof: WalletOwnershipProofRecord = load_typed(
            &state,
            &[b"wallet_ownership_proof::".as_slice(), PROOF.as_bytes()].concat(),
        )
        .expect("state read")
        .expect("the proof was written");
        assert_eq!(proof.account, account);
        assert_eq!(proof.verifier_profile_ref, SIWX_PROFILE_EVM_V1);
        assert_eq!(
            proof.contract_wallet_state_ref, None,
            "an EOA proof observes no contract-wallet state, and the contract says null"
        );
        assert!(
            !proof.effect_authority_created,
            "INV-40: a verified proof is authentication evidence and creates no effect authority"
        );

        let factor = stored_factor(&state, &account).expect("the factor was written");
        assert_eq!(factor.proof_ref, PROOF);
        assert_eq!(factor.chain_id, CHAIN);
        assert_eq!(factor.bound_product_session_binding_hash, SESSION_HASH);
        assert!(!factor.effect_authority_created);

        // IDENTITY IS NOT AUTHORITY, MEASURED: nothing that could authorize anything was written.
        // The proof yields a factor; a consequential path still commits its own authority request.
        for authority_prefix in [
            b"approval::".as_slice(),
            b"approval_grant_state::".as_slice(),
            b"standing_approval_grant_state::".as_slice(),
            b"session_delegation::".as_slice(),
            b"injection_grant::".as_slice(),
            b"policy::".as_slice(),
        ] {
            let rows = ioi_api::state::StateAccess::prefix_scan(&state, authority_prefix)
                .expect("prefix scan")
                .count();
            assert_eq!(
                rows,
                0,
                "verifying ownership wrote {rows} row(s) under {}, which would make identity into authority",
                String::from_utf8_lossy(authority_prefix)
            );
        }
    });
}

#[test]
fn the_nonce_is_consumed_at_verification_and_a_replay_is_refused_by_name() {
    let mut state = MockState::default();
    with_ctx(|ctx| {
        let key = key_from(12);
        let address = address_of(&key);
        let account = caip10(CHAIN, &address);
        mint(&mut state, ctx, Some(account.clone()));
        let challenge = stored_challenge(&state);
        let signature = sign(&key, &message_for(&challenge, &address));

        verify(&mut state, ctx, &account, &signature, "eoa_secp256k1").expect("first verify");
        assert_eq!(
            stored_challenge(&state).status,
            "consumed",
            "the nonce is consumed in the same transition that verified it"
        );

        let replay = verify(&mut state, ctx, &account, &signature, "eoa_secp256k1")
            .expect_err("the identical proof must not verify twice");
        assert!(
            replay.to_string().contains("consumed"),
            "replay must refuse by naming the consumed nonce: {replay}"
        );
    });
}

#[test]
fn a_signature_from_another_key_is_refused_and_names_the_address_it_actually_proves() {
    let mut state = MockState::default();
    with_ctx(|ctx| {
        let owner = key_from(13);
        let impostor = key_from(14);
        let address = address_of(&owner);
        let account = caip10(CHAIN, &address);
        mint(&mut state, ctx, Some(account.clone()));
        let challenge = stored_challenge(&state);
        // A VALID signature over the RIGHT message by the WRONG key: the failure must be the
        // identity it proves, not the shape of the bytes.
        let substituted = sign(&impostor, &message_for(&challenge, &address));

        let error = verify(&mut state, ctx, &account, &substituted, "eoa_secp256k1")
            .expect_err("a signature by another key proves control of another key");
        assert!(
            error.to_string().contains(&address_of(&impostor)),
            "the refusal must name the address actually recovered: {error}"
        );
        assert_eq!(
            stored_challenge(&state).status,
            "issued",
            "a refused proof consumes nothing"
        );
        assert!(stored_factor(&state, &account).is_none());
    });
}

#[test]
fn a_signature_over_a_different_challenge_does_not_verify_against_this_one() {
    let mut state = MockState::default();
    with_ctx(|ctx| {
        let key = key_from(15);
        let address = address_of(&key);
        let account = caip10(CHAIN, &address);
        mint(&mut state, ctx, Some(account.clone()));
        let mut other = stored_challenge(&state);
        other.nonce = "n0nce-9999999999999999".to_string();
        // The message the handler rebuilds carries THIS challenge's nonce, so a signature over any
        // other nonce recovers a different address and is refused.
        let signature = sign(&key, &message_for(&other, &address));

        let error = verify(&mut state, ctx, &account, &signature, "eoa_secp256k1")
            .expect_err("a signature over another challenge must not bind this one");
        assert!(
            error.to_string().contains("recovers"),
            "the refusal must come from the recovered identity, not from a message comparison: {error}"
        );
        assert_eq!(stored_challenge(&state).status, "issued");
    });
}

#[test]
fn an_account_on_another_chain_is_a_different_factor_and_is_refused() {
    let mut state = MockState::default();
    with_ctx(|ctx| {
        let key = key_from(16);
        let address = address_of(&key);
        let account = caip10(CHAIN, &address);
        mint(&mut state, ctx, Some(account));
        let challenge = stored_challenge(&state);
        let signature = sign(&key, &message_for(&challenge, &address));

        let foreign = caip10(OTHER_CHAIN, &address);
        let error = verify(&mut state, ctx, &foreign, &signature, "eoa_secp256k1")
            .expect_err("the same address on another chain is another factor");
        assert!(
            error.to_string().contains("chain-qualified"),
            "the refusal must say why the chain matters: {error}"
        );
        assert!(stored_factor(&state, &foreign).is_none());
    });
}

#[test]
fn a_proof_may_not_substitute_the_account_the_challenge_targeted() {
    let mut state = MockState::default();
    with_ctx(|ctx| {
        let targeted = key_from(17);
        let other = key_from(18);
        let targeted_account = caip10(CHAIN, &address_of(&targeted));
        mint(&mut state, ctx, Some(targeted_account));
        let challenge = stored_challenge(&state);
        // The other key signs the message for ITS OWN address, so the signature is internally
        // valid; the refusal must come from the challenge's target, not from recovery.
        let other_address = address_of(&other);
        let signature = sign(&other, &message_for(&challenge, &other_address));

        let error = verify(
            &mut state,
            ctx,
            &caip10(CHAIN, &other_address),
            &signature,
            "eoa_secp256k1",
        )
        .expect_err("a targeted challenge may only be answered by its target");
        assert!(
            error.to_string().contains("targets a different account"),
            "the refusal must name the substitution: {error}"
        );
        assert_eq!(stored_challenge(&state).status, "issued");
    });
}

#[test]
fn a_contract_account_kind_fails_closed_before_the_challenge_is_touched() {
    let mut state = MockState::default();
    with_ctx(|ctx| {
        let key = key_from(19);
        let address = address_of(&key);
        let account = caip10(CHAIN, &address);
        mint(&mut state, ctx, Some(account.clone()));
        let challenge = stored_challenge(&state);
        let signature = sign(&key, &message_for(&challenge, &address));

        for kind in ["erc1271_contract", "erc6492_counterfactual"] {
            let error = verify(&mut state, ctx, &account, &signature, kind)
                .expect_err("no audited on-chain verifier is bound in this build");
            assert!(
                error.to_string().contains("contract_wallet_state_ref"),
                "the refusal must name the observation the contract requires: {error}"
            );
            // BEFORE the challenge is touched: refusing after consuming would burn a challenge on a
            // path this build cannot complete.
            assert_eq!(stored_challenge(&state).status, "issued");
        }
    });
}

#[test]
fn an_expired_challenge_is_refused_and_marked_rather_than_left_answerable() {
    let mut state = MockState::default();
    let key = key_from(20);
    let address = address_of(&key);
    let account = caip10(CHAIN, &address);
    with_ctx(|ctx| mint(&mut state, ctx, Some(account.clone())));
    let challenge = stored_challenge(&state);
    let signature = sign(&key, &message_for(&challenge, &address));

    // A later block: the same signature, past the window.
    let services = ioi_api::services::access::ServiceDirectory::new(Vec::new());
    let mut ctx = TxContext {
        block_height: 43,
        block_timestamp: (challenge.expires_at_ms + 1) * 1_000_000,
        chain_id: ChainId(1),
        signer_account_id: AccountId([7u8; 32]),
        services: &services,
        simulation: false,
        is_internal: false,
    };
    let error = verify(&mut state, &mut ctx, &account, &signature, "eoa_secp256k1")
        .expect_err("an expired challenge is not answerable");
    assert!(error.to_string().contains("expired"), "{error}");
    assert_eq!(
        stored_challenge(&state).status,
        "expired",
        "the expiry is recorded, so the challenge is not left looking issued"
    );
    assert!(stored_factor(&state, &account).is_none());
}

#[test]
fn a_challenge_is_single_use_by_id_and_its_bindings_are_required() {
    let mut state = MockState::default();
    with_ctx(|ctx| {
        mint(&mut state, ctx, None);
        let again = mint_wallet_authentication_challenge(
            &mut state,
            ctx,
            MintWalletAuthChallengeParams {
                challenge_id: CHALLENGE.to_string(),
                siwx_profile_ref: SIWX_PROFILE_EVM_V1.to_string(),
                chain_id: CHAIN.to_string(),
                requested_account: None,
                domain: DOMAIN.to_string(),
                uri: URI.to_string(),
                nonce: NONCE.to_string(),
                product_session_binding_hash: SESSION_HASH.to_string(),
                expires_in_ms: 300_000,
                statement: STATEMENT.to_string(),
            },
        )
        .expect_err("a challenge id is never re-minted");
        assert!(again.to_string().contains("single-use"), "{again}");

        // An unaudited adapter profile is refused rather than verified by another adapter's rules.
        let foreign_profile = mint_wallet_authentication_challenge(
            &mut state,
            ctx,
            MintWalletAuthChallengeParams {
                challenge_id: "wallet-auth-challenge://m037/test/2".to_string(),
                siwx_profile_ref: "siwx://solana/siws/v1".to_string(),
                chain_id: CHAIN.to_string(),
                requested_account: None,
                domain: DOMAIN.to_string(),
                uri: URI.to_string(),
                nonce: NONCE.to_string(),
                product_session_binding_hash: SESSION_HASH.to_string(),
                expires_in_ms: 300_000,
                statement: STATEMENT.to_string(),
            },
        )
        .expect_err("only the audited EVM profile is issued here");
        assert!(
            foreign_profile
                .to_string()
                .contains("siwx://evm/erc4361/v1"),
            "{foreign_profile}"
        );

        // A challenge with no product-session binding would be a sign-in bound to nothing.
        let unbound = mint_wallet_authentication_challenge(
            &mut state,
            ctx,
            MintWalletAuthChallengeParams {
                challenge_id: "wallet-auth-challenge://m037/test/3".to_string(),
                siwx_profile_ref: SIWX_PROFILE_EVM_V1.to_string(),
                chain_id: CHAIN.to_string(),
                requested_account: None,
                domain: DOMAIN.to_string(),
                uri: URI.to_string(),
                nonce: NONCE.to_string(),
                product_session_binding_hash: "not-a-digest".to_string(),
                expires_in_ms: 300_000,
                statement: STATEMENT.to_string(),
            },
        )
        .expect_err("a challenge must bind the exact product session");
        assert!(
            unbound.to_string().contains("product_session_binding_hash"),
            "{unbound}"
        );
    });
}

#[test]
fn a_discover_then_bind_challenge_accepts_the_account_that_actually_signed() {
    let mut state = MockState::default();
    with_ctx(|ctx| {
        let key = key_from(21);
        let address = address_of(&key);
        let account = caip10(CHAIN, &address);
        // requested_account = None is the contract's discover-then-bind shape: the account is not
        // known in advance, so the signature decides it — and it still has to be on this chain.
        mint(&mut state, ctx, None);
        let challenge = stored_challenge(&state);
        let signature = sign(&key, &message_for(&challenge, &address));
        verify(&mut state, ctx, &account, &signature, "eoa_secp256k1")
            .expect("discover-then-bind binds the account that signed");
        assert_eq!(
            stored_factor(&state, &account).expect("factor").account,
            account
        );
    });
}
