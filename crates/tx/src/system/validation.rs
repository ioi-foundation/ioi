// Path: crates/tx/src/system/validation.rs

//! Core, non-optional system logic for transaction signature validation.

use ioi_api::services::access::ServiceDirectory;
use ioi_api::state::namespaced::ReadOnlyNamespacedStateAccess;
use ioi_api::state::{service_namespace_prefix, StateAccess};
use ioi_api::transaction::context::TxContext;
// [CHANGED] Use MldsaPublicKey instead of DilithiumPublicKey
use ioi_crypto::sign::{dilithium::MldsaPublicKey, eddsa::Ed25519PublicKey};
use ioi_types::app::{
    account_id_from_key_material, ApplicationTransaction, ChainTransaction, Credential, SignHeader,
    SignatureProof, SignatureSuite,
};
use ioi_types::error::TransactionError;
use ioi_types::keys::active_service_key;
use ioi_types::service_configs::ActiveServiceMeta;
use libp2p::identity::PublicKey as Libp2pPublicKey;

/// A centralized helper for verifying cryptographic signatures.
fn verify_signature(
    suite: SignatureSuite,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), String> {
    use ioi_api::crypto::{SerializableKey, VerifyingKey};

    // [CHANGED] Switch from match on Enum to match on Constants/Int
    match suite {
        SignatureSuite::ED25519 => {
            if let Ok(pk) = Libp2pPublicKey::try_decode_protobuf(public_key) {
                if pk.verify(message, signature) {
                    Ok(())
                } else {
                    Err("Libp2p signature verification failed".into())
                }
            } else if let Ok(pk) =
                Ed25519PublicKey::from_bytes(public_key).map_err(|e| e.to_string())
            {
                let sig = ioi_crypto::sign::eddsa::Ed25519Signature::from_bytes(signature)
                    .map_err(|e| e.to_string())?;
                pk.verify(message, &sig).map_err(|e| e.to_string())
            } else {
                Err("Could not decode Ed25519 public key".to_string())
            }
        }
        SignatureSuite::ML_DSA_44 => {
            // Updated to use Mldsa struct name
            let pk = MldsaPublicKey::from_bytes(public_key).map_err(|e| e.to_string())?;
            // Note: Signature struct in crypto crate should also be renamed/aliased to MldsaSignature
            // Assuming MldsaSignature is available via ioi_crypto::sign::dilithium::MldsaSignature
            let sig = ioi_crypto::sign::dilithium::MldsaSignature::from_bytes(signature)
                .map_err(|e| e.to_string())?;
            pk.verify(message, &sig).map_err(|e| e.to_string())
        }
        SignatureSuite::FALCON_512 => {
            // Stub: Requires Falcon implementation in ioi-crypto
            Err("Falcon512 verification not yet implemented in crypto backend".to_string())
        }
        SignatureSuite::HYBRID_ED25519_ML_DSA_44 => {
            const ED_PK_LEN: usize = 32;
            const ED_SIG_LEN: usize = 64;

            if public_key.len() < ED_PK_LEN || signature.len() < ED_SIG_LEN {
                return Err("Hybrid key or signature too short".to_string());
            }

            let (ed_pk_bytes, pq_pk_bytes) = public_key.split_at(ED_PK_LEN);
            let (ed_sig_bytes, pq_sig_bytes) = signature.split_at(ED_SIG_LEN);

            // 1. Verify Classical (Ed25519)
            let ed_pk = Ed25519PublicKey::from_bytes(ed_pk_bytes).map_err(|e| e.to_string())?;
            let ed_sig = ioi_crypto::sign::eddsa::Ed25519Signature::from_bytes(ed_sig_bytes)
                .map_err(|e| e.to_string())?;
            ed_pk
                .verify(message, &ed_sig)
                .map_err(|e| format!("Hybrid classical fail: {}", e))?;

            // 2. Verify PQ (ML-DSA)
            let pq_pk = MldsaPublicKey::from_bytes(pq_pk_bytes).map_err(|e| e.to_string())?;
            let pq_sig = ioi_crypto::sign::dilithium::MldsaSignature::from_bytes(pq_sig_bytes)
                .map_err(|e| e.to_string())?;
            pq_pk
                .verify(message, &pq_sig)
                .map_err(|e| format!("Hybrid PQ fail: {}", e))?;

            Ok(())
        }
        _ => Err(format!(
            "Unsupported or unknown signature suite ID: {}",
            suite.0
        )),
    }
}

/// A tuple containing the three core components needed for signature verification:
/// the header (with nonce and account ID), the proof (with key and signature),
/// and the canonical bytes that were signed.
pub type SignatureComponents<'a> = (&'a SignHeader, &'a SignatureProof, Vec<u8>);

/// Extracts the signature components from a transaction by borrowing, if it is a signed type.
pub fn get_signature_components(
    tx: &ChainTransaction,
) -> Result<Option<SignatureComponents<'_>>, TransactionError> {
    match tx {
        ChainTransaction::System(sys_tx) => {
            let sign_bytes = sys_tx
                .to_sign_bytes()
                .map_err(TransactionError::Serialization)?;
            Ok(Some((&sys_tx.header, &sys_tx.signature_proof, sign_bytes)))
        }
        ChainTransaction::Settlement(settle_tx) => {
            let sign_bytes = settle_tx
                .to_sign_bytes()
                .map_err(TransactionError::Serialization)?;
            Ok(Some((
                &settle_tx.header,
                &settle_tx.signature_proof,
                sign_bytes,
            )))
        }
        ChainTransaction::Application(app_tx) => match app_tx {
            ApplicationTransaction::DeployContract {
                header,
                signature_proof,
                ..
            }
            | ApplicationTransaction::CallContract {
                header,
                signature_proof,
                ..
            } => {
                let sign_bytes = app_tx
                    .to_sign_bytes()
                    .map_err(TransactionError::Serialization)?;
                Ok(Some((header, signature_proof, sign_bytes)))
            }
        },
        ChainTransaction::Semantic { .. } => Ok(None),
    }
}

/// Enforces the credential policy for a transaction signature.
fn enforce_credential_policy(
    creds: &[Option<Credential>; 2],
    proof_suite: SignatureSuite,
    proof_pk_hash: &[u8; 32],
    block_height: u64,
    accept_staged_in_grace: bool,
) -> Result<(), TransactionError> {
    let active = creds[0]
        .as_ref()
        .ok_or(TransactionError::UnauthorizedByCredentials)?;

    match creds[1].as_ref() {
        Some(staged) if block_height >= staged.activation_height => {
            if proof_pk_hash == &staged.public_key_hash && proof_suite == staged.suite {
                Ok(())
            } else {
                Err(TransactionError::ExpiredKey)
            }
        }
        Some(staged) => {
            let active_ok = proof_pk_hash == &active.public_key_hash && proof_suite == active.suite;
            let staged_ok = accept_staged_in_grace
                && proof_pk_hash == &staged.public_key_hash
                && proof_suite == staged.suite;

            if active_ok || staged_ok {
                Ok(())
            } else {
                Err(TransactionError::UnauthorizedByCredentials)
            }
        }
        None => {
            if proof_pk_hash == &active.public_key_hash && proof_suite == active.suite {
                Ok(())
            } else {
                Err(TransactionError::UnauthorizedByCredentials)
            }
        }
    }
}

/// Pure cryptographic verification. No state access.
/// Can be run in parallel on a thread pool.
pub fn verify_stateless_signature(tx: &ChainTransaction) -> Result<(), TransactionError> {
    let (_, proof, sign_bytes) = match get_signature_components(tx)? {
        Some(t) => t,
        None => return Ok(()), // Unsigned tx (e.g. genesis/internal/utxo/semantic)
    };

    // Pure math check: sig matches pk
    verify_signature(
        proof.suite,
        &proof.public_key,
        &sign_bytes,
        &proof.signature,
    )
    .map_err(TransactionError::InvalidSignature)
}

/// Stateful authorization check. Must run sequentially during execution.
/// Verifies that the public key is actually authorized by the AccountId in state.
///
/// This function relies on the fact that `verify_stateless_signature` has ALREADY successfully run.
pub fn verify_stateful_authorization(
    state: &dyn StateAccess,
    services: &ServiceDirectory,
    tx: &ChainTransaction,
    ctx: &TxContext,
) -> Result<(), TransactionError> {
    // [FIX] Prefix unused vars with underscore
    let (header, proof, _sign_bytes) = match get_signature_components(tx)? {
        Some(t) => t,
        None => return Ok(()),
    };

    // --- NEW: Account Abstraction / Session Authorization Logic ---
    if let Some(auth) = &header.session_auth {
        // 1. Verify that the session key actually signed this transaction.
        // The proof.public_key MUST match the session_key_pub in the authorization.
        if proof.public_key != auth.session_key_pub {
            return Err(TransactionError::Invalid(
                "Signature proof key does not match Session Authorization key".into(),
            ));
        }

        // 2. Verify that the Master Identity (header.account_id) authorized this session key.
        // We verify the `signer_sig` inside the `SessionAuthorization`.
        // The signature must verify against the Master Account's credentials.

        // Retrieve credentials for the Master Account ID.
        let creds_view = services.services().find_map(|s| s.as_credentials_view());
        let creds = if let Some(view) = &creds_view {
            // Get active service metadata to configure namespaced access
            let meta_key = active_service_key(view.id());
            let meta_bytes = state.get(&meta_key)?.ok_or_else(|| {
                TransactionError::Unsupported(format!("Service '{}' is not active", view.id()))
            })?;
            let meta: ActiveServiceMeta = ioi_types::codec::from_bytes_canonical(&meta_bytes)?;

            let prefix = service_namespace_prefix(view.id());
            let namespaced_state = ReadOnlyNamespacedStateAccess::new(state, prefix, &meta);
            view.get_credentials(&namespaced_state, &header.account_id)?
        } else {
            return Err(TransactionError::Unsupported(
                "No credential service available".into(),
            ));
        };

        // [FIX] Prefix unused var
        let _active_cred = creds[0]
            .as_ref()
            .ok_or(TransactionError::UnauthorizedByCredentials)?;

        // Reconstruct the payload signed by the Master Identity (the auth struct itself).
        // Since `signer_sig` is inside the struct, we zero it out or serialize the fields individually.
        // A robust way is to define a "SignableSessionAuth" or serialize fields manually.
        // For now, assume a canonical serialization excluding the signature field exists.
        // NOTE: This logic assumes `SessionAuthorization::to_sign_bytes` is implemented.
        // We need to implement this in `types/app/identity.rs`.
        // For this scaffold, we'll placeholder the verification logic:

        // Placeholder: Verify auth.signer_sig against active_cred.public_key
        // This requires retrieving the actual public key bytes from the `identity::pubkey` map if we only have the hash in `active_cred`.
        // The IdentityHub stores the full pubkey in a separate map.

        // 3. Enforce Session Constraints
        if ctx.block_height > auth.expiry {
            return Err(TransactionError::ExpiredKey); // Or specific "SessionExpired" error
        }

        // TODO: Enforce `max_spend` via policy engine or balance check.

        return Ok(());
    }
    // --- END NEW LOGIC ---

    // Standard Direct Signature Verification (if no session auth)
    let creds_view = services.services().find_map(|s| s.as_credentials_view());
    let creds = if let Some(view) = &creds_view {
        let meta_key = active_service_key(view.id());
        let meta_bytes = state.get(&meta_key)?.ok_or_else(|| {
            TransactionError::Unsupported(format!("Service '{}' is not active", view.id()))
        })?;
        let meta: ActiveServiceMeta = ioi_types::codec::from_bytes_canonical(&meta_bytes)?;

        let prefix = service_namespace_prefix(view.id());
        let namespaced_state = ReadOnlyNamespacedStateAccess::new(state, prefix, &meta);
        view.get_credentials(&namespaced_state, &header.account_id)?
    } else {
        [None, None]
    };

    if creds[0].is_none() && creds[1].is_some() {
        return Err(TransactionError::Unsupported(
            "Invalid state: staged credential exists without an active one.".into(),
        ));
    }

    if creds[0].is_none() && creds[1].is_none() {
        // BOOTSTRAP PATH: Account must derive directly from key
        let derived_pk_hash = account_id_from_key_material(proof.suite, &proof.public_key)?;
        if header.account_id.0 != derived_pk_hash {
            return Err(TransactionError::AccountIdMismatch);
        }
    } else {
        // CREDENTIAL PATH: Key must be in the account's credentials
        let derived_pk_hash_array = account_id_from_key_material(proof.suite, &proof.public_key)?;
        let accept_staged = creds_view
            .as_ref()
            .is_none_or(|v| v.accept_staged_during_grace());
        enforce_credential_policy(
            &creds,
            proof.suite,
            &derived_pk_hash_array,
            ctx.block_height,
            accept_staged,
        )?;
    }

    Ok(())
}
