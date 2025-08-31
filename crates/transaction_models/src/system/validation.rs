// Path: crates/transaction_models/src/system/validation.rs

//! Core, non-optional system logic for transaction signature validation.

use depin_sdk_api::services::access::ServiceDirectory;
use depin_sdk_api::state::{StateAccessor, StateManager};
use depin_sdk_api::transaction::context::TxContext;
use depin_sdk_crypto::sign::{dilithium::DilithiumPublicKey, eddsa::Ed25519PublicKey};
use depin_sdk_types::app::{
    account_id_from_key_material, ApplicationTransaction, ChainTransaction, Credential, SignHeader,
    SignatureProof, SignatureSuite,
};
use depin_sdk_types::error::TransactionError;
use libp2p::identity::PublicKey as Libp2pPublicKey;

/// A centralized helper for verifying cryptographic signatures.
fn verify_signature(
    suite: SignatureSuite,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), String> {
    use depin_sdk_api::crypto::{SerializableKey, VerifyingKey};

    match suite {
        SignatureSuite::Ed25519 => {
            if let Ok(pk) = Libp2pPublicKey::try_decode_protobuf(public_key) {
                if pk.verify(message, signature) {
                    Ok(())
                } else {
                    Err("Libp2p signature verification failed".into())
                }
            } else if let Ok(pk) = Ed25519PublicKey::from_bytes(public_key) {
                let sig = depin_sdk_crypto::sign::eddsa::Ed25519Signature::from_bytes(signature)?;
                if pk.verify(message, &sig) {
                    Ok(())
                } else {
                    Err("Ed25519 signature verification failed".into())
                }
            } else {
                Err("Could not decode Ed25519 public key".into())
            }
        }
        SignatureSuite::Dilithium2 => {
            let pk = DilithiumPublicKey::from_bytes(public_key)?;
            let sig = depin_sdk_crypto::sign::dilithium::DilithiumSignature::from_bytes(signature)?;
            if pk.verify(message, &sig) {
                Ok(())
            } else {
                Err("Dilithium signature verification failed".into())
            }
        }
    }
}

/// Extracts the signature components from a transaction by borrowing, if it is a signed type.
fn get_signature_components<'a>(
    tx: &'a ChainTransaction,
) -> Result<Option<(&'a SignHeader, &'a SignatureProof, Vec<u8>)>, TransactionError> {
    match tx {
        ChainTransaction::System(sys_tx) => match &sys_tx.payload {
            depin_sdk_types::app::SystemPayload::VerifyForeignReceipt { .. }
            | depin_sdk_types::app::SystemPayload::UpdateAuthorities { .. }
            | depin_sdk_types::app::SystemPayload::SubmitOracleData { .. } => Ok(None),
            _ => {
                let sign_bytes = sys_tx.to_sign_bytes()?;
                Ok(Some((&sys_tx.header, &sys_tx.signature_proof, sign_bytes)))
            }
        },
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
                let sign_bytes = app_tx.to_sign_bytes()?;
                Ok(Some((header, signature_proof, sign_bytes)))
            }
            ApplicationTransaction::UTXO(_) => Ok(None),
        },
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

/// Verifies the signature of a transaction against the on-chain credentials or allows bootstrapping.
pub fn verify_transaction_signature<S: StateManager + Send>(
    state: &S,
    services: &ServiceDirectory,
    tx: &ChainTransaction,
    ctx: &TxContext,
) -> Result<(), TransactionError> {
    let (header, proof, sign_bytes) = match get_signature_components(tx)? {
        Some(t) => t,
        None => return Ok(()),
    };

    let creds_view = services.services().find_map(|s| s.as_credentials_view());
    let creds = if let Some(view) = &creds_view {
        let state_accessor: &dyn StateAccessor = state;
        view.get_credentials(state_accessor, &header.account_id)?
    } else {
        [None, None]
    };

    if creds[0].is_none() && creds[1].is_some() {
        return Err(TransactionError::Unsupported(
            "Invalid state: staged credential exists without an active one.".into(),
        ));
    }

    if creds[0].is_none() && creds[1].is_none() {
        // BOOTSTRAP PATH
        let derived_pk_hash = account_id_from_key_material(proof.suite, &proof.public_key)?;
        if header.account_id.0 != derived_pk_hash {
            return Err(TransactionError::AccountIdMismatch);
        }
    } else {
        // CREDENTIAL PATH
        let derived_pk_hash_array = account_id_from_key_material(proof.suite, &proof.public_key)?;
        let accept_staged = creds_view
            .as_ref()
            .map_or(true, |v| v.accept_staged_during_grace());
        enforce_credential_policy(
            &creds,
            proof.suite,
            &derived_pk_hash_array,
            ctx.block_height,
            accept_staged,
        )?;
    }

    verify_signature(
        proof.suite,
        &proof.public_key,
        &sign_bytes,
        &proof.signature,
    )
    .map_err(TransactionError::InvalidSignature)?;

    Ok(())
}
