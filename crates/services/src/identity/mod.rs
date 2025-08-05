// Path: crates/services/src/identity/mod.rs

use depin_sdk_api::crypto::{SerializableKey, VerifyingKey};
use depin_sdk_api::services::{BlockchainService, ServiceType, UpgradableService};
use depin_sdk_api::state::StateManager;
use depin_sdk_crypto::sign::{dilithium::DilithiumPublicKey, eddsa::Ed25519PublicKey};
use depin_sdk_types::app::{AccountId, Credential, RotationProof, SignatureSuite};
use depin_sdk_types::error::{StateError, UpgradeError};
use std::any::Any;

#[derive(Debug, Clone)]
pub struct IdentityHub {
    grace_period_blocks: u64,
}

impl IdentityHub {
    pub fn new(grace_period_blocks: u64) -> Self {
        Self {
            grace_period_blocks,
        }
    }

    fn get_credentials_key(account_id: &AccountId) -> Vec<u8> {
        [b"identity::creds::", &account_id[..]].concat()
    }

    fn get_index_key(height: u64) -> Vec<u8> {
        [b"identity::index::", &height.to_le_bytes()].concat()
    }

    fn get_credentials<S: StateManager + ?Sized>(
        &self,
        state: &S,
        account_id: &AccountId,
    ) -> Result<[Option<Credential>; 2], StateError> {
        let creds_key = Self::get_credentials_key(account_id);
        let creds_bytes = state.get(&creds_key)?.unwrap_or_default();
        if creds_bytes.is_empty() {
            return Ok([None, None]);
        }
        serde_json::from_slice(&creds_bytes).map_err(|e| StateError::InvalidValue(e.to_string()))
    }

    fn save_credentials<S: StateManager + ?Sized>(
        &self,
        state: &mut S,
        account_id: &AccountId,
        creds: &[Option<Credential>; 2],
    ) -> Result<(), StateError> {
        let creds_key = Self::get_credentials_key(account_id);
        let creds_bytes =
            serde_json::to_vec(creds).map_err(|e| StateError::InvalidValue(e.to_string()))?;
        state.insert(&creds_key, &creds_bytes)
    }

    fn verify_signature(
        suite: SignatureSuite,
        pub_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), String> {
        let is_valid = match suite {
            SignatureSuite::Ed25519 => Ed25519PublicKey::from_bytes(pub_key)?.verify(
                message,
                &depin_sdk_crypto::sign::eddsa::Ed25519Signature::from_bytes(signature)?,
            ),
            SignatureSuite::Dilithium2 => DilithiumPublicKey::from_bytes(pub_key)?.verify(
                message,
                &depin_sdk_crypto::sign::dilithium::DilithiumSignature::from_bytes(signature)?,
            ),
            _ => return Err("Unsupported signature suite".to_string()),
        };
        if is_valid {
            Ok(())
        } else {
            Err("Signature verification failed".to_string())
        }
    }

    pub fn rotate<S: StateManager + ?Sized>(
        &self,
        state: &mut S,
        account_id: &AccountId,
        proof: &RotationProof,
        current_height: u64,
    ) -> Result<(), String> {
        let mut creds = self
            .get_credentials(state, account_id)
            .map_err(|e| e.to_string())?;
        let active_cred = creds[0]
            .as_ref()
            .ok_or("Account has no active credential")?;

        let mut challenge_data = b"DEPOT_PQC_MIGRATE_".to_vec();
        challenge_data.extend_from_slice(account_id);
        let challenge = depin_sdk_crypto::algorithms::hash::sha256(&challenge_data);

        let old_pk_hash: [u8; 32] =
            depin_sdk_crypto::algorithms::hash::sha256(&proof.old_public_key)
                .try_into()
                .unwrap();
        if old_pk_hash != active_cred.public_key_hash {
            return Err("Old public key does not match active credential".to_string());
        }

        Self::verify_signature(
            active_cred.suite,
            &proof.old_public_key,
            &challenge,
            &proof.old_signature,
        )?;
        Self::verify_signature(
            proof.target_suite,
            &proof.new_public_key,
            &challenge,
            &proof.new_signature,
        )?;

        let activation_height = current_height + self.grace_period_blocks;
        let new_credential = Credential {
            suite: proof.target_suite,
            public_key_hash: depin_sdk_crypto::algorithms::hash::sha256(&proof.new_public_key)
                .try_into()
                .unwrap(),
            activation_height,
            l2_location: None,
        };
        if creds[1].is_some() {
            return Err("Rotation already in progress".to_string());
        }
        creds[1] = Some(new_credential);
        self.save_credentials(state, account_id, &creds)
            .map_err(|e| e.to_string())?;

        // Add this account to the promotion index for the target height
        let index_key = Self::get_index_key(activation_height);
        let mut index_list: Vec<AccountId> = state
            .get(&index_key)
            .map_err(|e| e.to_string())?
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default();
        index_list.push(*account_id);
        let index_bytes = serde_json::to_vec(&index_list).map_err(|e| e.to_string())?;
        state
            .insert(&index_key, &index_bytes)
            .map_err(|e| e.to_string())?;

        log::info!(
            "Key rotation staged for account {}",
            hex::encode(account_id)
        );
        Ok(())
    }

    pub fn promote_staged_credential_for_account<S: StateManager + ?Sized>(
        &self,
        state: &mut S,
        account_id: &AccountId,
    ) -> Result<(), StateError> {
        let mut creds = self.get_credentials(state, account_id)?;
        if creds[1].is_some() {
            creds[0] = creds[1].take();
            self.save_credentials(state, account_id, &creds)?;
        }
        Ok(())
    }
}

impl BlockchainService for IdentityHub {
    fn service_type(&self) -> ServiceType {
        ServiceType::Custom("identity_hub".to_string())
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl UpgradableService for IdentityHub {
    fn prepare_upgrade(&self, _new_module_wasm: &[u8]) -> Result<Vec<u8>, UpgradeError> {
        Ok(Vec::new())
    }
    fn complete_upgrade(&mut self, _snapshot: &[u8]) -> Result<(), UpgradeError> {
        Ok(())
    }
}
