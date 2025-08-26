// Path: crates/services/src/identity/mod.rs

use depin_sdk_api::crypto::{SerializableKey, VerifyingKey};
use depin_sdk_api::lifecycle::OnEndBlock;
use depin_sdk_api::services::access::Service;
use depin_sdk_api::services::{BlockchainService, ServiceType, UpgradableService};
use depin_sdk_api::state::StateAccessor;
use depin_sdk_api::transaction::context::TxContext;
use depin_sdk_api::transaction::decorator::TxDecorator;
use depin_sdk_crypto::sign::{dilithium::DilithiumPublicKey, eddsa::Ed25519PublicKey};
use depin_sdk_types::app::{
    AccountId, ChainTransaction, Credential, RotationProof, SignatureSuite, SystemPayload,
};
use depin_sdk_types::error::{StateError, TransactionError, UpgradeError};
use depin_sdk_types::keys::{
    IDENTITY_CREDENTIALS_PREFIX, IDENTITY_PROMOTION_INDEX_PREFIX, IDENTITY_ROTATION_NONCE_PREFIX,
};
use depin_sdk_types::service_configs::MigrationConfig;
use libp2p::identity::PublicKey as Libp2pPublicKey;

#[derive(Debug, Clone)]
pub struct IdentityHub {
    pub config: MigrationConfig,
}

fn u64_from_le_bytes(bytes: Option<&Vec<u8>>) -> u64 {
    bytes
        .and_then(|b| b.as_slice().try_into().ok())
        .map(u64::from_le_bytes)
        .unwrap_or(0)
}

impl IdentityHub {
    pub fn new(config: MigrationConfig) -> Self {
        Self { config }
    }

    fn get_credentials_key(account_id: &AccountId) -> Vec<u8> {
        [IDENTITY_CREDENTIALS_PREFIX, &account_id[..]].concat()
    }
    fn get_index_key(height: u64) -> Vec<u8> {
        [IDENTITY_PROMOTION_INDEX_PREFIX, &height.to_le_bytes()].concat()
    }
    fn get_nonce_key(account_id: &AccountId) -> Vec<u8> {
        [IDENTITY_ROTATION_NONCE_PREFIX, &account_id[..]].concat()
    }

    pub fn get_credentials(
        &self,
        state: &dyn StateAccessor,
        account_id: &AccountId,
    ) -> Result<[Option<Credential>; 2], StateError> {
        let creds_bytes = state
            .get(&Self::get_credentials_key(account_id))?
            .unwrap_or_default();
        if creds_bytes.is_empty() {
            return Ok([None, None]);
        }
        serde_json::from_slice(&creds_bytes).map_err(|e| StateError::InvalidValue(e.to_string()))
    }

    fn save_credentials(
        &self,
        state: &mut dyn StateAccessor,
        account_id: &AccountId,
        creds: &[Option<Credential>; 2],
    ) -> Result<(), StateError> {
        let creds_bytes =
            serde_json::to_vec(creds).map_err(|e| StateError::InvalidValue(e.to_string()))?;
        state.insert(&Self::get_credentials_key(account_id), &creds_bytes)
    }

    fn verify_signature(
        suite: SignatureSuite,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), String> {
        match suite {
            SignatureSuite::Ed25519 => {
                if public_key.len() == 32 {
                    // Raw 32-byte Ed25519 key
                    let pk = Ed25519PublicKey::from_bytes(public_key)?;
                    let sig =
                        depin_sdk_crypto::sign::eddsa::Ed25519Signature::from_bytes(signature)?;
                    if pk.verify(message, &sig) {
                        Ok(())
                    } else {
                        Err("Signature verification failed".into())
                    }
                } else {
                    // Back-compat: libp2p protobuf-encoded Ed25519 public key
                    let pk = Libp2pPublicKey::try_decode_protobuf(public_key)
                        .map_err(|_| "Invalid libp2p protobuf public key".to_string())?;
                    if pk.verify(message, signature) {
                        Ok(())
                    } else {
                        Err("Signature verification failed".into())
                    }
                }
            }
            SignatureSuite::Dilithium2 => {
                let pk = DilithiumPublicKey::from_bytes(public_key)?;
                let sig =
                    depin_sdk_crypto::sign::dilithium::DilithiumSignature::from_bytes(signature)?;
                if pk.verify(message, &sig) {
                    Ok(())
                } else {
                    Err("Signature verification failed".into())
                }
            }
        }
    }

    pub fn rotation_challenge(
        &self,
        state: &dyn StateAccessor,
        account_id: &AccountId,
    ) -> Result<[u8; 32], StateError> {
        let nonce = u64_from_le_bytes(state.get(&Self::get_nonce_key(account_id))?.as_ref());
        let mut preimage = b"DePIN-PQ-MIGRATE/v1".to_vec();
        preimage.extend_from_slice(&self.config.chain_id.to_le_bytes());
        preimage.extend_from_slice(account_id);
        preimage.extend_from_slice(&nonce.to_le_bytes());
        Ok(depin_sdk_crypto::algorithms::hash::sha256(&preimage)
            .try_into()
            .unwrap())
    }

    pub fn rotate(
        &self,
        state: &mut dyn StateAccessor,
        account_id: &AccountId,
        proof: &RotationProof,
        current_height: u64,
    ) -> Result<(), String> {
        if !self
            .config
            .allowed_target_suites
            .contains(&proof.target_suite)
        {
            return Err("Target suite not allowed by chain policy".to_string());
        }
        let creds = self
            .get_credentials(state, account_id)
            .map_err(|e| e.to_string())?;
        let active_cred = creds[0]
            .as_ref()
            .ok_or("No active credential to rotate from")?;
        if creds[1].is_some() {
            return Err("Rotation already in progress for this account".to_string());
        }
        if !self.config.allow_downgrade && (proof.target_suite as u8) < (active_cred.suite as u8) {
            return Err("Cryptographic downgrade is forbidden by policy".to_string());
        }

        let challenge = self
            .rotation_challenge(state, account_id)
            .map_err(|e| e.to_string())?;
        let old_pk_hash: [u8; 32] =
            depin_sdk_crypto::algorithms::hash::sha256(&proof.old_public_key)
                .try_into()
                .unwrap();
        if old_pk_hash != active_cred.public_key_hash {
            return Err("old_public_key does not match active credential".into());
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

        if let Some(_loc) = &proof.l2_location {
            // let multihash = parse_multihash(loc)?; // Placeholder for a multihash library
            // if multihash.digest() != sha256(&proof.new_public_key) { return Err("l2_location hash mismatch".into()); }
        }

        let activation_height = current_height + self.config.grace_period_blocks;
        let new_cred = Credential {
            suite: proof.target_suite,
            public_key_hash: depin_sdk_crypto::algorithms::hash::sha256(&proof.new_public_key)
                .try_into()
                .unwrap(),
            activation_height,
            l2_location: proof.l2_location.clone(),
        };
        let mut creds_mut = creds;
        creds_mut[1] = Some(new_cred);
        self.save_credentials(state, account_id, &creds_mut)
            .map_err(|e| e.to_string())?;

        let idx_key = Self::get_index_key(activation_height);
        let mut list: Vec<AccountId> = state
            .get(&idx_key)
            .map_err(|e| e.to_string())?
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        if !list.contains(account_id) {
            list.push(*account_id);
            state
                .insert(&idx_key, &serde_json::to_vec(&list).unwrap())
                .map_err(|e| e.to_string())?;
        }

        let nonce_key = Self::get_nonce_key(account_id);
        let next_nonce =
            u64_from_le_bytes(state.get(&nonce_key).map_err(|e| e.to_string())?.as_ref()) + 1;
        state
            .insert(&nonce_key, &next_nonce.to_le_bytes())
            .map_err(|e| e.to_string())?;
        Ok(())
    }
}

impl BlockchainService for IdentityHub {
    fn service_type(&self) -> ServiceType {
        ServiceType::Custom("identity_hub".to_string())
    }
}

impl Service for IdentityHub {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn as_tx_decorator(&self) -> Option<&dyn depin_sdk_api::transaction::decorator::TxDecorator> {
        Some(self)
    }

    fn as_on_end_block(&self) -> Option<&dyn depin_sdk_api::lifecycle::OnEndBlock> {
        Some(self)
    }
}

impl UpgradableService for IdentityHub {
    fn prepare_upgrade(&mut self, _new_module_wasm: &[u8]) -> Result<Vec<u8>, UpgradeError> {
        Ok(Vec::new())
    }
    fn complete_upgrade(&mut self, _snapshot: &[u8]) -> Result<(), UpgradeError> {
        Ok(())
    }
}

impl TxDecorator for IdentityHub {
    fn ante_handle(
        &self,
        state: &mut dyn StateAccessor,
        tx: &ChainTransaction,
        ctx: &TxContext,
    ) -> Result<(), TransactionError> {
        // Only gate key-rotation at the identity layer; other system messages
        // are validated/authorized in their respective modules.
        if let ChainTransaction::System(sys_tx) = tx {
            if let SystemPayload::RotateKey(_) = sys_tx.payload {
                // continue
            } else {
                return Ok(());
            }
        }

        let (header, proof, sign_bytes) = match tx {
            ChainTransaction::System(sys_tx) => (
                sys_tx.header,
                sys_tx.signature_proof.clone(),
                sys_tx.to_sign_bytes()?,
            ),
            ChainTransaction::Application(app_tx) => match app_tx {
                depin_sdk_types::app::ApplicationTransaction::DeployContract {
                    header,
                    signature_proof,
                    ..
                }
                | depin_sdk_types::app::ApplicationTransaction::CallContract {
                    header,
                    signature_proof,
                    ..
                } => (*header, signature_proof.clone(), app_tx.to_sign_bytes()?),
                _ => return Ok(()), // UTXO has its own signing mechanism
            },
        };

        let pk_hash: [u8; 32] = depin_sdk_crypto::algorithms::hash::sha256(&proof.public_key)
            .try_into()
            .unwrap();
        let creds = self.get_credentials(state, &header.account_id)?;

        // First-use bootstrap if the account has no credentials at all
        if creds[0].is_none() && creds[1].is_none() {
            // Suite policy gate
            if !self.config.allowed_target_suites.contains(&proof.suite) {
                return Err(TransactionError::Invalid(
                    "Signature suite not allowed by chain policy".into(),
                ));
            }

            // Verify the signature with the presented public key.
            Self::verify_signature(
                proof.suite,
                &proof.public_key,
                &sign_bytes,
                &proof.signature,
            )
            .map_err(TransactionError::Invalid)?;

            // Persist as active credential immediately.
            let new_cred = Credential {
                suite: proof.suite,
                public_key_hash: pk_hash,
                activation_height: ctx.block_height,
                l2_location: None,
            };
            self.save_credentials(state, &header.account_id, &[Some(new_cred), None])?;

            // Initialize rotation nonce if missing.
            let nonce_key = Self::get_nonce_key(&header.account_id);
            if state.get(&nonce_key)?.is_none() {
                state.insert(&nonce_key, &0u64.to_le_bytes())?;
            }

            log::info!(
                "[Identity] Bootstrapped and authorized account {}",
                hex::encode(header.account_id)
            );
            return Ok(());
        }

        let mut is_authorized = false;
        if let Some(active) = &creds[0] {
            if active.public_key_hash == pk_hash && active.suite == proof.suite {
                // It's the active key. Is there a rotation in progress that has expired?
                if let Some(staged) = &creds[1] {
                    if ctx.block_height >= staged.activation_height {
                        // Grace period is over. This old key is no longer valid.
                        is_authorized = false;
                    } else {
                        // Inside grace period, old key is still ok.
                        is_authorized = true;
                    }
                } else {
                    // No rotation, active key is fine.
                    is_authorized = true;
                }
            }
        }

        if !is_authorized {
            if let Some(staged) = &creds[1] {
                // This logic is for accepting the *new* key during the grace period.
                if self.config.accept_staged_during_grace
                    && ctx.block_height < staged.activation_height
                {
                    if staged.public_key_hash == pk_hash && staged.suite == proof.suite {
                        is_authorized = true;
                    }
                }
                // Also check if the new key is being used *after* the grace period.
                if ctx.block_height >= staged.activation_height {
                    if staged.public_key_hash == pk_hash && staged.suite == proof.suite {
                        is_authorized = true;
                    }
                }
            }
        }

        if !is_authorized {
            return Err(TransactionError::Invalid(
                "Signer's key does not match any valid (active or staged) credential".into(),
            ));
        }

        // Cryptographic verification (defense-in-depth)
        Self::verify_signature(
            proof.suite,
            &proof.public_key,
            &sign_bytes,
            &proof.signature,
        )
        .map_err(|e| TransactionError::Invalid(format!("Signature verification failed: {}", e)))?;

        Ok(())
    }
}

impl OnEndBlock for IdentityHub {
    fn on_end_block(
        &self,
        state: &mut dyn StateAccessor,
        ctx: &TxContext,
    ) -> Result<(), StateError> {
        let height = ctx.block_height;
        let idx_key = Self::get_index_key(height);
        if let Some(bytes) = state.get(&idx_key)? {
            let accounts: Vec<AccountId> = serde_json::from_slice(&bytes).unwrap_or_default();
            for account_id in accounts {
                let mut creds = self.get_credentials(state, &account_id)?;
                if let Some(staged) = &creds[1] {
                    if height >= staged.activation_height {
                        if let Some(staged_taken) = creds[1].take() {
                            creds[0] = Some(staged_taken);
                            self.save_credentials(state, &account_id, &creds)?;
                        }
                    }
                }
            }
            state.delete(&idx_key)?;
        }
        Ok(())
    }
}
