// Path: crates/services/src/identity/mod.rs
use async_trait::async_trait;
use depin_sdk_api::crypto::{SerializableKey, VerifyingKey};
use depin_sdk_api::identity::CredentialsView;
use depin_sdk_api::lifecycle::OnEndBlock;
use depin_sdk_api::services::{BlockchainService, UpgradableService};
use depin_sdk_api::state::StateAccessor;
use depin_sdk_api::transaction::context::TxContext;
use depin_sdk_crypto::sign::{dilithium::DilithiumPublicKey, eddsa::Ed25519PublicKey};
use depin_sdk_types::app::{
    account_id_from_key_material, read_validator_sets, write_validator_sets, AccountId,
    ActiveKeyRecord, Credential, RotationProof, SignatureSuite, ValidatorSetV1,
};
use depin_sdk_types::codec;
use depin_sdk_types::error::{StateError, TransactionError, UpgradeError};
use depin_sdk_types::keys::{
    IDENTITY_CREDENTIALS_PREFIX, IDENTITY_PROMOTION_INDEX_PREFIX, IDENTITY_ROTATION_NONCE_PREFIX,
    VALIDATOR_SET_KEY,
};
use depin_sdk_types::service_configs::{Capabilities, MigrationConfig};
use parity_scale_codec::Decode;
use std::any::Any;

#[derive(Debug, Clone)]
pub struct IdentityHub {
    pub config: MigrationConfig,
}

/// Helper struct for deserializing parameters for the `rotate_key` method.
#[derive(Decode)]
struct RotateKeyParams {
    proof: RotationProof,
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
        [IDENTITY_CREDENTIALS_PREFIX, account_id.as_ref()].concat()
    }
    fn get_index_key(height: u64) -> Vec<u8> {
        [IDENTITY_PROMOTION_INDEX_PREFIX, &height.to_le_bytes()].concat()
    }
    fn get_nonce_key(account_id: &AccountId) -> Vec<u8> {
        [IDENTITY_ROTATION_NONCE_PREFIX, account_id.as_ref()].concat()
    }

    fn load_credentials(
        &self,
        state: &dyn StateAccessor,
        account_id: &AccountId,
    ) -> Result<[Option<Credential>; 2], StateError> {
        let key = Self::get_credentials_key(account_id);
        let bytes = state.get(&key)?.unwrap_or_default();
        if bytes.is_empty() {
            return Ok([None, None]);
        }
        depin_sdk_types::codec::from_bytes_canonical(&bytes)
            .map_err(|e| StateError::InvalidValue(e.to_string()))
    }

    fn save_credentials(
        &self,
        state: &mut dyn StateAccessor,
        account_id: &AccountId,
        creds: &[Option<Credential>; 2],
    ) -> Result<(), StateError> {
        let creds_bytes =
            depin_sdk_types::codec::to_bytes_canonical(creds).map_err(StateError::InvalidValue)?;
        state.insert(&Self::get_credentials_key(account_id), &creds_bytes)
    }

    /// Helper: bump validator set so the rotated key becomes active at next height
    fn apply_validator_key_update(
        &self,
        state: &mut dyn StateAccessor,
        account_id: &AccountId,
        new_suite: SignatureSuite,
        new_pubkey_hash: [u8; 32],
        promotion_height: u64,
    ) -> Result<(), StateError> {
        let Some(vs_blob) = state.get(VALIDATOR_SET_KEY)? else {
            return Ok(());
        };
        let mut sets = read_validator_sets(&vs_blob)?;
        let target_activation = promotion_height + 1;

        if sets
            .next
            .as_ref()
            .map_or(true, |n| n.effective_from_height != target_activation)
        {
            let mut next = sets.next.clone().unwrap_or_else(|| sets.current.clone());
            next.effective_from_height = target_activation;
            sets.next = Some(next);
        }
        let next_vs: &mut ValidatorSetV1 = sets.next.as_mut().expect("next set must exist");

        if let Some(v) = next_vs
            .validators
            .iter_mut()
            .find(|v| v.account_id == *account_id)
        {
            v.consensus_key = ActiveKeyRecord {
                suite: new_suite,
                public_key_hash: new_pubkey_hash,
                since_height: target_activation,
            };
            log::info!(
                "[IdentityHub] VS.next set for H={} updated: account 0x{} -> suite={:?}, since_height={}",
                target_activation,
                hex::encode(&account_id.as_ref()[..4]),
                new_suite,
                target_activation
            );
        } else {
            return Ok(());
        }

        next_vs
            .validators
            .sort_by(|a, b| a.account_id.cmp(&b.account_id));
        next_vs.total_weight = next_vs.validators.iter().map(|v| v.weight).sum();

        state.insert(VALIDATOR_SET_KEY, &write_validator_sets(&sets)?)?;
        Ok(())
    }

    fn verify_rotation_signature(
        suite: SignatureSuite,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), String> {
        match suite {
            SignatureSuite::Ed25519 => {
                let pk = Ed25519PublicKey::from_bytes(public_key).map_err(|e| e.to_string())?;
                let sig = depin_sdk_crypto::sign::eddsa::Ed25519Signature::from_bytes(signature)
                    .map_err(|e| e.to_string())?;
                pk.verify(message, &sig).map_err(|e| e.to_string())
            }
            SignatureSuite::Dilithium2 => {
                let pk = DilithiumPublicKey::from_bytes(public_key).map_err(|e| e.to_string())?;
                let sig =
                    depin_sdk_crypto::sign::dilithium::DilithiumSignature::from_bytes(signature)
                        .map_err(|e| e.to_string())?;
                pk.verify(message, &sig).map_err(|e| e.to_string())
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
        preimage.extend_from_slice(account_id.as_ref());
        preimage.extend_from_slice(&nonce.to_le_bytes());
        depin_sdk_crypto::algorithms::hash::sha256(&preimage)
            .map_err(|e| StateError::Backend(e.to_string()))?
            .try_into()
            .map_err(|_| StateError::InvalidValue("hash len".into()))
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
            .load_credentials(state, account_id)
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
        let old_pk_hash = account_id_from_key_material(active_cred.suite, &proof.old_public_key)
            .map_err(|e| e.to_string())?;

        if old_pk_hash != active_cred.public_key_hash {
            return Err("old_public_key does not match active credential".to_string());
        }
        Self::verify_rotation_signature(
            active_cred.suite,
            &proof.old_public_key,
            &challenge,
            &proof.old_signature,
        )?;
        Self::verify_rotation_signature(
            proof.target_suite,
            &proof.new_public_key,
            &challenge,
            &proof.new_signature,
        )?;

        let activation_height = current_height + self.config.grace_period_blocks;
        let new_cred = Credential {
            suite: proof.target_suite,
            public_key_hash: account_id_from_key_material(
                proof.target_suite,
                &proof.new_public_key,
            )
            .map_err(|e| e.to_string())?,
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
            .and_then(|b| codec::from_bytes_canonical(&b).ok())
            .unwrap_or_default();
        if !list.contains(account_id) {
            list.push(*account_id);
            state
                .insert(&idx_key, &codec::to_bytes_canonical(&list).map_err(|e| e)?)
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

#[async_trait]
impl BlockchainService for IdentityHub {
    fn id(&self) -> &'static str {
        "identity_hub"
    }
    fn abi_version(&self) -> u32 {
        1
    }
    fn state_schema(&self) -> &'static str {
        "v1"
    }
    fn capabilities(&self) -> Capabilities {
        // The service is no longer a TxDecorator itself for this specific action,
        // but it still needs to perform logic at the end of a block to promote keys.
        Capabilities::ON_END_BLOCK
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn as_on_end_block(&self) -> Option<&dyn OnEndBlock> {
        Some(self)
    }
    fn as_credentials_view(&self) -> Option<&dyn CredentialsView> {
        Some(self)
    }

    async fn handle_service_call(
        &self,
        state: &mut dyn StateAccessor,
        method: &str,
        params: &[u8],
        ctx: &mut TxContext<'_>,
    ) -> Result<(), TransactionError> {
        match method {
            "rotate_key@v1" => {
                // Deserialize the parameters for this specific method.
                let p: RotateKeyParams = codec::from_bytes_canonical(params)?;
                // The signer of the transaction is the account being rotated.
                let account_id = ctx.signer_account_id;

                self.rotate(state, &account_id, &p.proof, ctx.block_height)
                    .map_err(TransactionError::Invalid)
            }
            _ => Err(TransactionError::Unsupported(format!(
                "IdentityHub does not support method '{}'",
                method
            ))),
        }
    }
}

#[async_trait]
impl UpgradableService for IdentityHub {
    async fn prepare_upgrade(&mut self, _new_module_wasm: &[u8]) -> Result<Vec<u8>, UpgradeError> {
        Ok(Vec::new())
    }
    async fn complete_upgrade(&mut self, _snapshot: &[u8]) -> Result<(), UpgradeError> {
        Ok(())
    }
}

impl CredentialsView for IdentityHub {
    fn get_credentials(
        &self,
        state: &dyn StateAccessor,
        account_id: &AccountId,
    ) -> Result<[Option<Credential>; 2], TransactionError> {
        self.load_credentials(state, account_id)
            .map_err(TransactionError::State)
    }

    fn accept_staged_during_grace(&self) -> bool {
        self.config.accept_staged_during_grace
    }
}

#[async_trait]
impl OnEndBlock for IdentityHub {
    async fn on_end_block(
        &self,
        state: &mut dyn StateAccessor,
        ctx: &TxContext,
    ) -> Result<(), StateError> {
        let height = ctx.block_height;
        let idx_key = Self::get_index_key(height);

        if let Some(bytes) = state.get(&idx_key)? {
            let accounts: Vec<AccountId> = codec::from_bytes_canonical(&bytes).unwrap_or_default();
            for account_id in accounts {
                let mut creds = self.load_credentials(state, &account_id)?;
                if let Some(staged) = creds[1].as_ref() {
                    if height >= staged.activation_height {
                        if let Some(staged_taken) = creds[1].take() {
                            let new_active = staged_taken.clone();
                            log::info!(
                                "[IdentityHub] Promoting account 0x{} -> {:?} at H={}",
                                hex::encode(&account_id.as_ref()[..4]),
                                new_active.suite,
                                height
                            );
                            creds[0] = Some(new_active.clone());
                            self.save_credentials(state, &account_id, &creds)?;

                            self.apply_validator_key_update(
                                state,
                                &account_id,
                                new_active.suite,
                                new_active.public_key_hash,
                                height,
                            )?;
                        }
                    }
                }
            }
            state.delete(&idx_key)?;
        }
        Ok(())
    }
}