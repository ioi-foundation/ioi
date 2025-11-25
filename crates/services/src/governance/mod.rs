// Path: crates/services/src/governance/mod.rs
//! Governance module implementations for the IOI SDK

use async_trait::async_trait;
use ioi_api::identity::CredentialsView;
use ioi_api::lifecycle::OnEndBlock;
use ioi_api::services::{BlockchainService, UpgradableService};
use ioi_api::state::StateAccess;
use ioi_api::transaction::context::TxContext;
use ioi_types::app::{
    read_validator_sets, write_validator_sets, AccountId, ActiveKeyRecord, Proposal,
    ProposalStatus, ProposalType, StateEntry, TallyResult, ValidatorV1, VoteOption,
};
use ioi_types::codec;
use ioi_types::error::{StateError, TransactionError, UpgradeError};
use ioi_types::keys::{
    ACCOUNT_ID_TO_PUBKEY_PREFIX, GOVERNANCE_NEXT_PROPOSAL_ID_KEY, GOVERNANCE_PROPOSAL_KEY_PREFIX,
    GOVERNANCE_VOTE_KEY_PREFIX, UPGRADE_ARTIFACT_PREFIX, UPGRADE_MANIFEST_PREFIX,
    UPGRADE_PENDING_PREFIX, VALIDATOR_SET_KEY,
};
use ioi_types::service_configs::{Capabilities, GovernanceParams};
use libp2p::identity::PublicKey as Libp2pPublicKey;
use parity_scale_codec::{Decode, Encode};
use std::any::Any;
use std::collections::BTreeMap;

// --- Service Method Parameter Structs (The Service's Public ABI) ---

/// The parameters for the `submit_proposal@v1` method.
#[derive(Encode, Decode)]
pub struct SubmitProposalParams {
    pub proposal_type: ProposalType,
    pub title: String,
    pub description: String,
    pub deposit: u64,
}

/// The parameters for the `vote@v1` method.
#[derive(Encode, Decode)]
pub struct VoteParams {
    pub proposal_id: u64,
    pub option: VoteOption,
}

/// The parameters for the `stake@v1` method.
#[derive(Encode, Decode)]
pub struct StakeParams {
    pub public_key: Vec<u8>,
    pub amount: u64,
}

/// The parameters for the `unstake@v1` method.
#[derive(Encode, Decode)]
pub struct UnstakeParams {
    pub amount: u64,
}

// --- REMOVED: ReportMisbehaviorParams is now in `ioi-types` ---

/// The parameters for the `store_module@v1` method.
#[derive(Encode, Decode)]
pub struct StoreModuleParams {
    pub manifest: String,
    pub artifact: Vec<u8>,
}

/// The parameters for the `swap_module@v1` method.
#[derive(Encode, Decode)]
pub struct SwapModuleParams {
    pub service_id: String,
    pub manifest_hash: [u8; 32],
    pub artifact_hash: [u8; 32],
    pub activation_height: u64,
}

// --- Governance Module ---

#[derive(Default, Debug)]
pub struct GovernanceModule {
    params: GovernanceParams,
}

#[async_trait]
impl BlockchainService for GovernanceModule {
    fn id(&self) -> &str {
        "governance"
    }

    fn abi_version(&self) -> u32 {
        1
    }

    fn state_schema(&self) -> &str {
        "v1"
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities::ON_END_BLOCK
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_on_end_block(&self) -> Option<&dyn OnEndBlock> {
        Some(self)
    }

    async fn handle_service_call(
        &self,
        state: &mut dyn StateAccess,
        method: &str,
        params: &[u8],
        ctx: &mut TxContext<'_>,
    ) -> Result<(), TransactionError> {
        let signer_account_id = ctx.signer_account_id;

        match method {
            "submit_proposal@v1" => {
                let p: SubmitProposalParams = ioi_types::codec::from_bytes_canonical(params)?;
                self.submit_proposal(state, p, &signer_account_id, ctx.block_height)
                    .map_err(TransactionError::Invalid)?;
                Ok(())
            }
            "vote@v1" => {
                let p: VoteParams = ioi_types::codec::from_bytes_canonical(params)?;
                self.vote(
                    state,
                    p.proposal_id,
                    &signer_account_id,
                    p.option,
                    ctx.block_height,
                )
                .map_err(TransactionError::Invalid)
            }
            "stake@v1" => {
                let p: StakeParams = ioi_types::codec::from_bytes_canonical(params)?;
                self.stake(
                    state,
                    &signer_account_id,
                    p.public_key,
                    p.amount,
                    ctx.block_height,
                    ctx,
                )
                .map_err(TransactionError::Invalid)
            }
            "unstake@v1" => {
                let p: UnstakeParams = ioi_types::codec::from_bytes_canonical(params)?;
                self.unstake(state, &signer_account_id, p.amount, ctx.block_height)
                    .map_err(TransactionError::Invalid)
            }
            "store_module@v1" => {
                let p: StoreModuleParams = ioi_types::codec::from_bytes_canonical(params)?;
                self.store_module(state, p.manifest, p.artifact)
                    .map_err(TransactionError::Invalid)
            }
            "swap_module@v1" => {
                let p: SwapModuleParams = ioi_types::codec::from_bytes_canonical(params)?;
                self.swap_module(
                    state,
                    p.service_id,
                    p.manifest_hash,
                    p.artifact_hash,
                    p.activation_height,
                )
                .map_err(TransactionError::Invalid)
            }
            "report_misbehavior@v1" => {
                // --- CHANGED: Governance no longer handles penalties. This is now a kernel function. ---
                Err(TransactionError::Unsupported(
                    "Moved to 'penalties' service. Use service_id='penalties'.".into(),
                ))
            }
            _ => Err(TransactionError::Unsupported(format!(
                "Governance service does not support method '{}'",
                method
            ))),
        }
    }
}

#[async_trait]
impl UpgradableService for GovernanceModule {
    async fn prepare_upgrade(&self, _new_module_wasm: &[u8]) -> Result<Vec<u8>, UpgradeError> {
        Ok(Vec::new())
    }
    async fn complete_upgrade(&self, _snapshot: &[u8]) -> Result<(), UpgradeError> {
        Ok(())
    }
}

#[async_trait]
impl OnEndBlock for GovernanceModule {
    async fn on_end_block(
        &self,
        state: &mut dyn StateAccess,
        ctx: &TxContext,
    ) -> Result<(), StateError> {
        let proposals_to_tally: Vec<u64> = {
            let proposals_iter = state.prefix_scan(GOVERNANCE_PROPOSAL_KEY_PREFIX)?;
            let mut ids = Vec::new();
            for item_result in proposals_iter {
                let (_key, value_bytes) = item_result?;
                if let Ok(entry) =
                    ioi_types::codec::from_bytes_canonical::<StateEntry>(&value_bytes)
                {
                    if let Ok(proposal) =
                        ioi_types::codec::from_bytes_canonical::<Proposal>(&entry.value)
                    {
                        if proposal.status == ProposalStatus::VotingPeriod
                            && ctx.block_height >= proposal.voting_end_height
                        {
                            ids.push(proposal.id);
                        }
                    }
                }
            }
            ids
        };

        if !proposals_to_tally.is_empty() {
            let stakes: BTreeMap<AccountId, u64> = match state.get(VALIDATOR_SET_KEY)? {
                Some(bytes) => {
                    let sets = read_validator_sets(&bytes)?;
                    sets.current
                        .validators
                        .into_iter()
                        .map(|v| (v.account_id, v.weight as u64))
                        .collect()
                }
                _ => BTreeMap::new(),
            };

            for proposal_id in proposals_to_tally {
                log::info!("[Governance OnEndBlock] Tallying proposal {}", proposal_id);
                self.tally_proposal(state, proposal_id, &stakes, ctx.block_height)
                    .map_err(StateError::Apply)?;
            }
        }
        Ok(())
    }
}

impl GovernanceModule {
    pub fn new(params: GovernanceParams) -> Self {
        Self { params }
    }

    // --- Method Implementations ---

    pub fn store_module(
        &self,
        state: &mut dyn StateAccess,
        manifest: String,
        artifact: Vec<u8>,
    ) -> Result<(), String> {
        let manifest_hash =
            ioi_crypto::algorithms::hash::sha256(manifest.as_bytes()).map_err(|e| e.to_string())?;
        let artifact_hash =
            ioi_crypto::algorithms::hash::sha256(&artifact).map_err(|e| e.to_string())?;
        let manifest_key = [UPGRADE_MANIFEST_PREFIX, &manifest_hash].concat();
        let artifact_key = [UPGRADE_ARTIFACT_PREFIX, &artifact_hash].concat();
        if state
            .get(&manifest_key)
            .map_err(|e| e.to_string())?
            .is_none()
        {
            state
                .insert(&manifest_key, manifest.as_bytes())
                .map_err(|e| e.to_string())?;
        }
        if state
            .get(&artifact_key)
            .map_err(|e| e.to_string())?
            .is_none()
        {
            state
                .insert(&artifact_key, &artifact)
                .map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    pub fn swap_module(
        &self,
        state: &mut dyn StateAccess,
        service_id: String,
        manifest_hash: [u8; 32],
        artifact_hash: [u8; 32],
        activation_height: u64,
    ) -> Result<(), String> {
        let manifest_key = [UPGRADE_MANIFEST_PREFIX, &manifest_hash].concat();
        if state
            .get(&manifest_key)
            .map_err(|e| e.to_string())?
            .is_none()
        {
            return Err(format!(
                "Manifest not found for hash {}",
                hex::encode(manifest_hash)
            ));
        }
        let artifact_key = [UPGRADE_ARTIFACT_PREFIX, &artifact_hash].concat();
        if state
            .get(&artifact_key)
            .map_err(|e| e.to_string())?
            .is_none()
        {
            return Err(format!(
                "Artifact not found for hash {}",
                hex::encode(artifact_hash)
            ));
        }
        let key = [UPGRADE_PENDING_PREFIX, &activation_height.to_le_bytes()].concat();
        let mut pending: Vec<(String, [u8; 32], [u8; 32])> = state
            .get(&key)
            .map_err(|e| e.to_string())?
            .and_then(|b| codec::from_bytes_canonical(&b).ok())
            .unwrap_or_default();
        pending.push((service_id, manifest_hash, artifact_hash));
        state
            .insert(&key, &codec::to_bytes_canonical(&pending)?)
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn stake(
        &self,
        state: &mut dyn StateAccess,
        staker_account_id: &AccountId,
        public_key: Vec<u8>,
        amount: u64,
        block_height: u64,
        ctx: &TxContext<'_>,
    ) -> Result<(), String> {
        let target_activation = block_height + 2;

        let maybe_blob_bytes = state.get(VALIDATOR_SET_KEY).map_err(|e| e.to_string())?;
        let mut sets = maybe_blob_bytes
            .as_ref()
            .map(|b| read_validator_sets(b))
            .transpose()
            .map_err(|e| e.to_string())?
            .unwrap_or_default();

        if sets.next.is_none() {
            let mut new_next = sets.current.clone();
            new_next.effective_from_height = target_activation;
            sets.next = Some(new_next);
        }
        let next_vs = sets.next.as_mut().unwrap();

        if let Some(validator) = next_vs
            .validators
            .iter_mut()
            .find(|v| v.account_id == *staker_account_id)
        {
            validator.weight = validator.weight.saturating_add(amount as u128);
        } else {
            let creds_view = ctx
                .services
                .get::<crate::identity::IdentityHub>()
                .ok_or_else(|| "IdentityHub service not found for staking".to_string())?;
            let creds = creds_view
                .get_credentials(state, staker_account_id)
                .map_err(|e| e.to_string())?;
            let active_cred = creds[0]
                .as_ref()
                .ok_or_else(|| "Staker has no active key".to_string())?;

            next_vs.validators.push(ValidatorV1 {
                account_id: *staker_account_id,
                weight: amount as u128,
                consensus_key: ActiveKeyRecord {
                    suite: active_cred.suite,
                    public_key_hash: active_cred.public_key_hash,
                    since_height: active_cred.activation_height,
                },
            });

            let pubkey_map_key = [ACCOUNT_ID_TO_PUBKEY_PREFIX, staker_account_id.as_ref()].concat();
            if state
                .get(&pubkey_map_key)
                .map_err(|e| e.to_string())?
                .is_none()
            {
                let pk_to_store = match active_cred.suite {
                    ioi_types::app::SignatureSuite::Ed25519 => {
                        if Libp2pPublicKey::try_decode_protobuf(&public_key).is_ok() {
                            public_key
                        } else {
                            let ed =
                                libp2p::identity::ed25519::PublicKey::try_from_bytes(&public_key)
                                    .map_err(|_| "Malformed Ed25519 key".to_string())?;
                            libp2p::identity::PublicKey::from(ed).encode_protobuf()
                        }
                    }
                    ioi_types::app::SignatureSuite::Dilithium2 => public_key,
                };
                state
                    .insert(&pubkey_map_key, &pk_to_store)
                    .map_err(|e| e.to_string())?;
            }
        }

        // No manual sort needed; write_validator_sets enforces sorting.
        next_vs.total_weight = next_vs.validators.iter().map(|v| v.weight).sum();
        state
            .insert(
                VALIDATOR_SET_KEY,
                &write_validator_sets(&sets).map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn unstake(
        &self,
        state: &mut dyn StateAccess,
        staker_account_id: &AccountId,
        amount: u64,
        block_height: u64,
    ) -> Result<(), String> {
        let target_activation = block_height + 2;
        let maybe_blob_bytes = state.get(VALIDATOR_SET_KEY).map_err(|e| e.to_string())?;
        let blob_bytes = maybe_blob_bytes
            .ok_or_else(|| "Validator set does not exist to unstake from".to_string())?;
        let mut sets = read_validator_sets(&blob_bytes).map_err(|e| e.to_string())?;

        if sets.next.is_none() {
            let mut new_next = sets.current.clone();
            new_next.effective_from_height = target_activation;
            sets.next = Some(new_next);
        }
        let next_vs = sets.next.as_mut().unwrap();

        let mut validator_found = false;
        next_vs.validators.retain_mut(|v| {
            if v.account_id == *staker_account_id {
                validator_found = true;
                v.weight = v.weight.saturating_sub(amount as u128);
                v.weight > 0
            } else {
                true
            }
        });
        if !validator_found {
            return Err("Staker not in validator set".to_string());
        }

        // No manual sort needed; write_validator_sets enforces sorting.
        next_vs.total_weight = next_vs.validators.iter().map(|v| v.weight).sum();
        state
            .insert(
                VALIDATOR_SET_KEY,
                &write_validator_sets(&sets).map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    fn get_next_proposal_id<S: StateAccess + ?Sized>(&self, state: &mut S) -> Result<u64, String> {
        let id_bytes = state
            .get(GOVERNANCE_NEXT_PROPOSAL_ID_KEY)
            .map_err(|e| e.to_string())?
            .unwrap_or_else(|| 0u64.to_le_bytes().to_vec());
        let id = u64::from_le_bytes(
            id_bytes
                .try_into()
                .map_err(|_| "Invalid proposal ID bytes")?,
        );
        state
            .insert(GOVERNANCE_NEXT_PROPOSAL_ID_KEY, &(id + 1).to_le_bytes())
            .map_err(|e| e.to_string())?;
        Ok(id)
    }

    pub fn proposal_key(id: u64) -> Vec<u8> {
        [GOVERNANCE_PROPOSAL_KEY_PREFIX, &id.to_le_bytes()].concat()
    }

    pub fn vote_key(proposal_id: u64, voter: &AccountId) -> Vec<u8> {
        [
            GOVERNANCE_VOTE_KEY_PREFIX,
            &proposal_id.to_le_bytes(),
            b"::",
            voter.as_ref(),
        ]
        .concat()
    }

    pub fn submit_proposal<S: StateAccess + ?Sized>(
        &self,
        state: &mut S,
        params: SubmitProposalParams,
        proposer: &AccountId,
        current_height: u64,
    ) -> Result<u64, String> {
        if params.deposit < self.params.min_deposit {
            return Err("Initial deposit is less than min_deposit".to_string());
        }

        let id = self.get_next_proposal_id(state)?;
        let deposit_end_height = current_height + self.params.max_deposit_period_blocks;
        let proposal = Proposal {
            id,
            title: params.title,
            description: params.description,
            proposal_type: params.proposal_type,
            status: ProposalStatus::DepositPeriod,
            submitter: proposer.as_ref().to_vec(),
            submit_height: current_height,
            deposit_end_height,
            voting_start_height: 0,
            voting_end_height: 0,
            total_deposit: params.deposit,
            final_tally: None,
        };

        let key = Self::proposal_key(id);
        let entry = StateEntry {
            value: ioi_types::codec::to_bytes_canonical(&proposal)?,
            block_height: current_height,
        };
        let value_bytes = ioi_types::codec::to_bytes_canonical(&entry)?;
        state
            .insert(&key, &value_bytes)
            .map_err(|e| e.to_string())?;

        Ok(id)
    }

    pub fn vote(
        &self,
        state: &mut dyn StateAccess,
        proposal_id: u64,
        voter: &AccountId,
        option: VoteOption,
        current_height: u64,
    ) -> Result<(), String> {
        let key = Self::proposal_key(proposal_id);
        let entry_bytes = state
            .get(&key)
            .map_err(|e| e.to_string())?
            .ok_or("Proposal does not exist")?;
        let entry: StateEntry = ioi_types::codec::from_bytes_canonical(&entry_bytes)
            .map_err(|e| format!("StateEntry decode failed: {}", e))?;
        let proposal: Proposal = ioi_types::codec::from_bytes_canonical(&entry.value)
            .map_err(|e| format!("Proposal decode failed: {}", e))?;

        if proposal.status != ProposalStatus::VotingPeriod {
            return Err("Proposal is not in voting period".to_string());
        }
        if current_height < proposal.voting_start_height {
            return Err("Voting period has not started yet".to_string());
        }
        if current_height > proposal.voting_end_height {
            return Err("Voting period has ended".to_string());
        }

        let vote_key = Self::vote_key(proposal_id, voter);
        let vote_bytes = ioi_types::codec::to_bytes_canonical(&option)?;
        state
            .insert(&vote_key, &vote_bytes)
            .map_err(|e| e.to_string())?;

        Ok(())
    }

    pub fn tally_proposal<S: StateAccess + ?Sized>(
        &self,
        state: &mut S,
        proposal_id: u64,
        stakes: &BTreeMap<AccountId, u64>,
        _current_height: u64,
    ) -> Result<(), String> {
        let key = Self::proposal_key(proposal_id);
        let entry_bytes = state
            .get(&key)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| "Tally failed: Proposal not found".to_string())?;
        let entry: StateEntry = ioi_types::codec::from_bytes_canonical(&entry_bytes)
            .map_err(|e| format!("StateEntry decode failed: {}", e))?;
        let mut proposal: Proposal = ioi_types::codec::from_bytes_canonical(&entry.value)
            .map_err(|e| format!("Proposal decode failed: {}", e))?;

        let total_voting_power: u64 = stakes.values().sum();
        log::debug!(
            "[Tally] Total voting power from stakes: {}",
            total_voting_power
        );

        if total_voting_power == 0 {
            proposal.status = ProposalStatus::Rejected;
            let updated_entry = StateEntry {
                value: ioi_types::codec::to_bytes_canonical(&proposal)?,
                block_height: entry.block_height,
            };
            let updated_value_bytes = ioi_types::codec::to_bytes_canonical(&updated_entry)?;
            state
                .insert(&key, &updated_value_bytes)
                .map_err(|e| e.to_string())?;
            log::warn!(
                "[Tally] Proposal {} rejected: total voting power is zero.",
                proposal_id
            );
            return Ok(());
        }

        let vote_key_prefix = [
            GOVERNANCE_VOTE_KEY_PREFIX,
            &proposal_id.to_le_bytes(),
            b"::",
        ]
        .concat();
        let votes_iter = state
            .prefix_scan(&vote_key_prefix)
            .map_err(|e| e.to_string())?;
        log::debug!("[Tally] Scanning votes for proposal {}", proposal_id);

        let mut tally = TallyResult::default();
        let mut total_voted_power = 0;

        for item_result in votes_iter {
            let (vote_key, vote_bytes) = item_result.map_err(|e| e.to_string())?;
            let option: VoteOption = ioi_types::codec::from_bytes_canonical(&vote_bytes)
                .map_err(|_| "Failed to deserialize vote".to_string())?;

            // --- FIX: Robustly extract AccountId by slicing from the end of the key ---
            let key_len = vote_key.len();
            if key_len < 32 {
                log::warn!("[Tally] Skipping malformed vote key of length {}", key_len);
                continue;
            }
            let voter_account_id_bytes: [u8; 32] = vote_key[(key_len - 32)..]
                .try_into()
                .map_err(|_| "Invalid voter AccountId slice".to_string())?;
            let voter_account_id = AccountId(voter_account_id_bytes);
            // --- END FIX ---

            let voting_power = stakes.get(&voter_account_id).copied().unwrap_or(0);
            log::debug!(
                "[Tally] Voter 0x{} has power {} and voted {:?}",
                hex::encode(voter_account_id.as_ref()),
                voting_power,
                option
            );

            match option {
                VoteOption::Yes => tally.yes += voting_power,
                VoteOption::No => tally.no += voting_power,
                VoteOption::NoWithVeto => tally.no_with_veto += voting_power,
                VoteOption::Abstain => tally.abstain += voting_power,
            }
            total_voted_power += voting_power;
        }

        proposal.final_tally = Some(tally.clone());

        let quorum_threshold = (total_voting_power * self.params.quorum as u64) / 100;
        let total_power_excluding_abstain = tally.yes + tally.no + tally.no_with_veto;

        if total_voted_power < quorum_threshold {
            proposal.status = ProposalStatus::Rejected;
            log::info!(
                "Proposal {} rejected: voted power {} did not meet quorum {}",
                proposal.id,
                total_voted_power,
                quorum_threshold
            );
        } else {
            let veto_threshold =
                (total_power_excluding_abstain * self.params.veto_threshold as u64) / 100;
            if tally.no_with_veto > veto_threshold {
                proposal.status = ProposalStatus::Rejected;
                log::info!("Proposal {} rejected: veto threshold exceeded", proposal.id);
            } else {
                let pass_threshold =
                    (total_power_excluding_abstain * self.params.threshold as u64) / 100;
                if tally.yes > pass_threshold {
                    proposal.status = ProposalStatus::Passed;
                    log::info!("Proposal {} passed!", proposal.id);
                } else {
                    proposal.status = ProposalStatus::Rejected;
                    log::info!(
                        "Proposal {} rejected: 'Yes' votes {} did not meet threshold {}",
                        proposal.id,
                        tally.yes,
                        pass_threshold
                    );
                }
            }
        }

        let updated_entry = StateEntry {
            value: ioi_types::codec::to_bytes_canonical(&proposal)?,
            block_height: entry.block_height,
        };
        let updated_value_bytes = ioi_types::codec::to_bytes_canonical(&updated_entry)?;
        state
            .insert(&key, &updated_value_bytes)
            .map_err(|e| e.to_string())?;

        Ok(())
    }
}
