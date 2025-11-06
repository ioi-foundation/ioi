// Path: crates/services/src/governance/mod.rs
//! Governance module implementations for the DePIN SDK

use async_trait::async_trait;
use ioi_types::app::{
    read_validator_sets, AccountId, Proposal, ProposalStatus, ProposalType, StateEntry,
    TallyResult, VoteOption,
};
use ioi_types::error::{StateError, TransactionError, UpgradeError};
use ioi_types::keys::{
    GOVERNANCE_NEXT_PROPOSAL_ID_KEY, GOVERNANCE_PROPOSAL_KEY_PREFIX, GOVERNANCE_VOTE_KEY_PREFIX,
    VALIDATOR_SET_KEY,
};
use ioi_types::service_configs::{Capabilities, GovernanceParams};
use ioi_api::lifecycle::OnEndBlock;
use ioi_api::services::{BlockchainService, UpgradableService};
use ioi_api::state::StateAccessor;
use ioi_api::transaction::context::TxContext;
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
        state: &mut dyn StateAccessor,
        method: &str,
        params: &[u8],
        ctx: &mut TxContext<'_>,
    ) -> Result<(), TransactionError> {
        // For now, all governance actions are user-signed. A future version
        // could add governance-only or internal methods with ACL checks here.
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
            _ => Err(TransactionError::Unsupported(format!(
                "Governance service does not support method '{}'",
                method
            ))),
        }
    }
}

#[async_trait]
impl UpgradableService for GovernanceModule {
    async fn prepare_upgrade(&mut self, _new_module_wasm: &[u8]) -> Result<Vec<u8>, UpgradeError> {
        // A real implementation would serialize its `params` struct here.
        Ok(Vec::new())
    }
    async fn complete_upgrade(&mut self, _snapshot: &[u8]) -> Result<(), UpgradeError> {
        // A real implementation would deserialize the snapshot to restore its `params`.
        Ok(())
    }
}

#[async_trait]
impl OnEndBlock for GovernanceModule {
    async fn on_end_block(
        &self,
        state: &mut dyn StateAccessor,
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

    fn get_next_proposal_id<S: StateAccessor + ?Sized>(
        &self,
        state: &mut S,
    ) -> Result<u64, String> {
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

    pub fn submit_proposal<S: StateAccessor + ?Sized>(
        &self,
        state: &mut S,
        params: SubmitProposalParams,
        proposer: &AccountId,
        current_height: u64,
    ) -> Result<u64, String> {
        if params.deposit < self.params.min_deposit {
            return Err("Initial deposit is less than min_deposit".to_string());
        }
        // In a real implementation, we would lock the proposer's deposit here.

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
        state: &mut dyn StateAccessor,
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

        // In a real implementation, we would check the voter's voting power (stake).
        let vote_key = Self::vote_key(proposal_id, voter);
        let vote_bytes = ioi_types::codec::to_bytes_canonical(&option)?;
        state
            .insert(&vote_key, &vote_bytes)
            .map_err(|e| e.to_string())?;

        Ok(())
    }

    /// Tallies the votes for a concluded proposal and updates its status.
    pub fn tally_proposal<S: StateAccessor + ?Sized>(
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
            let prefix_len = vote_key_prefix.len();
            let voter_account_id_bytes: [u8; 32] = vote_key
                .get(prefix_len..)
                .ok_or("Invalid voter key length")?
                .try_into()
                .map_err(|_| "Invalid voter AccountId in state key".to_string())?;
            let voter_account_id = AccountId(voter_account_id_bytes);

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
