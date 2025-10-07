// Path: crates/services/src/governance/mod.rs
//! Governance module implementations for the DePIN SDK

use depin_sdk_api::lifecycle::OnEndBlock;
use depin_sdk_api::services::access::Service;
use depin_sdk_api::services::{BlockchainService, ServiceType, UpgradableService};
use depin_sdk_api::state::StateAccessor;
use depin_sdk_api::transaction::context::TxContext;
// --- FIX: Import the types from the `depin-sdk-types` crate ---
use depin_sdk_types::app::{
    read_validator_sets, AccountId, Proposal, ProposalStatus, ProposalType, StateEntry,
    TallyResult, VoteOption,
};
use depin_sdk_types::error::{StateError, UpgradeError};
use depin_sdk_types::keys::{
    GOVERNANCE_NEXT_PROPOSAL_ID_KEY, GOVERNANCE_PROPOSAL_KEY_PREFIX, GOVERNANCE_VOTE_KEY_PREFIX,
    VALIDATOR_SET_KEY,
};
use depin_sdk_types::service_configs::GovernanceParams;
use std::collections::BTreeMap;

// --- Enums and Structs are now defined in `depin-sdk-types` ---
// --- and have been removed from this file. ---

/// Encapsulates all data needed to submit a new proposal.
pub struct SubmitProposalMsg<'a> {
    pub proposal_type: ProposalType,
    pub title: &'a str,
    pub description: &'a str,
    pub proposer: &'a [u8],
    pub deposit: u64,
}

// --- Governance Module ---

#[derive(Default, Debug)]
pub struct GovernanceModule {
    params: GovernanceParams,
}

impl BlockchainService for GovernanceModule {
    fn service_type(&self) -> ServiceType {
        ServiceType::Governance
    }
}

impl Service for GovernanceModule {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn as_on_end_block(&self) -> Option<&dyn OnEndBlock> {
        Some(self)
    }
}

impl UpgradableService for GovernanceModule {
    fn prepare_upgrade(&mut self, _new_module_wasm: &[u8]) -> Result<Vec<u8>, UpgradeError> {
        // This simple version is stateless. A real implementation would serialize its params.
        Ok(Vec::new())
    }
    fn complete_upgrade(&mut self, _snapshot: &[u8]) -> Result<(), UpgradeError> {
        Ok(())
    }
}

impl OnEndBlock for GovernanceModule {
    fn on_end_block(
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
                    depin_sdk_types::codec::from_bytes_canonical::<StateEntry>(&value_bytes)
                {
                    if let Ok(proposal) =
                        depin_sdk_types::codec::from_bytes_canonical::<Proposal>(&entry.value)
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
        msg: SubmitProposalMsg,
        current_height: u64,
    ) -> Result<u64, String> {
        if msg.deposit < self.params.min_deposit {
            return Err("Initial deposit is less than min_deposit".to_string());
        }
        // In a real implementation, we would lock the proposer's deposit here.

        let id = self.get_next_proposal_id(state)?;
        let deposit_end_height = current_height + self.params.max_deposit_period_blocks;
        let proposal = Proposal {
            id,
            title: msg.title.to_string(),
            description: msg.description.to_string(),
            proposal_type: msg.proposal_type,
            status: ProposalStatus::DepositPeriod,
            submitter: msg.proposer.to_vec(),
            submit_height: current_height,
            deposit_end_height,
            voting_start_height: 0, // Set when voting period starts
            voting_end_height: 0,   // Set when voting period starts
            total_deposit: msg.deposit,
            final_tally: None,
        };

        let key = Self::proposal_key(id);
        let entry = StateEntry {
            value: depin_sdk_types::codec::to_bytes_canonical(&proposal)?,
            block_height: current_height,
        };
        let value_bytes = depin_sdk_types::codec::to_bytes_canonical(&entry)?;
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
        let entry: StateEntry = depin_sdk_types::codec::from_bytes_canonical(&entry_bytes)
            .map_err(|e| format!("StateEntry decode failed: {}", e))?;
        let proposal: Proposal = depin_sdk_types::codec::from_bytes_canonical(&entry.value)
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
        let vote_bytes = depin_sdk_types::codec::to_bytes_canonical(&option)?;
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
        stakes: &BTreeMap<AccountId, u64>, // The map of staker AccountId -> stake amount
        _current_height: u64,
    ) -> Result<(), String> {
        let key = Self::proposal_key(proposal_id);
        let entry_bytes = state
            .get(&key)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| "Tally failed: Proposal not found".to_string())?;
        let entry: StateEntry = depin_sdk_types::codec::from_bytes_canonical(&entry_bytes)
            .map_err(|e| format!("StateEntry decode failed: {}", e))?;
        let mut proposal: Proposal = depin_sdk_types::codec::from_bytes_canonical(&entry.value)
            .map_err(|e| format!("Proposal decode failed: {}", e))?;

        // 1. Calculate total voting power from the stakes map.
        let total_voting_power: u64 = stakes.values().sum();
        log::debug!(
            "[Tally] Total voting power from stakes: {}",
            total_voting_power
        );

        if total_voting_power == 0 {
            // No one has any stake, so the proposal is rejected by default.
            proposal.status = ProposalStatus::Rejected;
            let updated_entry = StateEntry {
                value: depin_sdk_types::codec::to_bytes_canonical(&proposal)?,
                block_height: entry.block_height,
            };
            let updated_value_bytes = depin_sdk_types::codec::to_bytes_canonical(&updated_entry)?;
            state
                .insert(&key, &updated_value_bytes)
                .map_err(|e| e.to_string())?;
            log::warn!(
                "[Tally] Proposal {} rejected: total voting power is zero.",
                proposal_id
            );
            return Ok(());
        }

        // 2. Scan for all votes using the new prefix_scan method.
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
        let mut total_voted_power = 0; // Total power of accounts that voted.

        for item_result in votes_iter {
            let (vote_key, vote_bytes) = item_result.map_err(|e| e.to_string())?;
            // 3. Deserialize the vote option.
            let option: VoteOption = depin_sdk_types::codec::from_bytes_canonical(&vote_bytes)
                .map_err(|_| "Failed to deserialize vote".to_string())?;

            // 4. Extract the voter's AccountId from the state key.
            // The key is formatted as: "gov::vote::<proposal_id>::<voter_account_id>"
            let prefix_len = vote_key_prefix.len();
            let voter_account_id_bytes: [u8; 32] = vote_key
                .get(prefix_len..)
                .ok_or("Invalid voter key length")?
                .try_into()
                .map_err(|_| "Invalid voter AccountId in state key".to_string())?;
            let voter_account_id = AccountId(voter_account_id_bytes);

            // 5. Get the voter's power from the stakes map. Default to 0 if not a staker.
            let voting_power = stakes.get(&voter_account_id).copied().unwrap_or(0);
            log::debug!(
                "[Tally] Voter 0x{} has power {} and voted {:?}",
                hex::encode(voter_account_id.as_ref()),
                voting_power,
                option
            );

            // 6. Tally the vote with its corresponding power.
            match option {
                VoteOption::Yes => tally.yes += voting_power,
                VoteOption::No => tally.no += voting_power,
                VoteOption::NoWithVeto => tally.no_with_veto += voting_power,
                VoteOption::Abstain => tally.abstain += voting_power,
            }
            // Abstain votes count for quorum but not for pass/veto thresholds.
            total_voted_power += voting_power;
        }

        proposal.final_tally = Some(tally.clone());

        // 2. Apply Governance Rules
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
            value: depin_sdk_types::codec::to_bytes_canonical(&proposal)?,
            block_height: entry.block_height,
        };
        let updated_value_bytes = depin_sdk_types::codec::to_bytes_canonical(&updated_entry)?;
        state
            .insert(&key, &updated_value_bytes)
            .map_err(|e| e.to_string())?;

        Ok(())
    }

    // NOTE: This is a simplified `get_status`. A real implementation would involve tallying.
    pub fn get_proposal_status<S: StateAccessor + ?Sized>(
        &self,
        state: &S,
        proposal_id: u64,
    ) -> Result<ProposalStatus, String> {
        let key = Self::proposal_key(proposal_id);
        let entry_bytes = state
            .get(&key)
            .map_err(|e| e.to_string())?
            .ok_or("Proposal not found")?;
        let entry: StateEntry = depin_sdk_types::codec::from_bytes_canonical(&entry_bytes)
            .map_err(|e| format!("StateEntry decode failed: {}", e))?;
        let proposal: Proposal = depin_sdk_types::codec::from_bytes_canonical(&entry.value)
            .map_err(|e| format!("Proposal decode failed: {}", e))?;
        Ok(proposal.status)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use depin_sdk_api::state::{PrunePlan, StateCommitment, StateManager};
    use depin_sdk_types::app::{Membership, RootHash};
    use depin_sdk_types::error::StateError;
    use std::any::Any;
    use std::collections::BTreeMap;
    use std::collections::HashMap;
    use std::sync::Arc;

    // A simple mock StateManager for testing governance logic.
    #[derive(Debug, Default)]
    struct MockStateManager {
        data: HashMap<Vec<u8>, Vec<u8>>,
    }

    impl StateCommitment for MockStateManager {
        type Commitment = Vec<u8>;
        type Proof = Vec<u8>;

        fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StateError> {
            Ok(self.data.get(key).cloned())
        }
        fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<(), StateError> {
            self.data.insert(key.to_vec(), value.to_vec());
            Ok(())
        }
        fn delete(&mut self, key: &[u8]) -> Result<(), StateError> {
            self.data.remove(key);
            Ok(())
        }
        fn root_commitment(&self) -> Self::Commitment {
            vec![]
        }
        fn create_proof(&self, _key: &[u8]) -> Option<Self::Proof> {
            None
        }
        fn verify_proof(
            &self,
            _commitment: &Self::Commitment,
            _proof: &Self::Proof,
            _key: &[u8],
            _value: &[u8],
        ) -> Result<(), StateError> {
            Ok(())
        }
        fn as_any(&self) -> &dyn Any {
            self
        }
        fn as_any_mut(&mut self) -> &mut dyn Any {
            self
        }
        fn prefix_scan(
            &self,
            prefix: &[u8],
        ) -> Result<depin_sdk_api::state::StateScanIter<'_>, StateError> {
            let mut results: Vec<_> = self
                .data
                .iter()
                .filter(|(key, _)| key.starts_with(prefix))
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect();
            results.sort_unstable_by(|a, b| a.0.cmp(&b.0));
            let iter = results
                .into_iter()
                .map(|(k, v)| Ok((Arc::from(k), Arc::from(v))));
            Ok(Box::new(iter))
        }
    }

    impl StateManager for MockStateManager {
        fn commitment_from_anchor(&self, anchor: &[u8; 32]) -> Option<Self::Commitment> {
            Some(anchor.to_vec())
        }
        fn batch_set(&mut self, updates: &[(Vec<u8>, Vec<u8>)]) -> Result<(), StateError> {
            for (key, value) in updates {
                StateCommitment::insert(self, key, value)?;
            }
            Ok(())
        }
        fn batch_get(&self, keys: &[Vec<u8>]) -> Result<Vec<Option<Vec<u8>>>, StateError> {
            keys.iter()
                .map(|key| StateCommitment::get(self, key))
                .collect()
        }
        fn get_with_proof_at(
            &self,
            _root: &Self::Commitment,
            _key: &[u8],
        ) -> Result<(Membership, Self::Proof), StateError> {
            unimplemented!("MockStateManager does not support proof generation")
        }
        fn commitment_from_bytes(&self, bytes: &[u8]) -> Result<Self::Commitment, StateError> {
            Ok(bytes.to_vec())
        }
        fn commitment_to_bytes(&self, c: &Self::Commitment) -> Vec<u8> {
            c.clone()
        }
        fn prune(&mut self, _plan: &PrunePlan) -> Result<(), StateError> {
            Ok(())
        }
        fn prune_batch(&mut self, _plan: &PrunePlan, _limit: usize) -> Result<usize, StateError> {
            Ok(0)
        }
        fn batch_apply(
            &mut self,
            inserts: &[(Vec<u8>, Vec<u8>)],
            deletes: &[Vec<u8>],
        ) -> Result<(), StateError> {
            for key in deletes {
                StateCommitment::delete(self, key)?;
            }
            for (key, value) in inserts {
                StateCommitment::insert(self, key, value)?;
            }
            Ok(())
        }
        fn commit_version(&mut self, _: u64) -> Result<RootHash, StateError> {
            Ok([0u8; 32])
        }
    }

    fn setup_proposal(state: &mut MockStateManager, status: ProposalStatus) -> u64 {
        let proposal_id = 1;
        let proposal = Proposal {
            id: proposal_id,
            title: "Test Proposal".to_string(),
            description: "A proposal for testing".to_string(),
            proposal_type: ProposalType::Text,
            status,
            submitter: vec![1],
            submit_height: 100,
            deposit_end_height: 200,
            voting_start_height: 201,
            voting_end_height: 300,
            total_deposit: 10000,
            final_tally: None,
        };
        let key = GovernanceModule::proposal_key(proposal_id);
        let entry = StateEntry {
            value: depin_sdk_types::codec::to_bytes_canonical(&proposal).unwrap(),
            block_height: 100,
        };
        let value_bytes = depin_sdk_types::codec::to_bytes_canonical(&entry).unwrap();
        StateCommitment::insert(state, &key, &value_bytes).unwrap();
        proposal_id
    }

    // Helper to get proposal status from state
    fn get_status(state: &MockStateManager, proposal_id: u64) -> ProposalStatus {
        let key = GovernanceModule::proposal_key(proposal_id);
        let bytes = StateCommitment::get(state, &key).unwrap().unwrap();
        let entry: StateEntry = depin_sdk_types::codec::from_bytes_canonical(&bytes).unwrap();
        let proposal: Proposal =
            depin_sdk_types::codec::from_bytes_canonical(&entry.value).unwrap();
        proposal.status
    }

    #[test]
    fn test_proposal_passes_when_conditions_met() {
        let mut state = MockStateManager::default();
        let proposal_id = setup_proposal(&mut state, ProposalStatus::VotingPeriod);
        let module = GovernanceModule::default(); // Quorum: 33%, Threshold: 50%, Veto: 33%

        let voter1_id = AccountId([1; 32]);
        let voter2_id = AccountId([2; 32]);

        // Setup stakes: Voter1 has 600, Voter2 has 400. Total power = 1000.
        let mut stakes = BTreeMap::new();
        stakes.insert(voter1_id, 600);
        stakes.insert(voter2_id, 400);

        // Setup votes: Voter1 votes YES. Total voted power = 600.
        StateCommitment::insert(
            &mut state,
            &GovernanceModule::vote_key(proposal_id, &voter1_id),
            &depin_sdk_types::codec::to_bytes_canonical(&VoteOption::Yes).unwrap(),
        )
        .unwrap();

        // Tally:
        // - total_voting_power = 1000. Quorum = 330. Voted power = 600. -> Quorum met.
        // - total_power_excluding_abstain = 600. Veto threshold = 198. Veto votes = 0. -> No veto.
        // - Pass threshold = 300. Yes votes = 600. -> Passed.
        module
            .tally_proposal(&mut state, proposal_id, &stakes, 301)
            .unwrap();
        assert_eq!(get_status(&state, proposal_id), ProposalStatus::Passed);
    }

    #[test]
    fn test_proposal_fails_quorum() {
        let mut state = MockStateManager::default();
        let proposal_id = setup_proposal(&mut state, ProposalStatus::VotingPeriod);
        let module = GovernanceModule::default();

        let voter1_id = AccountId([1; 32]);
        let voter2_id = AccountId([2; 32]);

        let mut stakes = BTreeMap::new();
        stakes.insert(voter1_id, 1000); // Total power = 1300
        stakes.insert(voter2_id, 300);

        // Only one voter with 300 power votes.
        StateCommitment::insert(
            &mut state,
            &GovernanceModule::vote_key(proposal_id, &voter2_id),
            &depin_sdk_types::codec::to_bytes_canonical(&VoteOption::Yes).unwrap(),
        )
        .unwrap();

        // Tally:
        // - total_voting_power = 1300. Quorum = 429. Voted power = 300. -> Quorum FAILED.
        module
            .tally_proposal(&mut state, proposal_id, &stakes, 301)
            .unwrap();
        assert_eq!(get_status(&state, proposal_id), ProposalStatus::Rejected);
    }

    #[test]
    fn test_proposal_fails_threshold() {
        let mut state = MockStateManager::default();
        let proposal_id = setup_proposal(&mut state, ProposalStatus::VotingPeriod);
        let module = GovernanceModule::default();

        let voter1_id = AccountId([1; 32]);
        let voter2_id = AccountId([2; 32]);

        let mut stakes = BTreeMap::new();
        stakes.insert(voter1_id, 400);
        stakes.insert(voter2_id, 600); // Total power = 1000

        // Both vote, so quorum is met. Voter1 votes YES, Voter2 votes NO.
        StateCommitment::insert(
            &mut state,
            &GovernanceModule::vote_key(proposal_id, &voter1_id),
            &depin_sdk_types::codec::to_bytes_canonical(&VoteOption::Yes).unwrap(),
        )
        .unwrap();
        StateCommitment::insert(
            &mut state,
            &GovernanceModule::vote_key(proposal_id, &voter2_id),
            &depin_sdk_types::codec::to_bytes_canonical(&VoteOption::No).unwrap(),
        )
        .unwrap();

        // Tally:
        // - total_voting_power = 1000. Quorum = 330. Voted power = 1000. -> Quorum met.
        // - total_power_excluding_abstain = 1000. Pass threshold = 500. Yes votes = 400. -> Threshold FAILED.
        module
            .tally_proposal(&mut state, proposal_id, &stakes, 301)
            .unwrap();
        assert_eq!(get_status(&state, proposal_id), ProposalStatus::Rejected);
    }

    #[test]
    fn test_proposal_is_vetoed() {
        let mut state = MockStateManager::default();
        let proposal_id = setup_proposal(&mut state, ProposalStatus::VotingPeriod);
        let module = GovernanceModule::default();

        let voter1_id = AccountId([1; 32]);
        let voter2_id = AccountId([2; 32]);

        let mut stakes = BTreeMap::new();
        stakes.insert(voter1_id, 600); // Majority Yes
        stakes.insert(voter2_id, 400); // Veto power

        StateCommitment::insert(
            &mut state,
            &GovernanceModule::vote_key(proposal_id, &voter1_id),
            &depin_sdk_types::codec::to_bytes_canonical(&VoteOption::Yes).unwrap(),
        )
        .unwrap();
        StateCommitment::insert(
            &mut state,
            &GovernanceModule::vote_key(proposal_id, &voter2_id),
            &depin_sdk_types::codec::to_bytes_canonical(&VoteOption::NoWithVeto).unwrap(),
        )
        .unwrap();

        // Tally:
        // - total_voting_power = 1000. Quorum = 330. Voted power = 1000. -> Quorum met.
        // - total_power_excluding_abstain = 1000. Veto threshold = 330. Veto votes = 400. -> VETOED.
        module
            .tally_proposal(&mut state, proposal_id, &stakes, 301)
            .unwrap();
        assert_eq!(get_status(&state, proposal_id), ProposalStatus::Rejected);
    }
}
