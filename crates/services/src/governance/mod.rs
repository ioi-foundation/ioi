// Path: crates/services/src/governance/mod.rs
//! Governance module implementations for the DePIN SDK

use depin_sdk_api::state::{StateAccessor, StateManager};
// --- FIX: Import the types from the `depin-sdk-types` crate ---
use depin_sdk_types::app::{
    AccountId, Proposal, ProposalStatus, ProposalType, TallyResult, VoteOption,
};
use depin_sdk_types::keys::{
    GOVERNANCE_NEXT_PROPOSAL_ID_KEY, GOVERNANCE_PROPOSAL_KEY_PREFIX, GOVERNANCE_VOTE_KEY_PREFIX,
};
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
// --- Governance Parameters ---

#[derive(Debug, Clone)]
pub struct GovernanceParams {
    pub min_deposit: u64,
    pub max_deposit_period_blocks: u64, // Changed to blocks
    pub voting_period_blocks: u64,      // Changed to blocks
    pub quorum: u8,
    pub threshold: u8,
    pub veto_threshold: u8,
}

impl Default for GovernanceParams {
    fn default() -> Self {
        Self {
            min_deposit: 10000,
            max_deposit_period_blocks: 20160, // ~14 days at 60s/block
            voting_period_blocks: 20160,      // ~14 days
            quorum: 33,
            threshold: 50,
            veto_threshold: 33,
        }
    }
}

// --- Governance Module ---

#[derive(Default)]
pub struct GovernanceModule {
    params: GovernanceParams,
}

impl GovernanceModule {
    pub fn new(params: GovernanceParams) -> Self {
        Self { params }
    }

    fn get_next_proposal_id<S: StateManager + ?Sized>(&self, state: &mut S) -> Result<u64, String> {
        let id_bytes = state
            .get(GOVERNANCE_NEXT_PROPOSAL_ID_KEY)
            .map_err(|e| e.to_string())?
            .unwrap_or_else(|| 0u64.to_le_bytes().to_vec());
        let id = u64::from_le_bytes(id_bytes.try_into().unwrap_or([0; 8]));
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

    pub fn submit_proposal<S: StateManager + ?Sized>(
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
        let value = serde_json::to_vec(&proposal).unwrap();
        state.insert(&key, &value).map_err(|e| e.to_string())?;

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
        let proposal_bytes = state
            .get(&key)
            .map_err(|e| e.to_string())?
            .ok_or("Proposal does not exist")?;
        let proposal: Proposal = serde_json::from_slice(&proposal_bytes).unwrap();

        if proposal.status != ProposalStatus::VotingPeriod {
            return Err("Proposal is not in voting period".to_string());
        }

        if current_height > proposal.voting_end_height {
            return Err("Voting period has ended".to_string());
        }

        // In a real implementation, we would check the voter's voting power (stake).
        let vote_key = Self::vote_key(proposal_id, voter);
        let vote_bytes = serde_json::to_vec(&option).unwrap();
        state
            .insert(&vote_key, &vote_bytes)
            .map_err(|e| e.to_string())?;

        Ok(())
    }

    /// Tallies the votes for a concluded proposal and updates its status.
    pub fn tally_proposal<S: StateManager + ?Sized>(
        &self,
        state: &mut S,
        proposal_id: u64,
        stakes: &BTreeMap<AccountId, u64>, // The map of staker AccountId -> stake amount
    ) -> Result<(), String> {
        let key = Self::proposal_key(proposal_id);
        let proposal_bytes = state
            .get(&key)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| "Tally failed: Proposal not found".to_string())?;
        let mut proposal: Proposal = serde_json::from_slice(&proposal_bytes).unwrap();

        // 1. Calculate total voting power from the stakes map.
        let total_voting_power: u64 = stakes.values().sum();
        if total_voting_power == 0 {
            // No one has any stake, so the proposal is rejected by default.
            proposal.status = ProposalStatus::Rejected;
            let updated_value = serde_json::to_vec(&proposal).unwrap();
            state
                .insert(&key, &updated_value)
                .map_err(|e| e.to_string())?;
            return Ok(());
        }

        // 2. Scan for all votes using the new prefix_scan method.
        let vote_key_prefix = [
            GOVERNANCE_VOTE_KEY_PREFIX,
            &proposal_id.to_le_bytes(),
            b"::",
        ]
        .concat();
        let votes = state
            .prefix_scan(&vote_key_prefix)
            .map_err(|e| e.to_string())?;

        let mut tally = TallyResult::default();
        let mut total_voted_power = 0; // Total power of accounts that voted.

        for (vote_key, vote_bytes) in votes {
            // 3. Deserialize the vote option.
            let option: VoteOption = serde_json::from_slice(&vote_bytes)
                .map_err(|_| "Failed to deserialize vote".to_string())?;

            // 4. Extract the voter's AccountId from the state key.
            // The key is formatted as: "gov::vote::<proposal_id>::<voter_account_id>"
            let prefix_len = vote_key_prefix.len();
            let voter_account_id_bytes: [u8; 32] = vote_key[prefix_len..]
                .try_into()
                .map_err(|_| "Invalid voter AccountId in state key".to_string())?;
            let voter_account_id = AccountId(voter_account_id_bytes);

            // 5. Get the voter's power from the stakes map. Default to 0 if not a staker.
            let voting_power = stakes.get(&voter_account_id).copied().unwrap_or(0);

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

        let updated_value = serde_json::to_vec(&proposal).unwrap();
        state
            .insert(&key, &updated_value)
            .map_err(|e| e.to_string())?;

        Ok(())
    }

    // NOTE: This is a simplified `get_status`. A real implementation would involve tallying.
    pub fn get_proposal_status<S: StateManager + ?Sized>(
        &self,
        state: &S,
        proposal_id: u64,
    ) -> Result<ProposalStatus, String> {
        let key = Self::proposal_key(proposal_id);
        let proposal_bytes = state
            .get(&key)
            .map_err(|e| e.to_string())?
            .ok_or("Proposal not found")?;
        let proposal: Proposal = serde_json::from_slice(&proposal_bytes).unwrap();
        Ok(proposal.status)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use depin_sdk_api::state::StateCommitment;
    use depin_sdk_types::app::Membership;
    use depin_sdk_types::error::StateError;
    use std::any::Any;
    use std::collections::BTreeMap;
    use std::collections::HashMap;

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
        ) -> bool {
            true
        }
        fn as_any(&self) -> &dyn Any {
            self
        }

        fn prefix_scan(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StateError> {
            let results = self
                .data
                .iter()
                .filter(|(key, _)| key.starts_with(prefix))
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect();
            Ok(results)
        }
    }

    impl StateManager for MockStateManager {
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
        fn prune(&mut self, _min_height_to_keep: u64) -> Result<(), StateError> {
            Ok(())
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
        let value = serde_json::to_vec(&proposal).unwrap();
        StateCommitment::insert(state, &key, &value).unwrap();
        proposal_id
    }

    // Helper to get proposal status from state
    fn get_status(state: &MockStateManager, proposal_id: u64) -> ProposalStatus {
        let key = GovernanceModule::proposal_key(proposal_id);
        let bytes = StateCommitment::get(state, &key).unwrap().unwrap();
        let proposal: Proposal = serde_json::from_slice(&bytes).unwrap();
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
            &serde_json::to_vec(&VoteOption::Yes).unwrap(),
        )
        .unwrap();

        // Tally:
        // - total_voting_power = 1000. Quorum = 330. Voted power = 600. -> Quorum met.
        // - total_power_excluding_abstain = 600. Veto threshold = 198. Veto votes = 0. -> No veto.
        // - Pass threshold = 300. Yes votes = 600. -> Passed.
        module
            .tally_proposal(&mut state, proposal_id, &stakes)
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
            &serde_json::to_vec(&VoteOption::Yes).unwrap(),
        )
        .unwrap();

        // Tally:
        // - total_voting_power = 1300. Quorum = 429. Voted power = 300. -> Quorum FAILED.
        module
            .tally_proposal(&mut state, proposal_id, &stakes)
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
            &serde_json::to_vec(&VoteOption::Yes).unwrap(),
        )
        .unwrap();
        StateCommitment::insert(
            &mut state,
            &GovernanceModule::vote_key(proposal_id, &voter2_id),
            &serde_json::to_vec(&VoteOption::No).unwrap(),
        )
        .unwrap();

        // Tally:
        // - total_voting_power = 1000. Quorum = 330. Voted power = 1000. -> Quorum met.
        // - total_power_excluding_abstain = 1000. Pass threshold = 500. Yes votes = 400. -> Threshold FAILED.
        module
            .tally_proposal(&mut state, proposal_id, &stakes)
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
            &serde_json::to_vec(&VoteOption::Yes).unwrap(),
        )
        .unwrap();
        StateCommitment::insert(
            &mut state,
            &GovernanceModule::vote_key(proposal_id, &voter2_id),
            &serde_json::to_vec(&VoteOption::NoWithVeto).unwrap(),
        )
        .unwrap();

        // Tally:
        // - total_voting_power = 1000. Quorum = 330. Voted power = 1000. -> Quorum met.
        // - total_power_excluding_abstain = 1000. Veto threshold = 330. Veto votes = 400. -> VETOED.
        module
            .tally_proposal(&mut state, proposal_id, &stakes)
            .unwrap();
        assert_eq!(get_status(&state, proposal_id), ProposalStatus::Rejected);
    }
}
