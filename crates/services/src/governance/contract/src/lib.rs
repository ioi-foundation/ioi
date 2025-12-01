// Path: crates/services/src/governance/contract/src/lib.rs
#![no_std]
extern crate alloc;

use alloc::{collections::BTreeMap, format, string::String, string::ToString, vec, vec::Vec};
use ioi_contract_sdk::{self as sdk, context, state};
use parity_scale_codec::{Decode, Encode};

mod bindings {
    pub use ioi_contract_sdk::bindings::*;
}
use bindings::Guest;

// --- Canonical Data Structures & Keys ---
const GOVERNANCE_NEXT_PROPOSAL_ID_KEY: &[u8] = b"gov::next_id";
const GOVERNANCE_PROPOSAL_KEY_PREFIX: &[u8] = b"gov::proposal::";
const GOVERNANCE_VOTE_KEY_PREFIX: &[u8] = b"gov::vote::";
const VALIDATOR_SET_KEY: &[u8] = b"system::validators::current";
const TALLY_INDEX_PREFIX: &[u8] = b"gov::index::tally::";

#[derive(Encode, Decode)]
struct SubmitProposalParams {
    proposal_type: ProposalType,
    title: String,
    description: String,
    deposit: u64,
}
#[derive(Encode, Decode)]
struct VoteParams {
    proposal_id: u64,
    option: VoteOption,
}
#[derive(Encode, Decode, Clone, Copy, PartialEq, Eq)]
enum ProposalStatus {
    DepositPeriod,
    VotingPeriod,
    Passed,
    Rejected,
}
#[derive(Encode, Decode, Clone, PartialEq, Eq)]
enum ProposalType {
    Text,
    Custom(String),
}
#[derive(Encode, Decode, Clone, Copy, PartialEq, Eq)]
enum VoteOption {
    Yes,
    No,
    NoWithVeto,
    Abstain,
}
#[derive(Encode, Decode, Clone, Default)]
struct TallyResult {
    yes: u64,
    no: u64,
    no_with_veto: u64,
    abstain: u64,
}
#[derive(Encode, Decode, Clone)]
struct Proposal {
    id: u64,
    title: String,
    description: String,
    proposal_type: ProposalType,
    status: ProposalStatus,
    submitter: Vec<u8>,
    submit_height: u64,
    deposit_end_height: u64,
    voting_start_height: u64,
    voting_end_height: u64,
    total_deposit: u64,
    final_tally: Option<TallyResult>,
}
#[derive(Encode, Decode)]
struct StateEntry {
    value: Vec<u8>,
    block_height: u64,
}
#[derive(Encode, Decode, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Default, Hash)]
struct AccountId(pub [u8; 32]);

#[derive(Encode, Decode, Clone, Default)]
struct ActiveKeyRecord {
    suite: u8, // SignatureSuite enum usually encodes as u8 variant index
    public_key_hash: [u8; 32],
    since_height: u64,
}

#[derive(Encode, Decode, Clone)]
struct ValidatorV1 {
    account_id: AccountId,
    weight: u128,
    consensus_key: ActiveKeyRecord,
}
#[derive(Encode, Decode, Clone, Default)]
struct ValidatorSetV1 {
    effective_from_height: u64,
    total_weight: u128,
    validators: Vec<ValidatorV1>,
}
#[derive(Encode, Decode, Clone, Default)]
struct ValidatorSetsV1 {
    current: ValidatorSetV1,
    next: Option<ValidatorSetV1>,
}

// --- On-Chain Logic ---

fn submit_proposal(submitter: &AccountId, params: &[u8]) -> Result<(), String> {
    let p: SubmitProposalParams = Decode::decode(&mut &*params).map_err(|e| e.to_string())?;

    let id: u64 = state::get(GOVERNANCE_NEXT_PROPOSAL_ID_KEY)
        .and_then(|b| Decode::decode(&mut &*b).ok())
        .unwrap_or(0);
    state::set(GOVERNANCE_NEXT_PROPOSAL_ID_KEY, &(id + 1).encode());

    let current_height = context::block_height();
    let voting_period_blocks = 20_000; // Placeholder
    let voting_end_height = current_height + voting_period_blocks;

    let proposal = Proposal {
        id,
        title: p.title,
        description: p.description,
        proposal_type: p.proposal_type,
        status: ProposalStatus::VotingPeriod,
        submitter: submitter.0.to_vec(),
        submit_height: current_height,
        deposit_end_height: 0,
        voting_start_height: current_height,
        voting_end_height,
        total_deposit: p.deposit,
        final_tally: None,
    };

    let key = [GOVERNANCE_PROPOSAL_KEY_PREFIX, &id.to_le_bytes()].concat();
    let entry = StateEntry {
        value: proposal.encode(),
        block_height: current_height,
    };
    state::set(&key, &entry.encode());

    // Add to tallying index
    let index_key = [TALLY_INDEX_PREFIX, &voting_end_height.to_le_bytes()].concat();
    let mut index: Vec<u64> = state::get(&index_key)
        .and_then(|b| Decode::decode(&mut &*b).ok())
        .unwrap_or_default();
    if !index.contains(&id) {
        index.push(id);
        state::set(&index_key, &index.encode());
    }

    Ok(())
}

fn vote(voter: &AccountId, params: &[u8]) -> Result<(), String> {
    let p: VoteParams = Decode::decode(&mut &*params).map_err(|e| e.to_string())?;

    // Read and check proposal status (VotingPeriod)
    let prop_key = [GOVERNANCE_PROPOSAL_KEY_PREFIX, &p.proposal_id.to_le_bytes()].concat();
    let prop_entry_bytes = state::get(&prop_key).ok_or("Proposal not found")?;
    let prop_entry: StateEntry =
        Decode::decode(&mut &*prop_entry_bytes).map_err(|e| e.to_string())?;
    let proposal: Proposal = Decode::decode(&mut &*prop_entry.value).map_err(|e| e.to_string())?;

    if proposal.status != ProposalStatus::VotingPeriod {
        return Err("Not in voting period".into());
    }

    let vote_key = [
        GOVERNANCE_VOTE_KEY_PREFIX,
        &p.proposal_id.to_le_bytes(),
        b"::",
        &voter.0,
    ]
    .concat();
    state::set(&vote_key, &p.option.encode());

    Ok(())
}

fn on_end_block() -> Result<(), String> {
    let height = context::block_height();
    let index_key = [TALLY_INDEX_PREFIX, &height.to_le_bytes()].concat();

    if let Some(index_bytes) = state::get(&index_key) {
        let proposals_to_tally: Vec<u64> =
            Decode::decode(&mut &*index_bytes).map_err(|e| e.to_string())?;

        // Fetch validator set for weights
        let stakes = state::get(VALIDATOR_SET_KEY)
            .and_then(|b| Decode::decode::<ValidatorSetsV1>(&mut &*b).ok())
            .map(|sets| {
                sets.current
                    .validators
                    .into_iter()
                    .map(|v| (v.account_id, v.weight as u64))
                    .collect::<BTreeMap<_, _>>()
            })
            .unwrap_or_default();

        for proposal_id in proposals_to_tally {
            // Re-fetch proposal to update it
            let prop_key = [GOVERNANCE_PROPOSAL_KEY_PREFIX, &proposal_id.to_le_bytes()].concat();
            let prop_entry_bytes = state::get(&prop_key).ok_or("Proposal not found")?;
            let prop_entry: StateEntry =
                Decode::decode(&mut &*prop_entry_bytes).map_err(|e| e.to_string())?;
            let mut proposal: Proposal =
                Decode::decode(&mut &*prop_entry.value).map_err(|e| e.to_string())?;

            // Construct prefix for votes: "gov::vote::{id}::"
            let vote_prefix = [
                GOVERNANCE_VOTE_KEY_PREFIX,
                &proposal_id.to_le_bytes(),
                b"::",
            ]
            .concat();

            // Use the new host function to scan for votes
            let votes = state::prefix_scan(&vote_prefix);

            let mut tally = TallyResult::default();
            let mut total_voted_power = 0;

            for (key, val) in votes {
                // Key format: gov::vote::{id}::{voter_account_id_bytes}
                // voter_account_id_bytes is 32 bytes at the end
                if key.len() < 32 {
                    continue;
                }
                let voter_bytes = &key[key.len() - 32..];
                let mut voter_arr = [0u8; 32];
                voter_arr.copy_from_slice(voter_bytes);
                let voter_id = AccountId(voter_arr);

                let weight = *stakes.get(&voter_id).unwrap_or(&0);

                if let Ok(option) = Decode::decode::<VoteOption>(&mut &*val) {
                    match option {
                        VoteOption::Yes => tally.yes += weight,
                        VoteOption::No => tally.no += weight,
                        VoteOption::NoWithVeto => tally.no_with_veto += weight,
                        VoteOption::Abstain => tally.abstain += weight,
                    }
                    total_voted_power += weight;
                }
            }

            proposal.final_tally = Some(tally.clone());

            let total_stake: u64 = stakes.values().sum();

            // Simple majority logic (threshold 50%, quorum 33% - hardcoded for demo/test)
            if total_stake > 0 && total_voted_power >= (total_stake / 3) {
                let non_abstain = tally.yes + tally.no + tally.no_with_veto;
                if non_abstain > 0 && tally.yes > (non_abstain / 2) {
                    proposal.status = ProposalStatus::Passed;
                } else {
                    proposal.status = ProposalStatus::Rejected;
                }
            } else {
                proposal.status = ProposalStatus::Rejected;
            }

            let updated_entry = StateEntry {
                value: proposal.encode(),
                block_height: prop_entry.block_height,
            };
            state::set(&prop_key, &updated_entry.encode());
        }
        state::delete(&index_key);
    }
    Ok(())
}

// --- Component Model Implementation ---

struct GovernanceService;

impl Guest for GovernanceService {
    fn id() -> String {
        "governance".to_string()
    }

    fn abi_version() -> u32 {
        1
    }

    fn state_schema() -> String {
        "v1".to_string()
    }

    fn manifest() -> String {
        r#"
id = "governance"
abi_version = 1
state_schema = "v1"
runtime = "wasm"
capabilities = ["OnEndBlock"]

[methods]
"submit_proposal@v1" = "User"
"vote@v1" = "User"
"on_end_block@v1" = "Internal"
"#
        .to_string()
    }

    fn handle_service_call(method: String, params: Vec<u8>) -> Result<Vec<u8>, String> {
        // Retrieve the caller from the execution context.
        // The context::get_caller() returns Vec<u8>, expected to be 32 bytes for AccountId.
        let caller_bytes = context::sender();
        let account_id = if caller_bytes.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&caller_bytes);
            AccountId(arr)
        } else {
            // For Internal calls (like on_end_block), caller might be empty or special.
            // on_end_block doesn't use the account_id argument, so default is fine.
            // For user calls, a valid account ID is required.
            AccountId([0u8; 32])
        };

        let result = match method.as_str() {
            "submit_proposal@v1" => submit_proposal(&account_id, &params),
            "vote@v1" => vote(&account_id, &params),
            "on_end_block@v1" => on_end_block(),
            _ => Err(format!("Unknown method: {}", method)),
        };

        // The host expects a SCALE-encoded Result<(), String> for the return data.
        Ok(result.encode())
    }

    fn prepare_upgrade(_input: Vec<u8>) -> Vec<u8> {
        Vec::new()
    }

    fn complete_upgrade(_input: Vec<u8>) -> Vec<u8> {
        Vec::new()
    }
}

bindings::export!(GovernanceService with_types_in bindings);
