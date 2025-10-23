// Path: crates/services/src/governance/contract/src/lib.rs
#![no_std]
#![cfg(target_arch = "wasm32")]
extern crate alloc;

use alloc::{collections::BTreeMap, format, string::String, vec, vec::Vec};
use depin_sdk_contract::{self as sdk, context, state};
use parity_scale_codec::{Decode, Encode};

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
enum ProposalStatus { DepositPeriod, VotingPeriod, Passed, Rejected }
#[derive(Encode, Decode, Clone, PartialEq, Eq)]
enum ProposalType { Text, Custom(String) }
#[derive(Encode, Decode, Clone, Copy, PartialEq, Eq)]
enum VoteOption { Yes, No, NoWithVeto, Abstain }
#[derive(Encode, Decode, Clone, Default)]
struct TallyResult { yes: u64, no: u64, no_with_veto: u64, abstain: u64 }
#[derive(Encode, Decode, Clone)]
struct Proposal {
    id: u64, title: String, description: String, proposal_type: ProposalType,
    status: ProposalStatus, submitter: Vec<u8>, submit_height: u64,
    deposit_end_height: u64, voting_start_height: u64, voting_end_height: u64,
    total_deposit: u64, final_tally: Option<TallyResult>,
}
#[derive(Encode, Decode)]
struct StateEntry { value: Vec<u8>, block_height: u64 }
#[derive(Encode, Decode, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Default, Hash)]
struct AccountId(pub [u8; 32]);
#[derive(Encode, Decode, Clone)]
struct ValidatorV1 { account_id: AccountId, weight: u128, /*...redacted...*/ }
#[derive(Encode, Decode, Clone, Default)]
struct ValidatorSetV1 { effective_from_height: u64, total_weight: u128, validators: Vec<ValidatorV1> }
#[derive(Encode, Decode, Clone, Default)]
struct ValidatorSetsV1 { current: ValidatorSetV1, next: Option<ValidatorSetV1> }

// --- FFI Helpers ---
fn return_result(res: Result<(), String>) -> u64 {
    let resp_bytes = res.encode();
    let ptr = sdk::allocate(resp_bytes.len() as u32);
    unsafe { core::ptr::copy_nonoverlapping(resp_bytes.as_ptr(), ptr, resp_bytes.len()); }
    ((ptr as u64) << 32) | (resp_bytes.len() as u64)
}
fn return_data(data: &[u8]) -> u64 {
    let ptr = sdk::allocate(data.len() as u32);
    unsafe { core::ptr::copy_nonoverlapping(data.as_ptr(), ptr, data.len()); }
    ((ptr as u64) << 32) | (data.len() as u64)
}

// --- On-Chain Logic ---
fn submit_proposal(submitter: &AccountId, params: &[u8]) -> Result<(), String> {
    let p: SubmitProposalParams = Decode::decode(&mut &*params).map_err(|e| e.to_string())?;
    
    let id: u64 = state::get(GOVERNANCE_NEXT_PROPOSAL_ID_KEY)
        .and_then(|b| Decode::decode(&mut &*b).ok())
        .unwrap_or(0);
    state::set(GOVERNANCE_NEXT_PROPOSAL_ID_KEY, &(id + 1).encode());
    
    let current_height = context::block_height();
    let voting_period_blocks = 20_000; // Placeholder, would come from on-chain params
    let voting_end_height = current_height + voting_period_blocks;

    let proposal = Proposal {
        id, title: p.title, description: p.description, proposal_type: p.proposal_type,
        status: ProposalStatus::VotingPeriod, submitter: submitter.0.to_vec(), submit_height: current_height,
        deposit_end_height: 0, voting_start_height: current_height, voting_end_height,
        total_deposit: p.deposit, final_tally: None,
    };
    
    let key = [GOVERNANCE_PROPOSAL_KEY_PREFIX, &id.to_le_bytes()].concat();
    let entry = StateEntry { value: proposal.encode(), block_height: current_height };
    state::set(&key, &entry.encode());

    // Add to tallying index
    let index_key = [TALLY_INDEX_PREFIX, &voting_end_height.to_le_bytes()].concat();
    let mut index: Vec<u64> = state::get(&index_key)
        .and_then(|b| Decode::decode(&mut &*b).ok()).unwrap_or_default();
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
    let prop_entry: StateEntry = Decode::decode(&mut &*prop_entry_bytes).map_err(|e| e.to_string())?;
    let proposal: Proposal = Decode::decode(&mut &*prop_entry.value).map_err(|e| e.to_string())?;
    
    if proposal.status != ProposalStatus::VotingPeriod {
        return Err("Not in voting period".into());
    }

    let vote_key = [
        GOVERNANCE_VOTE_KEY_PREFIX, &p.proposal_id.to_le_bytes(), b"::", &voter.0,
    ].concat();
    state::set(&vote_key, &p.option.encode());

    Ok(())
}

fn on_end_block() -> Result<(), String> {
    let height = context::block_height();
    let index_key = [TALLY_INDEX_PREFIX, &height.to_le_bytes()].concat();

    if let Some(index_bytes) = state::get(&index_key) {
        let proposals_to_tally: Vec<u64> = Decode::decode(&mut &*index_bytes).map_err(|e| e.to_string())?;

        // This is inefficient but necessary without a `prefix_scan` FFI.
        // A real implementation would require that host capability.
        let stakes = state::get(VALIDATOR_SET_KEY)
            .and_then(|b| Decode::decode::<ValidatorSetsV1>(&mut &*b).ok())
            .map(|sets| sets.current.validators.into_iter().map(|v| (v.account_id, v.weight as u64)).collect::<BTreeMap<_,_>>())
            .unwrap_or_default();
        
        for proposal_id in proposals_to_tally {
            // Re-fetch proposal to update it
            let prop_key = [GOVERNANCE_PROPOSAL_KEY_PREFIX, &proposal_id.to_le_bytes()].concat();
            let prop_entry_bytes = state::get(&prop_key).ok_or("Proposal not found")?;
            let prop_entry: StateEntry = Decode::decode(&mut &*prop_entry_bytes).map_err(|e| e.to_string())?;
            let mut proposal: Proposal = Decode::decode(&mut &*prop_entry.value).map_err(|e| e.to_string())?;
            
            // Tallying logic here is complex and requires iterating over all possible voters
            // since `prefix_scan` is not available. This is a significant limitation.
            // ... Simplified logic: Assume it passed for demonstration.
            
            proposal.status = ProposalStatus::Passed;
            let updated_entry = StateEntry { value: proposal.encode(), block_height: prop_entry.block_height };
            state::set(&prop_key, &updated_entry.encode());
        }
        state::delete(&index_key);
    }
    Ok(())
}


// --- Service ABI Exports ---
#[no_mangle]
pub extern "C" fn handle_service_call(method_ptr: *const u8, method_len: u32, params_ptr: *const u8, params_len: u32) -> u64 {
    let method = unsafe { core::str::from_utf8(core::slice::from_raw_parts(method_ptr, method_len as usize)).unwrap_or("") };
    let params = unsafe { core::slice::from_raw_parts(params_ptr, params_len as usize) };
    let account_id_bytes: [u8; 32] = [0; 32]; // Passed from host context
    let account_id = AccountId(account_id_bytes);

    let result = match method {
        "submit_proposal@v1" => submit_proposal(&account_id, params),
        "vote@v1" => vote(&account_id, params),
        "on_end_block@v1" => on_end_block(),
        _ => Err(format!("Unknown method: {}", method)),
    };
    return_result(result)
}

#[no_mangle]
pub extern "C" fn manifest() -> u64 {
    let manifest_str = r#"
id = "governance"
abi_version = 1
state_schema = "v1"
runtime = "wasm"
capabilities = ["OnEndBlock"]

[methods]
"submit_proposal@v1" = "User"
"vote@v1" = "User"
"on_end_block@v1" = "Internal"
"#;
    return_data(manifest_str.as_bytes())
}

// Standard service exports
#[no_mangle] pub extern "C" fn id() -> u64 { return_data(b"governance") }
#[no_mangle] pub extern "C" fn abi_version() -> u32 { 1 }
#[no_mangle] pub extern "C" fn state_schema() -> u64 { return_data(b"v1") }
#[no_mangle] pub extern "C" fn prepare_upgrade(_input_ptr: *const u8, _input_len: u32) -> u64 { return_data(&[]) }
#[no_mangle] pub extern "C" fn complete_upgrade(_input_ptr: *const u8, _input_len: u32) -> u64 { return_data(&[]) }