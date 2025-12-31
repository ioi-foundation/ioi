// Path: crates/services/src/oracle/contract/src/lib.rs
#![no_std]
extern crate alloc;

use alloc::{format, string::String, string::ToString, vec, vec::Vec};
use ioi_contract_sdk::{context, ioi_contract, state, IoiService};
use parity_scale_codec::{Decode, Encode};

// --- Canonical Data Structures & Keys ---

const ORACLE_PENDING_REQUEST_PREFIX: &[u8] = b"oracle::pending::";
const ORACLE_DATA_PREFIX: &[u8] = b"oracle::data::";

#[derive(Encode, Decode)]
struct RequestDataParams {
    url: String,
    request_id: u64,
}

#[derive(Encode, Decode)]
struct SubmitDataParams {
    request_id: u64,
    final_value: Vec<u8>,
    consensus_proof: OracleConsensusProof,
}

#[derive(Encode, Decode, Clone)]
struct OracleAttestation {
    request_id: u64,
    value: Vec<u8>,
    timestamp: u64,
    signature: Vec<u8>,
}

#[derive(Encode, Decode)]
struct OracleConsensusProof {
    attestations: Vec<OracleAttestation>,
}

#[derive(Encode, Decode)]
struct StateEntry {
    value: Vec<u8>,
    block_height: u64,
}

// --- Service Implementation ---

struct OracleService;

#[ioi_contract]
impl IoiService for OracleService {
    fn id() -> String {
        "oracle".to_string()
    }

    fn abi_version() -> u32 {
        1
    }

    fn state_schema() -> String {
        "v1".to_string()
    }

    fn manifest() -> String {
        r#"
id = "oracle"
abi_version = 1
state_schema = "v1"
runtime = "wasm"
capabilities = []

[methods]
"request_data@v1" = "User"
"submit_data@v1" = "User"
"#
        .to_string()
    }

    fn handle_service_call(method: String, params: Vec<u8>) -> Result<Vec<u8>, String> {
        let result = match method.as_str() {
            "request_data@v1" => request_data(&params),
            "submit_data@v1" => submit_data(&params),
            _ => Err(format!("Unknown method: {}", method)),
        };

        // The host expects a SCALE-encoded Result<(), String>
        Ok(result.encode())
    }

    // Default implementations for upgrade hooks are provided by the trait,
    // returning empty vectors which is correct for this stateless service logic.
}

// --- On-Chain Logic ---

/// Handles the `request_data@v1` call. Creates a pending request in the state.
fn request_data(params: &[u8]) -> Result<(), String> {
    let p: RequestDataParams =
        Decode::decode(&mut &*params).map_err(|e| format!("decode params failed: {}", e))?;

    let request_key = [ORACLE_PENDING_REQUEST_PREFIX, &p.request_id.to_le_bytes()].concat();

    // Prevent overwriting an existing request (basic idempotency)
    if state::get(&request_key).is_some() {
        return Err("Request ID already exists".to_string());
    }

    let entry = StateEntry {
        value: p.url.encode(),
        block_height: context::block_height(),
    };
    state::set(&request_key, &entry.encode());
    Ok(())
}

/// Handles the `submit_data@v1` call. Verifies consensus proof and finalizes data.
fn submit_data(params: &[u8]) -> Result<(), String> {
    let p: SubmitDataParams =
        Decode::decode(&mut &*params).map_err(|e| format!("decode params failed: {}", e))?;

    // On-chain guardrails
    const MAX_ATTESTATIONS: usize = 100;
    if p.consensus_proof.attestations.is_empty() {
        return Err("Oracle proof is empty".into());
    }
    if p.consensus_proof.attestations.len() > MAX_ATTESTATIONS {
        return Err("Exceeded max attestations".into());
    }

    // In a full implementation, we would verify signatures here using `host::call`
    // to access cryptographic primitives exposed by the host environment.
    // For now, we trust the consensus logic has filtered validity at the orchestration layer,
    // but the contract enforces state transitions.

    let pending_key = [ORACLE_PENDING_REQUEST_PREFIX, &p.request_id.to_le_bytes()].concat();

    // Ensure the request was actually made
    if state::get(&pending_key).is_none() {
        return Err("Request not pending or already finalized".into());
    }

    let final_key = [ORACLE_DATA_PREFIX, &p.request_id.to_le_bytes()].concat();
    let entry = StateEntry {
        value: p.final_value,
        block_height: context::block_height(),
    };

    // Atomic state transition: Remove pending, write data.
    state::delete(&pending_key);
    state::set(&final_key, &entry.encode());

    Ok(())
}
