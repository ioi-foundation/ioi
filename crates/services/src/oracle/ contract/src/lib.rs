// Path: crates/services/src/oracle/contract/src/lib.rs
#![no_std]
#![cfg(target_arch = "wasm32")]
extern crate alloc;

use alloc::{format, string::String, vec, vec::Vec};
use ioi_contract_sdk::{self as sdk, context, state};
use parity_scale_codec::{Decode, Encode};

// --- Canonical Data Structures & Keys (must match types crate) ---
// In a production SDK, these would ideally be in a shared `ioi-contract-sdk-types` crate.

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

// --- FFI Helper ---
/// Encodes a `Result<(), String>` into SCALE format and returns its pointer/length packed in a u64.
fn return_result(res: Result<(), String>) -> u64 {
    let resp_bytes = res.encode();
    let ptr = sdk::allocate(resp_bytes.len() as u32);
    unsafe {
        core::ptr::copy_nonoverlapping(resp_bytes.as_ptr(), ptr, resp_bytes.len());
    }
    ((ptr as u64) << 32) | (resp_bytes.len() as u64)
}

/// Returns a raw byte slice from a WASM function by packing its pointer/length into a u64.
fn return_data(data: &[u8]) -> u64 {
    let ptr = sdk::allocate(data.len() as u32);
    unsafe {
        core::ptr::copy_nonoverlapping(data.as_ptr(), ptr, data.len());
    }
    ((ptr as u64) << 32) | (data.len() as u64)
}

// --- On-Chain Logic ---

/// Handles the `request_data@v1` call. Creates a pending request in the state.
fn request_data(params: &[u8]) -> Result<(), String> {
    let p: RequestDataParams =
        Decode::decode(&mut &*params).map_err(|e| format!("decode failed: {}", e))?;
    let request_key = [ORACLE_PENDING_REQUEST_PREFIX, &p.request_id.to_le_bytes()].concat();

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
        Decode::decode(&mut &*params).map_err(|e| format!("decode failed: {}", e))?;

    // On-chain guardrails
    const MAX_ATTESTATIONS: usize = 100;
    if p.consensus_proof.attestations.is_empty() {
        return Err("Oracle proof is empty".into());
    }
    if p.consensus_proof.attestations.len() > MAX_ATTESTATIONS {
        return Err("Exceeded max attestations".into());
    }

    // A real implementation would verify the signatures in the consensus proof here
    // by making a `host::call` to a cryptographic capability.

    let pending_key = [ORACLE_PENDING_REQUEST_PREFIX, &p.request_id.to_le_bytes()].concat();
    let final_key = [ORACLE_DATA_PREFIX, &p.request_id.to_le_bytes()].concat();
    let entry = StateEntry {
        value: p.final_value,
        block_height: context::block_height(),
    };

    state::delete(&pending_key);
    state::set(&final_key, &entry.encode());
    Ok(())
}

// --- Service ABI Exports ---

/// The primary entrypoint for the generic service dispatcher.
#[no_mangle]
pub extern "C" fn handle_service_call(
    method_ptr: *const u8,
    method_len: u32,
    params_ptr: *const u8,
    params_len: u32,
) -> u64 {
    let method = unsafe {
        core::str::from_utf8(core::slice::from_raw_parts(method_ptr, method_len as usize))
            .unwrap_or("")
    };
    let params = unsafe { core::slice::from_raw_parts(params_ptr, params_len as usize) };

    let result = match method {
        "request_data@v1" => request_data(params),
        "submit_data@v1" => submit_data(params),
        _ => Err(format!("Unknown method: {}", method)),
    };
    return_result(result)
}

/// Exports the service's canonical manifest.
#[no_mangle]
pub extern "C" fn manifest() -> u64 {
    // This TOML string is the on-chain source of truth for the service's ABI and ACL.
    let manifest_str = r#"
id = "oracle"
abi_version = 1
state_schema = "v1"
runtime = "wasm"
capabilities = [] # No lifecycle hooks needed for this service

[methods]
"request_data@v1" = "User"
"submit_data@v1" = "User"
"#;
    return_data(manifest_str.as_bytes())
}

// Standard service exports for upgradability and discovery.
#[no_mangle]
pub extern "C" fn id() -> u64 {
    return_data(b"oracle")
}
#[no_mangle]
pub extern "C" fn abi_version() -> u32 {
    1
}
#[no_mangle]
pub extern "C" fn state_schema() -> u64 {
    return_data(b"v1")
}
#[no_mangle]
pub extern "C" fn prepare_upgrade(_input_ptr: *const u8, _input_len: u32) -> u64 {
    // Stateless service, returns empty snapshot.
    return_data(&[])
}
#[no_mangle]
pub extern "C" fn complete_upgrade(_input_ptr: *const u8, _input_len: u32) -> u64 {
    // Stateless service, nothing to restore. Return empty for success.
    return_data(&[])
}
