// Path: crates/services/src/identity/contract/src/lib.rs
#![no_std]
#![cfg(target_arch = "wasm32")]
extern crate alloc;

use alloc::{format, string::String, vec, vec::Vec};
use depin_sdk_contract::{self as sdk, context, host, state};
use parity_scale_codec::{Decode, Encode};

// --- Canonical Data Structures & Keys (must match types crate) ---
// Note: In a production SDK, these would be in a shared `depin-sdk-contract-types` crate.

const IDENTITY_CREDENTIALS_PREFIX: &[u8] = b"identity::creds::";
const IDENTITY_ROTATION_NONCE_PREFIX: &[u8] = b"identity::nonce::rotation::";
const IDENTITY_PROMOTION_INDEX_PREFIX: &[u8] = b"identity::index::promotion::";
const VALIDATOR_SET_KEY: &[u8] = b"system::validators::current";

#[derive(Encode, Decode, Clone, Copy, PartialEq, Eq, Debug)]
enum SignatureSuite {
    Ed25519 = 0,
    Dilithium2 = 1,
}

#[derive(Encode, Decode, Clone, PartialEq, Eq, Debug)]
struct Credential {
    suite: SignatureSuite,
    public_key_hash: [u8; 32],
    activation_height: u64,
}

#[derive(Encode, Decode)]
struct RotationProof {
    old_public_key: Vec<u8>,
    old_signature: Vec<u8>,
    new_public_key: Vec<u8>,
    new_signature: Vec<u8>,
    target_suite: SignatureSuite,
}

#[derive(Encode, Decode, Clone)]
struct ActiveKeyRecord {
    suite: SignatureSuite,
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

#[derive(Encode, Decode, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Default, Hash)]
struct AccountId(pub [u8; 32]);

#[derive(Encode)]
struct RotateKeyParams {
    proof: RotationProof,
}

// --- Host Call ABI for Crypto ---
#[derive(Encode)]
struct VerifySigParams<'a> {
    suite: SignatureSuite,
    public_key: &'a [u8],
    message: &'a [u8],
    signature: &'a [u8],
}
#[derive(Decode)]
struct VerifySigResult(bool);

#[derive(Encode)]
struct AccountIdParams<'a> {
    suite: SignatureSuite,
    public_key: &'a [u8],
}
#[derive(Decode)]
struct AccountIdResult(Result<[u8; 32], String>);

// --- FFI Helpers ---
fn return_result(res: Result<(), String>) -> u64 {
    let resp_bytes = res.encode();
    let ptr = sdk::allocate(resp_bytes.len() as u32);
    unsafe {
        core::ptr::copy_nonoverlapping(resp_bytes.as_ptr(), ptr, resp_bytes.len());
    }
    ((ptr as u64) << 32) | (resp_bytes.len() as u64)
}

fn return_data(data: &[u8]) -> u64 {
    let ptr = sdk::allocate(data.len() as u32);
    unsafe {
        core::ptr::copy_nonoverlapping(data.as_ptr(), ptr, data.len());
    }
    ((ptr as u64) << 32) | (data.len() as u64)
}

// --- On-Chain Logic ---

fn get_credentials(account_id: &AccountId) -> Result<[Option<Credential>; 2], String> {
    let key = [IDENTITY_CREDENTIALS_PREFIX, &account_id.0].concat();
    state::get(&key)
        .map(|bytes| Decode::decode(&mut &*bytes).map_err(|e| format!("decode creds: {}", e)))
        .unwrap_or(Ok([None, None]))
}

fn account_id_from_key(suite: SignatureSuite, public_key: &[u8]) -> Result<[u8; 32], String> {
    host::call::<_, AccountIdResult>(
        "crypto::account_id_from_key",
        &AccountIdParams { suite, public_key },
    )
    .map_err(|e| format!("host call failed: {:?}", e))?
    .0
}

fn rotate_key(account_id: &AccountId, params: &[u8]) -> Result<(), String> {
    let p: RotateKeyParams = Decode::decode(&mut &*params).map_err(|e| format!("decode params: {}", e))?;
    let proof = p.proof;

    let mut creds = get_credentials(account_id)?;
    let active_cred = creds[0]
        .as_ref()
        .ok_or("No active credential to rotate from")?;
    if creds[1].is_some() {
        return Err("Rotation already in progress".into());
    }

    let nonce_key = [IDENTITY_ROTATION_NONCE_PREFIX, &account_id.0].concat();
    let nonce: u64 = state::get(&nonce_key)
        .and_then(|b| Decode::decode(&mut &*b).ok())
        .unwrap_or(0);

    let mut challenge_preimage = b"DePIN-PQ-MIGRATE/v1".to_vec();
    // Assuming a host call for chain_id exists
    // challenge_preimage.extend_from_slice(&context::chain_id().to_le_bytes());
    challenge_preimage.extend_from_slice(&account_id.0);
    challenge_preimage.extend_from_slice(&nonce.to_le_bytes());

    // This would ideally be a single host call to `sha256`.
    let challenge: [u8; 32] = [0; 32]; // Placeholder

    // Verify signatures
    if !host::call::<_, VerifySigResult>(
        "crypto::verify_signature",
        &VerifySigParams {
            suite: active_cred.suite,
            public_key: &proof.old_public_key,
            message: &challenge,
            signature: &proof.old_signature,
        },
    )
    .map_err(|e| format!("host call failed: {:?}", e))?
    .0
    {
        return Err("Old key signature verification failed".into());
    }

    // ... (rest of the logic ported from `services/src/identity/mod.rs`)
    // - verify new signature
    // - check old_public_key hash against active_cred
    // - create new staged Credential
    // - write updated credentials array and promotion index to state
    // - increment and write nonce
    Ok(())
}

fn on_end_block() -> Result<(), String> {
    let height = context::block_height();
    let index_key = [IDENTITY_PROMOTION_INDEX_PREFIX, &height.to_le_bytes()].concat();

    if let Some(index_bytes) = state::get(&index_key) {
        let accounts: Vec<AccountId> = Decode::decode(&mut &*index_bytes).map_err(|e| e.to_string())?;

        for account_id in accounts {
            let mut creds = get_credentials(&account_id)?;
            if let Some(staged) = creds[1].take() {
                creds[0] = Some(staged);
                let creds_key = [IDENTITY_CREDENTIALS_PREFIX, &account_id.0].concat();
                state::set(&creds_key, &creds.encode());

                // Update validator set if applicable
                if let Some(vs_bytes) = state::get(VALIDATOR_SET_KEY) {
                    let mut sets: ValidatorSetsV1 = Decode::decode(&mut &*vs_bytes).map_err(|e| e.to_string())?;
                    let target_activation = height + 1;
                    if sets.next.as_ref().map_or(true, |n| n.effective_from_height != target_activation) {
                         let mut new_next = sets.next.clone().unwrap_or_else(|| sets.current.clone());
                         new_next.effective_from_height = target_activation;
                         sets.next = Some(new_next);
                    }
                    if let Some(next_vs) = sets.next.as_mut() {
                        if let Some(v) = next_vs.validators.iter_mut().find(|v| v.account_id == account_id) {
                            v.consensus_key = ActiveKeyRecord {
                                suite: creds[0].as_ref().unwrap().suite,
                                public_key_hash: creds[0].as_ref().unwrap().public_key_hash,
                                since_height: target_activation,
                            };
                            state::set(VALIDATOR_SET_KEY, &sets.encode());
                        }
                    }
                }
            }
        }
        state::delete(&index_key);
    }
    Ok(())
}

// --- FFI Exports ---
#[no_mangle]
pub extern "C" fn handle_service_call(
    method_ptr: *const u8,
    method_len: u32,
    params_ptr: *const u8,
    params_len: u32,
) -> u64 {
    let method =
        unsafe { core::str::from_utf8(core::slice::from_raw_parts(method_ptr, method_len as usize)).unwrap_or("") };
    let params = unsafe { core::slice::from_raw_parts(params_ptr, params_len as usize) };
    let account_id_bytes: [u8; 32] = [0; 32]; // This needs to be passed from the host context
    let account_id = AccountId(account_id_bytes);

    let result = match method {
        "rotate_key@v1" => rotate_key(&account_id, params),
        "on_end_block@v1" => on_end_block(),
        _ => Err(format!("Unknown method: {}", method)),
    };
    return_result(result)
}

#[no_mangle]
pub extern "C" fn manifest() -> u64 {
    let manifest_str = r#"
id = "identity_hub"
abi_version = 1
state_schema = "v1"
runtime = "wasm"
capabilities = ["OnEndBlock"]

[methods]
"rotate_key@v1" = "User"
"on_end_block@v1" = "Internal"
"#;
    return_data(manifest_str.as_bytes())
}

#[no_mangle]
pub extern "C" fn id() -> u64 {
    return_data(b"identity_hub")
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
    return_data(&[])
}
#[no_mangle]
pub extern "C" fn complete_upgrade(_input_ptr: *const u8, _input_len: u32) -> u64 {
    return_data(&[])
}