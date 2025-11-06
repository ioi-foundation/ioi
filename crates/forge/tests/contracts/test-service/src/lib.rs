// Path: crates/forge/tests/contracts/test-service/src/lib.rs
#![cfg(target_arch = "wasm32")]
#![no_std]
extern crate alloc;

use alloc::string::String;
use ioi_contract_sdk as sdk;

/// Helper to return a byte slice from a WASM function by packing its pointer and length into a u64.
/// This ABI is specific to wasm32.
fn return_data(data: &[u8]) -> u64 {
    let ptr = sdk::allocate(data.len() as u32);
    unsafe {
        core::ptr::copy_nonoverlapping(data.as_ptr(), ptr, data.len());
    }
    ((ptr as u64) << 32) | (data.len() as u64)
}

#[no_mangle]
pub extern "C" fn id() -> u64 {
    let id_str = String::from("fee_calculator_v2");
    return_data(id_str.as_bytes())
}

#[no_mangle]
pub extern "C" fn abi_version() -> u32 {
    1
}

#[no_mangle]
pub extern "C" fn state_schema() -> u64 {
    let schema_str = String::from("v1");
    return_data(schema_str.as_bytes())
}

#[no_mangle]
pub extern "C" fn prepare_upgrade(_input_ptr: *const u8, _input_len: u32) -> u64 {
    // This simple service is stateless, so it returns an empty snapshot.
    return_data(&[])
}

#[no_mangle]
pub extern "C" fn complete_upgrade(_input_ptr: *const u8, _input_len: u32) -> u64 {
    // Stateless, so nothing to do. Return empty to indicate success.
    return_data(&[])
}
