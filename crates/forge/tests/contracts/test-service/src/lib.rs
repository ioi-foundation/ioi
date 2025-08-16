// Path: crates/forge/tests/contracts/test-service/src/lib.rs
#![cfg(target_arch = "wasm32")]
#![no_std]
extern crate alloc;

use alloc::string::String;
use depin_sdk_contract as sdk;

/// Helper to return a byte slice from a WASM function.
fn return_data(data: &[u8]) -> u64 {
    let ptr = sdk::allocate(data.len() as u32);
    unsafe {
        core::ptr::copy_nonoverlapping(data.as_ptr(), ptr, data.len());
    }
    ((ptr as u64) << 32) | (data.len() as u64)
}

#[no_mangle]
pub extern "C" fn service_type() -> u64 {
    let type_str = String::from("fee_calculator_v2");
    return_data(type_str.as_bytes())
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
