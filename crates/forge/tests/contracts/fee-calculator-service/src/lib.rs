// Path: crates/forge/tests/contracts/fee-calculator-service/src/lib.rs
#![no_std]
extern crate alloc;

use alloc::string::String;
use depin_sdk_contract as sdk;
use parity_scale_codec::Encode;

/// Encodes a `Result<(), String>` and returns its pointer/length packed in a u64.
fn return_result(res: Result<(), String>) -> u64 {
    let resp_bytes = res.encode();
    return_data(&resp_bytes)
}

/// Helper to pack a pointer and length into a single u64 for returning from WASM.
fn return_data(data: &[u8]) -> u64 {
    let ptr = sdk::allocate(data.len() as u32);
    unsafe {
        core::ptr::copy_nonoverlapping(data.as_ptr(), ptr, data.len());
    }
    ((ptr as u64) << 32) | (data.len() as u64)
}

// --- Service ABI Implementation ---
#[no_mangle]
pub extern "C" fn id() -> u64 {
    return_data(b"fee_calculator")
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

/// --- TxDecorator Capability Implementation ---
#[export_name = "ante_handle@v1"]
pub extern "C" fn ante_handle(_req_ptr: *const u8, _req_len: u32) -> u64 {
    // Now that parity-scale-codec is correctly configured for no_std,
    // we can use .encode() safely. This makes the implementation consistent
    // with other services like governance.
    let res: Result<(), String> = Ok(());
    return_result(res)
}

#[no_mangle]
pub extern "C" fn manifest() -> u64 {
    let manifest_str = r#"
id = "fee_calculator"
abi_version = 1
state_schema = "v1"
runtime = "wasm"
capabilities = ["TxDecorator"]

[methods]
"ante_handle@v1" = "Internal"
"#;
    return_data(manifest_str.as_bytes())
}
