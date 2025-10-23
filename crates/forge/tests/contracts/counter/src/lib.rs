// Path: crates/forge/tests/contracts/counter/src/lib.rs
#![cfg(target_arch = "wasm32")]
#![no_std]
extern crate alloc;

// CORRECTED IMPORTS
use alloc::vec;
use alloc::vec::Vec;
// Use the crate name directly as specified in its Cargo.toml
use depin_sdk_contract::{self as sdk, state};

// A simple ABI: the first byte of the input data determines the function.
const FUNC_GET: u8 = 0;
const FUNC_INCREMENT: u8 = 1;

// Entrypoint called by the VM.
#[no_mangle]
pub extern "C" fn call(input_ptr: *const u8, input_len: u32) -> u64 {
    let input_data = unsafe { core::slice::from_raw_parts(input_ptr, input_len as usize) };

    if input_data.is_empty() {
        return pack_ptr_len(0, 0); // No input, do nothing.
    }

    let result_data = match input_data[0] {
        FUNC_GET => get_count(),
        FUNC_INCREMENT => increment_count(),
        _ => Vec::new(), // Unknown function
    };

    // Allocate memory for the return data and write it.
    let ptr = sdk::allocate(result_data.len() as u32);
    unsafe {
        core::ptr::copy_nonoverlapping(result_data.as_ptr(), ptr, result_data.len());
    }

    pack_ptr_len(ptr as u32, result_data.len() as u32)
}

fn get_count() -> Vec<u8> {
    // `vec!` macro now resolves correctly.
    state::get(b"count").unwrap_or_else(|| vec![0])
}

fn increment_count() -> Vec<u8> {
    let mut count = state::get(b"count").map(|v| v[0]).unwrap_or(0);
    count += 1;
    state::set(b"count", &[count]);
    vec![count]
}

// Helper to pack a pointer and length into a single u64 for returning from WASM.
fn pack_ptr_len(ptr: u32, len: u32) -> u64 {
    ((ptr as u64) << 32) | (len as u64)
}
