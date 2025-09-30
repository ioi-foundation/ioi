// Path: crates/contract/src/lib.rs
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::todo,
        clippy::unimplemented,
        clippy::indexing_slicing
    )
)]
#![allow(unsafe_code)]
//
// This crate is an exception to the `#![forbid(unsafe_code)]` policy.
// It defines the Foreign Function Interface (FFI) boundary between a smart contract
// (WASM) and the host runtime. All `unsafe` blocks herein are necessary to cross
// this boundary and must be rigorously audited to ensure they uphold the safety
// invariants required by the safe wrapper functions they implement.
//
#![no_std]
#![allow(dead_code)] // Allow unused functions for this example

extern crate alloc;
use alloc::vec::Vec;
// This is only needed for the panic handler, which is not used in tests.
#[cfg(not(test))]
use core::panic::PanicInfo;

// We use `wee_alloc` as a lightweight allocator suitable for WASM.
// This is enabled by the `wee_alloc` feature in Cargo.toml and solves the
// "no global memory allocator found" error.
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

/// FFI (Foreign Function Interface) for host functions.
/// These are the low-level, unsafe functions imported from the blockchain node.
mod ffi {
    #[link(wasm_import_module = "env")]
    extern "C" {
        // State management
        pub fn state_set(key_ptr: *const u8, key_len: u32, value_ptr: *const u8, value_len: u32);
        pub fn state_get(key_ptr: *const u8, key_len: u32, result_ptr: *mut u8) -> u32;

        // Context
        pub fn get_caller(result_ptr: *mut u8) -> u32;
    }
}

/// High-level, safe API for interacting with the blockchain state.
pub mod state {
    use super::ffi;
    use alloc::vec;
    use alloc::vec::Vec;

    /// Stores a key-value pair in the contract's storage.
    pub fn set(key: &[u8], value: &[u8]) {
        unsafe {
            ffi::state_set(
                key.as_ptr(),
                key.len() as u32,
                value.as_ptr(),
                value.len() as u32,
            );
        }
    }

    /// Retrieves a value from storage by key. Returns `None` if the key doesn't exist.
    pub fn get(key: &[u8]) -> Option<Vec<u8>> {
        // Allocate a buffer for the host to write the result into.
        // A real SDK would have a more robust max value size handling.
        let mut result_buffer = vec![0u8; 1024];
        let result_len =
            unsafe { ffi::state_get(key.as_ptr(), key.len() as u32, result_buffer.as_mut_ptr()) };

        if result_len > 0 {
            Some(
                result_buffer
                    .get(..result_len as usize)
                    .unwrap_or_default()
                    .to_vec(),
            )
        } else {
            None
        }
    }
}

/// High-level API for accessing execution context information.
pub mod context {
    use super::ffi;
    use alloc::vec;
    use alloc::vec::Vec;

    /// Gets the address of the entity that initiated the contract call.
    pub fn caller() -> Vec<u8> {
        let mut result_buffer = vec![0u8; 32]; // Standard address size
        let result_len = unsafe { ffi::get_caller(result_buffer.as_mut_ptr()) };
        result_buffer
            .get(..result_len as usize)
            .unwrap_or_default()
            .to_vec()
    }
}

// --- Memory Management & Panic Handler (Required for WASM no_std) ---

#[no_mangle]
pub extern "C" fn allocate(size: u32) -> *mut u8 {
    let mut buffer = Vec::with_capacity(size as usize);
    let ptr = buffer.as_mut_ptr();
    core::mem::forget(buffer); // Prevent Rust from dropping the memory
    ptr
}

// The panic handler is required for `no_std` builds, but conflicts with
// the standard library's handler when running tests. We exclude it from test builds.
#[cfg(not(test))]
#[panic_handler]
fn handle_panic(_info: &PanicInfo) -> ! {
    loop {}
}
