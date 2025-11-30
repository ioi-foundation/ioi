// Path: crates/contract-sdk/src/lib.rs
#![no_std]

pub extern crate alloc;

// All WIT-generated code lives under this module.
pub mod bindings {
    wit_bindgen::generate!({
        path: "../types/wit/ioi.wit",
        world: "service",
        // This makes `__export_service_impl!` visible to other crates.
        pub_export_macro: true,
    });
}

// Re-export the Guest trait so contracts can `use ioi_contract_sdk::Guest;`
pub use bindings::Guest;

// IMPORTANT: Do NOT re-export the macro here to avoid E0255 conflicts.
// Contracts will access the export macro via `#[macro_use] extern crate ioi_contract_sdk`
// and then call `__export_service_impl!(...)`.

use alloc::{string::String, vec::Vec};

// -----------------------------------------------------------------------------
// Provide `memcmp` so Rust core/alloc don’t import it from `env`.
// This avoids the `env::memcmp` import that `wit-component` rejects.
// -----------------------------------------------------------------------------
#[no_mangle]
pub unsafe extern "C" fn memcmp(s1: *const u8, s2: *const u8, n: usize) -> i32 {
    use core::ptr;

    // Standard C semantics: compare byte-by-byte, return <0, 0, or >0.
    for i in 0..n {
        let a = ptr::read(s1.add(i));
        let b = ptr::read(s2.add(i));
        if a != b {
            return (a as i32) - (b as i32);
        }
    }
    0
}

/// Convenience trait for IOI services.
pub trait IoiService {
    fn id() -> String;
    fn abi_version() -> u32;
    fn state_schema() -> String;
    fn manifest() -> String;

    fn handle_service_call(method: String, params: Vec<u8>) -> Result<Vec<u8>, String>;

    fn prepare_upgrade(_input: Vec<u8>) -> Vec<u8> {
        Vec::new()
    }

    fn complete_upgrade(_input: Vec<u8>) -> Vec<u8> {
        Vec::new()
    }
}

// Re-export the procedural macro for convenient use
pub use ioi_macros::ioi_contract;

pub mod context;
pub mod host;
pub mod state;
