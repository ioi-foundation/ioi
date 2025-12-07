// Path: crates/contract-sdk/src/lib.rs
#![no_std]

pub extern crate alloc;

// [NEW] Use rlibc to satisfy linker requirements for memcmp/memset
extern crate rlibc;

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

use alloc::{string::String, vec::Vec};

// [REMOVED] Manual unsafe extern "C" fn memcmp is no longer needed due to rlibc.

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

// Helper for FFI allocation (used by macros/generated code)
pub fn allocate(size: u32) -> *mut u8 {
    let layout = core::alloc::Layout::from_size_align(size as usize, 1).unwrap();
    unsafe { alloc::alloc::alloc(layout) }
}