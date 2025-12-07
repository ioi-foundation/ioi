// Path: crates/forge/tests/contracts/test-service/src/lib.rs
#![cfg(target_arch = "wasm32")]
#![no_std]
extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use ioi_contract_sdk::{ioi_contract, IoiService};

// [REMOVED] All manual Allocator, panic handler, and cabi_realloc logic.

struct TestServiceV2;

#[ioi_contract]
impl IoiService for TestServiceV2 {
    fn id() -> String {
        String::from("fee_calculator_v2")
    }

    fn abi_version() -> u32 {
        1
    }

    fn state_schema() -> String {
        String::from("v1")
    }

    fn manifest() -> String {
        String::from(
            r#"
id = "fee_calculator"
abi_version = 1
state_schema = "v1"
runtime = "wasm"
capabilities = ["TxDecorator"]

[methods]
"ante_validate@v1" = "Internal"
"ante_write@v1" = "Internal"
"#,
        )
    }

    fn handle_service_call(_method: String, _params: Vec<u8>) -> Result<Vec<u8>, String> {
        Err(String::from("Not implemented"))
    }
}

// [REMOVED] struct Component / impl Guest / __export_service_impl!
