// Path: crates/forge/tests/contracts/fee-calculator-service/src/lib.rs
#![no_std]
extern crate alloc;

// Use the macro instead of manual boilerplate
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use ioi_contract_sdk::{ioi_contract, IoiService};
use parity_scale_codec::Encode;

struct FeeCalculator;

// The macro automatically generates:
// 1. The Global Allocator
// 2. The Panic Handler
// 3. The cabi_realloc export
// 4. The Guest trait implementation and export! call
#[ioi_contract]
impl IoiService for FeeCalculator {
    fn id() -> String {
        "fee_calculator".to_string()
    }

    fn abi_version() -> u32 {
        1
    }

    fn state_schema() -> String {
        "v1".to_string()
    }

    fn manifest() -> String {
        alloc::format!(
            r#"
id = "fee_calculator"
abi_version = 1
state_schema = "v1"
runtime = "wasm"
capabilities = ["TxDecorator"]

[methods]
"ante_validate@v1" = "Internal"
"ante_write@v1" = "Internal"
"#
        )
    }

    fn handle_service_call(method: String, _params: Vec<u8>) -> Result<Vec<u8>, String> {
        match method.as_str() {
            // Read-only validation phase
            "ante_validate@v1" => {
                let res: Result<(), String> = Ok(());
                Ok(res.encode())
            }
            // State-changing execution phase
            "ante_write@v1" => {
                // Write the 'visited' key to state to signal successful execution
                ioi_contract_sdk::state::set(b"visited", b"1");

                let res: Result<(), String> = Ok(());
                Ok(res.encode())
            }
            _ => Err(alloc::format!("Unknown method: {}", method)),
        }
    }
}
