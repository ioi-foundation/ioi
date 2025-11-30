// Path: crates/forge/tests/contracts/counter/src/lib.rs
#![no_std]
extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use ioi_contract_sdk::{ioi_contract, IoiService};

// -----------------------------------------------------------------------------
// Contract implementation
// -----------------------------------------------------------------------------

struct CounterContract;

// Key under which we store the counter value.
const COUNTER_KEY: &[u8] = b"counter_value";

// The #[ioi_contract] macro automatically injects:
// 1. The global allocator (BumpAllocator)
// 2. The panic handler
// 3. The `cabi_realloc` export required by the Component Model
// 4. The `impl Guest` bridge code
// 5. The `export!` macro call
#[ioi_contract]
impl IoiService for CounterContract {
    fn id() -> String {
        "counter".to_string()
    }

    fn abi_version() -> u32 {
        1
    }

    fn state_schema() -> String {
        "v1".to_string()
    }

    fn manifest() -> String {
        // The current e2e test doesn’t inspect this.
        String::new()
    }

    fn handle_service_call(method: String, params: Vec<u8>) -> Result<Vec<u8>, String> {
        // Runtime entrypoint: method is usually "call".
        // e2e test encodes operation in params[0]:
        //   0 => get
        //   1 => increment
        if method == "call" && !params.is_empty() {
            return match params[0] {
                0 => {
                    // Get
                    let val_bytes = ioi_contract_sdk::state::get(COUNTER_KEY).unwrap_or(vec![0]);
                    Ok(val_bytes)
                }
                1 => {
                    // Increment
                    let val_bytes = ioi_contract_sdk::state::get(COUNTER_KEY).unwrap_or(vec![0]);
                    let mut val = val_bytes.first().copied().unwrap_or(0);

                    val = val.wrapping_add(1);

                    ioi_contract_sdk::state::set(COUNTER_KEY, &[val]);
                    Ok(vec![val])
                }
                _ => Err("Unknown opcode".to_string()),
            };
        }

        // Optional: string-based methods for future use.
        match method.as_str() {
            "get@v1" => {
                let val_bytes = ioi_contract_sdk::state::get(COUNTER_KEY).unwrap_or(vec![0]);
                Ok(val_bytes)
            }
            "increment@v1" => {
                let val_bytes = ioi_contract_sdk::state::get(COUNTER_KEY).unwrap_or(vec![0]);
                let mut val = val_bytes.first().copied().unwrap_or(0);
                val = val.wrapping_add(1);
                ioi_contract_sdk::state::set(COUNTER_KEY, &[val]);
                Ok(vec![val])
            }
            _ => Err("Unknown method".to_string()),
        }
    }

    // upgrade methods use default implementations from IoiService trait
}
