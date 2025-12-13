// Path: crates/forge/tests/contracts/mock-verifier/src/lib.rs
use wit_bindgen::generate;

generate!({
    // Adjusted path to be relative to the crate root (Cargo.toml location)
    // crates/forge/tests/contracts/mock-verifier -> crates/types/wit/ibc_verifier.wit
    path: "../../../../types/wit/ibc_verifier.wit",
    world: "verifier-module",
});

use exports::ioi::ibc::light_client::Guest;

struct MyVerifier;

impl Guest for MyVerifier {
    fn verify_header(header: Vec<u8>, _trusted: Vec<u8>) -> Result<Vec<u8>, String> {
        // Simple mock logic:
        // In the E2E test, we pass a Header::Ethereum struct.
        // We reject if the byte length is exactly 1 (test signal for failure).
        if header.len() == 1 {
            return Err("Mock verifier rejected invalid header".into());
        }

        // Return dummy new consensus state bytes
        Ok(vec![0x01, 0x02, 0x03])
    }

    fn verify_membership(
        _proof: Vec<u8>,
        _root: Vec<u8>,
        _path: Vec<u8>,
        _value: Vec<u8>,
    ) -> Result<bool, String> {
        Ok(true)
    }

    fn chain_id() -> String {
        "mock-chain-1".to_string()
    }
}

export!(MyVerifier);
