// Path: crates/chain/src/util.rs
//! Utility functions for chain and state management.

use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use depin_sdk_api::state::StateManager;
use serde_json::Value;
use std::fs;

/// Loads the initial state for a state manager from a JSON genesis file.
pub fn load_state_from_genesis_file<S: StateManager + ?Sized>(
    state_manager: &mut S,
    genesis_file_path: &str,
) -> Result<()> {
    log::info!(
        "No state file found. Initializing from genesis '{}'...",
        genesis_file_path
    );
    let genesis_bytes = fs::read(genesis_file_path)?;
    let genesis_json: Value = serde_json::from_slice(&genesis_bytes)?;

    if let Some(genesis_state) = genesis_json
        .get("genesis_state")
        .and_then(|s| s.as_object())
    {
        for (key_str, value) in genesis_state {
            let key_bytes = if let Some(stripped) = key_str.strip_prefix("b64:") {
                BASE64_STANDARD.decode(stripped)?
            } else {
                key_str.as_bytes().to_vec()
            };

            let value_bytes = if let Some(s) = value.as_str().and_then(|s| s.strip_prefix("b64:")) {
                BASE64_STANDARD.decode(s)?
            } else {
                serde_json::to_vec(value)?
            };

            log::info!("  -> Writing genesis key: {}", hex::encode(&key_bytes));
            state_manager.insert(&key_bytes, &value_bytes)?;
        }
        log::info!("Genesis state successfully loaded into state tree.");
    } else {
        log::warn!("'genesis_state' object not found in genesis file. Starting with empty state.");
    }
    Ok(())
}