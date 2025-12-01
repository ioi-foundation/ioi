// Path: crates/contract-sdk/src/state.rs
use crate::bindings::ioi::system::state;
use alloc::vec::Vec;

pub fn get(key: &[u8]) -> Option<Vec<u8>> {
    match state::get(key) {
        Ok(Some(v)) => Some(v),
        _ => None,
    }
}

pub fn set(key: &[u8], value: &[u8]) {
    let _ = state::set(key, value);
}

pub fn delete(key: &[u8]) {
    let _ = state::delete(key);
}

/// Scans the state for keys matching the given prefix.
pub fn prefix_scan(prefix: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
    match state::prefix_scan(prefix) {
        Ok(results) => results,
        Err(_) => Vec::new(), // Return empty on error for simplicity, or panic
    }
}
