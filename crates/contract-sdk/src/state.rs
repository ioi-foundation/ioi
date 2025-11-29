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
