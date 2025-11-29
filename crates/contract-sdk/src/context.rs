// Path: crates/contract-sdk/src/context.rs
use crate::bindings::ioi::system::context;
use alloc::vec::Vec;

pub fn sender() -> Vec<u8> {
    context::get_caller()
}

pub fn block_height() -> u64 {
    context::block_height()
}
