// Path: crates/state/src/tree/jellyfish/mod.rs
pub mod nibble;
pub mod node;
pub mod tree;
pub mod verifier; // [NEW] Export verifier

pub use tree::JellyfishMerkleTree;
