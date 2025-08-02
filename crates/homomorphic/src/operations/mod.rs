// Path: crates/homomorphic/src/operations/mod.rs
//! Operation implementations on commitments

mod add;
mod batch;
mod custom;
mod scalar_multiply;

#[cfg(test)]
mod tests;

// Use explicit imports instead of glob imports to avoid ambiguity
pub use add::{add, execute_add};
pub use batch::{execute_batch, execute_composite, BatchResult, CompositeOperation};
pub use custom::{execute_custom, CustomOperationHandler, CustomOperationRegistry};
pub use scalar_multiply::{execute_scalar_multiply, scalar_multiply};
