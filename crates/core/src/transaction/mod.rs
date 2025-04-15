//! Transaction model trait definitions

mod model;
mod utxo;
mod account;

#[cfg(test)]
mod tests;

pub use model::*;
pub use utxo::*;
pub use account::*;
