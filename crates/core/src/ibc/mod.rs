//! Inter-Blockchain Communication interface definitions

mod proof;
mod translator;
mod light_client;

#[cfg(test)]
mod tests;

pub use proof::*;
pub use translator::*;
pub use light_client::*;
