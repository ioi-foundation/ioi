// Path: crates/services/src/ibc/light_client/mod.rs

//! Contains concrete, chain-specific implementations of the `InterchainVerifier` trait.

pub mod tendermint;

// Define a common error module for all light clients.
pub mod errors {
    use thiserror::Error;

    #[derive(Error, Debug)]
    pub enum IbcError {
        #[error("client state not found for client id {0}")]
        ClientStateNotFound(String),
        #[error("consensus state not found for client id {0} at height {1}")]
        ConsensusStateNotFound(String, u64),
    }

    impl From<IbcError> for depin_sdk_api::error::CoreError {
        fn from(e: IbcError) -> Self {
            Self::Custom(e.to_string())
        }
    }
}
