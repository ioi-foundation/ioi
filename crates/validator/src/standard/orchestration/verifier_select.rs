// Path: crates/validator/src/standard/orchestration/verifier_select.rs

//! Selects the correct default proof verifier based on compile-time features.
//! This ensures that the Orchestration container always uses a verifier
//! that matches the state tree implementation of the Workload container.

use cfg_if::cfg_if;

// Only bring KZGParams into scope when the corresponding feature is enabled.
#[cfg(feature = "primitive-kzg")]
use depin_sdk_commitment::primitives::kzg::KZGParams;

// --- Define the Verifier Type Alias based on tree features using cfg_if ---
// This creates a mutually exclusive if/else-if/else block, guaranteeing that
// `DefaultVerifier` is only defined once, even when multiple features are enabled.
cfg_if! {
    if #[cfg(feature = "tree-iavl")] {
        pub use depin_sdk_commitment::tree::iavl::verifier::IAVLHashVerifier as DefaultVerifier;
    } else if #[cfg(feature = "tree-sparse-merkle")] {
        pub use depin_sdk_commitment::tree::sparse_merkle::verifier::SparseMerkleVerifier as DefaultVerifier;
    } else if #[cfg(feature = "tree-verkle")] {
        pub use depin_sdk_commitment::tree::verkle::verifier::KZGVerifier as DefaultVerifier;
    } else {
        // Fallback for when no tree feature is enabled, preventing compile errors in those cases.
        // A runtime check in the binary will catch this misconfiguration.
        pub use self::fallback::DefaultVerifier;
    }
}

/// Creates the default verifier. The signature and implementation of this function
/// adapt based on whether a KZG-based primitive is enabled.
pub fn create_default_verifier(
    #[cfg(feature = "primitive-kzg")] params: Option<KZGParams>,
    #[cfg(not(feature = "primitive-kzg"))] _params: Option<()>,
) -> DefaultVerifier {
    // The logic inside the function is conditionally compiled to match the type alias.
    cfg_if! {
        if #[cfg(feature = "tree-verkle")] {
            // This arm is only compiled when tree-verkle (and thus primitive-kzg) is active.
            // Here, `params` is guaranteed to be `Option<KZGParams>`.
            DefaultVerifier::new(params.expect("KZGVerifier requires SRS parameters"))
        } else {
            // This arm is compiled for all other tree types (IAVL, SMT) and the fallback.
            // Here, `params` is `Option<()>` and is ignored. The verifiers are unit structs.
            DefaultVerifier
        }
    }
}

// Fallback module for when no tree features are enabled.
// This allows the codebase to compile, while a runtime check in `main.rs`
// will provide a clear error message to the user.
#[cfg(not(any(
    feature = "tree-iavl",
    feature = "tree-sparse-merkle",
    feature = "tree-verkle"
)))]
mod fallback {
    use depin_sdk_api::error::StateError;
    use depin_sdk_api::state::Verifier;
    use depin_sdk_types::app::Membership;
    use depin_sdk_types::error::ProofError;
    use parity_scale_codec::{Decode, Encode};

    /// A fallback `Verifier` implementation that always fails.
    /// This is used to allow compilation when no state tree feature is enabled,
    /// while ensuring any runtime usage will result in a clear error.
    #[derive(Clone, Debug, Default)]
    pub struct DefaultVerifier;

    /// A dummy commitment type for the fallback verifier.
    #[derive(Clone, Debug, serde::Deserialize, Encode, Decode)]
    pub struct DummyCommitment;
    /// A dummy proof type for the fallback verifier.
    #[derive(Clone, Debug, serde::Deserialize, Encode, Decode)]
    pub struct DummyProof;

    impl AsRef<[u8]> for DummyProof {
        fn as_ref(&self) -> &[u8] {
            &[]
        }
    }
    impl From<Vec<u8>> for DummyCommitment {
        fn from(_v: Vec<u8>) -> Self {
            Self
        }
    }

    impl Verifier for DefaultVerifier {
        type Commitment = DummyCommitment;
        type Proof = DummyProof;
        fn commitment_from_bytes(&self, _bytes: &[u8]) -> Result<Self::Commitment, StateError> {
            Err(StateError::Validation(
                "No state tree feature is enabled.".to_string(),
            ))
        }
        fn verify(
            &self,
            _r: &Self::Commitment,
            _p: &Self::Proof,
            _k: &[u8],
            _o: &Membership,
        ) -> Result<(), ProofError> {
            Err(ProofError::InvalidExistence(
                "No state tree feature is enabled.".to_string(),
            ))
        }
    }
}
