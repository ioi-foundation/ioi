// Path: crates/validator/src/standard/orchestration/verifier_select.rs

//! Selects the correct default proof verifier based on compile-time features.
//! This ensures that the Orchestration container always uses a verifier
//! that matches the state tree implementation of the Workload container.

use cfg_if::cfg_if;

// Only bring KZGParams into scope when the corresponding feature is enabled.
#[cfg(feature = "commitment-kzg")]
use ioi_state::primitives::kzg::KZGParams;

// --- Define the Verifier Type Alias based on tree features using cfg_if ---
// This creates a mutually exclusive if/else-if/else block, guaranteeing that
// `DefaultVerifier` is only defined once, even when multiple features are enabled.
cfg_if! {
    if #[cfg(feature = "state-iavl")] {
        pub use ioi_state::tree::iavl::verifier::IAVLHashVerifier as DefaultVerifier;
    } else if #[cfg(feature = "state-sparse-merkle")] {
        pub use ioi_state::tree::sparse_merkle::verifier::SparseMerkleVerifier as DefaultVerifier;
    } else if #[cfg(feature = "state-verkle")] {
        pub use ioi_state::tree::verkle::verifier::KZGVerifier as DefaultVerifier;
    } else if #[cfg(feature = "state-jellyfish")] {
        // [NEW] Wire up Jellyfish Verifier
        pub use ioi_state::tree::jellyfish::verifier::JellyfishVerifier as DefaultVerifier;
    } else {
        // Fallback for when no tree feature is enabled, preventing compile errors in those cases.
        // A runtime check in the binary will catch this misconfiguration.
        pub use self::fallback::DefaultVerifier;
    }
}

/// Creates the default verifier. The signature and implementation of this function
/// adapt based on whether a KZG-based primitive is enabled.
pub fn create_default_verifier(
    #[cfg(feature = "commitment-kzg")]
    #[allow(unused_variables)] // [FIX] Allow unused for when other trees are selected
    params: Option<KZGParams>,
    #[cfg(not(feature = "commitment-kzg"))] _params: Option<()>,
) -> DefaultVerifier {
    // THIS IS THE FIX: The logic inside this function now exactly mirrors the
    // structure of the type alias block above, ensuring consistency.
    cfg_if! {
        if #[cfg(feature = "state-iavl")] {
            // In this branch, DefaultVerifier IS IAVLHashVerifier.
            // IAVLHashVerifier is a simple struct with no `::new()` method.
            DefaultVerifier
        } else if #[cfg(feature = "state-sparse-merkle")] {
            // In this branch, DefaultVerifier IS SparseMerkleVerifier.
            // Also a simple struct.
            DefaultVerifier
        } else if #[cfg(feature = "state-verkle")] {
            // This branch is only taken if the above are false.
            // DefaultVerifier IS KZGVerifier, which requires `::new(params)`.
            DefaultVerifier::new(params.expect("KZGVerifier requires SRS parameters"))
        } else if #[cfg(feature = "state-jellyfish")] {
            // [NEW] DefaultVerifier IS JellyfishVerifier (simple struct).
            DefaultVerifier
        } else {
            // Fallback branch for the dummy verifier.
            DefaultVerifier
        }
    }
}

// Fallback module for when no tree features are enabled.
// This allows the codebase to compile, while a runtime check in `main.rs`
// will provide a clear error message to the user.
#[cfg(not(any(
    feature = "state-iavl",
    feature = "state-sparse-merkle",
    feature = "state-verkle",
    feature = "state-jellyfish"
)))]
mod fallback {
    use ioi_api::error::StateError;
    use ioi_api::state::Verifier;
    use ioi_types::app::Membership;
    use ioi_types::error::ProofError;
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
