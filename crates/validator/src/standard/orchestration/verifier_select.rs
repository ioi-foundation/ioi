// Path: crates/validator/src/standard/orchestration/verifier_select.rs

//! Selects the correct default proof verifier based on compile-time features.
//! This ensures that the Orchestration container always uses a verifier
//! that matches the state tree implementation of the Workload container.

// Only bring KZGParams into scope when the corresponding feature is enabled.
#[cfg(feature = "primitive-kzg")]
use depin_sdk_commitment::primitives::kzg::KZGParams;

// --- Define the Verifier Type Alias based on tree features ---

#[cfg(feature = "tree-file")]
pub use depin_sdk_commitment::tree::file::verifier::FileTreeHashVerifier as DefaultVerifier;

#[cfg(feature = "tree-hashmap")]
pub use depin_sdk_commitment::tree::hashmap::verifier::HashMapTreeHashVerifier as DefaultVerifier;

#[cfg(feature = "tree-iavl")]
pub use depin_sdk_commitment::tree::iavl::verifier::IAVLHashVerifier as DefaultVerifier;

#[cfg(feature = "tree-sparse-merkle")]
pub use depin_sdk_commitment::tree::sparse_merkle::verifier::SparseMerkleVerifier as DefaultVerifier;

#[cfg(feature = "tree-verkle")]
pub use depin_sdk_commitment::tree::verkle::verifier::KZGVerifier as DefaultVerifier;

// --- Define the creator function with a single, adaptable signature ---

// Conditionally define a type alias for the function parameter. This allows
// the function signature to change based on features, which is key to solving the issue.
#[cfg(feature = "primitive-kzg")]
type VerifierParams = Option<KZGParams>;
#[cfg(not(feature = "primitive-kzg"))]
type VerifierParams = Option<()>;

/// Creates the default verifier. The signature and implementation of this function
/// adapt based on whether a KZG-based primitive is enabled.
pub fn create_default_verifier(params: VerifierParams) -> DefaultVerifier {
    // The logic *inside* the function is conditionally compiled.
    #[cfg(feature = "tree-verkle")]
    {
        // This arm is only compiled when tree-verkle (and thus primitive-kzg) is active.
        // Here, `params` is guaranteed to be `Option<KZGParams>`.
        DefaultVerifier::new(params.expect("KZGVerifier requires SRS parameters"))
    }

    #[cfg(not(feature = "tree-verkle"))]
    {
        // This arm is compiled for all other tree types.
        // Here, `params` is `Option<()>` and is ignored.
        let _ = params; // Explicitly ignore the parameter to prevent unused variable warnings.
        DefaultVerifier::default()
    }
}

// Fallback for when no tree features are enabled.
#[cfg(not(any(
    feature = "tree-file",
    feature = "tree-hashmap",
    feature = "tree-iavl",
    feature = "tree-sparse-merkle",
    feature = "tree-verkle"
)))]
mod fallback {
    use depin_sdk_api::error::StateError;
    use depin_sdk_api::state::Verifier;
    use depin_sdk_types::app::Membership;

    #[derive(Clone, Debug, Default)]
    pub struct DefaultVerifier;

    #[derive(Clone, Debug, serde::Deserialize)]
    pub struct DummyCommitment;
    #[derive(Clone, Debug, serde::Deserialize)]
    pub struct DummyProof;

    impl Verifier for DefaultVerifier {
        type Commitment = DummyCommitment;
        type Proof = DummyProof;
        fn commitment_from_bytes(&self, _bytes: &[u8]) -> Result<Self::Commitment, StateError> {
            unimplemented!("No state tree feature is enabled.")
        }
        fn verify(
            &self,
            _r: &Self::Commitment,
            _p: &Self::Proof,
            _k: &[u8],
            _o: &Membership,
        ) -> bool {
            unimplemented!("No state tree feature is enabled.")
        }
    }
}
