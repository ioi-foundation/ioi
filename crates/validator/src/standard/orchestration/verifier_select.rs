// Path: crates/validator/src/standard/orchestration/verifier_select.rs

//! Selects the correct default proof verifier based on compile-time features.
//! This ensures that the Orchestration container always uses a verifier
//! that matches the state tree implementation of the Workload container.

#[cfg(feature = "primitive-kzg")]
use depin_sdk_commitment::primitives::kzg::KZGParams;

#[cfg(feature = "tree-file")]
pub use depin_sdk_commitment::tree::file::verifier::FileTreeHashVerifier as DefaultVerifier;
#[cfg(feature = "tree-file")]
pub fn create_default_verifier(_params: Option<KZGParams>) -> DefaultVerifier {
    DefaultVerifier::default()
}

#[cfg(feature = "tree-hashmap")]
pub use depin_sdk_commitment::tree::hashmap::verifier::HashMapTreeHashVerifier as DefaultVerifier;
#[cfg(feature = "tree-hashmap")]
pub fn create_default_verifier(_params: Option<KZGParams>) -> DefaultVerifier {
    DefaultVerifier::default()
}

#[cfg(feature = "tree-iavl")]
pub use depin_sdk_commitment::tree::iavl::verifier::IAVLHashVerifier as DefaultVerifier;
#[cfg(feature = "tree-iavl")]
pub fn create_default_verifier(_params: Option<KZGParams>) -> DefaultVerifier {
    DefaultVerifier::default()
}

#[cfg(feature = "tree-sparse-merkle")]
pub use depin_sdk_commitment::tree::sparse_merkle::verifier::SparseMerkleVerifier as DefaultVerifier;
#[cfg(feature = "tree-sparse-merkle")]
pub fn create_default_verifier(_params: Option<KZGParams>) -> DefaultVerifier {
    DefaultVerifier::default()
}

#[cfg(feature = "tree-verkle")]
pub use depin_sdk_commitment::tree::verkle::verifier::KZGVerifier as DefaultVerifier;
#[cfg(feature = "tree-verkle")]
pub fn create_default_verifier(params: Option<KZGParams>) -> DefaultVerifier {
    DefaultVerifier::new(params.expect("KZGVerifier requires SRS parameters"))
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

#[cfg(not(any(
    feature = "tree-file",
    feature = "tree-hashmap",
    feature = "tree-iavl",
    feature = "tree-sparse-merkle",
    feature = "tree-verkle"
)))]
pub use fallback::DefaultVerifier;
#[cfg(not(any(
    feature = "tree-file",
    feature = "tree-hashmap",
    feature = "tree-iavl",
    feature = "tree-sparse-merkle",
    feature = "tree-verkle"
)))]
pub fn create_default_verifier(_params: Option<KZGParams>) -> DefaultVerifier {
    DefaultVerifier::default()
}
