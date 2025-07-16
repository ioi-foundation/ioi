//! Tests for the commitment scheme traits

#[cfg(test)]
mod tests {
    use crate::commitment::{
        CommitmentScheme, HomomorphicCommitmentScheme, HomomorphicOperation, ProofContext,
        SchemeIdentifier, Selector,
    };

    // Define a mock commitment scheme for testing
    #[derive(Debug)]
    struct MockCommitmentScheme;

    #[derive(Debug, Clone)]
    struct MockCommitment(Vec<u8>);

    impl AsRef<[u8]> for MockCommitment {
        fn as_ref(&self) -> &[u8] {
            &self.0
        }
    }

    #[derive(Clone)]
    struct MockProof(Vec<u8>);

    impl CommitmentScheme for MockCommitmentScheme {
        type Commitment = MockCommitment;
        type Proof = MockProof;
        type Value = Vec<u8>; // Added missing Value associated type

        fn commit(&self, values: &[Option<Self::Value>]) -> Self::Commitment {
            // Simple mock implementation for testing
            let combined: Vec<u8> = values
                .iter()
                .flat_map(|v| v.clone().unwrap_or_default())
                .collect();
            MockCommitment(combined)
        }

        fn create_proof(
            &self,
            selector: &Selector,
            value: &Self::Value,
        ) -> Result<Self::Proof, String> {
            // Simple mock implementation for testing
            Ok(MockProof(value.clone()))
        }

        fn verify(
            &self,
            _commitment: &Self::Commitment,
            proof: &Self::Proof,
            _selector: &Selector,
            value: &Self::Value,
            _context: &ProofContext, // Added context parameter
        ) -> bool {
            // Simple mock implementation for testing
            proof.0 == *value
        }

        fn scheme_id() -> SchemeIdentifier {
            SchemeIdentifier::new("mock")
        }
    }

    #[derive(Debug)]
    struct MockHomomorphicCommitmentScheme;

    impl CommitmentScheme for MockHomomorphicCommitmentScheme {
        type Commitment = MockCommitment;
        type Proof = MockProof;
        type Value = Vec<u8>; // Added missing Value associated type

        fn commit(&self, values: &[Option<Self::Value>]) -> Self::Commitment {
            // Simple mock implementation for testing
            let combined: Vec<u8> = values
                .iter()
                .flat_map(|v| v.clone().unwrap_or_default())
                .collect();
            MockCommitment(combined)
        }

        fn create_proof(
            &self,
            selector: &Selector,
            value: &Self::Value,
        ) -> Result<Self::Proof, String> {
            // Simple mock implementation for testing
            Ok(MockProof(value.clone()))
        }

        fn verify(
            &self,
            _commitment: &Self::Commitment,
            proof: &Self::Proof,
            _selector: &Selector,
            value: &Self::Value,
            _context: &ProofContext, // Added context parameter
        ) -> bool {
            // Simple mock implementation for testing
            proof.0 == *value
        }

        fn scheme_id() -> SchemeIdentifier {
            SchemeIdentifier::new("mock-homomorphic")
        }
    }

    impl HomomorphicCommitmentScheme for MockHomomorphicCommitmentScheme {
        fn add(
            &self,
            a: &Self::Commitment,
            b: &Self::Commitment,
        ) -> Result<Self::Commitment, String> {
            // Simple mock implementation for testing
            let mut result = a.0.clone();
            result.extend_from_slice(&b.0);
            Ok(MockCommitment(result))
        }

        fn scalar_multiply(
            &self,
            a: &Self::Commitment,
            scalar: i32,
        ) -> Result<Self::Commitment, String> {
            // Simple mock implementation for testing
            if scalar <= 0 {
                return Err("Scalar must be positive".to_string());
            }

            let mut result = Vec::new();
            for _ in 0..scalar {
                result.extend_from_slice(a.as_ref());
            }

            Ok(MockCommitment(result))
        }

        fn supports_operation(&self, operation: HomomorphicOperation) -> bool {
            // Simple mock implementation for testing
            match operation {
                HomomorphicOperation::Addition | HomomorphicOperation::ScalarMultiplication => true,
                HomomorphicOperation::Custom(_) => false,
            }
        }
    }

    #[test]
    fn test_commitment_scheme() {
        let scheme = MockCommitmentScheme;

        // Test commit
        let values = vec![Some(vec![1, 2, 3]), Some(vec![4, 5, 6])];
        let commitment = scheme.commit(&values);

        // Test create_proof
        let proof = scheme
            .create_proof(&Selector::Position(0), &vec![1, 2, 3])
            .unwrap();

        // Test verify
        let context = ProofContext::default();
        assert!(scheme.verify(
            &commitment,
            &proof,
            &Selector::Position(0),
            &vec![1, 2, 3],
            &context
        ));
        assert!(!scheme.verify(
            &commitment,
            &proof,
            &Selector::Position(0),
            &vec![7, 8, 9],
            &context
        ));

        // Test scheme_id
        assert_eq!(MockCommitmentScheme::scheme_id().0, "mock");
    }

    #[test]
    fn test_homomorphic_commitment_scheme() {
        let scheme = MockHomomorphicCommitmentScheme;

        // Test commit
        let values1 = vec![Some(vec![1, 2, 3])];
        let values2 = vec![Some(vec![4, 5, 6])];
        let commitment1 = scheme.commit(&values1);
        let commitment2 = scheme.commit(&values2);

        // Test add
        let sum = scheme.add(&commitment1, &commitment2).unwrap();
        assert_eq!(sum.0, vec![1, 2, 3, 4, 5, 6]);

        // Test scalar_multiply
        let product = scheme.scalar_multiply(&commitment1, 3).unwrap();
        assert_eq!(product.0, vec![1, 2, 3, 1, 2, 3, 1, 2, 3]);

        // Test supports_operation
        assert!(scheme.supports_operation(HomomorphicOperation::Addition));
        assert!(scheme.supports_operation(HomomorphicOperation::ScalarMultiplication));
        assert!(!scheme.supports_operation(HomomorphicOperation::Custom(42)));
    }
}
