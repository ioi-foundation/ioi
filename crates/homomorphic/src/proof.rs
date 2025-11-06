// Path: crates/homomorphic/src/proof.rs
use crate::error::{HomomorphicError, HomomorphicResult};
use ioi_api::commitment::HomomorphicCommitmentScheme;
use ioi_api::commitment::HomomorphicOperation;
use ioi_api::commitment::{ProofContext, Selector};
use ioi_api::homomorphic::CommitmentOperation;
use std::fmt::Debug;
use std::marker::PhantomData;

/// Proof that a commitment is the result of a homomorphic operation
#[derive(Debug, Clone)]
pub struct HomomorphicProof<CS: HomomorphicCommitmentScheme> {
    /// Type of operation
    operation_type: HomomorphicOperation,
    /// Input commitments
    inputs: Vec<CS::Commitment>,
    /// Result commitment
    result: CS::Commitment,
    /// Selector used for this proof
    selector: Selector,
    /// Additional data for verification
    auxiliary_data: Vec<u8>,
    /// Phantom data for commitment scheme
    _phantom: PhantomData<CS>,
}

impl<CS: HomomorphicCommitmentScheme> HomomorphicProof<CS> {
    /// Create a new homomorphic proof
    pub fn new(
        operation_type: HomomorphicOperation,
        inputs: Vec<CS::Commitment>,
        result: CS::Commitment,
        selector: Selector,
        auxiliary_data: Vec<u8>,
    ) -> Self {
        Self {
            operation_type,
            inputs,
            result,
            selector,
            auxiliary_data,
            _phantom: PhantomData,
        }
    }

    /// Create a new homomorphic proof with default selector (None)
    pub fn new_simple(
        operation_type: HomomorphicOperation,
        inputs: Vec<CS::Commitment>,
        result: CS::Commitment,
        auxiliary_data: Vec<u8>,
    ) -> Self {
        Self::new(
            operation_type,
            inputs,
            result,
            Selector::None,
            auxiliary_data,
        )
    }

    /// Get the operation type
    pub fn operation_type(&self) -> HomomorphicOperation {
        self.operation_type
    }

    /// Get the input commitments
    pub fn inputs(&self) -> &[CS::Commitment] {
        &self.inputs
    }

    /// Get the result commitment
    pub fn result(&self) -> &CS::Commitment {
        &self.result
    }

    /// Get the selector used for this proof
    pub fn selector(&self) -> &Selector {
        &self.selector
    }

    /// Get the auxiliary data
    pub fn auxiliary_data(&self) -> &[u8] {
        &self.auxiliary_data
    }

    /// Serialize the proof to bytes
    pub fn to_bytes(&self) -> HomomorphicResult<Vec<u8>> {
        let mut result = Vec::new();

        // Serialize operation type
        match self.operation_type {
            HomomorphicOperation::Addition => result.push(1),
            HomomorphicOperation::ScalarMultiplication => result.push(2),
            HomomorphicOperation::Custom(id) => {
                result.push(3);
                result.extend_from_slice(&(id).to_le_bytes());
            }
        }

        // Serialize input count
        result.extend_from_slice(&(self.inputs.len() as u32).to_le_bytes());

        // Serialize inputs
        for input in &self.inputs {
            let bytes = input.as_ref().to_vec();
            result.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            result.extend_from_slice(&bytes);
        }

        // Serialize result
        let result_bytes = self.result.as_ref().to_vec();
        result.extend_from_slice(&(result_bytes.len() as u32).to_le_bytes());
        result.extend_from_slice(&result_bytes);

        // Serialize selector type
        match &self.selector {
            Selector::Position(_) => result.push(1),
            Selector::Key(_) => result.push(2),
            Selector::Predicate(_) => result.push(3),
            Selector::None => result.push(0),
        }

        // Serialize selector data if present
        match &self.selector {
            Selector::Position(pos) => {
                result.extend_from_slice(&pos.to_le_bytes());
            }
            Selector::Key(key) => {
                result.extend_from_slice(&(key.len() as u32).to_le_bytes());
                result.extend_from_slice(key);
            }
            Selector::Predicate(data) => {
                result.extend_from_slice(&(data.len() as u32).to_le_bytes());
                result.extend_from_slice(data);
            }
            Selector::None => {} // No additional data
        }

        // Serialize auxiliary data
        result.extend_from_slice(&(self.auxiliary_data.len() as u32).to_le_bytes());
        result.extend_from_slice(&self.auxiliary_data);

        Ok(result)
    }

    /// Create from bytes
    pub fn from_bytes(_bytes: &[u8]) -> HomomorphicResult<Self>
    where
        CS::Commitment: From<Vec<u8>>,
    {
        Err(HomomorphicError::Custom(
            "Deserialization not implemented".to_string(),
        ))
    }
}

/// Generator for homomorphic proofs
pub struct ProofGenerator<CS: HomomorphicCommitmentScheme> {
    /// Commitment scheme
    scheme: CS,
}

impl<CS: HomomorphicCommitmentScheme> ProofGenerator<CS> {
    /// Create a new proof generator
    pub fn new(scheme: CS) -> Self {
        Self { scheme }
    }

    /// Generate a proof for an add operation
    pub fn prove_add(
        &self,
        a: &CS::Commitment,
        b: &CS::Commitment,
        result: &CS::Commitment,
        selector: &Selector,
    ) -> HomomorphicResult<HomomorphicProof<CS>> {
        // Verify that result = a + b
        let computed_result = self
            .scheme
            .add(a, b)
            .map_err(|e| HomomorphicError::Custom(e.to_string()))?;

        // Check that the computed result matches the provided result
        if computed_result.as_ref() != result.as_ref() {
            return Err(HomomorphicError::VerificationFailure);
        }

        // Create the proof with the specified selector
        Ok(HomomorphicProof::new(
            HomomorphicOperation::Addition,
            vec![a.clone(), b.clone()],
            result.clone(),
            selector.clone(),
            Vec::new(), // No auxiliary data needed for addition
        ))
    }

    /// Generate a proof for a scalar multiply operation
    pub fn prove_scalar_multiply(
        &self,
        a: &CS::Commitment,
        scalar: i32,
        result: &CS::Commitment,
        selector: &Selector,
    ) -> HomomorphicResult<HomomorphicProof<CS>> {
        if scalar <= 0 {
            return Err(HomomorphicError::NegativeScalar);
        }

        // Verify that result = a * scalar
        let computed_result = self
            .scheme
            .scalar_multiply(a, scalar)
            .map_err(|e| HomomorphicError::Custom(e.to_string()))?;

        // Check that the computed result matches the provided result
        if computed_result.as_ref() != result.as_ref() {
            return Err(HomomorphicError::VerificationFailure);
        }

        // Create the proof with scalar in auxiliary data
        let mut auxiliary_data = Vec::new();
        auxiliary_data.extend_from_slice(&scalar.to_le_bytes());

        Ok(HomomorphicProof::new(
            HomomorphicOperation::ScalarMultiplication,
            vec![a.clone()],
            result.clone(),
            selector.clone(),
            auxiliary_data,
        ))
    }

    /// Generate a proof for an operation
    pub fn prove_operation(
        &self,
        operation: &CommitmentOperation,
        result: &CS::Commitment,
    ) -> HomomorphicResult<HomomorphicProof<CS>> {
        // Default to None selector for backward compatibility
        self.prove_operation_with_selector(operation, result, &Selector::None)
    }

    /// Generate a proof for an operation with a specific selector
    pub fn prove_operation_with_selector(
        &self,
        operation: &CommitmentOperation,
        result: &CS::Commitment,
        selector: &Selector,
    ) -> HomomorphicResult<HomomorphicProof<CS>> {
        match operation {
            CommitmentOperation::Add { left, right } => {
                // Downcast inputs
                let a = left.downcast_ref::<CS::Commitment>().ok_or_else(|| {
                    HomomorphicError::InvalidInput(
                        "Left operand is not the correct commitment type".into(),
                    )
                })?;
                let b = right.downcast_ref::<CS::Commitment>().ok_or_else(|| {
                    HomomorphicError::InvalidInput(
                        "Right operand is not the correct commitment type".into(),
                    )
                })?;

                self.prove_add(a, b, result, selector)
            }
            CommitmentOperation::ScalarMultiply { commitment, scalar } => {
                // Downcast input
                let a = commitment.downcast_ref::<CS::Commitment>().ok_or_else(|| {
                    HomomorphicError::InvalidInput("Commitment is not the correct type".into())
                })?;

                self.prove_scalar_multiply(a, *scalar, result, selector)
            }
            CommitmentOperation::Custom { .. } => Err(HomomorphicError::UnsupportedOperation(
                HomomorphicOperation::Custom(0),
            )),
        }
    }

    /// Verify a homomorphic proof
    pub fn verify_proof(&self, proof: &HomomorphicProof<CS>) -> HomomorphicResult<bool> {
        // Use default empty context for backward compatibility
        self.verify_proof_with_context(proof, &ProofContext::default())
    }

    /// Verify a homomorphic proof with context
    pub fn verify_proof_with_context(
        &self,
        proof: &HomomorphicProof<CS>,
        context: &ProofContext,
    ) -> HomomorphicResult<bool> {
        match proof.operation_type() {
            HomomorphicOperation::Addition => {
                if proof.inputs().len() != 2 {
                    return Err(HomomorphicError::InvalidInput(
                        "Addition proof requires exactly 2 inputs".into(),
                    ));
                }

                let a = proof.inputs().get(0).ok_or_else(|| {
                    HomomorphicError::InvalidInput("Missing left operand in proof".into())
                })?;
                let b = proof.inputs().get(1).ok_or_else(|| {
                    HomomorphicError::InvalidInput("Missing right operand in proof".into())
                })?;

                // Compute a + b
                let computed_result = self
                    .scheme
                    .add(a, b)
                    .map_err(|e| HomomorphicError::Custom(e.to_string()))?;

                // Check that computed result matches the proof result
                Ok(computed_result.as_ref() == proof.result().as_ref())
            }
            HomomorphicOperation::ScalarMultiplication => {
                if proof.inputs().len() != 1 {
                    return Err(HomomorphicError::InvalidInput(
                        "Scalar multiplication proof requires exactly 1 input".into(),
                    ));
                }

                let a = proof.inputs().get(0).ok_or_else(|| {
                    HomomorphicError::InvalidInput("Missing commitment in proof".into())
                })?;

                // Extract scalar from auxiliary data
                let scalar_bytes_slice = proof.auxiliary_data().get(0..4).ok_or_else(|| {
                    HomomorphicError::InvalidInput(
                        "Invalid auxiliary data for scalar multiplication".into(),
                    )
                })?;
                let mut scalar_bytes = [0u8; 4];
                scalar_bytes.copy_from_slice(scalar_bytes_slice);
                let scalar = i32::from_le_bytes(scalar_bytes);

                if scalar <= 0 {
                    return Err(HomomorphicError::NegativeScalar);
                }

                // Check the context for any additional verification parameters
                if let Some(precision_data) = context.get_data("precision") {
                    if let Some(&precision) = precision_data.get(0) {
                        // Use precision parameter if provided
                        // This is just an example of how context might be used
                        if precision > 0 {
                            // High precision verification logic would go here
                        }
                    }
                }

                // Compute a * scalar
                let computed_result = self
                    .scheme
                    .scalar_multiply(a, scalar)
                    .map_err(|e| HomomorphicError::Custom(e.to_string()))?;

                // Check that computed result matches the proof result
                Ok(computed_result.as_ref() == proof.result().as_ref())
            }
            HomomorphicOperation::Custom(_) => Err(HomomorphicError::UnsupportedOperation(
                proof.operation_type(),
            )),
        }
    }
}
