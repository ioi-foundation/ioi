// Path: crates/homomorphic/src/computation/mod.rs
use crate::error::HomomorphicResult;
use crate::operations::{
    execute_add, execute_custom, execute_scalar_multiply, CustomOperationRegistry,
};
use crate::operations::{execute_batch, execute_composite, BatchResult, CompositeOperation};
use crate::proof::{HomomorphicProof, ProofGenerator};
use ioi_api::commitment::{HomomorphicCommitmentScheme, ProofContext, Selector};
use ioi_api::homomorphic::{CommitmentOperation, OperationResult};
use std::sync::Arc;

/// Computation engine for homomorphic operations
pub struct HomomorphicComputation<CS: HomomorphicCommitmentScheme> {
    /// Commitment scheme
    scheme: CS,
    /// Custom operation registry
    registry: Arc<CustomOperationRegistry>,
    /// Proof generator
    proof_generator: ProofGenerator<CS>,
}

impl<CS: HomomorphicCommitmentScheme + Clone> HomomorphicComputation<CS> {
    /// Create a new computation engine with the given scheme
    pub fn new(scheme: CS) -> Self {
        let registry = Arc::new(CustomOperationRegistry::new());
        let proof_generator = ProofGenerator::new(scheme.clone());

        Self {
            scheme,
            registry,
            proof_generator,
        }
    }

    /// Execute an operation
    pub fn execute(&self, operation: &CommitmentOperation) -> OperationResult {
        match operation {
            CommitmentOperation::Add { .. } => execute_add(&self.scheme, operation),
            CommitmentOperation::ScalarMultiply { .. } => {
                execute_scalar_multiply(&self.scheme, operation)
            }
            CommitmentOperation::Custom { .. } => execute_custom(&self.registry, operation),
        }
    }

    /// Execute a batch of operations
    pub fn execute_batch(&self, operations: &[CommitmentOperation]) -> BatchResult {
        execute_batch(operations, |op| self.execute(op))
    }

    /// Execute a composite operation
    pub fn execute_composite(
        &self,
        operation: &CompositeOperation,
    ) -> HomomorphicResult<OperationResult> {
        execute_composite(operation, |op| self.execute(op))
    }

    /// Get the custom operation registry
    pub fn registry(&self) -> Arc<CustomOperationRegistry> {
        self.registry.clone()
    }

    /// Get the underlying commitment scheme
    pub fn scheme(&self) -> &CS {
        &self.scheme
    }

    /// Create a proof for an operation
    pub fn create_proof(
        &self,
        operation: &CommitmentOperation,
        result: &CS::Commitment,
    ) -> HomomorphicResult<HomomorphicProof<CS>> {
        // Default to None selector for simple proofs
        self.create_proof_with_selector(operation, result, &Selector::None)
    }

    /// Create a proof for an operation with a specific selector
    pub fn create_proof_with_selector(
        &self,
        operation: &CommitmentOperation,
        result: &CS::Commitment,
        selector: &Selector,
    ) -> HomomorphicResult<HomomorphicProof<CS>> {
        self.proof_generator
            .prove_operation_with_selector(operation, result, selector)
    }

    /// Create a proof for an operation with a position selector
    pub fn create_proof_at_position(
        &self,
        operation: &CommitmentOperation,
        result: &CS::Commitment,
        position: u64, // FIX: Changed from usize to u64
    ) -> HomomorphicResult<HomomorphicProof<CS>> {
        self.create_proof_with_selector(operation, result, &Selector::Position(position))
    }

    /// Create a proof for an operation with a key selector
    pub fn create_proof_for_key(
        &self,
        operation: &CommitmentOperation,
        result: &CS::Commitment,
        key: &[u8],
    ) -> HomomorphicResult<HomomorphicProof<CS>> {
        self.create_proof_with_selector(operation, result, &Selector::Key(key.to_vec()))
    }

    /// Verify a homomorphic proof
    pub fn verify_proof(&self, proof: &HomomorphicProof<CS>) -> HomomorphicResult<bool> {
        // Use default empty context for simple verification
        self.verify_proof_with_context(proof, &ProofContext::default())
    }

    /// Verify a homomorphic proof with context
    pub fn verify_proof_with_context(
        &self,
        proof: &HomomorphicProof<CS>,
        context: &ProofContext,
    ) -> HomomorphicResult<bool> {
        self.proof_generator
            .verify_proof_with_context(proof, context)
    }

    /// Apply an operation and create a proof with a specific selector
    pub fn apply_and_prove(
        &self,
        operation: &CommitmentOperation,
        selector: &Selector,
    ) -> HomomorphicResult<(CS::Commitment, HomomorphicProof<CS>)> {
        // Execute the operation
        let result = match self.execute(operation) {
            OperationResult::Success(result_arc) => {
                match result_arc.downcast_ref::<CS::Commitment>() {
                    Some(commitment) => commitment.clone(),
                    None => {
                        return Err(crate::error::HomomorphicError::InvalidInput(
                            "Operation result is not the correct commitment type".into(),
                        ))
                    }
                }
            }
            OperationResult::Failure(err) => {
                return Err(crate::error::HomomorphicError::Custom(err))
            }
            OperationResult::Unsupported => {
                return Err(crate::error::HomomorphicError::UnsupportedOperation(
                    ioi_api::commitment::HomomorphicOperation::Custom(0),
                ))
            }
        };

        // Create proof for the operation
        let proof = self.create_proof_with_selector(operation, &result, selector)?;

        Ok((result, proof))
    }

    /// Apply a batch of operations and create proofs with specified selectors
    pub fn apply_batch_and_prove(
        &self,
        operations: &[(CommitmentOperation, Selector)],
    ) -> HomomorphicResult<Vec<(CS::Commitment, HomomorphicProof<CS>)>> {
        let mut results = Vec::with_capacity(operations.len());

        for (operation, selector) in operations {
            let (commitment, proof) = self.apply_and_prove(operation, selector)?;
            results.push((commitment, proof));
        }

        Ok(results)
    }
}

#[cfg(test)]
mod tests;
