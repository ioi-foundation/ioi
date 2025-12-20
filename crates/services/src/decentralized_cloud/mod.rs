use ioi_api::{impl_service_base, services::BlockchainService, state::StateAccess};
use ioi_crypto::algorithms::hash::sha256;
use ioi_types::{app::ChainTransaction, codec, error::TransactionError, keys::active_service_key};

pub struct DecentralizedCloudService;
impl_service_base!(DecentralizedCloudService, "decentralized_cloud");

impl BlockchainService for DecentralizedCloudService {
    async fn handle_service_call(
        &self,
        state: &mut dyn StateAccess,
        method: &str,
        params: &[u8],
        ctx: &mut ioi_api::transaction::context::TxContext<'_>,
    ) -> Result<(), TransactionError> {
        match method {
            // --- Phase 1: Request (Policy Router) ---
            "request_compute@v1" => {
                let req: HardwareSpecs = codec::from_bytes_canonical(params)?;

                // 1. Enforce Economic Policy (Escrow)
                // Call GasEscrow to lock 'req.max_bid' funds from ctx.signer_account_id

                // 2. Generate Ticket
                let id = self.next_id(state)?;
                let ticket = JobTicket {
                    request_id: id,
                    owner: ctx.signer_account_id,
                    specs: req,
                    max_bid: 1000,                         // simplified
                    expiry_height: ctx.block_height + 600, // ~1 hour timeout
                    security_tier: 1,
                    nonce: 0,
                };

                // 3. Commit to State (Pending)
                let key = format!("tickets::{}", id).into_bytes();
                state.insert(&key, &codec::to_bytes_canonical(&ticket)?)?;

                // 4. Emit Event (for Solvers to see)
                // "ComputeRequested: ID=123, Type=GPU-H100"
                Ok(())
            }

            // --- Phase 3: Settlement (Deterministic Verifier) ---
            "finalize_provisioning@v1" => {
                let receipt: ProvisioningReceipt = codec::from_bytes_canonical(params)?;

                // 1. Load Ticket
                let key = format!("tickets::{}", receipt.request_id).into_bytes();
                let ticket_bytes = state.get(&key)?.ok_or(TransactionError::Invalid(
                    "Ticket not found or expired".into(),
                ))?;
                let ticket: JobTicket = codec::from_bytes_canonical(&ticket_bytes)?;

                // 2. Verify Ticket Binding
                // Reconstruct the root the provider SHOULD have signed
                let canonical_ticket = codec::to_bytes_canonical(&ticket)?;
                let expected_root = sha256(&canonical_ticket)
                    .map_err(|e| TransactionError::Invalid(e.to_string()))?;

                if receipt.ticket_root.as_slice() != expected_root.as_ref() {
                    return Err(TransactionError::Invalid("Receipt root mismatch".into()));
                }

                // 3. Verify Provider Signature
                // Load provider's public key from registry
                let provider_key = self.get_provider_key(state, &receipt.provider_id)?;

                // Construct the payload the provider signed: (Root || MachineID || URI)
                let mut sign_payload = Vec::new();
                sign_payload.extend_from_slice(&receipt.ticket_root);
                sign_payload.extend_from_slice(receipt.machine_id.as_bytes());
                sign_payload.extend_from_slice(receipt.endpoint_uri.as_bytes());

                // Cryptographic Check
                // (Assuming Ed25519 for simplicity here, would use ioi_crypto)
                verify_signature(&provider_key, &sign_payload, &receipt.provider_signature)?;

                // 4. Settle
                // - Unlock Escrow -> Pay Provider
                // - Pay "Solver Bounty" to ctx.signer_account_id (The one who submitted this tx)
                // - Remove Ticket (Transition to Active/History)
                state.delete(&key)?;

                Ok(())
            }

            // --- Failure Case ---
            "expire_request@v1" => {
                let id_bytes: [u8; 8] = codec::from_bytes_canonical(params)?;
                let id = u64::from_le_bytes(id_bytes);
                let key = format!("tickets::{}", id).into_bytes();

                let ticket_bytes = state
                    .get(&key)?
                    .ok_or(TransactionError::Invalid("Not found".into()))?;
                let ticket: JobTicket = codec::from_bytes_canonical(&ticket_bytes)?;

                if ctx.block_height <= ticket.expiry_height {
                    return Err(TransactionError::Invalid("Not yet expired".into()));
                }

                // Refund User
                state.delete(&key)?;
                Ok(())
            }

            _ => Err(TransactionError::Unsupported(method.into())),
        }
    }
}
