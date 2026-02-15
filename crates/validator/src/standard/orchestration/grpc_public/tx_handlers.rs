use super::*;
use ioi_ipc::public::{SubmissionStatus, TxStatus};
use std::time::Instant;

impl<CS, ST, CE, V> PublicApiImpl<CS, ST, CE, V>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug
        + Clone,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
    CE: ioi_api::consensus::ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
    V: ioi_api::state::Verifier<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug,
    <CS as CommitmentScheme>::Proof: Serialize
        + for<'de> serde::Deserialize<'de>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug
        + Encode
        + Decode,
{
    pub(super) async fn handle_submit_transaction(
        &self,
        request: Request<SubmitTransactionRequest>,
    ) -> Result<Response<SubmitTransactionResponse>, Status> {
        let start = Instant::now();
        let req = request.into_inner();
        let tx_bytes = req.transaction_bytes;

        let tx_hash_bytes = ioi_crypto::algorithms::hash::sha256(&tx_bytes)
            .map_err(|e| Status::invalid_argument(format!("Hashing failed: {}", e)))?;
        let tx_hash_hex = hex::encode(tx_hash_bytes);

        {
            let ctx_arc = self.get_context().await?;
            let ctx = ctx_arc.lock().await;
            let mut cache = ctx.tx_status_cache.lock().await;
            cache.put(
                tx_hash_hex.clone(),
                TxStatusEntry {
                    status: TxStatus::Pending,
                    error: None,
                    block_height: None,
                },
            );
        }

        match self.tx_ingest_tx.try_send((tx_hash_bytes, tx_bytes)) {
            Ok(_) => {
                metrics().inc_requests_total("submit_transaction", 200);
                metrics()
                    .observe_request_duration("submit_transaction", start.elapsed().as_secs_f64());

                tracing::info!(
                    target: "rpc",
                    "Received transaction via gRPC. Hash: {}",
                    tx_hash_hex
                );

                Ok(Response::new(SubmitTransactionResponse {
                    tx_hash: tx_hash_hex,
                    status: SubmissionStatus::Accepted as i32,
                    approval_reason: String::new(),
                }))
            }
            Err(_) => {
                metrics().inc_requests_total("submit_transaction", 503);
                let ctx_arc = self.get_context().await?;
                let ctx = ctx_arc.lock().await;
                let mut cache = ctx.tx_status_cache.lock().await;
                cache.put(
                    tx_hash_hex,
                    TxStatusEntry {
                        status: TxStatus::Rejected,
                        error: Some("Ingestion queue full".into()),
                        block_height: None,
                    },
                );

                Err(Status::resource_exhausted("Ingestion queue full"))
            }
        }
    }

    pub(super) async fn handle_get_transaction_status(
        &self,
        request: Request<GetTransactionStatusRequest>,
    ) -> Result<Response<GetTransactionStatusResponse>, Status> {
        let req = request.into_inner();
        let ctx_arc = self.get_context().await?;
        let ctx = ctx_arc.lock().await;

        let mut cache = ctx.tx_status_cache.lock().await;
        if let Some(entry) = cache.get(&req.tx_hash) {
            Ok(Response::new(GetTransactionStatusResponse {
                status: entry.status as i32,
                error_message: entry.error.clone().unwrap_or_default(),
                block_height: entry.block_height.unwrap_or(0),
            }))
        } else {
            Ok(Response::new(GetTransactionStatusResponse {
                status: TxStatus::Unknown as i32,
                error_message: "Transaction not found".into(),
                block_height: 0,
            }))
        }
    }

    pub(super) async fn handle_draft_transaction(
        &self,
        request: Request<DraftTransactionRequest>,
    ) -> Result<Response<DraftTransactionResponse>, Status> {
        let req = request.into_inner();
        let ctx_arc = self.get_context().await?;

        let (
            chain_id,
            inference_runtime,
            keypair,
            nonce_manager,
            workload_client,
            account_id_bytes,
        ) = {
            let ctx = ctx_arc.lock().await;
            let account_id = account_id_from_key_material(
                SignatureSuite::ED25519,
                &ctx.local_keypair.public().encode_protobuf(),
            )
            .unwrap_or_default();

            (
                ctx.chain_id,
                ctx.inference_runtime.clone(),
                ctx.local_keypair.clone(),
                ctx.nonce_manager.clone(),
                ctx.view_resolver.workload_client().clone(),
                account_id,
            )
        };

        let account_id = AccountId(account_id_bytes);
        let nonce_key = [ioi_types::keys::ACCOUNT_NONCE_PREFIX, account_id.as_ref()].concat();

        let state_nonce = match workload_client.query_raw_state(&nonce_key).await {
            Ok(Some(b)) => codec::from_bytes_canonical::<u64>(&b).unwrap_or(0),
            _ => 0,
        };

        let nonce = {
            let mut guard = nonce_manager.lock().await;
            let entry = guard.entry(account_id).or_insert(0);

            if *entry < state_nonce {
                *entry = state_nonce;
            }

            let use_nonce = *entry;
            *entry += 1;

            use_nonce
        };

        let resolver = IntentResolver::new(inference_runtime);
        let address_book = std::collections::HashMap::new();

        let tx_bytes = resolver
            .resolve_intent(&req.intent, chain_id, nonce, &address_book)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let mut tx: ChainTransaction = codec::from_bytes_canonical(&tx_bytes)
            .map_err(|e| Status::internal(format!("Failed to deserialize draft: {}", e)))?;

        let signer_pk_bytes = keypair.public().encode_protobuf();
        let signer_account_id = AccountId(
            account_id_from_key_material(SignatureSuite::ED25519, &signer_pk_bytes)
                .map_err(|e| Status::internal(e.to_string()))?,
        );

        let signed_tx_bytes = match &mut tx {
            ChainTransaction::Settlement(s) => {
                s.header.account_id = signer_account_id;
                let sign_bytes = s.to_sign_bytes().map_err(Status::internal)?;
                let sig = keypair
                    .sign(&sign_bytes)
                    .map_err(|e| Status::internal(e.to_string()))?;
                s.signature_proof = SignatureProof {
                    suite: SignatureSuite::ED25519,
                    public_key: signer_pk_bytes,
                    signature: sig,
                };
                codec::to_bytes_canonical(&tx).map_err(Status::internal)?
            }
            ChainTransaction::System(s) => {
                s.header.account_id = signer_account_id;
                let sign_bytes = s.to_sign_bytes().map_err(Status::internal)?;
                let sig = keypair
                    .sign(&sign_bytes)
                    .map_err(|e| Status::internal(e.to_string()))?;
                s.signature_proof = SignatureProof {
                    suite: SignatureSuite::ED25519,
                    public_key: signer_pk_bytes,
                    signature: sig,
                };
                codec::to_bytes_canonical(&tx).map_err(Status::internal)?
            }
            _ => {
                return Err(Status::unimplemented(
                    "Auto-signing not supported for this transaction type",
                ))
            }
        };

        Ok(Response::new(DraftTransactionResponse {
            transaction_bytes: signed_tx_bytes,
            summary_markdown: format!(
                "**Action:** Execute `{}` (Auto-Signed, Nonce {})",
                req.intent, nonce
            ),
            required_capabilities: vec!["wallet::sign".into()],
        }))
    }
}
