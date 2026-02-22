use ioi_api::state::service_namespace_prefix;
use ioi_ipc::blockchain::QueryRawStateRequest;
use ioi_ipc::public::public_api_client::PublicApiClient;
use ioi_ipc::public::{GetTransactionStatusRequest, SubmitTransactionRequest};
use ioi_types::app::{
    account_id_from_key_material, AccountId, ChainId, ChainTransaction, SignHeader, SignatureProof,
    SignatureSuite, SystemPayload, SystemTransaction,
};
use ioi_types::codec;
use tonic::transport::Channel;

pub(crate) fn build_wallet_call_tx(
    method: &str,
    params: Vec<u8>,
) -> Result<ChainTransaction, String> {
    let keypair = libp2p::identity::Keypair::generate_ed25519();
    let public_key = keypair.public().encode_protobuf();
    let account_id = AccountId(
        account_id_from_key_material(SignatureSuite::ED25519, &public_key)
            .map_err(|e| format!("Failed to derive account id: {}", e))?,
    );

    let payload = SystemPayload::CallService {
        service_id: "wallet_network".to_string(),
        method: method.to_string(),
        params,
    };
    let mut sys_tx = SystemTransaction {
        header: SignHeader {
            account_id,
            nonce: 0,
            chain_id: ChainId(0),
            tx_version: 1,
            session_auth: None,
        },
        payload,
        signature_proof: SignatureProof::default(),
    };

    let sign_bytes = sys_tx.to_sign_bytes().map_err(|e| e.to_string())?;
    let signature = keypair.sign(&sign_bytes).map_err(|e| e.to_string())?;
    sys_tx.signature_proof = SignatureProof {
        suite: SignatureSuite::ED25519,
        public_key,
        signature,
    };

    Ok(ChainTransaction::System(Box::new(sys_tx)))
}

pub(crate) async fn submit_tx_and_wait(
    client: &mut PublicApiClient<Channel>,
    tx: ChainTransaction,
) -> Result<(), String> {
    let tx_bytes = codec::to_bytes_canonical(&tx).map_err(|e| e.to_string())?;
    let submit_resp = client
        .submit_transaction(tonic::Request::new(SubmitTransactionRequest {
            transaction_bytes: tx_bytes,
        }))
        .await
        .map_err(|e| format!("Failed to submit transaction: {}", e))?
        .into_inner();

    let mut attempts = 0;
    loop {
        tokio::time::sleep(std::time::Duration::from_millis(350)).await;
        attempts += 1;
        if attempts > 24 {
            return Err(format!(
                "Timed out waiting for connector tx commit (tx_hash={})",
                submit_resp.tx_hash
            ));
        }

        let status_resp = client
            .get_transaction_status(tonic::Request::new(GetTransactionStatusRequest {
                tx_hash: submit_resp.tx_hash.clone(),
            }))
            .await
            .map_err(|e| format!("Failed to query tx status: {}", e))?
            .into_inner();

        // 3=Committed, 4=Rejected
        if status_resp.status == 3 {
            return Ok(());
        }
        if status_resp.status == 4 {
            if status_resp.error_message.trim().is_empty() {
                return Err("Connector tx rejected".to_string());
            }
            return Err(format!(
                "Connector tx rejected: {}",
                status_resp.error_message
            ));
        }
    }
}

pub(crate) async fn query_wallet_state(
    client: &mut PublicApiClient<Channel>,
    local_key: Vec<u8>,
) -> Result<Vec<u8>, String> {
    let full_key = [
        service_namespace_prefix("wallet_network").as_slice(),
        &local_key,
    ]
    .concat();
    let resp = client
        .query_raw_state(tonic::Request::new(QueryRawStateRequest { key: full_key }))
        .await
        .map_err(|e| format!("Failed to query wallet state: {}", e))?
        .into_inner();
    if !resp.found || resp.value.is_empty() {
        return Err("wallet_network receipt not found".to_string());
    }
    Ok(resp.value)
}

pub(crate) async fn load_wallet_revocation_epoch(
    client: &mut PublicApiClient<Channel>,
) -> Result<u64, String> {
    let full_key = [
        service_namespace_prefix("wallet_network").as_slice(),
        b"revocation_epoch".as_slice(),
    ]
    .concat();
    let resp = client
        .query_raw_state(tonic::Request::new(QueryRawStateRequest { key: full_key }))
        .await
        .map_err(|e| format!("Failed to query wallet revocation epoch: {}", e))?
        .into_inner();
    if !resp.found || resp.value.is_empty() {
        return Ok(0);
    }
    codec::from_bytes_canonical::<u64>(&resp.value).map_err(|e| e.to_string())
}
