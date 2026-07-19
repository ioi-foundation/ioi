//! Authenticated wallet.network capability transport for Hypervisor.
//!
//! Resolution is a signed `CallService` transaction, never a bare HTTP lookup. The caller key
//! must already be registered by wallet.network as an active capability client. The server side
//! of the channel is pinned with a deployment-owned TLS CA + name, so a resolver-shaped endpoint
//! cannot forge current head/revocation state. After commit we also read the receipt and immutable
//! binding proof from namespaced chain state and verify the proof against an out-of-band pinned
//! wallet control root before returning anything to a route.
//!
//! Trust boundary: freshness of the current head/revocation decision terminates at the
//! deployment-pinned wallet.network TLS endpoint and its consensus state. Binding contents do not:
//! they are independently checked against the separately pinned wallet control root.

use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ioi_api::crypto::{SerializableKey, SigningKey, SigningKeyPair};
use ioi_api::state::service_namespace_prefix;
use ioi_crypto::sign::eddsa::{Ed25519KeyPair, Ed25519PrivateKey};
use ioi_ipc::blockchain::QueryRawStateRequest;
use ioi_ipc::public::public_api_client::PublicApiClient;
use ioi_ipc::public::{
    GetTransactionStatusRequest, SubmissionStatus, SubmitTransactionRequest, TxStatus,
};
use ioi_services::wallet_network::{
    verify_wallet_signature_proof, ApprovalGrantConsumptionReceipt,
    ConsumeApprovalGrantForEffectParams,
};
use ioi_types::app::{
    account_id_from_key_material, AccountId, ChainId, ChainTransaction,
    PrincipalAuthorityBindingProofV1, PrincipalAuthorityResolutionReceipt,
    ResolvePrincipalAuthorityParams, SignHeader, SignatureProof, SignatureSuite, StateEntry,
    SystemPayload, SystemTransaction, WalletControlPlaneRootRecord,
};
use ioi_types::codec;
use ioi_types::keys::ACCOUNT_NONCE_PREFIX;
use ioi_validator::common::GuardianContainer;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint};

const RECEIPT_PREFIX: &[u8] = b"principal_authority_resolution_receipt::";
const BINDING_PREFIX: &[u8] = b"principal_authority_binding::";
const EFFECT_CONSUMPTION_RECEIPT_PREFIX: &[u8] = b"approval_effect_consumption_receipt::";
const DEFAULT_TIMEOUT_MS: u64 = 5_000;
const MIN_TIMEOUT_MS: u64 = 250;
const MAX_TIMEOUT_MS: u64 = 180_000;

static TRANSACTION_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[derive(Debug)]
pub(crate) enum ResolveError {
    NotConfigured(String),
    Unavailable(String),
    Refused(String),
    Invalid(String),
}

#[derive(Debug)]
pub(crate) struct AuthenticatedResolution {
    pub(crate) receipt: PrincipalAuthorityResolutionReceipt,
    pub(crate) binding_proof: PrincipalAuthorityBindingProofV1,
}

struct Config {
    rpc_addr: String,
    chain_id: ChainId,
    client_key: Ed25519KeyPair,
    root: WalletControlPlaneRootRecord,
    tls_ca: Vec<u8>,
    tls_server_name: String,
    timeout: Duration,
}

pub(crate) fn configured() -> bool {
    load_config().is_ok()
}

fn required_env(name: &str) -> Result<String, ResolveError> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            ResolveError::NotConfigured(format!(
                "{name} is required for authenticated wallet.network resolution"
            ))
        })
}

fn load_config() -> Result<Config, ResolveError> {
    let rpc_addr = required_env("IOI_WALLET_NETWORK_RPC_ADDR")?;
    let chain_id = required_env("IOI_WALLET_NETWORK_CHAIN_ID")?
        .parse::<u32>()
        .map(ChainId)
        .map_err(|error| {
            ResolveError::NotConfigured(format!(
                "IOI_WALLET_NETWORK_CHAIN_ID is not a u32: {error}"
            ))
        })?;
    let key_path = PathBuf::from(required_env("IOI_HYPERVISOR_WALLET_CLIENT_KEY_PATH")?);
    let key_bytes = GuardianContainer::load_encrypted_file(&key_path).map_err(|error| {
        ResolveError::NotConfigured(format!(
            "Hypervisor wallet capability key '{}' could not be decrypted: {error}",
            key_path.display()
        ))
    })?;
    let client_private_key = Ed25519PrivateKey::from_bytes(&key_bytes).map_err(|error| {
        ResolveError::NotConfigured(format!(
            "Hypervisor wallet capability key is not a canonical Ed25519 seed: {error}"
        ))
    })?;
    let client_key = Ed25519KeyPair::from_private_key(&client_private_key).map_err(|error| {
        ResolveError::NotConfigured(format!(
            "Hypervisor wallet capability keypair could not be derived: {error}"
        ))
    })?;

    let root_path = PathBuf::from(required_env("IOI_WALLET_NETWORK_ROOT_RECORD_PATH")?);
    let root_bytes = std::fs::read(&root_path).map_err(|error| {
        ResolveError::NotConfigured(format!(
            "wallet.network root record '{}' could not be read: {error}",
            root_path.display()
        ))
    })?;
    let root: WalletControlPlaneRootRecord =
        serde_json::from_slice(&root_bytes).map_err(|error| {
            ResolveError::NotConfigured(format!(
                "wallet.network root record is not canonical JSON: {error}"
            ))
        })?;
    let derived_root = account_id_from_key_material(root.signature_suite, &root.public_key)
        .map_err(|error| {
            ResolveError::NotConfigured(format!(
                "wallet.network root record has invalid key material: {error}"
            ))
        })?;
    if root.account_id != derived_root {
        return Err(ResolveError::NotConfigured(
            "wallet.network root record account_id does not match its pinned key".to_string(),
        ));
    }

    if !rpc_addr.starts_with("https://") {
        return Err(ResolveError::NotConfigured(
            "IOI_WALLET_NETWORK_RPC_ADDR must use https:// with a pinned wallet.network server identity"
                .to_string(),
        ));
    }
    let tls_ca_path = PathBuf::from(required_env("IOI_WALLET_NETWORK_TLS_CA_PATH")?);
    let tls_ca = std::fs::read(&tls_ca_path).map_err(|error| {
        ResolveError::NotConfigured(format!(
            "wallet.network TLS CA '{}' could not be read: {error}",
            tls_ca_path.display()
        ))
    })?;
    if tls_ca.is_empty() {
        return Err(ResolveError::NotConfigured(
            "wallet.network TLS CA is empty".to_string(),
        ));
    }
    let tls_server_name = required_env("IOI_WALLET_NETWORK_TLS_SERVER_NAME")?;

    let timeout_ms = std::env::var("IOI_WALLET_NETWORK_RESOLUTION_TIMEOUT_MS")
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .unwrap_or(DEFAULT_TIMEOUT_MS)
        .clamp(MIN_TIMEOUT_MS, MAX_TIMEOUT_MS);
    Ok(Config {
        rpc_addr,
        chain_id,
        client_key,
        root,
        tls_ca,
        tls_server_name,
        timeout: Duration::from_millis(timeout_ms),
    })
}

async fn connect(config: &Config) -> Result<PublicApiClient<Channel>, ResolveError> {
    let endpoint = Endpoint::from_shared(config.rpc_addr.clone()).map_err(|error| {
        ResolveError::NotConfigured(format!("wallet.network RPC address is invalid: {error}"))
    })?;
    let tls = ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(&config.tls_ca))
        .domain_name(config.tls_server_name.clone());
    let endpoint = endpoint.tls_config(tls).map_err(|error| {
        ResolveError::NotConfigured(format!(
            "wallet.network pinned TLS configuration is invalid: {error}"
        ))
    })?;
    let channel = endpoint.connect().await.map_err(|error| {
        ResolveError::Unavailable(format!(
            "wallet.network pinned TLS channel could not be established: {error}"
        ))
    })?;
    Ok(PublicApiClient::new(channel))
}

fn namespaced_key(prefix: &[u8], suffix: &[u8]) -> Vec<u8> {
    [
        service_namespace_prefix("wallet_network").as_slice(),
        prefix,
        suffix,
    ]
    .concat()
}

fn decode_state_value<T: parity_scale_codec::Decode>(bytes: &[u8]) -> Result<T, ResolveError> {
    if let Ok(value) = codec::from_bytes_canonical::<T>(bytes) {
        return Ok(value);
    }
    let entry: StateEntry = codec::from_bytes_canonical(bytes).map_err(|error| {
        ResolveError::Invalid(format!(
            "wallet.network state wrapper is malformed: {error}"
        ))
    })?;
    codec::from_bytes_canonical(&entry.value).map_err(|error| {
        ResolveError::Invalid(format!("wallet.network state value is malformed: {error}"))
    })
}

fn decode_nonce(bytes: &[u8]) -> Result<u64, ResolveError> {
    if let Ok(value) = decode_state_value::<u64>(bytes) {
        return Ok(value);
    }
    if bytes.len() == 8 {
        let mut raw = [0u8; 8];
        raw.copy_from_slice(bytes);
        return Ok(u64::from_le_bytes(raw));
    }
    Err(ResolveError::Invalid(
        "Hypervisor capability-client nonce state is malformed".to_string(),
    ))
}

async fn query_raw(
    client: &mut PublicApiClient<Channel>,
    key: Vec<u8>,
) -> Result<Option<Vec<u8>>, ResolveError> {
    let response = client
        .query_raw_state(tonic::Request::new(QueryRawStateRequest { key }))
        .await
        .map_err(|error| {
            ResolveError::Unavailable(format!("wallet.network state query failed: {error}"))
        })?
        .into_inner();
    Ok(response.found.then_some(response.value))
}

fn build_transaction(
    keypair: &Ed25519KeyPair,
    chain_id: ChainId,
    nonce: u64,
    method: &str,
    params: Vec<u8>,
) -> Result<ChainTransaction, ResolveError> {
    let public_key = keypair.public_key().to_bytes();
    let account_id = account_id_from_key_material(SignatureSuite::ED25519, &public_key)
        .map(AccountId)
        .map_err(|error| {
            ResolveError::NotConfigured(format!(
                "Hypervisor capability signer id could not be derived: {error}"
            ))
        })?;
    let payload = SystemPayload::CallService {
        service_id: "wallet_network".to_string(),
        method: method.to_string(),
        params,
    };
    let mut transaction = SystemTransaction {
        header: SignHeader {
            account_id,
            nonce,
            chain_id,
            tx_version: 1,
            session_auth: None,
        },
        payload,
        signature_proof: SignatureProof::default(),
    };
    let signing_bytes = transaction.to_sign_bytes().map_err(|error| {
        ResolveError::Invalid(format!(
            "resolution transaction signing bytes failed: {error}"
        ))
    })?;
    transaction.signature_proof = SignatureProof {
        suite: SignatureSuite::ED25519,
        public_key,
        signature: keypair
            .private_key()
            .sign(&signing_bytes)
            .map_err(|error| {
                ResolveError::NotConfigured(format!(
                    "Hypervisor capability signer could not sign: {error}"
                ))
            })?
            .to_bytes(),
    };
    Ok(ChainTransaction::System(Box::new(transaction)))
}

async fn submit_service_call(
    config: &Config,
    client: &mut PublicApiClient<Channel>,
    method: &str,
    params: Vec<u8>,
) -> Result<(), ResolveError> {
    let public_key = config.client_key.public_key().to_bytes();
    let account_id =
        account_id_from_key_material(SignatureSuite::ED25519, &public_key).map_err(|error| {
            ResolveError::NotConfigured(format!(
                "Hypervisor capability signer id could not be derived: {error}"
            ))
        })?;
    let nonce_key = [ACCOUNT_NONCE_PREFIX, account_id.as_slice()].concat();
    let nonce = match query_raw(client, nonce_key).await? {
        Some(bytes) => decode_nonce(&bytes)?,
        None => 0,
    };
    let transaction =
        build_transaction(&config.client_key, config.chain_id, nonce, method, params)?;
    let transaction_bytes = codec::to_bytes_canonical(&transaction).map_err(|error| {
        ResolveError::Invalid(format!(
            "wallet.network {method} transaction encoding failed: {error}"
        ))
    })?;
    let submitted = client
        .submit_transaction(tonic::Request::new(SubmitTransactionRequest {
            transaction_bytes,
        }))
        .await
        .map_err(|error| {
            ResolveError::Unavailable(format!(
                "wallet.network {method} transaction submission failed: {error}"
            ))
        })?
        .into_inner();
    if submitted.tx_hash.trim().is_empty() {
        return Err(ResolveError::Refused(format!(
            "wallet.network refused {method} before assigning a transaction hash"
        )));
    }
    match SubmissionStatus::try_from(submitted.status)
        .unwrap_or(SubmissionStatus::SubmissionRejected)
    {
        SubmissionStatus::Accepted => {}
        SubmissionStatus::SubmissionRejected => {
            return Err(ResolveError::Refused(format!(
                "wallet.network rejected {method} submission: {}",
                submitted.approval_reason
            )))
        }
        SubmissionStatus::PendingApproval => {
            return Err(ResolveError::Refused(format!(
                "wallet.network unexpectedly gated capability-client {method}: {}",
                submitted.approval_reason
            )))
        }
    }
    loop {
        let status = client
            .get_transaction_status(tonic::Request::new(GetTransactionStatusRequest {
                tx_hash: submitted.tx_hash.clone(),
            }))
            .await
            .map_err(|error| {
                ResolveError::Unavailable(format!(
                    "wallet.network {method} transaction status failed: {error}"
                ))
            })?
            .into_inner();
        match TxStatus::try_from(status.status).unwrap_or(TxStatus::Unknown) {
            TxStatus::Committed => return Ok(()),
            TxStatus::Rejected => {
                return Err(ResolveError::Refused(format!(
                    "wallet.network rejected authenticated {method}: {}",
                    status.error_message
                )))
            }
            _ => tokio::time::sleep(Duration::from_millis(25)).await,
        }
    }
}

async fn resolve_inner(
    config: &Config,
    params: ResolvePrincipalAuthorityParams,
) -> Result<AuthenticatedResolution, ResolveError> {
    let _transaction_guard = TRANSACTION_LOCK.lock().await;
    let mut client = connect(config).await?;
    let encoded = codec::to_bytes_canonical(&params).map_err(|error| {
        ResolveError::Invalid(format!("resolution request encoding failed: {error}"))
    })?;
    submit_service_call(
        config,
        &mut client,
        "resolve_principal_authority@v1",
        encoded,
    )
    .await?;

    let receipt_key = namespaced_key(RECEIPT_PREFIX, &params.request_id);
    let receipt_bytes = query_raw(&mut client, receipt_key).await?.ok_or_else(|| {
        ResolveError::Invalid("committed wallet.network resolution emitted no receipt".to_string())
    })?;
    let receipt: PrincipalAuthorityResolutionReceipt = decode_state_value(&receipt_bytes)?;
    let proof_key = namespaced_key(BINDING_PREFIX, &receipt.resolution.coordinates.binding_hash);
    let proof_bytes = query_raw(&mut client, proof_key).await?.ok_or_else(|| {
        ResolveError::Invalid(
            "wallet.network resolution named an absent immutable binding proof".to_string(),
        )
    })?;
    let binding_proof: PrincipalAuthorityBindingProofV1 = decode_state_value(&proof_bytes)?;

    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    binding_proof
        .verify_root_signature_with(&config.root, |suite, public_key, message, signature| {
            verify_wallet_signature_proof(
                &SignatureProof {
                    suite,
                    public_key: public_key.to_vec(),
                    signature: signature.to_vec(),
                },
                message,
                "Hypervisor principal-authority binding",
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
        })
        .map_err(|error| {
            ResolveError::Invalid(format!(
                "wallet.network binding proof is not signed by the pinned root: {error}"
            ))
        })?;
    binding_proof.verify_active_at(now_ms).map_err(|error| {
        ResolveError::Invalid(format!(
            "wallet.network binding proof is not active now: {error}"
        ))
    })?;
    if binding_proof.coordinates() != receipt.resolution.coordinates
        || binding_proof.statement.principal_ref != receipt.resolution.principal_ref
        || binding_proof.statement.authority_kind != receipt.resolution.authority_kind
        || binding_proof.statement.authority_id != receipt.resolution.authority_id
        || binding_proof.statement.authority_public_key != receipt.resolution.authority_public_key
        || binding_proof.statement.authority_signature_suite
            != receipt.resolution.authority_signature_suite
        || binding_proof.statement.approval_authority_snapshot_hash
            != receipt.resolution.approval_authority_snapshot_hash
    {
        return Err(ResolveError::Invalid(
            "wallet.network resolution does not match its root-signed immutable proof".to_string(),
        ));
    }
    binding_proof
        .verify_authority_snapshot(&receipt.resolution.approval_authority)
        .map_err(|error| {
            ResolveError::Invalid(format!(
                "wallet.network authority snapshot is not frozen by the signed proof: {error}"
            ))
        })?;

    Ok(AuthenticatedResolution {
        receipt,
        binding_proof,
    })
}

async fn consume_for_effect_inner(
    config: &Config,
    params: ConsumeApprovalGrantForEffectParams,
) -> Result<ApprovalGrantConsumptionReceipt, ResolveError> {
    let _transaction_guard = TRANSACTION_LOCK.lock().await;
    let mut client = connect(config).await?;
    let encoded = codec::to_bytes_canonical(&params).map_err(|error| {
        ResolveError::Invalid(format!(
            "approval-grant consumption request encoding failed: {error}"
        ))
    })?;
    submit_service_call(
        config,
        &mut client,
        "consume_approval_grant_for_effect@v1",
        encoded,
    )
    .await?;

    let receipt_key = namespaced_key(EFFECT_CONSUMPTION_RECEIPT_PREFIX, &params.consumption_id);
    let receipt_bytes = query_raw(&mut client, receipt_key).await?.ok_or_else(|| {
        ResolveError::Invalid(
            "committed wallet.network grant consumption emitted no receipt".to_string(),
        )
    })?;
    let receipt: ApprovalGrantConsumptionReceipt = decode_state_value(&receipt_bytes)?;
    if receipt.schema_version != 1
        || receipt.request_hash != params.request_hash
        || receipt.grant_hash != params.grant_hash
        || receipt.consumption_id != params.consumption_id
        || receipt.principal_authority != params.expected_principal_authority
        || receipt.receipt_hash == [0u8; 32]
    {
        return Err(ResolveError::Invalid(
            "wallet.network grant-consumption receipt does not match the requested durable intent"
                .to_string(),
        ));
    }
    Ok(receipt)
}

pub(crate) async fn resolve_principal_authority(
    params: ResolvePrincipalAuthorityParams,
) -> Result<AuthenticatedResolution, ResolveError> {
    let config = load_config()?;
    let timeout = config.timeout;
    tokio::time::timeout(timeout, resolve_inner(&config, params))
        .await
        .map_err(|_| {
            ResolveError::Unavailable(format!(
                "authenticated wallet.network resolution exceeded {} ms",
                timeout.as_millis()
            ))
        })?
}

pub(crate) async fn consume_approval_grant_for_effect(
    params: ConsumeApprovalGrantForEffectParams,
) -> Result<ApprovalGrantConsumptionReceipt, ResolveError> {
    let config = load_config()?;
    let timeout = config.timeout;
    tokio::time::timeout(timeout, consume_for_effect_inner(&config, params))
        .await
        .map_err(|_| {
            ResolveError::Unavailable(format!(
                "authenticated wallet.network grant consumption exceeded {} ms",
                timeout.as_millis()
            ))
        })?
}
