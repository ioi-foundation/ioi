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

#[cfg(unix)]
use std::os::fd::AsRawFd;

use ioi_api::crypto::{SerializableKey, SigningKey, SigningKeyPair};
use ioi_api::state::service_namespace_prefix;
use ioi_crypto::sign::eddsa::{Ed25519KeyPair, Ed25519PrivateKey};
use ioi_ipc::blockchain::QueryRawStateRequest;
use ioi_ipc::public::public_api_client::PublicApiClient;
use ioi_ipc::public::{
    GetTransactionStatusRequest, SubmissionStatus, SubmitTransactionRequest, TxStatus,
};
use ioi_services::wallet_network::{
    verify_wallet_signature_proof, ApprovalGrantConsumptionReceipt, ApprovalGrantState,
    ConsumeApprovalGrantForEffectParams, ConsumeApprovalGrantForEffectV2Params,
    ConsumePortableAuthorityGrantV3ForEffectParams, ConsumeStandingApprovalGrantForEffectParams,
    PortableAuthorityGrantV3ConsumptionReceipt, PortableAuthorityGrantV3State,
    PortableAuthorityGrantV3Status, SettleStandingApprovalGrantConsumptionParams,
    StandingApprovalGrantConsumptionReceipt, StandingApprovalGrantSettlementReceipt,
};
use ioi_types::app::wallet_network::{WalletApprovalDecision, WalletApprovalDecisionKind};
use ioi_types::app::{
    account_id_from_key_material, AccountId, ChainId, ChainTransaction,
    PrincipalAuthorityBindingProofV1, PrincipalAuthorityResolutionReceipt,
    ResolvePrincipalAuthorityParams, SignHeader, SignatureProof, SignatureSuite, StateEntry,
    SystemPayload, SystemTransaction, WalletControlPlaneRootRecord,
};
use ioi_types::codec;
use ioi_types::keys::ACCOUNT_NONCE_PREFIX;
use ioi_validator::common::GuardianContainer;
use sha2::{Digest, Sha256};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint};

const RECEIPT_PREFIX: &[u8] = b"principal_authority_resolution_receipt::";
const BINDING_PREFIX: &[u8] = b"principal_authority_binding::";
const EFFECT_CONSUMPTION_RECEIPT_PREFIX: &[u8] = b"approval_effect_consumption_receipt::";
const APPROVAL_PREFIX: &[u8] = b"approval::";
const APPROVAL_GRANT_STATE_PREFIX: &[u8] = b"approval_grant_state::";
const STANDING_EFFECT_CONSUMPTION_RECEIPT_PREFIX: &[u8] =
    b"standing_approval_consumption_receipt::";
const STANDING_EFFECT_SETTLEMENT_RECEIPT_PREFIX: &[u8] = b"standing_approval_settlement_receipt::";
const PORTABLE_AUTHORITY_GRANT_V3_STATE_PREFIX: &[u8] = b"portable_authority_grant_v3_state::";
const PORTABLE_AUTHORITY_EFFECT_CONSUMPTION_RECEIPT_PREFIX: &[u8] =
    b"portable_authority_effect_consumption_receipt::";
const REVOCATION_EPOCH_KEY: &[u8] = b"revocation_epoch";
const PANIC_FLAG_KEY: &[u8] = b"panic";
const DEFAULT_TIMEOUT_MS: u64 = 5_000;
const MIN_TIMEOUT_MS: u64 = 250;
// Debug-profile wallet fixtures execute IAVL-deep blocks whose consumption
// latency grows with chain length; long held journeys legitimately hold a
// single governed consumption for minutes. The ceiling matches the estate's
// 900s held-operation precedent; callers still opt in via the env timeout.
const MAX_TIMEOUT_MS: u64 = 900_000;

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
    transaction_lock_path: PathBuf,
    root: WalletControlPlaneRootRecord,
    tls_ca: Vec<u8>,
    tls_server_name: String,
    timeout: Duration,
}

#[cfg(unix)]
struct WalletTransactionProcessLock(std::fs::File);

#[cfg(unix)]
impl Drop for WalletTransactionProcessLock {
    fn drop(&mut self) {
        // SAFETY: the descriptor remains owned by this guard for the call.
        unsafe {
            libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

#[cfg(unix)]
fn lock_wallet_transaction(path: &PathBuf) -> std::io::Result<WalletTransactionProcessLock> {
    let file = std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(path)?;
    loop {
        // SAFETY: `file` owns a valid descriptor and remains alive in the returned guard.
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
        if result == 0 {
            return Ok(WalletTransactionProcessLock(file));
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

#[cfg(unix)]
async fn acquire_wallet_transaction_process_lock(
    path: &PathBuf,
) -> Result<WalletTransactionProcessLock, ResolveError> {
    let path = path.clone();
    tokio::task::spawn_blocking(move || lock_wallet_transaction(&path))
        .await
        .map_err(|error| {
            ResolveError::Unavailable(format!(
                "wallet.network transaction lock task failed: {error}"
            ))
        })?
        .map_err(|error| {
            ResolveError::Unavailable(format!(
                "wallet.network transaction lock could not be acquired: {error}"
            ))
        })
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

fn load_pinned_root() -> Result<WalletControlPlaneRootRecord, ResolveError> {
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
    Ok(root)
}

pub(crate) fn verify_retained_principal_authority_binding_proof(
    proof: &PrincipalAuthorityBindingProofV1,
) -> Result<(), ResolveError> {
    let root = load_pinned_root()?;
    verify_retained_principal_authority_binding_proof_with_root(proof, &root)
}

pub(crate) fn verify_retained_principal_authority_binding_proof_with_root(
    proof: &PrincipalAuthorityBindingProofV1,
    root: &WalletControlPlaneRootRecord,
) -> Result<(), ResolveError> {
    proof
        .verify_root_signature_with(root, |suite, public_key, message, signature| {
            verify_wallet_signature_proof(
                &SignatureProof {
                    suite,
                    public_key: public_key.to_vec(),
                    signature: signature.to_vec(),
                },
                message,
                "Hypervisor retained principal-authority binding",
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
        })
        .map_err(|error| {
            ResolveError::Invalid(format!(
                "retained wallet.network binding proof is not signed by the pinned root: {error}"
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

    let root = load_pinned_root()?;

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
    let transaction_lock_path = std::env::var("IOI_WALLET_NETWORK_TRANSACTION_LOCK_PATH")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(
                std::env::var("IOI_HYPERVISOR_DATA_DIR")
                    .unwrap_or_else(|_| ".ioi/hypervisor/data".to_string()),
            )
            .join(".wallet-network-transactions.lock")
        });
    Ok(Config {
        rpc_addr,
        chain_id,
        client_key,
        // The capability key is commonly mounted read-only. Transaction
        // serialization is mutable daemon state and must never be placed
        // beside that secret merely because its pathname is convenient.
        transaction_lock_path,
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
    #[cfg(unix)]
    let _process_guard =
        acquire_wallet_transaction_process_lock(&config.transaction_lock_path).await?;
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

async fn consume_for_effect_inner<P: parity_scale_codec::Encode>(
    config: &Config,
    method: &str,
    wire_params: &P,
    receipt_params: &ConsumeApprovalGrantForEffectParams,
) -> Result<ApprovalGrantConsumptionReceipt, ResolveError> {
    // Phase-scoped timeouts: an opaque outer timeout cannot say WHERE a
    // consumption stalled (lock, connect, inclusion, or receipt query); the
    // phase name in the error is the only diagnostic that survives teardown.
    let phase = |name: &'static str| {
        move |_| {
            ResolveError::Unavailable(format!(
                "wallet.network grant consumption stalled in phase '{name}'"
            ))
        }
    };
    let _transaction_guard =
        tokio::time::timeout(std::time::Duration::from_secs(30), TRANSACTION_LOCK.lock())
            .await
            .map_err(phase("in-process transaction lock"))?;
    #[cfg(unix)]
    let _process_guard = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        acquire_wallet_transaction_process_lock(&config.transaction_lock_path),
    )
    .await
    .map_err(phase("cross-process transaction lock"))??;
    let mut client = tokio::time::timeout(std::time::Duration::from_secs(20), connect(config))
        .await
        .map_err(phase("wallet endpoint connect"))??;
    let encoded = codec::to_bytes_canonical(wire_params).map_err(|error| {
        ResolveError::Invalid(format!(
            "approval-grant consumption request encoding failed: {error}"
        ))
    })?;
    let submission_budget = config
        .timeout
        .saturating_sub(std::time::Duration::from_secs(20))
        .max(std::time::Duration::from_secs(60));
    tokio::time::timeout(
        submission_budget,
        submit_service_call(config, &mut client, method, encoded),
    )
    .await
    .map_err(phase("transaction submission and inclusion"))??;

    let receipt_key = namespaced_key(
        EFFECT_CONSUMPTION_RECEIPT_PREFIX,
        &receipt_params.consumption_id,
    );
    let receipt_bytes = query_raw(&mut client, receipt_key).await?.ok_or_else(|| {
        ResolveError::Invalid(
            "committed wallet.network grant consumption emitted no receipt".to_string(),
        )
    })?;
    let receipt: ApprovalGrantConsumptionReceipt = decode_state_value(&receipt_bytes)?;
    if receipt.schema_version != 1
        || receipt.request_hash != receipt_params.request_hash
        || receipt.grant_hash != receipt_params.grant_hash
        || receipt.consumption_id != receipt_params.consumption_id
        || receipt.principal_authority != receipt_params.expected_principal_authority
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

#[allow(dead_code)] // Retained for daemon consumers that still emit the four-field v1 wire.
pub(crate) async fn consume_approval_grant_for_effect(
    params: ConsumeApprovalGrantForEffectParams,
) -> Result<ApprovalGrantConsumptionReceipt, ResolveError> {
    let config = load_config()?;
    let timeout = config.timeout;
    tokio::time::timeout(
        timeout,
        consume_for_effect_inner(
            &config,
            "consume_approval_grant_for_effect@v1",
            &params,
            &params,
        ),
    )
    .await
    .map_err(|_| {
        ResolveError::Unavailable(format!(
            "authenticated wallet.network grant consumption exceeded {} ms",
            timeout.as_millis()
        ))
    })?
}

pub(crate) async fn consume_approval_grant_for_effect_v2(
    params: ConsumeApprovalGrantForEffectV2Params,
) -> Result<ApprovalGrantConsumptionReceipt, ResolveError> {
    let config = load_config()?;
    let timeout = config.timeout;
    let receipt_params = ConsumeApprovalGrantForEffectParams {
        request_hash: params.request_hash,
        grant_hash: params.grant_hash,
        consumption_id: params.consumption_id,
        expected_principal_authority: params.expected_principal_authority.clone(),
    };
    tokio::time::timeout(
        timeout,
        consume_for_effect_inner(
            &config,
            "consume_approval_grant_for_effect@v2",
            &params,
            &receipt_params,
        ),
    )
    .await
    .map_err(|_| {
        ResolveError::Unavailable(format!(
            "authenticated wallet.network grant consumption exceeded {} ms",
            timeout.as_millis()
        ))
    })?
}

fn validate_standing_effect_consumption_receipt(
    params: &ConsumeStandingApprovalGrantForEffectParams,
    receipt: StandingApprovalGrantConsumptionReceipt,
) -> Result<StandingApprovalGrantConsumptionReceipt, ResolveError> {
    let mut material = serde_json::to_value(&receipt).map_err(|error| {
        ResolveError::Invalid(format!("standing receipt cannot be projected: {error}"))
    })?;
    material["receipt_hash"] = serde_json::json!(vec![0u8; 32]);
    let canonical = serde_jcs::to_vec(&material).map_err(|error| {
        ResolveError::Invalid(format!("standing receipt cannot be canonicalized: {error}"))
    })?;
    let expected_hash: [u8; 32] = Sha256::digest(canonical).into();
    if receipt.schema_version == 1
        && receipt.grant_hash == params.grant_hash
        && receipt.standing_envelope_hash == params.standing_envelope_hash
        && receipt.policy_hash == params.policy_hash
        && receipt.request_hash == params.request_hash
        && receipt.consumption_id == params.consumption_id
        && receipt.expected_principal_authority == params.expected_principal_authority
        && receipt.target_label == params.expected_target_label
        && receipt.estimated_deposit_microusd == params.estimated_deposit_microusd
        && receipt.estimated_spend_microusd == params.estimated_spend_microusd
        && receipt.receipt_hash == expected_hash
    {
        Ok(receipt)
    } else {
        Err(ResolveError::Invalid(
            "wallet.network found a foreign standing receipt in the requested consumption slot"
                .to_string(),
        ))
    }
}

/// Atomically reserve one bounded effect against a previously registered standing grant.
pub(crate) async fn consume_standing_approval_grant_for_effect(
    params: ConsumeStandingApprovalGrantForEffectParams,
) -> Result<StandingApprovalGrantConsumptionReceipt, ResolveError> {
    let config = load_config()?;
    let timeout = config.timeout;
    tokio::time::timeout(timeout, async {
        let _transaction_guard = TRANSACTION_LOCK.lock().await;
        #[cfg(unix)]
        let _process_guard =
            acquire_wallet_transaction_process_lock(&config.transaction_lock_path).await?;
        let mut client = connect(&config).await?;
        let encoded = codec::to_bytes_canonical(&params).map_err(|error| {
            ResolveError::Invalid(format!("standing approval draw encoding failed: {error}"))
        })?;
        submit_service_call(
            &config,
            &mut client,
            "consume_standing_approval_grant_for_effect@v1",
            encoded,
        )
        .await?;
        let receipt_key = namespaced_key(
            STANDING_EFFECT_CONSUMPTION_RECEIPT_PREFIX,
            &params.consumption_id,
        );
        let bytes = query_raw(&mut client, receipt_key).await?.ok_or_else(|| {
            ResolveError::Invalid(
                "committed wallet.network standing draw emitted no receipt".to_string(),
            )
        })?;
        let receipt: StandingApprovalGrantConsumptionReceipt = decode_state_value(&bytes)?;
        validate_standing_effect_consumption_receipt(&params, receipt)
    })
    .await
    .map_err(|_| {
        ResolveError::Unavailable(format!(
            "authenticated wallet.network standing draw exceeded {} ms",
            timeout.as_millis()
        ))
    })?
}

/// Recover an idempotent standing draw after wallet commit without spending a second usage.
pub(crate) async fn recover_standing_approval_grant_consumption_for_effect(
    params: &ConsumeStandingApprovalGrantForEffectParams,
) -> Result<Option<StandingApprovalGrantConsumptionReceipt>, ResolveError> {
    let config = load_config()?;
    let timeout = config.timeout;
    tokio::time::timeout(timeout, async {
        let _transaction_guard = TRANSACTION_LOCK.lock().await;
        let mut client = connect(&config).await?;
        let receipt_key = namespaced_key(
            STANDING_EFFECT_CONSUMPTION_RECEIPT_PREFIX,
            &params.consumption_id,
        );
        query_raw(&mut client, receipt_key)
            .await?
            .map(|bytes| {
                decode_state_value::<StandingApprovalGrantConsumptionReceipt>(&bytes).and_then(
                    |receipt| validate_standing_effect_consumption_receipt(params, receipt),
                )
            })
            .transpose()
    })
    .await
    .map_err(|_| {
        ResolveError::Unavailable(format!(
            "authenticated wallet.network standing draw recovery exceeded {} ms",
            timeout.as_millis()
        ))
    })?
}

fn validate_standing_effect_settlement_receipt(
    params: &SettleStandingApprovalGrantConsumptionParams,
    receipt: StandingApprovalGrantSettlementReceipt,
) -> Result<StandingApprovalGrantSettlementReceipt, ResolveError> {
    let mut material = serde_json::to_value(&receipt).map_err(|error| {
        ResolveError::Invalid(format!("standing settlement cannot be projected: {error}"))
    })?;
    material["receipt_hash"] = serde_json::json!(vec![0u8; 32]);
    let canonical = serde_jcs::to_vec(&material).map_err(|error| {
        ResolveError::Invalid(format!(
            "standing settlement cannot be canonicalized: {error}"
        ))
    })?;
    let expected_hash: [u8; 32] = Sha256::digest(canonical).into();
    if receipt.schema_version == 1
        && receipt.consumption_id == params.consumption_id
        && receipt.terminal_evidence_hash == params.terminal_evidence_hash
        && receipt.terminal_evidence_ref == params.terminal_evidence_ref
        && receipt.actual_spend_microusd == params.actual_spend_microusd
        && receipt.receipt_hash == expected_hash
    {
        Ok(receipt)
    } else {
        Err(ResolveError::Invalid(
            "wallet.network found a foreign settlement receipt in the requested consumption slot"
                .to_string(),
        ))
    }
}

/// Record provider-native terminal spend without releasing the original reservation.
pub(crate) async fn settle_standing_approval_grant_consumption(
    params: SettleStandingApprovalGrantConsumptionParams,
) -> Result<StandingApprovalGrantSettlementReceipt, ResolveError> {
    let config = load_config()?;
    let timeout = config.timeout;
    tokio::time::timeout(timeout, async {
        let _transaction_guard = TRANSACTION_LOCK.lock().await;
        #[cfg(unix)]
        let _process_guard =
            acquire_wallet_transaction_process_lock(&config.transaction_lock_path).await?;
        let mut client = connect(&config).await?;
        let encoded = codec::to_bytes_canonical(&params).map_err(|error| {
            ResolveError::Invalid(format!("standing settlement encoding failed: {error}"))
        })?;
        submit_service_call(
            &config,
            &mut client,
            "settle_standing_approval_grant_consumption@v1",
            encoded,
        )
        .await?;
        let receipt_key = namespaced_key(
            STANDING_EFFECT_SETTLEMENT_RECEIPT_PREFIX,
            &params.consumption_id,
        );
        let bytes = query_raw(&mut client, receipt_key).await?.ok_or_else(|| {
            ResolveError::Invalid(
                "committed wallet.network standing settlement emitted no receipt".to_string(),
            )
        })?;
        let receipt: StandingApprovalGrantSettlementReceipt = decode_state_value(&bytes)?;
        validate_standing_effect_settlement_receipt(&params, receipt)
    })
    .await
    .map_err(|_| {
        ResolveError::Unavailable(format!(
            "authenticated wallet.network standing settlement exceeded {} ms",
            timeout.as_millis()
        ))
    })?
}

fn validate_exact_effect_consumption_receipt(
    params: &ConsumeApprovalGrantForEffectV2Params,
    receipt: ApprovalGrantConsumptionReceipt,
) -> Result<ApprovalGrantConsumptionReceipt, ResolveError> {
    if receipt.schema_version == 1
        && receipt.request_hash == params.request_hash
        && receipt.grant_hash == params.grant_hash
        && receipt.consumption_id == params.consumption_id
        && receipt.principal_authority == params.expected_principal_authority
        && receipt.target.canonical_label() == params.expected_target_label
    {
        Ok(receipt)
    } else {
        Err(ResolveError::Invalid(
            "wallet.network found a foreign receipt in the requested consumption slot".to_string(),
        ))
    }
}

/// Recover an already committed exact wallet consumption without submitting a second service
/// transaction. This is the crash boundary used after the wallet returned success but before the
/// daemon durably projected the receipt into its own evidence families.
pub(crate) async fn recover_approval_grant_consumption_for_effect_v2(
    params: &ConsumeApprovalGrantForEffectV2Params,
) -> Result<Option<ApprovalGrantConsumptionReceipt>, ResolveError> {
    let config = load_config()?;
    let timeout = config.timeout;
    tokio::time::timeout(timeout, async {
        let _transaction_guard = TRANSACTION_LOCK.lock().await;
        let mut client = connect(&config).await?;
        let receipt_key = namespaced_key(EFFECT_CONSUMPTION_RECEIPT_PREFIX, &params.consumption_id);
        query_raw(&mut client, receipt_key)
            .await?
            .map(|bytes| {
                decode_state_value::<ApprovalGrantConsumptionReceipt>(&bytes)
                    .and_then(|receipt| validate_exact_effect_consumption_receipt(params, receipt))
            })
            .transpose()
    })
    .await
    .map_err(|_| {
        ResolveError::Unavailable(format!(
            "authenticated wallet.network consumption recovery exceeded {} ms",
            timeout.as_millis()
        ))
    })?
}

fn validate_portable_effect_consumption_receipt(
    params: &ConsumePortableAuthorityGrantV3ForEffectParams,
    receipt: PortableAuthorityGrantV3ConsumptionReceipt,
) -> Result<PortableAuthorityGrantV3ConsumptionReceipt, ResolveError> {
    let mut material = serde_json::to_value(&receipt).map_err(|error| {
        ResolveError::Invalid(format!("portable receipt cannot be projected: {error}"))
    })?;
    material["receipt_hash"] = serde_json::json!(vec![0u8; 32]);
    let canonical = serde_jcs::to_vec(&material).map_err(|error| {
        ResolveError::Invalid(format!("portable receipt cannot be canonicalized: {error}"))
    })?;
    let expected_hash: [u8; 32] = Sha256::digest(canonical).into();
    if receipt.schema_version == 1
        && receipt.receipt_hash == expected_hash
        && receipt.grant_hash == params.grant_hash
        && receipt.consumption_id == params.consumption_id
        && receipt.actual_effect_ref == params.actual_effect_ref
        && receipt.actual_effect_hash == params.actual_effect_hash
        && receipt.audience == params.expected_audience
        && receipt.holder_id == params.expected_holder_id
        && receipt.holder_key_id == params.expected_holder_key_id
    {
        Ok(receipt)
    } else {
        Err(ResolveError::Invalid(
            "wallet.network found a foreign portable receipt in the requested consumption slot"
                .to_string(),
        ))
    }
}

/// Atomically consume one exact effect from a previously registered portable v3 grant.
pub(crate) async fn consume_portable_authority_grant_v3_for_effect(
    params: ConsumePortableAuthorityGrantV3ForEffectParams,
) -> Result<PortableAuthorityGrantV3ConsumptionReceipt, ResolveError> {
    let config = load_config()?;
    let timeout = config.timeout;
    tokio::time::timeout(timeout, async {
        let _transaction_guard = TRANSACTION_LOCK.lock().await;
        #[cfg(unix)]
        let _process_guard =
            acquire_wallet_transaction_process_lock(&config.transaction_lock_path).await?;
        let mut client = connect(&config).await?;
        let encoded = codec::to_bytes_canonical(&params).map_err(|error| {
            ResolveError::Invalid(format!(
                "portable authority consumption encoding failed: {error}"
            ))
        })?;
        submit_service_call(
            &config,
            &mut client,
            "consume_portable_authority_grant_v3_for_effect@v1",
            encoded,
        )
        .await?;
        let receipt_key = namespaced_key(
            PORTABLE_AUTHORITY_EFFECT_CONSUMPTION_RECEIPT_PREFIX,
            &params.consumption_id,
        );
        let bytes = query_raw(&mut client, receipt_key).await?.ok_or_else(|| {
            ResolveError::Invalid(
                "committed wallet.network portable consumption emitted no receipt".to_string(),
            )
        })?;
        let receipt: PortableAuthorityGrantV3ConsumptionReceipt = decode_state_value(&bytes)?;
        validate_portable_effect_consumption_receipt(&params, receipt)
    })
    .await
    .map_err(|_| {
        ResolveError::Unavailable(format!(
            "authenticated wallet.network portable consumption exceeded {} ms",
            timeout.as_millis()
        ))
    })?
}

/// Recover an immutable portable receipt after wallet commit without consuming another call.
pub(crate) async fn recover_portable_authority_grant_v3_consumption_for_effect(
    params: &ConsumePortableAuthorityGrantV3ForEffectParams,
) -> Result<Option<PortableAuthorityGrantV3ConsumptionReceipt>, ResolveError> {
    let config = load_config()?;
    let timeout = config.timeout;
    tokio::time::timeout(timeout, async {
        let _transaction_guard = TRANSACTION_LOCK.lock().await;
        let mut client = connect(&config).await?;
        let receipt_key = namespaced_key(
            PORTABLE_AUTHORITY_EFFECT_CONSUMPTION_RECEIPT_PREFIX,
            &params.consumption_id,
        );
        query_raw(&mut client, receipt_key)
            .await?
            .map(|bytes| {
                decode_state_value::<PortableAuthorityGrantV3ConsumptionReceipt>(&bytes).and_then(
                    |receipt| validate_portable_effect_consumption_receipt(params, receipt),
                )
            })
            .transpose()
    })
    .await
    .map_err(|_| {
        ResolveError::Unavailable(format!(
            "authenticated wallet.network portable recovery exceeded {} ms",
            timeout.as_millis()
        ))
    })?
}

fn validate_portable_grant_state_for_effect(
    params: &ConsumePortableAuthorityGrantV3ForEffectParams,
    state: PortableAuthorityGrantV3State,
    allow_already_consumed: bool,
    expected_audience_client_id: [u8; 32],
) -> Result<PortableAuthorityGrantV3State, ResolveError> {
    let leaf_bytes = state.grant_chain_json.last().ok_or_else(|| {
        ResolveError::Invalid("wallet.network portable grant chain is empty".to_string())
    })?;
    let leaf: serde_json::Value = serde_json::from_slice(leaf_bytes).map_err(|error| {
        ResolveError::Invalid(format!(
            "wallet.network portable leaf is malformed: {error}"
        ))
    })?;
    let effect_hash_ref = format!("sha256:{}", hex::encode(params.actual_effect_hash));
    let grant_hash_ref = format!("sha256:{}", hex::encode(params.grant_hash));
    let usable_status = state.status == PortableAuthorityGrantV3Status::Active
        && state.remaining_calls > 0
        || allow_already_consumed
            && state.status == PortableAuthorityGrantV3Status::Exhausted
            && state.remaining_calls == 0
            && state.uses_consumed == state.max_calls;
    if state.schema_version != 1
        || state.grant_hash != params.grant_hash
        || state.audience_client_id != expected_audience_client_id
        || !usable_status
        || state.uses_consumed.saturating_add(state.remaining_calls) != state.max_calls
        || leaf.get("body_hash").and_then(serde_json::Value::as_str)
            != Some(grant_hash_ref.as_str())
        || leaf.get("audience").and_then(serde_json::Value::as_str)
            != Some(params.expected_audience.as_str())
        || leaf.get("holder_id").and_then(serde_json::Value::as_str)
            != Some(params.expected_holder_id.as_str())
        || leaf
            .get("holder_key_id")
            .and_then(serde_json::Value::as_str)
            != Some(params.expected_holder_key_id.as_str())
        || leaf
            .pointer("/request_commitment/authorization_subject/kind")
            .and_then(serde_json::Value::as_str)
            != Some("exact_effect")
        || leaf
            .pointer("/request_commitment/authorization_subject/subject_ref")
            .and_then(serde_json::Value::as_str)
            != Some(params.actual_effect_ref.as_str())
        || leaf
            .pointer("/request_commitment/authorization_subject/subject_hash")
            .and_then(serde_json::Value::as_str)
            != Some(effect_hash_ref.as_str())
    {
        return Err(ResolveError::Refused(
            "wallet.network preflight refused the portable grant, exact effect, audience, holder, status, or call budget"
                .to_string(),
        ));
    }
    Ok(state)
}

/// Read the wallet-owned portable state and reject structural mismatches before preparing the
/// daemon writer slot. Consensus time, signatures, current authority, and revocation remain the
/// responsibility of the later atomic wallet transaction.
pub(crate) async fn preflight_portable_authority_grant_v3_for_effect(
    params: &ConsumePortableAuthorityGrantV3ForEffectParams,
) -> Result<PortableAuthorityGrantV3State, ResolveError> {
    let config = load_config()?;
    let audience_client_id = account_id_from_key_material(
        SignatureSuite::ED25519,
        &config.client_key.public_key().to_bytes(),
    )
    .map_err(|error| {
        ResolveError::NotConfigured(format!(
            "Hypervisor capability signer id could not be derived: {error}"
        ))
    })?;
    let timeout = config.timeout;
    tokio::time::timeout(timeout, async {
        let _transaction_guard = TRANSACTION_LOCK.lock().await;
        let mut client = connect(&config).await?;

        let already_consumed = if let Some(bytes) = query_raw(
            &mut client,
            namespaced_key(
                PORTABLE_AUTHORITY_EFFECT_CONSUMPTION_RECEIPT_PREFIX,
                &params.consumption_id,
            ),
        )
        .await?
        {
            let receipt: PortableAuthorityGrantV3ConsumptionReceipt = decode_state_value(&bytes)?;
            validate_portable_effect_consumption_receipt(params, receipt)?;
            true
        } else {
            false
        };

        let bytes = query_raw(
            &mut client,
            namespaced_key(PORTABLE_AUTHORITY_GRANT_V3_STATE_PREFIX, &params.grant_hash),
        )
        .await?
        .ok_or_else(|| {
            ResolveError::Refused(
                "wallet.network preflight found no state for the portable grant".to_string(),
            )
        })?;
        let state: PortableAuthorityGrantV3State = decode_state_value(&bytes)?;
        validate_portable_grant_state_for_effect(
            params,
            state,
            already_consumed,
            audience_client_id,
        )
    })
    .await
    .map_err(|_| {
        ResolveError::Unavailable(format!(
            "authenticated wallet.network portable preflight exceeded {} ms",
            timeout.as_millis()
        ))
    })?
}

/// Read-only fail-fast validation for every wallet-owned precondition that can be established
/// before a daemon claims the unique chain-writer reservation. The later consume transaction is
/// still authoritative and atomic; this check exists so an already wrong-target, exhausted,
/// revoked, or superseded grant cannot poison the predecessor's writer slot. Expiry is left to
/// the atomic wallet transaction because only wallet.network has authoritative consensus time.
pub(crate) async fn preflight_approval_grant_for_effect_v2(
    params: &ConsumeApprovalGrantForEffectV2Params,
) -> Result<(), ResolveError> {
    let config = load_config()?;
    let signer_account = account_id_from_key_material(
        SignatureSuite::ED25519,
        &config.client_key.public_key().to_bytes(),
    )
    .map_err(|error| {
        ResolveError::NotConfigured(format!(
            "Hypervisor capability signer id could not be derived: {error}"
        ))
    })?;
    let timeout = config.timeout;
    tokio::time::timeout(timeout, async {
        let _transaction_guard = TRANSACTION_LOCK.lock().await;
        let mut client = connect(&config).await?;

        let receipt_key = namespaced_key(
            EFFECT_CONSUMPTION_RECEIPT_PREFIX,
            &params.consumption_id,
        );
        if let Some(bytes) = query_raw(&mut client, receipt_key).await? {
            let receipt: ApprovalGrantConsumptionReceipt = decode_state_value(&bytes)?;
            validate_exact_effect_consumption_receipt(params, receipt)?;
            return Ok(());
        }

        let grant_key = namespaced_key(APPROVAL_GRANT_STATE_PREFIX, &params.grant_hash);
        let grant_bytes = query_raw(&mut client, grant_key).await?.ok_or_else(|| {
            ResolveError::Refused(
                "wallet.network preflight found no state for the exact approval grant".to_string(),
            )
        })?;
        let grant_state: ApprovalGrantState = decode_state_value(&grant_bytes)?;
        let grant = grant_state.approval.approval_grant.as_ref().ok_or_else(|| {
            ResolveError::Invalid(
                "wallet.network preflight found an approved decision without its grant".to_string(),
            )
        })?;
        let approval_key = namespaced_key(APPROVAL_PREFIX, &params.request_hash);
        let approval_bytes = query_raw(&mut client, approval_key).await?.ok_or_else(|| {
            ResolveError::Refused(
                "wallet.network preflight found no current approval for the exact request"
                    .to_string(),
            )
        })?;
        let current_approval: WalletApprovalDecision = decode_state_value(&approval_bytes)?;
        let active_revocation_epoch = match query_raw(
            &mut client,
            namespaced_key(REVOCATION_EPOCH_KEY, &[]),
        )
        .await?
        {
            Some(bytes) => decode_state_value::<u64>(&bytes)?,
            None => 0,
        };
        let panic_active = match query_raw(&mut client, namespaced_key(PANIC_FLAG_KEY, &[])).await? {
            Some(bytes) => decode_state_value::<bool>(&bytes)?,
            None => false,
        };
        if grant_state.schema_version != 1
            || grant_state.grant_hash != params.grant_hash
            || grant_state.approval != current_approval
            || grant_state.approval.interception.request_hash != params.request_hash
            || grant.request_hash != params.request_hash
            || !matches!(
                grant_state.approval.decision,
                WalletApprovalDecisionKind::AutoApproved
                    | WalletApprovalDecisionKind::ApprovedByHuman
            )
            || grant_state.approval.interception.target.canonical_label()
                != params.expected_target_label
            || grant_state.max_usages != params.expected_max_usages
            || grant_state.remaining_usages == 0
            || grant.audience != signer_account
            || grant_state.issued_revocation_epoch != active_revocation_epoch
            || panic_active
        {
            return Err(ResolveError::Refused(
                "wallet.network preflight refused the exact target, live approval, one-use budget, audience, or revocation state"
                    .to_string(),
            ));
        }
        Ok(())
    })
    .await
    .map_err(|_| {
        ResolveError::Unavailable(format!(
            "authenticated wallet.network grant preflight exceeded {} ms",
            timeout.as_millis()
        ))
    })?
}

#[cfg(test)]
mod portable_authority_client_tests {
    use super::*;

    fn params() -> ConsumePortableAuthorityGrantV3ForEffectParams {
        ConsumePortableAuthorityGrantV3ForEffectParams {
            grant_hash: [0x31; 32],
            consumption_id: [0x32; 32],
            expected_audience: "pep://tests/daemon".to_string(),
            expected_holder_id: "worker://tests/holder".to_string(),
            expected_holder_key_id: "key://tests/holder/1".to_string(),
            actual_effect_ref: "effect://tests/1".to_string(),
            actual_effect_hash: [0x33; 32],
        }
    }

    fn receipt(
        params: &ConsumePortableAuthorityGrantV3ForEffectParams,
    ) -> PortableAuthorityGrantV3ConsumptionReceipt {
        let mut receipt = PortableAuthorityGrantV3ConsumptionReceipt {
            schema_version: 1,
            receipt_hash: [0; 32],
            grant_hash: params.grant_hash,
            consumption_id: params.consumption_id,
            authority_grant_ref: "authority-grant://tests/portable/1".to_string(),
            actual_effect_ref: params.actual_effect_ref.clone(),
            actual_effect_hash: params.actual_effect_hash,
            audience: params.expected_audience.clone(),
            holder_id: params.expected_holder_id.clone(),
            holder_key_id: params.expected_holder_key_id.clone(),
            consumed_at_ms: 1_787_587_300_000,
            usage_ordinal: 1,
            remaining_calls: 0,
        };
        let mut material = serde_json::to_value(&receipt).expect("receipt value");
        material["receipt_hash"] = serde_json::json!(vec![0u8; 32]);
        receipt.receipt_hash =
            Sha256::digest(serde_jcs::to_vec(&material).expect("canonical receipt")).into();
        receipt
    }

    #[test]
    fn portable_receipt_validation_binds_the_exact_effect_and_idempotency_slot() {
        let params = params();
        let receipt = receipt(&params);
        assert_eq!(
            validate_portable_effect_consumption_receipt(&params, receipt.clone())
                .expect("exact receipt"),
            receipt
        );

        let mut substituted = params.clone();
        substituted.actual_effect_hash = [0x34; 32];
        assert!(matches!(
            validate_portable_effect_consumption_receipt(&substituted, receipt),
            Err(ResolveError::Invalid(_))
        ));
    }
}
