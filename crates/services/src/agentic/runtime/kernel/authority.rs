use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub const EXTERNAL_CAPABILITY_EXIT_AUTHORITY_SCHEMA_VERSION: &str =
    "ioi.external_capability_exit_authority.v1";
pub const EXTERNAL_CAPABILITY_EXIT_WALLET_AUTHORITY_NEGATIVE_CONFORMANCE: &str =
    "external capability exit without wallet.network authority fails";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalletAuthorityError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
    MissingField(&'static str),
    MissingWalletNetworkAuthority,
    MissingAuthorityReceipt,
    HashFailed(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityCommandError {
    code: &'static str,
    message: String,
}

impl AuthorityCommandError {
    fn new(code: &'static str, message: String) -> Self {
        Self { code, message }
    }

    pub fn code(&self) -> &'static str {
        self.code
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalCapabilityExitRequest {
    pub schema_version: String,
    pub exit_ref: String,
    pub capability_ref: String,
    pub target_ref: String,
    pub policy_hash: String,
    pub idempotency_key: String,
    #[serde(default)]
    pub authority_grant_refs: Vec<String>,
    #[serde(default)]
    pub authority_receipt_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalCapabilityExitAuthorityRecord {
    pub schema_version: String,
    pub exit_ref: String,
    pub capability_ref: String,
    pub target_ref: String,
    pub policy_hash: String,
    pub idempotency_key: String,
    pub wallet_network_grant_refs: Vec<String>,
    pub authority_receipt_refs: Vec<String>,
    pub authority_hash: String,
}

#[derive(Debug, Deserialize)]
pub struct ExternalCapabilityExitAuthorityBridgeRequest {
    #[serde(default)]
    pub backend: Option<String>,
    pub request: ExternalCapabilityExitRequest,
}

#[derive(Debug, Default, Clone)]
pub struct WalletAuthorityCore;

impl WalletAuthorityCore {
    pub fn authorize_external_capability_exit(
        &self,
        request: &ExternalCapabilityExitRequest,
    ) -> Result<ExternalCapabilityExitAuthorityRecord, WalletAuthorityError> {
        request.validate()?;
        let wallet_network_grant_refs = request
            .authority_grant_refs
            .iter()
            .filter(|grant_ref| is_wallet_network_grant_ref(grant_ref))
            .cloned()
            .collect::<Vec<_>>();

        if wallet_network_grant_refs.is_empty() {
            return Err(WalletAuthorityError::MissingWalletNetworkAuthority);
        }

        let mut record = ExternalCapabilityExitAuthorityRecord {
            schema_version: EXTERNAL_CAPABILITY_EXIT_AUTHORITY_SCHEMA_VERSION.to_string(),
            exit_ref: request.exit_ref.clone(),
            capability_ref: request.capability_ref.clone(),
            target_ref: request.target_ref.clone(),
            policy_hash: request.policy_hash.clone(),
            idempotency_key: request.idempotency_key.clone(),
            wallet_network_grant_refs,
            authority_receipt_refs: request.authority_receipt_refs.clone(),
            authority_hash: String::new(),
        };
        record.authority_hash = authority_hash(&record)?;
        Ok(record)
    }
}

pub fn authorize_external_capability_exit_response(
    request: ExternalCapabilityExitAuthorityBridgeRequest,
) -> Result<Value, AuthorityCommandError> {
    let record = WalletAuthorityCore
        .authorize_external_capability_exit(&request.request)
        .map_err(|error| {
            AuthorityCommandError::new(
                "external_capability_exit_authority_invalid",
                format!("{error:?}"),
            )
        })?;
    Ok(json!({
        "source": "rust_external_capability_exit_authority_command",
        "backend": request.backend.unwrap_or_else(|| "rust_authority".to_string()),
        "authority": record.clone(),
        "wallet_network_grant_refs": record.wallet_network_grant_refs.clone(),
        "authority_receipt_refs": record.authority_receipt_refs.clone(),
        "authority_hash": record.authority_hash.clone(),
    }))
}

impl ExternalCapabilityExitRequest {
    pub fn validate(&self) -> Result<(), WalletAuthorityError> {
        if self.schema_version != EXTERNAL_CAPABILITY_EXIT_AUTHORITY_SCHEMA_VERSION {
            return Err(WalletAuthorityError::InvalidSchemaVersion {
                expected: EXTERNAL_CAPABILITY_EXIT_AUTHORITY_SCHEMA_VERSION,
                actual: self.schema_version.clone(),
            });
        }
        require_non_empty("exit_ref", &self.exit_ref)?;
        require_non_empty("capability_ref", &self.capability_ref)?;
        require_non_empty("target_ref", &self.target_ref)?;
        require_non_empty("policy_hash", &self.policy_hash)?;
        require_non_empty("idempotency_key", &self.idempotency_key)?;
        if self.authority_receipt_refs.is_empty() {
            return Err(WalletAuthorityError::MissingAuthorityReceipt);
        }
        Ok(())
    }
}

fn is_wallet_network_grant_ref(grant_ref: &str) -> bool {
    let normalized = grant_ref.trim().to_ascii_lowercase();
    normalized.starts_with("wallet.network://grant/")
        || normalized.starts_with("grant://wallet.network/")
        || normalized.starts_with("wallet-network://grant/")
}

fn require_non_empty(field: &'static str, value: &str) -> Result<(), WalletAuthorityError> {
    if value.trim().is_empty() {
        Err(WalletAuthorityError::MissingField(field))
    } else {
        Ok(())
    }
}

fn authority_hash(
    record: &ExternalCapabilityExitAuthorityRecord,
) -> Result<String, WalletAuthorityError> {
    let mut canonical = record.clone();
    canonical.authority_hash.clear();
    let bytes = serde_json::to_vec(&canonical)
        .map_err(|error| WalletAuthorityError::HashFailed(error.to_string()))?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> ExternalCapabilityExitRequest {
        ExternalCapabilityExitRequest {
            schema_version: EXTERNAL_CAPABILITY_EXIT_AUTHORITY_SCHEMA_VERSION.to_string(),
            exit_ref: "exit://aiip/send-message".to_string(),
            capability_ref: "capability://connector/slack.postMessage".to_string(),
            target_ref: "aiip://workspace/channel".to_string(),
            policy_hash: "sha256:authority-policy".to_string(),
            idempotency_key: "idem:external-exit".to_string(),
            authority_grant_refs: vec![
                "wallet.network://grant/external-capability/slack".to_string()
            ],
            authority_receipt_refs: vec!["receipt://wallet.network/authority/slack".to_string()],
        }
    }

    #[test]
    fn authorizes_external_capability_exit_with_wallet_network_grant() {
        let record = WalletAuthorityCore
            .authorize_external_capability_exit(&request())
            .expect("authorized exit");

        assert_eq!(
            record.schema_version,
            EXTERNAL_CAPABILITY_EXIT_AUTHORITY_SCHEMA_VERSION
        );
        assert_eq!(
            record.wallet_network_grant_refs,
            vec!["wallet.network://grant/external-capability/slack"]
        );
        assert!(record.authority_hash.starts_with("sha256:"));
    }

    #[test]
    fn external_capability_exit_without_wallet_network_authority_fails() {
        assert_eq!(
            EXTERNAL_CAPABILITY_EXIT_WALLET_AUTHORITY_NEGATIVE_CONFORMANCE,
            "external capability exit without wallet.network authority fails"
        );

        let mut request = request();
        request.authority_grant_refs = vec!["grant://local-debug-only".to_string()];
        let error = WalletAuthorityCore
            .authorize_external_capability_exit(&request)
            .expect_err("wallet.network authority is required");

        assert_eq!(error, WalletAuthorityError::MissingWalletNetworkAuthority);
    }

    #[test]
    fn external_capability_exit_requires_authority_receipt() {
        let mut request = request();
        request.authority_receipt_refs.clear();
        let error = WalletAuthorityCore
            .authorize_external_capability_exit(&request)
            .expect_err("authority receipt is required");

        assert_eq!(error, WalletAuthorityError::MissingAuthorityReceipt);
    }

    #[test]
    fn rust_core_shapes_external_capability_authority_response() {
        let response = authorize_external_capability_exit_response(
            ExternalCapabilityExitAuthorityBridgeRequest {
                backend: Some("rust_authority".to_string()),
                request: request(),
            },
        )
        .expect("authority response");

        assert_eq!(
            response["source"],
            "rust_external_capability_exit_authority_command"
        );
        assert_eq!(response["backend"], "rust_authority");
        assert_eq!(
            response["wallet_network_grant_refs"][0],
            "wallet.network://grant/external-capability/slack"
        );
        assert_eq!(
            response["authority_receipt_refs"][0],
            "receipt://wallet.network/authority/slack"
        );
        assert!(response["authority_hash"]
            .as_str()
            .expect("authority hash")
            .starts_with("sha256:"));
    }
}
