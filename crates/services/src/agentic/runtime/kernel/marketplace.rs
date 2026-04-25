use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MarketplaceSchemaVersion {
    pub schema_name: String,
    pub version: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MarketplaceServiceContract {
    pub service_id: String,
    pub kind: MarketplaceServiceKind,
    #[serde(default)]
    pub schema_versions: Vec<MarketplaceSchemaVersion>,
    #[serde(default)]
    pub declared_capabilities: Vec<String>,
    #[serde(default)]
    pub declared_scopes: Vec<String>,
    #[serde(default)]
    pub deadline_policies: Vec<String>,
    #[serde(default)]
    pub evidence_manifests: Vec<String>,
    pub admission_profile: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MarketplaceServiceKind {
    Tool,
    Connector,
    Plugin,
    Workflow,
    Agent,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum MarketplaceAdmissionError {
    #[error("marketplace service id is missing")]
    MissingServiceId,
    #[error("marketplace schema version is missing: {0}")]
    MissingSchemaVersion(&'static str),
    #[error("marketplace capabilities are missing")]
    MissingCapabilities,
    #[error("marketplace scopes are missing")]
    MissingScopes,
    #[error("marketplace deadline policy is missing")]
    MissingDeadlinePolicy,
    #[error("marketplace evidence manifest is missing")]
    MissingEvidenceManifest,
}

impl MarketplaceServiceContract {
    pub fn validate(&self) -> Result<(), MarketplaceAdmissionError> {
        if self.service_id.trim().is_empty() {
            return Err(MarketplaceAdmissionError::MissingServiceId);
        }
        for required in REQUIRED_SCHEMA_NAMES {
            if !self
                .schema_versions
                .iter()
                .any(|schema| schema.schema_name == *required && schema.version > 0)
            {
                return Err(MarketplaceAdmissionError::MissingSchemaVersion(required));
            }
        }
        if self.declared_capabilities.is_empty() {
            return Err(MarketplaceAdmissionError::MissingCapabilities);
        }
        if self.declared_scopes.is_empty() {
            return Err(MarketplaceAdmissionError::MissingScopes);
        }
        if self.deadline_policies.is_empty() {
            return Err(MarketplaceAdmissionError::MissingDeadlinePolicy);
        }
        if self.evidence_manifests.is_empty() {
            return Err(MarketplaceAdmissionError::MissingEvidenceManifest);
        }
        Ok(())
    }
}

pub const REQUIRED_SCHEMA_NAMES: &[&str] = &[
    "tool",
    "capability_lease",
    "policy_decision",
    "approval_grant",
    "receipt_manifest",
    "settlement_bundle",
    "artifact_promotion",
    "trace_bundle",
];
