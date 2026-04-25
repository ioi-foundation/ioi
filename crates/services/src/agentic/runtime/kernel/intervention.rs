use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceTier {
    Projection,
    RuntimeEventReceipt,
    SettlementReceipt,
    ExternalApproval,
    ArtifactPromotion,
    MissingSettlement,
    SimulationOnly,
}

impl EvidenceTier {
    pub fn label(self) -> &'static str {
        match self {
            Self::Projection => "Projection",
            Self::RuntimeEventReceipt => "Runtime event receipt",
            Self::SettlementReceipt => "Settlement receipt",
            Self::ExternalApproval => "External approval",
            Self::ArtifactPromotion => "Artifact promotion",
            Self::MissingSettlement => "Missing settlement",
            Self::SimulationOnly => "Simulation-only",
        }
    }

    pub fn is_authoritative(self) -> bool {
        matches!(
            self,
            Self::SettlementReceipt | Self::ExternalApproval | Self::ArtifactPromotion
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorInterventionType {
    ApprovalRequired,
    GraphBlocked,
    WorkflowFailure,
    ConnectorStepUp,
    PluginTrustChange,
    ArtifactValidationFailure,
    MissingSettlement,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorInterventionStatus {
    Open,
    Resolved,
    Expired,
    Denied,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorIntervention {
    pub intervention_id: String,
    pub session_id: String,
    pub intervention_type: OperatorInterventionType,
    pub authority_required: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_hash: Option<[u8; 32]>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_hash: Option<[u8; 32]>,
    pub status: OperatorInterventionStatus,
    pub deadline_at_ms: u64,
    #[serde(default)]
    pub resolution_options: Vec<String>,
    pub evidence_tier: EvidenceTier,
}

impl OperatorIntervention {
    pub fn implies_authority(&self) -> bool {
        self.evidence_tier.is_authoritative()
            && matches!(self.status, OperatorInterventionStatus::Resolved)
    }
}
