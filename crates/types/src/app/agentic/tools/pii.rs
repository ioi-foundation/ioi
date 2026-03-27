use crate::app::agentic::security::PiiTarget;
use crate::app::ActionTarget;

use super::AgentTool;

/// Mutable text slot identifiers for deterministic PII egress enforcement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PiiEgressField {
    /// Clipboard payload for `os__copy`.
    OsCopyContent,
    /// Destination URL for `browser__navigate`.
    BrowserNavigateUrl,
    /// Computed destination URL for `web__search`.
    WebSearchUrl,
    /// Destination URL for `web__read`.
    WebReadUrl,
    /// Destination URL for `media__extract_transcript`.
    MediaExtractTranscriptUrl,
    /// Destination URL for `media__extract_multimodal_evidence`.
    MediaExtractMultimodalEvidenceUrl,
    /// Destination URL for `net__fetch`.
    NetFetchUrl,
    /// Free-form text payload for `browser__type`.
    BrowserTypeText,
    /// Buyer email field in `commerce__checkout`.
    CommerceBuyerEmail,
    /// Merchant URL field in `commerce__checkout`.
    CommerceMerchantUrl,
}

/// Risk surface for tool-level PII egress specs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PiiEgressRiskSurface {
    /// Content is leaving local processing boundaries.
    Egress,
}

/// Deterministic PII egress specification for an agent tool field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PiiEgressSpec {
    /// Which mutable field is covered by this spec.
    pub field: PiiEgressField,
    /// Canonical target identity bound into routing material.
    pub target: PiiTarget,
    /// Whether deterministic transform is allowed on this path.
    pub supports_transform: bool,
    /// Risk-surface classification for this field.
    pub risk_surface: PiiEgressRiskSurface,
}

impl AgentTool {
    /// Returns deterministic egress specs for all text fields that can cross trust boundaries.
    pub fn pii_egress_specs(&self) -> Vec<PiiEgressSpec> {
        match self {
            AgentTool::OsCopy { .. } => vec![PiiEgressSpec {
                field: PiiEgressField::OsCopyContent,
                target: PiiTarget::Action(ActionTarget::ClipboardWrite),
                supports_transform: true,
                risk_surface: PiiEgressRiskSurface::Egress,
            }],
            AgentTool::BrowserNavigate { .. } => vec![PiiEgressSpec {
                field: PiiEgressField::BrowserNavigateUrl,
                target: PiiTarget::Action(ActionTarget::BrowserInteract),
                supports_transform: false,
                risk_surface: PiiEgressRiskSurface::Egress,
            }],
            AgentTool::WebSearch { .. } => vec![PiiEgressSpec {
                field: PiiEgressField::WebSearchUrl,
                target: PiiTarget::Action(ActionTarget::WebRetrieve),
                supports_transform: false,
                risk_surface: PiiEgressRiskSurface::Egress,
            }],
            AgentTool::WebRead { .. } => vec![PiiEgressSpec {
                field: PiiEgressField::WebReadUrl,
                target: PiiTarget::Action(ActionTarget::WebRetrieve),
                supports_transform: false,
                risk_surface: PiiEgressRiskSurface::Egress,
            }],
            AgentTool::MediaExtractTranscript { .. } => vec![PiiEgressSpec {
                field: PiiEgressField::MediaExtractTranscriptUrl,
                target: PiiTarget::Action(ActionTarget::MediaExtractTranscript),
                supports_transform: false,
                risk_surface: PiiEgressRiskSurface::Egress,
            }],
            AgentTool::MediaExtractMultimodalEvidence { .. } => vec![PiiEgressSpec {
                field: PiiEgressField::MediaExtractMultimodalEvidenceUrl,
                target: PiiTarget::Action(ActionTarget::MediaExtractMultimodalEvidence),
                supports_transform: false,
                risk_surface: PiiEgressRiskSurface::Egress,
            }],
            AgentTool::NetFetch { .. } => vec![PiiEgressSpec {
                field: PiiEgressField::NetFetchUrl,
                target: PiiTarget::Action(ActionTarget::NetFetch),
                supports_transform: false,
                risk_surface: PiiEgressRiskSurface::Egress,
            }],
            AgentTool::Dynamic(val) => {
                let _ = val;
                vec![]
            }
            AgentTool::BrowserType { .. } => vec![PiiEgressSpec {
                field: PiiEgressField::BrowserTypeText,
                target: PiiTarget::Action(ActionTarget::BrowserInteract),
                supports_transform: true,
                risk_surface: PiiEgressRiskSurface::Egress,
            }],
            AgentTool::CommerceCheckout { .. } => vec![
                PiiEgressSpec {
                    field: PiiEgressField::CommerceBuyerEmail,
                    target: PiiTarget::Action(ActionTarget::CommerceCheckout),
                    supports_transform: true,
                    risk_surface: PiiEgressRiskSurface::Egress,
                },
                PiiEgressSpec {
                    field: PiiEgressField::CommerceMerchantUrl,
                    target: PiiTarget::Action(ActionTarget::CommerceCheckout),
                    supports_transform: false,
                    risk_surface: PiiEgressRiskSurface::Egress,
                },
            ],
            _ => vec![],
        }
    }

    /// Resolves a mutable reference to the requested egress text field.
    pub fn pii_egress_field_mut(&mut self, field: PiiEgressField) -> Option<&mut String> {
        match (self, field) {
            (AgentTool::OsCopy { content }, PiiEgressField::OsCopyContent) => Some(content),
            (AgentTool::BrowserNavigate { url }, PiiEgressField::BrowserNavigateUrl) => Some(url),
            (AgentTool::WebSearch { url, .. }, PiiEgressField::WebSearchUrl) => url.as_mut(),
            (AgentTool::WebRead { url, .. }, PiiEgressField::WebReadUrl) => Some(url),
            (
                AgentTool::MediaExtractTranscript { url, .. },
                PiiEgressField::MediaExtractTranscriptUrl,
            ) => Some(url),
            (
                AgentTool::MediaExtractMultimodalEvidence { url, .. },
                PiiEgressField::MediaExtractMultimodalEvidenceUrl,
            ) => Some(url),
            (AgentTool::NetFetch { url, .. }, PiiEgressField::NetFetchUrl) => Some(url),
            (AgentTool::BrowserType { text, .. }, PiiEgressField::BrowserTypeText) => Some(text),
            (
                AgentTool::CommerceCheckout { buyer_email, .. },
                PiiEgressField::CommerceBuyerEmail,
            ) => buyer_email.as_mut(),
            (
                AgentTool::CommerceCheckout { merchant_url, .. },
                PiiEgressField::CommerceMerchantUrl,
            ) => Some(merchant_url),
            _ => None,
        }
    }
}
