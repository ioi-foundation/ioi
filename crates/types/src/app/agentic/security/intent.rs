use crate::app::ActionTarget;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

use super::intent_catalog_defaults::default_intent_catalog;

/// Canonical intent scope profiles used by the step/action resolver.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Encode, Decode, Default,
)]
#[serde(rename_all = "snake_case")]
pub enum IntentScopeProfile {
    /// Conversational responses that should not require external side effects.
    Conversation,
    /// Browser-driven retrieval/research workflows.
    WebResearch,
    /// Filesystem/workspace operations.
    WorkspaceOps,
    /// Local app-launching workflows.
    AppLaunch,
    /// Visual/UI interaction workflows.
    UiInteraction,
    /// Command/shell execution workflows.
    CommandExecution,
    /// Multi-agent orchestration/delegation.
    Delegation,
    /// Unknown scope; safest defaults should apply.
    #[default]
    Unknown,
}

/// Confidence band output by the global intent resolver.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
#[serde(rename_all = "snake_case")]
pub enum IntentConfidenceBand {
    /// High confidence intent resolution.
    High,
    /// Medium confidence intent resolution.
    Medium,
    /// Low confidence intent resolution.
    #[default]
    Low,
}

/// Candidate ranking entry returned by the intent resolver.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Encode, Decode)]
pub struct IntentCandidateScore {
    /// Canonical candidate intent id.
    pub intent_id: String,
    /// Similarity/confidence score in [0.0, 1.0].
    pub score: f32,
}

/// Action policy for ambiguous intent cases.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
#[serde(rename_all = "snake_case")]
pub enum IntentAmbiguityAction {
    /// Pause execution and request user clarification.
    #[default]
    PauseForClarification,
    /// Deprecated: treated as `Proceed` (constrained mode removed).
    ConstrainedProceed,
    /// Continue with full scope.
    Proceed,
}

/// Confidence thresholds used to map intent scores into bands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct IntentConfidenceBandPolicy {
    /// Score threshold (basis points, 0..=10_000) for high confidence.
    pub high_threshold_bps: u16,
    /// Score threshold (basis points, 0..=10_000) for medium confidence.
    pub medium_threshold_bps: u16,
}

impl Default for IntentConfidenceBandPolicy {
    fn default() -> Self {
        Self {
            high_threshold_bps: 8_000,
            medium_threshold_bps: 5_500,
        }
    }
}

/// Ambiguity behavior controls for low/medium confidence routes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct IntentAmbiguityPolicy {
    /// Action to take for low confidence intent.
    pub low_confidence_action: IntentAmbiguityAction,
    /// Action to take for medium confidence intent.
    pub medium_confidence_action: IntentAmbiguityAction,
}

impl Default for IntentAmbiguityPolicy {
    fn default() -> Self {
        Self {
            low_confidence_action: IntentAmbiguityAction::PauseForClarification,
            medium_confidence_action: IntentAmbiguityAction::Proceed,
        }
    }
}

/// CEC execution applicability class for an intent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionApplicabilityClass {
    /// Host discovery and provider selection are required.
    #[default]
    TopologyDependent,
    /// Pure deterministic local transformation with no topology dependency.
    DeterministicLocal,
    /// External retrieval with no host topology discovery requirement.
    RemoteRetrieval,
    /// Combines multiple applicability classes.
    Mixed,
}

/// CEC provider-selection behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
#[serde(rename_all = "snake_case")]
pub enum ProviderSelectionMode {
    /// Select/generate providers dynamically from runtime discovery.
    #[default]
    DynamicSynthesis,
    /// Use only capability-availability checks.
    CapabilityOnly,
}

/// CEC verification behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
#[serde(rename_all = "snake_case")]
pub enum VerificationMode {
    /// Verification material is generated/synthesized from runtime context.
    #[default]
    DynamicSynthesis,
    /// Verification is deterministic/static.
    DeterministicCheck,
}

/// Semantic query-binding class used by resolver feasibility policy.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Encode, Decode, Default,
)]
#[serde(rename_all = "snake_case")]
pub enum IntentQueryBindingClass {
    /// No additional semantic binding gate.
    #[default]
    None,
    /// Query must explicitly target host-local clock semantics.
    HostLocal,
    /// Query must require remote/public fact grounding.
    RemotePublicFact,
    /// Query must express app-launch direction.
    AppLaunchDirected,
    /// Query must express command execution direction.
    CommandDirected,
    /// Query must express direct UI input interaction.
    DirectUiInput,
    /// Query must request desktop screenshot capture.
    DesktopScreenshot,
    /// Query must request a durable local automation or monitor that keeps running.
    DurableAutomation,
    /// Query must request local model registry or residency control.
    ModelRegistryControl,
}

/// A single canonical intent catalog row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct IntentCatalogEntry {
    /// Stable intent identifier (for example: "web.research").
    pub intent_id: String,
    /// Canonical semantic descriptor used for embedding-based ranking.
    pub semantic_descriptor: String,
    /// Semantic query-binding gate used during feasibility filtering.
    #[serde(default)]
    pub query_binding: IntentQueryBindingClass,
    /// Canonical capability requirements that must be satisfiable for execution.
    #[serde(default)]
    pub required_capabilities: Vec<CapabilityId>,
    /// Coarse risk class label used for governance/policy overlays.
    pub risk_class: String,
    /// Ontological scope for this intent.
    pub scope: IntentScopeProfile,
    /// Preferred execution tier label (`tool_first`, `ax_first`, `visual_last`).
    pub preferred_tier: String,
    /// CEC applicability class for intent execution.
    #[serde(default)]
    pub applicability_class: ExecutionApplicabilityClass,
    /// Optional host-discovery override. When omitted, class defaults apply.
    #[serde(default)]
    pub requires_host_discovery: Option<bool>,
    /// Optional provider-selection mode.
    #[serde(default)]
    pub provider_selection_mode: Option<ProviderSelectionMode>,
    /// Required execution receipts for completion gate enforcement.
    #[serde(default)]
    pub required_evidence: Vec<String>,
    /// Required execution postconditions for completion gate enforcement.
    #[serde(default)]
    pub success_conditions: Vec<String>,
    /// Optional verification mode.
    #[serde(default)]
    pub verification_mode: Option<VerificationMode>,
    /// Optional alias metadata for observability and analytics only.
    /// Routing must not depend on this field.
    #[serde(default)]
    pub aliases: Vec<String>,
    /// Optional exemplar metadata for observability and analytics only.
    /// Routing must not depend on this field.
    #[serde(default)]
    pub exemplars: Vec<String>,
}

impl IntentCatalogEntry {
    /// Returns the effective host-discovery requirement after class defaults.
    pub fn effective_requires_host_discovery(&self) -> bool {
        self.requires_host_discovery.unwrap_or(matches!(
            self.applicability_class,
            ExecutionApplicabilityClass::TopologyDependent
        ))
    }

    /// Returns the effective provider-selection mode after class defaults.
    pub fn effective_provider_selection_mode(&self) -> ProviderSelectionMode {
        self.provider_selection_mode
            .unwrap_or(match self.applicability_class {
                ExecutionApplicabilityClass::TopologyDependent
                | ExecutionApplicabilityClass::Mixed => ProviderSelectionMode::DynamicSynthesis,
                ExecutionApplicabilityClass::DeterministicLocal
                | ExecutionApplicabilityClass::RemoteRetrieval => {
                    ProviderSelectionMode::CapabilityOnly
                }
            })
    }

    /// Returns the effective verification mode after class defaults.
    pub fn effective_verification_mode(&self) -> VerificationMode {
        self.verification_mode
            .unwrap_or(match self.applicability_class {
                ExecutionApplicabilityClass::TopologyDependent
                | ExecutionApplicabilityClass::Mixed => VerificationMode::DynamicSynthesis,
                ExecutionApplicabilityClass::DeterministicLocal
                | ExecutionApplicabilityClass::RemoteRetrieval => {
                    VerificationMode::DeterministicCheck
                }
            })
    }
}

/// Canonical capability identifier.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Encode, Decode,
)]
#[serde(transparent)]
pub struct CapabilityId(pub String);

impl CapabilityId {
    /// Returns this capability as a canonical string slice.
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl From<&str> for CapabilityId {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}

impl From<String> for CapabilityId {
    fn from(value: String) -> Self {
        Self(value)
    }
}

/// Deterministic mapping between a tool identity and its advertised capabilities.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct ToolCapabilityBinding {
    /// Canonical tool name (for example: "web__search").
    pub tool_name: String,
    /// Policy target associated with this tool.
    pub action_target: ActionTarget,
    /// Capabilities provided by this tool.
    #[serde(default)]
    pub capabilities: Vec<CapabilityId>,
}

/// Dynamic provider candidate considered for satisfying an intent capability family.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
#[serde(rename_all = "camelCase")]
pub struct ProviderRouteCandidate {
    /// Stable provider-family identifier used for tool filtering.
    pub provider_family: String,
    /// Stable provider route label used for CEC receipt emission.
    pub route_label: String,
    /// Connector/runtime source that owns this provider route.
    pub connector_id: String,
    /// Optional concrete provider/account identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_id: Option<String>,
    /// Optional human-readable account or mailbox label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_label: Option<String>,
    /// Capabilities satisfiable through this provider route.
    #[serde(default)]
    pub capabilities: Vec<CapabilityId>,
    /// Human-readable candidate summary for synthesis/audit.
    #[serde(default)]
    pub summary: String,
}

/// Provider-selection material attached to a resolved intent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
#[serde(rename_all = "camelCase")]
pub struct ProviderSelectionState {
    /// Effective provider-selection mode applied to this intent.
    #[serde(default)]
    pub mode: ProviderSelectionMode,
    /// Selected provider-family identifier, when disambiguated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_provider_family: Option<String>,
    /// Selected provider route label used by CEC receipts, when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_route_label: Option<String>,
    /// Selected concrete provider/account identifier, when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_provider_id: Option<String>,
    /// Selected connector/runtime owner, when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_connector_id: Option<String>,
    /// Deterministic selection basis (`single_available`, `semantic_match`, `unresolved`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selection_basis: Option<String>,
    /// Candidate provider routes evaluated for this intent.
    #[serde(default)]
    pub candidates: Vec<ProviderRouteCandidate>,
}

/// Origin provenance for a concrete argument value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
#[serde(rename_all = "snake_case")]
pub enum ArgumentOrigin {
    /// Exact user-specified span or literal.
    UserSpan,
    /// Resolved from runtime/session state.
    StateRef,
    /// Resolved from post-tool evidence.
    EvidenceRef,
    /// Filled by deterministic tool defaults.
    ToolDefault,
    /// Proposed by the model without admissible grounding.
    #[default]
    ModelInferred,
}

/// Protected slot family requiring explicit grounding before execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
#[serde(rename_all = "snake_case")]
pub enum ProtectedSlotKind {
    /// Arbitrary email address destination/source.
    EmailAddress,
    /// Connected account email for the selected provider route.
    AccountEmail,
    /// Calendar identifier.
    CalendarId,
    /// Generic remote or local resource identifier.
    ResourceId,
    /// Cloud project identifier.
    ProjectId,
    /// File identifier or storage handle.
    FileId,
    /// Non-protected or unspecified slot kind.
    #[default]
    Unknown,
}

/// Side-effect mode inferred from the user's requested end state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
#[serde(rename_all = "snake_case")]
pub enum InstructionSideEffectMode {
    /// No external state mutation is requested.
    None,
    /// Read-only or observational operation.
    ReadOnly,
    /// Create a draft or staged mutation without final dispatch.
    DraftOnly,
    /// Final outbound dispatch or commit.
    Send,
    /// Create a new resource.
    Create,
    /// Update an existing resource.
    Update,
    /// Delete an existing resource.
    Delete,
    /// Unknown side-effect semantics.
    #[default]
    Unknown,
}

/// Binding mode for an instruction slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
#[serde(rename_all = "snake_case")]
pub enum InstructionBindingKind {
    /// Slot should be grounded from a symbolic runtime reference.
    SymbolicRef,
    /// Slot is an explicit user-provided literal.
    UserLiteral,
    /// Slot remains unresolved and must not execute if protected.
    #[default]
    Unresolved,
}

/// Single slot binding extracted from the user request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
#[serde(rename_all = "camelCase")]
pub struct InstructionSlotBinding {
    /// Tool argument / slot name.
    pub slot: String,
    /// Binding mode for the slot.
    #[serde(default)]
    pub binding_kind: InstructionBindingKind,
    /// Symbolic reference or literal value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    /// Provenance for the resolved value.
    #[serde(default)]
    pub origin: ArgumentOrigin,
    /// Protected slot class, when the slot must be grounded.
    #[serde(default)]
    pub protected_slot_kind: ProtectedSlotKind,
}

/// Generic instruction contract synthesized from a user request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
#[serde(rename_all = "camelCase")]
pub struct InstructionContract {
    /// Normalized requested operation.
    #[serde(default)]
    pub operation: String,
    /// Side-effect mode for end-state verification and approval semantics.
    #[serde(default)]
    pub side_effect_mode: InstructionSideEffectMode,
    /// Slot bindings derived from the user's request.
    #[serde(default)]
    pub slot_bindings: Vec<InstructionSlotBinding>,
    /// Explicit negative constraints from the user's request.
    #[serde(default)]
    pub negative_constraints: Vec<String>,
    /// Required postconditions implied by the user's requested end state.
    #[serde(default)]
    pub success_criteria: Vec<String>,
}

/// Global policy for the step/action intent resolver.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct IntentRoutingPolicy {
    /// Enables or disables intent_catalog-scoped resolution.
    pub enabled: bool,
    /// Emits receipts without enforcing routing changes when true.
    pub shadow_mode: bool,
    /// Intent catalog schema/version marker.
    pub intent_catalog_version: String,
    /// Confidence thresholds for banding.
    pub confidence: IntentConfidenceBandPolicy,
    /// Ambiguity handling policy.
    pub ambiguity: IntentAmbiguityPolicy,
    /// Score quantization precision in basis points (1 bps = 0.0001).
    #[serde(default = "default_score_quantization_bps")]
    pub score_quantization_bps: u16,
    /// Deterministic tie region epsilon in basis points.
    #[serde(default = "default_tie_region_eps_bps")]
    pub tie_region_eps_bps: u16,
    /// Ambiguity abstention margin in basis points.
    #[serde(default = "default_ambiguity_margin_bps")]
    pub ambiguity_margin_bps: u16,
    /// Intents exempt from ambiguity abstention fallback.
    /// This is policy-defined and versioned behavior, not resolver heuristics.
    #[serde(default)]
    pub ambiguity_abstain_exempt_intents: Vec<String>,
    /// Baseline + override intent_catalog entries.
    #[serde(default)]
    pub intent_catalog: Vec<IntentCatalogEntry>,
}

fn default_score_quantization_bps() -> u16 {
    1
}

fn default_tie_region_eps_bps() -> u16 {
    25
}

fn default_ambiguity_margin_bps() -> u16 {
    50
}
impl Default for IntentRoutingPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            shadow_mode: false,
            intent_catalog_version: "intent-catalog-v15".to_string(),
            confidence: IntentConfidenceBandPolicy::default(),
            ambiguity: IntentAmbiguityPolicy::default(),
            score_quantization_bps: default_score_quantization_bps(),
            tie_region_eps_bps: default_tie_region_eps_bps(),
            ambiguity_margin_bps: default_ambiguity_margin_bps(),
            ambiguity_abstain_exempt_intents: vec![
                "app.launch".to_string(),
                "command.exec".to_string(),
                "command.exec.install_dependency".to_string(),
                "ui.capture_screenshot".to_string(),
            ],
            intent_catalog: default_intent_catalog(),
        }
    }
}

/// Persisted intent resolution state attached to an agent session.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Encode, Decode)]
pub struct ResolvedIntentState {
    /// Canonical winning intent id.
    pub intent_id: String,
    /// Ontological scope for this step.
    pub scope: IntentScopeProfile,
    /// Confidence band used for routing policy.
    pub band: IntentConfidenceBand,
    /// Winning confidence score in [0.0, 1.0].
    pub score: f32,
    /// Ranked candidate intents for observability/debug.
    #[serde(default)]
    pub top_k: Vec<IntentCandidateScore>,
    /// Required capabilities copied from the winning intent profile.
    #[serde(default)]
    pub required_capabilities: Vec<CapabilityId>,
    /// Required execution receipts copied from the winning intent profile.
    #[serde(default)]
    pub required_evidence: Vec<String>,
    /// Required execution postconditions copied from the winning intent profile.
    #[serde(default)]
    pub success_conditions: Vec<String>,
    /// Risk class copied from winning intent profile.
    #[serde(default)]
    pub risk_class: String,
    /// Preferred tier label resolved from intent_catalog profile.
    pub preferred_tier: String,
    /// IntentCatalog version used for this resolution.
    pub intent_catalog_version: String,
    /// Embedding model identifier used for ranking.
    #[serde(default)]
    pub embedding_model_id: String,
    /// Embedding model version used for ranking.
    #[serde(default)]
    pub embedding_model_version: String,
    /// Similarity function identifier used during retrieval.
    #[serde(default)]
    pub similarity_function_id: String,
    /// Hash commitment over the active intent set.
    #[serde(default)]
    pub intent_set_hash: [u8; 32],
    /// Hash commitment over the active tool capability registry.
    #[serde(default)]
    pub tool_registry_hash: [u8; 32],
    /// Hash commitment over the capability ontology.
    #[serde(default)]
    pub capability_ontology_hash: [u8; 32],
    /// Query normalization version used before embedding.
    #[serde(default)]
    pub query_normalization_version: String,
    /// Hash commitment to the active intent_catalog source.
    pub intent_catalog_source_hash: [u8; 32],
    /// Deterministic receipt hash over resolution material.
    pub evidence_requirements_hash: [u8; 32],
    /// Optional provider-selection material for connector-backed execution.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_selection: Option<ProviderSelectionState>,
    /// Optional generic instruction contract synthesized from the user request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instruction_contract: Option<InstructionContract>,
    /// Deprecated/compat: always false (constrained mode removed).
    #[serde(default)]
    pub constrained: bool,
}
