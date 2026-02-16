// Path: crates/types/src/app/agentic/security.rs

use crate::app::ActionTarget;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Configuration for the "Law" (Firewall) of an agent.
/// Defines the hard constraints and liabilities.
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, Default)]
pub struct FirewallPolicy {
    /// Maximum USD spend per execution (converted to tokens).
    pub budget_cap: f64,
    /// List of allowed DNS domains (e.g. "*.stripe.com").
    #[serde(default)]
    pub network_allowlist: Vec<String>,
    /// If true, execution halts for "Hold to Sign".
    pub require_human_gate: bool,
    /// Data egress policy ("none", "masked", "zero-knowledge").
    pub privacy_level: Option<String>,
}

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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
#[serde(rename_all = "snake_case")]
pub enum IntentAmbiguityAction {
    /// Pause execution and request user clarification.
    PauseForClarification,
    /// Continue, but keep tool exposure constrained.
    ConstrainedProceed,
    /// Continue with full scope.
    Proceed,
}

impl Default for IntentAmbiguityAction {
    fn default() -> Self {
        Self::PauseForClarification
    }
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
            medium_confidence_action: IntentAmbiguityAction::ConstrainedProceed,
        }
    }
}

/// A single canonical intent matrix row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct IntentMatrixEntry {
    /// Stable intent identifier (for example: "web.research").
    pub intent_id: String,
    /// Ontological scope for this intent.
    pub scope: IntentScopeProfile,
    /// Preferred execution tier label (`tool_first`, `ax_first`, `visual_last`).
    pub preferred_tier: String,
    /// Slang/non-normal aliases used for lexical projection and observability.
    #[serde(default)]
    pub aliases: Vec<String>,
    /// Canonical exemplars used for semantic embedding/ranking.
    #[serde(default)]
    pub exemplars: Vec<String>,
}

/// Global policy for the step/action intent resolver.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct IntentRoutingPolicy {
    /// Enables or disables matrix-scoped resolution.
    pub enabled: bool,
    /// Emits receipts without enforcing routing changes when true.
    pub shadow_mode: bool,
    /// Matrix schema/version marker.
    pub matrix_version: String,
    /// Confidence thresholds for banding.
    pub confidence: IntentConfidenceBandPolicy,
    /// Ambiguity handling policy.
    pub ambiguity: IntentAmbiguityPolicy,
    /// Baseline + override matrix entries.
    #[serde(default)]
    pub matrix: Vec<IntentMatrixEntry>,
}

impl Default for IntentRoutingPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            shadow_mode: false,
            matrix_version: "intent-matrix-v1".to_string(),
            confidence: IntentConfidenceBandPolicy::default(),
            ambiguity: IntentAmbiguityPolicy::default(),
            matrix: vec![
                IntentMatrixEntry {
                    intent_id: "conversation.reply".to_string(),
                    scope: IntentScopeProfile::Conversation,
                    preferred_tier: "tool_first".to_string(),
                    aliases: vec![
                        "chat".to_string(),
                        "reply".to_string(),
                        "explain".to_string(),
                        "summarize".to_string(),
                    ],
                    exemplars: vec![
                        "answer the user message".to_string(),
                        "draft a response".to_string(),
                    ],
                },
                IntentMatrixEntry {
                    intent_id: "web.research".to_string(),
                    scope: IntentScopeProfile::WebResearch,
                    preferred_tier: "tool_first".to_string(),
                    aliases: vec![
                        "web".to_string(),
                        "browse".to_string(),
                        "lookup".to_string(),
                        "search".to_string(),
                    ],
                    exemplars: vec![
                        "find information online".to_string(),
                        "crawl a url and summarize".to_string(),
                    ],
                },
                IntentMatrixEntry {
                    intent_id: "workspace.ops".to_string(),
                    scope: IntentScopeProfile::WorkspaceOps,
                    preferred_tier: "tool_first".to_string(),
                    aliases: vec![
                        "repo".to_string(),
                        "workspace".to_string(),
                        "codebase".to_string(),
                    ],
                    exemplars: vec![
                        "read files in the workspace".to_string(),
                        "edit code in repository".to_string(),
                    ],
                },
                IntentMatrixEntry {
                    intent_id: "app.launch".to_string(),
                    scope: IntentScopeProfile::AppLaunch,
                    preferred_tier: "tool_first".to_string(),
                    aliases: vec!["open app".to_string(), "launch".to_string()],
                    exemplars: vec!["open calculator".to_string(), "launch browser".to_string()],
                },
                IntentMatrixEntry {
                    intent_id: "ui.interaction".to_string(),
                    scope: IntentScopeProfile::UiInteraction,
                    preferred_tier: "visual_last".to_string(),
                    aliases: vec![
                        "click".to_string(),
                        "tap".to_string(),
                        "press".to_string(),
                        "type".to_string(),
                    ],
                    exemplars: vec![
                        "click the login button".to_string(),
                        "type into the focused field".to_string(),
                    ],
                },
                IntentMatrixEntry {
                    intent_id: "command.exec".to_string(),
                    scope: IntentScopeProfile::CommandExecution,
                    preferred_tier: "tool_first".to_string(),
                    aliases: vec![
                        "shell".to_string(),
                        "terminal".to_string(),
                        "run command".to_string(),
                    ],
                    exemplars: vec![
                        "run a command".to_string(),
                        "install dependency".to_string(),
                    ],
                },
                IntentMatrixEntry {
                    intent_id: "delegation.task".to_string(),
                    scope: IntentScopeProfile::Delegation,
                    preferred_tier: "tool_first".to_string(),
                    aliases: vec!["delegate".to_string(), "sub-agent".to_string()],
                    exemplars: vec![
                        "delegate this task".to_string(),
                        "spawn researcher agent".to_string(),
                    ],
                },
            ],
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
    /// Preferred tier label resolved from matrix profile.
    pub preferred_tier: String,
    /// Matrix version used for this resolution.
    pub matrix_version: String,
    /// Hash commitment to the active matrix source.
    pub matrix_source_hash: [u8; 32],
    /// Deterministic receipt hash over resolution material.
    pub receipt_hash: [u8; 32],
    /// True when resolver constrained tool scope due ambiguity policy.
    #[serde(default)]
    pub constrained: bool,
}

/// Canonical classes for PII and secret-like data.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Encode, Decode)]
#[serde(rename_all = "snake_case")]
pub enum PiiClass {
    /// API credentials such as provider keys.
    ApiKey,
    /// Secret bearer-like tokens and credentials.
    SecretToken,
    /// Email addresses.
    Email,
    /// Phone numbers.
    Phone,
    /// US Social Security numbers.
    Ssn,
    /// Payment card primary account number.
    CardPan,
    /// Natural-person names.
    Name,
    /// Street or mailing addresses.
    Address,
    /// Custom deployment-specific category.
    Custom(String),
}

/// Severity bucket used by policy and routing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
#[serde(rename_all = "snake_case")]
pub enum PiiSeverity {
    /// Low-impact personal data.
    Low,
    /// Medium-impact sensitive data.
    Medium,
    /// High-impact sensitive data.
    High,
    /// Highest-impact sensitive data.
    Critical,
}

/// Coarse confidence bucket used for deterministic policy gates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
#[serde(rename_all = "snake_case")]
pub enum PiiConfidenceBucket {
    /// Weak supporting evidence.
    Low,
    /// Moderate supporting evidence.
    Medium,
    /// Strong supporting evidence.
    High,
}

/// A single evidence span produced by deterministic Stage A detectors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct EvidenceSpan {
    /// Start byte index in the source UTF-8 string.
    pub start_index: u32,
    /// End byte index in the source UTF-8 string.
    pub end_index: u32,
    /// Classified PII class.
    pub pii_class: PiiClass,
    /// Severity label for routing and enforcement.
    pub severity: PiiSeverity,
    /// Confidence bucket emitted by deterministic scoring.
    pub confidence_bucket: PiiConfidenceBucket,
    /// Stable detector/pattern identifier (for example: "email/rfc5322-lite").
    pub pattern_id: String,
    /// Whether a deterministic validator passed (for example Luhn).
    pub validator_passed: bool,
    /// Supporting context keywords matched around the span.
    #[serde(default)]
    pub context_keywords: Vec<String>,
    /// Detector source for traceability (for example: "regex", "validator", "rule").
    pub evidence_source: String,
}

/// Deterministic Stage A output used by CIM routing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct EvidenceGraph {
    /// Schema version for forward compatibility.
    pub version: u32,
    /// SHA-256 hash of the analyzed input bytes.
    pub source_hash: [u8; 32],
    /// Evidence spans in stable order.
    #[serde(default)]
    pub spans: Vec<EvidenceSpan>,
    /// True if one or more spans remain ambiguous after deterministic refinement.
    pub ambiguous: bool,
}

impl Default for EvidenceGraph {
    fn default() -> Self {
        Self {
            version: 1,
            source_hash: [0u8; 32],
            spans: Vec::new(),
            ambiguous: false,
        }
    }
}

/// Action to execute for a transform plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
#[serde(rename_all = "snake_case")]
pub enum TransformAction {
    /// Replace sensitive spans with placeholders.
    Redact,
    /// Replace sensitive spans with deterministic token references.
    Tokenize,
    /// Isolate content pending review handling.
    Quarantine,
}

/// Deterministic transform plan chosen by CIM routing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct TransformPlan {
    /// Stable unique plan id.
    pub plan_id: String,
    /// Transform operation.
    pub action: TransformAction,
    /// Indices into `EvidenceGraph.spans` this plan applies to.
    #[serde(default)]
    pub span_indices: Vec<u32>,
    /// Optional redaction label.
    pub redaction_label: Option<String>,
    /// Optional token vault reference (opaque).
    pub token_ref: Option<String>,
}

/// Router result after Stage B/C policy evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
#[serde(rename_all = "snake_case")]
pub enum FirewallDecision {
    /// Permit requested action without modification.
    Allow,
    /// Permit only local continuation without egress.
    AllowLocalOnly,
    /// Apply redaction before permitting action.
    RedactThenAllow,
    /// Apply tokenization before permitting action.
    TokenizeThenAllow,
    /// Hold payload in quarantine flow.
    Quarantine,
    /// Deny the requested action.
    Deny,
    /// Pause for explicit user review.
    RequireUserReview,
}

impl Default for FirewallDecision {
    fn default() -> Self {
        Self::Allow
    }
}

/// Override mode for raw egress controls.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
#[serde(rename_all = "snake_case")]
pub enum RawOverrideMode {
    /// Raw egress overrides are fully disabled.
    Disabled,
    /// Raw overrides are restricted to low-severity classes and scoped grants.
    ScopedLowSeverityOnly,
}

impl Default for RawOverrideMode {
    fn default() -> Self {
        Self::Disabled
    }
}

/// Scoped policy exception minted by Stage 2 review flow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct PiiScopedException {
    /// Stable exception id.
    pub exception_id: String,
    /// PII classes this exception applies to.
    #[serde(default)]
    pub allowed_classes: Vec<PiiClass>,
    /// Destination binding hash.
    pub destination_hash: [u8; 32],
    /// Action binding hash.
    pub action_hash: [u8; 32],
    /// UNIX timestamp when this exception expires.
    pub expires_at: u64,
    /// Maximum permitted uses.
    pub max_uses: u32,
    /// Hash of the supplied justification text.
    pub justification_hash: [u8; 32],
}

/// Governance output for Stage 2 escalation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
#[serde(rename_all = "snake_case")]
pub enum Stage2Decision {
    /// Approve one deterministic transform plan.
    ApproveTransformPlan {
        /// Identifier of the approved transform plan.
        plan_id: String,
    },
    /// Deny the pending review request.
    Deny {
        /// Human-readable denial reason.
        reason: String,
    },
    /// Request additional context from the operator/user.
    RequestMoreInfo {
        /// Prompt template for required additional information.
        question_template: String,
    },
    /// Issue a scoped low-severity raw exception.
    GrantScopedException {
        /// Generated scope-constrained exception token.
        exception: PiiScopedException,
    },
}

/// Policy profile for local-only PII firewall execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct PiiControls {
    /// Enforces local-only PII analysis; raw content must not be sent to cloud models.
    pub local_only: bool,
    /// Enables transform-first behavior before escalation.
    pub safe_transform_enabled: bool,
    /// Timeout budget for Stage 2 review interaction.
    pub stage2_timeout_ms: u32,
    /// Raw egress override mode.
    pub raw_override_mode: RawOverrideMode,
    /// Global default for whether raw override capability is enabled.
    pub raw_override_default_enabled: bool,
    /// High-risk action targets that require fail-closed egress behavior.
    #[serde(default)]
    pub high_risk_targets: Vec<String>,
}

impl Default for PiiControls {
    fn default() -> Self {
        Self {
            local_only: true,
            safe_transform_enabled: true,
            stage2_timeout_ms: 2_000,
            raw_override_mode: RawOverrideMode::Disabled,
            raw_override_default_enabled: false,
            high_risk_targets: vec![
                "clipboard::write".to_string(),
                "net::fetch".to_string(),
                "browser::navigate::hermetic".to_string(),
                "ucp::checkout".to_string(),
            ],
        }
    }
}

/// Canonical target identity bound into PII decision material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PiiTarget {
    /// Standard action-target routing path.
    Action(ActionTarget),
    /// Raw service call routing path.
    ServiceCall {
        /// Service identifier being called.
        service_id: String,
        /// Method identifier on the service.
        method: String,
    },
    /// Outbound cloud inference request path.
    CloudInference {
        /// Inference provider identifier.
        provider: String,
        /// Model identifier.
        model: String,
    },
}

impl PiiTarget {
    /// Returns a human-readable canonical label for events/logs.
    pub fn canonical_label(&self) -> String {
        match self {
            PiiTarget::Action(target) => target.canonical_label(),
            PiiTarget::ServiceCall { service_id, method } => {
                format!("{service_id}::{method}")
            }
            PiiTarget::CloudInference { provider, model } => {
                format!("cloud_inference::{provider}::{model}")
            }
        }
    }
}

/// Canonical deterministic material used to compute decision hashes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct PiiDecisionMaterial {
    /// Schema version for stable future evolution.
    pub version: u32,
    /// The evaluated action target.
    pub target: PiiTarget,
    /// Risk surface used during evaluation.
    pub risk_surface: String,
    /// Whether the evaluated call path supports deterministic transforms.
    pub supports_transform: bool,
    /// Hash of source input bytes used for inspection.
    pub source_hash: [u8; 32],
    /// Number of evidence spans in scope.
    pub span_count: u32,
    /// Whether ambiguity remained after deterministic assist/refinement.
    pub ambiguous: bool,
    /// Final firewall decision.
    pub decision: FirewallDecision,
    /// Optional selected transform plan id.
    pub transform_plan_id: Option<String>,
    /// Optional stage2 decision kind for review traceability.
    pub stage2_kind: Option<String>,
    /// Whether an assist provider was invoked.
    pub assist_invoked: bool,
    /// Whether the assist output graph differs from the input graph.
    pub assist_applied: bool,
    /// Deterministic assist provider kind (for example: "noop", "cim_wasm").
    pub assist_kind: String,
    /// Deterministic assist provider version (for example: "noop-v1").
    pub assist_version: String,
    /// Hash commitment to assist identity/config.
    pub assist_identity_hash: [u8; 32],
    /// Hash of assist input EvidenceGraph SCALE bytes.
    pub assist_input_graph_hash: [u8; 32],
    /// Hash of assist output EvidenceGraph SCALE bytes.
    pub assist_output_graph_hash: [u8; 32],
}

/// Human-readable summary attached to a deterministic PII review request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct PiiReviewSummary {
    /// Canonical display label for the target.
    pub target_label: String,
    /// Compact summary of in-scope spans.
    pub span_summary: String,
    /// Deterministic class histogram for review UX/debugging.
    #[serde(default)]
    pub class_counts: BTreeMap<String, u32>,
    /// Deterministic severity histogram for review UX/debugging.
    #[serde(default)]
    pub severity_counts: BTreeMap<String, u32>,
    /// Stage2 prompt text to guide operator action.
    pub stage2_prompt: String,
}

/// Canonical persisted request object for PII review.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct PiiReviewRequest {
    /// Schema version for forward compatibility.
    pub request_version: u32,
    /// Deterministic decision hash key.
    pub decision_hash: [u8; 32],
    /// Canonical deterministic material used to reproduce this decision.
    pub material: PiiDecisionMaterial,
    /// Human-readable context for UI/operator.
    pub summary: PiiReviewSummary,
    /// Session this request belongs to when available.
    pub session_id: Option<[u8; 32]>,
    /// Creation timestamp in milliseconds since UNIX epoch.
    pub created_at_ms: u64,
    /// Deterministic deadline timestamp in milliseconds since UNIX epoch.
    pub deadline_ms: u64,
}

/// Auditable receipt emitted for PII routing outcomes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct PiiDecisionReceipt {
    /// Canonical decision hash.
    pub decision_hash: [u8; 32],
    /// The evaluated action target.
    pub target: String,
    /// Risk surface used during evaluation.
    pub risk_surface: String,
    /// Final firewall decision.
    pub decision: FirewallDecision,
    /// Optional selected transform plan id.
    pub transform_plan_id: Option<String>,
    /// Whether an assist provider was invoked.
    pub assist_invoked: bool,
    /// Whether the assist output graph differs from the input graph.
    pub assist_applied: bool,
    /// Deterministic assist provider kind.
    pub assist_kind: String,
    /// Deterministic assist provider version.
    pub assist_version: String,
    /// Hash commitment to assist identity/config.
    pub assist_identity_hash: [u8; 32],
    /// Hash of assist input EvidenceGraph SCALE bytes.
    pub assist_input_graph_hash: [u8; 32],
    /// Hash of assist output EvidenceGraph SCALE bytes.
    pub assist_output_graph_hash: [u8; 32],
}
