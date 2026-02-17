// Path: crates/pii/src/lib.rs

use anyhow::Result;
use dcrypt::algorithms::hash::{HashFunction, Sha256};
use ioi_types::app::action::{ApprovalToken, PiiApprovalAction};
use ioi_types::app::agentic::{
    EvidenceGraph, EvidenceSpan, FirewallDecision, PiiClass, PiiControls, PiiDecisionMaterial,
    PiiReviewRequest, PiiReviewSummary, PiiScopedException, PiiSeverity, PiiTarget,
    RawOverrideMode, Stage2Decision, TransformAction, TransformPlan,
};
use ioi_types::app::ActionTarget;
use ioi_types::app::{RedactionEntry, RedactionMap, RedactionType};
use parity_scale_codec::Encode;
use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;

mod cim_v0;

pub use cim_v0::{CimAssistV0Config, CimAssistV0Provider};

/// Risk surface evaluated by the shared PII core.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiskSurface {
    LocalProcessing,
    Egress,
}

/// Boxed async inspector future used by `inspect_and_route_with`.
pub type InspectFuture<'a> = Pin<Box<dyn Future<Output = Result<EvidenceGraph>> + Send + 'a>>;

/// Assist invocation context for Stage A -> A' refinement.
pub struct CimAssistContext<'a> {
    pub target: &'a PiiTarget,
    pub risk_surface: RiskSurface,
    pub policy: &'a PiiControls,
    pub supports_transform: bool,
}

/// Structured result returned by a CIM assist provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CimAssistResult {
    pub output_graph: EvidenceGraph,
    pub assist_applied: bool,
}

/// Deterministic assist receipt bound into decision hash material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CimAssistReceipt {
    pub assist_invoked: bool,
    pub assist_applied: bool,
    pub assist_kind: String,
    pub assist_version: String,
    pub assist_identity_hash: [u8; 32],
    pub assist_config_hash: [u8; 32],
    pub assist_module_hash: [u8; 32],
    pub assist_input_graph_hash: [u8; 32],
    pub assist_output_graph_hash: [u8; 32],
}

/// Seam for deterministic Stage A -> A' assist providers.
pub trait CimAssistProvider: Send + Sync {
    fn assist_kind(&self) -> &str;
    fn assist_version(&self) -> &str;
    fn assist_config_hash(&self) -> [u8; 32] {
        [0u8; 32]
    }
    fn assist_module_hash(&self) -> [u8; 32] {
        [0u8; 32]
    }
    fn assist_identity_hash(&self) -> [u8; 32] {
        assist_identity_hash(
            self.assist_kind(),
            self.assist_version(),
            self.assist_config_hash(),
            self.assist_module_hash(),
        )
    }
    fn assist(&self, graph: &EvidenceGraph, ctx: &CimAssistContext<'_>) -> Result<CimAssistResult>;
}

/// Default deterministic no-op assist provider.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopCimAssistProvider;

impl CimAssistProvider for NoopCimAssistProvider {
    fn assist_kind(&self) -> &str {
        "noop"
    }

    fn assist_version(&self) -> &str {
        "noop-v1"
    }

    fn assist(
        &self,
        graph: &EvidenceGraph,
        _ctx: &CimAssistContext<'_>,
    ) -> Result<CimAssistResult> {
        Ok(CimAssistResult {
            output_graph: graph.clone(),
            assist_applied: false,
        })
    }
}

/// Stage B/C rules-only routing outcome for the local PII firewall.
#[derive(Debug, Clone)]
pub struct PiiRoutingOutcome {
    pub decision: FirewallDecision,
    pub transform_plan: Option<TransformPlan>,
    pub stage2_decision: Option<Stage2Decision>,
    pub assist: CimAssistReceipt,
    pub decision_hash: [u8; 32],
}

/// Post-transform enforcement report for deterministic Stage C checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostTransformReport {
    pub transformed: bool,
    pub unresolved_spans: u32,
    pub remaining_span_count: u32,
    /// True when no original raw span substrings remain in output.
    pub no_raw_substring_leak: bool,
}

fn risk_surface_label(risk_surface: RiskSurface) -> &'static str {
    match risk_surface {
        RiskSurface::LocalProcessing => "local_processing",
        RiskSurface::Egress => "egress",
    }
}

fn stage2_kind(stage2: Option<&Stage2Decision>) -> Option<String> {
    stage2.map(|d| {
        match d {
            Stage2Decision::ApproveTransformPlan { .. } => "approve_transform_plan",
            Stage2Decision::Deny { .. } => "deny",
            Stage2Decision::RequestMoreInfo { .. } => "request_more_info",
            Stage2Decision::GrantScopedException { .. } => "grant_scoped_exception",
        }
        .to_string()
    })
}

fn action_target_from_label(label: &str) -> Option<ActionTarget> {
    match label {
        "net::fetch" => Some(ActionTarget::NetFetch),
        "web::retrieve" => Some(ActionTarget::WebRetrieve),
        "fs::write" => Some(ActionTarget::FsWrite),
        "fs::read" => Some(ActionTarget::FsRead),
        "ui::click" => Some(ActionTarget::UiClick),
        "ui::type" => Some(ActionTarget::UiType),
        "sys::exec" => Some(ActionTarget::SysExec),
        "sys::install_package" => Some(ActionTarget::SysInstallPackage),
        "wallet::sign" => Some(ActionTarget::WalletSign),
        "wallet::send" => Some(ActionTarget::WalletSend),
        "gui::mouse_move" => Some(ActionTarget::GuiMouseMove),
        "gui::click" => Some(ActionTarget::GuiClick),
        "gui::type" => Some(ActionTarget::GuiType),
        "gui::screenshot" => Some(ActionTarget::GuiScreenshot),
        "gui::scroll" => Some(ActionTarget::GuiScroll),
        "gui::sequence" => Some(ActionTarget::GuiSequence),
        "browser::interact" => Some(ActionTarget::BrowserInteract),
        "browser::inspect" => Some(ActionTarget::BrowserInspect),
        "ucp::discovery" => Some(ActionTarget::CommerceDiscovery),
        "ucp::checkout" => Some(ActionTarget::CommerceCheckout),
        "os::focus" => Some(ActionTarget::WindowFocus),
        "clipboard::read" => Some(ActionTarget::ClipboardRead),
        "clipboard::write" => Some(ActionTarget::ClipboardWrite),
        _ => None,
    }
}

fn legacy_target_from_str(label: &str) -> PiiTarget {
    if let Some(action_target) = action_target_from_label(label) {
        return PiiTarget::Action(action_target);
    }

    let mut split = label.splitn(2, "::");
    let service_id = split.next().unwrap_or_default();
    let method = split.next().unwrap_or_default();
    if !service_id.is_empty() && !method.is_empty() && !label.ends_with("::") {
        return PiiTarget::ServiceCall {
            service_id: service_id.to_string(),
            method: method.to_string(),
        };
    }

    PiiTarget::Action(ActionTarget::Custom(label.to_string()))
}

fn sha256_array(input: &[u8]) -> Result<[u8; 32]> {
    let digest = Sha256::digest(input)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_ref());
    Ok(out)
}

fn graph_hash(graph: &EvidenceGraph) -> [u8; 32] {
    sha256_array(&graph.encode()).unwrap_or([0u8; 32])
}

pub const DEFAULT_SCOPED_EXCEPTION_TTL_SECS: u64 = 300;
pub const DEFAULT_SCOPED_EXCEPTION_MAX_USES: u32 = 1;
pub const REVIEW_REQUEST_VERSION: u32 = 3;

/// Review-mode indicator returned by contract validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResumeReviewMode {
    /// Traditional approval flow without a persisted review request.
    LegacyApproval,
    /// Review-bound approval flow with persisted request + explicit action.
    ReviewBound,
}

/// Deterministic validation errors for the review resume contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PiiReviewContractError {
    ApprovalTokenHashMismatch,
    MissingReviewRequest,
    ReviewRequestHashMismatch,
    UnsupportedReviewRequestVersion { found: u32, expected: u32 },
    ReviewApprovalDeadlineExceeded,
    MissingPiiActionForReview,
    PiiActionWithoutReviewRequest,
    AssistKindMismatch { found: String, expected: String },
    AssistVersionMismatch { found: String, expected: String },
    AssistIdentityHashMismatch { found: [u8; 32], expected: [u8; 32] },
    InvalidExceptionUsageState,
    ExceptionUsageOverflow,
}

impl std::fmt::Display for PiiReviewContractError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PiiReviewContractError::ApprovalTokenHashMismatch => {
                write!(f, "Approval token hash mismatch")
            }
            PiiReviewContractError::MissingReviewRequest => {
                write!(f, "Missing PII review request for pending decision")
            }
            PiiReviewContractError::ReviewRequestHashMismatch => {
                write!(f, "PII review request hash mismatch")
            }
            PiiReviewContractError::UnsupportedReviewRequestVersion { found, expected } => {
                write!(
                    f,
                    "Unsupported PII review request version {} (expected {}).",
                    found, expected
                )
            }
            PiiReviewContractError::ReviewApprovalDeadlineExceeded => {
                write!(f, "PII review approval deadline exceeded")
            }
            PiiReviewContractError::MissingPiiActionForReview => {
                write!(f, "PII review request requires explicit pii_action")
            }
            PiiReviewContractError::PiiActionWithoutReviewRequest => {
                write!(f, "PII action provided but no review request exists")
            }
            PiiReviewContractError::AssistKindMismatch { found, expected } => write!(
                f,
                "PII review request assist kind mismatch (found='{}', expected='{}')",
                found, expected
            ),
            PiiReviewContractError::AssistVersionMismatch { found, expected } => write!(
                f,
                "PII review request assist version mismatch (found='{}', expected='{}')",
                found, expected
            ),
            PiiReviewContractError::AssistIdentityHashMismatch { found, expected } => write!(
                f,
                "PII review request assist identity hash mismatch (found={}, expected={})",
                hex::encode(found),
                hex::encode(expected)
            ),
            PiiReviewContractError::InvalidExceptionUsageState => {
                write!(f, "Scoped exception usage state is invalid")
            }
            PiiReviewContractError::ExceptionUsageOverflow => {
                write!(f, "Scoped exception usage counter overflow")
            }
        }
    }
}

impl std::error::Error for PiiReviewContractError {}

/// Returns the expected deterministic CIM assist identity for review-contract compatibility.
pub fn expected_assist_identity() -> (String, String, [u8; 32]) {
    let provider = CimAssistV0Provider::default();
    (
        provider.assist_kind().to_string(),
        provider.assist_version().to_string(),
        provider.assist_identity_hash(),
    )
}

/// Validates that a review request is compatible with the locked v3+CIM contract.
pub fn validate_review_request_compat(
    req: &PiiReviewRequest,
) -> std::result::Result<(), PiiReviewContractError> {
    if req.request_version != REVIEW_REQUEST_VERSION {
        return Err(PiiReviewContractError::UnsupportedReviewRequestVersion {
            found: req.request_version,
            expected: REVIEW_REQUEST_VERSION,
        });
    }
    let (expected_kind, expected_version, expected_identity_hash) = expected_assist_identity();
    if req.material.assist_kind != expected_kind {
        return Err(PiiReviewContractError::AssistKindMismatch {
            found: req.material.assist_kind.clone(),
            expected: expected_kind,
        });
    }
    if req.material.assist_version != expected_version {
        return Err(PiiReviewContractError::AssistVersionMismatch {
            found: req.material.assist_version.clone(),
            expected: expected_version,
        });
    }
    if req.material.assist_identity_hash != expected_identity_hash {
        return Err(PiiReviewContractError::AssistIdentityHashMismatch {
            found: req.material.assist_identity_hash,
            expected: expected_identity_hash,
        });
    }
    Ok(())
}

/// Resolves the expected review decision hash.
///
/// If an incident pending gate hash exists it is canonical; otherwise fallback to pending tool hash.
pub fn resolve_expected_request_hash(
    pending_gate_hash: Option<[u8; 32]>,
    pending_tool_hash: [u8; 32],
) -> [u8; 32] {
    pending_gate_hash.unwrap_or(pending_tool_hash)
}

/// Validates resume-token review contract invariants.
pub fn validate_resume_review_contract(
    expected_request_hash: [u8; 32],
    approval_token: &ApprovalToken,
    review_request: Option<&PiiReviewRequest>,
    now_ms: u64,
) -> std::result::Result<ResumeReviewMode, PiiReviewContractError> {
    if approval_token.request_hash != expected_request_hash {
        return Err(PiiReviewContractError::ApprovalTokenHashMismatch);
    }

    let Some(request) = review_request else {
        // Legacy approvals are not review-bound. We still allow explicit denial for
        // non-review (policy) gates so UIs can deterministically clear pending actions
        // without minting a review request.
        if let Some(action) = approval_token.pii_action.as_ref() {
            if !matches!(action, PiiApprovalAction::Deny) {
                return Err(PiiReviewContractError::PiiActionWithoutReviewRequest);
            }
        }
        return Ok(ResumeReviewMode::LegacyApproval);
    };

    if request.decision_hash != expected_request_hash {
        return Err(PiiReviewContractError::ReviewRequestHashMismatch);
    }
    validate_review_request_compat(request)?;
    if now_ms > request.deadline_ms {
        return Err(PiiReviewContractError::ReviewApprovalDeadlineExceeded);
    }
    if approval_token.pii_action.is_none() {
        return Err(PiiReviewContractError::MissingPiiActionForReview);
    }

    Ok(ResumeReviewMode::ReviewBound)
}

/// Decodes a scoped-exception usage counter from state bytes.
pub fn decode_exception_usage_state(
    raw_usage: Option<&[u8]>,
) -> std::result::Result<u32, PiiReviewContractError> {
    match raw_usage {
        None => Ok(0),
        Some(bytes) => ioi_types::codec::from_bytes_canonical::<u32>(bytes)
            .map_err(|_| PiiReviewContractError::InvalidExceptionUsageState),
    }
}

/// Computes the next scoped-exception usage value with overflow protection.
pub fn check_exception_usage_increment_ok(
    uses_consumed: u32,
) -> std::result::Result<u32, PiiReviewContractError> {
    uses_consumed
        .checked_add(1)
        .ok_or(PiiReviewContractError::ExceptionUsageOverflow)
}

fn assist_identity_hash(
    kind: &str,
    version: &str,
    config_hash: [u8; 32],
    module_hash: [u8; 32],
) -> [u8; 32] {
    let material = (
        kind.to_string(),
        version.to_string(),
        config_hash,
        module_hash,
    )
        .encode();
    sha256_array(&material).unwrap_or([0u8; 32])
}

fn build_assist_receipt<P: CimAssistProvider + ?Sized>(
    provider: &P,
    input_graph: &EvidenceGraph,
    output_graph: &EvidenceGraph,
    assist_applied: bool,
) -> CimAssistReceipt {
    let assist_config_hash = provider.assist_config_hash();
    let assist_module_hash = provider.assist_module_hash();
    CimAssistReceipt {
        assist_invoked: true,
        assist_applied,
        assist_kind: provider.assist_kind().to_string(),
        assist_version: provider.assist_version().to_string(),
        assist_identity_hash: assist_identity_hash(
            provider.assist_kind(),
            provider.assist_version(),
            assist_config_hash,
            assist_module_hash,
        ),
        assist_config_hash,
        assist_module_hash,
        assist_input_graph_hash: graph_hash(input_graph),
        assist_output_graph_hash: graph_hash(output_graph),
    }
}

fn has_high_severity(graph: &EvidenceGraph) -> bool {
    graph
        .spans
        .iter()
        .any(|s| matches!(s.severity, PiiSeverity::High | PiiSeverity::Critical))
}

fn has_only_low_severity(graph: &EvidenceGraph) -> bool {
    !graph.spans.is_empty()
        && graph
            .spans
            .iter()
            .all(|s| matches!(s.severity, PiiSeverity::Low))
}

fn is_secret_heavy(graph: &EvidenceGraph) -> bool {
    graph
        .spans
        .iter()
        .any(|s| matches!(s.pii_class, PiiClass::ApiKey | PiiClass::SecretToken))
}

fn build_transform_plan(target: &PiiTarget, graph: &EvidenceGraph) -> TransformPlan {
    let target_label = target.canonical_label();
    let span_indices = (0..graph.spans.len() as u32).collect::<Vec<_>>();

    if is_secret_heavy(graph) {
        TransformPlan {
            plan_id: format!("tokenize::{target_label}"),
            action: TransformAction::Tokenize,
            span_indices,
            redaction_label: None,
            token_ref: Some(format!("tokref::{}", hex::encode(graph.source_hash))),
        }
    } else {
        TransformPlan {
            plan_id: format!("redact::{target_label}"),
            action: TransformAction::Redact,
            span_indices,
            redaction_label: Some("REDACTED".to_string()),
            token_ref: None,
        }
    }
}

/// Builds canonical deterministic decision material from a routed outcome.
pub fn build_decision_material(
    graph: &EvidenceGraph,
    decision: &FirewallDecision,
    transform_plan: Option<&TransformPlan>,
    stage2_decision: Option<&Stage2Decision>,
    risk_surface: RiskSurface,
    target: &PiiTarget,
    supports_transform: bool,
    assist: &CimAssistReceipt,
) -> PiiDecisionMaterial {
    PiiDecisionMaterial {
        version: 3,
        target: target.clone(),
        risk_surface: risk_surface_label(risk_surface).to_string(),
        supports_transform,
        source_hash: graph.source_hash,
        span_count: graph.spans.len() as u32,
        ambiguous: graph.ambiguous,
        decision: decision.clone(),
        transform_plan_id: transform_plan.map(|p| p.plan_id.clone()),
        stage2_kind: stage2_kind(stage2_decision),
        assist_invoked: assist.assist_invoked,
        assist_applied: assist.assist_applied,
        assist_kind: assist.assist_kind.clone(),
        assist_version: assist.assist_version.clone(),
        assist_identity_hash: assist.assist_identity_hash,
        assist_input_graph_hash: assist.assist_input_graph_hash,
        assist_output_graph_hash: assist.assist_output_graph_hash,
    }
}

/// Computes the canonical decision hash for a fully-populated decision material payload.
pub fn compute_decision_hash(material: &PiiDecisionMaterial) -> [u8; 32] {
    sha256_array(&material.encode()).unwrap_or([0u8; 32])
}

fn decision_hash(
    graph: &EvidenceGraph,
    decision: &FirewallDecision,
    transform_plan: Option<&TransformPlan>,
    stage2_decision: Option<&Stage2Decision>,
    risk_surface: RiskSurface,
    target: &PiiTarget,
    supports_transform: bool,
    assist: &CimAssistReceipt,
) -> [u8; 32] {
    let material = build_decision_material(
        graph,
        decision,
        transform_plan,
        stage2_decision,
        risk_surface,
        target,
        supports_transform,
        assist,
    );

    compute_decision_hash(&material)
}

fn with_hash(
    graph: &EvidenceGraph,
    decision: FirewallDecision,
    transform_plan: Option<TransformPlan>,
    stage2_decision: Option<Stage2Decision>,
    risk_surface: RiskSurface,
    target: &PiiTarget,
    supports_transform: bool,
    assist: &CimAssistReceipt,
) -> PiiRoutingOutcome {
    let hash = decision_hash(
        graph,
        &decision,
        transform_plan.as_ref(),
        stage2_decision.as_ref(),
        risk_surface,
        target,
        supports_transform,
        assist,
    );

    PiiRoutingOutcome {
        decision,
        transform_plan,
        stage2_decision,
        assist: assist.clone(),
        decision_hash: hash,
    }
}

/// Returns true if the target is configured as high-risk egress.
pub fn is_high_risk_target(policy: &PiiControls, target: &PiiTarget) -> bool {
    let label = target.canonical_label();
    policy
        .high_risk_targets
        .iter()
        .any(|configured| configured == &label)
}

/// Compatibility wrapper for legacy string targets.
#[deprecated(note = "Use is_high_risk_target(policy, &PiiTarget) instead")]
pub fn is_high_risk_target_legacy(policy: &PiiControls, target: &str) -> bool {
    let mapped = legacy_target_from_str(target);
    is_high_risk_target(policy, &mapped)
}

fn pii_class_key(class: &PiiClass) -> String {
    match class {
        PiiClass::ApiKey => "api_key".to_string(),
        PiiClass::SecretToken => "secret_token".to_string(),
        PiiClass::Email => "email".to_string(),
        PiiClass::Phone => "phone".to_string(),
        PiiClass::Ssn => "ssn".to_string(),
        PiiClass::CardPan => "card_pan".to_string(),
        PiiClass::Name => "name".to_string(),
        PiiClass::Address => "address".to_string(),
        PiiClass::Custom(label) => format!("custom:{label}"),
    }
}

fn severity_key(severity: PiiSeverity) -> &'static str {
    match severity {
        PiiSeverity::Low => "low",
        PiiSeverity::Medium => "medium",
        PiiSeverity::High => "high",
        PiiSeverity::Critical => "critical",
    }
}

fn collect_low_severity_classes(graph: &EvidenceGraph) -> Vec<PiiClass> {
    let mut by_key = BTreeMap::<String, PiiClass>::new();
    for span in &graph.spans {
        if matches!(span.severity, PiiSeverity::Low) {
            by_key.insert(pii_class_key(&span.pii_class), span.pii_class.clone());
        }
    }
    by_key.into_values().collect()
}

fn has_blocking_scoped_exception_evidence(graph: &EvidenceGraph) -> bool {
    graph.spans.iter().any(|span| {
        matches!(span.severity, PiiSeverity::High | PiiSeverity::Critical)
            || matches!(span.pii_class, PiiClass::ApiKey | PiiClass::SecretToken)
    })
}

fn canonical_class_keys(classes: &[PiiClass]) -> Vec<String> {
    let mut keys = classes.iter().map(pii_class_key).collect::<Vec<_>>();
    keys.sort();
    keys.dedup();
    keys
}

fn stage2_prompt(stage2_decision: Option<&Stage2Decision>) -> String {
    match stage2_decision {
        Some(Stage2Decision::RequestMoreInfo { question_template }) => question_template.clone(),
        Some(Stage2Decision::Deny { reason }) => format!("Denied: {reason}"),
        Some(Stage2Decision::ApproveTransformPlan { plan_id }) => {
            format!("Approve deterministic transform plan '{plan_id}'?")
        }
        Some(Stage2Decision::GrantScopedException { .. }) => {
            "Grant a scoped low-severity exception for this decision?".to_string()
        }
        None => "Review PII decision and choose transform approval, scoped exception, or deny."
            .to_string(),
    }
}

/// Builds a deterministic summary blob for review UX.
pub fn build_review_summary(
    graph: &EvidenceGraph,
    target: &PiiTarget,
    stage2_decision: Option<&Stage2Decision>,
) -> PiiReviewSummary {
    let mut class_counts = BTreeMap::<String, u32>::new();
    let mut severity_counts = BTreeMap::<String, u32>::new();

    for span in &graph.spans {
        *class_counts
            .entry(pii_class_key(&span.pii_class))
            .or_default() += 1;
        *severity_counts
            .entry(severity_key(span.severity).to_string())
            .or_default() += 1;
    }

    let classes = if class_counts.is_empty() {
        "none".to_string()
    } else {
        class_counts
            .iter()
            .map(|(class, count)| format!("{class}:{count}"))
            .collect::<Vec<_>>()
            .join(",")
    };
    let severities = if severity_counts.is_empty() {
        "none".to_string()
    } else {
        severity_counts
            .iter()
            .map(|(sev, count)| format!("{sev}:{count}"))
            .collect::<Vec<_>>()
            .join(",")
    };

    PiiReviewSummary {
        target_label: target.canonical_label(),
        span_summary: format!(
            "spans={}, ambiguous={}, classes=[{}], severities=[{}]",
            graph.spans.len(),
            graph.ambiguous,
            classes,
            severities
        ),
        class_counts,
        severity_counts,
        stage2_prompt: stage2_prompt(stage2_decision),
    }
}

/// Computes destination binding hash for scoped exception verification.
pub fn scoped_exception_destination_hash(
    target: &PiiTarget,
    risk_surface: RiskSurface,
) -> [u8; 32] {
    let material = (target.clone(), risk_surface_label(risk_surface).to_string()).encode();
    sha256_array(&material).unwrap_or([0u8; 32])
}

/// Mints a locked default scoped exception for low-severity-only evidence.
pub fn mint_default_scoped_exception(
    graph: &EvidenceGraph,
    target: &PiiTarget,
    risk_surface: RiskSurface,
    decision_hash: [u8; 32],
    now_unix: u64,
    justification: &str,
) -> Result<PiiScopedException> {
    if has_blocking_scoped_exception_evidence(graph) {
        anyhow::bail!("Scoped exception denied: high-severity or secret class present.");
    }
    let allowed_classes = collect_low_severity_classes(graph);
    if allowed_classes.is_empty() {
        anyhow::bail!("Scoped exception denied: no low-severity classes in evidence.");
    }

    let destination_hash = scoped_exception_destination_hash(target, risk_surface);
    let justification_hash = sha256_array(justification.as_bytes()).unwrap_or([0u8; 32]);
    let id_material = (
        "scoped_low_severity_v1".to_string(),
        destination_hash,
        decision_hash,
        canonical_class_keys(&allowed_classes),
        justification_hash,
    )
        .encode();
    let exception_id_hash = sha256_array(&id_material).unwrap_or([0u8; 32]);

    Ok(PiiScopedException {
        exception_id: format!("scope::{}", hex::encode(exception_id_hash)),
        allowed_classes,
        destination_hash,
        action_hash: decision_hash,
        expires_at: now_unix.saturating_add(DEFAULT_SCOPED_EXCEPTION_TTL_SECS),
        max_uses: DEFAULT_SCOPED_EXCEPTION_MAX_USES,
        justification_hash,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopedExceptionVerifyError {
    PolicyDisabled,
    MissingAllowedClasses,
    DestinationMismatch,
    ActionMismatch,
    Expired,
    Overused,
    IneligibleEvidence,
    ClassMismatch,
    InvalidMaxUses,
}

impl std::fmt::Display for ScopedExceptionVerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match self {
            ScopedExceptionVerifyError::PolicyDisabled => "policy does not allow scoped exceptions",
            ScopedExceptionVerifyError::MissingAllowedClasses => "missing allowed classes",
            ScopedExceptionVerifyError::DestinationMismatch => "destination binding mismatch",
            ScopedExceptionVerifyError::ActionMismatch => "action binding mismatch",
            ScopedExceptionVerifyError::Expired => "exception expired",
            ScopedExceptionVerifyError::Overused => "exception overused",
            ScopedExceptionVerifyError::IneligibleEvidence => "evidence is not low-severity-only",
            ScopedExceptionVerifyError::ClassMismatch => "allowed classes mismatch evidence",
            ScopedExceptionVerifyError::InvalidMaxUses => "invalid max_uses",
        };
        write!(f, "{msg}")
    }
}

impl std::error::Error for ScopedExceptionVerifyError {}

/// Verifies a scoped exception against the current deterministic decision context.
pub fn verify_scoped_exception_for_decision(
    exception: &PiiScopedException,
    graph: &EvidenceGraph,
    target: &PiiTarget,
    risk_surface: RiskSurface,
    decision_hash: [u8; 32],
    policy: &PiiControls,
    now_unix: u64,
    uses_consumed: u32,
) -> std::result::Result<(), ScopedExceptionVerifyError> {
    if !matches!(
        policy.raw_override_mode,
        RawOverrideMode::ScopedLowSeverityOnly
    ) {
        return Err(ScopedExceptionVerifyError::PolicyDisabled);
    }
    if exception.allowed_classes.is_empty() {
        return Err(ScopedExceptionVerifyError::MissingAllowedClasses);
    }
    if exception.max_uses == 0 {
        return Err(ScopedExceptionVerifyError::InvalidMaxUses);
    }
    if uses_consumed >= exception.max_uses {
        return Err(ScopedExceptionVerifyError::Overused);
    }
    if now_unix >= exception.expires_at {
        return Err(ScopedExceptionVerifyError::Expired);
    }

    let expected_destination = scoped_exception_destination_hash(target, risk_surface);
    if expected_destination != exception.destination_hash {
        return Err(ScopedExceptionVerifyError::DestinationMismatch);
    }
    if exception.action_hash != decision_hash {
        return Err(ScopedExceptionVerifyError::ActionMismatch);
    }

    if has_blocking_scoped_exception_evidence(graph) {
        return Err(ScopedExceptionVerifyError::IneligibleEvidence);
    }
    let expected_classes = collect_low_severity_classes(graph);
    if expected_classes.is_empty() {
        return Err(ScopedExceptionVerifyError::IneligibleEvidence);
    }
    if canonical_class_keys(&expected_classes) != canonical_class_keys(&exception.allowed_classes) {
        return Err(ScopedExceptionVerifyError::ClassMismatch);
    }

    Ok(())
}

/// Mints a one-time scoped exception for low-severity raw egress.
pub fn mint_scoped_exception(
    target: &str,
    allowed_classes: Vec<PiiClass>,
    destination_metadata: &[u8],
    action_metadata: &[u8],
    justification: &str,
    now_unix: u64,
    ttl_secs: u64,
) -> PiiScopedException {
    let destination_hash = sha256_array(destination_metadata).unwrap_or([0u8; 32]);

    let action_hash = sha256_array(action_metadata).unwrap_or([0u8; 32]);

    let justification_hash = sha256_array(justification.as_bytes()).unwrap_or([0u8; 32]);

    let exception_id_material = format!(
        "scope|{}|{}|{}|{}",
        target,
        hex::encode(destination_hash),
        hex::encode(action_hash),
        hex::encode(justification_hash)
    );
    let exception_id_hash = sha256_array(exception_id_material.as_bytes())
        .map(hex::encode)
        .unwrap_or_else(|_| "scope_error".to_string());

    PiiScopedException {
        exception_id: format!("scope::{exception_id_hash}"),
        allowed_classes,
        destination_hash,
        action_hash,
        expires_at: now_unix.saturating_add(ttl_secs),
        max_uses: 1,
        justification_hash,
    }
}

/// Deterministic Stage B/C CIM routing over structured evidence.
pub fn route_pii_decision_with_assist_for_target(
    graph: &EvidenceGraph,
    policy: &PiiControls,
    risk_surface: RiskSurface,
    target: &PiiTarget,
    supports_transform: bool,
    assist: &CimAssistReceipt,
) -> PiiRoutingOutcome {
    if graph.spans.is_empty() {
        return with_hash(
            graph,
            FirewallDecision::Allow,
            None,
            None,
            risk_surface,
            target,
            supports_transform,
            assist,
        );
    }

    if matches!(risk_surface, RiskSurface::LocalProcessing) {
        return with_hash(
            graph,
            FirewallDecision::AllowLocalOnly,
            None,
            None,
            risk_surface,
            target,
            supports_transform,
            assist,
        );
    }

    let high_risk_target = is_high_risk_target(policy, target);
    let has_high = has_high_severity(graph);
    let low_only = has_only_low_severity(graph);
    let can_transform = policy.safe_transform_enabled && supports_transform;
    let has_secret = is_secret_heavy(graph);

    // Strict egress secret rule: never allow raw secret payloads.
    if has_secret && matches!(risk_surface, RiskSurface::Egress) {
        if !can_transform {
            return with_hash(
                graph,
                FirewallDecision::Deny,
                None,
                Some(Stage2Decision::Deny {
                    reason: "Raw secret egress is not permitted without deterministic transform."
                        .to_string(),
                }),
                risk_surface,
                target,
                supports_transform,
                assist,
            );
        }

        let plan = build_transform_plan(target, graph);
        return with_hash(
            graph,
            match plan.action {
                TransformAction::Tokenize => FirewallDecision::TokenizeThenAllow,
                _ => FirewallDecision::RedactThenAllow,
            },
            Some(plan),
            Some(Stage2Decision::ApproveTransformPlan {
                plan_id: format!("transform::{}", target.canonical_label()),
            }),
            risk_surface,
            target,
            supports_transform,
            assist,
        );
    }

    if has_high && !can_transform {
        return with_hash(
            graph,
            FirewallDecision::Deny,
            None,
            Some(Stage2Decision::Deny {
                reason: "High-severity PII cannot egress as raw content in MVP.".to_string(),
            }),
            risk_surface,
            target,
            supports_transform,
            assist,
        );
    }

    if graph.ambiguous {
        if can_transform {
            let plan = build_transform_plan(target, graph);
            return with_hash(
                graph,
                match plan.action {
                    TransformAction::Tokenize => FirewallDecision::TokenizeThenAllow,
                    _ => FirewallDecision::RedactThenAllow,
                },
                Some(plan),
                Some(Stage2Decision::ApproveTransformPlan {
                    plan_id: format!("transform::{}", target.canonical_label()),
                }),
                risk_surface,
                target,
                supports_transform,
                assist,
            );
        }

        return with_hash(
            graph,
            if high_risk_target {
                FirewallDecision::Quarantine
            } else {
                FirewallDecision::RequireUserReview
            },
            None,
            Some(Stage2Decision::RequestMoreInfo {
                question_template:
                    "PII ambiguity detected. Approve deterministic transform or deny raw egress."
                        .to_string(),
            }),
            risk_surface,
            target,
            supports_transform,
            assist,
        );
    }

    if low_only
        && matches!(
            policy.raw_override_mode,
            RawOverrideMode::ScopedLowSeverityOnly
        )
        && policy.raw_override_default_enabled
    {
        return with_hash(
            graph,
            FirewallDecision::RequireUserReview,
            None,
            Some(Stage2Decision::RequestMoreInfo {
                question_template:
                    "Low-severity raw override eligible. Review may grant one scoped exception."
                        .to_string(),
            }),
            risk_surface,
            target,
            supports_transform,
            assist,
        );
    }

    if can_transform {
        let plan = build_transform_plan(target, graph);
        return with_hash(
            graph,
            match plan.action {
                TransformAction::Tokenize => FirewallDecision::TokenizeThenAllow,
                _ => FirewallDecision::RedactThenAllow,
            },
            Some(plan),
            Some(Stage2Decision::ApproveTransformPlan {
                plan_id: format!("transform::{}", target.canonical_label()),
            }),
            risk_surface,
            target,
            supports_transform,
            assist,
        );
    }

    with_hash(
        graph,
        if high_risk_target {
            FirewallDecision::Quarantine
        } else {
            FirewallDecision::RequireUserReview
        },
        None,
        Some(Stage2Decision::RequestMoreInfo {
            question_template:
                "PII detected. Approve deterministic transform, grant scoped override, or deny."
                    .to_string(),
        }),
        risk_surface,
        target,
        supports_transform,
        assist,
    )
}

/// Deterministic routing API without an explicit assist provider.
pub fn route_pii_decision_for_target(
    graph: &EvidenceGraph,
    policy: &PiiControls,
    risk_surface: RiskSurface,
    target: &PiiTarget,
    supports_transform: bool,
) -> PiiRoutingOutcome {
    let provider = CimAssistV0Provider::default();
    let assist_result = provider
        .assist(
            graph,
            &CimAssistContext {
                target,
                risk_surface,
                policy,
                supports_transform,
            },
        )
        .unwrap_or_else(|_| CimAssistResult {
            output_graph: graph.clone(),
            assist_applied: false,
        });
    let assist = build_assist_receipt(
        &provider,
        graph,
        &assist_result.output_graph,
        assist_result.assist_applied,
    );
    route_pii_decision_with_assist_for_target(
        &assist_result.output_graph,
        policy,
        risk_surface,
        target,
        supports_transform,
        &assist,
    )
}

/// Compatibility routing API without an explicit assist provider.
#[deprecated(note = "Use route_pii_decision_for_target with PiiTarget")]
pub fn route_pii_decision(
    graph: &EvidenceGraph,
    policy: &PiiControls,
    risk_surface: RiskSurface,
    target: &str,
    supports_transform: bool,
) -> PiiRoutingOutcome {
    let mapped = legacy_target_from_str(target);
    route_pii_decision_for_target(graph, policy, risk_surface, &mapped, supports_transform)
}

/// Compatibility routing API with explicit assist provider.
#[deprecated(note = "Use route_pii_decision_with_assist_for_target with PiiTarget")]
pub fn route_pii_decision_with_assist(
    graph: &EvidenceGraph,
    policy: &PiiControls,
    risk_surface: RiskSurface,
    target: &str,
    supports_transform: bool,
    assist: &CimAssistReceipt,
) -> PiiRoutingOutcome {
    let mapped = legacy_target_from_str(target);
    route_pii_decision_with_assist_for_target(
        graph,
        policy,
        risk_surface,
        &mapped,
        supports_transform,
        assist,
    )
}

/// Shared pipeline entrypoint for deterministic inspect + assist + route.
///
/// The inspector closure provides deterministic evidence extraction from the caller's
/// local safety model adapter without coupling this crate to `ioi-api`.
pub async fn inspect_and_route_with_provider_for_target<F, P>(
    inspect: F,
    assist_provider: &P,
    input: &str,
    target: &PiiTarget,
    risk_surface: RiskSurface,
    policy: &PiiControls,
    supports_transform: bool,
) -> Result<(EvidenceGraph, PiiRoutingOutcome)>
where
    F: for<'a> Fn(&'a str, RiskSurface) -> InspectFuture<'a> + Send + Sync,
    P: CimAssistProvider + ?Sized,
{
    let input_graph = inspect(input, risk_surface).await?;
    let assist_ctx = CimAssistContext {
        target,
        risk_surface,
        policy,
        supports_transform,
    };
    let assist_result = assist_provider.assist(&input_graph, &assist_ctx)?;
    let assist_receipt = build_assist_receipt(
        assist_provider,
        &input_graph,
        &assist_result.output_graph,
        assist_result.assist_applied,
    );
    let routed = route_pii_decision_with_assist_for_target(
        &assist_result.output_graph,
        policy,
        risk_surface,
        target,
        supports_transform,
        &assist_receipt,
    );
    Ok((assist_result.output_graph, routed))
}

/// Default pipeline entrypoint that always invokes deterministic CIM assist v0.
pub async fn inspect_and_route_with_for_target<F>(
    inspect: F,
    input: &str,
    target: &PiiTarget,
    risk_surface: RiskSurface,
    policy: &PiiControls,
    supports_transform: bool,
) -> Result<(EvidenceGraph, PiiRoutingOutcome)>
where
    F: for<'a> Fn(&'a str, RiskSurface) -> InspectFuture<'a> + Send + Sync,
{
    let provider = CimAssistV0Provider::default();
    inspect_and_route_with_provider_for_target(
        inspect,
        &provider,
        input,
        target,
        risk_surface,
        policy,
        supports_transform,
    )
    .await
}

/// Compatibility pipeline entrypoint that accepts legacy string targets.
#[deprecated(note = "Use inspect_and_route_with_for_target with PiiTarget")]
pub async fn inspect_and_route_with<F>(
    inspect: F,
    input: &str,
    target: &str,
    risk_surface: RiskSurface,
    policy: &PiiControls,
    supports_transform: bool,
) -> Result<(EvidenceGraph, PiiRoutingOutcome)>
where
    F: for<'a> Fn(&'a str, RiskSurface) -> InspectFuture<'a> + Send + Sync,
{
    let mapped = legacy_target_from_str(target);
    inspect_and_route_with_for_target(
        inspect,
        input,
        &mapped,
        risk_surface,
        policy,
        supports_transform,
    )
    .await
}

/// Compatibility inspect+route entrypoint with explicit assist provider and string target.
#[deprecated(note = "Use inspect_and_route_with_provider_for_target with PiiTarget")]
pub async fn inspect_and_route_with_provider<F, P>(
    inspect: F,
    assist_provider: &P,
    input: &str,
    target: &str,
    risk_surface: RiskSurface,
    policy: &PiiControls,
    supports_transform: bool,
) -> Result<(EvidenceGraph, PiiRoutingOutcome)>
where
    F: for<'a> Fn(&'a str, RiskSurface) -> InspectFuture<'a> + Send + Sync,
    P: CimAssistProvider + ?Sized,
{
    let mapped = legacy_target_from_str(target);
    inspect_and_route_with_provider_for_target(
        inspect,
        assist_provider,
        input,
        &mapped,
        risk_surface,
        policy,
        supports_transform,
    )
    .await
}

fn pii_class_from_category(category: &str) -> PiiClass {
    match category.to_ascii_uppercase().as_str() {
        "API_KEY" => PiiClass::ApiKey,
        "SECRET" | "SECRET_TOKEN" | "TOKEN" => PiiClass::SecretToken,
        "EMAIL" => PiiClass::Email,
        "PHONE" => PiiClass::Phone,
        "SSN" => PiiClass::Ssn,
        "CARD_PAN" | "CARD" => PiiClass::CardPan,
        "NAME" => PiiClass::Name,
        "ADDRESS" => PiiClass::Address,
        other => PiiClass::Custom(other.to_ascii_lowercase()),
    }
}

fn redaction_type_for_class(class: &PiiClass) -> RedactionType {
    match class {
        PiiClass::ApiKey | PiiClass::SecretToken => RedactionType::Secret,
        _ => RedactionType::Pii,
    }
}

/// Canonical placeholder label for PII classes.
pub fn canonical_placeholder_label(class: &PiiClass) -> &'static str {
    match class {
        PiiClass::ApiKey => "api_key",
        PiiClass::SecretToken => "secret_token",
        PiiClass::Email => "email",
        PiiClass::Phone => "phone",
        PiiClass::Ssn => "ssn",
        PiiClass::CardPan => "card_pan",
        PiiClass::Name => "name",
        PiiClass::Address => "address",
        PiiClass::Custom(_) => "custom",
    }
}

fn scrub_with_classes(
    input: &str,
    spans: &[(usize, usize, PiiClass)],
) -> Result<(String, RedactionMap, u32)> {
    let mut sorted = spans.to_vec();
    sorted.sort_by_key(|(start, _, _)| *start);

    let mut output = String::with_capacity(input.len());
    let mut redactions = Vec::new();
    let mut last_pos = 0usize;
    let mut unresolved_spans = 0u32;

    for (start, end, class) in sorted {
        let invalid_bounds = start >= end
            || end > input.len()
            || !input.is_char_boundary(start)
            || !input.is_char_boundary(end);
        if invalid_bounds {
            unresolved_spans = unresolved_spans.saturating_add(1);
            continue;
        }

        // Overlapping spans are common when multiple detectors identify the same secret.
        // Redact any uncovered tail instead of marking overlap as unresolved.
        if end <= last_pos {
            continue;
        }
        let effective_start = start.max(last_pos);
        output.push_str(&input[last_pos..effective_start]);

        let secret_slice = &input[effective_start..end];
        let hash_arr = sha256_array(secret_slice.as_bytes())?;

        redactions.push(RedactionEntry {
            start_index: effective_start as u32,
            end_index: end as u32,
            redaction_type: redaction_type_for_class(&class),
            original_hash: hash_arr,
        });

        output.push_str(&format!(
            "<REDACTED:{}>",
            canonical_placeholder_label(&class)
        ));

        last_pos = end;
    }

    if last_pos < input.len() {
        output.push_str(&input[last_pos..]);
    }

    Ok((
        output,
        RedactionMap {
            entries: redactions,
        },
        unresolved_spans,
    ))
}

/// Canonical shared scrub loop for deterministic redaction.
pub fn scrub_text(
    input: &str,
    detections: &[(usize, usize, String)],
) -> Result<(String, RedactionMap)> {
    let spans = detections
        .iter()
        .map(|(start, end, category)| (*start, *end, pii_class_from_category(category)))
        .collect::<Vec<_>>();
    let (scrubbed, map, _) = scrub_with_classes(input, &spans)?;
    Ok((scrubbed, map))
}

fn count_remaining_raw_segments(output: &str, input: &str, spans: &[EvidenceSpan]) -> u32 {
    spans
        .iter()
        .filter(|span| {
            let start = span.start_index as usize;
            let end = span.end_index as usize;
            if start >= end || end > input.len() {
                return false;
            }
            if !input.is_char_boundary(start) || !input.is_char_boundary(end) {
                return false;
            }
            let raw = &input[start..end];
            raw.len() > 3 && output.contains(raw)
        })
        .count() as u32
}

/// Shared pipeline entrypoint for deterministic Stage C transform.
pub fn apply_transform(
    input: &str,
    evidence: &EvidenceGraph,
    outcome: &PiiRoutingOutcome,
) -> Result<(String, RedactionMap, PostTransformReport)> {
    let should_transform = matches!(
        outcome.decision,
        FirewallDecision::RedactThenAllow | FirewallDecision::TokenizeThenAllow
    );

    if !should_transform {
        return Ok((
            input.to_string(),
            RedactionMap { entries: vec![] },
            PostTransformReport {
                transformed: false,
                unresolved_spans: 0,
                remaining_span_count: 0,
                no_raw_substring_leak: true,
            },
        ));
    }

    let class_spans = evidence
        .spans
        .iter()
        .map(|span| {
            (
                span.start_index as usize,
                span.end_index as usize,
                span.pii_class.clone(),
            )
        })
        .collect::<Vec<_>>();

    let (scrubbed, map, unresolved_spans) = scrub_with_classes(input, &class_spans)?;
    let remaining_span_count = count_remaining_raw_segments(&scrubbed, input, &evidence.spans);

    Ok((
        scrubbed,
        map,
        PostTransformReport {
            transformed: true,
            unresolved_spans,
            remaining_span_count,
            no_raw_substring_leak: unresolved_spans == 0 && remaining_span_count == 0,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::{
        apply_transform, build_assist_receipt, check_exception_usage_increment_ok,
        decode_exception_usage_state, expected_assist_identity, graph_hash,
        mint_default_scoped_exception, route_pii_decision_for_target,
        route_pii_decision_with_assist_for_target, scrub_text, validate_resume_review_contract,
        validate_review_request_compat, verify_scoped_exception_for_decision, CimAssistContext,
        CimAssistProvider, CimAssistReceipt, CimAssistResult, CimAssistV0Provider,
        NoopCimAssistProvider, PiiReviewContractError, PiiRoutingOutcome, ResumeReviewMode,
        RiskSurface, ScopedExceptionVerifyError, REVIEW_REQUEST_VERSION,
    };
    use ioi_types::app::action::{ApprovalScope, ApprovalToken, PiiApprovalAction};
    use ioi_types::app::agentic::{
        EvidenceGraph, EvidenceSpan, FirewallDecision, PiiClass, PiiConfidenceBucket, PiiControls,
        PiiDecisionMaterial, PiiReviewRequest, PiiReviewSummary, PiiSeverity, PiiTarget,
        RawOverrideMode,
    };
    use ioi_types::app::ActionTarget;

    #[derive(Debug, Clone, Copy)]
    struct IdentityProvider {
        kind: &'static str,
        version: &'static str,
        config_hash: [u8; 32],
        module_hash: [u8; 32],
    }

    impl CimAssistProvider for IdentityProvider {
        fn assist_kind(&self) -> &str {
            self.kind
        }

        fn assist_version(&self) -> &str {
            self.version
        }

        fn assist_config_hash(&self) -> [u8; 32] {
            self.config_hash
        }

        fn assist_module_hash(&self) -> [u8; 32] {
            self.module_hash
        }

        fn assist(
            &self,
            graph: &EvidenceGraph,
            _ctx: &CimAssistContext<'_>,
        ) -> anyhow::Result<CimAssistResult> {
            Ok(CimAssistResult {
                output_graph: graph.clone(),
                assist_applied: false,
            })
        }
    }

    #[test]
    fn noop_assist_provider_is_invoked_not_applied_and_hashes_are_deterministic() {
        let graph = EvidenceGraph::default();
        let policy = PiiControls::default();
        let provider = NoopCimAssistProvider;
        let target = PiiTarget::Action(ActionTarget::ClipboardWrite);
        let ctx = CimAssistContext {
            target: &target,
            risk_surface: RiskSurface::Egress,
            policy: &policy,
            supports_transform: true,
        };

        let result = provider.assist(&graph, &ctx).expect("assist");
        assert_eq!(result.output_graph, graph);
        assert!(!result.assist_applied);

        let receipt = build_assist_receipt(
            &provider,
            &graph,
            &result.output_graph,
            result.assist_applied,
        );
        assert!(receipt.assist_invoked);
        assert!(!receipt.assist_applied);
        assert_eq!(receipt.assist_kind, "noop");
        assert_eq!(receipt.assist_version, "noop-v1");
        assert_eq!(receipt.assist_input_graph_hash, graph_hash(&graph));
        assert_eq!(receipt.assist_output_graph_hash, graph_hash(&graph));

        let mut changed_graph = graph.clone();
        changed_graph.source_hash = [1u8; 32];
        assert_ne!(graph_hash(&graph), graph_hash(&changed_graph));
    }

    #[test]
    fn decision_hash_is_deterministic_for_same_material() {
        let graph = EvidenceGraph::default();
        let target = PiiTarget::Action(ActionTarget::ClipboardWrite);
        let a = route_pii_decision_for_target(
            &graph,
            &PiiControls::default(),
            RiskSurface::Egress,
            &target,
            true,
        );
        let b = route_pii_decision_for_target(
            &graph,
            &PiiControls::default(),
            RiskSurface::Egress,
            &target,
            true,
        );
        assert_eq!(a.decision_hash, b.decision_hash);
    }

    #[test]
    fn decision_hash_changes_when_assist_identity_changes() {
        let graph = EvidenceGraph::default();
        let policy = PiiControls::default();
        let target = PiiTarget::Action(ActionTarget::ClipboardWrite);
        let ctx = CimAssistContext {
            target: &target,
            risk_surface: RiskSurface::Egress,
            policy: &policy,
            supports_transform: true,
        };

        let provider_a = IdentityProvider {
            kind: "noop",
            version: "noop-v1",
            config_hash: [0u8; 32],
            module_hash: [0u8; 32],
        };
        let provider_b = IdentityProvider {
            kind: "cim_wasm",
            version: "cim-wasm-v0.1",
            config_hash: [0u8; 32],
            module_hash: [0u8; 32],
        };

        let result_a = provider_a.assist(&graph, &ctx).expect("assist a");
        let assist_a = build_assist_receipt(
            &provider_a,
            &graph,
            &result_a.output_graph,
            result_a.assist_applied,
        );
        let routed_a = route_pii_decision_with_assist_for_target(
            &graph,
            &policy,
            RiskSurface::Egress,
            &target,
            true,
            &assist_a,
        );

        let result_b = provider_b.assist(&graph, &ctx).expect("assist b");
        let assist_b = build_assist_receipt(
            &provider_b,
            &graph,
            &result_b.output_graph,
            result_b.assist_applied,
        );
        let routed_b = route_pii_decision_with_assist_for_target(
            &graph,
            &policy,
            RiskSurface::Egress,
            &target,
            true,
            &assist_b,
        );

        assert_eq!(routed_a.decision, routed_b.decision);
        assert_ne!(routed_a.decision_hash, routed_b.decision_hash);
    }

    #[test]
    fn decision_hash_changes_when_supports_transform_toggles() {
        let graph = EvidenceGraph::default();
        let policy = PiiControls::default();
        let target = PiiTarget::Action(ActionTarget::ClipboardWrite);
        let with_transform =
            route_pii_decision_for_target(&graph, &policy, RiskSurface::Egress, &target, true);
        let without_transform =
            route_pii_decision_for_target(&graph, &policy, RiskSurface::Egress, &target, false);

        assert_eq!(with_transform.decision, without_transform.decision);
        assert_ne!(
            with_transform.decision_hash,
            without_transform.decision_hash
        );
    }

    #[test]
    fn assist_identity_hash_changes_with_config_or_module_hash() {
        let graph = EvidenceGraph::default();
        let base = IdentityProvider {
            kind: "cim_wasm",
            version: "cim-wasm-v0.2",
            config_hash: [1u8; 32],
            module_hash: [2u8; 32],
        };
        let config_changed = IdentityProvider {
            config_hash: [3u8; 32],
            ..base
        };
        let module_changed = IdentityProvider {
            module_hash: [4u8; 32],
            ..base
        };

        let a = build_assist_receipt(&base, &graph, &graph, false);
        let b = build_assist_receipt(&config_changed, &graph, &graph, false);
        let c = build_assist_receipt(&module_changed, &graph, &graph, false);

        assert_ne!(a.assist_identity_hash, b.assist_identity_hash);
        assert_ne!(a.assist_identity_hash, c.assist_identity_hash);
    }

    #[test]
    fn secret_egress_never_returns_allow() {
        let graph = EvidenceGraph {
            version: 1,
            source_hash: [1u8; 32],
            ambiguous: false,
            spans: vec![EvidenceSpan {
                start_index: 0,
                end_index: 10,
                pii_class: PiiClass::ApiKey,
                severity: PiiSeverity::High,
                confidence_bucket: PiiConfidenceBucket::High,
                pattern_id: "test/api_key".to_string(),
                validator_passed: true,
                context_keywords: vec![],
                evidence_source: "test".to_string(),
            }],
        };
        let policy = PiiControls::default();
        let target = PiiTarget::Action(ActionTarget::ClipboardWrite);

        let with_transform =
            route_pii_decision_for_target(&graph, &policy, RiskSurface::Egress, &target, true);
        let without_transform =
            route_pii_decision_for_target(&graph, &policy, RiskSurface::Egress, &target, false);

        assert!(!matches!(with_transform.decision, FirewallDecision::Allow));
        assert!(!matches!(
            without_transform.decision,
            FirewallDecision::Allow
        ));
    }

    #[test]
    fn canonical_placeholder_labels_are_used() {
        let input = "send sk_live_abcd1234abcd1234 to john@example.com";
        let detections = vec![
            (5usize, 28usize, "API_KEY".to_string()),
            (32usize, 48usize, "EMAIL".to_string()),
        ];
        let (scrubbed, _) = scrub_text(input, &detections).expect("scrub");
        assert!(scrubbed.contains("<REDACTED:api_key>"));
        assert!(scrubbed.contains("<REDACTED:email>"));
    }

    #[test]
    fn invalid_span_boundaries_do_not_panic_and_fail_leak_check() {
        let graph = EvidenceGraph {
            version: 1,
            source_hash: [0u8; 32],
            ambiguous: false,
            spans: vec![EvidenceSpan {
                start_index: 1,
                end_index: 2,
                pii_class: PiiClass::ApiKey,
                severity: PiiSeverity::High,
                confidence_bucket: PiiConfidenceBucket::High,
                pattern_id: "test".to_string(),
                validator_passed: true,
                context_keywords: vec![],
                evidence_source: "test".to_string(),
            }],
        };

        let outcome = PiiRoutingOutcome {
            decision: FirewallDecision::RedactThenAllow,
            transform_plan: None,
            stage2_decision: None,
            assist: CimAssistReceipt {
                assist_invoked: false,
                assist_applied: false,
                assist_kind: "test".to_string(),
                assist_version: "test-v1".to_string(),
                assist_identity_hash: [0u8; 32],
                assist_config_hash: [0u8; 32],
                assist_module_hash: [0u8; 32],
                assist_input_graph_hash: [0u8; 32],
                assist_output_graph_hash: [0u8; 32],
            },
            decision_hash: [0u8; 32],
        };

        let (_scrubbed, _map, report) =
            apply_transform("🔥secret", &graph, &outcome).expect("apply");
        assert!(!report.no_raw_substring_leak);
        assert_eq!(report.unresolved_spans, 1);
    }

    #[test]
    fn overlapping_spans_redact_without_false_unresolved_failures() {
        let input = "token: sk_live_abcd1234abcd1234";
        let secret_start = input.find("sk_live_").expect("secret start");
        let secret_end = secret_start + "sk_live_abcd1234abcd1234".len();
        let token_start = input.find("token:").expect("token start");

        let graph = EvidenceGraph {
            version: 1,
            source_hash: [0u8; 32],
            ambiguous: false,
            spans: vec![
                EvidenceSpan {
                    start_index: token_start as u32,
                    end_index: secret_end as u32,
                    pii_class: PiiClass::SecretToken,
                    severity: PiiSeverity::High,
                    confidence_bucket: PiiConfidenceBucket::High,
                    pattern_id: "test/secret_token".to_string(),
                    validator_passed: true,
                    context_keywords: vec![],
                    evidence_source: "test".to_string(),
                },
                EvidenceSpan {
                    start_index: secret_start as u32,
                    end_index: secret_end as u32,
                    pii_class: PiiClass::ApiKey,
                    severity: PiiSeverity::High,
                    confidence_bucket: PiiConfidenceBucket::High,
                    pattern_id: "test/api_key".to_string(),
                    validator_passed: true,
                    context_keywords: vec![],
                    evidence_source: "test".to_string(),
                },
            ],
        };

        let outcome = PiiRoutingOutcome {
            decision: FirewallDecision::RedactThenAllow,
            transform_plan: None,
            stage2_decision: None,
            assist: CimAssistReceipt {
                assist_invoked: false,
                assist_applied: false,
                assist_kind: "test".to_string(),
                assist_version: "test-v1".to_string(),
                assist_identity_hash: [0u8; 32],
                assist_config_hash: [0u8; 32],
                assist_module_hash: [0u8; 32],
                assist_input_graph_hash: [0u8; 32],
                assist_output_graph_hash: [0u8; 32],
            },
            decision_hash: [0u8; 32],
        };

        let (scrubbed, _map, report) = apply_transform(input, &graph, &outcome).expect("apply");
        assert!(!scrubbed.contains("sk_live_abcd1234abcd1234"));
        assert!(!scrubbed.contains("token: sk_live_abcd1234abcd1234"));
        assert!(report.no_raw_substring_leak);
        assert_eq!(report.unresolved_spans, 0);
        assert_eq!(report.remaining_span_count, 0);
    }

    fn low_severity_email_graph() -> EvidenceGraph {
        EvidenceGraph {
            version: 1,
            source_hash: [7u8; 32],
            ambiguous: false,
            spans: vec![EvidenceSpan {
                start_index: 0,
                end_index: 16,
                pii_class: PiiClass::Email,
                severity: PiiSeverity::Low,
                confidence_bucket: PiiConfidenceBucket::High,
                pattern_id: "email/test".to_string(),
                validator_passed: true,
                context_keywords: vec![],
                evidence_source: "test".to_string(),
            }],
        }
    }

    #[test]
    fn scoped_exception_verifier_rejects_class_mismatch() {
        let graph = low_severity_email_graph();
        let target = PiiTarget::Action(ActionTarget::ClipboardWrite);
        let decision_hash = [9u8; 32];
        let mut policy = PiiControls::default();
        policy.raw_override_mode = RawOverrideMode::ScopedLowSeverityOnly;
        let mut exception = mint_default_scoped_exception(
            &graph,
            &target,
            RiskSurface::Egress,
            decision_hash,
            1_000,
            "test",
        )
        .expect("mint");
        exception.allowed_classes = vec![PiiClass::Phone];

        let result = verify_scoped_exception_for_decision(
            &exception,
            &graph,
            &target,
            RiskSurface::Egress,
            decision_hash,
            &policy,
            1_001,
            0,
        );
        assert_eq!(result, Err(ScopedExceptionVerifyError::ClassMismatch));
    }

    #[test]
    fn scoped_exception_verifier_rejects_expired_and_overused_and_binding_mismatch() {
        let graph = low_severity_email_graph();
        let target = PiiTarget::Action(ActionTarget::ClipboardWrite);
        let decision_hash = [11u8; 32];
        let mut policy = PiiControls::default();
        policy.raw_override_mode = RawOverrideMode::ScopedLowSeverityOnly;
        let exception = mint_default_scoped_exception(
            &graph,
            &target,
            RiskSurface::Egress,
            decision_hash,
            2_000,
            "test",
        )
        .expect("mint");

        let expired = verify_scoped_exception_for_decision(
            &exception,
            &graph,
            &target,
            RiskSurface::Egress,
            decision_hash,
            &policy,
            exception.expires_at,
            0,
        );
        assert_eq!(expired, Err(ScopedExceptionVerifyError::Expired));

        let overused = verify_scoped_exception_for_decision(
            &exception,
            &graph,
            &target,
            RiskSurface::Egress,
            decision_hash,
            &policy,
            2_100,
            1,
        );
        assert_eq!(overused, Err(ScopedExceptionVerifyError::Overused));

        let wrong_target = PiiTarget::Action(ActionTarget::NetFetch);
        let binding_mismatch = verify_scoped_exception_for_decision(
            &exception,
            &graph,
            &wrong_target,
            RiskSurface::Egress,
            decision_hash,
            &policy,
            2_100,
            0,
        );
        assert_eq!(
            binding_mismatch,
            Err(ScopedExceptionVerifyError::DestinationMismatch)
        );
    }

    fn sample_approval_token(
        request_hash: [u8; 32],
        pii_action: Option<PiiApprovalAction>,
    ) -> ApprovalToken {
        ApprovalToken {
            request_hash,
            scope: ApprovalScope {
                expires_at: 9_999,
                max_usages: Some(1),
            },
            visual_hash: None,
            pii_action,
            scoped_exception: None,
            approver_sig: vec![],
            approver_suite: ioi_types::app::SignatureSuite::ED25519,
        }
    }

    fn sample_review_request(hash: [u8; 32], deadline_ms: u64) -> PiiReviewRequest {
        let (assist_kind, assist_version, assist_identity_hash) = expected_assist_identity();
        PiiReviewRequest {
            request_version: REVIEW_REQUEST_VERSION,
            decision_hash: hash,
            material: PiiDecisionMaterial {
                version: 3,
                target: PiiTarget::Action(ActionTarget::ClipboardWrite),
                risk_surface: "egress".to_string(),
                supports_transform: true,
                source_hash: [1u8; 32],
                span_count: 1,
                ambiguous: false,
                decision: FirewallDecision::RequireUserReview,
                transform_plan_id: None,
                stage2_kind: Some("request_more_info".to_string()),
                assist_invoked: true,
                assist_applied: false,
                assist_kind,
                assist_version,
                assist_identity_hash,
                assist_input_graph_hash: [0u8; 32],
                assist_output_graph_hash: [0u8; 32],
            },
            summary: PiiReviewSummary {
                target_label: "clipboard::write".to_string(),
                span_summary: "spans=1".to_string(),
                class_counts: std::collections::BTreeMap::new(),
                severity_counts: std::collections::BTreeMap::new(),
                stage2_prompt: "Review".to_string(),
            },
            session_id: Some([2u8; 32]),
            created_at_ms: 100,
            deadline_ms,
        }
    }

    #[test]
    fn resume_contract_rejects_hash_mismatch() {
        let expected_hash = [7u8; 32];
        let token = sample_approval_token([8u8; 32], Some(PiiApprovalAction::Deny));
        let request = sample_review_request(expected_hash, 10_000);

        let result = validate_resume_review_contract(expected_hash, &token, Some(&request), 9_000);
        assert_eq!(
            result,
            Err(PiiReviewContractError::ApprovalTokenHashMismatch)
        );
    }

    #[test]
    fn resume_contract_rejects_missing_request_when_pii_action_present() {
        let expected_hash = [9u8; 32];
        let token = sample_approval_token(expected_hash, Some(PiiApprovalAction::ApproveTransform));
        let result = validate_resume_review_contract(expected_hash, &token, None, 500);
        assert_eq!(
            result,
            Err(PiiReviewContractError::PiiActionWithoutReviewRequest)
        );
    }

    #[test]
    fn resume_contract_accepts_deny_without_review_request() {
        let expected_hash = [9u8; 32];
        let token = sample_approval_token(expected_hash, Some(PiiApprovalAction::Deny));
        let result = validate_resume_review_contract(expected_hash, &token, None, 500)
            .expect("deny should be allowed without a review request");
        assert_eq!(result, ResumeReviewMode::LegacyApproval);
    }

    #[test]
    fn resume_contract_rejects_missing_pii_action_for_review_request() {
        let expected_hash = [10u8; 32];
        let token = sample_approval_token(expected_hash, None);
        let request = sample_review_request(expected_hash, 10_000);

        let result = validate_resume_review_contract(expected_hash, &token, Some(&request), 9_000);
        assert_eq!(
            result,
            Err(PiiReviewContractError::MissingPiiActionForReview)
        );
    }

    #[test]
    fn resume_contract_rejects_expired_deadline() {
        let expected_hash = [11u8; 32];
        let token = sample_approval_token(expected_hash, Some(PiiApprovalAction::Deny));
        let request = sample_review_request(expected_hash, 1_000);

        let result = validate_resume_review_contract(expected_hash, &token, Some(&request), 1_001);
        assert_eq!(
            result,
            Err(PiiReviewContractError::ReviewApprovalDeadlineExceeded)
        );
    }

    #[test]
    fn resume_contract_accepts_review_bound_token_at_deadline_boundary() {
        let expected_hash = [12u8; 32];
        let token = sample_approval_token(expected_hash, Some(PiiApprovalAction::Deny));
        let request = sample_review_request(expected_hash, 1_000);

        let result = validate_resume_review_contract(expected_hash, &token, Some(&request), 1_000)
            .expect("boundary deadline should be valid");
        assert_eq!(result, ResumeReviewMode::ReviewBound);
    }

    #[test]
    fn review_request_compat_rejects_v2() {
        let mut request = sample_review_request([13u8; 32], 5_000);
        request.request_version = 2;
        let result = validate_review_request_compat(&request);
        assert_eq!(
            result,
            Err(PiiReviewContractError::UnsupportedReviewRequestVersion {
                found: 2,
                expected: REVIEW_REQUEST_VERSION,
            })
        );
    }

    #[test]
    fn review_request_compat_rejects_wrong_assist_identity() {
        let mut request = sample_review_request([14u8; 32], 5_000);
        request.material.assist_identity_hash = [0xAB; 32];
        let result = validate_review_request_compat(&request);
        assert!(matches!(
            result,
            Err(PiiReviewContractError::AssistIdentityHashMismatch { .. })
        ));
    }

    #[test]
    fn review_request_compat_accepts_expected_cim_identity() {
        let request = sample_review_request([15u8; 32], 5_000);
        validate_review_request_compat(&request).expect("expected v3+cim request to be valid");
    }
    fn cim_severity_rank(severity: PiiSeverity) -> u8 {
        match severity {
            PiiSeverity::Low => 0,
            PiiSeverity::Medium => 1,
            PiiSeverity::High => 2,
            PiiSeverity::Critical => 3,
        }
    }
    fn cim_confidence_rank(confidence: PiiConfidenceBucket) -> u8 {
        match confidence {
            PiiConfidenceBucket::Low => 0,
            PiiConfidenceBucket::Medium => 1,
            PiiConfidenceBucket::High => 2,
        }
    }
    fn cim_sample_ambiguous_graph() -> EvidenceGraph {
        EvidenceGraph {
            version: 1,
            source_hash: [0xA5; 32],
            ambiguous: true,
            spans: vec![
                EvidenceSpan {
                    start_index: 0,
                    end_index: 16,
                    pii_class: PiiClass::CardPan,
                    severity: PiiSeverity::High,
                    confidence_bucket: PiiConfidenceBucket::Medium,
                    pattern_id: "card_pan/heuristic".to_string(),
                    validator_passed: false,
                    context_keywords: vec!["tracking".to_string(), "invoice".to_string()],
                    evidence_source: "regex".to_string(),
                },
                EvidenceSpan {
                    start_index: 20,
                    end_index: 32,
                    pii_class: PiiClass::Phone,
                    severity: PiiSeverity::Low,
                    confidence_bucket: PiiConfidenceBucket::Medium,
                    pattern_id: "phone/heuristic".to_string(),
                    validator_passed: false,
                    context_keywords: vec!["order id".to_string()],
                    evidence_source: "regex".to_string(),
                },
                EvidenceSpan {
                    start_index: 36,
                    end_index: 48,
                    pii_class: PiiClass::Custom("order_code".to_string()),
                    severity: PiiSeverity::Medium,
                    confidence_bucket: PiiConfidenceBucket::Low,
                    pattern_id: "custom/ambiguous".to_string(),
                    validator_passed: false,
                    context_keywords: vec!["tracking".to_string()],
                    evidence_source: "heuristic".to_string(),
                },
            ],
        }
    }
    #[test]
    fn cim_v0_is_deterministic_and_decision_hash_stable() {
        let graph = cim_sample_ambiguous_graph();
        let policy = PiiControls::default();
        let target = PiiTarget::Action(ActionTarget::ClipboardWrite);
        let provider = CimAssistV0Provider::default();
        let ctx = CimAssistContext {
            target: &target,
            risk_surface: RiskSurface::Egress,
            policy: &policy,
            supports_transform: true,
        };

        let run_a = provider.assist(&graph, &ctx).expect("assist a");
        let run_b = provider.assist(&graph, &ctx).expect("assist b");
        assert_eq!(run_a.output_graph, run_b.output_graph);
        assert_eq!(run_a.assist_applied, run_b.assist_applied);

        let assist_a =
            build_assist_receipt(&provider, &graph, &run_a.output_graph, run_a.assist_applied);
        let assist_b =
            build_assist_receipt(&provider, &graph, &run_b.output_graph, run_b.assist_applied);
        let routed_a = route_pii_decision_with_assist_for_target(
            &run_a.output_graph,
            &policy,
            RiskSurface::Egress,
            &target,
            true,
            &assist_a,
        );
        let routed_b = route_pii_decision_with_assist_for_target(
            &run_b.output_graph,
            &policy,
            RiskSurface::Egress,
            &target,
            true,
            &assist_b,
        );
        assert_eq!(routed_a.decision_hash, routed_b.decision_hash);
    }
    #[test]
    fn cim_v0_preserves_source_and_never_escalates_spans() {
        let graph = cim_sample_ambiguous_graph();
        let policy = PiiControls::default();
        let target = PiiTarget::Action(ActionTarget::ClipboardWrite);
        let provider = CimAssistV0Provider::default();
        let ctx = CimAssistContext {
            target: &target,
            risk_surface: RiskSurface::Egress,
            policy: &policy,
            supports_transform: true,
        };

        let refined = provider.assist(&graph, &ctx).expect("assist");
        assert_eq!(refined.output_graph.source_hash, graph.source_hash);
        assert!(refined.output_graph.spans.len() <= graph.spans.len());

        for out_span in &refined.output_graph.spans {
            let matching_input = graph
                .spans
                .iter()
                .find(|input| {
                    input.start_index == out_span.start_index
                        && input.end_index == out_span.end_index
                        && input.pii_class == out_span.pii_class
                        && input.severity == out_span.severity
                        && input.pattern_id == out_span.pattern_id
                        && input.evidence_source == out_span.evidence_source
                })
                .expect("output span must map to an input span");
            assert!(
                cim_confidence_rank(out_span.confidence_bucket)
                    <= cim_confidence_rank(matching_input.confidence_bucket),
                "provider must not increase confidence"
            );
            assert!(
                cim_severity_rank(out_span.severity) <= cim_severity_rank(matching_input.severity),
                "provider must not increase severity"
            );
        }
    }
    #[test]
    fn cim_v0_resolves_ambiguous_card_phone_and_custom_cases() {
        let graph = cim_sample_ambiguous_graph();
        let policy = PiiControls::default();
        let target = PiiTarget::Action(ActionTarget::ClipboardWrite);
        let provider = CimAssistV0Provider::default();
        let ctx = CimAssistContext {
            target: &target,
            risk_surface: RiskSurface::Egress,
            policy: &policy,
            supports_transform: true,
        };

        let refined = provider.assist(&graph, &ctx).expect("assist");
        assert!(refined.assist_applied);
        assert!(!refined.output_graph.ambiguous);
        assert!(
            refined.output_graph.spans.is_empty(),
            "v0 ambiguity samples should be dropped deterministically"
        );
    }
    #[test]
    fn cim_v0_identity_changes_decision_hash_vs_noop() {
        let graph = cim_sample_ambiguous_graph();
        let policy = PiiControls::default();
        let target = PiiTarget::Action(ActionTarget::ClipboardWrite);

        let noop = NoopCimAssistProvider;
        let noop_result = noop
            .assist(
                &graph,
                &CimAssistContext {
                    target: &target,
                    risk_surface: RiskSurface::Egress,
                    policy: &policy,
                    supports_transform: true,
                },
            )
            .expect("noop assist");
        let noop_receipt = build_assist_receipt(
            &noop,
            &graph,
            &noop_result.output_graph,
            noop_result.assist_applied,
        );
        let noop_routed = route_pii_decision_with_assist_for_target(
            &noop_result.output_graph,
            &policy,
            RiskSurface::Egress,
            &target,
            true,
            &noop_receipt,
        );

        let cim = CimAssistV0Provider::default();
        let cim_result = cim
            .assist(
                &graph,
                &CimAssistContext {
                    target: &target,
                    risk_surface: RiskSurface::Egress,
                    policy: &policy,
                    supports_transform: true,
                },
            )
            .expect("cim assist");
        let cim_receipt = build_assist_receipt(
            &cim,
            &graph,
            &cim_result.output_graph,
            cim_result.assist_applied,
        );
        let cim_routed = route_pii_decision_with_assist_for_target(
            &cim_result.output_graph,
            &policy,
            RiskSurface::Egress,
            &target,
            true,
            &cim_receipt,
        );

        assert_ne!(noop_routed.decision_hash, cim_routed.decision_hash);
    }

    #[test]
    fn usage_counter_decode_and_increment_fail_closed() {
        let invalid = decode_exception_usage_state(Some(&[0xFF, 0x00]));
        assert_eq!(
            invalid,
            Err(PiiReviewContractError::InvalidExceptionUsageState)
        );

        let overflow = check_exception_usage_increment_ok(u32::MAX);
        assert_eq!(
            overflow,
            Err(PiiReviewContractError::ExceptionUsageOverflow)
        );
    }
}
