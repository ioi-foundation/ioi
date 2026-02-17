use crate::agentic::desktop::keys::pii;
use crate::agentic::desktop::service::step::incident::mark_gate_approved;
use crate::agentic::desktop::service::DesktopAgentService;
use crate::agentic::desktop::types::AgentState;
use crate::agentic::rules::ActionRules;
use ioi_api::state::StateAccess;
use ioi_pii::{
    check_exception_usage_increment_ok, decode_exception_usage_state,
    mint_default_scoped_exception, validate_resume_review_contract,
    verify_scoped_exception_for_decision, RiskSurface, ScopedExceptionVerifyError,
};
use ioi_types::app::action::PiiApprovalAction;
use ioi_types::app::agentic::{AgentTool, PiiEgressRiskSurface, PiiReviewRequest};
use ioi_types::codec;
use ioi_types::error::TransactionError;

pub(super) struct ApprovalResult {
    pub(super) scoped_exception_override_hash: Option<[u8; 32]>,
    pub(super) explicit_pii_deny: bool,
}

fn to_shared_risk_surface(risk_surface: PiiEgressRiskSurface) -> RiskSurface {
    match risk_surface {
        PiiEgressRiskSurface::Egress => RiskSurface::Egress,
    }
}

pub(super) async fn validate_and_apply(
    service: &DesktopAgentService,
    state: &mut dyn StateAccess,
    agent_state: &AgentState,
    session_id: [u8; 32],
    tool: &AgentTool,
    tool_hash: [u8; 32],
    expected_request_hash: [u8; 32],
    pii_request: Option<&PiiReviewRequest>,
    block_timestamp_ms: u64,
    block_timestamp_secs: u64,
    rules: &mut ActionRules,
    verification_checks: &mut Vec<String>,
) -> Result<ApprovalResult, TransactionError> {
    let mut scoped_exception_override_hash: Option<[u8; 32]> = None;
    let mut explicit_pii_deny = false;

    // Validate approval token before executing anything.
    // Runtime secret retries for sys__install_package are allowed without approval token.
    if let Some(token) = agent_state.pending_approval.as_ref() {
        validate_resume_review_contract(
            expected_request_hash,
            token,
            pii_request,
            block_timestamp_ms,
        )
        .map_err(|e| TransactionError::Invalid(e.to_string()))?;

        if matches!(token.pii_action, Some(PiiApprovalAction::ApproveTransform)) {
            rules.pii_controls.safe_transform_enabled = true;
            verification_checks.push("pii_action=approve_transform".to_string());
        }

        if matches!(
            token.pii_action,
            Some(PiiApprovalAction::GrantScopedException)
        ) {
            let mut probe_tool = tool.clone();
            let mut verified = false;
            for spec in probe_tool.pii_egress_specs() {
                let Some(text) = probe_tool.pii_egress_field_mut(spec.field) else {
                    continue;
                };
                let (_scrubbed, _map, _report, routed, evidence) = service
                    .scrubber
                    .inspect_route_transform(
                        text,
                        &spec.target,
                        to_shared_risk_surface(spec.risk_surface),
                        &rules.pii_controls,
                        spec.supports_transform,
                    )
                    .await
                    .map_err(|e| {
                        TransactionError::Invalid(format!(
                            "PII verification failed while consuming scoped exception: {}",
                            e
                        ))
                    })?;

                if routed.decision_hash != expected_request_hash {
                    continue;
                }

                let scoped_exception = if let Some(existing) = token.scoped_exception.as_ref() {
                    existing.clone()
                } else {
                    mint_default_scoped_exception(
                        &evidence,
                        &spec.target,
                        to_shared_risk_surface(spec.risk_surface),
                        expected_request_hash,
                        block_timestamp_secs,
                        "deterministic-default",
                    )
                    .map_err(|e| {
                        TransactionError::Invalid(format!(
                            "Failed to mint deterministic scoped exception: {}",
                            e
                        ))
                    })?
                };

                let usage_key = pii::review::exception_usage(&scoped_exception.exception_id);
                let raw_usage = state.get(&usage_key)?;
                let uses_consumed = decode_exception_usage_state(raw_usage.as_deref())
                    .map_err(|e| TransactionError::Invalid(e.to_string()))?;
                verify_scoped_exception_for_decision(
                    &scoped_exception,
                    &evidence,
                    &spec.target,
                    to_shared_risk_surface(spec.risk_surface),
                    expected_request_hash,
                    &rules.pii_controls,
                    block_timestamp_secs,
                    uses_consumed,
                )
                .map_err(|e| {
                    let reason = match e {
                        ScopedExceptionVerifyError::PolicyDisabled => {
                            "Scoped exception policy disabled"
                        }
                        ScopedExceptionVerifyError::MissingAllowedClasses => {
                            "Scoped exception missing allowed classes"
                        }
                        ScopedExceptionVerifyError::DestinationMismatch => {
                            "Scoped exception destination mismatch"
                        }
                        ScopedExceptionVerifyError::ActionMismatch => {
                            "Scoped exception action mismatch"
                        }
                        ScopedExceptionVerifyError::Expired => "Scoped exception expired",
                        ScopedExceptionVerifyError::Overused => "Scoped exception overused",
                        ScopedExceptionVerifyError::IneligibleEvidence => {
                            "Scoped exception not eligible for this evidence"
                        }
                        ScopedExceptionVerifyError::ClassMismatch => {
                            "Scoped exception class mismatch"
                        }
                        ScopedExceptionVerifyError::InvalidMaxUses => {
                            "Scoped exception max_uses invalid"
                        }
                    };
                    TransactionError::Invalid(reason.to_string())
                })?;

                let next_uses = check_exception_usage_increment_ok(uses_consumed)
                    .map_err(|e| TransactionError::Invalid(e.to_string()))?;
                state.insert(&usage_key, &codec::to_bytes_canonical(&next_uses)?)?;
                scoped_exception_override_hash = Some(expected_request_hash);
                verified = true;
                break;
            }

            if !verified {
                return Err(TransactionError::Invalid(
                    "Scoped exception does not match the pending PII decision".into(),
                ));
            }
            verification_checks.push("pii_action=grant_scoped_exception".to_string());
        }

        if matches!(token.pii_action, Some(PiiApprovalAction::Deny)) {
            explicit_pii_deny = true;
            verification_checks.push("pii_action=deny".to_string());
        } else {
            mark_gate_approved(state, session_id)?;
        }
    } else if pii_request.is_some() {
        return Err(TransactionError::Invalid(
            "Missing approval token for review request".into(),
        ));
    } else if !matches!(tool, AgentTool::SysInstallPackage { .. }) {
        return Err(TransactionError::Invalid("Missing approval token".into()));
    } else {
        verification_checks.push("resume_without_approval_runtime_secret=true".to_string());
    }

    Ok(ApprovalResult {
        scoped_exception_override_hash,
        explicit_pii_deny,
    })
}
