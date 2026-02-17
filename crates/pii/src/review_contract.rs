// Submodule: review_contract (resume-token invariants)

use ioi_types::app::action::{ApprovalToken, PiiApprovalAction};
use ioi_types::app::agentic::{PiiDecisionMaterial, PiiReviewRequest, PiiReviewSummary};

use crate::cim_v0::CimAssistV0Provider;
use crate::assist::CimAssistProvider;

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

