// Path: crates/pii/src/lib.rs

mod cim_v0;

mod assist;
mod decision;
mod hashing;
mod review_contract;
mod review_summary;
mod routing;
mod scoped_exception;
mod targets;
mod transform;

#[cfg(test)]
mod tests;

pub use cim_v0::{CimAssistV0Config, CimAssistV0Provider};

pub use assist::{
    CimAssistContext, CimAssistProvider, CimAssistReceipt, CimAssistResult, InspectFuture,
    NoopCimAssistProvider, RiskSurface,
};

pub use review_contract::{
    expected_assist_identity, check_exception_usage_increment_ok, decode_exception_usage_state,
    resolve_expected_request_hash, validate_resume_review_contract, validate_review_request_compat,
    PiiReviewContractError, ResumeReviewMode, REVIEW_REQUEST_VERSION,
};

pub use decision::{build_decision_material, compute_decision_hash};

pub use review_summary::build_review_summary;

pub use scoped_exception::{
    mint_default_scoped_exception, mint_scoped_exception, scoped_exception_destination_hash,
    verify_scoped_exception_for_decision, ScopedExceptionVerifyError,
    DEFAULT_SCOPED_EXCEPTION_MAX_USES, DEFAULT_SCOPED_EXCEPTION_TTL_SECS,
};

pub use routing::{
    route_pii_decision, route_pii_decision_for_target, route_pii_decision_with_assist,
    route_pii_decision_with_assist_for_target, PiiRoutingOutcome,
};

pub use targets::{is_high_risk_target, is_high_risk_target_legacy};

pub use transform::{apply_transform, canonical_placeholder_label, scrub_text, PostTransformReport};

// Re-export a few crate-private helpers used by unit tests.
pub(crate) use assist::build_assist_receipt;
pub(crate) use hashing::graph_hash;
