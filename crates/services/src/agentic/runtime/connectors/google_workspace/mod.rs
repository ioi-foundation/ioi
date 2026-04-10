mod configure;
mod shield;
mod types;

use super::{
    google_api, google_auth, ConnectorPostconditionEvidence, ConnectorPostconditionProof,
    ConnectorPostconditionVerifierBinding, ConnectorProtectedSlotBinding,
    ConnectorProviderProbeBinding, ConnectorSymbolicReferenceBinding,
    ConnectorSymbolicReferenceInferenceBinding, ConnectorToolRouteBinding,
    PostconditionVerificationFuture, ProviderCandidateDiscoveryFuture, ResolvedSymbolicReference,
    SymbolicReferenceInferenceFuture, SymbolicReferenceResolutionFuture,
};
use crate::agentic::runtime::service::RuntimeAgentService;
use crate::agentic::runtime::types::AgentState;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ioi_types::app::agentic::{
    ArgumentOrigin, CapabilityId, LlmToolDefinition, ProtectedSlotKind, ToolCapabilityBinding,
};
use ioi_types::app::ActionTarget;
use ioi_types::error::TransactionError;
use lettre::message::Mailbox;
use serde_json::{json, Value};
use std::collections::BTreeSet;
use time::format_description::well_known::Rfc3339;
use time::{Duration as TimeDuration, OffsetDateTime};

pub use configure::connector_configure;
pub use shield::matches_google_connector_id;
use shield::{enforce_google_tool_shield_policy, runtime_resume_already_authorizes_google_tool};
pub use types::{
    ConnectorActionDefinition, ConnectorActionResult, ConnectorConfigureResult,
    ConnectorFieldDefinition, ConnectorFieldOption, GOOGLE_CONNECTOR_ID, GOOGLE_CONNECTOR_PROVIDER,
};
use types::{
    GoogleConnectorActionSpec, GwsCommandOutput, BIGQUERY_READ_TARGET, BIGQUERY_TOOL_NAME,
    BIGQUERY_WRITE_TARGET, GWS_DEFAULT_TIMEOUT_SECS,
};

include!("bindings.rs");
include!("postconditions.rs");
include!("execution.rs");
include!("action_specs.rs");
include!("args.rs");
include!("fields.rs");
