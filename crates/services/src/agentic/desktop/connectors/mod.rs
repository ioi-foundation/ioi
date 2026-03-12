use crate::agentic::desktop::types::AgentState;
use ioi_api::state::StateAccess;
use ioi_types::app::agentic::ArgumentOrigin;
use ioi_types::app::agentic::{CapabilityId, ProtectedSlotKind, ProviderRouteCandidate};
use serde_json::Value;
use std::collections::BTreeSet;
use std::future::Future;
use std::pin::Pin;

pub mod automation;
pub mod google_api;
pub mod google_auth;
pub mod google_workspace;
pub mod mail_connector;

pub type ProviderCandidateDiscoveryFuture<'a> =
    Pin<Box<dyn Future<Output = Vec<ProviderRouteCandidate>> + Send + 'a>>;
pub type ProviderCandidateDiscoverer = for<'a> fn(
    Option<&'a dyn StateAccess>,
    &'a str,
    &'a str,
    &'a BTreeSet<CapabilityId>,
) -> ProviderCandidateDiscoveryFuture<'a>;

pub type SymbolicReferenceResolutionFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Option<ResolvedSymbolicReference>, String>> + Send + 'a>>;
pub type SymbolicReferenceResolver =
    for<'a> fn(&'a AgentState, &'a str) -> SymbolicReferenceResolutionFuture<'a>;

pub type SymbolicReferenceInferenceFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Option<String>, String>> + Send + 'a>>;
pub type SymbolicReferenceInferencer = for<'a> fn(
    &'a AgentState,
    &'a str,
    &'a str,
    ProtectedSlotKind,
) -> SymbolicReferenceInferenceFuture<'a>;

pub type PostconditionVerificationFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Option<ConnectorPostconditionProof>, String>> + Send + 'a>>;
pub type PostconditionVerifier =
    for<'a> fn(&'a AgentState, &'a str, &'a Value, &'a str) -> PostconditionVerificationFuture<'a>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectorToolRouteBinding {
    pub tool_name: &'static str,
    pub provider_family: &'static str,
    pub route_label: &'static str,
}

#[derive(Clone, Copy)]
pub struct ConnectorProviderProbeBinding {
    pub provider_family: &'static str,
    pub discover: ProviderCandidateDiscoverer,
}

#[derive(Debug, Clone)]
pub struct ResolvedSymbolicReference {
    pub value: Value,
    pub origin: ArgumentOrigin,
    pub evidence: String,
    pub provider_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ConnectorPostconditionEvidence {
    pub key: String,
    pub evidence: String,
    pub observed_value: Option<String>,
    pub evidence_type: Option<String>,
    pub provider_id: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct ConnectorPostconditionProof {
    pub evidence: Vec<ConnectorPostconditionEvidence>,
}

#[derive(Clone, Copy)]
pub struct ConnectorSymbolicReferenceBinding {
    pub connector_id: &'static str,
    pub resolve: SymbolicReferenceResolver,
}

#[derive(Clone, Copy)]
pub struct ConnectorSymbolicReferenceInferenceBinding {
    pub connector_id: &'static str,
    pub infer: SymbolicReferenceInferencer,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectorProtectedSlotBinding {
    pub tool_name: String,
    pub slot: String,
    pub protected_slot_kind: ProtectedSlotKind,
}

#[derive(Clone, Copy)]
pub struct ConnectorPostconditionVerifierBinding {
    pub connector_id: &'static str,
    pub verify: PostconditionVerifier,
}

pub fn connector_tool_route_bindings() -> Vec<ConnectorToolRouteBinding> {
    let mut bindings = automation::automation_tool_route_bindings();
    bindings.extend(mail_connector::mail_connector_tool_route_bindings());
    bindings.extend(google_workspace::google_connector_tool_route_bindings());
    bindings
}

pub fn connector_id_for_tool_name(tool_name: &str) -> Option<&'static str> {
    let normalized = tool_name.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return None;
    }
    if google_workspace::is_google_connector_tool_name(&normalized) {
        return Some(google_workspace::GOOGLE_CONNECTOR_ID);
    }
    if mail_connector::mail_connector_tool_route_bindings()
        .into_iter()
        .any(|binding| binding.tool_name == normalized)
    {
        return Some(mail_connector::MAIL_CONNECTOR_ID);
    }
    None
}

pub fn connector_provider_probe_bindings() -> Vec<ConnectorProviderProbeBinding> {
    let mut bindings = automation::automation_provider_probe_bindings();
    bindings.extend(mail_connector::mail_connector_provider_probe_bindings());
    bindings.extend(google_workspace::google_connector_provider_probe_bindings());
    bindings
}

pub fn connector_symbolic_reference_bindings() -> Vec<ConnectorSymbolicReferenceBinding> {
    let mut bindings = mail_connector::mail_connector_symbolic_reference_bindings();
    bindings.extend(google_workspace::google_connector_symbolic_reference_bindings());
    bindings
}

pub fn connector_symbolic_reference_inference_bindings(
) -> Vec<ConnectorSymbolicReferenceInferenceBinding> {
    let mut bindings = mail_connector::mail_connector_symbolic_reference_inference_bindings();
    bindings.extend(google_workspace::google_connector_symbolic_reference_inference_bindings());
    bindings
}

pub fn connector_protected_slot_bindings() -> Vec<ConnectorProtectedSlotBinding> {
    let mut bindings = mail_connector::mail_connector_protected_slot_bindings();
    bindings.extend(google_workspace::google_connector_protected_slot_bindings());
    bindings
}

pub fn connector_postcondition_verifier_bindings() -> Vec<ConnectorPostconditionVerifierBinding> {
    let mut bindings = mail_connector::mail_connector_postcondition_verifier_bindings();
    bindings.extend(google_workspace::google_connector_postcondition_verifier_bindings());
    bindings
}
