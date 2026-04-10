use super::{
    ConnectorProviderProbeBinding, ConnectorToolRouteBinding, ProviderCandidateDiscoveryFuture,
};
use ioi_api::state::StateAccess;
use ioi_types::app::agentic::{CapabilityId, ProviderRouteCandidate};
use std::collections::BTreeSet;

const AUTOMATION_CONNECTOR_ID: &str = "autopilot.workflow_manager";
const AUTOMATION_PROVIDER_FAMILY: &str = "automation.local_kernel";
const AUTOMATION_ROUTE_LABEL: &str = "autopilot_workflow_kernel";

const AUTOMATION_TOOL_ROUTE_BINDINGS: &[ConnectorToolRouteBinding] = &[ConnectorToolRouteBinding {
    tool_name: "automation__create_monitor",
    provider_family: AUTOMATION_PROVIDER_FAMILY,
    route_label: AUTOMATION_ROUTE_LABEL,
}];

pub fn automation_tool_route_bindings() -> Vec<ConnectorToolRouteBinding> {
    AUTOMATION_TOOL_ROUTE_BINDINGS.to_vec()
}

fn capability_vec(sorted_caps: &BTreeSet<CapabilityId>) -> Vec<CapabilityId> {
    sorted_caps.iter().cloned().collect()
}

fn discover_automation_provider_candidates(
    _state: Option<&dyn StateAccess>,
    provider_family: &str,
    route_label: &str,
    capabilities: &BTreeSet<CapabilityId>,
) -> Vec<ProviderRouteCandidate> {
    vec![ProviderRouteCandidate {
        provider_family: provider_family.to_string(),
        route_label: route_label.to_string(),
        connector_id: AUTOMATION_CONNECTOR_ID.to_string(),
        provider_id: Some("automation://local-kernel".to_string()),
        account_label: Some("local automation kernel".to_string()),
        capabilities: capability_vec(capabilities),
        summary:
            "Local workflow kernel for durable automation installs with persisted artifacts and receipts."
                .to_string(),
    }]
}

fn discover_automation_provider_candidates_boxed<'a>(
    state: Option<&'a dyn StateAccess>,
    provider_family: &'a str,
    route_label: &'a str,
    capabilities: &'a BTreeSet<CapabilityId>,
) -> ProviderCandidateDiscoveryFuture<'a> {
    Box::pin(async move {
        discover_automation_provider_candidates(state, provider_family, route_label, capabilities)
    })
}

pub fn automation_provider_probe_bindings() -> Vec<ConnectorProviderProbeBinding> {
    vec![ConnectorProviderProbeBinding {
        provider_family: AUTOMATION_PROVIDER_FAMILY,
        discover: discover_automation_provider_candidates_boxed,
    }]
}
