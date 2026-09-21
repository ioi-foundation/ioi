//! M01.10 — CANONICAL MCP NON-TOOL PRIMITIVE NORMALIZATION.
//!
//! Canon's rule for the exposed MCP surface is one sentence: every primitive resolves to an EXISTING canonical
//! owner with exact session, invocation and context bindings, produces the same admitted semantics as the
//! native path, and fails TYPED-UNAVAILABLE rather than inventing truth when normalization is impossible.
//! Before this module the second half was implemented and the first was not, and the answer itself was three
//! divergent JSON shapes under one `schema_version` with no registered contract to reconcile them: the
//! thread-scoped 501, the outward gateway's 501, and — worst — the stdio client's silence, which dropped every
//! server-initiated primitive instead of refusing it.
//!
//! WHAT THIS MODULE OWNS.
//!
//!   * ONE ENVELOPE, and it is a registered contract
//!     (`schema://ioi/components/hypervisor/mcp-primitive-normalization-decision/v1`). Both the positive and
//!     the typed-unavailable answer are built here and VALIDATED against that contract before they are served,
//!     so a member that drifts is a 500 in this daemon rather than a shape a consumer discovers in production.
//!     The contract refuses, in the schema itself, the two claims a protocol projection must never make:
//!     `authority_granted` and `receipt_identity_granted` are constant false, and a normalized decision must
//!     name the admitted record it resolved to.
//!   * THE CLOSED PRIMITIVE → OWNER MAP. A URI substring no longer decides what a primitive is: the map is a
//!     table, the vocabulary is closed, and an unrecognised path resolves to `mcp.unknown` rather than falling
//!     through to whatever the last branch happened to be.
//!   * THE ONE POSITIVE THIS TREE CAN HONESTLY SERVE: an MCP App resolves to M08.10's admitted
//!     `extension_application` registration. The descriptor is a PROJECTION of that registration — its
//!     canonical route, class, origin, effect boundary and declared contract sets, bound to the exact
//!     installation revision — and it grants nothing: no host, no runtime, no authority, no receipt identity.
//!     An unregistered, recalled or foreign-organization App is refused by name rather than described.
//!
//! WHAT IT DELIBERATELY DOES NOT DO, and why each is a NAMED absence rather than a silent gap:
//!
//!   * RESOURCES. Canon's target is a `PolicyBoundDataView`, an `ArtifactRef` or a `MemoryProjection` read
//!     under a `ContextLease`. `ContextLease` is the ioi.ai orchestration application's record over the
//!     generic System-record seam (R-192, R-202), and the seam knows no application vocabulary by
//!     construction — a daemon route that read a lease's status to gate a resource would be the second spine
//!     the estate's one structural law forbids. `ArtifactRef` has no producer (R-205, open) and
//!     `MemoryProjection` has no registered contract. Three targets, none of which this daemon may resolve
//!     today, so the resource primitive names them and refuses.
//!   * PROMPTS. The owner exists (M04.3's `SkillManifest`) but the inert, provenance-bearing IMPORT RECORD
//!     that a normalized prompt would produce does not, and inventing one here would be a record family with
//!     no contract behind it.
//!   * ELICITATION and TASKS. No typed-user-input family and no `HarnessInvocation` record family exist.
//!
//! THE REFUSAL IS THE PRODUCT HERE. A typed-unavailable answer names the owner that WOULD serve the primitive,
//! which is what lets a caller tell "unbuilt" from "forbidden" from "unsupported" — and is why the negative
//! half of this module is longer than the positive one.

use std::sync::Arc;

use axum::extract::{Path as AxumPath, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use ioi_types::app::generated::architecture_contracts::validate_architecture_contract;
use serde_json::{json, Value};

use crate::DaemonState;

/// The registered contract every answer this module serves is validated against.
pub(crate) const MCP_NORMALIZATION_DECISION_CONTRACT: &str =
    "schema://ioi/components/hypervisor/mcp-primitive-normalization-decision/v1";

/// The closed primitive → canonical-owner map. Canon's, and a table rather than a chain of `contains`:
/// a substring test on a URI is how `/v1/threads/:id/mcp/apps/prompts-demo/descriptor` becomes a prompt.
const PRIMITIVE_OWNERS: &[(&str, &str, &str)] = &[
    // (path segment, primitive, the canonical owner that serves it or would have to)
    (
        "/resources",
        "mcp.resource",
        "PolicyBoundDataView|ArtifactRef|MemoryProjection+ContextLease",
    ),
    (
        "/prompts",
        "mcp.prompt",
        // R-192: the ioi.ai application owns goal pursuit, so a prompt normalizes to a tainted import of a
        // Hypervisor-owned SkillManifest or of an application-owned profile — never to a Hypervisor GoalRun.
        "tainted-import:SkillManifest|ioi.ai-owned-profile|invocation",
    ),
    (
        "/elicitation-requests",
        "mcp.elicitation",
        "typed-user-input-request",
    ),
    (
        "/external-task-bindings",
        "mcp.task",
        "HarnessInvocation.external-handle",
    ),
    (
        "/apps",
        "mcp.app",
        "sandboxed-extension_application-descriptor-and-surface",
    ),
    ("/serve", "mcp.serve", "RuntimeMcpServe"),
];

/// Classify one thread-scoped MCP path. An unrecognised path is `mcp.unknown`, never the last branch.
pub(crate) fn classify_primitive(path: &str) -> (&'static str, &'static str) {
    for (segment, primitive, owner) in PRIMITIVE_OWNERS {
        if path.contains(segment) {
            return (primitive, owner);
        }
    }
    ("mcp.unknown", "none")
}

/// The one envelope builder. `backing` is `Some(ref)` for a normalized decision and `None` for a
/// typed-unavailable one, which is the only difference the contract admits between the two answers.
pub(crate) fn normalization_decision(
    primitive: &str,
    canonical_owner: &str,
    backing: Option<&str>,
    reason: &str,
    context: Value,
) -> Result<Value, String> {
    let normalized = backing.is_some();
    let mut decision = json!({
        "schema_version": "ioi.runtime.mcp-normalization-decision.v1",
        "status": if normalized { "normalized" } else { "typed_unavailable" },
        "primitive": primitive,
        "canonical_owner": canonical_owner,
        "canonical_backing_ref": backing.map(Value::from).unwrap_or(Value::Null),
        "normalization_decision": if normalized { "normalized" } else { "typed_unavailable" },
        // NEVER TRUE, in either branch. A protocol projection describes an owner's record; it does not become
        // that owner's authority by describing it, and it writes no receipt.
        "authority_granted": false,
        "receipt_identity_granted": false,
        "source_protocol_version": ioi_drivers::mcp::protocol::MCP_PROTOCOL_VERSION,
        "policy_lease_posture": if normalized { "not_applicable" } else { "not_minted" },
        "reason": reason,
    });
    if let (Some(object), Some(extra)) = (decision.as_object_mut(), context.as_object()) {
        for (key, value) in extra {
            object.insert(key.clone(), value.clone());
        }
    }
    // The answer is checked against the registered contract HERE, before it is served. A drifting member is
    // this daemon's failure to notice, not a consumer's to discover.
    validate_architecture_contract(MCP_NORMALIZATION_DECISION_CONTRACT, &decision)
        .map_err(|error| format!("mcp normalization decision is not contract-valid: {error}"))?;
    Ok(decision)
}

fn decision_or_500(
    decision: Result<Value, String>,
    status: StatusCode,
) -> (StatusCode, Json<Value>) {
    match decision {
        Ok(value) => (status, Json(value)),
        Err(detail) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(
                json!({ "error": { "code": "mcp_normalization_decision_invalid", "message": detail } }),
            ),
        ),
    }
}

/// The typed-unavailable answer for a thread-scoped MCP path, as the registered contract.
pub(crate) fn typed_unavailable(
    path: &str,
    thread_id: &str,
    object_id: Option<String>,
) -> (StatusCode, Json<Value>) {
    let (primitive, canonical_owner) = classify_primitive(path);
    decision_or_500(
        normalization_decision(
            primitive,
            canonical_owner,
            None,
            "This MCP protocol object has no admitted canonical runtime normalization implementation.",
            json!({
                "thread_id": thread_id,
                "object_id": object_id,
                "effective_gateway_profile_revision": Value::Null,
            }),
        ),
        StatusCode::NOT_IMPLEMENTED,
    )
}

/// The outward gateway's typed-unavailable answer, now the SAME contract rather than a second shape.
pub(crate) fn gateway_typed_unavailable(tool: Option<String>) -> (StatusCode, Json<Value>) {
    decision_or_500(
        normalization_decision(
            "mcp.gateway",
            "HypervisorMCPGatewayProfile",
            None,
            "No admitted subject-scoped Hypervisor MCP Gateway profile resolves this external surface.",
            json!({
                "tool": tool,
                "gateway_profile_revision_ref": Value::Null,
                "resolved_requirement_revision_refs": [],
            }),
        ),
        StatusCode::NOT_IMPLEMENTED,
    )
}

// ---- the App positive ----------------------------------------------------------------------------------
// An MCP App resolves to an admitted `extension_application` registration and to nothing else. The descriptor
// is that registration's own bytes, projected: what it is, where it is mounted, what contracts it declared and
// what effect boundary it was admitted under. It is not the App's runtime, and reading it starts nothing.

/// The organization whose admitted registrations a caller may see. Registrations are org-scoped, so a caller
/// with no resolvable organization sees the local one and never another tenant's.
fn caller_org_ref(st: &DaemonState, headers: &HeaderMap) -> String {
    super::lifecycle_routes::resolve_principal(&st.data_dir, headers)
        .and_then(|principal| {
            principal["tenant_refs"].as_array().and_then(|refs| {
                refs.iter()
                    .filter_map(Value::as_str)
                    .find(|tenant| tenant.starts_with("org://"))
                    .map(str::to_owned)
            })
        })
        .unwrap_or_else(|| "org://local".to_string())
}

/// One admitted registration projected as a sandboxed App descriptor, or `None` when nothing admitted answers.
fn app_descriptor(
    st: &DaemonState,
    org_ref: &str,
    app_id: &str,
) -> Option<(Value, String, Vec<String>)> {
    let surface_ref = format!("surface://extensions/{app_id}");
    let (registrations, _releases, installations, _serving) =
        super::package_registry_routes::registered_extension_surfaces(&st.data_dir, org_ref)
            .ok()?;
    let registration = registrations
        .into_iter()
        .find(|row| row["surface_ref"].as_str() == Some(surface_ref.as_str()))?;
    let installation = installations
        .iter()
        .find(|row| row["surface_ref"].as_str() == Some(surface_ref.as_str()))
        .cloned()
        .unwrap_or(Value::Null);
    let revisions: Vec<String> = [
        installation["installation_ref"].as_str(),
        installation["release_ref"].as_str(),
    ]
    .into_iter()
    .flatten()
    .map(str::to_owned)
    .collect();
    let descriptor = json!({
        "app_id": app_id,
        "surface_ref": surface_ref,
        "display_name": registration["display_name"].clone(),
        "canonical_route": registration["canonical_route"].clone(),
        "surface_class": registration["surface_class"].clone(),
        "surface_origin": registration["surface_origin"].clone(),
        "surface_creation_method": registration["surface_creation_method"].clone(),
        "effect_boundary": registration["effect_boundary"].clone(),
        "declared_object_contract_refs": registration["declared_object_contract_refs"].clone(),
        "declared_action_contract_refs": registration["declared_action_contract_refs"].clone(),
        "supported_placements": registration["supported_placements"].clone(),
        "launch_modes": registration["launch_modes"].clone(),
        // Said in the bytes, not only in the envelope: what reading this descriptor does not buy.
        "grants": {
            "host_mutation": false,
            "runtime_ownership": false,
            "authority": false,
            "receipt_identity": false,
        },
    });
    Some((descriptor, surface_ref, revisions))
}

/// GET /v1/threads/:id/mcp/apps/search — the admitted extension applications this caller's organization holds.
pub(crate) async fn handle_mcp_apps_search(
    State(st): State<Arc<DaemonState>>,
    AxumPath(thread_id): AxumPath<String>,
    headers: HeaderMap,
) -> (StatusCode, Json<Value>) {
    if super::lifecycle_routes::mcp_thread_missing(&st, &thread_id) {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": { "code": "mcp_thread_not_found" } })),
        );
    }
    let org_ref = caller_org_ref(&st, &headers);
    let apps = match super::package_registry_routes::registered_extension_surfaces(
        &st.data_dir,
        &org_ref,
    ) {
        Ok((registrations, _, _, _)) => registrations
            .into_iter()
            .filter_map(|row| {
                let surface_ref = row["surface_ref"].as_str()?.to_owned();
                let app_id = surface_ref
                    .strip_prefix("surface://extensions/")?
                    .to_owned();
                Some(json!({
                    "app_id": app_id,
                    "surface_ref": surface_ref,
                    "display_name": row["display_name"].clone(),
                    "canonical_route": row["canonical_route"].clone(),
                    "effect_boundary": row["effect_boundary"].clone(),
                }))
            })
            .collect::<Vec<_>>(),
        Err(detail) => {
            // Registry unreadability is a typed refusal, never a thinner catalog.
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(
                    json!({ "error": { "code": "extension_registry_unavailable", "message": detail } }),
                ),
            );
        }
    };
    let count = apps.len();
    decision_or_500(
        normalization_decision(
            "mcp.app",
            "sandboxed-extension_application-descriptor-and-surface",
            Some("surface://extensions"),
            "Apps resolve to the organization's admitted extension_application registrations; the listing is a projection and grants nothing.",
            json!({
                "thread_id": thread_id,
                "object_id": Value::Null,
                "apps": apps,
                "app_count": count,
                "org_ref": org_ref,
            }),
        ),
        StatusCode::OK,
    )
}

/// GET /v1/threads/:id/mcp/apps/:app_id/descriptor — one admitted App, projected.
pub(crate) async fn handle_mcp_app_descriptor(
    State(st): State<Arc<DaemonState>>,
    AxumPath((thread_id, app_id)): AxumPath<(String, String)>,
    headers: HeaderMap,
) -> (StatusCode, Json<Value>) {
    if super::lifecycle_routes::mcp_thread_missing(&st, &thread_id) {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": { "code": "mcp_thread_not_found" } })),
        );
    }
    let org_ref = caller_org_ref(&st, &headers);
    let Some((descriptor, surface_ref, revisions)) = app_descriptor(&st, &org_ref, &app_id) else {
        // An App this organization has not admitted is REFUSED BY NAME, not described. A recalled release or
        // another tenant's registration reaches this same refusal, because neither is in this org's admitted
        // set — which is the whole of the private-projection rule for this route.
        return decision_or_500(
            normalization_decision(
                "mcp.app",
                "sandboxed-extension_application-descriptor-and-surface",
                None,
                "No extension_application registration admitted by this organization answers this App id.",
                json!({
                    "thread_id": thread_id,
                    "object_id": app_id,
                    "refusal_code": "extension_application_registration_absent",
                }),
            ),
            StatusCode::NOT_FOUND,
        );
    };
    decision_or_500(
        normalization_decision(
            "mcp.app",
            "sandboxed-extension_application-descriptor-and-surface",
            Some(&surface_ref),
            "The App resolves to an admitted extension_application registration; the descriptor is a projection of that registration and grants no host, runtime, authority or receipt identity.",
            json!({
                "thread_id": thread_id,
                "object_id": app_id,
                "backing_revision_refs": revisions,
                "descriptor": descriptor,
                "org_ref": org_ref,
            }),
        ),
        StatusCode::OK,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_primitive_map_is_a_table_and_an_unknown_path_is_not_the_last_branch() {
        assert_eq!(
            classify_primitive("/v1/threads/t/mcp/resources/search").0,
            "mcp.resource"
        );
        assert_eq!(
            classify_primitive("/v1/threads/t/mcp/prompts/p/imports").0,
            "mcp.prompt"
        );
        assert_eq!(
            classify_primitive("/v1/threads/t/mcp/elicitation-requests").0,
            "mcp.elicitation"
        );
        assert_eq!(
            classify_primitive("/v1/threads/t/mcp/external-task-bindings").0,
            "mcp.task"
        );
        assert_eq!(
            classify_primitive("/v1/threads/t/mcp/apps/a/descriptor").0,
            "mcp.app"
        );
        assert_eq!(classify_primitive("/v1/threads/t/mcp/serve").0, "mcp.serve");
        // The old classifier ended in an `else` that called anything unrecognised `mcp.serve`.
        assert_eq!(
            classify_primitive("/v1/threads/t/mcp/telepathy").0,
            "mcp.unknown"
        );
    }

    #[test]
    fn the_prompt_owner_no_longer_names_a_hypervisor_goal_run() {
        let (_, owner) = classify_primitive("/v1/threads/t/mcp/prompts/search");
        assert!(
            !owner.contains("GoalRun"),
            "R-192: goal pursuit is the ioi.ai application's composition; the daemon's own wire bytes may not \
             name a Hypervisor GoalRunProfile as an MCP prompt's canonical owner — got {owner}"
        );
        assert!(owner.contains("SkillManifest"));
    }

    #[test]
    fn every_decision_is_contract_valid_and_neither_branch_grants_anything() {
        let refused = normalization_decision(
            "mcp.resource",
            "PolicyBoundDataView|ArtifactRef|MemoryProjection+ContextLease",
            None,
            "no admitted owner",
            json!({ "thread_id": "thr_1", "object_id": Value::Null }),
        )
        .expect("the typed-unavailable envelope is contract-valid");
        assert_eq!(refused["normalization_decision"], "typed_unavailable");
        assert_eq!(refused["canonical_backing_ref"], Value::Null);
        assert_eq!(refused["authority_granted"], false);
        assert_eq!(refused["receipt_identity_granted"], false);
        assert_eq!(refused["policy_lease_posture"], "not_minted");

        let normalized = normalization_decision(
            "mcp.app",
            "sandboxed-extension_application-descriptor-and-surface",
            Some("surface://extensions/demo"),
            "resolved",
            json!({ "thread_id": "thr_1", "object_id": "demo" }),
        )
        .expect("the normalized envelope is contract-valid");
        assert_eq!(normalized["normalization_decision"], "normalized");
        assert_eq!(
            normalized["canonical_backing_ref"],
            "surface://extensions/demo"
        );
        assert_eq!(normalized["authority_granted"], false);
        assert_eq!(normalized["receipt_identity_granted"], false);
    }

    #[test]
    fn a_context_member_the_contract_does_not_admit_is_refused_here_rather_than_served() {
        let refused = normalization_decision(
            "mcp.app",
            "owner",
            Some("surface://extensions/demo"),
            "resolved",
            json!({ "admitted": true }),
        );
        assert!(
            refused.is_err(),
            "the contract closes the envelope against extra members, and the daemon must not serve one"
        );
    }

    #[test]
    fn the_gateway_and_the_thread_routes_answer_with_one_shape() {
        let (status, Json(gateway)) = gateway_typed_unavailable(Some("hypervisor.tool".into()));
        assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
        let (_, Json(thread)) = typed_unavailable("/v1/threads/t/mcp/resources/search", "t", None);
        for key in [
            "schema_version",
            "status",
            "primitive",
            "canonical_owner",
            "canonical_backing_ref",
            "normalization_decision",
            "authority_granted",
            "receipt_identity_granted",
            "source_protocol_version",
            "policy_lease_posture",
            "reason",
        ] {
            assert!(gateway.get(key).is_some(), "the gateway answer omits {key}");
            assert!(thread.get(key).is_some(), "the thread answer omits {key}");
        }
        assert_eq!(gateway["schema_version"], thread["schema_version"]);
    }
}
