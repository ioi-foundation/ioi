//! Domain Apps object plane — FOUNDATION cut (daemon-first, draft-only).
//!
//! A DomainApp is a real generated-app CANDIDATE over an ODK surface descriptor. This cut builds the
//! object plane, not a runtime: a durable draft `DomainApp` that MUST reference a real
//! `surface-descriptor://…` whose `composition_pattern == domain_app` (the app-shape contract), with
//! an optional `odk_manifest_ref` for packaging provenance.
//!
//! Deliberately inert — it does NOT pretend the runtime exists:
//!   * no generated/mounted app runtime, no app iframe/route mounting, no widget execution;
//!   * no form submission, no domain-action execution;
//!   * no marketplace publish; no authority crossing.
//! `runtime_posture` is always {mounted:false, route:null}. `status` is always "draft". No
//! `/__ioi/domain-apps` UI card in this cut. `/v1/hypervisor/blueprints` stays 404.

use std::path::Path;
use std::sync::Arc;

use axum::extract::{Path as AxumPath, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde_json::{json, Value};
use std::collections::HashMap;

use super::mutation_event_foundation::{
    admit_owner_scoped_write, replay_stable_id, require_write_caller, WriteCaller,
};
use super::{persist_record, remove_record, DaemonState};

/// Every Domain App record lives under one owner namespace so a tenant's apps cannot be read or
/// advanced through another tenant's scope.
const DAPP_NAMESPACE: &str = "hypervisor-domain-apps";

const KIND_DAPP: &str = "domain-apps";
const KIND_MANIFEST: &str = "odk-manifests";
/// Visibility of a draft DomainApp (marketplace_candidate is a flag, not a publish).
const VISIBILITIES: &[&str] = &["private", "org", "marketplace_candidate"];

// ================= M05.6 · REGISTERED CONTRACTS, AND THE TWO STATE KINDS KEPT APART ==============
//
// WHAT WAS UNREGISTERED AND WHY IT MATTERED. G-4 forbids a surface, client or projection from
// claiming an object family until that family's wire contract is registered under `_meta/schemas/`.
// No `_meta/schemas/` entry existed for ANY ODK family, so `ioi.hypervisor.domain-app.v1`,
// `…domain-app-runtime.v1` and `…domain-app-mount-receipt.v1` were Rust string literals: three
// families with no checkable shape, no fixtures, no projections, and nothing a relying party could
// validate against. Registration is this leg's first task, and these constants are what the routes
// now build and validate against.
//
// FOUR REPAIRS ARE STRUCTURAL RATHER THAN DOCUMENTARY.
//
// 1. THE RECEIPT BINDS THE RUNTIME IT TRANSITIONED. Canon requires `domain_app_runtime_ref` because
//    an app accumulates several runtimes over its life and a receipt naming only the app cannot say
//    which mount it transitioned. v2 carries the runtime ref, its OWNER, the exact `revision` this
//    receipt attests, the runtime's own `content_hash` for the state the transition produced, and
//    the exact admitted head the transition was admitted against.
//
// 2. INVENTORY STATUS AND RUNTIME STATE ARE DIFFERENT FIELDS WITH DIFFERENT WRITERS (G-6). `status`
//    was pinned to the literal `draft` and no path advanced it, so four of canon's five members were
//    unreachable. It now advances only through `handle_domain_app_inventory_status`, which requires
//    the stage binding that produced the advance, and NO runtime transition may move it. Runtime
//    state lives on the runtime; the app's `runtime_posture` is a backlink projection that must name
//    the runtime it projects.
//
// 3. IDENTITY AND TIME ARE DERIVED, NEVER MINTED FROM THE CLOCK. `dartm_{nanos():x}` made every
//    retried mount a SECOND runtime, and `iso_now()` in an admitted payload makes a retry
//    byte-different from itself — which is precisely what turns an idempotency key into a key that
//    matches nothing. Runtime and receipt ids are derived from owner and caller idempotency key, and
//    every stamp comes from the admission.
//
// 4. INGRESS IS SEPARABLE FROM SERVING. v1 had no ingress field at all, so "serving" and "reachable
//    from outside" were the same absence. `external_ingress_ref` is now its own required field that
//    serving leaves null.

const DOMAIN_APP_V2_SCHEMA_VERSION: &str = "ioi.domain-app.v2";
const DOMAIN_APP_V1_SCHEMA_VERSION: &str = "ioi.hypervisor.domain-app.v1";
const DOMAIN_APP_V2_CONTRACT_ID: &str = "schema://ioi/foundations/objects/domain-app/v2";
const DOMAIN_APP_V1_CONTRACT_ID: &str = "schema://ioi/foundations/objects/domain-app/v1";
const RUNTIME_V2_SCHEMA_VERSION: &str = "ioi.domain-app-runtime.v2";
const RUNTIME_V2_CONTRACT_ID: &str = "schema://ioi/foundations/objects/domain-app-runtime/v2";
const RECEIPT_V2_SCHEMA_VERSION: &str = "ioi.domain-app-mount-receipt.v2";
const RECEIPT_V2_CONTRACT_ID: &str = "schema://ioi/foundations/objects/domain-app-mount-receipt/v2";

/// The projection envelope a v2 DomainApp row is stored in.
///
/// The registered record is CLOSED, so `created_at`, `updated_at` and `admitted_head` — which are
/// facts about the stream rather than fields of the contract — cannot live inside it. A stored v1
/// row inlines them because that is how the legacy lane wrote it; there is no third shape.
const DOMAIN_APP_PROJECTION_SCHEMA: &str = "ioi.hypervisor.domain-app-projection.v2";

/// Canon's five inventory members. Disjoint from the runtime vocabulary on purpose: no member here
/// appears in a runtime `state`, so a reader can never mistake `admitted` for `running`.
const DOMAIN_APP_STATUSES: &[&str] = &["draft", "admitted", "installed", "deprecated", "revoked"];

/// The seven nonclaims every v2 DomainApp carries. `registration` and `launchability` are the two
/// this family needs most: a mounted, serving Domain App is still not product inventory.
const DOMAIN_APP_NONCLAIMS: &[&str] = &[
    "authority",
    "runtime_truth",
    "semantic_truth",
    "permission_truth",
    "marketplace_truth",
    "registration",
    "launchability",
];
const RUNTIME_NONCLAIMS: &[&str] = &[
    "authority",
    "registration",
    "launchability",
    "external_ingress",
    "app_behaviour",
];
const RECEIPT_NONCLAIMS: &[&str] = &[
    "app_behaviour",
    "semantic_validity",
    "external_surface_exists",
    "domain_action_ran",
];

const DOMAIN_APP_CONTENT_DOMAIN: &str = "ioi.domain-app-content-commitment-jcs-sha256.v2";
const RUNTIME_CONTENT_DOMAIN: &str = "ioi.domain-app-runtime-content-commitment-jcs-sha256.v2";
const RECEIPT_STATE_ROOT_DOMAIN: &str = "ioi.domain-app-mount-receipt-state-root-jcs-sha256.v2";

/// The v2 DomainApp contract's material list, in the registered invariant profile's own set.
///
/// A field added to the schema and forgotten here produces a commitment that omits it, which is how
/// a "committed" record acquires an uncommitted field. The focused test below asserts this list
/// against the registered profile, so the drift fails there rather than at the first relying party
/// who cannot reproduce a hash.
const DOMAIN_APP_MATERIAL_FIELDS: &[&str] = &[
    "schema_version",
    "domain_app_id",
    "name",
    "description",
    "surface_descriptor_ref",
    "surface_descriptor_schema_version",
    "surface_descriptor_content_hash",
    "odk_manifest_ref",
    "owner_ref",
    "project_ref",
    "visibility",
    "ontology_refs",
    "canonical_object_model_refs",
    "data_recipe_refs",
    "policy_bound_data_view_refs",
    "operator_contract_refs",
    "mcp_contract_refs",
    "authority_requirement_refs",
    "receipt_obligations",
    "generated_artifact_refs",
    "surface_registration_ref",
    "package_release_ref",
    "installation_ref",
    "system_binding_refs",
    "launch_posture",
    "status",
    "runtime_posture",
    "migration",
    "authority_nonclaim",
    "truth_nonclaim",
    "does_not_assert",
];
const RUNTIME_MATERIAL_FIELDS: &[&str] = &[
    "schema_version",
    "domain_app_runtime_id",
    "domain_app_ref",
    "owner_ref",
    "revision",
    "state",
    "mounted",
    "serving",
    "internal_route_ref",
    "external_ingress_ref",
    "approval_request_ref",
    "release_control_ref",
    "authority_refs",
    "receipt_refs",
    "rollback_posture",
    "mounted_at",
    "serve_started_at",
    "serve_stopped_at",
    "unmounted_at",
    "unmount_reason",
    "killed_at",
    "authority_nonclaim",
    "truth_nonclaim",
    "does_not_assert",
];
const RECEIPT_MATERIAL_FIELDS: &[&str] = &[
    "schema_version",
    "mount_receipt_id",
    "action",
    "domain_app_ref",
    "domain_app_runtime_ref",
    "domain_app_runtime_owner_ref",
    "domain_app_runtime_revision",
    "domain_app_runtime_content_hash",
    "domain_app_admitted_head_before",
    "approval_request_ref",
    "release_control_ref",
    "at",
    "does_not_assert",
];

/// Validate one assembled record against the REGISTERED contract before it can be admitted.
///
/// An unprojectable record refused here is a typed 400; the same record admitted and then found
/// unprojectable on read is permanently durable bytes the read path can only answer 502 about.
fn registered_valid(
    contract_id: &str,
    record: &Value,
    code: &'static str,
) -> Result<(), (StatusCode, Json<Value>)> {
    ioi_types::app::generated::architecture_contracts::validate_architecture_contract(
        contract_id, record,
    )
    .map_err(|reason| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "ok": false,
                "error": {
                    "code": code,
                    "message": format!(
                        "the record this request builds is not valid against {contract_id}: {reason}"
                    )
                }
            })),
        )
    })
}

/// Commit a record under its registered domain separator, writing the digest into `target`.
fn commit_record(record: &mut Value, domain: &str, fields: &[&str], target: &str) {
    let digest = super::odk_routes::domain_separated_hash(record, domain, fields);
    record[target] = json!(digest);
}

/// Refuse an authoring request that names any contract this build does not author.
///
/// DOWNGRADE IS A REFUSAL, NEVER A SILENT ACCEPT. A caller naming the predecessor is answered by
/// name — not read as v2, and not written as v1 — because reading a v1 request as a v2 record is the
/// exact reinterpretation the succession exists to avoid, and writing a v1 record would reopen the
/// lane whose divergences this unit closed.
fn require_authored_version(
    body: &Value,
    authored: &str,
    predecessor: &str,
    family: &str,
) -> Result<(), (StatusCode, Json<Value>)> {
    match body.get("schema_version") {
        None | Some(Value::Null) => Ok(()),
        Some(Value::String(declared)) if declared == authored => Ok(()),
        Some(Value::String(declared)) if declared == predecessor => Err(bad(
            "domain_app_predecessor_contract_not_authorable",
            &format!(
                "'{predecessor}' is the deprecated {family} contract and is no longer authorable; this build authors '{authored}'. Stored predecessor records remain readable and are never reinterpreted as successors"
            ),
        )),
        Some(declared) => Err(bad(
            "domain_app_contract_unsupported",
            &format!(
                "this build authors {authored} only; {declared} is refused rather than downgraded"
            ),
        )),
    }
}

fn safe(seg: &str) -> String {
    seg.replace(
        |c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '_',
        "_",
    )
}
fn load(data_dir: &str, kind: &str, id: &str) -> Option<Value> {
    serde_json::from_slice(
        &std::fs::read(
            Path::new(data_dir)
                .join(kind)
                .join(format!("{}.json", safe(id))),
        )
        .ok()?,
    )
    .ok()
}
fn bad(code: &str, message: &str) -> (StatusCode, Json<Value>) {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({ "ok": false, "error": { "code": code, "message": message } })),
    )
}
fn persist_required(
    data_dir: &str,
    kind: &str,
    id: &str,
    record: &Value,
    code: &str,
) -> Result<(), (StatusCode, Json<Value>)> {
    persist_record(data_dir, kind, id, record).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "ok": false,
                "error": {
                    "code": code,
                    "message": "the durable record could not be committed"
                }
            })),
        )
    })
}
fn split_ref(r: &str) -> Option<(&str, &str)> {
    r.split_once("://")
        .filter(|(s, rest)| !s.is_empty() && !rest.is_empty())
}
fn str_field<'a>(body: &'a Value, key: &str) -> &'a str {
    body.get(key)
        .and_then(|v| v.as_str())
        .map(str::trim)
        .unwrap_or("")
}
fn str_refs(body: &Value, key: &str) -> Vec<String> {
    body.get(key)
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}
fn arr_strs(v: &Value, key: &str) -> Vec<String> {
    v.get(key)
        .and_then(|x| x.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}
fn push_unique(v: &mut Vec<String>, s: &str) {
    if !s.is_empty() && !v.iter().any(|x| x == s) {
        v.push(s.to_string());
    }
}

/// Resolve `surface_descriptor_ref` and enforce the app-shape contract: it must resolve through the
/// descriptor OWNER and carry `composition_pattern: domain_app`.
///
/// M05.5 — THROUGH THE OWNER'S PUBLISHED READER, NOT THE RECORD DIRECTORY. This consumer used to
/// `load()` the local row, which made a rebuildable projection load-bearing for an admission
/// decision: delete the row and a DomainApp could not be created over a descriptor its owner had
/// admitted; corrupt the row and the pattern check ran against whatever the corruption said. The
/// owner reader answers from the Agentgres chain and applies that family's own scope, so this route
/// consumes an owner-resolved fact instead of re-deriving one from a copy.
fn resolve_domain_app_descriptor(
    data_dir: &str,
    identity: &super::substrate_store::RequestIdentity,
    sd_ref: &str,
) -> Result<super::odk_routes::ResolvedSurfaceDescriptor, (String, String)> {
    let resolved =
        super::odk_routes::resolve_admitted_surface_descriptor(data_dir, identity, sd_ref)
            .map_err(|(_, axum::Json(payload))| {
                (
                    "domain_app_descriptor_unresolved".to_string(),
                    format!(
                        "surface_descriptor_ref '{sd_ref}' does not resolve to an admitted surface descriptor this caller may bind: {}",
                        payload
                            .pointer("/error/message")
                            .and_then(|value| value.as_str())
                            .unwrap_or("refused by its owner")
                    ),
                )
            })?;
    if resolved.composition_pattern != "domain_app" {
        return Err((
            "domain_app_descriptor_pattern_mismatch".into(),
            "surface_descriptor_ref must reference a descriptor whose composition_pattern == domain_app".into(),
        ));
    }
    Ok(resolved)
}

/// The exact descriptor bytes a snapshot was derived from, committed under that version's own rule.
///
/// A DomainApp's four snapshot lists are a projection of ONE descriptor revision. Recording which
/// one is what makes "this snapshot is current" decidable offline: the descriptor advances, its
/// commitment moves, and the app's bound hash no longer matches. Without it, a snapshot derived from
/// a superseded revision is indistinguishable from a fresh one.
fn descriptor_binding(
    resolved: &super::odk_routes::ResolvedSurfaceDescriptor,
) -> Result<String, (String, String)> {
    super::odk_routes::descriptor_content_commitment(&resolved.record).ok_or_else(|| {
        (
            "domain_app_descriptor_version_unsupported".to_string(),
            format!(
                "the bound descriptor is admitted as '{}', which has no commitment rule in this build; binding a snapshot to a hash produced by guessing which contract a record satisfies is worse than no binding",
                resolved.schema_version
            ),
        )
    })
}

/// Resolve an optional `odk_manifest_ref`: must be an `odk://` ref that resolves AND whose
/// surface_descriptor_refs include `sd_ref`.
fn resolve_manifest_including(
    data_dir: &str,
    man_ref: &str,
    sd_ref: &str,
) -> Result<Value, (String, String)> {
    match split_ref(man_ref) {
        Some(("odk", id)) => match load(data_dir, KIND_MANIFEST, id) {
            Some(m) => {
                if manifest_includes_descriptor(&m, sd_ref) {
                    Ok(m)
                } else {
                    Err((
                        "domain_app_manifest_missing_descriptor".into(),
                        "odk_manifest_ref does not include surface_descriptor_ref in its surface_descriptor_refs".into(),
                    ))
                }
            }
            None => Err((
                "domain_app_manifest_unresolved".into(),
                format!("odk_manifest_ref '{man_ref}' does not resolve to an ODK manifest"),
            )),
        },
        _ => Err((
            "domain_app_ref_prefix_invalid".into(),
            "odk_manifest_ref must be an 'odk://' ref".into(),
        )),
    }
}
fn manifest_includes_descriptor(manifest: &Value, sd_ref: &str) -> bool {
    arr_strs(manifest, "surface_descriptor_refs")
        .iter()
        .any(|r| r == sd_ref)
}

/// A snapshot of provenance refs derived from the bound descriptor (+ manifest, if any).
///
/// M05.6 — THE SNAPSHOT IS NOW THE ONE CANON DEFINES. Two of canon's members had no field at all:
/// `canonical_object_model_refs` and `policy_bound_data_view_refs`. A DomainApp created over a
/// descriptor that bound eight object models and three policy-bound views recorded NEITHER, and
/// nothing failed — the record simply had nowhere to put them. Policy-bound views gate read,
/// transform, distill, train, evaluate, export, publish and route use of governed data, so an app
/// whose record could not name the views its descriptor binds could not be checked against them.
struct Derived {
    ontology_refs: Vec<String>,
    canonical_object_model_refs: Vec<String>,
    data_recipe_refs: Vec<String>,
    policy_bound_data_view_refs: Vec<String>,
    operator_contract_refs: Vec<String>,
    mcp_contract_refs: Vec<String>,
}
/// M05.5 — THE LINEAGE READ CANONICAL NAMES THAT ONLY v1 HAD, SO A v2 DESCRIPTOR CONTRIBUTED NONE.
///
/// This read `descriptor.ontology_ref` and `descriptor.recipe_refs`: the singular binding and the
/// unqualified recipe name, both of which the successor replaced with `ontology_refs` and
/// `data_recipe_refs`. Neither key exists on a v2 record, and `arr_strs` on an absent key is an empty
/// list rather than an error — so a DomainApp created over a v2 descriptor derived an EMPTY data
/// lineage and recorded it as its provenance snapshot. Nothing failed. The app was admitted, its
/// snapshot said this surface binds no ontology and no data recipe, and the descriptor that named
/// eight exact admitted revisions sat right beside it.
///
/// BOTH SPELLINGS ARE READ HERE, AND ONLY HERE. This is a consumer reading two contract versions of
/// the same fact, which is the one place compatibility belongs — v1's names are read FROM A STORED
/// v1 RECORD, never accepted on a v2 and never written back. The descriptor authoring path still
/// refuses the legacy spellings outright.
fn derive_snapshot(descriptor: &Value, manifest: Option<&Value>, body: &Value) -> Derived {
    let mut ontology_refs = Vec::new();
    let mut canonical_object_model_refs = Vec::new();
    let mut data_recipe_refs = Vec::new();
    let mut policy_bound_data_view_refs = Vec::new();
    let mut operator_contract_refs = Vec::new();
    let mut mcp_contract_refs = Vec::new();
    let collect = |target: &mut Vec<String>, source: &Value, key: &str| {
        for r in arr_strs(source, key) {
            push_unique(target, &r);
        }
    };
    // From a v2 descriptor: the canonical plural bindings under canon's own names.
    collect(&mut ontology_refs, descriptor, "ontology_refs");
    collect(
        &mut canonical_object_model_refs,
        descriptor,
        "canonical_object_model_refs",
    );
    collect(&mut data_recipe_refs, descriptor, "data_recipe_refs");
    collect(
        &mut policy_bound_data_view_refs,
        descriptor,
        "policy_bound_data_view_refs",
    );
    collect(
        &mut operator_contract_refs,
        descriptor,
        "operator_contract_refs",
    );
    collect(&mut mcp_contract_refs, descriptor, "mcp_contract_refs");
    // From a stored v1 descriptor: the singular ontology_ref and the legacy recipe_refs. v1 carries
    // no object-model or policy-view binding at all, so a snapshot derived from one is EMPTY in
    // those two members because its source has nothing to give — not because this read missed them.
    if let Some(o) = descriptor.get("ontology_ref").and_then(|v| v.as_str()) {
        push_unique(&mut ontology_refs, o);
    }
    collect(&mut data_recipe_refs, descriptor, "recipe_refs");
    // From the manifest, if bound — reading BOTH registered manifest versions. A stored v1 manifest
    // spells recipes `recipe_refs` and folds operator and MCP contracts into one
    // `mcp_operator_contracts` list it cannot tell apart, so the folded list contributes to the MCP
    // member and the operator member stays whatever the descriptor said. A v2 manifest carries the
    // two separately and both land where they belong.
    if let Some(m) = manifest {
        collect(&mut ontology_refs, m, "ontology_refs");
        collect(
            &mut canonical_object_model_refs,
            m,
            "canonical_object_model_refs",
        );
        collect(&mut data_recipe_refs, m, "data_recipe_refs");
        collect(&mut data_recipe_refs, m, "recipe_refs");
        collect(
            &mut policy_bound_data_view_refs,
            m,
            "policy_bound_data_view_refs",
        );
        collect(&mut operator_contract_refs, m, "operator_contract_refs");
        collect(&mut mcp_contract_refs, m, "mcp_contract_refs");
        collect(&mut mcp_contract_refs, m, "mcp_operator_contracts");
    }
    // Plus any author-supplied named mcp_contract_refs.
    for r in str_refs(body, "mcp_contract_refs") {
        push_unique(&mut mcp_contract_refs, &r);
    }
    Derived {
        ontology_refs,
        canonical_object_model_refs,
        data_recipe_refs,
        policy_bound_data_view_refs,
        operator_contract_refs,
        mcp_contract_refs,
    }
}

// ------------------------------------------------ the published DomainApp resolution seam

/// One admitted DomainApp, resolved from the Agentgres chain rather than from the read model.
pub(crate) struct ResolvedDomainApp {
    pub(crate) domain_app_ref: String,
    pub(crate) schema_version: String,
    /// The canonical admitted record, byte-exact as the chain holds it.
    pub(crate) record: Value,
    pub(crate) admitted_head: String,
    pub(crate) revision_count: usize,
    /// True when the last admitted operation was the terminal delete rather than a live record.
    pub(crate) withdrawn: bool,
    /// Whether the local row agreed with the chain, was rebuilt, or was absent entirely.
    pub(crate) index_state: &'static str,
    pub(crate) projected_created_at: String,
    pub(crate) projected_updated_at: String,
}

/// The DomainApp record inside one admitted operation payload.
///
/// THREE PAYLOAD SHAPES REACH THIS STREAM AND ALL THREE ARE ADMITTED FACTS. `create` and `patch`
/// admit the bare record. Every ladder transition admits a composite — the app, the runtime it
/// produced and the receipts that attest it — because those three commit or none of them do. And
/// `delete` admits a tombstone that is not a record at all. A reader that understood only the first
/// would see a mounted app as unparseable and a deleted one as still present, so the dispatch is
/// explicit and its unknown arm is a refusal rather than a default.
fn domain_app_payload(payload: &Value) -> Option<Option<Value>> {
    if payload.get("deleted").and_then(Value::as_bool) == Some(true) {
        return Some(None);
    }
    if let Some(app) = payload.get("domain_app") {
        return app.is_object().then(|| Some(app.clone()));
    }
    payload
        .get("schema_version")
        .and_then(Value::as_str)
        .map(|_| Some(payload.clone()))
}

/// The read-model row for one admitted DomainApp, in the shape ITS OWN registered version stores.
///
/// A v2 row is an envelope carrying the closed registered record byte-exact with the stream's own
/// metadata beside it; a stored v1 row IS the record with those three keys inlined, exactly as the
/// legacy lane wrote it. There is no third shape and no default arm: writing an unrecognised record
/// into whichever shape happened to be last in the match is how a projection starts claiming a
/// contract its contents were never admitted under.
fn domain_app_row(
    record: &Value,
    created_at: &str,
    updated_at: &str,
    admitted_head: &str,
) -> Result<Value, (StatusCode, Json<Value>)> {
    match record.get("schema_version").and_then(Value::as_str) {
        Some(DOMAIN_APP_V2_SCHEMA_VERSION) => Ok(json!({
            "schema_version": DOMAIN_APP_PROJECTION_SCHEMA,
            "domain_app_contract_id": DOMAIN_APP_V2_CONTRACT_ID,
            "domain_app": record,
            "created_at": created_at,
            "updated_at": updated_at,
            "admitted_head": admitted_head,
        })),
        Some(DOMAIN_APP_V1_SCHEMA_VERSION) => {
            let mut inlined = record.clone();
            inlined["created_at"] = json!(created_at);
            inlined["updated_at"] = json!(updated_at);
            inlined["admitted_head"] = json!(admitted_head);
            Ok(inlined)
        }
        unknown => Err((
            StatusCode::BAD_GATEWAY,
            Json(json!({
                "ok": false,
                "error": {
                    "code": "domain_app_projection_failed",
                    "message": format!(
                        "a DomainApp admitted as '{}' has no projection shape in this build; it is refused rather than stored under a contract it was never admitted under",
                        unknown.unwrap_or("(no schema_version)")
                    )
                }
            })),
        )),
    }
}

/// Resolve one DomainApp for a caller entitled to see it, FROM THE CHAIN.
///
/// THE ROW WAS THE ANSWER AND SHOULD NEVER HAVE BEEN. Every DomainApp read — overview, list, get,
/// and the runtime lookups beside them — loaded the local record directory, which makes a rebuildable
/// projection load-bearing: delete the row and the app is gone, corrupt it and the app is whatever
/// the corruption says, while the Agentgres owner chain still holds the admitted truth. A projection
/// whose loss changes the answer is not a projection.
///
/// So this reads the owner-scoped operation history, takes the last admitted payload as the record,
/// and reports what the row DID say — it is never consulted for the answer. Both registered versions
/// are validated, each against its OWN contract, and an unrecognised one fails closed: a stored
/// record this build cannot interpret must not be served as though it were understood, because every
/// consumer then reads its fields and a field this build cannot interpret reads as ABSENT.
///
/// GRANTS NOTHING. Reading a DomainApp is not permission to mount, serve, register or act on it.
pub(crate) fn resolve_admitted_domain_app(
    data_dir: &str,
    identity: &super::substrate_store::RequestIdentity,
    domain_app_ref: &str,
) -> Result<ResolvedDomainApp, (StatusCode, Json<Value>)> {
    let Some(("domain-app", id)) = split_ref(domain_app_ref) else {
        return Err(bad(
            "domain_app_ref_not_canonical",
            "a DomainApp is addressed as 'domain-app://<id>'",
        ));
    };
    let scope = super::substrate_store::authorize_request_resource_scope(
        data_dir,
        identity,
        KIND_DAPP,
        domain_app_ref,
        None,
    )
    .map_err(super::odk_routes::odk_scope_refusal)?;
    let history = super::mutation_event_foundation::read_owner_scoped_history(
        data_dir,
        identity,
        &scope,
        KIND_DAPP,
        domain_app_ref,
        DAPP_NAMESPACE,
        &super::mutation_event_foundation::stream_tail(KIND_DAPP, domain_app_ref),
    )
    .map_err(|error| {
        (
            StatusCode::CONFLICT,
            Json(json!({
                "ok": false,
                "error": { "code": error.code(), "message": error.message() }
            })),
        )
    })?;
    let Some(latest) = history.last() else {
        return Err((
            StatusCode::NOT_FOUND,
            Json(json!({
                "ok": false,
                "error": {
                    "code": "domain_app_not_found",
                    "message": "this DomainApp has no admitted history — an absent app is a typed absence, never an empty success"
                }
            })),
        ));
    };
    let Some(payload) = domain_app_payload(&latest.operation.payload) else {
        return Err((
            StatusCode::BAD_GATEWAY,
            Json(json!({
                "ok": false,
                "error": {
                    "code": "domain_app_payload_unrecognised",
                    "message": "the chain holds an operation whose payload this build cannot read as a DomainApp, a ladder transition or a withdrawal"
                }
            })),
        ));
    };
    // The genesis operation is the creation, the latest is the last update. Both stamps are a
    // function of the admitted history, so they survive the row being deleted and are unaffected by
    // the row being corrupted — which is the whole point of a projection that can be rebuilt.
    let projected_created_at = history
        .first()
        .map(|entry| {
            super::mutation_event_foundation::admitted_stamp(entry.operation.recorded_at_ms)
        })
        .unwrap_or_default();
    let projected_updated_at =
        super::mutation_event_foundation::admitted_stamp(latest.operation.recorded_at_ms);

    let Some(record) = payload else {
        // A withdrawal is the durable record of a delete, not an absence. It is reported as its own
        // typed state so a caller can tell a corpus that never grew from one that was withdrawn.
        return Ok(ResolvedDomainApp {
            domain_app_ref: domain_app_ref.to_string(),
            schema_version: String::new(),
            record: Value::Null,
            admitted_head: latest.head.clone(),
            revision_count: history.len(),
            withdrawn: true,
            index_state: if load(data_dir, KIND_DAPP, id).is_none() {
                "agreed_with_agentgres"
            } else {
                "stale_rebuilt_from_agentgres"
            },
            projected_created_at,
            projected_updated_at,
        });
    };
    let schema_version = record
        .get("schema_version")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let contract_id = match schema_version.as_str() {
        DOMAIN_APP_V2_SCHEMA_VERSION => DOMAIN_APP_V2_CONTRACT_ID,
        DOMAIN_APP_V1_SCHEMA_VERSION => DOMAIN_APP_V1_CONTRACT_ID,
        unknown => {
            return Err((
                StatusCode::BAD_GATEWAY,
                Json(json!({
                    "ok": false,
                    "error": {
                        "code": "domain_app_version_unsupported",
                        "message": format!(
                            "the chain holds a DomainApp admitted as '{unknown}', which this build neither authors nor projects; an unrecognised stored version is refused rather than served as though it were understood"
                        )
                    }
                })),
            ))
        }
    };
    if let Err(reason) =
        ioi_types::app::generated::architecture_contracts::validate_architecture_contract(
            contract_id,
            &record,
        )
    {
        return Err((
            StatusCode::BAD_GATEWAY,
            Json(json!({
                "ok": false,
                "error": {
                    "code": "domain_app_projection_failed",
                    "message": format!("the chain holds a DomainApp this build cannot project against {contract_id}: {reason}")
                }
            })),
        ));
    }
    // THE ROW IS COMPARED, NEVER CONSULTED. Reporting agreement positively is what lets a verifier
    // prove the rebuild happened rather than infer it from an unchanged answer.
    let expected = domain_app_row(
        &record,
        &projected_created_at,
        &projected_updated_at,
        &latest.head,
    )?;
    let row = load(data_dir, KIND_DAPP, id);
    let index_state = match row.as_ref() {
        None => "absent_rebuilt_from_agentgres",
        Some(row) if *row == expected => "agreed_with_agentgres",
        Some(_) => "stale_rebuilt_from_agentgres",
    };
    Ok(ResolvedDomainApp {
        domain_app_ref: domain_app_ref.to_string(),
        schema_version,
        record,
        admitted_head: latest.head.clone(),
        revision_count: history.len(),
        withdrawn: false,
        index_state,
        projected_created_at,
        projected_updated_at,
    })
}

/// GET /v1/hypervisor/domain-apps/overview — this caller's substrate, resolved through owner seams.
///
/// M05.6 — THE COUNT THAT READ THE ENVELOPE AND FOUND NOTHING. This handler swept the descriptor
/// RECORD DIRECTORY and filtered on `composition_pattern` at the row's top level. That name lives at
/// the top level of a stored **v1** descriptor row, and only there. A v2 row is a projection envelope
/// — `{schema_version: "…surface-descriptor-projection.v2", descriptor: {…}}` — so the pattern is at
/// `row.descriptor.composition_pattern` and `row.get("composition_pattern")` is `None` for every one
/// of them. `odk_domain_app_descriptors` therefore counted ZERO app-shaped descriptors on a substrate
/// full of them, and reported that zero as a substrate fact. Nothing errored: an absent key is not a
/// failure, it is a `None` that filters everything out, so the miscount was a confident number.
///
/// It is fixed the way the same class was fixed everywhere else in this module: the answer comes
/// from the OWNER, through the seam that knows which contract each record satisfies, and the
/// versioned payload is read rather than the row that wraps it. The row is not consulted at all.
///
/// It is also SCOPED now. The sweep took no identity and counted every tenant's descriptors,
/// ontologies, recipes, manifests and apps into one substrate total, then handed a `recent` list
/// containing other owners' app names and descriptor refs to any caller. A global count is a
/// cross-tenant oracle at lower resolution: poll it and the delta says when a competitor created
/// something. Every number below is a fact about THIS caller's own objects.
pub(crate) async fn handle_domain_apps_overview(
    State(st): State<Arc<DaemonState>>,
    headers: axum::http::HeaderMap,
) -> (StatusCode, Json<Value>) {
    let identity = match super::substrate_store::resolve_request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(error) => return super::odk_routes::odk_scope_refusal(error),
    };
    // ---- descriptors, through their owner seam, read at the version each was admitted under.
    let descriptor_refs = match super::substrate_store::authorized_request_resource_refs(
        &st.data_dir,
        &identity,
        "hypervisor-odk-surface-descriptor",
    ) {
        Ok(refs) => refs,
        Err(error) => return super::odk_routes::odk_scope_refusal(error),
    };
    let mut descriptors_resolved = 0usize;
    let mut domain_app_descriptors = 0usize;
    let mut descriptors_unreadable = 0usize;
    for descriptor_ref in &descriptor_refs {
        match super::odk_routes::resolve_admitted_surface_descriptor(
            &st.data_dir,
            &identity,
            descriptor_ref,
        ) {
            Ok(resolved) => {
                if matches!(resolved.status.as_str(), "revoked" | "deleted") {
                    continue;
                }
                descriptors_resolved += 1;
                // THE VERSIONED PAYLOAD, not the envelope. `composition_pattern` is a field of the
                // descriptor record at both registered versions, and the seam hands back that record.
                if resolved.composition_pattern == "domain_app" {
                    domain_app_descriptors += 1;
                }
            }
            // A stream this caller holds a scope for but cannot project is COUNTED, never dropped:
            // an unreadable descriptor and an absent one are different findings.
            Err(_) => descriptors_unreadable += 1,
        }
    }

    // ---- domain apps, through their own owner seam.
    let app_refs = match super::substrate_store::authorized_request_resource_refs(
        &st.data_dir,
        &identity,
        KIND_DAPP,
    ) {
        Ok(refs) => refs,
        Err(error) => return super::odk_routes::odk_scope_refusal(error),
    };
    let mut by_visibility: HashMap<String, i64> = HashMap::new();
    let mut by_status: HashMap<String, i64> = HashMap::new();
    let mut recent: Vec<Value> = Vec::new();
    let mut apps_resolved = 0usize;
    let mut apps_withdrawn = 0usize;
    let mut apps_unreadable = 0usize;
    let mut index_agreed = 0usize;
    let mut index_rebuilt = 0usize;
    for app_ref in &app_refs {
        match resolve_admitted_domain_app(&st.data_dir, &identity, app_ref) {
            Ok(resolved) => {
                if resolved.index_state == "agreed_with_agentgres" {
                    index_agreed += 1;
                } else {
                    index_rebuilt += 1;
                }
                if resolved.withdrawn {
                    apps_withdrawn += 1;
                    continue;
                }
                apps_resolved += 1;
                let record = &resolved.record;
                let visibility = record
                    .get("visibility")
                    .and_then(Value::as_str)
                    .unwrap_or("private");
                *by_visibility.entry(visibility.to_string()).or_insert(0) += 1;
                let status = record
                    .get("status")
                    .and_then(Value::as_str)
                    .unwrap_or("draft");
                *by_status.entry(status.to_string()).or_insert(0) += 1;
                recent.push(json!({
                    "domain_app_ref": resolved.domain_app_ref,
                    "schema_version": resolved.schema_version,
                    "name": record.get("name").cloned().unwrap_or(Value::Null),
                    // INVENTORY STATUS AND RUNTIME STATE, SIDE BY SIDE AND NAMED APART (G-6).
                    "inventory_status": status,
                    "runtime_posture": record.get("runtime_posture").cloned().unwrap_or(Value::Null),
                    "visibility": visibility,
                    "surface_descriptor_ref": record.get("surface_descriptor_ref").cloned().unwrap_or(Value::Null),
                    "updated_at": resolved.projected_updated_at,
                }));
            }
            Err(_) => apps_unreadable += 1,
        }
    }
    recent.sort_by(|a, b| {
        b["updated_at"]
            .as_str()
            .unwrap_or("")
            .cmp(a["updated_at"].as_str().unwrap_or(""))
    });
    recent.truncate(8);

    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "schema_version": "ioi.hypervisor.domain-apps-overview.v2",
            "status_note": "A DomainApp is a governed candidate over one domain_app-pattern descriptor. Inventory status advances through the composable-application journey; mounted and serving state belong to the DomainAppRuntime and are reported as a backlink, never as status.",
            "projection_source": "agentgres_owner_chain",
            "census_scope": "this_caller_only",
            "substrate": {
                "odk_surface_descriptors_authorized": descriptor_refs.len(),
                "odk_surface_descriptors_resolved": descriptors_resolved,
                "odk_domain_app_descriptors": domain_app_descriptors,
                "odk_surface_descriptors_unreadable": descriptors_unreadable
            },
            "domain_apps": {
                "authorized_for_this_caller": app_refs.len(),
                "resolved_from_chain": apps_resolved,
                "withdrawn_and_hidden": apps_withdrawn,
                "unreadable": apps_unreadable,
                "by_visibility": serde_json::to_value(&by_visibility).unwrap_or_else(|_| json!({})),
                "by_inventory_status": serde_json::to_value(&by_status).unwrap_or_else(|_| json!({})),
                "index_agreed_with_chain": index_agreed,
                "index_answered_from_chain": index_rebuilt
            },
            "visibilities": VISIBILITIES,
            "inventory_statuses": DOMAIN_APP_STATUSES,
            "recent_domain_apps": recent
        })),
    )
}

/// GET /v1/hypervisor/domain-apps[?visibility=…&surface_descriptor_ref=…] — this caller's apps.
///
/// Answered from the owner chain, so destroying the index cannot shorten this list, and scoped to
/// the caller, so it is not a cross-tenant inventory. The census names what it could NOT resolve:
/// a short list and an unreadable stream are different findings.
pub(crate) async fn handle_domain_apps_list(
    State(st): State<Arc<DaemonState>>,
    headers: axum::http::HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> (StatusCode, Json<Value>) {
    let identity = match super::substrate_store::resolve_request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(error) => return super::odk_routes::odk_scope_refusal(error),
    };
    let authorized = match super::substrate_store::authorized_request_resource_refs(
        &st.data_dir,
        &identity,
        KIND_DAPP,
    ) {
        Ok(refs) => refs,
        Err(error) => return super::odk_routes::odk_scope_refusal(error),
    };
    let mut items: Vec<Value> = Vec::new();
    let mut withdrawn = 0usize;
    let mut unreadable: Vec<Value> = Vec::new();
    let mut index_agreed = 0usize;
    let mut index_rebuilt = 0usize;
    for app_ref in &authorized {
        match resolve_admitted_domain_app(&st.data_dir, &identity, app_ref) {
            Ok(resolved) => {
                if resolved.index_state == "agreed_with_agentgres" {
                    index_agreed += 1;
                } else {
                    index_rebuilt += 1;
                }
                if resolved.withdrawn {
                    withdrawn += 1;
                    continue;
                }
                items.push(resolved.record);
            }
            Err((status, Json(payload))) => unreadable.push(json!({
                "domain_app_ref": app_ref,
                "status": status.as_u16(),
                "code": payload.pointer("/error/code").cloned().unwrap_or(Value::Null),
            })),
        }
    }
    let resolved_count = items.len();
    if let Some(vis) = q
        .get("visibility")
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    {
        items.retain(|a| a.get("visibility").and_then(|v| v.as_str()) == Some(vis));
    }
    if let Some(sd) = q
        .get("surface_descriptor_ref")
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    {
        items.retain(|a| a.get("surface_descriptor_ref").and_then(|v| v.as_str()) == Some(sd));
    }
    // INVENTORY STATUS FILTERS BY ITS OWN NAME. A caller asking for `status=serving` is asking a
    // runtime question of an inventory field, so it is refused as a category error rather than
    // answered with an empty list that reads like "none are serving".
    if let Some(status) = q.get("status").map(|s| s.trim()).filter(|s| !s.is_empty()) {
        if !DOMAIN_APP_STATUSES.contains(&status) {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "ok": false,
                    "error": {
                        "code": "domain_app_status_not_an_inventory_state",
                        "message": format!(
                            "'{status}' is not one of the inventory states {DOMAIN_APP_STATUSES:?}. Mounted and serving are RUNTIME states and belong to GET /v1/hypervisor/domain-app-runtimes"
                        )
                    }
                })),
            );
        }
        items.retain(|a| a.get("status").and_then(|v| v.as_str()) == Some(status));
    }
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "domain_apps": items,
            "projection_source": "agentgres_owner_chain",
            "census": {
                "census_scope": "this_caller_only",
                "authorized_for_this_caller": authorized.len(),
                "resolved_from_chain": resolved_count,
                "withdrawn_and_hidden": withdrawn,
                "unreadable": unreadable,
                "index_agreed_with_chain": index_agreed,
                "index_answered_from_chain": index_rebuilt
            }
        })),
    )
}

/// POST /v1/hypervisor/domain-apps — create a DomainApp DRAFT candidate over an ODK domain_app
/// descriptor. surface_descriptor_ref is required (must resolve + be composition_pattern domain_app);
/// odk_manifest_ref is optional (if present, must resolve AND include the descriptor).
pub(crate) async fn handle_domain_apps_create(
    State(st): State<Arc<DaemonState>>,
    headers: axum::http::HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    // Identity is the first gate. Validating the body first tells an unauthenticated caller which
    // fields this route wants, and answers 400 where it owes 401.
    let caller: WriteCaller = match require_write_caller(&st.data_dir, &headers, &body) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    // A caller naming the predecessor is refused BY NAME before anything else is read, so a
    // downgrade cannot be smuggled in as a successful create of a shape this build stopped writing.
    if let Err(response) = require_authored_version(
        &body,
        DOMAIN_APP_V2_SCHEMA_VERSION,
        DOMAIN_APP_V1_SCHEMA_VERSION,
        "DomainApp",
    ) {
        return response;
    }
    let sd_ref = str_field(&body, "surface_descriptor_ref");
    if sd_ref.is_empty() {
        return bad(
            "domain_app_descriptor_required",
            "A DomainApp must declare a surface_descriptor_ref (the app-shape contract).",
        );
    }
    let resolved_descriptor =
        match resolve_domain_app_descriptor(&st.data_dir, &caller.identity, sd_ref) {
            Ok(d) => d,
            Err((c, m)) => return bad(&c, &m),
        };
    let descriptor_hash = match descriptor_binding(&resolved_descriptor) {
        Ok(hash) => hash,
        Err((c, m)) => return bad(&c, &m),
    };
    let descriptor = resolved_descriptor.record.clone();
    let man_ref = str_field(&body, "odk_manifest_ref");
    let manifest = if man_ref.is_empty() {
        None
    } else {
        match resolve_manifest_including(&st.data_dir, man_ref, sd_ref) {
            Ok(m) => Some(m),
            Err((c, m)) => return bad(&c, &m),
        }
    };
    let visibility = {
        let v = body
            .get("visibility")
            .and_then(|v| v.as_str())
            .unwrap_or("private");
        if !VISIBILITIES.contains(&v) {
            return bad(
                "domain_app_visibility_invalid",
                &format!("visibility must be one of {VISIBILITIES:?}"),
            );
        }
        v.to_string()
    };
    let derived = derive_snapshot(&descriptor, manifest.as_ref(), &body);
    // Content-derived, not clock-derived: the same logical create submitted twice must resolve to
    // one resource, and `nanos()` mints a second one.
    let id = replay_stable_id("dapp", &caller.owner_ref, &caller.idempotency_key);
    let mut operator_contract_refs = derived.operator_contract_refs;
    for r in str_refs(&body, "operator_contract_refs") {
        push_unique(&mut operator_contract_refs, &r);
    }
    let mut record = json!({
        "schema_version": DOMAIN_APP_V2_SCHEMA_VERSION,
        "domain_app_id": format!("domain-app://{id}"),
        "name": body.get("name").and_then(|v| v.as_str()).unwrap_or("domain-app"),
        "description": body.get("description").and_then(|v| v.as_str()).unwrap_or(""),
        "surface_descriptor_ref": sd_ref,
        // WHICH BYTES THIS SNAPSHOT CAME FROM, and under which registered contract they were read.
        "surface_descriptor_schema_version": resolved_descriptor.schema_version,
        "surface_descriptor_content_hash": descriptor_hash,
        "odk_manifest_ref": if man_ref.is_empty() { Value::Null } else { json!(man_ref) },
        // Server-resolved. v1's patch path copied a caller-supplied owner_ref onto the record, which
        // is how a record's owner could stop being the owner its admission was scoped to.
        "owner_ref": caller.owner_ref,
        "project_ref": body.get("project_ref").cloned().unwrap_or(Value::Null),
        "visibility": visibility,
        // Derived provenance snapshot from the descriptor (+ manifest, if bound) — all six members.
        "ontology_refs": derived.ontology_refs,
        "canonical_object_model_refs": derived.canonical_object_model_refs,
        "data_recipe_refs": derived.data_recipe_refs,
        "policy_bound_data_view_refs": derived.policy_bound_data_view_refs,
        "operator_contract_refs": operator_contract_refs,
        "mcp_contract_refs": derived.mcp_contract_refs,
        // Author-supplied named refs (not resolved here). Declaring an authority requirement states
        // what the app will OWE when it acts; it grants nothing.
        "authority_requirement_refs": str_refs(&body, "authority_requirement_refs"),
        "receipt_obligations": str_refs(&body, "receipt_obligations"),
        "generated_artifact_refs": str_refs(&body, "generated_artifact_refs"),
        // STAGE 3 OF THE COMPOSABLE-APPLICATION JOURNEY, AND NO FURTHER. Generation is not admission:
        // scaffolding a descriptor does not package it, packaging does not admit it, admission does
        // not install it. A create completes exactly one stage, so every later stage's binding is
        // explicitly null rather than absent — an absent key would read as "not said" instead of
        // "not yet done", which is the ambiguity v1 could not escape because it had no keys at all.
        "surface_registration_ref": Value::Null,
        "package_release_ref": Value::Null,
        "installation_ref": Value::Null,
        "system_binding_refs": [],
        // Canon: system_binding_refs must be non-empty before any effectful System launch; their
        // absence bounds the app to inspect-only use rather than silently permitting effects.
        "launch_posture": "inspect_only",
        // INVENTORY STATUS. It is `draft` here because nothing has been admitted, packaged,
        // installed or registered — not because the field is pinned. `handle_domain_app_inventory_status`
        // advances it, and only with the stage binding that produced the advance.
        "status": "draft",
        // RUNTIME STATE, as a backlink projection of a runtime that does not exist yet. Draft is
        // inert: it starts no process, assigns no route, grants no authority, runs no domain action.
        "runtime_posture": {
            "mounted": false,
            "serving": false,
            "route": Value::Null,
            "mount_ref": Value::Null
        },
        "migration": {
            "from_schema_version": Value::Null,
            "from_domain_app_ref": Value::Null,
            "from_content_hash": Value::Null,
            "compatibility": "initial",
            "reinterprets_predecessor": false
        },
        "authority_nonclaim": "domain_app_grants_no_authority",
        "truth_nonclaim": "domain_app_is_not_registration_admission_or_runtime_truth",
        "does_not_assert": DOMAIN_APP_NONCLAIMS,
    });
    commit_record(
        &mut record,
        DOMAIN_APP_CONTENT_DOMAIN,
        DOMAIN_APP_MATERIAL_FIELDS,
        "content_hash",
    );
    if let Err(response) = registered_valid(
        DOMAIN_APP_V2_CONTRACT_ID,
        &record,
        "domain_app_not_registered_valid",
    ) {
        return response;
    }
    // The admitted transition is canon; the record directory is a projection of it. Admitting first
    // means a crash between the two is recoverable by replay rather than by rollback-and-hope.
    let commit = match admit_owner_scoped_write(
        &st.data_dir,
        &caller,
        DAPP_NAMESPACE,
        KIND_DAPP,
        &format!("domain-app://{id}"),
        "domain_app.create",
        None,
        &record,
    ) {
        Ok(commit) => commit,
        Err(response) => return response,
    };
    // The stamps come from the ADMISSION, so a replayed create projects the original creation time
    // rather than the retry's. The registered record is closed, so they live in the row envelope
    // beside it rather than inside a contract that has no field for them.
    let stamp = super::mutation_event_foundation::admitted_stamp(
        commit.projection.operation.recorded_at_ms,
    );
    let row = match domain_app_row(&record, &stamp, &stamp, &commit.projection.head) {
        Ok(row) => row,
        Err(response) => return response,
    };
    if let Err(response) = persist_required(
        &st.data_dir,
        KIND_DAPP,
        &id,
        &row,
        "domain_app_persistence_failed",
    ) {
        return response;
    }
    (
        if commit.replayed {
            StatusCode::OK
        } else {
            StatusCode::CREATED
        },
        Json(json!({
            "ok": true,
            "replayed": commit.replayed,
            "domain_app": record,
            "admitted_head": commit.projection.head,
            "created_at": stamp,
            "updated_at": stamp
        })),
    )
}

pub(crate) async fn handle_domain_apps_get(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    headers: axum::http::HeaderMap,
) -> (StatusCode, Json<Value>) {
    let identity = match super::substrate_store::resolve_request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(error) => return super::odk_routes::odk_scope_refusal(error),
    };
    let resolved =
        match resolve_admitted_domain_app(&st.data_dir, &identity, &format!("domain-app://{id}")) {
            Ok(resolved) => resolved,
            Err(response) => return response,
        };
    if resolved.withdrawn {
        // A tombstone is the durable record of a withdrawal, not an absence. Answering 404 with the
        // withdrawal named is different from answering 404 because nothing was ever here, and a
        // caller reconciling against the chain needs to be able to tell them apart.
        return (
            StatusCode::NOT_FOUND,
            Json(json!({
                "ok": false,
                "error": {
                    "code": "domain_app_withdrawn",
                    "message": "this DomainApp was withdrawn; its admitted history remains, and it is not a live record"
                },
                "admitted_head": resolved.admitted_head,
                "revision_count": resolved.revision_count
            })),
        );
    }
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "domain_app": resolved.record,
            "projection_source": "agentgres_owner_chain",
            "index_state": resolved.index_state,
            "admitted_head": resolved.admitted_head,
            "revision_count": resolved.revision_count,
            "created_at": resolved.projected_created_at,
            "updated_at": resolved.projected_updated_at
        })),
    )
}

/// PATCH /v1/hypervisor/domain-apps/:id — update mutable fields. If the descriptor or manifest ref
/// changes, re-validate the contract and re-derive the provenance snapshot. id / schema_version /
/// status / created_at are immutable (status stays draft; runtime_posture stays unmounted).
pub(crate) async fn handle_domain_apps_patch(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    headers: axum::http::HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let caller: WriteCaller = match require_write_caller(&st.data_dir, &headers, &body) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    if let Err(response) = require_authored_version(
        &body,
        DOMAIN_APP_V2_SCHEMA_VERSION,
        DOMAIN_APP_V1_SCHEMA_VERSION,
        "DomainApp",
    ) {
        return response;
    }
    // Resolved from the CHAIN, not the row. Patching a corrupted row used to write the corruption
    // forward as though the caller had authored it.
    let app_ref = format!("domain-app://{id}");
    let resolved = match resolve_admitted_domain_app(&st.data_dir, &caller.identity, &app_ref) {
        Ok(resolved) => resolved,
        Err(response) => return response,
    };
    if resolved.withdrawn {
        return bad(
            "domain_app_withdrawn",
            "this DomainApp was withdrawn; a withdrawal is terminal for the record and is not patched back into existence",
        );
    }
    // A stored v1 is READABLE, NEVER EDITED INTO A v2. Patching one would have to invent the
    // eighteen fields v1 never carried, and inventing them is exactly the silent reinterpretation
    // the succession exists to refuse. Converging one is an explicit act that names it.
    if resolved.schema_version != DOMAIN_APP_V2_SCHEMA_VERSION {
        return bad(
            "domain_app_predecessor_not_patchable",
            &format!(
                "this DomainApp is a stored '{}' record; it remains readable exactly as admitted and is never edited into a '{DOMAIN_APP_V2_SCHEMA_VERSION}'",
                resolved.schema_version
            ),
        );
    }
    let mut a = resolved.record.clone();
    // FIELDS THIS ROUTE DOES NOT MOVE, REFUSED BY NAME RATHER THAN IGNORED. Silently dropping them
    // answers 200 to a request that changed nothing the caller asked for, which reads as success.
    for (field, owner) in [
        ("status", "POST /v1/hypervisor/domain-apps/:id/inventory-status, which requires the stage binding that produced the advance"),
        ("runtime_posture", "the DomainAppRuntime; the app's posture is a backlink projection of it, never an independently authored field"),
        ("owner_ref", "the authenticated caller; a body-supplied owner is how a record stops being owned by the owner its admission was scoped to"),
        ("surface_registration_ref", "the inventory-status route"),
        ("package_release_ref", "the inventory-status route"),
        ("installation_ref", "the inventory-status route"),
        ("system_binding_refs", "the inventory-status route"),
        ("launch_posture", "the inventory-status route, derived from system_binding_refs"),
        ("content_hash", "this daemon, recomputed from the record it commits"),
        ("migration", "the create path; a migration is a provenance fact, not an editable field"),
    ] {
        if body.get(field).is_some() {
            return bad(
                "domain_app_field_not_patchable",
                &format!("'{field}' is not moved by this route; it is owned by {owner}"),
            );
        }
    }
    if let Some(v) = body.get("visibility").and_then(|v| v.as_str()) {
        if !VISIBILITIES.contains(&v) {
            return bad(
                "domain_app_visibility_invalid",
                &format!("visibility must be one of {VISIBILITIES:?}"),
            );
        }
    }
    // Resolve the effective descriptor + manifest refs (post-patch) and re-validate if either moves.
    let touches_refs =
        body.get("surface_descriptor_ref").is_some() || body.get("odk_manifest_ref").is_some();
    let sd_ref = body
        .get("surface_descriptor_ref")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .or_else(|| {
            a.get("surface_descriptor_ref")
                .and_then(|v| v.as_str())
                .map(str::to_string)
        })
        .unwrap_or_default();
    // odk_manifest_ref: an explicit empty string clears it; absent keeps the current value.
    let man_ref = if body.get("odk_manifest_ref").is_some() {
        str_field(&body, "odk_manifest_ref").to_string()
    } else {
        a.get("odk_manifest_ref")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    };
    if touches_refs {
        let resolved_descriptor =
            match resolve_domain_app_descriptor(&st.data_dir, &caller.identity, &sd_ref) {
                Ok(d) => d,
                Err((c, m)) => return bad(&c, &m),
            };
        let descriptor_hash = match descriptor_binding(&resolved_descriptor) {
            Ok(hash) => hash,
            Err((c, m)) => return bad(&c, &m),
        };
        let manifest = if man_ref.is_empty() {
            None
        } else {
            match resolve_manifest_including(&st.data_dir, &man_ref, &sd_ref) {
                Ok(m) => Some(m),
                Err((c, m)) => return bad(&c, &m),
            }
        };
        // The snapshot is REPLACED, never merged. A DomainApp cannot widen the set its descriptor
        // declares, and merging an old snapshot into a new descriptor's is exactly how it would.
        let derived = derive_snapshot(&resolved_descriptor.record, manifest.as_ref(), &body);
        a["surface_descriptor_ref"] = json!(sd_ref);
        a["surface_descriptor_schema_version"] = json!(resolved_descriptor.schema_version);
        a["surface_descriptor_content_hash"] = json!(descriptor_hash);
        a["odk_manifest_ref"] = if man_ref.is_empty() {
            Value::Null
        } else {
            json!(man_ref)
        };
        a["ontology_refs"] = json!(derived.ontology_refs);
        a["canonical_object_model_refs"] = json!(derived.canonical_object_model_refs);
        a["data_recipe_refs"] = json!(derived.data_recipe_refs);
        a["policy_bound_data_view_refs"] = json!(derived.policy_bound_data_view_refs);
        a["operator_contract_refs"] = json!(derived.operator_contract_refs);
        a["mcp_contract_refs"] = json!(derived.mcp_contract_refs);
    }
    for key in [
        "name",
        "description",
        "visibility",
        "project_ref",
        "authority_requirement_refs",
        "receipt_obligations",
        "generated_artifact_refs",
    ] {
        if let Some(v) = body.get(key) {
            a[key] = v.clone();
        }
    }
    commit_record(
        &mut a,
        DOMAIN_APP_CONTENT_DOMAIN,
        DOMAIN_APP_MATERIAL_FIELDS,
        "content_hash",
    );
    if let Err(response) = registered_valid(
        DOMAIN_APP_V2_CONTRACT_ID,
        &a,
        "domain_app_not_registered_valid",
    ) {
        return response;
    }
    // A successor must name the head it read. Without this, two concurrent patches both succeed and
    // the loser's edit is lost with no error anywhere. The head is the STREAM's fact, taken from the
    // chain rather than from the row, so a deleted or corrupted row cannot hand a patch a head the
    // stream never issued.
    let expected_head = resolved.admitted_head.clone();
    let commit = match admit_owner_scoped_write(
        &st.data_dir,
        &caller,
        DAPP_NAMESPACE,
        KIND_DAPP,
        &app_ref,
        "domain_app.patch",
        Some(&expected_head),
        &a,
    ) {
        Ok(commit) => commit,
        Err(response) => return response,
    };
    let stamp = super::mutation_event_foundation::admitted_stamp(
        commit.projection.operation.recorded_at_ms,
    );
    let row = match domain_app_row(
        &a,
        &resolved.projected_created_at,
        &stamp,
        &commit.projection.head,
    ) {
        Ok(row) => row,
        Err(response) => return response,
    };
    if let Err(response) = persist_required(
        &st.data_dir,
        KIND_DAPP,
        &id,
        &row,
        "domain_app_persistence_failed",
    ) {
        return response;
    }
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "replayed": commit.replayed,
            "domain_app": a,
            "admitted_head": commit.projection.head,
            "updated_at": stamp
        })),
    )
}

pub(crate) async fn handle_domain_apps_delete(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    headers: axum::http::HeaderMap,
    // Optional so a DELETE sent without a body answers the typed "owner_ref is required" refusal
    // instead of axum's bare 415, which tells the caller nothing about what it owes.
    body: Option<Json<Value>>,
) -> (StatusCode, Json<Value>) {
    let body = body.map(|Json(value)| value).unwrap_or_else(|| json!({}));
    let caller: WriteCaller = match require_write_caller(&st.data_dir, &headers, &body) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    let app_ref = format!("domain-app://{id}");
    let existing = match resolve_admitted_domain_app(&st.data_dir, &caller.identity, &app_ref) {
        Ok(resolved) => resolved,
        Err(response) => return response,
    };
    if existing.withdrawn {
        return bad(
            "domain_app_withdrawn",
            "this DomainApp is already withdrawn; a second withdrawal would admit a transition that changes nothing",
        );
    }
    // A mounted app is not deletable through the object plane. Removing the app while its runtime
    // still claims a mount leaves a runtime pointing at nothing and a mount nobody can unmount —
    // the lifecycle's inverse must run first (G-5).
    if existing
        .record
        .pointer("/runtime_posture/mounted")
        .and_then(Value::as_bool)
        == Some(true)
    {
        return bad(
            "domain_app_still_mounted",
            "this DomainApp has a mounted runtime; unmount it first. Deleting the app would strand a runtime that still claims a governed mount",
        );
    }
    // Deletion is a transition, not an absence of one. Removing the projection without admitting a
    // terminal event leaves the stream claiming the app still exists.
    let expected_head = existing.admitted_head.clone();
    let commit = match admit_owner_scoped_write(
        &st.data_dir,
        &caller,
        DAPP_NAMESPACE,
        KIND_DAPP,
        &app_ref,
        "domain_app.delete",
        Some(&expected_head),
        &json!({ "domain_app_id": id, "deleted": true }),
    ) {
        Ok(commit) => commit,
        Err(response) => return response,
    };
    let removed = remove_record(&st.data_dir, KIND_DAPP, &id);
    if !removed {
        // The transition is admitted and canonical; the projection did not follow. Say so rather
        // than reporting a clean delete, so recovery replays instead of assuming success.
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "ok": false,
                "error": {
                    "code": "domain_app_projection_removal_failed",
                    "message": "the delete is admitted but its projection could not be removed; replay to reconcile"
                },
                "admitted_head": commit.projection.head
            })),
        );
    }
    (
        StatusCode::OK,
        Json(json!({ "ok": true, "removed": true, "replayed": commit.replayed, "id": id })),
    )
}

/// POST /v1/hypervisor/domain-apps/:id/inventory-status — advance the composable-application stage.
///
/// M05.6 — THE FIELD THAT WAS PINNED, AND WHY A ROUTE WAS THE ONLY HONEST FIX. `status` was written
/// as the literal `draft` at create and no path anywhere moved it, so four of canon's five members
/// were unreachable and the field recorded a pin rather than a lifecycle. The tempting repair is to
/// let the ladder advance it — mount sets `admitted`, serve sets `installed` — and that is exactly
/// the conflation G-6 exists to prevent: "admitted" would start reading as "running", and a stopped
/// app would read as uninstalled.
///
/// So the advance is its own admission with its own precondition: EACH STATUS NAMES THE STAGE
/// BINDING THAT PRODUCED IT. `admitted` requires the immutable package release local Packages
/// admission produced. `installed` requires that release plus the installation binding plus the
/// surface registration, because installation and exposure are different stages and a record cannot
/// claim the later one while missing the earlier. A status advance with no binding behind it is a
/// claim about another plane's admission, made by a route that admitted nothing — which is the
/// stage-skip the composable-application journey calls a defect rather than a shortcut.
///
/// It grants nothing. Reaching `installed` does not make the app launchable: launchability comes
/// from the product-surface compiler over an `extension_application` registration, and this route
/// records that the registration exists rather than performing it.
pub(crate) async fn handle_domain_app_inventory_status(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    headers: axum::http::HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let caller: WriteCaller = match require_write_caller(&st.data_dir, &headers, &body) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    let target = str_field(&body, "status");
    // A RUNTIME STATE NAMED HERE IS A CATEGORY ERROR, NOT AN UNKNOWN VALUE. Answering "unknown
    // status" to `serving` would leave a caller believing inventory has a serving state it has not
    // reached yet; naming the other plane says which object actually owns the word.
    if matches!(target, "mounted" | "serving" | "unmounted" | "killed") {
        return bad(
            "domain_app_runtime_state_is_not_inventory_status",
            &format!(
                "'{target}' is a DomainAppRuntime state, not an inventory status. Runtime state is owned by the runtime and moved by the mount ladder; this route moves {DOMAIN_APP_STATUSES:?}"
            ),
        );
    }
    if !DOMAIN_APP_STATUSES.contains(&target) {
        return bad(
            "domain_app_status_invalid",
            &format!("status must be one of {DOMAIN_APP_STATUSES:?}"),
        );
    }
    let app_ref = format!("domain-app://{id}");
    let prior = match resolve_admitted_domain_app(&st.data_dir, &caller.identity, &app_ref) {
        Ok(resolved) => resolved,
        Err(response) => return response,
    };
    if prior.withdrawn {
        return bad(
            "domain_app_withdrawn",
            "this DomainApp was withdrawn; its inventory status is terminal",
        );
    }
    if prior.schema_version != DOMAIN_APP_V2_SCHEMA_VERSION {
        return bad(
            "domain_app_predecessor_status_pinned",
            "a stored predecessor DomainApp has no reachable status beyond 'draft' and no field for any stage binding; it remains readable exactly as admitted and is not advanced",
        );
    }
    let current = prior
        .record
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("draft");
    if current == "revoked" {
        return bad(
            "domain_app_status_terminal",
            "a revoked DomainApp is terminal; withdrawal runs the ladder backwards and does not run forwards again",
        );
    }
    // THE JOURNEY RUNS FORWARDS ONE STAGE AT A TIME, AND BACKWARDS ONLY BY WITHDRAWAL. Allowing an
    // arbitrary jump would let `installed` be reached without the admission that precedes it even
    // though the bindings happened to be present, which is the same stage-skip by a different route.
    let legal = match (current, target) {
        ("draft", "admitted") => true,
        ("admitted", "installed") => true,
        (_, "deprecated") | (_, "revoked") => true,
        _ => false,
    };
    if !legal {
        return bad(
            "domain_app_status_transition_illegal",
            &format!(
                "'{current}' does not advance to '{target}'. The journey is draft -> admitted -> installed, and withdrawal (deprecated, revoked) is reachable from any of them"
            ),
        );
    }
    let mut next = prior.record.clone();
    let carried = |key: &str| prior.record.get(key).cloned().unwrap_or(Value::Null);
    let supplied = |key: &str| {
        body.get(key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| json!(s))
    };
    next["package_release_ref"] =
        supplied("package_release_ref").unwrap_or_else(|| carried("package_release_ref"));
    next["installation_ref"] =
        supplied("installation_ref").unwrap_or_else(|| carried("installation_ref"));
    next["surface_registration_ref"] =
        supplied("surface_registration_ref").unwrap_or_else(|| carried("surface_registration_ref"));
    if let Some(bindings) = body.get("system_binding_refs") {
        next["system_binding_refs"] = bindings.clone();
    }
    // `launch_posture` is DERIVED, never authored. Canon bounds an app with no admitted System
    // binding to inspect-only use; letting a caller assert otherwise while binding nothing is
    // precisely the silent permission the bound exists to prevent.
    let bound_systems = next
        .get("system_binding_refs")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    next["launch_posture"] = json!(if bound_systems == 0 {
        "inspect_only"
    } else {
        "system_bound"
    });
    next["status"] = json!(target);
    // The ladder's runtime backlink is not touched here, and this route cannot reach it: a status
    // advance says nothing about whether the app is mounted, and an app that is serving is still
    // only `admitted` until its installation is admitted by the plane that owns installations.
    commit_record(
        &mut next,
        DOMAIN_APP_CONTENT_DOMAIN,
        DOMAIN_APP_MATERIAL_FIELDS,
        "content_hash",
    );
    // The stage-binding preconditions are the registered contract's own conditionals, so a status
    // advance with a missing binding is refused by the CONTRACT rather than by a hand-written check
    // that could drift from it.
    if let Err(response) = registered_valid(
        DOMAIN_APP_V2_CONTRACT_ID,
        &next,
        "domain_app_status_binding_missing",
    ) {
        return response;
    }
    let commit = match admit_owner_scoped_write(
        &st.data_dir,
        &caller,
        DAPP_NAMESPACE,
        KIND_DAPP,
        &app_ref,
        "domain_app.inventory_status",
        Some(&prior.admitted_head),
        &next,
    ) {
        Ok(commit) => commit,
        Err(response) => return response,
    };
    let stamp = super::mutation_event_foundation::admitted_stamp(
        commit.projection.operation.recorded_at_ms,
    );
    let row = match domain_app_row(
        &next,
        &prior.projected_created_at,
        &stamp,
        &commit.projection.head,
    ) {
        Ok(row) => row,
        Err(response) => return response,
    };
    if let Err(response) = persist_required(
        &st.data_dir,
        KIND_DAPP,
        &id,
        &row,
        "domain_app_persistence_failed",
    ) {
        return response;
    }
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "replayed": commit.replayed,
            "domain_app": next,
            "admitted_head": commit.projection.head,
            "updated_at": stamp,
            "state_kind_note": "inventory status only; mounted and serving state belong to the DomainAppRuntime"
        })),
    )
}

// ============================ DOMAIN-APP RUNTIME MOUNT (effectful cut A) =========================
//
// A GOVERNED mount admission — effectful but NOT serving. Mount requires a real domain-app plus an
// APPROVED ApprovalRequest and an OPEN ReleaseControl that both target this domain app; on success the
// daemon admits the mount, writes a durable DomainAppRuntime record (mounted:true), emits an admission
// receipt (hashed state_root), backlinks the DomainApp runtime_posture, and stores the governance +
// authority refs that permitted it. It does NOT start a process, expose a URL, create ingress, publish,
// run connectors, or generate app code — that is the later serving cut. Unmount is a governed, receipted
// state transition.

const KIND_RUNTIME: &str = "domain-app-runtimes";
const KIND_MOUNT_RECEIPT: &str = "domain-app-mount-receipts";
const KIND_APPROVAL: &str = "governance-approval-requests";
const KIND_RELEASE: &str = "governance-release-controls";

/// The ApprovalRequest must be `approved` AND target this domain app (subject_ref == domain_app_ref).
fn approval_admits(approval: &Value, domain_app_ref: &str) -> Result<(), (String, String)> {
    if approval.get("status").and_then(|v| v.as_str()) != Some("approved") {
        return Err((
            "mount_approval_not_approved".into(),
            "approval_request_ref must reference an ApprovalRequest with status 'approved'".into(),
        ));
    }
    if approval.get("subject_ref").and_then(|v| v.as_str()) != Some(domain_app_ref) {
        return Err((
            "mount_control_wrong_subject".into(),
            "approval_request.subject_ref must target this domain app".into(),
        ));
    }
    Ok(())
}
/// The ReleaseControl must be `open` AND target this domain app (release_target_ref == domain_app_ref).
fn release_admits(release: &Value, domain_app_ref: &str) -> Result<(), (String, String)> {
    if release.get("state").and_then(|v| v.as_str()) != Some("open") {
        return Err((
            "mount_release_not_open".into(),
            "release_control_ref must reference a ReleaseControl with state 'open'".into(),
        ));
    }
    if release.get("release_target_ref").and_then(|v| v.as_str()) != Some(domain_app_ref) {
        return Err((
            "mount_control_wrong_subject".into(),
            "release_control.release_target_ref must target this domain app".into(),
        ));
    }
    Ok(())
}
/// Load a scheme-prefixed local ref (`scheme://id`) from `kind`, requiring the given scheme.
fn load_scheme(data_dir: &str, r: &str, scheme: &str, kind: &str) -> Option<Value> {
    match split_ref(r) {
        Some((s, id)) if s == scheme => load(data_dir, kind, id),
        _ => None,
    }
}
/// The DomainApp's admitted history, as this caller is entitled to see it.
///
/// Every ladder transition is admitted on the APP's stream — app, runtime and receipts together,
/// because those three commit or none of them do — so one history read answers every question about
/// the runtime and its receipt chain. That is what makes the runtime and receipt record directories
/// projections in the strict sense: delete them and the fold below rebuilds byte-identical records,
/// because every input it uses is an admitted operation and an admission stamp.
fn ladder_history(
    data_dir: &str,
    identity: &super::substrate_store::RequestIdentity,
    domain_app_ref: &str,
) -> Result<Vec<(u64, String, Value)>, (StatusCode, Json<Value>)> {
    let scope = super::substrate_store::authorize_request_resource_scope(
        data_dir,
        identity,
        KIND_DAPP,
        domain_app_ref,
        None,
    )
    .map_err(super::odk_routes::odk_scope_refusal)?;
    let history = super::mutation_event_foundation::read_owner_scoped_history(
        data_dir,
        identity,
        &scope,
        KIND_DAPP,
        domain_app_ref,
        DAPP_NAMESPACE,
        &super::mutation_event_foundation::stream_tail(KIND_DAPP, domain_app_ref),
    )
    .map_err(|error| {
        (
            StatusCode::CONFLICT,
            Json(json!({
                "ok": false,
                "error": { "code": error.code(), "message": error.message() }
            })),
        )
    })?;
    Ok(history
        .into_iter()
        .map(|entry| {
            (
                entry.operation.recorded_at_ms,
                entry.head.clone(),
                entry.operation.payload,
            )
        })
        .collect())
}

/// Fill a runtime core's five admission-derived stamps and commit it.
///
/// TIME COMES FROM THE ADMISSION, AND THE STAMPS THE TRANSITION DID NOT TOUCH ARE CARRIED FORWARD.
/// A serve does not re-stamp `mounted_at`, and a stop does not clear `serve_started_at` — the
/// runtime's record is the whole mount's history, not the last transition's snapshot. Because every
/// input here is either the admitted core or the admitted operation's own timestamp, replaying the
/// fold over the same history produces the same bytes.
fn project_runtime(core: &Value, prior: Option<&Value>, action: &str, stamp: &str) -> Value {
    let mut runtime = core.clone();
    let carried = |key: &str| {
        prior
            .and_then(|p| p.get(key).cloned())
            .unwrap_or(Value::Null)
    };
    runtime["mounted_at"] = if action == "domain_app.mount" {
        json!(stamp)
    } else {
        carried("mounted_at")
    };
    runtime["serve_started_at"] = if action == "domain_app.serve_start" {
        json!(stamp)
    } else {
        carried("serve_started_at")
    };
    runtime["serve_stopped_at"] = if matches!(
        action,
        "domain_app.serve_stop" | "domain_app.kill_stop_serving"
    ) {
        json!(stamp)
    } else {
        carried("serve_stopped_at")
    };
    runtime["unmounted_at"] = if matches!(action, "domain_app.unmount" | "domain_app.kill_unmount")
    {
        json!(stamp)
    } else {
        carried("unmounted_at")
    };
    runtime["killed_at"] = if matches!(
        action,
        "domain_app.kill_unmount" | "domain_app.kill_stop_serving"
    ) {
        json!(stamp)
    } else {
        carried("killed_at")
    };
    commit_record(
        &mut runtime,
        RUNTIME_CONTENT_DOMAIN,
        RUNTIME_MATERIAL_FIELDS,
        "content_hash",
    );
    runtime
}

/// Fill a receipt core's admission stamp and the runtime binding only the projection can know.
///
/// THE THREE FIELDS THAT MAKE THE BINDING EXACT. The runtime ref, its owner and the revision are
/// known before the transition is admitted and travel in the admitted payload. The runtime's
/// `content_hash` is not: it commits the state the transition PRODUCED, including that state's own
/// admission stamps, so it exists only once the admission has a timestamp. Computing it here — from
/// the runtime this same projection just built — is what lets a relying party check offline that the
/// receipt and the runtime describe the same admitted state rather than merely coexist.
fn project_receipt(core: &Value, runtime_content_hash: &str, stamp: &str) -> Value {
    let mut receipt = core.clone();
    receipt["domain_app_runtime_content_hash"] = json!(runtime_content_hash);
    receipt["at"] = json!(stamp);
    commit_record(
        &mut receipt,
        RECEIPT_STATE_ROOT_DOMAIN,
        RECEIPT_MATERIAL_FIELDS,
        "state_root",
    );
    receipt
}

/// The runtime and receipt chain this app's admitted history entails, folded in order.
///
/// A PURE FUNCTION OF THE CHAIN. Nothing about the stored runtime or receipt rows is read: not their
/// bytes, not their timestamps. That is what makes `POST …/rebuild-index` deterministic and what
/// makes the deletion or corruption of either directory unable to change any answer this module
/// gives.
fn fold_ladder(history: &[(u64, String, Value)]) -> (Option<Value>, Vec<Value>) {
    let mut runtime: Option<Value> = None;
    let mut receipts: Vec<Value> = Vec::new();
    for (recorded_at_ms, _head, payload) in history {
        let Some(core) = payload.get("runtime") else {
            continue;
        };
        let action = payload
            .get("transition_action")
            .and_then(Value::as_str)
            .unwrap_or("domain_app.mount");
        let stamp = super::mutation_event_foundation::admitted_stamp(*recorded_at_ms);
        let next = project_runtime(core, runtime.as_ref(), action, &stamp);
        let hash = next
            .get("content_hash")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        for receipt_core in payload
            .get("receipts")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
        {
            receipts.push(project_receipt(&receipt_core, &hash, &stamp));
        }
        runtime = Some(next);
    }
    (runtime, receipts)
}

/// This app's current runtime, resolved from the chain.
fn resolve_admitted_runtime(
    data_dir: &str,
    identity: &super::substrate_store::RequestIdentity,
    domain_app_ref: &str,
) -> Result<(Option<Value>, Vec<Value>), (StatusCode, Json<Value>)> {
    let history = ladder_history(data_dir, identity, domain_app_ref)?;
    Ok(fold_ladder(&history))
}

/// The runtime id one mount mints, derived rather than clocked.
fn runtime_id_for(caller: &WriteCaller) -> String {
    replay_stable_id("dartm", &caller.owner_ref, &caller.idempotency_key)
}

/// The receipt id one transition emits, derived from the caller's key AND the action.
///
/// A kill emits two receipts in one admitted transition — one for the stop it drove and one for the
/// unmount — so the action has to be in the derivation or the two would collide. The same derivation
/// makes a replayed transition re-emit the receipt it already emitted rather than appending a second
/// one that attests the same fact under a different id, which is what `mrcpt_{nanos():x}` did.
fn receipt_id_for(caller: &WriteCaller, action: &str) -> String {
    replay_stable_id(
        "mrcpt",
        &caller.owner_ref,
        &format!("{}\u{0}{action}", caller.idempotency_key),
    )
}

struct PendingMountReceipt {
    id: String,
    reference: String,
    core: Value,
}

/// Build one receipt core: everything the transition knows BEFORE it is admitted.
#[allow(clippy::too_many_arguments)]
fn build_mount_receipt(
    caller: &WriteCaller,
    action: &str,
    domain_app_ref: &str,
    runtime_ref: &str,
    runtime_owner_ref: &str,
    runtime_revision: u64,
    admitted_head_before: &str,
    approval_ref: &str,
    release_ref: &str,
) -> PendingMountReceipt {
    let id = receipt_id_for(caller, action);
    let reference = format!("mount-receipt://{id}");
    PendingMountReceipt {
        id,
        core: json!({
            "schema_version": RECEIPT_V2_SCHEMA_VERSION,
            "mount_receipt_id": reference,
            "action": action,
            "domain_app_ref": domain_app_ref,
            // THE FOUR BINDINGS v1 DID NOT HAVE. An app accumulates several runtimes over its life,
            // and a receipt naming only the app cannot say which mount it transitioned.
            "domain_app_runtime_ref": runtime_ref,
            "domain_app_runtime_owner_ref": runtime_owner_ref,
            "domain_app_runtime_revision": runtime_revision,
            "domain_app_admitted_head_before": admitted_head_before,
            "approval_request_ref": approval_ref,
            "release_control_ref": release_ref,
            "does_not_assert": RECEIPT_NONCLAIMS,
        }),
        reference,
    }
}

fn rollback_record(data_dir: &str, kind: &str, id: &str, prior: Option<&Value>) -> bool {
    match prior {
        Some(record) => persist_record(data_dir, kind, id, record).is_ok(),
        None => load(data_dir, kind, id).is_none() || remove_record(data_dir, kind, id),
    }
}

fn transition_persist_failure(
    code: &str,
    stage: &str,
    rollback_succeeded: bool,
) -> (StatusCode, Json<Value>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({
            "ok": false,
            "error": {
                "code": code,
                "message": if rollback_succeeded {
                    format!("the {stage} durable write failed; prior Domain App state was restored")
                } else {
                    format!("the {stage} durable write failed and rollback was incomplete; manual repair is required")
                },
                "rollback_succeeded": rollback_succeeded
            }
        })),
    )
}

/// One committed ladder transition, as its caller sees it after projection.
struct CommittedTransition {
    runtime: Value,
    receipts: Vec<Value>,
    replayed: bool,
    admitted_head: String,
}

/// Commit one runtime transition as app + runtime + receipt set.
///
/// ADMIT FIRST, PROJECT SECOND, PERSIST LAST — and the projections are recomputed from the admitted
/// commit rather than carried across it. A mount touches an app record, a runtime and N receipts; if
/// the crash story were rollback, a process death between writes would leave no trace of what was
/// being attempted. Admitting the composite first makes the canonical transition durable, so
/// recovery is a replay of a known intent. Receipts are persisted last so none can attest to state
/// that failed to commit, and any later-stage failure restores both prior records and removes the
/// receipts this attempt wrote.
#[allow(clippy::too_many_arguments)]
fn finalize_domain_app_transition(
    data_dir: &str,
    caller: &WriteCaller,
    op_kind: &str,
    action: &str,
    runtime_id: &str,
    prior_runtime: Option<&Value>,
    next_runtime_core: &Value,
    domain_app_id: &str,
    prior_domain_app: &ResolvedDomainApp,
    next_domain_app: &Value,
    receipts: &[PendingMountReceipt],
) -> Result<CommittedTransition, (StatusCode, Json<Value>)> {
    let expected_head = prior_domain_app.admitted_head.clone();
    let commit = admit_owner_scoped_write(
        data_dir,
        caller,
        DAPP_NAMESPACE,
        KIND_DAPP,
        &prior_domain_app.domain_app_ref,
        op_kind,
        Some(&expected_head),
        &json!({
            "domain_app": next_domain_app,
            "runtime": next_runtime_core,
            // The action is in the admitted payload because the fold that rebuilds this runtime from
            // the chain has to know which stamp slot the transition filled. Deriving it from the
            // receipts instead would make a rebuild depend on a receipt array's order.
            "transition_action": action,
            "receipts": receipts.iter().map(|r| r.core.clone()).collect::<Vec<_>>()
        }),
    )?;
    let stamp = super::mutation_event_foundation::admitted_stamp(
        commit.projection.operation.recorded_at_ms,
    );
    let runtime = project_runtime(next_runtime_core, prior_runtime, action, &stamp);
    let runtime_hash = runtime
        .get("content_hash")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    registered_valid(
        RUNTIME_V2_CONTRACT_ID,
        &runtime,
        "domain_app_runtime_not_registered_valid",
    )?;
    let projected: Vec<Value> = receipts
        .iter()
        .map(|r| project_receipt(&r.core, &runtime_hash, &stamp))
        .collect();
    for receipt in &projected {
        registered_valid(
            RECEIPT_V2_CONTRACT_ID,
            receipt,
            "domain_app_mount_receipt_not_registered_valid",
        )?;
    }
    let row = domain_app_row(
        next_domain_app,
        &prior_domain_app.projected_created_at,
        &stamp,
        &commit.projection.head,
    )?;
    if persist_record(data_dir, KIND_RUNTIME, runtime_id, &runtime).is_err() {
        return Err(transition_persist_failure(
            "domain_app_runtime_persistence_failed",
            "runtime",
            true,
        ));
    }
    if persist_record(data_dir, KIND_DAPP, domain_app_id, &row).is_err() {
        return Err(transition_persist_failure(
            "domain_app_backlink_persistence_failed",
            "Domain App backlink",
            rollback_record(data_dir, KIND_RUNTIME, runtime_id, prior_runtime),
        ));
    }
    let mut written_receipts: Vec<&str> = Vec::new();
    for (pending, receipt) in receipts.iter().zip(projected.iter()) {
        if persist_record(data_dir, KIND_MOUNT_RECEIPT, &pending.id, receipt).is_err() {
            let mut rollback_succeeded = true;
            for id in written_receipts {
                rollback_succeeded &= load(data_dir, KIND_MOUNT_RECEIPT, id).is_none()
                    || remove_record(data_dir, KIND_MOUNT_RECEIPT, id);
            }
            rollback_succeeded &= load(data_dir, KIND_MOUNT_RECEIPT, &pending.id).is_none()
                || remove_record(data_dir, KIND_MOUNT_RECEIPT, &pending.id);
            // The app row is restored to the bytes the CHAIN says it had before this attempt, which
            // is a rebuild rather than a copy of whatever the row happened to hold.
            let restored_row = domain_app_row(
                &prior_domain_app.record,
                &prior_domain_app.projected_created_at,
                &prior_domain_app.projected_updated_at,
                &prior_domain_app.admitted_head,
            )
            .ok();
            rollback_succeeded &=
                rollback_record(data_dir, KIND_DAPP, domain_app_id, restored_row.as_ref());
            rollback_succeeded &=
                rollback_record(data_dir, KIND_RUNTIME, runtime_id, prior_runtime);
            return Err(transition_persist_failure(
                "domain_app_receipt_persistence_failed",
                "receipt",
                rollback_succeeded,
            ));
        }
        written_receipts.push(&pending.id);
    }
    Ok(CommittedTransition {
        runtime,
        receipts: projected,
        replayed: commit.replayed,
        admitted_head: commit.projection.head,
    })
}

/// Project the app's runtime backlink. A PROJECTION, never a second source of truth.
fn runtime_backlink(runtime: &Value) -> Value {
    let mounted = runtime.get("mounted").and_then(Value::as_bool) == Some(true);
    let serving = runtime.get("serving").and_then(Value::as_bool) == Some(true);
    json!({
        "mounted": mounted,
        "serving": serving,
        // The route the runtime holds, not a second route this record decides for itself.
        "route": if serving { runtime.get("internal_route_ref").cloned().unwrap_or(Value::Null) } else { Value::Null },
        // A live posture NAMES the runtime it projects. An unmounted one projects nothing, because
        // there is nothing live to point at and a stale pointer reads exactly like a live one.
        "mount_ref": if mounted { runtime.get("domain_app_runtime_id").cloned().unwrap_or(Value::Null) } else { Value::Null }
    })
}

/// Apply a runtime backlink to the app record and re-commit it. INVENTORY STATUS IS NOT TOUCHED.
///
/// This is the structural half of G-6. A mount, a serve, a stop, an unmount and a kill all pass
/// through here, and none of them can reach `status`: the field is not read, not written, and not
/// present in the value this function returns changed. "Admitted" cannot start reading as "running"
/// because the writer that would have to conflate them does not touch the field.
fn with_runtime_backlink(app: &Value, runtime: &Value) -> Value {
    let mut next = app.clone();
    next["runtime_posture"] = runtime_backlink(runtime);
    commit_record(
        &mut next,
        DOMAIN_APP_CONTENT_DOMAIN,
        DOMAIN_APP_MATERIAL_FIELDS,
        "content_hash",
    );
    next
}

/// POST /v1/hypervisor/domain-apps/:id/mount — governed mount admission (effectful, not serving).
pub(crate) async fn handle_domain_app_mount(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    headers: axum::http::HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let caller: WriteCaller = match require_write_caller(&st.data_dir, &headers, &body) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    let app_ref = format!("domain-app://{id}");
    let prior = match resolve_admitted_domain_app(&st.data_dir, &caller.identity, &app_ref) {
        Ok(resolved) => resolved,
        Err(response) => return response,
    };
    if prior.withdrawn {
        return bad(
            "domain_app_withdrawn",
            "this DomainApp was withdrawn; a withdrawn app has no runtime to mount",
        );
    }
    if prior.schema_version != DOMAIN_APP_V2_SCHEMA_VERSION {
        return bad(
            "domain_app_predecessor_not_mountable",
            "a stored predecessor DomainApp record has no field for the runtime binding this ladder writes; it remains readable and is not mounted",
        );
    }
    let (existing_runtime, _) =
        match resolve_admitted_runtime(&st.data_dir, &caller.identity, &app_ref) {
            Ok(found) => found,
            Err(response) => return response,
        };
    if existing_runtime
        .as_ref()
        .and_then(|rt| rt.get("mounted"))
        .and_then(Value::as_bool)
        == Some(true)
    {
        return bad(
            "domain_app_already_mounted",
            "this domain app already has a mounted runtime; unmount first",
        );
    }
    let approval_ref = str_field(&body, "approval_request_ref");
    let release_ref = str_field(&body, "release_control_ref");
    let Some(approval) = load_scheme(
        &st.data_dir,
        approval_ref,
        "approval-request",
        KIND_APPROVAL,
    ) else {
        return bad(
            "mount_approval_unresolved",
            "approval_request_ref must be an 'approval-request://' ref that resolves",
        );
    };
    let Some(release) = load_scheme(&st.data_dir, release_ref, "release-control", KIND_RELEASE)
    else {
        return bad(
            "mount_release_unresolved",
            "release_control_ref must be a 'release-control://' ref that resolves",
        );
    };
    if let Err((c, m)) = approval_admits(&approval, &app_ref) {
        return bad(&c, &m);
    }
    if let Err((c, m)) = release_admits(&release, &app_ref) {
        return bad(&c, &m);
    }
    let rid = runtime_id_for(&caller);
    let runtime_ref = format!("domain-app-runtime://{rid}");
    let receipt = build_mount_receipt(
        &caller,
        "domain_app.mount",
        &app_ref,
        &runtime_ref,
        &caller.owner_ref,
        0,
        &prior.admitted_head,
        approval_ref,
        release_ref,
    );
    let runtime_core = json!({
        "schema_version": RUNTIME_V2_SCHEMA_VERSION,
        "domain_app_runtime_id": runtime_ref,
        "domain_app_ref": app_ref,
        "owner_ref": caller.owner_ref,
        "revision": 0,
        "state": "mounted",
        "mounted": true,
        "serving": false,
        "internal_route_ref": Value::Null,
        // MOUNT DOES NOT SERVE AND SERVING DOES NOT EXPOSE. External ingress is a separate admission
        // this envelope RECORDS but does not grant, and no path in this module sets it.
        "external_ingress_ref": Value::Null,
        "approval_request_ref": approval_ref,
        "release_control_ref": release_ref,
        "authority_refs": approval.get("required_authority_refs").cloned().unwrap_or_else(|| json!([])),
        "receipt_refs": [receipt.reference.clone()],
        "unmount_reason": Value::Null,
        "rollback_posture": {
            "unmountable": true,
            "note": "governed unmount available; no process or ingress to tear down because this mount is not serving"
        },
        "authority_nonclaim": "domain_app_runtime_grants_no_authority",
        "truth_nonclaim": "domain_app_runtime_is_not_registration_or_launchability",
        "does_not_assert": RUNTIME_NONCLAIMS,
    });
    let next_app = with_runtime_backlink(
        &prior.record,
        &json!({
            "mounted": true, "serving": false, "domain_app_runtime_id": runtime_ref
        }),
    );
    match finalize_domain_app_transition(
        &st.data_dir,
        &caller,
        "domain_app.mount",
        "domain_app.mount",
        &rid,
        None,
        &runtime_core,
        &id,
        &prior,
        &next_app,
        std::slice::from_ref(&receipt),
    ) {
        Ok(committed) => (
            StatusCode::CREATED,
            Json(json!({
                "ok": true,
                "replayed": committed.replayed,
                "runtime": committed.runtime,
                "receipt": committed.receipts.first().cloned().unwrap_or(Value::Null),
                "domain_app": next_app,
                "admitted_head": committed.admitted_head
            })),
        ),
        Err(response) => response,
    }
}

/// Build the successor runtime core for one non-mount transition.
///
/// The runtime's REVISION advances by exactly one per admitted transition, and the receipt that
/// attests it binds that number. Every other field is carried from the prior runtime unless this
/// transition changes it, so a stop does not silently drop the approval refs the mount recorded.
fn advance_runtime_core(
    prior: &Value,
    state: &str,
    mounted: bool,
    serving: bool,
    internal_route_ref: Value,
    unmount_reason: Value,
    new_receipt_refs: &[String],
    rollback_note: &str,
) -> Value {
    let mut refs: Vec<String> = prior
        .get("receipt_refs")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    for r in new_receipt_refs {
        push_unique(&mut refs, r);
    }
    let revision = prior.get("revision").and_then(Value::as_u64).unwrap_or(0) + 1;
    json!({
        "schema_version": RUNTIME_V2_SCHEMA_VERSION,
        "domain_app_runtime_id": prior.get("domain_app_runtime_id").cloned().unwrap_or(Value::Null),
        "domain_app_ref": prior.get("domain_app_ref").cloned().unwrap_or(Value::Null),
        "owner_ref": prior.get("owner_ref").cloned().unwrap_or(Value::Null),
        "revision": revision,
        "state": state,
        "mounted": mounted,
        "serving": serving,
        "internal_route_ref": internal_route_ref,
        // Ingress is carried, never acquired. Serving assigns an internal route and nothing else;
        // exposing a Domain App externally is a separate admission this module does not perform.
        "external_ingress_ref": prior.get("external_ingress_ref").cloned().unwrap_or(Value::Null),
        "approval_request_ref": prior.get("approval_request_ref").cloned().unwrap_or(Value::Null),
        "release_control_ref": prior.get("release_control_ref").cloned().unwrap_or(Value::Null),
        "authority_refs": prior.get("authority_refs").cloned().unwrap_or_else(|| json!([])),
        "receipt_refs": refs,
        "unmount_reason": unmount_reason,
        "rollback_posture": { "unmountable": mounted, "note": rollback_note },
        "authority_nonclaim": "domain_app_runtime_grants_no_authority",
        "truth_nonclaim": "domain_app_runtime_is_not_registration_or_launchability",
        "does_not_assert": RUNTIME_NONCLAIMS,
    })
}

/// The app plus its live runtime, both resolved from the chain, for a ladder transition.
fn ladder_subject(
    data_dir: &str,
    caller: &WriteCaller,
    id: &str,
) -> Result<(ResolvedDomainApp, Value), (StatusCode, Json<Value>)> {
    let app_ref = format!("domain-app://{id}");
    let app = resolve_admitted_domain_app(data_dir, &caller.identity, &app_ref)?;
    if app.withdrawn {
        return Err(bad(
            "domain_app_withdrawn",
            "this DomainApp was withdrawn; a withdrawn app has no runtime to advance",
        ));
    }
    let (runtime, _) = resolve_admitted_runtime(data_dir, &caller.identity, &app_ref)?;
    let Some(runtime) = runtime else {
        return Err(bad(
            "domain_app_not_mounted",
            "no runtime has ever been mounted for this domain app",
        ));
    };
    Ok((app, runtime))
}

/// Re-read and re-check the mount's governance LIVE. Prior admission is never standing permission.
fn revalidate_governance(
    data_dir: &str,
    runtime: &Value,
    domain_app_ref: &str,
) -> Result<(String, String), (StatusCode, Json<Value>)> {
    let approval_ref = runtime
        .get("approval_request_ref")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let release_ref = runtime
        .get("release_control_ref")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let Some(approval) = load_scheme(data_dir, &approval_ref, "approval-request", KIND_APPROVAL)
    else {
        return Err(bad(
            "serve_approval_missing",
            "the mount's ApprovalRequest no longer resolves",
        ));
    };
    let Some(release) = load_scheme(data_dir, &release_ref, "release-control", KIND_RELEASE) else {
        return Err(bad(
            "serve_release_missing",
            "the mount's ReleaseControl no longer resolves",
        ));
    };
    if let Err((c, m)) = approval_admits(&approval, domain_app_ref) {
        return Err(bad(&c, &m));
    }
    if let Err((c, m)) = release_admits(&release, domain_app_ref) {
        return Err(bad(&c, &m));
    }
    Ok((approval_ref, release_ref))
}

/// Run one non-mount transition end to end.
#[allow(clippy::too_many_arguments)]
async fn run_ladder_transition(
    st: &Arc<DaemonState>,
    id: String,
    headers: axum::http::HeaderMap,
    body: Value,
    action: &'static str,
    op_kind: &'static str,
    precheck: impl Fn(&Value) -> Result<(), (String, String)>,
    revalidate: bool,
    state: &'static str,
    mounted: bool,
    serving: bool,
    route_from_runtime: bool,
    rollback_note: &'static str,
) -> (StatusCode, Json<Value>) {
    let caller: WriteCaller = match require_write_caller(&st.data_dir, &headers, &body) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    let (app, prior_runtime) = match ladder_subject(&st.data_dir, &caller, &id) {
        Ok(found) => found,
        Err(response) => return response,
    };
    if let Err((c, m)) = precheck(&prior_runtime) {
        return bad(&c, &m);
    }
    let (approval_ref, release_ref) = if revalidate {
        match revalidate_governance(&st.data_dir, &prior_runtime, &app.domain_app_ref) {
            Ok(pair) => pair,
            Err(response) => return response,
        }
    } else {
        (
            prior_runtime
                .get("approval_request_ref")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            prior_runtime
                .get("release_control_ref")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
        )
    };
    let rid = prior_runtime
        .get("domain_app_runtime_id")
        .and_then(Value::as_str)
        .and_then(|r| split_ref(r).map(|(_, id)| id.to_string()))
        .unwrap_or_default();
    let runtime_ref = prior_runtime
        .get("domain_app_runtime_id")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let revision = prior_runtime
        .get("revision")
        .and_then(Value::as_u64)
        .unwrap_or(0)
        + 1;
    let receipt = build_mount_receipt(
        &caller,
        action,
        &app.domain_app_ref,
        &runtime_ref,
        prior_runtime
            .get("owner_ref")
            .and_then(Value::as_str)
            .unwrap_or_default(),
        revision,
        &app.admitted_head,
        &approval_ref,
        &release_ref,
    );
    let route = if route_from_runtime {
        json!(format!("/__ioi/domain-app-runtime/{rid}"))
    } else {
        Value::Null
    };
    let unmount_reason = if mounted {
        prior_runtime
            .get("unmount_reason")
            .cloned()
            .unwrap_or(Value::Null)
    } else {
        json!(body.get("reason").and_then(Value::as_str).unwrap_or(""))
    };
    let core = advance_runtime_core(
        &prior_runtime,
        state,
        mounted,
        serving,
        route,
        unmount_reason,
        &[receipt.reference.clone()],
        rollback_note,
    );
    let next_app = with_runtime_backlink(&app.record, &core);
    match finalize_domain_app_transition(
        &st.data_dir,
        &caller,
        op_kind,
        action,
        &rid,
        Some(&prior_runtime),
        &core,
        &id,
        &app,
        &next_app,
        std::slice::from_ref(&receipt),
    ) {
        Ok(committed) => (
            StatusCode::CREATED,
            Json(json!({
                "ok": true,
                "replayed": committed.replayed,
                "runtime": committed.runtime,
                "receipt": committed.receipts.first().cloned().unwrap_or(Value::Null),
                "domain_app": next_app,
                "admitted_head": committed.admitted_head
            })),
        ),
        Err(response) => response,
    }
}

/// POST /v1/hypervisor/domain-apps/:id/unmount — governed, receipted unmount state transition.
pub(crate) async fn handle_domain_app_unmount(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    headers: axum::http::HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    run_ladder_transition(
        &st,
        id,
        headers,
        body,
        "domain_app.unmount",
        "domain_app.unmount",
        |runtime| {
            if runtime.get("mounted").and_then(Value::as_bool) != Some(true) {
                return Err((
                    "domain_app_not_mounted".into(),
                    "no mounted runtime for this domain app".into(),
                ));
            }
            Ok(())
        },
        false,
        "unmounted",
        false,
        false,
        false,
        "this mount is terminal; a later mount creates a new runtime rather than reviving this one",
    )
    .await
}

// ---- SERVING (internal, descriptor-driven; reuses the mount's governance) -----------------------
// Serving is a sub-step of the same governed mount — it reuses the mount's approved ApprovalRequest
// and open ReleaseControl, RE-VALIDATED LIVE, assigns an INTERNAL route only, and emits a receipt
// bound to the exact runtime revision it produced. Still no process, no public ingress, no publish,
// no connector action and no object mutation.

/// Precheck the runtime for a serve transition (pure): must be mounted and not already serving.
fn serve_precheck(runtime: &Value) -> Result<(), (String, String)> {
    if runtime.get("mounted").and_then(|v| v.as_bool()) != Some(true) {
        return Err((
            "domain_app_not_mounted".into(),
            "runtime must be mounted before it can serve".into(),
        ));
    }
    if runtime.get("serving").and_then(|v| v.as_bool()) == Some(true) {
        return Err((
            "domain_app_already_serving".into(),
            "runtime is already serving".into(),
        ));
    }
    Ok(())
}

/// POST /v1/hypervisor/domain-apps/:id/serve — start internal, descriptor-driven serving.
pub(crate) async fn handle_domain_app_serve(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    headers: axum::http::HeaderMap,
    Json(identity_body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    run_ladder_transition(
        &st,
        id,
        headers,
        identity_body,
        "domain_app.serve_start",
        "domain_app.serve",
        serve_precheck,
        true,
        "serving",
        true,
        true,
        true,
        "governed unmount available; stop serving first or the unmount withdraws the route with it",
    )
    .await
}

/// POST /v1/hypervisor/domain-apps/:id/stop-serving — stop serving; return to mounted, receipted.
pub(crate) async fn handle_domain_app_stop_serving(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    headers: axum::http::HeaderMap,
    Json(identity_body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    run_ladder_transition(
        &st,
        id,
        headers,
        identity_body,
        "domain_app.serve_stop",
        "domain_app.stop_serving",
        |runtime| {
            if runtime.get("mounted").and_then(Value::as_bool) != Some(true) {
                return Err((
                    "domain_app_not_mounted".into(),
                    "no mounted runtime for this domain app".into(),
                ));
            }
            if runtime.get("serving").and_then(Value::as_bool) != Some(true) {
                return Err((
                    "domain_app_not_serving".into(),
                    "runtime is not serving".into(),
                ));
            }
            Ok(())
        },
        false,
        "mounted",
        true,
        false,
        false,
        "governed unmount available; serving has been withdrawn",
    )
    .await
}

/// GET /v1/hypervisor/domain-app-runtimes[?domain_app_ref=…] — this caller's runtimes, from the chain.
pub(crate) async fn handle_domain_app_runtime_list(
    State(st): State<Arc<DaemonState>>,
    headers: axum::http::HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> (StatusCode, Json<Value>) {
    let identity = match super::substrate_store::resolve_request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(error) => return super::odk_routes::odk_scope_refusal(error),
    };
    let authorized = match super::substrate_store::authorized_request_resource_refs(
        &st.data_dir,
        &identity,
        KIND_DAPP,
    ) {
        Ok(refs) => refs,
        Err(error) => return super::odk_routes::odk_scope_refusal(error),
    };
    let filter = q
        .get("domain_app_ref")
        .map(|s| s.trim())
        .filter(|s| !s.is_empty());
    let mut items: Vec<Value> = Vec::new();
    let mut unreadable = 0usize;
    for app_ref in &authorized {
        if filter.is_some_and(|f| f != app_ref) {
            continue;
        }
        match resolve_admitted_runtime(&st.data_dir, &identity, app_ref) {
            Ok((Some(runtime), _)) => items.push(runtime),
            Ok((None, _)) => {}
            Err(_) => unreadable += 1,
        }
    }
    items.sort_by(|a, b| {
        b["mounted_at"]
            .as_str()
            .unwrap_or("")
            .cmp(a["mounted_at"].as_str().unwrap_or(""))
    });
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "runtimes": items,
            "projection_source": "agentgres_owner_chain",
            "census": { "census_scope": "this_caller_only", "unreadable": unreadable }
        })),
    )
}

/// GET /v1/hypervisor/domain-app-runtimes/:id — one runtime, and the receipt chain that attests it.
pub(crate) async fn handle_domain_app_runtime_get(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    headers: axum::http::HeaderMap,
) -> (StatusCode, Json<Value>) {
    let identity = match super::substrate_store::resolve_request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(error) => return super::odk_routes::odk_scope_refusal(error),
    };
    let authorized = match super::substrate_store::authorized_request_resource_refs(
        &st.data_dir,
        &identity,
        KIND_DAPP,
    ) {
        Ok(refs) => refs,
        Err(error) => return super::odk_routes::odk_scope_refusal(error),
    };
    let wanted = format!("domain-app-runtime://{id}");
    for app_ref in &authorized {
        if let Ok((Some(runtime), receipts)) =
            resolve_admitted_runtime(&st.data_dir, &identity, app_ref)
        {
            if runtime.get("domain_app_runtime_id").and_then(Value::as_str) == Some(wanted.as_str())
            {
                // EVERY RECEIPT NAMES THIS RUNTIME AND THE REVISION IT ATTESTS. A caller can now
                // attribute a serve-stop to the serve it stopped, which is exactly what a receipt
                // naming only the app could never do.
                return (
                    StatusCode::OK,
                    Json(json!({
                        "ok": true,
                        "runtime": runtime,
                        "receipts": receipts,
                        "projection_source": "agentgres_owner_chain"
                    })),
                );
            }
        }
    }
    (
        StatusCode::NOT_FOUND,
        Json(json!({
            "ok": false,
            "error": {
                "code": "domain_app_runtime_not_found",
                "message": "no runtime with this id is admitted under a DomainApp this caller may read"
            }
        })),
    )
}

// ---- KillSwitch enforcement helpers (shared with governance_routes) ----------------------------
// Enforcement drives the SAME transitions and emits the SAME receipt family as a voluntary stop, so
// an enforced stop leaves exactly the record a voluntary one produces, distinguished only by the
// receipt's action and the terminal `killed` state. Enforcement must not have a private path that
// leaves a thinner record.

/// Resolve the ACTIVE (mounted OR serving) runtimes a KillSwitch subject_ref targets.
///
/// Answered from the chain through the enforcing caller's own scope, so a deleted runtime row cannot
/// hide a live mount from enforcement — which is the failure mode a row-backed lookup had.
pub(crate) fn runtimes_for_kill_target(data_dir: &str, subject_ref: &str) -> Vec<Value> {
    let active = |rt: &Value| {
        rt.get("mounted").and_then(Value::as_bool) == Some(true)
            || rt.get("serving").and_then(Value::as_bool) == Some(true)
    };
    match split_ref(subject_ref) {
        Some(("domain-app-runtime", id)) => {
            let wanted = format!("domain-app-runtime://{id}");
            super::read_record_dir(data_dir, KIND_RUNTIME)
                .into_iter()
                .filter(|rt| {
                    rt.get("domain_app_runtime_id").and_then(Value::as_str) == Some(wanted.as_str())
                        && active(rt)
                })
                .collect()
        }
        Some(("domain-app", _)) => super::read_record_dir(data_dir, KIND_RUNTIME)
            .into_iter()
            .filter(|rt| {
                rt.get("domain_app_ref").and_then(Value::as_str) == Some(subject_ref) && active(rt)
            })
            .collect(),
        _ => Vec::new(),
    }
}

/// Enforce a kill on ONE runtime: stop serving (if serving) and unmount (if mounted), in ONE
/// admitted transition that emits the ordinary receipt family under enforcement action names and
/// ends in the terminal `killed` state.
///
/// BOTH RECEIPTS BIND THE SAME RUNTIME REVISION, and that is correct rather than a rounding: this is
/// one admitted transition with two attested sub-facts, so inventing a second revision would claim
/// an admission that never happened.
pub(crate) fn kill_enforce_runtime(
    data_dir: &str,
    caller: &WriteCaller,
    runtime: &Value,
) -> Result<Vec<String>, (StatusCode, Json<Value>)> {
    let domain_app_ref = runtime
        .get("domain_app_ref")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let Some(("domain-app", dapp_id)) = split_ref(&domain_app_ref) else {
        return Err(transition_persist_failure(
            "domain_app_backlink_invalid",
            "Domain App backlink resolution",
            true,
        ));
    };
    let app = resolve_admitted_domain_app(data_dir, &caller.identity, &domain_app_ref)?;
    // THE ROW THAT FOUND THIS RUNTIME IS NOT THE RUNTIME. `runtimes_for_kill_target` scans the
    // record directory because the governance enforce path calls it before it has resolved an
    // owner, so what it hands back is a projection. Enforcement re-resolves the runtime from the
    // chain and drives the transition from THAT, so a corrupted row cannot decide which state an
    // enforced stop transitions from. What the row scan can still do is fail to FIND a live mount if
    // its row was deleted; that discovery gap is stated rather than papered over, and closing it is
    // a governance-owned change to the call site rather than one this module may make alone.
    let (chain_runtime, _) = resolve_admitted_runtime(data_dir, &caller.identity, &domain_app_ref)?;
    let Some(runtime) = chain_runtime.as_ref() else {
        return Err(bad(
            "domain_app_not_mounted",
            "the row named a runtime the admitted chain does not hold; enforcement drives admitted state, never a projection",
        ));
    };
    let runtime_ref = runtime
        .get("domain_app_runtime_id")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let rid = split_ref(&runtime_ref)
        .map(|(_, id)| id.to_string())
        .unwrap_or_default();
    let owner_ref = runtime
        .get("owner_ref")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let approval = runtime
        .get("approval_request_ref")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let release = runtime
        .get("release_control_ref")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let revision = runtime.get("revision").and_then(Value::as_u64).unwrap_or(0) + 1;
    let mut receipts: Vec<PendingMountReceipt> = Vec::new();
    if runtime.get("serving").and_then(Value::as_bool) == Some(true) {
        receipts.push(build_mount_receipt(
            caller,
            "domain_app.kill_stop_serving",
            &domain_app_ref,
            &runtime_ref,
            owner_ref,
            revision,
            &app.admitted_head,
            &approval,
            &release,
        ));
    }
    if runtime.get("mounted").and_then(Value::as_bool) == Some(true) {
        receipts.push(build_mount_receipt(
            caller,
            "domain_app.kill_unmount",
            &domain_app_ref,
            &runtime_ref,
            owner_ref,
            revision,
            &app.admitted_head,
            &approval,
            &release,
        ));
    }
    let emitted: Vec<String> = receipts.iter().map(|r| r.reference.clone()).collect();
    let core = advance_runtime_core(
        runtime,
        "killed",
        false,
        false,
        Value::Null,
        json!("stopped by KillSwitch enforcement"),
        &emitted,
        "terminal; enforcement withdrew this mount and it is not revivable",
    );
    let next_app = with_runtime_backlink(&app.record, &core);
    finalize_domain_app_transition(
        data_dir,
        caller,
        "domain_app.kill_enforce",
        // The stamp slots a kill fills are the unmount's and the kill's, so the projection is driven
        // by the terminal action rather than by whichever receipt happened to be first.
        "domain_app.kill_unmount",
        &rid,
        Some(runtime),
        &core,
        dapp_id,
        &app,
        &next_app,
        &receipts,
    )?;
    Ok(emitted)
}

#[cfg(test)]
mod domain_apps_tests {
    use super::*;

    const DOMAIN_APP_PROFILE: &str = include_str!(
        "../../../../../docs/architecture/_meta/schemas/invariants/domain-app.v2.invariants.json"
    );
    const RUNTIME_PROFILE: &str = include_str!(
        "../../../../../docs/architecture/_meta/schemas/invariants/domain-app-runtime.v2.invariants.json"
    );
    const RECEIPT_PROFILE: &str = include_str!(
        "../../../../../docs/architecture/_meta/schemas/invariants/domain-app-mount-receipt.v2.invariants.json"
    );

    fn caller(key: &str) -> WriteCaller {
        WriteCaller {
            identity: super::super::substrate_store::request_identity_for_test(
                "user://enforcer",
                ["org://acme".to_string()],
            ),
            owner_ref: "org://acme".to_string(),
            idempotency_key: key.to_string(),
        }
    }

    /// THE PRODUCER'S MATERIAL LIST IS THE REGISTERED ONE, FIELD FOR FIELD.
    ///
    /// A commitment computed over a list that has drifted from the registered rule is a number no
    /// relying party can reproduce — and it fails silently, because the producer and its own reader
    /// move together. So the expectation is the committed PROFILE and the computation is this
    /// module's constant, compared rather than derived from each other.
    #[test]
    fn material_lists_match_the_registered_invariant_profiles() {
        for (profile, fields, target, domain) in [
            (
                DOMAIN_APP_PROFILE,
                DOMAIN_APP_MATERIAL_FIELDS,
                "content_hash",
                DOMAIN_APP_CONTENT_DOMAIN,
            ),
            (
                RUNTIME_PROFILE,
                RUNTIME_MATERIAL_FIELDS,
                "content_hash",
                RUNTIME_CONTENT_DOMAIN,
            ),
            (
                RECEIPT_PROFILE,
                RECEIPT_MATERIAL_FIELDS,
                "state_root",
                RECEIPT_STATE_ROOT_DOMAIN,
            ),
        ] {
            let profile: Value = serde_json::from_str(profile).expect("profile is JSON");
            let expression = &profile["rules"][0]["expression"];
            assert_eq!(expression["operator"], json!("jcs_sha256_equals"));
            assert_eq!(expression["expected_path"], json!(format!("$.{target}")));
            assert_eq!(expression["expected_encoding"], json!("sha256_string"));
            let material = expression["material_fields"]
                .as_object()
                .expect("material map");
            assert_eq!(
                material["domain"]["value"],
                json!(domain),
                "the domain separator is registered, not chosen by the producer"
            );
            let mut registered: Vec<&str> = material
                .keys()
                .filter(|k| *k != "domain")
                .map(String::as_str)
                .collect();
            registered.sort_unstable();
            let mut ours: Vec<&str> = fields.to_vec();
            ours.sort_unstable();
            assert_eq!(
                registered, ours,
                "the producer commits exactly the registered material for {domain}"
            );
            // And the material covers everything except the digest slot itself: a field the schema
            // requires but the rule omits is an uncommitted field on a "committed" record.
            assert!(
                !registered.contains(&target),
                "the digest never commits itself"
            );
        }
    }

    /// THE TWO STATE VOCABULARIES SHARE NO WORD (G-6).
    ///
    /// Conflation is not usually a bug in a comparison; it is a bug in a vocabulary. If `admitted`
    /// were also a runtime state, every reader that took a status string and asked "is it running"
    /// would be right often enough to look correct.
    #[test]
    fn inventory_status_and_runtime_state_vocabularies_are_disjoint() {
        let runtime_states = ["mounted", "serving", "unmounted", "killed"];
        for status in DOMAIN_APP_STATUSES {
            assert!(
                !runtime_states.contains(status),
                "'{status}' is an inventory status and must not also name a runtime state"
            );
        }
        for state in runtime_states {
            assert!(
                !DOMAIN_APP_STATUSES.contains(&state),
                "'{state}' is a runtime state and must not also name an inventory status"
            );
        }
    }

    /// A LIVE BACKLINK NAMES ITS RUNTIME; A DEAD ONE PROJECTS NOTHING.
    #[test]
    fn a_runtime_backlink_names_the_runtime_or_projects_nothing() {
        let serving = json!({
            "mounted": true, "serving": true,
            "domain_app_runtime_id": "domain-app-runtime://dartm_0123456789abcdef",
            "internal_route_ref": "/__ioi/domain-app-runtime/dartm_0123456789abcdef"
        });
        let posture = runtime_backlink(&serving);
        assert_eq!(posture["mounted"], json!(true));
        assert_eq!(posture["serving"], json!(true));
        assert_eq!(
            posture["mount_ref"],
            json!("domain-app-runtime://dartm_0123456789abcdef")
        );
        assert_eq!(
            posture["route"],
            json!("/__ioi/domain-app-runtime/dartm_0123456789abcdef")
        );

        let unmounted = json!({
            "mounted": false, "serving": false,
            "domain_app_runtime_id": "domain-app-runtime://dartm_0123456789abcdef",
            "internal_route_ref": Value::Null
        });
        let posture = runtime_backlink(&unmounted);
        assert_eq!(posture["mounted"], json!(false));
        assert_eq!(posture["serving"], json!(false));
        // A stale pointer reads exactly like a live one, so an unmounted posture holds neither.
        assert_eq!(posture["mount_ref"], Value::Null);
        assert_eq!(posture["route"], Value::Null);
    }

    /// A MOUNT RECEIPT BINDS THE EXACT RUNTIME IT TRANSITIONED, AND ITS COMMITMENT COVERS THAT.
    ///
    /// The claim v1 could not make: two runtimes of the same app, two receipts, and each receipt
    /// resolvable to one of them. Substituting the runtime ref moves the state root, which is what
    /// makes the binding evidence rather than decoration.
    #[test]
    fn a_mount_receipt_binds_the_exact_runtime_it_transitioned() {
        let caller = caller("mount-1");
        let receipt = build_mount_receipt(
            &caller,
            "domain_app.mount",
            "domain-app://dapp_0123456789abcdef",
            "domain-app-runtime://dartm_0123456789abcdef",
            "org://acme",
            0,
            "7c19e4a0bb35d2f81c6047ae9d3b5f20",
            "approval-request://apr_1",
            "release-control://rel_1",
        );
        let projected = project_receipt(
            &receipt.core,
            &format!("sha256:{}", "ab".repeat(32)),
            "2026-08-30T17:04:11Z",
        );
        assert_eq!(
            projected["domain_app_runtime_ref"],
            json!("domain-app-runtime://dartm_0123456789abcdef")
        );
        assert_eq!(
            projected["domain_app_runtime_owner_ref"],
            json!("org://acme")
        );
        assert_eq!(projected["domain_app_runtime_revision"], json!(0));
        assert_eq!(
            projected["domain_app_admitted_head_before"],
            json!("7c19e4a0bb35d2f81c6047ae9d3b5f20")
        );
        // The registered contract accepts it, and the registered invariant reproduces its root.
        ioi_types::app::generated::architecture_contracts::validate_architecture_contract(
            RECEIPT_V2_CONTRACT_ID,
            &projected,
        )
        .expect("a projected receipt is registered-valid");

        // Substituting the runtime binding breaks the commitment rather than passing quietly.
        let mut substituted = projected.clone();
        substituted["domain_app_runtime_ref"] =
            json!("domain-app-runtime://dartm_fedcba9876543210");
        ioi_types::app::generated::architecture_contracts::validate_architecture_contract(
            RECEIPT_V2_CONTRACT_ID,
            &substituted,
        )
        .expect_err("a substituted runtime binding fails the state root");

        // And a mount receipt attests the runtime's genesis revision, by contract.
        let mut wrong_revision = projected;
        wrong_revision["domain_app_runtime_revision"] = json!(2);
        commit_record(
            &mut wrong_revision,
            RECEIPT_STATE_ROOT_DOMAIN,
            RECEIPT_MATERIAL_FIELDS,
            "state_root",
        );
        ioi_types::app::generated::architecture_contracts::validate_architecture_contract(
            RECEIPT_V2_CONTRACT_ID,
            &wrong_revision,
        )
        .expect_err("a mount receipt cannot attest a non-genesis revision even with a fresh root");
    }

    /// RECEIPT AND RUNTIME IDENTITY ARE DERIVED, SO A REPLAY RESOLVES RATHER THAN APPENDS.
    #[test]
    fn ladder_identity_is_derived_from_the_caller_not_the_clock() {
        let first = caller("mount-1");
        let again = caller("mount-1");
        let other = caller("mount-2");
        assert_eq!(runtime_id_for(&first), runtime_id_for(&again));
        assert_ne!(runtime_id_for(&first), runtime_id_for(&other));
        // A kill emits two receipts inside ONE admitted transition, so the action has to be in the
        // derivation or the two would collide on the same id.
        assert_ne!(
            receipt_id_for(&first, "domain_app.kill_stop_serving"),
            receipt_id_for(&first, "domain_app.kill_unmount")
        );
        assert_eq!(
            receipt_id_for(&first, "domain_app.mount"),
            receipt_id_for(&again, "domain_app.mount")
        );
    }

    /// THE RUNTIME IS A FOLD OVER THE ADMITTED HISTORY, SO THE ROWS CANNOT CHANGE AN ANSWER.
    ///
    /// This is the claim that makes the runtime and receipt record directories projections in the
    /// strict sense. The fold reads nothing but admitted operations and their admission stamps, so
    /// running it twice over the same history is byte-identical and deleting every row changes
    /// nothing — the two properties a "rebuildable index" has to have to deserve the name.
    #[test]
    fn the_ladder_fold_is_a_pure_function_of_the_admitted_history() {
        let mount_core = json!({
            "schema_version": RUNTIME_V2_SCHEMA_VERSION,
            "domain_app_runtime_id": "domain-app-runtime://dartm_0123456789abcdef",
            "domain_app_ref": "domain-app://dapp_0123456789abcdef",
            "owner_ref": "org://acme",
            "revision": 0, "state": "mounted", "mounted": true, "serving": false,
            "internal_route_ref": Value::Null, "external_ingress_ref": Value::Null,
            "approval_request_ref": "approval-request://apr_1",
            "release_control_ref": "release-control://rel_1",
            "authority_refs": [], "receipt_refs": ["mount-receipt://mrcpt_0123456789abcdef"],
            "unmount_reason": Value::Null,
            "rollback_posture": { "unmountable": true, "note": "governed unmount available" },
            "authority_nonclaim": "domain_app_runtime_grants_no_authority",
            "truth_nonclaim": "domain_app_runtime_is_not_registration_or_launchability",
            "does_not_assert": RUNTIME_NONCLAIMS,
        });
        let mut serve_core = mount_core.clone();
        serve_core["revision"] = json!(1);
        serve_core["state"] = json!("serving");
        serve_core["serving"] = json!(true);
        serve_core["internal_route_ref"] =
            json!("/__ioi/domain-app-runtime/dartm_0123456789abcdef");
        serve_core["receipt_refs"] = json!([
            "mount-receipt://mrcpt_0123456789abcdef",
            "mount-receipt://mrcpt_fedcba9876543210"
        ]);
        let history = vec![
            (
                1_756_400_000_000u64,
                "head-0".to_string(),
                json!({ "runtime": mount_core, "transition_action": "domain_app.mount", "receipts": [] }),
            ),
            (
                1_756_400_600_000u64,
                "head-1".to_string(),
                json!({ "runtime": serve_core, "transition_action": "domain_app.serve_start", "receipts": [] }),
            ),
        ];
        let (first, _) = fold_ladder(&history);
        let (second, _) = fold_ladder(&history);
        assert_eq!(first, second, "the fold is deterministic");
        let runtime = first.expect("a runtime folds out of two transitions");
        // `mounted_at` is the MOUNT's admission stamp, carried across the serve rather than
        // re-stamped: the runtime's record is the whole mount's history, not the last step's.
        assert_eq!(runtime["mounted_at"], json!("2025-08-28T16:53:20Z"));
        assert_eq!(runtime["serve_started_at"], json!("2025-08-28T17:03:20Z"));
        assert_eq!(runtime["serve_stopped_at"], Value::Null);
        assert_eq!(runtime["revision"], json!(1));
        assert_eq!(runtime["state"], json!("serving"));
        ioi_types::app::generated::architecture_contracts::validate_architecture_contract(
            RUNTIME_V2_CONTRACT_ID,
            &runtime,
        )
        .expect("a folded runtime is registered-valid");
    }

    /// SERVING ASSIGNS AN INTERNAL ROUTE AND NOTHING ELSE.
    #[test]
    fn serving_never_acquires_external_ingress() {
        let prior = json!({
            "domain_app_runtime_id": "domain-app-runtime://dartm_0123456789abcdef",
            "domain_app_ref": "domain-app://dapp_0123456789abcdef",
            "owner_ref": "org://acme", "revision": 0,
            "approval_request_ref": "approval-request://apr_1",
            "release_control_ref": "release-control://rel_1",
            "authority_refs": [], "receipt_refs": ["mount-receipt://mrcpt_0123456789abcdef"],
            "external_ingress_ref": Value::Null,
        });
        let core = advance_runtime_core(
            &prior,
            "serving",
            true,
            true,
            json!("/__ioi/domain-app-runtime/dartm_0123456789abcdef"),
            Value::Null,
            &["mount-receipt://mrcpt_fedcba9876543210".to_string()],
            "note",
        );
        assert_eq!(core["external_ingress_ref"], Value::Null);
        assert_eq!(core["revision"], json!(1));
        // The receipt chain grows; it is never replaced by the transition that appended to it.
        assert_eq!(
            core["receipt_refs"],
            json!([
                "mount-receipt://mrcpt_0123456789abcdef",
                "mount-receipt://mrcpt_fedcba9876543210"
            ])
        );
    }

    /// DOWNGRADE IS A REFUSAL BY NAME, NOT A SILENT ACCEPT.
    #[test]
    fn a_predecessor_contract_is_refused_by_name() {
        assert!(require_authored_version(
            &json!({}),
            DOMAIN_APP_V2_SCHEMA_VERSION,
            DOMAIN_APP_V1_SCHEMA_VERSION,
            "DomainApp"
        )
        .is_ok());
        let refusal = require_authored_version(
            &json!({ "schema_version": DOMAIN_APP_V1_SCHEMA_VERSION }),
            DOMAIN_APP_V2_SCHEMA_VERSION,
            DOMAIN_APP_V1_SCHEMA_VERSION,
            "DomainApp",
        )
        .unwrap_err();
        assert_eq!(
            refusal.1 .0["error"]["code"],
            json!("domain_app_predecessor_contract_not_authorable")
        );
        let refusal = require_authored_version(
            &json!({ "schema_version": "ioi.domain-app.v9" }),
            DOMAIN_APP_V2_SCHEMA_VERSION,
            DOMAIN_APP_V1_SCHEMA_VERSION,
            "DomainApp",
        )
        .unwrap_err();
        assert_eq!(
            refusal.1 .0["error"]["code"],
            json!("domain_app_contract_unsupported")
        );
    }

    /// A v2 ROW IS AN ENVELOPE; A STORED v1 ROW IS THE RECORD. THERE IS NO THIRD SHAPE.
    #[test]
    fn the_row_shape_is_version_correct_and_fails_closed() {
        let v2 = json!({ "schema_version": DOMAIN_APP_V2_SCHEMA_VERSION, "domain_app_id": "domain-app://dapp_0123456789abcdef" });
        let row = domain_app_row(&v2, "created", "updated", "head").expect("v2 projects");
        assert_eq!(row["schema_version"], json!(DOMAIN_APP_PROJECTION_SCHEMA));
        assert_eq!(row["domain_app"], v2, "the record is carried byte-exact");
        assert_eq!(row["admitted_head"], json!("head"));

        let v1 = json!({ "schema_version": DOMAIN_APP_V1_SCHEMA_VERSION, "domain_app_id": "dapp_0123456789abcdef" });
        let row = domain_app_row(&v1, "created", "updated", "head").expect("v1 projects");
        assert_eq!(row["schema_version"], json!(DOMAIN_APP_V1_SCHEMA_VERSION));
        assert_eq!(row["created_at"], json!("created"));

        let unknown = json!({ "schema_version": "ioi.domain-app.v9" });
        let refusal = domain_app_row(&unknown, "c", "u", "h").unwrap_err();
        assert_eq!(refusal.0, StatusCode::BAD_GATEWAY);
        assert_eq!(
            refusal.1 .0["error"]["code"],
            json!("domain_app_projection_failed")
        );
    }

    /// THE THREE ADMITTED PAYLOAD SHAPES ARE ALL READ, AND AN UNKNOWN ONE IS NOT.
    #[test]
    fn every_admitted_payload_shape_is_dispatched_explicitly() {
        let record = json!({ "schema_version": DOMAIN_APP_V2_SCHEMA_VERSION });
        assert_eq!(
            domain_app_payload(&record),
            Some(Some(record.clone())),
            "a create or patch admits the bare record"
        );
        assert_eq!(
            domain_app_payload(&json!({ "domain_app": record, "runtime": {}, "receipts": [] })),
            Some(Some(record)),
            "a ladder transition admits the composite"
        );
        assert_eq!(
            domain_app_payload(&json!({ "domain_app_id": "dapp_1", "deleted": true })),
            Some(None),
            "a withdrawal is a tombstone, not a record"
        );
        assert_eq!(
            domain_app_payload(&json!({ "something": "else" })),
            None,
            "an unrecognised payload fails closed rather than defaulting"
        );
    }

    #[test]
    fn mount_gating_requires_approved_and_open_and_right_subject() {
        let dref = "domain-app://dapp_1";
        assert!(
            approval_admits(&json!({ "status": "approved", "subject_ref": dref }), dref).is_ok()
        );
        assert_eq!(
            approval_admits(&json!({ "status": "pending", "subject_ref": dref }), dref)
                .unwrap_err()
                .0,
            "mount_approval_not_approved"
        );
        assert_eq!(
            approval_admits(
                &json!({ "status": "approved", "subject_ref": "domain-app://other" }),
                dref
            )
            .unwrap_err()
            .0,
            "mount_control_wrong_subject"
        );
        assert!(release_admits(
            &json!({ "state": "open", "release_target_ref": dref }),
            dref
        )
        .is_ok());
        assert_eq!(
            release_admits(
                &json!({ "state": "closed", "release_target_ref": dref }),
                dref
            )
            .unwrap_err()
            .0,
            "mount_release_not_open"
        );
        assert_eq!(
            release_admits(
                &json!({ "state": "open", "release_target_ref": "domain-app://other" }),
                dref
            )
            .unwrap_err()
            .0,
            "mount_control_wrong_subject"
        );
    }

    #[test]
    fn serve_precheck_requires_mounted_not_already_serving() {
        assert!(serve_precheck(&json!({ "mounted": true, "serving": false })).is_ok());
        assert_eq!(
            serve_precheck(&json!({ "mounted": false, "serving": false }))
                .unwrap_err()
                .0,
            "domain_app_not_mounted"
        );
        assert_eq!(
            serve_precheck(&json!({ "mounted": true, "serving": true }))
                .unwrap_err()
                .0,
            "domain_app_already_serving"
        );
    }

    #[test]
    fn split_ref_and_prefixes() {
        assert_eq!(
            split_ref("surface-descriptor://sd_1"),
            Some(("surface-descriptor", "sd_1"))
        );
        assert_eq!(split_ref("odk://odk_1"), Some(("odk", "odk_1")));
        assert_eq!(split_ref("dapp_1"), None);
    }

    #[test]
    fn manifest_include_check() {
        let m = json!({ "surface_descriptor_refs": ["surface-descriptor://sd_1", "surface-descriptor://sd_2"] });
        assert!(manifest_includes_descriptor(
            &m,
            "surface-descriptor://sd_1"
        ));
        assert!(!manifest_includes_descriptor(
            &m,
            "surface-descriptor://sd_9"
        ));
        assert!(!manifest_includes_descriptor(
            &json!({}),
            "surface-descriptor://sd_1"
        ));
    }

    #[test]
    fn visibility_enum() {
        assert!(VISIBILITIES.contains(&"private"));
        assert!(VISIBILITIES.contains(&"marketplace_candidate"));
        assert!(!VISIBILITIES.contains(&"public"));
    }

    /// THE SNAPSHOT NOW HAS SOMEWHERE TO PUT WHAT THE DESCRIPTOR ACTUALLY BINDS.
    ///
    /// The two members v1 lacked entirely are the point: a v2 descriptor binding object models and
    /// policy-bound views used to contribute NOTHING, because the record had no field for either.
    #[test]
    fn derive_snapshot_covers_every_canonical_member_across_both_versions() {
        let v2_descriptor = json!({
            "schema_version": "ioi.ontology-surface-descriptor.v2",
            "ontology_refs": ["ontology://ont_1/revision/3"],
            "canonical_object_model_refs": ["object-model://om_1"],
            "data_recipe_refs": ["data-recipe://rec_1/revision/2"],
            "policy_bound_data_view_refs": ["view://vw_1"],
            "operator_contract_refs": ["contract://ct_1"],
            "mcp_contract_refs": ["mcp-profile://mcp_1"]
        });
        let d = derive_snapshot(&v2_descriptor, None, &json!({}));
        assert_eq!(d.ontology_refs, vec!["ontology://ont_1/revision/3"]);
        assert_eq!(d.canonical_object_model_refs, vec!["object-model://om_1"]);
        assert_eq!(d.data_recipe_refs, vec!["data-recipe://rec_1/revision/2"]);
        assert_eq!(d.policy_bound_data_view_refs, vec!["view://vw_1"]);
        assert_eq!(d.operator_contract_refs, vec!["contract://ct_1"]);
        assert_eq!(d.mcp_contract_refs, vec!["mcp-profile://mcp_1"]);

        // A stored v1 descriptor contributes what it HAS. Its object-model and policy-view members
        // are empty because its contract carries neither, which is a fact about the source rather
        // than a miss by this reader.
        let v1_descriptor = json!({
            "schema_version": "ioi.hypervisor.odk.surface-descriptor.v1",
            "ontology_ref": "ontology://ont_1",
            "recipe_refs": ["recipe://rec_1"]
        });
        let d = derive_snapshot(&v1_descriptor, None, &json!({}));
        assert_eq!(d.ontology_refs, vec!["ontology://ont_1"]);
        assert_eq!(d.data_recipe_refs, vec!["recipe://rec_1"]);
        assert!(d.canonical_object_model_refs.is_empty());
        assert!(d.policy_bound_data_view_refs.is_empty());
    }

    /// A v1 MANIFEST FOLDS OPERATOR AND MCP CONTRACTS INTO ONE LIST, AND THAT IS READ AS SUCH.
    #[test]
    fn derive_snapshot_reads_both_registered_manifest_versions() {
        let descriptor = json!({ "ontology_refs": ["ontology://ont_1"] });
        let v1_manifest = json!({
            "schema_version": "ioi.hypervisor.odk.manifest.v1",
            "ontology_refs": ["ontology://ont_2"],
            "recipe_refs": ["recipe://rec_1"],
            "mcp_operator_contracts": ["mcp-profile://mcp_1"]
        });
        let d = derive_snapshot(&descriptor, Some(&v1_manifest), &json!({}));
        assert_eq!(
            d.ontology_refs,
            vec!["ontology://ont_1", "ontology://ont_2"]
        );
        assert_eq!(d.data_recipe_refs, vec!["recipe://rec_1"]);
        assert_eq!(d.mcp_contract_refs, vec!["mcp-profile://mcp_1"]);

        let v2_manifest = json!({
            "schema_version": "ioi.ontology-development-kit-manifest.v2",
            "data_recipe_refs": ["data-recipe://rec_2/revision/1"],
            "operator_contract_refs": ["contract://ct_2"],
            "mcp_contract_refs": ["mcp-profile://mcp_2"]
        });
        let d = derive_snapshot(&descriptor, Some(&v2_manifest), &json!({}));
        assert_eq!(d.data_recipe_refs, vec!["data-recipe://rec_2/revision/1"]);
        assert_eq!(d.operator_contract_refs, vec!["contract://ct_2"]);
        assert_eq!(d.mcp_contract_refs, vec!["mcp-profile://mcp_2"]);
    }

    #[test]
    fn required_persistence_refuses_success_when_record_directory_is_unwritable() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(KIND_DAPP), b"not-a-directory").unwrap();
        let error = persist_required(
            dir.path().to_str().unwrap(),
            KIND_DAPP,
            "dapp_failure",
            &json!({"domain_app_id":"dapp_failure"}),
            "domain_app_persistence_failed",
        )
        .unwrap_err();
        assert_eq!(error.0, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            error.1 .0["error"]["code"],
            json!("domain_app_persistence_failed")
        );
    }
}
