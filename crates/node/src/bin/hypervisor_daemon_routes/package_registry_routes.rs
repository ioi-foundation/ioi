//! Daemon-owned local package registry for the ODK Domain App ladder.
//!
//! This is intentionally a narrow, truthful packet:
//! * an authenticated organization packages one exact DomainApp + ODK manifest +
//!   domain-app surface-descriptor snapshot as a package candidate;
//! * Packages admits an immutable, content-addressed
//!   `HypervisorSurfaceReleaseRecord` for that candidate;
//! * an organization installs that exact release as a disabled
//!   `HypervisorSurfaceInstallationBinding`, which may later be uninstalled; and
//! * the organization may RECALL an admitted release — the one legal disposition
//!   transition (`active` → `recalled`), appended as an immutable successor
//!   revision on the release stream under exact-head CAS.  Recall mutates no
//!   binding: every installation read derives its eligibility facts from the
//!   CURRENT admitted release head (see `render_installation`), and the
//!   product-surface projection consumes this namespace live (see
//!   `launcher_registry_application_entries`), so a recalled surface loses its
//!   launcher entry on the next read and after every restart, by construction.
//!
//! Every mutation crosses the shared owner-scoped Agentgres admission boundary.
//! The registry does NOT create a `HypervisorApplicationSurfaceRegistration`,
//! System interface, serving binding, process, route, or launch eligibility.  In
//! particular, an installed record returned here remains disabled until the
//! Applications owner admits the missing `extension_application` registration.

use std::collections::BTreeSet;
use std::sync::Arc;

use agentgres::event_stream::AdmissionRefusal;
use agentgres::mux::ExactProjection;
use axum::extract::{Path as AxumPath, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::DaemonState;

const NAMESPACE: &str = "hypervisor-package-registry";
const PACKAGE_SCOPE_KIND: &str = "hypervisor-package-candidate";
const RELEASE_SCOPE_KIND: &str = "hypervisor-surface-release";
const INSTALLATION_SCOPE_KIND: &str = "hypervisor-surface-installation";

const PACKAGE_CANDIDATE_SCHEMA: &str = "ioi.hypervisor.package_candidate.v1";
const RELEASE_ADMISSION_SCHEMA: &str = "ioi.hypervisor.package_release_admission.v1";
const INSTALLATION_ADMISSION_SCHEMA: &str = "ioi.hypervisor.package_installation_admission.v1";
const RELEASE_SCHEMA: &str = "ioi.hypervisor.surface_release_record.v1";
const INSTALLATION_SCHEMA: &str = "ioi.hypervisor.surface_installation_binding.v1";
const RELEASE_CONTRACT_ID: &str = "schema://ioi/components/hypervisor/surface-release-record/v1";
const INSTALLATION_CONTRACT_ID: &str =
    "schema://ioi/components/hypervisor/surface-installation-binding/v1";

type Reply = (StatusCode, Json<Value>);

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PackageCandidateRequest {
    package_id: String,
    owner_ref: String,
    domain_app_ref: String,
    idempotency_key: String,
    recorded_at_ms: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseRequest {
    expected_package_head: String,
    surface_distribution: String,
    surface_capability_depth: String,
    object_contract_refs: Vec<String>,
    action_contract_refs: Vec<String>,
    evidence_refs: Vec<String>,
    idempotency_key: String,
    recorded_at_ms: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct SurfaceReleaseRecord {
    schema_version: String,
    release_ref: String,
    surface_ref: String,
    package_ref: String,
    surface_distribution: String,
    surface_admission_state: String,
    surface_package_disposition: String,
    surface_capability_depth: String,
    object_contract_refs: Vec<String>,
    action_contract_refs: Vec<String>,
    evidence_refs: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InstallationRequest {
    installation_id: String,
    expected_release_head: String,
    project_ref: Option<String>,
    visibility: String,
    allowed_object_contract_refs: Vec<String>,
    allowed_action_refs: Vec<String>,
    idempotency_key: String,
    recorded_at_ms: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UninstallRequest {
    expected_installation_head: String,
    idempotency_key: String,
    recorded_at_ms: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecallRequest {
    expected_release_head: String,
    reason: String,
    idempotency_key: String,
    recorded_at_ms: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct SurfaceInstallationBinding {
    schema_version: String,
    installation_ref: String,
    surface_ref: String,
    release_ref: String,
    org_ref: String,
    project_ref: Option<String>,
    surface_installation_state: String,
    surface_enablement_state: String,
    visibility: String,
    allowed_object_contract_refs: Vec<String>,
    allowed_action_refs: Vec<String>,
    revision: u64,
}

fn bad(status: StatusCode, code: &str, message: impl Into<String>) -> Reply {
    (
        status,
        Json(json!({
            "ok": false,
            "error": { "code": code, "message": message.into() }
        })),
    )
}

fn parse<T: DeserializeOwned>(body: Value, code: &str) -> Result<T, Reply> {
    serde_json::from_value(body).map_err(|error| {
        bad(
            StatusCode::BAD_REQUEST,
            code,
            format!("request does not satisfy the closed contract: {error}"),
        )
    })
}

fn scope_refusal(error: super::substrate_store::RequestScopeRefusal) -> Reply {
    let status = match error {
        super::substrate_store::RequestScopeRefusal::AuthenticationRequired
        | super::substrate_store::RequestScopeRefusal::PrincipalIdentityInvalid => {
            StatusCode::UNAUTHORIZED
        }
        super::substrate_store::RequestScopeRefusal::TenantAuthorityRequired
        | super::substrate_store::RequestScopeRefusal::ResourceScopeRequired
        | super::substrate_store::RequestScopeRefusal::ResourceOwnerMismatch => {
            StatusCode::FORBIDDEN
        }
        super::substrate_store::RequestScopeRefusal::SubstrateUnavailable(_) => {
            StatusCode::SERVICE_UNAVAILABLE
        }
    };
    bad(status, error.code(), error.message())
}

fn admission_refusal(error: AdmissionRefusal) -> Reply {
    let status = match error {
        AdmissionRefusal::HeadConflict | AdmissionRefusal::SameKeyDifferentBytes { .. } => {
            StatusCode::CONFLICT
        }
        AdmissionRefusal::CoordinatesNotCanonical(_) => StatusCode::BAD_REQUEST,
        AdmissionRefusal::CapabilityAbsent => StatusCode::SERVICE_UNAVAILABLE,
        AdmissionRefusal::DurabilityUnconfirmed(_)
        | AdmissionRefusal::ProjectionDisagreesWithAck
        | AdmissionRefusal::SubstrateUnavailable(_) => StatusCode::BAD_GATEWAY,
    };
    bad(status, error.code(), error.to_string())
}

fn mutation_refusal(error: super::mutation_event_foundation::MutationRefusal) -> Reply {
    use super::mutation_event_foundation::MutationRefusal;
    match error {
        MutationRefusal::Scope(error) => scope_refusal(error),
        MutationRefusal::Admission(error) => admission_refusal(error),
        error @ (MutationRefusal::IdempotencyKeyInvalid
        | MutationRefusal::GenesisExpectedHeadPresent
        | MutationRefusal::SuccessorExpectedHeadRequired) => {
            bad(StatusCode::BAD_REQUEST, error.code(), error.message())
        }
        error @ MutationRefusal::RequestFingerprintFailed(_) => bad(
            StatusCode::INTERNAL_SERVER_ERROR,
            error.code(),
            error.message(),
        ),
    }
}

fn request_identity(
    data_dir: &str,
    headers: &HeaderMap,
) -> Result<super::substrate_store::RequestIdentity, Reply> {
    super::substrate_store::resolve_request_identity(data_dir, headers).map_err(scope_refusal)
}

fn bind_scope(
    data_dir: &str,
    identity: &super::substrate_store::RequestIdentity,
    resource_kind: &str,
    resource_ref: &str,
    owner_ref: &str,
    idempotency_key: &str,
) -> Result<super::substrate_store::RequestResourceScope, Reply> {
    super::substrate_store::bind_request_resource_scope(
        data_dir,
        identity,
        resource_kind,
        resource_ref,
        owner_ref,
        owner_ref,
        idempotency_key,
    )
    .map_err(scope_refusal)
}

fn authorize_scope(
    data_dir: &str,
    identity: &super::substrate_store::RequestIdentity,
    resource_kind: &str,
    resource_ref: &str,
    owner_ref: Option<&str>,
) -> Result<super::substrate_store::RequestResourceScope, Reply> {
    super::substrate_store::authorize_request_resource_scope(
        data_dir,
        identity,
        resource_kind,
        resource_ref,
        owner_ref,
    )
    .map_err(scope_refusal)
}

fn authorized_refs(
    data_dir: &str,
    identity: &super::substrate_store::RequestIdentity,
    resource_kind: &str,
) -> Result<BTreeSet<String>, Reply> {
    super::substrate_store::authorized_request_resource_refs(data_dir, identity, resource_kind)
        .map_err(scope_refusal)
}

fn digest(value: &Value) -> Result<String, Reply> {
    serde_jcs::to_vec(value)
        .map(|bytes| format!("sha256:{:x}", Sha256::digest(bytes)))
        .map_err(|error| {
            bad(
                StatusCode::INTERNAL_SERVER_ERROR,
                "package_canonicalization_failed",
                error.to_string(),
            )
        })
}

fn validate_canonical_contract(contract_id: &str, value: &Value, code: &str) -> Result<(), Reply> {
    ioi_types::app::generated::architecture_contracts::validate_architecture_contract(
        contract_id,
        value,
    )
    .map_err(|error| {
        bad(
            StatusCode::INTERNAL_SERVER_ERROR,
            code,
            format!("daemon-built canonical record failed its registered contract: {error}"),
        )
    })
}

fn hash_tail(prefix: &str, identity: &str) -> String {
    format!("{prefix}.{:x}", Sha256::digest(identity.as_bytes()))
}

fn package_ref(package_id: &str) -> String {
    format!("package://{package_id}")
}

fn surface_ref(package_id: &str) -> String {
    format!("surface://extensions/{package_id}")
}

fn release_ref(package_id: &str, release_digest: &str) -> String {
    format!("{}/release/{release_digest}", package_ref(package_id))
}

fn installation_ref(package_id: &str, installation_id: &str) -> String {
    format!("install://{package_id}/{installation_id}")
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"-_.".contains(&byte)
        })
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
}

fn valid_hash(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|tail| {
        tail.len() == 64
            && tail
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    })
}

fn valid_ref(value: &str, prefix: &str) -> bool {
    value.starts_with(prefix)
        && value.len() > prefix.len()
        && value.len() <= 500
        && !value.chars().any(char::is_whitespace)
}

fn valid_idempotency_key(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
}

fn valid_recall_reason(value: &str) -> bool {
    let trimmed = value.trim();
    !trimmed.is_empty() && trimmed.len() <= 500 && !trimmed.chars().any(char::is_control)
}

fn unique_nonempty(values: &[String]) -> bool {
    values.iter().all(|value| !value.trim().is_empty())
        && values.iter().collect::<BTreeSet<_>>().len() == values.len()
}

fn validate_package_request(request: &PackageCandidateRequest) -> Result<(), Reply> {
    if !valid_id(&request.package_id) {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "package_id_invalid",
            "package_id must be a globally unique lowercase package coordinate",
        ));
    }
    if !valid_ref(&request.owner_ref, "org://") {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "package_owner_ref_invalid",
            "owner_ref must be one canonical org:// reference",
        ));
    }
    if !valid_ref(&request.domain_app_ref, "domain-app://") {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "package_domain_app_ref_invalid",
            "domain_app_ref must be one canonical domain-app:// reference",
        ));
    }
    if !valid_idempotency_key(&request.idempotency_key) {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "package_idempotency_key_invalid",
            "idempotency_key is required, bounded, and contains no control characters",
        ));
    }
    Ok(())
}

// `record_by_ref` used to live here: a record-directory sweep that found a source by matching a
// top-level field. Every one of its callers now resolves through an owner seam instead, so it is
// removed rather than left available — a helper whose whole purpose is to make a rebuildable
// projection load-bearing is the next accident waiting for the next consumer.

struct PackageSource {
    domain_app: Value,
    manifest: Value,
    descriptor: Value,
    /// The descriptor's OWN committed hash when it is a v2, so the package freezes the commitment
    /// its owner published rather than one this module derives.
    descriptor_content_hash: Option<String>,
    /// Which registered contract the frozen descriptor was admitted under, recorded verbatim.
    descriptor_schema_version: String,
    /// Which registered contract the DomainApp was admitted under, and the exact head it was read
    /// at. A candidate that froze an app without saying which chain position it read cannot be
    /// checked later against the app it claims to package.
    domain_app_schema_version: String,
    domain_app_admitted_head: String,
    /// The same two facts for the ODK manifest, resolved through its own owner seam.
    manifest_schema_version: String,
    manifest_admitted_head: String,
    manifest_content_hash: String,
}

/// The DomainApp's canonical identity, at whichever registered contract it was admitted under.
///
/// v1 carried identity twice — a bare `domain_app_id` and a scheme-prefixed `domain_app_ref` that
/// could disagree — and v2 carries it once, as `domain_app_id`. Reading both HERE, at the one place
/// that has already resolved the record's version through its owner seam, is what keeps the version
/// difference from leaking into every consumer as a guess about which key exists.
fn domain_app_identity(record: &Value, schema_version: &str) -> Option<String> {
    match schema_version {
        "ioi.domain-app.v2" => record
            .get("domain_app_id")
            .and_then(Value::as_str)
            .map(str::to_string),
        "ioi.hypervisor.domain-app.v1" => record
            .get("domain_app_ref")
            .and_then(Value::as_str)
            .map(str::to_string),
        _ => None,
    }
}

/// M05.5 — THE PACKAGE SOURCE RESOLVES THROUGH THE DESCRIPTOR'S OWNER, NOT THE RECORD DIRECTORY.
///
/// This looked the descriptor up with `record_by_ref(.., "ref", ..)`, and a v2 descriptor HAS NO
/// `ref` FIELD — its identity is `surface_descriptor_id`, and its row is a projection envelope
/// rather than the record. So every v2 descriptor was unresolvable here: a DomainApp built on a
/// correctly-bound, invariant-11-conformant descriptor could not be packaged at all, and the refusal
/// said the ref "does not resolve", which is exactly what a caller would read as "you have not
/// created it yet". The whole point of the descriptor unit is that a surface becomes durable product
/// inventory only after it carries the binding set; the packaging lane, which is where inventory
/// becomes durable, was the one consumer that could not see it.
///
/// It also skipped authorization: a record-directory scan answers for every owner, so the package
/// froze another tenant's descriptor bytes into a candidate the caller owns. The owner reader
/// applies the descriptor family's own scope and projects the admitted chain, so a deleted or
/// corrupted row can neither hide a descriptor from packaging nor change what gets frozen.
fn resolve_package_source(
    data_dir: &str,
    identity: &super::substrate_store::RequestIdentity,
    owner_ref: &str,
    domain_app_ref: &str,
) -> Result<PackageSource, Reply> {
    // M05.6 — THE DOMAIN APP RESOLVES THROUGH ITS OWNER SEAM, NOT THE RECORD DIRECTORY.
    //
    // This swept `domain-apps` for a top-level `domain_app_ref`, which the v1 row happened to
    // satisfy because a v1 row WAS the record. Once the registered v2 record moved inside a
    // projection envelope, the sweep found nothing and a correctly-authored DomainApp became
    // unpackageable — and the refusal read as "you have not created it yet". Restoring the key at
    // the row's top level would have fixed the symptom by making package admission depend on a
    // rebuildable index again: delete the row and the app is unpackageable; corrupt it and the
    // package freezes whatever the corruption said. The owner seam projects the admitted chain under
    // that family's own scope, so neither deleting nor corrupting the row can change this decision.
    let resolved_app = super::domain_apps_routes::resolve_admitted_domain_app(
        data_dir,
        identity,
        domain_app_ref,
    )
    .map_err(|(_, Json(payload))| {
        bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            "package_domain_app_unresolved",
            format!(
                "domain_app_ref does not resolve to an admitted DomainApp this caller may package: {}",
                payload
                    .pointer("/error/message")
                    .and_then(Value::as_str)
                    .unwrap_or("refused by its owner")
            ),
        )
    })?;
    if resolved_app.withdrawn {
        return Err(bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            "package_domain_app_withdrawn",
            "the DomainApp was withdrawn; a withdrawal is terminal for the record and a withdrawn app does not become durable product inventory",
        ));
    }
    let domain_app_schema_version = resolved_app.schema_version.clone();
    let domain_app = resolved_app.record;
    // The identity the chain holds must be the identity the request named. Resolving by ref and then
    // freezing a record that calls itself something else is how a candidate ends up packaging one app
    // under another's coordinates.
    if domain_app_identity(&domain_app, &domain_app_schema_version).as_deref()
        != Some(domain_app_ref)
    {
        return Err(bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            "package_domain_app_identity_mismatch",
            "the admitted DomainApp does not carry the identity this request named",
        ));
    }
    if domain_app.get("status").and_then(Value::as_str) != Some("draft") {
        return Err(bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            "package_domain_app_state_invalid",
            "the ODK packaging lane accepts an exact draft DomainApp candidate",
        ));
    }
    if domain_app.get("owner_ref").and_then(Value::as_str) != Some(owner_ref) {
        return Err(bad(
            StatusCode::FORBIDDEN,
            "package_domain_app_owner_mismatch",
            "the DomainApp must carry the exact authenticated package owner_ref",
        ));
    }
    let manifest_ref = domain_app
        .get("odk_manifest_ref")
        .and_then(Value::as_str)
        .filter(|value| valid_ref(value, "odk://"))
        .ok_or_else(|| {
            bad(
                StatusCode::UNPROCESSABLE_ENTITY,
                "package_odk_manifest_required",
                "the DomainApp must bind one resolving odk_manifest_ref before packaging",
            )
        })?;
    let descriptor_ref = domain_app
        .get("surface_descriptor_ref")
        .and_then(Value::as_str)
        .filter(|value| valid_ref(value, "surface-descriptor://"))
        .ok_or_else(|| {
            bad(
                StatusCode::UNPROCESSABLE_ENTITY,
                "package_surface_descriptor_required",
                "the DomainApp must bind one resolving surface_descriptor_ref before packaging",
            )
        })?;
    // THE MANIFEST RESOLVES THROUGH ITS OWNER SEAM TOO, for exactly the same reason. It was found by
    // sweeping the record directory for a top-level `ref`, so a deleted row made a bound manifest
    // unresolvable and a corrupted one was frozen verbatim into a candidate — and the sweep answered
    // for every owner, so a package could freeze another tenant's manifest into a candidate this
    // caller owns.
    let resolved_manifest =
        super::odk_routes::resolve_admitted_odk_manifest(data_dir, identity, manifest_ref)
            .map_err(|(_, Json(payload))| {
                bad(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "package_odk_manifest_unresolved",
                    format!(
                        "the DomainApp's odk_manifest_ref does not resolve to an admitted manifest this caller may package: {}",
                        payload
                            .pointer("/error/message")
                            .and_then(Value::as_str)
                            .unwrap_or("refused by its owner")
                    ),
                )
            })?;
    let manifest_schema_version = resolved_manifest.schema_version.clone();
    let manifest_admitted_head = resolved_manifest.admitted_head.clone();
    let manifest_content_hash = resolved_manifest.content_hash.clone();
    let manifest = resolved_manifest.record;
    let resolved = super::odk_routes::resolve_admitted_surface_descriptor(
        data_dir,
        identity,
        descriptor_ref,
    )
    .map_err(|(_, Json(payload))| {
        bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            "package_surface_descriptor_unresolved",
            format!(
                "the DomainApp's surface_descriptor_ref does not resolve to an admitted descriptor this caller may package: {}",
                payload
                    .pointer("/error/message")
                    .and_then(Value::as_str)
                    .unwrap_or("refused by its owner")
            ),
        )
    })?;
    if resolved.composition_pattern != "domain_app" {
        return Err(bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            "package_surface_descriptor_pattern_mismatch",
            "the package source descriptor must declare composition_pattern domain_app",
        ));
    }
    // A WITHDRAWN DESCRIPTOR IS NOT PRODUCT INVENTORY. The row sweep this replaces could not see the
    // status at all, so a revoked descriptor packaged exactly like a live one.
    if matches!(resolved.status.as_str(), "revoked" | "deleted") {
        return Err(bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            "package_surface_descriptor_withdrawn",
            "the package source descriptor is withdrawn; a withdrawal is a governed state of the descriptor and a withdrawn surface does not become durable product inventory",
        ));
    }
    // A DESCRIPTOR IS PACKAGED UNDER A CONTRACT THIS BUILD KNOWS. v1 is explicitly readable here —
    // that is the whole compatibility surface, and it is stated rather than implied — and anything
    // else fails closed instead of being frozen under a contract it was never admitted under.
    let descriptor_schema_version = resolved.schema_version.clone();
    let descriptor_content_hash = match descriptor_schema_version.as_str() {
        "ioi.ontology-surface-descriptor.v2" => Some(
            resolved
                .record
                .get("content_hash")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    bad(
                        StatusCode::BAD_GATEWAY,
                        "package_surface_descriptor_commitment_absent",
                        "the admitted v2 descriptor carries no content_hash; a package freezes the owner's own commitment, never one this module invents",
                    )
                })?
                .to_string(),
        ),
        // A stored v1 carries no self-commitment, so there is none to freeze and the candidate says
        // so with an explicit null rather than a hash that would look like the owner's.
        "ioi.hypervisor.odk.surface-descriptor.v1" => None,
        unknown => {
            return Err(bad(
                StatusCode::UNPROCESSABLE_ENTITY,
                "package_surface_descriptor_version_unsupported",
                format!(
                    "the package source descriptor was admitted as '{unknown}', which this lane neither packages nor downgrades"
                ),
            ))
        }
    };
    let descriptor = resolved.record;
    let manifest_includes_descriptor = manifest
        .get("surface_descriptor_refs")
        .and_then(Value::as_array)
        .is_some_and(|refs| {
            refs.iter()
                .any(|value| value.as_str() == Some(descriptor_ref))
        });
    if !manifest_includes_descriptor {
        return Err(bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            "package_manifest_descriptor_mismatch",
            "the ODK manifest does not include the DomainApp surface descriptor",
        ));
    }
    Ok(PackageSource {
        domain_app,
        manifest,
        descriptor,
        descriptor_content_hash,
        descriptor_schema_version,
        domain_app_schema_version,
        domain_app_admitted_head: resolved_app.admitted_head,
        manifest_schema_version,
        manifest_admitted_head,
        manifest_content_hash,
    })
}

/// One descriptor's canonical identity, whichever registered contract admitted it.
///
/// A v2 names itself `surface_descriptor_id`; a stored v1 named itself `ref`. Reading only `ref`
/// froze `null` into the candidate for every v2 — and `null` is what a package would then present as
/// the exact descriptor it snapshotted.
fn descriptor_identity(descriptor: &Value) -> Value {
    descriptor
        .get("surface_descriptor_id")
        .or_else(|| descriptor.get("ref"))
        .cloned()
        .unwrap_or(Value::Null)
}

/// One manifest's canonical identity, whichever registered contract admitted it.
///
/// The same shape as the descriptor's, and for the same reason: a v2 manifest names itself
/// `odk_manifest_id`, a stored v1 named itself `ref`, and reading only `ref` would freeze `null`
/// into every candidate built over a successor.
fn manifest_identity(manifest: &Value) -> Value {
    manifest
        .get("odk_manifest_id")
        .or_else(|| manifest.get("ref"))
        .cloned()
        .unwrap_or(Value::Null)
}

fn build_package_candidate(
    request: &PackageCandidateRequest,
    source: &PackageSource,
) -> Result<Value, Reply> {
    let domain_app_hash = digest(&source.domain_app)?;
    // THE MANIFEST OWNER'S COMMITMENT, resolved through that family's own seam, exactly as the
    // descriptor's is. A v2 manifest publishes a `content_hash` its registered invariant commits; a
    // stored v1 has none, so the seam derives one under the v1 contract's own material list and the
    // candidate records which kind it holds.
    let manifest_hash = json!(source.manifest_content_hash);
    // THE OWNER'S COMMITMENT, NOT A SECOND ONE. A v2 descriptor carries a content hash its own
    // registered invariant commits and any relying party can recompute from the bytes; re-digesting
    // the record here would mint a NUMBER BESIDE IT that agrees with nothing and that no reader
    // could check against the descriptor family. A stored v1 has no self-commitment, so this module
    // derives one and the candidate labels it as derived rather than as the owner's.
    let (descriptor_hash, descriptor_hash_source) = match &source.descriptor_content_hash {
        Some(committed) => (json!(committed), "descriptor_owner_committed"),
        None => (
            json!(digest(&source.descriptor)?),
            "derived_by_package_registry",
        ),
    };
    let descriptor_ref = descriptor_identity(&source.descriptor);
    let package_ref = package_ref(&request.package_id);
    let surface_ref = surface_ref(&request.package_id);
    let material = json!({
        "package_ref": package_ref,
        "owner_ref": request.owner_ref,
        "domain_app_ref": request.domain_app_ref,
        "odk_manifest_ref": manifest_identity(&source.manifest),
        "surface_descriptor_ref": descriptor_ref,
        "surface_descriptor_schema_version": source.descriptor_schema_version,
        "surface_ref": surface_ref,
        "surface_class": "extension_application",
        "domain_app_content_hash": domain_app_hash,
        "odk_manifest_content_hash": manifest_hash,
        "surface_descriptor_content_hash": descriptor_hash,
        "surface_descriptor_content_hash_source": descriptor_hash_source,
        // THE EXACT CHAIN POSITIONS THIS CANDIDATE WAS BUILT FROM. A frozen hash says WHAT was read;
        // the head says WHERE in that owner's admitted history it was read. Without it a candidate
        // can be checked for self-consistency but never located against the app and manifest it
        // claims to package, which is the difference between a snapshot and a citation.
        "domain_app_schema_version": source.domain_app_schema_version,
        "domain_app_admitted_head": source.domain_app_admitted_head,
        "odk_manifest_schema_version": source.manifest_schema_version,
        "odk_manifest_admitted_head": source.manifest_admitted_head,
    });
    let candidate_content_hash = digest(&material)?;
    Ok(json!({
        "schema_version": PACKAGE_CANDIDATE_SCHEMA,
        "package_candidate_ref": format!("package-candidate://{}/{}", request.package_id, candidate_content_hash),
        "package_ref": package_ref,
        "package_id": request.package_id,
        "owner_ref": request.owner_ref,
        "domain_app_ref": request.domain_app_ref,
        "odk_manifest_ref": manifest_identity(&source.manifest),
        "surface_descriptor_ref": descriptor_ref,
        "surface_ref": surface_ref,
        "surface_class": "extension_application",
        "source_snapshots": {
            "domain_app_content_hash": domain_app_hash,
            "odk_manifest_content_hash": manifest_hash,
            "surface_descriptor_content_hash": descriptor_hash,
            // WHOSE NUMBER THIS IS, said in the record. A commitment the descriptor owner published
            // and one this lane derived are different kinds of fact, and a reader that cannot tell
            // them apart would verify the second against the first and conclude nothing.
            "surface_descriptor_content_hash_source": descriptor_hash_source,
            "surface_descriptor_schema_version": source.descriptor_schema_version,
            // Both other sources say which contract admitted them and at which exact head, so the
            // whole snapshot set is locatable in three owners' chains rather than only checkable
            // against itself.
            "domain_app_schema_version": source.domain_app_schema_version,
            "domain_app_admitted_head": source.domain_app_admitted_head,
            "odk_manifest_schema_version": source.manifest_schema_version,
            "odk_manifest_admitted_head": source.manifest_admitted_head,
        },
        "candidate_content_hash": candidate_content_hash,
        "status": "candidate",
        "registration_state": "absent",
        "nonclaim": "This package candidate does not create an extension_application registration, installation, System binding, serving binding, route, process, or launch eligibility."
    }))
}

fn stream_head(data_dir: &str, tail: &str, not_found_code: &str) -> Result<ExactProjection, Reply> {
    super::substrate_store::read_event_stream_operation(data_dir, NAMESPACE, tail)
        .map_err(admission_refusal)?
        .ok_or_else(|| {
            bad(
                StatusCode::NOT_FOUND,
                not_found_code,
                "the requested admitted package registry object does not exist",
            )
        })
}

fn stream_history(data_dir: &str, tail: &str) -> Result<Vec<ExactProjection>, Reply> {
    super::substrate_store::read_event_stream_history(data_dir, NAMESPACE, tail)
        .map_err(admission_refusal)
}

fn receipt_ref(exact: &ExactProjection) -> String {
    let coordinates = exact
        .operation
        .object_ref
        .strip_prefix("agentgres://event-stream-operations/")
        .and_then(|suffix| suffix.split_once('/'));
    let owner = coordinates.map(|(owner, _)| owner).unwrap_or(NAMESPACE);
    let tail = coordinates.map(|(_, tail)| tail).unwrap_or("unknown");
    agentgres::refs::event_stream_receipt_ref(
        owner,
        tail,
        exact.admission_batch_seq,
        &exact.admission_root,
    )
}

fn agentgres_metadata(exact: &ExactProjection, replayed: Option<bool>) -> Value {
    let coordinates = exact
        .operation
        .object_ref
        .strip_prefix("agentgres://event-stream-operations/")
        .and_then(|suffix| suffix.split_once('/'));
    let owner = coordinates.map(|(owner, _)| owner).unwrap_or(NAMESPACE);
    let tail = coordinates.map(|(_, tail)| tail).unwrap_or("unknown");
    json!({
        "operation_ref": agentgres::refs::event_stream_operation_ref(owner, tail, exact.seq, &exact.head),
        "receipt_ref": receipt_ref(exact),
        "sequence": exact.seq,
        "head": exact.head,
        "admission_batch_sequence": exact.admission_batch_seq,
        "admission_root": exact.admission_root,
        "terminal_root": exact.terminal_root,
        "recorded_at_ms": exact.operation.recorded_at_ms,
        "replayed": replayed,
    })
}

fn render_candidate(exact: &ExactProjection, replayed: Option<bool>) -> Value {
    json!({
        "record": exact.operation.payload,
        "agentgres": agentgres_metadata(exact, replayed),
    })
}

fn render_release(exact: &ExactProjection, replayed: Option<bool>) -> Value {
    json!({
        "record": exact.operation.payload["release"],
        "package_candidate_ref": exact.operation.payload["package_candidate_ref"],
        "package_candidate_head": exact.operation.payload["package_candidate_head"],
        "admission_decision_ref": exact.operation.payload["admission_decision_ref"],
        // Null on the genesis admission; the recall successor's bounded reason verbatim.
        "recall_reason": exact.operation.payload["recall_reason"],
        "registration_state": "absent",
        "agentgres": agentgres_metadata(exact, replayed),
    })
}

/// The recall cascade's read half: disposition + bounded reason from one exact
/// admitted release head.  Bindings are never mutated by a recall — every
/// installation read resolves the CURRENT release head in the same request, so
/// the derived facts are immediate and reconstruct identically after restart.
fn release_recall_facts(release: &ExactProjection) -> (String, Value) {
    let disposition = release.operation.payload["release"]["surface_package_disposition"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    (
        disposition,
        release.operation.payload["recall_reason"].clone(),
    )
}

/// Why this binding cannot launch, derived at read time from admitted truth:
/// its own terminal state, the current release disposition, and the structural
/// pair this packet never claims away (no registration, no serving binding).
fn derived_disabled_reason_codes(
    installation_state: &str,
    release_disposition: &str,
) -> Vec<&'static str> {
    let mut codes = Vec::new();
    if installation_state == "uninstalled" {
        codes.push("surface_installation_uninstalled");
    }
    if release_disposition == "recalled" {
        codes.push("surface_release_recalled");
    }
    codes.push("extension_application_registration_absent");
    codes.push("surface_serving_binding_absent");
    codes
}

fn render_installation(
    exact: &ExactProjection,
    replayed: Option<bool>,
    release: &ExactProjection,
) -> Value {
    let (release_disposition, recall_reason) = release_recall_facts(release);
    let installation_state = exact.operation.payload["installation"]["surface_installation_state"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    json!({
        "record": exact.operation.payload["installation"],
        "release_head": exact.operation.payload["release_head"],
        "registration_state": "absent",
        "launch_eligible": false,
        "release_disposition": release_disposition,
        "release_recall_reason": recall_reason,
        "disabled_reason_codes": derived_disabled_reason_codes(&installation_state, &release_disposition),
        "agentgres": agentgres_metadata(exact, replayed),
    })
}

fn admit(
    data_dir: &str,
    genesis: bool,
    identity: &super::substrate_store::RequestIdentity,
    scope: &super::substrate_store::RequestResourceScope,
    resource_kind: &str,
    resource_ref: &str,
    stream_tail: &str,
    op_kind: &str,
    expected_head: Option<&str>,
    payload: &Value,
    recorded_at_ms: u64,
    idempotency_key: &str,
) -> Result<super::mutation_event_foundation::MutationCommit, Reply> {
    super::mutation_event_foundation::admit_owner_scoped_mutation(
        data_dir,
        genesis,
        super::mutation_event_foundation::ScopedMutation {
            identity,
            scope,
            resource_kind,
            resource_ref,
            owner_namespace: NAMESPACE,
            stream_tail,
            op_kind,
            expected_head,
            payload,
            idempotency_key,
            recorded_at_ms,
        },
    )
    .map_err(mutation_refusal)
}

fn read_candidate_authorized(
    data_dir: &str,
    identity: &super::substrate_store::RequestIdentity,
    package_id: &str,
) -> Result<ExactProjection, Reply> {
    if !valid_id(package_id) {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "package_id_invalid",
            "package_id is not canonical",
        ));
    }
    let resource_ref = package_ref(package_id);
    authorize_scope(data_dir, identity, PACKAGE_SCOPE_KIND, &resource_ref, None)?;
    let exact = stream_head(
        data_dir,
        &hash_tail("package", &resource_ref),
        "package_candidate_not_found",
    )?;
    if exact.operation.payload["schema_version"] != PACKAGE_CANDIDATE_SCHEMA
        || exact.operation.payload["package_ref"] != resource_ref
    {
        return Err(bad(
            StatusCode::CONFLICT,
            "package_candidate_identity_collision",
            "the package coordinate contains different admitted bytes",
        ));
    }
    Ok(exact)
}

fn read_release_authorized(
    data_dir: &str,
    identity: &super::substrate_store::RequestIdentity,
    package_id: &str,
    release_digest: &str,
) -> Result<ExactProjection, Reply> {
    if !valid_id(package_id) || !valid_hash(release_digest) {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "package_release_coordinate_invalid",
            "package_id and release digest must be canonical",
        ));
    }
    let resource_ref = release_ref(package_id, release_digest);
    authorize_scope(data_dir, identity, RELEASE_SCOPE_KIND, &resource_ref, None)?;
    let exact = stream_head(
        data_dir,
        &hash_tail("release", &resource_ref),
        "package_release_not_found",
    )?;
    if exact.operation.payload["schema_version"] != RELEASE_ADMISSION_SCHEMA
        || exact.operation.payload["release"]["release_ref"] != resource_ref
    {
        return Err(bad(
            StatusCode::CONFLICT,
            "package_release_identity_collision",
            "the release coordinate contains different admitted bytes",
        ));
    }
    Ok(exact)
}

fn read_installation_authorized(
    data_dir: &str,
    identity: &super::substrate_store::RequestIdentity,
    package_id: &str,
    release_digest: &str,
    installation_id: &str,
) -> Result<ExactProjection, Reply> {
    if !valid_id(package_id) || !valid_hash(release_digest) || !valid_id(installation_id) {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "package_installation_coordinate_invalid",
            "package, release, and installation coordinates must be canonical",
        ));
    }
    let resource_ref = installation_ref(package_id, installation_id);
    authorize_scope(
        data_dir,
        identity,
        INSTALLATION_SCOPE_KIND,
        &resource_ref,
        None,
    )?;
    let exact = stream_head(
        data_dir,
        &hash_tail("installation", &resource_ref),
        "package_installation_not_found",
    )?;
    if exact.operation.payload["schema_version"] != INSTALLATION_ADMISSION_SCHEMA
        || exact.operation.payload["installation"]["installation_ref"] != resource_ref
        || exact.operation.payload["installation"]["release_ref"]
            != release_ref(package_id, release_digest)
    {
        return Err(bad(
            StatusCode::CONFLICT,
            "package_installation_identity_collision",
            "the installation coordinate contains different admitted bytes",
        ));
    }
    Ok(exact)
}

/// POST /v1/hypervisor/packages — freeze one ODK DomainApp source mesh as a
/// package candidate.  This is stage 5 only; it admits no release or app
/// registration.
pub(crate) async fn handle_package_create(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Reply {
    let identity = match request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(reply) => return reply,
    };
    let request: PackageCandidateRequest = match parse(body, "package_candidate_request_invalid") {
        Ok(request) => request,
        Err(reply) => return reply,
    };
    if let Err(reply) = validate_package_request(&request) {
        return reply;
    }
    // The AUTHENTICATED caller is carried into source resolution: the descriptor owner decides
    // whether this principal may see the record it is about to freeze into a package.
    let source = match resolve_package_source(
        &st.data_dir,
        &identity,
        &request.owner_ref,
        &request.domain_app_ref,
    ) {
        Ok(source) => source,
        Err(reply) => return reply,
    };
    let record = match build_package_candidate(&request, &source) {
        Ok(record) => record,
        Err(reply) => return reply,
    };
    let resource_ref = package_ref(&request.package_id);
    let scope = match bind_scope(
        &st.data_dir,
        &identity,
        PACKAGE_SCOPE_KIND,
        &resource_ref,
        &request.owner_ref,
        &request.idempotency_key,
    ) {
        Ok(scope) => scope,
        Err(reply) => return reply,
    };
    let tail = hash_tail("package", &resource_ref);
    match admit(
        &st.data_dir,
        true,
        &identity,
        &scope,
        PACKAGE_SCOPE_KIND,
        &resource_ref,
        &tail,
        "event_stream.hypervisor_package_candidate_admitted",
        None,
        &record,
        request.recorded_at_ms.unwrap_or_default(),
        &request.idempotency_key,
    ) {
        Ok(commit) => (
            StatusCode::CREATED,
            Json(json!({
                "ok": true,
                "package": render_candidate(&commit.projection, Some(commit.replayed))
            })),
        ),
        Err(reply) => reply,
    }
}

/// GET /v1/hypervisor/packages — authenticated owner-filtered package inventory.
pub(crate) async fn handle_package_list(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
) -> Reply {
    let identity = match request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(reply) => return reply,
    };
    let allowed = match authorized_refs(&st.data_dir, &identity, PACKAGE_SCOPE_KIND) {
        Ok(allowed) => allowed,
        Err(reply) => return reply,
    };
    let tails = match super::substrate_store::list_event_stream_tails(&st.data_dir, NAMESPACE) {
        Ok(tails) => tails,
        Err(error) => {
            return bad(
                StatusCode::SERVICE_UNAVAILABLE,
                "package_inventory_unavailable",
                error.to_string(),
            )
        }
    };
    let mut packages = Vec::new();
    for tail in tails
        .into_iter()
        .filter(|tail| tail.starts_with("package."))
    {
        let exact = match stream_head(&st.data_dir, &tail, "package_candidate_not_found") {
            Ok(exact) => exact,
            Err(reply) => return reply,
        };
        let resource_ref = exact.operation.payload["package_ref"]
            .as_str()
            .unwrap_or_default();
        if exact.operation.payload["schema_version"] == PACKAGE_CANDIDATE_SCHEMA
            && allowed.contains(resource_ref)
        {
            packages.push(render_candidate(&exact, None));
        }
    }
    packages.sort_by(|left, right| {
        left["record"]["package_ref"]
            .as_str()
            .cmp(&right["record"]["package_ref"].as_str())
    });
    (
        StatusCode::OK,
        Json(json!({ "ok": true, "packages": packages })),
    )
}

/// GET /v1/hypervisor/packages/:package_id — exact admitted candidate head.
pub(crate) async fn handle_package_get(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(package_id): AxumPath<String>,
) -> Reply {
    let identity = match request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(reply) => return reply,
    };
    match read_candidate_authorized(&st.data_dir, &identity, &package_id) {
        Ok(exact) => (
            StatusCode::OK,
            Json(json!({ "ok": true, "package": render_candidate(&exact, None) })),
        ),
        Err(reply) => reply,
    }
}

fn validate_release_request(request: &ReleaseRequest) -> Result<(), Reply> {
    if !valid_hash(&request.expected_package_head) {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "package_expected_head_invalid",
            "expected_package_head must be one canonical sha256 head",
        ));
    }
    if ![
        "bundled",
        "direct_package",
        "organization_catalog",
        "private_registry",
        "marketplace",
    ]
    .contains(&request.surface_distribution.as_str())
    {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "package_distribution_invalid",
            "surface_distribution is not canonical",
        ));
    }
    if !["browse", "inspect", "propose", "act", "workflow_complete"]
        .contains(&request.surface_capability_depth.as_str())
    {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "package_capability_depth_invalid",
            "surface_capability_depth is not canonical",
        ));
    }
    if !unique_nonempty(&request.object_contract_refs)
        || !unique_nonempty(&request.action_contract_refs)
        || !unique_nonempty(&request.evidence_refs)
    {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "package_release_refs_invalid",
            "release contract and evidence refs must be non-empty where present and unique",
        ));
    }
    if request.evidence_refs.iter().any(|reference| {
        !["artifact://", "evidence://", "receipt://"]
            .iter()
            .any(|prefix| valid_ref(reference, prefix))
    }) {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "package_release_evidence_ref_invalid",
            "evidence_refs accept only artifact://, evidence://, or receipt:// refs",
        ));
    }
    if !valid_idempotency_key(&request.idempotency_key) {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "package_idempotency_key_invalid",
            "idempotency_key is required, bounded, and contains no control characters",
        ));
    }
    Ok(())
}

fn build_release_admission(
    candidate: &ExactProjection,
    request: &ReleaseRequest,
) -> Result<(String, Value), Reply> {
    let candidate_record = &candidate.operation.payload;
    let mut evidence_refs = vec![receipt_ref(candidate)];
    for reference in &request.evidence_refs {
        if !evidence_refs.contains(reference) {
            evidence_refs.push(reference.clone());
        }
    }
    let material = json!({
        "package_candidate_ref": candidate_record["package_candidate_ref"],
        "package_candidate_head": candidate.head,
        "package_candidate_content_hash": candidate_record["candidate_content_hash"],
        "surface_ref": candidate_record["surface_ref"],
        "package_ref": candidate_record["package_ref"],
        "surface_distribution": request.surface_distribution,
        "surface_admission_state": "admitted",
        "surface_package_disposition": "active",
        "surface_capability_depth": request.surface_capability_depth,
        "object_contract_refs": request.object_contract_refs,
        "action_contract_refs": request.action_contract_refs,
        "evidence_refs": evidence_refs,
    });
    let release_digest = digest(&material)?;
    let release_ref = format!(
        "{}/release/{release_digest}",
        candidate_record["package_ref"].as_str().unwrap_or_default()
    );
    let release = SurfaceReleaseRecord {
        schema_version: RELEASE_SCHEMA.to_owned(),
        release_ref: release_ref.clone(),
        surface_ref: candidate_record["surface_ref"]
            .as_str()
            .unwrap_or_default()
            .to_owned(),
        package_ref: candidate_record["package_ref"]
            .as_str()
            .unwrap_or_default()
            .to_owned(),
        surface_distribution: request.surface_distribution.clone(),
        surface_admission_state: "admitted".into(),
        surface_package_disposition: "active".into(),
        surface_capability_depth: request.surface_capability_depth.clone(),
        object_contract_refs: request.object_contract_refs.clone(),
        action_contract_refs: request.action_contract_refs.clone(),
        evidence_refs,
    };
    let release_value = serde_json::to_value(release).map_err(|error| {
        bad(
            StatusCode::INTERNAL_SERVER_ERROR,
            "package_release_encoding_failed",
            error.to_string(),
        )
    })?;
    validate_canonical_contract(
        RELEASE_CONTRACT_ID,
        &release_value,
        "package_release_contract_failed",
    )?;
    Ok((
        release_ref,
        json!({
            "schema_version": RELEASE_ADMISSION_SCHEMA,
            "release": release_value,
            "owner_ref": candidate_record["owner_ref"],
            "package_candidate_ref": candidate_record["package_candidate_ref"],
            "package_candidate_head": candidate.head,
            "package_candidate_content_hash": candidate_record["candidate_content_hash"],
            "admission_decision_ref": format!("decision://hypervisor/packages/{release_digest}"),
            "registration_state": "absent",
            "nonclaim": "Local release admission does not register, install, expose, mount, serve, or authorize this extension application."
        }),
    ))
}

/// POST /v1/hypervisor/packages/:package_id/releases — admit one immutable,
/// content-addressed canonical surface release against the exact candidate head.
pub(crate) async fn handle_release_create(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(package_id): AxumPath<String>,
    Json(body): Json<Value>,
) -> Reply {
    let identity = match request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(reply) => return reply,
    };
    let request: ReleaseRequest = match parse(body, "package_release_request_invalid") {
        Ok(request) => request,
        Err(reply) => return reply,
    };
    if let Err(reply) = validate_release_request(&request) {
        return reply;
    }
    let candidate = match read_candidate_authorized(&st.data_dir, &identity, &package_id) {
        Ok(candidate) => candidate,
        Err(reply) => return reply,
    };
    if request.expected_package_head != candidate.head {
        return bad(
            StatusCode::CONFLICT,
            "package_expected_head_conflict",
            "expected_package_head is not the current admitted package candidate head",
        );
    }
    let (resource_ref, admission) = match build_release_admission(&candidate, &request) {
        Ok(value) => value,
        Err(reply) => return reply,
    };
    let owner_ref = candidate.operation.payload["owner_ref"]
        .as_str()
        .unwrap_or_default();
    let scope = match bind_scope(
        &st.data_dir,
        &identity,
        RELEASE_SCOPE_KIND,
        &resource_ref,
        owner_ref,
        &request.idempotency_key,
    ) {
        Ok(scope) => scope,
        Err(reply) => return reply,
    };
    let tail = hash_tail("release", &resource_ref);
    match admit(
        &st.data_dir,
        true,
        &identity,
        &scope,
        RELEASE_SCOPE_KIND,
        &resource_ref,
        &tail,
        "event_stream.hypervisor_package_release_admitted",
        None,
        &admission,
        request.recorded_at_ms.unwrap_or_default(),
        &request.idempotency_key,
    ) {
        Ok(commit) => (
            StatusCode::CREATED,
            Json(json!({
                "ok": true,
                "release": render_release(&commit.projection, Some(commit.replayed))
            })),
        ),
        Err(reply) => reply,
    }
}

/// GET /v1/hypervisor/packages/:package_id/releases — owner-filtered immutable releases.
pub(crate) async fn handle_release_list(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(package_id): AxumPath<String>,
) -> Reply {
    let identity = match request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(reply) => return reply,
    };
    if let Err(reply) = read_candidate_authorized(&st.data_dir, &identity, &package_id) {
        return reply;
    }
    let allowed = match authorized_refs(&st.data_dir, &identity, RELEASE_SCOPE_KIND) {
        Ok(allowed) => allowed,
        Err(reply) => return reply,
    };
    let package_ref = package_ref(&package_id);
    let tails = match super::substrate_store::list_event_stream_tails(&st.data_dir, NAMESPACE) {
        Ok(tails) => tails,
        Err(error) => {
            return bad(
                StatusCode::SERVICE_UNAVAILABLE,
                "package_release_inventory_unavailable",
                error.to_string(),
            )
        }
    };
    let mut releases = Vec::new();
    for tail in tails
        .into_iter()
        .filter(|tail| tail.starts_with("release."))
    {
        let exact = match stream_head(&st.data_dir, &tail, "package_release_not_found") {
            Ok(exact) => exact,
            Err(reply) => return reply,
        };
        let record = &exact.operation.payload["release"];
        let resource_ref = record["release_ref"].as_str().unwrap_or_default();
        if exact.operation.payload["schema_version"] == RELEASE_ADMISSION_SCHEMA
            && record["package_ref"] == package_ref
            && allowed.contains(resource_ref)
        {
            releases.push(render_release(&exact, None));
        }
    }
    releases.sort_by(|left, right| {
        left["record"]["release_ref"]
            .as_str()
            .cmp(&right["record"]["release_ref"].as_str())
    });
    (
        StatusCode::OK,
        Json(json!({ "ok": true, "releases": releases })),
    )
}

/// GET /v1/hypervisor/packages/:package_id/releases/:release_digest.
pub(crate) async fn handle_release_get(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath((package_id, release_digest)): AxumPath<(String, String)>,
) -> Reply {
    let identity = match request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(reply) => return reply,
    };
    match read_release_authorized(&st.data_dir, &identity, &package_id, &release_digest) {
        Ok(exact) => (
            StatusCode::OK,
            Json(json!({ "ok": true, "release": render_release(&exact, None) })),
        ),
        Err(reply) => reply,
    }
}

fn validate_installation_request(request: &InstallationRequest) -> Result<(), Reply> {
    if !valid_id(&request.installation_id) {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "package_installation_id_invalid",
            "installation_id must be a lowercase canonical coordinate",
        ));
    }
    if !valid_hash(&request.expected_release_head) {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "package_expected_head_invalid",
            "expected_release_head must be one canonical sha256 head",
        ));
    }
    if request
        .project_ref
        .as_deref()
        .is_some_and(|value| !valid_ref(value, "project://"))
    {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "package_installation_project_ref_invalid",
            "project_ref must be null or one canonical project:// reference",
        ));
    }
    if !["private", "organization", "permissioned", "public"].contains(&request.visibility.as_str())
    {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "package_installation_visibility_invalid",
            "visibility is not canonical",
        ));
    }
    if !unique_nonempty(&request.allowed_object_contract_refs)
        || !unique_nonempty(&request.allowed_action_refs)
    {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "package_installation_refs_invalid",
            "allowed object and action refs must be non-empty where present and unique",
        ));
    }
    if !valid_idempotency_key(&request.idempotency_key) {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "package_idempotency_key_invalid",
            "idempotency_key is required, bounded, and contains no control characters",
        ));
    }
    Ok(())
}

fn require_subset(values: &[String], ceiling: &[String], field: &str) -> Result<(), Reply> {
    if values.iter().all(|value| ceiling.contains(value)) {
        Ok(())
    } else {
        Err(bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            "package_installation_contract_widening",
            format!("{field} may only narrow the admitted release contract set"),
        ))
    }
}

fn build_installation_admission(
    package_id: &str,
    release: &ExactProjection,
    request: &InstallationRequest,
) -> Result<(String, Value), Reply> {
    let release_record: SurfaceReleaseRecord =
        serde_json::from_value(release.operation.payload["release"].clone()).map_err(|error| {
            bad(
                StatusCode::INTERNAL_SERVER_ERROR,
                "package_release_projection_invalid",
                error.to_string(),
            )
        })?;
    if release_record.surface_admission_state != "admitted"
        || release_record.surface_package_disposition != "active"
    {
        return Err(bad(
            StatusCode::CONFLICT,
            "package_release_not_installable",
            "only an admitted active release may receive an installation binding",
        ));
    }
    require_subset(
        &request.allowed_object_contract_refs,
        &release_record.object_contract_refs,
        "allowed_object_contract_refs",
    )?;
    require_subset(
        &request.allowed_action_refs,
        &release_record.action_contract_refs,
        "allowed_action_refs",
    )?;
    let installation_ref = installation_ref(package_id, &request.installation_id);
    let installation = SurfaceInstallationBinding {
        schema_version: INSTALLATION_SCHEMA.into(),
        installation_ref: installation_ref.clone(),
        surface_ref: release_record.surface_ref,
        release_ref: release_record.release_ref,
        org_ref: release.operation.payload["owner_ref"]
            .as_str()
            .unwrap_or_default()
            .to_owned(),
        project_ref: request.project_ref.clone(),
        surface_installation_state: "installed".into(),
        // Fail closed: Applications has not admitted an extension registration.
        surface_enablement_state: "disabled".into(),
        visibility: request.visibility.clone(),
        allowed_object_contract_refs: request.allowed_object_contract_refs.clone(),
        allowed_action_refs: request.allowed_action_refs.clone(),
        revision: 1,
    };
    let installation_value = serde_json::to_value(installation).map_err(|error| {
        bad(
            StatusCode::INTERNAL_SERVER_ERROR,
            "package_installation_encoding_failed",
            error.to_string(),
        )
    })?;
    validate_canonical_contract(
        INSTALLATION_CONTRACT_ID,
        &installation_value,
        "package_installation_contract_failed",
    )?;
    Ok((
        installation_ref,
        json!({
            "schema_version": INSTALLATION_ADMISSION_SCHEMA,
            "installation": installation_value,
            "owner_ref": release.operation.payload["owner_ref"],
            "release_head": release.head,
            "registration_state": "absent",
            "launch_eligible": false,
            "disabled_reason_codes": [
                "extension_application_registration_absent",
                "surface_serving_binding_absent"
            ],
            "transition": "installed_disabled",
            "nonclaim": "The ODK package source is locally bound, but no application registration, executable process, route, serving binding, System interface, or launch authority exists."
        }),
    ))
}

/// POST /v1/hypervisor/packages/:package_id/releases/:release_digest/installations
/// creates a disabled, owner-scoped installation binding for one exact release.
pub(crate) async fn handle_installation_create(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath((package_id, release_digest)): AxumPath<(String, String)>,
    Json(body): Json<Value>,
) -> Reply {
    let identity = match request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(reply) => return reply,
    };
    let request: InstallationRequest = match parse(body, "package_installation_request_invalid") {
        Ok(request) => request,
        Err(reply) => return reply,
    };
    if let Err(reply) = validate_installation_request(&request) {
        return reply;
    }
    let release =
        match read_release_authorized(&st.data_dir, &identity, &package_id, &release_digest) {
            Ok(release) => release,
            Err(reply) => return reply,
        };
    if request.expected_release_head != release.head {
        return bad(
            StatusCode::CONFLICT,
            "package_expected_head_conflict",
            "expected_release_head is not the exact admitted release head",
        );
    }
    let (resource_ref, admission) =
        match build_installation_admission(&package_id, &release, &request) {
            Ok(value) => value,
            Err(reply) => return reply,
        };
    let owner_ref = release.operation.payload["owner_ref"]
        .as_str()
        .unwrap_or_default();
    let scope = match bind_scope(
        &st.data_dir,
        &identity,
        INSTALLATION_SCOPE_KIND,
        &resource_ref,
        owner_ref,
        &request.idempotency_key,
    ) {
        Ok(scope) => scope,
        Err(reply) => return reply,
    };
    let tail = hash_tail("installation", &resource_ref);
    match admit(
        &st.data_dir,
        true,
        &identity,
        &scope,
        INSTALLATION_SCOPE_KIND,
        &resource_ref,
        &tail,
        "event_stream.hypervisor_surface_installation_admitted",
        None,
        &admission,
        request.recorded_at_ms.unwrap_or_default(),
        &request.idempotency_key,
    ) {
        Ok(commit) => (
            StatusCode::CREATED,
            Json(json!({
                "ok": true,
                "installation": render_installation(&commit.projection, Some(commit.replayed), &release)
            })),
        ),
        Err(reply) => reply,
    }
}

/// GET .../installations — owner-filtered bindings for one exact release.
pub(crate) async fn handle_installation_list(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath((package_id, release_digest)): AxumPath<(String, String)>,
) -> Reply {
    let identity = match request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(reply) => return reply,
    };
    let release =
        match read_release_authorized(&st.data_dir, &identity, &package_id, &release_digest) {
            Ok(release) => release,
            Err(reply) => return reply,
        };
    let allowed = match authorized_refs(&st.data_dir, &identity, INSTALLATION_SCOPE_KIND) {
        Ok(allowed) => allowed,
        Err(reply) => return reply,
    };
    let target_release_ref = release.operation.payload["release"]["release_ref"].clone();
    let tails = match super::substrate_store::list_event_stream_tails(&st.data_dir, NAMESPACE) {
        Ok(tails) => tails,
        Err(error) => {
            return bad(
                StatusCode::SERVICE_UNAVAILABLE,
                "package_installation_inventory_unavailable",
                error.to_string(),
            )
        }
    };
    let mut installations = Vec::new();
    for tail in tails
        .into_iter()
        .filter(|tail| tail.starts_with("installation."))
    {
        let exact = match stream_head(&st.data_dir, &tail, "package_installation_not_found") {
            Ok(exact) => exact,
            Err(reply) => return reply,
        };
        let record = &exact.operation.payload["installation"];
        let resource_ref = record["installation_ref"].as_str().unwrap_or_default();
        if exact.operation.payload["schema_version"] == INSTALLATION_ADMISSION_SCHEMA
            && record["release_ref"] == target_release_ref
            && allowed.contains(resource_ref)
        {
            installations.push(render_installation(&exact, None, &release));
        }
    }
    installations.sort_by(|left, right| {
        left["record"]["installation_ref"]
            .as_str()
            .cmp(&right["record"]["installation_ref"].as_str())
    });
    (
        StatusCode::OK,
        Json(json!({ "ok": true, "installations": installations })),
    )
}

/// GET .../installations/:installation_id — exact current binding revision.
pub(crate) async fn handle_installation_get(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath((package_id, release_digest, installation_id)): AxumPath<(String, String, String)>,
) -> Reply {
    let identity = match request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(reply) => return reply,
    };
    // The recall cascade reads the CURRENT release head alongside the binding,
    // so a recalled disposition reflects on this read immediately and after
    // restart — the binding's own admitted bytes stay untouched.
    let release =
        match read_release_authorized(&st.data_dir, &identity, &package_id, &release_digest) {
            Ok(release) => release,
            Err(reply) => return reply,
        };
    match read_installation_authorized(
        &st.data_dir,
        &identity,
        &package_id,
        &release_digest,
        &installation_id,
    ) {
        Ok(exact) => (
            StatusCode::OK,
            Json(json!({
                "ok": true,
                "installation": render_installation(&exact, None, &release)
            })),
        ),
        Err(reply) => reply,
    }
}

fn prior_idempotent_projection(
    data_dir: &str,
    tail: &str,
    idempotency_key: &str,
) -> Result<Option<ExactProjection>, Reply> {
    Ok(stream_history(data_dir, tail)?
        .into_iter()
        .find(|exact| exact.operation.idem_key == idempotency_key))
}

/// POST .../installations/:installation_id/uninstall — append an immutable
/// successor revision under exact-head CAS.  This removes only the local
/// binding; there is no process or serving route for this packet to stop.
pub(crate) async fn handle_installation_uninstall(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath((package_id, release_digest, installation_id)): AxumPath<(String, String, String)>,
    Json(body): Json<Value>,
) -> Reply {
    let identity = match request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(reply) => return reply,
    };
    let request: UninstallRequest = match parse(body, "package_uninstall_request_invalid") {
        Ok(request) => request,
        Err(reply) => return reply,
    };
    if !valid_hash(&request.expected_installation_head) {
        return bad(
            StatusCode::BAD_REQUEST,
            "package_expected_head_invalid",
            "expected_installation_head must be one canonical sha256 head",
        );
    }
    if !valid_idempotency_key(&request.idempotency_key) {
        return bad(
            StatusCode::BAD_REQUEST,
            "package_idempotency_key_invalid",
            "idempotency_key is required, bounded, and contains no control characters",
        );
    }
    // Uninstall stays legal over a recalled release (the cleanup path); the
    // release head is read for the derived eligibility facts, never gated on.
    let release =
        match read_release_authorized(&st.data_dir, &identity, &package_id, &release_digest) {
            Ok(release) => release,
            Err(reply) => return reply,
        };
    let current = match read_installation_authorized(
        &st.data_dir,
        &identity,
        &package_id,
        &release_digest,
        &installation_id,
    ) {
        Ok(current) => current,
        Err(reply) => return reply,
    };
    let resource_ref = installation_ref(&package_id, &installation_id);
    let tail = hash_tail("installation", &resource_ref);
    match prior_idempotent_projection(&st.data_dir, &tail, &request.idempotency_key) {
        Ok(Some(prior))
            if prior.operation.op_kind
                == "event_stream.hypervisor_surface_installation_uninstalled" =>
        {
            return (
                StatusCode::OK,
                Json(json!({
                    "ok": true,
                    "installation": render_installation(&prior, Some(true), &release)
                })),
            )
        }
        Ok(Some(_)) => {
            return bad(
                StatusCode::CONFLICT,
                "package_idempotency_payload_conflict",
                "the idempotency key already names a different installation operation",
            )
        }
        Ok(None) => {}
        Err(reply) => return reply,
    }
    if request.expected_installation_head != current.head {
        return bad(
            StatusCode::CONFLICT,
            "package_expected_head_conflict",
            "expected_installation_head is not the current admitted installation head",
        );
    }
    let mut installation: SurfaceInstallationBinding =
        match serde_json::from_value(current.operation.payload["installation"].clone()) {
            Ok(installation) => installation,
            Err(error) => {
                return bad(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "package_installation_projection_invalid",
                    error.to_string(),
                )
            }
        };
    if installation.surface_installation_state != "installed" {
        return bad(
            StatusCode::CONFLICT,
            "package_installation_not_installed",
            "only an installed binding may transition to uninstalled",
        );
    }
    installation.surface_installation_state = "uninstalled".into();
    installation.surface_enablement_state = "disabled".into();
    installation.revision = installation.revision.saturating_add(1);
    let installation_value = match serde_json::to_value(&installation) {
        Ok(value) => value,
        Err(error) => {
            return bad(
                StatusCode::INTERNAL_SERVER_ERROR,
                "package_installation_encoding_failed",
                error.to_string(),
            )
        }
    };
    if let Err(reply) = validate_canonical_contract(
        INSTALLATION_CONTRACT_ID,
        &installation_value,
        "package_installation_contract_failed",
    ) {
        return reply;
    }
    let payload = json!({
        "schema_version": INSTALLATION_ADMISSION_SCHEMA,
        "installation": installation_value,
        "owner_ref": current.operation.payload["owner_ref"],
        "release_head": current.operation.payload["release_head"],
        "registration_state": "absent",
        "launch_eligible": false,
        "disabled_reason_codes": [
            "surface_installation_uninstalled",
            "extension_application_registration_absent",
            "surface_serving_binding_absent"
        ],
        "transition": "uninstalled",
        "nonclaim": "The disabled local installation binding was removed; no runtime or route effect is claimed."
    });
    let scope = match authorize_scope(
        &st.data_dir,
        &identity,
        INSTALLATION_SCOPE_KIND,
        &resource_ref,
        current.operation.payload["owner_ref"].as_str(),
    ) {
        Ok(scope) => scope,
        Err(reply) => return reply,
    };
    match admit(
        &st.data_dir,
        false,
        &identity,
        &scope,
        INSTALLATION_SCOPE_KIND,
        &resource_ref,
        &tail,
        "event_stream.hypervisor_surface_installation_uninstalled",
        Some(&request.expected_installation_head),
        &payload,
        request.recorded_at_ms.unwrap_or_default(),
        &request.idempotency_key,
    ) {
        Ok(commit) => (
            StatusCode::OK,
            Json(json!({
                "ok": true,
                "installation": render_installation(&commit.projection, Some(commit.replayed), &release)
            })),
        ),
        Err(reply) => reply,
    }
}

/// POST /v1/hypervisor/packages/:package_id/releases/:release_digest/recall —
/// append the immutable disposition successor (`active` → `recalled`) under
/// exact-head CAS.  The registered contract has named `recalled` in the
/// disposition enum since v1; this is the route that legally reaches it.  The
/// verb mutates ONLY the release stream: installation bindings over the
/// recalled release keep their admitted bytes and derive `launch_eligible:
/// false` plus the `surface_release_recalled` reason at read time, and the
/// product-surface projection drops the surface from the launcher feed on its
/// next read of this namespace.
pub(crate) async fn handle_release_recall(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath((package_id, release_digest)): AxumPath<(String, String)>,
    Json(body): Json<Value>,
) -> Reply {
    let identity = match request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(reply) => return reply,
    };
    let request: RecallRequest = match parse(body, "package_recall_request_invalid") {
        Ok(request) => request,
        Err(reply) => return reply,
    };
    if !valid_hash(&request.expected_release_head) {
        return bad(
            StatusCode::BAD_REQUEST,
            "package_expected_head_invalid",
            "expected_release_head must be one canonical sha256 head",
        );
    }
    if !valid_recall_reason(&request.reason) {
        return bad(
            StatusCode::BAD_REQUEST,
            "package_recall_reason_invalid",
            "reason is required, at most 500 characters, and contains no control characters",
        );
    }
    if !valid_idempotency_key(&request.idempotency_key) {
        return bad(
            StatusCode::BAD_REQUEST,
            "package_idempotency_key_invalid",
            "idempotency_key is required, bounded, and contains no control characters",
        );
    }
    let current =
        match read_release_authorized(&st.data_dir, &identity, &package_id, &release_digest) {
            Ok(current) => current,
            Err(reply) => return reply,
        };
    let resource_ref = release_ref(&package_id, &release_digest);
    let tail = hash_tail("release", &resource_ref);
    match prior_idempotent_projection(&st.data_dir, &tail, &request.idempotency_key) {
        Ok(Some(prior))
            if prior.operation.op_kind == "event_stream.hypervisor_package_release_recalled" =>
        {
            return (
                StatusCode::OK,
                Json(json!({
                    "ok": true,
                    "release": render_release(&prior, Some(true))
                })),
            )
        }
        Ok(Some(_)) => {
            return bad(
                StatusCode::CONFLICT,
                "package_idempotency_payload_conflict",
                "the idempotency key already names a different release operation",
            )
        }
        Ok(None) => {}
        Err(reply) => return reply,
    }
    if request.expected_release_head != current.head {
        return bad(
            StatusCode::CONFLICT,
            "package_expected_head_conflict",
            "expected_release_head is not the current admitted release head",
        );
    }
    let mut release: SurfaceReleaseRecord =
        match serde_json::from_value(current.operation.payload["release"].clone()) {
            Ok(release) => release,
            Err(error) => {
                return bad(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "package_release_projection_invalid",
                    error.to_string(),
                )
            }
        };
    if release.surface_admission_state != "admitted"
        || release.surface_package_disposition != "active"
    {
        return bad(
            StatusCode::CONFLICT,
            "package_release_not_recallable",
            "only an admitted active release may transition to recalled",
        );
    }
    release.surface_package_disposition = "recalled".into();
    let release_value = match serde_json::to_value(&release) {
        Ok(value) => value,
        Err(error) => {
            return bad(
                StatusCode::INTERNAL_SERVER_ERROR,
                "package_release_encoding_failed",
                error.to_string(),
            )
        }
    };
    if let Err(reply) = validate_canonical_contract(
        RELEASE_CONTRACT_ID,
        &release_value,
        "package_release_contract_failed",
    ) {
        return reply;
    }
    let payload = json!({
        "schema_version": RELEASE_ADMISSION_SCHEMA,
        "release": release_value,
        "owner_ref": current.operation.payload["owner_ref"],
        "package_candidate_ref": current.operation.payload["package_candidate_ref"],
        "package_candidate_head": current.operation.payload["package_candidate_head"],
        "package_candidate_content_hash": current.operation.payload["package_candidate_content_hash"],
        "admission_decision_ref": current.operation.payload["admission_decision_ref"],
        "recall_reason": request.reason.trim(),
        "registration_state": "absent",
        "transition": "recalled",
        "nonclaim": "Recall flips only the admitted release disposition; it mutates no installation binding, registration, route, or process — binding eligibility and the launcher feed derive the loss on their next read."
    });
    let scope = match authorize_scope(
        &st.data_dir,
        &identity,
        RELEASE_SCOPE_KIND,
        &resource_ref,
        current.operation.payload["owner_ref"].as_str(),
    ) {
        Ok(scope) => scope,
        Err(reply) => return reply,
    };
    match admit(
        &st.data_dir,
        false,
        &identity,
        &scope,
        RELEASE_SCOPE_KIND,
        &resource_ref,
        &tail,
        "event_stream.hypervisor_package_release_recalled",
        Some(&request.expected_release_head),
        &payload,
        request.recorded_at_ms.unwrap_or_default(),
        &request.idempotency_key,
    ) {
        Ok(commit) => (
            StatusCode::OK,
            Json(json!({
                "ok": true,
                "release": render_release(&commit.projection, Some(commit.replayed))
            })),
        ),
        Err(reply) => reply,
    }
}

/// Launcher-feed truth over the registry namespace, computed live for one exact
/// organization on every product-surface projection read (never compiled-in,
/// never cached): each INSTALLED, non-uninstalled binding whose CURRENT release
/// head still carries the `active` disposition projects one honest application
/// entry — present in the launcher inventory, `launchable: false` with the
/// exact derived reasons (no registration, no serving binding).  A recalled or
/// uninstalled surface produces NO entry: the loss is derived from admitted
/// truth on the same read, so it is immediate and survives restart by
/// construction.  An empty registry yields an empty vector — honest absence.
/// Two bindings over one surface project one entry (the lexicographically
/// first installation_ref), matching the compiled join's one-entry-per-surface
/// shape.
pub(crate) fn launcher_registry_application_entries(
    data_dir: &str,
    org_ref: &str,
) -> Result<Vec<Value>, String> {
    let tails = super::substrate_store::list_event_stream_tails(data_dir, NAMESPACE)
        .map_err(|error| error.to_string())?;
    let mut entries: std::collections::BTreeMap<String, Value> = std::collections::BTreeMap::new();
    for tail in tails
        .into_iter()
        .filter(|tail| tail.starts_with("installation."))
    {
        let Some(exact) =
            super::substrate_store::read_event_stream_operation(data_dir, NAMESPACE, &tail)
                .map_err(|error| error.to_string())?
        else {
            continue;
        };
        if exact.operation.payload["schema_version"] != INSTALLATION_ADMISSION_SCHEMA {
            continue;
        }
        let installation = exact.operation.payload["installation"].clone();
        if installation["org_ref"].as_str() != Some(org_ref)
            || installation["surface_installation_state"].as_str() != Some("installed")
        {
            continue;
        }
        let (Some(surface_ref), Some(release_ref), Some(installation_ref)) = (
            installation["surface_ref"].as_str(),
            installation["release_ref"].as_str(),
            installation["installation_ref"].as_str(),
        ) else {
            continue;
        };
        let release_tail = hash_tail("release", release_ref);
        // A binding admits only over an admitted release, so an unreadable
        // release stream means no eligibility can be derived — honest absence,
        // never a fabricated entry.
        let Some(release) =
            super::substrate_store::read_event_stream_operation(data_dir, NAMESPACE, &release_tail)
                .map_err(|error| error.to_string())?
        else {
            continue;
        };
        let release_record = release.operation.payload["release"].clone();
        if release.operation.payload["schema_version"] != RELEASE_ADMISSION_SCHEMA
            || release_record["release_ref"].as_str() != Some(release_ref)
            || release_record["surface_package_disposition"].as_str() != Some("active")
        {
            continue;
        }
        let entry = json!({
            "identity_ref": surface_ref,
            "display_name": surface_ref.rsplit('/').next().unwrap_or(surface_ref),
            "entry_source": "hypervisor-package-registry",
            "canonical_route": Value::Null,
            "resolved_launch_route": Value::Null,
            "launchable": false,
            "disabled_reason_codes": derived_disabled_reason_codes("installed", "active"),
            "surface_capability_depth": release_record["surface_capability_depth"],
            "surface_operational_state": Value::Null,
            "installation_ref": installation_ref,
            "release_ref": release_ref,
            "release_disposition": "active",
            "surface_installation_state": "installed",
            "surface_enablement_state": installation["surface_enablement_state"],
        });
        match entries.get(surface_ref) {
            Some(existing) if existing["installation_ref"].as_str() <= Some(installation_ref) => {}
            _ => {
                entries.insert(surface_ref.to_owned(), entry);
            }
        }
    }
    Ok(entries.into_values().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// THE SMOKE PRODUCER NOW PRODUCES WHAT THIS LANE ACTUALLY PACKAGES.
    ///
    /// It built a v1 descriptor stub — three fields, a `ref`, no binding set — so the test froze a
    /// record shape the daemon has not authored since M05.5 and could say nothing about the one it
    /// has. Worse, it agreed with the consumer's own bug: both read `ref`, so the pair was
    /// self-consistently wrong and no assertion could see it.
    ///
    /// The descriptor here is a v2 carrying its own commitment and EXACT M05.1 admitted revisions —
    /// `ontology://<ns>/<name>/revision/<n>`, never a family head — because that is what an
    /// owner-resolved descriptor binds, and a package that froze a mutable head would freeze
    /// something that re-means itself.
    fn source() -> PackageSource {
        PackageSource {
            domain_app: json!({
                "schema_version":"ioi.hypervisor.domain-app.v1",
                "domain_app_ref":"domain-app://dapp-test",
                "status":"draft",
                "owner_ref":"org://local",
                "odk_manifest_ref":"odk://manifest-test",
                "surface_descriptor_ref":"surface-descriptor://sd_0123456789abcdef0",
                "ontology_refs":["ontology://acme-clinic/patient-intake/revision/3"],
                "data_recipe_refs":["data-recipe://acme-clinic/intake-normalise/revision/1"]
            }),
            manifest: json!({
                "schema_version":"ioi.hypervisor.odk.manifest.v1",
                "ref":"odk://manifest-test",
                "surface_descriptor_refs":["surface-descriptor://sd_0123456789abcdef0"]
            }),
            descriptor: json!({
                "schema_version":"ioi.ontology-surface-descriptor.v2",
                "surface_descriptor_id":"surface-descriptor://sd_0123456789abcdef0",
                "composition_pattern":"domain_app",
                "owner_ref":"org://local",
                "ontology_refs":["ontology://acme-clinic/patient-intake/revision/3"],
                "data_recipe_refs":["data-recipe://acme-clinic/intake-normalise/revision/1"],
                "content_hash":"sha256:5c6ef4a3be03aec05a0a2bd575dff175b451aaea3f7b02ad53c4118dbfdd2ba0",
                "status":"active"
            }),
            descriptor_content_hash: Some(
                "sha256:5c6ef4a3be03aec05a0a2bd575dff175b451aaea3f7b02ad53c4118dbfdd2ba0".into(),
            ),
            descriptor_schema_version: "ioi.ontology-surface-descriptor.v2".into(),
            // M05.6 — the app and manifest arrive from their own owner seams, so the source carries
            // which contract admitted each and the exact head it was read at. A candidate that froze
            // three records without saying where in three chains it read them can be checked for
            // self-consistency and against nothing else.
            domain_app_schema_version: "ioi.hypervisor.domain-app.v1".into(),
            domain_app_admitted_head: "sha256:".to_string() + &"1a".repeat(32),
            manifest_schema_version: "ioi.hypervisor.odk.manifest.v1".into(),
            manifest_admitted_head: "sha256:".to_string() + &"2b".repeat(32),
            manifest_content_hash: "sha256:".to_string() + &"3c".repeat(32),
        }
    }

    /// A v1 source, kept because v1 remains READABLE here and that compatibility is explicit.
    fn v1_source() -> PackageSource {
        let mut source = source();
        source.descriptor = json!({
            "schema_version":"ioi.hypervisor.odk.surface-descriptor.v1",
            "ref":"surface-descriptor://sd_0123456789abcdef0",
            "composition_pattern":"domain_app"
        });
        source.descriptor_content_hash = None;
        source.descriptor_schema_version = "ioi.hypervisor.odk.surface-descriptor.v1".into();
        source
    }

    /// The candidate freezes the descriptor OWNER'S committed hash, names the descriptor by its
    /// canonical v2 identity, and says whose number it carries.
    #[test]
    fn a_v2_source_freezes_the_owner_commitment_and_names_it_as_the_owners() {
        let record = build_package_candidate(&candidate_request(), &source()).unwrap();
        assert_eq!(
            record["surface_descriptor_ref"], "surface-descriptor://sd_0123456789abcdef0",
            "a v2 names itself surface_descriptor_id; reading only `ref` froze null"
        );
        assert_eq!(
            record["source_snapshots"]["surface_descriptor_content_hash"],
            "sha256:5c6ef4a3be03aec05a0a2bd575dff175b451aaea3f7b02ad53c4118dbfdd2ba0",
            "the frozen hash is the descriptor owner's own commitment, verbatim"
        );
        assert_eq!(
            record["source_snapshots"]["surface_descriptor_content_hash_source"],
            "descriptor_owner_committed"
        );
        assert_eq!(
            record["source_snapshots"]["surface_descriptor_schema_version"],
            "ioi.ontology-surface-descriptor.v2"
        );
    }

    /// A stored v1 has no self-commitment, so the derived number is LABELLED as derived rather than
    /// presented as the owner's — two different kinds of fact, distinguishable in the record.
    #[test]
    fn a_v1_source_labels_its_hash_as_derived_rather_than_owner_committed() {
        let record = build_package_candidate(&candidate_request(), &v1_source()).unwrap();
        assert_eq!(
            record["source_snapshots"]["surface_descriptor_content_hash_source"],
            "derived_by_package_registry"
        );
        assert_eq!(
            record["source_snapshots"]["surface_descriptor_schema_version"],
            "ioi.hypervisor.odk.surface-descriptor.v1"
        );
        assert!(valid_hash(
            record["source_snapshots"]["surface_descriptor_content_hash"]
                .as_str()
                .unwrap_or_default()
        ));
        // The two sources are distinguishable in the candidate hash itself, so a v1 snapshot can
        // never be mistaken for a v2 one after the fact.
        assert_ne!(
            record["candidate_content_hash"],
            build_package_candidate(&candidate_request(), &source()).unwrap()
                ["candidate_content_hash"]
        );
    }

    /// The exactness this lane inherits from M05.1: what a package freezes is an ADMITTED REVISION,
    /// never a family head that re-means itself after the freeze.
    #[test]
    fn the_packaged_descriptor_binds_exact_admitted_revisions_not_family_heads() {
        let source = source();
        let bound = source.descriptor["ontology_refs"].as_array().unwrap();
        assert!(!bound.is_empty());
        for reference in bound {
            let reference = reference.as_str().unwrap();
            assert!(
                reference.contains("/revision/"),
                "{reference} is a family head, and a package that froze one would freeze something that changes"
            );
        }
    }

    fn candidate_request() -> PackageCandidateRequest {
        PackageCandidateRequest {
            package_id: "local-telesupport".into(),
            owner_ref: "org://local".into(),
            domain_app_ref: "domain-app://dapp-test".into(),
            idempotency_key: "candidate-create-1".into(),
            recorded_at_ms: Some(1),
        }
    }

    #[test]
    fn candidate_freezes_all_three_odk_source_records_and_names_missing_registration() {
        let record = build_package_candidate(&candidate_request(), &source()).unwrap();
        assert_eq!(record["package_ref"], "package://local-telesupport");
        assert_eq!(
            record["surface_ref"],
            "surface://extensions/local-telesupport"
        );
        assert_eq!(record["surface_class"], "extension_application");
        assert_eq!(record["registration_state"], "absent");
        for field in [
            "domain_app_content_hash",
            "odk_manifest_content_hash",
            "surface_descriptor_content_hash",
        ] {
            assert!(valid_hash(
                record["source_snapshots"][field]
                    .as_str()
                    .unwrap_or_default()
            ));
        }
        assert!(valid_hash(
            record["candidate_content_hash"]
                .as_str()
                .unwrap_or_default()
        ));
    }

    #[test]
    fn release_and_install_shapes_are_closed_canonical_records() {
        let directory = tempfile::tempdir().unwrap();
        let data_dir = directory.path().to_str().unwrap();
        super::super::substrate_store::reset_handle_for_test();
        let identity = super::super::substrate_store::request_identity_for_test(
            "operator",
            ["org://local".to_string()],
        );
        let request = candidate_request();
        let candidate_record = build_package_candidate(&request, &source()).unwrap();
        let candidate_resource = package_ref(&request.package_id);
        let candidate_scope = bind_scope(
            data_dir,
            &identity,
            PACKAGE_SCOPE_KIND,
            &candidate_resource,
            &request.owner_ref,
            &request.idempotency_key,
        )
        .unwrap();
        let candidate_tail = hash_tail("package", &candidate_resource);
        let candidate = admit(
            data_dir,
            true,
            &identity,
            &candidate_scope,
            PACKAGE_SCOPE_KIND,
            &candidate_resource,
            &candidate_tail,
            "event_stream.hypervisor_package_candidate_admitted",
            None,
            &candidate_record,
            1,
            &request.idempotency_key,
        )
        .unwrap();
        assert!(candidate.receipt_ref.starts_with("receipt://"));

        let release_request = ReleaseRequest {
            expected_package_head: candidate.projection.head.clone(),
            surface_distribution: "private_registry".into(),
            surface_capability_depth: "propose".into(),
            object_contract_refs: vec!["object-model://telesupport".into()],
            action_contract_refs: vec!["action://telesupport/reply".into()],
            evidence_refs: vec!["artifact://telesupport/package-proof".into()],
            idempotency_key: "release-create-1".into(),
            recorded_at_ms: Some(2),
        };
        let (release_resource, release_payload) =
            build_release_admission(&candidate.projection, &release_request).unwrap();
        let canonical_release: SurfaceReleaseRecord =
            serde_json::from_value(release_payload["release"].clone()).unwrap();
        assert_eq!(canonical_release.schema_version, RELEASE_SCHEMA);
        assert_eq!(canonical_release.surface_admission_state, "admitted");
        assert!(canonical_release
            .evidence_refs
            .iter()
            .any(|reference| reference.starts_with("receipt://")));

        let release_scope = bind_scope(
            data_dir,
            &identity,
            RELEASE_SCOPE_KIND,
            &release_resource,
            "org://local",
            &release_request.idempotency_key,
        )
        .unwrap();
        let release_tail = hash_tail("release", &release_resource);
        let release = admit(
            data_dir,
            true,
            &identity,
            &release_scope,
            RELEASE_SCOPE_KIND,
            &release_resource,
            &release_tail,
            "event_stream.hypervisor_package_release_admitted",
            None,
            &release_payload,
            2,
            &release_request.idempotency_key,
        )
        .unwrap();

        let install_request = InstallationRequest {
            installation_id: "primary".into(),
            expected_release_head: release.projection.head.clone(),
            project_ref: None,
            visibility: "organization".into(),
            allowed_object_contract_refs: canonical_release.object_contract_refs.clone(),
            allowed_action_refs: canonical_release.action_contract_refs.clone(),
            idempotency_key: "install-create-1".into(),
            recorded_at_ms: Some(3),
        };
        let (_, install_payload) = build_installation_admission(
            &request.package_id,
            &release.projection,
            &install_request,
        )
        .unwrap();
        let binding: SurfaceInstallationBinding =
            serde_json::from_value(install_payload["installation"].clone()).unwrap();
        assert_eq!(binding.schema_version, INSTALLATION_SCHEMA);
        assert_eq!(binding.surface_installation_state, "installed");
        assert_eq!(binding.surface_enablement_state, "disabled");
        assert_eq!(install_payload["launch_eligible"], false);
        assert_eq!(install_payload["registration_state"], "absent");
        super::super::substrate_store::reset_handle_for_test();
    }

    #[test]
    fn recall_appends_the_disposition_successor_and_the_cascade_derives_at_read() {
        let directory = tempfile::tempdir().unwrap();
        let data_dir = directory.path().to_str().unwrap();
        super::super::substrate_store::reset_handle_for_test();
        let identity = super::super::substrate_store::request_identity_for_test(
            "operator",
            ["org://local".to_string()],
        );
        let request = candidate_request();
        let candidate_record = build_package_candidate(&request, &source()).unwrap();
        let candidate_resource = package_ref(&request.package_id);
        let candidate_scope = bind_scope(
            data_dir,
            &identity,
            PACKAGE_SCOPE_KIND,
            &candidate_resource,
            &request.owner_ref,
            &request.idempotency_key,
        )
        .unwrap();
        let candidate = admit(
            data_dir,
            true,
            &identity,
            &candidate_scope,
            PACKAGE_SCOPE_KIND,
            &candidate_resource,
            &hash_tail("package", &candidate_resource),
            "event_stream.hypervisor_package_candidate_admitted",
            None,
            &candidate_record,
            1,
            &request.idempotency_key,
        )
        .unwrap();
        let release_request = ReleaseRequest {
            expected_package_head: candidate.projection.head.clone(),
            surface_distribution: "private_registry".into(),
            surface_capability_depth: "propose".into(),
            object_contract_refs: vec!["object-model://telesupport".into()],
            action_contract_refs: vec!["action://telesupport/reply".into()],
            evidence_refs: vec![],
            idempotency_key: "release-create-1".into(),
            recorded_at_ms: Some(2),
        };
        let (release_resource, release_payload) =
            build_release_admission(&candidate.projection, &release_request).unwrap();
        let release_scope = bind_scope(
            data_dir,
            &identity,
            RELEASE_SCOPE_KIND,
            &release_resource,
            "org://local",
            &release_request.idempotency_key,
        )
        .unwrap();
        let release_tail = hash_tail("release", &release_resource);
        let release = admit(
            data_dir,
            true,
            &identity,
            &release_scope,
            RELEASE_SCOPE_KIND,
            &release_resource,
            &release_tail,
            "event_stream.hypervisor_package_release_admitted",
            None,
            &release_payload,
            2,
            &release_request.idempotency_key,
        )
        .unwrap();
        let install_request = InstallationRequest {
            installation_id: "primary".into(),
            expected_release_head: release.projection.head.clone(),
            project_ref: None,
            visibility: "organization".into(),
            allowed_object_contract_refs: vec![],
            allowed_action_refs: vec![],
            idempotency_key: "install-create-1".into(),
            recorded_at_ms: Some(3),
        };
        let (installation_resource, install_payload) = build_installation_admission(
            &request.package_id,
            &release.projection,
            &install_request,
        )
        .unwrap();
        let install_scope = bind_scope(
            data_dir,
            &identity,
            INSTALLATION_SCOPE_KIND,
            &installation_resource,
            "org://local",
            &install_request.idempotency_key,
        )
        .unwrap();
        let installation = admit(
            data_dir,
            true,
            &identity,
            &install_scope,
            INSTALLATION_SCOPE_KIND,
            &installation_resource,
            &hash_tail("installation", &installation_resource),
            "event_stream.hypervisor_surface_installation_admitted",
            None,
            &install_payload,
            3,
            &install_request.idempotency_key,
        )
        .unwrap();

        // Before recall: the binding derives the structural pair only, and the
        // launcher feed carries exactly one honest ineligible entry.
        let rendered = render_installation(&installation.projection, None, &release.projection);
        assert_eq!(rendered["release_disposition"], "active");
        assert_eq!(
            rendered["disabled_reason_codes"],
            json!([
                "extension_application_registration_absent",
                "surface_serving_binding_absent"
            ])
        );
        let entries = launcher_registry_application_entries(data_dir, "org://local").unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0]["identity_ref"],
            "surface://extensions/local-telesupport"
        );
        assert_eq!(entries[0]["launchable"], false);
        assert_eq!(entries[0]["entry_source"], "hypervisor-package-registry");
        assert!(
            launcher_registry_application_entries(data_dir, "org://other")
                .unwrap()
                .is_empty()
        );

        // The recall successor: same stream, exact-head CAS, disposition flips,
        // the record still satisfies the registered contract.
        let mut recalled: SurfaceReleaseRecord =
            serde_json::from_value(release_payload["release"].clone()).unwrap();
        recalled.surface_package_disposition = "recalled".into();
        let recalled_value = serde_json::to_value(&recalled).unwrap();
        validate_canonical_contract(
            RELEASE_CONTRACT_ID,
            &recalled_value,
            "package_release_contract_failed",
        )
        .unwrap();
        let recall_payload = json!({
            "schema_version": RELEASE_ADMISSION_SCHEMA,
            "release": recalled_value,
            "owner_ref": "org://local",
            "recall_reason": "conformance defect in the packaged surface",
            "registration_state": "absent",
            "transition": "recalled",
        });
        let recall = admit(
            data_dir,
            false,
            &identity,
            &release_scope,
            RELEASE_SCOPE_KIND,
            &release_resource,
            &release_tail,
            "event_stream.hypervisor_package_release_recalled",
            Some(&release.projection.head),
            &recall_payload,
            4,
            "release-recall-1",
        )
        .unwrap();
        assert_ne!(recall.projection.head, release.projection.head);
        assert_eq!(
            recall.projection.operation.payload["release"]["surface_package_disposition"],
            "recalled"
        );

        // After recall: the binding read derives the recall reason code without
        // any binding mutation, new installs refuse typed, and the launcher
        // feed loses the surface entirely.
        let rendered = render_installation(&installation.projection, None, &recall.projection);
        assert_eq!(rendered["launch_eligible"], false);
        assert_eq!(rendered["release_disposition"], "recalled");
        assert_eq!(
            rendered["release_recall_reason"],
            "conformance defect in the packaged surface"
        );
        assert_eq!(
            rendered["disabled_reason_codes"],
            json!([
                "surface_release_recalled",
                "extension_application_registration_absent",
                "surface_serving_binding_absent"
            ])
        );
        let refusal = build_installation_admission(
            &request.package_id,
            &recall.projection,
            &InstallationRequest {
                installation_id: "secondary".into(),
                expected_release_head: recall.projection.head.clone(),
                project_ref: None,
                visibility: "organization".into(),
                allowed_object_contract_refs: vec![],
                allowed_action_refs: vec![],
                idempotency_key: "install-create-2".into(),
                recorded_at_ms: Some(5),
            },
        )
        .unwrap_err();
        assert_eq!(refusal.0, StatusCode::CONFLICT);
        assert!(
            launcher_registry_application_entries(data_dir, "org://local")
                .unwrap()
                .is_empty()
        );
        super::super::substrate_store::reset_handle_for_test();
    }

    #[test]
    fn owner_scoped_candidate_replays_exactly_and_refuses_changed_bytes() {
        let directory = tempfile::tempdir().unwrap();
        let data_dir = directory.path().to_str().unwrap();
        super::super::substrate_store::reset_handle_for_test();
        let identity = super::super::substrate_store::request_identity_for_test(
            "operator",
            ["org://local".to_string()],
        );
        let request = candidate_request();
        let record = build_package_candidate(&request, &source()).unwrap();
        let resource_ref = package_ref(&request.package_id);
        let scope = bind_scope(
            data_dir,
            &identity,
            PACKAGE_SCOPE_KIND,
            &resource_ref,
            &request.owner_ref,
            &request.idempotency_key,
        )
        .unwrap();
        let tail = hash_tail("package", &resource_ref);
        let first = admit(
            data_dir,
            true,
            &identity,
            &scope,
            PACKAGE_SCOPE_KIND,
            &resource_ref,
            &tail,
            "event_stream.hypervisor_package_candidate_admitted",
            None,
            &record,
            1,
            &request.idempotency_key,
        )
        .unwrap();
        super::super::substrate_store::reset_handle_for_test();
        let replay = admit(
            data_dir,
            true,
            &identity,
            &scope,
            PACKAGE_SCOPE_KIND,
            &resource_ref,
            &tail,
            "event_stream.hypervisor_package_candidate_admitted",
            None,
            &record,
            99,
            &request.idempotency_key,
        )
        .unwrap();
        assert!(replay.replayed);
        assert_eq!(replay.projection.head, first.projection.head);
        assert_eq!(replay.receipt_ref, first.receipt_ref);

        let mut changed = record;
        changed["status"] = json!("different");
        assert!(admit(
            data_dir,
            true,
            &identity,
            &scope,
            PACKAGE_SCOPE_KIND,
            &resource_ref,
            &tail,
            "event_stream.hypervisor_package_candidate_admitted",
            None,
            &changed,
            100,
            &request.idempotency_key,
        )
        .is_err());
        super::super::substrate_store::reset_handle_for_test();
    }
}
