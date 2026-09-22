//! Jurisdiction-policy and compliance-audit-export plane (M06.10) — canonical contracts
//! `schema://ioi/foundations/jurisdiction-policy-pack/v1`,
//! `schema://ioi/foundations/jurisdiction-policy-decision/v1` and
//! `schema://ioi/foundations/compliance-audit-export-bundle/v1`
//! (docs/architecture/foundations/ecosystem-assurance-certification-liability.md).
//!
//! Canon has specified these objects member for member since the assurance foundation was
//! written, and until M06.10 nothing in the estate registered them: every obligation they
//! describe was a paragraph rather than a shape anything could refuse.
//!
//! WHAT THIS PLANE IS. A pack DECLARES obligations; it grants nothing and decides nothing,
//! because it compiles into owners that already exist — wallet.network identity and step-up
//! gates, daemon policy checks, Agentgres retention and export validity, marketplace listing
//! restrictions, sas.xyz service obligations. A decision REPORTS what a pack said about one
//! subject at one instant. An export is a MANIFEST over evidence that already exists, for one
//! named audience. None of the three is a legal determination, and none of them can express one:
//! `legal_conformity_claim` is `const not_determined` on the wire.
//!
//! THE LAW THIS PLANE ENFORCES THAT A SCHEMA CANNOT. Canon: changing a deadline, clock-start
//! rule, recipient, responsible party or accountable issuer requires a NEW PACK VERSION and must
//! never rewrite an already-recorded reporting decision. A schema can seal a pack with a root;
//! only the plane can refuse a DECISION whose bound `pack_root` is not the root of the pack the
//! estate actually admitted. That refusal is what makes the law bite: an in-place edit does not
//! silently reinterpret the decisions taken under it, it makes them unadmittable.
//!
//! Hard boundaries (enforced, not decorative):
//!   * A pack is admitted ONCE under its exact id; re-admitting a different body at the same id
//!     is refused, because supersession is a chain and an edit is not a version.
//!   * A decision naming a pack this estate never admitted is refused. Deciding against a
//!     document nobody holds is deciding against nothing.
//!   * An export naming a decision this estate never admitted is refused, for the same reason —
//!     an export is a manifest OVER evidence, not a way to introduce some.
//!   * Every read is tenant-scoped through the caller's own authorized scopes. A cross-tenant
//!     read answers the scope refusal, never a 404 existence oracle and never the record.
//!   * This plane mints no authority, performs no action and rewrites no workflow. It admits
//!     records and serves them back.

use std::sync::Arc;

use axum::extract::{Path as AxumPath, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde_json::{json, Value};

use ioi_types::app::generated::architecture_contracts::validate_architecture_contract;

use super::mutation_event_foundation::scope_refusal_reply;
use super::{persist_record, DaemonState};

type Reply = (StatusCode, Json<Value>);

const KIND_PACK: &str = "jurisdiction-policy-packs";
const KIND_DECISION: &str = "jurisdiction-policy-decisions";
const KIND_EXPORT: &str = "compliance-audit-exports";

const CONTRACT_PACK: &str = "schema://ioi/foundations/jurisdiction-policy-pack/v1";
const CONTRACT_DECISION: &str = "schema://ioi/foundations/jurisdiction-policy-decision/v1";
const CONTRACT_EXPORT: &str = "schema://ioi/foundations/compliance-audit-export-bundle/v1";

fn code(tail: &str) -> String {
    format!("hypervisor.jurisdiction.{tail}")
}

fn bad(status: StatusCode, tail: &str, detail: &str) -> Reply {
    (
        status,
        Json(json!({ "ok": false, "error": { "code": code(tail), "message": detail } })),
    )
}

fn refuse(tail: &str, detail: impl AsRef<str>) -> Reply {
    bad(StatusCode::UNPROCESSABLE_ENTITY, tail, detail.as_ref())
}

fn safe(segment: &str) -> String {
    segment.replace(
        |c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '_',
        "_",
    )
}

fn load(data_dir: &str, kind: &str, id: &str) -> Option<Value> {
    serde_json::from_slice(
        &std::fs::read(
            std::path::Path::new(data_dir)
                .join(kind)
                .join(format!("{}.json", safe(id))),
        )
        .ok()?,
    )
    .ok()
}

fn text(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

/// The owner a record is scoped to. A pack is scoped to the org that ISSUED it; a decision and an
/// export to the principal that recorded them. Nothing here is readable across that line.
fn owner_of(record: &Value) -> String {
    if let Some(issuer) = record.pointer("/issuer/issuer_ref").and_then(Value::as_str) {
        return issuer.to_string();
    }
    text(record, "recorded_by_ref")
}

/// WHO HOLDS A RECORD. Two ways, and both are needed. A pack is scoped to the ORG that issued it, so the
/// caller must hold that tenant. A decision or export is scoped to the PRINCIPAL that recorded it — and a
/// principal is not one of its own tenants, so a tenant-only predicate would lock every recorder out of
/// the records they just created. Checking only one of these admits records nobody can read.
fn holds(identity: &super::substrate_store::RequestIdentity, owner: &str) -> bool {
    !owner.is_empty() && (owner == identity.principal_ref || identity.authorizes_tenant(owner))
}

fn scope_refusal(error: super::substrate_store::RequestScopeRefusal) -> Reply {
    scope_refusal_reply(error)
}

/// Identity FIRST, then the record, then the scope. An unauthenticated caller is owed 401 and
/// never an existence oracle, and a caller outside the record's tenant is owed the scope refusal
/// rather than the record or a 404 that would leak whether it exists.
fn authorized(st: &DaemonState, headers: &HeaderMap, kind: &str, id: &str) -> Result<Value, Reply> {
    let identity = super::substrate_store::resolve_request_identity(&st.data_dir, headers)
        .map_err(scope_refusal)?;
    let Some(record) = load(&st.data_dir, kind, id) else {
        return Err(bad(
            StatusCode::NOT_FOUND,
            "absent",
            "no such record under this plane",
        ));
    };
    let owner = owner_of(&record);
    if !holds(&identity, &owner) {
        return Err(scope_refusal(
            super::substrate_store::RequestScopeRefusal::ResourceScopeRequired,
        ));
    }
    Ok(record)
}

fn admit(
    st: &DaemonState,
    headers: &HeaderMap,
    body: &Value,
    kind: &str,
    contract: &str,
    id_member: &str,
) -> Result<(super::substrate_store::RequestIdentity, Value, String), Reply> {
    let identity = super::substrate_store::resolve_request_identity(&st.data_dir, headers)
        .map_err(scope_refusal)?;
    if !body.is_object() {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "body_required",
            "the record to admit is a JSON object",
        ));
    }
    // THE RECORDER IS RESOLVED, NEVER ACCEPTED. A record scoped to an owner the caller chose is scoped to
    // nothing, and a record with NO owner admits successfully and is then readable by nobody — which is
    // what this plane did before the member existed, and what the unit's live leg caught. A caller-supplied
    // value is refused outright rather than corrected, on the same principle as the record seam's binding.
    let mut body = body.clone();
    if body.get("recorded_by_ref").is_some_and(|v| !v.is_null()) {
        return Err(refuse(
            "recorder_authored",
            "recorded_by_ref is resolved by this plane from the caller's own identity; a caller-authored recorder is refused, never corrected",
        ));
    }
    if id_member != "pack_id" {
        body["recorded_by_ref"] = json!(identity.principal_ref.clone());
    }
    let body = &body;
    // THE REGISTERED SHAPE DECIDES. Every refusal the contract can express — the `const
    // not_determined` legal-conformity claim, the typed exclusion reasons, the closed enforcing-owner
    // set, the sealed roots — is enforced here rather than restated.
    if let Err(reason) = validate_architecture_contract(contract, body) {
        return Err(refuse(
            "not_registered_valid",
            format!("this record does not satisfy {contract}: {reason}"),
        ));
    }
    let id = text(body, id_member);
    if id.is_empty() {
        return Err(refuse(
            "identity_absent",
            format!("{id_member} is the identity this plane admits under"),
        ));
    }
    // Only a CALLER-AUTHORED owner is checked here. The recorder this plane stamped is the caller by
    // construction, and re-checking it against the tenant set would refuse every record at the moment of
    // its creation — a principal is not one of its own tenants.
    let authored_owner = body
        .pointer("/issuer/issuer_ref")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if !authored_owner.is_empty() && !identity.authorizes_tenant(authored_owner) {
        return Err(scope_refusal(
            super::substrate_store::RequestScopeRefusal::ResourceScopeRequired,
        ));
    }
    if load(&st.data_dir, kind, &id).is_some() {
        return Err(refuse(
            "already_admitted",
            format!(
                "{id} is already admitted; supersession is a chain and an edit is not a version"
            ),
        ));
    }
    Ok((identity, body.clone(), id))
}

fn store(st: &DaemonState, kind: &str, id: &str, record: &Value) -> Result<(), Reply> {
    persist_record(&st.data_dir, kind, id, record).map_err(|error| {
        bad(
            StatusCode::INTERNAL_SERVER_ERROR,
            "not_persisted",
            &format!("the record could not be made durable: {error}"),
        )
    })
}

/// POST /v1/hypervisor/jurisdiction-policy-packs
pub(crate) async fn handle_pack_admit(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Reply {
    let (_identity, record, id) =
        match admit(&st, &headers, &body, KIND_PACK, CONTRACT_PACK, "pack_id") {
            Ok(value) => value,
            Err(reply) => return reply,
        };
    if let Err(reply) = store(&st, KIND_PACK, &id, &record) {
        return reply;
    }
    (
        StatusCode::OK,
        Json(json!({ "ok": true, "pack_id": id, "pack": record })),
    )
}

/// GET /v1/hypervisor/jurisdiction-policy-packs/:id
pub(crate) async fn handle_pack_get(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Reply {
    match authorized(&st, &headers, KIND_PACK, &id) {
        Ok(record) => (StatusCode::OK, Json(json!({ "ok": true, "pack": record }))),
        Err(reply) => reply,
    }
}

/// POST /v1/hypervisor/jurisdiction-policy-decisions
///
/// THE REFUSAL THIS ROUTE EXISTS FOR. A decision binds the pack's ROOT, not its name. If the pack
/// this estate admitted has a different root, the pack's content moved after the decision was
/// taken — which canon says must be a new version and must never rewrite a recorded decision. The
/// decision is refused rather than admitted against content it was never read under.
pub(crate) async fn handle_decision_admit(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Reply {
    let (_identity, record, id) = match admit(
        &st,
        &headers,
        &body,
        KIND_DECISION,
        CONTRACT_DECISION,
        "decision_id",
    ) {
        Ok(value) => value,
        Err(reply) => return reply,
    };
    let pack_ref = text(&record, "pack_ref");
    let Some(pack) = load(&st.data_dir, KIND_PACK, &pack_ref) else {
        return refuse(
            "pack_unadmitted",
            format!("no pack {pack_ref} is admitted here; deciding against a document nobody holds decides nothing"),
        );
    };
    if text(&record, "pack_version") != text(&pack, "version") {
        return refuse(
            "pack_version_moved",
            format!(
                "the decision was taken under version {} and the admitted pack reads {} — canon requires the EXACT version be retained",
                text(&record, "pack_version"),
                text(&pack, "version")
            ),
        );
    }
    if text(&record, "pack_root") != text(&pack, "pack_root") {
        return refuse(
            "pack_content_moved",
            "the admitted pack's content is not the content this decision was taken against; a change that should have been a new version is passing as the same one",
        );
    }
    if let Err(reply) = store(&st, KIND_DECISION, &id, &record) {
        return reply;
    }
    (
        StatusCode::OK,
        Json(json!({ "ok": true, "decision_id": id, "decision": record })),
    )
}

/// GET /v1/hypervisor/jurisdiction-policy-decisions/:id
pub(crate) async fn handle_decision_get(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Reply {
    match authorized(&st, &headers, KIND_DECISION, &id) {
        Ok(record) => (
            StatusCode::OK,
            Json(json!({ "ok": true, "decision": record })),
        ),
        Err(reply) => reply,
    }
}

/// POST /v1/hypervisor/compliance-audit-exports
///
/// An export is a MANIFEST OVER EVIDENCE THAT ALREADY EXISTS, so every decision it rests on must
/// already be admitted. An export naming a decision nobody holds would be introducing evidence
/// under the name of exporting it.
pub(crate) async fn handle_export_admit(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Reply {
    let (_identity, record, id) = match admit(
        &st,
        &headers,
        &body,
        KIND_EXPORT,
        CONTRACT_EXPORT,
        "export_id",
    ) {
        Ok(value) => value,
        Err(reply) => return reply,
    };
    for decision_ref in record
        .get("policy_decision_refs")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
    {
        let Some(reference) = decision_ref.as_str() else {
            continue;
        };
        // Only decisions of THIS plane are resolvable here; a receipt or policy ref is another
        // owner's and is carried, not resolved.
        if !reference.starts_with("jurisdiction_decision://") {
            continue;
        }
        if load(&st.data_dir, KIND_DECISION, reference).is_none() {
            return refuse(
                "decision_unadmitted",
                format!("the export rests on {reference}, which is not admitted here; an export is a manifest OVER evidence, not a way to introduce some"),
            );
        }
    }
    if let Err(reply) = store(&st, KIND_EXPORT, &id, &record) {
        return reply;
    }
    (
        StatusCode::OK,
        Json(json!({ "ok": true, "export_id": id, "export": record })),
    )
}

/// GET /v1/hypervisor/compliance-audit-exports/:id
pub(crate) async fn handle_export_get(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Reply {
    match authorized(&st, &headers, KIND_EXPORT, &id) {
        Ok(record) => (
            StatusCode::OK,
            Json(json!({ "ok": true, "export": record })),
        ),
        Err(reply) => reply,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pack(root: &str, version: &str) -> Value {
        json!({ "pack_id": "jurisdiction_policy_pack://x/1", "version": version, "pack_root": root,
                "issuer": { "issuer_ref": "org://ioi" } })
    }

    #[test]
    fn owner_is_the_issuer_for_a_pack_and_the_recorder_otherwise() {
        assert_eq!(owner_of(&pack("sha256:aa", "1.0.0")), "org://ioi");
        assert_eq!(
            owner_of(&json!({ "recorded_by_ref": "user://a" })),
            "user://a"
        );
        // A record naming neither is owned by nobody, and `authorized` refuses rather than serving it.
        assert_eq!(owner_of(&json!({})), "");
    }

    #[test]
    fn a_moved_pack_root_is_a_different_pack() {
        // The law canon states and only the plane can enforce: the decision binds the ROOT, so an
        // in-place edit makes the decision unadmittable rather than silently reinterpreting it.
        let admitted = pack("sha256:aa", "1.0.0");
        let decided_against = pack("sha256:bb", "1.0.0");
        assert_ne!(
            text(&admitted, "pack_root"),
            text(&decided_against, "pack_root")
        );
        assert_eq!(
            text(&admitted, "version"),
            text(&decided_against, "version")
        );
    }

    #[test]
    fn the_id_segment_never_escapes_its_family_directory() {
        assert_eq!(
            safe("jurisdiction_policy_pack://eu/ai-act"),
            "jurisdiction_policy_pack___eu_ai-act"
        );
        assert!(!safe("../../etc/passwd").contains('/'));
        assert!(!safe("..").contains('.'));
    }
}
