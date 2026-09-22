//! Regulated and sensitive-workload assurance plane (M09.9) — canonical contracts
//! `schema://ioi/foundations/regulated-workload-assurance-profile/v1` and
//! `schema://ioi/foundations/regulated-workload-admission-case/v1`
//! (docs/architecture/foundations/ecosystem-assurance-certification-liability.md).
//!
//! WHAT THIS PLANE IS. A profile DECLARES what a regulated workload must bind, as refs at exact
//! revisions, and restates nothing another owner already holds: residency, retention, deletion and
//! export belong to the bound `JurisdictionPolicyPack` (M06.10), and purpose, allowed uses, data
//! classes, redaction and egress belong to the bound `PolicyBoundDataView`. A profile that copied
//! any of those inline would be a second copy of a rule, free to drift from the policy it came
//! from. This plane reads both owners and writes to neither.
//!
//! THE CASE IS DERIVED HERE, NEVER ACCEPTED. A caller may POST only a `profile_ref`; the verdict,
//! the refusals and the seal are the plane's. A caller-authored case saying `admitted` would be
//! the subject grading its own homework, which is the same defect class as a caller-authored
//! `recorded_by_ref` — and this plane refuses that too, on M06.10's precedent.
//!
//! THE REFUSALS, AND WHY TWO OF THEM CANNOT LIVE IN A SCHEMA. `binding_missing` names a ref the
//! estate holds nothing at. `binding_stale` names one whose owner has moved past the revision the
//! profile pinned. `binding_substituted` names one whose CONTENT is not the content the profile
//! was written against — an in-place edit passing as the same version. Those three need the
//! ADMITTED record to compare against, and only the daemon holds it; a contract can seal a
//! profile, but it cannot know what the estate admitted. `binding_broader_than_purpose` compares
//! the bound view's own purpose with the workload's declared purpose.
//!
//! `binding_owner_absent` IS THIS UNIT'S NAMED ABSENCE, AND IT IS THE GATE WORKING. Measured
//! 2026-09-22: no plane in this estate resolves a `data_processor_terms`, a `key_control` or an
//! `access_log_binding`, under any name searched. They are required on the profile anyway, because
//! canon places those obligations on a regulated workload, so every regulated admission is refused
//! by name until each owner lands. A regulated workload SHOULD be refused while the estate cannot
//! log access to it; the alternative is a green profile that admits one that cannot be audited.
//!
//! Hard boundaries (enforced, not decorative):
//!   * A profile is admitted ONCE under its exact id; supersession is a chain and an edit is not
//!     a version.
//!   * A case names the profile ROOT it was evaluated against, so editing a binding in place
//!     breaks every recorded case instead of silently rewriting what they decided.
//!   * Every read is tenant-scoped through the caller's own identity. A cross-tenant read answers
//!     the scope refusal, never the record and never a 404 existence oracle.
//!   * This plane mints no authority and performs no action. A refusal quarantines nothing and
//!     revokes nothing; those verbs belong to the owners the profile binds.

use std::sync::Arc;

use axum::extract::{Path as AxumPath, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde_json::{json, Map, Value};

use ioi_types::app::generated::architecture_contracts::validate_architecture_contract;

use super::mutation_event_foundation::scope_refusal_reply;
use super::{persist_record, DaemonState};

type Reply = (StatusCode, Json<Value>);

const KIND_PROFILE: &str = "regulated-workload-assurance-profiles";
const KIND_CASE: &str = "regulated-workload-admission-cases";
const KIND_PACK: &str = "jurisdiction-policy-packs";
const KIND_VIEW: &str = "odk-policy-bound-data-views";

const CONTRACT_PROFILE: &str = "schema://ioi/foundations/regulated-workload-assurance-profile/v1";
const CONTRACT_CASE: &str = "schema://ioi/foundations/regulated-workload-admission-case/v1";

/// The profile members the root seals, in the contract's own order. `recorded_by_ref` is absent
/// deliberately: the caller seals the profile before the server stamps the recorder.
const PROFILE_MATERIAL: [&str; 13] = [
    "schema_version",
    "profile_id",
    "version",
    "issued_at",
    "supersedes_ref",
    "subject",
    "policy_bindings",
    "route_bindings",
    "custody_bindings",
    "operational_bindings",
    "unowned_bindings",
    "grants_no_authority",
    "is_not_legal_advice",
];

const CASE_MATERIAL: [&str; 11] = [
    "schema_version",
    "case_id",
    "profile_ref",
    "profile_version",
    "profile_root",
    "evaluated_at",
    "verdict",
    "refusals",
    "legal_conformity_claim",
    "grants_no_authority",
    "performs_no_action",
];

/// The three bindings canon requires and nothing in this estate resolves.
const UNOWNED: [(&str, &str); 3] = [
    (
        "data_processor_terms_ref",
        "no plane in this estate resolves a data_processor_terms ref, so the processor terms this workload runs under cannot be verified",
    ),
    (
        "key_control_ref",
        "no plane in this estate resolves a key_control ref, so who controls the keys over this workload's data cannot be verified",
    ),
    (
        "access_log_binding_ref",
        "no plane in this estate resolves an access_log_binding ref, so reads against this workload's bound view cannot be logged",
    ),
];

fn code(tail: &str) -> String {
    format!("hypervisor.regulated-workload.{tail}")
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

fn at(value: &Value, pointer: &str) -> String {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

/// SHA-256 over JCS of the named members, in the same shape the registered invariant recomputes.
/// A seal the plane computes differently from the way the contract checks it is not a seal.
fn seal(record: &Value, members: &[&str]) -> Result<String, Reply> {
    let mut material = Map::new();
    for member in members {
        material.insert(
            (*member).to_string(),
            record.get(*member).cloned().unwrap_or(Value::Null),
        );
    }
    let bytes = serde_jcs::to_vec(&Value::Object(material)).map_err(|error| {
        bad(
            StatusCode::INTERNAL_SERVER_ERROR,
            "not_sealed",
            &format!("the record could not be canonicalised: {error}"),
        )
    })?;
    Ok(format!(
        "sha256:{:x}",
        <sha2::Sha256 as sha2::Digest>::digest(&bytes)
    ))
}

fn scope_refusal(error: super::substrate_store::RequestScopeRefusal) -> Reply {
    scope_refusal_reply(error)
}

/// A principal is not one of its own tenants, so both branches are needed: a record scoped to the
/// principal that recorded it would otherwise be readable by nobody. M06.10 learned this the hard
/// way one unit earlier.
fn holds(identity: &super::substrate_store::RequestIdentity, owner: &str) -> bool {
    !owner.is_empty() && (owner == identity.principal_ref || identity.authorizes_tenant(owner))
}

/// Identity FIRST, then the record, then the scope. An unauthenticated caller is owed 401 and
/// never an existence oracle.
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
    if !holds(&identity, &text(&record, "recorded_by_ref")) {
        return Err(scope_refusal(
            super::substrate_store::RequestScopeRefusal::ResourceScopeRequired,
        ));
    }
    Ok(record)
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

fn refusal(reason: &str, member: &str, detail: &str) -> Value {
    json!({ "reason": reason, "member": member, "detail": detail })
}

/// THE EVALUATION. Every refusal names the exact profile member it is about, dotted from the
/// profile root, so the owner can act on it rather than guess.
pub(crate) fn evaluate(profile: &Value, pack: Option<&Value>, view: Option<&Value>) -> Vec<Value> {
    let mut out = Vec::new();

    let pack_ref = at(profile, "/policy_bindings/jurisdiction_policy_pack_ref");
    match pack {
        None => out.push(refusal(
            "binding_missing",
            "policy_bindings.jurisdiction_policy_pack_ref",
            &format!("this estate holds no admitted jurisdiction policy pack at {pack_ref}"),
        )),
        Some(pack) => {
            let bound = at(profile, "/policy_bindings/jurisdiction_policy_pack_version");
            let admitted = text(pack, "version");
            if bound != admitted {
                out.push(refusal(
                    "binding_stale",
                    "policy_bindings.jurisdiction_policy_pack_version",
                    &format!(
                        "the profile pins pack version {bound} and the admitted pack reads {admitted}"
                    ),
                ));
            }
        }
    }

    let view_ref = at(profile, "/policy_bindings/policy_bound_data_view_ref");
    match view {
        None => out.push(refusal(
            "binding_missing",
            "policy_bindings.policy_bound_data_view_ref",
            &format!("this estate holds no admitted policy-bound data view at {view_ref}"),
        )),
        Some(view) => {
            let bound = at(
                profile,
                "/policy_bindings/policy_bound_data_view_revision_ref",
            );
            let admitted = text(view, "revision_ref");
            if bound != admitted {
                out.push(refusal(
                    "binding_stale",
                    "policy_bindings.policy_bound_data_view_revision_ref",
                    &format!(
                        "the profile pins view revision {bound} and the view's current revision is {admitted}"
                    ),
                ));
            }
            // THE PURPOSE COMPARISON. This plane cannot rank two prose statements for breadth, so
            // it requires the bound view's purpose to BE the workload's declared purpose. A view
            // created for some other purpose may be broader than what this workload declared, and
            // binding it would let a workload read under a purpose it never stated.
            let declared = at(profile, "/subject/declared_purpose");
            let view_purpose = text(view, "purpose");
            if declared != view_purpose {
                out.push(refusal(
                    "binding_broader_than_purpose",
                    "policy_bindings.policy_bound_data_view_ref",
                    "the bound view's purpose is not the workload's declared purpose; this plane requires them to be identical because it cannot rank prose for breadth, and a view built for another purpose may be wider than what this workload declared",
                ));
            }
        }
    }

    // THE NAMED ABSENCE. Unconditional, because nothing resolves these refs anywhere in the estate.
    for (member, detail) in UNOWNED {
        out.push(refusal(
            "binding_owner_absent",
            &format!("unowned_bindings.{member}"),
            detail,
        ));
    }

    out
}

/// POST /v1/hypervisor/regulated-workload-assurance-profiles
pub(crate) async fn handle_profile_admit(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Reply {
    let identity = match super::substrate_store::resolve_request_identity(&st.data_dir, &headers) {
        Ok(value) => value,
        Err(error) => return scope_refusal(error),
    };
    if !body.is_object() {
        return bad(
            StatusCode::BAD_REQUEST,
            "body_required",
            "the profile to admit is a JSON object",
        );
    }
    let mut record = body.clone();
    if record
        .get("recorded_by_ref")
        .is_some_and(|value| !value.is_null())
    {
        return refuse(
            "recorder_authored",
            "recorded_by_ref is resolved by this plane from the caller's own identity; a caller-authored recorder is refused, never corrected",
        );
    }
    record["recorded_by_ref"] = json!(identity.principal_ref.clone());
    if let Err(reason) = validate_architecture_contract(CONTRACT_PROFILE, &record) {
        return refuse(
            "not_registered_valid",
            format!("this profile does not satisfy {CONTRACT_PROFILE}: {reason}"),
        );
    }
    let id = text(&record, "profile_id");
    if load(&st.data_dir, KIND_PROFILE, &id).is_some() {
        return refuse(
            "already_admitted",
            format!(
                "{id} is already admitted; supersession is a chain and an edit is not a version"
            ),
        );
    }
    if let Err(reply) = store(&st, KIND_PROFILE, &id, &record) {
        return reply;
    }
    (
        StatusCode::OK,
        Json(json!({ "ok": true, "profile_id": id, "profile": record })),
    )
}

/// GET /v1/hypervisor/regulated-workload-assurance-profiles/:id
pub(crate) async fn handle_profile_get(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Reply {
    match authorized(&st, &headers, KIND_PROFILE, &id) {
        Ok(record) => (
            StatusCode::OK,
            Json(json!({ "ok": true, "profile": record })),
        ),
        Err(reply) => reply,
    }
}

/// POST /v1/hypervisor/regulated-workload-admission-cases
///
/// The caller supplies a `profile_ref` and nothing else. The verdict is this plane's, because a
/// caller-authored verdict is the subject grading its own homework.
pub(crate) async fn handle_case_admit(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Reply {
    let identity = match super::substrate_store::resolve_request_identity(&st.data_dir, &headers) {
        Ok(value) => value,
        Err(error) => return scope_refusal(error),
    };
    if body.get("verdict").is_some() || body.get("refusals").is_some() {
        return refuse(
            "verdict_authored",
            "the verdict and its refusals are derived by this plane from what the estate admitted; a caller-authored verdict is refused, never corrected",
        );
    }
    let profile_ref = text(&body, "profile_ref");
    let Some(profile) = load(&st.data_dir, KIND_PROFILE, &profile_ref) else {
        return refuse(
            "profile_unadmitted",
            format!("no profile {profile_ref} is admitted here; evaluating a profile nobody holds evaluates nothing"),
        );
    };
    if !holds(&identity, &text(&profile, "recorded_by_ref")) {
        return scope_refusal(super::substrate_store::RequestScopeRefusal::ResourceScopeRequired);
    }

    let pack = load(
        &st.data_dir,
        KIND_PACK,
        &at(&profile, "/policy_bindings/jurisdiction_policy_pack_ref"),
    );
    let view = load(
        &st.data_dir,
        KIND_VIEW,
        &at(&profile, "/policy_bindings/policy_bound_data_view_ref"),
    );
    let refusals = evaluate(&profile, pack.as_ref(), view.as_ref());

    // THE PROFILE ROOT IS RECOMPUTED, NEVER READ. The member the profile carries is what its
    // author claimed; a case that copied it would bind the claim rather than the content, and an
    // in-place edit would go unnoticed by exactly the record meant to catch it.
    let recomputed = match seal(&profile, &PROFILE_MATERIAL) {
        Ok(value) => value,
        Err(reply) => return reply,
    };
    let mut refusals = refusals;
    if recomputed != text(&profile, "profile_root") {
        refusals.insert(
            0,
            refusal(
                "binding_substituted",
                "profile_root",
                "the admitted profile's content does not recompute to the root it carries; a change that should have been a new version is passing as the same one",
            ),
        );
    }

    let case_id = format!(
        "regulated_workload_admission_case://{}",
        hex_tail(&format!("{profile_ref}|{recomputed}"))
    );
    let mut record = json!({
        "schema_version": "ioi.foundations.regulated-workload-admission-case.v1",
        "case_id": case_id,
        "profile_ref": profile_ref,
        "profile_version": text(&profile, "version"),
        "profile_root": recomputed,
        "evaluated_at": now_rfc3339(),
        "verdict": if refusals.is_empty() { "admitted" } else { "refused" },
        "refusals": refusals,
        "legal_conformity_claim": "not_determined",
        "grants_no_authority": true,
        "performs_no_action": true,
    });
    let case_root = match seal(&record, &CASE_MATERIAL) {
        Ok(value) => value,
        Err(reply) => return reply,
    };
    record["recorded_by_ref"] = json!(identity.principal_ref.clone());
    record["case_root"] = json!(case_root);

    if let Err(reason) = validate_architecture_contract(CONTRACT_CASE, &record) {
        return refuse(
            "not_registered_valid",
            format!("this plane derived a case that does not satisfy {CONTRACT_CASE}: {reason}"),
        );
    }
    let id = text(&record, "case_id");
    if let Err(reply) = store(&st, KIND_CASE, &id, &record) {
        return reply;
    }
    (
        StatusCode::OK,
        Json(json!({ "ok": true, "case_id": id, "case": record })),
    )
}

/// GET /v1/hypervisor/regulated-workload-admission-cases/:id
pub(crate) async fn handle_case_get(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Reply {
    match authorized(&st, &headers, KIND_CASE, &id) {
        Ok(record) => (StatusCode::OK, Json(json!({ "ok": true, "case": record }))),
        Err(reply) => reply,
    }
}

fn hex_tail(material: &str) -> String {
    format!(
        "{:x}",
        <sha2::Sha256 as sha2::Digest>::digest(material.as_bytes())
    )
}

/// The instant this plane evaluated, in the exact shape the contract's timestamp pattern accepts.
/// Seconds resolution and a `Z` offset, because a case that cannot satisfy its own contract is a
/// case this plane would refuse after deriving it.
fn now_rfc3339() -> String {
    let now = time::OffsetDateTime::now_utc();
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        now.year(),
        u8::from(now.month()),
        now.day(),
        now.hour(),
        now.minute(),
        now.second()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile() -> Value {
        json!({
            "policy_bindings": {
                "jurisdiction_policy_pack_ref": "jurisdiction_policy_pack://acme/us-hipaa/v4",
                "jurisdiction_policy_pack_version": "4.2.0",
                "policy_bound_data_view_ref": "policy_bound_data_view://acme/claims",
                "policy_bound_data_view_revision_ref": "revision://acme/claims/17"
            },
            "subject": { "declared_purpose": "Adjudicate submitted health claims." }
        })
    }

    fn reasons(rows: &[Value]) -> Vec<String> {
        rows.iter()
            .map(|row| text(row, "reason"))
            .collect::<Vec<_>>()
    }

    #[test]
    fn an_absent_owner_is_named_for_each_of_the_three_unowned_bindings() {
        let pack = json!({ "version": "4.2.0" });
        let view = json!({
            "revision_ref": "revision://acme/claims/17",
            "purpose": "Adjudicate submitted health claims."
        });
        let rows = evaluate(&profile(), Some(&pack), Some(&view));
        // EXACTLY three, and all of them owner-absent: every other binding is current, so this is
        // the unit's named absence standing alone rather than hiding a second defect.
        assert_eq!(rows.len(), 3, "{rows:?}");
        assert!(reasons(&rows)
            .iter()
            .all(|reason| reason == "binding_owner_absent"));
        let members = rows
            .iter()
            .map(|row| text(row, "member"))
            .collect::<Vec<_>>();
        assert!(members.contains(&"unowned_bindings.access_log_binding_ref".to_string()));
        assert!(members.contains(&"unowned_bindings.key_control_ref".to_string()));
        assert!(members.contains(&"unowned_bindings.data_processor_terms_ref".to_string()));
    }

    #[test]
    fn a_pack_the_estate_never_admitted_is_missing_not_stale() {
        let view = json!({
            "revision_ref": "revision://acme/claims/17",
            "purpose": "Adjudicate submitted health claims."
        });
        let rows = evaluate(&profile(), None, Some(&view));
        assert!(rows
            .iter()
            .any(|row| text(row, "reason") == "binding_missing"
                && text(row, "member") == "policy_bindings.jurisdiction_policy_pack_ref"));
    }

    #[test]
    fn an_owner_that_moved_past_the_pinned_revision_is_stale() {
        let pack = json!({ "version": "4.3.0" });
        let view = json!({
            "revision_ref": "revision://acme/claims/18",
            "purpose": "Adjudicate submitted health claims."
        });
        let rows = evaluate(&profile(), Some(&pack), Some(&view));
        let stale = rows
            .iter()
            .filter(|row| text(row, "reason") == "binding_stale")
            .count();
        assert_eq!(
            stale, 2,
            "both the pack version and the view revision moved: {rows:?}"
        );
    }

    #[test]
    fn a_view_built_for_another_purpose_is_refused_as_broader() {
        let pack = json!({ "version": "4.2.0" });
        let view = json!({
            "revision_ref": "revision://acme/claims/17",
            "purpose": "Adjudicate claims and produce secondary analytics."
        });
        let rows = evaluate(&profile(), Some(&pack), Some(&view));
        assert!(rows
            .iter()
            .any(|row| text(row, "reason") == "binding_broader_than_purpose"));
    }
}
