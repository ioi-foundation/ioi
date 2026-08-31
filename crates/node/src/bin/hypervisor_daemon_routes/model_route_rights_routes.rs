//! M07.2 — the route-rights half of the compiled learning boundary, as owner-scoped runtime.
//!
//! `ModelRouteRightsContract` v1 becomes an immutable, owner-qualified, content-addressed revision
//! on the canonical Agentgres chain, and publishes ONE read-only resolver so M10.3 can intersect
//! against a route contract it did not shape-check itself.
//!
//! WHY THE SHARED FAMILY MACHINERY LIVES HERE. M10.3 `depends_on` M07.2, so the route-rights module
//! is the lower half of that edge and the natural owner of the chain machinery both halves share.
//! Putting it here means the learning-boundary module imports one implementation of "project the
//! chain, re-derive the commitment, compare" rather than growing a second interpretation of the
//! same rule. The ADMISSION boundary itself is not re-implemented at all: every write crosses
//! `mutation_event_foundation`, which remains the single owner-scoped admission spine.
//!
//! THE FAIL-CLOSED PARTITION IS DERIVED, NOT VALIDATED. A caller supplies the prohibitions its
//! terms state affirmatively and the findings for the rights it could not resolve. The server
//! derives `unresolved_route_uses` as the exact projection of those findings, derives
//! `prohibited_route_uses` as their disjoint union with the declared prohibitions, and derives
//! `permitted_route_uses` as the vocabulary MINUS that set. A caller therefore cannot permit a use
//! it has just recorded an unresolved finding for: the permission is a subtraction, not a field.
//! This is INV-37 in the shape canon asks for — the admitting core resolves the value it checks
//! instead of reading one the requester wrote into the request.
//!
//! REVOCATION AND EXPIRY EMPTY THE PERMISSION BY CONSTRUCTION. The registered contract pins
//! `permitted_route_uses` empty whenever `status` is not `active` or the revocation state is
//! `suspended`/`revoked`. Rather than let that conditional turn a well-meant admission into an
//! opaque schema refusal, the server moves every otherwise-permitted use into a synthesized
//! finding carrying `revoked` or `expired` and the authority that did it. The record then says WHY
//! each use is unavailable instead of merely that it is, and the partition still closes.
//!
//! A ROUTE-RIGHTS CONTRACT GRANTS NOTHING. It is a resolved reading of terms, not authority, not
//! provider behaviour, and not proof that a credential's possessor may do what the credential
//! makes technically possible. Those non-claims ride in the record's own `does_not_assert`.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, OnceLock};

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use agentgres::mux::ExactProjection;
use ioi_types::app::generated::architecture_contracts::validate_architecture_contract;

use super::mutation_event_foundation::{
    admit_owner_scoped_mutation, admitted_stamp, mutation_refusal_reply,
    prior_admission_for_key_on_stream, read_owner_scoped_history, require_write_caller,
    scope_refusal_reply, stream_tail, ScopedMutation, WriteCaller,
};
use super::substrate_store::{
    authorize_request_resource_scope, authorized_request_resource_refs,
    bind_request_resource_scope, resolve_request_identity, RequestIdentity, RequestResourceScope,
};
use super::DaemonState;

pub(crate) type Reply = (StatusCode, Json<Value>);

pub(crate) fn bad(status: StatusCode, code: &str, message: impl Into<String>) -> Reply {
    (
        status,
        Json(json!({ "ok": false, "error": { "code": code, "message": message.into() } })),
    )
}

pub(crate) fn refuse(code: &str, message: impl Into<String>) -> Reply {
    bad(StatusCode::UNPROCESSABLE_ENTITY, code, message)
}

pub(crate) fn sha256_of(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

pub(crate) fn is_sha256(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..].bytes().all(|byte| byte.is_ascii_hexdigit())
        && value[7..].bytes().all(|byte| !byte.is_ascii_uppercase())
}

/// JCS-SHA256 over a flat material map, exactly as every registered `jcs_sha256_equals` rule in
/// this estate defines it: a `domain` constant plus one entry per committed field.
pub(crate) fn digest_over(record: &Value, domain: &str, fields: &[&str]) -> Result<String, String> {
    let mut material = Map::new();
    material.insert("domain".into(), json!(domain));
    for field in fields {
        let value = record
            .get(*field)
            .ok_or_else(|| format!("commitment material is missing {field}"))?;
        material.insert((*field).to_string(), value.clone());
    }
    serde_jcs::to_vec(&Value::Object(material))
        .map(|bytes| sha256_of(&bytes))
        .map_err(|error| format!("commitment could not be canonicalized: {error}"))
}

/// `[a-z0-9][a-z0-9._-]{0,127}` — the family token every one of these contracts pins.
pub(crate) fn family_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

/// Parse `<scheme>://<family>/revision/<n>` strictly and totally.
///
/// STRICT, because a consumer is about to BIND whatever comes out of here. Percent-escapes,
/// backslashes, query/fragment tails, extra segments, a non-canonical family token and any ordinal
/// that is signed, zero, zero-padded, oversized or not a bare digit run are all REFUSED rather than
/// repaired: two spellings that resolve to one revision would let a compilation claim it intersected
/// something other than what it intersected. The mandatory `/revision/` segment is also what refuses
/// a family-head or mutable-latest reference wherever a revision is required.
pub(crate) fn parse_revision_ref(scheme: &str, value: &str) -> Option<(String, u64)> {
    if value.len() > 320
        || value.bytes().any(|byte| {
            byte.is_ascii_whitespace()
                || byte.is_ascii_control()
                || !byte.is_ascii()
                || matches!(byte, b'?' | b'#' | b'\\' | b'%')
        })
    {
        return None;
    }
    let mut segments = value.strip_prefix(scheme)?.split('/');
    let family = segments.next()?;
    let marker = segments.next()?;
    let ordinal = segments.next()?;
    if segments.next().is_some() || marker != "revision" || !family_token(family) {
        return None;
    }
    if ordinal.is_empty()
        || ordinal.len() > 9
        || ordinal.starts_with('0')
        || !ordinal.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    let ordinal: u64 = ordinal.parse().ok()?;
    (ordinal > 0).then(|| (family.to_owned(), ordinal))
}

/// The contract tenancy, DERIVED from the owner the substrate already authorized.
///
/// The substrate's owner and tenant refs are one value (`org://local`); these contracts carry a
/// `tenant://…` token whose charset excludes `/`. The mapping is total and deterministic, so a
/// caller cannot choose its own tenancy — which is what makes a cross-tenant binding a fact the
/// compiler can CHECK rather than one it has to trust.
pub(crate) fn contract_tenant_ref(owner_ref: &str) -> String {
    let mut token = String::with_capacity(owner_ref.len());
    for byte in owner_ref.bytes() {
        match byte {
            b':' => {}
            b'/' => {
                if !token.ends_with('.') {
                    token.push('.');
                }
            }
            b if b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-') => {
                token.push(b as char)
            }
            _ => token.push('-'),
        }
    }
    format!("tenant://{}", token.trim_matches('.'))
}

/// The owner schemes these contracts admit, verbatim from the registered `ownerRef` pattern.
pub(crate) const CONTRACT_OWNER_SCHEMES: &[&str] =
    &["org://", "user://", "system://", "project://", "domain://"];

pub(crate) fn contract_owner_ref(owner_ref: &str, code: &str) -> Result<(), Reply> {
    if CONTRACT_OWNER_SCHEMES
        .iter()
        .any(|scheme| owner_ref.starts_with(scheme))
        && owner_ref.len() <= 200
    {
        return Ok(());
    }
    Err(refuse(
        code,
        "these contracts admit an owner in org://, user://, system://, project:// or domain://; an owner this build cannot express is a typed refusal, never a rewritten one",
    ))
}

// ------------------------------------------------------------------------------- family descriptor

/// Everything that differs between the families, so the chain machinery below is written ONCE.
pub(crate) struct FamilySpec {
    pub(crate) owner_namespace: &'static str,
    pub(crate) resource_kind: &'static str,
    pub(crate) admit_op: &'static str,
    pub(crate) payload_schema: &'static str,
    pub(crate) contract_id: &'static str,
    pub(crate) schema_version: &'static str,
    pub(crate) record_key: &'static str,
    pub(crate) code_prefix: &'static str,
    pub(crate) commitment_domain: &'static str,
    pub(crate) material_fields: &'static [&'static str],
    /// The record field carrying the identity this family's projection must agree with.
    pub(crate) identity_field: &'static str,
    /// The `<scheme>://` this family's refs are spelled in.
    pub(crate) ref_scheme: &'static str,
    /// The record field carrying this family's own admission stamp. Revisioned families call it
    /// `admitted_at`; a receipt calls it `emitted_at`. Naming it here rather than hardcoding one
    /// spelling is what stops the projector from silently skipping the check on the family whose
    /// field it does not know.
    pub(crate) stamp_field: &'static str,
}

impl FamilySpec {
    pub(crate) fn code(&self, suffix: &str) -> String {
        format!("{}_{suffix}", self.code_prefix)
    }

    pub(crate) fn content_hash(&self, record: &Value) -> Result<String, String> {
        digest_over(record, self.commitment_domain, self.material_fields)
    }
}

/// One admitted record, exactly as the chain holds it, plus the admission facts that live BESIDE it.
///
/// These contracts are `additionalProperties: false`, so admission cannot be stapled inside the
/// record. That is an improvement, not a limitation: the stored bytes are the registered contract
/// and nothing else, and the admission coordinates are reported alongside where a reader can see
/// they are the chain's facts rather than the record's claims.
pub(crate) struct AdmittedRecord {
    pub(crate) record: Value,
    pub(crate) admission: Value,
    pub(crate) head: String,
    pub(crate) recorded_at_ms: u64,
}

fn entry_resource(payload: &Value) -> &str {
    payload
        .get("resource_ref")
        .and_then(Value::as_str)
        .unwrap_or_default()
}

pub(crate) fn project_admitted(
    spec: &FamilySpec,
    entry: &ExactProjection,
) -> Result<AdmittedRecord, String> {
    if entry.operation.op_kind != spec.admit_op {
        return Err(format!(
            "{} stream carries an unknown operation '{}'",
            spec.code_prefix, entry.operation.op_kind
        ));
    }
    let payload = &entry.operation.payload;
    if payload.get("schema_version").and_then(Value::as_str) != Some(spec.payload_schema) {
        return Err(format!(
            "{} admission carries an unknown payload schema",
            spec.code_prefix
        ));
    }
    let record = payload
        .get(spec.record_key)
        .cloned()
        .ok_or_else(|| format!("{} admission carries no record", spec.code_prefix))?;
    // The read side refuses an unknown contract version too: a frame written by a build this one
    // does not implement is reported unreadable rather than projected as though it were current.
    if record.get("schema_version").and_then(Value::as_str) != Some(spec.schema_version) {
        return Err(format!(
            "{} chain holds a record this build does not implement (expected {})",
            spec.code_prefix, spec.schema_version
        ));
    }
    // The served commitment is RE-DERIVED, never trusted: a tampered frame or a rebuilt index
    // cannot make this module serve bytes that do not hash to what they claim.
    let derived = spec.content_hash(&record)?;
    if record.get("content_hash").and_then(Value::as_str) != Some(derived.as_str()) {
        return Err(format!(
            "{} admitted content does not match its committed hash",
            spec.code_prefix
        ));
    }
    // The admission stamp is inside the commitment, so it must be the stamp the admitted operation
    // actually carries. A record whose `admitted_at` drifted from its own admission would be a
    // wall-clock stamp wearing an admission's clothes.
    let stamped = admitted_stamp(entry.operation.recorded_at_ms);
    if record.get(spec.stamp_field).and_then(Value::as_str) != Some(stamped.as_str()) {
        return Err(format!(
            "{} record's {} is not the stamp of its own admission",
            spec.code_prefix, spec.stamp_field
        ));
    }
    validate_architecture_contract(spec.contract_id, &record).map_err(|reason| {
        format!(
            "projected {} is not registered-valid: {reason}",
            spec.code_prefix
        )
    })?;
    let tail = stream_tail(spec.resource_kind, entry_resource(payload));
    let admission = json!({
        "owner_namespace": spec.owner_namespace,
        "stream_tail": tail,
        "admission_domain_ref": format!(
            "agentgres://domain/{}",
            agentgres::refs::event_stream_domain(spec.owner_namespace, &tail)
        ),
        "agentgres_operation_ref": agentgres::refs::event_stream_operation_ref(
            spec.owner_namespace, &tail, entry.seq, &entry.head,
        ),
        "agentgres_receipt_ref": agentgres::refs::event_stream_receipt_ref(
            spec.owner_namespace, &tail, entry.admission_batch_seq, &entry.admission_root,
        ),
        "admission_seq": entry.seq,
        "admission_head": entry.head,
        "admission_root": entry.admission_root,
        "expected_predecessor_head": entry
            .operation
            .expected_head
            .clone()
            .map_or(Value::Null, Value::String),
    });
    Ok(AdmittedRecord {
        record,
        admission,
        head: entry.head.clone(),
        recorded_at_ms: entry.operation.recorded_at_ms,
    })
}

pub(crate) fn project_stream(
    spec: &FamilySpec,
    history: &[ExactProjection],
) -> Result<Vec<AdmittedRecord>, String> {
    history
        .iter()
        .map(|entry| project_admitted(spec, entry))
        .collect()
}

pub(crate) fn read_stream(
    spec: &FamilySpec,
    data_dir: &str,
    identity: &RequestIdentity,
    scope: &RequestResourceScope,
    resource: &str,
) -> Result<Vec<AdmittedRecord>, Reply> {
    let history = read_owner_scoped_history(
        data_dir,
        identity,
        scope,
        spec.resource_kind,
        resource,
        spec.owner_namespace,
        &stream_tail(spec.resource_kind, resource),
    )
    .map_err(mutation_refusal_reply)?;
    project_stream(spec, &history).map_err(|reason| {
        bad(
            StatusCode::BAD_GATEWAY,
            &spec.code("projection_failed"),
            reason,
        )
    })
}

pub(crate) fn authorized_stream(
    spec: &FamilySpec,
    data_dir: &str,
    identity: &RequestIdentity,
    resource: &str,
) -> Result<Vec<AdmittedRecord>, Reply> {
    let scope =
        authorize_request_resource_scope(data_dir, identity, spec.resource_kind, resource, None)
            .map_err(scope_refusal_reply)?;
    read_stream(spec, data_dir, identity, &scope, resource)
}

// ------------------------------------------------------- rebuildable, process-local, never an answer

static PROJECTION_CACHE: OnceLock<Mutex<BTreeMap<String, (String, usize)>>> = OnceLock::new();

/// Report what the cache held BEFORE the freshly projected stream replaced it.
///
/// The stream is already computed when this is called, so the cache cannot contribute to the
/// answer. Reporting it lets a verifier assert index rebuild by POSITIVE detection: an unchanged
/// answer is also consistent with a cache that was never dropped, which would prove nothing.
pub(crate) fn projection_cache_state(key: &str, stream: &[AdmittedRecord]) -> &'static str {
    let observed = (
        stream
            .last()
            .map(|last| last.head.clone())
            .unwrap_or_default(),
        stream.len(),
    );
    let Ok(mut cache) = PROJECTION_CACHE
        .get_or_init(|| Mutex::new(BTreeMap::new()))
        .lock()
    else {
        return "unavailable_rebuilt_from_agentgres";
    };
    let state = match cache.get(key) {
        None => "rebuilt_from_agentgres",
        Some(held) if *held == observed => "agreed_with_agentgres",
        Some(_) => "stale_rebuilt_from_agentgres",
    };
    cache.insert(key.to_string(), observed);
    state
}

// ------------------------------------------------------------------------- caller-authored evidence

/// Fields the SERVER resolves. A caller may assert them through an `expected_*` twin and be refused
/// by name; writing them directly is INV-37's exact failure mode and is refused before anything is
/// read.
pub(crate) fn reject_authored(
    body: &Value,
    spec: &FamilySpec,
    authored: &[&str],
) -> Result<(), Reply> {
    for field in authored {
        if body.get(*field).is_some() {
            return Err(refuse(
                &spec.code("caller_authored_evidence_refused"),
                format!(
                    "'{field}' is resolved by the server from the durable predecessor, the owner seams and the admitted operation; assert it through its expected_* twin instead of authoring it"
                ),
            ));
        }
    }
    Ok(())
}

pub(crate) fn head_assertion(body: &Value, code_prefix: &str) -> Result<Option<String>, Reply> {
    match body.get("expected_head") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => Err(refuse(
            &format!("{code_prefix}_expected_head_not_canonical"),
            "expected_head is the exact current Agentgres head of this stream, or null for the first admission",
        )),
    }
}

/// Exact-head admission, checked here so the refusal names the family fact rather than surfacing as
/// a bare substrate conflict. The substrate compare-and-swap remains the authority.
pub(crate) fn require_exact_head(
    stream: &[AdmittedRecord],
    expected_head: &Option<String>,
    code_prefix: &str,
) -> Result<(), Reply> {
    let current = stream.last().map(|last| last.head.clone());
    if *expected_head == current {
        return Ok(());
    }
    Err(bad(
        StatusCode::CONFLICT,
        &format!("{code_prefix}_expected_head_conflict"),
        match (expected_head, &current) {
            (None, Some(_)) => {
                "this stream already has admissions; a successor names the exact current head"
            }
            (Some(_), None) => {
                "this stream has no admissions yet; the first names no predecessor head"
            }
            _ => "expected_head does not name the exact current head of this stream; re-read the head and re-derive the record",
        },
    ))
}

/// A retry of the SAME key resolves to the record it already admitted, rather than minting a second
/// one. The substrate owns replay; this only reaches the answer it holds.
#[allow(clippy::too_many_arguments)]
pub(crate) fn replay_for_key(
    spec: &FamilySpec,
    st: &DaemonState,
    caller: &WriteCaller,
    scope: &RequestResourceScope,
    resource: &str,
    stream: &[AdmittedRecord],
    reply_key: &str,
) -> Result<Option<Reply>, Reply> {
    match prior_admission_for_key_on_stream(
        &st.data_dir,
        &caller.identity,
        scope,
        spec.resource_kind,
        resource,
        spec.owner_namespace,
        &stream_tail(spec.resource_kind, resource),
        &caller.idempotency_key,
    ) {
        Ok(Some(prior)) => {
            let Some(entry) = stream.iter().find(|entry| entry.head == prior.head) else {
                return Err(bad(
                    StatusCode::BAD_GATEWAY,
                    &spec.code("projection_disagrees_with_ack"),
                    "this key's admitted head is absent from this stream's projection",
                ));
            };
            Ok(Some((
                StatusCode::OK,
                Json(json!({
                    "ok": true,
                    "replayed": true,
                    reply_key: entry.record,
                    "admission": entry.admission,
                    "expected_head_for_successor": stream.last().map(|last| last.head.clone()),
                    "index_state": projection_cache_state(resource, stream),
                })),
            )))
        }
        Ok(None) => Ok(None),
        Err(error) => Err(mutation_refusal_reply(error)),
    }
}

/// Derive the commitment, honour the `expected_content_hash` assertion, cross the SHARED owner-
/// scoped admission boundary, then answer from a RE-READ of the chain — never from the value this
/// handler happened to build.
#[allow(clippy::too_many_arguments)]
pub(crate) fn finish_admission(
    spec: &FamilySpec,
    st: &DaemonState,
    caller: &WriteCaller,
    scope: &RequestResourceScope,
    resource: &str,
    reply_key: &str,
    mut record: Value,
    expected_head: Option<String>,
    recorded_at_ms: u64,
    body: &Value,
    extra: Value,
) -> Reply {
    let derived = match spec.content_hash(&record) {
        Ok(hash) => hash,
        Err(reason) => {
            return bad(
                StatusCode::INTERNAL_SERVER_ERROR,
                &spec.code("content_hash_failed"),
                reason,
            )
        }
    };
    if let Some(asserted) = body.get("expected_content_hash").and_then(Value::as_str) {
        if asserted != derived {
            return refuse(
                &spec.code("content_hash_substituted"),
                "expected_content_hash does not match the hash this exact content commits to",
            );
        }
    }
    record["content_hash"] = json!(derived);
    if let Some(asserted) = body.get("expected_revision_ref").and_then(Value::as_str) {
        if Some(asserted) != record.get(spec.identity_field).and_then(Value::as_str) {
            return refuse(
                &spec.code("identity_substituted"),
                "the identity this admission resolves to is not the one asserted; identity is derived from the durable stream, never chosen",
            );
        }
    }
    // The record must satisfy its REGISTERED contract before it becomes durable, so an
    // unprojectable record cannot exist on the chain even for one frame.
    if let Err(reason) = validate_architecture_contract(spec.contract_id, &record) {
        return refuse(
            &spec.code("not_registered_valid"),
            format!(
                "this admission does not satisfy {}: {reason}",
                spec.contract_id
            ),
        );
    }
    let payload = json!({
        "schema_version": spec.payload_schema,
        "owner_ref": caller.owner_ref,
        "resource_ref": resource,
        spec.record_key: record,
    });
    let commit = match admit_owner_scoped_mutation(
        &st.data_dir,
        expected_head.is_none(),
        ScopedMutation {
            identity: &caller.identity,
            scope,
            resource_kind: spec.resource_kind,
            resource_ref: resource,
            owner_namespace: spec.owner_namespace,
            stream_tail: &stream_tail(spec.resource_kind, resource),
            op_kind: spec.admit_op,
            expected_head: expected_head.as_deref(),
            payload: &payload,
            idempotency_key: &caller.idempotency_key,
            recorded_at_ms,
        },
    ) {
        Ok(commit) => commit,
        Err(error) => return mutation_refusal_reply(error),
    };
    let stream = match read_stream(spec, &st.data_dir, &caller.identity, scope, resource) {
        Ok(stream) => stream,
        Err(response) => return response,
    };
    let Some(entry) = stream
        .iter()
        .find(|entry| entry.head == commit.projection.head)
    else {
        return bad(
            StatusCode::BAD_GATEWAY,
            &spec.code("projection_disagrees_with_ack"),
            "the admitted head is absent from this stream's projection",
        );
    };
    let mut reply = json!({
        "ok": true,
        "replayed": commit.replayed,
        reply_key: entry.record,
        "admission": entry.admission,
        "expected_head_for_successor": commit.projection.head,
        "receipt_ref": commit.receipt_ref,
        "operation_ref": commit.operation_ref,
        "request_fingerprint": commit.request_fingerprint,
        "index_state": projection_cache_state(resource, &stream),
    });
    if let (Some(target), Some(source)) = (reply.as_object_mut(), extra.as_object()) {
        for (key, value) in source {
            target.insert(key.clone(), value.clone());
        }
    }
    (
        if commit.replayed {
            StatusCode::OK
        } else {
            StatusCode::CREATED
        },
        Json(reply),
    )
}

#[derive(serde::Deserialize)]
pub(crate) struct StreamQuery {
    pub(crate) family: Option<String>,
    pub(crate) revision: Option<u64>,
    pub(crate) as_of_admitted_at: Option<String>,
}

/// The consumer route shared by every family here: the caller's inventory with no `family`, one
/// family's whole stream with it, and one exact revision with `revision`.
///
/// `as_of_admitted_at` is the TRANSACTION-time narrowing — "as this family stood then" — and is
/// deliberately the only time axis these families have: an immutable revision has one stamp.
pub(crate) fn family_query(
    spec: &'static FamilySpec,
    inventory_key: &'static str,
    st: Arc<DaemonState>,
    headers: &HeaderMap,
    query: StreamQuery,
) -> Reply {
    let identity = match resolve_request_identity(&st.data_dir, headers) {
        Ok(identity) => identity,
        Err(error) => return scope_refusal_reply(error),
    };
    let Some(family) = query.family.as_deref().filter(|value| family_token(value)) else {
        return match authorized_request_resource_refs(&st.data_dir, &identity, spec.resource_kind) {
            Ok(refs) => (
                StatusCode::OK,
                Json(json!({ "ok": true, inventory_key: refs.into_iter().collect::<Vec<_>>() })),
            ),
            Err(error) => scope_refusal_reply(error),
        };
    };
    let resource = format!("{}{family}", spec.ref_scheme);
    let stream = match authorized_stream(spec, &st.data_dir, &identity, &resource) {
        Ok(stream) => stream,
        Err(response) => return response,
    };
    let index_state = projection_cache_state(&resource, &stream);
    let mut records: Vec<&AdmittedRecord> = stream.iter().collect();
    if let Some(cutoff) = query.as_of_admitted_at.as_deref() {
        let cutoff_ms = agentgres::parse_rfc3339_ms(cutoff);
        if cutoff_ms == 0 {
            return refuse(
                &spec.code("as_of_not_canonical"),
                "as_of_admitted_at is an RFC3339 instant; a malformed stamp reads as absent, never as zero-o'clock",
            );
        }
        records.retain(|entry| entry.recorded_at_ms <= cutoff_ms);
    }
    if let Some(ordinal) = query.revision {
        let wanted = format!("{resource}/revision/{ordinal}");
        let Some(entry) = records
            .iter()
            .find(|entry| entry.record.get(spec.identity_field) == Some(&json!(wanted)))
        else {
            return bad(
                StatusCode::NOT_FOUND,
                &spec.code("revision_absent"),
                format!("this family has no revision {ordinal} at the requested point — an absent revision is a typed absence, never an empty success"),
            );
        };
        return (
            StatusCode::OK,
            Json(json!({
                "ok": true,
                "resolved": entry.record,
                "admission": entry.admission,
                "index_state": index_state,
            })),
        );
    }
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "family": resource,
            "revisions": records.iter().map(|entry| entry.record.clone()).collect::<Vec<_>>(),
            "admissions": records.iter().map(|entry| entry.admission.clone()).collect::<Vec<_>>(),
            "head": stream.last().map(|last| last.head.clone()),
            "index_state": index_state,
        })),
    )
}

// ---------------------------------------------------------------- shared body-reading conveniences

pub(crate) fn body_str(body: &Value, key: &str) -> String {
    body.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or_default()
        .to_string()
}

pub(crate) fn body_object(body: &Value, key: &str, spec: &FamilySpec) -> Result<Value, Reply> {
    match body.get(key) {
        Some(value) if value.is_object() => Ok(value.clone()),
        _ => Err(refuse(
            &spec.code("member_object_required"),
            format!("'{key}' is a required object member of this contract"),
        )),
    }
}

/// A closed-vocabulary list read from the request, in VOCABULARY order and deduplicated.
///
/// Canonical order is imposed by the server rather than accepted from the caller: two orderings of
/// the same set would hash differently, and a commitment that moves with presentation is not a
/// commitment over content.
pub(crate) fn vocabulary_list(
    body: &Value,
    key: &str,
    vocabulary: &[&str],
    spec: &FamilySpec,
) -> Result<Vec<String>, Reply> {
    let Some(value) = body.get(key) else {
        return Ok(Vec::new());
    };
    let Some(items) = value.as_array() else {
        return Err(refuse(
            &spec.code("use_list_invalid"),
            format!("'{key}' must be an array drawn from this contract's closed vocabulary"),
        ));
    };
    let mut chosen: BTreeSet<String> = BTreeSet::new();
    for item in items {
        let Some(token) = item.as_str() else {
            return Err(refuse(
                &spec.code("use_list_invalid"),
                format!("'{key}' members are vocabulary tokens"),
            ));
        };
        if !vocabulary.contains(&token) {
            return Err(refuse(
                &spec.code("use_outside_vocabulary"),
                format!(
                    "'{token}' is not a member of this contract's closed vocabulary; an unknown use is a typed refusal, never a silently ignored one"
                ),
            ));
        }
        chosen.insert(token.to_string());
    }
    Ok(vocabulary
        .iter()
        .filter(|token| chosen.contains(**token))
        .map(|token| (*token).to_string())
        .collect())
}

pub(crate) fn ref_list(
    body: &Value,
    key: &str,
    max: usize,
    spec: &FamilySpec,
) -> Result<Vec<String>, Reply> {
    let Some(value) = body.get(key) else {
        return Ok(Vec::new());
    };
    let Some(items) = value.as_array() else {
        return Err(refuse(
            &spec.code("ref_list_invalid"),
            format!("'{key}' must be an array of exact refs"),
        ));
    };
    if items.len() > max {
        return Err(refuse(
            &spec.code("ref_list_invalid"),
            format!("'{key}' admits at most {max} refs"),
        ));
    }
    let mut refs = Vec::with_capacity(items.len());
    for item in items {
        let Some(value) = item.as_str().map(str::trim).filter(|value| {
            !value.is_empty() && value.len() <= 512 && !value.chars().any(char::is_control)
        }) else {
            return Err(refuse(
                &spec.code("ref_list_invalid"),
                format!("'{key}' members are non-empty refs of at most 512 bytes"),
            ));
        };
        if !refs.iter().any(|held: &String| held == value) {
            refs.push(value.to_string());
        }
    }
    Ok(refs)
}

// ================================================================================ M07.2 route rights

/// The twelve canonical route uses, verbatim and in the order the registered contract declares them.
pub(crate) const ROUTE_USE_VOCABULARY: &[&str] = &[
    "model_inference",
    "unattended_automation",
    "screen_or_session_capture",
    "demonstration_training",
    "model_or_worker_training",
    "publication",
    "downstream_use",
    "oem_or_reseller_use",
    "interactive_control",
    "browser_or_account_use",
    "connector_use",
    "commercial_use",
];

static ROUTE_RIGHTS: FamilySpec = FamilySpec {
    owner_namespace: "model-route-rights-contracts",
    resource_kind: "model_route_rights_contract",
    admit_op: "event_stream.model_route_rights_contract_revision_admitted",
    payload_schema: "ioi.hypervisor.model-route-rights-contract-revision-admission.v1",
    contract_id: "schema://ioi/foundations/objects/model-route-rights-contract/v1",
    schema_version: "ioi.model-route-rights-contract.v1",
    record_key: "model_route_rights_contract_record",
    code_prefix: "model_route_rights",
    commitment_domain: "ioi.model-route-rights-contract-content-commitment-jcs-sha256.v1",
    material_fields: &[
        "schema_version",
        "model_route_rights_contract_id",
        "revision_ref",
        "owner_ref",
        "tenant_ref",
        "principal_resolution",
        "resolved_principal_ref",
        "credential_principal_ref",
        "route_binding",
        "purposes",
        "data_classes",
        "declared_route_use_vocabulary",
        "permitted_route_uses",
        "prohibited_route_uses",
        "declared_prohibited_route_uses",
        "unresolved_route_uses",
        "unresolved_rights_findings",
        "destination_and_egress",
        "customer_output_rights",
        "provider_use_of_customer_material",
        "retention_posture",
        "retention_policy_ref",
        "commercial_terms_refs",
        "technical_terms_refs",
        "fallback_substitution",
        "validity",
        "revocation",
        "status",
        "admitted_at",
        "succession",
        "constants",
        "authority_nonclaim",
        "truth_nonclaim",
        "does_not_assert",
    ],
    identity_field: "revision_ref",
    ref_scheme: "model-route-rights://",
    stamp_field: "admitted_at",
};

/// Fields the server resolves for this family. Authoring one is INV-37's failure mode.
const ROUTE_RIGHTS_SERVER_RESOLVED: &[&str] = &[
    "schema_version",
    "model_route_rights_contract_id",
    "revision_ref",
    "tenant_ref",
    "principal_resolution",
    "declared_route_use_vocabulary",
    "permitted_route_uses",
    "prohibited_route_uses",
    "unresolved_route_uses",
    "admitted_at",
    "succession",
    "constants",
    "authority_nonclaim",
    "truth_nonclaim",
    "content_hash",
];

/// ONE resolved route-rights revision, as a caller entitled to it may see it.
///
/// THE OWNER SEAM. M10.3 intersects against a route contract; it does not read this family's chain,
/// re-derive its commitment, or reinterpret its partition. There is one reader, it is here, it
/// shares the same owner scope and chain projection as the query route, and it GRANTS NOTHING.
#[derive(Clone, Debug)]
pub(crate) struct ResolvedModelRouteRights {
    pub(crate) revision_ref: String,
    pub(crate) owner_ref: String,
    pub(crate) tenant_ref: String,
    pub(crate) record: Value,
    pub(crate) content_hash: String,
    pub(crate) admitted_head: String,
    pub(crate) index_state: &'static str,
}

impl ResolvedModelRouteRights {
    pub(crate) fn permitted_route_uses(&self) -> Vec<String> {
        self.record
            .get("permitted_route_uses")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default()
    }

    pub(crate) fn unresolved_route_uses(&self) -> Vec<String> {
        self.record
            .get("unresolved_route_uses")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Whether this contract is CURRENT: active status and a live revocation state.
    ///
    /// A route contract that has expired, been superseded, suspended or revoked contributes only
    /// denial to an intersection. Reading it as "no opinion" is exactly the fail-open a
    /// most-restrictive intersection exists to prevent.
    pub(crate) fn is_live(&self) -> bool {
        self.record.get("status").and_then(Value::as_str) == Some("active")
            && self
                .record
                .pointer("/revocation/revocation_state")
                .and_then(Value::as_str)
                == Some("live")
    }

    pub(crate) fn provider_model_training_prohibited(&self) -> bool {
        self.record
            .pointer("/provider_use_of_customer_material/provider_model_training")
            .and_then(Value::as_str)
            == Some("prohibited")
    }

    pub(crate) fn competing_model_training_permitted(&self) -> bool {
        self.record
            .pointer("/customer_output_rights/competing_model_training_permitted")
            .and_then(Value::as_bool)
            .unwrap_or(false)
    }

    pub(crate) fn egress_ceiling(&self) -> String {
        self.record
            .pointer("/destination_and_egress/egress_ceiling")
            .and_then(Value::as_str)
            .unwrap_or("no_egress")
            .to_string()
    }

    pub(crate) fn permitted_destination_classes(&self) -> Vec<String> {
        self.record
            .pointer("/destination_and_egress/permitted_destination_classes")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// Resolve ONE exact route-rights revision under the CALLER'S OWN owner binding.
///
/// The caller's identity is passed in, so a cross-principal or cross-tenant resolution is refused at
/// the scope boundary BEFORE any bytes are returned — not resolved first and compared afterwards,
/// which would be a leak with a check bolted on behind it. A family-head reference is refused by the
/// ref grammar, never resolved to "latest".
pub(crate) fn resolve_admitted_model_route_rights_contract(
    data_dir: &str,
    identity: &RequestIdentity,
    expected_owner_ref: Option<&str>,
    revision_ref: &str,
) -> Result<ResolvedModelRouteRights, Reply> {
    let Some((family, ordinal)) = parse_revision_ref(ROUTE_RIGHTS.ref_scheme, revision_ref) else {
        return Err(refuse(
            &ROUTE_RIGHTS.code("revision_ref_not_canonical"),
            "a route-rights binding names model-route-rights://<family>/revision/<n>; a family head or mutable-latest reference is refused where a revision is required",
        ));
    };
    let resource = format!("{}{family}", ROUTE_RIGHTS.ref_scheme);
    let scope = authorize_request_resource_scope(
        data_dir,
        identity,
        ROUTE_RIGHTS.resource_kind,
        &resource,
        expected_owner_ref,
    )
    .map_err(scope_refusal_reply)?;
    let stream = read_stream(&ROUTE_RIGHTS, data_dir, identity, &scope, &resource)?;
    let index_state = projection_cache_state(&resource, &stream);
    let wanted = format!("{resource}/revision/{ordinal}");
    let Some(entry) = stream
        .iter()
        .find(|entry| entry.record.get("revision_ref") == Some(&json!(wanted)))
    else {
        return Err(bad(
            StatusCode::NOT_FOUND,
            &ROUTE_RIGHTS.code("revision_absent"),
            format!(
                "this route-rights family has no admitted revision {ordinal}; an absent revision is a typed absence, never the nearest one"
            ),
        ));
    };
    Ok(ResolvedModelRouteRights {
        revision_ref: wanted,
        owner_ref: scope.owner_ref.clone(),
        tenant_ref: entry
            .record
            .get("tenant_ref")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        content_hash: entry
            .record
            .get("content_hash")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        record: entry.record.clone(),
        admitted_head: entry.head.clone(),
        index_state,
    })
}

/// The fail-closed partition, DERIVED.
///
/// Returns `(declared_prohibited, unresolved, prohibited, permitted, findings)`. The caller states
/// what its terms prohibit and what it could not resolve; everything else follows by construction.
fn derive_route_partition(
    declared_prohibited: &[String],
    findings: &[Value],
) -> Result<(Vec<String>, Vec<String>, Vec<String>), Reply> {
    let mut unresolved: BTreeSet<String> = BTreeSet::new();
    for finding in findings {
        let Some(use_token) = finding.get("route_use").and_then(Value::as_str) else {
            return Err(refuse(
                &ROUTE_RIGHTS.code("finding_not_canonical"),
                "every unresolved-rights finding names its route_use, its resolution and the exact term it could not resolve",
            ));
        };
        unresolved.insert(use_token.to_string());
    }
    // A use that is BOTH affirmatively prohibited and unresolved would make the covering multiset
    // longer than `prohibited_route_uses` and the registered invariant would refuse the record
    // offline. Refusing here names WHICH use collided instead of surfacing a coverage arithmetic
    // failure, and the two facts are genuinely different: a term that forbids a use and an
    // unanswered question about it are not the same finding.
    if let Some(collision) = declared_prohibited
        .iter()
        .find(|token| unresolved.contains(*token))
    {
        return Err(refuse(
            &ROUTE_RIGHTS.code("prohibition_declared_and_unresolved"),
            format!(
                "'{collision}' is recorded as both affirmatively prohibited and unresolved; a term that forbids a use and an unanswered question about it are different facts and cannot be counted twice"
            ),
        ));
    }
    let prohibited: Vec<String> = ROUTE_USE_VOCABULARY
        .iter()
        .filter(|token| {
            declared_prohibited.iter().any(|held| held == *token) || unresolved.contains(**token)
        })
        .map(|token| (*token).to_string())
        .collect();
    let permitted: Vec<String> = ROUTE_USE_VOCABULARY
        .iter()
        .filter(|token| !prohibited.iter().any(|held| held == *token))
        .map(|token| (*token).to_string())
        .collect();
    let unresolved_ordered: Vec<String> = ROUTE_USE_VOCABULARY
        .iter()
        .filter(|token| unresolved.contains(**token))
        .map(|token| (*token).to_string())
        .collect();
    Ok((unresolved_ordered, prohibited, permitted))
}

/// Admit one immutable route-rights revision.
pub(crate) async fn handle_model_route_rights_admit(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Reply {
    let spec = &ROUTE_RIGHTS;
    let caller = match require_write_caller(&st.data_dir, &headers, &body) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    if let Err(response) =
        contract_owner_ref(&caller.owner_ref, &spec.code("owner_scheme_unsupported"))
    {
        return response;
    }
    if let Err(response) = reject_authored(&body, spec, ROUTE_RIGHTS_SERVER_RESOLVED) {
        return response;
    }
    let family = body_str(&body, "family");
    if !family_token(&family) {
        return refuse(
            &spec.code("family_not_canonical"),
            "'family' is the lineage token this revision extends: [a-z0-9][a-z0-9._-]{0,127}",
        );
    }
    let resource = format!("{}{family}", spec.ref_scheme);
    let scope = match bind_request_resource_scope(
        &st.data_dir,
        &caller.identity,
        spec.resource_kind,
        &resource,
        &caller.owner_ref,
        &caller.owner_ref,
        &caller.idempotency_key,
    ) {
        Ok(scope) => scope,
        Err(error) => return scope_refusal_reply(error),
    };
    let stream = match read_stream(spec, &st.data_dir, &caller.identity, &scope, &resource) {
        Ok(stream) => stream,
        Err(response) => return response,
    };
    // REPLAY BEFORE PRECONDITIONS. A retry after an ambiguous response necessarily observes a newer
    // head than the one it originally compare-and-swapped against, so checking `expected_head`
    // first would turn every real duplicate into a conflict and make the idempotency key unusable.
    match replay_for_key(
        spec,
        &st,
        &caller,
        &scope,
        &resource,
        &stream,
        "model_route_rights_contract",
    ) {
        Ok(Some(reply)) => return reply,
        Ok(None) => {}
        Err(response) => return response,
    }
    let expected_head = match head_assertion(&body, spec.code_prefix) {
        Ok(head) => head,
        Err(response) => return response,
    };
    if let Err(response) = require_exact_head(&stream, &expected_head, spec.code_prefix) {
        return response;
    }

    let declared_prohibited = match vocabulary_list(
        &body,
        "declared_prohibited_route_uses",
        ROUTE_USE_VOCABULARY,
        spec,
    ) {
        Ok(list) => list,
        Err(response) => return response,
    };
    let mut findings = match body.get("unresolved_rights_findings") {
        None => Vec::new(),
        Some(Value::Array(items)) => items.clone(),
        Some(_) => {
            return refuse(
                &spec.code("finding_not_canonical"),
                "'unresolved_rights_findings' is an array of {route_use, resolution, unresolved_term_ref}",
            )
        }
    };

    let status = {
        let raw = body_str(&body, "status");
        if raw.is_empty() {
            "active".to_string()
        } else {
            raw
        }
    };
    let revocation = match body_object(&body, "revocation", spec) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let revocation_state = revocation
        .get("revocation_state")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();

    // NOT-LIVE EMPTIES THE PERMISSION, AND SAYS WHY. The registered contract pins
    // `permitted_route_uses` empty for a non-active or suspended/revoked contract. Emptying it
    // silently would leave a record that cannot explain itself, so every use that would otherwise
    // have survived is moved into a finding carrying the reason and the authority that produced it.
    let live = status == "active" && revocation_state == "live";
    if !live {
        let reason = if revocation_state == "suspended" || revocation_state == "revoked" {
            "revoked"
        } else if status == "expired" {
            "expired"
        } else {
            "unsupported"
        };
        let term_ref = revocation
            .get("revocation_authority_ref")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| format!("model-route-rights://{family}#not-live"));
        let already: BTreeSet<String> = findings
            .iter()
            .filter_map(|finding| finding.get("route_use").and_then(Value::as_str))
            .map(str::to_string)
            .collect();
        for token in ROUTE_USE_VOCABULARY {
            if already.contains(*token) || declared_prohibited.iter().any(|held| held == *token) {
                continue;
            }
            findings.push(json!({
                "route_use": token,
                "resolution": reason,
                "unresolved_term_ref": term_ref,
            }));
        }
    }

    let (unresolved, prohibited, permitted) =
        match derive_route_partition(&declared_prohibited, &findings) {
            Ok(parts) => parts,
            Err(response) => return response,
        };

    let ordinal = stream.len() as u64 + 1;
    let revision_ref = format!("{resource}/revision/{ordinal}");
    let predecessor = stream.last();
    let succession_reason = {
        let raw = body_str(&body, "succession_reason");
        if predecessor.is_none() {
            "genesis".to_string()
        } else if raw.is_empty() {
            "terms_change".to_string()
        } else {
            raw
        }
    };
    let succession = match predecessor {
        None => json!({
            "succession_reason": "genesis",
            "predecessor_revision_ref": Value::Null,
            "predecessor_content_hash": Value::Null,
            "supersedes_predecessor": false,
            "reinterprets_predecessor": false,
        }),
        Some(entry) => json!({
            "succession_reason": succession_reason,
            "predecessor_revision_ref": entry.record.get("revision_ref").cloned().unwrap_or(Value::Null),
            "predecessor_content_hash": entry.record.get("content_hash").cloned().unwrap_or(Value::Null),
            "supersedes_predecessor": true,
            "reinterprets_predecessor": false,
        }),
    };

    let route_binding = match body_object(&body, "route_binding", spec) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let destination_and_egress = match body_object(&body, "destination_and_egress", spec) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let customer_output_rights = match body_object(&body, "customer_output_rights", spec) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let provider_use = match body_object(&body, "provider_use_of_customer_material", spec) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let fallback_substitution = match body_object(&body, "fallback_substitution", spec) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let validity = match body_object(&body, "validity", spec) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let purposes = match ref_list(&body, "purposes", 7, spec) {
        Ok(list) => list,
        Err(response) => return response,
    };
    let data_classes = match ref_list(&body, "data_classes", 12, spec) {
        Ok(list) => list,
        Err(response) => return response,
    };
    let commercial_terms_refs = match ref_list(&body, "commercial_terms_refs", 32, spec) {
        Ok(list) => list,
        Err(response) => return response,
    };
    let technical_terms_refs = match ref_list(&body, "technical_terms_refs", 32, spec) {
        Ok(list) => list,
        Err(response) => return response,
    };
    let does_not_assert = match ref_list(&body, "does_not_assert", 10, spec) {
        Ok(list) if !list.is_empty() => list,
        Ok(_) => vec![
            "authority".to_string(),
            "possession_proves_permission".to_string(),
            "provider_non_learning".to_string(),
            "source_rights".to_string(),
            "route_availability".to_string(),
            "cryptographic_privacy".to_string(),
        ],
        Err(response) => return response,
    };

    let recorded_at_ms = agentgres::parse_rfc3339_ms(&body_str(&body, "effective_at"));
    let record = json!({
        "schema_version": spec.schema_version,
        "model_route_rights_contract_id": resource,
        "revision_ref": revision_ref,
        "owner_ref": caller.owner_ref,
        "tenant_ref": contract_tenant_ref(&caller.owner_ref),
        // PINNED. The principal a route acts as is resolved by the server from the authenticated
        // request, never named by the caller: a caller that supplies its own principal resolution
        // has authenticated nothing.
        "principal_resolution": "server_resolved",
        "resolved_principal_ref": body.get("resolved_principal_ref").cloned().unwrap_or(Value::Null),
        "credential_principal_ref": body.get("credential_principal_ref").cloned().unwrap_or(Value::Null),
        "route_binding": route_binding,
        "purposes": purposes,
        "data_classes": data_classes,
        "declared_route_use_vocabulary": ROUTE_USE_VOCABULARY,
        "permitted_route_uses": permitted,
        "prohibited_route_uses": prohibited,
        "declared_prohibited_route_uses": declared_prohibited,
        "unresolved_route_uses": unresolved,
        "unresolved_rights_findings": findings,
        "destination_and_egress": destination_and_egress,
        "customer_output_rights": customer_output_rights,
        "provider_use_of_customer_material": provider_use,
        "retention_posture": body_str(&body, "retention_posture"),
        "retention_policy_ref": body_str(&body, "retention_policy_ref"),
        "commercial_terms_refs": commercial_terms_refs,
        "technical_terms_refs": technical_terms_refs,
        "fallback_substitution": fallback_substitution,
        "validity": validity,
        "revocation": revocation,
        "status": status,
        "admitted_at": admitted_stamp(recorded_at_ms),
        "succession": succession,
        "constants": {
            "lifecycle_id": "model_route_rights_contract_lifecycle.v1",
            "route_use_vocabulary_size": ROUTE_USE_VOCABULARY.len(),
            "provider_use_prohibited_token": "prohibited",
            "nonclaim_authority_token": "authority",
            "nonclaim_possession_token": "possession_proves_permission",
        },
        "authority_nonclaim": "model_route_rights_contract_grants_no_authority",
        "truth_nonclaim": "model_route_rights_contract_is_a_resolved_terms_reading_not_provider_behaviour",
        "does_not_assert": does_not_assert,
    });

    finish_admission(
        spec,
        &st,
        &caller,
        &scope,
        &resource,
        "model_route_rights_contract",
        record,
        expected_head,
        recorded_at_ms,
        &body,
        json!({ "route_rights_are_a_ceiling_not_a_grant": true }),
    )
}

pub(crate) async fn handle_model_route_rights_query(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Query(query): Query<StreamQuery>,
) -> Reply {
    family_query(
        &ROUTE_RIGHTS,
        "model_route_rights_contract_refs",
        st,
        &headers,
        query,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The registered positive fixture must hash to the number it carries under THIS module's
    /// material list. A gate that computed both sides from the same source would certify nothing;
    /// the fixture is a committed pin and the material list is this build's independent reading.
    #[test]
    fn registered_route_rights_fixture_matches_this_modules_material_list() {
        let fixture = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../docs/architecture/_meta/schemas/fixtures/model-route-rights-contract-v1/positive-genesis-active-inference-route.json"
        ));
        let record: Value = serde_json::from_str(fixture).expect("the fixture parses");
        let committed = record
            .get("content_hash")
            .and_then(Value::as_str)
            .expect("the fixture carries a commitment");
        let derived = ROUTE_RIGHTS
            .content_hash(&record)
            .expect("the material list resolves");
        assert_eq!(
            derived, committed,
            "this module's material list disagrees with the registered commitment"
        );
    }

    #[test]
    fn a_use_cannot_be_both_declared_prohibited_and_unresolved() {
        let declared = vec!["publication".to_string()];
        let findings = vec![json!({
            "route_use": "publication",
            "resolution": "missing",
            "unresolved_term_ref": "terms://x",
        })];
        let refused = derive_route_partition(&declared, &findings);
        assert!(
            refused.is_err(),
            "a use counted as both affirmatively prohibited and unresolved must refuse"
        );
    }

    /// The load-bearing property: a recorded unresolved right REMOVES the permission by
    /// construction. There is no branch a future edit can forget to take.
    #[test]
    fn an_unresolved_right_is_never_permitted() {
        let findings = vec![json!({
            "route_use": "connector_use",
            "resolution": "missing",
            "unresolved_term_ref": "terms://x",
        })];
        let (unresolved, prohibited, permitted) =
            derive_route_partition(&[], &findings).expect("the partition derives");
        assert_eq!(unresolved, vec!["connector_use".to_string()]);
        assert!(prohibited.contains(&"connector_use".to_string()));
        assert!(!permitted.contains(&"connector_use".to_string()));
        // and the partition is exactly the vocabulary, once each
        assert_eq!(
            prohibited.len() + permitted.len(),
            ROUTE_USE_VOCABULARY.len()
        );
    }

    #[test]
    fn the_partition_covers_the_vocabulary_exactly_once_each() {
        let declared = vec!["publication".to_string(), "commercial_use".to_string()];
        let findings = vec![json!({
            "route_use": "connector_use",
            "resolution": "unknown",
            "unresolved_term_ref": "terms://x",
        })];
        let (_, prohibited, permitted) =
            derive_route_partition(&declared, &findings).expect("the partition derives");
        let mut covering: Vec<String> =
            prohibited.iter().chain(permitted.iter()).cloned().collect();
        covering.sort();
        let mut vocabulary: Vec<String> = ROUTE_USE_VOCABULARY
            .iter()
            .map(|token| (*token).to_string())
            .collect();
        vocabulary.sort();
        assert_eq!(covering, vocabulary);
    }
}
