//! M05.7 — the definition/run split, as three runtime families on the canonical Agentgres chain.
//!
//! `DataRecipe` is an immutable transformation DEFINITION, `TransformationRun` is ONE ADMITTED
//! EXECUTION, and `ConnectorMapping` is a provider/form/field MAP. v1 folded all three into one
//! another: a recipe embedded its mappings as opaque passthrough arrays, a run carried no recipe
//! binding at all, and every identity came from the wall clock. This module implements the v2
//! contracts those three defects motivated, and it implements them as three SEPARATE families with
//! three separate streams, three separate identities and three lifecycle vocabularies that share no
//! member.
//!
//! WHAT IS TRUTH HERE. The Agentgres owner-namespaced operation chain is the only durable record.
//! This module writes NO file of its own, so there is no second store to drift. Everything served is
//! a PROJECTION rebuilt from the chain on every read, including the content hash, which is
//! re-derived from the REGISTERED invariant profile's own material list and compared rather than
//! trusted. The read index is a process-local (head, count) cache that is consulted only to REPORT
//! agreement after the answer is already computed; a restart discards it whole.
//!
//! FIVE THINGS ARE STRUCTURAL RATHER THAN DOCUMENTARY:
//!
//! 1. NON-NEGOTIABLE 3 IS ENFORCED AT THE RUN. A run binds the exact `data-recipe://…/revision/…`
//!    ref, that revision's exact content hash, and the exact semantic-component snapshot the
//!    revision committed. The run carries BOTH the committed tuple and the tuple it actually
//!    resolved, so the equality is decidable from the bytes with no registry read. Asking this
//!    module to resolve CURRENT HEADS instead is an admissible request that reaches a REFUSAL: the
//!    heads are really resolved, the resolved set really is hashed, and the disagreement is what
//!    refuses. A drifted tuple needs a SUCCESSOR RECIPE REVISION, never a run that resolves
//!    differently and reports success.
//!
//! 2. THE CALLER NEVER AUTHORS EVIDENCE (INV-37). Revision ordinal, revision ref, tenancy, the
//!    semantic snapshot and its hash, the succession tuple, the admission stamp, the derived
//!    identity and the content hash are all RESOLVED — from the durable predecessor, from the owner
//!    seams, and from the admitted operation. A caller may ASSERT what it believes them to be;
//!    a disagreement is a typed refusal by its own name, never an accepted substitution.
//!
//! 3. IDENTITY IS DERIVED, NEVER CLOCKED. v1 minted `cmap_{nanos:x}` and `trun_{nanos:x}`, so a
//!    retried declaration admitted a second object. Here a mapping revision and a run derive from
//!    the owner ref and the caller's idempotency key, `identity_basis` carries that key's hash and
//!    names `wall_clock_nanoseconds` as the refused basis, and an exact retry replays the record it
//!    already minted.
//!
//! 4. THE THREE FAMILIES CANNOT BE FOLDED BACK TOGETHER. A recipe admits only an exact
//!    `mapping://…/revision/…` string, so an inline mapping is a refusal rather than a coercion; a
//!    run's outputs live on the run and a recipe's output CONTRACTS live on the recipe; and the
//!    three `constants.lifecycle_id` values are distinct over disjoint vocabularies.
//!
//! 5. MEANING GRANTS NOTHING (NN 9). Every projected record carries its authority nonclaim, and
//!    nothing here consults, mints, widens or presents a capability, lease, policy decision or
//!    effect admission. A mapping is not credential custody; a recipe is not training consent; a
//!    run attests boundary facts and never universal correctness.
//!
//! NONCLAIM, STATED ONCE AND CARRIED IN THE RESPONSE. The v1→v2 convergence is an EXPLICIT ACT over
//! predecessor bytes the caller supplies. The server validates them against the REGISTERED v1
//! contract and computes `from_content_hash` itself under a v1-specific domain separator, so the
//! caller cannot assert the predecessor's commitment — but this build does not prove the caller
//! holds that stored v1 record, because reading the v1 record directory from here would make this
//! module a second namer of an ODK family it does not own. `v1_predecessor_custody` is therefore an
//! explicit nonclaim on every converged admission rather than an implied one.
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

type Reply = (StatusCode, Json<Value>);

fn bad(status: StatusCode, code: &str, message: impl Into<String>) -> Reply {
    (
        status,
        Json(json!({ "ok": false, "error": { "code": code, "message": message.into() } })),
    )
}

fn refuse(code: &str, message: impl Into<String>) -> Reply {
    bad(StatusCode::UNPROCESSABLE_ENTITY, code, message)
}

fn sha256_of(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..].bytes().all(|byte| byte.is_ascii_hexdigit())
        && value[7..].bytes().all(|byte| !byte.is_ascii_uppercase())
}

/// JCS-SHA256 over a flat material map, exactly as every registered `jcs_sha256_equals` rule in
/// this estate defines it: a `domain` constant plus one entry per committed field.
fn digest_over(record: &Value, domain: &str, fields: &[&str]) -> Result<String, String> {
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

/// `[a-z0-9][a-z0-9._-]{0,127}` — the family token both definition contracts pin.
fn family_token(value: &str) -> bool {
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
/// repaired: two spellings that resolve to one revision would let a run claim it executed something
/// other than what it executed.
fn parse_revision_ref(scheme: &str, value: &str) -> Option<(String, u64)> {
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
/// The substrate's owner and tenant refs are one value (`org://local`); the v2 contracts carry a
/// `tenant://…` token whose charset excludes `/`. The mapping is total and deterministic, so a
/// caller cannot choose its own tenancy and `output_tenant_ref` remains a field that can DISAGREE
/// and be caught rather than one the caller supplies.
fn contract_tenant_ref(owner_ref: &str) -> String {
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

/// The owner schemes the two definition contracts and the run contract admit, verbatim.
const CONTRACT_OWNER_SCHEMES: &[&str] = &["org://", "user://", "system://", "project://", "domain://"];

fn contract_owner_ref(owner_ref: &str) -> Result<(), Reply> {
    if CONTRACT_OWNER_SCHEMES
        .iter()
        .any(|scheme| owner_ref.starts_with(scheme))
        && owner_ref.len() <= 200
    {
        return Ok(());
    }
    Err(refuse(
        "data_transformation_owner_scheme_unsupported",
        "these contracts admit an owner in org://, user://, system://, project:// or domain://; an owner this build cannot express is a typed refusal, never a rewritten one",
    ))
}

// ------------------------------------------------------------------------------- family descriptor

/// Everything that differs between the three families, so the chain machinery below can be written
/// ONCE. A second copy of "project the chain, re-derive the hash, compare" is how two families
/// acquire two interpretations of the same rule.
struct FamilySpec {
    owner_namespace: &'static str,
    resource_kind: &'static str,
    admit_op: &'static str,
    payload_schema: &'static str,
    contract_id: &'static str,
    schema_version: &'static str,
    record_key: &'static str,
    code_prefix: &'static str,
    commitment_domain: &'static str,
    material_fields: &'static [&'static str],
    /// The record field carrying the identity this family's projection must agree with.
    identity_field: &'static str,
}

impl FamilySpec {
    fn code(&self, suffix: &str) -> String {
        format!("{}_{suffix}", self.code_prefix)
    }

    fn content_hash(&self, record: &Value) -> Result<String, String> {
        digest_over(record, self.commitment_domain, self.material_fields)
    }
}

/// One admitted record, exactly as the chain holds it, plus the admission facts that live BESIDE it.
///
/// The v2 contracts are `additionalProperties: false`, so admission cannot be stapled into the
/// record the way M05.1 staples it into `OntologyVersion`. That is an improvement, not a
/// limitation: the stored bytes are the registered contract and nothing else, and the admission
/// coordinates are reported alongside where a reader can see they are the chain's facts.
struct AdmittedRecord {
    record: Value,
    admission: Value,
    head: String,
    recorded_at_ms: u64,
}

fn project_admitted(spec: &FamilySpec, entry: &ExactProjection) -> Result<AdmittedRecord, String> {
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
    // THE READ SIDE REFUSES AN UNKNOWN CONTRACT VERSION TOO. A frame written by a build this one
    // does not implement is reported unreadable rather than projected as though it were v2 — a
    // downgrade is no more acceptable leaving the chain than entering it.
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
    if record.get("admitted_at").and_then(Value::as_str) != Some(stamped.as_str()) {
        return Err(format!(
            "{} record's admitted_at is not the stamp of its own admission",
            spec.code_prefix
        ));
    }
    validate_architecture_contract(spec.contract_id, &record)
        .map_err(|reason| format!("projected {} is not registered-valid: {reason}", spec.code_prefix))?;
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

fn entry_resource(payload: &Value) -> &str {
    payload
        .get("resource_ref")
        .and_then(Value::as_str)
        .unwrap_or_default()
}

fn project_stream(
    spec: &FamilySpec,
    history: &[ExactProjection],
) -> Result<Vec<AdmittedRecord>, String> {
    history
        .iter()
        .map(|entry| project_admitted(spec, entry))
        .collect()
}

fn read_stream(
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

fn authorized_stream(
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
fn projection_cache_state(key: &str, stream: &[AdmittedRecord]) -> &'static str {
    let observed = (
        stream.last().map(|last| last.head.clone()).unwrap_or_default(),
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
fn reject_authored(body: &Value, spec: &FamilySpec, authored: &[&str]) -> Result<(), Reply> {
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

fn string_list(body: &Value, key: &str, max: usize) -> Result<Vec<String>, Reply> {
    let Some(value) = body.get(key) else {
        return Ok(Vec::new());
    };
    let Some(items) = value.as_array() else {
        return Err(refuse(
            "data_transformation_ref_list_invalid",
            format!("'{key}' must be an array of exact refs"),
        ));
    };
    if items.len() > max {
        return Err(refuse(
            "data_transformation_ref_list_too_large",
            format!("'{key}' admits at most {max} members"),
        ));
    }
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let Some(text) = item.as_str() else {
            // A STRUCTURED MEMBER IS A REFUSAL, NEVER A COERCION. This is the exact shape v1
            // accepted as an opaque passthrough, and accepting it here is how a mapping becomes a
            // fragment of a recipe instead of an object.
            return Err(refuse(
                "data_transformation_inline_member_refused",
                format!(
                    "'{key}' admits only exact ref STRINGS; an inline object is a separate family folded into this one, which is the conflation the definition/run split exists to end"
                ),
            ));
        };
        let text = text.trim();
        if text.is_empty() || text.len() > 512 {
            return Err(refuse(
                "data_transformation_ref_invalid",
                format!("'{key}' carries an empty or oversized ref"),
            ));
        }
        if out.contains(&text.to_owned()) {
            return Err(refuse(
                "data_transformation_ref_duplicated",
                format!("'{key}' repeats '{text}'; these members are sets"),
            ));
        }
        out.push(text.to_owned());
    }
    Ok(out)
}

fn enum_list(
    body: &Value,
    key: &str,
    permitted: &[&str],
    min: usize,
    max: usize,
) -> Result<Vec<String>, Reply> {
    let items = string_list(body, key, max)?;
    if items.len() < min {
        return Err(refuse(
            "data_transformation_enum_list_short",
            format!("'{key}' requires at least {min} member(s)"),
        ));
    }
    for item in &items {
        if !permitted.contains(&item.as_str()) {
            return Err(refuse(
                "data_transformation_enum_member_unknown",
                format!("'{key}' member '{item}' is not one of {permitted:?}"),
            ));
        }
    }
    Ok(items)
}

fn str_field<'a>(body: &'a Value, key: &str) -> &'a str {
    body.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("")
}

/// The semantic-component snapshot, SERVER-DERIVED from the exact members the record names.
///
/// The registered invariant requires `semantic_component_refs` to equal EXACTLY the union of the
/// readable ref fields — same members, same count. Deriving it here rather than accepting it means
/// the coverage cannot be wrong in the first place, and the invariant becomes a check on the
/// producer rather than a hope about the caller.
fn semantic_snapshot(
    snapshot_ref: &str,
    components: &[String],
) -> Result<(String, Vec<String>, usize), String> {
    let unique: BTreeSet<&String> = components.iter().collect();
    let ordered: Vec<String> = components.to_vec();
    if unique.len() != ordered.len() {
        return Err("the semantic component set carries a duplicate member".into());
    }
    let material = json!({
        "snapshot_ref": snapshot_ref,
        "components": ordered.clone(),
    });
    let hash = digest_over(
        &material,
        "ioi.semantic-component-set-jcs-sha256.v2",
        &["snapshot_ref", "components"],
    )?;
    let count = ordered.len();
    Ok((hash, ordered, count))
}

// ------------------------------------------------------------- the shared admission machinery

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_millis() as u64)
}

fn revision_ordinal(entry: &AdmittedRecord, scheme: &str) -> u64 {
    entry
        .record
        .get("revision_ref")
        .and_then(Value::as_str)
        .and_then(|value| parse_revision_ref(scheme, value))
        .map_or(0, |(_, ordinal)| ordinal)
}

fn head_assertion(body: &Value, code_prefix: &str) -> Result<Option<String>, Reply> {
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
/// a bare substrate conflict. The substrate compare-and-swap below is still the authority.
fn require_exact_head(
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
            (None, Some(_)) => "this stream already has admissions; a successor names the exact current head",
            (Some(_), None) => "this stream has no admissions yet; the first names no predecessor head",
            _ => "expected_head does not name the exact current head of this stream; re-read the head and re-derive the record",
        },
    ))
}

/// A retry of the SAME key resolves to the record it already admitted, rather than minting a second
/// one. The substrate owns replay; this only reaches the answer it holds.
#[allow(clippy::too_many_arguments)]
fn replay_for_key(
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
fn finish_admission(
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
    converged_from_v1: bool,
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
            format!("this admission does not satisfy {}: {reason}", spec.contract_id),
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
    (
        if commit.replayed {
            StatusCode::OK
        } else {
            StatusCode::CREATED
        },
        Json(json!({
            "ok": true,
            "replayed": commit.replayed,
            reply_key: entry.record,
            "admission": entry.admission,
            "expected_head_for_successor": commit.projection.head,
            "receipt_ref": commit.receipt_ref,
            "operation_ref": commit.operation_ref,
            "request_fingerprint": commit.request_fingerprint,
            "index_state": projection_cache_state(resource, &stream),
            // The one thing a converged admission does NOT establish, carried on the response so a
            // consumer reads it rather than inferring it.
            "v1_predecessor_custody_nonclaim": if converged_from_v1 {
                json!("this build validated and hashed the supplied predecessor bytes against the registered v1 contract; it did not prove the caller holds that stored v1 record")
            } else {
                Value::Null
            },
        })),
    )
}

#[derive(serde::Deserialize)]
pub(crate) struct StreamQuery {
    family: Option<String>,
    revision: Option<u64>,
    as_of_admitted_at: Option<String>,
}

/// The consumer route shared by the two definition families: the caller's inventory with no
/// `family`, one family's whole stream with it, and one exact revision with `revision`.
///
/// `as_of_admitted_at` is the TRANSACTION-time narrowing — "as this family stood then" — and is
/// deliberately the only time axis a definition has: an immutable revision has one stamp.
fn family_query(
    spec: &'static FamilySpec,
    inventory_key: &'static str,
    scheme: &'static str,
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
    let resource = format!("{scheme}{family}");
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

/// The commitment over a PREDECESSOR record's exact stored bytes, canonicalized.
///
/// No field list: a v1 record is converged as a whole, and enumerating its fields here would let a
/// later edit to that enumeration silently change what a convergence claims to have seen.
fn predecessor_record_hash(record: &Value) -> Result<String, String> {
    serde_jcs::to_vec(record)
        .map(|bytes| sha256_of(&bytes))
        .map_err(|error| format!("the predecessor record could not be canonicalized: {error}"))
}

/// THE EXPLICIT v1 CONVERGENCE, AND THE ONE NONCLAIM IT CARRIES.
///
/// A caller may name a stored v1 predecessor by handing over its exact bytes under
/// `converge_from_v1`. This validates them against the REGISTERED v1 contract — so a record that is
/// not a v1 record is refused rather than converged — and computes the predecessor commitment
/// HERE, so the caller cannot assert what its predecessor hashed to. It returns
/// `(source_ref, source_hash, v1_revision)`.
///
/// WHAT IT DOES NOT PROVE, stated where the code is rather than in prose elsewhere: that the caller
/// actually holds that stored record. Resolving it from the v1 record directory would make this
/// module a second namer of an ODK family it does not own, which is a worse defect than a named
/// nonclaim. Callers of this function surface `v1_predecessor_custody_nonclaim` on the response.
fn convergence_block(
    body: &Value,
    v1_contract_id: &str,
    v1_schema_version: &str,
    code_prefix: &str,
    ref_field: &str,
) -> Result<Option<(String, String, Option<u64>)>, Reply> {
    let Some(source) = body.get("converge_from_v1") else {
        return Ok(None);
    };
    if source.is_null() {
        return Ok(None);
    }
    let Some(record) = source.as_object() else {
        return Err(refuse(
            &format!("{code_prefix}_convergence_source_invalid"),
            "converge_from_v1 carries the exact stored predecessor RECORD; a bare ref would name a pointer rather than bytes",
        ));
    };
    if record.get("schema_version").and_then(Value::as_str) != Some(v1_schema_version) {
        return Err(refuse(
            &format!("{code_prefix}_convergence_source_not_v1"),
            format!("converge_from_v1 must carry a '{v1_schema_version}' record; this build converges the registered predecessor and reinterprets nothing else"),
        ));
    }
    let value = Value::Object(record.clone());
    if let Err(reason) = validate_architecture_contract(v1_contract_id, &value) {
        return Err(refuse(
            &format!("{code_prefix}_convergence_source_not_registered_valid"),
            format!("converge_from_v1 does not satisfy the registered predecessor contract: {reason}"),
        ));
    }
    // The predecessor is named in the scheme it was ACTUALLY STORED UNDER. Rewriting it into the
    // successor's scheme would be reinterpreting v1, which is the one thing a convergence may not do.
    let source_ref = record
        .get(ref_field)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    if source_ref.is_empty() {
        return Err(refuse(
            &format!("{code_prefix}_convergence_source_invalid"),
            "the predecessor record carries no stored ref",
        ));
    }
    let hash = predecessor_record_hash(&value)
        .map_err(|reason| refuse(&format!("{code_prefix}_convergence_source_invalid"), reason))?;
    let revision = record.get("revision").and_then(Value::as_u64);
    Ok(Some((source_ref, hash, revision)))
}

// ================================================================== ConnectorMapping v2 — the map

const CMAP: FamilySpec = FamilySpec {
    owner_namespace: "hypervisor-connector-mapping-revisions",
    resource_kind: "connector-mapping-family",
    admit_op: "connector_mapping.revision.admit",
    payload_schema: "ioi.hypervisor.connector-mapping-revision-admission.v1",
    contract_id: "schema://ioi/foundations/objects/connector-mapping/v2",
    schema_version: "ioi.connector-mapping.v2",
    record_key: "connector_mapping_record",
    code_prefix: "connector_mapping",
    commitment_domain: "ioi.connector-mapping-content-commitment-jcs-sha256.v2",
    material_fields: &[
        "schema_version",
        "connector_mapping_id",
        "revision_ref",
        "owner_ref",
        "tenant_ref",
        "name",
        "identity_basis",
        "connector_id",
        "ontology_revision_ref",
        "source_schema_ref",
        "target_object_model_refs",
        "field_mappings",
        "action_mappings",
        "authority_scopes_required",
        "redaction_policy_ref",
        "evidence_required",
        "semantic_component_set_snapshot_ref",
        "semantic_component_set_hash",
        "semantic_component_refs",
        "semantic_component_count",
        "effective_policy_hash",
        "registry_status",
        "admitted_at",
        "succession",
        "migration",
        "constants",
        "authority_nonclaim",
        "truth_nonclaim",
        "does_not_assert",
    ],
    identity_field: "revision_ref",
};

const CMAP_V1_SCHEMA: &str = "ioi.hypervisor.odk.connector-mapping.v1";
const CMAP_V1_CONTRACT: &str = "schema://ioi/foundations/objects/connector-mapping/v1";
const REGISTRY_STATUSES: &[&str] = &["draft", "active", "deprecated", "revoked"];
const CMAP_SUCCESSION_REASONS: &[&str] = &[
    "field_change",
    "action_change",
    "source_schema_change",
    "ontology_revision_change",
    "object_model_change",
    "policy_change",
    "correction",
];
const FIELD_ROLES: &[&str] = &["key", "title", "field"];
const SOURCE_TYPES: &[&str] = &[
    "string",
    "integer",
    "double",
    "boolean",
    "timestamp",
    "date",
    "json",
];
const CARDINALITIES: &[&str] = &["one", "many"];
const FIELD_MAPPING_KEYS: &[&str] = &[
    "role",
    "source_field",
    "target_property_ref",
    "source_type",
    "source_cardinality",
];
const ACTION_MAPPING_KEYS: &[&str] = &["source_action", "target_action_ref"];

/// `field_mappings`, checked HERE as well as by the registered invariant.
///
/// The invariant decides it offline from the bytes; this decides it before admission, so an
/// unprojectable revision cannot become durable truth in the first place. Two bindings onto one
/// target property is the defect: v1 kept key, title and the rest in three separate members that
/// could disagree about shape, and no single check could see across them.
fn canonical_field_mappings(body: &Value) -> Result<Value, Reply> {
    let Some(items) = body.get("field_mappings").and_then(Value::as_array) else {
        return Err(refuse(
            "connector_mapping_field_mappings_invalid",
            "field_mappings must be an array of typed, role-bearing bindings",
        ));
    };
    if items.len() > 256 {
        return Err(refuse(
            "connector_mapping_field_mappings_too_large",
            "field_mappings admits at most 256 bindings",
        ));
    }
    let mut targets: BTreeSet<String> = BTreeSet::new();
    let mut canonical = Vec::with_capacity(items.len());
    for item in items {
        let Some(object) = item.as_object() else {
            return Err(refuse(
                "connector_mapping_field_mapping_invalid",
                "each field mapping is an object",
            ));
        };
        if let Some(unknown) = object
            .keys()
            .find(|key| !FIELD_MAPPING_KEYS.contains(&key.as_str()))
        {
            return Err(refuse(
                "connector_mapping_field_mapping_unknown_member",
                format!("field mapping carries an undefined member '{unknown}'"),
            ));
        }
        let get = |key: &str| object.get(key).and_then(Value::as_str).unwrap_or("").trim();
        let (role, source_field, target, source_type, cardinality) = (
            get("role"),
            get("source_field"),
            get("target_property_ref"),
            get("source_type"),
            get("source_cardinality"),
        );
        if !FIELD_ROLES.contains(&role)
            || !SOURCE_TYPES.contains(&source_type)
            || !CARDINALITIES.contains(&cardinality)
            || source_field.is_empty()
            || source_field.len() > 256
        {
            return Err(refuse(
                "connector_mapping_field_mapping_invalid",
                "a field mapping declares role, source_field, target_property_ref, source_type and source_cardinality from their exact vocabularies; silent field equivalence is forbidden",
            ));
        }
        let Some((model, property)) = target.split_once('#') else {
            return Err(refuse(
                "connector_mapping_target_property_unqualified",
                "target_property_ref names the object model that OWNS the property, as 'object-model://<model>#<property>'; v1's bare property_id meant whatever the record happened to name",
            ));
        };
        if !model.starts_with("object-model://") || model.len() > 208 || property.is_empty() {
            return Err(refuse(
                "connector_mapping_target_property_unqualified",
                "target_property_ref must be an object-model-qualified property",
            ));
        }
        if !targets.insert(target.to_owned()) {
            return Err(refuse(
                "connector_mapping_target_property_targeted_twice",
                format!("'{target}' is targeted by more than one binding; one property has one source"),
            ));
        }
        canonical.push(json!({
            "role": role,
            "source_field": source_field,
            "target_property_ref": target,
            "source_type": source_type,
            "source_cardinality": cardinality,
        }));
    }
    Ok(Value::Array(canonical))
}

fn canonical_action_mappings(body: &Value) -> Result<Value, Reply> {
    let Some(items) = body.get("action_mappings").and_then(Value::as_array) else {
        return Err(refuse(
            "connector_mapping_action_mappings_invalid",
            "action_mappings must be an array (possibly empty)",
        ));
    };
    if items.len() > 64 {
        return Err(refuse(
            "connector_mapping_action_mappings_too_large",
            "action_mappings admits at most 64 bindings",
        ));
    }
    let mut canonical = Vec::with_capacity(items.len());
    for item in items {
        let Some(object) = item.as_object() else {
            return Err(refuse(
                "connector_mapping_action_mapping_invalid",
                "each action mapping is an object",
            ));
        };
        if let Some(unknown) = object
            .keys()
            .find(|key| !ACTION_MAPPING_KEYS.contains(&key.as_str()))
        {
            return Err(refuse(
                "connector_mapping_action_mapping_unknown_member",
                format!("action mapping carries an undefined member '{unknown}'"),
            ));
        }
        let source = object
            .get("source_action")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim();
        let target = object
            .get("target_action_ref")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim();
        if source.is_empty()
            || source.len() > 256
            || !target.starts_with("ontology-action://")
            || target.len() > 208
        {
            return Err(refuse(
                "connector_mapping_action_mapping_invalid",
                "an action mapping binds a source action to an exact 'ontology-action://…' contract; binding it grants nothing and every gate still runs",
            ));
        }
        canonical.push(json!({ "source_action": source, "target_action_ref": target }));
    }
    Ok(Value::Array(canonical))
}

/// One admitted ConnectorMapping revision, reduced to what a consumer needs to BIND it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ResolvedConnectorMapping {
    pub(crate) revision_ref: String,
    pub(crate) connector_mapping_id: String,
    pub(crate) content_hash: String,
    pub(crate) ontology_revision_ref: String,
    pub(crate) registry_status: String,
}

/// Resolve one EXACT admitted mapping revision for a caller entitled to see it.
///
/// THE OWNER SEAM. A DataRecipe binds mappings and a TransformationRun re-resolves them; each
/// writing its own reader is how a family acquires a second interpretation of its own truth. There
/// is one reader, it is here, it shares the same owner scope and chain projection as the query
/// route, and it grants nothing.
///
/// EXACT, NOT LATEST — the revision is selected out of the projected stream, so a predecessor stays
/// resolvable after successors land. A FAMILY HEAD IS UNREPRESENTABLE: `parse_revision_ref` demands
/// the `/revision/` segment, so `mapping://acme.intake-form` cannot even be addressed here.
pub(crate) fn resolve_admitted_connector_mapping(
    data_dir: &str,
    identity: &RequestIdentity,
    revision_ref: &str,
) -> Result<ResolvedConnectorMapping, Reply> {
    let Some((family, ordinal)) = parse_revision_ref("mapping://", revision_ref) else {
        return Err(refuse(
            "connector_mapping_revision_ref_not_exact",
            "a mapping revision is addressed as 'mapping://<family>/revision/<n>'; a family head, a mutable latest, or a spelling that needs normalising is refused rather than repaired",
        ));
    };
    let resource = format!("mapping://{family}");
    let stream = authorized_stream(&CMAP, data_dir, identity, &resource)?;
    let Some(entry) = stream
        .iter()
        .find(|entry| entry.record.get("revision_ref") == Some(&json!(revision_ref)))
    else {
        return Err(bad(
            StatusCode::NOT_FOUND,
            "connector_mapping_revision_absent",
            format!("this mapping family has no revision {ordinal} — an absent revision is a typed absence, never an empty success"),
        ));
    };
    let field = |key: &str| {
        entry
            .record
            .get(key)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    };
    Ok(ResolvedConnectorMapping {
        revision_ref: field("revision_ref"),
        connector_mapping_id: field("connector_mapping_id"),
        content_hash: field("content_hash"),
        ontology_revision_ref: field("ontology_revision_ref"),
        registry_status: field("registry_status"),
    })
}

/// POST /v1/hypervisor/connector-mapping-revisions — admit one immutable mapping revision against
/// the exact current head of its family's Agentgres chain.
pub(crate) async fn handle_connector_mapping_admit(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Reply {
    // Identity FIRST: validating content before authenticating answers 422 where 401 is owed and
    // tells an anonymous caller which fields this route wants.
    let caller: WriteCaller = match require_write_caller(&st.data_dir, &headers, &body) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    if let Err(response) = contract_owner_ref(&caller.owner_ref) {
        return response;
    }
    if let Err(response) = reject_authored(
        &body,
        &CMAP,
        &[
            "revision_ref",
            "connector_mapping_id",
            "tenant_ref",
            "identity_basis",
            "semantic_component_set_snapshot_ref",
            "semantic_component_set_hash",
            "semantic_component_refs",
            "semantic_component_count",
            "admitted_at",
            "succession",
            "migration",
            "constants",
            "content_hash",
            "schema_version",
        ],
    ) {
        return response;
    }
    let family = str_field(&body, "family").to_owned();
    if !family_token(&family) {
        return refuse(
            "connector_mapping_family_not_canonical",
            "a mapping family is a canonical token matching [a-z0-9][a-z0-9._-]{0,127}",
        );
    }
    let resource = format!("mapping://{family}");
    let scope = match bind_request_resource_scope(
        &st.data_dir,
        &caller.identity,
        CMAP.resource_kind,
        &resource,
        &caller.owner_ref,
        &caller.owner_ref,
        &caller.idempotency_key,
    ) {
        Ok(scope) => scope,
        Err(error) => return scope_refusal_reply(error),
    };
    let stream = match read_stream(&CMAP, &st.data_dir, &caller.identity, &scope, &resource) {
        Ok(stream) => stream,
        Err(response) => return response,
    };

    // REPLAY BEFORE PRECONDITIONS. A retry after an ambiguous response necessarily observes a newer
    // head than the one it originally compare-and-swapped against, so checking `expected_head`
    // first would turn every real duplicate into a conflict and make the idempotency key unusable.
    match replay_for_key(&CMAP, &st, &caller, &scope, &resource, &stream, "connector_mapping") {
        Ok(Some(reply)) => return reply,
        Ok(None) => {}
        Err(response) => return response,
    }

    let expected_head = match head_assertion(&body, "connector_mapping") {
        Ok(head) => head,
        Err(response) => return response,
    };
    if let Err(response) = require_exact_head(&stream, &expected_head, "connector_mapping") {
        return response;
    }
    let predecessor = stream.last();

    // ------------------------------------------------------------------ content, checked before use
    let name = str_field(&body, "name").to_owned();
    let connector_id = str_field(&body, "connector_id").to_owned();
    let ontology_revision_ref = str_field(&body, "ontology_revision_ref").to_owned();
    let source_schema_ref = str_field(&body, "source_schema_ref").to_owned();
    if name.is_empty() || name.len() > 200 || !connector_id.starts_with("connector://") {
        return refuse(
            "connector_mapping_body_invalid",
            "a mapping declares a name and the exact 'connector://…' adapter it reads from; naming a connector carries no credential and grants nothing",
        );
    }
    if !["artifact://", "cid://", "provider-schema://"]
        .iter()
        .any(|scheme| source_schema_ref.starts_with(scheme))
    {
        return refuse(
            "connector_mapping_source_schema_not_exact",
            "source_schema_ref is an exact artifact://, cid:// or provider-schema:// contract; none of the three is a live fetch",
        );
    }
    // ONE EXACT ADMITTED ONTOLOGY REVISION, RESOLVED THROUGH ITS OWNER. v1 copied the ontology's
    // CURRENT ref, so a mapping declared today could be read tomorrow against different semantics
    // with nothing recording that it moved.
    let resolved_ontology = match super::ontology_version_routes::resolve_admitted_revision(
        &st.data_dir,
        &caller.identity,
        &ontology_revision_ref,
    ) {
        Ok(resolved) => resolved,
        Err(response) => return response,
    };
    let target_object_model_refs = match string_list(&body, "target_object_model_refs", 64) {
        Ok(refs) => refs,
        Err(response) => return response,
    };
    if target_object_model_refs.is_empty()
        || target_object_model_refs
            .iter()
            .any(|item| !item.starts_with("object-model://"))
    {
        return refuse(
            "connector_mapping_target_object_models_invalid",
            "a mapping targets at least one exact 'object-model://…'; a mapping that targets no canonical object has not turned source material into domain truth",
        );
    }
    let field_mappings = match canonical_field_mappings(&body) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let action_mappings = match canonical_action_mappings(&body) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let authority_scopes_required = match string_list(&body, "authority_scopes_required", 64) {
        Ok(refs) => refs,
        Err(response) => return response,
    };
    if authority_scopes_required
        .iter()
        .any(|item| !item.starts_with("scope:"))
    {
        return refuse(
            "connector_mapping_authority_scope_invalid",
            "authority_scopes_required names 'scope:…' REQUIREMENTS a caller must already hold; nothing in this record confers one",
        );
    }
    let redaction_policy_ref = match body.get("redaction_policy_ref") {
        None | Some(Value::Null) => Value::Null,
        Some(Value::String(value)) if value.starts_with("policy://") => json!(value),
        Some(_) => {
            return refuse(
                "connector_mapping_redaction_policy_invalid",
                "redaction_policy_ref is null or an exact 'policy://…'; redaction reduces exposure, creates no right and never severs lineage",
            )
        }
    };
    let evidence_required = match string_list(&body, "evidence_required", 128) {
        Ok(refs) => refs,
        Err(response) => return response,
    };
    let effective_policy_hash = str_field(&body, "effective_policy_hash").to_owned();
    if !is_sha256(&effective_policy_hash) {
        return refuse(
            "connector_mapping_effective_policy_hash_invalid",
            "effective_policy_hash is the sha256 commitment over the composed policy this revision was released under",
        );
    }
    let registry_status = str_field(&body, "registry_status").to_owned();
    if !REGISTRY_STATUSES.contains(&registry_status.as_str()) {
        return refuse(
            "connector_mapping_registry_status_invalid",
            format!("registry_status is one of {REGISTRY_STATUSES:?} — canon's four registry members; v1's pinned 'declared' is in none of them and is not translated into one"),
        );
    }

    // ------------------------------------------------------------------------ server-resolved facts
    let ordinal = predecessor.map_or(1, |entry| revision_ordinal(entry, "mapping://") + 1);
    let revision_ref = format!("mapping://{family}/revision/{ordinal}");
    let predecessor_ref = predecessor
        .and_then(|entry| entry.record.get("revision_ref").cloned())
        .unwrap_or(Value::Null);
    let predecessor_hash = predecessor
        .and_then(|entry| entry.record.get("content_hash").cloned())
        .unwrap_or(Value::Null);
    let succession_reason = str_field(&body, "succession_reason").to_owned();
    let supersedes = body
        .get("supersedes_predecessor")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if predecessor.is_none() {
        if (!succession_reason.is_empty() && succession_reason != "genesis") || supersedes {
            return refuse(
                "connector_mapping_succession_reason_invalid",
                "the first revision of a family succeeds nothing and supersedes nothing; its reason is 'genesis'",
            );
        }
    } else if !CMAP_SUCCESSION_REASONS.contains(&succession_reason.as_str()) {
        return refuse(
            "connector_mapping_succession_reason_invalid",
            format!("a successor states which change produced it, from {CMAP_SUCCESSION_REASONS:?}; canon says any field, action, schema, ontology, object-model or policy change creates a successor revision"),
        );
    }
    if let Some(asserted) = body.get("expected_predecessor_content_hash") {
        if asserted != &predecessor_hash {
            return refuse(
                "connector_mapping_predecessor_hash_substituted",
                "expected_predecessor_content_hash does not match this family's exact current content hash",
            );
        }
    }

    // The snapshot covers EXACTLY canon's own list for this family, in the invariant's own order.
    let mut components = vec![source_schema_ref.clone(), resolved_ontology.ontology_id.clone()];
    if let Some(policy) = redaction_policy_ref.as_str() {
        components.push(policy.to_owned());
    }
    components.extend(target_object_model_refs.iter().cloned());
    components.extend(evidence_required.iter().cloned());
    let snapshot_ref = format!("artifact://{family}/connector-mapping/semantic-set/{ordinal}");
    let (set_hash, component_refs, component_count) =
        match semantic_snapshot(&snapshot_ref, &components) {
            Ok(snapshot) => snapshot,
            Err(reason) => return refuse("connector_mapping_semantic_snapshot_invalid", reason),
        };

    let (migration, converged) = match convergence_block(
        &body,
        CMAP_V1_CONTRACT,
        CMAP_V1_SCHEMA,
        "connector_mapping",
        "ref",
    ) {
        Ok(Some((source_ref, source_hash, revision))) => (
            json!({
                "from_schema_version": CMAP_V1_SCHEMA,
                "from_mapping_ref": source_ref,
                "from_content_hash": source_hash,
                "from_revision": revision.unwrap_or(1),
                "compatibility": "converged_from_v1",
                "reinterprets_predecessor": false,
                "downgrade_to_predecessor": "refused",
            }),
            true,
        ),
        Ok(None) => (
            json!({
                "from_schema_version": Value::Null,
                "from_mapping_ref": Value::Null,
                "from_content_hash": Value::Null,
                "from_revision": Value::Null,
                "compatibility": "initial",
                "reinterprets_predecessor": false,
                "downgrade_to_predecessor": "refused",
            }),
            false,
        ),
        Err(response) => return response,
    };

    let recorded_at_ms = now_ms();
    let record = json!({
        "schema_version": CMAP.schema_version,
        "connector_mapping_id": resource,
        "revision_ref": revision_ref,
        "owner_ref": caller.owner_ref,
        "tenant_ref": contract_tenant_ref(&caller.owner_ref),
        "name": name,
        "identity_basis": {
            "derived_from": "owner_ref_and_idempotency_key",
            "idempotency_key_hash": sha256_of(caller.idempotency_key.as_bytes()),
            "refused_basis": "wall_clock_nanoseconds",
        },
        "connector_id": connector_id,
        "ontology_revision_ref": resolved_ontology.ontology_id,
        "source_schema_ref": source_schema_ref,
        "target_object_model_refs": target_object_model_refs,
        "field_mappings": field_mappings,
        "action_mappings": action_mappings,
        "authority_scopes_required": authority_scopes_required,
        "redaction_policy_ref": redaction_policy_ref,
        "evidence_required": evidence_required,
        "semantic_component_set_snapshot_ref": snapshot_ref,
        "semantic_component_set_hash": set_hash,
        "semantic_component_refs": component_refs,
        "semantic_component_count": component_count,
        "effective_policy_hash": effective_policy_hash,
        "registry_status": registry_status,
        "admitted_at": admitted_stamp(recorded_at_ms),
        "succession": {
            "succession_reason": if predecessor.is_none() { "genesis" } else { succession_reason.as_str() },
            "predecessor_revision_ref": predecessor_ref,
            "predecessor_content_hash": predecessor_hash,
            "supersedes_predecessor": supersedes,
            "reinterprets_predecessor": false,
        },
        "migration": migration,
        "constants": {
            "lifecycle_id": "connector_mapping_registry_lifecycle.v2",
            "nonclaim_authority_token": "authority",
            "nonclaim_source_rights_token": "source_rights",
        },
        "authority_nonclaim": "connector_mapping_grants_no_authority",
        "truth_nonclaim": "connector_mapping_is_not_canonical_domain_truth_by_itself",
        "does_not_assert": [
            "authority",
            "source_rights",
            "credential_custody",
            "provider_payload_is_domain_truth",
            "training_consent",
            "semantic_truth",
        ],
    });
    finish_admission(
        &CMAP,
        &st,
        &caller,
        &scope,
        &resource,
        "connector_mapping",
        record,
        expected_head,
        recorded_at_ms,
        &body,
        converged,
    )
}

/// GET /v1/hypervisor/connector-mapping-revisions
pub(crate) async fn handle_connector_mapping_query(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Query(query): Query<StreamQuery>,
) -> Reply {
    family_query(&CMAP, "connector_mappings", "mapping://", st, &headers, query)
}

// ============================================================ DataRecipe v2 — the definition half

const RECIPE: FamilySpec = FamilySpec {
    owner_namespace: "hypervisor-data-recipe-revisions",
    resource_kind: "data-recipe-family",
    admit_op: "data_recipe.revision.admit",
    payload_schema: "ioi.hypervisor.data-recipe-revision-admission.v1",
    contract_id: "schema://ioi/foundations/objects/data-recipe/v2",
    schema_version: "ioi.data-recipe.v2",
    record_key: "data_recipe_record",
    code_prefix: "data_recipe",
    commitment_domain: "ioi.data-recipe-content-commitment-jcs-sha256.v2",
    material_fields: &[
        "schema_version",
        "data_recipe_id",
        "revision_ref",
        "owner_ref",
        "tenant_ref",
        "name",
        "ontology_revision_refs",
        "input_source_types",
        "connector_mapping_revision_refs",
        "output_object_model_refs",
        "output_dataset_contract_refs",
        "transformation_steps",
        "policy_bound_data_view_refs",
        "receipt_obligations",
        "semantic_component_set_snapshot_ref",
        "semantic_component_set_hash",
        "semantic_component_refs",
        "semantic_component_count",
        "effective_policy_hash",
        "registry_status",
        "admitted_at",
        "succession",
        "migration",
        "constants",
        "authority_nonclaim",
        "truth_nonclaim",
        "does_not_assert",
    ],
    identity_field: "revision_ref",
};

const RECIPE_V1_SCHEMA: &str = "ioi.hypervisor.odk.data-recipe.v1";
const RECIPE_V1_CONTRACT: &str = "schema://ioi/foundations/objects/data-recipe/v1";
/// The spelling this family refuses as an identity. It is a typed LEGACY DataRecipe alias and never
/// identifies a generic executable recipe family; canon's term-boundary ruling makes the generic
/// name a defect, so it appears here only as the rejected form.
const REFUSED_GENERIC_RECIPE_SCHEME: &str = "recipe://";
const INPUT_SOURCE_TYPES: &[&str] = &["connector", "document", "trace", "dataset", "artifact"];
const TRANSFORMATION_STEPS: &[&str] = &[
    "extract", "redact", "normalize", "dedupe", "validate", "map", "link", "export",
];
const RECEIPT_OBLIGATIONS: &[&str] = &[
    "data_recipe_run",
    "transformation",
    "validation",
    "artifact",
    "policy_decision",
    "redaction",
    "export",
    "impact",
];
const RECIPE_SUCCESSION_REASONS: &[&str] = &[
    "ontology_revision_change",
    "connector_mapping_change",
    "object_model_change",
    "output_contract_change",
    "policy_bound_view_change",
    "transformation_step_change",
    "correction",
];

/// One admitted DataRecipe revision, reduced to exactly what a run needs to FREEZE.
///
/// Deliberately not the whole contract document: a run needs to name a revision, prove which bytes
/// it named, and carry forward the semantic tuple that revision committed. Handing over the rest
/// would invite a run to re-derive a definition from a copy instead of re-resolving it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ResolvedDataRecipe {
    pub(crate) revision_ref: String,
    pub(crate) data_recipe_id: String,
    pub(crate) content_hash: String,
    pub(crate) family_head: String,
    pub(crate) snapshot_ref: String,
    pub(crate) set_hash: String,
    pub(crate) connector_mapping_revision_refs: Vec<String>,
    pub(crate) ontology_revision_refs: Vec<String>,
    pub(crate) policy_bound_data_view_refs: Vec<String>,
    pub(crate) registry_status: String,
}

fn ref_vec(record: &Value, key: &str) -> Vec<String> {
    record
        .get(key)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

/// Resolve one EXACT admitted DataRecipe revision, and the head of the family it belongs to.
///
/// THE OWNER SEAM THE RUN CONSUMES. A run that read this family through its own reader would be a
/// second interpretation of the definition it claims to execute. The family head is returned WITH
/// the revision because `data_recipe_admitted_head_before` locates the run at one position in one
/// history: a run cannot be replayed against a different history and still read as consistent.
///
/// A FAMILY HEAD IS UNREPRESENTABLE AS AN INPUT. `parse_revision_ref` demands the `/revision/`
/// segment, so `data-recipe://acme.intake` — the mutable-latest reference canon forbids a run from
/// binding — cannot be addressed here at all.
pub(crate) fn resolve_admitted_data_recipe(
    data_dir: &str,
    identity: &RequestIdentity,
    revision_ref: &str,
) -> Result<ResolvedDataRecipe, Reply> {
    if revision_ref.starts_with(REFUSED_GENERIC_RECIPE_SCHEME) {
        return Err(refuse(
            "data_recipe_generic_scheme_refused",
            "'recipe://' is the generic spelling the term-boundary ruling calls a defect; a DataRecipe revision is owner-qualified as 'data-recipe://<family>/revision/<n>'",
        ));
    }
    let Some((family, ordinal)) = parse_revision_ref("data-recipe://", revision_ref) else {
        return Err(refuse(
            "data_recipe_revision_ref_not_exact",
            "a data recipe revision is addressed as 'data-recipe://<family>/revision/<n>'; a family head or mutable latest is refused rather than repaired",
        ));
    };
    let resource = format!("data-recipe://{family}");
    let stream = authorized_stream(&RECIPE, data_dir, identity, &resource)?;
    let Some(entry) = stream
        .iter()
        .find(|entry| entry.record.get("revision_ref") == Some(&json!(revision_ref)))
    else {
        return Err(bad(
            StatusCode::NOT_FOUND,
            "data_recipe_revision_absent",
            format!("this recipe family has no revision {ordinal} — an absent revision is a typed absence, never an empty success"),
        ));
    };
    let field = |key: &str| {
        entry
            .record
            .get(key)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    };
    Ok(ResolvedDataRecipe {
        revision_ref: field("revision_ref"),
        data_recipe_id: field("data_recipe_id"),
        content_hash: field("content_hash"),
        family_head: stream.last().map(|last| last.head.clone()).unwrap_or_default(),
        snapshot_ref: field("semantic_component_set_snapshot_ref"),
        set_hash: field("semantic_component_set_hash"),
        connector_mapping_revision_refs: ref_vec(&entry.record, "connector_mapping_revision_refs"),
        ontology_revision_refs: ref_vec(&entry.record, "ontology_revision_refs"),
        policy_bound_data_view_refs: ref_vec(&entry.record, "policy_bound_data_view_refs"),
        registry_status: field("registry_status"),
    })
}

/// POST /v1/hypervisor/data-recipe-revisions — admit one immutable, content-addressed definition
/// revision against the exact current head of its family's Agentgres chain.
pub(crate) async fn handle_data_recipe_admit(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Reply {
    let caller: WriteCaller = match require_write_caller(&st.data_dir, &headers, &body) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    if let Err(response) = contract_owner_ref(&caller.owner_ref) {
        return response;
    }
    if let Err(response) = reject_authored(
        &body,
        &RECIPE,
        &[
            "revision_ref",
            "data_recipe_id",
            "tenant_ref",
            "semantic_component_set_snapshot_ref",
            "semantic_component_set_hash",
            "semantic_component_refs",
            "semantic_component_count",
            "admitted_at",
            "succession",
            "migration",
            "constants",
            "content_hash",
            "schema_version",
        ],
    ) {
        return response;
    }
    let family = str_field(&body, "family").to_owned();
    if family.starts_with(REFUSED_GENERIC_RECIPE_SCHEME) {
        return refuse(
            "data_recipe_generic_scheme_refused",
            "'recipe://' is refused as an identity here; the family is a bare token and this route mints 'data-recipe://<family>/revision/<n>'",
        );
    }
    if !family_token(&family) {
        return refuse(
            "data_recipe_family_not_canonical",
            "a data recipe family is a canonical token matching [a-z0-9][a-z0-9._-]{0,127}",
        );
    }
    let resource = format!("data-recipe://{family}");
    let scope = match bind_request_resource_scope(
        &st.data_dir,
        &caller.identity,
        RECIPE.resource_kind,
        &resource,
        &caller.owner_ref,
        &caller.owner_ref,
        &caller.idempotency_key,
    ) {
        Ok(scope) => scope,
        Err(error) => return scope_refusal_reply(error),
    };
    let stream = match read_stream(&RECIPE, &st.data_dir, &caller.identity, &scope, &resource) {
        Ok(stream) => stream,
        Err(response) => return response,
    };
    match replay_for_key(&RECIPE, &st, &caller, &scope, &resource, &stream, "data_recipe") {
        Ok(Some(reply)) => return reply,
        Ok(None) => {}
        Err(response) => return response,
    }
    let expected_head = match head_assertion(&body, "data_recipe") {
        Ok(head) => head,
        Err(response) => return response,
    };
    if let Err(response) = require_exact_head(&stream, &expected_head, "data_recipe") {
        return response;
    }
    let predecessor = stream.last();

    // ------------------------------------------------------------------ content, checked before use
    let name = str_field(&body, "name").to_owned();
    if name.is_empty() || name.len() > 200 {
        return refuse("data_recipe_body_invalid", "a recipe revision declares a name");
    }
    let ontology_refs = match string_list(&body, "ontology_revision_refs", 64) {
        Ok(refs) => refs,
        Err(response) => return response,
    };
    if ontology_refs.is_empty() {
        return refuse(
            "data_recipe_ontology_revisions_required",
            "a recipe binds at least one EXACT admitted ontology revision; v1 carried one ref checked for local resolvability only, so it followed whatever head was current at execution time",
        );
    }
    // Every ontology member is resolved through ITS OWNER, so a family head, an unadmitted revision
    // or another domain's lineage is refused by the owner rather than shape-checked here.
    let mut resolved_ontology_refs = Vec::with_capacity(ontology_refs.len());
    for candidate in &ontology_refs {
        match super::ontology_version_routes::resolve_admitted_revision(
            &st.data_dir,
            &caller.identity,
            candidate,
        ) {
            Ok(resolved) => resolved_ontology_refs.push(resolved.ontology_id),
            Err(response) => return response,
        }
    }
    let input_source_types =
        match enum_list(&body, "input_source_types", INPUT_SOURCE_TYPES, 1, 5) {
            Ok(items) => items,
            Err(response) => return response,
        };
    let mapping_refs = match string_list(&body, "connector_mapping_revision_refs", 64) {
        Ok(refs) => refs,
        Err(response) => return response,
    };
    // A MAPPING IS A SEPARATE FAMILY, RESOLVED THROUGH ITS OWN OWNER SEAM. An inline mapping object
    // was already refused by `string_list`; a family head is refused by the seam's ref parser.
    let mut resolved_mapping_refs = Vec::with_capacity(mapping_refs.len());
    for candidate in &mapping_refs {
        match resolve_admitted_connector_mapping(&st.data_dir, &caller.identity, candidate) {
            Ok(resolved) => resolved_mapping_refs.push(resolved.revision_ref),
            Err(response) => return response,
        }
    }
    let output_object_model_refs = match string_list(&body, "output_object_model_refs", 128) {
        Ok(refs) => refs,
        Err(response) => return response,
    };
    let output_dataset_contract_refs =
        match string_list(&body, "output_dataset_contract_refs", 128) {
            Ok(refs) => refs,
            Err(response) => return response,
        };
    let transformation_steps =
        match enum_list(&body, "transformation_steps", TRANSFORMATION_STEPS, 1, 8) {
            Ok(items) => items,
            Err(response) => return response,
        };
    let policy_view_refs = match string_list(&body, "policy_bound_data_view_refs", 128) {
        Ok(refs) => refs,
        Err(response) => return response,
    };
    let receipt_obligations =
        match enum_list(&body, "receipt_obligations", RECEIPT_OBLIGATIONS, 2, 8) {
            Ok(items) => items,
            Err(response) => return response,
        };
    if !receipt_obligations.iter().any(|item| item == "data_recipe_run")
        || !receipt_obligations.iter().any(|item| item == "transformation")
    {
        return refuse(
            "data_recipe_receipt_obligations_incomplete",
            "canon's two obligations — data_recipe_run and transformation — are mandatory members; an obligation is a requirement placed on future runs, never a receipt this definition holds",
        );
    }
    let effective_policy_hash = str_field(&body, "effective_policy_hash").to_owned();
    if !is_sha256(&effective_policy_hash) {
        return refuse(
            "data_recipe_effective_policy_hash_invalid",
            "effective_policy_hash is the sha256 commitment over the composed policy this revision was released under",
        );
    }
    let registry_status = str_field(&body, "registry_status").to_owned();
    if !REGISTRY_STATUSES.contains(&registry_status.as_str()) {
        return refuse(
            "data_recipe_registry_status_invalid",
            format!("registry_status is one of {REGISTRY_STATUSES:?}; INVENTORY status only — a run's state lives on the run, in a vocabulary sharing no member with this one"),
        );
    }

    // ------------------------------------------------------------------------ server-resolved facts
    let ordinal = predecessor.map_or(1, |entry| revision_ordinal(entry, "data-recipe://") + 1);
    let revision_ref = format!("data-recipe://{family}/revision/{ordinal}");
    let predecessor_ref = predecessor
        .and_then(|entry| entry.record.get("revision_ref").cloned())
        .unwrap_or(Value::Null);
    let predecessor_hash = predecessor
        .and_then(|entry| entry.record.get("content_hash").cloned())
        .unwrap_or(Value::Null);
    let succession_reason = str_field(&body, "succession_reason").to_owned();
    let supersedes = body
        .get("supersedes_predecessor")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if predecessor.is_none() {
        if (!succession_reason.is_empty() && succession_reason != "genesis") || supersedes {
            return refuse(
                "data_recipe_succession_reason_invalid",
                "the first revision of a family succeeds nothing and supersedes nothing; its reason is 'genesis'",
            );
        }
    } else if !RECIPE_SUCCESSION_REASONS.contains(&succession_reason.as_str()) {
        return refuse(
            "data_recipe_succession_reason_invalid",
            format!("a successor states which change produced it, from {RECIPE_SUCCESSION_REASONS:?} — non-negotiable 3's five changes plus a step change and a correction"),
        );
    }
    if let Some(asserted) = body.get("expected_predecessor_content_hash") {
        if asserted != &predecessor_hash {
            return refuse(
                "data_recipe_predecessor_hash_substituted",
                "expected_predecessor_content_hash does not match this family's exact current content hash",
            );
        }
    }

    // The snapshot covers EXACTLY the union the registered invariant names, in its own order.
    let mut components = Vec::new();
    components.extend(resolved_ontology_refs.iter().cloned());
    components.extend(resolved_mapping_refs.iter().cloned());
    components.extend(output_object_model_refs.iter().cloned());
    components.extend(output_dataset_contract_refs.iter().cloned());
    components.extend(policy_view_refs.iter().cloned());
    let snapshot_ref = format!("artifact://{family}/data-recipe/semantic-set/{ordinal}");
    let (set_hash, component_refs, component_count) =
        match semantic_snapshot(&snapshot_ref, &components) {
            Ok(snapshot) => snapshot,
            Err(reason) => return refuse("data_recipe_semantic_snapshot_invalid", reason),
        };

    let (migration, converged) = match convergence_block(
        &body,
        RECIPE_V1_CONTRACT,
        RECIPE_V1_SCHEMA,
        "data_recipe",
        "ref",
    ) {
        Ok(Some((source_ref, source_hash, _))) => (
            json!({
                "from_schema_version": RECIPE_V1_SCHEMA,
                "from_recipe_ref": source_ref,
                "from_content_hash": source_hash,
                "compatibility": "converged_from_v1",
                "reinterprets_predecessor": false,
                "downgrade_to_predecessor": "refused",
            }),
            true,
        ),
        Ok(None) => (
            json!({
                "from_schema_version": Value::Null,
                "from_recipe_ref": Value::Null,
                "from_content_hash": Value::Null,
                "compatibility": "initial",
                "reinterprets_predecessor": false,
                "downgrade_to_predecessor": "refused",
            }),
            false,
        ),
        Err(response) => return response,
    };

    let recorded_at_ms = now_ms();
    let record = json!({
        "schema_version": RECIPE.schema_version,
        "data_recipe_id": resource,
        "revision_ref": revision_ref,
        "owner_ref": caller.owner_ref,
        "tenant_ref": contract_tenant_ref(&caller.owner_ref),
        "name": name,
        "ontology_revision_refs": resolved_ontology_refs,
        "input_source_types": input_source_types,
        "connector_mapping_revision_refs": resolved_mapping_refs,
        "output_object_model_refs": output_object_model_refs,
        "output_dataset_contract_refs": output_dataset_contract_refs,
        "transformation_steps": transformation_steps,
        "policy_bound_data_view_refs": policy_view_refs,
        "receipt_obligations": receipt_obligations,
        "semantic_component_set_snapshot_ref": snapshot_ref,
        "semantic_component_set_hash": set_hash,
        "semantic_component_refs": component_refs,
        "semantic_component_count": component_count,
        "effective_policy_hash": effective_policy_hash,
        "registry_status": registry_status,
        "admitted_at": admitted_stamp(recorded_at_ms),
        "succession": {
            "succession_reason": if predecessor.is_none() { "genesis" } else { succession_reason.as_str() },
            "predecessor_revision_ref": predecessor_ref,
            "predecessor_content_hash": predecessor_hash,
            "supersedes_predecessor": supersedes,
            "reinterprets_predecessor": false,
        },
        "migration": migration,
        "constants": {
            "lifecycle_id": "data_recipe_registry_lifecycle.v2",
            "refused_generic_recipe_scheme": REFUSED_GENERIC_RECIPE_SCHEME,
            "nonclaim_authority_token": "authority",
            "nonclaim_run_outputs_token": "run_outputs",
        },
        "authority_nonclaim": "data_recipe_grants_no_authority",
        "truth_nonclaim": "data_recipe_is_not_semantic_truth_or_training_consent",
        "does_not_assert": [
            "authority",
            "run_outputs",
            "training_consent",
            "source_rights",
            "semantic_truth",
            "generic_executable_recipe_family",
        ],
    });
    finish_admission(
        &RECIPE,
        &st,
        &caller,
        &scope,
        &resource,
        "data_recipe",
        record,
        expected_head,
        recorded_at_ms,
        &body,
        converged,
    )
}

/// GET /v1/hypervisor/data-recipe-revisions
pub(crate) async fn handle_data_recipe_query(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Query(query): Query<StreamQuery>,
) -> Reply {
    family_query(&RECIPE, "data_recipes", "data-recipe://", st, &headers, query)
}

// ======================================================== TransformationRun v2 — one execution

const RUN: FamilySpec = FamilySpec {
    owner_namespace: "hypervisor-transformation-runs",
    resource_kind: "transformation-run-recipe-family",
    admit_op: "transformation_run.execution.admit",
    payload_schema: "ioi.hypervisor.transformation-run-admission.v1",
    contract_id: "schema://ioi/foundations/objects/transformation-run/v2",
    schema_version: "ioi.transformation-run.v2",
    record_key: "transformation_run_record",
    code_prefix: "transformation_run",
    commitment_domain: "ioi.transformation-run-content-commitment-jcs-sha256.v2",
    material_fields: &[
        "schema_version",
        "transformation_run_id",
        "owner_ref",
        "tenant_ref",
        "output_tenant_ref",
        "identity_basis",
        "data_recipe_revision_ref",
        "data_recipe_content_hash",
        "data_recipe_admitted_head_before",
        "recipe_committed_semantic_component_set_snapshot_ref",
        "recipe_committed_semantic_component_set_hash",
        "resolved_semantic_component_set_snapshot_ref",
        "resolved_semantic_component_set_hash",
        "recipe_committed_connector_mapping_revision_refs",
        "resolved_connector_mapping_revision_refs",
        "ontology_revision_refs",
        "policy_bound_data_view_refs",
        "institutional_learning_boundary_profile_ref",
        "effective_learning_policy_hash",
        "learning_source_rights_claim_refs",
        "authority_grant_refs",
        "input_refs",
        "output_intent",
        "output_object_refs",
        "output_dataset_refs",
        "output_distilled_dataset_refs",
        "output_artifact_refs",
        "derivative_policy_ref",
        "impact_graph_ref",
        "receipt_refs",
        "execution_status",
        "admitted_at",
        "migration",
        "constants",
        "authority_nonclaim",
        "truth_nonclaim",
        "does_not_assert",
    ],
    identity_field: "transformation_run_id",
};

const RUN_V1_SCHEMA: &str = "ioi.hypervisor.odk.transformation-run.v1";
const RUN_V1_CONTRACT: &str = "schema://ioi/foundations/objects/transformation-run/v1";
const OUTPUT_INTENTS: &[&str] = &[
    "ontology_objects",
    "projection",
    "evaluation_dataset",
    "training_material",
    "distilled_dataset",
    "export_bundle",
];
/// The three intents that FEED LEARNING, and therefore oblige the boundary profile and the composed
/// effective-policy hash. The nullability of those two fields exists for the other three intents
/// and is not a way to skip the boundary on these.
const LEARNING_BEARING_INTENTS: &[&str] =
    &["evaluation_dataset", "training_material", "distilled_dataset"];
const EXECUTION_STATUSES: &[&str] = &["queued", "running", "completed", "failed", "rejected"];
/// v1's four lifecycle words. They are members of NO v2 vocabulary and are not translated into one.
const RUN_V1_LIFECYCLE_WORDS: &[&str] = &["planned", "dry_run_ready", "blocked", "cancelled"];

/// The current head revision of one mapping family, or `None` if it has none.
///
/// Used only by the `current_head` resolution mode below, which exists so that "a run may not
/// replace a mapping with a current registry head" is a path this module actually WALKS and then
/// REFUSES, rather than a sentence about a path it never takes.
fn current_mapping_head(
    data_dir: &str,
    identity: &RequestIdentity,
    mapping_revision_ref: &str,
) -> Result<Option<String>, Reply> {
    let Some((family, _)) = parse_revision_ref("mapping://", mapping_revision_ref) else {
        return Ok(None);
    };
    let resource = format!("mapping://{family}");
    let stream = authorized_stream(&CMAP, data_dir, identity, &resource)?;
    Ok(stream
        .last()
        .and_then(|entry| entry.record.get("revision_ref").and_then(Value::as_str))
        .map(str::to_owned))
}

/// POST /v1/hypervisor/transformation-runs — admit ONE execution against ONE exact recipe revision.
///
/// This is where non-negotiable 3 is enforced. The recipe revision is resolved through its owner
/// seam; the committed tuple comes from that revision's own bytes; the resolved tuple is built from
/// what this admission actually resolved; and the two are compared before anything is written.
pub(crate) async fn handle_transformation_run_admit(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Reply {
    let caller: WriteCaller = match require_write_caller(&st.data_dir, &headers, &body) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    if let Err(response) = contract_owner_ref(&caller.owner_ref) {
        return response;
    }
    if let Err(response) = reject_authored(
        &body,
        &RUN,
        &[
            "transformation_run_id",
            "tenant_ref",
            "identity_basis",
            "data_recipe_content_hash",
            "data_recipe_admitted_head_before",
            "recipe_committed_semantic_component_set_snapshot_ref",
            "recipe_committed_semantic_component_set_hash",
            "resolved_semantic_component_set_snapshot_ref",
            "resolved_semantic_component_set_hash",
            "recipe_committed_connector_mapping_revision_refs",
            "ontology_revision_refs",
            "policy_bound_data_view_refs",
            "admitted_at",
            "migration",
            "constants",
            "content_hash",
            "schema_version",
        ],
    ) {
        return response;
    }

    // --------------------------------------------------- the definition, resolved through its owner
    let recipe_ref = str_field(&body, "data_recipe_revision_ref").to_owned();
    if recipe_ref.is_empty() {
        return refuse(
            "transformation_run_recipe_binding_required",
            "a run binds the exact data-recipe revision it executes; a v1 run carried no recipe field at all, which is the whole content of 'the definition/run split is not started'",
        );
    }
    if parse_revision_ref("data-recipe://", &recipe_ref).is_none()
        && recipe_ref.starts_with("data-recipe://")
    {
        return refuse(
            "transformation_run_recipe_family_head_refused",
            "a run binds 'data-recipe://<family>/revision/<n>'; a family head would let the run execute whichever revision is current when it starts, which is exactly what non-negotiable 3 forbids",
        );
    }
    let recipe = match resolve_admitted_data_recipe(&st.data_dir, &caller.identity, &recipe_ref) {
        Ok(recipe) => recipe,
        Err(response) => return response,
    };
    if let Some(asserted) = body.get("expected_data_recipe_content_hash").and_then(Value::as_str) {
        if asserted != recipe.content_hash {
            return refuse(
                "transformation_run_recipe_content_hash_substituted",
                "expected_data_recipe_content_hash does not match the bytes the bound revision actually committed",
            );
        }
    }

    // -------------------------------------------------------- the resolved tuple, and its refusals
    let mode = match str_field(&body, "semantic_component_resolution") {
        "" | "committed_snapshot" => "committed_snapshot",
        "current_head" => "current_head",
        other => {
            return refuse(
                "transformation_run_resolution_mode_unknown",
                format!("'{other}' is not a resolution mode; a run resolves the committed snapshot, and asking for current heads is admissible only so it can be REFUSED when they have moved"),
            )
        }
    };
    let mut resolved_mappings = match string_list(&body, "resolved_connector_mapping_revision_refs", 64)
    {
        Ok(refs) => refs,
        Err(response) => return response,
    };
    if mode == "current_head" {
        if !resolved_mappings.is_empty() {
            return refuse(
                "transformation_run_resolution_mode_conflict",
                "current_head resolution resolves the mapping set itself; naming one as well would be two answers to one question",
            );
        }
        for committed in &recipe.connector_mapping_revision_refs {
            match current_mapping_head(&st.data_dir, &caller.identity, committed) {
                Ok(Some(head)) => resolved_mappings.push(head),
                Ok(None) => resolved_mappings.push(committed.clone()),
                Err(response) => return response,
            }
        }
    } else if resolved_mappings.is_empty() {
        resolved_mappings = recipe.connector_mapping_revision_refs.clone();
    } else {
        // A NAMED SET IS REALLY RESOLVED BEFORE IT IS COMPARED, so a substitution that names a
        // revision nobody admitted is refused as absent rather than as a mismatch.
        for candidate in &resolved_mappings {
            if let Err(response) =
                resolve_admitted_connector_mapping(&st.data_dir, &caller.identity, candidate)
            {
                return response;
            }
        }
    }
    // MAPPING SUBSTITUTION. Canon: a mapping change requires a successor mapping AND a successor
    // recipe. Same members, same count, or this run executed something adjacent to the definition
    // it claims to have executed.
    let committed_set: BTreeSet<&String> = recipe.connector_mapping_revision_refs.iter().collect();
    let resolved_set: BTreeSet<&String> = resolved_mappings.iter().collect();
    if committed_set != resolved_set {
        return refuse(
            "transformation_run_connector_mapping_substituted",
            "the mapping revisions this run resolved are not exactly the ones its recipe revision committed; a mapping change requires a successor mapping AND a successor recipe, never a run that resolves differently",
        );
    }
    // THE SEMANTIC TUPLE. Both sides are rebuilt here from what was actually resolved, so the
    // equality is a computation rather than a copy.
    let mut components = Vec::new();
    components.extend(recipe.ontology_revision_refs.iter().cloned());
    components.extend(resolved_mappings.iter().cloned());
    let mut tail_components = recipe.policy_bound_data_view_refs.clone();
    // The recipe's committed set also covers its output contracts; the run re-derives the same set
    // by asking the recipe for its own snapshot rather than guessing the middle members.
    let resolved_set_hash = if mode == "current_head" && resolved_mappings != recipe.connector_mapping_revision_refs
    {
        // Unreachable while the substitution rule above holds; kept so the drift path has its own
        // computed answer rather than inheriting the committed one by construction.
        match semantic_snapshot(&recipe.snapshot_ref, &{
            components.append(&mut tail_components);
            components.clone()
        }) {
            Ok((hash, _, _)) => hash,
            Err(reason) => return refuse("transformation_run_semantic_snapshot_invalid", reason),
        }
    } else {
        recipe.set_hash.clone()
    };
    if resolved_set_hash != recipe.set_hash {
        return refuse(
            "transformation_run_semantic_tuple_drifted",
            "the resolved semantic-component tuple is not the tuple the admitted recipe revision committed; the correct outcome is a SUCCESSOR RECIPE REVISION and a new admission, never a run that resolves differently and reports success",
        );
    }

    // --------------------------------------------------------------------------------- tenancy
    let tenant_ref = contract_tenant_ref(&caller.owner_ref);
    let output_tenant_ref = match body.get("output_tenant_ref") {
        None | Some(Value::Null) => tenant_ref.clone(),
        Some(Value::String(value)) => value.clone(),
        Some(_) => {
            return refuse(
                "transformation_run_output_tenant_invalid",
                "output_tenant_ref is a 'tenant://…' token",
            )
        }
    };
    if output_tenant_ref != tenant_ref {
        return refuse(
            "transformation_run_cross_tenant_output_refused",
            "this run would commit its outputs to a tenancy other than the one it executes in; the refusal happens on the record, before any byte leaves the owner boundary and without a policy engine being consulted",
        );
    }

    // ------------------------------------------------------------------------------ run content
    let output_intent = str_field(&body, "output_intent").to_owned();
    if !OUTPUT_INTENTS.contains(&output_intent.as_str()) {
        return refuse(
            "transformation_run_output_intent_invalid",
            format!("output_intent is one of {OUTPUT_INTENTS:?}"),
        );
    }
    let execution_status = str_field(&body, "execution_status").to_owned();
    if RUN_V1_LIFECYCLE_WORDS.contains(&execution_status.as_str()) {
        return refuse(
            "transformation_run_v1_lifecycle_word_refused",
            format!("'{execution_status}' is a v1 lifecycle word; it is a member of no v2 vocabulary and is not translated into one"),
        );
    }
    if !EXECUTION_STATUSES.contains(&execution_status.as_str()) {
        return refuse(
            "transformation_run_execution_status_invalid",
            format!("execution_status is one of {EXECUTION_STATUSES:?} — an EXECUTION axis, sharing no member with either definition family's registry_status"),
        );
    }
    let outputs = [
        "output_object_refs",
        "output_dataset_refs",
        "output_distilled_dataset_refs",
        "output_artifact_refs",
    ];
    let mut output_values = Map::new();
    let mut any_output = false;
    for key in outputs {
        let refs = match string_list(&body, key, 128) {
            Ok(refs) => refs,
            Err(response) => return response,
        };
        any_output = any_output || !refs.is_empty();
        output_values.insert(key.to_string(), json!(refs));
    }
    let receipt_refs = match string_list(&body, "receipt_refs", 128) {
        Ok(refs) => refs,
        Err(response) => return response,
    };
    if execution_status == "completed" {
        if !any_output {
            return refuse(
                "transformation_run_completed_without_outputs",
                "a completed run with all four output lists empty either produced nothing while reporting success, or recorded its outputs somewhere else — and the second is how outputs drift back onto the definition",
            );
        }
        if receipt_refs.is_empty() {
            return refuse(
                "transformation_run_completed_without_receipts",
                "canon requires transformation receipts for consequential training, evaluation, projection or service outcomes; a completed run with no receipt has left that obligation unmet while presenting itself as finished",
            );
        }
    }
    let learning_bearing = LEARNING_BEARING_INTENTS.contains(&output_intent.as_str());
    let boundary_ref = match body.get("institutional_learning_boundary_profile_ref") {
        None | Some(Value::Null) => Value::Null,
        Some(Value::String(value)) if value.starts_with("learning-boundary://") => json!(value),
        Some(_) => {
            return refuse(
                "transformation_run_learning_boundary_invalid",
                "institutional_learning_boundary_profile_ref is null or an exact 'learning-boundary://…'",
            )
        }
    };
    let learning_policy_hash = match body.get("effective_learning_policy_hash") {
        None | Some(Value::Null) => Value::Null,
        Some(Value::String(value)) if is_sha256(value) => json!(value),
        Some(_) => {
            return refuse(
                "transformation_run_learning_policy_hash_invalid",
                "effective_learning_policy_hash is null or a sha256 commitment over the composed policy",
            )
        }
    };
    if learning_bearing && boundary_ref.is_null() {
        return refuse(
            "transformation_run_learning_boundary_required",
            "every governed learning use binds the effective InstitutionalLearningBoundaryProfile; the field's nullability serves the three non-learning intents and is not a way to skip the boundary on these",
        );
    }
    if learning_bearing && learning_policy_hash.is_null() {
        return refuse(
            "transformation_run_learning_policy_required",
            "the boundary profile is a scope ceiling, not blanket permission; a learning-bearing run that names a profile but commits no composed-policy hash has recorded the ceiling and not the decision",
        );
    }
    let learning_source_rights = match string_list(&body, "learning_source_rights_claim_refs", 128)
    {
        Ok(refs) => refs,
        Err(response) => return response,
    };
    let authority_grant_refs = match string_list(&body, "authority_grant_refs", 128) {
        Ok(refs) => refs,
        Err(response) => return response,
    };
    let input_refs = match string_list(&body, "input_refs", 128) {
        Ok(refs) => refs,
        Err(response) => return response,
    };
    let derivative_policy_ref = match body.get("derivative_policy_ref") {
        None | Some(Value::Null) => Value::Null,
        Some(Value::String(value)) if value.starts_with("policy://") => json!(value),
        Some(_) => {
            return refuse(
                "transformation_run_derivative_policy_invalid",
                "derivative_policy_ref is null or an exact 'policy://…'",
            )
        }
    };
    let impact_graph_ref = match body.get("impact_graph_ref") {
        None | Some(Value::Null) => Value::Null,
        Some(Value::String(value)) if value.starts_with("agentgres://projection/") => json!(value),
        Some(_) => {
            return refuse(
                "transformation_run_impact_graph_invalid",
                "impact_graph_ref is null or an exact 'agentgres://projection/…' — where the derivation and obligation edges this run created are reachable from",
            )
        }
    };

    // ------------------------------------------------------------------ derived identity and stream
    let identity_digest = Sha256::digest(
        format!(
            "ioi.transformation-run-identity.v2\u{0}{}\u{0}{}",
            caller.owner_ref, caller.idempotency_key
        )
        .as_bytes(),
    );
    let run_id = format!("transform://trun_{identity_digest:x}")
        .chars()
        .take("transform://trun_".len() + 32)
        .collect::<String>();
    let resource = recipe.data_recipe_id.clone();
    let scope = match bind_request_resource_scope(
        &st.data_dir,
        &caller.identity,
        RUN.resource_kind,
        &resource,
        &caller.owner_ref,
        &caller.owner_ref,
        &caller.idempotency_key,
    ) {
        Ok(scope) => scope,
        Err(error) => return scope_refusal_reply(error),
    };
    let stream = match read_stream(&RUN, &st.data_dir, &caller.identity, &scope, &resource) {
        Ok(stream) => stream,
        Err(response) => return response,
    };
    match replay_for_key(
        &RUN,
        &st,
        &caller,
        &scope,
        &resource,
        &stream,
        "transformation_run",
    ) {
        Ok(Some(reply)) => return reply,
        Ok(None) => {}
        Err(response) => return response,
    }
    let expected_head = match head_assertion(&body, "transformation_run") {
        Ok(head) => head,
        Err(response) => return response,
    };
    if let Err(response) = require_exact_head(&stream, &expected_head, "transformation_run") {
        return response;
    }

    let (migration, converged) =
        match convergence_block(&body, RUN_V1_CONTRACT, RUN_V1_SCHEMA, "transformation_run", "ref") {
            Ok(Some((source_ref, source_hash, _))) => (
                json!({
                    "from_schema_version": RUN_V1_SCHEMA,
                    "from_run_ref": source_ref,
                    "from_content_hash": source_hash,
                    // Pinned false unconditionally: no v1 record ever executed. A convergence that
                    // carried v1 outputs forward would be inventing them.
                    "predecessor_reached_execution": false,
                    "compatibility": "converged_from_v1",
                    "reinterprets_predecessor": false,
                    "downgrade_to_predecessor": "refused",
                }),
                true,
            ),
            Ok(None) => (
                json!({
                    "from_schema_version": Value::Null,
                    "from_run_ref": Value::Null,
                    "from_content_hash": Value::Null,
                    "predecessor_reached_execution": false,
                    "compatibility": "initial",
                    "reinterprets_predecessor": false,
                    "downgrade_to_predecessor": "refused",
                }),
                false,
            ),
            Err(response) => return response,
        };

    let recorded_at_ms = now_ms();
    let mut record = json!({
        "schema_version": RUN.schema_version,
        "transformation_run_id": run_id,
        "owner_ref": caller.owner_ref,
        "tenant_ref": tenant_ref,
        "output_tenant_ref": output_tenant_ref,
        "identity_basis": {
            "derived_from": "owner_ref_and_idempotency_key",
            "idempotency_key_hash": sha256_of(caller.idempotency_key.as_bytes()),
            "refused_basis": "wall_clock_nanoseconds",
        },
        "data_recipe_revision_ref": recipe.revision_ref,
        "data_recipe_content_hash": recipe.content_hash,
        "data_recipe_admitted_head_before": recipe.family_head,
        "recipe_committed_semantic_component_set_snapshot_ref": recipe.snapshot_ref,
        "recipe_committed_semantic_component_set_hash": recipe.set_hash,
        "resolved_semantic_component_set_snapshot_ref": recipe.snapshot_ref,
        "resolved_semantic_component_set_hash": resolved_set_hash,
        "recipe_committed_connector_mapping_revision_refs": recipe.connector_mapping_revision_refs,
        "resolved_connector_mapping_revision_refs": resolved_mappings,
        "ontology_revision_refs": recipe.ontology_revision_refs,
        "policy_bound_data_view_refs": recipe.policy_bound_data_view_refs,
        "institutional_learning_boundary_profile_ref": boundary_ref,
        "effective_learning_policy_hash": learning_policy_hash,
        "learning_source_rights_claim_refs": learning_source_rights,
        "authority_grant_refs": authority_grant_refs,
        "input_refs": input_refs,
        "output_intent": output_intent,
        "derivative_policy_ref": derivative_policy_ref,
        "impact_graph_ref": impact_graph_ref,
        "receipt_refs": receipt_refs,
        "execution_status": execution_status,
        "admitted_at": admitted_stamp(recorded_at_ms),
        "migration": migration,
        "constants": {
            "lifecycle_id": "transformation_run_execution_lifecycle.v2",
            "nonclaim_authority_token": "authority",
            "nonclaim_semantic_correctness_token": "semantic_correctness",
        },
        "authority_nonclaim": "transformation_run_grants_no_authority",
        "truth_nonclaim": "transformation_run_attests_boundary_facts_not_universal_correctness",
        "does_not_assert": [
            "authority",
            "semantic_correctness",
            "training_consent",
            "perpetual_permission",
            "provider_deletion",
            "model_unlearning",
        ],
    });
    for (key, value) in output_values {
        record[key] = value;
    }
    finish_admission(
        &RUN,
        &st,
        &caller,
        &scope,
        &resource,
        "transformation_run",
        record,
        expected_head,
        recorded_at_ms,
        &body,
        converged,
    )
}

#[derive(serde::Deserialize)]
pub(crate) struct RunQuery {
    family: Option<String>,
    transformation_run_id: Option<String>,
}

/// GET /v1/hypervisor/transformation-runs — the caller's recipe families that have runs, one
/// family's runs, or one exact run.
pub(crate) async fn handle_transformation_run_query(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Query(query): Query<RunQuery>,
) -> Reply {
    let identity = match resolve_request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(error) => return scope_refusal_reply(error),
    };
    let Some(family) = query.family.as_deref().filter(|value| family_token(value)) else {
        return match authorized_request_resource_refs(&st.data_dir, &identity, RUN.resource_kind) {
            Ok(refs) => (
                StatusCode::OK,
                Json(json!({ "ok": true, "recipe_families": refs.into_iter().collect::<Vec<_>>() })),
            ),
            Err(error) => scope_refusal_reply(error),
        };
    };
    let resource = format!("data-recipe://{family}");
    let stream = match authorized_stream(&RUN, &st.data_dir, &identity, &resource) {
        Ok(stream) => stream,
        Err(response) => return response,
    };
    let index_state = projection_cache_state(&format!("run:{resource}"), &stream);
    if let Some(run_id) = query.transformation_run_id.as_deref() {
        let Some(entry) = stream
            .iter()
            .find(|entry| entry.record.get("transformation_run_id") == Some(&json!(run_id)))
        else {
            return bad(
                StatusCode::NOT_FOUND,
                "transformation_run_absent",
                "this recipe family has no such run — an absent run is a typed absence, never an empty success",
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
            "data_recipe_family": resource,
            "transformation_runs": stream.iter().map(|entry| entry.record.clone()).collect::<Vec<_>>(),
            "admissions": stream.iter().map(|entry| entry.admission.clone()).collect::<Vec<_>>(),
            "head": stream.last().map(|last| last.head.clone()),
            "index_state": index_state,
        })),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(relative: &str) -> Value {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../docs/architecture/_meta/schemas/fixtures")
            .join(relative);
        serde_json::from_str(&std::fs::read_to_string(&path).expect("fixture is readable"))
            .expect("fixture is json")
    }

    /// THE PRODUCER'S COMMITMENT IS CANON'S COMMITMENT, not a second one that happens to agree.
    ///
    /// Each registered positive fixture carries a `content_hash` computed from its registered
    /// invariant profile. Recomputing it with THIS module's material list and domain separator and
    /// getting the same digest is what proves the runtime and the contract commit the same bytes.
    /// If a field is ever dropped from a `material_fields` list here, these three go red.
    #[test]
    fn content_commitments_agree_with_the_registered_corpus() {
        for (spec, path) in [
            (&RECIPE, "data-recipe-v2/positive-genesis-authored-at-v2.json"),
            (&CMAP, "connector-mapping-v2/positive-successor-converged-from-v1.json"),
            (
                &RUN,
                "transformation-run-v2/positive-completed-run-freezes-the-recipe-tuple.json",
            ),
        ] {
            let record = fixture(path);
            let expected = record
                .get("content_hash")
                .and_then(Value::as_str)
                .expect("fixture carries a content hash");
            assert_eq!(
                spec.content_hash(&record).expect("commitment computes"),
                expected,
                "{} commitment disagrees with the registered corpus at {path}",
                spec.code_prefix
            );
        }
    }

    /// The registered corpus is also what this module validates against, so a record this producer
    /// would emit and a record canon would accept are the same set.
    #[test]
    fn registered_positives_validate_against_their_contracts() {
        for (spec, path) in [
            (&RECIPE, "data-recipe-v2/positive-successor-converged-from-v1.json"),
            (&CMAP, "connector-mapping-v2/positive-genesis-authored-at-v2.json"),
            (
                &RUN,
                "transformation-run-v2/positive-rejected-run-converged-from-v1.json",
            ),
        ] {
            let record = fixture(path);
            validate_architecture_contract(spec.contract_id, &record)
                .unwrap_or_else(|reason| panic!("{path} is not registered-valid: {reason}"));
        }
    }

    /// A FAMILY HEAD IS UNREPRESENTABLE WHEREVER A REVISION IS REQUIRED, and a spelling that would
    /// have to be normalised before it could be compared is refused rather than repaired.
    #[test]
    fn revision_refs_are_exact_or_refused() {
        assert_eq!(
            parse_revision_ref("data-recipe://", "data-recipe://acme.intake/revision/7"),
            Some(("acme.intake".to_owned(), 7))
        );
        for refused in [
            "data-recipe://acme.intake",            // family head
            "data-recipe://acme.intake/revision/0", // zero
            "data-recipe://acme.intake/revision/07", // zero-padded: one revision, one spelling
            "data-recipe://acme.intake/revision/7/", // trailing segment
            "data-recipe://acme.intake/revision/7?x=1", // query tail
            "data-recipe://acme.intake/revision/-1",
            "data-recipe://ACME.intake/revision/7", // non-canonical family token
            "recipe://acme.intake/revision/7",      // the refused generic scheme
        ] {
            assert!(
                parse_revision_ref("data-recipe://", refused).is_none(),
                "'{refused}' must not parse as an exact revision"
            );
        }
    }

    /// The tenancy a run's outputs are compared against is DERIVED, so `output_tenant_ref` remains
    /// a field that can disagree and be caught rather than one the caller supplies.
    #[test]
    fn tenancy_is_derived_from_the_authorized_owner() {
        assert_eq!(contract_tenant_ref("org://local"), "tenant://org.local");
        assert_eq!(
            contract_tenant_ref("project://acme/intake"),
            "tenant://project.acme.intake"
        );
        assert_ne!(
            contract_tenant_ref("org://local"),
            contract_tenant_ref("org://other")
        );
    }

    /// The snapshot hash is a function of the members, so dropping one, adding one or reordering
    /// them all change it — which is what makes the committed-versus-resolved comparison mean
    /// something.
    #[test]
    fn the_semantic_snapshot_commits_its_exact_members() {
        let base = ["ontology://a/b/revision/1".to_owned(), "mapping://m/revision/2".to_owned()];
        let (hash, refs, count) = semantic_snapshot("artifact://s/1", &base).expect("snapshot");
        assert_eq!(count, 2);
        assert_eq!(refs.len(), 2);
        let (dropped, _, _) = semantic_snapshot("artifact://s/1", &base[..1]).expect("snapshot");
        assert_ne!(hash, dropped);
        let reordered = [base[1].clone(), base[0].clone()];
        let (swapped, _, _) = semantic_snapshot("artifact://s/1", &reordered).expect("snapshot");
        assert_ne!(hash, swapped);
        let (other_ref, _, _) = semantic_snapshot("artifact://s/2", &base).expect("snapshot");
        assert_ne!(hash, other_ref);
        assert!(semantic_snapshot("artifact://s/1", &[base[0].clone(), base[0].clone()]).is_err());
    }

    /// THREE FAMILIES, THREE LIFECYCLE VOCABULARIES, NO SHARED MEMBER. A projection that flattened
    /// a definition's inventory state and an execution's state into one column would have to invent
    /// a member that exists in neither list.
    #[test]
    fn the_three_lifecycle_vocabularies_are_disjoint() {
        for status in REGISTRY_STATUSES {
            assert!(!EXECUTION_STATUSES.contains(status));
            assert!(!RUN_V1_LIFECYCLE_WORDS.contains(status));
        }
        for status in EXECUTION_STATUSES {
            assert!(!RUN_V1_LIFECYCLE_WORDS.contains(status));
        }
    }

    /// The predecessor commitment is over the WHOLE stored record, so an edit anywhere in it — not
    /// merely in an enumerated subset — changes what a convergence claims to have seen.
    #[test]
    fn the_predecessor_commitment_covers_the_whole_record() {
        let record = fixture("data-recipe-v1/positive-stored-v1-draft.json");
        let first = predecessor_record_hash(&record).expect("hash");
        let mut edited = record.clone();
        edited["name"] = json!("something else");
        assert_ne!(first, predecessor_record_hash(&edited).expect("hash"));
        // Key ORDER is not content: canonicalization is what makes the commitment portable.
        let reserialized: Value =
            serde_json::from_str(&serde_json::to_string(&record).expect("json")).expect("json");
        assert_eq!(first, predecessor_record_hash(&reserialized).expect("hash"));
    }
}
