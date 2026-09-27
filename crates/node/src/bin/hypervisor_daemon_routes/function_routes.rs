//! Functions (ADR 0056 Amendment 1, plane 3) — `FunctionRevision` and `FunctionTestRun`
//! (docs/architecture/foundations/objects/semantic-plane.md §FunctionRevision, §FunctionTestRun).
//!
//! A function is typed code over the semantic world. Each revision is immutable and content-addressed:
//! a change is a successor revision with a greater semantic version, never an edit. Every write is
//! identity-first and owner-scoped through the shared mutation foundation, and one function family is
//! ONE Agentgres chain: creating a revision, releasing it and deprecating it each compare-and-swap the
//! family's admitted head, so two concurrent revisions cannot take the same ordinal.
//!
//! Releasing a revision compiles it into an exact `RuntimeToolContract` revision
//! (`tool://function/fn_…/revision/<n>`) and admits it into the daemon's runtime tool-contract registry
//! — the one registry agents, automations and ontology action contracts already bind by exact revision
//! and hash. It is never resolvable by name. Deprecating revokes it; boot rehydrates the registry from
//! the released revisions, and a revision whose record no longer compiles to the hash it was released
//! under is skipped, never re-admitted as something else.
//!
//! A test run executes one exact revision through the governed exec primitive in an environment the
//! caller owns. The source and inputs travel IN the command as quoted heredocs — never encoded — so
//! the exec guardrail's deny-list reads exactly what will run. Nothing here grants anything.

use std::sync::Arc;

use axum::extract::{Path as AxumPath, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use ioi_services::agentic::runtime::runtime_tool_contract_registry::RuntimeToolContractRegistry;
use ioi_services::agentic::runtime::tools::contracts::{
    runtime_tool_contract_canonical_hash_material, AdmittedRuntimeToolContract,
    RuntimeToolEgressPolicy, RuntimeToolTimeout, CANONICAL_RUNTIME_TOOL_CONTRACT_SCHEMA_VERSION,
};

use super::mutation_event_foundation::{
    admit_owner_scoped_write, mutation_refusal_reply, prior_admission_for_key, replay_stable_id,
    require_write_caller, scope_refusal_reply, stream_tail, MutationCommit, MutationRefusal,
    WriteCaller,
};
use super::{persist_record, read_record_dir, DaemonState};

const NAMESPACE: &str = "hypervisor-functions";
/// The chain resource kind: one stream per function family.
const KIND_FUNCTION: &str = "functions";
const KIND_REVISION: &str = "function-revisions";
const KIND_TEST_RUN: &str = "function-test-runs";
const REVISION_SCHEMA: &str = "ioi.function-revision.v1";
const TEST_RUN_SCHEMA: &str = "ioi.function-test-run.v1";
const REVISION_CONTRACT: &str = "schema://ioi/foundations/objects/function-revision/v1";
const TEST_RUN_CONTRACT: &str = "schema://ioi/foundations/objects/function-test-run/v1";
const RUNTIMES: &[&str] = &["python3", "node", "bash"];
const SCALARS: &[&str] = &[
    "string",
    "integer",
    "double",
    "boolean",
    "date",
    "timestamp",
];
const MAX_SOURCE_BYTES: usize = 49_152;
const MAX_INPUT_BYTES: usize = 16_384;
const MAX_OUTPUT_RETAINED: usize = 16_384;
const MAX_INPUTS: usize = 32;
const DEFAULT_TIMEOUT_MS: i64 = 30_000;
/// The fields `content_hash` commits to (the registered contract's JCS material).
const CONTENT_FIELDS: [&str; 12] = [
    "function_ref",
    "revision_ref",
    "predecessor_revision_ref",
    "ordinal",
    "version",
    "display_name",
    "api_name",
    "documentation",
    "inputs",
    "output",
    "implementation",
    "timeout_ms",
];

type Reply = (StatusCode, Json<Value>);

fn bad(status: StatusCode, code: &str, message: impl Into<String>) -> Reply {
    (
        status,
        Json(json!({ "ok": false, "error": { "code": code, "message": message.into() } })),
    )
}

fn text<'a>(body: &'a Value, key: &str) -> &'a str {
    body.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("")
}

fn sha256_ref(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn validate(contract: &str, what: &str, record: &Value) -> Result<(), Reply> {
    ioi_types::app::generated::architecture_contracts::validate_architecture_contract(
        contract, record,
    )
    .map_err(|error| {
        bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            "function_contract_invalid",
            format!("the {what} would not satisfy its registered contract: {error}"),
        )
    })
}

fn persist(kind: &str, data_dir: &str, id: &str, record: &Value) -> Result<(), Reply> {
    persist_record(data_dir, kind, id, record).map_err(|_| {
        bad(
            StatusCode::INTERNAL_SERVER_ERROR,
            "function_persistence_failed",
            "the write is admitted but its projection could not be written; replay to reconcile",
        )
    })
}

fn load_record(data_dir: &str, kind: &str, id: &str) -> Option<Value> {
    let safe = id.replace(
        |c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '_',
        "_",
    );
    serde_json::from_slice(
        &std::fs::read(
            std::path::Path::new(data_dir)
                .join(kind)
                .join(format!("{safe}.json")),
        )
        .ok()?,
    )
    .ok()
}

fn is_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    value.len() <= 64
        && chars.next().is_some_and(|c| c.is_ascii_lowercase())
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// `fn_<16 hex>` from a path segment or a `function://` ref.
fn family_id(raw: &str) -> Option<String> {
    let id = raw.trim().trim_start_matches("function://");
    let hex = id.strip_prefix("fn_")?;
    (hex.len() == 16 && hex.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')))
        .then(|| id.to_string())
}

fn parse_version(value: &str) -> Option<(u64, u64, u64)> {
    let mut parts = value.split('.');
    let mut next = || -> Option<u64> {
        let part = parts.next()?;
        (!part.is_empty()
            && part.len() <= 6
            && part.chars().all(|c| c.is_ascii_digit())
            && (part == "0" || !part.starts_with('0')))
        .then(|| part.parse().ok())?
    };
    let version = (next()?, next()?, next()?);
    parts.next().is_none().then_some(version)
}

// ---------------------------------------------------------------------------------------------
// The type algebra: scalars and lists of scalars.
// ---------------------------------------------------------------------------------------------

/// A declared data type, normalized to `{type, element_type}`.
fn data_type(value: &Value) -> Result<Value, String> {
    let kind = text(value, "type");
    let element = value.get("element_type").and_then(Value::as_str);
    if kind == "list" {
        match element {
            Some(e) if SCALARS.contains(&e) => Ok(json!({ "type": "list", "element_type": e })),
            _ => Err(format!("a list names its element type, one of {SCALARS:?}")),
        }
    } else if SCALARS.contains(&kind) {
        if element.is_some() {
            return Err(format!("a {kind} has no element type"));
        }
        Ok(json!({ "type": kind, "element_type": Value::Null }))
    } else {
        Err(format!(
            "type must be one of {SCALARS:?} or list (ontology-object types are not in v1)"
        ))
    }
}

fn describe(data_type: &Value) -> String {
    match text(data_type, "type") {
        "list" => format!("list<{}>", text(data_type, "element_type")),
        other => other.to_string(),
    }
}

/// "an integer", "a list<string>".
fn with_article(data_type: &Value) -> String {
    let named = describe(data_type);
    let article = if named.starts_with(['a', 'e', 'i', 'o', 'u']) {
        "an"
    } else {
        "a"
    };
    format!("{article} {named}")
}

fn is_date(value: &str) -> bool {
    let b = value.as_bytes();
    if b.len() != 10 || b[4] != b'-' || b[7] != b'-' {
        return false;
    }
    let num = |s: &str| s.parse::<u32>().ok();
    match (num(&value[0..4]), num(&value[5..7]), num(&value[8..10])) {
        (Some(_), Some(m), Some(d)) => (1..=12).contains(&m) && (1..=31).contains(&d),
        _ => false,
    }
}

fn scalar_matches(kind: &str, value: &Value) -> bool {
    match kind {
        "string" => value.is_string(),
        "integer" => value.is_i64() || value.is_u64(),
        "double" => value.is_number(),
        "boolean" => value.is_boolean(),
        "date" => value.as_str().is_some_and(is_date),
        "timestamp" => value.as_str().is_some_and(|s| {
            time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339).is_ok()
        }),
        _ => false,
    }
}

fn value_matches(data_type: &Value, value: &Value) -> bool {
    match text(data_type, "type") {
        "list" => value.as_array().is_some_and(|items| {
            items
                .iter()
                .all(|item| scalar_matches(text(data_type, "element_type"), item))
        }),
        kind => scalar_matches(kind, value),
    }
}

/// The JSON Schema a declared type compiles to (the tool contract's input and output schemas).
fn json_schema_of(data_type: &Value) -> Value {
    let scalar = |kind: &str| match kind {
        "integer" => json!({ "type": "integer" }),
        "double" => json!({ "type": "number" }),
        "boolean" => json!({ "type": "boolean" }),
        "date" => json!({ "type": "string", "format": "date" }),
        "timestamp" => json!({ "type": "string", "format": "date-time" }),
        _ => json!({ "type": "string" }),
    };
    match text(data_type, "type") {
        "list" => json!({ "type": "array", "items": scalar(text(data_type, "element_type")) }),
        kind => scalar(kind),
    }
}

/// Supplied input values checked against the declared inputs; `Err` names what is wrong.
pub(crate) fn checked_inputs(declared: &[Value], supplied: &Value) -> Result<Value, String> {
    let supplied = match supplied {
        Value::Null => Map::new(),
        Value::Object(map) => map.clone(),
        _ => return Err("inputs is an object keyed by input name".into()),
    };
    if supplied.len() > MAX_INPUTS
        || serde_json::to_vec(&supplied).map_or(usize::MAX, |b| b.len()) > MAX_INPUT_BYTES
    {
        return Err(format!(
            "inputs are bounded at {MAX_INPUTS} names and {MAX_INPUT_BYTES} bytes"
        ));
    }
    for name in supplied.keys() {
        if !declared.iter().any(|input| text(input, "name") == name) {
            return Err(format!("this revision declares no input named {name}"));
        }
    }
    let mut checked = Map::new();
    for input in declared {
        let name = text(input, "name");
        match supplied.get(name) {
            None | Some(Value::Null) => {
                if input["required"].as_bool().unwrap_or(false) {
                    return Err(format!("{name} is required"));
                }
            }
            Some(value) => {
                if !value_matches(&input["data_type"], value) {
                    return Err(format!(
                        "{name} must be {}",
                        with_article(&input["data_type"])
                    ));
                }
                checked.insert(name.to_string(), value.clone());
            }
        }
    }
    Ok(Value::Object(checked))
}

// ---------------------------------------------------------------------------------------------
// Declarations and records.
// ---------------------------------------------------------------------------------------------

struct Declared {
    display_name: String,
    api_name: String,
    documentation: String,
    version: String,
    inputs: Vec<Value>,
    output: Value,
    runtime: String,
    source: String,
    timeout_ms: i64,
}

fn declared(body: &Value) -> Result<Declared, Reply> {
    let refuse = |code: &str, message: String| Err(bad(StatusCode::BAD_REQUEST, code, message));
    let display_name = text(body, "display_name").to_string();
    if display_name.is_empty() || display_name.chars().count() > 160 {
        return refuse(
            "function_display_name_required",
            "display_name is required and is 1..160 characters".into(),
        );
    }
    let api_name = text(body, "api_name").to_string();
    if !is_identifier(&api_name) {
        return refuse(
            "function_api_name_invalid",
            "api_name starts with a lowercase letter and uses letters, digits and _ (at most 64)"
                .into(),
        );
    }
    let documentation = body
        .get("documentation")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    if documentation.chars().count() > 4000 {
        return refuse(
            "function_documentation_too_long",
            "documentation is at most 4000 characters".into(),
        );
    }
    let version = text(body, "version").to_string();
    if parse_version(&version).is_none() {
        return refuse(
            "function_version_invalid",
            "version is MAJOR.MINOR.PATCH (for example 1.0.0)".into(),
        );
    }
    let raw_inputs = match body.get("inputs") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(items)) => items.clone(),
        Some(_) => {
            return refuse(
                "function_inputs_invalid",
                "inputs is a list of {name, description, data_type, required}".into(),
            )
        }
    };
    if raw_inputs.len() > MAX_INPUTS {
        return refuse(
            "function_inputs_invalid",
            format!("a function declares at most {MAX_INPUTS} inputs"),
        );
    }
    let mut inputs = Vec::with_capacity(raw_inputs.len());
    for input in &raw_inputs {
        let name = text(input, "name");
        if !is_identifier(name) {
            return refuse(
                "function_input_name_invalid",
                format!("input name '{name}' starts with a lowercase letter and uses letters, digits and _"),
            );
        }
        if inputs.iter().any(|seen: &Value| text(seen, "name") == name) {
            return refuse(
                "function_input_name_duplicate",
                format!("two inputs are named {name}"),
            );
        }
        let description = input
            .get("description")
            .and_then(Value::as_str)
            .unwrap_or("");
        if description.chars().count() > 1000 {
            return refuse(
                "function_input_invalid",
                format!("{name}: a description is at most 1000 characters"),
            );
        }
        let data_type = match data_type(&input["data_type"]) {
            Ok(data_type) => data_type,
            Err(why) => return refuse("function_input_type_invalid", format!("{name}: {why}")),
        };
        inputs.push(json!({
            "name": name,
            "description": description,
            "data_type": data_type,
            "required": input.get("required").and_then(Value::as_bool).unwrap_or(true),
        }));
    }
    let output_type = match data_type(&body["output"]["data_type"]) {
        Ok(data_type) => data_type,
        Err(why) => return refuse("function_output_type_invalid", format!("output: {why}")),
    };
    let output_description = body["output"]
        .get("description")
        .and_then(Value::as_str)
        .unwrap_or("");
    if output_description.chars().count() > 1000 {
        return refuse(
            "function_output_invalid",
            "output: a description is at most 1000 characters".into(),
        );
    }
    let runtime = text(&body["implementation"], "runtime").to_string();
    if !RUNTIMES.contains(&runtime.as_str()) {
        return refuse(
            "function_runtime_invalid",
            format!("implementation.runtime must be one of {RUNTIMES:?}"),
        );
    }
    let source = body["implementation"]
        .get("source")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    if source.trim().is_empty() || source.len() > MAX_SOURCE_BYTES || source.contains('\0') {
        return refuse(
            "function_source_invalid",
            format!("implementation.source is 1..{MAX_SOURCE_BYTES} bytes of text"),
        );
    }
    let timeout_ms = body
        .get("timeout_ms")
        .and_then(Value::as_i64)
        .unwrap_or(DEFAULT_TIMEOUT_MS);
    if !(1_000..=60_000).contains(&timeout_ms) {
        return refuse(
            "function_timeout_invalid",
            "timeout_ms is 1000..60000".into(),
        );
    }
    Ok(Declared {
        display_name,
        api_name,
        documentation,
        version,
        inputs,
        output: json!({ "data_type": output_type, "description": output_description }),
        runtime,
        source,
        timeout_ms,
    })
}

/// The JCS commitment over the revision's own fields.
pub(crate) fn revision_content_hash(record: &Value) -> String {
    let material: Map<String, Value> = CONTENT_FIELDS
        .iter()
        .map(|field| (field.to_string(), record[*field].clone()))
        .collect();
    let bytes = serde_jcs::to_vec(&Value::Object(material)).unwrap_or_default();
    sha256_ref(&bytes)
}

fn new_revision(
    decl: &Declared,
    fn_id: &str,
    ordinal: u64,
    predecessor: Option<&str>,
    caller: &WriteCaller,
) -> Value {
    let function_ref = format!("function://{fn_id}");
    let now = super::iso_now();
    let mut record = json!({
        "schema_version": REVISION_SCHEMA,
        "function_ref": function_ref,
        "revision_ref": format!("{function_ref}/revision/{ordinal}"),
        "predecessor_revision_ref": predecessor,
        "ordinal": ordinal,
        "version": decl.version,
        "display_name": decl.display_name,
        "api_name": decl.api_name,
        "documentation": decl.documentation,
        "inputs": decl.inputs,
        "output": decl.output,
        "implementation": {
            "runtime": decl.runtime,
            "source": decl.source,
            "source_hash": sha256_ref(decl.source.as_bytes()),
        },
        "timeout_ms": decl.timeout_ms,
        "content_hash": Value::Null,
        "status": "draft",
        "runtime_tool_contract": Value::Null,
        "deprecation": Value::Null,
        "owner_ref": caller.owner_ref,
        "created_by_principal_ref": caller.identity.principal_ref,
        "created_at": now,
        "updated_at": now,
        "released_at": Value::Null,
        "admitted_head": Value::Null,
    });
    record["content_hash"] = json!(revision_content_hash(&record));
    record
}

fn record_id(fn_id: &str, ordinal: u64) -> String {
    format!("{fn_id}--r{ordinal}")
}

/// Every revision of one family, oldest first.
fn revisions_of(data_dir: &str, fn_id: &str) -> Vec<Value> {
    let function_ref = format!("function://{fn_id}");
    let mut revisions: Vec<Value> = read_record_dir(data_dir, KIND_REVISION)
        .into_iter()
        .filter(|r| text(r, "function_ref") == function_ref)
        .collect();
    revisions.sort_by_key(|r| r["ordinal"].as_u64().unwrap_or(0));
    revisions
}

fn family_head(data_dir: &str, function_ref: &str) -> Result<Option<String>, Reply> {
    super::substrate_store::read_event_stream_operation(
        data_dir,
        NAMESPACE,
        &stream_tail(KIND_FUNCTION, function_ref),
    )
    .map(|projection| projection.map(|p| p.head))
    .map_err(|error| mutation_refusal_reply(MutationRefusal::Admission(error)))
}

/// A key this caller already admitted on the family stream: the revision it touched, if the
/// operation was the same kind; a key reused for a different operation is refused.
fn replayed_revision(
    data_dir: &str,
    caller: &WriteCaller,
    function_ref: &str,
    op_kind: &str,
) -> Result<Option<Value>, Reply> {
    let Some(prior) =
        prior_admission_for_key(data_dir, caller, NAMESPACE, KIND_FUNCTION, function_ref)?
    else {
        return Ok(None);
    };
    if prior.operation.op_kind != op_kind {
        return Err(bad(
            StatusCode::CONFLICT,
            "function_idempotency_key_reused",
            format!(
                "this idempotency key already admitted {} on this function",
                prior.operation.op_kind
            ),
        ));
    }
    let revision_ref = prior.operation.payload["revision_ref"]
        .as_str()
        .unwrap_or("");
    let ordinal = revision_ref
        .rsplit('/')
        .next()
        .and_then(|n| n.parse::<u64>().ok())
        .unwrap_or(0);
    let fn_id = family_id(function_ref).unwrap_or_default();
    Ok(load_record(
        data_dir,
        KIND_REVISION,
        &record_id(&fn_id, ordinal),
    ))
}

fn owned_family(
    st: &DaemonState,
    caller: &WriteCaller,
    raw_id: &str,
) -> Result<(String, Vec<Value>), Reply> {
    let not_found = || {
        bad(
            StatusCode::NOT_FOUND,
            "function_not_found",
            "no function exists at this id",
        )
    };
    let fn_id = family_id(raw_id).ok_or_else(not_found)?;
    let revisions = revisions_of(&st.data_dir, &fn_id);
    let Some(first) = revisions.first() else {
        return Err(not_found());
    };
    if first["owner_ref"].as_str() != Some(caller.owner_ref.as_str()) {
        return Err(scope_refusal_reply(
            super::substrate_store::RequestScopeRefusal::ResourceOwnerMismatch,
        ));
    }
    Ok((fn_id, revisions))
}

fn created(commit: &MutationCommit, record: Value, key: &str) -> Reply {
    (
        StatusCode::CREATED,
        Json(
            json!({ "ok": true, "replayed": commit.replayed, key: record, "receipt_ref": commit.receipt_ref }),
        ),
    )
}

fn replay(record: Value) -> Reply {
    (
        StatusCode::OK,
        Json(json!({ "ok": true, "replayed": true, "revision": record })),
    )
}

/// POST /v1/hypervisor/functions — declare a function: its first revision, as a draft.
pub(crate) async fn handle_function_create(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Reply {
    let caller = match require_write_caller(&st.data_dir, &headers, &body) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    let decl = match declared(&body) {
        Ok(decl) => decl,
        Err(response) => return response,
    };
    let fn_id = replay_stable_id("fn", &caller.owner_ref, &caller.idempotency_key);
    let function_ref = format!("function://{fn_id}");
    // An api_name names one function per owner.
    if read_record_dir(&st.data_dir, KIND_REVISION)
        .iter()
        .any(|r| {
            text(r, "owner_ref") == caller.owner_ref
                && text(r, "api_name") == decl.api_name
                && text(r, "function_ref") != function_ref
        })
    {
        return bad(
            StatusCode::CONFLICT,
            "function_api_name_taken",
            format!(
                "another function in this owner is already named {}",
                decl.api_name
            ),
        );
    }
    let mut record = new_revision(&decl, &fn_id, 1, None, &caller);
    if let Err(response) = validate(REVISION_CONTRACT, "function revision", &record) {
        return response;
    }
    let commit = match admit_owner_scoped_write(
        &st.data_dir,
        &caller,
        NAMESPACE,
        KIND_FUNCTION,
        &function_ref,
        "function.revision.create",
        None,
        &json!({ "function_ref": function_ref, "revision_ref": record["revision_ref"], "ordinal": 1, "version": record["version"], "content_hash": record["content_hash"] }),
    ) {
        Ok(commit) => commit,
        Err(response) => return response,
    };
    if commit.replayed {
        if let Some(existing) = load_record(&st.data_dir, KIND_REVISION, &record_id(&fn_id, 1)) {
            return replay(existing);
        }
    }
    record["admitted_head"] = json!(commit.projection.head);
    if let Err(response) = persist(KIND_REVISION, &st.data_dir, &record_id(&fn_id, 1), &record) {
        return response;
    }
    created(&commit, record, "revision")
}

/// POST /v1/hypervisor/functions/:id/revisions — a successor revision, as a draft. Its version is
/// strictly greater than every earlier revision's.
pub(crate) async fn handle_function_revise(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> Reply {
    let caller = match require_write_caller(&st.data_dir, &headers, &body) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    let (fn_id, revisions) = match owned_family(&st, &caller, &id) {
        Ok(found) => found,
        Err(response) => return response,
    };
    let function_ref = format!("function://{fn_id}");
    match replayed_revision(
        &st.data_dir,
        &caller,
        &function_ref,
        "function.revision.create",
    ) {
        Ok(Some(existing)) => return replay(existing),
        Ok(None) => {}
        Err(response) => return response,
    }
    let latest = revisions.last().cloned().unwrap_or(Value::Null);
    let mut body = body;
    if text(&body, "api_name").is_empty() {
        body["api_name"] = latest["api_name"].clone();
    }
    let decl = match declared(&body) {
        Ok(decl) => decl,
        Err(response) => return response,
    };
    if decl.api_name != text(&latest, "api_name") {
        return bad(
            StatusCode::BAD_REQUEST,
            "function_api_name_immutable",
            "a function keeps its api_name across revisions; declare a new function instead",
        );
    }
    let proposed = parse_version(&decl.version);
    if let Some(higher) = revisions
        .iter()
        .find(|r| parse_version(text(r, "version")) >= proposed)
    {
        return bad(
            StatusCode::CONFLICT,
            "function_version_not_increasing",
            format!(
                "version {} is not greater than revision {}'s {}",
                decl.version,
                higher["ordinal"],
                text(higher, "version")
            ),
        );
    }
    let expected_head = match family_head(&st.data_dir, &function_ref) {
        Ok(Some(head)) => head,
        Ok(None) => {
            return bad(
                StatusCode::CONFLICT,
                "function_expected_head_required",
                "this function has no admitted head; it cannot take a successor without one",
            )
        }
        Err(response) => return response,
    };
    let ordinal = latest["ordinal"].as_u64().unwrap_or(0) + 1;
    let mut record = new_revision(
        &decl,
        &fn_id,
        ordinal,
        latest["revision_ref"].as_str(),
        &caller,
    );
    if let Err(response) = validate(REVISION_CONTRACT, "function revision", &record) {
        return response;
    }
    let commit = match admit_owner_scoped_write(
        &st.data_dir,
        &caller,
        NAMESPACE,
        KIND_FUNCTION,
        &function_ref,
        "function.revision.create",
        Some(&expected_head),
        &json!({ "function_ref": function_ref, "revision_ref": record["revision_ref"], "ordinal": ordinal, "version": record["version"], "content_hash": record["content_hash"] }),
    ) {
        Ok(commit) => commit,
        Err(response) => return response,
    };
    record["admitted_head"] = json!(commit.projection.head);
    if let Err(response) = persist(
        KIND_REVISION,
        &st.data_dir,
        &record_id(&fn_id, ordinal),
        &record,
    ) {
        return response;
    }
    created(&commit, record, "revision")
}

// ---------------------------------------------------------------------------------------------
// Release: compile into the runtime tool-contract registry.
// ---------------------------------------------------------------------------------------------

/// The exact tool contract a released revision compiles to. Deterministic from the record and its
/// predecessor tool revision, so boot can rebuild it and prove it is the same bytes.
pub(crate) fn compile_tool_contract(
    revision: &Value,
    predecessor_tool_revision_ref: Option<String>,
) -> Result<AdmittedRuntimeToolContract, String> {
    let fn_id = family_id(text(revision, "function_ref"))
        .ok_or_else(|| "the revision names no function".to_string())?;
    let ordinal = revision["ordinal"]
        .as_u64()
        .ok_or_else(|| "the revision has no ordinal".to_string())?;
    let tool_id = format!("tool://function/{fn_id}");
    let mut properties = Map::new();
    let mut required = Vec::new();
    for input in revision["inputs"].as_array().into_iter().flatten() {
        let name = text(input, "name").to_string();
        let mut schema = json_schema_of(&input["data_type"]);
        if !text(input, "description").is_empty() {
            schema["description"] = json!(text(input, "description"));
        }
        if input["required"].as_bool().unwrap_or(false) {
            required.push(json!(name));
        }
        properties.insert(name, schema);
    }
    let timeout_ms = revision["timeout_ms"].as_u64().unwrap_or(30_000);
    let mut contract = AdmittedRuntimeToolContract {
        schema_version: CANONICAL_RUNTIME_TOOL_CONTRACT_SCHEMA_VERSION.to_string(),
        tool_id: tool_id.clone(),
        revision_ref: format!("{tool_id}/revision/{ordinal}"),
        predecessor_revision_ref: predecessor_tool_revision_ref,
        content_hash: String::new(),
        namespace: "function".to_string(),
        display_name: text(revision, "display_name").to_string(),
        version: text(revision, "version").to_string(),
        input_schema: json!({ "type": "object", "additionalProperties": false, "properties": properties, "required": required }),
        output_schema: json_schema_of(&revision["output"]["data_type"]),
        risk_class: "system".to_string(),
        effect_class: "external_effect".to_string(),
        concurrency_class: "resource_scoped".to_string(),
        timeout: RuntimeToolTimeout {
            default_ms: timeout_ms,
            max_ms: timeout_ms,
        },
        primitive_capabilities_required: vec!["prim:sys.exec".to_string()],
        authority_scopes_required: Vec::new(),
        approval_required: false,
        evidence_required: vec![
            "policy_verdict".to_string(),
            "stdout_stderr_exit".to_string(),
            "function_revision_content_hash".to_string(),
        ],
        redaction_policy: "redact_body".to_string(),
        owner: text(revision, "owner_ref").to_string(),
        data_class_allowlist: vec!["internal".to_string()],
        egress_policy: RuntimeToolEgressPolicy {
            default: "allow_declared".to_string(),
            allowed_destination_patterns: vec!["environment://bound".to_string()],
        },
        registry_lifecycle_ref: Some(text(revision, "revision_ref").to_string()),
        registry_status: "released".to_string(),
    };
    contract.content_hash = sha256_ref(&runtime_tool_contract_canonical_hash_material(&contract)?);
    Ok(contract)
}

/// The family's last revision that reached the registry (released or deprecated): its ordinal and
/// its tool binding. Releases go in ordinal order, so this is the registry head for the tool.
fn last_registered(revisions: &[Value]) -> Option<(u64, String, String)> {
    revisions
        .iter()
        .filter(|r| r["runtime_tool_contract"].is_object())
        .max_by_key(|r| r["ordinal"].as_u64().unwrap_or(0))
        .map(|r| {
            (
                r["ordinal"].as_u64().unwrap_or(0),
                text(&r["runtime_tool_contract"], "revision_ref").to_string(),
                text(&r["runtime_tool_contract"], "content_hash").to_string(),
            )
        })
}

fn revision_at(revisions: &[Value], ordinal: &str) -> Result<Value, Reply> {
    let n = ordinal.parse::<u64>().unwrap_or(0);
    revisions
        .iter()
        .find(|r| r["ordinal"].as_u64() == Some(n))
        .cloned()
        .ok_or_else(|| {
            bad(
                StatusCode::NOT_FOUND,
                "function_revision_not_found",
                format!("this function has no revision {ordinal}"),
            )
        })
}

fn registry_refusal(error: impl std::fmt::Display) -> Reply {
    bad(
        StatusCode::CONFLICT,
        "function_tool_contract_refused",
        format!("the runtime tool-contract registry refused this revision: {error}"),
    )
}

/// POST /v1/hypervisor/functions/:id/revisions/:ordinal/release — release a draft: admit it on the
/// family chain and compile it into the runtime tool-contract registry.
pub(crate) async fn handle_function_release(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath((id, ordinal)): AxumPath<(String, String)>,
    Json(body): Json<Value>,
) -> Reply {
    let caller = match require_write_caller(&st.data_dir, &headers, &body) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    let (fn_id, revisions) = match owned_family(&st, &caller, &id) {
        Ok(found) => found,
        Err(response) => return response,
    };
    let revision = match revision_at(&revisions, &ordinal) {
        Ok(revision) => revision,
        Err(response) => return response,
    };
    match text(&revision, "status") {
        "released" => return replay(revision),
        "deprecated" => {
            return bad(
                StatusCode::CONFLICT,
                "function_revision_deprecated",
                "a deprecated revision cannot be released again; release a successor",
            )
        }
        _ => {}
    }
    let n = revision["ordinal"].as_u64().unwrap_or(0);
    let previous = last_registered(&revisions);
    if let Some((registered, _, _)) = &previous {
        if *registered > n {
            return bad(
                StatusCode::CONFLICT,
                "function_revision_superseded",
                format!("revision {registered} is already released; a superseded draft cannot be released"),
            );
        }
    }
    if revision_content_hash(&revision) != text(&revision, "content_hash") {
        return bad(
            StatusCode::CONFLICT,
            "function_revision_content_mismatch",
            "this revision's record no longer matches its content hash; it cannot be released",
        );
    }
    let contract = match compile_tool_contract(
        &revision,
        previous.as_ref().map(|(_, tool_ref, _)| tool_ref.clone()),
    ) {
        Ok(contract) => contract,
        Err(error) => return registry_refusal(error),
    };
    let expected_tool_hash = previous.as_ref().map(|(_, _, hash)| hash.clone());
    let function_ref = format!("function://{fn_id}");
    let expected_head = match family_head(&st.data_dir, &function_ref) {
        Ok(Some(head)) => head,
        Ok(None) => {
            return bad(
                StatusCode::CONFLICT,
                "function_expected_head_required",
                "this function has no admitted head",
            )
        }
        Err(response) => return response,
    };
    let Ok(mut registry) = st.runtime_tool_contract_registry.write() else {
        return bad(
            StatusCode::SERVICE_UNAVAILABLE,
            "function_tool_registry_unavailable",
            "the runtime tool-contract registry is unavailable",
        );
    };
    // Prove the registry will take it before the chain records the release.
    let mut probe = registry.clone();
    if let Err(error) = probe.admit(
        contract.clone(),
        "receipt://hypervisor-functions/release-probe".to_string(),
        expected_tool_hash.clone(),
    ) {
        return registry_refusal(error);
    }
    let commit = match admit_owner_scoped_write(
        &st.data_dir,
        &caller,
        NAMESPACE,
        KIND_FUNCTION,
        &function_ref,
        "function.revision.release",
        Some(&expected_head),
        &json!({ "function_ref": function_ref, "revision_ref": revision["revision_ref"], "content_hash": revision["content_hash"], "tool_revision_ref": contract.revision_ref, "tool_content_hash": contract.content_hash }),
    ) {
        Ok(commit) => commit,
        Err(response) => return response,
    };
    if let Err(error) = registry.admit(
        contract.clone(),
        commit.receipt_ref.clone(),
        expected_tool_hash,
    ) {
        return registry_refusal(error);
    }
    drop(registry);
    let mut successor = revision;
    successor["status"] = json!("released");
    successor["runtime_tool_contract"] = json!({
        "tool_id": contract.tool_id,
        "revision_ref": contract.revision_ref,
        "content_hash": contract.content_hash,
        "admission_receipt_ref": commit.receipt_ref,
    });
    successor["released_at"] = json!(super::iso_now());
    successor["updated_at"] = successor["released_at"].clone();
    successor["admitted_head"] = json!(commit.projection.head);
    if let Err(response) = validate(REVISION_CONTRACT, "function revision", &successor) {
        return response;
    }
    if let Err(response) = persist(
        KIND_REVISION,
        &st.data_dir,
        &record_id(&fn_id, n),
        &successor,
    ) {
        return response;
    }
    created(&commit, successor, "revision")
}

/// POST /v1/hypervisor/functions/:id/revisions/:ordinal/deprecate {reason} — deprecate a released
/// revision and revoke its tool revision.
pub(crate) async fn handle_function_deprecate(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath((id, ordinal)): AxumPath<(String, String)>,
    Json(body): Json<Value>,
) -> Reply {
    let caller = match require_write_caller(&st.data_dir, &headers, &body) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    let (fn_id, revisions) = match owned_family(&st, &caller, &id) {
        Ok(found) => found,
        Err(response) => return response,
    };
    let revision = match revision_at(&revisions, &ordinal) {
        Ok(revision) => revision,
        Err(response) => return response,
    };
    match text(&revision, "status") {
        "deprecated" => return replay(revision),
        "released" => {}
        _ => {
            return bad(
                StatusCode::CONFLICT,
                "function_revision_not_released",
                "only a released revision is deprecated; a draft is simply never released",
            )
        }
    }
    let reason = text(&body, "reason").to_string();
    if reason.is_empty() || reason.chars().count() > 2000 {
        return bad(
            StatusCode::BAD_REQUEST,
            "function_deprecation_reason_required",
            "a deprecation says why, in 1..2000 characters",
        );
    }
    let function_ref = format!("function://{fn_id}");
    let expected_head = match family_head(&st.data_dir, &function_ref) {
        Ok(Some(head)) => head,
        Ok(None) => {
            return bad(
                StatusCode::CONFLICT,
                "function_expected_head_required",
                "this function has no admitted head",
            )
        }
        Err(response) => return response,
    };
    let tool_ref = text(&revision["runtime_tool_contract"], "revision_ref").to_string();
    let tool_hash = text(&revision["runtime_tool_contract"], "content_hash").to_string();
    let Ok(mut registry) = st.runtime_tool_contract_registry.write() else {
        return bad(
            StatusCode::SERVICE_UNAVAILABLE,
            "function_tool_registry_unavailable",
            "the runtime tool-contract registry is unavailable",
        );
    };
    let commit = match admit_owner_scoped_write(
        &st.data_dir,
        &caller,
        NAMESPACE,
        KIND_FUNCTION,
        &function_ref,
        "function.revision.deprecate",
        Some(&expected_head),
        &json!({ "function_ref": function_ref, "revision_ref": revision["revision_ref"], "tool_revision_ref": tool_ref, "reason": reason }),
    ) {
        Ok(commit) => commit,
        Err(response) => return response,
    };
    if let Err(error) = registry.revoke(
        &tool_ref,
        &tool_hash,
        commit.receipt_ref.clone(),
        reason.clone(),
    ) {
        return registry_refusal(error);
    }
    drop(registry);
    let mut successor = revision;
    successor["status"] = json!("deprecated");
    successor["deprecation"] = json!({
        "reason": reason,
        "deprecated_by_principal_ref": caller.identity.principal_ref,
        "receipt_ref": commit.receipt_ref,
    });
    successor["updated_at"] = json!(super::iso_now());
    successor["admitted_head"] = json!(commit.projection.head);
    if let Err(response) = validate(REVISION_CONTRACT, "function revision", &successor) {
        return response;
    }
    let n = successor["ordinal"].as_u64().unwrap_or(0);
    if let Err(response) = persist(
        KIND_REVISION,
        &st.data_dir,
        &record_id(&fn_id, n),
        &successor,
    ) {
        return response;
    }
    created(&commit, successor, "revision")
}

/// Boot: re-admit every released revision into the registry, family by family in ordinal order,
/// and re-revoke the deprecated ones. A revision whose record no longer compiles to the tool hash it
/// was released under is skipped (and named), never admitted as different bytes.
pub(crate) fn rehydrate_released_functions(
    data_dir: &str,
    registry: &mut RuntimeToolContractRegistry,
) -> Vec<String> {
    let mut skipped = Vec::new();
    let mut families: std::collections::BTreeMap<String, Vec<Value>> = Default::default();
    for revision in read_record_dir(data_dir, KIND_REVISION) {
        if revision["runtime_tool_contract"].is_object() {
            families
                .entry(text(&revision, "function_ref").to_string())
                .or_default()
                .push(revision);
        }
    }
    for mut revisions in families.into_values() {
        revisions.sort_by_key(|r| r["ordinal"].as_u64().unwrap_or(0));
        let mut previous: Option<(String, String)> = None;
        for revision in revisions {
            let binding = &revision["runtime_tool_contract"];
            let admitted = compile_tool_contract(&revision, previous.as_ref().map(|p| p.0.clone()))
                .map_err(|error| error.to_string())
                .and_then(|contract| {
                    if contract.content_hash != text(binding, "content_hash")
                        || revision_content_hash(&revision) != text(&revision, "content_hash")
                    {
                        return Err(
                            "the record no longer compiles to its released tool hash".into()
                        );
                    }
                    registry
                        .admit(
                            contract.clone(),
                            text(binding, "admission_receipt_ref").to_string(),
                            previous.as_ref().map(|p| p.1.clone()),
                        )
                        .map_err(|error| error.to_string())?;
                    if text(&revision, "status") == "deprecated" {
                        registry
                            .revoke(
                                &contract.revision_ref,
                                &contract.content_hash,
                                text(&revision["deprecation"], "receipt_ref").to_string(),
                                text(&revision["deprecation"], "reason").to_string(),
                            )
                            .map_err(|error| error.to_string())?;
                    }
                    Ok((contract.revision_ref, contract.content_hash))
                });
            match admitted {
                Ok(head) => previous = Some(head),
                Err(why) => {
                    skipped.push(format!("{}: {why}", text(&revision, "revision_ref")));
                    // Later revisions chain to this one; none of them can be admitted either.
                    break;
                }
            }
        }
    }
    skipped
}

// ---------------------------------------------------------------------------------------------
// Test runs.
// ---------------------------------------------------------------------------------------------

/// The command a run sends to the exec primitive. Source and inputs are quoted heredocs, so the
/// command string carries them in plaintext and the guardrail deny-list reads what will run.
pub(crate) fn run_command(revision: &Value, inputs: &Value) -> Result<String, String> {
    let runtime = text(&revision["implementation"], "runtime");
    let (interpreter, extension) = match runtime {
        "python3" => ("python3", "py"),
        "node" => ("node", "js"),
        "bash" => ("bash", "sh"),
        other => return Err(format!("unknown runtime {other}")),
    };
    let source = revision["implementation"]["source"]
        .as_str()
        .unwrap_or_default();
    let nonce: String = text(revision, "content_hash")
        .trim_start_matches("sha256:")
        .chars()
        .take(16)
        .collect();
    let source_end = format!("IOI_FUNCTION_SOURCE_{nonce}");
    let inputs_end = format!("IOI_FUNCTION_INPUTS_{nonce}");
    if source.lines().any(|line| line == source_end) {
        return Err("the source contains its own heredoc terminator".into());
    }
    let inputs_json = serde_json::to_string(inputs).map_err(|e| e.to_string())?;
    let newline = if source.ends_with('\n') { "" } else { "\n" };
    let seconds = revision["timeout_ms"]
        .as_u64()
        .unwrap_or(30_000)
        .div_ceil(1000);
    Ok(format!(
        "d=$(mktemp -d) || exit 125\n\
         cat > \"$d/function.{extension}\" <<'{source_end}'\n{source}{newline}{source_end}\n\
         cat > \"$d/inputs.json\" <<'{inputs_end}'\n{inputs_json}\n{inputs_end}\n\
         timeout {seconds} {interpreter} \"$d/function.{extension}\" < \"$d/inputs.json\"\n\
         rc=$?\n\
         rm -r -f -- \"$d\"\n\
         exit $rc\n"
    ))
}

pub(crate) struct RunObservation {
    pub(crate) outcome: &'static str,
    pub(crate) exit_code: Option<i64>,
    pub(crate) output: Value,
    pub(crate) output_bytes: usize,
    pub(crate) output_hash: Option<String>,
    pub(crate) summary: String,
    pub(crate) stderr_tail: String,
}

fn tail(text: &str, max: usize) -> String {
    let count = text.chars().count();
    text.chars().skip(count.saturating_sub(max)).collect()
}

/// One exec answer, classified against the revision's declared output type.
pub(crate) fn classify_run(answer: &Value, output_type: &Value, timeout_ms: u64) -> RunObservation {
    let stdout = answer.get("stdout").and_then(Value::as_str).unwrap_or("");
    let stderr = answer.get("stderr").and_then(Value::as_str).unwrap_or("");
    let mut observation = RunObservation {
        outcome: "errored",
        exit_code: answer.get("exit_code").and_then(Value::as_i64),
        output: Value::Null,
        output_bytes: stdout.len(),
        output_hash: (!stdout.is_empty()).then(|| sha256_ref(stdout.as_bytes())),
        summary: String::new(),
        stderr_tail: tail(stderr, 2000),
    };
    let refused = ["refused", "policy_denied", "policy_indeterminate"]
        .iter()
        .any(|key| answer.get(*key).and_then(Value::as_bool) == Some(true));
    if refused || observation.exit_code.is_none() {
        let why = answer
            .pointer("/denial/matched")
            .map(|m| format!("the exec guardrail denied it (matched {m})"))
            .or_else(|| {
                answer
                    .get("reason")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .or_else(|| {
                answer
                    .pointer("/error/message")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .unwrap_or_else(|| "the exec route answered without an exit code".into());
        observation.exit_code = observation.exit_code.filter(|_| !refused);
        observation.summary = format!(
            "could not be run: {}",
            why.chars().take(400).collect::<String>()
        );
        return observation;
    }
    let code = observation.exit_code.unwrap_or(-1);
    if code == 124 {
        observation.outcome = "timed_out";
        observation.summary = format!("stopped by its {}s timeout", timeout_ms.div_ceil(1000));
        return observation;
    }
    if code != 0 {
        observation.outcome = "failed";
        observation.summary = format!("exited {code}");
        return observation;
    }
    let expected = describe(output_type);
    match serde_json::from_str::<Value>(stdout.trim()) {
        Ok(value) => {
            let fits = value_matches(output_type, &value);
            if stdout.len() <= MAX_OUTPUT_RETAINED {
                observation.output = value;
            }
            if fits {
                observation.outcome = "passed";
                observation.summary = format!("exited 0 and printed one {expected} value");
            } else {
                observation.outcome = "failed";
                observation.summary = format!(
                    "exited 0 but printed a value that is not {}",
                    with_article(output_type)
                );
            }
        }
        Err(_) => {
            observation.outcome = "failed";
            observation.summary = format!(
                "exited 0 but did not print one JSON value (a function prints its {expected} result on stdout and logs on stderr)"
            );
        }
    }
    observation
}

/// POST /v1/hypervisor/functions/:id/test-runs {revision_ref?|ordinal?, environment_ref, inputs} —
/// run one exact revision now, in an environment the caller owns, and admit the run.
pub(crate) async fn handle_function_test_run(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> Reply {
    let caller = match require_write_caller(&st.data_dir, &headers, &body) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    let (fn_id, revisions) = match owned_family(&st, &caller, &id) {
        Ok(found) => found,
        Err(response) => return response,
    };
    let wanted = match (body.get("ordinal"), text(&body, "revision_ref")) {
        (Some(n), _) if n.is_u64() => n.to_string(),
        (_, reference) if !reference.is_empty() => {
            reference.rsplit('/').next().unwrap_or("").to_string()
        }
        _ => revisions
            .last()
            .and_then(|r| r["ordinal"].as_u64())
            .unwrap_or(0)
            .to_string(),
    };
    let revision = match revision_at(&revisions, &wanted) {
        Ok(revision) => revision,
        Err(response) => return response,
    };
    let environment_ref = text(&body, "environment_ref").to_string();
    let environment_id = environment_ref
        .strip_prefix("environment://")
        .unwrap_or("")
        .to_string();
    if environment_id.is_empty()
        || environment_ref.len() > 500
        || environment_ref.chars().any(char::is_whitespace)
    {
        return bad(
            StatusCode::BAD_REQUEST,
            "function_environment_required",
            "a test run names the environment it runs in (environment://…)",
        );
    }
    let declared_inputs: Vec<Value> = revision["inputs"].as_array().cloned().unwrap_or_default();
    let inputs = match checked_inputs(&declared_inputs, body.get("inputs").unwrap_or(&Value::Null))
    {
        Ok(inputs) => inputs,
        Err(why) => return bad(StatusCode::BAD_REQUEST, "function_input_invalid", why),
    };
    let run_tail = replay_stable_id("ftr", &caller.owner_ref, &caller.idempotency_key);
    let record_key = format!("{fn_id}--{run_tail}");
    if let Some(existing) = load_record(&st.data_dir, KIND_TEST_RUN, &record_key) {
        return (
            StatusCode::OK,
            Json(json!({ "ok": true, "replayed": true, "test_run": existing })),
        );
    }
    let command = match run_command(&revision, &inputs) {
        Ok(command) => command,
        Err(why) => return bad(StatusCode::CONFLICT, "function_source_unrunnable", why),
    };
    let answer = match super::environment_routes::handle_workspace_exec(
        State(st.clone()),
        headers.clone(),
        Json(json!({ "environment_id": environment_id, "command": command })),
    )
    .await
    {
        Ok(Json(answer)) => answer,
        Err(error) => json!({ "error": { "message": error.1 } }),
    };
    let timeout_ms = revision["timeout_ms"].as_u64().unwrap_or(30_000);
    let observed = classify_run(&answer, &revision["output"]["data_type"], timeout_ms);
    let test_run_ref = format!("function-test-run://{fn_id}/{run_tail}");
    let mut record = json!({
        "schema_version": TEST_RUN_SCHEMA,
        "test_run_id": test_run_ref,
        "function_ref": revision["function_ref"],
        "revision_ref": revision["revision_ref"],
        "revision_content_hash": revision["content_hash"],
        "environment_ref": environment_ref,
        "inputs": inputs,
        "outcome": observed.outcome,
        "exit_code": observed.exit_code,
        "output": observed.output,
        "output_bytes": observed.output_bytes,
        "output_hash": observed.output_hash,
        "redacted_summary": observed.summary,
        "stderr_tail": observed.stderr_tail,
        "observed_at": super::iso_now(),
        "evaluated_by_principal_ref": caller.identity.principal_ref,
        "owner_ref": caller.owner_ref,
        "admitted_head": Value::Null,
    });
    if let Err(response) = validate(TEST_RUN_CONTRACT, "function test run", &record) {
        return response;
    }
    let commit = match admit_owner_scoped_write(
        &st.data_dir,
        &caller,
        NAMESPACE,
        KIND_TEST_RUN,
        &test_run_ref,
        "function.test_run",
        None,
        &json!({ "test_run_id": test_run_ref, "revision_ref": record["revision_ref"], "revision_content_hash": record["revision_content_hash"], "environment_ref": record["environment_ref"], "outcome": record["outcome"], "exit_code": record["exit_code"], "output_hash": record["output_hash"] }),
    ) {
        Ok(commit) => commit,
        Err(response) => return response,
    };
    record["admitted_head"] = json!(commit.projection.head);
    if let Err(response) = persist(KIND_TEST_RUN, &st.data_dir, &record_key, &record) {
        return response;
    }
    created(&commit, record, "test_run")
}

// ---------------------------------------------------------------------------------------------
// The published readers.
// ---------------------------------------------------------------------------------------------

/// A revision as a list shows it: without its source, with whether its tool revision is operable.
fn summary(revision: &Value, registry: Option<&RuntimeToolContractRegistry>) -> Value {
    let mut out = revision.clone();
    if let Some(implementation) = out["implementation"].as_object_mut() {
        implementation.remove("source");
    }
    let binding = &revision["runtime_tool_contract"];
    out["tool_operable"] = json!(
        binding.is_object()
            && registry.is_some_and(|registry| registry
                .resolve_exact(text(binding, "revision_ref"), text(binding, "content_hash"))
                .is_ok())
    );
    out
}

fn family_view(revisions: &[Value], registry: Option<&RuntimeToolContractRegistry>) -> Value {
    let latest = revisions.last().cloned().unwrap_or(Value::Null);
    let released = revisions
        .iter()
        .rev()
        .find(|r| text(r, "status") == "released");
    json!({
        "function_ref": latest["function_ref"],
        "api_name": latest["api_name"],
        "display_name": latest["display_name"],
        "owner_ref": latest["owner_ref"],
        "revision_count": revisions.len(),
        "latest_revision": summary(&latest, registry),
        "released_revision": released.map(|r| summary(r, registry)),
        "updated_at": revisions.iter().map(|r| text(r, "updated_at")).max().unwrap_or(""),
    })
}

/// Every revision the caller's tenants may see, grouped by family (oldest revision first).
pub(crate) fn function_families_for_request(
    st: &DaemonState,
    headers: &HeaderMap,
) -> Result<Vec<Vec<Value>>, Reply> {
    let identity = super::substrate_store::resolve_request_identity(&st.data_dir, headers)
        .map_err(scope_refusal_reply)?;
    let mut families: std::collections::BTreeMap<String, Vec<Value>> = Default::default();
    for revision in read_record_dir(&st.data_dir, KIND_REVISION) {
        if revision["owner_ref"]
            .as_str()
            .is_some_and(|owner| identity.authorizes_tenant(owner))
        {
            families
                .entry(text(&revision, "function_ref").to_string())
                .or_default()
                .push(revision);
        }
    }
    Ok(families
        .into_values()
        .map(|mut revisions| {
            revisions.sort_by_key(|r| r["ordinal"].as_u64().unwrap_or(0));
            revisions
        })
        .collect())
}

fn test_runs_for_request(st: &DaemonState, headers: &HeaderMap) -> Result<Vec<Value>, Reply> {
    let identity = super::substrate_store::resolve_request_identity(&st.data_dir, headers)
        .map_err(scope_refusal_reply)?;
    let mut runs: Vec<Value> = read_record_dir(&st.data_dir, KIND_TEST_RUN)
        .into_iter()
        .filter(|run| {
            run["owner_ref"]
                .as_str()
                .is_some_and(|owner| identity.authorizes_tenant(owner))
        })
        .collect();
    runs.sort_by(|a, b| text(b, "observed_at").cmp(text(a, "observed_at")));
    Ok(runs)
}

/// GET /v1/hypervisor/functions
pub(crate) async fn handle_function_list(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
) -> Reply {
    let families = match function_families_for_request(&st, &headers) {
        Ok(families) => families,
        Err(reply) => return reply,
    };
    let registry = st.runtime_tool_contract_registry.read().ok();
    let mut functions: Vec<Value> = families
        .iter()
        .map(|revisions| family_view(revisions, registry.as_deref()))
        .collect();
    functions.sort_by(|a, b| text(b, "updated_at").cmp(text(a, "updated_at")));
    (
        StatusCode::OK,
        Json(json!({ "ok": true, "functions": functions })),
    )
}

/// GET /v1/hypervisor/functions/:id — the family, every revision (newest first, with source) and
/// its recent test runs.
pub(crate) async fn handle_function_get(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Reply {
    let identity = match super::substrate_store::resolve_request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(error) => return scope_refusal_reply(error),
    };
    let not_found = bad(
        StatusCode::NOT_FOUND,
        "function_not_found",
        "no function exists at this id",
    );
    let Some(fn_id) = family_id(&id) else {
        return not_found;
    };
    let revisions = revisions_of(&st.data_dir, &fn_id);
    let Some(first) = revisions.first() else {
        return not_found;
    };
    if !first["owner_ref"]
        .as_str()
        .is_some_and(|owner| identity.authorizes_tenant(owner))
    {
        return scope_refusal_reply(
            super::substrate_store::RequestScopeRefusal::ResourceScopeRequired,
        );
    }
    let registry = st.runtime_tool_contract_registry.read().ok();
    let function = family_view(&revisions, registry.as_deref());
    let full: Vec<Value> = revisions
        .iter()
        .rev()
        .map(|r| {
            let mut out = summary(r, registry.as_deref());
            out["implementation"] = r["implementation"].clone();
            out
        })
        .collect();
    drop(registry);
    let function_ref = format!("function://{fn_id}");
    let test_runs: Vec<Value> = read_record_dir(&st.data_dir, KIND_TEST_RUN)
        .into_iter()
        .filter(|run| text(run, "function_ref") == function_ref)
        .collect::<Vec<_>>();
    let mut test_runs = test_runs;
    test_runs.sort_by(|a, b| text(b, "observed_at").cmp(text(a, "observed_at")));
    test_runs.truncate(20);
    (
        StatusCode::OK,
        Json(
            json!({ "ok": true, "function": function, "revisions": full, "test_runs": test_runs }),
        ),
    )
}

/// GET /v1/hypervisor/function-test-runs[?function=<id>]
pub(crate) async fn handle_function_test_run_list(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Query(query): Query<std::collections::HashMap<String, String>>,
) -> Reply {
    let runs = match test_runs_for_request(&st, &headers) {
        Ok(runs) => runs,
        Err(reply) => return reply,
    };
    let function = query
        .get("function")
        .and_then(|id| family_id(id))
        .map(|id| format!("function://{id}"));
    let runs: Vec<Value> = runs
        .into_iter()
        .filter(|run| {
            function
                .as_deref()
                .is_none_or(|f| text(run, "function_ref") == f)
        })
        .collect();
    (
        StatusCode::OK,
        Json(json!({ "ok": true, "test_runs": runs })),
    )
}

#[cfg(test)]
mod function_tests {
    use super::*;

    fn declaration() -> Value {
        json!({
            "display_name": "Double an amount",
            "api_name": "doubleAmount",
            "version": "1.0.0",
            "inputs": [
                { "name": "amount", "description": "what to double", "data_type": { "type": "integer" }, "required": true },
                { "name": "tags", "data_type": { "type": "list", "element_type": "string" }, "required": false }
            ],
            "output": { "data_type": { "type": "integer" } },
            "implementation": { "runtime": "python3", "source": "import json, sys\nprint(json.dumps(json.load(sys.stdin)['amount'] * 2))\n" },
        })
    }

    fn revision() -> Value {
        let decl = declared(&declaration()).expect("a well-formed declaration");
        let mut record = json!({
            "function_ref": "function://fn_0123456789abcdef",
            "revision_ref": "function://fn_0123456789abcdef/revision/1",
            "predecessor_revision_ref": null,
            "ordinal": 1,
            "version": decl.version,
            "display_name": decl.display_name,
            "api_name": decl.api_name,
            "documentation": decl.documentation,
            "inputs": decl.inputs,
            "output": decl.output,
            "implementation": { "runtime": decl.runtime, "source": decl.source, "source_hash": sha256_ref(decl.source.as_bytes()) },
            "timeout_ms": decl.timeout_ms,
            "owner_ref": "org://acme",
        });
        record["content_hash"] = json!(revision_content_hash(&record));
        record
    }

    #[test]
    fn a_declaration_types_every_input_and_refuses_what_it_cannot_type() {
        let decl = declared(&declaration()).expect("well-formed");
        assert_eq!(
            decl.inputs[0]["data_type"],
            json!({ "type": "integer", "element_type": null })
        );
        assert_eq!(decl.inputs[1]["required"], json!(false));
        let mut untyped_list = declaration();
        untyped_list["inputs"][1]["data_type"] = json!({ "type": "list" });
        assert!(declared(&untyped_list).is_err());
        let mut object_input = declaration();
        object_input["inputs"][0]["data_type"] = json!({ "type": "object" });
        assert!(
            declared(&object_input).is_err(),
            "ontology-object inputs are a named gap in v1"
        );
        let mut duplicate = declaration();
        duplicate["inputs"][1]["name"] = json!("amount");
        assert!(declared(&duplicate).is_err());
        let mut bad_version = declaration();
        bad_version["version"] = json!("1.0");
        assert!(declared(&bad_version).is_err());
        let mut leading_zero = declaration();
        leading_zero["version"] = json!("1.02.0");
        assert!(declared(&leading_zero).is_err());
    }

    #[test]
    fn versions_order_numerically() {
        assert!(parse_version("1.10.0") > parse_version("1.9.9"));
        assert!(parse_version("2.0.0") > parse_version("1.99.99"));
        assert_eq!(parse_version("0.0.0"), Some((0, 0, 0)));
        assert_eq!(parse_version("1.0.0.0"), None);
    }

    #[test]
    fn inputs_are_checked_against_their_declared_types() {
        let decl = declared(&declaration()).unwrap();
        assert_eq!(
            checked_inputs(&decl.inputs, &json!({ "amount": 21 })).unwrap(),
            json!({ "amount": 21 })
        );
        assert!(checked_inputs(&decl.inputs, &json!({}))
            .unwrap_err()
            .contains("required"));
        assert!(checked_inputs(&decl.inputs, &json!({ "amount": 2.5 })).is_err());
        assert!(checked_inputs(&decl.inputs, &json!({ "amount": 1, "tags": ["a", 2] })).is_err());
        assert!(checked_inputs(&decl.inputs, &json!({ "amount": 1, "other": 1 })).is_err());
        assert!(scalar_matches("timestamp", &json!("2026-09-26T10:00:00Z")));
        assert!(!scalar_matches("date", &json!("2026-13-01")));
    }

    #[test]
    fn the_content_hash_commits_to_the_source() {
        let a = revision();
        let mut b = a.clone();
        b["implementation"]["source"] = json!("print(1)\n");
        assert_ne!(revision_content_hash(&a), revision_content_hash(&b));
        let mut c = a.clone();
        c["updated_at"] = json!("later");
        assert_eq!(
            revision_content_hash(&a),
            revision_content_hash(&c),
            "timestamps are not content"
        );
    }

    #[test]
    fn a_released_revision_compiles_to_a_registry_admissible_exact_tool_contract() {
        let mut registry = RuntimeToolContractRegistry::default();
        let first = compile_tool_contract(&revision(), None).expect("compiles");
        assert_eq!(first.tool_id, "tool://function/fn_0123456789abcdef");
        assert_eq!(
            first.revision_ref,
            "tool://function/fn_0123456789abcdef/revision/1"
        );
        assert_eq!(first.input_schema["required"], json!(["amount"]));
        assert_eq!(
            first.input_schema["properties"]["tags"]["type"],
            json!("array")
        );
        assert_eq!(
            compile_tool_contract(&revision(), None)
                .unwrap()
                .content_hash,
            first.content_hash,
            "compilation is deterministic, so boot can prove it rebuilt the same bytes"
        );
        registry
            .admit(first.clone(), "receipt://test/1".into(), None)
            .expect("the registry admits it");
        assert!(registry
            .resolve_exact(&first.revision_ref, &first.content_hash)
            .is_ok());
        let mut next = revision();
        next["ordinal"] = json!(2);
        next["revision_ref"] = json!("function://fn_0123456789abcdef/revision/2");
        next["version"] = json!("1.1.0");
        let second = compile_tool_contract(&next, Some(first.revision_ref.clone())).unwrap();
        registry
            .admit(
                second.clone(),
                "receipt://test/2".into(),
                Some(first.content_hash.clone()),
            )
            .expect("a successor chains to the released head");
        registry
            .revoke(
                &second.revision_ref,
                &second.content_hash,
                "receipt://test/3".into(),
                "bad".into(),
            )
            .unwrap();
        assert!(registry
            .resolve_exact(&second.revision_ref, &second.content_hash)
            .is_err());
    }

    #[test]
    fn the_run_command_carries_source_and_inputs_in_plaintext() {
        let command = run_command(&revision(), &json!({ "amount": 21 })).unwrap();
        assert!(
            command.contains("json.load(sys.stdin)['amount'] * 2"),
            "the deny-list must read the source"
        );
        assert!(command.contains("{\"amount\":21}"));
        assert!(command.contains("timeout 30 python3"));
        let mut hostile = revision();
        let end = format!(
            "IOI_FUNCTION_SOURCE_{}",
            &text(&hostile, "content_hash")["sha256:".len().."sha256:".len() + 16]
        );
        hostile["implementation"]["source"] = json!(format!("echo hi\n{end}\nrm -r -f ~\n"));
        assert!(run_command(&hostile, &json!({})).is_err());
    }

    #[test]
    fn a_run_is_classified_against_the_declared_output_type() {
        let integer = json!({ "type": "integer", "element_type": null });
        let passed = classify_run(
            &json!({ "exit_code": 0, "stdout": "42\n", "stderr": "" }),
            &integer,
            30_000,
        );
        assert_eq!(
            (passed.outcome, passed.output.clone()),
            ("passed", json!(42))
        );
        let wrong = classify_run(
            &json!({ "exit_code": 0, "stdout": "\"42\"" }),
            &integer,
            30_000,
        );
        assert_eq!(wrong.outcome, "failed");
        let noisy = classify_run(
            &json!({ "exit_code": 0, "stdout": "log line\n42" }),
            &integer,
            30_000,
        );
        assert_eq!(noisy.outcome, "failed");
        assert_eq!(
            classify_run(&json!({ "exit_code": 3 }), &integer, 30_000).outcome,
            "failed"
        );
        assert_eq!(
            classify_run(&json!({ "exit_code": 124 }), &integer, 30_000).outcome,
            "timed_out"
        );
        let denied = classify_run(
            &json!({ "policy_denied": true, "denial": { "matched": "shutdown" }, "exit_code": 126 }),
            &integer,
            30_000,
        );
        assert_eq!((denied.outcome, denied.exit_code), ("errored", None));
        assert!(denied.summary.contains("shutdown"));
        assert_eq!(
            classify_run(
                &json!({ "error": { "message": "environment not started" } }),
                &integer,
                30_000
            )
            .outcome,
            "errored"
        );
    }
}
