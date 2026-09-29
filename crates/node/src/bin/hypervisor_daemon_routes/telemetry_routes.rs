//! Telemetry series (ADR 0056 Amendment 1, plane 6) — `TelemetrySeries`, `TelemetryPoint` and
//! `TelemetryRange` (docs/architecture/components/daemon-runtime/platform-operability.md
//! §TelemetrySeries, §TelemetryPoint, §TelemetryRange).
//!
//! This plane EXTENDS the event-stream plane; it is not a second spine. A series is one
//! owner-namespaced event stream (`event-stream://hypervisor-telemetry/series.<ts_id>`), declared
//! through `event_stream_routes::declare_stream` with two classes on the two sides of the
//! event-class line, and every point is appended through `event_stream_routes::append_event`:
//!
//! * `telemetry.point` is ADMITTED truth. A point read from an admitted record (a health-check
//!   result) crosses an Agentgres transition with an exact expected head and carries a receipt; the
//!   range read replays it from the stream's own history.
//! * `telemetry.sample` is EPHEMERAL delivery. A sample of a changing value (how long a probe took)
//!   mints no sequence, head, root or receipt — the event-stream plane decides that from the
//!   stream's admitted declaration and awaits no Agentgres operation — and is held only in this
//!   plane's bounded in-process window, which a restart empties. The range read says so.
//!
//! A series' identity is (owner, producing principal, subject, scope, metric name, unit), committed
//! by a digest and admitted once as the series' declaration. The producing principal is part of it
//! because the event-stream plane admits appends only from the principal that reserved the stream.
//! Reads are the owner TENANT's (like the health-check plane whose results these points come from):
//! the series record and the stream's admitted scope must both name a tenant the caller belongs to.
//!
//! Producers today: Health's Evaluate (one admitted `ioi.health_check.passed` point per evaluation,
//! and one ephemeral `ioi.health_check.duration` sample when a probe ran). Names follow the
//! OpenTelemetry semantic-convention profile in [`CONVENTIONS`]; a producer may only declare a
//! series under a name the profile holds. Nothing here grants anything or becomes authority.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, OnceLock};

use axum::extract::{Path as AxumPath, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::event_stream_routes::{self, Appended};
use super::mutation_event_foundation::{admit_owner_scoped_write, scope_refusal_reply, WriteCaller};
use super::substrate_store::{self, RequestIdentity, RequestScopeRefusal};
use super::{persist_record, read_record_dir, DaemonState};

pub(crate) const NAMESPACE: &str = "hypervisor-telemetry";
const KIND_SERIES: &str = "telemetry-series";
const SERIES_SCHEMA: &str = "ioi.hypervisor.telemetry_series.v1";
const POINT_SCHEMA: &str = "ioi.hypervisor.telemetry_point.v1";
const RANGE_SCHEMA: &str = "ioi.hypervisor.telemetry_range.v1";
const SERIES_CONTRACT: &str = "schema://ioi/components/daemon-runtime/telemetry-series/v1";
const POINT_CONTRACT: &str = "schema://ioi/components/daemon-runtime/telemetry-point/v1";
const RANGE_CONTRACT: &str = "schema://ioi/components/daemon-runtime/telemetry-range/v1";
pub(crate) const ADMITTED_CLASS: &str = "telemetry.point";
pub(crate) const EPHEMERAL_CLASS: &str = "telemetry.sample";
/// Ephemeral samples kept per series, newest first out; and the number of series whose window is
/// held at once (the least recently sampled one is dropped first).
const WINDOW_POINTS: usize = 512;
const WINDOW_SERIES: usize = 4096;
/// Every range read is held to these, and the answer states them.
const MAX_SPAN_MS: u64 = 31 * 24 * 3600 * 1000;
const MAX_BUCKETS: u64 = 1440;
const MAX_POINTS: usize = 1000;
const DEFAULT_SPAN_MS: u64 = 24 * 3600 * 1000;
const DEFAULT_BUCKETS: u64 = 60;
const DEFAULT_ROLLING: u64 = 5;
const MAX_ROLLING: u64 = 100;
const APPEND_ATTEMPTS: usize = 4;
pub(crate) const HEALTH_PRODUCER: &str = "daemon-producer://health-check-evaluate";
pub(crate) const HEALTH_PASSED: &str = "ioi.health_check.passed";
pub(crate) const HEALTH_DURATION: &str = "ioi.health_check.duration";
pub(crate) const HEALTH_OUTCOME_ATTRIBUTE: &str = "ioi.health_check.outcome";
const CANON_ANCHOR: &str =
    "canon://docs/architecture/components/daemon-runtime/platform-operability.md#telemetryseries";

type Reply = (StatusCode, Json<Value>);

fn bad(status: StatusCode, code: &str, message: impl Into<String>) -> Reply {
    (
        status,
        Json(json!({ "ok": false, "error": { "code": code, "message": message.into() } })),
    )
}

/// An event-stream refusal, rendered in this plane's reply shape with its code and message intact.
fn refused_reply(refusal: event_stream_routes::Refused) -> Reply {
    let (status, body) = refusal.into_parts();
    let error = body.get("error").cloned().unwrap_or(Value::Null);
    (status, Json(json!({ "ok": false, "error": error })))
}

fn text<'a>(body: &'a Value, key: &str) -> &'a str {
    body.get(key).and_then(Value::as_str).unwrap_or("")
}

// ---- The OpenTelemetry profile ------------------------------------------------------------------

/// One adopted metric convention: the name, its UCUM unit and OpenTelemetry instrument kind, and
/// whose convention it is. The profile is the subset of OpenTelemetry this plane uses; the
/// conformance test below holds every entry to OpenTelemetry's naming, unit and instrument rules.
pub(crate) struct Convention {
    pub(crate) name: &'static str,
    pub(crate) unit: &'static str,
    pub(crate) instrument: &'static str,
    pub(crate) registry: &'static str,
    pub(crate) stability: &'static str,
    pub(crate) reference: &'static str,
    pub(crate) description: &'static str,
}

pub(crate) const CONVENTIONS: &[Convention] = &[
    // No OpenTelemetry convention covers a health check's outcome or its probe, so both live in the
    // `ioi.` namespace and follow OpenTelemetry's naming rules: lowercase dotted names, UCUM units,
    // a `.duration` in seconds recorded by a histogram.
    Convention {
        name: HEALTH_PASSED,
        unit: "1",
        instrument: "gauge",
        registry: "ioi",
        stability: "ioi_extension",
        reference: CANON_ANCHOR,
        description: "1 when an evaluation of the check passed, 0 when it did not; the outcome word is the ioi.health_check.outcome attribute.",
    },
    Convention {
        name: HEALTH_DURATION,
        unit: "s",
        instrument: "histogram",
        registry: "ioi",
        stability: "ioi_extension",
        reference: CANON_ANCHOR,
        description: "How long the check's probe took to answer, measured by the daemon around the governed exec call.",
    },
    // OpenTelemetry GenAI client metrics (development status), reserved for the model and agent
    // producer that W9.3's span export feeds; no producer declares them yet.
    Convention {
        name: "gen_ai.client.token.usage",
        unit: "{token}",
        instrument: "histogram",
        registry: "opentelemetry",
        stability: "development",
        reference: "https://opentelemetry.io/docs/specs/semconv/gen-ai/gen-ai-metrics/#metric-gen_aiclienttokenusage",
        description: "Number of input and output tokens used, by gen_ai.token.type.",
    },
    Convention {
        name: "gen_ai.client.operation.duration",
        unit: "s",
        instrument: "histogram",
        registry: "opentelemetry",
        stability: "development",
        reference: "https://opentelemetry.io/docs/specs/semconv/gen-ai/gen-ai-metrics/#metric-gen_aiclientoperationduration",
        description: "GenAI operation duration.",
    },
];

pub(crate) fn convention(name: &str) -> Option<&'static Convention> {
    CONVENTIONS.iter().find(|c| c.name == name)
}

/// OpenTelemetry's metric naming, as this profile applies it: at least two dot-separated lowercase
/// segments, each starting with a letter, 255 characters at most.
pub(crate) fn otel_metric_name(name: &str) -> bool {
    let segments: Vec<&str> = name.split('.').collect();
    name.len() <= 255
        && segments.len() >= 2
        && segments.iter().all(|segment| {
            let mut chars = segment.chars();
            chars.next().is_some_and(|c| c.is_ascii_lowercase())
                && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        })
}

/// OpenTelemetry's attribute naming: dot-separated lowercase segments, 128 characters at most.
pub(crate) fn otel_attribute_key(key: &str) -> bool {
    key.len() <= 128
        && key.split('.').all(|segment| {
            let mut chars = segment.chars();
            chars.next().is_some_and(|c| c.is_ascii_lowercase())
                && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        })
}

// ---- Series identity and records ----------------------------------------------------------------

/// sha256 over the JCS bytes of the series' identity. A different producing principal, subject,
/// scope, metric or unit is a different series.
pub(crate) fn identity_digest(
    owner_ref: &str,
    producer_principal_ref: &str,
    subject_ref: &str,
    scope_ref: Option<&str>,
    metric_name: &str,
    metric_unit: &str,
) -> String {
    let material = json!({
        "owner_ref": owner_ref,
        "producer_principal_ref": producer_principal_ref,
        "subject_ref": subject_ref,
        "scope_ref": scope_ref,
        "metric_name": metric_name,
        "metric_unit": metric_unit,
    });
    format!(
        "sha256:{:x}",
        Sha256::digest(serde_jcs::to_vec(&material).unwrap_or_default())
    )
}

fn series_tail_of(digest: &str) -> String {
    format!("ts_{}", &digest.trim_start_matches("sha256:")[..16])
}

fn stream_tail(series_tail: &str) -> String {
    format!("series.{series_tail}")
}

fn valid_series_tail(tail: &str) -> bool {
    tail.len() == 19
        && tail.starts_with("ts_")
        && tail[3..]
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
}

pub(crate) fn class_declaration() -> Value {
    json!({
        "admitted_truth_classes": [{
            "class_id": ADMITTED_CLASS,
            "payload_schema_ref": POINT_CONTRACT,
            "classification_basis": "a point read from an admitted record (a health-check result, a run): required to replay the series, and it bars or enables a claim about its subject",
        }],
        "ephemeral_delivery_classes": [{
            "class_id": EPHEMERAL_CLASS,
            "payload_schema_ref": POINT_CONTRACT,
            "classification_basis": "a sample of a changing value measured by the daemon: delivered to readers of the in-process window, never admitted",
        }],
    })
}

fn load_series(data_dir: &str, tail: &str) -> Option<Value> {
    if !valid_series_tail(tail) {
        return None;
    }
    serde_json::from_slice(
        &std::fs::read(
            std::path::Path::new(data_dir)
                .join(KIND_SERIES)
                .join(format!("{tail}.json")),
        )
        .ok()?,
    )
    .ok()
}

fn validate(contract: &str, what: &str, record: &Value) -> Result<(), Reply> {
    ioi_types::app::generated::architecture_contracts::validate_architecture_contract(
        contract, record,
    )
    .map_err(|error| {
        bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            "telemetry_contract_invalid",
            format!("the {what} would not satisfy its registered contract: {error}"),
        )
    })
}

fn persist(data_dir: &str, tail: &str, record: &Value) -> Result<(), Reply> {
    persist_record(data_dir, KIND_SERIES, tail, record).map_err(|_| {
        bad(
            StatusCode::INTERNAL_SERVER_ERROR,
            "telemetry_persistence_failed",
            "the declaration is admitted but its projection could not be written; producing again reconciles it",
        )
    })
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or_default()
}

/// An RFC 3339 UTC stamp for one instant in milliseconds.
pub(crate) fn stamp(ms: u64) -> String {
    use time::format_description::well_known::Rfc3339;
    time::OffsetDateTime::from_unix_timestamp_nanos((ms as i128) * 1_000_000)
        .ok()
        .and_then(|dt| dt.format(&Rfc3339).ok())
        .unwrap_or_else(super::iso_now)
}

/// Milliseconds since the epoch for an RFC 3339 instant; `None` when it does not parse.
pub(crate) fn parse_ms(iso: &str) -> Option<u64> {
    use time::format_description::well_known::Rfc3339;
    let nanos = time::OffsetDateTime::parse(iso, &Rfc3339)
        .ok()?
        .unix_timestamp_nanos();
    (nanos >= 0).then(|| (nanos / 1_000_000) as u64)
}

/// What a producer asks for: the series it appends to.
pub(crate) struct SeriesSpec<'a> {
    pub(crate) subject_ref: &'a str,
    pub(crate) scope_ref: Option<&'a str>,
    pub(crate) metric_name: &'a str,
    pub(crate) producer_ref: &'a str,
}

/// Declare the caller's series once, or find it. Replay-safe: the declaration and the stream's
/// genesis are both admitted under one key derived from the series, so a producer that died between
/// them re-runs both and each replays or completes.
pub(crate) fn ensure_series(
    st: &DaemonState,
    caller: &WriteCaller,
    spec: &SeriesSpec<'_>,
) -> Result<Value, Reply> {
    let Some(convention) = convention(spec.metric_name).filter(|c| otel_metric_name(c.name)) else {
        return Err(bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            "telemetry_metric_unregistered",
            format!(
                "{} is not a metric this plane's OpenTelemetry profile holds",
                spec.metric_name
            ),
        ));
    };
    let principal = caller.identity.principal_ref.as_str();
    let digest = identity_digest(
        &caller.owner_ref,
        principal,
        spec.subject_ref,
        spec.scope_ref,
        convention.name,
        convention.unit,
    );
    let tail = series_tail_of(&digest);
    let series_ref = format!("telemetry-series://{tail}");
    if let Some(existing) = load_series(&st.data_dir, &tail) {
        if text(&existing, "identity_digest") == digest {
            return Ok(existing);
        }
        return Err(bad(
            StatusCode::CONFLICT,
            "telemetry_series_identity_collision",
            "a different series holds this identifier",
        ));
    }
    let key = format!("telemetry-series:{tail}");
    let stream_id = event_stream_routes::event_stream_ref(NAMESPACE, &stream_tail(&tail));
    let metric = json!({ "name": convention.name, "unit": convention.unit, "instrument": convention.instrument });
    let declarer = WriteCaller {
        identity: caller.identity.clone(),
        owner_ref: caller.owner_ref.clone(),
        idempotency_key: key.clone(),
    };
    let declared = admit_owner_scoped_write(
        &st.data_dir,
        &declarer,
        NAMESPACE,
        KIND_SERIES,
        &series_ref,
        "telemetry_series.declare",
        None,
        &json!({
            "series_id": series_ref,
            "identity_digest": digest,
            "subject_ref": spec.subject_ref,
            "scope_ref": spec.scope_ref,
            "metric": metric,
            "stream_id": stream_id,
            "producer_ref": spec.producer_ref,
            "producer_principal_ref": principal,
        }),
    )?;
    event_stream_routes::declare_stream(
        st,
        &caller.identity,
        NAMESPACE,
        &stream_tail(&tail),
        &caller.owner_ref,
        &key,
        &class_declaration(),
        0,
    )
    .map_err(refused_reply)?;
    let record = json!({
        "schema_version": SERIES_SCHEMA,
        "series_id": series_ref,
        "identity_digest": digest,
        "subject_ref": spec.subject_ref,
        "scope_ref": spec.scope_ref,
        "metric": {
            "name": convention.name,
            "unit": convention.unit,
            "instrument": convention.instrument,
            "description": convention.description,
            "semantic_convention": {
                "registry": convention.registry,
                "stability": convention.stability,
                "reference": convention.reference,
            },
        },
        "stream_id": stream_id,
        "event_class_declaration": class_declaration(),
        "ephemeral_window": { "retention": "process_memory", "window_points": WINDOW_POINTS },
        "producer_ref": spec.producer_ref,
        "producer_principal_ref": principal,
        "owner_ref": caller.owner_ref,
        "declared_at": super::iso_now(),
        "declaration_receipt_ref": declared.receipt_ref,
        "latest_point": Value::Null,
    });
    validate(SERIES_CONTRACT, "telemetry series", &record)?;
    persist(&st.data_dir, &tail, &record)?;
    Ok(record)
}

// ---- The ephemeral window -----------------------------------------------------------------------

type Window = HashMap<String, VecDeque<Value>>;

fn window() -> &'static Mutex<Window> {
    static WINDOW: OnceLock<Mutex<Window>> = OnceLock::new();
    WINDOW.get_or_init(|| Mutex::new(HashMap::new()))
}

fn window_push(series_tail: &str, point: Value) {
    let Ok(mut held) = window().lock() else {
        return;
    };
    if !held.contains_key(series_tail) && held.len() >= WINDOW_SERIES {
        // Drop the series whose newest sample is oldest: the window is bounded in series as well as
        // in points, so a producer that mints series cannot grow the process without limit.
        let stalest = held
            .iter()
            .min_by_key(|(_, points)| {
                points
                    .back()
                    .and_then(|p| p.get("time_unix_ms"))
                    .and_then(Value::as_u64)
                    .unwrap_or(0)
            })
            .map(|(tail, _)| tail.clone());
        if let Some(stalest) = stalest {
            held.remove(&stalest);
        }
    }
    let points = held.entry(series_tail.to_string()).or_default();
    points.push_back(point);
    while points.len() > WINDOW_POINTS {
        points.pop_front();
    }
}

fn window_read(series_tail: &str) -> Vec<Value> {
    window()
        .lock()
        .ok()
        .and_then(|held| held.get(series_tail).map(|p| p.iter().cloned().collect()))
        .unwrap_or_default()
}

// ---- Producing points ---------------------------------------------------------------------------

/// Append one point to the caller's series through the event-stream plane. The point's class names
/// the side of the line it claims, and the plane's answer must agree: the stream's declaration, not
/// this function, decides. An admitted point names the admitted record it was read from, and its
/// idempotency key is derived from that record, so producing the same observation twice replays.
pub(crate) fn append_point(
    st: &DaemonState,
    identity: &RequestIdentity,
    series: &Value,
    point: &Value,
) -> Result<Value, Reply> {
    validate(POINT_CONTRACT, "telemetry point", point)?;
    let attributes = point
        .get("attributes")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut keys = std::collections::BTreeSet::new();
    if !attributes
        .iter()
        .all(|a| otel_attribute_key(text(a, "key")) && keys.insert(text(a, "key").to_string()))
    {
        return Err(bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            "telemetry_attribute_key_invalid",
            "a point names each attribute key once, in OpenTelemetry attribute naming",
        ));
    }
    let series_tail = text(series, "series_id")
        .trim_start_matches("telemetry-series://")
        .to_string();
    if text(point, "series_ref") != text(series, "series_id") {
        return Err(bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            "telemetry_point_series_mismatch",
            "the point names a different series than the one it is appended to",
        ));
    }
    let tail = stream_tail(&series_tail);
    let time_ms = point
        .get("time_unix_ms")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let (operation_ref, receipt_ref, replayed) = match text(point, "point_class") {
        "admitted" => {
            let source = text(point, "source_ref");
            if source.is_empty() {
                return Err(bad(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "telemetry_admitted_point_unsourced",
                    "an admitted point names the admitted record it was read from",
                ));
            }
            let mut key = format!("telemetry-point:{source}");
            if key.len() > 256 {
                key = format!("telemetry-point:sha256:{:x}", Sha256::digest(source.as_bytes()));
            }
            let mut committed = None;
            for _ in 0..APPEND_ATTEMPTS {
                let head = event_stream_routes::stream_head(st, identity, NAMESPACE, &tail)
                    .map_err(refused_reply)?
                    .ok_or_else(|| {
                        bad(
                            StatusCode::CONFLICT,
                            "telemetry_series_stream_absent",
                            "the series names a stream that holds no admitted declaration",
                        )
                    })?
                    .head;
                match event_stream_routes::append_event(
                    st,
                    identity,
                    NAMESPACE,
                    &tail,
                    ADMITTED_CLASS,
                    point,
                    Some(&head),
                    &key,
                    time_ms,
                ) {
                    Ok(Appended::Admitted { commit, .. }) => {
                        committed = Some(commit);
                        break;
                    }
                    Ok(Appended::Ephemeral { .. }) => {
                        return Err(bad(
                            StatusCode::CONFLICT,
                            "telemetry_point_class_mismatch",
                            "the stream's declaration delivered an admitted point as ephemeral",
                        ))
                    }
                    Err(refusal) => {
                        let reply = refused_reply(refusal);
                        let head_moved = (reply.1).0.pointer("/error/code").and_then(Value::as_str)
                            == Some("event_stream_expected_head_conflict");
                        if !head_moved {
                            return Err(reply);
                        }
                    }
                }
            }
            let Some(commit) = committed else {
                return Err(bad(
                    StatusCode::CONFLICT,
                    "telemetry_point_head_contended",
                    "the series' head moved on every attempt; produce the point again",
                ));
            };
            (
                json!(commit.operation_ref),
                json!(commit.receipt_ref),
                commit.replayed,
            )
        }
        "ephemeral" => {
            match event_stream_routes::append_event(
                st,
                identity,
                NAMESPACE,
                &tail,
                EPHEMERAL_CLASS,
                point,
                None,
                "",
                0,
            )
            .map_err(refused_reply)?
            {
                Appended::Ephemeral { .. } => window_push(&series_tail, point.clone()),
                Appended::Admitted { .. } => {
                    return Err(bad(
                        StatusCode::CONFLICT,
                        "telemetry_point_class_mismatch",
                        "the stream's declaration admitted an ephemeral sample",
                    ))
                }
            }
            (Value::Null, Value::Null, false)
        }
        other => {
            return Err(bad(
                StatusCode::UNPROCESSABLE_ENTITY,
                "telemetry_point_class_invalid",
                format!("point_class '{other}' is neither admitted nor ephemeral"),
            ))
        }
    };
    // The listing's projection of the newest point; the range read is the truth.
    if let Some(mut record) = load_series(&st.data_dir, &series_tail) {
        let newer = record
            .pointer("/latest_point/time_unix_ms")
            .and_then(Value::as_u64)
            .is_none_or(|at| at <= time_ms);
        if newer {
            record["latest_point"] = json!({
                "point_class": point["point_class"],
                "time_unix_ms": time_ms,
                "value": point["value"],
            });
            if validate(SERIES_CONTRACT, "telemetry series", &record).is_ok() {
                let _ = persist(&st.data_dir, &series_tail, &record);
            }
        }
    }
    Ok(json!({
        "series_ref": series["series_id"],
        "metric": series.pointer("/metric/name").cloned().unwrap_or(Value::Null),
        "point_class": point["point_class"],
        "time_unix_ms": time_ms,
        "value": point["value"],
        "source_ref": point["source_ref"],
        "operation_ref": operation_ref,
        "receipt_ref": receipt_ref,
        "replayed": replayed,
    }))
}

/// The System a health check's target serves: the target itself when it is a System, the System an
/// automation is tied to when it is an automation, otherwise none.
fn scope_of_target(st: &DaemonState, target_ref: &str) -> Option<String> {
    if target_ref.starts_with("system://") {
        return Some(target_ref.to_string());
    }
    let automation = target_ref.strip_prefix("automation://")?;
    read_record_dir(&st.data_dir, "automations")
        .into_iter()
        .find(|a| text(a, "id") == automation || text(a, "automation_id") == automation)
        .and_then(|a| a.get("system_ref").and_then(Value::as_str).map(str::to_string))
        .filter(|s| s.starts_with("system://"))
}

fn point(
    series: &Value,
    class: &str,
    time_ms: u64,
    value: f64,
    outcome: &str,
    source_ref: &str,
    run_ref: Option<&str>,
) -> Value {
    json!({
        "schema_version": POINT_SCHEMA,
        "series_ref": series["series_id"],
        "point_class": class,
        "time_unix_ms": time_ms,
        "observed_at": stamp(time_ms),
        "value": value,
        "attributes": [{ "key": HEALTH_OUTCOME_ATTRIBUTE, "value": outcome }],
        "source_ref": source_ref,
        "run_ref": run_ref,
    })
}

/// THE HEALTH PRODUCER. One evaluation of one check produces one admitted `ioi.health_check.passed`
/// point (1 when it passed, 0 when it did not; the outcome word as an attribute) about the CHECK,
/// scoped to the System the check observes; and, when a probe ran, one ephemeral
/// `ioi.health_check.duration` sample. The result is already admitted when this runs, so a refusal
/// here never undoes it: it is returned by name beside the result.
pub(crate) fn record_health_evaluation(
    st: &DaemonState,
    caller: &WriteCaller,
    result: &Value,
    probe_seconds: Option<f64>,
) -> Value {
    let subject = text(result, "health_check_ref");
    let result_ref = text(result, "result_id");
    let outcome = text(result, "outcome");
    let scope = scope_of_target(st, text(result, "target_ref"));
    let time_ms = parse_ms(text(result, "observed_at")).unwrap_or_else(now_ms);
    let run_ref = result
        .get("evidence_refs")
        .and_then(Value::as_array)
        .and_then(|refs| {
            refs.iter()
                .filter_map(Value::as_str)
                .find(|r| r.starts_with("automation-run://"))
        })
        .map(str::to_string);
    let mut produced = Vec::new();
    let mut refusals = Vec::new();
    let mut produce = |metric: &str, class: &str, value: f64| {
        let spec = SeriesSpec {
            subject_ref: subject,
            scope_ref: scope.as_deref(),
            metric_name: metric,
            producer_ref: HEALTH_PRODUCER,
        };
        let outcome_of = ensure_series(st, caller, &spec).and_then(|series| {
            append_point(
                st,
                &caller.identity,
                &series,
                &point(&series, class, time_ms, value, outcome, result_ref, run_ref.as_deref()),
            )
        });
        match outcome_of {
            Ok(summary) => produced.push(summary),
            Err((status, Json(body))) => {
                eprintln!("[telemetry] {metric} point for {result_ref} refused ({status}): {body}");
                refusals.push(json!({ "metric": metric, "status": status.as_u16(), "error": body.get("error").cloned().unwrap_or(Value::Null) }));
            }
        }
    };
    produce(
        HEALTH_PASSED,
        "admitted",
        if outcome == "passed" { 1.0 } else { 0.0 },
    );
    if let Some(seconds) = probe_seconds {
        produce(HEALTH_DURATION, "ephemeral", (seconds * 1000.0).round() / 1000.0);
    }
    json!({ "points": produced, "refusals": refusals })
}

// ---- Reading ------------------------------------------------------------------------------------

fn visible(identity: &RequestIdentity, record: &Value) -> bool {
    record
        .get("owner_ref")
        .and_then(Value::as_str)
        .is_some_and(|owner| identity.authorizes_tenant(owner))
}

/// THE PUBLISHED READER: the series the caller's tenants may see, newest point first — the one rule
/// this plane applies to a read, applied before any consumer (Operations / Telemetry, a System's
/// Overview) sees a record.
pub(crate) fn series_for_request(
    st: &DaemonState,
    headers: &HeaderMap,
) -> Result<Vec<Value>, Reply> {
    let identity = substrate_store::resolve_request_identity(&st.data_dir, headers)
        .map_err(scope_refusal_reply)?;
    let mut series: Vec<Value> = read_record_dir(&st.data_dir, KIND_SERIES)
        .into_iter()
        .filter(|s| visible(&identity, s))
        .collect();
    series.sort_by(|a, b| {
        let at = |s: &Value| {
            s.pointer("/latest_point/time_unix_ms")
                .and_then(Value::as_u64)
                .unwrap_or(0)
        };
        at(b)
            .cmp(&at(a))
            .then_with(|| text(a, "series_id").cmp(text(b, "series_id")))
    });
    Ok(series)
}

/// GET /v1/hypervisor/telemetry/series[?subject_ref=&scope_ref=&about_ref=&metric=] — `about_ref`
/// matches a series whose subject OR scope is the ref (a System and everything that serves it).
pub(crate) async fn handle_series_list(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Reply {
    let series = match series_for_request(&st, &headers) {
        Ok(series) => series,
        Err(reply) => return reply,
    };
    let wants = |key: &str| query.get(key).map(String::as_str).filter(|v| !v.is_empty());
    let series: Vec<Value> = series
        .into_iter()
        .filter(|s| wants("subject_ref").is_none_or(|v| text(s, "subject_ref") == v))
        .filter(|s| wants("scope_ref").is_none_or(|v| text(s, "scope_ref") == v))
        .filter(|s| {
            wants("about_ref").is_none_or(|v| text(s, "subject_ref") == v || text(s, "scope_ref") == v)
        })
        .filter(|s| {
            wants("metric").is_none_or(|v| s.pointer("/metric/name").and_then(Value::as_str) == Some(v))
        })
        .collect();
    (StatusCode::OK, Json(json!({ "ok": true, "series": series })))
}

/// One series the caller may read, or the refusal.
fn readable_series(
    st: &DaemonState,
    headers: &HeaderMap,
    id: &str,
) -> Result<(RequestIdentity, Value), Reply> {
    let identity = substrate_store::resolve_request_identity(&st.data_dir, headers)
        .map_err(scope_refusal_reply)?;
    let tail = id.trim_start_matches("telemetry-series://");
    let Some(record) = load_series(&st.data_dir, tail) else {
        return Err(bad(
            StatusCode::NOT_FOUND,
            "telemetry_series_not_found",
            "no telemetry series exists at this id",
        ));
    };
    if !visible(&identity, &record) {
        return Err(scope_refusal_reply(RequestScopeRefusal::ResourceScopeRequired));
    }
    Ok((identity, record))
}

/// GET /v1/hypervisor/telemetry/series/:id
pub(crate) async fn handle_series_get(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Reply {
    match readable_series(&st, &headers, &id) {
        Ok((_, record)) => (
            StatusCode::OK,
            Json(json!({ "ok": true, "series_record": record })),
        ),
        Err(reply) => reply,
    }
}

/// The bounded window one range read covers.
#[derive(Debug, PartialEq)]
pub(crate) struct RangeWindow {
    pub(crate) from_ms: u64,
    pub(crate) to_ms: u64,
    pub(crate) step_s: u64,
    pub(crate) rolling: u64,
}

fn parameter(query: &HashMap<String, String>, key: &str) -> Result<Option<u64>, Reply> {
    match query.get(key).map(|v| v.trim()).filter(|v| !v.is_empty()) {
        None => Ok(None),
        Some(raw) => raw.parse::<u64>().map(Some).map_err(|_| {
            bad(
                StatusCode::BAD_REQUEST,
                "telemetry_range_parameter_invalid",
                format!("{key} is a non-negative integer"),
            )
        }),
    }
}

/// Parse and bound one range request: `from` and `to` in epoch milliseconds (to defaults to now,
/// from to a day before it), `step` in seconds (defaults to a sixtieth of the span), `window` the
/// rolling mean's point count. A request past any bound is refused by name, never clamped.
pub(crate) fn range_window(
    query: &HashMap<String, String>,
    now: u64,
) -> Result<RangeWindow, Reply> {
    let to_ms = parameter(query, "to")?.unwrap_or(now + 1);
    let from_ms = parameter(query, "from")?.unwrap_or(to_ms.saturating_sub(DEFAULT_SPAN_MS));
    if from_ms >= to_ms {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "telemetry_range_empty",
            "from must be before to",
        ));
    }
    let span = to_ms - from_ms;
    if span > MAX_SPAN_MS {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "telemetry_range_span_exceeded",
            format!("a range read covers at most {MAX_SPAN_MS} ms (31 days)"),
        ));
    }
    let step_s = match parameter(query, "step")? {
        Some(0) => {
            return Err(bad(
                StatusCode::BAD_REQUEST,
                "telemetry_range_step_invalid",
                "step is at least one second",
            ))
        }
        Some(step) => step,
        None => span.div_ceil(DEFAULT_BUCKETS * 1000).max(1),
    };
    if span.div_ceil(step_s.saturating_mul(1000)) > MAX_BUCKETS {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "telemetry_range_too_many_buckets",
            format!("a range read answers at most {MAX_BUCKETS} step buckets; widen step"),
        ));
    }
    let rolling = parameter(query, "window")?.unwrap_or(DEFAULT_ROLLING);
    if !(1..=MAX_ROLLING).contains(&rolling) {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "telemetry_range_window_invalid",
            format!("window is 1..={MAX_ROLLING} points"),
        ));
    }
    Ok(RangeWindow {
        from_ms,
        to_ms,
        step_s,
        rolling,
    })
}

/// The pure half of a range read: points in [from, to) (newest MAX_POINTS kept, oldest first), the
/// step buckets, and the rolling mean. Returns (points, points_in_window, buckets, derived points).
pub(crate) fn compute_range(
    mut points: Vec<Value>,
    window: &RangeWindow,
) -> (Vec<Value>, usize, Vec<Value>, Vec<Value>) {
    let at = |p: &Value| p.get("time_unix_ms").and_then(Value::as_u64).unwrap_or(0);
    let value = |p: &Value| p.get("value").and_then(Value::as_f64).unwrap_or(0.0);
    points.retain(|p| (window.from_ms..window.to_ms).contains(&at(p)));
    points.sort_by_key(at);
    let in_window = points.len();
    if points.len() > MAX_POINTS {
        points.drain(..points.len() - MAX_POINTS);
    }
    let step_ms = window.step_s * 1000;
    let bucket_count = (window.to_ms - window.from_ms).div_ceil(step_ms);
    let buckets = (0..bucket_count)
        .map(|b| {
            let start = window.from_ms + b * step_ms;
            let inside: Vec<f64> = points
                .iter()
                .filter(|p| (start..start + step_ms).contains(&at(p)))
                .map(value)
                .collect();
            let stat = |f: fn(f64, f64) -> f64| {
                inside
                    .iter()
                    .copied()
                    .reduce(f)
                    .map_or(Value::Null, |v| json!(v))
            };
            json!({
                "start_unix_ms": start,
                "count": inside.len(),
                "mean": if inside.is_empty() { Value::Null } else { json!(inside.iter().sum::<f64>() / inside.len() as f64) },
                "min": stat(f64::min),
                "max": stat(f64::max),
            })
        })
        .collect();
    let rolling = window.rolling as usize;
    let derived = points
        .iter()
        .enumerate()
        .map(|(i, p)| {
            let from = i.saturating_sub(rolling - 1);
            let span = &points[from..=i];
            json!({
                "time_unix_ms": at(p),
                "value": span.iter().map(value).sum::<f64>() / span.len() as f64,
            })
        })
        .collect();
    (points, in_window, buckets, derived)
}

fn range_point(point: &Value, operation_ref: Value, receipt_ref: Value) -> Value {
    json!({
        "point_class": point["point_class"],
        "time_unix_ms": point["time_unix_ms"],
        "observed_at": point["observed_at"],
        "value": point["value"],
        "attributes": point.get("attributes").cloned().unwrap_or(json!([])),
        "source_ref": point["source_ref"],
        "run_ref": point["run_ref"],
        "operation_ref": operation_ref,
        "receipt_ref": receipt_ref,
    })
}

/// GET /v1/hypervisor/telemetry/series/:id/range[?from=&to=&step=&window=] — the bounded range
/// read: admitted points replayed from the series' stream (each with its operation and receipt),
/// ephemeral samples from the in-process window, step buckets, and one derived series — the
/// rolling mean — with its derivation named. Nothing is stored; asking again recomputes it.
pub(crate) async fn handle_series_range(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Query(query): Query<HashMap<String, String>>,
) -> Reply {
    let (identity, record) = match readable_series(&st, &headers, &id) {
        Ok(found) => found,
        Err(reply) => return reply,
    };
    let window = match range_window(&query, now_ms()) {
        Ok(window) => window,
        Err(reply) => return reply,
    };
    let series_tail = text(&record, "series_id")
        .trim_start_matches("telemetry-series://")
        .to_string();
    let tail = stream_tail(&series_tail);
    // The stream's ADMITTED scope must name the series' owner tenant too: the record file is a
    // projection, and a read is authorized against admitted truth, not against the projection alone.
    let stream_ref = event_stream_routes::event_stream_ref(NAMESPACE, &tail);
    match substrate_store::read_request_scope(
        &st.data_dir,
        event_stream_routes::EVENT_STREAM_SCOPE_KIND,
        &stream_ref,
    ) {
        Ok(Some(scope))
            if scope.owner_ref == text(&record, "owner_ref")
                && scope.tenant_ref == scope.owner_ref
                && identity.authorizes_tenant(&scope.tenant_ref) => {}
        Ok(Some(_)) => {
            return scope_refusal_reply(RequestScopeRefusal::ResourceOwnerMismatch);
        }
        Ok(None) => {
            return bad(
                StatusCode::CONFLICT,
                "telemetry_series_stream_absent",
                "the series names a stream that holds no admitted declaration",
            )
        }
        Err(error) => return scope_refusal_reply(error),
    }
    let history = match substrate_store::read_event_stream_history(&st.data_dir, NAMESPACE, &tail) {
        Ok(history) => history,
        Err(error) => {
            return bad(
                StatusCode::BAD_GATEWAY,
                error.code(),
                format!("the series' stream could not be replayed: {error}"),
            )
        }
    };
    let mut points: Vec<Value> = history
        .iter()
        .filter(|p| p.operation.op_kind == event_stream_routes::APPEND_OP_KIND)
        .filter(|p| text(&p.operation.payload, "class_id") == ADMITTED_CLASS)
        .map(|p| {
            range_point(
                &p.operation.payload["payload"],
                json!(agentgres::refs::event_stream_operation_ref(
                    NAMESPACE, &tail, p.seq, &p.head
                )),
                json!(agentgres::refs::event_stream_receipt_ref(
                    NAMESPACE,
                    &tail,
                    p.admission_batch_seq,
                    &p.admission_root
                )),
            )
        })
        .collect();
    let held = window_read(&series_tail);
    points.extend(
        held.iter()
            .map(|p| range_point(p, Value::Null, Value::Null)),
    );
    let (points, in_window, buckets, derived) = compute_range(points, &window);
    let range = json!({
        "schema_version": RANGE_SCHEMA,
        "series_ref": record["series_id"],
        "subject_ref": record["subject_ref"],
        "scope_ref": record["scope_ref"],
        "metric": {
            "name": record.pointer("/metric/name").cloned().unwrap_or(Value::Null),
            "unit": record.pointer("/metric/unit").cloned().unwrap_or(Value::Null),
            "instrument": record.pointer("/metric/instrument").cloned().unwrap_or(Value::Null),
        },
        "window": { "from_unix_ms": window.from_ms, "to_unix_ms": window.to_ms, "step_seconds": window.step_s },
        "bounds": { "max_span_ms": MAX_SPAN_MS, "max_buckets": MAX_BUCKETS, "max_points": MAX_POINTS },
        "points_truncated": in_window > points.len(),
        "points_in_window": in_window,
        "points": points,
        "buckets": buckets,
        "derived": {
            "derivation": "rolling_mean",
            "window_points": window.rolling,
            "basis": "raw_points",
            "formula": format!("at each raw point i (oldest first), the mean of value over points max(0, i-{})..=i", window.rolling - 1),
            "points": derived,
        },
        "ephemeral_window": { "retention": "process_memory", "window_points": WINDOW_POINTS, "held_points": held.len() },
        "read_at": super::iso_now(),
    });
    if let Err(reply) = validate(RANGE_CONTRACT, "range answer", &range) {
        return reply;
    }
    (StatusCode::OK, Json(json!({ "ok": true, "range": range })))
}

#[cfg(test)]
mod telemetry_tests {
    use super::*;

    fn q(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    // THE CONFORMANCE TEST for the adopted OpenTelemetry profile: every name follows OpenTelemetry's
    // metric naming; every OpenTelemetry entry carries the unit and instrument its convention
    // defines; every name outside OpenTelemetry is in the `ioi.` namespace and cites canon; every
    // `.duration` is seconds recorded by a histogram.
    #[test]
    fn the_profile_follows_opentelemetry_naming_units_and_instruments() {
        for c in CONVENTIONS {
            assert!(otel_metric_name(c.name), "{} is not an OpenTelemetry metric name", c.name);
            assert!(
                ["gauge", "counter", "updowncounter", "histogram"].contains(&c.instrument),
                "{} names an instrument OpenTelemetry does not define",
                c.name
            );
            match c.registry {
                "opentelemetry" => {
                    assert!(c.reference.starts_with("https://opentelemetry.io/docs/specs/semconv/"));
                    assert!(["stable", "development"].contains(&c.stability));
                }
                "ioi" => {
                    assert!(c.name.starts_with("ioi."), "{} is outside the ioi namespace", c.name);
                    assert_eq!(c.stability, "ioi_extension");
                    assert!(c.reference.starts_with("canon://docs/architecture/"));
                }
                other => panic!("{} names registry {other}", c.name),
            }
            if c.name.ends_with(".duration") {
                assert_eq!((c.unit, c.instrument), ("s", "histogram"), "{}", c.name);
            }
        }
        let token = convention("gen_ai.client.token.usage").expect("GenAI token usage is adopted");
        assert_eq!((token.unit, token.instrument), ("{token}", "histogram"));
        assert!(convention("ioi.made.up").is_none());
        assert!(otel_attribute_key(HEALTH_OUTCOME_ATTRIBUTE));
        assert!(otel_attribute_key("gen_ai.token.type"));
        assert!(!otel_metric_name("Health.Passed"));
        assert!(!otel_metric_name("passed"));
        assert!(!otel_attribute_key("ioi.health check"));
    }

    #[test]
    fn the_producing_principal_is_part_of_a_series_identity() {
        let a = identity_digest("org://acme", "user://ada", "health-check://hc_1", Some("system://acme/lending"), HEALTH_PASSED, "1");
        let again = identity_digest("org://acme", "user://ada", "health-check://hc_1", Some("system://acme/lending"), HEALTH_PASSED, "1");
        let other_principal = identity_digest("org://acme", "user://bo", "health-check://hc_1", Some("system://acme/lending"), HEALTH_PASSED, "1");
        let other_unit = identity_digest("org://acme", "user://ada", "health-check://hc_1", Some("system://acme/lending"), HEALTH_PASSED, "s");
        assert_eq!(a, again);
        assert_ne!(a, other_principal);
        assert_ne!(a, other_unit);
        let tail = series_tail_of(&a);
        assert!(valid_series_tail(&tail), "{tail}");
        assert!(!valid_series_tail("ts_../../etc/pas"));
        assert!(!valid_series_tail("ts_0123456789ABCDEF"));
    }

    #[test]
    fn a_range_request_past_any_bound_is_refused_by_name() {
        let now = 10 * 24 * 3600 * 1000;
        let w = range_window(&q(&[]), now).expect("defaults");
        assert_eq!((w.to_ms - w.from_ms, w.rolling), (DEFAULT_SPAN_MS, DEFAULT_ROLLING));
        assert!(w.step_s >= 1);
        let code = |pairs: &[(&str, &str)]| {
            range_window(&q(pairs), now)
                .err()
                .and_then(|(_, Json(b))| b.pointer("/error/code").and_then(Value::as_str).map(str::to_string))
        };
        assert_eq!(code(&[("from", "5"), ("to", "5")]).as_deref(), Some("telemetry_range_empty"));
        assert_eq!(code(&[("from", "0"), ("to", "9999999999999")]).as_deref(), Some("telemetry_range_span_exceeded"));
        assert_eq!(code(&[("from", "0"), ("to", "86400000"), ("step", "0")]).as_deref(), Some("telemetry_range_step_invalid"));
        assert_eq!(code(&[("from", "0"), ("to", "86400000"), ("step", "1")]).as_deref(), Some("telemetry_range_too_many_buckets"));
        assert_eq!(code(&[("window", "0")]).as_deref(), Some("telemetry_range_window_invalid"));
        assert_eq!(code(&[("to", "soon")]).as_deref(), Some("telemetry_range_parameter_invalid"));
    }

    #[test]
    fn a_range_buckets_its_points_and_names_one_rolling_mean() {
        let p = |t: u64, v: f64| json!({ "time_unix_ms": t, "value": v });
        let window = RangeWindow { from_ms: 0, to_ms: 3000, step_s: 1, rolling: 2 };
        let (points, in_window, buckets, derived) =
            compute_range(vec![p(2500, 1.0), p(100, 0.0), p(900, 1.0), p(3000, 9.0)], &window);
        assert_eq!(in_window, 3, "the point at `to` is outside [from, to)");
        assert_eq!(points.iter().map(|x| x["time_unix_ms"].as_u64().unwrap()).collect::<Vec<_>>(), vec![100, 900, 2500]);
        assert_eq!(buckets.len(), 3);
        assert_eq!((buckets[0]["count"].as_u64(), buckets[0]["mean"].as_f64()), (Some(2), Some(0.5)));
        assert_eq!((buckets[1]["count"].as_u64(), buckets[1]["mean"].clone()), (Some(0), Value::Null));
        assert_eq!(derived.iter().map(|x| x["value"].as_f64().unwrap()).collect::<Vec<_>>(), vec![0.0, 0.5, 1.0]);
    }

    #[test]
    fn a_range_keeps_the_newest_points_when_the_window_holds_too_many() {
        let window = RangeWindow { from_ms: 0, to_ms: 2_000_000, step_s: 3600, rolling: 1 };
        let many: Vec<Value> = (0..(MAX_POINTS as u64 + 5)).map(|t| json!({ "time_unix_ms": t, "value": 1.0 })).collect();
        let (points, in_window, _, _) = compute_range(many, &window);
        assert_eq!((points.len(), in_window), (MAX_POINTS, MAX_POINTS + 5));
        assert_eq!(points[0]["time_unix_ms"].as_u64(), Some(5));
    }

    #[test]
    fn the_series_declares_both_sides_of_the_event_class_line() {
        let declaration = class_declaration();
        assert_eq!(declaration["admitted_truth_classes"][0]["class_id"], ADMITTED_CLASS);
        assert_eq!(declaration["ephemeral_delivery_classes"][0]["class_id"], EPHEMERAL_CLASS);
        let fixture = json!({
            "schema_version": POINT_SCHEMA, "series_ref": "telemetry-series://ts_0123456789abcdef", "point_class": "admitted",
            "time_unix_ms": 1_790_676_300_000u64, "observed_at": stamp(1_790_676_300_000), "value": 1.0,
            "attributes": [{ "key": HEALTH_OUTCOME_ATTRIBUTE, "value": "passed" }],
            "source_ref": "observation://health-check/hc_0123456789abcdef/hcr_fedcba9876543210", "run_ref": null,
        });
        validate(POINT_CONTRACT, "point", &fixture).expect("a produced point satisfies its contract");
        assert_eq!(parse_ms(&stamp(1_790_676_300_123)), Some(1_790_676_300_123));
    }
}
