//! Operations health checks (ADR 0056 Amendment 1, plane 2) — `HealthCheck` and
//! `HealthCheckResult` (docs/architecture/components/daemon-runtime/platform-operability.md
//! §HealthCheck, §HealthCheckResult).
//!
//! A health check is a declaration of WHAT TO OBSERVE about one target; a result is one admitted
//! evaluation of it. Neither grants anything or becomes authority. A `command_exit` probe runs
//! through the governed exec primitive in the target's own environment and inherits every exec
//! guardrail and isolation refusal; an exec answer with no exit code is `errored` (the probe could
//! not be evaluated), never a pass. An `automation_run_outcome` check reads the latest execution of
//! an `automation://` target. A qualifying outcome files a SupportIncidentLink through that plane's
//! own admission (`operations_support_routes::file_incident`), and the result carries its ref.
//!
//! Every write is identity-first and owner-scoped through the shared mutation foundation: a
//! declaration and each evaluation are Agentgres admissions with receipts, a change compare-and-
//! swaps the check's admitted head, and a replayed idempotency key returns the original record.

use std::sync::Arc;

use axum::extract::{Path as AxumPath, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde_json::{json, Value};

use super::mutation_event_foundation::{
    admit_owner_scoped_write, replay_stable_id, require_write_caller, scope_refusal_reply,
    MutationCommit, WriteCaller,
};
use super::{persist_record, read_record_dir, DaemonState};

const NAMESPACE: &str = "hypervisor-health-checks";
const KIND_CHECK: &str = "health-checks";
const KIND_RESULT: &str = "health-check-results";
const CHECK_SCHEMA: &str = "ioi.hypervisor.health_check.v1";
const RESULT_SCHEMA: &str = "ioi.hypervisor.health_check_result.v1";
const CHECK_CONTRACT: &str = "schema://ioi/components/daemon-runtime/health-check/v1";
const RESULT_CONTRACT: &str = "schema://ioi/components/daemon-runtime/health-check-result/v1";
const CHECK_KINDS: &[&str] = &["command_exit", "automation_run_outcome"];
const SEVERITIES: &[&str] = &["informational", "minor", "major", "critical"];
const FILE_ON: &[&str] = &["never", "failed", "failed_or_errored"];
const ENABLEMENTS: &[&str] = &["enabled", "paused", "archived"];
const TARGET_SCHEMES: &[&str] = &[
    "system://",
    "environment://",
    "automation://",
    "surface-serving://",
];

type Reply = (StatusCode, Json<Value>);

fn bad(status: StatusCode, code: &str, message: impl Into<String>) -> Reply {
    (
        status,
        Json(json!({ "ok": false, "error": { "code": code, "message": message.into() } })),
    )
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
            std::path::Path::new(data_dir)
                .join(kind)
                .join(format!("{}.json", safe(id))),
        )
        .ok()?,
    )
    .ok()
}

fn text<'a>(body: &'a Value, key: &str) -> &'a str {
    body.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or("")
}

fn single_ref(value: &str, schemes: &[&str]) -> bool {
    schemes
        .iter()
        .any(|scheme| value.starts_with(scheme) && value.len() > scheme.len())
        && value.len() <= 500
        && !value.chars().any(char::is_whitespace)
}

fn validate(contract: &str, what: &str, record: &Value) -> Result<(), Reply> {
    ioi_types::app::generated::architecture_contracts::validate_architecture_contract(
        contract, record,
    )
    .map_err(|error| {
        bad(
            StatusCode::UNPROCESSABLE_ENTITY,
            "health_check_contract_invalid",
            format!("the {what} would not satisfy its registered contract: {error}"),
        )
    })
}

fn project(record: &mut Value, commit: &MutationCommit) {
    record["admitted_head"] = json!(commit.projection.head);
    record["updated_at"] = json!(super::iso_now());
}

fn persist(data_dir: &str, kind: &str, id: &str, record: &Value) -> Result<(), Reply> {
    persist_record(data_dir, kind, id, record).map_err(|_| {
        bad(
            StatusCode::INTERNAL_SERVER_ERROR,
            "health_check_persistence_failed",
            "the write is admitted but its projection could not be written; replay to reconcile",
        )
    })
}

/// The declaration's own fields, validated; `Err` names the first one that is wrong.
fn declared_fields(
    body: &Value,
) -> Result<(String, String, String, Value, String, String, String), Reply> {
    let display_name = text(body, "display_name").to_string();
    if display_name.is_empty() || display_name.chars().count() > 160 {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "health_check_display_name_required",
            "display_name is required and is 1..160 characters",
        ));
    }
    let target_ref = text(body, "target_ref").to_string();
    if !single_ref(&target_ref, TARGET_SCHEMES) {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "health_check_target_invalid",
            format!("target_ref names one target: {TARGET_SCHEMES:?}"),
        ));
    }
    let check_kind = text(body, "check_kind").to_string();
    if !CHECK_KINDS.contains(&check_kind.as_str()) {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "health_check_kind_invalid",
            format!("check_kind must be one of {CHECK_KINDS:?}"),
        ));
    }
    let probe = match check_kind.as_str() {
        "command_exit" => {
            let probe = body.get("probe").cloned().unwrap_or(Value::Null);
            let environment_ref = text(&probe, "environment_ref").to_string();
            let command = text(&probe, "command").to_string();
            if !single_ref(&environment_ref, &["environment://"])
                || command.is_empty()
                || command.chars().count() > 2000
            {
                return Err(bad(
                    StatusCode::BAD_REQUEST,
                    "health_check_probe_invalid",
                    "a command_exit check names the environment it probes (environment://…) and a command of 1..2000 characters",
                ));
            }
            json!({ "environment_ref": environment_ref, "command": command })
        }
        _ => {
            if !target_ref.starts_with("automation://") {
                return Err(bad(
                    StatusCode::BAD_REQUEST,
                    "health_check_target_invalid",
                    "an automation_run_outcome check observes an automation:// target",
                ));
            }
            Value::Null
        }
    };
    let severity = text(body, "severity").to_string();
    if !SEVERITIES.contains(&severity.as_str()) {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "health_check_severity_invalid",
            format!("severity must be one of {SEVERITIES:?}"),
        ));
    }
    let file_on = body
        .pointer("/incident_policy/file_on")
        .and_then(Value::as_str)
        .or_else(|| body.get("file_on").and_then(Value::as_str))
        .unwrap_or("never")
        .to_string();
    if !FILE_ON.contains(&file_on.as_str()) {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "health_check_incident_policy_invalid",
            format!("incident_policy.file_on must be one of {FILE_ON:?}"),
        ));
    }
    let enablement = match text(body, "enablement") {
        "" => "enabled".to_string(),
        value => value.to_string(),
    };
    if !ENABLEMENTS.contains(&enablement.as_str()) {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "health_check_enablement_invalid",
            format!("enablement must be one of {ENABLEMENTS:?}"),
        ));
    }
    Ok((
        display_name,
        target_ref,
        check_kind,
        probe,
        severity,
        file_on,
        enablement,
    ))
}

/// POST /v1/hypervisor/health-checks — declare what to observe about one target.
pub(crate) async fn handle_health_check_create(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Reply {
    let caller: WriteCaller = match require_write_caller(&st.data_dir, &headers, &body) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    let (display_name, target_ref, check_kind, probe, severity, file_on, enablement) =
        match declared_fields(&body) {
            Ok(fields) => fields,
            Err(response) => return response,
        };
    // ADR 0056 P5 — declaring a check passes the justification checkpoints that apply to it (the
    // item is the check's target).
    let justification_record_refs = match super::justification_checkpoint_routes::checkpoint_gate(
        &st,
        &headers,
        "health_check.declare",
        std::slice::from_ref(&target_ref),
        &body,
    ) {
        Ok(refs) => refs,
        Err(prompt) => return prompt,
    };
    let id = replay_stable_id("hc", &caller.owner_ref, &caller.idempotency_key);
    let check_ref = format!("health-check://{id}");
    let now = super::iso_now();
    let mut record = json!({
        "schema_version": CHECK_SCHEMA,
        "health_check_id": check_ref,
        "display_name": display_name,
        "target_ref": target_ref,
        "check_kind": check_kind,
        "probe": probe,
        "severity": severity,
        "incident_policy": { "file_on": file_on },
        "enablement": enablement,
        "owner_ref": caller.owner_ref,
        "created_by_principal_ref": caller.identity.principal_ref,
        "created_at": now,
        "updated_at": now,
        "admitted_head": Value::Null,
    });
    if let Err(response) = validate(CHECK_CONTRACT, "health check", &record) {
        return response;
    }
    let commit = match admit_owner_scoped_write(
        &st.data_dir,
        &caller,
        NAMESPACE,
        KIND_CHECK,
        &check_ref,
        "health_check.declare",
        None,
        &json!({ "health_check_id": check_ref, "target_ref": record["target_ref"], "check_kind": record["check_kind"], "probe": record["probe"], "severity": record["severity"], "incident_policy": record["incident_policy"], "enablement": record["enablement"] }),
    ) {
        Ok(commit) => commit,
        Err(response) => return response,
    };
    if commit.replayed {
        if let Some(existing) = load(&st.data_dir, KIND_CHECK, &id) {
            return (
                StatusCode::OK,
                Json(
                    json!({ "ok": true, "replayed": true, "health_check": existing, "receipt_ref": commit.receipt_ref }),
                ),
            );
        }
    }
    project(&mut record, &commit);
    if let Err(response) = persist(&st.data_dir, KIND_CHECK, &id, &record) {
        return response;
    }
    (
        StatusCode::CREATED,
        Json(
            json!({ "ok": true, "replayed": false, "health_check": record, "receipt_ref": commit.receipt_ref, "justification_record_refs": justification_record_refs }),
        ),
    )
}

/// POST /v1/hypervisor/health-checks/:id/enablement {enablement} — pause, resume or archive.
pub(crate) async fn handle_health_check_enablement(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> Reply {
    let caller: WriteCaller = match require_write_caller(&st.data_dir, &headers, &body) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    let to = text(&body, "enablement");
    if !ENABLEMENTS.contains(&to) {
        return bad(
            StatusCode::BAD_REQUEST,
            "health_check_enablement_invalid",
            format!("enablement must be one of {ENABLEMENTS:?}"),
        );
    }
    let Some(record) = load(&st.data_dir, KIND_CHECK, &id) else {
        return bad(
            StatusCode::NOT_FOUND,
            "health_check_not_found",
            "no health check exists at this id",
        );
    };
    if record["owner_ref"].as_str() != Some(caller.owner_ref.as_str()) {
        return scope_refusal_reply(
            super::substrate_store::RequestScopeRefusal::ResourceOwnerMismatch,
        );
    }
    if record["enablement"].as_str() == Some(to) {
        return (
            StatusCode::OK,
            Json(json!({ "ok": true, "replayed": true, "health_check": record })),
        );
    }
    let Some(expected_head) = record["admitted_head"].as_str().map(str::to_owned) else {
        return bad(
            StatusCode::CONFLICT,
            "health_check_expected_head_required",
            "this check carries no admitted head; it cannot be changed without one",
        );
    };
    let check_ref = format!("health-check://{id}");
    let commit = match admit_owner_scoped_write(
        &st.data_dir,
        &caller,
        NAMESPACE,
        KIND_CHECK,
        &check_ref,
        "health_check.enablement",
        Some(&expected_head),
        &json!({ "health_check_id": check_ref, "enablement": to }),
    ) {
        Ok(commit) => commit,
        Err(response) => return response,
    };
    let mut successor = record;
    successor["enablement"] = json!(to);
    project(&mut successor, &commit);
    if let Err(response) = validate(CHECK_CONTRACT, "health check", &successor) {
        return response;
    }
    if let Err(response) = persist(&st.data_dir, KIND_CHECK, &id, &successor) {
        return response;
    }
    (
        StatusCode::OK,
        Json(
            json!({ "ok": true, "replayed": commit.replayed, "health_check": successor, "receipt_ref": commit.receipt_ref }),
        ),
    )
}

/// One probe's outcome: (outcome, exit_code, redacted summary, evidence refs).
type Observation = (&'static str, Option<i64>, String, Vec<String>);

/// A `command_exit` answer from the exec route, classified. Stdout is NOT copied into the result
/// (it may carry anything); the summary names the exit code and how much output there was.
pub(crate) fn classify_exec_answer(environment_ref: &str, answer: &Value) -> Observation {
    let evidence = vec![environment_ref.to_string()];
    match answer.get("exit_code").and_then(Value::as_i64) {
        Some(0) => ("passed", Some(0), "probe exited 0".to_string(), evidence),
        Some(code) => {
            let bytes = answer
                .get("stdout")
                .and_then(Value::as_str)
                .map_or(0, str::len);
            (
                "failed",
                Some(code),
                format!("probe exited {code} ({bytes} bytes of output, not retained)"),
                evidence,
            )
        }
        None => {
            let why = answer
                .pointer("/error/message")
                .or_else(|| answer.get("message"))
                .or_else(|| answer.get("error"))
                .and_then(Value::as_str)
                .unwrap_or("the exec route answered without an exit code");
            (
                "errored",
                None,
                format!(
                    "the probe could not be evaluated: {}",
                    why.chars().take(400).collect::<String>()
                ),
                evidence,
            )
        }
    }
}

/// An `automation_run_outcome` observation over the automation's latest execution.
pub(crate) fn classify_latest_execution(executions: &[Value]) -> Observation {
    let Some(latest) = executions
        .iter()
        .max_by(|a, b| text(a, "started_at").cmp(text(b, "started_at")))
    else {
        return (
            "not_computable",
            None,
            "the automation has no execution yet".to_string(),
            vec![],
        );
    };
    let exec_id = text(latest, "execution_id");
    let mut evidence = vec![format!("automation-execution://{exec_id}")];
    if let Some(run_ref) = latest.get("automation_run_ref").and_then(Value::as_str) {
        evidence.push(run_ref.to_string());
    }
    let (outcome, summary) = match text(latest, "status") {
        "done" => (
            "passed",
            format!("latest execution {exec_id} finished done"),
        ),
        "failed" => ("failed", format!("latest execution {exec_id} failed")),
        "stopped" => ("warning", format!("latest execution {exec_id} was stopped")),
        "running" => (
            "not_computable",
            format!("latest execution {exec_id} is still running"),
        ),
        other => (
            "not_computable",
            format!("latest execution {exec_id} reads '{other}'"),
        ),
    };
    (outcome, None, summary, evidence)
}

fn files_incident(file_on: &str, outcome: &str) -> bool {
    matches!(
        (file_on, outcome),
        ("failed", "failed") | ("failed_or_errored", "failed" | "errored")
    )
}

/// POST /v1/hypervisor/health-checks/:id/evaluate — evaluate the check now, admit the result, and
/// file an incident when the check's policy says so.
pub(crate) async fn handle_health_check_evaluate(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> Reply {
    let caller: WriteCaller = match require_write_caller(&st.data_dir, &headers, &body) {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    let Some(check) = load(&st.data_dir, KIND_CHECK, &id) else {
        return bad(
            StatusCode::NOT_FOUND,
            "health_check_not_found",
            "no health check exists at this id",
        );
    };
    if check["owner_ref"].as_str() != Some(caller.owner_ref.as_str()) {
        return scope_refusal_reply(
            super::substrate_store::RequestScopeRefusal::ResourceOwnerMismatch,
        );
    }
    if check["enablement"].as_str() != Some("enabled") {
        return bad(
            StatusCode::CONFLICT,
            "health_check_not_enabled",
            format!(
                "this check is {}; resume it to evaluate it",
                check["enablement"].as_str().unwrap_or("not enabled")
            ),
        );
    }
    let result_tail = replay_stable_id("hcr", &caller.owner_ref, &caller.idempotency_key);
    let result_ref = format!("observation://health-check/{id}/{result_tail}");
    if let Some(existing) = load(&st.data_dir, KIND_RESULT, &format!("{id}--{result_tail}")) {
        return (
            StatusCode::OK,
            Json(json!({ "ok": true, "replayed": true, "health_check_result": existing })),
        );
    }
    let target_ref = text(&check, "target_ref").to_string();
    let (outcome, exit_code, summary, evidence) = match text(&check, "check_kind") {
        "command_exit" => {
            let environment_ref = text(&check["probe"], "environment_ref").to_string();
            let environment_id = environment_ref
                .trim_start_matches("environment://")
                .to_string();
            let command = text(&check["probe"], "command").to_string();
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
            classify_exec_answer(&environment_ref, &answer)
        }
        _ => {
            let automation_id = target_ref.trim_start_matches("automation://").to_string();
            let executions: Vec<Value> = read_record_dir(&st.data_dir, "automation-executions")
                .into_iter()
                .filter(|execution| text(execution, "automation_id") == automation_id)
                .collect();
            classify_latest_execution(&executions)
        }
    };
    let file_on = check
        .pointer("/incident_policy/file_on")
        .and_then(Value::as_str)
        .unwrap_or("never");
    let mut support_incident_ref = Value::Null;
    if files_incident(file_on, outcome) {
        let filed = super::operations_support_routes::file_incident(
            &st.data_dir,
            &WriteCaller {
                identity: caller.identity.clone(),
                owner_ref: caller.owner_ref.clone(),
                idempotency_key: format!("health-check-incident:{result_tail}"),
            },
            &caller.identity.principal_ref,
            &json!({
                "severity": check["severity"],
                "title": format!("Health check {outcome}: {}", text(&check, "display_name")),
                "affected_object_refs": [target_ref, format!("health-check://{id}")],
                "redacted_diagnostics": summary,
                "product": "hypervisor",
            }),
        );
        match filed {
            (status, Json(reply)) if status.is_success() => {
                support_incident_ref = reply
                    .pointer("/incident/incident_id")
                    .cloned()
                    .unwrap_or(Value::Null);
            }
            (status, Json(reply)) => {
                return bad(
                    status,
                    "health_check_incident_refused",
                    format!("the check {outcome}, and its incident was refused: {reply}"),
                );
            }
        }
    }
    let mut record = json!({
        "schema_version": RESULT_SCHEMA,
        "result_id": result_ref,
        "health_check_ref": format!("health-check://{id}"),
        "health_check_head": check.get("admitted_head").cloned().unwrap_or(Value::Null),
        "target_ref": target_ref,
        "outcome": outcome,
        "observed_at": super::iso_now(),
        "exit_code": exit_code,
        "redacted_summary": summary,
        "evidence_refs": evidence,
        "support_incident_ref": support_incident_ref,
        "evaluated_by_principal_ref": caller.identity.principal_ref,
        "owner_ref": caller.owner_ref,
        "admitted_head": Value::Null,
    });
    if let Err(response) = validate(RESULT_CONTRACT, "health check result", &record) {
        return response;
    }
    let commit = match admit_owner_scoped_write(
        &st.data_dir,
        &caller,
        NAMESPACE,
        KIND_RESULT,
        &result_ref,
        "health_check.result",
        None,
        &json!({ "result_id": result_ref, "health_check_ref": record["health_check_ref"], "health_check_head": record["health_check_head"], "outcome": outcome, "exit_code": record["exit_code"], "support_incident_ref": record["support_incident_ref"] }),
    ) {
        Ok(commit) => commit,
        Err(response) => return response,
    };
    record["admitted_head"] = json!(commit.projection.head);
    if let Err(response) = persist(
        &st.data_dir,
        KIND_RESULT,
        &format!("{id}--{result_tail}"),
        &record,
    ) {
        return response;
    }
    (
        StatusCode::CREATED,
        Json(
            json!({ "ok": true, "replayed": commit.replayed, "health_check_result": record, "receipt_ref": commit.receipt_ref }),
        ),
    )
}

/// THE PUBLISHED READERS. The checks and results the caller's tenants may see, newest first — the
/// one rule this plane applies to a read, applied before any consumer (Operations / Health, the
/// System workspace, the inbox) sees a record.
pub(crate) fn health_checks_for_request(
    st: &DaemonState,
    headers: &HeaderMap,
) -> Result<Vec<Value>, Reply> {
    let identity = super::substrate_store::resolve_request_identity(&st.data_dir, headers)
        .map_err(scope_refusal_reply)?;
    let mut checks: Vec<Value> = read_record_dir(&st.data_dir, KIND_CHECK)
        .into_iter()
        .filter(|check| {
            check["owner_ref"]
                .as_str()
                .is_some_and(|owner| identity.authorizes_tenant(owner))
        })
        .collect();
    checks.sort_by(|a, b| text(b, "updated_at").cmp(text(a, "updated_at")));
    Ok(checks)
}

pub(crate) fn health_check_results_for_request(
    st: &DaemonState,
    headers: &HeaderMap,
) -> Result<Vec<Value>, Reply> {
    let identity = super::substrate_store::resolve_request_identity(&st.data_dir, headers)
        .map_err(scope_refusal_reply)?;
    let mut results: Vec<Value> = read_record_dir(&st.data_dir, KIND_RESULT)
        .into_iter()
        .filter(|result| {
            result["owner_ref"]
                .as_str()
                .is_some_and(|owner| identity.authorizes_tenant(owner))
        })
        .collect();
    results.sort_by(|a, b| text(b, "observed_at").cmp(text(a, "observed_at")));
    Ok(results)
}

/// GET /v1/hypervisor/health-checks
pub(crate) async fn handle_health_check_list(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
) -> Reply {
    match health_checks_for_request(&st, &headers) {
        Ok(checks) => (
            StatusCode::OK,
            Json(json!({ "ok": true, "health_checks": checks })),
        ),
        Err(reply) => reply,
    }
}

/// GET /v1/hypervisor/health-checks/:id
pub(crate) async fn handle_health_check_get(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Reply {
    let identity = match super::substrate_store::resolve_request_identity(&st.data_dir, &headers) {
        Ok(identity) => identity,
        Err(error) => return scope_refusal_reply(error),
    };
    let Some(record) = load(&st.data_dir, KIND_CHECK, &id) else {
        return bad(
            StatusCode::NOT_FOUND,
            "health_check_not_found",
            "no health check exists at this id",
        );
    };
    if !record["owner_ref"]
        .as_str()
        .is_some_and(|owner| identity.authorizes_tenant(owner))
    {
        return scope_refusal_reply(
            super::substrate_store::RequestScopeRefusal::ResourceScopeRequired,
        );
    }
    (
        StatusCode::OK,
        Json(json!({ "ok": true, "health_check": record })),
    )
}

/// GET /v1/hypervisor/health-check-results[?health_check=<id>&target_ref=<ref>]
pub(crate) async fn handle_health_check_result_list(
    State(st): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Query(query): Query<std::collections::HashMap<String, String>>,
) -> Reply {
    let results = match health_check_results_for_request(&st, &headers) {
        Ok(results) => results,
        Err(reply) => return reply,
    };
    let check = query.get("health_check").map(|id| {
        format!(
            "health-check://{}",
            id.trim_start_matches("health-check://")
        )
    });
    let target = query.get("target_ref");
    let results: Vec<Value> = results
        .into_iter()
        .filter(|r| {
            check
                .as_deref()
                .is_none_or(|c| text(r, "health_check_ref") == c)
        })
        .filter(|r| target.is_none_or(|t| text(r, "target_ref") == t))
        .collect();
    (
        StatusCode::OK,
        Json(json!({ "ok": true, "health_check_results": results })),
    )
}

#[cfg(test)]
mod health_check_tests {
    use super::*;

    #[test]
    fn a_probe_that_did_not_run_is_errored_never_passed() {
        let (outcome, code, summary, evidence) = classify_exec_answer(
            "environment://env_1",
            &json!({ "error": { "message": "environment_not_running" } }),
        );
        assert_eq!((outcome, code), ("errored", None));
        assert!(summary.contains("environment_not_running"));
        assert_eq!(evidence, vec!["environment://env_1".to_string()]);
        assert_eq!(
            classify_exec_answer("environment://env_1", &json!({ "exit_code": 0 })).0,
            "passed"
        );
        let failed = classify_exec_answer(
            "environment://env_1",
            &json!({ "exit_code": 7, "stdout": "secret-token-123" }),
        );
        assert_eq!((failed.0, failed.1), ("failed", Some(7)));
        assert!(
            !failed.2.contains("secret-token-123"),
            "probe output is never copied into a result"
        );
    }

    #[test]
    fn an_automation_run_outcome_reads_the_latest_execution() {
        assert_eq!(classify_latest_execution(&[]).0, "not_computable");
        let executions = vec![
            json!({ "execution_id": "aex_1", "status": "done", "started_at": "2026-09-26T09:00:00Z" }),
            json!({ "execution_id": "aex_2", "status": "failed", "started_at": "2026-09-26T10:00:00Z", "automation_run_ref": "automation-run://autorun_2" }),
        ];
        let (outcome, _, _, evidence) = classify_latest_execution(&executions);
        assert_eq!(outcome, "failed");
        assert_eq!(
            evidence,
            vec![
                "automation-execution://aex_2".to_string(),
                "automation-run://autorun_2".to_string()
            ]
        );
    }

    #[test]
    fn only_the_policy_s_outcomes_file_an_incident() {
        assert!(!files_incident("never", "failed"));
        assert!(files_incident("failed", "failed"));
        assert!(!files_incident("failed", "errored"));
        assert!(files_incident("failed_or_errored", "errored"));
        assert!(!files_incident("failed_or_errored", "passed"));
    }

    #[test]
    fn a_declaration_names_one_target_a_real_probe_and_registered_values() {
        let ok = json!({ "display_name": "lending answers", "target_ref": "system://acme/lending", "check_kind": "command_exit", "probe": { "environment_ref": "environment://env_1", "command": "true" }, "severity": "major", "incident_policy": { "file_on": "failed" } });
        let (_, _, _, _, _, _, enablement) =
            declared_fields(&ok).expect("a well-formed declaration");
        assert_eq!(enablement, "enabled");
        let mut no_probe = ok.clone();
        no_probe["probe"] = Value::Null;
        assert!(declared_fields(&no_probe).is_err());
        let mut wrong_target = ok.clone();
        wrong_target["check_kind"] = json!("automation_run_outcome");
        assert!(
            declared_fields(&wrong_target).is_err(),
            "an automation_run_outcome check observes an automation"
        );
        let mut bad_target = ok;
        bad_target["target_ref"] = json!("https://example.com");
        assert!(declared_fields(&bad_target).is_err());
    }
}
