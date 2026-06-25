//! Cut D — AgentOps conversation service (daemon-native).
//!
//! A real conversation is a persisted thread of structured EVENT BLOCKS emitted as a turn actually
//! executes over a bound environment: `user_message` → `action_started` (the real tool the harness
//! runs) → `file_modification` (with a real git diff) → `action_completed` → `assistant_message`
//! (real daemon-routed model output) → `turn_completed`. The conversation can SUSPEND on a named
//! waiting interest (authority request / user input / environment rebuild) and RESUME the SAME turn
//! — the pending action + model output are preserved across the suspend, so no turn is lost. An
//! operator can `interrupt` a running turn.
//!
//! This supersedes the empty conversation endpoint: it is a real AgentOps service, not a placeholder.
//! Records persist under `state_dir/agentops-conversations/<id>.json` (blocks inline + a cursor).
//! UI note: the harvested SPA decodes its transcript as base64-protobuf frames; rendering these
//! blocks IN that bundle is the named SPA-frame follow-on (the substrate here is daemon truth and is
//! consumed by the contract done-bar + the app's own conversation view).
use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::extract::{Path as AxumPath, Query, State};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Value};

use super::{
    invoke_native_local, iso_now, persist_invocation_receipt, resolve_route, short_hash, AppError,
    DaemonState,
};

fn safe(seg: &str) -> String {
    seg.replace(|c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '_', "_")
}

fn conv_dir(data_dir: &str) -> PathBuf {
    Path::new(data_dir).join("agentops-conversations")
}
fn conv_path(data_dir: &str, id: &str) -> PathBuf {
    conv_dir(data_dir).join(format!("{}.json", safe(id)))
}
fn load_conv(data_dir: &str, id: &str) -> Option<Value> {
    serde_json::from_slice(&std::fs::read(conv_path(data_dir, id)).ok()?).ok()
}
fn save_conv(data_dir: &str, conv: &Value) -> Result<(), AppError> {
    let id = conv["conversation_id"].as_str().unwrap_or_default();
    let dir = conv_dir(data_dir);
    std::fs::create_dir_all(&dir).map_err(|e| AppError(axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    std::fs::write(conv_path(data_dir, id), serde_json::to_vec_pretty(conv).unwrap_or_default())
        .map_err(|e| AppError(axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
}

/// Resolve an environment's scoped workspace root (daemon truth; empty ⇒ not started).
fn env_workspace(data_dir: &str, env_id: &str) -> Option<String> {
    let v: Value = serde_json::from_slice(&std::fs::read(Path::new(data_dir).join("environments").join(format!("{}.json", safe(env_id)))).ok()?).ok()?;
    v["status"]["workspace_root"].as_str().filter(|s| !s.is_empty()).map(str::to_string)
}

fn git(ws: &str, args: &[&str]) -> String {
    std::process::Command::new("git").arg("-C").arg(ws).args(args).output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned()).unwrap_or_default()
}

/// Append a typed event block to the conversation and bump the monotonic cursor.
fn emit(conv: &mut Value, kind: &str, payload: Value) {
    let seq = conv["cursor"].as_u64().unwrap_or(0) + 1;
    conv["cursor"] = json!(seq);
    let mut block = json!({ "seq": seq, "kind": kind, "at": iso_now() });
    if let (Some(obj), Some(p)) = (block.as_object_mut(), payload.as_object()) {
        for (k, v) in p { obj.insert(k.clone(), v.clone()); }
    }
    conv["blocks"].as_array_mut().map(|a| a.push(block));
}

// ---- POST /v1/hypervisor/agentops/conversations — create ----------------------------------------
pub(crate) async fn handle_conversation_create(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    let env_id = body.get("environment_id").and_then(|v| v.as_str()).unwrap_or_default().to_string();
    if env_id.is_empty() {
        return Ok(Json(json!({ "ok": false, "reason": "environment_id required" })));
    }
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    let id = format!("conv_{nanos:x}");
    let conv = json!({
        "schema_version": "ioi.hypervisor.agentops-conversation.v1",
        "conversation_id": id,
        "environment_id": env_id,
        "harness_binding_ref": body.get("harness_binding_ref").cloned().unwrap_or(Value::Null),
        "title": body.get("title").and_then(|v| v.as_str()).unwrap_or("Conversation"),
        "status": "active",
        "waiting_interest": Value::Null,
        "pending_turn": Value::Null,
        "cursor": 0,
        "turn_count": 0,
        "blocks": [],
        "created_at": iso_now()
    });
    save_conv(&st.data_dir, &conv)?;
    Ok(Json(json!({ "ok": true, "conversation": conv })))
}

// ---- the real turn: model-routed output + a real child-harness file write -----------------------
struct TurnPlan { objective: String, file_rel: String, file_body: String, model_output: String, route_id: String, model: String }

async fn plan_turn(st: &DaemonState, conv: &Value, user_text: &str) -> Result<TurnPlan, AppError> {
    let turn_idx = conv["turn_count"].as_u64().unwrap_or(0);
    let cid = conv["conversation_id"].as_str().unwrap_or_default();
    let objective = user_text.trim().to_string();
    let prompt = format!(
        "You are a coding harness in an AgentOps conversation turn.\nObjective: {objective}\n\
         Write the full contents of a single concise markdown note documenting the concrete change.\n");
    let route = resolve_route(st, &json!({}));
    let model_output = if route.is_native_local {
        let result = invoke_native_local(&prompt, &route.model)
            .map_err(|e| AppError(axum::http::StatusCode::BAD_GATEWAY, format!("native_local: {e}")))?;
        let out = result.get("output_text").and_then(|v| v.as_str()).unwrap_or_default().to_string();
        persist_invocation_receipt(st, &route, &result,
            &format!("conv:{cid}:turn:{turn_idx}:{}", short_hash(&prompt)),
            json!({ "capability": "chat", "invocationKind": "agentops.turn", "conversationId": cid, "turnRef": format!("turn_{turn_idx}") }));
        out
    } else {
        let options = ioi_types::app::agentic::InferenceOptions { max_tokens: 1024, ..Default::default() };
        let output = st.inference.execute_inference([0u8; 32], prompt.as_bytes(), options).await
            .map_err(|e| AppError(axum::http::StatusCode::BAD_GATEWAY, format!("no_model_route: {e:?}")))?;
        String::from_utf8_lossy(&output).to_string()
    };
    let file_rel = format!("agentops/{}/turn-{turn_idx}.md", safe(cid));
    let file_body = format!("<!-- conversation {cid} · turn {turn_idx} · model {} -->\n\n# Objective\n\n{objective}\n\n# Output\n\n{model_output}\n", route.model);
    Ok(TurnPlan { objective, file_rel, file_body, model_output, route_id: route.route_id, model: route.model })
}

/// Execute the planned action (the real file write + commit) and emit its blocks. Used both for an
/// immediate turn and for a resumed turn — IDENTICAL plan, so resume loses nothing.
fn apply_turn(conv: &mut Value, ws: &str, plan: &TurnPlan) {
    emit(conv, "action_started", json!({ "tool": "write_file", "path": plan.file_rel, "objective": plan.objective }));
    let abs = Path::new(ws).join(&plan.file_rel);
    if let Some(parent) = abs.parent() { let _ = std::fs::create_dir_all(parent); }
    let _ = std::fs::write(&abs, &plan.file_body);
    let child = ["-c", "user.email=child@local", "-c", "user.name=agentops_harness"];
    let mut add = child.to_vec(); add.extend_from_slice(&["add", "-A"]); let _ = git(ws, &add);
    // a REAL diff of what the turn changed (staged), then commit.
    let diff = git(ws, &["diff", "--cached", "--", &plan.file_rel]);
    emit(conv, "file_modification", json!({ "path": plan.file_rel, "change_type": "added", "diff": diff }));
    let msg = format!("agentops turn: {}", plan.objective.chars().take(60).collect::<String>());
    let mut commit = child.to_vec(); commit.extend_from_slice(&["commit", "-q", "-m", msg.as_str()]); let _ = git(ws, &commit);
    let head = git(ws, &["rev-parse", "HEAD"]).trim().to_string();
    emit(conv, "action_completed", json!({ "tool": "write_file", "path": plan.file_rel, "commit": head, "host_mutation": false }));
    emit(conv, "assistant_message", json!({ "text": plan.model_output, "route_id": plan.route_id, "model": plan.model }));
    let turn = conv["turn_count"].as_u64().unwrap_or(0) + 1;
    conv["turn_count"] = json!(turn);
    emit(conv, "turn_completed", json!({ "turn": turn, "commit": head }));
}

// ---- POST /v1/hypervisor/agentops/conversations/:id/send ----------------------------------------
pub(crate) async fn handle_conversation_send(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    let Some(mut conv) = load_conv(&st.data_dir, &id) else {
        return Ok(Json(json!({ "ok": false, "reason": "conversation not found" })));
    };
    if conv["status"].as_str() == Some("waiting") {
        return Ok(Json(json!({ "ok": false, "reason": "conversation is waiting on an interest; resolve it via /provide", "waiting_interest": conv["waiting_interest"] })));
    }
    let user_text = body.get("text").and_then(|v| v.as_str()).unwrap_or_default().to_string();
    if user_text.trim().is_empty() {
        return Ok(Json(json!({ "ok": false, "reason": "text required" })));
    }
    let env_id = conv["environment_id"].as_str().unwrap_or_default().to_string();
    let Some(ws) = env_workspace(&st.data_dir, &env_id) else {
        return Ok(Json(json!({ "ok": false, "reason": "environment not started (no scoped workspace)", "fail_closed": true })));
    };
    let from = conv["cursor"].as_u64().unwrap_or(0);
    emit(&mut conv, "user_message", json!({ "text": user_text }));
    conv["status"] = json!("running");

    let plan = plan_turn(&st, &conv, &user_text).await?;

    // Waiting interest: if this turn requires an authority crossing (caller-declared or harness
    // posture), SUSPEND before the action — preserve the full plan so resume re-applies it verbatim.
    let require_authority = body.get("require_authority").and_then(|v| v.as_bool()).unwrap_or(false);
    if require_authority {
        conv["pending_turn"] = json!({ "objective": plan.objective, "file_rel": plan.file_rel, "file_body": plan.file_body, "model_output": plan.model_output, "route_id": plan.route_id, "model": plan.model });
        conv["waiting_interest"] = json!({ "kind": "authority_request", "reason": "turn requires an authority crossing before applying the action", "since": iso_now() });
        conv["status"] = json!("waiting");
        emit(&mut conv, "waiting", json!({ "interest": "authority_request", "reason": "operator/authority approval required before the file action is applied", "resumable": true }));
        save_conv(&st.data_dir, &conv)?;
        let new_blocks: Vec<Value> = conv["blocks"].as_array().cloned().unwrap_or_default().into_iter().filter(|b| b["seq"].as_u64().unwrap_or(0) > from).collect();
        return Ok(Json(json!({ "ok": true, "status": "waiting", "waiting_interest": conv["waiting_interest"], "blocks": new_blocks, "cursor": conv["cursor"] })));
    }

    apply_turn(&mut conv, &ws, &plan);
    conv["status"] = json!("active");
    save_conv(&st.data_dir, &conv)?;
    let new_blocks: Vec<Value> = conv["blocks"].as_array().cloned().unwrap_or_default().into_iter().filter(|b| b["seq"].as_u64().unwrap_or(0) > from).collect();
    Ok(Json(json!({ "ok": true, "status": conv["status"], "blocks": new_blocks, "cursor": conv["cursor"] })))
}

// ---- POST /v1/hypervisor/agentops/conversations/:id/provide — resolve a waiting interest ---------
pub(crate) async fn handle_conversation_provide(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    let Some(mut conv) = load_conv(&st.data_dir, &id) else {
        return Ok(Json(json!({ "ok": false, "reason": "conversation not found" })));
    };
    if conv["status"].as_str() != Some("waiting") {
        return Ok(Json(json!({ "ok": false, "reason": "conversation is not waiting" })));
    }
    let from = conv["cursor"].as_u64().unwrap_or(0);
    let interest = conv["waiting_interest"]["kind"].as_str().unwrap_or("").to_string();
    // authority interest: a denial cancels the pending turn (fail-closed); a grant resumes it.
    let granted = body.get("granted").and_then(|v| v.as_bool()).unwrap_or(true);
    if interest == "authority_request" && !granted {
        emit(&mut conv, "waiting_resolved", json!({ "interest": interest, "outcome": "denied" }));
        emit(&mut conv, "turn_canceled", json!({ "reason": "authority denied" }));
        conv["pending_turn"] = Value::Null;
        conv["waiting_interest"] = Value::Null;
        conv["status"] = json!("active");
        save_conv(&st.data_dir, &conv)?;
        let nb: Vec<Value> = conv["blocks"].as_array().cloned().unwrap_or_default().into_iter().filter(|b| b["seq"].as_u64().unwrap_or(0) > from).collect();
        return Ok(Json(json!({ "ok": true, "status": "active", "outcome": "denied", "blocks": nb, "cursor": conv["cursor"] })));
    }
    // resume the SAME turn from the preserved plan — nothing recomputed, nothing lost.
    let pending = conv["pending_turn"].clone();
    let plan = TurnPlan {
        objective: pending["objective"].as_str().unwrap_or_default().to_string(),
        file_rel: pending["file_rel"].as_str().unwrap_or_default().to_string(),
        file_body: pending["file_body"].as_str().unwrap_or_default().to_string(),
        model_output: pending["model_output"].as_str().unwrap_or_default().to_string(),
        route_id: pending["route_id"].as_str().unwrap_or_default().to_string(),
        model: pending["model"].as_str().unwrap_or_default().to_string(),
    };
    if plan.file_rel.is_empty() {
        return Ok(Json(json!({ "ok": false, "reason": "no pending turn to resume" })));
    }
    let env_id = conv["environment_id"].as_str().unwrap_or_default().to_string();
    let Some(ws) = env_workspace(&st.data_dir, &env_id) else {
        return Ok(Json(json!({ "ok": false, "reason": "environment not started" })));
    };
    emit(&mut conv, "waiting_resolved", json!({ "interest": interest, "outcome": "granted", "value": body.get("value").cloned().unwrap_or(Value::Null) }));
    apply_turn(&mut conv, &ws, &plan);
    conv["pending_turn"] = Value::Null;
    conv["waiting_interest"] = Value::Null;
    conv["status"] = json!("active");
    save_conv(&st.data_dir, &conv)?;
    let nb: Vec<Value> = conv["blocks"].as_array().cloned().unwrap_or_default().into_iter().filter(|b| b["seq"].as_u64().unwrap_or(0) > from).collect();
    Ok(Json(json!({ "ok": true, "status": "active", "outcome": "resumed", "resumed_turn": true, "blocks": nb, "cursor": conv["cursor"] })))
}

// ---- POST /v1/hypervisor/agentops/conversations/:id/interrupt -----------------------------------
pub(crate) async fn handle_conversation_interrupt(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<Value>, AppError> {
    let Some(mut conv) = load_conv(&st.data_dir, &id) else {
        return Ok(Json(json!({ "ok": false, "reason": "conversation not found" })));
    };
    let prior = conv["status"].clone();
    emit(&mut conv, "interrupted", json!({ "by": "operator", "prior_status": prior }));
    conv["status"] = json!("interrupted");
    conv["pending_turn"] = Value::Null;
    conv["waiting_interest"] = Value::Null;
    save_conv(&st.data_dir, &conv)?;
    Ok(Json(json!({ "ok": true, "status": "interrupted", "cursor": conv["cursor"] })))
}

// ---- GET /v1/hypervisor/agentops/conversations/:id — history ------------------------------------
pub(crate) async fn handle_conversation_get(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<Value>, AppError> {
    let Some(conv) = load_conv(&st.data_dir, &id) else {
        return Ok(Json(json!({ "ok": false, "reason": "conversation not found" })));
    };
    Ok(Json(json!({ "ok": true, "conversation": conv })))
}

// ---- GET /v1/hypervisor/agentops/conversations — list -------------------------------------------
pub(crate) async fn handle_conversation_list(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    let mut convs = Vec::new();
    if let Ok(rd) = std::fs::read_dir(conv_dir(&st.data_dir)) {
        for e in rd.flatten() {
            if let Ok(v) = std::fs::read(e.path()).map_err(|_| ()).and_then(|b| serde_json::from_slice::<Value>(&b).map_err(|_| ())) {
                convs.push(json!({ "conversation_id": v["conversation_id"], "environment_id": v["environment_id"], "title": v["title"], "status": v["status"], "turn_count": v["turn_count"] }));
            }
        }
    }
    Json(json!({ "ok": true, "conversations": convs }))
}

// ---- GET /v1/hypervisor/agentops/conversations/:id/events?since=N — SSE replay -------------------
pub(crate) async fn handle_conversation_events(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let Some(conv) = load_conv(&st.data_dir, &id) else {
        return (axum::http::StatusCode::NOT_FOUND, "conversation not found").into_response();
    };
    let since: u64 = q.get("since").and_then(|s| s.parse().ok()).unwrap_or(0);
    let mut out = String::new();
    for b in conv["blocks"].as_array().cloned().unwrap_or_default() {
        if b["seq"].as_u64().unwrap_or(0) > since {
            out.push_str(&format!("event: agentops.block\ndata: {}\n\n", b));
        }
    }
    out.push_str(&format!("event: agentops.cursor\ndata: {{\"cursor\":{}}}\n\n", conv["cursor"].as_u64().unwrap_or(0)));
    ([(axum::http::header::CONTENT_TYPE, "text/event-stream")], out).into_response()
}
