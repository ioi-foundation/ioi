//! Process / state-machine DEFINITION object plane — FOUNDATION cut (daemon-first, definition-only).
//!
//! A HypervisorStateMachine is a DECLARED, INERT process/state-machine DEFINITION: it says what the
//! states are, how they may transition, what guards a transition declares, and the machine's declared
//! inputs/outputs and owners. It is a grammar for a process — never a running one.
//!
//! Deliberately inert — this plane DEFINES, it does not act:
//!   * there is NO run/step/fire/execute endpoint, no `current_state`, no scheduling, and no binding
//!     to Automations / Missions / ODK — that is a later, separate authority-crossing cut;
//!   * writes are fail-closed: a definition that cannot be a coherent machine is rejected with a
//!     typed code, never half-persisted;
//!   * `health` is a declared-completeness signal (empty | incomplete | ready), never runtime state.
//!
//! Fail-closed write lanes: missing name; invalid state / transition id shape; duplicate state or
//! transition ids; unknown state `kind`; not exactly one initial state; a transition end that does
//! not resolve to a declared state; a transition guard_ref that does not resolve to a declared guard;
//! a malformed owner ref.

use std::sync::Arc;

use axum::extract::{Path as AxumPath, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};

use super::{iso_now, persist_record, read_record_dir, remove_record, DaemonState};

const KIND_STATE_MACHINE: &str = "state-machines";
/// The role a declared state plays. Exactly one `initial` is required for a coherent machine.
const STATE_KINDS: &[&str] = &["initial", "normal", "final"];
/// Bounds — a definition is a small grammar, not a data dump. Oversized inputs fail closed so the
/// object store never absorbs attacker-controlled bulk.
const MAX_SLUG: usize = 128;
const MAX_TEXT: usize = 2000;
const MAX_ELEMS: usize = 512;
const MAX_PORTS: usize = 128;

fn nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}
fn bad(code: &str, msg: &str) -> (StatusCode, Json<Value>) {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({ "ok": false, "error": { "code": code, "message": msg } })),
    )
}
fn text<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(Value::as_str).unwrap_or("")
}
fn load(data_dir: &str, id: &str) -> Option<Value> {
    read_record_dir(data_dir, KIND_STATE_MACHINE)
        .into_iter()
        .find(|r| r.get("id").and_then(Value::as_str) == Some(id))
}
/// A valid id/ref slug: 1..=MAX_SLUG chars, only [a-z0-9_-] (lowercased grammar ids, not free text).
fn is_slug(s: &str) -> bool {
    (1..=MAX_SLUG).contains(&s.len())
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
}
/// Get a field as an array of elements, treating absent/null as empty; Err(()) if present-but-not-array
/// (uniform null handling across every container field — null == absent == empty).
fn arr_or_empty<'a>(body: &'a Value, key: &str) -> Result<Vec<&'a Value>, ()> {
    match body.get(key) {
        None | Some(Value::Null) => Ok(vec![]),
        Some(Value::Array(a)) => Ok(a.iter().collect()),
        _ => Err(()),
    }
}
/// A well-formed named owner ref: `scheme://body` with a non-empty body (definition-only — owners are
/// declared named refs here; resolving them into the identity/agent planes is a later crossing).
fn owner_ref_ok(s: &str) -> bool {
    if s.len() > MAX_TEXT {
        return false;
    }
    match s.split_once("://") {
        Some((scheme, body)) => !scheme.is_empty() && !body.is_empty(),
        None => false,
    }
}
/// name/description free-text bound (a definition is a grammar, not a document store).
fn bounded_text(s: &str) -> bool {
    s.len() <= MAX_TEXT
}
/// An OPTIONAL free-text field on a nested element: absent/null → ""; a bounded string → itself; a
/// present non-string OR over-long string → Err(code) (never silently coerced to "", never unbounded).
fn opt_text<'a>(v: &'a Value, key: &str, code: &'static str) -> Result<&'a str, (String, String)> {
    match v.get(key) {
        None | Some(Value::Null) => Ok(""),
        Some(Value::String(s)) if s.len() <= MAX_TEXT => Ok(s.as_str()),
        Some(Value::String(_)) => Err((code.to_string(), format!("`{key}` exceeds {MAX_TEXT} chars"))),
        Some(_) => Err((code.to_string(), format!("`{key}` must be a string"))),
    }
}

/// Parse a JSON array of strings; None if a non-string element is present (absent = empty).
fn str_array(v: Option<&Value>) -> Option<Vec<String>> {
    match v {
        None | Some(Value::Null) => Some(vec![]),
        Some(Value::Array(a)) => a.iter().map(|e| e.as_str().map(str::to_string)).collect(),
        _ => None,
    }
}

#[derive(Debug)]
struct Validated {
    states: Vec<Value>,
    transitions: Vec<Value>,
    guards: Vec<Value>,
    inputs: Vec<String>,
    outputs: Vec<String>,
    owner_refs: Vec<String>,
    health: &'static str,
}

/// The single fail-closed validator shared by create + patch. Rejects any definition that could not
/// be a coherent machine; on success returns the normalized parts + the honest health signal.
fn validate_definition(body: &Value) -> Result<Validated, (String, String)> {
    let err = |c: &str, m: String| Err((c.to_string(), m));

    // ---- Guards (declared first; transitions may reference them). {id, name}
    let mut guards = Vec::new();
    let mut guard_ids = HashSet::new();
    let Ok(guard_list) = arr_or_empty(body, "guards") else {
        return err("state_machine_guards_invalid", "guards must be an array of objects".into());
    };
    if guard_list.len() > MAX_ELEMS {
        return err("state_machine_too_many_guards", format!("at most {MAX_ELEMS} guards allowed"));
    }
    for g in guard_list {
        let id = text(g, "id");
        if !is_slug(id) {
            return err("state_machine_guard_id_invalid", format!("guard id `{id}` is not a valid slug ([a-z0-9_-], 1..={MAX_SLUG})"));
        }
        if !guard_ids.insert(id.to_string()) {
            return err("state_machine_duplicate_guard_id", format!("duplicate guard id `{id}`"));
        }
        let gname = opt_text(g, "name", "state_machine_guard_field_invalid")?;
        let gexpr = opt_text(g, "expression", "state_machine_guard_field_invalid")?;
        guards.push(json!({ "id": id, "name": gname, "expression": gexpr }));
    }

    // ---- States. {id, name, kind}
    let mut states = Vec::new();
    let mut state_ids = HashSet::new();
    let mut initial_count = 0usize;
    let mut final_count = 0usize;
    let mut initial_id: Option<String> = None;
    let mut final_ids: HashSet<String> = HashSet::new();
    let Ok(state_list) = arr_or_empty(body, "states") else {
        return err("state_machine_states_invalid", "states must be an array of objects".into());
    };
    if state_list.len() > MAX_ELEMS {
        return err("state_machine_too_many_states", format!("at most {MAX_ELEMS} states allowed"));
    }
    for s in state_list {
        let id = text(s, "id");
        if !is_slug(id) {
            return err("state_machine_state_id_invalid", format!("state id `{id}` is not a valid slug ([a-z0-9_-], 1..={MAX_SLUG})"));
        }
        if !state_ids.insert(id.to_string()) {
            return err("state_machine_duplicate_state_id", format!("duplicate state id `{id}`"));
        }
        // `kind` is optional (absent/null → normal) but a PRESENT value must be a valid string kind —
        // a non-string (or unknown) kind is rejected, never silently coerced.
        let kind = match s.get("kind") {
            None | Some(Value::Null) => "normal",
            Some(Value::String(k)) if k.is_empty() => "normal",
            Some(Value::String(k)) => k.as_str(),
            Some(_) => return err("state_machine_state_kind_invalid", format!("state `{id}` kind must be a string, one of {STATE_KINDS:?}")),
        };
        if !STATE_KINDS.contains(&kind) {
            return err("state_machine_state_kind_invalid", format!("state `{id}` kind `{kind}` must be one of {STATE_KINDS:?}"));
        }
        if kind == "initial" { initial_count += 1; initial_id = Some(id.to_string()); }
        if kind == "final" { final_count += 1; final_ids.insert(id.to_string()); }
        let sname = opt_text(s, "name", "state_machine_state_field_invalid")?;
        states.push(json!({ "id": id, "name": sname, "kind": kind }));
    }

    // Exactly one initial state — but only enforced once a machine has states (an empty draft is a
    // legitimate `empty` starting point, not an error).
    if !states.is_empty() {
        if initial_count == 0 {
            return err("state_machine_no_initial_state", "a machine with states must declare exactly one initial state".into());
        }
        if initial_count > 1 {
            return err("state_machine_multiple_initial_states", format!("exactly one initial state is allowed; found {initial_count}"));
        }
    }

    // ---- Transitions. {id, from, to, event?, guard_ref?}
    let mut transitions = Vec::new();
    let mut transition_ids = HashSet::new();
    let mut adj: HashMap<String, Vec<String>> = HashMap::new();
    let Ok(transition_list) = arr_or_empty(body, "transitions") else {
        return err("state_machine_transitions_invalid", "transitions must be an array of objects".into());
    };
    if transition_list.len() > MAX_ELEMS {
        return err("state_machine_too_many_transitions", format!("at most {MAX_ELEMS} transitions allowed"));
    }
    for t in transition_list {
        let id = text(t, "id");
        if !is_slug(id) {
            return err("state_machine_transition_id_invalid", format!("transition id `{id}` is not a valid slug ([a-z0-9_-], 1..={MAX_SLUG})"));
        }
        if !transition_ids.insert(id.to_string()) {
            return err("state_machine_duplicate_transition_id", format!("duplicate transition id `{id}`"));
        }
        let from = text(t, "from");
        let to = text(t, "to");
        if !state_ids.contains(from) {
            return err("state_machine_transition_end_unresolved", format!("transition `{id}` from `{from}` does not resolve to a declared state"));
        }
        if !state_ids.contains(to) {
            return err("state_machine_transition_end_unresolved", format!("transition `{id}` to `{to}` does not resolve to a declared state"));
        }
        // guard_ref: a present value must be a string (never silently dropped); empty = no guard; a
        // non-empty guard_ref must resolve to a declared guard.
        let guard_ref = opt_text(t, "guard_ref", "state_machine_guard_ref_invalid")?;
        if !guard_ref.is_empty() && !guard_ids.contains(guard_ref) {
            return err("state_machine_guard_unresolved", format!("transition `{id}` guard_ref `{guard_ref}` does not resolve to a declared guard"));
        }
        let event = opt_text(t, "event", "state_machine_transition_field_invalid")?;
        adj.entry(from.to_string()).or_default().push(to.to_string());
        transitions.push(json!({ "id": id, "from": from, "to": to, "event": event, "guard_ref": guard_ref }));
    }

    // ---- Declared inputs / outputs (named ports) — each a non-empty, bounded name.
    let ports = |key: &str, code: &'static str| -> Result<Vec<String>, (String, String)> {
        let Some(list) = str_array(body.get(key)) else {
            return Err((code.to_string(), format!("{key} must be an array of strings")));
        };
        if list.len() > MAX_PORTS {
            return Err((code.to_string(), format!("at most {MAX_PORTS} {key} allowed")));
        }
        for p in &list {
            if p.trim().is_empty() || p.len() > MAX_SLUG {
                return Err((code.to_string(), format!("a {key} port name must be non-empty and <= {MAX_SLUG} chars")));
            }
        }
        Ok(list)
    };
    let inputs = ports("inputs", "state_machine_inputs_invalid")?;
    let outputs = ports("outputs", "state_machine_outputs_invalid")?;

    // ---- Owner refs — well-formed named refs (definition-only; not resolved into other planes yet).
    let Some(owner_refs) = str_array(body.get("owner_refs")) else {
        return err("state_machine_owner_refs_invalid", "owner_refs must be an array of strings".into());
    };
    if owner_refs.len() > MAX_PORTS {
        return err("state_machine_owner_refs_invalid", format!("at most {MAX_PORTS} owner refs allowed"));
    }
    for o in &owner_refs {
        if !owner_ref_ok(o) {
            return err("state_machine_owner_ref_invalid", format!("owner ref `{o}` is not a well-formed `scheme://body` ref"));
        }
    }

    // ---- Reachability from the initial state (BFS over the transition graph) — `ready` must reflect
    // what is actually REACHABLE, never a disconnected terminal.
    let reachable: HashSet<String> = {
        let mut seen: HashSet<String> = HashSet::new();
        if let Some(init) = &initial_id {
            let mut stack = vec![init.clone()];
            seen.insert(init.clone());
            while let Some(cur) = stack.pop() {
                if let Some(nexts) = adj.get(&cur) {
                    for n in nexts {
                        if seen.insert(n.clone()) {
                            stack.push(n.clone());
                        }
                    }
                }
            }
        }
        seen
    };
    // Forward motion: at least one non-self transition FROM a reachable state (a pure self-loop, or a
    // transition out of an unreachable island, does not count).
    let has_forward = transitions.iter().any(|t| {
        let from = t.get("from").and_then(Value::as_str).unwrap_or("");
        let to = t.get("to").and_then(Value::as_str).unwrap_or("");
        from != to && reachable.contains(from)
    });
    // If the machine declares any final state, at least one must be REACHABLE from the initial state.
    let final_reachable = final_ids.is_empty() || final_ids.iter().any(|f| reachable.contains(f));

    // ---- Health — declared completeness, never runtime state. `ready` requires exactly one initial
    // state, real forward motion, and (if a terminal is declared) a reachable terminal.
    let health = if states.is_empty() {
        "empty"
    } else if initial_count == 1 && has_forward && final_reachable {
        "ready"
    } else {
        "incomplete"
    };

    Ok(Validated { states, transitions, guards, inputs, outputs, owner_refs, health })
}

pub(crate) async fn handle_state_machine_overview(State(st): State<Arc<DaemonState>>) -> Json<Value> {
    let items = read_record_dir(&st.data_dir, KIND_STATE_MACHINE);
    let mut by_status: HashMap<String, i64> = HashMap::new();
    let mut by_health: HashMap<String, i64> = HashMap::new();
    for e in &items {
        *by_status.entry(text(e, "status").to_string()).or_insert(0) += 1;
        *by_health.entry(text(e, "health").to_string()).or_insert(0) += 1;
    }
    Json(json!({
        "ok": true,
        "total": items.len(),
        "by_status": serde_json::to_value(&by_status).unwrap_or_else(|_| json!({})),
        "by_health": serde_json::to_value(&by_health).unwrap_or_else(|_| json!({})),
        "state_kinds": STATE_KINDS,
        "status_note": "Definition truth only: a state machine declares states/transitions/guards. There is no run/step/execution here — a running instance, scheduling, and automation binding are a later authority-crossing cut."
    }))
}

pub(crate) async fn handle_state_machine_list(
    State(st): State<Arc<DaemonState>>,
    Query(q): Query<HashMap<String, String>>,
) -> Json<Value> {
    let mut items = read_record_dir(&st.data_dir, KIND_STATE_MACHINE);
    if let Some(h) = q.get("health").map(|s| s.trim()).filter(|s| !s.is_empty()) {
        items.retain(|e| text(e, "health") == h);
    }
    items.sort_by(|a, b| text(b, "updated_at").cmp(text(a, "updated_at")));
    Json(json!({ "ok": true, "state_machines": items }))
}

pub(crate) async fn handle_state_machine_create(
    State(st): State<Arc<DaemonState>>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let name = text(&body, "name").trim().to_string();
    if name.is_empty() {
        return bad("state_machine_name_required", "a state-machine name is required");
    }
    if !bounded_text(&name) {
        return bad("state_machine_name_invalid", "name is too long");
    }
    if !bounded_text(text(&body, "description")) {
        return bad("state_machine_description_invalid", "description is too long");
    }
    let v = match validate_definition(&body) {
        Ok(v) => v,
        Err((c, m)) => return bad(&c, &m),
    };
    let id = format!("sm_{:x}", nanos());
    let now = iso_now();
    let record = json!({
        "schema_version": "ioi.hypervisor.state-machine.v1",
        "object": "ioi.hypervisor.state_machine",
        "id": id, "ref": format!("state-machine://{id}"),
        "name": name,
        "description": text(&body, "description"),
        "states": v.states,
        "transitions": v.transitions,
        "guards": v.guards,
        "inputs": v.inputs,
        "outputs": v.outputs,
        "owner_refs": v.owner_refs,
        // Inert: a definition is always a draft. It never runs.
        "status": "draft",
        "health": v.health,
        "authority_note": "inert definition — no run/step/execution, no scheduling, no automation binding",
        "history": [ json!({ "op": "create", "at": now, "summary": format!("defined ({} state(s), {} transition(s)) — {}", v.states.len(), v.transitions.len(), v.health) }) ],
        "created_at": now, "updated_at": now
    });
    let _ = persist_record(&st.data_dir, KIND_STATE_MACHINE, &id, &record);
    (StatusCode::CREATED, Json(json!({ "ok": true, "state_machine": record })))
}

pub(crate) async fn handle_state_machine_get(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> Json<Value> {
    match load(&st.data_dir, &id) {
        Some(e) => Json(json!({ "ok": true, "state_machine": e })),
        None => Json(json!({ "ok": false, "reason": "state_machine not found" })),
    }
}

pub(crate) async fn handle_state_machine_patch(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let Some(mut e) = load(&st.data_dir, &id) else {
        return bad("state_machine_not_found", "state_machine not found");
    };
    if let Some(v) = body.get("name") {
        let n = v.as_str().unwrap_or("").trim();
        if n.is_empty() {
            return bad("state_machine_name_required", "name cannot be blank");
        }
        if !bounded_text(n) {
            return bad("state_machine_name_invalid", "name is too long");
        }
        e["name"] = json!(n);
    }
    if body.get("description").is_some() {
        if !bounded_text(text(&body, "description")) {
            return bad("state_machine_description_invalid", "description is too long");
        }
        e["description"] = json!(text(&body, "description"));
    }
    // Re-validate the WHOLE definition against a merged view (patch replaces the arrays it supplies;
    // untouched arrays are carried from the stored record) — a patch can never leave it incoherent.
    let touches_def = ["states", "transitions", "guards", "inputs", "outputs", "owner_refs"]
        .iter()
        .any(|k| body.get(k).is_some());
    if touches_def {
        let merged = json!({
            "states": body.get("states").cloned().unwrap_or_else(|| e.get("states").cloned().unwrap_or_else(|| json!([]))),
            "transitions": body.get("transitions").cloned().unwrap_or_else(|| e.get("transitions").cloned().unwrap_or_else(|| json!([]))),
            "guards": body.get("guards").cloned().unwrap_or_else(|| e.get("guards").cloned().unwrap_or_else(|| json!([]))),
            "inputs": body.get("inputs").cloned().unwrap_or_else(|| e.get("inputs").cloned().unwrap_or_else(|| json!([]))),
            "outputs": body.get("outputs").cloned().unwrap_or_else(|| e.get("outputs").cloned().unwrap_or_else(|| json!([]))),
            "owner_refs": body.get("owner_refs").cloned().unwrap_or_else(|| e.get("owner_refs").cloned().unwrap_or_else(|| json!([]))),
        });
        let v = match validate_definition(&merged) {
            Ok(v) => v,
            Err((c, m)) => return bad(&c, &m),
        };
        e["states"] = json!(v.states);
        e["transitions"] = json!(v.transitions);
        e["guards"] = json!(v.guards);
        e["inputs"] = json!(v.inputs);
        e["outputs"] = json!(v.outputs);
        e["owner_refs"] = json!(v.owner_refs);
        e["health"] = json!(v.health);
    }
    let now = iso_now();
    let health_now = text(&e, "health").to_string();
    e["updated_at"] = json!(now);
    if let Some(h) = e.get_mut("history").and_then(Value::as_array_mut) {
        h.push(json!({ "op": "patch", "at": now, "summary": format!("edited — {health_now}") }));
    }
    let _ = persist_record(&st.data_dir, KIND_STATE_MACHINE, &id, &e);
    (StatusCode::OK, Json(json!({ "ok": true, "state_machine": e })))
}

pub(crate) async fn handle_state_machine_delete(
    State(st): State<Arc<DaemonState>>,
    AxumPath(id): AxumPath<String>,
) -> Json<Value> {
    let removed = remove_record(&st.data_dir, KIND_STATE_MACHINE, &id);
    Json(json!({ "ok": removed, "removed": removed, "id": id }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn def(states: Value, transitions: Value, guards: Value) -> Value {
        json!({ "name": "m", "states": states, "transitions": transitions, "guards": guards })
    }

    #[test]
    fn slug_and_owner_ref_shapes() {
        assert!(is_slug("start"));
        assert!(is_slug("s_1-a"));
        assert!(!is_slug("Start")); // uppercase rejected
        assert!(!is_slug("")); // empty rejected
        assert!(!is_slug("a b")); // space rejected
        assert!(owner_ref_ok("agent://a1"));
        assert!(owner_ref_ok("principal://usr_1"));
        assert!(!owner_ref_ok("agent://")); // empty body
        assert!(!owner_ref_ok("bare")); // no scheme
    }

    #[test]
    fn empty_definition_is_health_empty_not_error() {
        let v = validate_definition(&json!({ "name": "m" })).unwrap();
        assert_eq!(v.health, "empty");
    }

    #[test]
    fn ready_requires_initial_forward_and_reachable_terminal() {
        // one state, initial, no transition → incomplete (no forward motion)
        let v = validate_definition(&def(json!([{ "id": "a", "kind": "initial" }]), json!([]), json!([]))).unwrap();
        assert_eq!(v.health, "incomplete");
        // initial + a final state but NO transition → the terminal is UNREACHABLE → incomplete (honest)
        let v = validate_definition(&def(json!([{ "id": "a", "kind": "initial" }, { "id": "b", "kind": "final" }]), json!([]), json!([]))).unwrap();
        assert_eq!(v.health, "incomplete");
        // initial + one transition (no terminal declared) → ready (forward motion, vacuous terminal)
        let v = validate_definition(&def(json!([{ "id": "a", "kind": "initial" }, { "id": "b", "kind": "normal" }]), json!([{ "id": "t1", "from": "a", "to": "b" }]), json!([]))).unwrap();
        assert_eq!(v.health, "ready");
        // initial + final + a transition that REACHES the final → ready
        let v = validate_definition(&def(json!([{ "id": "a", "kind": "initial" }, { "id": "b", "kind": "final" }]), json!([{ "id": "t", "from": "a", "to": "b" }]), json!([]))).unwrap();
        assert_eq!(v.health, "ready");
        // initial + UNREACHABLE final (transition leads elsewhere) → incomplete (reachability checked)
        let v = validate_definition(&def(json!([{ "id": "a", "kind": "initial" }, { "id": "b", "kind": "normal" }, { "id": "c", "kind": "final" }]), json!([{ "id": "t", "from": "a", "to": "b" }]), json!([]))).unwrap();
        assert_eq!(v.health, "incomplete");
    }

    #[test]
    fn fail_closed_lanes() {
        // duplicate state id
        assert_eq!(validate_definition(&def(json!([{ "id": "a", "kind": "initial" }, { "id": "a", "kind": "final" }]), json!([]), json!([]))).unwrap_err().0, "state_machine_duplicate_state_id");
        // no initial
        assert_eq!(validate_definition(&def(json!([{ "id": "a", "kind": "normal" }]), json!([]), json!([]))).unwrap_err().0, "state_machine_no_initial_state");
        // multiple initial
        assert_eq!(validate_definition(&def(json!([{ "id": "a", "kind": "initial" }, { "id": "b", "kind": "initial" }]), json!([]), json!([]))).unwrap_err().0, "state_machine_multiple_initial_states");
        // bad state kind
        assert_eq!(validate_definition(&def(json!([{ "id": "a", "kind": "weird" }]), json!([]), json!([]))).unwrap_err().0, "state_machine_state_kind_invalid");
        // bad state id shape
        assert_eq!(validate_definition(&def(json!([{ "id": "A", "kind": "initial" }]), json!([]), json!([]))).unwrap_err().0, "state_machine_state_id_invalid");
        // transition end unresolved
        assert_eq!(validate_definition(&def(json!([{ "id": "a", "kind": "initial" }]), json!([{ "id": "t1", "from": "a", "to": "ghost" }]), json!([]))).unwrap_err().0, "state_machine_transition_end_unresolved");
        // duplicate transition id
        assert_eq!(validate_definition(&def(json!([{ "id": "a", "kind": "initial" }, { "id": "b", "kind": "final" }]), json!([{ "id": "t", "from": "a", "to": "b" }, { "id": "t", "from": "b", "to": "a" }]), json!([]))).unwrap_err().0, "state_machine_duplicate_transition_id");
        // guard unresolved
        assert_eq!(validate_definition(&def(json!([{ "id": "a", "kind": "initial" }, { "id": "b", "kind": "final" }]), json!([{ "id": "t", "from": "a", "to": "b", "guard_ref": "g_missing" }]), json!([]))).unwrap_err().0, "state_machine_guard_unresolved");
        // guard resolves when declared
        assert!(validate_definition(&def(json!([{ "id": "a", "kind": "initial" }, { "id": "b", "kind": "final" }]), json!([{ "id": "t", "from": "a", "to": "b", "guard_ref": "g1" }]), json!([{ "id": "g1", "name": "ok" }]))).is_ok());
        // bad owner ref
        let mut d = def(json!([{ "id": "a", "kind": "initial" }]), json!([]), json!([]));
        d["owner_refs"] = json!(["not-a-ref"]);
        assert_eq!(validate_definition(&d).unwrap_err().0, "state_machine_owner_ref_invalid");
    }

    #[test]
    fn adversarial_hardening_lanes() {
        // non-string kind is REJECTED, never coerced to "normal" (the medium finding)
        assert_eq!(validate_definition(&def(json!([{ "id": "a", "kind": "initial" }, { "id": "b", "kind": ["final"] }]), json!([]), json!([]))).unwrap_err().0, "state_machine_state_kind_invalid");
        assert_eq!(validate_definition(&def(json!([{ "id": "a", "kind": 999 }]), json!([]), json!([]))).unwrap_err().0, "state_machine_state_kind_invalid");
        // absent/null kind still defaults to normal (unchanged behavior)
        assert!(validate_definition(&def(json!([{ "id": "a", "kind": "initial" }, { "id": "b" }]), json!([]), json!([]))).is_ok());

        // oversized slug id rejected (length bound)
        let big = "a".repeat(MAX_SLUG + 1);
        assert_eq!(validate_definition(&def(json!([{ "id": big, "kind": "initial" }]), json!([]), json!([]))).unwrap_err().0, "state_machine_state_id_invalid");

        // empty / blank port rejected
        let mut d = def(json!([{ "id": "a", "kind": "initial" }]), json!([]), json!([]));
        d["inputs"] = json!(["", "ok"]);
        assert_eq!(validate_definition(&d).unwrap_err().0, "state_machine_inputs_invalid");

        // a PURE self-loop stays incomplete — `ready` never overstates completeness
        let v = validate_definition(&def(json!([{ "id": "a", "kind": "initial" }]), json!([{ "id": "t", "from": "a", "to": "a" }]), json!([]))).unwrap();
        assert_eq!(v.health, "incomplete");
        // but a self-loop PLUS a real forward transition is ready
        let v = validate_definition(&def(json!([{ "id": "a", "kind": "initial" }, { "id": "b", "kind": "final" }]), json!([{ "id": "loop", "from": "a", "to": "a" }, { "id": "fwd", "from": "a", "to": "b" }]), json!([]))).unwrap();
        assert_eq!(v.health, "ready");

        // null containers are uniformly tolerated as empty (consistency)
        assert!(validate_definition(&json!({ "name": "m", "states": Value::Null, "transitions": Value::Null, "guards": Value::Null })).is_ok());
        // but a non-array container is rejected
        assert_eq!(validate_definition(&json!({ "name": "m", "states": "not-an-array" })).unwrap_err().0, "state_machine_states_invalid");

        // a present NON-STRING guard_ref is rejected, never silently dropped into an unguarded transition
        assert_eq!(validate_definition(&def(json!([{ "id": "a", "kind": "initial" }, { "id": "b", "kind": "final" }]), json!([{ "id": "t", "from": "a", "to": "b", "guard_ref": ["g1"] }]), json!([{ "id": "g1", "name": "ok" }]))).unwrap_err().0, "state_machine_guard_ref_invalid");
        // free-text fields are bounded + must be strings (guard expression / state name / transition event)
        assert_eq!(validate_definition(&def(json!([{ "id": "a", "kind": "initial" }]), json!([]), json!([{ "id": "g1", "expression": "x".repeat(MAX_TEXT + 1) }]))).unwrap_err().0, "state_machine_guard_field_invalid");
        assert_eq!(validate_definition(&def(json!([{ "id": "a", "kind": "initial", "name": 42 }]), json!([]), json!([]))).unwrap_err().0, "state_machine_state_field_invalid");
        assert_eq!(validate_definition(&def(json!([{ "id": "a", "kind": "initial" }, { "id": "b", "kind": "final" }]), json!([{ "id": "t", "from": "a", "to": "b", "event": { "x": 1 } }]), json!([]))).unwrap_err().0, "state_machine_transition_field_invalid");
    }
}
