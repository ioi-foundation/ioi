// apps/autopilot/src-tauri/src/orchestrator.rs

use crate::execution::{self, ExecutionResult, GovernanceTier}; // [NEW] Import GovernanceTier
use crate::models::{AgentTask, SessionSummary}; 
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::time::{Instant, Duration};
use std::sync::{Arc, Mutex};
use ioi_crypto::algorithms::hash::sha256;
use ioi_scs::{SovereignContextStore, FrameType, RetentionClass}; // [FIX] Import RetentionClass
use hex;
use ioi_api::vm::inference::InferenceRuntime;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GraphNode {
    pub id: String,
    #[serde(rename = "type")]
    pub node_type: String,
    pub config: Option<Value>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GraphEdge {
    pub source: String,
    pub target: String,
    #[serde(rename = "sourceHandle")] 
    pub source_handle: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct GraphPayload {
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
    pub global_config: Option<Value>,
    pub session_id: Option<String>,
}

#[derive(Serialize, Clone)]
pub struct GraphEvent {
    pub node_id: String,
    pub status: String, 
    pub result: Option<ExecutionResult>,
    pub fitness_score: Option<f32>,
    pub generation: Option<u64>,
}

static GLOBAL_EXECUTION_CACHE: once_cell::sync::Lazy<Mutex<HashMap<String, ExecutionResult>>> = once_cell::sync::Lazy::new(|| {
    Mutex::new(HashMap::new())
});

fn interpolate_template(template: &str, context: &Value) -> String {
    let mut result = template.to_string();
    let mut start_idx = 0;
    while let Some(open) = result[start_idx..].find("{{") {
        let actual_open = start_idx + open;
        if let Some(close) = result[actual_open..].find("}}") {
            let actual_close = actual_open + close;
            let key = &result[actual_open + 2..actual_close].trim();
            
            let replacement = if let Some(val) = context.get(key) {
                if let Some(s) = val.as_str() { s.to_string() } else { val.to_string() }
            } else {
                format!("<<MISSING:{}>>", key)
            };

            result.replace_range(actual_open..actual_close + 2, &replacement);
            start_idx = actual_open + replacement.len();
        } else {
            break;
        }
    }
    result
}

fn merge_inputs(parent_outputs: Vec<Value>, global_env: &Value) -> Value {
    let mut merged_map = if let Value::Object(map) = global_env {
        map.clone()
    } else {
        serde_json::Map::new()
    };

    if parent_outputs.is_empty() {
        merged_map.insert("manual_trigger".to_string(), json!(true));
        return Value::Object(merged_map);
    }

    for output in parent_outputs {
        if let Value::Object(map) = output {
            for (k, v) in map {
                merged_map.insert(k, v);
            }
        }
    }

    Value::Object(merged_map)
}

pub fn compute_cache_key(node_id: &str, config: &Value, input_str: &str) -> [u8; 32] {
    let config_str = serde_json::to_string(config).unwrap_or_default();
    let preimage = format!("{}|{}|{}", node_id, config_str, input_str);
    
    match sha256(preimage.as_bytes()) {
        Ok(digest) => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(digest.as_ref());
            arr
        },
        Err(_) => [0u8; 32],
    }
}

fn fetch_cached_result(scs: &Arc<Mutex<SovereignContextStore>>, cache_key: [u8; 32]) -> Option<ExecutionResult> {
    let store = scs.lock().ok()?;
    if let Some(frame_ids) = store.session_index.get(&cache_key) {
        if let Some(&last_id) = frame_ids.last() {
            if let Ok(payload) = store.read_frame_payload(last_id) {
                // [FIX] Add reference &payload
                if let Ok(result) = serde_json::from_slice::<ExecutionResult>(&payload) {
                    return Some(result);
                }
            }
        }
    }
    None
}

fn persist_execution_result(scs: &Arc<Mutex<SovereignContextStore>>, cache_key: [u8; 32], result: &ExecutionResult) {
    if let Ok(mut store) = scs.lock() {
        if let Ok(bytes) = serde_json::to_vec(result) {
            // [FIX] Add RetentionClass::Ephemeral (Cache is transient-ish, but let's say Ephemeral or Epoch)
            let _ = store.append_frame(FrameType::System, &bytes, 0, [0u8; 32], cache_key, RetentionClass::Ephemeral);
        }
    }
}

pub fn query_cache(scs: &Arc<Mutex<SovereignContextStore>>, node_id: String, config: Value, input_str: String) -> Option<ExecutionResult> {
    let key_bytes = compute_cache_key(&node_id, &config, &input_str);
    let key_hex = hex::encode(key_bytes);
    
    {
        let cache = GLOBAL_EXECUTION_CACHE.lock().unwrap();
        if let Some(res) = cache.get(&key_hex) {
            return Some(res.clone());
        }
    }

    let res = fetch_cached_result(scs, key_bytes);
    if let Some(r) = &res {
        let mut cache = GLOBAL_EXECUTION_CACHE.lock().unwrap();
        cache.insert(key_hex, r.clone());
    }
    res
}

pub fn inject_execution_result(scs: &Arc<Mutex<SovereignContextStore>>, node_id: String, config: Value, input_str: String, result: ExecutionResult) {
    let key_bytes = compute_cache_key(&node_id, &config, &input_str);
    let key_hex = hex::encode(key_bytes);
    {
        let mut cache = GLOBAL_EXECUTION_CACHE.lock().unwrap();
        cache.insert(key_hex, result.clone());
    }
    persist_execution_result(scs, key_bytes, &result);
}

pub const SESSION_INDEX_KEY: [u8; 32] = [
    0x53, 0x45, 0x53, 0x53, 0x49, 0x4F, 0x4E, 0x5F, 0x49, 0x4E, 0x44, 0x45, 0x53, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
];

pub fn get_local_sessions(scs: &Arc<Mutex<SovereignContextStore>>) -> Vec<SessionSummary> {
    if let Ok(store) = scs.lock() {
        if let Some(frame_ids) = store.session_index.get(&SESSION_INDEX_KEY) {
            if let Some(&last_id) = frame_ids.last() {
                if let Ok(payload) = store.read_frame_payload(last_id) {
                    // [FIX] Add reference &payload
                    if let Ok(list) = serde_json::from_slice::<Vec<SessionSummary>>(&payload) {
                        return list;
                    }
                }
            }
        }
    }
    Vec::new()
}

pub fn save_local_session_summary(scs: &Arc<Mutex<SovereignContextStore>>, summary: SessionSummary) {
    let mut sessions = get_local_sessions(scs);
    if let Some(pos) = sessions.iter().position(|s| s.session_id == summary.session_id) {
        sessions[pos] = summary;
    } else {
        sessions.push(summary);
    }
    sessions.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

    if let Ok(bytes) = serde_json::to_vec(&sessions) {
        if let Ok(mut store) = scs.lock() {
            let _ = store.append_frame(
                FrameType::System,
                &bytes,
                0,
                [0u8; 32],
                SESSION_INDEX_KEY,
                RetentionClass::Archival // [FIX] Add RetentionClass (Index is vital)
            );
        }
    }
}

fn get_session_storage_key(session_id: &str) -> Option<[u8; 32]> {
    if session_id.len() == 64 {
        if let Ok(bytes) = hex::decode(session_id) {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            return Some(arr);
        }
    }
    match sha256(session_id.as_bytes()) {
        Ok(digest) => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(digest.as_ref());
            Some(arr)
        },
        Err(_) => None
    }
}

pub fn save_local_task_state(scs: &Arc<Mutex<SovereignContextStore>>, task: &AgentTask) {
    let sid = task.session_id.as_deref().unwrap_or(&task.id);
    let key = match get_session_storage_key(sid) {
        Some(k) => k,
        None => return,
    };

    if let Ok(bytes) = serde_json::to_vec(task) {
        if let Ok(mut store) = scs.lock() {
            let _ = store.append_frame(
                FrameType::System,
                &bytes,
                0,
                [0u8; 32],
                key,
                RetentionClass::Ephemeral // [FIX] Task state is snapshots, can be Ephemeral
            );
        }
    }
}

pub fn load_local_task(scs: &Arc<Mutex<SovereignContextStore>>, session_id: &str) -> Option<AgentTask> {
    let key = get_session_storage_key(session_id)?;

    if let Ok(store) = scs.lock() {
        if let Some(frame_ids) = store.session_index.get(&key) {
            if let Some(&last_id) = frame_ids.last() {
                if let Ok(payload) = store.read_frame_payload(last_id) {
                    // [FIX] Add reference &payload
                    if let Ok(task) = serde_json::from_slice::<AgentTask>(&payload) {
                        return Some(task);
                    }
                }
            }
        }
    }
    None
}

pub async fn run_local_graph<F>(
    scs: Arc<Mutex<SovereignContextStore>>, 
    inference: Arc<dyn InferenceRuntime>,
    payload: GraphPayload, 
    emit_event: F
) -> Result<(), String> 
where F: Fn(GraphEvent) + Send + 'static 
{
    if let Some(sid) = &payload.session_id {
        let meta = payload.global_config.as_ref()
            .and_then(|g| g.get("meta"))
            .and_then(|m| m.get("name"))
            .and_then(|s| s.as_str())
            .unwrap_or("Graph Execution");
            
        let summary = SessionSummary {
            session_id: sid.clone(),
            title: meta.to_string(),
            timestamp: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64,
        };
        save_local_session_summary(&scs, summary);
    }

    let globals = payload.global_config.unwrap_or(json!({}));
    let active_session_id = payload.session_id.clone();
    
    let global_env = if let Some(env_val) = globals.get("env") {
        if let Some(s) = env_val.as_str() {
            serde_json::from_str(s).unwrap_or(json!({}))
        } else {
            env_val.clone()
        }
    } else {
        json!({})
    };

    let default_policy = json!({});
    let policy = globals.get("policy").unwrap_or(&default_policy);
    let max_steps = policy.get("maxSteps").and_then(|v| v.as_u64()).unwrap_or(50);
    let timeout_ms = policy.get("timeoutMs").and_then(|v| v.as_u64()).unwrap_or(30_000);

    // [NEW] Extract Governance Tier from Global Policy
    let liability_mode = policy.get("liability").and_then(|s| s.as_str()).unwrap_or("optional");
    let tier = match liability_mode {
        "none" => GovernanceTier::None,
        "required" => GovernanceTier::Strict,
        _ => GovernanceTier::Silent, // Default to "Optional" / Silent
    };

    println!("[Orchestrator] Running graph with Governance Tier: {:?}", tier);

    let start_time = Instant::now();
    let mut step_count = 0;

    let mut adj: HashMap<String, Vec<(String, String)>> = HashMap::new();
    let mut reverse_adj: HashMap<String, Vec<String>> = HashMap::new();
    let mut in_degree: HashMap<String, usize> = HashMap::new();
    let mut node_map: HashMap<String, GraphNode> = HashMap::new();

    for node in payload.nodes {
        let node_id = node.id.clone();
        in_degree.entry(node_id.clone()).or_insert(0);
        node_map.insert(node_id, node);
    }

    for edge in &payload.edges {
        let handle = edge.source_handle.clone().unwrap_or_else(|| "out".to_string());
        adj.entry(edge.source.clone()).or_default().push((handle, edge.target.clone()));
        reverse_adj.entry(edge.target.clone()).or_default().push(edge.source.clone());
        *in_degree.entry(edge.target.clone()).or_default() += 1;
    }

    let mut queue: Vec<String> = node_map.keys()
        .filter(|k| *in_degree.get(*k).unwrap_or(&0) == 0)
        .cloned()
        .collect();

    let mut context: HashMap<String, Value> = HashMap::new();

    while let Some(node_id) = queue.pop() {
        if step_count >= max_steps {
            let msg = format!("🚫 Max Steps ({}) Exceeded.", max_steps);
            emit_event(GraphEvent { 
                node_id: node_id.clone(), 
                status: "error".into(), 
                result: Some(ExecutionResult { 
                    status: "error".into(), 
                    output: msg, 
                    data: None, 
                    metrics: None, 
                    input_snapshot: None,
                    context_slice: None // [FIX] Added missing field
                }), 
                fitness_score: None, 
                generation: None 
            });
            break;
        }
        if start_time.elapsed() > Duration::from_millis(timeout_ms) {
            let msg = format!("⏱️ Timeout ({}ms) Exceeded.", timeout_ms);
            emit_event(GraphEvent { 
                node_id: node_id.clone(), 
                status: "error".into(), 
                result: Some(ExecutionResult { 
                    status: "error".into(), 
                    output: msg, 
                    data: None, 
                    metrics: None, 
                    input_snapshot: None,
                    context_slice: None // [FIX] Added missing field
                }), 
                fitness_score: None, 
                generation: None 
            });
            break;
        }

        step_count += 1;
        let node = node_map.get(&node_id).ok_or("Node missing")?;
        
        let mut parent_outputs = Vec::new();
        if let Some(parents) = reverse_adj.get(&node_id) {
            for parent_id in parents {
                if let Some(output_val) = context.get(parent_id) {
                    parent_outputs.push(output_val.clone());
                }
            }
        }
        
        let effective_input = merge_inputs(parent_outputs, &global_env);
        let input_str = effective_input.to_string();
        let default_config = json!({});
        let config = node.config.as_ref().unwrap_or(&default_config);
        
        // --- CACHE CHECK (Persistent) ---
        let result_opt = query_cache(&scs, node_id.clone(), config.clone(), input_str.clone());

        if let Some(mut result) = result_opt {
            let output_val: Value = if let Some(data) = &result.data { data.clone() } else { json!({"raw": result.output}) };
            context.insert(node_id.clone(), output_val);
            result.input_snapshot = Some(effective_input.clone());

            let active_handle = match result.status.as_str() {
                "success" => "out",       
                "blocked" => "blocked",   
                "failed" | "error" => "error", 
                _ => "out",
            };
            
            emit_event(GraphEvent { 
                node_id: node_id.clone(), 
                status: "cached".into(), 
                result: Some(result),
                fitness_score: None,
                generation: None
            });
            
            if let Some(children) = adj.get(&node_id) {
                for (edge_handle, child_id) in children {
                    let is_active_path = edge_handle == active_handle 
                        || (active_handle == "out" && (edge_handle == "source" || edge_handle == "out")); 
                    if is_active_path {
                        if let Some(degree) = in_degree.get_mut(child_id) {
                            if *degree > 0 {
                                *degree -= 1;
                                if *degree == 0 {
                                    queue.push(child_id.clone());
                                }
                            }
                        }
                    }
                }
            }
            continue; 
        }

        emit_event(GraphEvent { node_id: node_id.clone(), status: "running".into(), result: None, fitness_score: None, generation: None });

        match execution::execute_ephemeral_node(
            &node.node_type, 
            config, 
            &input_str, 
            active_session_id.clone(), 
            scs.clone(), 
            inference.clone(), // [FIX] Passed inference
            tier // [NEW] Pass tier
        ).await {
            Ok(mut res) => {
                res.input_snapshot = Some(effective_input.clone());
                let output_val: Value = if let Some(data) = &res.data { data.clone() } else { json!({"raw": res.output}) };
                context.insert(node_id.clone(), output_val);
                
                let active_handle = match res.status.as_str() {
                    "success" => "out",       
                    "blocked" => "blocked",   
                    "failed" | "error" => "error", 
                    _ => "out",
                };

                inject_execution_result(&scs, node_id.clone(), config.clone(), input_str.clone(), res.clone());
                
                let mut fitness_score = None;
                let mut generation = None;
                if let Some(metrics) = &res.metrics {
                    if let Some(score) = metrics.get("fitness_score").and_then(|v| v.as_f64()) {
                        fitness_score = Some(score as f32);
                    }
                    if let Some(gen) = metrics.get("generation").and_then(|v| v.as_u64()) {
                        generation = Some(gen);
                    }
                }

                emit_event(GraphEvent { 
                    node_id: node_id.clone(), 
                    status: res.status.clone(), 
                    result: Some(res.clone()),
                    fitness_score,
                    generation
                });

                if let Some(children) = adj.get(&node_id) {
                    for (edge_handle, child_id) in children {
                        let is_active_path = edge_handle == active_handle 
                            || (active_handle == "out" && (edge_handle == "source" || edge_handle == "out")); 

                        if is_active_path {
                            if let Some(degree) = in_degree.get_mut(child_id) {
                                if *degree > 0 {
                                    *degree -= 1;
                                    if *degree == 0 {
                                        queue.push(child_id.clone());
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => {
                emit_event(GraphEvent { 
                    node_id: node_id.clone(), 
                    status: "error".into(), 
                    result: Some(ExecutionResult { 
                        status: "error".into(), 
                        output: format!("Error: {}", e), 
                        data: None, 
                        metrics: None,
                        input_snapshot: Some(effective_input.clone()),
                        context_slice: None // [FIX] Added missing field
                    }),
                    fitness_score: None,
                    generation: None
                });
            }
        }
    }

    Ok(())
}