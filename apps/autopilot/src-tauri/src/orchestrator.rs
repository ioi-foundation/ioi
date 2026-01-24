// apps/autopilot/src-tauri/src/orchestrator.rs

use crate::execution::{self, ExecutionResult};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::time::{Instant, Duration};
use std::sync::{Arc, Mutex};
use ioi_crypto::algorithms::hash::sha256;
use ioi_scs::{SovereignContextStore, FrameType}; 
use dcrypt::algorithms::ByteSerializable; // For copy_from_slice
use hex; // Ensure hex is imported

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
}

#[derive(Serialize, Clone)]
pub struct GraphEvent {
    pub node_id: String,
    pub status: String, 
    pub result: Option<ExecutionResult>,
    pub fitness_score: Option<f32>,
    pub generation: Option<u64>,
}

// --- GLOBAL EXECUTION CACHE (Memoization Layer) ---
// Maps hex(hash(NodeID + Config + Input)) -> ExecutionResult
static GLOBAL_EXECUTION_CACHE: once_cell::sync::Lazy<Mutex<HashMap<String, ExecutionResult>>> = once_cell::sync::Lazy::new(|| {
    Mutex::new(HashMap::new())
});

/// Helper: Merges Global Environment variables with Parent Outputs.
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

/// Computes a deterministic cache key for a node execution state (SHA-256).
pub fn compute_cache_key(node_id: &str, config: &Value, input_str: &str) -> [u8; 32] {
    let config_str = serde_json::to_string(config).unwrap_or_default();
    let preimage = format!("{}|{}|{}", node_id, config_str, input_str);
    
    match sha256(preimage.as_bytes()) {
        Ok(digest) => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(digest.as_ref());
            arr
        },
        Err(_) => [0u8; 32], // Fallback
    }
}

/// Retrieves a cached execution result from the persistent SCS.
fn fetch_cached_result(
    scs: &Arc<Mutex<SovereignContextStore>>,
    cache_key: [u8; 32]
) -> Option<ExecutionResult> {
    let store = scs.lock().ok()?;
    
    // We abuse the `session_index` to look up frames by "Input Hash".
    // In Studio mode, Session ID == Input Hash.
    if let Some(frame_ids) = store.session_index.get(&cache_key) {
        if let Some(&last_id) = frame_ids.last() {
            if let Ok(payload) = store.read_frame_payload(last_id) {
                if let Ok(result) = serde_json::from_slice::<ExecutionResult>(payload) {
                    return Some(result);
                }
            }
        }
    }
    None
}

/// Persists an execution result to the SCS.
fn persist_execution_result(
    scs: &Arc<Mutex<SovereignContextStore>>,
    cache_key: [u8; 32],
    result: &ExecutionResult
) {
    if let Ok(mut store) = scs.lock() {
        if let Ok(bytes) = serde_json::to_vec(result) {
            // Write as a System frame, tagged with the Input Hash as session_id
            let _ = store.append_frame(
                FrameType::System, 
                &bytes, 
                0, 
                [0u8; 32], 
                cache_key // This enables the lookup in fetch_cached_result
            );
        }
    }
}

/// [NEW] Queries the cache for a specific node configuration.
pub fn query_cache(
    scs: &Arc<Mutex<SovereignContextStore>>,
    node_id: String,
    config: Value,
    input_str: String,
) -> Option<ExecutionResult> {
    let key_bytes = compute_cache_key(&node_id, &config, &input_str);
    let key_hex = hex::encode(key_bytes);
    
    // 1. Check RAM Cache (Fast Path)
    {
        let cache = GLOBAL_EXECUTION_CACHE.lock().unwrap();
        if let Some(res) = cache.get(&key_hex) {
            return Some(res.clone());
        }
    }

    // 2. Check Persistent SCS (Cold Path)
    let res = fetch_cached_result(scs, key_bytes);
    
    // If found in disk, warm up RAM cache
    if let Some(r) = &res {
        let mut cache = GLOBAL_EXECUTION_CACHE.lock().unwrap();
        cache.insert(key_hex, r.clone());
    }
    
    res
}

/// [NEW] Manually injects a successful execution result into the global cache.
pub fn inject_execution_result(
    scs: &Arc<Mutex<SovereignContextStore>>, // [MODIFIED] Accepts SCS
    node_id: String,
    config: Value,
    input_str: String,
    result: ExecutionResult
) {
    let key_bytes = compute_cache_key(&node_id, &config, &input_str);
    let key_hex = hex::encode(key_bytes);

    // 1. Update RAM
    {
        let mut cache = GLOBAL_EXECUTION_CACHE.lock().unwrap();
        cache.insert(key_hex, result.clone());
    }

    // 2. Persist to Disk
    persist_execution_result(scs, key_bytes, &result);
    println!("[Orchestrator] Persisted result for node: {}", node_id);
}

/// Runs a topological sort execution of the graph defined in the Studio.
pub async fn run_local_graph<F>(
    scs: Arc<Mutex<SovereignContextStore>>, // [MODIFIED] Accepts SCS
    payload: GraphPayload, 
    emit_event: F
) -> Result<(), String> 
where F: Fn(GraphEvent) + Send + 'static 
{
    let globals = payload.global_config.unwrap_or(json!({}));
    
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
            emit_event(GraphEvent { node_id: node_id.clone(), status: "error".into(), result: Some(ExecutionResult { status: "error".into(), output: msg, data: None, metrics: None, input_snapshot: None }), fitness_score: None, generation: None });
            break;
        }
        if start_time.elapsed() > Duration::from_millis(timeout_ms) {
            let msg = format!("⏱️ Timeout ({}ms) Exceeded.", timeout_ms);
            emit_event(GraphEvent { node_id: node_id.clone(), status: "error".into(), result: Some(ExecutionResult { status: "error".into(), output: msg, data: None, metrics: None, input_snapshot: None }), fitness_score: None, generation: None });
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
            // [HIT]
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

        // [MISS] Execution
        emit_event(GraphEvent { node_id: node_id.clone(), status: "running".into(), result: None, fitness_score: None, generation: None });

        match execution::execute_ephemeral_node(&node.node_type, config, &input_str).await {
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

                // [MODIFIED] Persist to SCS using the public injection method to ensure consistency
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
                        input_snapshot: Some(effective_input.clone()) 
                    }),
                    fitness_score: None,
                    generation: None
                });
            }
        }
    }

    Ok(())
}