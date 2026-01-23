// src-tauri/src/orchestrator.rs

use crate::execution::{self, ExecutionResult};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::time::{Instant, Duration};

#[derive(Debug, Deserialize, Clone)]
pub struct GraphNode {
    pub id: String,
    #[serde(rename = "type")]
    pub node_type: String,
    pub config: Option<Value>,
}

#[derive(Debug, Deserialize, Clone)]
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
    // The Global Constitution
    pub global_config: Option<Value>,
}

// [FIX] Derive Clone so we can emit it via Tauri Event
#[derive(Serialize, Clone)]
pub struct GraphEvent {
    pub node_id: String,
    pub status: String, // "running", "success", "failed", "blocked"
    pub result: Option<ExecutionResult>,
}

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

/// Runs a topological sort execution of the graph defined in the Studio.
pub async fn run_local_graph<F>(
    payload: GraphPayload, 
    emit_event: F
) -> Result<(), String> 
where F: Fn(GraphEvent) + Send + 'static 
{
    let globals = payload.global_config.unwrap_or(json!({}));
    
    // Parse Env safely
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

    // --- Graph Construction ---
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

    // --- Execution ---
    let mut queue: Vec<String> = node_map.keys()
        .filter(|k| *in_degree.get(*k).unwrap_or(&0) == 0)
        .cloned()
        .collect();

    let mut context: HashMap<String, Value> = HashMap::new();

    while let Some(node_id) = queue.pop() {
        if step_count >= max_steps {
            let msg = format!("🚫 Max Steps ({}) Exceeded.", max_steps);
            emit_event(GraphEvent { node_id: node_id.clone(), status: "error".into(), result: Some(ExecutionResult { status: "error".into(), output: msg, data: None, metrics: None }) });
            break;
        }
        if start_time.elapsed() > Duration::from_millis(timeout_ms) {
            let msg = format!("⏱️ Timeout ({}ms) Exceeded.", timeout_ms);
            emit_event(GraphEvent { node_id: node_id.clone(), status: "error".into(), result: Some(ExecutionResult { status: "error".into(), output: msg, data: None, metrics: None }) });
            break;
        }

        step_count += 1;
        let node = node_map.get(&node_id).ok_or("Node missing")?;
        
        emit_event(GraphEvent { node_id: node_id.clone(), status: "running".into(), result: None });

        // Resolve Inputs
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
        
        // Execute
        match execution::execute_ephemeral_node(&node.node_type, config, &input_str).await {
            Ok(res) => {
                let output_val = if let Some(data) = &res.data { data.clone() } else { json!({"raw": res.output}) };
                context.insert(node_id.clone(), output_val);
                
                let active_handle = match res.status.as_str() {
                    "success" => "out",       
                    "blocked" => "blocked",   
                    "failed" | "error" => "error", 
                    _ => "out",
                };

                emit_event(GraphEvent { node_id: node_id.clone(), status: res.status.clone(), result: Some(res.clone()) });

                // Propagate
                if let Some(children) = adj.get(&node_id) {
                    for (edge_handle, child_id) in children {
                        // Semantic Branching Logic
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
                emit_event(GraphEvent { node_id: node_id.clone(), status: "error".into(), result: Some(ExecutionResult { status: "error".into(), output: format!("Error: {}", e), data: None, metrics: None }) });
            }
        }
    }

    Ok(())
}