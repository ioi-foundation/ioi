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
    // Capture the semantic port from ReactFlow (e.g., "out", "blocked", "error")
    #[serde(rename = "sourceHandle")] 
    pub source_handle: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct GraphPayload {
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
    // [NEW] Global Constitution: Env vars and Policy constraints
    pub global_config: Option<Value>,
}

#[derive(Serialize, Clone)]
pub struct GraphEvent {
    pub node_id: String,
    pub status: String, // "running", "success", "failed", "blocked"
    pub result: Option<ExecutionResult>,
}

/// Helper: Merges Global Environment variables with Parent Outputs.
/// Global variables act as the "Base Layer" of the context.
/// Parent outputs override globals if keys collide.
fn merge_inputs(parent_outputs: Vec<Value>, global_env: &Value) -> Value {
    // 1. Start with Global Context
    let mut merged_map = if let Value::Object(map) = global_env {
        map.clone()
    } else {
        serde_json::Map::new()
    };

    // 2. Merge Parent Outputs
    if parent_outputs.is_empty() {
        // If no parents, we still return globals, plus a manual trigger flag
        merged_map.insert("manual_trigger".to_string(), json!(true));
        return Value::Object(merged_map);
    }

    // 3. Flatten inputs
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
/// This is a "Local/Ephemeral" run, distinct from the persistent Kernel session.
pub async fn run_local_graph<F>(
    payload: GraphPayload, 
    emit_event: F
) -> Result<(), String> 
where F: Fn(GraphEvent) + Send + 'static 
{
    // --- 0. Parse Global Constitution ---
    let globals = payload.global_config.unwrap_or(json!({}));
    
    // Parse Env (sent as stringified JSON from frontend textarea)
    let global_env_str = globals.get("env").and_then(|v| v.as_str()).unwrap_or("{}");
    let global_env: Value = serde_json::from_str(global_env_str).unwrap_or_else(|_| {
        eprintln!("[Orchestrator] Warning: Invalid Global Env JSON");
        json!({})
    });

    // Parse Policies
    let policy = globals.get("policy").unwrap_or(&json!({}));
    let max_steps = policy.get("maxSteps").and_then(|v| v.as_u64()).unwrap_or(50);
    let timeout_ms = policy.get("timeoutMs").and_then(|v| v.as_u64()).unwrap_or(30_000);
    // let max_budget = policy.get("maxBudget").and_then(|v| v.as_f64()).unwrap_or(5.0); // Future use

    let start_time = Instant::now();
    let mut step_count = 0;

    // --- 1. Graph Construction ---
    
    // Map: SourceNode -> List of (SourceHandle, TargetNode)
    let mut adj: HashMap<String, Vec<(String, String)>> = HashMap::new();
    
    // Map: TargetNode -> List of SourceNodes (Used for input data aggregation)
    let mut reverse_adj: HashMap<String, Vec<String>> = HashMap::new();
    
    // Map: NodeId -> Number of unmet dependencies
    let mut in_degree: HashMap<String, usize> = HashMap::new();
    
    let mut node_map: HashMap<String, GraphNode> = HashMap::new();

    for node in payload.nodes {
        let node_id = node.id.clone();
        // Initialize in_degree to 0 using cloned ID
        in_degree.entry(node_id.clone()).or_insert(0);
        // Move node into map
        node_map.insert(node_id, node);
    }

    for edge in &payload.edges {
        let handle = edge.source_handle.clone().unwrap_or_else(|| "out".to_string());
        
        // Forward Graph
        adj.entry(edge.source.clone())
           .or_default()
           .push((handle, edge.target.clone()));
           
        // Reverse Graph (for context)
        reverse_adj.entry(edge.target.clone())
            .or_default()
            .push(edge.source.clone());
           
        *in_degree.entry(edge.target.clone()).or_default() += 1;
    }

    // --- 2. Initialization ---
    
    // Nodes with 0 in-degree are start nodes (e.g. Triggers)
    let mut queue: Vec<String> = node_map.keys()
        .filter(|k| *in_degree.get(*k).unwrap_or(&0) == 0)
        .cloned()
        .collect();

    // Store outputs: NodeId -> Structured Value
    let mut context: HashMap<String, Value> = HashMap::new();

    // --- 3. Execution Loop ---
    
    while let Some(node_id) = queue.pop() {
        // --- A. Global Governance Checks ---
        
        // Check 1: Step Limit
        if step_count >= max_steps {
            let msg = format!("🚫 Execution Halted: Max Steps ({}) Exceeded.", max_steps);
            eprintln!("[Orchestrator] {}", msg);
            emit_event(GraphEvent { 
                node_id: node_id.clone(), 
                status: "error".into(), 
                result: Some(ExecutionResult { status: "error".into(), output: msg, data: None, metrics: None }) 
            });
            break;
        }

        // Check 2: Timeout
        if start_time.elapsed() > Duration::from_millis(timeout_ms) {
            let msg = format!("⏱️ Execution Halted: Global Timeout ({}ms) Exceeded.", timeout_ms);
            eprintln!("[Orchestrator] {}", msg);
            emit_event(GraphEvent { 
                node_id: node_id.clone(), 
                status: "error".into(), 
                result: Some(ExecutionResult { status: "error".into(), output: msg, data: None, metrics: None }) 
            });
            break;
        }

        step_count += 1;

        let node = node_map.get(&node_id).ok_or("Node missing in map")?;
        
        // Notify UI: Node Started
        emit_event(GraphEvent { 
            node_id: node_id.clone(), 
            status: "running".into(), 
            result: None 
        });

        // --- B. Input Resolution ---
        // Fetch outputs ONLY from direct parents defined in the graph
        let mut parent_outputs = Vec::new();
        if let Some(parents) = reverse_adj.get(&node_id) {
            for parent_id in parents {
                if let Some(output_val) = context.get(parent_id) {
                    parent_outputs.push(output_val.clone());
                }
            }
        }
        
        // Merge inputs (Parents + Global Env) into a single JSON Value
        let effective_input_json = merge_inputs(parent_outputs, &global_env);
        
        // Serialize to string for the execution module
        let input_str = effective_input_json.to_string();

        let default_config = json!({});
        let config = node.config.as_ref().unwrap_or(&default_config);
        
        // --- C. Execute Logic ---
        match execution::execute_ephemeral_node(&node.node_type, config, &input_str).await {
            Ok(res) => {
                let output_val = if let Some(data) = &res.data {
                    data.clone()
                } else {
                    serde_json::from_str(&res.output).unwrap_or(json!({ "raw": res.output }))
                };

                context.insert(node_id.clone(), output_val);
                
                // Map Execution Status to Graph Handle
                let active_handle = match res.status.as_str() {
                    "success" => "out",       
                    "blocked" => "blocked",   
                    "failed" | "error" => "error", 
                    _ => "out",
                };

                // Notify UI: Node Finished
                emit_event(GraphEvent { 
                    node_id: node_id.clone(), 
                    status: res.status.clone(), 
                    result: Some(res.clone()) 
                });

                println!("[Orchestrator] Node {} finished: {}. Active handle: '{}'", node_id, res.status, active_handle);

                // --- D. Propagate to Children ---
                if let Some(children) = adj.get(&node_id) {
                    for (edge_handle, child_id) in children {
                        // CRITICAL: Semantic Branching
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
                        output: format!("Runtime Exception: {}", e), 
                        data: None, 
                        metrics: None 
                    }) 
                });
                eprintln!("[Orchestrator] Critical Failure at Node {}: {}", node_id, e);
            }
        }
    }

    Ok(())
}