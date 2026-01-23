// src-tauri/src/orchestrator.rs

use crate::execution::{self, ExecutionResult};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;

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
    // "source" is the default handle name in ReactFlow if none is specified
    #[serde(rename = "sourceHandle")] 
    pub source_handle: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct GraphPayload {
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
}

#[derive(Serialize, Clone)]
pub struct GraphEvent {
    pub node_id: String,
    pub status: String, // "running", "success", "failed", "blocked"
    pub result: Option<ExecutionResult>,
}

/// Helper: Deterministically merges multiple parent outputs into a single JSON Value.
fn merge_inputs(parent_outputs: Vec<Value>) -> Value {
    if parent_outputs.is_empty() {
        return json!({ "manual_trigger": true });
    }

    if parent_outputs.len() == 1 {
        return parent_outputs[0].clone();
    }

    // Check if all are objects to perform a shallow merge
    if parent_outputs.iter().all(|v| v.is_object()) {
        let mut merged = serde_json::Map::new();
        for output in parent_outputs {
            if let Value::Object(map) = output {
                for (k, v) in map {
                    merged.insert(k, v);
                }
            }
        }
        return Value::Object(merged);
    }

    // Fallback: Array of results
    Value::Array(parent_outputs)
}

/// Runs a topological sort execution of the graph defined in the Studio.
/// This is a "Local/Ephemeral" run, distinct from the persistent Kernel session.
pub async fn run_local_graph<F>(
    payload: GraphPayload, 
    emit_event: F
) -> Result<(), String> 
where F: Fn(GraphEvent) + Send + 'static 
{
    // --- 1. Graph Construction ---
    
    // Map: SourceNode -> List of (SourceHandle, TargetNode)
    let mut adj: HashMap<String, Vec<(String, String)>> = HashMap::new();
    
    // Map: TargetNode -> List of SourceNodes (Used for input data aggregation)
    let mut reverse_adj: HashMap<String, Vec<String>> = HashMap::new();
    
    // Map: NodeId -> Number of unmet dependencies
    let mut in_degree: HashMap<String, usize> = HashMap::new();
    
    let mut node_map: HashMap<String, GraphNode> = HashMap::new();

    // [FIX] Ownership issue resolved here
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
        let node = node_map.get(&node_id).ok_or("Node missing in map")?;
        
        // Notify UI: Node Started
        emit_event(GraphEvent { 
            node_id: node_id.clone(), 
            status: "running".into(), 
            result: None 
        });

        // --- Input Resolution ---
        // Fetch outputs ONLY from direct parents defined in the graph
        let mut parent_outputs = Vec::new();
        if let Some(parents) = reverse_adj.get(&node_id) {
            for parent_id in parents {
                if let Some(output_val) = context.get(parent_id) {
                    parent_outputs.push(output_val.clone());
                }
            }
        }
        
        // Merge inputs into a single JSON Value
        let effective_input_json = merge_inputs(parent_outputs);
        
        // Serialize to string for the execution module
        let input_str = effective_input_json.to_string();

        let default_config = json!({});
        let config = node.config.as_ref().unwrap_or(&default_config);
        
        // --- Execute Logic ---
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

                // --- Propagate to Children ---
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