use super::cache::{inject_execution_result, query_cache};
use super::store::save_local_session_summary;
use crate::execution::{self, ExecutionResult, GovernanceTier};
use crate::models::SessionSummary;
use ioi_api::vm::inference::InferenceRuntime;
use ioi_scs::SovereignContextStore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

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

fn extract_governance_tier(policy: &Value) -> GovernanceTier {
    let liability_mode = policy
        .get("liability")
        .and_then(|s| s.as_str())
        .unwrap_or("optional");

    match liability_mode {
        "none" => GovernanceTier::None,
        "required" => GovernanceTier::Strict,
        _ => GovernanceTier::Silent,
    }
}

fn output_value_for_result(result: &ExecutionResult) -> Value {
    if let Some(data) = &result.data {
        data.clone()
    } else {
        json!({"raw": result.output})
    }
}

fn router_route_from_result(result: &ExecutionResult) -> Option<String> {
    result
        .data
        .as_ref()
        .and_then(|d| d.get("route").and_then(|v| v.as_str()))
        .map(str::to_string)
        .or_else(|| {
            let trimmed = result.output.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        })
}

fn active_handle_for_result(node_type: &str, result: &ExecutionResult) -> String {
    match result.status.as_str() {
        "success" if node_type == "router" => {
            router_route_from_result(result).unwrap_or_else(|| "out".to_string())
        }
        "success" => "out".to_string(),
        "blocked" => "blocked".to_string(),
        "failed" | "error" => "error".to_string(),
        _ => "out".to_string(),
    }
}

fn enqueue_active_children(
    adj: &HashMap<String, Vec<(String, String)>>,
    in_degree: &mut HashMap<String, usize>,
    queue: &mut Vec<String>,
    node_id: &str,
    active_handle: &str,
) {
    if let Some(children) = adj.get(node_id) {
        for (edge_handle, child_id) in children {
            let is_active_path = edge_handle == active_handle
                || (active_handle == "out" && (edge_handle == "source" || edge_handle == "out"));

            if !is_active_path {
                continue;
            }

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

fn extract_evolution_metrics(metrics: &Option<Value>) -> (Option<f32>, Option<u64>) {
    let Some(metrics) = metrics else {
        return (None, None);
    };

    let fitness_score = metrics
        .get("fitness_score")
        .and_then(|v| v.as_f64())
        .map(|v| v as f32);
    let generation = metrics.get("generation").and_then(|v| v.as_u64());

    (fitness_score, generation)
}

fn error_result(output: String, input_snapshot: Option<Value>) -> ExecutionResult {
    ExecutionResult {
        status: "error".into(),
        output,
        data: None,
        metrics: None,
        input_snapshot,
        context_slice: None,
    }
}

pub async fn run_local_graph<F>(
    scs: Arc<Mutex<SovereignContextStore>>,
    inference: Arc<dyn InferenceRuntime>,
    payload: GraphPayload,
    emit_event: F,
) -> Result<(), String>
where
    F: Fn(GraphEvent) + Send + 'static,
{
    if let Some(sid) = &payload.session_id {
        let title = payload
            .global_config
            .as_ref()
            .and_then(|g| g.get("meta"))
            .and_then(|m| m.get("name"))
            .and_then(|s| s.as_str())
            .unwrap_or("Graph Execution")
            .to_string();

        let summary = SessionSummary {
            session_id: sid.clone(),
            title,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
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
    let max_steps = policy
        .get("maxSteps")
        .and_then(|v| v.as_u64())
        .unwrap_or(50);
    let timeout_ms = policy
        .get("timeoutMs")
        .and_then(|v| v.as_u64())
        .unwrap_or(30_000);
    let tier = extract_governance_tier(policy);

    println!(
        "[Orchestrator] Running graph with Governance Tier: {:?}",
        tier
    );

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
        let handle = edge
            .source_handle
            .clone()
            .unwrap_or_else(|| "out".to_string());

        adj.entry(edge.source.clone())
            .or_default()
            .push((handle, edge.target.clone()));
        reverse_adj
            .entry(edge.target.clone())
            .or_default()
            .push(edge.source.clone());
        *in_degree.entry(edge.target.clone()).or_default() += 1;
    }

    let mut queue: Vec<String> = node_map
        .keys()
        .filter(|k| *in_degree.get(*k).unwrap_or(&0) == 0)
        .cloned()
        .collect();

    let mut context: HashMap<String, Value> = HashMap::new();

    while let Some(node_id) = queue.pop() {
        if step_count >= max_steps {
            emit_event(GraphEvent {
                node_id,
                status: "error".into(),
                result: Some(error_result(
                    format!("🚫 Max Steps ({}) Exceeded.", max_steps),
                    None,
                )),
                fitness_score: None,
                generation: None,
            });
            break;
        }

        if start_time.elapsed() > Duration::from_millis(timeout_ms) {
            emit_event(GraphEvent {
                node_id,
                status: "error".into(),
                result: Some(error_result(
                    format!("⏱️ Timeout ({}ms) Exceeded.", timeout_ms),
                    None,
                )),
                fitness_score: None,
                generation: None,
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

        if let Some(mut result) =
            query_cache(&scs, node_id.clone(), config.clone(), input_str.clone())
        {
            result.input_snapshot = Some(effective_input.clone());
            context.insert(node_id.clone(), output_value_for_result(&result));

            let active_handle = active_handle_for_result(&node.node_type, &result);

            emit_event(GraphEvent {
                node_id: node_id.clone(),
                status: "cached".into(),
                result: Some(result),
                fitness_score: None,
                generation: None,
            });

            enqueue_active_children(&adj, &mut in_degree, &mut queue, &node_id, &active_handle);
            continue;
        }

        emit_event(GraphEvent {
            node_id: node_id.clone(),
            status: "running".into(),
            result: None,
            fitness_score: None,
            generation: None,
        });

        match execution::execute_ephemeral_node(
            &node.node_type,
            config,
            &input_str,
            active_session_id.clone(),
            scs.clone(),
            inference.clone(),
            tier,
        )
        .await
        {
            Ok(mut result) => {
                result.input_snapshot = Some(effective_input.clone());
                context.insert(node_id.clone(), output_value_for_result(&result));

                let active_handle = active_handle_for_result(&node.node_type, &result);

                inject_execution_result(
                    &scs,
                    node_id.clone(),
                    config.clone(),
                    input_str.clone(),
                    result.clone(),
                );

                let (fitness_score, generation) = extract_evolution_metrics(&result.metrics);

                emit_event(GraphEvent {
                    node_id: node_id.clone(),
                    status: result.status.clone(),
                    result: Some(result),
                    fitness_score,
                    generation,
                });

                enqueue_active_children(&adj, &mut in_degree, &mut queue, &node_id, &active_handle);
            }
            Err(e) => {
                emit_event(GraphEvent {
                    node_id,
                    status: "error".into(),
                    result: Some(error_result(
                        format!("Error: {}", e),
                        Some(effective_input.clone()),
                    )),
                    fitness_score: None,
                    generation: None,
                });
            }
        }
    }

    Ok(())
}
