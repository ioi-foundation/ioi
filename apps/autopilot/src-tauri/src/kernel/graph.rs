use crate::execution;
use crate::models::AppState;
use crate::orchestrator::{self, GraphPayload};
use std::sync::Mutex;
use tauri::{Emitter, State};

#[tauri::command]
pub async fn run_studio_graph(
    state: State<'_, Mutex<AppState>>,
    app: tauri::AppHandle,
    payload: GraphPayload,
) -> Result<(), String> {
    println!(
        "[Studio] Received Graph with {} nodes. Starting local execution...",
        payload.nodes.len()
    );

    let (memory_runtime, inference) = {
        let guard = state.lock().map_err(|_| "Failed to lock state")?;
        let memory_runtime = guard.memory_runtime.clone();
        let i = guard
            .inference_runtime
            .clone()
            .ok_or("Inference runtime not initialized")?;
        let memory_runtime = memory_runtime.ok_or("Memory runtime not initialized")?;
        (memory_runtime, i)
    };

    let app_handle = app.clone();

    tauri::async_runtime::spawn(async move {
        let result =
            orchestrator::run_local_graph(memory_runtime, inference, payload, move |event| {
                let _ = app_handle.emit("graph-event", event);
            })
            .await;

        if let Err(e) = result {
            eprintln!("[Studio] Orchestrator Runtime Error: {}", e);
        } else {
            println!("[Studio] Graph execution completed successfully.");
        }
    });

    Ok(())
}

#[tauri::command]
pub async fn test_node_execution(
    state: State<'_, Mutex<AppState>>,
    node_type: String,
    config: serde_json::Value,
    input: serde_json::Value,
    node_id: Option<String>,
    session_id: Option<String>,
    global_config: Option<serde_json::Value>,
) -> Result<serde_json::Value, String> {
    println!(
        "[Studio] Running Ephemeral Execution: {} (Session: {:?})",
        node_type, session_id
    );

    let (memory_runtime, inference) = {
        let guard = state.lock().map_err(|_| "Failed to lock state")?;
        let memory_runtime = guard
            .memory_runtime
            .clone()
            .ok_or("Memory runtime not initialized")?;
        let i = guard
            .inference_runtime
            .clone()
            .ok_or("Inference runtime not initialized")?;
        (memory_runtime, i)
    };

    let registry_state = orchestrator::load_local_engine_registry_state(&memory_runtime);
    let resolved_config = match orchestrator::resolve_node_execution_config(
        &node_type,
        &config,
        global_config.as_ref(),
        registry_state.as_ref(),
    ) {
        Ok(resolved) => resolved,
        Err(error) => {
            return Ok(serde_json::json!({
                "status": "error",
                "output": error,
                "data": null,
                "metrics": { "latency_ms": 0 }
            }));
        }
    };

    let input_str = if let Some(s) = input.as_str() {
        s.to_string()
    } else {
        input.to_string()
    };

    let tier = execution::GovernanceTier::Silent;

    match execution::execute_ephemeral_node(
        &node_type,
        &resolved_config,
        &input_str,
        session_id,
        memory_runtime.clone(),
        inference,
        tier,
    )
    .await
    {
        Ok(result) => {
            if result.status == "success" {
                if let Some(nid) = node_id {
                    orchestrator::inject_execution_result(
                        &memory_runtime,
                        nid,
                        resolved_config,
                        input_str,
                        result.clone(),
                    );
                }
            }
            serde_json::to_value(result).map_err(|e| e.to_string())
        }
        Err(e) => {
            eprintln!("[Studio] Execution Error: {}", e);
            Ok(serde_json::json!({
                "status": "error",
                "output": format!("Execution Logic Failed: {}", e),
                "data": null,
                "metrics": { "latency_ms": 0 }
            }))
        }
    }
}

#[tauri::command]
pub async fn check_node_cache(
    state: State<'_, Mutex<AppState>>,
    node_id: String,
    config: serde_json::Value,
    input: String,
) -> Result<Option<execution::ExecutionResult>, String> {
    let memory_runtime = {
        let guard = state.lock().map_err(|_| "Failed to lock state")?;
        guard
            .memory_runtime
            .clone()
            .ok_or("Memory runtime not initialized")?
    };

    Ok(orchestrator::query_cache(
        &memory_runtime,
        node_id,
        config,
        input,
    ))
}
