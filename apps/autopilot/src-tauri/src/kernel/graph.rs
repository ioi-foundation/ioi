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

    let (scs, inference) = {
        let guard = state.lock().map_err(|_| "Failed to lock state")?;
        let s = guard
            .studio_scs
            .clone()
            .ok_or("Studio SCS not initialized")?;
        let i = guard
            .inference_runtime
            .clone()
            .ok_or("Inference runtime not initialized")?;
        (s, i)
    };

    let app_handle = app.clone();

    tauri::async_runtime::spawn(async move {
        // [MODIFIED] Pass inference to run_local_graph
        let result = orchestrator::run_local_graph(scs, inference, payload, move |event| {
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
) -> Result<serde_json::Value, String> {
    println!(
        "[Studio] Running Ephemeral Execution: {} (Session: {:?})",
        node_type, session_id
    );

    let (scs, inference) = {
        let guard = state.lock().map_err(|_| "Failed to lock state")?;
        let s = guard
            .studio_scs
            .clone()
            .ok_or("Studio SCS not initialized")?;
        let i = guard
            .inference_runtime
            .clone()
            .ok_or("Inference runtime not initialized")?;
        (s, i)
    };

    let input_str = if let Some(s) = input.as_str() {
        s.to_string()
    } else {
        input.to_string()
    };

    let tier = execution::GovernanceTier::Silent;

    match execution::execute_ephemeral_node(
        &node_type,
        &config,
        &input_str,
        session_id,
        scs.clone(),
        inference,
        tier,
    )
    .await
    {
        Ok(result) => {
            if result.status == "success" {
                if let Some(nid) = node_id {
                    orchestrator::inject_execution_result(
                        &scs,
                        nid,
                        config,
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
    let scs = {
        let guard = state.lock().map_err(|_| "Failed to lock state")?;
        guard
            .studio_scs
            .clone()
            .ok_or("Studio SCS not initialized")?
    };

    Ok(orchestrator::query_cache(&scs, node_id, config, input))
}
