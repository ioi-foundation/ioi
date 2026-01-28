use crate::kernel::state::get_rpc_client;
use crate::models::{AppState, ContextBlob};
use crate::execution;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ioi_ipc::public::GetContextBlobRequest;
use ioi_types::app::agentic::LlmToolDefinition;
use std::sync::Mutex;
use tauri::State;

#[tauri::command]
pub async fn get_available_tools() -> Result<Vec<LlmToolDefinition>, String> {
    Ok(execution::get_active_mcp_tools().await)
}

#[tauri::command]
pub async fn get_context_blob(
    state: State<'_, Mutex<AppState>>,
    hash: String,
) -> Result<ContextBlob, String> {
    let mut client = get_rpc_client(&state).await?;

    let request = tonic::Request::new(GetContextBlobRequest { blob_hash: hash });

    let response = client
        .get_context_blob(request)
        .await
        .map_err(|e| format!("RPC error: {}", e))?
        .into_inner();

    let data_base64 = STANDARD.encode(&response.data);

    let mime_type = if response.mime_type == "application/octet-stream" {
        if response.data.starts_with(b"\x89PNG") {
            "image/png".to_string()
        } else if response.data.starts_with(b"<") || response.data.starts_with(b"<?xml") {
            "text/xml".to_string()
        } else if response.data.starts_with(b"{") || response.data.starts_with(b"[") {
            "application/json".to_string()
        } else {
            "text/plain".to_string()
        }
    } else {
        response.mime_type
    };

    Ok(ContextBlob {
        data_base64,
        mime_type,
    })
}