use crate::execution;
use crate::kernel::state::get_rpc_client;
use crate::models::{AppState, ContextBlob};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ioi_ipc::public::GetContextBlobRequest;
use ioi_types::app::agentic::LlmToolDefinition;
use std::sync::Mutex;
use tauri::State;
use tonic::Code;

const CONTEXT_BLOB_UNAVAILABLE_MIME: &str = "application/x-ioi-context-unavailable";

#[tauri::command]
pub async fn get_available_tools() -> Result<Vec<LlmToolDefinition>, String> {
    let mut tools = execution::get_active_mcp_tools().await;
    let existing = tools
        .iter()
        .map(|tool| tool.name.clone())
        .collect::<std::collections::HashSet<_>>();
    tools.extend(
        ioi_services::agentic::desktop::connectors::google_workspace::google_connector_tool_definitions()
            .into_iter()
            .filter(|tool| !existing.contains(&tool.name)),
    );
    Ok(tools)
}

#[tauri::command]
pub async fn get_context_blob(
    state: State<'_, Mutex<AppState>>,
    hash: String,
) -> Result<ContextBlob, String> {
    let mut client = get_rpc_client(&state).await?;

    let request = tonic::Request::new(GetContextBlobRequest { blob_hash: hash });

    let response = match client.get_context_blob(request).await {
        Ok(resp) => resp.into_inner(),
        Err(status) if status.code() == Code::NotFound => {
            return Ok(ContextBlob {
                data_base64: String::new(),
                mime_type: CONTEXT_BLOB_UNAVAILABLE_MIME.to_string(),
            });
        }
        Err(status) => return Err(format!("RPC error: {}", status)),
    };

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
