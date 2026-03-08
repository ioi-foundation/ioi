use crate::execution;
use crate::kernel::state::get_rpc_client;
use crate::models::{AppState, ContextBlob, SkillCatalogEntry};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ioi_ipc::blockchain::QueryRawStateRequest;
use ioi_ipc::public::public_api_client::PublicApiClient;
use ioi_ipc::public::GetContextBlobRequest;
use ioi_services::agentic::desktop::keys::{
    get_skill_doc_key, get_skill_record_key, SKILL_CATALOG_INDEX_KEY,
};
use ioi_types::app::agentic::{
    LlmToolDefinition, PublishedSkillDoc, SkillCatalogIndex, SkillRecord,
};
use ioi_types::codec;
use std::sync::Mutex;
use tauri::State;
use tonic::transport::Channel;
use tonic::Code;

const CONTEXT_BLOB_UNAVAILABLE_MIME: &str = "application/x-ioi-context-unavailable";

#[tauri::command]
pub async fn get_available_tools(
    state: State<'_, Mutex<AppState>>,
) -> Result<Vec<LlmToolDefinition>, String> {
    let mut tools = execution::get_active_mcp_tools().await;
    let mut existing = tools
        .iter()
        .map(|tool| tool.name.clone())
        .collect::<std::collections::HashSet<_>>();
    tools.extend(
        ioi_services::agentic::desktop::connectors::google_workspace::google_connector_tool_definitions()
            .into_iter()
            .filter(|tool| !existing.contains(&tool.name)),
    );
    existing.extend(tools.iter().map(|tool| tool.name.clone()));

    if let Ok(mut client) = get_rpc_client(&state).await {
        if let Ok(skill_catalog) = load_skill_catalog_entries(&mut client).await {
            for entry in skill_catalog {
                if entry.stale || entry.lifecycle_state == "Deprecated" {
                    continue;
                }
                if existing.insert(entry.definition.name.clone()) {
                    tools.push(entry.definition);
                }
            }
        }
    }

    Ok(tools)
}

#[tauri::command]
pub async fn get_skill_catalog(
    state: State<'_, Mutex<AppState>>,
) -> Result<Vec<SkillCatalogEntry>, String> {
    let mut client = get_rpc_client(&state).await?;
    load_skill_catalog_entries(&mut client).await
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

async fn query_raw_state(
    client: &mut PublicApiClient<Channel>,
    key: Vec<u8>,
) -> Result<Option<Vec<u8>>, String> {
    let response = client
        .query_raw_state(tonic::Request::new(QueryRawStateRequest { key }))
        .await
        .map_err(|status| format!("RPC error: {}", status))?
        .into_inner();
    if response.found {
        Ok(Some(response.value))
    } else {
        Ok(None)
    }
}

async fn load_skill_catalog_entries(
    client: &mut PublicApiClient<Channel>,
) -> Result<Vec<SkillCatalogEntry>, String> {
    let index =
        if let Some(bytes) = query_raw_state(client, SKILL_CATALOG_INDEX_KEY.to_vec()).await? {
            codec::from_bytes_canonical::<SkillCatalogIndex>(&bytes)
                .map_err(|e| format!("Failed to decode skill catalog index: {}", e))?
        } else {
            SkillCatalogIndex::default()
        };

    let mut entries = Vec::new();
    for skill_hash in index.skills {
        let Some(record_bytes) = query_raw_state(client, get_skill_record_key(&skill_hash)).await?
        else {
            continue;
        };
        let record = codec::from_bytes_canonical::<SkillRecord>(&record_bytes)
            .map_err(|e| format!("Failed to decode skill record: {}", e))?;

        let published_doc = if let Some(doc_bytes) =
            query_raw_state(client, get_skill_doc_key(&skill_hash)).await?
        {
            codec::from_bytes_canonical::<PublishedSkillDoc>(&doc_bytes).ok()
        } else {
            None
        };

        let benchmark = record.benchmark.clone().unwrap_or_default();
        let relative_path = published_doc
            .as_ref()
            .map(|doc| doc.relative_path.clone())
            .or_else(|| {
                record
                    .publication
                    .as_ref()
                    .map(|publication| publication.relative_path.clone())
            });
        let stale = published_doc
            .as_ref()
            .map(|doc| doc.stale)
            .or_else(|| {
                record
                    .publication
                    .as_ref()
                    .map(|publication| publication.stale)
            })
            .unwrap_or(false);

        entries.push(SkillCatalogEntry {
            skill_hash: hex::encode(skill_hash),
            name: record.macro_body.definition.name.clone(),
            description: record.macro_body.definition.description.clone(),
            lifecycle_state: format!("{:?}", record.lifecycle_state),
            source_type: format!("{:?}", record.source_type),
            success_rate_bps: benchmark.success_rate_bps,
            sample_size: benchmark.sample_size,
            frame_id: record.frame_id,
            source_session_id: record.source_session_id.map(hex::encode),
            source_evidence_hash: record.source_evidence_hash.map(hex::encode),
            relative_path,
            stale,
            definition: record.macro_body.definition.clone(),
        });
    }

    entries.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(entries)
}
