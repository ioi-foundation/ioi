use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::error::Error;
use std::sync::Arc;

use async_trait::async_trait;
use ioi_api::vm::drivers::os::OsDriver;
use ioi_api::vm::inference::{
    InferenceRuntime, LocalSafetyModel, PiiInspection, PiiRiskSurface, SafetyVerdict,
};
use ioi_drivers::browser::BrowserDriver;
use ioi_drivers::mcp::{McpManager, McpServerConfig};
use ioi_drivers::os::NativeOsDriver;
use ioi_memory::MemoryRuntime;
use ioi_services::agentic::policy::PolicyEngine;
use ioi_services::agentic::rules::{ActionRules, DefaultPolicy, Rule, RuleConditions, Verdict};
use ioi_types::app::agentic::EvidenceGraph;
use ioi_types::app::{ActionContext, ActionRequest, ActionTarget};
use ioi_types::config::{
    McpContainmentConfig, McpContainmentMode, McpIntegrityConfig, McpMode, McpServerSource,
    McpServerTier,
};
use tauri::Manager;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum GovernanceTier {
    None,
    Silent,
    Strict,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ExecutionResult {
    pub status: String,
    pub output: String,
    pub data: Option<Value>,
    pub metrics: Option<Value>,
    pub input_snapshot: Option<Value>,
    pub context_slice: Option<Value>,
}

static BROWSER_DRIVER: Lazy<BrowserDriver> = Lazy::new(BrowserDriver::new);
static MCP_MANAGER: Lazy<Arc<McpManager>> = Lazy::new(|| Arc::new(McpManager::new()));
static OS_DRIVER: Lazy<Arc<dyn OsDriver>> = Lazy::new(|| Arc::new(NativeOsDriver::new()));

pub(crate) async fn release_browser_session() {
    BROWSER_DRIVER.release_session().await;
}

pub async fn get_active_mcp_tools() -> Vec<ioi_types::app::agentic::LlmToolDefinition> {
    MCP_MANAGER.get_all_tools().await
}

struct SimulationSafetyModel;

#[async_trait]
impl LocalSafetyModel for SimulationSafetyModel {
    async fn classify_intent(&self, _input: &str) -> anyhow::Result<SafetyVerdict> {
        Ok(SafetyVerdict::Safe)
    }

    async fn detect_pii(&self, _input: &str) -> anyhow::Result<Vec<(usize, usize, String)>> {
        Ok(vec![])
    }

    async fn inspect_pii(
        &self,
        _input: &str,
        _risk_surface: PiiRiskSurface,
    ) -> anyhow::Result<PiiInspection> {
        Ok(PiiInspection {
            evidence: EvidenceGraph::default(),
            ambiguous: false,
            stage2_status: None,
        })
    }
}

static SAFETY_MODEL: Lazy<Arc<dyn LocalSafetyModel>> =
    Lazy::new(|| Arc::new(SimulationSafetyModel));

pub fn is_consequential_node_type(node_type: &str) -> bool {
    matches!(
        node_type,
        "browser"
            | "code"
            | "tool"
            | "web_search"
            | "web_read"
            | "transcribe_audio"
            | "synthesize_speech"
            | "vision_read"
            | "generate_image"
            | "edit_image"
            | "generate_video"
    )
}

fn has_settlement_authority(config: &Value) -> bool {
    config.get("settlementRef").is_some()
        || config.get("runtimeSettlementRef").is_some()
        || config
            .get("authority")
            .and_then(|authority| authority.get("settlementRef"))
            .is_some()
}

pub async fn init_mcp_servers(app_handle: tauri::AppHandle) {
    let data_dir = app_handle
        .path()
        .app_data_dir()
        .unwrap_or_else(|_| std::path::PathBuf::from("./ioi-data"));
    let abs_data_dir = std::fs::canonicalize(&data_dir).unwrap_or_else(|_| {
        std::fs::create_dir_all(&data_dir).ok();
        data_dir.clone()
    });

    let profile = std::env::var("IOI_CHAT_MCP_PROFILE")
        .unwrap_or_else(|_| "disabled".to_string())
        .to_ascii_lowercase();
    if profile != "dev_filesystem" {
        println!(
            "[Chat] MCP disabled by default. Native filesystem drivers remain available; optional MCP filesystem server is off for safety."
        );
        println!("[Chat] Set IOI_CHAT_MCP_PROFILE=dev_filesystem to opt in.");
        return;
    }
    let mcp_mode = McpMode::Development;

    let fs_config = McpServerConfig {
        command: "npx".to_string(),
        args: vec![
            "-y".to_string(),
            "@modelcontextprotocol/server-filesystem".to_string(),
            abs_data_dir.to_string_lossy().to_string(),
        ],
        env: HashMap::new(),
        tier: McpServerTier::Unverified,
        source: McpServerSource::PackageManager,
        integrity: McpIntegrityConfig::default(),
        containment: McpContainmentConfig {
            mode: McpContainmentMode::DeveloperUnconfined,
            allow_network_egress: true,
            allow_child_processes: true,
            workspace_root: Some(abs_data_dir.to_string_lossy().to_string()),
        },
        allowed_tools: Vec::new(),
    };

    println!(
        "[Chat] Spawning optional dev Filesystem MCP at {:?}",
        abs_data_dir
    );

    if let Err(e) = MCP_MANAGER
        .start_server("filesystem_dev", mcp_mode, fs_config)
        .await
    {
        eprintln!("[Chat] Failed to start filesystem_dev MCP: {}", e);
    } else {
        println!("[Chat] filesystem_dev MCP active.");
    }
}

mod governance;
mod runners;

pub async fn execute_ephemeral_node(
    node_type: &str,
    full_config: &Value,
    input_json: &str,
    session_id: Option<String>,
    memory_runtime: Arc<MemoryRuntime>,
    inference: Arc<dyn InferenceRuntime>,
    tier: GovernanceTier,
) -> Result<ExecutionResult, Box<dyn Error>> {
    let input_snapshot: Option<Value> = serde_json::from_str(input_json).ok();

    if let Err(violation) =
        governance::check_governance(node_type, full_config, input_json, session_id.clone(), tier)
            .await
    {
        return Ok(ExecutionResult {
            status: "blocked".to_string(),
            output: violation,
            data: None,
            metrics: Some(serde_json::json!({ "risk": "high" })),
            input_snapshot,
            context_slice: None,
        });
    }

    if tier != GovernanceTier::None
        && is_consequential_node_type(node_type)
        && !has_settlement_authority(full_config)
    {
        return Ok(ExecutionResult {
            status: "blocked".to_string(),
            output: format!(
                "🛡️ BLOCKED: consequential graph node '{}' requires runtime settlement authority.",
                node_type
            ),
            data: None,
            metrics: Some(serde_json::json!({
                "authority": "missing_settlement",
                "simulation_only": false,
                "node_type": node_type,
            })),
            input_snapshot,
            context_slice: None,
        });
    }

    let logic_config = full_config.get("logic").unwrap_or(full_config);

    match node_type {
        "model_call" | "responses" => {
            runners::run_responses_execution(logic_config, input_json, inference.clone()).await
        }
        "embeddings" => {
            runners::run_embeddings_execution(logic_config, input_json, inference.clone()).await
        }
        "rerank" => {
            runners::run_rerank_execution(logic_config, input_json, inference.clone()).await
        }
        "transcribe_audio" => {
            runners::run_transcribe_audio_execution(logic_config, input_json, inference.clone())
                .await
        }
        "synthesize_speech" => {
            runners::run_synthesize_speech_execution(logic_config, input_json, inference.clone())
                .await
        }
        "vision_read" => {
            runners::run_vision_read_execution(logic_config, input_json, inference.clone()).await
        }
        "generate_image" => {
            runners::run_generate_image_execution(logic_config, input_json, inference.clone()).await
        }
        "edit_image" => {
            runners::run_edit_image_execution(logic_config, input_json, inference.clone()).await
        }
        "generate_video" => {
            runners::run_generate_video_execution(logic_config, input_json, inference.clone()).await
        }
        "gate" => runners::run_gate_execution(logic_config, input_json).await,
        "browser" => runners::run_browser_execution(logic_config, input_json).await,
        "web_search" => runners::run_web_search_execution(logic_config, input_json).await,
        "web_read" => runners::run_web_read_execution(logic_config, input_json).await,
        "tool" => {
            let tool_name = logic_config.get("tool_name").and_then(|s| s.as_str());
            if let Some(name) = tool_name {
                runners::run_mcp_tool(name, logic_config, input_json).await
            } else {
                runners::run_tool_execution(logic_config, input_json).await
            }
        }
        "retrieval" => {
            runners::run_retrieval_execution(logic_config, input_json, memory_runtime, inference)
                .await
        }
        "receipt" => Ok(ExecutionResult {
            status: "success".to_string(),
            output: format!(
                "Receipt Logged: {}",
                input_json.chars().take(50).collect::<String>()
            ),
            data: Some(
                serde_json::json!({ "signed": true, "timestamp": chrono::Utc::now().to_rfc3339() }),
            ),
            metrics: None,
            input_snapshot,
            context_slice: None,
        }),
        "code" => runners::run_code_execution(logic_config, input_json).await,
        "router" => runners::run_router_execution(logic_config, input_json).await,
        "wait" => runners::run_wait_execution(logic_config).await,
        "context" => runners::run_context_execution(logic_config, input_json).await,
        _ => Ok(ExecutionResult {
            status: "skipped".to_string(),
            output: format!("Ephemeral execution not implemented for {}", node_type),
            data: None,
            metrics: None,
            input_snapshot,
            context_slice: None,
        }),
    }
}
