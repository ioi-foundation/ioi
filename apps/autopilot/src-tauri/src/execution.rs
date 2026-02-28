use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::error::Error;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ioi_api::vm::drivers::os::OsDriver;
use ioi_api::vm::inference::{
    InferenceRuntime, LocalSafetyModel, PiiInspection, PiiRiskSurface, SafetyVerdict,
};
use ioi_drivers::browser::BrowserDriver;
use ioi_drivers::mcp::{McpManager, McpServerConfig};
use ioi_drivers::os::NativeOsDriver;
use ioi_scs::SovereignContextStore;
use ioi_services::agentic::policy::PolicyEngine;
use ioi_services::agentic::rules::{ActionRules, DefaultPolicy, Rule, RuleConditions, Verdict};
use ioi_types::app::agentic::EvidenceGraph;
use ioi_types::app::{ActionContext, ActionRequest, ActionTarget};
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

pub async fn init_mcp_servers(app_handle: tauri::AppHandle) {
    let data_dir = app_handle
        .path()
        .app_data_dir()
        .unwrap_or_else(|_| std::path::PathBuf::from("./ioi-data"));
    let abs_data_dir = std::fs::canonicalize(&data_dir).unwrap_or_else(|_| {
        std::fs::create_dir_all(&data_dir).ok();
        data_dir.clone()
    });

    let fs_config = McpServerConfig {
        command: "npx".to_string(),
        args: vec![
            "-y".to_string(),
            "@modelcontextprotocol/server-filesystem".to_string(),
            abs_data_dir.to_string_lossy().to_string(),
        ],
        env: HashMap::new(),
    };

    println!("[Studio] Spawning Filesystem MCP at {:?}", abs_data_dir);

    if let Err(e) = MCP_MANAGER.start_server("filesystem", fs_config).await {
        eprintln!("[Studio] Failed to start filesystem MCP: {}", e);
    } else {
        println!("[Studio] Filesystem MCP active.");
    }
}

mod governance;
mod runners;

pub async fn execute_ephemeral_node(
    node_type: &str,
    full_config: &Value,
    input_json: &str,
    session_id: Option<String>,
    scs: Arc<Mutex<SovereignContextStore>>,
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

    let logic_config = full_config.get("logic").unwrap_or(full_config);

    match node_type {
        "model" => runners::run_llm_inference(logic_config, input_json).await,
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
            runners::run_retrieval_execution(logic_config, input_json, scs, inference).await
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
