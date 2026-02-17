// apps/autopilot/src-tauri/src/execution.rs

use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::error::Error;
use std::sync::{Arc, Mutex};

// Native Drivers & MCP
use ioi_drivers::browser::BrowserDriver;
use ioi_drivers::mcp::{McpManager, McpServerConfig};
use tauri::Manager;

// Governance & Policy Integration
use async_trait::async_trait;
use ioi_api::vm::drivers::os::OsDriver;
use ioi_api::vm::inference::{
    InferenceRuntime, LocalSafetyModel, PiiInspection, PiiRiskSurface, SafetyVerdict,
};
use ioi_drivers::os::NativeOsDriver;
use ioi_services::agentic::policy::PolicyEngine;
use ioi_services::agentic::rules::{ActionRules, DefaultPolicy, Rule, RuleConditions, Verdict};
use ioi_types::app::agentic::EvidenceGraph;
use ioi_types::app::{ActionContext, ActionRequest, ActionTarget};

// SCS Integration
use ioi_scs::SovereignContextStore;

// [NEW] Governance Tiers for Execution Context
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

// Persistent Browser Driver for the Simulator
static BROWSER_DRIVER: Lazy<BrowserDriver> = Lazy::new(|| BrowserDriver::new());

// Persistent MCP Manager for the Simulator
static MCP_MANAGER: Lazy<Arc<McpManager>> = Lazy::new(|| Arc::new(McpManager::new()));

// Public accessor for Kernel commands
pub async fn get_active_mcp_tools() -> Vec<ioi_types::app::agentic::LlmToolDefinition> {
    MCP_MANAGER.get_all_tools().await
}

// Native OS Driver for Policy Context
static OS_DRIVER: Lazy<Arc<dyn OsDriver>> = Lazy::new(|| Arc::new(NativeOsDriver::new()));

// Simulation Safety Model (Mock)
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

/// Initializes default MCP servers for the local Studio environment.
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

/// Helper: Basic Handlebars-style interpolation {{key}} -> value
fn interpolate_template(template: &str, context: &Value) -> String {
    let mut result = template.to_string();
    let mut start_idx = 0;
    while let Some(open) = result[start_idx..].find("{{") {
        let actual_open = start_idx + open;
        if let Some(close) = result[actual_open..].find("}}") {
            let actual_close = actual_open + close;
            let key = &result[actual_open + 2..actual_close].trim();

            let replacement = if let Some(val) = context.get(key) {
                if let Some(s) = val.as_str() {
                    s.to_string()
                } else {
                    val.to_string()
                }
            } else {
                format!("<<MISSING:{}>>", key)
            };

            result.replace_range(actual_open..actual_close + 2, &replacement);
            start_idx = actual_open + replacement.len();
        } else {
            break;
        }
    }
    result
}

mod governance;
mod runners;

/// Main entry point for executing a node in the local environment.
pub async fn execute_ephemeral_node(
    node_type: &str,
    full_config: &Value,
    input_json: &str,
    session_id: Option<String>,
    scs: Arc<Mutex<SovereignContextStore>>,
    inference: Arc<dyn InferenceRuntime>,
    // [NEW] Configurable Governance Tier
    tier: GovernanceTier,
) -> Result<ExecutionResult, Box<dyn Error>> {
    let input_snapshot: Option<Value> = serde_json::from_str(input_json).ok();

    // --- STEP 1: GOVERNANCE CHECK ---
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

    // --- STEP 2: EXECUTION ---
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
