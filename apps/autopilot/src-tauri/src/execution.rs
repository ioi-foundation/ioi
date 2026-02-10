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
use ioi_api::vm::inference::{InferenceRuntime, LocalSafetyModel, SafetyVerdict};
use ioi_drivers::os::NativeOsDriver;
use ioi_services::agentic::policy::PolicyEngine;
use ioi_services::agentic::rules::{ActionRules, DefaultPolicy, Rule, RuleConditions, Verdict};
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

// Governance Logic: Synthesize ActionRules from UI Config
fn synthesize_node_policy(node_type: &str, law_config: &Value) -> ActionRules {
    let mut rules = Vec::new();
    let mut conditions = RuleConditions::default();

    if let Some(budget) = law_config.get("budgetCap").and_then(|v| v.as_f64()) {
        if budget > 0.0 {
            conditions.max_spend = Some((budget * 1000.0) as u64);
        }
    }

    if let Some(allowlist) = law_config
        .get("networkAllowlist")
        .and_then(|v| v.as_array())
    {
        let domains: Vec<String> = allowlist
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect();
        if !domains.is_empty() {
            conditions.allow_domains = Some(domains);
        }
    }

    let target = match node_type {
        "browser" => "browser::navigate",
        "tool" => "net::fetch",
        "model" => "model::inference",
        "gate" => "gov::gate",
        "code" => "sys::exec",
        _ => "*",
    };

    let require_human = law_config
        .get("requireHumanGate")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let action = if require_human {
        Verdict::RequireApproval
    } else {
        Verdict::Allow
    };

    rules.push(Rule {
        rule_id: Some("studio-rule-1".into()),
        target: target.to_string(),
        conditions,
        action,
    });

    ActionRules {
        policy_id: "studio-simulation".into(),
        defaults: DefaultPolicy::DenyAll,
        rules,
    }
}

// Governance Logic: Construct canonical ActionRequest with Session Context
fn map_to_action_request(
    node_type: &str,
    logic_config: &Value,
    input_json: &str,
    session_id: Option<String>,
) -> ActionRequest {
    let target = match node_type {
        "browser" => ActionTarget::BrowserNavigateHermetic,
        "tool" => {
            if let Some(endpoint) = logic_config.get("endpoint").and_then(|s| s.as_str()) {
                if endpoint.starts_with("http") {
                    ActionTarget::NetFetch
                } else {
                    ActionTarget::Custom("tool:generic".into())
                }
            } else {
                ActionTarget::Custom("tool:generic".into())
            }
        }
        _ => ActionTarget::Custom(format!("node:{}", node_type)),
    };

    let mut params_obj = json!({});
    let input_ctx: Value = serde_json::from_str(input_json).unwrap_or(json!({}));

    if let Some(url_template) = logic_config
        .get("url")
        .or_else(|| logic_config.get("endpoint"))
        .and_then(|s| s.as_str())
    {
        let final_url = interpolate_template(url_template, &input_ctx);
        params_obj["url"] = json!(final_url);
    }

    if let Some(budget) = logic_config.get("cost").and_then(|v| v.as_u64()) {
        params_obj["total_amount"] = json!(budget);
    }

    let params_bytes = serde_json::to_vec(&params_obj).unwrap_or_default();

    let session_id_bytes: Option<[u8; 32]> = session_id.and_then(|s| {
        let vec = hex::decode(s).ok()?;
        if vec.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&vec);
            Some(arr)
        } else {
            None
        }
    });

    ActionRequest {
        target,
        params: params_bytes,
        context: ActionContext {
            agent_id: "studio-simulator".into(),
            session_id: session_id_bytes,
            window_id: None,
        },
        nonce: 0,
    }
}

/// The Governance Layer
async fn check_governance(
    node_type: &str,
    config: &Value,
    input_context: &str,
    session_id: Option<String>,
    tier: GovernanceTier, // [NEW] Accept Tier
) -> Result<(), String> {
    if tier == GovernanceTier::None {
        return Ok(());
    }

    let default_val = serde_json::json!({});
    let law_config = config.get("law").unwrap_or(&default_val);
    let logic_config = config.get("logic").unwrap_or(&default_val);

    let policy = synthesize_node_policy(node_type, law_config);
    let request = map_to_action_request(node_type, logic_config, input_context, session_id);

    // Evaluate against policy + current OS state
    let verdict =
        PolicyEngine::evaluate(&policy, &request, &*SAFETY_MODEL, &*OS_DRIVER, None).await;

    match verdict {
        Verdict::Allow => Ok(()),
        Verdict::Block => {
            // 2. Silent Mode: Only block if it's a "Hard" violation (e.g. key access),
            // otherwise allow but log warning.
            // For MVP, we treat Block as Block, but in production this would differ.
            Err("🛡️ BLOCKED: Policy violation (e.g., Domain not in allowlist)".into())
        }
        Verdict::RequireApproval => {
            // 3. Silent Mode: Auto-approve "Soft" gates
            if tier == GovernanceTier::Silent {
                // Log the bypass
                println!(
                    "[Governance] Auto-approving gate for {} (Silent Mode)",
                    node_type
                );
                Ok(())
            } else {
                Err("🛡️ PAUSED: Execution requires Human Approval (Gate)".into())
            }
        }
    }
}

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
        check_governance(node_type, full_config, input_json, session_id.clone(), tier).await
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
        "model" => run_llm_inference(logic_config, input_json).await,
        "gate" => run_gate_execution(logic_config, input_json).await,
        "browser" => run_browser_execution(logic_config, input_json).await,
        "tool" => {
            let tool_name = logic_config.get("tool_name").and_then(|s| s.as_str());
            if let Some(name) = tool_name {
                run_mcp_tool(name, logic_config, input_json).await
            } else {
                run_tool_execution(logic_config, input_json).await
            }
        }
        "retrieval" => run_retrieval_execution(logic_config, input_json, scs, inference).await,

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
        "code" => run_code_execution(logic_config, input_json).await,
        "router" => run_router_execution(logic_config, input_json).await,
        "wait" => run_wait_execution(logic_config).await,
        "context" => run_context_execution(logic_config, input_json).await,

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

async fn run_mcp_tool(
    tool_name: &str,
    config: &Value,
    input: &str,
) -> Result<ExecutionResult, Box<dyn Error>> {
    let start = std::time::Instant::now();
    let input_obj: Value = serde_json::from_str(input).unwrap_or(json!({}));

    let raw_args = config.get("arguments").cloned().unwrap_or(json!({}));

    fn interpolate_recursive(val: &Value, ctx: &Value) -> Value {
        match val {
            Value::String(s) => {
                if s.contains("{{") {
                    Value::String(interpolate_template(s, ctx))
                } else {
                    val.clone()
                }
            }
            Value::Array(arr) => {
                Value::Array(arr.iter().map(|v| interpolate_recursive(v, ctx)).collect())
            }
            Value::Object(map) => {
                let mut new_map = serde_json::Map::new();
                for (k, v) in map {
                    new_map.insert(k.clone(), interpolate_recursive(v, ctx));
                }
                Value::Object(new_map)
            }
            _ => val.clone(),
        }
    }

    let mut args = interpolate_recursive(&raw_args, &input_obj);

    if let Value::Object(ref mut map) = args {
        if let Value::Object(input_map) = &input_obj {
            for (k, v) in input_map {
                map.entry(k).or_insert(v.clone());
            }
        }
    }

    match MCP_MANAGER.execute_tool(tool_name, args).await {
        Ok(output) => Ok(ExecutionResult {
            status: "success".to_string(),
            output: output.clone(),
            data: match serde_json::from_str(&output) {
                Ok(v) => Some(v),
                Err(_) => Some(json!({ "raw": output })),
            },
            metrics: Some(json!({ "latency_ms": start.elapsed().as_millis() })),
            input_snapshot: Some(input_obj),
            context_slice: None,
        }),
        Err(e) => Ok(ExecutionResult {
            status: "error".to_string(),
            output: format!("MCP Error: {}", e),
            data: None,
            metrics: None,
            input_snapshot: Some(input_obj),
            context_slice: None,
        }),
    }
}

async fn run_browser_execution(
    config: &Value,
    input: &str,
) -> Result<ExecutionResult, Box<dyn Error>> {
    let start = std::time::Instant::now();
    let input_obj: Value = serde_json::from_str(input).unwrap_or(serde_json::json!({}));

    if let Err(e) = BROWSER_DRIVER.launch(false).await {
        return Ok(ExecutionResult {
            status: "error".to_string(),
            output: format!("Failed to launch browser driver: {}", e),
            data: None,
            metrics: None,
            input_snapshot: Some(input_obj),
            context_slice: None,
        });
    }

    let action = config
        .get("action")
        .and_then(|v| v.as_str())
        .unwrap_or("navigate");

    match action {
        "navigate" => {
            let url_template = config
                .get("url")
                .and_then(|v| v.as_str())
                .ok_or("Missing 'url' in logic config")?;
            let url = interpolate_template(url_template, &input_obj);

            match BROWSER_DRIVER.navigate(&url, "hermetic").await {
                Ok(content) => Ok(ExecutionResult {
                    status: "success".to_string(),
                    output: content.clone(),
                    data: Some(serde_json::json!({
                        "url": url,
                        "title": "Page Loaded",
                        "content_length": content.len()
                    })),
                    metrics: Some(serde_json::json!({ "latency_ms": start.elapsed().as_millis() })),
                    input_snapshot: Some(input_obj),
                    context_slice: None,
                }),
                Err(e) => Ok(ExecutionResult {
                    status: "error".to_string(),
                    output: format!("Navigation failed: {}", e),
                    data: None,
                    metrics: Some(serde_json::json!({ "latency_ms": start.elapsed().as_millis() })),
                    input_snapshot: Some(input_obj),
                    context_slice: None,
                }),
            }
        }
        "extract_dom" => match BROWSER_DRIVER.extract_dom().await {
            Ok(dom) => Ok(ExecutionResult {
                status: "success".to_string(),
                output: dom.clone(),
                data: Some(serde_json::json!({ "dom_length": dom.len() })),
                metrics: Some(serde_json::json!({ "latency_ms": start.elapsed().as_millis() })),
                input_snapshot: Some(input_obj),
                context_slice: None,
            }),
            Err(e) => Ok(ExecutionResult {
                status: "error".to_string(),
                output: format!("DOM extraction failed: {}", e),
                data: None,
                metrics: None,
                input_snapshot: Some(input_obj),
                context_slice: None,
            }),
        },
        "click" => {
            let selector_template = config
                .get("selector")
                .and_then(|v| v.as_str())
                .ok_or("Missing 'selector'")?;

            // [UPDATED] Interpolate the selector string
            let selector = interpolate_template(selector_template, &input_obj);

            match BROWSER_DRIVER.click_selector(&selector).await {
                Ok(_) => Ok(ExecutionResult {
                    status: "success".to_string(),
                    output: format!("Clicked element: {}", selector),
                    data: Some(serde_json::json!({ "action": "click", "selector": selector })),
                    metrics: Some(serde_json::json!({ "latency_ms": start.elapsed().as_millis() })),
                    input_snapshot: Some(input_obj),
                    context_slice: None,
                }),
                Err(e) => Ok(ExecutionResult {
                    status: "error".to_string(),
                    output: format!("Click failed for '{}': {}", selector, e),
                    data: None,
                    metrics: None,
                    input_snapshot: Some(input_obj),
                    context_slice: None,
                }),
            }
        }
        _ => Ok(ExecutionResult {
            status: "error".to_string(),
            output: format!("Unknown browser action: {}", action),
            data: None,
            metrics: None,
            input_snapshot: Some(input_obj),
            context_slice: None,
        }),
    }
}

async fn run_gate_execution(
    config: &Value,
    input: &str,
) -> Result<ExecutionResult, Box<dyn Error>> {
    let start = std::time::Instant::now();
    let condition = config
        .get("conditionScript")
        .or_else(|| config.get("condition"))
        .and_then(|v| v.as_str())
        .unwrap_or("true");

    let input_obj: Value = serde_json::from_str(input).unwrap_or(serde_json::json!({}));
    let passed;
    let mut reason = "Condition met".to_string();
    let cond = condition.trim().to_string();

    if cond == "true" {
        passed = true;
    } else {
        let parts: Vec<&str> = cond.split_whitespace().collect();

        if parts.len() >= 3 {
            let key_path = parts[0];
            let op = parts[1];
            let target_val_str = parts[2];

            let json_pointer = if key_path.starts_with("input.") {
                key_path.replace("input.", "/").replace(".", "/")
            } else {
                format!("/{}", key_path.replace(".", "/"))
            };

            let actual_val_opt = input_obj.pointer(&json_pointer);

            if let Some(val) = actual_val_opt {
                if let Some(num_val) = val.as_f64() {
                    let target_num = target_val_str.parse::<f64>().unwrap_or(0.0);
                    match op {
                        ">" => passed = num_val > target_num,
                        "<" => passed = num_val < target_num,
                        ">=" => passed = num_val >= target_num,
                        "<=" => passed = num_val <= target_num,
                        "==" => passed = (num_val - target_num).abs() < f64::EPSILON,
                        _ => {
                            passed = false;
                            reason = format!("Unknown operator: {}", op);
                        }
                    }
                    if !passed {
                        reason = format!(
                            "Field '{}' ({}) is not {} {}",
                            key_path, num_val, op, target_num
                        );
                    }
                } else if let Some(str_val) = val.as_str() {
                    let target_clean = target_val_str.trim_matches('"').trim_matches('\'');
                    match op {
                        "==" => passed = str_val == target_clean,
                        "!=" => passed = str_val != target_clean,
                        "contains" => passed = str_val.contains(target_clean),
                        _ => {
                            passed = false;
                            reason = "Invalid operator for string".into();
                        }
                    }
                    if !passed {
                        reason = format!(
                            "Field '{}' ('{}') check failed vs '{}'",
                            key_path, str_val, target_clean
                        );
                    }
                } else if let Some(bool_val) = val.as_bool() {
                    let target_bool = target_val_str.parse::<bool>().unwrap_or(false);
                    match op {
                        "==" => passed = bool_val == target_bool,
                        "!=" => passed = bool_val != target_bool,
                        _ => {
                            passed = false;
                            reason = "Invalid operator for boolean".into();
                        }
                    }
                    if !passed {
                        reason =
                            format!("Field '{}' ({}) is not {}", key_path, bool_val, target_bool);
                    }
                } else {
                    passed = false;
                    reason = format!("Field '{}' is not a comparable primitive", key_path);
                }
            } else {
                passed = false;
                reason = format!("Field '{}' not found in input data", key_path);
            }
        } else {
            reason = "Complex script syntax not supported in Local Mode. Use 'input.field > value'"
                .to_string();
            passed = false;
        }
    }

    Ok(ExecutionResult {
        status: if passed {
            "success".to_string()
        } else {
            "blocked".to_string()
        },
        output: if passed {
            input.to_string()
        } else {
            format!("Gate Blocked: {}", reason)
        },
        data: Some(serde_json::json!({
            "condition": condition,
            "passed": passed,
            "reason": reason
        })),
        metrics: Some(serde_json::json!({ "latency_ms": start.elapsed().as_millis() })),
        input_snapshot: Some(input_obj),
        context_slice: None,
    })
}

// Helper to format retrieval results into LLM-friendly text
fn format_context_for_llm(input_obj: &Value) -> String {
    let mut context_str = String::new();

    // Check for "results" array (output from retrieval node)
    if let Some(results) = input_obj.get("results").and_then(|v| v.as_array()) {
        context_str.push_str("\n\n### Retrieved Context:\n");
        for (i, doc) in results.iter().enumerate() {
            let content = doc["content"].as_str().unwrap_or("").trim();
            let score = doc["score"].as_f64().unwrap_or(0.0);
            if !content.is_empty() {
                context_str.push_str(&format!(
                    "--- Doc {} (Score: {:.2}) ---\n{}\n",
                    i + 1,
                    score,
                    content
                ));
            }
        }
    }

    // Check for direct "context" field
    if let Some(ctx) = input_obj.get("context").and_then(|v| v.as_str()) {
        context_str.push_str(&format!("\n\n### Additional Context:\n{}\n", ctx));
    }

    context_str
}

async fn run_llm_inference(
    config: &Value,
    input_json: &str,
) -> Result<ExecutionResult, Box<dyn Error>> {
    let system_prompt = config
        .get("systemPrompt")
        .or_else(|| config.get("system_prompt"))
        .and_then(|v| v.as_str())
        .unwrap_or("You are a helpful assistant.");

    let model = config
        .get("model")
        .and_then(|v| v.as_str())
        .unwrap_or("llama3");

    let input_obj: Value = serde_json::from_str(input_json).unwrap_or(serde_json::json!({}));

    // Intelligent Context Injection
    // 1. Interpolate variables as before
    let mut interpolated_prompt = if system_prompt.contains("{{") {
        interpolate_template(system_prompt, &input_obj)
    } else {
        // Default behavior if no template: append input
        format!("System: {}\n\nUser Input: {}", system_prompt, input_json)
    };

    // 2. Append formatted RAG context if present (and not already interpolated)
    let rag_context = format_context_for_llm(&input_obj);
    if !rag_context.is_empty() && !interpolated_prompt.contains("Retrieved Context") {
        interpolated_prompt.push_str(&rag_context);

        // Add instruction to use context if not present
        if !interpolated_prompt.to_lowercase().contains("context") {
            interpolated_prompt.push_str(
                "\n\nINSTRUCTION: Answer the user's request using the Retrieved Context above.",
            );
        }
    }

    let client = reqwest::Client::new();
    let start = std::time::Instant::now();

    let res = client.post("http://127.0.0.1:11434/api/generate")
        .json(&serde_json::json!({
            "model": model, 
            "system": "You are an automated agent executing a specific task based on the provided context.",
            "prompt": interpolated_prompt, // Use enriched prompt
            "stream": false
        }))
        .send()
        .await;

    let duration = start.elapsed();

    match res {
        Ok(response) => {
            if response.status().is_success() {
                let body: Value = response.json().await?;
                let response_text = body["response"]
                    .as_str()
                    .unwrap_or("No response content")
                    .to_string();

                Ok(ExecutionResult {
                    status: "success".to_string(),
                    output: response_text,
                    data: Some(serde_json::json!({ "raw_response": body })),
                    metrics: Some(serde_json::json!({
                        "latency_ms": duration.as_millis(),
                        "eval_count": body.get("eval_count").unwrap_or(&serde_json::json!(0)),
                        "final_prompt_snapshot": interpolated_prompt // Capture full prompt for debug
                    })),
                    input_snapshot: Some(input_obj),
                    context_slice: None,
                })
            } else {
                Ok(ExecutionResult {
                    status: "failed".to_string(),
                    output: format!("LLM Provider Error: {}", response.status()),
                    data: None,
                    metrics: Some(serde_json::json!({ "latency_ms": duration.as_millis() })),
                    input_snapshot: Some(input_obj),
                    context_slice: None,
                })
            }
        }
        Err(e) => Ok(ExecutionResult {
            status: "simulated".to_string(),
            output: format!(
                "[Simulated Output - Ollama Offline]\nModel: {}\nPrompt Used: {}\nError: {}",
                model,
                interpolated_prompt.chars().take(150).collect::<String>(),
                e
            ),
            data: Some(serde_json::json!({ "final_prompt_snapshot": interpolated_prompt })),
            metrics: Some(serde_json::json!({ "latency_ms": 15, "error": e.to_string() })),
            input_snapshot: Some(input_obj),
            context_slice: None,
        }),
    }
}

async fn run_tool_execution(
    config: &Value,
    input: &str,
) -> Result<ExecutionResult, Box<dyn Error>> {
    let url = config
        .get("endpoint")
        .or_else(|| config.get("url"))
        .and_then(|v| v.as_str())
        .ok_or("Tool configuration missing 'endpoint'")?;

    let method = config
        .get("method")
        .and_then(|v| v.as_str())
        .unwrap_or("GET")
        .to_uppercase();
    let body_template = config
        .get("bodyTemplate")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let client = reqwest::Client::new();
    let start = std::time::Instant::now();

    let input_obj: Value = serde_json::from_str(input).unwrap_or(serde_json::json!({}));

    let mut builder = match method.as_str() {
        "POST" => client.post(url),
        "PUT" => client.put(url),
        "DELETE" => client.delete(url),
        _ => client.get(url),
    };

    if !body_template.is_empty() && (method == "POST" || method == "PUT") {
        let final_body = interpolate_template(body_template, &input_obj);

        if let Ok(json_body) = serde_json::from_str::<Value>(&final_body) {
            builder = builder.json(&json_body);
        } else {
            builder = builder.body(final_body);
        }
    }

    let res = builder.send().await;
    let duration = start.elapsed();

    match res {
        Ok(response) => {
            let status = response.status();
            let text = response.text().await?;

            Ok(ExecutionResult {
                status: if status.is_success() {
                    "success".to_string()
                } else {
                    "failed".to_string()
                },
                output: text.clone(),
                data: Some(serde_json::json!({
                    "status_code": status.as_u16(),
                    "body_preview": text.chars().take(500).collect::<String>()
                })),
                metrics: Some(serde_json::json!({ "latency_ms": duration.as_millis() })),
                input_snapshot: Some(input_obj),
                context_slice: None,
            })
        }
        Err(e) => Ok(ExecutionResult {
            status: "error".to_string(),
            output: format!("Network Request Failed: {}", e),
            data: None,
            metrics: Some(serde_json::json!({ "latency_ms": duration.as_millis() })),
            input_snapshot: Some(input_obj),
            context_slice: None,
        }),
    }
}

async fn run_code_execution(
    config: &Value,
    input: &str,
) -> Result<ExecutionResult, Box<dyn Error>> {
    let language = config
        .get("language")
        .and_then(|s| s.as_str())
        .unwrap_or("python");
    let _code = config.get("code").and_then(|s| s.as_str()).unwrap_or("");

    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    let input_obj: Value = serde_json::from_str(input).unwrap_or(json!({}));

    Ok(ExecutionResult {
        status: "success".into(),
        output: format!("Executed {} code (Simulated)", language),
        data: Some(serde_json::json!({ "processed": true, "result": "simulated_data" })),
        metrics: None,
        input_snapshot: Some(input_obj),
        context_slice: None,
    })
}

async fn run_router_execution(
    config: &Value,
    input: &str,
) -> Result<ExecutionResult, Box<dyn Error>> {
    let routes = config
        .get("routes")
        .and_then(|v| v.as_array())
        .ok_or("No routes defined")?;

    let input_lower = input.to_lowercase();
    let mut selected_route = routes[0].as_str().unwrap_or("default").to_string();

    for r in routes {
        if let Some(route_str) = r.as_str() {
            if input_lower.contains(&route_str.to_lowercase()) {
                selected_route = route_str.to_string();
                break;
            }
        }
    }

    Ok(ExecutionResult {
        status: "success".into(),
        output: selected_route.clone(),
        data: Some(json!({ "route": selected_route })),
        metrics: None,
        input_snapshot: Some(serde_json::from_str(input)?),
        context_slice: None,
    })
}

async fn run_wait_execution(config: &Value) -> Result<ExecutionResult, Box<dyn Error>> {
    let duration = config
        .get("durationMs")
        .and_then(|v| v.as_u64())
        .unwrap_or(1000);
    tokio::time::sleep(std::time::Duration::from_millis(duration)).await;

    Ok(ExecutionResult {
        status: "success".into(),
        output: format!("Waited {}ms", duration),
        data: None,
        metrics: None,
        input_snapshot: None,
        context_slice: None,
    })
}

async fn run_context_execution(
    config: &Value,
    input: &str,
) -> Result<ExecutionResult, Box<dyn Error>> {
    let vars = config.get("variables").cloned().unwrap_or(json!({}));

    Ok(ExecutionResult {
        status: "success".into(),
        output: "Context Updated".into(),
        data: Some(vars),
        metrics: None,
        input_snapshot: Some(serde_json::from_str(input)?),
        context_slice: None,
    })
}

// Semantic Retrieval Implementation
async fn run_retrieval_execution(
    config: &Value,
    input: &str,
    scs: Arc<Mutex<SovereignContextStore>>,
    inference: Arc<dyn InferenceRuntime>,
) -> Result<ExecutionResult, Box<dyn Error>> {
    let start = std::time::Instant::now();

    // 1. Resolve Query
    // Either from config "query" template or raw input
    let input_obj: Value = serde_json::from_str(input).unwrap_or(json!({}));
    let query_template = config
        .get("query")
        .and_then(|s| s.as_str())
        .unwrap_or("{{input}}");
    let query = interpolate_template(query_template, &input_obj);

    if query.trim().is_empty() {
        return Ok(ExecutionResult {
            status: "error".into(),
            output: "Empty query".into(),
            data: None,
            metrics: None,
            input_snapshot: Some(input_obj),
            context_slice: None,
        });
    }

    // 2. Generate Embedding
    let embedding = match inference.embed_text(&query).await {
        Ok(vec) => vec,
        Err(e) => {
            return Ok(ExecutionResult {
                status: "error".into(),
                output: format!("Embedding failed: {}", e),
                data: None,
                metrics: None,
                input_snapshot: Some(input_obj),
                context_slice: None,
            })
        }
    };

    // 3. Search SCS
    let limit = config.get("limit").and_then(|v| v.as_u64()).unwrap_or(3) as usize;

    // Search logic requires unlocking SCS
    let results = {
        let store = scs.lock().map_err(|_| "SCS lock poisoned")?;

        // We need to access the index. Since get_vector_index returns a mutex, we must handle it.
        // In ioi-scs crate, get_vector_index returns Result<Arc<Mutex<Option<VectorIndex>>>>.

        let index_arc = store
            .get_vector_index()
            .map_err(|e| format!("Failed to get index: {}", e))?;
        let index_guard = index_arc.lock().map_err(|_| "Index lock poisoned")?;

        if let Some(index) = index_guard.as_ref() {
            match index.search(&embedding, limit) {
                Ok(hits) => {
                    let mut docs = Vec::new();
                    for (frame_id, dist) in hits {
                        // Read payload
                        if let Ok(payload) = store.read_frame_payload(frame_id) {
                            // Try UTF-8
                            if let Ok(text) = String::from_utf8(payload.to_vec()) {
                                docs.push(json!({
                                    "content": text,
                                    "score": 1.0 - dist,
                                    "frame_id": frame_id
                                }));
                            }
                        }
                    }
                    docs
                }
                Err(e) => return Err(format!("Index search failed: {}", e).into()),
            }
        } else {
            // No index loaded/created yet
            Vec::new()
        }
    };

    // 4. Format Output
    let context_str = results
        .iter()
        .map(|d| d["content"].as_str().unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n\n---\n\n");

    Ok(ExecutionResult {
        status: "success".into(),
        output: context_str,
        data: Some(json!({ "results": results })),
        metrics: Some(json!({
            "latency_ms": start.elapsed().as_millis(),
            "hits": results.len()
        })),
        input_snapshot: Some(input_obj),
        // [NEW] Populate context_slice with the raw results array
        context_slice: Some(json!(results)),
    })
}
