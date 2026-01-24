// apps/autopilot/src-tauri/src/execution.rs

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::error::Error;
use once_cell::sync::Lazy;
use std::sync::Arc;
use std::collections::HashMap;

// Native Drivers & MCP
use ioi_drivers::browser::BrowserDriver;
use ioi_drivers::mcp::{McpManager, McpServerConfig};
use tauri::Manager; 

// Governance & Policy Integration
use ioi_services::agentic::policy::PolicyEngine;
use ioi_services::agentic::rules::{ActionRules, DefaultPolicy, Rule, RuleConditions, Verdict};
use ioi_types::app::{ActionContext, ActionRequest, ActionTarget};
use ioi_api::vm::drivers::os::OsDriver;
use ioi_drivers::os::NativeOsDriver;
use ioi_api::vm::inference::{LocalSafetyModel, SafetyVerdict};
use async_trait::async_trait;

// [MODIFIED] Added `input_snapshot` field for Data Intimacy / Input Observability
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ExecutionResult {
    pub status: String,
    pub output: String,
    pub data: Option<Value>,
    pub metrics: Option<Value>,
    // [NEW] The exact JSON context state used during this execution
    pub input_snapshot: Option<Value>,
}

// Persistent Browser Driver for the Simulator
static BROWSER_DRIVER: Lazy<BrowserDriver> = Lazy::new(|| BrowserDriver::new());

// Persistent MCP Manager for the Simulator
static MCP_MANAGER: Lazy<Arc<McpManager>> = Lazy::new(|| {
    Arc::new(McpManager::new())
});

// Public accessor for Kernel commands
pub async fn get_active_mcp_tools() -> Vec<ioi_types::app::agentic::LlmToolDefinition> {
    MCP_MANAGER.get_all_tools().await
}

// Native OS Driver for Policy Context
static OS_DRIVER: Lazy<Arc<dyn OsDriver>> = Lazy::new(|| {
    Arc::new(NativeOsDriver::new())
});

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
static SAFETY_MODEL: Lazy<Arc<dyn LocalSafetyModel>> = Lazy::new(|| {
    Arc::new(SimulationSafetyModel)
});

/// Initializes default MCP servers for the local Studio environment.
pub async fn init_mcp_servers(app_handle: tauri::AppHandle) {
    let data_dir = app_handle.path().app_data_dir().unwrap_or_else(|_| std::path::PathBuf::from("./ioi-data"));
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
                if let Some(s) = val.as_str() { s.to_string() } else { val.to_string() }
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

    if let Some(allowlist) = law_config.get("networkAllowlist").and_then(|v| v.as_array()) {
        let domains: Vec<String> = allowlist.iter()
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
        _ => "*"
    };

    let require_human = law_config.get("requireHumanGate").and_then(|v| v.as_bool()).unwrap_or(false);
    let action = if require_human { Verdict::RequireApproval } else { Verdict::Allow };

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

// Governance Logic: Construct canonical ActionRequest
fn map_to_action_request(node_type: &str, logic_config: &Value, input_json: &str) -> ActionRequest {
    let target = match node_type {
        "browser" => ActionTarget::BrowserNavigate,
        "tool" => {
            if let Some(endpoint) = logic_config.get("endpoint").and_then(|s| s.as_str()) {
                 if endpoint.starts_with("http") { ActionTarget::NetFetch } 
                 else { ActionTarget::Custom("tool:generic".into()) }
            } else {
                 ActionTarget::Custom("tool:generic".into())
            }
        },
        _ => ActionTarget::Custom(format!("node:{}", node_type))
    };

    let mut params_obj = json!({});
    let input_ctx: Value = serde_json::from_str(input_json).unwrap_or(json!({}));

    if let Some(url_template) = logic_config.get("url").or_else(|| logic_config.get("endpoint")).and_then(|s| s.as_str()) {
        let final_url = interpolate_template(url_template, &input_ctx);
        params_obj["url"] = json!(final_url);
    }
    
    if let Some(budget) = logic_config.get("cost").and_then(|v| v.as_u64()) {
        params_obj["total_amount"] = json!(budget);
    }

    let params_bytes = serde_json::to_vec(&params_obj).unwrap_or_default();

    ActionRequest {
        target,
        params: params_bytes,
        context: ActionContext {
            agent_id: "studio-simulator".into(),
            session_id: None,
            window_id: None,
        },
        nonce: 0,
    }
}

/// The Governance Layer
async fn check_governance(node_type: &str, config: &Value, input_context: &str) -> Result<(), String> {
    let default_val = serde_json::json!({});
    let law_config = config.get("law").unwrap_or(&default_val);
    let logic_config = config.get("logic").unwrap_or(&default_val);

    let policy = synthesize_node_policy(node_type, law_config);
    let request = map_to_action_request(node_type, logic_config, input_context);

    let verdict = PolicyEngine::evaluate(
        &policy,
        &request,
        &*SAFETY_MODEL,
        &*OS_DRIVER,
        None 
    ).await;

    match verdict {
        Verdict::Allow => Ok(()),
        Verdict::Block => Err("🛡️ BLOCKED: Policy violation (e.g., Domain not in allowlist)".into()),
        Verdict::RequireApproval => Err("🛡️ PAUSED: Execution requires Human Approval (Gate)".into()),
    }
}

/// Main entry point for executing a node in the local environment.
pub async fn execute_ephemeral_node(
    node_type: &str,
    full_config: &Value, 
    input_json: &str,
) -> Result<ExecutionResult, Box<dyn Error>> {
    
    // Parse input snapshot primarily for debugging visibility in blocked states
    let input_snapshot: Option<Value> = serde_json::from_str(input_json).ok();

    // --- STEP 1: GOVERNANCE CHECK ---
    if let Err(violation) = check_governance(node_type, full_config, input_json).await {
        return Ok(ExecutionResult {
            status: "blocked".to_string(),
            output: violation,
            data: None,
            metrics: Some(serde_json::json!({ "risk": "high" })),
            input_snapshot, // [MODIFIED] Return input even on block so user can see what triggered it
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
        },
        "receipt" => Ok(ExecutionResult {
            status: "success".to_string(),
            output: format!("Receipt Logged: {}", input_json.chars().take(50).collect::<String>()),
            data: Some(serde_json::json!({ "signed": true, "timestamp": chrono::Utc::now().to_rfc3339() })),
            metrics: None,
            input_snapshot,
        }),
        _ => Ok(ExecutionResult {
            status: "skipped".to_string(),
            output: format!("Ephemeral execution not implemented for {}", node_type),
            data: None,
            metrics: None,
            input_snapshot,
        }),
    }
}

// [MODIFIED] MCP Execution Handler with Input Snapshot
async fn run_mcp_tool(tool_name: &str, config: &Value, input: &str) -> Result<ExecutionResult, Box<dyn Error>> {
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
            },
            Value::Array(arr) => {
                Value::Array(arr.iter().map(|v| interpolate_recursive(v, ctx)).collect())
            },
            Value::Object(map) => {
                let mut new_map = serde_json::Map::new();
                for (k, v) in map {
                    new_map.insert(k.clone(), interpolate_recursive(v, ctx));
                }
                Value::Object(new_map)
            },
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
            input_snapshot: Some(input_obj), // [NEW] Capture
        }),
        Err(e) => Ok(ExecutionResult {
            status: "error".to_string(),
            output: format!("MCP Error: {}", e),
            data: None,
            metrics: None,
            input_snapshot: Some(input_obj), // [NEW] Capture
        })
    }
}

// [MODIFIED] Browser Execution with Input Snapshot
async fn run_browser_execution(config: &Value, input: &str) -> Result<ExecutionResult, Box<dyn Error>> {
    let start = std::time::Instant::now();
    let input_obj: Value = serde_json::from_str(input).unwrap_or(serde_json::json!({}));
    
    if let Err(e) = BROWSER_DRIVER.launch().await {
        return Ok(ExecutionResult {
            status: "error".to_string(),
            output: format!("Failed to launch browser driver: {}", e),
            data: None,
            metrics: None,
            input_snapshot: Some(input_obj),
        });
    }

    let action = config.get("action").and_then(|v| v.as_str()).unwrap_or("navigate");
    
    match action {
        "navigate" => {
            let url_template = config.get("url").and_then(|v| v.as_str()).ok_or("Missing 'url' in logic config")?;
            let url = interpolate_template(url_template, &input_obj);
            
            match BROWSER_DRIVER.navigate(&url).await {
                Ok(content) => {
                    Ok(ExecutionResult {
                        status: "success".to_string(),
                        output: content.clone(),
                        data: Some(serde_json::json!({ 
                            "url": url,
                            "title": "Page Loaded", 
                            "content_length": content.len()
                        })),
                        metrics: Some(serde_json::json!({ "latency_ms": start.elapsed().as_millis() })),
                        input_snapshot: Some(input_obj), // [NEW] Capture
                    })
                },
                Err(e) => Ok(ExecutionResult {
                    status: "error".to_string(),
                    output: format!("Navigation failed: {}", e),
                    data: None,
                    metrics: Some(serde_json::json!({ "latency_ms": start.elapsed().as_millis() })),
                    input_snapshot: Some(input_obj), // [NEW] Capture
                })
            }
        },
        "extract_dom" => {
            match BROWSER_DRIVER.extract_dom().await {
                Ok(dom) => Ok(ExecutionResult {
                    status: "success".to_string(),
                    output: dom.clone(),
                    data: Some(serde_json::json!({ "dom_length": dom.len() })),
                    metrics: Some(serde_json::json!({ "latency_ms": start.elapsed().as_millis() })),
                    input_snapshot: Some(input_obj),
                }),
                Err(e) => Ok(ExecutionResult {
                    status: "error".to_string(),
                    output: format!("DOM extraction failed: {}", e),
                    data: None,
                    metrics: None,
                    input_snapshot: Some(input_obj),
                })
            }
        },
        "click" => {
            let selector = config.get("selector").and_then(|v| v.as_str()).ok_or("Missing 'selector'")?;
             match BROWSER_DRIVER.click_selector(selector).await {
                Ok(_) => Ok(ExecutionResult {
                    status: "success".to_string(),
                    output: format!("Clicked element: {}", selector),
                    data: Some(serde_json::json!({ "action": "click", "selector": selector })),
                    metrics: Some(serde_json::json!({ "latency_ms": start.elapsed().as_millis() })),
                    input_snapshot: Some(input_obj),
                }),
                Err(e) => Ok(ExecutionResult {
                    status: "error".to_string(),
                    output: format!("Click failed: {}", e),
                    data: None,
                    metrics: None,
                    input_snapshot: Some(input_obj),
                })
            }
        },
        _ => Ok(ExecutionResult {
            status: "error".to_string(),
            output: format!("Unknown browser action: {}", action),
            data: None,
            metrics: None,
            input_snapshot: Some(input_obj),
        })
    }
}

// [MODIFIED] Gate Execution with Input Snapshot
async fn run_gate_execution(config: &Value, input: &str) -> Result<ExecutionResult, Box<dyn Error>> {
    let start = std::time::Instant::now();
    let condition = config.get("conditionScript")
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
                        _ => { passed = false; reason = format!("Unknown operator: {}", op); }
                    }
                    if !passed {
                        reason = format!("Field '{}' ({}) is not {} {}", key_path, num_val, op, target_num);
                    }
                } else if let Some(str_val) = val.as_str() {
                    let target_clean = target_val_str.trim_matches('"').trim_matches('\'');
                    match op {
                        "==" => passed = str_val == target_clean,
                        "!=" => passed = str_val != target_clean,
                        "contains" => passed = str_val.contains(target_clean),
                        _ => { passed = false; reason = "Invalid operator for string".into(); }
                    }
                    if !passed {
                        reason = format!("Field '{}' ('{}') check failed vs '{}'", key_path, str_val, target_clean);
                    }
                } else if let Some(bool_val) = val.as_bool() {
                    let target_bool = target_val_str.parse::<bool>().unwrap_or(false);
                    match op {
                        "==" => passed = bool_val == target_bool,
                        "!=" => passed = bool_val != target_bool,
                        _ => { passed = false; reason = "Invalid operator for boolean".into(); }
                    }
                    if !passed {
                        reason = format!("Field '{}' ({}) is not {}", key_path, bool_val, target_bool);
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
            reason = "Complex script syntax not supported in Local Mode. Use 'input.field > value'".to_string();
            passed = false; 
        }
    }

    Ok(ExecutionResult {
        status: if passed { "success".to_string() } else { "blocked".to_string() },
        output: if passed { input.to_string() } else { format!("Gate Blocked: {}", reason) },
        data: Some(serde_json::json!({ 
            "condition": condition, 
            "passed": passed,
            "reason": reason
        })),
        metrics: Some(serde_json::json!({ "latency_ms": start.elapsed().as_millis() })),
        input_snapshot: Some(input_obj), // [NEW] Capture
    })
}

// [MODIFIED] LLM Inference with Input Snapshot
async fn run_llm_inference(config: &Value, input_json: &str) -> Result<ExecutionResult, Box<dyn Error>> {
    let system_prompt = config.get("systemPrompt")
        .or_else(|| config.get("system_prompt"))
        .and_then(|v| v.as_str())
        .unwrap_or("You are a helpful assistant.");
        
    let model = config.get("model")
        .and_then(|v| v.as_str())
        .unwrap_or("llama3");

    let input_obj: Value = serde_json::from_str(input_json).unwrap_or(serde_json::json!({}));

    let final_user_prompt = if system_prompt.contains("{{") {
        interpolate_template(system_prompt, &input_obj)
    } else {
        format!("Context Data:\n{}\n\nTask: Analyze this data based on system instructions.", input_json)
    };

    let client = reqwest::Client::new();
    let start = std::time::Instant::now();
    
    let res = client.post("http://127.0.0.1:11434/api/generate")
        .json(&serde_json::json!({
            "model": model, 
            "system": "You are an automated agent executing a specific task based on the provided context.",
            "prompt": final_user_prompt,
            "stream": false
        }))
        .send()
        .await;

    let duration = start.elapsed();

    match res {
        Ok(response) => {
            if response.status().is_success() {
                let body: Value = response.json().await?;
                let response_text = body["response"].as_str().unwrap_or("No response content").to_string();
                
                Ok(ExecutionResult {
                    status: "success".to_string(),
                    output: response_text,
                    data: Some(serde_json::json!({ "raw_response": body })),
                    metrics: Some(serde_json::json!({
                        "latency_ms": duration.as_millis(),
                        "eval_count": body.get("eval_count").unwrap_or(&serde_json::json!(0)),
                        "final_prompt_snapshot": final_user_prompt 
                    })),
                    input_snapshot: Some(input_obj), // [NEW] Capture
                })
            } else {
                Ok(ExecutionResult {
                    status: "failed".to_string(),
                    output: format!("LLM Provider Error: {}", response.status()),
                    data: None,
                    metrics: Some(serde_json::json!({ "latency_ms": duration.as_millis() })),
                    input_snapshot: Some(input_obj), // [NEW] Capture
                })
            }
        },
        Err(e) => {
            Ok(ExecutionResult {
                status: "simulated".to_string(),
                output: format!("[Simulated Output - Ollama Offline]\nModel: {}\nPrompt Used: {}\nError: {}", model, final_user_prompt.chars().take(150).collect::<String>(), e),
                data: Some(serde_json::json!({ "final_prompt_snapshot": final_user_prompt })),
                metrics: Some(serde_json::json!({ "latency_ms": 15, "error": e.to_string() })),
                input_snapshot: Some(input_obj), // [NEW] Capture
            })
        }
    }
}

// [MODIFIED] Tool Execution with Input Snapshot
async fn run_tool_execution(config: &Value, input: &str) -> Result<ExecutionResult, Box<dyn Error>> {
    let url = config.get("endpoint")
        .or_else(|| config.get("url"))
        .and_then(|v| v.as_str())
        .ok_or("Tool configuration missing 'endpoint'")?;

    let method = config.get("method").and_then(|v| v.as_str()).unwrap_or("GET").to_uppercase();
    let body_template = config.get("bodyTemplate").and_then(|v| v.as_str()).unwrap_or("");

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
                status: if status.is_success() { "success".to_string() } else { "failed".to_string() },
                output: text.clone(),
                data: Some(serde_json::json!({ 
                    "status_code": status.as_u16(),
                    "body_preview": text.chars().take(500).collect::<String>() 
                })),
                metrics: Some(serde_json::json!({ "latency_ms": duration.as_millis() })),
                input_snapshot: Some(input_obj), // [NEW] Capture
            })
        },
        Err(e) => {
            Ok(ExecutionResult {
                status: "error".to_string(),
                output: format!("Network Request Failed: {}", e),
                data: None,
                metrics: Some(serde_json::json!({ "latency_ms": duration.as_millis() })),
                input_snapshot: Some(input_obj), // [NEW] Capture
            })
        }
    }
}