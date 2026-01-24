// src-tauri/src/execution.rs

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::error::Error;
use url::Url;
use once_cell::sync::Lazy;
use std::sync::Arc;
use std::collections::HashMap;

// [NEW] Native Drivers & MCP
use ioi_drivers::browser::BrowserDriver;
use ioi_drivers::mcp::{McpManager, McpServerConfig};
use tauri::Manager; // Required for path resolution in init

// [FIX] Added Clone derive so GraphEvent can be cloned for Tauri events in orchestrator.rs
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ExecutionResult {
    pub status: String,
    pub output: String,
    pub data: Option<Value>,
    pub metrics: Option<Value>,
}

// [NEW] Persistent Browser Driver for the Simulator
// The driver internally manages the browser process via Arc<Mutex<...>>, so we can hold it statically.
static BROWSER_DRIVER: Lazy<BrowserDriver> = Lazy::new(|| BrowserDriver::new());

// [NEW] Persistent MCP Manager for the Simulator
// This manages the lifecycle of child processes (like the filesystem server) for the Studio.
static MCP_MANAGER: Lazy<Arc<McpManager>> = Lazy::new(|| {
    Arc::new(McpManager::new())
});

/// Initializes default MCP servers for the local Studio environment.
/// This allows "Run Unit Test" to access the local filesystem via the standard protocol.
pub async fn init_mcp_servers(app_handle: tauri::AppHandle) {
    // Resolve data directory (same as ioi-local)
    let data_dir = app_handle.path().app_data_dir().unwrap_or_else(|_| std::path::PathBuf::from("./ioi-data"));
    
    // Ensure absolute path
    let abs_data_dir = std::fs::canonicalize(&data_dir).unwrap_or_else(|_| {
        std::fs::create_dir_all(&data_dir).ok();
        data_dir.clone()
    });
    
    // Default Filesystem Server
    // We assume 'npx' is available. In a bundled app, we might bundle the binary directly.
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
/// This enforces data discipline: only explicitly bound variables enter the context.
fn interpolate_template(template: &str, context: &Value) -> String {
    let mut result = template.to_string();
    
    // Simple parser to find {{key}} patterns
    let mut start_idx = 0;
    while let Some(open) = result[start_idx..].find("{{") {
        let actual_open = start_idx + open;
        if let Some(close) = result[actual_open..].find("}}") {
            let actual_close = actual_open + close;
            // Extract key, e.g., "vendor_name"
            let key = &result[actual_open + 2..actual_close].trim();
            
            // Resolve key from JSON context (supports top-level keys for now)
            // If the value is a string, unwrap it to avoid extra quotes in the prompt.
            // If it's a number/object, serialize it.
            let replacement = if let Some(val) = context.get(key) {
                if let Some(s) = val.as_str() { 
                    s.to_string() 
                } else { 
                    val.to_string() 
                }
            } else {
                format!("<<MISSING:{}>>", key)
            };

            // Replace {{key}} with value
            result.replace_range(actual_open..actual_close + 2, &replacement);
            
            // Move search index forward to handle multiple occurrences
            start_idx = actual_open + replacement.len();
        } else {
            break;
        }
    }
    result
}

/// The Governance Layer
/// Checks constraints defined in the "Law" tab before Logic execution.
fn enforce_law(node_type: &str, config: &Value, input_context: &str) -> Result<(), String> {
    let default_val = serde_json::json!({});
    let law = config.get("law").unwrap_or(&default_val);
    let logic = config.get("logic").unwrap_or(&default_val);

    // 1. Network Policy Enforcement (Firewall)
    if node_type == "tool" || node_type == "browser" {
        // [FIX] Check for 'endpoint' (tool) OR 'url' (browser)
        let target = logic.get("endpoint")
            .or_else(|| logic.get("url"))
            .and_then(|v| v.as_str());

        if let Some(target_url) = target {
            if let Ok(url) = Url::parse(target_url) {
                if let Some(host) = url.host_str() {
                    let allowlist = law.get("networkAllowlist")
                        .and_then(|v| v.as_array())
                        .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect::<Vec<&str>>())
                        .unwrap_or_default();

                    if !allowlist.is_empty() {
                        let mut allowed = false;
                        for pattern in allowlist {
                            if pattern.starts_with("*.") {
                                let suffix: &str = &pattern[2..];
                                if host.ends_with(suffix) { allowed = true; break; }
                            } else if host == pattern {
                                allowed = true; break;
                            }
                        }
                        if !allowed {
                            return Err(format!("🛡️ BLOCKED: Domain '{}' is not in the Network Allowlist.", host));
                        }
                    }
                }
            }
        }
    }

    // 2. Budget/Risk Simulation
    if let Some(budget_cap) = law.get("budgetCap").and_then(|v| v.as_f64()) {
        // Simple heuristic: If input context is massive (likely expensive LLM processing) 
        // and budget is tiny, block it.
        if input_context.len() > 10_000 && budget_cap < 0.05 {
             return Err(format!("🛡️ BLOCKED: Input size ({} chars) likely exceeds Budget Cap (${})", input_context.len(), budget_cap));
        }
    }

    Ok(())
}

/// Main entry point for executing a node in the local environment.
pub async fn execute_ephemeral_node(
    node_type: &str,
    full_config: &Value, 
    input_json: &str,
) -> Result<ExecutionResult, Box<dyn Error>> {
    
    // --- STEP 1: GOVERNANCE CHECK ---
    if let Err(violation) = enforce_law(node_type, full_config, input_json) {
        return Ok(ExecutionResult {
            status: "blocked".to_string(),
            output: violation,
            data: None,
            metrics: Some(serde_json::json!({ "risk": "high" })),
        });
    }

    // --- STEP 2: EXECUTION ---
    let logic_config = full_config.get("logic").unwrap_or(full_config);

    match node_type {
        "model" => run_llm_inference(logic_config, input_json).await,
        "gate" => run_gate_execution(logic_config, input_json).await,
        "browser" => run_browser_execution(logic_config, input_json).await,
        // [UPDATED] Route "tool" to MCP if it's not a native HTTP tool
        "tool" => {
            let tool_name = logic_config.get("tool_name").and_then(|s| s.as_str());
            if let Some(name) = tool_name {
                // If it names a specific tool (e.g. "filesystem__read_file"), use MCP
                run_mcp_tool(name, logic_config, input_json).await
            } else {
                // Fallback to legacy HTTP handler (if "endpoint" is present)
                run_tool_execution(logic_config, input_json).await
            }
        },
        "receipt" => Ok(ExecutionResult {
            status: "success".to_string(),
            output: format!("Receipt Logged: {}", input_json.chars().take(50).collect::<String>()),
            data: Some(serde_json::json!({ "signed": true, "timestamp": chrono::Utc::now().to_rfc3339() })),
            metrics: None,
        }),
        _ => Ok(ExecutionResult {
            status: "skipped".to_string(),
            output: format!("Ephemeral execution not implemented for {}", node_type),
            data: None,
            metrics: None,
        }),
    }
}

// [NEW] MCP Execution Handler
async fn run_mcp_tool(tool_name: &str, config: &Value, input: &str) -> Result<ExecutionResult, Box<dyn Error>> {
    let start = std::time::Instant::now();
    let input_obj: Value = serde_json::from_str(input).unwrap_or(json!({}));
    
    // Merge config args with input args (Input takes precedence for variables)
    // The Studio UI might store default arguments in config.
    let mut args = config.get("arguments").cloned().unwrap_or(json!({}));
    
    if let Value::Object(ref mut map) = args {
        if let Value::Object(input_map) = input_obj {
            for (k, v) in input_map {
                map.insert(k, v);
            }
        }
    }

    match MCP_MANAGER.execute_tool(tool_name, args).await {
        Ok(output) => Ok(ExecutionResult {
            status: "success".to_string(),
            output: output.clone(),
            // Wrap in "raw" if string, or parse if JSON for data inspector
            data: match serde_json::from_str(&output) {
                Ok(v) => Some(v),
                Err(_) => Some(json!({ "raw": output })),
            },
            metrics: Some(json!({ "latency_ms": start.elapsed().as_millis() })),
        }),
        Err(e) => Ok(ExecutionResult {
            status: "error".to_string(),
            output: format!("MCP Error: {}", e),
            data: None,
            metrics: None,
        })
    }
}

// [NEW] Browser Execution Handler (Real Native Driver)
async fn run_browser_execution(config: &Value, input: &str) -> Result<ExecutionResult, Box<dyn Error>> {
    let start = std::time::Instant::now();
    
    // 1. Ensure Driver is Running
    if let Err(e) = BROWSER_DRIVER.launch().await {
        return Ok(ExecutionResult {
            status: "error".to_string(),
            output: format!("Failed to launch browser driver: {}", e),
            data: None,
            metrics: None
        });
    }

    // 2. Parse Context & Config
    let input_obj: Value = serde_json::from_str(input).unwrap_or(serde_json::json!({}));
    
    // Determine action type
    let action = config.get("action").and_then(|v| v.as_str()).unwrap_or("navigate");
    
    match action {
        "navigate" => {
            // Get URL from config or input context
            let url_template = config.get("url").and_then(|v| v.as_str()).ok_or("Missing 'url' in logic config")?;
            let url = interpolate_template(url_template, &input_obj);
            
            match BROWSER_DRIVER.navigate(&url).await {
                Ok(content) => {
                    // let preview = if content.len() > 500 { format!("{}...", &content[..500]) } else { content.clone() };
                    Ok(ExecutionResult {
                        status: "success".to_string(),
                        output: content.clone(),
                        data: Some(serde_json::json!({ 
                            "url": url,
                            "title": "Page Loaded", // Driver could be updated to return title
                            "content_length": content.len()
                        })),
                        metrics: Some(serde_json::json!({ "latency_ms": start.elapsed().as_millis() })),
                    })
                },
                Err(e) => Ok(ExecutionResult {
                    status: "error".to_string(),
                    output: format!("Navigation failed: {}", e),
                    data: None,
                    metrics: Some(serde_json::json!({ "latency_ms": start.elapsed().as_millis() })),
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
                }),
                Err(e) => Ok(ExecutionResult {
                    status: "error".to_string(),
                    output: format!("DOM extraction failed: {}", e),
                    data: None,
                    metrics: None
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
                }),
                Err(e) => Ok(ExecutionResult {
                    status: "error".to_string(),
                    output: format!("Click failed: {}", e),
                    data: None,
                    metrics: None
                })
            }
        },
        _ => Ok(ExecutionResult {
            status: "error".to_string(),
            output: format!("Unknown browser action: {}", action),
            data: None,
            metrics: None
        })
    }
}

// [UPDATED] Gate Logic Evaluator with robust JSON Pointer support
async fn run_gate_execution(config: &Value, input: &str) -> Result<ExecutionResult, Box<dyn Error>> {
    let start = std::time::Instant::now();
    let condition = config.get("conditionScript")
        .or_else(|| config.get("condition"))
        .and_then(|v| v.as_str())
        .unwrap_or("true"); // Default to pass if no condition

    // Parse Input JSON to check fields
    let input_obj: Value = serde_json::from_str(input).unwrap_or(serde_json::json!({}));

    // Logic Evaluation
    let passed; 
    let mut reason = "Condition met".to_string();

    // 1. Clean string
    let cond = condition.trim().to_string();
    
    if cond == "true" {
        passed = true;
    } else {
        // Basic parser: splits by spaces.
        // E.g. "input.risk_score > 0.5" or "input.vendor == 'ACME'"
        let parts: Vec<&str> = cond.split_whitespace().collect();
        
        if parts.len() >= 3 {
            let key_path = parts[0]; // e.g. "input.risk_score"
            let op = parts[1];       // e.g. ">"
            let target_val_str = parts[2]; // e.g. "0.5"

            // Convert "input.a.b" -> "/a/b" for serde pointer
            let json_pointer = if key_path.starts_with("input.") {
                key_path.replace("input.", "/").replace(".", "/")
            } else {
                format!("/{}", key_path.replace(".", "/"))
            };

            // Resolve value from input object
            let actual_val_opt = input_obj.pointer(&json_pointer);
            
            // Perform comparison
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
                    // String comparison
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
            // Fallback for complex scripts not yet supported locally
            reason = "Complex script syntax not supported in Local Mode. Use 'input.field > value'".to_string();
            passed = false; 
        }
    }

    Ok(ExecutionResult {
        // [IMPORTANT] Map failure to "blocked" so Orchestrator routes to the "blocked" handle
        status: if passed { "success".to_string() } else { "blocked".to_string() },
        output: if passed { input.to_string() } else { format!("Gate Blocked: {}", reason) },
        data: Some(serde_json::json!({ 
            "condition": condition, 
            "passed": passed,
            "reason": reason
        })),
        metrics: Some(serde_json::json!({ "latency_ms": start.elapsed().as_millis() })),
    })
}

// [UPDATED] LLM Inference with Strict Templating Support
async fn run_llm_inference(config: &Value, input_json: &str) -> Result<ExecutionResult, Box<dyn Error>> {
    let system_prompt = config.get("systemPrompt")
        .or_else(|| config.get("system_prompt"))
        .and_then(|v| v.as_str())
        .unwrap_or("You are a helpful assistant.");
        
    let model = config.get("model")
        .and_then(|v| v.as_str())
        .unwrap_or("llama3");

    // [FIX] Correct variable name from `input` to `input_json`
    // Parse input to Value for interpolation
    let input_obj: Value = serde_json::from_str(input_json).unwrap_or(serde_json::json!({}));

    // [GOVERNANCE] Strict Context Construction
    // If the system prompt contains templating {{...}}, we ONLY use the templated variables.
    // If not, we fallback to the "Context Dump" mode (Legacy support).
    let final_user_prompt = if system_prompt.contains("{{") {
        interpolate_template(system_prompt, &input_obj)
    } else {
        // Fallback: Dump everything (Lazy Mode)
        format!("Context Data:\n{}\n\nTask: Analyze this data based on system instructions.", input_json)
    };

    let client = reqwest::Client::new();
    let start = std::time::Instant::now();
    
    // Call Ollama (Local)
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
                        // Return the prompt we actually used for debugging transparency
                        "final_prompt_snapshot": final_user_prompt 
                    })),
                })
            } else {
                Ok(ExecutionResult {
                    status: "failed".to_string(),
                    output: format!("LLM Provider Error: {}", response.status()),
                    data: None,
                    metrics: Some(serde_json::json!({ "latency_ms": duration.as_millis() })),
                })
            }
        },
        Err(e) => {
            // Simulation fallback if Ollama is not running
            Ok(ExecutionResult {
                status: "simulated".to_string(),
                output: format!("[Simulated Output - Ollama Offline]\nModel: {}\nPrompt Used: {}\nError: {}", model, final_user_prompt.chars().take(150).collect::<String>(), e),
                data: Some(serde_json::json!({ "final_prompt_snapshot": final_user_prompt })),
                metrics: Some(serde_json::json!({ "latency_ms": 15, "error": e.to_string() })),
            })
        }
    }
}

// [UPDATED] Tool Execution with Strict Templating Support
async fn run_tool_execution(config: &Value, input: &str) -> Result<ExecutionResult, Box<dyn Error>> {
    let url = config.get("endpoint")
        .or_else(|| config.get("url"))
        .and_then(|v| v.as_str())
        .ok_or("Tool configuration missing 'endpoint'")?;

    let method = config.get("method").and_then(|v| v.as_str()).unwrap_or("GET").to_uppercase();
    let body_template = config.get("bodyTemplate").and_then(|v| v.as_str()).unwrap_or("");

    let client = reqwest::Client::new();
    let start = std::time::Instant::now();

    // Parse input once
    let input_obj: Value = serde_json::from_str(input).unwrap_or(serde_json::json!({}));

    let mut builder = match method.as_str() {
        "POST" => client.post(url),
        "PUT" => client.put(url),
        "DELETE" => client.delete(url),
        _ => client.get(url),
    };

    if !body_template.is_empty() && (method == "POST" || method == "PUT") {
        // Use the unified interpolator logic
        let final_body = interpolate_template(body_template, &input_obj);
        
        // Try to send as JSON if valid, else raw text
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
            })
        },
        Err(e) => {
            Ok(ExecutionResult {
                status: "error".to_string(),
                output: format!("Network Request Failed: {}", e),
                data: None,
                metrics: Some(serde_json::json!({ "latency_ms": duration.as_millis() })),
            })
        }
    }
}