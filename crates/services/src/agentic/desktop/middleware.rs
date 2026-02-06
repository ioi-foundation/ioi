// Path: crates/services/src/agentic/desktop/middleware.rs

use ioi_types::app::agentic::AgentTool;
use anyhow::{Result, anyhow};
use serde_json::{json, Value};

// [FIX] Renamed to match call site in step/mod.rs
pub fn normalize_tool_call(raw_llm_output: &str) -> Result<AgentTool> {
    ToolNormalizer::normalize(raw_llm_output)
}

pub struct ToolNormalizer;

impl ToolNormalizer {
    /// The boundary function. 
    /// Input: Raw, potentially hallucinated JSON from LLM.
    /// Output: Strict Rust Type or Error.
    pub fn normalize(raw_llm_output: &str) -> Result<AgentTool> {
        // [FIX] Fast fail on empty input
        if raw_llm_output.trim().is_empty() {
            return Err(anyhow!("LLM returned empty output (Possible Refusal/Filter)"));
        }

        // 1. Sanitize (Remove markdown blocks, fix trailing commas)
        let json_str = Self::sanitize_json(raw_llm_output); 

        // 2. Parse Generic JSON
        let mut raw_val: Value = serde_json::from_str(&json_str)
            .map_err(|e| anyhow!("JSON Syntax Error: {}", e))?;

        // 3. Heuristic Normalization (Fix "parameters" vs "arguments", Infer missing names)
        // Use flags to avoid borrowing raw_val immutably and mutably at the same time
        let mut needs_wrap_sys = false;
        let mut needs_wrap_chat = false;
        let mut needs_wrap_nav = false;

        if let Some(map) = raw_val.as_object_mut() {
            // [FIX] Handle "recipient_name" hallucination (common in some fine-tunes)
            // Some models output {"recipient_name": "functions.computer", ...} instead of {"name": ...}
            if !map.contains_key("name") {
                if let Some(rn) = map.remove("recipient_name") {
                    map.insert("name".to_string(), rn);
                }
            }

            // [FIX] Handle "functions." prefix hallucination (e.g. "functions.chat__reply")
            if let Some(name_val) = map.get("name") {
                if let Some(name_str) = name_val.as_str() {
                    if name_str.starts_with("functions.") {
                        let fixed_name = name_str.strip_prefix("functions.").unwrap();
                        map.insert("name".to_string(), json!(fixed_name));
                    }
                }
            }

            if !map.contains_key("name") {
                if map.contains_key("command") { needs_wrap_sys = true; }
                else if map.contains_key("message") && map.len() == 1 { needs_wrap_chat = true; }
                else if map.contains_key("url") && map.len() == 1 { needs_wrap_nav = true; }
            }
        }

        if needs_wrap_sys {
            // It's likely a sys__exec call provided flat
            // Wrap it: { "name": "sys__exec", "arguments": { "command": ..., ... } }
            let args = raw_val; // Move
            let mut new_map = serde_json::Map::new();
            new_map.insert("name".to_string(), json!("sys__exec"));
            new_map.insert("arguments".to_string(), args);
            raw_val = Value::Object(new_map);
        } else if needs_wrap_chat {
             let args = raw_val; // Move
             let mut new_map = serde_json::Map::new();
             new_map.insert("name".to_string(), json!("chat__reply"));
             new_map.insert("arguments".to_string(), args);
             raw_val = Value::Object(new_map);
        } else if needs_wrap_nav {
             let args = raw_val; // Move
             let mut new_map = serde_json::Map::new();
             new_map.insert("name".to_string(), json!("browser__navigate"));
             new_map.insert("arguments".to_string(), args);
             raw_val = Value::Object(new_map);
        } else {
             // Alias check (safe to do in-place if we get mut ref now)
             if let Some(map_mut) = raw_val.as_object_mut() {
                 if let Some(params) = map_mut.get("parameters").cloned() {
                    map_mut.insert("arguments".to_string(), params);
                 }
                 
                 // [NEW] Handle synthetic click aliases if LLM gets lazy
                 if let Some(name) = map_mut.get("name").and_then(|n| n.as_str()) {
                     if name == "browser__synthetic_click" {
                         // Ensure arguments are numbers (LLM might pass strings)
                         if let Some(args) = map_mut.get_mut("arguments") {
                             if let Some(x) = args.get("x").and_then(|v| v.as_f64()) {
                                 args["x"] = json!(x as u32);
                             }
                             if let Some(y) = args.get("y").and_then(|v| v.as_f64()) {
                                 args["y"] = json!(y as u32);
                             }
                         }
                     }
                 }
            }
        }
        
        // 4. Strict Typed Deserialization
        // This validates the structure matches AgentTool definitions exactly.
        let tool_call: AgentTool = serde_json::from_value(raw_val)
            .map_err(|e| anyhow!("Schema Validation Error: {}", e))?;

        Ok(tool_call)
    }

    fn sanitize_json(input: &str) -> String {
        let trimmed = input.trim();
        // Check for markdown code blocks
        if trimmed.starts_with("```") {
            let lines: Vec<&str> = trimmed.lines().collect();
            // Remove first line (```json or ```) and last line (```) if valid
            if lines.len() >= 2 && lines.last().unwrap().trim().starts_with("```") {
                return lines[1..lines.len()-1].join("\n");
            }
        }
        // Also handle raw strings that might just have the json prefix without backticks
        if let Some(json_start) = trimmed.strip_prefix("json") {
             return json_start.to_string();
        }
        
        input.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ioi_types::app::agentic::{AgentTool, ComputerAction}; 

    #[test]
    fn test_normalize_clean_json() {
        let input = r#"{"name": "computer", "arguments": {"action": "screenshot"}}"#;
        let tool = ToolNormalizer::normalize(input).unwrap();
        match tool {
            AgentTool::Computer(ComputerAction::Screenshot) => {},
            _ => panic!("Wrong tool type"),
        }
    }

    #[test]
    fn test_normalize_markdown() {
        let input = "```json\n{\"name\": \"sys__exec\", \"arguments\": {\"command\": \"ls\"}}\n```";
        let tool = ToolNormalizer::normalize(input).unwrap();
        match tool {
            AgentTool::SysExec { command, .. } => assert_eq!(command, "ls"),
            _ => panic!("Wrong tool type"),
        }
    }

    #[test]
    fn test_normalize_parameters_alias() {
        // LLM often outputs "parameters" instead of "arguments"
        let input = r#"{"name": "gui__type", "parameters": {"text": "hello"}}"#;
        let tool = ToolNormalizer::normalize(input).unwrap();
        match tool {
            AgentTool::GuiType { text } => assert_eq!(text, "hello"),
            _ => panic!("Wrong tool type"),
        }
    }
    
    #[test]
    fn test_normalize_functions_prefix() {
        // LLM outputs "functions.chat__reply"
        let input = r#"{"name": "functions.chat__reply", "arguments": {"message": "hello"}}"#;
        let tool = ToolNormalizer::normalize(input).unwrap();
        match tool {
            AgentTool::ChatReply { message } => assert_eq!(message, "hello"),
            _ => panic!("Wrong tool type or failed to strip prefix"),
        }
    }

    #[test]
    fn test_normalize_recipient_name() {
        // LLM outputs "recipient_name" instead of "name"
        let input = r#"{"recipient_name": "functions.computer", "parameters": {"action": "screenshot"}}"#;
        let tool = ToolNormalizer::normalize(input).unwrap();
        match tool {
            AgentTool::Computer(ComputerAction::Screenshot) => {},
            _ => panic!("Wrong tool type or failed to handle recipient_name"),
        }
    }
    
    #[test]
    fn test_infer_sys_exec_flat() {
        // Flat output without wrapper
        let input = r#"{"command": "gnome-calculator", "args": [], "detach": true}"#;
        let tool = ToolNormalizer::normalize(input).unwrap();
        match tool {
            AgentTool::SysExec { command, detach, .. } => {
                assert_eq!(command, "gnome-calculator");
                assert_eq!(detach, true);
            },
            _ => panic!("Wrong tool type inferred"),
        }
    }

    #[test]
    fn test_schema_violation_fails() {
        // Missing required field
        let input = r#"{"name": "browser__navigate", "arguments": {}}"#;
        assert!(ToolNormalizer::normalize(input).is_err());
    }
    
    #[test]
    fn test_empty_input_fails() {
        let input = "   ";
        assert!(ToolNormalizer::normalize(input).is_err());
    }
    
    #[test]
    fn test_normalize_synthetic_click() {
        let input = r#"{"name": "browser__synthetic_click", "arguments": {"x": 100.5, "y": 200.1}}"#;
        let tool = ToolNormalizer::normalize(input).unwrap();
        match tool {
            AgentTool::BrowserSyntheticClick { x, y } => {
                assert_eq!(x, 100);
                assert_eq!(y, 200);
            },
            _ => panic!("Wrong tool type"),
        }
    }
}