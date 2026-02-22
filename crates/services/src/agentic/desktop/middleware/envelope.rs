use anyhow::{anyhow, Result};
use serde_json::{json, Value};

pub(super) fn unwrap_tool_envelope(raw_val: Value) -> Result<Value> {
    let mut current = raw_val;

    // Peel a small bounded set of wrappers deterministically.
    for _ in 0..4 {
        let Some(map) = current.as_object() else {
            break;
        };

        // OpenAI: {"tool_calls":[{...}]} (we only take the first tool call in this slice)
        if let Some(tool_calls) = map.get("tool_calls").and_then(|v| v.as_array()) {
            if let Some(first) = tool_calls.first() {
                current = first.clone();
                continue;
            }
        }

        // Generic: {"tool_call": {...}}
        if let Some(tool_call) = map.get("tool_call") {
            current = tool_call.clone();
            continue;
        }

        // OpenAI: {"type":"function","function":{"name":"...","arguments":"{...}"}} (or arguments object)
        let has_name = map.get("name").and_then(|v| v.as_str()).is_some();
        if !has_name {
            if let Some(func) = map.get("function").and_then(|v| v.as_object()) {
                let name = func
                    .get("name")
                    .and_then(|v| v.as_str())
                    .map(str::trim)
                    .filter(|v| !v.is_empty())
                    .ok_or_else(|| anyhow!("Schema Validation Error: missing tool function name"))?
                    .to_string();

                let args = func
                    .get("arguments")
                    .cloned()
                    .or_else(|| func.get("input").cloned())
                    .unwrap_or_else(|| json!({}));

                let args = if let Some(arg_str) = args.as_str() {
                    let trimmed = arg_str.trim();
                    if trimmed.is_empty() {
                        json!({})
                    } else {
                        serde_json::from_str::<Value>(trimmed).map_err(|e| {
                            anyhow!(
                                "Schema Validation Error: function.arguments string must be valid JSON: {}",
                                e
                            )
                        })?
                    }
                } else {
                    args
                };

                if !args.is_object() {
                    return Err(anyhow!(
                        "Schema Validation Error: function.arguments must be a JSON object."
                    ));
                }

                current = json!({
                    "name": name,
                    "arguments": args
                });
                continue;
            }
        }

        break;
    }

    Ok(current)
}

pub(super) fn sanitize_json(input: &str) -> String {
    let trimmed = input.trim();
    // Check for markdown code blocks
    if trimmed.starts_with("```") {
        let lines: Vec<&str> = trimmed.lines().collect();
        // Remove first line (```json or ```) and last line (```) if valid
        if lines.len() >= 2
            && lines
                .last()
                .is_some_and(|line| line.trim().starts_with("```"))
        {
            return lines[1..lines.len() - 1].join("\n");
        }
    }
    // Also handle raw strings that might just have the json prefix without backticks
    if let Some(json_start) = trimmed.strip_prefix("json") {
        return json_start.to_string();
    }

    input.to_string()
}
