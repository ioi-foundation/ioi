// Path: crates/services/src/agentic/desktop/execution/web.rs

use super::{ToolExecutionResult, ToolExecutor};
use ioi_types::app::agentic::AgentTool;
use reqwest::{redirect, Client, Url};
use serde_json::json;
use std::time::Duration;

const NET_FETCH_DEFAULT_MAX_CHARS: u32 = 12_000;
const NET_FETCH_MAX_CHARS_LIMIT: u32 = 120_000;

fn truncate_chars(input: &str, max: usize) -> (String, bool) {
    if max == 0 {
        return (String::new(), !input.is_empty());
    }
    let mut out = String::new();
    let mut count = 0usize;
    for ch in input.chars() {
        if count >= max {
            return (out, true);
        }
        out.push(ch);
        count += 1;
    }
    (out, false)
}

pub async fn handle(exec: &ToolExecutor, tool: AgentTool) -> ToolExecutionResult {
    match tool {
        AgentTool::WebSearch { query, limit, .. } => {
            let limit = limit.unwrap_or(5).clamp(1, 10);
            match crate::agentic::web::edge_web_search(&exec.browser, &query, limit).await {
                Ok(bundle) => match serde_json::to_string_pretty(&bundle) {
                    Ok(out) => ToolExecutionResult::success(out),
                    Err(e) => ToolExecutionResult::failure(format!(
                        "ERROR_CLASS=SerializationFailed Failed to serialize web evidence: {}",
                        e
                    )),
                },
                Err(e) => ToolExecutionResult::failure(e.to_string()),
            }
        }
        AgentTool::WebRead { url, max_chars } => {
            let max_chars = Some(max_chars.unwrap_or(NET_FETCH_DEFAULT_MAX_CHARS));
            match crate::agentic::web::edge_web_read(&exec.browser, &url, max_chars).await {
                Ok(bundle) => match serde_json::to_string_pretty(&bundle) {
                    Ok(out) => ToolExecutionResult::success(out),
                    Err(e) => ToolExecutionResult::failure(format!(
                        "ERROR_CLASS=SerializationFailed Failed to serialize web evidence: {}",
                        e
                    )),
                },
                Err(e) => ToolExecutionResult::failure(e.to_string()),
            }
        }
        AgentTool::Dynamic(val) => {
            if val.get("name").and_then(|n| n.as_str()) != Some("net__fetch") {
                return ToolExecutionResult::failure(format!(
                    "Tool {:?} not handled by web executor",
                    AgentTool::Dynamic(val)
                ));
            }

            let args = val
                .get("arguments")
                .cloned()
                .unwrap_or_else(|| json!({}));
            let url = args
                .get("url")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim();
            if url.is_empty() {
                return ToolExecutionResult::failure(
                    "ERROR_CLASS=ToolUnavailable net__fetch requires a non-empty url.".to_string(),
                );
            }

            let parsed = match Url::parse(url) {
                Ok(u) => u,
                Err(e) => {
                    return ToolExecutionResult::failure(format!(
                        "ERROR_CLASS=TargetNotFound net__fetch url parse failed: {}",
                        e
                    ))
                }
            };
            if parsed.scheme() != "http" && parsed.scheme() != "https" {
                return ToolExecutionResult::failure(format!(
                    "ERROR_CLASS=TargetNotFound net__fetch only supports http/https (got scheme='{}').",
                    parsed.scheme()
                ));
            }

            let max_chars = args
                .get("max_chars")
                .and_then(|v| v.as_u64())
                .unwrap_or(NET_FETCH_DEFAULT_MAX_CHARS as u64)
                .clamp(1, NET_FETCH_MAX_CHARS_LIMIT as u64) as usize;

            let client = match Client::builder()
                .redirect(redirect::Policy::limited(5))
                .timeout(Duration::from_secs(30))
                .user_agent("ioi-net-fetch/1.0")
                .build()
            {
                Ok(c) => c,
                Err(e) => {
                    return ToolExecutionResult::failure(format!(
                        "ERROR_CLASS=UnexpectedState net__fetch client init failed: {}",
                        e
                    ))
                }
            };

            let resp = match client.get(parsed).send().await {
                Ok(r) => r,
                Err(e) => {
                    return ToolExecutionResult::failure(format!(
                        "ERROR_CLASS=UnexpectedState net__fetch request failed: {}",
                        e
                    ))
                }
            };

            let status = resp.status().as_u16();
            let final_url = resp.url().to_string();
            let content_type = resp
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());

            let bytes = match resp.bytes().await {
                Ok(b) => b,
                Err(e) => {
                    return ToolExecutionResult::failure(format!(
                        "ERROR_CLASS=UnexpectedState net__fetch body read failed: {}",
                        e
                    ))
                }
            };

            let body_full = String::from_utf8_lossy(&bytes).to_string();
            let (body_text, truncated) = truncate_chars(&body_full, max_chars);

            let out = json!({
                "requested_url": url,
                "final_url": final_url,
                "status": status,
                "content_type": content_type,
                "truncated": truncated,
                "body_text": body_text,
            });

            ToolExecutionResult::success(out.to_string())
        }
        other => {
            ToolExecutionResult::failure(format!("Tool {:?} not handled by web executor", other))
        }
    }
}
