// Path: crates/services/src/agentic/desktop/execution/web.rs

use super::{ToolExecutionResult, ToolExecutor};
use ioi_types::app::agentic::AgentTool;
use reqwest::{redirect, Client, Url};
use serde_json::json;
use std::time::Duration;

const NET_FETCH_DEFAULT_MAX_CHARS: u32 = 12_000;
const NET_FETCH_MAX_CHARS_LIMIT: u32 = 120_000;
const NET_FETCH_MAX_BYTES_LIMIT: usize = 2_000_000;

fn is_text_like_content_type(content_type: &str) -> bool {
    let ct = content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if ct.starts_with("text/") {
        return true;
    }

    matches!(
        ct.as_str(),
        "application/json"
            | "application/xml"
            | "application/xhtml+xml"
            | "application/javascript"
            | "application/x-javascript"
            | "application/rss+xml"
            | "application/atom+xml"
    ) || ct.ends_with("+json")
        || ct.ends_with("+xml")
}

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
                    "ERROR_CLASS=TargetNotFound net__fetch requires a non-empty url.".to_string(),
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
            let max_bytes = max_chars
                .saturating_mul(4)
                .clamp(1, NET_FETCH_MAX_BYTES_LIMIT);

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

            let mut resp = match client.get(parsed).send().await {
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

            if let Some(ct) = content_type.as_deref() {
                if !is_text_like_content_type(ct) {
                    let out = json!({
                        "requested_url": url,
                        "final_url": final_url,
                        "status": status,
                        "content_type": content_type,
                        "truncated": false,
                        "body_text": "",
                        "body_omitted": true,
                        "body_omitted_reason": format!("unsupported content-type for text extraction: {}", ct),
                    });
                    return match serde_json::to_string_pretty(&out) {
                        Ok(s) => ToolExecutionResult::success(s),
                        Err(e) => ToolExecutionResult::failure(format!(
                            "ERROR_CLASS=SerializationFailed net__fetch output serialization failed: {}",
                            e
                        )),
                    };
                }
            }

            let mut buf: Vec<u8> = Vec::new();
            let mut truncated_by_bytes = false;
            loop {
                let next = match resp.chunk().await {
                    Ok(chunk) => chunk,
                    Err(e) => {
                        return ToolExecutionResult::failure(format!(
                            "ERROR_CLASS=UnexpectedState net__fetch body read failed: {}",
                            e
                        ))
                    }
                };
                let Some(chunk) = next else {
                    break;
                };

                if buf.len() >= max_bytes {
                    truncated_by_bytes = true;
                    break;
                }

                let remaining = max_bytes.saturating_sub(buf.len());
                if chunk.len() > remaining {
                    buf.extend_from_slice(&chunk[..remaining]);
                    truncated_by_bytes = true;
                    break;
                }

                buf.extend_from_slice(&chunk);
            }

            let body_full = String::from_utf8_lossy(&buf).to_string();
            let (body_text, truncated_by_chars) = truncate_chars(&body_full, max_chars);

            let truncated = truncated_by_bytes || truncated_by_chars;
            let out = json!({
                "requested_url": url,
                "final_url": final_url,
                "status": status,
                "content_type": content_type,
                "truncated": truncated,
                "body_text": body_text,
            });

            match serde_json::to_string_pretty(&out) {
                Ok(s) => ToolExecutionResult::success(s),
                Err(e) => ToolExecutionResult::failure(format!(
                    "ERROR_CLASS=SerializationFailed net__fetch output serialization failed: {}",
                    e
                )),
            }
        }
        other => {
            ToolExecutionResult::failure(format!("Tool {:?} not handled by web executor", other))
        }
    }
}
