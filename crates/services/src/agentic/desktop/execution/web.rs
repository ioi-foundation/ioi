// Path: crates/services/src/agentic/desktop/execution/web.rs

use super::{workload, ToolExecutionResult, ToolExecutor};
use ioi_types::app::agentic::AgentTool;
use ioi_types::app::{WorkloadActivityKind, WorkloadNetFetchReceipt, WorkloadReceipt};
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

fn strip_query_fragment(raw: &str) -> &str {
    let q = raw.find('?');
    let f = raw.find('#');
    match (q, f) {
        (Some(a), Some(b)) => &raw[..a.min(b)],
        (Some(a), None) => &raw[..a],
        (None, Some(b)) => &raw[..b],
        (None, None) => raw,
    }
}

#[cfg(test)]
mod tests {
    use super::{redact_url_for_receipt, strip_userinfo_from_urlish};
    use reqwest::Url;

    #[test]
    fn redact_url_for_receipt_strips_query_fragment_and_userinfo() {
        let u = Url::parse("https://user:pass@example.com/path?x=1#frag").expect("parse");
        let redacted = redact_url_for_receipt(&u).to_string();
        assert_eq!(redacted, "https://example.com/path");
    }

    #[test]
    fn strip_userinfo_from_urlish_removes_authority_userinfo() {
        let stripped = strip_userinfo_from_urlish("https://user:pass@example.com/path?x=1");
        assert_eq!(stripped, "https://example.com/path?x=1");
    }
}

fn strip_userinfo_from_urlish(raw: &str) -> String {
    let Some(scheme_idx) = raw.find("://") else {
        return raw.to_string();
    };
    let after_scheme = scheme_idx + 3;
    let rest = &raw[after_scheme..];
    let stop = rest
        .find(['/', '?', '#'])
        .map(|idx| after_scheme + idx)
        .unwrap_or_else(|| raw.len());
    let authority = &raw[after_scheme..stop];
    let Some(at_rel) = authority.rfind('@') else {
        return raw.to_string();
    };
    let at_abs = after_scheme + at_rel;
    format!("{}{}", &raw[..after_scheme], &raw[at_abs + 1..])
}

fn redact_url_for_receipt(parsed: &Url) -> Url {
    let mut out = parsed.clone();
    out.set_query(None);
    out.set_fragment(None);
    let _ = out.set_username("");
    let _ = out.set_password(None);
    out
}

pub async fn handle(
    exec: &ToolExecutor,
    tool: AgentTool,
    session_id: [u8; 32],
    step_index: u32,
) -> ToolExecutionResult {
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

            let max_chars = args
                .get("max_chars")
                .and_then(|v| v.as_u64())
                .unwrap_or(NET_FETCH_DEFAULT_MAX_CHARS as u64)
                .clamp(1, NET_FETCH_MAX_CHARS_LIMIT as u64) as u32;
            let max_bytes: usize = (max_chars as usize)
                .saturating_mul(4)
                .clamp(1, NET_FETCH_MAX_BYTES_LIMIT);
            let timeout = Duration::from_secs(30);
            let timeout_ms = timeout.as_millis() as u64;

            let parsed = match Url::parse(url) {
                Ok(u) => u,
                Err(e) => {
                    let sanitized = strip_userinfo_from_urlish(strip_query_fragment(url));
                    let requested_url_for_receipt =
                        workload::scrub_workload_text_field_for_receipt(exec, sanitized.as_str())
                            .await;
                    let receipt_preview = format!("net__fetch {}", requested_url_for_receipt);
                    let workload_id = workload::compute_workload_id(
                        session_id,
                        step_index,
                        "net__fetch",
                        receipt_preview.as_str(),
                    );

                    let result = ToolExecutionResult::failure(format!(
                        "ERROR_CLASS=TargetNotFound net__fetch url parse failed: {}",
                        e
                    ));
                    if let Some(tx) = exec.event_sender.as_ref() {
                        workload::emit_workload_activity(
                            tx,
                            session_id,
                            step_index,
                            workload_id.clone(),
                            WorkloadActivityKind::Lifecycle {
                                phase: "started".to_string(),
                                exit_code: None,
                            },
                        );
                        workload::emit_workload_activity(
                            tx,
                            session_id,
                            step_index,
                            workload_id.clone(),
                            WorkloadActivityKind::Lifecycle {
                                phase: "failed".to_string(),
                                exit_code: None,
                            },
                        );
                        workload::emit_workload_receipt(
                            tx,
                            session_id,
                            step_index,
                            workload_id.clone(),
                            WorkloadReceipt::NetFetch(WorkloadNetFetchReceipt {
                                tool_name: "net__fetch".to_string(),
                                method: "GET".to_string(),
                                requested_url: requested_url_for_receipt,
                                final_url: None,
                                status_code: None,
                                content_type: None,
                                max_chars,
                                max_bytes: max_bytes as u64,
                                bytes_read: 0,
                                truncated: false,
                                timeout_ms,
                                success: false,
                                error_class: workload::extract_error_class(result.error.as_deref()),
                            }),
                        );
                    }
                    return result;
                }
            };

            if parsed.scheme() != "http" && parsed.scheme() != "https" {
                let sanitized = strip_userinfo_from_urlish(strip_query_fragment(url));
                let requested_url_for_receipt =
                    workload::scrub_workload_text_field_for_receipt(exec, sanitized.as_str()).await;
                let receipt_preview = format!("net__fetch {}", requested_url_for_receipt);
                let workload_id = workload::compute_workload_id(
                    session_id,
                    step_index,
                    "net__fetch",
                    receipt_preview.as_str(),
                );
                let result = ToolExecutionResult::failure(format!(
                    "ERROR_CLASS=TargetNotFound net__fetch only supports http/https (got scheme='{}').",
                    parsed.scheme()
                ));
                if let Some(tx) = exec.event_sender.as_ref() {
                    workload::emit_workload_activity(
                        tx,
                        session_id,
                        step_index,
                        workload_id.clone(),
                        WorkloadActivityKind::Lifecycle {
                            phase: "started".to_string(),
                            exit_code: None,
                        },
                    );
                    workload::emit_workload_activity(
                        tx,
                        session_id,
                        step_index,
                        workload_id.clone(),
                        WorkloadActivityKind::Lifecycle {
                            phase: "failed".to_string(),
                            exit_code: None,
                        },
                    );
                    workload::emit_workload_receipt(
                        tx,
                        session_id,
                        step_index,
                        workload_id.clone(),
                        WorkloadReceipt::NetFetch(WorkloadNetFetchReceipt {
                            tool_name: "net__fetch".to_string(),
                            method: "GET".to_string(),
                            requested_url: requested_url_for_receipt,
                            final_url: None,
                            status_code: None,
                            content_type: None,
                            max_chars,
                            max_bytes: max_bytes as u64,
                            bytes_read: 0,
                            truncated: false,
                            timeout_ms,
                            success: false,
                            error_class: workload::extract_error_class(result.error.as_deref()),
                        }),
                    );
                }
                return result;
            }

            let requested_url_for_receipt = workload::scrub_workload_text_field_for_receipt(
                exec,
                redact_url_for_receipt(&parsed).as_str(),
            )
            .await;
            let receipt_preview = format!("net__fetch {}", requested_url_for_receipt);
            let workload_id = workload::compute_workload_id(
                session_id,
                step_index,
                "net__fetch",
                receipt_preview.as_str(),
            );
            if let Some(tx) = exec.event_sender.as_ref() {
                workload::emit_workload_activity(
                    tx,
                    session_id,
                    step_index,
                    workload_id.clone(),
                    WorkloadActivityKind::Lifecycle {
                        phase: "started".to_string(),
                        exit_code: None,
                    },
                );
            }

            let client = match Client::builder()
                .redirect(redirect::Policy::limited(5))
                .timeout(timeout)
                .user_agent("ioi-net-fetch/1.0")
                .build()
            {
                Ok(c) => c,
                Err(e) => {
                    let result = ToolExecutionResult::failure(format!(
                        "ERROR_CLASS=UnexpectedState net__fetch client init failed: {}",
                        e
                    ));
                    if let Some(tx) = exec.event_sender.as_ref() {
                        workload::emit_workload_activity(
                            tx,
                            session_id,
                            step_index,
                            workload_id.clone(),
                            WorkloadActivityKind::Lifecycle {
                                phase: "failed".to_string(),
                                exit_code: None,
                            },
                        );
                        workload::emit_workload_receipt(
                            tx,
                            session_id,
                            step_index,
                            workload_id.clone(),
                            WorkloadReceipt::NetFetch(WorkloadNetFetchReceipt {
                                tool_name: "net__fetch".to_string(),
                                method: "GET".to_string(),
                                requested_url: requested_url_for_receipt,
                                final_url: None,
                                status_code: None,
                                content_type: None,
                                max_chars,
                                max_bytes: max_bytes as u64,
                                bytes_read: 0,
                                truncated: false,
                                timeout_ms,
                                success: false,
                                error_class: workload::extract_error_class(result.error.as_deref()),
                            }),
                        );
                    }
                    return result;
                }
            };

            let mut resp = match client.get(parsed).send().await {
                Ok(r) => r,
                Err(e) => {
                    let result = ToolExecutionResult::failure(format!(
                        "ERROR_CLASS=UnexpectedState net__fetch request failed: {}",
                        e
                    ));
                    if let Some(tx) = exec.event_sender.as_ref() {
                        workload::emit_workload_activity(
                            tx,
                            session_id,
                            step_index,
                            workload_id.clone(),
                            WorkloadActivityKind::Lifecycle {
                                phase: "failed".to_string(),
                                exit_code: None,
                            },
                        );
                        workload::emit_workload_receipt(
                            tx,
                            session_id,
                            step_index,
                            workload_id.clone(),
                            WorkloadReceipt::NetFetch(WorkloadNetFetchReceipt {
                                tool_name: "net__fetch".to_string(),
                                method: "GET".to_string(),
                                requested_url: requested_url_for_receipt,
                                final_url: None,
                                status_code: None,
                                content_type: None,
                                max_chars,
                                max_bytes: max_bytes as u64,
                                bytes_read: 0,
                                truncated: false,
                                timeout_ms,
                                success: false,
                                error_class: workload::extract_error_class(result.error.as_deref()),
                            }),
                        );
                    }
                    return result;
                }
            };

            let status = resp.status().as_u16() as u32;
            let final_url_for_receipt = workload::scrub_workload_text_field_for_receipt(
                exec,
                redact_url_for_receipt(resp.url()).as_str(),
            )
            .await;
            let content_type = resp
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());

            if let Some(ct) = content_type.as_deref() {
                if !is_text_like_content_type(ct) {
                    let out = json!({
                        "requested_url": url,
                        "final_url": resp.url().to_string(),
                        "status": status,
                        "content_type": content_type,
                        "truncated": false,
                        "body_text": "",
                        "body_omitted": true,
                        "body_omitted_reason": format!("unsupported content-type for text extraction: {}", ct),
                    });

                    let result = match serde_json::to_string_pretty(&out) {
                        Ok(s) => ToolExecutionResult::success(s),
                        Err(e) => ToolExecutionResult::failure(format!(
                            "ERROR_CLASS=SerializationFailed net__fetch output serialization failed: {}",
                            e
                        )),
                    };
                    if let Some(tx) = exec.event_sender.as_ref() {
                        workload::emit_workload_activity(
                            tx,
                            session_id,
                            step_index,
                            workload_id.clone(),
                            WorkloadActivityKind::Lifecycle {
                                phase: if result.success {
                                    "completed".to_string()
                                } else {
                                    "failed".to_string()
                                },
                                exit_code: None,
                            },
                        );
                        workload::emit_workload_receipt(
                            tx,
                            session_id,
                            step_index,
                            workload_id.clone(),
                            WorkloadReceipt::NetFetch(WorkloadNetFetchReceipt {
                                tool_name: "net__fetch".to_string(),
                                method: "GET".to_string(),
                                requested_url: requested_url_for_receipt,
                                final_url: Some(final_url_for_receipt),
                                status_code: Some(status),
                                content_type: content_type.clone(),
                                max_chars,
                                max_bytes: max_bytes as u64,
                                bytes_read: 0,
                                truncated: false,
                                timeout_ms,
                                success: result.success,
                                error_class: workload::extract_error_class(result.error.as_deref()),
                            }),
                        );
                    }
                    return result;
                }
            }

            let mut buf: Vec<u8> = Vec::new();
            let mut truncated_by_bytes = false;
            loop {
                let next = match resp.chunk().await {
                    Ok(chunk) => chunk,
                    Err(e) => {
                        let result = ToolExecutionResult::failure(format!(
                            "ERROR_CLASS=UnexpectedState net__fetch body read failed: {}",
                            e
                        ));
                        if let Some(tx) = exec.event_sender.as_ref() {
                            workload::emit_workload_activity(
                                tx,
                                session_id,
                                step_index,
                                workload_id.clone(),
                                WorkloadActivityKind::Lifecycle {
                                    phase: "failed".to_string(),
                                    exit_code: None,
                                },
                            );
                            workload::emit_workload_receipt(
                                tx,
                                session_id,
                                step_index,
                                workload_id.clone(),
                                WorkloadReceipt::NetFetch(WorkloadNetFetchReceipt {
                                    tool_name: "net__fetch".to_string(),
                                    method: "GET".to_string(),
                                    requested_url: requested_url_for_receipt,
                                    final_url: Some(final_url_for_receipt),
                                    status_code: Some(status),
                                    content_type: content_type.clone(),
                                    max_chars,
                                    max_bytes: max_bytes as u64,
                                    bytes_read: buf.len() as u64,
                                    truncated: truncated_by_bytes,
                                    timeout_ms,
                                    success: false,
                                    error_class: workload::extract_error_class(result.error.as_deref()),
                                }),
                            );
                        }
                        return result;
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
            let bytes_read = buf.len() as u64;
            let (body_text, truncated_by_chars) = truncate_chars(&body_full, max_chars as usize);

            let truncated = truncated_by_bytes || truncated_by_chars;
            let out = json!({
                "requested_url": url,
                "final_url": resp.url().to_string(),
                "status": status,
                "content_type": content_type,
                "truncated": truncated,
                "body_text": body_text,
            });

            let result = match serde_json::to_string_pretty(&out) {
                Ok(s) => ToolExecutionResult::success(s),
                Err(e) => ToolExecutionResult::failure(format!(
                    "ERROR_CLASS=SerializationFailed net__fetch output serialization failed: {}",
                    e
                )),
            };
            if let Some(tx) = exec.event_sender.as_ref() {
                workload::emit_workload_activity(
                    tx,
                    session_id,
                    step_index,
                    workload_id.clone(),
                    WorkloadActivityKind::Lifecycle {
                        phase: if result.success {
                            "completed".to_string()
                        } else {
                            "failed".to_string()
                        },
                        exit_code: None,
                    },
                );
                workload::emit_workload_receipt(
                    tx,
                    session_id,
                    step_index,
                    workload_id.clone(),
                    WorkloadReceipt::NetFetch(WorkloadNetFetchReceipt {
                        tool_name: "net__fetch".to_string(),
                        method: "GET".to_string(),
                        requested_url: requested_url_for_receipt,
                        final_url: Some(final_url_for_receipt),
                        status_code: Some(status),
                        content_type: content_type.clone(),
                        max_chars,
                        max_bytes: max_bytes as u64,
                        bytes_read,
                        truncated,
                        timeout_ms,
                        success: result.success,
                        error_class: workload::extract_error_class(result.error.as_deref()),
                    }),
                );
            }
            result
        }
        other => {
            ToolExecutionResult::failure(format!("Tool {:?} not handled by web executor", other))
        }
    }
}
