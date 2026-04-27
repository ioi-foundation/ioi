// Path: crates/services/src/agentic/runtime/execution/web.rs

use super::{workload, ToolExecutionResult, ToolExecutor};
use ioi_types::app::agentic::AgentTool;
use ioi_types::app::{
    WorkloadActivityKind, WorkloadNetFetchReceipt, WorkloadReceipt, WorkloadWebRetrieveReceipt,
};
use reqwest::{redirect, Client, Url};
use serde_json::json;
use std::time::Duration;

const NET_FETCH_DEFAULT_MAX_CHARS: u32 = 12_000;
const NET_FETCH_MAX_CHARS_LIMIT: u32 = 120_000;
const NET_FETCH_MAX_BYTES_LIMIT: usize = 2_000_000;
const MEDIA_EXTRACT_DEFAULT_MAX_CHARS: u32 = 72_000;
const WEB_RETRIEVE_RECEIPT_MAX_CHARS: usize = 512;
const WEB_RETRIEVE_PREVIEW_MAX_CHARS: usize = 256;

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
#[path = "web/tests.rs"]
mod tests;

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

fn redact_url_for_evidence(parsed: &Url) -> Url {
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
        AgentTool::WebSearch {
            query,
            query_contract,
            retrieval_contract,
            limit,
            ..
        } => {
            let limit = limit.unwrap_or(5).clamp(1, 10);
            let query_trimmed = query.trim();
            let query_for_evidence_raw =
                workload::scrub_workload_text_field_for_evidence(exec, query_trimmed).await;
            let (query_for_evidence, _) =
                truncate_chars(&query_for_evidence_raw, WEB_RETRIEVE_RECEIPT_MAX_CHARS);

            let receipt_preview_raw = if query_for_evidence.trim().is_empty() {
                "web__search".to_string()
            } else {
                format!("web__search {}", query_for_evidence)
            };
            let (receipt_preview, _) =
                truncate_chars(&receipt_preview_raw, WEB_RETRIEVE_PREVIEW_MAX_CHARS);
            let workload_id = workload::compute_workload_id(
                session_id,
                step_index,
                "web__search",
                &receipt_preview,
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

            let mut sources_count: u32 = 0;
            let mut documents_count: u32 = 0;
            let mut backend_for_evidence = "edge:search".to_string();
            let retrieval_contract_result = if let Some(contract) = retrieval_contract {
                Ok(contract)
            } else {
                crate::agentic::web::derive_web_retrieval_contract(
                    &query,
                    query_contract.as_deref(),
                )
            };
            let result = match retrieval_contract_result {
                Ok(retrieval_contract) => match crate::agentic::web::edge_web_search(
                    &exec.browser,
                    &query,
                    query_contract.as_deref(),
                    &retrieval_contract,
                    limit,
                )
                .await
                {
                    Ok(bundle) => {
                        backend_for_evidence = bundle.backend.clone();
                        match serde_json::to_string_pretty(&bundle) {
                            Ok(out) => {
                                sources_count = bundle.sources.len() as u32;
                                documents_count = bundle.documents.len() as u32;
                                ToolExecutionResult::success(out)
                            }
                            Err(e) => ToolExecutionResult::failure(format!(
                                "ERROR_CLASS=SerializationFailed Failed to serialize web evidence: {}",
                                e
                            )),
                        }
                    }
                    Err(e) => {
                        let error_text: String = e.to_string();
                        ToolExecutionResult::failure(error_text)
                    }
                },
                Err(err) => ToolExecutionResult::failure(format!(
                    "ERROR_CLASS=SynthesisFailed {}",
                    err.trim()
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
                    WorkloadReceipt::WebRetrieve(WorkloadWebRetrieveReceipt {
                        tool_name: "web__search".to_string(),
                        backend: backend_for_evidence,
                        query: (!query_for_evidence.trim().is_empty())
                            .then_some(query_for_evidence),
                        url: None,
                        limit: Some(limit),
                        max_chars: None,
                        sources_count: if result.success { sources_count } else { 0 },
                        documents_count: if result.success { documents_count } else { 0 },
                        success: result.success,
                        error_class: workload::extract_error_class(result.error.as_deref()),
                    }),
                );
            }
            result
        }
        AgentTool::WebRead {
            url,
            max_chars,
            allow_browser_fallback,
        } => {
            let max_chars = max_chars.unwrap_or(NET_FETCH_DEFAULT_MAX_CHARS);
            let allow_browser_fallback = allow_browser_fallback.unwrap_or(true);
            let url_trimmed = url.trim();
            let url_redacted = Url::parse(url_trimmed)
                .ok()
                .map(|parsed| redact_url_for_evidence(&parsed).to_string())
                .unwrap_or_else(|| strip_userinfo_from_urlish(strip_query_fragment(url_trimmed)));
            let url_for_evidence_raw =
                workload::scrub_workload_text_field_for_evidence(exec, url_redacted.as_str()).await;
            let (url_for_evidence, _) =
                truncate_chars(&url_for_evidence_raw, WEB_RETRIEVE_RECEIPT_MAX_CHARS);

            let receipt_preview_raw = if url_for_evidence.trim().is_empty() {
                "web__read".to_string()
            } else {
                format!("web__read {}", url_for_evidence)
            };
            let (receipt_preview, _) =
                truncate_chars(&receipt_preview_raw, WEB_RETRIEVE_PREVIEW_MAX_CHARS);
            let workload_id = workload::compute_workload_id(
                session_id,
                step_index,
                "web__read",
                &receipt_preview,
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

            let mut sources_count: u32 = 0;
            let mut documents_count: u32 = 0;
            let result = match crate::agentic::web::edge_web_read(
                &exec.browser,
                &url,
                Some(max_chars),
                allow_browser_fallback,
            )
            .await
            {
                Ok(bundle) => match serde_json::to_string_pretty(&bundle) {
                    Ok(out) => {
                        sources_count = bundle.sources.len() as u32;
                        documents_count = bundle.documents.len() as u32;
                        ToolExecutionResult::success(out)
                    }
                    Err(e) => ToolExecutionResult::failure(format!(
                        "ERROR_CLASS=SerializationFailed Failed to serialize web evidence: {}",
                        e
                    )),
                },
                Err(e) => ToolExecutionResult::failure(e.to_string()),
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
                    WorkloadReceipt::WebRetrieve(WorkloadWebRetrieveReceipt {
                        tool_name: "web__read".to_string(),
                        backend: "edge:read".to_string(),
                        query: None,
                        url: (!url_for_evidence.trim().is_empty()).then_some(url_for_evidence),
                        limit: None,
                        max_chars: Some(max_chars),
                        sources_count: if result.success { sources_count } else { 0 },
                        documents_count: if result.success { documents_count } else { 0 },
                        success: result.success,
                        error_class: workload::extract_error_class(result.error.as_deref()),
                    }),
                );
            }

            result
        }
        AgentTool::MediaExtractTranscript {
            url,
            language,
            max_chars,
        } => {
            let max_chars = max_chars.unwrap_or(MEDIA_EXTRACT_DEFAULT_MAX_CHARS);
            let url_trimmed = url.trim();
            let url_redacted = Url::parse(url_trimmed)
                .ok()
                .map(|parsed| redact_url_for_evidence(&parsed).to_string())
                .unwrap_or_else(|| strip_userinfo_from_urlish(strip_query_fragment(url_trimmed)));
            let url_for_evidence_raw =
                workload::scrub_workload_text_field_for_evidence(exec, url_redacted.as_str()).await;
            let (url_for_evidence, _) =
                truncate_chars(&url_for_evidence_raw, WEB_RETRIEVE_RECEIPT_MAX_CHARS);

            let receipt_preview_raw = if url_for_evidence.trim().is_empty() {
                "media__extract_transcript".to_string()
            } else {
                format!("media__extract_transcript {}", url_for_evidence)
            };
            let (receipt_preview, _) =
                truncate_chars(&receipt_preview_raw, WEB_RETRIEVE_PREVIEW_MAX_CHARS);
            let workload_id = workload::compute_workload_id(
                session_id,
                step_index,
                "media__extract_transcript",
                &receipt_preview,
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

            let mut backend_for_evidence = "edge:media".to_string();
            let result = match crate::agentic::web::edge_media_extract_transcript(
                &url,
                language.as_deref(),
                Some(max_chars),
                exec.browser.clone(),
            )
            .await
            {
                Ok(bundle) => {
                    backend_for_evidence = bundle.backend.clone();
                    serde_json::to_string_pretty(&bundle).map_or_else(
                        |err| {
                            ToolExecutionResult::failure(format!(
                                "ERROR_CLASS=SerializationFailed Failed to serialize media transcript evidence: {}",
                                err
                            ))
                        },
                        ToolExecutionResult::success,
                    )
                }
                Err(err) => ToolExecutionResult::failure(err.to_string()),
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
                    WorkloadReceipt::WebRetrieve(WorkloadWebRetrieveReceipt {
                        tool_name: "media__extract_transcript".to_string(),
                        backend: backend_for_evidence,
                        query: language
                            .as_deref()
                            .map(str::trim)
                            .filter(|value| !value.is_empty())
                            .map(|value| format!("language={}", value)),
                        url: (!url_for_evidence.trim().is_empty()).then_some(url_for_evidence),
                        limit: None,
                        max_chars: Some(max_chars),
                        sources_count: if result.success { 1 } else { 0 },
                        documents_count: if result.success { 1 } else { 0 },
                        success: result.success,
                        error_class: workload::extract_error_class(result.error.as_deref()),
                    }),
                );
            }

            result
        }
        AgentTool::MediaExtractMultimodalEvidence {
            url,
            language,
            max_chars,
            frame_limit,
        } => {
            let max_chars = max_chars.unwrap_or(MEDIA_EXTRACT_DEFAULT_MAX_CHARS);
            let url_trimmed = url.trim();
            let url_redacted = Url::parse(url_trimmed)
                .ok()
                .map(|parsed| redact_url_for_evidence(&parsed).to_string())
                .unwrap_or_else(|| strip_userinfo_from_urlish(strip_query_fragment(url_trimmed)));
            let url_for_evidence_raw =
                workload::scrub_workload_text_field_for_evidence(exec, url_redacted.as_str()).await;
            let (url_for_evidence, _) =
                truncate_chars(&url_for_evidence_raw, WEB_RETRIEVE_RECEIPT_MAX_CHARS);

            let receipt_preview_raw = if url_for_evidence.trim().is_empty() {
                "media__extract_evidence".to_string()
            } else {
                format!("media__extract_evidence {}", url_for_evidence)
            };
            let (receipt_preview, _) =
                truncate_chars(&receipt_preview_raw, WEB_RETRIEVE_PREVIEW_MAX_CHARS);
            let workload_id = workload::compute_workload_id(
                session_id,
                step_index,
                "media__extract_evidence",
                &receipt_preview,
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

            let mut backend_for_evidence = "edge:media:multimodal".to_string();
            let result = match crate::agentic::web::edge_media_extract_multimodal_evidence(
                &url,
                language.as_deref(),
                Some(max_chars),
                frame_limit,
                exec.browser.clone(),
                exec.inference.clone(),
            )
            .await
            {
                Ok(bundle) => {
                    backend_for_evidence = bundle
                        .visual
                        .as_ref()
                        .map(|visual| visual.backend.clone())
                        .or_else(|| {
                            bundle
                                .timeline
                                .as_ref()
                                .map(|timeline| timeline.backend.clone())
                        })
                        .or_else(|| {
                            bundle
                                .transcript
                                .as_ref()
                                .map(|transcript| transcript.backend.clone())
                        })
                        .unwrap_or_else(|| "edge:media:multimodal".to_string());
                    serde_json::to_string_pretty(&bundle).map_or_else(
                        |err| {
                            ToolExecutionResult::failure(format!(
                                "ERROR_CLASS=SerializationFailed Failed to serialize media multimodal evidence: {}",
                                err
                            ))
                        },
                        ToolExecutionResult::success,
                    )
                }
                Err(err) => ToolExecutionResult::failure(err.to_string()),
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
                    WorkloadReceipt::WebRetrieve(WorkloadWebRetrieveReceipt {
                        tool_name: "media__extract_evidence".to_string(),
                        backend: backend_for_evidence,
                        query: language
                            .as_deref()
                            .map(str::trim)
                            .filter(|value| !value.is_empty())
                            .map(|value| format!("language={}", value)),
                        url: (!url_for_evidence.trim().is_empty()).then_some(url_for_evidence),
                        limit: frame_limit,
                        max_chars: Some(max_chars),
                        sources_count: if result.success { 1 } else { 0 },
                        documents_count: if result.success { 1 } else { 0 },
                        success: result.success,
                        error_class: workload::extract_error_class(result.error.as_deref()),
                    }),
                );
            }

            result
        }
        AgentTool::NetFetch { url, max_chars } => {
            handle_net_fetch(exec, session_id, step_index, url.as_str(), max_chars).await
        }
        other => {
            ToolExecutionResult::failure(format!("Tool {:?} not handled by web executor", other))
        }
    }
}

async fn handle_net_fetch(
    exec: &ToolExecutor,
    session_id: [u8; 32],
    step_index: u32,
    url: &str,
    max_chars_override: Option<u32>,
) -> ToolExecutionResult {
    let url = url.trim();
    if url.is_empty() {
        return ToolExecutionResult::failure(
            "ERROR_CLASS=TargetNotFound http__fetch requires a non-empty url.".to_string(),
        );
    }

    let max_chars = max_chars_override
        .unwrap_or(NET_FETCH_DEFAULT_MAX_CHARS)
        .clamp(1, NET_FETCH_MAX_CHARS_LIMIT);
    let max_bytes: usize = (max_chars as usize)
        .saturating_mul(4)
        .clamp(1, NET_FETCH_MAX_BYTES_LIMIT);
    let timeout = Duration::from_secs(30);
    let timeout_ms = timeout.as_millis() as u64;

    let parsed = match Url::parse(url) {
        Ok(u) => u,
        Err(e) => {
            let sanitized = strip_userinfo_from_urlish(strip_query_fragment(url));
            let requested_url_for_evidence =
                workload::scrub_workload_text_field_for_evidence(exec, sanitized.as_str()).await;
            let receipt_preview = format!("http__fetch {}", requested_url_for_evidence);
            let workload_id = workload::compute_workload_id(
                session_id,
                step_index,
                "http__fetch",
                receipt_preview.as_str(),
            );

            let result = ToolExecutionResult::failure(format!(
                "ERROR_CLASS=TargetNotFound http__fetch url parse failed: {}",
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
                        tool_name: "http__fetch".to_string(),
                        method: "GET".to_string(),
                        requested_url: requested_url_for_evidence,
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
        let requested_url_for_evidence =
            workload::scrub_workload_text_field_for_evidence(exec, sanitized.as_str()).await;
        let receipt_preview = format!("http__fetch {}", requested_url_for_evidence);
        let workload_id = workload::compute_workload_id(
            session_id,
            step_index,
            "http__fetch",
            receipt_preview.as_str(),
        );
        let result = ToolExecutionResult::failure(format!(
            "ERROR_CLASS=TargetNotFound http__fetch only supports http/https (got scheme='{}').",
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
                    tool_name: "http__fetch".to_string(),
                    method: "GET".to_string(),
                    requested_url: requested_url_for_evidence,
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

    let requested_url_for_evidence = workload::scrub_workload_text_field_for_evidence(
        exec,
        redact_url_for_evidence(&parsed).as_str(),
    )
    .await;
    let receipt_preview = format!("http__fetch {}", requested_url_for_evidence);
    let workload_id = workload::compute_workload_id(
        session_id,
        step_index,
        "http__fetch",
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
                "ERROR_CLASS=UnexpectedState http__fetch client init failed: {}",
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
                        tool_name: "http__fetch".to_string(),
                        method: "GET".to_string(),
                        requested_url: requested_url_for_evidence,
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
                "ERROR_CLASS=UnexpectedState http__fetch request failed: {}",
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
                        tool_name: "http__fetch".to_string(),
                        method: "GET".to_string(),
                        requested_url: requested_url_for_evidence,
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
    let final_url_for_evidence = workload::scrub_workload_text_field_for_evidence(
        exec,
        redact_url_for_evidence(resp.url()).as_str(),
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
                    "ERROR_CLASS=SerializationFailed http__fetch output serialization failed: {}",
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
                        tool_name: "http__fetch".to_string(),
                        method: "GET".to_string(),
                        requested_url: requested_url_for_evidence,
                        final_url: Some(final_url_for_evidence),
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
                    "ERROR_CLASS=UnexpectedState http__fetch body read failed: {}",
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
                            tool_name: "http__fetch".to_string(),
                            method: "GET".to_string(),
                            requested_url: requested_url_for_evidence,
                            final_url: Some(final_url_for_evidence),
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
            "ERROR_CLASS=SerializationFailed http__fetch output serialization failed: {}",
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
                tool_name: "http__fetch".to_string(),
                method: "GET".to_string(),
                requested_url: requested_url_for_evidence,
                final_url: Some(final_url_for_evidence),
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
