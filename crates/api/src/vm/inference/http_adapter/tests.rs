use super::{
    apply_local_qwen_no_think_prompt_for_request_with_lookup,
    default_inference_http_stream_idle_timeout_seconds, default_inference_http_timeout_seconds,
    inference_http_stream_idle_timeout_seconds_for_api_url_with_lookup,
    inference_http_timeout_seconds_for_api_url_with_lookup, local_ollama_native_chat_url,
    local_openai_reasoning_effort_for_request_with_lookup,
    ollama_native_request_options_for_request, resolve_embedding_model_with,
    resolve_embedding_target_url, restore_consumed_stop_sequence, should_use_openai_streaming,
    stop_sequence_match, HttpInferenceRuntime, Message, OpenAiStrategy, OpenAiStreamAccumulator,
    ProviderKind, ProviderStrategy,
};
use crate::vm::inference::InferenceRuntime;
use ioi_types::app::agentic::{InferenceOptions, LlmToolDefinition};
use reqwest::Client;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

fn ollama_context_env_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .expect("ollama context env lock")
}

#[test]
fn openai_stream_accumulator_returns_complete_tool_call_before_done() {
    let mut accumulator = OpenAiStreamAccumulator::default();

    let first = json!({
        "choices": [{
            "delta": {
                "tool_calls": [{
                    "index": 0,
                    "function": {
                        "name": "browser__hover",
                        "arguments": ""
                    }
                }]
            },
            "finish_reason": Value::Null
        }]
    })
    .to_string();
    let second = json!({
        "choices": [{
            "delta": {
                "tool_calls": [{
                    "index": 0,
                    "function": {
                        "arguments": "{\"duration_ms\":10000,\"id\":\"circ\"}"
                    }
                }]
            },
            "finish_reason": Value::Null
        }]
    })
    .to_string();

    assert!(accumulator.apply_data_line(&first).unwrap().is_none());
    let output = accumulator.apply_data_line(&second).unwrap().unwrap();
    let parsed: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(parsed["name"], "browser__hover");
    assert_eq!(parsed["arguments"]["duration_ms"], 10000);
    assert_eq!(parsed["arguments"]["id"], "circ");
}

#[test]
fn openai_stream_accumulator_collects_text_until_stop() {
    let mut accumulator = OpenAiStreamAccumulator::default();

    let first = json!({
        "choices": [{
            "delta": { "content": "hello " },
            "finish_reason": Value::Null
        }]
    })
    .to_string();
    let second = json!({
        "choices": [{
            "delta": { "content": "world" },
            "finish_reason": "stop"
        }]
    })
    .to_string();

    assert!(accumulator.apply_data_line(&first).unwrap().is_none());
    let output = accumulator.apply_data_line(&second).unwrap().unwrap();
    assert_eq!(String::from_utf8(output).unwrap(), "hello world");
}

#[test]
fn restore_consumed_stop_sequence_appends_boundary_for_stop_finish_reason() {
    let restored = restore_consumed_stop_sequence(
        "<!doctype html><html><body><main>Quantum</main></body>",
        Some("stop"),
        &["</html>".to_string()],
    );
    assert_eq!(
        restored,
        "<!doctype html><html><body><main>Quantum</main></body></html>"
    );
}

#[test]
fn openai_stream_accumulator_restores_configured_stop_sequence() {
    let mut accumulator = OpenAiStreamAccumulator {
        stop_sequences: vec!["</html>".to_string()],
        ..Default::default()
    };

    let line = json!({
        "choices": [{
            "delta": { "content": "<!doctype html><html><body><main>Quantum</main></body>" },
            "finish_reason": "stop"
        }]
    })
    .to_string();

    let output = accumulator.apply_data_line(&line).unwrap().unwrap();
    assert_eq!(
        String::from_utf8(output).unwrap(),
        "<!doctype html><html><body><main>Quantum</main></body></html>"
    );
}

#[test]
fn openai_stream_accumulator_finalizes_text_on_done() {
    let mut accumulator = OpenAiStreamAccumulator::default();
    let line = json!({
        "choices": [{
            "delta": { "content": "streamed text" },
            "finish_reason": Value::Null
        }]
    })
    .to_string();

    assert!(accumulator.apply_data_line(&line).unwrap().is_none());
    let output = accumulator.apply_data_line("[DONE]").unwrap().unwrap();
    assert_eq!(String::from_utf8(output).unwrap(), "streamed text");
}

#[test]
fn stop_sequence_match_accepts_case_insensitive_html_closure() {
    let text = "<!doctype html><html><body><main>Quantum</main></body></HTML>";
    let matched =
        stop_sequence_match(text, &["</html>".to_string()]).expect("html stop sequence match");
    assert_eq!(&text[matched.0..matched.0 + matched.1], "</HTML>");
}

#[test]
fn stop_sequence_match_accepts_html_closure_with_internal_whitespace() {
    let text = "<!doctype html><html><body><main>Quantum</main></body></html   >";
    let matched =
        stop_sequence_match(text, &["</html>".to_string()]).expect("html stop sequence match");
    assert_eq!(&text[matched.0..matched.0 + matched.1], "</html   >");
}

#[test]
fn openai_tool_requests_skip_redundant_json_object_mode() {
    let request = OpenAiStrategy
        .build_request(
            &Client::new(),
            "https://api.openai.com/v1/chat/completions",
            "test-key",
            "gpt-4o",
            br#"[{"role":"user","content":"Select the next tool."}]"#,
            &InferenceOptions {
                json_mode: true,
                tools: vec![LlmToolDefinition {
                    name: "browser__hover".to_string(),
                    description: "Hover a target.".to_string(),
                    parameters: r#"{"type":"object","properties":{"id":{"type":"string"}}}"#
                        .to_string(),
                }],
                ..Default::default()
            },
            false,
        )
        .expect("request builder")
        .build()
        .expect("request");

    let body = request
        .body()
        .and_then(|payload| payload.as_bytes())
        .expect("request body");
    let parsed: Value = serde_json::from_slice(body).expect("json body");

    assert_eq!(parsed["tool_choice"], "required");
    assert_eq!(parsed["parallel_tool_calls"], false);
    assert!(parsed.get("response_format").is_none());
}

#[test]
fn local_openai_requests_include_ollama_num_ctx_when_configured() {
    let _guard = ollama_context_env_lock();
    std::env::set_var("OLLAMA_CONTEXT_LENGTH", "2048");
    let request = OpenAiStrategy
        .build_request(
            &Client::new(),
            "http://127.0.0.1:11434/v1/chat/completions",
            "",
            "qwen2.5:7b",
            br#"[{"role":"user","content":"Say ok"}]"#,
            &InferenceOptions {
                max_tokens: 8,
                ..Default::default()
            },
            false,
        )
        .expect("request builder")
        .build()
        .expect("request");
    std::env::remove_var("OLLAMA_CONTEXT_LENGTH");

    let body = request
        .body()
        .and_then(|payload| payload.as_bytes())
        .expect("request body");
    let parsed: Value = serde_json::from_slice(body).expect("json body");

    assert_eq!(parsed["options"]["num_ctx"], 2048);
}

#[test]
fn openai_requests_include_stop_sequences_when_configured() {
    let request = OpenAiStrategy
        .build_request(
            &Client::new(),
            "http://127.0.0.1:11434/v1/chat/completions",
            "",
            "qwen3.5:9b",
            br#"[{"role":"user","content":"Return only one HTML document."}]"#,
            &InferenceOptions {
                max_tokens: 32,
                stop_sequences: vec!["</html>".to_string()],
                ..Default::default()
            },
            false,
        )
        .expect("request builder")
        .build()
        .expect("request");

    let body = request
        .body()
        .and_then(|payload| payload.as_bytes())
        .expect("request body");
    let parsed: Value = serde_json::from_slice(body).expect("json body");

    assert_eq!(parsed["stop"], json!(["</html>"]));
}

#[test]
fn ollama_native_request_options_forward_html_document_stop_sequences() {
    let options = ollama_native_request_options_for_request(
        "http://127.0.0.1:11434/v1/chat/completions",
        &InferenceOptions {
            max_tokens: 128,
            stop_sequences: vec!["</html>".to_string(), "</svg>".to_string()],
            ..Default::default()
        },
    )
    .expect("native request options");

    assert_eq!(options["num_predict"], 128);
    assert_eq!(options["stop"], json!(["</html>", "</svg>"]));
}

#[test]
fn ollama_native_request_options_preserve_non_document_stop_sequences() {
    let options = ollama_native_request_options_for_request(
        "http://127.0.0.1:11434/v1/chat/completions",
        &InferenceOptions {
            max_tokens: 128,
            stop_sequences: vec!["END_OF_CARD".to_string()],
            ..Default::default()
        },
    )
    .expect("native request options");

    assert_eq!(options["stop"][0], "END_OF_CARD");
}

#[test]
fn local_non_qwen_ollama_requests_default_reasoning_effort_to_none() {
    let request = OpenAiStrategy
        .build_request(
            &Client::new(),
            "http://127.0.0.1:11434/v1/chat/completions",
            "",
            "llama3.2:3b",
            br#"[{"role":"user","content":"Say ok"}]"#,
            &InferenceOptions {
                max_tokens: 8,
                ..Default::default()
            },
            false,
        )
        .expect("request builder")
        .build()
        .expect("request");

    let body = request
        .body()
        .and_then(|payload| payload.as_bytes())
        .expect("request body");
    let parsed: Value = serde_json::from_slice(body).expect("json body");

    assert_eq!(parsed["reasoning_effort"], "none");
}

#[test]
fn local_reasoning_effort_policy_can_be_explicitly_omitted() {
    let effort = local_openai_reasoning_effort_for_request_with_lookup(
        "http://127.0.0.1:11434/v1/chat/completions",
        "qwen3.5:9b",
        |key| match key {
            "AUTOPILOT_LOCAL_OPENAI_REASONING_EFFORT" => Some("omit".to_string()),
            _ => None,
        },
    );

    assert!(effort.is_none());
}

#[test]
fn local_qwen_requests_omit_reasoning_effort_and_prefix_no_think() {
    let request = OpenAiStrategy
        .build_request(
            &Client::new(),
            "http://127.0.0.1:11434/v1/chat/completions",
            "",
            "qwen3.5:9b",
            br#"[{"role":"system","content":"Return only one HTML document."},{"role":"user","content":"Create the artifact."}]"#,
            &InferenceOptions {
                max_tokens: 32,
                ..Default::default()
            },
            true,
        )
        .expect("request builder")
        .build()
        .expect("request");

    let body = request
        .body()
        .and_then(|payload| payload.as_bytes())
        .expect("request body");
    let parsed: Value = serde_json::from_slice(body).expect("json body");

    assert!(parsed.get("reasoning_effort").is_none());
    assert_eq!(
        parsed["messages"][0]["content"],
        "/no_think\nReturn only one HTML document."
    );
}

#[test]
fn local_qwen_no_think_prompt_is_not_added_when_reasoning_policy_is_explicit() {
    let mut messages = vec![Message {
        role: "system".to_string(),
        content: Value::String("Return only one HTML document.".to_string()),
    }];

    apply_local_qwen_no_think_prompt_for_request_with_lookup(
        "http://127.0.0.1:11434/v1/chat/completions",
        "qwen3.5:9b",
        &mut messages,
        |key| match key {
            "AUTOPILOT_LOCAL_OPENAI_REASONING_EFFORT" => Some("low".to_string()),
            _ => None,
        },
    );

    assert_eq!(
        messages[0].content,
        Value::String("Return only one HTML document.".to_string())
    );
}

#[test]
fn openai_non_stream_requests_serialize_stream_false_explicitly() {
    let request = OpenAiStrategy
        .build_request(
            &Client::new(),
            "http://127.0.0.1:11434/v1/chat/completions",
            "",
            "qwen2.5:7b",
            br#"[{"role":"user","content":"Say ok"}]"#,
            &InferenceOptions {
                max_tokens: 8,
                ..Default::default()
            },
            false,
        )
        .expect("request builder")
        .build()
        .expect("request");

    let body = request
        .body()
        .and_then(|payload| payload.as_bytes())
        .expect("request body");
    let parsed: Value = serde_json::from_slice(body).expect("json body");

    assert_eq!(parsed["stream"], false);
}

#[test]
fn openai_streaming_requests_still_serialize_stream_true() {
    let request = OpenAiStrategy
        .build_request(
            &Client::new(),
            "https://api.openai.com/v1/chat/completions",
            "test-key",
            "gpt-4o",
            br#"[{"role":"user","content":"Say ok"}]"#,
            &InferenceOptions {
                max_tokens: 8,
                ..Default::default()
            },
            true,
        )
        .expect("request builder")
        .build()
        .expect("request");

    let body = request
        .body()
        .and_then(|payload| payload.as_bytes())
        .expect("request body");
    let parsed: Value = serde_json::from_slice(body).expect("json body");

    assert_eq!(parsed["stream"], true);
}

#[tokio::test]
async fn openai_parse_response_does_not_wait_for_chunked_connection_close() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind local listener");
    let address = listener.local_addr().expect("listener address");
    let response_json = json!({
        "id": "chatcmpl-local",
        "object": "chat.completion",
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": "{\"ok\":true}"
            },
            "finish_reason": "stop"
        }]
    })
    .to_string();
    let response_chunk = format!("{:x}\r\n{}\r\n", response_json.len(), response_json);

    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept test client");
        let mut request = vec![0u8; 16384];
        let _ = socket.read(&mut request).await.expect("read request");
        let headers = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n";
        socket
            .write_all(headers.as_bytes())
            .await
            .expect("write headers");
        socket
            .write_all(response_chunk.as_bytes())
            .await
            .expect("write chunk");
        socket
            .write_all(b"0\r\n\r\n")
            .await
            .expect("write chunk terminator");
        tokio::time::sleep(Duration::from_secs(5)).await;
    });

    let runtime = HttpInferenceRuntime::new(
        format!("http://{address}/v1/chat/completions"),
        String::new(),
        "local-openai-test".to_string(),
    );
    let result = tokio::time::timeout(
        Duration::from_secs(2),
        runtime.execute_inference(
            [0u8; 32],
            br#"[{"role":"user","content":"Say ok"}]"#,
            InferenceOptions {
                json_mode: true,
                ..Default::default()
            },
        ),
    )
    .await;

    let output = result
        .expect("non-stream parse should not wait for connection close")
        .expect("inference result");
    assert_eq!(String::from_utf8(output).unwrap(), "{\"ok\":true}");
}

#[tokio::test]
async fn local_qwen_raw_text_requests_use_native_ollama_chat_streaming() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind local listener");
    let address = listener.local_addr().expect("listener address");

    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept test client");
        let mut request = vec![0u8; 16384];
        let bytes_read = socket.read(&mut request).await.expect("read request");
        let request_text = String::from_utf8_lossy(&request[..bytes_read]);
        assert!(request_text.starts_with("POST /api/chat HTTP/1.1"));
        assert!(request_text.contains("\"think\":false"));
        assert!(request_text.contains("\"stream\":true"));
        assert!(request_text.contains("\"num_predict\":321"));
        assert!(request_text.contains("\"stop\":[\"</html>\"]"));

        let response_body = concat!(
            "{\"message\":{\"content\":\"<!doctype html><html><body>\"},\"done\":false}\n",
            "{\"message\":{\"content\":\"ok</body></html>\"},\"done\":true}\n"
        );
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson\r\nContent-Length: {}\r\n\r\n{}",
            response_body.len(),
            response_body
        );
        socket
            .write_all(response.as_bytes())
            .await
            .expect("write response");
    });

    let runtime = HttpInferenceRuntime::new(
        format!("http://{address}/v1/chat/completions"),
        String::new(),
        "qwen3.5:9b".to_string(),
    );
    let expected_url = format!("http://{address}/api/chat");
    assert_eq!(
        local_ollama_native_chat_url(&format!("http://{address}/v1/chat/completions")).as_deref(),
        Some(expected_url.as_str())
    );

    let output = runtime
        .execute_inference(
            [0u8; 32],
            br#"[{"role":"user","content":"Return only html."}]"#,
            InferenceOptions {
                max_tokens: 321,
                stop_sequences: vec!["</html>".to_string()],
                ..Default::default()
            },
        )
        .await
        .expect("inference result");

    assert_eq!(
        String::from_utf8(output).unwrap(),
        "<!doctype html><html><body>ok</body></html>"
    );
}

#[tokio::test]
async fn local_qwen_native_chat_stream_idle_timeout_fails_stalled_streams() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind local listener");
    let address = listener.local_addr().expect("listener address");

    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept test client");
        let mut request = vec![0u8; 16384];
        let bytes_read = socket.read(&mut request).await.expect("read request");
        let request_text = String::from_utf8_lossy(&request[..bytes_read]);
        assert!(request_text.starts_with("POST /api/chat HTTP/1.1"));

        let response_head = "HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson\r\nTransfer-Encoding: chunked\r\n\r\n";
        socket
            .write_all(response_head.as_bytes())
            .await
            .expect("write response headers");
        let stalled_chunk =
            "{\"message\":{\"content\":\"<!doctype html><html><body>\"},\"done\":false}\n";
        let chunk = format!("{:x}\r\n{}\r\n", stalled_chunk.len(), stalled_chunk);
        socket
            .write_all(chunk.as_bytes())
            .await
            .expect("write first chunk");
        socket.flush().await.expect("flush first chunk");
        tokio::time::sleep(Duration::from_secs(5)).await;
    });

    let runtime = HttpInferenceRuntime {
        client: Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("http client"),
        api_url: format!("http://{address}/v1/chat/completions"),
        api_key: String::new(),
        model_name: "qwen3.5:9b".to_string(),
        strategy: Box::new(OpenAiStrategy),
        provider_kind: ProviderKind::OpenAi,
        stream_idle_timeout: Duration::from_millis(250),
    };

    let error = runtime
        .execute_inference(
            [0u8; 32],
            br#"[{"role":"user","content":"Return only html."}]"#,
            InferenceOptions {
                max_tokens: 321,
                stop_sequences: vec!["</html>".to_string()],
                ..Default::default()
            },
        )
        .await
        .expect_err("stalled stream should fail");

    assert!(
        error
            .to_string()
            .contains("Local Ollama native chat stream stalled after 250ms"),
        "unexpected error: {error}"
    );
}

#[test]
fn local_embedding_routes_use_local_model_defaults() {
    let env = HashMap::from([(
        "AUTOPILOT_LOCAL_EMBEDDING_MODEL",
        "nomic-embed-text".to_string(),
    )]);

    let model = resolve_embedding_model_with("http://127.0.0.1:11434/v1/chat/completions", |key| {
        env.get(key).cloned()
    });
    let target = resolve_embedding_target_url("http://127.0.0.1:11434/v1/chat/completions")
        .expect("local embedding URL");

    assert_eq!(model, "nomic-embed-text");
    assert_eq!(target, "http://127.0.0.1:11434/v1/embeddings");
}

#[test]
fn openai_embedding_routes_keep_openai_default_model() {
    let env = HashMap::from([(
        "OPENAI_EMBEDDING_MODEL",
        "text-embedding-3-large".to_string(),
    )]);

    let model = resolve_embedding_model_with("https://api.openai.com/v1/chat/completions", |key| {
        env.get(key).cloned()
    });
    let target = resolve_embedding_target_url("https://api.openai.com/v1/chat/completions")
        .expect("openai embedding URL");

    assert_eq!(model, "text-embedding-3-large");
    assert_eq!(target, "https://api.openai.com/v1/embeddings");
}

#[test]
fn local_runtime_defaults_to_longer_http_timeout() {
    assert_eq!(
        default_inference_http_timeout_seconds("http://127.0.0.1:11434/v1/chat/completions"),
        600
    );
    assert_eq!(
        default_inference_http_timeout_seconds("https://api.openai.com/v1/chat/completions"),
        60
    );
}

#[test]
fn local_runtime_defaults_to_shorter_stream_idle_timeout() {
    assert_eq!(
        default_inference_http_stream_idle_timeout_seconds(
            "http://127.0.0.1:11434/v1/chat/completions"
        ),
        20
    );
    assert_eq!(
        default_inference_http_stream_idle_timeout_seconds(
            "https://api.openai.com/v1/chat/completions"
        ),
        30
    );
}

#[test]
fn explicit_http_timeout_override_takes_precedence() {
    let env = HashMap::from([("AUTOPILOT_INFERENCE_HTTP_TIMEOUT_SECS", "300".to_string())]);

    let timeout = inference_http_timeout_seconds_for_api_url_with_lookup(
        "http://127.0.0.1:11434/v1/chat/completions",
        |key| env.get(key).cloned(),
    );

    assert_eq!(timeout, 300);
}

#[test]
fn explicit_stream_idle_timeout_override_takes_precedence() {
    let env = HashMap::from([(
        "AUTOPILOT_INFERENCE_HTTP_STREAM_IDLE_TIMEOUT_SECS",
        "45".to_string(),
    )]);

    let timeout = inference_http_stream_idle_timeout_seconds_for_api_url_with_lookup(
        "http://127.0.0.1:11434/v1/chat/completions",
        |key| env.get(key).cloned(),
    );

    assert_eq!(timeout, 45);
}

#[test]
fn local_openai_tool_requests_do_not_force_streaming_without_token_sink() {
    assert!(!should_use_openai_streaming(
        "http://127.0.0.1:11434/v1/chat/completions",
        ProviderKind::OpenAi,
        true,
        false,
        &InferenceOptions {
            tools: vec![LlmToolDefinition {
                name: "browser__hover".to_string(),
                description: "Hover a target.".to_string(),
                parameters: r#"{"type":"object","properties":{"id":{"type":"string"}}}"#
                    .to_string(),
            }],
            ..Default::default()
        }
    ));
}

#[test]
fn remote_openai_tool_requests_can_still_stream_without_token_sink() {
    assert!(should_use_openai_streaming(
        "https://api.openai.com/v1/chat/completions",
        ProviderKind::OpenAi,
        true,
        false,
        &InferenceOptions {
            tools: vec![LlmToolDefinition {
                name: "browser__hover".to_string(),
                description: "Hover a target.".to_string(),
                parameters: r#"{"type":"object","properties":{"id":{"type":"string"}}}"#
                    .to_string(),
            }],
            ..Default::default()
        }
    ));
}

#[tokio::test]
async fn local_runtime_load_model_uses_tiny_chat_warmup_request() {
    let _guard = ollama_context_env_lock();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind local listener");
    let address = listener.local_addr().expect("listener address");
    let (request_tx, request_rx) = oneshot::channel::<String>();

    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept test client");
        let mut request = vec![0u8; 16384];
        let read = socket.read(&mut request).await.expect("read request");
        request_tx
            .send(String::from_utf8_lossy(&request[..read]).to_string())
            .expect("send request payload");
        let body = json!({
            "id": "chatcmpl-warmup",
            "object": "chat.completion",
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": "OK"
                },
                "finish_reason": "stop"
            }]
        })
        .to_string();
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        socket
            .write_all(response.as_bytes())
            .await
            .expect("write response");
    });

    std::env::set_var("OLLAMA_CONTEXT_LENGTH", "4096");
    let runtime = HttpInferenceRuntime::new(
        format!("http://{address}/v1/chat/completions"),
        String::new(),
        "qwen2.5:14b".to_string(),
    );
    runtime
        .load_model([0u8; 32], Path::new(""))
        .await
        .expect("warmup should succeed");
    std::env::remove_var("OLLAMA_CONTEXT_LENGTH");

    let request = request_rx.await.expect("captured request");
    assert!(request.starts_with("POST /v1/chat/completions HTTP/1.1"));
    assert!(request.contains("\"model\":\"qwen2.5:14b\""));
    assert!(request.contains("\"max_tokens\":1"));
    assert!(request.contains("\"temperature\":0.0"));
    assert!(request.contains("\"Reply with OK.\""));
    assert!(request.contains("\"num_ctx\":4096"));
}
