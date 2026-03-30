// Path: crates/api/src/vm/inference/http_adapter.rs

use super::InferenceRuntime;
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use futures_util::StreamExt;
use ioi_types::app::agentic::InferenceOptions;
use ioi_types::app::{StudioRuntimeProvenance, StudioRuntimeProvenanceKind};
use ioi_types::error::VmError;
use reqwest::{Client, RequestBuilder};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;
use tokio::sync::mpsc::Sender;

// --- Strategy Trait ---

#[async_trait]
pub trait ProviderStrategy: Send + Sync {
    /// Builds the HTTP request for the specific provider.
    #[allow(clippy::too_many_arguments)]
    fn build_request(
        &self,
        client: &Client,
        api_url: &str,
        api_key: &str,
        model_name: &str,
        input_context: &[u8],
        options: &InferenceOptions,
        stream: bool,
    ) -> Result<RequestBuilder, VmError>;

    /// Parses the raw response bytes into the standard IOI Kernel output format.
    /// (UTF-8 string or JSON tool call).
    async fn parse_response(&self, response: reqwest::Response) -> Result<Vec<u8>, VmError>;

    /// Parses a streaming chunk.
    async fn parse_stream_chunk(&self, chunk: &[u8]) -> Result<Option<String>, VmError>;

    fn supports_streaming(&self) -> bool {
        false
    }
}

// --- Internal Modules for Provider Strategies ---
// We define them inline or in submodules here for cleaner separation.

mod providers {
    // We would typically put these in separate files in `src/vm/inference/providers/`
    // but for this refactor within one file/module context, we can define them here
    // or assume they are available if we split the files as planned.
    // For this output, I will inline the OpenAI and Anthropic logic as private modules/structs
    // to keep `http_adapter.rs` self-contained if file splitting isn't done yet,
    // OR I will assume the file split happened and import them if you prefer.

    // Given the instruction "For this single-file refactor request, I will implement this separation within http_adapter.rs",
    // I will inline the logic but keep it structured.
}

// --- OpenAI Strategy ---

struct OpenAiStrategy;

#[derive(Serialize)]
struct OpenAiRequest {
    model: String,
    messages: Vec<Message>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tools: Option<Vec<Tool>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_choice: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    parallel_tool_calls: Option<bool>,
    temperature: f32,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_tokens: Option<u32>,
    stream: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_format: Option<ResponseFormat>,
    #[serde(skip_serializing_if = "Option::is_none")]
    options: Option<Value>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Message {
    role: String,
    content: serde_json::Value,
}

#[derive(Serialize)]
struct Tool {
    #[serde(rename = "type")]
    tool_type: String,
    function: ToolFunction,
}

#[derive(Serialize)]
struct ToolFunction {
    name: String,
    description: String,
    parameters: serde_json::Value,
}

#[derive(Serialize)]
struct ResponseFormat {
    #[serde(rename = "type")]
    type_: String,
}

#[async_trait]
impl ProviderStrategy for OpenAiStrategy {
    fn build_request(
        &self,
        client: &Client,
        api_url: &str,
        api_key: &str,
        model_name: &str,
        input_context: &[u8],
        options: &InferenceOptions,
        stream: bool,
    ) -> Result<RequestBuilder, VmError> {
        let messages: Vec<Message> =
            if let Ok(json_val) = serde_json::from_slice::<Value>(input_context) {
                if let Ok(msgs) = serde_json::from_value::<Vec<Message>>(json_val.clone()) {
                    msgs
                } else {
                    vec![Message {
                        role: "user".to_string(),
                        content: json_val,
                    }]
                }
            } else {
                let prompt_str = String::from_utf8(input_context.to_vec())
                    .map_err(|e| VmError::InvalidBytecode(format!("Input must be UTF-8: {}", e)))?;
                vec![Message {
                    role: "user".to_string(),
                    content: Value::String(prompt_str),
                }]
            };

        let tools = if options.tools.is_empty() {
            None
        } else {
            Some(
                options
                    .tools
                    .iter()
                    .map(|t| {
                        let params: Value =
                            serde_json::from_str(&t.parameters).unwrap_or(json!({}));
                        Tool {
                            tool_type: "function".to_string(),
                            function: ToolFunction {
                                name: t.name.clone(),
                                description: t.description.clone(),
                                parameters: params,
                            },
                        }
                    })
                    .collect(),
            )
        };

        let has_tools = tools.is_some();
        let response_format = if options.json_mode && !has_tools {
            Some(ResponseFormat {
                type_: "json_object".to_string(),
            })
        } else {
            None
        };
        let max_tokens = (options.max_tokens > 0).then_some(options.max_tokens);
        let local_runtime_options = ollama_request_options_for_api_url(api_url);

        let body = OpenAiRequest {
            model: model_name.to_string(),
            messages,
            tools,
            tool_choice: has_tools.then(|| json!("required")),
            parallel_tool_calls: has_tools.then_some(false),
            temperature: options.temperature,
            max_tokens,
            stream,
            response_format,
            options: local_runtime_options,
        };

        Ok(client
            .post(api_url)
            .header("Authorization", format!("Bearer {}", api_key))
            .json(&body))
    }

    async fn parse_response(&self, response: reqwest::Response) -> Result<Vec<u8>, VmError> {
        #[derive(Deserialize)]
        struct OpenAiResponse {
            choices: Vec<Choice>,
        }
        #[derive(Deserialize)]
        struct Choice {
            message: ResponseMessage,
            finish_reason: Option<String>,
        }
        #[derive(Deserialize)]
        struct ResponseMessage {
            content: Option<String>,
            tool_calls: Option<Vec<ToolCall>>,
            refusal: Option<String>,
        }
        #[derive(Deserialize)]
        struct ToolCall {
            function: FunctionCall,
        }
        #[derive(Deserialize)]
        struct FunctionCall {
            name: String,
            arguments: String,
        }

        fn decode_openai_response(resp: OpenAiResponse, text: &str) -> Result<Vec<u8>, VmError> {
            let choice = resp
                .choices
                .first()
                .ok_or(VmError::HostError("No choices".into()))?;

            if let Some(refusal) = &choice.message.refusal {
                return Err(VmError::HostError(format!("LLM_REFUSAL: {}", refusal)));
            }

            if let Some(calls) = &choice.message.tool_calls {
                if let Some(call) = calls.first() {
                    let json = json!({
                        "name": call.function.name,
                        "arguments": serde_json::from_str::<Value>(&call.function.arguments).unwrap_or(Value::Null)
                    });
                    return Ok(json.to_string().into_bytes());
                }
            }

            let content = choice.message.content.clone().unwrap_or_default();
            if content.trim().is_empty() {
                let reason = choice
                    .finish_reason
                    .clone()
                    .unwrap_or("unknown".to_string());
                if ["content_filter", "stop", "length"].contains(&reason.as_str()) {
                    return Err(VmError::HostError(format!(
                        "LLM_REFUSAL: Empty content (reason: {})",
                        reason
                    )));
                }
                return Err(VmError::HostError(format!(
                    "Empty content. Reason: {}. Raw: {}",
                    reason, text
                )));
            }
            Ok(content.into_bytes())
        }

        let mut body = Vec::new();
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|e| VmError::HostError(e.to_string()))?;
            body.extend_from_slice(&chunk);

            if let Ok(resp) = serde_json::from_slice::<OpenAiResponse>(&body) {
                let text = String::from_utf8(body.clone())
                    .map_err(|e| VmError::HostError(format!("UTF-8 decode error: {}", e)))?;
                return decode_openai_response(resp, &text);
            }
        }

        let text = String::from_utf8(body)
            .map_err(|e| VmError::HostError(format!("UTF-8 decode error: {}", e)))?;
        let resp: OpenAiResponse = serde_json::from_str(&text)
            .map_err(|e| VmError::HostError(format!("Parse error: {} | Raw: {}", e, text)))?;

        decode_openai_response(resp, &text)
    }

    async fn parse_stream_chunk(&self, _chunk: &[u8]) -> Result<Option<String>, VmError> {
        Ok(None)
    }

    fn supports_streaming(&self) -> bool {
        true
    }
}

// --- Anthropic Strategy ---

struct AnthropicStrategy {
    beta_header: String,
}

#[derive(Serialize)]
struct AnthropicRequest {
    model: String,
    messages: Vec<AnthropicMessage>,
    max_tokens: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    tools: Option<Vec<AnthropicTool>>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    stream: bool,
    temperature: f32,
}

#[derive(Serialize)]
struct AnthropicMessage {
    role: String,
    content: Vec<AnthropicContentBlock>,
}

#[derive(Serialize)]
#[serde(tag = "type")]
enum AnthropicContentBlock {
    #[serde(rename = "text")]
    Text { text: String },
    #[serde(rename = "image")]
    Image { source: AnthropicImageSource },
}

#[derive(Serialize)]
struct AnthropicImageSource {
    #[serde(rename = "type")]
    type_: String,
    media_type: String,
    data: String,
}

#[derive(Serialize)]
struct AnthropicTool {
    name: String,
    description: String,
    input_schema: Value,
}

#[derive(Deserialize)]
struct AnthropicResponse {
    content: Vec<ContentBlock>,
}

#[derive(Deserialize)]
#[serde(tag = "type")]
enum ContentBlock {
    #[serde(rename = "text")]
    Text { text: String },
    #[serde(rename = "tool_use")]
    ToolUse { name: String, input: Value },
}

#[async_trait]
impl ProviderStrategy for AnthropicStrategy {
    fn build_request(
        &self,
        client: &Client,
        api_url: &str,
        api_key: &str,
        model_name: &str,
        input_context: &[u8],
        options: &InferenceOptions,
        stream: bool,
    ) -> Result<RequestBuilder, VmError> {
        let json_input: Value = serde_json::from_slice(input_context).or_else(|_| {
            let text = String::from_utf8_lossy(input_context).to_string();
            Ok::<_, VmError>(json!([{"role": "user", "content": text}]))
        })?;

        let mut messages = Vec::new();
        if let Some(arr) = json_input.as_array() {
            for msg in arr {
                let role = msg.get("role").and_then(Value::as_str).unwrap_or("user");
                let mut blocks = Vec::new();

                if let Some(text) = msg.get("content").and_then(Value::as_str) {
                    blocks.push(AnthropicContentBlock::Text {
                        text: text.to_string(),
                    });
                } else if let Some(content_arr) = msg.get("content").and_then(Value::as_array) {
                    for item in content_arr {
                        if let Some(t) = item.get("type").and_then(Value::as_str) {
                            match t {
                                "text" => {
                                    if let Some(txt) = item.get("text").and_then(Value::as_str) {
                                        blocks.push(AnthropicContentBlock::Text {
                                            text: txt.to_string(),
                                        });
                                    }
                                }
                                "image_url" => {
                                    if let Some(url) = item
                                        .get("image_url")
                                        .and_then(|v| v.get("url"))
                                        .and_then(Value::as_str)
                                    {
                                        if let Some(b64) =
                                            url.strip_prefix("data:image/jpeg;base64,")
                                        {
                                            blocks.push(AnthropicContentBlock::Image {
                                                source: AnthropicImageSource {
                                                    type_: "base64".into(),
                                                    media_type: "image/jpeg".into(),
                                                    data: b64.into(),
                                                },
                                            });
                                        } else if let Some(b64) =
                                            url.strip_prefix("data:image/png;base64,")
                                        {
                                            blocks.push(AnthropicContentBlock::Image {
                                                source: AnthropicImageSource {
                                                    type_: "base64".into(),
                                                    media_type: "image/png".into(),
                                                    data: b64.into(),
                                                },
                                            });
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                }
                messages.push(AnthropicMessage {
                    role: role.into(),
                    content: blocks,
                });
            }
        }

        let tools = if options.tools.is_empty() {
            None
        } else {
            Some(
                options
                    .tools
                    .iter()
                    .map(|t| {
                        let schema: Value =
                            serde_json::from_str(&t.parameters).unwrap_or(json!({}));
                        AnthropicTool {
                            name: t.name.clone(),
                            description: t.description.clone(),
                            input_schema: schema,
                        }
                    })
                    .collect(),
            )
        };

        // Use options.max_tokens if set (non-zero), otherwise fallback to 4096
        let max_tokens = if options.max_tokens > 0 {
            options.max_tokens
        } else {
            4096
        };

        let body = AnthropicRequest {
            model: model_name.into(),
            messages,
            max_tokens,
            tools,
            stream,
            temperature: options.temperature,
        };

        let mut builder = client
            .post(api_url)
            .header("x-api-key", api_key)
            .header("anthropic-version", "2023-06-01")
            .json(&body);

        if model_name.contains("claude-3-5-sonnet") {
            builder = builder.header("anthropic-beta", &self.beta_header);
        }

        Ok(builder)
    }

    async fn parse_response(&self, response: reqwest::Response) -> Result<Vec<u8>, VmError> {
        let text = response
            .text()
            .await
            .map_err(|e| VmError::HostError(e.to_string()))?;
        let resp: AnthropicResponse = serde_json::from_str(&text).map_err(|e| {
            VmError::HostError(format!("Anthropic parse error: {} | Raw: {}", e, text))
        })?;

        for block in resp.content {
            match block {
                ContentBlock::ToolUse { name, input } => {
                    let tool_json = json!({
                        "name": name,
                        "arguments": input
                    });
                    return Ok(tool_json.to_string().into_bytes());
                }
                ContentBlock::Text { text } => {
                    if !text.trim().is_empty() {
                        return Ok(text.into_bytes());
                    }
                }
            }
        }

        Err(VmError::HostError("Empty response from Anthropic".into()))
    }

    async fn parse_stream_chunk(&self, _chunk: &[u8]) -> Result<Option<String>, VmError> {
        Ok(None)
    }
}

// --- Main Runtime Implementation ---

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProviderKind {
    OpenAi,
    Anthropic,
}

impl ProviderKind {
    fn label(self) -> &'static str {
        match self {
            Self::OpenAi => "openai-compatible",
            Self::Anthropic => "anthropic-compatible",
        }
    }
}

#[derive(Debug, Default)]
struct PartialToolCall {
    name: Option<String>,
    arguments: String,
}

#[derive(Debug, Default)]
struct OpenAiStreamAccumulator {
    content: String,
    refusal: Option<String>,
    tool_calls: BTreeMap<usize, PartialToolCall>,
}

#[derive(Deserialize)]
struct OpenAiStreamEnvelope {
    choices: Vec<OpenAiStreamChoice>,
}

#[derive(Deserialize)]
struct OpenAiStreamChoice {
    #[serde(default)]
    delta: OpenAiStreamDelta,
    finish_reason: Option<String>,
}

#[derive(Deserialize, Default)]
struct OpenAiStreamDelta {
    content: Option<String>,
    refusal: Option<String>,
    tool_calls: Option<Vec<OpenAiStreamToolCallDelta>>,
}

#[derive(Deserialize)]
struct OpenAiStreamToolCallDelta {
    #[serde(default)]
    index: usize,
    function: Option<OpenAiStreamFunctionDelta>,
}

#[derive(Deserialize)]
struct OpenAiStreamFunctionDelta {
    name: Option<String>,
    arguments: Option<String>,
}

impl OpenAiStreamAccumulator {
    fn apply_data_line(&mut self, line: &str) -> Result<Option<Vec<u8>>, VmError> {
        if line == "[DONE]" {
            return self.finalize();
        }

        let envelope: OpenAiStreamEnvelope = serde_json::from_str(line).map_err(|e| {
            VmError::HostError(format!(
                "OpenAI streaming parse error: {} | Chunk: {}",
                e, line
            ))
        })?;

        for choice in envelope.choices {
            self.apply_choice(&choice);
            if let Some(output) = self.completed_tool_call()? {
                return Ok(Some(output));
            }
            if matches!(
                choice.finish_reason.as_deref(),
                Some("stop" | "length" | "tool_calls" | "content_filter")
            ) {
                return self.finalize();
            }
        }

        Ok(None)
    }

    fn apply_choice(&mut self, choice: &OpenAiStreamChoice) {
        if let Some(refusal) = &choice.delta.refusal {
            self.refusal = Some(refusal.clone());
        }
        if let Some(content) = &choice.delta.content {
            self.content.push_str(content);
        }
        if let Some(tool_calls) = &choice.delta.tool_calls {
            for delta in tool_calls {
                let entry = self.tool_calls.entry(delta.index).or_default();
                if let Some(function) = &delta.function {
                    if let Some(name) = &function.name {
                        entry.name = Some(name.clone());
                    }
                    if let Some(arguments) = &function.arguments {
                        entry.arguments.push_str(arguments);
                    }
                }
            }
        }
    }

    fn completed_tool_call(&self) -> Result<Option<Vec<u8>>, VmError> {
        for partial in self.tool_calls.values() {
            if let Some(name) = &partial.name {
                if let Ok(arguments) = serde_json::from_str::<Value>(&partial.arguments) {
                    let output = json!({
                        "name": name,
                        "arguments": arguments,
                    });
                    return Ok(Some(output.to_string().into_bytes()));
                }
            }
        }
        Ok(None)
    }

    fn finalize(&self) -> Result<Option<Vec<u8>>, VmError> {
        if let Some(refusal) = &self.refusal {
            return Err(VmError::HostError(format!("LLM_REFUSAL: {}", refusal)));
        }

        if let Some(tool_call) = self.completed_tool_call()? {
            return Ok(Some(tool_call));
        }

        if !self.content.trim().is_empty() {
            return Ok(Some(self.content.clone().into_bytes()));
        }

        Ok(None)
    }
}

pub struct HttpInferenceRuntime {
    client: Client,
    api_url: String,
    api_key: String,
    model_name: String,
    strategy: Box<dyn ProviderStrategy>,
    provider_kind: ProviderKind,
}

impl HttpInferenceRuntime {
    pub fn new(api_url: String, api_key: String, model_name: String) -> Self {
        let client = match Client::builder()
            .timeout(inference_http_timeout_for_api_url(&api_url))
            .build()
        {
            Ok(client) => client,
            Err(err) => {
                log::warn!(
                    "Failed to build configured HTTP client ({}); falling back to default client",
                    err
                );
                Client::new()
            }
        };

        let (provider_kind, strategy): (ProviderKind, Box<dyn ProviderStrategy>) =
            if model_name.to_lowercase().contains("claude") {
                let beta = std::env::var("ANTHROPIC_BETA_HEADER")
                    .unwrap_or_else(|_| "computer-use-2024-10-22".to_string());
                (
                    ProviderKind::Anthropic,
                    Box::new(AnthropicStrategy { beta_header: beta }),
                )
            } else {
                (ProviderKind::OpenAi, Box::new(OpenAiStrategy))
            };

        Self {
            client,
            api_url,
            api_key,
            model_name,
            strategy,
            provider_kind,
        }
    }

    async fn execute_openai_streaming(
        &self,
        input_context: &[u8],
        options: &InferenceOptions,
        token_stream: Option<Sender<String>>,
    ) -> Result<Vec<u8>, VmError> {
        let request = self.strategy.build_request(
            &self.client,
            &self.api_url,
            &self.api_key,
            &self.model_name,
            input_context,
            options,
            true,
        )?;

        let response = request
            .send()
            .await
            .map_err(|e| VmError::HostError(format!("Network Error: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = read_error_response_body(response).await;
            log::error!("Provider Error {}: {}", status, body);
            return Err(VmError::HostError(format!(
                "Provider Error {}: {}",
                status, body
            )));
        }

        let mut byte_stream = response.bytes_stream();
        let mut pending = String::new();
        let mut accumulator = OpenAiStreamAccumulator::default();
        let mut emitted_text_len = 0usize;

        while let Some(chunk) = byte_stream.next().await {
            let chunk = chunk.map_err(|e| VmError::HostError(format!("Stream Error: {}", e)))?;
            let chunk_text = std::str::from_utf8(&chunk).map_err(|e| {
                VmError::HostError(format!("Streaming chunk was not valid UTF-8: {}", e))
            })?;
            pending.push_str(chunk_text);

            while let Some(newline_pos) = pending.find('\n') {
                let mut line = pending.drain(..=newline_pos).collect::<String>();
                if line.ends_with('\n') {
                    line.pop();
                }
                if line.ends_with('\r') {
                    line.pop();
                }
                if line.is_empty() {
                    continue;
                }
                if let Some(data) = line.strip_prefix("data: ") {
                    if let Some(output) = accumulator.apply_data_line(data)? {
                        return Ok(output);
                    }
                    if let Some(sender) = token_stream.as_ref() {
                        if accumulator.content.len() > emitted_text_len {
                            let delta = accumulator.content[emitted_text_len..].to_string();
                            emitted_text_len = accumulator.content.len();
                            let _ = sender.send(delta).await;
                        }
                    }
                }
            }
        }

        if !pending.trim().is_empty() {
            if let Some(data) = pending
                .trim_end_matches(['\r', '\n'])
                .strip_prefix("data: ")
            {
                if let Some(output) = accumulator.apply_data_line(data)? {
                    return Ok(output);
                }
            }
        }

        accumulator.finalize()?.ok_or_else(|| {
            VmError::HostError("OpenAI streaming response ended without content".into())
        })
    }
}

fn inference_http_timeout_for_api_url(api_url: &str) -> Duration {
    Duration::from_secs(inference_http_timeout_seconds_for_api_url_with_lookup(
        api_url,
        |key| std::env::var(key).ok(),
    ))
}

fn ollama_request_options_for_api_url(api_url: &str) -> Option<Value> {
    if runtime_kind_for_api_url(api_url) != StudioRuntimeProvenanceKind::RealLocalRuntime {
        return None;
    }

    let num_ctx = std::env::var("OLLAMA_CONTEXT_LENGTH")
        .ok()
        .and_then(|value| value.trim().parse::<u32>().ok())
        .filter(|value| *value > 0)?;
    Some(json!({ "num_ctx": num_ctx }))
}

async fn read_error_response_body(response: reqwest::Response) -> String {
    match tokio::time::timeout(Duration::from_secs(3), response.text()).await {
        Ok(Ok(body)) if !body.trim().is_empty() => body,
        Ok(Ok(_)) => "<empty error body>".to_string(),
        Ok(Err(error)) => format!("<failed to read error body: {error}>"),
        Err(_) => "<timed out while reading error body>".to_string(),
    }
}

fn inference_http_timeout_seconds_for_api_url_with_lookup<F>(api_url: &str, lookup: F) -> u64
where
    F: Fn(&str) -> Option<String>,
{
    inference_http_timeout_override_seconds_with_lookup(&lookup)
        .unwrap_or_else(|| default_inference_http_timeout_seconds(api_url))
}

fn inference_http_timeout_override_seconds_with_lookup<F>(lookup: &F) -> Option<u64>
where
    F: Fn(&str) -> Option<String>,
{
    [
        "AUTOPILOT_INFERENCE_HTTP_TIMEOUT_SECS",
        "IOI_INFERENCE_HTTP_TIMEOUT_SECS",
    ]
    .iter()
    .find_map(|key| {
        lookup(key).and_then(|value| {
            value
                .trim()
                .parse::<u64>()
                .ok()
                .filter(|seconds| *seconds > 0)
        })
    })
}

fn default_inference_http_timeout_seconds(api_url: &str) -> u64 {
    match runtime_kind_for_api_url(api_url) {
        StudioRuntimeProvenanceKind::RealLocalRuntime => 600,
        _ => 60,
    }
}

fn should_use_openai_streaming(
    api_url: &str,
    provider_kind: ProviderKind,
    strategy_supports_streaming: bool,
    has_token_stream: bool,
    options: &InferenceOptions,
) -> bool {
    if !strategy_supports_streaming || provider_kind != ProviderKind::OpenAi {
        return false;
    }

    if has_token_stream {
        return true;
    }

    !options.tools.is_empty()
        && runtime_kind_for_api_url(api_url) != StudioRuntimeProvenanceKind::RealLocalRuntime
}

fn normalize_embedding_env(value: Option<String>) -> Option<String> {
    value
        .map(|entry| entry.trim().to_string())
        .filter(|entry| !entry.is_empty())
}

fn uses_openai_embedding_endpoint(api_url: &str) -> bool {
    api_url.contains("openai.com")
}

fn resolve_embedding_target_url(api_url: &str) -> Result<String, VmError> {
    if uses_openai_embedding_endpoint(api_url) {
        return Ok("https://api.openai.com/v1/embeddings".to_string());
    }

    let trimmed = api_url.trim_end_matches('/');
    if trimmed.ends_with("/embeddings") {
        return Ok(trimmed.to_string());
    }
    if let Some(prefix) = trimmed.strip_suffix("/chat/completions") {
        return Ok(format!("{prefix}/embeddings"));
    }
    if trimmed.ends_with("/v1") {
        return Ok(format!("{trimmed}/embeddings"));
    }

    Err(VmError::HostError(format!(
        "Cannot determine embedding URL from '{}'",
        api_url
    )))
}

fn resolve_embedding_model_with<F>(api_url: &str, lookup: F) -> String
where
    F: Fn(&str) -> Option<String>,
{
    if uses_openai_embedding_endpoint(api_url) {
        return normalize_embedding_env(lookup("OPENAI_EMBEDDING_MODEL"))
            .unwrap_or_else(|| "text-embedding-3-small".to_string());
    }

    normalize_embedding_env(lookup("AUTOPILOT_LOCAL_EMBEDDING_MODEL"))
        .or_else(|| normalize_embedding_env(lookup("LOCAL_LLM_EMBEDDING_MODEL")))
        .or_else(|| normalize_embedding_env(lookup("OPENAI_EMBEDDING_MODEL")))
        .unwrap_or_else(|| "nomic-embed-text".to_string())
}

#[async_trait]
impl InferenceRuntime for HttpInferenceRuntime {
    async fn execute_inference(
        &self,
        model_hash: [u8; 32],
        input_context: &[u8],
        options: InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        self.execute_inference_streaming(model_hash, input_context, options, None)
            .await
    }

    async fn execute_inference_streaming(
        &self,
        _model_hash: [u8; 32],
        input_context: &[u8],
        options: InferenceOptions,
        token_stream: Option<Sender<String>>,
    ) -> Result<Vec<u8>, VmError> {
        let can_stream = should_use_openai_streaming(
            &self.api_url,
            self.provider_kind,
            self.strategy.supports_streaming(),
            token_stream.is_some(),
            &options,
        );
        if can_stream {
            return self
                .execute_openai_streaming(input_context, &options, token_stream)
                .await;
        }

        let request = self.strategy.build_request(
            &self.client,
            &self.api_url,
            &self.api_key,
            &self.model_name,
            input_context,
            &options,
            false,
        )?;

        let response = request
            .send()
            .await
            .map_err(|e| VmError::HostError(format!("Network Error: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = read_error_response_body(response).await;
            log::error!("Provider Error {}: {}", status, body);
            return Err(VmError::HostError(format!(
                "Provider Error {}: {}",
                status, body
            )));
        }

        self.strategy.parse_response(response).await
    }

    async fn embed_text(&self, text: &str) -> Result<Vec<f32>, VmError> {
        #[derive(Deserialize)]
        struct EmbeddingResponse {
            data: Vec<EmbeddingData>,
        }
        #[derive(Deserialize)]
        struct EmbeddingData {
            embedding: Vec<f32>,
        }

        let target_url = resolve_embedding_target_url(&self.api_url)?;
        let model = resolve_embedding_model_with(&self.api_url, |key| std::env::var(key).ok());

        let body = json!({
            "input": text,
            "model": model
        });

        let mut request = self.client.post(&target_url);
        if !self.api_key.trim().is_empty() {
            request = request.header("Authorization", format!("Bearer {}", self.api_key));
        }

        let resp = request
            .json(&body)
            .send()
            .await
            .map_err(|e| VmError::HostError(format!("Embedding req failed: {}", e)))?;

        let status = resp.status();
        let raw = resp
            .text()
            .await
            .map_err(|e| VmError::HostError(format!("Embedding read failed: {}", e)))?;
        if !status.is_success() {
            return Err(VmError::HostError(format!(
                "Embedding provider error {}: {}",
                status, raw
            )));
        }

        let data: EmbeddingResponse = serde_json::from_str(&raw).map_err(|e| {
            VmError::HostError(format!("Embedding parse failed: {} | Raw: {}", e, raw))
        })?;

        if let Some(item) = data.data.first() {
            Ok(item.embedding.clone())
        } else {
            Err(VmError::HostError("No embedding returned".into()))
        }
    }

    // [NEW] Implement embed_image via Captioning + Embedding
    async fn embed_image(&self, image_bytes: &[u8]) -> Result<Vec<f32>, VmError> {
        // Since standard APIs (OpenAI) don't have a direct "Embed Image to Vector" endpoint public yet (CLIP is separate),
        // we use a "VLM Caption -> Text Embedding" pipeline. This is a robust fallback for semantic visual search.

        // 1. Caption the image using the VLM
        let b64 = BASE64.encode(image_bytes);
        let prompt = json!([
            { "role": "user", "content": [
                { "type": "text", "text": "Describe this UI screenshot in extreme detail for search indexing. Include text, buttons, layout, and colors." },
                { "type": "image_url", "image_url": { "url": format!("data:image/jpeg;base64,{}", b64) } }
            ]}
        ]);

        // Use a fast VLM call (max tokens low)
        let model_hash = [0u8; 32];
        let options = InferenceOptions {
            max_tokens: 150,
            temperature: 0.0,
            ..Default::default()
        };

        let input_bytes =
            serde_json::to_vec(&prompt).map_err(|e| VmError::Initialization(e.to_string()))?; // [FIX] Use Initialization variant

        let caption_bytes = self
            .execute_inference(model_hash, &input_bytes, options)
            .await?;
        let caption = String::from_utf8_lossy(&caption_bytes).to_string();

        // 2. Embed the caption
        self.embed_text(&caption).await
    }

    async fn load_model(&self, _hash: [u8; 32], _path: &Path) -> Result<(), VmError> {
        Ok(())
    }
    async fn unload_model(&self, _hash: [u8; 32]) -> Result<(), VmError> {
        Ok(())
    }

    fn studio_runtime_provenance(&self) -> StudioRuntimeProvenance {
        StudioRuntimeProvenance {
            kind: runtime_kind_for_api_url(&self.api_url),
            label: self.provider_kind.label().to_string(),
            model: Some(self.model_name.clone()),
            endpoint: Some(self.api_url.clone()),
        }
    }
}

fn runtime_kind_for_api_url(api_url: &str) -> StudioRuntimeProvenanceKind {
    let host = reqwest::Url::parse(api_url)
        .ok()
        .and_then(|url| url.host_str().map(str::to_ascii_lowercase));
    match host.as_deref() {
        Some("localhost") | Some("127.0.0.1") | Some("::1") => {
            StudioRuntimeProvenanceKind::RealLocalRuntime
        }
        Some(_) => StudioRuntimeProvenanceKind::RealRemoteModelRuntime,
        None => StudioRuntimeProvenanceKind::OpaqueRuntime,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        default_inference_http_timeout_seconds,
        inference_http_timeout_seconds_for_api_url_with_lookup, resolve_embedding_model_with,
        resolve_embedding_target_url, should_use_openai_streaming, HttpInferenceRuntime,
        OpenAiStrategy, OpenAiStreamAccumulator, ProviderKind, ProviderStrategy,
    };
    use crate::vm::inference::InferenceRuntime;
    use ioi_types::app::agentic::{InferenceOptions, LlmToolDefinition};
    use reqwest::Client;
    use serde_json::{json, Value};
    use std::collections::HashMap;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

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
    async fn openai_parse_response_does_not_wait_for_chunked_body_termination() {
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
            tokio::time::sleep(Duration::from_secs(5)).await;
        });

        let runtime = HttpInferenceRuntime::new(
            format!("http://{address}/v1/chat/completions"),
            String::new(),
            "qwen2.5:7b".to_string(),
        );
        let result = tokio::time::timeout(
            Duration::from_secs(2),
            runtime.execute_inference(
                [0u8; 32],
                br#"[{"role":"user","content":"Say ok"}]"#,
                InferenceOptions::default(),
            ),
        )
        .await;

        let output = result
            .expect("non-stream parse should not wait for terminal chunk")
            .expect("inference result");
        assert_eq!(String::from_utf8(output).unwrap(), "{\"ok\":true}");
    }

    #[test]
    fn local_embedding_routes_use_local_model_defaults() {
        let env = HashMap::from([(
            "AUTOPILOT_LOCAL_EMBEDDING_MODEL",
            "nomic-embed-text".to_string(),
        )]);

        let model =
            resolve_embedding_model_with("http://127.0.0.1:11434/v1/chat/completions", |key| {
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

        let model =
            resolve_embedding_model_with("https://api.openai.com/v1/chat/completions", |key| {
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
    fn explicit_http_timeout_override_takes_precedence() {
        let env = HashMap::from([("AUTOPILOT_INFERENCE_HTTP_TIMEOUT_SECS", "300".to_string())]);

        let timeout = inference_http_timeout_seconds_for_api_url_with_lookup(
            "http://127.0.0.1:11434/v1/chat/completions",
            |key| env.get(key).cloned(),
        );

        assert_eq!(timeout, 300);
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
}
