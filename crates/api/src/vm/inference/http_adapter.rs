// Path: crates/api/src/vm/inference/http_adapter.rs

use async_trait::async_trait;
use ioi_types::app::agentic::InferenceOptions;
use ioi_types::error::VmError;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::path::Path;
use std::time::Duration;
use tokio::sync::mpsc::Sender;

use super::InferenceRuntime;

pub struct HttpInferenceRuntime {
    client: Client,
    api_url: String,
    api_key: String,
    model_name: String,
}

impl HttpInferenceRuntime {
    pub fn new(api_url: String, api_key: String, model_name: String) -> Self {
        Self {
            client: Client::builder()
                .timeout(Duration::from_secs(60))
                .build()
                .expect("Failed to build HTTP client"),
            api_url,
            api_key,
            model_name,
        }
    }
}

#[derive(Serialize)]
struct ResponseFormat {
    #[serde(rename = "type")]
    type_: String, 
}

#[derive(Serialize)]
struct ChatCompletionRequest {
    model: String,
    messages: Vec<Message>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tools: Option<Vec<Tool>>,
    temperature: f32,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    stream: bool, 
    #[serde(skip_serializing_if = "Option::is_none")]
    response_format: Option<ResponseFormat>,
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

#[derive(Deserialize, Debug)]
struct ChatCompletionResponse {
    choices: Vec<Choice>,
}

#[derive(Deserialize, Debug)]
struct Choice {
    message: ResponseMessage,
    // [NEW] Capture finish_reason for debugging (e.g. "content_filter", "length")
    finish_reason: Option<String>,
}

#[derive(Deserialize, Debug)]
struct ResponseMessage {
    content: Option<String>,
    tool_calls: Option<Vec<ToolCall>>,
    // [FIX] Capture refusal field (OpenAI specific safety mechanism)
    refusal: Option<String>,
}

#[derive(Deserialize, Debug)]
struct ToolCall {
    function: FunctionCall,
}

#[derive(Deserialize, Debug)]
struct FunctionCall {
    name: String,
    arguments: String,
}

#[derive(Deserialize)]
struct ChatCompletionChunk {
    choices: Vec<ChunkChoice>,
}

#[derive(Deserialize)]
struct ChunkChoice {
    delta: ChunkDelta,
}

// [FIX] Expanded to support tool calls in streaming mode
#[derive(Deserialize, Debug)]
struct ChunkDelta {
    content: Option<String>,
    tool_calls: Option<Vec<ChunkToolCall>>,
}

#[derive(Deserialize, Debug)]
struct ChunkToolCall {
    index: u64,
    function: Option<ChunkFunction>,
}

#[derive(Deserialize, Debug)]
struct ChunkFunction {
    name: Option<String>,
    arguments: Option<String>,
}

#[derive(Deserialize)]
struct EmbeddingResponse {
    data: Vec<EmbeddingData>,
}

#[derive(Deserialize)]
struct EmbeddingData {
    embedding: Vec<f32>,
}

#[async_trait]
impl InferenceRuntime for HttpInferenceRuntime {
    async fn execute_inference(
        &self,
        model_hash: [u8; 32],
        input_context: &[u8],
        options: InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        self.execute_inference_streaming(model_hash, input_context, options, None).await
    }

    async fn execute_inference_streaming(
        &self,
        _model_hash: [u8; 32],
        input_context: &[u8],
        options: InferenceOptions,
        token_stream: Option<Sender<String>>,
    ) -> Result<Vec<u8>, VmError> {
        let messages: Vec<Message> = if let Ok(json_val) = serde_json::from_slice::<serde_json::Value>(input_context) {
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
                 .map_err(|e| VmError::InvalidBytecode(format!("Input context must be UTF-8: {}", e)))?;
             vec![Message {
                 role: "user".to_string(),
                 content: serde_json::Value::String(prompt_str),
             }]
        };

        let tools = if options.tools.is_empty() {
            None
        } else {
            Some(
                options
                    .tools
                    .into_iter()
                    .map(|t| {
                        let params_val: serde_json::Value =
                            serde_json::from_str(&t.parameters).unwrap_or(json!({})); 

                        Tool {
                            tool_type: "function".to_string(),
                            function: ToolFunction {
                                name: t.name,
                                description: t.description,
                                parameters: params_val,
                            },
                        }
                    })
                    .collect(),
            )
        };

        let response_format = if options.json_mode {
            Some(ResponseFormat {
                type_: "json_object".to_string(),
            })
        } else {
            None
        };

        let stream_mode = token_stream.is_some();
        let request_body = ChatCompletionRequest {
            model: self.model_name.clone(),
            messages,
            tools,
            temperature: options.temperature,
            stream: stream_mode,
            response_format, 
        };

        let mut response = self
            .client
            .post(&self.api_url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .json(&request_body)
            .send()
            .await
            .map_err(|e| VmError::HostError(format!("HTTP Request failed: {}", e)))?;

        // [FIX] Explicit Error Logging
        if !response.status().is_success() {
            let status = response.status();
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error/No body".into());
            
            log::error!("LLM Provider Error: HTTP {} - Body: {}", status, error_text);
            return Err(VmError::HostError(format!("Provider Error {}: {}", status, error_text)));
        }

        if stream_mode {
            let mut full_content = String::new();
            let mut buffer = String::new();
            let sender = token_stream.unwrap();
            
            // [FIX] Buffers for tool call reconstruction
            let mut tool_name = String::new();
            let mut tool_args = String::new();
            let mut is_tool_call = false;

            while let Ok(Some(chunk)) = response.chunk().await {
                let chunk_str = String::from_utf8_lossy(&chunk);
                buffer.push_str(&chunk_str);

                while let Some(line_end) = buffer.find('\n') {
                    let line = buffer[..line_end].trim();
                    if line.starts_with("data: ") {
                        let data = &line[6..];
                        if data != "[DONE]" {
                            if let Ok(chunk_data) = serde_json::from_str::<ChatCompletionChunk>(data) {
                                if let Some(choice) = chunk_data.choices.first() {
                                    // Handle Content (Thoughts)
                                    if let Some(content) = &choice.delta.content {
                                        let _ = sender.send(content.clone()).await;
                                        full_content.push_str(content);
                                    }

                                    // [FIX] Handle Tool Calls (Action)
                                    if let Some(calls) = &choice.delta.tool_calls {
                                        is_tool_call = true;
                                        if let Some(call) = calls.first() {
                                            if let Some(func) = &call.function {
                                                if let Some(n) = &func.name {
                                                    tool_name.push_str(n);
                                                }
                                                if let Some(a) = &func.arguments {
                                                    tool_args.push_str(a);
                                                    // Stream arguments as tokens so UI sees activity
                                                    let _ = sender.send(a.clone()).await;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    buffer = buffer[line_end + 1..].to_string();
                }
            }
            
            // Process residual buffer (data often comes in split packets)
            if !buffer.trim().is_empty() {
                let line = buffer.trim();
                 if line.starts_with("data: ") {
                        let data = &line[6..];
                        if data != "[DONE]" {
                            if let Ok(chunk_data) = serde_json::from_str::<ChatCompletionChunk>(data) {
                                if let Some(choice) = chunk_data.choices.first() {
                                    if let Some(content) = &choice.delta.content {
                                        let _ = sender.send(content.clone()).await;
                                        full_content.push_str(content);
                                    }
                                    if let Some(calls) = &choice.delta.tool_calls {
                                        is_tool_call = true;
                                        if let Some(call) = calls.first() {
                                            if let Some(func) = &call.function {
                                                if let Some(n) = &func.name { tool_name.push_str(n); }
                                                if let Some(a) = &func.arguments { tool_args.push_str(a); let _ = sender.send(a.clone()).await; }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                 }
            }

            // [FIX] If we accumulated a tool call, format it as the JSON the Kernel expects.
            if is_tool_call {
                // OpenAI tool args are usually a JSON string. We ensure it's valid JSON, 
                // or wrap it if it's malformed (though it usually isn't).
                let args_value: serde_json::Value = serde_json::from_str(&tool_args)
                    .unwrap_or(serde_json::Value::String(tool_args));
                
                let tool_json = json!({
                    "name": tool_name,
                    "arguments": args_value
                });
                return Ok(tool_json.to_string().into_bytes());
            }
            
            Ok(full_content.into_bytes())
        } else {
            // [FIX] Read response as text first to allow logging raw body on error
            let response_text = response.text().await
                .map_err(|e| VmError::HostError(format!("Failed to read response text: {}", e)))?;

            let response_body: ChatCompletionResponse = serde_json::from_str(&response_text)
                .map_err(|e| VmError::HostError(format!("Failed to parse response JSON: {} | Raw: {:.1000}", e, response_text)))?;

            let choice = response_body
                .choices
                .first()
                .ok_or_else(|| VmError::HostError("No choices returned".into()))?;

            // [FIX] Explicitly check for refusal field (OpenAI)
            // Use a specific error prefix 'LLM_REFUSAL:' so the service logic can catch it
            // and pause the agent instead of retrying indefinitely.
            if let Some(refusal) = &choice.message.refusal {
                return Err(VmError::HostError(format!("LLM_REFUSAL: {}", refusal)));
            }

            if let Some(tool_calls) = &choice.message.tool_calls {
                if let Some(first_call) = tool_calls.first() {
                    let output_json = json!({
                        "name": first_call.function.name,
                        "arguments": serde_json::from_str::<serde_json::Value>(&first_call.function.arguments)
                            .unwrap_or(serde_json::Value::Null)
                    });
                    return Ok(output_json.to_string().into_bytes());
                }
            }

            let content = choice.message.content.clone().unwrap_or_default();
            
            // [FIX] Detect empty content and treat as error unless finish_reason explains it.
            // If content is empty and it wasn't a tool call, the model likely refused or hit a filter
            // but didn't populate the `refusal` field (rare but possible).
            if content.trim().is_empty() {
                 let reason = choice.finish_reason.clone().unwrap_or("unknown".to_string());
                 
                 // If reason is "stop" or "content_filter" but content is empty, treat as refusal.
                 if reason == "content_filter" || reason == "stop" || reason == "length" {
                     return Err(VmError::HostError(format!("LLM_REFUSAL: Empty content with finish_reason='{}'", reason)));
                 }
                 
                 // If no tool call, no content, and unknown reason, it's a generic host error.
                 return Err(VmError::HostError(format!(
                     "LLM_REFUSAL: Empty content. Finish Reason: {}. Raw Response: {:.500}", 
                     reason, response_text
                 )));
            }

            Ok(content.into_bytes())
        }
    }

    async fn embed_text(&self, text: &str) -> Result<Vec<f32>, VmError> {
        let embedding_url = if self.api_url.contains("/chat/completions") {
            self.api_url.replace("/chat/completions", "/embeddings")
        } else if self.api_url.contains("/completions") {
            self.api_url.replace("/completions", "/embeddings")
        } else {
            return Err(VmError::HostError(
                "Cannot determine embeddings URL from configured API URL.".into(),
            ));
        };

        let model_to_use = if self.model_name.starts_with("gpt-") || self.model_name.starts_with("chat")
        {
            "text-embedding-3-small"
        } else {
            &self.model_name
        };

        let request_body = json!({
            "input": text,
            "model": model_to_use
        });

        let response = self
            .client
            .post(&embedding_url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .json(&request_body)
            .send()
            .await
            .map_err(|e| VmError::HostError(format!("Embedding Request failed: {}", e)))?;

        if !response.status().is_success() {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".into());
            return Err(VmError::HostError(format!(
                "API Error (Embeddings): {}",
                error_text
            )));
        }

        let response_body: EmbeddingResponse = response.json::<EmbeddingResponse>().await.map_err(
            |e| VmError::HostError(format!("Failed to parse embedding response: {}", e)),
        )?;

        if let Some(first) = response_body.data.first() {
            Ok(first.embedding.clone())
        } else {
            Err(VmError::HostError("No embedding data returned".into()))
        }
    }

    async fn load_model(&self, _model_hash: [u8; 32], _path: &Path) -> Result<(), VmError> {
        Ok(())
    }

    async fn unload_model(&self, _model_hash: [u8; 32]) -> Result<(), VmError> {
        Ok(())
    }
}