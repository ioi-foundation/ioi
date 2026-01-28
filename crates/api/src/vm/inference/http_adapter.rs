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

#[derive(Deserialize)]
struct ChatCompletionResponse {
    choices: Vec<Choice>,
}

#[derive(Deserialize)]
struct Choice {
    message: ResponseMessage,
}

#[derive(Deserialize)]
struct ResponseMessage {
    content: Option<String>,
    tool_calls: Option<Vec<ToolCall>>,
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

#[derive(Deserialize)]
struct ChatCompletionChunk {
    choices: Vec<ChunkChoice>,
}
#[derive(Deserialize)]
struct ChunkChoice {
    delta: ChunkDelta,
}
#[derive(Deserialize)]
struct ChunkDelta {
    content: Option<String>,
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

        if !response.status().is_success() {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".into());
            return Err(VmError::HostError(format!("API Error: {}", error_text)));
        }

        if stream_mode {
            let mut full_content = String::new();
            let mut buffer = String::new();
            let sender = token_stream.unwrap();

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
                                    if let Some(content) = &choice.delta.content {
                                        let _ = sender.send(content.clone()).await;
                                        full_content.push_str(content);
                                    }
                                }
                            }
                        }
                    }
                    // [FIX] Correct buffer slicing to discard processed line
                    buffer = buffer[line_end + 1..].to_string();
                }
            }
            
            // [FIX] Process residual buffer (The Fix for Data Loss)
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
                                }
                            }
                        }
                 }
            }
            
            Ok(full_content.into_bytes())
        } else {
            let response_body: ChatCompletionResponse = response
                .json::<ChatCompletionResponse>()
                .await
                .map_err(|e| VmError::HostError(format!("Failed to parse response: {}", e)))?;

            let choice = response_body
                .choices
                .first()
                .ok_or_else(|| VmError::HostError("No choices returned".into()))?;

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