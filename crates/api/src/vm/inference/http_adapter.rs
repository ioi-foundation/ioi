// Path: crates/api/src/vm/inference/http_adapter.rs

use async_trait::async_trait;
use ioi_types::app::agentic::InferenceOptions;
use ioi_types::error::VmError;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::path::Path;
use std::time::Duration;

use super::InferenceRuntime;

/// A generic HTTP adapter for OpenAI-compatible inference APIs.
/// This allows the IOI Kernel to drive external models (GPT-4, Claude, vLLM, Ollama).
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
                .timeout(Duration::from_secs(60)) // Generous timeout for chain-of-thought
                .build()
                .expect("Failed to build HTTP client"),
            api_url,
            api_key,
            model_name,
        }
    }
}

// --- OpenAI API Request/Response Structures ---

#[derive(Serialize)]
struct ChatCompletionRequest {
    model: String,
    messages: Vec<Message>,
    tools: Option<Vec<Tool>>,
    temperature: f32,
}

#[derive(Serialize)]
struct Message {
    role: String,
    content: String,
}

#[derive(Serialize)]
struct Tool {
    #[serde(rename = "type")]
    tool_type: String, // Always "function"
    function: ToolFunction, // [CHANGED] Use a local struct for API mapping
}

// [NEW] Local struct to map LlmToolDefinition to OpenAI API format
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

#[async_trait]
impl InferenceRuntime for HttpInferenceRuntime {
    async fn execute_inference(
        &self,
        _model_hash: [u8; 32], // Ignored for HTTP adapter, we trust the endpoint
        input_context: &[u8],
        options: InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        // 1. Decode Input
        let prompt_str = String::from_utf8(input_context.to_vec())
            .map_err(|e| VmError::InvalidBytecode(format!("Input context must be UTF-8: {}", e)))?;

        // 2. Map Tools
        let tools = if options.tools.is_empty() {
            None
        } else {
            Some(
                options
                    .tools
                    .into_iter()
                    .map(|t| {
                        // [FIX] Parse the string back to Value for the API
                        let params_val: serde_json::Value =
                            serde_json::from_str(&t.parameters).unwrap_or(json!({})); // Fallback if invalid JSON

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

        // 3. Construct Request
        let request_body = ChatCompletionRequest {
            model: self.model_name.clone(),
            messages: vec![Message {
                role: "user".to_string(),
                content: prompt_str,
            }],
            tools,
            temperature: options.temperature,
        };

        // 4. Execute HTTP Call
        // [FIX] Explicitly handle the Response future
        let response = self
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

        // [FIX] Explicitly deserialize into ChatCompletionResponse
        let response_body: ChatCompletionResponse = response
            .json::<ChatCompletionResponse>()
            .await
            .map_err(|e| VmError::HostError(format!("Failed to parse response: {}", e)))?;

        // 5. Map Response back to Kernel Format
        let choice = response_body
            .choices
            .first()
            .ok_or_else(|| VmError::HostError("No choices returned".into()))?;

        if let Some(tool_calls) = &choice.message.tool_calls {
            // [FIX] Handle tool_calls being potentially empty but Some
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

    async fn load_model(&self, _model_hash: [u8; 32], _path: &Path) -> Result<(), VmError> {
        Ok(())
    }

    async fn unload_model(&self, _model_hash: [u8; 32]) -> Result<(), VmError> {
        Ok(())
    }
}
