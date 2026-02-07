// Path: crates/api/src/vm/inference/providers/openai.rs

use async_trait::async_trait;
use reqwest::{Client, RequestBuilder};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use ioi_types::app::agentic::InferenceOptions;
use ioi_types::error::VmError;

// [FIX] Define the ProviderStrategy trait locally if not exported, or import if it is.
// Assuming it's defined in a shared internal module or we re-define for this file context.
// For this output, we assume it's part of the crate's internal API.

use super::super::http_adapter::ProviderStrategy; // Assuming internal visibility

pub struct OpenAiStrategy;

#[derive(Serialize)]
struct OpenAiRequest {
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
        stream: bool
    ) -> Result<RequestBuilder, VmError> {
        let messages: Vec<Message> = if let Ok(json_val) = serde_json::from_slice::<Value>(input_context) {
             if let Ok(msgs) = serde_json::from_value::<Vec<Message>>(json_val.clone()) {
                 msgs
             } else {
                 vec![Message { role: "user".to_string(), content: json_val }]
             }
        } else {
             let prompt_str = String::from_utf8(input_context.to_vec())
                 .map_err(|e| VmError::InvalidBytecode(format!("Input must be UTF-8: {}", e)))?;
             vec![Message { role: "user".to_string(), content: Value::String(prompt_str) }]
        };

        let tools = if options.tools.is_empty() {
            None
        } else {
            Some(options.tools.iter().map(|t| {
                let params: Value = serde_json::from_str(&t.parameters).unwrap_or(json!({}));
                Tool {
                    tool_type: "function".to_string(),
                    function: ToolFunction {
                        name: t.name.clone(),
                        description: t.description.clone(),
                        parameters: params,
                    },
                }
            }).collect())
        };

        let response_format = if options.json_mode {
            Some(ResponseFormat { type_: "json_object".to_string() })
        } else {
            None
        };

        let body = OpenAiRequest {
            model: model_name.to_string(),
            messages,
            tools,
            temperature: options.temperature,
            stream,
            response_format,
        };

        Ok(client.post(api_url)
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

        let text = response.text().await.map_err(|e| VmError::HostError(e.to_string()))?;
        let resp: OpenAiResponse = serde_json::from_str(&text)
            .map_err(|e| VmError::HostError(format!("Parse error: {} | Raw: {}", e, text)))?;

        let choice = resp.choices.first().ok_or(VmError::HostError("No choices".into()))?;

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
             let reason = choice.finish_reason.clone().unwrap_or("unknown".to_string());
             if ["content_filter", "stop", "length"].contains(&reason.as_str()) {
                 return Err(VmError::HostError(format!("LLM_REFUSAL: Empty content (reason: {})", reason)));
             }
             return Err(VmError::HostError(format!("Empty content. Reason: {}. Raw: {}", reason, text)));
        }
        Ok(content.into_bytes())
    }

    async fn parse_stream_chunk(&self, _chunk: &[u8]) -> Result<Option<String>, VmError> {
        Ok(None)
    }
}