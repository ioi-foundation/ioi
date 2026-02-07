// Path: crates/api/src/vm/inference/providers/anthropic.rs

use async_trait::async_trait;
use reqwest::{Client, RequestBuilder};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use ioi_types::app::agentic::InferenceOptions;
use ioi_types::error::VmError;

use super::super::http_adapter::ProviderStrategy; // Assuming internal visibility

pub struct AnthropicStrategy {
    pub beta_header: String,
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
        stream: bool
    ) -> Result<RequestBuilder, VmError> {
        
        // 1. Parse Input
        let json_input: Value = serde_json::from_slice(input_context)
            .or_else(|_| {
                let text = String::from_utf8_lossy(input_context).to_string();
                Ok::<_, VmError>(json!([{"role": "user", "content": text}]))
            })?;

        // 2. Map Messages
        let mut messages = Vec::new();
        if let Some(arr) = json_input.as_array() {
            for msg in arr {
                let role = msg["role"].as_str().unwrap_or("user");
                let mut blocks = Vec::new();

                if let Some(text) = msg["content"].as_str() {
                     blocks.push(AnthropicContentBlock::Text { text: text.to_string() });
                } else if let Some(content_arr) = msg["content"].as_array() {
                    for item in content_arr {
                        if let Some(t) = item["type"].as_str() {
                            match t {
                                "text" => {
                                    if let Some(txt) = item["text"].as_str() {
                                        blocks.push(AnthropicContentBlock::Text { text: txt.to_string() });
                                    }
                                },
                                "image_url" => {
                                    if let Some(url) = item["image_url"]["url"].as_str() {
                                        if let Some(b64) = url.strip_prefix("data:image/jpeg;base64,") {
                                             blocks.push(AnthropicContentBlock::Image {
                                                 source: AnthropicImageSource {
                                                     type_: "base64".into(),
                                                     media_type: "image/jpeg".into(),
                                                     data: b64.into(),
                                                 }
                                             });
                                        } else if let Some(b64) = url.strip_prefix("data:image/png;base64,") {
                                             blocks.push(AnthropicContentBlock::Image {
                                                 source: AnthropicImageSource {
                                                     type_: "base64".into(),
                                                     media_type: "image/png".into(),
                                                     data: b64.into(),
                                                 }
                                             });
                                        }
                                    }
                                },
                                _ => {}
                            }
                        }
                    }
                }
                messages.push(AnthropicMessage { role: role.into(), content: blocks });
            }
        }

        // 3. Map Tools
        let tools = if options.tools.is_empty() {
            None
        } else {
            Some(options.tools.iter().map(|t| {
                let schema: Value = serde_json::from_str(&t.parameters).unwrap_or(json!({}));
                AnthropicTool {
                    name: t.name.clone(),
                    description: t.description.clone(),
                    input_schema: schema,
                }
            }).collect())
        };

        // 4. Build Body
        let body = AnthropicRequest {
            model: model_name.into(),
            messages,
            max_tokens: 4096,
            tools,
            stream,
            temperature: options.temperature,
        };

        // 5. Construct Request
        let mut builder = client.post(api_url)
            .header("x-api-key", api_key)
            .header("anthropic-version", "2023-06-01")
            .json(&body);

        // Inject Beta Header only if doing computer use (heuristic: model name contains 'sonnet')
        if model_name.contains("claude-3-5-sonnet") {
            builder = builder.header("anthropic-beta", &self.beta_header);
        }

        Ok(builder)
    }

    async fn parse_response(&self, response: reqwest::Response) -> Result<Vec<u8>, VmError> {
        let text = response.text().await.map_err(|e| VmError::HostError(e.to_string()))?;
        let resp: AnthropicResponse = serde_json::from_str(&text)
            .map_err(|e| VmError::HostError(format!("Anthropic parse error: {} | Raw: {}", e, text)))?;

        // Prefer Tool Use over Text
        for block in resp.content {
            match block {
                ContentBlock::ToolUse { name, input } => {
                    let tool_json = json!({
                        "name": name,
                        "arguments": input
                    });
                    return Ok(tool_json.to_string().into_bytes());
                },
                ContentBlock::Text { text } => {
                     // If it's the last block and no tool use found yet, return text
                     // But we prefer tool use. Loop will continue if there are multiple blocks.
                     // For simple chat, this returns the text.
                     if text.trim().len() > 0 {
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