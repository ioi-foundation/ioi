// Path: crates/api/src/vm/inference/http_adapter.rs

use async_trait::async_trait;
use ioi_types::app::agentic::InferenceOptions;
use ioi_types::error::VmError;
use reqwest::{Client, RequestBuilder};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::time::Duration;
use tokio::sync::mpsc::Sender;
use std::path::Path;
use super::InferenceRuntime;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};

// --- Strategy Trait ---

#[async_trait]
pub trait ProviderStrategy: Send + Sync {
    /// Builds the HTTP request for the specific provider.
    fn build_request(
        &self, 
        client: &Client, 
        api_url: &str, 
        api_key: &str, 
        model_name: &str, 
        input_context: &[u8], 
        options: &InferenceOptions,
        stream: bool
    ) -> Result<RequestBuilder, VmError>;

    /// Parses the raw response bytes into the standard IOI Kernel output format.
    /// (UTF-8 string or JSON tool call).
    async fn parse_response(&self, response: reqwest::Response) -> Result<Vec<u8>, VmError>;

    /// Parses a streaming chunk.
    async fn parse_stream_chunk(&self, chunk: &[u8]) -> Result<Option<String>, VmError>;
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
        stream: bool
    ) -> Result<RequestBuilder, VmError> {
        
        let json_input: Value = serde_json::from_slice(input_context)
            .or_else(|_| {
                let text = String::from_utf8_lossy(input_context).to_string();
                Ok::<_, VmError>(json!([{"role": "user", "content": text}]))
            })?;

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

        // Use options.max_tokens if set (non-zero), otherwise fallback to 4096
        let max_tokens = if options.max_tokens > 0 { options.max_tokens } else { 4096 };

        let body = AnthropicRequest {
            model: model_name.into(),
            messages,
            max_tokens,
            tools,
            stream,
            temperature: options.temperature,
        };

        let mut builder = client.post(api_url)
            .header("x-api-key", api_key)
            .header("anthropic-version", "2023-06-01")
            .json(&body);

        if model_name.contains("claude-3-5-sonnet") {
            builder = builder.header("anthropic-beta", &self.beta_header);
        }

        Ok(builder)
    }

    async fn parse_response(&self, response: reqwest::Response) -> Result<Vec<u8>, VmError> {
        let text = response.text().await.map_err(|e| VmError::HostError(e.to_string()))?;
        let resp: AnthropicResponse = serde_json::from_str(&text)
            .map_err(|e| VmError::HostError(format!("Anthropic parse error: {} | Raw: {}", e, text)))?;

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

// --- Main Runtime Implementation ---

pub struct HttpInferenceRuntime {
    client: Client,
    api_url: String,
    api_key: String,
    model_name: String,
    strategy: Box<dyn ProviderStrategy>,
}

impl HttpInferenceRuntime {
    pub fn new(api_url: String, api_key: String, model_name: String) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(60))
            .build()
            .expect("Failed to build HTTP client");

        let strategy: Box<dyn ProviderStrategy> = if model_name.to_lowercase().contains("claude") {
            let beta = std::env::var("ANTHROPIC_BETA_HEADER")
                .unwrap_or_else(|_| "computer-use-2024-10-22".to_string());
            Box::new(AnthropicStrategy { beta_header: beta })
        } else {
            Box::new(OpenAiStrategy)
        };

        Self {
            client,
            api_url,
            api_key,
            model_name,
            strategy,
        }
    }
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
        _token_stream: Option<Sender<String>>,
    ) -> Result<Vec<u8>, VmError> {
        let request = self.strategy.build_request(
            &self.client, 
            &self.api_url, 
            &self.api_key, 
            &self.model_name, 
            input_context, 
            &options, 
            false // No streaming for now
        )?;

        let response = request.send().await
            .map_err(|e| VmError::HostError(format!("Network Error: {}", e)))?;

        if !response.status().is_success() {
             let status = response.status();
             let body = response.text().await.unwrap_or_default();
             log::error!("Provider Error {}: {}", status, body);
             return Err(VmError::HostError(format!("Provider Error {}: {}", status, body)));
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

        // [FIX] OpenAI Embedding logic (Default)
        // Ideally this should also be strategy-based if Anthropic adds embeddings.
        let embedding_url = "https://api.openai.com/v1/embeddings";
        let model = "text-embedding-3-small";
        
        // If the user configured a custom URL for chat (e.g. local), try to infer embedding URL
        // or fallback to OpenAI if the provider is openai.
        let target_url = if self.api_url.contains("openai.com") {
             embedding_url.to_string()
        } else if self.api_url.contains("/v1") {
             self.api_url.replace("/chat/completions", "/embeddings")
        } else {
             return Err(VmError::HostError("Cannot determine embedding URL".into()));
        };

        let body = json!({
            "input": text,
            "model": model
        });

        let resp = self.client.post(&target_url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .json(&body)
            .send()
            .await
            .map_err(|e| VmError::HostError(format!("Embedding req failed: {}", e)))?;
            
        let data: EmbeddingResponse = resp.json().await
            .map_err(|e| VmError::HostError(format!("Embedding parse failed: {}", e)))?;
            
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
        
        let input_bytes = serde_json::to_vec(&prompt).map_err(|e| VmError::Initialization(e.to_string()))?; // [FIX] Use Initialization variant
        
        let caption_bytes = self.execute_inference(model_hash, &input_bytes, options).await?;
        let caption = String::from_utf8_lossy(&caption_bytes).to_string();
        
        // 2. Embed the caption
        self.embed_text(&caption).await
    }
    
    async fn load_model(&self, _hash: [u8; 32], _path: &Path) -> Result<(), VmError> { Ok(()) }
    async fn unload_model(&self, _hash: [u8; 32]) -> Result<(), VmError> { Ok(()) }
}