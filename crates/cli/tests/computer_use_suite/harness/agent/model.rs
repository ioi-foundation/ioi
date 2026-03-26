use anyhow::{anyhow, Context, Result};
use reqwest::Client;
use serde_json::{json, Value};

use crate::computer_use_suite::live_inference_support::{
    configured_model_candidates, select_http_inference_model, InferenceCallRecord,
    OPENAI_CHAT_COMPLETIONS_URL,
};

use super::super::support::now_ms;

#[derive(Clone)]
pub(super) struct AgentModelClient {
    http: Client,
    api_url: String,
    api_key: String,
    model: String,
}

pub(super) struct ModelDecision {
    pub call_record: InferenceCallRecord,
    pub tool_name: String,
    pub arguments: Value,
}

impl AgentModelClient {
    pub(super) async fn from_env() -> Result<Self> {
        let api_key = std::env::var("OPENAI_API_KEY")
            .context("OPENAI_API_KEY is required for live MiniWoB harness runs")?;
        let api_url = std::env::var("OPENAI_API_URL")
            .unwrap_or_else(|_| OPENAI_CHAT_COMPLETIONS_URL.to_string());
        let candidates =
            configured_model_candidates("COMPUTER_USE_SUITE_AGENT_MODELS", "OPENAI_MODEL");
        let model = select_http_inference_model(
            &api_url,
            &api_key,
            &candidates,
            "COMPUTER_USE_SUITE_INFERENCE_MODEL_SELECTED",
        )
        .await?;
        let http = Client::builder()
            .timeout(std::time::Duration::from_secs(60))
            .build()
            .context("build OpenAI chat client")?;
        Ok(Self {
            http,
            api_url,
            api_key,
            model,
        })
    }

    pub(super) fn model(&self) -> &str {
        &self.model
    }

    pub(super) fn api_url(&self) -> &str {
        &self.api_url
    }

    fn parse_response_tool(message: &Value) -> Result<(String, Value)> {
        if let Some(tool_call) = message
            .get("tool_calls")
            .and_then(Value::as_array)
            .and_then(|calls| calls.first())
        {
            let function = tool_call
                .get("function")
                .ok_or_else(|| anyhow!("tool call missing function payload"))?;
            let tool_name = function
                .get("name")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("tool call missing function name"))?
                .to_string();
            let raw_arguments = function
                .get("arguments")
                .and_then(Value::as_str)
                .unwrap_or("{}");
            let arguments =
                serde_json::from_str::<Value>(raw_arguments).unwrap_or_else(|_| json!({}));
            return Ok((tool_name, arguments));
        }

        let raw_content = message
            .get("content")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("chat completion returned no tool call or content"))?;
        let parsed =
            serde_json::from_str::<Value>(raw_content).context("parse fallback JSON tool call")?;
        let tool_name = parsed
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("fallback tool call missing name"))?
            .to_string();
        let arguments = parsed
            .get("arguments")
            .cloned()
            .unwrap_or_else(|| json!({}));
        Ok((tool_name, arguments))
    }

    pub(super) async fn choose_tool(
        &self,
        ordinal: usize,
        system_prompt: &str,
        user_prompt: &str,
        tools: &[Value],
    ) -> Result<ModelDecision> {
        let messages = json!([
            { "role": "system", "content": system_prompt },
            { "role": "user", "content": user_prompt }
        ]);
        let request_body = json!({
            "model": self.model,
            "messages": messages,
            "tools": tools,
            "tool_choice": "required",
            "parallel_tool_calls": false,
            "temperature": 0,
        });
        let input_utf8 = serde_json::to_string(&messages).ok();
        let started_at_ms = now_ms();
        let response = self
            .http
            .post(&self.api_url)
            .bearer_auth(&self.api_key)
            .json(&request_body)
            .send()
            .await
            .context("send chat completion request")?;
        let finished_at_ms = now_ms();
        let elapsed_ms = finished_at_ms.saturating_sub(started_at_ms);
        let response = response
            .error_for_status()
            .context("chat completion status")?;
        let payload = response
            .json::<Value>()
            .await
            .context("chat completion json")?;
        let message = payload
            .get("choices")
            .and_then(Value::as_array)
            .and_then(|choices| choices.first())
            .and_then(|choice| choice.get("message"))
            .ok_or_else(|| anyhow!("chat completion choices missing message"))?;
        let (tool_name, arguments) = Self::parse_response_tool(message)?;
        let output_value = json!({
            "name": tool_name,
            "arguments": arguments,
        });
        let output_utf8 = serde_json::to_string(&output_value).ok();
        Ok(ModelDecision {
            call_record: InferenceCallRecord {
                ordinal,
                method: "chat_completions_tool_call",
                source_hint: Some("computer_use_suite.harness.agent".to_string()),
                model_hash_hex: "0000000000000000000000000000000000000000000000000000000000000000"
                    .to_string(),
                started_at_ms,
                finished_at_ms,
                elapsed_ms,
                input_utf8,
                output_utf8,
                error: None,
            },
            tool_name: output_value
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            arguments: output_value
                .get("arguments")
                .cloned()
                .unwrap_or_else(|| json!({})),
        })
    }
}
