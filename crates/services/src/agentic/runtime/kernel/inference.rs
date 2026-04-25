use ioi_crypto::algorithms::hash::sha256;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ModelRuntimeErrorClass {
    ProviderUnavailable,
    RateLimited,
    Timeout,
    ContextOverflow,
    MalformedStructuredOutput,
    ToolCallInvalid,
    SafetyRefusal,
    PolicyRefusal,
    StreamingStall,
    BudgetExceeded,
    UnknownProviderError,
}

impl ModelRuntimeErrorClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ProviderUnavailable => "ProviderUnavailable",
            Self::RateLimited => "RateLimited",
            Self::Timeout => "Timeout",
            Self::ContextOverflow => "ContextOverflow",
            Self::MalformedStructuredOutput => "MalformedStructuredOutput",
            Self::ToolCallInvalid => "ToolCallInvalid",
            Self::SafetyRefusal => "SafetyRefusal",
            Self::PolicyRefusal => "PolicyRefusal",
            Self::StreamingStall => "StreamingStall",
            Self::BudgetExceeded => "BudgetExceeded",
            Self::UnknownProviderError => "UnknownProviderError",
        }
    }
}

impl std::fmt::Display for ModelRuntimeErrorClass {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelInvocationReceipt {
    pub model_id: String,
    pub provider: String,
    pub latency_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt_tokens: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completion_tokens: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_tokens: Option<u32>,
    pub streaming: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub structured_output_schema_hash: Option<[u8; 32]>,
    pub output_hash: [u8; 32],
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_class: Option<ModelRuntimeErrorClass>,
}

impl ModelInvocationReceipt {
    pub fn from_output(
        model_id: impl Into<String>,
        provider: impl Into<String>,
        latency_ms: u64,
        streaming: bool,
        output: &[u8],
    ) -> Result<Self, String> {
        Ok(Self {
            model_id: model_id.into(),
            provider: provider.into(),
            latency_ms,
            prompt_tokens: None,
            completion_tokens: None,
            total_tokens: None,
            streaming,
            structured_output_schema_hash: None,
            output_hash: sha256(output).map_err(|error| error.to_string())?,
            error_class: None,
        })
    }
}
