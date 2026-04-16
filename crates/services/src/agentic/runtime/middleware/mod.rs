use anyhow::Result;
use ioi_types::app::agentic::AgentTool;

mod builtins;
mod coercion;
mod envelope;
mod normalizer;

pub fn normalize_tool_call(raw_llm_output: &str) -> Result<AgentTool> {
    ToolNormalizer::normalize(raw_llm_output)
}

pub fn normalize_tool_call_with_observation(
    raw_llm_output: &str,
) -> Result<ToolNormalizationResult> {
    ToolNormalizer::normalize_with_observation(raw_llm_output)
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ToolNormalizationObservation {
    pub raw_name: Option<String>,
    pub normalized_name: Option<String>,
    pub labels: Vec<String>,
}

impl ToolNormalizationObservation {
    pub fn changed(&self) -> bool {
        !self.labels.is_empty()
            || match (&self.raw_name, &self.normalized_name) {
                (Some(raw), Some(normalized)) => raw != normalized,
                _ => false,
            }
    }

    fn push_label(&mut self, label: impl Into<String>) {
        let label = label.into();
        if self.labels.iter().any(|existing| existing == &label) {
            return;
        }
        self.labels.push(label);
    }
}

#[derive(Debug, Clone)]
pub struct ToolNormalizationResult {
    pub tool: AgentTool,
    pub observation: ToolNormalizationObservation,
}

pub struct ToolNormalizer;

#[cfg(test)]
mod tests;
