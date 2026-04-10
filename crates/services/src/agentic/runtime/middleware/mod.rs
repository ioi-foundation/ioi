use anyhow::Result;
use ioi_types::app::agentic::AgentTool;

mod builtins;
mod coercion;
mod envelope;
mod normalizer;

pub fn normalize_tool_call(raw_llm_output: &str) -> Result<AgentTool> {
    ToolNormalizer::normalize(raw_llm_output)
}

pub struct ToolNormalizer;

#[cfg(test)]
mod tests;
