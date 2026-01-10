// Path: crates/services/src/agentic/scrub_adapter.rs

use anyhow::Result;
use async_trait::async_trait;
use ioi_api::vm::inference::InferenceRuntime;
// [FIX] Import trait/enums from API now
use ioi_api::vm::inference::{LocalSafetyModel, SafetyVerdict};
use std::sync::Arc;

/// Adapter to allow using an InferenceRuntime as a LocalSafetyModel for scrubbing.
pub struct RuntimeAsSafetyModel {
    runtime: Arc<dyn InferenceRuntime>,
}

impl RuntimeAsSafetyModel {
    pub fn new(runtime: Arc<dyn InferenceRuntime>) -> Self {
        Self { runtime }
    }
}

#[async_trait]
impl LocalSafetyModel for RuntimeAsSafetyModel {
    async fn classify_intent(&self, _input: &str) -> Result<SafetyVerdict> {
        Ok(SafetyVerdict::Safe)
    }

    async fn detect_pii(&self, input: &str) -> Result<Vec<(usize, usize, String)>> {
        let mut findings = Vec::new();
        let key_pattern = "sk_live_";
        for (i, _) in input.match_indices(key_pattern) {
            let end = (i + 32).min(input.len());
            findings.push((i, end, "API_KEY".to_string()));
        }
        Ok(findings)
    }
}