// Path: crates/validator/src/firewall/inference.rs

use anyhow::Result;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Represents the output of a safety check by the local BitNet engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SafetyVerdict {
    /// The content is safe to proceed.
    Safe,
    /// The content violates safety guidelines (e.g., jailbreak attempt, malicious intent).
    Unsafe(String),
    /// The content contains PII that must be scrubbed.
    ContainsPII,
}

/// Abstract interface for the local CPU-based inference engine (BitNet b1.58).
/// This engine is optimized for low-latency classification and scrubbing, not deep reasoning.
#[async_trait::async_trait]
pub trait LocalSafetyModel: Send + Sync {
    /// Classifies the intent of a prompt or action payload.
    async fn classify_intent(&self, input: &str) -> Result<SafetyVerdict>;

    /// Identifies spans of text that contain PII or secrets.
    /// Returns a list of (start_index, end_index, category).
    async fn detect_pii(&self, input: &str) -> Result<Vec<(usize, usize, String)>>;
}

/// A mock implementation of BitNet for testing/dev environments.
/// It uses simple heuristics (regex/keywords) to simulate the 1.58-bit model behavior.
pub struct MockBitNet;

#[async_trait::async_trait]
impl LocalSafetyModel for MockBitNet {
    async fn classify_intent(&self, input: &str) -> Result<SafetyVerdict> {
        let lower = input.to_lowercase();
        if lower.contains("malicious") || lower.contains("bypass") {
            return Ok(SafetyVerdict::Unsafe("Malicious keyword detected".into()));
        }
        if lower.contains("secret") || lower.contains("key") || lower.contains("password") {
            return Ok(SafetyVerdict::ContainsPII);
        }
        Ok(SafetyVerdict::Safe)
    }

    async fn detect_pii(&self, input: &str) -> Result<Vec<(usize, usize, String)>> {
        let mut findings = Vec::new();
        
        // Mock detection of "sk_live_..." keys
        let key_pattern = "sk_live_";
        for (i, _) in input.match_indices(key_pattern) {
            // Assume 32 char key len for mock
            let end = (i + 32).min(input.len());
            findings.push((i, end, "API_KEY".to_string()));
        }

        // Mock detection of email-like symbols
        if let Some(idx) = input.find('@') {
             // Crude mock: mask 5 chars around @
             let start = idx.saturating_sub(5);
             let end = (idx + 5).min(input.len());
             findings.push((start, end, "EMAIL".to_string()));
        }

        Ok(findings)
    }
}