// Path: crates/validator/src/firewall/inference.rs

use anyhow::Result;
// [FIX] Import trait and enum from API
use async_trait::async_trait;
use dcrypt::algorithms::hash::{HashFunction, Sha256};
use ioi_api::vm::inference::{LocalSafetyModel, PiiInspection, PiiRiskSurface, SafetyVerdict};
use ioi_types::app::agentic::{
    EvidenceGraph, EvidenceSpan, PiiClass, PiiConfidenceBucket, PiiSeverity,
};

/// A mock implementation of BitNet for testing/dev environments.
/// It uses simple heuristics (regex/keywords) to simulate the 1.58-bit model behavior.
pub struct MockBitNet;

#[async_trait]
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

    async fn inspect_pii(
        &self,
        input: &str,
        risk_surface: PiiRiskSurface,
    ) -> Result<PiiInspection> {
        let detections = self.detect_pii(input).await?;
        let spans = detections
            .iter()
            .map(|(start, end, category)| {
                let pii_class = match category.as_str() {
                    "API_KEY" => PiiClass::ApiKey,
                    "EMAIL" => PiiClass::Email,
                    other => PiiClass::Custom(other.to_ascii_lowercase()),
                };
                EvidenceSpan {
                    start_index: *start as u32,
                    end_index: *end as u32,
                    pii_class: pii_class.clone(),
                    severity: match pii_class {
                        PiiClass::ApiKey => PiiSeverity::High,
                        PiiClass::Email => PiiSeverity::Low,
                        _ => PiiSeverity::Medium,
                    },
                    confidence_bucket: PiiConfidenceBucket::Low,
                    pattern_id: format!("mock::{}", category.to_ascii_lowercase()),
                    validator_passed: false,
                    context_keywords: Vec::new(),
                    evidence_source: "mock_detect_pii".to_string(),
                }
            })
            .collect::<Vec<_>>();

        let ambiguous = !spans.is_empty();
        let mut source_hash = [0u8; 32];
        if let Ok(digest) = Sha256::digest(input.as_bytes()) {
            source_hash.copy_from_slice(digest.as_ref());
        }

        Ok(PiiInspection {
            evidence: EvidenceGraph {
                version: 1,
                source_hash,
                spans,
                ambiguous,
            },
            ambiguous,
            stage2_status: if matches!(risk_surface, PiiRiskSurface::Egress) && ambiguous {
                Some("legacy_mock_ambiguous".to_string())
            } else {
                None
            },
        })
    }
}
