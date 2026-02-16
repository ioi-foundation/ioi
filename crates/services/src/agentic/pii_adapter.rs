// Path: crates/services/src/agentic/pii_adapter.rs

use anyhow::Result;
use async_trait::async_trait;
use ioi_api::vm::inference::InferenceRuntime;
use ioi_api::vm::inference::{LocalSafetyModel, PiiInspection, PiiRiskSurface, SafetyVerdict};
use std::sync::Arc;

use crate::agentic::pii_substrate;

/// Adapter to allow using an InferenceRuntime as a LocalSafetyModel for PII inspection.
pub struct RuntimeAsPiiModel {
    _runtime: Arc<dyn InferenceRuntime>,
}

impl RuntimeAsPiiModel {
    pub fn new(runtime: Arc<dyn InferenceRuntime>) -> Self {
        Self { _runtime: runtime }
    }
}

#[async_trait]
impl LocalSafetyModel for RuntimeAsPiiModel {
    async fn classify_intent(&self, input: &str) -> Result<SafetyVerdict> {
        // Deterministic local intent heuristics (never forward raw text to runtime backends).
        let lower = input.to_ascii_lowercase();
        let malicious_markers = [
            "bypass",
            "jailbreak",
            "exfiltrate",
            "steal credentials",
            "rm -rf /",
            "destroy system",
            "disable firewall",
        ];
        if let Some(marker) = malicious_markers.iter().find(|m| lower.contains(**m)) {
            return Ok(SafetyVerdict::Unsafe(format!(
                "Unsafe intent marker detected: {}",
                marker
            )));
        }
        Ok(SafetyVerdict::Safe)
    }

    async fn detect_pii(&self, input: &str) -> Result<Vec<(usize, usize, String)>> {
        let graph = pii_substrate::build_evidence_graph(input)?;
        Ok(pii_substrate::to_legacy_detections(&graph))
    }

    async fn inspect_pii(
        &self,
        input: &str,
        risk_surface: PiiRiskSurface,
    ) -> Result<PiiInspection> {
        let graph = pii_substrate::build_evidence_graph(input)?;
        let should_escalate = matches!(risk_surface, PiiRiskSurface::Egress)
            && (graph.ambiguous || pii_substrate::has_high_severity(&graph));

        Ok(PiiInspection {
            ambiguous: graph.ambiguous,
            evidence: graph,
            stage2_status: if should_escalate {
                Some("require_review".to_string())
            } else {
                None
            },
        })
    }
}
