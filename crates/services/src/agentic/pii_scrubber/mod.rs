// Path: crates/services/src/agentic/pii_scrubber/mod.rs

use anyhow::Result;
use ioi_api::vm::inference::{LocalSafetyModel, PiiRiskSurface};
use ioi_pii::{
    apply_transform, inspect_and_route_with_for_target, scrub_text, PiiRoutingOutcome,
    PostTransformReport, RiskSurface,
};
use ioi_types::app::agentic::{EvidenceGraph, PiiControls, PiiTarget};
use ioi_types::app::RedactionMap;
use std::sync::Arc;

/// The PII Scrubber acts as the "Airlock" for data leaving the Orchestrator.
/// It uses the local safety model to identify and redact sensitive information.
#[derive(Clone)]
pub struct PiiScrubber {
    /// The underlying safety model used for PII detection.
    pub model: Arc<dyn LocalSafetyModel>,
}

impl PiiScrubber {
    /// Creates a new `PiiScrubber` backed by the given safety model.
    pub fn new(model: Arc<dyn LocalSafetyModel>) -> Self {
        Self { model }
    }

    /// Scrubs PII and secrets from text using canonical shared redaction behavior.
    pub async fn scrub(&self, input: &str) -> Result<(String, RedactionMap)> {
        let detections = self.model.detect_pii(input).await?;
        scrub_text(input, &detections)
    }

    /// Applies a routed transform and returns a post-transform leak report.
    pub fn transform_with_report(
        &self,
        input: &str,
        evidence: &EvidenceGraph,
        outcome: &PiiRoutingOutcome,
    ) -> Result<(String, RedactionMap, PostTransformReport)> {
        apply_transform(input, evidence, outcome)
    }

    /// Canonical inspect->route->transform helper used by Stage D enforcement.
    pub async fn inspect_route_transform(
        &self,
        input: &str,
        target: &PiiTarget,
        risk_surface: RiskSurface,
        policy: &PiiControls,
        supports_transform: bool,
    ) -> Result<(
        String,
        RedactionMap,
        PostTransformReport,
        PiiRoutingOutcome,
        EvidenceGraph,
    )> {
        let model = Arc::clone(&self.model);
        let (evidence, routed) = inspect_and_route_with_for_target(
            move |text, shared_risk_surface| {
                let model = Arc::clone(&model);
                Box::pin(async move {
                    let api_risk_surface = match shared_risk_surface {
                        RiskSurface::LocalProcessing => PiiRiskSurface::LocalProcessing,
                        RiskSurface::Egress => PiiRiskSurface::Egress,
                    };
                    let inspection = model.inspect_pii(text, api_risk_surface).await?;
                    Ok(inspection.evidence)
                })
            },
            input,
            target,
            risk_surface,
            policy,
            supports_transform,
        )
        .await?;

        let (scrubbed, map, report) = apply_transform(input, &evidence, &routed)?;
        Ok((scrubbed, map, report, routed, evidence))
    }
}
