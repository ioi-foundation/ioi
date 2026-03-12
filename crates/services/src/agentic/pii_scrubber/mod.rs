// Path: crates/services/src/agentic/pii_scrubber/mod.rs

use anyhow::Result;
use ioi_api::vm::inference::{LocalSafetyModel, PiiRiskSurface};
use ioi_pii::{
    apply_transform, inspect_and_route_with_for_target, scrub_text, PiiRoutingOutcome,
    PostTransformReport, RiskSurface,
};
use ioi_types::app::agentic::{EvidenceGraph, PiiControls, PiiEgressField, PiiTarget};
use ioi_types::app::RedactionMap;
use std::sync::Arc;
use url::Url;

fn field_uses_structured_url_inspection(field: PiiEgressField) -> bool {
    matches!(
        field,
        PiiEgressField::BrowserNavigateUrl
            | PiiEgressField::WebSearchUrl
            | PiiEgressField::WebReadUrl
            | PiiEgressField::MediaExtractTranscriptUrl
            | PiiEgressField::MediaExtractMultimodalEvidenceUrl
            | PiiEgressField::NetFetchUrl
            | PiiEgressField::CommerceMerchantUrl
    )
}

fn parse_url_for_pii_inspection(input: &str) -> Option<Url> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return None;
    }

    Url::parse(trimmed)
        .or_else(|_| Url::parse(&format!("https://{}", trimmed)))
        .ok()
}

pub(crate) fn pii_inspection_input_for_egress_field(field: PiiEgressField, input: &str) -> String {
    if !field_uses_structured_url_inspection(field) {
        return input.to_string();
    }

    let Some(parsed) = parse_url_for_pii_inspection(input) else {
        return input.to_string();
    };

    let mut lines = Vec::new();
    lines.push(format!("scheme:{}", parsed.scheme()));

    if !parsed.username().is_empty() {
        lines.push(format!("userinfo_username:{}", parsed.username()));
    }
    if let Some(password) = parsed.password().filter(|value| !value.is_empty()) {
        lines.push(format!("userinfo_password:{}", password));
    }
    if let Some(host) = parsed.host_str().filter(|value| !value.is_empty()) {
        lines.push(format!("host:{}", host.to_ascii_lowercase()));
    }
    if let Some(port) = parsed.port() {
        lines.push(format!("port:{}", port));
    }

    for segment in parsed.path().split('/') {
        let trimmed = segment.trim();
        if !trimmed.is_empty() {
            lines.push(format!("path_segment:{}", trimmed));
        }
    }

    if let Some(query) = parsed.query() {
        for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
            let key = key.trim();
            let value = value.trim();
            if !key.is_empty() {
                lines.push(format!("query_key:{}", key));
            }
            if !value.is_empty() {
                lines.push(format!("query_value:{}", value));
            }
        }
    }

    if let Some(fragment) = parsed
        .fragment()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        lines.push(format!("fragment:{}", fragment));
    }

    if lines.is_empty() {
        input.to_string()
    } else {
        lines.join("\n")
    }
}

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

    async fn inspect_route_with_input(
        &self,
        inspection_input: &str,
        target: &PiiTarget,
        risk_surface: RiskSurface,
        policy: &PiiControls,
        supports_transform: bool,
    ) -> Result<(EvidenceGraph, PiiRoutingOutcome)> {
        let model = Arc::clone(&self.model);
        inspect_and_route_with_for_target(
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
            inspection_input,
            target,
            risk_surface,
            policy,
            supports_transform,
        )
        .await
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
        let (evidence, routed) = self
            .inspect_route_with_input(input, target, risk_surface, policy, supports_transform)
            .await?;
        let (scrubbed, map, report) = apply_transform(input, &evidence, &routed)?;
        Ok((scrubbed, map, report, routed, evidence))
    }

    /// Field-aware inspect->route->transform helper that canonicalizes URL inputs before
    /// inspection so raw URL formatting does not create spurious PII detections.
    pub async fn inspect_route_transform_for_egress_field(
        &self,
        input: &str,
        field: PiiEgressField,
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
        let inspection_input = pii_inspection_input_for_egress_field(field, input);
        let (evidence, routed) = self
            .inspect_route_with_input(
                &inspection_input,
                target,
                risk_surface,
                policy,
                supports_transform,
            )
            .await?;

        let uses_projection = inspection_input != input;
        let (scrubbed, map, report) = if uses_projection {
            (
                input.to_string(),
                RedactionMap {
                    entries: Vec::new(),
                },
                PostTransformReport {
                    transformed: false,
                    unresolved_spans: 0,
                    remaining_span_count: 0,
                    no_raw_substring_leak: true,
                },
            )
        } else {
            apply_transform(input, &evidence, &routed)?
        };

        Ok((scrubbed, map, report, routed, evidence))
    }
}

#[cfg(test)]
mod tests {
    use super::{pii_inspection_input_for_egress_field, PiiScrubber};
    use anyhow::Result;
    use async_trait::async_trait;
    use ioi_api::vm::inference::{LocalSafetyModel, PiiInspection, PiiRiskSurface, SafetyVerdict};
    use ioi_pii::RiskSurface;
    use ioi_types::app::agentic::{
        EvidenceGraph, EvidenceSpan, FirewallDecision, PiiClass, PiiConfidenceBucket, PiiControls,
        PiiEgressField, PiiSeverity, PiiTarget,
    };
    use ioi_types::app::ActionTarget;
    use std::sync::Arc;

    const NIST_STANDARDS_URL: &str = "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards";

    struct RawUrlFalsePositiveSafety;

    #[async_trait]
    impl LocalSafetyModel for RawUrlFalsePositiveSafety {
        async fn classify_intent(&self, _input: &str) -> anyhow::Result<SafetyVerdict> {
            Ok(SafetyVerdict::Safe)
        }

        async fn detect_pii(&self, _input: &str) -> anyhow::Result<Vec<(usize, usize, String)>> {
            Ok(Vec::new())
        }

        async fn inspect_pii(
            &self,
            input: &str,
            _risk_surface: PiiRiskSurface,
        ) -> anyhow::Result<PiiInspection> {
            let evidence = if input == NIST_STANDARDS_URL {
                EvidenceGraph {
                    version: 1,
                    source_hash: [7u8; 32],
                    ambiguous: false,
                    spans: vec![EvidenceSpan {
                        start_index: 0,
                        end_index: 10,
                        pii_class: PiiClass::Phone,
                        severity: PiiSeverity::Low,
                        confidence_bucket: PiiConfidenceBucket::Medium,
                        pattern_id: "phone/test-url-false-positive".to_string(),
                        validator_passed: true,
                        context_keywords: Vec::new(),
                        evidence_source: "test".to_string(),
                    }],
                }
            } else {
                EvidenceGraph::default()
            };

            Ok(PiiInspection {
                evidence,
                ambiguous: false,
                stage2_status: None,
            })
        }
    }

    #[test]
    fn structured_url_projection_splits_segments_and_query_values() {
        let projection = pii_inspection_input_for_egress_field(
            PiiEgressField::WebReadUrl,
            "https://example.com/contact/415-555-1234?email=john%40example.com",
        );
        assert!(projection.contains("host:example.com"));
        assert!(projection.contains("path_segment:contact"));
        assert!(projection.contains("path_segment:415-555-1234"));
        assert!(projection.contains("query_key:email"));
        assert!(projection.contains("query_value:john@example.com"));
        assert!(!projection.contains("https://example.com/contact/415-555-1234"));
    }

    #[tokio::test]
    async fn url_like_egress_fields_use_structured_projection_for_inspection() -> Result<()> {
        let scrubber = PiiScrubber::new(Arc::new(RawUrlFalsePositiveSafety));
        let (_scrubbed, _map, _report, routed, evidence) = scrubber
            .inspect_route_transform_for_egress_field(
                NIST_STANDARDS_URL,
                PiiEgressField::WebReadUrl,
                &PiiTarget::Action(ActionTarget::WebRetrieve),
                RiskSurface::Egress,
                &PiiControls::default(),
                false,
            )
            .await?;

        assert!(evidence.spans.is_empty());
        assert!(matches!(routed.decision, FirewallDecision::Allow));
        Ok(())
    }
}
