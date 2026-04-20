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
