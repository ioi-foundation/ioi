// Path: crates/cli/tests/agent_scrub_e2e.rs
#![cfg(all(feature = "consensus-admft", feature = "vm-wasm"))]

use anyhow::Result;
use async_trait::async_trait;
use ioi_api::vm::inference::{InferenceRuntime, LocalSafetyModel, PiiRiskSurface};
use ioi_pii::RiskSurface;
use ioi_services::agentic::pii_adapter::RuntimeAsPiiModel;
use ioi_services::agentic::pii_scrubber::PiiScrubber;
use ioi_types::app::agentic::{FirewallDecision, InferenceOptions, PiiControls, PiiTarget};
use ioi_types::app::ActionTarget;
use ioi_types::error::VmError;
use std::path::Path;
use std::sync::Arc;

struct NoopRuntime;

#[async_trait]
impl InferenceRuntime for NoopRuntime {
    async fn execute_inference(
        &self,
        _: [u8; 32],
        _: &[u8],
        _: InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        Ok(br#"{"safe":true}"#.to_vec())
    }

    async fn load_model(&self, _: [u8; 32], _: &Path) -> Result<(), VmError> {
        Ok(())
    }

    async fn unload_model(&self, _: [u8; 32]) -> Result<(), VmError> {
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_agent_pii_pipeline_transforms_before_egress() -> Result<()> {
    let runtime = Arc::new(NoopRuntime);
    let model = Arc::new(RuntimeAsPiiModel::new(runtime));
    let scrubber = PiiScrubber::new(model.clone());

    let input = "copy sk_live_abcd1234abcd1234 and john@example.com";
    let target = PiiTarget::Action(ActionTarget::ClipboardWrite);

    let inspection = model.inspect_pii(input, PiiRiskSurface::Egress).await?;
    assert!(
        !inspection.evidence.spans.is_empty(),
        "expected deterministic evidence for PII/secret payload"
    );

    let (scrubbed, _map, report, routed, evidence) = scrubber
        .inspect_route_transform(
            input,
            &target,
            RiskSurface::Egress,
            &PiiControls::default(),
            true,
        )
        .await?;

    assert_eq!(evidence, inspection.evidence);
    assert!(report.no_raw_substring_leak);
    assert!(matches!(
        routed.decision,
        FirewallDecision::RedactThenAllow | FirewallDecision::TokenizeThenAllow
    ));

    let direct = ioi_pii::route_pii_decision_for_target(
        &inspection.evidence,
        &PiiControls::default(),
        RiskSurface::Egress,
        &target,
        true,
    );
    assert!(matches!(
        direct.decision,
        FirewallDecision::RedactThenAllow | FirewallDecision::TokenizeThenAllow
    ));
    assert!(!scrubbed.contains("sk_live_abcd1234abcd1234"));
    assert!(!scrubbed.contains("john@example.com"));
    assert!(scrubbed.contains("<REDACTED:api_key>"));
    assert!(scrubbed.contains("<REDACTED:email>"));

    Ok(())
}
