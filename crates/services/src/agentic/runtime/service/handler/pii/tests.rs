use super::{browser_url_uses_local_processing, pii_risk_surface_for_spec, to_shared_risk_surface};
use ioi_pii::RiskSurface;
use ioi_types::app::agentic::{
    AgentTool, PiiEgressField, PiiEgressRiskSurface, PiiEgressSpec, PiiTarget,
};
use ioi_types::app::ActionTarget;

fn browser_interact_spec(field: PiiEgressField, supports_transform: bool) -> PiiEgressSpec {
    PiiEgressSpec {
        field,
        target: PiiTarget::Action(ActionTarget::BrowserInteract),
        supports_transform,
        risk_surface: PiiEgressRiskSurface::Egress,
    }
}

#[test]
fn browser_local_processing_detection_covers_loopback_and_local_schemes() {
    assert!(browser_url_uses_local_processing(
        "http://127.0.0.1:8000/login"
    ));
    assert!(browser_url_uses_local_processing(
        "http://localhost:3000/queue"
    ));
    assert!(browser_url_uses_local_processing(
        "https://bench.localhost/workflow"
    ));
    assert!(browser_url_uses_local_processing(
        "file:///tmp/miniwob.html"
    ));
    assert!(browser_url_uses_local_processing("about:blank"));
    assert!(browser_url_uses_local_processing(
        "data:text/html,<p>fixture</p>"
    ));
    assert!(!browser_url_uses_local_processing(
        "https://example.com/login"
    ));
}

#[test]
fn browser_navigate_uses_destination_url_for_local_processing_routing() {
    let tool = AgentTool::BrowserNavigate {
        url: "http://127.0.0.1:4123/workflow/login".to_string(),
    };
    let spec = browser_interact_spec(PiiEgressField::BrowserNavigateUrl, false);

    assert!(matches!(
        pii_risk_surface_for_spec(&tool, &spec, None),
        RiskSurface::LocalProcessing
    ));
}

#[test]
fn browser_type_uses_active_page_context_for_local_processing_routing() {
    let tool = AgentTool::BrowserType {
        text: "secret".to_string(),
        selector: Some("#password".to_string()),
    };
    let spec = browser_interact_spec(PiiEgressField::BrowserTypeText, true);

    assert!(matches!(
        pii_risk_surface_for_spec(&tool, &spec, Some("file:///tmp/workflow.html")),
        RiskSurface::LocalProcessing
    ));
    assert!(matches!(
        pii_risk_surface_for_spec(&tool, &spec, Some("https://example.com/login")),
        RiskSurface::Egress
    ));
    assert_eq!(
        pii_risk_surface_for_spec(&tool, &spec, None),
        to_shared_risk_surface(PiiEgressRiskSurface::Egress)
    );
}
