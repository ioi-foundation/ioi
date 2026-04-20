use super::places_request_for_tool_widget;
use crate::models::StudioOutcomeRequest;
use ioi_types::app::studio::{
    StudioNormalizedRequestFrame, StudioOutcomeKind, StudioPlacesRequestFrame,
};
use ioi_types::app::StudioExecutionStrategy;

fn places_outcome_request(frame: Option<StudioPlacesRequestFrame>) -> StudioOutcomeRequest {
    StudioOutcomeRequest {
        request_id: "places-request".to_string(),
        raw_prompt: "Find coffee shops open now.".to_string(),
        active_artifact_id: None,
        outcome_kind: StudioOutcomeKind::ToolWidget,
        execution_strategy: StudioExecutionStrategy::PlanExecute,
        execution_mode_decision: None,
        confidence: 0.92,
        needs_clarification: false,
        clarification_questions: Vec::new(),
        routing_hints: vec!["tool_widget:places".to_string()],
        lane_frame: None,
        request_frame: frame.map(StudioNormalizedRequestFrame::Places),
        source_selection: None,
        retained_lane_state: None,
        lane_transitions: Vec::new(),
        orchestration_state: None,
        artifact: None,
    }
}

#[test]
fn places_request_for_tool_widget_prefers_request_frame_state() {
    let outcome_request = places_outcome_request(Some(StudioPlacesRequestFrame {
        search_anchor: None,
        category: Some("coffee shops".to_string()),
        location_scope: Some("Williamsburg, Brooklyn".to_string()),
        missing_slots: Vec::new(),
        clarification_required_slots: Vec::new(),
    }));

    let parsed = places_request_for_tool_widget("Near Williamsburg, Brooklyn.", &outcome_request)
        .expect("retained places request");

    assert_eq!(parsed.category.label, "coffee shops");
    assert_eq!(parsed.category.amenity, "cafe");
    assert_eq!(parsed.anchor_phrase, "Williamsburg, Brooklyn");
}
