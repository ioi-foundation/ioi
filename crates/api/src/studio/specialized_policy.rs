use ioi_types::app::{
    StudioFallbackMode, StudioNormalizedRequestFrame, StudioRendererKind, StudioRiskSensitivity,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StudioSpecializedDomainKind {
    Weather,
    Sports,
    Places,
    Recipe,
    MessageCompose,
    UserInput,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StudioSpecializedDomainPolicySpec {
    pub domain_id: &'static str,
    pub clarification_rationale: &'static str,
    pub fallback_mode: StudioFallbackMode,
    pub fallback_rationale: &'static str,
    pub presentation_surface: &'static str,
    pub widget_family: Option<&'static str>,
    pub renderer: Option<StudioRendererKind>,
    pub tab_priority: &'static [&'static str],
    pub presentation_rationale: &'static str,
    pub output_shape: &'static str,
    pub ordered_steps: &'static [&'static str],
    pub transformation_rationale: &'static str,
    pub sensitivity: StudioRiskSensitivity,
    pub base_risk_reasons: &'static [&'static str],
    pub user_visible_guardrails: &'static [&'static str],
    pub verification_strategy: &'static str,
    pub verification_required_checks: &'static [&'static str],
    pub selected_source_rationale: &'static str,
    pub fallback_source_rationale: &'static str,
    pub missing_slot_fallback_reason: &'static str,
}

pub fn studio_specialized_domain_kind(
    request_frame: Option<&StudioNormalizedRequestFrame>,
) -> Option<StudioSpecializedDomainKind> {
    request_frame.map(studio_specialized_domain_kind_for_frame)
}

pub fn studio_specialized_domain_kind_for_frame(
    frame: &StudioNormalizedRequestFrame,
) -> StudioSpecializedDomainKind {
    match frame {
        StudioNormalizedRequestFrame::Weather(_) => StudioSpecializedDomainKind::Weather,
        StudioNormalizedRequestFrame::Sports(_) => StudioSpecializedDomainKind::Sports,
        StudioNormalizedRequestFrame::Places(_) => StudioSpecializedDomainKind::Places,
        StudioNormalizedRequestFrame::Recipe(_) => StudioSpecializedDomainKind::Recipe,
        StudioNormalizedRequestFrame::MessageCompose(_) => {
            StudioSpecializedDomainKind::MessageCompose
        }
        StudioNormalizedRequestFrame::UserInput(_) => StudioSpecializedDomainKind::UserInput,
    }
}

pub fn studio_request_frame_missing_slots(frame: &StudioNormalizedRequestFrame) -> &[String] {
    match frame {
        StudioNormalizedRequestFrame::Weather(frame) => &frame.missing_slots,
        StudioNormalizedRequestFrame::Sports(frame) => &frame.missing_slots,
        StudioNormalizedRequestFrame::Places(frame) => &frame.missing_slots,
        StudioNormalizedRequestFrame::Recipe(frame) => &frame.missing_slots,
        StudioNormalizedRequestFrame::MessageCompose(frame) => &frame.missing_slots,
        StudioNormalizedRequestFrame::UserInput(frame) => &frame.missing_slots,
    }
}

pub fn studio_request_frame_clarification_slots(frame: &StudioNormalizedRequestFrame) -> &[String] {
    match frame {
        StudioNormalizedRequestFrame::Weather(frame) => &frame.clarification_required_slots,
        StudioNormalizedRequestFrame::Sports(frame) => &frame.clarification_required_slots,
        StudioNormalizedRequestFrame::Places(frame) => &frame.clarification_required_slots,
        StudioNormalizedRequestFrame::Recipe(frame) => &frame.clarification_required_slots,
        StudioNormalizedRequestFrame::MessageCompose(frame) => &frame.clarification_required_slots,
        StudioNormalizedRequestFrame::UserInput(frame) => &frame.clarification_required_slots,
    }
}

pub fn studio_specialized_domain_policy(
    kind: StudioSpecializedDomainKind,
) -> StudioSpecializedDomainPolicySpec {
    match kind {
        StudioSpecializedDomainKind::Weather => StudioSpecializedDomainPolicySpec {
            domain_id: "weather",
            clarification_rationale:
                "Weather advice clarifies only when location scope is missing and cannot be safely inherited.",
            fallback_mode: StudioFallbackMode::StayInSpecializedLane,
            fallback_rationale:
                "Weather stays in its specialized lane unless scope is unresolved or an explicit ranked fallback is required.",
            presentation_surface: "weather_widget",
            widget_family: Some("weather"),
            renderer: Some(StudioRendererKind::HtmlIframe),
            tab_priority: &["render", "evidence"],
            presentation_rationale:
                "Weather answers should stay on the compact parity widget so scope, recency, and retained location context remain visible.",
            output_shape: "weather_summary_with_practical_guidance",
            ordered_steps: &[
                "resolve_scope",
                "fetch_conditions",
                "summarize_actionable_weather",
                "retain_widget_state",
            ],
            transformation_rationale:
                "Weather turns normalize live conditions into a concise answer plus retained location context.",
            sensitivity: StudioRiskSensitivity::Medium,
            base_risk_reasons: &[
                "weather advice depends on precise location scope",
                "currentness matters for practical weather guidance",
            ],
            user_visible_guardrails: &[
                "Show the selected lane, source, and retained scope before answering.",
            ],
            verification_strategy: "weather_scope_and_currentness",
            verification_required_checks: &[
                "location_scope_resolved",
                "current_conditions_available",
                "weather_surface_rendered",
            ],
            selected_source_rationale:
                "The specialized weather surface outranks broad search because it keeps currentness and location scope explicit.",
            fallback_source_rationale:
                "Conversation context and web search remain ordered fallbacks if the weather surface cannot fully answer.",
            missing_slot_fallback_reason:
                "weather execution is blocked until location scope is clarified or safely inherited",
        },
        StudioSpecializedDomainKind::Sports => StudioSpecializedDomainPolicySpec {
            domain_id: "sports",
            clarification_rationale:
                "Sports routes clarify only when league or target cannot be recovered from the active context.",
            fallback_mode: StudioFallbackMode::StayInSpecializedLane,
            fallback_rationale:
                "Sports stays in its specialized lane unless the target is unresolved or the runtime must fall back to a broader source.",
            presentation_surface: "sports_widget",
            widget_family: Some("sports"),
            renderer: Some(StudioRendererKind::HtmlIframe),
            tab_priority: &["render", "evidence"],
            presentation_rationale:
                "Sports answers should preserve the native scorecard-style surface so target, scope, and recency remain inspectable.",
            output_shape: "sports_status_card",
            ordered_steps: &[
                "resolve_target",
                "fetch_latest_data",
                "summarize_team_state",
                "retain_widget_state",
            ],
            transformation_rationale:
                "Sports turns normalize team or league data into a compact status surface.",
            sensitivity: StudioRiskSensitivity::Medium,
            base_risk_reasons: &[
                "sports answers depend on precise league and target resolution",
                "recency matters for scores, standings, and schedules",
            ],
            user_visible_guardrails: &[
                "Show the selected target and freshness expectations before answering.",
            ],
            verification_strategy: "sports_target_and_recency",
            verification_required_checks: &[
                "sports_target_resolved",
                "latest_team_data_available",
                "sports_surface_rendered",
            ],
            selected_source_rationale:
                "The specialized sports surface outranks broad search because it preserves the resolved target and current sports scope.",
            fallback_source_rationale:
                "Conversation context and web search remain ordered fallbacks when the native sports surface lacks coverage.",
            missing_slot_fallback_reason:
                "sports execution is blocked until league or team scope is clarified",
        },
        StudioSpecializedDomainKind::Places => StudioSpecializedDomainPolicySpec {
            domain_id: "places",
            clarification_rationale:
                "Places routes clarify only when the category or anchor location is still unresolved.",
            fallback_mode: StudioFallbackMode::StayInSpecializedLane,
            fallback_rationale:
                "Places stays in its specialized lane unless search scope is unresolved or a ranked fallback is explicitly required.",
            presentation_surface: "places_widget",
            widget_family: Some("places"),
            renderer: Some(StudioRendererKind::HtmlIframe),
            tab_priority: &["render", "evidence"],
            presentation_rationale:
                "Places answers should keep the map-oriented parity surface so ranking and anchor scope stay visible.",
            output_shape: "places_recommendation_list",
            ordered_steps: &[
                "resolve_category",
                "resolve_anchor_location",
                "rank_places",
                "project_map_surface",
            ],
            transformation_rationale:
                "Places turns transform ranked map results into a recommendation surface with retained search context.",
            sensitivity: StudioRiskSensitivity::Medium,
            base_risk_reasons: &[
                "place recommendations must stay grounded in the requested location scope",
                "ranked lists should preserve category and anchor assumptions",
            ],
            user_visible_guardrails: &[
                "Show the selected search anchor and ranking source before answering.",
            ],
            verification_strategy: "places_scope_and_presentation",
            verification_required_checks: &[
                "place_category_resolved",
                "location_scope_resolved",
                "places_surface_rendered",
            ],
            selected_source_rationale:
                "The specialized places surface outranks broad search because it preserves anchor scope, category, and ranked map results.",
            fallback_source_rationale:
                "Conversation context and web search remain ordered fallbacks when the places surface cannot satisfy the scope.",
            missing_slot_fallback_reason:
                "places execution is blocked until anchor or category scope is clarified",
        },
        StudioSpecializedDomainKind::Recipe => StudioSpecializedDomainPolicySpec {
            domain_id: "recipe",
            clarification_rationale:
                "Recipe routes clarify only when the dish is still ambiguous.",
            fallback_mode: StudioFallbackMode::StayInSpecializedLane,
            fallback_rationale:
                "Recipe stays in its specialized lane unless the dish is unresolved or the user explicitly asks for a different presentation.",
            presentation_surface: "recipe_widget",
            widget_family: Some("recipe"),
            renderer: Some(StudioRendererKind::HtmlIframe),
            tab_priority: &["render", "evidence"],
            presentation_rationale:
                "Recipe answers should stay on the recipe parity surface so ingredients, servings, and preparation steps remain structured.",
            output_shape: "compact_recipe",
            ordered_steps: &[
                "resolve_dish",
                "size_servings",
                "compose_ingredients_and_steps",
            ],
            transformation_rationale:
                "Recipe turns transform the request into a compact kitchen-usable recipe.",
            sensitivity: StudioRiskSensitivity::Low,
            base_risk_reasons: &[
                "recipe outputs should preserve dish identity and serving assumptions",
            ],
            user_visible_guardrails: &[
                "Show the resolved dish and serving assumptions before answering.",
            ],
            verification_strategy: "recipe_shape_and_servings",
            verification_required_checks: &["dish_resolved", "recipe_surface_rendered"],
            selected_source_rationale:
                "The specialized recipe surface outranks generic prose because it preserves the structured recipe shape.",
            fallback_source_rationale:
                "Conversation context remains an ordered fallback when the recipe lane needs missing dish details.",
            missing_slot_fallback_reason:
                "recipe execution is blocked until the requested dish is clarified",
        },
        StudioSpecializedDomainKind::MessageCompose => StudioSpecializedDomainPolicySpec {
            domain_id: "message_compose",
            clarification_rationale:
                "Communication routes clarify only when channel, purpose, or recipient context is still missing.",
            fallback_mode: StudioFallbackMode::AllowRankedFallbacks,
            fallback_rationale:
                "Communication keeps its structured compose lane primary, but may rank direct drafting and connector-backed delivery paths behind it.",
            presentation_surface: "communication_surface",
            widget_family: Some("message"),
            renderer: Some(StudioRendererKind::HtmlIframe),
            tab_priority: &["render", "evidence"],
            presentation_rationale:
                "Message composition should remain on a structured compose surface so channel, recipient context, and draft shape stay explicit.",
            output_shape: "message_draft",
            ordered_steps: &[
                "resolve_channel",
                "ground_recipient_context",
                "compose_draft",
            ],
            transformation_rationale:
                "Communication turns transform the prompt into a draftable message with explicit audience and purpose.",
            sensitivity: StudioRiskSensitivity::Medium,
            base_risk_reasons: &[
                "message drafts depend on recipient and channel precision",
                "connector-backed communication can affect external systems",
            ],
            user_visible_guardrails: &[
                "Show the selected channel and audience before presenting the draft.",
            ],
            verification_strategy: "message_shape_and_audience",
            verification_required_checks: &[
                "message_channel_resolved",
                "communication_surface_rendered",
            ],
            selected_source_rationale:
                "The structured compose lane outranks a plain direct answer because the message needs explicit channel and audience framing.",
            fallback_source_rationale:
                "Connector and conversation sources remain ordered fallbacks when the compose lane needs delivery context.",
            missing_slot_fallback_reason:
                "communication execution is blocked until channel or recipient context is clarified",
        },
        StudioSpecializedDomainKind::UserInput => StudioSpecializedDomainPolicySpec {
            domain_id: "user_input",
            clarification_rationale:
                "Structured input routes clarify when Studio still lacks the option set or decision shape.",
            fallback_mode: StudioFallbackMode::BlockUntilClarified,
            fallback_rationale:
                "Structured input should not fall back to generic prose when the option set itself is missing.",
            presentation_surface: "decision_widget",
            widget_family: Some("user_input"),
            renderer: Some(StudioRendererKind::HtmlIframe),
            tab_priority: &["render", "evidence"],
            presentation_rationale:
                "Structured choices should stay on a tappable decision surface instead of collapsing to open-ended prose.",
            output_shape: "structured_choice_surface",
            ordered_steps: &[
                "normalize_options",
                "project_choice_surface",
                "await_selection",
            ],
            transformation_rationale:
                "User-input turns transform the prompt into a structured decision surface instead of open-ended prose.",
            sensitivity: StudioRiskSensitivity::Low,
            base_risk_reasons: &[
                "decision surfaces should preserve the intended option set and ranking criteria",
            ],
            user_visible_guardrails: &[
                "Show the decision shape and option set before waiting for input.",
            ],
            verification_strategy: "structured_choice_surface",
            verification_required_checks: &[
                "input_options_projected",
                "decision_surface_rendered",
            ],
            selected_source_rationale:
                "The structured choice surface outranks generic prose because the turn is about collecting a bounded decision.",
            fallback_source_rationale:
                "Conversation context remains supporting evidence, but the decision surface stays primary until options are clarified.",
            missing_slot_fallback_reason:
                "structured input execution is blocked until the option set is explicit",
        },
    }
}
