use super::intent_signals::StudioIntentContext;
use super::runtime_locality::studio_runtime_locality_scope_hint;
use super::specialized_policy::{
    studio_request_frame_clarification_slots, studio_request_frame_missing_slots,
    studio_specialized_domain_kind, studio_specialized_domain_policy,
};
use ioi_types::app::{
    StudioArtifactClass, StudioCheckpointState, StudioClarificationMode, StudioClarificationPolicy,
    StudioCompletionInvariant, StudioDomainLaneFrame, StudioDomainPolicyBundle,
    StudioExecutionModeDecision, StudioExecutionStrategy, StudioFallbackMode, StudioFallbackPolicy,
    StudioLaneFamily, StudioLaneTransition, StudioLaneTransitionKind,
    StudioMessageComposeRequestFrame, StudioNormalizedRequestFrame, StudioObjectiveState,
    StudioOrchestrationState, StudioOutcomeArtifactRequest, StudioOutcomeKind,
    StudioPlacesRequestFrame, StudioPolicyContractSummary, StudioPresentationPolicy,
    StudioRecipeRequestFrame, StudioRendererKind, StudioRetainedLaneState,
    StudioRetainedWidgetState, StudioRiskProfile, StudioRiskSensitivity, StudioSourceFamily,
    StudioSourceRankingEntry, StudioSourceSelection, StudioSportsRequestFrame, StudioTaskUnitState,
    StudioTransformationPolicy, StudioUserInputRequestFrame, StudioVerificationContract,
    StudioWeatherRequestFrame, StudioWidgetStateBinding, StudioWorkStatus,
};

#[derive(Debug, Clone, PartialEq)]
pub struct StudioTopologyProjection {
    pub lane_frame: Option<StudioDomainLaneFrame>,
    pub request_frame: Option<StudioNormalizedRequestFrame>,
    pub source_selection: Option<StudioSourceSelection>,
    pub retained_lane_state: Option<StudioRetainedLaneState>,
    pub lane_transitions: Vec<StudioLaneTransition>,
    pub orchestration_state: Option<StudioOrchestrationState>,
}

pub fn derive_studio_topology_projection(
    intent: &str,
    active_artifact_id: Option<&str>,
    active_widget_state: Option<&StudioRetainedWidgetState>,
    outcome_kind: StudioOutcomeKind,
    execution_strategy: StudioExecutionStrategy,
    execution_mode_decision: Option<&StudioExecutionModeDecision>,
    confidence: f32,
    needs_clarification: bool,
    clarification_questions: &[String],
    routing_hints: &[String],
    artifact: Option<&StudioOutcomeArtifactRequest>,
) -> StudioTopologyProjection {
    let context = StudioIntentContext::new(intent);
    let request_frame = derive_request_frame(&context, routing_hints, active_widget_state);
    let primary_lane = primary_lane_family(
        &context,
        outcome_kind,
        routing_hints,
        artifact,
        request_frame.as_ref(),
    );
    let lane_frame = Some(StudioDomainLaneFrame {
        primary_lane,
        secondary_lanes: secondary_lane_families(
            primary_lane,
            request_frame.as_ref(),
            routing_hints,
            artifact,
        ),
        primary_goal: primary_goal(
            intent,
            primary_lane,
            outcome_kind,
            routing_hints,
            request_frame.as_ref(),
            artifact,
        ),
        tool_widget_family: tool_widget_family_hint(routing_hints).map(str::to_string),
        currentness_pressure: routing_hint_flag(routing_hints, "currentness_override")
            || matches!(
                tool_widget_family_hint(routing_hints),
                Some("weather" | "sports" | "places")
            )
            || context.currentness_pressure(),
        workspace_grounding_required: routing_hint_flag(
            routing_hints,
            "workspace_grounding_required",
        ) || artifact.is_some_and(|request| {
            matches!(
                request.artifact_class,
                StudioArtifactClass::WorkspaceProject | StudioArtifactClass::CodePatch
            )
        }),
        persistent_deliverable_requested: outcome_kind == StudioOutcomeKind::Artifact,
        active_artifact_follow_up: active_artifact_id.is_some(),
        lane_confidence: if confidence.is_finite() {
            confidence.clamp(0.0, 1.0)
        } else {
            0.0
        },
    });
    let source_selection = Some(derive_source_selection(
        &context,
        primary_lane,
        request_frame.as_ref(),
        routing_hints,
        active_artifact_id,
    ));
    let retained_lane_state = Some(StudioRetainedLaneState {
        active_lane: if needs_clarification && primary_lane != StudioLaneFamily::Conversation {
            primary_lane
        } else {
            primary_lane
        },
        active_tool_widget_family: tool_widget_family_hint(routing_hints).map(str::to_string),
        active_artifact_id: active_artifact_id.map(str::to_string),
        unresolved_clarification_question: clarification_questions.first().cloned(),
        selected_provider_family: routing_hint_value(routing_hints, "selected_provider_family:"),
        selected_provider_route_label: routing_hint_value(
            routing_hints,
            "selected_provider_route_label:",
        ),
        selected_source_family: source_selection
            .as_ref()
            .map(|selection| selection.selected_source),
    });
    let lane_transitions = derive_lane_transitions(
        primary_lane,
        lane_frame
            .as_ref()
            .map(|frame| frame.secondary_lanes.as_slice())
            .unwrap_or(&[]),
        request_frame.as_ref(),
        needs_clarification,
        clarification_questions,
        routing_hints,
    );
    let orchestration_state = derive_orchestration_state(
        intent,
        primary_lane,
        outcome_kind,
        execution_strategy,
        execution_mode_decision,
        needs_clarification,
        clarification_questions,
        request_frame.as_ref(),
    );

    StudioTopologyProjection {
        lane_frame,
        request_frame,
        source_selection,
        retained_lane_state,
        lane_transitions,
        orchestration_state,
    }
}

pub fn derive_studio_domain_policy_bundle(
    lane_frame: Option<&StudioDomainLaneFrame>,
    request_frame: Option<&StudioNormalizedRequestFrame>,
    source_selection: Option<&StudioSourceSelection>,
    outcome_kind: StudioOutcomeKind,
    routing_hints: &[String],
    needs_clarification: bool,
    active_widget_state: Option<&StudioRetainedWidgetState>,
) -> StudioDomainPolicyBundle {
    let retained_widget_state = merge_retained_widget_state(request_frame, active_widget_state);
    let clarification_policy = derive_clarification_policy(
        request_frame,
        needs_clarification,
        retained_widget_state.as_ref(),
    );
    let fallback_policy = derive_fallback_policy(
        lane_frame,
        request_frame,
        routing_hints,
        needs_clarification,
    );
    let presentation_policy = derive_presentation_policy(
        lane_frame,
        request_frame,
        outcome_kind,
        retained_widget_state.as_ref(),
    );
    let transformation_policy = derive_transformation_policy(request_frame, outcome_kind);
    let risk_profile = derive_risk_profile(lane_frame, request_frame, routing_hints);
    let verification_contract =
        derive_verification_contract(lane_frame, request_frame, outcome_kind, needs_clarification);
    let source_ranking = derive_source_ranking(request_frame, source_selection);

    StudioDomainPolicyBundle {
        clarification_policy,
        fallback_policy,
        presentation_policy,
        transformation_policy,
        risk_profile,
        verification_contract,
        policy_contract: Some(StudioPolicyContractSummary {
            bindings: vec![
                "lane_frame".to_string(),
                "request_frame".to_string(),
                "source_selection".to_string(),
                "route_decision.effective_tool_surface".to_string(),
                "domain_policy_bundle".to_string(),
            ],
            hidden_instruction_dependency: false,
            rationale:
                "Lane choice, fallback posture, source ranking, presentation, and verification are retained as typed runtime receipts."
                    .to_string(),
        }),
        source_ranking,
        retained_widget_state,
    }
}

fn routing_hint_flag(routing_hints: &[String], needle: &str) -> bool {
    routing_hints.iter().any(|hint| hint == needle)
}

fn routing_hint_value(routing_hints: &[String], prefix: &str) -> Option<String> {
    routing_hints
        .iter()
        .find_map(|hint| hint.strip_prefix(prefix))
        .map(str::to_string)
}

fn tool_widget_family_hint(routing_hints: &[String]) -> Option<&str> {
    routing_hints
        .iter()
        .find_map(|hint| hint.strip_prefix("tool_widget:"))
}

fn widget_binding_value(
    active_widget_state: Option<&StudioRetainedWidgetState>,
    key: &str,
) -> Option<String> {
    active_widget_state.and_then(|state| {
        state
            .bindings
            .iter()
            .find(|binding| binding.key == key)
            .map(|binding| binding.value.clone())
    })
}

fn runtime_locality_scope_for_context(context: &StudioIntentContext) -> Option<String> {
    context
        .requests_runtime_locality()
        .then(studio_runtime_locality_scope_hint)
        .flatten()
}

fn is_self_referential_places_anchor(anchor: &str) -> bool {
    matches!(
        anchor.trim().to_ascii_lowercase().as_str(),
        "me" | "my area"
            | "current area"
            | "current location"
            | "here"
            | "around here"
            | "where i am"
    )
}

fn derive_request_frame(
    context: &StudioIntentContext,
    routing_hints: &[String],
    active_widget_state: Option<&StudioRetainedWidgetState>,
) -> Option<StudioNormalizedRequestFrame> {
    if matches!(tool_widget_family_hint(routing_hints), Some("weather"))
        || context.tool_widget_family() == Some("weather")
    {
        let inferred_locations = context.extract_weather_scopes();
        let retained_location = widget_binding_value(active_widget_state, "weather.location");
        let assumed_location = runtime_locality_scope_for_context(context).or(retained_location);
        let missing_slots = if inferred_locations.is_empty() && assumed_location.is_none() {
            vec!["location".to_string()]
        } else {
            Vec::new()
        };
        let clarification_required_slots =
            if routing_hint_flag(routing_hints, "location_required_for_weather_advice")
                || (routing_hint_flag(routing_hints, "tool_widget:weather")
                    && !missing_slots.is_empty())
            {
                missing_slots.clone()
            } else {
                Vec::new()
            };
        return Some(StudioNormalizedRequestFrame::Weather(
            StudioWeatherRequestFrame {
                inferred_locations,
                assumed_location,
                temporal_scope: context
                    .weather_temporal_scope()
                    .map(str::to_string)
                    .or_else(|| {
                        widget_binding_value(active_widget_state, "weather.temporal_scope")
                    }),
                missing_slots,
                clarification_required_slots,
            },
        ));
    }

    if matches!(tool_widget_family_hint(routing_hints), Some("sports"))
        || context.tool_widget_family() == Some("sports")
    {
        let league = context
            .sports_league()
            .map(str::to_string)
            .or_else(|| widget_binding_value(active_widget_state, "sports.league"));
        let team_or_target = context
            .sports_team_target()
            .or_else(|| widget_binding_value(active_widget_state, "sports.target"));
        let mut missing_slots = Vec::new();
        if league.is_none() {
            missing_slots.push("league".to_string());
        }
        if team_or_target.is_none() {
            missing_slots.push("target".to_string());
        }
        let clarification_required_slots = if routing_hint_flag(routing_hints, "tool_widget:sports")
            && !missing_slots.is_empty()
        {
            missing_slots.clone()
        } else {
            Vec::new()
        };
        return Some(StudioNormalizedRequestFrame::Sports(
            StudioSportsRequestFrame {
                league,
                team_or_target,
                data_scope: context
                    .sports_data_scope()
                    .map(str::to_string)
                    .or_else(|| widget_binding_value(active_widget_state, "sports.data_scope")),
                missing_slots,
                clarification_required_slots,
            },
        ));
    }

    if matches!(tool_widget_family_hint(routing_hints), Some("places"))
        || context.tool_widget_family() == Some("places")
    {
        let runtime_locality_scope = runtime_locality_scope_for_context(context);
        let search_anchor = context
            .places_anchor_phrase()
            .filter(|anchor| !is_self_referential_places_anchor(anchor))
            .or_else(|| runtime_locality_scope.clone());
        let category = context
            .places_category_label()
            .map(str::to_string)
            .or_else(|| widget_binding_value(active_widget_state, "places.category"));
        let location_scope = if search_anchor.is_some() {
            search_anchor.clone()
        } else {
            runtime_locality_scope
                .or_else(|| widget_binding_value(active_widget_state, "places.location_scope"))
        };
        let mut missing_slots = Vec::new();
        if category.is_none() {
            missing_slots.push("category".to_string());
        }
        if location_scope.is_none() {
            missing_slots.push("location".to_string());
        }
        let clarification_required_slots = if routing_hint_flag(routing_hints, "tool_widget:places")
            && !missing_slots.is_empty()
        {
            missing_slots.clone()
        } else {
            Vec::new()
        };
        return Some(StudioNormalizedRequestFrame::Places(
            StudioPlacesRequestFrame {
                search_anchor,
                category,
                location_scope,
                missing_slots,
                clarification_required_slots,
            },
        ));
    }

    if matches!(tool_widget_family_hint(routing_hints), Some("recipe"))
        || context.tool_widget_family() == Some("recipe")
    {
        let dish = context
            .recipe_dish()
            .or_else(|| widget_binding_value(active_widget_state, "recipe.dish"));
        let missing_slots = if dish.is_none() {
            vec!["dish".to_string()]
        } else {
            Vec::new()
        };
        let clarification_required_slots = if routing_hint_flag(routing_hints, "tool_widget:recipe")
            && !missing_slots.is_empty()
        {
            missing_slots.clone()
        } else {
            Vec::new()
        };
        return Some(StudioNormalizedRequestFrame::Recipe(
            StudioRecipeRequestFrame {
                dish,
                servings: context
                    .recipe_servings()
                    .or_else(|| widget_binding_value(active_widget_state, "recipe.servings")),
                missing_slots,
                clarification_required_slots,
            },
        ));
    }

    if matches!(tool_widget_family_hint(routing_hints), Some("user_input"))
        || routing_hint_flag(routing_hints, "prioritization_request")
        || routing_hint_flag(routing_hints, "prioritization_guidance_request")
        || context.requests_prioritization()
    {
        let explicit_options_present = context.explicit_prioritization_options();
        let missing_slots = if explicit_options_present {
            Vec::new()
        } else {
            vec!["options".to_string()]
        };
        let clarification_required_slots =
            if (routing_hint_flag(routing_hints, "tool_widget:user_input")
                || context.requests_prioritization())
                && !missing_slots.is_empty()
            {
                missing_slots.clone()
            } else {
                Vec::new()
            };
        return Some(StudioNormalizedRequestFrame::UserInput(
            StudioUserInputRequestFrame {
                interaction_kind: Some(
                    widget_binding_value(active_widget_state, "user_input.interaction_kind")
                        .unwrap_or_else(|| {
                            if routing_hint_flag(routing_hints, "prioritization_request")
                                || routing_hint_flag(
                                    routing_hints,
                                    "prioritization_guidance_request",
                                )
                            {
                                "prioritization".to_string()
                            } else {
                                "selection".to_string()
                            }
                        }),
                ),
                explicit_options_present,
                missing_slots,
                clarification_required_slots,
            },
        ));
    }

    let message_channel = context
        .message_channel()
        .map(str::to_string)
        .or_else(|| widget_binding_value(active_widget_state, "message.channel"));
    let message_purpose = context
        .message_purpose()
        .map(str::to_string)
        .or_else(|| widget_binding_value(active_widget_state, "message.purpose"));
    let message_recipient_context = context
        .message_recipient_context()
        .or_else(|| widget_binding_value(active_widget_state, "message.recipient_context"));
    if routing_hint_flag(routing_hints, "message_compose_surface")
        || context.prefers_message_compose_surface()
        || message_channel.is_some()
    {
        let mut missing_slots = Vec::new();
        if message_channel.is_none() {
            missing_slots.push("channel".to_string());
        }
        if message_purpose.is_none() {
            missing_slots.push("purpose".to_string());
        }
        if message_recipient_context.is_none()
            && matches!(
                message_purpose.as_deref(),
                Some("draft" | "reply" | "compose")
            )
        {
            missing_slots.push("recipient_context".to_string());
        }
        return Some(StudioNormalizedRequestFrame::MessageCompose(
            StudioMessageComposeRequestFrame {
                channel: message_channel,
                recipient_context: message_recipient_context,
                purpose: message_purpose,
                clarification_required_slots: missing_slots.clone(),
                missing_slots,
            },
        ));
    }

    None
}

fn request_frame_kind(frame: &StudioNormalizedRequestFrame) -> &'static str {
    match frame {
        StudioNormalizedRequestFrame::Weather(_) => "weather",
        StudioNormalizedRequestFrame::Sports(_) => "sports",
        StudioNormalizedRequestFrame::Places(_) => "places",
        StudioNormalizedRequestFrame::Recipe(_) => "recipe",
        StudioNormalizedRequestFrame::MessageCompose(_) => "message",
        StudioNormalizedRequestFrame::UserInput(_) => "user_input",
    }
}

fn merge_retained_widget_state(
    request_frame: Option<&StudioNormalizedRequestFrame>,
    active_widget_state: Option<&StudioRetainedWidgetState>,
) -> Option<StudioRetainedWidgetState> {
    let mut state = active_widget_state
        .cloned()
        .unwrap_or(StudioRetainedWidgetState {
            widget_family: None,
            bindings: Vec::new(),
            last_updated_at: None,
        });
    let Some(frame) = request_frame else {
        return if state.bindings.is_empty() && state.widget_family.is_none() {
            None
        } else {
            Some(state)
        };
    };

    state.widget_family = Some(request_frame_kind(frame).to_string());
    let mut upsert = |key: &str, value: Option<String>, source: &str| {
        let Some(value) = value else {
            return;
        };
        if value.trim().is_empty() {
            return;
        }
        if let Some(existing) = state.bindings.iter_mut().find(|binding| binding.key == key) {
            existing.value = value;
            existing.source = source.to_string();
        } else {
            state.bindings.push(StudioWidgetStateBinding {
                key: key.to_string(),
                value,
                source: source.to_string(),
            });
        }
    };

    match frame {
        StudioNormalizedRequestFrame::Weather(frame) => {
            upsert(
                "weather.location",
                frame
                    .inferred_locations
                    .first()
                    .cloned()
                    .or_else(|| frame.assumed_location.clone()),
                "request_frame",
            );
            upsert(
                "weather.temporal_scope",
                frame.temporal_scope.clone(),
                "request_frame",
            );
        }
        StudioNormalizedRequestFrame::Sports(frame) => {
            upsert("sports.league", frame.league.clone(), "request_frame");
            upsert(
                "sports.target",
                frame.team_or_target.clone(),
                "request_frame",
            );
            upsert(
                "sports.data_scope",
                frame.data_scope.clone(),
                "request_frame",
            );
        }
        StudioNormalizedRequestFrame::Places(frame) => {
            upsert("places.category", frame.category.clone(), "request_frame");
            upsert(
                "places.location_scope",
                frame
                    .location_scope
                    .clone()
                    .or_else(|| frame.search_anchor.clone()),
                "request_frame",
            );
        }
        StudioNormalizedRequestFrame::Recipe(frame) => {
            upsert("recipe.dish", frame.dish.clone(), "request_frame");
            upsert("recipe.servings", frame.servings.clone(), "request_frame");
        }
        StudioNormalizedRequestFrame::MessageCompose(frame) => {
            upsert("message.channel", frame.channel.clone(), "request_frame");
            upsert(
                "message.recipient_context",
                frame.recipient_context.clone(),
                "request_frame",
            );
            upsert("message.purpose", frame.purpose.clone(), "request_frame");
        }
        StudioNormalizedRequestFrame::UserInput(frame) => {
            upsert(
                "user_input.interaction_kind",
                frame.interaction_kind.clone(),
                "request_frame",
            );
        }
    }

    Some(state)
}

fn derive_clarification_policy(
    request_frame: Option<&StudioNormalizedRequestFrame>,
    needs_clarification: bool,
    retained_widget_state: Option<&StudioRetainedWidgetState>,
) -> Option<StudioClarificationPolicy> {
    let Some(frame) = request_frame else {
        return needs_clarification.then(|| StudioClarificationPolicy {
            mode: StudioClarificationMode::BlockUntilClarified,
            assumed_bindings: Vec::new(),
            blocking_slots: Vec::new(),
            rationale:
                "The lane is blocked on unresolved clarification before execution can continue."
                    .to_string(),
        });
    };
    let blocking_slots = studio_request_frame_clarification_slots(frame).to_vec();
    let rationale = studio_specialized_domain_kind(Some(frame))
        .map(studio_specialized_domain_policy)
        .map(|policy| policy.clarification_rationale.to_string())
        .unwrap_or_else(|| {
            "The selected lane clarifies only when required slots remain unresolved.".to_string()
        });
    let assumed_bindings: Vec<String> = retained_widget_state
        .map(|state| {
            state
                .bindings
                .iter()
                .map(|binding| binding.key.clone())
                .collect()
        })
        .unwrap_or_default();
    Some(StudioClarificationPolicy {
        mode: if blocking_slots.is_empty() && !assumed_bindings.is_empty() {
            StudioClarificationMode::AssumeFromRetainedState
        } else if needs_clarification || !blocking_slots.is_empty() {
            StudioClarificationMode::BlockUntilClarified
        } else {
            StudioClarificationMode::ClarifyOnMissingSlots
        },
        assumed_bindings,
        blocking_slots,
        rationale,
    })
}

fn derive_fallback_policy(
    lane_frame: Option<&StudioDomainLaneFrame>,
    request_frame: Option<&StudioNormalizedRequestFrame>,
    routing_hints: &[String],
    needs_clarification: bool,
) -> Option<StudioFallbackPolicy> {
    let primary_lane = lane_frame?.primary_lane;
    let specialized_policy =
        studio_specialized_domain_kind(request_frame).map(studio_specialized_domain_policy);
    Some(StudioFallbackPolicy {
        mode: if needs_clarification {
            StudioFallbackMode::BlockUntilClarified
        } else if let Some(policy) = specialized_policy {
            policy.fallback_mode
        } else {
            StudioFallbackMode::AllowRankedFallbacks
        },
        primary_lane,
        fallback_lanes: lane_frame
            .map(|frame| frame.secondary_lanes.clone())
            .unwrap_or_default(),
        trigger_signals: routing_hints
            .iter()
            .filter(|hint| {
                matches!(
                    hint.as_str(),
                    "currentness_override"
                        | "connector_missing"
                        | "connector_auth_required"
                        | "connector_preferred"
                        | "narrow_surface_preferred"
                        | "retained_widget_state_applied"
                        | "retained_widget_follow_up"
                )
            })
            .cloned()
            .collect(),
        rationale: if let Some(policy) = specialized_policy {
            policy.fallback_rationale.to_string()
        } else {
            "General and communication lanes may escalate through ranked fallbacks when the primary path is unavailable.".to_string()
        },
    })
}

fn derive_presentation_policy(
    lane_frame: Option<&StudioDomainLaneFrame>,
    request_frame: Option<&StudioNormalizedRequestFrame>,
    outcome_kind: StudioOutcomeKind,
    retained_widget_state: Option<&StudioRetainedWidgetState>,
) -> Option<StudioPresentationPolicy> {
    let specialized_policy =
        studio_specialized_domain_kind(request_frame).map(studio_specialized_domain_policy);
    let primary_surface = if let Some(policy) = specialized_policy {
        policy.presentation_surface
    } else {
        match outcome_kind {
            StudioOutcomeKind::Artifact => "artifact_surface",
            StudioOutcomeKind::Visualizer => "inline_visualizer",
            _ => match request_frame {
                None => match outcome_kind {
                    StudioOutcomeKind::ToolWidget => "tool_widget_surface",
                    StudioOutcomeKind::Conversation => "reply_surface",
                    StudioOutcomeKind::Artifact => "artifact_surface",
                    StudioOutcomeKind::Visualizer => "inline_visualizer",
                },
                Some(_) => "tool_widget_surface",
            },
        }
    };
    Some(StudioPresentationPolicy {
        primary_surface: primary_surface.to_string(),
        widget_family: retained_widget_state
            .and_then(|state| state.widget_family.clone())
            .or_else(|| lane_frame.and_then(|frame| frame.tool_widget_family.clone()))
            .or_else(|| specialized_policy.and_then(|policy| policy.widget_family.map(str::to_string))),
        renderer: if let Some(policy) = specialized_policy {
            policy.renderer
        } else {
            match outcome_kind {
                StudioOutcomeKind::Artifact => None,
                StudioOutcomeKind::Visualizer => Some(StudioRendererKind::Mermaid),
                _ => Some(StudioRendererKind::HtmlIframe),
            }
        },
        tab_priority: if let Some(policy) = specialized_policy {
            policy
                .tab_priority
                .iter()
                .map(|entry| (*entry).to_string())
                .collect()
        } else {
            match outcome_kind {
                StudioOutcomeKind::Artifact => vec![
                    "render".to_string(),
                    "source".to_string(),
                    "evidence".to_string(),
                ],
                _ => vec!["render".to_string(), "evidence".to_string()],
            }
        },
        rationale: specialized_policy
            .map(|policy| policy.presentation_rationale.to_string())
            .unwrap_or_else(|| {
                "Studio prefers a route-shaped parity surface so the desktop shell shows the active lane instead of collapsing to a generic summary."
                    .to_string()
            }),
    })
}

fn derive_transformation_policy(
    request_frame: Option<&StudioNormalizedRequestFrame>,
    outcome_kind: StudioOutcomeKind,
) -> Option<StudioTransformationPolicy> {
    let specialized_policy =
        studio_specialized_domain_kind(request_frame).map(studio_specialized_domain_policy);
    let (output_shape, ordered_steps, rationale) = match outcome_kind {
        StudioOutcomeKind::Artifact => (
            "persistent_artifact",
            vec![
                "plan_artifact".to_string(),
                "materialize_files".to_string(),
                "verify_surface".to_string(),
            ],
            "Artifact turns transform the request into a persistent deliverable with file-backed verification.".to_string(),
        ),
        StudioOutcomeKind::Visualizer => (
            "inline_visual",
            vec!["draft_visual".to_string(), "project_inline_surface".to_string()],
            "Visualizer turns transform the request into an inline visual projection.".to_string(),
        ),
        _ => {
            if let Some(policy) = specialized_policy {
                (
                    policy.output_shape,
                    policy
                        .ordered_steps
                        .iter()
                        .map(|entry| (*entry).to_string())
                        .collect(),
                    policy.transformation_rationale.to_string(),
                )
            } else {
                (
                    "direct_or_tool_backed_reply",
                    vec!["route".to_string(), "answer".to_string()],
                    "General turns either answer directly or land through the selected route-backed reply surface.".to_string(),
                )
            }
        }
    };
    Some(StudioTransformationPolicy {
        output_shape: output_shape.to_string(),
        ordered_steps,
        rationale,
    })
}

fn derive_risk_profile(
    lane_frame: Option<&StudioDomainLaneFrame>,
    request_frame: Option<&StudioNormalizedRequestFrame>,
    routing_hints: &[String],
) -> Option<StudioRiskProfile> {
    let Some(frame) = lane_frame else {
        return None;
    };
    let specialized_policy =
        studio_specialized_domain_kind(request_frame).map(studio_specialized_domain_policy);
    let (sensitivity, mut reasons) = if let Some(policy) = specialized_policy {
        (
            policy.sensitivity,
            policy
                .base_risk_reasons
                .iter()
                .map(|reason| (*reason).to_string())
                .collect(),
        )
    } else {
        match frame.primary_lane {
            StudioLaneFamily::Communication | StudioLaneFamily::Integrations => (
                StudioRiskSensitivity::Medium,
                vec!["connector-backed communication can affect external systems".to_string()],
            ),
            StudioLaneFamily::Coding | StudioLaneFamily::Artifact => (
                StudioRiskSensitivity::Medium,
                vec![
                    "persistent outputs or workspace-backed work need explicit verification"
                        .to_string(),
                ],
            ),
            _ => (StudioRiskSensitivity::Low, Vec::new()),
        }
    };
    if matches!(request_frame, Some(StudioNormalizedRequestFrame::Places(_))) {
        reasons.push(
            "ranked place recommendations should stay grounded in the requested location scope"
                .to_string(),
        );
    }
    if routing_hints
        .iter()
        .any(|hint| hint == "connector_auth_required")
    {
        reasons
            .push("execution remains blocked until connector authentication completes".to_string());
    }
    Some(StudioRiskProfile {
        sensitivity,
        reasons,
        approval_required: false,
        user_visible_guardrails: if let Some(policy) = specialized_policy {
            policy
                .user_visible_guardrails
                .iter()
                .map(|entry| (*entry).to_string())
                .collect()
        } else {
            match sensitivity {
                StudioRiskSensitivity::Low => {
                    vec!["Show the selected lane and source before answering.".to_string()]
                }
                StudioRiskSensitivity::Medium | StudioRiskSensitivity::High => vec![
                    "Show the selected lane, provider, and verification gate before completion."
                        .to_string(),
                ],
            }
        },
    })
}

fn derive_verification_contract(
    lane_frame: Option<&StudioDomainLaneFrame>,
    request_frame: Option<&StudioNormalizedRequestFrame>,
    outcome_kind: StudioOutcomeKind,
    needs_clarification: bool,
) -> Option<StudioVerificationContract> {
    let specialized_policy =
        studio_specialized_domain_kind(request_frame).map(studio_specialized_domain_policy);
    let strategy = if outcome_kind == StudioOutcomeKind::Artifact {
        "artifact_contract"
    } else if let Some(policy) = specialized_policy {
        policy.verification_strategy
    } else {
        match outcome_kind {
            StudioOutcomeKind::Visualizer => "inline_visual_contract",
            _ => "route_contract",
        }
    };
    Some(StudioVerificationContract {
        strategy: strategy.to_string(),
        required_checks: if outcome_kind == StudioOutcomeKind::Artifact {
            vec![
                "artifact_contract_recorded".to_string(),
                "artifact_surface_rendered".to_string(),
            ]
        } else if let Some(policy) = specialized_policy {
            policy
                .verification_required_checks
                .iter()
                .map(|entry| (*entry).to_string())
                .collect()
        } else {
            {
                if matches!(
                    lane_frame.map(|frame| frame.primary_lane),
                    Some(StudioLaneFamily::Research)
                ) {
                    vec![
                        "selected_source_recorded".to_string(),
                        "reply_surface_rendered".to_string(),
                    ]
                } else {
                    vec!["route_contract_recorded".to_string()]
                }
            }
        },
        completion_gate: if needs_clarification {
            "blocked_on_clarification".to_string()
        } else {
            "surface_and_route_verified".to_string()
        },
    })
}

fn derive_source_ranking(
    request_frame: Option<&StudioNormalizedRequestFrame>,
    source_selection: Option<&StudioSourceSelection>,
) -> Vec<StudioSourceRankingEntry> {
    let Some(selection) = source_selection else {
        return Vec::new();
    };
    let specialized_policy =
        studio_specialized_domain_kind(request_frame).map(studio_specialized_domain_policy);
    let mut ordered_sources = vec![selection.selected_source];
    for source in &selection.candidate_sources {
        if !ordered_sources.contains(source) {
            ordered_sources.push(*source);
        }
    }
    ordered_sources
        .into_iter()
        .enumerate()
        .map(|(index, source)| StudioSourceRankingEntry {
            source,
            rank: index as u32 + 1,
            rationale: if source == selection.selected_source {
                specialized_policy
                    .map(|policy| policy.selected_source_rationale.to_string())
                    .unwrap_or_else(|| "Selected as the active source for this turn.".to_string())
            } else {
                specialized_policy
                    .map(|policy| policy.fallback_source_rationale.to_string())
                    .unwrap_or_else(|| {
                        "Retained as an ordered fallback or supporting source.".to_string()
                    })
            },
        })
        .collect()
}

fn primary_lane_family(
    context: &StudioIntentContext,
    outcome_kind: StudioOutcomeKind,
    routing_hints: &[String],
    artifact: Option<&StudioOutcomeArtifactRequest>,
    request_frame: Option<&StudioNormalizedRequestFrame>,
) -> StudioLaneFamily {
    if matches!(
        request_frame,
        Some(StudioNormalizedRequestFrame::MessageCompose(_))
    ) {
        return StudioLaneFamily::Communication;
    }
    if routing_hint_flag(routing_hints, "connector_intent_detected") {
        return StudioLaneFamily::Integrations;
    }
    if routing_hint_flag(routing_hints, "workspace_grounding_required")
        || artifact.is_some_and(|request| {
            matches!(
                request.artifact_class,
                StudioArtifactClass::WorkspaceProject | StudioArtifactClass::CodePatch
            )
        })
    {
        return StudioLaneFamily::Coding;
    }
    if outcome_kind == StudioOutcomeKind::Artifact {
        return StudioLaneFamily::Artifact;
    }
    if outcome_kind == StudioOutcomeKind::Visualizer {
        return StudioLaneFamily::Visualizer;
    }
    if outcome_kind == StudioOutcomeKind::ToolWidget {
        return match request_frame {
            Some(StudioNormalizedRequestFrame::Weather(_))
            | Some(StudioNormalizedRequestFrame::Sports(_))
            | Some(StudioNormalizedRequestFrame::Places(_))
            | Some(StudioNormalizedRequestFrame::Recipe(_)) => StudioLaneFamily::Research,
            Some(StudioNormalizedRequestFrame::UserInput(_)) => StudioLaneFamily::UserInput,
            _ => StudioLaneFamily::ToolWidget,
        };
    }
    if routing_hint_flag(routing_hints, "currentness_override") || context.currentness_pressure() {
        return StudioLaneFamily::Research;
    }
    StudioLaneFamily::Conversation
}

fn secondary_lane_families(
    primary_lane: StudioLaneFamily,
    request_frame: Option<&StudioNormalizedRequestFrame>,
    routing_hints: &[String],
    artifact: Option<&StudioOutcomeArtifactRequest>,
) -> Vec<StudioLaneFamily> {
    let mut lanes = Vec::new();
    let mut push_unique = |lane: StudioLaneFamily| {
        if lane != primary_lane && !lanes.contains(&lane) {
            lanes.push(lane);
        }
    };

    match primary_lane {
        StudioLaneFamily::Research => {
            if tool_widget_family_hint(routing_hints).is_some() {
                push_unique(StudioLaneFamily::ToolWidget);
            }
            push_unique(StudioLaneFamily::Conversation);
        }
        StudioLaneFamily::Integrations => {
            push_unique(StudioLaneFamily::Conversation);
            if matches!(
                request_frame,
                Some(StudioNormalizedRequestFrame::MessageCompose(_))
            ) {
                push_unique(StudioLaneFamily::Communication);
            }
        }
        StudioLaneFamily::Communication => {
            if routing_hint_flag(routing_hints, "connector_intent_detected") {
                push_unique(StudioLaneFamily::Integrations);
            }
        }
        StudioLaneFamily::UserInput => {
            push_unique(StudioLaneFamily::ToolWidget);
            push_unique(StudioLaneFamily::Conversation);
        }
        StudioLaneFamily::Coding => {
            if artifact.is_some() {
                push_unique(StudioLaneFamily::Artifact);
            }
        }
        StudioLaneFamily::Artifact => {
            if artifact.is_some_and(|request| {
                matches!(
                    request.artifact_class,
                    StudioArtifactClass::WorkspaceProject | StudioArtifactClass::CodePatch
                )
            }) {
                push_unique(StudioLaneFamily::Coding);
            }
            match request_frame {
                Some(
                    StudioNormalizedRequestFrame::Weather(_)
                    | StudioNormalizedRequestFrame::Sports(_)
                    | StudioNormalizedRequestFrame::Places(_)
                    | StudioNormalizedRequestFrame::Recipe(_),
                ) => {
                    push_unique(StudioLaneFamily::Research);
                    push_unique(StudioLaneFamily::ToolWidget);
                }
                Some(StudioNormalizedRequestFrame::MessageCompose(_)) => {
                    push_unique(StudioLaneFamily::Communication);
                }
                Some(StudioNormalizedRequestFrame::UserInput(_)) => {
                    push_unique(StudioLaneFamily::UserInput);
                    push_unique(StudioLaneFamily::ToolWidget);
                }
                None => {}
            }
        }
        _ => {}
    }

    lanes
}

fn primary_goal(
    intent: &str,
    primary_lane: StudioLaneFamily,
    outcome_kind: StudioOutcomeKind,
    _routing_hints: &[String],
    request_frame: Option<&StudioNormalizedRequestFrame>,
    artifact: Option<&StudioOutcomeArtifactRequest>,
) -> String {
    match request_frame {
        Some(StudioNormalizedRequestFrame::Weather(_)) => {
            "Resolve the weather scope and return current conditions for the requested location.".to_string()
        }
        Some(StudioNormalizedRequestFrame::Sports(_)) => {
            "Resolve the sports target and return the requested current sports context.".to_string()
        }
        Some(StudioNormalizedRequestFrame::Places(_)) => {
            "Resolve the place category and anchor location before searching the map surface.".to_string()
        }
        Some(StudioNormalizedRequestFrame::Recipe(_)) => {
            "Turn the recipe request into a concise, kitchen-usable deliverable.".to_string()
        }
        Some(StudioNormalizedRequestFrame::MessageCompose(_)) => {
            "Compose a message that fits the requested channel, audience, and purpose.".to_string()
        }
        Some(StudioNormalizedRequestFrame::UserInput(_)) => {
            "Collect structured user input before continuing with the requested comparison or prioritization.".to_string()
        }
        None => match primary_lane {
            StudioLaneFamily::Research => {
                "Gather fresh evidence before answering in the shared reply lane.".to_string()
            }
            StudioLaneFamily::Coding => {
                "Ground the answer or change in the current workspace before responding."
                    .to_string()
            }
            StudioLaneFamily::Artifact => match artifact {
                Some(request) if matches!(request.artifact_class, StudioArtifactClass::WorkspaceProject) => {
                    "Create the requested workspace-backed artifact and verify the live build."
                        .to_string()
                }
                _ => "Create the requested persistent artifact and verify its contract."
                    .to_string(),
            },
            StudioLaneFamily::Visualizer => {
                "Return an inline visual without opening a persistent artifact lane.".to_string()
            }
            StudioLaneFamily::Integrations => {
                "Use the selected connector-backed route instead of a generic fallback.".to_string()
            }
            _ if outcome_kind == StudioOutcomeKind::Conversation => {
                format!("Answer the request directly: {}.", summarize_prompt_fragment(intent))
            }
            _ => "Advance the selected Studio route while preserving route truth.".to_string(),
        },
    }
}

fn summarize_prompt_fragment(intent: &str) -> String {
    let trimmed = intent.trim();
    let mut summary = trimmed.chars().take(80).collect::<String>();
    if trimmed.chars().count() > 80 {
        summary.push('…');
    }
    summary
}

fn derive_source_selection(
    context: &StudioIntentContext,
    primary_lane: StudioLaneFamily,
    request_frame: Option<&StudioNormalizedRequestFrame>,
    routing_hints: &[String],
    active_artifact_id: Option<&str>,
) -> StudioSourceSelection {
    let specialized_policy =
        studio_specialized_domain_kind(request_frame).map(studio_specialized_domain_policy);
    let mut candidate_sources = Vec::new();
    let mut push_unique = |source: StudioSourceFamily| {
        if !candidate_sources.contains(&source) {
            candidate_sources.push(source);
        }
    };

    if active_artifact_id.is_some() {
        push_unique(StudioSourceFamily::ArtifactContext);
    }
    if context.references_previous_conversation() {
        push_unique(StudioSourceFamily::ConversationRetrieval);
    }
    if context.references_memory_context() {
        push_unique(StudioSourceFamily::Memory);
    }
    push_unique(StudioSourceFamily::ConversationContext);

    let selected_source = if active_artifact_id.is_some() {
        StudioSourceFamily::ArtifactContext
    } else if routing_hint_flag(routing_hints, "connector_intent_detected") {
        push_unique(StudioSourceFamily::Connector);
        StudioSourceFamily::Connector
    } else if routing_hint_flag(routing_hints, "workspace_grounding_required") {
        push_unique(StudioSourceFamily::Workspace);
        StudioSourceFamily::Workspace
    } else if routing_hint_flag(routing_hints, "currentness_override")
        || primary_lane == StudioLaneFamily::Research
        || matches!(
            request_frame,
            Some(
                StudioNormalizedRequestFrame::Weather(_)
                    | StudioNormalizedRequestFrame::Sports(_)
                    | StudioNormalizedRequestFrame::Places(_)
                    | StudioNormalizedRequestFrame::Recipe(_)
            )
        )
    {
        if matches!(
            request_frame,
            Some(
                StudioNormalizedRequestFrame::Weather(_)
                    | StudioNormalizedRequestFrame::Sports(_)
                    | StudioNormalizedRequestFrame::Places(_)
                    | StudioNormalizedRequestFrame::Recipe(_)
                    | StudioNormalizedRequestFrame::UserInput(_)
            )
        ) {
            push_unique(StudioSourceFamily::SpecializedTool);
            push_unique(StudioSourceFamily::WebSearch);
            StudioSourceFamily::SpecializedTool
        } else {
            push_unique(StudioSourceFamily::WebSearch);
            StudioSourceFamily::WebSearch
        }
    } else if matches!(
        request_frame,
        Some(StudioNormalizedRequestFrame::MessageCompose(_))
    ) {
        if routing_hint_flag(routing_hints, "connector_intent_detected") {
            push_unique(StudioSourceFamily::Connector);
            StudioSourceFamily::Connector
        } else {
            StudioSourceFamily::DirectAnswer
        }
    } else if context.references_memory_context() {
        StudioSourceFamily::Memory
    } else if context.references_previous_conversation() {
        StudioSourceFamily::ConversationRetrieval
    } else {
        StudioSourceFamily::DirectAnswer
    };

    push_unique(selected_source);

    let explicit_user_source = active_artifact_id.is_some()
        || routing_hint_flag(routing_hints, "connector_intent_detected")
        || routing_hint_flag(routing_hints, "workspace_grounding_required")
        || routing_hint_flag(routing_hints, "currentness_override")
        || tool_widget_family_hint(routing_hints).is_some()
        || context.references_previous_conversation()
        || context.references_memory_context();

    let fallback_reason = if routing_hint_flag(routing_hints, "connector_missing") {
        Some("connector route is preferred but unavailable in this runtime".to_string())
    } else if routing_hint_flag(routing_hints, "connector_auth_required") {
        Some("connector route is preferred but still needs authentication".to_string())
    } else if request_frame
        .is_some_and(|frame| !studio_request_frame_missing_slots(frame).is_empty())
    {
        Some(
            specialized_policy
                .map(|policy| policy.missing_slot_fallback_reason.to_string())
                .unwrap_or_else(|| {
                    "required lane slots are still missing, so execution is blocked on clarification"
                        .to_string()
                }),
        )
    } else {
        None
    };

    StudioSourceSelection {
        candidate_sources,
        selected_source,
        explicit_user_source,
        fallback_reason,
    }
}

fn derive_lane_transitions(
    primary_lane: StudioLaneFamily,
    secondary_lanes: &[StudioLaneFamily],
    request_frame: Option<&StudioNormalizedRequestFrame>,
    needs_clarification: bool,
    clarification_questions: &[String],
    routing_hints: &[String],
) -> Vec<StudioLaneTransition> {
    let mut transitions = vec![StudioLaneTransition {
        transition_kind: StudioLaneTransitionKind::Planned,
        from_lane: None,
        to_lane: primary_lane,
        reason: planned_transition_reason(primary_lane, request_frame, routing_hints),
        evidence: planned_transition_evidence(primary_lane, request_frame, routing_hints),
    }];

    for secondary_lane in secondary_lanes {
        transitions.push(StudioLaneTransition {
            transition_kind: StudioLaneTransitionKind::Planned,
            from_lane: Some(primary_lane),
            to_lane: *secondary_lane,
            reason: secondary_transition_reason(primary_lane, *secondary_lane, request_frame),
            evidence: secondary_transition_evidence(primary_lane, *secondary_lane, routing_hints),
        });
    }

    if needs_clarification && primary_lane != StudioLaneFamily::Conversation {
        transitions.push(StudioLaneTransition {
            transition_kind: StudioLaneTransitionKind::Reactive,
            from_lane: Some(primary_lane),
            to_lane: StudioLaneFamily::Conversation,
            reason: "Clarification is required before Studio can continue in the selected lane."
                .to_string(),
            evidence: clarification_questions.to_vec(),
        });
    }

    transitions
}

fn planned_transition_reason(
    primary_lane: StudioLaneFamily,
    request_frame: Option<&StudioNormalizedRequestFrame>,
    routing_hints: &[String],
) -> String {
    match request_frame {
        Some(StudioNormalizedRequestFrame::Weather(_)) => {
            "The prompt maps to a weather-specific lane with location-bound tool semantics."
                .to_string()
        }
        Some(StudioNormalizedRequestFrame::Sports(_)) => {
            "The prompt maps to a sports-specific lane with team and league semantics.".to_string()
        }
        Some(StudioNormalizedRequestFrame::Places(_)) => {
            "The prompt maps to a places lane with category and anchor-location semantics."
                .to_string()
        }
        Some(StudioNormalizedRequestFrame::Recipe(_)) => {
            "The prompt maps to a recipe lane that benefits from a specialized response shape."
                .to_string()
        }
        Some(StudioNormalizedRequestFrame::MessageCompose(_)) => {
            "The prompt is best treated as a communication/composition task.".to_string()
        }
        Some(StudioNormalizedRequestFrame::UserInput(_)) => {
            "The prompt benefits from a structured user-input lane before execution.".to_string()
        }
        None => {
            if routing_hint_flag(routing_hints, "connector_intent_detected") {
                "A connector-capable route outranks a broad fallback here.".to_string()
            } else if routing_hint_flag(routing_hints, "workspace_grounding_required") {
                "The request must be grounded in the current workspace.".to_string()
            } else {
                format!("Studio selected the {:?} lane for this turn.", primary_lane)
                    .to_ascii_lowercase()
            }
        }
    }
}

fn planned_transition_evidence(
    _primary_lane: StudioLaneFamily,
    request_frame: Option<&StudioNormalizedRequestFrame>,
    routing_hints: &[String],
) -> Vec<String> {
    let mut evidence = routing_hints.to_vec();
    if let Some(frame) = request_frame {
        evidence.push(match frame {
            StudioNormalizedRequestFrame::Weather(_) => "request_frame:weather".to_string(),
            StudioNormalizedRequestFrame::Sports(_) => "request_frame:sports".to_string(),
            StudioNormalizedRequestFrame::Places(_) => "request_frame:places".to_string(),
            StudioNormalizedRequestFrame::Recipe(_) => "request_frame:recipe".to_string(),
            StudioNormalizedRequestFrame::MessageCompose(_) => {
                "request_frame:message_compose".to_string()
            }
            StudioNormalizedRequestFrame::UserInput(_) => "request_frame:user_input".to_string(),
        });
    }
    evidence
}

fn secondary_transition_reason(
    primary_lane: StudioLaneFamily,
    secondary_lane: StudioLaneFamily,
    request_frame: Option<&StudioNormalizedRequestFrame>,
) -> String {
    match (primary_lane, secondary_lane, request_frame) {
        (
            StudioLaneFamily::Communication,
            StudioLaneFamily::Integrations,
            Some(StudioNormalizedRequestFrame::MessageCompose(_)),
        ) => {
            "The message lane will lean on a connected provider when one is available.".to_string()
        }
        (StudioLaneFamily::Research, StudioLaneFamily::ToolWidget, _) => {
            "The research lane can land through a specialized tool-widget surface.".to_string()
        }
        (StudioLaneFamily::UserInput, StudioLaneFamily::ToolWidget, _) => {
            "The structured input lane projects through the user-input widget.".to_string()
        }
        (StudioLaneFamily::Artifact, StudioLaneFamily::Coding, _) => {
            "The artifact lane depends on workspace-grounded coding support.".to_string()
        }
        _ => format!(
            "Studio retained the {:?} lane as a secondary assist for this turn.",
            secondary_lane
        )
        .to_ascii_lowercase(),
    }
}

fn secondary_transition_evidence(
    primary_lane: StudioLaneFamily,
    secondary_lane: StudioLaneFamily,
    routing_hints: &[String],
) -> Vec<String> {
    let mut evidence = routing_hints.to_vec();
    evidence.push(
        format!("secondary_lane:{:?}->{:?}", primary_lane, secondary_lane).to_ascii_lowercase(),
    );
    evidence
}

fn derive_orchestration_state(
    intent: &str,
    primary_lane: StudioLaneFamily,
    outcome_kind: StudioOutcomeKind,
    execution_strategy: StudioExecutionStrategy,
    execution_mode_decision: Option<&StudioExecutionModeDecision>,
    needs_clarification: bool,
    clarification_questions: &[String],
    request_frame: Option<&StudioNormalizedRequestFrame>,
) -> Option<StudioOrchestrationState> {
    let should_surface = needs_clarification
        || outcome_kind == StudioOutcomeKind::Artifact
        || !matches!(execution_strategy, StudioExecutionStrategy::SinglePass)
        || matches!(
            primary_lane,
            StudioLaneFamily::Research
                | StudioLaneFamily::Coding
                | StudioLaneFamily::Integrations
                | StudioLaneFamily::Communication
                | StudioLaneFamily::UserInput
        );
    if !should_surface {
        return None;
    }

    let objective_status = if needs_clarification {
        StudioWorkStatus::Blocked
    } else {
        StudioWorkStatus::InProgress
    };
    let objective = StudioObjectiveState {
        objective_id: "studio_objective".to_string(),
        title: summarize_prompt_fragment(intent),
        status: objective_status,
        success_criteria: success_criteria_for_lane(primary_lane, outcome_kind),
    };
    let tasks = orchestration_tasks(
        primary_lane,
        outcome_kind,
        needs_clarification,
        request_frame,
    );
    let checkpoints = vec![
        StudioCheckpointState {
            checkpoint_id: "route_contract".to_string(),
            label: "Route contract recorded".to_string(),
            status: StudioWorkStatus::Complete,
            summary: "Studio captured a typed route, source, and lane contract.".to_string(),
        },
        StudioCheckpointState {
            checkpoint_id: "lane_readiness".to_string(),
            label: "Lane readiness".to_string(),
            status: if needs_clarification {
                StudioWorkStatus::Blocked
            } else {
                StudioWorkStatus::Pending
            },
            summary: if needs_clarification {
                clarification_questions
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "Studio is waiting for clarification.".to_string())
            } else {
                "Studio can continue into lane execution.".to_string()
            },
        },
    ];
    let completion_invariant = Some(StudioCompletionInvariant {
        summary: completion_invariant_summary(primary_lane, outcome_kind),
        satisfied: false,
        outstanding_requirements: outstanding_requirements(
            primary_lane,
            outcome_kind,
            needs_clarification,
            request_frame,
            execution_mode_decision,
        ),
    });

    Some(StudioOrchestrationState {
        objective: Some(objective),
        tasks,
        checkpoints,
        completion_invariant,
    })
}

fn success_criteria_for_lane(
    primary_lane: StudioLaneFamily,
    outcome_kind: StudioOutcomeKind,
) -> Vec<String> {
    match primary_lane {
        StudioLaneFamily::Research => vec![
            "Resolve the required scope for the research lane.".to_string(),
            "Return a grounded answer rather than a speculative reply.".to_string(),
        ],
        StudioLaneFamily::Coding => vec![
            "Inspect or mutate the workspace in the correct boundary.".to_string(),
            "Surface verification truth alongside the result.".to_string(),
        ],
        StudioLaneFamily::Integrations => vec![
            "Use the selected connector-backed route when available.".to_string(),
            "Avoid broad fallbacks unless the preferred connector path is blocked.".to_string(),
        ],
        StudioLaneFamily::Artifact if outcome_kind == StudioOutcomeKind::Artifact => vec![
            "Materialize the requested artifact.".to_string(),
            "Verify the artifact contract before promoting it.".to_string(),
        ],
        _ => vec!["Finish the selected Studio lane truthfully.".to_string()],
    }
}

fn orchestration_tasks(
    primary_lane: StudioLaneFamily,
    outcome_kind: StudioOutcomeKind,
    needs_clarification: bool,
    request_frame: Option<&StudioNormalizedRequestFrame>,
) -> Vec<StudioTaskUnitState> {
    let blocked_or_pending = if needs_clarification {
        StudioWorkStatus::Blocked
    } else {
        StudioWorkStatus::Pending
    };
    let execution_lane = match primary_lane {
        StudioLaneFamily::Communication if outcome_kind != StudioOutcomeKind::Artifact => {
            StudioLaneFamily::Communication
        }
        lane => lane,
    };

    match primary_lane {
        StudioLaneFamily::Artifact => vec![
            StudioTaskUnitState {
                task_id: "artifact_brief".to_string(),
                label: "Lock the deliverable contract".to_string(),
                status: if needs_clarification {
                    StudioWorkStatus::Blocked
                } else {
                    StudioWorkStatus::InProgress
                },
                lane_family: StudioLaneFamily::Artifact,
                depends_on: Vec::new(),
                summary: Some(
                    "Studio should keep the artifact request coherent before generation."
                        .to_string(),
                ),
            },
            StudioTaskUnitState {
                task_id: "artifact_materialize".to_string(),
                label: "Materialize the artifact".to_string(),
                status: blocked_or_pending,
                lane_family: StudioLaneFamily::Artifact,
                depends_on: vec!["artifact_brief".to_string()],
                summary: None,
            },
            StudioTaskUnitState {
                task_id: "artifact_verify".to_string(),
                label: "Verify the artifact contract".to_string(),
                status: blocked_or_pending,
                lane_family: StudioLaneFamily::Artifact,
                depends_on: vec!["artifact_materialize".to_string()],
                summary: None,
            },
        ],
        _ => {
            let resolve_label = if let Some(frame) = request_frame {
                match frame {
                    StudioNormalizedRequestFrame::Weather(_) => {
                        "Resolve the weather scope".to_string()
                    }
                    StudioNormalizedRequestFrame::Sports(_) => {
                        "Resolve the sports target".to_string()
                    }
                    StudioNormalizedRequestFrame::Places(_) => {
                        "Resolve the places request frame".to_string()
                    }
                    StudioNormalizedRequestFrame::Recipe(_) => {
                        "Resolve the recipe request frame".to_string()
                    }
                    StudioNormalizedRequestFrame::MessageCompose(_) => {
                        "Resolve the message composition frame".to_string()
                    }
                    StudioNormalizedRequestFrame::UserInput(_) => {
                        "Resolve the required options".to_string()
                    }
                }
            } else {
                "Resolve the lane inputs".to_string()
            };
            vec![
                StudioTaskUnitState {
                    task_id: "lane_inputs".to_string(),
                    label: resolve_label,
                    status: if needs_clarification {
                        StudioWorkStatus::Blocked
                    } else {
                        StudioWorkStatus::InProgress
                    },
                    lane_family: execution_lane,
                    depends_on: Vec::new(),
                    summary: Some(
                        "Studio should make the lane contract explicit before execution."
                            .to_string(),
                    ),
                },
                StudioTaskUnitState {
                    task_id: "lane_execute".to_string(),
                    label: "Execute the selected lane".to_string(),
                    status: blocked_or_pending,
                    lane_family: execution_lane,
                    depends_on: vec!["lane_inputs".to_string()],
                    summary: None,
                },
                StudioTaskUnitState {
                    task_id: "lane_finish".to_string(),
                    label: "Finish the response truthfully".to_string(),
                    status: blocked_or_pending,
                    lane_family: StudioLaneFamily::Conversation,
                    depends_on: vec!["lane_execute".to_string()],
                    summary: None,
                },
            ]
        }
    }
}

fn completion_invariant_summary(
    primary_lane: StudioLaneFamily,
    outcome_kind: StudioOutcomeKind,
) -> String {
    match primary_lane {
        StudioLaneFamily::Artifact if outcome_kind == StudioOutcomeKind::Artifact => {
            "The requested artifact exists and its verification contract is surfaced truthfully."
                .to_string()
        }
        StudioLaneFamily::Research => {
            "The answer is grounded in the selected fresh-information lane.".to_string()
        }
        StudioLaneFamily::Coding => {
            "The result is grounded in the current workspace and paired with verification truth."
                .to_string()
        }
        StudioLaneFamily::Integrations => {
            "Studio uses the selected connector-backed route or makes the blocking condition explicit."
                .to_string()
        }
        _ => "Studio finishes the selected lane without hiding blockers or substitutions.".to_string(),
    }
}

fn outstanding_requirements(
    primary_lane: StudioLaneFamily,
    outcome_kind: StudioOutcomeKind,
    needs_clarification: bool,
    request_frame: Option<&StudioNormalizedRequestFrame>,
    execution_mode_decision: Option<&StudioExecutionModeDecision>,
) -> Vec<String> {
    let mut requirements = Vec::new();
    if needs_clarification {
        requirements.push("resolve_clarification".to_string());
    }
    if let Some(frame) = request_frame {
        match frame {
            StudioNormalizedRequestFrame::Weather(frame) => {
                requirements.extend(frame.missing_slots.clone());
            }
            StudioNormalizedRequestFrame::Sports(frame) => {
                requirements.extend(frame.missing_slots.clone());
            }
            StudioNormalizedRequestFrame::Places(frame) => {
                requirements.extend(frame.missing_slots.clone());
            }
            StudioNormalizedRequestFrame::Recipe(frame) => {
                requirements.extend(frame.missing_slots.clone());
            }
            StudioNormalizedRequestFrame::MessageCompose(frame) => {
                requirements.extend(frame.missing_slots.clone());
            }
            StudioNormalizedRequestFrame::UserInput(frame) => {
                requirements.extend(frame.missing_slots.clone());
            }
        }
    }
    if outcome_kind == StudioOutcomeKind::Artifact {
        requirements.push("materialize_artifact".to_string());
        requirements.push("verify_artifact".to_string());
    } else {
        requirements.push("execute_lane".to_string());
        requirements.push("deliver_response".to_string());
    }
    if execution_mode_decision.is_some_and(|decision| decision.work_graph_required) {
        requirements.push("complete_work_graph".to_string());
    }
    if primary_lane == StudioLaneFamily::Coding {
        requirements.push("workspace_verification".to_string());
    }
    requirements
}
