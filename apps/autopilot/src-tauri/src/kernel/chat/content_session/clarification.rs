use super::decision_record::{decision_evidence_item_flag, decision_evidence_item_prefixed_value};
use super::*;
use ioi_api::runtime_harness::{
    chat_normalized_request_clarification_slots, chat_specialized_domain_kind,
    runtime_locality_scope_hint, ChatSpecializedDomainKind,
};

fn current_area_option_available() -> bool {
    runtime_locality_scope_hint().is_some()
}

fn use_current_area_option(
    description: &str,
    recommended: bool,
) -> crate::models::ClarificationOption {
    crate::models::ClarificationOption {
        id: "use_current_area".to_string(),
        label: "Use my area".to_string(),
        description: description.to_string(),
        recommended,
    }
}

pub(super) fn specialized_domain_clarification_question(
    outcome_request: &ChatOutcomeRequest,
) -> Option<String> {
    let frame = outcome_request.normalized_request.as_ref()?;
    let kind = chat_specialized_domain_kind(Some(frame))?;
    let blocking_slots = chat_normalized_request_clarification_slots(frame);
    if blocking_slots.is_empty() {
        return None;
    }

    Some(match kind {
        ChatSpecializedDomainKind::Weather => {
            "Which city or area should Chat check for the weather?".to_string()
        }
        ChatSpecializedDomainKind::Sports => {
            if blocking_slots.iter().any(|slot| slot == "team_or_target") {
                "Which team, player, or matchup should Chat use for the sports lookup?".to_string()
            } else {
                "Which league should Chat use for the sports lookup?".to_string()
            }
        }
        ChatSpecializedDomainKind::Places => {
            if blocking_slots.iter().any(|slot| {
                slot == "search_anchor" || slot == "location_scope" || slot == "location"
            }) {
                "Which neighborhood, city, or anchor location should Chat search around?"
                    .to_string()
            } else {
                "What kind of place should Chat look for?".to_string()
            }
        }
        ChatSpecializedDomainKind::Recipe => "Which dish or recipe should Chat make?".to_string(),
        ChatSpecializedDomainKind::MessageCompose => {
            if blocking_slots.iter().any(|slot| slot == "channel") {
                "Which channel should Chat draft this for: email, Slack, text, or chat?".to_string()
            } else if blocking_slots
                .iter()
                .any(|slot| slot == "recipient_context")
            {
                "Who is this message for, or how should Chat describe the recipient context?"
                    .to_string()
            } else {
                "Should Chat draft a new message, reply to someone, or summarize a thread?"
                    .to_string()
            }
        }
        ChatSpecializedDomainKind::UserInput => {
            "What options or decision shape should Chat present?".to_string()
        }
    })
}

fn specialized_domain_clarification_options(
    outcome_request: &ChatOutcomeRequest,
) -> Vec<crate::models::ClarificationOption> {
    let Some(frame) = outcome_request.normalized_request.as_ref() else {
        return Vec::new();
    };
    let Some(kind) = chat_specialized_domain_kind(Some(frame)) else {
        return Vec::new();
    };
    let blocking_slots = chat_normalized_request_clarification_slots(frame);
    if blocking_slots.is_empty() {
        return Vec::new();
    }

    match kind {
        ChatSpecializedDomainKind::Weather => {
            let locality_available = current_area_option_available();
            let mut options = vec![crate::models::ClarificationOption {
                id: "share_city".to_string(),
                label: "Share a city".to_string(),
                description: "Tell Chat which city or area to use for the forecast.".to_string(),
                recommended: !locality_available,
            }];
            if locality_available {
                options.push(use_current_area_option(
                    "Use the current area already available to this Chat session.",
                    true,
                ));
            }
            options.push(crate::models::ClarificationOption {
                id: "general_weather_guidance".to_string(),
                label: "General advice".to_string(),
                description:
                    "Skip the forecast and give broad clothing or planning guidance instead."
                        .to_string(),
                recommended: false,
            });
            options
        }
        ChatSpecializedDomainKind::Sports => {
            if blocking_slots.iter().any(|slot| slot == "team_or_target") {
                vec![
                    crate::models::ClarificationOption {
                        id: "share_team_or_matchup".to_string(),
                        label: "Share a team".to_string(),
                        description:
                            "Tell Chat the team, player, or matchup to anchor the sports lookup."
                                .to_string(),
                        recommended: true,
                    },
                    crate::models::ClarificationOption {
                        id: "league_overview".to_string(),
                        label: "League overview".to_string(),
                        description:
                            "Use the current league context and give a broader overview instead."
                                .to_string(),
                        recommended: false,
                    },
                    crate::models::ClarificationOption {
                        id: "recent_results_only".to_string(),
                        label: "Recent results".to_string(),
                        description:
                            "Focus on the latest headlines or recent results rather than a named target."
                                .to_string(),
                        recommended: false,
                    },
                ]
            } else {
                vec![
                    crate::models::ClarificationOption {
                        id: "share_league".to_string(),
                        label: "Choose a league".to_string(),
                        description: "Tell Chat which league to use before it continues."
                            .to_string(),
                        recommended: true,
                    },
                    crate::models::ClarificationOption {
                        id: "nba_default".to_string(),
                        label: "Use NBA".to_string(),
                        description: "Treat the request as an NBA lookup.".to_string(),
                        recommended: false,
                    },
                    crate::models::ClarificationOption {
                        id: "nfl_default".to_string(),
                        label: "Use NFL".to_string(),
                        description: "Treat the request as an NFL lookup.".to_string(),
                        recommended: false,
                    },
                ]
            }
        }
        ChatSpecializedDomainKind::Places => {
            if blocking_slots.iter().any(|slot| {
                slot == "search_anchor" || slot == "location_scope" || slot == "location"
            }) {
                let locality_available = current_area_option_available();
                let mut options = vec![crate::models::ClarificationOption {
                    id: "share_location_anchor".to_string(),
                    label: "Share a location".to_string(),
                    description: "Tell Chat the neighborhood, city, or landmark to search around."
                        .to_string(),
                    recommended: !locality_available,
                }];
                if locality_available {
                    options.push(use_current_area_option(
                        "Use the current area already available to this Chat session.",
                        true,
                    ));
                }
                options.push(crate::models::ClarificationOption {
                        id: "broad_city_recs".to_string(),
                        label: "Broad city picks".to_string(),
                        description:
                            "Give a broader city-level recommendation list instead of a tight anchor search."
                                .to_string(),
                        recommended: false,
                    });
                options
            } else {
                vec![
                    crate::models::ClarificationOption {
                        id: "share_place_category".to_string(),
                        label: "Choose a category".to_string(),
                        description: "Tell Chat what kind of place to search for.".to_string(),
                        recommended: true,
                    },
                    crate::models::ClarificationOption {
                        id: "coffee_shops".to_string(),
                        label: "Coffee shops".to_string(),
                        description: "Search for coffee shops.".to_string(),
                        recommended: false,
                    },
                    crate::models::ClarificationOption {
                        id: "restaurants".to_string(),
                        label: "Restaurants".to_string(),
                        description: "Search for restaurants.".to_string(),
                        recommended: false,
                    },
                ]
            }
        }
        ChatSpecializedDomainKind::Recipe => vec![
            crate::models::ClarificationOption {
                id: "name_the_dish".to_string(),
                label: "Name the dish".to_string(),
                description: "Tell Chat the exact dish or recipe you want.".to_string(),
                recommended: true,
            },
            crate::models::ClarificationOption {
                id: "use_a_cuisine".to_string(),
                label: "Use a cuisine".to_string(),
                description: "Give a cuisine or style so Chat can suggest a fitting dish."
                    .to_string(),
                recommended: false,
            },
            crate::models::ClarificationOption {
                id: "general_cooking_help".to_string(),
                label: "Cooking help".to_string(),
                description: "Switch to general cooking guidance instead of a specific recipe."
                    .to_string(),
                recommended: false,
            },
        ],
        ChatSpecializedDomainKind::MessageCompose => {
            if blocking_slots.iter().any(|slot| slot == "channel") {
                vec![
                    crate::models::ClarificationOption {
                        id: "draft_email".to_string(),
                        label: "Email".to_string(),
                        description: "Draft this as an email.".to_string(),
                        recommended: true,
                    },
                    crate::models::ClarificationOption {
                        id: "draft_slack".to_string(),
                        label: "Slack".to_string(),
                        description: "Draft this as a Slack message.".to_string(),
                        recommended: false,
                    },
                    crate::models::ClarificationOption {
                        id: "draft_text".to_string(),
                        label: "Text".to_string(),
                        description: "Draft this as a text message.".to_string(),
                        recommended: false,
                    },
                ]
            } else if blocking_slots
                .iter()
                .any(|slot| slot == "recipient_context")
            {
                vec![
                    crate::models::ClarificationOption {
                        id: "name_recipient".to_string(),
                        label: "Name recipient".to_string(),
                        description: "Tell Chat who the message is for or how to describe them."
                            .to_string(),
                        recommended: true,
                    },
                    crate::models::ClarificationOption {
                        id: "keep_generic".to_string(),
                        label: "Keep generic".to_string(),
                        description: "Write a generic draft without naming the recipient."
                            .to_string(),
                        recommended: false,
                    },
                    crate::models::ClarificationOption {
                        id: "describe_relationship".to_string(),
                        label: "Describe relationship".to_string(),
                        description:
                            "Describe the recipient by relationship, such as manager or client."
                                .to_string(),
                        recommended: false,
                    },
                ]
            } else {
                vec![
                    crate::models::ClarificationOption {
                        id: "new_draft".to_string(),
                        label: "New draft".to_string(),
                        description: "Draft a new outbound message.".to_string(),
                        recommended: true,
                    },
                    crate::models::ClarificationOption {
                        id: "reply_to_message".to_string(),
                        label: "Reply".to_string(),
                        description: "Treat this as a reply to an existing message.".to_string(),
                        recommended: false,
                    },
                    crate::models::ClarificationOption {
                        id: "summarize_thread".to_string(),
                        label: "Summarize".to_string(),
                        description: "Summarize a thread or draft summary notes instead."
                            .to_string(),
                        recommended: false,
                    },
                ]
            }
        }
        ChatSpecializedDomainKind::UserInput => vec![
            crate::models::ClarificationOption {
                id: "add_options".to_string(),
                label: "Add options".to_string(),
                description: "Tell Chat what choices should appear in the decision surface."
                    .to_string(),
                recommended: true,
            },
            crate::models::ClarificationOption {
                id: "set_decision_rule".to_string(),
                label: "Set decision rule".to_string(),
                description: "Tell Chat how the options should be ranked or compared.".to_string(),
                recommended: false,
            },
            crate::models::ClarificationOption {
                id: "draft_options_for_me".to_string(),
                label: "Draft options".to_string(),
                description:
                    "Ask Chat to draft a first set of candidate options for you to refine."
                        .to_string(),
                recommended: false,
            },
        ],
    }
}

pub(in crate::kernel::chat) fn clarification_request_for_outcome_request(
    outcome_request: &ChatOutcomeRequest,
) -> Option<crate::models::ClarificationRequest> {
    if !outcome_request.needs_clarification {
        return None;
    }

    let question = outcome_request
        .clarification_questions
        .first()
        .cloned()
        .unwrap_or_else(|| "What should Chat create before it continues?".to_string());
    let has_hint = |needle: &str| decision_evidence_item_flag(outcome_request, needle);
    let question = if has_hint("prioritization_request") && has_hint("user_input_preferred") {
        "What should drive the ranking: impact, urgency, or return on investment?".to_string()
    } else if has_hint("connector_missing") {
        let target_label =
            decision_evidence_item_prefixed_value(outcome_request, "connector_target_label:")
                .unwrap_or_else(|| "That connector".to_string());
        format!(
            "{target_label} is not available in this runtime yet. Should Chat wait for you to connect it, or should I work from pasted data instead?"
        )
    } else if has_hint("connector_auth_required") {
        let target_label =
            decision_evidence_item_prefixed_value(outcome_request, "connector_target_label:")
                .unwrap_or_else(|| "That connector".to_string());
        format!(
            "{target_label} is available here but not connected yet. Should Chat wait for you to connect it, or should I use another source?"
        )
    } else if has_hint("location_required_for_weather_advice") {
        "What city should Chat check the weather for?".to_string()
    } else if let Some(domain_question) = specialized_domain_clarification_question(outcome_request)
    {
        domain_question
    } else {
        question
    };
    let context_hint = if outcome_request.decision_evidence.is_empty() {
        None
    } else {
        Some(format!(
            "Routing hints: {}",
            outcome_request.decision_evidence.join(", ")
        ))
    };
    let options = route_clarification_options(outcome_request);
    let evidence_snippet = format!(
        "Chat paused before selecting the outcome surface because it needs clarification: {}",
        question
    );

    Some(crate::models::ClarificationRequest {
        kind: "intent_resolution".to_string(),
        question,
        tool_name: "chat::route_clarification".to_string(),
        failure_class: Some("UserInterventionNeeded".to_string()),
        evidence_snippet: Some(evidence_snippet),
        context_hint,
        options,
        allow_other: true,
    })
}

fn route_clarification_options(
    outcome_request: &ChatOutcomeRequest,
) -> Vec<crate::models::ClarificationOption> {
    let has_hint = |needle: &str| decision_evidence_item_flag(outcome_request, needle);

    if has_hint("connector_missing") {
        return vec![
            crate::models::ClarificationOption {
                id: "open_capabilities_to_connect".to_string(),
                label: "Connect it".to_string(),
                description:
                    "Open Chat capabilities and connect the missing service before retrying."
                        .to_string(),
                recommended: true,
            },
            crate::models::ClarificationOption {
                id: "paste_the_source_data".to_string(),
                label: "Paste the data".to_string(),
                description:
                    "Paste the messages, issues, or records here so Chat can work locally."
                        .to_string(),
                recommended: false,
            },
            crate::models::ClarificationOption {
                id: "use_a_different_source".to_string(),
                label: "Use another source".to_string(),
                description: "Switch to a different connected source that can answer the request."
                    .to_string(),
                recommended: false,
            },
        ];
    }

    if has_hint("connector_auth_required") {
        return vec![
            crate::models::ClarificationOption {
                id: "connect_the_existing_connector".to_string(),
                label: "Connect now".to_string(),
                description: "Finish connector authentication, then let Chat retry the request."
                    .to_string(),
                recommended: true,
            },
            crate::models::ClarificationOption {
                id: "use_a_different_source".to_string(),
                label: "Use another source".to_string(),
                description: "Answer from a different connected system or from pasted source data."
                    .to_string(),
                recommended: false,
            },
            crate::models::ClarificationOption {
                id: "explain_how_to_connect_it".to_string(),
                label: "Explain setup".to_string(),
                description: "Ask Chat to explain how to connect the required service first."
                    .to_string(),
                recommended: false,
            },
        ];
    }

    if has_hint("currentness_scope_ambiguous") {
        return vec![
            crate::models::ClarificationOption {
                id: "local_events".to_string(),
                label: "Local events".to_string(),
                description: "Use a city or area to look for events happening this week."
                    .to_string(),
                recommended: true,
            },
            crate::models::ClarificationOption {
                id: "specific_topic".to_string(),
                label: "Specific topic".to_string(),
                description: "Focus on one subject and summarize this week's developments."
                    .to_string(),
                recommended: false,
            },
            crate::models::ClarificationOption {
                id: "general_news".to_string(),
                label: "General news".to_string(),
                description: "Give a broad snapshot of major news from this week.".to_string(),
                recommended: false,
            },
        ];
    }

    if has_hint("location_required_for_weather_advice") {
        let locality_available = current_area_option_available();
        let mut options = vec![crate::models::ClarificationOption {
            id: "share_city".to_string(),
            label: "Share a city".to_string(),
            description: "Tell Chat which city to check before it answers.".to_string(),
            recommended: !locality_available,
        }];
        if locality_available {
            options.push(use_current_area_option(
                "Use the current area already available to this Chat session.",
                true,
            ));
        }
        options.push(crate::models::ClarificationOption {
            id: "general_layering".to_string(),
            label: "General advice".to_string(),
            description: "Skip the forecast and give generic jacket advice instead.".to_string(),
            recommended: false,
        });
        return options;
    }

    if has_hint("prioritization_request") && has_hint("user_input_preferred") {
        return vec![
            crate::models::ClarificationOption {
                id: "impact_first".to_string(),
                label: "Impact first".to_string(),
                description: "Rank the projects by how much they improve the home or daily life."
                    .to_string(),
                recommended: true,
            },
            crate::models::ClarificationOption {
                id: "urgency_first".to_string(),
                label: "Urgency first".to_string(),
                description: "Rank the projects by which ones feel most time-sensitive."
                    .to_string(),
                recommended: false,
            },
            crate::models::ClarificationOption {
                id: "roi_first".to_string(),
                label: "ROI first".to_string(),
                description: "Rank the projects by expected value or return relative to cost."
                    .to_string(),
                recommended: false,
            },
        ];
    }

    let specialized_options = specialized_domain_clarification_options(outcome_request);
    if !specialized_options.is_empty() {
        return specialized_options;
    }

    Vec::new()
}
