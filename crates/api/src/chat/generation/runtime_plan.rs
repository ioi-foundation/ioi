use super::*;
use std::{path::Path, sync::Arc, time::Duration};

pub(super) fn compact_local_html_materialization_prompt(
    renderer: ChatRendererKind,
    runtime_kind: ChatRuntimeProvenanceKind,
) -> bool {
    renderer == ChatRendererKind::HtmlIframe
        && runtime_kind == ChatRuntimeProvenanceKind::RealLocalRuntime
}

pub(crate) fn effective_candidate_generation_temperature(
    renderer: ChatRendererKind,
    runtime_kind: ChatRuntimeProvenanceKind,
    configured_temperature: f32,
) -> f32 {
    // Keep local HTML stability policy tied to runtime shape and prompt budget,
    // not to a particular model family label.
    if compact_local_html_materialization_prompt(renderer, runtime_kind) {
        if chat_modal_first_html_enabled() {
            return configured_temperature;
        }
        return configured_temperature.min(0.32);
    }

    configured_temperature
}

pub(super) fn effective_direct_author_temperature(
    renderer: ChatRendererKind,
    runtime_kind: ChatRuntimeProvenanceKind,
    configured_temperature: f32,
) -> f32 {
    if renderer == ChatRendererKind::HtmlIframe
        && runtime_kind == ChatRuntimeProvenanceKind::RealLocalRuntime
    {
        return configured_temperature.min(0.28);
    }

    effective_candidate_generation_temperature(renderer, runtime_kind, configured_temperature)
}

pub(crate) fn materialization_max_tokens_for_runtime(
    renderer: ChatRendererKind,
    runtime_kind: ChatRuntimeProvenanceKind,
) -> u32 {
    if compact_local_html_materialization_prompt(renderer, runtime_kind) {
        if chat_modal_first_html_enabled() {
            // Keep local structured HTML authoring comfortably above the
            // direct-author lane while avoiding oversized completions that
            // destabilize small local runners during JSON-mode generation.
            return 2800;
        }
        return 2200;
    }

    materialization_max_tokens(renderer)
}

pub(crate) fn materialization_max_tokens_for_execution_strategy(
    renderer: ChatRendererKind,
    execution_strategy: ChatExecutionStrategy,
    runtime_kind: ChatRuntimeProvenanceKind,
) -> u32 {
    if execution_strategy == ChatExecutionStrategy::DirectAuthor {
        let direct_author_budget = match renderer {
            ChatRendererKind::Markdown | ChatRendererKind::Mermaid => {
                if runtime_kind == ChatRuntimeProvenanceKind::RealLocalRuntime {
                    1200
                } else {
                    materialization_max_tokens(renderer).min(1800)
                }
            }
            ChatRendererKind::Svg | ChatRendererKind::PdfEmbed => {
                if runtime_kind == ChatRuntimeProvenanceKind::RealLocalRuntime {
                    1600
                } else {
                    materialization_max_tokens(renderer).min(2200)
                }
            }
            ChatRendererKind::HtmlIframe => {
                if runtime_kind == ChatRuntimeProvenanceKind::RealLocalRuntime {
                    // Keep local raw-document authoring bounded even when
                    // modal-first HTML is enabled. The direct-author lane is
                    // used for fast create/edit loops, and the larger
                    // structured-materialization budget is better reserved for the heavier
                    // structured materialization path.
                    2400
                } else {
                    materialization_max_tokens(renderer).min(2600)
                }
            }
            _ => 0,
        };
        if direct_author_budget > 0 {
            return direct_author_budget;
        }
    }

    materialization_max_tokens_for_runtime(renderer, runtime_kind)
}

pub(crate) fn materialization_repair_runtime_for_request(
    request: &ChatOutcomeArtifactRequest,
    production_runtime: &Arc<dyn InferenceRuntime>,
    repair_runtime: Option<&Arc<dyn InferenceRuntime>>,
) -> Arc<dyn InferenceRuntime> {
    let production_provenance = production_runtime.chat_runtime_provenance();
    if request.renderer == ChatRendererKind::HtmlIframe
        && production_provenance.kind == ChatRuntimeProvenanceKind::RealLocalRuntime
    {
        if let Some(runtime) = repair_runtime {
            let repair_provenance = runtime.chat_runtime_provenance();
            if repair_provenance.kind == ChatRuntimeProvenanceKind::RealLocalRuntime
                && !chat_runtime_provenance_matches(&repair_provenance, &production_provenance)
            {
                return runtime.clone();
            }
        }
    }

    production_runtime.clone()
}

pub(super) fn should_warm_local_html_generation_runtime(
    request: &ChatOutcomeArtifactRequest,
    planning_runtime: &Arc<dyn InferenceRuntime>,
    production_runtime: &Arc<dyn InferenceRuntime>,
) -> bool {
    if request.renderer != ChatRendererKind::HtmlIframe {
        return false;
    }

    let planning_provenance = planning_runtime.chat_runtime_provenance();
    let production_provenance = production_runtime.chat_runtime_provenance();
    production_provenance.kind == ChatRuntimeProvenanceKind::RealLocalRuntime
        && planning_provenance.kind == ChatRuntimeProvenanceKind::RealLocalRuntime
        && !chat_runtime_provenance_matches(&planning_provenance, &production_provenance)
}

pub(super) fn local_html_generation_warmup_timeout() -> Duration {
    Duration::from_secs(12)
}

pub(super) async fn warm_local_html_generation_runtime_if_needed(
    request: &ChatOutcomeArtifactRequest,
    planning_runtime: &Arc<dyn InferenceRuntime>,
    production_runtime: &Arc<dyn InferenceRuntime>,
) {
    if !should_warm_local_html_generation_runtime(request, planning_runtime, production_runtime) {
        return;
    }

    let production_provenance = production_runtime.chat_runtime_provenance();
    chat_generation_trace(format!(
        "artifact_generation:generation_warmup:start model={:?}",
        production_provenance.model
    ));
    match tokio::time::timeout(
        local_html_generation_warmup_timeout(),
        production_runtime.load_model([0u8; 32], Path::new("")),
    )
    .await
    {
        Ok(Ok(())) => chat_generation_trace(format!(
            "artifact_generation:generation_warmup:ok model={:?}",
            production_provenance.model
        )),
        Ok(Err(error)) => chat_generation_trace(format!(
            "artifact_generation:generation_warmup:error model={:?} error={}",
            production_provenance.model, error
        )),
        Err(_) => chat_generation_trace(format!(
            "artifact_generation:generation_warmup:timeout model={:?} timeout={}s",
            production_provenance.model,
            local_html_generation_warmup_timeout().as_secs()
        )),
    }
}

#[derive(Clone)]
pub struct ChatArtifactResolvedRuntimePlan {
    pub policy: ChatArtifactRuntimePolicy,
    pub planning_runtime: Arc<dyn InferenceRuntime>,
    pub generation_runtime: Arc<dyn InferenceRuntime>,
    pub acceptance_runtime: Arc<dyn InferenceRuntime>,
    pub repair_runtime: Arc<dyn InferenceRuntime>,
}

pub(super) fn chat_runtime_available(runtime: &Arc<dyn InferenceRuntime>) -> bool {
    runtime.chat_runtime_provenance().kind != ChatRuntimeProvenanceKind::InferenceUnavailable
}

pub(super) fn normalized_runtime_endpoint(endpoint: Option<&str>) -> Option<String> {
    let endpoint = endpoint?.trim();
    if endpoint.is_empty() {
        return None;
    }

    let (without_fragment, fragment) = endpoint.split_once('#').unwrap_or((endpoint, ""));
    let Some((base, query)) = without_fragment.split_once('?') else {
        return Some(endpoint.to_string());
    };

    let filtered_pairs = query
        .split('&')
        .filter(|pair| {
            let key = pair
                .split_once('=')
                .map(|(key, _)| key)
                .unwrap_or(*pair)
                .trim();
            !key.is_empty() && !key.eq_ignore_ascii_case("lane")
        })
        .collect::<Vec<_>>();

    let mut normalized = base.to_string();
    if !filtered_pairs.is_empty() {
        normalized.push('?');
        normalized.push_str(&filtered_pairs.join("&"));
    }
    if !fragment.is_empty() {
        normalized.push('#');
        normalized.push_str(fragment);
    }

    Some(normalized)
}

pub(super) fn chat_runtime_provenance_matches(
    left: &ChatRuntimeProvenance,
    right: &ChatRuntimeProvenance,
) -> bool {
    left.kind == right.kind
        && left.label == right.label
        && left.model == right.model
        && normalized_runtime_endpoint(left.endpoint.as_deref())
            == normalized_runtime_endpoint(right.endpoint.as_deref())
}

pub(super) fn generation_runtime_tier(
    provenance: &ChatRuntimeProvenance,
) -> ChatArtifactRuntimeTier {
    match provenance.kind {
        ChatRuntimeProvenanceKind::RealLocalRuntime => ChatArtifactRuntimeTier::Local,
        ChatRuntimeProvenanceKind::RealRemoteModelRuntime
        | ChatRuntimeProvenanceKind::OpaqueRuntime => ChatArtifactRuntimeTier::CostEffective,
        ChatRuntimeProvenanceKind::DeterministicContinuityFallback
        | ChatRuntimeProvenanceKind::FixtureRuntime
        | ChatRuntimeProvenanceKind::MockRuntime
        | ChatRuntimeProvenanceKind::InferenceUnavailable => ChatArtifactRuntimeTier::Deterministic,
    }
}

pub(super) fn runtime_step_policies(
    profile: ChatArtifactRuntimePolicyProfile,
    renderer: ChatRendererKind,
) -> Vec<ChatArtifactRuntimeStepPolicy> {
    let premium_html_planning = matches!(
        renderer,
        ChatRendererKind::HtmlIframe | ChatRendererKind::JsxSandbox
    );
    vec![
        ChatArtifactRuntimeStepPolicy {
            step: ChatArtifactRuntimeStep::OutcomeRouting,
            preferred_tier: ChatArtifactRuntimeTier::CostEffective,
            fallback_to_generation_runtime: true,
            require_distinct_runtime: false,
        },
        ChatArtifactRuntimeStepPolicy {
            step: ChatArtifactRuntimeStep::BlueprintPlanning,
            preferred_tier: match profile {
                ChatArtifactRuntimePolicyProfile::PremiumEndToEnd => {
                    ChatArtifactRuntimeTier::Premium
                }
                ChatArtifactRuntimePolicyProfile::PremiumPlanningLocalGeneration
                    if premium_html_planning =>
                {
                    ChatArtifactRuntimeTier::Premium
                }
                ChatArtifactRuntimePolicyProfile::FullyLocal
                | ChatArtifactRuntimePolicyProfile::LocalGenerationRemoteAcceptance
                | ChatArtifactRuntimePolicyProfile::PremiumPlanningLocalGeneration => {
                    ChatArtifactRuntimeTier::Local
                }
                ChatArtifactRuntimePolicyProfile::Auto => ChatArtifactRuntimeTier::CostEffective,
            },
            fallback_to_generation_runtime: true,
            require_distinct_runtime: false,
        },
        ChatArtifactRuntimeStepPolicy {
            step: ChatArtifactRuntimeStep::CandidateGeneration,
            preferred_tier: match profile {
                ChatArtifactRuntimePolicyProfile::PremiumEndToEnd => {
                    ChatArtifactRuntimeTier::Premium
                }
                ChatArtifactRuntimePolicyProfile::FullyLocal
                | ChatArtifactRuntimePolicyProfile::LocalGenerationRemoteAcceptance
                | ChatArtifactRuntimePolicyProfile::PremiumPlanningLocalGeneration => {
                    ChatArtifactRuntimeTier::Local
                }
                ChatArtifactRuntimePolicyProfile::Auto => ChatArtifactRuntimeTier::CostEffective,
            },
            fallback_to_generation_runtime: false,
            require_distinct_runtime: false,
        },
        ChatArtifactRuntimeStepPolicy {
            step: ChatArtifactRuntimeStep::ArtifactValidation,
            preferred_tier: match profile {
                ChatArtifactRuntimePolicyProfile::FullyLocal => ChatArtifactRuntimeTier::Local,
                _ => ChatArtifactRuntimeTier::Premium,
            },
            fallback_to_generation_runtime: true,
            require_distinct_runtime: matches!(
                profile,
                ChatArtifactRuntimePolicyProfile::LocalGenerationRemoteAcceptance
                    | ChatArtifactRuntimePolicyProfile::PremiumPlanningLocalGeneration
            ),
        },
        ChatArtifactRuntimeStepPolicy {
            step: ChatArtifactRuntimeStep::RepairPlanning,
            preferred_tier: match profile {
                ChatArtifactRuntimePolicyProfile::FullyLocal => ChatArtifactRuntimeTier::Local,
                ChatArtifactRuntimePolicyProfile::LocalGenerationRemoteAcceptance => {
                    ChatArtifactRuntimeTier::Premium
                }
                ChatArtifactRuntimePolicyProfile::PremiumPlanningLocalGeneration
                    if premium_html_planning =>
                {
                    ChatArtifactRuntimeTier::Premium
                }
                ChatArtifactRuntimePolicyProfile::PremiumPlanningLocalGeneration => {
                    ChatArtifactRuntimeTier::Local
                }
                ChatArtifactRuntimePolicyProfile::PremiumEndToEnd => {
                    ChatArtifactRuntimeTier::Premium
                }
                ChatArtifactRuntimePolicyProfile::Auto => ChatArtifactRuntimeTier::CostEffective,
            },
            fallback_to_generation_runtime: true,
            require_distinct_runtime: matches!(
                profile,
                ChatArtifactRuntimePolicyProfile::LocalGenerationRemoteAcceptance
                    | ChatArtifactRuntimePolicyProfile::PremiumPlanningLocalGeneration
            ),
        },
        ChatArtifactRuntimeStepPolicy {
            step: ChatArtifactRuntimeStep::MemoryDistillation,
            preferred_tier: ChatArtifactRuntimeTier::Deterministic,
            fallback_to_generation_runtime: true,
            require_distinct_runtime: false,
        },
    ]
}

pub(super) fn compact_local_specialist_generation_renderer(renderer: ChatRendererKind) -> bool {
    matches!(
        renderer,
        ChatRendererKind::Markdown
            | ChatRendererKind::DownloadCard
            | ChatRendererKind::BundleManifest
    )
}

pub(super) fn compact_local_specialist_planning_renderer(renderer: ChatRendererKind) -> bool {
    matches!(
        renderer,
        ChatRendererKind::Markdown
            | ChatRendererKind::DownloadCard
            | ChatRendererKind::BundleManifest
    )
}

pub(super) fn prefers_distinct_local_specialist_generation_runtime(
    profile: ChatArtifactRuntimePolicyProfile,
    request: &ChatOutcomeArtifactRequest,
    generation_provenance: &ChatRuntimeProvenance,
    acceptance_runtime: Option<&Arc<dyn InferenceRuntime>>,
) -> bool {
    if profile != ChatArtifactRuntimePolicyProfile::LocalGenerationRemoteAcceptance
        || !compact_local_specialist_generation_renderer(request.renderer)
        || generation_provenance.kind != ChatRuntimeProvenanceKind::RealLocalRuntime
    {
        return false;
    }

    let Some(runtime) = acceptance_runtime else {
        return false;
    };
    let acceptance_provenance = runtime.chat_runtime_provenance();
    acceptance_provenance.kind == ChatRuntimeProvenanceKind::RealLocalRuntime
        && !chat_runtime_provenance_matches(&acceptance_provenance, generation_provenance)
}

pub(super) fn prefers_distinct_local_specialist_planning_runtime(
    profile: ChatArtifactRuntimePolicyProfile,
    request: &ChatOutcomeArtifactRequest,
    generation_provenance: &ChatRuntimeProvenance,
    acceptance_runtime: Option<&Arc<dyn InferenceRuntime>>,
) -> bool {
    if profile != ChatArtifactRuntimePolicyProfile::LocalGenerationRemoteAcceptance
        || !compact_local_specialist_planning_renderer(request.renderer)
        || generation_provenance.kind != ChatRuntimeProvenanceKind::RealLocalRuntime
    {
        return false;
    }

    let Some(runtime) = acceptance_runtime else {
        return false;
    };
    let acceptance_provenance = runtime.chat_runtime_provenance();
    acceptance_provenance.kind == ChatRuntimeProvenanceKind::RealLocalRuntime
        && !chat_runtime_provenance_matches(&acceptance_provenance, generation_provenance)
}

pub(super) fn fallback_reason_for_premium_lane(
    acceptance_runtime: Option<&Arc<dyn InferenceRuntime>>,
    generation_provenance: &ChatRuntimeProvenance,
    require_distinct_runtime: bool,
) -> Option<String> {
    let Some(runtime) = acceptance_runtime else {
        return Some("acceptance_runtime_missing".to_string());
    };
    let acceptance_provenance = runtime.chat_runtime_provenance();
    if acceptance_provenance.kind == ChatRuntimeProvenanceKind::InferenceUnavailable {
        return Some("acceptance_runtime_unavailable".to_string());
    }
    if require_distinct_runtime
        && chat_runtime_provenance_matches(&acceptance_provenance, generation_provenance)
    {
        return Some("acceptance_runtime_not_distinct".to_string());
    }
    None
}

pub(super) fn build_runtime_binding(
    step: ChatArtifactRuntimeStep,
    preferred_tier: ChatArtifactRuntimeTier,
    selected_tier: ChatArtifactRuntimeTier,
    runtime: &Arc<dyn InferenceRuntime>,
    fallback_reason: Option<String>,
) -> ChatArtifactRuntimeBinding {
    ChatArtifactRuntimeBinding {
        step,
        preferred_tier,
        selected_tier,
        fallback_applied: fallback_reason.is_some(),
        fallback_reason,
        provenance: runtime.chat_runtime_provenance(),
    }
}

pub fn resolve_chat_artifact_runtime_plan(
    request: &ChatOutcomeArtifactRequest,
    generation_runtime: Arc<dyn InferenceRuntime>,
    acceptance_runtime: Option<Arc<dyn InferenceRuntime>>,
    requested_profile: ChatArtifactRuntimePolicyProfile,
) -> ChatArtifactResolvedRuntimePlan {
    let generation_provenance = generation_runtime.chat_runtime_provenance();
    let acceptance_available = acceptance_runtime
        .as_ref()
        .map(chat_runtime_available)
        .unwrap_or(false);
    let acceptance_distinct = acceptance_runtime
        .as_ref()
        .map(|runtime| {
            let provenance = runtime.chat_runtime_provenance();
            acceptance_available
                && !chat_runtime_provenance_matches(&provenance, &generation_provenance)
        })
        .unwrap_or(false);
    let resolved_profile = match requested_profile {
        ChatArtifactRuntimePolicyProfile::Auto => {
            if generation_provenance.kind == ChatRuntimeProvenanceKind::RealRemoteModelRuntime {
                ChatArtifactRuntimePolicyProfile::PremiumEndToEnd
            } else if acceptance_distinct {
                ChatArtifactRuntimePolicyProfile::LocalGenerationRemoteAcceptance
            } else {
                ChatArtifactRuntimePolicyProfile::FullyLocal
            }
        }
        other => other,
    };
    let step_policies = runtime_step_policies(resolved_profile, request.renderer);
    let generation_tier = generation_runtime_tier(&generation_provenance);
    let planning_policy = step_policies
        .iter()
        .find(|policy| policy.step == ChatArtifactRuntimeStep::BlueprintPlanning)
        .cloned()
        .expect("planning policy");
    let generation_policy = step_policies
        .iter()
        .find(|policy| policy.step == ChatArtifactRuntimeStep::CandidateGeneration)
        .cloned()
        .expect("generation policy");
    let acceptance_policy = step_policies
        .iter()
        .find(|policy| policy.step == ChatArtifactRuntimeStep::ArtifactValidation)
        .cloned()
        .expect("acceptance policy");
    let repair_policy = step_policies
        .iter()
        .find(|policy| policy.step == ChatArtifactRuntimeStep::RepairPlanning)
        .cloned()
        .expect("repair policy");
    let compact_local_specialist_generation = prefers_distinct_local_specialist_generation_runtime(
        resolved_profile,
        request,
        &generation_provenance,
        acceptance_runtime.as_ref(),
    );
    let compact_local_specialist_acceptance = compact_local_specialist_generation;
    let compact_local_specialist_repair = compact_local_specialist_generation;
    let compact_local_specialist_planning = prefers_distinct_local_specialist_planning_runtime(
        resolved_profile,
        request,
        &generation_provenance,
        acceptance_runtime.as_ref(),
    );
    let planning_prefers_premium = matches!(
        resolved_profile,
        ChatArtifactRuntimePolicyProfile::PremiumPlanningLocalGeneration
            | ChatArtifactRuntimePolicyProfile::PremiumEndToEnd
    ) && matches!(
        request.renderer,
        ChatRendererKind::HtmlIframe | ChatRendererKind::JsxSandbox
    );
    let planning_fallback_reason = if planning_prefers_premium {
        fallback_reason_for_premium_lane(
            acceptance_runtime.as_ref(),
            &generation_provenance,
            planning_policy.require_distinct_runtime,
        )
    } else {
        None
    };
    let (planning_runtime, planning_binding) = if compact_local_specialist_planning {
        let runtime = acceptance_runtime
            .as_ref()
            .expect("compact local specialist planning requires acceptance runtime");
        (
            runtime.clone(),
            build_runtime_binding(
                ChatArtifactRuntimeStep::BlueprintPlanning,
                planning_policy.preferred_tier,
                ChatArtifactRuntimeTier::Local,
                runtime,
                None,
            ),
        )
    } else if planning_prefers_premium && planning_fallback_reason.is_none() {
        let runtime = acceptance_runtime
            .as_ref()
            .expect("premium planning requires acceptance runtime");
        (
            runtime.clone(),
            build_runtime_binding(
                ChatArtifactRuntimeStep::BlueprintPlanning,
                planning_policy.preferred_tier,
                ChatArtifactRuntimeTier::Premium,
                runtime,
                None,
            ),
        )
    } else {
        (
            generation_runtime.clone(),
            build_runtime_binding(
                ChatArtifactRuntimeStep::BlueprintPlanning,
                planning_policy.preferred_tier,
                generation_tier,
                &generation_runtime,
                planning_fallback_reason,
            ),
        )
    };

    let generation_fallback_reason = if matches!(
        resolved_profile,
        ChatArtifactRuntimePolicyProfile::PremiumEndToEnd
    ) {
        fallback_reason_for_premium_lane(acceptance_runtime.as_ref(), &generation_provenance, false)
    } else {
        None
    };
    let (resolved_generation_runtime, generation_binding) = if compact_local_specialist_generation {
        let runtime = acceptance_runtime
            .as_ref()
            .expect("compact local specialist generation requires acceptance runtime");
        (
            runtime.clone(),
            build_runtime_binding(
                ChatArtifactRuntimeStep::CandidateGeneration,
                generation_policy.preferred_tier,
                ChatArtifactRuntimeTier::Local,
                runtime,
                None,
            ),
        )
    } else if matches!(
        resolved_profile,
        ChatArtifactRuntimePolicyProfile::PremiumEndToEnd
    ) && generation_fallback_reason.is_none()
    {
        let runtime = acceptance_runtime
            .as_ref()
            .expect("premium end-to-end requires acceptance runtime");
        (
            runtime.clone(),
            build_runtime_binding(
                ChatArtifactRuntimeStep::CandidateGeneration,
                generation_policy.preferred_tier,
                ChatArtifactRuntimeTier::Premium,
                runtime,
                None,
            ),
        )
    } else {
        (
            generation_runtime.clone(),
            build_runtime_binding(
                ChatArtifactRuntimeStep::CandidateGeneration,
                generation_policy.preferred_tier,
                generation_tier,
                &generation_runtime,
                generation_fallback_reason,
            ),
        )
    };
    let resolved_generation_provenance = resolved_generation_runtime.chat_runtime_provenance();

    let acceptance_fallback_reason = if matches!(
        resolved_profile,
        ChatArtifactRuntimePolicyProfile::FullyLocal
    ) {
        None
    } else {
        fallback_reason_for_premium_lane(
            acceptance_runtime.as_ref(),
            &resolved_generation_provenance,
            acceptance_policy.require_distinct_runtime,
        )
    };
    let (resolved_acceptance_runtime, acceptance_binding) = if compact_local_specialist_acceptance {
        (
            resolved_generation_runtime.clone(),
            build_runtime_binding(
                ChatArtifactRuntimeStep::ArtifactValidation,
                acceptance_policy.preferred_tier,
                ChatArtifactRuntimeTier::Local,
                &resolved_generation_runtime,
                Some("compact_local_specialist_acceptance".to_string()),
            ),
        )
    } else if matches!(
        resolved_profile,
        ChatArtifactRuntimePolicyProfile::FullyLocal
    ) || acceptance_fallback_reason.is_some()
    {
        (
            generation_runtime.clone(),
            build_runtime_binding(
                ChatArtifactRuntimeStep::ArtifactValidation,
                acceptance_policy.preferred_tier,
                generation_tier,
                &generation_runtime,
                acceptance_fallback_reason,
            ),
        )
    } else {
        let runtime = acceptance_runtime
            .as_ref()
            .expect("premium acceptance requires acceptance runtime");
        (
            runtime.clone(),
            build_runtime_binding(
                ChatArtifactRuntimeStep::ArtifactValidation,
                acceptance_policy.preferred_tier,
                ChatArtifactRuntimeTier::Premium,
                runtime,
                None,
            ),
        )
    };

    let repair_prefers_premium = match resolved_profile {
        ChatArtifactRuntimePolicyProfile::FullyLocal => false,
        ChatArtifactRuntimePolicyProfile::LocalGenerationRemoteAcceptance => true,
        ChatArtifactRuntimePolicyProfile::PremiumPlanningLocalGeneration => matches!(
            request.renderer,
            ChatRendererKind::HtmlIframe | ChatRendererKind::JsxSandbox
        ),
        ChatArtifactRuntimePolicyProfile::PremiumEndToEnd => true,
        ChatArtifactRuntimePolicyProfile::Auto => false,
    };
    let repair_fallback_reason = if repair_prefers_premium
        && !matches!(
            resolved_profile,
            ChatArtifactRuntimePolicyProfile::FullyLocal
        ) {
        fallback_reason_for_premium_lane(
            acceptance_runtime.as_ref(),
            &resolved_generation_provenance,
            repair_policy.require_distinct_runtime,
        )
    } else {
        None
    };
    let (repair_runtime, repair_binding) = if compact_local_specialist_repair {
        let runtime = acceptance_runtime
            .as_ref()
            .expect("compact local specialist repair requires acceptance runtime");
        (
            runtime.clone(),
            build_runtime_binding(
                ChatArtifactRuntimeStep::RepairPlanning,
                repair_policy.preferred_tier,
                ChatArtifactRuntimeTier::Local,
                runtime,
                Some("compact_local_specialist_repair".to_string()),
            ),
        )
    } else if repair_prefers_premium
        && repair_fallback_reason.is_none()
        && !matches!(
            resolved_profile,
            ChatArtifactRuntimePolicyProfile::FullyLocal
        )
    {
        let runtime = acceptance_runtime
            .as_ref()
            .expect("premium repair requires acceptance runtime");
        (
            runtime.clone(),
            build_runtime_binding(
                ChatArtifactRuntimeStep::RepairPlanning,
                repair_policy.preferred_tier,
                ChatArtifactRuntimeTier::Premium,
                runtime,
                None,
            ),
        )
    } else {
        (
            generation_runtime.clone(),
            build_runtime_binding(
                ChatArtifactRuntimeStep::RepairPlanning,
                repair_policy.preferred_tier,
                generation_tier,
                &generation_runtime,
                repair_fallback_reason,
            ),
        )
    };

    ChatArtifactResolvedRuntimePlan {
        policy: ChatArtifactRuntimePolicy {
            profile: resolved_profile,
            step_policies,
            bindings: vec![
                planning_binding,
                generation_binding,
                acceptance_binding,
                repair_binding,
            ],
        },
        planning_runtime,
        generation_runtime: resolved_generation_runtime,
        acceptance_runtime: resolved_acceptance_runtime,
        repair_runtime,
    }
}

pub fn render_eval_timeout_for_runtime(
    renderer: ChatRendererKind,
    _runtime_kind: ChatRuntimeProvenanceKind,
) -> Option<Duration> {
    match renderer {
        ChatRendererKind::HtmlIframe => Some(Duration::from_secs(60)),
        ChatRendererKind::Svg | ChatRendererKind::Markdown | ChatRendererKind::PdfEmbed => {
            Some(Duration::from_secs(30))
        }
        _ => None,
    }
}

pub(crate) fn materialization_repair_pass_limit(
    renderer: ChatRendererKind,
    runtime_kind: ChatRuntimeProvenanceKind,
) -> usize {
    match renderer {
        ChatRendererKind::HtmlIframe
            if runtime_kind == ChatRuntimeProvenanceKind::RealLocalRuntime =>
        {
            1
        }
        ChatRendererKind::HtmlIframe => 3,
        ChatRendererKind::PdfEmbed => 3,
        _ => 1,
    }
}
