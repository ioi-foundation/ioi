use super::*;
use std::{path::Path, sync::Arc, time::Duration};

pub(super) fn compact_local_html_materialization_prompt(
    renderer: StudioRendererKind,
    runtime_kind: StudioRuntimeProvenanceKind,
) -> bool {
    renderer == StudioRendererKind::HtmlIframe
        && runtime_kind == StudioRuntimeProvenanceKind::RealLocalRuntime
}

pub(crate) fn effective_candidate_generation_temperature(
    renderer: StudioRendererKind,
    runtime_kind: StudioRuntimeProvenanceKind,
    configured_temperature: f32,
) -> f32 {
    // Keep local HTML stability policy tied to runtime shape and prompt budget,
    // not to a particular model family label.
    if compact_local_html_materialization_prompt(renderer, runtime_kind) {
        if studio_modal_first_html_enabled() {
            return configured_temperature;
        }
        return configured_temperature.min(0.32);
    }

    configured_temperature
}

pub(super) fn effective_direct_author_temperature(
    renderer: StudioRendererKind,
    runtime_kind: StudioRuntimeProvenanceKind,
    configured_temperature: f32,
) -> f32 {
    if renderer == StudioRendererKind::HtmlIframe
        && runtime_kind == StudioRuntimeProvenanceKind::RealLocalRuntime
    {
        return configured_temperature.min(0.28);
    }

    effective_candidate_generation_temperature(renderer, runtime_kind, configured_temperature)
}

pub(crate) fn materialization_max_tokens_for_runtime(
    renderer: StudioRendererKind,
    runtime_kind: StudioRuntimeProvenanceKind,
) -> u32 {
    if compact_local_html_materialization_prompt(renderer, runtime_kind) {
        if studio_modal_first_html_enabled() {
            return 4200;
        }
        return 2200;
    }

    materialization_max_tokens(renderer)
}

pub(crate) fn materialization_max_tokens_for_execution_strategy(
    renderer: StudioRendererKind,
    execution_strategy: StudioExecutionStrategy,
    runtime_kind: StudioRuntimeProvenanceKind,
) -> u32 {
    if execution_strategy == StudioExecutionStrategy::DirectAuthor {
        let direct_author_budget = match renderer {
            StudioRendererKind::Markdown | StudioRendererKind::Mermaid => {
                if runtime_kind == StudioRuntimeProvenanceKind::RealLocalRuntime {
                    1200
                } else {
                    materialization_max_tokens(renderer).min(1800)
                }
            }
            StudioRendererKind::Svg | StudioRendererKind::PdfEmbed => {
                if runtime_kind == StudioRuntimeProvenanceKind::RealLocalRuntime {
                    1600
                } else {
                    materialization_max_tokens(renderer).min(2200)
                }
            }
            StudioRendererKind::HtmlIframe => {
                if runtime_kind == StudioRuntimeProvenanceKind::RealLocalRuntime {
                    materialization_max_tokens_for_runtime(renderer, runtime_kind)
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
    request: &StudioOutcomeArtifactRequest,
    production_runtime: &Arc<dyn InferenceRuntime>,
    repair_runtime: Option<&Arc<dyn InferenceRuntime>>,
) -> Arc<dyn InferenceRuntime> {
    let production_provenance = production_runtime.studio_runtime_provenance();
    if request.renderer == StudioRendererKind::HtmlIframe
        && production_provenance.kind == StudioRuntimeProvenanceKind::RealLocalRuntime
    {
        if let Some(runtime) = repair_runtime {
            let repair_provenance = runtime.studio_runtime_provenance();
            if repair_provenance.kind == StudioRuntimeProvenanceKind::RealLocalRuntime
                && !studio_runtime_provenance_matches(&repair_provenance, &production_provenance)
            {
                return runtime.clone();
            }
        }
    }

    production_runtime.clone()
}

pub(super) fn should_warm_local_html_generation_runtime(
    request: &StudioOutcomeArtifactRequest,
    planning_runtime: &Arc<dyn InferenceRuntime>,
    production_runtime: &Arc<dyn InferenceRuntime>,
) -> bool {
    if request.renderer != StudioRendererKind::HtmlIframe {
        return false;
    }

    let planning_provenance = planning_runtime.studio_runtime_provenance();
    let production_provenance = production_runtime.studio_runtime_provenance();
    production_provenance.kind == StudioRuntimeProvenanceKind::RealLocalRuntime
        && planning_provenance.kind == StudioRuntimeProvenanceKind::RealLocalRuntime
        && !studio_runtime_provenance_matches(&planning_provenance, &production_provenance)
}

pub(super) fn local_html_generation_warmup_timeout() -> Duration {
    Duration::from_secs(12)
}

pub(super) async fn warm_local_html_generation_runtime_if_needed(
    request: &StudioOutcomeArtifactRequest,
    planning_runtime: &Arc<dyn InferenceRuntime>,
    production_runtime: &Arc<dyn InferenceRuntime>,
) {
    if !should_warm_local_html_generation_runtime(request, planning_runtime, production_runtime) {
        return;
    }

    let production_provenance = production_runtime.studio_runtime_provenance();
    studio_generation_trace(format!(
        "artifact_generation:generation_warmup:start model={:?}",
        production_provenance.model
    ));
    match tokio::time::timeout(
        local_html_generation_warmup_timeout(),
        production_runtime.load_model([0u8; 32], Path::new("")),
    )
    .await
    {
        Ok(Ok(())) => studio_generation_trace(format!(
            "artifact_generation:generation_warmup:ok model={:?}",
            production_provenance.model
        )),
        Ok(Err(error)) => studio_generation_trace(format!(
            "artifact_generation:generation_warmup:error model={:?} error={}",
            production_provenance.model, error
        )),
        Err(_) => studio_generation_trace(format!(
            "artifact_generation:generation_warmup:timeout model={:?} timeout={}s",
            production_provenance.model,
            local_html_generation_warmup_timeout().as_secs()
        )),
    }
}

#[derive(Clone)]
pub struct StudioArtifactResolvedRuntimePlan {
    pub policy: StudioArtifactRuntimePolicy,
    pub planning_runtime: Arc<dyn InferenceRuntime>,
    pub generation_runtime: Arc<dyn InferenceRuntime>,
    pub acceptance_runtime: Arc<dyn InferenceRuntime>,
    pub repair_runtime: Arc<dyn InferenceRuntime>,
}

pub(super) fn studio_runtime_available(runtime: &Arc<dyn InferenceRuntime>) -> bool {
    runtime.studio_runtime_provenance().kind != StudioRuntimeProvenanceKind::InferenceUnavailable
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

pub(super) fn studio_runtime_provenance_matches(
    left: &StudioRuntimeProvenance,
    right: &StudioRuntimeProvenance,
) -> bool {
    left.kind == right.kind
        && left.label == right.label
        && left.model == right.model
        && normalized_runtime_endpoint(left.endpoint.as_deref())
            == normalized_runtime_endpoint(right.endpoint.as_deref())
}

pub(super) fn generation_runtime_tier(
    provenance: &StudioRuntimeProvenance,
) -> StudioArtifactRuntimeTier {
    match provenance.kind {
        StudioRuntimeProvenanceKind::RealLocalRuntime => StudioArtifactRuntimeTier::Local,
        StudioRuntimeProvenanceKind::RealRemoteModelRuntime
        | StudioRuntimeProvenanceKind::OpaqueRuntime => StudioArtifactRuntimeTier::CostEffective,
        StudioRuntimeProvenanceKind::DeterministicContinuityFallback
        | StudioRuntimeProvenanceKind::FixtureRuntime
        | StudioRuntimeProvenanceKind::MockRuntime
        | StudioRuntimeProvenanceKind::InferenceUnavailable => {
            StudioArtifactRuntimeTier::Deterministic
        }
    }
}

pub(super) fn runtime_step_policies(
    profile: StudioArtifactRuntimePolicyProfile,
    renderer: StudioRendererKind,
) -> Vec<StudioArtifactRuntimeStepPolicy> {
    let premium_html_planning = matches!(
        renderer,
        StudioRendererKind::HtmlIframe | StudioRendererKind::JsxSandbox
    );
    vec![
        StudioArtifactRuntimeStepPolicy {
            step: StudioArtifactRuntimeStep::OutcomeRouting,
            preferred_tier: StudioArtifactRuntimeTier::CostEffective,
            fallback_to_generation_runtime: true,
            require_distinct_runtime: false,
        },
        StudioArtifactRuntimeStepPolicy {
            step: StudioArtifactRuntimeStep::BlueprintPlanning,
            preferred_tier: match profile {
                StudioArtifactRuntimePolicyProfile::PremiumEndToEnd => {
                    StudioArtifactRuntimeTier::Premium
                }
                StudioArtifactRuntimePolicyProfile::PremiumPlanningLocalGeneration
                    if premium_html_planning =>
                {
                    StudioArtifactRuntimeTier::Premium
                }
                StudioArtifactRuntimePolicyProfile::FullyLocal
                | StudioArtifactRuntimePolicyProfile::LocalGenerationRemoteAcceptance
                | StudioArtifactRuntimePolicyProfile::PremiumPlanningLocalGeneration => {
                    StudioArtifactRuntimeTier::Local
                }
                StudioArtifactRuntimePolicyProfile::Auto => {
                    StudioArtifactRuntimeTier::CostEffective
                }
            },
            fallback_to_generation_runtime: true,
            require_distinct_runtime: false,
        },
        StudioArtifactRuntimeStepPolicy {
            step: StudioArtifactRuntimeStep::CandidateGeneration,
            preferred_tier: match profile {
                StudioArtifactRuntimePolicyProfile::PremiumEndToEnd => {
                    StudioArtifactRuntimeTier::Premium
                }
                StudioArtifactRuntimePolicyProfile::FullyLocal
                | StudioArtifactRuntimePolicyProfile::LocalGenerationRemoteAcceptance
                | StudioArtifactRuntimePolicyProfile::PremiumPlanningLocalGeneration => {
                    StudioArtifactRuntimeTier::Local
                }
                StudioArtifactRuntimePolicyProfile::Auto => {
                    StudioArtifactRuntimeTier::CostEffective
                }
            },
            fallback_to_generation_runtime: false,
            require_distinct_runtime: false,
        },
        StudioArtifactRuntimeStepPolicy {
            step: StudioArtifactRuntimeStep::ArtifactValidation,
            preferred_tier: match profile {
                StudioArtifactRuntimePolicyProfile::FullyLocal => StudioArtifactRuntimeTier::Local,
                _ => StudioArtifactRuntimeTier::Premium,
            },
            fallback_to_generation_runtime: true,
            require_distinct_runtime: matches!(
                profile,
                StudioArtifactRuntimePolicyProfile::LocalGenerationRemoteAcceptance
                    | StudioArtifactRuntimePolicyProfile::PremiumPlanningLocalGeneration
            ),
        },
        StudioArtifactRuntimeStepPolicy {
            step: StudioArtifactRuntimeStep::RepairPlanning,
            preferred_tier: match profile {
                StudioArtifactRuntimePolicyProfile::FullyLocal => StudioArtifactRuntimeTier::Local,
                StudioArtifactRuntimePolicyProfile::LocalGenerationRemoteAcceptance => {
                    StudioArtifactRuntimeTier::Premium
                }
                StudioArtifactRuntimePolicyProfile::PremiumPlanningLocalGeneration
                    if premium_html_planning =>
                {
                    StudioArtifactRuntimeTier::Premium
                }
                StudioArtifactRuntimePolicyProfile::PremiumPlanningLocalGeneration => {
                    StudioArtifactRuntimeTier::Local
                }
                StudioArtifactRuntimePolicyProfile::PremiumEndToEnd => {
                    StudioArtifactRuntimeTier::Premium
                }
                StudioArtifactRuntimePolicyProfile::Auto => {
                    StudioArtifactRuntimeTier::CostEffective
                }
            },
            fallback_to_generation_runtime: true,
            require_distinct_runtime: matches!(
                profile,
                StudioArtifactRuntimePolicyProfile::LocalGenerationRemoteAcceptance
                    | StudioArtifactRuntimePolicyProfile::PremiumPlanningLocalGeneration
            ),
        },
        StudioArtifactRuntimeStepPolicy {
            step: StudioArtifactRuntimeStep::MemoryDistillation,
            preferred_tier: StudioArtifactRuntimeTier::Deterministic,
            fallback_to_generation_runtime: true,
            require_distinct_runtime: false,
        },
    ]
}

pub(super) fn compact_local_specialist_generation_renderer(renderer: StudioRendererKind) -> bool {
    matches!(
        renderer,
        StudioRendererKind::Markdown
            | StudioRendererKind::DownloadCard
            | StudioRendererKind::BundleManifest
    )
}

pub(super) fn compact_local_specialist_planning_renderer(renderer: StudioRendererKind) -> bool {
    matches!(
        renderer,
        StudioRendererKind::Markdown
            | StudioRendererKind::DownloadCard
            | StudioRendererKind::BundleManifest
    )
}

pub(super) fn prefers_distinct_local_specialist_generation_runtime(
    profile: StudioArtifactRuntimePolicyProfile,
    request: &StudioOutcomeArtifactRequest,
    generation_provenance: &StudioRuntimeProvenance,
    acceptance_runtime: Option<&Arc<dyn InferenceRuntime>>,
) -> bool {
    if profile != StudioArtifactRuntimePolicyProfile::LocalGenerationRemoteAcceptance
        || !compact_local_specialist_generation_renderer(request.renderer)
        || generation_provenance.kind != StudioRuntimeProvenanceKind::RealLocalRuntime
    {
        return false;
    }

    let Some(runtime) = acceptance_runtime else {
        return false;
    };
    let acceptance_provenance = runtime.studio_runtime_provenance();
    acceptance_provenance.kind == StudioRuntimeProvenanceKind::RealLocalRuntime
        && !studio_runtime_provenance_matches(&acceptance_provenance, generation_provenance)
}

pub(super) fn prefers_distinct_local_specialist_planning_runtime(
    profile: StudioArtifactRuntimePolicyProfile,
    request: &StudioOutcomeArtifactRequest,
    generation_provenance: &StudioRuntimeProvenance,
    acceptance_runtime: Option<&Arc<dyn InferenceRuntime>>,
) -> bool {
    if profile != StudioArtifactRuntimePolicyProfile::LocalGenerationRemoteAcceptance
        || !compact_local_specialist_planning_renderer(request.renderer)
        || generation_provenance.kind != StudioRuntimeProvenanceKind::RealLocalRuntime
    {
        return false;
    }

    let Some(runtime) = acceptance_runtime else {
        return false;
    };
    let acceptance_provenance = runtime.studio_runtime_provenance();
    acceptance_provenance.kind == StudioRuntimeProvenanceKind::RealLocalRuntime
        && !studio_runtime_provenance_matches(&acceptance_provenance, generation_provenance)
}

pub(super) fn fallback_reason_for_premium_lane(
    acceptance_runtime: Option<&Arc<dyn InferenceRuntime>>,
    generation_provenance: &StudioRuntimeProvenance,
    require_distinct_runtime: bool,
) -> Option<String> {
    let Some(runtime) = acceptance_runtime else {
        return Some("acceptance_runtime_missing".to_string());
    };
    let acceptance_provenance = runtime.studio_runtime_provenance();
    if acceptance_provenance.kind == StudioRuntimeProvenanceKind::InferenceUnavailable {
        return Some("acceptance_runtime_unavailable".to_string());
    }
    if require_distinct_runtime
        && studio_runtime_provenance_matches(&acceptance_provenance, generation_provenance)
    {
        return Some("acceptance_runtime_not_distinct".to_string());
    }
    None
}

pub(super) fn build_runtime_binding(
    step: StudioArtifactRuntimeStep,
    preferred_tier: StudioArtifactRuntimeTier,
    selected_tier: StudioArtifactRuntimeTier,
    runtime: &Arc<dyn InferenceRuntime>,
    fallback_reason: Option<String>,
) -> StudioArtifactRuntimeBinding {
    StudioArtifactRuntimeBinding {
        step,
        preferred_tier,
        selected_tier,
        fallback_applied: fallback_reason.is_some(),
        fallback_reason,
        provenance: runtime.studio_runtime_provenance(),
    }
}

pub fn resolve_studio_artifact_runtime_plan(
    request: &StudioOutcomeArtifactRequest,
    generation_runtime: Arc<dyn InferenceRuntime>,
    acceptance_runtime: Option<Arc<dyn InferenceRuntime>>,
    requested_profile: StudioArtifactRuntimePolicyProfile,
) -> StudioArtifactResolvedRuntimePlan {
    let generation_provenance = generation_runtime.studio_runtime_provenance();
    let acceptance_available = acceptance_runtime
        .as_ref()
        .map(studio_runtime_available)
        .unwrap_or(false);
    let acceptance_distinct = acceptance_runtime
        .as_ref()
        .map(|runtime| {
            let provenance = runtime.studio_runtime_provenance();
            acceptance_available
                && !studio_runtime_provenance_matches(&provenance, &generation_provenance)
        })
        .unwrap_or(false);
    let resolved_profile = match requested_profile {
        StudioArtifactRuntimePolicyProfile::Auto => {
            if generation_provenance.kind == StudioRuntimeProvenanceKind::RealRemoteModelRuntime {
                StudioArtifactRuntimePolicyProfile::PremiumEndToEnd
            } else if acceptance_distinct {
                StudioArtifactRuntimePolicyProfile::LocalGenerationRemoteAcceptance
            } else {
                StudioArtifactRuntimePolicyProfile::FullyLocal
            }
        }
        other => other,
    };
    let step_policies = runtime_step_policies(resolved_profile, request.renderer);
    let generation_tier = generation_runtime_tier(&generation_provenance);
    let planning_policy = step_policies
        .iter()
        .find(|policy| policy.step == StudioArtifactRuntimeStep::BlueprintPlanning)
        .cloned()
        .expect("planning policy");
    let generation_policy = step_policies
        .iter()
        .find(|policy| policy.step == StudioArtifactRuntimeStep::CandidateGeneration)
        .cloned()
        .expect("generation policy");
    let acceptance_policy = step_policies
        .iter()
        .find(|policy| policy.step == StudioArtifactRuntimeStep::ArtifactValidation)
        .cloned()
        .expect("acceptance policy");
    let repair_policy = step_policies
        .iter()
        .find(|policy| policy.step == StudioArtifactRuntimeStep::RepairPlanning)
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
        StudioArtifactRuntimePolicyProfile::PremiumPlanningLocalGeneration
            | StudioArtifactRuntimePolicyProfile::PremiumEndToEnd
    ) && matches!(
        request.renderer,
        StudioRendererKind::HtmlIframe | StudioRendererKind::JsxSandbox
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
                StudioArtifactRuntimeStep::BlueprintPlanning,
                planning_policy.preferred_tier,
                StudioArtifactRuntimeTier::Local,
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
                StudioArtifactRuntimeStep::BlueprintPlanning,
                planning_policy.preferred_tier,
                StudioArtifactRuntimeTier::Premium,
                runtime,
                None,
            ),
        )
    } else {
        (
            generation_runtime.clone(),
            build_runtime_binding(
                StudioArtifactRuntimeStep::BlueprintPlanning,
                planning_policy.preferred_tier,
                generation_tier,
                &generation_runtime,
                planning_fallback_reason,
            ),
        )
    };

    let generation_fallback_reason = if matches!(
        resolved_profile,
        StudioArtifactRuntimePolicyProfile::PremiumEndToEnd
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
                StudioArtifactRuntimeStep::CandidateGeneration,
                generation_policy.preferred_tier,
                StudioArtifactRuntimeTier::Local,
                runtime,
                None,
            ),
        )
    } else if matches!(
        resolved_profile,
        StudioArtifactRuntimePolicyProfile::PremiumEndToEnd
    ) && generation_fallback_reason.is_none()
    {
        let runtime = acceptance_runtime
            .as_ref()
            .expect("premium end-to-end requires acceptance runtime");
        (
            runtime.clone(),
            build_runtime_binding(
                StudioArtifactRuntimeStep::CandidateGeneration,
                generation_policy.preferred_tier,
                StudioArtifactRuntimeTier::Premium,
                runtime,
                None,
            ),
        )
    } else {
        (
            generation_runtime.clone(),
            build_runtime_binding(
                StudioArtifactRuntimeStep::CandidateGeneration,
                generation_policy.preferred_tier,
                generation_tier,
                &generation_runtime,
                generation_fallback_reason,
            ),
        )
    };
    let resolved_generation_provenance = resolved_generation_runtime.studio_runtime_provenance();

    let acceptance_fallback_reason = if matches!(
        resolved_profile,
        StudioArtifactRuntimePolicyProfile::FullyLocal
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
                StudioArtifactRuntimeStep::ArtifactValidation,
                acceptance_policy.preferred_tier,
                StudioArtifactRuntimeTier::Local,
                &resolved_generation_runtime,
                Some("compact_local_specialist_acceptance".to_string()),
            ),
        )
    } else if matches!(
        resolved_profile,
        StudioArtifactRuntimePolicyProfile::FullyLocal
    ) || acceptance_fallback_reason.is_some()
    {
        (
            generation_runtime.clone(),
            build_runtime_binding(
                StudioArtifactRuntimeStep::ArtifactValidation,
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
                StudioArtifactRuntimeStep::ArtifactValidation,
                acceptance_policy.preferred_tier,
                StudioArtifactRuntimeTier::Premium,
                runtime,
                None,
            ),
        )
    };

    let repair_prefers_premium = match resolved_profile {
        StudioArtifactRuntimePolicyProfile::FullyLocal => false,
        StudioArtifactRuntimePolicyProfile::LocalGenerationRemoteAcceptance => true,
        StudioArtifactRuntimePolicyProfile::PremiumPlanningLocalGeneration => matches!(
            request.renderer,
            StudioRendererKind::HtmlIframe | StudioRendererKind::JsxSandbox
        ),
        StudioArtifactRuntimePolicyProfile::PremiumEndToEnd => true,
        StudioArtifactRuntimePolicyProfile::Auto => false,
    };
    let repair_fallback_reason = if repair_prefers_premium
        && !matches!(
            resolved_profile,
            StudioArtifactRuntimePolicyProfile::FullyLocal
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
                StudioArtifactRuntimeStep::RepairPlanning,
                repair_policy.preferred_tier,
                StudioArtifactRuntimeTier::Local,
                runtime,
                Some("compact_local_specialist_repair".to_string()),
            ),
        )
    } else if repair_prefers_premium
        && repair_fallback_reason.is_none()
        && !matches!(
            resolved_profile,
            StudioArtifactRuntimePolicyProfile::FullyLocal
        )
    {
        let runtime = acceptance_runtime
            .as_ref()
            .expect("premium repair requires acceptance runtime");
        (
            runtime.clone(),
            build_runtime_binding(
                StudioArtifactRuntimeStep::RepairPlanning,
                repair_policy.preferred_tier,
                StudioArtifactRuntimeTier::Premium,
                runtime,
                None,
            ),
        )
    } else {
        (
            generation_runtime.clone(),
            build_runtime_binding(
                StudioArtifactRuntimeStep::RepairPlanning,
                repair_policy.preferred_tier,
                generation_tier,
                &generation_runtime,
                repair_fallback_reason,
            ),
        )
    };

    StudioArtifactResolvedRuntimePlan {
        policy: StudioArtifactRuntimePolicy {
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
    renderer: StudioRendererKind,
    _runtime_kind: StudioRuntimeProvenanceKind,
) -> Option<Duration> {
    match renderer {
        StudioRendererKind::HtmlIframe => Some(Duration::from_secs(60)),
        StudioRendererKind::Svg | StudioRendererKind::Markdown | StudioRendererKind::PdfEmbed => {
            Some(Duration::from_secs(30))
        }
        _ => None,
    }
}

pub(crate) fn materialization_repair_pass_limit(
    renderer: StudioRendererKind,
    runtime_kind: StudioRuntimeProvenanceKind,
) -> usize {
    match renderer {
        StudioRendererKind::HtmlIframe
            if runtime_kind == StudioRuntimeProvenanceKind::RealLocalRuntime =>
        {
            1
        }
        StudioRendererKind::HtmlIframe => 3,
        StudioRendererKind::PdfEmbed => 3,
        _ => 1,
    }
}
