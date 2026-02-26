use super::*;

pub async fn resolve_step_intent(
    service: &DesktopAgentService,
    agent_state: &AgentState,
    rules: &ActionRules,
    active_window_title: &str,
) -> Result<ResolvedIntentState, TransactionError> {
    let policy = &rules.ontology_policy.intent_routing;
    if !policy.enabled {
        return Ok(ResolvedIntentState {
            intent_id: "resolver.disabled".to_string(),
            scope: IntentScopeProfile::Unknown,
            band: IntentConfidenceBand::High,
            score: 1.0,
            top_k: vec![IntentCandidateScore {
                intent_id: "resolver.disabled".to_string(),
                score: 1.0,
            }],
            required_capabilities: vec![],
            risk_class: "unknown".to_string(),
            preferred_tier: "tool_first".to_string(),
            matrix_version: policy.matrix_version.clone(),
            embedding_model_id: String::new(),
            embedding_model_version: String::new(),
            similarity_function_id: String::new(),
            intent_set_hash: [0u8; 32],
            tool_registry_hash: [0u8; 32],
            capability_ontology_hash: [0u8; 32],
            query_normalization_version: INTENT_QUERY_NORMALIZATION_VERSION.to_string(),
            matrix_source_hash: [0u8; 32],
            receipt_hash: [0u8; 32],
            constrained: false,
        });
    }

    let latest_user_message = service
        .hydrate_session_history(agent_state.session_id)
        .ok()
        .and_then(|history| {
            history
                .iter()
                .rfind(|m| m.role == "user")
                .map(|m| m.content.clone())
        })
        .unwrap_or_else(|| agent_state.goal.clone());

    let query = if latest_user_message.trim().is_empty() {
        agent_state.goal.clone()
    } else {
        latest_user_message
    };
    let normalized_query = normalize_query_for_ranking(&query);
    let ranking_query = if normalized_query.trim().is_empty() {
        query.clone()
    } else {
        normalized_query.clone()
    };
    let query_facets = analyze_query_facets(&query);
    let session_prefix = hex::encode(&agent_state.session_id[..4]);
    let query_hash = hex::encode(
        sha256(query.as_bytes()).map_err(|e| TransactionError::Invalid(e.to_string()))?,
    );
    let normalized_query_hash = hex::encode(
        sha256(ranking_query.as_bytes()).map_err(|e| TransactionError::Invalid(e.to_string()))?,
    );
    let raw_enabled =
        crate::agentic::desktop::service::step::helpers::should_log_raw_prompt_content();
    if raw_enabled {
        let query_json = serde_json::to_string(&query)
            .unwrap_or_else(|_| "\"<query-serialization-error>\"".to_string());
        log::info!(
            "IntentResolverInput session={} chars={} bytes={} lines={} query_hash={} normalized_query_hash={} normalization_version={} query_json={}",
            session_prefix,
            query.chars().count(),
            query.len(),
            query.lines().count(),
            query_hash,
            normalized_query_hash,
            INTENT_QUERY_NORMALIZATION_VERSION,
            query_json
        );
    } else {
        log::info!(
            "IntentResolverInput session={} chars={} bytes={} lines={} query_hash={} normalized_query_hash={} normalization_version={} query_json=<omitted:raw_prompt_disabled>",
            session_prefix,
            query.chars().count(),
            query.len(),
            query.lines().count(),
            query_hash,
            normalized_query_hash,
            INTENT_QUERY_NORMALIZATION_VERSION
        );
    }
    let matrix = effective_matrix(policy)?;
    let matrix_hash = matrix_source_hash(policy, &matrix)?;
    let bindings = tool_capability_bindings();
    let intent_hash = intent_set_hash(&matrix)?;
    let registry_hash = tool_registry_hash(&bindings)?;
    let ontology_hash = capability_ontology_hash(&bindings)?;
    if matrix.is_empty() {
        log::warn!(
            "IntentResolver matrix is empty for version={}, abstaining.",
            policy.matrix_version
        );
    }

    let runtime = service.reasoning_inference.clone();
    let prototypes_ready = match timeout(
        INTENT_PROTOTYPE_BUILD_TIMEOUT,
        ensure_intent_prototypes(&runtime, &policy.matrix_version, matrix_hash, &matrix),
    )
    .await
    {
        Ok(Ok(())) => true,
        Ok(Err(e)) => {
            log::warn!(
                "IntentResolver prototype build failed session={} error={}",
                session_prefix,
                e
            );
            false
        }
        Err(_) => {
            log::warn!(
                "IntentResolver prototype build timed out session={} timeout_ms={}",
                session_prefix,
                INTENT_PROTOTYPE_BUILD_TIMEOUT.as_millis()
            );
            false
        }
    };

    let mut ranked_candidates = if prototypes_ready {
        match timeout(
            INTENT_EMBED_RANK_TIMEOUT,
            runtime.embed_or_rank(&ranking_query, &policy.matrix_version, matrix_hash, &matrix),
        )
        .await
        {
            Ok(Ok(scores)) => scores,
            Ok(Err(e)) => {
                log::warn!(
                    "IntentResolver embedding rank failed session={} error={}",
                    session_prefix,
                    e
                );
                vec![]
            }
            Err(_) => {
                log::warn!(
                    "IntentResolver embedding rank timed out session={} timeout_ms={}",
                    session_prefix,
                    INTENT_EMBED_RANK_TIMEOUT.as_millis()
                );
                vec![]
            }
        }
    } else {
        vec![]
    };
    if ranked_candidates.is_empty() && !matrix.is_empty() {
        ranked_candidates = zero_ranked_candidates(&matrix);
    }
    quantize_and_sort_scores(&mut ranked_candidates, policy);
    let routed_top_k = ranked_candidates
        .iter()
        .take(5)
        .cloned()
        .collect::<Vec<_>>();
    let selection_top_k = ranked_candidates
        .iter()
        .filter_map(|candidate| {
            let entry = matrix
                .iter()
                .find(|entry| entry.intent_id == candidate.intent_id)?;
            intent_feasible_for_execution(entry, &bindings, rules, &query, &query_facets)
                .then_some(candidate.clone())
        })
        .collect::<Vec<_>>();
    let mut resolver_error_class: Option<String> = None;
    if selection_top_k.is_empty() {
        log::warn!(
            "IntentResolverFeasibility no feasible candidates after capability/policy checks session={}",
            session_prefix
        );
        resolver_error_class = Some(infer_unclassified_error_class(
            &ranked_candidates,
            &matrix,
            &bindings,
            rules,
            &query,
            &query_facets,
        ));
    }
    let unclassified = selection_top_k.is_empty() || all_candidate_scores_zero(&selection_top_k);
    if unclassified && resolver_error_class.is_none() {
        resolver_error_class = Some("IntentUnclassified".to_string());
    }
    let mut winner = if unclassified {
        IntentCandidateScore {
            intent_id: "resolver.unclassified".to_string(),
            score: 0.0,
        }
    } else {
        select_deterministic_winner(&selection_top_k, &matrix, policy).unwrap_or(
            IntentCandidateScore {
                intent_id: "resolver.unclassified".to_string(),
                score: 0.0,
            },
        )
    };
    if winner.intent_id != "resolver.unclassified"
        && should_abstain_for_ambiguity(&selection_top_k, &winner, policy)
        && !is_ambiguity_abstain_exempt(policy, &winner.intent_id)
    {
        log::info!(
            "IntentResolverAmbiguityAbstain session={} winner={} score={:.3} ambiguity_margin_bps={}",
            session_prefix,
            winner.intent_id,
            winner.score,
            ambiguity_margin_bps(policy)
        );
        winner = IntentCandidateScore {
            intent_id: "resolver.unclassified".to_string(),
            score: 0.0,
        };
        resolver_error_class = Some("IntentUnclassified".to_string());
    }

    let (scope, preferred_tier, score, band, required_capabilities, risk_class) = if winner
        .intent_id
        == "resolver.unclassified"
    {
        (
            IntentScopeProfile::Unknown,
            "tool_first".to_string(),
            0.0,
            IntentConfidenceBand::Low,
            vec![],
            "unknown".to_string(),
        )
    } else {
        let entry = matrix
            .iter()
            .find(|entry| entry.intent_id == winner.intent_id)
            .ok_or_else(|| {
                TransactionError::Invalid(format!(
                    "ERROR_CLASS=ResolverContractViolation Intent '{}' missing matrix binding",
                    winner.intent_id
                ))
            })?;
        let scope = scope_for_intent(&matrix, &winner.intent_id).ok_or_else(|| {
            TransactionError::Invalid(format!(
                "ERROR_CLASS=ResolverContractViolation Intent '{}' missing matrix scope binding",
                winner.intent_id
            ))
        })?;
        let preferred_tier =
                preferred_tier_for_intent(&matrix, &winner.intent_id).ok_or_else(|| {
                    TransactionError::Invalid(format!(
                        "ERROR_CLASS=ResolverContractViolation Intent '{}' missing preferred tier binding",
                        winner.intent_id
                    ))
                })?;
        let score = winner.score.clamp(0.0, 1.0);
        (
            scope,
            preferred_tier,
            score,
            resolve_band(score, policy),
            entry.required_capabilities.clone(),
            entry.risk_class.clone(),
        )
    };
    let mut resolved = ResolvedIntentState {
        intent_id: winner.intent_id,
        scope,
        band,
        score,
        top_k: routed_top_k,
        required_capabilities,
        risk_class,
        preferred_tier,
        matrix_version: policy.matrix_version.clone(),
        embedding_model_id: INTENT_EMBEDDING_MODEL_ID.to_string(),
        embedding_model_version: INTENT_EMBEDDING_MODEL_VERSION.to_string(),
        similarity_function_id: INTENT_SIMILARITY_FUNCTION_ID.to_string(),
        intent_set_hash: intent_hash,
        tool_registry_hash: registry_hash,
        capability_ontology_hash: ontology_hash,
        query_normalization_version: INTENT_QUERY_NORMALIZATION_VERSION.to_string(),
        matrix_source_hash: matrix_hash,
        receipt_hash: [0u8; 32],
        // Constrained routing is deprecated (compat field only). We rely on policy gates + ontology.
        constrained: false,
    };
    resolved.receipt_hash = receipt_hash(
        &query,
        &ranking_query,
        &resolved,
        policy,
        Some(agent_state.session_id),
        active_window_title,
    )?;

    emit_intent_resolution_receipt(
        service,
        agent_state.session_id,
        &resolved,
        resolver_error_class,
    );

    Ok(resolved)
}
