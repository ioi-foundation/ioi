use super::*;
use ioi_api::state::StateAccess;

fn matrix_contains_intent(matrix: &[IntentMatrixEntry], intent_id: &str) -> bool {
    matrix.iter().any(|entry| entry.intent_id == intent_id)
}

fn obvious_casual_conversation_query(
    query: &str,
    query_binding_profile: &QueryBindingProfile,
    matrix: &[IntentMatrixEntry],
) -> bool {
    if !matrix_contains_intent(matrix, "conversation.reply") {
        return false;
    }

    if query_binding_profile.remote_public_fact_required
        || query_binding_profile.host_local_clock_targeted
        || query_binding_profile.durable_automation_requested
        || query_binding_profile.model_registry_control_requested
        || query_binding_profile.app_launch_directed
        || query_binding_profile.desktop_screenshot_requested
        || query_binding_profile.temporal_filesystem_filter
    {
        return false;
    }

    let trimmed = query.trim();
    if trimmed.is_empty() {
        return false;
    }

    let normalized = trimmed.to_ascii_lowercase();
    if normalized.contains("http://")
        || normalized.contains("https://")
        || normalized.contains("www.")
        || normalized.contains("```")
        || normalized.contains("~/")
        || normalized.contains("./")
        || normalized.contains('/')
        || normalized.contains('\\')
    {
        return false;
    }

    let words = normalized
        .split_whitespace()
        .map(|word| word.trim_matches(|ch: char| !ch.is_ascii_alphanumeric() && ch != '\''))
        .filter(|word| !word.is_empty())
        .collect::<Vec<_>>();
    if words.is_empty() || words.len() > 14 {
        return false;
    }

    let first_two = words.iter().take(2).copied().collect::<Vec<_>>().join(" ");
    let first_three = words.iter().take(3).copied().collect::<Vec<_>>().join(" ");
    let first_word = words.first().copied().unwrap_or_default();

    let explanatory_reply_format = matches!(
        first_two.as_str(),
        "explain what" | "describe what" | "summarize what"
    ) || matches!(
        first_three.as_str(),
        "summarize what you" | "explain what you" | "describe what you"
    );
    if explanatory_reply_format
        && words
            .iter()
            .any(|word| matches!(*word, "you" | "your" | "me" | "we"))
    {
        return true;
    }

    let action_verbs = [
        "open",
        "launch",
        "run",
        "execute",
        "create",
        "build",
        "make",
        "install",
        "search",
        "find",
        "look",
        "click",
        "type",
        "scroll",
        "copy",
        "paste",
        "download",
        "load",
        "unload",
        "sync",
        "monitor",
        "set",
        "list",
        "show",
        "navigate",
        "read",
        "edit",
        "write",
        "summarize",
        "draft",
        "transcribe",
        "generate",
        "remove",
        "delete",
        "rename",
        "move",
    ];
    if action_verbs.contains(&first_word) {
        return false;
    }

    let greeting_like = matches!(
        first_word,
        "hi" | "hello" | "hey" | "yo" | "thanks" | "thank"
    ) || matches!(
        first_two.as_str(),
        "good morning" | "good afternoon" | "good evening" | "thank you"
    );
    if greeting_like {
        return true;
    }

    let explicit_reply_format = normalized.starts_with("reply with ")
        || normalized.starts_with("answer with ")
        || normalized.starts_with("respond with ")
        || normalized.starts_with("say ")
        || normalized.starts_with("tell me ");
    if explicit_reply_format {
        return true;
    }

    let conversational_question = matches!(
        first_two.as_str(),
        "do you"
            | "did you"
            | "are you"
            | "can you"
            | "could you"
            | "would you"
            | "will you"
            | "have you"
            | "how are"
            | "who are"
    ) || matches!(
        first_three.as_str(),
        "what do you" | "what are you" | "what is your" | "how do you" | "why do you"
    );
    if conversational_question {
        return true;
    }

    normalized.ends_with('?')
        && words
            .iter()
            .any(|word| matches!(*word, "you" | "your" | "we" | "i" | "me"))
}

pub async fn resolve_step_intent(
    service: &DesktopAgentService,
    agent_state: &AgentState,
    rules: &ActionRules,
    active_window_title: &str,
) -> Result<ResolvedIntentState, TransactionError> {
    resolve_step_intent_with_state(service, None, agent_state, rules, active_window_title).await
}

pub async fn resolve_step_intent_with_state(
    service: &DesktopAgentService,
    state: Option<&dyn StateAccess>,
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
            required_receipts: vec![],
            required_postconditions: vec![],
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
            provider_selection: None,
            instruction_contract: None,
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
    let runtime = service.reasoning_inference.clone();
    let query_binding_profile =
        infer_query_binding_profile(service, &runtime, agent_state.session_id, &query).await;
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

    let forced_intent_id =
        obvious_casual_conversation_query(&query, &query_binding_profile, &matrix)
            .then_some("conversation.reply");
    if forced_intent_id.is_some() {
        log::info!(
            "IntentResolver forced obvious casual conversation to conversation.reply session={} query_hash={}",
            session_prefix,
            query_hash
        );
    }

    let rank_result = if forced_intent_id.is_some() {
        None
    } else {
        match timeout(
            INTENT_EMBED_RANK_TIMEOUT,
            runtime.embed_or_rank(
                &ranking_query,
                &policy.matrix_version,
                matrix_hash,
                &matrix,
                Some(service),
                Some(agent_state.session_id),
            ),
        )
        .await
        {
            Ok(Ok(result)) => Some(result),
            Ok(Err(e)) => {
                log::warn!(
                    "IntentResolver semantic rank failed session={} error={}",
                    session_prefix,
                    e
                );
                None
            }
            Err(_) => {
                log::warn!(
                    "IntentResolver semantic rank timed out session={} timeout_ms={}",
                    session_prefix,
                    INTENT_EMBED_RANK_TIMEOUT.as_millis()
                );
                None
            }
        }
    };
    let mut ranked_candidates = if let Some(intent_id) = forced_intent_id {
        vec![IntentCandidateScore {
            intent_id: intent_id.to_string(),
            score: 1.0,
        }]
    } else {
        rank_result
            .as_ref()
            .map(|result| result.scores.clone())
            .unwrap_or_default()
    };
    let rank_model_id = rank_result
        .as_ref()
        .map(|result| result.model_id.clone())
        .unwrap_or_else(|| "resolver.unavailable".to_string());
    let rank_model_version = rank_result
        .as_ref()
        .map(|result| result.model_version.clone())
        .unwrap_or_else(|| "v0".to_string());
    let rank_similarity_function_id = rank_result
        .as_ref()
        .map(|result| result.similarity_function_id.clone())
        .unwrap_or_else(|| "none".to_string());
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
            intent_feasible_for_execution(entry, &bindings, rules, &query_binding_profile)
                .then_some(candidate.clone())
        })
        .collect::<Vec<_>>();
    let preferred_selection_top_k = if query_binding_profile.available
        && query_binding_profile.durable_automation_requested
    {
        let durable_candidates = selection_top_k
            .iter()
            .filter_map(|candidate| {
                let entry = matrix
                    .iter()
                    .find(|entry| entry.intent_id == candidate.intent_id)?;
                matches!(
                    entry.query_binding,
                    IntentQueryBindingClass::DurableAutomation
                )
                .then_some(candidate.clone())
            })
            .collect::<Vec<_>>();
        if durable_candidates.is_empty() {
            selection_top_k.clone()
        } else {
            log::info!(
                "IntentResolver narrowed winner candidates to durable automation intents session={} candidate_count={}",
                session_prefix,
                durable_candidates.len()
            );
            durable_candidates
        }
    } else {
        selection_top_k.clone()
    };
    let preferred_selection_top_k = if query_binding_profile.available
        && query_binding_profile.model_registry_control_requested
    {
        let model_control_candidates = preferred_selection_top_k
            .iter()
            .filter_map(|candidate| {
                let entry = matrix
                    .iter()
                    .find(|entry| entry.intent_id == candidate.intent_id)?;
                matches!(
                    entry.query_binding,
                    IntentQueryBindingClass::ModelRegistryControl
                )
                .then_some(candidate.clone())
            })
            .collect::<Vec<_>>();
        if model_control_candidates.is_empty() {
            preferred_selection_top_k
        } else {
            log::info!(
                "IntentResolver narrowed winner candidates to local engine control intents session={} candidate_count={}",
                session_prefix,
                model_control_candidates.len()
            );
            model_control_candidates
        }
    } else {
        preferred_selection_top_k
    };
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
            &query_binding_profile,
        ));
    }
    let unclassified = preferred_selection_top_k.is_empty()
        || all_candidate_scores_zero(&preferred_selection_top_k);
    if unclassified && resolver_error_class.is_none() {
        resolver_error_class = Some("IntentUnclassified".to_string());
    }
    let mut winner = if unclassified {
        IntentCandidateScore {
            intent_id: "resolver.unclassified".to_string(),
            score: 0.0,
        }
    } else {
        select_deterministic_winner(&preferred_selection_top_k, &matrix, policy).unwrap_or(
            IntentCandidateScore {
                intent_id: "resolver.unclassified".to_string(),
                score: 0.0,
            },
        )
    };
    if winner.intent_id != "resolver.unclassified"
        && should_abstain_for_ambiguity(&preferred_selection_top_k, &winner, policy)
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

    fn maybe_promote_low_band_for_policy_exempt_winner(
        winner: &IntentCandidateScore,
        selection_top_k: &[IntentCandidateScore],
        policy: &IntentRoutingPolicy,
        band: IntentConfidenceBand,
    ) -> IntentConfidenceBand {
        if winner.intent_id == "resolver.unclassified" || !matches!(band, IntentConfidenceBand::Low)
        {
            return band;
        }
        if !is_ambiguity_abstain_exempt(policy, &winner.intent_id) {
            return band;
        }

        let winner_bps = score_to_bps(winner.score);
        let second_bps = selection_top_k
            .iter()
            .find(|candidate| candidate.intent_id != winner.intent_id)
            .map(|candidate| score_to_bps(candidate.score))
            .unwrap_or(0);
        let gap_bps = winner_bps.saturating_sub(second_bps);

        if gap_bps >= ambiguity_margin_bps(policy) {
            IntentConfidenceBand::Medium
        } else {
            band
        }
    }

    let (
        scope,
        preferred_tier,
        score,
        band,
        required_capabilities,
        required_receipts,
        required_postconditions,
        risk_class,
        provider_selection,
    ) = if winner.intent_id == "resolver.unclassified" {
        (
            IntentScopeProfile::Unknown,
            "tool_first".to_string(),
            0.0,
            IntentConfidenceBand::Low,
            vec![],
            vec![],
            vec![],
            "unknown".to_string(),
            None,
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
        let base_band = resolve_band(score, policy);
        let band = maybe_promote_low_band_for_policy_exempt_winner(
            &winner,
            &preferred_selection_top_k,
            policy,
            base_band,
        );
        let provider_selection = resolve_provider_selection_state(
            service,
            state,
            &runtime,
            agent_state.session_id,
            &query,
            entry,
            &entry.required_capabilities,
            &bindings,
        )
        .await;
        (
            scope,
            preferred_tier,
            score,
            band,
            entry.required_capabilities.clone(),
            entry.required_receipts.clone(),
            entry.required_postconditions.clone(),
            entry.risk_class.clone(),
            provider_selection,
        )
    };
    let instruction_contract = synthesize_instruction_contract(
        service,
        &runtime,
        agent_state.session_id,
        &query,
        &winner.intent_id,
        &required_capabilities,
        provider_selection.as_ref(),
    )
    .await;
    let required_capabilities = required_capabilities_with_instruction_contract(
        &required_capabilities,
        instruction_contract.as_ref(),
    );
    let mut resolved = ResolvedIntentState {
        intent_id: winner.intent_id,
        scope,
        band,
        score,
        top_k: routed_top_k,
        required_capabilities,
        required_receipts,
        required_postconditions,
        risk_class,
        preferred_tier,
        matrix_version: policy.matrix_version.clone(),
        embedding_model_id: rank_model_id,
        embedding_model_version: rank_model_version,
        similarity_function_id: rank_similarity_function_id,
        intent_set_hash: intent_hash,
        tool_registry_hash: registry_hash,
        capability_ontology_hash: ontology_hash,
        query_normalization_version: INTENT_QUERY_NORMALIZATION_VERSION.to_string(),
        matrix_source_hash: matrix_hash,
        receipt_hash: [0u8; 32],
        provider_selection,
        instruction_contract,
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
