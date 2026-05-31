fn planning_bundle_after_surface_filter(
    entity_filtered_bundle: &WebEvidenceBundle,
    surface_filtered_bundle: WebEvidenceBundle,
    verification_checks: &mut Vec<String>,
) -> WebEvidenceBundle {
    if surface_filtered_bundle.sources.is_empty()
        && surface_filtered_bundle.documents.is_empty()
        && !(entity_filtered_bundle.sources.is_empty()
            && entity_filtered_bundle.documents.is_empty())
    {
        verification_checks
            .push("web_discovery_surface_filter_preserved_empty_bundle=true".to_string());
    }
    surface_filtered_bundle
}

fn market_quote_hint_coverage_count(
    query_contract: &str,
    hints: &[PendingSearchReadSummary],
) -> usize {
    let groups = query_market_quote_entity_anchor_groups(query_contract);
    let quote_hints = hints
        .iter()
        .filter(|hint| {
            let title = hint.title.as_deref().unwrap_or_default();
            let observed_text = format!(
                "{} {}",
                title,
                hint.excerpt
            );
            has_price_quote_payload(&observed_text)
                || candidate_time_sensitive_resolvable_payload(&hint.url, title, &hint.excerpt)
        })
        .collect::<Vec<_>>();
    if groups.len() < 2 {
        return quote_hints.len();
    }

    let mut covered_groups = BTreeSet::new();
    for hint in quote_hints {
        for (idx, group) in groups.iter().enumerate() {
            if market_quote_hint_covers_group(hint, group) {
                covered_groups.insert(idx);
            }
        }
    }
    covered_groups.len()
}

fn market_quote_hint_covers_group(hint: &PendingSearchReadSummary, group: &BTreeSet<String>) -> bool {
    let source_tokens = source_anchor_tokens(
        &hint.url,
        hint.title.as_deref().unwrap_or_default(),
        &hint.excerpt,
    );
    group.iter().any(|token| source_tokens.contains(token))
}

fn market_quote_missing_group_search_query(
    query_contract: &str,
    hints: &[PendingSearchReadSummary],
) -> Option<String> {
    let groups = query_market_quote_entity_anchor_groups(query_contract);
    if groups.is_empty() {
        return market_quote_grounding_search_query(query_contract);
    }

    let quote_hints = hints
        .iter()
        .filter(|hint| {
            let title = hint.title.as_deref().unwrap_or_default();
            let observed_text = format!(
                "{} {}",
                title,
                hint.excerpt
            );
            has_price_quote_payload(&observed_text)
                || candidate_time_sensitive_resolvable_payload(&hint.url, title, &hint.excerpt)
        })
        .collect::<Vec<_>>();
    for group in groups {
        let covered = quote_hints
            .iter()
            .any(|hint| market_quote_hint_covers_group(hint, &group));
        if covered {
            continue;
        }
        let terms = group.into_iter().collect::<Vec<_>>();
        if !terms.is_empty() {
            return Some(format!(
                "{} crypto token live price quote market cap USD today",
                terms.join(" ")
            ));
        }
    }
    None
}

fn market_quote_hint_coverage_floor(query_contract: &str, min_sources: u32) -> usize {
    let anchor_group_floor = query_market_quote_entity_anchor_groups(query_contract)
        .len()
        .max(1);
    if min_sources > 1 {
        anchor_group_floor.max(2)
    } else {
        1
    }
}

fn defer_search_planning_failure_while_recovery_actions_remain(
    agent_state: &mut AgentState,
    verification_checks: &mut Vec<String>,
    success: &mut bool,
    err: &mut Option<String>,
    error: &str,
) -> bool {
    let queued_recovery_actions = queued_web_retrieve_count(agent_state);
    if queued_recovery_actions == 0 || agent_state.pending_search_completion.is_none() {
        return false;
    }

    verification_checks.push(format!("web_pre_read_payload_error={}", error));
    verification_checks.push("web_pre_read_payload_error_nonterminal=true".to_string());
    verification_checks.push(format!(
        "web_queued_web_recovery_actions_remaining={}",
        queued_recovery_actions
    ));
    verification_checks.push("web_pipeline_active=true".to_string());
    verification_checks.push("web_sources_success=0".to_string());
    verification_checks.push("web_sources_blocked=0".to_string());
    verification_checks.push("web_budget_ms=0".to_string());
    *success = true;
    *err = None;
    agent_state.status = AgentStatus::Running;
    true
}

fn should_complete_web_search_after_duplicate_no_effect(
    agent_state: &AgentState,
    tool_name: &str,
    is_gated: bool,
    success: bool,
    err: Option<&str>,
) -> bool {
    if success || is_gated || !matches!(tool_name, "web__search" | "memory__search") {
        return false;
    }
    if !is_web_research_scope(agent_state) {
        return false;
    }
    if !err
        .map(|value| {
            value.contains("ERROR_CLASS=NoEffectAfterAction")
                || value.contains("NoEffectAfterAction")
        })
        .unwrap_or(false)
    {
        return false;
    }
    agent_state
        .pending_search_completion
        .as_ref()
        .map(|pending| !pending.successful_reads.is_empty())
        .unwrap_or(false)
}

#[cfg(test)]
fn source_list_request_allows_search_result_terminalization(
    agent_state: &AgentState,
    pending: &PendingSearchCompletion,
    payload_error: Option<&str>,
) -> bool {
    let _ = (agent_state, pending, payload_error);
    false
}

fn recovered_pre_read_selection_after_payload_error(
    retrieval_contract: &WebRetrievalContract,
    query_contract: &str,
    required_url_count: usize,
    candidate_recovery_selected_urls: &[String],
    candidate_recovery_plan: &crate::agentic::runtime::service::queue::support::PreReadCandidatePlan,
    payload_source_hints: &[PendingSearchReadSummary],
) -> Option<PreReadSelectionResponse> {
    let mut candidate_recovery_urls = if !candidate_recovery_selected_urls.is_empty() {
        candidate_recovery_selected_urls.to_vec()
    } else {
        distinct_domain_preserving_selected_urls(
            retrieval_contract,
            query_contract,
            &candidate_recovery_plan.candidate_urls,
            required_url_count,
        )
    };
    if candidate_recovery_urls.is_empty() {
        candidate_recovery_urls = candidate_recovery_plan
            .candidate_urls
            .iter()
            .take(required_url_count)
            .cloned()
            .collect::<Vec<_>>();
    }
    if candidate_recovery_urls.is_empty() {
        let payload_hint_urls = payload_source_hints
            .iter()
            .filter_map(|hint| {
                let trimmed = hint.url.trim();
                (!trimmed.is_empty()
                    && is_citable_web_url(trimmed)
                    && !is_search_hub_url(trimmed))
                .then(|| trimmed.to_string())
            })
            .collect::<Vec<_>>();
        candidate_recovery_urls = distinct_domain_preserving_selected_urls(
            retrieval_contract,
            query_contract,
            &payload_hint_urls,
            required_url_count,
        );
        if candidate_recovery_urls.is_empty() {
            candidate_recovery_urls = payload_hint_urls
                .into_iter()
                .take(required_url_count)
                .collect::<Vec<_>>();
        }
    }
    if candidate_recovery_urls.is_empty() {
        return None;
    }
    Some(PreReadSelectionResponse {
        selection_mode: PreReadSelectionMode::DirectDetail,
        urls: candidate_recovery_urls,
    })
}

async fn complete_web_search_after_duplicate_no_effect_if_ready(
    service: &RuntimeAgentService,
    agent_state: &mut AgentState,
    session_id: [u8; 32],
    pre_state_step_index: u32,
    intent_id: &str,
    tool_name: &str,
    is_gated: bool,
    success: &mut bool,
    out: &mut Option<String>,
    err: &mut Option<String>,
    completion_summary: &mut Option<String>,
    verification_checks: &mut Vec<String>,
) -> Result<bool, TransactionError> {
    if !should_complete_web_search_after_duplicate_no_effect(
        agent_state,
        tool_name,
        is_gated,
        *success,
        err.as_deref(),
    ) {
        return Ok(false);
    }

    let Some(pending) = agent_state.pending_search_completion.clone() else {
        return Ok(false);
    };
    mark_web_pipeline_waiting_for_model_answer(
        service,
        agent_state,
        session_id,
        pre_state_step_index,
        intent_id,
        pending,
        WebPipelineCompletionReason::MinSourcesReached,
        out,
        err,
        completion_summary,
        verification_checks,
    );
    *success = true;
    verification_checks
        .push("web_duplicate_search_no_effect_waiting_for_model_answer=true".to_string());
    Ok(true)
}

fn evidence_probe_recovery_source_hints(
    discovery_hints: &[PendingSearchReadSummary],
    probe_source_hints: &[PendingSearchReadSummary],
    authority_hint_read_recovery_urls: &[String],
) -> Vec<PendingSearchReadSummary> {
    let mut merged = merge_source_hints(discovery_hints.to_vec(), probe_source_hints);
    for url in authority_hint_read_recovery_urls {
        let trimmed = url.trim();
        if trimmed.is_empty() {
            continue;
        }
        if merged.iter().any(|existing| {
            existing.url.eq_ignore_ascii_case(trimmed)
                || url_structurally_equivalent(&existing.url, trimmed)
        }) {
            continue;
        }
        merged.push(PendingSearchReadSummary {
            url: trimmed.to_string(),
            title: None,
            excerpt: String::new(),
        });
    }
    merged
}

fn ordered_source_hints_with_selected_urls_first(
    selected_urls: &[String],
    source_hints: &[PendingSearchReadSummary],
) -> Vec<PendingSearchReadSummary> {
    let mut ordered = Vec::new();
    let mut seen_urls = BTreeSet::new();

    for url in selected_urls {
        let trimmed = url.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some(hint) = source_hints.iter().find(|hint| {
            hint.url.eq_ignore_ascii_case(trimmed)
                || url_structurally_equivalent(&hint.url, trimmed)
        }) {
            if seen_urls.insert(hint.url.trim().to_ascii_lowercase()) {
                ordered.push(hint.clone());
            }
        } else if seen_urls.insert(trimmed.to_ascii_lowercase()) {
            ordered.push(PendingSearchReadSummary {
                url: trimmed.to_string(),
                title: None,
                excerpt: String::new(),
            });
        }
    }

    for hint in source_hints {
        let trimmed = hint.url.trim();
        if trimmed.is_empty() {
            continue;
        }
        if seen_urls.insert(trimmed.to_ascii_lowercase()) {
            ordered.push(hint.clone());
        }
    }

    ordered
}

fn search_attempt_urls_from_bundle(
    bundle: &WebEvidenceBundle,
    candidate_urls: &[String],
    source_hints: &[PendingSearchReadSummary],
) -> Vec<String> {
    let Some(trimmed) = bundle
        .url
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Vec::new();
    };

    let matches_candidate_source = candidate_urls
        .iter()
        .map(String::as_str)
        .chain(source_hints.iter().map(|hint| hint.url.as_str()))
        .map(str::trim)
        .filter(|candidate| !candidate.is_empty())
        .any(|candidate| {
            candidate.eq_ignore_ascii_case(trimmed)
                || url_structurally_equivalent(candidate, trimmed)
        });

    if matches_candidate_source && !is_search_hub_url(trimmed) {
        Vec::new()
    } else {
        vec![trimmed.to_string()]
    }
}

fn pre_read_selection_sources_from_planning_context(
    planning_bundle: &WebEvidenceBundle,
    prioritized_hints: &[PendingSearchReadSummary],
) -> Vec<WebSource> {
    let mut merged = Vec::new();
    let mut seen = BTreeSet::new();

    let mut push_source =
        |url: &str, title: Option<String>, snippet: Option<String>, domain: Option<String>| {
            let trimmed = url.trim();
            if trimmed.is_empty() {
                return;
            }
            let dedup_key = crate::agentic::web::normalize_url_for_id(trimmed);
            if !seen.insert(dedup_key) {
                return;
            }
            merged.push(WebSource {
                source_id: crate::agentic::web::source_id_for_url(trimmed),
                rank: Some(merged.len() as u32 + 1),
                url: trimmed.to_string(),
                title: title.filter(|value| !value.trim().is_empty()),
                snippet: snippet.filter(|value| !value.trim().is_empty()),
                domain,
            });
        };

    for hint in prioritized_hints {
        let trimmed = hint.url.trim();
        if trimmed.is_empty() {
            continue;
        }
        let existing_source = planning_bundle.sources.iter().find(|source| {
            source.url.eq_ignore_ascii_case(trimmed)
                || url_structurally_equivalent(&source.url, trimmed)
        });
        push_source(
            trimmed,
            hint.title
                .clone()
                .filter(|value| !value.trim().is_empty())
                .or_else(|| {
                    existing_source
                        .and_then(|source| source.title.clone())
                        .filter(|value| !value.trim().is_empty())
                }),
            (!hint.excerpt.trim().is_empty())
                .then(|| hint.excerpt.trim().to_string())
                .or_else(|| {
                    existing_source
                        .and_then(|source| source.snippet.clone())
                        .filter(|value| !value.trim().is_empty())
                }),
            existing_source
                .and_then(|source| source.domain.clone())
                .filter(|value| !value.trim().is_empty())
                .or_else(|| {
                    url::Url::parse(trimmed)
                        .ok()
                        .and_then(|parsed| parsed.host_str().map(str::to_string))
                }),
        );
    }

    for source in &planning_bundle.sources {
        push_source(
            &source.url,
            source.title.clone(),
            source.snippet.clone(),
            source.domain.clone(),
        );
    }

    merged
}

fn pre_read_selection_source_observations_from_planning_context(
    planning_bundle: &WebEvidenceBundle,
    selection_sources: &[WebSource],
) -> Vec<ioi_types::app::agentic::WebSourceObservation> {
    planning_bundle
        .source_observations
        .iter()
        .filter(|observation| {
            selection_sources.iter().any(|source| {
                observation.url.eq_ignore_ascii_case(&source.url)
                    || url_structurally_equivalent(&observation.url, &source.url)
            })
        })
        .cloned()
        .collect()
}

fn source_hints_from_web_sources(sources: &[WebSource]) -> Vec<PendingSearchReadSummary> {
    sources
        .iter()
        .filter_map(|source| {
            let trimmed = source.url.trim();
            (!trimmed.is_empty()).then(|| PendingSearchReadSummary {
                url: trimmed.to_string(),
                title: source
                    .title
                    .clone()
                    .filter(|value| !value.trim().is_empty()),
                excerpt: source
                    .snippet
                    .as_deref()
                    .unwrap_or_default()
                    .trim()
                    .to_string(),
            })
        })
        .collect()
}

fn seed_pending_inventory_from_pre_read_payload_hints(
    pending: &mut PendingSearchCompletion,
    payload_source_hints: &[PendingSearchReadSummary],
) -> bool {
    let merged_candidate_urls = merge_url_sequence(
        pending.candidate_urls.clone(),
        payload_source_hints
            .iter()
            .map(|hint| hint.url.clone())
            .collect::<Vec<_>>(),
    );
    let merged_candidate_source_hints =
        merge_source_hints(pending.candidate_source_hints.clone(), payload_source_hints);
    let changed = merged_candidate_urls != pending.candidate_urls
        || merged_candidate_source_hints != pending.candidate_source_hints;
    if changed {
        pending.candidate_urls = merged_candidate_urls;
        pending.candidate_source_hints = merged_candidate_source_hints;
    }
    changed
}

fn authority_hint_read_recovery_site_terms(urls: &[String]) -> Vec<String> {
    let mut terms = std::collections::BTreeSet::new();
    for url in urls {
        let Ok(parsed) = url::Url::parse(url.trim()) else {
            continue;
        };
        let Some(host) = parsed.host_str() else {
            continue;
        };
        let normalized_host = host
            .strip_prefix("www.")
            .unwrap_or(host)
            .to_ascii_lowercase();
        let path = parsed.path().to_ascii_lowercase();
        if path.contains("/pubs/") {
            terms.insert(format!("site:{normalized_host}/pubs"));
        }
        if path.contains("/publications/") {
            terms.insert(format!("site:{normalized_host}/publications"));
        }
        if path.contains("/standards/") {
            terms.insert(format!("site:{normalized_host}/standards"));
        }
    }
    terms.into_iter().collect()
}

fn append_missing_query_terms(base_query: &str, terms: &[String]) -> String {
    let mut query = base_query.trim().to_string();
    let mut seen_terms = std::collections::BTreeSet::new();
    for token in query.split_whitespace() {
        let trimmed = token.trim();
        if !trimmed.is_empty() {
            seen_terms.insert(trimmed.to_ascii_lowercase());
        }
    }
    for term in terms {
        let trimmed = term.trim();
        let normalized = trimmed.to_ascii_lowercase();
        if trimmed.is_empty() || seen_terms.contains(&normalized) {
            continue;
        }
        if !query.is_empty() {
            query.push(' ');
        }
        query.push_str(trimmed);
        seen_terms.insert(normalized);
    }
    query
}

fn local_business_alignment_target_name(
    url: &str,
    source_hints: &[PendingSearchReadSummary],
    locality_hint: Option<&str>,
) -> Option<String> {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return None;
    }
    let hint = selected_url_hint(source_hints, trimmed);
    let title = hint
        .and_then(|entry| entry.title.as_deref())
        .unwrap_or_default();
    let excerpt = hint.map(|entry| entry.excerpt.as_str()).unwrap_or_default();
    local_business_target_name_from_source(
        &PendingSearchReadSummary {
            url: trimmed.to_string(),
            title: (!title.trim().is_empty()).then(|| title.trim().to_string()),
            excerpt: excerpt.trim().to_string(),
        },
        locality_hint,
    )
}

fn local_business_selected_url_semantically_aligned(
    selected_url: &str,
    aligned_urls: &[String],
    source_hints: &[PendingSearchReadSummary],
    locality_hint: Option<&str>,
) -> bool {
    if url_in_alignment_set(selected_url, aligned_urls) {
        return true;
    }
    let Some(selected_target) =
        local_business_alignment_target_name(selected_url, source_hints, locality_hint)
    else {
        return false;
    };
    aligned_urls.iter().any(|aligned_url| {
        local_business_alignment_target_name(aligned_url, source_hints, locality_hint)
            .map(|aligned_target| aligned_target.eq_ignore_ascii_case(&selected_target))
            .unwrap_or(false)
    })
}

fn selected_url_alignment_source(
    url: &str,
    source_hints: &[PendingSearchReadSummary],
    rank: usize,
) -> ioi_types::app::agentic::WebSource {
    let trimmed = url.trim();
    let hint = selected_url_hint(source_hints, trimmed);
    let title = hint.and_then(|entry| entry.title.clone());
    let excerpt = hint.map(|entry| entry.excerpt.trim().to_string());
    let domain = url::Url::parse(trimmed)
        .ok()
        .and_then(|parsed| parsed.host_str().map(str::to_string));

    ioi_types::app::agentic::WebSource {
        source_id: format!("selected-alignment-{rank}"),
        rank: Some(rank as u32),
        url: trimmed.to_string(),
        title,
        snippet: excerpt,
        domain,
    }
}

fn selected_source_alignment_urls(
    query_contract: &str,
    retrieval_contract: &ioi_types::app::agentic::WebRetrievalContract,
    selected_urls: &[String],
    aligned_urls: &[String],
    source_hints: &[PendingSearchReadSummary],
    locality_hint: Option<&str>,
) -> Vec<String> {
    if crate::agentic::web::contract_requires_geo_scoped_entity_expansion(retrieval_contract) {
        return selected_urls
            .iter()
            .filter(|selected| {
                local_business_selected_url_semantically_aligned(
                    selected,
                    aligned_urls,
                    source_hints,
                    locality_hint,
                )
            })
            .cloned()
            .collect();
    }

    let selected_sources = selected_urls
        .iter()
        .enumerate()
        .map(|(index, url)| selected_url_alignment_source(url, source_hints, index + 1))
        .collect::<Vec<_>>();
    crate::agentic::web::query_matching_source_urls(
        query_contract,
        retrieval_contract,
        &selected_sources,
    )
    .unwrap_or_else(|_| {
        selected_urls
            .iter()
            .filter(|selected| url_in_alignment_set(selected, aligned_urls))
            .cloned()
            .collect()
    })
}

fn evidence_grounded_recovery_required(
    query_contract: &str,
    retrieval_contract: &ioi_types::app::agentic::WebRetrievalContract,
    candidate_recovery_plan: &crate::agentic::runtime::service::queue::support::PreReadCandidatePlan,
    required_url_count: usize,
    candidate_recovery_selection_ready: bool,
) -> bool {
    query_prefers_document_report_layout(query_contract)
        && !query_requests_comparison(query_contract)
        && crate::agentic::runtime::service::decision_loop::signals::analyze_query_facets(
            query_contract,
        )
        .grounded_external_required
        && (retrieval_contract.currentness_required
            || retrieval_contract.source_independence_min > 1)
        && !candidate_recovery_selection_ready
        && candidate_recovery_plan.candidate_urls.len() < required_url_count
        && candidate_recovery_plan.requires_constraint_search_probe
}

fn pending_search_matches_query_contract(
    pending: &PendingSearchCompletion,
    query_contract: &str,
) -> bool {
    let pending_contract = pending.query_contract.trim();
    let incoming_contract = query_contract.trim();
    pending_contract.is_empty()
        || incoming_contract.is_empty()
        || pending_contract.eq_ignore_ascii_case(incoming_contract)
}

fn merge_candidate_recovery_plan_with_pending_inventory(
    retrieval_contract: &ioi_types::app::agentic::WebRetrievalContract,
    query_contract: &str,
    min_sources: u32,
    locality_hint: Option<&str>,
    pending: Option<&PendingSearchCompletion>,
    candidate_recovery_plan: crate::agentic::runtime::service::queue::support::PreReadCandidatePlan,
    verification_checks: &mut Vec<String>,
) -> crate::agentic::runtime::service::queue::support::PreReadCandidatePlan {
    let required_url_count = min_sources.max(1) as usize;
    let Some(pending) = pending else {
        verification_checks.push("web_pre_read_pending_inventory_reused=false".to_string());
        return candidate_recovery_plan;
    };
    let market_quote_inventory_floor_met = !query_requires_market_quote_grounding(query_contract)
        || market_quote_hint_coverage_count(query_contract, &candidate_recovery_plan.candidate_source_hints)
            >= market_quote_hint_coverage_floor(query_contract, min_sources);
    if (candidate_recovery_plan.candidate_urls.len() >= required_url_count
        && market_quote_inventory_floor_met)
        || (!pending_search_matches_query_contract(pending, query_contract))
        || (pending.candidate_urls.is_empty()
            && pending.candidate_source_hints.is_empty()
            && pending.successful_reads.is_empty())
    {
        verification_checks.push("web_pre_read_pending_inventory_reused=false".to_string());
        return candidate_recovery_plan;
    }

    let pending_reuse_source_hints = merge_source_hints(
        pending.successful_reads.clone(),
        &pending.candidate_source_hints,
    );
    let pending_candidate_urls = merge_url_sequence(
        pending.candidate_urls.clone(),
        pending
            .candidate_source_hints
            .iter()
            .map(|hint| hint.url.clone())
            .collect::<Vec<_>>(),
    );
    let pending_recovery_candidate_urls = merge_url_sequence(
        pending
            .successful_reads
            .iter()
            .map(|hint| hint.url.clone())
            .collect::<Vec<_>>(),
        pending_candidate_urls.clone(),
    );
    let merged_candidate_urls = merge_url_sequence(
        pending_candidate_urls.clone(),
        candidate_recovery_plan.candidate_urls.clone(),
    );
    let merged_candidate_source_hints = merge_source_hints(
        pending_reuse_source_hints,
        &candidate_recovery_plan.candidate_source_hints,
    );
    let mut merged_plan = pre_read_candidate_plan_with_contract(
        Some(retrieval_contract),
        query_contract,
        min_sources,
        merged_candidate_urls,
        merged_candidate_source_hints.clone(),
        locality_hint,
        true,
    );
    let pending_inventory_floor_recovery_required = evidence_grounded_recovery_required(
        query_contract,
        retrieval_contract,
        &merged_plan,
        required_url_count,
        false,
    );
    if pending_inventory_floor_recovery_required {
        let recovery_seed_plan =
            crate::agentic::runtime::service::queue::support::PreReadCandidatePlan {
                candidate_urls: merge_url_sequence(
                    pending_recovery_candidate_urls.clone(),
                    candidate_recovery_plan.candidate_urls.clone(),
                ),
                candidate_source_hints: merged_candidate_source_hints.clone(),
                probe_source_hints: merged_plan.probe_source_hints.clone(),
                total_candidates: pending_recovery_candidate_urls.len(),
                pruned_candidates: 0,
                resolvable_candidates: merged_plan.resolvable_candidates,
                scoreable_candidates: merged_plan.scoreable_candidates,
                requires_constraint_search_probe: true,
            };
        let recovery_urls = evidence_authority_hint_read_recovery_urls(
            retrieval_contract,
            query_contract,
            min_sources,
            &recovery_seed_plan,
            &pending.successful_reads,
            &[],
            locality_hint,
            required_url_count,
        );
        let recovery_materially_improves_plan = !recovery_urls.is_empty()
            && (recovery_urls.len() > merged_plan.candidate_urls.len()
                || recovery_urls.iter().any(|recovery_url| {
                    !merged_plan.candidate_urls.iter().any(|existing_url| {
                        existing_url.eq_ignore_ascii_case(recovery_url)
                            || url_structurally_equivalent(existing_url, recovery_url)
                    })
                }));
        if recovery_materially_improves_plan {
            let recovery_source_hints = ordered_source_hints_with_selected_urls_first(
                &recovery_urls,
                &merged_candidate_source_hints,
            );
            verification_checks
                .push("web_pre_read_pending_inventory_floor_recovery_applied=true".to_string());
            verification_checks.push(format!(
                "web_pre_read_pending_inventory_floor_recovery_urls={}",
                recovery_urls.len()
            ));
            merged_plan = crate::agentic::runtime::service::queue::support::PreReadCandidatePlan {
                candidate_urls: recovery_urls.clone(),
                candidate_source_hints: recovery_source_hints.clone(),
                probe_source_hints: evidence_probe_recovery_source_hints(
                    &recovery_source_hints,
                    &merged_plan.probe_source_hints,
                    &recovery_urls,
                ),
                total_candidates: recovery_seed_plan.total_candidates,
                pruned_candidates: recovery_seed_plan
                    .total_candidates
                    .saturating_sub(recovery_urls.len()),
                resolvable_candidates: merged_plan.resolvable_candidates,
                scoreable_candidates: merged_plan.scoreable_candidates,
                requires_constraint_search_probe: true,
            };
        }
    }
    let reused = merged_plan.candidate_urls.len() > candidate_recovery_plan.candidate_urls.len()
        || merged_plan.candidate_source_hints != candidate_recovery_plan.candidate_source_hints
        || merged_plan.probe_source_hints != candidate_recovery_plan.probe_source_hints;
    verification_checks.push(format!("web_pre_read_pending_inventory_reused={}", reused));
    verification_checks.push(format!(
        "web_pre_read_pending_inventory_candidate_urls={}",
        pending_candidate_urls.len()
    ));
    verification_checks.push(format!(
        "web_pre_read_pending_inventory_raw_candidate_urls={}",
        pending.candidate_urls.len()
    ));
    verification_checks.push(format!(
        "web_pre_read_pending_inventory_candidate_source_hints={}",
        pending.candidate_source_hints.len()
    ));
    verification_checks.push(format!(
        "web_pre_read_pending_inventory_successful_read_hints={}",
        pending.successful_reads.len()
    ));
    verification_checks.push(format!(
        "web_pre_read_pending_inventory_merged_candidate_urls={}",
        merged_plan.candidate_urls.len()
    ));
    if reused {
        merged_plan
    } else {
        candidate_recovery_plan
    }
}

fn evidence_authority_hint_read_recovery_urls(
    retrieval_contract: &ioi_types::app::agentic::WebRetrievalContract,
    query_contract: &str,
    min_sources: u32,
    candidate_recovery_plan: &crate::agentic::runtime::service::queue::support::PreReadCandidatePlan,
    preferred_read_backed_hints: &[PendingSearchReadSummary],
    discovery_hints: &[PendingSearchReadSummary],
    locality_hint: Option<&str>,
    required_url_count: usize,
) -> Vec<String> {
    let domain_key_for_url = |url: &str| {
        crate::agentic::runtime::service::queue::support::source_host(url)
            .map(|host| host.strip_prefix("www.").unwrap_or(&host).to_string())
    };
    let authority_slot_cap = crate::agentic::runtime::service::queue::support::retrieval_contract_primary_authority_source_slot_cap(
        Some(retrieval_contract),
        query_contract,
        required_url_count,
    );
    if authority_slot_cap == 0 {
        return Vec::new();
    }
    let merged_hints = merge_source_hints(
        discovery_hints.to_vec(),
        &candidate_recovery_plan.candidate_source_hints,
    );
    let candidate_urls = merge_url_sequence(
        candidate_recovery_plan.candidate_urls.clone(),
        merged_hints
            .iter()
            .map(|hint| hint.url.clone())
            .collect::<Vec<_>>(),
    );
    let reranked_plan = pre_read_candidate_plan_with_contract(
        Some(retrieval_contract),
        query_contract,
        min_sources,
        candidate_urls.clone(),
        merged_hints.clone(),
        locality_hint,
        true,
    );
    let recovery_urls = if reranked_plan.candidate_urls.is_empty() {
        candidate_urls.clone()
    } else {
        reranked_plan.candidate_urls
    };
    let preferred_read_backed_authority_url = preferred_read_backed_hints.iter().find_map(|hint| {
        let trimmed = hint.url.trim();
        let present_in_recovery_inventory = !trimmed.is_empty()
            && candidate_urls.iter().any(|candidate| {
                candidate.eq_ignore_ascii_case(trimmed)
                    || url_structurally_equivalent(candidate, trimmed)
            });
        present_in_recovery_inventory.then(|| trimmed.to_string())
    });
    let mut recovery_urls = recovery_urls;
    if let Some(preferred_url) = preferred_read_backed_authority_url {
        if let Some(existing_idx) = recovery_urls.iter().position(|existing| {
            existing.eq_ignore_ascii_case(preferred_url.as_str())
                || url_structurally_equivalent(existing, preferred_url.as_str())
        }) {
            let preferred = recovery_urls.remove(existing_idx);
            recovery_urls.insert(0, preferred);
        } else {
            recovery_urls.insert(0, preferred_url);
        }
    }
    let support_priority_urls = merged_hints
        .iter()
        .filter_map(|hint| {
            let trimmed = hint.url.trim();
            if trimmed.is_empty() {
                return None;
            }
            let title = hint.title.as_deref().unwrap_or_default();
            let excerpt = hint.excerpt.as_str();
            let grounded_primary_authority =
                crate::agentic::runtime::service::queue::support::source_has_grounded_primary_authority(
                    query_contract,
                    trimmed,
                    title,
                    excerpt,
                );
            let identifier_bearing =
                crate::agentic::runtime::service::queue::support::source_has_evidence_standard_identifier_signal(
                    query_contract,
                    trimmed,
                    title,
                    excerpt,
                );
            let query_grounded =
                crate::agentic::runtime::service::queue::support::excerpt_has_query_grounding_signal_with_contract(
                    Some(retrieval_contract),
                    query_contract,
                    min_sources as usize,
                    trimmed,
                    title,
                    excerpt,
                );
            (!grounded_primary_authority && (identifier_bearing || query_grounded))
                .then(|| trimmed.to_string())
        })
        .collect::<Vec<_>>();
    let distinct_domain_floor =
        crate::agentic::runtime::service::queue::support::retrieval_contract_required_distinct_domain_floor(
            Some(retrieval_contract),
            query_contract,
        )
        .min(required_url_count);
    let authority_batch_target = if distinct_domain_floor > 1 {
        1
    } else {
        authority_slot_cap.min(required_url_count)
    };
    let mut selected = pre_read_batch_urls(&recovery_urls, authority_batch_target.max(1));
    if distinct_domain_floor <= 1 || selected.len() >= required_url_count {
        return selected;
    }

    let recovery_backfill_urls = if authority_batch_target == 1 && !support_priority_urls.is_empty()
    {
        merge_url_sequence(support_priority_urls, recovery_urls.clone())
    } else {
        recovery_urls.clone()
    };
    let mut seen_domains = selected
        .iter()
        .filter_map(|url| domain_key_for_url(url))
        .collect::<BTreeSet<_>>();
    for url in &recovery_backfill_urls {
        if selected.len() >= required_url_count || seen_domains.len() >= distinct_domain_floor {
            break;
        }
        if selected.iter().any(|existing| {
            existing.eq_ignore_ascii_case(url.as_str())
                || crate::agentic::runtime::service::queue::support::url_structurally_equivalent(
                    existing, &url,
                )
        }) {
            continue;
        }
        let Some(domain_key) = domain_key_for_url(&url) else {
            continue;
        };
        if seen_domains.contains(&domain_key) {
            continue;
        }
        seen_domains.insert(domain_key);
        selected.push(url.clone());
    }

    if selected.len() >= required_url_count {
        return selected;
    }

    for url in &recovery_backfill_urls {
        if selected.len() >= required_url_count {
            break;
        }
        if selected.iter().any(|existing| {
            existing.eq_ignore_ascii_case(url.as_str())
                || crate::agentic::runtime::service::queue::support::url_structurally_equivalent(
                    existing, &url,
                )
        }) {
            continue;
        }
        selected.push(url.clone());
    }

    selected
}

fn distinct_domain_preserving_selected_urls(
    retrieval_contract: &ioi_types::app::agentic::WebRetrievalContract,
    query_contract: &str,
    candidate_urls: &[String],
    required_url_count: usize,
) -> Vec<String> {
    let batch_target = required_url_count.max(1);
    let distinct_domain_floor =
        crate::agentic::runtime::service::queue::support::retrieval_contract_required_distinct_domain_floor(
            Some(retrieval_contract),
            query_contract,
        )
        .min(batch_target);
    if distinct_domain_floor <= 1
        || !query_prefers_document_report_layout(query_contract)
        || query_requests_comparison(query_contract)
    {
        return pre_read_batch_urls(candidate_urls, batch_target);
    }

    let domain_key_for_url = |url: &str| {
        crate::agentic::runtime::service::queue::support::source_host(url)
            .map(|host| host.strip_prefix("www.").unwrap_or(&host).to_string())
            .unwrap_or_else(|| url.trim().to_ascii_lowercase())
    };

    let mut selected: Vec<String> = Vec::new();
    let mut deferred: Vec<String> = Vec::new();
    let mut seen_domains = std::collections::BTreeSet::new();

    for url in candidate_urls {
        let trimmed = url.trim();
        if trimmed.is_empty() {
            continue;
        }
        if selected.iter().chain(deferred.iter()).any(|existing| {
            existing.eq_ignore_ascii_case(trimmed) || url_structurally_equivalent(existing, trimmed)
        }) {
            continue;
        }

        let domain_key = domain_key_for_url(trimmed);
        if selected.is_empty() {
            seen_domains.insert(domain_key);
            selected.push(trimmed.to_string());
            continue;
        }

        if selected.len() < batch_target
            && seen_domains.len() < distinct_domain_floor
            && !seen_domains.contains(&domain_key)
        {
            seen_domains.insert(domain_key);
            selected.push(trimmed.to_string());
        } else {
            deferred.push(trimmed.to_string());
        }

        if selected.len() >= batch_target && seen_domains.len() >= distinct_domain_floor {
            break;
        }
    }

    selected.extend(deferred);
    selected.truncate(batch_target);
    selected
}

fn merge_candidate_urls_preserving_order(
    primary: &[String],
    secondary: &[String],
    tertiary: &[String],
) -> Vec<String> {
    let mut merged = Vec::new();
    let mut seen = std::collections::BTreeSet::new();

    for url in primary
        .iter()
        .chain(secondary.iter())
        .chain(tertiary.iter())
    {
        let trimmed = url.trim();
        if trimmed.is_empty() {
            continue;
        }
        let dedup_key = crate::agentic::web::normalize_url_for_id(trimmed);
        if seen.insert(dedup_key) {
            merged.push(trimmed.to_string());
        }
    }

    merged
}

const EVIDENCE_GROUNDED_RECOVERY_MARKER_PREFIX: &str = "ioi://evidence-grounded-recovery/";

fn evidence_grounded_recovery_marker(query: &str) -> Option<String> {
    let compact = compact_whitespace(query);
    let trimmed = compact.trim();
    (!trimmed.is_empty())
        .then(|| format!("{}{}", EVIDENCE_GROUNDED_RECOVERY_MARKER_PREFIX, trimmed))
}

fn evidence_grounded_recovery_attempted(
    pending: Option<&PendingSearchCompletion>,
    query: &str,
) -> bool {
    let Some(marker) = evidence_grounded_recovery_marker(query) else {
        return false;
    };
    pending
        .map(|entry| {
            entry
                .attempted_urls
                .iter()
                .any(|existing| existing.eq_ignore_ascii_case(&marker))
        })
        .unwrap_or(false)
}

fn mark_evidence_grounded_recovery_attempt(pending: &mut PendingSearchCompletion, query: &str) {
    let Some(marker) = evidence_grounded_recovery_marker(query) else {
        return;
    };
    if pending
        .attempted_urls
        .iter()
        .any(|existing| existing.eq_ignore_ascii_case(&marker))
    {
        return;
    }
    pending.attempted_urls.push(marker);
}

fn semantic_alignment_recovery_query(
    query_contract: &str,
    query_value: &str,
    retrieval_contract: &ioi_types::app::agentic::WebRetrievalContract,
    min_sources: u32,
    candidate_hints: &[PendingSearchReadSummary],
    locality_hint: Option<&str>,
) -> String {
    if crate::agentic::web::contract_requires_geo_scoped_entity_expansion(retrieval_contract) {
        return crate::agentic::runtime::service::queue::web_pipeline::local_business_entity_discovery_query_contract(
            query_contract,
            locality_hint,
        );
    }

    constraint_grounded_probe_query_with_contract_and_hints_and_locality_hint(
        query_contract,
        Some(retrieval_contract),
        min_sources,
        candidate_hints,
        query_value,
        locality_hint,
    )
    .unwrap_or_else(|| {
        constraint_grounded_search_query_with_contract_and_hints_and_locality_hint(
            query_contract,
            Some(retrieval_contract),
            min_sources,
            candidate_hints,
            locality_hint,
        )
    })
}

fn planning_bundle_from_discovery_sources(
    bundle: &WebEvidenceBundle,
    retrieval_contract: &ioi_types::app::agentic::WebRetrievalContract,
    discovery_sources: Vec<WebSource>,
    source_observations: &[ioi_types::app::agentic::WebSourceObservation],
    verification_checks: &mut Vec<String>,
) -> WebEvidenceBundle {
    let retained_source_urls = discovery_sources
        .iter()
        .map(|source| source.url.trim().to_string())
        .filter(|url| !url.is_empty())
        .collect::<Vec<_>>();
    let surface_filtered_bundle = WebEvidenceBundle {
        schema_version: bundle.schema_version,
        retrieved_at_ms: bundle.retrieved_at_ms,
        tool: bundle.tool.clone(),
        backend: bundle.backend.clone(),
        query: bundle.query.clone(),
        url: bundle.url.clone(),
        sources: discovery_sources,
        source_observations: source_observations
            .iter()
            .filter(|observation| {
                retained_source_urls.iter().any(|retained_url| {
                    observation.url.eq_ignore_ascii_case(retained_url)
                        || url_structurally_equivalent(&observation.url, retained_url)
                })
            })
            .cloned()
            .collect(),
        documents: vec![],
        provider_candidates: bundle.provider_candidates.clone(),
        retrieval_contract: Some(retrieval_contract.clone()),
    };
    planning_bundle_after_surface_filter(bundle, surface_filtered_bundle, verification_checks)
}

fn candidate_recovery_local_business_direct_detail_urls(
    retrieval_contract: &ioi_types::app::agentic::WebRetrievalContract,
    query_contract: &str,
    min_sources: u32,
    candidate_urls: &[String],
    source_hints: &[PendingSearchReadSummary],
    locality_hint: Option<&str>,
    required_url_count: usize,
) -> Vec<String> {
    if !crate::agentic::web::contract_requires_geo_scoped_entity_expansion(retrieval_contract) {
        return candidate_urls
            .iter()
            .take(required_url_count)
            .cloned()
            .collect::<Vec<_>>();
    }

    let mut direct_detail_sources = Vec::new();
    let mut seen = BTreeSet::new();
    for candidate_url in candidate_urls {
        let trimmed = candidate_url.trim();
        if trimmed.is_empty() {
            continue;
        }
        let hint = selected_url_hint(source_hints, trimmed);
        let title = hint
            .and_then(|entry| entry.title.as_deref())
            .unwrap_or_default();
        let excerpt = hint.map(|entry| entry.excerpt.as_str()).unwrap_or_default();
        let affordances = retrieval_affordances_with_contract_and_locality_hint(
            Some(retrieval_contract),
            query_contract,
            min_sources.max(1),
            source_hints,
            locality_hint,
            trimmed,
            title,
            excerpt,
        );
        if !affordances.contains(&RetrievalAffordanceKind::DirectCitationRead) {
            continue;
        }
        if !seen.insert(trimmed.to_ascii_lowercase()) {
            continue;
        }
        direct_detail_sources.push(PendingSearchReadSummary {
            url: trimmed.to_string(),
            title: (!title.trim().is_empty()).then(|| title.trim().to_string()),
            excerpt: excerpt.trim().to_string(),
        });
    }

    let target_names = local_business_target_names_from_sources(
        &direct_detail_sources,
        locality_hint,
        required_url_count,
    );
    if target_names.len() < required_url_count {
        return Vec::new();
    }

    selected_local_business_target_sources(
        query_contract,
        &target_names,
        &direct_detail_sources,
        locality_hint,
        required_url_count,
    )
    .into_iter()
    .map(|source| source.url)
    .collect()
}

fn candidate_recovery_local_business_discovery_seed_url(
    retrieval_contract: &ioi_types::app::agentic::WebRetrievalContract,
    query_contract: &str,
    min_sources: u32,
    discovery_sources: &[WebSource],
    source_observations: &[ioi_types::app::agentic::WebSourceObservation],
    source_hints: &[PendingSearchReadSummary],
    locality_hint: Option<&str>,
) -> Option<String> {
    if !crate::agentic::web::contract_requires_geo_scoped_entity_expansion(retrieval_contract) {
        return None;
    }

    let projection = build_query_constraint_projection_with_locality_hint(
        query_contract,
        min_sources.max(1),
        source_hints,
        locality_hint,
    );
    let mut ranked = Vec::new();
    for source in discovery_sources {
        let trimmed = source.url.trim();
        if trimmed.is_empty() {
            continue;
        }
        let title = source.title.as_deref().unwrap_or_default();
        let excerpt = source.snippet.as_deref().unwrap_or_default();
        let affordances = retrieval_affordances_with_contract_and_locality_hint(
            Some(retrieval_contract),
            query_contract,
            min_sources.max(1),
            source_hints,
            locality_hint,
            trimmed,
            title,
            excerpt,
        );
        let source_observation = source_observations.iter().find(|observation| {
            observation.url.eq_ignore_ascii_case(trimmed)
                || url_structurally_equivalent(&observation.url, trimmed)
        });
        let observed_seed_affordance = source_observation
            .map(|observation| {
                observation.affordances.contains(
                    &ioi_types::app::agentic::WebRetrievalAffordance::LinkCollection,
                ) && observation.affordances.contains(
                    &ioi_types::app::agentic::WebRetrievalAffordance::CanonicalLinkOut,
                ) && observation.expansion_affordances.iter().any(|affordance| {
                    matches!(
                        affordance,
                        ioi_types::app::agentic::WebSourceExpansionAffordance::JsonLdItemList
                            | ioi_types::app::agentic::WebSourceExpansionAffordance::ChildLinkCollection
                    )
                })
            })
            .unwrap_or(false);
        let collection_surface =
            crate::agentic::runtime::service::queue::support::local_business_collection_surface_candidate(
                locality_hint,
                trimmed,
                title,
                excerpt,
            );
        let detail_like_source = local_business_target_name_from_source(
            &PendingSearchReadSummary {
                url: trimmed.to_string(),
                title: (!title.trim().is_empty()).then(|| title.trim().to_string()),
                excerpt: excerpt.trim().to_string(),
            },
            locality_hint,
        )
        .is_some();
        let compatibility = candidate_constraint_compatibility(
            &projection.constraints,
            &projection.query_facets,
            &projection.query_native_tokens,
            &projection.query_tokens,
            &projection.locality_tokens,
            projection.locality_scope.is_some(),
            trimmed,
            title,
            excerpt,
        );
        if !(collection_surface
            || observed_seed_affordance
            || affordances.contains(&RetrievalAffordanceKind::DiscoveryExpansionSeedRead))
        {
            continue;
        }
        let signals = analyze_source_record_signals(trimmed, title, excerpt);
        ranked.push((
            collection_surface,
            !detail_like_source,
            observed_seed_affordance,
            compatibility.locality_compatible,
            compatibility.compatibility_score,
            signals.relevance_score(false),
            trimmed.to_string(),
        ));
    }

    ranked.sort_by(|left, right| {
        right
            .0
            .cmp(&left.0)
            .then_with(|| right.1.cmp(&left.1))
            .then_with(|| right.2.cmp(&left.2))
            .then_with(|| right.3.cmp(&left.3))
            .then_with(|| right.4.cmp(&left.4))
            .then_with(|| right.5.cmp(&left.5))
            .then_with(|| left.6.cmp(&right.6))
    });

    ranked.into_iter().map(|(_, _, _, _, _, _, url)| url).next()
}
