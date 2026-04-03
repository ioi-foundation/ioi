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

fn briefing_probe_recovery_source_hints(
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

fn briefing_grounded_recovery_required(
    query_contract: &str,
    retrieval_contract: &ioi_types::app::agentic::WebRetrievalContract,
    deterministic_plan: &crate::agentic::desktop::service::step::queue::support::PreReadCandidatePlan,
    required_url_count: usize,
    deterministic_selection_ready: bool,
) -> bool {
    query_prefers_document_briefing_layout(query_contract)
        && !query_requests_comparison(query_contract)
        && crate::agentic::desktop::service::step::signals::analyze_query_facets(query_contract)
            .grounded_external_required
        && (retrieval_contract.currentness_required
            || retrieval_contract.source_independence_min > 1)
        && !deterministic_selection_ready
        && deterministic_plan.candidate_urls.len() < required_url_count
        && deterministic_plan.requires_constraint_search_probe
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

fn merge_deterministic_plan_with_pending_inventory(
    retrieval_contract: &ioi_types::app::agentic::WebRetrievalContract,
    query_contract: &str,
    min_sources: u32,
    locality_hint: Option<&str>,
    pending: Option<&PendingSearchCompletion>,
    deterministic_plan: crate::agentic::desktop::service::step::queue::support::PreReadCandidatePlan,
    verification_checks: &mut Vec<String>,
) -> crate::agentic::desktop::service::step::queue::support::PreReadCandidatePlan {
    let required_url_count = min_sources.max(1) as usize;
    let Some(pending) = pending else {
        verification_checks.push("web_pre_read_pending_inventory_reused=false".to_string());
        return deterministic_plan;
    };
    if deterministic_plan.candidate_urls.len() >= required_url_count
        || (!pending_search_matches_query_contract(pending, query_contract))
        || (pending.candidate_urls.is_empty()
            && pending.candidate_source_hints.is_empty()
            && pending.successful_reads.is_empty())
    {
        verification_checks.push("web_pre_read_pending_inventory_reused=false".to_string());
        return deterministic_plan;
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
        deterministic_plan.candidate_urls.clone(),
    );
    let merged_candidate_source_hints = merge_source_hints(
        pending_reuse_source_hints,
        &deterministic_plan.candidate_source_hints,
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
    let pending_inventory_floor_recovery_required = briefing_grounded_recovery_required(
        query_contract,
        retrieval_contract,
        &merged_plan,
        required_url_count,
        false,
    );
    if pending_inventory_floor_recovery_required {
        let recovery_seed_plan =
            crate::agentic::desktop::service::step::queue::support::PreReadCandidatePlan {
                candidate_urls: merge_url_sequence(
                    pending_recovery_candidate_urls.clone(),
                    deterministic_plan.candidate_urls.clone(),
                ),
                candidate_source_hints: merged_candidate_source_hints.clone(),
                probe_source_hints: merged_plan.probe_source_hints.clone(),
                total_candidates: pending_recovery_candidate_urls.len(),
                pruned_candidates: 0,
                resolvable_candidates: merged_plan.resolvable_candidates,
                scoreable_candidates: merged_plan.scoreable_candidates,
                requires_constraint_search_probe: true,
            };
        let recovery_urls = briefing_authority_hint_read_recovery_urls(
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
            merged_plan =
                crate::agentic::desktop::service::step::queue::support::PreReadCandidatePlan {
                    candidate_urls: recovery_urls.clone(),
                    candidate_source_hints: recovery_source_hints.clone(),
                    probe_source_hints: briefing_probe_recovery_source_hints(
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
    let reused = merged_plan.candidate_urls.len() > deterministic_plan.candidate_urls.len()
        || merged_plan.candidate_source_hints != deterministic_plan.candidate_source_hints
        || merged_plan.probe_source_hints != deterministic_plan.probe_source_hints;
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
        deterministic_plan
    }
}

fn briefing_authority_hint_read_recovery_urls(
    retrieval_contract: &ioi_types::app::agentic::WebRetrievalContract,
    query_contract: &str,
    min_sources: u32,
    deterministic_plan: &crate::agentic::desktop::service::step::queue::support::PreReadCandidatePlan,
    preferred_read_backed_hints: &[PendingSearchReadSummary],
    discovery_hints: &[PendingSearchReadSummary],
    locality_hint: Option<&str>,
    required_url_count: usize,
) -> Vec<String> {
    let domain_key_for_url = |url: &str| {
        crate::agentic::desktop::service::step::queue::support::source_host(url)
            .map(|host| host.strip_prefix("www.").unwrap_or(&host).to_string())
    };
    let authority_slot_cap = crate::agentic::desktop::service::step::queue::support::retrieval_contract_primary_authority_source_slot_cap(
        Some(retrieval_contract),
        query_contract,
        required_url_count,
    );
    if authority_slot_cap == 0 {
        return Vec::new();
    }
    let merged_hints = merge_source_hints(
        discovery_hints.to_vec(),
        &deterministic_plan.candidate_source_hints,
    );
    let candidate_urls = merge_url_sequence(
        deterministic_plan.candidate_urls.clone(),
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
                crate::agentic::desktop::service::step::queue::support::source_has_grounded_primary_authority(
                    query_contract,
                    trimmed,
                    title,
                    excerpt,
                );
            let identifier_bearing =
                crate::agentic::desktop::service::step::queue::support::source_has_briefing_standard_identifier_signal(
                    query_contract,
                    trimmed,
                    title,
                    excerpt,
                );
            let query_grounded =
                crate::agentic::desktop::service::step::queue::support::excerpt_has_query_grounding_signal_with_contract(
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
        crate::agentic::desktop::service::step::queue::support::retrieval_contract_required_distinct_domain_floor(
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
                || crate::agentic::desktop::service::step::queue::support::url_structurally_equivalent(existing, &url)
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
                || crate::agentic::desktop::service::step::queue::support::url_structurally_equivalent(existing, &url)
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
        crate::agentic::desktop::service::step::queue::support::retrieval_contract_required_distinct_domain_floor(
            Some(retrieval_contract),
            query_contract,
        )
        .min(batch_target);
    if distinct_domain_floor <= 1
        || !query_prefers_document_briefing_layout(query_contract)
        || query_requests_comparison(query_contract)
    {
        return pre_read_batch_urls(candidate_urls, batch_target);
    }

    let domain_key_for_url = |url: &str| {
        crate::agentic::desktop::service::step::queue::support::source_host(url)
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

const BRIEFING_GROUNDED_RECOVERY_MARKER_PREFIX: &str = "ioi://briefing-grounded-recovery/";

fn briefing_grounded_recovery_marker(query: &str) -> Option<String> {
    let compact = compact_whitespace(query);
    let trimmed = compact.trim();
    (!trimmed.is_empty())
        .then(|| format!("{}{}", BRIEFING_GROUNDED_RECOVERY_MARKER_PREFIX, trimmed))
}

fn briefing_grounded_recovery_attempted(
    pending: Option<&PendingSearchCompletion>,
    query: &str,
) -> bool {
    let Some(marker) = briefing_grounded_recovery_marker(query) else {
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

fn mark_briefing_grounded_recovery_attempt(pending: &mut PendingSearchCompletion, query: &str) {
    let Some(marker) = briefing_grounded_recovery_marker(query) else {
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
        return crate::agentic::desktop::service::step::queue::web_pipeline::local_business_entity_discovery_query_contract(
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

fn deterministic_local_business_direct_detail_urls(
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

fn deterministic_local_business_discovery_seed_url(
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
            crate::agentic::desktop::service::step::queue::support::local_business_collection_surface_candidate(
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

pub(crate) async fn maybe_handle_web_search(
    service: &DesktopAgentService,
    agent_state: &mut AgentState,
    session_id: [u8; 32],
    pre_state_step_index: u32,
    tool_name: &str,
    tool_wrapper: &AgentTool,
    is_gated: bool,
    success: &mut bool,
    out: &mut Option<String>,
    err: &mut Option<String>,
    completion_summary: &mut Option<String>,
    verification_checks: &mut Vec<String>,
) -> Result<(), TransactionError> {
    let parsed_bundle = out.as_deref().and_then(parse_web_evidence_bundle);
    let promoted_memory_search = tool_name == "memory__search"
        && parsed_bundle
            .as_ref()
            .map(|bundle| bundle.tool == "web__search")
            .unwrap_or(false);
    let effective_web_search = tool_name == "web__search" || promoted_memory_search;
    if promoted_memory_search {
        verification_checks.push("memory_search_promoted_to_web_search=true".to_string());
    }
    if !effective_web_search || is_gated || !is_web_research_scope(agent_state) || !*success {
        return Ok(());
    }
    let Some(bundle) = parsed_bundle.as_ref() else {
        return Ok(());
    };

    let query_value = bundle
        .query
        .clone()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| match tool_wrapper {
            AgentTool::WebSearch { query, .. } => {
                let trimmed = query.trim();
                (!trimmed.is_empty()).then(|| trimmed.to_string())
            }
            AgentTool::MemorySearch { query } => {
                let trimmed = query.trim();
                (!trimmed.is_empty()).then(|| trimmed.to_string())
            }
            _ => None,
        })
        .unwrap_or_else(|| agent_state.goal.clone());
    let query_contract = agent_state
        .pending_search_completion
        .as_ref()
        .map(|pending| pending.query_contract.trim())
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| {
            select_web_pipeline_query_contract(agent_state.goal.as_str(), &query_value)
        });
    let intent_id = resolved_intent_id(agent_state);
    let pending_contract = agent_state
        .pending_search_completion
        .as_ref()
        .and_then(|pending| pending.retrieval_contract.clone());
    let retrieval_goal = agent_state.goal.trim();
    let retrieval_query_basis = if retrieval_goal.is_empty() {
        query_value.as_str()
    } else {
        retrieval_goal
    };
    let retrieval_contract =
        if let Some(contract) = pending_contract.or_else(|| bundle.retrieval_contract.clone()) {
            match crate::agentic::web::normalize_web_retrieval_contract(
                retrieval_query_basis,
                Some(query_contract.as_str()),
                contract,
            ) {
                Ok(contract) => contract,
                Err(inference_err) => {
                    *success = false;
                    *err = Some(format!(
                        "ERROR_CLASS=SynthesisFailed {}",
                        inference_err.to_string().trim()
                    ));
                    return Ok(());
                }
            }
        } else {
            match crate::agentic::web::derive_web_retrieval_contract(
                retrieval_query_basis,
                Some(query_contract.as_str()),
            ) {
                Ok(contract) => contract,
                Err(inference_err) => {
                    *success = false;
                    *err = Some(format!(
                        "ERROR_CLASS=SynthesisFailed {}",
                        inference_err.to_string().trim()
                    ));
                    return Ok(());
                }
            }
        };
    let min_sources =
        retrieval_contract_min_sources(Some(&retrieval_contract), &query_contract).max(1);
    let headline_lookup_mode = retrieval_contract_is_generic_headline_collection(
        Some(&retrieval_contract),
        &query_contract,
    );
    let started_at_ms = web_pipeline_now_ms();
    let locality_scope_required = retrieval_contract.runtime_locality_required;
    let locality_hint = if locality_scope_required {
        effective_locality_scope_hint(None)
    } else {
        None
    };
    let locality_requirement_observed = locality_scope_required.to_string();
    let locality_alignment_satisfied = if locality_scope_required {
        let expected_query_contract = resolved_query_contract_with_locality_hint(
            agent_state.goal.as_str(),
            locality_hint.as_deref(),
        );
        !expected_query_contract.trim().is_empty()
            && expected_query_contract.eq_ignore_ascii_case(query_contract.trim())
    } else {
        true
    };
    let currentness_required = retrieval_contract.currentness_required;
    verification_checks.push(format!(
        "web_runtime_locality_scope_required={}",
        locality_scope_required
    ));
    verification_checks.push(format!(
        "web_runtime_locality_scope_satisfied={}",
        !locality_scope_required || locality_hint.is_some()
    ));
    if let Some(scope) = locality_hint.as_ref() {
        verification_checks.push(format!("web_runtime_locality_scope={}", scope));
    }
    emit_web_contract_receipt(
        service,
        session_id,
        pre_state_step_index,
        intent_id.as_str(),
        "execution",
        "query_contract",
        !query_contract.trim().is_empty(),
        "web.pipeline.query_contract.v1",
        query_contract.trim(),
        "string",
        None,
    );
    emit_web_contract_receipt(
        service,
        session_id,
        pre_state_step_index,
        intent_id.as_str(),
        "execution",
        "query_value",
        !query_value.trim().is_empty(),
        "web.pipeline.query_value.v1",
        query_value.trim(),
        "string",
        None,
    );
    emit_web_contract_receipt(
        service,
        session_id,
        pre_state_step_index,
        intent_id.as_str(),
        "discovery",
        "runtime_locality_required",
        true,
        "web.pipeline.locality_requirement.v1",
        locality_requirement_observed.as_str(),
        "bool",
        None,
    );
    if let Ok(observed_value) = serde_json::to_string(&retrieval_contract) {
        emit_web_contract_receipt(
            service,
            session_id,
            pre_state_step_index,
            intent_id.as_str(),
            "execution",
            "retrieval_contract",
            true,
            "web.pipeline.retrieval_contract.v1",
            observed_value.as_str(),
            "json",
            None,
        );
    }
    emit_web_contract_receipt(
        service,
        session_id,
        pre_state_step_index,
        intent_id.as_str(),
        "discovery",
        "runtime_locality_scope",
        !locality_scope_required || locality_hint.is_some(),
        "web.pipeline.locality_scope.v1",
        locality_hint.as_deref().unwrap_or("<unset>"),
        "scope",
        None,
    );
    emit_web_contract_receipt(
        service,
        session_id,
        pre_state_step_index,
        intent_id.as_str(),
        "discovery",
        "query_contract_locality_alignment",
        locality_alignment_satisfied,
        "web.pipeline.query_contract_locality_alignment.v1",
        query_contract.trim(),
        "string",
        None,
    );
    emit_web_contract_receipt(
        service,
        session_id,
        pre_state_step_index,
        intent_id.as_str(),
        "execution",
        "currentness_required",
        true,
        "web.pipeline.currentness_requirement.v1",
        if currentness_required {
            "true"
        } else {
            "false"
        },
        "bool",
        None,
    );
    emit_web_contract_receipt(
        service,
        session_id,
        pre_state_step_index,
        intent_id.as_str(),
        "execution",
        "min_sources_required",
        min_sources > 0,
        "web.pipeline.min_sources_required.v1",
        &min_sources.to_string(),
        "scalar",
        None,
    );
    for candidate in &bundle.provider_candidates {
        let observed_value = serde_json::json!({
            "provider_id": candidate.provider_id,
            "source_count": candidate.source_count,
            "selected": candidate.selected,
            "success": candidate.success,
            "request_url": candidate.request_url,
            "challenge_reason": candidate.challenge_reason,
            "affordances": candidate.affordances,
        })
        .to_string();
        emit_web_contract_receipt(
            service,
            session_id,
            pre_state_step_index,
            intent_id.as_str(),
            "discovery",
            "provider_candidate",
            candidate.success && candidate.source_count > 0,
            "web.search.provider_candidate.v2",
            observed_value.as_str(),
            "json",
            Some(candidate.provider_id.clone()),
        );
    }
    verification_checks.push("web_discovery_source_filters_bypassed=true".to_string());
    let bundle = bundle;
    for candidate in bundle
        .provider_candidates
        .iter()
        .filter(|candidate| candidate.selected)
    {
        let observed_value = serde_json::json!({
            "provider_id": candidate.provider_id,
            "source_count": candidate.source_count,
            "request_url": candidate.request_url,
        })
        .to_string();
        emit_web_contract_receipt(
            service,
            session_id,
            pre_state_step_index,
            intent_id.as_str(),
            "provider_selection",
            "provider_selected",
            !bundle.sources.is_empty() && candidate.source_count > 0,
            "web.search.provider_selection.v2",
            observed_value.as_str(),
            "json",
            Some(candidate.provider_id.clone()),
        );
    }
    let discovery_sources = ordered_discovery_sources(bundle);
    let required_url_count = min_sources.max(1) as usize;
    let (discovery_sources, semantic_aligned_discovery_urls, semantic_alignment_required) =
        match filter_discovery_sources_by_semantic_alignment(
            service,
            session_id,
            pre_state_step_index,
            intent_id.as_str(),
            &retrieval_contract,
            &query_contract,
            discovery_sources,
            verification_checks,
        )
        .await
        {
            Ok(result) => result,
            Err(error) => {
                let semantic_alignment_recovery_query = semantic_alignment_recovery_query(
                    query_contract.as_str(),
                    query_value.as_str(),
                    &retrieval_contract,
                    min_sources,
                    &candidate_source_hints_from_bundle(bundle),
                    locality_hint.as_deref(),
                );
                let semantic_alignment_recovery_limit =
                    constraint_grounded_search_limit(query_contract.as_str(), min_sources);
                let semantic_alignment_recovery_queued =
                    !semantic_alignment_recovery_query.trim().is_empty()
                        && !semantic_alignment_recovery_query
                            .trim()
                            .eq_ignore_ascii_case(query_value.trim())
                        && queue_web_search_from_pipeline(
                            agent_state,
                            session_id,
                            semantic_alignment_recovery_query.as_str(),
                            Some(query_contract.as_str()),
                            Some(&retrieval_contract),
                            semantic_alignment_recovery_limit,
                        )?;
                verification_checks.push(format!(
                    "web_semantic_subject_alignment_recovery_query={}",
                    semantic_alignment_recovery_query
                ));
                verification_checks.push(format!(
                    "web_semantic_subject_alignment_recovery_limit={}",
                    semantic_alignment_recovery_limit
                ));
                verification_checks.push(format!(
                    "web_semantic_subject_alignment_recovery_queued={}",
                    semantic_alignment_recovery_queued
                ));
                if semantic_alignment_recovery_queued {
                    verification_checks.push("web_pipeline_active=true".to_string());
                    verification_checks.push("web_sources_success=0".to_string());
                    verification_checks.push("web_sources_blocked=0".to_string());
                    verification_checks.push("web_budget_ms=0".to_string());
                    *success = true;
                    *out = Some(format!(
                        "Queued grounded search recovery after discovery alignment failure: {}",
                        semantic_alignment_recovery_query
                    ));
                    *err = None;
                    agent_state.status = AgentStatus::Running;
                    return Ok(());
                }
                if defer_search_planning_failure_while_recovery_actions_remain(
                    agent_state,
                    verification_checks,
                    success,
                    err,
                    &error,
                ) {
                    return Ok(());
                }
                verification_checks.push(format!("web_pre_read_payload_error={}", error));
                *success = false;
                *err = Some(format!("ERROR_CLASS=SynthesisFailed {}", error));
                return Ok(());
            }
        };
    let source_observations = if crate::agentic::web::contract_requires_geo_scoped_entity_expansion(
        &retrieval_contract,
    ) {
        observe_geo_scoped_discovery_sources(
            &discovery_sources,
            &bundle.source_observations,
            required_url_count,
            verification_checks,
        )
        .await
    } else {
        bundle.source_observations.clone()
    };
    let discovery_sources = match expand_geo_scoped_discovery_seed_sources(
        service,
        &retrieval_contract,
        &query_contract,
        discovery_sources,
        &source_observations,
        required_url_count,
        verification_checks,
    )
    .await
    {
        Ok(sources) => sources,
        Err(error) => {
            if defer_search_planning_failure_while_recovery_actions_remain(
                agent_state,
                verification_checks,
                success,
                err,
                &error,
            ) {
                return Ok(());
            }
            verification_checks.push(format!("web_pre_read_payload_error={}", error));
            *success = false;
            *err = Some(format!("ERROR_CLASS=SynthesisFailed {}", error));
            return Ok(());
        }
    };
    let discovery_sources = match expand_briefing_authority_link_out_sources(
        &retrieval_contract,
        &query_contract,
        discovery_sources,
        required_url_count,
        verification_checks,
    )
    .await
    {
        Ok(sources) => sources,
        Err(error) => {
            if defer_search_planning_failure_while_recovery_actions_remain(
                agent_state,
                verification_checks,
                success,
                err,
                &error,
            ) {
                return Ok(());
            }
            verification_checks.push(format!("web_pre_read_payload_error={}", error));
            *success = false;
            *err = Some(format!("ERROR_CLASS=SynthesisFailed {}", error));
            return Ok(());
        }
    };
    let discovery_sources = if semantic_alignment_required {
        discovery_sources
            .into_iter()
            .take(WEB_PIPELINE_DISCOVERY_SOURCE_LIMIT)
            .collect::<Vec<_>>()
    } else {
        discovery_sources
    };
    let semantic_aligned_discovery_urls = if semantic_alignment_required {
        effective_semantic_alignment_urls(&discovery_sources)
    } else {
        semantic_aligned_discovery_urls
    };
    let filtered_discovery_hints = discovery_source_hints(&discovery_sources);
    let discovery_hints = if semantic_alignment_required {
        filtered_discovery_hints.clone()
    } else {
        merge_source_hints(
            candidate_source_hints_from_bundle(bundle),
            &filtered_discovery_hints,
        )
    };
    let planning_bundle = planning_bundle_from_discovery_sources(
        bundle,
        &retrieval_contract,
        discovery_sources.clone(),
        &source_observations,
        verification_checks,
    );
    let pre_read_target = required_url_count;
    let deterministic_plan =
        pre_read_candidate_plan_from_bundle_with_contract_and_locality_hint_and_recovery_mode(
            Some(&retrieval_contract),
            &query_contract,
            min_sources,
            &planning_bundle,
            locality_hint.as_deref(),
            true,
        );
    let deterministic_plan = merge_deterministic_plan_with_pending_inventory(
        &retrieval_contract,
        &query_contract,
        min_sources,
        locality_hint.as_deref(),
        agent_state.pending_search_completion.as_ref(),
        deterministic_plan,
        verification_checks,
    );
    let pre_read_payload_source_hints = ordered_source_hints_with_selected_urls_first(
        &deterministic_plan.candidate_urls,
        &merge_source_hints(
            discovery_hints.clone(),
            &deterministic_plan.candidate_source_hints,
        ),
    );
    let pre_read_payload_sources = pre_read_selection_sources_from_planning_context(
        &planning_bundle,
        &pre_read_payload_source_hints,
    );
    let pre_read_payload_source_observations =
        pre_read_selection_source_observations_from_planning_context(
            &planning_bundle,
            &pre_read_payload_sources,
        );
    let pre_read_payload_seed_hints = merge_source_hints(
        source_hints_from_web_sources(&pre_read_payload_sources),
        &pre_read_payload_source_hints,
    );
    let geo_seed_mode_applicable =
        crate::agentic::web::contract_requires_geo_scoped_entity_expansion(&retrieval_contract)
            && required_url_count > 1;
    let deterministic_direct_selected_urls = deterministic_local_business_direct_detail_urls(
        &retrieval_contract,
        &query_contract,
        min_sources,
        &deterministic_plan.candidate_urls,
        &deterministic_plan.candidate_source_hints,
        locality_hint.as_deref(),
        required_url_count,
    );
    let deterministic_discovery_seed_url = deterministic_local_business_discovery_seed_url(
        &retrieval_contract,
        &query_contract,
        min_sources,
        &discovery_sources,
        &source_observations,
        &deterministic_plan.candidate_source_hints,
        locality_hint.as_deref(),
    );
    let deterministic_selection_ready = if geo_seed_mode_applicable {
        deterministic_direct_selected_urls.len() >= required_url_count
            || deterministic_discovery_seed_url.is_some()
    } else {
        deterministic_plan.candidate_urls.len() >= required_url_count
    };
    let search_url_attempt = bundle
        .url
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string())
        .into_iter()
        .collect::<Vec<_>>();
    let briefing_probe_recovery_required = briefing_grounded_recovery_required(
        &query_contract,
        &retrieval_contract,
        &deterministic_plan,
        required_url_count,
        deterministic_selection_ready,
    );
    if briefing_probe_recovery_required {
        let authority_hint_read_recovery_urls = briefing_authority_hint_read_recovery_urls(
            &retrieval_contract,
            query_contract.as_str(),
            min_sources,
            &deterministic_plan,
            &[],
            &discovery_hints,
            locality_hint.as_deref(),
            required_url_count,
        );
        let briefing_probe_recovery_source_hints = briefing_probe_recovery_source_hints(
            &discovery_hints,
            &deterministic_plan.probe_source_hints,
            &authority_hint_read_recovery_urls,
        );
        let briefing_probe_recovery_query =
            constraint_grounded_probe_query_with_contract_and_hints_and_locality_hint(
                query_contract.as_str(),
                Some(&retrieval_contract),
                min_sources,
                &briefing_probe_recovery_source_hints,
                query_value.trim(),
                locality_hint.as_deref(),
            );
        let briefing_probe_recovery_limit =
            constraint_grounded_search_limit(query_contract.as_str(), min_sources);
        let authority_hint_read_recovery_site_terms = if crate::agentic::desktop::service::step::queue::support::query_probe_document_authority_site_terms(
            query_contract.as_str(),
            Some(&retrieval_contract),
            &briefing_probe_recovery_source_hints,
        )
        .is_empty()
        {
            Vec::new()
        } else {
            authority_hint_read_recovery_site_terms(&authority_hint_read_recovery_urls)
        };
        let mut briefing_probe_recovery_query_value =
            briefing_probe_recovery_query.clone().unwrap_or_default();
        if !briefing_probe_recovery_query_value.trim().is_empty()
            && !authority_hint_read_recovery_site_terms.is_empty()
        {
            briefing_probe_recovery_query_value = append_missing_query_terms(
                &briefing_probe_recovery_query_value,
                &authority_hint_read_recovery_site_terms,
            );
        }
        let recovery_pending_seed = PendingSearchCompletion {
            query: query_value.clone(),
            query_contract: query_contract.clone(),
            retrieval_contract: Some(retrieval_contract.clone()),
            url: bundle.url.clone().unwrap_or_default(),
            started_step: pre_state_step_index,
            started_at_ms,
            deadline_ms: started_at_ms.saturating_add(WEB_PIPELINE_BUDGET_MS),
            candidate_urls: deterministic_plan.candidate_urls.clone(),
            candidate_source_hints: merge_source_hints(
                discovery_hints.clone(),
                &deterministic_plan.candidate_source_hints,
            ),
            attempted_urls: search_url_attempt.clone(),
            blocked_urls: Vec::new(),
            successful_reads: Vec::new(),
            min_sources,
        };
        let mut recovery_pending =
            if let Some(existing) = agent_state.pending_search_completion.clone() {
                merge_pending_search_completion(existing, recovery_pending_seed)
            } else {
                recovery_pending_seed
            };
        let authority_hint_read_recovery_queued = if authority_hint_read_recovery_urls.is_empty() {
            false
        } else {
            queue_web_read_batch_from_pipeline(
                agent_state,
                session_id,
                &authority_hint_read_recovery_urls,
                pending_web_read_allows_browser_fallback(&recovery_pending),
            )? > 0
        };
        let briefing_probe_recovery_already_attempted = briefing_grounded_recovery_attempted(
            Some(&recovery_pending),
            briefing_probe_recovery_query_value.as_str(),
        );
        let briefing_probe_recovery_queued = !briefing_probe_recovery_query_value.trim().is_empty()
            && !briefing_probe_recovery_already_attempted
            && !briefing_probe_recovery_query_value
                .trim()
                .eq_ignore_ascii_case(query_value.trim())
            && queue_web_search_from_pipeline(
                agent_state,
                session_id,
                briefing_probe_recovery_query_value.as_str(),
                Some(query_contract.as_str()),
                Some(&retrieval_contract),
                briefing_probe_recovery_limit,
            )?;
        verification_checks.push(format!("web_pre_read_grounded_recovery_required={}", true));
        verification_checks.push(format!(
            "web_pre_read_authority_hint_read_recovery_candidate_urls={}",
            authority_hint_read_recovery_urls.len()
        ));
        if !authority_hint_read_recovery_urls.is_empty() {
            verification_checks.push(format!(
                "web_pre_read_authority_hint_read_recovery_url_values={}",
                authority_hint_read_recovery_urls.join(" | ")
            ));
        }
        verification_checks.push(format!(
            "web_pre_read_authority_hint_read_recovery_queued={}",
            authority_hint_read_recovery_queued
        ));
        verification_checks.push(format!(
            "web_pre_read_grounded_recovery_query={}",
            briefing_probe_recovery_query_value
        ));
        verification_checks.push(format!(
            "web_pre_read_grounded_recovery_limit={}",
            briefing_probe_recovery_limit
        ));
        verification_checks.push(format!(
            "web_pre_read_grounded_recovery_already_attempted={}",
            briefing_probe_recovery_already_attempted
        ));
        verification_checks.push(format!(
            "web_pre_read_grounded_recovery_queued={}",
            briefing_probe_recovery_queued
        ));
        if authority_hint_read_recovery_queued || briefing_probe_recovery_queued {
            mark_briefing_grounded_recovery_attempt(
                &mut recovery_pending,
                briefing_probe_recovery_query_value.as_str(),
            );
            agent_state.pending_search_completion = Some(recovery_pending);
            verification_checks.push("web_pipeline_active=true".to_string());
            verification_checks.push("web_sources_success=0".to_string());
            verification_checks.push("web_sources_blocked=0".to_string());
            verification_checks.push("web_budget_ms=0".to_string());
            *success = true;
            *out = Some(if authority_hint_read_recovery_queued {
                format!(
                    "Queued authority read recovery before pre-read selection: {}",
                    authority_hint_read_recovery_urls.join(", ")
                )
            } else {
                format!(
                    "Queued grounded search recovery before pre-read selection: {}",
                    briefing_probe_recovery_query_value
                )
            });
            *err = None;
            agent_state.status = AgentStatus::Running;
            return Ok(());
        }
        agent_state.pending_search_completion = Some(recovery_pending);
    }
    let deterministic_selection_mode =
        if crate::agentic::web::contract_requires_geo_scoped_entity_expansion(&retrieval_contract)
            && required_url_count > 1
            && deterministic_direct_selected_urls.len() < required_url_count
            && deterministic_discovery_seed_url.is_some()
        {
            PreReadSelectionMode::DiscoverySeed
        } else {
            PreReadSelectionMode::DirectDetail
        };
    let deterministic_selected_urls = match deterministic_selection_mode {
        PreReadSelectionMode::DirectDetail => {
            if crate::agentic::web::contract_requires_geo_scoped_entity_expansion(
                &retrieval_contract,
            ) {
                deterministic_direct_selected_urls.clone()
            } else {
                distinct_domain_preserving_selected_urls(
                    &retrieval_contract,
                    query_contract.as_str(),
                    &deterministic_plan.candidate_urls,
                    required_url_count,
                )
            }
        }
        PreReadSelectionMode::DiscoverySeed => deterministic_discovery_seed_url
            .iter()
            .cloned()
            .collect::<Vec<_>>(),
    };
    let deterministic_selection_available = match deterministic_selection_mode {
        PreReadSelectionMode::DirectDetail => {
            deterministic_selected_urls.len() == required_url_count
        }
        PreReadSelectionMode::DiscoverySeed => !deterministic_selected_urls.is_empty(),
    };
    let payload_error: Option<String> = None;
    let payload_synthesis_skipped: bool;
    let deterministic_fallback_used: bool;
    let deterministic_top_up_used =
        deterministic_plan.candidate_urls.len() > deterministic_selected_urls.len();
    let selection = if deterministic_selection_available {
        payload_synthesis_skipped = true;
        deterministic_fallback_used = false;
        PreReadSelectionResponse {
            selection_mode: deterministic_selection_mode,
            urls: deterministic_selected_urls.clone(),
        }
    } else {
        payload_synthesis_skipped = false;
        deterministic_fallback_used = false;
        match synthesize_pre_read_selection(
            service,
            Some(&retrieval_contract),
            &query_contract,
            required_url_count,
            &pre_read_payload_sources,
            &pre_read_payload_source_observations,
        )
        .await
        {
            Ok(selection) => selection,
            Err(error) => {
                if let Some(pending) = agent_state.pending_search_completion.as_mut() {
                    let seeded = seed_pending_inventory_from_pre_read_payload_hints(
                        pending,
                        &pre_read_payload_seed_hints,
                    );
                    verification_checks.push(format!(
                        "web_pre_read_payload_inventory_seeded_on_error={}",
                        seeded
                    ));
                    if seeded {
                        verification_checks.push(format!(
                            "web_pre_read_payload_inventory_seeded_candidate_urls={}",
                            pending.candidate_urls.len()
                        ));
                    }
                }
                if defer_search_planning_failure_while_recovery_actions_remain(
                    agent_state,
                    verification_checks,
                    success,
                    err,
                    &error,
                ) {
                    return Ok(());
                }
                verification_checks.push(format!("web_pre_read_payload_error={}", error));
                *success = false;
                *err = Some(format!("ERROR_CLASS=SynthesisFailed {}", error));
                return Ok(());
            }
        }
    };
    if selection.urls.is_empty() {
        let error = "typed pre-read selection returned no admissible URLs".to_string();
        if defer_search_planning_failure_while_recovery_actions_remain(
            agent_state,
            verification_checks,
            success,
            err,
            &error,
        ) {
            return Ok(());
        }
        verification_checks.push(format!("web_pre_read_payload_error={}", error));
        *success = false;
        *err = Some(format!("ERROR_CLASS=SynthesisFailed {}", error));
        return Ok(());
    }
    let merged_hints =
        merge_source_hints(discovery_hints, &deterministic_plan.candidate_source_hints);
    let mut selected_urls = selection.urls;
    let selected_urls_before_resolution = selected_urls.clone();
    let allowed_resolution_urls =
        semantic_alignment_required.then_some(semantic_aligned_discovery_urls.as_slice());
    resolve_selected_urls_from_hints(&mut selected_urls, &merged_hints, allowed_resolution_urls);
    let merged_candidate_urls = merge_candidate_urls_preserving_order(
        &selected_urls,
        &deterministic_plan.candidate_urls,
        &semantic_aligned_discovery_urls,
    );
    if !crate::agentic::web::contract_requires_geo_scoped_entity_expansion(&retrieval_contract) {
        selected_urls = distinct_domain_preserving_selected_urls(
            &retrieval_contract,
            query_contract.as_str(),
            &merged_candidate_urls,
            required_url_count,
        );
    }
    let candidate_urls = if payload_synthesis_skipped {
        merged_candidate_urls
    } else {
        selected_urls.clone()
    };
    let selection_mode = match selection.selection_mode {
        PreReadSelectionMode::DirectDetail => "direct_detail",
        PreReadSelectionMode::DiscoverySeed => "discovery_seed",
    };
    emit_web_contract_receipt(
        service,
        session_id,
        pre_state_step_index,
        intent_id.as_str(),
        "verification",
        "pre_read_selection_mode",
        true,
        "web.pipeline.pre_read.selection_mode.v1",
        selection_mode,
        "enum",
        None,
    );
    emit_web_string_receipts(
        service,
        session_id,
        pre_state_step_index,
        intent_id.as_str(),
        "verification",
        "pre_read_selected_url_raw",
        "web.pipeline.pre_read.selection.v1",
        "url",
        &selected_urls_before_resolution,
    );
    emit_web_string_receipts(
        service,
        session_id,
        pre_state_step_index,
        intent_id.as_str(),
        "verification",
        "pre_read_selected_url",
        "web.pipeline.pre_read.selection.v1",
        "url",
        &selected_urls,
    );
    verification_checks.push(format!("web_pre_read_selection_mode={}", selection_mode));
    let geo_scoped_entity_expansion =
        crate::agentic::web::contract_requires_geo_scoped_entity_expansion(&retrieval_contract);
    let aligned_selected_urls = selected_source_alignment_urls(
        query_contract.as_str(),
        &retrieval_contract,
        &selected_urls,
        &semantic_aligned_discovery_urls,
        &merged_hints,
        locality_hint.as_deref(),
    );
    let selected_subject_alignment_floor_met = if semantic_alignment_required {
        let minimum_aligned_selection = if geo_scoped_entity_expansion {
            1
        } else {
            required_url_count
        };
        selected_urls.len() >= minimum_aligned_selection
            && aligned_selected_urls.len() == selected_urls.len()
    } else {
        true
    };
    let selected_subject_alignment_count = aligned_selected_urls.len();
    let selected_subject_alignment_summary = format!(
        "required={};selected_sources={};aligned_selected_sources={}",
        semantic_alignment_required,
        selected_urls.len(),
        selected_subject_alignment_count
    );
    emit_web_contract_receipt(
        service,
        session_id,
        pre_state_step_index,
        intent_id.as_str(),
        "verification",
        "selected_source_subject_alignment_floor",
        selected_subject_alignment_floor_met,
        "web.pipeline.selected_source_subject_alignment.v1",
        selected_subject_alignment_summary.as_str(),
        "summary",
        None,
    );
    emit_web_string_receipts(
        service,
        session_id,
        pre_state_step_index,
        intent_id.as_str(),
        "verification",
        "selected_source_subject_alignment_url",
        "web.pipeline.selected_source_subject_alignment.v1",
        "url",
        &aligned_selected_urls,
    );
    verification_checks.push(format!(
        "web_selected_source_subject_alignment_floor_met={}",
        selected_subject_alignment_floor_met
    ));
    if !aligned_selected_urls.is_empty() {
        verification_checks.push(format!(
            "web_selected_source_subject_alignment_url_values={}",
            aligned_selected_urls.join(" | ")
        ));
    }
    if semantic_alignment_required && !selected_subject_alignment_floor_met {
        let error =
            "selected sources failed semantic subject alignment against query contract".to_string();
        if defer_search_planning_failure_while_recovery_actions_remain(
            agent_state,
            verification_checks,
            success,
            err,
            &error,
        ) {
            return Ok(());
        }
        verification_checks.push(format!("web_pre_read_payload_error={}", error));
        *success = false;
        *err = Some(format!("ERROR_CLASS=SynthesisFailed {}", error));
        return Ok(());
    }
    let (
        selected_source_total,
        selected_source_compatible,
        selected_source_locality_compatible,
        selected_source_distinct_domains,
        selected_source_low_priority,
        selected_source_quality_floor_met,
        selected_source_low_priority_urls,
    ) = selected_source_structural_metrics(
        Some(&retrieval_contract),
        &query_contract,
        min_sources,
        &selected_urls,
        &merged_hints,
    );
    let raw_query_requires_runtime_scope = retrieval_contract.runtime_locality_required;
    let needs_locality_rebound_search = raw_query_requires_runtime_scope
        && locality_hint.is_some()
        && !selected_source_quality_floor_met
        && !query_contract
            .trim()
            .eq_ignore_ascii_case(query_value.trim());
    let mut rebound_queued = false;
    if needs_locality_rebound_search {
        let rebound_query = if crate::agentic::web::contract_requires_geo_scoped_entity_expansion(
            &retrieval_contract,
        ) {
            crate::agentic::desktop::service::step::queue::web_pipeline::local_business_entity_discovery_query_contract(
                query_contract.as_str(),
                locality_hint.as_deref(),
            )
        } else {
            constraint_grounded_search_query_with_contract_and_hints_and_locality_hint(
                query_contract.as_str(),
                Some(&retrieval_contract),
                min_sources,
                &[],
                None,
            )
        };
        let rebound_limit = constraint_grounded_search_limit(query_contract.as_str(), min_sources);
        rebound_queued = !rebound_query.trim().is_empty()
            && !rebound_query
                .trim()
                .eq_ignore_ascii_case(query_value.trim())
            && queue_web_search_from_pipeline(
                agent_state,
                session_id,
                rebound_query.as_str(),
                Some(query_contract.as_str()),
                Some(&retrieval_contract),
                rebound_limit,
            )?;
        verification_checks.push(format!(
            "web_runtime_locality_scope_rebound_search_required={}",
            true
        ));
        verification_checks.push(format!(
            "web_runtime_locality_scope_rebound_search_query={}",
            rebound_query
        ));
        verification_checks.push(format!(
            "web_runtime_locality_scope_rebound_search_queued={}",
            rebound_queued
        ));
    }

    let incoming_pending = PendingSearchCompletion {
        query: query_value,
        query_contract,
        retrieval_contract: Some(retrieval_contract),
        url: bundle.url.clone().unwrap_or_default(),
        started_step: pre_state_step_index,
        started_at_ms,
        deadline_ms: started_at_ms.saturating_add(WEB_PIPELINE_BUDGET_MS),
        candidate_urls: candidate_urls.clone(),
        candidate_source_hints: merged_hints,
        attempted_urls: search_url_attempt,
        blocked_urls: Vec::new(),
        successful_reads: Vec::new(),
        min_sources,
    };
    let mut pending = if let Some(existing) = agent_state.pending_search_completion.clone() {
        merge_pending_search_completion(existing, incoming_pending)
    } else {
        incoming_pending
    };

    let preexisting_queued_reads = queued_web_read_count(agent_state);
    let queued_reads = if !selected_urls.is_empty() {
        queue_web_read_batch_from_pipeline(
            agent_state,
            session_id,
            &selected_urls,
            pending_web_read_allows_browser_fallback(&pending),
        )?
    } else {
        0
    };
    let total_queued_reads = preexisting_queued_reads.saturating_add(queued_reads);
    let probe_queued = false;
    let probe_budget_ok = true;
    let pending_search_recovery_probe_allowed = false;
    let probe_allowed = false;

    if headline_lookup_mode {
        let (
            headline_total_sources,
            headline_low_priority_sources,
            headline_distinct_domains,
            headline_low_priority_urls,
        ) = headline_selection_quality_metrics(&selected_urls, &pending.candidate_source_hints);
        let headline_quality_floor_met = headline_total_sources >= required_url_count
            && headline_low_priority_sources == 0
            && headline_distinct_domains >= required_url_count;
        verification_checks.push(format!(
            "web_headline_selected_sources_total={}",
            headline_total_sources
        ));
        verification_checks.push(format!(
            "web_headline_selected_sources_low_priority={}",
            headline_low_priority_sources
        ));
        verification_checks.push(format!(
            "web_headline_selected_sources_distinct_domains={}",
            headline_distinct_domains
        ));
        verification_checks.push(format!(
            "web_headline_selected_sources_quality_floor_met={}",
            headline_quality_floor_met
        ));
        if !headline_low_priority_urls.is_empty() {
            verification_checks.push(format!(
                "web_headline_selected_sources_low_priority_urls={}",
                headline_low_priority_urls.join(" | ")
            ));
        }
    }
    verification_checks.push(format!(
        "web_selected_sources_total={}",
        selected_source_total
    ));
    verification_checks.push(format!(
        "web_selected_sources_compatible={}",
        selected_source_compatible
    ));
    verification_checks.push(format!(
        "web_selected_sources_locality_compatible={}",
        selected_source_locality_compatible
    ));
    verification_checks.push(format!(
        "web_selected_sources_distinct_domains={}",
        selected_source_distinct_domains
    ));
    verification_checks.push(format!(
        "web_selected_sources_low_priority={}",
        selected_source_low_priority
    ));
    verification_checks.push(format!(
        "web_selected_sources_quality_floor_met={}",
        selected_source_quality_floor_met
    ));
    if !selected_source_low_priority_urls.is_empty() {
        verification_checks.push(format!(
            "web_selected_sources_low_priority_urls={}",
            selected_source_low_priority_urls.join(" | ")
        ));
    }

    verification_checks.push(format!(
        "web_pre_read_discovery_sources={}",
        discovery_sources.len()
    ));
    verification_checks.push(format!(
        "web_pre_read_payload_sources={}",
        pre_read_payload_sources.len()
    ));
    verification_checks.push(format!("web_pre_read_required_urls={}", required_url_count));
    verification_checks.push(format!(
        "web_pre_read_selected_urls={}",
        selected_urls.len()
    ));
    verification_checks.push(format!(
        "web_pre_read_candidate_inventory_urls={}",
        candidate_urls.len()
    ));
    verification_checks.push(format!("web_pre_read_batch_target={}", pre_read_target));
    if headline_lookup_mode {
        verification_checks.push(format!(
            "web_headline_read_batch_target={}",
            pre_read_target
        ));
    }
    if !selected_urls.is_empty() {
        verification_checks.push(format!(
            "web_pre_read_selected_url_values={}",
            selected_urls.join(" | ")
        ));
    }
    if !selected_urls_before_resolution.is_empty() {
        verification_checks.push(format!(
            "web_pre_read_selected_url_raw_values={}",
            selected_urls_before_resolution.join(" | ")
        ));
    }
    if !candidate_urls.is_empty() {
        verification_checks.push(format!(
            "web_pre_read_candidate_inventory_url_values={}",
            candidate_urls
                .iter()
                .take(10)
                .cloned()
                .collect::<Vec<_>>()
                .join(" | ")
        ));
    }
    if !discovery_sources.is_empty() {
        let discovery_urls = discovery_sources
            .iter()
            .map(|source| source.url.trim())
            .filter(|url| !url.is_empty())
            .take(10)
            .collect::<Vec<_>>();
        if !discovery_urls.is_empty() {
            verification_checks.push(format!(
                "web_pre_read_discovery_url_values={}",
                discovery_urls.join(" | ")
            ));
        }
    }
    verification_checks.push(format!(
        "web_pre_read_existing_reads_queued={}",
        preexisting_queued_reads
    ));
    verification_checks.push(format!("web_pre_read_batch_reads_queued={}", queued_reads));
    verification_checks.push(format!(
        "web_pre_read_total_reads_queued={}",
        total_queued_reads
    ));
    verification_checks.push(format!(
        "web_pre_read_deterministic_fallback_used={}",
        deterministic_fallback_used
    ));
    verification_checks.push(format!(
        "web_pre_read_deterministic_top_up_used={}",
        deterministic_top_up_used
    ));
    verification_checks.push(format!(
        "web_pre_read_local_business_direct_detail_selected={}",
        deterministic_direct_selected_urls.len()
    ));
    verification_checks.push(format!(
        "web_pre_read_local_business_discovery_seed_available={}",
        deterministic_discovery_seed_url.is_some()
    ));
    if let Some(seed_url) = deterministic_discovery_seed_url.as_deref() {
        verification_checks.push(format!(
            "web_pre_read_local_business_discovery_seed_url={}",
            seed_url
        ));
    }
    verification_checks.push(format!("web_min_sources={}", min_sources));
    verification_checks.push(format!("web_headline_lookup_mode={}", headline_lookup_mode));
    verification_checks.push(format!(
        "web_query_contract={}",
        pending.query_contract.trim()
    ));
    verification_checks.push(format!("web_pending_query={}", pending.query.trim()));
    verification_checks.push(format!("web_constraint_search_probe_required={}", false));
    verification_checks.push(format!(
        "web_constraint_search_probe_allowed={}",
        probe_allowed
    ));
    verification_checks.push(format!(
        "web_constraint_search_probe_recovery_allowed={}",
        pending_search_recovery_probe_allowed
    ));
    verification_checks.push(format!(
        "web_constraint_search_probe_budget_ok={}",
        probe_budget_ok
    ));
    verification_checks.push(format!(
        "web_constraint_search_probe_queued={}",
        probe_queued
    ));
    verification_checks.push(format!(
        "web_pre_read_payload_valid={}",
        payload_error.is_none()
    ));
    verification_checks.push(format!(
        "web_pre_read_payload_synthesis_skipped={}",
        payload_synthesis_skipped
    ));
    if let Some(error) = payload_error.as_deref() {
        verification_checks.push(format!("web_pre_read_payload_error={}", error));
    }

    if total_queued_reads == 0 && !probe_queued && !rebound_queued {
        if let Some(error) = payload_error {
            // Preserve synthesis diagnostics while carrying the explicit state-3 failure signal.
            pending
                .blocked_urls
                .push(format!("ioi://state3-synthesis-error/{}", error));
        }
        let completion_reason = web_pipeline_completion_reason(&pending, web_pipeline_now_ms());
        let terminal_completion_reason = completion_reason.filter(|reason| {
            crate::agentic::desktop::service::step::queue::support::web_pipeline_completion_terminalization_allowed(
                &pending,
                *reason,
                total_queued_reads,
            )
        });
        let selection_reason = terminal_completion_reason
            .or(completion_reason)
            .unwrap_or(WebPipelineCompletionReason::ExhaustedCandidates);
        let selection = synthesize_summary(service, &pending, selection_reason).await;
        append_summary_selection_checks(&selection, verification_checks);
        let summary = selection.summary;
        let final_facts = selection.facts;
        crate::agentic::desktop::service::step::queue::emit_final_web_completion_contract_receipts(
            service,
            session_id,
            pre_state_step_index,
            intent_id.as_str(),
            &final_facts,
        );
        append_final_web_completion_receipts_with_rendered_summary(
            &pending,
            selection_reason,
            &summary,
            verification_checks,
        );
        if !selection.contract_ready {
            emit_completion_gate_status_event(
                service,
                session_id,
                pre_state_step_index,
                intent_id.as_str(),
                false,
                "receipt::final_output_contract_ready=true",
            );
            verification_checks.push("cec_completion_gate_emitted=true".to_string());
            verification_checks.push("execution_contract_gate_blocked=true".to_string());
            verification_checks.push(
                "execution_contract_missing_keys=receipt::final_output_contract_ready=true"
                    .to_string(),
            );
            if let Some(reason) = terminal_completion_reason {
                terminalize_failed_web_pipeline_completion(
                    agent_state,
                    pending,
                    reason,
                    summary,
                    success,
                    out,
                    err,
                    completion_summary,
                    verification_checks,
                );
                return Ok(());
            }
            verification_checks
                .push("web_pipeline_terminalization_blocked_on_rendered_output=true".to_string());
            verification_checks.push("web_pipeline_active=true".to_string());
            verification_checks.push("terminal_chat_reply_ready=false".to_string());
            agent_state.pending_search_completion = Some(pending);
            agent_state.status = AgentStatus::Running;
            return Ok(());
        }
        complete_with_summary(
            agent_state,
            summary,
            success,
            out,
            err,
            completion_summary,
            true,
        );
        emit_completion_gate_status_event(
            service,
            session_id,
            pre_state_step_index,
            intent_id.as_str(),
            true,
            "web_pipeline_search_completion_gate_passed",
        );
        verification_checks.push("cec_completion_gate_emitted=true".to_string());
        verification_checks.push("web_pipeline_active=false".to_string());
        verification_checks.push("terminal_chat_reply_ready=true".to_string());
        return Ok(());
    }

    verification_checks.push("web_pipeline_active=true".to_string());
    verification_checks.push("web_sources_success=0".to_string());
    verification_checks.push("web_sources_blocked=0".to_string());
    verification_checks.push("web_budget_ms=0".to_string());
    agent_state.pending_search_completion = Some(pending);
    agent_state.status = AgentStatus::Running;
    Ok(())
}

#[cfg(test)]
mod planning_regression_tests {
    use super::*;
    use crate::agentic::desktop::service::step::queue::support::PreReadCandidatePlan;

    fn research_query_contract() -> String {
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing."
            .to_string()
    }

    fn research_retrieval_contract() -> ioi_types::app::agentic::WebRetrievalContract {
        crate::agentic::web::derive_web_retrieval_contract(&research_query_contract(), None)
            .expect("retrieval contract")
    }

    fn restaurant_query_contract() -> String {
        "Find the three best-reviewed Italian restaurants in Anderson, SC and compare their menus."
            .to_string()
    }

    fn restaurant_retrieval_contract() -> ioi_types::app::agentic::WebRetrievalContract {
        crate::agentic::web::derive_web_retrieval_contract(&restaurant_query_contract(), None)
            .expect("retrieval contract")
    }

    fn restaurant_source_hints() -> Vec<PendingSearchReadSummary> {
        vec![
            PendingSearchReadSummary {
                url: "https://www.yelp.com/biz/dolce-vita-italian-bistro-and-pizzeria-anderson"
                    .to_string(),
                title: Some(
                    "Dolce Vita Italian Bistro and Pizzeria - Anderson, SC - Yelp".to_string(),
                ),
                excerpt: "Italian restaurant in Anderson, SC with pasta, pizza, and baked dishes."
                    .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://www.tripadvisor.com/Restaurant_Review-g30090-d15074041-Reviews-DolceVita_Italian_Bistro_Pizzeria-Anderson_South_Carolina.html".to_string(),
                title: Some(
                    "DolceVita Italian Bistro & Pizzeria - Tripadvisor".to_string(),
                ),
                excerpt:
                    "Italian restaurant in Anderson, South Carolina serving pizza and pasta."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://theredtomatorestaurant.com/".to_string(),
                title: Some("The Red Tomato and Wine Bar | Anderson, SC".to_string()),
                excerpt: "Italian dining in Anderson, SC with wine, pasta, and entrees."
                    .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://www.yelp.com/search?cflt=italian&find_loc=Anderson,+SC".to_string(),
                title: Some(
                    "Top 10 Best Italian Restaurants Near Anderson, South Carolina - Yelp"
                        .to_string(),
                ),
                excerpt:
                    "Best Italian in Anderson, SC: Dolce Vita Italian Bistro, The Red Tomato and Brothers Italian Cuisine."
                        .to_string(),
            },
        ]
    }

    #[test]
    fn authority_hint_read_recovery_site_terms_add_publication_scope_for_csrc_ir_url() {
        let terms = authority_hint_read_recovery_site_terms(&[String::from(
            "https://csrc.nist.gov/pubs/ir/8413/upd1/final",
        )]);

        assert!(
            terms
                .iter()
                .any(|term| term.eq_ignore_ascii_case("site:csrc.nist.gov/pubs")),
            "terms={terms:?}"
        );
    }

    #[test]
    fn append_missing_query_terms_appends_publication_scope_once() {
        let query =
            "nist post quantum cryptography standards \"nist post quantum cryptography\" \"observed now\"";
        let next = append_missing_query_terms(
            query,
            &[
                String::from("site:csrc.nist.gov/pubs"),
                String::from("site:csrc.nist.gov/pubs"),
            ],
        );

        assert!(next.contains("site:csrc.nist.gov/pubs"), "next={next}");
        assert_eq!(
            next.matches("site:csrc.nist.gov/pubs").count(),
            1,
            "next={next}"
        );
    }

    #[test]
    fn deterministic_local_business_direct_selection_requires_distinct_entities() {
        let query_contract = restaurant_query_contract();
        let retrieval_contract = restaurant_retrieval_contract();
        let source_hints = restaurant_source_hints();
        let candidate_urls = source_hints
            .iter()
            .map(|hint| hint.url.clone())
            .collect::<Vec<_>>();

        let selected = deterministic_local_business_direct_detail_urls(
            &retrieval_contract,
            &query_contract,
            3,
            &candidate_urls,
            &source_hints,
            Some("Anderson, SC"),
            3,
        );

        assert!(selected.is_empty(), "{selected:?}");
    }

    #[test]
    fn deterministic_local_business_seed_selection_finds_listing_surface() {
        let query_contract = restaurant_query_contract();
        let retrieval_contract = restaurant_retrieval_contract();
        let source_hints = restaurant_source_hints();

        let seed_url = deterministic_local_business_discovery_seed_url(
            &retrieval_contract,
            &query_contract,
            3,
            &vec![
                WebSource {
                    source_id: "1".to_string(),
                    rank: Some(1),
                    url: "https://www.yelp.com/biz/dolce-vita-italian-bistro-and-pizzeria-anderson"
                        .to_string(),
                    title: Some(
                        "Dolce Vita Italian Bistro and Pizzeria - Anderson, SC - Yelp"
                            .to_string(),
                    ),
                    snippet: Some(
                        "Italian restaurant in Anderson, SC with pasta, pizza, and baked dishes."
                            .to_string(),
                    ),
                    domain: Some("www.yelp.com".to_string()),
                },
                WebSource {
                    source_id: "2".to_string(),
                    rank: Some(2),
                    url: "https://www.tripadvisor.com/Restaurants-g30090-c26-Anderson_South_Carolina.html".to_string(),
                    title: Some("THE 10 BEST Italian Restaurants in Anderson (Updated 2026) - Tripadvisor".to_string()),
                    snippet: Some(
                        "Best Italian Restaurants in Anderson, South Carolina: find reviews for Dolce Vita, The Red Tomato, and Brothers Italian Cuisine."
                            .to_string(),
                    ),
                    domain: Some("www.tripadvisor.com".to_string()),
                },
            ],
            &[],
            &source_hints,
            Some("Anderson, SC"),
        );

        assert_eq!(
            seed_url.as_deref(),
            Some("https://www.tripadvisor.com/Restaurants-g30090-c26-Anderson_South_Carolina.html")
        );
    }

    #[test]
    fn briefing_grounded_recovery_does_not_block_when_selection_ready() {
        let query_contract = research_query_contract();
        let retrieval_contract = research_retrieval_contract();
        let plan = PreReadCandidatePlan {
            candidate_urls: vec![
                "https://csrc.nist.gov/Projects/post-quantum-cryptography/workshops-and-timeline"
                    .to_string(),
                "https://www.nccoe.nist.gov/sites/default/files/2023-12/pqc-migration-nist-sp-1800-38c-preliminary-draft.pdf"
                    .to_string(),
            ],
            requires_constraint_search_probe: true,
            ..PreReadCandidatePlan::default()
        };

        assert!(!briefing_grounded_recovery_required(
            &query_contract,
            &retrieval_contract,
            &plan,
            2,
            true,
        ));
    }

    #[test]
    fn briefing_grounded_recovery_still_requires_probe_when_selection_sparse() {
        let query_contract = research_query_contract();
        let retrieval_contract = research_retrieval_contract();
        let plan = PreReadCandidatePlan {
            candidate_urls: vec![
                "https://www.nccoe.nist.gov/sites/default/files/2023-12/pqc-migration-nist-sp-1800-38c-preliminary-draft.pdf"
                    .to_string(),
            ],
            requires_constraint_search_probe: true,
            ..PreReadCandidatePlan::default()
        };

        assert!(briefing_grounded_recovery_required(
            &query_contract,
            &retrieval_contract,
            &plan,
            2,
            false,
        ));
    }

    #[test]
    fn briefing_grounded_recovery_attempt_marker_prevents_repeat_queue() {
        let recovery_query =
            "nist post quantum cryptography standards web UTC timestamp site:nist.gov";
        let mut pending = PendingSearchCompletion::default();

        assert!(!briefing_grounded_recovery_attempted(
            Some(&pending),
            recovery_query,
        ));

        mark_briefing_grounded_recovery_attempt(&mut pending, recovery_query);

        assert!(briefing_grounded_recovery_attempted(
            Some(&pending),
            recovery_query,
        ));
        assert_eq!(pending.attempted_urls.len(), 1);

        mark_briefing_grounded_recovery_attempt(&mut pending, recovery_query);

        assert_eq!(pending.attempted_urls.len(), 1);
    }

    #[test]
    fn semantic_alignment_recovery_query_escalates_away_from_off_topic_authority_neighbor_host() {
        let query_contract = research_query_contract();
        let retrieval_contract = research_retrieval_contract();
        let prior_query =
            "nist post quantum cryptography standards web UTC timestamp site:nist.gov \"nist post quantum cryptography\"";
        let candidate_hints = vec![PendingSearchReadSummary {
            url: "https://www.ibm.com/es-es/think/insights/nist-cybersecurity-framework-2"
                .to_string(),
            title: Some("El marco de ciberseguridad 2.0 del NIST, en detalle | IBM".to_string()),
            excerpt:
                "He aqui todo lo que las empresas deben saber sobre como el marco de ciberseguridad 2.0 del NIST puede mejorar la gestion de riesgos."
                    .to_string(),
        }];

        let recovery_query = semantic_alignment_recovery_query(
            &query_contract,
            prior_query,
            &retrieval_contract,
            2,
            &candidate_hints,
            None,
        );

        assert_ne!(recovery_query, prior_query);
        assert!(
            recovery_query
                .split_whitespace()
                .any(|term| term.eq_ignore_ascii_case("site:nist.gov")),
            "recovery_query={recovery_query}"
        );
        assert!(
            recovery_query
                .split_whitespace()
                .any(|term| term.eq_ignore_ascii_case("-site:ibm.com")),
            "recovery_query={recovery_query}"
        );
    }

    #[test]
    fn merge_deterministic_plan_with_pending_inventory_reuses_prior_authority_candidates_when_current_turn_is_sparse(
    ) {
        let query_contract = research_query_contract();
        let retrieval_contract = research_retrieval_contract();
        let pending = PendingSearchCompletion {
            query: query_contract.clone(),
            query_contract: query_contract.clone(),
            retrieval_contract: Some(retrieval_contract.clone()),
            candidate_urls: vec![
                "https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string(),
                "https://nvlpubs.nist.gov/nistpubs/ir/2022/NIST.IR.8413-upd1.pdf".to_string(),
            ],
            candidate_source_hints: vec![
                PendingSearchReadSummary {
                    url: "https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string(),
                    title: Some(
                        "Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process"
                            .to_string(),
                    ),
                    excerpt:
                        "The new public-key cryptography standards will specify additional digital signature, public-key encryption, and key-establishment algorithms."
                            .to_string(),
                },
                PendingSearchReadSummary {
                    url: "https://nvlpubs.nist.gov/nistpubs/ir/2022/NIST.IR.8413-upd1.pdf"
                        .to_string(),
                    title: Some(
                        "Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process"
                            .to_string(),
                    ),
                    excerpt:
                        "NIST IR 8413 Update 1 summarizes the standardization process and references FIPS 203, FIPS 204, and FIPS 205."
                            .to_string(),
                },
            ],
            min_sources: 2,
            ..PendingSearchCompletion::default()
        };
        let sparse_plan = PreReadCandidatePlan {
            candidate_urls: vec![
                "https://www.ibm.com/es-es/think/insights/nist-cybersecurity-framework-2"
                    .to_string(),
            ],
            candidate_source_hints: vec![PendingSearchReadSummary {
                url: "https://www.ibm.com/es-es/think/insights/nist-cybersecurity-framework-2"
                    .to_string(),
                title: Some("El marco de ciberseguridad 2.0 del NIST, en detalle | IBM".to_string()),
                excerpt:
                    "He aqui todo lo que las empresas deben saber sobre como el marco de ciberseguridad 2.0 del NIST puede mejorar la gestion de riesgos."
                        .to_string(),
            }],
            requires_constraint_search_probe: true,
            ..PreReadCandidatePlan::default()
        };
        let mut checks = Vec::new();

        let merged = merge_deterministic_plan_with_pending_inventory(
            &retrieval_contract,
            &query_contract,
            2,
            None,
            Some(&pending),
            sparse_plan,
            &mut checks,
        );

        assert_eq!(
            merged.candidate_urls.len(),
            2,
            "{:?}",
            merged.candidate_urls
        );
        assert!(merged
            .candidate_urls
            .iter()
            .any(|url| url.eq_ignore_ascii_case("https://csrc.nist.gov/pubs/ir/8413/upd1/final")));
        assert!(merged.candidate_urls.iter().any(|url| {
            url.eq_ignore_ascii_case(
                "https://nvlpubs.nist.gov/nistpubs/ir/2022/NIST.IR.8413-upd1.pdf",
            )
        }));
        assert!(checks
            .iter()
            .any(|check| { check == "web_pre_read_pending_inventory_reused=true" }));
    }

    #[test]
    fn merge_deterministic_plan_with_pending_inventory_does_not_reuse_on_query_contract_mismatch() {
        let query_contract = research_query_contract();
        let retrieval_contract = research_retrieval_contract();
        let pending = PendingSearchCompletion {
            query_contract: "Research the latest OpenAI API pricing updates and write me a memo."
                .to_string(),
            candidate_urls: vec![
                "https://openai.com/api/pricing".to_string(),
                "https://platform.openai.com/docs/pricing".to_string(),
            ],
            min_sources: 2,
            ..PendingSearchCompletion::default()
        };
        let sparse_plan = PreReadCandidatePlan {
            candidate_urls: vec![
                "https://www.ibm.com/es-es/think/insights/nist-cybersecurity-framework-2"
                    .to_string(),
            ],
            requires_constraint_search_probe: true,
            ..PreReadCandidatePlan::default()
        };
        let mut checks = Vec::new();

        let merged = merge_deterministic_plan_with_pending_inventory(
            &retrieval_contract,
            &query_contract,
            2,
            None,
            Some(&pending),
            sparse_plan.clone(),
            &mut checks,
        );

        assert_eq!(merged.candidate_urls, sparse_plan.candidate_urls);
        assert!(checks
            .iter()
            .any(|check| { check == "web_pre_read_pending_inventory_reused=false" }));
    }

    #[test]
    fn merge_deterministic_plan_with_pending_inventory_reconstructs_candidate_urls_from_pending_hints(
    ) {
        let query_contract = research_query_contract();
        let retrieval_contract = research_retrieval_contract();
        let pending = PendingSearchCompletion {
            query: query_contract.clone(),
            query_contract: query_contract.clone(),
            retrieval_contract: Some(retrieval_contract.clone()),
            candidate_urls: Vec::new(),
            candidate_source_hints: vec![
                PendingSearchReadSummary {
                    url: "https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string(),
                    title: Some(
                        "Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process"
                            .to_string(),
                    ),
                    excerpt:
                        "The new public-key cryptography standards will specify additional digital signature, public-key encryption, and key-establishment algorithms."
                            .to_string(),
                },
                PendingSearchReadSummary {
                    url: "https://nvlpubs.nist.gov/nistpubs/ir/2022/NIST.IR.8413-upd1.pdf"
                        .to_string(),
                    title: Some(
                        "Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process"
                            .to_string(),
                    ),
                    excerpt:
                        "NIST IR 8413 Update 1 summarizes the standardization process and references FIPS 203, FIPS 204, and FIPS 205."
                            .to_string(),
                },
            ],
            min_sources: 2,
            ..PendingSearchCompletion::default()
        };
        let sparse_plan = PreReadCandidatePlan {
            candidate_urls: vec![
                "https://www.ibm.com/es-es/think/insights/nist-cybersecurity-framework-2"
                    .to_string(),
            ],
            candidate_source_hints: vec![PendingSearchReadSummary {
                url: "https://www.ibm.com/es-es/think/insights/nist-cybersecurity-framework-2"
                    .to_string(),
                title: Some("El marco de ciberseguridad 2.0 del NIST, en detalle | IBM".to_string()),
                excerpt:
                    "He aqui todo lo que las empresas deben saber sobre como el marco de ciberseguridad 2.0 del NIST puede mejorar la gestion de riesgos."
                        .to_string(),
            }],
            requires_constraint_search_probe: true,
            ..PreReadCandidatePlan::default()
        };
        let mut checks = Vec::new();

        let merged = merge_deterministic_plan_with_pending_inventory(
            &retrieval_contract,
            &query_contract,
            2,
            None,
            Some(&pending),
            sparse_plan,
            &mut checks,
        );

        assert_eq!(
            merged.candidate_urls.len(),
            2,
            "{:?}",
            merged.candidate_urls
        );
        assert!(merged
            .candidate_urls
            .iter()
            .any(|url| url.eq_ignore_ascii_case("https://csrc.nist.gov/pubs/ir/8413/upd1/final")));
        assert!(merged.candidate_urls.iter().any(|url| {
            url.eq_ignore_ascii_case(
                "https://nvlpubs.nist.gov/nistpubs/ir/2022/NIST.IR.8413-upd1.pdf",
            )
        }));
        assert!(checks
            .iter()
            .any(|check| { check == "web_pre_read_pending_inventory_reused=true" }));
        assert!(checks
            .iter()
            .any(|check| { check == "web_pre_read_pending_inventory_candidate_urls=2" }));
        assert!(checks
            .iter()
            .any(|check| { check == "web_pre_read_pending_inventory_raw_candidate_urls=0" }));
    }

    #[test]
    fn merge_deterministic_plan_with_pending_inventory_preserves_distinct_official_support_from_run_shaped_research_inventory(
    ) {
        let query_contract = "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing using current web and local memory evidence, then return a cited brief with findings, uncertainties, and next checks.".to_string();
        let retrieval_contract = crate::agentic::web::derive_web_retrieval_contract(
            &query_contract,
            Some(&query_contract),
        )
        .unwrap();
        let pending = PendingSearchCompletion {
            query: "nist post quantum cryptography standards".to_string(),
            query_contract: query_contract.clone(),
            retrieval_contract: Some(retrieval_contract.clone()),
            candidate_urls: vec![
                "https://csrc.nist.gov/pubs/ir/8547/ipd".to_string(),
                "https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization".to_string(),
                "https://csrc.nist.gov/News/2024/postquantum-cryptography-fips-approved".to_string(),
                "https://csrc.nist.gov/Projects/Post-Quantum-Cryptography/news".to_string(),
                "https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string(),
                "https://csrc.nist.gov/pubs/ir/8545/final".to_string(),
                "https://csrc.nist.gov/projects/post-quantum-cryptography".to_string(),
                "https://csrc.nist.gov/Projects/Post-Quantum-Cryptography/publications".to_string(),
                "https://csrc.nist.gov/Projects/Cryptographic-Standards-and-Guidelines".to_string(),
                "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards".to_string(),
                "https://www.nist.gov/news-events/news/2026/03/nist-researchers-develop-photonic-chip-packaging-can-withstand-extreme".to_string(),
                "https://csrc.nist.gov/".to_string(),
            ],
            candidate_source_hints: vec![
                PendingSearchReadSummary {
                    url: "https://csrc.nist.gov/pubs/ir/8547/ipd".to_string(),
                    title: Some(
                        "IR 8547 (Initial Public Draft), Transition to Post-Quantum Cryptography Standards"
                            .to_string(),
                    ),
                    excerpt:
                        "NIST draft guidance on transitioning to the latest post-quantum cryptography standards."
                            .to_string(),
                },
                PendingSearchReadSummary {
                    url: "https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization".to_string(),
                    title: Some("Post-Quantum Cryptography Standardization | CSRC".to_string()),
                    excerpt:
                        "Current CSRC project page for the latest NIST post-quantum cryptography standardization updates."
                            .to_string(),
                },
                PendingSearchReadSummary {
                    url: "https://csrc.nist.gov/News/2024/postquantum-cryptography-fips-approved".to_string(),
                    title: Some("Post-Quantum Cryptography FIPS Approved | CSRC".to_string()),
                    excerpt:
                        "CSRC announced approval of the post-quantum cryptography FIPS standards."
                            .to_string(),
                },
                PendingSearchReadSummary {
                    url: "https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string(),
                    title: Some(
                        "IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC"
                            .to_string(),
                    ),
                    excerpt:
                        "IR 8413 Update 1 summarizes the latest NIST post-quantum cryptography standards and references FIPS 203, FIPS 204, and FIPS 205."
                            .to_string(),
                },
                PendingSearchReadSummary {
                    url: "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards".to_string(),
                    title: Some(
                        "NIST Releases First 3 Finalized Post-Quantum Encryption Standards"
                            .to_string(),
                    ),
                    excerpt:
                        "NIST released the first three finalized post-quantum encryption standards and urged administrators to begin transitioning."
                            .to_string(),
                },
            ],
            successful_reads: vec![
                PendingSearchReadSummary {
                    url: "https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string(),
                    title: Some(
                        "IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC"
                            .to_string(),
                    ),
                    excerpt:
                        "IR 8413 Update 1 summarizes the latest NIST post-quantum cryptography standards and references FIPS 203, FIPS 204, and FIPS 205."
                            .to_string(),
                },
                PendingSearchReadSummary {
                    url: "https://csrc.nist.gov/pubs/ir/8413/final".to_string(),
                    title: Some(
                        "IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC"
                            .to_string(),
                    ),
                    excerpt:
                        "IR 8413 documents the third-round status of the NIST post-quantum cryptography standardization process."
                            .to_string(),
                },
            ],
            min_sources: 2,
            ..PendingSearchCompletion::default()
        };
        let sparse_plan = PreReadCandidatePlan {
            candidate_urls: vec![
                "https://www.ciodive.com/spons/building-organizational-readiness-for-post-quantum-cryptography/815308/".to_string(),
            ],
            candidate_source_hints: vec![PendingSearchReadSummary {
                url: "https://www.ciodive.com/spons/building-organizational-readiness-for-post-quantum-cryptography/815308/".to_string(),
                title: Some(
                    "Sponsored: Building organizational readiness for post-quantum cryptography"
                        .to_string(),
                ),
                excerpt:
                    "Sponsored briefing on organizational readiness for post-quantum cryptography."
                        .to_string(),
            }],
            requires_constraint_search_probe: true,
            ..PreReadCandidatePlan::default()
        };
        let mut checks = Vec::new();

        let merged = merge_deterministic_plan_with_pending_inventory(
            &retrieval_contract,
            &query_contract,
            2,
            None,
            Some(&pending),
            sparse_plan,
            &mut checks,
        );

        assert!(
            merged.candidate_urls.len() >= 2,
            "{:?}",
            merged.candidate_urls
        );
        assert!(
            merged.candidate_urls.iter().any(|url| {
                url.eq_ignore_ascii_case("https://csrc.nist.gov/pubs/ir/8413/upd1/final")
            }),
            "{:?}",
            merged.candidate_urls
        );
        assert!(
            merged.candidate_urls.iter().any(|url| {
                url.eq_ignore_ascii_case(
                    "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards"
                )
            }),
            "{:?}",
            merged.candidate_urls
        );
        assert!(
            checks
                .iter()
                .any(|check| { check == "web_pre_read_pending_inventory_reused=true" }),
            "{checks:?}"
        );
    }

    #[test]
    fn pre_read_selection_sources_merge_pending_authority_with_live_support_artifact() {
        let query_contract = research_query_contract();
        let retrieval_contract = research_retrieval_contract();
        let planning_bundle = WebEvidenceBundle {
            schema_version: 1,
            retrieved_at_ms: 0,
            tool: "web__search".to_string(),
            backend: "test".to_string(),
            query: Some(query_contract.clone()),
            url: Some("https://example.test/search".to_string()),
            sources: vec![
                WebSource {
                    source_id: crate::agentic::web::source_id_for_url(
                        "https://www.ciodive.com/spons/building-organizational-readiness-for-post-quantum-cryptography/815308/",
                    ),
                    rank: Some(1),
                    url: "https://www.ciodive.com/spons/building-organizational-readiness-for-post-quantum-cryptography/815308/".to_string(),
                    title: Some(
                        "Sponsored: Building organizational readiness for post-quantum cryptography"
                            .to_string(),
                    ),
                    snippet: Some(
                        "Sponsored briefing on organizational readiness for post-quantum cryptography."
                            .to_string(),
                    ),
                    domain: Some("www.ciodive.com".to_string()),
                },
                WebSource {
                    source_id: crate::agentic::web::source_id_for_url(
                        "https://trustedcomputinggroup.org/wp-content/uploads/State-of-PQC-Readiness-2025-November-2025.pdf",
                    ),
                    rank: Some(2),
                    url: "https://trustedcomputinggroup.org/wp-content/uploads/State-of-PQC-Readiness-2025-November-2025.pdf".to_string(),
                    title: Some("State of PQC Readiness 2025".to_string()),
                    snippet: Some(
                        "Independent November 2025 report on post-quantum cryptography readiness after NIST finalized its first post-quantum standards."
                            .to_string(),
                    ),
                    domain: Some("trustedcomputinggroup.org".to_string()),
                },
            ],
            source_observations: vec![ioi_types::app::agentic::WebSourceObservation {
                url: "https://www.ciodive.com/spons/building-organizational-readiness-for-post-quantum-cryptography/815308/".to_string(),
                affordances: vec![
                    ioi_types::app::agentic::WebRetrievalAffordance::DetailDocument,
                    ioi_types::app::agentic::WebRetrievalAffordance::CanonicalLinkOut,
                    ioi_types::app::agentic::WebRetrievalAffordance::LinkCollection,
                ],
                expansion_affordances: vec![
                    ioi_types::app::agentic::WebSourceExpansionAffordance::ChildLinkCollection,
                ],
            }],
            documents: Vec::new(),
            provider_candidates: Vec::new(),
            retrieval_contract: Some(retrieval_contract),
        };
        let prioritized_hints = ordered_source_hints_with_selected_urls_first(
            &["https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string()],
            &[
                PendingSearchReadSummary {
                    url: "https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string(),
                    title: Some(
                        "IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC"
                            .to_string(),
                    ),
                    excerpt:
                        "IR 8413 Update 1 summarizes the latest NIST post-quantum cryptography standards and references FIPS 203, FIPS 204, and FIPS 205."
                            .to_string(),
                },
                PendingSearchReadSummary {
                    url: "https://trustedcomputinggroup.org/wp-content/uploads/State-of-PQC-Readiness-2025-November-2025.pdf".to_string(),
                    title: Some("State of PQC Readiness 2025".to_string()),
                    excerpt:
                        "Independent November 2025 report on post-quantum cryptography readiness after NIST finalized its first post-quantum standards."
                            .to_string(),
                },
                PendingSearchReadSummary {
                    url: "https://www.ciodive.com/spons/building-organizational-readiness-for-post-quantum-cryptography/815308/".to_string(),
                    title: Some(
                        "Sponsored: Building organizational readiness for post-quantum cryptography"
                            .to_string(),
                    ),
                    excerpt:
                        "Sponsored briefing on organizational readiness for post-quantum cryptography."
                            .to_string(),
                },
            ],
        );

        let payload_sources =
            pre_read_selection_sources_from_planning_context(&planning_bundle, &prioritized_hints);
        let payload_observations = pre_read_selection_source_observations_from_planning_context(
            &planning_bundle,
            &payload_sources,
        );

        assert_eq!(
            payload_sources.first().map(|source| source.url.as_str()),
            Some("https://csrc.nist.gov/pubs/ir/8413/upd1/final")
        );
        assert!(payload_sources.iter().any(|source| {
            source.url.eq_ignore_ascii_case(
                "https://trustedcomputinggroup.org/wp-content/uploads/State-of-PQC-Readiness-2025-November-2025.pdf",
            )
        }));
        assert!(payload_sources.iter().any(|source| {
            source.url.eq_ignore_ascii_case(
                "https://www.ciodive.com/spons/building-organizational-readiness-for-post-quantum-cryptography/815308/",
            )
        }));
        assert_eq!(payload_observations.len(), 1);
        assert_eq!(
            payload_observations.first().map(|observation| observation.url.as_str()),
            Some(
                "https://www.ciodive.com/spons/building-organizational-readiness-for-post-quantum-cryptography/815308/"
            )
        );
    }

    #[test]
    fn seed_pending_inventory_from_pre_read_payload_hints_preserves_expanded_support_candidates() {
        let mut pending = PendingSearchCompletion {
            query: research_query_contract(),
            query_contract: research_query_contract(),
            retrieval_contract: Some(research_retrieval_contract()),
            candidate_urls: vec!["https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string()],
            candidate_source_hints: vec![PendingSearchReadSummary {
                url: "https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string(),
                title: Some(
                    "IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC"
                        .to_string(),
                ),
                excerpt:
                    "IR 8413 Update 1 summarizes the latest NIST post-quantum cryptography standards and references FIPS 203, FIPS 204, and FIPS 205."
                        .to_string(),
            }],
            min_sources: 2,
            ..PendingSearchCompletion::default()
        };
        let payload_sources = vec![
            WebSource {
                source_id: crate::agentic::web::source_id_for_url(
                    "https://csrc.nist.gov/pubs/ir/8413/upd1/final",
                ),
                rank: Some(1),
                url: "https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string(),
                title: Some(
                    "IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC"
                        .to_string(),
                ),
                snippet: Some(
                    "IR 8413 Update 1 summarizes the latest NIST post-quantum cryptography standards and references FIPS 203, FIPS 204, and FIPS 205."
                        .to_string(),
                ),
                domain: Some("csrc.nist.gov".to_string()),
            },
            WebSource {
                source_id: crate::agentic::web::source_id_for_url(
                    "https://trustedcomputinggroup.org/wp-content/uploads/State-of-PQC-Readiness-2025-November-2025.pdf",
                ),
                rank: Some(2),
                url: "https://trustedcomputinggroup.org/wp-content/uploads/State-of-PQC-Readiness-2025-November-2025.pdf".to_string(),
                title: Some("State of PQC Readiness 2025".to_string()),
                snippet: Some(
                    "State of PQC Readiness 2025 | linked from Building organizational readiness for post-quantum cryptography | guidance on organizational readiness for post-quantum cryptography."
                        .to_string(),
                ),
                domain: Some("trustedcomputinggroup.org".to_string()),
            },
            WebSource {
                source_id: crate::agentic::web::source_id_for_url(
                    "https://www.ciodive.com/spons/building-organizational-readiness-for-post-quantum-cryptography/815308/",
                ),
                rank: Some(3),
                url: "https://www.ciodive.com/spons/building-organizational-readiness-for-post-quantum-cryptography/815308/".to_string(),
                title: Some(
                    "Sponsored: Building organizational readiness for post-quantum cryptography"
                        .to_string(),
                ),
                snippet: Some(
                    "Sponsored briefing on organizational readiness for post-quantum cryptography."
                        .to_string(),
                ),
                domain: Some("www.ciodive.com".to_string()),
            },
        ];
        let prioritized_payload_hints = vec![
            PendingSearchReadSummary {
                url: "https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string(),
                title: Some(
                    "IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC"
                        .to_string(),
                ),
                excerpt:
                    "IR 8413 Update 1 summarizes the latest NIST post-quantum cryptography standards and references FIPS 203, FIPS 204, and FIPS 205."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://www.ciodive.com/spons/building-organizational-readiness-for-post-quantum-cryptography/815308/".to_string(),
                title: Some(
                    "Sponsored: Building organizational readiness for post-quantum cryptography"
                        .to_string(),
                ),
                excerpt:
                    "Sponsored briefing on organizational readiness for post-quantum cryptography."
                        .to_string(),
            },
        ];
        let payload_source_hints = merge_source_hints(
            source_hints_from_web_sources(&payload_sources),
            &prioritized_payload_hints,
        );

        let seeded =
            seed_pending_inventory_from_pre_read_payload_hints(&mut pending, &payload_source_hints);

        assert!(seeded);
        assert!(pending.candidate_urls.iter().any(|url| {
            url.eq_ignore_ascii_case(
                "https://trustedcomputinggroup.org/wp-content/uploads/State-of-PQC-Readiness-2025-November-2025.pdf",
            )
        }));
        assert!(pending.candidate_source_hints.iter().any(|hint| {
            hint.url.eq_ignore_ascii_case(
                "https://trustedcomputinggroup.org/wp-content/uploads/State-of-PQC-Readiness-2025-November-2025.pdf",
            )
        }));
    }

    #[test]
    fn merge_deterministic_plan_with_pending_inventory_reuses_successful_read_hints_for_probe_grounding(
    ) {
        let query_contract = research_query_contract();
        let retrieval_contract = research_retrieval_contract();
        let pending = PendingSearchCompletion {
            query: query_contract.clone(),
            query_contract: query_contract.clone(),
            retrieval_contract: Some(retrieval_contract.clone()),
            successful_reads: vec![PendingSearchReadSummary {
                url: "https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string(),
                title: Some(
                    "Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process"
                        .to_string(),
                ),
                excerpt:
                    "NIST IR 8413 Update 1 summarizes the standardization process and references FIPS 203, FIPS 204, and FIPS 205."
                        .to_string(),
            }],
            min_sources: 2,
            ..PendingSearchCompletion::default()
        };
        let sparse_plan = PreReadCandidatePlan {
            candidate_urls: vec![
                "https://www.ibm.com/es-es/think/insights/nist-cybersecurity-framework-2"
                    .to_string(),
            ],
            candidate_source_hints: vec![PendingSearchReadSummary {
                url: "https://www.ibm.com/es-es/think/insights/nist-cybersecurity-framework-2"
                    .to_string(),
                title: Some("El marco de ciberseguridad 2.0 del NIST, en detalle | IBM".to_string()),
                excerpt:
                    "He aqui todo lo que las empresas deben saber sobre como el marco de ciberseguridad 2.0 del NIST puede mejorar la gestion de riesgos."
                        .to_string(),
            }],
            requires_constraint_search_probe: true,
            ..PreReadCandidatePlan::default()
        };
        let mut checks = Vec::new();

        let merged = merge_deterministic_plan_with_pending_inventory(
            &retrieval_contract,
            &query_contract,
            2,
            None,
            Some(&pending),
            sparse_plan,
            &mut checks,
        );
        let grounded = constraint_grounded_search_query_with_contract_and_hints_and_locality_hint(
            &query_contract,
            Some(&retrieval_contract),
            2,
            &[],
            None,
        );
        let probe = constraint_grounded_probe_query_with_contract_and_hints_and_locality_hint(
            &query_contract,
            Some(&retrieval_contract),
            2,
            &merged.probe_source_hints,
            &grounded,
            None,
        )
        .expect("probe query should be generated");

        assert!(checks
            .iter()
            .any(|check| { check == "web_pre_read_pending_inventory_reused=true" }));
        assert!(checks
            .iter()
            .any(|check| { check == "web_pre_read_pending_inventory_successful_read_hints=1" }));
        assert!(merged.probe_source_hints.iter().any(|hint| {
            hint.url
                .eq_ignore_ascii_case("https://csrc.nist.gov/pubs/ir/8413/upd1/final")
        }));
        assert!(probe.contains("\"FIPS 203\""), "probe={probe}");
        assert!(probe.contains("\"FIPS 204\""), "probe={probe}");
        assert!(probe.contains("\"FIPS 205\""), "probe={probe}");
    }

    #[test]
    fn briefing_authority_hint_read_recovery_urls_preserve_one_authority_slot_and_one_distinct_support_slot(
    ) {
        let query =
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
        let retrieval_contract =
            crate::agentic::web::derive_web_retrieval_contract(query, Some(query)).unwrap();
        let deterministic_plan = PreReadCandidatePlan {
            candidate_urls: vec!["https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string()],
            candidate_source_hints: vec![PendingSearchReadSummary {
                url: "https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string(),
                title: Some(
                    "Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process"
                        .to_string(),
                ),
                excerpt:
                    "The new public-key cryptography standards will specify additional digital signature, public-key encryption, and key-establishment algorithms."
                        .to_string(),
            }],
            requires_constraint_search_probe: true,
            ..PreReadCandidatePlan::default()
        };
        let discovery_hints = vec![
            PendingSearchReadSummary {
                url: "https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string(),
                title: Some(
                    "Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process"
                        .to_string(),
                ),
                excerpt:
                    "The new public-key cryptography standards will specify additional digital signature, public-key encryption, and key-establishment algorithms."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://www.nist.gov/news-events/news/2022/07/nist-announces-first-four-quantum-resistant-cryptographic-algorithms"
                    .to_string(),
                title: Some(
                    "NIST Announces First Four Quantum-Resistant Cryptographic Algorithms"
                        .to_string(),
                ),
                excerpt:
                    "NIST selected CRYSTALS-Kyber, CRYSTALS-Dilithium, SPHINCS+, and FALCON."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://csrc.nist.gov/pubs/fips/203/final".to_string(),
                title: Some("Federal Information Processing Standard (FIPS) 203".to_string()),
                excerpt:
                    "NIST IR 8413 Update 1 references FIPS 203 as part of the post-quantum cryptography standards set."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://csrc.nist.gov/pubs/fips/204/final".to_string(),
                title: Some("Federal Information Processing Standard (FIPS) 204".to_string()),
                excerpt:
                    "NIST IR 8413 Update 1 references FIPS 204 as part of the post-quantum cryptography standards set."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://csrc.nist.gov/pubs/fips/205/final".to_string(),
                title: Some("Federal Information Processing Standard (FIPS) 205".to_string()),
                excerpt:
                    "NIST IR 8413 Update 1 references FIPS 205 as part of the post-quantum cryptography standards set."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://nvlpubs.nist.gov/nistpubs/ir/2022/NIST.IR.8413-upd1.pdf"
                    .to_string(),
                title: Some(
                    "Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process"
                        .to_string(),
                ),
                excerpt:
                    "NIST IR 8413 Update 1 summarizes the standardization process and references FIPS 203, FIPS 204, and FIPS 205."
                        .to_string(),
            },
        ];

        let urls = briefing_authority_hint_read_recovery_urls(
            &retrieval_contract,
            query,
            2,
            &deterministic_plan,
            &[],
            &discovery_hints,
            None,
            2,
        );

        assert_eq!(urls.len(), 2, "{urls:?}");
        assert!(
            urls.iter()
                .any(|url| url.starts_with("https://csrc.nist.gov/pubs/fips/20")),
            "{urls:?}"
        );
        assert!(
            urls.iter()
                .any(|url| url.eq_ignore_ascii_case("https://csrc.nist.gov/pubs/fips/203/final")),
            "{urls:?}"
        );
        assert!(
            urls.iter().any(|url| {
                url.eq_ignore_ascii_case(
                    "https://nvlpubs.nist.gov/nistpubs/ir/2022/NIST.IR.8413-upd1.pdf"
                )
                    || url.eq_ignore_ascii_case(
                        "https://www.nist.gov/news-events/news/2022/07/nist-announces-first-four-quantum-resistant-cryptographic-algorithms"
                    )
            }),
            "{urls:?}"
        );
    }

    #[test]
    fn briefing_authority_hint_read_recovery_urls_choose_official_news_when_no_pdf_domain_available(
    ) {
        let query =
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
        let retrieval_contract =
            crate::agentic::web::derive_web_retrieval_contract(query, Some(query)).unwrap();
        let deterministic_plan = PreReadCandidatePlan {
            candidate_urls: vec!["https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string()],
            candidate_source_hints: vec![PendingSearchReadSummary {
                url: "https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string(),
                title: Some(
                    "IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC"
                        .to_string(),
                ),
                excerpt:
                    "The latest NIST post-quantum cryptography standards track FIPS 203, FIPS 204, and FIPS 205."
                        .to_string(),
            }],
            requires_constraint_search_probe: true,
            ..PreReadCandidatePlan::default()
        };
        let discovery_hints = vec![
            PendingSearchReadSummary {
                url: "https://csrc.nist.gov/pubs/fips/203/final".to_string(),
                title: Some("Federal Information Processing Standard (FIPS) 203".to_string()),
                excerpt:
                    "NIST IR 8413 Update 1 references FIPS 203 as part of the post-quantum cryptography standards set."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards"
                    .to_string(),
                title: Some(
                    "NIST Releases First 3 Finalized Post-Quantum Encryption Standards"
                        .to_string(),
                ),
                excerpt:
                    "NIST released the first three finalized post-quantum encryption standards and urged migration to the new standards."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization"
                    .to_string(),
                title: Some("Post-Quantum Cryptography Standardization".to_string()),
                excerpt:
                    "NIST project page for the latest post-quantum cryptography standards and standardization updates."
                        .to_string(),
            },
        ];

        let urls = briefing_authority_hint_read_recovery_urls(
            &retrieval_contract,
            query,
            2,
            &deterministic_plan,
            &[],
            &discovery_hints,
            None,
            2,
        );

        assert_eq!(urls.len(), 2, "{urls:?}");
        assert!(
            urls.iter()
                .any(|url| url.eq_ignore_ascii_case("https://csrc.nist.gov/pubs/fips/203/final")),
            "{urls:?}"
        );
        assert!(
            urls.iter().any(|url| {
                url.eq_ignore_ascii_case(
                    "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards"
                )
            }),
            "{urls:?}"
        );
    }

    #[test]
    fn briefing_authority_hint_read_recovery_urls_fill_recovery_batch_after_single_authority_slot()
    {
        let query =
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing using current web and local memory evidence, then return a cited brief with findings, uncertainties, and next checks.";
        let retrieval_contract =
            crate::agentic::web::derive_web_retrieval_contract(query, Some(query)).unwrap();
        let deterministic_plan = PreReadCandidatePlan {
            candidate_urls: vec![
                "https://www.nist.gov/cybersecurity-and-privacy".to_string(),
                "https://www.nist.gov/about-nist".to_string(),
                "https://www.nist.gov/standards".to_string(),
                "https://www.nist.gov/publications".to_string(),
                "https://www.nist.gov/standards-measurements".to_string(),
                "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards"
                    .to_string(),
                "https://csrc.nist.gov/pubs/fips/203/final".to_string(),
                "https://csrc.nist.gov/pubs/fips/204/final".to_string(),
                "https://csrc.nist.gov/pubs/fips/205/final".to_string(),
            ],
            candidate_source_hints: vec![
                PendingSearchReadSummary {
                    url: "https://www.nist.gov/cybersecurity-and-privacy".to_string(),
                    title: Some("Cybersecurity and privacy | NIST".to_string()),
                    excerpt:
                        "NIST advances standards, guidelines, best practices, and resources for cybersecurity."
                            .to_string(),
                },
                PendingSearchReadSummary {
                    url: "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards"
                        .to_string(),
                    title: Some(
                        "NIST Releases First 3 Finalized Post-Quantum Encryption Standards"
                            .to_string(),
                    ),
                    excerpt:
                        "NIST released FIPS 203, FIPS 204, and FIPS 205 as finalized post-quantum standards."
                            .to_string(),
                },
                PendingSearchReadSummary {
                    url: "https://csrc.nist.gov/pubs/fips/203/final".to_string(),
                    title: Some(
                        "FIPS 203, Module-Lattice-Based Key-Encapsulation Mechanism Standard"
                            .to_string(),
                    ),
                    excerpt:
                        "Finalized NIST FIPS 203 post-quantum cryptography standard.".to_string(),
                },
                PendingSearchReadSummary {
                    url: "https://csrc.nist.gov/pubs/fips/204/final".to_string(),
                    title: Some(
                        "FIPS 204, Module-Lattice-Based Digital Signature Standard".to_string(),
                    ),
                    excerpt:
                        "Finalized NIST FIPS 204 post-quantum cryptography standard.".to_string(),
                },
                PendingSearchReadSummary {
                    url: "https://csrc.nist.gov/pubs/fips/205/final".to_string(),
                    title: Some(
                        "FIPS 205, Stateless Hash-Based Digital Signature Standard".to_string(),
                    ),
                    excerpt:
                        "Finalized NIST FIPS 205 post-quantum cryptography standard.".to_string(),
                },
            ],
            requires_constraint_search_probe: true,
            ..PreReadCandidatePlan::default()
        };

        let urls = briefing_authority_hint_read_recovery_urls(
            &retrieval_contract,
            query,
            2,
            &deterministic_plan,
            &[],
            &deterministic_plan.candidate_source_hints,
            None,
            2,
        );

        assert_eq!(urls.len(), 2, "{urls:?}");
        assert!(
            urls.iter().any(|url| {
                url.eq_ignore_ascii_case(
                    "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards"
                ) || url.starts_with("https://csrc.nist.gov/pubs/fips/20")
            }),
            "{urls:?}"
        );
    }

    #[test]
    fn distinct_domain_preserving_selected_urls_promotes_official_support_into_initial_briefing_batch(
    ) {
        let query = "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing using current web and local memory evidence, then return a cited brief with findings, uncertainties, and next checks.";
        let retrieval_contract =
            crate::agentic::web::derive_web_retrieval_contract(query, Some(query)).unwrap();
        let candidate_urls = vec![
            "https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string(),
            "https://csrc.nist.gov/pubs/ir/8413/final".to_string(),
            "https://csrc.nist.gov/News/2024/postquantum-cryptography-fips-approved".to_string(),
            "https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization".to_string(),
            "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards".to_string(),
        ];

        let selected = distinct_domain_preserving_selected_urls(
            &retrieval_contract,
            query,
            &candidate_urls,
            2,
        );

        assert_eq!(
            selected,
            vec![
                "https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string(),
                "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards"
                    .to_string(),
            ]
        );
    }

    #[test]
    fn merged_candidate_urls_promote_semantic_distinct_host_support_into_initial_briefing_batch() {
        let query = "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing using current web and local memory evidence, then return a cited brief with findings, uncertainties, and next checks.";
        let retrieval_contract =
            crate::agentic::web::derive_web_retrieval_contract(query, Some(query)).unwrap();
        let selected_urls = vec![
            "https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string(),
            "https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization"
                .to_string(),
        ];
        let deterministic_candidate_urls = selected_urls.clone();
        let semantic_aligned_discovery_urls = vec![
            "https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string(),
            "https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization"
                .to_string(),
            "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards"
                .to_string(),
        ];

        let merged = merge_candidate_urls_preserving_order(
            &selected_urls,
            &deterministic_candidate_urls,
            &semantic_aligned_discovery_urls,
        );
        let promoted =
            distinct_domain_preserving_selected_urls(&retrieval_contract, query, &merged, 2);

        assert_eq!(
            promoted,
            vec![
                "https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string(),
                "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards"
                    .to_string(),
            ]
        );
    }

    #[test]
    fn selected_source_alignment_uses_selected_surface_hints_for_document_briefings() {
        let query =
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
        let retrieval_contract =
            crate::agentic::web::derive_web_retrieval_contract(query, Some(query)).unwrap();
        let selected_urls = vec![
            "https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string(),
            "https://csrc.nist.gov/pubs/fips/203/final".to_string(),
            "https://csrc.nist.gov/pubs/fips/204/final".to_string(),
            "https://csrc.nist.gov/pubs/fips/205/final".to_string(),
        ];
        let discovery_aligned_urls =
            vec!["https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string()];
        let source_hints = vec![
            PendingSearchReadSummary {
                url: "https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string(),
                title: Some(
                    "IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC"
                        .to_string(),
                ),
                excerpt:
                    "NIST IR 8413 Update 1 references FIPS 203, FIPS 204, and FIPS 205 as the finalized post-quantum cryptography standards."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://csrc.nist.gov/pubs/fips/203/final".to_string(),
                title: Some(
                    "FIPS 203, Module-Lattice-Based Key-Encapsulation Mechanism Standard | CSRC"
                        .to_string(),
                ),
                excerpt:
                    "Federal Information Processing Standard FIPS 203 specifies ML-KEM as a finalized NIST post-quantum cryptography standard."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://csrc.nist.gov/pubs/fips/204/final".to_string(),
                title: Some(
                    "FIPS 204, Module-Lattice-Based Digital Signature Standard | CSRC"
                        .to_string(),
                ),
                excerpt:
                    "Federal Information Processing Standard FIPS 204 specifies ML-DSA as a finalized NIST post-quantum cryptography standard."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://csrc.nist.gov/pubs/fips/205/final".to_string(),
                title: Some(
                    "FIPS 205, Stateless Hash-Based Digital Signature Standard | CSRC"
                        .to_string(),
                ),
                excerpt:
                    "Federal Information Processing Standard FIPS 205 specifies SLH-DSA as a finalized NIST post-quantum cryptography standard."
                        .to_string(),
            },
        ];

        let aligned = selected_source_alignment_urls(
            query,
            &retrieval_contract,
            &selected_urls,
            &discovery_aligned_urls,
            &source_hints,
            None,
        );

        assert_eq!(aligned.len(), selected_urls.len(), "{aligned:?}");
        assert!(aligned.contains(&"https://csrc.nist.gov/pubs/fips/203/final".to_string()));
        assert!(aligned.contains(&"https://csrc.nist.gov/pubs/fips/204/final".to_string()));
        assert!(aligned.contains(&"https://csrc.nist.gov/pubs/fips/205/final".to_string()));
    }

    #[test]
    fn briefing_authority_hint_read_recovery_urls_prefer_grounded_support_over_generic_same_host_neighbors(
    ) {
        let query =
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing using current web and local memory evidence, then return a cited brief with findings, uncertainties, and next checks.";
        let retrieval_contract =
            crate::agentic::web::derive_web_retrieval_contract(query, Some(query)).unwrap();
        let deterministic_plan = PreReadCandidatePlan {
            candidate_urls: vec![
                "https://www.nist.gov/cybersecurity-and-privacy".to_string(),
                "https://www.nist.gov/about-nist".to_string(),
                "https://www.nist.gov/standards".to_string(),
                "https://www.nist.gov/publications".to_string(),
                "https://www.nist.gov/standards-measurements".to_string(),
                "https://www.nist.gov/cybersecurity-and-privacy/what-post-quantum-cryptography"
                    .to_string(),
                "https://csrc.nist.gov/pubs/fips/203/final".to_string(),
                "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards"
                    .to_string(),
            ],
            candidate_source_hints: vec![
                PendingSearchReadSummary {
                    url: "https://www.nist.gov/cybersecurity-and-privacy".to_string(),
                    title: Some("Cybersecurity and privacy | NIST".to_string()),
                    excerpt:
                        "NIST advances standards, guidelines, best practices, and resources for cybersecurity."
                            .to_string(),
                },
                PendingSearchReadSummary {
                    url: "https://www.nist.gov/about-nist".to_string(),
                    title: Some("About NIST".to_string()),
                    excerpt: "Overview of the National Institute of Standards and Technology."
                        .to_string(),
                },
                PendingSearchReadSummary {
                    url: "https://www.nist.gov/cybersecurity-and-privacy/what-post-quantum-cryptography"
                        .to_string(),
                    title: Some("What Is Post-Quantum Cryptography? | NIST".to_string()),
                    excerpt:
                        "Overview of post-quantum cryptography and why NIST is standardizing new algorithms."
                            .to_string(),
                },
                PendingSearchReadSummary {
                    url: "https://csrc.nist.gov/pubs/fips/203/final".to_string(),
                    title: Some(
                        "FIPS 203, Module-Lattice-Based Key-Encapsulation Mechanism Standard"
                            .to_string(),
                    ),
                    excerpt:
                        "Finalized NIST FIPS 203 post-quantum cryptography standard.".to_string(),
                },
                PendingSearchReadSummary {
                    url: "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards"
                        .to_string(),
                    title: Some(
                        "NIST Releases First 3 Finalized Post-Quantum Encryption Standards"
                            .to_string(),
                    ),
                    excerpt:
                        "NIST released FIPS 203, FIPS 204, and FIPS 205 as finalized post-quantum standards."
                            .to_string(),
                },
            ],
            requires_constraint_search_probe: true,
            ..PreReadCandidatePlan::default()
        };

        let urls = briefing_authority_hint_read_recovery_urls(
            &retrieval_contract,
            query,
            2,
            &deterministic_plan,
            &[],
            &deterministic_plan.candidate_source_hints,
            None,
            2,
        );

        assert_eq!(urls.len(), 2, "{urls:?}");
        assert!(
            urls.iter()
                .all(|url| !url.eq_ignore_ascii_case("https://www.nist.gov/about-nist")),
            "{urls:?}"
        );
        assert!(
            urls.iter().any(|url| {
                url.eq_ignore_ascii_case(
                    "https://www.nist.gov/cybersecurity-and-privacy/what-post-quantum-cryptography"
                ) || url.eq_ignore_ascii_case("https://csrc.nist.gov/pubs/fips/203/final")
                    || url.eq_ignore_ascii_case(
                        "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards"
                    )
            }),
            "{urls:?}"
        );
    }
}
