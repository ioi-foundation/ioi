use super::*;

pub(crate) fn push_pending_web_success(
    pending: &mut PendingSearchCompletion,
    url: &str,
    title: Option<String>,
    excerpt: String,
) {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return;
    }
    if pending
        .successful_reads
        .iter()
        .any(|existing| url_structurally_equivalent(existing.url.trim(), trimmed))
    {
        return;
    }

    let hint = hint_for_url(pending, trimmed);
    let mut resolved_title = title
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string());
    if resolved_title
        .as_deref()
        .map(is_low_signal_title)
        .unwrap_or(true)
    {
        if let Some(hint_title) = hint
            .and_then(|value| value.title.as_deref())
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            resolved_title = Some(hint_title.to_string());
        }
    }

    let hint_excerpt = hint
        .map(|value| value.excerpt.trim())
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string());
    let mut resolved_excerpt = excerpt.trim().to_string();
    if let Some(hint_excerpt) = hint_excerpt.as_deref() {
        // Keep retrieved page content authoritative. Only backfill from the search
        // snippet when the read itself yielded no excerpt text.
        if resolved_excerpt.is_empty() {
            resolved_excerpt = hint_excerpt.to_string();
        }
    }

    let query_contract = synthesis_query_contract(pending);
    let projection = build_query_constraint_projection(
        &query_contract,
        pending.min_sources,
        &pending.candidate_source_hints,
    );
    let headline_collection_mode = query_is_generic_headline_collection(&query_contract);
    let min_sources_required = pending.min_sources.max(1) as usize;
    let source_floor_unmet = pending.successful_reads.len() < min_sources_required;
    let time_sensitive = projection
        .constraints
        .scopes
        .contains(&ConstraintScope::TimeSensitive);
    let reject_search_hub = projection.reject_search_hub_candidates();
    if headline_collection_mode {
        let script_like_excerpt = resolved_excerpt.contains("||")
            && resolved_excerpt.contains("==")
            && resolved_excerpt.to_ascii_lowercase().contains("return");
        if (resolved_excerpt.is_empty()
            || is_low_signal_excerpt(&resolved_excerpt)
            || script_like_excerpt)
            && hint_excerpt.is_some()
        {
            if let Some(hint_excerpt_text) = hint_excerpt.as_deref() {
                resolved_excerpt = hint_excerpt_text.to_string();
            }
        }
        let resolved_url = if is_news_feed_wrapper_url(trimmed) {
            source_url_from_metadata_excerpt(&resolved_excerpt)
                .or_else(|| {
                    hint_excerpt
                        .as_deref()
                        .and_then(source_url_from_metadata_excerpt)
                })
                .filter(|candidate_url| {
                    let candidate = candidate_url.trim();
                    is_citable_web_url(candidate)
                        && !is_news_feed_wrapper_url(candidate)
                        && !is_search_hub_url(candidate)
                        && !is_multi_item_listing_url(candidate)
                })
                .unwrap_or_else(|| trimmed.to_string())
        } else {
            trimmed.to_string()
        };
        pending.successful_reads.push(PendingSearchReadSummary {
            url: resolved_url,
            title: resolved_title,
            excerpt: resolved_excerpt,
        });
        return;
    }
    if reject_search_hub && is_search_hub_url(trimmed) {
        return;
    }
    if projection.query_facets.grounded_external_required || time_sensitive {
        let compatibility = candidate_constraint_compatibility(
            &projection.constraints,
            &projection.query_facets,
            &projection.query_native_tokens,
            &projection.query_tokens,
            &projection.locality_tokens,
            projection.locality_scope.is_some(),
            trimmed,
            resolved_title.as_deref().unwrap_or_default(),
            &resolved_excerpt,
        );
        let mut compatibility_passes = compatibility_passes_projection(&projection, &compatibility);
        if !compatibility_passes {
            if let Some(hint_entry) = hint {
                let hint_title = hint_entry.title.as_deref().unwrap_or_default().trim();
                let hint_excerpt = hint_entry.excerpt.trim();
                let hint_compatibility = candidate_constraint_compatibility(
                    &projection.constraints,
                    &projection.query_facets,
                    &projection.query_native_tokens,
                    &projection.query_tokens,
                    &projection.locality_tokens,
                    projection.locality_scope.is_some(),
                    trimmed,
                    hint_title,
                    hint_excerpt,
                );
                if compatibility_passes_projection(&projection, &hint_compatibility) {
                    compatibility_passes = true;
                    if resolved_title
                        .as_deref()
                        .map(is_low_signal_title)
                        .unwrap_or(true)
                        && !hint_title.is_empty()
                    {
                        resolved_title = Some(hint_title.to_string());
                    }
                    if !hint_excerpt.is_empty() {
                        resolved_excerpt = hint_excerpt.to_string();
                    }
                }
            }
        }
        if !compatibility_passes {
            let has_compatible_alternative =
                pending.candidate_source_hints.iter().any(|candidate| {
                    let candidate_url = candidate.url.trim();
                    if candidate_url.is_empty() || candidate_url.eq_ignore_ascii_case(trimmed) {
                        return false;
                    }
                    if is_search_hub_url(candidate_url) {
                        return false;
                    }
                    let candidate_title = candidate.title.as_deref().unwrap_or_default();
                    let candidate_excerpt = candidate.excerpt.as_str();
                    let candidate_compatibility = candidate_constraint_compatibility(
                        &projection.constraints,
                        &projection.query_facets,
                        &projection.query_native_tokens,
                        &projection.query_tokens,
                        &projection.locality_tokens,
                        projection.locality_scope.is_some(),
                        candidate_url,
                        candidate_title,
                        candidate_excerpt,
                    );
                    compatibility_passes_projection(&projection, &candidate_compatibility)
                });
            let allow_exploratory_first_capture =
                projection.locality_scope_inferred && !projection.locality_tokens.is_empty();
            let allow_exploratory_floor_capture = source_floor_unmet
                && time_sensitive
                && compatibility.locality_compatible
                && !is_search_hub_url(trimmed);
            if (!source_floor_unmet && has_compatible_alternative)
                || (!source_floor_unmet && !pending.successful_reads.is_empty())
                || (!allow_exploratory_first_capture && !allow_exploratory_floor_capture)
            {
                return;
            }
        }

        if time_sensitive {
            let mut resolved_payload = candidate_time_sensitive_resolvable_payload(
                resolved_title.as_deref().unwrap_or_default(),
                &resolved_excerpt,
            );
            if !resolved_payload {
                if let Some(hint_entry) = hint {
                    let hint_title = hint_entry.title.as_deref().unwrap_or_default().trim();
                    let hint_excerpt = hint_entry.excerpt.trim();
                    if !hint_excerpt.is_empty()
                        && candidate_time_sensitive_resolvable_payload(hint_title, hint_excerpt)
                    {
                        let hint_compatibility = candidate_constraint_compatibility(
                            &projection.constraints,
                            &projection.query_facets,
                            &projection.query_native_tokens,
                            &projection.query_tokens,
                            &projection.locality_tokens,
                            projection.locality_scope.is_some(),
                            trimmed,
                            hint_title,
                            hint_excerpt,
                        );
                        if compatibility_passes_projection(&projection, &hint_compatibility) {
                            if !hint_title.is_empty() {
                                resolved_title = Some(hint_title.to_string());
                            }
                            resolved_excerpt = hint_excerpt.to_string();
                            resolved_payload = true;
                        }
                    }
                }
            }
            if !resolved_payload {
                let has_resolvable_alternative = pending
                    .candidate_source_hints
                    .iter()
                    .chain(pending.successful_reads.iter())
                    .any(|candidate| {
                        let candidate_url = candidate.url.trim();
                        if candidate_url.is_empty() || is_search_hub_url(candidate_url) {
                            return false;
                        }
                        if candidate_url.eq_ignore_ascii_case(trimmed) {
                            return false;
                        }
                        let candidate_title = candidate.title.as_deref().unwrap_or_default().trim();
                        let candidate_excerpt = candidate.excerpt.trim();
                        if !candidate_time_sensitive_resolvable_payload(
                            candidate_title,
                            candidate_excerpt,
                        ) {
                            return false;
                        }
                        let candidate_compatibility = candidate_constraint_compatibility(
                            &projection.constraints,
                            &projection.query_facets,
                            &projection.query_native_tokens,
                            &projection.query_tokens,
                            &projection.locality_tokens,
                            projection.locality_scope.is_some(),
                            candidate_url,
                            candidate_title,
                            candidate_excerpt,
                        );
                        compatibility_passes_projection(&projection, &candidate_compatibility)
                    });
                if has_resolvable_alternative {
                    if source_floor_unmet {
                        // Floor-recovery mode: retain additional locality-compatible reads even
                        // when stronger resolvable alternatives already exist.
                    } else {
                        return;
                    }
                }
            }
        }
    }

    pending.successful_reads.push(PendingSearchReadSummary {
        url: trimmed.to_string(),
        title: resolved_title,
        excerpt: resolved_excerpt,
    });
}

fn source_url_from_metadata_excerpt(excerpt: &str) -> Option<String> {
    let marker = "source_url=";
    let lower = excerpt.to_ascii_lowercase();
    let start = lower.find(marker)? + marker.len();
    let candidate = excerpt
        .get(start..)?
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .trim_matches(|ch: char| "|,;:!?)]}\"'".contains(ch))
        .trim();
    if candidate.starts_with("http://") || candidate.starts_with("https://") {
        Some(candidate.to_string())
    } else {
        None
    }
}

pub(crate) fn append_pending_web_success_fallback(
    pending: &mut PendingSearchCompletion,
    url: &str,
    raw_output: Option<&str>,
) {
    let excerpt =
        prioritized_signal_excerpt(raw_output.unwrap_or_default(), WEB_PIPELINE_EXCERPT_CHARS);
    push_pending_web_success(pending, url, None, excerpt);
}

pub(crate) fn append_pending_web_success_from_bundle(
    pending: &mut PendingSearchCompletion,
    bundle: &WebEvidenceBundle,
    fallback_url: &str,
) {
    let query_contract = synthesis_query_contract(pending);
    let headline_collection_mode = query_is_generic_headline_collection(&query_contract);
    if headline_collection_mode {
        let before = pending.successful_reads.len();

        for doc in bundle.documents.iter().take(8) {
            let title = doc
                .title
                .clone()
                .or_else(|| {
                    bundle
                        .sources
                        .iter()
                        .find(|source| source.source_id == doc.source_id)
                        .and_then(|source| source.title.clone())
                })
                .filter(|value| !value.trim().is_empty());
            let excerpt = prioritized_signal_excerpt(&doc.content_text, WEB_PIPELINE_EXCERPT_CHARS);
            push_pending_web_success(pending, &doc.url, title, excerpt);
        }

        for source in bundle.sources.iter().take(8) {
            let excerpt =
                prioritized_signal_excerpt(source.snippet.as_deref().unwrap_or_default(), 180);
            push_pending_web_success(pending, &source.url, source.title.clone(), excerpt);
        }

        let fallback_trimmed = fallback_url.trim();
        if pending.successful_reads.len() == before && !fallback_trimmed.is_empty() {
            append_pending_web_success_fallback(pending, fallback_trimmed, None);
        }
        return;
    }

    if let Some(doc) = bundle.documents.first() {
        let title = doc
            .title
            .clone()
            .or_else(|| {
                bundle
                    .sources
                    .iter()
                    .find(|source| source.source_id == doc.source_id)
                    .and_then(|source| source.title.clone())
            })
            .filter(|value| !value.trim().is_empty());
        let excerpt = prioritized_signal_excerpt(&doc.content_text, WEB_PIPELINE_EXCERPT_CHARS);
        let before = pending.successful_reads.len();
        push_pending_web_success(pending, &doc.url, title.clone(), excerpt.clone());
        if pending.successful_reads.len() > before {
            return;
        }
        let fallback_trimmed = fallback_url.trim();
        if !fallback_trimmed.is_empty() && !url_structurally_equivalent(&doc.url, fallback_trimmed)
        {
            push_pending_web_success(pending, fallback_trimmed, title, excerpt);
            if pending.successful_reads.len() > before {
                return;
            }
        } else if pending.successful_reads.len() > before {
            return;
        }
    }

    if let Some(source) = bundle.sources.first() {
        let excerpt =
            prioritized_signal_excerpt(source.snippet.as_deref().unwrap_or_default(), 180);
        let before = pending.successful_reads.len();
        push_pending_web_success(pending, &source.url, source.title.clone(), excerpt.clone());
        if pending.successful_reads.len() > before {
            return;
        }
        let fallback_trimmed = fallback_url.trim();
        if !fallback_trimmed.is_empty()
            && !url_structurally_equivalent(&source.url, fallback_trimmed)
        {
            push_pending_web_success(pending, fallback_trimmed, source.title.clone(), excerpt);
            if pending.successful_reads.len() > before {
                return;
            }
        } else if pending.successful_reads.len() > before {
            return;
        }
    }

    append_pending_web_success_fallback(pending, fallback_url, None);
}

