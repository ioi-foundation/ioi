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
    if source_has_human_challenge_signal(
        trimmed,
        resolved_title.as_deref().unwrap_or_default(),
        &resolved_excerpt,
    ) {
        mark_pending_web_blocked(pending, trimmed);
        return;
    }
    if source_has_terminal_error_signal(
        trimmed,
        resolved_title.as_deref().unwrap_or_default(),
        &resolved_excerpt,
    ) {
        return;
    }

    let query_contract = synthesis_query_contract(pending);
    let retrieval_contract = pending.retrieval_contract.as_ref();
    let single_snapshot_contract =
        retrieval_contract_prefers_single_fact_snapshot(retrieval_contract, &query_contract);
    let projection = build_query_constraint_projection(
        &query_contract,
        pending.min_sources,
        &pending.candidate_source_hints,
    );
    let headline_collection_mode =
        retrieval_contract_is_generic_headline_collection(retrieval_contract, &query_contract);
    let min_sources_required = pending.min_sources.max(1) as usize;
    let source_floor_unmet = pending.successful_reads.len() < min_sources_required;
    let time_sensitive = projection
        .constraints
        .scopes
        .contains(&ConstraintScope::TimeSensitive)
        || retrieval_contract
            .map(|contract| contract.currentness_required)
            .unwrap_or(false);
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
        let base_url_allowed = is_citable_web_url(trimmed)
            && !is_search_hub_url(trimmed)
            && !is_multi_item_listing_url(trimmed);
        let resolved_url = if base_url_allowed {
            trimmed.to_string()
        } else {
            source_url_from_metadata_excerpt(&resolved_excerpt)
                .or_else(|| {
                    hint_excerpt
                        .as_deref()
                        .and_then(source_url_from_metadata_excerpt)
                })
                .filter(|candidate_url| {
                    let candidate = candidate_url.trim();
                    is_citable_web_url(candidate)
                        && !is_search_hub_url(candidate)
                        && !is_multi_item_listing_url(candidate)
                })
                .unwrap_or_else(|| trimmed.to_string())
        };
        if headline_source_is_low_quality(
            &resolved_url,
            resolved_title.as_deref().unwrap_or_default(),
            &resolved_excerpt,
        ) {
            return;
        }
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
                trimmed,
                resolved_title.as_deref().unwrap_or_default(),
                &resolved_excerpt,
            );
            if !resolved_payload {
                if let Some(hint_entry) = hint {
                    let hint_title = hint_entry.title.as_deref().unwrap_or_default().trim();
                    let hint_excerpt = hint_entry.excerpt.trim();
                    if !hint_excerpt.is_empty()
                        && candidate_time_sensitive_resolvable_payload(
                            trimmed,
                            hint_title,
                            hint_excerpt,
                        )
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
                            candidate_url,
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
                if single_snapshot_contract {
                    return;
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

fn excerpt_without_source_url_metadata(excerpt: &str) -> String {
    excerpt
        .split_whitespace()
        .filter(|token| {
            let trimmed = token.trim();
            !trimmed.is_empty()
                && trimmed != "|"
                && !trimmed.to_ascii_lowercase().starts_with("source_url=")
        })
        .collect::<Vec<_>>()
        .join(" ")
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

pub(crate) fn append_pending_web_success_from_hint(
    pending: &mut PendingSearchCompletion,
    requested_url: &str,
) -> bool {
    let query_contract = synthesis_query_contract(pending);
    if !retrieval_contract_is_generic_headline_collection(
        pending.retrieval_contract.as_ref(),
        &query_contract,
    ) {
        return false;
    }

    let Some(hint) = hint_for_url(pending, requested_url).cloned() else {
        return false;
    };
    let candidate_url = source_url_from_metadata_excerpt(&hint.excerpt)
        .unwrap_or_else(|| hint.url.trim().to_string());
    if candidate_url.trim().is_empty() {
        return false;
    }
    let cleaned_excerpt = excerpt_without_source_url_metadata(&hint.excerpt);
    let excerpt = prioritized_signal_excerpt(&cleaned_excerpt, 180);
    let candidate_source = PendingSearchReadSummary {
        url: candidate_url.clone(),
        title: hint.title.clone(),
        excerpt: excerpt.clone(),
    };
    let candidate_title = canonical_source_title(&candidate_source);
    if is_low_signal_title(&candidate_title)
        || !headline_story_title_has_specificity(&candidate_title)
        || headline_source_is_low_quality(&candidate_url, &candidate_title, &excerpt)
    {
        return false;
    }

    let before = pending.successful_reads.len();
    if !try_append_headline_bundle_success(
        pending,
        requested_url,
        &candidate_url,
        hint.title,
        excerpt,
    ) {
        return false;
    }

    pending.successful_reads.len() > before
}

pub(crate) fn append_pending_web_success_from_bundle(
    pending: &mut PendingSearchCompletion,
    bundle: &WebEvidenceBundle,
    fallback_url: &str,
) {
    let query_contract = synthesis_query_contract(pending);
    let headline_collection_mode = retrieval_contract_is_generic_headline_collection(
        pending.retrieval_contract.as_ref(),
        &query_contract,
    );
    if headline_collection_mode {
        let fallback_trimmed = fallback_url.trim();
        let mut appended = false;

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
            if try_append_headline_bundle_success(
                pending,
                fallback_trimmed,
                doc.url.as_str(),
                title,
                excerpt,
            ) {
                appended = true;
                break;
            }
        }

        if !appended {
            for source in bundle.sources.iter().take(8) {
                let excerpt =
                    prioritized_signal_excerpt(source.snippet.as_deref().unwrap_or_default(), 180);
                if try_append_headline_bundle_success(
                    pending,
                    fallback_trimmed,
                    source.url.as_str(),
                    source.title.clone(),
                    excerpt,
                ) {
                    appended = true;
                    break;
                }
            }
        }

        if !appended && !fallback_trimmed.is_empty() {
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

fn try_append_headline_bundle_success(
    pending: &mut PendingSearchCompletion,
    requested_url: &str,
    candidate_url: &str,
    title: Option<String>,
    excerpt: String,
) -> bool {
    let candidate_trimmed = candidate_url.trim();
    if candidate_trimmed.is_empty() {
        return false;
    }
    let requested_trimmed = requested_url.trim();
    if !requested_trimmed.is_empty()
        && !headline_bundle_url_matches_requested(candidate_trimmed, requested_trimmed)
    {
        return false;
    }

    let requested_allowed = headline_read_success_url_allowed(requested_trimmed);
    let candidate_allowed = headline_read_success_url_allowed(candidate_trimmed);
    let requested_is_google_news_wrapper =
        crate::agentic::web::is_google_news_article_wrapper_url(requested_trimmed);
    let recorded_url =
        if candidate_allowed && (requested_is_google_news_wrapper || !requested_allowed) {
            candidate_trimmed.to_string()
        } else if requested_allowed {
            requested_trimmed.to_string()
        } else if candidate_allowed {
            candidate_trimmed.to_string()
        } else {
            return false;
        };
    if headline_source_is_low_quality(
        &recorded_url,
        title.as_deref().unwrap_or_default(),
        &excerpt,
    ) {
        return false;
    }
    push_pending_web_success(pending, &recorded_url, title, excerpt);
    true
}

fn headline_bundle_url_matches_requested(candidate_url: &str, requested_url: &str) -> bool {
    if url_structurally_equivalent(candidate_url, requested_url) {
        return true;
    }
    if crate::agentic::web::is_google_news_article_wrapper_url(requested_url)
        && headline_read_success_url_allowed(candidate_url)
    {
        return true;
    }
    let Some(candidate_host) = normalized_source_host(candidate_url) else {
        return false;
    };
    let Some(requested_host) = normalized_source_host(requested_url) else {
        return false;
    };
    candidate_host == requested_host
}

fn normalized_source_host(url: &str) -> Option<String> {
    source_host(url).map(|host| {
        host.strip_prefix("www.")
            .unwrap_or(&host)
            .to_ascii_lowercase()
    })
}

fn headline_read_success_url_allowed(url: &str) -> bool {
    let trimmed = url.trim();
    !trimmed.is_empty() && projection_candidate_url_allowed(trimmed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn headline_read_success_url_rejects_root_homepages() {
        assert!(!headline_read_success_url_allowed(
            "https://www.cbsnews.com/"
        ));
        assert!(!headline_read_success_url_allowed(
            "https://www.nbcnews.com/"
        ));
    }

    #[test]
    fn headline_read_success_url_accepts_deep_article_urls() {
        assert!(headline_read_success_url_allowed(
            "https://www.reuters.com/world/europe/example-story-2026-03-01/"
        ));
        assert!(headline_read_success_url_allowed(
            "https://news.google.com/rss/articles/CBMiY2h0dHBzOi8vd3d3LmFwbmV3cy5jb20vYXJ0aWNsZS9leGFtcGxlLXN0b3J5LTIwMjYtMDMtMDFSAQA"
        ));
    }
}
