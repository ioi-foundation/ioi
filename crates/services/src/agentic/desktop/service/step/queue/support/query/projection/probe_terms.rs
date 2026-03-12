pub(crate) fn projection_constraint_search_terms(
    projection: &QueryConstraintProjection,
) -> Vec<String> {
    let mut terms = Vec::new();
    let has_explicit_metric_objective = !projection.constraints.required_facets.is_empty()
        || !projection.query_facets.metric_schema.axis_hits.is_empty();
    if projection
        .constraints
        .scopes
        .contains(&ConstraintScope::TimeSensitive)
        && has_explicit_metric_objective
    {
        terms.push("latest measured data".to_string());
        terms.push("as-of observation".to_string());
    }
    if !projection.constraints.required_facets.is_empty() {
        let axes = projection
            .constraints
            .required_facets
            .iter()
            .copied()
            .map(metric_axis_search_phrase)
            .collect::<Vec<_>>()
            .join(", ");
        if !axes.is_empty() {
            terms.push(format!("{} values", axes));
        }
    }
    if projection.constraints.output_contract.requires_absolute_utc
        && projection.query_facets.goal.provenance_hits > 0
    {
        terms.push("UTC timestamp".to_string());
    }
    if projection.query_facets.grounded_external_required
        && projection_prefers_service_status_surfaces(projection)
    {
        terms.push("official status page".to_string());
        terms.push("service health dashboard".to_string());
        terms.push("incident update".to_string());
    }
    if projection
        .constraints
        .provenance_policy
        .min_independent_sources
        > 1
        && has_explicit_metric_objective
    {
        terms.push(format!(
            "{} independent sources",
            projection
                .constraints
                .provenance_policy
                .min_independent_sources
        ));
    }
    terms
}

pub(crate) fn projection_prefers_service_status_surfaces(
    projection: &QueryConstraintProjection,
) -> bool {
    let incident_tokens = [
        "incident",
        "incidents",
        "outage",
        "outages",
        "downtime",
        "availability",
        "degraded",
        "degradation",
    ];
    let status_tokens = ["status", "service", "health", "dashboard", "provider"];
    projection
        .query_tokens
        .iter()
        .any(|token| incident_tokens.contains(&token.as_str()))
        || (projection
            .query_tokens
            .iter()
            .any(|token| status_tokens.contains(&token.as_str()))
            && projection.query_facets.goal.external_hits > 0)
}

pub(crate) fn constraint_grounded_search_limit(query: &str, min_sources: u32) -> u32 {
    let projection = build_query_constraint_projection(query, min_sources, &[]);
    if !projection.has_constraint_objective() {
        return WEB_PIPELINE_SEARCH_LIMIT;
    }
    if !projection
        .constraints
        .scopes
        .contains(&ConstraintScope::TimeSensitive)
    {
        return WEB_PIPELINE_SEARCH_LIMIT;
    }

    let objective_floor = min_sources
        .max(1)
        .saturating_mul(WEB_PIPELINE_CONSTRAINT_SEARCH_LIMIT_MULTIPLIER);
    objective_floor.clamp(
        WEB_PIPELINE_CONSTRAINT_SEARCH_LIMIT_MIN,
        WEB_PIPELINE_CONSTRAINT_SEARCH_LIMIT_MAX,
    )
}

pub(crate) fn projection_probe_conflict_exclusion_terms(
    projection: &QueryConstraintProjection,
    candidate_hints: &[PendingSearchReadSummary],
) -> Vec<String> {
    if candidate_hints.is_empty() || !projection.enforce_grounded_compatibility() {
        return Vec::new();
    }

    let mut token_hits = BTreeMap::<String, usize>::new();
    for hint in candidate_hints {
        let compatibility = candidate_constraint_compatibility(
            &projection.constraints,
            &projection.query_facets,
            &projection.query_native_tokens,
            &projection.query_tokens,
            &projection.locality_tokens,
            projection.locality_scope.is_some(),
            &hint.url,
            hint.title.as_deref().unwrap_or_default(),
            &hint.excerpt,
        );
        if compatibility_passes_projection(projection, &compatibility) {
            continue;
        }

        let source_tokens = source_anchor_tokens(
            &hint.url,
            hint.title.as_deref().unwrap_or_default(),
            &hint.excerpt,
        );
        for token in source_tokens {
            if token.len() < QUERY_COMPATIBILITY_MIN_TOKEN_CHARS || is_query_stopword(&token) {
                continue;
            }
            if projection.query_tokens.contains(&token)
                || projection.query_native_tokens.contains(&token)
                || projection.locality_tokens.contains(&token)
            {
                continue;
            }
            *token_hits.entry(token).or_insert(0) += 1;
        }
    }

    let mut ranked_tokens = token_hits.into_iter().collect::<Vec<_>>();
    ranked_tokens.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
    ranked_tokens
        .into_iter()
        .filter(|(_, hits)| *hits >= QUERY_PROBE_ESCALATION_MIN_CONFLICT_HITS)
        .take(QUERY_PROBE_ESCALATION_MAX_CONFLICT_TERMS)
        .map(|(token, _)| format!("-{}", token))
        .collect()
}

pub(crate) fn projection_probe_host_exclusion_terms(
    query_contract: &str,
    projection: &QueryConstraintProjection,
    candidate_hints: &[PendingSearchReadSummary],
) -> Vec<String> {
    if candidate_hints.is_empty() {
        return Vec::new();
    }
    let time_sensitive_scope = projection
        .constraints
        .scopes
        .contains(&ConstraintScope::TimeSensitive);
    let host_exclusion_allowed =
        time_sensitive_scope || projection.enforce_grounded_compatibility();
    if !host_exclusion_allowed {
        return Vec::new();
    }

    fn collapsed_host_keys(host: &str) -> Vec<String> {
        let normalized = host.trim().trim_start_matches("www.").to_ascii_lowercase();
        if normalized.is_empty() {
            return Vec::new();
        }

        let mut out = BTreeSet::new();
        out.insert(normalized.clone());
        let labels = normalized.split('.').collect::<Vec<_>>();
        if labels.len() >= 2 {
            out.insert(format!(
                "{}.{}",
                labels[labels.len() - 2],
                labels[labels.len() - 1]
            ));
        }
        out.into_iter().collect()
    }

    let protected_host_keys = if retrieval_contract_requires_document_briefing_identifier_evidence(
        None,
        query_contract,
    ) {
        let mut protected = BTreeSet::new();
        for hint in candidate_hints {
            let title = hint.title.as_deref().unwrap_or_default();
            if !source_has_document_authority(query_contract, &hint.url, title, &hint.excerpt)
                || !source_has_briefing_standard_identifier_signal(
                    query_contract,
                    &hint.url,
                    title,
                    &hint.excerpt,
                )
            {
                continue;
            }
            if let Some(host) = source_host(&hint.url) {
                protected.extend(collapsed_host_keys(&host));
            }
        }
        protected
    } else {
        BTreeSet::new()
    };

    let mut bad_host_hits = BTreeMap::<String, usize>::new();
    let mut good_host_hits = BTreeMap::<String, usize>::new();
    for hint in candidate_hints {
        let title = hint.title.as_deref().unwrap_or_default();
        let Some(host) = source_host(&hint.url) else {
            continue;
        };
        if host.trim().is_empty() {
            continue;
        }
        let compatibility = candidate_constraint_compatibility(
            &projection.constraints,
            &projection.query_facets,
            &projection.query_native_tokens,
            &projection.query_tokens,
            &projection.locality_tokens,
            projection.locality_scope.is_some(),
            &hint.url,
            title,
            &hint.excerpt,
        );
        let payload_resolvable = !time_sensitive_scope
            || candidate_time_sensitive_resolvable_payload(&hint.url, title, &hint.excerpt);
        let compatible = compatibility_passes_projection(projection, &compatibility);
        let host_keys = collapsed_host_keys(&host);
        if compatible && payload_resolvable {
            for key in host_keys {
                *good_host_hits.entry(key).or_insert(0) += 1;
            }
            continue;
        }
        for key in host_keys {
            *bad_host_hits.entry(key).or_insert(0) += 1;
        }
    }

    let mut ranked_hosts = bad_host_hits
        .into_iter()
        .filter(|(host, hits)| {
            *hits >= QUERY_PROBE_ESCALATION_MIN_CONFLICT_HITS
                && !good_host_hits.contains_key(host)
                && !protected_host_keys.contains(host)
        })
        .collect::<Vec<_>>();
    ranked_hosts.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
    let mut selected_hosts = Vec::new();
    for (host, _) in ranked_hosts {
        if selected_hosts.iter().any(|selected: &String| {
            host == *selected
                || host.ends_with(&format!(".{selected}"))
                || selected.ends_with(&format!(".{host}"))
        }) {
            continue;
        }
        selected_hosts.push(host);
        if selected_hosts.len() >= QUERY_PROBE_ESCALATION_MAX_HOST_EXCLUSION_TERMS {
            break;
        }
    }
    selected_hosts
        .into_iter()
        .map(|host| format!("-site:{host}"))
        .collect()
}

#[cfg(test)]
mod probe_terms_tests {
    use super::*;

    #[test]
    fn probe_host_exclusions_preserve_discovered_authority_hosts_for_identifier_briefings() {
        let query =
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
        let projection = build_query_constraint_projection(query, 2, &[]);
        let candidate_hints = vec![
            PendingSearchReadSummary {
                url: "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards".to_string(),
                title: Some(
                    "NIST Releases First 3 Finalized Post-Quantum Encryption Standards"
                        .to_string(),
                ),
                excerpt:
                    "NIST finalized FIPS 203, FIPS 204, and FIPS 205 for post-quantum cryptography."
                        .to_string(),
            },
        ];

        let terms = projection_probe_host_exclusion_terms(query, &projection, &candidate_hints);

        assert!(
            !terms.iter().any(|term| term.eq_ignore_ascii_case("-site:nist.gov")),
            "terms={terms:?}"
        );
    }
}

pub(crate) fn projection_probe_structural_terms(
    projection: &QueryConstraintProjection,
) -> Vec<String> {
    let mut terms = Vec::new();
    if let Some(scope) = projection.locality_scope.as_ref() {
        terms.push(format!("\"{}\"", scope));
    }
    let facet_terms = projection
        .constraints
        .required_facets
        .iter()
        .copied()
        .map(metric_axis_search_phrase)
        .collect::<Vec<_>>();
    if !facet_terms.is_empty() {
        terms.push(format!("\"{} observed\"", facet_terms.join(" ")));
    }
    if projection
        .constraints
        .scopes
        .contains(&ConstraintScope::TimeSensitive)
    {
        terms.push("\"observed now\"".to_string());
    }
    if projection.query_facets.grounded_external_required
        && projection_prefers_service_status_surfaces(projection)
    {
        terms.push("\"official status page\"".to_string());
        terms.push("\"service health\"".to_string());
        terms.push("\"incident update\"".to_string());
    }
    terms
}

pub(crate) fn projection_probe_progressive_fallback_terms(
    projection: &QueryConstraintProjection,
) -> Vec<String> {
    let mut terms = Vec::new();
    if projection
        .constraints
        .scopes
        .contains(&ConstraintScope::TimeSensitive)
    {
        terms.push("\"latest update\"".to_string());
        terms.push("\"service advisory\"".to_string());
        terms.push("\"status dashboard\"".to_string());
        terms.push("\"incident report\"".to_string());
        terms.push("\"customer impact\"".to_string());
        terms.push("\"workaround\"".to_string());
    }
    if projection.query_facets.grounded_external_required
        && projection_prefers_service_status_surfaces(projection)
    {
        terms.push("\"official status page\"".to_string());
        terms.push("\"service health\"".to_string());
        terms.push("\"incident update\"".to_string());
        terms.push("\"statuspage\"".to_string());
    }
    terms.extend(projection_probe_structural_terms(projection));

    let mut deduped = Vec::new();
    let mut seen = BTreeSet::new();
    for term in terms {
        let key = term.trim().to_ascii_lowercase();
        if key.is_empty() || !seen.insert(key) {
            continue;
        }
        deduped.push(term);
    }
    deduped
}

pub(crate) fn append_unique_query_terms(base_query: &str, terms: &[String]) -> String {
    let mut appended = base_query.trim().to_string();
    let lower = base_query.to_ascii_lowercase();
    for term in terms {
        let trimmed = term.trim();
        if trimmed.is_empty() {
            continue;
        }
        if lower.contains(&trimmed.to_ascii_lowercase()) {
            continue;
        }
        if !appended.is_empty() {
            appended.push(' ');
        }
        appended.push_str(trimmed);
    }
    appended
}
