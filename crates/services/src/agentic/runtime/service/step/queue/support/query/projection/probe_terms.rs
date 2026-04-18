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
        && has_explicit_metric_objective
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
    if projection.query_facets.service_status_lookup {
        return true;
    }
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
    if query_is_generic_headline_collection(query_contract)
        || (prefers_single_fact_snapshot(query_contract)
            && projection.query_facets.locality_sensitive_public_fact)
        || projection_prefers_service_status_surfaces(projection)
    {
        return Vec::new();
    }
    let time_sensitive_scope = projection
        .constraints
        .scopes
        .contains(&ConstraintScope::TimeSensitive);
    let host_exclusion_allowed =
        projection.enforce_grounded_compatibility() || time_sensitive_scope;
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

    let protect_document_briefing_authority_hosts =
        query_prefers_document_briefing_layout(query_contract)
            && !query_requests_comparison(query_contract)
            && analyze_query_facets(query_contract).grounded_external_required;
    let protected_host_keys = if protect_document_briefing_authority_hosts {
        let mut protected = BTreeSet::new();
        for hint in candidate_hints {
            let title = hint.title.as_deref().unwrap_or_default();
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
            let grounded_authority_host =
                source_has_document_authority(query_contract, &hint.url, title, &hint.excerpt)
                    && (source_has_briefing_standard_identifier_signal(
                        query_contract,
                        &hint.url,
                        title,
                        &hint.excerpt,
                    ) || compatibility_passes_projection(projection, &compatibility)
                        || compatibility.compatibility_score > 0);
            if !grounded_authority_host {
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

pub(crate) fn projection_probe_locality_disambiguation_terms(
    projection: &QueryConstraintProjection,
    candidate_hints: &[PendingSearchReadSummary],
) -> Vec<String> {
    if candidate_hints.is_empty()
        || !projection
            .constraints
            .scopes
            .contains(&ConstraintScope::TimeSensitive)
        || !projection.query_facets.locality_sensitive_public_fact
        || projection.locality_scope.is_none()
    {
        return Vec::new();
    }

    for hint in candidate_hints {
        let title = hint.title.as_deref().unwrap_or_default();
        if !candidate_time_sensitive_resolvable_payload(&hint.url, title, &hint.excerpt) {
            continue;
        }

        let locality_tokens = source_structural_locality_tokens(&hint.url, title)
            .into_iter()
            .filter(|token| token.len() >= QUERY_COMPATIBILITY_MIN_TOKEN_CHARS)
            .filter(|token| !is_query_stopword(token))
            .filter(|token| !is_locality_scope_noise_token(token))
            .filter(|token| !projection.locality_tokens.contains(token))
            .filter(|token| !projection.query_tokens.contains(token))
            .filter(|token| !projection.query_native_tokens.contains(token))
            .take(2)
            .collect::<Vec<_>>();
        if locality_tokens.len() >= 2 {
            return vec![format!("\"{}\"", locality_tokens.join(" "))];
        }
        if let Some(token) = locality_tokens.first() {
            return vec![format!("\"{token}\"")];
        }
    }

    Vec::new()
}

const QUERY_PROBE_AUTHORITY_SITE_MIN_TOKEN_LEN: usize = 4;
const QUERY_PROBE_AUTHORITY_SITE_MAX_TOKEN_LEN: usize = 8;
const QUERY_PROBE_AUTHORITY_SITE_EXCLUSIONS: &[&str] = &["http", "https"];

fn authority_query_site_term_variants(token: &str) -> Vec<String> {
    let normalized = token.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return Vec::new();
    }

    let mut terms = vec![format!("site:{normalized}.gov")];
    if !normalized.starts_with("www.") {
        terms.push(format!("site:www.{normalized}.gov"));
    }
    terms
}

fn observed_authority_site_term_variants(url: &str) -> Vec<String> {
    let Ok(parsed) = Url::parse(url.trim()) else {
        return Vec::new();
    };
    let Some(host) = parsed.host_str() else {
        return Vec::new();
    };
    let normalized = host
        .strip_prefix("www.")
        .unwrap_or(host)
        .to_ascii_lowercase();
    let mut sites = BTreeSet::new();
    if normalized.ends_with(".gov") {
        sites.insert(format!("site:{normalized}"));
        if let Some((_, suffix)) = normalized.split_once('.') {
            if suffix.ends_with(".gov") {
                sites.insert(format!("site:{suffix}"));
            }
        }
    }

    let path = parsed.path().to_ascii_lowercase();
    if path.contains("/pubs/") {
        sites.insert(format!("site:{normalized}/pubs"));
    }
    if path.contains("/publications/") {
        sites.insert(format!("site:{normalized}/publications"));
    }
    if path.contains("/standards/") {
        sites.insert(format!("site:{normalized}/standards"));
    }

    sites.into_iter().collect()
}

pub(crate) fn query_probe_document_authority_site_terms(
    query_contract: &str,
    retrieval_contract: Option<&ioi_types::app::agentic::WebRetrievalContract>,
    candidate_hints: &[PendingSearchReadSummary],
) -> Vec<String> {
    query_document_authority_site_terms(query_contract, retrieval_contract, candidate_hints, true)
}

pub(crate) fn query_probe_grounded_authority_host_exclusion_terms(
    query_contract: &str,
    retrieval_contract: Option<&ioi_types::app::agentic::WebRetrievalContract>,
    candidate_hints: &[PendingSearchReadSummary],
) -> Vec<String> {
    fn observed_domain_key(url: &str) -> Option<String> {
        let host = source_host(url)?;
        let normalized = host.trim().trim_start_matches("www.").to_ascii_lowercase();
        if normalized.is_empty() {
            return None;
        }
        let labels = normalized.split('.').collect::<Vec<_>>();
        if labels.len() >= 2 {
            Some(format!(
                "{}.{}",
                labels[labels.len() - 2],
                labels[labels.len() - 1]
            ))
        } else {
            Some(normalized)
        }
    }

    let authority_recovery_applicable = query_prefers_document_briefing_layout(query_contract)
        && !query_requests_comparison(query_contract)
        && analyze_query_facets(query_contract).grounded_external_required
        && retrieval_contract
            .map(|contract| contract.currentness_required || contract.source_independence_min > 1)
            .unwrap_or(false);
    if !authority_recovery_applicable || candidate_hints.is_empty() {
        return Vec::new();
    }

    let expected_count =
        retrieval_contract_required_citations_per_story(retrieval_contract, query_contract).max(1);
    let required_domain_floor =
        retrieval_contract_required_distinct_domain_floor(retrieval_contract, query_contract)
            .min(expected_count);
    if required_domain_floor <= 1 {
        return Vec::new();
    }

    let required_authority_floor = retrieval_contract_primary_authority_source_slot_cap(
        retrieval_contract,
        query_contract,
        expected_count,
    );
    if required_authority_floor == 0 {
        return Vec::new();
    }

    let semantic_tokens = query_semantic_anchor_tokens(query_contract);
    let identifier_floor_required = briefing_standard_identifier_group_floor(query_contract) > 0
        || semantic_tokens.contains("standard")
        || semantic_tokens.contains("standards");
    let mut observed_domains = BTreeSet::new();
    let mut authority_source_count = 0usize;
    let mut authority_identifier_sources = 0usize;
    let mut authority_hosts = BTreeSet::new();

    for hint in candidate_hints {
        let title = hint.title.as_deref().unwrap_or_default();
        if let Some(domain) = observed_domain_key(&hint.url) {
            observed_domains.insert(domain);
        }
        if !source_has_grounded_primary_authority(query_contract, &hint.url, title, &hint.excerpt) {
            continue;
        }
        authority_source_count = authority_source_count.saturating_add(1);
        if source_has_briefing_standard_identifier_signal(
            query_contract,
            &hint.url,
            title,
            &hint.excerpt,
        ) {
            authority_identifier_sources = authority_identifier_sources.saturating_add(1);
        }
        if let Some(host) = source_host(&hint.url) {
            let normalized = host.trim().trim_start_matches("www.").to_ascii_lowercase();
            if !normalized.is_empty() {
                // Only suppress the exact authority host we already exhausted.
                // Do not widen the exclusion to the registrable authority domain
                // (for example `nist.gov`), because document briefings often need
                // corroboration from a sibling public host such as `www.nist.gov`
                // after reading an initial `csrc.nist.gov` authority page.
                authority_hosts.insert(normalized);
            }
        }
    }

    let authority_floor_satisfied = authority_source_count >= required_authority_floor
        && (!identifier_floor_required || authority_identifier_sources > 0);
    if !authority_floor_satisfied || observed_domains.len() >= required_domain_floor {
        return Vec::new();
    }

    authority_hosts
        .into_iter()
        .take(3)
        .map(|host| format!("-site:{host}"))
        .collect()
}

pub(crate) fn query_document_authority_site_terms(
    query_contract: &str,
    retrieval_contract: Option<&ioi_types::app::agentic::WebRetrievalContract>,
    candidate_hints: &[PendingSearchReadSummary],
    require_surface_hit: bool,
) -> Vec<String> {
    let authority_recovery_applicable = query_prefers_document_briefing_layout(query_contract)
        && !query_requests_comparison(query_contract)
        && analyze_query_facets(query_contract).grounded_external_required
        && retrieval_contract
            .map(|contract| contract.currentness_required || contract.source_independence_min > 1)
            .unwrap_or(false);
    if !authority_recovery_applicable {
        return Vec::new();
    }

    let expected_count =
        retrieval_contract_required_citations_per_story(retrieval_contract, query_contract).max(1);
    let required_authority_floor = retrieval_contract_primary_authority_source_slot_cap(
        retrieval_contract,
        query_contract,
        expected_count,
    );
    let semantic_tokens = query_semantic_anchor_tokens(query_contract);
    let mut authority_source_count = 0usize;
    let mut authority_identifier_sources = 0usize;
    for hint in candidate_hints {
        let title = hint.title.as_deref().unwrap_or_default();
        if !source_has_grounded_primary_authority(query_contract, &hint.url, title, &hint.excerpt) {
            continue;
        }
        authority_source_count = authority_source_count.saturating_add(1);
        if source_has_briefing_standard_identifier_signal(
            query_contract,
            &hint.url,
            title,
            &hint.excerpt,
        ) {
            authority_identifier_sources = authority_identifier_sources.saturating_add(1);
        }
    }
    let identifier_floor_required = briefing_standard_identifier_group_floor(query_contract) > 0
        || semantic_tokens.contains("standard")
        || semantic_tokens.contains("standards");
    let authority_floor_satisfied = authority_source_count >= required_authority_floor
        && (!identifier_floor_required || authority_identifier_sources > 0);
    if authority_floor_satisfied {
        return Vec::new();
    }

    let query_authority_tokens = query_contract
        .split_whitespace()
        .filter_map(|token| {
            let trimmed = token.trim_matches(|ch: char| !ch.is_ascii_alphabetic());
            if trimmed.len() < QUERY_PROBE_AUTHORITY_SITE_MIN_TOKEN_LEN
                || trimmed.len() > QUERY_PROBE_AUTHORITY_SITE_MAX_TOKEN_LEN
            {
                return None;
            }
            if !trimmed.chars().all(|ch| ch.is_ascii_uppercase()) {
                return None;
            }
            let normalized = trimmed.to_ascii_lowercase();
            if !semantic_tokens.contains(&normalized)
                || QUERY_PROBE_AUTHORITY_SITE_EXCLUSIONS.contains(&normalized.as_str())
            {
                return None;
            }
            Some(normalized)
        })
        .collect::<BTreeSet<_>>();
    let observed_authority_site_terms = candidate_hints
        .iter()
        .flat_map(|hint| observed_authority_site_term_variants(&hint.url))
        .collect::<BTreeSet<_>>();
    if query_authority_tokens.is_empty() {
        return observed_authority_site_terms.into_iter().take(5).collect();
    }

    if !require_surface_hit {
        let token_sites = query_authority_tokens
            .into_iter()
            .take(2)
            .flat_map(|token| authority_query_site_term_variants(&token))
            .collect::<Vec<_>>();
        return observed_authority_site_terms
            .into_iter()
            .chain(token_sites)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .take(5)
            .collect();
    }

    if candidate_hints.is_empty() {
        return Vec::new();
    }

    let surface_tokens = candidate_hints
        .iter()
        .flat_map(|hint| {
            format!(
                "{} {} {}",
                hint.url,
                hint.title.as_deref().unwrap_or_default(),
                hint.excerpt
            )
            .to_ascii_lowercase()
            .chars()
            .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { ' ' })
            .collect::<String>()
            .split_whitespace()
            .map(str::to_string)
            .collect::<Vec<_>>()
        })
        .collect::<BTreeSet<_>>();

    observed_authority_site_terms
        .into_iter()
        .chain(
            query_authority_tokens
                .into_iter()
                .filter(|token| surface_tokens.contains(token))
                .take(2)
                .flat_map(|token| authority_query_site_term_variants(&token)),
        )
        .collect::<BTreeSet<_>>()
        .into_iter()
        .take(5)
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
            !terms
                .iter()
                .any(|term| term.eq_ignore_ascii_case("-site:nist.gov")),
            "terms={terms:?}"
        );
    }

    #[test]
    fn probe_host_exclusions_preserve_grounded_public_authority_hosts_for_document_briefings() {
        let query =
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
        let projection = build_query_constraint_projection(query, 2, &[]);
        let candidate_hints = vec![
            PendingSearchReadSummary {
                url: "https://csrc.nist.gov/Projects/post-quantum-cryptography/workshops-and-timeline".to_string(),
                title: Some("Post-Quantum Cryptography Workshops and Timeline | CSRC".to_string()),
                excerpt:
                    "NIST post-quantum cryptography workshops and timeline for standards development."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://www.nccoe.nist.gov/sites/default/files/2023-12/pqc-migration-nist-sp-1800-38c-preliminary-draft.pdf".to_string(),
                title: Some(
                    "Migration to Post-Quantum Cryptography Quantum Read-iness: Testing Draft Standards - National Institute of Standards and Technology (.gov)"
                        .to_string(),
                ),
                excerpt:
                    "Testing draft standards for migration to post-quantum cryptography."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://www.ibm.com/es-es/think/insights/nist-cybersecurity-framework-2"
                    .to_string(),
                title: Some(
                    "El marco de ciberseguridad 2.0 del NIST, en detalle | IBM".to_string(),
                ),
                excerpt:
                    "IBM overview of the NIST cybersecurity framework and related standards."
                        .to_string(),
            },
        ];

        let terms = projection_probe_host_exclusion_terms(query, &projection, &candidate_hints);

        assert!(
            !terms
                .iter()
                .any(|term| term.eq_ignore_ascii_case("-site:nist.gov")),
            "terms={terms:?}"
        );
    }

    #[test]
    fn document_briefing_probe_terms_add_public_authority_site_when_only_secondary_hints_exist() {
        let query =
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
        let retrieval_contract =
            crate::agentic::web::derive_web_retrieval_contract(query, Some(query))
                .expect("contract");
        let candidate_hints = vec![
            PendingSearchReadSummary {
                url: "https://www.ibm.com/think/topics/nist".to_string(),
                title: Some("What is the NIST Cybersecurity Framework? | IBM".to_string()),
                excerpt: "IBM overview of NIST cybersecurity frameworks and standards.".to_string(),
            },
            PendingSearchReadSummary {
                url: "https://www.ibm.com/es-es/think/insights/nist-cybersecurity-framework-2"
                    .to_string(),
                title: Some(
                    "El marco de ciberseguridad 2.0 del NIST, en detalle | IBM".to_string(),
                ),
                excerpt: "IBM details NIST topics without an official NIST host.".to_string(),
            },
        ];

        let terms = query_probe_document_authority_site_terms(
            query,
            Some(&retrieval_contract),
            &candidate_hints,
        );

        assert!(
            terms
                .iter()
                .any(|term| term.eq_ignore_ascii_case("site:nist.gov")),
            "terms={terms:?}"
        );
        assert!(
            terms
                .iter()
                .any(|term| term.eq_ignore_ascii_case("site:www.nist.gov")),
            "terms={terms:?}"
        );
    }

    #[test]
    fn document_briefing_probe_terms_skip_public_authority_site_when_authority_slot_is_satisfied() {
        let query =
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
        let retrieval_contract =
            crate::agentic::web::derive_web_retrieval_contract(query, Some(query))
                .expect("contract");
        let candidate_hints = vec![
            PendingSearchReadSummary {
                url: "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards".to_string(),
                title: Some(
                    "NIST Releases First 3 Finalized Post-Quantum Encryption Standards"
                        .to_string(),
                ),
                excerpt:
                    "NIST finalized FIPS 203, FIPS 204, and FIPS 205 as the first post-quantum standards."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://research.ibm.com/blog/nist-pqc-standards".to_string(),
                title: Some(
                    "NIST’s post-quantum cryptography standards are here - IBM Research"
                        .to_string(),
                ),
                excerpt:
                    "IBM summarized FIPS 203, FIPS 204, and FIPS 205 after NIST released the standards."
                        .to_string(),
            },
        ];

        let terms = query_probe_document_authority_site_terms(
            query,
            Some(&retrieval_contract),
            &candidate_hints,
        );

        assert!(terms.is_empty(), "terms={terms:?}");
    }

    #[test]
    fn document_briefing_probe_terms_keep_authority_site_expansion_when_floor_is_still_unmet() {
        let query =
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
        let retrieval_contract =
            crate::agentic::web::derive_web_retrieval_contract(query, Some(query))
                .expect("contract");
        let candidate_hints = vec![PendingSearchReadSummary {
            url: "https://www.nccoe.nist.gov/sites/default/files/2023-12/pqc-migration-nist-sp-1800-38c-preliminary-draft.pdf".to_string(),
            title: Some(
                "Migration to Post-Quantum Cryptography Quantum Read-iness: Testing Draft Standards - National Institute of Standards and Technology (.gov)"
                    .to_string(),
            ),
            excerpt:
                "Testing draft standards for migration to post-quantum cryptography without the finalized FIPS identifiers yet."
                    .to_string(),
        }];

        let terms = query_probe_document_authority_site_terms(
            query,
            Some(&retrieval_contract),
            &candidate_hints,
        );

        assert!(
            terms
                .iter()
                .any(|term| term.eq_ignore_ascii_case("site:nist.gov")),
            "terms={terms:?}"
        );
        assert!(
            terms
                .iter()
                .any(|term| term.eq_ignore_ascii_case("site:www.nist.gov")),
            "terms={terms:?}"
        );
        assert!(
            terms
                .iter()
                .any(|term| term.eq_ignore_ascii_case("site:nccoe.nist.gov")),
            "terms={terms:?}"
        );
    }

    #[test]
    fn document_briefing_probe_terms_skip_publication_path_scope_once_grounded_authority_is_present(
    ) {
        let query =
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
        let retrieval_contract =
            crate::agentic::web::derive_web_retrieval_contract(query, Some(query))
                .expect("contract");
        let candidate_hints = vec![PendingSearchReadSummary {
            url: "https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string(),
            title: Some(
                "IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC"
                    .to_string(),
            ),
            excerpt:
                "NIST IR 8413 summarizes the post-quantum cryptography standardization process."
                    .to_string(),
        }];

        let terms = query_probe_document_authority_site_terms(
            query,
            Some(&retrieval_contract),
            &candidate_hints,
        );

        assert!(terms.is_empty(), "terms={terms:?}");
    }

    #[test]
    fn document_briefing_probe_terms_skip_publication_path_scope_without_uppercase_authority_token_once_grounded_authority_is_present(
    ) {
        let query =
            "research the latest nist post-quantum cryptography standards and write me a one-page briefing.";
        let retrieval_contract =
            crate::agentic::web::derive_web_retrieval_contract(query, Some(query))
                .expect("contract");
        let candidate_hints = vec![PendingSearchReadSummary {
            url: "https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string(),
            title: Some(
                "IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC"
                    .to_string(),
            ),
            excerpt:
                "NIST IR 8413 summarizes the post-quantum cryptography standardization process."
                    .to_string(),
        }];

        let terms = query_probe_document_authority_site_terms(
            query,
            Some(&retrieval_contract),
            &candidate_hints,
        );

        assert!(terms.is_empty(), "terms={terms:?}");
    }

    #[test]
    fn document_briefing_probe_terms_exclude_grounded_authority_hosts_when_domain_diversity_is_unmet(
    ) {
        let query =
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
        let retrieval_contract =
            crate::agentic::web::derive_web_retrieval_contract(query, Some(query))
                .expect("contract");
        let candidate_hints = vec![
            PendingSearchReadSummary {
                url: "https://csrc.nist.gov/News/2024/postquantum-cryptography-fips-approved"
                    .to_string(),
                title: Some("Post-Quantum Cryptography FIPS Approved | CSRC".to_string()),
                excerpt:
                    "FIPS 203, FIPS 204, and FIPS 205 are approved post-quantum cryptography standards."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string(),
                title: Some(
                    "IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC"
                        .to_string(),
                ),
                excerpt:
                    "IR 8413 documents the NIST post-quantum cryptography standardization process."
                        .to_string(),
            },
        ];

        let terms = query_probe_grounded_authority_host_exclusion_terms(
            query,
            Some(&retrieval_contract),
            &candidate_hints,
        );

        assert!(
            terms
                .iter()
                .any(|term| term.eq_ignore_ascii_case("-site:csrc.nist.gov")),
            "terms={terms:?}"
        );
        assert!(
            !terms
                .iter()
                .any(|term| term.eq_ignore_ascii_case("-site:nist.gov")),
            "terms={terms:?}"
        );
        assert!(
            !terms
                .iter()
                .any(|term| term.eq_ignore_ascii_case("-site:gov")),
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
