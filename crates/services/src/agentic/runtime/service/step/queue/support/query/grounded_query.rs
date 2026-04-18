use super::*;

fn briefing_identifier_search_terms(query_contract: &str, include_optional: bool) -> Vec<String> {
    briefing_standard_identifier_groups_for_query(query_contract)
        .iter()
        .filter(|group| group.required || include_optional)
        .filter_map(|group| group.needles.first())
        .map(|needle| format!("\"{}\"", needle.to_ascii_uppercase()))
        .collect()
}

fn should_expand_optional_briefing_identifier_terms(
    query_contract: &str,
    retrieval_contract: Option<&ioi_types::app::agentic::WebRetrievalContract>,
) -> bool {
    let facets = analyze_query_facets(query_contract);
    query_prefers_document_briefing_layout(query_contract)
        && !query_requests_comparison(query_contract)
        && facets.grounded_external_required
        && (retrieval_contract
            .map(|contract| contract.currentness_required)
            .unwrap_or(false)
            || facets.goal.recency_hits > 0)
}

fn inferred_briefing_identifier_probe_terms(
    query_contract: &str,
    candidate_hints: &[PendingSearchReadSummary],
) -> Vec<String> {
    if candidate_hints.is_empty() {
        return Vec::new();
    }

    let observations = candidate_hints
        .iter()
        .filter_map(|hint| {
            let trimmed = hint.url.trim();
            let title = hint.title.as_deref().unwrap_or_default();
            (!trimmed.is_empty()).then(|| BriefingIdentifierObservation {
                url: trimmed.to_string(),
                surface: preferred_source_briefing_identifier_surface(
                    query_contract,
                    &hint.url,
                    title,
                    &hint.excerpt,
                ),
                authoritative: source_has_document_authority(
                    query_contract,
                    trimmed,
                    title,
                    &hint.excerpt,
                ),
            })
        })
        .collect::<Vec<_>>();
    let mut labels = infer_briefing_required_identifier_labels(query_contract, &observations)
        .into_iter()
        .collect::<Vec<_>>();
    labels.sort();
    labels
        .into_iter()
        .take(3)
        .map(|label| format!("\"{}\"", label.to_ascii_uppercase()))
        .collect()
}

pub(crate) fn constraint_grounded_search_query_with_hints_and_locality_hint(
    query: &str,
    min_sources: u32,
    candidate_hints: &[PendingSearchReadSummary],
    locality_hint: Option<&str>,
) -> String {
    constraint_grounded_search_query_with_contract_and_hints_and_locality_hint(
        query,
        None,
        min_sources,
        candidate_hints,
        locality_hint,
    )
}

pub(crate) fn constraint_grounded_search_query_with_contract_and_hints_and_locality_hint(
    query: &str,
    retrieval_contract: Option<&ioi_types::app::agentic::WebRetrievalContract>,
    min_sources: u32,
    candidate_hints: &[PendingSearchReadSummary],
    locality_hint: Option<&str>,
) -> String {
    let resolved = resolved_query_contract_with_locality_hint(query, locality_hint);
    if resolved.trim().is_empty() {
        return String::new();
    }
    let local_business_discovery_query =
        local_business_discovery_query_contract(query, locality_hint);
    let local_business_entity_discovery_query =
        local_business_entity_discovery_query_contract(query, locality_hint);
    let local_business_entity_expansion = retrieval_contract
        .map(crate::agentic::web::contract_requires_geo_scoped_entity_expansion)
        .unwrap_or_else(|| query_requires_local_business_entity_diversity(&resolved));
    let grounded_query_basis = if local_business_entity_expansion {
        local_business_entity_discovery_query
            .trim()
            .is_empty()
            .then_some(local_business_discovery_query.as_str())
            .unwrap_or(local_business_entity_discovery_query.as_str())
    } else {
        resolved.as_str()
    };
    if retrieval_or_query_is_generic_headline_collection(retrieval_contract, &resolved) {
        return generic_headline_search_phrase(&resolved);
    }

    let base = semantic_retrieval_query_contract_with_contract_and_locality_hint(
        grounded_query_basis,
        retrieval_contract,
        locality_hint,
    );
    if base.trim().is_empty() {
        return String::new();
    }
    let projection = build_query_constraint_projection_with_locality_hint(
        query,
        min_sources,
        candidate_hints,
        locality_hint,
    );
    let mut constraint_terms = projection_constraint_search_terms(&projection);
    if projection.query_facets.grounded_external_required
        && projection.query_facets.service_status_lookup
    {
        for term in [
            "official status page",
            "service health dashboard",
            "incident update",
        ] {
            if !constraint_terms.iter().any(|existing| existing == term) {
                constraint_terms.push(term.to_string());
            }
        }
    }
    let bootstrap_without_hints = candidate_hints.is_empty();
    let authority_site_terms = if bootstrap_without_hints {
        query_document_authority_site_terms(&resolved, retrieval_contract, candidate_hints, false)
    } else {
        Vec::new()
    };
    constraint_terms.extend(briefing_identifier_search_terms(
        &resolved,
        should_expand_optional_briefing_identifier_terms(&resolved, retrieval_contract),
    ));
    if bootstrap_without_hints {
        constraint_terms.extend(authority_site_terms.clone());
    }
    if bootstrap_without_hints
        && retrieval_contract
            .map(crate::agentic::web::contract_requires_geo_scoped_entity_expansion)
            .unwrap_or(false)
    {
        return base;
    }
    if bootstrap_without_hints
        && retrieval_contract_prefers_single_fact_snapshot(retrieval_contract, &resolved)
    {
        return base;
    }
    let bootstrap_time_sensitive_locality_scope = bootstrap_without_hints
        && projection
            .constraints
            .scopes
            .contains(&ConstraintScope::TimeSensitive)
        && projection.locality_scope.is_some();
    if bootstrap_time_sensitive_locality_scope {
        return base;
    }
    let suppress_native_anchor_phrase = bootstrap_without_hints
        && projection.query_facets.grounded_external_required
        && !projection.query_facets.locality_sensitive_public_fact
        && (query_prefers_multi_item_cardinality(&resolved) || !authority_site_terms.is_empty());
    let native_anchor_phrase = if suppress_native_anchor_phrase {
        None
    } else {
        projection_native_anchor_phrase(&projection)
    };
    if projection.enforce_grounded_compatibility() {
        if let Some(anchor_phrase) = native_anchor_phrase.as_ref() {
            constraint_terms.push(anchor_phrase.clone());
        }
    }
    if projection.query_facets.grounded_external_required
        && !projection
            .constraints
            .scopes
            .contains(&ConstraintScope::TimeSensitive)
    {
        if let Some(scope) = projection.locality_scope.as_ref() {
            let scoped_phrase = format!("\"{}\"", scope);
            if !constraint_terms.iter().any(|term| term == &scoped_phrase) {
                constraint_terms.push(scoped_phrase);
            }
        }
    }
    let inferred_locality_grounding = projection.locality_scope_inferred
        && projection
            .constraints
            .scopes
            .contains(&ConstraintScope::TimeSensitive);
    if inferred_locality_grounding && !bootstrap_without_hints {
        for term in ["latest measured data", "as-of observation"] {
            if !constraint_terms.iter().any(|existing| existing == term) {
                constraint_terms.push(term.to_string());
            }
        }
        if let Some(scope) = projection.locality_scope.as_ref() {
            let scoped_phrase = format!("\"{}\"", scope);
            if !constraint_terms.iter().any(|term| term == &scoped_phrase) {
                constraint_terms.insert(0, scoped_phrase);
            }
        }
        if let Some(anchor_phrase) = projection_locality_semantic_anchor_phrase(&projection) {
            if !constraint_terms.iter().any(|term| term == &anchor_phrase) {
                constraint_terms.insert(0, anchor_phrase);
            }
        } else if let Some(anchor_phrase) = native_anchor_phrase {
            if !constraint_terms.iter().any(|term| term == &anchor_phrase) {
                constraint_terms.insert(0, anchor_phrase);
            }
        }
    }
    if constraint_terms.is_empty() {
        return base;
    }
    if inferred_locality_grounding && !bootstrap_without_hints {
        return append_unique_query_terms(&constraint_terms.join(" "), &[base]);
    }
    append_unique_query_terms(&base, &constraint_terms)
}

pub(crate) fn constraint_grounded_probe_query_with_hints_and_locality_hint(
    query: &str,
    min_sources: u32,
    candidate_hints: &[PendingSearchReadSummary],
    prior_query: &str,
    locality_hint: Option<&str>,
) -> Option<String> {
    constraint_grounded_probe_query_with_contract_and_hints_and_locality_hint(
        query,
        None,
        min_sources,
        candidate_hints,
        prior_query,
        locality_hint,
    )
}

pub(crate) fn constraint_grounded_probe_query_with_contract_and_hints_and_locality_hint(
    query: &str,
    retrieval_contract: Option<&ioi_types::app::agentic::WebRetrievalContract>,
    min_sources: u32,
    candidate_hints: &[PendingSearchReadSummary],
    prior_query: &str,
    locality_hint: Option<&str>,
) -> Option<String> {
    let grounded_query = constraint_grounded_search_query_with_contract_and_hints_and_locality_hint(
        query,
        retrieval_contract,
        min_sources,
        candidate_hints,
        locality_hint,
    );
    if grounded_query.trim().is_empty() {
        return None;
    }

    let prior_trimmed = prior_query.trim();
    let headline_collection_query =
        retrieval_or_query_is_generic_headline_collection(retrieval_contract, query);
    if headline_collection_query {
        return (prior_trimmed.is_empty() || !grounded_query.eq_ignore_ascii_case(prior_trimmed))
            .then_some(grounded_query);
    }
    let projection = build_query_constraint_projection_with_locality_hint(
        query,
        min_sources,
        candidate_hints,
        locality_hint,
    );
    let mut escalation_terms = projection_probe_structural_terms(&projection);
    escalation_terms.extend(projection_probe_locality_disambiguation_terms(
        &projection,
        candidate_hints,
    ));
    escalation_terms.extend(query_probe_document_authority_site_terms(
        query,
        retrieval_contract,
        candidate_hints,
    ));
    escalation_terms.extend(query_probe_grounded_authority_host_exclusion_terms(
        query,
        retrieval_contract,
        candidate_hints,
    ));
    escalation_terms.extend(inferred_briefing_identifier_probe_terms(
        query,
        candidate_hints,
    ));
    escalation_terms.extend(projection_probe_host_exclusion_terms(
        query,
        &projection,
        candidate_hints,
    ));
    let requires_locality_metric_escalation = projection
        .constraints
        .scopes
        .contains(&ConstraintScope::TimeSensitive)
        && projection.query_facets.locality_sensitive_public_fact;
    let metric_probe_terms = [
        QUERY_PROBE_LOCALITY_METRIC_ESCALATION_PHRASE.to_string(),
        metric_axis_search_phrase(MetricAxis::Temperature).to_string(),
        metric_axis_search_phrase(MetricAxis::Humidity).to_string(),
        metric_axis_search_phrase(MetricAxis::Wind).to_string(),
    ];
    if prior_trimmed.is_empty() || !grounded_query.eq_ignore_ascii_case(prior_trimmed) {
        let escalated_grounded_query =
            append_unique_query_terms(&grounded_query, &escalation_terms);
        if !escalated_grounded_query.trim().is_empty()
            && !escalated_grounded_query.eq_ignore_ascii_case(prior_trimmed)
            && !escalated_grounded_query.eq_ignore_ascii_case(&grounded_query)
        {
            return Some(if requires_locality_metric_escalation {
                append_unique_query_terms(&escalated_grounded_query, &metric_probe_terms)
            } else {
                escalated_grounded_query
            });
        }
        return Some(grounded_query);
    }
    let escalated_query = append_unique_query_terms(&grounded_query, &escalation_terms);
    if !escalated_query.trim().is_empty() && !escalated_query.eq_ignore_ascii_case(prior_trimmed) {
        let locality_escalated_query = if requires_locality_metric_escalation {
            append_unique_query_terms(&escalated_query, &metric_probe_terms)
        } else {
            escalated_query.clone()
        };
        if locality_escalated_query.trim().is_empty()
            || locality_escalated_query.eq_ignore_ascii_case(prior_trimmed)
        {
            Some(escalated_query)
        } else {
            Some(locality_escalated_query)
        }
    } else if requires_locality_metric_escalation {
        let fallback_query = append_unique_query_terms(&grounded_query, &metric_probe_terms);
        if fallback_query.trim().is_empty() || fallback_query.eq_ignore_ascii_case(prior_trimmed) {
            None
        } else {
            Some(fallback_query)
        }
    } else {
        for fallback_term in projection_probe_progressive_fallback_terms(&projection) {
            let fallback_query = append_unique_query_terms(&grounded_query, &[fallback_term]);
            if fallback_query.trim().is_empty()
                || fallback_query.eq_ignore_ascii_case(prior_trimmed)
            {
                continue;
            }
            return Some(fallback_query);
        }
        None
    }
}

pub(crate) fn constraint_grounded_probe_query_with_hints(
    query: &str,
    min_sources: u32,
    candidate_hints: &[PendingSearchReadSummary],
    prior_query: &str,
) -> Option<String> {
    constraint_grounded_probe_query_with_hints_and_locality_hint(
        query,
        min_sources,
        candidate_hints,
        prior_query,
        None,
    )
}

pub(crate) fn constraint_grounded_search_query_with_hints(
    query: &str,
    min_sources: u32,
    candidate_hints: &[PendingSearchReadSummary],
) -> String {
    constraint_grounded_search_query_with_hints_and_locality_hint(
        query,
        min_sources,
        candidate_hints,
        None,
    )
}

pub(crate) fn constraint_grounded_search_query(query: &str, min_sources: u32) -> String {
    constraint_grounded_search_query_with_hints(query, min_sources, &[])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grounded_search_query_does_not_inject_subject_specific_standard_identifiers() {
        let query =
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
        let contract =
            crate::agentic::web::derive_web_retrieval_contract(query, Some(query)).unwrap();

        let grounded = constraint_grounded_search_query_with_contract_and_hints_and_locality_hint(
            query,
            Some(&contract),
            2,
            &[],
            None,
        );

        assert!(!grounded.contains("\"FIPS 203\""), "query={grounded}");
        assert!(!grounded.contains("\"FIPS 204\""), "query={grounded}");
        assert!(!grounded.contains("\"FIPS 205\""), "query={grounded}");
        assert!(!grounded.contains("\"FIPS 206\""), "query={grounded}");
        assert!(!grounded.contains("\"HQC\""), "query={grounded}");
    }

    #[test]
    fn grounded_search_query_strips_document_briefing_output_scaffolding() {
        let query = "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing using current web and local memory evidence, then return a cited brief with findings, uncertainties, and next checks.";
        let contract =
            crate::agentic::web::derive_web_retrieval_contract(query, Some(query)).unwrap();

        let grounded = constraint_grounded_search_query_with_contract_and_hints_and_locality_hint(
            query,
            Some(&contract),
            2,
            &[],
            None,
        );
        let normalized = grounded.to_ascii_lowercase();

        assert!(
            normalized.contains("nist post quantum cryptography standards"),
            "query={grounded}"
        );
        assert!(!normalized.contains("local memory"), "query={grounded}");
        assert!(!normalized.contains("then return"), "query={grounded}");
        assert!(!normalized.contains("uncertainties"), "query={grounded}");
        assert!(!normalized.contains("next checks"), "query={grounded}");
    }

    #[test]
    fn grounded_search_query_uses_local_business_discovery_basis_for_menu_comparison_queries() {
        let query =
            "Find the three best-reviewed Italian restaurants in Anderson, SC and compare their menus.";
        let contract = crate::agentic::web::derive_web_retrieval_contract(query, Some(query))
            .expect("contract");

        let grounded = constraint_grounded_search_query_with_contract_and_hints_and_locality_hint(
            query,
            Some(&contract),
            3,
            &[],
            Some("Anderson, SC"),
        );
        let normalized = grounded.to_ascii_lowercase();

        assert!(
            normalized.contains("italian restaurants in anderson")
                || normalized.contains("restaurants in anderson"),
            "query={grounded}"
        );
        assert!(!normalized.contains("compare"), "query={grounded}");
        assert!(!normalized.contains("menus"), "query={grounded}");
    }

    #[test]
    fn grounded_probe_query_adds_public_authority_site_for_document_briefing_recovery() {
        let query =
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
        let contract = crate::agentic::web::derive_web_retrieval_contract(query, Some(query))
            .expect("contract");
        let hints = vec![
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
        let grounded = constraint_grounded_search_query_with_contract_and_hints_and_locality_hint(
            query,
            Some(&contract),
            2,
            &hints,
            None,
        );

        let probe = constraint_grounded_probe_query_with_contract_and_hints_and_locality_hint(
            query,
            Some(&contract),
            2,
            &hints,
            &grounded,
            None,
        )
        .expect("probe query should be generated");

        assert!(
            probe.to_ascii_lowercase().contains("site:nist.gov"),
            "probe={probe}"
        );
        assert!(
            probe.to_ascii_lowercase().contains("site:www.nist.gov"),
            "probe={probe}"
        );
    }

    #[test]
    fn grounded_probe_query_does_not_blacklist_public_authority_recovery_host() {
        let query =
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
        let contract = crate::agentic::web::derive_web_retrieval_contract(query, Some(query))
            .expect("contract");
        let hints = vec![
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
        let initial_query =
            constraint_grounded_search_query_with_contract_and_hints_and_locality_hint(
                query,
                Some(&contract),
                2,
                &[],
                None,
            );

        let probe = constraint_grounded_probe_query_with_contract_and_hints_and_locality_hint(
            query,
            Some(&contract),
            2,
            &hints,
            &initial_query,
            None,
        )
        .expect("probe query should be generated");

        assert!(
            !probe.to_ascii_lowercase().contains("-site:nist.gov"),
            "probe={probe}"
        );
    }

    #[test]
    fn grounded_probe_query_pivots_to_corroboration_after_authority_slot_is_satisfied() {
        let query =
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
        let contract = crate::agentic::web::derive_web_retrieval_contract(query, Some(query))
            .expect("contract");
        let hints = vec![
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
        let grounded = constraint_grounded_search_query_with_contract_and_hints_and_locality_hint(
            query,
            Some(&contract),
            2,
            &hints,
            None,
        );

        let probe = constraint_grounded_probe_query_with_contract_and_hints_and_locality_hint(
            query,
            Some(&contract),
            2,
            &hints,
            &grounded,
            None,
        )
        .expect("probe query should be generated");

        assert!(
            probe
                .split_whitespace()
                .any(|term| term.eq_ignore_ascii_case("-site:csrc.nist.gov")),
            "probe={probe}"
        );
        assert!(
            !probe
                .split_whitespace()
                .any(|term| term.eq_ignore_ascii_case("-site:nist.gov")),
            "probe={probe}"
        );
        assert!(
            !probe
                .split_whitespace()
                .any(|term| term.eq_ignore_ascii_case("site:nist.gov")),
            "probe={probe}"
        );
    }

    #[test]
    fn grounded_probe_query_adds_identifier_terms_from_authority_backed_hints() {
        let query =
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
        let contract = crate::agentic::web::derive_web_retrieval_contract(query, Some(query))
            .expect("contract");
        let hints = vec![PendingSearchReadSummary {
            url: "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards".to_string(),
            title: Some(
                "NIST Releases First 3 Finalized Post-Quantum Encryption Standards"
                    .to_string(),
            ),
            excerpt:
                "NIST finalized FIPS 203, FIPS 204, and FIPS 205 as the first post-quantum standards."
                    .to_string(),
        }];
        let grounded = constraint_grounded_search_query_with_contract_and_hints_and_locality_hint(
            query,
            Some(&contract),
            2,
            &hints,
            None,
        );

        let probe = constraint_grounded_probe_query_with_contract_and_hints_and_locality_hint(
            query,
            Some(&contract),
            2,
            &hints,
            &grounded,
            None,
        )
        .expect("probe query should be generated");

        assert!(probe.contains("\"FIPS 203\""), "probe={probe}");
        assert!(probe.contains("\"FIPS 204\""), "probe={probe}");
        assert!(probe.contains("\"FIPS 205\""), "probe={probe}");
    }

    #[test]
    fn grounded_probe_query_pivots_away_from_path_scoped_authority_site_once_authority_slot_is_satisfied(
    ) {
        let query =
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
        let contract = crate::agentic::web::derive_web_retrieval_contract(query, Some(query))
            .expect("contract");
        let hints = vec![PendingSearchReadSummary {
            url: "https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string(),
            title: Some(
                "IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC"
                    .to_string(),
            ),
            excerpt:
                "NIST IR 8413 Update 1 references the finalized post-quantum cryptography standards."
                    .to_string(),
        }];
        let grounded = constraint_grounded_search_query_with_contract_and_hints_and_locality_hint(
            query,
            Some(&contract),
            2,
            &hints,
            None,
        );

        let probe = constraint_grounded_probe_query_with_contract_and_hints_and_locality_hint(
            query,
            Some(&contract),
            2,
            &hints,
            &grounded,
            None,
        )
        .expect("probe query should be generated");

        assert!(
            probe
                .split_whitespace()
                .any(|term| term.eq_ignore_ascii_case("-site:csrc.nist.gov")),
            "probe={probe}"
        );
        assert!(
            !probe
                .split_whitespace()
                .any(|term| term.eq_ignore_ascii_case("site:csrc.nist.gov/pubs")),
            "probe={probe}"
        );
    }

    #[test]
    fn grounded_probe_query_omits_legacy_excerpt_fips_reference_for_ir_publication() {
        let query =
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
        let contract = crate::agentic::web::derive_web_retrieval_contract(query, Some(query))
            .expect("contract");
        let hints = vec![PendingSearchReadSummary {
            url: "https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string(),
            title: Some(
                "IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC"
                    .to_string(),
            ),
            excerpt:
                "IR 8413 Update 1 notes that the new public-key standards will augment Federal Information Processing Standard (FIPS) 186-4."
                    .to_string(),
        }];
        let grounded = constraint_grounded_search_query_with_contract_and_hints_and_locality_hint(
            query,
            Some(&contract),
            2,
            &hints,
            None,
        );

        let probe = constraint_grounded_probe_query_with_contract_and_hints_and_locality_hint(
            query,
            Some(&contract),
            2,
            &hints,
            &grounded,
            None,
        )
        .expect("probe query should be generated");

        assert!(!probe.contains("\"FIPS 186\""), "probe={probe}");
        assert!(
            probe
                .split_whitespace()
                .any(|term| term.eq_ignore_ascii_case("-site:csrc.nist.gov")),
            "probe={probe}"
        );
    }

    #[test]
    fn grounded_search_query_bootstraps_public_authority_site_for_document_briefings() {
        let query =
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
        let contract = crate::agentic::web::derive_web_retrieval_contract(query, Some(query))
            .expect("contract");

        let grounded = constraint_grounded_search_query_with_contract_and_hints_and_locality_hint(
            query,
            Some(&contract),
            2,
            &[],
            None,
        );

        assert!(
            grounded.to_ascii_lowercase().contains("site:nist.gov"),
            "grounded={grounded}"
        );
        assert!(
            grounded.to_ascii_lowercase().contains("site:www.nist.gov"),
            "grounded={grounded}"
        );
        assert!(
            !grounded
                .to_ascii_lowercase()
                .contains("\"nist post quantum cryptography\""),
            "grounded={grounded}"
        );
        assert!(
            !grounded.to_ascii_lowercase().contains("web utc timestamp"),
            "grounded={grounded}"
        );
        assert!(
            !grounded.to_ascii_lowercase().contains("utc timestamp"),
            "grounded={grounded}"
        );
    }
}
