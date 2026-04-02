#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct SelectedSourceQualityObservation {
    pub(crate) total_sources: usize,
    pub(crate) compatible_sources: usize,
    pub(crate) locality_compatible_sources: usize,
    pub(crate) distinct_domains: usize,
    pub(crate) low_priority_sources: usize,
    pub(crate) quality_floor_met: bool,
    pub(crate) low_priority_urls: Vec<String>,
    pub(crate) entity_anchor_required: bool,
    pub(crate) entity_anchor_compatible_sources: usize,
    pub(crate) entity_anchor_floor_met: bool,
    pub(crate) entity_anchor_source_urls: Vec<String>,
    pub(crate) entity_anchor_mismatched_urls: Vec<String>,
    pub(crate) identifier_evidence_required: bool,
    pub(crate) identifier_bearing_sources: usize,
    pub(crate) authority_identifier_sources: usize,
    pub(crate) required_identifier_label_coverage: usize,
    pub(crate) optional_identifier_label_coverage: usize,
    pub(crate) required_identifier_group_floor: usize,
    pub(crate) identifier_coverage_floor_met: bool,
    pub(crate) missing_identifier_urls: Vec<String>,
}

pub(crate) fn selected_source_quality_observation_with_contract_and_locality_hint(
    retrieval_contract: Option<&WebRetrievalContract>,
    query_contract: &str,
    min_sources: u32,
    selected_urls: &[String],
    source_hints: &[PendingSearchReadSummary],
    locality_hint: Option<&str>,
) -> SelectedSourceQualityObservation {
    let projection = build_query_constraint_projection_with_locality_hint(
        query_contract,
        min_sources.max(1),
        source_hints,
        locality_hint,
    );
    let headline_lookup_mode =
        retrieval_contract_is_generic_headline_collection(retrieval_contract, query_contract);
    let required_source_count = min_sources.max(1) as usize;
    let briefing_identifier_observations = source_hints
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
    let required_identifier_labels = infer_briefing_required_identifier_labels(
        query_contract,
        &briefing_identifier_observations,
    );
    let required_identifier_group_floor = required_identifier_labels.len();
    let optional_identifier_labels = BTreeSet::<String>::new();
    let identifier_evidence_required = !required_identifier_labels.is_empty()
        && retrieval_contract
            .is_some_and(|_| query_prefers_document_briefing_layout(query_contract));
    let local_business_entity_selection_flow =
        query_requires_local_business_entity_diversity(query_contract);
    let local_business_menu_surface_required = query_requires_local_business_menu_surface(
        query_contract,
        retrieval_contract,
        locality_hint,
    );
    let entity_anchor_required = !local_business_search_entity_anchor_tokens_with_contract(
        query_contract,
        retrieval_contract,
        locality_hint,
    )
    .is_empty();
    let mut total_sources = 0usize;
    let mut compatible_sources = 0usize;
    let mut locality_compatible_sources = 0usize;
    let mut low_priority_sources = 0usize;
    let mut distinct_domains = BTreeSet::new();
    let mut low_priority_urls = Vec::new();
    let mut entity_anchor_compatible_sources = 0usize;
    let mut entity_anchor_source_urls = Vec::new();
    let mut entity_anchor_mismatched_urls = Vec::new();
    let mut seen_urls = BTreeSet::new();
    let mut identifier_bearing_sources = 0usize;
    let mut authority_identifier_sources = 0usize;
    let mut authoritative_source_families = BTreeSet::new();
    let mut required_identifier_coverage = BTreeSet::new();
    let mut optional_identifier_coverage = BTreeSet::new();
    let mut missing_identifier_urls = Vec::new();
    let mut authority_backed_compatible_sources = 0usize;

    for selected in selected_urls {
        let selected_trimmed = selected.trim();
        if selected_trimmed.is_empty() {
            continue;
        }
        let dedup_key = selected_trimmed.to_ascii_lowercase();
        if !seen_urls.insert(dedup_key) {
            continue;
        }

        let (title, excerpt) = source_hint_for_url(source_hints, selected_trimmed)
            .map(|hint| {
                (
                    hint.title.as_deref().unwrap_or_default(),
                    hint.excerpt.as_str(),
                )
            })
            .unwrap_or(("", ""));
        total_sources = total_sources.saturating_add(1);
        if let Some(domain) = candidate_distinct_domain_key_from_excerpt(selected_trimmed, excerpt)
        {
            distinct_domains.insert(domain);
        }
        let selected_source_summary = PendingSearchReadSummary {
            url: selected_trimmed.to_string(),
            title: (!title.trim().is_empty()).then(|| title.trim().to_string()),
            excerpt: excerpt.trim().to_string(),
        };
        let entity_anchor_compatible = if !entity_anchor_required {
            true
        } else if local_business_entity_selection_flow {
            local_business_target_name_from_source(&selected_source_summary, locality_hint)
                .is_some()
        } else {
            source_matches_local_business_search_entity_anchor(
                query_contract,
                retrieval_contract,
                locality_hint,
                selected_trimmed,
                title,
                excerpt,
            )
        };
        if entity_anchor_compatible {
            entity_anchor_compatible_sources = entity_anchor_compatible_sources.saturating_add(1);
            entity_anchor_source_urls.push(selected_trimmed.to_string());
        } else {
            entity_anchor_mismatched_urls.push(selected_trimmed.to_string());
        }

        let identifier_labels = source_briefing_standard_identifier_labels(
            query_contract,
            selected_trimmed,
            title,
            excerpt,
        );
        let identifier_bearing = !identifier_labels.is_empty();
        let authoritative =
            source_has_document_authority(query_contract, selected_trimmed, title, excerpt);
        if authoritative {
            authoritative_source_families.insert(
                source_document_authority_family_key(
                    query_contract,
                    selected_trimmed,
                    title,
                    excerpt,
                )
                .unwrap_or_else(|| selected_trimmed.to_ascii_lowercase()),
            );
        }
        if identifier_bearing {
            identifier_bearing_sources = identifier_bearing_sources.saturating_add(1);
            if authoritative {
                authority_identifier_sources = authority_identifier_sources.saturating_add(1);
            }
            required_identifier_coverage.extend(
                identifier_labels
                    .iter()
                    .filter(|label| required_identifier_labels.contains(*label))
                    .cloned(),
            );
            optional_identifier_coverage.extend(
                identifier_labels
                    .iter()
                    .filter(|label| optional_identifier_labels.contains(*label))
                    .cloned(),
            );
        } else if identifier_evidence_required {
            missing_identifier_urls.push(selected_trimmed.to_string());
        }

        let admissible_for_document_briefing =
            !identifier_evidence_required || identifier_bearing || authoritative;
        let compatibility = if headline_lookup_mode {
            None
        } else {
            Some(candidate_constraint_compatibility(
                &projection.constraints,
                &projection.query_facets,
                &projection.query_native_tokens,
                &projection.query_tokens,
                &projection.locality_tokens,
                projection.locality_scope.is_some(),
                selected_trimmed,
                title,
                excerpt,
            ))
        };
        let local_business_entity_compatible = admissible_for_document_briefing
            && entity_anchor_compatible
            && (!local_business_menu_surface_required
                || local_business_menu_surface_url(selected_trimmed));
        let local_business_locality_compatible = !projection.locality_scope.is_some()
            || compatibility
                .as_ref()
                .map(|value| value.locality_compatible)
                .unwrap_or(true);
        if headline_lookup_mode {
            let headline_source = PendingSearchReadSummary {
                url: selected_trimmed.to_string(),
                title: (!title.trim().is_empty()).then(|| title.trim().to_string()),
                excerpt: excerpt.trim().to_string(),
            };
            if headline_source_is_actionable(&headline_source)
                && admissible_for_document_briefing
                && entity_anchor_compatible
            {
                compatible_sources = compatible_sources.saturating_add(1);
            }
            if admissible_for_document_briefing && entity_anchor_compatible {
                locality_compatible_sources = locality_compatible_sources.saturating_add(1);
            }
        } else if local_business_entity_selection_flow {
            if local_business_entity_compatible {
                compatible_sources = compatible_sources.saturating_add(1);
            }
            if local_business_entity_compatible && local_business_locality_compatible {
                locality_compatible_sources = locality_compatible_sources.saturating_add(1);
            }
        } else {
            let compatibility = compatibility.expect("non-headline compatibility");
            let authority_aligned = source_has_document_briefing_authority_alignment_with_contract(
                retrieval_contract,
                query_contract,
                required_source_count,
                selected_trimmed,
                title,
                excerpt,
            );
            let grounded_external_publication_support =
                source_is_grounded_external_publication_support_artifact(
                    retrieval_contract,
                    query_contract,
                    selected_trimmed,
                    title,
                    excerpt,
                );
            let quality_compatible = (compatibility_passes_projection(&projection, &compatibility)
                || authority_aligned
                || grounded_external_publication_support)
                && admissible_for_document_briefing
                && entity_anchor_compatible;
            if quality_compatible {
                compatible_sources = compatible_sources.saturating_add(1);
            }
            if quality_compatible && (authority_aligned || authoritative) {
                authority_backed_compatible_sources =
                    authority_backed_compatible_sources.saturating_add(1);
            }
            if compatibility.locality_compatible
                && admissible_for_document_briefing
                && entity_anchor_compatible
            {
                locality_compatible_sources = locality_compatible_sources.saturating_add(1);
            }
        }

        let signals = analyze_source_record_signals(selected_trimmed, title, excerpt);
        if source_has_human_challenge_signal(selected_trimmed, title, excerpt)
            || signals.low_priority_hits > 0
            || signals.low_priority_dominates()
        {
            low_priority_sources = low_priority_sources.saturating_add(1);
            low_priority_urls.push(selected_trimmed.to_string());
        }
    }

    let required_domain_floor =
        retrieval_contract_required_distinct_domain_floor(retrieval_contract, query_contract)
            .min(required_source_count)
            .max(usize::from(required_source_count > 1));
    let locality_floor_met = !projection.locality_scope.is_some()
        || locality_compatible_sources >= required_source_count;
    let distinct_domain_floor_met =
        required_domain_floor == 0 || distinct_domains.len() >= required_domain_floor;
    let entity_anchor_floor_met =
        !entity_anchor_required || entity_anchor_compatible_sources >= required_source_count;
    let local_business_same_authority_override = local_business_entity_selection_flow
        && entity_anchor_floor_met
        && (!local_business_menu_surface_required || compatible_sources >= required_source_count);
    let distinct_domain_floor_met =
        distinct_domain_floor_met || local_business_same_authority_override;
    let identifier_coverage_floor_met = !identifier_evidence_required
        || (identifier_bearing_sources >= required_source_count
            && required_identifier_coverage.len() >= required_identifier_group_floor);
    let grounded_document_briefing_support_mode =
        query_prefers_document_briefing_layout(query_contract)
            && !query_requests_comparison(query_contract)
            && analyze_query_facets(query_contract).grounded_external_required
            && retrieval_contract
                .map(|contract| {
                    contract.currentness_required || contract.source_independence_min > 1
                })
                .unwrap_or(false);
    let quality_floor_met = total_sources >= required_source_count
        && compatible_sources >= required_source_count
        && locality_floor_met
        && distinct_domain_floor_met
        && low_priority_sources == 0
        && entity_anchor_floor_met
        && (!grounded_document_briefing_support_mode || authority_backed_compatible_sources > 0)
        && identifier_coverage_floor_met;

    SelectedSourceQualityObservation {
        total_sources,
        compatible_sources,
        locality_compatible_sources,
        distinct_domains: distinct_domains.len(),
        low_priority_sources,
        quality_floor_met,
        low_priority_urls,
        entity_anchor_required,
        entity_anchor_compatible_sources,
        entity_anchor_floor_met,
        entity_anchor_source_urls,
        entity_anchor_mismatched_urls,
        identifier_evidence_required,
        identifier_bearing_sources,
        authority_identifier_sources,
        required_identifier_label_coverage: required_identifier_coverage.len(),
        optional_identifier_label_coverage: optional_identifier_coverage.len(),
        required_identifier_group_floor,
        identifier_coverage_floor_met,
        missing_identifier_urls,
    }
}

pub(crate) fn selected_source_quality_metrics_with_contract_and_locality_hint(
    retrieval_contract: Option<&WebRetrievalContract>,
    query_contract: &str,
    min_sources: u32,
    selected_urls: &[String],
    source_hints: &[PendingSearchReadSummary],
    locality_hint: Option<&str>,
) -> (usize, usize, usize, usize, usize, bool, Vec<String>) {
    let observation = selected_source_quality_observation_with_contract_and_locality_hint(
        retrieval_contract,
        query_contract,
        min_sources,
        selected_urls,
        source_hints,
        locality_hint,
    );
    (
        observation.total_sources,
        observation.compatible_sources,
        observation.locality_compatible_sources,
        observation.distinct_domains,
        observation.low_priority_sources,
        observation.quality_floor_met,
        observation.low_priority_urls,
    )
}

pub(crate) fn selected_source_quality_metrics_with_locality_hint(
    query_contract: &str,
    min_sources: u32,
    selected_urls: &[String],
    source_hints: &[PendingSearchReadSummary],
    locality_hint: Option<&str>,
) -> (usize, usize, usize, usize, usize, bool, Vec<String>) {
    selected_source_quality_metrics_with_contract_and_locality_hint(
        None,
        query_contract,
        min_sources,
        selected_urls,
        source_hints,
        locality_hint,
    )
}

#[cfg(test)]
mod selection_metrics_tests {
    use super::*;

    #[test]
    fn document_briefing_quality_observation_does_not_require_identifier_bearing_sources() {
        let query =
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
        let contract = crate::agentic::web::derive_web_retrieval_contract(query, None)
            .expect("retrieval contract");
        let selected_urls = vec![
            "https://www.nist.gov/news-events/news/2025/03/nist-selects-hqc-fifth-algorithm-post-quantum-encryption"
                .to_string(),
            "https://www.ibm.com/think/insights/post-quantum-cryptography-transition".to_string(),
        ];
        let source_hints = vec![
            PendingSearchReadSummary {
                url: selected_urls[0].clone(),
                title: Some(
                    "NIST selects HQC as fifth algorithm for post-quantum encryption".to_string(),
                ),
                excerpt: "March 11, 2025 - NIST selects HQC as a fifth algorithm for post-quantum encryption."
                    .to_string(),
            },
            PendingSearchReadSummary {
                url: selected_urls[1].clone(),
                title: Some("Post-quantum cryptography transition guidance".to_string()),
                excerpt:
                    "March 2026 - IBM explains recent NIST post-quantum cryptography transition planning for enterprises."
                        .to_string(),
            },
        ];

        let observation = selected_source_quality_observation_with_contract_and_locality_hint(
            Some(&contract),
            query,
            2,
            &selected_urls,
            &source_hints,
            None,
        );

        assert!(!observation.identifier_evidence_required);
        assert_eq!(observation.identifier_bearing_sources, 0);
        assert_eq!(observation.required_identifier_label_coverage, 0);
        assert!(observation.identifier_coverage_floor_met);
        assert!(observation.missing_identifier_urls.is_empty());
    }

    #[test]
    fn document_briefing_quality_observation_requires_evidence_backed_identifier_inventory() {
        let query =
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
        let contract = crate::agentic::web::derive_web_retrieval_contract(query, None)
            .expect("retrieval contract");
        let selected_urls = vec![
            "https://www.nist.gov/pqc".to_string(),
            "https://research.ibm.com/blog/nist-pqc-standards".to_string(),
        ];
        let source_hints = vec![
            PendingSearchReadSummary {
                url: selected_urls[0].clone(),
                title: Some("Post-quantum cryptography | NIST".to_string()),
                excerpt:
                    "December 8, 2025 - Federal Information Processing Standards FIPS 203, FIPS 204, and FIPS 205 are mandatory for federal systems."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: selected_urls[1].clone(),
                title: Some(
                    "NIST's post-quantum cryptography standards are here - IBM Research"
                        .to_string(),
                ),
                excerpt:
                    "September 18, 2025 - NIST released Federal Information Processing Standards FIPS 203, FIPS 204, and FIPS 205 for ML-KEM, ML-DSA, and SLH-DSA."
                        .to_string(),
            },
        ];

        let observation = selected_source_quality_observation_with_contract_and_locality_hint(
            Some(&contract),
            query,
            2,
            &selected_urls,
            &source_hints,
            None,
        );

        assert!(observation.identifier_evidence_required);
        assert_eq!(observation.identifier_bearing_sources, 2);
        assert_eq!(observation.authority_identifier_sources, 1);
        assert_eq!(observation.required_identifier_label_coverage, 3);
        assert!(observation.identifier_coverage_floor_met);
        assert!(observation.quality_floor_met);
        assert!(observation.missing_identifier_urls.is_empty());
    }

    #[test]
    fn document_briefing_quality_observation_rejects_grounded_same_authority_selection_when_distinct_domain_floor_is_required(
    ) {
        let query =
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
        let contract = crate::agentic::web::derive_web_retrieval_contract(query, None)
            .expect("retrieval contract");
        let selected_urls = vec![
            "https://csrc.nist.gov/pubs/fips/203/final".to_string(),
            "https://csrc.nist.gov/pubs/fips/204/final".to_string(),
        ];
        let source_hints = vec![
            PendingSearchReadSummary {
                url: selected_urls[0].clone(),
                title: Some(
                    "FIPS 203 Module-Lattice-Based Key-Encapsulation Mechanism Standard"
                        .to_string(),
                ),
                excerpt:
                    "NIST finalized FIPS 203 as a post-quantum cryptography standard based on ML-KEM."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: selected_urls[1].clone(),
                title: Some(
                    "FIPS 204 Module-Lattice-Based Digital Signature Standard".to_string(),
                ),
                excerpt:
                    "NIST finalized FIPS 204 as a post-quantum cryptography standard based on ML-DSA."
                        .to_string(),
            },
        ];

        let observation = selected_source_quality_observation_with_contract_and_locality_hint(
            Some(&contract),
            query,
            2,
            &selected_urls,
            &source_hints,
            None,
        );

        assert!(!observation.identifier_evidence_required);
        assert!(observation.identifier_coverage_floor_met);
        assert_eq!(observation.distinct_domains, 1);
        assert!(!observation.quality_floor_met);
    }

    #[test]
    fn document_briefing_quality_observation_rejects_duplicate_ir_authority_family_fill() {
        let query = "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing using current web and local memory evidence, then return a cited brief with findings, uncertainties, and next checks.";
        let contract = crate::agentic::web::derive_web_retrieval_contract(query, Some(query))
            .expect("retrieval contract");
        let selected_urls = vec![
            "https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string(),
            "https://csrc.nist.gov/pubs/ir/8413/final".to_string(),
        ];
        let source_hints = vec![
            PendingSearchReadSummary {
                url: selected_urls[0].clone(),
                title: Some(
                    "IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC"
                        .to_string(),
                ),
                excerpt:
                    "The report references FIPS 203, FIPS 204, and FIPS 205 in the NIST post-quantum cryptography standardization process."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: selected_urls[1].clone(),
                title: Some(
                    "IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC"
                        .to_string(),
                ),
                excerpt:
                    "The report references FIPS 203, FIPS 204, and FIPS 205 in the NIST post-quantum cryptography standardization process."
                        .to_string(),
            },
        ];

        let observation = selected_source_quality_observation_with_contract_and_locality_hint(
            Some(&contract),
            query,
            2,
            &selected_urls,
            &source_hints,
            None,
        );

        assert!(observation.identifier_evidence_required);
        assert_eq!(observation.compatible_sources, 2);
        assert_eq!(observation.required_identifier_group_floor, 1);
        assert_eq!(observation.required_identifier_label_coverage, 1);
        assert!(observation.identifier_coverage_floor_met);
        assert!(!observation.quality_floor_met);
        assert!(observation.missing_identifier_urls.is_empty());
    }

    #[test]
    fn document_briefing_quality_observation_rejects_empty_snippet_duplicate_authority_family_fill()
    {
        let query = "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing using current web and local memory evidence, then return a cited brief with findings, uncertainties, and next checks.";
        let contract = crate::agentic::web::derive_web_retrieval_contract(query, Some(query))
            .expect("retrieval contract");
        let selected_urls = vec![
            "https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string(),
            "https://csrc.nist.gov/pubs/ir/8413/final".to_string(),
        ];
        let source_hints = vec![
            PendingSearchReadSummary {
                url: selected_urls[0].clone(),
                title: Some(
                    "IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC"
                        .to_string(),
                ),
                excerpt: "".to_string(),
            },
            PendingSearchReadSummary {
                url: selected_urls[1].clone(),
                title: Some(
                    "IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC"
                        .to_string(),
                ),
                excerpt: "".to_string(),
            },
        ];

        let observation = selected_source_quality_observation_with_contract_and_locality_hint(
            Some(&contract),
            query,
            2,
            &selected_urls,
            &source_hints,
            None,
        );

        assert_eq!(observation.compatible_sources, 2);
        assert_eq!(observation.required_identifier_group_floor, 1);
        assert!(observation.identifier_coverage_floor_met);
        assert!(!observation.quality_floor_met);
    }

    #[test]
    fn document_briefing_quality_observation_accepts_grounded_external_pdf_support_with_authority_pairing(
    ) {
        let query =
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
        let contract = crate::agentic::web::derive_web_retrieval_contract(query, Some(query))
            .expect("retrieval contract");
        let selected_urls = vec![
            "https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string(),
            "https://trustedcomputinggroup.org/wp-content/uploads/State-of-PQC-Readiness-2025-November-2025.pdf"
                .to_string(),
        ];
        let source_hints = vec![
            PendingSearchReadSummary {
                url: selected_urls[0].clone(),
                title: Some(
                    "IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC"
                        .to_string(),
                ),
                excerpt:
                    "NIST IR 8413 Update 1 tracks the current post-quantum cryptography standardization process and references FIPS 203, FIPS 204, and FIPS 205."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: selected_urls[1].clone(),
                title: Some("91% of organizations".to_string()),
                excerpt:
                    "Industry readiness report for quantum-safe migration and deployment planning."
                        .to_string(),
            },
        ];

        let observation = selected_source_quality_observation_with_contract_and_locality_hint(
            Some(&contract),
            query,
            2,
            &selected_urls,
            &source_hints,
            None,
        );

        assert_eq!(observation.total_sources, 2);
        assert_eq!(observation.compatible_sources, 2);
        assert_eq!(observation.distinct_domains, 2);
        assert!(observation.quality_floor_met);
    }

    #[test]
    fn local_business_quality_observation_requires_entity_anchor_compatible_sources() {
        let query =
            "Find the three best-reviewed Italian restaurants in Anderson, SC and compare their menus.";
        let contract = crate::agentic::web::derive_web_retrieval_contract(query, Some(query))
            .expect("retrieval contract");
        let selected_urls = vec![
            "https://www.restaurantji.com/sc/anderson/chick-fil-a-/".to_string(),
            "https://www.restaurantji.com/sc/anderson/arnolds-famous-homemade-hamburgers-/"
                .to_string(),
            "https://www.restaurantji.com/sc/anderson/arbys-2/".to_string(),
        ];
        let source_hints = vec![
            PendingSearchReadSummary {
                url: selected_urls[0].clone(),
                title: Some(
                    "Chick-fil-A, Anderson - Menu, Reviews (189), Photos (44) - Restaurantji"
                        .to_string(),
                ),
                excerpt: "Fast-food restaurant in Anderson, SC serving chicken sandwiches, nuggets and fries."
                    .to_string(),
            },
            PendingSearchReadSummary {
                url: selected_urls[1].clone(),
                title: Some(
                    "Arnold's Famous Homemade Hamburgers, Anderson - Menu, Reviews (214), Photos (38) - Restaurantji"
                        .to_string(),
                ),
                excerpt:
                    "American restaurant in Anderson, SC serving burgers, onion rings and shakes."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: selected_urls[2].clone(),
                title: Some(
                    "Arby's, Anderson - Menu, Reviews (145), Photos (21) - Restaurantji"
                        .to_string(),
                ),
                excerpt:
                    "Fast-food restaurant in Anderson, SC serving roast beef sandwiches and curly fries."
                        .to_string(),
            },
        ];

        let observation = selected_source_quality_observation_with_contract_and_locality_hint(
            Some(&contract),
            query,
            3,
            &selected_urls,
            &source_hints,
            Some("Anderson, SC"),
        );

        assert!(observation.entity_anchor_required);
        assert_eq!(observation.entity_anchor_compatible_sources, 0);
        assert!(!observation.entity_anchor_floor_met);
        assert!(!observation.quality_floor_met);
        assert!(observation.entity_anchor_source_urls.is_empty());
        assert_eq!(observation.entity_anchor_mismatched_urls, selected_urls);
    }

    #[test]
    fn local_business_quality_observation_accepts_entity_anchor_compatible_sources() {
        let query =
            "Find the three best-reviewed Italian restaurants in Anderson, SC and compare their menus.";
        let contract = crate::agentic::web::derive_web_retrieval_contract(query, Some(query))
            .expect("retrieval contract");
        let selected_urls = vec![
            "https://www.restaurantji.com/sc/anderson/brothers-italian-cuisine-/".to_string(),
            "https://www.restaurantji.com/sc/anderson/coach-house-restaurant-/".to_string(),
            "https://www.restaurantji.com/sc/anderson/dolce-vita-italian-bistro-/".to_string(),
        ];
        let source_hints = vec![
            PendingSearchReadSummary {
                url: selected_urls[0].clone(),
                title: Some(
                    "Brothers Italian Cuisine, Anderson - Menu, Reviews (226), Photos (25) - Restaurantji"
                        .to_string(),
                ),
                excerpt: "Italian restaurant in Anderson, SC serving pizza, pasta and subs."
                    .to_string(),
            },
            PendingSearchReadSummary {
                url: selected_urls[1].clone(),
                title: Some(
                    "Coach House Restaurant, Anderson - Menu, Reviews (242), Photos (52) - Restaurantji"
                        .to_string(),
                ),
                excerpt:
                    "Anderson steakhouse and Italian restaurant with lasagna, ravioli and house specials."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: selected_urls[2].clone(),
                title: Some(
                    "Dolce Vita Italian Bistro, Anderson - Menu, Reviews (278), Photos (51) - Restaurantji"
                        .to_string(),
                ),
                excerpt:
                    "Italian bistro in Anderson, SC with pizza, pasta, calzones and dessert."
                        .to_string(),
            },
        ];

        let observation = selected_source_quality_observation_with_contract_and_locality_hint(
            Some(&contract),
            query,
            3,
            &selected_urls,
            &source_hints,
            Some("Anderson, SC"),
        );

        assert!(observation.entity_anchor_required);
        assert_eq!(observation.entity_anchor_compatible_sources, 3);
        assert!(observation.entity_anchor_floor_met);
        assert!(observation.quality_floor_met);
        assert_eq!(observation.entity_anchor_source_urls, selected_urls);
        assert!(observation.entity_anchor_mismatched_urls.is_empty());
    }
}
