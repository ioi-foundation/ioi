use super::*;
use crate::agentic::desktop::service::DesktopAgentService;
use tokio::time::Duration;

fn hybrid_synthesis_timeout() -> Duration {
    const DEFAULT_TIMEOUT_MS: u64 = 4_000;
    std::env::var("IOI_WEB_HYBRID_SYNTHESIS_TIMEOUT_MS")
        .ok()
        .and_then(|raw| raw.parse::<u64>().ok())
        .filter(|ms| *ms > 0)
        .map(Duration::from_millis)
        .unwrap_or_else(|| Duration::from_millis(DEFAULT_TIMEOUT_MS))
}

pub(crate) fn extract_json_object(raw: &str) -> Option<&str> {
    let start = raw.find('{')?;
    let end = raw.rfind('}')?;
    (end >= start).then_some(&raw[start..=end])
}

pub(crate) fn is_iso_utc_datetime(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 20 {
        return false;
    }
    bytes[0].is_ascii_digit()
        && bytes[1].is_ascii_digit()
        && bytes[2].is_ascii_digit()
        && bytes[3].is_ascii_digit()
        && bytes[4] == b'-'
        && bytes[5].is_ascii_digit()
        && bytes[6].is_ascii_digit()
        && bytes[7] == b'-'
        && bytes[8].is_ascii_digit()
        && bytes[9].is_ascii_digit()
        && bytes[10] == b'T'
        && bytes[11].is_ascii_digit()
        && bytes[12].is_ascii_digit()
        && bytes[13] == b':'
        && bytes[14].is_ascii_digit()
        && bytes[15].is_ascii_digit()
        && bytes[16] == b':'
        && bytes[17].is_ascii_digit()
        && bytes[18].is_ascii_digit()
        && bytes[19] == b'Z'
}

pub(crate) fn normalize_section_key(label: &str) -> String {
    let mut out = String::new();
    let mut last_was_underscore = false;
    for ch in label.chars() {
        let normalized = ch.to_ascii_lowercase();
        if normalized.is_ascii_alphanumeric() {
            out.push(normalized);
            last_was_underscore = false;
            continue;
        }
        if !last_was_underscore {
            out.push('_');
            last_was_underscore = true;
        }
    }
    out.trim_matches('_').to_string()
}

pub(crate) fn dedupe_labels(labels: Vec<String>) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    for label in labels {
        let key = normalize_section_key(&label);
        if key.is_empty() || !seen.insert(key) {
            continue;
        }
        out.push(label);
    }
    out
}

pub(crate) fn required_section_labels_for_query(query: &str) -> Vec<String> {
    dedupe_labels(
        infer_report_sections(query)
            .into_iter()
            .map(|kind| report_section_label(kind, query))
            .collect(),
    )
}

pub(crate) fn build_hybrid_required_sections(query: &str) -> Vec<HybridSectionSpec> {
    required_section_labels_for_query(query)
        .into_iter()
        .map(|label| HybridSectionSpec {
            key: normalize_section_key(&label),
            label,
            required: true,
        })
        .collect()
}

pub(crate) fn section_kind_from_key(key: &str) -> Option<ReportSectionKind> {
    let normalized = normalize_section_key(key);
    if let Some(kind) = [
        ReportSectionKind::Summary,
        ReportSectionKind::RecentChange,
        ReportSectionKind::Significance,
        ReportSectionKind::UserImpact,
        ReportSectionKind::Mitigation,
        ReportSectionKind::EtaConfidence,
        ReportSectionKind::Caveat,
        ReportSectionKind::Evidence,
    ]
    .into_iter()
    .find(|kind| normalized == report_section_key(*kind))
    {
        return Some(kind);
    }
    [
        ReportSectionKind::Summary,
        ReportSectionKind::RecentChange,
        ReportSectionKind::Significance,
        ReportSectionKind::UserImpact,
        ReportSectionKind::Mitigation,
        ReportSectionKind::EtaConfidence,
        ReportSectionKind::Caveat,
        ReportSectionKind::Evidence,
    ]
    .into_iter()
    .find(|kind| {
        normalized == report_section_key(*kind)
            || report_section_aliases(*kind)
                .iter()
                .any(|alias| normalize_section_key(alias) == normalized)
    })
}

pub(crate) fn section_content_for_story(
    story: &StoryDraft,
    section: &HybridSectionSpec,
) -> Option<HybridSectionDraft> {
    let kind = section_kind_from_key(&section.key)
        .or_else(|| section_kind_from_key(&section.label))
        .unwrap_or(ReportSectionKind::Summary);
    let content = match kind {
        ReportSectionKind::Summary => story.what_happened.clone(),
        ReportSectionKind::RecentChange => story.changed_last_hour.clone(),
        ReportSectionKind::Significance => story.why_it_matters.clone(),
        ReportSectionKind::UserImpact => story.user_impact.clone(),
        ReportSectionKind::Mitigation => story.workaround.clone(),
        ReportSectionKind::EtaConfidence => story.eta_confidence.clone(),
        ReportSectionKind::Caveat => story.caveat.clone(),
        ReportSectionKind::Evidence => {
            "Supporting source evidence is listed in the citations section.".to_string()
        }
    };

    let normalized = compact_whitespace(content.trim());
    if normalized.is_empty() {
        return None;
    }
    Some(HybridSectionDraft {
        key: section.key.clone(),
        label: section.label.clone(),
        content: normalized,
    })
}

pub(crate) fn section_content_from_map(
    sections: &BTreeMap<String, String>,
    keys: &[&str],
) -> Option<String> {
    for key in keys {
        if let Some(value) = sections.get(*key) {
            let trimmed = compact_whitespace(value.trim());
            if !trimmed.is_empty() {
                return Some(trimmed);
            }
        }
    }
    None
}

pub(crate) fn section_content_from_map_for_kind(
    sections: &BTreeMap<String, String>,
    kind: ReportSectionKind,
) -> Option<String> {
    section_content_from_map(sections, report_section_aliases(kind))
}

pub(crate) fn apply_hybrid_synthesis_response(
    base: &SynthesisDraft,
    required_sections: &[HybridSectionSpec],
    response: HybridSynthesisResponse,
) -> Option<SynthesisDraft> {
    let retrieval_contract = base.retrieval_contract.as_ref();
    let layout_profile = synthesis_layout_profile(retrieval_contract, &base.query);
    let document_briefing_layout =
        matches!(layout_profile, SynthesisLayoutProfile::DocumentBriefing);
    let required_story_count =
        retrieval_contract_required_story_count(retrieval_contract, &base.query);
    let required_item_count = if document_briefing_layout {
        1
    } else {
        required_story_count
    };
    let citations_per_story =
        retrieval_contract_required_citations_per_story(retrieval_contract, &base.query);
    let required_distinct_citations =
        retrieval_contract_required_distinct_citations(retrieval_contract, &base.query);
    let required_item_citation_count = if document_briefing_layout {
        retrieval_contract_required_document_briefing_citation_count(
            retrieval_contract,
            &base.query,
        )
        .max(citations_per_story)
    } else {
        citations_per_story
    };
    if response.items.len() < required_item_count {
        return None;
    }
    if document_briefing_layout && response.items.len() != 1 {
        return None;
    }

    let mut used_urls = BTreeSet::new();
    let mut stories = Vec::new();
    let required_keys = required_sections
        .iter()
        .map(|section| section.key.clone())
        .collect::<BTreeSet<_>>();

    for (idx, item) in response
        .items
        .into_iter()
        .take(required_item_count)
        .enumerate()
    {
        let base_story = base.stories.get(idx)?;
        let title = item.title.trim();
        if title.is_empty() {
            return None;
        }

        let mut sections_by_key = BTreeMap::<String, String>::new();
        for section in item.sections {
            let key = {
                let from_key = normalize_section_key(&section.key);
                if from_key.is_empty() {
                    normalize_section_key(&section.label)
                } else {
                    from_key
                }
            };
            if key.is_empty() {
                continue;
            }
            let content = compact_whitespace(section.content.trim());
            if content.is_empty() {
                continue;
            }
            sections_by_key.entry(key).or_insert(content);
        }
        if required_keys
            .iter()
            .any(|required| !sections_by_key.contains_key(required))
        {
            return None;
        }

        let happened =
            section_content_from_map_for_kind(&sections_by_key, ReportSectionKind::Summary)
                .unwrap_or_else(|| base_story.what_happened.clone());
        let changed =
            section_content_from_map_for_kind(&sections_by_key, ReportSectionKind::RecentChange)
                .unwrap_or_else(|| base_story.changed_last_hour.clone());
        let matters =
            section_content_from_map_for_kind(&sections_by_key, ReportSectionKind::Significance)
                .unwrap_or_else(|| base_story.why_it_matters.clone());
        let user_impact =
            section_content_from_map_for_kind(&sections_by_key, ReportSectionKind::UserImpact)
                .unwrap_or_else(|| base_story.user_impact.clone());
        let workaround =
            section_content_from_map_for_kind(&sections_by_key, ReportSectionKind::Mitigation)
                .unwrap_or_else(|| base_story.workaround.clone());
        let eta_label =
            section_content_from_map_for_kind(&sections_by_key, ReportSectionKind::EtaConfidence)
                .unwrap_or_else(|| base_story.eta_confidence.clone());

        let mut citation_ids = Vec::new();
        for id in item.citation_ids {
            let trimmed = id.trim();
            if trimmed.is_empty() || citation_ids.iter().any(|existing| existing == trimmed) {
                continue;
            }
            let Some(citation) = base.citations_by_id.get(trimmed) else {
                continue;
            };
            citation_ids.push(trimmed.to_string());
            used_urls.insert(citation.url.clone());
            if citation_ids.len() >= required_item_citation_count {
                break;
            }
        }
        if citation_ids.len() < required_item_citation_count {
            return None;
        }

        let mut normalized_confidence = normalize_confidence_label(&item.confidence);
        if normalized_confidence == "low" && citation_ids.len() >= required_item_citation_count {
            normalized_confidence = "medium".to_string();
        }

        stories.push(StoryDraft {
            title: title.to_string(),
            what_happened: happened.to_string(),
            changed_last_hour: changed.to_string(),
            why_it_matters: matters.to_string(),
            user_impact,
            workaround,
            eta_confidence: normalize_confidence_label(&eta_label),
            citation_ids,
            confidence: normalized_confidence,
            caveat: if item.caveat.trim().is_empty() {
                "Model omitted caveat; fallback caveat applied.".to_string()
            } else {
                item.caveat.trim().to_string()
            },
        });
    }

    if used_urls.len() < required_distinct_citations {
        return None;
    }

    let mut overall_confidence = normalize_confidence_label(&response.overall_confidence);
    if overall_confidence == "low" && used_urls.len() >= required_distinct_citations {
        overall_confidence = "medium".to_string();
    }

    Some(SynthesisDraft {
        query: base.query.clone(),
        retrieval_contract: base.retrieval_contract.clone(),
        run_date: base.run_date.clone(),
        run_timestamp_ms: base.run_timestamp_ms,
        run_timestamp_iso_utc: base.run_timestamp_iso_utc.clone(),
        completion_reason: base.completion_reason.clone(),
        overall_confidence,
        overall_caveat: if response.overall_caveat.trim().is_empty() {
            base.overall_caveat.clone()
        } else {
            let heading = response.heading.trim();
            if heading.is_empty() {
                response.overall_caveat.trim().to_string()
            } else {
                format!(
                    "{} | heading: {}",
                    response.overall_caveat.trim(),
                    compact_whitespace(heading)
                )
            }
        },
        stories,
        citations_by_id: base.citations_by_id.clone(),
        blocked_urls: base.blocked_urls.clone(),
        partial_note: base.partial_note.clone(),
    })
}

pub(crate) async fn synthesize_web_pipeline_reply_hybrid(
    service: &DesktopAgentService,
    pending: &PendingSearchCompletion,
    reason: WebPipelineCompletionReason,
) -> Option<String> {
    let draft = build_deterministic_story_draft(pending, reason);
    if !query_requires_structured_synthesis(&draft.query) {
        return None;
    }
    let retrieval_contract = draft.retrieval_contract.as_ref();
    let layout_profile = synthesis_layout_profile(retrieval_contract, &draft.query);
    let document_briefing_layout =
        matches!(layout_profile, SynthesisLayoutProfile::DocumentBriefing);
    let required_story_count =
        retrieval_contract_required_story_count(retrieval_contract, &draft.query);
    let required_support_count =
        retrieval_contract_required_support_count(retrieval_contract, &draft.query);
    let required_item_count = if document_briefing_layout {
        1
    } else {
        required_story_count
    };
    let citations_per_story =
        retrieval_contract_required_citations_per_story(retrieval_contract, &draft.query);
    let required_item_citation_count = if document_briefing_layout {
        retrieval_contract_required_document_briefing_citation_count(
            retrieval_contract,
            &draft.query,
        )
        .max(citations_per_story)
    } else {
        citations_per_story
    };
    let required_distinct_citations =
        retrieval_contract_required_distinct_citations(retrieval_contract, &draft.query);
    let now_ms = web_pipeline_now_ms();
    if pending.deadline_ms > 0
        && now_ms.saturating_add(WEB_PIPELINE_HYBRID_BUDGET_GUARD_MS) >= pending.deadline_ms
    {
        return None;
    }

    let candidates = draft
        .citations_by_id
        .values()
        .map(|citation| HybridCitationCandidate {
            id: citation.id.clone(),
            url: citation.url.clone(),
            source_label: citation.source_label.clone(),
            excerpt: citation.excerpt.clone(),
            timestamp_utc: citation.timestamp_utc.clone(),
            note: citation.note.clone(),
        })
        .collect::<Vec<_>>();
    if candidates.len() < required_distinct_citations {
        return None;
    }

    let required_sections = build_hybrid_required_sections(&draft.query);
    if required_sections.is_empty() {
        return None;
    }

    let deterministic_story_drafts = draft
        .stories
        .iter()
        .take(if document_briefing_layout {
            required_support_count
        } else {
            required_story_count
        })
        .map(|story| HybridStoryDraft {
            title: story.title.clone(),
            sections: required_sections
                .iter()
                .filter_map(|section| section_content_for_story(story, section))
                .collect::<Vec<_>>(),
            citation_ids: story.citation_ids.clone(),
            confidence: story.confidence.clone(),
            caveat: story.caveat.clone(),
        })
        .collect::<Vec<_>>();

    let output_shape_requirement = if document_briefing_layout {
        "- Exactly 1 item.\n\
- The single item must be a merged document briefing, not a per-source or per-story breakdown.\n"
            .to_string()
    } else {
        format!("- Exactly {} items.\n", required_item_count)
    };
    let payload = HybridSynthesisPayload {
        query: draft.query.clone(),
        run_timestamp_ms: draft.run_timestamp_ms,
        run_timestamp_iso_utc: draft.run_timestamp_iso_utc.clone(),
        completion_reason: draft.completion_reason.clone(),
        required_sections: required_sections.clone(),
        citation_candidates: candidates,
        deterministic_story_drafts,
    };
    let prompt = format!(
        "Return JSON only with schema: \
{{\"heading\":string,\"items\":[{{\"title\":string,\"sections\":[{{\"label\":string,\"content\":string}}],\"citation_ids\":[string],\"confidence\":\"high|medium|low\",\"caveat\":string}}],\"overall_confidence\":\"high|medium|low\",\"overall_caveat\":string}}.\n\
Requirements:\n\
{}\
- For each item, include all payload.required_sections labels exactly once in `sections`.\n\
- Use ONLY citation_ids from payload.\n\
- Each item must include exactly {} citation_ids.\n\
- Keep text concise, factual, and query-aligned.\n\
- Treat run_timestamp_ms and run_timestamp_iso_utc as authoritative UTC clock for recency.\n\
Payload:\n{}",
        output_shape_requirement,
        required_item_citation_count,
        serde_json::to_string_pretty(&payload).ok()?
    );
    let options = InferenceOptions {
        tools: vec![],
        temperature: 0.0,
        json_mode: true,
        max_tokens: WEB_PIPELINE_HYBRID_MAX_TOKENS,
        required_finality_tier: Default::default(),
        sealed_finality_proof: None,
        canonical_collapse_object: None,
    };
    let airlocked_prompt = service
        .prepare_cloud_inference_input(
            None,
            "desktop_agent",
            "web_pipeline_hybrid_synthesis",
            prompt.as_bytes(),
        )
        .await
        .ok()?;
    let timeout = hybrid_synthesis_timeout();
    let raw = match tokio::time::timeout(
        timeout,
        service
            .reasoning_inference
            .execute_inference([0u8; 32], &airlocked_prompt, options),
    )
    .await
    {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(_)) => return None,
        Err(_) => return None,
    };
    let text = String::from_utf8(raw).ok()?;
    let json_text = extract_json_object(&text).unwrap_or(text.as_str());
    let response: HybridSynthesisResponse = serde_json::from_str(json_text).ok()?;
    let updated = apply_hybrid_synthesis_response(&draft, &required_sections, response)?;

    // Ensure rendered citations still carry absolute UTC datetimes.
    let has_timestamps = updated
        .citations_by_id
        .values()
        .all(|citation| is_iso_utc_datetime(&citation.timestamp_utc));
    if !has_timestamps {
        return None;
    }
    Some(render_user_synthesis_draft(&updated))
}

pub(crate) fn synthesize_web_pipeline_reply(
    pending: &PendingSearchCompletion,
    reason: WebPipelineCompletionReason,
) -> String {
    let draft = build_deterministic_story_draft(pending, reason);
    render_user_synthesis_draft(&draft)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nist_briefing_contract() -> ioi_types::app::agentic::WebRetrievalContract {
        crate::agentic::web::derive_web_retrieval_contract(
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.",
            None,
        )
        .expect("retrieval contract")
    }

    fn nist_briefing_base_draft() -> SynthesisDraft {
        let query =
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
        let mut citations_by_id = BTreeMap::new();
        citations_by_id.insert(
            "C1".to_string(),
            CitationCandidate {
                id: "C1".to_string(),
                url: "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards".to_string(),
                source_label: "NIST Releases First 3 Finalized Post-Quantum Encryption Standards"
                    .to_string(),
                excerpt: "NIST released FIPS 203, FIPS 204, and FIPS 205 as the first finalized post-quantum encryption standards."
                    .to_string(),
                timestamp_utc: "2026-03-10T12:00:00Z".to_string(),
                note: "retrieved_utc".to_string(),
                from_successful_read: true,
            },
        );
        citations_by_id.insert(
            "C2".to_string(),
            CitationCandidate {
                id: "C2".to_string(),
                url: "https://www.nist.gov/news-events/news/2025/03/nist-selects-hqc-fifth-algorithm-post-quantum-encryption".to_string(),
                source_label: "NIST Selects HQC as Fifth Algorithm for Post-Quantum Encryption"
                    .to_string(),
                excerpt: "NIST selected HQC in March 2025 as the fifth post-quantum algorithm for standardization."
                    .to_string(),
                timestamp_utc: "2026-03-10T12:00:00Z".to_string(),
                note: "retrieved_utc".to_string(),
                from_successful_read: true,
            },
        );
        citations_by_id.insert(
            "C3".to_string(),
            CitationCandidate {
                id: "C3".to_string(),
                url: "https://csrc.nist.gov/pubs/fips/204/final".to_string(),
                source_label: "Federal Information Processing Standard (FIPS) 204".to_string(),
                excerpt: "Federal Information Processing Standard (FIPS) 204 specifies ML-DSA."
                    .to_string(),
                timestamp_utc: "2026-03-10T12:00:00Z".to_string(),
                note: "retrieved_utc".to_string(),
                from_successful_read: true,
            },
        );
        citations_by_id.insert(
            "C4".to_string(),
            CitationCandidate {
                id: "C4".to_string(),
                url:
                    "https://terraquantum.swiss/news/diving-into-nists-new-post-quantum-standards/"
                        .to_string(),
                source_label: "Diving into NIST's new post-quantum standards".to_string(),
                excerpt: "The finalized standards set includes FIPS 203, FIPS 204, and FIPS 205."
                    .to_string(),
                timestamp_utc: "2026-03-10T12:00:00Z".to_string(),
                note: "retrieved_utc".to_string(),
                from_successful_read: true,
            },
        );

        SynthesisDraft {
            query: query.to_string(),
            retrieval_contract: Some(nist_briefing_contract()),
            run_date: "2026-03-10".to_string(),
            run_timestamp_ms: 1_773_174_400_000,
            run_timestamp_iso_utc: "2026-03-10T12:00:00Z".to_string(),
            completion_reason: "Completed after meeting the source floor.".to_string(),
            overall_confidence: "high".to_string(),
            overall_caveat: "caveat".to_string(),
            stories: vec![
                StoryDraft {
                    title: "NIST Releases First 3 Finalized Post-Quantum Encryption Standards"
                        .to_string(),
                    what_happened:
                        "NIST finalized FIPS 203, FIPS 204, and FIPS 205 in August 2024."
                            .to_string(),
                    changed_last_hour: String::new(),
                    why_it_matters: "These standards define the initial federal PQC baseline."
                        .to_string(),
                    user_impact: String::new(),
                    workaround: String::new(),
                    eta_confidence: "high".to_string(),
                    citation_ids: vec!["C1".to_string(), "C3".to_string()],
                    confidence: "high".to_string(),
                    caveat: "caveat".to_string(),
                },
                StoryDraft {
                    title: "NIST Selects HQC as Fifth Algorithm for Post-Quantum Encryption"
                        .to_string(),
                    what_happened: "NIST selected HQC in March 2025 for standardization."
                        .to_string(),
                    changed_last_hour: String::new(),
                    why_it_matters:
                        "The selection expands the PQC roadmap beyond the first finalized trio."
                            .to_string(),
                    user_impact: String::new(),
                    workaround: String::new(),
                    eta_confidence: "medium".to_string(),
                    citation_ids: vec!["C2".to_string(), "C4".to_string()],
                    confidence: "medium".to_string(),
                    caveat: "caveat".to_string(),
                },
            ],
            citations_by_id,
            blocked_urls: Vec::new(),
            partial_note: None,
        }
    }

    #[test]
    fn document_briefing_hybrid_response_requires_support_coverage_on_single_item() {
        let base = nist_briefing_base_draft();
        let required_sections = build_hybrid_required_sections(&base.query);
        let single_item_response = HybridSynthesisResponse {
            heading: "Briefing".to_string(),
            items: vec![HybridItemResponse {
                title: "Summary".to_string(),
                sections: vec![
                    HybridSectionResponse {
                        key: "what_happened".to_string(),
                        label: "What happened".to_string(),
                        content: "NIST finalized the first PQC standards.".to_string(),
                    },
                    HybridSectionResponse {
                        key: "key_evidence".to_string(),
                        label: "Key evidence".to_string(),
                        content: "Official NIST citations support the standards summary."
                            .to_string(),
                    },
                ],
                citation_ids: vec!["C1".to_string(), "C3".to_string()],
                confidence: "high".to_string(),
                caveat: "caveat".to_string(),
            }],
            overall_confidence: "high".to_string(),
            overall_caveat: "caveat".to_string(),
        };

        assert!(
            apply_hybrid_synthesis_response(&base, &required_sections, single_item_response)
                .is_none()
        );
    }

    #[test]
    fn document_briefing_hybrid_response_rejects_multi_item_shape() {
        let base = nist_briefing_base_draft();
        let required_sections = build_hybrid_required_sections(&base.query);
        let response = HybridSynthesisResponse {
            heading: "Briefing".to_string(),
            items: vec![
                HybridItemResponse {
                    title: "First standards".to_string(),
                    sections: vec![
                        HybridSectionResponse {
                            key: "what_happened".to_string(),
                            label: "What happened".to_string(),
                            content: "NIST finalized FIPS 203, FIPS 204, and FIPS 205 in August 2024."
                                .to_string(),
                        },
                        HybridSectionResponse {
                            key: "key_evidence".to_string(),
                            label: "Key evidence".to_string(),
                            content: "NIST's August 2024 release and the FIPS 204 publication anchor the current baseline."
                                .to_string(),
                        },
                    ],
                    citation_ids: vec!["C1".to_string(), "C3".to_string()],
                    confidence: "high".to_string(),
                    caveat: "caveat".to_string(),
                },
                HybridItemResponse {
                    title: "HQC selection".to_string(),
                    sections: vec![
                        HybridSectionResponse {
                            key: "what_happened".to_string(),
                            label: "What happened".to_string(),
                            content: "NIST selected HQC in March 2025 as a fifth algorithm for standardization."
                                .to_string(),
                        },
                        HybridSectionResponse {
                            key: "key_evidence".to_string(),
                            label: "Key evidence".to_string(),
                            content: "The March 2025 NIST announcement and supporting standards analysis describe the expanded roadmap."
                                .to_string(),
                        },
                    ],
                    citation_ids: vec!["C2".to_string(), "C4".to_string()],
                    confidence: "medium".to_string(),
                    caveat: "caveat".to_string(),
                },
            ],
            overall_confidence: "high".to_string(),
            overall_caveat: "caveat".to_string(),
        };

        assert!(apply_hybrid_synthesis_response(&base, &required_sections, response).is_none());
    }

    #[test]
    fn document_briefing_hybrid_response_accepts_single_briefing_item() {
        let base = nist_briefing_base_draft();
        let required_sections = build_hybrid_required_sections(&base.query);
        let response = HybridSynthesisResponse {
            heading: "Briefing".to_string(),
            items: vec![HybridItemResponse {
                title: "NIST PQC briefing".to_string(),
                sections: vec![
                    HybridSectionResponse {
                        key: "what_happened".to_string(),
                        label: "What happened".to_string(),
                        content: "NIST finalized FIPS 203, FIPS 204, and FIPS 205 in August 2024, then selected HQC in March 2025 as an additional algorithm for standardization."
                            .to_string(),
                    },
                    HybridSectionResponse {
                        key: "key_evidence".to_string(),
                        label: "Key evidence".to_string(),
                        content: "NIST's August 2024 release, the March 2025 HQC announcement, and the FIPS 204 publication collectively anchor the current standards picture."
                            .to_string(),
                    },
                ],
                citation_ids: vec!["C1".to_string(), "C2".to_string(), "C3".to_string()],
                confidence: "high".to_string(),
                caveat: "caveat".to_string(),
            }],
            overall_confidence: "high".to_string(),
            overall_caveat: "caveat".to_string(),
        };

        let updated = apply_hybrid_synthesis_response(&base, &required_sections, response)
            .expect("response should satisfy single-item briefing contract");
        assert_eq!(updated.stories.len(), 1);
        assert_eq!(updated.stories[0].citation_ids.len(), 3);
    }

    #[test]
    fn section_kind_resolution_prefers_exact_evidence_key_over_summary_aliases() {
        assert_eq!(
            section_kind_from_key("key_evidence"),
            Some(ReportSectionKind::Evidence)
        );
        assert_eq!(
            section_kind_from_key("what_happened"),
            Some(ReportSectionKind::Summary)
        );
    }
}
