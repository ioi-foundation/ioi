use super::*;

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
        ReportSectionKind::Evidence => story.what_happened.clone(),
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
    let required_story_count = required_story_count(&base.query);
    let citations_per_story = required_citations_per_story(&base.query);
    let required_distinct_citations = required_distinct_citations(&base.query);
    if response.items.len() < required_story_count {
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
        .take(required_story_count)
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
            if citation_ids.len() >= citations_per_story {
                break;
            }
        }
        if citation_ids.len() < citations_per_story {
            return None;
        }

        let mut normalized_confidence = normalize_confidence_label(&item.confidence);
        if normalized_confidence == "low" && citation_ids.len() >= citations_per_story {
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
    runtime: Arc<dyn InferenceRuntime>,
    pending: &PendingSearchCompletion,
    reason: WebPipelineCompletionReason,
) -> Option<String> {
    let draft = build_deterministic_story_draft(pending, reason);
    let required_story_count = required_story_count(&draft.query);
    let citations_per_story = required_citations_per_story(&draft.query);
    let required_distinct_citations = required_distinct_citations(&draft.query);
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
        .take(required_story_count)
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
- Exactly {} items.\n\
- For each item, include all payload.required_sections labels exactly once in `sections`.\n\
- Use ONLY citation_ids from payload.\n\
- Each item must include exactly {} citation_ids.\n\
- Keep text concise, factual, and query-aligned.\n\
- Treat run_timestamp_ms and run_timestamp_iso_utc as authoritative UTC clock for recency.\n\
Payload:\n{}",
        required_story_count,
        citations_per_story,
        serde_json::to_string_pretty(&payload).ok()?
    );
    let options = InferenceOptions {
        tools: vec![],
        temperature: 0.0,
        json_mode: true,
        max_tokens: WEB_PIPELINE_HYBRID_MAX_TOKENS,
    };
    let raw = runtime
        .execute_inference([0u8; 32], prompt.as_bytes(), options)
        .await
        .ok()?;
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
    Some(render_synthesis_draft(&updated))
}

pub(crate) fn synthesize_web_pipeline_reply(
    pending: &PendingSearchCompletion,
    reason: WebPipelineCompletionReason,
) -> String {
    let draft = build_deterministic_story_draft(pending, reason);
    render_synthesis_draft(&draft)
}
