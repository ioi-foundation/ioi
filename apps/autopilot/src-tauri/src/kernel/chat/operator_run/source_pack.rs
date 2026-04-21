use super::{ArtifactSourcePack, ArtifactSourceReference, ChatArtifactSession};

pub(super) fn source_pack_for_session(
    session: &ChatArtifactSession,
    origin_prompt_event_id: &str,
) -> ArtifactSourcePack {
    let mut items = Vec::new();

    for source in &session.materialization.retrieved_sources {
        let mut source = source.clone();
        if source.origin_prompt_event_id.trim().is_empty() {
            source.origin_prompt_event_id = origin_prompt_event_id.to_string();
        }
        items.push(source);
    }

    if items.is_empty() {
        if let Some(brief) = session.materialization.artifact_brief.as_ref() {
            for (index, anchor) in brief.factual_anchors.iter().enumerate() {
                let anchor: &str = anchor.trim();
                if anchor.is_empty() {
                    continue;
                }
                items.push(ArtifactSourceReference {
                    source_id: format!("anchor:{index}"),
                    origin_prompt_event_id: origin_prompt_event_id.to_string(),
                    title: anchor.to_string(),
                    url: None,
                    domain: None,
                    excerpt: Some(anchor.to_string()),
                    retrieved_at_ms: None,
                    freshness: Some("brief_anchor".to_string()),
                    reason: "Required factual anchor from the artifact brief.".to_string(),
                });
            }
            for (index, hint) in brief.reference_hints.iter().enumerate() {
                let hint: &str = hint.trim();
                if hint.is_empty() {
                    continue;
                }
                items.push(ArtifactSourceReference {
                    source_id: format!("hint:{index}"),
                    origin_prompt_event_id: origin_prompt_event_id.to_string(),
                    title: hint.to_string(),
                    url: None,
                    domain: None,
                    excerpt: None,
                    retrieved_at_ms: None,
                    freshness: Some("reference_hint".to_string()),
                    reason: "Reference hint captured while shaping the artifact brief.".to_string(),
                });
            }
        }
    }

    for exemplar in &session.materialization.retrieved_exemplars {
        items.push(ArtifactSourceReference {
            source_id: format!("exemplar:{}", exemplar.record_id),
            origin_prompt_event_id: origin_prompt_event_id.to_string(),
            title: exemplar.title.clone(),
            url: None,
            domain: None,
            excerpt: Some(exemplar.summary.clone()),
            retrieved_at_ms: None,
            freshness: Some("artifact_exemplar".to_string()),
            reason: exemplar.quality_rationale.clone(),
        });
    }

    let summary = if items.is_empty() {
        String::new()
    } else {
        format!(
            "Grounded this artifact run with {} source item(s).",
            items.len()
        )
    };

    ArtifactSourcePack { summary, items }
}

pub(super) fn prompt_requires_source_pack(
    session: &ChatArtifactSession,
    source_pack: &ArtifactSourcePack,
) -> bool {
    if !source_pack.items.is_empty() {
        return true;
    }

    let prompt = session.outcome_request.raw_prompt.to_ascii_lowercase();
    [
        "explainer",
        "guide",
        "overview",
        "primer",
        "current",
        "latest",
        "source-backed",
        "sources",
    ]
    .iter()
    .any(|keyword| prompt.contains(keyword))
}

pub(super) fn build_source_activity_preview(source_pack: &ArtifactSourcePack) -> Option<String> {
    let lines = source_pack
        .items
        .iter()
        .take(6)
        .map(|item| {
            let title = item.title.trim();
            let domain = item.domain.as_deref().unwrap_or_default().trim();
            if title.is_empty() {
                domain.to_string()
            } else if domain.is_empty() {
                title.to_string()
            } else {
                format!("{title} - {domain}")
            }
        })
        .filter(|line| !line.trim().is_empty())
        .collect::<Vec<_>>();
    if lines.is_empty() {
        None
    } else {
        Some(lines.join("\n"))
    }
}
