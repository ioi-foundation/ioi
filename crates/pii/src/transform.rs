// Submodule: transform (deterministic redaction + post-transform enforcement)

use ioi_types::app::{RedactionEntry, RedactionMap, RedactionType};
use ioi_types::app::agentic::{EvidenceGraph, EvidenceSpan, PiiClass, TransformAction, TransformPlan};

pub struct PostTransformReport {
    pub transformed: bool,
    pub unresolved_spans: u32,
    pub remaining_span_count: u32,
    /// True when no original raw span substrings remain in output.
    pub no_raw_substring_leak: bool,
}

fn pii_class_from_category(category: &str) -> PiiClass {
    match category.to_ascii_uppercase().as_str() {
        "API_KEY" => PiiClass::ApiKey,
        "SECRET" | "SECRET_TOKEN" | "TOKEN" => PiiClass::SecretToken,
        "EMAIL" => PiiClass::Email,
        "PHONE" => PiiClass::Phone,
        "SSN" => PiiClass::Ssn,
        "CARD_PAN" | "CARD" => PiiClass::CardPan,
        "NAME" => PiiClass::Name,
        "ADDRESS" => PiiClass::Address,
        other => PiiClass::Custom(other.to_ascii_lowercase()),
    }
}

fn redaction_type_for_class(class: &PiiClass) -> RedactionType {
    match class {
        PiiClass::ApiKey | PiiClass::SecretToken => RedactionType::Secret,
        _ => RedactionType::Pii,
    }
}

/// Canonical placeholder label for PII classes.
pub fn canonical_placeholder_label(class: &PiiClass) -> &'static str {
    match class {
        PiiClass::ApiKey => "api_key",
        PiiClass::SecretToken => "secret_token",
        PiiClass::Email => "email",
        PiiClass::Phone => "phone",
        PiiClass::Ssn => "ssn",
        PiiClass::CardPan => "card_pan",
        PiiClass::Name => "name",
        PiiClass::Address => "address",
        PiiClass::Custom(_) => "custom",
    }
}

fn scrub_with_classes(
    input: &str,
    spans: &[(usize, usize, PiiClass)],
) -> Result<(String, RedactionMap, u32)> {
    let mut sorted = spans.to_vec();
    sorted.sort_by_key(|(start, _, _)| *start);

    let mut output = String::with_capacity(input.len());
    let mut redactions = Vec::new();
    let mut last_pos = 0usize;
    let mut unresolved_spans = 0u32;

    for (start, end, class) in sorted {
        let invalid_bounds = start >= end
            || end > input.len()
            || !input.is_char_boundary(start)
            || !input.is_char_boundary(end);
        if invalid_bounds {
            unresolved_spans = unresolved_spans.saturating_add(1);
            continue;
        }

        // Overlapping spans are common when multiple detectors identify the same secret.
        // Redact any uncovered tail instead of marking overlap as unresolved.
        if end <= last_pos {
            continue;
        }
        let effective_start = start.max(last_pos);
        output.push_str(&input[last_pos..effective_start]);

        let secret_slice = &input[effective_start..end];
        let hash_arr = sha256_array(secret_slice.as_bytes())?;

        redactions.push(RedactionEntry {
            start_index: effective_start as u32,
            end_index: end as u32,
            redaction_type: redaction_type_for_class(&class),
            original_hash: hash_arr,
        });

        output.push_str(&format!(
            "<REDACTED:{}>",
            canonical_placeholder_label(&class)
        ));

        last_pos = end;
    }

    if last_pos < input.len() {
        output.push_str(&input[last_pos..]);
    }

    Ok((
        output,
        RedactionMap {
            entries: redactions,
        },
        unresolved_spans,
    ))
}

/// Canonical shared scrub loop for deterministic redaction.
pub fn scrub_text(
    input: &str,
    detections: &[(usize, usize, String)],
) -> Result<(String, RedactionMap)> {
    let spans = detections
        .iter()
        .map(|(start, end, category)| (*start, *end, pii_class_from_category(category)))
        .collect::<Vec<_>>();
    let (scrubbed, map, _) = scrub_with_classes(input, &spans)?;
    Ok((scrubbed, map))
}

fn count_remaining_raw_segments(output: &str, input: &str, spans: &[EvidenceSpan]) -> u32 {
    spans
        .iter()
        .filter(|span| {
            let start = span.start_index as usize;
            let end = span.end_index as usize;
            if start >= end || end > input.len() {
                return false;
            }
            if !input.is_char_boundary(start) || !input.is_char_boundary(end) {
                return false;
            }
            let raw = &input[start..end];
            raw.len() > 3 && output.contains(raw)
        })
        .count() as u32
}

/// Shared pipeline entrypoint for deterministic Stage C transform.
pub fn apply_transform(
    input: &str,
    evidence: &EvidenceGraph,
    outcome: &PiiRoutingOutcome,
) -> Result<(String, RedactionMap, PostTransformReport)> {
    let should_transform = matches!(
        outcome.decision,
        FirewallDecision::RedactThenAllow | FirewallDecision::TokenizeThenAllow
    );

    if !should_transform {
        return Ok((
            input.to_string(),
            RedactionMap { entries: vec![] },
            PostTransformReport {
                transformed: false,
                unresolved_spans: 0,
                remaining_span_count: 0,
                no_raw_substring_leak: true,
            },
        ));
    }

    let class_spans = evidence
        .spans
        .iter()
        .map(|span| {
            (
                span.start_index as usize,
                span.end_index as usize,
                span.pii_class.clone(),
            )
        })
        .collect::<Vec<_>>();

    let (scrubbed, map, unresolved_spans) = scrub_with_classes(input, &class_spans)?;
    let remaining_span_count = count_remaining_raw_segments(&scrubbed, input, &evidence.spans);

    Ok((
        scrubbed,
        map,
        PostTransformReport {
            transformed: true,
            unresolved_spans,
            remaining_span_count,
            no_raw_substring_leak: unresolved_spans == 0 && remaining_span_count == 0,
        },
    ))
}

