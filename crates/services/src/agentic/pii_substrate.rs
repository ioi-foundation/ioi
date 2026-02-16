use anyhow::Result;
use ioi_crypto::algorithms::hash::sha256;
use ioi_types::app::agentic::{
    EvidenceGraph, EvidenceSpan, PiiClass, PiiConfidenceBucket, PiiSeverity,
};
use regex::Regex;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;
use unicode_normalization::UnicodeNormalization;

const CONTEXT_RADIUS: usize = 24;

#[derive(Debug, Clone)]
struct SpanCandidate {
    start: usize,
    end: usize,
    pii_class: PiiClass,
    pattern_id: String,
    validator_passed: bool,
    evidence_source: String,
}

fn email_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)\b[a-z0-9._%+\-]+@[a-z0-9.\-\p{L}]+\.[a-z\p{L}]{2,}\b")
            .expect("email regex must compile")
    })
}

fn phone_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?x)\b(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}\b")
            .expect("phone regex must compile")
    })
}

fn ssn_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\b\d{3}[- ]?\d{2}[- ]?\d{4}\b").expect("ssn regex must compile"))
}

fn card_candidate_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\b(?:\d[ -]*?){13,19}\b").expect("card regex must compile"))
}

fn stripe_live_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\bsk_live_[A-Za-z0-9]{12,}\b").expect("stripe live regex"))
}

fn stripe_live_relaxed_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)\bsk[\s\-_]*live[\s\-_]*[a-z0-9]{12,}\b")
            .expect("stripe live relaxed regex")
    })
}

fn stripe_test_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\bsk_test_[A-Za-z0-9]{12,}\b").expect("stripe test regex"))
}

fn stripe_test_relaxed_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)\bsk[\s\-_]*test[\s\-_]*[a-z0-9]{12,}\b")
            .expect("stripe test relaxed regex")
    })
}

fn openai_proj_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\bsk-proj-[A-Za-z0-9\-_]{10,}\b").expect("openai project key regex")
    })
}

fn aws_key_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\bAKIA[0-9A-Z]{16}\b").expect("aws key regex"))
}

fn generic_secret_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)\b(?:api[_\- ]?key|secret|token|access[_\- ]?token)\b\s*[:=]\s*[A-Za-z0-9_\-]{12,}",
        )
        .expect("generic secret regex")
    })
}

fn normalize_card_digits(raw: &str) -> String {
    raw.chars().filter(|c| c.is_ascii_digit()).collect()
}

fn is_zero_width(ch: char) -> bool {
    matches!(
        ch,
        '\u{200B}' // zero-width space
            | '\u{200C}' // zero-width non-joiner
            | '\u{200D}' // zero-width joiner
            | '\u{FEFF}' // zero-width no-break space / BOM
    )
}

/// Builds a normalized view for scoring-only features.
///
/// This does not alter canonical span offsets because we never emit indices from this view.
fn scoring_view(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut previous_was_space = false;

    for ch in text.nfkc() {
        if is_zero_width(ch) {
            continue;
        }

        let mapped = if ch.is_whitespace() { ' ' } else { ch };
        if mapped == ' ' {
            if previous_was_space {
                continue;
            }
            previous_was_space = true;
        } else {
            previous_was_space = false;
        }

        out.push(mapped);
    }

    out.trim().to_string()
}

#[derive(Debug, Clone)]
struct NormalizedView {
    text: String,
    /// For each byte in `text`, stores the source byte start in original input.
    byte_to_source_start: Vec<usize>,
}

fn normalized_detection_view(text: &str) -> NormalizedView {
    let mut out = String::with_capacity(text.len());
    let mut byte_to_source_start = Vec::with_capacity(text.len());

    for (source_start, ch) in text.char_indices() {
        if is_zero_width(ch) {
            continue;
        }

        let normalized = ch.to_string().nfkc().collect::<String>();
        for normalized_ch in normalized.chars() {
            let before = out.len();
            out.push(normalized_ch);
            let emitted_len = out.len() - before;
            for _ in 0..emitted_len {
                byte_to_source_start.push(source_start);
            }
        }
    }

    NormalizedView {
        text: out,
        byte_to_source_start,
    }
}

fn map_normalized_range_to_source(
    input: &str,
    view: &NormalizedView,
    start: usize,
    end: usize,
) -> Option<(usize, usize)> {
    if start >= end || end == 0 {
        return None;
    }
    if start >= view.byte_to_source_start.len() || end > view.byte_to_source_start.len() {
        return None;
    }

    let source_start = *view.byte_to_source_start.get(start)?;
    let source_last_start = *view.byte_to_source_start.get(end - 1)?;
    let source_last_char = input[source_last_start..].chars().next()?;
    let source_end = source_last_start + source_last_char.len_utf8();

    if source_start >= source_end {
        return None;
    }
    Some((source_start, source_end))
}

fn is_valid_us_ssn(raw: &str) -> bool {
    let digits: String = raw.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() != 9 || !digits.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }

    let area = &digits[0..3];
    let group = &digits[3..5];
    let serial = &digits[5..9];

    if area == "000" || area == "666" {
        return false;
    }
    if let Ok(area_num) = area.parse::<u16>() {
        if area_num >= 900 {
            return false;
        }
    } else {
        return false;
    }

    if group == "00" || serial == "0000" {
        return false;
    }

    true
}

fn luhn_check(digits: &str) -> bool {
    if digits.len() < 13 || digits.len() > 19 || !digits.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    let mut sum = 0u32;
    let mut alternate = false;
    for ch in digits.chars().rev() {
        let mut val = ch.to_digit(10).unwrap_or(0);
        if alternate {
            val *= 2;
            if val > 9 {
                val -= 9;
            }
        }
        sum += val;
        alternate = !alternate;
    }
    sum % 10 == 0
}

fn severity_for_class(class: &PiiClass) -> PiiSeverity {
    match class {
        PiiClass::ApiKey | PiiClass::SecretToken | PiiClass::CardPan | PiiClass::Ssn => {
            PiiSeverity::High
        }
        PiiClass::Email | PiiClass::Phone | PiiClass::Name | PiiClass::Address => PiiSeverity::Low,
        PiiClass::Custom(_) => PiiSeverity::Medium,
    }
}

fn pii_class_slug(class: &PiiClass) -> String {
    match class {
        PiiClass::ApiKey => "api_key".to_string(),
        PiiClass::SecretToken => "secret_token".to_string(),
        PiiClass::Email => "email".to_string(),
        PiiClass::Phone => "phone".to_string(),
        PiiClass::Ssn => "ssn".to_string(),
        PiiClass::CardPan => "card_pan".to_string(),
        PiiClass::Name => "name".to_string(),
        PiiClass::Address => "address".to_string(),
        PiiClass::Custom(v) => format!("custom:{}", v),
    }
}

fn slice_with_context<'a>(input: &'a str, start: usize, end: usize) -> &'a str {
    let s = start.saturating_sub(CONTEXT_RADIUS);
    let e = (end + CONTEXT_RADIUS).min(input.len());
    &input[s..e]
}

fn context_keywords(text: &str) -> Vec<String> {
    const KEYWORDS: &[&str] = &[
        "cvv",
        "expiry",
        "card",
        "card number",
        "ssn",
        "social",
        "api key",
        "access token",
        "secret",
        "tracking",
        "invoice",
        "order id",
    ];

    let lc = scoring_view(text).to_ascii_lowercase();
    KEYWORDS
        .iter()
        .filter(|kw| lc.contains(**kw))
        .map(|kw| (*kw).to_string())
        .collect()
}

fn confidence_for_candidate(
    candidate: &SpanCandidate,
    context_hits: &[String],
) -> PiiConfidenceBucket {
    let has_positive = context_hits.iter().any(|k| {
        matches!(
            k.as_str(),
            "cvv"
                | "expiry"
                | "card"
                | "card number"
                | "ssn"
                | "social"
                | "api key"
                | "access token"
                | "secret"
        )
    });
    let has_negative = context_hits
        .iter()
        .any(|k| matches!(k.as_str(), "tracking" | "invoice" | "order id"));

    match candidate.pii_class {
        PiiClass::CardPan => {
            if candidate.validator_passed && has_positive {
                PiiConfidenceBucket::High
            } else if candidate.validator_passed && !has_negative {
                PiiConfidenceBucket::Medium
            } else {
                PiiConfidenceBucket::Low
            }
        }
        PiiClass::Phone => {
            if has_positive {
                PiiConfidenceBucket::High
            } else {
                PiiConfidenceBucket::Medium
            }
        }
        PiiClass::Custom(_) => PiiConfidenceBucket::Medium,
        _ => PiiConfidenceBucket::High,
    }
}

fn is_ambiguous(
    class: &PiiClass,
    confidence: PiiConfidenceBucket,
    context_hits: &[String],
) -> bool {
    let has_negative = context_hits
        .iter()
        .any(|k| matches!(k.as_str(), "tracking" | "invoice" | "order id"));
    match class {
        PiiClass::CardPan => confidence != PiiConfidenceBucket::High || has_negative,
        PiiClass::Phone => confidence == PiiConfidenceBucket::Low,
        PiiClass::Custom(_) => true,
        _ => false,
    }
}

fn push_normalized_candidate(
    candidates: &mut Vec<SpanCandidate>,
    input: &str,
    view: &NormalizedView,
    m: regex::Match<'_>,
    pii_class: PiiClass,
    pattern_id: &str,
) {
    if let Some((start, end)) = map_normalized_range_to_source(input, view, m.start(), m.end()) {
        candidates.push(SpanCandidate {
            start,
            end,
            pii_class,
            pattern_id: pattern_id.to_string(),
            validator_passed: true,
            evidence_source: "regex+normalized".to_string(),
        });
    }
}

/// Deterministic Stage A + C local-only evidence extraction.
pub fn build_evidence_graph(input: &str) -> Result<EvidenceGraph> {
    let mut source_hash = [0u8; 32];
    source_hash.copy_from_slice(sha256(input.as_bytes())?.as_ref());

    let mut candidates = Vec::<SpanCandidate>::new();

    for m in email_re().find_iter(input) {
        candidates.push(SpanCandidate {
            start: m.start(),
            end: m.end(),
            pii_class: PiiClass::Email,
            pattern_id: "email/rfc-lite".to_string(),
            validator_passed: true,
            evidence_source: "regex".to_string(),
        });
    }

    for m in phone_re().find_iter(input) {
        candidates.push(SpanCandidate {
            start: m.start(),
            end: m.end(),
            pii_class: PiiClass::Phone,
            pattern_id: "phone/e164-us-lite".to_string(),
            validator_passed: true,
            evidence_source: "regex".to_string(),
        });
    }

    for m in ssn_re().find_iter(input) {
        if is_valid_us_ssn(m.as_str()) {
            candidates.push(SpanCandidate {
                start: m.start(),
                end: m.end(),
                pii_class: PiiClass::Ssn,
                pattern_id: "ssn/us".to_string(),
                validator_passed: true,
                evidence_source: "regex+validator".to_string(),
            });
        }
    }

    for m in card_candidate_re().find_iter(input) {
        let digits = normalize_card_digits(m.as_str());
        let luhn_ok = luhn_check(&digits);
        if luhn_ok {
            candidates.push(SpanCandidate {
                start: m.start(),
                end: m.end(),
                pii_class: PiiClass::CardPan,
                pattern_id: "card/pan-luhn".to_string(),
                validator_passed: true,
                evidence_source: "regex+luhn".to_string(),
            });
        }
    }

    for m in stripe_live_re().find_iter(input) {
        candidates.push(SpanCandidate {
            start: m.start(),
            end: m.end(),
            pii_class: PiiClass::ApiKey,
            pattern_id: "secret/stripe_live".to_string(),
            validator_passed: true,
            evidence_source: "regex".to_string(),
        });
    }

    for m in stripe_test_re().find_iter(input) {
        candidates.push(SpanCandidate {
            start: m.start(),
            end: m.end(),
            pii_class: PiiClass::ApiKey,
            pattern_id: "secret/stripe_test".to_string(),
            validator_passed: true,
            evidence_source: "regex".to_string(),
        });
    }

    for m in openai_proj_re().find_iter(input) {
        candidates.push(SpanCandidate {
            start: m.start(),
            end: m.end(),
            pii_class: PiiClass::ApiKey,
            pattern_id: "secret/openai_project".to_string(),
            validator_passed: true,
            evidence_source: "regex".to_string(),
        });
    }

    for m in aws_key_re().find_iter(input) {
        candidates.push(SpanCandidate {
            start: m.start(),
            end: m.end(),
            pii_class: PiiClass::ApiKey,
            pattern_id: "secret/aws_access_key".to_string(),
            validator_passed: true,
            evidence_source: "regex".to_string(),
        });
    }

    for m in generic_secret_re().find_iter(input) {
        candidates.push(SpanCandidate {
            start: m.start(),
            end: m.end(),
            pii_class: PiiClass::SecretToken,
            pattern_id: "secret/generic_kv".to_string(),
            validator_passed: true,
            evidence_source: "regex".to_string(),
        });
    }

    // Normalized detection pass for adversarial bypasses (zero-width / NFKC variants).
    let normalized = normalized_detection_view(input);

    for m in stripe_live_re().find_iter(&normalized.text) {
        push_normalized_candidate(
            &mut candidates,
            input,
            &normalized,
            m,
            PiiClass::ApiKey,
            "secret/stripe_live",
        );
    }
    for m in stripe_test_re().find_iter(&normalized.text) {
        push_normalized_candidate(
            &mut candidates,
            input,
            &normalized,
            m,
            PiiClass::ApiKey,
            "secret/stripe_test",
        );
    }
    for m in stripe_live_relaxed_re().find_iter(&normalized.text) {
        push_normalized_candidate(
            &mut candidates,
            input,
            &normalized,
            m,
            PiiClass::ApiKey,
            "secret/stripe_live",
        );
    }
    for m in stripe_test_relaxed_re().find_iter(&normalized.text) {
        push_normalized_candidate(
            &mut candidates,
            input,
            &normalized,
            m,
            PiiClass::ApiKey,
            "secret/stripe_test",
        );
    }
    for m in openai_proj_re().find_iter(&normalized.text) {
        push_normalized_candidate(
            &mut candidates,
            input,
            &normalized,
            m,
            PiiClass::ApiKey,
            "secret/openai_project",
        );
    }
    for m in aws_key_re().find_iter(&normalized.text) {
        push_normalized_candidate(
            &mut candidates,
            input,
            &normalized,
            m,
            PiiClass::ApiKey,
            "secret/aws_access_key",
        );
    }
    for m in generic_secret_re().find_iter(&normalized.text) {
        push_normalized_candidate(
            &mut candidates,
            input,
            &normalized,
            m,
            PiiClass::SecretToken,
            "secret/generic_kv",
        );
    }
    for m in email_re().find_iter(&normalized.text) {
        push_normalized_candidate(
            &mut candidates,
            input,
            &normalized,
            m,
            PiiClass::Email,
            "email/rfc-lite",
        );
    }

    // Deduplicate same spans/class/pattern deterministically.
    let mut unique = BTreeMap::<(usize, usize, String, String), SpanCandidate>::new();
    for c in candidates {
        let class_key = pii_class_slug(&c.pii_class);
        unique.insert((c.start, c.end, class_key, c.pattern_id.clone()), c);
    }

    let mut spans = Vec::<EvidenceSpan>::new();
    let mut ambiguity = false;

    for (_, candidate) in unique {
        let ctx = slice_with_context(input, candidate.start, candidate.end);
        let keywords = context_keywords(ctx);
        let confidence = confidence_for_candidate(&candidate, &keywords);
        let span_ambiguous = is_ambiguous(&candidate.pii_class, confidence, &keywords);
        ambiguity |= span_ambiguous;

        let pii_class = candidate.pii_class.clone();
        let severity = severity_for_class(&pii_class);

        spans.push(EvidenceSpan {
            start_index: candidate.start as u32,
            end_index: candidate.end as u32,
            pii_class,
            severity,
            confidence_bucket: confidence,
            pattern_id: candidate.pattern_id,
            validator_passed: candidate.validator_passed,
            context_keywords: keywords,
            evidence_source: candidate.evidence_source,
        });
    }

    spans.sort_by_key(|s| (s.start_index, s.end_index, pii_class_slug(&s.pii_class)));

    Ok(EvidenceGraph {
        version: 1,
        source_hash,
        spans,
        ambiguous: ambiguity,
    })
}

/// Converts evidence spans to legacy `(start, end, category)` tuples used by older callsites.
pub fn to_legacy_detections(graph: &EvidenceGraph) -> Vec<(usize, usize, String)> {
    graph
        .spans
        .iter()
        .map(|s| {
            let category = match &s.pii_class {
                PiiClass::ApiKey => "API_KEY".to_string(),
                PiiClass::SecretToken => "SECRET".to_string(),
                PiiClass::Email => "EMAIL".to_string(),
                PiiClass::Phone => "PHONE".to_string(),
                PiiClass::Ssn => "SSN".to_string(),
                PiiClass::CardPan => "CARD_PAN".to_string(),
                PiiClass::Name => "NAME".to_string(),
                PiiClass::Address => "ADDRESS".to_string(),
                PiiClass::Custom(c) => c.clone(),
            };
            (s.start_index as usize, s.end_index as usize, category)
        })
        .collect()
}

/// Returns true when high severity signals are present.
pub fn has_high_severity(graph: &EvidenceGraph) -> bool {
    graph
        .spans
        .iter()
        .any(|s| matches!(s.severity, PiiSeverity::High | PiiSeverity::Critical))
}

/// Returns the set of categories found in evidence.
pub fn categories(graph: &EvidenceGraph) -> BTreeSet<String> {
    graph
        .spans
        .iter()
        .map(|s| pii_class_slug(&s.pii_class))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{build_evidence_graph, categories};

    #[test]
    fn detects_email_and_api_key() {
        let g = build_evidence_graph(
            "contact john@example.com use sk_live_abcd1234abcd1234 to continue",
        )
        .expect("graph");
        let cats = categories(&g);
        assert!(cats.contains("email"));
        assert!(cats.contains("api_key"));
    }

    #[test]
    fn validates_card_with_luhn() {
        let g = build_evidence_graph("card 4242 4242 4242 4242").expect("graph");
        let cats = categories(&g);
        assert!(cats.contains("card_pan"));
    }

    #[test]
    fn rejects_non_luhn_card_like_numbers() {
        let g = build_evidence_graph("tracking 1234 5678 9012 3456").expect("graph");
        let cats = categories(&g);
        assert!(!cats.contains("card_pan"));
    }

    #[test]
    fn detects_zero_width_secret_bypass() {
        let g = build_evidence_graph("copy sk\u{200d}_live_abcd1234abcd1234").expect("graph");
        let cats = categories(&g);
        assert!(cats.contains("api_key"));
    }

    #[test]
    fn detects_nfkc_fullwidth_secret_bypass() {
        let g = build_evidence_graph("key ｓｋ＿ｌｉｖｅ＿abcd1234abcd1234").expect("graph");
        let cats = categories(&g);
        assert!(cats.contains("api_key"));
    }
}
