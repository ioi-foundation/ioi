use crate::{CimAssistContext, CimAssistProvider, CimAssistResult};
use anyhow::Result;
use dcrypt::algorithms::hash::{HashFunction, Sha256};
use ioi_types::app::agentic::{EvidenceGraph, EvidenceSpan, PiiClass, PiiConfidenceBucket};
use parity_scale_codec::Encode;

const ASSIST_KIND: &str = "cim_v0";
const ASSIST_VERSION: &str = "cim-v0.1";

// Native v0 provider ships without external module bytes in this sprint.
// Keep this at zero to make the commitment explicit and deterministic.
const ASSIST_MODULE_HASH_V0: [u8; 32] = [0u8; 32];

const NEGATIVE_ID_CONTEXT: &[&str] = &[
    "tracking",
    "tracking id",
    "tracking number",
    "invoice",
    "invoice id",
    "order id",
    "order-id",
];

const CARD_PAYMENT_CONTEXT: &[&str] = &[
    "card",
    "card number",
    "cvv",
    "expiry",
    "payment",
    "visa",
    "mastercard",
    "amex",
];

const PHONE_CONTACT_CONTEXT: &[&str] = &["phone", "call", "sms", "text", "contact", "mobile"];

const CUSTOM_AMBIGUOUS_MARKERS: &[&str] = &["ambiguous", "heuristic", "fallback", "uncertain"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode)]
pub struct CimAssistV0Config {
    pub ruleset_version: u32,
    pub card_pan_refine_enabled: bool,
    pub phone_refine_enabled: bool,
    pub custom_refine_enabled: bool,
}

impl Default for CimAssistV0Config {
    fn default() -> Self {
        Self {
            ruleset_version: 1,
            card_pan_refine_enabled: true,
            phone_refine_enabled: true,
            custom_refine_enabled: true,
        }
    }
}

impl CimAssistV0Config {
    fn canonical_hash(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        if let Ok(digest) = Sha256::digest(&self.encode()) {
            out.copy_from_slice(digest.as_ref());
        }
        out
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CimAssistV0Provider {
    config: CimAssistV0Config,
}

impl Default for CimAssistV0Provider {
    fn default() -> Self {
        Self {
            config: CimAssistV0Config::default(),
        }
    }
}

impl CimAssistV0Provider {
    pub fn new(config: CimAssistV0Config) -> Self {
        Self { config }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SpanRefinement {
    Keep,
    Drop,
    Downgrade(PiiConfidenceBucket),
}

fn confidence_rank(bucket: PiiConfidenceBucket) -> u8 {
    match bucket {
        PiiConfidenceBucket::Low => 0,
        PiiConfidenceBucket::Medium => 1,
        PiiConfidenceBucket::High => 2,
    }
}

fn keyword_matches(span: &EvidenceSpan, needles: &[&str]) -> bool {
    span.context_keywords.iter().any(|kw| {
        let lower = kw.to_ascii_lowercase();
        needles.iter().any(|needle| lower.contains(needle))
    })
}

fn is_explicitly_ambiguous_custom(span: &EvidenceSpan) -> bool {
    let pattern = span.pattern_id.to_ascii_lowercase();
    let source = span.evidence_source.to_ascii_lowercase();
    CUSTOM_AMBIGUOUS_MARKERS
        .iter()
        .any(|marker| pattern.contains(marker) || source.contains(marker))
}

fn refine_card_pan(span: &EvidenceSpan) -> SpanRefinement {
    if !matches!(span.pii_class, PiiClass::CardPan) {
        return SpanRefinement::Keep;
    }
    let has_negative = keyword_matches(span, NEGATIVE_ID_CONTEXT);
    let has_positive = keyword_matches(span, CARD_PAYMENT_CONTEXT);
    if !has_negative || has_positive {
        return SpanRefinement::Keep;
    }

    match span.confidence_bucket {
        PiiConfidenceBucket::Low => SpanRefinement::Drop,
        PiiConfidenceBucket::Medium => {
            if span.validator_passed {
                SpanRefinement::Downgrade(PiiConfidenceBucket::Low)
            } else {
                SpanRefinement::Drop
            }
        }
        PiiConfidenceBucket::High => {
            if span.validator_passed {
                SpanRefinement::Downgrade(PiiConfidenceBucket::Medium)
            } else {
                SpanRefinement::Downgrade(PiiConfidenceBucket::Low)
            }
        }
    }
}

fn refine_phone(span: &EvidenceSpan) -> SpanRefinement {
    if !matches!(span.pii_class, PiiClass::Phone) {
        return SpanRefinement::Keep;
    }
    let has_negative = keyword_matches(span, NEGATIVE_ID_CONTEXT);
    let has_positive = keyword_matches(span, PHONE_CONTACT_CONTEXT);
    if !has_negative || has_positive {
        return SpanRefinement::Keep;
    }

    match span.confidence_bucket {
        PiiConfidenceBucket::Low | PiiConfidenceBucket::Medium => SpanRefinement::Drop,
        PiiConfidenceBucket::High => SpanRefinement::Downgrade(PiiConfidenceBucket::Medium),
    }
}

fn refine_custom(span: &EvidenceSpan, input_ambiguous: bool) -> SpanRefinement {
    if !matches!(span.pii_class, PiiClass::Custom(_)) {
        return SpanRefinement::Keep;
    }
    if !input_ambiguous {
        return SpanRefinement::Keep;
    }
    if !matches!(span.confidence_bucket, PiiConfidenceBucket::Low) {
        return SpanRefinement::Keep;
    }
    let context_is_ambiguous = keyword_matches(span, NEGATIVE_ID_CONTEXT);
    if context_is_ambiguous || is_explicitly_ambiguous_custom(span) {
        return SpanRefinement::Drop;
    }
    SpanRefinement::Keep
}

fn span_still_ambiguous(span: &EvidenceSpan) -> bool {
    let has_negative = keyword_matches(span, NEGATIVE_ID_CONTEXT);
    match &span.pii_class {
        PiiClass::CardPan => {
            has_negative
                && !keyword_matches(span, CARD_PAYMENT_CONTEXT)
                && !matches!(span.confidence_bucket, PiiConfidenceBucket::High)
        }
        PiiClass::Phone => {
            has_negative
                && !keyword_matches(span, PHONE_CONTACT_CONTEXT)
                && !matches!(span.confidence_bucket, PiiConfidenceBucket::High)
        }
        PiiClass::Custom(_) => {
            matches!(span.confidence_bucket, PiiConfidenceBucket::Low)
                && (keyword_matches(span, NEGATIVE_ID_CONTEXT)
                    || is_explicitly_ambiguous_custom(span))
        }
        _ => false,
    }
}

impl CimAssistProvider for CimAssistV0Provider {
    fn assist_kind(&self) -> &str {
        ASSIST_KIND
    }

    fn assist_version(&self) -> &str {
        ASSIST_VERSION
    }

    fn assist_config_hash(&self) -> [u8; 32] {
        self.config.canonical_hash()
    }

    fn assist_module_hash(&self) -> [u8; 32] {
        ASSIST_MODULE_HASH_V0
    }

    fn assist(
        &self,
        graph: &EvidenceGraph,
        _ctx: &CimAssistContext<'_>,
    ) -> Result<CimAssistResult> {
        let mut output = graph.clone();
        let mut refined = Vec::with_capacity(graph.spans.len());

        for span in &graph.spans {
            let mut decision = SpanRefinement::Keep;
            if self.config.card_pan_refine_enabled {
                decision = refine_card_pan(span);
            }
            if matches!(decision, SpanRefinement::Keep) && self.config.phone_refine_enabled {
                decision = refine_phone(span);
            }
            if matches!(decision, SpanRefinement::Keep) && self.config.custom_refine_enabled {
                decision = refine_custom(span, graph.ambiguous);
            }

            match decision {
                SpanRefinement::Drop => {}
                SpanRefinement::Keep => refined.push(span.clone()),
                SpanRefinement::Downgrade(target_bucket) => {
                    let mut updated = span.clone();
                    if confidence_rank(target_bucket) < confidence_rank(updated.confidence_bucket) {
                        updated.confidence_bucket = target_bucket;
                    }
                    refined.push(updated);
                }
            }
        }

        output.spans = refined;
        output.ambiguous = if graph.ambiguous {
            output.spans.iter().any(span_still_ambiguous)
        } else {
            false
        };

        let assist_applied = output != *graph;
        Ok(CimAssistResult {
            output_graph: output,
            assist_applied,
        })
    }
}
