use crate::agentic::desktop::service::step::signals::{
    analyze_metric_schema, analyze_query_facets, MetricAxis,
};
use crate::agentic::desktop::types::PendingSearchReadSummary;
use std::collections::{BTreeMap, BTreeSet};
use url::Url;

const CLAIM_UNAVAILABLE_MARKERS: [&str; 6] = [
    "no data available",
    "not available",
    "unavailable",
    "-- no data",
    "n/a",
    "unknown",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ConstraintScope {
    TimeSensitive,
    PublicFact,
    WorkspaceBound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceClass {
    Structured,
    Html,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtractionMethod {
    StructuredParse,
    MetricSchemaParse,
    TextExtraction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimValueState {
    NumericObserved,
    PresentWithoutNumeric,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvenancePolicy {
    pub min_independent_sources: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputContract {
    pub requires_absolute_utc: bool,
    pub unresolved_requires_caveat: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConstraintSet {
    pub target: String,
    pub required_facets: BTreeSet<MetricAxis>,
    pub scopes: BTreeSet<ConstraintScope>,
    pub provenance_policy: ProvenancePolicy,
    pub output_contract: OutputContract,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evidence {
    pub evidence_ref: String,
    pub locator: String,
    pub publisher: String,
    pub fetched_at_utc: String,
    pub content_type: EvidenceClass,
    pub access_path: String,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claim {
    pub facet: MetricAxis,
    pub value_state: ClaimValueState,
    pub observed_at_utc: Option<String>,
    pub asserted_at_utc: Option<String>,
    pub scope: BTreeSet<ConstraintScope>,
    pub evidence_ref: String,
    pub extraction_confidence: u8,
    pub method: ExtractionMethod,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalClaim {
    pub facet: MetricAxis,
    pub value_state: ClaimValueState,
    pub observed_at_utc: Option<String>,
    pub asserted_at_utc: Option<String>,
    pub evidence_ref: String,
    pub extraction_confidence: u8,
    pub method: ExtractionMethod,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClaimGraph {
    pub clusters: BTreeMap<MetricAxis, Vec<CanonicalClaim>>,
    pub independent_publishers: BTreeSet<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolutionPolicy {
    pub authority_weight: i32,
    pub recency_weight: i32,
    pub extraction_weight: i32,
    pub unavailable_penalty: i32,
    pub min_resolution_score: i32,
}

impl Default for ResolutionPolicy {
    fn default() -> Self {
        Self {
            authority_weight: 12,
            recency_weight: 8,
            extraction_weight: 8,
            unavailable_penalty: 20,
            min_resolution_score: 20,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedFacet {
    pub facet: MetricAxis,
    pub resolved: bool,
    pub reason_code: Option<String>,
    pub evidence_refs: BTreeSet<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvelopeStatus {
    Valid,
    ValidWithCaveats,
    Invalid,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EnvelopeVerification {
    pub status: Option<EnvelopeStatus>,
    pub unresolved_facets: BTreeSet<MetricAxis>,
    pub resolved_facets: BTreeSet<MetricAxis>,
    pub reason_codes: BTreeSet<String>,
    pub independent_source_count: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CandidateEvidenceScore {
    pub total_score: i32,
    pub required_facets: usize,
    pub numeric_observed_facets: usize,
    pub present_without_numeric_facets: usize,
    pub unavailable_facets: usize,
    pub missing_facets: usize,
    pub observed_timestamp_facets: usize,
}

impl CandidateEvidenceScore {
    pub fn has_numeric_observation(&self) -> bool {
        self.numeric_observed_facets > 0
    }
}

pub fn compile_constraint_set(
    query: &str,
    required_facets: BTreeSet<MetricAxis>,
    min_independent_sources: usize,
) -> ConstraintSet {
    let facets = analyze_query_facets(query);
    let mut scopes = BTreeSet::new();
    if facets.time_sensitive_public_fact {
        scopes.insert(ConstraintScope::TimeSensitive);
        scopes.insert(ConstraintScope::PublicFact);
    }
    if facets.workspace_constrained {
        scopes.insert(ConstraintScope::WorkspaceBound);
    }

    ConstraintSet {
        target: query.trim().to_string(),
        required_facets,
        scopes,
        provenance_policy: ProvenancePolicy {
            min_independent_sources: min_independent_sources.max(1),
        },
        output_contract: OutputContract {
            requires_absolute_utc: facets.time_sensitive_public_fact,
            unresolved_requires_caveat: true,
        },
    }
}

pub fn verify_claim_envelope(
    constraints: &ConstraintSet,
    sources: &[PendingSearchReadSummary],
    fetched_at_utc: &str,
    policy: ResolutionPolicy,
) -> EnvelopeVerification {
    let evidence = build_evidence(sources, fetched_at_utc);
    let claims = evidence
        .iter()
        .flat_map(extract_claims)
        .map(canonicalize_claim)
        .collect::<Vec<_>>();
    let graph = build_claim_graph(&evidence, &claims);
    let resolved = resolve_facets(constraints, &graph, policy);

    let mut unresolved_facets = BTreeSet::new();
    let mut resolved_facets = BTreeSet::new();
    let mut reason_codes = BTreeSet::new();
    if constraints.required_facets.is_empty() {
        if constraints.scopes.contains(&ConstraintScope::TimeSensitive) {
            let has_numeric_observation = claims
                .iter()
                .any(|claim| matches!(claim.value_state, ClaimValueState::NumericObserved));
            if !has_numeric_observation {
                reason_codes.insert("time_sensitive_numeric_observation_missing".to_string());
            }
        }
    } else {
        for facet in resolved {
            if facet.resolved {
                resolved_facets.insert(facet.facet);
            } else {
                unresolved_facets.insert(facet.facet);
                if let Some(code) = facet.reason_code {
                    reason_codes.insert(code);
                }
            }
        }
    }

    if graph.independent_publishers.len() < constraints.provenance_policy.min_independent_sources {
        reason_codes.insert("provenance_min_sources_unmet".to_string());
    }
    if constraints.output_contract.requires_absolute_utc && fetched_at_utc.trim().is_empty() {
        reason_codes.insert("utc_timestamp_missing".to_string());
    }

    let status = if reason_codes.contains("provenance_min_sources_unmet")
        || reason_codes.contains("utc_timestamp_missing")
    {
        EnvelopeStatus::Invalid
    } else if !unresolved_facets.is_empty()
        || reason_codes.contains("time_sensitive_numeric_observation_missing")
    {
        EnvelopeStatus::ValidWithCaveats
    } else {
        EnvelopeStatus::Valid
    };

    EnvelopeVerification {
        status: Some(status),
        unresolved_facets,
        resolved_facets,
        reason_codes,
        independent_source_count: graph.independent_publishers.len(),
    }
}

pub fn score_evidence_candidate(
    constraints: &ConstraintSet,
    source: &PendingSearchReadSummary,
    fetched_at_utc: &str,
    policy: ResolutionPolicy,
) -> CandidateEvidenceScore {
    let evidence = build_evidence(std::slice::from_ref(source), fetched_at_utc);
    let claims = evidence
        .iter()
        .flat_map(extract_claims)
        .map(canonicalize_claim)
        .collect::<Vec<_>>();

    let mut best_claim_by_facet: BTreeMap<MetricAxis, CanonicalClaim> = BTreeMap::new();
    for claim in claims {
        let next_score = claim_resolution_score(&claim, policy);
        let should_replace = best_claim_by_facet
            .get(&claim.facet)
            .map(|current| claim_resolution_score(current, policy) < next_score)
            .unwrap_or(true);
        if should_replace {
            best_claim_by_facet.insert(claim.facet, claim);
        }
    }

    let required_facets = if constraints.required_facets.is_empty() {
        best_claim_by_facet.keys().copied().collect::<BTreeSet<_>>()
    } else {
        constraints.required_facets.clone()
    };

    let mut score = CandidateEvidenceScore {
        required_facets: required_facets.len(),
        ..CandidateEvidenceScore::default()
    };

    for facet in required_facets {
        let Some(claim) = best_claim_by_facet.get(&facet) else {
            score.missing_facets += 1;
            score.total_score -= policy.unavailable_penalty;
            continue;
        };

        score.total_score += claim_resolution_score(claim, policy);
        if claim.observed_at_utc.is_some() {
            score.observed_timestamp_facets += 1;
        }

        match claim.value_state {
            ClaimValueState::NumericObserved => score.numeric_observed_facets += 1,
            ClaimValueState::PresentWithoutNumeric => score.present_without_numeric_facets += 1,
            ClaimValueState::Unavailable => score.unavailable_facets += 1,
        }
    }

    score
}

fn build_evidence(sources: &[PendingSearchReadSummary], fetched_at_utc: &str) -> Vec<Evidence> {
    sources
        .iter()
        .enumerate()
        .map(|(idx, source)| {
            let title = source.title.as_deref().unwrap_or_default();
            let publisher = publisher_from_url(source.url.as_str());
            Evidence {
                evidence_ref: format!("evidence:{}", idx + 1),
                locator: source.url.clone(),
                publisher,
                fetched_at_utc: fetched_at_utc.to_string(),
                content_type: infer_content_type(source.url.as_str()),
                access_path: "web_read".to_string(),
                text: format!("{} {}", title, source.excerpt),
            }
        })
        .collect()
}

fn infer_content_type(url: &str) -> EvidenceClass {
    let lower = url.to_ascii_lowercase();
    if lower.ends_with(".json")
        || lower.contains("api.")
        || lower.contains("/api/")
        || lower.contains("format=json")
    {
        return EvidenceClass::Structured;
    }
    if lower.starts_with("http://") || lower.starts_with("https://") {
        return EvidenceClass::Html;
    }
    EvidenceClass::Unknown
}

fn publisher_from_url(url: &str) -> String {
    Url::parse(url)
        .ok()
        .and_then(|parsed| parsed.host_str().map(str::to_ascii_lowercase))
        .unwrap_or_else(|| "unknown".to_string())
}

fn extract_claims(evidence: &Evidence) -> Vec<Claim> {
    let schema = analyze_metric_schema(&evidence.text);
    if schema.axis_hits.is_empty() {
        return Vec::new();
    }
    let unavailable = text_has_unavailable_markers(evidence.text.as_str());
    let mut out = Vec::new();
    for facet in schema.axis_hits.iter().copied() {
        let value_state = if unavailable {
            ClaimValueState::Unavailable
        } else if schema.has_current_observation_payload() && schema.numeric_token_hits > 0 {
            ClaimValueState::NumericObserved
        } else {
            ClaimValueState::PresentWithoutNumeric
        };

        out.push(Claim {
            facet,
            value_state,
            observed_at_utc: if schema.timestamp_hits > 0 {
                Some(evidence.fetched_at_utc.clone())
            } else {
                None
            },
            asserted_at_utc: Some(evidence.fetched_at_utc.clone()),
            scope: infer_claim_scope(&schema),
            evidence_ref: evidence.evidence_ref.clone(),
            extraction_confidence: extraction_confidence(&schema, unavailable),
            method: extraction_method(evidence.content_type),
        });
    }
    out
}

fn infer_claim_scope(
    schema: &crate::agentic::desktop::service::step::signals::MetricSchemaProfile,
) -> BTreeSet<ConstraintScope> {
    let mut scope = BTreeSet::new();
    if schema.observation_hits > 0 || schema.timestamp_hits > 0 {
        scope.insert(ConstraintScope::TimeSensitive);
    }
    if !schema.axis_hits.is_empty() {
        scope.insert(ConstraintScope::PublicFact);
    }
    scope
}

fn extraction_confidence(
    schema: &crate::agentic::desktop::service::step::signals::MetricSchemaProfile,
    unavailable: bool,
) -> u8 {
    if unavailable {
        return 40;
    }
    let mut score = 40u8;
    if schema.numeric_token_hits > 0 {
        score = score.saturating_add(25);
    }
    if schema.unit_hits > 0 {
        score = score.saturating_add(15);
    }
    if schema.timestamp_hits > 0 {
        score = score.saturating_add(10);
    }
    if schema.has_current_observation_payload() {
        score = score.saturating_add(10);
    }
    score.min(100)
}

fn extraction_method(content_type: EvidenceClass) -> ExtractionMethod {
    match content_type {
        EvidenceClass::Structured => ExtractionMethod::StructuredParse,
        EvidenceClass::Html => ExtractionMethod::MetricSchemaParse,
        EvidenceClass::Unknown => ExtractionMethod::TextExtraction,
    }
}

fn text_has_unavailable_markers(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    CLAIM_UNAVAILABLE_MARKERS
        .iter()
        .any(|marker| lower.contains(marker))
}

fn canonicalize_claim(claim: Claim) -> CanonicalClaim {
    CanonicalClaim {
        facet: claim.facet,
        value_state: claim.value_state,
        observed_at_utc: claim.observed_at_utc.map(normalize_utc_like),
        asserted_at_utc: claim.asserted_at_utc.map(normalize_utc_like),
        evidence_ref: claim.evidence_ref,
        extraction_confidence: claim.extraction_confidence,
        method: claim.method,
    }
}

fn normalize_utc_like(value: String) -> String {
    value.trim().to_ascii_uppercase()
}

fn build_claim_graph(evidence: &[Evidence], claims: &[CanonicalClaim]) -> ClaimGraph {
    let mut clusters: BTreeMap<MetricAxis, Vec<CanonicalClaim>> = BTreeMap::new();
    for claim in claims {
        clusters.entry(claim.facet).or_default().push(claim.clone());
    }

    let independent_publishers = evidence
        .iter()
        .map(|record| record.publisher.clone())
        .filter(|publisher| !publisher.trim().is_empty() && publisher != "unknown")
        .collect::<BTreeSet<_>>();

    ClaimGraph {
        clusters,
        independent_publishers,
    }
}

fn resolve_facets(
    constraints: &ConstraintSet,
    graph: &ClaimGraph,
    policy: ResolutionPolicy,
) -> Vec<ResolvedFacet> {
    let mut out = Vec::new();
    for facet in &constraints.required_facets {
        let candidates = graph.clusters.get(facet).cloned().unwrap_or_default();
        if candidates.is_empty() {
            out.push(ResolvedFacet {
                facet: *facet,
                resolved: false,
                reason_code: Some("facet_missing".to_string()),
                evidence_refs: BTreeSet::new(),
            });
            continue;
        }

        let winner = candidates
            .iter()
            .max_by_key(|claim| claim_resolution_score(claim, policy))
            .cloned();
        let Some(winner) = winner else {
            out.push(ResolvedFacet {
                facet: *facet,
                resolved: false,
                reason_code: Some("facet_missing".to_string()),
                evidence_refs: BTreeSet::new(),
            });
            continue;
        };

        let score = claim_resolution_score(&winner, policy);
        let resolved = score >= policy.min_resolution_score
            && matches!(winner.value_state, ClaimValueState::NumericObserved);
        let reason_code = if resolved {
            None
        } else {
            Some(
                match winner.value_state {
                    ClaimValueState::Unavailable => "facet_unavailable_in_evidence",
                    ClaimValueState::PresentWithoutNumeric => "facet_numeric_missing",
                    ClaimValueState::NumericObserved => "facet_resolution_score_low",
                }
                .to_string(),
            )
        };
        let mut evidence_refs = BTreeSet::new();
        evidence_refs.insert(winner.evidence_ref.clone());
        out.push(ResolvedFacet {
            facet: *facet,
            resolved,
            reason_code,
            evidence_refs,
        });
    }
    out
}

fn claim_resolution_score(claim: &CanonicalClaim, policy: ResolutionPolicy) -> i32 {
    let base = match claim.value_state {
        ClaimValueState::NumericObserved => 32,
        ClaimValueState::PresentWithoutNumeric => 12,
        ClaimValueState::Unavailable => -policy.unavailable_penalty,
    };
    let method_score = match claim.method {
        ExtractionMethod::StructuredParse => policy.extraction_weight,
        ExtractionMethod::MetricSchemaParse => policy.extraction_weight / 2,
        ExtractionMethod::TextExtraction => 0,
    };
    let recency_score = if claim.observed_at_utc.is_some() {
        policy.recency_weight
    } else if claim.asserted_at_utc.is_some() {
        policy.recency_weight / 2
    } else {
        0
    };
    let authority_score = policy.authority_weight;
    let confidence_score = i32::from(claim.extraction_confidence) / 5;
    base + method_score + recency_score + authority_score + confidence_score
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_source(url: &str, title: &str, excerpt: &str) -> PendingSearchReadSummary {
        PendingSearchReadSummary {
            url: url.to_string(),
            title: Some(title.to_string()),
            excerpt: excerpt.to_string(),
        }
    }

    #[test]
    fn compile_constraint_set_marks_time_sensitive_public_fact_queries() {
        let mut required = BTreeSet::new();
        required.insert(MetricAxis::Temperature);
        let constraints =
            compile_constraint_set("what's the weather right now?", required.clone(), 2);
        assert_eq!(constraints.required_facets, required);
        assert!(constraints.scopes.contains(&ConstraintScope::TimeSensitive));
        assert!(constraints.scopes.contains(&ConstraintScope::PublicFact));
        assert!(constraints.output_contract.requires_absolute_utc);
    }

    #[test]
    fn envelope_verifier_resolves_current_numeric_claims() {
        let required = [MetricAxis::Temperature, MetricAxis::Humidity]
            .into_iter()
            .collect::<BTreeSet<_>>();
        let constraints = compile_constraint_set("weather now", required, 2);
        let verification = verify_claim_envelope(
            &constraints,
            &[
                make_source(
                    "https://example.com/a",
                    "Current weather",
                    "Current conditions as of 10:35 AM: temperature 62F humidity 42%.",
                ),
                make_source(
                    "https://example.net/b",
                    "Current weather B",
                    "Current weather report: temperature 61F humidity 44%.",
                ),
            ],
            "2026-02-21T16:00:00Z",
            ResolutionPolicy::default(),
        );

        assert_eq!(verification.status, Some(EnvelopeStatus::Valid));
        assert!(verification.unresolved_facets.is_empty());
        assert!(verification
            .resolved_facets
            .contains(&MetricAxis::Temperature));
        assert!(verification.resolved_facets.contains(&MetricAxis::Humidity));
    }

    #[test]
    fn envelope_verifier_marks_unresolved_when_numeric_current_metrics_absent() {
        let required = [
            MetricAxis::Temperature,
            MetricAxis::Humidity,
            MetricAxis::Wind,
        ]
        .into_iter()
        .collect::<BTreeSet<_>>();
        let constraints = compile_constraint_set("weather now", required, 2);
        let verification = verify_claim_envelope(
            &constraints,
            &[
                make_source(
                    "https://weather.example.com/a",
                    "Weather",
                    "Current weather source page with radar and forecast updates.",
                ),
                make_source(
                    "https://weather2.example.com/b",
                    "Weather 2",
                    "Wind -- No Data Available. Humidity -- No Data Available.",
                ),
            ],
            "2026-02-21T16:00:00Z",
            ResolutionPolicy::default(),
        );

        assert_eq!(verification.status, Some(EnvelopeStatus::ValidWithCaveats));
        assert!(verification.reason_codes.contains("facet_missing"));
        assert!(verification
            .reason_codes
            .contains("facet_unavailable_in_evidence"));
        assert!(verification
            .unresolved_facets
            .contains(&MetricAxis::Temperature));
    }

    #[test]
    fn envelope_verifier_requires_numeric_observation_for_time_sensitive_empty_facet_sets() {
        let constraints =
            compile_constraint_set("what's the weather right now?", BTreeSet::new(), 1);
        let verification = verify_claim_envelope(
            &constraints,
            &[make_source(
                "https://weather.example.com/a",
                "Current weather",
                "Current weather source page with radar and forecast updates.",
            )],
            "2026-02-21T16:00:00Z",
            ResolutionPolicy::default(),
        );

        assert_eq!(verification.status, Some(EnvelopeStatus::ValidWithCaveats));
        assert!(verification
            .reason_codes
            .contains("time_sensitive_numeric_observation_missing"));
    }

    #[test]
    fn candidate_score_prefers_numeric_observation_claims() {
        let required = [MetricAxis::Rate].into_iter().collect::<BTreeSet<_>>();
        let constraints = compile_constraint_set("exchange rate right now", required, 1);
        let policy = ResolutionPolicy::default();

        let weak = make_source(
            "https://example.com/forecast",
            "FX forecast",
            "Weekly exchange-rate outlook with analyst expectations.",
        );
        let strong = make_source(
            "https://example.com/current",
            "Current exchange rate",
            "Current exchange rate as of 10:30 UTC: 1 USD = 0.92 EUR.",
        );

        let weak_score =
            score_evidence_candidate(&constraints, &weak, "2026-02-21T16:00:00Z", policy);
        let strong_score =
            score_evidence_candidate(&constraints, &strong, "2026-02-21T16:00:00Z", policy);

        assert!(strong_score.total_score > weak_score.total_score);
        assert!(strong_score.has_numeric_observation());
    }
}
