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
    let constraints = compile_constraint_set("what's the weather right now?", required.clone(), 2);
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
    let constraints = compile_constraint_set("what's the weather right now?", BTreeSet::new(), 1);
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

    let weak_score = score_evidence_candidate(&constraints, &weak, "2026-02-21T16:00:00Z", policy);
    let strong_score =
        score_evidence_candidate(&constraints, &strong, "2026-02-21T16:00:00Z", policy);

    assert!(strong_score.total_score > weak_score.total_score);
    assert!(strong_score.has_numeric_observation());
}
