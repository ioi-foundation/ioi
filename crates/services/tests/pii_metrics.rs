// Path: crates/services/tests/pii_metrics.rs

use ioi_types::app::agentic::EvidenceGraph;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;

use ioi_pii::{
    CimAssistContext, CimAssistProvider, CimAssistV0Provider, NoopCimAssistProvider, RiskSurface,
};
use ioi_types::app::agentic::{PiiControls, PiiTarget};
use ioi_types::app::ActionTarget;

#[derive(Debug, Deserialize)]
struct Corpus {
    positives: Vec<PositiveCase>,
    adversarial_negatives: Vec<NegativeCase>,
    #[serde(default)]
    adversarial_positives: Vec<PositiveCase>,
    #[serde(default)]
    adversarial_evasion_negatives: Vec<NegativeCase>,
    #[serde(default)]
    cim_ambiguous_cases: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct PositiveCase {
    input: String,
    expected_classes: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct NegativeCase {
    input: String,
}

#[derive(Debug, Serialize)]
struct MetricsReport {
    secret_recall_pct: f64,
    class_recall_pct: BTreeMap<String, f64>,
    adversarial_fpr_pct: f64,
    adversarial_secret_recall_pct: f64,
    adversarial_class_recall_pct: BTreeMap<String, f64>,
    adversarial_evasion_fpr_pct: f64,
    positive_count: usize,
    negative_count: usize,
    adversarial_positive_count: usize,
    adversarial_evasion_negative_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    cim_ambiguous_resolved_count: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cim_secret_recall_delta_pct: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cim_high_critical_fp_delta: Option<i64>,
}

fn class_slug(class: &ioi_types::app::agentic::PiiClass) -> String {
    match class {
        ioi_types::app::agentic::PiiClass::ApiKey => "api_key".to_string(),
        ioi_types::app::agentic::PiiClass::SecretToken => "secret_token".to_string(),
        ioi_types::app::agentic::PiiClass::Email => "email".to_string(),
        ioi_types::app::agentic::PiiClass::Phone => "phone".to_string(),
        ioi_types::app::agentic::PiiClass::Ssn => "ssn".to_string(),
        ioi_types::app::agentic::PiiClass::CardPan => "card_pan".to_string(),
        ioi_types::app::agentic::PiiClass::Name => "name".to_string(),
        ioi_types::app::agentic::PiiClass::Address => "address".to_string(),
        ioi_types::app::agentic::PiiClass::Custom(v) => format!("custom:{}", v),
    }
}

fn recall_pct(hit: u64, total: u64) -> f64 {
    if total == 0 {
        100.0
    } else {
        (hit as f64 / total as f64) * 100.0
    }
}

fn stage_a_graph(input: &str) -> EvidenceGraph {
    ioi_services::agentic::pii_substrate::build_evidence_graph(input).expect("build evidence graph")
}

fn collect_recall_with<F>(
    cases: &[PositiveCase],
    graph_for_input: F,
) -> (BTreeMap<String, u64>, BTreeMap<String, u64>)
where
    F: Fn(&str) -> EvidenceGraph,
{
    let mut hit_by_class: BTreeMap<String, u64> = BTreeMap::new();
    let mut total_by_class: BTreeMap<String, u64> = BTreeMap::new();

    for case in cases {
        let graph = graph_for_input(&case.input);
        let found: BTreeSet<String> = graph
            .spans
            .iter()
            .map(|span| class_slug(&span.pii_class))
            .collect();

        for expected in &case.expected_classes {
            *total_by_class.entry(expected.clone()).or_default() += 1;
            if found.contains(expected) {
                *hit_by_class.entry(expected.clone()).or_default() += 1;
            }
        }
    }

    (hit_by_class, total_by_class)
}

fn collect_negative_stats_with<F>(cases: &[NegativeCase], graph_for_input: F) -> (u64, u64)
where
    F: Fn(&str) -> EvidenceGraph,
{
    let mut false_positives = 0u64;
    let mut high_or_critical_false_positives = 0u64;

    for case in cases {
        let graph = graph_for_input(&case.input);
        if !graph.spans.is_empty() {
            false_positives += 1;
        }
        if graph.spans.iter().any(|span| {
            matches!(
                span.severity,
                ioi_types::app::agentic::PiiSeverity::High
                    | ioi_types::app::agentic::PiiSeverity::Critical
            )
        }) {
            high_or_critical_false_positives += 1;
        }
    }

    (false_positives, high_or_critical_false_positives)
}

fn collect_recall(cases: &[PositiveCase]) -> (BTreeMap<String, u64>, BTreeMap<String, u64>) {
    collect_recall_with(cases, stage_a_graph)
}

fn collect_negative_stats(cases: &[NegativeCase]) -> (u64, u64) {
    collect_negative_stats_with(cases, stage_a_graph)
}

fn secret_counts(
    hit_by_class: &BTreeMap<String, u64>,
    total_by_class: &BTreeMap<String, u64>,
) -> (u64, u64) {
    let hits = hit_by_class.get("api_key").copied().unwrap_or(0)
        + hit_by_class.get("secret_token").copied().unwrap_or(0);
    let total = total_by_class.get("api_key").copied().unwrap_or(0)
        + total_by_class.get("secret_token").copied().unwrap_or(0);
    (hits, total)
}

fn refine_with_provider<P: CimAssistProvider>(input: &str, provider: &P) -> EvidenceGraph {
    let base_graph = stage_a_graph(input);
    let target = PiiTarget::Action(ActionTarget::ClipboardWrite);
    let policy = PiiControls::default();
    let ctx = CimAssistContext {
        target: &target,
        risk_surface: RiskSurface::Egress,
        policy: &policy,
        supports_transform: true,
    };
    provider
        .assist(&base_graph, &ctx)
        .expect("cim assist")
        .output_graph
}

#[test]
fn pii_metrics_thresholds_and_artifact() {
    let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("pii")
        .join("corpus.json");
    let fixture = fs::read_to_string(&fixture_path).expect("read corpus fixture");
    let corpus: Corpus = serde_json::from_str(&fixture).expect("parse corpus fixture");

    let (hit_by_class, total_by_class) = collect_recall(&corpus.positives);
    let (false_positives, high_or_critical_false_positives) =
        collect_negative_stats(&corpus.adversarial_negatives);

    let (secret_hits, secret_total) = secret_counts(&hit_by_class, &total_by_class);
    let secret_recall_pct = recall_pct(secret_hits, secret_total);

    let mut class_recall_pct = BTreeMap::new();
    for class in ["email", "phone", "ssn", "card_pan"] {
        let hit = hit_by_class.get(class).copied().unwrap_or(0);
        let total = total_by_class.get(class).copied().unwrap_or(0);
        class_recall_pct.insert(class.to_string(), recall_pct(hit, total));
    }

    let adversarial_fpr_pct = if corpus.adversarial_negatives.is_empty() {
        0.0
    } else {
        (false_positives as f64 / corpus.adversarial_negatives.len() as f64) * 100.0
    };

    let (adv_hit_by_class, adv_total_by_class) = collect_recall(&corpus.adversarial_positives);
    let (adv_false_positives, adv_high_or_critical_false_positives) =
        collect_negative_stats(&corpus.adversarial_evasion_negatives);

    let (adv_secret_hits, adv_secret_total) = secret_counts(&adv_hit_by_class, &adv_total_by_class);
    let adversarial_secret_recall_pct = recall_pct(adv_secret_hits, adv_secret_total);

    let mut adversarial_class_recall_pct = BTreeMap::new();
    for class in ["email", "phone", "ssn", "card_pan"] {
        let hit = adv_hit_by_class.get(class).copied().unwrap_or(0);
        let total = adv_total_by_class.get(class).copied().unwrap_or(0);
        adversarial_class_recall_pct.insert(class.to_string(), recall_pct(hit, total));
    }

    let adversarial_evasion_fpr_pct = if corpus.adversarial_evasion_negatives.is_empty() {
        0.0
    } else {
        (adv_false_positives as f64 / corpus.adversarial_evasion_negatives.len() as f64) * 100.0
    };

    let mut report = MetricsReport {
        secret_recall_pct,
        class_recall_pct: class_recall_pct.clone(),
        adversarial_fpr_pct,
        adversarial_secret_recall_pct,
        adversarial_class_recall_pct: adversarial_class_recall_pct.clone(),
        adversarial_evasion_fpr_pct,
        positive_count: corpus.positives.len(),
        negative_count: corpus.adversarial_negatives.len(),
        adversarial_positive_count: corpus.adversarial_positives.len(),
        adversarial_evasion_negative_count: corpus.adversarial_evasion_negatives.len(),
        cim_ambiguous_resolved_count: None,
        cim_secret_recall_delta_pct: None,
        cim_high_critical_fp_delta: None,
    };

    let noop = NoopCimAssistProvider;
    let cim = CimAssistV0Provider::default();

    let (baseline_pos_hits, baseline_pos_totals) =
        collect_recall_with(&corpus.positives, |input| refine_with_provider(input, &noop));
    let (baseline_adv_hits, baseline_adv_totals) =
        collect_recall_with(&corpus.adversarial_positives, |input| {
            refine_with_provider(input, &noop)
        });
    let (cim_pos_hits, cim_pos_totals) =
        collect_recall_with(&corpus.positives, |input| refine_with_provider(input, &cim));
    let (cim_adv_hits, cim_adv_totals) =
        collect_recall_with(&corpus.adversarial_positives, |input| {
            refine_with_provider(input, &cim)
        });

    let (baseline_secret_hits_pos, baseline_secret_total_pos) =
        secret_counts(&baseline_pos_hits, &baseline_pos_totals);
    let (baseline_secret_hits_adv, baseline_secret_total_adv) =
        secret_counts(&baseline_adv_hits, &baseline_adv_totals);
    let baseline_secret_recall_pct = recall_pct(
        baseline_secret_hits_pos + baseline_secret_hits_adv,
        baseline_secret_total_pos + baseline_secret_total_adv,
    );

    let (cim_secret_hits_pos, cim_secret_total_pos) = secret_counts(&cim_pos_hits, &cim_pos_totals);
    let (cim_secret_hits_adv, cim_secret_total_adv) = secret_counts(&cim_adv_hits, &cim_adv_totals);
    let cim_secret_recall_pct = recall_pct(
        cim_secret_hits_pos + cim_secret_hits_adv,
        cim_secret_total_pos + cim_secret_total_adv,
    );

    let (_, baseline_high_critical_neg) =
        collect_negative_stats_with(&corpus.adversarial_negatives, |input| {
            refine_with_provider(input, &noop)
        });
    let (_, baseline_high_critical_evasion) =
        collect_negative_stats_with(&corpus.adversarial_evasion_negatives, |input| {
            refine_with_provider(input, &noop)
        });
    let baseline_high_critical_total = baseline_high_critical_neg + baseline_high_critical_evasion;

    let (_, cim_high_critical_neg) =
        collect_negative_stats_with(&corpus.adversarial_negatives, |input| {
            refine_with_provider(input, &cim)
        });
    let (_, cim_high_critical_evasion) =
        collect_negative_stats_with(&corpus.adversarial_evasion_negatives, |input| {
            refine_with_provider(input, &cim)
        });
    let cim_high_critical_total = cim_high_critical_neg + cim_high_critical_evasion;

    let mut ambiguous_resolved_count = 0u64;
    for input in corpus
        .cim_ambiguous_cases
        .iter()
        .map(|input| input.as_str())
        .chain(corpus.positives.iter().map(|case| case.input.as_str()))
        .chain(corpus.adversarial_positives.iter().map(|case| case.input.as_str()))
        .chain(corpus.adversarial_negatives.iter().map(|case| case.input.as_str()))
        .chain(
            corpus
                .adversarial_evasion_negatives
                .iter()
                .map(|case| case.input.as_str()),
        )
    {
        let baseline_graph = refine_with_provider(input, &noop);
        let cim_graph = refine_with_provider(input, &cim);
        if baseline_graph.ambiguous && !cim_graph.ambiguous {
            ambiguous_resolved_count = ambiguous_resolved_count.saturating_add(1);
        }
    }

    let cim_secret_recall_delta_pct = cim_secret_recall_pct - baseline_secret_recall_pct;
    let cim_high_critical_fp_delta =
        (cim_high_critical_total as i64) - (baseline_high_critical_total as i64);

    report.cim_ambiguous_resolved_count = Some(ambiguous_resolved_count);
    report.cim_secret_recall_delta_pct = Some(cim_secret_recall_delta_pct);
    report.cim_high_critical_fp_delta = Some(cim_high_critical_fp_delta);

    assert!(
        cim_secret_recall_pct >= baseline_secret_recall_pct,
        "CIM v0 regression: secret recall dropped from {:.2}% to {:.2}%",
        baseline_secret_recall_pct,
        cim_secret_recall_pct
    );
    assert!(
        cim_high_critical_total <= baseline_high_critical_total,
        "CIM v0 regression: high/critical false positives increased from {} to {}",
        baseline_high_critical_total,
        cim_high_critical_total
    );
    assert!(
        ambiguous_resolved_count > 0,
        "CIM v0 expected to resolve at least one ambiguous case in corpus"
    );

    let out_path = std::env::var("PII_METRICS_OUT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("target/pii_metrics.json"));
    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent).expect("create metrics parent dir");
    }
    fs::write(
        &out_path,
        serde_json::to_vec_pretty(&report).expect("serialize report"),
    )
    .expect("write metrics report");

    // PR hard tripwires
    assert_eq!(
        high_or_critical_false_positives, 0,
        "PR hard blocker: adversarial negatives produced high/critical detections"
    );
    assert_eq!(
        adv_high_or_critical_false_positives, 0,
        "PR hard blocker: adversarial evasion negatives produced high/critical detections"
    );
    if !corpus.adversarial_positives.is_empty() {
        let total_adv_hits: u64 = adv_hit_by_class.values().sum();
        assert!(
            total_adv_hits > 0,
            "PR hard blocker: adversarial positives had zero detections"
        );
    }

    let enforce_nightly = std::env::var("PII_NIGHTLY_ENFORCE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let enforce_adversarial = std::env::var("PII_ADVERSARIAL")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    if enforce_nightly {
        assert!(
            secret_recall_pct >= 99.5,
            "Nightly threshold failed: API_KEY/SECRET recall {:.2}% < 99.5%",
            secret_recall_pct
        );

        for class in ["email", "phone", "ssn", "card_pan"] {
            let value = class_recall_pct.get(class).copied().unwrap_or(0.0);
            assert!(
                value >= 97.0,
                "Nightly threshold failed: {} recall {:.2}% < 97%",
                class,
                value
            );
        }

        assert!(
            adversarial_fpr_pct <= 2.0,
            "Nightly threshold failed: adversarial FPR {:.2}% > 2%",
            adversarial_fpr_pct
        );
    }

    if enforce_nightly && enforce_adversarial {
        assert!(
            adversarial_secret_recall_pct >= 90.0,
            "Nightly adversarial threshold failed: secret recall {:.2}% < 90%",
            adversarial_secret_recall_pct
        );
        assert!(
            adversarial_evasion_fpr_pct <= 10.0,
            "Nightly adversarial threshold failed: evasion FPR {:.2}% > 10%",
            adversarial_evasion_fpr_pct
        );
    }
}
