// Submodule: review_summary (user-facing deterministic review summary)

use ioi_types::app::agentic::{
    EvidenceGraph, PiiClass, PiiReviewRequest, PiiReviewSummary, PiiSeverity, PiiTarget,
    Stage2Decision,
};

use crate::assist::stage2_kind;

fn pii_class_key(class: &PiiClass) -> String {
    match class {
        PiiClass::ApiKey => "api_key".to_string(),
        PiiClass::SecretToken => "secret_token".to_string(),
        PiiClass::Email => "email".to_string(),
        PiiClass::Phone => "phone".to_string(),
        PiiClass::Ssn => "ssn".to_string(),
        PiiClass::CardPan => "card_pan".to_string(),
        PiiClass::Name => "name".to_string(),
        PiiClass::Address => "address".to_string(),
        PiiClass::Custom(label) => format!("custom:{label}"),
    }
}

fn severity_key(severity: PiiSeverity) -> &'static str {
    match severity {
        PiiSeverity::Low => "low",
        PiiSeverity::Medium => "medium",
        PiiSeverity::High => "high",
        PiiSeverity::Critical => "critical",
    }
}

fn collect_low_severity_classes(graph: &EvidenceGraph) -> Vec<PiiClass> {
    let mut by_key = BTreeMap::<String, PiiClass>::new();
    for span in &graph.spans {
        if matches!(span.severity, PiiSeverity::Low) {
            by_key.insert(pii_class_key(&span.pii_class), span.pii_class.clone());
        }
    }
    by_key.into_values().collect()
}

fn has_blocking_scoped_exception_evidence(graph: &EvidenceGraph) -> bool {
    graph.spans.iter().any(|span| {
        matches!(span.severity, PiiSeverity::High | PiiSeverity::Critical)
            || matches!(span.pii_class, PiiClass::ApiKey | PiiClass::SecretToken)
    })
}

fn canonical_class_keys(classes: &[PiiClass]) -> Vec<String> {
    let mut keys = classes.iter().map(pii_class_key).collect::<Vec<_>>();
    keys.sort();
    keys.dedup();
    keys
}

fn stage2_prompt(stage2_decision: Option<&Stage2Decision>) -> String {
    match stage2_decision {
        Some(Stage2Decision::RequestMoreInfo { question_template }) => question_template.clone(),
        Some(Stage2Decision::Deny { reason }) => format!("Denied: {reason}"),
        Some(Stage2Decision::ApproveTransformPlan { plan_id }) => {
            format!("Approve deterministic transform plan '{plan_id}'?")
        }
        Some(Stage2Decision::GrantScopedException { .. }) => {
            "Grant a scoped low-severity exception for this decision?".to_string()
        }
        None => "Review PII decision and choose transform approval, scoped exception, or deny."
            .to_string(),
    }
}

/// Builds a deterministic summary blob for review UX.
pub fn build_review_summary(
    graph: &EvidenceGraph,
    target: &PiiTarget,
    stage2_decision: Option<&Stage2Decision>,
) -> PiiReviewSummary {
    let mut class_counts = BTreeMap::<String, u32>::new();
    let mut severity_counts = BTreeMap::<String, u32>::new();

    for span in &graph.spans {
        *class_counts
            .entry(pii_class_key(&span.pii_class))
            .or_default() += 1;
        *severity_counts
            .entry(severity_key(span.severity).to_string())
            .or_default() += 1;
    }

    let classes = if class_counts.is_empty() {
        "none".to_string()
    } else {
        class_counts
            .iter()
            .map(|(class, count)| format!("{class}:{count}"))
            .collect::<Vec<_>>()
            .join(",")
    };
    let severities = if severity_counts.is_empty() {
        "none".to_string()
    } else {
        severity_counts
            .iter()
            .map(|(sev, count)| format!("{sev}:{count}"))
            .collect::<Vec<_>>()
            .join(",")
    };

    PiiReviewSummary {
        target_label: target.canonical_label(),
        span_summary: format!(
            "spans={}, ambiguous={}, classes=[{}], severities=[{}]",
            graph.spans.len(),
            graph.ambiguous,
            classes,
            severities
        ),
        class_counts,
        severity_counts,
        stage2_prompt: stage2_prompt(stage2_decision),
    }
}

/// Computes destination binding hash for scoped exception verification.
