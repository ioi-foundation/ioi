use super::goal::provenance_marker_hits;
use super::util::marker_hits;

const REPORT_CHANGE_MARKERS: [&str; 8] = [
    "change",
    "changed",
    "delta",
    "update",
    "new since",
    "recently",
    "what changed",
    "what is new",
];

const REPORT_HOURLY_SCOPE_MARKERS: [&str; 6] = [
    "last hour",
    "last-hour",
    "past hour",
    "past-hour",
    "this hour",
    "this-hour",
];

const REPORT_SIGNIFICANCE_MARKERS: [&str; 4] = [
    "why it matters",
    "why this matters",
    "importance",
    "implication",
];

const REPORT_IMPACT_MARKERS: [&str; 8] = [
    "impact",
    "impacts",
    "affected",
    "effect",
    "customer impact",
    "user impact",
    "blast radius",
    "who is affected",
];

const REPORT_MITIGATION_MARKERS: [&str; 7] = [
    "workaround",
    "mitigation",
    "temporary fix",
    "fallback",
    "remediation",
    "how to mitigate",
    "next steps",
];

const REPORT_TIMELINE_MARKERS: [&str; 8] = [
    "eta",
    "confidence",
    "expected",
    "timeline",
    "restoration",
    "resolution",
    "when",
    "next update",
];

const REPORT_CAVEAT_MARKERS: [&str; 4] = ["caveat", "limitation", "uncertainty", "unknown"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ReportSectionKind {
    Summary,
    RecentChange,
    Significance,
    UserImpact,
    Mitigation,
    EtaConfidence,
    Caveat,
    Evidence,
}

pub fn infer_report_sections(query: &str) -> Vec<ReportSectionKind> {
    let query_lc = query.to_ascii_lowercase();
    let mut sections = vec![ReportSectionKind::Summary];

    if marker_hits(&query_lc, &REPORT_CHANGE_MARKERS) > 0 {
        sections.push(ReportSectionKind::RecentChange);
    }
    if marker_hits(&query_lc, &REPORT_SIGNIFICANCE_MARKERS) > 0 {
        sections.push(ReportSectionKind::Significance);
    }
    if marker_hits(&query_lc, &REPORT_IMPACT_MARKERS) > 0 {
        sections.push(ReportSectionKind::UserImpact);
    }
    if marker_hits(&query_lc, &REPORT_MITIGATION_MARKERS) > 0 {
        sections.push(ReportSectionKind::Mitigation);
    }
    if marker_hits(&query_lc, &REPORT_TIMELINE_MARKERS) > 0 {
        sections.push(ReportSectionKind::EtaConfidence);
    }
    if marker_hits(&query_lc, &REPORT_CAVEAT_MARKERS) > 0 {
        sections.push(ReportSectionKind::Caveat);
    }

    if provenance_marker_hits(&query_lc) > 0 {
        sections.push(ReportSectionKind::Evidence);
    }

    if sections.len() == 1 {
        sections.push(ReportSectionKind::Evidence);
    }

    sections.sort();
    sections.dedup();
    sections
}

pub fn report_section_label(kind: ReportSectionKind, query: &str) -> String {
    match kind {
        ReportSectionKind::Summary => "What happened".to_string(),
        ReportSectionKind::RecentChange => {
            let query_lc = query.to_ascii_lowercase();
            if marker_hits(&query_lc, &REPORT_HOURLY_SCOPE_MARKERS) > 0 {
                "What changed in the last hour".to_string()
            } else {
                "What changed recently".to_string()
            }
        }
        ReportSectionKind::Significance => "Why it matters".to_string(),
        ReportSectionKind::UserImpact => "User impact".to_string(),
        ReportSectionKind::Mitigation => "Workaround".to_string(),
        ReportSectionKind::EtaConfidence => "ETA confidence".to_string(),
        ReportSectionKind::Caveat => "Caveat".to_string(),
        ReportSectionKind::Evidence => "Key evidence".to_string(),
    }
}

pub fn report_section_key(kind: ReportSectionKind) -> &'static str {
    match kind {
        ReportSectionKind::Summary => "what_happened",
        ReportSectionKind::RecentChange => "recent_change",
        ReportSectionKind::Significance => "significance",
        ReportSectionKind::UserImpact => "user_impact",
        ReportSectionKind::Mitigation => "mitigation",
        ReportSectionKind::EtaConfidence => "eta_confidence",
        ReportSectionKind::Caveat => "caveat",
        ReportSectionKind::Evidence => "key_evidence",
    }
}

pub fn report_section_aliases(kind: ReportSectionKind) -> &'static [&'static str] {
    match kind {
        ReportSectionKind::Summary => &[
            "what_happened",
            "summary",
            "overview",
            "key_evidence",
            "evidence",
        ],
        ReportSectionKind::RecentChange => &[
            "what_changed_in_the_last_hour",
            "what_changed_recently",
            "recent_change",
            "changes",
            "recent_changes",
            "delta",
        ],
        ReportSectionKind::Significance => &[
            "why_it_matters",
            "why_this_matters",
            "importance",
            "significance",
            "why_it_is_important",
        ],
        ReportSectionKind::UserImpact => &["user_impact", "impact", "customer_impact"],
        ReportSectionKind::Mitigation => &["workaround", "mitigation", "temporary_fix", "fallback"],
        ReportSectionKind::EtaConfidence => &[
            "eta_confidence",
            "eta",
            "resolution_confidence",
            "restoration_confidence",
            "confidence",
        ],
        ReportSectionKind::Caveat => &["caveat", "limitation", "uncertainty"],
        ReportSectionKind::Evidence => &["key_evidence", "evidence", "supporting_evidence"],
    }
}
