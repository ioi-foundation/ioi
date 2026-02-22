mod goal;
mod metric;
mod query;
mod report;
mod source;
mod surface;
mod util;

pub use goal::{
    analyze_goal_signals, infer_intent_surface, infer_interaction_target,
    is_live_external_research_goal, is_mail_connector_tool_name, is_mailbox_connector_intent,
    query_semantic_anchor_tokens, query_structural_directive_tokens, GoalSignalProfile,
    IntentSurface,
};
pub use metric::{analyze_metric_schema, MetricAxis, MetricSchemaProfile};
pub use query::{analyze_query_facets, QueryFacetProfile};
pub use report::{
    infer_report_sections, report_section_aliases, report_section_key, report_section_label,
    ReportSectionKind,
};
pub use source::{analyze_source_record_signals, analyze_source_text_signals, SourceSignalProfile};
pub use surface::{is_browser_surface, is_system_surface};

pub const ONTOLOGY_SIGNAL_VERSION: &str = "ontology_signals_v3";
pub const LIVE_EXTERNAL_RESEARCH_SIGNAL_VERSION: &str = ONTOLOGY_SIGNAL_VERSION;
pub const WEB_EVIDENCE_SIGNAL_VERSION: &str = "web_evidence_signals_v3";

#[cfg(test)]
mod tests;
