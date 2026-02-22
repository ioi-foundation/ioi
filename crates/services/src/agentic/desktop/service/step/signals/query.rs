use super::goal::{analyze_goal_signals, GoalSignalProfile};
use super::metric::{analyze_metric_schema, MetricAxis, MetricSchemaProfile};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QueryFacetProfile {
    pub goal: GoalSignalProfile,
    pub metric_schema: MetricSchemaProfile,
    pub time_sensitive_public_fact: bool,
    pub locality_sensitive_public_fact: bool,
    pub grounded_external_required: bool,
    pub workspace_constrained: bool,
}

pub fn analyze_query_facets(query: &str) -> QueryFacetProfile {
    let goal = analyze_goal_signals(query);
    let metric_schema = analyze_metric_schema(query);
    let workspace_constrained = goal.workspace_dominant()
        || goal.filesystem_hits > 0
        || goal.command_hits > 0
        || goal.install_hits > 0;
    let time_sensitive_public_fact = goal.recency_hits > 0 && goal.public_fact_hits > 0;
    let metric_locality_sensitive = metric_schema.axis_hits.iter().any(|axis| {
        matches!(
            axis,
            MetricAxis::Temperature
                | MetricAxis::Humidity
                | MetricAxis::Wind
                | MetricAxis::Pressure
                | MetricAxis::Visibility
                | MetricAxis::AirQuality
                | MetricAxis::Precipitation
                | MetricAxis::Duration
        )
    });
    let implicit_locality_shape =
        goal.public_fact_hits > 0 && goal.external_hits == 0 && metric_schema.axis_hits.is_empty();
    let locality_sensitive_public_fact =
        time_sensitive_public_fact && (metric_locality_sensitive || implicit_locality_shape);
    let grounded_external_required = goal.prefers_live_external_research()
        || (time_sensitive_public_fact && !workspace_constrained);

    QueryFacetProfile {
        goal,
        metric_schema,
        time_sensitive_public_fact,
        locality_sensitive_public_fact,
        grounded_external_required,
        workspace_constrained,
    }
}
