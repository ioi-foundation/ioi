use super::goal::{analyze_goal_signals, GoalSignalProfile};
use super::metric::{analyze_metric_schema, MetricAxis, MetricSchemaProfile};
use super::util::{marker_hits, normalize_marker_text};

const LOCAL_DISCOVERY_LOCALITY_MARKERS: [&str; 7] = [
    " near me ",
    " nearby ",
    " closest ",
    " nearest ",
    " around me ",
    " around here ",
    " in my area ",
];

const LOCAL_DISCOVERY_SCOPE_MARKERS: [&str; 4] = [" in ", " near ", " around ", " at "];

const LOCAL_DISCOVERY_STRUCTURAL_MARKERS: [&str; 18] = [
    " find ",
    " show ",
    " list ",
    " compare ",
    " comparison ",
    " versus ",
    " vs ",
    " across ",
    " between ",
    " among ",
    " top ",
    " best ",
    " rank ",
    " ranking ",
    " ranked ",
    " review ",
    " reviews ",
    " reviewed ",
];

fn has_explicit_small_count_hint(query: &str) -> bool {
    query.split_whitespace().any(|token| {
        matches!(
            token
                .trim_matches(|ch: char| !ch.is_ascii_alphanumeric())
                .to_ascii_lowercase()
                .as_str(),
            "1" | "one" | "2" | "two" | "3" | "three" | "4" | "four" | "5" | "five" | "6" | "six"
        )
    })
}

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
    let live_external_lookup_pressure = goal.prefers_live_external_research()
        || goal.external_hits > 0
        || goal.browser_hits > 0
        || goal.explicit_url_hits > 0
        || goal.provenance_hits > 0;
    let time_sensitive_public_fact = goal.recency_hits > 0
        && !workspace_constrained
        && !goal.prefers_mailbox_connector_flow()
        && (goal.public_fact_hits > 0 || live_external_lookup_pressure);
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
    let normalized_query = normalize_marker_text(query);
    let locality_scope_signal = marker_hits(&normalized_query, &LOCAL_DISCOVERY_LOCALITY_MARKERS)
        > 0
        || marker_hits(&normalized_query, &LOCAL_DISCOVERY_SCOPE_MARKERS) > 0;
    let structural_lookup_pressure =
        marker_hits(&normalized_query, &LOCAL_DISCOVERY_STRUCTURAL_MARKERS) > 0
            || has_explicit_small_count_hint(&normalized_query)
            || goal.locality_lookup_hits > 0;
    let locality_scoped_grounded_lookup =
        !workspace_constrained && locality_scope_signal && structural_lookup_pressure;
    let locality_sensitive_public_fact = (time_sensitive_public_fact
        && (metric_locality_sensitive || implicit_locality_shape))
        || locality_scoped_grounded_lookup;
    let grounded_external_required = goal.prefers_live_external_research()
        || locality_scoped_grounded_lookup
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
