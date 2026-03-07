use super::*;

include!("general_output/rendering.rs");

include!("general_output/restaurant_output.rs");

include!("general_output/headline_output.rs");

include!("general_output/single_snapshot_output.rs");

#[test]
fn web_pipeline_user_renderer_has_no_env_gated_weather_baseline_bypass() {
    let renderer_source = include_str!("../../support/synthesis/draft/renderers/mod.rs");

    assert!(
        !renderer_source.contains("IOI_WEATHER_BASELINE_RENDER"),
        "env-gated query-specific weather baseline bypass must not exist in user synthesis renderer"
    );
    assert!(
        !renderer_source.contains("query_matches_weather_baseline_contract"),
        "query-specific weather baseline contract matching must not exist in user synthesis renderer"
    );
}
