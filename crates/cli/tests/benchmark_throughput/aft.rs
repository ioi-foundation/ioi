#![cfg(all(
    feature = "consensus-aft",
    feature = "vm-wasm",
    any(feature = "state-iavl", feature = "state-jellyfish")
))]

include!("aft/cluster_build.rs");
include!("aft/env_overrides.rs");
include!("aft/routing_defaults.rs");
include!("aft/metrics_and_churn.rs");
include!("aft/submission_channels.rs");
include!("aft/submission_summaries.rs");
include!("aft/scenarios_and_unit_tests.rs");
