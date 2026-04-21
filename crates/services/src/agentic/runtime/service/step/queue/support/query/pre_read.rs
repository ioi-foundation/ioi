#![allow(dead_code)]

use super::*;
use ioi_types::app::agentic::WebRetrievalContract;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RetrievalAffordanceKind {
    DirectCitationRead,
    DiscoveryExpansionSeedRead,
}

include!("pre_read/candidate_filtering.rs");

include!("pre_read/url_policy.rs");

include!("pre_read/candidate_collection.rs");

include!("pre_read/selection_metrics.rs");

include!("pre_read/planning.rs");
