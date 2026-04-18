mod extraction;
mod orchestration;
mod profile;

pub use orchestration::edge_web_search;
#[allow(unused_imports)]
pub(crate) use orchestration::{
    aggregated_sources_meet_pre_read_floor, should_stop_provider_aggregation,
};
#[allow(unused_imports)]
pub(crate) use profile::{
    provider_backend_id, provider_candidate_is_usable, provider_candidate_selection_key,
    provider_descriptor_is_admissible, provider_probe_priority_key, search_budget_exhausted,
    search_provider_registry, search_provider_requirements_from_contract,
    SearchProviderCandidateSelectionInput, SearchProviderDescriptor,
};
