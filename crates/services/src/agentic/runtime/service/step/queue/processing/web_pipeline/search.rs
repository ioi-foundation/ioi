use super::*;
use crate::agentic::runtime::service::step::queue::support::{
    merge_url_sequence, pre_read_candidate_plan_with_contract,
    retrieval_contract_is_generic_headline_collection, retrieval_contract_min_sources,
    retrieval_contract_required_distinct_domain_floor,
};
use crate::agentic::runtime::service::step::queue::web_pipeline::resolved_query_contract_with_locality_hint;

include!("search/alignment.rs");

include!("search/discovery.rs");

include!("search/planning.rs");

#[cfg(test)]
#[path = "search/tests.rs"]
mod tests;
