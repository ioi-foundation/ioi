use super::super::constants::EDGE_WEB_SEARCH_TOTAL_BUDGET_MS;
use super::super::types::{
    SearchProviderRequirements, SearchProviderStage, SearchStructuralAffordance,
};
use super::super::util::now_ms;
use ioi_types::app::agentic::WebRetrievalContract;
use std::cmp::Reverse;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SearchProviderDescriptor {
    pub stage: SearchProviderStage,
    pub affordances: &'static [SearchStructuralAffordance],
    pub locality_binding_required: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SearchProviderCandidateSelectionInput<'a> {
    pub descriptor: &'a SearchProviderDescriptor,
    pub source_count: usize,
    pub challenge_present: bool,
}

const QUERYABLE_INDEX_AFFORDANCES: &[SearchStructuralAffordance] =
    &[SearchStructuralAffordance::QueryableIndex];
const QUERYABLE_INDEX_BROWSER_AFFORDANCES: &[SearchStructuralAffordance] = &[
    SearchStructuralAffordance::QueryableIndex,
    SearchStructuralAffordance::BrowserRetrieval,
];
const GEO_STRUCTURED_DETAIL_AFFORDANCES: &[SearchStructuralAffordance] = &[
    SearchStructuralAffordance::DetailDocument,
    SearchStructuralAffordance::StructuredRecord,
    SearchStructuralAffordance::TimestampedRecord,
    SearchStructuralAffordance::GeoScopedRecord,
];
const LOCAL_BUSINESS_DIRECTORY_AFFORDANCES: &[SearchStructuralAffordance] = &[
    SearchStructuralAffordance::LinkCollection,
    SearchStructuralAffordance::CanonicalLinkOut,
    SearchStructuralAffordance::GeoScopedRecord,
];
const ORDERED_COLLECTION_AFFORDANCES: &[SearchStructuralAffordance] =
    &[SearchStructuralAffordance::OrderedCollection];

const SEARCH_PROVIDER_REGISTRY: &[SearchProviderDescriptor] = &[
    SearchProviderDescriptor {
        stage: SearchProviderStage::WeatherGovLocalityDetail,
        affordances: GEO_STRUCTURED_DETAIL_AFFORDANCES,
        locality_binding_required: true,
    },
    SearchProviderDescriptor {
        stage: SearchProviderStage::RestaurantJiLocalityDirectory,
        affordances: LOCAL_BUSINESS_DIRECTORY_AFFORDANCES,
        locality_binding_required: true,
    },
    SearchProviderDescriptor {
        stage: SearchProviderStage::BraveHttp,
        affordances: QUERYABLE_INDEX_AFFORDANCES,
        locality_binding_required: false,
    },
    SearchProviderDescriptor {
        stage: SearchProviderStage::GoogleNewsTopStoriesRss,
        affordances: ORDERED_COLLECTION_AFFORDANCES,
        locality_binding_required: false,
    },
    SearchProviderDescriptor {
        stage: SearchProviderStage::BingNewsRss,
        affordances: ORDERED_COLLECTION_AFFORDANCES,
        locality_binding_required: false,
    },
    SearchProviderDescriptor {
        stage: SearchProviderStage::GoogleNewsRss,
        affordances: ORDERED_COLLECTION_AFFORDANCES,
        locality_binding_required: false,
    },
    SearchProviderDescriptor {
        stage: SearchProviderStage::BingHttp,
        affordances: QUERYABLE_INDEX_AFFORDANCES,
        locality_binding_required: false,
    },
    SearchProviderDescriptor {
        stage: SearchProviderStage::BingSearchRss,
        affordances: QUERYABLE_INDEX_AFFORDANCES,
        locality_binding_required: false,
    },
    SearchProviderDescriptor {
        stage: SearchProviderStage::GoogleHttp,
        affordances: QUERYABLE_INDEX_AFFORDANCES,
        locality_binding_required: false,
    },
    SearchProviderDescriptor {
        stage: SearchProviderStage::DdgHttp,
        affordances: QUERYABLE_INDEX_AFFORDANCES,
        locality_binding_required: false,
    },
    SearchProviderDescriptor {
        stage: SearchProviderStage::DdgBrowser,
        affordances: QUERYABLE_INDEX_BROWSER_AFFORDANCES,
        locality_binding_required: false,
    },
];

pub(crate) fn search_provider_registry() -> &'static [SearchProviderDescriptor] {
    SEARCH_PROVIDER_REGISTRY
}

pub(crate) fn provider_supports_affordance(
    descriptor: &SearchProviderDescriptor,
    affordance: SearchStructuralAffordance,
) -> bool {
    descriptor.affordances.contains(&affordance)
}

pub(crate) fn provider_backend_id(stage: SearchProviderStage) -> &'static str {
    match stage {
        SearchProviderStage::WeatherGovLocalityDetail => "edge:weather-gov:detail",
        SearchProviderStage::RestaurantJiLocalityDirectory => "edge:restaurantji:directory",
        SearchProviderStage::BraveHttp => "edge:brave:http",
        SearchProviderStage::DdgHttp => "edge:ddg:http",
        SearchProviderStage::DdgBrowser => "edge:ddg:browser",
        SearchProviderStage::BingHttp => "edge:bing:http",
        SearchProviderStage::BingSearchRss => "edge:bing-search-rss",
        SearchProviderStage::BingNewsRss => "edge:bing-news-rss",
        SearchProviderStage::GoogleHttp => "edge:google:http",
        SearchProviderStage::GoogleNewsRss => "edge:google-news-rss",
        SearchProviderStage::GoogleNewsTopStoriesRss => "edge:google-news-top-stories-rss",
    }
}

pub(crate) fn search_provider_requirements_from_contract(
    contract: &WebRetrievalContract,
    locality_scope: Option<&str>,
) -> SearchProviderRequirements {
    let direct_single_record_snapshot = contract.entity_cardinality_min <= 1
        && contract.structured_record_preferred
        && !contract.comparison_required
        && !contract.ordered_collection_preferred
        && !contract.link_collection_preferred
        && !contract.canonical_link_out_preferred;
    let locality_scope_required = locality_scope
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false)
        || contract.runtime_locality_required;
    SearchProviderRequirements {
        freshness_bias: contract.currentness_required,
        ordered_collection_preferred: contract.ordered_collection_preferred,
        structured_record_preferred: contract.structured_record_preferred,
        link_collection_preferred: contract.link_collection_preferred,
        canonical_link_out_preferred: contract.canonical_link_out_preferred,
        currentness_required: contract.currentness_required,
        locality_scope_required,
        discovery_surface_required: contract.discovery_surface_required
            && !direct_single_record_snapshot,
        geo_scoped_detail_required: locality_scope_required && contract.geo_scoped_detail_required,
        browser_fallback_allowed: contract.browser_fallback_allowed,
    }
}

fn provider_supports_discovery_surface(descriptor: &SearchProviderDescriptor) -> bool {
    provider_supports_affordance(descriptor, SearchStructuralAffordance::QueryableIndex)
        || provider_supports_affordance(descriptor, SearchStructuralAffordance::OrderedCollection)
        || provider_supports_affordance(descriptor, SearchStructuralAffordance::LinkCollection)
}

fn provider_supports_structured_lookup(descriptor: &SearchProviderDescriptor) -> bool {
    provider_supports_affordance(descriptor, SearchStructuralAffordance::StructuredRecord)
        || provider_supports_affordance(descriptor, SearchStructuralAffordance::QueryableIndex)
}

fn provider_supports_geo_scoped_resolution(descriptor: &SearchProviderDescriptor) -> bool {
    provider_supports_affordance(descriptor, SearchStructuralAffordance::GeoScopedRecord)
        || provider_supports_affordance(descriptor, SearchStructuralAffordance::QueryableIndex)
}

fn provider_supports_link_out_resolution(descriptor: &SearchProviderDescriptor) -> bool {
    provider_supports_affordance(descriptor, SearchStructuralAffordance::CanonicalLinkOut)
        || provider_supports_affordance(descriptor, SearchStructuralAffordance::QueryableIndex)
}

fn provider_supports_expansion_surface(descriptor: &SearchProviderDescriptor) -> bool {
    provider_supports_affordance(descriptor, SearchStructuralAffordance::LinkCollection)
        && provider_supports_link_out_resolution(descriptor)
}

pub(crate) fn provider_descriptor_is_admissible(
    requirements: &SearchProviderRequirements,
    descriptor: &SearchProviderDescriptor,
) -> bool {
    if descriptor.locality_binding_required && !requirements.locality_scope_required {
        return false;
    }
    if requirements.discovery_surface_required && !provider_supports_discovery_surface(descriptor) {
        return false;
    }
    if requirements.ordered_collection_preferred
        && !provider_supports_affordance(descriptor, SearchStructuralAffordance::OrderedCollection)
        && !provider_supports_affordance(descriptor, SearchStructuralAffordance::QueryableIndex)
        && !(requirements.link_collection_preferred
            && requirements.canonical_link_out_preferred
            && provider_supports_expansion_surface(descriptor))
    {
        return false;
    }
    if requirements.structured_record_preferred && !provider_supports_structured_lookup(descriptor)
    {
        return false;
    }
    if requirements.link_collection_preferred
        && !provider_supports_affordance(descriptor, SearchStructuralAffordance::LinkCollection)
        && !provider_supports_affordance(descriptor, SearchStructuralAffordance::QueryableIndex)
    {
        return false;
    }
    if requirements.canonical_link_out_preferred
        && !provider_supports_link_out_resolution(descriptor)
    {
        return false;
    }
    if requirements.geo_scoped_detail_required
        && !provider_supports_geo_scoped_resolution(descriptor)
    {
        return false;
    }
    if requirements.geo_scoped_detail_required
        && !requirements.link_collection_preferred
        && !requirements.canonical_link_out_preferred
        && !provider_supports_affordance(descriptor, SearchStructuralAffordance::QueryableIndex)
        && !provider_supports_affordance(descriptor, SearchStructuralAffordance::StructuredRecord)
        && !provider_supports_affordance(descriptor, SearchStructuralAffordance::DetailDocument)
    {
        return false;
    }
    true
}

pub(crate) fn provider_candidate_is_usable(
    requirements: &SearchProviderRequirements,
    candidate: SearchProviderCandidateSelectionInput<'_>,
) -> bool {
    candidate.source_count > 0
        && (!candidate.challenge_present
            || provider_supports_affordance(
                candidate.descriptor,
                SearchStructuralAffordance::BrowserRetrieval,
            ))
        && (requirements.browser_fallback_allowed
            || !provider_supports_affordance(
                candidate.descriptor,
                SearchStructuralAffordance::BrowserRetrieval,
            ))
}

pub(crate) fn provider_candidate_selection_key(
    requirements: &SearchProviderRequirements,
    candidate: SearchProviderCandidateSelectionInput<'_>,
) -> (usize, Reverse<usize>, usize, usize) {
    let supports_queryable_index = provider_supports_affordance(
        candidate.descriptor,
        SearchStructuralAffordance::QueryableIndex,
    );
    let supports_structured_record = provider_supports_affordance(
        candidate.descriptor,
        SearchStructuralAffordance::StructuredRecord,
    );
    let supports_timestamped_record = provider_supports_affordance(
        candidate.descriptor,
        SearchStructuralAffordance::TimestampedRecord,
    );
    let supports_geo_scoped_record = provider_supports_affordance(
        candidate.descriptor,
        SearchStructuralAffordance::GeoScopedRecord,
    );
    let supports_ordered_collection = provider_supports_affordance(
        candidate.descriptor,
        SearchStructuralAffordance::OrderedCollection,
    );
    let supports_link_collection = provider_supports_affordance(
        candidate.descriptor,
        SearchStructuralAffordance::LinkCollection,
    );
    let supports_canonical_link_out = provider_supports_affordance(
        candidate.descriptor,
        SearchStructuralAffordance::CanonicalLinkOut,
    );
    let satisfies_expansion_surface = requirements.link_collection_preferred
        && requirements.canonical_link_out_preferred
        && supports_link_collection
        && (supports_canonical_link_out || supports_queryable_index);
    let ordered_collection_penalty = if requirements.ordered_collection_preferred {
        usize::from(!supports_ordered_collection && !satisfies_expansion_surface)
    } else if requirements.structured_record_preferred {
        usize::from(supports_ordered_collection)
    } else {
        0
    };
    let structured_record_penalty =
        usize::from(requirements.structured_record_preferred && !supports_structured_record);
    let timestamped_record_penalty =
        usize::from(requirements.currentness_required && !supports_timestamped_record);
    let geo_scoped_record_penalty = usize::from(
        requirements.geo_scoped_detail_required
            && !supports_geo_scoped_record
            && !supports_queryable_index,
    );
    let link_collection_penalty = usize::from(
        requirements.link_collection_preferred
            && !supports_link_collection
            && !supports_queryable_index,
    );
    let canonical_link_out_penalty = usize::from(
        requirements.canonical_link_out_preferred
            && !supports_canonical_link_out
            && !supports_queryable_index,
    );
    let browser_penalty = usize::from(provider_supports_affordance(
        candidate.descriptor,
        SearchStructuralAffordance::BrowserRetrieval,
    ));
    let challenge_penalty = usize::from(candidate.challenge_present);
    let registry_index = search_provider_registry()
        .iter()
        .position(|descriptor| descriptor.stage == candidate.descriptor.stage)
        .unwrap_or(usize::MAX);

    (
        ordered_collection_penalty
            + structured_record_penalty
            + timestamped_record_penalty
            + geo_scoped_record_penalty
            + link_collection_penalty
            + canonical_link_out_penalty,
        Reverse(candidate.source_count),
        challenge_penalty + browser_penalty,
        registry_index,
    )
}

pub(crate) fn provider_probe_priority_key(
    requirements: &SearchProviderRequirements,
    descriptor: &SearchProviderDescriptor,
) -> (usize, usize, usize, String) {
    let supports_queryable_index =
        provider_supports_affordance(descriptor, SearchStructuralAffordance::QueryableIndex);
    let supports_structured_record =
        provider_supports_affordance(descriptor, SearchStructuralAffordance::StructuredRecord);
    let supports_timestamped_record =
        provider_supports_affordance(descriptor, SearchStructuralAffordance::TimestampedRecord);
    let supports_geo_scoped_record =
        provider_supports_affordance(descriptor, SearchStructuralAffordance::GeoScopedRecord);
    let supports_ordered_collection =
        provider_supports_affordance(descriptor, SearchStructuralAffordance::OrderedCollection);
    let supports_link_collection =
        provider_supports_affordance(descriptor, SearchStructuralAffordance::LinkCollection);
    let supports_canonical_link_out =
        provider_supports_affordance(descriptor, SearchStructuralAffordance::CanonicalLinkOut);
    let supports_browser =
        provider_supports_affordance(descriptor, SearchStructuralAffordance::BrowserRetrieval);
    let satisfies_expansion_surface = requirements.link_collection_preferred
        && requirements.canonical_link_out_preferred
        && supports_link_collection
        && (supports_canonical_link_out || supports_queryable_index);

    let ordered_collection_penalty = if requirements.ordered_collection_preferred {
        usize::from(!supports_ordered_collection && !satisfies_expansion_surface)
    } else if requirements.structured_record_preferred {
        usize::from(supports_ordered_collection)
    } else {
        0
    };
    let structured_record_penalty =
        usize::from(requirements.structured_record_preferred && !supports_structured_record);
    let timestamped_record_penalty =
        usize::from(requirements.currentness_required && !supports_timestamped_record);
    let geo_scoped_record_penalty = usize::from(
        requirements.geo_scoped_detail_required
            && !supports_geo_scoped_record
            && !supports_queryable_index,
    );
    let link_collection_penalty = usize::from(
        requirements.link_collection_preferred
            && !supports_link_collection
            && !supports_queryable_index,
    );
    let canonical_link_out_penalty = usize::from(
        requirements.canonical_link_out_preferred
            && !supports_canonical_link_out
            && !supports_queryable_index,
    );
    let browser_penalty = usize::from(supports_browser && !requirements.browser_fallback_allowed);
    let queryable_index_penalty = if requirements.structured_record_preferred
        || requirements.link_collection_preferred
        || requirements.ordered_collection_preferred
    {
        usize::from(supports_queryable_index)
    } else {
        0
    };
    let registry_index = search_provider_registry()
        .iter()
        .position(|candidate| candidate.stage == descriptor.stage)
        .unwrap_or(usize::MAX);

    (
        ordered_collection_penalty
            + structured_record_penalty
            + timestamped_record_penalty
            + geo_scoped_record_penalty
            + link_collection_penalty
            + canonical_link_out_penalty
            + queryable_index_penalty,
        browser_penalty,
        registry_index,
        provider_backend_id(descriptor.stage).to_string(),
    )
}

pub(crate) fn search_budget_exhausted(started_at_ms: u64) -> bool {
    now_ms().saturating_sub(started_at_ms) >= EDGE_WEB_SEARCH_TOTAL_BUDGET_MS
}
