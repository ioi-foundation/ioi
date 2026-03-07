use ioi_types::app::agentic::WebRetrievalAffordance;

pub(crate) type SearchStructuralAffordance = WebRetrievalAffordance;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct SearchProviderRequirements {
    pub freshness_bias: bool,
    pub ordered_collection_preferred: bool,
    pub structured_record_preferred: bool,
    pub link_collection_preferred: bool,
    pub canonical_link_out_preferred: bool,
    pub currentness_required: bool,
    pub locality_scope_required: bool,
    pub discovery_surface_required: bool,
    pub geo_scoped_detail_required: bool,
    pub browser_fallback_allowed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SearchProviderStage {
    WeatherGovLocalityDetail,
    BraveHttp,
    DdgHttp,
    DdgBrowser,
    BingHttp,
    BingSearchRss,
    BingNewsRss,
    GoogleHttp,
    GoogleNewsRss,
    GoogleNewsTopStoriesRss,
}
