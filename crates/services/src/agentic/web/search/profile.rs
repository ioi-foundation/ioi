use super::*;

pub(crate) fn search_backend_profile(query: &str) -> SearchBackendProfile {
    let facets = analyze_query_facets(query);
    if facets.time_sensitive_public_fact {
        return SearchBackendProfile::ConstraintGroundedTimeSensitive;
    }
    if facets.grounded_external_required {
        return SearchBackendProfile::ConstraintGroundedExternal;
    }
    SearchBackendProfile::General
}

pub(crate) fn search_provider_plan(
    profile: SearchBackendProfile,
) -> &'static [SearchProviderStage] {
    match profile {
        SearchBackendProfile::ConstraintGroundedTimeSensitive => &[
            SearchProviderStage::BingHttp,
            SearchProviderStage::BingNewsRss,
            SearchProviderStage::GoogleHttp,
            SearchProviderStage::GoogleNewsRss,
            SearchProviderStage::DdgHttp,
            SearchProviderStage::DdgBrowser,
        ],
        SearchBackendProfile::ConstraintGroundedExternal => &[
            SearchProviderStage::BingHttp,
            SearchProviderStage::BingNewsRss,
            SearchProviderStage::DdgHttp,
            SearchProviderStage::GoogleHttp,
            SearchProviderStage::GoogleNewsRss,
            SearchProviderStage::DdgBrowser,
        ],
        SearchBackendProfile::General => &[
            SearchProviderStage::DdgHttp,
            SearchProviderStage::DdgBrowser,
            SearchProviderStage::BingHttp,
            SearchProviderStage::BingNewsRss,
            SearchProviderStage::GoogleHttp,
            SearchProviderStage::GoogleNewsRss,
        ],
    }
}

pub(crate) fn effective_search_provider_plan(query: &str) -> Vec<SearchProviderStage> {
    let profile = search_backend_profile(query);
    search_provider_plan(profile).to_vec()
}

pub(crate) fn search_budget_exhausted(started_at_ms: u64) -> bool {
    now_ms().saturating_sub(started_at_ms) >= EDGE_WEB_SEARCH_TOTAL_BUDGET_MS
}
