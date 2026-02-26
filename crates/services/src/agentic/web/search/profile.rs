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
            SearchProviderStage::GoogleHttp,
            SearchProviderStage::DdgHttp,
            SearchProviderStage::DdgBrowser,
        ],
        SearchBackendProfile::ConstraintGroundedExternal => &[
            SearchProviderStage::BingHttp,
            SearchProviderStage::DdgHttp,
            SearchProviderStage::GoogleHttp,
            SearchProviderStage::GoogleNewsRss,
            SearchProviderStage::DdgBrowser,
        ],
        SearchBackendProfile::General => &[
            SearchProviderStage::DdgHttp,
            SearchProviderStage::DdgBrowser,
            SearchProviderStage::BingHttp,
            SearchProviderStage::GoogleHttp,
            SearchProviderStage::GoogleNewsRss,
        ],
    }
}

pub(crate) fn effective_search_provider_plan(query: &str) -> Vec<SearchProviderStage> {
    let profile = search_backend_profile(query);
    let mut plan = search_provider_plan(profile).to_vec();
    if query_is_generic_headline_lookup(query) {
        // Headline retrieval is time-budgeted; prioritize RSS first to maximize
        // early multi-outlet discovery hints before direct provider fallbacks.
        if let Some(idx) = plan
            .iter()
            .position(|stage| *stage == SearchProviderStage::GoogleNewsRss)
        {
            let stage = plan.remove(idx);
            let insert_idx = 0;
            plan.insert(insert_idx, stage);
        } else {
            let insert_idx = 0;
            plan.insert(insert_idx, SearchProviderStage::GoogleNewsRss);
        }
    }
    plan
}

pub(crate) fn search_budget_exhausted(started_at_ms: u64) -> bool {
    now_ms().saturating_sub(started_at_ms) >= EDGE_WEB_SEARCH_TOTAL_BUDGET_MS
}
