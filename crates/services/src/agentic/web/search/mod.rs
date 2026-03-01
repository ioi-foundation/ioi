use crate::agentic::desktop::service::step::signals::analyze_query_facets;
use anyhow::Result;
use ioi_drivers::browser::BrowserDriver;
use ioi_types::app::agentic::{WebEvidenceBundle, WebSource};
use std::collections::HashSet;

use super::anchor_policy::filter_provider_sources_by_query_anchors;
use super::constants::EDGE_WEB_SEARCH_TOTAL_BUDGET_MS;
use super::parsers::{
    fetch_bing_news_rss_sources, fetch_google_news_rss_sources, parse_bing_sources_from_html,
    parse_ddg_sources_from_html, parse_google_sources_from_html,
};
use super::transport::{
    detect_human_challenge, fetch_html_http_fallback, navigate_browser_retrieval, record_challenge,
};
use super::types::{SearchBackendProfile, SearchProviderStage};
use super::urls::{
    build_bing_news_rss_url, build_bing_serp_url, build_ddg_serp_url, build_google_news_rss_url,
    build_google_news_serp_url, build_google_serp_url,
};
use super::util::{domain_for_url, normalize_url_for_id, now_ms, source_id_for_url};

mod extraction;
mod orchestration;
mod profile;

use extraction::*;

pub use orchestration::edge_web_search;
pub(crate) use profile::{effective_search_provider_plan, search_budget_exhausted};
#[cfg(test)]
pub(crate) use profile::{search_backend_profile, search_provider_plan};
