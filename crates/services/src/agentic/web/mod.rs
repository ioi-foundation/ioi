mod anchor_policy;
mod constants;
mod contract;
mod google_news;
mod media;
mod parsers;
mod readability;
mod search;
mod transport;
mod types;
mod urls;
mod util;

#[cfg(test)]
mod tests;

pub use contract::derive_web_retrieval_contract;
pub(crate) use contract::{
    contract_requires_geo_scoped_entity_expansion, contract_requires_semantic_source_alignment,
    infer_query_matching_source_urls, infer_web_retrieval_contract,
    normalize_web_retrieval_contract, query_matching_source_urls, WEB_SOURCE_ALIGNMENT_MAX_SOURCES,
};
pub(crate) use media::media_provider_candidate_receipt;
pub(crate) use media::sample_local_video_preview;
pub use media::{
    edge_media_extract_multimodal_evidence, edge_media_extract_transcript, kernel_media_edit_image,
    kernel_media_generate_image, kernel_media_generate_video, kernel_media_synthesize_speech,
    kernel_media_transcribe_audio, kernel_media_vision_read, KernelMediaImageGeneration,
    KernelMediaSpeechSynthesis, KernelMediaTranscription, KernelMediaVideoGeneration,
    KernelMediaVisionRead,
};
pub(crate) use parsers::parse_json_ld_item_list_sources_from_html;
pub(crate) use parsers::parse_same_host_authority_document_sources_from_html;
pub(crate) use parsers::parse_same_host_child_collection_sources_from_html;
pub use readability::edge_web_read;
pub use search::edge_web_search;
pub(crate) use transport::{
    detect_human_challenge, fetch_html_http_fallback_browser_ua,
    fetch_structured_detail_http_fallback_browser_ua_with_final_url,
};
pub use urls::{build_ddg_serp_url, build_default_search_url};

pub(crate) use google_news::is_google_news_article_wrapper_url;
pub(crate) use parsers::parse_generic_page_source_from_html;
pub(crate) use search::{provider_backend_id, search_provider_registry};
pub(crate) use util::{normalize_url_for_id, source_id_for_url};
