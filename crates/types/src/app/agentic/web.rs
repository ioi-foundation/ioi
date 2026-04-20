// Path: crates/types/src/app/agentic/web.rs

use parity_scale_codec::{Decode, Encode};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// A typed, provenance-tracked bundle of web evidence produced by deterministic tools.
///
/// This is designed to be:
/// - Graph-friendly (easy to pass between nodes)
/// - Citation-friendly (stable `source_id` references)
/// - Auditable (explicit tool/backend + timestamps)
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct WebEvidenceBundle {
    /// Schema version for forward compatibility.
    pub schema_version: u32,
    /// UNIX timestamp (milliseconds) when the evidence was retrieved.
    pub retrieved_at_ms: u64,
    /// Tool that produced this bundle (e.g. "web__search", "web__read").
    pub tool: String,
    /// Backend identifier (e.g. "edge:ddg").
    pub backend: String,
    /// Optional user query for search bundles.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
    /// Optional canonical URL for the retrieval operation (SERP URL or read URL).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Ranked sources discovered from a SERP (or a single source for `web__read`).
    #[serde(default)]
    pub sources: Vec<WebSource>,
    /// Typed discovery-time observations for individual source candidates.
    #[serde(default)]
    pub source_observations: Vec<WebSourceObservation>,
    /// Extracted documents (typically one for `web__read`).
    #[serde(default)]
    pub documents: Vec<WebDocument>,
    /// Discovery-time provider candidates observed during retrieval.
    #[serde(default)]
    pub provider_candidates: Vec<WebProviderCandidate>,
    /// Typed structural retrieval contract used to plan discovery and verification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retrieval_contract: Option<WebRetrievalContract>,
}

/// Typed structural retrieval requirements inferred before provider discovery.
#[derive(
    Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq, Encode, Decode, Default,
)]
pub struct WebRetrievalContract {
    /// Schema/contract version for replay and migration.
    pub contract_version: String,
    /// Minimum number of distinct answer entities or records required.
    pub entity_cardinality_min: u32,
    /// Whether the answer must compare multiple entities or records.
    pub comparison_required: bool,
    /// Whether the answer depends on current or latest state.
    pub currentness_required: bool,
    /// Whether the query requires runtime locality binding (for example, "near me").
    pub runtime_locality_required: bool,
    /// Minimum number of independent final sources required.
    pub source_independence_min: u32,
    /// Minimum citations required per answer entity/story.
    pub citation_count_min: u32,
    /// Prefer providers exposing direct structured records.
    pub structured_record_preferred: bool,
    /// Prefer providers exposing ordered collections.
    pub ordered_collection_preferred: bool,
    /// Prefer providers exposing link collections for expansion.
    pub link_collection_preferred: bool,
    /// Prefer providers exposing canonical detail link-outs.
    pub canonical_link_out_preferred: bool,
    /// Require geo-scoped detail records when locality is involved.
    pub geo_scoped_detail_required: bool,
    /// Require discovery/index surfaces before final reads.
    pub discovery_surface_required: bool,
    /// Require distinct answer entities even when sources share a domain.
    pub entity_diversity_required: bool,
    /// Require a scalar quantitative measure in the final answer.
    pub scalar_measure_required: bool,
    /// Whether browser-mediated fallback is admissible.
    pub browser_fallback_allowed: bool,
}

/// Structural retrieval affordances observed for a provider candidate.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WebRetrievalAffordance {
    /// Provider supports a queryable search/index surface.
    QueryableIndex,
    /// Provider supports an ordered collection surface.
    OrderedCollection,
    /// Provider supports a generic collection of outbound links.
    LinkCollection,
    /// Provider exposes a directly readable detail document.
    DetailDocument,
    /// Provider exposes a structured record body.
    StructuredRecord,
    /// Provider exposes timestamped observations or records.
    TimestampedRecord,
    /// Provider exposes locality- or geo-scoped records.
    GeoScopedRecord,
    /// Provider exposes a canonical link-out to a detail record.
    CanonicalLinkOut,
    /// Provider requires browser-mediated retrieval.
    BrowserRetrieval,
}

/// Structural expansion affordances observed for an individual discovered source.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WebSourceExpansionAffordance {
    /// The source exposes a JSON-LD ItemList surface that can be expanded into child links.
    JsonLdItemList,
    /// The source exposes a structural collection of child links that can be expanded.
    ChildLinkCollection,
}

/// Provider candidate observed during discovery before final source selection.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct WebProviderCandidate {
    /// Stable provider identifier.
    pub provider_id: String,
    /// Structural affordances observed for this provider adapter.
    #[serde(default)]
    pub affordances: Vec<WebRetrievalAffordance>,
    /// Canonical request URL used during discovery, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_url: Option<String>,
    /// Number of filtered sources contributed by this candidate.
    #[serde(default)]
    pub source_count: u32,
    /// Whether the provider probe completed successfully.
    #[serde(default)]
    pub success: bool,
    /// Whether the provider contributed final selected sources.
    #[serde(default)]
    pub selected: bool,
    /// Optional challenge/block reason encountered during discovery.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub challenge_reason: Option<String>,
}

/// Discovery-time structural observations for a specific source candidate.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct WebSourceObservation {
    /// Final destination URL for the observed source.
    pub url: String,
    /// Structural affordances observed for this source candidate.
    #[serde(default)]
    pub affordances: Vec<WebRetrievalAffordance>,
    /// Structural expansion affordances observed for this source candidate.
    #[serde(default)]
    pub expansion_affordances: Vec<WebSourceExpansionAffordance>,
}

/// A single web source (search result).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct WebSource {
    /// Stable identifier for citations (hex SHA-256 of the normalized final URL).
    pub source_id: String,
    /// Optional rank (1-based) in the search results.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rank: Option<u32>,
    /// Final destination URL.
    pub url: String,
    /// Optional title extracted from SERP.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Optional snippet extracted from SERP.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snippet: Option<String>,
    /// Optional domain (host) for quick filtering.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
}

/// Extracted content for a URL read.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct WebDocument {
    /// The `source_id` this document corresponds to.
    pub source_id: String,
    /// URL that was read.
    pub url: String,
    /// Optional title extracted from the page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Extracted page text.
    pub content_text: String,
    /// Hex SHA-256 of `content_text` bytes.
    pub content_hash: String,
    /// Deterministic quote spans over `content_text` for citation placement.
    #[serde(default)]
    pub quote_spans: Vec<WebQuoteSpan>,
}

/// A quoted span within a `WebDocument.content_text` buffer.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct WebQuoteSpan {
    /// Start byte offset (inclusive) in the UTF-8 buffer.
    pub start_byte: u32,
    /// End byte offset (exclusive) in the UTF-8 buffer.
    pub end_byte: u32,
    /// The extracted quote text for convenience.
    pub quote: String,
}

#[cfg(test)]
#[path = "web/tests.rs"]
mod tests;
