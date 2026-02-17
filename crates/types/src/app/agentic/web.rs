// Path: crates/types/src/app/agentic/web.rs

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
    /// Extracted documents (typically one for `web__read`).
    #[serde(default)]
    pub documents: Vec<WebDocument>,
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
