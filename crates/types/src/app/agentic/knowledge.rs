// Path: crates/types/src/app/agentic/knowledge.rs

use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The classification of a static knowledge chunk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub enum KnowledgeKind {
    /// A compressed file tree or directory map.
    FileIndex,
    /// Specific API documentation or framework patterns.
    ApiDocs,
    /// User-defined rules or preferences (AGENTS.md content).
    ProjectRules,
    /// A crystallized cheat-sheet from previous failures.
    LearnedPattern,
}

/// A structured unit of static context.
/// Allows the Optimizer to manage the "Long Term RAM" of the agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct StaticKnowledgeChunk {
    /// Unique identifier or path (e.g., "docs/api/v1.md" or "project_root").
    /// Used for deduplication/replacement.
    pub source: String,

    /// The type of knowledge.
    pub kind: KnowledgeKind,

    /// The actual content (compressed/minified).
    pub content: String,

    /// SHA-256 hash of the content for change detection.
    pub content_hash: [u8; 32],

    /// Block height when this chunk was last updated.
    pub updated_at: u64,

    /// Optional: Block height when this chunk expires (for cache invalidation).
    pub ttl: Option<u64>,
}

/// Defines criteria for selecting a UI element in an accessibility tree.
/// Used by Application Lenses to map raw UI nodes to semantic concepts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct ElementSelector {
    /// Matches the accessibility role (e.g. "button").
    pub role: Option<String>,
    /// Matches substring in the name/label.
    pub name_contains: Option<String>,
    /// Matches substring in the ID attribute.
    pub id_pattern: Option<String>,
}

/// Configuration for an Application Lens ("LiDAR").
/// Defines how to transform the raw accessibility tree of a specific application
/// into a semantic, agent-friendly representation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct LensConfig {
    /// The application window title this lens applies to.
    pub app_name: String,
    /// Semantic mappings: "Intent Name" -> Selector.
    /// e.g. "trade_button" -> { role: "button", name_contains: "Execute" }
    pub mappings: BTreeMap<String, ElementSelector>,
}

/// A versioned wrapper for lens configurations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub enum LensManifest {
    /// Version 1 of the Lens configuration schema.
    V1(LensConfig),
}

/// A structured, immutable fact extracted from an agent's thought or observation.
/// Used for the "Canonical Semantic Model" RAG system.
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq, Eq)]
pub struct SemanticFact {
    /// The subject of the fact (e.g., "user_budget").
    pub subject: String,
    /// The relationship (e.g., "is_limited_to").
    pub predicate: String,
    /// The value/object (e.g., "50_USD").
    pub object: String,
}
