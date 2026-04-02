// Path: crates/services/src/agentic/desktop/service/memory.rs

use super::DesktopAgentService;
use crate::agentic::desktop::service::step::perception::PerceptionContext;
use crate::agentic::desktop::types::{
    AgentState, MessagePrivacyMetadata, RecordedMessage, DEFAULT_MESSAGE_PRIVACY_POLICY_ID,
    DEFAULT_MESSAGE_PRIVACY_POLICY_VERSION, DEFAULT_MESSAGE_REDACTION_VERSION,
    MESSAGE_SANITIZED_PLACEHOLDER,
};
use hex;
use ioi_api::state::StateAccess;
use ioi_api::vm::inference::InferenceRuntime;
use ioi_crypto::algorithms::hash::sha256;
use ioi_memory::{
    ArchivalMemoryQuery, HybridArchivalMemoryQuery, NewArchivalMemoryRecord, NewEnrichmentJob,
    StoredTranscriptMessage, TranscriptPrivacyMetadata, TranscriptSurface,
};
use ioi_state::tree::mhnsw::proof::RetrievalSearchPolicy;
use ioi_types::app::agentic::{ChatMessage, SwarmManifest};
use ioi_types::app::{RedactionMap, RedactionType, WorkloadMemoryRetrieveReceipt};
use ioi_types::codec;
use ioi_types::error::TransactionError;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::time::{timeout, Duration, Instant};

const SEMANTIC_INDEXING_BUDGET: Duration = Duration::from_secs(2);
const MEMORY_RUNTIME_TRANSCRIPT_SCOPE: &str = "desktop.transcript";
const MEMORY_RUNTIME_COMPACTION_SCOPE: &str = "desktop.compaction";
const MEMORY_RUNTIME_FACT_SCOPE: &str = "desktop.facts";
const MEMORY_RUNTIME_ENTITY_SCOPE: &str = "desktop.entities";
const MEMORY_RUNTIME_PROCEDURE_SCOPE: &str = "desktop.procedures";
const MEMORY_RUNTIME_UI_SCOPE: &str = "desktop.ui.memory";
const MEMORY_RUNTIME_CORE_AUDIT_SCOPE: &str = "desktop.core_memory.audit";
const MEMORY_RUNTIME_CORE_PINS_CHECKPOINT: &str = "desktop.core_memory.pins.v1";
const MEMORY_RUNTIME_LAST_UI_SNAPSHOT_CHECKPOINT: &str = "desktop.ui.last_snapshot.v1";
const MEMORY_RUNTIME_PROMPT_DIAGNOSTICS_CHECKPOINT: &str = "desktop.memory.prompt_diagnostics.v1";
const MEMORY_RUNTIME_RETRIEVAL_DIAGNOSTICS_CHECKPOINT: &str =
    "desktop.memory.retrieval_diagnostics.v1";
const MEMORY_RUNTIME_ENRICHMENT_DIAGNOSTICS_CHECKPOINT: &str =
    "desktop.memory.enrichment_diagnostics.v1";
const MEMORY_RUNTIME_EVALUATION_CHECKPOINT: &str = "desktop.memory.evaluation.v1";
const MEMORY_RUNTIME_EVALUATION_SCOPE: &str = "desktop.memory.evaluation";
const MEMORY_RUNTIME_ENRICHMENT_WORKER_ID: &str = "desktop-memory-runtime";
const MEMORY_RUNTIME_INSPECT_ID_OFFSET: u64 = 1_000_000_000_000;
const MEMORY_RUNTIME_RETRIEVAL_SCORE_THRESHOLD: f32 = 0.65;
const MEMORY_RUNTIME_GLOBAL_DIAGNOSTICS_THREAD: [u8; 32] = [0u8; 32];
const MEMORY_RUNTIME_DIAGNOSTIC_TOP_HITS: usize = 6;
const MARKET_ASSET_REGISTRY_PREFIX: &[u8] = b"market::asset::";

#[derive(Debug, Clone, Copy)]
struct CoreMemorySectionSchema {
    section: &'static str,
    label: &'static str,
    max_chars: usize,
    prompt_eligible: bool,
    tool_writable: bool,
    append_allowed: bool,
    default_pinned: bool,
}

const CORE_MEMORY_SCHEMAS: &[CoreMemorySectionSchema] = &[
    CoreMemorySectionSchema {
        section: "goal.current",
        label: "Current Goal",
        max_chars: 320,
        prompt_eligible: true,
        tool_writable: false,
        append_allowed: false,
        default_pinned: true,
    },
    CoreMemorySectionSchema {
        section: "workflow.stage",
        label: "Workflow Stage",
        max_chars: 280,
        prompt_eligible: true,
        tool_writable: true,
        append_allowed: false,
        default_pinned: true,
    },
    CoreMemorySectionSchema {
        section: "environment.window.active",
        label: "Active Window",
        max_chars: 240,
        prompt_eligible: true,
        tool_writable: false,
        append_allowed: false,
        default_pinned: true,
    },
    CoreMemorySectionSchema {
        section: "environment.browser.url",
        label: "Active Browser URL",
        max_chars: 600,
        prompt_eligible: true,
        tool_writable: false,
        append_allowed: false,
        default_pinned: true,
    },
    CoreMemorySectionSchema {
        section: "intent.resolved",
        label: "Resolved Intent",
        max_chars: 320,
        prompt_eligible: true,
        tool_writable: false,
        append_allowed: false,
        default_pinned: true,
    },
    CoreMemorySectionSchema {
        section: "execution.last_failure",
        label: "Last Failure Context",
        max_chars: 420,
        prompt_eligible: true,
        tool_writable: false,
        append_allowed: false,
        default_pinned: true,
    },
    CoreMemorySectionSchema {
        section: "environment.invariants",
        label: "Environment Invariants",
        max_chars: 900,
        prompt_eligible: true,
        tool_writable: true,
        append_allowed: true,
        default_pinned: true,
    },
    CoreMemorySectionSchema {
        section: "user.preferences.safe",
        label: "Safe User Preferences",
        max_chars: 900,
        prompt_eligible: true,
        tool_writable: true,
        append_allowed: true,
        default_pinned: false,
    },
    CoreMemorySectionSchema {
        section: "site.learned_constraints",
        label: "Learned Site Constraints",
        max_chars: 900,
        prompt_eligible: true,
        tool_writable: true,
        append_allowed: true,
        default_pinned: false,
    },
    CoreMemorySectionSchema {
        section: "workflow.notes",
        label: "Workflow Notes",
        max_chars: 1_200,
        prompt_eligible: true,
        tool_writable: true,
        append_allowed: true,
        default_pinned: false,
    },
];

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct CoreMemoryPinState {
    #[serde(default)]
    pinned_sections: BTreeMap<String, bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct UiSnapshotCheckpoint {
    #[serde(default)]
    snapshot_hash: String,
    #[serde(default)]
    artifact_id: String,
    #[serde(default)]
    archival_record_id: Option<i64>,
    #[serde(default)]
    active_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TranscriptEnrichmentPayload {
    source_record_id: i64,
    #[serde(default)]
    session_id_hex: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UiObservationEnrichmentPayload {
    source_record_id: i64,
    artifact_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ArchivalEmbeddingPayload {
    source_record_id: i64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MemoryEnrichmentTickReport {
    pub claimed: usize,
    pub completed: usize,
    pub failed: usize,
    pub inserted_records: usize,
    pub rejected_candidates: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct MemoryPromptSectionDiagnostic {
    pub name: String,
    pub included: bool,
    #[serde(default)]
    pub budget_chars: Option<usize>,
    pub original_chars: usize,
    pub rendered_chars: usize,
    pub truncated: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct MemoryPromptDiagnostics {
    pub updated_at_ms: u64,
    pub session_id_hex: String,
    pub total_chars: usize,
    #[serde(default)]
    pub prompt_hash: String,
    #[serde(default)]
    pub stable_prefix_hash: String,
    #[serde(default)]
    pub dynamic_suffix_hash: String,
    #[serde(default)]
    pub sections: Vec<MemoryPromptSectionDiagnostic>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct MemoryRetrievalHitDiagnostic {
    #[serde(default)]
    pub inspect_id: Option<u64>,
    pub scope: String,
    pub kind: String,
    pub trust_level: String,
    pub score: f32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct MemoryRetrievalDiagnostics {
    pub updated_at_ms: u64,
    pub search_count: u64,
    pub successful_search_count: u64,
    pub empty_search_count: u64,
    pub total_candidates_seen: u64,
    pub total_candidates_returned: u64,
    pub usefulness_bps: u32,
    #[serde(default)]
    pub last_query_hash: String,
    pub last_candidate_count: usize,
    pub last_returned_count: usize,
    #[serde(default)]
    pub last_hits: Vec<MemoryRetrievalHitDiagnostic>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct MemoryEnrichmentDiagnostics {
    pub updated_at_ms: u64,
    pub completed_jobs: u64,
    pub failed_jobs: u64,
    pub inserted_records: u64,
    pub rejected_candidates: u64,
    #[serde(default)]
    pub completed_by_kind: BTreeMap<String, u64>,
    #[serde(default)]
    pub failed_by_kind: BTreeMap<String, u64>,
    #[serde(default)]
    pub inserted_by_scope: BTreeMap<String, u64>,
    #[serde(default)]
    pub rejected_by_reason: BTreeMap<String, u64>,
    #[serde(default)]
    pub last_job_kind: Option<String>,
    #[serde(default)]
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct MemoryCoreSectionStatus {
    pub section: String,
    pub label: String,
    pub content: String,
    pub updated_at_ms: u64,
    pub prompt_eligible: bool,
    pub tool_writable: bool,
    pub append_allowed: bool,
    pub pinned: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct MemoryCoreAuditEntry {
    pub archival_record_id: i64,
    pub created_at_ms: u64,
    pub section: String,
    pub action: String,
    pub source: String,
    pub accepted: bool,
    #[serde(default)]
    pub rejection_reason: Option<String>,
    #[serde(default)]
    pub previous_hash: Option<String>,
    #[serde(default)]
    pub new_hash: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct MemorySessionEvaluation {
    pub updated_at_ms: u64,
    pub session_id_hex: String,
    pub transcript_message_count: u64,
    pub compacted_message_count: u64,
    pub summary_chars: usize,
    pub active_core_sections: usize,
    pub ui_snapshot_count: u64,
    pub enrichment_completed_jobs: u64,
    pub enrichment_failed_jobs: u64,
    pub score_bps: u32,
    pub assessment: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct MemorySessionStatus {
    pub session_id_hex: String,
    #[serde(default)]
    pub core_sections: Vec<MemoryCoreSectionStatus>,
    #[serde(default)]
    pub core_audits: Vec<MemoryCoreAuditEntry>,
    #[serde(default)]
    pub prompt_diagnostics: Option<MemoryPromptDiagnostics>,
    #[serde(default)]
    pub retrieval_diagnostics: Option<MemoryRetrievalDiagnostics>,
    #[serde(default)]
    pub enrichment_diagnostics: Option<MemoryEnrichmentDiagnostics>,
    #[serde(default)]
    pub evaluation: Option<MemorySessionEvaluation>,
}

#[derive(Debug, Clone, Default)]
struct DerivedRecordInsertOutcome {
    inserted: Option<(i64, String)>,
    rejection_reason: Option<String>,
}

#[derive(Debug, Clone, Default)]
struct EnrichmentJobOutcome {
    inserted_records: usize,
    rejected_candidates: usize,
    inserted_scopes: BTreeMap<String, usize>,
    rejected_by_reason: BTreeMap<String, usize>,
}

include!("core.rs");
include!("diagnostics.rs");
include!("context.rs");
include!("enrichment.rs");
include!("retrieval.rs");
include!("transcript.rs");
