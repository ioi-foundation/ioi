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

fn core_memory_schema(section: &str) -> Option<&'static CoreMemorySectionSchema> {
    CORE_MEMORY_SCHEMAS
        .iter()
        .find(|schema| schema.section == section)
}

fn normalize_core_memory_content(content: &str, max_chars: usize) -> String {
    let collapsed = content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join("\n");
    let trimmed = collapsed.trim();
    if trimmed.chars().count() <= max_chars {
        trimmed.to_string()
    } else {
        let mut truncated: String = trimmed.chars().take(max_chars.saturating_sub(3)).collect();
        if max_chars > 3 {
            truncated.push_str("...");
        }
        truncated
    }
}

fn content_looks_secret_like(content: &str) -> bool {
    let lowered = content.to_ascii_lowercase();
    [
        "password",
        "passwd",
        "api key",
        "api_key",
        "token",
        "secret",
        "private key",
        "bearer ",
        "authorization:",
        "ssh-rsa",
        "-----begin",
    ]
    .iter()
    .any(|needle| lowered.contains(needle))
}

fn digest_hex(input: &str) -> String {
    sha256(input.as_bytes())
        .ok()
        .map(hex::encode)
        .unwrap_or_default()
}

fn unix_timestamp_ms_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn diagnostics_thread_id(thread_id: Option<[u8; 32]>) -> [u8; 32] {
    thread_id.unwrap_or(MEMORY_RUNTIME_GLOBAL_DIAGNOSTICS_THREAD)
}

fn persist_checkpoint_json<T: Serialize>(
    memory_runtime: &ioi_memory::MemoryRuntime,
    thread_id: [u8; 32],
    checkpoint_name: &str,
    value: &T,
) -> Result<(), TransactionError> {
    let payload = serde_json::to_vec(value)
        .map_err(|error| TransactionError::Serialization(error.to_string()))?;
    memory_runtime
        .upsert_checkpoint_blob(thread_id, checkpoint_name, &payload)
        .map_err(|error| TransactionError::Invalid(format!("Internal: {}", error)))
}

fn load_checkpoint_json<T: DeserializeOwned>(
    memory_runtime: &ioi_memory::MemoryRuntime,
    thread_id: [u8; 32],
    checkpoint_name: &str,
) -> Result<Option<T>, TransactionError> {
    let Some(blob) = memory_runtime
        .load_checkpoint_blob(thread_id, checkpoint_name)
        .map_err(|error| TransactionError::Invalid(format!("Internal: {}", error)))?
    else {
        return Ok(None);
    };
    serde_json::from_slice::<T>(&blob)
        .map(Some)
        .map_err(|error| TransactionError::Serialization(error.to_string()))
}

fn load_core_memory_pin_state(
    memory_runtime: &ioi_memory::MemoryRuntime,
    thread_id: [u8; 32],
) -> Result<CoreMemoryPinState, TransactionError> {
    let Some(blob) = memory_runtime
        .load_checkpoint_blob(thread_id, MEMORY_RUNTIME_CORE_PINS_CHECKPOINT)
        .map_err(|error| TransactionError::Invalid(format!("Internal: {}", error)))?
    else {
        return Ok(CoreMemoryPinState::default());
    };
    serde_json::from_slice::<CoreMemoryPinState>(&blob)
        .map_err(|error| TransactionError::Serialization(error.to_string()))
}

fn persist_core_memory_pin_state(
    memory_runtime: &ioi_memory::MemoryRuntime,
    thread_id: [u8; 32],
    pin_state: &CoreMemoryPinState,
) -> Result<(), TransactionError> {
    let payload = serde_json::to_vec(pin_state)
        .map_err(|error| TransactionError::Serialization(error.to_string()))?;
    memory_runtime
        .upsert_checkpoint_blob(thread_id, MEMORY_RUNTIME_CORE_PINS_CHECKPOINT, &payload)
        .map_err(|error| TransactionError::Invalid(format!("Internal: {}", error)))
}

pub fn pin_core_memory_section(
    memory_runtime: &ioi_memory::MemoryRuntime,
    thread_id: [u8; 32],
    section: &str,
    pinned: bool,
) -> Result<(), TransactionError> {
    let schema = core_memory_schema(section).ok_or_else(|| {
        TransactionError::Invalid(format!("Unsupported core-memory section '{}'.", section))
    })?;
    if !schema.prompt_eligible {
        return Err(TransactionError::Invalid(format!(
            "Section '{}' is not prompt eligible and cannot be pinned.",
            section
        )));
    }
    let mut pin_state = load_core_memory_pin_state(memory_runtime, thread_id)?;
    pin_state
        .pinned_sections
        .insert(section.to_string(), pinned);
    persist_core_memory_pin_state(memory_runtime, thread_id, &pin_state)
}

fn effective_core_memory_pin(
    pin_state: &CoreMemoryPinState,
    schema: &CoreMemorySectionSchema,
) -> bool {
    pin_state
        .pinned_sections
        .get(schema.section)
        .copied()
        .unwrap_or(schema.default_pinned)
}

fn audit_core_memory_write(
    memory_runtime: &ioi_memory::MemoryRuntime,
    thread_id: [u8; 32],
    section: &str,
    action: &str,
    source: &str,
    accepted: bool,
    previous_content: Option<&str>,
    new_content: Option<&str>,
    rejection_reason: Option<&str>,
) {
    let metadata_json = serde_json::to_string(&json!({
        "trust_level": "runtime_controlled",
        "section": section,
        "action": action,
        "source": source,
        "accepted": accepted,
        "previous_hash": previous_content.map(digest_hex),
        "new_hash": new_content.map(digest_hex),
        "rejection_reason": rejection_reason,
    }))
    .unwrap_or_else(|_| "{}".to_string());
    let content = if accepted {
        format!(
            "section={section}\naction={action}\nsource={source}\nprevious={}\ncurrent={}",
            previous_content.unwrap_or("<empty>"),
            new_content.unwrap_or("<empty>")
        )
    } else {
        format!(
            "section={section}\naction={action}\nsource={source}\nrejected={}",
            rejection_reason.unwrap_or("unknown")
        )
    };
    if let Err(error) = memory_runtime.insert_archival_record(&NewArchivalMemoryRecord {
        scope: MEMORY_RUNTIME_CORE_AUDIT_SCOPE.to_string(),
        thread_id: Some(thread_id),
        kind: "core_memory_update".to_string(),
        content,
        metadata_json,
    }) {
        log::warn!("Failed to audit core memory write: {}", error);
    }
}

fn replace_core_memory_governed(
    memory_runtime: &ioi_memory::MemoryRuntime,
    thread_id: [u8; 32],
    section: &str,
    content: &str,
    source: &str,
) -> Result<(), TransactionError> {
    let schema = core_memory_schema(section).ok_or_else(|| {
        TransactionError::Invalid(format!("Unsupported core-memory section '{}'.", section))
    })?;
    let normalized = normalize_core_memory_content(content, schema.max_chars);
    let previous = memory_runtime
        .load_core_memory_section(thread_id, section)
        .map_err(|error| TransactionError::Invalid(format!("Internal: {}", error)))?;
    let previous_content = previous.as_ref().map(|section| section.content.as_str());

    if content_looks_secret_like(&normalized) {
        audit_core_memory_write(
            memory_runtime,
            thread_id,
            section,
            "replace",
            source,
            false,
            previous_content,
            None,
            Some("secret_like_content"),
        );
        return Err(TransactionError::Invalid(format!(
            "Rejected core-memory update for '{}': content appears secret-bearing.",
            section
        )));
    }

    if normalized.is_empty() {
        memory_runtime
            .delete_core_memory_section(thread_id, section)
            .map_err(|error| TransactionError::Invalid(format!("Internal: {}", error)))?;
        audit_core_memory_write(
            memory_runtime,
            thread_id,
            section,
            "clear",
            source,
            true,
            previous_content,
            None,
            None,
        );
        return Ok(());
    }

    memory_runtime
        .replace_core_memory_section(thread_id, section, &normalized)
        .map_err(|error| TransactionError::Invalid(format!("Internal: {}", error)))?;
    audit_core_memory_write(
        memory_runtime,
        thread_id,
        section,
        "replace",
        source,
        true,
        previous_content,
        Some(&normalized),
        None,
    );
    Ok(())
}

fn append_core_memory_governed(
    memory_runtime: &ioi_memory::MemoryRuntime,
    thread_id: [u8; 32],
    section: &str,
    content: &str,
    source: &str,
) -> Result<(), TransactionError> {
    let schema = core_memory_schema(section).ok_or_else(|| {
        TransactionError::Invalid(format!("Unsupported core-memory section '{}'.", section))
    })?;
    if !schema.append_allowed {
        return Err(TransactionError::Invalid(format!(
            "Core-memory section '{}' does not allow append operations.",
            section
        )));
    }
    let current = memory_runtime
        .load_core_memory_section(thread_id, section)
        .map_err(|error| TransactionError::Invalid(format!("Internal: {}", error)))?
        .map(|section| section.content)
        .unwrap_or_default();
    let appended = if current.trim().is_empty() {
        content.trim().to_string()
    } else if current.contains(content.trim()) {
        current
    } else {
        format!("{}\n{}", current.trim(), content.trim())
    };
    replace_core_memory_governed(memory_runtime, thread_id, section, &appended, source)
}

pub fn clear_core_memory_section(
    memory_runtime: &ioi_memory::MemoryRuntime,
    thread_id: [u8; 32],
    section: &str,
    source: &str,
) -> Result<(), TransactionError> {
    replace_core_memory_governed(memory_runtime, thread_id, section, "", source)
}

pub fn replace_core_memory_from_tool(
    memory_runtime: &ioi_memory::MemoryRuntime,
    thread_id: [u8; 32],
    section: &str,
    content: &str,
) -> Result<(), TransactionError> {
    let schema = core_memory_schema(section).ok_or_else(|| {
        TransactionError::Invalid(format!("Unsupported core-memory section '{}'.", section))
    })?;
    if !schema.tool_writable {
        return Err(TransactionError::Invalid(format!(
            "Core-memory section '{}' is runtime-owned and not tool-writable.",
            section
        )));
    }
    replace_core_memory_governed(memory_runtime, thread_id, section, content, "tool_request")
}

pub fn append_core_memory_from_tool(
    memory_runtime: &ioi_memory::MemoryRuntime,
    thread_id: [u8; 32],
    section: &str,
    content: &str,
) -> Result<(), TransactionError> {
    let schema = core_memory_schema(section).ok_or_else(|| {
        TransactionError::Invalid(format!("Unsupported core-memory section '{}'.", section))
    })?;
    if !schema.tool_writable {
        return Err(TransactionError::Invalid(format!(
            "Core-memory section '{}' is runtime-owned and not tool-writable.",
            section
        )));
    }
    append_core_memory_governed(memory_runtime, thread_id, section, content, "tool_request")
}

pub fn clear_core_memory_from_tool(
    memory_runtime: &ioi_memory::MemoryRuntime,
    thread_id: [u8; 32],
    section: &str,
) -> Result<(), TransactionError> {
    let schema = core_memory_schema(section).ok_or_else(|| {
        TransactionError::Invalid(format!("Unsupported core-memory section '{}'.", section))
    })?;
    if !schema.tool_writable {
        return Err(TransactionError::Invalid(format!(
            "Core-memory section '{}' is runtime-owned and not tool-writable.",
            section
        )));
    }
    clear_core_memory_section(memory_runtime, thread_id, section, "tool_request")
}

fn format_prompt_eligible_core_memory(
    memory_runtime: &ioi_memory::MemoryRuntime,
    thread_id: [u8; 32],
) -> Result<String, TransactionError> {
    let pin_state = load_core_memory_pin_state(memory_runtime, thread_id)?;
    let mut lines = Vec::new();
    for schema in CORE_MEMORY_SCHEMAS
        .iter()
        .filter(|schema| schema.prompt_eligible && effective_core_memory_pin(&pin_state, schema))
    {
        let Some(section) = memory_runtime
            .load_core_memory_section(thread_id, schema.section)
            .map_err(|error| TransactionError::Invalid(format!("Internal: {}", error)))?
        else {
            continue;
        };
        let content = section.content.trim();
        if content.is_empty() {
            continue;
        }
        lines.push(format!("- {}: {}", schema.label, content));
    }
    if lines.is_empty() {
        Ok(String::new())
    } else {
        Ok(format!("CORE MEMORY:\n{}", lines.join("\n")))
    }
}

pub fn persist_prompt_memory_diagnostics(
    memory_runtime: &ioi_memory::MemoryRuntime,
    thread_id: [u8; 32],
    diagnostics: &MemoryPromptDiagnostics,
) -> Result<(), TransactionError> {
    persist_checkpoint_json(
        memory_runtime,
        thread_id,
        MEMORY_RUNTIME_PROMPT_DIAGNOSTICS_CHECKPOINT,
        diagnostics,
    )
}

fn update_retrieval_diagnostics(
    memory_runtime: &ioi_memory::MemoryRuntime,
    query_hash: &str,
    candidate_count: usize,
    returned_count: usize,
    hits: &[MemoryRetrievalHitDiagnostic],
) -> Result<(), TransactionError> {
    let thread_id = diagnostics_thread_id(None);
    let mut diagnostics = load_checkpoint_json::<MemoryRetrievalDiagnostics>(
        memory_runtime,
        thread_id,
        MEMORY_RUNTIME_RETRIEVAL_DIAGNOSTICS_CHECKPOINT,
    )?
    .unwrap_or_default();
    diagnostics.updated_at_ms = unix_timestamp_ms_now();
    diagnostics.search_count += 1;
    diagnostics.total_candidates_seen += candidate_count as u64;
    diagnostics.total_candidates_returned += returned_count as u64;
    if returned_count > 0 {
        diagnostics.successful_search_count += 1;
    } else {
        diagnostics.empty_search_count += 1;
    }
    diagnostics.usefulness_bps = if diagnostics.search_count == 0 {
        0
    } else {
        ((diagnostics.successful_search_count.saturating_mul(10_000)) / diagnostics.search_count)
            .min(10_000) as u32
    };
    diagnostics.last_query_hash = query_hash.to_string();
    diagnostics.last_candidate_count = candidate_count;
    diagnostics.last_returned_count = returned_count;
    diagnostics.last_hits = hits.to_vec();
    persist_checkpoint_json(
        memory_runtime,
        thread_id,
        MEMORY_RUNTIME_RETRIEVAL_DIAGNOSTICS_CHECKPOINT,
        &diagnostics,
    )
}

fn update_enrichment_diagnostics_success(
    memory_runtime: &ioi_memory::MemoryRuntime,
    thread_id: Option<[u8; 32]>,
    job_kind: &str,
    outcome: &EnrichmentJobOutcome,
) -> Result<(), TransactionError> {
    let checkpoint_thread_id = diagnostics_thread_id(thread_id);
    let mut diagnostics = load_checkpoint_json::<MemoryEnrichmentDiagnostics>(
        memory_runtime,
        checkpoint_thread_id,
        MEMORY_RUNTIME_ENRICHMENT_DIAGNOSTICS_CHECKPOINT,
    )?
    .unwrap_or_default();
    diagnostics.updated_at_ms = unix_timestamp_ms_now();
    diagnostics.completed_jobs += 1;
    diagnostics.inserted_records += outcome.inserted_records as u64;
    diagnostics.rejected_candidates += outcome.rejected_candidates as u64;
    *diagnostics
        .completed_by_kind
        .entry(job_kind.to_string())
        .or_insert(0) += 1;
    for (scope, count) in &outcome.inserted_scopes {
        *diagnostics
            .inserted_by_scope
            .entry(scope.clone())
            .or_insert(0) += *count as u64;
    }
    for (reason, count) in &outcome.rejected_by_reason {
        *diagnostics
            .rejected_by_reason
            .entry(reason.clone())
            .or_insert(0) += *count as u64;
    }
    diagnostics.last_job_kind = Some(job_kind.to_string());
    diagnostics.last_error = None;
    persist_checkpoint_json(
        memory_runtime,
        checkpoint_thread_id,
        MEMORY_RUNTIME_ENRICHMENT_DIAGNOSTICS_CHECKPOINT,
        &diagnostics,
    )
}

fn update_enrichment_diagnostics_failure(
    memory_runtime: &ioi_memory::MemoryRuntime,
    thread_id: Option<[u8; 32]>,
    job_kind: &str,
    error: &str,
) -> Result<(), TransactionError> {
    let checkpoint_thread_id = diagnostics_thread_id(thread_id);
    let mut diagnostics = load_checkpoint_json::<MemoryEnrichmentDiagnostics>(
        memory_runtime,
        checkpoint_thread_id,
        MEMORY_RUNTIME_ENRICHMENT_DIAGNOSTICS_CHECKPOINT,
    )?
    .unwrap_or_default();
    diagnostics.updated_at_ms = unix_timestamp_ms_now();
    diagnostics.failed_jobs += 1;
    *diagnostics
        .failed_by_kind
        .entry(job_kind.to_string())
        .or_insert(0) += 1;
    diagnostics.last_job_kind = Some(job_kind.to_string());
    diagnostics.last_error = Some(error.to_string());
    persist_checkpoint_json(
        memory_runtime,
        checkpoint_thread_id,
        MEMORY_RUNTIME_ENRICHMENT_DIAGNOSTICS_CHECKPOINT,
        &diagnostics,
    )
}

fn derived_memory_rejection_reason(scope: &str, kind: &str, content: &str) -> Option<&'static str> {
    let trimmed = content.trim();
    if trimmed.is_empty() {
        return Some("empty_content");
    }
    if content_looks_secret_like(trimmed) {
        return Some("secret_like_content");
    }
    if trimmed.chars().count() < 12 {
        return Some("too_short");
    }
    if trimmed.chars().count() > 1_200 {
        return Some("too_long");
    }
    if kind == "entity"
        && trimmed.chars().count() > 16
        && trimmed
            .chars()
            .filter(|ch| ch.is_ascii_hexdigit() || *ch == '-' || *ch == '_')
            .count()
            == trimmed.chars().count()
    {
        return Some("opaque_identifier");
    }
    if scope == MEMORY_RUNTIME_FACT_SCOPE && !trimmed.contains(' ') {
        return Some("low_information_fact");
    }
    None
}

fn load_core_memory_sections_status(
    memory_runtime: &ioi_memory::MemoryRuntime,
    thread_id: [u8; 32],
) -> Result<Vec<MemoryCoreSectionStatus>, TransactionError> {
    let pin_state = load_core_memory_pin_state(memory_runtime, thread_id)?;
    let mut sections = Vec::new();
    for schema in CORE_MEMORY_SCHEMAS {
        let Some(section) = memory_runtime
            .load_core_memory_section(thread_id, schema.section)
            .map_err(|error| TransactionError::Invalid(format!("Internal: {}", error)))?
        else {
            continue;
        };
        if section.content.trim().is_empty() {
            continue;
        }
        sections.push(MemoryCoreSectionStatus {
            section: schema.section.to_string(),
            label: schema.label.to_string(),
            content: section.content,
            updated_at_ms: section.updated_at_ms,
            prompt_eligible: schema.prompt_eligible,
            tool_writable: schema.tool_writable,
            append_allowed: schema.append_allowed,
            pinned: effective_core_memory_pin(&pin_state, schema),
        });
    }
    Ok(sections)
}

fn load_core_memory_audits(
    memory_runtime: &ioi_memory::MemoryRuntime,
    thread_id: [u8; 32],
    limit: usize,
) -> Result<Vec<MemoryCoreAuditEntry>, TransactionError> {
    let records = memory_runtime
        .search_archival_memory(&ArchivalMemoryQuery {
            scope: MEMORY_RUNTIME_CORE_AUDIT_SCOPE.to_string(),
            thread_id: Some(thread_id),
            text: String::new(),
            limit,
        })
        .map_err(|error| TransactionError::Invalid(format!("Internal: {}", error)))?;
    let mut audits = records
        .into_iter()
        .map(|record| {
            let metadata =
                serde_json::from_str::<Value>(&record.metadata_json).unwrap_or_else(|_| json!({}));
            MemoryCoreAuditEntry {
                archival_record_id: record.id,
                created_at_ms: record.created_at_ms,
                section: metadata
                    .get("section")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                action: metadata
                    .get("action")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                source: metadata
                    .get("source")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                accepted: metadata
                    .get("accepted")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                rejection_reason: metadata
                    .get("rejection_reason")
                    .and_then(Value::as_str)
                    .map(str::to_string),
                previous_hash: metadata
                    .get("previous_hash")
                    .and_then(Value::as_str)
                    .map(str::to_string),
                new_hash: metadata
                    .get("new_hash")
                    .and_then(Value::as_str)
                    .map(str::to_string),
            }
        })
        .collect::<Vec<_>>();
    audits.sort_by(|left, right| right.created_at_ms.cmp(&left.created_at_ms));
    Ok(audits)
}

pub fn load_memory_session_status(
    memory_runtime: &ioi_memory::MemoryRuntime,
    thread_id: [u8; 32],
) -> Result<MemorySessionStatus, TransactionError> {
    Ok(MemorySessionStatus {
        session_id_hex: hex::encode(thread_id),
        core_sections: load_core_memory_sections_status(memory_runtime, thread_id)?,
        core_audits: load_core_memory_audits(memory_runtime, thread_id, 24)?,
        prompt_diagnostics: load_checkpoint_json(
            memory_runtime,
            thread_id,
            MEMORY_RUNTIME_PROMPT_DIAGNOSTICS_CHECKPOINT,
        )?,
        retrieval_diagnostics: load_checkpoint_json(
            memory_runtime,
            diagnostics_thread_id(None),
            MEMORY_RUNTIME_RETRIEVAL_DIAGNOSTICS_CHECKPOINT,
        )?,
        enrichment_diagnostics: load_checkpoint_json(
            memory_runtime,
            thread_id,
            MEMORY_RUNTIME_ENRICHMENT_DIAGNOSTICS_CHECKPOINT,
        )?,
        evaluation: load_checkpoint_json(
            memory_runtime,
            thread_id,
            MEMORY_RUNTIME_EVALUATION_CHECKPOINT,
        )?,
    })
}

pub fn record_memory_session_evaluation(
    memory_runtime: &ioi_memory::MemoryRuntime,
    thread_id: [u8; 32],
    transcript_message_count: usize,
    compacted_message_count: usize,
    summary: &str,
) -> Result<MemorySessionEvaluation, TransactionError> {
    let core_sections = load_core_memory_sections_status(memory_runtime, thread_id)?;
    let enrichment = load_checkpoint_json::<MemoryEnrichmentDiagnostics>(
        memory_runtime,
        thread_id,
        MEMORY_RUNTIME_ENRICHMENT_DIAGNOSTICS_CHECKPOINT,
    )?
    .unwrap_or_default();
    let ui_snapshots = memory_runtime
        .search_archival_memory(&ArchivalMemoryQuery {
            scope: MEMORY_RUNTIME_UI_SCOPE.to_string(),
            thread_id: Some(thread_id),
            text: String::new(),
            limit: 256,
        })
        .map_err(|error| TransactionError::Invalid(format!("Internal: {}", error)))?
        .into_iter()
        .filter(|record| record.kind == "ui_observation" || record.kind == "ui_summary")
        .count() as u64;

    let mut score_bps = 0u32;
    if !summary.trim().is_empty() {
        score_bps += 2_000;
    }
    if compacted_message_count >= 8 {
        score_bps += 1_500;
    }
    if !core_sections.is_empty() {
        score_bps += 2_000;
    }
    if ui_snapshots > 0 {
        score_bps += 1_500;
    }
    if enrichment.completed_jobs > 0 {
        score_bps += 2_000;
    }
    if enrichment.failed_jobs == 0 {
        score_bps += 1_000;
    }
    score_bps = score_bps.min(10_000);
    let assessment = if score_bps >= 8_500 {
        "strong".to_string()
    } else if score_bps >= 6_000 {
        "healthy".to_string()
    } else {
        "needs_attention".to_string()
    };

    let evaluation = MemorySessionEvaluation {
        updated_at_ms: unix_timestamp_ms_now(),
        session_id_hex: hex::encode(thread_id),
        transcript_message_count: transcript_message_count as u64,
        compacted_message_count: compacted_message_count as u64,
        summary_chars: summary.chars().count(),
        active_core_sections: core_sections.len(),
        ui_snapshot_count: ui_snapshots,
        enrichment_completed_jobs: enrichment.completed_jobs,
        enrichment_failed_jobs: enrichment.failed_jobs,
        score_bps,
        assessment: assessment.clone(),
    };

    persist_checkpoint_json(
        memory_runtime,
        thread_id,
        MEMORY_RUNTIME_EVALUATION_CHECKPOINT,
        &evaluation,
    )?;

    let metadata_json = serde_json::to_string(&json!({
        "trust_level": "runtime_controlled",
        "session_id": hex::encode(thread_id),
        "score_bps": score_bps,
        "assessment": assessment,
    }))
    .map_err(|error| TransactionError::Serialization(error.to_string()))?;
    let content = format!(
        "session={} score_bps={} assessment={} transcript_messages={} compacted_messages={} core_sections={} ui_snapshots={} enrichment_completed={} enrichment_failed={}",
        hex::encode(thread_id),
        evaluation.score_bps,
        evaluation.assessment,
        evaluation.transcript_message_count,
        evaluation.compacted_message_count,
        evaluation.active_core_sections,
        evaluation.ui_snapshot_count,
        evaluation.enrichment_completed_jobs,
        evaluation.enrichment_failed_jobs
    );
    memory_runtime
        .insert_archival_record(&NewArchivalMemoryRecord {
            scope: MEMORY_RUNTIME_EVALUATION_SCOPE.to_string(),
            thread_id: Some(thread_id),
            kind: "session_memory_health".to_string(),
            content,
            metadata_json,
        })
        .map_err(|error| TransactionError::Invalid(format!("Internal: {}", error)))?;

    Ok(evaluation)
}

fn summarize_ui_snapshot_for_memory(
    active_window_title: &str,
    active_url: Option<&str>,
    snapshot_hash: &str,
    snapshot_xml: &str,
) -> String {
    let structural_lines = snapshot_xml
        .lines()
        .map(str::trim)
        .filter(|line| {
            !line.is_empty()
                && (line.contains("button")
                    || line.contains("textbox")
                    || line.contains("link")
                    || line.contains("dialog")
                    || line.contains("modal")
                    || line.contains("menu")
                    || line.contains("heading")
                    || line.contains("tab")
                    || line.contains("checkbox")
                    || line.contains("combobox")
                    || line.contains("role=")
                    || line.contains("tag_name="))
        })
        .take(24)
        .collect::<Vec<_>>();
    let mut summary = format!(
        "Window: {}\nURL: {}\nSnapshot Hash: {}\nObserved Structure:\n",
        active_window_title,
        active_url.unwrap_or("unavailable"),
        snapshot_hash
    );
    if structural_lines.is_empty() {
        summary.push_str(
            snapshot_xml
                .lines()
                .take(12)
                .collect::<Vec<_>>()
                .join("\n")
                .as_str(),
        );
    } else {
        summary.push_str(&structural_lines.join("\n"));
    }
    summary
}

fn assistant_message_is_structured_tool_call(text: &str) -> bool {
    fn is_tool_call_payload(value: &Value) -> bool {
        match value {
            Value::Object(map) => {
                matches!(map.get("name"), Some(Value::String(_)))
                    && matches!(map.get("arguments"), Some(Value::Object(_)))
                    && map
                        .keys()
                        .all(|key| matches!(key.as_str(), "name" | "arguments"))
            }
            _ => false,
        }
    }

    let trimmed = text.trim();
    if trimmed.is_empty() {
        return false;
    }

    match serde_json::from_str::<Value>(trimmed) {
        Ok(Value::Array(items)) => !items.is_empty() && items.iter().all(is_tool_call_payload),
        Ok(value) => is_tool_call_payload(&value),
        Err(_) => false,
    }
}

fn should_embed_for_semantic_indexing(role: &str, scrubbed_text: &str) -> bool {
    if role.eq_ignore_ascii_case("user") {
        return true;
    }

    role.eq_ignore_ascii_case("assistant")
        && !assistant_message_is_structured_tool_call(scrubbed_text)
}

#[derive(Debug, Clone)]
pub struct HybridRetrievalResult {
    pub output: String,
    pub receipt: Option<WorkloadMemoryRetrieveReceipt>,
}

pub(crate) fn archival_memory_inspect_id(record_id: i64) -> Option<u64> {
    u64::try_from(record_id)
        .ok()
        .and_then(|id| MEMORY_RUNTIME_INSPECT_ID_OFFSET.checked_add(id))
}

pub(crate) fn archival_record_id_from_inspect_id(inspect_id: u64) -> Option<i64> {
    inspect_id
        .checked_sub(MEMORY_RUNTIME_INSPECT_ID_OFFSET)
        .and_then(|value| i64::try_from(value).ok())
}

/// Retrieve a Swarm manifest from the market registry state.
pub async fn fetch_swarm_manifest(
    state: &dyn StateAccess,
    hash: [u8; 32],
) -> Option<SwarmManifest> {
    let key = [MARKET_ASSET_REGISTRY_PREFIX, &hash].concat();
    let bytes = state.get(&key).ok()??;
    match codec::from_bytes_canonical::<ioi_types::app::agentic::IntelligenceAsset>(&bytes).ok()? {
        ioi_types::app::agentic::IntelligenceAsset::Swarm(manifest) => Some(manifest),
        _ => None,
    }
}

fn enqueue_enrichment_job_best_effort(
    memory_runtime: &ioi_memory::MemoryRuntime,
    job: &NewEnrichmentJob,
) -> bool {
    match memory_runtime.enqueue_enrichment_job(job) {
        Ok(Some(_)) => true,
        Ok(None) => false,
        Err(error) => {
            log::warn!("Failed to enqueue enrichment job {}: {}", job.kind, error);
            false
        }
    }
}

fn enqueue_transcript_enrichment_jobs(
    memory_runtime: &ioi_memory::MemoryRuntime,
    session_id: [u8; 32],
    source_record_id: i64,
) -> bool {
    let payload = serde_json::to_string(&TranscriptEnrichmentPayload {
        source_record_id,
        session_id_hex: Some(hex::encode(session_id)),
    })
    .unwrap_or_else(|_| "{}".to_string());
    let jobs = [
        NewEnrichmentJob {
            thread_id: Some(session_id),
            kind: "transcript.fact_extraction".to_string(),
            payload_json: payload.clone(),
            dedupe_key: Some(format!("transcript.fact_extraction:{source_record_id}")),
        },
        NewEnrichmentJob {
            thread_id: Some(session_id),
            kind: "transcript.entity_extraction".to_string(),
            payload_json: payload.clone(),
            dedupe_key: Some(format!("transcript.entity_extraction:{source_record_id}")),
        },
        NewEnrichmentJob {
            thread_id: Some(session_id),
            kind: "transcript.procedure_extraction".to_string(),
            payload_json: payload.clone(),
            dedupe_key: Some(format!(
                "transcript.procedure_extraction:{source_record_id}"
            )),
        },
        NewEnrichmentJob {
            thread_id: Some(session_id),
            kind: "archival.embedding".to_string(),
            payload_json: serde_json::to_string(&ArchivalEmbeddingPayload { source_record_id })
                .unwrap_or_else(|_| "{}".to_string()),
            dedupe_key: Some(format!("archival.embedding:{source_record_id}")),
        },
    ];
    jobs.iter()
        .any(|job| enqueue_enrichment_job_best_effort(memory_runtime, job))
}

fn enqueue_ui_enrichment_jobs(
    memory_runtime: &ioi_memory::MemoryRuntime,
    session_id: [u8; 32],
    source_record_id: i64,
    artifact_id: &str,
) -> bool {
    let payload = serde_json::to_string(&UiObservationEnrichmentPayload {
        source_record_id,
        artifact_id: artifact_id.to_string(),
    })
    .unwrap_or_else(|_| "{}".to_string());
    let jobs = [
        NewEnrichmentJob {
            thread_id: Some(session_id),
            kind: "ui.observation.summary".to_string(),
            payload_json: payload,
            dedupe_key: Some(format!("ui.observation.summary:{source_record_id}")),
        },
        NewEnrichmentJob {
            thread_id: Some(session_id),
            kind: "ui.relationship_extraction".to_string(),
            payload_json: serde_json::to_string(&UiObservationEnrichmentPayload {
                source_record_id,
                artifact_id: artifact_id.to_string(),
            })
            .unwrap_or_else(|_| "{}".to_string()),
            dedupe_key: Some(format!("ui.relationship_extraction:{source_record_id}")),
        },
        NewEnrichmentJob {
            thread_id: Some(session_id),
            kind: "archival.embedding".to_string(),
            payload_json: serde_json::to_string(&ArchivalEmbeddingPayload { source_record_id })
                .unwrap_or_else(|_| "{}".to_string()),
            dedupe_key: Some(format!("archival.embedding:{source_record_id}")),
        },
    ];
    jobs.iter()
        .any(|job| enqueue_enrichment_job_best_effort(memory_runtime, job))
}

fn spawn_memory_enrichment_tick(service: &DesktopAgentService, reason: &'static str) {
    let Some(memory_runtime) = service.memory_runtime.clone() else {
        return;
    };
    let inference = service.reasoning_inference.clone();
    tokio::spawn(async move {
        match process_pending_memory_enrichment_jobs_once(memory_runtime, inference, 6).await {
            Ok(report) => {
                if report.claimed > 0 {
                    log::info!(
                        "Memory enrichment tick ({}) claimed={} completed={} failed={} inserted={} rejected={}",
                        reason,
                        report.claimed,
                        report.completed,
                        report.failed,
                        report.inserted_records,
                        report.rejected_candidates,
                    );
                }
            }
            Err(error) => {
                log::warn!("Memory enrichment tick ({}) failed: {}", reason, error);
            }
        }
    });
}

pub fn kick_memory_enrichment(service: &DesktopAgentService, reason: &'static str) {
    spawn_memory_enrichment_tick(service, reason);
}

async fn sync_system_core_memory(
    service: &DesktopAgentService,
    session_id: [u8; 32],
    agent_state: &AgentState,
    perception: &PerceptionContext,
) -> Result<(), TransactionError> {
    let Some(memory_runtime) = service.memory_runtime.as_ref() else {
        return Ok(());
    };

    replace_core_memory_governed(
        memory_runtime,
        session_id,
        "goal.current",
        &agent_state.goal,
        "runtime_sync",
    )?;
    replace_core_memory_governed(
        memory_runtime,
        session_id,
        "environment.window.active",
        &perception.active_window_title,
        "runtime_sync",
    )?;

    let resolved_intent = agent_state
        .resolved_intent
        .as_ref()
        .map(|resolved| {
            format!(
                "{} (scope={:?}, band={:?}, score={:.3})",
                resolved.intent_id, resolved.scope, resolved.band, resolved.score
            )
        })
        .unwrap_or_default();
    replace_core_memory_governed(
        memory_runtime,
        session_id,
        "intent.resolved",
        &resolved_intent,
        "runtime_sync",
    )?;

    let failure_context = if perception.consecutive_failures > 0 {
        let reason = perception
            .last_failure_reason
            .clone()
            .unwrap_or_else(|| "UnknownFailure".to_string());
        format!(
            "consecutive_failures={} last_failure_reason={}",
            perception.consecutive_failures, reason
        )
    } else {
        String::new()
    };
    replace_core_memory_governed(
        memory_runtime,
        session_id,
        "execution.last_failure",
        &failure_context,
        "runtime_sync",
    )?;

    let active_url = service.browser.known_active_url().await.unwrap_or_default();
    replace_core_memory_governed(
        memory_runtime,
        session_id,
        "environment.browser.url",
        &active_url,
        "runtime_sync",
    )?;
    Ok(())
}

async fn persist_structured_ui_memory(
    service: &DesktopAgentService,
    session_id: [u8; 32],
    active_window_title: &str,
    current_browser_snapshot: Option<&str>,
) -> Result<bool, TransactionError> {
    let Some(memory_runtime) = service.memory_runtime.as_ref() else {
        return Ok(false);
    };
    let Some(snapshot_xml) = current_browser_snapshot
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Ok(false);
    };

    let snapshot_hash = digest_hex(snapshot_xml);
    let prior_checkpoint = memory_runtime
        .load_checkpoint_blob(session_id, MEMORY_RUNTIME_LAST_UI_SNAPSHOT_CHECKPOINT)
        .map_err(|error| TransactionError::Invalid(format!("Internal: {}", error)))?
        .and_then(|blob| serde_json::from_slice::<UiSnapshotCheckpoint>(&blob).ok());
    if prior_checkpoint
        .as_ref()
        .map(|checkpoint| checkpoint.snapshot_hash == snapshot_hash)
        .unwrap_or(false)
    {
        return Ok(false);
    }

    let active_url = service.browser.known_active_url().await;
    let artifact_id = format!(
        "desktop.ui.snapshot.{}.{}",
        hex::encode(&session_id[..4]),
        snapshot_hash.chars().take(16).collect::<String>()
    );
    let artifact_metadata = serde_json::to_string(&json!({
        "kind": "ui_snapshot_xml",
        "snapshot_hash": snapshot_hash,
        "active_window_title": active_window_title,
        "active_url": active_url,
        "trust_level": "runtime_observed",
    }))
    .map_err(|error| TransactionError::Serialization(error.to_string()))?;
    memory_runtime
        .upsert_artifact_json(session_id, &artifact_id, &artifact_metadata)
        .map_err(|error| TransactionError::Invalid(format!("Internal: {}", error)))?;
    memory_runtime
        .put_artifact_blob(session_id, &artifact_id, snapshot_xml.as_bytes())
        .map_err(|error| TransactionError::Invalid(format!("Internal: {}", error)))?;

    let content = summarize_ui_snapshot_for_memory(
        active_window_title,
        active_url.as_deref(),
        &snapshot_hash,
        snapshot_xml,
    );
    let metadata_json = serde_json::to_string(&json!({
        "trust_level": "runtime_observed",
        "snapshot_hash": snapshot_hash,
        "artifact_id": artifact_id,
        "active_window_title": active_window_title,
        "active_url": active_url,
        "source": "prompt_observation",
    }))
    .map_err(|error| TransactionError::Serialization(error.to_string()))?;
    let record_id = memory_runtime
        .insert_archival_record(&NewArchivalMemoryRecord {
            scope: MEMORY_RUNTIME_UI_SCOPE.to_string(),
            thread_id: Some(session_id),
            kind: "ui_observation".to_string(),
            content,
            metadata_json,
        })
        .map_err(|error| TransactionError::Invalid(format!("Internal: {}", error)))?;

    let checkpoint = UiSnapshotCheckpoint {
        snapshot_hash,
        artifact_id: artifact_id.clone(),
        archival_record_id: record_id,
        active_url,
    };
    let payload = serde_json::to_vec(&checkpoint)
        .map_err(|error| TransactionError::Serialization(error.to_string()))?;
    memory_runtime
        .upsert_checkpoint_blob(
            session_id,
            MEMORY_RUNTIME_LAST_UI_SNAPSHOT_CHECKPOINT,
            &payload,
        )
        .map_err(|error| TransactionError::Invalid(format!("Internal: {}", error)))?;

    if let Some(record_id) = record_id {
        let _ = enqueue_ui_enrichment_jobs(memory_runtime, session_id, record_id, &artifact_id);
        spawn_memory_enrichment_tick(service, "ui_memory");
    }

    Ok(true)
}

pub async fn prepare_prompt_memory_context(
    service: &DesktopAgentService,
    session_id: [u8; 32],
    agent_state: &AgentState,
    perception: &PerceptionContext,
    current_browser_snapshot: Option<&str>,
) -> Result<String, TransactionError> {
    let Some(memory_runtime) = service.memory_runtime.as_ref() else {
        return Ok(String::new());
    };
    sync_system_core_memory(service, session_id, agent_state, perception).await?;
    let _ = persist_structured_ui_memory(
        service,
        session_id,
        &perception.active_window_title,
        current_browser_snapshot,
    )
    .await?;
    format_prompt_eligible_core_memory(memory_runtime, session_id)
}

fn extract_fact_candidates(text: &str) -> Vec<String> {
    let keywords = [
        " is ",
        " are ",
        " should ",
        " must ",
        " use ",
        " click ",
        " login ",
        " dashboard",
        " checkout",
        " url",
        " route",
        " modal",
        " page",
    ];
    let mut seen = HashSet::new();
    text.split(['\n', '.', '!', '?'])
        .map(str::trim)
        .filter(|candidate| candidate.chars().count() >= 24 && candidate.chars().count() <= 220)
        .filter(|candidate| {
            let lowered = candidate.to_ascii_lowercase();
            keywords.iter().any(|needle| lowered.contains(needle))
        })
        .filter(|candidate| seen.insert(candidate.to_string()))
        .take(4)
        .map(str::to_string)
        .collect()
}

fn extract_entity_candidates(text: &str) -> Vec<String> {
    let mut entities = Vec::new();
    let mut seen = HashSet::new();
    for token in text.split_whitespace() {
        let trimmed = token
            .trim_matches(|ch: char| !ch.is_alphanumeric() && ch != '.' && ch != '/' && ch != '_');
        if trimmed.is_empty() {
            continue;
        }
        let looks_like_url = trimmed.starts_with("http://") || trimmed.starts_with("https://");
        let looks_like_named_entity = trimmed
            .chars()
            .next()
            .map(|ch| ch.is_ascii_uppercase())
            .unwrap_or(false)
            && trimmed.chars().count() > 2;
        if (looks_like_url || looks_like_named_entity) && seen.insert(trimmed.to_string()) {
            entities.push(trimmed.to_string());
        }
        if entities.len() >= 6 {
            break;
        }
    }
    entities
}

fn extract_procedure_candidate(text: &str) -> Option<String> {
    let compact = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    let lowered = compact.to_ascii_lowercase();
    let has_procedure_shape = lowered.contains("step ")
        || lowered.contains("1.")
        || lowered.contains(" then ")
        || lowered.contains(" after ")
        || lowered.contains(" next ");
    if !has_procedure_shape {
        return None;
    }
    Some(normalize_core_memory_content(&compact, 480))
}

fn xml_attribute_value(line: &str, key: &str) -> Option<String> {
    let pattern = format!(r#"{key}=""#);
    let start = line.find(&pattern)? + pattern.len();
    let rest = &line[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

fn xml_tag_name(line: &str) -> Option<String> {
    let trimmed = line.trim_start();
    let tag = trimmed.strip_prefix('<')?;
    if tag.starts_with('/') {
        return None;
    }
    Some(
        tag.split(|ch: char| ch.is_whitespace() || ch == '>' || ch == '/')
            .next()?
            .to_string(),
    )
}

fn extract_ui_relationship_candidates(
    source: &ioi_memory::ArchivalMemoryRecord,
    xml: &str,
) -> Vec<String> {
    let metadata =
        serde_json::from_str::<Value>(&source.metadata_json).unwrap_or_else(|_| json!({}));
    let active_window_title = metadata
        .get("active_window_title")
        .and_then(Value::as_str)
        .unwrap_or("Unknown Window");
    let active_url = metadata
        .get("active_url")
        .and_then(Value::as_str)
        .unwrap_or("unavailable");
    let snapshot_hash = metadata
        .get("snapshot_hash")
        .and_then(Value::as_str)
        .unwrap_or_default();

    let contextual_tags = [
        "dialog",
        "modal",
        "heading",
        "tab",
        "tabpanel",
        "menu",
        "navigation",
    ];
    let control_tags = [
        "button", "link", "textbox", "combobox", "checkbox", "radio", "menuitem", "tab",
    ];
    let mut contexts: Vec<String> = Vec::new();
    let mut seen = HashSet::new();
    let mut results = Vec::new();

    for raw_line in xml.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        let Some(tag) = xml_tag_name(line) else {
            continue;
        };
        let name = xml_attribute_value(line, "name")
            .or_else(|| xml_attribute_value(line, "id"))
            .unwrap_or_default();
        if name.is_empty() {
            continue;
        }

        if contextual_tags.contains(&tag.as_str()) {
            if contexts.last().map(String::as_str) != Some(name.as_str()) {
                contexts.push(name.clone());
                if contexts.len() > 4 {
                    contexts.remove(0);
                }
            }
        }

        if !control_tags.contains(&tag.as_str()) {
            continue;
        }

        let context_path = if contexts.is_empty() {
            "direct viewport".to_string()
        } else {
            contexts.join(" > ")
        };
        let summary = normalize_core_memory_content(
            &format!(
                "Window {active_window_title} URL {active_url} control '{name}' role '{tag}' within {context_path}. Snapshot {snapshot_hash}."
            ),
            420,
        );
        if seen.insert(summary.clone()) {
            results.push(summary);
        }
        if results.len() >= 10 {
            break;
        }
    }

    results
}

async fn embed_archival_record_content(
    memory_runtime: &ioi_memory::MemoryRuntime,
    inference: &Arc<dyn InferenceRuntime>,
    record_id: i64,
) -> anyhow::Result<()> {
    let Some(record) = memory_runtime.load_archival_record(record_id)? else {
        return Ok(());
    };
    let embedding = inference.embed_text(&record.content).await?;
    memory_runtime.upsert_archival_embedding(record_id, &embedding)?;
    Ok(())
}

async fn insert_derived_archival_record(
    memory_runtime: &ioi_memory::MemoryRuntime,
    inference: &Arc<dyn InferenceRuntime>,
    scope: &str,
    thread_id: Option<[u8; 32]>,
    kind: &str,
    content: &str,
    source_record_id: i64,
) -> anyhow::Result<DerivedRecordInsertOutcome> {
    if let Some(reason) = derived_memory_rejection_reason(scope, kind, content) {
        return Ok(DerivedRecordInsertOutcome {
            inserted: None,
            rejection_reason: Some(reason.to_string()),
        });
    }

    let metadata_json = serde_json::to_string(&json!({
        "trust_level": "runtime_derived",
        "source_record_id": source_record_id,
        "source": "enrichment_pipeline",
    }))?;
    let record_id = memory_runtime
        .insert_archival_record(&NewArchivalMemoryRecord {
            scope: scope.to_string(),
            thread_id,
            kind: kind.to_string(),
            content: content.to_string(),
            metadata_json,
        })?
        .ok_or_else(|| anyhow::anyhow!("archival store unavailable"))?;
    embed_archival_record_content(memory_runtime, inference, record_id).await?;
    Ok(DerivedRecordInsertOutcome {
        inserted: Some((record_id, scope.to_string())),
        rejection_reason: None,
    })
}

pub async fn process_pending_memory_enrichment_jobs_once(
    memory_runtime: Arc<ioi_memory::MemoryRuntime>,
    inference: Arc<dyn InferenceRuntime>,
    limit: usize,
) -> anyhow::Result<MemoryEnrichmentTickReport> {
    let jobs = memory_runtime.claim_enrichment_jobs(MEMORY_RUNTIME_ENRICHMENT_WORKER_ID, limit)?;
    let mut report = MemoryEnrichmentTickReport {
        claimed: jobs.len(),
        ..Default::default()
    };

    for job in jobs {
        let result: anyhow::Result<EnrichmentJobOutcome> = async {
            match job.kind.as_str() {
                "archival.embedding" => {
                    let payload =
                        serde_json::from_str::<ArchivalEmbeddingPayload>(&job.payload_json)?;
                    embed_archival_record_content(
                        &memory_runtime,
                        &inference,
                        payload.source_record_id,
                    )
                    .await?;
                    Ok(EnrichmentJobOutcome::default())
                }
                "transcript.fact_extraction" => {
                    let payload =
                        serde_json::from_str::<TranscriptEnrichmentPayload>(&job.payload_json)?;
                    let Some(source) =
                        memory_runtime.load_archival_record(payload.source_record_id)?
                    else {
                        return Ok(EnrichmentJobOutcome::default());
                    };
                    let mut outcome = EnrichmentJobOutcome::default();
                    for fact in extract_fact_candidates(&source.content) {
                        let insert = insert_derived_archival_record(
                            &memory_runtime,
                            &inference,
                            MEMORY_RUNTIME_FACT_SCOPE,
                            source.thread_id,
                            "fact",
                            &fact,
                            source.id,
                        )
                        .await?;
                        if let Some((_, scope)) = insert.inserted {
                            outcome.inserted_records += 1;
                            *outcome.inserted_scopes.entry(scope).or_insert(0) += 1;
                        } else if let Some(reason) = insert.rejection_reason {
                            outcome.rejected_candidates += 1;
                            *outcome.rejected_by_reason.entry(reason).or_insert(0) += 1;
                        }
                    }
                    Ok(outcome)
                }
                "transcript.entity_extraction" => {
                    let payload =
                        serde_json::from_str::<TranscriptEnrichmentPayload>(&job.payload_json)?;
                    let Some(source) =
                        memory_runtime.load_archival_record(payload.source_record_id)?
                    else {
                        return Ok(EnrichmentJobOutcome::default());
                    };
                    let mut outcome = EnrichmentJobOutcome::default();
                    for entity in extract_entity_candidates(&source.content) {
                        let insert = insert_derived_archival_record(
                            &memory_runtime,
                            &inference,
                            MEMORY_RUNTIME_ENTITY_SCOPE,
                            source.thread_id,
                            "entity",
                            &entity,
                            source.id,
                        )
                        .await?;
                        if let Some((_, scope)) = insert.inserted {
                            outcome.inserted_records += 1;
                            *outcome.inserted_scopes.entry(scope).or_insert(0) += 1;
                        } else if let Some(reason) = insert.rejection_reason {
                            outcome.rejected_candidates += 1;
                            *outcome.rejected_by_reason.entry(reason).or_insert(0) += 1;
                        }
                    }
                    Ok(outcome)
                }
                "transcript.procedure_extraction" => {
                    let payload =
                        serde_json::from_str::<TranscriptEnrichmentPayload>(&job.payload_json)?;
                    let Some(source) =
                        memory_runtime.load_archival_record(payload.source_record_id)?
                    else {
                        return Ok(EnrichmentJobOutcome::default());
                    };
                    let Some(procedure) = extract_procedure_candidate(&source.content) else {
                        return Ok(EnrichmentJobOutcome::default());
                    };
                    let insert = insert_derived_archival_record(
                        &memory_runtime,
                        &inference,
                        MEMORY_RUNTIME_PROCEDURE_SCOPE,
                        source.thread_id,
                        "procedure_candidate",
                        &procedure,
                        source.id,
                    )
                    .await?;
                    let mut outcome = EnrichmentJobOutcome::default();
                    if let Some((_, scope)) = insert.inserted {
                        outcome.inserted_records = 1;
                        outcome.inserted_scopes.insert(scope, 1);
                    } else if let Some(reason) = insert.rejection_reason {
                        outcome.rejected_candidates = 1;
                        outcome.rejected_by_reason.insert(reason, 1);
                    }
                    Ok(outcome)
                }
                "ui.observation.summary" => {
                    let payload =
                        serde_json::from_str::<UiObservationEnrichmentPayload>(&job.payload_json)?;
                    let Some(source) =
                        memory_runtime.load_archival_record(payload.source_record_id)?
                    else {
                        return Ok(EnrichmentJobOutcome::default());
                    };
                    let Some(blob) = memory_runtime.load_artifact_blob(&payload.artifact_id)?
                    else {
                        return Ok(EnrichmentJobOutcome::default());
                    };
                    let xml = String::from_utf8_lossy(&blob);
                    let summary =
                        summarize_ui_snapshot_for_memory("Browser", None, &digest_hex(&xml), &xml);
                    let insert = insert_derived_archival_record(
                        &memory_runtime,
                        &inference,
                        MEMORY_RUNTIME_UI_SCOPE,
                        source.thread_id,
                        "ui_summary",
                        &summary,
                        source.id,
                    )
                    .await?;
                    let mut outcome = EnrichmentJobOutcome::default();
                    if let Some((_, scope)) = insert.inserted {
                        outcome.inserted_records = 1;
                        outcome.inserted_scopes.insert(scope, 1);
                    } else if let Some(reason) = insert.rejection_reason {
                        outcome.rejected_candidates = 1;
                        outcome.rejected_by_reason.insert(reason, 1);
                    }
                    Ok(outcome)
                }
                "ui.relationship_extraction" => {
                    let payload =
                        serde_json::from_str::<UiObservationEnrichmentPayload>(&job.payload_json)?;
                    let Some(source) =
                        memory_runtime.load_archival_record(payload.source_record_id)?
                    else {
                        return Ok(EnrichmentJobOutcome::default());
                    };
                    let Some(blob) = memory_runtime.load_artifact_blob(&payload.artifact_id)?
                    else {
                        return Ok(EnrichmentJobOutcome::default());
                    };
                    let xml = String::from_utf8_lossy(&blob);
                    let mut outcome = EnrichmentJobOutcome::default();
                    for relationship in extract_ui_relationship_candidates(&source, &xml) {
                        let insert = insert_derived_archival_record(
                            &memory_runtime,
                            &inference,
                            MEMORY_RUNTIME_UI_SCOPE,
                            source.thread_id,
                            "ui_control_relationship",
                            &relationship,
                            source.id,
                        )
                        .await?;
                        if let Some((_, scope)) = insert.inserted {
                            outcome.inserted_records += 1;
                            *outcome.inserted_scopes.entry(scope).or_insert(0) += 1;
                        } else if let Some(reason) = insert.rejection_reason {
                            outcome.rejected_candidates += 1;
                            *outcome.rejected_by_reason.entry(reason).or_insert(0) += 1;
                        }
                    }
                    Ok(outcome)
                }
                other => Err(anyhow::anyhow!("unsupported enrichment job '{}'", other)),
            }
        }
        .await;

        match result {
            Ok(outcome) => {
                memory_runtime.complete_enrichment_job(job.id)?;
                update_enrichment_diagnostics_success(
                    &memory_runtime,
                    job.thread_id,
                    &job.kind,
                    &outcome,
                )?;
                report.completed += 1;
                report.inserted_records += outcome.inserted_records;
                report.rejected_candidates += outcome.rejected_candidates;
            }
            Err(error) => {
                memory_runtime.fail_enrichment_job(job.id, &error.to_string())?;
                update_enrichment_diagnostics_failure(
                    &memory_runtime,
                    job.thread_id,
                    &job.kind,
                    &error.to_string(),
                )?;
                report.failed += 1;
            }
        }
    }

    Ok(report)
}

/// Hybrid retrieval of transcript memory via the runtime archival store.
pub async fn retrieve_context_hybrid(
    service: &DesktopAgentService,
    query: &str,
    _visual_phash: Option<[u8; 32]>,
) -> String {
    retrieve_context_hybrid_with_receipt(service, query, _visual_phash)
        .await
        .output
}

/// Hybrid Retrieval with a structured receipt payload suitable for workload events.
pub async fn retrieve_context_hybrid_with_receipt(
    service: &DesktopAgentService,
    query: &str,
    _visual_phash: Option<[u8; 32]>,
) -> HybridRetrievalResult {
    let default_policy = RetrievalSearchPolicy {
        k: 5,
        ef_search: 64,
        candidate_limit: 32,
        distance_metric: "cosine_distance".to_string(),
        embedding_normalized: true,
    };
    let query_hash = sha256(query.as_bytes())
        .ok()
        .map(hex::encode)
        .unwrap_or_default();

    let empty_failure_receipt =
        |backend: &str,
         distance_metric: &str,
         embedding_normalized: bool,
         certificate_mode: Option<&str>,
         error_class: Option<String>| WorkloadMemoryRetrieveReceipt {
            tool_name: "memory__search".to_string(),
            backend: backend.to_string(),
            query_hash: query_hash.clone(),
            index_root: String::new(),
            k: default_policy.k,
            ef_search: default_policy.ef_search,
            candidate_limit: default_policy.candidate_limit,
            candidate_count_total: 0,
            candidate_count_reranked: 0,
            candidate_truncated: false,
            distance_metric: distance_metric.to_string(),
            embedding_normalized,
            proof_ref: None,
            proof_hash: None,
            certificate_mode: certificate_mode.map(str::to_string),
            success: false,
            error_class,
        };

    let Some(memory_runtime) = service.memory_runtime.as_ref() else {
        return HybridRetrievalResult {
            output: String::new(),
            receipt: Some(empty_failure_receipt(
                "ioi-memory:hybrid-archival",
                "hybrid_lexical_semantic",
                false,
                Some("none"),
                Some("UnexpectedState".to_string()),
            )),
        };
    };

    let embedding = match service.reasoning_inference.embed_text(query).await {
        Ok(vec) => vec,
        Err(e) => {
            log::warn!(
                "Failed to generate embedding for memory runtime retrieval: {}",
                e
            );
            return HybridRetrievalResult {
                output: String::new(),
                receipt: Some(empty_failure_receipt(
                    "ioi-memory:hybrid-archival",
                    "hybrid_lexical_semantic",
                    false,
                    Some("none"),
                    Some("UnexpectedState".to_string()),
                )),
            };
        }
    };

    let matches = match memory_runtime.hybrid_search_archival_memory(&HybridArchivalMemoryQuery {
        scopes: vec![
            MEMORY_RUNTIME_TRANSCRIPT_SCOPE.to_string(),
            MEMORY_RUNTIME_COMPACTION_SCOPE.to_string(),
            MEMORY_RUNTIME_FACT_SCOPE.to_string(),
            MEMORY_RUNTIME_ENTITY_SCOPE.to_string(),
            MEMORY_RUNTIME_PROCEDURE_SCOPE.to_string(),
            MEMORY_RUNTIME_UI_SCOPE.to_string(),
        ],
        thread_id: None,
        text: query.to_string(),
        embedding: Some(embedding),
        limit: default_policy.k as usize,
        candidate_limit: default_policy.candidate_limit as usize,
        allowed_trust_levels: vec![
            "runtime_observed".to_string(),
            "runtime_derived".to_string(),
            "runtime_controlled".to_string(),
            "standard".to_string(),
        ],
    }) {
        Ok(matches) => matches,
        Err(error) => {
            log::warn!("Memory runtime retrieval failed: {}", error);
            return HybridRetrievalResult {
                output: String::new(),
                receipt: Some(empty_failure_receipt(
                    "ioi-memory:hybrid-archival",
                    "hybrid_lexical_semantic",
                    false,
                    Some("none"),
                    Some("UnexpectedState".to_string()),
                )),
            };
        }
    };

    let mut output = String::new();
    let mut top_snippet_included = false;
    let mut included = 0usize;
    let mut diagnostic_hits = Vec::new();

    for (i, hit) in matches.iter().enumerate() {
        if hit.score < MEMORY_RUNTIME_RETRIEVAL_SCORE_THRESHOLD {
            continue;
        }

        let inspect_id = archival_memory_inspect_id(hit.record.id).unwrap_or_default();
        let metadata =
            serde_json::from_str::<Value>(&hit.record.metadata_json).unwrap_or_else(|_| json!({}));
        let kind = metadata
            .get("role")
            .and_then(Value::as_str)
            .unwrap_or(hit.record.kind.as_str());
        let confidence = (hit.score.clamp(0.0, 1.0)) * 100.0;
        let scope = hit.record.scope.as_str();
        let trust_level = hit.trust_level.as_str();

        output.push_str(&format!(
            "- [ID:{}] Scope:{} Kind:{} Trust:{} Conf:{:.0}% | ",
            inspect_id, scope, kind, trust_level, confidence
        ));

        if i == 0 && !top_snippet_included {
            let snippet: String = hit
                .record
                .content
                .lines()
                .take(3)
                .collect::<Vec<_>>()
                .join(" ");
            output.push_str(&format!("Snippet: \"{}...\"\n", snippet));
            top_snippet_included = true;
        } else {
            let mut summary: String = hit.record.content.chars().take(60).collect();
            if hit.record.content.chars().count() > 60 {
                summary.push_str("...");
            }
            output.push_str(&format!("Summary: \"{}\"\n", summary));
        }
        included += 1;
        if diagnostic_hits.len() < MEMORY_RUNTIME_DIAGNOSTIC_TOP_HITS {
            diagnostic_hits.push(MemoryRetrievalHitDiagnostic {
                inspect_id: Some(inspect_id),
                scope: scope.to_string(),
                kind: kind.to_string(),
                trust_level: trust_level.to_string(),
                score: hit.score,
            });
        }
    }

    if let Err(error) = update_retrieval_diagnostics(
        memory_runtime,
        &query_hash,
        matches.len(),
        included,
        &diagnostic_hits,
    ) {
        log::warn!("Failed to persist memory retrieval diagnostics: {}", error);
    }

    HybridRetrievalResult {
        output,
        receipt: Some(WorkloadMemoryRetrieveReceipt {
            tool_name: "memory__search".to_string(),
            backend: "ioi-memory:hybrid-archival".to_string(),
            query_hash,
            index_root: String::new(),
            k: default_policy.k,
            ef_search: default_policy.ef_search,
            candidate_limit: default_policy.candidate_limit,
            candidate_count_total: matches.len().min(u32::MAX as usize) as u32,
            candidate_count_reranked: matches.len().min(u32::MAX as usize) as u32,
            candidate_truncated: matches.len() > included.max(1),
            distance_metric: "hybrid_lexical_semantic".to_string(),
            embedding_normalized: false,
            proof_ref: None,
            proof_hash: None,
            certificate_mode: Some("none".to_string()),
            success: true,
            error_class: None,
        }),
    }
}

pub async fn append_chat_to_scs(
    service: &DesktopAgentService,
    session_id: [u8; 32],
    msg: &ChatMessage,
    _block_height: u64,
) -> Result<[u8; 32], TransactionError> {
    let recorded_message = build_recorded_message(&service.scrubber, msg).await;
    let payload =
        codec::to_bytes_canonical(&recorded_message).map_err(TransactionError::Serialization)?;
    let payload_checksum =
        digest32(&payload).map_err(|e| TransactionError::Invalid(format!("Internal: {}", e)))?;
    let memory_runtime = service
        .memory_runtime
        .as_ref()
        .ok_or(TransactionError::Invalid(
            "Internal: transcript memory runtime not available".into(),
        ))?;

    memory_runtime
        .append_transcript_message(
            session_id,
            &stored_transcript_message_from_recorded(&recorded_message),
        )
        .map_err(|e| TransactionError::Invalid(format!("Internal: {}", e)))?;

    // 2. Semantic Indexing
    // Keep indexing best-effort and bounded so action completion never waits on
    // long-running inference calls.
    let semantic_index_started_at = Instant::now();
    let semantic_budget_remaining =
        || SEMANTIC_INDEXING_BUDGET.saturating_sub(semantic_index_started_at.elapsed());

    let should_archive_message = should_embed_for_semantic_indexing(
        &recorded_message.role,
        &recorded_message.scrubbed_for_scs,
    );
    let semantic_vector = {
        let remaining = semantic_budget_remaining();
        if should_archive_message && !remaining.is_zero() {
            match timeout(
                remaining,
                service
                    .reasoning_inference
                    .embed_text(&recorded_message.scrubbed_for_scs),
            )
            .await
            {
                Ok(Ok(vec)) => Some(vec),
                Ok(Err(e)) => {
                    log::warn!("Transcript semantic embedding failed: {}", e);
                    None
                }
                Err(_) => {
                    log::warn!(
                        "Transcript semantic embedding timed out for session {} after {:?}.",
                        hex::encode(&session_id[..4]),
                        SEMANTIC_INDEXING_BUDGET
                    );
                    None
                }
            }
        } else {
            None
        }
    };

    if should_archive_message {
        let metadata_json = serde_json::to_string(&json!({
            "session_id": hex::encode(session_id),
            "role": recorded_message.role,
            "timestamp_ms": recorded_message.timestamp_ms,
            "trace_hash": recorded_message.trace_hash.map(hex::encode),
            "trust_level": "runtime_observed",
        }))
        .map_err(|e| TransactionError::Invalid(format!("Internal: {}", e)))?;

        match memory_runtime.insert_archival_record(&NewArchivalMemoryRecord {
            scope: MEMORY_RUNTIME_TRANSCRIPT_SCOPE.to_string(),
            thread_id: Some(session_id),
            kind: "chat_message".to_string(),
            content: recorded_message.scrubbed_for_scs.clone(),
            metadata_json,
        }) {
            Ok(Some(record_id)) => {
                if let Some(vector) = semantic_vector.as_ref() {
                    if let Err(error) = memory_runtime.upsert_archival_embedding(record_id, vector)
                    {
                        log::warn!(
                            "Memory runtime transcript embedding write failed for record {}: {}",
                            record_id,
                            error
                        );
                    }
                }
                if enqueue_transcript_enrichment_jobs(memory_runtime, session_id, record_id) {
                    spawn_memory_enrichment_tick(service, "transcript_append");
                }
            }
            Ok(None) => {}
            Err(error) => {
                log::warn!(
                    "Memory runtime transcript archival insert failed: {}",
                    error
                );
            }
        }
    }

    Ok(payload_checksum)
}

pub fn hydrate_session_history(
    service: &DesktopAgentService,
    session_id: [u8; 32],
) -> Result<Vec<ChatMessage>, TransactionError> {
    hydrate_session_history_surface(service, session_id, false)
}

pub fn hydrate_session_history_raw(
    service: &DesktopAgentService,
    session_id: [u8; 32],
) -> Result<Vec<ChatMessage>, TransactionError> {
    hydrate_session_history_surface(service, session_id, true)
}

fn hydrate_session_history_surface(
    service: &DesktopAgentService,
    session_id: [u8; 32],
    raw: bool,
) -> Result<Vec<ChatMessage>, TransactionError> {
    let memory_runtime = service
        .memory_runtime
        .as_ref()
        .ok_or(TransactionError::Invalid(
            "Internal: transcript memory runtime not available".into(),
        ))?;
    let messages = memory_runtime
        .load_transcript_messages(session_id)
        .map_err(|error| TransactionError::Invalid(format!("Internal: {}", error)))?;
    let surface = if raw {
        TranscriptSurface::Raw
    } else {
        TranscriptSurface::Model
    };
    Ok(messages
        .iter()
        .map(|message| chat_message_from_transcript(message, surface))
        .collect())
}

#[cfg(test)]
fn decode_session_message(payload: &[u8], raw: bool) -> Option<ChatMessage> {
    if let Ok(message) = codec::from_bytes_canonical::<RecordedMessage>(&payload) {
        let content = if raw {
            if message.raw_content.is_empty() {
                message.scrubbed_for_model.clone()
            } else {
                message.raw_content
            }
        } else if message.scrubbed_for_model.is_empty() {
            message.scrubbed_for_scs
        } else {
            message.scrubbed_for_model
        };

        Some(ChatMessage {
            role: message.role,
            content,
            timestamp: message.timestamp_ms,
            trace_hash: message.trace_hash,
        })
    } else {
        None
    }
}

fn stored_transcript_message_from_recorded(message: &RecordedMessage) -> StoredTranscriptMessage {
    StoredTranscriptMessage {
        role: message.role.clone(),
        timestamp_ms: message.timestamp_ms,
        trace_hash: message.trace_hash,
        raw_content: message.raw_content.clone(),
        model_content: if message.scrubbed_for_model.is_empty() {
            message.scrubbed_for_scs.clone()
        } else {
            message.scrubbed_for_model.clone()
        },
        store_content: message.scrubbed_for_scs.clone(),
        raw_reference: message.raw_reference.clone(),
        privacy_metadata: TranscriptPrivacyMetadata {
            redaction_version: message.privacy_metadata.redaction_version.clone(),
            sensitive_fields_mask: message.privacy_metadata.sensitive_fields_mask.clone(),
            policy_id: message.privacy_metadata.policy_id.clone(),
            policy_version: message.privacy_metadata.policy_version.clone(),
            scrubbed_for_model_hash: message.privacy_metadata.scrubbed_for_model_hash.clone(),
        },
    }
}

fn chat_message_from_transcript(
    message: &StoredTranscriptMessage,
    surface: TranscriptSurface,
) -> ChatMessage {
    let content = match surface {
        TranscriptSurface::Model => {
            if message.model_content.is_empty() {
                message.store_content.clone()
            } else {
                message.model_content.clone()
            }
        }
        TranscriptSurface::Raw => {
            if message.raw_content.is_empty() {
                if message.model_content.is_empty() {
                    message.store_content.clone()
                } else {
                    message.model_content.clone()
                }
            } else {
                message.raw_content.clone()
            }
        }
        TranscriptSurface::Store => message.store_content.clone(),
    };

    ChatMessage {
        role: message.role.clone(),
        content,
        timestamp: message.timestamp_ms,
        trace_hash: message.trace_hash,
    }
}

fn digest32(bytes: &[u8]) -> anyhow::Result<[u8; 32]> {
    let digest = sha256(bytes)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_ref());
    Ok(out)
}

fn redact_fields_from_map(redaction_map: &RedactionMap) -> Vec<String> {
    let mut fields: Vec<String> = redaction_map
        .entries
        .iter()
        .map(|entry| match &entry.redaction_type {
            RedactionType::Pii => "pii".to_string(),
            RedactionType::Secret => "secret".to_string(),
            RedactionType::Custom(custom) => format!("custom:{custom}"),
        })
        .collect();

    let unique: HashSet<String> = fields.drain(..).collect();
    let mut normalized: Vec<String> = unique.into_iter().collect();
    normalized.sort_unstable();
    normalized
}

async fn scrub_message_text_for_ingest(
    scrubber: &crate::agentic::pii_scrubber::PiiScrubber,
    input: &str,
) -> (String, Vec<String>) {
    match scrubber.scrub(input).await {
        Ok((scrubbed, redaction_map)) => (scrubbed, redact_fields_from_map(&redaction_map)),
        Err(_) => (
            MESSAGE_SANITIZED_PLACEHOLDER.to_string(),
            vec!["scrubber_failure".to_string()],
        ),
    }
}

async fn build_recorded_message(
    scrubber: &crate::agentic::pii_scrubber::PiiScrubber,
    msg: &ChatMessage,
) -> RecordedMessage {
    let (scrubbed_for_model, sensitive_fields_mask) =
        scrub_message_text_for_ingest(scrubber, &msg.content).await;
    let scrubbed_for_model_hash = sha256(scrubbed_for_model.as_bytes())
        .ok()
        .map(|digest| hex::encode(digest));
    RecordedMessage {
        role: msg.role.clone(),
        timestamp_ms: msg.timestamp,
        trace_hash: msg.trace_hash,
        raw_content: msg.content.clone(),
        scrubbed_for_model: scrubbed_for_model.clone(),
        scrubbed_for_scs: scrubbed_for_model,
        raw_reference: None,
        privacy_metadata: MessagePrivacyMetadata {
            redaction_version: DEFAULT_MESSAGE_REDACTION_VERSION.to_string(),
            sensitive_fields_mask,
            policy_id: DEFAULT_MESSAGE_PRIVACY_POLICY_ID.to_string(),
            policy_version: DEFAULT_MESSAGE_PRIVACY_POLICY_VERSION.to_string(),
            scrubbed_for_model_hash,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use ioi_api::vm::drivers::gui::{GuiDriver, InputEvent};
    use ioi_api::vm::inference::mock::MockInferenceRuntime;
    use ioi_api::vm::inference::InferenceRuntime;
    use ioi_drivers::browser::BrowserDriver;
    use ioi_drivers::terminal::TerminalDriver;
    use ioi_memory::{ArchivalMemoryQuery, MemoryRuntime};
    use ioi_types::app::action::ApprovalToken;
    use ioi_types::app::agentic::{
        InferenceOptions, IntentConfidenceBand, IntentScopeProfile, ResolvedIntentState,
    };
    use ioi_types::app::{ActionRequest, ContextSlice};
    use ioi_types::error::VmError;
    use std::collections::{BTreeMap, VecDeque};
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tokio::time::Instant;

    fn sample_recorded_message() -> RecordedMessage {
        RecordedMessage {
            role: "user".to_string(),
            timestamp_ms: 123,
            trace_hash: None,
            raw_content: "raw secret: password=abc123".to_string(),
            scrubbed_for_model: "raw secret: [REDACTED_PII]".to_string(),
            scrubbed_for_scs: "raw secret: [REDACTED_PII]".to_string(),
            raw_reference: None,
            privacy_metadata: MessagePrivacyMetadata {
                redaction_version: "v1".to_string(),
                sensitive_fields_mask: vec!["pii".to_string()],
                policy_id: "desktop-agent/default".to_string(),
                policy_version: "1".to_string(),
                scrubbed_for_model_hash: None,
            },
        }
    }

    fn sample_agent_state(session_id: [u8; 32], goal: &str) -> AgentState {
        AgentState {
            session_id,
            goal: goal.to_string(),
            transcript_root: [0u8; 32],
            status: crate::agentic::desktop::types::AgentStatus::Running,
            step_count: 3,
            max_steps: 32,
            last_action_type: None,
            parent_session_id: None,
            child_session_ids: Vec::new(),
            budget: 0,
            tokens_used: 0,
            consecutive_failures: 0,
            pending_approval: None::<ApprovalToken>,
            pending_tool_call: None,
            pending_tool_jcs: None,
            pending_tool_hash: None,
            pending_request_nonce: None,
            pending_visual_hash: None,
            recent_actions: Vec::new(),
            mode: crate::agentic::desktop::types::AgentMode::Agent,
            current_tier: crate::agentic::desktop::types::ExecutionTier::DomHeadless,
            last_screen_phash: None,
            execution_queue: Vec::new(),
            pending_search_completion: None,
            planner_state: None,
            active_skill_hash: None,
            tool_execution_log: BTreeMap::new(),
            visual_som_map: None,
            visual_semantic_map: None,
            swarm_context: None,
            target: None,
            resolved_intent: Some(ResolvedIntentState {
                intent_id: "browser.checkout".to_string(),
                scope: IntentScopeProfile::UiInteraction,
                band: IntentConfidenceBand::High,
                score: 0.98,
                top_k: Vec::new(),
                required_capabilities: Vec::new(),
                required_receipts: Vec::new(),
                required_postconditions: Vec::new(),
                risk_class: String::new(),
                preferred_tier: "dom_headless".to_string(),
                matrix_version: "test".to_string(),
                embedding_model_id: String::new(),
                embedding_model_version: String::new(),
                similarity_function_id: String::new(),
                intent_set_hash: [0u8; 32],
                tool_registry_hash: [0u8; 32],
                capability_ontology_hash: [0u8; 32],
                query_normalization_version: String::new(),
                matrix_source_hash: [0u8; 32],
                receipt_hash: [0u8; 32],
                provider_selection: None,
                instruction_contract: None,
                constrained: false,
            }),
            awaiting_intent_clarification: false,
            working_directory: ".".to_string(),
            command_history: VecDeque::new(),
            active_lens: None,
        }
    }

    fn sample_perception_context() -> PerceptionContext {
        PerceptionContext {
            tier: crate::agentic::desktop::types::ExecutionTier::DomHeadless,
            screenshot_base64: None,
            visual_phash: [0u8; 32],
            active_window_title: "Chromium".to_string(),
            project_index: String::new(),
            agents_md_content: String::new(),
            memory_pointers: String::new(),
            available_tools: Vec::new(),
            tool_desc: String::new(),
            visual_verification_note: None,
            last_failure_reason: None,
            consecutive_failures: 0,
        }
    }

    #[test]
    fn decode_recorded_messages_for_model_surface() {
        let encoded_recorded =
            codec::to_bytes_canonical(&sample_recorded_message()).expect("recorded encode");
        let model_msg = decode_session_message(&encoded_recorded, false);
        assert!(model_msg.is_some());
        let model_msg = model_msg.expect("model decode");
        assert_eq!(model_msg.role, "user");
        assert_eq!(model_msg.content, "raw secret: [REDACTED_PII]");
    }

    #[test]
    fn decode_recorded_message_prefers_raw_content_for_raw_surface() {
        let encoded_recorded =
            codec::to_bytes_canonical(&sample_recorded_message()).expect("recorded encode");
        let raw_msg = decode_session_message(&encoded_recorded, true);
        assert!(raw_msg.is_some());
        let raw_msg = raw_msg.expect("raw decode");
        assert_eq!(raw_msg.content, "raw secret: password=abc123");
    }

    struct NoopGuiDriver;

    #[async_trait]
    impl GuiDriver for NoopGuiDriver {
        async fn capture_screen(
            &self,
            _crop_rect: Option<(i32, i32, u32, u32)>,
        ) -> Result<Vec<u8>, VmError> {
            Err(VmError::HostError("noop gui".into()))
        }

        async fn capture_raw_screen(&self) -> Result<Vec<u8>, VmError> {
            Err(VmError::HostError("noop gui".into()))
        }

        async fn capture_tree(&self) -> Result<String, VmError> {
            Err(VmError::HostError("noop gui".into()))
        }

        async fn capture_context(&self, _intent: &ActionRequest) -> Result<ContextSlice, VmError> {
            Err(VmError::HostError("noop gui".into()))
        }

        async fn inject_input(&self, _event: InputEvent) -> Result<(), VmError> {
            Err(VmError::HostError("noop gui".into()))
        }

        async fn get_element_center(&self, _id: u32) -> Result<Option<(u32, u32)>, VmError> {
            Ok(None)
        }

        async fn register_som_overlay(
            &self,
            _map: std::collections::HashMap<u32, (i32, i32, i32, i32)>,
        ) -> Result<(), VmError> {
            Ok(())
        }
    }

    fn build_test_service_without_memory_runtime_with_inference(
        inference: Arc<dyn InferenceRuntime>,
    ) -> DesktopAgentService {
        let service = DesktopAgentService::new(
            Arc::new(NoopGuiDriver),
            Arc::new(TerminalDriver::new()),
            Arc::new(BrowserDriver::new()),
            inference,
        );
        service
    }

    fn build_test_service_with_temp_memory_runtime_with_inference(
        inference: Arc<dyn InferenceRuntime>,
    ) -> (DesktopAgentService, std::path::PathBuf) {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |time| time.as_nanos());
        let path = std::env::temp_dir().join(format!("ioi_service_memory_runtime_tests_{ts}.db"));
        let memory_runtime =
            MemoryRuntime::open_sqlite(&path).expect("memory runtime should initialize");

        let service = DesktopAgentService::new(
            Arc::new(NoopGuiDriver),
            Arc::new(TerminalDriver::new()),
            Arc::new(BrowserDriver::new()),
            inference,
        )
        .with_memory_runtime(Arc::new(memory_runtime));

        (service, path)
    }

    struct SlowInferenceRuntime;

    #[async_trait]
    impl InferenceRuntime for SlowInferenceRuntime {
        async fn execute_inference(
            &self,
            _model_hash: [u8; 32],
            _input_context: &[u8],
            _options: InferenceOptions,
        ) -> Result<Vec<u8>, VmError> {
            tokio::time::sleep(Duration::from_secs(30)).await;
            Ok(b"[]".to_vec())
        }

        async fn embed_text(&self, _text: &str) -> Result<Vec<f32>, VmError> {
            tokio::time::sleep(Duration::from_secs(30)).await;
            Ok(vec![0.0, 1.0, 2.0])
        }

        async fn load_model(
            &self,
            _model_hash: [u8; 32],
            _path: &std::path::Path,
        ) -> Result<(), VmError> {
            Ok(())
        }

        async fn unload_model(&self, _model_hash: [u8; 32]) -> Result<(), VmError> {
            Ok(())
        }
    }

    struct NoExecuteInferenceRuntime;

    #[async_trait]
    impl InferenceRuntime for NoExecuteInferenceRuntime {
        async fn execute_inference(
            &self,
            _model_hash: [u8; 32],
            _input_context: &[u8],
            _options: InferenceOptions,
        ) -> Result<Vec<u8>, VmError> {
            panic!("append_chat_to_scs must not call execute_inference");
        }

        async fn embed_text(&self, _text: &str) -> Result<Vec<f32>, VmError> {
            Ok(vec![0.0, 1.0, 2.0])
        }

        async fn load_model(
            &self,
            _model_hash: [u8; 32],
            _path: &std::path::Path,
        ) -> Result<(), VmError> {
            Ok(())
        }

        async fn unload_model(&self, _model_hash: [u8; 32]) -> Result<(), VmError> {
            Ok(())
        }
    }

    struct NoInferenceRuntime;

    #[async_trait]
    impl InferenceRuntime for NoInferenceRuntime {
        async fn execute_inference(
            &self,
            _model_hash: [u8; 32],
            _input_context: &[u8],
            _options: InferenceOptions,
        ) -> Result<Vec<u8>, VmError> {
            panic!("append_chat_to_scs must not call execute_inference");
        }

        async fn embed_text(&self, _text: &str) -> Result<Vec<f32>, VmError> {
            panic!("append_chat_to_scs must not call embed_text for tool/system roles");
        }

        async fn load_model(
            &self,
            _model_hash: [u8; 32],
            _path: &std::path::Path,
        ) -> Result<(), VmError> {
            Ok(())
        }

        async fn unload_model(&self, _model_hash: [u8; 32]) -> Result<(), VmError> {
            Ok(())
        }
    }

    struct KeywordEmbeddingRuntime;

    #[async_trait]
    impl InferenceRuntime for KeywordEmbeddingRuntime {
        async fn execute_inference(
            &self,
            _model_hash: [u8; 32],
            _input_context: &[u8],
            _options: InferenceOptions,
        ) -> Result<Vec<u8>, VmError> {
            panic!("memory retrieval tests must not call execute_inference");
        }

        async fn embed_text(&self, text: &str) -> Result<Vec<f32>, VmError> {
            let normalized = text.to_ascii_lowercase();
            if normalized.contains("standup") || normalized.contains("2 pm") {
                Ok(vec![1.0, 0.0])
            } else if normalized.contains("calculator") {
                Ok(vec![0.0, 1.0])
            } else {
                Ok(vec![0.5, 0.5])
            }
        }

        async fn load_model(
            &self,
            _model_hash: [u8; 32],
            _path: &std::path::Path,
        ) -> Result<(), VmError> {
            Ok(())
        }

        async fn unload_model(&self, _model_hash: [u8; 32]) -> Result<(), VmError> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn append_and_hydrate_session_history_requires_memory_runtime() {
        let service = build_test_service_without_memory_runtime_with_inference(Arc::new(
            MockInferenceRuntime,
        ));
        let session_id = [11u8; 32];
        let msg = ChatMessage {
            role: "user".to_string(),
            content: "please use API_KEY=sk_live_123456789".to_string(),
            timestamp: 1_700_000_000_000u64,
            trace_hash: None,
        };

        let append_res = service.append_chat_to_scs(session_id, &msg, 0).await;
        assert!(append_res.is_err());

        let model_surface = service.hydrate_session_history(session_id);
        assert!(model_surface.is_err());

        let raw_surface = service.hydrate_session_history_raw(session_id);
        assert!(raw_surface.is_err());
    }

    #[tokio::test]
    async fn append_and_hydrate_session_history_roundtrips_through_memory_runtime() {
        let (service, path) = build_test_service_with_temp_memory_runtime_with_inference(Arc::new(
            MockInferenceRuntime,
        ));
        let session_id = [12u8; 32];
        let msg = ChatMessage {
            role: "user".to_string(),
            content: "please use API_KEY=sk_live_987654321".to_string(),
            timestamp: 1_700_000_000_001u64,
            trace_hash: None,
        };

        let append_res = service.append_chat_to_scs(session_id, &msg, 0).await;
        assert!(append_res.is_ok());

        let model_surface = service.hydrate_session_history(session_id);
        assert!(model_surface.is_ok());
        let model_msgs = model_surface.expect("model hydration");
        assert_eq!(model_msgs.len(), 1);
        assert!(!model_msgs[0].content.contains("sk_live_987654321"));

        let raw_surface = service.hydrate_session_history_raw(session_id);
        assert!(raw_surface.is_ok());
        let raw_msgs = raw_surface.expect("raw hydration");
        assert_eq!(raw_msgs.len(), 1);
        assert!(raw_msgs[0].content.contains("sk_live_987654321"));

        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn retrieve_context_hybrid_roundtrips_through_memory_runtime_archival_search() {
        let (service, path) = build_test_service_with_temp_memory_runtime_with_inference(Arc::new(
            KeywordEmbeddingRuntime,
        ));
        let session_id = [21u8; 32];

        let first = ChatMessage {
            role: "user".to_string(),
            content: "Tomorrow's standup is moved to 2 pm Eastern.".to_string(),
            timestamp: 1_700_000_000_010u64,
            trace_hash: None,
        };
        let second = ChatMessage {
            role: "user".to_string(),
            content: "Launch calculator and keep it pinned.".to_string(),
            timestamp: 1_700_000_000_011u64,
            trace_hash: None,
        };

        assert!(service
            .append_chat_to_scs(session_id, &first, 0)
            .await
            .is_ok());
        assert!(service
            .append_chat_to_scs(session_id, &second, 0)
            .await
            .is_ok());

        let retrieval = service
            .retrieve_context_hybrid_with_receipt("what changed about tomorrow's standup?", None)
            .await;

        assert!(retrieval.output.contains("standup"));
        assert!(retrieval.output.contains("[ID:"));
        let receipt = retrieval.receipt.expect("memory runtime receipt");
        assert_eq!(receipt.backend, "ioi-memory:hybrid-archival");
        assert!(receipt.success);
        assert_eq!(receipt.proof_ref, None);

        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn append_chat_to_scs_enforces_semantic_indexing_budget() {
        let (service, path) = build_test_service_with_temp_memory_runtime_with_inference(Arc::new(
            SlowInferenceRuntime,
        ));
        let session_id = [33u8; 32];
        let seed_msg = ChatMessage {
            role: "user".to_string(),
            content: "Seed semantic history before timing assistant indexing.".to_string(),
            timestamp: 1_700_000_000_100u64,
            trace_hash: None,
        };
        let seed_res = service.append_chat_to_scs(session_id, &seed_msg, 0).await;
        assert!(seed_res.is_ok());

        let msg = ChatMessage {
            role: "assistant".to_string(),
            content: "This is long enough to trigger semantic fact extraction and embedding work."
                .to_string(),
            timestamp: 1_700_000_000_123u64,
            trace_hash: None,
        };

        let started = Instant::now();
        let append_res = service.append_chat_to_scs(session_id, &msg, 0).await;
        let elapsed = started.elapsed();

        assert!(append_res.is_ok());
        assert!(
            elapsed < SEMANTIC_INDEXING_BUDGET + Duration::from_secs(3),
            "append_chat_to_scs exceeded semantic indexing budget: {:?}",
            elapsed
        );

        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn append_chat_to_scs_skips_semantic_indexing_for_structured_assistant_tool_calls() {
        let (service, path) = build_test_service_with_temp_memory_runtime_with_inference(Arc::new(
            NoInferenceRuntime,
        ));
        let session_id = [56u8; 32];
        let msg = ChatMessage {
            role: "assistant".to_string(),
            content: r#"{"name":"browser__synthetic_click","arguments":{"x":63.0,"y":104.0}}"#
                .to_string(),
            timestamp: 1_700_000_000_791u64,
            trace_hash: None,
        };

        let append_res = service.append_chat_to_scs(session_id, &msg, 0).await;
        assert!(append_res.is_ok());

        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn append_chat_to_scs_avoids_execute_inference_for_fact_extraction() {
        let (service, path) = build_test_service_with_temp_memory_runtime_with_inference(Arc::new(
            NoExecuteInferenceRuntime,
        ));
        let session_id = [44u8; 32];
        let msg = ChatMessage {
            role: "tool".to_string(),
            content: "Tool Output (os__launch_app): Launched background process 'gnome-calculator' (PID: 555837)"
                .to_string(),
            timestamp: 1_700_000_000_456u64,
            trace_hash: None,
        };

        let append_res = service.append_chat_to_scs(session_id, &msg, 0).await;
        assert!(append_res.is_ok());

        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn append_chat_to_scs_skips_inference_for_tool_messages() {
        let (service, path) = build_test_service_with_temp_memory_runtime_with_inference(Arc::new(
            NoInferenceRuntime,
        ));
        let session_id = [55u8; 32];
        let msg = ChatMessage {
            role: "tool".to_string(),
            content: "Tool Output (os__launch_app): Launched background process 'calculator'"
                .to_string(),
            timestamp: 1_700_000_000_789u64,
            trace_hash: None,
        };

        let append_res = service.append_chat_to_scs(session_id, &msg, 0).await;
        assert!(append_res.is_ok());

        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn core_memory_updates_are_governed_and_prompt_ready() {
        let (service, path) = build_test_service_with_temp_memory_runtime_with_inference(Arc::new(
            MockInferenceRuntime,
        ));
        let session_id = [77u8; 32];
        let agent_state = sample_agent_state(session_id, "Complete checkout flow");
        let perception = sample_perception_context();
        let memory_runtime = service.memory_runtime.as_ref().expect("memory runtime");

        replace_core_memory_from_tool(
            memory_runtime,
            session_id,
            "workflow.stage",
            "Logged in and navigating to cart.",
        )
        .expect("replace workflow stage");
        append_core_memory_from_tool(
            memory_runtime,
            session_id,
            "workflow.notes",
            "Cart modal appears after clicking the top-right cart icon.",
        )
        .expect("append workflow notes");
        pin_core_memory_section(memory_runtime, session_id, "workflow.notes", true)
            .expect("pin workflow notes");

        let prompt_memory =
            prepare_prompt_memory_context(&service, session_id, &agent_state, &perception, None)
                .await
                .expect("prepare prompt memory");
        assert!(prompt_memory.contains("Current Goal: Complete checkout flow"));
        assert!(prompt_memory.contains("Workflow Stage: Logged in and navigating to cart."));
        assert!(prompt_memory.contains("Workflow Notes: Cart modal appears"));

        let rejected = replace_core_memory_from_tool(
            memory_runtime,
            session_id,
            "user.preferences.safe",
            "The password is hunter2",
        );
        assert!(rejected.is_err());

        let audits = memory_runtime
            .search_archival_memory(&ArchivalMemoryQuery {
                scope: MEMORY_RUNTIME_CORE_AUDIT_SCOPE.to_string(),
                thread_id: Some(session_id),
                text: "workflow.stage".to_string(),
                limit: 10,
            })
            .expect("load core audit records");
        assert!(!audits.is_empty());

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn load_memory_session_status_exposes_core_memory_and_prompt_diagnostics() {
        let runtime = MemoryRuntime::open_sqlite_in_memory().expect("runtime");
        let session_id = [76u8; 32];

        replace_core_memory_from_tool(
            &runtime,
            session_id,
            "workflow.stage",
            "Reviewing the cart modal before checkout.",
        )
        .expect("replace core memory");
        persist_prompt_memory_diagnostics(
            &runtime,
            session_id,
            &MemoryPromptDiagnostics {
                updated_at_ms: 123,
                session_id_hex: hex::encode(session_id),
                total_chars: 400,
                prompt_hash: "prompt".to_string(),
                stable_prefix_hash: "stable".to_string(),
                dynamic_suffix_hash: "dynamic".to_string(),
                sections: vec![MemoryPromptSectionDiagnostic {
                    name: "core_memory".to_string(),
                    included: true,
                    budget_chars: Some(500),
                    original_chars: 120,
                    rendered_chars: 120,
                    truncated: false,
                }],
            },
        )
        .expect("persist prompt diagnostics");

        let status = load_memory_session_status(&runtime, session_id).expect("load session status");
        assert_eq!(status.session_id_hex, hex::encode(session_id));
        assert_eq!(status.core_sections.len(), 1);
        assert_eq!(status.core_sections[0].section, "workflow.stage");
        assert!(status.prompt_diagnostics.is_some());
        assert!(!status.core_audits.is_empty());
    }

    #[tokio::test]
    async fn prepare_prompt_memory_context_persists_structured_ui_memory() {
        let (service, path) = build_test_service_with_temp_memory_runtime_with_inference(Arc::new(
            MockInferenceRuntime,
        ));
        let session_id = [78u8; 32];
        let agent_state = sample_agent_state(session_id, "Open cart modal");
        let perception = sample_perception_context();
        let snapshot = r#"
            <root>
              <window name="Shop">
                <dialog name="Cart">
                  <button id="checkout">Checkout</button>
                </dialog>
              </window>
            </root>
        "#;

        let prompt_memory = prepare_prompt_memory_context(
            &service,
            session_id,
            &agent_state,
            &perception,
            Some(snapshot),
        )
        .await
        .expect("prepare prompt memory");
        assert!(prompt_memory.contains("Current Goal"));

        let memory_runtime = service.memory_runtime.as_ref().expect("memory runtime");
        let ui_records = memory_runtime
            .search_archival_memory(&ArchivalMemoryQuery {
                scope: MEMORY_RUNTIME_UI_SCOPE.to_string(),
                thread_id: Some(session_id),
                text: "Checkout".to_string(),
                limit: 10,
            })
            .expect("search ui memory");
        assert!(!ui_records.is_empty());
        assert!(ui_records[0].content.contains("Checkout"));

        let checkpoint_blob = memory_runtime
            .load_checkpoint_blob(session_id, MEMORY_RUNTIME_LAST_UI_SNAPSHOT_CHECKPOINT)
            .expect("load ui checkpoint");
        assert!(checkpoint_blob.is_some());

        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn enrichment_jobs_materialize_runtime_derived_records() {
        let runtime = Arc::new(MemoryRuntime::open_sqlite_in_memory().expect("runtime"));
        let session_id = [79u8; 32];
        let source_record_id = runtime
            .insert_archival_record(&NewArchivalMemoryRecord {
                scope: MEMORY_RUNTIME_TRANSCRIPT_SCOPE.to_string(),
                thread_id: Some(session_id),
                kind: "chat_message".to_string(),
                content: "Checkout Button opens the Cart Modal. Step 1. Click Checkout Button. Then confirm the order on the Dashboard.".to_string(),
                metadata_json: r#"{"trust_level":"runtime_observed"}"#.to_string(),
            })
            .expect("insert source")
            .expect("source id");
        assert!(enqueue_transcript_enrichment_jobs(
            &runtime,
            session_id,
            source_record_id
        ));

        let report = process_pending_memory_enrichment_jobs_once(
            runtime.clone(),
            Arc::new(KeywordEmbeddingRuntime),
            8,
        )
        .await
        .expect("process enrichment");
        assert!(report.claimed >= 1);
        assert!(report.completed >= 1);
        assert!(report.inserted_records >= 1);

        let facts = runtime
            .search_archival_memory(&ArchivalMemoryQuery {
                scope: MEMORY_RUNTIME_FACT_SCOPE.to_string(),
                thread_id: Some(session_id),
                text: "Checkout".to_string(),
                limit: 10,
            })
            .expect("search facts");
        assert!(!facts.is_empty());

        let status = load_memory_session_status(runtime.as_ref(), session_id).expect("status");
        let diagnostics = status
            .enrichment_diagnostics
            .expect("enrichment diagnostics");
        assert!(diagnostics.completed_jobs >= 1);
        assert!(diagnostics.inserted_records >= 1);
    }

    #[tokio::test]
    async fn enrichment_diagnostics_track_secret_like_rejections() {
        let runtime = Arc::new(MemoryRuntime::open_sqlite_in_memory().expect("runtime"));
        let session_id = [80u8; 32];
        let source_record_id = runtime
            .insert_archival_record(&NewArchivalMemoryRecord {
                scope: MEMORY_RUNTIME_TRANSCRIPT_SCOPE.to_string(),
                thread_id: Some(session_id),
                kind: "chat_message".to_string(),
                content: "The password is hunter2 for the staging dashboard.".to_string(),
                metadata_json: r#"{"trust_level":"runtime_observed"}"#.to_string(),
            })
            .expect("insert source")
            .expect("source id");
        assert!(enqueue_transcript_enrichment_jobs(
            &runtime,
            session_id,
            source_record_id
        ));

        let report = process_pending_memory_enrichment_jobs_once(
            runtime.clone(),
            Arc::new(KeywordEmbeddingRuntime),
            8,
        )
        .await
        .expect("process enrichment");
        assert!(report.rejected_candidates >= 1);

        let status = load_memory_session_status(runtime.as_ref(), session_id).expect("status");
        let diagnostics = status
            .enrichment_diagnostics
            .expect("enrichment diagnostics");
        assert!(diagnostics.rejected_candidates >= 1);
        assert!(diagnostics
            .rejected_by_reason
            .contains_key("secret_like_content"));
    }

    #[tokio::test]
    async fn ui_relationship_enrichment_materializes_control_context_records() {
        let runtime = Arc::new(MemoryRuntime::open_sqlite_in_memory().expect("runtime"));
        let session_id = [81u8; 32];
        let artifact_id = "desktop.ui.snapshot.test".to_string();
        runtime
            .upsert_artifact_json(
                session_id,
                &artifact_id,
                r#"{"kind":"ui_snapshot_xml","trust_level":"runtime_observed"}"#,
            )
            .expect("artifact metadata");
        runtime
            .put_artifact_blob(
                session_id,
                &artifact_id,
                br#"
                    <root>
                      <window name="Shop">
                        <dialog name="Cart Modal">
                          <button id="checkout_button" name="Checkout" />
                        </dialog>
                      </window>
                    </root>
                "#,
            )
            .expect("artifact blob");
        let source_record_id = runtime
            .insert_archival_record(&NewArchivalMemoryRecord {
                scope: MEMORY_RUNTIME_UI_SCOPE.to_string(),
                thread_id: Some(session_id),
                kind: "ui_observation".to_string(),
                content: "Window Shop URL https://example.test/cart Snapshot Hash abc".to_string(),
                metadata_json: r#"{"trust_level":"runtime_observed","active_window_title":"Shop","active_url":"https://example.test/cart","snapshot_hash":"abc"}"#.to_string(),
            })
            .expect("insert source")
            .expect("source id");

        assert!(enqueue_ui_enrichment_jobs(
            &runtime,
            session_id,
            source_record_id,
            &artifact_id
        ));
        let report = process_pending_memory_enrichment_jobs_once(
            runtime.clone(),
            Arc::new(KeywordEmbeddingRuntime),
            8,
        )
        .await
        .expect("process ui enrichment");
        assert!(report.inserted_records >= 1);
        let blob = runtime
            .load_artifact_blob(&artifact_id)
            .expect("load artifact")
            .expect("artifact blob");
        let source = runtime
            .load_archival_record(source_record_id)
            .expect("load source")
            .expect("source record");
        let extracted =
            extract_ui_relationship_candidates(&source, &String::from_utf8_lossy(&blob));
        assert!(extracted
            .iter()
            .any(|record| record.contains("Checkout") && record.contains("Cart Modal")));
    }

    #[test]
    fn procedure_candidate_extractor_recognizes_inline_step_sequences() {
        let candidate = extract_procedure_candidate(
            "Checkout Button opens the Cart Modal. Step 1. Click Checkout Button. Then confirm the order on the Dashboard.",
        );
        assert!(candidate.is_some());
        let candidate = candidate.expect("procedure candidate");
        assert!(candidate.contains("Step 1"));
        assert!(candidate.contains("Then confirm"));
    }
}
