use crate::identity;
use crate::kernel::state::get_rpc_client;
use crate::models::{
    AgentPhase, AppState, SessionCompactionCarryForwardState, SessionCompactionDisposition,
    SessionCompactionMemoryItem, SessionCompactionMode, SessionCompactionPolicy,
    SessionCompactionPreview, SessionCompactionPruneDecision, SessionCompactionRecommendation,
    SessionCompactionRecord, SessionCompactionResumeSafetyReceipt,
    SessionCompactionResumeSafetyStatus, SessionCompactionSnapshot, SessionDurabilityPortfolio,
    SessionMemoryClass, SessionProjection, SessionRewindCandidate, SessionRewindSnapshot,
    SessionSummary, TeamMemoryRedactionSummary, TeamMemoryScopeKind, TeamMemorySyncEntry,
    TeamMemorySyncSnapshot, TeamMemorySyncStatus,
};
use crate::orchestrator;
use ioi_crypto::algorithms::hash::sha256;
use ioi_ipc::blockchain::QueryRawStateRequest;
use ioi_pii::scrub_text;
use ioi_types::app::{
    account_id_from_key_material, ChainId, ChainTransaction, RedactionType, SignHeader,
    SignatureProof, SignatureSuite, SystemPayload, SystemTransaction,
};
use ioi_types::codec;
use parity_scale_codec::{Decode, Encode};
use std::collections::BTreeSet;
use std::path::Path;
use std::sync::{Arc, Mutex};
use tauri::{AppHandle, Emitter, Manager, State};
use tokio::time::{timeout, Duration};
use uuid::Uuid;

const SESSION_HISTORY_RPC_TIMEOUT_MS: u64 = 1_500;
const SESSION_HISTORY_MONITOR_INTERVAL_MS: u64 = 2_000;
const AUTO_COMPACTION_HISTORY_THRESHOLD: usize = 24;
const AUTO_COMPACTION_EVENT_THRESHOLD: usize = 24;
const AUTO_COMPACTION_ARTIFACT_THRESHOLD: usize = 8;
const AUTO_COMPACTION_FILE_CONTEXT_THRESHOLD: usize = 4;
const AUTO_COMPACTION_IDLE_THRESHOLD_MS: u64 = 5 * 60 * 1000;
const AUTO_COMPACTION_BLOCKED_THRESHOLD_MS: u64 = 2 * 60 * 1000;
const TEAM_MEMORY_SYNC_REDACTION_VERSION: &str = "team_memory_sync.redaction.v1";
const TEAM_MEMORY_SYNC_MAX_ENTRIES: usize = 48;
const TEAM_MEMORY_SYNC_MAX_ITEM_VALUES: usize = 3;
const TEAM_MEMORY_SYNC_MAX_ITEM_VALUE_CHARS: usize = 96;

include!("remote.rs");
include!("projection.rs");
include!("summaries.rs");
include!("compaction.rs");
include!("compaction_policy.rs");
include!("team_memory.rs");
include!("rewind.rs");
include!("history.rs");

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
