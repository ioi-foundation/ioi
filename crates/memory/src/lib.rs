#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unimplemented,
        clippy::todo,
        clippy::indexing_slicing
    )
)]

use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MemoryError {
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("serde json: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("memory connection lock poisoned")]
    LockPoisoned,
}

pub type Result<T> = std::result::Result<T, MemoryError>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct TranscriptPrivacyMetadata {
    #[serde(default)]
    pub redaction_version: String,
    #[serde(default)]
    pub sensitive_fields_mask: Vec<String>,
    #[serde(default)]
    pub policy_id: String,
    #[serde(default)]
    pub policy_version: String,
    #[serde(default)]
    pub scrubbed_for_model_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct StoredTranscriptMessage {
    #[serde(default)]
    pub role: String,
    #[serde(default)]
    pub timestamp_ms: u64,
    #[serde(default)]
    pub trace_hash: Option<[u8; 32]>,
    #[serde(default)]
    pub raw_content: String,
    #[serde(default)]
    pub model_content: String,
    #[serde(default)]
    pub store_content: String,
    #[serde(default)]
    pub raw_reference: Option<String>,
    #[serde(default)]
    pub privacy_metadata: TranscriptPrivacyMetadata,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TranscriptSurface {
    Model,
    Raw,
    Store,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CoreMemorySection {
    pub section: String,
    pub content: String,
    pub updated_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NewArchivalMemoryRecord {
    pub scope: String,
    pub thread_id: Option<[u8; 32]>,
    pub kind: String,
    pub content: String,
    pub metadata_json: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArchivalMemoryRecord {
    pub id: i64,
    pub scope: String,
    pub thread_id: Option<[u8; 32]>,
    pub kind: String,
    pub content: String,
    pub metadata_json: String,
    pub created_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArchivalMemoryQuery {
    pub scope: String,
    pub thread_id: Option<[u8; 32]>,
    pub text: String,
    pub limit: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SemanticArchivalMemoryQuery {
    pub scope: String,
    pub thread_id: Option<[u8; 32]>,
    pub text_filter: Option<String>,
    pub embedding: Vec<f32>,
    pub limit: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ArchivalMemorySearchHit {
    pub record: ArchivalMemoryRecord,
    pub score: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HybridArchivalMemoryQuery {
    pub scopes: Vec<String>,
    pub thread_id: Option<[u8; 32]>,
    pub text: String,
    pub embedding: Option<Vec<f32>>,
    pub limit: usize,
    pub candidate_limit: usize,
    #[serde(default)]
    pub allowed_trust_levels: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HybridArchivalMemorySearchHit {
    pub record: ArchivalMemoryRecord,
    pub score: f32,
    pub semantic_score: Option<f32>,
    pub lexical_score: f32,
    pub trust_level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredThreadEvent {
    pub event_id: String,
    pub payload_json: String,
    pub created_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredArtifactRecord {
    pub artifact_id: String,
    pub payload_json: String,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EnrichmentJobStatus {
    Pending,
    Claimed,
    Completed,
    Failed,
}

impl EnrichmentJobStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Claimed => "claimed",
            Self::Completed => "completed",
            Self::Failed => "failed",
        }
    }

    fn parse(raw: &str) -> Self {
        match raw {
            "claimed" => Self::Claimed,
            "completed" => Self::Completed,
            "failed" => Self::Failed,
            _ => Self::Pending,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NewEnrichmentJob {
    pub thread_id: Option<[u8; 32]>,
    pub kind: String,
    pub payload_json: String,
    #[serde(default)]
    pub dedupe_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredEnrichmentJob {
    pub id: i64,
    pub thread_id: Option<[u8; 32]>,
    pub kind: String,
    pub payload_json: String,
    pub status: EnrichmentJobStatus,
    pub dedupe_key: Option<String>,
    pub attempts: u32,
    pub claimed_by: Option<String>,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
    pub last_error: Option<String>,
}

pub trait Checkpointer: Send + Sync {
    fn append_transcript_message(
        &self,
        thread_id: [u8; 32],
        message: &StoredTranscriptMessage,
    ) -> Result<()>;

    fn load_transcript_messages(&self, thread_id: [u8; 32])
        -> Result<Vec<StoredTranscriptMessage>>;

    fn upsert_checkpoint_blob(
        &self,
        thread_id: [u8; 32],
        checkpoint_name: &str,
        payload: &[u8],
    ) -> Result<()>;

    fn load_checkpoint_blob(
        &self,
        thread_id: [u8; 32],
        checkpoint_name: &str,
    ) -> Result<Option<Vec<u8>>>;

    fn delete_checkpoint_blob(&self, thread_id: [u8; 32], checkpoint_name: &str) -> Result<()>;
}

pub trait CoreMemoryStore: Send + Sync {
    fn replace_section(&self, thread_id: [u8; 32], section: &str, content: &str) -> Result<()>;

    fn load_section(&self, thread_id: [u8; 32], section: &str)
        -> Result<Option<CoreMemorySection>>;

    fn delete_section(&self, thread_id: [u8; 32], section: &str) -> Result<()>;
}

pub trait ArchivalMemoryStore: Send + Sync {
    fn insert_record(&self, record: &NewArchivalMemoryRecord) -> Result<i64>;

    fn load_record(&self, record_id: i64) -> Result<Option<ArchivalMemoryRecord>>;

    fn search(&self, query: &ArchivalMemoryQuery) -> Result<Vec<ArchivalMemoryRecord>>;

    fn upsert_record_embedding(&self, record_id: i64, embedding: &[f32]) -> Result<()>;

    fn semantic_search(
        &self,
        query: &SemanticArchivalMemoryQuery,
    ) -> Result<Vec<ArchivalMemorySearchHit>>;
}

pub trait EventStore: Send + Sync {
    fn append_event_json(
        &self,
        thread_id: [u8; 32],
        event_id: &str,
        payload_json: &str,
    ) -> Result<()>;

    fn load_event_jsons(
        &self,
        thread_id: [u8; 32],
        limit: Option<usize>,
        cursor: Option<usize>,
    ) -> Result<Vec<StoredThreadEvent>>;
}

pub trait ArtifactStore: Send + Sync {
    fn upsert_artifact_json(
        &self,
        thread_id: [u8; 32],
        artifact_id: &str,
        payload_json: &str,
    ) -> Result<()>;

    fn load_artifact_jsons(&self, thread_id: [u8; 32]) -> Result<Vec<StoredArtifactRecord>>;

    fn put_artifact_blob(
        &self,
        thread_id: [u8; 32],
        artifact_id: &str,
        content: &[u8],
    ) -> Result<()>;

    fn load_artifact_blob(&self, artifact_id: &str) -> Result<Option<Vec<u8>>>;
}

pub trait ExecutionCacheStore: Send + Sync {
    fn upsert_execution_cache_json(&self, cache_key: [u8; 32], payload_json: &str) -> Result<()>;

    fn load_execution_cache_json(&self, cache_key: [u8; 32]) -> Result<Option<String>>;
}

pub trait EnrichmentQueueStore: Send + Sync {
    fn enqueue_job(&self, job: &NewEnrichmentJob) -> Result<i64>;

    fn load_jobs(
        &self,
        status: Option<EnrichmentJobStatus>,
        limit: usize,
    ) -> Result<Vec<StoredEnrichmentJob>>;

    fn claim_jobs(&self, worker_id: &str, limit: usize) -> Result<Vec<StoredEnrichmentJob>>;

    fn complete_job(&self, job_id: i64) -> Result<()>;

    fn fail_job(&self, job_id: i64, error: &str) -> Result<()>;
}

#[derive(Clone)]
pub struct MemoryRuntime {
    checkpointer: Arc<dyn Checkpointer>,
    core_memory: Option<Arc<dyn CoreMemoryStore>>,
    archival_memory: Option<Arc<dyn ArchivalMemoryStore>>,
    event_store: Option<Arc<dyn EventStore>>,
    artifact_store: Option<Arc<dyn ArtifactStore>>,
    execution_cache: Option<Arc<dyn ExecutionCacheStore>>,
    enrichment_queue: Option<Arc<dyn EnrichmentQueueStore>>,
}

impl MemoryRuntime {
    pub fn new(checkpointer: Arc<dyn Checkpointer>) -> Self {
        Self {
            checkpointer,
            core_memory: None,
            archival_memory: None,
            event_store: None,
            artifact_store: None,
            execution_cache: None,
            enrichment_queue: None,
        }
    }

    pub fn with_core_memory(mut self, store: Arc<dyn CoreMemoryStore>) -> Self {
        self.core_memory = Some(store);
        self
    }

    pub fn with_archival_memory(mut self, store: Arc<dyn ArchivalMemoryStore>) -> Self {
        self.archival_memory = Some(store);
        self
    }

    pub fn with_event_store(mut self, store: Arc<dyn EventStore>) -> Self {
        self.event_store = Some(store);
        self
    }

    pub fn with_artifact_store(mut self, store: Arc<dyn ArtifactStore>) -> Self {
        self.artifact_store = Some(store);
        self
    }

    pub fn with_execution_cache(mut self, store: Arc<dyn ExecutionCacheStore>) -> Self {
        self.execution_cache = Some(store);
        self
    }

    pub fn with_enrichment_queue(mut self, store: Arc<dyn EnrichmentQueueStore>) -> Self {
        self.enrichment_queue = Some(store);
        self
    }

    pub fn open_sqlite(path: &Path) -> Result<Self> {
        let store = Arc::new(SqliteMemoryStore::open(path)?);
        let checkpointer: Arc<dyn Checkpointer> = store.clone();
        let core_memory: Arc<dyn CoreMemoryStore> = store.clone();
        let archival_memory: Arc<dyn ArchivalMemoryStore> = store.clone();
        let event_store: Arc<dyn EventStore> = store.clone();
        let artifact_store: Arc<dyn ArtifactStore> = store.clone();
        let execution_cache: Arc<dyn ExecutionCacheStore> = store.clone();
        let enrichment_queue: Arc<dyn EnrichmentQueueStore> = store;
        Ok(Self::new(checkpointer)
            .with_core_memory(core_memory)
            .with_archival_memory(archival_memory)
            .with_event_store(event_store)
            .with_artifact_store(artifact_store)
            .with_execution_cache(execution_cache)
            .with_enrichment_queue(enrichment_queue))
    }

    pub fn open_sqlite_in_memory() -> Result<Self> {
        let store = Arc::new(SqliteMemoryStore::open_in_memory()?);
        let checkpointer: Arc<dyn Checkpointer> = store.clone();
        let core_memory: Arc<dyn CoreMemoryStore> = store.clone();
        let archival_memory: Arc<dyn ArchivalMemoryStore> = store.clone();
        let event_store: Arc<dyn EventStore> = store.clone();
        let artifact_store: Arc<dyn ArtifactStore> = store.clone();
        let execution_cache: Arc<dyn ExecutionCacheStore> = store.clone();
        let enrichment_queue: Arc<dyn EnrichmentQueueStore> = store;
        Ok(Self::new(checkpointer)
            .with_core_memory(core_memory)
            .with_archival_memory(archival_memory)
            .with_event_store(event_store)
            .with_artifact_store(artifact_store)
            .with_execution_cache(execution_cache)
            .with_enrichment_queue(enrichment_queue))
    }

    pub fn append_transcript_message(
        &self,
        thread_id: [u8; 32],
        message: &StoredTranscriptMessage,
    ) -> Result<()> {
        self.checkpointer
            .append_transcript_message(thread_id, message)
    }

    pub fn load_transcript_messages(
        &self,
        thread_id: [u8; 32],
    ) -> Result<Vec<StoredTranscriptMessage>> {
        self.checkpointer.load_transcript_messages(thread_id)
    }

    pub fn upsert_checkpoint_blob(
        &self,
        thread_id: [u8; 32],
        checkpoint_name: &str,
        payload: &[u8],
    ) -> Result<()> {
        self.checkpointer
            .upsert_checkpoint_blob(thread_id, checkpoint_name, payload)
    }

    pub fn load_checkpoint_blob(
        &self,
        thread_id: [u8; 32],
        checkpoint_name: &str,
    ) -> Result<Option<Vec<u8>>> {
        self.checkpointer
            .load_checkpoint_blob(thread_id, checkpoint_name)
    }

    pub fn delete_checkpoint_blob(&self, thread_id: [u8; 32], checkpoint_name: &str) -> Result<()> {
        self.checkpointer
            .delete_checkpoint_blob(thread_id, checkpoint_name)
    }

    pub fn replace_core_memory_section(
        &self,
        thread_id: [u8; 32],
        section: &str,
        content: &str,
    ) -> Result<()> {
        match &self.core_memory {
            Some(store) => store.replace_section(thread_id, section, content),
            None => Ok(()),
        }
    }

    pub fn load_core_memory_section(
        &self,
        thread_id: [u8; 32],
        section: &str,
    ) -> Result<Option<CoreMemorySection>> {
        match &self.core_memory {
            Some(store) => store.load_section(thread_id, section),
            None => Ok(None),
        }
    }

    pub fn delete_core_memory_section(&self, thread_id: [u8; 32], section: &str) -> Result<()> {
        match &self.core_memory {
            Some(store) => store.delete_section(thread_id, section),
            None => Ok(()),
        }
    }

    pub fn insert_archival_record(&self, record: &NewArchivalMemoryRecord) -> Result<Option<i64>> {
        match &self.archival_memory {
            Some(store) => store.insert_record(record).map(Some),
            None => Ok(None),
        }
    }

    pub fn search_archival_memory(
        &self,
        query: &ArchivalMemoryQuery,
    ) -> Result<Vec<ArchivalMemoryRecord>> {
        match &self.archival_memory {
            Some(store) => store.search(query),
            None => Ok(Vec::new()),
        }
    }

    pub fn load_archival_record(&self, record_id: i64) -> Result<Option<ArchivalMemoryRecord>> {
        match &self.archival_memory {
            Some(store) => store.load_record(record_id),
            None => Ok(None),
        }
    }

    pub fn upsert_archival_embedding(&self, record_id: i64, embedding: &[f32]) -> Result<()> {
        match &self.archival_memory {
            Some(store) => store.upsert_record_embedding(record_id, embedding),
            None => Ok(()),
        }
    }

    pub fn semantic_search_archival_memory(
        &self,
        query: &SemanticArchivalMemoryQuery,
    ) -> Result<Vec<ArchivalMemorySearchHit>> {
        match &self.archival_memory {
            Some(store) => store.semantic_search(query),
            None => Ok(Vec::new()),
        }
    }

    pub fn hybrid_search_archival_memory(
        &self,
        query: &HybridArchivalMemoryQuery,
    ) -> Result<Vec<HybridArchivalMemorySearchHit>> {
        let limit = query.limit.max(1);
        let candidate_limit = query.candidate_limit.max(limit);
        let text = query.text.trim().to_string();
        let allowed_trust_levels = query
            .allowed_trust_levels
            .iter()
            .map(|value| value.trim().to_ascii_lowercase())
            .filter(|value| !value.is_empty())
            .collect::<std::collections::HashSet<_>>();

        #[derive(Debug)]
        struct CombinedHit {
            record: ArchivalMemoryRecord,
            lexical_score: f32,
            semantic_score: Option<f32>,
            trust_level: String,
        }

        let mut combined = std::collections::BTreeMap::<i64, CombinedHit>::new();
        let mut seen_scopes = std::collections::HashSet::<String>::new();

        for scope in query
            .scopes
            .iter()
            .map(|scope| scope.trim())
            .filter(|scope| !scope.is_empty())
        {
            if !seen_scopes.insert(scope.to_string()) {
                continue;
            }

            if !text.is_empty() {
                for record in self.search_archival_memory(&ArchivalMemoryQuery {
                    scope: scope.to_string(),
                    thread_id: query.thread_id,
                    text: text.clone(),
                    limit: candidate_limit,
                })? {
                    let trust_level = archival_record_trust_level(&record.metadata_json);
                    if !allowed_trust_levels.is_empty()
                        && !allowed_trust_levels.contains(&trust_level.to_ascii_lowercase())
                    {
                        continue;
                    }
                    combined
                        .entry(record.id)
                        .and_modify(|hit| hit.lexical_score = 1.0)
                        .or_insert(CombinedHit {
                            record,
                            lexical_score: 1.0,
                            semantic_score: None,
                            trust_level,
                        });
                }
            }

            if let Some(embedding) = query
                .embedding
                .as_ref()
                .filter(|embedding| !embedding.is_empty())
            {
                for hit in self.semantic_search_archival_memory(&SemanticArchivalMemoryQuery {
                    scope: scope.to_string(),
                    thread_id: query.thread_id,
                    text_filter: None,
                    embedding: embedding.clone(),
                    limit: candidate_limit,
                })? {
                    let trust_level = archival_record_trust_level(&hit.record.metadata_json);
                    if !allowed_trust_levels.is_empty()
                        && !allowed_trust_levels.contains(&trust_level.to_ascii_lowercase())
                    {
                        continue;
                    }
                    combined
                        .entry(hit.record.id)
                        .and_modify(|existing| {
                            let score = existing.semantic_score.unwrap_or(f32::MIN);
                            if hit.score > score {
                                existing.semantic_score = Some(hit.score);
                            }
                        })
                        .or_insert(CombinedHit {
                            record: hit.record,
                            lexical_score: 0.0,
                            semantic_score: Some(hit.score),
                            trust_level,
                        });
                }
            }
        }

        let mut hits = combined
            .into_values()
            .map(|hit| {
                let score = hit.semantic_score.unwrap_or(0.0) + (hit.lexical_score * 0.15);
                HybridArchivalMemorySearchHit {
                    record: hit.record,
                    score,
                    semantic_score: hit.semantic_score,
                    lexical_score: hit.lexical_score,
                    trust_level: hit.trust_level,
                }
            })
            .collect::<Vec<_>>();

        hits.sort_by(|left, right| {
            right
                .score
                .partial_cmp(&left.score)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| right.record.created_at_ms.cmp(&left.record.created_at_ms))
                .then_with(|| right.record.id.cmp(&left.record.id))
        });
        hits.truncate(limit);
        Ok(hits)
    }

    pub fn append_event_json(
        &self,
        thread_id: [u8; 32],
        event_id: &str,
        payload_json: &str,
    ) -> Result<()> {
        match &self.event_store {
            Some(store) => store.append_event_json(thread_id, event_id, payload_json),
            None => Ok(()),
        }
    }

    pub fn load_event_jsons(
        &self,
        thread_id: [u8; 32],
        limit: Option<usize>,
        cursor: Option<usize>,
    ) -> Result<Vec<StoredThreadEvent>> {
        match &self.event_store {
            Some(store) => store.load_event_jsons(thread_id, limit, cursor),
            None => Ok(Vec::new()),
        }
    }

    pub fn upsert_artifact_json(
        &self,
        thread_id: [u8; 32],
        artifact_id: &str,
        payload_json: &str,
    ) -> Result<()> {
        match &self.artifact_store {
            Some(store) => store.upsert_artifact_json(thread_id, artifact_id, payload_json),
            None => Ok(()),
        }
    }

    pub fn load_artifact_jsons(&self, thread_id: [u8; 32]) -> Result<Vec<StoredArtifactRecord>> {
        match &self.artifact_store {
            Some(store) => store.load_artifact_jsons(thread_id),
            None => Ok(Vec::new()),
        }
    }

    pub fn put_artifact_blob(
        &self,
        thread_id: [u8; 32],
        artifact_id: &str,
        content: &[u8],
    ) -> Result<()> {
        match &self.artifact_store {
            Some(store) => store.put_artifact_blob(thread_id, artifact_id, content),
            None => Ok(()),
        }
    }

    pub fn load_artifact_blob(&self, artifact_id: &str) -> Result<Option<Vec<u8>>> {
        match &self.artifact_store {
            Some(store) => store.load_artifact_blob(artifact_id),
            None => Ok(None),
        }
    }

    pub fn upsert_execution_cache_json(
        &self,
        cache_key: [u8; 32],
        payload_json: &str,
    ) -> Result<()> {
        match &self.execution_cache {
            Some(store) => store.upsert_execution_cache_json(cache_key, payload_json),
            None => Ok(()),
        }
    }

    pub fn load_execution_cache_json(&self, cache_key: [u8; 32]) -> Result<Option<String>> {
        match &self.execution_cache {
            Some(store) => store.load_execution_cache_json(cache_key),
            None => Ok(None),
        }
    }

    pub fn enqueue_enrichment_job(&self, job: &NewEnrichmentJob) -> Result<Option<i64>> {
        match &self.enrichment_queue {
            Some(store) => store.enqueue_job(job).map(Some),
            None => Ok(None),
        }
    }

    pub fn load_enrichment_jobs(
        &self,
        status: Option<EnrichmentJobStatus>,
        limit: usize,
    ) -> Result<Vec<StoredEnrichmentJob>> {
        match &self.enrichment_queue {
            Some(store) => store.load_jobs(status, limit),
            None => Ok(Vec::new()),
        }
    }

    pub fn claim_enrichment_jobs(
        &self,
        worker_id: &str,
        limit: usize,
    ) -> Result<Vec<StoredEnrichmentJob>> {
        match &self.enrichment_queue {
            Some(store) => store.claim_jobs(worker_id, limit),
            None => Ok(Vec::new()),
        }
    }

    pub fn complete_enrichment_job(&self, job_id: i64) -> Result<()> {
        match &self.enrichment_queue {
            Some(store) => store.complete_job(job_id),
            None => Ok(()),
        }
    }

    pub fn fail_enrichment_job(&self, job_id: i64, error: &str) -> Result<()> {
        match &self.enrichment_queue {
            Some(store) => store.fail_job(job_id, error),
            None => Ok(()),
        }
    }
}

pub struct SqliteMemoryStore {
    conn: Mutex<Connection>,
}

impl SqliteMemoryStore {
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)?;
        let store = Self {
            conn: Mutex::new(conn),
        };
        store.initialize()?;
        Ok(store)
    }

    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        let store = Self {
            conn: Mutex::new(conn),
        };
        store.initialize()?;
        Ok(store)
    }

    fn initialize(&self) -> Result<()> {
        let conn = self.conn.lock().map_err(|_| MemoryError::LockPoisoned)?;
        conn.execute_batch(
            "
            PRAGMA journal_mode = WAL;
            CREATE TABLE IF NOT EXISTS checkpoint_transcript_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                thread_id BLOB NOT NULL,
                role TEXT NOT NULL,
                timestamp_ms INTEGER NOT NULL,
                trace_hash BLOB,
                raw_content TEXT NOT NULL,
                model_content TEXT NOT NULL,
                store_content TEXT NOT NULL,
                raw_reference TEXT,
                privacy_metadata_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_checkpoint_transcript_messages_thread_id
                ON checkpoint_transcript_messages(thread_id, id);

            CREATE TABLE IF NOT EXISTS checkpoint_blobs (
                thread_id BLOB NOT NULL,
                checkpoint_name TEXT NOT NULL,
                payload BLOB NOT NULL,
                updated_at_ms INTEGER NOT NULL,
                PRIMARY KEY(thread_id, checkpoint_name)
            );

            CREATE TABLE IF NOT EXISTS core_memory_sections (
                thread_id BLOB NOT NULL,
                section TEXT NOT NULL,
                content TEXT NOT NULL,
                updated_at_ms INTEGER NOT NULL,
                PRIMARY KEY(thread_id, section)
            );

            CREATE TABLE IF NOT EXISTS archival_memory_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scope TEXT NOT NULL,
                thread_id BLOB,
                kind TEXT NOT NULL,
                content TEXT NOT NULL,
                metadata_json TEXT NOT NULL,
                created_at_ms INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_archival_memory_scope
                ON archival_memory_records(scope, created_at_ms DESC);

            CREATE TABLE IF NOT EXISTS archival_memory_embeddings (
                record_id INTEGER PRIMARY KEY,
                embedding_json TEXT NOT NULL,
                updated_at_ms INTEGER NOT NULL,
                FOREIGN KEY(record_id) REFERENCES archival_memory_records(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS thread_events (
                sort_id INTEGER PRIMARY KEY AUTOINCREMENT,
                thread_id BLOB NOT NULL,
                event_id TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                created_at_ms INTEGER NOT NULL,
                UNIQUE(thread_id, event_id)
            );
            CREATE INDEX IF NOT EXISTS idx_thread_events_thread_sort
                ON thread_events(thread_id, sort_id);

            CREATE TABLE IF NOT EXISTS artifact_records (
                sort_id INTEGER PRIMARY KEY AUTOINCREMENT,
                thread_id BLOB NOT NULL,
                artifact_id TEXT NOT NULL UNIQUE,
                payload_json TEXT NOT NULL,
                created_at_ms INTEGER NOT NULL,
                updated_at_ms INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_artifact_records_thread_sort
                ON artifact_records(thread_id, sort_id);

            CREATE TABLE IF NOT EXISTS artifact_blobs (
                artifact_id TEXT PRIMARY KEY,
                thread_id BLOB NOT NULL,
                content BLOB NOT NULL,
                updated_at_ms INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_artifact_blobs_thread_id
                ON artifact_blobs(thread_id);

            CREATE TABLE IF NOT EXISTS execution_cache (
                cache_key BLOB PRIMARY KEY,
                payload_json TEXT NOT NULL,
                updated_at_ms INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS enrichment_jobs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                thread_id BLOB,
                kind TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                status TEXT NOT NULL,
                dedupe_key TEXT,
                attempts INTEGER NOT NULL,
                claimed_by TEXT,
                created_at_ms INTEGER NOT NULL,
                updated_at_ms INTEGER NOT NULL,
                last_error TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_enrichment_jobs_status_updated
                ON enrichment_jobs(status, updated_at_ms, id);
            CREATE UNIQUE INDEX IF NOT EXISTS idx_enrichment_jobs_dedupe_pending
                ON enrichment_jobs(dedupe_key, status)
                WHERE dedupe_key IS NOT NULL AND status IN ('pending', 'claimed');
            ",
        )?;
        Ok(())
    }
}

impl Checkpointer for SqliteMemoryStore {
    fn append_transcript_message(
        &self,
        thread_id: [u8; 32],
        message: &StoredTranscriptMessage,
    ) -> Result<()> {
        let privacy_metadata_json = serde_json::to_string(&message.privacy_metadata)?;
        let trace_hash = message.trace_hash.map(|hash| hash.to_vec());
        let conn = self.conn.lock().map_err(|_| MemoryError::LockPoisoned)?;
        conn.execute(
            "
            INSERT INTO checkpoint_transcript_messages (
                thread_id,
                role,
                timestamp_ms,
                trace_hash,
                raw_content,
                model_content,
                store_content,
                raw_reference,
                privacy_metadata_json
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
            ",
            params![
                thread_id.to_vec(),
                message.role,
                message.timestamp_ms as i64,
                trace_hash,
                message.raw_content,
                message.model_content,
                message.store_content,
                message.raw_reference,
                privacy_metadata_json,
            ],
        )?;
        Ok(())
    }

    fn load_transcript_messages(
        &self,
        thread_id: [u8; 32],
    ) -> Result<Vec<StoredTranscriptMessage>> {
        let conn = self.conn.lock().map_err(|_| MemoryError::LockPoisoned)?;
        let mut stmt = conn.prepare(
            "
            SELECT
                role,
                timestamp_ms,
                trace_hash,
                raw_content,
                model_content,
                store_content,
                raw_reference,
                privacy_metadata_json
            FROM checkpoint_transcript_messages
            WHERE thread_id = ?1
            ORDER BY id ASC
            ",
        )?;

        let rows = stmt.query_map(params![thread_id.to_vec()], |row| {
            let trace_hash_bytes: Option<Vec<u8>> = row.get(2)?;
            let trace_hash = match trace_hash_bytes {
                Some(bytes) if bytes.len() == 32 => {
                    let mut out = [0u8; 32];
                    out.copy_from_slice(&bytes);
                    Some(out)
                }
                _ => None,
            };

            let privacy_metadata_json: String = row.get(7)?;
            let privacy_metadata =
                serde_json::from_str(&privacy_metadata_json).map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        7,
                        rusqlite::types::Type::Text,
                        Box::new(error),
                    )
                })?;

            Ok(StoredTranscriptMessage {
                role: row.get(0)?,
                timestamp_ms: row.get::<_, i64>(1)? as u64,
                trace_hash,
                raw_content: row.get(3)?,
                model_content: row.get(4)?,
                store_content: row.get(5)?,
                raw_reference: row.get(6)?,
                privacy_metadata,
            })
        })?;

        let mut messages = Vec::new();
        for row in rows {
            messages.push(row?);
        }
        Ok(messages)
    }

    fn upsert_checkpoint_blob(
        &self,
        thread_id: [u8; 32],
        checkpoint_name: &str,
        payload: &[u8],
    ) -> Result<()> {
        let conn = self.conn.lock().map_err(|_| MemoryError::LockPoisoned)?;
        conn.execute(
            "
            INSERT INTO checkpoint_blobs (
                thread_id,
                checkpoint_name,
                payload,
                updated_at_ms
            ) VALUES (?1, ?2, ?3, ?4)
            ON CONFLICT(thread_id, checkpoint_name) DO UPDATE SET
                payload = excluded.payload,
                updated_at_ms = excluded.updated_at_ms
            ",
            params![
                thread_id.to_vec(),
                checkpoint_name,
                payload,
                now_ms() as i64
            ],
        )?;
        Ok(())
    }

    fn load_checkpoint_blob(
        &self,
        thread_id: [u8; 32],
        checkpoint_name: &str,
    ) -> Result<Option<Vec<u8>>> {
        let conn = self.conn.lock().map_err(|_| MemoryError::LockPoisoned)?;
        let payload = conn
            .query_row(
                "
                SELECT payload
                FROM checkpoint_blobs
                WHERE thread_id = ?1 AND checkpoint_name = ?2
                ",
                params![thread_id.to_vec(), checkpoint_name],
                |row| row.get(0),
            )
            .optional()?;
        Ok(payload)
    }

    fn delete_checkpoint_blob(&self, thread_id: [u8; 32], checkpoint_name: &str) -> Result<()> {
        let conn = self.conn.lock().map_err(|_| MemoryError::LockPoisoned)?;
        conn.execute(
            "
            DELETE FROM checkpoint_blobs
            WHERE thread_id = ?1 AND checkpoint_name = ?2
            ",
            params![thread_id.to_vec(), checkpoint_name],
        )?;
        Ok(())
    }
}

impl CoreMemoryStore for SqliteMemoryStore {
    fn replace_section(&self, thread_id: [u8; 32], section: &str, content: &str) -> Result<()> {
        let conn = self.conn.lock().map_err(|_| MemoryError::LockPoisoned)?;
        conn.execute(
            "
            INSERT INTO core_memory_sections (
                thread_id,
                section,
                content,
                updated_at_ms
            ) VALUES (?1, ?2, ?3, ?4)
            ON CONFLICT(thread_id, section) DO UPDATE SET
                content = excluded.content,
                updated_at_ms = excluded.updated_at_ms
            ",
            params![thread_id.to_vec(), section, content, now_ms() as i64],
        )?;
        Ok(())
    }

    fn load_section(
        &self,
        thread_id: [u8; 32],
        section: &str,
    ) -> Result<Option<CoreMemorySection>> {
        let conn = self.conn.lock().map_err(|_| MemoryError::LockPoisoned)?;
        let section = conn
            .query_row(
                "
                SELECT section, content, updated_at_ms
                FROM core_memory_sections
                WHERE thread_id = ?1 AND section = ?2
                ",
                params![thread_id.to_vec(), section],
                |row| {
                    Ok(CoreMemorySection {
                        section: row.get(0)?,
                        content: row.get(1)?,
                        updated_at_ms: row.get::<_, i64>(2)? as u64,
                    })
                },
            )
            .optional()?;
        Ok(section)
    }

    fn delete_section(&self, thread_id: [u8; 32], section: &str) -> Result<()> {
        let conn = self.conn.lock().map_err(|_| MemoryError::LockPoisoned)?;
        conn.execute(
            "
            DELETE FROM core_memory_sections
            WHERE thread_id = ?1 AND section = ?2
            ",
            params![thread_id.to_vec(), section],
        )?;
        Ok(())
    }
}

impl ArchivalMemoryStore for SqliteMemoryStore {
    fn insert_record(&self, record: &NewArchivalMemoryRecord) -> Result<i64> {
        let conn = self.conn.lock().map_err(|_| MemoryError::LockPoisoned)?;
        let thread_id = record.thread_id.map(|value| value.to_vec());
        conn.execute(
            "
            INSERT INTO archival_memory_records (
                scope,
                thread_id,
                kind,
                content,
                metadata_json,
                created_at_ms
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            ",
            params![
                record.scope,
                thread_id,
                record.kind,
                record.content,
                record.metadata_json,
                now_ms() as i64
            ],
        )?;
        Ok(conn.last_insert_rowid())
    }

    fn load_record(&self, record_id: i64) -> Result<Option<ArchivalMemoryRecord>> {
        let conn = self.conn.lock().map_err(|_| MemoryError::LockPoisoned)?;
        let record = conn
            .query_row(
                "
                SELECT
                    id,
                    scope,
                    thread_id,
                    kind,
                    content,
                    metadata_json,
                    created_at_ms
                FROM archival_memory_records
                WHERE id = ?1
                ",
                params![record_id],
                |row| {
                    let thread_id_bytes: Option<Vec<u8>> = row.get(2)?;
                    let thread_id = match thread_id_bytes {
                        Some(bytes) if bytes.len() == 32 => {
                            let mut out = [0u8; 32];
                            out.copy_from_slice(&bytes);
                            Some(out)
                        }
                        _ => None,
                    };

                    Ok(ArchivalMemoryRecord {
                        id: row.get(0)?,
                        scope: row.get(1)?,
                        thread_id,
                        kind: row.get(3)?,
                        content: row.get(4)?,
                        metadata_json: row.get(5)?,
                        created_at_ms: row.get::<_, i64>(6)? as u64,
                    })
                },
            )
            .optional()?;
        Ok(record)
    }

    fn search(&self, query: &ArchivalMemoryQuery) -> Result<Vec<ArchivalMemoryRecord>> {
        let conn = self.conn.lock().map_err(|_| MemoryError::LockPoisoned)?;
        let pattern = format!("%{}%", query.text);
        let limit = query.limit.max(1).min(i64::MAX as usize) as i64;
        let thread_id = query.thread_id.map(|value| value.to_vec());
        let mut stmt = conn.prepare(
            "
            SELECT
                id,
                scope,
                thread_id,
                kind,
                content,
                metadata_json,
                created_at_ms
            FROM archival_memory_records
            WHERE
                scope = ?1
                AND (?2 IS NULL OR thread_id = ?2)
                AND content LIKE ?3
            ORDER BY created_at_ms DESC, id DESC
            LIMIT ?4
            ",
        )?;

        let rows = stmt.query_map(params![query.scope, thread_id, pattern, limit], |row| {
            let thread_id_bytes: Option<Vec<u8>> = row.get(2)?;
            let thread_id = match thread_id_bytes {
                Some(bytes) if bytes.len() == 32 => {
                    let mut out = [0u8; 32];
                    out.copy_from_slice(&bytes);
                    Some(out)
                }
                _ => None,
            };

            Ok(ArchivalMemoryRecord {
                id: row.get(0)?,
                scope: row.get(1)?,
                thread_id,
                kind: row.get(3)?,
                content: row.get(4)?,
                metadata_json: row.get(5)?,
                created_at_ms: row.get::<_, i64>(6)? as u64,
            })
        })?;

        let mut records = Vec::new();
        for row in rows {
            records.push(row?);
        }
        Ok(records)
    }

    fn upsert_record_embedding(&self, record_id: i64, embedding: &[f32]) -> Result<()> {
        let embedding_json = serde_json::to_string(embedding)?;
        let conn = self.conn.lock().map_err(|_| MemoryError::LockPoisoned)?;
        conn.execute(
            "
            INSERT INTO archival_memory_embeddings (
                record_id,
                embedding_json,
                updated_at_ms
            ) VALUES (?1, ?2, ?3)
            ON CONFLICT(record_id) DO UPDATE SET
                embedding_json = excluded.embedding_json,
                updated_at_ms = excluded.updated_at_ms
            ",
            params![record_id, embedding_json, now_ms() as i64],
        )?;
        Ok(())
    }

    fn semantic_search(
        &self,
        query: &SemanticArchivalMemoryQuery,
    ) -> Result<Vec<ArchivalMemorySearchHit>> {
        if query.embedding.is_empty() {
            return Ok(Vec::new());
        }

        let conn = self.conn.lock().map_err(|_| MemoryError::LockPoisoned)?;
        let thread_id = query.thread_id.map(|value| value.to_vec());
        let text_filter = query
            .text_filter
            .as_ref()
            .map(|value| format!("%{}%", value));

        let mut candidates: Vec<(ArchivalMemoryRecord, Vec<f32>)> = Vec::new();
        if let Some(pattern) = text_filter {
            let mut stmt = conn.prepare(
                "
                SELECT
                    r.id,
                    r.scope,
                    r.thread_id,
                    r.kind,
                    r.content,
                    r.metadata_json,
                    r.created_at_ms,
                    e.embedding_json
                FROM archival_memory_records r
                JOIN archival_memory_embeddings e ON e.record_id = r.id
                WHERE
                    r.scope = ?1
                    AND (?2 IS NULL OR r.thread_id = ?2)
                    AND r.content LIKE ?3
                ORDER BY r.created_at_ms DESC, r.id DESC
                ",
            )?;

            let rows = stmt.query_map(params![query.scope, thread_id, pattern], |row| {
                let thread_id_bytes: Option<Vec<u8>> = row.get(2)?;
                let thread_id = match thread_id_bytes {
                    Some(bytes) if bytes.len() == 32 => {
                        let mut out = [0u8; 32];
                        out.copy_from_slice(&bytes);
                        Some(out)
                    }
                    _ => None,
                };

                let embedding_json: String = row.get(7)?;
                let embedding =
                    serde_json::from_str::<Vec<f32>>(&embedding_json).map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            7,
                            rusqlite::types::Type::Text,
                            Box::new(error),
                        )
                    })?;

                Ok((
                    ArchivalMemoryRecord {
                        id: row.get(0)?,
                        scope: row.get(1)?,
                        thread_id,
                        kind: row.get(3)?,
                        content: row.get(4)?,
                        metadata_json: row.get(5)?,
                        created_at_ms: row.get::<_, i64>(6)? as u64,
                    },
                    embedding,
                ))
            })?;

            for row in rows {
                candidates.push(row?);
            }
        } else {
            let mut stmt = conn.prepare(
                "
                SELECT
                    r.id,
                    r.scope,
                    r.thread_id,
                    r.kind,
                    r.content,
                    r.metadata_json,
                    r.created_at_ms,
                    e.embedding_json
                FROM archival_memory_records r
                JOIN archival_memory_embeddings e ON e.record_id = r.id
                WHERE
                    r.scope = ?1
                    AND (?2 IS NULL OR r.thread_id = ?2)
                ORDER BY r.created_at_ms DESC, r.id DESC
                ",
            )?;

            let rows = stmt.query_map(params![query.scope, thread_id], |row| {
                let thread_id_bytes: Option<Vec<u8>> = row.get(2)?;
                let thread_id = match thread_id_bytes {
                    Some(bytes) if bytes.len() == 32 => {
                        let mut out = [0u8; 32];
                        out.copy_from_slice(&bytes);
                        Some(out)
                    }
                    _ => None,
                };

                let embedding_json: String = row.get(7)?;
                let embedding =
                    serde_json::from_str::<Vec<f32>>(&embedding_json).map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            7,
                            rusqlite::types::Type::Text,
                            Box::new(error),
                        )
                    })?;

                Ok((
                    ArchivalMemoryRecord {
                        id: row.get(0)?,
                        scope: row.get(1)?,
                        thread_id,
                        kind: row.get(3)?,
                        content: row.get(4)?,
                        metadata_json: row.get(5)?,
                        created_at_ms: row.get::<_, i64>(6)? as u64,
                    },
                    embedding,
                ))
            })?;

            for row in rows {
                candidates.push(row?);
            }
        }

        let mut scored = candidates
            .into_iter()
            .filter_map(|(record, embedding)| {
                cosine_similarity(&query.embedding, &embedding)
                    .map(|score| ArchivalMemorySearchHit { record, score })
            })
            .collect::<Vec<_>>();

        scored.sort_by(|left, right| {
            right
                .score
                .partial_cmp(&left.score)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| right.record.created_at_ms.cmp(&left.record.created_at_ms))
                .then_with(|| right.record.id.cmp(&left.record.id))
        });
        scored.truncate(query.limit.max(1));
        Ok(scored)
    }
}

impl EventStore for SqliteMemoryStore {
    fn append_event_json(
        &self,
        thread_id: [u8; 32],
        event_id: &str,
        payload_json: &str,
    ) -> Result<()> {
        let conn = self.conn.lock().map_err(|_| MemoryError::LockPoisoned)?;
        conn.execute(
            "
            INSERT INTO thread_events (
                thread_id,
                event_id,
                payload_json,
                created_at_ms
            ) VALUES (?1, ?2, ?3, ?4)
            ON CONFLICT(thread_id, event_id) DO UPDATE SET
                payload_json = excluded.payload_json
            ",
            params![thread_id.to_vec(), event_id, payload_json, now_ms() as i64],
        )?;
        Ok(())
    }

    fn load_event_jsons(
        &self,
        thread_id: [u8; 32],
        limit: Option<usize>,
        cursor: Option<usize>,
    ) -> Result<Vec<StoredThreadEvent>> {
        let conn = self.conn.lock().map_err(|_| MemoryError::LockPoisoned)?;
        let offset = cursor.unwrap_or(0).min(i64::MAX as usize) as i64;
        let limit = limit.unwrap_or(usize::MAX).min(i64::MAX as usize) as i64;
        let mut events = Vec::new();
        if limit == i64::MAX {
            let mut stmt = conn.prepare(
                "
                SELECT event_id, payload_json, created_at_ms
                FROM thread_events
                WHERE thread_id = ?1
                ORDER BY sort_id ASC
                LIMIT -1 OFFSET ?2
                ",
            )?;
            let rows = stmt.query_map(params![thread_id.to_vec(), offset], |row| {
                Ok(StoredThreadEvent {
                    event_id: row.get(0)?,
                    payload_json: row.get(1)?,
                    created_at_ms: row.get::<_, i64>(2)? as u64,
                })
            })?;
            for row in rows {
                events.push(row?);
            }
        } else {
            let mut stmt = conn.prepare(
                "
                SELECT event_id, payload_json, created_at_ms
                FROM thread_events
                WHERE thread_id = ?1
                ORDER BY sort_id ASC
                LIMIT ?2 OFFSET ?3
                ",
            )?;
            let rows = stmt.query_map(params![thread_id.to_vec(), limit, offset], |row| {
                Ok(StoredThreadEvent {
                    event_id: row.get(0)?,
                    payload_json: row.get(1)?,
                    created_at_ms: row.get::<_, i64>(2)? as u64,
                })
            })?;
            for row in rows {
                events.push(row?);
            }
        }
        Ok(events)
    }
}

impl ArtifactStore for SqliteMemoryStore {
    fn upsert_artifact_json(
        &self,
        thread_id: [u8; 32],
        artifact_id: &str,
        payload_json: &str,
    ) -> Result<()> {
        let now = now_ms() as i64;
        let conn = self.conn.lock().map_err(|_| MemoryError::LockPoisoned)?;
        conn.execute(
            "
            INSERT INTO artifact_records (
                thread_id,
                artifact_id,
                payload_json,
                created_at_ms,
                updated_at_ms
            ) VALUES (?1, ?2, ?3, ?4, ?5)
            ON CONFLICT(artifact_id) DO UPDATE SET
                thread_id = excluded.thread_id,
                payload_json = excluded.payload_json,
                updated_at_ms = excluded.updated_at_ms
            ",
            params![thread_id.to_vec(), artifact_id, payload_json, now, now],
        )?;
        Ok(())
    }

    fn load_artifact_jsons(&self, thread_id: [u8; 32]) -> Result<Vec<StoredArtifactRecord>> {
        let conn = self.conn.lock().map_err(|_| MemoryError::LockPoisoned)?;
        let mut stmt = conn.prepare(
            "
            SELECT artifact_id, payload_json, created_at_ms, updated_at_ms
            FROM artifact_records
            WHERE thread_id = ?1
            ORDER BY sort_id ASC
            ",
        )?;

        let rows = stmt.query_map(params![thread_id.to_vec()], |row| {
            Ok(StoredArtifactRecord {
                artifact_id: row.get(0)?,
                payload_json: row.get(1)?,
                created_at_ms: row.get::<_, i64>(2)? as u64,
                updated_at_ms: row.get::<_, i64>(3)? as u64,
            })
        })?;

        let mut artifacts = Vec::new();
        for row in rows {
            artifacts.push(row?);
        }
        Ok(artifacts)
    }

    fn put_artifact_blob(
        &self,
        thread_id: [u8; 32],
        artifact_id: &str,
        content: &[u8],
    ) -> Result<()> {
        let conn = self.conn.lock().map_err(|_| MemoryError::LockPoisoned)?;
        conn.execute(
            "
            INSERT INTO artifact_blobs (
                artifact_id,
                thread_id,
                content,
                updated_at_ms
            ) VALUES (?1, ?2, ?3, ?4)
            ON CONFLICT(artifact_id) DO UPDATE SET
                thread_id = excluded.thread_id,
                content = excluded.content,
                updated_at_ms = excluded.updated_at_ms
            ",
            params![artifact_id, thread_id.to_vec(), content, now_ms() as i64],
        )?;
        Ok(())
    }

    fn load_artifact_blob(&self, artifact_id: &str) -> Result<Option<Vec<u8>>> {
        let conn = self.conn.lock().map_err(|_| MemoryError::LockPoisoned)?;
        let payload = conn
            .query_row(
                "
                SELECT content
                FROM artifact_blobs
                WHERE artifact_id = ?1
                ",
                params![artifact_id],
                |row| row.get(0),
            )
            .optional()?;
        Ok(payload)
    }
}

impl ExecutionCacheStore for SqliteMemoryStore {
    fn upsert_execution_cache_json(&self, cache_key: [u8; 32], payload_json: &str) -> Result<()> {
        let conn = self.conn.lock().map_err(|_| MemoryError::LockPoisoned)?;
        conn.execute(
            "
            INSERT INTO execution_cache (
                cache_key,
                payload_json,
                updated_at_ms
            ) VALUES (?1, ?2, ?3)
            ON CONFLICT(cache_key) DO UPDATE SET
                payload_json = excluded.payload_json,
                updated_at_ms = excluded.updated_at_ms
            ",
            params![cache_key.to_vec(), payload_json, now_ms() as i64],
        )?;
        Ok(())
    }

    fn load_execution_cache_json(&self, cache_key: [u8; 32]) -> Result<Option<String>> {
        let conn = self.conn.lock().map_err(|_| MemoryError::LockPoisoned)?;
        let payload = conn
            .query_row(
                "
                SELECT payload_json
                FROM execution_cache
                WHERE cache_key = ?1
                ",
                params![cache_key.to_vec()],
                |row| row.get(0),
            )
            .optional()?;
        Ok(payload)
    }
}

impl EnrichmentQueueStore for SqliteMemoryStore {
    fn enqueue_job(&self, job: &NewEnrichmentJob) -> Result<i64> {
        let now = now_ms() as i64;
        let thread_id = job.thread_id.map(|value| value.to_vec());
        let conn = self.conn.lock().map_err(|_| MemoryError::LockPoisoned)?;
        let inserted = conn.execute(
            "
            INSERT OR IGNORE INTO enrichment_jobs (
                thread_id,
                kind,
                payload_json,
                status,
                dedupe_key,
                attempts,
                claimed_by,
                created_at_ms,
                updated_at_ms,
                last_error
            ) VALUES (?1, ?2, ?3, ?4, ?5, 0, NULL, ?6, ?6, NULL)
            ",
            params![
                thread_id,
                job.kind,
                job.payload_json,
                EnrichmentJobStatus::Pending.as_str(),
                job.dedupe_key,
                now,
            ],
        )?;
        if inserted > 0 {
            return Ok(conn.last_insert_rowid());
        }

        let Some(dedupe_key) = job.dedupe_key.as_deref() else {
            return Err(MemoryError::Sqlite(rusqlite::Error::QueryReturnedNoRows));
        };

        let existing_id = conn.query_row(
            "
            SELECT id
            FROM enrichment_jobs
            WHERE dedupe_key = ?1 AND status IN ('pending', 'claimed')
            ORDER BY updated_at_ms DESC, id DESC
            LIMIT 1
            ",
            params![dedupe_key],
            |row| row.get(0),
        )?;
        Ok(existing_id)
    }

    fn load_jobs(
        &self,
        status: Option<EnrichmentJobStatus>,
        limit: usize,
    ) -> Result<Vec<StoredEnrichmentJob>> {
        let conn = self.conn.lock().map_err(|_| MemoryError::LockPoisoned)?;
        let limit = limit.max(1).min(i64::MAX as usize) as i64;
        let mut jobs = Vec::new();
        if let Some(status) = status {
            let mut stmt = conn.prepare(
                "
                SELECT
                    id,
                    thread_id,
                    kind,
                    payload_json,
                    status,
                    dedupe_key,
                    attempts,
                    claimed_by,
                    created_at_ms,
                    updated_at_ms,
                    last_error
                FROM enrichment_jobs
                WHERE status = ?1
                ORDER BY updated_at_ms ASC, id ASC
                LIMIT ?2
                ",
            )?;
            let rows =
                stmt.query_map(params![status.as_str(), limit], map_stored_enrichment_job)?;
            for row in rows {
                jobs.push(row?);
            }
        } else {
            let mut stmt = conn.prepare(
                "
                SELECT
                    id,
                    thread_id,
                    kind,
                    payload_json,
                    status,
                    dedupe_key,
                    attempts,
                    claimed_by,
                    created_at_ms,
                    updated_at_ms,
                    last_error
                FROM enrichment_jobs
                ORDER BY updated_at_ms ASC, id ASC
                LIMIT ?1
                ",
            )?;
            let rows = stmt.query_map(params![limit], map_stored_enrichment_job)?;
            for row in rows {
                jobs.push(row?);
            }
        }
        Ok(jobs)
    }

    fn claim_jobs(&self, worker_id: &str, limit: usize) -> Result<Vec<StoredEnrichmentJob>> {
        let mut conn = self.conn.lock().map_err(|_| MemoryError::LockPoisoned)?;
        let tx = conn.transaction()?;
        let limit = limit.max(1).min(i64::MAX as usize) as i64;
        let mut stmt = tx.prepare(
            "
            SELECT id
            FROM enrichment_jobs
            WHERE status = 'pending'
            ORDER BY updated_at_ms ASC, id ASC
            LIMIT ?1
            ",
        )?;
        let ids = stmt
            .query_map(params![limit], |row| row.get::<_, i64>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        drop(stmt);

        let now = now_ms() as i64;
        let mut claimed = Vec::new();
        for job_id in ids {
            let updated = tx.execute(
                "
                UPDATE enrichment_jobs
                SET
                    status = 'claimed',
                    attempts = attempts + 1,
                    claimed_by = ?2,
                    updated_at_ms = ?3,
                    last_error = NULL
                WHERE id = ?1 AND status = 'pending'
                ",
                params![job_id, worker_id, now],
            )?;
            if updated == 0 {
                continue;
            }
            let job = tx.query_row(
                "
                SELECT
                    id,
                    thread_id,
                    kind,
                    payload_json,
                    status,
                    dedupe_key,
                    attempts,
                    claimed_by,
                    created_at_ms,
                    updated_at_ms,
                    last_error
                FROM enrichment_jobs
                WHERE id = ?1
                ",
                params![job_id],
                map_stored_enrichment_job,
            )?;
            claimed.push(job);
        }
        tx.commit()?;
        Ok(claimed)
    }

    fn complete_job(&self, job_id: i64) -> Result<()> {
        let conn = self.conn.lock().map_err(|_| MemoryError::LockPoisoned)?;
        conn.execute(
            "
            UPDATE enrichment_jobs
            SET
                status = 'completed',
                updated_at_ms = ?2,
                claimed_by = NULL,
                last_error = NULL
            WHERE id = ?1
            ",
            params![job_id, now_ms() as i64],
        )?;
        Ok(())
    }

    fn fail_job(&self, job_id: i64, error: &str) -> Result<()> {
        let conn = self.conn.lock().map_err(|_| MemoryError::LockPoisoned)?;
        conn.execute(
            "
            UPDATE enrichment_jobs
            SET
                status = 'failed',
                updated_at_ms = ?2,
                claimed_by = NULL,
                last_error = ?3
            WHERE id = ?1
            ",
            params![job_id, now_ms() as i64, error],
        )?;
        Ok(())
    }
}

fn map_stored_enrichment_job(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredEnrichmentJob> {
    let thread_id_bytes: Option<Vec<u8>> = row.get(1)?;
    let thread_id = match thread_id_bytes {
        Some(bytes) if bytes.len() == 32 => {
            let mut out = [0u8; 32];
            out.copy_from_slice(&bytes);
            Some(out)
        }
        _ => None,
    };
    Ok(StoredEnrichmentJob {
        id: row.get(0)?,
        thread_id,
        kind: row.get(2)?,
        payload_json: row.get(3)?,
        status: EnrichmentJobStatus::parse(&row.get::<_, String>(4)?),
        dedupe_key: row.get(5)?,
        attempts: row.get::<_, i64>(6)? as u32,
        claimed_by: row.get(7)?,
        created_at_ms: row.get::<_, i64>(8)? as u64,
        updated_at_ms: row.get::<_, i64>(9)? as u64,
        last_error: row.get(10)?,
    })
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_millis() as u64)
}

fn archival_record_trust_level(metadata_json: &str) -> String {
    serde_json::from_str::<serde_json::Value>(metadata_json)
        .ok()
        .and_then(|value| {
            value
                .get("trust_level")
                .and_then(serde_json::Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(|value| value.to_ascii_lowercase())
        })
        .unwrap_or_else(|| "standard".to_string())
}

fn cosine_similarity(left: &[f32], right: &[f32]) -> Option<f32> {
    if left.len() != right.len() || left.is_empty() {
        return None;
    }

    let mut dot = 0.0f32;
    let mut left_norm_sq = 0.0f32;
    let mut right_norm_sq = 0.0f32;
    for (left_value, right_value) in left.iter().zip(right.iter()) {
        dot += left_value * right_value;
        left_norm_sq += left_value * left_value;
        right_norm_sq += right_value * right_value;
    }

    let left_norm = left_norm_sq.sqrt();
    let right_norm = right_norm_sq.sqrt();
    if left_norm == 0.0 || right_norm == 0.0 {
        return None;
    }
    Some(dot / (left_norm * right_norm))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sqlite_runtime_roundtrips_transcript_messages() {
        let runtime = MemoryRuntime::open_sqlite_in_memory().expect("runtime");
        let thread_id = [0x11; 32];

        runtime
            .append_transcript_message(
                thread_id,
                &StoredTranscriptMessage {
                    role: "user".to_string(),
                    timestamp_ms: 123,
                    trace_hash: None,
                    raw_content: "raw secret".to_string(),
                    model_content: "[REDACTED]".to_string(),
                    store_content: "[REDACTED]".to_string(),
                    raw_reference: None,
                    privacy_metadata: TranscriptPrivacyMetadata {
                        redaction_version: "v1".to_string(),
                        sensitive_fields_mask: vec!["secret".to_string()],
                        policy_id: "policy".to_string(),
                        policy_version: "1".to_string(),
                        scrubbed_for_model_hash: None,
                    },
                },
            )
            .expect("append");

        let messages = runtime
            .load_transcript_messages(thread_id)
            .expect("load transcript");
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].raw_content, "raw secret");
        assert_eq!(messages[0].model_content, "[REDACTED]");
    }

    #[test]
    fn sqlite_runtime_roundtrips_core_and_archival_memory() {
        let runtime = MemoryRuntime::open_sqlite_in_memory().expect("runtime");
        let thread_id = [0x22; 32];

        runtime
            .replace_core_memory_section(thread_id, "current_goal", "checkout cart")
            .expect("replace core");
        let section = runtime
            .load_core_memory_section(thread_id, "current_goal")
            .expect("load core");
        assert!(section.is_some());
        assert_eq!(section.expect("section").content, "checkout cart");

        runtime
            .insert_archival_record(&NewArchivalMemoryRecord {
                scope: "user".to_string(),
                thread_id: Some(thread_id),
                kind: "fact".to_string(),
                content: "favorite color is blue".to_string(),
                metadata_json: "{}".to_string(),
            })
            .expect("insert archival");

        let results = runtime
            .search_archival_memory(&ArchivalMemoryQuery {
                scope: "user".to_string(),
                thread_id: Some(thread_id),
                text: "blue".to_string(),
                limit: 5,
            })
            .expect("search archival");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].content, "favorite color is blue");
    }

    #[test]
    fn sqlite_runtime_roundtrips_semantic_archival_search() {
        let runtime = MemoryRuntime::open_sqlite_in_memory().expect("runtime");
        let record_id = runtime
            .insert_archival_record(&NewArchivalMemoryRecord {
                scope: "autopilot.retrieval".to_string(),
                thread_id: None,
                kind: "file_chunk".to_string(),
                content: "checkout flow instructions".to_string(),
                metadata_json: "{}".to_string(),
            })
            .expect("insert record")
            .expect("record id");
        runtime
            .upsert_archival_embedding(record_id, &[1.0, 0.0])
            .expect("store embedding");

        let other_id = runtime
            .insert_archival_record(&NewArchivalMemoryRecord {
                scope: "autopilot.retrieval".to_string(),
                thread_id: None,
                kind: "file_chunk".to_string(),
                content: "calendar renewal notes".to_string(),
                metadata_json: "{}".to_string(),
            })
            .expect("insert record")
            .expect("record id");
        runtime
            .upsert_archival_embedding(other_id, &[0.0, 1.0])
            .expect("store embedding");

        let hits = runtime
            .semantic_search_archival_memory(&SemanticArchivalMemoryQuery {
                scope: "autopilot.retrieval".to_string(),
                thread_id: None,
                text_filter: None,
                embedding: vec![1.0, 0.0],
                limit: 1,
            })
            .expect("semantic search");

        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].record.id, record_id);
        assert!(hits[0].score > 0.99);
    }

    #[test]
    fn sqlite_runtime_roundtrips_execution_cache_entries() {
        let runtime = MemoryRuntime::open_sqlite_in_memory().expect("runtime");
        let cache_key = [0x33; 32];

        runtime
            .upsert_execution_cache_json(cache_key, "{\"status\":\"success\"}")
            .expect("store cache entry");

        let cached = runtime
            .load_execution_cache_json(cache_key)
            .expect("load cache entry");
        assert_eq!(cached.as_deref(), Some("{\"status\":\"success\"}"));
    }

    #[test]
    fn sqlite_runtime_roundtrips_artifact_records_and_blobs() {
        let runtime = MemoryRuntime::open_sqlite_in_memory().expect("runtime");
        let thread_id = [0x44; 32];
        let artifact_id = "desktop.visual_observation.deadbeef";

        runtime
            .upsert_artifact_json(
                thread_id,
                artifact_id,
                r#"{"kind":"visual_observation","content_type":"image/png"}"#,
            )
            .expect("store artifact metadata");
        runtime
            .put_artifact_blob(thread_id, artifact_id, &[0x89, b'P', b'N', b'G'])
            .expect("store artifact blob");

        let artifacts = runtime
            .load_artifact_jsons(thread_id)
            .expect("load artifact metadata");
        assert_eq!(artifacts.len(), 1);
        assert_eq!(artifacts[0].artifact_id, artifact_id);

        let blob = runtime
            .load_artifact_blob(artifact_id)
            .expect("load artifact blob");
        assert_eq!(blob, Some(vec![0x89, b'P', b'N', b'G']));
    }

    #[test]
    fn sqlite_runtime_hybrid_search_honors_scope_lexical_and_trust_filters() {
        let runtime = MemoryRuntime::open_sqlite_in_memory().expect("runtime");
        let trusted_id = runtime
            .insert_archival_record(&NewArchivalMemoryRecord {
                scope: "desktop.transcript".to_string(),
                thread_id: None,
                kind: "chat_message".to_string(),
                content: "checkout button appears inside the cart modal".to_string(),
                metadata_json: r#"{"trust_level":"runtime_observed"}"#.to_string(),
            })
            .expect("insert trusted")
            .expect("record id");
        runtime
            .upsert_archival_embedding(trusted_id, &[1.0, 0.0])
            .expect("trusted embedding");

        let untrusted_id = runtime
            .insert_archival_record(&NewArchivalMemoryRecord {
                scope: "desktop.ui.memory".to_string(),
                thread_id: None,
                kind: "ui_observation".to_string(),
                content: "checkout button might be somewhere else".to_string(),
                metadata_json: r#"{"trust_level":"model_asserted"}"#.to_string(),
            })
            .expect("insert untrusted")
            .expect("record id");
        runtime
            .upsert_archival_embedding(untrusted_id, &[0.9, 0.1])
            .expect("untrusted embedding");

        let hits = runtime
            .hybrid_search_archival_memory(&HybridArchivalMemoryQuery {
                scopes: vec![
                    "desktop.transcript".to_string(),
                    "desktop.ui.memory".to_string(),
                ],
                thread_id: None,
                text: "checkout button".to_string(),
                embedding: Some(vec![1.0, 0.0]),
                limit: 5,
                candidate_limit: 8,
                allowed_trust_levels: vec!["runtime_observed".to_string()],
            })
            .expect("hybrid search");

        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].record.id, trusted_id);
        assert_eq!(hits[0].trust_level, "runtime_observed");
        assert!(hits[0].lexical_score > 0.0);
        assert!(hits[0].semantic_score.unwrap_or_default() > 0.9);
    }

    #[test]
    fn sqlite_runtime_roundtrips_enrichment_queue_jobs() {
        let runtime = MemoryRuntime::open_sqlite_in_memory().expect("runtime");
        let thread_id = [0x55; 32];

        let job_id = runtime
            .enqueue_enrichment_job(&NewEnrichmentJob {
                thread_id: Some(thread_id),
                kind: "fact_extraction".to_string(),
                payload_json: r#"{"record_id":1}"#.to_string(),
                dedupe_key: Some("fact:1".to_string()),
            })
            .expect("enqueue")
            .expect("job id");

        let deduped = runtime
            .enqueue_enrichment_job(&NewEnrichmentJob {
                thread_id: Some(thread_id),
                kind: "fact_extraction".to_string(),
                payload_json: r#"{"record_id":1}"#.to_string(),
                dedupe_key: Some("fact:1".to_string()),
            })
            .expect("dedupe enqueue")
            .expect("dedupe id");
        assert_eq!(deduped, job_id);

        let pending = runtime
            .load_enrichment_jobs(Some(EnrichmentJobStatus::Pending), 10)
            .expect("load pending");
        assert_eq!(pending.len(), 1);

        let claimed = runtime
            .claim_enrichment_jobs("worker-a", 5)
            .expect("claim jobs");
        assert_eq!(claimed.len(), 1);
        assert_eq!(claimed[0].id, job_id);
        assert_eq!(claimed[0].status, EnrichmentJobStatus::Claimed);
        assert_eq!(claimed[0].claimed_by.as_deref(), Some("worker-a"));
        assert_eq!(claimed[0].attempts, 1);

        runtime
            .fail_enrichment_job(job_id, "embedding provider unavailable")
            .expect("fail job");
        let failed = runtime
            .load_enrichment_jobs(Some(EnrichmentJobStatus::Failed), 10)
            .expect("load failed");
        assert_eq!(failed.len(), 1);
        assert_eq!(
            failed[0].last_error.as_deref(),
            Some("embedding provider unavailable")
        );

        let second_job_id = runtime
            .enqueue_enrichment_job(&NewEnrichmentJob {
                thread_id: Some(thread_id),
                kind: "summary".to_string(),
                payload_json: r#"{"thread_id":"abc"}"#.to_string(),
                dedupe_key: Some("summary:abc".to_string()),
            })
            .expect("enqueue second")
            .expect("second job id");
        let claimed_second = runtime
            .claim_enrichment_jobs("worker-b", 5)
            .expect("claim second");
        assert_eq!(claimed_second.len(), 1);
        assert_eq!(claimed_second[0].id, second_job_id);
        runtime
            .complete_enrichment_job(second_job_id)
            .expect("complete second");
        let completed = runtime
            .load_enrichment_jobs(Some(EnrichmentJobStatus::Completed), 10)
            .expect("load completed");
        assert_eq!(completed.len(), 1);
        assert_eq!(completed[0].id, second_job_id);
    }
}
