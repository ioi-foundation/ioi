use crate::models::{
    AppState, LocalEngineActivityRecord, LocalEngineBackendRecord, LocalEngineControlPlane,
    LocalEngineGalleryCatalogRecord, LocalEngineGalleryEntryPreview, LocalEngineJobRecord,
    LocalEngineModelRecord, LocalEngineRegistryState,
};
use crate::orchestrator;
use chrono::Utc;
use ioi_memory::MemoryRuntime;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use tauri::{AppHandle, Emitter, Manager};
use url::Url;

const MAX_ACTIVITY_HISTORY: usize = 24;
const LOCAL_ENGINE_EXECUTOR_TICK_MS: u64 = 4_000;
const LOCAL_ENGINE_UPDATED_EVENT: &str = "local-engine-updated";
const LOCAL_ENGINE_MODEL_INSTALL_MANIFEST: &str = ".ioi-model-install.json";
const LOCAL_ENGINE_MODEL_INSTALL_RECEIPTS_DIR: &str = "local-engine/model-installs";
const LOCAL_ENGINE_MODEL_DOWNLOADS_DIR: &str = "downloads/models";
const LOCAL_ENGINE_BACKEND_INSTALL_MANIFEST: &str = ".ioi-backend-install.json";
const LOCAL_ENGINE_BACKEND_PACKAGE_MANIFEST: &str = ".ioi-backend-package.json";
const LOCAL_ENGINE_BACKEND_INSTALL_RECEIPTS_DIR: &str = "local-engine/backend-installs";
const LOCAL_ENGINE_BACKEND_DOWNLOADS_DIR: &str = "downloads/backends";
const LOCAL_ENGINE_DEV_BOOTSTRAP_MAX_ITERATIONS: usize = 10;
const LOCAL_ENGINE_DEV_BOOTSTRAP_SLEEP_MS: u64 = 300;
#[cfg(unix)]
const LOCAL_ENGINE_BACKEND_CONTAINER_LAUNCHER: &str = "launch-backend.sh";
#[cfg(windows)]
const LOCAL_ENGINE_BACKEND_CONTAINER_LAUNCHER: &str = "launch-backend.cmd";
const LOCAL_ENGINE_GALLERY_SYNC_RECEIPTS_DIR: &str = "local-engine/gallery-sync";
const LOCAL_ENGINE_GALLERY_CATALOGS_DIR: &str = "galleries";
const LOCAL_ENGINE_HEALTH_PROBE_TIMEOUT_MS: u64 = 750;
const LOCAL_ENGINE_GALLERY_SAMPLE_LIMIT: usize = 4;
const LOCAL_GPU_DEV_DEFAULT_PRESET: &str = "ollama-openai";
const LOCAL_GPU_DEV_DEFAULT_RUNTIME_URL: &str = "http://127.0.0.1:11434/v1/chat/completions";
const LOCAL_GPU_DEV_DEFAULT_HEALTH_URL: &str = "http://127.0.0.1:11434/api/tags";
const LOCAL_GPU_DEV_DEFAULT_MODEL: &str = "llama3.2:3b";
const LOCAL_GPU_DEV_DEFAULT_EMBEDDING_MODEL: &str = "nomic-embed-text";
const LOCAL_GPU_DEV_DEFAULT_BACKEND_ID: &str = "ollama-openai";
const LOCAL_GPU_DEV_DEFAULT_BACKEND_SOURCE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/dev/local-backends/ollama-openai"
);

static MANAGED_BACKEND_PROCESSES: Lazy<Mutex<BTreeMap<String, ManagedBackendProcess>>> =
    Lazy::new(|| Mutex::new(BTreeMap::new()));

#[derive(Debug, Clone)]
pub struct ModelLifecycleReceiptUpdate {
    pub session_id: String,
    pub workload_id: String,
    pub timestamp_ms: u64,
    pub tool_name: String,
    pub operation: String,
    pub subject_kind: String,
    pub subject_id: String,
    pub success: bool,
    pub backend_id: Option<String>,
    pub source_uri: Option<String>,
    pub job_id: Option<String>,
    pub bytes_transferred: Option<u64>,
    pub hardware_profile: Option<String>,
    pub error_class: Option<String>,
}

#[derive(Debug, Clone, Default)]
struct RegistryEffectHints {
    bytes_transferred: Option<u64>,
    hardware_profile: Option<String>,
    backend_status: Option<String>,
    backend_health: Option<String>,
    backend_alias: Option<String>,
    backend_install_path: Option<String>,
    backend_entrypoint: Option<String>,
    backend_health_endpoint: Option<String>,
    backend_pid: Option<u32>,
    backend_last_started_at_ms: Option<u64>,
    backend_last_health_check_at_ms: Option<u64>,
    gallery_records: Vec<LocalEngineGalleryCatalogRecord>,
}

#[derive(Debug, Clone, Default)]
struct ExecutorAdvanceOutcome {
    status: String,
    summary: Option<String>,
    hints: RegistryEffectHints,
}

#[derive(Debug, Clone)]
struct ModelInstallContext {
    model_id: String,
    source_uri: String,
    source_path: PathBuf,
    source_is_remote: bool,
    models_root: PathBuf,
    install_root: PathBuf,
    receipt_path: Option<PathBuf>,
}

#[derive(Debug, Clone)]
struct ModelInstallMaterialization {
    payload_path: PathBuf,
    bytes_transferred: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct InstalledModelManifest {
    model_id: String,
    #[serde(default)]
    job_id: Option<String>,
    #[serde(default)]
    source_uri: Option<String>,
    source_path: String,
    payload_path: String,
    install_root: String,
    #[serde(default)]
    bytes_transferred: Option<u64>,
    #[serde(default)]
    imported_at_ms: Option<u64>,
    #[serde(default)]
    backend_id: Option<String>,
}

#[derive(Debug, Clone)]
struct BackendContext {
    backend_id: String,
    source_uri: Option<String>,
    source_path: Option<PathBuf>,
    source_is_remote: bool,
    source_is_container_image: bool,
    backends_root: PathBuf,
    install_root: PathBuf,
    manifest_path: PathBuf,
    receipt_path: Option<PathBuf>,
}

#[derive(Debug, Clone)]
struct BackendInstallMaterialization {
    entrypoint: String,
    alias: Option<String>,
    health_endpoint: Option<String>,
    bytes_transferred: u64,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct BackendPackageManifest {
    #[serde(default)]
    entrypoint: Option<String>,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    env: BTreeMap<String, String>,
    #[serde(default)]
    health_url: Option<String>,
    #[serde(default)]
    alias: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct InstalledBackendManifest {
    backend_id: String,
    entrypoint: String,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    env: BTreeMap<String, String>,
    #[serde(default)]
    health_url: Option<String>,
    #[serde(default)]
    alias: Option<String>,
    #[serde(default)]
    source_uri: Option<String>,
    #[serde(default)]
    source_path: Option<String>,
    install_root: String,
    #[serde(default)]
    bytes_transferred: Option<u64>,
    #[serde(default)]
    installed_at_ms: Option<u64>,
    #[serde(default)]
    job_id: Option<String>,
}

#[derive(Debug)]
struct ManagedBackendProcess {
    child: Child,
    entrypoint: String,
    health_url: Option<String>,
    started_at_ms: u64,
}

#[derive(Debug, Clone)]
struct LocalGpuDevPreset {
    preset_id: String,
    runtime_url: Option<String>,
    runtime_health_url: Option<String>,
    runtime_model: Option<String>,
    embedding_model: Option<String>,
    backend_source: Option<String>,
    backend_id: Option<String>,
    model_cache_dir: Option<String>,
    backend_autostart: bool,
}

#[derive(Debug, Clone, Default)]
struct BackendRuntimeObservation {
    status: String,
    health: String,
    pid: Option<u32>,
    alias: Option<String>,
    install_path: Option<String>,
    entrypoint: Option<String>,
    health_endpoint: Option<String>,
    last_started_at_ms: Option<u64>,
    last_health_check_at_ms: Option<u64>,
}

#[derive(Debug, Clone)]
struct GallerySyncTarget {
    gallery_id: String,
    kind: String,
    label: String,
    source_uri: String,
    compatibility_tier: String,
    enabled: bool,
    catalog_path: PathBuf,
}

#[derive(Debug, Clone)]
struct GallerySyncContext {
    targets: Vec<GallerySyncTarget>,
    receipt_path: Option<PathBuf>,
}

#[derive(Debug, Clone)]
struct GallerySyncMaterialization {
    records: Vec<LocalEngineGalleryCatalogRecord>,
    total_entries: u32,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct GalleryCatalogDocument {
    version: u8,
    gallery_id: String,
    kind: String,
    label: String,
    source_uri: String,
    compatibility_tier: String,
    synced_at_ms: u64,
    entry_count: u32,
    entries: Vec<GalleryCatalogDocumentEntry>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct GalleryCatalogDocumentEntry {
    entry_id: String,
    label: String,
    summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_uri: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    tags: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    backend_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct LocalAiModelGalleryEntry {
    name: String,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    urls: Vec<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    files: Vec<LocalAiGalleryFile>,
    #[serde(default)]
    overrides: LocalAiModelGalleryOverrides,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct LocalAiGalleryFile {
    #[serde(default)]
    filename: Option<String>,
    #[serde(default)]
    uri: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct LocalAiModelGalleryOverrides {
    #[serde(default)]
    backend: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    known_usecases: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct LocalAiBackendGalleryEntry {
    name: String,
    #[serde(default)]
    alias: Option<String>,
    #[serde(default)]
    uri: Option<String>,
    #[serde(default)]
    mirrors: Vec<String>,
    #[serde(default)]
    urls: Vec<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    capabilities: BTreeMap<String, String>,
}

#[derive(Debug, Clone)]
struct ResolvedBackendGallerySource {
    backend_name: String,
    source_uri: Option<String>,
    selected_capability: Option<String>,
    resolved_from_meta: bool,
}


include!("status.rs");
include!("bootstrap.rs");
include!("executor.rs");
include!("models.rs");
include!("backend_jobs.rs");
include!("gallery.rs");
include!("backends.rs");
include!("effects.rs");
