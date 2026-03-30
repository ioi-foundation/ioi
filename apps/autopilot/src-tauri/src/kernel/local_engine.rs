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

pub fn job_progress_for_status(status: &str) -> u8 {
    match status {
        "queued" => 8,
        "ready" => 16,
        "running" => 55,
        "syncing" => 62,
        "applying" => 72,
        "completed" => 100,
        "failed" => 100,
        "cancelled" => 100,
        _ => 0,
    }
}

pub fn summary_for_job_status(job: &LocalEngineJobRecord, status: &str) -> String {
    let operation = humanize_token(&job.operation).to_ascii_lowercase();
    let subject = humanize_token(&job.subject_kind).to_ascii_lowercase();
    match status {
        "running" => format!(
            "Kernel-native control-plane execution is actively running {} {}.",
            operation, subject
        ),
        "syncing" => {
            "Gallery or registry synchronization is actively refreshing catalog truth.".to_string()
        }
        "applying" => format!(
            "Applying {} policy for the {} control plane under kernel authority.",
            operation, subject
        ),
        "completed" => completion_summary(job),
        "failed" => format!(
            "{} {} failed and should be triaged through typed lifecycle receipts.",
            humanize_token(&job.operation),
            humanize_token(&job.subject_kind).to_ascii_lowercase()
        ),
        "cancelled" => format!(
            "Operator cancelled the queued {} {} transition before completion.",
            operation, subject
        ),
        "ready" => format!(
            "{} {} is staged and ready to execute under kernel control.",
            humanize_token(&job.operation),
            subject
        ),
        _ => format!(
            "{} {} is queued inside the kernel-owned local engine registry.",
            humanize_token(&job.operation),
            subject
        ),
    }
}

pub fn load_or_sync_registry_state(
    memory_runtime: &Arc<MemoryRuntime>,
    control_plane: Option<&LocalEngineControlPlane>,
) -> LocalEngineRegistryState {
    let mut state =
        orchestrator::load_local_engine_registry_state(memory_runtime).unwrap_or_default();
    normalize_registry_state(&mut state, control_plane, now_ms());
    orchestrator::save_local_engine_registry_state(memory_runtime, &state);
    state
}

pub fn bootstrap_local_engine_dev_support(
    memory_runtime: &Arc<MemoryRuntime>,
) -> Result<(), String> {
    let mut control_plane =
        crate::kernel::data::load_or_initialize_local_engine_control_plane(memory_runtime);
    let dev_bootstrap_enabled = apply_dev_bootstrap_overrides(&mut control_plane);
    if dev_bootstrap_enabled {
        orchestrator::save_local_engine_control_plane(memory_runtime, &control_plane);
    }

    let registry_state = load_or_sync_registry_state(memory_runtime, Some(&control_plane));
    if dev_bootstrap_enabled {
        seed_bootstrap_jobs_from_env(memory_runtime, &control_plane, &registry_state)?;
        drive_local_gpu_dev_bootstrap(memory_runtime, &control_plane)?;
    }

    let mut state =
        orchestrator::load_local_engine_registry_state(memory_runtime).unwrap_or_default();
    normalize_registry_state(&mut state, Some(&control_plane), now_ms());
    orchestrator::save_local_engine_registry_state(memory_runtime, &state);
    Ok(())
}

fn apply_dev_bootstrap_overrides(control_plane: &mut LocalEngineControlPlane) -> bool {
    let local_gpu_preset = resolve_local_gpu_dev_preset();
    if let Some(preset) = local_gpu_preset.as_ref() {
        apply_local_gpu_dev_preset_env(preset);
    }

    let local_runtime_url =
        env_text("AUTOPILOT_LOCAL_RUNTIME_URL").or_else(|| env_text("LOCAL_LLM_URL"));
    let local_runtime_health_url = env_text("AUTOPILOT_LOCAL_RUNTIME_HEALTH_URL");
    let local_runtime_model = env_text("AUTOPILOT_LOCAL_RUNTIME_MODEL")
        .or_else(|| env_text("AUTOPILOT_LOCAL_MODEL_ID"))
        .or_else(|| env_text("OPENAI_MODEL"));
    let local_embedding_model = env_text("AUTOPILOT_LOCAL_EMBEDDING_MODEL")
        .or_else(|| env_text("LOCAL_LLM_EMBEDDING_MODEL"))
        .or_else(|| env_text("OPENAI_EMBEDDING_MODEL"));
    let local_model_source = env_text("AUTOPILOT_LOCAL_MODEL_SOURCE");
    let local_backend_source = env_text("AUTOPILOT_LOCAL_BACKEND_SOURCE");
    let local_backend_id = env_text("AUTOPILOT_LOCAL_BACKEND_ID");
    let local_dev_preset = env_text("AUTOPILOT_LOCAL_DEV_PRESET");
    let local_model_cache_dir = env_text("AUTOPILOT_LOCAL_MODEL_CACHE_DIR");
    let data_profile = env_text("AUTOPILOT_DATA_PROFILE");
    let dev_bootstrap_enabled = crate::is_env_var_truthy("AUTOPILOT_LOCAL_GPU_DEV")
        || local_runtime_url.is_some()
        || local_model_source.is_some()
        || local_backend_source.is_some()
        || local_dev_preset.is_some()
        || data_profile.is_some();

    if !dev_bootstrap_enabled {
        return false;
    }

    control_plane.runtime.mode = if local_runtime_url.is_some() {
        "http_local_dev".to_string()
    } else {
        "local_asset_bootstrap".to_string()
    };
    if let Some(local_runtime_url) = local_runtime_url.clone() {
        control_plane.runtime.endpoint = local_runtime_url;
    }
    if let Some(local_runtime_model) = local_runtime_model.clone() {
        control_plane.runtime.default_model = local_runtime_model;
    }
    control_plane.runtime.baseline_role =
        "Local bootstrap profile for Studio workflow testing on a developer-managed GPU/runtime."
            .to_string();
    control_plane.runtime.kernel_authority =
        "Kernel remains planner-of-record, receipt authority, and policy boundary while local GPU assets are bootstrapped for testing."
            .to_string();
    control_plane.memory.prefer_gpu = true;
    if control_plane.memory.target_resource.trim().is_empty()
        || control_plane.memory.target_resource == "auto"
    {
        control_plane.memory.target_resource = "gpu".to_string();
    }
    if crate::is_env_var_truthy("AUTOPILOT_LOCAL_BACKEND_AUTOSTART")
        || local_gpu_preset
            .as_ref()
            .map(|preset| preset.backend_autostart)
            .unwrap_or(false)
    {
        control_plane.launcher.auto_start_on_boot = true;
    }

    upsert_environment_binding(
        &mut control_plane.environment,
        "AUTOPILOT_LOCAL_RUNTIME_URL",
        local_runtime_url,
    );
    upsert_environment_binding(
        &mut control_plane.environment,
        "AUTOPILOT_LOCAL_RUNTIME_MODEL",
        local_runtime_model,
    );
    upsert_environment_binding(
        &mut control_plane.environment,
        "AUTOPILOT_LOCAL_EMBEDDING_MODEL",
        local_embedding_model.clone(),
    );
    upsert_environment_binding(
        &mut control_plane.environment,
        "LOCAL_LLM_EMBEDDING_MODEL",
        local_embedding_model.clone(),
    );
    upsert_environment_binding(
        &mut control_plane.environment,
        "OPENAI_EMBEDDING_MODEL",
        local_embedding_model,
    );
    upsert_environment_binding(
        &mut control_plane.environment,
        "AUTOPILOT_LOCAL_RUNTIME_HEALTH_URL",
        local_runtime_health_url,
    );
    upsert_environment_binding(
        &mut control_plane.environment,
        "AUTOPILOT_LOCAL_MODEL_SOURCE",
        local_model_source,
    );
    upsert_environment_binding(
        &mut control_plane.environment,
        "AUTOPILOT_LOCAL_BACKEND_SOURCE",
        local_backend_source,
    );
    upsert_environment_binding(
        &mut control_plane.environment,
        "AUTOPILOT_LOCAL_BACKEND_ID",
        local_backend_id,
    );
    upsert_environment_binding(
        &mut control_plane.environment,
        "AUTOPILOT_LOCAL_DEV_PRESET",
        local_dev_preset,
    );
    upsert_environment_binding(
        &mut control_plane.environment,
        "AUTOPILOT_LOCAL_MODEL_CACHE_DIR",
        local_model_cache_dir,
    );
    upsert_environment_binding(
        &mut control_plane.environment,
        "AUTOPILOT_DATA_PROFILE",
        data_profile,
    );
    true
}

fn default_local_gpu_dev_model_cache_dir() -> String {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".ollama")
        .join("models")
        .display()
        .to_string()
}

fn resolve_local_gpu_dev_preset() -> Option<LocalGpuDevPreset> {
    let local_gpu_dev_enabled = crate::is_env_var_truthy("AUTOPILOT_LOCAL_GPU_DEV");
    let explicit_runtime_url =
        env_text("AUTOPILOT_LOCAL_RUNTIME_URL").or_else(|| env_text("LOCAL_LLM_URL"));
    let explicit_health_url = env_text("AUTOPILOT_LOCAL_RUNTIME_HEALTH_URL");
    let explicit_backend_source = env_text("AUTOPILOT_LOCAL_BACKEND_SOURCE");
    let explicit_backend_id = env_text("AUTOPILOT_LOCAL_BACKEND_ID");
    let preset_id = env_text("AUTOPILOT_LOCAL_DEV_PRESET").or_else(|| {
        if local_gpu_dev_enabled {
            Some(LOCAL_GPU_DEV_DEFAULT_PRESET.to_string())
        } else {
            None
        }
    })?;

    let normalized_preset_id = normalize_text(&preset_id);
    if normalized_preset_id != LOCAL_GPU_DEV_DEFAULT_PRESET {
        return Some(LocalGpuDevPreset {
            preset_id: normalized_preset_id,
            runtime_url: explicit_runtime_url,
            runtime_health_url: explicit_health_url,
            runtime_model: env_text("AUTOPILOT_LOCAL_RUNTIME_MODEL")
                .or_else(|| env_text("AUTOPILOT_LOCAL_MODEL_ID"))
                .or_else(|| env_text("OPENAI_MODEL")),
            embedding_model: env_text("AUTOPILOT_LOCAL_EMBEDDING_MODEL")
                .or_else(|| env_text("LOCAL_LLM_EMBEDDING_MODEL"))
                .or_else(|| env_text("OPENAI_EMBEDDING_MODEL")),
            backend_source: explicit_backend_source,
            backend_id: explicit_backend_id,
            model_cache_dir: env_text("AUTOPILOT_LOCAL_MODEL_CACHE_DIR"),
            backend_autostart: crate::is_env_var_truthy("AUTOPILOT_LOCAL_BACKEND_AUTOSTART"),
        });
    }

    let ollama_available = command_exists("ollama");
    if !ollama_available && explicit_runtime_url.is_none() && explicit_backend_source.is_none() {
        println!(
            "[Studio] Local GPU preset '{}' is available, but 'ollama' was not found on PATH. Falling back to mock inference until a local runtime is installed or configured.",
            LOCAL_GPU_DEV_DEFAULT_PRESET
        );
        return Some(LocalGpuDevPreset {
            preset_id: normalized_preset_id,
            runtime_url: None,
            runtime_health_url: explicit_health_url,
            runtime_model: env_text("AUTOPILOT_LOCAL_RUNTIME_MODEL")
                .or_else(|| env_text("AUTOPILOT_LOCAL_MODEL_ID"))
                .or_else(|| Some(LOCAL_GPU_DEV_DEFAULT_MODEL.to_string())),
            embedding_model: env_text("AUTOPILOT_LOCAL_EMBEDDING_MODEL")
                .or_else(|| env_text("LOCAL_LLM_EMBEDDING_MODEL"))
                .or_else(|| env_text("OPENAI_EMBEDDING_MODEL"))
                .or_else(|| Some(LOCAL_GPU_DEV_DEFAULT_EMBEDDING_MODEL.to_string())),
            backend_source: None,
            backend_id: explicit_backend_id
                .or_else(|| Some(LOCAL_GPU_DEV_DEFAULT_BACKEND_ID.to_string())),
            model_cache_dir: env_text("AUTOPILOT_LOCAL_MODEL_CACHE_DIR")
                .or_else(|| Some(default_local_gpu_dev_model_cache_dir())),
            backend_autostart: false,
        });
    }

    Some(LocalGpuDevPreset {
        preset_id: normalized_preset_id,
        runtime_url: explicit_runtime_url
            .or_else(|| Some(LOCAL_GPU_DEV_DEFAULT_RUNTIME_URL.to_string())),
        runtime_health_url: explicit_health_url
            .or_else(|| Some(LOCAL_GPU_DEV_DEFAULT_HEALTH_URL.to_string())),
        runtime_model: env_text("AUTOPILOT_LOCAL_RUNTIME_MODEL")
            .or_else(|| env_text("AUTOPILOT_LOCAL_MODEL_ID"))
            .or_else(|| env_text("OPENAI_MODEL"))
            .or_else(|| Some(LOCAL_GPU_DEV_DEFAULT_MODEL.to_string())),
        embedding_model: env_text("AUTOPILOT_LOCAL_EMBEDDING_MODEL")
            .or_else(|| env_text("LOCAL_LLM_EMBEDDING_MODEL"))
            .or_else(|| env_text("OPENAI_EMBEDDING_MODEL"))
            .or_else(|| Some(LOCAL_GPU_DEV_DEFAULT_EMBEDDING_MODEL.to_string())),
        backend_source: explicit_backend_source
            .or_else(|| Some(LOCAL_GPU_DEV_DEFAULT_BACKEND_SOURCE.to_string())),
        backend_id: explicit_backend_id
            .or_else(|| Some(LOCAL_GPU_DEV_DEFAULT_BACKEND_ID.to_string())),
        model_cache_dir: env_text("AUTOPILOT_LOCAL_MODEL_CACHE_DIR")
            .or_else(|| Some(default_local_gpu_dev_model_cache_dir())),
        backend_autostart: crate::is_env_var_truthy("AUTOPILOT_LOCAL_BACKEND_AUTOSTART")
            || local_gpu_dev_enabled,
    })
}

fn apply_local_gpu_dev_preset_env(preset: &LocalGpuDevPreset) {
    std::env::set_var("AUTOPILOT_LOCAL_DEV_PRESET", &preset.preset_id);
    if let Some(runtime_url) = preset.runtime_url.as_ref() {
        std::env::set_var("AUTOPILOT_LOCAL_RUNTIME_URL", runtime_url);
    }
    if let Some(runtime_health_url) = preset.runtime_health_url.as_ref() {
        std::env::set_var("AUTOPILOT_LOCAL_RUNTIME_HEALTH_URL", runtime_health_url);
    }
    if let Some(runtime_model) = preset.runtime_model.as_ref() {
        std::env::set_var("AUTOPILOT_LOCAL_RUNTIME_MODEL", runtime_model);
    }
    if let Some(embedding_model) = preset.embedding_model.as_ref() {
        std::env::set_var("AUTOPILOT_LOCAL_EMBEDDING_MODEL", embedding_model);
        std::env::set_var("LOCAL_LLM_EMBEDDING_MODEL", embedding_model);
        std::env::set_var("OPENAI_EMBEDDING_MODEL", embedding_model);
    }
    if let Some(backend_source) = preset.backend_source.as_ref() {
        std::env::set_var("AUTOPILOT_LOCAL_BACKEND_SOURCE", backend_source);
    }
    if let Some(backend_id) = preset.backend_id.as_ref() {
        std::env::set_var("AUTOPILOT_LOCAL_BACKEND_ID", backend_id);
    }
    if let Some(model_cache_dir) = preset.model_cache_dir.as_ref() {
        std::env::set_var("AUTOPILOT_LOCAL_MODEL_CACHE_DIR", model_cache_dir);
    }
    if preset.backend_autostart {
        std::env::set_var("AUTOPILOT_LOCAL_BACKEND_AUTOSTART", "1");
    }
}

fn command_exists(binary: &str) -> bool {
    command_path(binary)
        .map(|binary_path| {
            Command::new(binary_path)
                .arg("--version")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .is_ok()
        })
        .unwrap_or(false)
}

fn command_path(binary: &str) -> Option<PathBuf> {
    if binary.contains(std::path::MAIN_SEPARATOR) {
        let path = PathBuf::from(binary);
        return path.exists().then_some(path);
    }

    std::env::var_os("PATH")
        .and_then(|paths| {
            std::env::split_paths(&paths)
                .map(|dir| dir.join(binary))
                .find(|candidate| candidate.exists())
        })
        .or_else(|| {
            std::env::var_os("HOME")
                .map(PathBuf::from)
                .map(|home| home.join(".local").join("bin").join(binary))
                .filter(|candidate| candidate.exists())
        })
}

fn run_command_capture_stdout(binary: &str, args: &[&str]) -> Result<String, String> {
    let binary_path = command_path(binary)
        .ok_or_else(|| format!("required command '{}' was not found on PATH", binary))?;
    let output = Command::new(binary_path)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .map_err(|error| format!("failed to run {}: {}", binary, error))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(if stderr.is_empty() {
            format!("{} exited with status {}", binary, output.status)
        } else {
            format!(
                "{} exited with status {}: {}",
                binary, output.status, stderr
            )
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn drive_local_gpu_dev_bootstrap(
    memory_runtime: &Arc<MemoryRuntime>,
    control_plane: &LocalEngineControlPlane,
) -> Result<(), String> {
    let runtime_health_required = local_gpu_dev_runtime_health_required(control_plane);
    for _ in 0..LOCAL_ENGINE_DEV_BOOTSTRAP_MAX_ITERATIONS {
        let registry_state = load_or_sync_registry_state(memory_runtime, Some(control_plane));
        seed_bootstrap_jobs_from_env(memory_runtime, control_plane, &registry_state)?;
        mark_live_bootstrap_jobs_ready(memory_runtime);
        let advanced = advance_executor_jobs(memory_runtime, Some(control_plane));
        if bootstrap_jobs_failed(memory_runtime) {
            break;
        }

        let runtime_ready = local_runtime_health_ready(control_plane);
        let live_jobs = has_live_bootstrap_jobs(memory_runtime);
        if local_gpu_dev_bootstrap_ready(runtime_health_required, runtime_ready, live_jobs) {
            break;
        }

        if advanced == 0 || !live_jobs {
            std::thread::sleep(std::time::Duration::from_millis(
                LOCAL_ENGINE_DEV_BOOTSTRAP_SLEEP_MS,
            ));
        }
    }
    if runtime_health_required && !local_runtime_health_ready(control_plane) {
        let endpoint = env_text("AUTOPILOT_LOCAL_RUNTIME_HEALTH_URL")
            .or_else(|| Some(control_plane.runtime.endpoint.clone()))
            .unwrap_or_else(|| "the configured local runtime".to_string());
        eprintln!(
            "[Studio] Local GPU dev bootstrap did not reach a healthy runtime at {} before setup completed. Studio and the kernel will keep retrying, but early requests may fail until the local runtime is reachable.",
            endpoint
        );
    }
    ensure_local_gpu_dev_model_ready(control_plane);
    Ok(())
}

fn local_gpu_dev_runtime_health_required(control_plane: &LocalEngineControlPlane) -> bool {
    env_text("AUTOPILOT_LOCAL_RUNTIME_HEALTH_URL").is_some()
        || !control_plane.runtime.endpoint.trim().is_empty()
}

fn local_gpu_dev_bootstrap_ready(
    runtime_health_required: bool,
    runtime_ready: bool,
    live_jobs: bool,
) -> bool {
    runtime_ready || (!runtime_health_required && !live_jobs)
}

fn mark_live_bootstrap_jobs_ready(memory_runtime: &Arc<MemoryRuntime>) {
    let mut jobs = orchestrator::load_local_engine_jobs(memory_runtime);
    let mut changed = false;
    let due_at_ms = now_ms().saturating_sub(LOCAL_ENGINE_EXECUTOR_TICK_MS);
    for job in &mut jobs {
        if job.origin == "bootstrap"
            && !matches!(job.status.as_str(), "completed" | "failed" | "cancelled")
            && job.updated_at_ms > due_at_ms
        {
            job.updated_at_ms = due_at_ms;
            changed = true;
        }
    }
    if changed {
        orchestrator::save_local_engine_jobs(memory_runtime, &jobs);
    }
}

fn has_live_bootstrap_jobs(memory_runtime: &Arc<MemoryRuntime>) -> bool {
    orchestrator::load_local_engine_jobs(memory_runtime)
        .iter()
        .any(|job| {
            job.origin == "bootstrap"
                && !matches!(job.status.as_str(), "completed" | "failed" | "cancelled")
        })
}

fn bootstrap_jobs_failed(memory_runtime: &Arc<MemoryRuntime>) -> bool {
    orchestrator::load_local_engine_jobs(memory_runtime)
        .iter()
        .any(|job| job.origin == "bootstrap" && job.status == "failed")
}

fn local_runtime_health_ready(control_plane: &LocalEngineControlPlane) -> bool {
    env_text("AUTOPILOT_LOCAL_RUNTIME_HEALTH_URL")
        .or_else(|| {
            if control_plane.runtime.endpoint.trim().is_empty() {
                None
            } else {
                Some(control_plane.runtime.endpoint.clone())
            }
        })
        .map(|endpoint| probe_health_endpoint(&endpoint).is_ok())
        .unwrap_or(false)
}

fn ensure_local_gpu_dev_model_ready(control_plane: &LocalEngineControlPlane) {
    if env_text("AUTOPILOT_LOCAL_DEV_PRESET").as_deref() != Some(LOCAL_GPU_DEV_DEFAULT_PRESET) {
        return;
    }
    if !local_runtime_health_ready(control_plane) {
        return;
    }

    if !command_exists("ollama") {
        return;
    }

    let runtime_model = env_text("AUTOPILOT_LOCAL_RUNTIME_MODEL")
        .or_else(|| Some(control_plane.runtime.default_model.clone()))
        .filter(|value| !value.trim().is_empty());
    let embedding_model = env_text("AUTOPILOT_LOCAL_EMBEDDING_MODEL")
        .or_else(|| env_text("LOCAL_LLM_EMBEDDING_MODEL"))
        .or_else(|| env_text("OPENAI_EMBEDDING_MODEL"))
        .filter(|value| !value.trim().is_empty());

    if let Some(model) = runtime_model.as_ref() {
        ensure_ollama_model_ready(model, "Default local GPU chat model");
    }
    if let Some(model) = embedding_model.as_ref() {
        if runtime_model.as_deref() != Some(model.as_str()) {
            ensure_ollama_model_ready(model, "Default local GPU embedding model");
        }
    }
}

fn ollama_model_is_available(model: &str) -> Result<bool, String> {
    let output = run_command_capture_stdout("ollama", &["list"])?;
    Ok(output.lines().skip(1).any(|line| {
        line.split_whitespace()
            .next()
            .map(|value| {
                value == model || (!model.contains(':') && value == format!("{model}:latest"))
            })
            .unwrap_or(false)
    }))
}

fn ensure_ollama_model_ready(model: &str, label: &str) {
    if ollama_model_is_available(model).unwrap_or(false) {
        return;
    }

    println!(
        "[Studio] {} '{}' is not cached yet. Pulling it into the persistent host cache for future clean-profile runs.",
        label, model
    );
    match run_command_capture_stdout("ollama", &["pull", model]) {
        Ok(_) => println!(
            "[Studio] {} '{}' is now ready in the persistent cache.",
            label, model
        ),
        Err(error) => eprintln!(
            "[Studio] Failed to pull {} '{}': {}",
            label.to_ascii_lowercase(),
            model,
            error
        ),
    }
}

fn upsert_environment_binding(
    bindings: &mut Vec<crate::models::LocalEngineEnvironmentBinding>,
    key: &str,
    value: Option<String>,
) {
    let value = value.unwrap_or_default();
    if let Some(existing) = bindings.iter_mut().find(|binding| binding.key == key) {
        existing.value = value;
        existing.secret = false;
        return;
    }
    bindings.push(crate::models::LocalEngineEnvironmentBinding {
        key: key.to_string(),
        value,
        secret: false,
    });
}

fn env_text(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

pub fn emit_local_engine_update(app: &AppHandle, reason: &str) {
    let _ = app.emit(LOCAL_ENGINE_UPDATED_EVENT, reason);
}

pub async fn spawn_local_engine_executor(app: AppHandle) {
    let _ = tick_local_engine_executor(&app);
    loop {
        tokio::time::sleep(std::time::Duration::from_millis(
            LOCAL_ENGINE_EXECUTOR_TICK_MS,
        ))
        .await;
        let _ = tick_local_engine_executor(&app);
    }
}

pub fn tick_local_engine_executor(app: &AppHandle) -> usize {
    let Some(memory_runtime) = app_memory_runtime(app) else {
        return 0;
    };
    let control_plane = orchestrator::load_local_engine_control_plane(&memory_runtime);
    let advanced = advance_executor_jobs(&memory_runtime, control_plane.as_ref());
    if advanced > 0 {
        emit_local_engine_update(app, "executor_tick");
    }
    advanced
}

pub fn record_promoted_job(
    memory_runtime: &Arc<MemoryRuntime>,
    control_plane: Option<&LocalEngineControlPlane>,
    job: &LocalEngineJobRecord,
) {
    let now_ms = now_ms();
    let mut state =
        orchestrator::load_local_engine_registry_state(memory_runtime).unwrap_or_default();
    apply_job_effect(
        &mut state,
        control_plane,
        job,
        now_ms,
        &RegistryEffectHints::default(),
    );
    push_operator_activity(&mut state, job, now_ms);
    normalize_registry_state(&mut state, control_plane, now_ms);
    orchestrator::save_local_engine_registry_state(memory_runtime, &state);
}

pub fn advance_executor_jobs(
    memory_runtime: &Arc<MemoryRuntime>,
    control_plane: Option<&LocalEngineControlPlane>,
) -> usize {
    let now_ms = now_ms();
    let mut jobs = orchestrator::load_local_engine_jobs(memory_runtime);
    let mut state =
        orchestrator::load_local_engine_registry_state(memory_runtime).unwrap_or_default();
    let mut advanced_count = 0usize;

    for job in &mut jobs {
        let Some(outcome) = advance_executor_job(job, &state, control_plane, now_ms) else {
            continue;
        };
        job.status = outcome.status.clone();
        job.updated_at_ms = now_ms;
        job.progress_percent = job_progress_for_status(&outcome.status);
        job.summary = outcome
            .summary
            .unwrap_or_else(|| summary_for_job_status(job, &outcome.status));
        apply_job_effect(&mut state, control_plane, job, now_ms, &outcome.hints);
        push_executor_activity(&mut state, job, now_ms);
        advanced_count = advanced_count.saturating_add(1);
    }

    advanced_count =
        advanced_count.saturating_add(refresh_supervised_backend_state(&mut state, now_ms));

    if advanced_count == 0 {
        return 0;
    }

    if !jobs.is_empty() {
        jobs.sort_by(|left, right| {
            right
                .updated_at_ms
                .cmp(&left.updated_at_ms)
                .then_with(|| left.title.cmp(&right.title))
        });
        orchestrator::save_local_engine_jobs(memory_runtime, &jobs);
    }
    normalize_registry_state(&mut state, control_plane, now_ms);
    orchestrator::save_local_engine_registry_state(memory_runtime, &state);
    advanced_count
}

pub fn update_job_status(
    memory_runtime: &Arc<MemoryRuntime>,
    control_plane: Option<&LocalEngineControlPlane>,
    job_id: &str,
    status: &str,
) -> Result<LocalEngineJobRecord, String> {
    let normalized_status = normalize_job_status(status);
    let now_ms = now_ms();
    let mut jobs = orchestrator::load_local_engine_jobs(memory_runtime);
    let Some(index) = jobs.iter().position(|job| job.job_id == job_id) else {
        return Err("job not found".to_string());
    };

    jobs[index].status = normalized_status.clone();
    jobs[index].updated_at_ms = now_ms;
    jobs[index].progress_percent = job_progress_for_status(&normalized_status);
    jobs[index].summary = summary_for_job_status(&jobs[index], &normalized_status);
    let updated = jobs[index].clone();

    jobs.sort_by(|left, right| {
        right
            .updated_at_ms
            .cmp(&left.updated_at_ms)
            .then_with(|| left.title.cmp(&right.title))
    });
    orchestrator::save_local_engine_jobs(memory_runtime, &jobs);

    let mut state =
        orchestrator::load_local_engine_registry_state(memory_runtime).unwrap_or_default();
    apply_job_effect(
        &mut state,
        control_plane,
        &updated,
        now_ms,
        &RegistryEffectHints::default(),
    );
    push_operator_activity(&mut state, &updated, now_ms);
    normalize_registry_state(&mut state, control_plane, now_ms);
    orchestrator::save_local_engine_registry_state(memory_runtime, &state);

    Ok(updated)
}

pub fn ingest_model_lifecycle_receipt(
    memory_runtime: &Arc<MemoryRuntime>,
    control_plane: Option<&LocalEngineControlPlane>,
    receipt: ModelLifecycleReceiptUpdate,
) {
    let operation = normalize_token(&receipt.operation);
    let subject_kind = normalize_subject_kind(&receipt.subject_kind);
    let subject_id = normalize_text(&receipt.subject_id);
    if operation.is_empty() || subject_kind.is_empty() {
        return;
    }

    let status = lifecycle_status_for_receipt(&receipt, &subject_kind, &operation);
    let timestamp_ms = if receipt.timestamp_ms == 0 {
        now_ms()
    } else {
        receipt.timestamp_ms
    };
    let source_uri = normalize_optional_text(receipt.source_uri.clone());
    let backend_id = normalize_optional_text(receipt.backend_id.clone());
    let job_id = normalize_optional_text(receipt.job_id.clone()).unwrap_or_else(|| {
        format!(
            "receipt:{}:{}:{}:{}:{}",
            subject_kind,
            operation,
            if subject_id.is_empty() {
                "anonymous"
            } else {
                subject_id.as_str()
            },
            receipt.session_id,
            receipt.workload_id
        )
    });
    let subject_id_opt = if subject_id.is_empty() {
        None
    } else {
        Some(subject_id.clone())
    };

    let mut jobs = orchestrator::load_local_engine_jobs(memory_runtime);
    let existing = jobs.iter().position(|job| job.job_id == job_id);
    let title = stage_operation_title(&subject_kind, &operation, subject_id_opt.as_deref());

    let mut job = existing
        .and_then(|index| jobs.get(index).cloned())
        .unwrap_or(LocalEngineJobRecord {
            job_id: job_id.clone(),
            title,
            summary: String::new(),
            status: status.clone(),
            origin: "workload_receipt".to_string(),
            subject_kind: subject_kind.clone(),
            operation: operation.clone(),
            created_at_ms: timestamp_ms,
            updated_at_ms: timestamp_ms,
            progress_percent: job_progress_for_status(&status),
            source_uri: source_uri.clone(),
            subject_id: subject_id_opt.clone(),
            backend_id: backend_id.clone(),
            severity: Some(if receipt.success {
                "informational".to_string()
            } else {
                "high".to_string()
            }),
            approval_scope: Some("model::control".to_string()),
        });

    job.title = if job.title.trim().is_empty() {
        stage_operation_title(&subject_kind, &operation, subject_id_opt.as_deref())
    } else {
        job.title
    };
    job.summary = summary_for_receipt(&job, &receipt, &status);
    job.status = status.clone();
    job.origin = if job.origin.trim().is_empty() {
        "workload_receipt".to_string()
    } else {
        job.origin
    };
    job.subject_kind = subject_kind.clone();
    job.operation = operation.clone();
    job.updated_at_ms = timestamp_ms;
    job.progress_percent = job_progress_for_status(&status);
    job.source_uri = source_uri.or(job.source_uri);
    job.subject_id = subject_id_opt.or(job.subject_id);
    job.backend_id = backend_id.or(job.backend_id);
    job.severity = Some(if receipt.success {
        "informational".to_string()
    } else {
        "high".to_string()
    });
    if job.approval_scope.is_none() {
        job.approval_scope = Some("model::control".to_string());
    }

    if let Some(index) = existing {
        jobs[index] = job.clone();
    } else {
        jobs.push(job.clone());
    }
    jobs.sort_by(|left, right| {
        right
            .updated_at_ms
            .cmp(&left.updated_at_ms)
            .then_with(|| left.title.cmp(&right.title))
    });
    orchestrator::save_local_engine_jobs(memory_runtime, &jobs);

    let hints = RegistryEffectHints {
        bytes_transferred: receipt.bytes_transferred,
        hardware_profile: normalize_optional_text(receipt.hardware_profile.clone()),
        ..RegistryEffectHints::default()
    };
    let mut state =
        orchestrator::load_local_engine_registry_state(memory_runtime).unwrap_or_default();
    apply_job_effect(&mut state, control_plane, &job, timestamp_ms, &hints);
    normalize_registry_state(&mut state, control_plane, timestamp_ms);
    orchestrator::save_local_engine_registry_state(memory_runtime, &state);
}

pub fn merge_recent_activity(
    receipt_activity: Vec<LocalEngineActivityRecord>,
    registry_state: &LocalEngineRegistryState,
    limit: usize,
) -> Vec<LocalEngineActivityRecord> {
    let mut merged = receipt_activity;
    merged.extend(registry_state.activity_history.iter().cloned());
    merged.sort_by(|left, right| {
        right
            .timestamp_ms
            .cmp(&left.timestamp_ms)
            .then_with(|| left.event_id.cmp(&right.event_id))
    });
    merged.dedup_by(|left, right| left.event_id == right.event_id);
    merged.truncate(limit);
    merged
}

fn seed_bootstrap_jobs_from_env(
    memory_runtime: &Arc<MemoryRuntime>,
    control_plane: &LocalEngineControlPlane,
    registry_state: &LocalEngineRegistryState,
) -> Result<(), String> {
    let jobs = orchestrator::load_local_engine_jobs(memory_runtime);
    if let Some(model_source) = env_text("AUTOPILOT_LOCAL_MODEL_SOURCE") {
        let model_id = normalize_bootstrap_identifier(
            env_text("AUTOPILOT_LOCAL_MODEL_ID")
                .unwrap_or_else(|| infer_identifier_from_source(&model_source)),
        );
        let already_installed = registry_state
            .registry_models
            .iter()
            .any(|record| record.model_id == model_id && record.status != "failed");
        let install_job_id = format!("bootstrap:model:install:{}", model_id);
        let has_live_install_job = jobs.iter().any(|job| {
            job.job_id == install_job_id
                && !matches!(job.status.as_str(), "completed" | "failed" | "cancelled")
        });
        if !already_installed && !has_live_install_job {
            queue_bootstrap_job(
                memory_runtime,
                control_plane,
                bootstrap_job("model", "install", Some(model_source), Some(model_id), None),
            )?;
        }
    }

    if let Some(backend_source) = env_text("AUTOPILOT_LOCAL_BACKEND_SOURCE") {
        let backend_id = normalize_bootstrap_identifier(
            env_text("AUTOPILOT_LOCAL_BACKEND_ID")
                .unwrap_or_else(|| infer_identifier_from_source(&backend_source)),
        );
        let installed_backend = registry_state
            .managed_backends
            .iter()
            .find(|record| record.backend_id == backend_id);
        let install_job_id = format!("bootstrap:backend:install:{}", backend_id);
        let start_job_id = format!("bootstrap:backend:start:{}", backend_id);
        let health_job_id = format!("bootstrap:backend:health:{}", backend_id);
        let has_live_install_job = jobs.iter().any(|job| {
            job.job_id == install_job_id
                && !matches!(job.status.as_str(), "completed" | "failed" | "cancelled")
        });
        let has_live_start_job = jobs.iter().any(|job| {
            job.job_id == start_job_id
                && !matches!(job.status.as_str(), "completed" | "failed" | "cancelled")
        });
        let has_live_health_job = jobs.iter().any(|job| {
            job.job_id == health_job_id
                && !matches!(job.status.as_str(), "completed" | "failed" | "cancelled")
        });
        if installed_backend.is_none() && !has_live_install_job {
            queue_bootstrap_job(
                memory_runtime,
                control_plane,
                bootstrap_job(
                    "backend",
                    "install",
                    Some(backend_source),
                    Some(backend_id.clone()),
                    Some(backend_id.clone()),
                ),
            )?;
        } else if control_plane.launcher.auto_start_on_boot {
            let runtime_healthy = local_runtime_health_ready(control_plane);
            if should_queue_bootstrap_backend_start(
                installed_backend,
                has_live_install_job,
                has_live_start_job,
                runtime_healthy,
            ) {
                queue_bootstrap_job(
                    memory_runtime,
                    control_plane,
                    bootstrap_job(
                        "backend",
                        "start",
                        None,
                        Some(backend_id.clone()),
                        Some(backend_id.clone()),
                    ),
                )?;
            } else if should_queue_bootstrap_backend_health(
                installed_backend,
                has_live_install_job,
                has_live_start_job,
                has_live_health_job,
            ) {
                queue_bootstrap_job(
                    memory_runtime,
                    control_plane,
                    bootstrap_job(
                        "backend",
                        "health",
                        None,
                        Some(backend_id.clone()),
                        Some(backend_id),
                    ),
                )?;
            }
        }
    }

    Ok(())
}

fn should_queue_bootstrap_backend_start(
    installed_backend: Option<&LocalEngineBackendRecord>,
    has_live_install_job: bool,
    has_live_start_job: bool,
    runtime_healthy: bool,
) -> bool {
    !has_live_install_job
        && !has_live_start_job
        && !runtime_healthy
        && installed_backend.is_some_and(bootstrap_backend_can_start)
}

fn should_queue_bootstrap_backend_health(
    installed_backend: Option<&LocalEngineBackendRecord>,
    has_live_install_job: bool,
    has_live_start_job: bool,
    has_live_health_job: bool,
) -> bool {
    !has_live_install_job
        && !has_live_start_job
        && !has_live_health_job
        && installed_backend
            .is_some_and(|record| record.status == "running" && record.health != "healthy")
}

fn bootstrap_backend_can_start(record: &LocalEngineBackendRecord) -> bool {
    matches!(record.status.as_str(), "installed" | "stopped") && record.health != "healthy"
}

fn bootstrap_job(
    subject_kind: &str,
    operation: &str,
    source_uri: Option<String>,
    subject_id: Option<String>,
    backend_id: Option<String>,
) -> LocalEngineJobRecord {
    let now = now_ms();
    let identifier = subject_id
        .clone()
        .or_else(|| backend_id.clone())
        .unwrap_or_else(|| normalize_bootstrap_identifier(subject_kind));
    let title = stage_operation_title(subject_kind, operation, Some(&identifier));
    let mut job = LocalEngineJobRecord {
        job_id: format!("bootstrap:{}:{}:{}", subject_kind, operation, identifier),
        title,
        summary: String::new(),
        status: "queued".to_string(),
        origin: "bootstrap".to_string(),
        subject_kind: subject_kind.to_string(),
        operation: operation.to_string(),
        created_at_ms: now,
        updated_at_ms: now,
        progress_percent: job_progress_for_status("queued"),
        source_uri,
        subject_id,
        backend_id,
        severity: Some("informational".to_string()),
        approval_scope: Some("model::control".to_string()),
    };
    job.summary = summary_for_job_status(&job, &job.status);
    job
}

fn queue_bootstrap_job(
    memory_runtime: &Arc<MemoryRuntime>,
    control_plane: &LocalEngineControlPlane,
    job: LocalEngineJobRecord,
) -> Result<(), String> {
    let mut jobs = orchestrator::load_local_engine_jobs(memory_runtime);
    let has_live_match = jobs.iter().any(|existing| {
        existing.job_id == job.job_id
            && !matches!(
                existing.status.as_str(),
                "completed" | "failed" | "cancelled"
            )
    });
    if has_live_match {
        return Ok(());
    }

    jobs.retain(|existing| existing.job_id != job.job_id);
    jobs.push(job.clone());
    jobs.sort_by(|left, right| {
        right
            .updated_at_ms
            .cmp(&left.updated_at_ms)
            .then_with(|| left.title.cmp(&right.title))
    });
    orchestrator::save_local_engine_jobs(memory_runtime, &jobs);
    record_promoted_job(memory_runtime, Some(control_plane), &job);
    Ok(())
}

fn normalize_bootstrap_identifier(value: impl AsRef<str>) -> String {
    normalize_model_identifier(value.as_ref())
}

fn infer_identifier_from_source(source: &str) -> String {
    if let Ok(path) = resolve_local_source_path(source) {
        if path.exists() {
            return normalize_bootstrap_identifier(infer_model_identifier_from_path(&path));
        }
    }
    infer_model_identifier_from_source_uri(source)
}

fn normalize_registry_state(
    state: &mut LocalEngineRegistryState,
    control_plane: Option<&LocalEngineControlPlane>,
    now_ms: u64,
) {
    if let Some(control_plane) = control_plane {
        rehydrate_installed_models(state, control_plane, now_ms);
        rehydrate_installed_backends(state, control_plane, now_ms);
    }

    if let Some(control_plane) = control_plane {
        state.gallery_catalogs = reconcile_gallery_catalogs(
            &state.gallery_catalogs,
            control_plane,
            state.registry_models.len() as u32,
            state.managed_backends.len() as u32,
            now_ms,
        );
    } else {
        state.gallery_catalogs.sort_by(|left, right| {
            left.kind
                .cmp(&right.kind)
                .then_with(|| left.label.cmp(&right.label))
        });
    }

    state.registry_models.sort_by(|left, right| {
        right
            .updated_at_ms
            .cmp(&left.updated_at_ms)
            .then_with(|| left.model_id.cmp(&right.model_id))
    });
    state.managed_backends.sort_by(|left, right| {
        right
            .updated_at_ms
            .cmp(&left.updated_at_ms)
            .then_with(|| left.backend_id.cmp(&right.backend_id))
    });
    state.activity_history.sort_by(|left, right| {
        right
            .timestamp_ms
            .cmp(&left.timestamp_ms)
            .then_with(|| left.event_id.cmp(&right.event_id))
    });
    state.activity_history.truncate(MAX_ACTIVITY_HISTORY);
}

fn rehydrate_installed_models(
    state: &mut LocalEngineRegistryState,
    control_plane: &LocalEngineControlPlane,
    now_ms: u64,
) {
    for record in discover_installed_models(control_plane, now_ms) {
        if let Some(existing) = state
            .registry_models
            .iter_mut()
            .find(|existing| existing.model_id == record.model_id)
        {
            if matches!(existing.status.as_str(), "failed" | "cancelled") {
                existing.status = record.status.clone();
                existing.residency = record.residency.clone();
            }
            if existing.source_uri.is_none() {
                existing.source_uri = record.source_uri.clone();
            }
            if existing.backend_id.is_none() {
                existing.backend_id = record.backend_id.clone();
            }
            if existing.hardware_profile.is_none() {
                existing.hardware_profile = record.hardware_profile.clone();
            }
            if existing.job_id.is_none() {
                existing.job_id = record.job_id.clone();
            }
            if existing.bytes_transferred.is_none() {
                existing.bytes_transferred = record.bytes_transferred;
            }
            if existing.installed_at_ms == 0 {
                existing.installed_at_ms = record.installed_at_ms;
            }
            continue;
        }
        state.registry_models.push(record);
    }
}

fn rehydrate_installed_backends(
    state: &mut LocalEngineRegistryState,
    control_plane: &LocalEngineControlPlane,
    now_ms: u64,
) {
    for record in discover_installed_backends(control_plane, now_ms) {
        if let Some(existing) = state
            .managed_backends
            .iter_mut()
            .find(|existing| existing.backend_id == record.backend_id)
        {
            if matches!(existing.status.as_str(), "failed" | "cancelled" | "queued") {
                existing.status = record.status.clone();
                existing.health = record.health.clone();
            }
            if existing.source_uri.is_none() {
                existing.source_uri = record.source_uri.clone();
            }
            if existing.alias.is_none() {
                existing.alias = record.alias.clone();
            }
            if existing.hardware_profile.is_none() {
                existing.hardware_profile = record.hardware_profile.clone();
            }
            if existing.job_id.is_none() {
                existing.job_id = record.job_id.clone();
            }
            if existing.install_path.is_none() {
                existing.install_path = record.install_path.clone();
            }
            if existing.entrypoint.is_none() {
                existing.entrypoint = record.entrypoint.clone();
            }
            if existing.health_endpoint.is_none() {
                existing.health_endpoint = record.health_endpoint.clone();
            }
            continue;
        }
        state.managed_backends.push(record);
    }
}

fn discover_installed_models(
    control_plane: &LocalEngineControlPlane,
    now_ms: u64,
) -> Vec<LocalEngineModelRecord> {
    let Ok(models_root) = resolve_local_engine_path(&control_plane.storage.models_path) else {
        return Vec::new();
    };
    let Ok(entries) = fs::read_dir(models_root) else {
        return Vec::new();
    };

    entries
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path().join(LOCAL_ENGINE_MODEL_INSTALL_MANIFEST))
        .filter(|manifest_path| manifest_path.exists())
        .filter_map(|manifest_path| load_installed_model_manifest(&manifest_path).ok())
        .map(|manifest| LocalEngineModelRecord {
            model_id: manifest.model_id.clone(),
            status: "installed".to_string(),
            residency: "cold".to_string(),
            installed_at_ms: manifest.imported_at_ms.unwrap_or(now_ms),
            updated_at_ms: now_ms,
            source_uri: manifest.source_uri.clone(),
            backend_id: manifest.backend_id.clone(),
            hardware_profile: Some(if control_plane.memory.prefer_gpu {
                "gpu".to_string()
            } else {
                control_plane.memory.target_resource.clone()
            }),
            job_id: manifest.job_id.clone(),
            bytes_transferred: manifest.bytes_transferred,
        })
        .collect()
}

fn discover_installed_backends(
    control_plane: &LocalEngineControlPlane,
    now_ms: u64,
) -> Vec<LocalEngineBackendRecord> {
    let Ok(backends_root) = resolve_local_engine_path(&control_plane.storage.backends_path) else {
        return Vec::new();
    };
    let Ok(entries) = fs::read_dir(backends_root) else {
        return Vec::new();
    };

    entries
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path().join(LOCAL_ENGINE_BACKEND_INSTALL_MANIFEST))
        .filter(|manifest_path| manifest_path.exists())
        .filter_map(|manifest_path| load_installed_backend_manifest(&manifest_path).ok())
        .map(|manifest| {
            let observation =
                observe_supervised_backend(&manifest.backend_id, Some(&manifest), now_ms, true)
                    .unwrap_or_else(|_| BackendRuntimeObservation {
                        status: "installed".to_string(),
                        health: "unknown".to_string(),
                        pid: None,
                        alias: manifest.alias.clone(),
                        install_path: Some(manifest.install_root.clone()),
                        entrypoint: Some(manifest.entrypoint.clone()),
                        health_endpoint: manifest.health_url.clone(),
                        last_started_at_ms: None,
                        last_health_check_at_ms: None,
                    });
            LocalEngineBackendRecord {
                backend_id: manifest.backend_id.clone(),
                status: observation.status,
                health: observation.health,
                installed_at_ms: manifest.installed_at_ms.unwrap_or(now_ms),
                updated_at_ms: now_ms,
                source_uri: manifest.source_uri.clone(),
                alias: observation.alias.or(manifest.alias.clone()),
                hardware_profile: Some(if control_plane.memory.prefer_gpu {
                    "gpu".to_string()
                } else {
                    control_plane.memory.target_resource.clone()
                }),
                job_id: manifest.job_id.clone(),
                install_path: observation
                    .install_path
                    .or(Some(manifest.install_root.clone())),
                entrypoint: observation.entrypoint.or(Some(manifest.entrypoint.clone())),
                health_endpoint: observation.health_endpoint.or(manifest.health_url.clone()),
                pid: observation.pid,
                last_started_at_ms: observation.last_started_at_ms,
                last_health_check_at_ms: observation.last_health_check_at_ms,
            }
        })
        .collect()
}

fn reconcile_gallery_catalogs(
    existing: &[LocalEngineGalleryCatalogRecord],
    control_plane: &LocalEngineControlPlane,
    model_count: u32,
    backend_count: u32,
    now_ms: u64,
) -> Vec<LocalEngineGalleryCatalogRecord> {
    let mut existing_by_id = existing
        .iter()
        .cloned()
        .map(|record| (record.gallery_id.clone(), record))
        .collect::<BTreeMap<_, _>>();

    let mut catalogs = control_plane
        .galleries
        .iter()
        .map(|source| {
            let previous = existing_by_id.remove(&source.id);
            let entry_count = match source.id.as_str() {
                "kernel.models.primary" => model_count,
                "kernel.backends.primary" => backend_count,
                _ => previous
                    .as_ref()
                    .map(|record| record.entry_count)
                    .unwrap_or_default(),
            };
            let sync_status = if source.enabled {
                let source_status = normalize_text(&source.sync_status);
                if !source_status.is_empty() {
                    source_status
                } else {
                    previous
                        .as_ref()
                        .map(|record| record.sync_status.clone())
                        .filter(|status| !status.trim().is_empty())
                        .unwrap_or_else(|| "ready".to_string())
                }
            } else {
                "disabled".to_string()
            };

            LocalEngineGalleryCatalogRecord {
                gallery_id: source.id.clone(),
                kind: normalize_text(&source.kind),
                label: source.label.clone(),
                source_uri: source.uri.clone(),
                sync_status,
                compatibility_tier: source.compatibility_tier.clone(),
                enabled: source.enabled,
                entry_count,
                updated_at_ms: previous
                    .as_ref()
                    .map(|record| record.updated_at_ms)
                    .unwrap_or(now_ms),
                last_job_id: previous
                    .as_ref()
                    .and_then(|record| record.last_job_id.clone()),
                last_synced_at_ms: previous
                    .as_ref()
                    .and_then(|record| record.last_synced_at_ms),
                catalog_path: previous
                    .as_ref()
                    .and_then(|record| record.catalog_path.clone()),
                sample_entries: previous
                    .as_ref()
                    .map(|record| record.sample_entries.clone())
                    .unwrap_or_default(),
                last_error: previous
                    .as_ref()
                    .and_then(|record| record.last_error.clone()),
            }
        })
        .collect::<Vec<_>>();

    catalogs.sort_by(|left, right| {
        left.kind
            .cmp(&right.kind)
            .then_with(|| left.label.cmp(&right.label))
    });
    catalogs
}

fn lifecycle_status_for_receipt(
    receipt: &ModelLifecycleReceiptUpdate,
    subject_kind: &str,
    operation: &str,
) -> String {
    if !receipt.success {
        return "failed".to_string();
    }

    if receipt.tool_name == "model_registry__load"
        || receipt.tool_name == "model_registry__unload"
        || (subject_kind == "model" && matches!(operation, "load" | "unload"))
    {
        return "completed".to_string();
    }

    if subject_kind == "gallery" && matches!(operation, "sync" | "refresh") {
        return "queued".to_string();
    }

    "queued".to_string()
}

fn summary_for_receipt(
    job: &LocalEngineJobRecord,
    receipt: &ModelLifecycleReceiptUpdate,
    status: &str,
) -> String {
    if !receipt.success {
        return format!(
            "{} {} failed{}.",
            humanize_token(&job.operation),
            humanize_token(&job.subject_kind).to_ascii_lowercase(),
            receipt
                .error_class
                .as_ref()
                .map(|value| format!(" ({value})"))
                .unwrap_or_default()
        );
    }

    if status == "completed" {
        return completion_summary(job);
    }

    match normalize_subject_kind(&receipt.subject_kind).as_str() {
        "gallery" => {
            "Kernel accepted the gallery sync request and queued it inside the control plane."
                .to_string()
        }
        "backend" => {
            "Kernel accepted the backend lifecycle request and queued it for operator-visible execution."
                .to_string()
        }
        _ => {
            "Kernel accepted the model lifecycle request and queued it for the absorbed registry executor."
                .to_string()
        }
    }
}

fn completion_summary(job: &LocalEngineJobRecord) -> String {
    match job.subject_kind.as_str() {
        "gallery" => {
            "Gallery catalog synchronization completed and the local engine registry was refreshed."
                .to_string()
        }
        "backend" => match job.operation.as_str() {
            "install" => {
                "Backend runtime was installed and is now tracked by the kernel control plane."
                    .to_string()
            }
            "apply" => {
                "Backend policy was applied and persisted under kernel authority.".to_string()
            }
            "start" => {
                "Backend process is running and health state is now visible in the Runtime Deck."
                    .to_string()
            }
            "stop" => {
                "Backend process was stopped without leaving the kernel control plane.".to_string()
            }
            "health" | "health_check" | "probe" => {
                "Backend health signal was refreshed and published into the registry surface."
                    .to_string()
            }
            "delete" | "remove" => {
                "Backend runtime was removed from the managed registry.".to_string()
            }
            _ => "Backend registry state was updated under kernel control.".to_string(),
        },
        _ => match job.operation.as_str() {
            "load" => {
                "Model is resident and available for kernel-native local workloads.".to_string()
            }
            "unload" => {
                "Model was evicted from active residency but remains registered for future use."
                    .to_string()
            }
            "delete" | "remove" => "Model was removed from the kernel-owned registry.".to_string(),
            "apply" => "Model policy was applied without leaving the kernel boundary.".to_string(),
            _ => "Model registry state was updated under kernel control.".to_string(),
        },
    }
}

fn advance_executor_job(
    job: &mut LocalEngineJobRecord,
    state: &LocalEngineRegistryState,
    control_plane: Option<&LocalEngineControlPlane>,
    now_ms: u64,
) -> Option<ExecutorAdvanceOutcome> {
    let next_status = next_executor_status(job, now_ms)?;
    if is_model_install_job(job) {
        return Some(
            advance_model_install_job(job, control_plane, &next_status, now_ms).unwrap_or_else(
                |error| ExecutorAdvanceOutcome {
                    status: "failed".to_string(),
                    summary: Some(format!(
                        "{} model failed: {}",
                        humanize_token(&job.operation),
                        error
                    )),
                    hints: RegistryEffectHints::default(),
                },
            ),
        );
    }
    if job.subject_kind == "backend" {
        return Some(
            advance_backend_job(job, control_plane, &next_status, now_ms).unwrap_or_else(|error| {
                ExecutorAdvanceOutcome {
                    status: "failed".to_string(),
                    summary: Some(format!(
                        "{} backend failed: {}",
                        humanize_token(&job.operation),
                        error
                    )),
                    hints: RegistryEffectHints::default(),
                }
            }),
        );
    }
    if job.subject_kind == "gallery" {
        return Some(
            advance_gallery_job(job, state, control_plane, &next_status, now_ms).unwrap_or_else(
                |error| ExecutorAdvanceOutcome {
                    status: "failed".to_string(),
                    summary: Some(format!(
                        "{} gallery sync failed: {}",
                        humanize_token(&job.operation),
                        error
                    )),
                    hints: RegistryEffectHints::default(),
                },
            ),
        );
    }

    Some(ExecutorAdvanceOutcome {
        status: next_status,
        summary: None,
        hints: RegistryEffectHints::default(),
    })
}

fn advance_model_install_job(
    job: &mut LocalEngineJobRecord,
    control_plane: Option<&LocalEngineControlPlane>,
    next_status: &str,
    now_ms: u64,
) -> Result<ExecutorAdvanceOutcome, String> {
    let context = resolve_model_install_context(job, control_plane)?;
    if job.subject_id.as_deref() != Some(context.model_id.as_str()) {
        job.subject_id = Some(context.model_id.clone());
        job.title = stage_operation_title("model", &job.operation, job.subject_id.as_deref());
    }

    match next_status {
        "running" => Ok(ExecutorAdvanceOutcome {
            status: next_status.to_string(),
            summary: Some(format!(
                "{} model source {} and staged import into {}.",
                if context.source_is_remote {
                    "Validated remote"
                } else {
                    "Validated local"
                },
                context.source_uri,
                context.install_root.display()
            )),
            hints: RegistryEffectHints::default(),
        }),
        "applying" => {
            let materialization = match materialize_model_install(&context, job, now_ms) {
                Ok(materialization) => materialization,
                Err(error) => {
                    let _ = write_model_install_receipt(
                        &context,
                        job,
                        now_ms,
                        "failed",
                        None,
                        None,
                        Some(&error),
                    );
                    return Err(error);
                }
            };
            let _ = write_model_install_receipt(
                &context,
                job,
                now_ms,
                "materialized",
                Some(materialization.bytes_transferred),
                Some(&materialization.payload_path),
                None,
            );
            Ok(ExecutorAdvanceOutcome {
                status: next_status.to_string(),
                summary: Some(format!(
                    "Imported local model artifact into {} ({} bytes).",
                    materialization.payload_path.display(),
                    materialization.bytes_transferred
                )),
                hints: RegistryEffectHints {
                    bytes_transferred: Some(materialization.bytes_transferred),
                    hardware_profile: None,
                    ..RegistryEffectHints::default()
                },
            })
        }
        "completed" => {
            let materialization = match verify_model_install(&context) {
                Ok(materialization) => materialization,
                Err(error) => {
                    let _ = write_model_install_receipt(
                        &context,
                        job,
                        now_ms,
                        "failed",
                        None,
                        None,
                        Some(&error),
                    );
                    return Err(error);
                }
            };
            let _ = write_model_install_receipt(
                &context,
                job,
                now_ms,
                "completed",
                Some(materialization.bytes_transferred),
                Some(&materialization.payload_path),
                None,
            );
            Ok(ExecutorAdvanceOutcome {
                status: next_status.to_string(),
                summary: Some(format!(
                    "Model {} is installed at {} and recorded in the kernel-owned registry.",
                    context.model_id,
                    context.install_root.display()
                )),
                hints: RegistryEffectHints {
                    bytes_transferred: Some(materialization.bytes_transferred),
                    hardware_profile: None,
                    ..RegistryEffectHints::default()
                },
            })
        }
        _ => Ok(ExecutorAdvanceOutcome {
            status: next_status.to_string(),
            summary: None,
            hints: RegistryEffectHints::default(),
        }),
    }
}

fn is_model_install_job(job: &LocalEngineJobRecord) -> bool {
    job.subject_kind == "model"
        && matches!(job.operation.as_str(), "install" | "import" | "register")
}

fn resolve_model_install_context(
    job: &LocalEngineJobRecord,
    control_plane: Option<&LocalEngineControlPlane>,
) -> Result<ModelInstallContext, String> {
    let source_uri = job
        .source_uri
        .clone()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| "model install requires a source URI or local path".to_string())?;
    let control_plane =
        control_plane.ok_or_else(|| "local engine control plane is unavailable".to_string())?;
    let models_root = resolve_local_engine_path(&control_plane.storage.models_path)?;
    let cache_root = resolve_local_engine_path(&control_plane.storage.cache_path)?;
    let (source_path, source_is_remote, inferred_source_id) =
        resolve_model_install_source(&source_uri, &cache_root)?;
    let model_id = normalize_model_identifier(
        job.subject_id
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or(inferred_source_id.as_str()),
    );
    let install_root = models_root.join(&model_id);
    let receipt_path = model_install_receipt_path(control_plane, &job.job_id);
    Ok(ModelInstallContext {
        model_id,
        source_uri,
        source_path,
        source_is_remote,
        models_root,
        install_root,
        receipt_path,
    })
}

fn resolve_model_install_source(
    source_uri: &str,
    cache_root: &Path,
) -> Result<(PathBuf, bool, String), String> {
    if source_uri.contains("://") {
        let parsed = Url::parse(source_uri)
            .map_err(|error| format!("invalid source URI '{}': {}", source_uri, error))?;
        return match parsed.scheme() {
            "file" => {
                let source_path = parsed.to_file_path().map_err(|_| {
                    format!(
                        "file URI '{}' could not be resolved into a local filesystem path",
                        source_uri
                    )
                })?;
                if !source_path.exists() {
                    return Err(format!(
                        "local model source does not exist: {}",
                        source_path.display()
                    ));
                }
                Ok((
                    source_path.clone(),
                    false,
                    infer_model_identifier_from_path(&source_path).to_string(),
                ))
            }
            "http" | "https" => {
                let file_name = parsed
                    .path_segments()
                    .and_then(|segments| segments.filter(|segment| !segment.is_empty()).last())
                    .filter(|segment| !segment.trim().is_empty())
                    .unwrap_or("model.bin");
                let inferred_model_id = infer_model_identifier_from_source_uri(source_uri);
                Ok((
                    cache_root
                        .join(LOCAL_ENGINE_MODEL_DOWNLOADS_DIR)
                        .join(&inferred_model_id)
                        .join(file_name),
                    true,
                    inferred_model_id,
                ))
            }
            unsupported => Err(format!(
                "remote source scheme '{}' is not yet supported by the absorbed model installer",
                unsupported
            )),
        };
    }

    let source_path = resolve_local_engine_path(source_uri)?;
    if !source_path.exists() {
        return Err(format!(
            "local model source does not exist: {}",
            source_path.display()
        ));
    }
    Ok((
        source_path.clone(),
        false,
        infer_model_identifier_from_path(&source_path).to_string(),
    ))
}

fn resolve_local_engine_path(raw: &str) -> Result<PathBuf, String> {
    let path = expand_home_path(raw);
    if path.as_os_str().is_empty() {
        return Err("path is empty".to_string());
    }
    if path.is_absolute() {
        Ok(path)
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(path))
            .map_err(|error| format!("failed to resolve relative path: {}", error))
    }
}

fn expand_home_path(raw: &str) -> PathBuf {
    if raw == "~" {
        return home_dir();
    }
    if let Some(stripped) = raw.strip_prefix("~/") {
        return home_dir().join(stripped);
    }
    PathBuf::from(raw)
}

fn home_dir() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

fn resolve_local_source_path(source_uri: &str) -> Result<PathBuf, String> {
    if source_uri.contains("://") {
        let parsed = Url::parse(source_uri)
            .map_err(|error| format!("invalid source URI '{}': {}", source_uri, error))?;
        return match parsed.scheme() {
            "file" => parsed.to_file_path().map_err(|_| {
                format!(
                    "file URI '{}' could not be resolved into a local filesystem path",
                    source_uri
                )
            }),
            unsupported => Err(format!(
                "remote source scheme '{}' is not yet supported by the absorbed model installer",
                unsupported
            )),
        };
    }

    resolve_local_engine_path(source_uri)
}

fn infer_model_identifier_from_path(source_path: &Path) -> &str {
    source_path
        .file_stem()
        .and_then(|value| value.to_str())
        .or_else(|| source_path.file_name().and_then(|value| value.to_str()))
        .unwrap_or("model")
}

fn infer_model_identifier_from_source_uri(source_uri: &str) -> String {
    if let Ok(parsed) = Url::parse(source_uri) {
        if let Some(segment) = parsed
            .path_segments()
            .and_then(|segments| segments.filter(|segment| !segment.is_empty()).last())
        {
            return normalize_model_identifier(
                segment
                    .split('@')
                    .next()
                    .unwrap_or(segment)
                    .trim_end_matches(".json")
                    .trim_end_matches(".yaml"),
            );
        }
    }
    normalize_model_identifier(source_uri)
}

fn normalize_model_identifier(value: &str) -> String {
    let mut normalized = String::new();
    let mut previous_was_separator = false;
    for ch in value.trim().chars() {
        let candidate = if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-') {
            previous_was_separator = false;
            ch.to_ascii_lowercase()
        } else {
            if previous_was_separator {
                continue;
            }
            previous_was_separator = true;
            '-'
        };
        normalized.push(candidate);
    }
    let normalized = normalized
        .trim_matches(|ch| matches!(ch, '-' | '_' | '.'))
        .to_string();
    if normalized.is_empty() {
        "model".to_string()
    } else {
        normalized
    }
}

fn model_install_receipt_path(
    control_plane: &LocalEngineControlPlane,
    job_id: &str,
) -> Option<PathBuf> {
    if !control_plane.responses.persist_artifacts {
        return None;
    }
    let artifacts_root = resolve_local_engine_path(&control_plane.storage.artifacts_path).ok()?;
    Some(
        artifacts_root
            .join(LOCAL_ENGINE_MODEL_INSTALL_RECEIPTS_DIR)
            .join(format!("{}.json", normalize_model_identifier(job_id))),
    )
}

fn materialize_model_install(
    context: &ModelInstallContext,
    job: &LocalEngineJobRecord,
    now_ms: u64,
) -> Result<ModelInstallMaterialization, String> {
    fs::create_dir_all(&context.models_root)
        .map_err(|error| format!("failed to create models root: {}", error))?;
    fs::create_dir_all(&context.install_root)
        .map_err(|error| format!("failed to create model install root: {}", error))?;

    let source_path = if context.source_is_remote {
        download_remote_model_source(context)?
    } else {
        context.source_path.clone()
    };

    let payload_path = if source_path.is_file() {
        let Some(file_name) = source_path.file_name() else {
            return Err("local model source file is missing a file name".to_string());
        };
        context.install_root.join(file_name)
    } else if source_path.is_dir() {
        context.install_root.clone()
    } else {
        return Err(format!(
            "unsupported model source type at {}",
            source_path.display()
        ));
    };

    guard_against_recursive_install(&source_path, &context.install_root)?;

    let bytes_transferred = if paths_equivalent(&source_path, &payload_path)
        || paths_equivalent(&source_path, &context.install_root)
    {
        measure_path_bytes(&source_path)?
    } else if source_path.is_file() {
        copy_file_with_parent(&source_path, &payload_path)?
    } else {
        copy_directory_contents(&source_path, &context.install_root)?
    };

    write_model_install_manifest(context, job, now_ms, &payload_path, bytes_transferred)?;

    Ok(ModelInstallMaterialization {
        payload_path,
        bytes_transferred,
    })
}

fn download_remote_model_source(context: &ModelInstallContext) -> Result<PathBuf, String> {
    if let Some(parent) = context.source_path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("failed to create model download directory: {}", error))?;
    }
    let response = reqwest::blocking::Client::new()
        .get(&context.source_uri)
        .send()
        .map_err(|error| format!("failed to download remote model source: {}", error))?
        .error_for_status()
        .map_err(|error| format!("remote model source responded with an error: {}", error))?;
    let bytes = response
        .bytes()
        .map_err(|error| format!("failed to read remote model payload: {}", error))?;
    fs::write(&context.source_path, &bytes).map_err(|error| {
        format!(
            "failed to write downloaded model source {}: {}",
            context.source_path.display(),
            error
        )
    })?;
    Ok(context.source_path.clone())
}

fn verify_model_install(
    context: &ModelInstallContext,
) -> Result<ModelInstallMaterialization, String> {
    let manifest_path = context
        .install_root
        .join(LOCAL_ENGINE_MODEL_INSTALL_MANIFEST);
    let manifest = load_installed_model_manifest(&manifest_path)?;
    let payload_path = {
        let candidate = PathBuf::from(&manifest.payload_path);
        if candidate.exists() {
            candidate
        } else {
            context.install_root.clone()
        }
    };
    let bytes_transferred = manifest
        .bytes_transferred
        .unwrap_or_else(|| measure_path_bytes(&payload_path).unwrap_or_default());
    Ok(ModelInstallMaterialization {
        payload_path,
        bytes_transferred,
    })
}

fn guard_against_recursive_install(source_path: &Path, install_root: &Path) -> Result<(), String> {
    let source_canonical = source_path
        .canonicalize()
        .map_err(|error| format!("failed to canonicalize local source: {}", error))?;
    let install_absolute = absolute_path(install_root)?;
    if source_canonical.is_dir() && install_absolute.starts_with(&source_canonical) {
        if install_absolute == source_canonical {
            return Ok(());
        }
        return Err(format!(
            "install destination {} cannot be nested inside source directory {}",
            install_absolute.display(),
            source_canonical.display()
        ));
    }
    Ok(())
}

fn absolute_path(path: &Path) -> Result<PathBuf, String> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(path))
            .map_err(|error| format!("failed to resolve absolute path: {}", error))
    }
}

fn paths_equivalent(left: &Path, right: &Path) -> bool {
    match (left.canonicalize(), right.canonicalize()) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}

fn measure_path_bytes(path: &Path) -> Result<u64, String> {
    let metadata = fs::metadata(path)
        .map_err(|error| format!("failed to read metadata for {}: {}", path.display(), error))?;
    if metadata.is_file() {
        return Ok(metadata.len());
    }
    if metadata.is_dir() {
        let mut total = 0u64;
        let entries = fs::read_dir(path)
            .map_err(|error| format!("failed to read directory {}: {}", path.display(), error))?;
        for entry in entries {
            let entry = entry.map_err(|error| {
                format!(
                    "failed to enumerate directory {}: {}",
                    path.display(),
                    error
                )
            })?;
            total = total.saturating_add(measure_path_bytes(&entry.path())?);
        }
        return Ok(total);
    }
    Err(format!(
        "unsupported filesystem entry while measuring {}",
        path.display()
    ))
}

fn copy_file_with_parent(source: &Path, destination: &Path) -> Result<u64, String> {
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent).map_err(|error| {
            format!(
                "failed to create install directory {}: {}",
                parent.display(),
                error
            )
        })?;
    }
    fs::copy(source, destination).map_err(|error| {
        format!(
            "failed to copy {} into {}: {}",
            source.display(),
            destination.display(),
            error
        )
    })
}

fn copy_directory_contents(source_dir: &Path, destination_dir: &Path) -> Result<u64, String> {
    let mut total = 0u64;
    let entries = fs::read_dir(source_dir).map_err(|error| {
        format!(
            "failed to read local source directory {}: {}",
            source_dir.display(),
            error
        )
    })?;
    for entry in entries {
        let entry = entry.map_err(|error| {
            format!(
                "failed to enumerate local source directory {}: {}",
                source_dir.display(),
                error
            )
        })?;
        let source_path = entry.path();
        let destination_path = destination_dir.join(entry.file_name());
        total = total.saturating_add(copy_path_recursive(&source_path, &destination_path)?);
    }
    Ok(total)
}

fn copy_path_recursive(source: &Path, destination: &Path) -> Result<u64, String> {
    let metadata = fs::metadata(source).map_err(|error| {
        format!(
            "failed to read metadata for {}: {}",
            source.display(),
            error
        )
    })?;
    if metadata.is_file() {
        return copy_file_with_parent(source, destination);
    }
    if metadata.is_dir() {
        fs::create_dir_all(destination).map_err(|error| {
            format!(
                "failed to create install directory {}: {}",
                destination.display(),
                error
            )
        })?;
        let mut total = 0u64;
        let entries = fs::read_dir(source).map_err(|error| {
            format!(
                "failed to read source directory {}: {}",
                source.display(),
                error
            )
        })?;
        for entry in entries {
            let entry = entry.map_err(|error| {
                format!(
                    "failed to enumerate source directory {}: {}",
                    source.display(),
                    error
                )
            })?;
            total = total.saturating_add(copy_path_recursive(
                &entry.path(),
                &destination.join(entry.file_name()),
            )?);
        }
        return Ok(total);
    }
    Err(format!(
        "unsupported filesystem entry while copying {}",
        source.display()
    ))
}

fn write_model_install_manifest(
    context: &ModelInstallContext,
    job: &LocalEngineJobRecord,
    now_ms: u64,
    payload_path: &Path,
    bytes_transferred: u64,
) -> Result<(), String> {
    let manifest_path = context
        .install_root
        .join(LOCAL_ENGINE_MODEL_INSTALL_MANIFEST);
    let manifest = json!({
        "modelId": context.model_id,
        "jobId": job.job_id,
        "operation": job.operation,
        "sourceUri": context.source_uri,
        "backendId": job.backend_id,
        "sourcePath": context.source_path.display().to_string(),
        "payloadPath": payload_path.display().to_string(),
        "installRoot": context.install_root.display().to_string(),
        "bytesTransferred": bytes_transferred,
        "importedAtMs": now_ms,
        "receiptPath": context
            .receipt_path
            .as_ref()
            .map(|path| path.display().to_string()),
    });
    write_json_file(&manifest_path, &manifest)
}

fn load_installed_model_manifest(path: &Path) -> Result<InstalledModelManifest, String> {
    let raw = fs::read(path).map_err(|error| {
        format!(
            "failed to read installed model manifest {}: {}",
            path.display(),
            error
        )
    })?;
    serde_json::from_slice(&raw).map_err(|error| {
        format!(
            "failed to parse installed model manifest {}: {}",
            path.display(),
            error
        )
    })
}

fn write_model_install_receipt(
    context: &ModelInstallContext,
    job: &LocalEngineJobRecord,
    now_ms: u64,
    stage: &str,
    bytes_transferred: Option<u64>,
    payload_path: Option<&Path>,
    error: Option<&str>,
) -> Result<(), String> {
    let Some(receipt_path) = context.receipt_path.as_ref() else {
        return Ok(());
    };
    let receipt = json!({
        "family": "model_lifecycle",
        "subjectKind": "model",
        "operation": job.operation,
        "stage": stage,
        "status": if error.is_some() { "failed" } else { stage },
        "success": error.is_none(),
        "jobId": job.job_id,
        "modelId": context.model_id,
        "sourceUri": context.source_uri,
        "sourcePath": context.source_path.display().to_string(),
        "installRoot": context.install_root.display().to_string(),
        "payloadPath": payload_path.map(|path| path.display().to_string()),
        "bytesTransferred": bytes_transferred,
        "timestampMs": now_ms,
        "kernelAuthority": true,
        "error": error,
    });
    write_json_file(receipt_path, &receipt)
}

fn write_json_file(path: &Path, value: &serde_json::Value) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| {
            format!(
                "failed to create artifact directory {}: {}",
                parent.display(),
                error
            )
        })?;
    }
    let payload = serde_json::to_vec_pretty(value)
        .map_err(|error| format!("failed to serialize JSON payload: {}", error))?;
    fs::write(path, payload)
        .map_err(|error| format!("failed to write {}: {}", path.display(), error))
}

fn advance_backend_job(
    job: &mut LocalEngineJobRecord,
    control_plane: Option<&LocalEngineControlPlane>,
    next_status: &str,
    now_ms: u64,
) -> Result<ExecutorAdvanceOutcome, String> {
    let context = resolve_backend_context(job, control_plane)?;
    if job.backend_id.as_deref() != Some(context.backend_id.as_str()) {
        job.backend_id = Some(context.backend_id.clone());
    }
    if job.subject_id.as_deref() != Some(context.backend_id.as_str()) {
        job.subject_id = Some(context.backend_id.clone());
        job.title = stage_operation_title("backend", &job.operation, job.subject_id.as_deref());
    }

    match job.operation.as_str() {
        "install" | "import" | "register" => {
            advance_backend_install_job(job, &context, next_status, now_ms)
        }
        "start" | "load" => advance_backend_start_job(job, &context, next_status, now_ms),
        "stop" | "unload" => advance_backend_stop_job(job, &context, next_status, now_ms),
        "health" | "health_check" | "probe" => {
            advance_backend_health_job(job, &context, next_status, now_ms)
        }
        _ => Ok(ExecutorAdvanceOutcome {
            status: next_status.to_string(),
            summary: None,
            hints: RegistryEffectHints::default(),
        }),
    }
}

fn advance_backend_install_job(
    job: &LocalEngineJobRecord,
    context: &BackendContext,
    next_status: &str,
    now_ms: u64,
) -> Result<ExecutorAdvanceOutcome, String> {
    match next_status {
        "running" => {
            let (summary, alias, entrypoint, health_endpoint) = if context.source_is_container_image
            {
                (
                    format!(
                        "Validated container-backed backend source {} for kernel-managed installation.",
                        context.source_uri.as_deref().unwrap_or("container-image")
                    ),
                    Some(humanize_token(&context.backend_id)),
                    Some(LOCAL_ENGINE_BACKEND_CONTAINER_LAUNCHER.to_string()),
                    None,
                )
            } else if context.source_is_remote {
                (
                    format!(
                        "Validated remote backend source {} and queued artifact acquisition into the absorbed registry.",
                        context.source_uri.as_deref().unwrap_or("remote")
                    ),
                    Some(humanize_token(&context.backend_id)),
                    None,
                    None,
                )
            } else {
                let source_path = context
                    .source_path
                    .as_ref()
                    .ok_or_else(|| "backend install requires a local source path".to_string())?;
                if !source_path.exists() {
                    return Err(format!(
                        "local backend source does not exist: {}",
                        source_path.display()
                    ));
                }
                let package = inspect_backend_source(source_path)?;
                (
                    format!(
                        "Validated backend source {} with entrypoint {}.",
                        source_path.display(),
                        package
                            .entrypoint
                            .clone()
                            .unwrap_or_else(|| "unresolved".to_string())
                    ),
                    package.alias,
                    package.entrypoint,
                    package.health_url,
                )
            };
            Ok(ExecutorAdvanceOutcome {
                status: next_status.to_string(),
                summary: Some(summary),
                hints: RegistryEffectHints {
                    backend_alias: alias,
                    backend_entrypoint: entrypoint,
                    backend_health_endpoint: health_endpoint,
                    ..RegistryEffectHints::default()
                },
            })
        }
        "applying" => {
            let materialization = match materialize_backend_install(context, job, now_ms) {
                Ok(materialization) => materialization,
                Err(error) => {
                    let _ = write_backend_receipt(
                        context,
                        job,
                        now_ms,
                        "failed",
                        None,
                        None,
                        Some(&error),
                    );
                    return Err(error);
                }
            };
            let _ = write_backend_receipt(
                context,
                job,
                now_ms,
                "materialized",
                Some(materialization.bytes_transferred),
                Some(&materialization.entrypoint),
                None,
            );
            Ok(ExecutorAdvanceOutcome {
                status: next_status.to_string(),
                summary: Some(format!(
                    "Installed backend {} into {}.",
                    context.backend_id,
                    context.install_root.display()
                )),
                hints: RegistryEffectHints {
                    backend_status: Some("installing".to_string()),
                    backend_health: Some("unknown".to_string()),
                    backend_alias: materialization.alias,
                    backend_install_path: Some(context.install_root.display().to_string()),
                    backend_entrypoint: Some(materialization.entrypoint),
                    backend_health_endpoint: materialization.health_endpoint,
                    ..RegistryEffectHints {
                        bytes_transferred: Some(materialization.bytes_transferred),
                        ..RegistryEffectHints::default()
                    }
                },
            })
        }
        "completed" => {
            let manifest = match load_installed_backend_manifest(&context.manifest_path) {
                Ok(manifest) => manifest,
                Err(error) => {
                    let _ = write_backend_receipt(
                        context,
                        job,
                        now_ms,
                        "failed",
                        None,
                        None,
                        Some(&error),
                    );
                    return Err(error);
                }
            };
            let _ = write_backend_receipt(
                context,
                job,
                now_ms,
                "completed",
                manifest.bytes_transferred,
                Some(&manifest.entrypoint),
                None,
            );
            Ok(ExecutorAdvanceOutcome {
                status: next_status.to_string(),
                summary: Some(format!(
                    "Backend {} is installed and ready for supervised startup.",
                    context.backend_id
                )),
                hints: RegistryEffectHints {
                    backend_status: Some("installed".to_string()),
                    backend_health: Some("unknown".to_string()),
                    backend_alias: manifest.alias.clone(),
                    backend_install_path: Some(manifest.install_root.clone()),
                    backend_entrypoint: Some(manifest.entrypoint.clone()),
                    backend_health_endpoint: manifest.health_url.clone(),
                    ..RegistryEffectHints {
                        bytes_transferred: manifest.bytes_transferred,
                        ..RegistryEffectHints::default()
                    }
                },
            })
        }
        _ => Ok(ExecutorAdvanceOutcome {
            status: next_status.to_string(),
            summary: None,
            hints: RegistryEffectHints::default(),
        }),
    }
}

fn advance_backend_start_job(
    job: &LocalEngineJobRecord,
    context: &BackendContext,
    next_status: &str,
    now_ms: u64,
) -> Result<ExecutorAdvanceOutcome, String> {
    let manifest = load_installed_backend_manifest(&context.manifest_path)?;
    match next_status {
        "running" => Ok(ExecutorAdvanceOutcome {
            status: next_status.to_string(),
            summary: Some(format!(
                "Preparing supervised backend launch for {} via {}.",
                context.backend_id, manifest.entrypoint
            )),
            hints: RegistryEffectHints {
                backend_alias: manifest.alias.clone(),
                backend_install_path: Some(manifest.install_root.clone()),
                backend_entrypoint: Some(manifest.entrypoint.clone()),
                backend_health_endpoint: manifest.health_url.clone(),
                ..RegistryEffectHints::default()
            },
        }),
        "applying" => {
            let observation = start_supervised_backend(context, &manifest, now_ms)?;
            let _ = write_backend_receipt(
                context,
                job,
                now_ms,
                "started",
                manifest.bytes_transferred,
                Some(&manifest.entrypoint),
                None,
            );
            Ok(ExecutorAdvanceOutcome {
                status: next_status.to_string(),
                summary: Some(format!(
                    "Started backend {} under kernel supervision{}.",
                    context.backend_id,
                    observation
                        .pid
                        .map(|pid| format!(" (pid {})", pid))
                        .unwrap_or_default()
                )),
                hints: backend_hints_from_observation(&observation),
            })
        }
        "completed" => {
            let observation =
                observe_supervised_backend(&context.backend_id, Some(&manifest), now_ms, false)?;
            let _ = write_backend_receipt(
                context,
                job,
                now_ms,
                "completed",
                manifest.bytes_transferred,
                Some(&manifest.entrypoint),
                None,
            );
            Ok(ExecutorAdvanceOutcome {
                status: next_status.to_string(),
                summary: Some(format!(
                    "Backend {} is running with {} health.",
                    context.backend_id, observation.health
                )),
                hints: backend_hints_from_observation(&observation),
            })
        }
        _ => Ok(ExecutorAdvanceOutcome {
            status: next_status.to_string(),
            summary: None,
            hints: RegistryEffectHints::default(),
        }),
    }
}

fn advance_backend_stop_job(
    job: &LocalEngineJobRecord,
    context: &BackendContext,
    next_status: &str,
    now_ms: u64,
) -> Result<ExecutorAdvanceOutcome, String> {
    match next_status {
        "running" => Ok(ExecutorAdvanceOutcome {
            status: next_status.to_string(),
            summary: Some(format!(
                "Preparing to stop supervised backend {}.",
                context.backend_id
            )),
            hints: RegistryEffectHints::default(),
        }),
        "applying" => {
            let observation = stop_supervised_backend(context, now_ms)?;
            let _ = write_backend_receipt(context, job, now_ms, "stopping", None, None, None);
            Ok(ExecutorAdvanceOutcome {
                status: next_status.to_string(),
                summary: Some(format!(
                    "Sent stop signal to backend {}.",
                    context.backend_id
                )),
                hints: backend_hints_from_observation(&observation),
            })
        }
        "completed" => {
            let manifest = load_installed_backend_manifest(&context.manifest_path).ok();
            let mut observation =
                observe_supervised_backend(&context.backend_id, manifest.as_ref(), now_ms, true)
                    .unwrap_or_else(|_| BackendRuntimeObservation {
                        status: "stopped".to_string(),
                        health: "stopped".to_string(),
                        install_path: Some(context.install_root.display().to_string()),
                        entrypoint: manifest.as_ref().map(|value| value.entrypoint.clone()),
                        health_endpoint: manifest
                            .as_ref()
                            .and_then(|value| value.health_url.clone()),
                        last_health_check_at_ms: Some(now_ms),
                        ..BackendRuntimeObservation::default()
                    });
            if observation.status == "installed" {
                observation.status = "stopped".to_string();
                observation.health = "stopped".to_string();
                observation.last_health_check_at_ms = Some(now_ms);
            }
            let _ = write_backend_receipt(context, job, now_ms, "completed", None, None, None);
            Ok(ExecutorAdvanceOutcome {
                status: next_status.to_string(),
                summary: Some(
                    if observation.status == "running" && observation.pid.is_none() {
                        format!(
                        "Backend {} is externally managed and remains running outside kernel supervision.",
                        context.backend_id
                    )
                    } else {
                        format!("Backend {} is no longer running.", context.backend_id)
                    },
                ),
                hints: backend_hints_from_observation(&observation),
            })
        }
        _ => Ok(ExecutorAdvanceOutcome {
            status: next_status.to_string(),
            summary: None,
            hints: RegistryEffectHints::default(),
        }),
    }
}

fn advance_backend_health_job(
    job: &LocalEngineJobRecord,
    context: &BackendContext,
    next_status: &str,
    now_ms: u64,
) -> Result<ExecutorAdvanceOutcome, String> {
    let manifest = load_installed_backend_manifest(&context.manifest_path)?;
    match next_status {
        "running" => Ok(ExecutorAdvanceOutcome {
            status: next_status.to_string(),
            summary: Some(format!(
                "Running a kernel-owned health probe for backend {}.",
                context.backend_id
            )),
            hints: RegistryEffectHints::default(),
        }),
        "completed" => {
            let observation =
                observe_supervised_backend(&context.backend_id, Some(&manifest), now_ms, true)?;
            let _ = write_backend_receipt(
                context,
                job,
                now_ms,
                "health-checked",
                manifest.bytes_transferred,
                Some(&manifest.entrypoint),
                None,
            );
            Ok(ExecutorAdvanceOutcome {
                status: next_status.to_string(),
                summary: Some(format!(
                    "Backend {} health is {}.",
                    context.backend_id, observation.health
                )),
                hints: backend_hints_from_observation(&observation),
            })
        }
        _ => Ok(ExecutorAdvanceOutcome {
            status: next_status.to_string(),
            summary: None,
            hints: RegistryEffectHints::default(),
        }),
    }
}

fn advance_gallery_job(
    job: &mut LocalEngineJobRecord,
    state: &LocalEngineRegistryState,
    control_plane: Option<&LocalEngineControlPlane>,
    next_status: &str,
    now_ms: u64,
) -> Result<ExecutorAdvanceOutcome, String> {
    let context = resolve_gallery_context(job, state, control_plane)?;
    if context.targets.len() == 1 {
        let target = &context.targets[0];
        if job.subject_id.as_deref() != Some(target.gallery_id.as_str()) {
            job.subject_id = Some(target.gallery_id.clone());
            job.title = stage_operation_title("gallery", &job.operation, job.subject_id.as_deref());
        }
    }

    match next_status {
        "syncing" => {
            let materialization =
                match sync_gallery_targets(state, &context, control_plane, now_ms, false) {
                    Ok(materialization) => materialization,
                    Err(error) => {
                        let _ = write_gallery_receipt(
                            &context,
                            job,
                            now_ms,
                            "failed",
                            &[],
                            Some(&error),
                        );
                        return Err(error);
                    }
                };
            let _ = write_gallery_receipt(
                &context,
                job,
                now_ms,
                "validated",
                &materialization.records,
                None,
            );
            Ok(ExecutorAdvanceOutcome {
                status: next_status.to_string(),
                summary: Some(format!(
                    "Validated {} gallery source{} and prepared {} catalog entr{} for reconciliation.",
                    context.targets.len(),
                    if context.targets.len() == 1 { "" } else { "s" },
                    materialization.total_entries,
                    if materialization.total_entries == 1 { "y" } else { "ies" }
                )),
                hints: RegistryEffectHints {
                    gallery_records: materialization.records,
                    ..RegistryEffectHints::default()
                },
            })
        }
        "completed" => {
            let materialization =
                match sync_gallery_targets(state, &context, control_plane, now_ms, true) {
                    Ok(materialization) => materialization,
                    Err(error) => {
                        let _ = write_gallery_receipt(
                            &context,
                            job,
                            now_ms,
                            "failed",
                            &[],
                            Some(&error),
                        );
                        return Err(error);
                    }
                };
            let _ = write_gallery_receipt(
                &context,
                job,
                now_ms,
                "completed",
                &materialization.records,
                None,
            );
            Ok(ExecutorAdvanceOutcome {
                status: next_status.to_string(),
                summary: Some(format!(
                    "Synchronized {} gallery catalog{} with {} normalized entr{}.",
                    materialization.records.len(),
                    if materialization.records.len() == 1 {
                        ""
                    } else {
                        "s"
                    },
                    materialization.total_entries,
                    if materialization.total_entries == 1 {
                        "y"
                    } else {
                        "ies"
                    }
                )),
                hints: RegistryEffectHints {
                    gallery_records: materialization.records,
                    ..RegistryEffectHints::default()
                },
            })
        }
        _ => Ok(ExecutorAdvanceOutcome {
            status: next_status.to_string(),
            summary: None,
            hints: RegistryEffectHints::default(),
        }),
    }
}

fn resolve_gallery_context(
    job: &LocalEngineJobRecord,
    state: &LocalEngineRegistryState,
    control_plane: Option<&LocalEngineControlPlane>,
) -> Result<GallerySyncContext, String> {
    let target_ids = resolve_gallery_targets(state, control_plane, job);
    if target_ids.is_empty() {
        return Err("no gallery targets were resolved for the requested sync".to_string());
    }

    let cache_root = if let Some(control_plane) = control_plane {
        resolve_local_engine_path(&control_plane.storage.cache_path)?
    } else {
        home_dir().join(".ioi").join("local-engine").join("cache")
    }
    .join(LOCAL_ENGINE_GALLERY_CATALOGS_DIR);

    let targets = target_ids
        .into_iter()
        .map(|target_id| {
            let source = control_plane
                .and_then(|plane| plane.galleries.iter().find(|entry| entry.id == target_id));
            let previous = state
                .gallery_catalogs
                .iter()
                .find(|record| record.gallery_id == target_id);
            let source_uri = source
                .map(|entry| entry.uri.clone())
                .or_else(|| previous.map(|record| record.source_uri.clone()))
                .or_else(|| job.source_uri.clone())
                .unwrap_or_else(|| target_id.clone());
            Ok(GallerySyncTarget {
                gallery_id: target_id.clone(),
                kind: source
                    .map(|entry| normalize_text(&entry.kind))
                    .or_else(|| previous.map(|record| record.kind.clone()))
                    .unwrap_or_else(|| infer_gallery_kind(&target_id, Some(source_uri.as_str()))),
                label: source
                    .map(|entry| entry.label.clone())
                    .or_else(|| previous.map(|record| record.label.clone()))
                    .unwrap_or_else(|| humanize_token(&target_id)),
                source_uri,
                compatibility_tier: source
                    .map(|entry| entry.compatibility_tier.clone())
                    .or_else(|| previous.map(|record| record.compatibility_tier.clone()))
                    .unwrap_or_else(|| infer_compatibility_tier(&target_id)),
                enabled: source
                    .map(|entry| entry.enabled)
                    .or_else(|| previous.map(|record| record.enabled))
                    .unwrap_or(true),
                catalog_path: cache_root
                    .join(format!("{}.json", normalize_gallery_identifier(&target_id))),
            })
        })
        .collect::<Result<Vec<_>, String>>()?;

    Ok(GallerySyncContext {
        targets,
        receipt_path: gallery_sync_receipt_path(control_plane, &job.job_id),
    })
}

fn gallery_sync_receipt_path(
    control_plane: Option<&LocalEngineControlPlane>,
    job_id: &str,
) -> Option<PathBuf> {
    let control_plane = control_plane?;
    if !control_plane.responses.persist_artifacts {
        return None;
    }
    let artifacts_root = resolve_local_engine_path(&control_plane.storage.artifacts_path).ok()?;
    Some(
        artifacts_root
            .join(LOCAL_ENGINE_GALLERY_SYNC_RECEIPTS_DIR)
            .join(format!("{}.json", normalize_gallery_identifier(job_id))),
    )
}

fn sync_gallery_targets(
    state: &LocalEngineRegistryState,
    context: &GallerySyncContext,
    control_plane: Option<&LocalEngineControlPlane>,
    now_ms: u64,
    persist_catalogs: bool,
) -> Result<GallerySyncMaterialization, String> {
    let mut records = Vec::new();
    let mut total_entries = 0u32;

    for target in &context.targets {
        let document = build_gallery_document(state, target, control_plane, now_ms)?;
        if persist_catalogs {
            let value = serde_json::to_value(&document)
                .map_err(|error| format!("failed to serialize gallery catalog: {}", error))?;
            write_json_file(&target.catalog_path, &value)?;
        }
        total_entries = total_entries.saturating_add(document.entry_count);
        records.push(LocalEngineGalleryCatalogRecord {
            gallery_id: target.gallery_id.clone(),
            kind: target.kind.clone(),
            label: target.label.clone(),
            source_uri: target.source_uri.clone(),
            sync_status: if persist_catalogs {
                "synced".to_string()
            } else {
                "syncing".to_string()
            },
            compatibility_tier: target.compatibility_tier.clone(),
            enabled: target.enabled,
            entry_count: document.entry_count,
            updated_at_ms: now_ms,
            last_job_id: None,
            last_synced_at_ms: persist_catalogs.then_some(now_ms),
            catalog_path: Some(target.catalog_path.display().to_string()),
            sample_entries: document
                .entries
                .iter()
                .take(LOCAL_ENGINE_GALLERY_SAMPLE_LIMIT)
                .map(|entry| LocalEngineGalleryEntryPreview {
                    entry_id: entry.entry_id.clone(),
                    label: entry.label.clone(),
                    summary: entry.summary.clone(),
                    source_uri: entry.source_uri.clone(),
                })
                .collect(),
            last_error: None,
        });
    }

    Ok(GallerySyncMaterialization {
        records,
        total_entries,
    })
}

fn build_gallery_document(
    state: &LocalEngineRegistryState,
    target: &GallerySyncTarget,
    control_plane: Option<&LocalEngineControlPlane>,
    now_ms: u64,
) -> Result<GalleryCatalogDocument, String> {
    let entries = if target.source_uri.starts_with("kernel://gallery/models") {
        kernel_model_gallery_entries(state)
    } else if target.source_uri.starts_with("kernel://gallery/backends") {
        kernel_backend_gallery_entries(state)
    } else if target.kind == "backend" {
        localai_backend_gallery_entries(&target.source_uri, control_plane)?
    } else {
        localai_model_gallery_entries(&target.source_uri)?
    };

    Ok(GalleryCatalogDocument {
        version: 1,
        gallery_id: target.gallery_id.clone(),
        kind: target.kind.clone(),
        label: target.label.clone(),
        source_uri: target.source_uri.clone(),
        compatibility_tier: target.compatibility_tier.clone(),
        synced_at_ms: now_ms,
        entry_count: entries.len() as u32,
        entries,
    })
}

fn kernel_model_gallery_entries(
    state: &LocalEngineRegistryState,
) -> Vec<GalleryCatalogDocumentEntry> {
    state
        .registry_models
        .iter()
        .map(|record| {
            let mut tags = vec![record.status.clone(), record.residency.clone()];
            if let Some(backend_id) = record.backend_id.clone() {
                tags.push(format!("backend:{}", backend_id));
            }
            GalleryCatalogDocumentEntry {
                entry_id: record.model_id.clone(),
                label: humanize_token(&record.model_id),
                summary: compact_summary(
                    record
                        .source_uri
                        .as_deref()
                        .map(|source| {
                            format!("{} model from {}", humanize_token(&record.status), source)
                        })
                        .unwrap_or_else(|| {
                            format!(
                                "{} model with {} residency.",
                                humanize_token(&record.status),
                                humanize_token(&record.residency).to_ascii_lowercase()
                            )
                        })
                        .as_str(),
                ),
                source_uri: record.source_uri.clone(),
                tags,
                backend_id: record.backend_id.clone(),
            }
        })
        .collect()
}

fn kernel_backend_gallery_entries(
    state: &LocalEngineRegistryState,
) -> Vec<GalleryCatalogDocumentEntry> {
    state
        .managed_backends
        .iter()
        .map(|record| GalleryCatalogDocumentEntry {
            entry_id: record.backend_id.clone(),
            label: record
                .alias
                .clone()
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| humanize_token(&record.backend_id)),
            summary: compact_summary(&format!(
                "{} backend with {} health{}",
                humanize_token(&record.status),
                humanize_token(&record.health).to_ascii_lowercase(),
                record
                    .entrypoint
                    .as_deref()
                    .map(|entrypoint| format!(" via {}", entrypoint))
                    .unwrap_or_default()
            )),
            source_uri: record.source_uri.clone(),
            tags: vec![record.status.clone(), record.health.clone()],
            backend_id: Some(record.backend_id.clone()),
        })
        .collect()
}

fn localai_model_gallery_entries(
    source_uri: &str,
) -> Result<Vec<GalleryCatalogDocumentEntry>, String> {
    let source_text = load_gallery_source_text(source_uri)?;
    let entries: Vec<LocalAiModelGalleryEntry> = serde_yaml::from_str(&source_text)
        .map_err(|error| format!("failed to parse model gallery YAML: {}", error))?;
    Ok(entries
        .into_iter()
        .map(|entry| {
            let summary_source = entry
                .overrides
                .description
                .clone()
                .or(entry.description.clone())
                .unwrap_or_else(|| {
                    let backend = entry
                        .overrides
                        .backend
                        .clone()
                        .unwrap_or_else(|| "unspecified backend".to_string());
                    let file_count = entry.files.len();
                    format!(
                        "{} backed model with {} file{}.",
                        backend,
                        file_count,
                        if file_count == 1 { "" } else { "s" }
                    )
                });
            let source_uri = entry
                .files
                .iter()
                .find_map(|file| file.uri.clone())
                .or_else(|| entry.urls.first().cloned())
                .or(entry.url.clone());
            let mut tags = entry.tags.clone();
            if let Some(backend) = entry.overrides.backend.clone() {
                tags.push(format!("backend:{}", backend));
            }
            tags.extend(
                entry
                    .overrides
                    .known_usecases
                    .iter()
                    .map(|usecase| format!("use:{}", usecase)),
            );
            GalleryCatalogDocumentEntry {
                entry_id: normalize_model_identifier(&entry.name),
                label: entry.name.clone(),
                summary: compact_summary(&summary_source),
                source_uri,
                tags,
                backend_id: entry.overrides.backend.clone(),
            }
        })
        .collect())
}

fn localai_backend_gallery_entries(
    source_uri: &str,
    control_plane: Option<&LocalEngineControlPlane>,
) -> Result<Vec<GalleryCatalogDocumentEntry>, String> {
    let source_text = load_gallery_source_text(source_uri)?;
    let entries: Vec<LocalAiBackendGalleryEntry> = serde_yaml::from_str(&source_text)
        .map_err(|error| format!("failed to parse backend gallery YAML: {}", error))?;
    let entries_by_name = entries
        .iter()
        .map(|entry| (entry.name.clone(), entry.clone()))
        .collect::<BTreeMap<_, _>>();
    let preferred_capabilities = preferred_backend_capability_keys(control_plane);
    Ok(entries
        .into_iter()
        .map(|entry| {
            let resolution = resolve_localai_backend_gallery_source(
                &entry,
                &entries_by_name,
                &preferred_capabilities,
            );
            let source_uri = resolution.as_ref().and_then(|item| item.source_uri.clone());
            let mut summary_source = entry.description.clone().unwrap_or_else(|| {
                if entry.capabilities.is_empty() {
                    "Managed backend package available for kernel supervision.".to_string()
                } else {
                    format!(
                        "{} capability target{} available.",
                        entry.capabilities.len(),
                        if entry.capabilities.len() == 1 {
                            ""
                        } else {
                            "s"
                        }
                    )
                }
            });
            if let Some(resolution) = resolution.as_ref().filter(|item| item.resolved_from_meta) {
                let capability = resolution
                    .selected_capability
                    .clone()
                    .unwrap_or_else(|| "default".to_string());
                summary_source = format!(
                    "{} Resolved to {} via the {} runtime capability.",
                    summary_source.trim(),
                    resolution.backend_name,
                    capability
                );
            }
            GalleryCatalogDocumentEntry {
                entry_id: normalize_gallery_identifier(&entry.name),
                label: entry
                    .alias
                    .clone()
                    .filter(|value| !value.trim().is_empty())
                    .unwrap_or_else(|| entry.name.clone()),
                summary: compact_summary(&summary_source),
                source_uri,
                tags: entry.tags.clone(),
                backend_id: Some(
                    resolution
                        .map(|item| item.backend_name)
                        .unwrap_or_else(|| entry.name.clone()),
                ),
            }
        })
        .collect())
}

fn resolve_localai_backend_gallery_source(
    entry: &LocalAiBackendGalleryEntry,
    entries_by_name: &BTreeMap<String, LocalAiBackendGalleryEntry>,
    preferred_capabilities: &[String],
) -> Option<ResolvedBackendGallerySource> {
    if let Some(source_uri) = backend_entry_source_uri(entry) {
        return Some(ResolvedBackendGallerySource {
            backend_name: entry.name.clone(),
            source_uri: Some(source_uri),
            selected_capability: None,
            resolved_from_meta: false,
        });
    }
    if entry.capabilities.is_empty() {
        return None;
    }

    let (selected_capability, resolved_name) = preferred_capabilities
        .iter()
        .find_map(|capability| {
            entry
                .capabilities
                .get(capability)
                .cloned()
                .map(|name| (capability.clone(), name))
        })
        .or_else(|| {
            entry
                .capabilities
                .get("default")
                .cloned()
                .map(|name| ("default".to_string(), name))
        })
        .or_else(|| {
            entry
                .capabilities
                .iter()
                .next()
                .map(|(capability, name)| (capability.clone(), name.clone()))
        })?;
    let resolved_source_uri = entries_by_name
        .get(&resolved_name)
        .and_then(backend_entry_source_uri);
    Some(ResolvedBackendGallerySource {
        backend_name: resolved_name,
        source_uri: resolved_source_uri,
        selected_capability: Some(selected_capability),
        resolved_from_meta: true,
    })
}

fn backend_entry_source_uri(entry: &LocalAiBackendGalleryEntry) -> Option<String> {
    entry.uri.clone().or_else(|| entry.mirrors.first().cloned())
}

fn preferred_backend_capability_keys(
    control_plane: Option<&LocalEngineControlPlane>,
) -> Vec<String> {
    let target_resource = control_plane
        .map(|plane| normalize_text(&plane.memory.target_resource))
        .unwrap_or_else(|| "auto".to_string());
    let mut keys = match target_resource.as_str() {
        value if value.is_empty() || value == "auto" => default_backend_capability_keys(),
        value if value.contains("metal") && value.contains("arm64") => {
            vec!["metal-darwin-arm64".to_string(), "metal".to_string()]
        }
        value if value.contains("metal") => vec!["metal".to_string()],
        value if value.contains("nvidia-l4t") && value.contains("13") => vec![
            "nvidia-l4t-cuda-13".to_string(),
            "nvidia-l4t".to_string(),
            "nvidia-cuda-13".to_string(),
            "nvidia".to_string(),
        ],
        value if value.contains("nvidia-l4t") => vec![
            "nvidia-l4t-cuda-12".to_string(),
            "nvidia-l4t".to_string(),
            "nvidia-cuda-12".to_string(),
            "nvidia".to_string(),
        ],
        value if value.contains("nvidia") && value.contains("13") => {
            vec!["nvidia-cuda-13".to_string(), "nvidia".to_string()]
        }
        value if value.contains("nvidia") || value.contains("cuda") => {
            vec!["nvidia-cuda-12".to_string(), "nvidia".to_string()]
        }
        value if value.contains("amd") || value.contains("rocm") => vec!["amd".to_string()],
        value if value.contains("intel") => vec!["intel".to_string()],
        value if value.contains("vulkan") => vec!["vulkan".to_string()],
        value if value.contains("cpu") => Vec::new(),
        value => vec![value.to_string()],
    };
    keys.push("default".to_string());
    dedupe_preserving_order(&keys)
}

fn default_backend_capability_keys() -> Vec<String> {
    let mut keys = Vec::new();
    if cfg!(target_os = "macos") && cfg!(target_arch = "aarch64") {
        keys.push("metal-darwin-arm64".to_string());
    }
    if cfg!(target_os = "macos") {
        keys.push("metal".to_string());
    }
    keys.push("default".to_string());
    dedupe_preserving_order(&keys)
}

fn dedupe_preserving_order(values: &[String]) -> Vec<String> {
    let mut ordered = Vec::new();
    for value in values {
        if !value.is_empty() && !ordered.contains(value) {
            ordered.push(value.clone());
        }
    }
    ordered
}

fn load_gallery_source_text(source_uri: &str) -> Result<String, String> {
    if source_uri.starts_with("kernel://gallery/") {
        return Err("kernel gallery sources are synthesized from registry state".to_string());
    }

    let resolved_path = if source_uri.starts_with("github:") {
        resolve_vendored_localai_source_path(source_uri)?
    } else {
        resolve_local_source_path(source_uri)?
    };

    fs::read_to_string(&resolved_path).map_err(|error| {
        format!(
            "failed to read gallery source {}: {}",
            resolved_path.display(),
            error
        )
    })
}

fn resolve_vendored_localai_source_path(source_uri: &str) -> Result<PathBuf, String> {
    let Some(stripped) = source_uri.strip_prefix("github:mudler/LocalAI/") else {
        return Err(format!(
            "remote gallery source '{}' is not yet supported without a vendored LocalAI mapping",
            source_uri
        ));
    };
    let relative = stripped
        .split('@')
        .next()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            format!(
                "gallery source '{}' is missing a repository path",
                source_uri
            )
        })?;
    let path = workspace_root()
        .join("examples")
        .join("LocalAI-master(1)")
        .join("LocalAI-master")
        .join(relative);
    if path.exists() {
        Ok(path)
    } else {
        Err(format!(
            "vendored LocalAI gallery source does not exist at {}",
            path.display()
        ))
    }
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .unwrap_or_else(|_| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../.."))
}

fn write_gallery_receipt(
    context: &GallerySyncContext,
    job: &LocalEngineJobRecord,
    now_ms: u64,
    stage: &str,
    records: &[LocalEngineGalleryCatalogRecord],
    error: Option<&str>,
) -> Result<(), String> {
    let Some(receipt_path) = context.receipt_path.as_ref() else {
        return Ok(());
    };
    let receipt = json!({
        "family": "model_lifecycle",
        "subjectKind": "gallery",
        "operation": job.operation,
        "stage": stage,
        "status": if error.is_some() { "failed" } else { stage },
        "success": error.is_none(),
        "jobId": job.job_id,
        "galleryIds": records.iter().map(|record| record.gallery_id.clone()).collect::<Vec<_>>(),
        "entryCount": records.iter().map(|record| record.entry_count).sum::<u32>(),
        "catalogPaths": records.iter().filter_map(|record| record.catalog_path.clone()).collect::<Vec<_>>(),
        "sourceUris": records.iter().map(|record| record.source_uri.clone()).collect::<Vec<_>>(),
        "timestampMs": now_ms,
        "kernelAuthority": true,
        "error": error,
    });
    write_json_file(receipt_path, &receipt)
}

fn resolve_backend_context(
    job: &LocalEngineJobRecord,
    control_plane: Option<&LocalEngineControlPlane>,
) -> Result<BackendContext, String> {
    let control_plane =
        control_plane.ok_or_else(|| "local engine control plane is unavailable".to_string())?;
    let backends_root = resolve_local_engine_path(&control_plane.storage.backends_path)?;
    let cache_root = resolve_local_engine_path(&control_plane.storage.cache_path)?;
    let source_uri = job
        .source_uri
        .clone()
        .filter(|value| !value.trim().is_empty());
    let (source_path, source_is_remote, source_is_container_image, inferred_source_id) =
        if let Some(source_uri) = source_uri.as_deref() {
            resolve_backend_install_source(source_uri, &cache_root)?
        } else {
            (None, false, false, "backend".to_string())
        };
    let backend_id = normalize_model_identifier(
        job.backend_id
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .or_else(|| {
                job.subject_id
                    .as_deref()
                    .filter(|value| !value.trim().is_empty())
            })
            .unwrap_or(inferred_source_id.as_str()),
    );
    let install_root = backends_root.join(&backend_id);
    Ok(BackendContext {
        backend_id,
        source_uri,
        source_path,
        source_is_remote,
        source_is_container_image,
        backends_root,
        install_root: install_root.clone(),
        manifest_path: install_root.join(LOCAL_ENGINE_BACKEND_INSTALL_MANIFEST),
        receipt_path: backend_install_receipt_path(control_plane, &job.job_id),
    })
}

fn resolve_backend_install_source(
    source_uri: &str,
    cache_root: &Path,
) -> Result<(Option<PathBuf>, bool, bool, String), String> {
    if source_uri.contains("://") {
        let parsed = Url::parse(source_uri)
            .map_err(|error| format!("invalid source URI '{}': {}", source_uri, error))?;
        return match parsed.scheme() {
            "file" => {
                let source_path = parsed.to_file_path().map_err(|_| {
                    format!(
                        "file URI '{}' could not be resolved into a local filesystem path",
                        source_uri
                    )
                })?;
                if !source_path.exists() {
                    return Err(format!(
                        "local backend source does not exist: {}",
                        source_path.display()
                    ));
                }
                Ok((
                    Some(source_path.clone()),
                    false,
                    false,
                    infer_model_identifier_from_path(&source_path).to_string(),
                ))
            }
            "http" | "https" => {
                let file_name = parsed
                    .path_segments()
                    .and_then(|segments| segments.filter(|segment| !segment.is_empty()).last())
                    .filter(|segment| !segment.trim().is_empty())
                    .unwrap_or("backend-package");
                let inferred_backend_id = infer_model_identifier_from_source_uri(source_uri);
                Ok((
                    Some(
                        cache_root
                            .join(LOCAL_ENGINE_BACKEND_DOWNLOADS_DIR)
                            .join(&inferred_backend_id)
                            .join(file_name),
                    ),
                    true,
                    false,
                    inferred_backend_id,
                ))
            }
            "docker" | "oci" => Ok((
                None,
                false,
                true,
                infer_model_identifier_from_source_uri(source_uri),
            )),
            unsupported => Err(format!(
                "remote source scheme '{}' is not yet supported by the absorbed backend installer",
                unsupported
            )),
        };
    }

    if looks_like_container_image_reference(source_uri) {
        return Ok((
            None,
            false,
            true,
            infer_model_identifier_from_source_uri(source_uri),
        ));
    }

    let source_path = resolve_local_engine_path(source_uri)?;
    if !source_path.exists() {
        return Err(format!(
            "local backend source does not exist: {}",
            source_path.display()
        ));
    }
    Ok((
        Some(source_path.clone()),
        false,
        false,
        infer_model_identifier_from_path(&source_path).to_string(),
    ))
}

fn looks_like_container_image_reference(source_uri: &str) -> bool {
    let trimmed = source_uri.trim();
    if trimmed.is_empty() || trimmed.starts_with('.') || trimmed.starts_with('/') {
        return false;
    }
    if trimmed.starts_with("~/")
        || trimmed.contains('\\')
        || trimmed.chars().any(char::is_whitespace)
    {
        return false;
    }
    let has_registry_path = trimmed.contains('/') && trimmed.rsplit('/').next().is_some();
    let has_tag = trimmed
        .rsplit('/')
        .next()
        .map(|segment| segment.contains(':'))
        .unwrap_or(false);
    has_registry_path && has_tag
}

fn backend_install_receipt_path(
    control_plane: &LocalEngineControlPlane,
    job_id: &str,
) -> Option<PathBuf> {
    if !control_plane.responses.persist_artifacts {
        return None;
    }
    let artifacts_root = resolve_local_engine_path(&control_plane.storage.artifacts_path).ok()?;
    Some(
        artifacts_root
            .join(LOCAL_ENGINE_BACKEND_INSTALL_RECEIPTS_DIR)
            .join(format!("{}.json", normalize_model_identifier(job_id))),
    )
}

fn materialize_backend_install(
    context: &BackendContext,
    job: &LocalEngineJobRecord,
    now_ms: u64,
) -> Result<BackendInstallMaterialization, String> {
    fs::create_dir_all(&context.backends_root)
        .map_err(|error| format!("failed to create backends root: {}", error))?;
    fs::create_dir_all(&context.install_root)
        .map_err(|error| format!("failed to create backend install root: {}", error))?;

    if context.source_is_container_image {
        return materialize_container_backed_backend_install(context, job, now_ms);
    }

    let source_path = if context.source_is_remote {
        download_remote_backend_source(context)?
    } else {
        context
            .source_path
            .clone()
            .ok_or_else(|| "backend install requires a source path".to_string())?
    };
    if !source_path.exists() {
        return Err(format!(
            "local backend source does not exist: {}",
            source_path.display()
        ));
    }
    guard_against_recursive_install(&source_path, &context.install_root)?;

    let bytes_transferred = if source_path.is_file() {
        let file_name = source_path
            .file_name()
            .ok_or_else(|| "backend source file is missing a file name".to_string())?;
        let destination = context.install_root.join(file_name);
        let copied = if paths_equivalent(&source_path, &destination) {
            measure_path_bytes(&source_path)?
        } else {
            copy_file_with_parent(&source_path, &destination)?
        };
        preserve_file_permissions(&source_path, &destination)?;
        copied
    } else if source_path.is_dir() {
        copy_directory_contents(&source_path, &context.install_root)?
    } else {
        return Err(format!(
            "unsupported backend source type at {}",
            source_path.display()
        ));
    };

    let package = inspect_backend_source(&source_path)?;
    let entrypoint = package
        .entrypoint
        .clone()
        .ok_or_else(|| "backend package did not resolve an entrypoint".to_string())?;
    let resolved_entrypoint = resolve_backend_entrypoint(&context.install_root, &entrypoint);
    let resolved_entrypoint_path = PathBuf::from(&resolved_entrypoint);
    if resolved_entrypoint_path.exists() {
        ensure_script_is_executable(&resolved_entrypoint_path)?;
    }
    let installed_manifest = json!({
        "backendId": context.backend_id,
        "entrypoint": resolved_entrypoint,
        "args": package.args,
        "env": package.env,
        "healthUrl": package.health_url,
        "alias": package.alias,
        "sourceUri": context.source_uri,
        "sourcePath": source_path.display().to_string(),
        "installRoot": context.install_root.display().to_string(),
        "bytesTransferred": bytes_transferred,
        "installedAtMs": now_ms,
        "jobId": job.job_id,
    });
    write_json_file(&context.manifest_path, &installed_manifest)?;

    let manifest = load_installed_backend_manifest(&context.manifest_path)?;
    Ok(BackendInstallMaterialization {
        entrypoint: manifest.entrypoint,
        alias: manifest.alias,
        health_endpoint: manifest.health_url,
        bytes_transferred,
    })
}

fn download_remote_backend_source(context: &BackendContext) -> Result<PathBuf, String> {
    let source_path = context
        .source_path
        .as_ref()
        .ok_or_else(|| "remote backend install requires a download target".to_string())?;
    if let Some(parent) = source_path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("failed to create backend download directory: {}", error))?;
    }
    let source_uri = context
        .source_uri
        .as_deref()
        .ok_or_else(|| "remote backend install requires a source URI".to_string())?;
    let response = reqwest::blocking::Client::new()
        .get(source_uri)
        .send()
        .map_err(|error| format!("failed to download remote backend source: {}", error))?
        .error_for_status()
        .map_err(|error| format!("remote backend source responded with an error: {}", error))?;
    let bytes = response
        .bytes()
        .map_err(|error| format!("failed to read remote backend payload: {}", error))?;
    fs::write(source_path, &bytes).map_err(|error| {
        format!(
            "failed to write downloaded backend source {}: {}",
            source_path.display(),
            error
        )
    })?;

    let is_zip_archive = source_path
        .extension()
        .and_then(|value| value.to_str())
        .map(|value| value.eq_ignore_ascii_case("zip"))
        .unwrap_or(false);
    if !is_zip_archive {
        return Ok(source_path.clone());
    }

    let extract_root = source_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("unzipped");
    if extract_root.exists() {
        fs::remove_dir_all(&extract_root).map_err(|error| {
            format!(
                "failed to clear previous backend archive extraction {}: {}",
                extract_root.display(),
                error
            )
        })?;
    }
    fs::create_dir_all(&extract_root)
        .map_err(|error| format!("failed to create backend extraction root: {}", error))?;
    extract_zip_archive(source_path, &extract_root)?;
    collapse_single_directory_root(&extract_root)
}

fn materialize_container_backed_backend_install(
    context: &BackendContext,
    job: &LocalEngineJobRecord,
    now_ms: u64,
) -> Result<BackendInstallMaterialization, String> {
    let source_uri = context
        .source_uri
        .as_deref()
        .ok_or_else(|| "container-backed backend install requires a source URI".to_string())?;
    let launcher_path = context
        .install_root
        .join(LOCAL_ENGINE_BACKEND_CONTAINER_LAUNCHER);
    let launcher = container_backed_backend_launcher(source_uri);
    fs::write(&launcher_path, launcher.as_bytes()).map_err(|error| {
        format!(
            "failed to write backend launcher {}: {}",
            launcher_path.display(),
            error
        )
    })?;
    ensure_script_is_executable(&launcher_path)?;

    let package_manifest = json!({
        "entrypoint": LOCAL_ENGINE_BACKEND_CONTAINER_LAUNCHER,
        "args": [],
        "env": {},
        "healthUrl": serde_json::Value::Null,
        "alias": humanize_token(&context.backend_id),
        "sourceUri": source_uri,
        "installMode": "container_image",
    });
    let package_manifest_path = context
        .install_root
        .join(LOCAL_ENGINE_BACKEND_PACKAGE_MANIFEST);
    write_json_file(&package_manifest_path, &package_manifest)?;

    let bytes_transferred = measure_path_bytes(&context.install_root)?;
    let installed_manifest = json!({
        "backendId": context.backend_id,
        "entrypoint": launcher_path.display().to_string(),
        "args": [],
        "env": {},
        "healthUrl": serde_json::Value::Null,
        "alias": humanize_token(&context.backend_id),
        "sourceUri": context.source_uri,
        "sourcePath": serde_json::Value::Null,
        "installRoot": context.install_root.display().to_string(),
        "bytesTransferred": bytes_transferred,
        "installedAtMs": now_ms,
        "jobId": job.job_id,
    });
    write_json_file(&context.manifest_path, &installed_manifest)?;

    let manifest = load_installed_backend_manifest(&context.manifest_path)?;
    Ok(BackendInstallMaterialization {
        entrypoint: manifest.entrypoint,
        alias: manifest.alias,
        health_endpoint: manifest.health_url,
        bytes_transferred,
    })
}

#[cfg(unix)]
fn container_backed_backend_launcher(source_uri: &str) -> String {
    format!(
        r#"#!/usr/bin/env sh
set -eu
IMAGE={source_uri:?}
if command -v docker >/dev/null 2>&1; then
  exec docker run --rm "$IMAGE" "$@"
fi
if command -v podman >/dev/null 2>&1; then
  exec podman run --rm "$IMAGE" "$@"
fi
printf '%s\n' "No supported container runtime (docker or podman) is available for $IMAGE." >&2
exit 127
"#
    )
}

#[cfg(windows)]
fn container_backed_backend_launcher(source_uri: &str) -> String {
    format!(
        "@echo off\r\nsetlocal\r\nset IMAGE={source_uri}\r\nwhere docker >nul 2>nul\r\nif %ERRORLEVEL% EQU 0 (\r\n  docker run --rm %IMAGE% %*\r\n  exit /b %ERRORLEVEL%\r\n)\r\nwhere podman >nul 2>nul\r\nif %ERRORLEVEL% EQU 0 (\r\n  podman run --rm %IMAGE% %*\r\n  exit /b %ERRORLEVEL%\r\n)\r\necho No supported container runtime (docker or podman) is available for %IMAGE%. 1>&2\r\nexit /b 127\r\n"
    )
}

fn extract_zip_archive(archive_path: &Path, target_root: &Path) -> Result<(), String> {
    let archive_file = fs::File::open(archive_path).map_err(|error| {
        format!(
            "failed to open backend archive {}: {}",
            archive_path.display(),
            error
        )
    })?;
    let mut archive = zip::ZipArchive::new(archive_file)
        .map_err(|error| format!("failed to read backend archive: {}", error))?;
    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .map_err(|error| format!("failed to read backend archive entry: {}", error))?;
        let Some(relative_path) = entry.enclosed_name().map(|value| value.to_path_buf()) else {
            continue;
        };
        let destination = target_root.join(relative_path);
        if entry.is_dir() {
            fs::create_dir_all(&destination).map_err(|error| {
                format!(
                    "failed to create backend archive directory {}: {}",
                    destination.display(),
                    error
                )
            })?;
            continue;
        }
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                format!(
                    "failed to create backend archive parent {}: {}",
                    parent.display(),
                    error
                )
            })?;
        }
        let mut file = fs::File::create(&destination).map_err(|error| {
            format!(
                "failed to create backend archive file {}: {}",
                destination.display(),
                error
            )
        })?;
        std::io::copy(&mut entry, &mut file)
            .map_err(|error| format!("failed to extract backend archive entry: {}", error))?;
    }
    Ok(())
}

fn collapse_single_directory_root(root: &Path) -> Result<PathBuf, String> {
    let mut entries = fs::read_dir(root)
        .map_err(|error| format!("failed to read backend extraction root: {}", error))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("failed to enumerate backend extraction root: {}", error))?;
    entries.sort_by_key(|entry| entry.file_name());
    if entries.len() == 1 {
        let only = entries.remove(0).path();
        if only.is_dir() {
            return Ok(only);
        }
    }
    Ok(root.to_path_buf())
}

fn inspect_backend_source(source_path: &Path) -> Result<BackendPackageManifest, String> {
    if source_path.is_file() {
        return Ok(BackendPackageManifest {
            entrypoint: Some(source_path.display().to_string()),
            args: Vec::new(),
            env: BTreeMap::new(),
            health_url: None,
            alias: source_path
                .file_stem()
                .and_then(|value| value.to_str())
                .map(|value| value.to_string()),
        });
    }
    if !source_path.is_dir() {
        return Err(format!(
            "unsupported backend source type at {}",
            source_path.display()
        ));
    }

    let manifest_path = source_path.join(LOCAL_ENGINE_BACKEND_PACKAGE_MANIFEST);
    if manifest_path.exists() {
        let raw = fs::read(&manifest_path).map_err(|error| {
            format!(
                "failed to read backend package manifest {}: {}",
                manifest_path.display(),
                error
            )
        })?;
        let mut package: BackendPackageManifest =
            serde_json::from_slice(&raw).map_err(|error| {
                format!(
                    "failed to parse backend package manifest {}: {}",
                    manifest_path.display(),
                    error
                )
            })?;
        if package
            .entrypoint
            .as_deref()
            .map(|value| value.trim().is_empty())
            .unwrap_or(true)
        {
            package.entrypoint = Some(infer_backend_entrypoint_from_dir(source_path)?);
        }
        return Ok(package);
    }

    Ok(BackendPackageManifest {
        entrypoint: Some(infer_backend_entrypoint_from_dir(source_path)?),
        args: Vec::new(),
        env: BTreeMap::new(),
        health_url: None,
        alias: source_path
            .file_name()
            .and_then(|value| value.to_str())
            .map(|value| value.to_string()),
    })
}

fn infer_backend_entrypoint_from_dir(source_dir: &Path) -> Result<String, String> {
    let candidates = [
        "start.sh",
        "run.sh",
        "serve.sh",
        "backend.sh",
        "server.sh",
        "backend",
        "server",
    ];
    for candidate in candidates {
        let path = source_dir.join(candidate);
        if path.exists() && path.is_file() {
            return Ok(candidate.to_string());
        }
    }
    Err(format!(
        "directory backend sources must provide {} or a known entrypoint script",
        LOCAL_ENGINE_BACKEND_PACKAGE_MANIFEST
    ))
}

fn resolve_backend_entrypoint(install_root: &Path, entrypoint: &str) -> String {
    let path = PathBuf::from(entrypoint);
    if path.is_absolute() {
        path.display().to_string()
    } else {
        install_root.join(path).display().to_string()
    }
}

fn load_installed_backend_manifest(path: &Path) -> Result<InstalledBackendManifest, String> {
    let raw = fs::read(path).map_err(|error| {
        format!(
            "failed to read backend manifest {}: {}",
            path.display(),
            error
        )
    })?;
    serde_json::from_slice(&raw).map_err(|error| {
        format!(
            "failed to parse backend manifest {}: {}",
            path.display(),
            error
        )
    })
}

fn write_backend_receipt(
    context: &BackendContext,
    job: &LocalEngineJobRecord,
    now_ms: u64,
    stage: &str,
    bytes_transferred: Option<u64>,
    entrypoint: Option<&str>,
    error: Option<&str>,
) -> Result<(), String> {
    let Some(receipt_path) = context.receipt_path.as_ref() else {
        return Ok(());
    };
    let receipt = json!({
        "family": "model_lifecycle",
        "subjectKind": "backend",
        "operation": job.operation,
        "stage": stage,
        "status": if error.is_some() { "failed" } else { stage },
        "success": error.is_none(),
        "jobId": job.job_id,
        "backendId": context.backend_id,
        "sourceUri": context.source_uri,
        "sourcePath": context.source_path.as_ref().map(|path| path.display().to_string()),
        "installRoot": context.install_root.display().to_string(),
        "entrypoint": entrypoint,
        "bytesTransferred": bytes_transferred,
        "timestampMs": now_ms,
        "kernelAuthority": true,
        "error": error,
    });
    write_json_file(receipt_path, &receipt)
}

fn start_supervised_backend(
    context: &BackendContext,
    manifest: &InstalledBackendManifest,
    now_ms: u64,
) -> Result<BackendRuntimeObservation, String> {
    let mut supervisor = MANAGED_BACKEND_PROCESSES
        .lock()
        .map_err(|_| "failed to lock backend supervisor".to_string())?;

    let should_remove = match supervisor.get_mut(&context.backend_id) {
        Some(existing) => match existing.child.try_wait() {
            Ok(None) => {
                return Ok(BackendRuntimeObservation {
                    status: "running".to_string(),
                    health: if existing.health_url.is_some() {
                        "probing".to_string()
                    } else {
                        "healthy".to_string()
                    },
                    pid: Some(existing.child.id()),
                    alias: manifest.alias.clone(),
                    install_path: Some(manifest.install_root.clone()),
                    entrypoint: Some(existing.entrypoint.clone()),
                    health_endpoint: existing.health_url.clone(),
                    last_started_at_ms: Some(existing.started_at_ms),
                    last_health_check_at_ms: Some(now_ms),
                });
            }
            Ok(Some(_)) | Err(_) => true,
        },
        None => false,
    };
    if should_remove {
        supervisor.remove(&context.backend_id);
    }

    if let Some(health_url) = manifest.health_url.as_deref() {
        if probe_health_endpoint(health_url).is_ok() {
            return Ok(BackendRuntimeObservation {
                status: "running".to_string(),
                health: "healthy".to_string(),
                pid: None,
                alias: manifest.alias.clone(),
                install_path: Some(manifest.install_root.clone()),
                entrypoint: Some(manifest.entrypoint.clone()),
                health_endpoint: manifest.health_url.clone(),
                last_health_check_at_ms: Some(now_ms),
                ..BackendRuntimeObservation::default()
            });
        }
    }

    let mut command = Command::new(&manifest.entrypoint);
    command.args(&manifest.args);
    command.current_dir(&context.install_root);
    command.stdin(Stdio::null());
    command.stdout(Stdio::null());
    command.stderr(Stdio::null());
    for (key, value) in &manifest.env {
        command.env(key, value);
    }
    let child = command.spawn().map_err(|error| {
        format!(
            "failed to start backend {} using {}: {}",
            context.backend_id, manifest.entrypoint, error
        )
    })?;
    let pid = child.id();
    supervisor.insert(
        context.backend_id.clone(),
        ManagedBackendProcess {
            child,
            entrypoint: manifest.entrypoint.clone(),
            health_url: manifest.health_url.clone(),
            started_at_ms: now_ms,
        },
    );
    Ok(BackendRuntimeObservation {
        status: "running".to_string(),
        health: if manifest.health_url.is_some() {
            "probing".to_string()
        } else {
            "healthy".to_string()
        },
        pid: Some(pid),
        alias: manifest.alias.clone(),
        install_path: Some(manifest.install_root.clone()),
        entrypoint: Some(manifest.entrypoint.clone()),
        health_endpoint: manifest.health_url.clone(),
        last_started_at_ms: Some(now_ms),
        last_health_check_at_ms: Some(now_ms),
    })
}

fn stop_supervised_backend(
    context: &BackendContext,
    now_ms: u64,
) -> Result<BackendRuntimeObservation, String> {
    let manifest = load_installed_backend_manifest(&context.manifest_path).ok();
    let mut supervisor = MANAGED_BACKEND_PROCESSES
        .lock()
        .map_err(|_| "failed to lock backend supervisor".to_string())?;
    let Some(mut managed) = supervisor.remove(&context.backend_id) else {
        return Ok(BackendRuntimeObservation {
            status: "stopped".to_string(),
            health: "stopped".to_string(),
            install_path: manifest.as_ref().map(|value| value.install_root.clone()),
            entrypoint: manifest.as_ref().map(|value| value.entrypoint.clone()),
            health_endpoint: manifest.as_ref().and_then(|value| value.health_url.clone()),
            last_health_check_at_ms: Some(now_ms),
            ..BackendRuntimeObservation::default()
        });
    };

    if managed
        .child
        .try_wait()
        .map_err(|error| error.to_string())?
        .is_none()
    {
        managed
            .child
            .kill()
            .map_err(|error| format!("failed to kill backend {}: {}", context.backend_id, error))?;
        let _ = managed.child.wait();
    }

    Ok(BackendRuntimeObservation {
        status: "stopped".to_string(),
        health: "stopped".to_string(),
        alias: manifest.as_ref().and_then(|value| value.alias.clone()),
        install_path: manifest.as_ref().map(|value| value.install_root.clone()),
        entrypoint: Some(managed.entrypoint.clone()),
        health_endpoint: managed.health_url.clone(),
        last_started_at_ms: Some(managed.started_at_ms),
        last_health_check_at_ms: Some(now_ms),
        ..BackendRuntimeObservation::default()
    })
}

fn observe_supervised_backend(
    backend_id: &str,
    manifest: Option<&InstalledBackendManifest>,
    now_ms: u64,
    strict_probe: bool,
) -> Result<BackendRuntimeObservation, String> {
    let mut supervisor = MANAGED_BACKEND_PROCESSES
        .lock()
        .map_err(|_| "failed to lock backend supervisor".to_string())?;
    let Some(managed) = supervisor.get_mut(backend_id) else {
        if let Some(manifest) = manifest {
            if let Some(health_url) = manifest.health_url.as_deref() {
                if let Ok(health) = probe_health_endpoint(health_url) {
                    return Ok(BackendRuntimeObservation {
                        status: "running".to_string(),
                        health,
                        pid: None,
                        alias: manifest.alias.clone(),
                        install_path: Some(manifest.install_root.clone()),
                        entrypoint: Some(manifest.entrypoint.clone()),
                        health_endpoint: manifest.health_url.clone(),
                        last_health_check_at_ms: Some(now_ms),
                        ..BackendRuntimeObservation::default()
                    });
                }
            }
        }
        return Ok(BackendRuntimeObservation {
            status: manifest
                .map(|_| "installed".to_string())
                .unwrap_or_else(|| "stopped".to_string()),
            health: manifest
                .map(|_| "stopped".to_string())
                .unwrap_or_else(|| "unknown".to_string()),
            alias: manifest.and_then(|value| value.alias.clone()),
            install_path: manifest.map(|value| value.install_root.clone()),
            entrypoint: manifest.map(|value| value.entrypoint.clone()),
            health_endpoint: manifest.and_then(|value| value.health_url.clone()),
            last_health_check_at_ms: Some(now_ms),
            ..BackendRuntimeObservation::default()
        });
    };

    let mut should_remove = false;
    let observation = match managed.child.try_wait() {
        Ok(Some(status)) => {
            should_remove = true;
            BackendRuntimeObservation {
                status: if status.success() {
                    "stopped".to_string()
                } else {
                    "failed".to_string()
                },
                health: if status.success() {
                    "stopped".to_string()
                } else {
                    "degraded".to_string()
                },
                pid: None,
                alias: manifest.and_then(|value| value.alias.clone()),
                install_path: manifest.map(|value| value.install_root.clone()),
                entrypoint: Some(managed.entrypoint.clone()),
                health_endpoint: managed.health_url.clone(),
                last_started_at_ms: Some(managed.started_at_ms),
                last_health_check_at_ms: Some(now_ms),
            }
        }
        Ok(None) => {
            let health = match managed.health_url.as_deref() {
                Some(endpoint) => match probe_health_endpoint(endpoint) {
                    Ok(probe_health) => probe_health,
                    Err(_)
                        if !strict_probe
                            || now_ms.saturating_sub(managed.started_at_ms) < 15_000 =>
                    {
                        "probing".to_string()
                    }
                    Err(_) => "degraded".to_string(),
                },
                None => "healthy".to_string(),
            };
            BackendRuntimeObservation {
                status: "running".to_string(),
                health,
                pid: Some(managed.child.id()),
                alias: manifest.and_then(|value| value.alias.clone()),
                install_path: manifest.map(|value| value.install_root.clone()),
                entrypoint: Some(managed.entrypoint.clone()),
                health_endpoint: managed.health_url.clone(),
                last_started_at_ms: Some(managed.started_at_ms),
                last_health_check_at_ms: Some(now_ms),
            }
        }
        Err(error) => {
            should_remove = true;
            BackendRuntimeObservation {
                status: "failed".to_string(),
                health: "degraded".to_string(),
                pid: None,
                alias: manifest.and_then(|value| value.alias.clone()),
                install_path: manifest.map(|value| value.install_root.clone()),
                entrypoint: Some(managed.entrypoint.clone()),
                health_endpoint: managed.health_url.clone(),
                last_started_at_ms: Some(managed.started_at_ms),
                last_health_check_at_ms: Some(now_ms),
            }
            .with_summary_error(error)
        }
    };

    if should_remove {
        supervisor.remove(backend_id);
    }
    Ok(observation)
}

fn refresh_supervised_backend_state(state: &mut LocalEngineRegistryState, now_ms: u64) -> usize {
    let mut changed = 0usize;
    for record in &mut state.managed_backends {
        let manifest = record
            .install_path
            .as_deref()
            .map(PathBuf::from)
            .map(|path| path.join(LOCAL_ENGINE_BACKEND_INSTALL_MANIFEST))
            .and_then(|path| load_installed_backend_manifest(&path).ok());
        let Ok(observation) =
            observe_supervised_backend(&record.backend_id, manifest.as_ref(), now_ms, true)
        else {
            continue;
        };
        let mut record_changed = false;
        record_changed |= replace_if_different(&mut record.status, observation.status.clone());
        record_changed |= replace_if_different(&mut record.health, observation.health.clone());
        record_changed |= replace_if_different(&mut record.alias, observation.alias.clone());
        record_changed |=
            replace_if_different(&mut record.install_path, observation.install_path.clone());
        record_changed |= replace_if_different(&mut record.entrypoint, observation.entrypoint);
        record_changed |=
            replace_if_different(&mut record.health_endpoint, observation.health_endpoint);
        record_changed |= replace_if_different(&mut record.pid, observation.pid);
        record_changed |= replace_if_different(
            &mut record.last_started_at_ms,
            observation.last_started_at_ms,
        );
        record_changed |= replace_if_different(
            &mut record.last_health_check_at_ms,
            observation.last_health_check_at_ms,
        );
        if record_changed {
            record.updated_at_ms = now_ms;
            changed = changed.saturating_add(1);
        }
    }
    changed
}

fn probe_health_endpoint(endpoint: &str) -> Result<String, String> {
    let parsed = Url::parse(endpoint)
        .map_err(|error| format!("invalid health endpoint {}: {}", endpoint, error))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| format!("health endpoint {} is missing a host", endpoint))?;
    let port = parsed
        .port_or_known_default()
        .ok_or_else(|| format!("health endpoint {} is missing a port", endpoint))?;
    let address = format!("{}:{}", host, port);
    let timeout = std::time::Duration::from_millis(LOCAL_ENGINE_HEALTH_PROBE_TIMEOUT_MS);
    let socket = TcpStream::connect_timeout(
        &address
            .parse()
            .map_err(|error| format!("invalid health probe address {}: {}", address, error))?,
        timeout,
    )
    .map_err(|error| format!("health probe failed to connect to {}: {}", endpoint, error))?;
    socket
        .set_read_timeout(Some(timeout))
        .map_err(|error| format!("failed to set probe read timeout: {}", error))?;
    socket
        .set_write_timeout(Some(timeout))
        .map_err(|error| format!("failed to set probe write timeout: {}", error))?;

    if parsed.scheme() == "http" {
        let path = if parsed.path().is_empty() {
            "/"
        } else {
            parsed.path()
        };
        let request = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            path, host
        );
        let mut stream = socket;
        stream
            .write_all(request.as_bytes())
            .map_err(|error| format!("failed to send health probe request: {}", error))?;
        let mut response = String::new();
        stream
            .read_to_string(&mut response)
            .map_err(|error| format!("failed to read health probe response: {}", error))?;
        let status_code = response
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|value| value.parse::<u16>().ok())
            .unwrap_or(0);
        return if (200..400).contains(&status_code) {
            Ok("healthy".to_string())
        } else {
            Ok("degraded".to_string())
        };
    }

    Ok("healthy".to_string())
}

fn backend_hints_from_observation(observation: &BackendRuntimeObservation) -> RegistryEffectHints {
    RegistryEffectHints {
        backend_status: Some(observation.status.clone()),
        backend_health: Some(observation.health.clone()),
        backend_alias: observation.alias.clone(),
        backend_install_path: observation.install_path.clone(),
        backend_entrypoint: observation.entrypoint.clone(),
        backend_health_endpoint: observation.health_endpoint.clone(),
        backend_pid: observation.pid,
        backend_last_started_at_ms: observation.last_started_at_ms,
        backend_last_health_check_at_ms: observation.last_health_check_at_ms,
        ..RegistryEffectHints::default()
    }
}

fn replace_if_different<T: PartialEq>(slot: &mut T, next: T) -> bool {
    if *slot == next {
        false
    } else {
        *slot = next;
        true
    }
}

#[cfg(unix)]
fn ensure_script_is_executable(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;

    let mut permissions = fs::metadata(path)
        .map_err(|error| {
            format!(
                "failed to read permissions for {}: {}",
                path.display(),
                error
            )
        })?
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions)
        .map_err(|error| format!("failed to mark {} as executable: {}", path.display(), error))
}

#[cfg(not(unix))]
fn ensure_script_is_executable(_path: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(unix)]
fn preserve_file_permissions(source: &Path, destination: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;

    let permissions = fs::metadata(source)
        .map_err(|error| {
            format!(
                "failed to read permissions for {}: {}",
                source.display(),
                error
            )
        })?
        .permissions();
    fs::set_permissions(destination, fs::Permissions::from_mode(permissions.mode())).map_err(
        |error| {
            format!(
                "failed to preserve permissions from {} to {}: {}",
                source.display(),
                destination.display(),
                error
            )
        },
    )
}

#[cfg(not(unix))]
fn preserve_file_permissions(_source: &Path, _destination: &Path) -> Result<(), String> {
    Ok(())
}

impl BackendRuntimeObservation {
    fn with_summary_error(self, _error: std::io::Error) -> Self {
        self
    }
}

fn apply_job_effect(
    state: &mut LocalEngineRegistryState,
    control_plane: Option<&LocalEngineControlPlane>,
    job: &LocalEngineJobRecord,
    now_ms: u64,
    hints: &RegistryEffectHints,
) {
    match job.subject_kind.as_str() {
        "model" => apply_model_effect(state, job, now_ms, hints),
        "backend" => apply_backend_effect(state, job, now_ms, hints),
        "gallery" => apply_gallery_effect(state, control_plane, job, now_ms, hints),
        _ => {}
    }
}

fn apply_model_effect(
    state: &mut LocalEngineRegistryState,
    job: &LocalEngineJobRecord,
    now_ms: u64,
    hints: &RegistryEffectHints,
) {
    let Some(model_id) = primary_subject_identifier(job) else {
        return;
    };

    if job.status == "completed" && matches!(job.operation.as_str(), "delete" | "remove") {
        state
            .registry_models
            .retain(|record| record.model_id != model_id);
        return;
    }

    let existing = state
        .registry_models
        .iter()
        .position(|record| record.model_id == model_id);
    let previous = existing.and_then(|index| state.registry_models.get(index).cloned());
    let record = LocalEngineModelRecord {
        model_id: model_id.clone(),
        status: model_status_for_job(job),
        residency: model_residency_for_job(job, previous.as_ref()),
        installed_at_ms: previous
            .as_ref()
            .map(|record| record.installed_at_ms)
            .unwrap_or(job.created_at_ms.min(now_ms)),
        updated_at_ms: now_ms,
        source_uri: job.source_uri.clone().or_else(|| {
            previous
                .as_ref()
                .and_then(|record| record.source_uri.clone())
        }),
        backend_id: job.backend_id.clone().or_else(|| {
            previous
                .as_ref()
                .and_then(|record| record.backend_id.clone())
        }),
        hardware_profile: hints.hardware_profile.clone().or_else(|| {
            previous
                .as_ref()
                .and_then(|record| record.hardware_profile.clone())
        }),
        job_id: Some(job.job_id.clone()),
        bytes_transferred: hints.bytes_transferred.or_else(|| {
            previous
                .as_ref()
                .and_then(|record| record.bytes_transferred)
        }),
    };

    if let Some(index) = existing {
        state.registry_models[index] = record;
    } else {
        state.registry_models.push(record);
    }
}

fn apply_backend_effect(
    state: &mut LocalEngineRegistryState,
    job: &LocalEngineJobRecord,
    now_ms: u64,
    hints: &RegistryEffectHints,
) {
    let backend_id = job
        .backend_id
        .clone()
        .or_else(|| job.subject_id.clone())
        .or_else(|| job.source_uri.clone());
    let Some(backend_id) = backend_id.filter(|value| !value.trim().is_empty()) else {
        return;
    };

    if job.status == "completed" && matches!(job.operation.as_str(), "delete" | "remove") {
        state
            .managed_backends
            .retain(|record| record.backend_id != backend_id);
        return;
    }

    let existing = state
        .managed_backends
        .iter()
        .position(|record| record.backend_id == backend_id);
    let previous = existing.and_then(|index| state.managed_backends.get(index).cloned());
    let record = LocalEngineBackendRecord {
        backend_id: backend_id.clone(),
        status: hints
            .backend_status
            .clone()
            .unwrap_or_else(|| backend_status_for_job(job)),
        health: hints
            .backend_health
            .clone()
            .unwrap_or_else(|| backend_health_for_job(job, previous.as_ref())),
        installed_at_ms: previous
            .as_ref()
            .map(|record| record.installed_at_ms)
            .unwrap_or(job.created_at_ms.min(now_ms)),
        updated_at_ms: now_ms,
        source_uri: job.source_uri.clone().or_else(|| {
            previous
                .as_ref()
                .and_then(|record| record.source_uri.clone())
        }),
        alias: hints
            .backend_alias
            .clone()
            .or_else(|| previous.as_ref().and_then(|record| record.alias.clone())),
        hardware_profile: hints.hardware_profile.clone().or_else(|| {
            previous
                .as_ref()
                .and_then(|record| record.hardware_profile.clone())
        }),
        job_id: Some(job.job_id.clone()),
        install_path: hints.backend_install_path.clone().or_else(|| {
            previous
                .as_ref()
                .and_then(|record| record.install_path.clone())
        }),
        entrypoint: hints.backend_entrypoint.clone().or_else(|| {
            previous
                .as_ref()
                .and_then(|record| record.entrypoint.clone())
        }),
        health_endpoint: hints.backend_health_endpoint.clone().or_else(|| {
            previous
                .as_ref()
                .and_then(|record| record.health_endpoint.clone())
        }),
        pid: hints
            .backend_pid
            .or_else(|| previous.as_ref().and_then(|record| record.pid)),
        last_started_at_ms: hints.backend_last_started_at_ms.or_else(|| {
            previous
                .as_ref()
                .and_then(|record| record.last_started_at_ms)
        }),
        last_health_check_at_ms: hints.backend_last_health_check_at_ms.or_else(|| {
            previous
                .as_ref()
                .and_then(|record| record.last_health_check_at_ms)
        }),
    };

    if let Some(index) = existing {
        state.managed_backends[index] = record;
    } else {
        state.managed_backends.push(record);
    }
}

fn apply_gallery_effect(
    state: &mut LocalEngineRegistryState,
    control_plane: Option<&LocalEngineControlPlane>,
    job: &LocalEngineJobRecord,
    now_ms: u64,
    hints: &RegistryEffectHints,
) {
    let target_ids = resolve_gallery_targets(state, control_plane, job);
    if target_ids.is_empty() {
        return;
    }

    if job.status == "completed" && matches!(job.operation.as_str(), "delete" | "remove") {
        state
            .gallery_catalogs
            .retain(|record| !target_ids.iter().any(|target| target == &record.gallery_id));
        return;
    }

    if !hints.gallery_records.is_empty() {
        for hinted_record in &hints.gallery_records {
            let mut record = hinted_record.clone();
            record.updated_at_ms = now_ms;
            record.last_job_id = Some(job.job_id.clone());
            if record.sync_status == "synced" {
                record.last_synced_at_ms = Some(now_ms);
            }
            if let Some(index) = state
                .gallery_catalogs
                .iter()
                .position(|existing| existing.gallery_id == record.gallery_id)
            {
                state.gallery_catalogs[index] = record;
            } else {
                state.gallery_catalogs.push(record);
            }
        }
        return;
    }

    for target_id in target_ids {
        let previous = state
            .gallery_catalogs
            .iter()
            .find(|record| record.gallery_id == target_id)
            .cloned();
        let source = control_plane
            .and_then(|plane| plane.galleries.iter().find(|source| source.id == target_id));
        let kind = source
            .map(|source| normalize_text(&source.kind))
            .or_else(|| previous.as_ref().map(|record| record.kind.clone()))
            .unwrap_or_else(|| infer_gallery_kind(&target_id, job.source_uri.as_deref()));
        let entry_count = match target_id.as_str() {
            "kernel.models.primary" => state.registry_models.len() as u32,
            "kernel.backends.primary" => state.managed_backends.len() as u32,
            _ => {
                if job.status == "completed" {
                    previous
                        .as_ref()
                        .map(|record| record.entry_count)
                        .unwrap_or_default()
                        .max(gallery_entry_count_hint(&target_id, &kind))
                } else {
                    previous
                        .as_ref()
                        .map(|record| record.entry_count)
                        .unwrap_or_default()
                }
            }
        };
        let record = LocalEngineGalleryCatalogRecord {
            gallery_id: target_id.clone(),
            kind,
            label: source
                .map(|source| source.label.clone())
                .or_else(|| previous.as_ref().map(|record| record.label.clone()))
                .unwrap_or_else(|| humanize_token(&target_id)),
            source_uri: source
                .map(|source| source.uri.clone())
                .or_else(|| previous.as_ref().map(|record| record.source_uri.clone()))
                .or_else(|| job.source_uri.clone())
                .unwrap_or_else(|| target_id.clone()),
            sync_status: gallery_sync_status(job),
            compatibility_tier: source
                .map(|source| source.compatibility_tier.clone())
                .or_else(|| {
                    previous
                        .as_ref()
                        .map(|record| record.compatibility_tier.clone())
                })
                .unwrap_or_else(|| infer_compatibility_tier(&target_id)),
            enabled: source
                .map(|source| source.enabled)
                .or_else(|| previous.as_ref().map(|record| record.enabled))
                .unwrap_or(true),
            entry_count,
            updated_at_ms: now_ms,
            last_job_id: Some(job.job_id.clone()),
            last_synced_at_ms: if job.status == "completed" {
                Some(now_ms)
            } else {
                previous
                    .as_ref()
                    .and_then(|record| record.last_synced_at_ms)
            },
            catalog_path: previous
                .as_ref()
                .and_then(|record| record.catalog_path.clone()),
            sample_entries: previous
                .as_ref()
                .map(|record| record.sample_entries.clone())
                .unwrap_or_default(),
            last_error: if job.status == "failed" {
                Some(job.summary.clone())
            } else {
                previous
                    .as_ref()
                    .and_then(|record| record.last_error.clone())
            },
        };

        if let Some(index) = state
            .gallery_catalogs
            .iter()
            .position(|record| record.gallery_id == target_id)
        {
            state.gallery_catalogs[index] = record;
        } else {
            state.gallery_catalogs.push(record);
        }
    }
}

fn push_operator_activity(
    state: &mut LocalEngineRegistryState,
    job: &LocalEngineJobRecord,
    timestamp_ms: u64,
) {
    push_job_activity(
        state,
        job,
        timestamp_ms,
        "local_engine::control_plane",
        "operator_marked_failed",
    );
}

fn push_executor_activity(
    state: &mut LocalEngineRegistryState,
    job: &LocalEngineJobRecord,
    timestamp_ms: u64,
) {
    push_job_activity(
        state,
        job,
        timestamp_ms,
        "local_engine::executor",
        "executor_failed",
    );
}

fn push_job_activity(
    state: &mut LocalEngineRegistryState,
    job: &LocalEngineJobRecord,
    timestamp_ms: u64,
    tool_name: &str,
    failure_class: &str,
) {
    let status_label = humanize_token(&job.status);
    state.activity_history.push(LocalEngineActivityRecord {
        event_id: format!(
            "local_engine:{}:{}:{}",
            job.job_id, job.status, timestamp_ms
        ),
        session_id: "local-engine".to_string(),
        family: "model_lifecycle".to_string(),
        title: format!("{} {}", status_label, job.title),
        tool_name: tool_name.to_string(),
        timestamp_ms,
        success: !matches!(job.status.as_str(), "failed" | "cancelled"),
        operation: Some(job.operation.clone()),
        subject_kind: Some(job.subject_kind.clone()),
        subject_id: job.subject_id.clone(),
        backend_id: job.backend_id.clone(),
        error_class: if job.status == "failed" {
            Some(failure_class.to_string())
        } else {
            None
        },
    });
}

fn resolve_gallery_targets(
    state: &LocalEngineRegistryState,
    control_plane: Option<&LocalEngineControlPlane>,
    job: &LocalEngineJobRecord,
) -> Vec<String> {
    if let Some(subject_id) = job
        .subject_id
        .as_ref()
        .filter(|value| !value.trim().is_empty())
    {
        return vec![subject_id.clone()];
    }

    if let Some(source_uri) = job
        .source_uri
        .as_ref()
        .filter(|value| !value.trim().is_empty())
    {
        if let Some(control_plane) = control_plane {
            let matched = control_plane
                .galleries
                .iter()
                .filter(|source| source.uri == *source_uri)
                .map(|source| source.id.clone())
                .collect::<Vec<_>>();
            if !matched.is_empty() {
                return matched;
            }
        }

        let matched = state
            .gallery_catalogs
            .iter()
            .filter(|record| record.source_uri == *source_uri)
            .map(|record| record.gallery_id.clone())
            .collect::<Vec<_>>();
        if !matched.is_empty() {
            return matched;
        }

        return vec![infer_gallery_identifier_from_source_uri(source_uri)];
    }

    if let Some(control_plane) = control_plane {
        let enabled = control_plane
            .galleries
            .iter()
            .filter(|source| source.enabled)
            .map(|source| source.id.clone())
            .collect::<Vec<_>>();
        if !enabled.is_empty() {
            return enabled;
        }
    }

    let enabled = state
        .gallery_catalogs
        .iter()
        .filter(|record| record.enabled)
        .map(|record| record.gallery_id.clone())
        .collect::<Vec<_>>();
    if !enabled.is_empty() {
        return enabled;
    }

    state
        .gallery_catalogs
        .iter()
        .map(|record| record.gallery_id.clone())
        .collect()
}

fn gallery_sync_status(job: &LocalEngineJobRecord) -> String {
    match job.status.as_str() {
        "completed" => "synced".to_string(),
        "failed" => "failed".to_string(),
        "cancelled" => "cancelled".to_string(),
        "running" | "syncing" | "applying" => "syncing".to_string(),
        "ready" => "ready".to_string(),
        _ => "queued".to_string(),
    }
}

fn gallery_entry_count_hint(gallery_id: &str, kind: &str) -> u32 {
    match gallery_id {
        "import.localai.models" => 66,
        "import.localai.backends" => 35,
        _ if kind == "model" && gallery_id.contains("localai") => 66,
        _ if kind == "backend" && gallery_id.contains("localai") => 35,
        _ => 0,
    }
}

fn infer_gallery_kind(gallery_id: &str, source_uri: Option<&str>) -> String {
    if gallery_id.contains("backend")
        || source_uri
            .map(|value| value.to_ascii_lowercase().contains("backend"))
            .unwrap_or(false)
    {
        "backend".to_string()
    } else {
        "model".to_string()
    }
}

fn infer_compatibility_tier(gallery_id: &str) -> String {
    if gallery_id.starts_with("kernel.") {
        "native".to_string()
    } else if gallery_id.contains("localai") {
        "migration".to_string()
    } else {
        "compatibility".to_string()
    }
}

fn model_status_for_job(job: &LocalEngineJobRecord) -> String {
    match job.status.as_str() {
        "completed" => match job.operation.as_str() {
            "load" => "loaded".to_string(),
            "unload" => "installed".to_string(),
            "apply" => "applied".to_string(),
            _ => "installed".to_string(),
        },
        "failed" => "failed".to_string(),
        "cancelled" => "cancelled".to_string(),
        "running" | "syncing" | "applying" => match job.operation.as_str() {
            "load" => "loading".to_string(),
            "unload" => "unloading".to_string(),
            "apply" => "applying".to_string(),
            _ => "installing".to_string(),
        },
        _ => "queued".to_string(),
    }
}

fn model_residency_for_job(
    job: &LocalEngineJobRecord,
    previous: Option<&LocalEngineModelRecord>,
) -> String {
    match job.status.as_str() {
        "completed" => match job.operation.as_str() {
            "load" => "resident".to_string(),
            "unload" => "evicted".to_string(),
            _ => previous
                .map(|record| record.residency.clone())
                .unwrap_or_else(|| "cold".to_string()),
        },
        "running" | "syncing" | "applying" => match job.operation.as_str() {
            "load" => "warming".to_string(),
            "unload" => "evicting".to_string(),
            _ => previous
                .map(|record| record.residency.clone())
                .unwrap_or_else(|| "cold".to_string()),
        },
        _ => previous
            .map(|record| record.residency.clone())
            .unwrap_or_else(|| "cold".to_string()),
    }
}

fn backend_status_for_job(job: &LocalEngineJobRecord) -> String {
    match job.status.as_str() {
        "completed" => match job.operation.as_str() {
            "install" => "installed".to_string(),
            "apply" => "configured".to_string(),
            "start" | "load" => "running".to_string(),
            "stop" | "unload" => "stopped".to_string(),
            "health" | "health_check" | "probe" => "running".to_string(),
            _ => "managed".to_string(),
        },
        "failed" => "failed".to_string(),
        "cancelled" => "cancelled".to_string(),
        "running" | "syncing" | "applying" => match job.operation.as_str() {
            "install" => "installing".to_string(),
            "apply" => "applying".to_string(),
            "start" | "load" => "starting".to_string(),
            "stop" | "unload" => "stopping".to_string(),
            "health" | "health_check" | "probe" => "probing".to_string(),
            _ => "running".to_string(),
        },
        _ => "queued".to_string(),
    }
}

fn backend_health_for_job(
    job: &LocalEngineJobRecord,
    previous: Option<&LocalEngineBackendRecord>,
) -> String {
    match job.status.as_str() {
        "completed" => match job.operation.as_str() {
            "install" => "unknown".to_string(),
            "stop" | "unload" => "stopped".to_string(),
            _ => "healthy".to_string(),
        },
        "failed" => "degraded".to_string(),
        "running" | "syncing" | "applying" => match job.operation.as_str() {
            "health" | "health_check" | "probe" => "probing".to_string(),
            "start" | "load" => "starting".to_string(),
            "stop" | "unload" => "stopping".to_string(),
            _ => previous
                .map(|record| record.health.clone())
                .unwrap_or_else(|| "unknown".to_string()),
        },
        _ => previous
            .map(|record| record.health.clone())
            .unwrap_or_else(|| "unknown".to_string()),
    }
}

fn primary_subject_identifier(job: &LocalEngineJobRecord) -> Option<String> {
    job.subject_id
        .clone()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            job.source_uri
                .clone()
                .filter(|value| !value.trim().is_empty())
        })
}

fn app_memory_runtime(app: &AppHandle) -> Option<Arc<MemoryRuntime>> {
    let state = app.state::<Mutex<AppState>>();
    state
        .lock()
        .ok()
        .and_then(|guard| guard.memory_runtime.clone())
}

fn next_executor_status(job: &LocalEngineJobRecord, now_ms: u64) -> Option<String> {
    if !matches!(job.subject_kind.as_str(), "model" | "backend" | "gallery") {
        return None;
    }
    if matches!(job.status.as_str(), "completed" | "failed" | "cancelled") {
        return None;
    }
    if now_ms.saturating_sub(job.updated_at_ms) < LOCAL_ENGINE_EXECUTOR_TICK_MS {
        return None;
    }

    let sequence = executor_status_sequence(job);
    if sequence.is_empty() {
        return None;
    }

    if matches!(job.status.as_str(), "queued" | "ready") {
        return Some(sequence[0].to_string());
    }

    sequence
        .iter()
        .position(|status| *status == job.status)
        .and_then(|index| sequence.get(index + 1))
        .map(|status| (*status).to_string())
}

fn executor_status_sequence(job: &LocalEngineJobRecord) -> &'static [&'static str] {
    match job.subject_kind.as_str() {
        "gallery" => &["syncing", "completed"],
        "backend" => match job.operation.as_str() {
            "health" | "health_check" | "probe" => &["running", "completed"],
            "apply" | "activate" | "update" => &["applying", "completed"],
            "delete" | "remove" => &["running", "completed"],
            _ => &["running", "applying", "completed"],
        },
        "model" => match job.operation.as_str() {
            "apply" | "activate" | "update" => &["applying", "completed"],
            "delete" | "remove" => &["running", "completed"],
            _ => &["running", "applying", "completed"],
        },
        _ => &[],
    }
}

fn normalize_job_status(status: &str) -> String {
    match status.trim().to_ascii_lowercase().as_str() {
        "queued" | "ready" | "running" | "syncing" | "applying" | "completed" | "failed"
        | "cancelled" => status.trim().to_ascii_lowercase(),
        _ => "queued".to_string(),
    }
}

fn stage_operation_title(subject_kind: &str, operation: &str, subject_id: Option<&str>) -> String {
    let operation_label = humanize_token(operation);
    let subject_label = humanize_token(subject_kind);
    match subject_id {
        Some(id) if !id.trim().is_empty() => {
            format!("{} {} {}", operation_label, subject_label, id)
        }
        _ => format!("{} {}", operation_label, subject_label),
    }
}

fn humanize_token(value: &str) -> String {
    value
        .split(['_', '-', '.'])
        .filter(|part| !part.trim().is_empty())
        .map(|part| {
            let mut chars = part.chars();
            match chars.next() {
                Some(first) => format!("{}{}", first.to_uppercase(), chars.as_str()),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn normalize_subject_kind(value: &str) -> String {
    let normalized = normalize_token(value);
    match normalized.as_str() {
        "installjob" | "install_job" => "model".to_string(),
        _ => normalized,
    }
}

fn normalize_token(value: &str) -> String {
    value
        .trim()
        .to_ascii_lowercase()
        .replace(' ', "_")
        .replace('-', "_")
}

fn normalize_text(value: &str) -> String {
    value.trim().to_string()
}

fn normalize_gallery_identifier(value: &str) -> String {
    normalize_model_identifier(value)
}

fn infer_gallery_identifier_from_source_uri(source_uri: &str) -> String {
    if let Ok(parsed) = Url::parse(source_uri) {
        if let Some(segment) = parsed
            .path_segments()
            .and_then(|segments| segments.filter(|segment| !segment.is_empty()).last())
        {
            let segment = segment
                .split('@')
                .next()
                .unwrap_or(segment)
                .trim_end_matches(".json")
                .trim_end_matches(".yaml");
            return normalize_gallery_identifier(segment);
        }
    }
    let candidate = Path::new(source_uri)
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or(source_uri);
    normalize_gallery_identifier(candidate)
}

fn compact_summary(value: &str) -> String {
    let normalized = value
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .trim()
        .to_string();
    if normalized.chars().count() <= 180 {
        return normalized;
    }
    let mut compact = normalized.chars().take(177).collect::<String>();
    compact.push_str("...");
    compact
}

fn normalize_optional_text(value: Option<String>) -> Option<String> {
    value
        .map(|entry| entry.trim().to_string())
        .filter(|entry| !entry.is_empty())
}

fn now_ms() -> u64 {
    Utc::now().timestamp_millis().max(0) as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{
        LocalEngineApiConfig, LocalEngineBackendPolicyConfig, LocalEngineGallerySource,
        LocalEngineLauncherConfig, LocalEngineMemoryConfig, LocalEngineResponseConfig,
        LocalEngineRuntimeProfile, LocalEngineStorageConfig, LocalEngineWatchdogConfig,
    };
    use std::fs;
    use std::net::TcpListener;
    use std::thread;
    use uuid::Uuid;

    fn sample_job(subject_kind: &str, operation: &str, status: &str) -> LocalEngineJobRecord {
        LocalEngineJobRecord {
            job_id: format!("{subject_kind}:{operation}"),
            title: "Sample".to_string(),
            summary: String::new(),
            status: status.to_string(),
            origin: "workload_receipt".to_string(),
            subject_kind: subject_kind.to_string(),
            operation: operation.to_string(),
            created_at_ms: 1_000,
            updated_at_ms: 1_000,
            progress_percent: 0,
            source_uri: None,
            subject_id: Some("sample".to_string()),
            backend_id: None,
            severity: None,
            approval_scope: None,
        }
    }

    fn sample_control_plane(root: &Path) -> LocalEngineControlPlane {
        LocalEngineControlPlane {
            runtime: LocalEngineRuntimeProfile {
                mode: "mock".to_string(),
                endpoint: "mock://reasoning-runtime".to_string(),
                default_model: "mock".to_string(),
                baseline_role: "test".to_string(),
                kernel_authority: "kernel".to_string(),
            },
            storage: LocalEngineStorageConfig {
                models_path: root.join("models").display().to_string(),
                backends_path: root.join("backends").display().to_string(),
                artifacts_path: root.join("artifacts").display().to_string(),
                cache_path: root.join("cache").display().to_string(),
            },
            watchdog: LocalEngineWatchdogConfig {
                enabled: true,
                idle_check_enabled: true,
                idle_timeout: "15m".to_string(),
                busy_check_enabled: true,
                busy_timeout: "5m".to_string(),
                check_interval: "2s".to_string(),
                force_eviction_when_busy: false,
                lru_eviction_max_retries: 30,
                lru_eviction_retry_interval: "1s".to_string(),
            },
            memory: LocalEngineMemoryConfig {
                reclaimer_enabled: true,
                threshold_percent: 80,
                prefer_gpu: true,
                target_resource: "auto".to_string(),
            },
            backend_policy: LocalEngineBackendPolicyConfig {
                max_concurrency: 4,
                max_queued_requests: 32,
                parallel_backend_loads: 2,
                allow_parallel_requests: true,
                health_probe_interval: "10s".to_string(),
                log_level: "info".to_string(),
                auto_shutdown_on_idle: true,
            },
            responses: LocalEngineResponseConfig {
                retain_receipts_days: 7,
                persist_artifacts: true,
                allow_streaming: true,
                store_request_previews: true,
            },
            api: LocalEngineApiConfig {
                bind_address: "127.0.0.1:8787".to_string(),
                remote_access_enabled: false,
                expose_compat_routes: true,
                cors_mode: "local_only".to_string(),
                auth_mode: "kernel_leases".to_string(),
            },
            launcher: LocalEngineLauncherConfig::default(),
            galleries: Vec::new(),
            environment: Vec::new(),
            notes: Vec::new(),
        }
    }

    fn sample_backend_record(status: &str, health: &str) -> LocalEngineBackendRecord {
        LocalEngineBackendRecord {
            backend_id: "ollama-openai".to_string(),
            status: status.to_string(),
            health: health.to_string(),
            installed_at_ms: 1_000,
            updated_at_ms: 1_000,
            source_uri: Some("file:///tmp/ollama-openai".to_string()),
            alias: Some("Ollama OpenAI Dev Runtime".to_string()),
            hardware_profile: Some("gpu".to_string()),
            job_id: Some("job:backend:ollama-openai".to_string()),
            install_path: Some("/tmp/ollama-openai".to_string()),
            entrypoint: Some("/tmp/ollama-openai/start.sh".to_string()),
            health_endpoint: Some("http://127.0.0.1:11434/api/tags".to_string()),
            pid: None,
            last_started_at_ms: None,
            last_health_check_at_ms: None,
        }
    }

    #[test]
    fn local_gpu_dev_bootstrap_requires_runtime_health_before_declaring_ready() {
        assert!(!local_gpu_dev_bootstrap_ready(true, false, false));
        assert!(!local_gpu_dev_bootstrap_ready(true, false, true));
        assert!(local_gpu_dev_bootstrap_ready(true, true, false));
        assert!(local_gpu_dev_bootstrap_ready(false, false, false));
        assert!(!local_gpu_dev_bootstrap_ready(false, false, true));
    }

    fn test_root(label: &str) -> PathBuf {
        let root =
            std::env::temp_dir().join(format!("ioi-local-engine-{label}-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).expect("create test root");
        root
    }

    fn spawn_single_response_http_server(
        body: Vec<u8>,
        content_type: &str,
    ) -> (String, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
        let address = listener.local_addr().expect("local addr");
        let content_type = content_type.to_string();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept request");
            let mut buffer = [0_u8; 1024];
            let _ = stream.read(&mut buffer);
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: {}\r\nConnection: close\r\n\r\n",
                body.len(),
                content_type
            );
            stream
                .write_all(response.as_bytes())
                .expect("write headers");
            stream.write_all(&body).expect("write body");
        });
        (format!("http://{}/model.gguf", address), handle)
    }

    #[test]
    fn gallery_jobs_advance_from_queue_to_sync_and_completion() {
        let mut job = sample_job("gallery", "sync", "queued");
        assert_eq!(
            next_executor_status(&job, 1_000 + LOCAL_ENGINE_EXECUTOR_TICK_MS),
            Some("syncing".to_string())
        );
        job.status = "syncing".to_string();
        job.updated_at_ms = 1_000 + LOCAL_ENGINE_EXECUTOR_TICK_MS;
        assert_eq!(
            next_executor_status(&job, 1_000 + (LOCAL_ENGINE_EXECUTOR_TICK_MS * 2)),
            Some("completed".to_string())
        );
    }

    #[test]
    fn bootstrap_backend_start_waits_for_install_to_finish() {
        let backend = sample_backend_record("installed", "stopped");
        assert!(!should_queue_bootstrap_backend_start(
            Some(&backend),
            true,
            false,
            false
        ));
        assert!(should_queue_bootstrap_backend_start(
            Some(&backend),
            false,
            false,
            false
        ));
        assert!(!should_queue_bootstrap_backend_start(
            Some(&backend),
            false,
            true,
            false
        ));
        assert!(!should_queue_bootstrap_backend_start(
            Some(&backend),
            false,
            false,
            true
        ));
    }

    #[test]
    fn bootstrap_backend_health_waits_for_start_to_finish() {
        let backend = sample_backend_record("running", "starting");
        assert!(!should_queue_bootstrap_backend_health(
            Some(&backend),
            true,
            false,
            false
        ));
        assert!(!should_queue_bootstrap_backend_health(
            Some(&backend),
            false,
            true,
            false
        ));
        assert!(should_queue_bootstrap_backend_health(
            Some(&backend),
            false,
            false,
            false
        ));
        assert!(!should_queue_bootstrap_backend_health(
            Some(&backend),
            false,
            false,
            true
        ));
    }

    #[test]
    fn install_jobs_gain_midflight_applying_phase() {
        let mut job = sample_job("model", "install", "queued");
        assert_eq!(
            next_executor_status(&job, 1_000 + LOCAL_ENGINE_EXECUTOR_TICK_MS),
            Some("running".to_string())
        );
        job.status = "running".to_string();
        job.updated_at_ms = 1_000 + LOCAL_ENGINE_EXECUTOR_TICK_MS;
        assert_eq!(
            next_executor_status(&job, 1_000 + (LOCAL_ENGINE_EXECUTOR_TICK_MS * 2)),
            Some("applying".to_string())
        );
        job.status = "applying".to_string();
        job.updated_at_ms = 1_000 + (LOCAL_ENGINE_EXECUTOR_TICK_MS * 2);
        assert_eq!(
            next_executor_status(&job, 1_000 + (LOCAL_ENGINE_EXECUTOR_TICK_MS * 3)),
            Some("completed".to_string())
        );
    }

    #[test]
    fn model_install_materializes_local_file_and_writes_receipts() {
        let root = test_root("materialize");
        let source_root = root.join("source");
        fs::create_dir_all(&source_root).expect("create source root");
        let source_path = source_root.join("phi-mini.gguf");
        let payload = b"local-model-payload";
        fs::write(&source_path, payload).expect("write source payload");

        let control_plane = sample_control_plane(&root);
        let mut job = sample_job("model", "install", "running");
        job.job_id = "job:model:install".to_string();
        job.source_uri = Some(
            Url::from_file_path(&source_path)
                .expect("file uri")
                .to_string(),
        );
        job.subject_id = Some("Phi Mini".to_string());

        let applying = advance_model_install_job(&mut job, Some(&control_plane), "applying", 2_000)
            .expect("apply install");
        assert_eq!(applying.status, "applying");
        assert_eq!(job.subject_id.as_deref(), Some("phi-mini"));
        assert_eq!(applying.hints.bytes_transferred, Some(payload.len() as u64));

        let install_root = resolve_local_engine_path(&control_plane.storage.models_path)
            .expect("models path")
            .join("phi-mini");
        let installed_file = install_root.join("phi-mini.gguf");
        assert_eq!(
            fs::read(&installed_file).expect("read installed file"),
            payload
        );
        assert!(install_root
            .join(LOCAL_ENGINE_MODEL_INSTALL_MANIFEST)
            .exists());

        let receipt_path =
            model_install_receipt_path(&control_plane, &job.job_id).expect("receipt path");
        let applying_receipt: serde_json::Value =
            serde_json::from_slice(&fs::read(&receipt_path).expect("read applying receipt"))
                .expect("parse applying receipt");
        assert_eq!(applying_receipt["stage"], "materialized");

        job.status = "applying".to_string();
        let completed =
            advance_model_install_job(&mut job, Some(&control_plane), "completed", 3_000)
                .expect("complete install");
        assert_eq!(completed.status, "completed");
        let completed_receipt: serde_json::Value =
            serde_json::from_slice(&fs::read(&receipt_path).expect("read completed receipt"))
                .expect("parse completed receipt");
        assert_eq!(completed_receipt["stage"], "completed");

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn missing_model_source_fails_before_install_progresses() {
        let root = test_root("missing-source");
        let control_plane = sample_control_plane(&root);
        let mut job = sample_job("model", "install", "queued");
        job.source_uri = Some(root.join("missing.gguf").display().to_string());
        job.subject_id = Some("missing".to_string());

        let outcome = advance_executor_job(
            &mut job,
            &LocalEngineRegistryState::default(),
            Some(&control_plane),
            1_000 + LOCAL_ENGINE_EXECUTOR_TICK_MS,
        )
        .expect("failed outcome");

        assert_eq!(outcome.status, "failed");
        assert!(outcome
            .summary
            .as_deref()
            .unwrap_or_default()
            .contains("does not exist"));

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn remote_model_install_downloads_http_artifact_into_registry() {
        let root = test_root("remote-model");
        let control_plane = sample_control_plane(&root);
        let payload = b"remote-model-payload".to_vec();
        let (url, server) =
            spawn_single_response_http_server(payload.clone(), "application/octet-stream");

        let mut job = sample_job("model", "install", "running");
        job.job_id = "job:model:install:remote".to_string();
        job.source_uri = Some(url.clone());
        job.subject_id = Some("remote-model".to_string());

        let applying = advance_model_install_job(&mut job, Some(&control_plane), "applying", 2_000)
            .expect("apply remote install");
        assert_eq!(applying.status, "applying");
        assert_eq!(applying.hints.bytes_transferred, Some(payload.len() as u64));

        let install_root = resolve_local_engine_path(&control_plane.storage.models_path)
            .expect("models path")
            .join("remote-model");
        let installed_file = install_root.join("model.gguf");
        assert_eq!(
            fs::read(&installed_file).expect("read installed file"),
            payload
        );

        let receipt_path =
            model_install_receipt_path(&control_plane, &job.job_id).expect("receipt path");
        let applying_receipt: serde_json::Value =
            serde_json::from_slice(&fs::read(&receipt_path).expect("read applying receipt"))
                .expect("parse applying receipt");
        assert_eq!(applying_receipt["stage"], "materialized");
        assert_eq!(applying_receipt["sourceUri"], url);

        job.status = "applying".to_string();
        let completed =
            advance_model_install_job(&mut job, Some(&control_plane), "completed", 3_000)
                .expect("complete remote install");
        assert_eq!(completed.status, "completed");

        server.join().expect("join test server");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn backend_install_start_health_and_stop_use_kernel_supervision() {
        let root = test_root("backend-runtime");
        let source_root = root.join("backend-source");
        fs::create_dir_all(&source_root).expect("create backend source");
        let package_manifest = serde_json::json!({
            "entrypoint": "/bin/sh",
            "args": ["-c", "sleep 60"],
            "alias": "Sleep backend"
        });
        fs::write(
            source_root.join(LOCAL_ENGINE_BACKEND_PACKAGE_MANIFEST),
            serde_json::to_vec_pretty(&package_manifest).expect("serialize backend package"),
        )
        .expect("write backend package");

        let control_plane = sample_control_plane(&root);

        let mut install_job = sample_job("backend", "install", "running");
        install_job.job_id = "job:backend:install".to_string();
        install_job.source_uri = Some(source_root.display().to_string());
        install_job.subject_id = Some("sleep-backend".to_string());
        let install_applying =
            advance_backend_job(&mut install_job, Some(&control_plane), "applying", 2_000)
                .expect("apply backend install");
        assert_eq!(
            install_applying.hints.backend_entrypoint.as_deref(),
            Some("/bin/sh")
        );
        let install_completed =
            advance_backend_job(&mut install_job, Some(&control_plane), "completed", 3_000)
                .expect("complete backend install");
        assert_eq!(
            install_completed.hints.backend_status.as_deref(),
            Some("installed")
        );

        let manifest_path = resolve_local_engine_path(&control_plane.storage.backends_path)
            .expect("backends path")
            .join("sleep-backend")
            .join(LOCAL_ENGINE_BACKEND_INSTALL_MANIFEST);
        assert!(manifest_path.exists());

        let mut start_job = sample_job("backend", "start", "running");
        start_job.job_id = "job:backend:start".to_string();
        start_job.subject_id = Some("sleep-backend".to_string());
        start_job.backend_id = Some("sleep-backend".to_string());
        let start_applying =
            advance_backend_job(&mut start_job, Some(&control_plane), "applying", 4_000)
                .expect("start backend");
        assert!(start_applying.hints.backend_pid.is_some());
        let start_completed =
            advance_backend_job(&mut start_job, Some(&control_plane), "completed", 5_000)
                .expect("complete backend start");
        assert_eq!(
            start_completed.hints.backend_status.as_deref(),
            Some("running")
        );

        let mut health_job = sample_job("backend", "health", "running");
        health_job.job_id = "job:backend:health".to_string();
        health_job.subject_id = Some("sleep-backend".to_string());
        health_job.backend_id = Some("sleep-backend".to_string());
        let health_completed =
            advance_backend_job(&mut health_job, Some(&control_plane), "completed", 6_000)
                .expect("health check backend");
        assert_eq!(
            health_completed.hints.backend_health.as_deref(),
            Some("healthy")
        );

        let mut stop_job = sample_job("backend", "stop", "running");
        stop_job.job_id = "job:backend:stop".to_string();
        stop_job.subject_id = Some("sleep-backend".to_string());
        stop_job.backend_id = Some("sleep-backend".to_string());
        let stop_applying =
            advance_backend_job(&mut stop_job, Some(&control_plane), "applying", 7_000)
                .expect("apply backend stop");
        assert_eq!(
            stop_applying.hints.backend_status.as_deref(),
            Some("stopped")
        );
        let stop_completed =
            advance_backend_job(&mut stop_job, Some(&control_plane), "completed", 8_000)
                .expect("stop backend");
        assert_eq!(
            stop_completed.hints.backend_status.as_deref(),
            Some("stopped")
        );
        assert_eq!(
            stop_completed.hints.backend_health.as_deref(),
            Some("stopped")
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn observe_supervised_backend_attaches_to_external_health_endpoint() {
        let root = test_root("external-backend");
        let control_plane = sample_control_plane(&root);
        let install_root = resolve_local_engine_path(&control_plane.storage.backends_path)
            .expect("backends path")
            .join("ollama-openai");
        fs::create_dir_all(&install_root).expect("create backend install root");

        let (health_url, server) =
            spawn_single_response_http_server(b"{\"models\":[]}".to_vec(), "application/json");
        let health_url = health_url.replace("/model.gguf", "");

        let manifest = InstalledBackendManifest {
            backend_id: "ollama-openai".to_string(),
            entrypoint: "/bin/sh".to_string(),
            args: Vec::new(),
            env: BTreeMap::new(),
            health_url: Some(health_url.clone()),
            alias: Some("Ollama OpenAI Dev Runtime".to_string()),
            source_uri: Some("file:///tmp/ollama-openai".to_string()),
            source_path: Some("/tmp/ollama-openai".to_string()),
            install_root: install_root.display().to_string(),
            bytes_transferred: None,
            installed_at_ms: Some(1_000),
            job_id: Some("job:backend:ollama-openai".to_string()),
        };

        let observation = observe_supervised_backend("ollama-openai", Some(&manifest), 2_000, true)
            .expect("observe external backend");
        assert_eq!(observation.status, "running");
        assert_eq!(observation.health, "healthy");
        assert_eq!(
            observation.health_endpoint.as_deref(),
            Some(health_url.as_str())
        );
        assert_eq!(observation.pid, None);

        server.join().expect("join health server");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn backend_install_materializes_container_backed_launcher() {
        let root = test_root("backend-container");
        let control_plane = sample_control_plane(&root);

        let mut job = sample_job("backend", "install", "running");
        job.job_id = "job:backend:install:container".to_string();
        job.source_uri = Some("quay.io/go-skynet/local-ai-backends:latest-piper".to_string());
        job.subject_id = Some("piper".to_string());

        let running = advance_backend_job(&mut job, Some(&control_plane), "running", 2_000)
            .expect("validate container backend");
        assert_eq!(
            running.hints.backend_entrypoint.as_deref(),
            Some(LOCAL_ENGINE_BACKEND_CONTAINER_LAUNCHER)
        );

        let applying = advance_backend_job(&mut job, Some(&control_plane), "applying", 3_000)
            .expect("materialize container backend");
        assert_eq!(applying.status, "applying");
        assert!(applying.hints.bytes_transferred.unwrap_or_default() > 0);

        let install_root = resolve_local_engine_path(&control_plane.storage.backends_path)
            .expect("backends path")
            .join("piper");
        let launcher_path = install_root.join(LOCAL_ENGINE_BACKEND_CONTAINER_LAUNCHER);
        assert!(launcher_path.exists());
        let launcher_text = fs::read_to_string(&launcher_path).expect("read launcher");
        assert!(launcher_text.contains("docker run --rm"));

        let manifest_path = install_root.join(LOCAL_ENGINE_BACKEND_INSTALL_MANIFEST);
        let manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(&manifest_path).expect("read manifest"))
                .expect("parse manifest");
        assert_eq!(
            manifest["sourceUri"],
            "quay.io/go-skynet/local-ai-backends:latest-piper"
        );
        assert_eq!(
            manifest["entrypoint"].as_str().unwrap_or_default(),
            launcher_path.display().to_string()
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn normalize_registry_state_rehydrates_installed_assets_from_manifests() {
        let root = test_root("rehydrate-assets");
        let control_plane = sample_control_plane(&root);

        let model_install_root = resolve_local_engine_path(&control_plane.storage.models_path)
            .expect("models path")
            .join("phi-mini");
        fs::create_dir_all(&model_install_root).expect("create model install root");
        let model_payload = model_install_root.join("phi-mini.gguf");
        fs::write(&model_payload, b"phi-mini").expect("write model payload");
        fs::write(
            model_install_root.join(LOCAL_ENGINE_MODEL_INSTALL_MANIFEST),
            serde_json::to_vec_pretty(&serde_json::json!({
                "modelId": "phi-mini",
                "jobId": "job:model:phi-mini",
                "sourceUri": "file:///tmp/phi-mini.gguf",
                "sourcePath": "/tmp/phi-mini.gguf",
                "payloadPath": model_payload.display().to_string(),
                "installRoot": model_install_root.display().to_string(),
                "bytesTransferred": 8,
                "importedAtMs": 2_000
            }))
            .expect("serialize model manifest"),
        )
        .expect("write model manifest");

        let backend_install_root = resolve_local_engine_path(&control_plane.storage.backends_path)
            .expect("backends path")
            .join("llama-cpp");
        fs::create_dir_all(&backend_install_root).expect("create backend install root");
        let backend_entrypoint = backend_install_root.join("launch-backend.sh");
        fs::write(&backend_entrypoint, "#!/usr/bin/env sh\nexit 0\n")
            .expect("write backend entrypoint");
        fs::write(
            backend_install_root.join(LOCAL_ENGINE_BACKEND_INSTALL_MANIFEST),
            serde_json::to_vec_pretty(&serde_json::json!({
                "backendId": "llama-cpp",
                "entrypoint": backend_entrypoint.display().to_string(),
                "args": [],
                "env": {},
                "healthUrl": serde_json::Value::Null,
                "alias": "Llama CPP",
                "sourceUri": "file:///tmp/llama-cpp",
                "sourcePath": "/tmp/llama-cpp",
                "installRoot": backend_install_root.display().to_string(),
                "bytesTransferred": 17,
                "installedAtMs": 3_000,
                "jobId": "job:backend:llama-cpp"
            }))
            .expect("serialize backend manifest"),
        )
        .expect("write backend manifest");

        let mut state = LocalEngineRegistryState::default();
        normalize_registry_state(&mut state, Some(&control_plane), 9_000);

        assert_eq!(state.registry_models.len(), 1);
        assert_eq!(state.registry_models[0].model_id, "phi-mini");
        assert_eq!(state.registry_models[0].status, "installed");
        assert_eq!(state.registry_models[0].bytes_transferred, Some(8));

        assert_eq!(state.managed_backends.len(), 1);
        assert_eq!(state.managed_backends[0].backend_id, "llama-cpp");
        assert_eq!(state.managed_backends[0].status, "installed");
        let backend_install_root_text = backend_install_root.display().to_string();
        assert_eq!(
            state.managed_backends[0].install_path.as_deref(),
            Some(backend_install_root_text.as_str())
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn gallery_sync_materializes_catalog_documents_and_receipts() {
        let root = test_root("gallery-sync");
        let control_plane = sample_control_plane(&root);
        let gallery_path = root.join("gallery.yaml");
        fs::write(
            &gallery_path,
            r#"
- name: "Phi Mini"
  description: "Compact reasoning model"
  tags: ["llm", "chat"]
  overrides:
    backend: "llama-cpp"
    knownUsecases: ["chat"]
  files:
    - filename: "phi-mini.gguf"
      uri: "https://example.invalid/phi-mini.gguf"
- name: "Whisper Tiny"
  description: "Audio transcription starter"
  tags: ["audio", "transcription"]
  overrides:
    backend: "whisper"
    knownUsecases: ["transcription"]
  files:
    - filename: "whisper-tiny.bin"
      uri: "https://example.invalid/whisper-tiny.bin"
"#,
        )
        .expect("write gallery source");

        let mut job = sample_job("gallery", "sync", "syncing");
        job.job_id = "job:gallery:sync".to_string();
        job.source_uri = Some(gallery_path.display().to_string());
        job.subject_id = Some("import.custom.models".to_string());

        let state = LocalEngineRegistryState::default();
        let syncing = advance_gallery_job(&mut job, &state, Some(&control_plane), "syncing", 2_000)
            .expect("validate gallery");
        assert_eq!(syncing.hints.gallery_records.len(), 1);
        assert_eq!(syncing.hints.gallery_records[0].entry_count, 2);
        assert_eq!(syncing.hints.gallery_records[0].sync_status, "syncing");

        let completed =
            advance_gallery_job(&mut job, &state, Some(&control_plane), "completed", 3_000)
                .expect("materialize gallery");
        let record = &completed.hints.gallery_records[0];
        assert_eq!(record.sync_status, "synced");
        assert_eq!(record.entry_count, 2);
        assert_eq!(record.sample_entries.len(), 2);

        let catalog_path = PathBuf::from(
            record
                .catalog_path
                .clone()
                .expect("catalog path should be persisted"),
        );
        assert!(catalog_path.exists());
        let catalog: serde_json::Value =
            serde_json::from_slice(&fs::read(&catalog_path).expect("read catalog"))
                .expect("parse catalog");
        assert_eq!(catalog["entryCount"], 2);

        let receipt_path =
            gallery_sync_receipt_path(Some(&control_plane), &job.job_id).expect("receipt path");
        let receipt: serde_json::Value =
            serde_json::from_slice(&fs::read(&receipt_path).expect("read receipt"))
                .expect("parse receipt");
        assert_eq!(receipt["stage"], "completed");

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn vendored_localai_gallery_sources_sync_into_catalog_records() {
        let root = test_root("vendored-gallery-sync");
        let mut control_plane = sample_control_plane(&root);
        control_plane.memory.prefer_gpu = false;
        control_plane.memory.target_resource = "cpu".to_string();
        control_plane.galleries = vec![
            LocalEngineGallerySource {
                id: "import.localai.models".to_string(),
                kind: "model".to_string(),
                label: "LocalAI model gallery import".to_string(),
                uri: "github:mudler/LocalAI/gallery/index.yaml@master".to_string(),
                enabled: true,
                sync_status: "ready".to_string(),
                compatibility_tier: "migration".to_string(),
            },
            LocalEngineGallerySource {
                id: "import.localai.backends".to_string(),
                kind: "backend".to_string(),
                label: "LocalAI backend gallery import".to_string(),
                uri: "github:mudler/LocalAI/backend/index.yaml@master".to_string(),
                enabled: true,
                sync_status: "ready".to_string(),
                compatibility_tier: "migration".to_string(),
            },
        ];

        let state = LocalEngineRegistryState::default();

        let mut model_job = sample_job("gallery", "sync", "syncing");
        model_job.job_id = "job:gallery:localai-models".to_string();
        model_job.subject_id = Some("import.localai.models".to_string());
        model_job.source_uri = Some("github:mudler/LocalAI/gallery/index.yaml@master".to_string());
        let model_outcome = advance_gallery_job(
            &mut model_job,
            &state,
            Some(&control_plane),
            "completed",
            4_000,
        )
        .expect("sync vendored model gallery");
        assert_eq!(model_outcome.hints.gallery_records.len(), 1);
        assert!(model_outcome.hints.gallery_records[0].entry_count > 100);

        let mut backend_job = sample_job("gallery", "sync", "syncing");
        backend_job.job_id = "job:gallery:localai-backends".to_string();
        backend_job.subject_id = Some("import.localai.backends".to_string());
        backend_job.source_uri =
            Some("github:mudler/LocalAI/backend/index.yaml@master".to_string());
        let backend_outcome = advance_gallery_job(
            &mut backend_job,
            &state,
            Some(&control_plane),
            "completed",
            5_000,
        )
        .expect("sync vendored backend gallery");
        assert_eq!(backend_outcome.hints.gallery_records.len(), 1);
        assert!(backend_outcome.hints.gallery_records[0].entry_count > 100);
        let backend_catalog_path = PathBuf::from(
            backend_outcome.hints.gallery_records[0]
                .catalog_path
                .clone()
                .expect("backend catalog path"),
        );
        let backend_catalog: serde_json::Value =
            serde_json::from_slice(&fs::read(&backend_catalog_path).expect("read backend catalog"))
                .expect("parse backend catalog");
        let llama_cpp = backend_catalog["entries"]
            .as_array()
            .expect("backend entries")
            .iter()
            .find(|entry| entry["entryId"] == "llama-cpp")
            .expect("llama-cpp entry");
        assert_eq!(llama_cpp["backendId"], "cpu-llama-cpp");
        assert!(llama_cpp["sourceUri"]
            .as_str()
            .unwrap_or_default()
            .contains("local-ai-backends"));
        assert!(llama_cpp["summary"]
            .as_str()
            .unwrap_or_default()
            .contains("Resolved to cpu-llama-cpp"));

        let _ = fs::remove_dir_all(&root);
    }
}
