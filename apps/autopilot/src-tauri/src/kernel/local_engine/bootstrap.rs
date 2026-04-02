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

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct LocalGpuDevPresetCatalogDocument {
    #[serde(default)]
    default_preset_id: Option<String>,
    #[serde(default)]
    presets: Vec<LocalGpuDevPresetCatalogEntry>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct LocalGpuDevPresetCatalogEntry {
    id: String,
    #[serde(default)]
    runtime_kind: Option<String>,
    #[serde(default)]
    runtime_url: Option<String>,
    #[serde(default)]
    runtime_health_url: Option<String>,
    #[serde(default)]
    runtime_model: Option<String>,
    #[serde(default)]
    embedding_model: Option<String>,
    #[serde(default)]
    backend_source: Option<String>,
    #[serde(default)]
    backend_id: Option<String>,
    #[serde(default)]
    backend_autostart: Option<bool>,
}

fn local_gpu_dev_preset_catalog_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("dev")
        .join("model-matrix-presets.json")
}

fn load_local_gpu_dev_preset_catalog() -> Option<LocalGpuDevPresetCatalogDocument> {
    let path = local_gpu_dev_preset_catalog_path();
    let raw = fs::read_to_string(&path).ok()?;
    serde_json::from_str::<LocalGpuDevPresetCatalogDocument>(&raw).ok()
}

fn catalog_default_local_gpu_dev_preset_id() -> String {
    load_local_gpu_dev_preset_catalog()
        .and_then(|catalog| catalog.default_preset_id)
        .map(|value| normalize_text(&value))
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| LOCAL_GPU_DEV_DEFAULT_PRESET.to_string())
}

fn resolve_catalog_local_gpu_dev_preset_entry(
    preset_id: &str,
) -> Option<LocalGpuDevPresetCatalogEntry> {
    load_local_gpu_dev_preset_catalog()?
        .presets
        .into_iter()
        .find(|entry| normalize_text(&entry.id) == preset_id)
}

fn resolve_catalog_backend_source(source: Option<String>) -> Option<String> {
    source.and_then(|value| {
        let trimmed = normalize_text(&value);
        if trimmed.is_empty() {
            return None;
        }
        if trimmed.contains("://") {
            return Some(trimmed);
        }
        let candidate = PathBuf::from(&trimmed);
        if candidate.is_absolute() {
            return Some(candidate.display().to_string());
        }
        Some(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join(trimmed)
                .display()
                .to_string(),
        )
    })
}

fn catalog_entry_to_local_gpu_dev_preset(
    preset_id: String,
    entry: LocalGpuDevPresetCatalogEntry,
    local_gpu_dev_enabled: bool,
    explicit_runtime_url: Option<String>,
    explicit_health_url: Option<String>,
    explicit_backend_source: Option<String>,
    explicit_backend_id: Option<String>,
) -> LocalGpuDevPreset {
    LocalGpuDevPreset {
        preset_id,
        runtime_url: explicit_runtime_url.or(entry.runtime_url),
        runtime_health_url: explicit_health_url.or(entry.runtime_health_url),
        runtime_model: env_text("AUTOPILOT_LOCAL_RUNTIME_MODEL")
            .or_else(|| env_text("AUTOPILOT_LOCAL_MODEL_ID"))
            .or_else(|| env_text("OPENAI_MODEL"))
            .or(entry.runtime_model),
        embedding_model: env_text("AUTOPILOT_LOCAL_EMBEDDING_MODEL")
            .or_else(|| env_text("LOCAL_LLM_EMBEDDING_MODEL"))
            .or_else(|| env_text("OPENAI_EMBEDDING_MODEL"))
            .or(entry.embedding_model),
        backend_source: explicit_backend_source.or_else(|| {
            resolve_catalog_backend_source(entry.backend_source)
        }),
        backend_id: explicit_backend_id.or(entry.backend_id),
        model_cache_dir: env_text("AUTOPILOT_LOCAL_MODEL_CACHE_DIR")
            .or_else(|| Some(default_local_gpu_dev_model_cache_dir())),
        backend_autostart: crate::is_env_var_truthy("AUTOPILOT_LOCAL_BACKEND_AUTOSTART")
            || entry.backend_autostart.unwrap_or(false)
            || local_gpu_dev_enabled,
    }
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
            Some(catalog_default_local_gpu_dev_preset_id())
        } else {
            None
        }
    })?;

    let normalized_preset_id = normalize_text(&preset_id);
    if let Some(entry) = resolve_catalog_local_gpu_dev_preset_entry(&normalized_preset_id) {
        if entry.runtime_kind.as_deref() == Some("remote_http") {
            return None;
        }

        let catalog_preset = catalog_entry_to_local_gpu_dev_preset(
            normalized_preset_id.clone(),
            entry,
            local_gpu_dev_enabled,
            explicit_runtime_url.clone(),
            explicit_health_url.clone(),
            explicit_backend_source.clone(),
            explicit_backend_id.clone(),
        );

        if normalized_preset_id == LOCAL_GPU_DEV_DEFAULT_PRESET {
            let ollama_available = command_exists("ollama");
            if !ollama_available
                && explicit_runtime_url.is_none()
                && explicit_backend_source.is_none()
            {
                println!(
                    "[Studio] Local GPU preset '{}' is available, but 'ollama' was not found on PATH. Falling back to mock inference until a local runtime is installed or configured.",
                    LOCAL_GPU_DEV_DEFAULT_PRESET
                );
                return Some(LocalGpuDevPreset {
                    preset_id: catalog_preset.preset_id,
                    runtime_url: None,
                    runtime_health_url: catalog_preset.runtime_health_url,
                    runtime_model: catalog_preset
                        .runtime_model
                        .or_else(|| Some(LOCAL_GPU_DEV_DEFAULT_MODEL.to_string())),
                    embedding_model: catalog_preset
                        .embedding_model
                        .or_else(|| Some(LOCAL_GPU_DEV_DEFAULT_EMBEDDING_MODEL.to_string())),
                    backend_source: None,
                    backend_id: catalog_preset
                        .backend_id
                        .or_else(|| Some(LOCAL_GPU_DEV_DEFAULT_BACKEND_ID.to_string())),
                    model_cache_dir: catalog_preset
                        .model_cache_dir
                        .or_else(|| Some(default_local_gpu_dev_model_cache_dir())),
                    backend_autostart: false,
                });
            }
        }

        return Some(catalog_preset);
    }

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

#[cfg(test)]
mod bootstrap_tests {
    use super::*;

    static LOCAL_GPU_DEV_TEST_ENV_GUARD: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

    const LOCAL_GPU_ENV_KEYS: &[&str] = &[
        "AUTOPILOT_LOCAL_GPU_DEV",
        "AUTOPILOT_LOCAL_DEV_PRESET",
        "AUTOPILOT_LOCAL_RUNTIME_URL",
        "AUTOPILOT_LOCAL_RUNTIME_HEALTH_URL",
        "AUTOPILOT_LOCAL_RUNTIME_MODEL",
        "AUTOPILOT_LOCAL_MODEL_ID",
        "AUTOPILOT_LOCAL_EMBEDDING_MODEL",
        "AUTOPILOT_LOCAL_BACKEND_SOURCE",
        "AUTOPILOT_LOCAL_BACKEND_ID",
        "AUTOPILOT_LOCAL_MODEL_CACHE_DIR",
        "AUTOPILOT_LOCAL_BACKEND_AUTOSTART",
        "LOCAL_LLM_URL",
        "LOCAL_LLM_EMBEDDING_MODEL",
        "OPENAI_MODEL",
        "OPENAI_EMBEDDING_MODEL",
    ];

    fn with_local_gpu_env(vars: &[(&str, Option<&str>)], test: impl FnOnce()) {
        let _guard = LOCAL_GPU_DEV_TEST_ENV_GUARD.lock().unwrap();
        let saved: Vec<(String, Option<String>)> = LOCAL_GPU_ENV_KEYS
            .iter()
            .map(|key| (key.to_string(), std::env::var(key).ok()))
            .collect();

        for key in LOCAL_GPU_ENV_KEYS {
            std::env::remove_var(key);
        }
        for (key, value) in vars {
            if let Some(value) = value {
                std::env::set_var(key, value);
            }
        }

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(test));

        for (key, value) in saved {
            match value {
                Some(value) => std::env::set_var(key, value),
                None => std::env::remove_var(key),
            }
        }

        result.unwrap();
    }

    #[test]
    fn catalog_default_preset_matches_shipped_default() {
        assert_eq!(
            catalog_default_local_gpu_dev_preset_id(),
            LOCAL_GPU_DEV_DEFAULT_PRESET
        );
    }

    #[test]
    fn catalog_backend_source_resolves_relative_paths() {
        let resolved = resolve_catalog_backend_source(Some(
            "dev/local-backends/ollama-openai".to_string(),
        ))
        .expect("relative backend source should resolve");

        assert!(std::path::PathBuf::from(&resolved).is_absolute());
        assert!(resolved.ends_with("/dev/local-backends/ollama-openai"));
    }

    #[test]
    fn resolve_local_gpu_dev_preset_uses_catalog_for_explicit_local_preset() {
        with_local_gpu_env(
            &[("AUTOPILOT_LOCAL_DEV_PRESET", Some("coding-executor-local-oss"))],
            || {
                let preset = resolve_local_gpu_dev_preset()
                    .expect("explicit local catalog preset should resolve");

                assert_eq!(preset.preset_id, "coding-executor-local-oss");
                assert_eq!(preset.runtime_model.as_deref(), Some("qwen2.5:7b"));
                assert_eq!(preset.embedding_model.as_deref(), Some("nomic-embed-text"));
                assert_eq!(preset.runtime_url.as_deref(), Some(LOCAL_GPU_DEV_DEFAULT_RUNTIME_URL));
                assert_eq!(preset.backend_id.as_deref(), Some("ollama-openai"));
                assert!(
                    preset
                        .backend_source
                        .as_deref()
                        .unwrap_or_default()
                        .ends_with("/dev/local-backends/ollama-openai")
                );
            },
        );
    }

    #[test]
    fn resolve_local_gpu_dev_preset_skips_remote_catalog_entries() {
        with_local_gpu_env(
            &[("AUTOPILOT_LOCAL_DEV_PRESET", Some("remote-multimodal-lane"))],
            || {
                assert!(resolve_local_gpu_dev_preset().is_none());
            },
        );
    }
}
