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
