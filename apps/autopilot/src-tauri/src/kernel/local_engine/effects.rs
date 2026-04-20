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
#[path = "effects/tests.rs"]
mod tests;
