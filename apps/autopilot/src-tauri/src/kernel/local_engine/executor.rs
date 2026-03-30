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

