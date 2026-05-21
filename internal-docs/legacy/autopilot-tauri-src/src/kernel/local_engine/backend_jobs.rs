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

