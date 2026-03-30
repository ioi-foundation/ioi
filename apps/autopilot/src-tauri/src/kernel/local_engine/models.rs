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

