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

