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

