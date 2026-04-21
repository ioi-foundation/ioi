use super::*;

pub struct PluginRuntimeManager {
    path: Arc<PathBuf>,
    state: Arc<Mutex<PluginRuntimeState>>,
}

impl PluginRuntimeManager {
    pub fn new(path: PathBuf) -> Self {
        let state = load_plugin_runtime_state(&path).unwrap_or_default();
        Self {
            path: Arc::new(path),
            state: Arc::new(Mutex::new(state)),
        }
    }

    #[cfg(test)]
    pub(crate) fn path(&self) -> &Path {
        self.path.as_ref()
    }

    pub(crate) fn snapshot(&self) -> PluginRuntimeState {
        self.state
            .lock()
            .map(|state| state.clone())
            .unwrap_or_default()
    }

    fn replace_state(&self, next_state: PluginRuntimeState) -> Result<PluginRuntimeState, String> {
        let normalized = normalize_plugin_runtime_state(next_state);
        persist_plugin_runtime_state(&self.path, &normalized)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| "Failed to lock plugin runtime state.".to_string())?;
        *state = normalized.clone();
        Ok(normalized)
    }

    fn update_plugin<F>(&self, plugin_id: &str, action: F) -> Result<PluginRuntimeState, String>
    where
        F: FnOnce(&mut PluginRuntimeState, &mut PluginRuntimeRecord),
    {
        let mut next_state = self.snapshot();
        let index = next_state
            .plugins
            .iter()
            .position(|record| record.plugin_id == plugin_id)
            .unwrap_or_else(|| {
                next_state
                    .plugins
                    .push(PluginRuntimeRecord::trust_required(plugin_id));
                next_state.plugins.len() - 1
            });
        let mut record = next_state.plugins.remove(index);
        action(&mut next_state, &mut record);
        next_state.plugins.push(record);
        self.replace_state(next_state)
    }

    pub(crate) fn trust_plugin(
        &self,
        manifest: &ExtensionManifestRecord,
        enable_after_trust: bool,
    ) -> Result<(), String> {
        if let Some(block_reason) = plugin_authenticity_block_reason(manifest, "trust") {
            return self
                .update_plugin(&manifest.extension_id, |state, record| {
                    let now = state::now();
                    record.load_error = Some(block_reason.clone());
                    push_plugin_receipt(
                        state,
                        SessionPluginLifecycleReceipt {
                            receipt_id: format!(
                                "trust-blocked-signature:{}:{now}",
                                manifest.extension_id
                            ),
                            timestamp_ms: now,
                            plugin_id: manifest.extension_id.clone(),
                            plugin_label: manifest
                                .display_name
                                .clone()
                                .unwrap_or_else(|| manifest.name.clone()),
                            action: "trust".to_string(),
                            status: "blocked".to_string(),
                            summary: block_reason.clone(),
                        },
                    );
                })
                .map(|_| ());
        }
        self.update_plugin(&manifest.extension_id, |state, record| {
            let now = state::now();
            record.trust_state = "trusted".to_string();
            record.remembered_trust = true;
            record.last_trusted_at_ms = Some(now);
            record.revoked_at_ms = None;
            record.load_error = None;
            if enable_after_trust {
                record.enabled = manifest.enabled;
                record.last_enabled_at_ms = Some(now);
                record.last_reloaded_at_ms = Some(now);
                if !manifest.enabled {
                    record.load_error = Some(
                        "Tracked source is currently disabled, so the plugin cannot be loaded yet."
                            .to_string(),
                    );
                }
            }
            push_plugin_receipt(
                state,
                SessionPluginLifecycleReceipt {
                    receipt_id: format!("trust:{}:{now}", manifest.extension_id),
                    timestamp_ms: now,
                    plugin_id: manifest.extension_id.clone(),
                    plugin_label: manifest
                        .display_name
                        .clone()
                        .unwrap_or_else(|| manifest.name.clone()),
                    action: "trust".to_string(),
                    status: "recorded".to_string(),
                    summary: if enable_after_trust {
                        format!(
                            "Remembered trust for {} and enabled it for runtime load.",
                            manifest
                                .display_name
                                .clone()
                                .unwrap_or_else(|| manifest.name.clone())
                        )
                    } else {
                        format!(
                            "Remembered trust for {} without enabling runtime load yet.",
                            manifest
                                .display_name
                                .clone()
                                .unwrap_or_else(|| manifest.name.clone())
                        )
                    },
                },
            );
        })
        .map(|_| ())
    }

    pub(crate) fn set_plugin_enabled(
        &self,
        manifest: &ExtensionManifestRecord,
        enabled: bool,
    ) -> Result<(), String> {
        if enabled {
            if let Some(block_reason) = plugin_authenticity_block_reason(manifest, "enable") {
                return self
                    .update_plugin(&manifest.extension_id, |state, record| {
                        let now = state::now();
                        record.enabled = false;
                        record.load_error = Some(block_reason.clone());
                        push_plugin_receipt(
                            state,
                            SessionPluginLifecycleReceipt {
                                receipt_id: format!(
                                    "enable-blocked-signature:{}:{now}",
                                    manifest.extension_id
                                ),
                                timestamp_ms: now,
                                plugin_id: manifest.extension_id.clone(),
                                plugin_label: manifest
                                    .display_name
                                    .clone()
                                    .unwrap_or_else(|| manifest.name.clone()),
                                action: "enable".to_string(),
                                status: "blocked".to_string(),
                                summary: block_reason.clone(),
                            },
                        );
                    })
                    .map(|_| ());
            }
        }
        self.update_plugin(&manifest.extension_id, |state, record| {
            let now = state::now();
            let label = manifest
                .display_name
                .clone()
                .unwrap_or_else(|| manifest.name.clone());
            if enabled {
                if record.trust_state != "trusted" {
                    record.enabled = false;
                    record.load_error =
                        Some("Trust this plugin before enabling it in runtime.".to_string());
                    push_plugin_receipt(
                        state,
                        SessionPluginLifecycleReceipt {
                            receipt_id: format!("enable-blocked:{}:{now}", manifest.extension_id),
                            timestamp_ms: now,
                            plugin_id: manifest.extension_id.clone(),
                            plugin_label: label,
                            action: "enable".to_string(),
                            status: "blocked".to_string(),
                            summary: format!(
                                "Blocked enabling {} because runtime trust has not been granted yet.",
                                manifest.name
                            ),
                        },
                    );
                    return;
                }
                if !manifest.enabled {
                    record.enabled = false;
                    record.load_error = Some(
                        "The tracked source is disabled, so runtime load cannot start yet."
                            .to_string(),
                    );
                    push_plugin_receipt(
                        state,
                        SessionPluginLifecycleReceipt {
                            receipt_id: format!("enable-source-disabled:{}:{now}", manifest.extension_id),
                            timestamp_ms: now,
                            plugin_id: manifest.extension_id.clone(),
                            plugin_label: label,
                            action: "enable".to_string(),
                            status: "blocked".to_string(),
                            summary: format!(
                                "Blocked enabling {} because its tracked source is disabled.",
                                manifest.name
                            ),
                        },
                    );
                    return;
                }

                record.enabled = true;
                record.load_error = None;
                record.last_enabled_at_ms = Some(now);
                push_plugin_receipt(
                    state,
                    SessionPluginLifecycleReceipt {
                        receipt_id: format!("enable:{}:{now}", manifest.extension_id),
                        timestamp_ms: now,
                        plugin_id: manifest.extension_id.clone(),
                        plugin_label: label,
                        action: "enable".to_string(),
                        status: "applied".to_string(),
                        summary: format!("Enabled {} in the runtime plugin roster.", manifest.name),
                    },
                );
                return;
            }

            record.enabled = false;
            record.load_error = None;
            record.last_disabled_at_ms = Some(now);
            push_plugin_receipt(
                state,
                SessionPluginLifecycleReceipt {
                    receipt_id: format!("disable:{}:{now}", manifest.extension_id),
                    timestamp_ms: now,
                    plugin_id: manifest.extension_id.clone(),
                    plugin_label: label,
                    action: "disable".to_string(),
                    status: "applied".to_string(),
                    summary: format!("Disabled {} without revoking remembered trust.", manifest.name),
                },
            );
        })
        .map(|_| ())
    }

    pub(crate) fn reload_plugin(&self, manifest: &ExtensionManifestRecord) -> Result<(), String> {
        if let Some(block_reason) = plugin_authenticity_block_reason(manifest, "reload") {
            return self
                .update_plugin(&manifest.extension_id, |state, record| {
                    let now = state::now();
                    record.load_error = Some(block_reason.clone());
                    push_plugin_receipt(
                        state,
                        SessionPluginLifecycleReceipt {
                            receipt_id: format!(
                                "reload-blocked-signature:{}:{now}",
                                manifest.extension_id
                            ),
                            timestamp_ms: now,
                            plugin_id: manifest.extension_id.clone(),
                            plugin_label: manifest
                                .display_name
                                .clone()
                                .unwrap_or_else(|| manifest.name.clone()),
                            action: "reload".to_string(),
                            status: "blocked".to_string(),
                            summary: block_reason.clone(),
                        },
                    );
                })
                .map(|_| ());
        }
        self.update_plugin(&manifest.extension_id, |state, record| {
            let now = state::now();
            let label = manifest
                .display_name
                .clone()
                .unwrap_or_else(|| manifest.name.clone());
            if record.trust_state != "trusted" {
                record.load_error =
                    Some("Trust this plugin before reloading it in runtime.".to_string());
                push_plugin_receipt(
                    state,
                    SessionPluginLifecycleReceipt {
                        receipt_id: format!("reload-untrusted:{}:{now}", manifest.extension_id),
                        timestamp_ms: now,
                        plugin_id: manifest.extension_id.clone(),
                        plugin_label: label,
                        action: "reload".to_string(),
                        status: "blocked".to_string(),
                        summary: format!(
                            "Blocked reloading {} because remembered trust is not active.",
                            manifest.name
                        ),
                    },
                );
                return;
            }
            if !record.enabled {
                record.load_error =
                    Some("Enable this plugin before asking runtime to reload it.".to_string());
                push_plugin_receipt(
                    state,
                    SessionPluginLifecycleReceipt {
                        receipt_id: format!("reload-disabled:{}:{now}", manifest.extension_id),
                        timestamp_ms: now,
                        plugin_id: manifest.extension_id.clone(),
                        plugin_label: label,
                        action: "reload".to_string(),
                        status: "blocked".to_string(),
                        summary: format!(
                            "Blocked reloading {} because it is currently disabled in runtime.",
                            manifest.name
                        ),
                    },
                );
                return;
            }
            if !reloadable(manifest) {
                record.load_error = Some(
                    "Tracked source is unavailable, so runtime reload could not be completed."
                        .to_string(),
                );
                push_plugin_receipt(
                    state,
                    SessionPluginLifecycleReceipt {
                        receipt_id: format!(
                            "reload-missing-source:{}:{now}",
                            manifest.extension_id
                        ),
                        timestamp_ms: now,
                        plugin_id: manifest.extension_id.clone(),
                        plugin_label: label,
                        action: "reload".to_string(),
                        status: "blocked".to_string(),
                        summary: format!(
                            "Blocked reloading {} because the tracked source is unavailable.",
                            manifest.name
                        ),
                    },
                );
                return;
            }

            record.last_reloaded_at_ms = Some(now);
            record.load_error = None;
            push_plugin_receipt(
                state,
                SessionPluginLifecycleReceipt {
                    receipt_id: format!("reload:{}:{now}", manifest.extension_id),
                    timestamp_ms: now,
                    plugin_id: manifest.extension_id.clone(),
                    plugin_label: label,
                    action: "reload".to_string(),
                    status: "matched".to_string(),
                    summary: format!(
                        "Used remembered trust to reload {} from its tracked source.",
                        manifest.name
                    ),
                },
            );
        })
        .map(|_| ())
    }

    pub(crate) fn revoke_plugin_trust(
        &self,
        manifest: &ExtensionManifestRecord,
    ) -> Result<(), String> {
        self.update_plugin(&manifest.extension_id, |state, record| {
            let now = state::now();
            record.trust_state = "revoked".to_string();
            record.enabled = false;
            record.remembered_trust = false;
            record.revoked_at_ms = Some(now);
            record.load_error = Some(
                "Trust revoked. Grant trust again before enabling or reloading this plugin."
                    .to_string(),
            );
            push_plugin_receipt(
                state,
                SessionPluginLifecycleReceipt {
                    receipt_id: format!("revoke:{}:{now}", manifest.extension_id),
                    timestamp_ms: now,
                    plugin_id: manifest.extension_id.clone(),
                    plugin_label: manifest
                        .display_name
                        .clone()
                        .unwrap_or_else(|| manifest.name.clone()),
                    action: "revoke".to_string(),
                    status: "revoked".to_string(),
                    summary: format!(
                        "Revoked remembered trust for {} and removed it from the runtime roster.",
                        manifest.name
                    ),
                },
            );
        })
        .map(|_| ())
    }

    pub(crate) fn install_plugin_package(
        &self,
        manifest: &ExtensionManifestRecord,
    ) -> Result<(), String> {
        if let Some(block_reason) = plugin_authenticity_block_reason(manifest, "install") {
            return self
                .update_plugin(&manifest.extension_id, |state, record| {
                    let now = state::now();
                    let label = plugin_display_label(manifest);
                    record.package_error = Some(block_reason.clone());
                    push_plugin_receipt(
                        state,
                        SessionPluginLifecycleReceipt {
                            receipt_id: format!(
                                "install-package-blocked-signature:{}:{now}",
                                manifest.extension_id
                            ),
                            timestamp_ms: now,
                            plugin_id: manifest.extension_id.clone(),
                            plugin_label: label,
                            action: "install".to_string(),
                            status: "blocked".to_string(),
                            summary: block_reason.clone(),
                        },
                    );
                })
                .map(|_| ());
        }
        let label = plugin_display_label(manifest);
        let managed_root = managed_plugin_root_for(self.path.as_ref(), &manifest.extension_id);
        let managed_manifest = managed_root.join(".codex-plugin/plugin.json");
        let copy_result = if let Some(package_url) = manifest
            .marketplace_package_url
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            install_managed_plugin_package_from_archive(
                package_url,
                &managed_root,
                managed_manifest.as_path(),
                manifest.version.as_deref(),
            )
        } else {
            let source_root = PathBuf::from(&manifest.root_path);
            install_managed_plugin_package(
                &source_root,
                &managed_root,
                managed_manifest.as_path(),
                manifest.version.as_deref(),
            )
        };
        let (install_source, install_source_label) = package_install_source(manifest);

        self.update_plugin(&manifest.extension_id, |state, record| {
            let now = state::now();
            match &copy_result {
                Ok(()) => {
                    record.package_managed = true;
                    record.package_install_source = Some(install_source.clone());
                    record.package_install_source_label = Some(install_source_label.clone());
                    record.package_root_path = Some(slash_path(&managed_root));
                    record.package_manifest_path = Some(slash_path(&managed_manifest));
                    record.installed_version = manifest.version.clone();
                    record.last_installed_at_ms = Some(now);
                    record.package_error = None;
                    push_plugin_receipt(
                        state,
                        SessionPluginLifecycleReceipt {
                            receipt_id: format!("install-package:{}:{now}", manifest.extension_id),
                            timestamp_ms: now,
                            plugin_id: manifest.extension_id.clone(),
                            plugin_label: label.clone(),
                            action: "install".to_string(),
                            status: "applied".to_string(),
                            summary: format!(
                                "Installed a managed package copy for {} from its tracked source.",
                                label
                            ),
                        },
                    );
                }
                Err(error) => {
                    record.package_error = Some(error.clone());
                    push_plugin_receipt(
                        state,
                        SessionPluginLifecycleReceipt {
                            receipt_id: format!(
                                "install-package-failed:{}:{now}",
                                manifest.extension_id
                            ),
                            timestamp_ms: now,
                            plugin_id: manifest.extension_id.clone(),
                            plugin_label: label.clone(),
                            action: "install".to_string(),
                            status: "failed".to_string(),
                            summary: format!(
                                "Failed to install a managed package copy for {}: {}",
                                label, error
                            ),
                        },
                    );
                }
            }
        })
        .map(|_| ())
    }

    pub(crate) fn stage_plugin_update(
        &self,
        manifest: &ExtensionManifestRecord,
        available_version: &str,
    ) -> Result<(), String> {
        let label = plugin_display_label(manifest);
        let available_version = available_version.trim().to_string();
        if available_version.is_empty() {
            return Err("Available version is required.".to_string());
        }

        self.update_plugin(&manifest.extension_id, |state, record| {
            let now = state::now();
            record.available_version = Some(available_version.clone());
            record.package_error = None;
            push_plugin_receipt(
                state,
                SessionPluginLifecycleReceipt {
                    receipt_id: format!("update-detected:{}:{now}", manifest.extension_id),
                    timestamp_ms: now,
                    plugin_id: manifest.extension_id.clone(),
                    plugin_label: label.clone(),
                    action: "update_detected".to_string(),
                    status: "available".to_string(),
                    summary: format!(
                        "Marked {} package update {} as available for review.",
                        label, available_version
                    ),
                },
            );
        })
        .map(|_| ())
    }

    pub(crate) fn refresh_plugin_catalog(
        &self,
        manifest: &ExtensionManifestRecord,
        refresh_target: Result<PluginCatalogRefreshTarget, String>,
    ) -> Result<(), String> {
        let label = plugin_display_label(manifest);
        self.update_plugin(&manifest.extension_id, |state, record| {
            let now = state::now();
            match &refresh_target {
                Ok(target) => {
                    record.catalog_issued_at_ms = target.catalog_issued_at_ms;
                    record.catalog_expires_at_ms = target.catalog_expires_at_ms;
                    record.catalog_refreshed_at_ms = target.catalog_refreshed_at_ms;
                    record.catalog_refresh_source = target.catalog_refresh_source.clone();
                    record.catalog_channel = target.catalog_channel.clone();
                    record.catalog_refresh_bundle_id = Some(target.bundle_id.clone());
                    record.catalog_refresh_bundle_label = target.bundle_label.clone();
                    record.catalog_refresh_bundle_issued_at_ms = target.bundle_issued_at_ms;
                    record.catalog_refresh_bundle_expires_at_ms = target.bundle_expires_at_ms;
                    if let Some(available_version) = target.available_version.clone() {
                        record.available_version = Some(available_version);
                    }
                    record.catalog_refresh_error = None;
                    record.last_catalog_refresh_at_ms = Some(now);
                    push_plugin_receipt(
                        state,
                        SessionPluginLifecycleReceipt {
                            receipt_id: format!(
                                "catalog-refresh:{}:{now}",
                                manifest.extension_id
                            ),
                            timestamp_ms: now,
                            plugin_id: manifest.extension_id.clone(),
                            plugin_label: label.clone(),
                            action: "catalog_refresh".to_string(),
                            status: "applied".to_string(),
                            summary: format!(
                                "Applied signed catalog refresh for {} from {}.",
                                label,
                                target
                                    .bundle_label
                                    .clone()
                                    .unwrap_or_else(|| target.bundle_id.clone())
                            ),
                        },
                    );
                }
                Err(error) => {
                    let missing_refresh = error.starts_with(
                        "No signed catalog refresh bundle is currently available",
                    );
                    record.catalog_refresh_error = if missing_refresh {
                        None
                    } else {
                        Some(error.clone())
                    };
                    record.last_catalog_refresh_at_ms = Some(now);
                    push_plugin_receipt(
                        state,
                        SessionPluginLifecycleReceipt {
                            receipt_id: format!(
                                "catalog-refresh-failed:{}:{now}",
                                manifest.extension_id
                            ),
                            timestamp_ms: now,
                            plugin_id: manifest.extension_id.clone(),
                            plugin_label: label.clone(),
                            action: "catalog_refresh".to_string(),
                            status: if missing_refresh {
                                "matched".to_string()
                            } else {
                                "failed".to_string()
                            },
                            summary: if missing_refresh {
                                format!(
                                    "No newer signed catalog refresh is currently available for {}.",
                                    label
                                )
                            } else {
                                format!("Failed to refresh the signed catalog for {}: {}", label, error)
                            },
                        },
                    );
                }
            }
        })
        .map(|_| ())
    }

    pub(crate) fn update_plugin_package(
        &self,
        manifest: &ExtensionManifestRecord,
    ) -> Result<(), String> {
        if let Some(block_reason) = plugin_authenticity_block_reason(manifest, "update") {
            return self
                .update_plugin(&manifest.extension_id, |state, record| {
                    let now = state::now();
                    let label = plugin_display_label(manifest);
                    record.package_error = Some(block_reason.clone());
                    push_plugin_receipt(
                        state,
                        SessionPluginLifecycleReceipt {
                            receipt_id: format!(
                                "update-package-blocked-signature:{}:{now}",
                                manifest.extension_id
                            ),
                            timestamp_ms: now,
                            plugin_id: manifest.extension_id.clone(),
                            plugin_label: label,
                            action: "update".to_string(),
                            status: "blocked".to_string(),
                            summary: block_reason.clone(),
                        },
                    );
                })
                .map(|_| ());
        }
        let label = plugin_display_label(manifest);
        let current_record = self
            .snapshot()
            .plugins
            .into_iter()
            .find(|record| record.plugin_id == manifest.extension_id)
            .unwrap_or_else(|| PluginRuntimeRecord::trust_required(&manifest.extension_id));

        let Some(package_root_path) = current_record.package_root_path.clone() else {
            return self
                .update_plugin(&manifest.extension_id, |state, record| {
                    let now = state::now();
                    record.package_error =
                        Some("Install a managed package copy before applying updates.".to_string());
                    push_plugin_receipt(
                        state,
                        SessionPluginLifecycleReceipt {
                            receipt_id: format!(
                                "update-package-unmanaged:{}:{now}",
                                manifest.extension_id
                            ),
                            timestamp_ms: now,
                            plugin_id: manifest.extension_id.clone(),
                            plugin_label: label.clone(),
                            action: "update".to_string(),
                            status: "blocked".to_string(),
                            summary: format!(
                                "Blocked updating {} because it is not installed as a managed package yet.",
                                label
                            ),
                        },
                    );
                })
                .map(|_| ());
        };

        let installed_version = current_record
            .installed_version
            .clone()
            .or_else(|| manifest.version.clone());
        let Some(available_version) = current_record
            .available_version
            .clone()
            .or_else(|| manifest.marketplace_available_version.clone())
        else {
            return self
                .update_plugin(&manifest.extension_id, |state, record| {
                    let now = state::now();
                    record.package_error =
                        Some("No packaged update is currently staged for this plugin.".to_string());
                    push_plugin_receipt(
                        state,
                        SessionPluginLifecycleReceipt {
                            receipt_id: format!(
                                "update-package-none:{}:{now}",
                                manifest.extension_id
                            ),
                            timestamp_ms: now,
                            plugin_id: manifest.extension_id.clone(),
                            plugin_label: label.clone(),
                            action: "update".to_string(),
                            status: "blocked".to_string(),
                            summary: format!(
                                "Blocked updating {} because no newer packaged version is available yet.",
                                label
                            ),
                        },
                    );
                })
                .map(|_| ());
        };
        if installed_version.as_deref() == Some(available_version.as_str()) {
            return self
                .update_plugin(&manifest.extension_id, |state, record| {
                    let now = state::now();
                    record.package_error = None;
                    push_plugin_receipt(
                        state,
                        SessionPluginLifecycleReceipt {
                            receipt_id: format!(
                                "update-package-current:{}:{now}",
                                manifest.extension_id
                            ),
                            timestamp_ms: now,
                            plugin_id: manifest.extension_id.clone(),
                            plugin_label: label.clone(),
                            action: "update".to_string(),
                            status: "matched".to_string(),
                            summary: format!(
                                "{} is already installed at packaged version {}.",
                                label, available_version
                            ),
                        },
                    );
                })
                .map(|_| ());
        }

        let managed_root = PathBuf::from(&package_root_path);
        let managed_manifest = current_record
            .package_manifest_path
            .clone()
            .map(PathBuf::from)
            .unwrap_or_else(|| managed_root.join(".codex-plugin/plugin.json"));
        let copy_result = if let Some(package_url) = manifest
            .marketplace_package_url
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            install_managed_plugin_package_from_archive(
                package_url,
                &managed_root,
                managed_manifest.as_path(),
                Some(available_version.as_str()),
            )
        } else {
            let source_root = PathBuf::from(&manifest.root_path);
            install_managed_plugin_package(
                &source_root,
                &managed_root,
                managed_manifest.as_path(),
                Some(available_version.as_str()),
            )
        };

        self.update_plugin(&manifest.extension_id, |state, record| {
            let now = state::now();
            match &copy_result {
                Ok(()) => {
                    record.package_managed = true;
                    record.installed_version = Some(available_version.clone());
                    record.last_updated_at_ms = Some(now);
                    record.package_error = None;
                    push_plugin_receipt(
                        state,
                        SessionPluginLifecycleReceipt {
                            receipt_id: format!("update-package:{}:{now}", manifest.extension_id),
                            timestamp_ms: now,
                            plugin_id: manifest.extension_id.clone(),
                            plugin_label: label.clone(),
                            action: "update".to_string(),
                            status: "applied".to_string(),
                            summary: format!(
                                "Applied packaged update {} for {}.",
                                available_version, label
                            ),
                        },
                    );
                }
                Err(error) => {
                    record.package_error = Some(error.clone());
                    push_plugin_receipt(
                        state,
                        SessionPluginLifecycleReceipt {
                            receipt_id: format!(
                                "update-package-failed:{}:{now}",
                                manifest.extension_id
                            ),
                            timestamp_ms: now,
                            plugin_id: manifest.extension_id.clone(),
                            plugin_label: label.clone(),
                            action: "update".to_string(),
                            status: "failed".to_string(),
                            summary: format!(
                                "Failed to apply packaged update for {}: {}",
                                label, error
                            ),
                        },
                    );
                }
            }
        })
        .map(|_| ())
    }

    pub(crate) fn remove_plugin_package(
        &self,
        manifest: &ExtensionManifestRecord,
    ) -> Result<(), String> {
        let label = plugin_display_label(manifest);
        let current_record = self
            .snapshot()
            .plugins
            .into_iter()
            .find(|record| record.plugin_id == manifest.extension_id)
            .unwrap_or_else(|| PluginRuntimeRecord::trust_required(&manifest.extension_id));
        let removal_result = current_record
            .package_root_path
            .as_ref()
            .map(PathBuf::from)
            .map(remove_managed_plugin_package)
            .unwrap_or(Ok(()));

        self.update_plugin(&manifest.extension_id, |state, record| {
            let now = state::now();
            match &removal_result {
                Ok(()) => {
                    record.package_managed = false;
                    record.package_root_path = None;
                    record.package_manifest_path = None;
                    record.installed_version = None;
                    record.package_error = None;
                    record.last_removed_at_ms = Some(now);
                    push_plugin_receipt(
                        state,
                        SessionPluginLifecycleReceipt {
                            receipt_id: format!("remove-package:{}:{now}", manifest.extension_id),
                            timestamp_ms: now,
                            plugin_id: manifest.extension_id.clone(),
                            plugin_label: label.clone(),
                            action: "remove".to_string(),
                            status: "removed".to_string(),
                            summary: format!(
                                "Removed the managed package copy for {} without deleting the tracked source manifest.",
                                label
                            ),
                        },
                    );
                }
                Err(error) => {
                    record.package_error = Some(error.clone());
                    push_plugin_receipt(
                        state,
                        SessionPluginLifecycleReceipt {
                            receipt_id: format!(
                                "remove-package-failed:{}:{now}",
                                manifest.extension_id
                            ),
                            timestamp_ms: now,
                            plugin_id: manifest.extension_id.clone(),
                            plugin_label: label.clone(),
                            action: "remove".to_string(),
                            status: "failed".to_string(),
                            summary: format!(
                                "Failed to remove the managed package copy for {}: {}",
                                label, error
                            ),
                        },
                    );
                }
            }
        })
        .map(|_| ())
    }
}
