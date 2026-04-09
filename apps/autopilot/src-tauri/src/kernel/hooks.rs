use crate::kernel::{capabilities, connectors, state};
use crate::models::{
    AppState, CapabilityRegistryEntry, CapabilityRegistrySnapshot, ExtensionContributionRecord,
    ExtensionManifestRecord, LocalEngineActivityRecord, SessionHookReceiptSummary,
    SessionHookRecord, SessionHookSnapshot,
};
use std::sync::Mutex;
use tauri::State;

fn normalize_optional_text(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn normalize_path_like(value: &str) -> Option<String> {
    let normalized = value.trim().replace('\\', "/");
    let normalized = normalized.trim_end_matches('/').to_string();
    if normalized.is_empty() {
        None
    } else {
        Some(normalized)
    }
}

fn humanize(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return "Unknown".to_string();
    }

    trimmed
        .replace(['_', '-'], " ")
        .split_whitespace()
        .map(|part| {
            let mut chars = part.chars();
            match chars.next() {
                Some(first) => first.to_ascii_uppercase().to_string() + chars.as_str(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn workspace_root_from_task(task: &crate::models::AgentTask) -> Option<String> {
    task.build_session
        .as_ref()
        .map(|session| session.workspace_root.clone())
        .or_else(|| {
            task.renderer_session
                .as_ref()
                .map(|session| session.workspace_root.clone())
        })
        .or_else(|| {
            task.studio_session
                .as_ref()
                .and_then(|session| session.workspace_root.clone())
        })
}

fn scope_matches_workspace(
    workspace_root: Option<&str>,
    manifest: &ExtensionManifestRecord,
) -> bool {
    let Some(workspace_root) = workspace_root.and_then(normalize_path_like) else {
        return false;
    };
    let manifest_roots = [
        manifest.root_path.as_str(),
        manifest.source_uri.as_str(),
        manifest.manifest_path.as_str(),
    ];

    manifest_roots.iter().any(|candidate| {
        let Some(candidate) = normalize_path_like(candidate) else {
            return false;
        };
        workspace_root.starts_with(&candidate) || candidate.starts_with(&workspace_root)
    })
}

fn hook_trigger_label(contribution: &ExtensionContributionRecord) -> String {
    if let Some(path) = contribution
        .path
        .as_ref()
        .and_then(|value| normalize_path_like(value))
    {
        format!("Trigger path: {}", path)
    } else if let Some(detail) = contribution
        .detail
        .as_ref()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
    {
        detail.to_string()
    } else {
        "Manifest hook contribution".to_string()
    }
}

fn hook_row_label(
    manifest: &ExtensionManifestRecord,
    contribution: &ExtensionContributionRecord,
) -> String {
    if let Some(path) = contribution
        .path
        .as_ref()
        .and_then(|value| normalize_path_like(value))
    {
        format!(
            "{} · {}",
            contribution.label,
            path.rsplit('/').next().unwrap_or(path.as_str())
        )
    } else {
        manifest
            .display_name
            .clone()
            .unwrap_or_else(|| manifest.name.clone())
    }
}

fn activity_is_hook_related(activity: &LocalEngineActivityRecord) -> bool {
    let family = activity.family.trim().to_ascii_lowercase();
    let title = activity.title.trim().to_ascii_lowercase();
    let operation = activity
        .operation
        .as_deref()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    let subject_kind = activity
        .subject_kind
        .as_deref()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();

    family.contains("worker")
        || family.contains("automation")
        || family.contains("hook")
        || title.contains("hook")
        || operation.contains("hook")
        || subject_kind.contains("hook")
}

fn build_hook_receipt_summary(activity: &LocalEngineActivityRecord) -> SessionHookReceiptSummary {
    let mut summary_parts = vec![humanize(&activity.family)];
    if let Some(operation) = activity
        .operation
        .as_ref()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
    {
        summary_parts.push(format!("Op {}", humanize(operation)));
    }
    if let Some(subject_kind) = activity
        .subject_kind
        .as_ref()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
    {
        summary_parts.push(format!("Subject {}", humanize(subject_kind)));
    }
    if let Some(backend_id) = activity
        .backend_id
        .as_ref()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
    {
        summary_parts.push(format!("Backend {}", backend_id));
    }
    if let Some(error_class) = activity
        .error_class
        .as_ref()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
    {
        summary_parts.push(format!("Error {}", error_class));
    }

    SessionHookReceiptSummary {
        title: activity.title.clone(),
        timestamp_ms: activity.timestamp_ms,
        tool_name: activity.tool_name.clone(),
        status: if activity.success {
            "success".to_string()
        } else {
            "error".to_string()
        },
        summary: summary_parts.join(" · "),
    }
}

fn build_approval_hook_receipt_summary(
    receipt: &connectors::ShieldApprovalHookReceipt,
) -> SessionHookReceiptSummary {
    SessionHookReceiptSummary {
        title: humanize(&receipt.hook_kind),
        timestamp_ms: receipt.timestamp_ms,
        tool_name: format!("{} · {}", receipt.connector_id, receipt.action_id),
        status: receipt.status.clone(),
        summary: receipt.summary.clone(),
    }
}

fn recent_runtime_hook_receipts(
    activities: &[LocalEngineActivityRecord],
    session_id: Option<&str>,
) -> Vec<SessionHookReceiptSummary> {
    let mut rows = activities
        .iter()
        .filter(|activity| activity_is_hook_related(activity))
        .filter(|activity| {
            session_id
                .map(|value| activity.session_id == value)
                .unwrap_or(true)
        })
        .map(build_hook_receipt_summary)
        .collect::<Vec<_>>();

    if rows.is_empty() && session_id.is_some() {
        rows = activities
            .iter()
            .filter(|activity| activity_is_hook_related(activity))
            .map(build_hook_receipt_summary)
            .collect::<Vec<_>>();
    }

    rows.sort_by(|left, right| right.timestamp_ms.cmp(&left.timestamp_ms));
    rows
}

fn recent_approval_hook_receipts(
    approval_snapshot: &connectors::ShieldRememberedApprovalSnapshot,
) -> Vec<SessionHookReceiptSummary> {
    let mut rows = approval_snapshot
        .recent_receipts
        .iter()
        .map(build_approval_hook_receipt_summary)
        .collect::<Vec<_>>();
    rows.sort_by(|left, right| right.timestamp_ms.cmp(&left.timestamp_ms));
    rows
}

fn merge_recent_hook_receipts(
    mut runtime_rows: Vec<SessionHookReceiptSummary>,
    approval_rows: Vec<SessionHookReceiptSummary>,
) -> Vec<SessionHookReceiptSummary> {
    runtime_rows.extend(approval_rows);
    runtime_rows.sort_by(|left, right| right.timestamp_ms.cmp(&left.timestamp_ms));
    runtime_rows.truncate(6);
    runtime_rows
}

pub(crate) fn build_session_hook_snapshot_from_parts(
    entries: &[CapabilityRegistryEntry],
    extension_manifests: &[ExtensionManifestRecord],
    recent_activity: &[LocalEngineActivityRecord],
    approval_snapshot: connectors::ShieldRememberedApprovalSnapshot,
    session_id: Option<String>,
    workspace_root: Option<String>,
) -> SessionHookSnapshot {
    let extension_lookup = entries
        .iter()
        .filter(|entry| entry.kind == "extension")
        .map(|entry| (entry.entry_id.clone(), entry.clone()))
        .collect::<std::collections::HashMap<_, _>>();

    let mut hooks = extension_manifests
        .iter()
        .flat_map(|manifest| {
            manifest
                .contributions
                .iter()
                .filter(|contribution| contribution.kind == "hooks")
                .map(|contribution| {
                    let entry_id = format!("extension:{}", manifest.extension_id);
                    let capability_entry = extension_lookup.get(&entry_id);
                    let owner_label = manifest
                        .display_name
                        .clone()
                        .unwrap_or_else(|| manifest.name.clone());
                    let in_workspace = scope_matches_workspace(workspace_root.as_deref(), manifest);
                    let why_active = if in_workspace && manifest.enabled {
                        format!(
                            "This hook contribution is tracked from the current workspace and can shape live runtime behavior for the active shell."
                        )
                    } else if manifest.enabled {
                        format!(
                            "This hook contribution is active in the runtime inventory and can influence governed automation behavior."
                        )
                    } else {
                        format!(
                            "This hook contribution exists on disk, but its source is currently disabled."
                        )
                    };

                    SessionHookRecord {
                        hook_id: format!(
                            "{}:{}",
                            manifest.extension_id,
                            contribution
                                .path
                                .clone()
                                .unwrap_or_else(|| contribution.kind.clone())
                        ),
                        entry_id: capability_entry.map(|entry| entry.entry_id.clone()),
                        label: hook_row_label(manifest, contribution),
                        owner_label,
                        source_label: manifest.source_label.clone(),
                        source_kind: manifest.source_kind.clone(),
                        source_uri: Some(manifest.source_uri.clone()),
                        contribution_path: contribution.path.clone(),
                        trigger_label: hook_trigger_label(contribution),
                        enabled: manifest.enabled,
                        status_label: if manifest.enabled {
                            "Enabled".to_string()
                        } else {
                            "Disabled".to_string()
                        },
                        trust_posture: manifest.trust_posture.clone(),
                        governed_profile: manifest.governed_profile.clone(),
                        authority_tier_label: capability_entry
                            .map(|entry| entry.authority.tier_label.clone())
                            .unwrap_or_else(|| humanize(&manifest.trust_posture)),
                        availability_label: capability_entry
                            .map(|entry| entry.lease.availability_label.clone())
                            .unwrap_or_else(|| {
                                if manifest.enabled {
                                    "Ready".to_string()
                                } else {
                                    "Disabled".to_string()
                                }
                            }),
                        session_scope_label: if in_workspace {
                            "Matches current workspace".to_string()
                        } else if session_id.is_some() {
                            "Runtime-visible in this session".to_string()
                        } else {
                            "Runtime-visible hook contribution".to_string()
                        },
                        why_active,
                    }
                })
        })
        .collect::<Vec<_>>();

    hooks.sort_by(|left, right| {
        right
            .enabled
            .cmp(&left.enabled)
            .then_with(|| left.owner_label.cmp(&right.owner_label))
            .then_with(|| left.label.cmp(&right.label))
    });

    let runtime_receipts = recent_runtime_hook_receipts(recent_activity, session_id.as_deref());
    let approval_receipts = recent_approval_hook_receipts(&approval_snapshot);
    let recent_receipts =
        merge_recent_hook_receipts(runtime_receipts.clone(), approval_receipts.clone());
    let active_hook_count = hooks.iter().filter(|hook| hook.enabled).count();
    let disabled_hook_count = hooks.len().saturating_sub(active_hook_count);

    SessionHookSnapshot {
        generated_at_ms: state::now(),
        session_id,
        workspace_root,
        active_hook_count,
        disabled_hook_count,
        runtime_receipt_count: runtime_receipts.len(),
        approval_receipt_count: approval_receipts.len(),
        hooks,
        recent_receipts,
    }
}

fn build_session_hook_snapshot(
    snapshot: CapabilityRegistrySnapshot,
    approval_snapshot: connectors::ShieldRememberedApprovalSnapshot,
    session_id: Option<String>,
    workspace_root: Option<String>,
) -> SessionHookSnapshot {
    build_session_hook_snapshot_from_parts(
        &snapshot.entries,
        &snapshot.extension_manifests,
        &snapshot.local_engine.recent_activity,
        approval_snapshot,
        session_id,
        workspace_root,
    )
}

#[tauri::command]
pub async fn get_session_hook_snapshot(
    state: State<'_, Mutex<AppState>>,
    policy_manager: State<'_, connectors::ShieldPolicyManager>,
    session_id: Option<String>,
    workspace_root: Option<String>,
) -> Result<SessionHookSnapshot, String> {
    let current_task = state
        .lock()
        .map_err(|_| "Failed to lock app state.".to_string())?
        .current_task
        .clone();

    let session_id = normalize_optional_text(session_id).or_else(|| {
        current_task
            .as_ref()
            .and_then(|task| task.session_id.clone().or_else(|| Some(task.id.clone())))
    });
    let workspace_root = normalize_optional_text(workspace_root)
        .or_else(|| current_task.as_ref().and_then(workspace_root_from_task));

    let snapshot =
        capabilities::get_capability_registry_snapshot(state, policy_manager.clone()).await?;
    let approval_snapshot = policy_manager.approval_snapshot();
    Ok(build_session_hook_snapshot(
        snapshot,
        approval_snapshot,
        session_id,
        workspace_root,
    ))
}

#[cfg(test)]
mod tests {
    use super::build_session_hook_snapshot;
    use crate::kernel::connectors::{ShieldApprovalHookReceipt, ShieldRememberedApprovalSnapshot};
    use crate::models::{
        CapabilityAuthorityDescriptor, CapabilityLeaseDescriptor, CapabilityRegistryEntry,
        CapabilityRegistrySnapshot, CapabilityRegistrySummary, ExtensionContributionRecord,
        ExtensionManifestRecord, LocalEngineApiConfig, LocalEngineBackendPolicyConfig,
        LocalEngineControlPlane, LocalEngineMemoryConfig, LocalEngineResponseConfig,
        LocalEngineRuntimeProfile, LocalEngineSnapshot, LocalEngineStorageConfig,
        LocalEngineWatchdogConfig, SkillSourceDiscoveredSkill,
    };

    fn empty_local_engine_snapshot() -> LocalEngineSnapshot {
        LocalEngineSnapshot {
            generated_at_ms: 0,
            total_native_tools: 0,
            pending_control_count: 0,
            pending_approval_count: 0,
            active_issue_count: 0,
            capabilities: Vec::new(),
            compatibility_routes: Vec::new(),
            pending_controls: Vec::new(),
            jobs: Vec::new(),
            recent_activity: Vec::new(),
            registry_models: Vec::new(),
            managed_backends: Vec::new(),
            gallery_catalogs: Vec::new(),
            worker_templates: Vec::new(),
            agent_playbooks: Vec::new(),
            parent_playbook_runs: Vec::new(),
            control_plane_schema_version: 1,
            control_plane_profile_id: "test".to_string(),
            control_plane_migrations: Vec::new(),
            control_plane: LocalEngineControlPlane {
                runtime: LocalEngineRuntimeProfile {
                    mode: "local".to_string(),
                    endpoint: "http://127.0.0.1:11434/v1".to_string(),
                    default_model: "none".to_string(),
                    baseline_role: "operator".to_string(),
                    kernel_authority: "contained_local".to_string(),
                },
                storage: LocalEngineStorageConfig {
                    models_path: ".".to_string(),
                    backends_path: ".".to_string(),
                    artifacts_path: ".".to_string(),
                    cache_path: ".".to_string(),
                },
                watchdog: LocalEngineWatchdogConfig {
                    enabled: false,
                    idle_check_enabled: false,
                    idle_timeout: "0s".to_string(),
                    busy_check_enabled: false,
                    busy_timeout: "0s".to_string(),
                    check_interval: "0s".to_string(),
                    force_eviction_when_busy: false,
                    lru_eviction_max_retries: 0,
                    lru_eviction_retry_interval: "0s".to_string(),
                },
                memory: LocalEngineMemoryConfig {
                    reclaimer_enabled: false,
                    threshold_percent: 0,
                    prefer_gpu: false,
                    target_resource: "cpu".to_string(),
                },
                backend_policy: LocalEngineBackendPolicyConfig {
                    max_concurrency: 1,
                    max_queued_requests: 1,
                    parallel_backend_loads: 1,
                    allow_parallel_requests: false,
                    health_probe_interval: "0s".to_string(),
                    log_level: "info".to_string(),
                    auto_shutdown_on_idle: false,
                },
                responses: LocalEngineResponseConfig {
                    retain_receipts_days: 1,
                    persist_artifacts: false,
                    allow_streaming: false,
                    store_request_previews: false,
                },
                api: LocalEngineApiConfig {
                    bind_address: "127.0.0.1:0".to_string(),
                    remote_access_enabled: false,
                    expose_compat_routes: false,
                    cors_mode: "off".to_string(),
                    auth_mode: "none".to_string(),
                },
                launcher: Default::default(),
                galleries: Vec::new(),
                environment: Vec::new(),
                notes: Vec::new(),
            },
            managed_settings: crate::models::LocalEngineManagedSettingsSnapshot {
                sync_status: "local_only".to_string(),
                summary: "No managed settings active.".to_string(),
                ..Default::default()
            },
            staged_operations: Vec::new(),
        }
    }

    #[test]
    fn session_hook_snapshot_collects_manifest_hooks_and_recent_receipts() {
        let mut local_engine = empty_local_engine_snapshot();
        local_engine
            .recent_activity
            .push(crate::models::LocalEngineActivityRecord {
                event_id: "evt-1".to_string(),
                session_id: "session-123".to_string(),
                family: "workers".to_string(),
                title: "Hook worker evaluated".to_string(),
                tool_name: "hook_worker".to_string(),
                timestamp_ms: 42,
                success: true,
                operation: Some("hook_eval".to_string()),
                subject_kind: Some("hook".to_string()),
                subject_id: Some("hook://alpha".to_string()),
                backend_id: None,
                error_class: None,
            });

        let snapshot = CapabilityRegistrySnapshot {
            generated_at_ms: 1,
            summary: CapabilityRegistrySummary {
                generated_at_ms: 1,
                total_entries: 1,
                connector_count: 0,
                connected_connector_count: 0,
                runtime_skill_count: 0,
                tracked_source_count: 1,
                filesystem_skill_count: 0,
                extension_count: 1,
                model_count: 0,
                backend_count: 0,
                native_family_count: 0,
                pending_engine_control_count: 0,
                active_issue_count: 0,
                authoritative_source_count: 1,
            },
            entries: vec![CapabilityRegistryEntry {
                entry_id: "extension:manifest:alpha".to_string(),
                kind: "extension".to_string(),
                label: "Alpha Hooks".to_string(),
                summary: "Alpha summary".to_string(),
                source_kind: "tracked_source".to_string(),
                source_label: "Workspace source".to_string(),
                source_uri: Some("/workspace/plugin".to_string()),
                trust_posture: "local_only".to_string(),
                governed_profile: Some("automation_bridge".to_string()),
                availability: "ready".to_string(),
                status_label: "Ready".to_string(),
                why_selectable: "Selectable".to_string(),
                governing_family_id: None,
                related_governing_entry_ids: Vec::new(),
                governing_family_hints: Vec::new(),
                runtime_target: Some("runtime_bridge".to_string()),
                lease_mode: Some("governed_extension".to_string()),
                authority: CapabilityAuthorityDescriptor {
                    tier_id: "automation".to_string(),
                    tier_label: "Automation bridge".to_string(),
                    governed_profile_id: Some("automation_bridge".to_string()),
                    governed_profile_label: Some("Automation bridge".to_string()),
                    summary: "summary".to_string(),
                    detail: "detail".to_string(),
                    signals: Vec::new(),
                },
                lease: CapabilityLeaseDescriptor {
                    availability: "ready".to_string(),
                    availability_label: "Ready".to_string(),
                    runtime_target_id: Some("runtime_bridge".to_string()),
                    runtime_target_label: Some("Runtime bridge".to_string()),
                    mode_id: Some("governed_extension".to_string()),
                    mode_label: Some("Governed extension".to_string()),
                    summary: "summary".to_string(),
                    detail: "detail".to_string(),
                    requires_auth: false,
                    signals: Vec::new(),
                },
            }],
            connectors: Vec::new(),
            skill_catalog: Vec::new(),
            skill_sources: Vec::new(),
            extension_manifests: vec![ExtensionManifestRecord {
                extension_id: "manifest:alpha".to_string(),
                manifest_kind: "codex_plugin".to_string(),
                manifest_path: "/workspace/plugin/.codex-plugin/plugin.json".to_string(),
                root_path: "/workspace/plugin".to_string(),
                source_label: "Workspace source".to_string(),
                source_uri: "/workspace/plugin".to_string(),
                source_kind: "tracked_source".to_string(),
                enabled: true,
                name: "alpha".to_string(),
                display_name: Some("Alpha Hooks".to_string()),
                version: None,
                description: None,
                developer_name: None,
                author_name: None,
                author_email: None,
                author_url: None,
                category: None,
                trust_posture: "local_only".to_string(),
                governed_profile: "automation_bridge".to_string(),
                homepage: None,
                repository: None,
                license: None,
                keywords: Vec::new(),
                capabilities: Vec::new(),
                default_prompts: Vec::new(),
                contributions: vec![ExtensionContributionRecord {
                    kind: "hooks".to_string(),
                    label: "Hooks".to_string(),
                    path: Some("hooks/main.ts".to_string()),
                    item_count: Some(1),
                    detail: Some("Runtime automation hooks".to_string()),
                }],
                filesystem_skills: Vec::<SkillSourceDiscoveredSkill>::new(),
                marketplace_name: None,
                marketplace_display_name: None,
                marketplace_category: None,
                marketplace_installation_policy: None,
                marketplace_authentication_policy: None,
                marketplace_products: Vec::new(),
                marketplace_available_version: None,
                marketplace_catalog_issued_at_ms: None,
                marketplace_catalog_expires_at_ms: None,
                marketplace_catalog_refreshed_at_ms: None,
                marketplace_catalog_refresh_source: None,
                marketplace_catalog_channel: None,
                marketplace_catalog_source_id: None,
                marketplace_catalog_source_label: None,
                marketplace_catalog_source_uri: None,
                marketplace_package_url: None,
                marketplace_catalog_refresh_bundle_id: None,
                marketplace_catalog_refresh_bundle_label: None,
                marketplace_catalog_refresh_bundle_issued_at_ms: None,
                marketplace_catalog_refresh_bundle_expires_at_ms: None,
                marketplace_catalog_refresh_available_version: None,
                marketplace_verification_status: None,
                marketplace_signature_algorithm: None,
                marketplace_signer_identity: None,
                marketplace_publisher_id: None,
                marketplace_signing_key_id: None,
                marketplace_publisher_label: None,
                marketplace_publisher_trust_status: None,
                marketplace_publisher_trust_source: None,
                marketplace_publisher_root_id: None,
                marketplace_publisher_root_label: None,
                marketplace_authority_bundle_id: None,
                marketplace_authority_bundle_label: None,
                marketplace_authority_bundle_issued_at_ms: None,
                marketplace_authority_trust_bundle_id: None,
                marketplace_authority_trust_bundle_label: None,
                marketplace_authority_trust_bundle_issued_at_ms: None,
                marketplace_authority_trust_bundle_expires_at_ms: None,
                marketplace_authority_trust_bundle_status: None,
                marketplace_authority_trust_issuer_id: None,
                marketplace_authority_trust_issuer_label: None,
                marketplace_authority_id: None,
                marketplace_authority_label: None,
                marketplace_publisher_statement_issued_at_ms: None,
                marketplace_publisher_trust_detail: None,
                marketplace_publisher_revoked_at_ms: None,
                marketplace_verification_error: None,
                marketplace_verified_at_ms: None,
                marketplace_verification_source: None,
                marketplace_verified_digest_sha256: None,
                marketplace_trust_score_label: None,
                marketplace_trust_score_source: None,
                marketplace_trust_recommendation: None,
            }],
            local_engine,
        };

        let hook_snapshot = build_session_hook_snapshot(
            snapshot,
            ShieldRememberedApprovalSnapshot {
                generated_at_ms: 1,
                active_decision_count: 0,
                recent_receipt_count: 1,
                decisions: Vec::new(),
                recent_receipts: vec![ShieldApprovalHookReceipt {
                    receipt_id: "approval-1".to_string(),
                    timestamp_ms: 84,
                    hook_kind: "pre_run_approval_hook".to_string(),
                    status: "matched".to_string(),
                    summary: "Used remembered approval for Mail read.".to_string(),
                    connector_id: "mail.primary".to_string(),
                    action_id: "mail.read_latest".to_string(),
                    decision_id: Some("decision-1".to_string()),
                }],
            },
            Some("session-123".to_string()),
            Some("/workspace".to_string()),
        );

        assert_eq!(hook_snapshot.active_hook_count, 1);
        assert_eq!(hook_snapshot.runtime_receipt_count, 1);
        assert_eq!(hook_snapshot.approval_receipt_count, 1);
        assert_eq!(hook_snapshot.hooks.len(), 1);
        assert_eq!(
            hook_snapshot.hooks[0].authority_tier_label,
            "Automation bridge"
        );
        assert_eq!(
            hook_snapshot.hooks[0].session_scope_label,
            "Matches current workspace"
        );
        assert_eq!(
            hook_snapshot.recent_receipts[0].tool_name,
            "mail.primary · mail.read_latest"
        );
        assert_eq!(hook_snapshot.recent_receipts[1].tool_name, "hook_worker");
    }
}
