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
#[path = "hooks/tests.rs"]
mod tests;
