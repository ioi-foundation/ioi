use crate::kernel::connectors::{
    policy_state_path_for, ShieldPolicyManager, ShieldRememberApprovalInput,
};
use crate::kernel::data::{default_agent_playbooks, default_local_engine_control_plane_document};
use crate::kernel::events::build_event;
use crate::models::{
    AgentPhase, AgentTask, Artifact, ArtifactRef, ArtifactType, BuildArtifactSession, ChatMessage,
    ClarificationRequest, CredentialRequest, EventStatus, EventType, GateInfo,
    SessionBackgroundTaskRecord, SessionChecklistItem, SessionCompactionPolicy, SessionSummary,
    StudioBuildReceipt, StudioCodeWorkerLease,
};
use crate::open_or_create_memory_runtime;
use crate::orchestrator::store::save_local_session_summary;
use crate::orchestrator::{
    append_artifact, append_event, get_local_sessions, save_local_task_state,
};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use ioi_api::crypto::{SerializableKey, SigningKeyPair as _};
use ioi_crypto::sign::eddsa::Ed25519KeyPair;
use serde::Serialize;
use std::collections::HashSet;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use uuid::Uuid;

fn env_text(key: &str) -> Option<String> {
    env::var(key)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn bool_env(key: &str) -> bool {
    env::var(key)
        .ok()
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

fn cli_data_dir() -> Result<PathBuf, String> {
    if let Some(override_path) = env_text("AUTOPILOT_DATA_DIR") {
        return Ok(PathBuf::from(override_path));
    }

    let home = env_text("HOME").ok_or_else(|| "HOME is not set.".to_string())?;
    let mut base = PathBuf::from(home);
    base.push(".local/share/ai.ioi.autopilot");

    let profile = env_text("AUTOPILOT_DATA_PROFILE").or_else(|| {
        if bool_env("AUTOPILOT_LOCAL_GPU_DEV") {
            Some("desktop-localgpu".to_string())
        } else {
            None
        }
    });

    if let Some(profile) = profile {
        Ok(base.join("profiles").join(profile))
    } else {
        Ok(base)
    }
}

fn now_iso() -> String {
    chrono::Utc::now().to_rfc3339()
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SeededReplProof {
    session_id: String,
    workspace_root: String,
    title: String,
    current_step: String,
    phase: String,
    history_count: usize,
    artifact_count: usize,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SeededManagedSettingsProof {
    output_path: String,
    channel_id: String,
    label: String,
    authority_id: String,
    profile_id: String,
    default_model: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SeededDurabilityPortfolioProof {
    data_dir: String,
    workspace_root: String,
    session_ids: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SeededAuthorityProof {
    data_dir: String,
    workspace_root: String,
    session_id: String,
    current_profile_id: String,
    remembered_decision_count: usize,
    recent_receipt_count: usize,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SeededTaskGraphProof {
    data_dir: String,
    workspace_root: String,
    parent_session_id: String,
    child_session_ids: Vec<String>,
    playbook_ids: Vec<String>,
    artifact_ids: Vec<String>,
}

#[derive(Debug, Clone, Copy)]
enum SeedBlocker {
    Approval,
    Clarification,
    Credential,
}

#[derive(Debug, Clone)]
struct SeedOptions {
    phase: AgentPhase,
    current_step: String,
    history_count: usize,
    blocker: Option<SeedBlocker>,
    artifact_title: Option<String>,
}

fn build_seed_task(
    session_id: &str,
    intent: &str,
    workspace_root: &str,
    options: &SeedOptions,
) -> AgentTask {
    let trimmed_root = workspace_root.trim();
    let receipt = StudioBuildReceipt {
        receipt_id: Uuid::new_v4().to_string(),
        kind: "proof_seed".to_string(),
        title: "Seeded REPL proof workspace".to_string(),
        status: "success".to_string(),
        summary: format!(
            "Seeded a retained workspace-backed session for CLI attach proof at {}.",
            trimmed_root
        ),
        started_at: now_iso(),
        finished_at: Some(now_iso()),
        artifact_ids: Vec::new(),
        command: None,
        exit_code: Some(0),
        duration_ms: Some(0),
        failure_class: None,
        replay_classification: Some("replay_safe".to_string()),
    };

    let build_session = BuildArtifactSession {
        session_id: Uuid::new_v4().to_string(),
        studio_session_id: Uuid::new_v4().to_string(),
        workspace_root: trimmed_root.to_string(),
        entry_document: "README.md".to_string(),
        preview_url: None,
        preview_process_id: None,
        scaffold_recipe_id: "repl-proof-seed".to_string(),
        presentation_variant_id: None,
        package_manager: "npm".to_string(),
        build_status: "ready".to_string(),
        verification_status: "ready".to_string(),
        receipts: vec![receipt],
        current_worker_execution: StudioCodeWorkerLease {
            backend: "proof".to_string(),
            planner_authority: "kernel".to_string(),
            allowed_mutation_scope: vec![trimmed_root.to_string()],
            allowed_command_classes: vec!["shell".to_string()],
            execution_state: "idle".to_string(),
            retry_classification: None,
            last_summary: Some("Workspace-backed REPL proof seed".to_string()),
        },
        current_lens: "code".to_string(),
        available_lenses: vec!["code".to_string()],
        ready_lenses: vec!["code".to_string()],
        retry_count: 0,
        last_failure_summary: None,
    };

    let mut history = Vec::new();
    let history_count = options.history_count.max(1);
    for index in 0..history_count {
        history.push(ChatMessage {
            role: if index % 2 == 0 {
                "assistant".to_string()
            } else {
                "user".to_string()
            },
            text: if index + 1 == history_count {
                options.current_step.clone()
            } else {
                format!("Proof history message {}", index + 1)
            },
            timestamp: 1_700_000_000_000 + index as u64,
        });
    }

    let mut artifacts = Vec::new();
    if let Some(title) = options.artifact_title.as_deref() {
        artifacts.push(Artifact {
            artifact_id: Uuid::new_v4().to_string(),
            created_at: now_iso(),
            thread_id: session_id.to_string(),
            artifact_type: ArtifactType::Report,
            title: title.to_string(),
            description: "Seeded proof artifact".to_string(),
            content_ref: "proof://artifact".to_string(),
            metadata: serde_json::json!({"source": "repl_proof"}),
            version: Some(1),
            parent_artifact_id: None,
        });
    }

    let (phase, gate_info, pending_request_hash, credential_request, clarification_request) =
        match options.blocker {
            Some(SeedBlocker::Approval) => (
                AgentPhase::Gate,
                Some(GateInfo {
                    title: "Approve protected operation".to_string(),
                    description:
                        "The run is waiting for approval to continue the protected operation."
                            .to_string(),
                    risk: "medium".to_string(),
                    approve_label: Some("Approve".to_string()),
                    deny_label: Some("Deny".to_string()),
                    deadline_ms: None,
                    surface_label: Some("Spotlight".to_string()),
                    scope_label: Some("repo".to_string()),
                    operation_label: Some("apply changes".to_string()),
                    target_label: Some("README.md".to_string()),
                    operator_note: Some(
                        "Resume should preserve this approval context.".to_string(),
                    ),
                    pii: None,
                }),
                Some("proof-gate-hash".to_string()),
                None,
                None,
            ),
            Some(SeedBlocker::Clarification) => (
                AgentPhase::Running,
                None,
                None,
                None,
                Some(ClarificationRequest {
                    kind: "question".to_string(),
                    question: "Should the proof run preserve unresolved clarification context?"
                        .to_string(),
                    tool_name: "proof".to_string(),
                    failure_class: None,
                    evidence_snippet: None,
                    context_hint: None,
                    options: Vec::new(),
                    allow_other: false,
                }),
            ),
            Some(SeedBlocker::Credential) => (
                AgentPhase::Running,
                None,
                None,
                Some(CredentialRequest {
                    kind: "oauth".to_string(),
                    prompt: "Provide a proof credential before the run can continue.".to_string(),
                    one_time: true,
                }),
                None,
            ),
            None => (options.phase.clone(), None, None, None, None),
        };

    let mut task = AgentTask {
        id: session_id.to_string(),
        intent: intent.trim().to_string(),
        agent: "Autopilot".to_string(),
        phase,
        progress: 10,
        total_steps: 20,
        current_step: options.current_step.clone(),
        gate_info,
        receipt: None,
        visual_hash: None,
        pending_request_hash,
        session_id: Some(session_id.to_string()),
        credential_request,
        clarification_request,
        session_checklist: Vec::new(),
        background_tasks: Vec::new(),
        history,
        events: Vec::new(),
        artifacts,
        studio_session: None,
        studio_outcome: None,
        renderer_session: None,
        build_session: Some(build_session),
        run_bundle_id: None,
        processed_steps: HashSet::new(),
        swarm_tree: Vec::new(),
        generation: 0,
        lineage_id: "proof".to_string(),
        fitness_score: 0.0,
    };
    task.sync_runtime_views();
    task
}

fn print_json<T: Serialize>(value: &T) -> Result<(), String> {
    let text = serde_json::to_string_pretty(value)
        .map_err(|error| format!("JSON encode failed: {error}"))?;
    println!("{text}");
    Ok(())
}

fn required_flag(args: &mut Vec<String>, flag: &str) -> Result<String, String> {
    let Some(index) = args.iter().position(|value| value == flag) else {
        return Err(format!("Missing required flag '{}'.", flag));
    };
    if index + 1 >= args.len() {
        return Err(format!("Missing value for flag '{}'.", flag));
    }
    let value = args.remove(index + 1);
    args.remove(index);
    Ok(value)
}

fn optional_flag_value(args: &mut Vec<String>, flag: &str) -> Result<Option<String>, String> {
    let Some(index) = args.iter().position(|value| value == flag) else {
        return Ok(None);
    };
    if index + 1 >= args.len() {
        return Err(format!("Missing value for flag '{}'.", flag));
    }
    let value = args.remove(index + 1);
    args.remove(index);
    Ok(Some(value))
}

fn parse_phase(value: Option<String>) -> Result<AgentPhase, String> {
    match value
        .unwrap_or_else(|| "running".to_string())
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "idle" => Ok(AgentPhase::Idle),
        "running" => Ok(AgentPhase::Running),
        "gate" => Ok(AgentPhase::Gate),
        "complete" => Ok(AgentPhase::Complete),
        "failed" => Ok(AgentPhase::Failed),
        other => Err(format!("Unknown phase '{}'.", other)),
    }
}

fn parse_blocker(value: Option<String>) -> Result<Option<SeedBlocker>, String> {
    match value
        .unwrap_or_else(|| "none".to_string())
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "none" => Ok(None),
        "approval" => Ok(Some(SeedBlocker::Approval)),
        "clarification" => Ok(Some(SeedBlocker::Clarification)),
        "credential" => Ok(Some(SeedBlocker::Credential)),
        other => Err(format!("Unknown blocker '{}'.", other)),
    }
}

fn seed_managed_settings_fixture(mut args: Vec<String>) -> Result<(), String> {
    let output_path = required_flag(&mut args, "--output")?;
    let channel_id =
        optional_flag_value(&mut args, "--channel-id")?.unwrap_or_else(|| "ops-stable".to_string());
    let label =
        optional_flag_value(&mut args, "--label")?.unwrap_or_else(|| "Ops Stable".to_string());
    let authority_id = optional_flag_value(&mut args, "--authority-id")?
        .unwrap_or_else(|| "managed.settings.root".to_string());
    let authority_label = optional_flag_value(&mut args, "--authority-label")?
        .unwrap_or_else(|| "Managed settings root".to_string());
    let profile_id = optional_flag_value(&mut args, "--profile-id")?
        .unwrap_or_else(|| "managed.settings.primary".to_string());
    let source_uri = optional_flag_value(&mut args, "--source-uri")?
        .unwrap_or_else(|| format!("fixture://managed-settings/{}", channel_id));
    let default_model = optional_flag_value(&mut args, "--default-model")?
        .unwrap_or_else(|| "gpt-4.1-mini".to_string());
    let release_channel = optional_flag_value(&mut args, "--release-channel")?
        .unwrap_or_else(|| "stable".to_string());
    let precedence = optional_flag_value(&mut args, "--precedence")?
        .map(|value| {
            value
                .parse::<i32>()
                .map_err(|error| format!("Invalid value for '--precedence': {}", error))
        })
        .transpose()?
        .unwrap_or(10);
    if !args.is_empty() {
        return Err(format!("Unexpected arguments: {}", args.join(" ")));
    }

    let keypair = Ed25519KeyPair::generate().map_err(|error| {
        format!(
            "Failed to generate managed settings signing keypair: {}",
            error
        )
    })?;
    let issued_at_ms = chrono::Utc::now().timestamp_millis().max(0) as u64;
    let mut document = default_local_engine_control_plane_document();
    document.profile_id = profile_id.clone();
    document.control_plane.runtime.default_model = default_model.clone();
    document.control_plane.launcher.release_channel = release_channel;

    let message = crate::kernel::local_engine::managed_settings_channel_message(
        &authority_id,
        &channel_id,
        &label,
        &source_uri,
        precedence,
        Some(issued_at_ms),
        None,
        &document,
    )?;
    let signature = keypair.sign(&message).map_err(|error| {
        format!(
            "Failed to sign managed settings fixture for channel '{}': {}",
            channel_id, error
        )
    })?;

    let fixture = serde_json::json!({
        "channels": [
            {
                "authorityId": authority_id,
                "authorityLabel": authority_label,
                "channelId": channel_id,
                "label": label,
                "sourceUri": source_uri,
                "publicKey": BASE64_STANDARD.encode(keypair.public_key().to_bytes()),
                "signature": BASE64_STANDARD.encode(signature.to_bytes()),
                "signatureAlgorithm": "ed25519",
                "precedence": precedence,
                "issuedAtMs": issued_at_ms,
                "document": document,
            }
        ]
    });

    let output = PathBuf::from(output_path);
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent).map_err(|error| {
            format!(
                "Failed to create parent directory for '{}': {}",
                output.display(),
                error
            )
        })?;
    }
    fs::write(
        &output,
        serde_json::to_vec_pretty(&fixture)
            .map_err(|error| format!("Failed to encode managed settings fixture: {}", error))?,
    )
    .map_err(|error| {
        format!(
            "Failed to write managed settings fixture '{}': {}",
            output.display(),
            error
        )
    })?;

    print_json(&SeededManagedSettingsProof {
        output_path: output.display().to_string(),
        channel_id,
        label,
        authority_id,
        profile_id,
        default_model,
    })
}

fn stored_summary(
    memory_runtime: &Arc<ioi_memory::MemoryRuntime>,
    session_id: &str,
) -> Result<SessionSummary, String> {
    get_local_sessions(memory_runtime)
        .into_iter()
        .find(|summary| summary.session_id == session_id)
        .ok_or_else(|| format!("Session '{}' was not persisted.", session_id))
}

fn seed_durability_portfolio(mut args: Vec<String>) -> Result<(), String> {
    let root = required_flag(&mut args, "--root")?;
    if !args.is_empty() {
        return Err(format!("Unexpected arguments: {}", args.join(" ")));
    }

    let workspace_root = Path::new(&root).canonicalize().map_err(|error| {
        format!(
            "Failed to canonicalize workspace root '{}': {}",
            root, error
        )
    })?;
    let data_dir = cli_data_dir()?;
    let memory_runtime = Arc::new(open_or_create_memory_runtime(Path::new(&data_dir))?);
    let root_text = workspace_root.to_string_lossy().to_string();

    let ready_session_id = "durability-proof-ready";
    let ready_task = build_seed_task(
        ready_session_id,
        "Retain a replay-safe session summary",
        &root_text,
        &SeedOptions {
            phase: AgentPhase::Complete,
            current_step: "Final replay-safe report ready.".to_string(),
            history_count: 4,
            blocker: None,
            artifact_title: Some("Replay-safe report".to_string()),
        },
    );
    save_local_task_state(&memory_runtime, &ready_task);
    let ready_summary = stored_summary(&memory_runtime, ready_session_id)?;
    crate::kernel::session::compact_retained_session_for_sessions(
        &memory_runtime,
        vec![ready_summary.clone()],
        Some(ready_session_id),
        Some(ready_session_id),
        None,
    )?;
    crate::kernel::session::sync_team_memory_for_sessions(
        &memory_runtime,
        vec![ready_summary.clone()],
        Some(ready_session_id),
        Some(ready_session_id),
        Some("Spotlight".to_string()),
        Some("operator".to_string()),
        false,
    )?;

    let stale_session_id = "durability-proof-stale";
    let stale_task = build_seed_task(
        stale_session_id,
        "Retain a session that later drifts after compaction",
        &root_text,
        &SeedOptions {
            phase: AgentPhase::Complete,
            current_step: "Older retained summary before drift.".to_string(),
            history_count: 24,
            blocker: None,
            artifact_title: Some("Stale durability note".to_string()),
        },
    );
    save_local_task_state(&memory_runtime, &stale_task);
    let stale_summary = stored_summary(&memory_runtime, stale_session_id)?;
    crate::kernel::session::compact_retained_session_for_sessions(
        &memory_runtime,
        vec![stale_summary.clone()],
        Some(stale_session_id),
        Some(stale_session_id),
        None,
    )?;
    let mut stale_task_after_compaction = stale_task.clone();
    stale_task_after_compaction.current_step =
        "New follow-up for ops@example.com token=sk-proof-1234567890".to_string();
    stale_task_after_compaction.history.push(ChatMessage {
        role: "assistant".to_string(),
        text: "Post-compaction follow-up for ops@example.com token=sk-proof-1234567890".to_string(),
        timestamp: crate::kernel::state::now() + 60_000,
    });
    save_local_task_state(&memory_runtime, &stale_task_after_compaction);
    let stale_summary_after_compaction = SessionSummary {
        session_id: stale_summary.session_id.clone(),
        title: stale_summary.title.clone(),
        timestamp: crate::kernel::state::now() + 60_000,
        phase: Some(stale_task_after_compaction.phase.clone()),
        current_step: Some(stale_task_after_compaction.current_step.clone()),
        resume_hint: stale_summary.resume_hint.clone(),
        workspace_root: stale_summary.workspace_root.clone(),
    };
    save_local_session_summary(&memory_runtime, stale_summary_after_compaction.clone());
    crate::kernel::session::sync_team_memory_for_sessions(
        &memory_runtime,
        vec![stale_summary_after_compaction.clone()],
        Some(stale_session_id),
        Some(stale_session_id),
        Some("REPL".to_string()),
        Some("operator".to_string()),
        false,
    )?;

    let degraded_session_id = "durability-proof-degraded";
    let mut degraded_task = build_seed_task(
        degraded_session_id,
        "Retain a session with degraded resume safety",
        &root_text,
        &SeedOptions {
            phase: AgentPhase::Gate,
            current_step: "Waiting on protected deploy approval.".to_string(),
            history_count: 3,
            blocker: Some(SeedBlocker::Approval),
            artifact_title: Some("Protected deploy note".to_string()),
        },
    );
    degraded_task.session_checklist.push(SessionChecklistItem {
        item_id: "deploy-review".to_string(),
        label: "Review protected deploy plan".to_string(),
        status: "open".to_string(),
        detail: None,
        updated_at_ms: 1_700_000_300_100,
    });
    degraded_task
        .background_tasks
        .push(SessionBackgroundTaskRecord {
            task_id: "deploy-watch".to_string(),
            session_id: Some(degraded_session_id.to_string()),
            label: "Watch deploy health".to_string(),
            status: "running".to_string(),
            detail: None,
            latest_output: None,
            can_stop: true,
            updated_at_ms: 1_700_000_300_200,
        });
    save_local_task_state(&memory_runtime, &degraded_task);
    let degraded_summary = stored_summary(&memory_runtime, degraded_session_id)?;
    crate::kernel::session::compact_retained_session_for_sessions(
        &memory_runtime,
        vec![degraded_summary.clone()],
        Some(degraded_session_id),
        Some(degraded_session_id),
        Some(SessionCompactionPolicy {
            carry_pinned_only: false,
            preserve_checklist_state: false,
            preserve_background_tasks: false,
            preserve_latest_output_excerpt: false,
            preserve_governance_blockers: false,
            aggressive_transcript_pruning: true,
        }),
    )?;
    crate::kernel::session::sync_team_memory_for_sessions(
        &memory_runtime,
        vec![degraded_summary.clone()],
        Some(degraded_session_id),
        Some(degraded_session_id),
        Some("Studio".to_string()),
        Some("operator".to_string()),
        true,
    )?;

    print_json(&SeededDurabilityPortfolioProof {
        data_dir: data_dir.display().to_string(),
        workspace_root: root_text,
        session_ids: vec![
            ready_session_id.to_string(),
            stale_session_id.to_string(),
            degraded_session_id.to_string(),
        ],
    })
}

fn seed_authority_scenario(mut args: Vec<String>) -> Result<(), String> {
    let root = required_flag(&mut args, "--root")?;
    let session_id = optional_flag_value(&mut args, "--session-id")?
        .unwrap_or_else(|| "authority-proof-session".to_string());
    if !args.is_empty() {
        return Err(format!("Unexpected arguments: {}", args.join(" ")));
    }

    let workspace_root = Path::new(&root).canonicalize().map_err(|error| {
        format!(
            "Failed to canonicalize workspace root '{}': {}",
            root, error
        )
    })?;
    let data_dir = cli_data_dir()?;
    let memory_runtime = Arc::new(open_or_create_memory_runtime(Path::new(&data_dir))?);
    let root_text = workspace_root.to_string_lossy().to_string();

    let task = build_seed_task(
        &session_id,
        "Retain a session with approval-sensitive authority posture",
        &root_text,
        &SeedOptions {
            phase: AgentPhase::Complete,
            current_step: "Authority proof seed retained for shared REPL posture.".to_string(),
            history_count: 3,
            blocker: None,
            artifact_title: Some("Authority proof note".to_string()),
        },
    );
    save_local_task_state(&memory_runtime, &task);

    let policy_manager = ShieldPolicyManager::new(policy_state_path_for(Path::new(&data_dir)));
    let _ = policy_manager.reset_to_default()?;
    let _ = policy_manager.remember_approval(ShieldRememberApprovalInput {
        connector_id: "mail.primary".to_string(),
        action_id: "mail.read_latest".to_string(),
        action_label: "Read latest mail".to_string(),
        policy_family: "reads".to_string(),
        scope_key: Some(root_text.clone()),
        scope_label: Some("Current workspace".to_string()),
        source_label: Some("Authority proof fixture".to_string()),
        scope_mode: None,
        expires_at_ms: None,
    })?;
    let _ = policy_manager.match_remembered_approval(
        "mail.primary",
        "mail.read_latest",
        "reads",
        Some(root_text.as_str()),
        "Read latest mail",
    );
    let approvals = policy_manager.approval_snapshot();

    print_json(&SeededAuthorityProof {
        data_dir: data_dir.display().to_string(),
        workspace_root: root_text,
        session_id,
        current_profile_id: "guided_default".to_string(),
        remembered_decision_count: approvals.active_decision_count,
        recent_receipt_count: approvals.recent_receipt_count,
    })
}

fn seed_task_graph_scenario(mut args: Vec<String>) -> Result<(), String> {
    let root = required_flag(&mut args, "--root")?;
    let parent_session_id = optional_flag_value(&mut args, "--session-id")?
        .unwrap_or_else(|| "tasks-proof-parent".to_string());
    if !args.is_empty() {
        return Err(format!("Unexpected arguments: {}", args.join(" ")));
    }

    let workspace_root = Path::new(&root).canonicalize().map_err(|error| {
        format!(
            "Failed to canonicalize workspace root '{}': {}",
            root, error
        )
    })?;
    let data_dir = cli_data_dir()?;
    let memory_runtime = Arc::new(open_or_create_memory_runtime(Path::new(&data_dir))?);
    let root_text = workspace_root.to_string_lossy().to_string();

    let context_child_session_id = format!("{parent_session_id}-context-worker");
    let implement_child_session_id = format!("{parent_session_id}-implement-worker");
    let research_child_session_id = format!("{parent_session_id}-research-worker");

    let context_child = build_seed_task(
        &context_child_session_id,
        "Capture repo context for the proof session",
        &root_text,
        &SeedOptions {
            phase: AgentPhase::Complete,
            current_step: "Context brief captured for the delegated task proof.".to_string(),
            history_count: 3,
            blocker: None,
            artifact_title: Some("Context brief".to_string()),
        },
    );
    save_local_task_state(&memory_runtime, &context_child);

    let implement_child = build_seed_task(
        &implement_child_session_id,
        "Patch the workspace for the proof session",
        &root_text,
        &SeedOptions {
            phase: AgentPhase::Running,
            current_step: "Waiting on operator review before continuing the patch.".to_string(),
            history_count: 3,
            blocker: None,
            artifact_title: Some("Implementation notes".to_string()),
        },
    );
    save_local_task_state(&memory_runtime, &implement_child);

    let research_child = build_seed_task(
        &research_child_session_id,
        "Gather current sources for the proof session",
        &root_text,
        &SeedOptions {
            phase: AgentPhase::Complete,
            current_step: "Research brief captured for the delegated task proof.".to_string(),
            history_count: 3,
            blocker: None,
            artifact_title: Some("Research brief".to_string()),
        },
    );
    save_local_task_state(&memory_runtime, &research_child);

    let parent_task = build_seed_task(
        &parent_session_id,
        "Review delegated graph state in the shared task drawer",
        &root_text,
        &SeedOptions {
            phase: AgentPhase::Running,
            current_step: "The parent session is reviewing delegated worker output, a blocked implementation lane, and a verifier lane that is ready to start."
                .to_string(),
            history_count: 4,
            blocker: None,
            artifact_title: Some("Parent proof summary".to_string()),
        },
    );
    save_local_task_state(&memory_runtime, &parent_task);

    let context_artifact = Artifact {
        artifact_id: Uuid::new_v4().to_string(),
        created_at: now_iso(),
        thread_id: parent_session_id.clone(),
        artifact_type: ArtifactType::Report,
        title: "Retained repo context brief".to_string(),
        description: "Seeded parent playbook proof artifact".to_string(),
        content_ref: "proof://tasks/context".to_string(),
        metadata: serde_json::json!({ "source": "repl_proof", "kind": "task_graph" }),
        version: Some(1),
        parent_artifact_id: None,
    };
    append_artifact(
        &memory_runtime,
        &context_artifact,
        b"Seeded delegated task proof artifact.",
    );

    let research_artifact = Artifact {
        artifact_id: Uuid::new_v4().to_string(),
        created_at: now_iso(),
        thread_id: parent_session_id.clone(),
        artifact_type: ArtifactType::Report,
        title: "Retained research brief".to_string(),
        description: "Seeded citation-grounded proof artifact".to_string(),
        content_ref: "proof://tasks/research".to_string(),
        metadata: serde_json::json!({ "source": "repl_proof", "kind": "task_graph_research" }),
        version: Some(1),
        parent_artifact_id: None,
    };
    append_artifact(
        &memory_runtime,
        &research_artifact,
        b"Seeded delegated research proof artifact.",
    );

    let playbooks = default_agent_playbooks()
        .into_iter()
        .map(|playbook| (playbook.playbook_id.clone(), playbook))
        .collect::<std::collections::BTreeMap<_, _>>();

    let evidence_playbook = playbooks
        .get("evidence_audited_patch")
        .cloned()
        .ok_or_else(|| "Evidence-Audited Patch playbook is unavailable.".to_string())?;
    let citation_playbook = playbooks
        .get("citation_grounded_brief")
        .cloned()
        .ok_or_else(|| "Citation-Grounded Brief playbook is unavailable.".to_string())?;
    let context_step = evidence_playbook
        .steps
        .iter()
        .find(|step| step.step_id == "context")
        .ok_or_else(|| "Context step missing from the seeded playbook.".to_string())?;
    let implement_step = evidence_playbook
        .steps
        .iter()
        .find(|step| step.step_id == "implement")
        .ok_or_else(|| "Implement step missing from the seeded playbook.".to_string())?;
    let research_step = citation_playbook
        .steps
        .iter()
        .find(|step| step.step_id == "research")
        .ok_or_else(|| "Research step missing from the seeded playbook.".to_string())?;

    let event_base_ms = crate::kernel::state::now();
    let context_spawned = build_event(
        &parent_session_id,
        1,
        EventType::InfoNote,
        format!("Spawned {}", context_step.label),
        serde_json::json!({
            "kind": "parent_playbook",
            "playbook_id": evidence_playbook.playbook_id,
            "playbook_label": evidence_playbook.label,
            "phase": "step_spawned",
            "status": "running",
            "success": true,
        }),
        serde_json::json!({
            "timestamp_ms": event_base_ms,
            "parent_session_id": parent_session_id,
            "step_id": context_step.step_id,
            "step_label": context_step.label,
            "child_session_id": context_child_session_id,
            "template_id": context_step.worker_template_id,
            "workflow_id": context_step.worker_workflow_id,
            "summary": "Repo context worker started collecting likely files and targeted verification hints.",
        }),
        EventStatus::Success,
        Vec::new(),
        Some("receipt-context-start".to_string()),
        Vec::new(),
        None,
    );
    append_event(&memory_runtime, &context_spawned);

    let context_completed = build_event(
        &parent_session_id,
        2,
        EventType::Receipt,
        format!("Completed {}", context_step.label),
        serde_json::json!({
            "kind": "parent_playbook",
            "playbook_id": evidence_playbook.playbook_id,
            "playbook_label": evidence_playbook.label,
            "phase": "step_completed",
            "status": "completed",
            "success": true,
        }),
        serde_json::json!({
            "timestamp_ms": event_base_ms + 1_000,
            "parent_session_id": parent_session_id,
            "step_id": context_step.step_id,
            "step_label": context_step.label,
            "child_session_id": context_child_session_id,
            "template_id": context_step.worker_template_id,
            "workflow_id": context_step.worker_workflow_id,
            "summary": "Repo context brief retained with likely files, skills, and targeted test suggestions.",
        }),
        EventStatus::Success,
        vec![ArtifactRef {
            artifact_id: context_artifact.artifact_id.clone(),
            artifact_type: ArtifactType::Report,
        }],
        Some("receipt-context-complete".to_string()),
        Vec::new(),
        None,
    );
    append_event(&memory_runtime, &context_completed);

    let implement_spawned = build_event(
        &parent_session_id,
        3,
        EventType::InfoNote,
        format!("Spawned {}", implement_step.label),
        serde_json::json!({
            "kind": "parent_playbook",
            "playbook_id": evidence_playbook.playbook_id,
            "playbook_label": evidence_playbook.label,
            "phase": "step_spawned",
            "status": "running",
            "success": true,
        }),
        serde_json::json!({
            "timestamp_ms": event_base_ms + 2_000,
            "parent_session_id": parent_session_id,
            "step_id": implement_step.step_id,
            "step_label": implement_step.label,
            "child_session_id": implement_child_session_id,
            "template_id": implement_step.worker_template_id,
            "workflow_id": implement_step.worker_workflow_id,
            "summary": "Implementation worker started preparing the workspace patch.",
        }),
        EventStatus::Success,
        Vec::new(),
        Some("receipt-implement-start".to_string()),
        Vec::new(),
        None,
    );
    append_event(&memory_runtime, &implement_spawned);

    let implement_blocked = build_event(
        &parent_session_id,
        4,
        EventType::Warning,
        format!("Blocked {}", implement_step.label),
        serde_json::json!({
            "kind": "parent_playbook",
            "playbook_id": evidence_playbook.playbook_id,
            "playbook_label": evidence_playbook.label,
            "phase": "blocked",
            "status": "blocked",
            "success": false,
            "error_class": "operator_review_required",
        }),
        serde_json::json!({
            "timestamp_ms": event_base_ms + 3_000,
            "parent_session_id": parent_session_id,
            "step_id": implement_step.step_id,
            "step_label": implement_step.label,
            "child_session_id": implement_child_session_id,
            "template_id": implement_step.worker_template_id,
            "workflow_id": implement_step.worker_workflow_id,
            "summary": "Implementation worker needs operator review before applying the retained patch plan.",
        }),
        EventStatus::Partial,
        Vec::new(),
        Some("receipt-implement-blocked".to_string()),
        Vec::new(),
        None,
    );
    append_event(&memory_runtime, &implement_blocked);

    let research_spawned = build_event(
        &parent_session_id,
        5,
        EventType::InfoNote,
        format!("Spawned {}", research_step.label),
        serde_json::json!({
            "kind": "parent_playbook",
            "playbook_id": citation_playbook.playbook_id,
            "playbook_label": citation_playbook.label,
            "phase": "step_spawned",
            "status": "running",
            "success": true,
        }),
        serde_json::json!({
            "timestamp_ms": event_base_ms + 4_000,
            "parent_session_id": parent_session_id,
            "step_id": research_step.step_id,
            "step_label": research_step.label,
            "child_session_id": research_child_session_id,
            "template_id": research_step.worker_template_id,
            "workflow_id": research_step.worker_workflow_id,
            "summary": "Research worker gathered current sources and collapsed them into a retained brief.",
        }),
        EventStatus::Success,
        Vec::new(),
        Some("receipt-research-start".to_string()),
        Vec::new(),
        None,
    );
    append_event(&memory_runtime, &research_spawned);

    let research_completed = build_event(
        &parent_session_id,
        6,
        EventType::Receipt,
        format!("Completed {}", research_step.label),
        serde_json::json!({
            "kind": "parent_playbook",
            "playbook_id": citation_playbook.playbook_id,
            "playbook_label": citation_playbook.label,
            "phase": "step_completed",
            "status": "completed",
            "success": true,
        }),
        serde_json::json!({
            "timestamp_ms": event_base_ms + 5_000,
            "parent_session_id": parent_session_id,
            "step_id": research_step.step_id,
            "step_label": research_step.label,
            "child_session_id": research_child_session_id,
            "template_id": research_step.worker_template_id,
            "workflow_id": research_step.worker_workflow_id,
            "summary": "Research brief retained with current citations so the verification lane can start immediately.",
        }),
        EventStatus::Success,
        vec![ArtifactRef {
            artifact_id: research_artifact.artifact_id.clone(),
            artifact_type: ArtifactType::Report,
        }],
        Some("receipt-research-complete".to_string()),
        Vec::new(),
        None,
    );
    append_event(&memory_runtime, &research_completed);

    print_json(&SeededTaskGraphProof {
        data_dir: data_dir.display().to_string(),
        workspace_root: root_text,
        parent_session_id,
        child_session_ids: vec![
            context_child_session_id,
            implement_child_session_id,
            research_child_session_id,
        ],
        playbook_ids: vec![evidence_playbook.playbook_id, citation_playbook.playbook_id],
        artifact_ids: vec![context_artifact.artifact_id, research_artifact.artifact_id],
    })
}

pub fn run_cli() -> Result<(), String> {
    let mut args = env::args().skip(1).collect::<Vec<_>>();
    let command = args
        .first()
        .cloned()
        .ok_or_else(|| {
            "Usage: autopilot_repl_proof <seed-workspace|seed-managed-settings|seed-durability-portfolio|seed-authority-scenario|seed-task-graph> ..."
                .to_string()
        })?;
    args.remove(0);

    if command == "seed-managed-settings" {
        return seed_managed_settings_fixture(args);
    }

    if command == "seed-durability-portfolio" {
        return seed_durability_portfolio(args);
    }

    if command == "seed-authority-scenario" {
        return seed_authority_scenario(args);
    }

    if command == "seed-task-graph" {
        return seed_task_graph_scenario(args);
    }

    if command != "seed-workspace" {
        return Err(format!(
            "Unknown command '{}'. Usage: autopilot_repl_proof <seed-workspace|seed-managed-settings|seed-durability-portfolio|seed-authority-scenario|seed-task-graph> ...",
            command
        ));
    }

    let root = required_flag(&mut args, "--root")?;
    let intent = if let Some(index) = args.iter().position(|value| value == "--intent") {
        if index + 1 >= args.len() {
            return Err("Missing value for flag '--intent'.".to_string());
        }
        let value = args.remove(index + 1);
        args.remove(index);
        value
    } else {
        format!("CLI attach proof for {}", root)
    };
    let session_id = if let Some(index) = args.iter().position(|value| value == "--session-id") {
        if index + 1 >= args.len() {
            return Err("Missing value for flag '--session-id'.".to_string());
        }
        let value = args.remove(index + 1);
        args.remove(index);
        value
    } else {
        format!("repl-proof-{}", Uuid::new_v4().simple())
    };
    let phase = parse_phase(optional_flag_value(&mut args, "--phase")?)?;
    let blocker = parse_blocker(optional_flag_value(&mut args, "--blocker")?)?;
    let current_step = optional_flag_value(&mut args, "--current-step")?
        .unwrap_or_else(|| "Workspace-backed REPL proof session seeded.".to_string());
    let history_count = optional_flag_value(&mut args, "--history-count")?
        .map(|value| {
            value
                .parse::<usize>()
                .map_err(|error| format!("Invalid value for '--history-count': {}", error))
        })
        .transpose()?
        .unwrap_or(3);
    let artifact_title = optional_flag_value(&mut args, "--artifact-title")?;
    if !args.is_empty() {
        return Err(format!("Unexpected arguments: {}", args.join(" ")));
    }

    let workspace_root = Path::new(&root).canonicalize().map_err(|error| {
        format!(
            "Failed to canonicalize workspace root '{}': {}",
            root, error
        )
    })?;
    let data_dir = cli_data_dir()?;
    let memory_runtime = Arc::new(open_or_create_memory_runtime(Path::new(&data_dir))?);
    let options = SeedOptions {
        phase,
        current_step,
        history_count,
        blocker,
        artifact_title,
    };
    let task = build_seed_task(
        &session_id,
        &intent,
        workspace_root.to_string_lossy().as_ref(),
        &options,
    );
    save_local_task_state(&memory_runtime, &task);
    print_json(&SeededReplProof {
        session_id: session_id.clone(),
        workspace_root: workspace_root.display().to_string(),
        title: task.intent.clone(),
        current_step: task.current_step.clone(),
        phase: format!("{:?}", task.phase),
        history_count: task.history.len(),
        artifact_count: task.artifacts.len(),
    })
}
