use super::evidence::{scrub_workload_args_for_evidence, scrub_workload_text_field_for_evidence};
use super::paths::resolve_working_directory;
use super::sys_exec::{
    command_output_indicates_failure, command_preview, extract_exit_code, process_stream_observer,
    summarize_command_output,
};
use super::{
    compute_workload_id, emit_workload_activity, emit_workload_receipt, extract_error_class,
    ToolExecutionResult, ToolExecutor,
};
use crate::agentic::runtime::resolver::software_install::{
    host_discovery_snapshot, install_source_candidate_from_target,
    resolve_install_plan_for_request, target_from_resolved_plan, InstallResolutionPlan,
    ResolvedInstallTarget,
};
use crate::agentic::runtime::runtime_secret;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ioi_drivers::terminal::CommandExecutionOptions;
use ioi_types::app::agentic::{
    AgentTool, InstallFinalReceipt, InstallResolutionEvent, InstallVerificationEvent,
    ResolvedInstallPlan, SoftwareInstallRequestFrame,
};
use ioi_types::app::{WorkloadActivityKind, WorkloadExecReceipt, WorkloadReceipt};
use serde::{Deserialize, Serialize};
use std::env;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

const INSTALL_COMMAND_TIMEOUT: Duration = Duration::from_secs(600);
const RUNTIME_SECRET_KIND_SUDO_PASSWORD: &str = "sudo_password";

#[cfg(test)]
use crate::agentic::runtime::resolver::software_install::{
    normalize_install_manager, resolve_install_target,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct InstallResolutionSummary {
    pub stage: String,
    pub display_name: Option<String>,
    pub manager: Option<String>,
    pub source_kind: Option<String>,
    pub blocker: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct SoftwareInstallPlanRefPayload {
    version: u8,
    plan: ResolvedInstallPlan,
}

pub(crate) fn software_install_plan_ref_for_resolved_plan(plan: &ResolvedInstallPlan) -> String {
    let payload = SoftwareInstallPlanRefPayload {
        version: 2,
        plan: plan.clone(),
    };
    let bytes = serde_json::to_vec(&payload).unwrap_or_default();
    format!("software-install-plan:v2:{}", URL_SAFE_NO_PAD.encode(bytes))
}

#[cfg(test)]
pub(crate) fn software_install_plan_ref_for_request(
    request: &SoftwareInstallRequestFrame,
) -> String {
    let target = match resolve_install_plan_for_request(request) {
        Ok(InstallResolutionPlan::Resolved(target)) => target,
        Ok(plan) => panic!(
            "test helper requires a resolved install plan, got {}",
            install_plan_blocker_error(&plan)
        ),
        Err(error) => panic!("test helper failed to resolve install plan: {error}"),
    };
    let plan = resolved_install_plan_for_target(request, &target)
        .expect("test helper should build resolved install plan");
    software_install_plan_ref_for_resolved_plan(&plan)
}

fn software_install_plan_from_plan_ref(plan_ref: &str) -> Result<ResolvedInstallPlan, String> {
    let encoded = plan_ref
        .strip_prefix("software-install-plan:v2:")
        .ok_or_else(|| {
            "ERROR_CLASS=InstallerResolutionRequired Invalid software install plan_ref.".to_string()
        })?;
    let bytes = URL_SAFE_NO_PAD.decode(encoded).map_err(|error| {
        format!(
            "ERROR_CLASS=InstallerResolutionRequired Invalid software install plan_ref: {error}."
        )
    })?;
    let payload: SoftwareInstallPlanRefPayload = serde_json::from_slice(&bytes).map_err(|error| {
        format!("ERROR_CLASS=InstallerResolutionRequired Invalid software install plan payload: {error}.")
    })?;
    if payload.version != 2 {
        return Err(format!(
            "ERROR_CLASS=InstallerResolutionRequired Unsupported software install plan version '{}'.",
            payload.version
        ));
    }
    Ok(payload.plan)
}

pub(super) async fn handle_software_install_resolve(
    request: &SoftwareInstallRequestFrame,
) -> ToolExecutionResult {
    match resolve_install_plan_for_request(request) {
        Ok(InstallResolutionPlan::Resolved(target)) => {
            let plan = match resolved_install_plan_for_target(request, &target) {
                Ok(plan) => plan,
                Err(error) => return ToolExecutionResult::failure(error),
            };
            let plan_ref = software_install_plan_ref_for_resolved_plan(&plan);
            let event = install_resolution_event("resolved", &target, Some(plan_ref), None);
            ToolExecutionResult::success(install_resolution_output(
                event,
                format!(
                    "Resolved install plan for {} via {}.",
                    target.display_name, target.manager
                ),
            ))
        }
        Ok(plan) => ToolExecutionResult::failure(install_plan_blocker_error(&plan)),
        Err(error) => ToolExecutionResult::failure(error),
    }
}

pub(super) async fn handle_software_install_execute_plan(
    exec: &ToolExecutor,
    cwd: &str,
    plan_ref: &str,
    session_id: [u8; 32],
    step_index: u32,
) -> ToolExecutionResult {
    let resolved_cwd = match resolve_working_directory(cwd) {
        Ok(path) => path,
        Err(error) => return ToolExecutionResult::failure(error),
    };

    let plan = match software_install_plan_from_plan_ref(plan_ref) {
        Ok(plan) => plan,
        Err(error) => return ToolExecutionResult::failure(error),
    };
    let request = plan.request.clone();
    let target_text = request.target_text.trim();
    if target_text.is_empty() {
        return ToolExecutionResult::failure(
            "ERROR_CLASS=MissingDependency Software install target cannot be empty.".to_string(),
        );
    }
    let target = target_from_resolved_plan(&plan);
    if target.verification_command.is_none() {
        let verification = InstallVerificationEvent {
            plan_ref: plan_ref.to_string(),
            status: "blocked_manual_verification".to_string(),
            command: Vec::new(),
            summary: format!(
                "No verification command is registered for {}.",
                target.package_id
            ),
        };
        let receipt = InstallFinalReceipt {
            plan_ref: plan_ref.to_string(),
            status: "blocked_manual_verification".to_string(),
            display_name: target.display_name.clone(),
            failure_class: Some("VerificationMissing".to_string()),
            verification: Some(verification),
        };
        return ToolExecutionResult::failure(format!(
            "ERROR_CLASS=VerificationMissing {}",
            install_final_receipt_output(
                receipt,
                format!(
                    "Install plan for {} cannot report success without verification.",
                    target.display_name
                ),
            )
        ));
    }

    let manager = target.manager.clone();
    let mut stdin_data: Option<Vec<u8>> = None;
    let (command, mut args) = match install_command_for_target(&target) {
        Ok(command) => command,
        Err(error) => return ToolExecutionResult::failure(error),
    };

    if target.requires_elevation {
        let session_id_hex = hex::encode(session_id);
        if let Some(secret) =
            runtime_secret::take_secret(&session_id_hex, RUNTIME_SECRET_KIND_SUDO_PASSWORD)
        {
            args = sudo_password_retry_args(&target);
            stdin_data = Some(format!("{}\n", secret).into_bytes());
        }
    }

    let resolved_cwd_string = resolved_cwd.to_string_lossy().to_string();
    let evidence_command = scrub_workload_text_field_for_evidence(exec, &command).await;
    let evidence_args = scrub_workload_args_for_evidence(exec, &args).await;
    let evidence_cwd =
        scrub_workload_text_field_for_evidence(exec, resolved_cwd_string.as_str()).await;
    let receipt_preview = command_preview(&evidence_command, &evidence_args);
    let workload_id = compute_workload_id(
        session_id,
        step_index,
        "software_install__execute_plan",
        &receipt_preview,
    );
    if let Some(tx) = exec.event_sender.as_ref() {
        emit_workload_activity(
            tx,
            session_id,
            step_index,
            workload_id.clone(),
            WorkloadActivityKind::Lifecycle {
                phase: "started".to_string(),
                exit_code: None,
            },
        );
    }

    let options = CommandExecutionOptions::default()
        .with_timeout(INSTALL_COMMAND_TIMEOUT)
        .with_stdin_data(stdin_data)
        .with_stream_observer(process_stream_observer(
            exec,
            session_id,
            step_index,
            workload_id.clone(),
        ));

    let result = match exec
        .terminal
        .execute_in_dir_with_options(&command, &args, false, Some(&resolved_cwd), options)
        .await
    {
        Ok(output) => {
            if command_output_indicates_failure(&output) {
                let class = classify_install_failure(output.as_str(), &command, &manager);
                let summary = format!(
                    "Failed to install '{}' via '{}': {}.",
                    target_text,
                    manager,
                    summarize_install_failure_output(&output)
                );
                let receipt = InstallFinalReceipt {
                    plan_ref: plan_ref.to_string(),
                    status: "failed".to_string(),
                    display_name: target.display_name.clone(),
                    failure_class: Some(class.to_string()),
                    verification: None,
                };
                ToolExecutionResult::failure(format!(
                    "ERROR_CLASS={} {}",
                    class,
                    install_final_receipt_output(receipt, summary),
                ))
            } else {
                match verify_install_target(exec, &target, Some(resolved_cwd.as_path())).await {
                    Ok(verification) => {
                        let verification_event = InstallVerificationEvent {
                            plan_ref: plan_ref.to_string(),
                            status: "verified".to_string(),
                            command: target.verification_command.clone().unwrap_or_default(),
                            summary: verification.clone(),
                        };
                        let receipt = InstallFinalReceipt {
                            plan_ref: plan_ref.to_string(),
                            status: "installed_verified".to_string(),
                            display_name: target.display_name.clone(),
                            failure_class: None,
                            verification: Some(verification_event),
                        };
                        ToolExecutionResult::success(install_final_receipt_output(
                            receipt,
                            format!(
                                "Installed '{}' as '{}' via '{}'; verification passed: {}.",
                                target.display_name,
                                target.package_id,
                                target.manager,
                                verification
                            ),
                        ))
                    }
                    Err(verification_error) => {
                        let verification_event = InstallVerificationEvent {
                            plan_ref: plan_ref.to_string(),
                            status: "failed".to_string(),
                            command: target.verification_command.clone().unwrap_or_default(),
                            summary: verification_error.clone(),
                        };
                        let receipt = InstallFinalReceipt {
                            plan_ref: plan_ref.to_string(),
                            status: "verification_failed".to_string(),
                            display_name: target.display_name.clone(),
                            failure_class: Some("VerificationFailed".to_string()),
                            verification: Some(verification_event),
                        };
                        ToolExecutionResult::failure(format!(
                            "ERROR_CLASS=VerificationFailed {}",
                            install_final_receipt_output(
                                receipt,
                                format!(
                                    "Installer completed for '{}' via '{}', but verification failed: {}.",
                                    target.display_name, target.manager, verification_error
                                ),
                            )
                        ))
                    }
                }
            }
        }
        Err(e) => {
            let msg = e.to_string();
            let class = classify_install_failure(msg.as_str(), &command, &manager);
            let receipt = InstallFinalReceipt {
                plan_ref: plan_ref.to_string(),
                status: "failed".to_string(),
                display_name: target.display_name.clone(),
                failure_class: Some(class.to_string()),
                verification: None,
            };
            ToolExecutionResult::failure(format!(
                "ERROR_CLASS={} {}",
                class,
                install_final_receipt_output(
                    receipt,
                    format!(
                        "Failed to install '{}' via '{}': {}.",
                        target_text, manager, msg
                    ),
                ),
            ))
        }
    };

    if let Some(tx) = exec.event_sender.as_ref() {
        let exit_code = result
            .history_entry
            .as_deref()
            .and_then(extract_exit_code)
            .or_else(|| result.error.as_deref().and_then(extract_exit_code));
        let phase = if result.success {
            "completed"
        } else {
            "failed"
        };
        emit_workload_activity(
            tx,
            session_id,
            step_index,
            workload_id.clone(),
            WorkloadActivityKind::Lifecycle {
                phase: phase.to_string(),
                exit_code,
            },
        );
        emit_workload_receipt(
            tx,
            session_id,
            step_index,
            workload_id.clone(),
            WorkloadReceipt::Exec(WorkloadExecReceipt {
                tool_name: "software_install__execute_plan".to_string(),
                command: evidence_command,
                args: evidence_args,
                cwd: evidence_cwd,
                detach: false,
                timeout_ms: INSTALL_COMMAND_TIMEOUT.as_millis() as u64,
                success: result.success,
                exit_code,
                error_class: extract_error_class(result.error.as_deref()),
                command_preview: receipt_preview,
            }),
        );
    }

    result
}

pub(crate) fn install_resolution_checks_for_tool(tool: &AgentTool) -> Vec<String> {
    let Some(request) = install_request_from_tool(tool) else {
        return Vec::new();
    };

    match resolve_install_plan_for_request(&request) {
        Ok(plan) => install_resolution_checks(&plan),
        Err(error) => vec![
            "software_install.stage=resolution_failed".to_string(),
            format!(
                "software_install.error={}",
                compact_resolution_value(&error)
            ),
        ],
    }
}

pub(crate) fn install_resolution_summary_for_tool(
    tool: &AgentTool,
) -> Option<InstallResolutionSummary> {
    let request = install_request_from_tool(tool)?;
    let manager = request.manager_preference.as_deref();
    let plan = resolve_install_plan_for_request(&request).ok()?;
    Some(match plan {
        InstallResolutionPlan::Resolved(target) => InstallResolutionSummary {
            stage: "resolved".to_string(),
            display_name: Some(target.display_name),
            manager: Some(target.manager),
            source_kind: Some(target.source_kind),
            blocker: None,
        },
        InstallResolutionPlan::Unsupported(target) => InstallResolutionSummary {
            stage: "unsupported".to_string(),
            display_name: Some(target.display_name.clone()),
            manager: Some(target.manager.clone()),
            source_kind: Some(target.source_kind.clone()),
            blocker: Some(unsupported_target_error(&target).unwrap_or_else(|| {
                "ERROR_CLASS=InstallerResolutionRequired Install plan is unsupported.".to_string()
            })),
        },
        InstallResolutionPlan::Unresolved(target) => InstallResolutionSummary {
            stage: "unresolved".to_string(),
            display_name: Some(target.display_name.clone()),
            manager: Some(target.manager.clone()),
            source_kind: Some(target.source_kind.clone()),
            blocker: Some(unsupported_target_error(&target).unwrap_or_else(|| {
                "ERROR_CLASS=InstallerResolutionRequired Install target is unresolved.".to_string()
            })),
        },
        InstallResolutionPlan::Ambiguous {
            target_text,
            candidates,
        } => InstallResolutionSummary {
            stage: "ambiguous".to_string(),
            display_name: Some(target_text),
            manager: manager.map(str::to_string),
            source_kind: None,
            blocker: Some(format!(
                "ERROR_CLASS=InstallerResolutionRequired Install target is ambiguous. Candidates: {}.",
                candidates.join(", ")
            )),
        },
    })
}

pub(crate) fn install_already_satisfied_before_approval_for_tool(
    tool: &AgentTool,
) -> Option<String> {
    let request = install_request_from_tool(tool)?;
    let plan = resolve_install_plan_for_request(&request).ok()?;
    let target = match plan {
        InstallResolutionPlan::Resolved(target) | InstallResolutionPlan::Unsupported(target) => {
            target
        }
        InstallResolutionPlan::Unresolved(_) | InstallResolutionPlan::Ambiguous { .. } => {
            return None
        }
    };

    if target.source_kind == "current_app" {
        let current_exe = env::current_exe().ok()?;
        if !current_exe.is_file() {
            return None;
        }
        let plan_ref = format!("already-current-app:{}", target.canonical_id);
        let verification = InstallVerificationEvent {
            plan_ref: plan_ref.clone(),
            status: "verified".to_string(),
            command: vec!["current_exe_exists".to_string()],
            summary: format!(
                "Current executable exists at {}.",
                compact_resolution_value(current_exe.to_string_lossy().as_ref())
            ),
        };
        let receipt = InstallFinalReceipt {
            plan_ref,
            status: "already_available_verified".to_string(),
            display_name: target.display_name.clone(),
            failure_class: None,
            verification: Some(verification),
        };
        return Some(install_final_receipt_output(
            receipt,
            format!(
                "{} is already available as the running product; no host mutation was performed.",
                target.display_name
            ),
        ));
    }

    if target.source_kind == "editor_extension" {
        return None;
    }

    let parts = target.verification_command.as_ref()?;
    let (command, args) = parts.split_first()?;
    let output = Command::new(command).args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("Stdout:\n{}\nStderr:\n{}", stdout, stderr);
    let verification = summarize_command_output(&combined);

    let plan = resolved_install_plan_for_target(&request, &target).ok()?;
    let plan_ref = software_install_plan_ref_for_resolved_plan(&plan);
    let verification_event = InstallVerificationEvent {
        plan_ref: plan_ref.clone(),
        status: "verified".to_string(),
        command: target.verification_command.clone().unwrap_or_default(),
        summary: verification.clone(),
    };
    let receipt = InstallFinalReceipt {
        plan_ref,
        status: "already_installed_verified".to_string(),
        display_name: target.display_name.clone(),
        failure_class: None,
        verification: Some(verification_event),
    };
    Some(install_final_receipt_output(
        receipt,
        format!(
            "{} is already installed; verification passed: {}.",
            target.display_name,
            compact_resolution_value(&verification)
        ),
    ))
}

fn install_request_from_tool(tool: &AgentTool) -> Option<SoftwareInstallRequestFrame> {
    match tool {
        AgentTool::SoftwareInstallResolve { request } => Some(request.clone()),
        AgentTool::SoftwareInstallExecutePlan { plan_ref } => {
            software_install_plan_from_plan_ref(plan_ref)
                .ok()
                .map(|plan| plan.request)
        }
        _ => None,
    }
}

fn compact_resolution_value(value: &str) -> String {
    value
        .replace(['\n', '\r'], " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn install_resolution_event(
    stage: &str,
    target: &ResolvedInstallTarget,
    plan_ref: Option<String>,
    blocker: Option<String>,
) -> InstallResolutionEvent {
    InstallResolutionEvent {
        stage: stage.to_string(),
        display_name: target.display_name.clone(),
        canonical_id: target.canonical_id.clone(),
        target_kind: target.target_kind.clone(),
        host: host_discovery_snapshot(),
        source: install_source_candidate_from_target(target),
        requires_elevation: target.requires_elevation,
        plan_ref,
        blocker,
    }
}

fn install_resolution_output(event: InstallResolutionEvent, summary: String) -> String {
    serde_json::to_string(&serde_json::json!({
        "kind": "install_resolution",
        "summary": summary,
        "install_event": event,
    }))
    .unwrap_or_else(|_| summary)
}

fn install_blocker_output(
    error_class: &str,
    event: InstallResolutionEvent,
    summary: String,
) -> String {
    serde_json::to_string(&serde_json::json!({
        "kind": "install_resolution",
        "error_class": error_class,
        "summary": summary,
        "install_event": event,
    }))
    .unwrap_or_else(|_| format!("ERROR_CLASS={error_class} {summary}"))
}

fn install_final_receipt_output(receipt: InstallFinalReceipt, summary: String) -> String {
    serde_json::to_string(&serde_json::json!({
        "kind": "install_final_receipt",
        "summary": summary,
        "install_final_receipt": receipt,
    }))
    .unwrap_or_else(|_| summary)
}

fn install_resolution_checks(plan: &InstallResolutionPlan) -> Vec<String> {
    let target = match plan {
        InstallResolutionPlan::Resolved(target)
        | InstallResolutionPlan::Unsupported(target)
        | InstallResolutionPlan::Unresolved(target) => target,
        InstallResolutionPlan::Ambiguous {
            target_text,
            candidates,
        } => {
            return vec![
                "software_install.stage=ambiguous".to_string(),
                format!(
                    "software_install.display_name={}",
                    compact_resolution_value(target_text)
                ),
                format!(
                    "software_install.blocker={}",
                    compact_resolution_value(&format!(
                        "ERROR_CLASS=InstallerResolutionRequired Install target is ambiguous. Candidates: {}.",
                        candidates.join(", ")
                    ))
                ),
            ];
        }
    };
    let stage = match plan {
        InstallResolutionPlan::Resolved(_) | InstallResolutionPlan::Unsupported(_) => "resolved",
        InstallResolutionPlan::Unresolved(_) => "unresolved",
        InstallResolutionPlan::Ambiguous { .. } => "ambiguous",
    };
    let mut checks = vec![
        format!("software_install.stage={stage}"),
        format!(
            "software_install.display_name={}",
            compact_resolution_value(&target.display_name)
        ),
        format!(
            "software_install.canonical_id={}",
            compact_resolution_value(&target.canonical_id)
        ),
        format!(
            "software_install.target_kind={}",
            compact_resolution_value(&target.target_kind)
        ),
        format!(
            "software_install.platform={}",
            compact_resolution_value(&target.platform)
        ),
        format!(
            "software_install.architecture={}",
            compact_resolution_value(&target.architecture)
        ),
        format!(
            "software_install.source_kind={}",
            compact_resolution_value(&target.source_kind)
        ),
        format!(
            "software_install.manager={}",
            compact_resolution_value(&target.manager)
        ),
        format!(
            "software_install.package_id={}",
            compact_resolution_value(&target.package_id)
        ),
        format!(
            "software_install.requires_elevation={}",
            target.requires_elevation
        ),
        format!(
            "software_install.verification={}",
            compact_resolution_value(&verification_preview(target))
        ),
    ];

    if let Some(url) = target.installer_url.as_deref() {
        checks.push(format!(
            "software_install.installer_url={}",
            compact_resolution_value(url)
        ));
    }
    if let Some(url) = target.source_discovery_url.as_deref() {
        checks.push(format!(
            "software_install.source_discovery_url={}",
            compact_resolution_value(url)
        ));
    }
    if let Some(launch) = target.launch_target.as_deref() {
        checks.push(format!(
            "software_install.launch_target={}",
            compact_resolution_value(launch)
        ));
    }

    if let Some(error) = unsupported_target_error(target) {
        checks.push("software_install.command=not_available".to_string());
        checks.push(format!(
            "software_install.blocker={}",
            compact_resolution_value(&error)
        ));
    } else if let Ok((command, args)) = install_command_for_target(target) {
        checks.push(format!(
            "software_install.command={}",
            compact_resolution_value(&command_preview(&command, &args))
        ));
    }

    checks
}

fn resolved_install_plan_for_target(
    request: &SoftwareInstallRequestFrame,
    target: &ResolvedInstallTarget,
) -> Result<ResolvedInstallPlan, String> {
    let (command, args) = install_command_for_target(target)?;
    let mut command_parts = Vec::with_capacity(args.len() + 1);
    command_parts.push(command);
    command_parts.extend(args);
    Ok(ResolvedInstallPlan {
        request: request.clone(),
        display_name: target.display_name.clone(),
        canonical_id: target.canonical_id.clone(),
        target_kind: target.target_kind.clone(),
        host: host_discovery_snapshot(),
        source: install_source_candidate_from_target(target),
        requires_elevation: target.requires_elevation,
        command: command_parts,
        verification_command: target.verification_command.clone(),
        launch_target: target.launch_target.clone(),
        approval_scope: if target.requires_elevation {
            "host_mutation:elevated_install".to_string()
        } else {
            "host_mutation:user_install".to_string()
        },
        failure_policy: "verification_required_for_success".to_string(),
    })
}

fn install_plan_blocker_error(plan: &InstallResolutionPlan) -> String {
    match plan {
        InstallResolutionPlan::Unsupported(target) | InstallResolutionPlan::Unresolved(target) => {
            unsupported_target_error(target).unwrap_or_else(|| {
                "ERROR_CLASS=InstallerResolutionRequired Install plan is not executable.".to_string()
            })
        }
        InstallResolutionPlan::Ambiguous {
            target_text,
            candidates,
        } => format!(
            "ERROR_CLASS=InstallerResolutionRequired Install target '{}' is ambiguous. Candidates: {}.",
            target_text,
            candidates.join(", ")
        ),
        InstallResolutionPlan::Resolved(_) => {
            "ERROR_CLASS=UnexpectedState Resolved install plan was blocked unexpectedly."
                .to_string()
        }
    }
}

fn unsupported_target_error(target: &ResolvedInstallTarget) -> Option<String> {
    let (class, stage, summary) = match target.source_kind.as_str() {
        "unsupported_platform" => (
            "UnsupportedPlatform",
            "unsupported",
            format!(
                "'{}' has resolver metadata, but no verified installer is registered for {} {}.",
                target.display_name, target.platform, target.architecture
            ),
        ),
        "manual_installer" => {
            let official_source = target
                .installer_url
                .as_deref()
                .or(target.source_discovery_url.as_deref())
                .unwrap_or("no_url_available");
            (
                "InstallerResolutionRequired",
                "unsupported",
                format!(
                    "Resolved '{}' for {} {} as an official manual installer source ({}), but no verified unattended installer candidate passed policy for manager '{}'.",
                    target.display_name, target.platform, target.architecture, official_source, target.manager
                ),
            )
        }
        "current_app" => (
            "AlreadyCurrentApp",
            "already_current_app",
            format!(
                "'{}' resolves to the current product. Use the product release/update workflow or build artifacts for self-install/update.",
                target.display_name
            ),
        ),
        "editor_extension" => (
            "InstallerResolutionRequired",
            "unsupported",
            format!(
                "'{}' resolves to an editor extension, not a desktop app package. Use an editor extension resolver for '{}'.",
                target.display_name, target.package_id
            ),
        ),
        "unresolved" => (
            "InstallerResolutionRequired",
            "unresolved",
            format!(
                "No verified install candidate passed resolver policy for '{}'. Specify an explicit package manager/package id or choose a resolver-supported target before mutating the host.",
                target.display_name
            ),
        ),
        _ => return None,
    };
    let event = install_resolution_event(stage, target, None, Some(summary.clone()));
    Some(format!(
        "ERROR_CLASS={} {}",
        class,
        install_blocker_output(class, event, summary)
    ))
}

fn verification_preview(target: &ResolvedInstallTarget) -> String {
    target
        .verification_command
        .as_ref()
        .map(|parts| parts.join(" "))
        .unwrap_or_else(|| "package_manager_success_only".to_string())
}

fn install_command_for_target(
    target: &ResolvedInstallTarget,
) -> Result<(String, Vec<String>), String> {
    let pkg = target.package_id.clone();
    match target.manager.as_str() {
        "apt-get" => Ok((
            "sudo".to_string(),
            vec![
                "-n".to_string(),
                "apt-get".to_string(),
                "install".to_string(),
                "-y".to_string(),
                pkg,
            ],
        )),
        "brew" => Ok(("brew".to_string(), vec!["install".to_string(), pkg])),
        "brew-cask" => Ok((
            "brew".to_string(),
            vec!["install".to_string(), "--cask".to_string(), pkg],
        )),
        "pip" => Ok((
            "python".to_string(),
            vec![
                "-m".to_string(),
                "pip".to_string(),
                "install".to_string(),
                pkg,
            ],
        )),
        "npm" => Ok((
            "npm".to_string(),
            vec!["install".to_string(), "-g".to_string(), pkg],
        )),
        "pnpm" => Ok((
            "pnpm".to_string(),
            vec!["add".to_string(), "-g".to_string(), pkg],
        )),
        "cargo" => Ok(("cargo".to_string(), vec!["install".to_string(), pkg])),
        "winget" => Ok((
            "winget".to_string(),
            vec![
                "install".to_string(),
                "--id".to_string(),
                pkg,
                "--silent".to_string(),
                "--accept-package-agreements".to_string(),
                "--accept-source-agreements".to_string(),
            ],
        )),
        "choco" => Ok((
            "choco".to_string(),
            vec!["install".to_string(), pkg, "-y".to_string()],
        )),
        "scoop" => Ok(("scoop".to_string(), vec!["install".to_string(), pkg])),
        "yum" => Ok((
            "sudo".to_string(),
            vec![
                "-n".to_string(),
                "yum".to_string(),
                "install".to_string(),
                "-y".to_string(),
                pkg,
            ],
        )),
        "dnf" => Ok((
            "sudo".to_string(),
            vec![
                "-n".to_string(),
                "dnf".to_string(),
                "install".to_string(),
                "-y".to_string(),
                pkg,
            ],
        )),
        "pacman" => Ok((
            "sudo".to_string(),
            vec![
                "-n".to_string(),
                "pacman".to_string(),
                "-S".to_string(),
                "--noconfirm".to_string(),
                pkg,
            ],
        )),
        "zypper" => Ok((
            "sudo".to_string(),
            vec![
                "-n".to_string(),
                "zypper".to_string(),
                "--non-interactive".to_string(),
                "install".to_string(),
                pkg,
            ],
        )),
        "apk" => Ok((
            "sudo".to_string(),
            vec!["-n".to_string(), "apk".to_string(), "add".to_string(), pkg],
        )),
        "flatpak" => Ok((
            "flatpak".to_string(),
            vec![
                "install".to_string(),
                "-y".to_string(),
                "flathub".to_string(),
                pkg,
            ],
        )),
        "snap" => Ok((
            "sudo".to_string(),
            vec![
                "-n".to_string(),
                "snap".to_string(),
                "install".to_string(),
                pkg,
            ],
        )),
        "appimage" => {
            let direct_installer_url = target.installer_url.as_deref().unwrap_or("");
            if direct_installer_url.is_empty() {
                return Err(
                    "ERROR_CLASS=InstallerResolutionRequired AppImage install target is missing a resolver-provenanced installer URL."
                        .to_string(),
                );
            }
            let display_name = compact_resolution_value(&target.display_name);
            let appimage_name = compact_resolution_value(&target.package_id);
            let launcher_name = compact_resolution_value(&target.canonical_id);
            let script = format!(
                r#"set -euo pipefail
install_dir="${{HOME}}/.local/bin"
appimage="${{install_dir}}/{appimage_name}"
launcher="${{install_dir}}/{launcher_name}"
display_name="{display_name}"
installer_url="{direct_installer_url}"
mkdir -p "${{install_dir}}"
tmp="$(mktemp "${{TMPDIR:-/tmp}}/{launcher_name}.XXXXXX.AppImage")"
cleanup() {{
  rm -f "${{tmp}}"
}}
trap cleanup EXIT

download_file() {{
  if command -v curl >/dev/null 2>&1; then
    curl -fL --progress-bar -o "${{tmp}}" "$1"
  elif command -v wget >/dev/null 2>&1; then
    wget --progress=dot:giga -O "${{tmp}}" "$1"
  else
    echo "ERROR_CLASS=ToolUnavailable Neither curl nor wget is available for AppImage download." >&2
    return 127
  fi
}}

echo "Downloading ${{display_name}} AppImage from ${{installer_url}}"
download_file "${{installer_url}}"
chmod +x "${{tmp}}"
mv "${{tmp}}" "${{appimage}}"
cat > "${{launcher}}" <<'EOF'
#!/usr/bin/env sh
exec "${{HOME}}/.local/bin/{appimage_name}" "$@"
EOF
chmod +x "${{launcher}}"
echo "Installed ${{display_name}} AppImage to ${{appimage}}"
"#
            );
            Ok(("bash".to_string(), vec!["-lc".to_string(), script]))
        }
        other => Err(format!(
            "ERROR_CLASS=ToolUnavailable Unsupported executable install manager '{}'.",
            other
        )),
    }
}

fn sudo_password_retry_args(target: &ResolvedInstallTarget) -> Vec<String> {
    let pkg = target.package_id.clone();
    match target.manager.as_str() {
        "apt-get" => vec![
            "-S".to_string(),
            "-k".to_string(),
            "apt-get".to_string(),
            "install".to_string(),
            "-y".to_string(),
            pkg,
        ],
        "yum" => vec![
            "-S".to_string(),
            "-k".to_string(),
            "yum".to_string(),
            "install".to_string(),
            "-y".to_string(),
            pkg,
        ],
        "dnf" => vec![
            "-S".to_string(),
            "-k".to_string(),
            "dnf".to_string(),
            "install".to_string(),
            "-y".to_string(),
            pkg,
        ],
        "pacman" => vec![
            "-S".to_string(),
            "-k".to_string(),
            "pacman".to_string(),
            "-S".to_string(),
            "--noconfirm".to_string(),
            pkg,
        ],
        "zypper" => vec![
            "-S".to_string(),
            "-k".to_string(),
            "zypper".to_string(),
            "--non-interactive".to_string(),
            "install".to_string(),
            pkg,
        ],
        "apk" => vec![
            "-S".to_string(),
            "-k".to_string(),
            "apk".to_string(),
            "add".to_string(),
            pkg,
        ],
        "snap" => vec![
            "-S".to_string(),
            "-k".to_string(),
            "snap".to_string(),
            "install".to_string(),
            pkg,
        ],
        _ => Vec::new(),
    }
}

async fn verify_install_target(
    exec: &ToolExecutor,
    target: &ResolvedInstallTarget,
    cwd: Option<&Path>,
) -> Result<String, String> {
    let Some(parts) = target.verification_command.as_ref() else {
        return Err(format!(
            "No binary/app verification command is registered for '{}'.",
            target.package_id
        ));
    };
    let Some((command, args)) = parts.split_first() else {
        return Err("verification command was empty".to_string());
    };
    let output = exec
        .terminal
        .execute_in_dir_with_options(
            command,
            args,
            false,
            cwd,
            CommandExecutionOptions::default().with_timeout(Duration::from_secs(30)),
        )
        .await
        .map_err(|error| error.to_string())?;
    if command_output_indicates_failure(&output) {
        Err(summarize_install_failure_output(&output))
    } else {
        let summary = summarize_command_output(&output);
        if summary == "unknown error" {
            Ok(format!(
                "{} completed successfully",
                verification_preview(target)
            ))
        } else {
            Ok(summary)
        }
    }
}

pub(super) fn classify_install_failure(error: &str, command: &str, manager: &str) -> &'static str {
    let msg = error.to_ascii_lowercase();

    if msg.contains("timed out") || msg.contains("timeout") {
        return "TimeoutOrHang";
    }

    // Prefer deterministic package lookup failures over incidental sudo text.
    // Some environments can surface both in a single stderr stream.
    if is_install_package_lookup_error(error) {
        return "MissingDependency";
    }

    if is_sudo_password_required_install_error(error) || msg.contains("permission denied") {
        return "PermissionOrApprovalRequired";
    }

    if msg.contains("no such file")
        || msg.contains("not found")
        || msg.contains("failed to spawn")
        || msg.contains("command not found")
    {
        if msg.contains(command) || msg.contains(manager) {
            return "ToolUnavailable";
        }
    }

    "UnexpectedState"
}

pub(crate) fn is_install_package_lookup_error(error: &str) -> bool {
    let msg = error.to_ascii_lowercase();
    msg.contains("unable to locate package")
        || msg.contains("no package")
        || msg.contains("could not find")
        || msg.contains("has no installation candidate")
        || msg.contains("no match for argument")
        || msg.contains("cannot find a package")
        || msg.contains("target not found")
        || msg.contains("no package matches")
        || msg.contains("no such package")
        || msg.contains("unable to find")
}

pub(crate) fn is_sudo_password_required_install_error(error: &str) -> bool {
    if is_install_package_lookup_error(error) {
        return false;
    }
    let msg = error.to_ascii_lowercase();
    msg.contains("sudo:")
        || msg.contains("a password is required")
        || msg.contains("not in the sudoers")
        || msg.contains("requires elevated privileges")
        || msg.contains("incorrect password")
        || msg.contains("sorry, try again")
        || msg.contains("error_class=permissionorapprovalrequired")
}

fn summarize_install_failure_output(output: &str) -> String {
    let trimmed = output.trim();
    if trimmed.is_empty() {
        return "unknown error".to_string();
    }
    let stderr_or_full = trimmed
        .split_once("Stderr:")
        .map(|(_, stderr)| stderr.trim())
        .unwrap_or(trimmed);
    let compact = stderr_or_full
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    if compact.is_empty() {
        return summarize_command_output(trimmed);
    }
    let max_chars = 480;
    let compact_chars = compact.chars().count();
    if compact_chars > max_chars {
        let truncated = compact.chars().take(max_chars).collect::<String>();
        format!("{}...", truncated)
    } else {
        compact
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(target_text: &str, manager_preference: Option<&str>) -> SoftwareInstallRequestFrame {
        SoftwareInstallRequestFrame {
            target_text: target_text.to_string(),
            target_kind: None,
            manager_preference: manager_preference.map(str::to_string),
            launch_after_install: None,
            provenance: Some("test".to_string()),
        }
    }

    fn execute_plan_tool(target_text: &str, manager_preference: Option<&str>) -> AgentTool {
        AgentTool::SoftwareInstallExecutePlan {
            plan_ref: software_install_plan_ref_for_request(&request(
                target_text,
                manager_preference,
            )),
        }
    }

    fn resolve_tool(target_text: &str, manager_preference: Option<&str>) -> AgentTool {
        AgentTool::SoftwareInstallResolve {
            request: request(target_text, manager_preference),
        }
    }

    #[test]
    fn explicit_manager_install_keeps_package_manager_path_for_unknown_package() {
        let target = resolve_install_target("generic-tool", Some("apt-get")).expect("target");
        assert_eq!(target.source_kind, "package_manager");
        assert_eq!(target.manager, "apt-get");
        assert_eq!(target.package_id, "generic-tool");
        assert!(unsupported_target_error(&target).is_none());
    }

    #[test]
    fn install_resolution_checks_capture_pre_execution_plan() {
        let checks =
            install_resolution_checks_for_tool(&execute_plan_tool("generic tool", Some("apt")));
        let joined = checks.join("\n");

        assert!(joined.contains("software_install.display_name=generic tool"));
        assert!(joined.contains("software_install.manager=apt-get"));
        assert!(joined.contains("software_install.source_kind=package_manager"));
        assert!(joined.contains("software_install.verification=generic-tool --version"));
        assert!(joined.contains("software_install.command=sudo -n apt-get install -y generic-tool"));
    }

    #[test]
    fn unknown_auto_install_target_blocks_without_package_manager_guess() {
        let target = resolve_install_target("snorflepaint", Some("auto")).expect("target");
        assert_eq!(target.source_kind, "unresolved");
        assert!(target.manager.is_empty());
        assert!(target.package_id.is_empty());
        assert!(unsupported_target_error(&target)
            .expect("unknown app should block")
            .contains("No verified install candidate"));

        let checks =
            install_resolution_checks_for_tool(&resolve_tool("snorflepaint", Some("auto")))
                .join("\n");
        assert!(checks.contains("software_install.source_kind=unresolved"));
        assert!(checks.contains("software_install.manager="));
        assert!(checks.contains("software_install.package_id="));
        assert!(checks.contains("software_install.command=not_available"));
        assert!(checks.contains("No verified install candidate"));
    }

    #[test]
    fn autopilot_resolves_to_current_product_not_github_copilot() {
        let target = resolve_install_target("autopilot", Some("auto")).expect("target");
        assert_eq!(target.display_name, "IOI Autopilot");
        assert_eq!(target.canonical_id, "ioi-autopilot");
        assert_eq!(target.target_kind, "current_product");
        assert_eq!(target.source_kind, "current_app");
        assert!(unsupported_target_error(&target)
            .expect("self install should block")
            .contains("current product"));
    }

    #[test]
    fn autopilot_current_product_can_complete_as_already_available() {
        let summary = install_already_satisfied_before_approval_for_tool(&resolve_tool(
            "autopilot",
            Some("auto"),
        ))
        .expect("current executable verifies the running product");

        assert!(summary.contains("IOI Autopilot"));
        assert!(summary.contains("already_available_verified"));
        assert!(summary.contains("install_final_receipt"));
        assert!(!summary.contains("GitHub Copilot"));
    }

    #[test]
    fn production_runtime_does_not_expose_legacy_install_tool_contract() {
        let source = include_str!("install.rs");
        let legacy_tool_name = ["package", "__install"].concat();
        let legacy_variant_name = ["Sys", "Install", "Package"].concat();
        assert!(
            !source.contains(&legacy_tool_name) && !source.contains(&legacy_variant_name),
            "software install runtime must not retain legacy package install contract"
        );
    }

    #[test]
    fn execution_module_does_not_own_install_provider_discovery() {
        let source = include_str!("install.rs");
        for forbidden in [
            ["fetch_text", "_with_system_tool"].concat(),
            ["search_official", "_source_url"].concat(),
            ["package_manager", "_has_exact_candidate"].concat(),
            ["current_product", "_target("].concat(),
            ["install_product", "_metadata"].concat(),
            ["install", "_resolver"].concat(),
        ] {
            assert!(
                !source.contains(&forbidden),
                "CEC install executor must not contain resolver/provider discovery: {forbidden}"
            );
        }
    }

    #[test]
    fn supports_cross_platform_manager_normalization() {
        for (raw, expected) in [
            ("apt", "apt-get"),
            ("cask", "brew-cask"),
            ("chocolatey", "choco"),
            ("pacman", "pacman"),
            ("zypper", "zypper"),
            ("apk", "apk"),
            ("flatpak", "flatpak"),
            ("snap", "snap"),
            ("scoop", "scoop"),
        ] {
            assert_eq!(normalize_install_manager(Some(raw)), expected);
        }
    }
}
