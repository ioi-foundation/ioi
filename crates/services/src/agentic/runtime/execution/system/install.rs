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
use crate::agentic::runtime::runtime_secret;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ioi_drivers::terminal::CommandExecutionOptions;
use ioi_types::app::agentic::{AgentTool, SoftwareInstallRequestFrame};
use ioi_types::app::{WorkloadActivityKind, WorkloadExecReceipt, WorkloadReceipt};
use serde::{Deserialize, Serialize};
use std::env;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

const INSTALL_COMMAND_TIMEOUT: Duration = Duration::from_secs(600);
const RUNTIME_SECRET_KIND_SUDO_PASSWORD: &str = "sudo_password";
const INSTALL_RESOLVER_FETCH_TIMEOUT_SECS: &str = "6";

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ResolvedInstallTarget {
    pub display_name: String,
    pub canonical_id: String,
    pub target_kind: String,
    pub platform: String,
    pub architecture: String,
    pub source_kind: String,
    pub manager: String,
    pub package_id: String,
    pub installer_url: Option<String>,
    pub source_discovery_url: Option<String>,
    pub requires_elevation: bool,
    pub verification_command: Option<Vec<String>>,
    pub launch_target: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum InstallResolutionPlan {
    Resolved(ResolvedInstallTarget),
    Unsupported(ResolvedInstallTarget),
    Ambiguous {
        target_text: String,
        candidates: Vec<String>,
    },
    Unresolved(ResolvedInstallTarget),
}

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
    request: SoftwareInstallRequestFrame,
}

pub(crate) fn software_install_plan_ref_for_request(
    request: &SoftwareInstallRequestFrame,
) -> String {
    let payload = SoftwareInstallPlanRefPayload {
        version: 1,
        request: request.clone(),
    };
    let bytes = serde_json::to_vec(&payload).unwrap_or_default();
    format!("software-install-plan:v1:{}", URL_SAFE_NO_PAD.encode(bytes))
}

fn software_install_request_from_plan_ref(
    plan_ref: &str,
) -> Result<SoftwareInstallRequestFrame, String> {
    let encoded = plan_ref
        .strip_prefix("software-install-plan:v1:")
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
    if payload.version != 1 {
        return Err(format!(
            "ERROR_CLASS=InstallerResolutionRequired Unsupported software install plan version '{}'.",
            payload.version
        ));
    }
    Ok(payload.request)
}

pub(super) async fn handle_software_install_resolve(
    request: &SoftwareInstallRequestFrame,
) -> ToolExecutionResult {
    match resolve_install_plan_for_request(request) {
        Ok(InstallResolutionPlan::Resolved(target)) => {
            let plan_ref = software_install_plan_ref_for_request(request);
            ToolExecutionResult::success(format!(
                "Software install plan resolved. SOFTWARE_INSTALL stage='resolved' target='{}' canonical_id='{}' target_kind='{}' platform='{}' architecture='{}' source_kind='{}' manager='{}' package_id='{}' plan_ref='{}' provenance='{}' verification='{}'",
                compact_resolution_value(&target.display_name),
                compact_resolution_value(&target.canonical_id),
                compact_resolution_value(&target.target_kind),
                compact_resolution_value(&target.platform),
                compact_resolution_value(&target.architecture),
                compact_resolution_value(&target.source_kind),
                compact_resolution_value(&target.manager),
                compact_resolution_value(&target.package_id),
                compact_resolution_value(&plan_ref),
                compact_resolution_value(target.source_discovery_url.as_deref().unwrap_or("resolver_provider")),
                compact_resolution_value(&verification_preview(&target)),
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

    let request = match software_install_request_from_plan_ref(plan_ref) {
        Ok(request) => request,
        Err(error) => return ToolExecutionResult::failure(error),
    };
    let target_text = request.target_text.trim();
    if target_text.is_empty() {
        return ToolExecutionResult::failure(
            "ERROR_CLASS=MissingDependency Software install target cannot be empty.".to_string(),
        );
    }

    let target = match resolve_install_plan_for_request(&request) {
        Ok(InstallResolutionPlan::Resolved(target)) => target,
        Ok(plan) => {
            return ToolExecutionResult::failure(install_plan_blocker_error(&plan));
        }
        Err(error) => return ToolExecutionResult::failure(error),
    };

    let manager = target.manager.clone();
    let mut stdin_data: Option<Vec<u8>> = None;
    let mut used_runtime_password = false;
    let (command, mut args) = match install_command_for_target(&target) {
        Ok(command) => command,
        Err(error) => return ToolExecutionResult::failure(error),
    };

    if target.requires_elevation {
        let session_id_hex = hex::encode(session_id);
        if let Some(secret) =
            runtime_secret::take_secret(&session_id_hex, RUNTIME_SECRET_KIND_SUDO_PASSWORD)
        {
            used_runtime_password = true;
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
                ToolExecutionResult::failure(format!(
                    "ERROR_CLASS={} Failed to install '{}' via '{}': {}. {}",
                    class,
                    target_text,
                    manager,
                    summarize_install_failure_output(&output),
                    install_resolution_receipt(&target, "failed", &receipt_preview),
                ))
            } else {
                let mode_note = if used_runtime_password {
                    "sudo-password"
                } else {
                    command.as_str()
                };
                match verify_install_target(exec, &target, Some(resolved_cwd.as_path())).await {
                    Ok(verification) => ToolExecutionResult::success(format!(
                        "Installed '{}' as '{}' via '{}' (source_kind={}, mode={}); verification passed: {}. {}",
                        target.display_name,
                        target.package_id,
                        target.manager,
                        target.source_kind,
                        mode_note,
                        verification,
                        install_resolution_receipt(&target, "installed", &receipt_preview),
                    )),
                    Err(verification_error) => ToolExecutionResult::failure(format!(
                        "ERROR_CLASS=VerificationFailed Package manager completed for '{}' via '{}', but verification failed: {}. {}",
                        target.display_name,
                        target.manager,
                        verification_error,
                        install_resolution_receipt(&target, "verification_failed", &receipt_preview),
                    )),
                }
            }
        }
        Err(e) => {
            let msg = e.to_string();
            let class = classify_install_failure(msg.as_str(), &command, &manager);
            ToolExecutionResult::failure(format!(
                "ERROR_CLASS={} Failed to install '{}' via '{}': {}. {}",
                class,
                target_text,
                manager,
                msg,
                install_resolution_receipt(&target, "failed", &receipt_preview),
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
        return Some(format!(
            "Already available: '{}' resolves to the running product, so no host mutation was performed; verification passed: current executable exists at {}. SOFTWARE_INSTALL stage='already_available' display_name='{}' canonical_id='{}' target_kind='{}' platform='{}' architecture='{}' source_kind='{}' manager='{}' package_id='{}' requires_elevation='false' verification='current_exe_exists' command='skipped_already_available'",
            target.display_name,
            compact_resolution_value(current_exe.to_string_lossy().as_ref()),
            target.display_name,
            target.canonical_id,
            target.target_kind,
            target.platform,
            target.architecture,
            target.source_kind,
            target.manager,
            target.package_id,
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

    Some(format!(
        "Already installed: '{}' is present before host mutation; verification passed: {}. SOFTWARE_INSTALL stage='already_installed' display_name='{}' canonical_id='{}' target_kind='{}' platform='{}' architecture='{}' source_kind='{}' manager='{}' package_id='{}' requires_elevation='{}' verification='{}' command='skipped_already_installed'",
        target.display_name,
        compact_resolution_value(&verification),
        target.display_name,
        target.canonical_id,
        target.target_kind,
        target.platform,
        target.architecture,
        target.source_kind,
        target.manager,
        target.package_id,
        target.requires_elevation,
        verification_preview(&target),
    ))
}

fn install_request_from_tool(tool: &AgentTool) -> Option<SoftwareInstallRequestFrame> {
    match tool {
        AgentTool::SoftwareInstallResolve { request } => Some(request.clone()),
        AgentTool::SoftwareInstallExecutePlan { plan_ref } => {
            software_install_request_from_plan_ref(plan_ref).ok()
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

fn supported_install_managers() -> &'static [&'static str] {
    &[
        "apt-get",
        "brew",
        "brew-cask",
        "pip",
        "npm",
        "pnpm",
        "cargo",
        "winget",
        "choco",
        "scoop",
        "yum",
        "dnf",
        "pacman",
        "zypper",
        "apk",
        "flatpak",
        "snap",
        "appimage",
        "manual",
        "self",
    ]
}

fn command_exists(command: &str) -> bool {
    let Some(paths) = env::var_os("PATH") else {
        return false;
    };
    let candidates = if cfg!(windows) {
        vec![
            command.to_string(),
            format!("{command}.exe"),
            format!("{command}.cmd"),
            format!("{command}.bat"),
        ]
    } else {
        vec![command.to_string()]
    };
    env::split_paths(&paths).any(|path| {
        candidates
            .iter()
            .map(|candidate| path.join(candidate))
            .any(|candidate| candidate.is_file())
    })
}

fn first_available_manager(candidates: &[&str], fallback: &str) -> String {
    candidates
        .iter()
        .copied()
        .find(|candidate| {
            let command = match *candidate {
                "brew-cask" => "brew",
                "apt-get" => "apt-get",
                other => other,
            };
            command_exists(command)
        })
        .unwrap_or(fallback)
        .to_string()
}

fn default_install_manager() -> String {
    if cfg!(target_os = "macos") {
        first_available_manager(&["brew"], "brew")
    } else if cfg!(target_os = "windows") {
        first_available_manager(&["winget", "choco", "scoop"], "winget")
    } else {
        first_available_manager(
            &[
                "apt-get", "dnf", "yum", "pacman", "zypper", "apk", "flatpak", "snap",
            ],
            "apt-get",
        )
    }
}

fn normalize_install_manager(raw: Option<&str>) -> String {
    let manager = raw
        .map(|m| m.trim().to_ascii_lowercase())
        .filter(|m| !m.is_empty())
        .unwrap_or_else(default_install_manager);
    match manager.as_str() {
        "auto" | "default" | "system" => default_install_manager(),
        "apt" | "apt-get" => "apt-get".to_string(),
        "brew" => "brew".to_string(),
        "cask" | "brew-cask" | "homebrew-cask" => "brew-cask".to_string(),
        "pip" | "pip3" => "pip".to_string(),
        "npm" => "npm".to_string(),
        "pnpm" => "pnpm".to_string(),
        "cargo" => "cargo".to_string(),
        "winget" => "winget".to_string(),
        "choco" | "chocolatey" => "choco".to_string(),
        "scoop" => "scoop".to_string(),
        "yum" => "yum".to_string(),
        "dnf" => "dnf".to_string(),
        "pacman" => "pacman".to_string(),
        "zypper" => "zypper".to_string(),
        "apk" => "apk".to_string(),
        "flatpak" => "flatpak".to_string(),
        "snap" => "snap".to_string(),
        "appimage" | "app-image" => "appimage".to_string(),
        "manual" | "official-installer" => "manual".to_string(),
        "self" => "self".to_string(),
        _ => manager,
    }
}

fn host_platform() -> String {
    env::consts::OS.to_string()
}

fn host_architecture() -> String {
    env::consts::ARCH.to_string()
}

fn canonical_package_key(package: &str) -> String {
    package
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .flat_map(|ch| ch.to_lowercase())
        .collect()
}

fn generic_resolved_target(package: &str, manager: String) -> ResolvedInstallTarget {
    ResolvedInstallTarget {
        display_name: package.to_string(),
        canonical_id: canonical_package_key(package),
        target_kind: "package".to_string(),
        platform: host_platform(),
        architecture: host_architecture(),
        source_kind: "package_manager".to_string(),
        requires_elevation: manager_requires_elevation(&manager),
        manager,
        package_id: package.to_string(),
        installer_url: None,
        source_discovery_url: None,
        verification_command: None,
        launch_target: None,
    }
}

fn unknown_resolved_target(package: &str, manager: String) -> ResolvedInstallTarget {
    ResolvedInstallTarget {
        display_name: package.to_string(),
        canonical_id: canonical_package_key(package),
        target_kind: "unknown".to_string(),
        platform: host_platform(),
        architecture: host_architecture(),
        source_kind: "unknown_target".to_string(),
        requires_elevation: false,
        manager,
        package_id: package.to_string(),
        installer_url: None,
        source_discovery_url: None,
        verification_command: None,
        launch_target: None,
    }
}

struct CurrentProductInstallIdentity {
    display_name: String,
    canonical_id: String,
    aliases: Vec<String>,
}

fn current_product_install_identity() -> CurrentProductInstallIdentity {
    let display_name = env::var("IOI_PRODUCT_INSTALL_DISPLAY_NAME")
        .unwrap_or_else(|_| "IOI Autopilot".to_string());
    let canonical_id = env::var("IOI_PRODUCT_INSTALL_CANONICAL_ID")
        .unwrap_or_else(|_| "ioi-autopilot".to_string());
    let aliases = env::var("IOI_PRODUCT_INSTALL_ALIASES")
        .unwrap_or_else(|_| "autopilot,ioi autopilot".to_string())
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .collect();
    CurrentProductInstallIdentity {
        display_name,
        canonical_id,
        aliases,
    }
}

fn current_product_target(package: &str) -> Option<ResolvedInstallTarget> {
    let key = canonical_package_key(package);
    let identity = current_product_install_identity();
    if !identity
        .aliases
        .iter()
        .any(|alias| canonical_package_key(alias) == key)
    {
        return None;
    }
    Some(ResolvedInstallTarget {
        display_name: identity.display_name.clone(),
        canonical_id: identity.canonical_id.clone(),
        target_kind: "current_product".to_string(),
        platform: host_platform(),
        architecture: host_architecture(),
        source_kind: "current_app".to_string(),
        manager: "self".to_string(),
        package_id: identity.canonical_id,
        installer_url: None,
        source_discovery_url: None,
        requires_elevation: false,
        verification_command: None,
        launch_target: Some(identity.display_name),
    })
}

fn slugify_package_id(target: &str, separator: &str) -> String {
    let mut out = String::new();
    let mut last_was_sep = false;
    for ch in target.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            last_was_sep = false;
        } else if !last_was_sep {
            out.push_str(separator);
            last_was_sep = true;
        }
    }
    out.trim_matches(|ch| separator.contains(ch)).to_string()
}

fn manager_package_id_for_target(target: &str, manager: &str) -> String {
    match manager {
        "npm" => target.trim().to_string(),
        "pip" | "cargo" | "pnpm" => slugify_package_id(target, "-"),
        "brew-cask" => slugify_package_id(target, "-"),
        "flatpak" => target.trim().to_string(),
        "winget" | "choco" | "scoop" => target.trim().to_string(),
        _ => slugify_package_id(target, "-"),
    }
}

fn inferred_verification_command(
    package_id: &str,
    target_kind: Option<&str>,
) -> Option<Vec<String>> {
    if matches!(target_kind, Some("desktop_app" | "editor_extension")) {
        return None;
    }
    let binary = package_id
        .rsplit(['/', ':'])
        .next()
        .unwrap_or(package_id)
        .trim()
        .to_string();
    if binary.is_empty() {
        None
    } else {
        Some(vec![binary, "--version".to_string()])
    }
}

fn explicit_manager_target(
    request: &SoftwareInstallRequestFrame,
    manager: String,
) -> ResolvedInstallTarget {
    let package_id = manager_package_id_for_target(&request.target_text, &manager);
    let mut target = generic_resolved_target(&package_id, manager);
    target.display_name = request.target_text.trim().to_string();
    target.target_kind = request
        .target_kind
        .clone()
        .unwrap_or_else(|| "package".to_string());
    target.verification_command =
        inferred_verification_command(&target.package_id, request.target_kind.as_deref());
    target
}

fn auto_discovery_managers_for_host() -> Vec<&'static str> {
    if cfg!(target_os = "macos") {
        vec!["brew", "brew-cask"]
    } else if cfg!(target_os = "windows") {
        vec!["winget", "choco", "scoop"]
    } else {
        vec![
            "apt-get", "dnf", "yum", "pacman", "zypper", "apk", "flatpak", "snap",
        ]
    }
}

fn manager_probe_binary(manager: &str) -> &str {
    match manager {
        "apt-get" => "apt-cache",
        "brew-cask" => "brew",
        other => other,
    }
}

fn manager_exact_probe(manager: &str, package_id: &str) -> Option<(String, Vec<String>)> {
    let pkg = package_id.trim();
    if pkg.is_empty() {
        return None;
    }
    let args = match manager {
        "apt-get" => vec![
            "show".to_string(),
            "--no-all-versions".to_string(),
            pkg.to_string(),
        ],
        "dnf" | "yum" => vec!["info".to_string(), pkg.to_string()],
        "pacman" => vec!["-Si".to_string(), pkg.to_string()],
        "zypper" => vec!["info".to_string(), pkg.to_string()],
        "apk" => vec!["info".to_string(), "-a".to_string(), pkg.to_string()],
        "flatpak" => vec![
            "remote-info".to_string(),
            "flathub".to_string(),
            pkg.to_string(),
        ],
        "snap" => vec!["info".to_string(), pkg.to_string()],
        "brew" => vec!["info".to_string(), "--formula".to_string(), pkg.to_string()],
        "brew-cask" => vec!["info".to_string(), "--cask".to_string(), pkg.to_string()],
        "winget" => vec![
            "search".to_string(),
            "--exact".to_string(),
            "--id".to_string(),
            pkg.to_string(),
        ],
        "choco" => vec!["search".to_string(), "--exact".to_string(), pkg.to_string()],
        "scoop" => vec!["search".to_string(), pkg.to_string()],
        _ => return None,
    };
    Some((manager_probe_binary(manager).to_string(), args))
}

fn package_manager_has_exact_candidate(manager: &str, package_id: &str) -> bool {
    let Some((binary, args)) = manager_exact_probe(manager, package_id) else {
        return false;
    };
    if !command_exists(&binary) {
        return false;
    }
    Command::new(binary)
        .args(args)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .is_some()
}

fn package_id_candidates_for_auto(target: &str) -> Vec<String> {
    let mut candidates = Vec::new();
    for candidate in [
        target.trim().to_string(),
        slugify_package_id(target, "-"),
        slugify_package_id(target, ""),
    ] {
        let candidate = candidate.trim().to_string();
        if candidate.is_empty() || candidates.iter().any(|seen| seen == &candidate) {
            continue;
        }
        candidates.push(candidate);
    }
    candidates
}

fn discover_package_manager_candidates(
    request: &SoftwareInstallRequestFrame,
) -> Vec<ResolvedInstallTarget> {
    let mut candidates = Vec::new();
    for manager in auto_discovery_managers_for_host() {
        for package_id in package_id_candidates_for_auto(&request.target_text) {
            if !package_manager_has_exact_candidate(manager, &package_id) {
                continue;
            }
            let mut target = generic_resolved_target(&package_id, manager.to_string());
            target.display_name = request.target_text.trim().to_string();
            target.target_kind = request
                .target_kind
                .clone()
                .unwrap_or_else(|| "package".to_string());
            target.verification_command =
                inferred_verification_command(&target.package_id, request.target_kind.as_deref());
            candidates.push(target);
        }
    }
    candidates
}

fn fetch_text_with_system_tool(url: &str) -> Option<String> {
    let output = if command_exists("curl") {
        Command::new("curl")
            .args([
                "-fsSL",
                "--compressed",
                "--max-time",
                INSTALL_RESOLVER_FETCH_TIMEOUT_SECS,
                "-A",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124 Safari/537.36",
                "-H",
                "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "-H",
                "Accept-Language: en-US,en;q=0.9",
                url,
            ])
            .output()
            .ok()?
    } else if command_exists("wget") {
        Command::new("wget")
            .args([
                "-qO-",
                "--timeout=6",
                "--user-agent=Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124 Safari/537.36",
                "--header=Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "--header=Accept-Language: en-US,en;q=0.9",
                url,
            ])
            .output()
            .ok()?
    } else {
        return None;
    };
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).to_string())
}

fn compact_target_tokens(target: &str) -> Vec<String> {
    target
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter(|term| term.len() > 1)
        .map(|term| term.to_ascii_lowercase())
        .collect()
}

fn html_entity_decode_basic(value: &str) -> String {
    value
        .replace("&amp;", "&")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&apos;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
}

fn query_encode(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

fn push_unique(values: &mut Vec<String>, value: String) {
    if !values.iter().any(|seen| seen == &value) {
        values.push(value);
    }
}

fn url_from_candidate(raw: &str, base_url: &str) -> Option<String> {
    let decoded = html_entity_decode_basic(raw.trim());
    if decoded.is_empty() || decoded.starts_with('#') || decoded.starts_with("javascript:") {
        return None;
    }

    let absolute = if decoded.starts_with("//") {
        format!("https:{decoded}")
    } else if decoded.starts_with('/') {
        let base = url::Url::parse(base_url).ok()?;
        base.join(&decoded).ok()?.to_string()
    } else {
        decoded
    };

    let parsed = url::Url::parse(&absolute).ok()?;
    if parsed
        .host_str()
        .unwrap_or_default()
        .contains("duckduckgo.com")
    {
        if let Some((_, uddg)) = parsed.query_pairs().find(|(key, _)| key == "uddg") {
            return Some(uddg.into_owned());
        }
    }

    Some(parsed.to_string())
}

fn extract_links_from_text(text: &str, base_url: &str) -> Vec<String> {
    let mut links = Vec::new();
    for token in text.split(['"', '\'', '<', '>', ' ', '\n', '\r', '\t', '(', ')', ',']) {
        let Some(url) = url_from_candidate(token, base_url) else {
            continue;
        };
        push_unique(&mut links, url);
    }

    for marker in ["href=", "src=", "url=", "downloadUrl"] {
        let mut rest = text;
        while let Some((_, after_marker)) = rest.split_once(marker) {
            let trimmed = after_marker.trim_start_matches([' ', ':', '=']);
            let quote = trimmed.chars().next().unwrap_or_default();
            if matches!(quote, '"' | '\'') {
                if let Some(end) = trimmed[1..].find(quote) {
                    if let Some(url) = url_from_candidate(&trimmed[1..1 + end], base_url) {
                        push_unique(&mut links, url);
                    }
                    rest = &trimmed[1 + end..];
                    continue;
                }
            }
            rest = trimmed;
        }
    }

    links
}

fn is_search_or_asset_url(url: &str) -> bool {
    let Ok(parsed) = url::Url::parse(url) else {
        return true;
    };
    let host = parsed.host_str().unwrap_or_default();
    if [
        "duckduckgo.com",
        "bing.com",
        "google.com",
        "brave.com",
        "yahoo.com",
        "w3.org",
    ]
    .iter()
    .any(|blocked| host.ends_with(blocked))
    {
        return true;
    }
    let path = parsed.path().to_ascii_lowercase();
    path.ends_with(".css")
        || path.ends_with(".js")
        || path.ends_with(".png")
        || path.ends_with(".jpg")
        || path.ends_with(".jpeg")
        || path.ends_with(".gif")
        || path.ends_with(".svg")
        || path.ends_with(".ico")
        || path.ends_with(".woff")
        || path.ends_with(".woff2")
}

fn url_matches_target(url: &str, target: &str) -> bool {
    let compact_target = canonical_package_key(target);
    if compact_target.is_empty() {
        return false;
    }
    let compact_url = canonical_package_key(url);
    if compact_url.contains(&compact_target) {
        return true;
    }
    let tokens = compact_target_tokens(target);
    !tokens.is_empty()
        && tokens
            .iter()
            .all(|token| compact_url.contains(&canonical_package_key(token)))
}

fn source_page_matches_target(target: &str, source_url: &str, html: &str) -> bool {
    if !url_matches_target(source_url, target) && !url_matches_target(html, target) {
        return false;
    }
    let lower = html.to_ascii_lowercase();
    lower.contains("softwareapplication")
        || lower.contains("downloadurl")
        || lower.contains("download")
        || lower.contains("appimage")
        || lower.contains("installer")
}

fn query_derived_source_candidates(target: &str) -> Vec<String> {
    let mut candidates = Vec::new();
    let compact = canonical_package_key(target);
    let dashed = slugify_package_id(target, "-");
    for stem in [compact, dashed] {
        if stem.is_empty() {
            continue;
        }
        for tld in ["com", "ai", "app", "dev", "io", "org", "net"] {
            let origin = format!("https://{stem}.{tld}");
            push_unique(&mut candidates, format!("{origin}/download"));
            push_unique(&mut candidates, format!("{origin}/downloads"));
            push_unique(&mut candidates, origin);
        }
    }
    candidates
}

fn search_engine_source_candidates(target: &str) -> Vec<String> {
    let mut candidates = Vec::new();
    let queries = [
        format!("{target} official download"),
        format!("\"{target}\" official download"),
    ];
    for query in queries {
        let encoded = query_encode(&query);
        for endpoint in [
            format!("https://duckduckgo.com/html/?q={encoded}"),
            format!("https://lite.duckduckgo.com/lite/?q={encoded}"),
            format!("https://www.bing.com/search?format=rss&q={encoded}"),
        ] {
            let Some(html) = fetch_text_with_system_tool(&endpoint) else {
                continue;
            };
            for link in extract_links_from_text(&html, &endpoint) {
                if is_search_or_asset_url(&link) || !url_matches_target(&link, target) {
                    continue;
                }
                push_unique(&mut candidates, link);
            }
        }
    }
    candidates
}

fn search_official_source_url(target: &str) -> Option<String> {
    let mut candidates = query_derived_source_candidates(target);
    for candidate in search_engine_source_candidates(target) {
        push_unique(&mut candidates, candidate);
    }

    for candidate in candidates.into_iter().take(48) {
        if is_search_or_asset_url(&candidate) {
            continue;
        }
        let Some(html) = fetch_text_with_system_tool(&candidate) else {
            continue;
        };
        if source_page_matches_target(target, &candidate, &html) {
            return Some(candidate);
        }
    }

    None
}

fn appimage_installer_url_from_html(source_url: &str, source_html: &str) -> Option<String> {
    let normalized = source_html.replace(['\\', '\n', '\r'], "");
    for link in extract_links_from_text(&normalized, source_url) {
        if link.contains(".AppImage") {
            return Some(link);
        }
    }

    let origin = url::Url::parse(source_url).ok()?;
    let origin = format!(
        "{}://{}",
        origin.scheme(),
        origin.host_str().unwrap_or_default()
    );
    let route_prefix = normalized
        .split('"')
        .find(|part| part.starts_with("/download/") && part.ends_with('/'))?;
    Some(format!(
        "{}{}linux/{}?format=AppImage",
        origin,
        route_prefix,
        download_artifact_architecture(&host_architecture())
    ))
}

fn internal_download_pages(source_url: &str, source_html: &str) -> Vec<String> {
    extract_links_from_text(source_html, source_url)
        .into_iter()
        .filter(|link| {
            let same_origin = match (url::Url::parse(source_url), url::Url::parse(link)) {
                (Ok(source), Ok(candidate)) => source.host_str() == candidate.host_str(),
                _ => false,
            };
            same_origin && link.to_ascii_lowercase().contains("download")
        })
        .collect()
}

fn discover_appimage_candidate(target: &str, source_url: &str) -> Option<ResolvedInstallTarget> {
    let source_html = fetch_text_with_system_tool(source_url)?;
    let installer_url =
        appimage_installer_url_from_html(source_url, &source_html).or_else(|| {
            for download_page in internal_download_pages(source_url, &source_html) {
                let Some(download_html) = fetch_text_with_system_tool(&download_page) else {
                    continue;
                };
                if let Some(url) = appimage_installer_url_from_html(&download_page, &download_html)
                {
                    return Some(url);
                }
            }
            None
        })?;
    let display_name = target.trim().to_string();
    let canonical_id = slugify_package_id(&display_name, "-");
    let appimage_name = format!(
        "{}.AppImage",
        display_name
            .split_whitespace()
            .collect::<Vec<_>>()
            .join("-")
    );
    Some(ResolvedInstallTarget {
        display_name: display_name.clone(),
        canonical_id,
        target_kind: "desktop_app".to_string(),
        platform: host_platform(),
        architecture: host_architecture(),
        source_kind: "appimage".to_string(),
        manager: "appimage".to_string(),
        package_id: appimage_name,
        installer_url: Some(installer_url),
        source_discovery_url: Some(source_url.to_string()),
        requires_elevation: false,
        verification_command: Some(vec![
            "sh".to_string(),
            "-lc".to_string(),
            format!(
                "test -x \"$HOME/.local/bin/{}\" || test -x \"$HOME/.local/bin/{}\"",
                display_name
                    .split_whitespace()
                    .collect::<Vec<_>>()
                    .join("-")
                    + ".AppImage",
                slugify_package_id(&display_name, "-")
            ),
        ]),
        launch_target: Some(display_name),
    })
}

pub(crate) fn resolve_install_plan_for_request(
    request: &SoftwareInstallRequestFrame,
) -> Result<InstallResolutionPlan, String> {
    let target_text = request.target_text.trim();
    if target_text.is_empty() {
        return Err(
            "ERROR_CLASS=MissingDependency Software install target cannot be empty.".to_string(),
        );
    }
    let requested_manager = request.manager_preference.as_deref();
    let manager_was_auto = requested_manager
        .map(|manager| manager.trim().to_ascii_lowercase())
        .filter(|manager| !manager.is_empty())
        .map(|manager| matches!(manager.as_str(), "auto" | "default" | "system"))
        .unwrap_or(true);
    let manager = normalize_install_manager(requested_manager);
    if !supported_install_managers().contains(&manager.as_str()) {
        return Err(format!(
            "ERROR_CLASS=ToolUnavailable Unsupported package manager '{}'. Supported managers: {}.",
            manager,
            supported_install_managers().join(", ")
        ));
    }

    if let Some(target) = current_product_target(target_text) {
        return Ok(InstallResolutionPlan::Unsupported(target));
    }

    if !manager_was_auto {
        return Ok(InstallResolutionPlan::Resolved(explicit_manager_target(
            request, manager,
        )));
    }

    let package_manager_candidates = discover_package_manager_candidates(request);
    if package_manager_candidates.len() == 1 {
        return Ok(InstallResolutionPlan::Resolved(
            package_manager_candidates
                .into_iter()
                .next()
                .expect("len checked"),
        ));
    }
    if package_manager_candidates.len() > 1 {
        return Ok(InstallResolutionPlan::Ambiguous {
            target_text: target_text.to_string(),
            candidates: package_manager_candidates
                .into_iter()
                .map(|target| format!("{} via {}", target.package_id, target.manager))
                .collect(),
        });
    }

    if host_platform() == "linux" {
        if let Some(source_url) = search_official_source_url(target_text) {
            if let Some(target) = discover_appimage_candidate(target_text, &source_url) {
                return Ok(InstallResolutionPlan::Resolved(target));
            }
        }
    }

    Ok(InstallResolutionPlan::Unresolved(unknown_resolved_target(
        target_text,
        manager,
    )))
}

#[cfg(test)]
pub(crate) fn resolve_install_target(
    package: &str,
    requested_manager: Option<&str>,
) -> Result<ResolvedInstallTarget, String> {
    let request = SoftwareInstallRequestFrame {
        target_text: package.to_string(),
        target_kind: None,
        manager_preference: requested_manager.map(str::to_string),
        launch_after_install: None,
        provenance: Some("test".to_string()),
    };
    match resolve_install_plan_for_request(&request)? {
        InstallResolutionPlan::Resolved(target)
        | InstallResolutionPlan::Unsupported(target)
        | InstallResolutionPlan::Unresolved(target) => Ok(target),
        InstallResolutionPlan::Ambiguous {
            target_text,
            candidates,
        } => Err(format!(
            "ERROR_CLASS=InstallerResolutionRequired Install target '{}' is ambiguous. Candidates: {}.",
            target_text,
            candidates.join(", ")
        )),
    }
}

fn manager_requires_elevation(manager: &str) -> bool {
    matches!(
        manager,
        "apt-get" | "yum" | "dnf" | "pacman" | "zypper" | "apk" | "snap"
    )
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
    match target.source_kind.as_str() {
        "unsupported_platform" => Some(format!(
            "ERROR_CLASS=UnsupportedPlatform '{}' has resolver metadata, but no verified installer is registered for {} {}. SOFTWARE_INSTALL display_name='{}' canonical_id='{}' target_kind='{}' source_kind='{}'",
            target.display_name,
            target.platform,
            target.architecture,
            target.display_name,
            target.canonical_id,
            target.target_kind,
            target.source_kind,
        )),
        "manual_installer" => {
            let official_source = target
                .installer_url
                .as_deref()
                .or(target.source_discovery_url.as_deref())
                .unwrap_or("no_url_available");
            Some(format!(
            "ERROR_CLASS=InstallerResolutionRequired Resolved '{}' for {} {} as an official manual installer source ({}), but no verified unattended installer candidate passed policy for manager '{}'. SOFTWARE_INSTALL display_name='{}' canonical_id='{}' target_kind='{}' source_kind='{}' source_discovery_url='{}' verification='{}'",
            target.display_name,
            target.platform,
            target.architecture,
            official_source,
            target.manager,
            target.display_name,
            target.canonical_id,
            target.target_kind,
            target.source_kind,
            official_source,
            verification_preview(target),
        ))
        },
        "current_app" => Some(format!(
            "ERROR_CLASS=AlreadyCurrentApp '{}' resolves to the current product. Use the product release/update workflow or build artifacts for self-install/update. SOFTWARE_INSTALL display_name='{}' canonical_id='{}' target_kind='{}' source_kind='{}'",
            target.display_name, target.display_name, target.canonical_id, target.target_kind, target.source_kind
        )),
        "editor_extension" => Some(format!(
            "ERROR_CLASS=InstallerResolutionRequired '{}' resolves to an editor extension, not a desktop app package. Use an editor extension resolver for '{}'. SOFTWARE_INSTALL display_name='{}' canonical_id='{}' target_kind='{}' source_kind='{}' installer_url='{}'",
            target.display_name,
            target.package_id,
            target.display_name,
            target.canonical_id,
            target.target_kind,
            target.source_kind,
            target
                .installer_url
                .as_deref()
                .unwrap_or("no_url_available"),
        )),
        "unknown_target" => Some(format!(
            "ERROR_CLASS=InstallerResolutionRequired No verified install candidate passed resolver policy for '{}'. Specify an explicit package manager/package id or choose a resolver-supported target before mutating the host. SOFTWARE_INSTALL display_name='{}' canonical_id='{}' target_kind='{}' source_kind='{}'",
            target.display_name,
            target.display_name,
            target.canonical_id,
            target.target_kind,
            target.source_kind,
        )),
        _ => None,
    }
}

fn verification_preview(target: &ResolvedInstallTarget) -> String {
    target
        .verification_command
        .as_ref()
        .map(|parts| parts.join(" "))
        .unwrap_or_else(|| "package_manager_success_only".to_string())
}

fn download_artifact_architecture(architecture: &str) -> String {
    match architecture {
        "x86_64" | "amd64" => "x64".to_string(),
        "aarch64" => "arm64".to_string(),
        other => other.to_string(),
    }
}

fn install_resolution_receipt(
    target: &ResolvedInstallTarget,
    stage: &str,
    command: &str,
) -> String {
    let mut receipt = format!(
        "SOFTWARE_INSTALL stage='{}' display_name='{}' canonical_id='{}' target_kind='{}' platform='{}' architecture='{}' source_kind='{}' manager='{}' package_id='{}' requires_elevation='{}' verification='{}' command='{}'",
        compact_resolution_value(stage),
        compact_resolution_value(&target.display_name),
        compact_resolution_value(&target.canonical_id),
        compact_resolution_value(&target.target_kind),
        compact_resolution_value(&target.platform),
        compact_resolution_value(&target.architecture),
        compact_resolution_value(&target.source_kind),
        compact_resolution_value(&target.manager),
        compact_resolution_value(&target.package_id),
        target.requires_elevation,
        compact_resolution_value(&verification_preview(target)),
        compact_resolution_value(command),
    );
    if let Some(url) = target.installer_url.as_deref() {
        receipt.push_str(&format!(
            " installer_url='{}'",
            compact_resolution_value(url)
        ));
    }
    if let Some(url) = target.source_discovery_url.as_deref() {
        receipt.push_str(&format!(
            " source_discovery_url='{}'",
            compact_resolution_value(url)
        ));
    }
    receipt
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
        return Ok(format!(
            "manager '{}' reported success; no binary verification command is registered for '{}'",
            target.manager, target.package_id
        ));
    };
    let Some((command, args)) = parts.split_first() else {
        return Ok("verification command was empty".to_string());
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
        assert_eq!(target.source_kind, "unknown_target");
        assert!(unsupported_target_error(&target)
            .expect("unknown app should block")
            .contains("No verified install candidate"));

        let checks =
            install_resolution_checks_for_tool(&execute_plan_tool("snorflepaint", Some("auto")))
                .join("\n");
        assert!(checks.contains("software_install.source_kind=unknown_target"));
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
        let summary = install_already_satisfied_before_approval_for_tool(&execute_plan_tool(
            "autopilot",
            Some("auto"),
        ))
        .expect("current executable verifies the running product");

        assert!(summary.contains("IOI Autopilot"));
        assert!(summary.contains("stage='already_available'"));
        assert!(summary.contains("source_kind='current_app'"));
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

    #[test]
    fn provider_decodes_search_redirect_links_without_app_specific_targets() {
        let html = r#"
            <a class="result__a" href="/l/?kh=-1&amp;uddg=https%3A%2F%2Facmestudio.ai%2Fdownload">Download</a>
            <a href="https://duckduckgo.com/y.js">asset</a>
        "#;
        let links = extract_links_from_text(html, "https://duckduckgo.com/html/?q=acme+studio");

        assert!(links.contains(&"https://acmestudio.ai/download".to_string()));
        assert!(links
            .iter()
            .any(|link| url_matches_target(link, "acme studio")));
    }

    #[test]
    fn provider_extracts_download_script_links_without_app_specific_targets() {
        let html = r#"
            <script src="/_next/static/chunks/app/(dynamic)/download/page.js"></script>
        "#;
        let links = extract_links_from_text(html, "https://acmestudio.ai/download");

        assert!(links.contains(
            &"https://acmestudio.ai/_next/static/chunks/app/(dynamic)/download/page.js".to_string()
        ));
    }

    #[test]
    fn provider_derives_appimage_download_route_from_download_script() {
        let script = r#"
            function build(B,P){return "/download/latest/".concat(B,"/").concat(P)}
            params.set("format","AppImage");
        "#;
        let installer = appimage_installer_url_from_html(
            "https://acmestudio.ai/_next/static/chunks/app/(dynamic)/download/page.js",
            script,
        )
        .expect("appimage route from script");

        assert!(installer.starts_with("https://acmestudio.ai/download/latest/linux/"));
        assert!(installer.ends_with("?format=AppImage"));
    }

    #[test]
    fn provider_derives_appimage_download_route_from_official_page_metadata() {
        let html = r#"
            <script>
                let href = "/download/latest/".concat(os, "/").concat(arch) + "?format=AppImage";
            </script>
            <script type="application/ld+json">
                {"@type":"SoftwareApplication","name":"Acme Studio","downloadUrl":"https://acmestudio.ai/download"}
            </script>
        "#;

        assert!(source_page_matches_target(
            "acme studio",
            "https://acmestudio.ai/download",
            html
        ));
        let installer = appimage_installer_url_from_html("https://acmestudio.ai/download", html)
            .expect("appimage route");

        assert!(installer.starts_with("https://acmestudio.ai/download/latest/linux/"));
        assert!(installer.ends_with("?format=AppImage"));
    }

    #[test]
    fn provider_extracts_direct_appimage_link_from_download_page() {
        let html = r#"
            <a href="https://downloads.example.dev/releases/Acme-Studio-x64.AppImage">AppImage</a>
        "#;
        let installer = appimage_installer_url_from_html("https://acmestudio.ai/download", html)
            .expect("direct appimage");

        assert_eq!(
            installer,
            "https://downloads.example.dev/releases/Acme-Studio-x64.AppImage"
        );
    }
}
