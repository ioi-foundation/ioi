use super::model_mount_http::{daemon_request, print_value};
use anyhow::{anyhow, Context, Result};
use clap::{Args, Parser, Subcommand};
use reqwest::Method;
use serde_json::{json, Value};
use std::path::PathBuf;

#[derive(Parser, Debug)]
pub struct RuntimeArgs {
    /// Runtime daemon endpoint. Defaults to IOI_DAEMON_ENDPOINT or http://127.0.0.1:8765.
    #[clap(long)]
    pub endpoint: Option<String>,

    /// Capability token. Defaults to IOI_DAEMON_TOKEN.
    #[clap(long)]
    pub token: Option<String>,

    /// Emit machine-readable JSON.
    #[clap(long)]
    pub json: bool,

    #[clap(subcommand)]
    pub command: RuntimeCommands,
}

#[derive(Subcommand, Debug)]
pub enum RuntimeCommands {
    /// Submit worker/service package invocations to the daemon.
    WorkerServicePackage {
        #[clap(subcommand)]
        command: WorkerServicePackageCommands,
    },

    /// Submit cTEE Private Workspace actions to the daemon.
    CteePrivateWorkspace {
        #[clap(subcommand)]
        command: CteePrivateWorkspaceCommands,
    },

    /// Submit governed runtime-improvement proposals to the daemon.
    GovernedImprovement {
        #[clap(subcommand)]
        command: GovernedImprovementCommands,
    },

    /// Submit trigger-required sparse L1 settlement attempts to the daemon.
    L1Settlement {
        #[clap(subcommand)]
        command: L1SettlementCommands,
    },

    /// Submit external capability exit authority requests to the daemon.
    ExternalCapability {
        #[clap(subcommand)]
        command: ExternalCapabilityCommands,
    },

    /// Inspect or request workspace snapshot restore through the daemon.
    WorkspaceSnapshot {
        #[clap(subcommand)]
        command: WorkspaceSnapshotCommands,
    },
}

#[derive(Subcommand, Debug)]
pub enum WorkerServicePackageCommands {
    /// Admit an invocation through the daemon-mounted Rust package guard.
    Admit(WorkerServicePackageAdmitArgs),
}

#[derive(Args, Debug)]
pub struct WorkerServicePackageAdmitArgs {
    /// Runtime thread id that owns the admission request.
    pub thread_id: String,

    /// Worker/service package invocation JSON object.
    #[clap(long, conflicts_with = "invocation_file")]
    pub invocation_json: Option<String>,

    /// Path to a worker/service package invocation JSON file.
    #[clap(long, conflicts_with = "invocation_json")]
    pub invocation_file: Option<PathBuf>,
}

#[derive(Subcommand, Debug)]
pub enum CteePrivateWorkspaceCommands {
    /// Execute/admit an action through the daemon-mounted Rust cTEE guard.
    Execute(CteePrivateWorkspaceExecuteArgs),
}

#[derive(Args, Debug)]
pub struct CteePrivateWorkspaceExecuteArgs {
    /// Runtime thread id that owns the admission request.
    pub thread_id: String,

    /// cTEE Private Workspace action JSON object.
    #[clap(long, conflicts_with = "action_file")]
    pub action_json: Option<String>,

    /// Path to a cTEE Private Workspace action JSON file.
    #[clap(long, conflicts_with = "action_json")]
    pub action_file: Option<PathBuf>,
}

#[derive(Subcommand, Debug)]
pub enum GovernedImprovementCommands {
    /// Admit a governed improvement proposal through the daemon-mounted Rust guard.
    Admit(GovernedImprovementAdmitArgs),
}

#[derive(Args, Debug)]
pub struct GovernedImprovementAdmitArgs {
    /// Runtime thread id that owns the admission request.
    pub thread_id: String,

    /// Governed improvement proposal JSON object.
    #[clap(long, conflicts_with = "proposal_file")]
    pub proposal_json: Option<String>,

    /// Path to a governed improvement proposal JSON file.
    #[clap(long, conflicts_with = "proposal_json")]
    pub proposal_file: Option<PathBuf>,
}

#[derive(Subcommand, Debug)]
pub enum L1SettlementCommands {
    /// Admit a settlement attempt through the daemon-mounted Rust trigger guard.
    Admit(L1SettlementAdmitArgs),
}

#[derive(Args, Debug)]
pub struct L1SettlementAdmitArgs {
    /// Runtime thread id that owns the admission request.
    pub thread_id: String,

    /// Settlement attempt JSON object.
    #[clap(long, conflicts_with = "attempt_file")]
    pub attempt_json: Option<String>,

    /// Path to a settlement attempt JSON file.
    #[clap(long, conflicts_with = "attempt_json")]
    pub attempt_file: Option<PathBuf>,
}

#[derive(Subcommand, Debug)]
pub enum ExternalCapabilityCommands {
    /// Authorize an external capability exit through the daemon-mounted Rust authority guard.
    Authorize(ExternalCapabilityAuthorizeArgs),
}

#[derive(Args, Debug)]
pub struct ExternalCapabilityAuthorizeArgs {
    /// Runtime thread id that owns the authority request.
    pub thread_id: String,

    /// External capability exit authority request JSON object.
    #[clap(long, conflicts_with = "request_file")]
    pub request_json: Option<String>,

    /// Path to an external capability exit authority request JSON file.
    #[clap(long, conflicts_with = "request_json")]
    pub request_file: Option<PathBuf>,
}

#[derive(Subcommand, Debug)]
pub enum WorkspaceSnapshotCommands {
    /// List workspace snapshots recorded for a runtime thread.
    List(WorkspaceSnapshotListArgs),

    /// Preview a workspace snapshot restore through the daemon-mounted Rust restore guard.
    RestorePreview(WorkspaceSnapshotRestoreArgs),

    /// Apply a workspace snapshot restore through the daemon-mounted Rust restore guard.
    RestoreApply(WorkspaceSnapshotRestoreArgs),
}

#[derive(Args, Debug)]
pub struct WorkspaceSnapshotListArgs {
    /// Runtime thread id that owns the workspace snapshots.
    pub thread_id: String,
}

#[derive(Args, Debug)]
pub struct WorkspaceSnapshotRestoreArgs {
    /// Runtime thread id that owns the workspace snapshot.
    pub thread_id: String,

    /// Workspace snapshot id to restore.
    pub snapshot_id: String,

    /// Canonical workspace restore request JSON object.
    #[clap(long, conflicts_with = "request_file")]
    pub request_json: Option<String>,

    /// Path to a canonical workspace restore request JSON file.
    #[clap(long, conflicts_with = "request_json")]
    pub request_file: Option<PathBuf>,
}

pub async fn run(args: RuntimeArgs) -> Result<()> {
    let endpoint = args.endpoint.as_deref();
    let token = args.token.as_deref();
    let value = match args.command {
        RuntimeCommands::WorkerServicePackage { command } => match command {
            WorkerServicePackageCommands::Admit(admit_args) => {
                let invocation = parse_json_input(
                    admit_args.invocation_json.as_deref(),
                    admit_args.invocation_file.as_ref(),
                    "worker/service package invocation",
                    "--invocation-json",
                    "--invocation-file",
                )?;
                daemon_request(
                    endpoint,
                    token,
                    Method::POST,
                    &worker_service_package_invocations_route(&admit_args.thread_id),
                    Some(worker_service_package_admission_body(invocation)),
                )
                .await?
            }
        },
        RuntimeCommands::CteePrivateWorkspace { command } => match command {
            CteePrivateWorkspaceCommands::Execute(execute_args) => {
                let action = parse_json_input(
                    execute_args.action_json.as_deref(),
                    execute_args.action_file.as_ref(),
                    "cTEE private workspace action",
                    "--action-json",
                    "--action-file",
                )?;
                daemon_request(
                    endpoint,
                    token,
                    Method::POST,
                    &ctee_private_workspace_actions_route(&execute_args.thread_id),
                    Some(ctee_private_workspace_action_body(action)),
                )
                .await?
            }
        },
        RuntimeCommands::GovernedImprovement { command } => match command {
            GovernedImprovementCommands::Admit(admit_args) => {
                let proposal = parse_json_input(
                    admit_args.proposal_json.as_deref(),
                    admit_args.proposal_file.as_ref(),
                    "governed improvement proposal",
                    "--proposal-json",
                    "--proposal-file",
                )?;
                daemon_request(
                    endpoint,
                    token,
                    Method::POST,
                    &governed_improvement_proposals_route(&admit_args.thread_id),
                    Some(governed_improvement_proposal_admission_body(proposal)),
                )
                .await?
            }
        },
        RuntimeCommands::L1Settlement { command } => match command {
            L1SettlementCommands::Admit(admit_args) => {
                let attempt = parse_json_input(
                    admit_args.attempt_json.as_deref(),
                    admit_args.attempt_file.as_ref(),
                    "L1 settlement attempt",
                    "--attempt-json",
                    "--attempt-file",
                )?;
                daemon_request(
                    endpoint,
                    token,
                    Method::POST,
                    &l1_settlement_attempts_route(&admit_args.thread_id),
                    Some(l1_settlement_admission_body(attempt)),
                )
                .await?
            }
        },
        RuntimeCommands::ExternalCapability { command } => match command {
            ExternalCapabilityCommands::Authorize(authorize_args) => {
                let request = parse_json_input(
                    authorize_args.request_json.as_deref(),
                    authorize_args.request_file.as_ref(),
                    "external capability authority request",
                    "--request-json",
                    "--request-file",
                )?;
                daemon_request(
                    endpoint,
                    token,
                    Method::POST,
                    &external_capability_exits_route(&authorize_args.thread_id),
                    Some(external_capability_authority_body(request)),
                )
                .await?
            }
        },
        RuntimeCommands::WorkspaceSnapshot { command } => match command {
            WorkspaceSnapshotCommands::List(list_args) => {
                daemon_request(
                    endpoint,
                    token,
                    Method::GET,
                    &workspace_snapshots_route(&list_args.thread_id),
                    None,
                )
                .await?
            }
            WorkspaceSnapshotCommands::RestorePreview(restore_args) => {
                let request = parse_optional_json_input(
                    restore_args.request_json.as_deref(),
                    restore_args.request_file.as_ref(),
                    "workspace restore preview request",
                    "--request-json",
                    "--request-file",
                )?;
                daemon_request(
                    endpoint,
                    token,
                    Method::POST,
                    &workspace_snapshot_restore_preview_route(
                        &restore_args.thread_id,
                        &restore_args.snapshot_id,
                    ),
                    Some(workspace_restore_request_body(request)),
                )
                .await?
            }
            WorkspaceSnapshotCommands::RestoreApply(restore_args) => {
                let request = parse_optional_json_input(
                    restore_args.request_json.as_deref(),
                    restore_args.request_file.as_ref(),
                    "workspace restore apply request",
                    "--request-json",
                    "--request-file",
                )?;
                daemon_request(
                    endpoint,
                    token,
                    Method::POST,
                    &workspace_snapshot_restore_apply_route(
                        &restore_args.thread_id,
                        &restore_args.snapshot_id,
                    ),
                    Some(workspace_restore_request_body(request)),
                )
                .await?
            }
        },
    };
    print_value(&value, args.json)
}

pub(crate) fn worker_service_package_invocations_route(thread_id: &str) -> String {
    format!(
        "/v1/threads/{}/worker-service-package-invocations",
        encode_path_segment(thread_id)
    )
}

pub(crate) fn ctee_private_workspace_actions_route(thread_id: &str) -> String {
    format!(
        "/v1/threads/{}/ctee-private-workspace-actions",
        encode_path_segment(thread_id)
    )
}

pub(crate) fn governed_improvement_proposals_route(thread_id: &str) -> String {
    format!(
        "/v1/threads/{}/governed-improvement-proposals",
        encode_path_segment(thread_id)
    )
}

pub(crate) fn l1_settlement_attempts_route(thread_id: &str) -> String {
    format!(
        "/v1/threads/{}/l1-settlement-attempts",
        encode_path_segment(thread_id)
    )
}

pub(crate) fn external_capability_exits_route(thread_id: &str) -> String {
    format!(
        "/v1/threads/{}/external-capability-exits",
        encode_path_segment(thread_id)
    )
}

pub(crate) fn workspace_snapshots_route(thread_id: &str) -> String {
    format!("/v1/threads/{}/snapshots", encode_path_segment(thread_id))
}

pub(crate) fn workspace_snapshot_restore_preview_route(
    thread_id: &str,
    snapshot_id: &str,
) -> String {
    format!(
        "/v1/threads/{}/snapshots/{}/restore-preview",
        encode_path_segment(thread_id),
        encode_path_segment(snapshot_id)
    )
}

pub(crate) fn workspace_snapshot_restore_apply_route(thread_id: &str, snapshot_id: &str) -> String {
    format!(
        "/v1/threads/{}/snapshots/{}/restore-apply",
        encode_path_segment(thread_id),
        encode_path_segment(snapshot_id)
    )
}

fn worker_service_package_admission_body(invocation: Value) -> Value {
    json!({
        "source": "cli_client",
        "invocation": invocation,
    })
}

fn ctee_private_workspace_action_body(action: Value) -> Value {
    json!({
        "source": "cli_client",
        "action": action,
    })
}

fn governed_improvement_proposal_admission_body(proposal: Value) -> Value {
    json!({
        "source": "cli_client",
        "proposal": proposal,
    })
}

fn l1_settlement_admission_body(attempt: Value) -> Value {
    json!({
        "source": "cli_client",
        "attempt": attempt,
    })
}

fn external_capability_authority_body(request: Value) -> Value {
    json!({
        "source": "cli_client",
        "request": request,
    })
}

fn workspace_restore_request_body(request: Value) -> Value {
    let mut body = match request {
        Value::Object(map) => Value::Object(map),
        _ => json!({}),
    };
    if let Value::Object(map) = &mut body {
        map.insert(
            "source".to_string(),
            Value::String("cli_client".to_string()),
        );
    }
    body
}

fn parse_optional_json_input(
    inline: Option<&str>,
    file: Option<&PathBuf>,
    label: &str,
    inline_flag: &str,
    file_flag: &str,
) -> Result<Value> {
    match (inline, file) {
        (None, None) => Ok(json!({})),
        _ => parse_json_input(inline, file, label, inline_flag, file_flag),
    }
}

fn parse_json_input(
    inline: Option<&str>,
    file: Option<&PathBuf>,
    label: &str,
    inline_flag: &str,
    file_flag: &str,
) -> Result<Value> {
    match (inline, file) {
        (Some(_), Some(_)) => Err(anyhow!(
            "{label} accepts either {inline_flag} or {file_flag}, not both."
        )),
        (Some(value), None) => serde_json::from_str(value)
            .with_context(|| format!("{label} JSON argument must be a JSON object.")),
        (None, Some(path)) => {
            let text = std::fs::read_to_string(path)
                .with_context(|| format!("failed to read {label} JSON from {}", path.display()))?;
            serde_json::from_str(&text).with_context(|| {
                format!(
                    "{label} file must contain a JSON object: {}",
                    path.display()
                )
            })
        }
        (None, None) => Err(anyhow!("{label} requires {inline_flag} or {file_flag}.")),
    }
    .and_then(|value: Value| {
        if value.is_object() {
            Ok(value)
        } else {
            Err(anyhow!("{label} must be a JSON object."))
        }
    })
}

fn encode_path_segment(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                encoded.push(char::from(*byte))
            }
            _ => encoded.push_str(&format!("%{byte:02X}")),
        }
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worker_service_package_route_encodes_thread_id() {
        assert_eq!(
            worker_service_package_invocations_route("thread/with spaces"),
            "/v1/threads/thread%2Fwith%20spaces/worker-service-package-invocations"
        );
    }

    #[test]
    fn ctee_private_workspace_route_encodes_thread_id() {
        assert_eq!(
            ctee_private_workspace_actions_route("thread/with spaces"),
            "/v1/threads/thread%2Fwith%20spaces/ctee-private-workspace-actions"
        );
    }

    #[test]
    fn governed_improvement_route_encodes_thread_id() {
        assert_eq!(
            governed_improvement_proposals_route("thread/with spaces"),
            "/v1/threads/thread%2Fwith%20spaces/governed-improvement-proposals"
        );
    }

    #[test]
    fn l1_settlement_route_encodes_thread_id() {
        assert_eq!(
            l1_settlement_attempts_route("thread/with spaces"),
            "/v1/threads/thread%2Fwith%20spaces/l1-settlement-attempts"
        );
    }

    #[test]
    fn external_capability_route_encodes_thread_id() {
        assert_eq!(
            external_capability_exits_route("thread/with spaces"),
            "/v1/threads/thread%2Fwith%20spaces/external-capability-exits"
        );
    }

    #[test]
    fn workspace_snapshot_routes_encode_ids() {
        assert_eq!(
            workspace_snapshots_route("thread/with spaces"),
            "/v1/threads/thread%2Fwith%20spaces/snapshots"
        );
        assert_eq!(
            workspace_snapshot_restore_preview_route(
                "thread/with spaces",
                "workspace/snapshot one"
            ),
            "/v1/threads/thread%2Fwith%20spaces/snapshots/workspace%2Fsnapshot%20one/restore-preview"
        );
        assert_eq!(
            workspace_snapshot_restore_apply_route("thread/with spaces", "workspace/snapshot one"),
            "/v1/threads/thread%2Fwith%20spaces/snapshots/workspace%2Fsnapshot%20one/restore-apply"
        );
    }

    #[test]
    fn worker_service_package_body_is_cli_admission_only() -> Result<()> {
        let invocation = serde_json::json!({
            "schema_version": "ioi.worker_service_package_invocation.v1",
            "package_kind": "worker_package",
            "package_ref": "package://worker/cli",
            "manifest_ref": "artifact://package-manifest/cli",
            "invocation": { "invocation_id": "worker-service-package-cli" },
            "expected_heads": ["agentgres://worker-service-package/head/before"]
        });
        let body = worker_service_package_admission_body(invocation);

        assert_eq!(
            body.get("source"),
            Some(&Value::String("cli_client".to_string()))
        );
        assert!(body.get("invocation").is_some());
        assert!(body.get("invocation_admitted").is_none());
        assert!(body.get("accepted_receipt_append").is_none());
        Ok(())
    }

    #[test]
    fn ctee_private_workspace_body_is_cli_admission_only() -> Result<()> {
        let action = serde_json::json!({
            "schema_version": "ioi.ctee_private_workspace_action.v1",
            "invocation": { "invocation_id": "ctee-cli" },
            "node_trust": {
                "plaintext_allowed": false,
                "trusted_execution_profile": "ctee_private_workspace"
            },
            "expected_heads": ["agentgres://ctee/head/before"]
        });
        let body = ctee_private_workspace_action_body(action);

        assert_eq!(
            body.get("source"),
            Some(&Value::String("cli_client".to_string()))
        );
        assert!(body.get("action").is_some());
        assert!(body.get("action_executed").is_none());
        assert!(body.get("accepted_receipt_append").is_none());
        Ok(())
    }

    #[test]
    fn governed_improvement_body_is_cli_admission_only() -> Result<()> {
        let proposal = serde_json::json!({
            "schema_version": "ioi.governed_runtime_improvement.v1",
            "proposal_id": "governed-improvement-cli",
            "target_ref": "runtime://route/cli",
            "candidate_ref": "artifact://candidate/cli",
            "surface": "route",
            "source_trace_ref": "trace://cli",
            "eval_receipt_refs": ["receipt://eval/cli"],
            "verifier_receipt_refs": ["receipt://verifier/cli"],
            "approval_ref": "wallet://approval/cli",
            "rollback_ref": "artifact://rollback/cli",
            "agentgres_operation_ref": "agentgres://operations/cli",
            "expected_heads": ["agentgres://head/before"],
            "state_root_before": "sha256:before",
            "state_root_after": "sha256:after",
            "resulting_head": "agentgres://head/after"
        });
        let body = governed_improvement_proposal_admission_body(proposal);

        assert_eq!(
            body.get("source"),
            Some(&Value::String("cli_client".to_string()))
        );
        assert!(body.get("proposal").is_some());
        assert!(body.get("proposal_admitted").is_none());
        assert!(body.get("mutation_executed").is_none());
        Ok(())
    }

    #[test]
    fn l1_settlement_body_is_cli_admission_only() -> Result<()> {
        let attempt = serde_json::json!({
            "schema_version": "ioi.l1_settlement_admission.v1",
            "settlement_ref": "l1://settlement/cli",
            "trigger_refs": ["l1-trigger://operator"],
            "receipt_refs": ["receipt://local-settlement/cli"]
        });
        let body = l1_settlement_admission_body(attempt);

        assert_eq!(
            body.get("source"),
            Some(&Value::String("cli_client".to_string()))
        );
        assert!(body.get("attempt").is_some());
        assert!(body.get("settlement_admitted").is_none());
        assert!(body.get("accepted_receipt_append").is_none());
        Ok(())
    }

    #[test]
    fn external_capability_body_is_cli_authorization_only() -> Result<()> {
        let request = serde_json::json!({
            "schema_version": "ioi.external_capability_exit_authority.v1",
            "exit_ref": "exit://aiip/cli",
            "capability_ref": "capability://connector/cli",
            "target_ref": "aiip://target/cli",
            "policy_hash": "sha256:policy",
            "idempotency_key": "idem:external-capability-cli",
            "authority_grant_refs": ["wallet.network://grant/external-capability/cli"],
            "authority_receipt_refs": ["receipt://wallet.network/authority/cli"]
        });
        let body = external_capability_authority_body(request);

        assert_eq!(
            body.get("source"),
            Some(&Value::String("cli_client".to_string()))
        );
        assert!(body.get("request").is_some());
        assert!(body.get("exit_authorized").is_none());
        assert!(body.get("authority_hash").is_none());
        assert!(body.get("direct_truth_write_allowed").is_none());
        Ok(())
    }

    #[test]
    fn workspace_restore_body_is_cli_request_only() -> Result<()> {
        let request = serde_json::json!({
            "workflow_graph_id": "workflow_restore",
            "workflow_node_id": "node_restore",
            "idempotency_key": "idem:workspace-restore-cli",
            "approval_granted": true,
            "allow_conflicts": false
        });
        let body = workspace_restore_request_body(request);

        assert_eq!(
            body.get("source"),
            Some(&Value::String("cli_client".to_string()))
        );
        assert_eq!(
            body.get("workflow_graph_id"),
            Some(&Value::String("workflow_restore".to_string()))
        );
        assert!(body.get("restore_preview").is_none());
        assert!(body.get("restore_apply").is_none());
        assert!(body.get("operations").is_none());
        assert!(body.get("policy_decision_refs").is_none());
        assert!(body.get("accepted_receipt_append").is_none());
        Ok(())
    }

    #[test]
    fn optional_workspace_restore_body_defaults_to_cli_source() -> Result<()> {
        let body = workspace_restore_request_body(parse_optional_json_input(
            None,
            None,
            "workspace restore request",
            "--request-json",
            "--request-file",
        )?);

        assert_eq!(
            body.get("source"),
            Some(&Value::String("cli_client".to_string()))
        );
        assert_eq!(body.as_object().map(|map| map.len()), Some(1));
        Ok(())
    }
}
