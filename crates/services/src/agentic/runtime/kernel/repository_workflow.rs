use serde::Deserialize;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::process::Command;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

pub const REPOSITORY_WORKFLOW_PROJECTION_REQUEST_SCHEMA_VERSION: &str =
    "ioi.runtime.repository-workflow-projection-request.v1";
pub const REPOSITORY_WORKFLOW_PROJECTION_RESULT_SCHEMA_VERSION: &str =
    "ioi.runtime.repository-workflow-projection.v1";

#[derive(Debug, Clone, Deserialize, Default)]
pub struct RepositoryWorkflowProjectionBridgeRequest {
    #[serde(default)]
    pub operation: Option<String>,
    #[serde(default)]
    pub operation_kind: Option<String>,
    #[serde(default)]
    pub projection_kind: Option<String>,
    #[serde(default)]
    pub workspace_root: Option<String>,
    #[serde(default)]
    pub prompt: Option<String>,
    #[serde(default)]
    pub issue: Option<Value>,
    #[serde(default)]
    pub source: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepositoryWorkflowProjectionCommandError {
    code: &'static str,
    message: String,
}

impl RepositoryWorkflowProjectionCommandError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub fn code(&self) -> &'static str {
        self.code
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

#[derive(Debug, Clone, Default)]
pub struct RepositoryWorkflowProjectionCore;

#[derive(Debug, Clone)]
pub struct RepositoryWorkflowProjectionRecord {
    pub operation: String,
    pub operation_kind: String,
    pub projection_kind: String,
    pub workspace_root: String,
    pub source: String,
    pub projection: Value,
    pub repository_context: Value,
    pub branch_policy: Value,
    pub github_context: Value,
    pub pr_attempt: Value,
    pub issue_context: Value,
    pub review_gate: Value,
    pub github_pr_create_plan: Value,
    pub repositories: Vec<Value>,
    pub record_count: usize,
    pub evidence_refs: Vec<String>,
    pub receipt_refs: Vec<String>,
}

pub fn project_repository_workflow_response(
    request: RepositoryWorkflowProjectionBridgeRequest,
) -> Result<Value, RepositoryWorkflowProjectionCommandError> {
    let record = RepositoryWorkflowProjectionCore::default().project(request)?;
    Ok(json!({
        "source": "rust_repository_workflow_projection_command",
        "backend": "rust_policy",
        "record": record.to_value(),
    }))
}

impl RepositoryWorkflowProjectionCore {
    pub fn project(
        &self,
        request: RepositoryWorkflowProjectionBridgeRequest,
    ) -> Result<RepositoryWorkflowProjectionRecord, RepositoryWorkflowProjectionCommandError> {
        let projection_kind = normalized_projection_kind(&request)?;
        let workspace_root = absolute_path(
            optional_trimmed(request.workspace_root.as_deref()).unwrap_or_else(|| ".".to_string()),
        );
        let operation_kind = request.operation_kind.clone().unwrap_or_else(|| {
            match projection_kind.as_str() {
                "repository_list" => "repository_workflow.projection.repository_list",
                "repository_context" => "repository_workflow.projection.repository_context",
                "branch_policy" => "repository_workflow.projection.branch_policy",
                "github_context" => "repository_workflow.projection.github_context",
                "pr_attempts" => "repository_workflow.projection.pr_attempts",
                "issue_context" => "repository_workflow.projection.issue_context",
                "review_gate" => "repository_workflow.projection.review_gate",
                "github_pr_create_plan" => "repository_workflow.projection.github_pr_create_plan",
                _ => "repository_workflow.projection.unknown",
            }
            .to_string()
        });
        let operation = request
            .operation
            .clone()
            .unwrap_or_else(|| format!("repository_workflow_{projection_kind}"));
        let source = optional_trimmed(request.source.as_deref())
            .unwrap_or_else(|| "rust_repository_workflow_projection_command".to_string());
        let generated_at = now_rfc3339();
        let repository_context = repository_context_projection(&workspace_root, &generated_at);
        let branch_policy = branch_policy_projection(&repository_context, &generated_at);
        let github_context =
            github_context_projection(&repository_context, &branch_policy, &generated_at);
        let pr_attempt = pr_attempt_projection(
            &repository_context,
            &branch_policy,
            &github_context,
            request.prompt.as_deref(),
            &generated_at,
        );
        let review_gate = review_gate_projection(
            &repository_context,
            &branch_policy,
            &github_context,
            &pr_attempt,
            &generated_at,
        );
        let issue_context = issue_context_projection(
            &repository_context,
            &github_context,
            &pr_attempt,
            &review_gate,
            request.issue.as_ref(),
            &generated_at,
        );
        let github_pr_create_plan = github_pr_create_plan_projection(
            &repository_context,
            &branch_policy,
            &github_context,
            &issue_context,
            &pr_attempt,
            &review_gate,
            &generated_at,
        );
        let repositories = vec![repository_list_item(&repository_context)];
        let projection = match projection_kind.as_str() {
            "repository_list" => Value::Array(repositories.clone()),
            "repository_context" => repository_context.clone(),
            "branch_policy" => branch_policy.clone(),
            "github_context" => github_context.clone(),
            "pr_attempts" => json!([pr_attempt.clone()]),
            "issue_context" => issue_context.clone(),
            "review_gate" => review_gate.clone(),
            "github_pr_create_plan" => github_pr_create_plan.clone(),
            _ => {
                return Err(RepositoryWorkflowProjectionCommandError::new(
                    "repository_workflow_projection_kind_invalid",
                    format!("unsupported repository workflow projection kind {projection_kind}"),
                ));
            }
        };
        let record_count =
            if projection_kind == "repository_list" || projection_kind == "pr_attempts" {
                1
            } else {
                1
            };

        Ok(RepositoryWorkflowProjectionRecord {
            operation,
            operation_kind,
            projection_kind: projection_kind.clone(),
            workspace_root,
            source,
            projection,
            repository_context,
            branch_policy,
            github_context,
            pr_attempt,
            issue_context,
            review_gate,
            github_pr_create_plan,
            repositories,
            record_count,
            evidence_refs: vec![
                "runtime_repository_workflow_rust_projection".to_string(),
                "agentgres_repository_workflow_truth_required".to_string(),
            ],
            receipt_refs: vec![format!(
                "receipt_repository_workflow_projection_{projection_kind}"
            )],
        })
    }
}

impl RepositoryWorkflowProjectionRecord {
    fn to_value(&self) -> Value {
        json!({
            "schema_version": REPOSITORY_WORKFLOW_PROJECTION_RESULT_SCHEMA_VERSION,
            "object": "ioi.runtime_repository_workflow_projection",
            "status": "projected",
            "operation": self.operation,
            "operation_kind": self.operation_kind,
            "projection_kind": self.projection_kind,
            "workspace_root": self.workspace_root,
            "source": self.source,
            "projection": self.projection,
            "repository_context": self.repository_context,
            "branch_policy": self.branch_policy,
            "github_context": self.github_context,
            "pr_attempt": self.pr_attempt,
            "issue_context": self.issue_context,
            "review_gate": self.review_gate,
            "github_pr_create_plan": self.github_pr_create_plan,
            "repositories": self.repositories,
            "record_count": self.record_count,
            "evidence_refs": self.evidence_refs,
            "receipt_refs": self.receipt_refs,
        })
    }
}

fn repository_context_projection(workspace_root: &str, generated_at: &str) -> Value {
    let context_id = format!("repoctx_{}", &doctor_hash(workspace_root)[..12]);
    let root_output = git_output(workspace_root, &["rev-parse", "--show-toplevel"]);
    let base = json!({
        "schemaVersion": "ioi.agent-runtime.repository-context.v1",
        "object": "ioi.repository_context",
        "contextId": context_id,
        "generatedAt": generated_at,
        "workspaceRoot": workspace_root,
        "workspaceRootHash": doctor_hash(workspace_root),
        "provider": "git",
        "readOnly": true,
        "mutationExecuted": false,
        "evidenceRefs": ["repository_context", "repository.context.read_only", "RepositoryContextNode"],
    });
    let Some(repo_root) = root_output else {
        return merge_json(
            base,
            json!({
                "status": repository_status_projection("not_a_git_repository", Counts::default(), (0, 0), ""),
                "isGitRepository": false,
                "repoRoot": null,
                "repoRootHash": null,
                "workspaceRelativePath": null,
                "branch": null,
                "defaultBranch": null,
                "detachedHead": false,
                "headSha": null,
                "headShortSha": null,
                "upstream": null,
                "remoteCount": 0,
                "remotes": [],
                "redaction": repository_context_redaction(),
            }),
        );
    };
    let branch_name = empty_to_none(git_output(&repo_root, &["branch", "--show-current"]));
    let abbrev_ref = empty_to_none(git_output(
        &repo_root,
        &["rev-parse", "--abbrev-ref", "HEAD"],
    ));
    let detached_head = branch_name.is_none() && abbrev_ref.as_deref() == Some("HEAD");
    let head_sha = empty_to_none(git_output(&repo_root, &["rev-parse", "HEAD"]));
    let upstream = empty_to_none(git_output(
        &repo_root,
        &["rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"],
    ));
    let porcelain = git_output(
        &repo_root,
        &["status", "--porcelain=v1", "--untracked-files=normal"],
    )
    .unwrap_or_default();
    let branch_status = git_output(
        &repo_root,
        &[
            "status",
            "--porcelain=v2",
            "--branch",
            "--untracked-files=no",
        ],
    )
    .unwrap_or_default();
    let counts = repository_status_counts(&porcelain);
    let ahead_behind = repository_ahead_behind(&branch_status);
    let remotes = parse_git_remotes(&git_output(&repo_root, &["remote", "-v"]).unwrap_or_default());
    let branch = branch_name.clone().or_else(|| {
        if detached_head {
            None
        } else {
            abbrev_ref.clone()
        }
    });
    let head_short_sha = head_sha
        .as_ref()
        .map(|value| value.chars().take(12).collect::<String>());
    merge_json(
        base,
        json!({
            "status": repository_status_projection("available", counts, ahead_behind, &porcelain),
            "isGitRepository": true,
            "repoRoot": repo_root,
            "repoRootHash": doctor_hash(&repo_root),
            "workspaceRelativePath": relative_path(&repo_root, workspace_root),
            "branch": branch,
            "defaultBranch": repository_default_branch(&repo_root),
            "detachedHead": detached_head,
            "headSha": head_sha,
            "headShortSha": head_short_sha,
            "upstream": upstream,
            "remoteCount": remotes.len(),
            "remotes": remotes,
            "redaction": repository_context_redaction(),
        }),
    )
}

fn repository_list_item(repository_context: &Value) -> Value {
    json!({
        "url": repository_context["workspaceRoot"].clone(),
        "source": if bool_field(repository_context, "isGitRepository") { "local_git" } else { "local_workspace" },
        "status": if bool_field(repository_context, "isGitRepository") { "available" } else { "not_a_git_repository" },
        "contextId": repository_context["contextId"].clone(),
        "repoRoot": repository_context["repoRoot"].clone(),
        "branch": repository_context["branch"].clone(),
        "headSha": repository_context["headSha"].clone(),
        "upstream": repository_context["upstream"].clone(),
        "remoteCount": repository_context["remoteCount"].clone(),
        "remotes": repository_context["remotes"].clone(),
        "isDirty": repository_context["status"]["isDirty"].clone(),
        "dirtyCounts": repository_context["status"]["counts"].clone(),
        "redaction": repository_context["redaction"].clone(),
    })
}

fn branch_policy_projection(repository_context: &Value, generated_at: &str) -> Value {
    let context_id = string_field(repository_context, "contextId");
    let policy_id = format!(
        "branch_policy_{}",
        &doctor_hash(context_id.as_deref().unwrap_or("workspace"))[..12]
    );
    let branch = string_field(repository_context, "branch");
    let default_branch = string_field(repository_context, "defaultBranch");
    let protected_branch_names = unique_strings(
        [
            default_branch.clone(),
            Some("main".to_string()),
            Some("master".to_string()),
            Some("trunk".to_string()),
            Some("production".to_string()),
            Some("release".to_string()),
            Some("stable".to_string()),
        ]
        .into_iter()
        .flatten()
        .collect(),
    );
    let protected_branch = branch
        .as_ref()
        .map(|value| protected_branch_names.contains(value))
        .unwrap_or(false);
    let counts = repository_context["status"]["counts"].clone();
    let mut blockers = vec![];
    let mut warnings = vec![];
    if !bool_field(repository_context, "isGitRepository") {
        blockers.push("not_a_git_repository".to_string());
    }
    if string_field(repository_context, "headSha").is_none()
        && bool_field(repository_context, "isGitRepository")
    {
        blockers.push("missing_head".to_string());
    }
    if bool_field(repository_context, "detachedHead") || branch.is_none() {
        blockers.push("detached_head".to_string());
    }
    if number_field(&counts, "conflicted") > 0 {
        blockers.push("conflicted_worktree".to_string());
    }
    if protected_branch {
        blockers.push("protected_branch".to_string());
    }
    if bool_field(&repository_context["status"], "isDirty") {
        warnings.push("dirty_worktree".to_string());
    }
    if number_field(&counts, "untracked") > 0 {
        warnings.push("untracked_files".to_string());
    }
    if string_field(repository_context, "upstream").is_none()
        && bool_field(repository_context, "isGitRepository")
    {
        warnings.push("missing_upstream".to_string());
    }
    if number_field(&repository_context["status"], "ahead") > 0 {
        warnings.push("ahead_of_upstream".to_string());
    }
    if number_field(&repository_context["status"], "behind") > 0 {
        warnings.push("behind_upstream".to_string());
    }
    let blockers = unique_strings(blockers);
    let warnings = unique_strings(warnings);
    let status = if !blockers.is_empty() {
        "blocked"
    } else if !warnings.is_empty() {
        "warning"
    } else {
        "passed"
    };
    let mutation_allowed = status == "passed";
    let evidence_refs = evidence_refs(vec![
        json!("branch_policy"),
        json!("repository.branch_policy.read_only"),
        json!("BranchPolicyNode"),
        optional_value(context_id.clone()),
    ]);
    json!({
        "schemaVersion": "ioi.agent-runtime.branch-policy.v1",
        "object": "ioi.branch_policy_decision",
        "policyId": policy_id,
        "generatedAt": generated_at,
        "repositoryContextId": context_id,
        "status": status,
        "decision": status,
        "summary": branch_policy_summary(status, branch.as_deref(), protected_branch, &blockers, &warnings),
        "readOnly": true,
        "mutationExecuted": false,
        "mutationAllowed": mutation_allowed,
        "prCreationAllowed": mutation_allowed,
        "reviewRequired": !warnings.is_empty() || !blockers.is_empty(),
        "approvalRequired": !warnings.is_empty() || !blockers.is_empty(),
        "branch": branch,
        "defaultBranch": default_branch,
        "protectedBranch": protected_branch,
        "protectedBranchNames": protected_branch_names,
        "detachedHead": bool_field(repository_context, "detachedHead"),
        "headSha": repository_context["headSha"].clone(),
        "headShortSha": repository_context["headShortSha"].clone(),
        "upstream": repository_context["upstream"].clone(),
        "ahead": repository_context["status"]["ahead"].clone(),
        "behind": repository_context["status"]["behind"].clone(),
        "dirty": repository_context["status"]["isDirty"].clone(),
        "counts": counts,
        "blockers": blockers,
        "warnings": warnings,
        "recommendedNextAction": branch_policy_recommended_next_action(status, &blockers, &warnings),
        "redaction": {
            "profile": "branch_policy_safe",
            "remoteCredentialsIncluded": false,
            "statusPathsIncluded": false,
        },
        "evidenceRefs": evidence_refs,
    })
}

fn github_context_projection(
    repository_context: &Value,
    branch_policy: &Value,
    generated_at: &str,
) -> Value {
    let context_id = format!(
        "github_context_{}",
        &doctor_hash(
            string_field(repository_context, "contextId")
                .as_deref()
                .unwrap_or("workspace")
        )[..12]
    );
    let github_remotes: Vec<Value> = repository_context["remotes"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter(|remote| string_field(remote, "provider").as_deref() == Some("github"))
        .collect();
    let default_remote = github_remotes
        .iter()
        .find(|remote| string_field(remote, "name").as_deref() == Some("origin"))
        .or_else(|| github_remotes.first());
    let owner = default_remote.and_then(|remote| string_field(remote, "owner"));
    let repo = default_remote.and_then(|remote| string_field(remote, "repo"));
    let repo_full_name = match (owner.as_ref(), repo.as_ref()) {
        (Some(owner), Some(repo)) => Some(format!("{owner}/{repo}")),
        _ => None,
    };
    let token_sources = github_token_sources();
    let github_remote_present = default_remote.is_some() && repo_full_name.is_some();
    let branch_policy_allows_pr = bool_field(branch_policy, "prCreationAllowed");
    let pr_creation_eligible =
        github_remote_present && branch_policy_allows_pr && !token_sources.is_empty();
    let policy_status = string_field(branch_policy, "status");
    let status = if !github_remote_present {
        "unavailable"
    } else if policy_status.as_deref() == Some("blocked") {
        "blocked"
    } else if policy_status.as_deref() == Some("warning") {
        "warning"
    } else {
        "available"
    };
    let remote_projections: Vec<Value> = github_remotes
        .iter()
        .map(|remote| {
            json!({
                "name": remote["name"].clone(),
                "host": remote["host"].clone(),
                "owner": remote["owner"].clone(),
                "repo": remote["repo"].clone(),
                "repoFullName": remote["repoFullName"].clone(),
                "fetchUrl": remote["fetchUrl"].clone(),
                "fetchUrlHash": remote["fetchUrlHash"].clone(),
                "pushUrl": remote["pushUrl"].clone(),
                "pushUrlHash": remote["pushUrlHash"].clone(),
            })
        })
        .collect();
    let evidence_refs = evidence_refs(vec![
        json!("github_context"),
        json!("github.context.read_only"),
        json!("GitHubContextNode"),
        repository_context["contextId"].clone(),
        branch_policy["policyId"].clone(),
    ]);
    json!({
        "schemaVersion": "ioi.agent-runtime.github-context.v1",
        "object": "ioi.github_context",
        "contextId": context_id,
        "generatedAt": generated_at,
        "repositoryContextId": repository_context["contextId"].clone(),
        "branchPolicyId": branch_policy["policyId"].clone(),
        "status": status,
        "summary": github_context_summary(status, repo_full_name.as_deref(), branch_policy),
        "readOnly": true,
        "networkLookupPerformed": false,
        "mutationExecuted": false,
        "provider": "github",
        "githubRemotePresent": github_remote_present,
        "defaultRemoteName": default_remote.map(|remote| remote["name"].clone()).unwrap_or(Value::Null),
        "owner": owner,
        "repo": repo,
        "repoFullName": repo_full_name.as_ref(),
        "htmlUrl": repo_full_name.as_ref().map(|name| format!("https://github.com/{name}")),
        "defaultBranch": repository_context["defaultBranch"].clone(),
        "branch": repository_context["branch"].clone(),
        "branchPolicyStatus": branch_policy["status"].clone(),
        "branchPolicyBlockers": branch_policy["blockers"].clone(),
        "branchPolicyWarnings": branch_policy["warnings"].clone(),
        "prCreationEligible": pr_creation_eligible,
        "prCreationPreconditions": {
            "githubRemotePresent": github_remote_present,
            "branchPolicyAllowsPr": branch_policy_allows_pr,
            "tokenAvailable": !token_sources.is_empty(),
            "networkLookupPerformed": false,
            "mutationExecuted": false,
        },
        "remotes": remote_projections,
        "credentials": {
            "tokenAvailable": !token_sources.is_empty(),
            "tokenSources": token_sources,
            "tokenValueIncluded": false,
            "authorizationHeaderIncluded": false,
        },
        "redaction": {
            "profile": "github_context_safe",
            "tokenValueIncluded": false,
            "remoteCredentialsIncluded": false,
            "networkResponseIncluded": false,
        },
        "evidenceRefs": evidence_refs,
    })
}

fn issue_context_projection(
    repository_context: &Value,
    github_context: &Value,
    pr_attempt: &Value,
    review_gate: &Value,
    issue: Option<&Value>,
    generated_at: &str,
) -> Value {
    let issue_number = issue
        .and_then(|value| value.get("number").or_else(|| value.get("issueNumber")))
        .and_then(|value| value.as_i64())
        .filter(|value| *value > 0);
    let title = issue
        .and_then(|value| value.get("title"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    let source_url = issue
        .and_then(|value| value.get("url").or_else(|| value.get("sourceUrl")))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    let bound = issue_number.is_some() || title.is_some() || source_url.is_some();
    let github_remote_present = bool_field(github_context, "githubRemotePresent");
    let status = if !github_remote_present {
        "unavailable"
    } else if bound {
        "bound"
    } else {
        "unbound"
    };
    let mut warnings = vec![];
    if !bound {
        warnings.push("issue_context_unbound".to_string());
    }
    if !github_remote_present {
        warnings.push("missing_github_remote".to_string());
    }
    let repo_full_name = string_field(github_context, "repoFullName");
    let labels = issue
        .and_then(|value| value.get("labels"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let evidence_refs = evidence_refs(vec![
        json!("issue_context"),
        json!("IssueContextNode"),
        json!("github.issue_context.read_only"),
        repository_context["contextId"].clone(),
        github_context["contextId"].clone(),
        pr_attempt["attemptId"].clone(),
        review_gate["gateId"].clone(),
    ]);
    json!({
        "schemaVersion": "ioi.agent-runtime.issue-context.v1",
        "object": "ioi.issue_context",
        "contextId": format!("issue_context_{}", &doctor_hash(string_field(github_context, "contextId").as_deref().unwrap_or("workspace"))[..12]),
        "runId": null,
        "generatedAt": generated_at,
        "repositoryContextId": repository_context["contextId"].clone(),
        "githubContextId": github_context["contextId"].clone(),
        "prAttemptId": pr_attempt["attemptId"].clone(),
        "reviewGateId": review_gate["gateId"].clone(),
        "status": status,
        "summary": issue_context_summary(status, repo_full_name.as_deref(), issue_number, title.as_deref()),
        "readOnly": true,
        "provider": "github",
        "repoFullName": repo_full_name,
        "htmlUrl": github_context["htmlUrl"].clone(),
        "bound": bound,
        "issueProvided": bound,
        "issueNumber": issue_number,
        "title": title,
        "sourceUrl": source_url,
        "sourceKind": if bound { "github_issue" } else { "unbound" },
        "labels": labels,
        "assignees": [],
        "blockers": [],
        "warnings": unique_strings(warnings),
        "noIssuePolicy": {
            "allowed": true,
            "reason": "Issue context is optional for local PR previews until a task source is supplied.",
        },
        "networkLookupPerformed": false,
        "mutationExecuted": false,
        "redaction": {
            "profile": "issue_context_safe",
            "tokenValueIncluded": false,
            "remoteCredentialsIncluded": false,
            "networkResponseIncluded": false,
            "bodyIncluded": false,
            "reviewerIdentityIncluded": false,
        },
        "evidenceRefs": evidence_refs,
    })
}

fn pr_attempt_projection(
    repository_context: &Value,
    branch_policy: &Value,
    github_context: &Value,
    prompt: Option<&str>,
    generated_at: &str,
) -> Value {
    let diff_artifact = pr_diff_artifact(repository_context);
    let branch_artifact = pr_branch_artifact(repository_context, branch_policy, github_context);
    let mut blockers = vec![];
    blockers.extend(string_array(branch_policy["blockers"].clone()));
    if !bool_field(repository_context, "isGitRepository") {
        blockers.push("not_git_repository".to_string());
    }
    if !bool_field(github_context, "githubRemotePresent") {
        blockers.push("missing_github_remote".to_string());
    }
    if !bool_field(&github_context["prCreationPreconditions"], "tokenAvailable") {
        blockers.push("missing_github_token".to_string());
    }
    if !bool_field(
        &github_context["prCreationPreconditions"],
        "branchPolicyAllowsPr",
    ) {
        blockers.push("branch_policy_not_passed".to_string());
    }
    blockers.push("missing_authority_scope:github.pr.create".to_string());
    let blockers = unique_strings(blockers);
    let mut warnings = string_array(branch_policy["warnings"].clone());
    warnings.extend(string_array(github_context["branchPolicyWarnings"].clone()));
    warnings.push("pr_attempt_preview_only".to_string());
    let warnings = unique_strings(warnings);
    let status = if blockers.is_empty() {
        "ready"
    } else {
        "blocked"
    };
    let outcome = if blockers.is_empty() {
        "preview_ready"
    } else {
        "failed_precondition"
    };
    let repo_full_name = string_field(github_context, "repoFullName");
    let attempt_id = format!(
        "pr_attempt_{}",
        &doctor_hash(
            string_field(repository_context, "contextId")
                .as_deref()
                .unwrap_or("workspace")
        )[..12]
    );
    let title = prompt.map(|value| {
        format!(
            "Draft PR for: {}",
            value.chars().take(96).collect::<String>()
        )
    });
    let failure = if status == "blocked" {
        json!({
            "reason": blockers.first().cloned(),
            "message": "PR creation was not attempted because preview preconditions or authority requirements were not satisfied.",
        })
    } else {
        Value::Null
    };
    let branch_artifact_metadata = artifact_metadata(&branch_artifact);
    let diff_artifact_metadata = artifact_metadata(&diff_artifact);
    let evidence_refs = evidence_refs(vec![
        json!("pr_attempt"),
        json!("pr_attempt_preview_only"),
        json!("PrAttemptNode"),
        repository_context["contextId"].clone(),
        branch_policy["policyId"].clone(),
        github_context["contextId"].clone(),
        branch_artifact["artifactName"].clone(),
        diff_artifact["artifactName"].clone(),
    ]);
    let preconditions = json!({
        "gitRepositoryPresent": bool_field(repository_context, "isGitRepository"),
        "githubRemotePresent": bool_field(github_context, "githubRemotePresent"),
        "branchPolicyAllowsPr": bool_field(&github_context["prCreationPreconditions"], "branchPolicyAllowsPr"),
        "tokenAvailable": bool_field(&github_context["prCreationPreconditions"], "tokenAvailable"),
        "authorityScopeGranted": false,
        "diffCaptured": true,
        "branchArtifactAttached": true,
        "diffArtifactAttached": true,
        "networkLookupPerformed": false,
        "mutationExecuted": false,
    });
    let artifacts = json!([
        {"name": "pr-attempt.json", "mediaType": "application/json"},
        branch_artifact_metadata.clone(),
        diff_artifact_metadata.clone(),
    ]);
    let redaction = json!({
        "profile": "pr_attempt_safe",
        "tokenValueIncluded": false,
        "remoteCredentialsIncluded": false,
        "networkResponseIncluded": false,
        "diffContentInProjection": false,
    });
    let mut record = Map::new();
    record.insert(
        "schemaVersion".to_string(),
        json!("ioi.agent-runtime.pr-attempt.v1"),
    );
    record.insert("object".to_string(), json!("ioi.pr_attempt"));
    record.insert("attemptId".to_string(), json!(attempt_id));
    record.insert("runId".to_string(), Value::Null);
    record.insert("generatedAt".to_string(), json!(generated_at));
    record.insert(
        "repositoryContextId".to_string(),
        repository_context["contextId"].clone(),
    );
    record.insert(
        "branchPolicyId".to_string(),
        branch_policy["policyId"].clone(),
    );
    record.insert(
        "githubContextId".to_string(),
        github_context["contextId"].clone(),
    );
    record.insert("status".to_string(), json!(status));
    record.insert("outcome".to_string(), json!(outcome));
    record.insert(
        "summary".to_string(),
        json!(pr_attempt_summary(
            status,
            outcome,
            repo_full_name.as_deref(),
            &blockers
        )),
    );
    record.insert("previewOnly".to_string(), json!(true));
    record.insert("readOnly".to_string(), json!(true));
    record.insert("provider".to_string(), json!("github"));
    record.insert("action".to_string(), json!("pr_create"));
    record.insert("title".to_string(), json!(title));
    record.insert("bodyIncluded".to_string(), json!(false));
    record.insert("repoFullName".to_string(), json!(repo_full_name));
    record.insert("htmlUrl".to_string(), github_context["htmlUrl"].clone());
    record.insert("branch".to_string(), repository_context["branch"].clone());
    record.insert(
        "defaultBranch".to_string(),
        repository_context["defaultBranch"].clone(),
    );
    record.insert("headSha".to_string(), repository_context["headSha"].clone());
    record.insert(
        "headShortSha".to_string(),
        repository_context["headShortSha"].clone(),
    );
    record.insert(
        "upstream".to_string(),
        repository_context["upstream"].clone(),
    );
    record.insert(
        "dirty".to_string(),
        repository_context["status"]["isDirty"].clone(),
    );
    record.insert(
        "counts".to_string(),
        repository_context["status"]["counts"].clone(),
    );
    record.insert("blockers".to_string(), json!(blockers));
    record.insert("warnings".to_string(), json!(warnings));
    record.insert("failure".to_string(), failure);
    record.insert("authority".to_string(), repository_authority());
    record.insert("preconditions".to_string(), preconditions);
    record.insert("mutationAttempted".to_string(), json!(false));
    record.insert("mutationExecuted".to_string(), json!(false));
    record.insert("networkLookupPerformed".to_string(), json!(false));
    record.insert("prNumber".to_string(), Value::Null);
    record.insert("prUrl".to_string(), Value::Null);
    record.insert("branchArtifact".to_string(), branch_artifact_metadata);
    record.insert("diffArtifact".to_string(), diff_artifact_metadata);
    record.insert("artifacts".to_string(), artifacts);
    record.insert("redaction".to_string(), redaction);
    record.insert("evidenceRefs".to_string(), json!(evidence_refs));
    Value::Object(record)
}

fn review_gate_projection(
    repository_context: &Value,
    branch_policy: &Value,
    github_context: &Value,
    pr_attempt: &Value,
    generated_at: &str,
) -> Value {
    let pr_attempt_ready = string_field(pr_attempt, "status").as_deref() == Some("ready");
    let review_satisfied = false;
    let mut blockers = string_array(pr_attempt["blockers"].clone());
    if string_field(branch_policy, "status").as_deref() != Some("passed") {
        blockers.push("branch_policy_not_passed".to_string());
    }
    if string_field(github_context, "status").as_deref() != Some("available") {
        blockers.push("github_context_not_available".to_string());
    }
    if !pr_attempt_ready {
        blockers.push("pr_attempt_not_ready".to_string());
    }
    if !review_satisfied {
        blockers.push("review_not_satisfied".to_string());
    }
    let blockers = unique_strings(blockers);
    let mut warnings = string_array(branch_policy["warnings"].clone());
    warnings.extend(string_array(pr_attempt["warnings"].clone()));
    warnings.push("review_gate_preview_only".to_string());
    let warnings = unique_strings(warnings);
    let status = if blockers.is_empty() {
        "passed"
    } else {
        "blocked"
    };
    let repo_full_name = string_field(github_context, "repoFullName");
    let gate_id = format!(
        "review_gate_{}",
        &doctor_hash(
            string_field(pr_attempt, "attemptId")
                .as_deref()
                .unwrap_or("workspace")
        )[..12]
    );
    let evidence_refs = evidence_refs(vec![
        json!("review_gate"),
        json!("review_gate_preview_only"),
        json!("ReviewGateNode"),
        repository_context["contextId"].clone(),
        branch_policy["policyId"].clone(),
        github_context["contextId"].clone(),
        pr_attempt["attemptId"].clone(),
    ]);
    let required_checks = json!([
        "branch_policy_passed",
        "github_context_available",
        "pr_attempt_ready",
        "diff_artifact_attached",
        "human_review_satisfied",
    ]);
    let preconditions = json!({
        "repositoryContextPresent": !repository_context["contextId"].is_null(),
        "branchPolicyPassed": string_field(branch_policy, "status").as_deref() == Some("passed"),
        "githubContextAvailable": string_field(github_context, "status").as_deref() == Some("available"),
        "prAttemptPresent": !pr_attempt["attemptId"].is_null(),
        "prAttemptReady": pr_attempt_ready,
        "diffArtifactAttached": !pr_attempt["diffArtifact"]["artifactName"].is_null(),
        "branchArtifactAttached": !pr_attempt["branchArtifact"]["artifactName"].is_null(),
        "reviewPolicySatisfied": review_satisfied,
        "networkLookupPerformed": false,
        "mutationExecuted": false,
    });
    let redaction = json!({
        "profile": "review_gate_safe",
        "reviewerIdentityIncluded": false,
        "tokenValueIncluded": false,
        "networkResponseIncluded": false,
    });
    let mut record = Map::new();
    record.insert(
        "schemaVersion".to_string(),
        json!("ioi.agent-runtime.review-gate.v1"),
    );
    record.insert("object".to_string(), json!("ioi.review_gate_decision"));
    record.insert("gateId".to_string(), json!(gate_id));
    record.insert("runId".to_string(), Value::Null);
    record.insert("generatedAt".to_string(), json!(generated_at));
    record.insert(
        "repositoryContextId".to_string(),
        repository_context["contextId"].clone(),
    );
    record.insert(
        "branchPolicyId".to_string(),
        branch_policy["policyId"].clone(),
    );
    record.insert(
        "githubContextId".to_string(),
        github_context["contextId"].clone(),
    );
    record.insert("prAttemptId".to_string(), pr_attempt["attemptId"].clone());
    record.insert("status".to_string(), json!(status));
    record.insert("decision".to_string(), json!(status));
    record.insert(
        "summary".to_string(),
        json!(review_gate_summary(
            status,
            repo_full_name.as_deref(),
            &blockers
        )),
    );
    record.insert("readOnly".to_string(), json!(true));
    record.insert("previewOnly".to_string(), json!(true));
    record.insert("reviewRequired".to_string(), json!(true));
    record.insert("approvalRequired".to_string(), json!(true));
    record.insert("reviewSatisfied".to_string(), json!(review_satisfied));
    record.insert("approvalSatisfied".to_string(), json!(false));
    record.insert("mutationAllowed".to_string(), json!(false));
    record.insert("prCreationAllowed".to_string(), json!(false));
    record.insert("mutationExecuted".to_string(), json!(false));
    record.insert("networkLookupPerformed".to_string(), json!(false));
    record.insert("provider".to_string(), json!("github"));
    record.insert("repoFullName".to_string(), json!(repo_full_name));
    record.insert("branch".to_string(), repository_context["branch"].clone());
    record.insert(
        "defaultBranch".to_string(),
        repository_context["defaultBranch"].clone(),
    );
    record.insert("prAttemptStatus".to_string(), pr_attempt["status"].clone());
    record.insert(
        "prAttemptOutcome".to_string(),
        pr_attempt["outcome"].clone(),
    );
    record.insert("requiredReviewers".to_string(), json!(["code-owner"]));
    record.insert("satisfiedReviewers".to_string(), json!([]));
    record.insert("requiredChecks".to_string(), required_checks);
    record.insert("passedChecks".to_string(), json!([]));
    record.insert("blockers".to_string(), json!(blockers));
    record.insert("warnings".to_string(), json!(warnings));
    record.insert("authority".to_string(), repository_authority());
    record.insert("preconditions".to_string(), preconditions);
    record.insert("redaction".to_string(), redaction);
    record.insert("evidenceRefs".to_string(), json!(evidence_refs));
    Value::Object(record)
}

fn github_pr_create_plan_projection(
    repository_context: &Value,
    branch_policy: &Value,
    github_context: &Value,
    issue_context: &Value,
    pr_attempt: &Value,
    review_gate: &Value,
    generated_at: &str,
) -> Value {
    let title = string_field(pr_attempt, "title").unwrap_or_else(|| {
        format!(
            "Draft PR for {}",
            string_field(repository_context, "branch")
                .unwrap_or_else(|| "working branch".to_string())
        )
    });
    let payload_preview = json!({
        "owner": github_context["owner"].clone(),
        "repo": github_context["repo"].clone(),
        "base": repository_context["defaultBranch"].clone(),
        "head": repository_context["branch"].clone(),
        "title": title,
        "bodyIncluded": false,
        "draft": true,
        "maintainerCanModify": true,
        "issueNumber": issue_context["issueNumber"].clone(),
    });
    let mut blockers = string_array(review_gate["blockers"].clone());
    blockers.extend(string_array(pr_attempt["blockers"].clone()));
    if string_field(github_context, "status").as_deref() != Some("available") {
        blockers.push("github_context_not_available".to_string());
    }
    if string_field(branch_policy, "status").as_deref() != Some("passed") {
        blockers.push("branch_policy_not_passed".to_string());
    }
    if string_field(pr_attempt, "status").as_deref() != Some("ready") {
        blockers.push("pr_attempt_not_ready".to_string());
    }
    if string_field(review_gate, "status").as_deref() != Some("passed") {
        blockers.push("review_gate_not_passed".to_string());
    }
    if !bool_field(review_gate, "reviewSatisfied") {
        blockers.push("review_not_satisfied".to_string());
    }
    if !bool_field(&github_context["credentials"], "tokenAvailable") {
        blockers.push("missing_github_token".to_string());
    }
    blockers.push("missing_authority_scope:github.pr.create".to_string());
    blockers.push("dry_run_only".to_string());
    let blockers = unique_strings(blockers);
    let mut warnings = string_array(issue_context["warnings"].clone());
    warnings.extend(string_array(review_gate["warnings"].clone()));
    warnings.push("github_pr_create_plan_dry_run".to_string());
    let warnings = unique_strings(warnings);
    let status = if blockers.is_empty() {
        "ready"
    } else {
        "blocked"
    };
    let repo_full_name = string_field(github_context, "repoFullName");
    let request_path = repo_full_name
        .as_ref()
        .map(|name| format!("/repos/{name}/pulls"));
    let body_plan_source = if bool_field(issue_context, "bound") {
        "issue_context"
    } else {
        "runtime_template"
    };
    let evidence_refs = evidence_refs(vec![
        json!("github_pr_create_plan"),
        json!("github.pr_create.request_hash"),
        json!("github.pr_create.authority_scope"),
        json!("github.pr_create.dry_run"),
        json!("GitHubPrCreateNode"),
        repository_context["contextId"].clone(),
        branch_policy["policyId"].clone(),
        github_context["contextId"].clone(),
        issue_context["contextId"].clone(),
        pr_attempt["attemptId"].clone(),
        review_gate["gateId"].clone(),
    ]);
    let body_plan = json!({
        "included": false,
        "source": body_plan_source,
        "redaction": "body_not_included_in_projection",
    });
    let request = json!({
        "method": "POST",
        "path": request_path,
        "payloadHash": doctor_hash(&payload_preview.to_string()),
        "payloadPreview": payload_preview,
        "bodyIncluded": false,
        "tokenIncluded": false,
    });
    let redaction = json!({
        "profile": "github_pr_create_plan_safe",
        "tokenValueIncluded": false,
        "authorizationHeaderIncluded": false,
        "requestBodyIncluded": false,
        "responseBodyIncluded": false,
        "networkResponseIncluded": false,
    });
    let mut record = Map::new();
    record.insert(
        "schemaVersion".to_string(),
        json!("ioi.agent-runtime.github-pr-create-plan.v1"),
    );
    record.insert("object".to_string(), json!("ioi.github_pr_create_plan"));
    record.insert(
        "planId".to_string(),
        json!(format!(
            "github_pr_create_plan_{}",
            &doctor_hash(
                string_field(review_gate, "gateId")
                    .as_deref()
                    .unwrap_or("workspace")
            )[..12]
        )),
    );
    record.insert("runId".to_string(), Value::Null);
    record.insert("generatedAt".to_string(), json!(generated_at));
    record.insert(
        "repositoryContextId".to_string(),
        repository_context["contextId"].clone(),
    );
    record.insert(
        "branchPolicyId".to_string(),
        branch_policy["policyId"].clone(),
    );
    record.insert(
        "githubContextId".to_string(),
        github_context["contextId"].clone(),
    );
    record.insert(
        "issueContextId".to_string(),
        issue_context["contextId"].clone(),
    );
    record.insert("prAttemptId".to_string(), pr_attempt["attemptId"].clone());
    record.insert("reviewGateId".to_string(), review_gate["gateId"].clone());
    record.insert("status".to_string(), json!(status));
    record.insert("decision".to_string(), json!(status));
    record.insert(
        "summary".to_string(),
        json!(github_pr_create_plan_summary(
            status,
            repo_full_name.as_deref(),
            &blockers
        )),
    );
    record.insert("dryRun".to_string(), json!(true));
    record.insert("previewOnly".to_string(), json!(true));
    record.insert("provider".to_string(), json!("github"));
    record.insert("toolName".to_string(), json!("github__pr_create"));
    record.insert("action".to_string(), json!("pr_create"));
    record.insert("repoFullName".to_string(), json!(repo_full_name));
    record.insert("owner".to_string(), github_context["owner"].clone());
    record.insert("repo".to_string(), github_context["repo"].clone());
    record.insert(
        "baseBranch".to_string(),
        repository_context["defaultBranch"].clone(),
    );
    record.insert(
        "headBranch".to_string(),
        repository_context["branch"].clone(),
    );
    record.insert("title".to_string(), json!(title));
    record.insert("bodyPlan".to_string(), body_plan);
    record.insert(
        "issueNumber".to_string(),
        issue_context["issueNumber"].clone(),
    );
    record.insert(
        "reviewGateStatus".to_string(),
        review_gate["status"].clone(),
    );
    record.insert(
        "reviewSatisfied".to_string(),
        review_gate["reviewSatisfied"].clone(),
    );
    record.insert("authority".to_string(), repository_authority());
    record.insert("request".to_string(), request);
    record.insert("blockers".to_string(), json!(blockers));
    record.insert("warnings".to_string(), json!(warnings));
    record.insert("networkLookupPerformed".to_string(), json!(false));
    record.insert("mutationAttempted".to_string(), json!(false));
    record.insert("mutationExecuted".to_string(), json!(false));
    record.insert("prNumber".to_string(), Value::Null);
    record.insert("prUrl".to_string(), Value::Null);
    record.insert("redaction".to_string(), redaction);
    record.insert("evidenceRefs".to_string(), json!(evidence_refs));
    Value::Object(record)
}

fn pr_branch_artifact(
    repository_context: &Value,
    branch_policy: &Value,
    github_context: &Value,
) -> Value {
    let content = json!({
        "schemaVersion": "ioi.agent-runtime.pr-branch-artifact.v1",
        "object": "ioi.pr_branch_artifact",
        "repositoryContextId": repository_context["contextId"].clone(),
        "branchPolicyId": branch_policy["policyId"].clone(),
        "githubContextId": github_context["contextId"].clone(),
        "repoFullName": github_context["repoFullName"].clone(),
        "branch": repository_context["branch"].clone(),
        "defaultBranch": repository_context["defaultBranch"].clone(),
        "headSha": repository_context["headSha"].clone(),
        "headShortSha": repository_context["headShortSha"].clone(),
        "upstream": repository_context["upstream"].clone(),
        "dirty": repository_context["status"]["isDirty"].clone(),
        "counts": repository_context["status"]["counts"].clone(),
        "branchPolicyStatus": branch_policy["status"].clone(),
        "redaction": {
            "profile": "pr_branch_artifact_safe",
            "statusPathsIncluded": false,
            "remoteCredentialsIncluded": false,
        },
    });
    json!({
        "artifactName": "pr-branch.json",
        "mediaType": "application/json",
        "artifactHash": doctor_hash(&content.to_string()),
        "content": content,
    })
}

fn pr_diff_artifact(repository_context: &Value) -> Value {
    let raw_patch = if bool_field(repository_context, "isGitRepository") {
        string_field(repository_context, "repoRoot")
            .and_then(|repo_root| {
                git_output(
                    &repo_root,
                    &["diff", "--no-ext-diff", "--binary", "HEAD", "--"],
                )
            })
            .unwrap_or_default()
    } else {
        String::new()
    };
    let raw_bytes = raw_patch.len();
    let max_bytes = 512 * 1024;
    let truncated = raw_bytes > max_bytes;
    let retained = if truncated {
        format!(
            "{}\n\n[ioi pr diff truncated: {} byte(s) omitted]\n",
            raw_patch.chars().take(max_bytes).collect::<String>(),
            raw_bytes - max_bytes
        )
    } else {
        raw_patch.clone()
    };
    json!({
        "artifactName": "pr-diff.patch",
        "mediaType": "text/x-diff",
        "artifactHash": doctor_hash(&raw_patch),
        "diffHash": doctor_hash(&raw_patch),
        "byteLength": raw_bytes,
        "retainedByteLength": retained.len(),
        "truncated": truncated,
        "fileCount": raw_patch.lines().filter(|line| line.starts_with("diff --git ")).count(),
        "hasDiff": !raw_patch.is_empty(),
        "untrackedCount": repository_context["status"]["counts"]["untracked"].clone(),
        "content": retained,
    })
}

fn artifact_metadata(artifact: &Value) -> Value {
    let mut metadata = artifact.as_object().cloned().unwrap_or_default();
    metadata.remove("content");
    Value::Object(metadata)
}

fn repository_authority() -> Value {
    json!({
        "requiredScopes": ["github.pr.create"],
        "grantedScopes": [],
        "missingScopes": ["github.pr.create"],
        "scopeGranted": false,
        "approvalRequired": true,
        "approvalSatisfied": false,
    })
}

#[derive(Debug, Clone, Copy, Default)]
struct Counts {
    staged: usize,
    unstaged: usize,
    untracked: usize,
    ignored: usize,
    conflicted: usize,
}

fn repository_status_counts(porcelain: &str) -> Counts {
    let mut counts = Counts::default();
    for line in porcelain.lines().filter(|line| !line.is_empty()) {
        let status = line.chars().take(2).collect::<String>();
        let mut chars = status.chars();
        let x = chars.next().unwrap_or(' ');
        let y = chars.next().unwrap_or(' ');
        if status == "??" {
            counts.untracked += 1;
            continue;
        }
        if status == "!!" {
            counts.ignored += 1;
            continue;
        }
        if repository_status_is_conflict(&status) {
            counts.conflicted += 1;
        }
        if !matches!(x, ' ' | '?' | '!') {
            counts.staged += 1;
        }
        if !matches!(y, ' ' | '?' | '!') {
            counts.unstaged += 1;
        }
    }
    counts
}

fn repository_status_projection(
    availability: &str,
    counts: Counts,
    ahead_behind: (usize, usize),
    porcelain: &str,
) -> Value {
    let is_dirty =
        counts.staged > 0 || counts.unstaged > 0 || counts.untracked > 0 || counts.conflicted > 0;
    json!({
        "availability": availability,
        "clean": if availability == "available" { json!(!is_dirty) } else { Value::Null },
        "isDirty": is_dirty,
        "counts": {
            "staged": counts.staged,
            "unstaged": counts.unstaged,
            "untracked": counts.untracked,
            "ignored": counts.ignored,
            "conflicted": counts.conflicted,
        },
        "ahead": ahead_behind.0,
        "behind": ahead_behind.1,
        "porcelainHash": if porcelain.is_empty() { Value::Null } else { json!(doctor_hash(porcelain)) },
        "untrackedMode": if availability == "available" { "normal" } else { "none" },
    })
}

fn parse_git_remotes(remote_output: &str) -> Vec<Value> {
    let mut remotes: Vec<RemoteRecord> = vec![];
    for line in remote_output.lines().filter(|line| !line.trim().is_empty()) {
        let Some((name, rest)) = line.split_once(char::is_whitespace) else {
            continue;
        };
        let rest = rest.trim();
        let Some((url, kind)) = rest.rsplit_once(" (") else {
            continue;
        };
        let kind = kind.trim_end_matches(')');
        if kind != "fetch" && kind != "push" {
            continue;
        }
        let metadata = parse_remote_metadata(url);
        let index = remotes
            .iter()
            .position(|remote| remote.name == name)
            .unwrap_or_else(|| {
                remotes.push(RemoteRecord {
                    name: name.to_string(),
                    ..RemoteRecord::default()
                });
                remotes.len() - 1
            });
        let remote = &mut remotes[index];
        if kind == "fetch" {
            remote.fetch_url = Some(redact_remote_url(url));
            remote.fetch_url_hash = Some(doctor_hash(url));
        } else {
            remote.push_url = Some(redact_remote_url(url));
            remote.push_url_hash = Some(doctor_hash(url));
        }
        remote.provider = remote.provider.clone().or(metadata.provider);
        remote.host = remote.host.clone().or(metadata.host);
        remote.owner = remote.owner.clone().or(metadata.owner);
        remote.repo = remote.repo.clone().or(metadata.repo);
        remote.repo_full_name = remote.repo_full_name.clone().or(metadata.repo_full_name);
    }
    remotes.sort_by(|left, right| left.name.cmp(&right.name));
    remotes.into_iter().map(RemoteRecord::to_value).collect()
}

#[derive(Debug, Clone, Default)]
struct RemoteRecord {
    name: String,
    fetch_url: Option<String>,
    fetch_url_hash: Option<String>,
    push_url: Option<String>,
    push_url_hash: Option<String>,
    provider: Option<String>,
    host: Option<String>,
    owner: Option<String>,
    repo: Option<String>,
    repo_full_name: Option<String>,
}

impl RemoteRecord {
    fn to_value(self) -> Value {
        json!({
            "name": self.name,
            "fetchUrl": self.fetch_url,
            "fetchUrlHash": self.fetch_url_hash,
            "pushUrl": self.push_url,
            "pushUrlHash": self.push_url_hash,
            "provider": self.provider,
            "host": self.host,
            "owner": self.owner,
            "repo": self.repo,
            "repoFullName": self.repo_full_name,
        })
    }
}

#[derive(Debug, Clone, Default)]
struct RemoteMetadata {
    provider: Option<String>,
    host: Option<String>,
    owner: Option<String>,
    repo: Option<String>,
    repo_full_name: Option<String>,
}

fn parse_remote_metadata(remote_url: &str) -> RemoteMetadata {
    let (host, path) =
        if let Some(after_scheme) = remote_url.split_once("://").map(|(_, rest)| rest) {
            let path_start = after_scheme.find('/').unwrap_or(after_scheme.len());
            let authority = &after_scheme[..path_start];
            let host = authority
                .rsplit_once('@')
                .map(|(_, host)| host)
                .unwrap_or(authority);
            (host.to_string(), after_scheme[path_start..].to_string())
        } else if let Some((authority, path)) = remote_url.rsplit_once(':') {
            let host = authority
                .rsplit_once('@')
                .map(|(_, host)| host)
                .unwrap_or(authority);
            (host.to_string(), path.to_string())
        } else {
            return RemoteMetadata::default();
        };
    let lower_host = host.to_lowercase();
    let parts: Vec<String> = path
        .trim_start_matches('/')
        .trim_end_matches(".git")
        .split('/')
        .filter(|part| !part.is_empty())
        .map(ToOwned::to_owned)
        .collect();
    let owner = parts.first().cloned();
    let repo = parts.get(1).cloned();
    let repo_full_name = match (owner.as_ref(), repo.as_ref()) {
        (Some(owner), Some(repo)) => Some(format!("{owner}/{repo}")),
        _ => None,
    };
    RemoteMetadata {
        provider: if lower_host == "github.com" {
            Some("github".to_string())
        } else {
            None
        },
        host: if lower_host.is_empty() {
            None
        } else {
            Some(lower_host)
        },
        owner,
        repo,
        repo_full_name,
    }
}

fn redact_remote_url(remote_url: &str) -> String {
    if let Some((scheme, rest)) = remote_url.split_once("://") {
        let path_start = rest.find('/').unwrap_or(rest.len());
        let authority = &rest[..path_start];
        let path = &rest[path_start..];
        let host = authority
            .rsplit_once('@')
            .map(|(_, host)| host)
            .unwrap_or(authority);
        return format!("{scheme}://{host}{path}");
    }
    if remote_url.contains('@') {
        format!("redacted:{}", &doctor_hash(remote_url)[..12])
    } else {
        remote_url.to_string()
    }
}

fn repository_default_branch(repo_root: &str) -> Option<String> {
    let remote_head = empty_to_none(git_output(
        repo_root,
        &["symbolic-ref", "--short", "refs/remotes/origin/HEAD"],
    ))?;
    Some(
        remote_head
            .strip_prefix("origin/")
            .unwrap_or(remote_head.as_str())
            .to_string(),
    )
}

fn repository_ahead_behind(branch_status: &str) -> (usize, usize) {
    let Some(line) = branch_status
        .lines()
        .find(|line| line.starts_with("# branch.ab "))
    else {
        return (0, 0);
    };
    let mut parts = line.split_whitespace();
    let _hash = parts.next();
    let _branch = parts.next();
    let ahead = parts
        .next()
        .and_then(|value| value.strip_prefix('+'))
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    let behind = parts
        .next()
        .and_then(|value| value.strip_prefix('-'))
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    (ahead, behind)
}

fn normalized_projection_kind(
    request: &RepositoryWorkflowProjectionBridgeRequest,
) -> Result<String, RepositoryWorkflowProjectionCommandError> {
    if let Some(value) = optional_trimmed_lower(request.projection_kind.as_deref()) {
        return Ok(value);
    }
    let operation_kind = optional_trimmed(request.operation_kind.as_deref()).unwrap_or_default();
    for kind in [
        "repository_list",
        "repository_context",
        "branch_policy",
        "github_context",
        "pr_attempts",
        "issue_context",
        "review_gate",
        "github_pr_create_plan",
    ] {
        if operation_kind.ends_with(kind) {
            return Ok(kind.to_string());
        }
    }
    Err(RepositoryWorkflowProjectionCommandError::new(
        "repository_workflow_projection_kind_required",
        "repository workflow projection kind is required",
    ))
}

fn git_output(cwd: &str, args: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(cwd)
        .args(args)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?;
    empty_to_none(Some(text))
}

fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

fn absolute_path(value: String) -> String {
    let path = PathBuf::from(value);
    if path.is_absolute() {
        return path.to_string_lossy().into_owned();
    }
    std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(path)
        .to_string_lossy()
        .into_owned()
}

fn relative_path(from: &str, to: &str) -> String {
    let from = Path::new(from);
    let to = Path::new(to);
    let value = to
        .strip_prefix(from)
        .ok()
        .and_then(|path| path.to_str())
        .filter(|path| !path.is_empty())
        .unwrap_or(".");
    value.to_string()
}

fn empty_to_none(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn optional_trimmed(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn optional_trimmed_lower(value: Option<&str>) -> Option<String> {
    optional_trimmed(value).map(|value| value.to_ascii_lowercase())
}

fn doctor_hash(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn merge_json(mut base: Value, addition: Value) -> Value {
    let Some(base_object) = base.as_object_mut() else {
        return addition;
    };
    if let Some(addition_object) = addition.as_object() {
        for (key, value) in addition_object {
            base_object.insert(key.clone(), value.clone());
        }
    }
    base
}

fn string_field(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

fn bool_field(value: &Value, key: &str) -> bool {
    value.get(key).and_then(Value::as_bool).unwrap_or(false)
}

fn number_field(value: &Value, key: &str) -> usize {
    value
        .get(key)
        .and_then(Value::as_u64)
        .map(|value| value as usize)
        .unwrap_or(0)
}

fn string_array(value: Value) -> Vec<String> {
    value
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|value| value.as_str().map(ToOwned::to_owned))
        .collect()
}

fn unique_strings(values: Vec<String>) -> Vec<String> {
    let mut unique = vec![];
    for value in values.into_iter().filter(|value| !value.is_empty()) {
        if !unique.contains(&value) {
            unique.push(value);
        }
    }
    unique
}

fn optional_value(value: Option<String>) -> Value {
    value.map(Value::String).unwrap_or(Value::Null)
}

fn evidence_refs(values: Vec<Value>) -> Vec<Value> {
    values
        .into_iter()
        .filter(|value| !value.is_null())
        .collect()
}

fn repository_status_is_conflict(status: &str) -> bool {
    matches!(status, "DD" | "AU" | "UD" | "UA" | "DU" | "AA" | "UU")
}

fn repository_context_redaction() -> Value {
    json!({
        "profile": "repository_context_safe",
        "pathIncluded": true,
        "remoteUrlsHashed": true,
        "remoteCredentialsIncluded": false,
        "statusPathsIncluded": false,
    })
}

fn github_token_sources() -> Vec<String> {
    ["GITHUB_TOKEN", "GH_TOKEN"]
        .iter()
        .filter(|name| {
            std::env::var(name)
                .map(|value| !value.is_empty())
                .unwrap_or(false)
        })
        .map(|name| name.to_string())
        .collect()
}

fn branch_policy_summary(
    status: &str,
    branch: Option<&str>,
    protected_branch: bool,
    blockers: &[String],
    warnings: &[String],
) -> String {
    let branch = branch.unwrap_or("detached HEAD");
    if status == "passed" {
        return format!(
            "Branch policy passed for {branch}; mutation and PR workflows may proceed."
        );
    }
    if status == "blocked" {
        return format!(
            "Branch policy blocked {branch}{}: {}.",
            if protected_branch {
                " because it is protected/default"
            } else {
                ""
            },
            blockers.join(", ")
        );
    }
    format!(
        "Branch policy warning for {branch}: {}.",
        warnings.join(", ")
    )
}

fn branch_policy_recommended_next_action(
    status: &str,
    blockers: &[String],
    warnings: &[String],
) -> &'static str {
    if status == "passed" {
        return "Proceed to review or PR workflow gates.";
    }
    if blockers.iter().any(|value| value == "protected_branch") {
        return "Create or switch to a feature branch before requesting branch mutation or PR creation.";
    }
    if blockers.iter().any(|value| value == "conflicted_worktree") {
        return "Resolve merge conflicts before requesting branch mutation or PR creation.";
    }
    if blockers.iter().any(|value| value == "detached_head") {
        return "Check out a named feature branch before requesting branch mutation or PR creation.";
    }
    if warnings.iter().any(|value| value == "dirty_worktree") {
        return "Review, stage, or commit local worktree changes before requesting PR creation.";
    }
    if warnings.iter().any(|value| value == "missing_upstream") {
        return "Configure an upstream branch or accept a review gate before PR creation.";
    }
    "Review branch policy warnings before requesting mutation."
}

fn github_context_summary(status: &str, repo_full_name: Option<&str>, policy: &Value) -> String {
    let Some(repo_full_name) = repo_full_name else {
        return "No GitHub remote was detected in repository context.".to_string();
    };
    if status == "blocked" {
        return format!(
            "GitHub context resolved {repo_full_name}, but branch policy is blocked: {}.",
            string_array(policy["blockers"].clone()).join(", ")
        );
    }
    if status == "warning" {
        return format!(
            "GitHub context resolved {repo_full_name} with branch policy warnings: {}.",
            string_array(policy["warnings"].clone()).join(", ")
        );
    }
    format!("GitHub context resolved {repo_full_name} without network calls.")
}

fn issue_context_summary(
    status: &str,
    repo_full_name: Option<&str>,
    issue_number: Option<i64>,
    title: Option<&str>,
) -> String {
    let target = repo_full_name.unwrap_or("unknown GitHub repository");
    if status == "bound" {
        let issue_ref = issue_number
            .map(|value| format!("#{value}"))
            .or_else(|| title.map(ToOwned::to_owned))
            .unwrap_or_else(|| "provided issue".to_string());
        return format!("Issue context {issue_ref} is bound for {target} without network reads.");
    }
    if status == "unavailable" {
        return "Issue context is unavailable because no GitHub remote was detected.".to_string();
    }
    format!(
        "No issue is bound for {target}; PR workflow may continue with an unbound issue context."
    )
}

fn pr_attempt_summary(
    status: &str,
    outcome: &str,
    repo_full_name: Option<&str>,
    blockers: &[String],
) -> String {
    let target = repo_full_name.unwrap_or("unknown GitHub repository");
    if status == "blocked" {
        return format!(
            "PR attempt for {target} recorded as {outcome}; blockers: {}.",
            blockers.join(", ")
        );
    }
    format!("PR attempt for {target} recorded as preview-ready; mutation remains disabled.")
}

fn review_gate_summary(status: &str, repo_full_name: Option<&str>, blockers: &[String]) -> String {
    let target = repo_full_name.unwrap_or("unknown GitHub repository");
    if status == "passed" {
        return format!(
            "Review gate passed for {target}; PR creation may proceed to authority checks."
        );
    }
    format!(
        "Review gate blocked PR creation for {target}: {}.",
        blockers.join(", ")
    )
}

fn github_pr_create_plan_summary(
    status: &str,
    repo_full_name: Option<&str>,
    blockers: &[String],
) -> String {
    let target = repo_full_name.unwrap_or("unknown GitHub repository");
    if status == "ready" {
        return format!("GitHub PR create dry-run plan is ready for {target}; mutation remains disabled pending authority approval.");
    }
    format!(
        "GitHub PR create dry-run plan is blocked for {target}: {}.",
        blockers.join(", ")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rust_projects_repository_workflow_context_and_policy() {
        let response =
            project_repository_workflow_response(RepositoryWorkflowProjectionBridgeRequest {
                operation: Some("repository_workflow_repository_context".to_string()),
                operation_kind: Some(
                    "repository_workflow.projection.repository_context".to_string(),
                ),
                projection_kind: Some("repository_context".to_string()),
                workspace_root: Some("/tmp/nonexistent-ioi-repository-workflow-test".to_string()),
                source: Some("test".to_string()),
                ..Default::default()
            })
            .expect("repository workflow projection");
        let record = &response["record"];
        assert_eq!(
            response["source"],
            "rust_repository_workflow_projection_command"
        );
        assert_eq!(record["projection_kind"], "repository_context");
        assert_eq!(
            record["projection"]["schemaVersion"],
            "ioi.agent-runtime.repository-context.v1"
        );
        assert_eq!(record["projection"]["object"], "ioi.repository_context");
        assert_eq!(record["projection"]["isGitRepository"], false);
        assert_eq!(
            record["repository_context"]["status"]["availability"],
            "not_a_git_repository"
        );
    }

    #[test]
    fn rust_projects_repository_workflow_pr_family_shapes() {
        let response =
            project_repository_workflow_response(RepositoryWorkflowProjectionBridgeRequest {
                operation: Some("repository_workflow_github_pr_create_plan".to_string()),
                operation_kind: Some(
                    "repository_workflow.projection.github_pr_create_plan".to_string(),
                ),
                projection_kind: Some("github_pr_create_plan".to_string()),
                workspace_root: Some("/tmp/nonexistent-ioi-repository-workflow-test".to_string()),
                source: Some("test".to_string()),
                ..Default::default()
            })
            .expect("repository workflow projection");
        let record = &response["record"];
        assert_eq!(record["projection_kind"], "github_pr_create_plan");
        assert_eq!(
            record["projection"]["schemaVersion"],
            "ioi.agent-runtime.github-pr-create-plan.v1"
        );
        assert_eq!(
            record["pr_attempt"]["schemaVersion"],
            "ioi.agent-runtime.pr-attempt.v1"
        );
        assert_eq!(
            record["review_gate"]["schemaVersion"],
            "ioi.agent-runtime.review-gate.v1"
        );
        assert_eq!(record["projection"]["request"]["method"], "POST");
        assert_eq!(record["projection"]["dryRun"], true);
    }

    #[test]
    fn rust_shapes_repository_workflow_command_response() {
        let response =
            project_repository_workflow_response(RepositoryWorkflowProjectionBridgeRequest {
                operation_kind: Some("repository_workflow.projection.pr_attempts".to_string()),
                projection_kind: Some("pr_attempts".to_string()),
                workspace_root: Some("/workspace/project".to_string()),
                ..Default::default()
            })
            .expect("repository workflow command response");
        assert_eq!(
            response["source"],
            "rust_repository_workflow_projection_command"
        );
        assert_eq!(response["backend"], "rust_policy");
        assert_eq!(
            response["record"]["schema_version"],
            REPOSITORY_WORKFLOW_PROJECTION_RESULT_SCHEMA_VERSION
        );
        assert_eq!(response["record"]["projection_kind"], "pr_attempts");
        assert!(response["record"]["receipt_refs"][0]
            .as_str()
            .expect("receipt")
            .contains("repository_workflow_projection_pr_attempts"));
    }
}
