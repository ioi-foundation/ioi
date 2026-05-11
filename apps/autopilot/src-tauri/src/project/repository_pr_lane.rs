// apps/autopilot/src-tauri/src/project/repository_pr_lane.rs

use super::*;
use sha2::{Digest, Sha256};

fn workflow_value_string_any(value: &Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(Value::as_str))
        .map(str::to_string)
}

fn workflow_value_bool_any(value: &Value, keys: &[&str]) -> Option<bool> {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(Value::as_bool))
}

fn workflow_value_u64_any(value: &Value, keys: &[&str]) -> Option<u64> {
    keys.iter().find_map(|key| {
        value.get(*key).and_then(Value::as_u64).or_else(|| {
            value
                .get(*key)
                .and_then(Value::as_i64)
                .and_then(|item| (item >= 0).then_some(item as u64))
        })
    })
}

fn workflow_string_array_any(value: &Value, keys: &[&str]) -> Vec<String> {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(Value::as_array))
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(str::to_string)
        .collect()
}

fn workflow_project_root_for_path(workflow_path: &Path) -> String {
    workflow_path
        .parent()
        .and_then(|workflows_dir| workflows_dir.parent())
        .and_then(|agents_dir| {
            (agents_dir.file_name().and_then(|name| name.to_str()) == Some(".agents"))
                .then(|| agents_dir.parent())
                .flatten()
        })
        .or_else(|| workflow_path.parent())
        .unwrap_or_else(|| Path::new("."))
        .display()
        .to_string()
}

fn workflow_value_at_path(value: &Value, path: &str) -> Option<Value> {
    path.split('.')
        .try_fold(value, |cursor, segment| cursor.get(segment))
        .cloned()
}

fn workflow_hash_value_raw_hex(value: &Value) -> String {
    let bytes = serde_jcs::to_vec(value)
        .or_else(|_| serde_json::to_vec(value))
        .unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn workflow_find_object_by_marker<'a>(value: &'a Value, object_marker: &str) -> Option<&'a Value> {
    if value.get("object").and_then(Value::as_str) == Some(object_marker) {
        return Some(value);
    }
    match value {
        Value::Array(items) => items
            .iter()
            .find_map(|item| workflow_find_object_by_marker(item, object_marker)),
        Value::Object(object) => object
            .values()
            .find_map(|item| workflow_find_object_by_marker(item, object_marker)),
        _ => None,
    }
}

fn workflow_object_string_any(value: Option<&Value>, keys: &[&str]) -> Option<String> {
    value.and_then(|item| workflow_value_string_any(item, keys))
}

fn workflow_object_bool_any(value: Option<&Value>, keys: &[&str]) -> Option<bool> {
    value.and_then(|item| workflow_value_bool_any(item, keys))
}

fn workflow_object_u64_any(value: Option<&Value>, keys: &[&str]) -> Option<u64> {
    value.and_then(|item| workflow_value_u64_any(item, keys))
}

fn workflow_object_array_strings(value: Option<&Value>, key: &str) -> Vec<String> {
    value
        .and_then(|item| item.get(key))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(str::to_string)
        .collect()
}

fn workflow_push_unique_string(items: &mut Vec<String>, value: impl Into<String>) {
    let value = value.into();
    if !value.trim().is_empty() && !items.iter().any(|item| item == &value) {
        items.push(value);
    }
}

fn workflow_repo_owner_repo(repo_full_name: Option<String>) -> (Option<String>, Option<String>) {
    let Some(repo_full_name) = repo_full_name else {
        return (None, None);
    };
    let mut segments = repo_full_name.split('/').map(str::trim);
    let owner = segments
        .next()
        .filter(|item| !item.is_empty())
        .map(str::to_string);
    let repo = segments
        .next()
        .filter(|item| !item.is_empty())
        .map(str::to_string);
    (owner, repo)
}

fn workflow_repo_full_name(owner: Option<&str>, repo: Option<&str>) -> Option<String> {
    match (owner, repo) {
        (Some(owner), Some(repo)) if !owner.trim().is_empty() && !repo.trim().is_empty() => {
            Some(format!("{}/{}", owner.trim(), repo.trim()))
        }
        _ => None,
    }
}

pub(super) fn workflow_repository_context_output(
    workflow_path: &Path,
    node_id: &str,
    logic: &Value,
    evidence_kind: &str,
) -> Value {
    let root_path = workflow_value_string_any(logic, &["projectRoot", "rootPath"])
        .unwrap_or_else(|| workflow_project_root_for_path(workflow_path));
    let branch = workflow_value_string_any(logic, &["branch", "currentBranch", "headBranch"])
        .unwrap_or_else(|| "working-branch".to_string());
    let default_branch = workflow_value_string_any(logic, &["defaultBranch", "baseBranch"])
        .unwrap_or_else(|| "main".to_string());
    let repo_full_name = workflow_value_string_any(logic, &["repoFullName", "repository"]);
    let (owner, repo) = workflow_repo_owner_repo(repo_full_name.clone());
    let dirty = workflow_value_bool_any(logic, &["dirty", "worktreeDirty"]).unwrap_or(false);
    let repository_available = repo_full_name.is_some();
    json!({
        "schemaVersion": "ioi.agent-runtime.repository-context.v1",
        "object": "ioi.repository_context",
        "contextId": workflow_value_string_any(logic, &["contextId", "repositoryContextId"]).unwrap_or_else(|| format!("repository_context_{}", node_id)),
        "nodeId": node_id,
        "kind": evidence_kind,
        "rootPath": root_path,
        "repoFullName": repo_full_name,
        "owner": owner,
        "repo": repo,
        "branch": branch,
        "currentBranch": branch,
        "defaultBranch": default_branch,
        "status": {
            "availability": if repository_available { "available" } else { "projection" },
            "dirty": dirty,
            "counts": {
                "staged": workflow_value_u64_any(logic, &["stagedCount"]).unwrap_or(0),
                "unstaged": workflow_value_u64_any(logic, &["unstagedCount"]).unwrap_or(0),
                "untracked": workflow_value_u64_any(logic, &["untrackedCount"]).unwrap_or(0)
            }
        },
        "readOnly": workflow_value_bool_any(logic, &["readOnly"]).unwrap_or(false),
        "networkLookupPerformed": false,
        "mutationExecuted": false,
        "redaction": { "profile": "repository_context_safe" },
        "evidenceRefs": ["repository_context"]
    })
}

pub(super) fn workflow_branch_policy_output(
    node_id: &str,
    logic: &Value,
    input: &Value,
    evidence_kind: &str,
) -> Value {
    let repository_context = workflow_find_object_by_marker(input, "ioi.repository_context");
    let branch = workflow_value_string_any(logic, &["branch", "currentBranch"])
        .or_else(|| workflow_object_string_any(repository_context, &["branch", "currentBranch"]))
        .unwrap_or_else(|| "working-branch".to_string());
    let dirty = workflow_value_bool_any(logic, &["dirty", "worktreeDirty"])
        .or_else(|| {
            repository_context
                .and_then(|context| workflow_value_at_path(context, "status.dirty"))
                .and_then(|value| value.as_bool())
        })
        .unwrap_or(false);
    let allow_dirty =
        workflow_value_bool_any(logic, &["allowDirtyWorktree", "allowDirty"]).unwrap_or(true);
    let protected_branches = workflow_string_array_any(logic, &["protectedBranches"]);
    let block_protected =
        workflow_value_bool_any(logic, &["blockProtectedBranches"]).unwrap_or(false);
    let mut blockers = Vec::new();
    if dirty && !allow_dirty {
        workflow_push_unique_string(&mut blockers, "dirty_worktree");
    }
    if block_protected && protected_branches.iter().any(|item| item == &branch) {
        workflow_push_unique_string(&mut blockers, "protected_branch");
    }
    let status = if blockers.is_empty() {
        "passed"
    } else {
        "blocked"
    };
    json!({
        "schemaVersion": "ioi.agent-runtime.branch-policy.v1",
        "object": "ioi.branch_policy_decision",
        "policyId": workflow_value_string_any(logic, &["policyId", "branchPolicyId"]).unwrap_or_else(|| format!("branch_policy_{}", node_id)),
        "repositoryContextId": workflow_object_string_any(repository_context, &["contextId"]),
        "nodeId": node_id,
        "kind": evidence_kind,
        "status": status,
        "branch": branch,
        "defaultBranch": workflow_object_string_any(repository_context, &["defaultBranch"]),
        "allowDirtyWorktree": allow_dirty,
        "protectedBranches": protected_branches,
        "blockers": blockers,
        "warnings": workflow_string_array_any(logic, &["warnings"]),
        "readOnly": true,
        "networkLookupPerformed": false,
        "mutationExecuted": false,
        "redaction": { "profile": "branch_policy_safe" },
        "evidenceRefs": ["branch_policy", "repository_context"]
    })
}

pub(super) fn workflow_github_context_output(
    node_id: &str,
    logic: &Value,
    input: &Value,
    evidence_kind: &str,
) -> Value {
    let repository_context = workflow_find_object_by_marker(input, "ioi.repository_context");
    let branch_policy = workflow_find_object_by_marker(input, "ioi.branch_policy_decision");
    let repo_full_name = workflow_value_string_any(logic, &["repoFullName", "repository"])
        .or_else(|| workflow_object_string_any(repository_context, &["repoFullName"]));
    let (owner_from_full, repo_from_full) = workflow_repo_owner_repo(repo_full_name.clone());
    let owner = workflow_value_string_any(logic, &["owner"])
        .or(owner_from_full)
        .or_else(|| workflow_object_string_any(repository_context, &["owner"]));
    let repo = workflow_value_string_any(logic, &["repo"])
        .or(repo_from_full)
        .or_else(|| workflow_object_string_any(repository_context, &["repo"]));
    let resolved_repo_full_name =
        repo_full_name.or_else(|| workflow_repo_full_name(owner.as_deref(), repo.as_deref()));
    let status = if resolved_repo_full_name.is_some() {
        "available"
    } else {
        "unavailable"
    };
    json!({
        "schemaVersion": "ioi.agent-runtime.github-context.v1",
        "object": "ioi.github_context",
        "contextId": workflow_value_string_any(logic, &["contextId", "githubContextId"]).unwrap_or_else(|| format!("github_context_{}", node_id)),
        "repositoryContextId": workflow_object_string_any(repository_context, &["contextId"]),
        "branchPolicyId": workflow_object_string_any(branch_policy, &["policyId"]),
        "nodeId": node_id,
        "kind": evidence_kind,
        "status": status,
        "repoFullName": resolved_repo_full_name.clone(),
        "owner": owner,
        "repo": repo,
        "defaultBranch": workflow_value_string_any(logic, &["defaultBranch", "baseBranch"])
            .or_else(|| workflow_object_string_any(repository_context, &["defaultBranch"])),
        "branch": workflow_value_string_any(logic, &["branch", "headBranch"])
            .or_else(|| workflow_object_string_any(repository_context, &["branch", "currentBranch"])),
        "credentials": {
            "tokenAvailable": workflow_value_bool_any(logic, &["tokenAvailable", "credentialReady"]).unwrap_or(false),
            "tokenValueIncluded": false
        },
        "networkLookupPerformed": false,
        "mutationExecuted": false,
        "redaction": {
            "profile": "github_context_safe",
            "tokenValueIncluded": false,
            "authorizationHeaderIncluded": false
        },
        "evidenceRefs": ["github_context", "repository_context", "branch_policy"]
    })
}

pub(super) fn workflow_issue_context_output(
    node_id: &str,
    logic: &Value,
    input: &Value,
    evidence_kind: &str,
) -> Value {
    let github_context = workflow_find_object_by_marker(input, "ioi.github_context");
    let issue_number = workflow_value_u64_any(logic, &["issueNumber"])
        .or_else(|| workflow_object_u64_any(github_context, &["issueNumber"]));
    let bound = issue_number.is_some();
    json!({
        "schemaVersion": "ioi.agent-runtime.issue-context.v1",
        "object": "ioi.issue_context",
        "contextId": workflow_value_string_any(logic, &["contextId", "issueContextId"]).unwrap_or_else(|| format!("issue_context_{}", node_id)),
        "githubContextId": workflow_object_string_any(github_context, &["contextId"]),
        "nodeId": node_id,
        "kind": evidence_kind,
        "status": if bound { "bound" } else { "unbound" },
        "bound": bound,
        "issueNumber": issue_number,
        "warnings": if bound { Vec::<String>::new() } else { vec!["issue_context_unbound".to_string()] },
        "networkLookupPerformed": false,
        "mutationExecuted": false,
        "redaction": { "profile": "issue_context_safe", "bodyIncluded": false },
        "evidenceRefs": ["issue_context", "github_context"]
    })
}

pub(super) fn workflow_pr_attempt_output(
    node_id: &str,
    logic: &Value,
    input: &Value,
    evidence_kind: &str,
) -> Value {
    let repository_context = workflow_find_object_by_marker(input, "ioi.repository_context");
    let branch_policy = workflow_find_object_by_marker(input, "ioi.branch_policy_decision");
    let github_context = workflow_find_object_by_marker(input, "ioi.github_context");
    let issue_context = workflow_find_object_by_marker(input, "ioi.issue_context");
    let branch_policy_status = workflow_object_string_any(branch_policy, &["status"])
        .unwrap_or_else(|| "unknown".to_string());
    let github_status = workflow_object_string_any(github_context, &["status"])
        .unwrap_or_else(|| "unknown".to_string());
    let mut blockers = Vec::new();
    if branch_policy_status != "passed" {
        workflow_push_unique_string(&mut blockers, "branch_policy_not_passed");
    }
    if github_status != "available" {
        workflow_push_unique_string(&mut blockers, "github_context_not_available");
    }
    for blocker in workflow_object_array_strings(branch_policy, "blockers") {
        workflow_push_unique_string(&mut blockers, blocker);
    }
    let status = if blockers.is_empty() {
        "ready"
    } else {
        "blocked"
    };
    let head_branch = workflow_value_string_any(logic, &["headBranch", "branch"])
        .or_else(|| workflow_object_string_any(repository_context, &["branch", "currentBranch"]))
        .unwrap_or_else(|| "working-branch".to_string());
    let base_branch = workflow_value_string_any(logic, &["baseBranch", "defaultBranch"])
        .or_else(|| workflow_object_string_any(repository_context, &["defaultBranch"]))
        .unwrap_or_else(|| "main".to_string());
    let title = workflow_value_string_any(logic, &["title", "prTitle"])
        .unwrap_or_else(|| format!("Draft PR for {}", head_branch));
    json!({
        "schemaVersion": "ioi.agent-runtime.pr-attempt.v1",
        "object": "ioi.pr_attempt",
        "attemptId": workflow_value_string_any(logic, &["attemptId", "prAttemptId"]).unwrap_or_else(|| format!("pr_attempt_{}", node_id)),
        "repositoryContextId": workflow_object_string_any(repository_context, &["contextId"]),
        "branchPolicyId": workflow_object_string_any(branch_policy, &["policyId"]),
        "githubContextId": workflow_object_string_any(github_context, &["contextId"]),
        "issueContextId": workflow_object_string_any(issue_context, &["contextId"]),
        "nodeId": node_id,
        "kind": evidence_kind,
        "status": status,
        "title": title,
        "baseBranch": base_branch,
        "headBranch": head_branch,
        "draft": true,
        "diffArtifactAttached": workflow_value_bool_any(logic, &["diffArtifactAttached"]).unwrap_or(true),
        "branchArtifactAttached": workflow_value_bool_any(logic, &["branchArtifactAttached"]).unwrap_or(true),
        "blockers": blockers,
        "warnings": ["pr_attempt_preview_only"],
        "previewOnly": true,
        "networkLookupPerformed": false,
        "mutationAttempted": false,
        "mutationExecuted": false,
        "redaction": { "profile": "pr_attempt_safe", "bodyIncluded": false },
        "evidenceRefs": ["pr_attempt", "repository_context", "branch_policy", "github_context"]
    })
}

pub(super) fn workflow_review_gate_output(
    node_id: &str,
    logic: &Value,
    input: &Value,
    evidence_kind: &str,
) -> Value {
    let repository_context = workflow_find_object_by_marker(input, "ioi.repository_context");
    let branch_policy = workflow_find_object_by_marker(input, "ioi.branch_policy_decision");
    let github_context = workflow_find_object_by_marker(input, "ioi.github_context");
    let issue_context = workflow_find_object_by_marker(input, "ioi.issue_context");
    let pr_attempt = workflow_find_object_by_marker(input, "ioi.pr_attempt");
    let review_satisfied =
        workflow_value_bool_any(logic, &["reviewSatisfied", "approvalSatisfied"]).unwrap_or(false);
    let mut blockers = Vec::new();
    if workflow_object_string_any(branch_policy, &["status"]).as_deref() != Some("passed") {
        workflow_push_unique_string(&mut blockers, "branch_policy_not_passed");
    }
    if workflow_object_string_any(github_context, &["status"]).as_deref() != Some("available") {
        workflow_push_unique_string(&mut blockers, "github_context_not_available");
    }
    if workflow_object_string_any(pr_attempt, &["status"]).as_deref() != Some("ready") {
        workflow_push_unique_string(&mut blockers, "pr_attempt_not_ready");
    }
    if !review_satisfied {
        workflow_push_unique_string(&mut blockers, "review_not_satisfied");
    }
    let status = if blockers.is_empty() {
        "passed"
    } else {
        "blocked"
    };
    json!({
        "schemaVersion": "ioi.agent-runtime.review-gate.v1",
        "object": "ioi.review_gate_decision",
        "gateId": workflow_value_string_any(logic, &["gateId", "reviewGateId"]).unwrap_or_else(|| format!("review_gate_{}", node_id)),
        "repositoryContextId": workflow_object_string_any(repository_context, &["contextId"]),
        "branchPolicyId": workflow_object_string_any(branch_policy, &["policyId"]),
        "githubContextId": workflow_object_string_any(github_context, &["contextId"]),
        "issueContextId": workflow_object_string_any(issue_context, &["contextId"]),
        "prAttemptId": workflow_object_string_any(pr_attempt, &["attemptId"]),
        "nodeId": node_id,
        "kind": evidence_kind,
        "status": status,
        "decision": status,
        "reviewSatisfied": review_satisfied,
        "mutationAllowed": false,
        "prCreationAllowed": false,
        "blockers": blockers,
        "warnings": ["review_gate_preview_only"],
        "preconditions": {
            "branchPolicyPassed": workflow_object_string_any(branch_policy, &["status"]).as_deref() == Some("passed"),
            "githubContextAvailable": workflow_object_string_any(github_context, &["status"]).as_deref() == Some("available"),
            "prAttemptReady": workflow_object_string_any(pr_attempt, &["status"]).as_deref() == Some("ready"),
            "diffArtifactAttached": workflow_object_bool_any(pr_attempt, &["diffArtifactAttached"]).unwrap_or(false),
            "reviewPolicySatisfied": review_satisfied,
            "networkLookupPerformed": false,
            "mutationExecuted": false
        },
        "networkLookupPerformed": false,
        "mutationExecuted": false,
        "redaction": { "profile": "review_gate_safe" },
        "evidenceRefs": ["review_gate", "repository_context", "branch_policy", "github_context", "pr_attempt"]
    })
}

pub(super) fn workflow_github_pr_create_output(
    node_id: &str,
    logic: &Value,
    input: &Value,
    evidence_kind: &str,
) -> Result<Value, String> {
    if !workflow_value_bool_any(logic, &["dryRun", "previewOnly"]).unwrap_or(true) {
        return Err(
            "GitHub PR creation workflow nodes currently execute as dry-run plans only."
                .to_string(),
        );
    }
    let repository_context = workflow_find_object_by_marker(input, "ioi.repository_context");
    let branch_policy = workflow_find_object_by_marker(input, "ioi.branch_policy_decision");
    let github_context = workflow_find_object_by_marker(input, "ioi.github_context");
    let issue_context = workflow_find_object_by_marker(input, "ioi.issue_context");
    let pr_attempt = workflow_find_object_by_marker(input, "ioi.pr_attempt");
    let review_gate = workflow_find_object_by_marker(input, "ioi.review_gate_decision");
    let repo_full_name = workflow_value_string_any(logic, &["repoFullName", "repository"])
        .or_else(|| workflow_object_string_any(github_context, &["repoFullName"]))
        .or_else(|| workflow_object_string_any(repository_context, &["repoFullName"]));
    let (owner_from_full, repo_from_full) = workflow_repo_owner_repo(repo_full_name.clone());
    let owner = workflow_value_string_any(logic, &["owner"])
        .or(owner_from_full)
        .or_else(|| workflow_object_string_any(github_context, &["owner"]))
        .or_else(|| workflow_object_string_any(repository_context, &["owner"]));
    let repo = workflow_value_string_any(logic, &["repo"])
        .or(repo_from_full)
        .or_else(|| workflow_object_string_any(github_context, &["repo"]))
        .or_else(|| workflow_object_string_any(repository_context, &["repo"]));
    let resolved_repo_full_name =
        repo_full_name.or_else(|| workflow_repo_full_name(owner.as_deref(), repo.as_deref()));
    let base_branch = workflow_value_string_any(logic, &["baseBranch", "defaultBranch"])
        .or_else(|| workflow_object_string_any(pr_attempt, &["baseBranch"]))
        .or_else(|| workflow_object_string_any(repository_context, &["defaultBranch"]))
        .or_else(|| workflow_object_string_any(github_context, &["defaultBranch"]));
    let head_branch = workflow_value_string_any(logic, &["headBranch", "branch"])
        .or_else(|| workflow_object_string_any(pr_attempt, &["headBranch"]))
        .or_else(|| workflow_object_string_any(repository_context, &["branch", "currentBranch"]))
        .or_else(|| workflow_object_string_any(github_context, &["branch"]));
    let title = workflow_value_string_any(logic, &["title", "prTitle"])
        .or_else(|| workflow_object_string_any(pr_attempt, &["title"]))
        .unwrap_or_else(|| {
            format!(
                "Draft PR for {}",
                head_branch.as_deref().unwrap_or("working branch")
            )
        });
    let issue_number = workflow_object_u64_any(issue_context, &["issueNumber"]);
    let issue_bound = workflow_object_bool_any(issue_context, &["bound"]).unwrap_or(false);
    let payload_preview = json!({
        "owner": owner,
        "repo": repo,
        "base": base_branch,
        "head": head_branch,
        "title": title,
        "bodyIncluded": false,
        "draft": true,
        "maintainerCanModify": true,
        "issueNumber": issue_number,
    });
    let payload_hash = workflow_hash_value_raw_hex(&payload_preview);
    let review_gate_status = workflow_object_string_any(review_gate, &["status"])
        .unwrap_or_else(|| "blocked".to_string());
    let review_satisfied =
        workflow_object_bool_any(review_gate, &["reviewSatisfied"]).unwrap_or(false);
    let github_status = workflow_object_string_any(github_context, &["status"])
        .unwrap_or_else(|| "unavailable".to_string());
    let branch_policy_status = workflow_object_string_any(branch_policy, &["status"])
        .unwrap_or_else(|| "blocked".to_string());
    let pr_attempt_status = workflow_object_string_any(pr_attempt, &["status"])
        .unwrap_or_else(|| "blocked".to_string());
    let token_available = github_context
        .and_then(|context| workflow_value_at_path(context, "credentials.tokenAvailable"))
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    let mut blockers = Vec::new();
    for blocker in workflow_object_array_strings(review_gate, "blockers") {
        workflow_push_unique_string(&mut blockers, blocker);
    }
    for blocker in workflow_object_array_strings(pr_attempt, "blockers") {
        workflow_push_unique_string(&mut blockers, blocker);
    }
    if github_status != "available" {
        workflow_push_unique_string(&mut blockers, "github_context_not_available");
    }
    if branch_policy_status != "passed" {
        workflow_push_unique_string(&mut blockers, "branch_policy_not_passed");
    }
    if pr_attempt_status != "ready" {
        workflow_push_unique_string(&mut blockers, "pr_attempt_not_ready");
    }
    if review_gate_status != "passed" {
        workflow_push_unique_string(&mut blockers, "review_gate_not_passed");
    }
    if !review_satisfied {
        workflow_push_unique_string(&mut blockers, "review_not_satisfied");
    }
    if !token_available {
        workflow_push_unique_string(&mut blockers, "missing_github_token");
    }
    workflow_push_unique_string(&mut blockers, "missing_authority_scope:github.pr.create");
    workflow_push_unique_string(&mut blockers, "dry_run_only");
    let status = if blockers.is_empty() {
        "ready"
    } else {
        "blocked"
    };
    let target = resolved_repo_full_name
        .as_deref()
        .unwrap_or("unknown GitHub repository");
    let summary = if status == "ready" {
        format!(
            "GitHub PR create dry-run plan is ready for {}; mutation remains disabled pending authority approval.",
            target
        )
    } else {
        format!(
            "GitHub PR create dry-run plan is blocked for {}: {}.",
            target,
            blockers.join(", ")
        )
    };
    let plan_id = workflow_value_string_any(logic, &["planId"])
        .unwrap_or_else(|| format!("github_pr_create_plan_{}", &payload_hash[..12]));
    let plan = json!({
        "schemaVersion": "ioi.agent-runtime.github-pr-create-plan.v1",
        "object": "ioi.github_pr_create_plan",
        "planId": plan_id,
        "nodeId": node_id,
        "kind": evidence_kind,
        "runId": Value::Null,
        "generatedAt": chrono::Utc::now().to_rfc3339(),
        "repositoryContextId": workflow_object_string_any(repository_context, &["contextId"]),
        "branchPolicyId": workflow_object_string_any(branch_policy, &["policyId"]),
        "githubContextId": workflow_object_string_any(github_context, &["contextId"]),
        "issueContextId": workflow_object_string_any(issue_context, &["contextId"]),
        "prAttemptId": workflow_object_string_any(pr_attempt, &["attemptId"]),
        "reviewGateId": workflow_object_string_any(review_gate, &["gateId"]),
        "status": status,
        "decision": status,
        "summary": summary,
        "dryRun": true,
        "previewOnly": true,
        "provider": "github",
        "toolName": "github__pr_create",
        "action": "pr_create",
        "repoFullName": resolved_repo_full_name,
        "owner": payload_preview.get("owner").cloned().unwrap_or(Value::Null),
        "repo": payload_preview.get("repo").cloned().unwrap_or(Value::Null),
        "baseBranch": payload_preview.get("base").cloned().unwrap_or(Value::Null),
        "headBranch": payload_preview.get("head").cloned().unwrap_or(Value::Null),
        "title": payload_preview.get("title").cloned().unwrap_or(Value::Null),
        "bodyPlan": {
            "included": false,
            "source": if issue_bound { "issue_context" } else { "runtime_template" },
            "redaction": "body_not_included_in_projection"
        },
        "issueNumber": issue_number,
        "reviewGateStatus": review_gate_status,
        "reviewSatisfied": review_satisfied,
        "authority": {
            "requiredScopes": ["github.pr.create"],
            "grantedScopes": [],
            "missingScopes": ["github.pr.create"],
            "scopeGranted": false,
            "approvalRequired": true,
            "approvalSatisfied": false
        },
        "request": {
            "method": "POST",
            "path": resolved_repo_full_name.as_ref().map(|repo| format!("/repos/{}/pulls", repo)),
            "payloadHash": payload_hash.clone(),
            "payloadPreview": payload_preview,
            "bodyIncluded": false,
            "tokenIncluded": false
        },
        "blockers": blockers,
        "warnings": ["github_pr_create_plan_dry_run"],
        "networkLookupPerformed": false,
        "mutationAttempted": false,
        "mutationExecuted": false,
        "prNumber": Value::Null,
        "prUrl": Value::Null,
        "redaction": {
            "profile": "github_pr_create_plan_safe",
            "tokenValueIncluded": false,
            "authorizationHeaderIncluded": false,
            "requestBodyIncluded": false,
            "responseBodyIncluded": false,
            "networkResponseIncluded": false
        },
        "receiptId": format!("github_pr_create_plan:{}", &payload_hash[..16]),
        "evidenceRefs": [
            "github_pr_create_plan",
            "github.pr_create.request_hash",
            "github.pr_create.authority_scope",
            "github.pr_create.dry_run",
            "GitHubPrCreateNode"
        ]
    });
    let mut output = plan.clone();
    if let Some(object) = output.as_object_mut() {
        object.insert("githubPrCreatePlan".to_string(), plan);
    }
    Ok(output)
}
