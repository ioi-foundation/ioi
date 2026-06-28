//! Hypervisor project-create planner.
//!
//! There was never a JS handler for `POST /v1/hypervisor/projects` — the Hypervisor app
//! (`hypervisorProjectStateModel.ts requestHypervisorProjectCreate`) POSTs a repository-backed
//! create request and normalizes the response as a `HypervisorProjectStateProjection`, but no
//! daemon ever served it. This planner builds the canonical project-state RECORD from the request
//! (pure validation + canonicalization); the daemon persists it and assembles the projection over
//! all projects.
//!
//! The record shape matches `HypervisorProjectStateRecord` in hypervisorProjectStateModel.ts so the
//! app normalizer keeps the daemon-authored values rather than falling back.

use serde_json::{json, Value};

pub const PROJECT_STATE_PROJECTION_SCHEMA_VERSION: &str =
    "ioi.hypervisor.project_state_projection.v1";

pub const PROJECT_BOUNDARY_INVARIANT: &str =
    "Projects are repository-backed work containers. Hypervisor clients inspect project state; Hypervisor Core is runtime/control substrate, not a project; Agentgres admits project truth and storage backends only hold bytes.";

const SOURCES: &[&str] = &["manual_url", "repository_picker"];
const DEFAULT_ADAPTER_PREFERENCE_REF: &str = "code-editor-adapter:embedded_code_editor";

#[derive(Debug, Clone)]
pub struct RuntimeHypervisorProjectCreateError {
    pub status: u16,
    pub code: String,
    pub message: String,
    pub details: Value,
}

impl RuntimeHypervisorProjectCreateError {
    fn new(code: &str, message: String, details: Value) -> Self {
        Self {
            status: 400,
            code: code.to_string(),
            message,
            details,
        }
    }
}

type PlanResult<T> = Result<T, RuntimeHypervisorProjectCreateError>;

#[derive(Default)]
pub struct RuntimeHypervisorProjectCreateCore;

impl RuntimeHypervisorProjectCreateCore {
    /// Validate the create request and build the canonical project-state record.
    pub fn plan(&self, request: &Value, now_iso: &str) -> PlanResult<Value> {
        let repository_url = required_string(request.get("repository_url"), "repository_url")?;
        let project_name = required_string(request.get("project_name"), "project_name")?;
        // `source` is provenance only (not stored): accept manual_url / repository_picker, default
        // manual_url when absent; reject a present-but-unknown value.
        if let Some(source) = optional_value(request.get("source")) {
            if !SOURCES.contains(&source.as_str()) {
                return Err(RuntimeHypervisorProjectCreateError::new(
                    "project_create_source_invalid",
                    "Project create source must be manual_url or repository_picker.".to_string(),
                    json!({ "source": source, "allowed_values": SOURCES }),
                ));
            }
        }
        let environment_class_refs = string_list(request.get("environment_class_refs"));

        let slug = repo_slug(&repository_url)
            .or_else(|| {
                let project_slug = slugify(&project_name);
                if project_slug.is_empty() {
                    None
                } else {
                    Some(project_slug)
                }
            })
            .unwrap_or_else(|| "repository".to_string());
        let project_id = format!("project:{slug}");

        let created_at =
            optional_value(request.get("created_at")).unwrap_or_else(|| now_iso.to_string());

        Ok(json!({
            "project_id": project_id,
            "name": project_name,
            "description": "Repository-backed project admitted by Hypervisor Daemon replay.",
            "repository_url": repository_url,
            "repository_ref": Value::Null,
            "repository_branch": "main",
            "created_at": created_at,
            "environment_class_refs": environment_class_refs,
            "prebuilds_enabled": false,
            "environment": "No environment yet",
            "root_path": format!("/workspace/{slug}"),
            "workspace_ref": format!("workspace://repo/{slug}"),
            "current_session_ref": Value::Null,
            "environment_ref": Value::Null,
            "provider_candidate_ref": Value::Null,
            "adapter_preference_ref": DEFAULT_ADAPTER_PREFERENCE_REF,
            "custody_posture": "local_private",
            "restore_state": "active",
            "agentgres_object_head_ref": format!("agentgres://object-head/{project_id}"),
            "state_root_ref": format!("agentgres://state-root/{project_id}"),
            "artifact_refs": [format!("artifact://project/{slug}/workspace-summary")],
            "archive_ref": format!("artifact://agentgres/archive/{slug}/latest"),
            "restore_ref": format!("agentgres://restore/{slug}/latest"),
            "latest_receipt_refs": [format!("receipt://project/{slug}/state")],
        }))
    }
}

fn required_string(value: Option<&Value>, field: &str) -> PlanResult<String> {
    optional_value(value).ok_or_else(|| {
        RuntimeHypervisorProjectCreateError::new(
            &format!("project_create_{field}_required"),
            format!("Project create requires {field}."),
            json!({ "field": field }),
        )
    })
}

/// Mirror the app normalizer's `stringList`: trimmed non-empty strings, [] otherwise.
fn string_list(value: Option<&Value>) -> Vec<String> {
    let Some(Value::Array(items)) = value else {
        return Vec::new();
    };
    items
        .iter()
        .filter_map(|item| item.as_str())
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(str::to_string)
        .collect()
}

fn optional_value(value: Option<&Value>) -> Option<String> {
    match value {
        Some(Value::String(string)) => {
            let trimmed = string.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        }
        _ => None,
    }
}

/// Derive a project slug from a repository URL's terminal path segment (minus a trailing `.git`).
fn repo_slug(url: &str) -> Option<String> {
    let trimmed = url.trim().trim_end_matches('/');
    let last = trimmed.rsplit('/').next().unwrap_or("");
    let last = last.strip_suffix(".git").unwrap_or(last);
    let slug = slugify(last);
    if slug.is_empty() {
        None
    } else {
        Some(slug)
    }
}

/// Lowercase, collapse runs of chars outside [a-z0-9._-] to a single `-`, trim `-`.
fn slugify(value: &str) -> String {
    let lowered = value.to_lowercase();
    let mut out = String::with_capacity(lowered.len());
    let mut in_run = false;
    for ch in lowered.chars() {
        if ch.is_ascii_lowercase() || ch.is_ascii_digit() || matches!(ch, '.' | '_' | '-') {
            out.push(ch);
            in_run = false;
        } else if !in_run {
            out.push('-');
            in_run = true;
        }
    }
    out.trim_matches('-').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_project_record_from_repo_url() {
        let record = RuntimeHypervisorProjectCreateCore
            .plan(
                &json!({
                    "repository_url": "https://github.com/teamioitest/ioi",
                    "project_name": "ioi",
                    "source": "manual_url",
                    "environment_class_refs": ["environment-class:local-dev-replay"],
                }),
                "2026-06-22T00:00:00.000Z",
            )
            .expect("planned");
        assert_eq!(record["project_id"], "project:ioi");
        assert_eq!(record["name"], "ioi");
        assert_eq!(
            record["repository_url"],
            "https://github.com/teamioitest/ioi"
        );
        assert_eq!(record["repository_branch"], "main");
        assert_eq!(record["root_path"], "/workspace/ioi");
        assert_eq!(record["workspace_ref"], "workspace://repo/ioi");
        assert_eq!(record["restore_state"], "active");
        assert_eq!(record["created_at"], "2026-06-22T00:00:00.000Z");
        assert_eq!(
            record["environment_class_refs"],
            json!(["environment-class:local-dev-replay"])
        );
        assert_eq!(
            record["agentgres_object_head_ref"],
            "agentgres://object-head/project:ioi"
        );
    }

    #[test]
    fn strips_dot_git_and_trailing_slash() {
        let record = RuntimeHypervisorProjectCreateCore
            .plan(&json!({ "repository_url": "https://github.com/x/My-Repo.git/", "project_name": "X" }), "now")
            .expect("planned");
        assert_eq!(record["project_id"], "project:my-repo");
    }

    #[test]
    fn falls_back_to_project_name_slug() {
        // A degenerate URL with no usable terminal segment falls back to the project-name slug.
        let record = RuntimeHypervisorProjectCreateCore
            .plan(
                &json!({ "repository_url": "/", "project_name": "Cool Project" }),
                "now",
            )
            .expect("planned");
        assert_eq!(record["project_id"], "project:cool-project");
    }

    #[test]
    fn host_only_url_uses_host_slug() {
        let record = RuntimeHypervisorProjectCreateCore
            .plan(
                &json!({ "repository_url": "https://example.com/", "project_name": "Cool" }),
                "now",
            )
            .expect("planned");
        assert_eq!(record["project_id"], "project:example.com");
    }

    #[test]
    fn requires_repository_url() {
        let error = RuntimeHypervisorProjectCreateCore
            .plan(&json!({ "project_name": "ioi" }), "now")
            .expect_err("blocked");
        assert_eq!(error.status, 400);
        assert_eq!(error.code, "project_create_repository_url_required");
    }

    #[test]
    fn requires_project_name() {
        let error = RuntimeHypervisorProjectCreateCore
            .plan(&json!({ "repository_url": "https://x/y" }), "now")
            .expect_err("blocked");
        assert_eq!(error.code, "project_create_project_name_required");
    }

    #[test]
    fn rejects_unknown_source() {
        let error = RuntimeHypervisorProjectCreateCore
            .plan(
                &json!({ "repository_url": "https://x/y", "project_name": "y", "source": "nope" }),
                "now",
            )
            .expect_err("blocked");
        assert_eq!(error.code, "project_create_source_invalid");
    }
}
