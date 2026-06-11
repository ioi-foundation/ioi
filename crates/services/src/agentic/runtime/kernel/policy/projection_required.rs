use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::{
    optional_trimmed, REPOSITORY_WORKFLOW_PROJECTION_REQUIRED_REQUEST_SCHEMA_VERSION,
    REPOSITORY_WORKFLOW_PROJECTION_REQUIRED_RESULT_SCHEMA_VERSION,
    RUNTIME_LIFECYCLE_PROJECTION_REQUIRED_REQUEST_SCHEMA_VERSION,
    RUNTIME_LIFECYCLE_PROJECTION_REQUIRED_RESULT_SCHEMA_VERSION,
    RUNTIME_TOOL_CATALOG_PROJECTION_REQUIRED_REQUEST_SCHEMA_VERSION,
    RUNTIME_TOOL_CATALOG_PROJECTION_REQUIRED_RESULT_SCHEMA_VERSION,
    SKILL_HOOK_REGISTRY_PROJECTION_REQUIRED_REQUEST_SCHEMA_VERSION,
    SKILL_HOOK_REGISTRY_PROJECTION_REQUIRED_RESULT_SCHEMA_VERSION,
};

#[derive(Debug, Clone, PartialEq)]
pub enum SkillHookRegistryProjectionRequiredError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
    MissingField(&'static str),
}

#[derive(Debug, Clone, PartialEq)]
pub enum RepositoryWorkflowProjectionRequiredError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
    MissingField(&'static str),
}

#[derive(Debug, Clone, PartialEq)]
pub enum RuntimeToolCatalogProjectionRequiredError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
    MissingField(&'static str),
}

#[derive(Debug, Clone, PartialEq)]
pub enum RuntimeLifecycleProjectionRequiredError {
    InvalidSchemaVersion {
        expected: &'static str,
        actual: String,
    },
    MissingField(&'static str),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SkillHookRegistryProjectionRequiredRequest {
    pub schema_version: String,
    pub operation: String,
    pub operation_kind: String,
    #[serde(default)]
    pub registry_kind: Option<String>,
    #[serde(default)]
    pub workspace_root: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SkillHookRegistryProjectionRequiredRecord {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub status_code: u16,
    pub code: String,
    pub message: String,
    pub rust_core_boundary: String,
    pub operation: String,
    pub operation_kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry_kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workspace_root: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    pub evidence_refs: Vec<String>,
    pub details: Value,
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RepositoryWorkflowProjectionRequiredRequest {
    pub schema_version: String,
    pub operation: String,
    pub operation_kind: String,
    #[serde(default)]
    pub projection_kind: Option<String>,
    #[serde(default)]
    pub workspace_root: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RepositoryWorkflowProjectionRequiredRecord {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub status_code: u16,
    pub code: String,
    pub message: String,
    pub rust_core_boundary: String,
    pub operation: String,
    pub operation_kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub projection_kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workspace_root: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    pub evidence_refs: Vec<String>,
    pub details: Value,
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeToolCatalogProjectionRequiredRequest {
    pub schema_version: String,
    pub operation: String,
    pub operation_kind: String,
    #[serde(default)]
    pub projection_kind: Option<String>,
    #[serde(default)]
    pub pack: Option<String>,
    #[serde(default)]
    pub workspace_root: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeToolCatalogProjectionRequiredRecord {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub status_code: u16,
    pub code: String,
    pub message: String,
    pub rust_core_boundary: String,
    pub operation: String,
    pub operation_kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub projection_kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pack: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workspace_root: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    pub evidence_refs: Vec<String>,
    pub details: Value,
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeLifecycleProjectionRequiredRequest {
    pub schema_version: String,
    pub operation: String,
    pub operation_kind: String,
    #[serde(default)]
    pub projection_kind: Option<String>,
    #[serde(default)]
    pub agent_id: Option<String>,
    #[serde(default)]
    pub thread_id: Option<String>,
    #[serde(default)]
    pub turn_id: Option<String>,
    #[serde(default)]
    pub run_id: Option<String>,
    #[serde(default)]
    pub artifact_ref: Option<String>,
    #[serde(default)]
    pub workspace_root: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeLifecycleProjectionRequiredRecord {
    pub schema_version: String,
    pub object: String,
    pub status: String,
    pub status_code: u16,
    pub code: String,
    pub message: String,
    pub rust_core_boundary: String,
    pub operation: String,
    pub operation_kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub projection_kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thread_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub turn_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workspace_root: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    pub evidence_refs: Vec<String>,
    pub details: Value,
    pub generated_at: String,
}

#[derive(Debug, Default, Clone)]
pub struct SkillHookRegistryProjectionRequiredCore;

impl SkillHookRegistryProjectionRequiredCore {
    pub fn plan(
        &self,
        request: &SkillHookRegistryProjectionRequiredRequest,
    ) -> Result<SkillHookRegistryProjectionRequiredRecord, SkillHookRegistryProjectionRequiredError>
    {
        request.validate()?;
        let operation = optional_trimmed(Some(request.operation.as_str())).unwrap();
        let operation_kind = optional_trimmed(Some(request.operation_kind.as_str())).unwrap();
        let registry_kind = optional_trimmed(request.registry_kind.as_deref());
        let workspace_root = optional_trimmed(request.workspace_root.as_deref());
        let source = optional_trimmed(request.source.as_deref())
            .or_else(|| Some("rust_skill_hook_registry_projection_required_command".to_string()));
        let evidence_refs = if request.evidence_refs.is_empty() {
            vec![
                "runtime_skill_hook_registry_js_projection_retired".to_string(),
                "rust_daemon_core_skill_hook_registry_required".to_string(),
                "agentgres_skill_hook_registry_truth_required".to_string(),
            ]
        } else {
            request.evidence_refs.clone()
        };
        let details = json!({
            "rust_core_boundary": "runtime.skill_hook_registry",
            "operation": operation,
            "operation_kind": operation_kind,
            "registry_kind": registry_kind,
            "workspace_root": workspace_root,
            "source": source,
            "evidence_refs": evidence_refs,
        });

        Ok(SkillHookRegistryProjectionRequiredRecord {
            schema_version: SKILL_HOOK_REGISTRY_PROJECTION_REQUIRED_RESULT_SCHEMA_VERSION
                .to_string(),
            object: "ioi.runtime_skill_hook_registry_projection_required".to_string(),
            status: "rust_core_required".to_string(),
            status_code: 501,
            code: "runtime_skill_hook_registry_rust_core_required".to_string(),
            message: "Skill and hook registry projection requires direct Rust daemon-core projection over admitted governance/catalog truth.".to_string(),
            rust_core_boundary: "runtime.skill_hook_registry".to_string(),
            operation,
            operation_kind,
            registry_kind,
            workspace_root,
            source,
            evidence_refs,
            details,
            generated_at: "rust_policy_core".to_string(),
        })
    }
}

#[derive(Debug, Default, Clone)]
pub struct RepositoryWorkflowProjectionRequiredCore;

impl RepositoryWorkflowProjectionRequiredCore {
    pub fn plan(
        &self,
        request: &RepositoryWorkflowProjectionRequiredRequest,
    ) -> Result<RepositoryWorkflowProjectionRequiredRecord, RepositoryWorkflowProjectionRequiredError>
    {
        request.validate()?;
        let operation = optional_trimmed(Some(request.operation.as_str())).unwrap();
        let operation_kind = optional_trimmed(Some(request.operation_kind.as_str())).unwrap();
        let projection_kind = optional_trimmed(request.projection_kind.as_deref());
        let workspace_root = optional_trimmed(request.workspace_root.as_deref());
        let source = optional_trimmed(request.source.as_deref())
            .or_else(|| Some("rust_repository_workflow_projection_required_command".to_string()));
        let evidence_refs = if request.evidence_refs.is_empty() {
            vec![
                "runtime_repository_workflow_js_projection_retired".to_string(),
                "rust_daemon_core_repository_workflow_projection_required".to_string(),
                "agentgres_repository_workflow_truth_required".to_string(),
            ]
        } else {
            request.evidence_refs.clone()
        };
        let details = json!({
            "rust_core_boundary": "runtime.repository_workflow_projection",
            "operation": operation,
            "operation_kind": operation_kind,
            "projection_kind": projection_kind,
            "workspace_root": workspace_root,
            "source": source,
            "evidence_refs": evidence_refs,
        });

        Ok(RepositoryWorkflowProjectionRequiredRecord {
            schema_version: REPOSITORY_WORKFLOW_PROJECTION_REQUIRED_RESULT_SCHEMA_VERSION
                .to_string(),
            object: "ioi.runtime_repository_workflow_projection_required".to_string(),
            status: "rust_core_required".to_string(),
            status_code: 501,
            code: "runtime_repository_workflow_projection_rust_core_required".to_string(),
            message: "Repository workflow projection requires direct Rust daemon-core projection over Agentgres-admitted repository workflow truth.".to_string(),
            rust_core_boundary: "runtime.repository_workflow_projection".to_string(),
            operation,
            operation_kind,
            projection_kind,
            workspace_root,
            source,
            evidence_refs,
            details,
            generated_at: "rust_policy_core".to_string(),
        })
    }
}

#[derive(Debug, Default, Clone)]
pub struct RuntimeToolCatalogProjectionRequiredCore;

impl RuntimeToolCatalogProjectionRequiredCore {
    pub fn plan(
        &self,
        request: &RuntimeToolCatalogProjectionRequiredRequest,
    ) -> Result<RuntimeToolCatalogProjectionRequiredRecord, RuntimeToolCatalogProjectionRequiredError>
    {
        request.validate()?;
        let operation = optional_trimmed(Some(request.operation.as_str())).unwrap();
        let operation_kind = optional_trimmed(Some(request.operation_kind.as_str())).unwrap();
        let projection_kind = optional_trimmed(request.projection_kind.as_deref());
        let pack = optional_trimmed(request.pack.as_deref());
        let workspace_root = optional_trimmed(request.workspace_root.as_deref());
        let source = optional_trimmed(request.source.as_deref())
            .or_else(|| Some("rust_runtime_tool_catalog_projection_required_command".to_string()));
        let evidence_refs = if request.evidence_refs.is_empty() {
            vec![
                "runtime_tool_catalog_js_projection_retired".to_string(),
                "rust_daemon_core_runtime_tool_catalog_required".to_string(),
                "agentgres_runtime_tool_catalog_truth_required".to_string(),
            ]
        } else {
            request.evidence_refs.clone()
        };
        let details = json!({
            "rust_core_boundary": "runtime.tool_catalog",
            "operation": operation,
            "operation_kind": operation_kind,
            "projection_kind": projection_kind,
            "pack": pack,
            "workspace_root": workspace_root,
            "source": source,
            "evidence_refs": evidence_refs,
        });

        Ok(RuntimeToolCatalogProjectionRequiredRecord {
            schema_version: RUNTIME_TOOL_CATALOG_PROJECTION_REQUIRED_RESULT_SCHEMA_VERSION
                .to_string(),
            object: "ioi.runtime_tool_catalog_projection_required".to_string(),
            status: "rust_core_required".to_string(),
            status_code: 501,
            code: "runtime_tool_catalog_rust_core_required".to_string(),
            message: "Runtime account, node, and tool catalog projections require direct Rust daemon-core projection over Agentgres-admitted runtime catalog truth.".to_string(),
            rust_core_boundary: "runtime.tool_catalog".to_string(),
            operation,
            operation_kind,
            projection_kind,
            pack,
            workspace_root,
            source,
            evidence_refs,
            details,
            generated_at: "rust_policy_core".to_string(),
        })
    }
}

#[derive(Debug, Default, Clone)]
pub struct RuntimeLifecycleProjectionRequiredCore;

impl RuntimeLifecycleProjectionRequiredCore {
    pub fn plan(
        &self,
        request: &RuntimeLifecycleProjectionRequiredRequest,
    ) -> Result<RuntimeLifecycleProjectionRequiredRecord, RuntimeLifecycleProjectionRequiredError>
    {
        request.validate()?;
        let operation = optional_trimmed(Some(request.operation.as_str())).unwrap();
        let operation_kind = optional_trimmed(Some(request.operation_kind.as_str())).unwrap();
        let projection_kind = optional_trimmed(request.projection_kind.as_deref());
        let agent_id = optional_trimmed(request.agent_id.as_deref());
        let thread_id = optional_trimmed(request.thread_id.as_deref());
        let turn_id = optional_trimmed(request.turn_id.as_deref());
        let run_id = optional_trimmed(request.run_id.as_deref());
        let artifact_ref = optional_trimmed(request.artifact_ref.as_deref());
        let workspace_root = optional_trimmed(request.workspace_root.as_deref());
        let source = optional_trimmed(request.source.as_deref())
            .or_else(|| Some("rust_runtime_lifecycle_projection_required_command".to_string()));
        let evidence_refs = if request.evidence_refs.is_empty() {
            vec![
                "runtime_lifecycle_js_projection_retired".to_string(),
                "rust_daemon_core_runtime_lifecycle_projection_required".to_string(),
                "agentgres_runtime_lifecycle_truth_required".to_string(),
            ]
        } else {
            request.evidence_refs.clone()
        };
        let details = json!({
            "rust_core_boundary": "runtime.lifecycle_projection",
            "operation": operation,
            "operation_kind": operation_kind,
            "projection_kind": projection_kind,
            "agent_id": agent_id,
            "thread_id": thread_id,
            "turn_id": turn_id,
            "run_id": run_id,
            "artifact_ref": artifact_ref,
            "workspace_root": workspace_root,
            "source": source,
            "evidence_refs": evidence_refs,
        });

        Ok(RuntimeLifecycleProjectionRequiredRecord {
            schema_version: RUNTIME_LIFECYCLE_PROJECTION_REQUIRED_RESULT_SCHEMA_VERSION
                .to_string(),
            object: "ioi.runtime_lifecycle_projection_required".to_string(),
            status: "rust_core_required".to_string(),
            status_code: 501,
            code: "runtime_lifecycle_projection_rust_core_required".to_string(),
            message: "Runtime agent, thread, and run lifecycle projections require direct Rust daemon-core projection over Agentgres-admitted lifecycle truth.".to_string(),
            rust_core_boundary: "runtime.lifecycle_projection".to_string(),
            operation,
            operation_kind,
            projection_kind,
            agent_id,
            thread_id,
            turn_id,
            run_id,
            artifact_ref,
            workspace_root,
            source,
            evidence_refs,
            details,
            generated_at: "rust_policy_core".to_string(),
        })
    }
}

impl SkillHookRegistryProjectionRequiredRequest {
    pub fn validate(&self) -> Result<(), SkillHookRegistryProjectionRequiredError> {
        if self.schema_version != SKILL_HOOK_REGISTRY_PROJECTION_REQUIRED_REQUEST_SCHEMA_VERSION {
            return Err(
                SkillHookRegistryProjectionRequiredError::InvalidSchemaVersion {
                    expected: SKILL_HOOK_REGISTRY_PROJECTION_REQUIRED_REQUEST_SCHEMA_VERSION,
                    actual: self.schema_version.clone(),
                },
            );
        }
        if optional_trimmed(Some(self.operation.as_str())).is_none() {
            return Err(SkillHookRegistryProjectionRequiredError::MissingField(
                "operation",
            ));
        }
        if optional_trimmed(Some(self.operation_kind.as_str())).is_none() {
            return Err(SkillHookRegistryProjectionRequiredError::MissingField(
                "operation_kind",
            ));
        }
        Ok(())
    }
}

impl RepositoryWorkflowProjectionRequiredRequest {
    pub fn validate(&self) -> Result<(), RepositoryWorkflowProjectionRequiredError> {
        if self.schema_version != REPOSITORY_WORKFLOW_PROJECTION_REQUIRED_REQUEST_SCHEMA_VERSION {
            return Err(
                RepositoryWorkflowProjectionRequiredError::InvalidSchemaVersion {
                    expected: REPOSITORY_WORKFLOW_PROJECTION_REQUIRED_REQUEST_SCHEMA_VERSION,
                    actual: self.schema_version.clone(),
                },
            );
        }
        if optional_trimmed(Some(self.operation.as_str())).is_none() {
            return Err(RepositoryWorkflowProjectionRequiredError::MissingField(
                "operation",
            ));
        }
        if optional_trimmed(Some(self.operation_kind.as_str())).is_none() {
            return Err(RepositoryWorkflowProjectionRequiredError::MissingField(
                "operation_kind",
            ));
        }
        Ok(())
    }
}

impl RuntimeToolCatalogProjectionRequiredRequest {
    pub fn validate(&self) -> Result<(), RuntimeToolCatalogProjectionRequiredError> {
        if self.schema_version != RUNTIME_TOOL_CATALOG_PROJECTION_REQUIRED_REQUEST_SCHEMA_VERSION {
            return Err(
                RuntimeToolCatalogProjectionRequiredError::InvalidSchemaVersion {
                    expected: RUNTIME_TOOL_CATALOG_PROJECTION_REQUIRED_REQUEST_SCHEMA_VERSION,
                    actual: self.schema_version.clone(),
                },
            );
        }
        if optional_trimmed(Some(self.operation.as_str())).is_none() {
            return Err(RuntimeToolCatalogProjectionRequiredError::MissingField(
                "operation",
            ));
        }
        if optional_trimmed(Some(self.operation_kind.as_str())).is_none() {
            return Err(RuntimeToolCatalogProjectionRequiredError::MissingField(
                "operation_kind",
            ));
        }
        Ok(())
    }
}

impl RuntimeLifecycleProjectionRequiredRequest {
    pub fn validate(&self) -> Result<(), RuntimeLifecycleProjectionRequiredError> {
        if self.schema_version != RUNTIME_LIFECYCLE_PROJECTION_REQUIRED_REQUEST_SCHEMA_VERSION {
            return Err(
                RuntimeLifecycleProjectionRequiredError::InvalidSchemaVersion {
                    expected: RUNTIME_LIFECYCLE_PROJECTION_REQUIRED_REQUEST_SCHEMA_VERSION,
                    actual: self.schema_version.clone(),
                },
            );
        }
        if optional_trimmed(Some(self.operation.as_str())).is_none() {
            return Err(RuntimeLifecycleProjectionRequiredError::MissingField(
                "operation",
            ));
        }
        if optional_trimmed(Some(self.operation_kind.as_str())).is_none() {
            return Err(RuntimeLifecycleProjectionRequiredError::MissingField(
                "operation_kind",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rust_policy_plans_skill_hook_registry_projection_required() {
        let record = SkillHookRegistryProjectionRequiredCore
            .plan(&SkillHookRegistryProjectionRequiredRequest {
                schema_version: SKILL_HOOK_REGISTRY_PROJECTION_REQUIRED_REQUEST_SCHEMA_VERSION
                    .to_string(),
                operation: "skill_hook_registry_skills".to_string(),
                operation_kind: "skill_hook.registry.skills".to_string(),
                registry_kind: Some("skills".to_string()),
                workspace_root: Some("/workspace/project".to_string()),
                source: Some("runtime.skill_hook_surface".to_string()),
                evidence_refs: vec![
                    "runtime_skill_hook_registry_js_projection_retired".to_string(),
                    "rust_daemon_core_skill_hook_registry_required".to_string(),
                    "agentgres_skill_hook_registry_truth_required".to_string(),
                ],
            })
            .expect("skill hook registry projection required");

        assert_eq!(
            record.schema_version,
            SKILL_HOOK_REGISTRY_PROJECTION_REQUIRED_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.status, "rust_core_required");
        assert_eq!(record.status_code, 501);
        assert_eq!(
            record.code,
            "runtime_skill_hook_registry_rust_core_required"
        );
        assert_eq!(record.rust_core_boundary, "runtime.skill_hook_registry");
        assert_eq!(record.operation, "skill_hook_registry_skills");
        assert_eq!(record.operation_kind, "skill_hook.registry.skills");
        assert_eq!(record.details["registry_kind"], "skills");
        assert_eq!(record.details["workspace_root"], "/workspace/project");
        assert!(record.details.get("registryKind").is_none());
        assert!(record.details.get("workspaceRoot").is_none());
    }

    #[test]
    fn rust_policy_plans_repository_workflow_projection_required() {
        let record = RepositoryWorkflowProjectionRequiredCore
            .plan(&RepositoryWorkflowProjectionRequiredRequest {
                schema_version: REPOSITORY_WORKFLOW_PROJECTION_REQUIRED_REQUEST_SCHEMA_VERSION
                    .to_string(),
                operation: "repository_workflow_pr_attempts".to_string(),
                operation_kind: "repository_workflow.projection.pr_attempts".to_string(),
                projection_kind: Some("pr_attempts".to_string()),
                workspace_root: Some("/workspace/project".to_string()),
                source: Some("runtime.repository_surface".to_string()),
                evidence_refs: vec![
                    "runtime_repository_workflow_js_projection_retired".to_string(),
                    "rust_daemon_core_repository_workflow_projection_required".to_string(),
                    "agentgres_repository_workflow_truth_required".to_string(),
                ],
            })
            .expect("repository workflow projection required");

        assert_eq!(
            record.schema_version,
            REPOSITORY_WORKFLOW_PROJECTION_REQUIRED_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.status, "rust_core_required");
        assert_eq!(record.status_code, 501);
        assert_eq!(
            record.code,
            "runtime_repository_workflow_projection_rust_core_required"
        );
        assert_eq!(
            record.rust_core_boundary,
            "runtime.repository_workflow_projection"
        );
        assert_eq!(record.operation, "repository_workflow_pr_attempts");
        assert_eq!(
            record.operation_kind,
            "repository_workflow.projection.pr_attempts"
        );
        assert_eq!(record.details["projection_kind"], "pr_attempts");
        assert_eq!(record.details["workspace_root"], "/workspace/project");
        assert!(record.details.get("projectionKind").is_none());
        assert!(record.details.get("workspaceRoot").is_none());
    }

    #[test]
    fn rust_policy_plans_runtime_tool_catalog_projection_required() {
        let record = RuntimeToolCatalogProjectionRequiredCore
            .plan(&RuntimeToolCatalogProjectionRequiredRequest {
                schema_version: RUNTIME_TOOL_CATALOG_PROJECTION_REQUIRED_REQUEST_SCHEMA_VERSION
                    .to_string(),
                operation: "runtime_tool_catalog".to_string(),
                operation_kind: "runtime.tool_catalog.projection.tools".to_string(),
                projection_kind: Some("tools".to_string()),
                pack: Some("coding".to_string()),
                workspace_root: Some("/workspace/project".to_string()),
                source: Some("runtime.tool_surface".to_string()),
                evidence_refs: vec![
                    "runtime_tool_catalog_js_projection_retired".to_string(),
                    "rust_daemon_core_runtime_tool_catalog_required".to_string(),
                    "agentgres_runtime_tool_catalog_truth_required".to_string(),
                ],
            })
            .expect("runtime tool catalog projection required");

        assert_eq!(
            record.schema_version,
            RUNTIME_TOOL_CATALOG_PROJECTION_REQUIRED_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.status, "rust_core_required");
        assert_eq!(record.status_code, 501);
        assert_eq!(record.code, "runtime_tool_catalog_rust_core_required");
        assert_eq!(record.rust_core_boundary, "runtime.tool_catalog");
        assert_eq!(record.operation, "runtime_tool_catalog");
        assert_eq!(
            record.operation_kind,
            "runtime.tool_catalog.projection.tools"
        );
        assert_eq!(record.details["projection_kind"], "tools");
        assert_eq!(record.details["pack"], "coding");
        assert_eq!(record.details["workspace_root"], "/workspace/project");
        assert!(record.details.get("projectionKind").is_none());
        assert!(record.details.get("workspaceRoot").is_none());
    }

    #[test]
    fn rust_policy_plans_runtime_lifecycle_projection_required() {
        let record = RuntimeLifecycleProjectionRequiredCore
            .plan(&RuntimeLifecycleProjectionRequiredRequest {
                schema_version: RUNTIME_LIFECYCLE_PROJECTION_REQUIRED_REQUEST_SCHEMA_VERSION
                    .to_string(),
                operation: "runtime_lifecycle_projection".to_string(),
                operation_kind: "runtime.lifecycle_projection.agent_runs".to_string(),
                projection_kind: Some("agent_runs".to_string()),
                agent_id: Some("agent_123".to_string()),
                thread_id: Some("thread_123".to_string()),
                turn_id: Some("turn_123".to_string()),
                run_id: Some("run_123".to_string()),
                artifact_ref: Some("artifact_123".to_string()),
                workspace_root: Some("/workspace/project".to_string()),
                source: Some("runtime.lifecycle_projection_surface".to_string()),
                evidence_refs: vec![
                    "runtime_lifecycle_js_projection_retired".to_string(),
                    "rust_daemon_core_runtime_lifecycle_projection_required".to_string(),
                    "agentgres_runtime_lifecycle_truth_required".to_string(),
                ],
            })
            .expect("runtime lifecycle projection required");

        assert_eq!(
            record.schema_version,
            RUNTIME_LIFECYCLE_PROJECTION_REQUIRED_RESULT_SCHEMA_VERSION
        );
        assert_eq!(record.status, "rust_core_required");
        assert_eq!(record.status_code, 501);
        assert_eq!(
            record.code,
            "runtime_lifecycle_projection_rust_core_required"
        );
        assert_eq!(record.rust_core_boundary, "runtime.lifecycle_projection");
        assert_eq!(record.operation, "runtime_lifecycle_projection");
        assert_eq!(
            record.operation_kind,
            "runtime.lifecycle_projection.agent_runs"
        );
        assert_eq!(record.details["projection_kind"], "agent_runs");
        assert_eq!(record.details["agent_id"], "agent_123");
        assert_eq!(record.details["thread_id"], "thread_123");
        assert_eq!(record.details["turn_id"], "turn_123");
        assert_eq!(record.details["run_id"], "run_123");
        assert_eq!(record.details["artifact_ref"], "artifact_123");
        assert_eq!(record.details["workspace_root"], "/workspace/project");
        assert!(record.details.get("projectionKind").is_none());
        assert!(record.details.get("agentId").is_none());
        assert!(record.details.get("threadId").is_none());
        assert!(record.details.get("turnId").is_none());
        assert!(record.details.get("artifactRef").is_none());
        assert!(record.details.get("workspaceRoot").is_none());
    }
}
