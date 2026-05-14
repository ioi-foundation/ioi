use super::explorer::inspect_git;
use super::ids::{now_ms, slugify_workflow_name};
use super::types::{
    WorkflowProject, WorkflowProjectMetadata, WorkflowTestAssertion, WorkflowTestCase,
};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

pub(super) fn default_workflow_project(
    name: &str,
    workflow_kind: &str,
    execution_mode: &str,
    workflow_path: &Path,
) -> WorkflowProject {
    let slug = slugify_workflow_name(name);
    let timestamp = now_ms();
    WorkflowProject {
        version: "workflow.v1".to_string(),
        metadata: WorkflowProjectMetadata {
            id: slug.clone(),
            name: name.trim().to_string(),
            slug,
            workflow_kind: workflow_kind.to_string(),
            execution_mode: execution_mode.to_string(),
            git_location: Some(workflow_path.display().to_string()),
            branch: inspect_git(
                &workflow_path
                    .parent()
                    .and_then(|path| path.parent())
                    .and_then(|path| path.parent())
                    .map(Path::to_path_buf)
                    .unwrap_or_else(|| PathBuf::from(".")),
            )
            .branch,
            dirty: Some(false),
            read_only: Some(false),
            harness: None,
            worker_harness_binding: None,
            created_at_ms: Some(timestamp),
            updated_at_ms: Some(timestamp),
        },
        nodes: Vec::new(),
        edges: Vec::new(),
        global_config: json!({
            "env": "{}",
            "environmentProfile": {
                "target": "local",
                "credentialScope": "local",
                "mockBindingPolicy": "block"
            },
            "modelBindings": {
                "reasoning": { "modelId": "", "required": false },
                "vision": { "modelId": "", "required": false },
                "embedding": { "modelId": "", "required": false },
                "image": { "modelId": "", "required": false }
            },
            "requiredCapabilities": {
                "reasoning": { "required": false, "bindingKey": "reasoning" },
                "vision": { "required": false, "bindingKey": "vision" },
                "embedding": { "required": false, "bindingKey": "embedding" },
                "image": { "required": false, "bindingKey": "image" },
                "speech": { "required": false },
                "video": { "required": false }
            },
            "policy": { "maxBudget": 5, "maxSteps": 50, "timeoutMs": 30000 },
            "contract": { "developerBond": 0, "adjudicationRubric": "" },
            "meta": {
                "name": name,
                "description": "Git-backed visual workflow."
            },
            "production": {
                "errorWorkflowPath": "",
                "evaluationSetPath": "",
                "expectedTimeSavedMinutes": 0,
                "mcpAccessReviewed": false
            }
        }),
    }
}

pub(super) fn default_workflow_tests() -> Vec<WorkflowTestCase> {
    Vec::new()
}

pub(super) fn workflow_node(
    id: &str,
    node_type: &str,
    name: &str,
    x: i64,
    y: i64,
    metric_label: &str,
    metric_value: &str,
) -> Value {
    let (inputs, outputs, io_types) = match node_type {
        "source" => (
            json!([]),
            json!(["output"]),
            json!({ "in": "none", "out": "payload" }),
        ),
        "trigger" => (
            json!([]),
            json!(["output"]),
            json!({ "in": "none", "out": "payload" }),
        ),
        "model_binding" => (
            json!([]),
            json!(["model"]),
            json!({ "in": "none", "out": "model" }),
        ),
        "model_call" => (
            json!(["input", "context", "model", "memory", "tool", "parser"]),
            json!(["output", "error", "retry"]),
            json!({ "in": "prompt", "out": "message" }),
        ),
        "skill_context" => (
            json!(["input"]),
            json!(["output", "error"]),
            json!({ "in": "payload", "out": "payload" }),
        ),
        "workflow_package_export" => (
            json!(["workflow"]),
            json!(["package", "manifest", "readiness", "locale"]),
            json!({ "in": "state", "out": "output_bundle" }),
        ),
        "workflow_package_import" => (
            json!(["package"]),
            json!(["review", "imported_workflow", "evidence", "locale"]),
            json!({ "in": "output_bundle", "out": "state" }),
        ),
        "repository_context" => (
            json!([]),
            json!(["repository"]),
            json!({ "in": "none", "out": "state" }),
        ),
        "branch_policy" => (
            json!(["repository"]),
            json!(["branch_policy"]),
            json!({ "in": "state", "out": "state" }),
        ),
        "github_context" => (
            json!(["repository", "branch_policy"]),
            json!(["github_context"]),
            json!({ "in": "state", "out": "state" }),
        ),
        "issue_context" => (
            json!(["github_context"]),
            json!(["issue_context"]),
            json!({ "in": "state", "out": "state" }),
        ),
        "pr_attempt" => (
            json!([
                "repository",
                "branch_policy",
                "github_context",
                "issue_context"
            ]),
            json!(["pr_attempt"]),
            json!({ "in": "state", "out": "state" }),
        ),
        "review_gate" => (
            json!([
                "repository",
                "branch_policy",
                "github_context",
                "issue_context",
                "pr_attempt"
            ]),
            json!(["review_gate"]),
            json!({ "in": "state", "out": "approval" }),
        ),
        "github_pr_create" => (
            json!([
                "repository",
                "branch_policy",
                "github_context",
                "issue_context",
                "pr_attempt",
                "review_gate"
            ]),
            json!(["plan", "blockers", "request"]),
            json!({ "in": "approval", "out": "approval" }),
        ),
        "parser" => (
            json!([]),
            json!(["parser"]),
            json!({ "in": "none", "out": "parser" }),
        ),
        "adapter" => (
            json!(["input", "context"]),
            json!(["output", "error", "retry"]),
            json!({ "in": "request", "out": "response" }),
        ),
        "plugin_tool" => (
            json!(["input", "context"]),
            json!(["output", "tool", "error"]),
            json!({ "in": "args", "out": "result" }),
        ),
        "decision" => (
            json!(["input", "context"]),
            json!(["left", "right", "error"]),
            json!({ "in": "payload", "out": "branch" }),
        ),
        "state" => (
            json!(["input", "context"]),
            json!(["output", "memory", "error"]),
            json!({ "in": "payload", "out": "state" }),
        ),
        "loop" => (
            json!(["input", "context"]),
            json!(["output", "retry", "error"]),
            json!({ "in": "payload", "out": "branch" }),
        ),
        "barrier" => (
            json!(["left", "right"]),
            json!(["output", "error"]),
            json!({ "in": "payload", "out": "payload" }),
        ),
        "subgraph" => (
            json!(["input", "context"]),
            json!(["output", "tool", "error"]),
            json!({ "in": "payload", "out": "run" }),
        ),
        "human_gate" => (
            json!(["approval"]),
            json!(["output", "error"]),
            json!({ "in": "request", "out": "decision" }),
        ),
        "output" => (
            json!(["input"]),
            json!([]),
            json!({ "in": "payload", "out": "output_bundle" }),
        ),
        "proposal" => (
            json!(["input"]),
            json!(["output", "approval", "error"]),
            json!({ "in": "payload", "out": "proposal" }),
        ),
        _ => (
            json!(["input"]),
            json!(["output", "error"]),
            json!({ "in": "payload", "out": "payload" }),
        ),
    };

    let logic = match node_type {
        "source" if metric_value == "image" => json!({
            "sourceKind": "media",
            "sourcePath": "input.jpg",
            "fileExtension": "jpg",
            "mediaKind": "image",
            "mimeType": "image/jpeg",
            "sanitizeInput": true,
            "validateMime": true,
            "stripMetadata": true,
            "payload": {
                "file": "input.jpg",
                "mediaKind": "image",
                "extension": "jpg"
            },
            "schema": { "type": "object" }
        }),
        "source" => json!({
            "sourceKind": "manual",
            "payload": { "request": format!("Provide input for {}.", name) },
            "schema": { "type": "object" }
        }),
        "trigger" => json!({
            "triggerKind": "manual",
            "cronSchedule": "",
            "eventSourceRef": "",
            "dedupeKey": ""
        }),
        "repository_context" => json!({
            "repositoryContextEndpoint": "runtime.repositoryContext",
            "repoFullName": "ioi-test/ioi",
            "branch": "feature/runtime-pr-plan",
            "defaultBranch": "main",
            "dirty": false,
            "readOnly": true,
            "mutationExecuted": false,
            "redactionProfile": "repository_context_safe"
        }),
        "branch_policy" => json!({
            "branchPolicyEndpoint": "runtime.branchPolicy",
            "allowDirtyWorktree": true,
            "blockProtectedBranches": false,
            "protectedBranches": ["main"],
            "mutationExecuted": false,
            "redactionProfile": "branch_policy_safe"
        }),
        "github_context" => json!({
            "githubContextEndpoint": "runtime.githubContext",
            "repoFullName": "ioi-test/ioi",
            "tokenAvailable": false,
            "networkLookupPerformed": false,
            "mutationExecuted": false,
            "redactionProfile": "github_context_safe"
        }),
        "issue_context" => json!({
            "issueContextEndpoint": "runtime.issueContext",
            "issueNumber": Value::Null,
            "networkLookupPerformed": false,
            "mutationExecuted": false,
            "redactionProfile": "issue_context_safe"
        }),
        "pr_attempt" => json!({
            "prAttemptEndpoint": "runtime.prAttempt",
            "title": "Draft PR for feature/runtime-pr-plan",
            "baseBranch": "main",
            "headBranch": "feature/runtime-pr-plan",
            "diffArtifactAttached": true,
            "branchArtifactAttached": true,
            "dryRun": true,
            "mutationExecuted": false,
            "redactionProfile": "pr_attempt_safe"
        }),
        "review_gate" => json!({
            "reviewGateEndpoint": "runtime.reviewGate",
            "reviewSatisfied": false,
            "dryRun": true,
            "mutationExecuted": false,
            "redactionProfile": "review_gate_safe"
        }),
        "github_pr_create" => json!({
            "githubPrCreatePlanEndpoint": "runtime.githubPrCreatePlan",
            "githubPrCreatePlanField": "githubPrCreatePlan",
            "dryRun": true,
            "previewOnly": true,
            "mutationExecuted": false,
            "networkLookupPerformed": false,
            "redactionProfile": "github_pr_create_plan_safe",
            "outputSchema": workflow_github_pr_create_output_schema()
        }),
        "model_call" => json!({
            "modelRef": if metric_value == "vision" { "vision" } else { "reasoning" },
            "prompt": format!("Run the {} step.", name)
        }),
        "skill_context" => json!({
            "skillContext": {
                "mode": "discover",
                "goalSource": "node_input",
                "goal": "",
                "minScoreBps": 6500,
                "maxSkills": 3,
                "onNoMatch": "warn",
                "pinnedSkills": [],
                "onMissingPinned": "block",
                "includeMarkdown": true,
                "guidanceMaxChars": 1800
            },
            "outputSchema": workflow_skill_context_output_schema()
        }),
        "workflow_package_export" => json!({
            "workflowPackageExportEndpoint": "runtime.exportWorkflowPackage",
            "workflowPackageExportField": "workflowPackageExport",
            "workflowPackagePath": "{{workflow.path}}",
            "workflowPackageOutputDir": "",
            "workflowPackageManifestField": "workflowPackageExport.manifest",
            "workflowPackageReadinessStatusField": "workflowPackageExport.manifest.readinessStatus",
            "workflowPackagePortableField": "workflowPackageExport.manifest.portable",
            "workflowPackageLocaleField": "workflowPackageExport.manifest.workflowChromeLocale",
            "workflowPackageEvidenceReadyField": "workflowPackageExport.manifest.harnessPackageManifest",
            "dryRun": false,
            "mutationExecuted": true,
            "outputSchema": workflow_package_export_output_schema()
        }),
        "workflow_package_import" => json!({
            "workflowPackageImportEndpoint": "runtime.importWorkflowPackage",
            "workflowPackagePath": "{{workflowPackageExport.packagePath}}",
            "workflowPackageProjectRoot": "{{project.root}}",
            "workflowPackageImportName": "",
            "workflowPackageImportField": "workflowPackageImport",
            "workflowPackageImportReviewField": "workflowPackageImportReview",
            "workflowPackageImportEvidenceReadyField": "workflowPackageImportReview.evidence.packageEvidenceReady",
            "workflowPackageImportLocalePreservedField": "workflowPackageImportReview.evidence.workflowChromeLocalePreserved",
            "workflowPackageImportedWorkflowPathField": "workflowPackageImport.imported.workflowPath",
            "dryRun": false,
            "mutationExecuted": true,
            "outputSchema": workflow_package_import_output_schema()
        }),
        "model_binding" => json!({
            "modelRef": if metric_value == "vision" { "vision" } else { "reasoning" },
            "modelBinding": {
                "modelRef": if metric_value == "vision" { "vision" } else { "reasoning" },
                "mockBinding": true,
                "capabilityScope": [if metric_value == "vision" { "vision" } else { "reasoning" }],
                "argumentSchema": { "type": "object" },
                "resultSchema": { "type": "object" },
                "sideEffectClass": "none",
                "requiresApproval": false,
                "credentialReady": false,
                "toolUseMode": "none"
            }
        }),
        "parser" => json!({
            "parserRef": "json_schema",
            "parserBinding": {
                "parserRef": "json_schema",
                "parserKind": "json_schema",
                "resultSchema": { "type": "object" },
                "mockBinding": true
            },
            "outputSchema": { "type": "object" }
        }),
        "adapter" => json!({
            "connectorBinding": {
                "connectorRef": metric_value,
                "mockBinding": true,
                "credentialReady": false,
                "capabilityScope": ["read"],
                "sideEffectClass": "none",
                "requiresApproval": false,
                "operation": "read"
            }
        }),
        "plugin_tool" => json!({
            "toolBinding": {
                "toolRef": metric_value,
                "bindingKind": "plugin_tool",
                "mockBinding": true,
                "credentialReady": false,
                "capabilityScope": ["read"],
                "sideEffectClass": "read",
                "requiresApproval": false,
                "arguments": {}
            }
        }),
        "function" => json!({
            "language": "javascript",
            "code": "return { result: input };",
            "outputSchema": { "type": "object" },
            "functionBinding": {
                "language": "javascript",
                "code": "return { result: input };",
                "outputSchema": { "type": "object" },
                "sandboxPolicy": {
                    "timeoutMs": 1000,
                    "memoryMb": 64,
                    "outputLimitBytes": 32768,
                    "permissions": []
                },
                "testInput": { "payload": "sample" }
            }
        }),
        "decision" => json!({
            "routes": ["left", "right"],
            "routerInstruction": format!("Route the result for {}.", name)
        }),
        "state" => json!({
            "stateKey": "memory",
            "stateOperation": "merge",
            "reducer": "merge",
            "initialValue": {}
        }),
        "loop" => json!({
            "loopCondition": "return input.iteration < 3;",
            "maxIterations": 3
        }),
        "barrier" => json!({
            "barrierStrategy": "all"
        }),
        "subgraph" => json!({
            "subgraphRef": { "workflowPath": "" }
        }),
        "output" => json!({
            "format": "markdown",
            "rendererRef": { "rendererId": "markdown", "displayMode": "inline" },
            "materialization": { "enabled": false },
            "deliveryTarget": { "targetKind": "none" },
            "retentionPolicy": { "retentionKind": "run_scoped" },
            "versioning": { "enabled": true }
        }),
        "proposal" => json!({
            "proposalAction": {
                "actionKind": "create",
                "boundedTargets": [],
                "requiresApproval": true
            }
        }),
        _ => json!({ "variables": {} }),
    };

    let law = if node_type == "human_gate" {
        json!({ "requireHumanGate": true })
    } else if node_type == "proposal" {
        json!({
            "requireHumanGate": true,
            "privilegedActions": ["bounded_self_mutation"]
        })
    } else if node_type == "function" {
        json!({
            "sandboxPolicy": {
                "timeoutMs": 1000,
                "memoryMb": 64,
                "outputLimitBytes": 32768,
                "permissions": []
            }
        })
    } else {
        json!({})
    };

    json!({
        "id": id,
        "type": node_type,
        "name": name,
        "x": x,
        "y": y,
        "metricLabel": metric_label,
        "metricValue": metric_value,
        "ioTypes": io_types,
        "inputs": inputs,
        "outputs": outputs,
        "config": { "kind": node_type, "logic": logic, "law": law }
    })
}

pub(super) fn canonical_workflow_node_types() -> Vec<(&'static str, &'static str, &'static str)> {
    vec![
        ("source", "Sources", "Source/Input"),
        ("trigger", "Triggers", "Trigger"),
        ("function", "Functions", "Function"),
        ("model_binding", "Models", "Model Binding"),
        ("model_call", "Models", "Model"),
        ("skill_context", "Context", "Skill Context"),
        (
            "workflow_package_export",
            "Tools",
            "Workflow Package Export",
        ),
        (
            "workflow_package_import",
            "Tools",
            "Workflow Package Import",
        ),
        ("runtime_thread_fork", "Runtime", "Thread Fork"),
        (
            "runtime_operator_interrupt",
            "Runtime",
            "Operator Interrupt",
        ),
        ("runtime_operator_steer", "Runtime", "Operator Steer"),
        ("runtime_thread_mode", "Runtime", "Thread Mode"),
        ("runtime_context_compact", "Runtime", "Context Compact"),
        ("runtime_approval_request", "Runtime", "Approval Request"),
        ("runtime_rollback_snapshot", "Runtime", "Rollback Snapshot"),
        ("runtime_restore_gate", "Runtime", "Restore Gate"),
        ("repository_context", "Context", "Repository Context"),
        ("branch_policy", "Policy", "Branch Policy"),
        ("github_context", "Context", "GitHub Context"),
        ("issue_context", "Context", "Issue Context"),
        ("pr_attempt", "Tools", "PR Attempt"),
        ("review_gate", "Gates", "Review Gate"),
        ("github_pr_create", "Tools", "GitHub PR Create"),
        ("parser", "Models", "Output Parser"),
        ("adapter", "Connectors", "Adapter"),
        ("plugin_tool", "Tools", "Plugin Tool"),
        ("state", "State", "State"),
        ("decision", "Flow Control", "Decision"),
        ("loop", "Flow Control", "Loop"),
        ("barrier", "Flow Control", "Barrier"),
        ("subgraph", "Subgraphs", "Subgraph"),
        ("human_gate", "Gates", "Human Gate"),
        ("output", "Outputs", "Output"),
        ("test_assertion", "Tests", "Test Assertion"),
        ("proposal", "Proposals", "Proposal"),
    ]
}

pub(super) fn workflow_skill_context_output_schema() -> Value {
    json!({
        "type": "object",
        "required": [
            "schemaVersion",
            "status",
            "mode",
            "selectedSkills",
            "promptContext",
            "evidenceRefs"
        ],
        "properties": {
            "schemaVersion": { "type": "string" },
            "status": { "type": "string" },
            "mode": { "type": "string" },
            "goal": { "type": "string" },
            "selectedSkills": { "type": "array" },
            "promptContext": { "type": "string" },
            "evidenceRefs": { "type": "array" }
        }
    })
}

pub(super) fn workflow_package_export_output_schema() -> Value {
    json!({
        "type": "object",
        "required": [
            "schemaVersion",
            "status",
            "toolName",
            "packagePath",
            "manifest",
            "portable",
            "readinessStatus",
            "workflowChromeLocale",
            "packageEvidenceReady"
        ],
        "properties": {
            "workflowPackageExport": { "type": "object" },
            "manifest": { "type": "object" },
            "packagePath": { "type": "string" },
            "portable": { "type": "boolean" },
            "readinessStatus": { "type": "string" },
            "workflowChromeLocale": { "type": ["string", "null"] },
            "packageEvidenceReady": { "type": "boolean" }
        }
    })
}

pub(super) fn workflow_package_import_output_schema() -> Value {
    json!({
        "type": "object",
        "required": [
            "schemaVersion",
            "status",
            "toolName",
            "packagePath",
            "importedWorkflowPath",
            "review",
            "packageEvidenceReady",
            "workflowChromeLocalePreserved"
        ],
        "properties": {
            "workflowPackageImport": { "type": "object" },
            "workflowPackageImportReview": { "type": "object" },
            "review": { "type": "object" },
            "packagePath": { "type": "string" },
            "importedWorkflowPath": { "type": "string" },
            "packageEvidenceReady": { "type": "boolean" },
            "workflowChromeLocalePreserved": { "type": "boolean" },
            "sourceWorkflowChromeLocale": { "type": ["string", "null"] },
            "importedWorkflowChromeLocale": { "type": ["string", "null"] }
        }
    })
}

pub(super) fn workflow_runtime_thread_fork_output_schema() -> Value {
    json!({
        "type": "object",
        "required": [
            "schemaVersion",
            "status",
            "source",
            "componentKind",
            "workflowNodeId",
            "request"
        ],
        "properties": {
            "schemaVersion": { "type": "string" },
            "status": { "type": "string" },
            "source": { "type": "string" },
            "componentKind": { "type": "string" },
            "workflowGraphId": { "type": ["string", "null"] },
            "workflowNodeId": { "type": "string" },
            "threadId": { "type": "string" },
            "endpoint": { "type": "string" },
            "request": { "type": "object" },
            "runtimeThreadFork": { "type": "object" }
        }
    })
}

pub(super) fn workflow_runtime_operator_interrupt_output_schema() -> Value {
    json!({
        "type": "object",
        "required": [
            "schemaVersion",
            "status",
            "source",
            "componentKind",
            "workflowNodeId",
            "request"
        ],
        "properties": {
            "schemaVersion": { "type": "string" },
            "status": { "type": "string" },
            "source": { "type": "string" },
            "componentKind": { "type": "string" },
            "workflowGraphId": { "type": ["string", "null"] },
            "workflowNodeId": { "type": "string" },
            "threadId": { "type": "string" },
            "turnId": { "type": "string" },
            "endpoint": { "type": "string" },
            "request": { "type": "object" },
            "runtimeOperatorInterrupt": { "type": "object" }
        }
    })
}

pub(super) fn workflow_runtime_operator_steer_output_schema() -> Value {
    json!({
        "type": "object",
        "required": [
            "schemaVersion",
            "status",
            "source",
            "componentKind",
            "workflowNodeId",
            "request"
        ],
        "properties": {
            "schemaVersion": { "type": "string" },
            "status": { "type": "string" },
            "source": { "type": "string" },
            "componentKind": { "type": "string" },
            "workflowGraphId": { "type": ["string", "null"] },
            "workflowNodeId": { "type": "string" },
            "threadId": { "type": "string" },
            "turnId": { "type": "string" },
            "endpoint": { "type": "string" },
            "request": { "type": "object" },
            "runtimeOperatorSteer": { "type": "object" }
        }
    })
}

pub(super) fn workflow_runtime_context_compact_output_schema() -> Value {
    json!({
        "type": "object",
        "required": [
            "schemaVersion",
            "status",
            "source",
            "componentKind",
            "workflowNodeId",
            "request"
        ],
        "properties": {
            "schemaVersion": { "type": "string" },
            "status": { "type": "string" },
            "source": { "type": "string" },
            "componentKind": { "type": "string" },
            "workflowGraphId": { "type": ["string", "null"] },
            "workflowNodeId": { "type": "string" },
            "threadId": { "type": "string" },
            "turnId": { "type": ["string", "null"] },
            "endpoint": { "type": "string" },
            "request": { "type": "object" },
            "runtimeContextCompact": { "type": "object" }
        }
    })
}

pub(super) fn workflow_runtime_thread_mode_output_schema() -> Value {
    json!({
        "type": "object",
        "required": [
            "schemaVersion",
            "status",
            "source",
            "componentKind",
            "workflowNodeId",
            "request"
        ],
        "properties": {
            "schemaVersion": { "type": "string" },
            "status": { "type": "string" },
            "source": { "type": "string" },
            "componentKind": { "type": "string" },
            "workflowGraphId": { "type": ["string", "null"] },
            "workflowNodeId": { "type": "string" },
            "threadId": { "type": "string" },
            "mode": { "type": "string" },
            "approvalMode": { "type": "string" },
            "endpoint": { "type": "string" },
            "request": { "type": "object" },
            "runtimeThreadMode": { "type": "object" }
        }
    })
}

pub(super) fn workflow_runtime_approval_request_output_schema() -> Value {
    json!({
        "type": "object",
        "required": [
            "schemaVersion",
            "status",
            "source",
            "componentKind",
            "workflowNodeId",
            "request"
        ],
        "properties": {
            "schemaVersion": { "type": "string" },
            "status": { "type": "string" },
            "source": { "type": "string" },
            "componentKind": { "type": "string" },
            "workflowGraphId": { "type": ["string", "null"] },
            "workflowNodeId": { "type": "string" },
            "threadId": { "type": "string" },
            "turnId": { "type": ["string", "null"] },
            "approvalId": { "type": "string" },
            "endpoint": { "type": "string" },
            "request": { "type": "object" },
            "runtimeApprovalRequest": { "type": "object" }
        }
    })
}

pub(super) fn workflow_runtime_rollback_snapshot_output_schema() -> Value {
    json!({
        "type": "object",
        "required": [
            "schemaVersion",
            "status",
            "source",
            "componentKind",
            "workflowNodeId",
            "request"
        ],
        "properties": {
            "schemaVersion": { "type": "string" },
            "status": { "type": "string" },
            "source": { "type": "string" },
            "componentKind": { "type": "string" },
            "workflowGraphId": { "type": ["string", "null"] },
            "workflowNodeId": { "type": "string" },
            "threadId": { "type": "string" },
            "endpoint": { "type": "string" },
            "request": { "type": "object" },
            "runtimeRollbackSnapshot": { "type": "object" }
        }
    })
}

pub(super) fn workflow_runtime_restore_gate_output_schema() -> Value {
    json!({
        "type": "object",
        "required": [
            "schemaVersion",
            "status",
            "source",
            "componentKind",
            "workflowNodeId",
            "snapshotId",
            "mode",
            "request"
        ],
        "properties": {
            "schemaVersion": { "type": "string" },
            "status": { "type": "string" },
            "source": { "type": "string" },
            "componentKind": { "type": "string" },
            "workflowGraphId": { "type": ["string", "null"] },
            "workflowNodeId": { "type": "string" },
            "threadId": { "type": "string" },
            "snapshotId": { "type": "string" },
            "mode": { "type": "string" },
            "conflictPolicy": { "type": "string" },
            "approvalGranted": { "type": "boolean" },
            "endpoint": { "type": "string" },
            "request": { "type": "object" },
            "runtimeRestoreGate": { "type": "object" }
        }
    })
}

pub(super) fn workflow_github_pr_create_output_schema() -> Value {
    json!({
        "type": "object",
        "required": [
            "schemaVersion",
            "object",
            "status",
            "decision",
            "dryRun",
            "previewOnly",
            "toolName",
            "action",
            "request",
            "authority",
            "blockers",
            "networkLookupPerformed",
            "mutationAttempted",
            "mutationExecuted",
            "redaction"
        ],
        "properties": {
            "schemaVersion": { "type": "string" },
            "object": { "type": "string" },
            "planId": { "type": "string" },
            "status": { "type": "string" },
            "decision": { "type": "string" },
            "dryRun": { "type": "boolean" },
            "previewOnly": { "type": "boolean" },
            "toolName": { "type": "string" },
            "action": { "type": "string" },
            "request": { "type": "object" },
            "authority": { "type": "object" },
            "blockers": { "type": "array" },
            "networkLookupPerformed": { "type": "boolean" },
            "mutationAttempted": { "type": "boolean" },
            "mutationExecuted": { "type": "boolean" },
            "redaction": { "type": "object" },
            "githubPrCreatePlan": { "type": "object" }
        }
    })
}

fn workflow_scaffold(
    scaffold_id: &str,
    node_type: &str,
    group: &str,
    label: &str,
    description: &str,
    metric_label: &str,
    metric_value: &str,
    preset_logic: Value,
    preset_law: Value,
    action_override: Option<Value>,
) -> Value {
    let mut action = workflow_node_action_metadata(node_type);
    if let (Some(action_object), Some(override_object)) = (
        action.as_object_mut(),
        action_override.and_then(|value| value.as_object().cloned()),
    ) {
        for (key, value) in override_object {
            action_object.insert(key, value);
        }
    }
    json!({
        "scaffoldId": scaffold_id,
        "nodeType": node_type,
        "family": group.to_ascii_lowercase().replace(' ', "_"),
        "label": label,
        "description": description,
        "defaultName": label,
        "metricLabel": metric_label,
        "metricValue": metric_value,
        "presetLogic": preset_logic,
        "presetLaw": preset_law,
        "action": action,
    })
}

pub(super) fn workflow_scaffold_definitions() -> Vec<Value> {
    let mut scaffolds = vec![
        workflow_scaffold(
            "workflow.trigger.manual",
            "trigger",
            "Start",
            "Manual trigger",
            "Run on demand from the workbench.",
            "Trigger",
            "manual",
            json!({ "triggerKind": "manual", "runtimeReady": true, "dedupeKey": "" }),
            json!({}),
            None,
        ),
        workflow_scaffold(
            "workflow.trigger.scheduled",
            "trigger",
            "Start",
            "Scheduled trigger",
            "Start from a cron-style schedule.",
            "Trigger",
            "cron",
            json!({ "triggerKind": "scheduled", "cronSchedule": "0 9 * * 1", "runtimeReady": false, "dedupeKey": "{{scheduled_at}}" }),
            json!({}),
            None,
        ),
        workflow_scaffold(
            "workflow.trigger.event",
            "trigger",
            "Start",
            "Event trigger",
            "Start from a connector or app event payload.",
            "Trigger",
            "event",
            json!({ "triggerKind": "event", "eventSourceRef": "", "runtimeReady": false, "dedupeKey": "{{event.id}}" }),
            json!({}),
            None,
        ),
        workflow_scaffold(
            "workflow.source.manual",
            "source",
            "Sources",
            "Manual input",
            "Typed user or prompt payload entered directly into the workflow.",
            "Input",
            "manual",
            json!({ "sourceKind": "manual", "payload": { "request": "Describe the input for this workflow." }, "schema": { "type": "object" } }),
            json!({}),
            None,
        ),
        workflow_scaffold(
            "workflow.source.file",
            "source",
            "Sources",
            "File input",
            "A local file source with extension and MIME validation.",
            "File",
            "selected",
            json!({ "sourceKind": "file", "sourcePath": "", "fileExtension": "", "mimeType": "application/octet-stream", "sanitizeInput": true, "validateMime": true, "payload": { "file": "" }, "schema": { "type": "object" } }),
            json!({}),
            None,
        ),
        workflow_scaffold(
            "workflow.source.media",
            "source",
            "Sources",
            "Media input",
            "Image, audio, video, or document input with extension, MIME, and sanitization controls.",
            "Media",
            "image",
            json!({ "sourceKind": "media", "sourcePath": "input.jpg", "fileExtension": "jpg", "mediaKind": "image", "mimeType": "image/jpeg", "sanitizeInput": true, "validateMime": true, "stripMetadata": true, "payload": { "file": "input.jpg", "mediaKind": "image", "extension": "jpg" }, "schema": { "type": "object" } }),
            json!({}),
            None,
        ),
        workflow_scaffold(
            "workflow.source.dataset",
            "source",
            "Sources",
            "Dataset input",
            "Tabular or JSON collection input with declared schema.",
            "Rows",
            "sample",
            json!({ "sourceKind": "dataset", "mimeType": "application/json", "sanitizeInput": true, "validateMime": true, "payload": { "rows": [], "schema": {} }, "schema": { "type": "object" } }),
            json!({}),
            None,
        ),
        workflow_scaffold(
            "workflow.source.api_payload",
            "source",
            "Sources",
            "API payload input",
            "Structured request body or webhook payload sample.",
            "Payload",
            "json",
            json!({ "sourceKind": "api_payload", "mimeType": "application/json", "sanitizeInput": true, "validateMime": true, "payload": { "body": {} }, "schema": { "type": "object" } }),
            json!({}),
            None,
        ),
        workflow_scaffold(
            "workflow.adapter.read",
            "adapter",
            "Connectors",
            "Connector read",
            "Read from an external connector with explicit mock/live binding.",
            "Connector",
            "read",
            json!({ "connectorBinding": { "connectorRef": "", "mockBinding": true, "credentialReady": false, "capabilityScope": ["read"], "sideEffectClass": "read", "requiresApproval": false, "operation": "read" } }),
            json!({}),
            None,
        ),
        workflow_scaffold(
            "workflow.adapter.write",
            "adapter",
            "Connectors",
            "Connector write",
            "Prepare an external write that requires contextual approval.",
            "Connector",
            "write",
            json!({ "connectorBinding": { "connectorRef": "", "mockBinding": true, "credentialReady": false, "capabilityScope": ["write"], "sideEffectClass": "external_write", "requiresApproval": true, "operation": "write" } }),
            json!({ "requireHumanGate": true, "privilegedActions": ["external_write"] }),
            Some(json!({ "sideEffectClass": "external_write", "requiresApproval": true })),
        ),
        workflow_scaffold(
            "workflow.plugin_tool.plugin",
            "plugin_tool",
            "Tools",
            "Plugin/MCP tool",
            "Call a plugin or MCP tool through an explicit binding.",
            "Tool",
            "tool",
            json!({ "toolBinding": { "toolRef": "", "bindingKind": "plugin_tool", "mockBinding": true, "credentialReady": false, "capabilityScope": ["read"], "sideEffectClass": "read", "requiresApproval": false, "arguments": {} } }),
            json!({}),
            None,
        ),
        workflow_scaffold(
            "workflow.plugin_tool.workflow_tool",
            "plugin_tool",
            "Tools",
            "Workflow tool",
            "Call another workflow as a schema-bound tool.",
            "Tool",
            "subflow",
            json!({ "toolBinding": { "toolRef": "", "bindingKind": "workflow_tool", "mockBinding": true, "credentialReady": true, "capabilityScope": ["workflow_tool"], "sideEffectClass": "none", "requiresApproval": false, "workflowTool": { "workflowPath": "", "argumentSchema": { "type": "object" }, "resultSchema": { "type": "object" }, "timeoutMs": 30000, "maxAttempts": 1 } } }),
            json!({}),
            None,
        ),
        workflow_scaffold(
            "workflow.workflow_package_export",
            "workflow_package_export",
            "Tools",
            "Workflow package export",
            "Export the current workflow bundle as a portable package.",
            "Package",
            "export",
            json!({ "workflowPackageExportEndpoint": "runtime.exportWorkflowPackage", "workflowPackageExportField": "workflowPackageExport", "workflowPackagePath": "{{workflow.path}}", "workflowPackageOutputDir": "", "workflowPackageManifestField": "workflowPackageExport.manifest", "workflowPackageReadinessStatusField": "workflowPackageExport.manifest.readinessStatus", "workflowPackagePortableField": "workflowPackageExport.manifest.portable", "workflowPackageLocaleField": "workflowPackageExport.manifest.workflowChromeLocale", "workflowPackageEvidenceReadyField": "workflowPackageExport.manifest.harnessPackageManifest", "dryRun": false, "mutationExecuted": true, "outputSchema": workflow_package_export_output_schema() }),
            json!({ "privilegedActions": ["workflow.package.export"] }),
            Some(json!({ "sideEffectClass": "write", "requiresApproval": false })),
        ),
        workflow_scaffold(
            "workflow.workflow_package_import",
            "workflow_package_import",
            "Tools",
            "Workflow package import",
            "Import a portable workflow package and expose package review evidence.",
            "Package",
            "import",
            json!({ "workflowPackageImportEndpoint": "runtime.importWorkflowPackage", "workflowPackagePath": "{{workflowPackageExport.packagePath}}", "workflowPackageProjectRoot": "{{project.root}}", "workflowPackageImportName": "", "workflowPackageImportField": "workflowPackageImport", "workflowPackageImportReviewField": "workflowPackageImportReview", "workflowPackageImportEvidenceReadyField": "workflowPackageImportReview.evidence.packageEvidenceReady", "workflowPackageImportLocalePreservedField": "workflowPackageImportReview.evidence.workflowChromeLocalePreserved", "workflowPackageImportedWorkflowPathField": "workflowPackageImport.imported.workflowPath", "dryRun": false, "mutationExecuted": true, "outputSchema": workflow_package_import_output_schema() }),
            json!({ "requireHumanGate": true, "privilegedActions": ["workflow.package.import"] }),
            Some(json!({ "sideEffectClass": "write", "requiresApproval": true })),
        ),
        workflow_scaffold(
            "workflow.skill_context.discover",
            "skill_context",
            "Context",
            "Discover skills",
            "Resolve runtime skills deterministically from workflow or node input goal text.",
            "Skills",
            "discover",
            json!({ "skillContext": { "mode": "discover", "goalSource": "node_input", "goal": "", "minScoreBps": 6500, "maxSkills": 3, "onNoMatch": "warn", "pinnedSkills": [], "onMissingPinned": "block", "includeMarkdown": true, "guidanceMaxChars": 1800 }, "outputSchema": workflow_skill_context_output_schema() }),
            json!({}),
            None,
        ),
        workflow_scaffold(
            "workflow.skill_context.pinned",
            "skill_context",
            "Context",
            "Pinned skill",
            "Attach one or more pinned runtime skills by skill hash or deterministic name lookup.",
            "Skills",
            "pinned",
            json!({ "skillContext": { "mode": "pinned", "goalSource": "node_input", "goal": "", "minScoreBps": 6500, "maxSkills": 3, "onNoMatch": "warn", "pinnedSkills": [{ "skillHash": "", "name": "", "required": true }], "onMissingPinned": "block", "includeMarkdown": true, "guidanceMaxChars": 1800 }, "outputSchema": workflow_skill_context_output_schema() }),
            json!({}),
            None,
        ),
        workflow_scaffold(
            "workflow.output.inline",
            "output",
            "Outputs",
            "Inline output",
            "Create a workflow output rendered inline or on the canvas.",
            "Output",
            "inline",
            json!({ "format": "markdown", "rendererRef": { "rendererId": "markdown", "displayMode": "inline" }, "materialization": { "enabled": false }, "retentionPolicy": { "retentionKind": "run_scoped", "ttlMs": 2592000000_u64 } }),
            json!({}),
            None,
        ),
        workflow_scaffold(
            "workflow.output.file",
            "output",
            "Outputs",
            "File output",
            "Materialize a durable local file with output evidence.",
            "Output",
            "file",
            json!({ "format": "json", "path": "outputs/result.json", "rendererRef": { "rendererId": "json", "displayMode": "json" }, "materialization": { "enabled": true, "assetPath": "outputs/result.json", "assetKind": "file" }, "deliveryTarget": { "targetKind": "local_file", "requiresApproval": false }, "retentionPolicy": { "retentionKind": "versioned" } }),
            json!({}),
            None,
        ),
        workflow_scaffold(
            "workflow.output.media",
            "output",
            "Outputs",
            "Media output",
            "Render or materialize image, SVG, audio, or video output.",
            "Output",
            "media",
            json!({ "format": "svg", "path": "outputs/result.svg", "fileExtension": "svg", "mimeType": "image/svg+xml", "rendererRef": { "rendererId": "media", "displayMode": "media" }, "materialization": { "enabled": false, "assetPath": "outputs/result.svg", "assetKind": "svg" }, "retentionPolicy": { "retentionKind": "versioned" } }),
            json!({}),
            None,
        ),
        workflow_scaffold(
            "workflow.output.delivery_draft",
            "output",
            "Outputs",
            "Delivery draft",
            "Prepare a message, ticket, or connector delivery draft.",
            "Output",
            "draft",
            json!({ "format": "message", "rendererRef": { "rendererId": "report", "displayMode": "report" }, "materialization": { "enabled": false }, "deliveryTarget": { "targetKind": "message_draft", "targetRef": "", "requiresApproval": true }, "retentionPolicy": { "retentionKind": "run_scoped", "ttlMs": 2592000000_u64 } }),
            json!({ "requireHumanGate": true, "privilegedActions": ["message_sending"] }),
            Some(json!({ "sideEffectClass": "external_write", "requiresApproval": true })),
        ),
        workflow_scaffold(
            "workflow.runtime.thread_fork",
            "runtime_thread_fork",
            "Runtime",
            "Thread fork control",
            "Fork the active runtime thread from a React Flow workflow control.",
            "Fork",
            "control",
            json!({
                "runtimeThreadForkEndpoint": "/v1/threads/{threadId}/fork",
                "runtimeThreadForkField": "runtimeThreadFork",
                "runtimeThreadForkEventField": "runtimeThreadFork.event",
                "runtimeThreadForkStatusField": "runtimeThreadFork.status",
                "runtimeThreadForkReceiptField": "runtimeThreadFork.receiptRefs",
                "runtimeThreadForkPolicyField": "runtimeThreadFork.policyDecisionRefs",
                "runtimeThreadForkThreadIdField": "threadId",
                "runtimeThreadForkReasonField": "reason",
                "runtimeThreadForkReason": "Fork thread from React Flow workflow control.",
                "runtimeThreadForkWorkflowNodeId": "runtime.thread-fork",
                "runtimeThreadForkSource": "react_flow",
                "runtimeThreadForkActor": "operator",
                "dryRun": false,
                "mutationExecuted": true,
                "redactionProfile": "runtime_thread_fork_safe",
                "outputSchema": workflow_runtime_thread_fork_output_schema()
            }),
            json!({ "privilegedActions": ["runtime.thread.fork"] }),
            Some(json!({
                "sideEffectClass": "write",
                "supportsDryRun": true,
                "schemaRequired": true,
                "connectionClasses": ["state", "data", "control"]
            })),
        ),
        workflow_scaffold(
            "workflow.runtime.operator_interrupt",
            "runtime_operator_interrupt",
            "Runtime",
            "Operator interrupt control",
            "Interrupt the active runtime turn from a React Flow workflow control.",
            "Interrupt",
            "control",
            json!({
                "runtimeOperatorInterruptEndpoint": "/v1/threads/{threadId}/turns/{turnId}/interrupt",
                "runtimeOperatorInterruptField": "runtimeOperatorInterrupt",
                "runtimeOperatorInterruptEventField": "runtimeOperatorInterrupt.event",
                "runtimeOperatorInterruptStatusField": "runtimeOperatorInterrupt.status",
                "runtimeOperatorInterruptReceiptField": "runtimeOperatorInterrupt.receiptRefs",
                "runtimeOperatorInterruptPolicyField": "runtimeOperatorInterrupt.policyDecisionRefs",
                "runtimeOperatorInterruptThreadIdField": "threadId",
                "runtimeOperatorInterruptTurnIdField": "turnId",
                "runtimeOperatorInterruptReasonField": "reason",
                "runtimeOperatorInterruptReason": "Interrupt turn from React Flow workflow control.",
                "runtimeOperatorInterruptWorkflowNodeId": "runtime.operator-interrupt",
                "runtimeOperatorInterruptSource": "react_flow",
                "runtimeOperatorInterruptActor": "operator",
                "dryRun": false,
                "mutationExecuted": true,
                "redactionProfile": "runtime_operator_interrupt_safe",
                "outputSchema": workflow_runtime_operator_interrupt_output_schema()
            }),
            json!({ "privilegedActions": ["runtime.turn.interrupt"] }),
            Some(json!({
                "sideEffectClass": "write",
                "supportsDryRun": true,
                "schemaRequired": true,
                "connectionClasses": ["state", "data", "control"]
            })),
        ),
        workflow_scaffold(
            "workflow.runtime.operator_steer",
            "runtime_operator_steer",
            "Runtime",
            "Operator steer control",
            "Steer the active runtime turn from a React Flow workflow control.",
            "Steer",
            "control",
            json!({
                "runtimeOperatorSteerEndpoint": "/v1/threads/{threadId}/turns/{turnId}/steer",
                "runtimeOperatorSteerField": "runtimeOperatorSteer",
                "runtimeOperatorSteerEventField": "runtimeOperatorSteer.event",
                "runtimeOperatorSteerStatusField": "runtimeOperatorSteer.status",
                "runtimeOperatorSteerReceiptField": "runtimeOperatorSteer.receiptRefs",
                "runtimeOperatorSteerPolicyField": "runtimeOperatorSteer.policyDecisionRefs",
                "runtimeOperatorSteerThreadIdField": "threadId",
                "runtimeOperatorSteerTurnIdField": "turnId",
                "runtimeOperatorSteerGuidanceField": "guidance",
                "runtimeOperatorSteerGuidance": "Steer turn from React Flow workflow control.",
                "runtimeOperatorSteerWorkflowNodeId": "runtime.operator-steer",
                "runtimeOperatorSteerSource": "react_flow",
                "runtimeOperatorSteerActor": "operator",
                "dryRun": false,
                "mutationExecuted": true,
                "redactionProfile": "runtime_operator_steer_safe",
                "outputSchema": workflow_runtime_operator_steer_output_schema()
            }),
            json!({ "privilegedActions": ["runtime.turn.steer"] }),
            Some(json!({
                "sideEffectClass": "write",
                "supportsDryRun": true,
                "schemaRequired": true,
                "connectionClasses": ["state", "data", "control"]
            })),
        ),
        workflow_scaffold(
            "workflow.runtime.thread_mode",
            "runtime_thread_mode",
            "Runtime",
            "Thread mode control",
            "Set runtime thread mode from a React Flow workflow control and surface daemon trust warnings.",
            "Mode",
            "control",
            json!({
                "runtimeThreadModeEndpoint": "/v1/threads/{threadId}/mode",
                "runtimeThreadModeField": "runtimeThreadMode",
                "runtimeThreadModeEventField": "runtimeThreadMode.event",
                "runtimeThreadModeStatusField": "runtimeThreadMode.status",
                "runtimeThreadModeTrustField": "runtimeThreadMode.workspaceTrustWarning",
                "runtimeThreadModeReceiptField": "runtimeThreadMode.receiptRefs",
                "runtimeThreadModePolicyField": "runtimeThreadMode.policyDecisionRefs",
                "runtimeThreadModeThreadIdField": "threadId",
                "runtimeThreadModeModeField": "mode",
                "runtimeThreadModeMode": "review",
                "runtimeThreadModeApprovalModeField": "approvalMode",
                "runtimeThreadModeApprovalMode": "human_required",
                "runtimeThreadModeTrustProfileField": "trustProfile",
                "runtimeThreadModeTrustProfile": "local_private",
                "runtimeThreadModeWorkspaceTrustWorkflowNodeId": "runtime.thread-mode.workspace-trust",
                "runtimeThreadModeRequestWarningAcknowledgement": true,
                "runtimeThreadModeWorkflowNodeId": "runtime.thread-mode",
                "runtimeThreadModeSource": "react_flow",
                "runtimeThreadModeActor": "operator",
                "dryRun": false,
                "mutationExecuted": true,
                "redactionProfile": "runtime_thread_mode_safe",
                "outputSchema": workflow_runtime_thread_mode_output_schema()
            }),
            json!({ "privilegedActions": ["runtime.thread.mode"] }),
            Some(json!({
                "sideEffectClass": "write",
                "requiresApproval": true,
                "supportsDryRun": true,
                "schemaRequired": true,
                "connectionClasses": ["state", "data", "control", "approval"]
            })),
        ),
        workflow_scaffold(
            "workflow.runtime.context_compact",
            "runtime_context_compact",
            "Runtime",
            "Context compact control",
            "Compact runtime thread context from a React Flow workflow control.",
            "Compact",
            "control",
            json!({
                "runtimeContextCompactEndpoint": "/v1/threads/{threadId}/compact",
                "runtimeContextCompactField": "runtimeContextCompact",
                "runtimeContextCompactEventField": "runtimeContextCompact.event",
                "runtimeContextCompactStatusField": "runtimeContextCompact.status",
                "runtimeContextCompactReceiptField": "runtimeContextCompact.receiptRefs",
                "runtimeContextCompactPolicyField": "runtimeContextCompact.policyDecisionRefs",
                "runtimeContextCompactThreadIdField": "threadId",
                "runtimeContextCompactTurnIdField": "turnId",
                "runtimeContextCompactReasonField": "reason",
                "runtimeContextCompactReason": "Compact thread context from React Flow workflow control.",
                "runtimeContextCompactScopeField": "scope",
                "runtimeContextCompactScope": "thread",
                "runtimeContextCompactWorkflowNodeId": "runtime.context-compact",
                "runtimeContextCompactSource": "react_flow",
                "runtimeContextCompactActor": "operator",
                "dryRun": false,
                "mutationExecuted": true,
                "redactionProfile": "runtime_context_compact_safe",
                "outputSchema": workflow_runtime_context_compact_output_schema()
            }),
            json!({ "privilegedActions": ["runtime.context.compact"] }),
            Some(json!({
                "sideEffectClass": "write",
                "supportsDryRun": true,
                "schemaRequired": true,
                "connectionClasses": ["state", "data", "control"]
            })),
        ),
        workflow_scaffold(
            "workflow.runtime.approval_request",
            "runtime_approval_request",
            "Runtime",
            "Approval request control",
            "Request runtime operator approval from a React Flow workflow control.",
            "Approval",
            "gate",
            json!({
                "runtimeApprovalRequestEndpoint": "/v1/threads/{threadId}/approvals",
                "runtimeApprovalRequestField": "runtimeApprovalRequest",
                "runtimeApprovalRequestEventField": "runtimeApprovalRequest.event",
                "runtimeApprovalRequestStatusField": "runtimeApprovalRequest.status",
                "runtimeApprovalRequestReceiptField": "runtimeApprovalRequest.receiptRefs",
                "runtimeApprovalRequestPolicyField": "runtimeApprovalRequest.policyDecisionRefs",
                "runtimeApprovalRequestThreadIdField": "threadId",
                "runtimeApprovalRequestTurnIdField": "turnId",
                "runtimeApprovalRequestApprovalIdField": "approvalId",
                "runtimeApprovalRequestReasonField": "reason",
                "runtimeApprovalRequestReason": "Request operator approval from React Flow workflow control.",
                "runtimeApprovalRequestScopeField": "scope",
                "runtimeApprovalRequestScope": "thread",
                "runtimeApprovalRequestPressureField": "pressure",
                "runtimeApprovalRequestPressureStatusField": "pressureStatus",
                "runtimeApprovalRequestAlertIdField": "alertId",
                "runtimeApprovalRequestSourceEventIdField": "sourceEventId",
                "runtimeApprovalRequestWorkflowNodeId": "runtime.approval.context-pressure",
                "runtimeApprovalRequestSource": "react_flow",
                "runtimeApprovalRequestActor": "operator",
                "dryRun": false,
                "mutationExecuted": true,
                "redactionProfile": "runtime_approval_request_safe",
                "outputSchema": workflow_runtime_approval_request_output_schema()
            }),
            json!({ "privilegedActions": ["runtime.approval.request"] }),
            Some(json!({
                "sideEffectClass": "write",
                "requiresApproval": true,
                "supportsDryRun": true,
                "schemaRequired": true,
                "connectionClasses": ["state", "data", "control", "approval"]
            })),
        ),
        workflow_scaffold(
            "workflow.runtime.rollback_snapshot",
            "runtime_rollback_snapshot",
            "Runtime",
            "Rollback snapshot",
            "List rollback snapshots for a runtime thread from a React Flow workflow control.",
            "Snapshot",
            "list",
            json!({
                "runtimeRollbackSnapshotEndpoint": "/v1/threads/{threadId}/snapshots",
                "runtimeRollbackSnapshotField": "runtimeRollbackSnapshot",
                "runtimeRollbackSnapshotEventField": "runtimeRollbackSnapshot.event",
                "runtimeRollbackSnapshotStatusField": "runtimeRollbackSnapshot.status",
                "runtimeRollbackSnapshotReceiptField": "runtimeRollbackSnapshot.receiptRefs",
                "runtimeRollbackSnapshotPolicyField": "runtimeRollbackSnapshot.policyDecisionRefs",
                "runtimeRollbackSnapshotThreadIdField": "threadId",
                "runtimeRollbackSnapshotWorkflowNodeId": "runtime.rollback-snapshot",
                "runtimeRollbackSnapshotSource": "react_flow",
                "runtimeRollbackSnapshotActor": "operator",
                "readOnly": true,
                "dryRun": false,
                "mutationExecuted": false,
                "redactionProfile": "runtime_rollback_snapshot_safe",
                "outputSchema": workflow_runtime_rollback_snapshot_output_schema()
            }),
            json!({}),
            Some(json!({
                "sideEffectClass": "none",
                "supportsDryRun": true,
                "schemaRequired": true,
                "connectionClasses": ["state", "data", "control"]
            })),
        ),
        workflow_scaffold(
            "workflow.runtime.restore_gate",
            "runtime_restore_gate",
            "Runtime",
            "Restore gate",
            "Preview or apply a runtime workspace restore from a React Flow workflow gate.",
            "Restore",
            "gated",
            json!({
                "runtimeRestoreGateEndpoint": "/v1/threads/{threadId}/snapshots/{snapshotId}/restore-{mode}",
                "runtimeRestoreGateField": "runtimeRestoreGate",
                "runtimeRestoreGateEventField": "runtimeRestoreGate.event",
                "runtimeRestoreGateStatusField": "runtimeRestoreGate.status",
                "runtimeRestoreGateReceiptField": "runtimeRestoreGate.receiptRefs",
                "runtimeRestoreGatePolicyField": "runtimeRestoreGate.policyDecisionRefs",
                "runtimeRestoreGateThreadIdField": "threadId",
                "runtimeRestoreGateSnapshotIdField": "snapshotId",
                "runtimeRestoreGateMode": "preview",
                "runtimeRestoreGateModeField": "mode",
                "runtimeRestoreGateConflictPolicy": "block",
                "runtimeRestoreGateConflictPolicyField": "conflictPolicy",
                "runtimeRestoreGateApprovalGranted": false,
                "runtimeRestoreGateApprovalGrantedField": "approvalGranted",
                "runtimeRestoreGateWorkflowNodeId": "runtime.restore-gate",
                "runtimeRestoreGateSource": "react_flow",
                "runtimeRestoreGateActor": "operator",
                "readOnly": false,
                "dryRun": false,
                "mutationExecuted": true,
                "redactionProfile": "runtime_restore_gate_safe",
                "outputSchema": workflow_runtime_restore_gate_output_schema()
            }),
            json!({ "privilegedActions": ["runtime.workspace.restore"] }),
            Some(json!({
                "sideEffectClass": "write",
                "requiresApproval": true,
                "supportsDryRun": true,
                "schemaRequired": true,
                "connectionClasses": ["state", "data", "control", "approval"]
            })),
        ),
    ];
    for (node_type, group, label) in canonical_workflow_node_types() {
        if matches!(
            node_type,
            "source"
                | "trigger"
                | "adapter"
                | "plugin_tool"
                | "skill_context"
                | "runtime_thread_fork"
                | "runtime_operator_interrupt"
                | "runtime_operator_steer"
                | "runtime_thread_mode"
                | "runtime_context_compact"
                | "runtime_approval_request"
                | "runtime_rollback_snapshot"
                | "runtime_restore_gate"
                | "workflow_package_export"
                | "workflow_package_import"
                | "output"
        ) {
            continue;
        }
        scaffolds.push(workflow_scaffold(
            &format!("workflow.{}", node_type),
            node_type,
            group,
            label,
            &format!("Create a {} node from the canonical ontology.", label),
            "Status",
            "idle",
            json!({}),
            json!({}),
            None,
        ));
    }
    scaffolds
}

pub(super) fn workflow_node_action_metadata(node_type: &str) -> Value {
    let required_binding = match node_type {
        "function" => Some("function"),
        "model_binding" | "model_call" => Some("model"),
        "parser" => Some("parser"),
        "adapter" => Some("connector"),
        "plugin_tool" => Some("tool"),
        "subgraph" => Some("subgraph"),
        "proposal" => Some("proposal"),
        _ => None,
    };
    let side_effect_class = match node_type {
        "adapter" | "plugin_tool" => "read",
        "github_pr_create" => "external_write",
        "human_gate"
        | "proposal"
        | "runtime_thread_fork"
        | "runtime_operator_interrupt"
        | "runtime_operator_steer"
        | "runtime_thread_mode"
        | "runtime_context_compact"
        | "runtime_approval_request"
        | "runtime_restore_gate"
        | "workflow_package_export"
        | "workflow_package_import" => "write",
        _ => "none",
    };
    let requires_approval = matches!(
        node_type,
        "human_gate"
            | "proposal"
            | "workflow_package_import"
            | "github_pr_create"
            | "runtime_thread_mode"
            | "runtime_approval_request"
            | "runtime_restore_gate"
    );
    let sandboxed = node_type == "function";
    let supports_dry_run = matches!(
        node_type,
        "function"
            | "adapter"
            | "plugin_tool"
            | "pr_attempt"
            | "review_gate"
            | "github_pr_create"
            | "runtime_thread_fork"
            | "runtime_operator_interrupt"
            | "runtime_operator_steer"
            | "runtime_thread_mode"
            | "runtime_context_compact"
            | "runtime_approval_request"
            | "runtime_rollback_snapshot"
            | "runtime_restore_gate"
            | "workflow_package_export"
            | "workflow_package_import"
    );
    let supports_mock_binding = matches!(
        node_type,
        "model_binding" | "parser" | "adapter" | "plugin_tool" | "subgraph"
    );
    let schema_required = matches!(
        node_type,
        "function"
            | "skill_context"
            | "model_call"
            | "parser"
            | "adapter"
            | "plugin_tool"
            | "repository_context"
            | "branch_policy"
            | "github_context"
            | "issue_context"
            | "pr_attempt"
            | "review_gate"
            | "github_pr_create"
            | "runtime_thread_fork"
            | "runtime_operator_interrupt"
            | "runtime_operator_steer"
            | "runtime_thread_mode"
            | "runtime_context_compact"
            | "runtime_approval_request"
            | "runtime_rollback_snapshot"
            | "runtime_restore_gate"
            | "workflow_package_export"
            | "workflow_package_import"
            | "subgraph"
            | "output"
            | "test_assertion"
    );
    let connection_classes: Vec<&str> = match node_type {
        "model_binding" => vec!["model"],
        "model_call" => vec!["data", "model", "memory", "tool", "parser"],
        "skill_context" => vec!["data", "error"],
        "repository_context" => vec!["state"],
        "branch_policy" => vec!["state", "approval"],
        "github_context" => vec!["state", "approval"],
        "issue_context" => vec!["state"],
        "pr_attempt" => vec!["state", "approval", "data"],
        "review_gate" => vec!["state", "approval"],
        "github_pr_create" => vec!["state", "approval", "data"],
        "runtime_thread_fork" => vec!["state", "data", "control"],
        "runtime_operator_interrupt" => vec!["state", "data", "control"],
        "runtime_operator_steer" => vec!["state", "data", "control"],
        "runtime_thread_mode" => vec!["state", "data", "control", "approval"],
        "runtime_context_compact" => vec!["state", "data", "control"],
        "runtime_approval_request" => vec!["state", "data", "control", "approval"],
        "runtime_rollback_snapshot" => vec!["state", "data", "control"],
        "runtime_restore_gate" => vec!["state", "data", "control", "approval"],
        "workflow_package_export" => vec!["data", "output_bundle"],
        "workflow_package_import" => vec!["data", "output_bundle", "approval"],
        "parser" => vec!["data", "parser"],
        "plugin_tool" => vec!["data", "tool", "error"],
        "adapter" => vec!["data", "error"],
        "state" => vec!["data", "memory", "state"],
        "decision" => vec!["data", "error"],
        "human_gate" => vec!["data", "approval"],
        "subgraph" => vec!["data", "tool", "subgraph"],
        "output" => vec!["data", "delivery"],
        "proposal" => vec!["data", "proposal"],
        _ => vec!["data"],
    };
    json!({
        "actionId": format!("workflow.action.{}", node_type),
        "requiredBinding": required_binding,
        "bindingMode": if required_binding.is_some() { "required" } else { "none" },
        "supportsMockBinding": supports_mock_binding,
        "sideEffectClass": side_effect_class,
        "requiresApproval": requires_approval,
        "sandboxed": sandboxed,
        "supportsDryRun": supports_dry_run,
        "schemaRequired": schema_required,
        "connectionClasses": connection_classes,
    })
}

pub(super) fn workflow_edge(id: &str, from: &str, to: &str) -> Value {
    json!({
        "id": id,
        "from": from,
        "to": to,
        "fromPort": "output",
        "toPort": "input",
        "type": "data",
        "connectionClass": "data",
        "data": { "connectionClass": "data" }
    })
}

pub(super) fn workflow_edge_port(id: &str, from: &str, to: &str, from_port: &str) -> Value {
    json!({
        "id": id,
        "from": from,
        "to": to,
        "fromPort": from_port,
        "toPort": "input",
        "type": "data",
        "connectionClass": "data",
        "data": { "connectionClass": "data" }
    })
}

pub(super) fn workflow_edge_ports(
    id: &str,
    from: &str,
    to: &str,
    from_port: &str,
    to_port: &str,
) -> Value {
    json!({
        "id": id,
        "from": from,
        "to": to,
        "fromPort": from_port,
        "toPort": to_port,
        "type": "data",
        "connectionClass": "data",
        "data": { "connectionClass": "data" }
    })
}

pub(super) fn workflow_coding_route_contract(route_id: &str) -> Value {
    match route_id {
        "coding.template.debug" => json!({
            "schemaVersion": "workflow.coding-route.v1",
            "routeId": "coding.template.debug",
            "label": "Debug",
            "taskClass": "debug",
            "riskLevel": "normal",
            "phases": ["coding.intake", "coding.context", "coding.define", "coding.verify", "coding.review", "coding.closeout"],
            "phaseDetails": [
                { "phaseId": "coding.intake", "label": "Intake", "componentKind": "context", "required": true, "gateIds": [] },
                { "phaseId": "coding.context", "label": "Context", "componentKind": "context", "required": true, "gateIds": [] },
                { "phaseId": "coding.define", "label": "Define", "componentKind": "planner", "required": true, "gateIds": ["route.debug.repro"] },
                { "phaseId": "coding.verify", "label": "Verify", "componentKind": "verifier", "required": true, "gateIds": ["route.verify.execution"] },
                { "phaseId": "coding.review", "label": "Review", "componentKind": "reviewer", "required": true, "gateIds": [] },
                { "phaseId": "coding.closeout", "label": "Closeout", "componentKind": "merge_verdict", "required": true, "gateIds": [] }
            ],
            "requiredSkillSelectors": [{ "mode": "discover", "names": ["debugging", "regression", "test-driven-development"], "required": false }],
            "optionalSkillSelectors": [{ "mode": "discover", "names": ["incremental-implementation"], "required": false }],
            "evidenceRequirements": [
                "coding.route.classification.v1",
                "coding.route.phase.start.v1",
                "coding.route.phase.complete.v1",
                "coding.route.skill_selection.v1",
                "coding.route.gate.v1",
                "coding.route.benchmark.v1",
                "coding.route.promotion.v1"
            ],
            "gates": [
                { "gateId": "route.debug.repro", "label": "Failure reproduction", "phaseId": "coding.define", "evidenceKind": "execution", "required": true, "status": "skipped", "operatorOverrideAllowed": false, "blockingRequirements": ["reproduction or diagnostic evidence"] },
                { "gateId": "route.verify.execution", "label": "Verification evidence", "phaseId": "coding.verify", "evidenceKind": "execution", "required": true, "status": "skipped", "operatorOverrideAllowed": false, "blockingRequirements": ["node execution evidence"] }
            ],
            "skipRules": ["Do not ship without a verified repro or equivalent diagnostic evidence."],
            "failureBehavior": "block"
        }),
        "coding.template.review" => json!({
            "schemaVersion": "workflow.coding-route.v1",
            "routeId": "coding.template.review",
            "label": "Review",
            "taskClass": "review",
            "riskLevel": "normal",
            "phases": ["coding.intake", "coding.context", "coding.review", "coding.verify", "coding.closeout"],
            "phaseDetails": [
                { "phaseId": "coding.intake", "label": "Intake", "componentKind": "context", "required": true, "gateIds": [] },
                { "phaseId": "coding.context", "label": "Context", "componentKind": "context", "required": true, "gateIds": [] },
                { "phaseId": "coding.review", "label": "Review", "componentKind": "reviewer", "required": true, "gateIds": ["route.review.findings"] },
                { "phaseId": "coding.verify", "label": "Verify", "componentKind": "verifier", "required": true, "gateIds": ["route.verify.execution"] },
                { "phaseId": "coding.closeout", "label": "Closeout", "componentKind": "merge_verdict", "required": true, "gateIds": [] }
            ],
            "requiredSkillSelectors": [{ "mode": "discover", "names": ["code-review", "security-review", "test-review"], "required": false }],
            "optionalSkillSelectors": [{ "mode": "discover", "names": ["incremental-implementation"], "required": false }],
            "evidenceRequirements": [
                "coding.route.classification.v1",
                "coding.route.phase.start.v1",
                "coding.route.phase.complete.v1",
                "coding.route.skill_selection.v1",
                "coding.route.gate.v1",
                "coding.route.benchmark.v1",
                "coding.route.promotion.v1"
            ],
            "gates": [
                { "gateId": "route.review.findings", "label": "Finding evidence", "phaseId": "coding.review", "evidenceKind": "execution", "required": true, "status": "skipped", "operatorOverrideAllowed": false, "blockingRequirements": ["findings or explicit no-findings evidence"] },
                { "gateId": "route.verify.execution", "label": "Verification evidence", "phaseId": "coding.verify", "evidenceKind": "execution", "required": true, "status": "skipped", "operatorOverrideAllowed": false, "blockingRequirements": ["node execution evidence"] }
            ],
            "skipRules": ["Do not treat skill guidance as review findings without runtime evidence."],
            "failureBehavior": "block"
        }),
        _ => json!({
            "schemaVersion": "workflow.coding-route.v1",
            "routeId": "coding.template.build",
            "label": "Build",
            "taskClass": "build",
            "riskLevel": "normal",
            "phases": ["coding.intake", "coding.context", "coding.plan", "coding.build", "coding.verify", "coding.closeout"],
            "phaseDetails": [
                { "phaseId": "coding.intake", "label": "Intake", "componentKind": "context", "required": true, "gateIds": [] },
                { "phaseId": "coding.context", "label": "Context", "componentKind": "context", "required": true, "gateIds": [] },
                { "phaseId": "coding.plan", "label": "Plan", "componentKind": "planner", "required": true, "gateIds": ["route.build.plan"] },
                { "phaseId": "coding.build", "label": "Build", "componentKind": "builder", "required": true, "gateIds": [] },
                { "phaseId": "coding.verify", "label": "Verify", "componentKind": "verifier", "required": true, "gateIds": ["route.verify.execution"] },
                { "phaseId": "coding.closeout", "label": "Closeout", "componentKind": "merge_verdict", "required": true, "gateIds": [] }
            ],
            "requiredSkillSelectors": [{ "mode": "discover", "names": ["incremental-implementation", "test-driven-development"], "required": false }],
            "optionalSkillSelectors": [{ "mode": "discover", "names": ["code-review"], "required": false }],
            "evidenceRequirements": [
                "coding.route.classification.v1",
                "coding.route.phase.start.v1",
                "coding.route.phase.complete.v1",
                "coding.route.skill_selection.v1",
                "coding.route.gate.v1",
                "coding.route.benchmark.v1",
                "coding.route.promotion.v1"
            ],
            "gates": [
                { "gateId": "route.build.plan", "label": "Implementation plan", "phaseId": "coding.plan", "evidenceKind": "execution", "required": true, "status": "skipped", "operatorOverrideAllowed": false, "blockingRequirements": ["planning evidence"] },
                { "gateId": "route.verify.execution", "label": "Verification evidence", "phaseId": "coding.verify", "evidenceKind": "execution", "required": true, "status": "skipped", "operatorOverrideAllowed": false, "blockingRequirements": ["node execution evidence"] }
            ],
            "skipRules": ["Do not bypass explicit skill_context attachment for model context."],
            "failureBehavior": "block"
        }),
    }
}

fn workflow_coding_route_source_node(route_id: &str, request: &str) -> Value {
    let mut node = workflow_node(
        "source-coding-goal",
        "source",
        "Coding goal",
        90,
        180,
        "Input",
        "manual",
    );
    if let Some(logic) = node
        .get_mut("config")
        .and_then(|config| config.get_mut("logic"))
        .and_then(Value::as_object_mut)
    {
        logic.insert(
            "payload".to_string(),
            json!({
                "request": request,
                "routeId": route_id
            }),
        );
        logic.insert(
            "schema".to_string(),
            json!({
                "type": "object",
                "required": ["request"],
                "properties": {
                    "request": { "type": "string" },
                    "routeId": { "type": "string" }
                }
            }),
        );
    }
    node
}

fn workflow_coding_route_skill_context_node(_route_id: &str, goal: &str) -> Value {
    let mut node = workflow_node(
        "skill-context-route",
        "skill_context",
        "Runtime skill context",
        340,
        170,
        "Skills",
        "registry",
    );
    if let Some(logic) = node
        .get_mut("config")
        .and_then(|config| config.get_mut("logic"))
        .and_then(Value::as_object_mut)
    {
        logic.insert(
            "skillContext".to_string(),
            json!({
                "mode": "discover",
                "goalSource": "static",
                "goal": goal,
                "minScoreBps": 4500,
                "maxSkills": 3,
                "onNoMatch": "warn",
                "allowDraftForBenchmark": true,
                "pinnedSkills": [],
                "onMissingPinned": "block",
                "includeMarkdown": true,
                "guidanceMaxChars": 1800
            }),
        );
        logic.insert(
            "outputSchema".to_string(),
            workflow_skill_context_output_schema(),
        );
    }
    node
}

fn workflow_coding_route_model_node(route_id: &str, prompt: &str) -> Value {
    let mut node = workflow_node(
        "model-route-worker",
        "model_call",
        "Route worker",
        610,
        170,
        "Model",
        "reasoning",
    );
    if let Some(logic) = node
        .get_mut("config")
        .and_then(|config| config.get_mut("logic"))
        .and_then(Value::as_object_mut)
    {
        logic.insert("modelRef".to_string(), json!("reasoning"));
        logic.insert("routeId".to_string(), json!(route_id));
        logic.insert("prompt".to_string(), json!(prompt));
    }
    node
}

pub(super) fn workflow_function_node(id: &str, name: &str, x: i64, y: i64, code: &str) -> Value {
    let mut node = workflow_node(id, "function", name, x, y, "Runtime", "local");
    if let Some(logic) = node
        .get_mut("config")
        .and_then(|config| config.get_mut("logic"))
        .and_then(Value::as_object_mut)
    {
        logic.insert("code".to_string(), json!(code));
        logic.insert(
            "functionBinding".to_string(),
            json!({
                "language": "javascript",
                "code": code,
                "outputSchema": { "type": "object" },
                "sandboxPolicy": {
                    "timeoutMs": 1000,
                    "memoryMb": 64,
                    "outputLimitBytes": 32768,
                    "permissions": []
                },
                "testInput": { "payload": "sample" }
            }),
        );
    }
    node
}

pub(super) fn workflow_adapter_node(
    id: &str,
    name: &str,
    x: i64,
    y: i64,
    connector: &str,
    privileged: bool,
) -> Value {
    let mut node = workflow_node(id, "adapter", name, x, y, "Connector", connector);
    let side_effect = if privileged { "external_write" } else { "read" };
    let capability_scope = if privileged {
        json!(["read", "write"])
    } else {
        json!(["read"])
    };
    let operation = if privileged {
        "draft_or_create"
    } else {
        "read"
    };
    if let Some(logic) = node
        .get_mut("config")
        .and_then(|config| config.get_mut("logic"))
        .and_then(Value::as_object_mut)
    {
        logic.insert(
            "connectorBinding".to_string(),
            json!({
                "connectorRef": connector,
                "mockBinding": true,
                "credentialReady": false,
                "capabilityScope": capability_scope,
                "sideEffectClass": side_effect,
                "requiresApproval": privileged,
                "operation": operation
            }),
        );
    }
    if privileged {
        if let Some(law) = node
            .get_mut("config")
            .and_then(|config| config.get_mut("law"))
            .and_then(Value::as_object_mut)
        {
            law.insert("requireHumanGate".to_string(), Value::Bool(true));
            law.insert("privilegedActions".to_string(), json!([side_effect]));
        }
    }
    node
}

pub(super) fn workflow_plugin_node(id: &str, name: &str, x: i64, y: i64, tool_ref: &str) -> Value {
    workflow_node(id, "plugin_tool", name, x, y, "Plugin", tool_ref)
}

pub(super) fn workflow_test(id: &str, name: &str, target_node_ids: Vec<&str>) -> WorkflowTestCase {
    WorkflowTestCase {
        id: id.to_string(),
        name: name.to_string(),
        target_node_ids: target_node_ids.into_iter().map(str::to_string).collect(),
        target_subgraph_id: None,
        assertion: WorkflowTestAssertion {
            kind: "node_exists".to_string(),
            expected: None,
            expression: None,
        },
        status: Some("idle".to_string()),
        last_message: None,
    }
}

pub(super) fn template_workflow_seed(
    template_id: &str,
) -> Option<(
    &'static str,
    &'static str,
    &'static str,
    Vec<Value>,
    Vec<Value>,
    Vec<WorkflowTestCase>,
)> {
    let seed = match template_id {
        "coding.template.build" => (
            "Coding route build",
            "agent_workflow",
            "local",
            vec![
                workflow_coding_route_source_node(
                    "coding.template.build",
                    "Implement the requested coding change with explicit verification evidence.",
                ),
                workflow_coding_route_skill_context_node(
                    "coding.template.build",
                    "incremental implementation test driven development focused verification",
                ),
                workflow_coding_route_model_node(
                    "coding.template.build",
                    "Run the build route. Use the attached runtime skill context only as bounded guidance. Produce implementation, verification, and closeout evidence.",
                ),
                workflow_node(
                    "output-route-report",
                    "output",
                    "Route report",
                    880,
                    180,
                    "Output",
                    "report",
                ),
            ],
            vec![
                workflow_edge(
                    "edge-goal-skill-context",
                    "source-coding-goal",
                    "skill-context-route",
                ),
                workflow_edge(
                    "edge-goal-model",
                    "source-coding-goal",
                    "model-route-worker",
                ),
                workflow_edge_ports(
                    "edge-skill-context-model-context",
                    "skill-context-route",
                    "model-route-worker",
                    "output",
                    "context",
                ),
                workflow_edge(
                    "edge-model-route-output",
                    "model-route-worker",
                    "output-route-report",
                ),
            ],
            vec![workflow_test(
                "test-coding-build-route",
                "Build route has explicit skill context and output path",
                vec![
                    "source-coding-goal",
                    "skill-context-route",
                    "model-route-worker",
                    "output-route-report",
                ],
            )],
        ),
        "coding.template.debug" => (
            "Coding route debug",
            "agent_workflow",
            "local",
            vec![
                workflow_coding_route_source_node(
                    "coding.template.debug",
                    "Debug the reported failure by reproducing, isolating, fixing, and verifying it.",
                ),
                workflow_coding_route_skill_context_node(
                    "coding.template.debug",
                    "debugging regression reproduction test driven verification",
                ),
                workflow_coding_route_model_node(
                    "coding.template.debug",
                    "Run the debug route. Use the attached runtime skill context only as bounded guidance. Produce reproduction, fix, verification, and closeout evidence.",
                ),
                workflow_node(
                    "output-route-report",
                    "output",
                    "Route report",
                    880,
                    180,
                    "Output",
                    "report",
                ),
            ],
            vec![
                workflow_edge(
                    "edge-goal-skill-context",
                    "source-coding-goal",
                    "skill-context-route",
                ),
                workflow_edge(
                    "edge-goal-model",
                    "source-coding-goal",
                    "model-route-worker",
                ),
                workflow_edge_ports(
                    "edge-skill-context-model-context",
                    "skill-context-route",
                    "model-route-worker",
                    "output",
                    "context",
                ),
                workflow_edge(
                    "edge-model-route-output",
                    "model-route-worker",
                    "output-route-report",
                ),
            ],
            vec![workflow_test(
                "test-coding-debug-route",
                "Debug route has explicit skill context and output path",
                vec![
                    "source-coding-goal",
                    "skill-context-route",
                    "model-route-worker",
                    "output-route-report",
                ],
            )],
        ),
        "coding.template.review" => (
            "Coding route review",
            "agent_workflow",
            "local",
            vec![
                workflow_coding_route_source_node(
                    "coding.template.review",
                    "Review the requested change and report grounded findings, risks, and verification gaps.",
                ),
                workflow_coding_route_skill_context_node(
                    "coding.template.review",
                    "code review security review test review verification evidence",
                ),
                workflow_coding_route_model_node(
                    "coding.template.review",
                    "Run the review route. Use the attached runtime skill context only as bounded guidance. Lead with findings, verification evidence, and residual risk.",
                ),
                workflow_node(
                    "output-route-report",
                    "output",
                    "Route report",
                    880,
                    180,
                    "Output",
                    "report",
                ),
            ],
            vec![
                workflow_edge(
                    "edge-goal-skill-context",
                    "source-coding-goal",
                    "skill-context-route",
                ),
                workflow_edge(
                    "edge-goal-model",
                    "source-coding-goal",
                    "model-route-worker",
                ),
                workflow_edge_ports(
                    "edge-skill-context-model-context",
                    "skill-context-route",
                    "model-route-worker",
                    "output",
                    "context",
                ),
                workflow_edge(
                    "edge-model-route-output",
                    "model-route-worker",
                    "output-route-report",
                ),
            ],
            vec![workflow_test(
                "test-coding-review-route",
                "Review route has explicit skill context and output path",
                vec![
                    "source-coding-goal",
                    "skill-context-route",
                    "model-route-worker",
                    "output-route-report",
                ],
            )],
        ),
        "basic-agent-answer" => (
            "Basic agent answer",
            "agent_workflow",
            "local",
            vec![
                workflow_node(
                    "source-user-input",
                    "source",
                    "User input",
                    120,
                    180,
                    "Input",
                    "manual",
                ),
                workflow_node(
                    "model-answer",
                    "model_call",
                    "Draft answer",
                    390,
                    170,
                    "Model",
                    "reasoning",
                ),
                workflow_node(
                    "output-answer",
                    "output",
                    "Answer bundle",
                    690,
                    180,
                    "Output",
                    "draft",
                ),
            ],
            vec![
                workflow_edge("edge-source-model", "source-user-input", "model-answer"),
                workflow_edge("edge-model-output", "model-answer", "output-answer"),
            ],
            vec![workflow_test(
                "test-basic-path",
                "Input and answer path exists",
                vec!["source-user-input", "model-answer", "output-answer"],
            )],
        ),
        "repo-function-test" => (
            "Repo function test",
            "evaluation_workflow",
            "local",
            vec![
                workflow_node(
                    "source-repo-context",
                    "source",
                    "Repo context",
                    90,
                    180,
                    "Input",
                    "workspace",
                ),
                workflow_node(
                    "function-summarize",
                    "function",
                    "Summarize files",
                    340,
                    170,
                    "Runtime",
                    "local",
                ),
                workflow_node(
                    "test-shape",
                    "test_assertion",
                    "Output has summary",
                    590,
                    180,
                    "Tests",
                    "mapped",
                ),
                workflow_node(
                    "output-test-report",
                    "output",
                    "Test report",
                    840,
                    180,
                    "Output",
                    "report",
                ),
            ],
            vec![
                workflow_edge(
                    "edge-source-function",
                    "source-repo-context",
                    "function-summarize",
                ),
                workflow_edge("edge-function-test", "function-summarize", "test-shape"),
                workflow_edge("edge-test-output", "test-shape", "output-test-report"),
            ],
            vec![workflow_test(
                "test-function-path",
                "Function and test path exists",
                vec!["source-repo-context", "function-summarize", "test-shape"],
            )],
        ),
        "adapter-connector-check" => (
            "Adapter connector check",
            "agent_workflow",
            "hybrid",
            vec![
                workflow_node(
                    "source-request",
                    "source",
                    "Request",
                    90,
                    190,
                    "Input",
                    "manual",
                ),
                workflow_node(
                    "adapter-read",
                    "adapter",
                    "Read connector",
                    330,
                    180,
                    "Connector",
                    "generic_connector",
                ),
                workflow_node(
                    "decision-health",
                    "decision",
                    "Check response",
                    570,
                    175,
                    "Paths",
                    "2",
                ),
                workflow_node(
                    "output-connector",
                    "output",
                    "Connector report",
                    820,
                    185,
                    "Output",
                    "status",
                ),
            ],
            vec![
                workflow_edge("edge-request-adapter", "source-request", "adapter-read"),
                workflow_edge("edge-adapter-decision", "adapter-read", "decision-health"),
                workflow_edge(
                    "edge-decision-output",
                    "decision-health",
                    "output-connector",
                ),
            ],
            vec![workflow_test(
                "test-adapter-path",
                "Connector path exists",
                vec!["source-request", "adapter-read", "decision-health"],
            )],
        ),
        "plugin-tool-action" => (
            "Plugin tool action",
            "agent_workflow",
            "hybrid",
            vec![
                workflow_node(
                    "source-task",
                    "source",
                    "Task input",
                    90,
                    180,
                    "Input",
                    "manual",
                ),
                workflow_node(
                    "plugin-codex",
                    "plugin_tool",
                    "Invoke plugin",
                    330,
                    170,
                    "Plugin",
                    "codex_plugin",
                ),
                workflow_node(
                    "model-interpret",
                    "model_call",
                    "Interpret result",
                    590,
                    170,
                    "Model",
                    "reasoning",
                ),
                workflow_node(
                    "output-plugin",
                    "output",
                    "Plugin result",
                    860,
                    180,
                    "Output",
                    "summary",
                ),
            ],
            vec![
                workflow_edge("edge-task-plugin", "source-task", "plugin-codex"),
                workflow_edge("edge-plugin-model", "plugin-codex", "model-interpret"),
                workflow_edge("edge-model-output", "model-interpret", "output-plugin"),
            ],
            vec![workflow_test(
                "test-plugin-path",
                "Plugin path exists",
                vec!["source-task", "plugin-codex", "model-interpret"],
            )],
        ),
        "human-gated-change" => (
            "Human gated change",
            "agent_workflow",
            "local",
            vec![
                workflow_node(
                    "source-change-request",
                    "source",
                    "Change request",
                    90,
                    180,
                    "Input",
                    "manual",
                ),
                workflow_node(
                    "model-proposal",
                    "model_call",
                    "Draft change",
                    330,
                    170,
                    "Model",
                    "reasoning",
                ),
                workflow_node(
                    "gate-approval",
                    "human_gate",
                    "Approval gate",
                    590,
                    175,
                    "Gate",
                    "approval",
                ),
                workflow_node(
                    "output-approved-change",
                    "output",
                    "Approved bundle",
                    840,
                    185,
                    "Output",
                    "pending",
                ),
            ],
            vec![
                workflow_edge(
                    "edge-request-model",
                    "source-change-request",
                    "model-proposal",
                ),
                workflow_edge("edge-model-gate", "model-proposal", "gate-approval"),
                workflow_edge(
                    "edge-gate-output",
                    "gate-approval",
                    "output-approved-change",
                ),
            ],
            vec![workflow_test(
                "test-gated-path",
                "Gated path exists",
                vec!["source-change-request", "model-proposal", "gate-approval"],
            )],
        ),
        "jpg-to-svg-tracing" => (
            "JPG to SVG tracing",
            "agent_workflow",
            "local",
            vec![
                workflow_node(
                    "source-jpg",
                    "source",
                    "Media input",
                    80,
                    180,
                    "Input",
                    "image",
                ),
                workflow_node(
                    "model-vision-trace",
                    "model_call",
                    "Trace image",
                    330,
                    170,
                    "Model",
                    "vision",
                ),
                workflow_node(
                    "function-svg",
                    "function",
                    "Build SVG",
                    590,
                    170,
                    "Runtime",
                    "local",
                ),
                workflow_node(
                    "output-svg",
                    "output",
                    "SVG output",
                    850,
                    180,
                    "Output",
                    "svg",
                ),
            ],
            vec![
                workflow_edge("edge-jpg-vision", "source-jpg", "model-vision-trace"),
                workflow_edge("edge-vision-function", "model-vision-trace", "function-svg"),
                workflow_edge("edge-function-svg", "function-svg", "output-svg"),
            ],
            vec![workflow_test(
                "test-svg-path",
                "SVG transform path exists",
                vec![
                    "source-jpg",
                    "model-vision-trace",
                    "function-svg",
                    "output-svg",
                ],
            )],
        ),
        "proposal-mutation" => (
            "Proposal mutation",
            "agent_workflow",
            "local",
            vec![
                workflow_node(
                    "source-existing-flow",
                    "source",
                    "Existing workflow",
                    80,
                    180,
                    "Input",
                    "graph",
                ),
                workflow_node(
                    "model-mutation",
                    "model_call",
                    "Suggest mutation",
                    330,
                    170,
                    "Model",
                    "reasoning",
                ),
                workflow_node(
                    "gate-apply",
                    "human_gate",
                    "Apply approval",
                    590,
                    175,
                    "Gate",
                    "approval",
                ),
                workflow_node(
                    "output-proposal",
                    "output",
                    "Proposal preview",
                    850,
                    180,
                    "Output",
                    "diff",
                ),
            ],
            vec![
                workflow_edge("edge-flow-model", "source-existing-flow", "model-mutation"),
                workflow_edge("edge-model-gate", "model-mutation", "gate-apply"),
                workflow_edge("edge-gate-proposal", "gate-apply", "output-proposal"),
            ],
            vec![workflow_test(
                "test-proposal-path",
                "Proposal path exists",
                vec!["source-existing-flow", "model-mutation", "gate-apply"],
            )],
        ),
        "software-request-triage-agent" => (
            "Software request triage agent",
            "event_workflow",
            "hybrid",
            vec![
                workflow_node(
                    "source-request-intake",
                    "source",
                    "Request intake",
                    70,
                    185,
                    "Input",
                    "queue",
                ),
                workflow_node(
                    "decision-policy",
                    "decision",
                    "Policy check",
                    300,
                    170,
                    "Paths",
                    "2",
                ),
                workflow_node(
                    "adapter-ticket",
                    "adapter",
                    "IT ticket draft",
                    540,
                    170,
                    "Connector",
                    "it_ticketing",
                ),
                workflow_node(
                    "gate-ticket-create",
                    "human_gate",
                    "Create approval",
                    780,
                    175,
                    "Gate",
                    "approval",
                ),
                workflow_node(
                    "output-triage",
                    "output",
                    "Triage record",
                    1030,
                    185,
                    "Output",
                    "ticket",
                ),
            ],
            vec![
                workflow_edge(
                    "edge-intake-policy",
                    "source-request-intake",
                    "decision-policy",
                ),
                workflow_edge("edge-policy-ticket", "decision-policy", "adapter-ticket"),
                workflow_edge("edge-ticket-gate", "adapter-ticket", "gate-ticket-create"),
                workflow_edge("edge-gate-record", "gate-ticket-create", "output-triage"),
            ],
            vec![workflow_test(
                "test-triage-path",
                "Triage path exists",
                vec![
                    "source-request-intake",
                    "decision-policy",
                    "adapter-ticket",
                    "gate-ticket-create",
                ],
            )],
        ),
        "product-feedback-router-agent" => (
            "Product feedback router",
            "scheduled_workflow",
            "hybrid",
            vec![
                workflow_node(
                    "source-feedback",
                    "source",
                    "Feedback sources",
                    70,
                    180,
                    "Input",
                    "multi",
                ),
                workflow_node(
                    "function-dedupe",
                    "function",
                    "Dedupe feedback",
                    310,
                    170,
                    "Runtime",
                    "local",
                ),
                workflow_node(
                    "model-classify",
                    "model_call",
                    "Classify themes",
                    550,
                    170,
                    "Model",
                    "reasoning",
                ),
                workflow_node(
                    "output-priority",
                    "output",
                    "Weekly signal",
                    820,
                    180,
                    "Output",
                    "weekly",
                ),
            ],
            vec![
                workflow_edge("edge-feedback-dedupe", "source-feedback", "function-dedupe"),
                workflow_edge("edge-dedupe-model", "function-dedupe", "model-classify"),
                workflow_edge("edge-model-signal", "model-classify", "output-priority"),
            ],
            vec![workflow_test(
                "test-feedback-path",
                "Feedback router path exists",
                vec!["source-feedback", "function-dedupe", "model-classify"],
            )],
        ),
        "weekly-metrics-reporting-agent" => (
            "Weekly metrics reporting agent",
            "scheduled_workflow",
            "hybrid",
            vec![
                workflow_node(
                    "adapter-metrics",
                    "adapter",
                    "Pull metrics",
                    80,
                    180,
                    "Connector",
                    "analytics",
                ),
                workflow_node(
                    "function-chart",
                    "function",
                    "Generate charts",
                    320,
                    170,
                    "Runtime",
                    "local",
                ),
                workflow_node(
                    "model-narrative",
                    "model_call",
                    "Draft narrative",
                    560,
                    170,
                    "Model",
                    "reasoning",
                ),
                workflow_node(
                    "output-report",
                    "output",
                    "Weekly report",
                    830,
                    180,
                    "Output",
                    "scheduled",
                ),
            ],
            vec![
                workflow_edge("edge-metrics-chart", "adapter-metrics", "function-chart"),
                workflow_edge("edge-chart-narrative", "function-chart", "model-narrative"),
                workflow_edge("edge-narrative-report", "model-narrative", "output-report"),
            ],
            vec![workflow_test(
                "test-metrics-path",
                "Metrics report path exists",
                vec!["adapter-metrics", "function-chart", "model-narrative"],
            )],
        ),
        "month-end-accounting-close-agent" => (
            "Month-end accounting close agent",
            "scheduled_workflow",
            "hybrid",
            vec![
                workflow_node(
                    "adapter-close-source",
                    "adapter",
                    "Collect close data",
                    70,
                    185,
                    "Connector",
                    "accounting_system",
                ),
                workflow_node(
                    "function-reconcile",
                    "function",
                    "Reconcile entries",
                    310,
                    170,
                    "Runtime",
                    "local",
                ),
                workflow_node(
                    "model-variance",
                    "model_call",
                    "Variance analysis",
                    550,
                    170,
                    "Model",
                    "reasoning",
                ),
                workflow_node(
                    "gate-financial-write",
                    "human_gate",
                    "Financial approval",
                    800,
                    175,
                    "Gate",
                    "approval",
                ),
                workflow_node(
                    "output-workpapers",
                    "output",
                    "Workpaper bundle",
                    1050,
                    185,
                    "Output",
                    "close",
                ),
            ],
            vec![
                workflow_edge(
                    "edge-source-reconcile",
                    "adapter-close-source",
                    "function-reconcile",
                ),
                workflow_edge(
                    "edge-reconcile-variance",
                    "function-reconcile",
                    "model-variance",
                ),
                workflow_edge(
                    "edge-variance-gate",
                    "model-variance",
                    "gate-financial-write",
                ),
                workflow_edge(
                    "edge-gate-workpapers",
                    "gate-financial-write",
                    "output-workpapers",
                ),
            ],
            vec![workflow_test(
                "test-close-path",
                "Close path exists",
                vec![
                    "adapter-close-source",
                    "function-reconcile",
                    "model-variance",
                    "gate-financial-write",
                ],
            )],
        ),
        "slack-qa-agent" => (
            "Slack Q&A agent",
            "event_workflow",
            "hybrid",
            vec![
                workflow_node(
                    "adapter-slack-question",
                    "adapter",
                    "Slack question",
                    70,
                    180,
                    "Connector",
                    "slack",
                ),
                workflow_node(
                    "adapter-docs",
                    "adapter",
                    "Docs lookup",
                    310,
                    170,
                    "Connector",
                    "docs",
                ),
                workflow_node(
                    "model-answer",
                    "model_call",
                    "Answer question",
                    550,
                    170,
                    "Model",
                    "reasoning",
                ),
                workflow_node(
                    "decision-novel",
                    "decision",
                    "Novel issue?",
                    800,
                    175,
                    "Paths",
                    "2",
                ),
                workflow_node(
                    "output-qa",
                    "output",
                    "Answer or ticket proposal",
                    1050,
                    185,
                    "Output",
                    "response",
                ),
            ],
            vec![
                workflow_edge("edge-slack-docs", "adapter-slack-question", "adapter-docs"),
                workflow_edge("edge-docs-answer", "adapter-docs", "model-answer"),
                workflow_edge("edge-answer-decision", "model-answer", "decision-novel"),
                workflow_edge("edge-decision-output", "decision-novel", "output-qa"),
            ],
            vec![workflow_test(
                "test-qa-path",
                "Q&A path exists",
                vec![
                    "adapter-slack-question",
                    "adapter-docs",
                    "model-answer",
                    "decision-novel",
                ],
            )],
        ),
        "heavy-repo-test-engineer" => (
            "Repo test engineer",
            "evaluation_workflow",
            "local",
            vec![
                workflow_node(
                    "source-workspace",
                    "source",
                    "Workspace source",
                    70,
                    180,
                    "Input",
                    "repo",
                ),
                workflow_function_node(
                    "function-file-scan",
                    "File scanner",
                    300,
                    170,
                    "return { result: { files: ['package.json'], findings: [] } };",
                ),
                workflow_node(
                    "model-test-diagnosis",
                    "model_call",
                    "Test diagnosis",
                    540,
                    170,
                    "Model",
                    "reasoning",
                ),
                workflow_node(
                    "test-diagnosis",
                    "test_assertion",
                    "Diagnosis exists",
                    790,
                    180,
                    "Tests",
                    "mapped",
                ),
                workflow_node(
                    "output-repair-report",
                    "output",
                    "Repair report",
                    1040,
                    185,
                    "Output",
                    "proposal",
                ),
            ],
            vec![
                workflow_edge(
                    "edge-workspace-scan",
                    "source-workspace",
                    "function-file-scan",
                ),
                workflow_edge(
                    "edge-scan-diagnosis",
                    "function-file-scan",
                    "model-test-diagnosis",
                ),
                workflow_edge(
                    "edge-diagnosis-test",
                    "model-test-diagnosis",
                    "test-diagnosis",
                ),
                workflow_edge("edge-test-report", "test-diagnosis", "output-repair-report"),
            ],
            vec![workflow_test(
                "test-heavy-repo-path",
                "Repo test workflow path exists",
                vec![
                    "source-workspace",
                    "function-file-scan",
                    "model-test-diagnosis",
                ],
            )],
        ),
        "heavy-mcp-research-operator" => (
            "MCP research operator",
            "agent_workflow",
            "hybrid",
            vec![
                workflow_node(
                    "source-research-prompt",
                    "source",
                    "Research prompt",
                    70,
                    180,
                    "Input",
                    "prompt",
                ),
                workflow_plugin_node("plugin-search", "Search tool", 310, 170, "web_search_mcp"),
                workflow_function_node(
                    "function-validate-sources",
                    "Validate sources",
                    550,
                    170,
                    "return { result: { sourceCount: 1, valid: true } };",
                ),
                workflow_node(
                    "model-research-synthesis",
                    "model_call",
                    "Synthesize answer",
                    790,
                    170,
                    "Model",
                    "reasoning",
                ),
                workflow_node(
                    "output-research",
                    "output",
                    "Research brief",
                    1060,
                    185,
                    "Output",
                    "cited",
                ),
            ],
            vec![
                workflow_edge(
                    "edge-prompt-search",
                    "source-research-prompt",
                    "plugin-search",
                ),
                workflow_edge(
                    "edge-search-validate",
                    "plugin-search",
                    "function-validate-sources",
                ),
                workflow_edge(
                    "edge-validate-synthesis",
                    "function-validate-sources",
                    "model-research-synthesis",
                ),
                workflow_edge(
                    "edge-synthesis-brief",
                    "model-research-synthesis",
                    "output-research",
                ),
            ],
            vec![workflow_test(
                "test-heavy-research-path",
                "Research operator path exists",
                vec![
                    "source-research-prompt",
                    "plugin-search",
                    "function-validate-sources",
                ],
            )],
        ),
        "heavy-connector-triage" => (
            "Connector triage agent",
            "event_workflow",
            "hybrid",
            vec![
                workflow_node(
                    "source-support-event",
                    "source",
                    "Support event",
                    70,
                    185,
                    "Input",
                    "event",
                ),
                workflow_adapter_node(
                    "adapter-support-read",
                    "Support read",
                    300,
                    175,
                    "support",
                    false,
                ),
                workflow_node(
                    "decision-urgency",
                    "decision",
                    "Urgency branch",
                    540,
                    170,
                    "Paths",
                    "2",
                ),
                workflow_adapter_node(
                    "adapter-ticket-draft",
                    "Ticket draft",
                    790,
                    170,
                    "it_ticketing",
                    true,
                ),
                workflow_node(
                    "gate-ticket-write",
                    "human_gate",
                    "Write approval",
                    1030,
                    175,
                    "Gate",
                    "approval",
                ),
                workflow_node(
                    "output-ticket-plan",
                    "output",
                    "Ticket plan",
                    1280,
                    185,
                    "Output",
                    "ticket",
                ),
            ],
            vec![
                workflow_edge(
                    "edge-event-support",
                    "source-support-event",
                    "adapter-support-read",
                ),
                workflow_edge(
                    "edge-support-urgency",
                    "adapter-support-read",
                    "decision-urgency",
                ),
                workflow_edge_port(
                    "edge-urgency-ticket",
                    "decision-urgency",
                    "adapter-ticket-draft",
                    "left",
                ),
                workflow_edge(
                    "edge-ticket-gate-heavy",
                    "adapter-ticket-draft",
                    "gate-ticket-write",
                ),
                workflow_edge(
                    "edge-gate-ticket-plan",
                    "gate-ticket-write",
                    "output-ticket-plan",
                ),
            ],
            vec![workflow_test(
                "test-heavy-triage-path",
                "Connector triage path exists",
                vec![
                    "adapter-support-read",
                    "decision-urgency",
                    "adapter-ticket-draft",
                ],
            )],
        ),
        "heavy-financial-close" => (
            "Financial close assistant",
            "scheduled_workflow",
            "hybrid",
            vec![
                workflow_adapter_node(
                    "adapter-close-collect",
                    "Close data",
                    70,
                    185,
                    "accounting_system",
                    false,
                ),
                workflow_function_node(
                    "function-reconcile-heavy",
                    "Reconciliation",
                    310,
                    170,
                    "return { result: { balanced: true, exceptions: [] } };",
                ),
                workflow_function_node(
                    "function-variance-heavy",
                    "Variance calc",
                    550,
                    170,
                    "return { result: { materialVariances: [] } };",
                ),
                workflow_node(
                    "model-close-analysis",
                    "model_call",
                    "Close analysis",
                    790,
                    170,
                    "Model",
                    "reasoning",
                ),
                workflow_node(
                    "gate-close-write",
                    "human_gate",
                    "Financial write approval",
                    1030,
                    175,
                    "Gate",
                    "approval",
                ),
                workflow_node(
                    "output-close-workpapers",
                    "output",
                    "Workpapers",
                    1280,
                    185,
                    "Output",
                    "bundle",
                ),
            ],
            vec![
                workflow_edge(
                    "edge-close-collect-reconcile",
                    "adapter-close-collect",
                    "function-reconcile-heavy",
                ),
                workflow_edge(
                    "edge-reconcile-variance-heavy",
                    "function-reconcile-heavy",
                    "function-variance-heavy",
                ),
                workflow_edge(
                    "edge-variance-analysis-heavy",
                    "function-variance-heavy",
                    "model-close-analysis",
                ),
                workflow_edge(
                    "edge-analysis-gate-heavy",
                    "model-close-analysis",
                    "gate-close-write",
                ),
                workflow_edge(
                    "edge-gate-workpapers-heavy",
                    "gate-close-write",
                    "output-close-workpapers",
                ),
            ],
            vec![workflow_test(
                "test-heavy-close-path",
                "Financial close path exists",
                vec![
                    "adapter-close-collect",
                    "function-reconcile-heavy",
                    "gate-close-write",
                ],
            )],
        ),
        "heavy-media-transform" => (
            "Media transform agent",
            "agent_workflow",
            "local",
            vec![
                workflow_node(
                    "source-media-jpg",
                    "source",
                    "Media source",
                    70,
                    180,
                    "Input",
                    "image",
                ),
                workflow_node(
                    "model-media-vision",
                    "model_call",
                    "Vision trace",
                    310,
                    170,
                    "Model",
                    "vision",
                ),
                workflow_function_node(
                    "function-svg-trace",
                    "SVG tracing",
                    550,
                    170,
                    "return { result: { svg: '<svg xmlns=\"http://www.w3.org/2000/svg\" />' } };",
                ),
                workflow_node(
                    "output-media-svg",
                    "output",
                    "SVG output",
                    820,
                    185,
                    "Output",
                    "svg",
                ),
            ],
            vec![
                workflow_edge(
                    "edge-media-vision",
                    "source-media-jpg",
                    "model-media-vision",
                ),
                workflow_edge(
                    "edge-vision-svg-trace",
                    "model-media-vision",
                    "function-svg-trace",
                ),
                workflow_edge("edge-svg-output", "function-svg-trace", "output-media-svg"),
            ],
            vec![workflow_test(
                "test-heavy-media-path",
                "Media transform path exists",
                vec![
                    "source-media-jpg",
                    "model-media-vision",
                    "function-svg-trace",
                ],
            )],
        ),
        "heavy-scheduled-reporter" => (
            "Long-running scheduled reporter",
            "scheduled_workflow",
            "hybrid",
            vec![
                workflow_node(
                    "source-schedule",
                    "source",
                    "Weekly trigger",
                    70,
                    185,
                    "Input",
                    "schedule",
                ),
                workflow_adapter_node(
                    "adapter-report-data",
                    "Data pull",
                    300,
                    175,
                    "analytics",
                    false,
                ),
                workflow_function_node(
                    "function-chart-payload",
                    "Chart payload",
                    540,
                    170,
                    "return { result: { series: [], chartType: 'line' } };",
                ),
                workflow_node(
                    "model-report-narrative",
                    "model_call",
                    "Narrative",
                    790,
                    170,
                    "Model",
                    "reasoning",
                ),
                workflow_node(
                    "output-scheduled-report",
                    "output",
                    "Scheduled report",
                    1060,
                    185,
                    "Output",
                    "report",
                ),
            ],
            vec![
                workflow_edge(
                    "edge-schedule-data",
                    "source-schedule",
                    "adapter-report-data",
                ),
                workflow_edge(
                    "edge-data-chart",
                    "adapter-report-data",
                    "function-chart-payload",
                ),
                workflow_edge(
                    "edge-chart-narrative-heavy",
                    "function-chart-payload",
                    "model-report-narrative",
                ),
                workflow_edge(
                    "edge-narrative-report-heavy",
                    "model-report-narrative",
                    "output-scheduled-report",
                ),
            ],
            vec![workflow_test(
                "test-heavy-reporter-path",
                "Scheduled reporter path exists",
                vec![
                    "source-schedule",
                    "adapter-report-data",
                    "function-chart-payload",
                ],
            )],
        ),
        "heavy-self-improving-proposal" => (
            "Self-improving workflow proposal",
            "agent_workflow",
            "local",
            vec![
                workflow_node(
                    "source-workflow-under-review",
                    "source",
                    "Workflow under review",
                    70,
                    185,
                    "Input",
                    "graph",
                ),
                workflow_function_node(
                    "function-gap-scan",
                    "Gap scanner",
                    310,
                    170,
                    "return { result: { boundedTargets: ['model-review'], issues: [] } };",
                ),
                workflow_node(
                    "model-review",
                    "model_call",
                    "Improvement proposal",
                    550,
                    170,
                    "Model",
                    "reasoning",
                ),
                workflow_node(
                    "gate-apply-proposal",
                    "human_gate",
                    "Apply approval",
                    800,
                    175,
                    "Gate",
                    "approval",
                ),
                workflow_node(
                    "output-improvement-proposal",
                    "output",
                    "Proposal diff",
                    1050,
                    185,
                    "Output",
                    "diff",
                ),
            ],
            vec![
                workflow_edge(
                    "edge-review-gap-scan",
                    "source-workflow-under-review",
                    "function-gap-scan",
                ),
                workflow_edge("edge-gap-proposal", "function-gap-scan", "model-review"),
                workflow_edge(
                    "edge-proposal-gate-heavy",
                    "model-review",
                    "gate-apply-proposal",
                ),
                workflow_edge(
                    "edge-gate-diff-heavy",
                    "gate-apply-proposal",
                    "output-improvement-proposal",
                ),
            ],
            vec![workflow_test(
                "test-heavy-self-improving-path",
                "Self-improving proposal path exists",
                vec![
                    "source-workflow-under-review",
                    "function-gap-scan",
                    "gate-apply-proposal",
                ],
            )],
        ),
        _ => return None,
    };
    Some(seed)
}

pub(super) fn workflow_project_from_template(
    template_id: &str,
    name_override: Option<&str>,
    workflow_path: &Path,
) -> Result<(WorkflowProject, Vec<WorkflowTestCase>), String> {
    let Some((default_name, workflow_kind, execution_mode, nodes, edges, tests)) =
        template_workflow_seed(template_id)
    else {
        return Err(format!("Unknown workflow template '{}'.", template_id));
    };
    let name = name_override.unwrap_or(default_name);
    let mut workflow = default_workflow_project(name, workflow_kind, execution_mode, workflow_path);
    workflow.nodes = nodes;
    workflow.edges = edges;
    if let Some(meta) = workflow.global_config.get_mut("meta") {
        meta["description"] = json!(format!("Workflow template: {}", template_id));
    }
    if matches!(
        template_id,
        "coding.template.build" | "coding.template.debug" | "coding.template.review"
    ) {
        if let Some(config) = workflow.global_config.as_object_mut() {
            config.insert(
                "codingRoute".to_string(),
                workflow_coding_route_contract(template_id),
            );
        }
    }
    Ok((workflow, tests))
}
