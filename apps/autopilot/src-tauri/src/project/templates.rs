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
        "model_call" => json!({
            "modelRef": if metric_value == "vision" { "vision" } else { "reasoning" },
            "prompt": format!("Run the {} step.", name)
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
    ];
    for (node_type, group, label) in canonical_workflow_node_types() {
        if matches!(
            node_type,
            "source" | "trigger" | "adapter" | "plugin_tool" | "output"
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
        "human_gate" | "proposal" => "write",
        _ => "none",
    };
    let requires_approval = matches!(node_type, "human_gate" | "proposal");
    let sandboxed = node_type == "function";
    let supports_dry_run = matches!(node_type, "function" | "adapter" | "plugin_tool");
    let supports_mock_binding = matches!(
        node_type,
        "model_binding" | "parser" | "adapter" | "plugin_tool" | "subgraph"
    );
    let schema_required = matches!(
        node_type,
        "function"
            | "model_call"
            | "parser"
            | "adapter"
            | "plugin_tool"
            | "subgraph"
            | "output"
            | "test_assertion"
    );
    let connection_classes: Vec<&str> = match node_type {
        "model_binding" => vec!["model"],
        "model_call" => vec!["data", "model", "memory", "tool", "parser"],
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
    Ok((workflow, tests))
}
