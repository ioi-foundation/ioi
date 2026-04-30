#[test]
fn workflow_function_dry_run_executes_in_sandbox_and_records_evidence() {
    let root = temp_root("function-dry-run");
    let bundle = create_workflow_from_template(CreateWorkflowFromTemplateRequest {
        project_root: root.display().to_string(),
        template_id: "repo-function-test".to_string(),
        name: Some("Function Sandbox".to_string()),
    })
    .expect("template should instantiate");

    let mut workflow = bundle.workflow.clone();
    let function_node = workflow
        .nodes
        .iter_mut()
        .find(|node| workflow_node_id(node).as_deref() == Some("function-summarize"))
        .expect("function node exists");
    let logic = logic_mut(function_node);
    logic.insert(
        "functionBinding".to_string(),
        json!({
            "language": "javascript",
            "code": "console.log('scan-ok'); return { summary: 'ok', count: input.items.length };",
            "inputSchema": { "type": "object" },
            "outputSchema": { "type": "object", "required": ["summary", "count"] },
            "sandboxPolicy": {
                "timeoutMs": 1000,
                "memoryMb": 64,
                "outputLimitBytes": 4096,
                "permissions": []
            },
            "testInput": { "items": [1, 2, 3] }
        }),
    );
    save_workflow_project(bundle.workflow_path.clone(), workflow).expect("workflow should save");

    let run = dry_run_workflow_function(
        bundle.workflow_path,
        "function-summarize".to_string(),
        Some(json!({ "items": [1, 2, 3] })),
    )
    .expect("function dry run should execute");
    assert_eq!(run.summary.status, "passed");
    assert_eq!(
        run.node_runs[0]
            .input
            .as_ref()
            .and_then(|input| input.pointer("/items/2"))
            .and_then(Value::as_i64),
        Some(3)
    );
    let output = run.node_runs[0].output.as_ref().expect("node output");
    assert_eq!(
        output.pointer("/result/summary").and_then(Value::as_str),
        Some("ok")
    );
    assert_eq!(
        output.pointer("/result/count").and_then(Value::as_i64),
        Some(3)
    );
    assert!(output
        .get("stdout")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .contains("scan-ok"));
    assert!(run
        .verification_evidence
        .iter()
        .any(|evidence| evidence.node_id == "function-summarize" && evidence.status == "passed"));
}

#[test]
fn workflow_function_materializes_and_executes_file_backed_source() {
    let root = temp_root("function-file-backed");
    let bundle = create_workflow_from_template(CreateWorkflowFromTemplateRequest {
        project_root: root.display().to_string(),
        template_id: "repo-function-test".to_string(),
        name: Some("File Backed Function".to_string()),
    })
    .expect("template should instantiate");

    let materialized = materialize_workflow_function(
        bundle.workflow_path.clone(),
        "function-summarize".to_string(),
        None,
    )
    .expect("function should materialize");
    let function_node = materialized
        .workflow
        .nodes
        .iter()
        .find(|node| workflow_node_id(node).as_deref() == Some("function-summarize"))
        .expect("function node exists");
    let function_ref = workflow_node_logic(function_node)
        .pointer("/functionBinding/functionRef")
        .cloned()
        .expect("function ref should exist");
    let source_path = function_ref
        .get("sourcePath")
        .and_then(Value::as_str)
        .expect("source path should exist");
    assert_eq!(
        function_ref
            .get("codeHash")
            .and_then(Value::as_str)
            .map(str::len),
        Some(64)
    );
    assert_eq!(
        function_ref
            .pointer("/dependencyManifest/runtime")
            .and_then(Value::as_str),
        Some("node")
    );
    fs::write(
        source_path,
        "return { summary: 'file-backed', count: input.items.length };",
    )
    .expect("function source should be editable");

    let run = dry_run_workflow_function(
        bundle.workflow_path,
        "function-summarize".to_string(),
        Some(json!({ "items": [1, 2, 3, 4] })),
    )
    .expect("file-backed function should execute");
    assert_eq!(run.summary.status, "passed");
    let output = run.node_runs[0].output.as_ref().expect("node output");
    assert_eq!(
        output.pointer("/result/summary").and_then(Value::as_str),
        Some("file-backed")
    );
    assert_eq!(
        output.get("codeHash").and_then(Value::as_str).map(str::len),
        Some(64)
    );
}

#[test]
fn workflow_function_blocks_undeclared_filesystem_access() {
    let root = temp_root("unsafe-function");
    let bundle = create_workflow_from_template(CreateWorkflowFromTemplateRequest {
        project_root: root.display().to_string(),
        template_id: "repo-function-test".to_string(),
        name: Some("Unsafe Function".to_string()),
    })
    .expect("template should instantiate");

    let mut workflow = bundle.workflow.clone();
    let function_node = workflow
        .nodes
        .iter_mut()
        .find(|node| workflow_node_id(node).as_deref() == Some("function-summarize"))
        .expect("function node exists");
    logic_mut(function_node).insert(
            "functionBinding".to_string(),
            json!({
                "language": "javascript",
                "code": "const fs = require('fs'); return { summary: fs.readFileSync('/etc/passwd', 'utf8') };",
                "outputSchema": { "type": "object", "required": ["summary"] },
                "sandboxPolicy": {
                    "timeoutMs": 1000,
                    "memoryMb": 64,
                    "outputLimitBytes": 4096,
                    "permissions": []
                },
                "testInput": {}
            }),
        );
    save_workflow_project(bundle.workflow_path.clone(), workflow).expect("workflow should save");

    let validation =
        validate_workflow_bundle(bundle.workflow_path.clone()).expect("validation should run");
    assert_eq!(validation.status, "blocked");
    assert!(validation
        .execution_readiness_issues
        .iter()
        .any(|issue| issue.code == "unsafe_function_permission"));
    let run =
        dry_run_workflow_function(bundle.workflow_path, "function-summarize".to_string(), None)
            .expect("dry run should return structured blocker");
    assert_eq!(run.summary.status, "blocked");
    assert!(run.node_runs[0]
        .error
        .as_deref()
        .unwrap_or_default()
        .contains("filesystem"));
}

#[test]
fn workflow_function_validates_input_schema_and_captures_stderr() {
    let root = temp_root("function-input-schema");
    let bundle = create_workflow_from_template(CreateWorkflowFromTemplateRequest {
        project_root: root.display().to_string(),
        template_id: "repo-function-test".to_string(),
        name: Some("Function Input Schema".to_string()),
    })
    .expect("template should instantiate");

    let mut workflow = bundle.workflow.clone();
    let function_node = workflow
        .nodes
        .iter_mut()
        .find(|node| workflow_node_id(node).as_deref() == Some("function-summarize"))
        .expect("function node exists");
    logic_mut(function_node).insert(
        "functionBinding".to_string(),
        json!({
            "language": "javascript",
            "code": "console.error('schema-ok'); return { summary: input.title.toUpperCase() };",
            "inputSchema": { "type": "object", "required": ["title"] },
            "outputSchema": { "type": "object", "required": ["summary"] },
            "sandboxPolicy": {
                "timeoutMs": 1000,
                "memoryMb": 64,
                "outputLimitBytes": 4096,
                "permissions": []
            },
            "testInput": { "title": "ready" }
        }),
    );
    save_workflow_project(bundle.workflow_path.clone(), workflow).expect("workflow should save");

    let run = dry_run_workflow_function(
        bundle.workflow_path.clone(),
        "function-summarize".to_string(),
        Some(json!({ "title": "ready" })),
    )
    .expect("valid function input should run");
    assert_eq!(run.summary.status, "passed");
    let output = run.node_runs[0].output.as_ref().expect("node output");
    assert_eq!(
        output.pointer("/result/summary").and_then(Value::as_str),
        Some("READY")
    );
    assert!(output
        .get("stderr")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .contains("schema-ok"));

    let blocked = dry_run_workflow_function(
        bundle.workflow_path,
        "function-summarize".to_string(),
        Some(json!({ "body": "missing title" })),
    )
    .expect("invalid function input should return a structured blocker");
    assert_eq!(blocked.summary.status, "blocked");
    assert!(blocked.node_runs[0]
        .error
        .as_deref()
        .unwrap_or_default()
        .contains("Function input failed schema validation"));
}

#[test]
fn workflow_function_blocks_unsupported_dependency_manifest() {
    let root = temp_root("function-dependencies");
    let bundle = create_workflow_from_template(CreateWorkflowFromTemplateRequest {
        project_root: root.display().to_string(),
        template_id: "repo-function-test".to_string(),
        name: Some("Function Dependency Manifest".to_string()),
    })
    .expect("template should instantiate");

    let mut materialized = materialize_workflow_function(
        bundle.workflow_path.clone(),
        "function-summarize".to_string(),
        None,
    )
    .expect("function should materialize");
    let function_node = materialized
        .workflow
        .nodes
        .iter_mut()
        .find(|node| workflow_node_id(node).as_deref() == Some("function-summarize"))
        .expect("function node exists");
    logic_mut(function_node)
        .get_mut("functionBinding")
        .expect("function binding should exist")
        .pointer_mut("/functionRef/dependencyManifest/dependencies")
        .expect("dependency manifest should exist")
        .as_object_mut()
        .expect("dependencies should be an object")
        .insert("lodash".to_string(), json!("^4.17.21"));
    save_workflow_project(bundle.workflow_path.clone(), materialized.workflow)
        .expect("workflow should save");

    let validation =
        validate_workflow_bundle(bundle.workflow_path.clone()).expect("validation should run");
    assert_eq!(validation.status, "blocked");
    assert!(validation
        .execution_readiness_issues
        .iter()
        .any(|issue| issue.code == "unsupported_function_dependency"));

    let run =
        dry_run_workflow_function(bundle.workflow_path, "function-summarize".to_string(), None)
            .expect("dependency issue should return a structured blocker");
    assert_eq!(run.summary.status, "blocked");
    assert!(run.node_runs[0]
        .error
        .as_deref()
        .unwrap_or_default()
        .contains("unsupported external dependencies"));
}

#[test]
fn workflow_function_blocks_output_over_sandbox_limit() {
    let root = temp_root("function-output-limit");
    let bundle = create_workflow_from_template(CreateWorkflowFromTemplateRequest {
        project_root: root.display().to_string(),
        template_id: "repo-function-test".to_string(),
        name: Some("Function Output Limit".to_string()),
    })
    .expect("template should instantiate");

    let mut workflow = bundle.workflow.clone();
    let function_node = workflow
        .nodes
        .iter_mut()
        .find(|node| workflow_node_id(node).as_deref() == Some("function-summarize"))
        .expect("function node exists");
    logic_mut(function_node).insert(
        "functionBinding".to_string(),
        json!({
            "language": "javascript",
            "code": "return { summary: 'oversized', payload: 'x'.repeat(5000) };",
            "outputSchema": { "type": "object", "required": ["summary", "payload"] },
            "sandboxPolicy": {
                "timeoutMs": 1000,
                "memoryMb": 64,
                "outputLimitBytes": 1024,
                "permissions": []
            },
            "testInput": {}
        }),
    );
    save_workflow_project(bundle.workflow_path.clone(), workflow).expect("workflow should save");

    let run =
        dry_run_workflow_function(bundle.workflow_path, "function-summarize".to_string(), None)
            .expect("oversized output should return a structured blocker");
    assert_eq!(run.summary.status, "blocked");
    assert!(run.node_runs[0]
        .error
        .as_deref()
        .unwrap_or_default()
        .contains("output limit"));
}

