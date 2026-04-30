// apps/autopilot/src-tauri/src/project.rs

use crate::agent_runtime_substrate::{
    completion_requirement_kinds, validate_action_edge, validate_workflow_connection_class,
    ActionBindingRef, ActionFrame, ActionKind, ActionPolicy, ActionSurface,
};
use regex::Regex;
use serde_json::{json, Value};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

mod commands;
mod explorer;
mod ids;
mod package;
mod paths;
mod runtime;
mod sidecars;
mod templates;
pub mod types;
mod validation;
pub use commands::*;
use explorer::*;
use ids::*;
use package::*;
use paths::*;
use runtime::*;
use sidecars::*;
use templates::*;
pub use types::*;
use validation::*;

fn default_gitignore() -> &'static str {
    "node_modules/\ndist/\ntarget/\n.DS_Store\n.env\nioi-data/\n.autopilot/\n"
}

fn normalize_legacy_workflow_output_nodes(workflow: &mut WorkflowProject) {
    for node in &mut workflow.nodes {
        let Some(node_object) = node.as_object_mut() else {
            continue;
        };
        let was_legacy_artifact = node_object
            .get("type")
            .and_then(Value::as_str)
            .map(|node_type| node_type == "artifact")
            .unwrap_or(false);
        if was_legacy_artifact {
            node_object.insert("type".to_string(), json!("output"));
        }
        if !was_legacy_artifact
            && node_object
                .get("type")
                .and_then(Value::as_str)
                .map(|node_type| node_type != "output")
                .unwrap_or(true)
        {
            continue;
        }
        if let Some(io_types) = node_object
            .get_mut("ioTypes")
            .and_then(Value::as_object_mut)
        {
            if io_types
                .get("out")
                .and_then(Value::as_str)
                .map(|value| value == "file")
                .unwrap_or(false)
            {
                io_types.insert("out".to_string(), json!("output_bundle"));
            }
        }
        let Some(logic) = node_object
            .get_mut("config")
            .and_then(Value::as_object_mut)
            .and_then(|config| config.get_mut("logic"))
            .and_then(Value::as_object_mut)
        else {
            continue;
        };
        logic
            .entry("rendererRef".to_string())
            .or_insert_with(|| json!({ "rendererId": "markdown", "displayMode": "inline" }));
        let legacy_path = logic
            .remove("path")
            .and_then(|value| value.as_str().map(str::to_string))
            .filter(|value| !value.trim().is_empty());
        if let Some(materialization) = logic
            .get_mut("materialization")
            .and_then(Value::as_object_mut)
        {
            if let Some(path) = legacy_path {
                materialization.insert("enabled".to_string(), json!(true));
                materialization.insert("assetPath".to_string(), json!(path));
                materialization
                    .entry("assetKind".to_string())
                    .or_insert_with(|| json!("file"));
            }
        } else {
            logic.insert(
                "materialization".to_string(),
                match legacy_path {
                    Some(path) => json!({
                        "enabled": true,
                        "assetPath": path,
                        "assetKind": "file"
                    }),
                    None => json!({ "enabled": false }),
                },
            );
        }
        logic
            .entry("deliveryTarget".to_string())
            .or_insert_with(|| json!({ "targetKind": "none" }));
        logic
            .entry("retentionPolicy".to_string())
            .or_insert_with(|| json!({ "retentionKind": "run_scoped" }));
        logic
            .entry("versioning".to_string())
            .or_insert_with(|| json!({ "enabled": true }));
    }
}

fn workflow_validation_blockers(result: &WorkflowValidationResult) -> Vec<WorkflowValidationIssue> {
    let mut seen = std::collections::BTreeSet::new();
    let mut blockers = Vec::new();
    for issue in result
        .errors
        .iter()
        .chain(result.execution_readiness_issues.iter())
        .chain(result.missing_config.iter())
        .chain(result.connector_binding_issues.iter())
        .chain(result.verification_issues.iter())
    {
        let key = format!(
            "{}\n{}\n{}",
            issue.node_id.clone().unwrap_or_default(),
            issue.code,
            issue.message
        );
        if seen.insert(key) {
            blockers.push(issue.clone());
        }
    }
    blockers
}

fn load_workflow_bundle_from_path(workflow_path: &Path) -> Result<WorkflowWorkbenchBundle, String> {
    let mut workflow: WorkflowProject = read_json_file(workflow_path)?;
    normalize_legacy_workflow_output_nodes(&mut workflow);
    let tests_path = workflow_tests_path(workflow_path);
    let proposals_dir = workflow_proposals_dir(workflow_path);
    let runs_path = workflow_runs_path(workflow_path);
    let tests = load_workflow_tests(&tests_path)?;
    let proposals = load_workflow_proposals(&proposals_dir)?;
    let runs = load_workflow_runs(&runs_path)?;
    Ok(WorkflowWorkbenchBundle {
        workflow_path: workflow_path.display().to_string(),
        tests_path: tests_path.display().to_string(),
        proposals_dir: proposals_dir.display().to_string(),
        workflow,
        tests,
        proposals,
        runs,
    })
}

fn inspect_project_root(root: &PathBuf) -> ProjectShellSnapshot {
    let tree = build_tree(root, root, 0);
    let mut artifacts = Vec::new();
    gather_artifacts(root, root, 0, &mut artifacts);

    ProjectShellSnapshot {
        root_path: root.display().to_string(),
        git: inspect_git(root),
        tree,
        artifacts,
    }
}

fn workflow_json_type_matches(expected_type: &str, value: &Value) -> bool {
    match expected_type {
        "object" => value.is_object(),
        "array" => value.is_array(),
        "string" => value.is_string(),
        "number" => value.is_number(),
        "integer" => value.as_i64().is_some() || value.as_u64().is_some(),
        "boolean" => value.is_boolean(),
        "null" => value.is_null(),
        _ => true,
    }
}

fn workflow_json_satisfies_schema(schema: &Value, value: &Value) -> Result<(), String> {
    if let Some(expected_type) = schema.get("type").and_then(Value::as_str) {
        if !workflow_json_type_matches(expected_type, value) {
            return Err(format!(
                "Expected JSON value of type '{}', but received {}.",
                expected_type,
                match value {
                    Value::Null => "null",
                    Value::Bool(_) => "boolean",
                    Value::Number(_) => "number",
                    Value::String(_) => "string",
                    Value::Array(_) => "array",
                    Value::Object(_) => "object",
                }
            ));
        }
    }

    let required = schema
        .get("required")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    for required_key in required {
        let Some(key) = required_key.as_str() else {
            continue;
        };
        if value.get(key).is_none() {
            return Err(format!("Output did not include required field '{}'.", key));
        }
    }

    if let (Some(properties), Some(object)) = (
        schema.get("properties").and_then(Value::as_object),
        value.as_object(),
    ) {
        for (key, property_schema) in properties {
            let Some(property_value) = object.get(key) else {
                continue;
            };
            workflow_json_satisfies_schema(property_schema, property_value)
                .map_err(|error| format!("Property '{}': {}", key, error))?;
        }
    }

    Ok(())
}

fn workflow_node_output_schema(node: &Value) -> Option<Value> {
    workflow_node_logic(node)
        .get("functionBinding")
        .and_then(|binding| binding.get("outputSchema"))
        .cloned()
        .or_else(|| {
            workflow_node_logic(node)
                .get("toolBinding")
                .and_then(|binding| binding.get("workflowTool"))
                .and_then(|tool| tool.get("resultSchema"))
                .cloned()
        })
        .or_else(|| {
            workflow_node_logic(node)
                .get("parserBinding")
                .and_then(|binding| binding.get("resultSchema"))
                .cloned()
        })
        .or_else(|| workflow_node_schema(node, "outputSchema"))
}

fn workflow_output_satisfies_test_schema(schema: &Value, output: &Value) -> Result<(), String> {
    match workflow_json_satisfies_schema(schema, output) {
        Ok(()) => Ok(()),
        Err(output_error) => {
            if let Some(result) = output.get("result") {
                workflow_json_satisfies_schema(schema, result).map_err(|result_error| {
                    format!(
                        "{} Result payload also failed schema validation: {}",
                        output_error, result_error
                    )
                })
            } else {
                Err(output_error)
            }
        }
    }
}

fn workflow_output_contains_expected(output: &Value, expected: &Value) -> bool {
    if expected.is_null() {
        return false;
    }
    let haystack = serde_json::to_string(output).unwrap_or_else(|_| output.to_string());
    let needle = expected.as_str().map(str::to_string).unwrap_or_else(|| {
        serde_json::to_string(expected).unwrap_or_else(|_| expected.to_string())
    });
    haystack.contains(&needle)
}

fn workflow_custom_assertion_result(
    expression: &str,
    input: Value,
) -> Result<(bool, String), String> {
    if expression.trim().is_empty() {
        return Err("Custom assertion expression is empty.".to_string());
    }
    let code = format!(
        r#"
const assertionResult = (() => {{
{expression}
}})();
if (typeof assertionResult === "boolean") {{
  return {{ passed: assertionResult, message: assertionResult ? "Custom assertion passed." : "Custom assertion returned false." }};
}}
if (assertionResult && typeof assertionResult === "object" && Object.prototype.hasOwnProperty.call(assertionResult, "passed")) {{
  return assertionResult;
}}
return {{ passed: Boolean(assertionResult), message: "Custom assertion returned a truthy/falsy value." }};
"#,
        expression = expression
    );
    let assertion_node = json!({
        "id": "custom-assertion",
        "type": "function",
        "name": "Custom assertion",
        "config": {
            "logic": {
                "functionBinding": {
                    "language": "javascript",
                    "code": code,
                    "outputSchema": {
                        "type": "object",
                        "required": ["passed"]
                    },
                    "sandboxPolicy": {
                        "timeoutMs": 1000,
                        "memoryMb": 64,
                        "outputLimitBytes": 32768,
                        "permissions": []
                    }
                }
            },
            "law": {}
        }
    });
    let output = execute_workflow_function_node(&assertion_node, input)?;
    let passed = output
        .pointer("/result/passed")
        .and_then(Value::as_bool)
        .or_else(|| output.get("result").and_then(Value::as_bool))
        .ok_or_else(|| "Custom assertion did not return a boolean 'passed' field.".to_string())?;
    let message = output
        .pointer("/result/message")
        .and_then(Value::as_str)
        .unwrap_or(if passed {
            "Custom assertion passed."
        } else {
            "Custom assertion failed."
        })
        .to_string();
    Ok((passed, message))
}

fn workflow_evaluate_value_assertion(
    assertion: &WorkflowTestAssertion,
    value: &Value,
    schema: Option<&Value>,
) -> Result<(bool, String), String> {
    match assertion.kind.as_str() {
        "schema_matches" => {
            let Some(schema_value) = assertion.expected.as_ref().or(schema) else {
                return Err(
                    "Schema assertion needs an expected schema or node output schema.".to_string(),
                );
            };
            workflow_output_satisfies_test_schema(schema_value, value)?;
            Ok((true, "Output matches schema.".to_string()))
        }
        "output_contains" => {
            let Some(expected) = assertion.expected.as_ref() else {
                return Err("Output contains assertion needs an expected value.".to_string());
            };
            let passed = workflow_output_contains_expected(value, expected);
            Ok((
                passed,
                if passed {
                    "Output contains expected value.".to_string()
                } else {
                    "Output did not contain expected value.".to_string()
                },
            ))
        }
        "custom" => workflow_custom_assertion_result(
            assertion
                .expression
                .as_deref()
                .ok_or_else(|| "Custom assertion needs an expression.".to_string())?,
            json!({
                "value": value,
                "expected": assertion.expected
            }),
        ),
        "node_exists" => Ok((!value.is_null(), "Value is present.".to_string())),
        other => Err(format!("Unsupported workflow assertion kind '{}'.", other)),
    }
}

fn workflow_test_needs_run(test: &WorkflowTestCase) -> bool {
    test.assertion.kind != "node_exists"
}

fn workflow_evaluate_test_case(
    test: &WorkflowTestCase,
    workflow: &WorkflowProject,
    node_ids: &std::collections::HashSet<String>,
    run_result: Option<&WorkflowRunResult>,
) -> WorkflowTestCaseRun {
    let missing = test
        .target_node_ids
        .iter()
        .filter(|node_id| !node_ids.contains(*node_id))
        .cloned()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return WorkflowTestCaseRun {
            test_id: test.id.clone(),
            status: "failed".to_string(),
            message: format!("Missing targets: {}", missing.join(", ")),
            covered_node_ids: test.target_node_ids.clone(),
        };
    }

    if test.assertion.kind == "node_exists" {
        return WorkflowTestCaseRun {
            test_id: test.id.clone(),
            status: "passed".to_string(),
            message: "Targets are present.".to_string(),
            covered_node_ids: test.target_node_ids.clone(),
        };
    }

    let Some(run) = run_result else {
        return WorkflowTestCaseRun {
            test_id: test.id.clone(),
            status: "blocked".to_string(),
            message: "Executable assertion needs a workflow run result.".to_string(),
            covered_node_ids: test.target_node_ids.clone(),
        };
    };
    for node_id in &test.target_node_ids {
        let Some(output) = run.final_state.node_outputs.get(node_id) else {
            return WorkflowTestCaseRun {
                test_id: test.id.clone(),
                status: if run.summary.status == "passed" {
                    "failed"
                } else {
                    "blocked"
                }
                .to_string(),
                message: format!(
                    "Node '{}' did not produce output before workflow status '{}'.",
                    node_id, run.summary.status
                ),
                covered_node_ids: test.target_node_ids.clone(),
            };
        };
        let schema = workflow_node_by_id(workflow, node_id).and_then(workflow_node_output_schema);
        match workflow_evaluate_value_assertion(&test.assertion, output, schema.as_ref()) {
            Ok((true, _message)) => {}
            Ok((false, message)) => {
                return WorkflowTestCaseRun {
                    test_id: test.id.clone(),
                    status: "failed".to_string(),
                    message: format!("Node '{}': {}", node_id, message),
                    covered_node_ids: test.target_node_ids.clone(),
                };
            }
            Err(error) => {
                return WorkflowTestCaseRun {
                    test_id: test.id.clone(),
                    status: "blocked".to_string(),
                    message: format!("Node '{}': {}", node_id, error),
                    covered_node_ids: test.target_node_ids.clone(),
                };
            }
        }
    }

    WorkflowTestCaseRun {
        test_id: test.id.clone(),
        status: "passed".to_string(),
        message: "Executable assertion passed for all target outputs.".to_string(),
        covered_node_ids: test.target_node_ids.clone(),
    }
}

#[cfg(test)]
mod workflow_project_tests;
