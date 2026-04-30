// apps/autopilot/src-tauri/src/project/validation.rs

use super::*;

pub(super) fn validate_workflow_project_bundle(
    workflow: &WorkflowProject,
    tests: &[WorkflowTestCase],
) -> WorkflowValidationResult {
    let node_ids = workflow
        .nodes
        .iter()
        .filter_map(|node| node.get("id").and_then(Value::as_str).map(str::to_string))
        .collect::<std::collections::BTreeSet<_>>();
    let action_kind_by_id = workflow
        .nodes
        .iter()
        .filter_map(|node| {
            Some((
                node.get("id")?.as_str()?.to_string(),
                ActionKind::from_node_type(node.get("type")?.as_str()?),
            ))
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    let mut errors = Vec::new();
    let mut warnings = Vec::new();
    let mut missing_config = Vec::new();
    let mut unsupported_runtime_nodes = Vec::new();
    let mut policy_required_nodes = Vec::new();
    let mut connector_binding_issues = Vec::new();
    let mut execution_readiness_issues = Vec::new();
    let mut verification_issues = Vec::new();
    let mut coverage_by_node_id = std::collections::BTreeMap::<String, Vec<String>>::new();

    for test in tests {
        for node_id in &test.target_node_ids {
            coverage_by_node_id
                .entry(node_id.clone())
                .or_default()
                .push(test.id.clone());
            if !node_ids.contains(node_id) {
                errors.push(WorkflowValidationIssue {
                    node_id: Some(node_id.clone()),
                    code: "missing_test_target".to_string(),
                    message: format!("Test '{}' targets a missing node.", test.name),
                });
            }
        }
    }

    for edge in &workflow.edges {
        let edge_id = edge.get("id").and_then(Value::as_str).unwrap_or("unknown");
        let from = workflow_edge_from(edge);
        let to = workflow_edge_to(edge);
        let Some(from_id) = from else {
            errors.push(WorkflowValidationIssue {
                node_id: None,
                code: "missing_edge_endpoint".to_string(),
                message: format!("Edge '{}' is missing a source node.", edge_id),
            });
            continue;
        };
        let Some(to_id) = to else {
            errors.push(WorkflowValidationIssue {
                node_id: None,
                code: "missing_edge_endpoint".to_string(),
                message: format!("Edge '{}' is missing a target node.", edge_id),
            });
            continue;
        };
        let Some(from_kind) = action_kind_by_id.get(&from_id) else {
            errors.push(WorkflowValidationIssue {
                node_id: Some(from_id.clone()),
                code: "missing_edge_endpoint".to_string(),
                message: format!("Edge '{}' references a missing source node.", edge_id),
            });
            continue;
        };
        let Some(to_kind) = action_kind_by_id.get(&to_id) else {
            errors.push(WorkflowValidationIssue {
                node_id: Some(to_id.clone()),
                code: "missing_edge_endpoint".to_string(),
                message: format!("Edge '{}' references a missing target node.", edge_id),
            });
            continue;
        };
        if let Err(issue) = validate_action_edge(&from_id, from_kind, &to_id, to_kind) {
            errors.push(WorkflowValidationIssue {
                node_id: issue.action_id,
                code: issue.code,
                message: issue.message,
            });
        }
        if let (Some(from_node), Some(to_node)) = (
            workflow_node_by_id(workflow, &from_id),
            workflow_node_by_id(workflow, &to_id),
        ) {
            if let Err(issue) = validate_workflow_edge_ports(edge, from_node, to_node) {
                errors.push(issue);
            }
        }
    }

    for node in &workflow.nodes {
        let node_id = node
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string();
        let node_type = node
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let action_kind = ActionKind::from_node_type(node_type);
        let logic = node
            .get("config")
            .and_then(|config| config.get("logic"))
            .cloned()
            .unwrap_or_else(|| json!({}));
        let law = node
            .get("config")
            .and_then(|config| config.get("law"))
            .cloned()
            .unwrap_or_else(|| json!({}));
        let action_metadata = workflow_node_action_metadata(node_type);
        let required_binding = action_metadata
            .get("requiredBinding")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty());

        execution_readiness_issues
            .extend(validate_workflow_expression_refs(workflow, node, &logic));

        if action_kind == ActionKind::Unknown {
            unsupported_runtime_nodes.push(node_id.clone());
            execution_readiness_issues.push(WorkflowValidationIssue {
                node_id: Some(node_id.clone()),
                code: "unsupported_node_kind".to_string(),
                message: format!(
                    "Workflow node type '{}' has no executor mapping.",
                    node_type
                ),
            });
        }
        if let Some(required_binding) = required_binding {
            if !workflow_node_satisfies_action_binding(workflow, node, &node_id, required_binding) {
                missing_config.push(WorkflowValidationIssue {
                    node_id: Some(node_id.clone()),
                    code: "missing_action_binding".to_string(),
                    message: format!(
                        "{} nodes require a configured {} binding.",
                        workflow_node_name(node),
                        required_binding
                    ),
                });
            }
        }
        if action_kind == ActionKind::Trigger {
            let trigger_kind = logic
                .get("triggerKind")
                .and_then(Value::as_str)
                .unwrap_or("manual");
            if trigger_kind == "scheduled"
                && logic
                    .get("cronSchedule")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .is_none()
            {
                missing_config.push(WorkflowValidationIssue {
                    node_id: Some(node_id.clone()),
                    code: "missing_trigger_schedule".to_string(),
                    message: "Scheduled triggers need a schedule.".to_string(),
                });
            }
            if trigger_kind == "event"
                && logic
                    .get("eventSourceRef")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .is_none()
            {
                missing_config.push(WorkflowValidationIssue {
                    node_id: Some(node_id.clone()),
                    code: "missing_trigger_event_source".to_string(),
                    message: "Event triggers need an event source reference.".to_string(),
                });
            }
        }
        if action_kind == ActionKind::State
            && logic
                .get("stateKey")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .is_none()
        {
            missing_config.push(WorkflowValidationIssue {
                node_id: Some(node_id.clone()),
                code: "missing_state_key".to_string(),
                message: "State nodes need a state key.".to_string(),
            });
        }
        if action_kind == ActionKind::Subgraph
            && logic
                .get("subgraphRef")
                .and_then(|ref_value| ref_value.get("workflowPath"))
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .is_none()
        {
            execution_readiness_issues.push(WorkflowValidationIssue {
                node_id: Some(node_id.clone()),
                code: "missing_subgraph_ref".to_string(),
                message: "Subgraph nodes need a workflow path binding.".to_string(),
            });
        }
        if action_kind == ActionKind::Proposal {
            let targets = logic
                .get("proposalAction")
                .and_then(|action| action.get("boundedTargets"))
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .filter_map(Value::as_str)
                        .filter(|item| !item.trim().is_empty())
                        .count()
                })
                .unwrap_or(0);
            if targets == 0 {
                missing_config.push(WorkflowValidationIssue {
                    node_id: Some(node_id.clone()),
                    code: "missing_proposal_bounds".to_string(),
                    message: "Proposal nodes need bounded targets.".to_string(),
                });
            }
            if !law
                .get("requireHumanGate")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                policy_required_nodes.push(node_id.clone());
                warnings.push(WorkflowValidationIssue {
                    node_id: Some(node_id.clone()),
                    code: "proposal_approval_required".to_string(),
                    message: "Proposal nodes require explicit approval.".to_string(),
                });
            }
        }
        if action_kind == ActionKind::ModelCall {
            let has_incoming_connection_class = |connection_class: &str| -> bool {
                workflow.edges.iter().any(|edge| {
                    workflow_edge_to(edge).as_deref() == Some(node_id.as_str())
                        && (workflow_edge_connection_class(edge).as_deref()
                            == Some(connection_class)
                            || workflow_edge_to_port(edge) == connection_class)
                })
            };
            if logic
                .get("modelRef")
                .and_then(Value::as_str)
                .map(str::is_empty)
                .unwrap_or(true)
                && !has_incoming_connection_class("model")
            {
                missing_config.push(WorkflowValidationIssue {
                    node_id: Some(node_id.clone()),
                    code: "missing_model_binding".to_string(),
                    message: "Model nodes need an inline model ref or attached Model Binding before runtime execution.".to_string(),
                });
            }
            let tool_use_mode = logic
                .get("modelBinding")
                .and_then(|binding| workflow_value_string(binding, "toolUseMode"))
                .or_else(|| workflow_value_string(&logic, "toolUseMode"))
                .unwrap_or_else(|| "none".to_string());
            if matches!(tool_use_mode.as_str(), "explicit" | "auto")
                && !has_incoming_connection_class("tool")
            {
                execution_readiness_issues.push(WorkflowValidationIssue {
                    node_id: Some(node_id.clone()),
                    code: "missing_model_tool_attachment".to_string(),
                    message:
                        "Model tool-use mode needs an attached tool port before runtime execution."
                            .to_string(),
                });
            }
            if logic
                .get("parserRef")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .is_some()
                && !has_incoming_connection_class("parser")
            {
                execution_readiness_issues.push(WorkflowValidationIssue {
                    node_id: Some(node_id.clone()),
                    code: "missing_model_parser_attachment".to_string(),
                    message: "Model parser references need an attached parser port.".to_string(),
                });
            }
            if logic
                .get("memoryKey")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .is_some()
                && !has_incoming_connection_class("memory")
            {
                execution_readiness_issues.push(WorkflowValidationIssue {
                    node_id: Some(node_id.clone()),
                    code: "missing_model_memory_attachment".to_string(),
                    message: "Model memory keys need an attached memory port.".to_string(),
                });
            }
            let structured_validation = logic
                .get("validateStructuredOutput")
                .and_then(Value::as_bool)
                .unwrap_or(false)
                || logic
                    .get("jsonMode")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
            let has_result_schema = logic.get("outputSchema").is_some()
                || logic
                    .get("modelBinding")
                    .and_then(|binding| binding.get("resultSchema"))
                    .is_some();
            if structured_validation && !has_result_schema {
                verification_issues.push(WorkflowValidationIssue {
                    node_id: Some(node_id.clone()),
                    code: "missing_model_output_schema".to_string(),
                    message: "Structured model output validation needs a result schema."
                        .to_string(),
                });
            }
        }
        if action_kind == ActionKind::ModelBinding {
            match workflow_model_binding(node) {
                Ok(binding) => {
                    if binding.model_ref.trim().is_empty() {
                        missing_config.push(WorkflowValidationIssue {
                            node_id: Some(node_id.clone()),
                            code: "missing_model_binding".to_string(),
                            message:
                                "Model Binding nodes need a model ref before they can attach to model calls."
                                    .to_string(),
                        });
                    }
                    if !workflow_schema_is_object_like(binding.result_schema.as_ref())
                        && !workflow_schema_is_object_like(logic.get("outputSchema"))
                    {
                        verification_issues.push(WorkflowValidationIssue {
                            node_id: Some(node_id.clone()),
                            code: "missing_model_binding_result_schema".to_string(),
                            message: "Model Binding nodes need a result schema so downstream model outputs can be verified.".to_string(),
                        });
                    }
                    if !binding.mock_binding && binding.credential_ready != Some(true) {
                        connector_binding_issues.push(WorkflowValidationIssue {
                            node_id: Some(node_id.clone()),
                            code: "missing_live_model_credential".to_string(),
                            message: "Live model bindings need credentials marked ready before execution.".to_string(),
                        });
                    }
                }
                Err(error) => missing_config.push(WorkflowValidationIssue {
                    node_id: Some(node_id.clone()),
                    code: "missing_model_binding".to_string(),
                    message: error,
                }),
            }
        }
        if action_kind == ActionKind::Parser {
            match workflow_parser_binding(node) {
                Ok(binding) => {
                    if binding.parser_ref.trim().is_empty() {
                        missing_config.push(WorkflowValidationIssue {
                            node_id: Some(node_id.clone()),
                            code: "missing_parser_binding".to_string(),
                            message:
                                "Output Parser nodes need a parser binding before model attachment."
                                    .to_string(),
                        });
                    }
                    if !workflow_schema_is_object_like(binding.result_schema.as_ref())
                        && !workflow_schema_is_object_like(logic.get("outputSchema"))
                    {
                        verification_issues.push(WorkflowValidationIssue {
                            node_id: Some(node_id.clone()),
                            code: "missing_parser_result_schema".to_string(),
                            message: "Output Parser nodes need a result schema for typed model output validation.".to_string(),
                        });
                    }
                }
                Err(error) => missing_config.push(WorkflowValidationIssue {
                    node_id: Some(node_id.clone()),
                    code: "missing_parser_binding".to_string(),
                    message: error,
                }),
            }
        }
        if action_kind == ActionKind::Function {
            match workflow_function_binding(node) {
                Ok(binding) => {
                    let policy = workflow_sandbox_policy(&binding, node);
                    if let Err(error) = workflow_function_sandbox_precheck(&binding.code, &policy) {
                        execution_readiness_issues.push(WorkflowValidationIssue {
                            node_id: Some(node_id.clone()),
                            code: "unsafe_function_permission".to_string(),
                            message: error,
                        });
                    }
                    if let Err(error) = workflow_function_dependency_precheck(&binding) {
                        execution_readiness_issues.push(WorkflowValidationIssue {
                            node_id: Some(node_id.clone()),
                            code: "unsupported_function_dependency".to_string(),
                            message: error,
                        });
                    }
                    let function_ref_output_schema = binding
                        .function_ref
                        .as_ref()
                        .and_then(|function_ref| function_ref.output_schema.as_ref());
                    if binding.output_schema.is_none()
                        && function_ref_output_schema.is_none()
                        && workflow_node_schema(node, "outputSchema").is_none()
                    {
                        verification_issues.push(WorkflowValidationIssue {
                            node_id: Some(node_id.clone()),
                            code: "missing_output_schema".to_string(),
                            message: "Function nodes need an output schema for typed verification."
                                .to_string(),
                        });
                    }
                }
                Err(error) => missing_config.push(WorkflowValidationIssue {
                    node_id: Some(node_id.clone()),
                    code: "missing_function_binding".to_string(),
                    message: error,
                }),
            }
        }
        if action_kind == ActionKind::AdapterConnector {
            match workflow_connector_binding(node) {
                Ok(binding) => {
                    if !binding.mock_binding && binding.credential_ready != Some(true) {
                        connector_binding_issues.push(WorkflowValidationIssue {
                            node_id: Some(node_id.clone()),
                            code: "missing_live_connector_credential".to_string(),
                            message: "Live connector bindings need credentials marked ready before execution.".to_string(),
                        });
                    }
                    if !binding.mock_binding
                        && workflow_side_effect_requires_live_runtime(&binding.side_effect_class)
                    {
                        execution_readiness_issues.push(WorkflowValidationIssue {
                            node_id: Some(node_id.clone()),
                            code: "live_connector_write_unavailable".to_string(),
                            message: "Live connector side effects need a configured connector runtime and approval.".to_string(),
                        });
                    }
                    let privileged_side_effect =
                        !matches!(binding.side_effect_class.as_str(), "none" | "read");
                    if privileged_side_effect
                        && !binding.requires_approval
                        && !law
                            .get("requireHumanGate")
                            .and_then(Value::as_bool)
                            .unwrap_or(false)
                    {
                        policy_required_nodes.push(node_id.clone());
                    }
                }
                Err(error) => connector_binding_issues.push(WorkflowValidationIssue {
                    node_id: Some(node_id.clone()),
                    code: "missing_connector_binding".to_string(),
                    message: error,
                }),
            }
        }
        if action_kind == ActionKind::PluginTool {
            match workflow_tool_binding(node) {
                Ok(binding) => {
                    if binding.binding_kind.as_deref() == Some("workflow_tool") {
                        let workflow_tool = binding.workflow_tool.as_ref();
                        let workflow_path = workflow_tool
                            .map(|tool| tool.workflow_path.trim())
                            .filter(|path| !path.is_empty());
                        if workflow_path.is_none() {
                            missing_config.push(WorkflowValidationIssue {
                                node_id: Some(node_id.clone()),
                                code: "missing_workflow_tool_ref".to_string(),
                                message: "Workflow tool bindings need a child workflow path."
                                    .to_string(),
                            });
                        }
                        if !workflow_schema_is_object_like(
                            workflow_tool.and_then(|tool| tool.argument_schema.as_ref()),
                        ) {
                            verification_issues.push(WorkflowValidationIssue {
                                node_id: Some(node_id.clone()),
                                code: "missing_workflow_tool_argument_schema".to_string(),
                                message: "Workflow tool bindings need an argument schema before agent/tool execution.".to_string(),
                            });
                        }
                        if !workflow_schema_is_object_like(
                            workflow_tool.and_then(|tool| tool.result_schema.as_ref()),
                        ) {
                            verification_issues.push(WorkflowValidationIssue {
                                node_id: Some(node_id.clone()),
                                code: "missing_workflow_tool_result_schema".to_string(),
                                message: "Workflow tool bindings need a result schema before agent/tool execution.".to_string(),
                            });
                        }
                        let timeout_ms =
                            workflow_tool.and_then(|tool| tool.timeout_ms).unwrap_or(0);
                        if timeout_ms == 0 {
                            execution_readiness_issues.push(WorkflowValidationIssue {
                                node_id: Some(node_id.clone()),
                                code: "invalid_workflow_tool_timeout".to_string(),
                                message:
                                    "Workflow tool timeout must be greater than zero milliseconds."
                                        .to_string(),
                            });
                        }
                        let max_attempts = workflow_tool
                            .and_then(|tool| tool.max_attempts)
                            .unwrap_or(0);
                        if !(1..=5).contains(&max_attempts) {
                            execution_readiness_issues.push(WorkflowValidationIssue {
                                node_id: Some(node_id.clone()),
                                code: "invalid_workflow_tool_attempts".to_string(),
                                message: "Workflow tool retry attempts must be between 1 and 5."
                                    .to_string(),
                            });
                        }
                    }
                    if binding.binding_kind.as_deref() != Some("workflow_tool")
                        && !binding.mock_binding
                        && binding.credential_ready != Some(true)
                    {
                        connector_binding_issues.push(WorkflowValidationIssue {
                            node_id: Some(node_id.clone()),
                            code: "missing_live_tool_credential".to_string(),
                            message: "Live plugin or MCP tool bindings need credentials marked ready before execution.".to_string(),
                        });
                    }
                    if !binding.mock_binding
                        && workflow_side_effect_requires_live_runtime(&binding.side_effect_class)
                    {
                        execution_readiness_issues.push(WorkflowValidationIssue {
                            node_id: Some(node_id.clone()),
                            code: "live_tool_side_effect_unavailable".to_string(),
                            message: "Live plugin side effects need a configured tool runtime and approval.".to_string(),
                        });
                    }
                    let privileged_side_effect =
                        !matches!(binding.side_effect_class.as_str(), "none" | "read");
                    if privileged_side_effect
                        && !binding.requires_approval
                        && !law
                            .get("requireHumanGate")
                            .and_then(Value::as_bool)
                            .unwrap_or(false)
                    {
                        policy_required_nodes.push(node_id.clone());
                    }
                }
                Err(error) => connector_binding_issues.push(WorkflowValidationIssue {
                    node_id: Some(node_id.clone()),
                    code: "missing_tool_binding".to_string(),
                    message: error,
                }),
            }
        }
        let requires_gate = law
            .get("requireHumanGate")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if action_kind == ActionKind::Output {
            let materializes_asset = logic
                .get("materialization")
                .and_then(Value::as_object)
                .and_then(|materialization| materialization.get("enabled"))
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let delivery_target = logic
                .get("deliveryTarget")
                .and_then(|target| target.get("targetKind"))
                .and_then(Value::as_str)
                .unwrap_or("none");
            let privileged_delivery = matches!(
                delivery_target,
                "local_file" | "repo_patch" | "connector_write" | "deploy"
            );
            let delivery_requires_approval = logic
                .get("deliveryTarget")
                .and_then(|target| target.get("requiresApproval"))
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let guarded_by_incoming_gate = workflow.edges.iter().any(|edge| {
                workflow_edge_to(edge).as_deref() == Some(node_id.as_str())
                    && workflow_edge_from(edge)
                        .and_then(|source_id| action_kind_by_id.get(&source_id).cloned())
                        == Some(ActionKind::HumanGate)
            });
            if (materializes_asset || privileged_delivery)
                && !requires_gate
                && !delivery_requires_approval
                && !guarded_by_incoming_gate
            {
                policy_required_nodes.push(node_id.clone());
                warnings.push(WorkflowValidationIssue {
                    node_id: Some(node_id.clone()),
                    code: "output_policy_required".to_string(),
                    message: "Output materialization or delivery needs an approval or policy gate."
                        .to_string(),
                });
            }
        }
        let privileged_actions = law
            .get("privilegedActions")
            .or_else(|| logic.get("privilegedActions"))
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .filter(|item| !item.trim().is_empty())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let guarded_by_incoming_gate = workflow.edges.iter().any(|edge| {
            workflow_edge_to(edge).as_deref() == Some(node_id.as_str())
                && workflow_edge_from(edge)
                    .and_then(|source_id| action_kind_by_id.get(&source_id).cloned())
                    == Some(ActionKind::HumanGate)
        });
        if !privileged_actions.is_empty() && !requires_gate && !guarded_by_incoming_gate {
            policy_required_nodes.push(node_id.clone());
            warnings.push(WorkflowValidationIssue {
                node_id: Some(node_id.clone()),
                code: "policy_required".to_string(),
                message: "Privileged actions need an approval or policy gate.".to_string(),
            });
        }
    }

    warnings.extend(missing_config.clone());
    warnings.extend(connector_binding_issues.clone());
    warnings.extend(execution_readiness_issues.clone());
    warnings.extend(verification_issues.clone());
    let mut blocked_nodes = unsupported_runtime_nodes.clone();
    blocked_nodes.extend(policy_required_nodes.clone());
    blocked_nodes.extend(
        missing_config
            .iter()
            .filter_map(|issue| issue.node_id.clone()),
    );
    blocked_nodes.extend(
        connector_binding_issues
            .iter()
            .filter_map(|issue| issue.node_id.clone()),
    );
    blocked_nodes.extend(
        execution_readiness_issues
            .iter()
            .filter_map(|issue| issue.node_id.clone()),
    );
    blocked_nodes.extend(
        verification_issues
            .iter()
            .filter_map(|issue| issue.node_id.clone()),
    );
    blocked_nodes.sort();
    blocked_nodes.dedup();
    let status = if !errors.is_empty() {
        "failed"
    } else if !blocked_nodes.is_empty() {
        "blocked"
    } else {
        "passed"
    };

    WorkflowValidationResult {
        status: status.to_string(),
        errors,
        warnings,
        blocked_nodes,
        missing_config,
        unsupported_runtime_nodes,
        policy_required_nodes,
        coverage_by_node_id,
        connector_binding_issues,
        execution_readiness_issues,
        verification_issues,
    }
}

fn push_workflow_readiness_issue(
    result: &mut WorkflowValidationResult,
    issue: WorkflowValidationIssue,
) {
    let exists = result.execution_readiness_issues.iter().any(|current| {
        current.node_id == issue.node_id
            && current.code == issue.code
            && current.message == issue.message
    });
    if exists {
        return;
    }
    if let Some(node_id) = issue.node_id.as_ref() {
        result.blocked_nodes.push(node_id.clone());
    }
    result.warnings.push(issue.clone());
    result.execution_readiness_issues.push(issue);
}

fn push_workflow_advisory_warning(
    result: &mut WorkflowValidationResult,
    issue: WorkflowValidationIssue,
) {
    let exists = result.warnings.iter().any(|current| {
        current.node_id == issue.node_id
            && current.code == issue.code
            && current.message == issue.message
    });
    if !exists {
        result.warnings.push(issue);
    }
}

fn finalize_workflow_readiness_status(result: &mut WorkflowValidationResult) {
    result.blocked_nodes.sort();
    result.blocked_nodes.dedup();
    result.status = if !result.errors.is_empty() {
        "failed".to_string()
    } else if !result.blocked_nodes.is_empty() || !result.execution_readiness_issues.is_empty() {
        "blocked".to_string()
    } else {
        "passed".to_string()
    };
}

fn workflow_production_string(workflow: &WorkflowProject, key: &str) -> Option<String> {
    workflow
        .global_config
        .get("production")
        .and_then(|production| production.get(key))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn workflow_production_bool(workflow: &WorkflowProject, key: &str) -> bool {
    workflow
        .global_config
        .get("production")
        .and_then(|production| production.get(key))
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn workflow_production_number(workflow: &WorkflowProject, key: &str) -> Option<f64> {
    workflow
        .global_config
        .get("production")
        .and_then(|production| production.get(key))
        .and_then(Value::as_f64)
}

fn workflow_environment_string(workflow: &WorkflowProject, key: &str) -> Option<String> {
    workflow
        .global_config
        .get("environmentProfile")
        .and_then(|environment| environment.get(key))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn workflow_environment_target(workflow: &WorkflowProject) -> String {
    workflow_environment_string(workflow, "target").unwrap_or_else(|| "local".to_string())
}

fn workflow_environment_requires_live_readiness(workflow: &WorkflowProject) -> bool {
    matches!(
        workflow_environment_target(workflow).as_str(),
        "staging" | "production"
    )
}

fn workflow_mock_bindings_block_activation(workflow: &WorkflowProject) -> bool {
    let target = workflow_environment_target(workflow);
    let policy = workflow_environment_string(workflow, "mockBindingPolicy")
        .unwrap_or_else(|| "block".to_string());
    target == "production" || policy == "block"
}

fn workflow_has_error_or_retry_path(workflow: &WorkflowProject) -> bool {
    workflow_production_string(workflow, "errorWorkflowPath").is_some()
        || workflow.edges.iter().any(|edge| {
            matches!(
                workflow_edge_connection_class(edge).as_deref(),
                Some("error" | "retry")
            ) || matches!(workflow_edge_from_port(edge).as_str(), "error" | "retry")
        })
}

fn workflow_node_needs_operational_error_path(node: &Value) -> bool {
    let node_type = workflow_node_type(node);
    let logic = workflow_node_logic(node);
    if node_type == "adapter" {
        let side_effect_class = logic
            .get("connectorBinding")
            .and_then(|binding| binding.get("sideEffectClass"))
            .and_then(Value::as_str)
            .unwrap_or("none");
        return !matches!(side_effect_class, "none" | "read");
    }
    if node_type == "plugin_tool" {
        let side_effect_class = logic
            .get("toolBinding")
            .and_then(|binding| binding.get("sideEffectClass"))
            .and_then(Value::as_str)
            .unwrap_or("none");
        return !matches!(side_effect_class, "none" | "read");
    }
    if node_type == "output" {
        let materializes_asset = logic
            .get("materialization")
            .and_then(|materialization| materialization.get("enabled"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let target_kind = logic
            .get("deliveryTarget")
            .and_then(|target| target.get("targetKind"))
            .and_then(Value::as_str)
            .unwrap_or("none");
        return materializes_asset
            || matches!(
                target_kind,
                "local_file" | "repo_patch" | "connector_write" | "deploy"
            );
    }
    false
}

fn workflow_node_is_mcp_tool(node: &Value) -> bool {
    workflow_node_type(node) == "plugin_tool"
        && workflow_node_logic(node)
            .get("toolBinding")
            .and_then(|binding| binding.get("bindingKind"))
            .and_then(Value::as_str)
            == Some("mcp_tool")
}

pub(super) fn apply_workflow_activation_readiness(
    workflow: &WorkflowProject,
    tests: &[WorkflowTestCase],
    mut result: WorkflowValidationResult,
    fixtures: &[WorkflowNodeFixture],
) -> WorkflowValidationResult {
    let has_start = workflow.nodes.iter().any(|node| {
        let node_type = workflow_node_type(node);
        node_type == "trigger" || node_type == "source"
    });
    let has_output = workflow
        .nodes
        .iter()
        .any(|node| workflow_node_type(node) == "output");
    if !has_start {
        push_workflow_readiness_issue(
            &mut result,
            WorkflowValidationIssue {
                node_id: None,
                code: "missing_start_node".to_string(),
                message: "Activation needs a trigger or source/input node.".to_string(),
            },
        );
    }
    if !has_output {
        push_workflow_readiness_issue(
            &mut result,
            WorkflowValidationIssue {
                node_id: None,
                code: "missing_output_node".to_string(),
                message: "Activation needs at least one output node.".to_string(),
            },
        );
    }
    if tests.is_empty() {
        push_workflow_readiness_issue(
            &mut result,
            WorkflowValidationIssue {
                node_id: None,
                code: "missing_unit_tests".to_string(),
                message: "Activation needs at least one workflow unit test.".to_string(),
            },
        );
    }
    if let Some(node) = workflow
        .nodes
        .iter()
        .find(|node| workflow_node_needs_operational_error_path(node))
    {
        if !workflow_has_error_or_retry_path(workflow) {
            push_workflow_readiness_issue(
                &mut result,
                WorkflowValidationIssue {
                    node_id: workflow_node_id(node),
                    code: "missing_error_handling_path".to_string(),
                    message:
                        "Operational side effects need an error or retry path before activation."
                            .to_string(),
                },
            );
        }
    }
    let covered_node_ids = tests
        .iter()
        .flat_map(|test| test.target_node_ids.iter().cloned())
        .collect::<std::collections::BTreeSet<_>>();
    if workflow_production_string(workflow, "evaluationSetPath").is_none() {
        if let Some(model_node) = workflow.nodes.iter().find(|node| {
            workflow_node_type(node) == "model_call"
                && workflow_node_id(node)
                    .map(|node_id| !covered_node_ids.contains(&node_id))
                    .unwrap_or(false)
        }) {
            push_workflow_readiness_issue(
                &mut result,
                WorkflowValidationIssue {
                    node_id: workflow_node_id(model_node),
                    code: "missing_ai_evaluation_coverage".to_string(),
                    message:
                        "Model-driven workflow nodes need unit-test coverage or an evaluation set before activation."
                            .to_string(),
                },
            );
        }
    }
    if let Some(mcp_node) = workflow
        .nodes
        .iter()
        .find(|node| workflow_node_is_mcp_tool(node))
    {
        if !workflow_production_bool(workflow, "mcpAccessReviewed") {
            push_workflow_readiness_issue(
                &mut result,
                WorkflowValidationIssue {
                    node_id: workflow_node_id(mcp_node),
                    code: "mcp_access_not_reviewed".to_string(),
                    message: "MCP tool workflows need access review before activation.".to_string(),
                },
            );
        }
    }
    if workflow_environment_requires_live_readiness(workflow) {
        for trigger in workflow.nodes.iter().filter(|node| {
            let trigger_kind = workflow_node_logic(node)
                .get("triggerKind")
                .and_then(Value::as_str)
                .unwrap_or("manual")
                .to_string();
            workflow_node_type(node) == "trigger"
                && matches!(trigger_kind.as_str(), "scheduled" | "event")
        }) {
            let logic = workflow_node_logic(trigger);
            let trigger_runtime_ready = logic
                .get("runtimeReady")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            if !trigger_runtime_ready {
                push_workflow_readiness_issue(
                    &mut result,
                    WorkflowValidationIssue {
                        node_id: workflow_node_id(trigger),
                        code: "unsupported_live_trigger".to_string(),
                        message: "Scheduled and event triggers need a configured live trigger runtime before staging or production activation.".to_string(),
                    },
                );
            }
        }
    }
    if workflow_production_number(workflow, "expectedTimeSavedMinutes")
        .map(|value| value <= 0.0)
        .unwrap_or(true)
    {
        push_workflow_advisory_warning(
            &mut result,
            WorkflowValidationIssue {
                node_id: None,
                code: "operational_value_not_estimated".to_string(),
                message:
                    "Add an expected time-saved estimate so the workflow has an operator-facing value baseline."
                        .to_string(),
            },
        );
    }
    let replay_fixture_blocks_activation = workflow_environment_requires_live_readiness(workflow)
        || workflow_production_bool(workflow, "requireReplayFixtures");
    for node in workflow
        .nodes
        .iter()
        .filter(|node| workflow_node_needs_replay_fixture(node))
    {
        if let Some(node_id) = workflow_node_id(node) {
            if !workflow_has_usable_replay_fixture(&node_id, fixtures) {
                let issue = WorkflowValidationIssue {
                    node_id: Some(node_id),
                    code: "missing_replay_fixture".to_string(),
                    message: format!(
                        "Capture a sample for '{}' so tests and downstream nodes can replay it without re-running external or expensive work.",
                        workflow_node_name(node)
                    ),
                };
                if replay_fixture_blocks_activation {
                    push_workflow_readiness_issue(&mut result, issue);
                } else {
                    push_workflow_advisory_warning(&mut result, issue);
                }
            }
        }
    }
    let mock_bindings_block_activation = workflow_mock_bindings_block_activation(workflow);
    let environment_target = workflow_environment_target(workflow);
    if workflow.metadata.workflow_kind == "scheduled_workflow"
        && !workflow.nodes.iter().any(|node| {
            workflow_node_type(node) == "trigger"
                && workflow_node_logic(node)
                    .get("triggerKind")
                    .and_then(Value::as_str)
                    == Some("scheduled")
        })
    {
        push_workflow_readiness_issue(
            &mut result,
            WorkflowValidationIssue {
                node_id: None,
                code: "missing_scheduled_trigger".to_string(),
                message: "Scheduled workflows need a scheduled trigger before activation."
                    .to_string(),
            },
        );
    }
    if workflow.metadata.workflow_kind == "event_workflow"
        && !workflow.nodes.iter().any(|node| {
            workflow_node_type(node) == "trigger"
                && workflow_node_logic(node)
                    .get("triggerKind")
                    .and_then(Value::as_str)
                    == Some("event")
        })
    {
        push_workflow_readiness_issue(
            &mut result,
            WorkflowValidationIssue {
                node_id: None,
                code: "missing_event_trigger".to_string(),
                message: "Event workflows need an event trigger before activation.".to_string(),
            },
        );
    }
    for node in &workflow.nodes {
        let node_type = workflow_node_type(node);
        let node_id = workflow_node_id(node);
        let node_name = workflow_node_name(node);
        let logic = workflow_node_logic(node);
        if node_type == "model_call" {
            let model_ref = logic
                .get("modelRef")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let attached_model_ready = node_id
                .as_deref()
                .map(|id| workflow_has_incoming_connection_class(workflow, id, "model"))
                .unwrap_or(false);
            let model_ready = workflow
                .global_config
                .get("modelBindings")
                .and_then(|bindings| bindings.get(model_ref))
                .and_then(|binding| binding.get("modelId"))
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .is_some();
            if !model_ready && !attached_model_ready {
                let issue = WorkflowValidationIssue {
                    node_id: node_id.clone(),
                    code: "unbound_model_ref".to_string(),
                    message: format!(
                        "Model node '{}' needs a concrete model binding before activation.",
                        node_name
                    ),
                };
                if !result
                    .missing_config
                    .iter()
                    .any(|current| current.node_id == issue.node_id && current.code == issue.code)
                {
                    result.missing_config.push(issue.clone());
                }
                push_workflow_readiness_issue(&mut result, issue);
            }
        }
        let binding = logic
            .get("toolBinding")
            .or_else(|| logic.get("connectorBinding"))
            .or_else(|| logic.get("modelBinding"))
            .or_else(|| logic.get("parserBinding"));
        if binding
            .and_then(|value| value.get("mockBinding"))
            .and_then(Value::as_bool)
            == Some(true)
        {
            let issue = WorkflowValidationIssue {
                node_id,
                code: "mock_binding_active".to_string(),
                message: if mock_bindings_block_activation {
                    format!(
                        "'{}' is using an explicit mock binding. Switch to live credentials before activation.",
                        node_name
                    )
                } else {
                    format!(
                        "'{}' is using an explicit mock binding in {} mode.",
                        node_name, environment_target
                    )
                },
            };
            if mock_bindings_block_activation {
                push_workflow_readiness_issue(&mut result, issue);
            } else {
                push_workflow_advisory_warning(&mut result, issue);
            }
        }
    }
    finalize_workflow_readiness_status(&mut result);
    result
}

fn workflow_node_needs_replay_fixture(node: &Value) -> bool {
    matches!(
        workflow_node_type(node).as_str(),
        "model_call" | "adapter" | "plugin_tool" | "function"
    )
}

fn workflow_node_satisfies_action_binding(
    workflow: &WorkflowProject,
    node: &Value,
    node_id: &str,
    required_binding: &str,
) -> bool {
    let logic = workflow_node_logic(node);
    match required_binding {
        "function" => workflow_function_binding(node).is_ok(),
        "model" => {
            if workflow_node_type(node) == "model_binding" {
                return workflow_model_binding(node)
                    .map(|binding| !binding.model_ref.trim().is_empty())
                    .unwrap_or(false);
            }
            logic
                .get("modelRef")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .is_some()
                || workflow.edges.iter().any(|edge| {
                    workflow_edge_to(edge).as_deref() == Some(node_id)
                        && (workflow_edge_connection_class(edge).as_deref() == Some("model")
                            || workflow_edge_to_port(edge) == "model")
                })
        }
        "parser" => workflow_parser_binding(node)
            .map(|binding| !binding.parser_ref.trim().is_empty())
            .unwrap_or(false),
        "connector" => workflow_connector_binding(node)
            .map(|binding| !binding.connector_ref.trim().is_empty())
            .unwrap_or(false),
        "tool" => workflow_tool_binding(node)
            .map(|binding| {
                if binding.binding_kind.as_deref() == Some("workflow_tool") {
                    binding
                        .workflow_tool
                        .as_ref()
                        .map(|tool| !tool.workflow_path.trim().is_empty())
                        .unwrap_or(false)
                } else {
                    !binding.tool_ref.trim().is_empty()
                }
            })
            .unwrap_or(false),
        "subgraph" => logic
            .get("subgraphRef")
            .and_then(|reference| reference.get("workflowPath"))
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .is_some(),
        "proposal" => logic
            .get("proposalAction")
            .and_then(|action| action.get("boundedTargets"))
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .any(|item| !item.trim().is_empty())
            })
            .unwrap_or(false),
        _ => true,
    }
}

fn workflow_has_usable_replay_fixture(node_id: &str, fixtures: &[WorkflowNodeFixture]) -> bool {
    fixtures.iter().any(|fixture| {
        if fixture.node_id != node_id {
            return false;
        }
        if fixture.stale.unwrap_or(false) {
            return false;
        }
        if matches!(
            fixture.validation_status.as_deref(),
            Some("failed") | Some("stale")
        ) {
            return false;
        }
        fixture.input.is_some() && fixture.output.is_some()
    })
}
