use super::evidence::ReceiptManifestKind;
use super::scope::RuntimeScope;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunBudget {
    pub max_steps: u32,
    pub max_runtime_ms: u64,
    pub max_model_tokens: u64,
}

impl RunBudget {
    pub fn is_bounded(&self) -> bool {
        self.max_steps > 0 && self.max_runtime_ms > 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutablePlan {
    pub plan_id: String,
    pub session_id: [u8; 32],
    pub intent_hash: [u8; 32],
    #[serde(default)]
    pub steps: Vec<ExecutableStep>,
    #[serde(default)]
    pub dependency_graph: Vec<StepDependency>,
    #[serde(default)]
    pub scope_requirements: Vec<RuntimeScope>,
    pub budget: RunBudget,
    pub policy_summary: String,
    pub validation_status: PlanValidationStatus,
    #[serde(default)]
    pub receipt_manifest: Vec<ReceiptManifestKind>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutableStep {
    pub step_id: String,
    pub kind: ExecutableStepKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_or_model_ref: Option<String>,
    #[serde(default)]
    pub typed_args: Value,
    #[serde(default)]
    pub dependencies: Vec<String>,
    #[serde(default)]
    pub read_scopes: Vec<RuntimeScope>,
    #[serde(default)]
    pub write_scopes: Vec<RuntimeScope>,
    #[serde(default)]
    pub required_capabilities: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_policy: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_requirement: Option<String>,
    #[serde(default)]
    pub expected_postconditions: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutableStepKind {
    Tool,
    Model,
    Artifact,
    Workflow,
    Graph,
    Connector,
    Plugin,
    SimulationOnly,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StepDependency {
    pub step_id: String,
    pub depends_on: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanValidationStatus {
    Pending,
    Valid,
    Invalid,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PlanValidationError {
    EmptyPlanId,
    EmptyStepId {
        index: usize,
    },
    DuplicateStepId {
        step_id: String,
    },
    MissingDependency {
        step_id: String,
        missing_dependency: String,
    },
    DependencyCycle {
        step_id: String,
    },
    UnboundedBudget,
    MissingReceiptManifest,
    MissingTimeoutPolicy {
        step_id: String,
    },
    MissingCapability {
        step_id: String,
    },
    OverlappingIndependentWriteScope {
        left_step_id: String,
        right_step_id: String,
        scope: String,
    },
}

pub fn validate_plan(plan: &ExecutablePlan) -> Result<(), Vec<PlanValidationError>> {
    let mut errors = Vec::new();
    if plan.plan_id.trim().is_empty() {
        errors.push(PlanValidationError::EmptyPlanId);
    }
    if !plan.budget.is_bounded() {
        errors.push(PlanValidationError::UnboundedBudget);
    }
    if plan.receipt_manifest.is_empty() {
        errors.push(PlanValidationError::MissingReceiptManifest);
    }

    let mut step_ids = BTreeSet::new();
    let mut steps_by_id = BTreeMap::new();
    for (index, step) in plan.steps.iter().enumerate() {
        if step.step_id.trim().is_empty() {
            errors.push(PlanValidationError::EmptyStepId { index });
            continue;
        }
        if !step_ids.insert(step.step_id.clone()) {
            errors.push(PlanValidationError::DuplicateStepId {
                step_id: step.step_id.clone(),
            });
        }
        steps_by_id.insert(step.step_id.clone(), step);
        if !matches!(step.kind, ExecutableStepKind::SimulationOnly) {
            if step
                .timeout_policy
                .as_deref()
                .unwrap_or("")
                .trim()
                .is_empty()
            {
                errors.push(PlanValidationError::MissingTimeoutPolicy {
                    step_id: step.step_id.clone(),
                });
            }
            if step.required_capabilities.is_empty() {
                errors.push(PlanValidationError::MissingCapability {
                    step_id: step.step_id.clone(),
                });
            }
        }
    }

    let mut dependency_edges: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for step in &plan.steps {
        for dependency in &step.dependencies {
            if !step_ids.contains(dependency) {
                errors.push(PlanValidationError::MissingDependency {
                    step_id: step.step_id.clone(),
                    missing_dependency: dependency.clone(),
                });
            }
            dependency_edges
                .entry(step.step_id.as_str())
                .or_default()
                .insert(dependency.as_str());
        }
    }
    for edge in &plan.dependency_graph {
        if !step_ids.contains(&edge.step_id) {
            errors.push(PlanValidationError::MissingDependency {
                step_id: edge.step_id.clone(),
                missing_dependency: edge.depends_on.clone(),
            });
        }
        if !step_ids.contains(&edge.depends_on) {
            errors.push(PlanValidationError::MissingDependency {
                step_id: edge.step_id.clone(),
                missing_dependency: edge.depends_on.clone(),
            });
        }
        dependency_edges
            .entry(edge.step_id.as_str())
            .or_default()
            .insert(edge.depends_on.as_str());
    }
    for step_id in &step_ids {
        if depends_on(step_id, step_id, &dependency_edges, &mut BTreeSet::new()) {
            errors.push(PlanValidationError::DependencyCycle {
                step_id: step_id.clone(),
            });
        }
    }

    for left_index in 0..plan.steps.len() {
        for right_index in (left_index + 1)..plan.steps.len() {
            let left = &plan.steps[left_index];
            let right = &plan.steps[right_index];
            if has_dependency_path(&left.step_id, &right.step_id, &dependency_edges)
                || has_dependency_path(&right.step_id, &left.step_id, &dependency_edges)
            {
                continue;
            }
            for left_scope in &left.write_scopes {
                if right
                    .write_scopes
                    .iter()
                    .any(|right_scope| left_scope.conflicts_with(right_scope))
                {
                    errors.push(PlanValidationError::OverlappingIndependentWriteScope {
                        left_step_id: left.step_id.clone(),
                        right_step_id: right.step_id.clone(),
                        scope: left_scope.label(),
                    });
                }
            }
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

fn has_dependency_path<'a>(
    step_id: &'a str,
    depends_on_id: &'a str,
    edges: &BTreeMap<&'a str, BTreeSet<&'a str>>,
) -> bool {
    depends_on(step_id, depends_on_id, edges, &mut BTreeSet::new())
}

fn depends_on<'a>(
    step_id: &'a str,
    depends_on_id: &'a str,
    edges: &BTreeMap<&'a str, BTreeSet<&'a str>>,
    visited: &mut BTreeSet<&'a str>,
) -> bool {
    if !visited.insert(step_id) {
        return false;
    }
    let Some(dependencies) = edges.get(step_id) else {
        return false;
    };
    dependencies.contains(depends_on_id)
        || dependencies
            .iter()
            .any(|dependency| depends_on(dependency, depends_on_id, edges, visited))
}
