mod catalog;
mod core;
mod smoke;
mod stress;
mod workflow;
mod workflow_audit;
mod workflow_mutation;
mod workflow_reorder;
mod workflow_rich;

use anyhow::Result;
use std::collections::BTreeSet;
use std::path::Path;

use super::types::{ComputerUseCase, TaskSet};

pub fn cases_for_task_set(
    task_set: TaskSet,
    source_dir: Option<&Path>,
) -> Result<Vec<ComputerUseCase>> {
    if matches!(task_set, TaskSet::Catalog) {
        return catalog::cases(source_dir);
    }
    if matches!(task_set, TaskSet::Workflow) {
        return Ok(workflow::cases());
    }
    if matches!(task_set, TaskSet::WorkflowRich) {
        return Ok(workflow_rich::cases());
    }
    if matches!(task_set, TaskSet::WorkflowAudit) {
        return Ok(workflow_audit::cases());
    }
    if matches!(task_set, TaskSet::WorkflowMutation) {
        return Ok(workflow_mutation::cases());
    }
    if matches!(task_set, TaskSet::WorkflowReorder) {
        return Ok(workflow_reorder::cases());
    }

    let mut out = smoke::cases();
    if matches!(task_set, TaskSet::Core | TaskSet::Stress) {
        out.extend(core::cases());
    }
    if matches!(task_set, TaskSet::Stress) {
        out.extend(stress::cases());
    }
    Ok(out)
}

pub fn validate_case_catalog(cases: &[ComputerUseCase]) -> Result<()> {
    let mut ids = BTreeSet::new();
    for case in cases {
        if !ids.insert(case.id.clone()) {
            anyhow::bail!("duplicate computer use case id '{}'", case.id);
        }
    }
    Ok(())
}
