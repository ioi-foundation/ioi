mod core;
mod smoke;
mod stress;

use std::collections::BTreeSet;

use super::types::{ComputerUseCase, TaskSet};

pub fn cases_for_task_set(task_set: TaskSet) -> Vec<ComputerUseCase> {
    let mut out = smoke::cases();
    if matches!(task_set, TaskSet::Core | TaskSet::Stress) {
        out.extend(core::cases());
    }
    if matches!(task_set, TaskSet::Stress) {
        out.extend(stress::cases());
    }
    out
}

pub fn validate_case_catalog(cases: &[ComputerUseCase]) -> anyhow::Result<()> {
    let mut ids = BTreeSet::new();
    for case in cases {
        if !ids.insert(case.id) {
            anyhow::bail!("duplicate computer use case id '{}'", case.id);
        }
    }
    Ok(())
}
