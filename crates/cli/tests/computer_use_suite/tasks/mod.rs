mod catalog;
mod core;
mod smoke;
mod stress;

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
