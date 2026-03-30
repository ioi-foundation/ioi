pub fn job_progress_for_status(status: &str) -> u8 {
    match status {
        "queued" => 8,
        "ready" => 16,
        "running" => 55,
        "syncing" => 62,
        "applying" => 72,
        "completed" => 100,
        "failed" => 100,
        "cancelled" => 100,
        _ => 0,
    }
}

pub fn summary_for_job_status(job: &LocalEngineJobRecord, status: &str) -> String {
    let operation = humanize_token(&job.operation).to_ascii_lowercase();
    let subject = humanize_token(&job.subject_kind).to_ascii_lowercase();
    match status {
        "running" => format!(
            "Kernel-native control-plane execution is actively running {} {}.",
            operation, subject
        ),
        "syncing" => {
            "Gallery or registry synchronization is actively refreshing catalog truth.".to_string()
        }
        "applying" => format!(
            "Applying {} policy for the {} control plane under kernel authority.",
            operation, subject
        ),
        "completed" => completion_summary(job),
        "failed" => format!(
            "{} {} failed and should be triaged through typed lifecycle receipts.",
            humanize_token(&job.operation),
            humanize_token(&job.subject_kind).to_ascii_lowercase()
        ),
        "cancelled" => format!(
            "Operator cancelled the queued {} {} transition before completion.",
            operation, subject
        ),
        "ready" => format!(
            "{} {} is staged and ready to execute under kernel control.",
            humanize_token(&job.operation),
            subject
        ),
        _ => format!(
            "{} {} is queued inside the kernel-owned local engine registry.",
            humanize_token(&job.operation),
            subject
        ),
    }
}

