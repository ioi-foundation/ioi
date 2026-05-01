use std::time::Duration;

fn env_var_truthy(name: &str) -> bool {
    std::env::var(name)
        .ok()
        .map(|raw| {
            matches!(
                raw.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

pub(super) fn cognition_inference_timeout() -> Duration {
    const DEFAULT_TIMEOUT_SECS: u64 = 15;
    const LOCAL_GPU_DEV_DEFAULT_TIMEOUT_SECS: u64 = 60;
    let default_timeout_secs = if env_var_truthy("AUTOPILOT_LOCAL_GPU_DEV") {
        LOCAL_GPU_DEV_DEFAULT_TIMEOUT_SECS
    } else {
        DEFAULT_TIMEOUT_SECS
    };
    std::env::var("IOI_COGNITION_INFERENCE_TIMEOUT_SECS")
        .ok()
        .and_then(|raw| raw.parse::<u64>().ok())
        .filter(|secs| *secs > 0)
        .map(Duration::from_secs)
        .unwrap_or_else(|| Duration::from_secs(default_timeout_secs))
}

fn compact_single_line(input: &str, max_chars: usize) -> String {
    let collapsed = input.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.chars().count() <= max_chars {
        collapsed
    } else {
        let mut truncated = collapsed.chars().take(max_chars).collect::<String>();
        truncated.push_str("...");
        truncated
    }
}

pub(super) fn inference_error_system_fail_reason(raw_error: &str) -> String {
    let lower = raw_error.to_ascii_lowercase();

    if lower.contains("insufficient_quota")
        || (lower.contains("429") && lower.contains("too many requests"))
    {
        return "ERROR_CLASS=UserInterventionNeeded Cognition inference unavailable: provider quota exhausted (HTTP 429 insufficient_quota). Update billing/quota and resume.".to_string();
    }

    if lower.contains("invalid_api_key")
        || lower.contains("authentication")
        || (lower.contains("401") && lower.contains("unauthorized"))
    {
        return "ERROR_CLASS=UserInterventionNeeded Cognition inference unavailable: provider authentication failed (check API key/runtime credentials).".to_string();
    }

    if lower.contains("forbidden") || (lower.contains("403") && lower.contains("provider")) {
        return "ERROR_CLASS=UserInterventionNeeded Cognition inference unavailable: provider access is forbidden for current credentials/config.".to_string();
    }

    let detail = compact_single_line(raw_error, 240);
    format!(
        "ERROR_CLASS=UserInterventionNeeded Cognition inference failed before tool planning. detail={}",
        detail
    )
}

#[cfg(test)]
#[path = "inference/tests.rs"]
mod tests;
