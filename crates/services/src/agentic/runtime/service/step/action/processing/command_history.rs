use crate::agentic::runtime::service::step::action::json::extract_balanced_json_object;
use crate::agentic::runtime::types::CommandExecution;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};

const COMMAND_HISTORY_PREFIX: &str = "COMMAND_HISTORY:";
const COMMAND_HISTORY_SCRUBBED_PLACEHOLDER: &str = "[REDACTED_PII]";
static COMMAND_HISTORY_MARKER_MISS_COUNT: AtomicU64 = AtomicU64::new(0);
static COMMAND_HISTORY_PARSE_FAIL_COUNT: AtomicU64 = AtomicU64::new(0);
static COMMAND_HISTORY_SCRUB_FAIL_COUNT: AtomicU64 = AtomicU64::new(0);

pub(super) fn extract_command_history(history_entry: &Option<String>) -> Option<CommandExecution> {
    let entry = history_entry.as_deref()?;
    let mut latest: Option<CommandExecution> = None;
    let mut saw_marker = false;
    let mut saw_parse_failure = false;

    for (marker_idx, _) in entry.match_indices(COMMAND_HISTORY_PREFIX) {
        saw_marker = true;
        let payload = &entry[marker_idx + COMMAND_HISTORY_PREFIX.len()..];
        if payload.trim().is_empty() {
            saw_parse_failure = true;
            continue;
        }
        match parse_command_history_payload(payload) {
            Ok(parsed) => latest = Some(parsed),
            Err(_) => saw_parse_failure = true,
        }
    }

    if let Some(parsed) = latest {
        return Some(parsed);
    }

    if !saw_marker {
        let _ = COMMAND_HISTORY_MARKER_MISS_COUNT.fetch_add(1, Ordering::Relaxed);
    } else if saw_parse_failure {
        let _ = COMMAND_HISTORY_PARSE_FAIL_COUNT.fetch_add(1, Ordering::Relaxed);
    }
    None
}

fn parse_command_history_payload(payload: &str) -> Result<CommandExecution, serde_json::Error> {
    if let Some(start) = payload.find('{') {
        if let Some(json) = extract_balanced_json_object(payload, start) {
            return serde_json::from_str::<CommandExecution>(json);
        }
    }
    serde_json::from_str::<CommandExecution>(payload.trim())
}

pub(super) async fn scrub_command_history_fields(
    scrubber: &crate::agentic::pii_scrubber::PiiScrubber,
    mut entry: CommandExecution,
) -> CommandExecution {
    entry.command = scrub_text_field(scrubber, &entry.command).await;
    entry.stdout = scrub_text_field(scrubber, &entry.stdout).await;
    entry.stderr = scrub_text_field(scrubber, &entry.stderr).await;
    entry
}

async fn scrub_text_field(
    scrubber: &crate::agentic::pii_scrubber::PiiScrubber,
    input: &str,
) -> String {
    match scrubber.scrub(input).await {
        Ok((scrubbed, _)) => scrubbed,
        Err(_) => {
            let _ = COMMAND_HISTORY_SCRUB_FAIL_COUNT.fetch_add(1, Ordering::Relaxed);
            COMMAND_HISTORY_SCRUBBED_PLACEHOLDER.to_string()
        }
    }
}

pub(super) fn append_to_bounded_history(
    history: &mut VecDeque<CommandExecution>,
    entry: CommandExecution,
    max_size: usize,
) {
    history.push_back(entry);
    while history.len() > max_size {
        let _ = history.pop_front();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agentic::pii_scrubber::PiiScrubber;
    use async_trait::async_trait;
    use ioi_api::vm::inference::{LocalSafetyModel, PiiInspection, PiiRiskSurface, SafetyVerdict};
    use std::sync::Arc;

    struct DetectingSafetyModel;

    #[async_trait]
    impl LocalSafetyModel for DetectingSafetyModel {
        async fn classify_intent(&self, _input: &str) -> anyhow::Result<SafetyVerdict> {
            Ok(SafetyVerdict::Safe)
        }

        async fn detect_pii(&self, input: &str) -> anyhow::Result<Vec<(usize, usize, String)>> {
            let mut findings = Vec::new();
            if let Some(start) = input.find("API_KEY=") {
                findings.push((start, input.len(), "api_key".to_string()));
            }
            if let Some(start) = input.find("password=") {
                findings.push((start, input.len(), "password".to_string()));
            }
            if let Some(start) = input.find("token=") {
                findings.push((start, input.len(), "token".to_string()));
            }
            Ok(findings)
        }

        async fn inspect_pii(
            &self,
            _input: &str,
            _risk_surface: PiiRiskSurface,
        ) -> anyhow::Result<PiiInspection> {
            Ok(PiiInspection {
                evidence: Default::default(),
                ambiguous: false,
                stage2_status: None,
            })
        }
    }

    struct FailingSafetyModel;

    #[async_trait]
    impl LocalSafetyModel for FailingSafetyModel {
        async fn classify_intent(&self, _input: &str) -> anyhow::Result<SafetyVerdict> {
            Ok(SafetyVerdict::Safe)
        }

        async fn detect_pii(&self, _input: &str) -> anyhow::Result<Vec<(usize, usize, String)>> {
            Err(anyhow::anyhow!("failure"))
        }

        async fn inspect_pii(
            &self,
            _input: &str,
            _risk_surface: PiiRiskSurface,
        ) -> anyhow::Result<PiiInspection> {
            Ok(PiiInspection {
                evidence: Default::default(),
                ambiguous: false,
                stage2_status: None,
            })
        }
    }

    #[test]
    fn command_history_parse_valid_and_invalid_payloads() {
        let valid_entry = CommandExecution {
            command: "echo hi".to_string(),
            exit_code: 0,
            stdout: "ok".to_string(),
            stderr: String::new(),
            timestamp_ms: 1,
            step_index: 3,
        };
        let valid = serde_json::to_string(&valid_entry).map_or_else(
            |_| String::new(),
            |serialized| format!("{}{}", COMMAND_HISTORY_PREFIX, serialized),
        );
        let parsed = match extract_command_history(&Some(valid)) {
            Some(payload) => payload,
            None => panic!("valid command history should parse"),
        };
        assert_eq!(parsed.step_index, 3);
        assert_eq!(parsed.exit_code, 0);

        let malformed = Some(format!("{}{}", COMMAND_HISTORY_PREFIX, "{ invalid "));
        assert!(extract_command_history(&malformed).is_none());

        let unrelated = Some("no metadata here".to_string());
        assert!(extract_command_history(&unrelated).is_none());

        let prefixed = Some(format!(
            "stdout line\n> {}{}\n",
            COMMAND_HISTORY_PREFIX,
            serde_json::to_string(&valid_entry).expect("serialize")
        ));
        let parsed_prefixed = extract_command_history(&prefixed).expect("prefixed payload");
        assert_eq!(parsed_prefixed.command, "echo hi");

        let newer_entry = CommandExecution {
            command: "echo newer".to_string(),
            exit_code: 0,
            stdout: "new".to_string(),
            stderr: String::new(),
            timestamp_ms: 2,
            step_index: 4,
        };
        let multi = Some(format!(
            "{}{}\nnoise\n{}{}\n",
            COMMAND_HISTORY_PREFIX,
            serde_json::to_string(&valid_entry).expect("serialize"),
            COMMAND_HISTORY_PREFIX,
            serde_json::to_string(&newer_entry).expect("serialize")
        ));
        let parsed_multi = extract_command_history(&multi).expect("latest payload");
        assert_eq!(parsed_multi.command, "echo newer");
        assert_eq!(parsed_multi.step_index, 4);

        let merged_with_noise = Some(format!(
            "noise {}{} tail",
            COMMAND_HISTORY_PREFIX,
            serde_json::to_string(&valid_entry).expect("serialize")
        ));
        let parsed_merged = extract_command_history(&merged_with_noise).expect("merged payload");
        assert_eq!(parsed_merged.command, "echo hi");
        assert_eq!(parsed_merged.step_index, 3);

        let json_with_trailing = Some(format!(
            "{}{} \u{001b}[0m",
            COMMAND_HISTORY_PREFIX,
            serde_json::to_string(&valid_entry).expect("serialize")
        ));
        let parsed_trailing = extract_command_history(&json_with_trailing).expect("trailing noise");
        assert_eq!(parsed_trailing.command, "echo hi");
    }

    #[test]
    fn append_to_bounded_history_evictions() {
        let mut history: VecDeque<CommandExecution> = VecDeque::new();
        for step in 0..25 {
            append_to_bounded_history(
                &mut history,
                CommandExecution {
                    command: format!("cmd {step}"),
                    exit_code: 0,
                    stdout: String::new(),
                    stderr: String::new(),
                    timestamp_ms: step,
                    step_index: step as u32,
                },
                20,
            );
        }

        assert_eq!(history.len(), 20);
        assert_eq!(history.front().map(|entry| entry.step_index), Some(5));
        assert_eq!(history.back().map(|entry| entry.step_index), Some(24));
    }

    #[tokio::test]
    async fn scrub_command_history_fields_uses_pii_scrubber_and_fallback() {
        let raw = CommandExecution {
            command: "echo API_KEY=abc123".to_string(),
            exit_code: 0,
            stdout: "password=xyz".to_string(),
            stderr: "token=secret".to_string(),
            timestamp_ms: 9,
            step_index: 1,
        };
        let tagged = serde_json::to_string(&raw).map_or_else(
            |_| String::new(),
            |serialized| format!("{}{}", COMMAND_HISTORY_PREFIX, serialized),
        );
        let parsed = match extract_command_history(&Some(tagged)) {
            Some(payload) => payload,
            None => panic!("valid payload should parse"),
        };
        let scrubber = PiiScrubber::new(Arc::new(DetectingSafetyModel));
        let scrubbed = scrub_command_history_fields(&scrubber, parsed).await;
        assert!(!scrubbed.command.contains("API_KEY"));
        assert!(!scrubbed.stdout.contains("password"));
        assert!(scrubbed.stderr.contains("<REDACTED"));

        let fallback_scrubber = PiiScrubber::new(Arc::new(FailingSafetyModel));
        let fallback = scrub_command_history_fields(
            &fallback_scrubber,
            CommandExecution {
                command: "token=bad".to_string(),
                exit_code: 0,
                stdout: String::new(),
                stderr: String::new(),
                timestamp_ms: 10,
                step_index: 2,
            },
        )
        .await;
        assert_eq!(fallback.command, COMMAND_HISTORY_SCRUBBED_PLACEHOLDER);
        assert_eq!(fallback.stdout, COMMAND_HISTORY_SCRUBBED_PLACEHOLDER);
        assert_eq!(fallback.stderr, COMMAND_HISTORY_SCRUBBED_PLACEHOLDER);
    }
}
