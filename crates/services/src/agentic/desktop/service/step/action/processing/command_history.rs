use crate::agentic::desktop::types::CommandExecution;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};

const COMMAND_HISTORY_PREFIX: &str = "COMMAND_HISTORY:";
const COMMAND_HISTORY_SCRUBBED_PLACEHOLDER: &str = "[REDACTED_PII]";
static COMMAND_HISTORY_MARKER_MISS_COUNT: AtomicU64 = AtomicU64::new(0);
static COMMAND_HISTORY_PARSE_FAIL_COUNT: AtomicU64 = AtomicU64::new(0);
static COMMAND_HISTORY_SCRUB_FAIL_COUNT: AtomicU64 = AtomicU64::new(0);

pub(super) fn extract_command_history(history_entry: &Option<String>) -> Option<CommandExecution> {
    let entry = history_entry.as_deref()?;
    if !entry.starts_with(COMMAND_HISTORY_PREFIX) {
        let _ = COMMAND_HISTORY_MARKER_MISS_COUNT.fetch_add(1, Ordering::Relaxed);
        return None;
    }

    let suffix = &entry[COMMAND_HISTORY_PREFIX.len()..];
    let json_payload = suffix
        .find('\n')
        .map_or(suffix, |idx| &suffix[..idx])
        .trim();
    if json_payload.is_empty() {
        let _ = COMMAND_HISTORY_PARSE_FAIL_COUNT.fetch_add(1, Ordering::Relaxed);
        return None;
    }

    match serde_json::from_str::<CommandExecution>(json_payload) {
        Ok(entry) => Some(entry),
        Err(_) => {
            let _ = COMMAND_HISTORY_PARSE_FAIL_COUNT.fetch_add(1, Ordering::Relaxed);
            None
        }
    }
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
