#![cfg(all(feature = "consensus-admft", feature = "vm-wasm"))]

use anyhow::Result;
use async_trait::async_trait;
use ioi_api::vm::inference::{mock::MockInferenceRuntime, InferenceRuntime};
use ioi_types::app::agentic::InferenceOptions;
use ioi_types::error::VmError;
use serde_json::json;
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};

mod capabilities_suite;

#[derive(Default, Clone)]
struct CapabilitiesMockRuntime {
    fallback: MockInferenceRuntime,
}

fn contains_mail_reply_context(lower: &str) -> bool {
    !contains_google_gmail_draft_context(lower)
        && !contains_google_gmail_send_context(lower)
        && (lower.contains("resolved intent:\nmail.reply")
            || lower.contains("\"mail.reply\"")
            || lower.contains("wallet_network__mail_reply")
            || lower.contains("wallet_mail_reply")
            || lower.contains("mail__reply")
            || (lower.contains("draft an email") && lower.contains("2 pm"))
            || (lower.contains("send it") && lower.contains("email")))
}

fn contains_mail_read_context(lower: &str) -> bool {
    lower.contains("read me the last email i received")
        || lower.contains("wallet_network__mail_read_latest")
        || lower.contains("wallet_mail_read_latest")
        || lower.contains("mail__read_latest")
        || lower.contains("\"mail.read.latest\"")
}

fn contains_google_gmail_draft_context(lower: &str) -> bool {
    lower.contains("save it as a gmail draft")
}

fn contains_google_gmail_send_context(lower: &str) -> bool {
    lower.contains("via gmail")
}

fn contains_google_calendar_create_context(lower: &str) -> bool {
    lower.contains("google calendar event")
}

fn google_fixture_test_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

#[async_trait]
impl InferenceRuntime for CapabilitiesMockRuntime {
    async fn execute_inference(
        &self,
        model_hash: [u8; 32],
        input_context: &[u8],
        options: InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        let input = String::from_utf8_lossy(input_context);
        let lower = input.to_ascii_lowercase();

        if lower.contains("you synthesize a final outbound email draft for the mail.reply intent") {
            return Ok(json!({
                "to_token": "EMAIL_1",
                "subject": "Tomorrow's standup is moved to 2 PM",
                "body": "Tomorrow's standup is moved to 2 PM.",
                "signoff": null,
                "signature_mode": "omit"
            })
            .to_string()
            .into_bytes());
        }

        if lower.contains("extract a connector-agnostic instruction contract")
            && contains_google_gmail_draft_context(&lower)
        {
            return Ok(json!({
                "operation": "gmail.draft_email",
                "sideEffectMode": "draft",
                "slotBindings": [
                    {
                        "slot": "to",
                        "bindingKind": "grounded",
                        "value": "team@ioi.network",
                        "origin": "query_literal",
                        "protectedSlotKind": "email_address"
                    }
                ],
                "negativeConstraints": [],
                "successCriteria": ["gmail.draft.created"]
            })
            .to_string()
            .into_bytes());
        }

        if lower.contains("extract a connector-agnostic instruction contract")
            && contains_google_gmail_send_context(&lower)
        {
            return Ok(json!({
                "operation": "gmail.send_email",
                "sideEffectMode": "send",
                "slotBindings": [
                    {
                        "slot": "to",
                        "bindingKind": "grounded",
                        "value": "team@ioi.network",
                        "origin": "query_literal",
                        "protectedSlotKind": "email_address"
                    }
                ],
                "negativeConstraints": [],
                "successCriteria": ["gmail.message.sent"]
            })
            .to_string()
            .into_bytes());
        }

        if lower.contains("extract a connector-agnostic instruction contract")
            && contains_google_calendar_create_context(&lower)
        {
            return Ok(json!({
                "operation": "calendar.create_event",
                "sideEffectMode": "write",
                "slotBindings": [],
                "negativeConstraints": [],
                "successCriteria": ["calendar.event.created"]
            })
            .to_string()
            .into_bytes());
        }

        if lower.contains("extract a connector-agnostic instruction contract")
            && contains_mail_reply_context(&lower)
        {
            return Ok(json!({
                "operation": "mail.reply",
                "sideEffectMode": "send",
                "slotBindings": [
                    {
                        "slot": "to",
                        "bindingKind": "unresolved",
                        "value": null,
                        "origin": "model_inferred",
                        "protectedSlotKind": "email_address"
                    }
                ],
                "negativeConstraints": [],
                "successCriteria": ["mail.reply.completed"]
            })
            .to_string()
            .into_bytes());
        }

        if lower.contains("select the best provider route for a resolved intent")
            && contains_google_gmail_draft_context(&lower)
        {
            return Ok(json!({
                "selectedProviderFamily": "mail.google.gmail",
                "selectedProviderId": "google_gmail",
                "selectionBasis": "explicit_provider_reference",
                "reason": "the query explicitly requested Gmail draft creation"
            })
            .to_string()
            .into_bytes());
        }

        if lower.contains("select the best provider route for a resolved intent")
            && contains_google_gmail_send_context(&lower)
        {
            return Ok(json!({
                "selectedProviderFamily": "mail.google.gmail",
                "selectedProviderId": "google_gmail",
                "selectionBasis": "explicit_provider_reference",
                "reason": "the query explicitly requested Gmail delivery"
            })
            .to_string()
            .into_bytes());
        }

        if lower.contains("select the best provider route for a resolved intent")
            && contains_google_calendar_create_context(&lower)
        {
            return Ok(json!({
                "selectedProviderFamily": "calendar.google.workspace",
                "selectedProviderId": "google_calendar",
                "selectionBasis": "explicit_provider_reference",
                "reason": "the query explicitly requested Google Calendar"
            })
            .to_string()
            .into_bytes());
        }

        if lower.contains("select the best provider route for a resolved intent")
            && contains_mail_reply_context(&lower)
        {
            return Ok(json!({
                "selectedProviderFamily": "mail.wallet_network",
                "selectedProviderId": null,
                "selectionBasis": "single_wallet_route",
                "reason": "wallet-backed mailbox connector is the registered route for mail.reply"
            })
            .to_string()
            .into_bytes());
        }

        if lower.contains("labelids") && lower.contains("draft") && lower.contains("message") {
            return Ok(json!({
                "name": "agent__complete",
                "arguments": { "result": "Gmail draft created." }
            })
            .to_string()
            .into_bytes());
        }

        if lower.contains("labelids") && lower.contains("sent") {
            return Ok(json!({
                "name": "agent__complete",
                "arguments": { "result": "Gmail message sent." }
            })
            .to_string()
            .into_bytes());
        }

        if (lower.contains("htmllink") && lower.contains("calendarid"))
            || (lower.contains("created calendar event") && lower.contains("tomorrow's standup"))
            || lower.contains("mock-event-")
        {
            return Ok(json!({
                "name": "agent__complete",
                "arguments": { "result": "Google Calendar event created." }
            })
            .to_string()
            .into_bytes());
        }

        if lower.contains("\"message_id\"")
            && lower.contains("\"preview\"")
            && lower.contains("\"mailbox\"")
        {
            return Ok(json!({
                "name": "agent__complete",
                "arguments": { "result": "Mailbox read completed." }
            })
            .to_string()
            .into_bytes());
        }

        if lower.contains("\"sent_message_id\"")
            || lower.contains("\"operation\":\"mail_reply@v1\"")
        {
            return Ok(json!({
                "name": "agent__complete",
                "arguments": { "result": "Mail reply completed." }
            })
            .to_string()
            .into_bytes());
        }

        if contains_google_gmail_draft_context(&lower) {
            return Ok(json!({
                "name": "connector__google__gmail_draft_email",
                "arguments": {
                    "to": "team@ioi.network",
                    "subject": "Tomorrow's standup is moved to 2 PM",
                    "body": "Tomorrow's standup is moved to 2 PM."
                }
            })
            .to_string()
            .into_bytes());
        }

        if contains_google_gmail_send_context(&lower) {
            return Ok(json!({
                "name": "connector__google__gmail_send_email",
                "arguments": {
                    "to": "team@ioi.network",
                    "subject": "Tomorrow's standup is moved to 2 PM",
                    "body": "Tomorrow's standup is moved to 2 PM."
                }
            })
            .to_string()
            .into_bytes());
        }

        if contains_google_calendar_create_context(&lower) {
            return Ok(json!({
                "name": "connector__google__calendar_create_event",
                "arguments": {
                    "calendarId": "primary",
                    "summary": "Tomorrow's standup",
                    "start": "2026-03-10T14:00:00-05:00",
                    "end": "2026-03-10T14:30:00-05:00",
                    "description": "Tomorrow's standup is moved to 2 PM."
                }
            })
            .to_string()
            .into_bytes());
        }

        if contains_mail_read_context(&lower) {
            return Ok(json!({
                "name": "wallet_network__mail_read_latest",
                "arguments": {
                    "mailbox": "primary"
                }
            })
            .to_string()
            .into_bytes());
        }

        if contains_mail_reply_context(&lower) {
            return Ok(json!({
                "name": "wallet_network__mail_reply",
                "arguments": {
                    "mailbox": "primary"
                }
            })
            .to_string()
            .into_bytes());
        }

        self.fallback
            .execute_inference(model_hash, input_context, options)
            .await
    }

    async fn embed_text(&self, text: &str) -> Result<Vec<f32>, VmError> {
        self.fallback.embed_text(text).await
    }

    async fn load_model(&self, model_hash: [u8; 32], path: &Path) -> Result<(), VmError> {
        self.fallback.load_model(model_hash, path).await
    }

    async fn unload_model(&self, model_hash: [u8; 32]) -> Result<(), VmError> {
        self.fallback.unload_model(model_hash).await
    }
}

fn capabilities_case(case_id: &str) -> capabilities_suite::types::QueryCase {
    capabilities_suite::queries::all_cases()
        .into_iter()
        .find(|case| case.id == case_id)
        .unwrap_or_else(|| panic!("missing capabilities case '{}'", case_id))
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "live internet + external inference required"]
async fn capabilities_query_suite_e2e() -> Result<()> {
    capabilities_suite::run_capabilities_suite().await
}

#[tokio::test(flavor = "multi_thread")]
async fn capabilities_mail_read_case_passes_with_wallet_bootstrap_and_mock_runtime() -> Result<()> {
    let case = capabilities_case("read_me_the_last_email_i_received");
    let observation = capabilities_suite::harness::run_case(
        &case,
        1,
        Arc::new(CapabilitiesMockRuntime::default()),
    )
    .await?;
    let local = (case.local_sniff)(&observation);
    assert!(
        local.pass,
        "mail read local judge failed: {:?}\nobservation={}",
        local.failures,
        serde_json::to_string_pretty(&observation)?
    );
    assert!(observation.completed, "mail read case did not complete");
    assert!(!observation.failed, "mail read case failed");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn capabilities_mail_reply_case_passes_with_wallet_bootstrap_and_mock_runtime() -> Result<()>
{
    let case = capabilities_case(
        "draft_an_email_to_team_ioi_network_saying_tomorrows_standup_is_moved_to_2_pm_and_send_it",
    );
    let observation = capabilities_suite::harness::run_case(
        &case,
        2,
        Arc::new(CapabilitiesMockRuntime::default()),
    )
    .await?;
    let local = (case.local_sniff)(&observation);
    assert!(
        local.pass,
        "mail reply local judge failed: {:?}\nobservation={}",
        local.failures,
        serde_json::to_string_pretty(&observation)?
    );
    assert!(observation.completed, "mail reply case did not complete");
    assert!(!observation.failed, "mail reply case failed");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn capabilities_google_gmail_draft_case_passes_with_mock_runtime() -> Result<()> {
    let _guard = google_fixture_test_lock()
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let case = capabilities_case(
        "draft_an_email_to_team_ioi_network_saying_tomorrows_standup_is_moved_to_2_pm_and_save_it_as_a_gmail_draft",
    );
    let observation = capabilities_suite::harness::run_case(
        &case,
        3,
        Arc::new(CapabilitiesMockRuntime::default()),
    )
    .await?;
    let local = (case.local_sniff)(&observation);
    assert!(
        local.pass,
        "google gmail draft local judge failed: {:?}\nobservation={}",
        local.failures,
        serde_json::to_string_pretty(&observation)?
    );
    assert!(
        observation.completed,
        "google gmail draft case did not complete"
    );
    assert!(!observation.failed, "google gmail draft case failed");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn capabilities_google_gmail_send_case_passes_with_mock_runtime() -> Result<()> {
    let _guard = google_fixture_test_lock()
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let case = capabilities_case(
        "send_an_email_to_team_ioi_network_saying_tomorrows_standup_is_moved_to_2_pm_via_gmail",
    );
    let observation = capabilities_suite::harness::run_case(
        &case,
        4,
        Arc::new(CapabilitiesMockRuntime::default()),
    )
    .await?;
    let local = (case.local_sniff)(&observation);
    assert!(
        local.pass,
        "google gmail send local judge failed: {:?}\nobservation={}",
        local.failures,
        serde_json::to_string_pretty(&observation)?
    );
    assert!(
        observation.completed,
        "google gmail send case did not complete"
    );
    assert!(!observation.failed, "google gmail send case failed");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn capabilities_google_calendar_create_case_passes_with_mock_runtime() -> Result<()> {
    let _guard = google_fixture_test_lock()
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let case = capabilities_case("create_a_google_calendar_event_for_tomorrows_standup_at_2_pm");
    let observation = capabilities_suite::harness::run_case(
        &case,
        5,
        Arc::new(CapabilitiesMockRuntime::default()),
    )
    .await?;
    let local = (case.local_sniff)(&observation);
    assert!(
        local.pass,
        "google calendar create local judge failed: {:?}\nobservation={}",
        local.failures,
        serde_json::to_string_pretty(&observation)?
    );
    assert!(
        observation.completed,
        "google calendar create case did not complete"
    );
    assert!(!observation.failed, "google calendar create case failed");
    Ok(())
}
