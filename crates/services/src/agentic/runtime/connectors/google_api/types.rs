use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

pub(super) const GMAIL_BASE_URL: &str = "https://gmail.googleapis.com/gmail/v1";
pub(super) const CALENDAR_BASE_URL: &str = "https://www.googleapis.com/calendar/v3";
pub(super) const DOCS_BASE_URL: &str = "https://docs.googleapis.com/v1";
pub(super) const SHEETS_BASE_URL: &str = "https://sheets.googleapis.com/v4";
pub(super) const DRIVE_BASE_URL: &str = "https://www.googleapis.com/drive/v3";
pub(super) const DRIVE_UPLOAD_BASE_URL: &str = "https://www.googleapis.com/upload/drive/v3";
pub(super) const TASKS_BASE_URL: &str = "https://tasks.googleapis.com/tasks/v1";
pub(super) const CHAT_BASE_URL: &str = "https://chat.googleapis.com/v1";
pub(super) const BIGQUERY_BASE_URL: &str = "https://bigquery.googleapis.com/bigquery/v2";
pub(super) const PUBSUB_BASE_URL: &str = "https://pubsub.googleapis.com/v1";
pub(super) const WORKSPACE_EVENTS_BASE_URL: &str = "https://workspaceevents.googleapis.com/v1";

#[derive(Debug, Clone)]
pub struct GmailMessageReadback {
    pub message_id: String,
    pub thread_id: Option<String>,
    pub to: Option<String>,
    pub subject: Option<String>,
    pub body_text: Option<String>,
    pub label_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GmailFollowUpCandidate {
    pub message_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thread_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender_email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub received_at_utc: Option<String>,
    #[serde(default)]
    pub label_ids: Vec<String>,
    pub age_minutes: u64,
    pub external_sender: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CalendarMeetingPrepCandidate {
    pub event_id: String,
    pub calendar_id: String,
    pub summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_at_utc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_at_utc: Option<String>,
    #[serde(default)]
    pub attendee_emails: Vec<String>,
    pub external_attendee_count: usize,
    pub minutes_until_start: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub html_link: Option<String>,
}

#[derive(Debug, Clone)]
pub(super) struct ParsedGoogleCommand {
    pub(super) service: String,
    pub(super) path: Vec<String>,
    pub(super) params: Value,
    pub(super) body: Option<Value>,
    pub(super) upload_path: Option<String>,
    pub(super) page_all: bool,
    pub(super) page_limit: u64,
    pub(super) page_delay_ms: u64,
    pub(super) options: HashMap<String, Vec<String>>,
}
