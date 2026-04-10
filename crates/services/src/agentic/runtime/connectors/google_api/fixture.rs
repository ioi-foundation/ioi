use super::types::GOOGLE_MOCK_FIXTURE_PATH_ENV;
use super::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct MockGoogleFixtureState {
    pub(super) account_email: String,
    #[serde(default)]
    pub(super) granted_scopes: Vec<String>,
    #[serde(default)]
    pub(super) messages: Vec<MockGoogleFixtureMessage>,
    #[serde(default)]
    pub(super) events: Vec<MockGoogleFixtureCalendarEvent>,
    #[serde(default = "default_mock_sequence")]
    pub(super) next_message_seq: u64,
    #[serde(default = "default_mock_sequence")]
    pub(super) next_thread_seq: u64,
    #[serde(default = "default_mock_sequence")]
    pub(super) next_event_seq: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct MockGoogleFixtureMessage {
    pub(super) id: String,
    pub(super) thread_id: String,
    pub(super) to: String,
    pub(super) subject: String,
    pub(super) body_text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) in_reply_to: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) references: Option<String>,
    pub(super) label_ids: Vec<String>,
}

#[derive(Debug, Clone)]
struct ParsedMockGmailRawMessage {
    to: String,
    subject: String,
    body_text: String,
    in_reply_to: Option<String>,
    references: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct MockGoogleFixtureCalendarEvent {
    id: String,
    calendar_id: String,
    summary: String,
    start: String,
    end: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    location: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(default)]
    attendee_emails: Vec<String>,
    html_link: String,
}

fn default_mock_sequence() -> u64 {
    1
}

pub(super) fn mock_fixture_path() -> Option<PathBuf> {
    std::env::var(GOOGLE_MOCK_FIXTURE_PATH_ENV)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

pub(super) fn load_mock_fixture_state(path: &Path) -> Result<MockGoogleFixtureState, String> {
    let raw = fs::read_to_string(path).map_err(|error| {
        format!(
            "Failed to read Google mock fixture state {}: {}",
            path.display(),
            error
        )
    })?;
    serde_json::from_str::<MockGoogleFixtureState>(&raw).map_err(|error| {
        format!(
            "Failed to parse Google mock fixture state {}: {}",
            path.display(),
            error
        )
    })
}

fn save_mock_fixture_state(path: &Path, state: &MockGoogleFixtureState) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(state).map_err(|error| {
        format!(
            "Failed to serialize Google mock fixture state {}: {}",
            path.display(),
            error
        )
    })?;
    fs::write(path, bytes).map_err(|error| {
        format!(
            "Failed to write Google mock fixture state {}: {}",
            path.display(),
            error
        )
    })
}

fn next_mock_message_id(state: &mut MockGoogleFixtureState) -> String {
    let id = format!("mock-msg-{}", state.next_message_seq);
    state.next_message_seq = state.next_message_seq.saturating_add(1);
    id
}

fn next_mock_thread_id(state: &mut MockGoogleFixtureState) -> String {
    let id = format!("mock-thread-{}", state.next_thread_seq);
    state.next_thread_seq = state.next_thread_seq.saturating_add(1);
    id
}

fn next_mock_event_id(state: &mut MockGoogleFixtureState) -> String {
    let id = format!("mock-event-{}", state.next_event_seq);
    state.next_event_seq = state.next_event_seq.saturating_add(1);
    id
}

fn parse_mock_gmail_raw_message(raw: &str) -> Result<ParsedMockGmailRawMessage, String> {
    let decoded = URL_SAFE_NO_PAD
        .decode(raw.as_bytes())
        .map_err(|error| format!("Failed to decode Gmail raw message: {}", error))?;
    let text = String::from_utf8(decoded)
        .map_err(|error| format!("Gmail raw message was not UTF-8: {}", error))?;
    let normalized = text.replace("\r\n", "\n");
    let (headers, body) = normalized
        .split_once("\n\n")
        .ok_or_else(|| "Gmail raw message was missing header/body separator.".to_string())?;
    let mut to = None::<String>;
    let mut subject = None::<String>;
    let mut in_reply_to = None::<String>;
    let mut references = None::<String>;
    for line in headers.lines() {
        let trimmed = line.trim();
        if let Some(value) = trimmed.strip_prefix("To:") {
            to = Some(value.trim().to_string());
        } else if let Some(value) = trimmed.strip_prefix("Subject:") {
            subject = Some(value.trim().to_string());
        } else if let Some(value) = trimmed.strip_prefix("In-Reply-To:") {
            in_reply_to = Some(value.trim().to_string());
        } else if let Some(value) = trimmed.strip_prefix("References:") {
            references = Some(value.trim().to_string());
        }
    }
    Ok(ParsedMockGmailRawMessage {
        to: to.ok_or_else(|| "Gmail raw message was missing To header.".to_string())?,
        subject: subject
            .ok_or_else(|| "Gmail raw message was missing Subject header.".to_string())?,
        body_text: body.trim().to_string(),
        in_reply_to,
        references,
    })
}

fn mock_option_value(options: &HashMap<String, Vec<String>>, key: &str) -> Option<String> {
    options.get(key).and_then(|values| values.last()).cloned()
}

fn mock_option_values(options: &HashMap<String, Vec<String>>, key: &str) -> Vec<String> {
    options.get(key).cloned().unwrap_or_default()
}

fn mock_message_matches_query(message: &MockGoogleFixtureMessage, query: Option<&str>) -> bool {
    let Some(query) = query.map(str::trim).filter(|value| !value.is_empty()) else {
        return true;
    };
    let lowered = query.to_ascii_lowercase();
    if lowered.contains("label:drafts")
        && !message
            .label_ids
            .iter()
            .any(|label| label.eq_ignore_ascii_case("DRAFT"))
    {
        return false;
    }
    if lowered.contains("label:sent")
        && !message
            .label_ids
            .iter()
            .any(|label| label.eq_ignore_ascii_case("SENT"))
    {
        return false;
    }
    if lowered.contains("in:sent")
        && !message
            .label_ids
            .iter()
            .any(|label| label.eq_ignore_ascii_case("SENT"))
    {
        return false;
    }
    let general = lowered
        .replace("label:drafts", "")
        .replace("label:sent", "")
        .replace("in:sent", "");
    let general = general.trim();
    if general.is_empty() {
        return true;
    }
    message.to.to_ascii_lowercase().contains(general)
        || message.subject.to_ascii_lowercase().contains(general)
        || message.body_text.to_ascii_lowercase().contains(general)
}

pub(super) fn execute_mock_google_command(
    path: &Path,
    parsed: ParsedGoogleCommand,
) -> Result<Value, String> {
    let mut state = load_mock_fixture_state(path)?;
    let path_segments = parsed.path.iter().map(String::as_str).collect::<Vec<_>>();
    let output = match (parsed.service.as_str(), path_segments.as_slice()) {
        ("gmail", ["drafts", "create"]) => {
            let raw = parsed
                .body
                .as_ref()
                .and_then(|value| value.get("message"))
                .and_then(|value| value.get("raw"))
                .and_then(Value::as_str)
                .ok_or_else(|| "Google mock draft create requires message.raw.".to_string())?;
            let parsed_raw = parse_mock_gmail_raw_message(raw)?;
            let message_id = next_mock_message_id(&mut state);
            let thread_id = parsed
                .body
                .as_ref()
                .and_then(|value| value.get("message"))
                .and_then(|value| value.get("threadId"))
                .and_then(Value::as_str)
                .map(str::to_string)
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| next_mock_thread_id(&mut state));
            let message = MockGoogleFixtureMessage {
                id: message_id.clone(),
                thread_id: thread_id.clone(),
                to: parsed_raw.to.clone(),
                subject: parsed_raw.subject.clone(),
                body_text: parsed_raw.body_text.clone(),
                in_reply_to: parsed_raw.in_reply_to.clone(),
                references: parsed_raw.references.clone(),
                label_ids: vec!["DRAFT".to_string()],
            };
            state.messages.push(message.clone());
            json!({
                "id": format!("mock-draft-{}", message_id),
                "message": {
                    "id": message.id,
                    "threadId": message.thread_id,
                    "to": message.to,
                    "subject": message.subject,
                    "bodyText": message.body_text,
                    "labelIds": message.label_ids
                }
            })
        }
        ("gmail", ["+send"]) => {
            let to = mock_option_value(&parsed.options, "to")
                .ok_or_else(|| "Google mock send requires --to.".to_string())?;
            let subject = mock_option_value(&parsed.options, "subject")
                .ok_or_else(|| "Google mock send requires --subject.".to_string())?;
            let body_text = mock_option_value(&parsed.options, "body")
                .ok_or_else(|| "Google mock send requires --body.".to_string())?;
            let message_id = next_mock_message_id(&mut state);
            let thread_id = mock_option_value(&parsed.options, "thread-id")
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| next_mock_thread_id(&mut state));
            let message = MockGoogleFixtureMessage {
                id: message_id.clone(),
                thread_id: thread_id.clone(),
                to: to.clone(),
                subject: subject.clone(),
                body_text: body_text.clone(),
                in_reply_to: mock_option_value(&parsed.options, "in-reply-to"),
                references: mock_option_value(&parsed.options, "references"),
                label_ids: vec!["SENT".to_string()],
            };
            state.messages.push(message.clone());
            json!({
                "id": message.id,
                "threadId": message.thread_id,
                "to": message.to,
                "subject": message.subject,
                "bodyText": message.body_text,
                "labelIds": message.label_ids
            })
        }
        ("gmail", ["+triage"]) => {
            let max = mock_option_value(&parsed.options, "max")
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(20);
            let query = mock_option_value(&parsed.options, "query");
            let include_labels = parsed.options.contains_key("labels");
            let messages = state
                .messages
                .iter()
                .rev()
                .filter(|message| mock_message_matches_query(message, query.as_deref()))
                .take(max)
                .map(|message| {
                    let mut value = json!({
                        "id": message.id,
                        "threadId": message.thread_id,
                        "to": message.to,
                        "subject": message.subject,
                        "preview": message.body_text,
                    });
                    if include_labels {
                        value["labelIds"] = Value::Array(
                            message
                                .label_ids
                                .iter()
                                .map(|label| Value::String(label.clone()))
                                .collect(),
                        );
                    }
                    value
                })
                .collect::<Vec<_>>();
            json!({ "messages": messages })
        }
        ("calendar", ["+insert"]) => {
            let calendar_id = mock_option_value(&parsed.options, "calendar")
                .unwrap_or_else(|| "primary".to_string());
            let summary = mock_option_value(&parsed.options, "summary")
                .ok_or_else(|| "Google mock calendar insert requires --summary.".to_string())?;
            let start = mock_option_value(&parsed.options, "start")
                .ok_or_else(|| "Google mock calendar insert requires --start.".to_string())?;
            let end = mock_option_value(&parsed.options, "end")
                .ok_or_else(|| "Google mock calendar insert requires --end.".to_string())?;
            let attendees = mock_option_values(&parsed.options, "attendee");
            let event_id = next_mock_event_id(&mut state);
            let event = MockGoogleFixtureCalendarEvent {
                id: event_id.clone(),
                calendar_id: calendar_id.clone(),
                summary: summary.clone(),
                start: start.clone(),
                end: end.clone(),
                location: mock_option_value(&parsed.options, "location"),
                description: mock_option_value(&parsed.options, "description"),
                attendee_emails: attendees.clone(),
                html_link: format!(
                    "https://calendar.google.com/calendar/event?eid={}",
                    event_id
                ),
            };
            state.events.push(event.clone());
            json!({
                "id": event.id,
                "calendarId": event.calendar_id,
                "summary": event.summary,
                "start": { "dateTime": event.start },
                "end": { "dateTime": event.end },
                "location": event.location,
                "description": event.description,
                "attendees": event.attendee_emails.into_iter().map(|email| json!({ "email": email })).collect::<Vec<_>>(),
                "htmlLink": event.html_link
            })
        }
        ("calendar", ["events", "list"]) => {
            let calendar_id = parsed
                .params
                .get("calendarId")
                .and_then(Value::as_str)
                .unwrap_or("primary");
            let items = state
                .events
                .iter()
                .filter(|event| event.calendar_id == calendar_id)
                .map(|event| {
                    json!({
                        "id": event.id,
                        "calendarId": event.calendar_id,
                        "summary": event.summary,
                        "start": { "dateTime": event.start },
                        "end": { "dateTime": event.end },
                        "htmlLink": event.html_link
                    })
                })
                .collect::<Vec<_>>();
            json!({ "items": items })
        }
        ("calendar", ["events", "get"]) => {
            let calendar_id = parsed
                .params
                .get("calendarId")
                .and_then(Value::as_str)
                .unwrap_or("primary");
            let event_id = parsed
                .params
                .get("eventId")
                .and_then(Value::as_str)
                .ok_or_else(|| "Google mock calendar get requires eventId.".to_string())?;
            let event = state
                .events
                .iter()
                .find(|event| event.calendar_id == calendar_id && event.id == event_id)
                .ok_or_else(|| format!("Mock calendar event '{}' was not found.", event_id))?;
            json!({
                "id": event.id,
                "calendarId": event.calendar_id,
                "summary": event.summary,
                "start": { "dateTime": event.start },
                "end": { "dateTime": event.end },
                "htmlLink": event.html_link
            })
        }
        _ => {
            return Err(format!(
                "Unsupported Google mock command service='{}' path={:?}",
                parsed.service, parsed.path
            ))
        }
    };
    save_mock_fixture_state(path, &state)?;
    Ok(output)
}
