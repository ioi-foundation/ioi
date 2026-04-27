use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnectorIntentTarget {
    Slack,
    Jira,
    Asana,
    Gmail,
    Mail,
    Calendar,
    Docs,
    Sheets,
    Drive,
    Tasks,
    Chat,
    BigQuery,
}

impl ConnectorIntentTarget {
    fn key(self) -> &'static str {
        match self {
            Self::Slack => "slack",
            Self::Jira => "jira",
            Self::Asana => "asana",
            Self::Gmail => "gmail",
            Self::Mail => "mail",
            Self::Calendar => "calendar",
            Self::Docs => "docs",
            Self::Sheets => "sheets",
            Self::Drive => "drive",
            Self::Tasks => "tasks",
            Self::Chat => "chat",
            Self::BigQuery => "bigquery",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Slack => "Slack",
            Self::Jira => "Jira",
            Self::Asana => "Asana",
            Self::Gmail => "Gmail",
            Self::Mail => "Mail",
            Self::Calendar => "Google Calendar",
            Self::Docs => "Google Docs",
            Self::Sheets => "Google Sheets",
            Self::Drive => "Google Drive",
            Self::Tasks => "Google Tasks",
            Self::Chat => "Google Chat",
            Self::BigQuery => "Google BigQuery",
        }
    }

    fn identity_terms(self) -> &'static [&'static str] {
        match self {
            Self::Slack => &["workspace", "channel", "team"],
            Self::Jira => &["project", "workspace", "board"],
            Self::Asana => &["workspace", "project", "team"],
            Self::Gmail | Self::Mail => &["inbox", "mailbox", "email", "account"],
            Self::Calendar => &["calendar", "account"],
            Self::Docs => &["document", "doc", "account"],
            Self::Sheets => &["sheet", "spreadsheet", "account"],
            Self::Drive => &["drive", "folder", "account"],
            Self::Tasks => &["task list", "list", "account"],
            Self::Chat => &["space", "chat", "account"],
            Self::BigQuery => &["project", "dataset", "account"],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::kernel::chat) struct ChatConnectorRouteContext {
    pub(in crate::kernel::chat) decision_evidence: Vec<String>,
    pub(in crate::kernel::chat) force_clarification_question: Option<String>,
    pub(in crate::kernel::chat) clear_redundant_identity_clarification: bool,
}

fn normalized_connector_intent_text(intent: &str) -> String {
    ChatIntentContext::new(intent).normalized().to_string()
}

fn normalized_contains_any_phrase(normalized: &str, phrases: &[&str]) -> bool {
    phrases.iter().any(|phrase| normalized.contains(phrase))
}

fn intent_requests_created_deliverable(intent: &str) -> bool {
    ChatIntentContext::new(intent).requests_created_deliverable()
}

fn intent_requests_explicit_downloadable_export(intent: &str) -> bool {
    ChatIntentContext::new(intent)
        .explicit_downloadable_export_format()
        .is_some()
}

fn connector_action_signal_present(normalized: &str) -> bool {
    normalized_contains_any_phrase(
        normalized,
        &[
            " my ",
            " our ",
            " unread ",
            " inbox ",
            " mailbox ",
            " email ",
            " emails ",
            " message ",
            " messages ",
            " summarize ",
            " summary ",
            " check ",
            " show ",
            " list ",
            " read ",
            " find ",
            " search ",
            " create ",
            " draft ",
            " reply ",
            " calendar ",
            " task ",
            " tasks ",
            " sheet ",
            " sheets ",
            " spreadsheet ",
            " drive ",
            " doc ",
            " docs ",
            " channel ",
            " issue ",
            " issues ",
            " ticket ",
            " tickets ",
            " board ",
            " project ",
            " dataset ",
            " query ",
        ],
    )
}

fn inferred_connector_intent_target(intent: &str) -> Option<ConnectorIntentTarget> {
    let padded = format!(" {} ", normalized_connector_intent_text(intent));
    if !connector_action_signal_present(&padded) {
        return None;
    }

    if padded.contains(" slack ") {
        return Some(ConnectorIntentTarget::Slack);
    }
    if padded.contains(" jira ") {
        return Some(ConnectorIntentTarget::Jira);
    }
    if padded.contains(" asana ") {
        return Some(ConnectorIntentTarget::Asana);
    }
    if padded.contains(" gmail ")
        || (padded.contains(" google ")
            && (padded.contains(" email ") || padded.contains(" inbox ")))
    {
        return Some(ConnectorIntentTarget::Gmail);
    }
    if padded.contains(" bigquery ") {
        return Some(ConnectorIntentTarget::BigQuery);
    }
    if padded.contains(" calendar ") {
        return Some(ConnectorIntentTarget::Calendar);
    }
    if padded.contains(" sheets ")
        || padded.contains(" spreadsheet ")
        || padded.contains(" spreadsheets ")
    {
        return Some(ConnectorIntentTarget::Sheets);
    }
    if padded.contains(" docs ") || padded.contains(" doc ") {
        return Some(ConnectorIntentTarget::Docs);
    }
    if padded.contains(" drive ") {
        return Some(ConnectorIntentTarget::Drive);
    }
    if padded.contains(" tasks ") || padded.contains(" task list ") {
        return Some(ConnectorIntentTarget::Tasks);
    }
    if padded.contains(" google chat ") || padded.contains(" chat space ") {
        return Some(ConnectorIntentTarget::Chat);
    }
    if padded.contains(" email ")
        || padded.contains(" emails ")
        || padded.contains(" mailbox ")
        || padded.contains(" inbox ")
        || padded.contains(" unread ")
    {
        return Some(ConnectorIntentTarget::Mail);
    }

    None
}

fn intent_prefers_local_message_compose(intent: &str) -> bool {
    let padded = format!(" {} ", normalized_connector_intent_text(intent));
    let draft_signal =
        padded.contains(" draft ") || padded.contains(" compose ") || padded.contains(" write ");
    let email_signal = padded.contains(" email ") || padded.contains(" message ");
    let remote_mail_signal = padded.contains(" inbox ")
        || padded.contains(" mailbox ")
        || padded.contains(" unread ")
        || padded.contains(" gmail ")
        || padded.contains(" google ")
        || padded.contains(" send ")
        || padded.contains(" reply ")
        || padded.contains(" summarize ")
        || padded.contains(" summary ")
        || padded.contains(" check ")
        || padded.contains(" show ")
        || padded.contains(" list ")
        || padded.contains(" read ")
        || padded.contains(" find ")
        || padded.contains(" search ");

    draft_signal && email_signal && !remote_mail_signal
}

fn connector_status_rank(status: &str) -> u8 {
    match status.trim().to_ascii_lowercase().as_str() {
        "connected" => 3,
        "degraded" => 2,
        "needs_auth" => 1,
        _ => 0,
    }
}

fn connector_entry_supports_target(
    entry: &crate::kernel::connectors::ConnectorCatalogEntry,
    target: ConnectorIntentTarget,
) -> bool {
    let connector_id = entry.id.trim().to_ascii_lowercase();
    let provider = entry.provider.trim().to_ascii_lowercase();
    let scopes = entry
        .scopes
        .iter()
        .map(|scope| scope.trim().to_ascii_lowercase())
        .collect::<Vec<_>>();
    let has_scope = |needle: &str| scopes.iter().any(|scope| scope.contains(needle));

    match target {
        ConnectorIntentTarget::Slack => {
            connector_id.contains("slack") || provider.contains("slack") || has_scope("slack")
        }
        ConnectorIntentTarget::Jira => {
            connector_id.contains("jira") || provider.contains("jira") || has_scope("jira")
        }
        ConnectorIntentTarget::Asana => {
            connector_id.contains("asana") || provider.contains("asana") || has_scope("asana")
        }
        ConnectorIntentTarget::Gmail => connector_id == "google.workspace" || has_scope("gmail"),
        ConnectorIntentTarget::Mail => {
            connector_id == "mail.primary"
                || connector_id == "google.workspace"
                || has_scope("gmail")
                || has_scope("mail.")
        }
        ConnectorIntentTarget::Calendar => {
            connector_id == "google.workspace" || has_scope("calendar")
        }
        ConnectorIntentTarget::Docs => connector_id == "google.workspace" || has_scope("docs"),
        ConnectorIntentTarget::Sheets => connector_id == "google.workspace" || has_scope("sheets"),
        ConnectorIntentTarget::Drive => connector_id == "google.workspace" || has_scope("drive"),
        ConnectorIntentTarget::Tasks => connector_id == "google.workspace" || has_scope("tasks"),
        ConnectorIntentTarget::Chat => connector_id == "google.workspace" || has_scope("chat"),
        ConnectorIntentTarget::BigQuery => {
            connector_id == "google.workspace" || has_scope("bigquery")
        }
    }
}

fn connector_specificity_rank(
    entry: &crate::kernel::connectors::ConnectorCatalogEntry,
    target: ConnectorIntentTarget,
    intent: &str,
) -> u8 {
    let normalized = format!(" {} ", normalized_connector_intent_text(intent));
    let connector_id = entry.id.trim().to_ascii_lowercase();

    match target {
        ConnectorIntentTarget::Mail => {
            if normalized.contains(" gmail ") || normalized.contains(" google ") {
                if connector_id == "google.workspace" {
                    3
                } else {
                    0
                }
            } else if connector_id == "mail.primary" {
                2
            } else if connector_id == "google.workspace" {
                1
            } else {
                0
            }
        }
        ConnectorIntentTarget::Gmail
        | ConnectorIntentTarget::Calendar
        | ConnectorIntentTarget::Docs
        | ConnectorIntentTarget::Sheets
        | ConnectorIntentTarget::Drive
        | ConnectorIntentTarget::Tasks
        | ConnectorIntentTarget::Chat
        | ConnectorIntentTarget::BigQuery => {
            if connector_id == "google.workspace" {
                2
            } else {
                0
            }
        }
        _ => 0,
    }
}

fn provider_route_for_connector_target(
    connector_id: &str,
    target: ConnectorIntentTarget,
) -> Option<(&'static str, &'static str)> {
    match (connector_id.trim(), target) {
        ("google.workspace", ConnectorIntentTarget::Gmail | ConnectorIntentTarget::Mail) => {
            Some(("mail.google.gmail", "google_gmail"))
        }
        ("mail.primary", ConnectorIntentTarget::Mail) => {
            Some(("mail.wallet_network", "mail_connector"))
        }
        ("google.workspace", ConnectorIntentTarget::Calendar) => {
            Some(("calendar.google.workspace", "google_calendar"))
        }
        ("google.workspace", ConnectorIntentTarget::Docs) => {
            Some(("docs.google.workspace", "google_docs"))
        }
        ("google.workspace", ConnectorIntentTarget::Sheets) => {
            Some(("sheets.google.workspace", "google_sheets"))
        }
        ("google.workspace", ConnectorIntentTarget::Drive) => {
            Some(("drive.google.workspace", "google_drive"))
        }
        ("google.workspace", ConnectorIntentTarget::Tasks) => {
            Some(("tasks.google.workspace", "google_tasks"))
        }
        ("google.workspace", ConnectorIntentTarget::Chat) => {
            Some(("chat.google.workspace", "google_chat"))
        }
        ("google.workspace", ConnectorIntentTarget::BigQuery) => {
            Some(("bigquery.google.workspace", "google_bigquery"))
        }
        _ => None,
    }
}

fn redundant_connector_identity_clarification(
    question: &str,
    target: ConnectorIntentTarget,
) -> bool {
    let normalized = normalized_connector_intent_text(question);
    if !normalized.starts_with("which ") {
        return false;
    }
    target
        .identity_terms()
        .iter()
        .any(|term| normalized.contains(term))
}

pub(in crate::kernel::chat) fn infer_connector_route_context_from_catalog(
    intent: &str,
    connectors: &[crate::kernel::connectors::ConnectorCatalogEntry],
) -> Option<ChatConnectorRouteContext> {
    if intent_requests_created_deliverable(intent)
        && intent_requests_explicit_downloadable_export(intent)
    {
        return None;
    }

    let target = inferred_connector_intent_target(intent)?;
    if matches!(
        target,
        ConnectorIntentTarget::Mail | ConnectorIntentTarget::Gmail
    ) && intent_prefers_local_message_compose(intent)
    {
        return None;
    }
    let target_label = target.label();
    let mut matching = connectors
        .iter()
        .filter(|entry| connector_entry_supports_target(entry, target))
        .collect::<Vec<_>>();
    matching.sort_by(|left, right| {
        connector_status_rank(&right.status)
            .cmp(&connector_status_rank(&left.status))
            .then_with(|| {
                connector_specificity_rank(right, target, intent)
                    .cmp(&connector_specificity_rank(left, target, intent))
            })
            .then_with(|| left.id.cmp(&right.id))
    });

    if matching.is_empty() {
        return Some(ChatConnectorRouteContext {
            decision_evidence: vec![
                "connector_intent_detected".to_string(),
                format!("connector_target:{}", target.key()),
                format!("connector_target_label:{target_label}"),
                "connector_candidate_count:0".to_string(),
                "connector_missing".to_string(),
                "connector_capability_gap".to_string(),
            ],
            force_clarification_question: Some(format!(
                "{target_label} is not available in this runtime yet. Should Chat wait for you to connect it, or should I work from pasted data instead?"
            )),
            clear_redundant_identity_clarification: false,
        });
    }

    let candidate_count = matching.len();
    let best_rank = matching
        .first()
        .map(|entry| connector_status_rank(&entry.status))
        .unwrap_or(0);
    let best_specificity = matching
        .first()
        .map(|entry| connector_specificity_rank(entry, target, intent))
        .unwrap_or(0);
    let top_ranked = matching
        .iter()
        .copied()
        .take_while(|entry| {
            connector_status_rank(&entry.status) == best_rank
                && connector_specificity_rank(entry, target, intent) == best_specificity
        })
        .collect::<Vec<_>>();
    let selected = matching[0];
    let mut decision_evidence = vec![
        "connector_intent_detected".to_string(),
        "connector_preferred".to_string(),
        format!("connector_target:{}", target.key()),
        format!("connector_target_label:{target_label}"),
        format!("connector_candidate_count:{candidate_count}"),
        format!("selected_connector_id:{}", selected.id),
        format!("selected_connector_status:{}", selected.status),
    ];

    if let Some((provider_family, route_label)) =
        provider_route_for_connector_target(&selected.id, target)
    {
        decision_evidence.push(format!("selected_provider_family:{provider_family}"));
        decision_evidence.push(format!("selected_provider_route_label:{route_label}"));
    }
    if target == ConnectorIntentTarget::Mail && selected.id == "mail.primary" && candidate_count > 1
    {
        decision_evidence.push("connector_tiebreaker:narrow_connector".to_string());
    } else if target == ConnectorIntentTarget::Mail
        && selected.id == "google.workspace"
        && normalized_connector_intent_text(intent).contains("gmail")
    {
        decision_evidence.push("connector_tiebreaker:explicit_provider_mention".to_string());
    }

    let force_clarification_question = if best_rank < 3 {
        decision_evidence.push("connector_auth_required".to_string());
        Some(format!(
            "{target_label} is available here but not connected yet. Should Chat wait for you to connect it, or should I use another source?"
        ))
    } else if top_ranked.len() > 1 {
        decision_evidence.push("connector_choice_required".to_string());
        let choice_labels = top_ranked
            .iter()
            .map(|entry| entry.name.trim())
            .filter(|value| !value.is_empty())
            .collect::<Vec<_>>();
        Some(format!(
            "Chat found more than one connected {target_label} route. Which connector should it use{}?",
            if choice_labels.is_empty() {
                String::new()
            } else {
                format!(": {}", choice_labels.join(" or "))
            }
        ))
    } else {
        None
    };

    Some(ChatConnectorRouteContext {
        decision_evidence,
        force_clarification_question,
        clear_redundant_identity_clarification: best_rank >= 3 && candidate_count == 1,
    })
}

pub(in crate::kernel::chat) fn merge_connector_route_context(
    outcome_request: &mut ChatOutcomeRequest,
    connector_context: ChatConnectorRouteContext,
) {
    for hint in connector_context.decision_evidence {
        if !outcome_request
            .decision_evidence
            .iter()
            .any(|existing| existing == &hint)
        {
            outcome_request.decision_evidence.push(hint);
        }
    }

    if let Some(question) = connector_context.force_clarification_question {
        outcome_request.needs_clarification = true;
        outcome_request.clarification_questions = vec![question];
        return;
    }

    if connector_context.clear_redundant_identity_clarification
        && outcome_request.needs_clarification
        && outcome_request
            .clarification_questions
            .first()
            .map(|question| {
                inferred_connector_intent_target(question)
                    .or_else(|| inferred_connector_intent_target(&outcome_request.raw_prompt))
                    .map(|target| redundant_connector_identity_clarification(question, target))
                    .unwrap_or(false)
            })
            .unwrap_or(false)
    {
        outcome_request.needs_clarification = false;
        outcome_request.clarification_questions.clear();
        if !outcome_request
            .decision_evidence
            .iter()
            .any(|hint| hint == "connector_identity_auto_selected")
        {
            outcome_request
                .decision_evidence
                .push("connector_identity_auto_selected".to_string());
        }
    }

    super::refresh_outcome_request_topology(outcome_request, None);
}
