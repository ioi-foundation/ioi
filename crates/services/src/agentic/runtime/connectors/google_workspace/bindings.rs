pub fn google_connector_actions() -> Vec<ConnectorActionDefinition> {
    google_connector_action_specs()
        .into_iter()
        .map(|spec| ConnectorActionDefinition {
            id: spec.id.to_string(),
            service: spec.service.to_string(),
            service_label: spec.service_label.to_string(),
            tool_name: spec.tool_name.to_string(),
            label: spec.label.to_string(),
            description: spec.description.to_string(),
            kind: spec.kind.to_string(),
            confirm_before_run: spec.confirm_before_run,
            fields: spec.fields,
            required_scopes: spec
                .required_scopes
                .iter()
                .map(|scope| (*scope).to_string())
                .collect(),
        })
        .collect()
}

pub fn google_connector_tool_definitions() -> Vec<LlmToolDefinition> {
    google_connector_action_specs()
        .into_iter()
        .map(|spec| LlmToolDefinition {
            name: spec.tool_name.to_string(),
            description: spec.description.to_string(),
            parameters: connector_fields_to_schema(&spec.fields).to_string(),
        })
        .collect()
}

pub fn google_connector_tool_bindings() -> Vec<ToolCapabilityBinding> {
    google_connector_action_specs()
        .into_iter()
        .map(|spec| ToolCapabilityBinding {
            tool_name: spec.tool_name.to_string(),
            action_target: ActionTarget::Custom(spec.tool_name.to_string()),
            capabilities: spec
                .capabilities
                .iter()
                .map(|capability| CapabilityId::from(*capability))
                .collect(),
        })
        .collect()
}

fn google_service_route_binding(service: &str) -> Option<(&'static str, &'static str)> {
    match service {
        "gmail" => Some(("mail.google.gmail", "google_gmail")),
        "calendar" => Some(("calendar.google.workspace", "google_calendar")),
        "docs" => Some(("docs.google.workspace", "google_docs")),
        "sheets" => Some(("sheets.google.workspace", "google_sheets")),
        "drive" => Some(("drive.google.workspace", "google_drive")),
        "tasks" => Some(("tasks.google.workspace", "google_tasks")),
        "chat" => Some(("chat.google.workspace", "google_chat")),
        "bigquery" => Some(("bigquery.google.workspace", "google_bigquery")),
        "events" => Some(("events.google.workspace", "google_events")),
        "workflow" => Some(("workflow.google.workspace", "google_workflow")),
        "expert" => Some(("expert.google.workspace", "google_expert")),
        _ => None,
    }
}

pub fn google_connector_tool_route_bindings() -> Vec<ConnectorToolRouteBinding> {
    google_connector_action_specs()
        .into_iter()
        .filter_map(|spec| {
            let (provider_family, route_label) = google_service_route_binding(spec.service)?;
            Some(ConnectorToolRouteBinding {
                tool_name: spec.tool_name,
                provider_family,
                route_label,
            })
        })
        .collect()
}

pub fn is_google_connector_tool_name(name: &str) -> bool {
    let normalized = name.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return false;
    }
    google_connector_action_specs()
        .iter()
        .any(|spec| spec.tool_name == normalized)
}

pub fn is_google_mail_tool_name(name: &str) -> bool {
    name.trim()
        .to_ascii_lowercase()
        .starts_with("connector__google__gmail_")
}

pub fn google_tool_provider_family(name: &str) -> Option<&'static str> {
    let normalized = name.trim().to_ascii_lowercase();
    google_connector_tool_route_bindings()
        .into_iter()
        .find(|binding| binding.tool_name == normalized)
        .map(|binding| binding.provider_family)
}

pub fn google_tool_route_label(name: &str) -> Option<&'static str> {
    let normalized = name.trim().to_ascii_lowercase();
    google_connector_tool_route_bindings()
        .into_iter()
        .find(|binding| binding.tool_name == normalized)
        .map(|binding| binding.route_label)
}

fn capability_vec(sorted_caps: &BTreeSet<CapabilityId>) -> Vec<CapabilityId> {
    sorted_caps.iter().cloned().collect()
}

fn google_family_summary(provider_family: &str, account: Option<&str>) -> String {
    let surface = match provider_family {
        "mail.google.gmail" => "Connected Gmail route",
        "calendar.google.workspace" => "Connected Google Calendar route",
        "docs.google.workspace" => "Connected Google Docs route",
        "sheets.google.workspace" => "Connected Google Sheets route",
        "drive.google.workspace" => "Connected Google Drive route",
        "tasks.google.workspace" => "Connected Google Tasks route",
        "chat.google.workspace" => "Connected Google Chat route",
        "bigquery.google.workspace" => "Connected Google BigQuery route",
        "events.google.workspace" => "Connected Google Events route",
        "workflow.google.workspace" => "Connected Google workflow route",
        "expert.google.workspace" => "Connected expert Google route",
        _ => "Connected Google provider route",
    };
    match account.filter(|value| !value.trim().is_empty()) {
        Some(account) => format!("{} for account {}.", surface, account.trim()),
        None => format!("{}.", surface),
    }
}

async fn discover_google_provider_candidates(
    provider_family: &str,
    route_label: &str,
    capabilities: &BTreeSet<CapabilityId>,
) -> Vec<ioi_types::app::agentic::ProviderRouteCandidate> {
    let Ok(status) = google_auth::status().await else {
        return Vec::new();
    };
    if status.status != "connected" {
        return Vec::new();
    }
    let account = status
        .data
        .get("account")
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let provider_id = format!(
        "google://{}/{}",
        account.unwrap_or("connected-account"),
        provider_family
    );
    vec![ioi_types::app::agentic::ProviderRouteCandidate {
        provider_family: provider_family.to_string(),
        route_label: route_label.to_string(),
        connector_id: GOOGLE_CONNECTOR_ID.to_string(),
        provider_id: Some(provider_id),
        account_label: account.map(str::to_string),
        capabilities: capability_vec(capabilities),
        summary: google_family_summary(provider_family, account),
    }]
}

fn discover_google_provider_candidates_boxed<'a>(
    _state: Option<&'a dyn ioi_api::state::StateAccess>,
    provider_family: &'a str,
    route_label: &'a str,
    capabilities: &'a BTreeSet<CapabilityId>,
) -> ProviderCandidateDiscoveryFuture<'a> {
    Box::pin(async move {
        discover_google_provider_candidates(provider_family, route_label, capabilities).await
    })
}

pub fn google_connector_provider_probe_bindings() -> Vec<ConnectorProviderProbeBinding> {
    let mut seen = BTreeSet::new();
    google_connector_tool_route_bindings()
        .into_iter()
        .filter(|binding| seen.insert(binding.provider_family))
        .map(|binding| ConnectorProviderProbeBinding {
            provider_family: binding.provider_family,
            discover: discover_google_provider_candidates_boxed,
        })
        .collect()
}

fn google_selected_provider_id(agent_state: &AgentState) -> Option<String> {
    agent_state
        .resolved_intent
        .as_ref()
        .and_then(|resolved| resolved.provider_selection.as_ref())
        .and_then(|selection| selection.selected_provider_id.clone())
}

fn resolve_google_symbolic_reference_boxed<'a>(
    agent_state: &'a AgentState,
    reference: &'a str,
) -> SymbolicReferenceResolutionFuture<'a> {
    Box::pin(async move {
        match reference.trim() {
            "connected_account.email" => {
                let auth = google_auth::access_context(&[]).await?;
                let Some(email) = auth
                    .account_email
                    .as_deref()
                    .and_then(canonicalize_email_recipient)
                else {
                    return Ok(None);
                };
                Ok(Some(ResolvedSymbolicReference {
                    value: Value::String(email.clone()),
                    origin: ArgumentOrigin::StateRef,
                    evidence: format!("symbolic_ref=connected_account.email;resolved={}", email),
                    provider_id: google_selected_provider_id(agent_state),
                }))
            }
            _ => Ok(None),
        }
    })
}

pub fn google_connector_symbolic_reference_bindings() -> Vec<ConnectorSymbolicReferenceBinding> {
    vec![ConnectorSymbolicReferenceBinding {
        connector_id: GOOGLE_CONNECTOR_ID,
        resolve: resolve_google_symbolic_reference_boxed,
    }]
}

fn query_mentions_connected_account_alias(query: &str, provider_terms: &[&str]) -> bool {
    let normalized_query = format!(" {} ", normalize_alias_phrase(query));
    if normalized_query.trim().is_empty() {
        return false;
    }

    let generic_aliases = [
        "connected address",
        "my connected address",
        "your connected address",
        "connected email",
        "my connected email",
        "your connected email",
        "connected email address",
        "my connected email address",
        "your connected email address",
        "connected account",
        "my connected account",
        "your connected account",
        "connected account email",
        "my connected account email",
        "your connected account email",
    ];
    if generic_aliases.iter().any(|candidate| {
        normalized_query.contains(&format!(" {} ", normalize_alias_phrase(candidate)))
    }) {
        return true;
    }

    provider_terms.iter().any(|provider| {
        let provider = normalize_alias_phrase(provider);
        [
            format!("connected {} address", provider),
            format!("my connected {} address", provider),
            format!("your connected {} address", provider),
            format!("connected {} email", provider),
            format!("my connected {} email", provider),
            format!("your connected {} email", provider),
            format!("connected {} email address", provider),
            format!("my connected {} email address", provider),
            format!("your connected {} email address", provider),
            format!("connected {} account", provider),
            format!("my connected {} account", provider),
            format!("your connected {} account", provider),
            format!("connected {} account email", provider),
            format!("my connected {} account email", provider),
            format!("your connected {} account email", provider),
        ]
        .iter()
        .any(|candidate| normalized_query.contains(&format!(" {} ", candidate)))
    })
}

fn infer_google_symbolic_reference_from_query_boxed<'a>(
    _agent_state: &'a AgentState,
    _slot: &'a str,
    query: &'a str,
    protected_slot_kind: ProtectedSlotKind,
) -> SymbolicReferenceInferenceFuture<'a> {
    Box::pin(async move {
        if !matches!(
            protected_slot_kind,
            ProtectedSlotKind::EmailAddress | ProtectedSlotKind::AccountEmail
        ) {
            return Ok(None);
        }
        if query_mentions_connected_account_alias(query, &["google", "gmail", "google workspace"]) {
            return Ok(Some("connected_account.email".to_string()));
        }
        Ok(None)
    })
}

pub fn google_connector_symbolic_reference_inference_bindings(
) -> Vec<ConnectorSymbolicReferenceInferenceBinding> {
    vec![ConnectorSymbolicReferenceInferenceBinding {
        connector_id: GOOGLE_CONNECTOR_ID,
        infer: infer_google_symbolic_reference_from_query_boxed,
    }]
}

fn protected_slot_kind_for_google_field(
    field: &ConnectorFieldDefinition,
) -> Option<ProtectedSlotKind> {
    match field.field_type.as_str() {
        "email" => Some(ProtectedSlotKind::EmailAddress),
        _ => None,
    }
}

pub fn google_connector_protected_slot_bindings() -> Vec<ConnectorProtectedSlotBinding> {
    let mut bindings = Vec::new();
    for spec in google_connector_action_specs() {
        for field in spec.fields {
            let Some(protected_slot_kind) = protected_slot_kind_for_google_field(&field) else {
                continue;
            };
            bindings.push(ConnectorProtectedSlotBinding {
                tool_name: spec.tool_name.to_string(),
                slot: field.id,
                protected_slot_kind,
            });
        }
    }
    bindings
}

