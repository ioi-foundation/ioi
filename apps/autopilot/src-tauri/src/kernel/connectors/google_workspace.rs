use super::auth;
use super::policy::{
    approval_marker_present, approval_required_error, AutomationPolicyMode, PolicyDecisionMode,
    ShieldApprovalRequest, ShieldPolicyManager,
};
use super::subscriptions::{
    build_registration_from_result, GoogleAutomationManager, GoogleConnectorSubscriptionView,
};
use crate::models::AppState;
use ioi_services::agentic::runtime::connectors::google_workspace as shared;
use serde_json::{json, Value};
use std::sync::Mutex;
use tauri::State;

pub use shared::{ConnectorActionDefinition, ConnectorActionResult, ConnectorConfigureResult};

pub async fn connector_list_actions(
    connector_id: String,
) -> Result<Vec<ConnectorActionDefinition>, String> {
    if shared::matches_google_connector_id(&connector_id) {
        Ok(shared::google_connector_actions())
    } else {
        Ok(Vec::new())
    }
}

pub async fn connector_configure(
    state: State<'_, Mutex<AppState>>,
    manager: State<'_, GoogleAutomationManager>,
    connector_id: String,
    input: Value,
) -> Result<ConnectorConfigureResult, String> {
    if shared::matches_google_connector_id(&connector_id) {
        let _ = auth::sync_google_auth_from_wallet(&state).await;
    }
    let mut result = shared::connector_configure(&connector_id, input).await?;
    if shared::matches_google_connector_id(&connector_id) {
        auth::sync_google_auth_to_wallet(&state).await?;
        let subscriptions = manager
            .list_subscriptions(shared::GOOGLE_CONNECTOR_ID)
            .await?;
        result.data = Some(merge_data_with_subscriptions(
            result.data.take(),
            subscriptions,
        )?);
    }
    Ok(result)
}

pub async fn connector_run_action(
    manager: State<'_, GoogleAutomationManager>,
    policy_manager: State<'_, ShieldPolicyManager>,
    connector_id: String,
    action_id: String,
    input: Value,
) -> Result<ConnectorActionResult, String> {
    enforce_google_connector_policy(&policy_manager, &connector_id, &action_id, &input)?;
    let mut result = shared::connector_run_action(&connector_id, &action_id, input.clone()).await?;
    if shared::matches_google_connector_id(&connector_id) {
        if let Some(registration) =
            build_registration_from_result(&action_id, &input, &result).await?
        {
            let subscription = manager.register_subscription(registration).await?;
            result.summary = match action_id.as_str() {
                "gmail.watch_emails" => "Started durable Gmail watch automation.".to_string(),
                "events.subscribe" => "Started durable Workspace Events automation.".to_string(),
                _ => result.summary,
            };
            result.data = merge_data_with_subscription(result.data, subscription)?;
        }
    }
    Ok(result)
}

pub async fn connector_list_subscriptions(
    manager: State<'_, GoogleAutomationManager>,
    connector_id: String,
) -> Result<Vec<GoogleConnectorSubscriptionView>, String> {
    if shared::matches_google_connector_id(&connector_id) {
        manager
            .list_subscriptions(shared::GOOGLE_CONNECTOR_ID)
            .await
    } else {
        Ok(Vec::new())
    }
}

fn enforce_google_connector_policy(
    policy_manager: &State<'_, ShieldPolicyManager>,
    connector_id: &str,
    action_id: &str,
    input: &Value,
) -> Result<(), String> {
    if !shared::matches_google_connector_id(connector_id) {
        return Ok(());
    }

    let Some(action) = shared::google_connector_actions()
        .into_iter()
        .find(|candidate| candidate.id == action_id)
    else {
        return Ok(());
    };

    let policy = policy_manager.resolve_connector_policy(shared::GOOGLE_CONNECTOR_ID);
    let approved = approval_marker_present(input);
    let action_id_owned = action.id.clone();
    let action_label = action.label.clone();
    let policy_family = match action.kind.as_str() {
        "read" => "reads",
        "write" | "workflow" => "writes",
        "expert" => "expert",
        "admin" if is_automation_action(action_id) => "automations",
        "admin" => "admin",
        _ => "connector_action",
    };
    let scope_key = format!("connector:{}:action:{}", connector_id, action_id);
    let scope_label = format!("{} · {}", connector_id, action_label);
    let requires_confirmation = match action.kind.as_str() {
        "read" => match policy.reads {
            PolicyDecisionMode::Auto => false,
            PolicyDecisionMode::Confirm => true,
            PolicyDecisionMode::Block => {
                return Err(format!(
                    "Blocked by Shield policy: {} is disabled for this connector.",
                    action_label
                ));
            }
        },
        "write" | "workflow" => match policy.writes {
            PolicyDecisionMode::Auto => false,
            PolicyDecisionMode::Confirm => true,
            PolicyDecisionMode::Block => {
                return Err(format!(
                    "Blocked by Shield policy: {} is disabled for this connector.",
                    action_label
                ));
            }
        },
        "expert" => match policy.expert {
            PolicyDecisionMode::Auto => false,
            PolicyDecisionMode::Confirm => true,
            PolicyDecisionMode::Block => {
                return Err(format!(
                    "Blocked by Shield policy: expert Google actions are disabled for this connector.",
                ));
            }
        },
        "admin" if is_automation_action(action_id) => match policy.automations {
            AutomationPolicyMode::ConfirmOnCreate
            | AutomationPolicyMode::ConfirmOnRun
            | AutomationPolicyMode::ManualOnly => true,
        },
        "admin" => match policy.admin {
            PolicyDecisionMode::Auto => false,
            PolicyDecisionMode::Confirm => true,
            PolicyDecisionMode::Block => {
                return Err(format!(
                    "Blocked by Shield policy: {} is disabled for this connector.",
                    action_label
                ));
            }
        },
        _ => false,
    };

    if requires_confirmation && !approved {
        if policy_manager.match_remembered_approval(
            connector_id,
            action_id,
            policy_family,
            Some(&scope_key),
            &action_label,
        ) {
            return Ok(());
        }
        policy_manager.record_blocker_escalation(
            connector_id,
            action_id,
            &action_label,
            policy_family,
            Some(&scope_key),
        );
        return Err(approval_required_error(&ShieldApprovalRequest {
            connector_id: connector_id.to_string(),
            action_id: action_id_owned,
            action_label: action_label.clone(),
            message: format!(
                "Shield policy requires explicit approval before running {}.",
                action_label
            ),
            policy_family: Some(policy_family.to_string()),
            scope_key: Some(scope_key),
            scope_label: Some(scope_label),
            rememberable: true,
        }));
    }

    Ok(())
}

fn is_automation_action(action_id: &str) -> bool {
    matches!(
        action_id,
        "gmail.watch_emails" | "events.subscribe" | "events.renew"
    )
}

pub async fn connector_stop_subscription(
    manager: State<'_, GoogleAutomationManager>,
    connector_id: String,
    subscription_id: String,
) -> Result<GoogleConnectorSubscriptionView, String> {
    if shared::matches_google_connector_id(&connector_id) {
        manager.stop_subscription(&subscription_id).await
    } else {
        Err(format!("Unsupported connector '{}'.", connector_id))
    }
}

pub async fn connector_resume_subscription(
    manager: State<'_, GoogleAutomationManager>,
    connector_id: String,
    subscription_id: String,
) -> Result<GoogleConnectorSubscriptionView, String> {
    if shared::matches_google_connector_id(&connector_id) {
        manager.resume_subscription(&subscription_id).await
    } else {
        Err(format!("Unsupported connector '{}'.", connector_id))
    }
}

pub async fn connector_renew_subscription(
    manager: State<'_, GoogleAutomationManager>,
    connector_id: String,
    subscription_id: String,
) -> Result<GoogleConnectorSubscriptionView, String> {
    if shared::matches_google_connector_id(&connector_id) {
        manager.renew_subscription_now(&subscription_id).await
    } else {
        Err(format!("Unsupported connector '{}'.", connector_id))
    }
}

pub async fn connector_get_subscription(
    manager: State<'_, GoogleAutomationManager>,
    connector_id: String,
    subscription_id: String,
) -> Result<GoogleConnectorSubscriptionView, String> {
    if shared::matches_google_connector_id(&connector_id) {
        manager
            .get_view(&subscription_id)
            .await?
            .ok_or_else(|| format!("Unknown Google subscription '{}'.", subscription_id))
    } else {
        Err(format!("Unsupported connector '{}'.", connector_id))
    }
}

pub async fn connector_fetch_gmail_thread(
    policy_manager: State<'_, ShieldPolicyManager>,
    connector_id: String,
    thread_id: String,
) -> Result<ConnectorActionResult, String> {
    enforce_google_connector_policy(
        &policy_manager,
        &connector_id,
        "gmail.get_thread",
        &json!({
            "threadId": thread_id,
            "format": "full"
        }),
    )?;
    shared::connector_run_action(
        &connector_id,
        "gmail.get_thread",
        json!({
            "threadId": thread_id,
            "format": "full"
        }),
    )
    .await
}

pub async fn connector_fetch_calendar_event(
    policy_manager: State<'_, ShieldPolicyManager>,
    connector_id: String,
    calendar_id: String,
    event_id: String,
) -> Result<ConnectorActionResult, String> {
    let input = json!({
        "calendarId": calendar_id,
        "eventId": event_id
    });
    enforce_google_connector_policy(&policy_manager, &connector_id, "calendar.get_event", &input)?;
    shared::connector_run_action(&connector_id, "calendar.get_event", input).await
}

fn merge_data_with_subscriptions(
    data: Option<Value>,
    subscriptions: Vec<GoogleConnectorSubscriptionView>,
) -> Result<Value, String> {
    let mut payload = match data.unwrap_or_else(|| json!({})) {
        Value::Object(map) => map,
        other => {
            let mut map = serde_json::Map::new();
            map.insert("result".to_string(), other);
            map
        }
    };
    payload.insert(
        "subscriptions".to_string(),
        serde_json::to_value(subscriptions)
            .map_err(|error| format!("Failed to serialize Google subscriptions: {}", error))?,
    );
    Ok(Value::Object(payload))
}

fn merge_data_with_subscription(
    data: Value,
    subscription: GoogleConnectorSubscriptionView,
) -> Result<Value, String> {
    let mut payload = match data {
        Value::Object(map) => map,
        other => {
            let mut map = serde_json::Map::new();
            map.insert("result".to_string(), other);
            map
        }
    };
    payload.insert(
        "subscriptionRuntime".to_string(),
        serde_json::to_value(subscription).map_err(|error| {
            format!("Failed to serialize Google subscription runtime: {}", error)
        })?,
    );
    Ok(Value::Object(payload))
}
