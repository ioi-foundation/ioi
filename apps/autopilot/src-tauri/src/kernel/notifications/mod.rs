mod commands;

use crate::kernel::connectors::{self, GoogleAutomationManager, GoogleConnectorSubscriptionView};
use crate::models::{
    AppState, AssistantAttentionPolicy, AssistantAttentionProfile, AssistantNotificationClass,
    AssistantNotificationRecord, AssistantNotificationStatus, AssistantUserProfile,
    InterventionRecord, InterventionStatus, InterventionType, NotificationAction,
    NotificationActionStyle, NotificationDeliveryState, NotificationPolicyRefs,
    NotificationPreviewMode, NotificationPrivacy, NotificationRail, NotificationSeverity,
    NotificationSource, NotificationTarget, ObservationTier,
};
use crate::orchestrator::{
    load_assistant_attention_policy, load_assistant_attention_profile,
    load_assistant_notifications, load_assistant_user_profile, load_interventions,
    save_assistant_attention_policy, save_assistant_attention_profile, save_assistant_user_profile,
    upsert_assistant_notification, upsert_intervention,
};
use chrono::{DateTime, Utc};
use ioi_memory::MemoryRuntime;
use ioi_services::agentic::desktop::connectors::google_api::{
    self, CalendarMeetingPrepCandidate, GmailFollowUpCandidate,
};
use std::collections::HashSet;
use std::sync::Mutex;
use tauri::{AppHandle, Emitter, Manager, Runtime, State};
use uuid::Uuid;

pub use commands::*;

fn now_ms() -> u64 {
    crate::kernel::state::now()
}

fn app_memory_runtime<R: Runtime>(app: &AppHandle<R>) -> Option<std::sync::Arc<MemoryRuntime>> {
    let state = app.state::<Mutex<AppState>>();
    state
        .lock()
        .ok()
        .and_then(|guard| guard.memory_runtime.clone())
}

fn unresolved_intervention(status: &InterventionStatus) -> bool {
    !matches!(
        status,
        InterventionStatus::Resolved | InterventionStatus::Expired | InterventionStatus::Cancelled
    )
}

fn unresolved_assistant_notification(status: &AssistantNotificationStatus) -> bool {
    !matches!(
        status,
        AssistantNotificationStatus::Resolved
            | AssistantNotificationStatus::Dismissed
            | AssistantNotificationStatus::Expired
            | AssistantNotificationStatus::Archived
    )
}

fn is_snoozed_until_future(snoozed_until_ms: Option<u64>, now_ms: u64) -> bool {
    snoozed_until_ms.is_some_and(|snoozed_until_ms| snoozed_until_ms > now_ms)
}

fn normalize_request_hash(request_hash: &str) -> String {
    request_hash
        .trim()
        .trim_start_matches("0x")
        .to_ascii_lowercase()
}

fn detector_key_for_class(notification_class: &AssistantNotificationClass) -> &'static str {
    match notification_class {
        AssistantNotificationClass::FollowUpRisk => "follow_up_risk",
        AssistantNotificationClass::DeadlineRisk => "deadline_risk",
        AssistantNotificationClass::MeetingPrep => "meeting_prep",
        AssistantNotificationClass::StalledWorkflow => "stalled_workflow",
        AssistantNotificationClass::ValuableCompletion => "valuable_completion",
        AssistantNotificationClass::Digest => "digest",
        AssistantNotificationClass::AutomationOpportunity => "automation_opportunity",
        AssistantNotificationClass::HabitualFriction => "habitual_friction",
        AssistantNotificationClass::AuthAttention => "auth_attention",
    }
}

fn connector_scan_mode<'a>(
    policy: &'a AssistantAttentionPolicy,
    connector_key: &str,
) -> Option<&'a str> {
    policy
        .connectors
        .get(connector_key)
        .and_then(|config| config.scan_mode.as_deref())
}

fn metadata_scan_enabled(policy: &AssistantAttentionPolicy, connector_key: &str) -> bool {
    !matches!(connector_scan_mode(policy, connector_key), Some("disabled"))
}

fn feedback_priority_bias(profile: &AssistantAttentionProfile, detector_key: &str) -> f32 {
    let Some(feedback) = profile.notification_feedback.get(detector_key) else {
        return 0.0;
    };
    let resolved = *feedback.get("resolved").unwrap_or(&0) as f32;
    let acknowledged = *feedback.get("acknowledged").unwrap_or(&0) as f32;
    let dismissed = *feedback.get("dismissed").unwrap_or(&0) as f32;
    let snoozed = *feedback.get("snoozed").unwrap_or(&0) as f32;
    let total = resolved + acknowledged + dismissed + snoozed;
    if total <= f32::EPSILON {
        return 0.0;
    }
    (((resolved + 0.5 * acknowledged) - (dismissed + 0.4 * snoozed)) / total * 0.08)
        .clamp(-0.08, 0.08)
}

fn priority_boost_for_high_value_contact(
    profile: &AssistantAttentionProfile,
    values: &[Option<&str>],
) -> f32 {
    if profile.high_value_contacts.is_empty() {
        return 0.0;
    }
    let normalized_contacts = profile
        .high_value_contacts
        .iter()
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    if normalized_contacts.is_empty() {
        return 0.0;
    }

    let haystacks = values
        .iter()
        .flatten()
        .map(|value| value.trim().to_ascii_lowercase())
        .collect::<Vec<_>>();
    if haystacks.iter().any(|haystack| {
        normalized_contacts
            .iter()
            .any(|needle| haystack.contains(needle))
    }) {
        0.08
    } else {
        0.0
    }
}

fn clamp_score(score: f32) -> f32 {
    score.clamp(0.0, 0.99)
}

fn format_age_minutes(age_minutes: u64) -> String {
    if age_minutes >= 24 * 60 {
        let days = age_minutes / (24 * 60);
        if days == 1 {
            "1 day".to_string()
        } else {
            format!("{} days", days)
        }
    } else if age_minutes >= 60 {
        let hours = age_minutes / 60;
        if hours == 1 {
            "1 hour".to_string()
        } else {
            format!("{} hours", hours)
        }
    } else if age_minutes == 1 {
        "1 minute".to_string()
    } else {
        format!("{} minutes", age_minutes)
    }
}

fn rfc3339_to_ms(raw: &str) -> Option<u64> {
    DateTime::parse_from_rfc3339(raw)
        .ok()
        .map(|value| value.with_timezone(&Utc).timestamp_millis())
        .and_then(|millis| u64::try_from(millis).ok())
}

fn format_timestamp_ms(raw: u64) -> String {
    let millis = i64::try_from(raw).unwrap_or(i64::MAX);
    DateTime::<Utc>::from_timestamp_millis(millis)
        .map(|value| {
            value
                .format("%b %e %H:%M UTC")
                .to_string()
                .trim()
                .to_string()
        })
        .unwrap_or_else(|| "the configured deadline".to_string())
}

fn compact_sender_label(candidate: &GmailFollowUpCandidate) -> String {
    candidate
        .from
        .as_deref()
        .or(candidate.sender_email.as_deref())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("an inbox thread")
        .to_string()
}

fn follow_up_priority(
    candidate: &GmailFollowUpCandidate,
    profile: &AssistantAttentionProfile,
) -> f32 {
    let mut score = 0.72;
    if candidate.external_sender {
        score += 0.1;
    }
    if candidate.label_ids.iter().any(|label| {
        label.eq_ignore_ascii_case("IMPORTANT") || label.eq_ignore_ascii_case("STARRED")
    }) {
        score += 0.08;
    }
    if candidate.age_minutes >= 24 * 60 {
        score += 0.09;
    } else if candidate.age_minutes >= 6 * 60 {
        score += 0.05;
    }
    score += priority_boost_for_high_value_contact(
        profile,
        &[
            candidate.from.as_deref(),
            candidate.sender_email.as_deref(),
            candidate.subject.as_deref(),
        ],
    );
    score += feedback_priority_bias(profile, "follow_up_risk");
    clamp_score(score)
}

fn meeting_prep_priority(
    candidate: &CalendarMeetingPrepCandidate,
    profile: &AssistantAttentionProfile,
) -> f32 {
    let mut score = 0.74;
    if candidate.external_attendee_count > 0 {
        score += 0.08;
    }
    if candidate.attendee_emails.len() >= 3 {
        score += 0.05;
    }
    if candidate.minutes_until_start <= 15 {
        score += 0.08;
    } else if candidate.minutes_until_start <= 30 {
        score += 0.05;
    }
    score += priority_boost_for_high_value_contact(profile, &[Some(candidate.summary.as_str())]);
    score += feedback_priority_bias(profile, "meeting_prep");
    clamp_score(score)
}

fn auth_record_priority(state: &str, expires_at_ms: Option<u64>) -> f32 {
    let mut score = match state {
        "expired" | "revoked" => 0.96,
        "degraded" => 0.9,
        "needs_auth" => 0.84,
        _ => 0.74,
    };
    if let Some(expires_at_ms) = expires_at_ms {
        let now = now_ms();
        if expires_at_ms <= now {
            score += 0.08;
        } else if expires_at_ms.saturating_sub(now) <= 30 * 60 * 1000 {
            score += 0.05;
        }
    }
    clamp_score(score)
}

fn subscription_attention_priority(
    subscription: &GoogleConnectorSubscriptionView,
    now: u64,
) -> Option<(f32, NotificationSeverity, Option<u64>, &'static str)> {
    let renew_at_ms = subscription.renew_at_utc.as_deref().and_then(rfc3339_to_ms);
    let expires_at_ms = subscription
        .expires_at_utc
        .as_deref()
        .and_then(rfc3339_to_ms);
    let last_ack_ms = subscription
        .last_ack_at_utc
        .as_deref()
        .and_then(rfc3339_to_ms);
    let created_at_ms = rfc3339_to_ms(subscription.created_at_utc.as_str());

    match subscription.status.as_str() {
        "reauth_required" => Some((
            0.97,
            NotificationSeverity::High,
            expires_at_ms,
            "reauth_required",
        )),
        "degraded" => Some((
            0.9,
            NotificationSeverity::High,
            renew_at_ms.or(expires_at_ms),
            "subscription_degraded",
        )),
        "renewing" => {
            if renew_at_ms.is_some_and(|value| value <= now) {
                Some((
                    0.82,
                    NotificationSeverity::Medium,
                    renew_at_ms,
                    "renewal_due",
                ))
            } else {
                None
            }
        }
        "active" => {
            if renew_at_ms.is_some_and(|value| value <= now) {
                Some((
                    0.83,
                    NotificationSeverity::Medium,
                    renew_at_ms,
                    "renewal_due",
                ))
            } else if expires_at_ms.is_some_and(|value| value <= now + 30 * 60 * 1000) {
                Some((
                    0.8,
                    NotificationSeverity::Medium,
                    expires_at_ms,
                    "expires_soon",
                ))
            } else if created_at_ms.is_some_and(|created| created + 12 * 60 * 60 * 1000 <= now)
                && last_ack_ms.is_some_and(|last_ack| last_ack + 12 * 60 * 60 * 1000 <= now)
            {
                Some((0.78, NotificationSeverity::Medium, None, "stale_delivery"))
            } else {
                None
            }
        }
        _ => None,
    }
}

fn google_subscription_label(kind: &str) -> &str {
    match kind {
        "gmail_watch" => "Gmail watch",
        "workspace_events" => "Workspace events",
        _ => "Google subscription",
    }
}

fn record_assistant_feedback(
    memory_runtime: &std::sync::Arc<MemoryRuntime>,
    notification_class: &AssistantNotificationClass,
    status: &AssistantNotificationStatus,
) -> AssistantAttentionProfile {
    let mut profile = load_assistant_attention_profile(memory_runtime);
    let detector_key = detector_key_for_class(notification_class).to_string();
    let status_key = match status {
        AssistantNotificationStatus::New => "new",
        AssistantNotificationStatus::Seen => "seen",
        AssistantNotificationStatus::Acknowledged => "acknowledged",
        AssistantNotificationStatus::Snoozed => "snoozed",
        AssistantNotificationStatus::Resolved => "resolved",
        AssistantNotificationStatus::Dismissed => "dismissed",
        AssistantNotificationStatus::Expired => "expired",
        AssistantNotificationStatus::Archived => "archived",
    }
    .to_string();
    *profile
        .notification_feedback
        .entry(detector_key)
        .or_default()
        .entry(status_key)
        .or_insert(0) += 1;
    save_assistant_attention_profile(memory_runtime, &profile);
    profile
}

fn compute_badge_count(
    interventions: &[InterventionRecord],
    notifications: &[AssistantNotificationRecord],
    policy: &AssistantAttentionPolicy,
) -> usize {
    let now = now_ms();
    let intervention_count = interventions
        .iter()
        .filter(|item| unresolved_intervention(&item.status))
        .filter(|item| !is_snoozed_until_future(item.snoozed_until_ms, now))
        .count();
    let assistant_count = if policy.global.badge_enabled {
        notifications
            .iter()
            .filter(|item| unresolved_assistant_notification(&item.status))
            .filter(|item| !is_snoozed_until_future(item.snoozed_until_ms, now))
            .filter(|item| {
                matches!(
                    item.severity,
                    NotificationSeverity::High | NotificationSeverity::Critical
                )
            })
            .count()
    } else {
        0
    };
    intervention_count + assistant_count
}

fn emit_badge_count<R: Runtime>(app: &AppHandle<R>) {
    let Some(memory_runtime) = app_memory_runtime(app) else {
        return;
    };
    let interventions = load_interventions(&memory_runtime);
    let notifications = load_assistant_notifications(&memory_runtime);
    let policy = load_assistant_attention_policy(&memory_runtime);
    let count = compute_badge_count(&interventions, &notifications, &policy);
    let _ = app.emit("notifications-badge-updated", count);
}

fn should_emit_toast(
    severity: &NotificationSeverity,
    status_new: bool,
    policy: &AssistantAttentionPolicy,
) -> bool {
    if !status_new || !policy.global.toasts_enabled {
        return false;
    }
    matches!(
        severity,
        NotificationSeverity::High | NotificationSeverity::Critical
    )
}

fn maybe_emit_intervention_toast<R: Runtime>(
    app: &AppHandle<R>,
    record: &InterventionRecord,
    policy: &AssistantAttentionPolicy,
) {
    if should_emit_toast(
        &record.severity,
        matches!(record.status, InterventionStatus::New),
        policy,
    ) {
        let _ = app.emit("intervention-toast-candidate", record);
    }
}

fn maybe_emit_assistant_toast<R: Runtime>(
    app: &AppHandle<R>,
    record: &AssistantNotificationRecord,
    policy: &AssistantAttentionPolicy,
) {
    if !should_emit_toast(
        &record.severity,
        matches!(record.status, AssistantNotificationStatus::New),
        policy,
    ) {
        return;
    }

    let detector_key = detector_key_for_class(&record.notification_class);
    let detector = policy.detectors.get(detector_key);
    if detector.is_some_and(|item| !item.enabled) {
        return;
    }
    let min_score = detector
        .and_then(|item| item.toast_min_score)
        .unwrap_or(0.85);
    if record.priority_score >= min_score {
        let _ = app.emit("assistant-notification-toast-candidate", record);
    }
}

fn default_source(service_name: &str, workflow_name: &str, step_name: &str) -> NotificationSource {
    NotificationSource {
        service_name: service_name.to_string(),
        workflow_name: workflow_name.to_string(),
        step_name: step_name.to_string(),
    }
}

fn default_privacy(observation_tier: ObservationTier) -> NotificationPrivacy {
    NotificationPrivacy {
        preview_mode: NotificationPreviewMode::Redacted,
        contains_sensitive_data: true,
        observation_tier,
    }
}

fn derive_avatar_seed(value: &str) -> String {
    let initials = value
        .split_whitespace()
        .filter_map(|segment| segment.chars().find(|ch| ch.is_alphanumeric()))
        .take(2)
        .collect::<String>()
        .to_uppercase();
    if initials.is_empty() {
        "OP".to_string()
    } else {
        initials
    }
}

fn normalize_optional_field(value: Option<String>) -> Option<String> {
    value
        .map(|item| item.trim().to_string())
        .filter(|item| !item.is_empty())
}

fn sanitize_assistant_user_profile(mut profile: AssistantUserProfile) -> AssistantUserProfile {
    profile.version = 1;
    profile.display_name = profile.display_name.trim().to_string();
    if profile.display_name.is_empty() {
        profile.display_name = AssistantUserProfile::default().display_name;
    }
    profile.preferred_name = normalize_optional_field(profile.preferred_name);
    profile.role_label = normalize_optional_field(profile.role_label);
    profile.primary_email = normalize_optional_field(profile.primary_email);
    profile.timezone = profile.timezone.trim().to_string();
    if profile.timezone.is_empty() {
        profile.timezone = AssistantUserProfile::default().timezone;
    }
    profile.locale = profile.locale.trim().to_string();
    if profile.locale.is_empty() {
        profile.locale = AssistantUserProfile::default().locale;
    }
    profile.avatar_seed = derive_avatar_seed(
        profile
            .preferred_name
            .as_deref()
            .unwrap_or(profile.display_name.as_str()),
    );
    profile.grounding_allowed = false;
    profile
}

pub(crate) fn bootstrap_notification_defaults<R: Runtime>(app: &AppHandle<R>) {
    let Some(memory_runtime) = app_memory_runtime(app) else {
        return;
    };
    let policy = load_assistant_attention_policy(&memory_runtime);
    save_assistant_attention_policy(&memory_runtime, &policy);
    let profile = load_assistant_attention_profile(&memory_runtime);
    save_assistant_attention_profile(&memory_runtime, &profile);
    let user_profile =
        sanitize_assistant_user_profile(load_assistant_user_profile(&memory_runtime));
    save_assistant_user_profile(&memory_runtime, &user_profile);
    emit_badge_count(app);
}

pub(crate) async fn spawn_notification_scheduler(app: AppHandle) {
    maybe_emit_google_productivity_notifications(&app).await;
    let mut connector_scan_ticks = 0u32;
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        maybe_emit_deadline_risk_notifications(&app);
        connector_scan_ticks = connector_scan_ticks.saturating_add(1);
        if connector_scan_ticks >= 5 {
            connector_scan_ticks = 0;
            maybe_emit_google_productivity_notifications(&app).await;
        }
        emit_badge_count(&app);
    }
}

pub(crate) fn upsert_intervention_record<R: Runtime>(
    app: &AppHandle<R>,
    record: InterventionRecord,
) {
    let Some(memory_runtime) = app_memory_runtime(app) else {
        return;
    };
    let policy = load_assistant_attention_policy(&memory_runtime);
    upsert_intervention(&memory_runtime, record.clone());
    let _ = app.emit("intervention-updated", &record);
    maybe_emit_intervention_toast(app, &record, &policy);
    emit_badge_count(app);
}

pub(crate) fn upsert_assistant_notification_record<R: Runtime>(
    app: &AppHandle<R>,
    record: AssistantNotificationRecord,
) {
    let Some(memory_runtime) = app_memory_runtime(app) else {
        return;
    };
    let policy = load_assistant_attention_policy(&memory_runtime);
    upsert_assistant_notification(&memory_runtime, record.clone());
    let _ = app.emit("assistant-notification-updated", &record);
    maybe_emit_assistant_toast(app, &record, &policy);
    emit_badge_count(app);
}

pub(crate) fn record_approval_intervention(
    app: &AppHandle,
    thread_id: &str,
    session_id: &str,
    request_hash: &str,
    title: &str,
    summary: &str,
    severity: NotificationSeverity,
    due_at_ms: Option<u64>,
    approval_scope: Option<String>,
    sensitive_action_type: Option<String>,
    recovery_hint: Option<String>,
) {
    let request_hash = normalize_request_hash(request_hash);
    let now = now_ms();
    upsert_intervention_record(
        app,
        InterventionRecord {
            item_id: format!("intv-{}", Uuid::new_v4()),
            rail: NotificationRail::Control,
            intervention_type: InterventionType::ApprovalGate,
            status: InterventionStatus::New,
            severity,
            blocking: true,
            title: title.to_string(),
            summary: summary.to_string(),
            reason: Some("Execution policy requires approval.".to_string()),
            recommended_action: Some("Review and approve or deny the request.".to_string()),
            consequence_if_ignored: Some("The workflow remains paused.".to_string()),
            created_at_ms: now,
            updated_at_ms: now,
            due_at_ms,
            expires_at_ms: None,
            snoozed_until_ms: None,
            dedupe_key: format!("approval:{}", request_hash),
            thread_id: Some(thread_id.to_string()),
            session_id: Some(session_id.to_string()),
            workflow_id: None,
            run_id: None,
            delivery_state: NotificationDeliveryState {
                inbox_visible: true,
                badge_counted: true,
                ..Default::default()
            },
            privacy: default_privacy(ObservationTier::WorkflowState),
            source: default_source("Autopilot", "workflow", "approval_gate"),
            artifact_refs: Vec::new(),
            source_event_ids: Vec::new(),
            policy_refs: NotificationPolicyRefs {
                policy_hash: None,
                request_hash: Some(request_hash.clone()),
            },
            actions: vec![
                NotificationAction {
                    id: "approve".to_string(),
                    label: "Approve".to_string(),
                    style: Some(NotificationActionStyle::Primary),
                },
                NotificationAction {
                    id: "deny".to_string(),
                    label: "Deny".to_string(),
                    style: Some(NotificationActionStyle::Danger),
                },
                NotificationAction {
                    id: "open_details".to_string(),
                    label: "Open Details".to_string(),
                    style: Some(NotificationActionStyle::Secondary),
                },
            ],
            target: None,
            request_hash: Some(request_hash),
            policy_hash: None,
            approval_scope,
            sensitive_action_type,
            error_class: None,
            blocked_stage: None,
            retry_available: None,
            recovery_hint,
        },
    );
}

pub(crate) fn record_pii_review_intervention(
    app: &AppHandle,
    thread_id: &str,
    session_id: &str,
    request_hash: &str,
    deadline_ms: Option<u64>,
) {
    let request_hash = normalize_request_hash(request_hash);
    let now = now_ms();
    upsert_intervention_record(
        app,
        InterventionRecord {
            item_id: format!("intv-{}", Uuid::new_v4()),
            rail: NotificationRail::Control,
            intervention_type: InterventionType::PiiReviewGate,
            status: InterventionStatus::New,
            severity: NotificationSeverity::High,
            blocking: true,
            title: "PII Review Required".to_string(),
            summary: "Sensitive content must be reviewed before egress.".to_string(),
            reason: Some("Sensitive output hit the PII review gate.".to_string()),
            recommended_action: Some(
                "Review transform, deny, or grant a scoped exception.".to_string(),
            ),
            consequence_if_ignored: Some("The workflow remains paused.".to_string()),
            created_at_ms: now,
            updated_at_ms: now,
            due_at_ms: deadline_ms,
            expires_at_ms: None,
            snoozed_until_ms: None,
            dedupe_key: format!("pii_review:{}", request_hash),
            thread_id: Some(thread_id.to_string()),
            session_id: Some(session_id.to_string()),
            workflow_id: None,
            run_id: None,
            delivery_state: NotificationDeliveryState {
                inbox_visible: true,
                badge_counted: true,
                ..Default::default()
            },
            privacy: default_privacy(ObservationTier::WorkflowState),
            source: default_source("Autopilot", "workflow", "pii_review_gate"),
            artifact_refs: Vec::new(),
            source_event_ids: Vec::new(),
            policy_refs: NotificationPolicyRefs {
                policy_hash: None,
                request_hash: Some(request_hash.clone()),
            },
            actions: vec![
                NotificationAction {
                    id: "approve_transform".to_string(),
                    label: "Approve Transform".to_string(),
                    style: Some(NotificationActionStyle::Primary),
                },
                NotificationAction {
                    id: "deny".to_string(),
                    label: "Deny".to_string(),
                    style: Some(NotificationActionStyle::Danger),
                },
                NotificationAction {
                    id: "grant_scoped_exception".to_string(),
                    label: "Grant Scoped Exception".to_string(),
                    style: Some(NotificationActionStyle::Secondary),
                },
            ],
            target: None,
            request_hash: Some(request_hash),
            policy_hash: None,
            approval_scope: None,
            sensitive_action_type: Some("pii_egress".to_string()),
            error_class: None,
            blocked_stage: None,
            retry_available: None,
            recovery_hint: None,
        },
    );
}

pub(crate) fn record_clarification_intervention(
    app: &AppHandle,
    thread_id: &str,
    session_id: &str,
    kind: &str,
    question: &str,
) {
    let now = now_ms();
    let dedupe = format!("clarification:{}:{}", session_id, kind);
    upsert_intervention_record(
        app,
        InterventionRecord {
            item_id: format!("intv-{}", Uuid::new_v4()),
            rail: NotificationRail::Control,
            intervention_type: InterventionType::ClarificationGate,
            status: InterventionStatus::New,
            severity: NotificationSeverity::Medium,
            blocking: true,
            title: "Clarification Needed".to_string(),
            summary: question.to_string(),
            reason: Some(
                "The workflow needs an exact user choice before it can continue.".to_string(),
            ),
            recommended_action: Some("Choose one option or provide the exact target.".to_string()),
            consequence_if_ignored: Some(
                "The workflow remains blocked awaiting clarification.".to_string(),
            ),
            created_at_ms: now,
            updated_at_ms: now,
            due_at_ms: None,
            expires_at_ms: None,
            snoozed_until_ms: None,
            dedupe_key: dedupe,
            thread_id: Some(thread_id.to_string()),
            session_id: Some(session_id.to_string()),
            workflow_id: None,
            run_id: None,
            delivery_state: NotificationDeliveryState {
                inbox_visible: true,
                badge_counted: true,
                ..Default::default()
            },
            privacy: default_privacy(ObservationTier::WorkflowState),
            source: default_source("Autopilot", "workflow", "clarification_gate"),
            artifact_refs: Vec::new(),
            source_event_ids: Vec::new(),
            policy_refs: NotificationPolicyRefs::default(),
            actions: vec![
                NotificationAction {
                    id: "open_details".to_string(),
                    label: "Open Details".to_string(),
                    style: Some(NotificationActionStyle::Primary),
                },
                NotificationAction {
                    id: "dismiss".to_string(),
                    label: "Dismiss".to_string(),
                    style: Some(NotificationActionStyle::Secondary),
                },
            ],
            target: None,
            request_hash: None,
            policy_hash: None,
            approval_scope: None,
            sensitive_action_type: None,
            error_class: Some(kind.to_string()),
            blocked_stage: Some("clarification".to_string()),
            retry_available: Some(false),
            recovery_hint: None,
        },
    );
}

pub(crate) fn record_credential_intervention(
    app: &AppHandle,
    thread_id: &str,
    session_id: &str,
    kind: &str,
    prompt: &str,
) {
    let now = now_ms();
    let dedupe = format!("credential:{}:{}", session_id, kind);
    upsert_intervention_record(
        app,
        InterventionRecord {
            item_id: format!("intv-{}", Uuid::new_v4()),
            rail: NotificationRail::Control,
            intervention_type: InterventionType::CredentialGate,
            status: InterventionStatus::New,
            severity: NotificationSeverity::High,
            blocking: true,
            title: "Credential Required".to_string(),
            summary: prompt.to_string(),
            reason: Some("Execution requires a user-provided credential.".to_string()),
            recommended_action: Some("Provide the credential to continue.".to_string()),
            consequence_if_ignored: Some("The workflow remains paused.".to_string()),
            created_at_ms: now,
            updated_at_ms: now,
            due_at_ms: None,
            expires_at_ms: None,
            snoozed_until_ms: None,
            dedupe_key: dedupe,
            thread_id: Some(thread_id.to_string()),
            session_id: Some(session_id.to_string()),
            workflow_id: None,
            run_id: None,
            delivery_state: NotificationDeliveryState {
                inbox_visible: true,
                badge_counted: true,
                ..Default::default()
            },
            privacy: default_privacy(ObservationTier::WorkflowState),
            source: default_source("Autopilot", "workflow", "credential_gate"),
            artifact_refs: Vec::new(),
            source_event_ids: Vec::new(),
            policy_refs: NotificationPolicyRefs::default(),
            actions: vec![NotificationAction {
                id: "open_details".to_string(),
                label: "Open Details".to_string(),
                style: Some(NotificationActionStyle::Primary),
            }],
            target: None,
            request_hash: None,
            policy_hash: None,
            approval_scope: None,
            sensitive_action_type: Some(kind.to_string()),
            error_class: Some(kind.to_string()),
            blocked_stage: Some("credential".to_string()),
            retry_available: Some(false),
            recovery_hint: None,
        },
    );
}

pub(crate) fn record_valuable_completion(
    app: &AppHandle,
    thread_id: &str,
    session_id: &str,
    title: &str,
    summary: &str,
    artifact_refs: Vec<crate::models::ArtifactRef>,
) {
    let now = now_ms();
    let record = AssistantNotificationRecord {
        item_id: format!("notif-{}", Uuid::new_v4()),
        rail: NotificationRail::Assistant,
        notification_class: AssistantNotificationClass::ValuableCompletion,
        status: AssistantNotificationStatus::New,
        severity: NotificationSeverity::Medium,
        title: title.to_string(),
        summary: summary.to_string(),
        reason: Some("A user-visible result is ready.".to_string()),
        recommended_action: Some("Open the result or archive it.".to_string()),
        consequence_if_ignored: Some("The result remains available in the inbox.".to_string()),
        created_at_ms: now,
        updated_at_ms: now,
        due_at_ms: None,
        expires_at_ms: None,
        snoozed_until_ms: None,
        dedupe_key: format!("valuable_completion:{}:{}", session_id, title),
        thread_id: Some(thread_id.to_string()),
        session_id: Some(session_id.to_string()),
        workflow_id: None,
        run_id: None,
        delivery_state: NotificationDeliveryState {
            inbox_visible: true,
            badge_counted: false,
            ..Default::default()
        },
        privacy: default_privacy(ObservationTier::WorkflowState),
        source: default_source("Autopilot", "workflow", "valuable_completion"),
        artifact_refs,
        source_event_ids: Vec::new(),
        policy_refs: NotificationPolicyRefs::default(),
        actions: vec![
            NotificationAction {
                id: "open_autopilot".to_string(),
                label: "Open Result".to_string(),
                style: Some(NotificationActionStyle::Primary),
            },
            NotificationAction {
                id: "archive".to_string(),
                label: "Archive".to_string(),
                style: Some(NotificationActionStyle::Secondary),
            },
        ],
        target: None,
        priority_score: 0.82,
        confidence_score: 0.95,
        ranking_reason: vec![
            "user_visible_result".to_string(),
            "workflow_completed".to_string(),
        ],
    };
    upsert_assistant_notification_record(app, record);
}

async fn maybe_emit_google_productivity_notifications(app: &AppHandle) {
    let Some(memory_runtime) = app_memory_runtime(app) else {
        return;
    };
    let policy = load_assistant_attention_policy(&memory_runtime);
    let profile = load_assistant_attention_profile(&memory_runtime);
    let scan_now = now_ms();
    let existing_notifications = load_assistant_notifications(&memory_runtime);
    let mut seen_dedupes = existing_notifications
        .iter()
        .map(|item| item.dedupe_key.clone())
        .collect::<HashSet<_>>();

    if policy
        .detectors
        .get("follow_up_risk")
        .is_some_and(|config| config.enabled)
        && metadata_scan_enabled(&policy, "gmail")
    {
        let min_age_minutes = policy
            .detectors
            .get("follow_up_risk")
            .and_then(|config| config.min_age_minutes)
            .unwrap_or(180) as u64;
        if let Ok(candidates) = google_api::gmail_follow_up_candidates(4, min_age_minutes).await {
            let mut seen_threads = HashSet::new();
            for candidate in candidates {
                let thread_or_message = candidate
                    .thread_id
                    .clone()
                    .unwrap_or_else(|| candidate.message_id.clone());
                if !seen_threads.insert(thread_or_message.clone()) {
                    continue;
                }

                let dedupe = format!("follow_up_risk:{}", thread_or_message);
                if seen_dedupes.contains(&dedupe) {
                    continue;
                }
                let priority = follow_up_priority(&candidate, &profile);
                let min_score = policy
                    .detectors
                    .get("follow_up_risk")
                    .and_then(|config| config.min_score)
                    .unwrap_or(0.72) as f32;
                if priority < min_score {
                    continue;
                }

                let sender = compact_sender_label(&candidate);
                let age = format_age_minutes(candidate.age_minutes);
                let summary = candidate
                    .subject
                    .as_deref()
                    .map(|subject| {
                        format!(
                            "{} has been unread for {} about \"{}\".",
                            sender, age, subject
                        )
                    })
                    .unwrap_or_else(|| format!("{} has been unread for {}.", sender, age));
                let severity = if candidate.age_minutes >= 24 * 60
                    || (candidate.external_sender && candidate.age_minutes >= 6 * 60)
                {
                    NotificationSeverity::High
                } else {
                    NotificationSeverity::Medium
                };
                let badge_counted = matches!(severity, NotificationSeverity::High);
                let record = AssistantNotificationRecord {
                    item_id: format!("notif-{}", Uuid::new_v4()),
                    rail: NotificationRail::Assistant,
                    notification_class: AssistantNotificationClass::FollowUpRisk,
                    status: AssistantNotificationStatus::New,
                    severity,
                    title: format!("Reply may be overdue: {}", sender),
                    summary,
                    reason: Some(if candidate.external_sender {
                        "An unread external thread has been waiting for attention.".to_string()
                    } else {
                        "An unread inbox thread has been waiting for attention.".to_string()
                    }),
                    recommended_action: Some(
                        "Open the thread, confirm urgency, and draft a reply if needed."
                            .to_string(),
                    ),
                    consequence_if_ignored: Some(
                        "The thread may continue aging without a response.".to_string(),
                    ),
                    created_at_ms: now_ms(),
                    updated_at_ms: now_ms(),
                    due_at_ms: None,
                    expires_at_ms: None,
                    snoozed_until_ms: None,
                    dedupe_key: dedupe.clone(),
                    thread_id: candidate.thread_id.clone(),
                    session_id: None,
                    workflow_id: None,
                    run_id: None,
                    delivery_state: NotificationDeliveryState {
                        inbox_visible: true,
                        badge_counted,
                        ..Default::default()
                    },
                    privacy: default_privacy(ObservationTier::ConnectorMetadata),
                    source: default_source("Google Gmail", "assistant", "follow_up_risk"),
                    artifact_refs: Vec::new(),
                    source_event_ids: Vec::new(),
                    policy_refs: NotificationPolicyRefs::default(),
                    actions: vec![
                        NotificationAction {
                            id: "open_target".to_string(),
                            label: "Open Thread".to_string(),
                            style: Some(NotificationActionStyle::Primary),
                        },
                        NotificationAction {
                            id: "open_integrations:google.workspace".to_string(),
                            label: "Open Capabilities".to_string(),
                            style: Some(NotificationActionStyle::Secondary),
                        },
                    ],
                    target: Some(NotificationTarget::GmailThread {
                        connector_id: "google.workspace".to_string(),
                        thread_id: thread_or_message.clone(),
                        message_id: Some(candidate.message_id.clone()),
                    }),
                    priority_score: priority,
                    confidence_score: 0.92,
                    ranking_reason: vec![
                        "connector_metadata".to_string(),
                        if candidate.external_sender {
                            "external_sender".to_string()
                        } else {
                            "unread_thread".to_string()
                        },
                        "unreplied_risk".to_string(),
                    ],
                };
                upsert_assistant_notification_record(app, record);
                seen_dedupes.insert(dedupe);
            }
        }
    }

    if policy
        .detectors
        .get("meeting_prep")
        .is_some_and(|config| config.enabled)
        && metadata_scan_enabled(&policy, "calendar")
    {
        let lead_time_minutes = policy
            .detectors
            .get("meeting_prep")
            .and_then(|config| config.lead_time_minutes)
            .unwrap_or(45) as u64;
        if let Ok(candidates) =
            google_api::calendar_meeting_prep_candidates("primary", lead_time_minutes, 3).await
        {
            for candidate in candidates {
                let dedupe = format!(
                    "meeting_prep:{}:{}",
                    candidate.calendar_id, candidate.event_id
                );
                if seen_dedupes.contains(&dedupe) {
                    continue;
                }
                let priority = meeting_prep_priority(&candidate, &profile);
                let min_score = policy
                    .detectors
                    .get("meeting_prep")
                    .and_then(|config| config.min_score)
                    .unwrap_or(0.74) as f32;
                if priority < min_score {
                    continue;
                }

                let attendee_count = candidate.attendee_emails.len();
                let attendee_label = if attendee_count == 1 {
                    "1 attendee".to_string()
                } else {
                    format!("{} attendees", attendee_count)
                };
                let external_copy = if candidate.external_attendee_count > 0 {
                    format!(", {} external", candidate.external_attendee_count)
                } else {
                    String::new()
                };
                let severity = if candidate.minutes_until_start <= 15 {
                    NotificationSeverity::High
                } else {
                    NotificationSeverity::Medium
                };
                let badge_counted = matches!(severity, NotificationSeverity::High);
                let record = AssistantNotificationRecord {
                    item_id: format!("notif-{}", Uuid::new_v4()),
                    rail: NotificationRail::Assistant,
                    notification_class: AssistantNotificationClass::MeetingPrep,
                    status: AssistantNotificationStatus::New,
                    severity,
                    title: format!("Meeting soon: {}", candidate.summary),
                    summary: format!(
                        "Starts in {} minutes with {}{}.",
                        candidate.minutes_until_start.max(0),
                        attendee_label,
                        external_copy
                    ),
                    reason: Some(
                        "An upcoming calendar event is approaching its start time.".to_string(),
                    ),
                    recommended_action: Some(
                        "Open the event, review the thread, or prepare a short brief.".to_string(),
                    ),
                    consequence_if_ignored: Some(
                        "You may enter the meeting without context or prep.".to_string(),
                    ),
                    created_at_ms: now_ms(),
                    updated_at_ms: now_ms(),
                    due_at_ms: candidate.start_at_utc.as_deref().and_then(rfc3339_to_ms),
                    expires_at_ms: None,
                    snoozed_until_ms: None,
                    dedupe_key: dedupe.clone(),
                    thread_id: None,
                    session_id: None,
                    workflow_id: None,
                    run_id: None,
                    delivery_state: NotificationDeliveryState {
                        inbox_visible: true,
                        badge_counted,
                        ..Default::default()
                    },
                    privacy: default_privacy(ObservationTier::ConnectorMetadata),
                    source: default_source("Google Calendar", "assistant", "meeting_prep"),
                    artifact_refs: Vec::new(),
                    source_event_ids: Vec::new(),
                    policy_refs: NotificationPolicyRefs::default(),
                    actions: vec![
                        NotificationAction {
                            id: "open_target".to_string(),
                            label: "Open Event".to_string(),
                            style: Some(NotificationActionStyle::Primary),
                        },
                        NotificationAction {
                            id: "open_integrations:google.workspace".to_string(),
                            label: "Open Capabilities".to_string(),
                            style: Some(NotificationActionStyle::Secondary),
                        },
                    ],
                    target: Some(NotificationTarget::CalendarEvent {
                        connector_id: "google.workspace".to_string(),
                        calendar_id: candidate.calendar_id.clone(),
                        event_id: candidate.event_id.clone(),
                    }),
                    priority_score: priority,
                    confidence_score: 0.95,
                    ranking_reason: vec![
                        "connector_metadata".to_string(),
                        "meeting_starting_soon".to_string(),
                        if candidate.external_attendee_count > 0 {
                            "external_attendees".to_string()
                        } else {
                            "calendar_event".to_string()
                        },
                    ],
                };
                upsert_assistant_notification_record(app, record);
                seen_dedupes.insert(dedupe);
            }
        }
    }

    if policy
        .detectors
        .get("auth_attention")
        .is_some_and(|config| config.enabled)
    {
        let state = app.state::<Mutex<AppState>>();
        if let Ok(auth_list) =
            connectors::wallet_connector_auth_list(state, Some("google.workspace".to_string()))
                .await
        {
            for record in auth_list.records {
                let expires_at_ms = record.expires_at_ms;
                let needs_attention = matches!(
                    record.state.as_str(),
                    "needs_auth" | "expired" | "revoked" | "degraded"
                ) || expires_at_ms
                    .is_some_and(|value| value <= scan_now + 30 * 60 * 1000);
                if !needs_attention {
                    continue;
                }

                let dedupe = format!(
                    "auth_attention:connector:{}:{}:{}",
                    record.connector_id, record.state, record.updated_at_ms
                );
                if seen_dedupes.contains(&dedupe) {
                    continue;
                }

                let priority = auth_record_priority(record.state.as_str(), expires_at_ms);
                let min_score = policy
                    .detectors
                    .get("auth_attention")
                    .and_then(|config| config.min_score)
                    .unwrap_or(0.65) as f32;
                if priority < min_score {
                    continue;
                }

                let account_label = record
                    .account_label
                    .clone()
                    .unwrap_or_else(|| "Google Workspace".to_string());
                let severity =
                    if matches!(record.state.as_str(), "expired" | "revoked" | "degraded") {
                        NotificationSeverity::High
                    } else {
                        NotificationSeverity::Medium
                    };
                let title = if expires_at_ms.is_some_and(|value| value <= scan_now + 30 * 60 * 1000)
                    && record.state == "connected"
                {
                    format!("Google auth expiring soon: {}", account_label)
                } else {
                    format!("Google auth needs attention: {}", account_label)
                };
                let reason = match record.state.as_str() {
                    "needs_auth" => "The connector is registered but still needs authorization.",
                    "expired" => "The wallet-backed Google auth state is expired.",
                    "revoked" => "The wallet-backed Google auth state was revoked.",
                    "degraded" => "The wallet-backed Google auth state is degraded.",
                    _ => "The connector auth lease or token metadata is nearing expiry.",
                };
                let summary = if let Some(expires_at_ms) = expires_at_ms {
                    format!(
                        "{} requires review before {}.",
                        account_label,
                        format_timestamp_ms(expires_at_ms)
                    )
                } else {
                    format!("{} may need reconnection or policy review.", account_label)
                };

                let record = AssistantNotificationRecord {
                    item_id: format!("notif-{}", Uuid::new_v4()),
                    rail: NotificationRail::Assistant,
                    notification_class: AssistantNotificationClass::AuthAttention,
                    status: AssistantNotificationStatus::New,
                    severity: severity.clone(),
                    title,
                    summary,
                    reason: Some(reason.to_string()),
                    recommended_action: Some(
                        "Open Capabilities to reconnect the account or inspect the connection."
                            .to_string(),
                    ),
                    consequence_if_ignored: Some(
                        "Google-driven workflows and discovery may stop or degrade.".to_string(),
                    ),
                    created_at_ms: scan_now,
                    updated_at_ms: scan_now,
                    due_at_ms: expires_at_ms,
                    expires_at_ms,
                    snoozed_until_ms: None,
                    dedupe_key: dedupe.clone(),
                    thread_id: None,
                    session_id: None,
                    workflow_id: None,
                    run_id: None,
                    delivery_state: NotificationDeliveryState {
                        inbox_visible: true,
                        badge_counted: matches!(
                            severity,
                            NotificationSeverity::High | NotificationSeverity::Critical
                        ),
                        ..Default::default()
                    },
                    privacy: default_privacy(ObservationTier::ConnectorMetadata),
                    source: default_source("Google Connector", "assistant", "auth_attention"),
                    artifact_refs: Vec::new(),
                    source_event_ids: Vec::new(),
                    policy_refs: NotificationPolicyRefs::default(),
                    actions: vec![
                        NotificationAction {
                            id: "open_target".to_string(),
                            label: "Open Auth".to_string(),
                            style: Some(NotificationActionStyle::Primary),
                        },
                        NotificationAction {
                            id: format!("open_shield:{}", record.connector_id),
                            label: "Open Policy".to_string(),
                            style: Some(NotificationActionStyle::Secondary),
                        },
                    ],
                    target: Some(NotificationTarget::ConnectorAuth {
                        connector_id: record.connector_id.clone(),
                    }),
                    priority_score: priority,
                    confidence_score: 0.97,
                    ranking_reason: vec![
                        "connector_metadata".to_string(),
                        "wallet_auth_state".to_string(),
                        record.state.clone(),
                    ],
                };
                upsert_assistant_notification_record(app, record);
                seen_dedupes.insert(dedupe);
            }
        }

        let manager = app.state::<GoogleAutomationManager>();
        if let Ok(subscriptions) = manager.list_subscriptions("google.workspace").await {
            for subscription in subscriptions {
                let Some((priority, severity, due_at_ms, reason_code)) =
                    subscription_attention_priority(&subscription, scan_now)
                else {
                    continue;
                };

                let dedupe = format!(
                    "auth_attention:subscription:{}:{}:{}",
                    subscription.subscription_id, reason_code, subscription.updated_at_utc
                );
                if seen_dedupes.contains(&dedupe) {
                    continue;
                }

                let min_score = policy
                    .detectors
                    .get("auth_attention")
                    .and_then(|config| config.min_score)
                    .unwrap_or(0.65) as f32;
                if priority < min_score {
                    continue;
                }

                let label = google_subscription_label(subscription.kind.as_str());
                let title = match reason_code {
                    "reauth_required" => format!("Reconnect {} subscription", label),
                    "subscription_degraded" => format!("Subscription degraded: {}", label),
                    "renewal_due" => format!("Renew {} subscription", label),
                    "expires_soon" => format!("{} expires soon", label),
                    "stale_delivery" => format!("{} looks stale", label),
                    _ => format!("Check {} subscription", label),
                };
                let summary = if let Some(last_error) = subscription.last_error.as_deref() {
                    format!("{} is reporting {}.", label, last_error)
                } else if let Some(account_email) = subscription.account_email.as_deref() {
                    format!("{} for {} needs maintenance.", label, account_email)
                } else {
                    format!("{} needs maintenance or renewal.", label)
                };
                let recommended_action = if matches!(
                    reason_code,
                    "renewal_due" | "expires_soon" | "stale_delivery"
                ) {
                    "Renew the subscription now or inspect it in Capabilities."
                } else {
                    "Open Capabilities to reconnect or inspect the subscription."
                };
                let record = AssistantNotificationRecord {
                    item_id: format!("notif-{}", Uuid::new_v4()),
                    rail: NotificationRail::Assistant,
                    notification_class: AssistantNotificationClass::AuthAttention,
                    status: AssistantNotificationStatus::New,
                    severity: severity.clone(),
                    title,
                    summary,
                    reason: Some(
                        "The Google subscription runtime reported auth drift or maintenance risk."
                            .to_string(),
                    ),
                    recommended_action: Some(recommended_action.to_string()),
                    consequence_if_ignored: Some(
                        "Background Gmail or Calendar automations may miss events.".to_string(),
                    ),
                    created_at_ms: scan_now,
                    updated_at_ms: scan_now,
                    due_at_ms,
                    expires_at_ms: due_at_ms,
                    snoozed_until_ms: None,
                    dedupe_key: dedupe.clone(),
                    thread_id: Some(subscription.thread_id.clone()),
                    session_id: None,
                    workflow_id: None,
                    run_id: None,
                    delivery_state: NotificationDeliveryState {
                        inbox_visible: true,
                        badge_counted: matches!(
                            severity,
                            NotificationSeverity::High | NotificationSeverity::Critical
                        ),
                        ..Default::default()
                    },
                    privacy: default_privacy(ObservationTier::ConnectorMetadata),
                    source: default_source("Google Connector", "assistant", "auth_attention"),
                    artifact_refs: Vec::new(),
                    source_event_ids: Vec::new(),
                    policy_refs: NotificationPolicyRefs::default(),
                    actions: vec![
                        NotificationAction {
                            id: "open_target".to_string(),
                            label: "Open Subscription".to_string(),
                            style: Some(NotificationActionStyle::Primary),
                        },
                        NotificationAction {
                            id: format!("open_integrations:{}", subscription.connector_id),
                            label: "Open Capabilities".to_string(),
                            style: Some(NotificationActionStyle::Secondary),
                        },
                    ],
                    target: Some(NotificationTarget::ConnectorSubscription {
                        connector_id: subscription.connector_id.clone(),
                        subscription_id: subscription.subscription_id.clone(),
                    }),
                    priority_score: priority,
                    confidence_score: 0.95,
                    ranking_reason: vec![
                        "connector_metadata".to_string(),
                        "subscription_runtime".to_string(),
                        reason_code.to_string(),
                    ],
                };
                upsert_assistant_notification_record(app, record);
                seen_dedupes.insert(dedupe);
            }
        }
    }
}

pub(crate) fn maybe_emit_deadline_risk_notifications(app: &AppHandle) {
    let Some(memory_runtime) = app_memory_runtime(app) else {
        return;
    };
    let now = now_ms();
    let policy = load_assistant_attention_policy(&memory_runtime);
    if policy
        .detectors
        .get("deadline_risk")
        .is_some_and(|config| !config.enabled)
    {
        return;
    }
    let interventions = load_interventions(&memory_runtime);
    let notifications = load_assistant_notifications(&memory_runtime);
    for item in interventions
        .iter()
        .filter(|item| unresolved_intervention(&item.status))
        .filter(|item| !is_snoozed_until_future(item.snoozed_until_ms, now))
        .filter_map(|item| item.due_at_ms.map(|due_at_ms| (item, due_at_ms)))
    {
        let (item, due_at_ms) = item;
        if due_at_ms <= now || due_at_ms.saturating_sub(now) > 30 * 60 * 1000 {
            continue;
        }

        let dedupe = format!("deadline_risk:{}", item.dedupe_key);
        if notifications
            .iter()
            .any(|existing| existing.dedupe_key == dedupe)
        {
            continue;
        }

        upsert_assistant_notification_record(
            app,
            AssistantNotificationRecord {
                item_id: format!("notif-{}", Uuid::new_v4()),
                rail: NotificationRail::Assistant,
                notification_class: AssistantNotificationClass::DeadlineRisk,
                status: AssistantNotificationStatus::New,
                severity: NotificationSeverity::High,
                title: format!("Deadline risk: {}", item.title),
                summary: item.summary.clone().if_empty_then(|| {
                    "An unresolved intervention is nearing its deadline.".to_string()
                }),
                reason: Some("A required intervention is approaching its deadline.".to_string()),
                recommended_action: Some("Act now or snooze with care.".to_string()),
                consequence_if_ignored: Some(
                    "The workflow may miss its deadline or stay blocked.".to_string(),
                ),
                created_at_ms: now,
                updated_at_ms: now,
                due_at_ms: Some(due_at_ms),
                expires_at_ms: item.expires_at_ms,
                snoozed_until_ms: None,
                dedupe_key: dedupe,
                thread_id: item.thread_id.clone(),
                session_id: item.session_id.clone(),
                workflow_id: item.workflow_id.clone(),
                run_id: item.run_id.clone(),
                delivery_state: NotificationDeliveryState {
                    inbox_visible: true,
                    badge_counted: true,
                    ..Default::default()
                },
                privacy: default_privacy(ObservationTier::WorkflowState),
                source: default_source("Autopilot", "workflow", "deadline_risk"),
                artifact_refs: item.artifact_refs.clone(),
                source_event_ids: item.source_event_ids.clone(),
                policy_refs: item.policy_refs.clone(),
                actions: vec![
                    NotificationAction {
                        id: "open_autopilot".to_string(),
                        label: "Open Autopilot".to_string(),
                        style: Some(NotificationActionStyle::Primary),
                    },
                    NotificationAction {
                        id: "snooze".to_string(),
                        label: "Snooze".to_string(),
                        style: Some(NotificationActionStyle::Secondary),
                    },
                ],
                target: None,
                priority_score: 0.91,
                confidence_score: 0.99,
                ranking_reason: vec![
                    "intervention_near_deadline".to_string(),
                    "workflow_blocked".to_string(),
                ],
            },
        );
    }

    if policy
        .detectors
        .get("stalled_workflow")
        .is_some_and(|config| !config.enabled)
    {
        return;
    }

    for item in interventions
        .iter()
        .filter(|item| unresolved_intervention(&item.status))
        .filter(|item| !is_snoozed_until_future(item.snoozed_until_ms, now))
        .filter(|item| now.saturating_sub(item.updated_at_ms) >= 10 * 60 * 1000)
    {
        let dedupe = format!("stalled_workflow:{}", item.dedupe_key);
        if notifications
            .iter()
            .any(|existing| existing.dedupe_key == dedupe)
        {
            continue;
        }

        upsert_assistant_notification_record(
            app,
            AssistantNotificationRecord {
                item_id: format!("notif-{}", Uuid::new_v4()),
                rail: NotificationRail::Assistant,
                notification_class: AssistantNotificationClass::StalledWorkflow,
                status: AssistantNotificationStatus::New,
                severity: if item.blocking {
                    NotificationSeverity::High
                } else {
                    NotificationSeverity::Medium
                },
                title: format!("Workflow stalled: {}", item.title),
                summary: item.summary.clone().if_empty_then(|| {
                    "A workflow has been waiting on the same intervention.".to_string()
                }),
                reason: Some(
                    "A blocking state has remained unresolved for more than 10 minutes."
                        .to_string(),
                ),
                recommended_action: Some("Open the workflow and resolve the blocker.".to_string()),
                consequence_if_ignored: Some(
                    "The workflow will continue to idle without making progress.".to_string(),
                ),
                created_at_ms: now,
                updated_at_ms: now,
                due_at_ms: item.due_at_ms,
                expires_at_ms: item.expires_at_ms,
                snoozed_until_ms: None,
                dedupe_key: dedupe,
                thread_id: item.thread_id.clone(),
                session_id: item.session_id.clone(),
                workflow_id: item.workflow_id.clone(),
                run_id: item.run_id.clone(),
                delivery_state: NotificationDeliveryState {
                    inbox_visible: true,
                    badge_counted: item.blocking,
                    ..Default::default()
                },
                privacy: default_privacy(ObservationTier::WorkflowState),
                source: default_source("Autopilot", "workflow", "stalled_workflow"),
                artifact_refs: item.artifact_refs.clone(),
                source_event_ids: item.source_event_ids.clone(),
                policy_refs: item.policy_refs.clone(),
                actions: vec![
                    NotificationAction {
                        id: "open_autopilot".to_string(),
                        label: "Open Autopilot".to_string(),
                        style: Some(NotificationActionStyle::Primary),
                    },
                    NotificationAction {
                        id: "snooze".to_string(),
                        label: "Snooze".to_string(),
                        style: Some(NotificationActionStyle::Secondary),
                    },
                ],
                target: None,
                priority_score: if item.blocking { 0.89 } else { 0.78 },
                confidence_score: 0.98,
                ranking_reason: vec![
                    "stalled_intervention".to_string(),
                    "workflow_blocked".to_string(),
                ],
            },
        );
    }
}

trait IfEmptyThen {
    fn if_empty_then(self, fallback: impl FnOnce() -> String) -> String;
}

impl IfEmptyThen for String {
    fn if_empty_then(self, fallback: impl FnOnce() -> String) -> String {
        if self.trim().is_empty() {
            fallback()
        } else {
            self
        }
    }
}
