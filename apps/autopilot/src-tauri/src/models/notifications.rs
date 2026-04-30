use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use ts_rs::TS;

use super::events::ArtifactRef;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, TS)]
#[ts(export)]
#[serde(rename_all = "snake_case")]
pub enum NotificationRail {
    Control,
    Assistant,
}

impl Default for NotificationRail {
    fn default() -> Self {
        Self::Assistant
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, TS)]
#[ts(export)]
#[serde(rename_all = "snake_case")]
pub enum NotificationSeverity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

impl Default for NotificationSeverity {
    fn default() -> Self {
        Self::Medium
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, TS)]
#[ts(export)]
#[serde(rename_all = "snake_case")]
pub enum InterventionStatus {
    New,
    Seen,
    Pending,
    Responded,
    Resolved,
    Expired,
    Cancelled,
}

impl Default for InterventionStatus {
    fn default() -> Self {
        Self::New
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, TS)]
#[ts(export)]
#[serde(rename_all = "snake_case")]
pub enum AssistantNotificationStatus {
    New,
    Seen,
    Acknowledged,
    Snoozed,
    Resolved,
    Dismissed,
    Expired,
    Archived,
}

impl Default for AssistantNotificationStatus {
    fn default() -> Self {
        Self::New
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, TS)]
#[ts(export)]
#[serde(rename_all = "snake_case")]
pub enum InterventionType {
    ApprovalGate,
    PiiReviewGate,
    ClarificationGate,
    CredentialGate,
    ReauthGate,
    DecisionGate,
    InterventionOutcome,
}

impl Default for InterventionType {
    fn default() -> Self {
        Self::ApprovalGate
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, TS)]
#[ts(export)]
#[serde(rename_all = "snake_case")]
pub enum AssistantNotificationClass {
    FollowUpRisk,
    DeadlineRisk,
    MeetingPrep,
    StalledWorkflow,
    ValuableCompletion,
    Digest,
    AutomationOpportunity,
    HabitualFriction,
    AuthAttention,
}

impl Default for AssistantNotificationClass {
    fn default() -> Self {
        Self::Digest
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, TS)]
#[ts(export)]
#[serde(rename_all = "snake_case")]
pub enum NotificationActionStyle {
    Primary,
    Secondary,
    Danger,
    Quiet,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, TS)]
#[ts(export)]
#[serde(rename_all = "snake_case")]
pub enum NotificationPreviewMode {
    Redacted,
    Compact,
    Full,
}

impl Default for NotificationPreviewMode {
    fn default() -> Self {
        Self::Redacted
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, TS)]
#[ts(export)]
#[serde(rename_all = "snake_case")]
pub enum ObservationTier {
    WorkflowState,
    ConnectorMetadata,
    RedactedConnectorContent,
    CoarseHostContext,
    DeepAmbientBehavior,
}

impl Default for ObservationTier {
    fn default() -> Self {
        Self::WorkflowState
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct NotificationAction {
    pub id: String,
    pub label: String,
    #[serde(default)]
    pub style: Option<NotificationActionStyle>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct NotificationDeliveryState {
    #[serde(default)]
    pub toast_sent: bool,
    #[serde(default)]
    pub inbox_visible: bool,
    #[serde(default)]
    pub badge_counted: bool,
    #[serde(default)]
    pub pill_visible: bool,
    #[serde(default)]
    pub last_toast_at_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct NotificationPrivacy {
    #[serde(default)]
    pub preview_mode: NotificationPreviewMode,
    #[serde(default)]
    pub contains_sensitive_data: bool,
    #[serde(default)]
    pub observation_tier: ObservationTier,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct NotificationSource {
    #[serde(default)]
    pub service_name: String,
    #[serde(default)]
    pub workflow_name: String,
    #[serde(default)]
    pub step_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct NotificationPolicyRefs {
    #[serde(default)]
    pub policy_hash: Option<String>,
    #[serde(default)]
    pub request_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, TS)]
#[ts(export)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum NotificationTarget {
    GmailThread {
        connector_id: String,
        thread_id: String,
        #[serde(default)]
        message_id: Option<String>,
    },
    CalendarEvent {
        connector_id: String,
        calendar_id: String,
        event_id: String,
    },
    ConnectorAuth {
        connector_id: String,
    },
    ConnectorSubscription {
        connector_id: String,
        subscription_id: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct DetectorPolicyConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub min_score: Option<f32>,
    #[serde(default)]
    pub min_age_minutes: Option<u32>,
    #[serde(default)]
    pub lead_time_minutes: Option<u32>,
    #[serde(default)]
    pub toast_min_score: Option<f32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AssistantAttentionGlobalPolicy {
    pub toasts_enabled: bool,
    pub badge_enabled: bool,
    pub digest_enabled: bool,
    #[serde(default)]
    pub hosted_inference_allowed: bool,
}

impl Default for AssistantAttentionGlobalPolicy {
    fn default() -> Self {
        Self {
            toasts_enabled: true,
            badge_enabled: true,
            digest_enabled: true,
            hosted_inference_allowed: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ConnectorAttentionPolicy {
    #[serde(default)]
    pub scan_mode: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AssistantUserProfile {
    pub version: u32,
    pub display_name: String,
    #[serde(default)]
    pub preferred_name: Option<String>,
    #[serde(default)]
    pub role_label: Option<String>,
    pub timezone: String,
    pub locale: String,
    #[serde(default)]
    pub primary_email: Option<String>,
    #[serde(default)]
    pub avatar_seed: String,
    #[serde(default)]
    pub grounding_allowed: bool,
}

impl Default for AssistantUserProfile {
    fn default() -> Self {
        let timezone = std::env::var("TZ")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| chrono::Local::now().offset().to_string());
        Self {
            version: 1,
            display_name: "Operator".to_string(),
            preferred_name: None,
            role_label: Some("Private Operator".to_string()),
            timezone,
            locale: "en-US".to_string(),
            primary_email: None,
            avatar_seed: "OP".to_string(),
            grounding_allowed: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AssistantAttentionPolicy {
    pub version: u32,
    #[serde(default)]
    pub global: AssistantAttentionGlobalPolicy,
    #[serde(default)]
    pub detectors: HashMap<String, DetectorPolicyConfig>,
    #[serde(default)]
    pub connectors: HashMap<String, ConnectorAttentionPolicy>,
}

impl Default for AssistantAttentionPolicy {
    fn default() -> Self {
        let mut detectors = HashMap::new();
        detectors.insert(
            "valuable_completion".to_string(),
            DetectorPolicyConfig {
                enabled: true,
                min_score: Some(0.75),
                min_age_minutes: None,
                lead_time_minutes: None,
                toast_min_score: Some(0.9),
            },
        );
        detectors.insert(
            "deadline_risk".to_string(),
            DetectorPolicyConfig {
                enabled: true,
                min_score: Some(0.7),
                min_age_minutes: None,
                lead_time_minutes: Some(30),
                toast_min_score: Some(0.8),
            },
        );
        detectors.insert(
            "auth_attention".to_string(),
            DetectorPolicyConfig {
                enabled: true,
                min_score: Some(0.65),
                min_age_minutes: None,
                lead_time_minutes: None,
                toast_min_score: Some(0.85),
            },
        );
        detectors.insert(
            "follow_up_risk".to_string(),
            DetectorPolicyConfig {
                enabled: true,
                min_score: Some(0.72),
                min_age_minutes: Some(180),
                lead_time_minutes: None,
                toast_min_score: Some(0.9),
            },
        );
        detectors.insert(
            "meeting_prep".to_string(),
            DetectorPolicyConfig {
                enabled: true,
                min_score: Some(0.74),
                min_age_minutes: None,
                lead_time_minutes: Some(45),
                toast_min_score: Some(0.88),
            },
        );
        detectors.insert(
            "stalled_workflow".to_string(),
            DetectorPolicyConfig {
                enabled: true,
                min_score: Some(0.78),
                min_age_minutes: Some(10),
                lead_time_minutes: None,
                toast_min_score: Some(0.9),
            },
        );
        let mut connectors = HashMap::new();
        connectors.insert(
            "gmail".to_string(),
            ConnectorAttentionPolicy {
                scan_mode: Some("metadata_only".to_string()),
            },
        );
        connectors.insert(
            "calendar".to_string(),
            ConnectorAttentionPolicy {
                scan_mode: Some("metadata_only".to_string()),
            },
        );
        Self {
            version: 1,
            global: AssistantAttentionGlobalPolicy::default(),
            detectors,
            connectors,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AssistantAttentionProfile {
    pub version: u32,
    #[serde(default)]
    pub preferred_surfaces: Vec<String>,
    #[serde(default)]
    pub high_value_contacts: Vec<String>,
    #[serde(default)]
    pub focus_windows: Vec<String>,
    #[serde(default)]
    pub notification_feedback: HashMap<String, HashMap<String, u32>>,
}

impl Default for AssistantAttentionProfile {
    fn default() -> Self {
        Self {
            version: 1,
            preferred_surfaces: vec!["inbox".to_string(), "pill".to_string()],
            high_value_contacts: Vec::new(),
            focus_windows: Vec::new(),
            notification_feedback: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct InterventionRecord {
    pub item_id: String,
    #[serde(default = "control_rail")]
    pub rail: NotificationRail,
    pub intervention_type: InterventionType,
    #[serde(default)]
    pub status: InterventionStatus,
    #[serde(default)]
    pub severity: NotificationSeverity,
    #[serde(default)]
    pub blocking: bool,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub summary: String,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub recommended_action: Option<String>,
    #[serde(default)]
    pub consequence_if_ignored: Option<String>,
    #[serde(default)]
    pub created_at_ms: u64,
    #[serde(default)]
    pub updated_at_ms: u64,
    #[serde(default)]
    pub due_at_ms: Option<u64>,
    #[serde(default)]
    pub expires_at_ms: Option<u64>,
    #[serde(default)]
    pub snoozed_until_ms: Option<u64>,
    #[serde(default)]
    pub dedupe_key: String,
    #[serde(default)]
    pub thread_id: Option<String>,
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub workflow_id: Option<String>,
    #[serde(default)]
    pub run_id: Option<String>,
    #[serde(default)]
    pub delivery_state: NotificationDeliveryState,
    #[serde(default)]
    pub privacy: NotificationPrivacy,
    #[serde(default)]
    pub source: NotificationSource,
    #[serde(default)]
    pub artifact_refs: Vec<ArtifactRef>,
    #[serde(default)]
    pub source_event_ids: Vec<String>,
    #[serde(default)]
    pub policy_refs: NotificationPolicyRefs,
    #[serde(default)]
    pub actions: Vec<NotificationAction>,
    #[serde(default)]
    pub target: Option<NotificationTarget>,
    #[serde(default)]
    pub request_hash: Option<String>,
    #[serde(default)]
    pub policy_hash: Option<String>,
    #[serde(default)]
    pub approval_scope: Option<String>,
    #[serde(default)]
    pub sensitive_action_type: Option<String>,
    #[serde(default)]
    pub error_class: Option<String>,
    #[serde(default)]
    pub blocked_stage: Option<String>,
    #[serde(default)]
    pub retry_available: Option<bool>,
    #[serde(default)]
    pub recovery_hint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct AssistantNotificationRecord {
    pub item_id: String,
    #[serde(default)]
    pub rail: NotificationRail,
    pub notification_class: AssistantNotificationClass,
    #[serde(default)]
    pub status: AssistantNotificationStatus,
    #[serde(default)]
    pub severity: NotificationSeverity,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub summary: String,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub recommended_action: Option<String>,
    #[serde(default)]
    pub consequence_if_ignored: Option<String>,
    #[serde(default)]
    pub created_at_ms: u64,
    #[serde(default)]
    pub updated_at_ms: u64,
    #[serde(default)]
    pub due_at_ms: Option<u64>,
    #[serde(default)]
    pub expires_at_ms: Option<u64>,
    #[serde(default)]
    pub snoozed_until_ms: Option<u64>,
    #[serde(default)]
    pub dedupe_key: String,
    #[serde(default)]
    pub thread_id: Option<String>,
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub workflow_id: Option<String>,
    #[serde(default)]
    pub run_id: Option<String>,
    #[serde(default)]
    pub delivery_state: NotificationDeliveryState,
    #[serde(default)]
    pub privacy: NotificationPrivacy,
    #[serde(default)]
    pub source: NotificationSource,
    #[serde(default)]
    pub artifact_refs: Vec<ArtifactRef>,
    #[serde(default)]
    pub source_event_ids: Vec<String>,
    #[serde(default)]
    pub policy_refs: NotificationPolicyRefs,
    #[serde(default)]
    pub actions: Vec<NotificationAction>,
    #[serde(default)]
    pub target: Option<NotificationTarget>,
    #[serde(default)]
    pub priority_score: f32,
    #[serde(default)]
    pub confidence_score: f32,
    #[serde(default)]
    pub ranking_reason: Vec<String>,
}

fn default_true() -> bool {
    true
}

fn control_rail() -> NotificationRail {
    NotificationRail::Control
}
