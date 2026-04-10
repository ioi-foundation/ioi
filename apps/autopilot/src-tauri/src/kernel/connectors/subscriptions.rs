use crate::kernel::artifacts;
use crate::kernel::events::{build_event, register_artifact, register_event};
use crate::models::{AppState, ArtifactRef, ArtifactType, EventStatus, EventType};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::{DateTime, Duration as ChronoDuration, TimeZone, Utc};
use ioi_services::agentic::runtime::connectors::google_auth;
use ioi_services::agentic::runtime::connectors::google_workspace as shared;
use reqwest::{Client, Method};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tauri::{AppHandle, Emitter, Manager};
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::JoinHandle;
use tokio::time::{sleep, Duration};
use uuid::Uuid;

const GOOGLE_AUTOMATION_REGISTRY_VERSION: u32 = 1;
const GOOGLE_AUTOMATION_REGISTRY_FILE: &str = "google_automation_registry.json";
const GOOGLE_AUTOMATION_EVENT_NAME: &str = "connector-subscriptions-changed";
const PUBSUB_BASE_URL: &str = "https://pubsub.googleapis.com/v1";
const GMAIL_BASE_URL: &str = "https://gmail.googleapis.com/gmail/v1";
const WORKSPACE_EVENTS_BASE_URL: &str = "https://workspaceevents.googleapis.com/v1";
const DEFAULT_MAX_MESSAGES: u64 = 10;
const DEFAULT_POLL_INTERVAL_SECS: u64 = 5;
const RENEW_SCAN_INTERVAL_SECS: u64 = 30;
const RECEIPT_RETENTION_LIMIT: usize = 2000;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GoogleSubscriptionKind {
    GmailWatch,
    WorkspaceEvents,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GoogleSubscriptionStatus {
    Active,
    Paused,
    Stopped,
    Degraded,
    ReauthRequired,
    Renewing,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GoogleAutomationTrigger {
    pub action_id: String,
    pub input_template: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GoogleAutomationReceipt {
    pub receipt_id: String,
    pub subscription_id: String,
    pub event_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action_id: Option<String>,
    pub status: String,
    pub summary: String,
    pub created_at_utc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GoogleSubscriptionRecord {
    pub subscription_id: String,
    pub connector_id: String,
    pub thread_id: String,
    pub kind: GoogleSubscriptionKind,
    pub status: GoogleSubscriptionStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_id: Option<String>,
    pub pubsub_topic: String,
    pub pubsub_subscription: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub google_resource_name: Option<String>,
    #[serde(default)]
    pub label_ids: Vec<String>,
    #[serde(default)]
    pub event_types: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_resource: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gmail_history_id: Option<String>,
    pub max_messages: u64,
    pub poll_interval_seconds: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at_utc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub renew_at_utc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_ack_at_utc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_delivery_at_utc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_processed_key: Option<String>,
    pub created_by_action_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub automation: Option<GoogleAutomationTrigger>,
    pub created_at_utc: String,
    pub updated_at_utc: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GoogleConnectorSubscriptionView {
    pub subscription_id: String,
    pub connector_id: String,
    pub kind: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_id: Option<String>,
    pub pubsub_topic: String,
    pub pubsub_subscription: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub google_resource_name: Option<String>,
    #[serde(default)]
    pub label_ids: Vec<String>,
    #[serde(default)]
    pub event_types: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_resource: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gmail_history_id: Option<String>,
    pub max_messages: u64,
    pub poll_interval_seconds: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at_utc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub renew_at_utc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_ack_at_utc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_delivery_at_utc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub automation_action_id: Option<String>,
    pub thread_id: String,
    pub created_at_utc: String,
    pub updated_at_utc: String,
}

#[derive(Debug, Clone)]
pub struct GoogleSubscriptionRegistration {
    pub kind: GoogleSubscriptionKind,
    pub connector_id: String,
    pub account_email: Option<String>,
    pub project_id: Option<String>,
    pub pubsub_topic: String,
    pub pubsub_subscription: String,
    pub google_resource_name: Option<String>,
    pub label_ids: Vec<String>,
    pub event_types: Vec<String>,
    pub target_resource: Option<String>,
    pub gmail_history_id: Option<String>,
    pub max_messages: u64,
    pub poll_interval_seconds: u64,
    pub expires_at_utc: Option<String>,
    pub renew_at_utc: Option<String>,
    pub created_by_action_id: String,
    pub automation: Option<GoogleAutomationTrigger>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct GoogleAutomationRegistry {
    version: u32,
    #[serde(default)]
    subscriptions: Vec<GoogleSubscriptionRecord>,
    #[serde(default)]
    receipts: Vec<GoogleAutomationReceipt>,
}

struct GoogleAutomationInner {
    registry: GoogleAutomationRegistry,
    workers: HashMap<String, JoinHandle<()>>,
    renew_loop: Option<JoinHandle<()>>,
}

impl Default for GoogleAutomationInner {
    fn default() -> Self {
        Self {
            registry: GoogleAutomationRegistry {
                version: GOOGLE_AUTOMATION_REGISTRY_VERSION,
                subscriptions: Vec::new(),
                receipts: Vec::new(),
            },
            workers: HashMap::new(),
            renew_loop: None,
        }
    }
}

#[derive(Clone)]
pub struct GoogleAutomationManager {
    app: AppHandle,
    registry_path: Arc<PathBuf>,
    client: Client,
    inner: Arc<AsyncMutex<GoogleAutomationInner>>,
}

impl GoogleAutomationManager {
    pub fn new(app: AppHandle, registry_path: PathBuf) -> Self {
        let registry = load_registry(&registry_path).unwrap_or_else(|_| GoogleAutomationRegistry {
            version: GOOGLE_AUTOMATION_REGISTRY_VERSION,
            subscriptions: Vec::new(),
            receipts: Vec::new(),
        });
        Self {
            app,
            registry_path: Arc::new(registry_path),
            client: Client::new(),
            inner: Arc::new(AsyncMutex::new(GoogleAutomationInner {
                registry,
                workers: HashMap::new(),
                renew_loop: None,
            })),
        }
    }

    pub async fn bootstrap(&self) -> Result<(), String> {
        self.ensure_renew_loop().await?;
        let active_ids = {
            let inner = self.inner.lock().await;
            inner
                .registry
                .subscriptions
                .iter()
                .filter(|record| {
                    matches!(
                        record.status,
                        GoogleSubscriptionStatus::Active | GoogleSubscriptionStatus::Degraded
                    )
                })
                .map(|record| record.subscription_id.clone())
                .collect::<Vec<_>>()
        };
        for subscription_id in active_ids {
            self.spawn_worker_if_needed(&subscription_id).await?;
        }
        self.emit_subscription_change().await;
        Ok(())
    }

    pub async fn reset_registry(&self) -> Result<(), String> {
        let mut inner = self.inner.lock().await;
        for (_, handle) in inner.workers.drain() {
            handle.abort();
        }
        if let Some(handle) = inner.renew_loop.take() {
            handle.abort();
        }
        inner.registry = GoogleAutomationRegistry {
            version: GOOGLE_AUTOMATION_REGISTRY_VERSION,
            subscriptions: Vec::new(),
            receipts: Vec::new(),
        };
        persist_registry(&self.registry_path, &inner.registry)?;
        drop(inner);
        self.ensure_renew_loop().await?;
        self.emit_subscription_change().await;
        Ok(())
    }

    pub async fn register_subscription(
        &self,
        registration: GoogleSubscriptionRegistration,
    ) -> Result<GoogleConnectorSubscriptionView, String> {
        let now = now_utc_string();
        let mut inner = self.inner.lock().await;
        let existing_idx = inner.registry.subscriptions.iter().position(|record| {
            record.kind == registration.kind
                && (record.pubsub_subscription == registration.pubsub_subscription
                    || record.google_resource_name == registration.google_resource_name)
        });

        let record = if let Some(index) = existing_idx {
            let existing = inner.registry.subscriptions.get_mut(index).expect("index");
            existing.connector_id = registration.connector_id;
            existing.status = GoogleSubscriptionStatus::Active;
            existing.account_email = registration.account_email;
            existing.project_id = registration.project_id;
            existing.pubsub_topic = registration.pubsub_topic;
            existing.pubsub_subscription = registration.pubsub_subscription;
            existing.google_resource_name = registration.google_resource_name;
            existing.label_ids = registration.label_ids;
            existing.event_types = registration.event_types;
            existing.target_resource = registration.target_resource;
            existing.gmail_history_id = registration.gmail_history_id;
            existing.max_messages = registration.max_messages.max(1);
            existing.poll_interval_seconds = registration.poll_interval_seconds.max(1);
            existing.expires_at_utc = registration.expires_at_utc;
            existing.renew_at_utc = registration.renew_at_utc;
            existing.created_by_action_id = registration.created_by_action_id;
            existing.automation = registration.automation;
            existing.updated_at_utc = now.clone();
            existing.clone()
        } else {
            let subscription_id = Uuid::new_v4().to_string();
            let record = GoogleSubscriptionRecord {
                subscription_id: subscription_id.clone(),
                connector_id: registration.connector_id,
                thread_id: format!("google-automation-{}", subscription_id),
                kind: registration.kind,
                status: GoogleSubscriptionStatus::Active,
                account_email: registration.account_email,
                project_id: registration.project_id,
                pubsub_topic: registration.pubsub_topic,
                pubsub_subscription: registration.pubsub_subscription,
                google_resource_name: registration.google_resource_name,
                label_ids: registration.label_ids,
                event_types: registration.event_types,
                target_resource: registration.target_resource,
                gmail_history_id: registration.gmail_history_id,
                max_messages: registration.max_messages.max(1),
                poll_interval_seconds: registration.poll_interval_seconds.max(1),
                expires_at_utc: registration.expires_at_utc,
                renew_at_utc: registration.renew_at_utc,
                last_ack_at_utc: None,
                last_delivery_at_utc: None,
                last_error: None,
                last_processed_key: None,
                created_by_action_id: registration.created_by_action_id,
                automation: registration.automation,
                created_at_utc: now.clone(),
                updated_at_utc: now.clone(),
            };
            inner.registry.subscriptions.push(record.clone());
            record
        };
        persist_registry(&self.registry_path, &inner.registry)?;
        drop(inner);

        self.emit_subscription_registered(&record).await;
        self.spawn_worker_if_needed(&record.subscription_id).await?;
        self.emit_subscription_change().await;
        Ok(view_from_record(&record))
    }

    pub async fn list_subscriptions(
        &self,
        connector_id: &str,
    ) -> Result<Vec<GoogleConnectorSubscriptionView>, String> {
        let inner = self.inner.lock().await;
        let mut items = inner
            .registry
            .subscriptions
            .iter()
            .filter(|record| record.connector_id == connector_id)
            .map(view_from_record)
            .collect::<Vec<_>>();
        items.sort_by(|left, right| right.updated_at_utc.cmp(&left.updated_at_utc));
        Ok(items)
    }

    pub async fn stop_subscription(
        &self,
        subscription_id: &str,
    ) -> Result<GoogleConnectorSubscriptionView, String> {
        let mut inner = self.inner.lock().await;
        if let Some(handle) = inner.workers.remove(subscription_id) {
            handle.abort();
        }
        let view = {
            let record = inner
                .registry
                .subscriptions
                .iter_mut()
                .find(|record| record.subscription_id == subscription_id)
                .ok_or_else(|| format!("Unknown Google subscription '{}'.", subscription_id))?;
            record.status = GoogleSubscriptionStatus::Paused;
            record.updated_at_utc = now_utc_string();
            view_from_record(record)
        };
        persist_registry(&self.registry_path, &inner.registry)?;
        drop(inner);
        self.emit_subscription_change().await;
        Ok(view)
    }

    pub async fn resume_subscription(
        &self,
        subscription_id: &str,
    ) -> Result<GoogleConnectorSubscriptionView, String> {
        let mut inner = self.inner.lock().await;
        let record = inner
            .registry
            .subscriptions
            .iter_mut()
            .find(|record| record.subscription_id == subscription_id)
            .ok_or_else(|| format!("Unknown Google subscription '{}'.", subscription_id))?;
        record.status = GoogleSubscriptionStatus::Active;
        record.last_error = None;
        record.updated_at_utc = now_utc_string();
        let view = view_from_record(record);
        persist_registry(&self.registry_path, &inner.registry)?;
        drop(inner);
        self.spawn_worker_if_needed(subscription_id).await?;
        self.emit_subscription_change().await;
        Ok(view)
    }

    pub async fn renew_subscription_now(
        &self,
        subscription_id: &str,
    ) -> Result<GoogleConnectorSubscriptionView, String> {
        let record = self
            .get_record(subscription_id)
            .await?
            .ok_or_else(|| format!("Unknown Google subscription '{}'.", subscription_id))?;
        self.perform_subscription_renewal(&record).await?;
        self.get_view(subscription_id)
            .await?
            .ok_or_else(|| format!("Unknown Google subscription '{}'.", subscription_id))
    }

    pub async fn get_view(
        &self,
        subscription_id: &str,
    ) -> Result<Option<GoogleConnectorSubscriptionView>, String> {
        Ok(self
            .get_record(subscription_id)
            .await?
            .map(|record| view_from_record(&record)))
    }

    async fn ensure_renew_loop(&self) -> Result<(), String> {
        let mut inner = self.inner.lock().await;
        if inner.renew_loop.is_some() {
            return Ok(());
        }
        let manager = self.clone();
        let handle = tokio::spawn(async move {
            loop {
                manager.scan_renewals().await;
                sleep(Duration::from_secs(RENEW_SCAN_INTERVAL_SECS)).await;
            }
        });
        inner.renew_loop = Some(handle);
        Ok(())
    }

    async fn scan_renewals(&self) {
        let due = {
            let inner = self.inner.lock().await;
            let now = Utc::now();
            inner
                .registry
                .subscriptions
                .iter()
                .filter(|record| {
                    matches!(
                        record.status,
                        GoogleSubscriptionStatus::Active | GoogleSubscriptionStatus::Degraded
                    )
                })
                .filter(|record| {
                    record
                        .renew_at_utc
                        .as_deref()
                        .and_then(parse_datetime)
                        .map(|renew_at| renew_at <= now)
                        .unwrap_or(false)
                })
                .map(|record| record.subscription_id.clone())
                .collect::<Vec<_>>()
        };

        for subscription_id in due {
            if let Some(record) = self.get_record(&subscription_id).await.ok().flatten() {
                let _ = self.perform_subscription_renewal(&record).await;
            }
        }
    }

    async fn spawn_worker_if_needed(&self, subscription_id: &str) -> Result<(), String> {
        let mut inner = self.inner.lock().await;
        if inner
            .workers
            .get(subscription_id)
            .map(|handle| !handle.is_finished())
            .unwrap_or(false)
        {
            return Ok(());
        }

        let manager = self.clone();
        let subscription_id = subscription_id.to_string();
        let worker_subscription_id = subscription_id.clone();
        let handle = tokio::spawn(async move {
            manager.worker_loop(worker_subscription_id).await;
        });
        inner.workers.insert(subscription_id, handle);
        Ok(())
    }

    async fn worker_loop(&self, subscription_id: String) {
        loop {
            let record = match self.get_record(&subscription_id).await {
                Ok(Some(record)) => record,
                _ => break,
            };
            if !matches!(
                record.status,
                GoogleSubscriptionStatus::Active | GoogleSubscriptionStatus::Degraded
            ) {
                break;
            }

            if let Err(error) = self.process_subscription_batch(&record).await {
                let status = if error.contains("missing required scopes")
                    || error.contains("not connected")
                {
                    GoogleSubscriptionStatus::ReauthRequired
                } else {
                    GoogleSubscriptionStatus::Degraded
                };
                let _ = self
                    .update_record(&record.subscription_id, move |existing| {
                        existing.status = status.clone();
                        existing.last_error = Some(error.clone());
                    })
                    .await;
            }

            sleep(Duration::from_secs(record.poll_interval_seconds.max(1))).await;
        }

        let mut inner = self.inner.lock().await;
        inner.workers.remove(&subscription_id);
    }

    async fn process_subscription_batch(
        &self,
        record: &GoogleSubscriptionRecord,
    ) -> Result<(), String> {
        let required_scopes = match record.kind {
            GoogleSubscriptionKind::GmailWatch => vec!["pubsub", "gmail.readonly"],
            GoogleSubscriptionKind::WorkspaceEvents => vec!["pubsub", "workspace.events"],
        };
        let auth = google_auth::access_context(&required_scopes).await?;
        let pulled = pubsub_pull(
            &self.client,
            &auth.access_token,
            &record.pubsub_subscription,
            record.max_messages.max(1),
        )
        .await?;
        let messages = pulled
            .get("receivedMessages")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        if messages.is_empty() {
            return Ok(());
        }

        let mut ack_ids = Vec::new();
        for received in messages {
            let ack_id = received
                .get("ackId")
                .and_then(Value::as_str)
                .map(ToString::to_string);
            let message = received
                .get("message")
                .cloned()
                .unwrap_or_else(|| json!({}));
            let outcome = match record.kind {
                GoogleSubscriptionKind::GmailWatch => {
                    self.process_gmail_notification(record, &auth.access_token, &message)
                        .await
                }
                GoogleSubscriptionKind::WorkspaceEvents => {
                    self.process_workspace_notification(record, &auth.access_token, &message)
                        .await
                }
            };

            match outcome {
                Ok(_) => {
                    if let Some(ack_id) = ack_id {
                        ack_ids.push(ack_id);
                    }
                }
                Err(error) => {
                    self.record_error(record, error).await?;
                }
            }
        }

        if !ack_ids.is_empty() {
            pubsub_acknowledge(
                &self.client,
                &auth.access_token,
                &record.pubsub_subscription,
                ack_ids,
            )
            .await?;
            self.update_record(&record.subscription_id, |existing| {
                existing.last_ack_at_utc = Some(now_utc_string());
                existing.last_error = None;
                if matches!(
                    existing.status,
                    GoogleSubscriptionStatus::Degraded | GoogleSubscriptionStatus::ReauthRequired
                ) {
                    existing.status = GoogleSubscriptionStatus::Active;
                }
            })
            .await?;
        }

        Ok(())
    }

    async fn process_gmail_notification(
        &self,
        record: &GoogleSubscriptionRecord,
        access_token: &str,
        message: &Value,
    ) -> Result<(), String> {
        let message_id = message
            .get("messageId")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let notification = decode_pubsub_json(message)?;
        let latest_history_id = notification
            .get("historyId")
            .and_then(Value::as_str)
            .map(ToString::to_string)
            .ok_or_else(|| "Gmail notification is missing `historyId`.".to_string())?;
        let start_history_id = record
            .gmail_history_id
            .clone()
            .unwrap_or_else(|| latest_history_id.clone());

        let history = match gmail_list_history(
            &self.client,
            access_token,
            &start_history_id,
            record.label_ids.clone(),
        )
        .await
        {
            Ok(history) => history,
            Err(error) if error.contains("404") || error.contains("startHistoryId") => {
                let renewed = renew_gmail_watch(&self.client, access_token, record).await?;
                let watch = renewed.get("watch").cloned().unwrap_or_else(|| json!({}));
                let next_history_id = watch
                    .get("historyId")
                    .and_then(Value::as_str)
                    .map(ToString::to_string)
                    .or_else(|| Some(latest_history_id.clone()));
                self.update_record(&record.subscription_id, |existing| {
                    existing.gmail_history_id = next_history_id.clone();
                    existing.expires_at_utc = parse_gmail_watch_expiration(&watch);
                    existing.renew_at_utc = existing
                        .expires_at_utc
                        .clone()
                        .and_then(|value| calculate_gmail_renew_at(&value));
                    existing.last_error = Some(
                        "Gmail history cursor expired; watch was renewed and the cursor was reset."
                            .to_string(),
                    );
                    existing.status = GoogleSubscriptionStatus::Degraded;
                })
                .await?;
                return Ok(());
            }
            Err(error) => return Err(error),
        };

        let mut processed_any = false;
        let mut latest_cursor = history
            .get("historyId")
            .and_then(Value::as_str)
            .map(ToString::to_string)
            .unwrap_or_else(|| latest_history_id.clone());

        let histories = history
            .get("history")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let mut message_ids = BTreeMap::<String, Value>::new();
        for entry in histories {
            if let Some(history_id) = entry.get("id").and_then(Value::as_str) {
                latest_cursor = history_id.to_string();
            }
            for added in entry
                .get("messagesAdded")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default()
            {
                if let Some(message_obj) = added.get("message") {
                    if let Some(id) = message_obj.get("id").and_then(Value::as_str) {
                        message_ids.insert(id.to_string(), message_obj.clone());
                    }
                }
            }
        }

        for gmail_message_id in message_ids.keys() {
            let gmail_message =
                gmail_get_message_metadata(&self.client, access_token, gmail_message_id).await?;
            let event_key = format!("gmail:{}:{}", record.subscription_id, gmail_message_id);
            if self
                .receipt_exists(&event_key, record.automation.as_ref())
                .await?
            {
                processed_any = true;
                continue;
            }

            let context = json!({
                "subscription": view_from_record(record),
                "notification": notification,
                "pubsub": message,
                "message": normalize_gmail_message(&gmail_message),
            });
            let artifact_refs = self
                .create_delivery_artifacts(
                    &record.thread_id,
                    "gmail_delivery",
                    &format!("Gmail delivery {}", gmail_message_id),
                    &context,
                )
                .await;
            let agent_event = build_event(
                &record.thread_id,
                0,
                EventType::InfoNote,
                format!("Processed Gmail delivery {}", gmail_message_id),
                json!({
                    "subscription_id": record.subscription_id,
                    "gmail_message_id": gmail_message_id,
                    "pubsub_message_id": message_id,
                    "automation_action_id": record.automation.as_ref().map(|item| item.action_id.clone()),
                }),
                context.clone(),
                EventStatus::Success,
                artifact_refs.clone(),
                None,
                Vec::new(),
                None,
            );
            register_event(&self.app, agent_event);
            self.execute_trigger(record, &event_key, &context).await?;
            self.record_receipt(GoogleAutomationReceipt {
                receipt_id: Uuid::new_v4().to_string(),
                subscription_id: record.subscription_id.clone(),
                event_key,
                action_id: record
                    .automation
                    .as_ref()
                    .map(|trigger| trigger.action_id.clone()),
                status: "success".to_string(),
                summary: format!("Processed Gmail message {}.", gmail_message_id),
                created_at_utc: now_utc_string(),
                result: Some(json!({
                    "gmailMessageId": gmail_message_id,
                    "pubsubMessageId": message_id,
                })),
            })
            .await?;
            processed_any = true;
        }

        self.update_record(&record.subscription_id, |existing| {
            existing.gmail_history_id = Some(latest_cursor.clone());
            if processed_any {
                existing.last_delivery_at_utc = Some(now_utc_string());
            }
            existing.last_error = None;
        })
        .await?;
        Ok(())
    }

    async fn process_workspace_notification(
        &self,
        record: &GoogleSubscriptionRecord,
        _access_token: &str,
        message: &Value,
    ) -> Result<(), String> {
        let pubsub_message_id = message
            .get("messageId")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let event_payload = decode_pubsub_json(message)?;
        let event_id = event_payload
            .get("id")
            .and_then(Value::as_str)
            .map(ToString::to_string)
            .unwrap_or_else(|| pubsub_message_id.clone());
        let event_key = format!("workspace:{}:{}", record.subscription_id, event_id);
        if self
            .receipt_exists(&event_key, record.automation.as_ref())
            .await?
        {
            return Ok(());
        }

        let context = json!({
            "subscription": view_from_record(record),
            "pubsub": message,
            "event": event_payload,
        });
        let artifact_refs = self
            .create_delivery_artifacts(
                &record.thread_id,
                "workspace_event_delivery",
                &format!("Workspace event {}", event_id),
                &context,
            )
            .await;
        let event = build_event(
            &record.thread_id,
            0,
            EventType::InfoNote,
            format!("Processed Workspace event {}", event_id),
            json!({
                "subscription_id": record.subscription_id,
                "event_id": event_id,
                "pubsub_message_id": pubsub_message_id,
                "automation_action_id": record.automation.as_ref().map(|item| item.action_id.clone()),
            }),
            context.clone(),
            EventStatus::Success,
            artifact_refs,
            None,
            Vec::new(),
            None,
        );
        register_event(&self.app, event);
        self.execute_trigger(record, &event_key, &context).await?;
        self.record_receipt(GoogleAutomationReceipt {
            receipt_id: Uuid::new_v4().to_string(),
            subscription_id: record.subscription_id.clone(),
            event_key,
            action_id: record
                .automation
                .as_ref()
                .map(|trigger| trigger.action_id.clone()),
            status: "success".to_string(),
            summary: "Processed Workspace event.".to_string(),
            created_at_utc: now_utc_string(),
            result: Some(json!({
                "pubsubMessageId": pubsub_message_id,
                "eventId": event_id,
            })),
        })
        .await?;
        self.update_record(&record.subscription_id, |existing| {
            existing.last_delivery_at_utc = Some(now_utc_string());
            existing.last_error = None;
        })
        .await?;
        Ok(())
    }

    async fn execute_trigger(
        &self,
        record: &GoogleSubscriptionRecord,
        event_key: &str,
        context: &Value,
    ) -> Result<(), String> {
        let Some(trigger) = &record.automation else {
            return Ok(());
        };
        let input = render_template(&trigger.input_template, context);
        let result = shared::connector_run_action(
            shared::GOOGLE_CONNECTOR_ID,
            &trigger.action_id,
            input.clone(),
        )
        .await?;
        let report = json!({
            "subscriptionId": record.subscription_id,
            "eventKey": event_key,
            "actionId": trigger.action_id,
            "input": input,
            "result": result,
        });
        let artifact_refs = self
            .create_delivery_artifacts(
                &record.thread_id,
                "automation_receipt",
                &format!("Automation receipt {}", trigger.action_id),
                &report,
            )
            .await;
        let event = build_event(
            &record.thread_id,
            0,
            EventType::Receipt,
            format!("Automation executed {}", trigger.action_id),
            json!({
                "subscription_id": record.subscription_id,
                "action_id": trigger.action_id,
                "event_key": event_key,
            }),
            report,
            EventStatus::Success,
            artifact_refs,
            None,
            Vec::new(),
            None,
        );
        register_event(&self.app, event);
        Ok(())
    }

    async fn perform_subscription_renewal(
        &self,
        record: &GoogleSubscriptionRecord,
    ) -> Result<(), String> {
        self.update_record(&record.subscription_id, |existing| {
            existing.status = GoogleSubscriptionStatus::Renewing;
            existing.last_error = None;
        })
        .await?;

        let result = match record.kind {
            GoogleSubscriptionKind::GmailWatch => {
                let auth = google_auth::access_context(&["gmail.modify", "pubsub"]).await?;
                renew_gmail_watch(&self.client, &auth.access_token, record).await
            }
            GoogleSubscriptionKind::WorkspaceEvents => {
                let auth = google_auth::access_context(&["workspace.events"]).await?;
                reactivate_workspace_subscription(
                    &self.client,
                    &auth.access_token,
                    record.google_resource_name.as_deref().ok_or_else(|| {
                        "Workspace subscription is missing the Google resource name.".to_string()
                    })?,
                )
                .await
            }
        }?;

        let renewed_at = now_utc_string();
        self.update_record(&record.subscription_id, |existing| {
            existing.status = GoogleSubscriptionStatus::Active;
            existing.last_error = None;
            existing.updated_at_utc = renewed_at.clone();
            match existing.kind {
                GoogleSubscriptionKind::GmailWatch => {
                    let watch = result.get("watch").cloned().unwrap_or_else(|| json!({}));
                    existing.gmail_history_id = watch
                        .get("historyId")
                        .and_then(Value::as_str)
                        .map(ToString::to_string)
                        .or_else(|| existing.gmail_history_id.clone());
                    existing.expires_at_utc = parse_gmail_watch_expiration(&watch);
                    existing.renew_at_utc = existing
                        .expires_at_utc
                        .clone()
                        .and_then(|value| calculate_gmail_renew_at(&value));
                }
                GoogleSubscriptionKind::WorkspaceEvents => {
                    existing.expires_at_utc = result
                        .get("expireTime")
                        .and_then(Value::as_str)
                        .map(ToString::to_string)
                        .or_else(|| existing.expires_at_utc.clone());
                    existing.renew_at_utc = existing
                        .expires_at_utc
                        .clone()
                        .and_then(|value| calculate_workspace_renew_at(&value));
                }
            }
        })
        .await?;

        let event = build_event(
            &record.thread_id,
            0,
            EventType::InfoNote,
            format!("Renewed {}", subscription_kind_label(&record.kind)),
            json!({
                "subscription_id": record.subscription_id,
                "kind": subscription_kind_label(&record.kind),
            }),
            json!({
                "result": result,
            }),
            EventStatus::Success,
            Vec::new(),
            None,
            Vec::new(),
            None,
        );
        register_event(&self.app, event);
        self.emit_subscription_change().await;
        Ok(())
    }

    async fn record_error(
        &self,
        record: &GoogleSubscriptionRecord,
        error: String,
    ) -> Result<(), String> {
        let status = if error.contains("missing required scopes") || error.contains("not connected")
        {
            GoogleSubscriptionStatus::ReauthRequired
        } else {
            GoogleSubscriptionStatus::Degraded
        };
        self.update_record(&record.subscription_id, |existing| {
            existing.status = status.clone();
            existing.last_error = Some(error.clone());
        })
        .await?;
        Ok(())
    }

    async fn create_delivery_artifacts(
        &self,
        thread_id: &str,
        title_prefix: &str,
        title: &str,
        payload: &Value,
    ) -> Vec<ArtifactRef> {
        let memory_runtime = {
            let state = self.app.state::<Mutex<AppState>>();
            state
                .lock()
                .ok()
                .and_then(|guard| guard.memory_runtime.clone())
        };
        let Some(memory_runtime) = memory_runtime else {
            return Vec::new();
        };

        let artifact = artifacts::create_report_artifact(
            &memory_runtime,
            thread_id,
            title,
            title_prefix,
            payload,
        );
        let artifact_id = artifact.artifact_id.clone();
        register_artifact(&self.app, artifact);
        vec![ArtifactRef {
            artifact_id,
            artifact_type: ArtifactType::Report,
        }]
    }

    async fn update_record<F>(&self, subscription_id: &str, mut apply: F) -> Result<(), String>
    where
        F: FnMut(&mut GoogleSubscriptionRecord),
    {
        let mut inner = self.inner.lock().await;
        let record = inner
            .registry
            .subscriptions
            .iter_mut()
            .find(|record| record.subscription_id == subscription_id)
            .ok_or_else(|| format!("Unknown Google subscription '{}'.", subscription_id))?;
        apply(record);
        record.updated_at_utc = now_utc_string();
        persist_registry(&self.registry_path, &inner.registry)?;
        drop(inner);
        self.emit_subscription_change().await;
        Ok(())
    }

    async fn get_record(
        &self,
        subscription_id: &str,
    ) -> Result<Option<GoogleSubscriptionRecord>, String> {
        let inner = self.inner.lock().await;
        Ok(inner
            .registry
            .subscriptions
            .iter()
            .find(|record| record.subscription_id == subscription_id)
            .cloned())
    }

    async fn receipt_exists(
        &self,
        event_key: &str,
        automation: Option<&GoogleAutomationTrigger>,
    ) -> Result<bool, String> {
        let inner = self.inner.lock().await;
        let action_id = automation.map(|item| item.action_id.as_str());
        Ok(inner.registry.receipts.iter().any(|receipt| {
            receipt.event_key == event_key
                && receipt.action_id.as_deref() == action_id
                && receipt.status == "success"
        }))
    }

    async fn record_receipt(&self, receipt: GoogleAutomationReceipt) -> Result<(), String> {
        let mut inner = self.inner.lock().await;
        inner.registry.receipts.push(receipt);
        if inner.registry.receipts.len() > RECEIPT_RETENTION_LIMIT {
            let overflow = inner.registry.receipts.len() - RECEIPT_RETENTION_LIMIT;
            inner.registry.receipts.drain(0..overflow);
        }
        persist_registry(&self.registry_path, &inner.registry)?;
        Ok(())
    }

    async fn emit_subscription_registered(&self, record: &GoogleSubscriptionRecord) {
        let event = build_event(
            &record.thread_id,
            0,
            EventType::InfoNote,
            format!("Registered {}", subscription_kind_label(&record.kind)),
            json!({
                "subscription_id": record.subscription_id,
                "kind": subscription_kind_label(&record.kind),
            }),
            json!(view_from_record(record)),
            EventStatus::Success,
            Vec::new(),
            None,
            Vec::new(),
            None,
        );
        register_event(&self.app, event);
    }

    async fn emit_subscription_change(&self) {
        if let Ok(items) = self.list_subscriptions(shared::GOOGLE_CONNECTOR_ID).await {
            let _ = self.app.emit(GOOGLE_AUTOMATION_EVENT_NAME, &items);
        }
    }
}

pub fn registry_path_for(data_dir: &Path) -> PathBuf {
    data_dir.join(GOOGLE_AUTOMATION_REGISTRY_FILE)
}

pub async fn build_registration_from_result(
    action_id: &str,
    input: &Value,
    result: &shared::ConnectorActionResult,
) -> Result<Option<GoogleSubscriptionRegistration>, String> {
    let account_email = google_auth::access_context(&[])
        .await
        .ok()
        .and_then(|context| context.account_email);
    let automation = parse_automation_trigger(input)?;

    match action_id {
        "gmail.watch_emails" => {
            let data = result.data.clone();
            let watch = data.get("watch").cloned().unwrap_or_else(|| json!({}));
            let topic = data
                .get("topic")
                .and_then(Value::as_str)
                .ok_or_else(|| "Gmail watch did not return a Pub/Sub topic.".to_string())?;
            let subscription = data
                .get("subscription")
                .and_then(Value::as_str)
                .ok_or_else(|| "Gmail watch did not return a Pub/Sub subscription.".to_string())?;
            let project_id = input
                .get("project")
                .and_then(Value::as_str)
                .map(ToString::to_string)
                .or_else(|| google_project_from_resource_name("topics", topic))
                .or_else(|| google_project_from_resource_name("subscriptions", subscription));
            Ok(Some(GoogleSubscriptionRegistration {
                kind: GoogleSubscriptionKind::GmailWatch,
                connector_id: result.connector_id.clone(),
                account_email,
                project_id,
                pubsub_topic: topic.to_string(),
                pubsub_subscription: subscription.to_string(),
                google_resource_name: None,
                label_ids: split_csv_field(input.get("labelIds").and_then(Value::as_str)),
                event_types: Vec::new(),
                target_resource: None,
                gmail_history_id: watch
                    .get("historyId")
                    .and_then(Value::as_str)
                    .map(ToString::to_string),
                max_messages: input
                    .get("maxMessages")
                    .and_then(Value::as_u64)
                    .unwrap_or(DEFAULT_MAX_MESSAGES),
                poll_interval_seconds: input
                    .get("pollInterval")
                    .and_then(Value::as_u64)
                    .unwrap_or(DEFAULT_POLL_INTERVAL_SECS),
                expires_at_utc: parse_gmail_watch_expiration(&watch),
                renew_at_utc: parse_gmail_watch_expiration(&watch)
                    .and_then(|value| calculate_gmail_renew_at(&value)),
                created_by_action_id: action_id.to_string(),
                automation,
            }))
        }
        "events.subscribe" => {
            let data = result.data.clone();
            let subscription_response = data
                .get("subscription")
                .cloned()
                .unwrap_or_else(|| json!({}));
            let pubsub_topic =
                data.get("pubsubTopic")
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        "Workspace Events subscribe did not return a Pub/Sub topic.".to_string()
                    })?;
            let pubsub_subscription = data
                .get("pubsubSubscription")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    "Workspace Events subscribe did not return a Pub/Sub subscription.".to_string()
                })?;
            let google_resource_name = subscription_response
                .get("name")
                .and_then(Value::as_str)
                .map(ToString::to_string);
            let project_id = input
                .get("project")
                .and_then(Value::as_str)
                .map(ToString::to_string)
                .or_else(|| google_project_from_resource_name("topics", pubsub_topic))
                .or_else(|| {
                    google_project_from_resource_name("subscriptions", pubsub_subscription)
                });
            Ok(Some(GoogleSubscriptionRegistration {
                kind: GoogleSubscriptionKind::WorkspaceEvents,
                connector_id: result.connector_id.clone(),
                account_email,
                project_id,
                pubsub_topic: pubsub_topic.to_string(),
                pubsub_subscription: pubsub_subscription.to_string(),
                google_resource_name,
                label_ids: Vec::new(),
                event_types: split_csv_field(input.get("eventTypes").and_then(Value::as_str)),
                target_resource: input
                    .get("target")
                    .and_then(Value::as_str)
                    .map(ToString::to_string)
                    .or_else(|| {
                        subscription_response
                            .get("targetResource")
                            .and_then(Value::as_str)
                            .map(ToString::to_string)
                    }),
                gmail_history_id: None,
                max_messages: input
                    .get("maxMessages")
                    .and_then(Value::as_u64)
                    .unwrap_or(DEFAULT_MAX_MESSAGES),
                poll_interval_seconds: input
                    .get("pollInterval")
                    .and_then(Value::as_u64)
                    .unwrap_or(DEFAULT_POLL_INTERVAL_SECS),
                expires_at_utc: subscription_response
                    .get("expireTime")
                    .and_then(Value::as_str)
                    .map(ToString::to_string),
                renew_at_utc: subscription_response
                    .get("expireTime")
                    .and_then(Value::as_str)
                    .and_then(calculate_workspace_renew_at),
                created_by_action_id: action_id.to_string(),
                automation,
            }))
        }
        _ => Ok(None),
    }
}

async fn pubsub_pull(
    client: &Client,
    access_token: &str,
    subscription_name: &str,
    max_messages: u64,
) -> Result<Value, String> {
    google_json_request(
        client,
        access_token,
        Method::POST,
        &format!("{}/{subscription_name}:pull", PUBSUB_BASE_URL),
        None,
        Some(json!({
            "maxMessages": max_messages,
        })),
    )
    .await
}

async fn pubsub_acknowledge(
    client: &Client,
    access_token: &str,
    subscription_name: &str,
    ack_ids: Vec<String>,
) -> Result<Value, String> {
    google_json_request(
        client,
        access_token,
        Method::POST,
        &format!("{}/{subscription_name}:acknowledge", PUBSUB_BASE_URL),
        None,
        Some(json!({
            "ackIds": ack_ids,
        })),
    )
    .await
}

async fn gmail_list_history(
    client: &Client,
    access_token: &str,
    start_history_id: &str,
    label_ids: Vec<String>,
) -> Result<Value, String> {
    let mut query = vec![
        ("startHistoryId".to_string(), start_history_id.to_string()),
        ("historyTypes".to_string(), "messageAdded".to_string()),
        ("maxResults".to_string(), "50".to_string()),
    ];
    for label_id in label_ids {
        query.push(("labelId".to_string(), label_id));
    }
    google_json_request(
        client,
        access_token,
        Method::GET,
        &format!("{}/users/me/history", GMAIL_BASE_URL),
        Some(query),
        None,
    )
    .await
}

async fn gmail_get_message_metadata(
    client: &Client,
    access_token: &str,
    message_id: &str,
) -> Result<Value, String> {
    let query = vec![
        ("format".to_string(), "metadata".to_string()),
        ("metadataHeaders".to_string(), "From".to_string()),
        ("metadataHeaders".to_string(), "Subject".to_string()),
        ("metadataHeaders".to_string(), "Date".to_string()),
    ];
    google_json_request(
        client,
        access_token,
        Method::GET,
        &format!(
            "{}/users/me/messages/{}",
            GMAIL_BASE_URL,
            url_encode(message_id)
        ),
        Some(query),
        None,
    )
    .await
}

async fn renew_gmail_watch(
    client: &Client,
    access_token: &str,
    record: &GoogleSubscriptionRecord,
) -> Result<Value, String> {
    let mut body = json!({
        "topicName": record.pubsub_topic
    });
    if !record.label_ids.is_empty() {
        body["labelIds"] = Value::Array(
            record
                .label_ids
                .iter()
                .cloned()
                .map(Value::String)
                .collect(),
        );
    }
    let watch = google_json_request(
        client,
        access_token,
        Method::POST,
        &format!("{}/users/me/watch", GMAIL_BASE_URL),
        Some(vec![("userId".to_string(), "me".to_string())]),
        Some(body),
    )
    .await?;
    Ok(json!({
        "watch": watch,
        "topic": record.pubsub_topic,
        "subscription": record.pubsub_subscription,
    }))
}

async fn reactivate_workspace_subscription(
    client: &Client,
    access_token: &str,
    resource_name: &str,
) -> Result<Value, String> {
    google_json_request(
        client,
        access_token,
        Method::POST,
        &format!(
            "{}/{}:reactivate",
            WORKSPACE_EVENTS_BASE_URL,
            resource_name.trim_start_matches('/')
        ),
        None,
        Some(json!({})),
    )
    .await
}

async fn google_json_request(
    client: &Client,
    access_token: &str,
    method: Method,
    url: &str,
    query: Option<Vec<(String, String)>>,
    body: Option<Value>,
) -> Result<Value, String> {
    let mut request = client.request(method, url).bearer_auth(access_token);
    if let Some(query) = query {
        request = request.query(&query);
    }
    if let Some(body) = body {
        request = request.json(&body);
    }
    let response = request
        .send()
        .await
        .map_err(|error| format!("Google API request failed for '{}': {}", url, error))?;
    parse_google_response(response).await
}

async fn parse_google_response(response: reqwest::Response) -> Result<Value, String> {
    let status = response.status();
    let text = response
        .text()
        .await
        .map_err(|error| format!("Failed to read Google API response: {}", error))?;
    if !status.is_success() {
        return Err(format!(
            "Google API request failed with {}: {}",
            status, text
        ));
    }
    if text.trim().is_empty() {
        return Ok(json!({ "ok": true, "status": status.as_u16() }));
    }
    serde_json::from_str(&text).map_err(|error| {
        format!(
            "Failed to parse Google API JSON response '{}': {}",
            text, error
        )
    })
}

fn load_registry(path: &Path) -> Result<GoogleAutomationRegistry, String> {
    if !path.exists() {
        return Ok(GoogleAutomationRegistry {
            version: GOOGLE_AUTOMATION_REGISTRY_VERSION,
            subscriptions: Vec::new(),
            receipts: Vec::new(),
        });
    }
    let bytes = fs::read(path)
        .map_err(|error| format!("Failed to read Google automation registry: {}", error))?;
    serde_json::from_slice(&bytes)
        .map_err(|error| format!("Failed to parse Google automation registry: {}", error))
}

fn persist_registry(path: &Path, registry: &GoogleAutomationRegistry) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| {
            format!("Failed to create Google automation registry dir: {}", error)
        })?;
    }
    let payload = serde_json::to_vec_pretty(registry)
        .map_err(|error| format!("Failed to serialize Google automation registry: {}", error))?;
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, payload).map_err(|error| {
        format!(
            "Failed to write Google automation registry temp file: {}",
            error
        )
    })?;
    fs::rename(&tmp, path).map_err(|error| {
        format!(
            "Failed to finalize Google automation registry file: {}",
            error
        )
    })?;
    Ok(())
}

fn view_from_record(record: &GoogleSubscriptionRecord) -> GoogleConnectorSubscriptionView {
    GoogleConnectorSubscriptionView {
        subscription_id: record.subscription_id.clone(),
        connector_id: record.connector_id.clone(),
        kind: subscription_kind_label(&record.kind).to_string(),
        status: subscription_status_label(&record.status).to_string(),
        account_email: record.account_email.clone(),
        project_id: record.project_id.clone(),
        pubsub_topic: record.pubsub_topic.clone(),
        pubsub_subscription: record.pubsub_subscription.clone(),
        google_resource_name: record.google_resource_name.clone(),
        label_ids: record.label_ids.clone(),
        event_types: record.event_types.clone(),
        target_resource: record.target_resource.clone(),
        gmail_history_id: record.gmail_history_id.clone(),
        max_messages: record.max_messages,
        poll_interval_seconds: record.poll_interval_seconds,
        expires_at_utc: record.expires_at_utc.clone(),
        renew_at_utc: record.renew_at_utc.clone(),
        last_ack_at_utc: record.last_ack_at_utc.clone(),
        last_delivery_at_utc: record.last_delivery_at_utc.clone(),
        last_error: record.last_error.clone(),
        automation_action_id: record
            .automation
            .as_ref()
            .map(|trigger| trigger.action_id.clone()),
        thread_id: record.thread_id.clone(),
        created_at_utc: record.created_at_utc.clone(),
        updated_at_utc: record.updated_at_utc.clone(),
    }
}

fn parse_automation_trigger(input: &Value) -> Result<Option<GoogleAutomationTrigger>, String> {
    let Some(action_id) = input
        .get("automationActionId")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Ok(None);
    };
    if matches!(
        action_id,
        "gmail.watch_emails" | "events.subscribe" | "events.renew" | "expert.raw_request"
    ) {
        return Err(format!(
            "Automation action '{}' is not allowed as a background trigger target.",
            action_id
        ));
    }
    let template = match input.get("automationInputTemplate") {
        Some(Value::String(raw)) if !raw.trim().is_empty() => serde_json::from_str(raw)
            .map_err(|error| format!("Invalid automationInputTemplate JSON: {}", error))?,
        Some(Value::Object(map)) => Value::Object(map.clone()),
        Some(Value::Null) | None => default_automation_template(action_id),
        Some(other) => other.clone(),
    };
    Ok(Some(GoogleAutomationTrigger {
        action_id: action_id.to_string(),
        input_template: template,
    }))
}

fn default_automation_template(action_id: &str) -> Value {
    match action_id {
        "workflow.email_to_task" => json!({
            "messageId": "{{message.messageId}}",
            "tasklist": "@default"
        }),
        _ => json!({}),
    }
}

fn render_template(template: &Value, context: &Value) -> Value {
    match template {
        Value::String(raw) => render_template_string(raw, context),
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(|item| render_template(item, context))
                .collect(),
        ),
        Value::Object(map) => {
            let mut next = Map::new();
            for (key, value) in map {
                next.insert(key.clone(), render_template(value, context));
            }
            Value::Object(next)
        }
        other => other.clone(),
    }
}

fn render_template_string(template: &str, context: &Value) -> Value {
    let trimmed = template.trim();
    if trimmed.starts_with("{{") && trimmed.ends_with("}}") && trimmed.matches("{{").count() == 1 {
        let path = trimmed
            .trim_start_matches("{{")
            .trim_end_matches("}}")
            .trim();
        return resolve_context_value(context, path)
            .cloned()
            .unwrap_or_else(|| Value::String(template.to_string()));
    }

    let mut output = template.to_string();
    for placeholder in collect_placeholders(template) {
        let token = format!("{{{{{}}}}}", placeholder);
        let replacement = resolve_context_value(context, &placeholder)
            .map(stringify_template_value)
            .unwrap_or_default();
        output = output.replace(&token, &replacement);
    }
    Value::String(output)
}

fn collect_placeholders(template: &str) -> Vec<String> {
    let mut placeholders = Vec::new();
    let bytes = template.as_bytes();
    let mut index = 0;
    while index + 1 < bytes.len() {
        if bytes[index] == b'{' && bytes[index + 1] == b'{' {
            if let Some(end) = template[index + 2..].find("}}") {
                let raw = template[index + 2..index + 2 + end].trim();
                if !raw.is_empty() && !placeholders.iter().any(|value| value == raw) {
                    placeholders.push(raw.to_string());
                }
                index += end + 4;
                continue;
            }
        }
        index += 1;
    }
    placeholders
}

fn resolve_context_value<'a>(context: &'a Value, path: &str) -> Option<&'a Value> {
    let mut current = context;
    for part in path.split('.') {
        match current {
            Value::Object(map) => current = map.get(part)?,
            _ => return None,
        }
    }
    Some(current)
}

fn stringify_template_value(value: &Value) -> String {
    match value {
        Value::Null => String::new(),
        Value::Bool(item) => item.to_string(),
        Value::Number(item) => item.to_string(),
        Value::String(item) => item.clone(),
        other => serde_json::to_string(other).unwrap_or_else(|_| other.to_string()),
    }
}

fn decode_pubsub_json(message: &Value) -> Result<Value, String> {
    let data = message
        .get("data")
        .and_then(Value::as_str)
        .ok_or_else(|| "Pub/Sub message is missing `data`.".to_string())?;
    let decoded = STANDARD
        .decode(data)
        .map_err(|error| format!("Failed to decode Pub/Sub message data: {}", error))?;
    serde_json::from_slice(&decoded)
        .map_err(|error| format!("Failed to parse Pub/Sub message data JSON: {}", error))
}

fn normalize_gmail_message(message: &Value) -> Value {
    let headers = message
        .get("payload")
        .and_then(|payload| payload.get("headers"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut header_map = BTreeMap::new();
    for header in headers {
        if let (Some(name), Some(value)) = (
            header.get("name").and_then(Value::as_str),
            header.get("value").and_then(Value::as_str),
        ) {
            header_map.insert(name.to_ascii_lowercase(), value.to_string());
        }
    }
    json!({
        "messageId": message.get("id").and_then(Value::as_str).unwrap_or_default(),
        "threadId": message.get("threadId").and_then(Value::as_str).unwrap_or_default(),
        "labelIds": message.get("labelIds").cloned().unwrap_or_else(|| Value::Array(Vec::new())),
        "snippet": message.get("snippet").and_then(Value::as_str).unwrap_or_default(),
        "internalDate": message.get("internalDate").and_then(Value::as_str).unwrap_or_default(),
        "from": header_map.get("from").cloned().unwrap_or_default(),
        "subject": header_map.get("subject").cloned().unwrap_or_default(),
        "date": header_map.get("date").cloned().unwrap_or_default(),
    })
}

fn split_csv_field(raw: Option<&str>) -> Vec<String> {
    raw.unwrap_or_default()
        .split(|ch| ch == ',' || ch == '\n')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .collect()
}

fn google_project_from_resource_name(resource_kind: &str, name: &str) -> Option<String> {
    let segments = name.split('/').collect::<Vec<_>>();
    if segments.len() >= 4 && segments[0] == "projects" && segments[2] == resource_kind {
        return Some(segments[1].to_string());
    }
    None
}

fn parse_gmail_watch_expiration(watch: &Value) -> Option<String> {
    let millis = watch.get("expiration").and_then(Value::as_str)?;
    let timestamp = millis.parse::<i64>().ok()?;
    let datetime = Utc.timestamp_millis_opt(timestamp).single()?;
    Some(datetime.to_rfc3339())
}

fn calculate_gmail_renew_at(expires_at_utc: &str) -> Option<String> {
    let expires_at = parse_datetime(expires_at_utc)?;
    Some((expires_at - ChronoDuration::hours(1)).to_rfc3339())
}

fn calculate_workspace_renew_at(expires_at_utc: &str) -> Option<String> {
    let expires_at = parse_datetime(expires_at_utc)?;
    Some((expires_at - ChronoDuration::minutes(30)).to_rfc3339())
}

fn parse_datetime(raw: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(raw)
        .ok()
        .map(|value| value.with_timezone(&Utc))
}

fn now_utc_string() -> String {
    Utc::now().to_rfc3339()
}

fn subscription_kind_label(kind: &GoogleSubscriptionKind) -> &'static str {
    match kind {
        GoogleSubscriptionKind::GmailWatch => "gmail_watch",
        GoogleSubscriptionKind::WorkspaceEvents => "workspace_events",
    }
}

fn subscription_status_label(status: &GoogleSubscriptionStatus) -> &'static str {
    match status {
        GoogleSubscriptionStatus::Active => "active",
        GoogleSubscriptionStatus::Paused => "paused",
        GoogleSubscriptionStatus::Stopped => "stopped",
        GoogleSubscriptionStatus::Degraded => "degraded",
        GoogleSubscriptionStatus::ReauthRequired => "reauth_required",
        GoogleSubscriptionStatus::Renewing => "renewing",
    }
}

fn url_encode(raw: &str) -> String {
    url::form_urlencoded::byte_serialize(raw.as_bytes()).collect()
}

#[cfg(test)]
mod tests {
    use super::{
        calculate_gmail_renew_at, collect_placeholders, default_automation_template,
        google_project_from_resource_name, render_template, split_csv_field,
    };
    use serde_json::json;

    #[test]
    fn defaults_email_to_task_template() {
        let template = default_automation_template("workflow.email_to_task");
        assert_eq!(template["messageId"], "{{message.messageId}}");
    }

    #[test]
    fn renders_string_and_scalar_placeholders() {
        let rendered = render_template(
            &json!({
                "messageId": "{{message.messageId}}",
                "text": "New event {{event.type}}"
            }),
            &json!({
                "message": { "messageId": "abc123" },
                "event": { "type": "created" }
            }),
        );
        assert_eq!(rendered["messageId"], "abc123");
        assert_eq!(rendered["text"], "New event created");
    }

    #[test]
    fn extracts_placeholders_once() {
        let placeholders =
            collect_placeholders("{{message.id}} -> {{message.id}} -> {{event.type}}");
        assert_eq!(
            placeholders,
            vec!["message.id".to_string(), "event.type".to_string()]
        );
    }

    #[test]
    fn derives_project_id_from_pubsub_resource_names() {
        let topic_project =
            google_project_from_resource_name("topics", "projects/demo-project/topics/demo-topic");
        let subscription_project = google_project_from_resource_name(
            "subscriptions",
            "projects/demo-project/subscriptions/demo-sub",
        );
        assert_eq!(topic_project.as_deref(), Some("demo-project"));
        assert_eq!(subscription_project.as_deref(), Some("demo-project"));
    }

    #[test]
    fn splits_csv_fields() {
        let values = split_csv_field(Some("INBOX, Label_1\nLabel_2"));
        assert_eq!(values, vec!["INBOX", "Label_1", "Label_2"]);
    }

    #[test]
    fn calculates_gmail_renewal_window() {
        let renew_at = calculate_gmail_renew_at("2026-03-08T12:00:00Z").expect("renew_at");
        assert_eq!(renew_at, "2026-03-08T11:00:00+00:00");
    }
}
