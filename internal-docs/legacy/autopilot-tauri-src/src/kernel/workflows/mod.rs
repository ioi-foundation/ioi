mod commands;
mod types;

use crate::kernel::notifications::upsert_assistant_notification_record;
use crate::kernel::state::now;
use crate::models::{
    AssistantNotificationClass, AssistantNotificationRecord, NotificationDeliveryState,
    NotificationPrivacy, NotificationRail, NotificationSeverity, NotificationSource,
    ObservationTier,
};
use ioi_crypto::algorithms::hash::sha256;
use reqwest::Client;
use scraper::{Html, Selector};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tauri::{AppHandle, Emitter, Runtime, State};
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::JoinHandle;
use tokio::time::{sleep, Duration};
use url::Url;
use uuid::Uuid;

pub use commands::*;
pub use types::*;
use types::{WorkflowRegistry, WorkflowRegistryRecord};

const AUTOMATION_ROOT_DIR: &str = "automation";
const AUTOMATION_REGISTRY_FILE: &str = "workflow_registry.json";
const AUTOMATION_SPEC_VERSION: &str = "workflow.v1";
const AUTOMATION_REGISTRY_VERSION: u32 = 1;
const AUTOMATION_STATE_VERSION: u32 = 1;
const AUTOMATION_RECEIPT_VERSION: u32 = 1;
const AUTOMATION_EVENT_NAME: &str = "automation-workflows-changed";
const AUTOMATION_RUN_EVENT_NAME: &str = "automation-workflow-run";
const WORKFLOW_TRIGGER_INTERVAL: &str = "interval";
const WORKFLOW_TRIGGER_REMOTE: &str = "remote";
const WORKFLOW_TRIGGER_WAIT_UNTIL: &str = "wait_until";
const HACKER_NEWS_FRONT_PAGE_URL: &str = "https://news.ycombinator.com/";
const HACKER_NEWS_SOURCE_KIND: &str = "hacker_news_front_page";
const HACKER_NEWS_FIXTURE_SOURCE_KIND: &str = "hacker_news_front_page_fixture";
const HACKER_NEWS_EXTRACTOR_KIND: &str = "hacker_news_front_page_titles";
const CONTAINS_ANY_PREDICATE_KIND: &str = "contains_any_title";
const ASSISTANT_NOTIFICATION_SINK_KIND: &str = "assistant_notification";
const SEEN_KEY_LIMIT: usize = 1024;
const RUN_RECEIPT_LIMIT: usize = 50;
#[derive(Debug, Clone)]
struct ExtractedHeadline {
    title: String,
    href: String,
    state_key: String,
}

#[derive(Debug, Clone)]
struct RunOutcome {
    matched_titles: Vec<String>,
    match_count: usize,
    emitted_notification_ids: Vec<String>,
    emitted_count: usize,
    suppressed_count: usize,
    total_titles: usize,
}

struct WorkflowManagerInner {
    registry: WorkflowRegistry,
    workers: HashMap<String, JoinHandle<()>>,
    run_locks: HashMap<String, Arc<AsyncMutex<()>>>,
}

impl Default for WorkflowManagerInner {
    fn default() -> Self {
        Self {
            registry: WorkflowRegistry {
                version: AUTOMATION_REGISTRY_VERSION,
                workflows: Vec::new(),
            },
            workers: HashMap::new(),
            run_locks: HashMap::new(),
        }
    }
}

pub struct WorkflowManager<R: Runtime = tauri::Wry> {
    app: AppHandle<R>,
    root_dir: Arc<PathBuf>,
    client: Client,
    inner: Arc<AsyncMutex<WorkflowManagerInner>>,
}

impl<R: Runtime> Clone for WorkflowManager<R> {
    fn clone(&self) -> Self {
        Self {
            app: self.app.clone(),
            root_dir: self.root_dir.clone(),
            client: self.client.clone(),
            inner: self.inner.clone(),
        }
    }
}

fn normalize_optional_text(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn interval_seconds_for_trigger(trigger: &WorkflowTrigger) -> u64 {
    if trigger.trigger_type == WORKFLOW_TRIGGER_INTERVAL {
        trigger.every_seconds.max(60)
    } else {
        0
    }
}

fn next_run_at_ms_for_trigger(trigger: &WorkflowTrigger, scheduled_at_ms: u64) -> Option<u64> {
    match trigger.trigger_type.as_str() {
        WORKFLOW_TRIGGER_INTERVAL => Some(scheduled_at_ms),
        WORKFLOW_TRIGGER_WAIT_UNTIL => trigger.wait_until_ms,
        WORKFLOW_TRIGGER_REMOTE => None,
        _ => None,
    }
}

fn trigger_metadata(trigger: &WorkflowTrigger) -> (String, String, Option<String>, Option<u64>) {
    let kind = trigger.trigger_type.trim().to_string();
    let remote_trigger_id = normalize_optional_text(trigger.remote_trigger_id.clone());
    let wait_until_ms = trigger.wait_until_ms;
    let label = match kind.as_str() {
        WORKFLOW_TRIGGER_INTERVAL => format!("Every {}s", trigger.every_seconds.max(60)),
        WORKFLOW_TRIGGER_REMOTE => remote_trigger_id
            .as_ref()
            .map(|value| format!("Remote trigger {}", value))
            .unwrap_or_else(|| "Remote trigger".to_string()),
        WORKFLOW_TRIGGER_WAIT_UNTIL => wait_until_ms
            .map(|value| format!("Wait until {}", value))
            .unwrap_or_else(|| "Wait until".to_string()),
        _ => "Workflow trigger".to_string(),
    };
    (kind, label, remote_trigger_id, wait_until_ms)
}

fn trigger_kind_for_record(record: &WorkflowRegistryRecord) -> String {
    if record.trigger_kind.trim().is_empty() {
        WORKFLOW_TRIGGER_INTERVAL.to_string()
    } else {
        record.trigger_kind.clone()
    }
}

fn trigger_label_for_record(record: &WorkflowRegistryRecord) -> String {
    if !record.trigger_label.trim().is_empty() {
        return record.trigger_label.clone();
    }

    match trigger_kind_for_record(record).as_str() {
        WORKFLOW_TRIGGER_INTERVAL => format!("Every {}s", record.poll_interval_seconds.max(60)),
        WORKFLOW_TRIGGER_REMOTE => record
            .remote_trigger_id
            .as_ref()
            .map(|value| format!("Remote trigger {}", value))
            .unwrap_or_else(|| "Remote trigger".to_string()),
        WORKFLOW_TRIGGER_WAIT_UNTIL => record
            .wait_until_ms
            .map(|value| format!("Wait until {}", value))
            .unwrap_or_else(|| "Wait until".to_string()),
        _ => "Workflow trigger".to_string(),
    }
}

impl<R: Runtime + 'static> WorkflowManager<R> {
    pub fn new(app: AppHandle<R>, root_dir: PathBuf) -> Self {
        let registry =
            load_json::<WorkflowRegistry>(&registry_path_for(&root_dir)).unwrap_or_else(|_| {
                WorkflowRegistry {
                    version: AUTOMATION_REGISTRY_VERSION,
                    workflows: Vec::new(),
                }
            });
        Self {
            app,
            root_dir: Arc::new(root_dir),
            client: Client::new(),
            inner: Arc::new(AsyncMutex::new(WorkflowManagerInner {
                registry,
                workers: HashMap::new(),
                run_locks: HashMap::new(),
            })),
        }
    }

    pub async fn bootstrap(&self) -> Result<(), String> {
        ensure_runtime_dirs(&self.root_dir)?;
        let active_workflow_ids = {
            let inner = self.inner.lock().await;
            inner
                .registry
                .workflows
                .iter()
                .filter(|record| {
                    matches!(
                        record.status,
                        WorkflowStatus::Active | WorkflowStatus::Degraded
                    )
                })
                .map(|record| record.workflow_id.clone())
                .collect::<Vec<_>>()
        };
        for workflow_id in active_workflow_ids {
            self.spawn_worker_if_needed(&workflow_id).await?;
        }
        self.emit_change().await;
        Ok(())
    }

    pub async fn sync_from_disk(&self) -> Result<(), String> {
        ensure_runtime_dirs(&self.root_dir)?;
        let registry = load_json::<WorkflowRegistry>(&registry_path_for(&self.root_dir))
            .unwrap_or_else(|_| WorkflowRegistry {
                version: AUTOMATION_REGISTRY_VERSION,
                workflows: Vec::new(),
            });
        let desired_active = registry
            .workflows
            .iter()
            .filter(|record| {
                matches!(
                    record.status,
                    WorkflowStatus::Active | WorkflowStatus::Degraded
                )
            })
            .map(|record| record.workflow_id.clone())
            .collect::<HashSet<_>>();

        let to_spawn = {
            let mut inner = self.inner.lock().await;
            let existing_worker_ids = inner.workers.keys().cloned().collect::<Vec<_>>();
            for workflow_id in existing_worker_ids {
                if !desired_active.contains(&workflow_id) {
                    if let Some(handle) = inner.workers.remove(&workflow_id) {
                        handle.abort();
                    }
                }
            }
            inner.registry = registry;
            inner
                .registry
                .workflows
                .iter()
                .filter(|record| {
                    matches!(
                        record.status,
                        WorkflowStatus::Active | WorkflowStatus::Degraded
                    )
                })
                .filter_map(|record| {
                    let workflow_id = record.workflow_id.clone();
                    let worker_running = inner
                        .workers
                        .get(&workflow_id)
                        .map(|handle| !handle.is_finished())
                        .unwrap_or(false);
                    (!worker_running).then_some(workflow_id)
                })
                .collect::<Vec<_>>()
        };

        for workflow_id in to_spawn {
            self.spawn_worker_if_needed(&workflow_id).await?;
        }
        self.emit_change().await;
        Ok(())
    }

    pub async fn install_workflow(
        &self,
        artifact: WorkflowArtifact,
        authoring_tool_override: Option<&str>,
    ) -> Result<InstalledWorkflowSummary, String> {
        validate_artifact(&artifact)?;
        ensure_runtime_dirs(&self.root_dir)?;

        let installed_at_ms = now();
        let artifact_hash = json_sha256_hex(&artifact)?;
        let policy_hash = json_sha256_hex(&artifact.policy)?;
        let artifact_path = artifact_path_for(&self.root_dir, &artifact.workflow_id);
        write_json_atomic(&artifact_path, &artifact)?;

        let state = WorkflowRuntimeState {
            schema_version: AUTOMATION_STATE_VERSION,
            workflow_id: artifact.workflow_id.clone(),
            cursor: artifact.state_schema.cursor.clone(),
            seen_keys: artifact.state_schema.seen_keys.clone(),
            last_run_ms: artifact.state_schema.last_run_ms,
            last_success_ms: artifact.state_schema.last_success_ms,
            last_emission_hash: artifact.state_schema.last_emission_hash.clone(),
            updated_at_ms: installed_at_ms,
            failure_count: 0,
        };
        write_json_atomic(
            &state_path_for(&self.root_dir, &artifact.workflow_id),
            &state,
        )?;

        let mut inner = self.inner.lock().await;
        let next_run_at_ms = next_run_at_ms_for_trigger(&artifact.trigger, installed_at_ms);
        let (trigger_kind, trigger_label, remote_trigger_id, wait_until_ms) =
            trigger_metadata(&artifact.trigger);
        let summary = if let Some(existing) = inner
            .registry
            .workflows
            .iter_mut()
            .find(|record| record.workflow_id == artifact.workflow_id)
        {
            existing.kind = artifact.kind.clone();
            existing.status = WorkflowStatus::Active;
            existing.trigger_kind = trigger_kind.clone();
            existing.trigger_label = trigger_label.clone();
            existing.remote_trigger_id = remote_trigger_id.clone();
            existing.wait_until_ms = wait_until_ms;
            existing.title = artifact.title.clone();
            existing.description = artifact.description.clone();
            existing.artifact_hash = artifact_hash.clone();
            existing.spec_version = artifact.spec_version.clone();
            existing.artifact_path = artifact_path.to_string_lossy().to_string();
            existing.poll_interval_seconds = interval_seconds_for_trigger(&artifact.trigger);
            existing.source_label = artifact.monitor.source.url.clone();
            existing.keywords = artifact.monitor.predicate.keywords.clone();
            existing.updated_at_ms = installed_at_ms;
            existing.next_run_at_ms = next_run_at_ms;
            existing.last_error = None;
            summary_from_record(existing)
        } else {
            let record = WorkflowRegistryRecord {
                workflow_id: artifact.workflow_id.clone(),
                kind: artifact.kind.clone(),
                status: WorkflowStatus::Active,
                trigger_kind,
                trigger_label,
                remote_trigger_id,
                wait_until_ms,
                title: artifact.title.clone(),
                description: artifact.description.clone(),
                artifact_hash: artifact_hash.clone(),
                spec_version: artifact.spec_version.clone(),
                artifact_path: artifact_path.to_string_lossy().to_string(),
                poll_interval_seconds: interval_seconds_for_trigger(&artifact.trigger),
                source_label: artifact.monitor.source.url.clone(),
                keywords: artifact.monitor.predicate.keywords.clone(),
                installed_at_ms,
                updated_at_ms: installed_at_ms,
                next_run_at_ms,
                last_run_at_ms: None,
                last_success_at_ms: None,
                last_error: None,
                last_run_id: None,
                run_count: 0,
                failure_count: 0,
            };
            inner.registry.workflows.push(record.clone());
            summary_from_record(&record)
        };
        persist_registry(&self.root_dir, &inner.registry)?;
        drop(inner);

        let install_receipt = WorkflowInstallReceipt {
            receipt_version: AUTOMATION_RECEIPT_VERSION,
            workflow_id: artifact.workflow_id.clone(),
            installed_at_ms,
            artifact_hash,
            policy_hash,
            authoring_tool: authoring_tool_override
                .map(ToString::to_string)
                .unwrap_or_else(|| artifact.provenance.authoring_tool.clone()),
            trigger_kind: artifact.trigger.trigger_type.clone(),
            valid: true,
        };
        append_install_receipt(&self.root_dir, &artifact.workflow_id, &install_receipt)?;

        self.spawn_worker_if_needed(&artifact.workflow_id).await?;
        self.emit_change().await;
        Ok(summary)
    }

    pub async fn list_workflows(&self) -> Result<Vec<InstalledWorkflowSummary>, String> {
        let inner = self.inner.lock().await;
        let mut items = inner
            .registry
            .workflows
            .iter()
            .map(summary_from_record)
            .collect::<Vec<_>>();
        items.sort_by(|left, right| right.updated_at_ms.cmp(&left.updated_at_ms));
        Ok(items)
    }

    pub async fn get_workflow(
        &self,
        workflow_id: &str,
    ) -> Result<Option<InstalledWorkflowDetail>, String> {
        let record = self.get_record(workflow_id).await?;
        let Some(record) = record else {
            return Ok(None);
        };
        let artifact = self.load_artifact(workflow_id)?;
        let state = self.load_state(workflow_id)?;
        let recent_receipts = load_recent_run_receipts(&self.root_dir, workflow_id)?;
        Ok(Some(InstalledWorkflowDetail {
            summary: summary_from_record(&record),
            artifact,
            state,
            recent_receipts,
        }))
    }

    pub async fn pause_workflow(
        &self,
        workflow_id: &str,
    ) -> Result<InstalledWorkflowSummary, String> {
        let mut inner = self.inner.lock().await;
        if let Some(handle) = inner.workers.remove(workflow_id) {
            handle.abort();
        }
        let record = inner
            .registry
            .workflows
            .iter_mut()
            .find(|record| record.workflow_id == workflow_id)
            .ok_or_else(|| format!("Unknown workflow '{}'.", workflow_id))?;
        record.status = WorkflowStatus::Paused;
        record.updated_at_ms = now();
        record.next_run_at_ms = None;
        let summary = summary_from_record(record);
        persist_registry(&self.root_dir, &inner.registry)?;
        drop(inner);
        self.emit_change().await;
        Ok(summary)
    }

    pub async fn resume_workflow(
        &self,
        workflow_id: &str,
    ) -> Result<InstalledWorkflowSummary, String> {
        let artifact = self.load_artifact(workflow_id)?;
        let resumed_at_ms = now();
        let mut inner = self.inner.lock().await;
        let record = inner
            .registry
            .workflows
            .iter_mut()
            .find(|record| record.workflow_id == workflow_id)
            .ok_or_else(|| format!("Unknown workflow '{}'.", workflow_id))?;
        record.status = WorkflowStatus::Active;
        record.last_error = None;
        record.updated_at_ms = resumed_at_ms;
        record.next_run_at_ms = next_run_at_ms_for_trigger(&artifact.trigger, resumed_at_ms);
        let summary = summary_from_record(record);
        persist_registry(&self.root_dir, &inner.registry)?;
        drop(inner);
        self.spawn_worker_if_needed(workflow_id).await?;
        self.emit_change().await;
        Ok(summary)
    }

    pub async fn delete_workflow(
        &self,
        workflow_id: &str,
    ) -> Result<InstalledWorkflowSummary, String> {
        let mut inner = self.inner.lock().await;
        if let Some(handle) = inner.workers.remove(workflow_id) {
            handle.abort();
        }
        let index = inner
            .registry
            .workflows
            .iter()
            .position(|record| record.workflow_id == workflow_id)
            .ok_or_else(|| format!("Unknown workflow '{}'.", workflow_id))?;
        let removed = inner.registry.workflows.remove(index);
        inner.run_locks.remove(workflow_id);
        persist_registry(&self.root_dir, &inner.registry)?;
        drop(inner);

        remove_if_exists(&artifact_path_for(&self.root_dir, workflow_id))?;
        remove_if_exists(&state_path_for(&self.root_dir, workflow_id))?;
        remove_dir_if_exists(&receipt_dir_for(&self.root_dir, workflow_id))?;

        self.emit_change().await;
        Ok(summary_from_record(&removed))
    }

    pub async fn run_workflow_now(&self, workflow_id: &str) -> Result<WorkflowRunReceipt, String> {
        self.execute_workflow(workflow_id, "manual", None, None)
            .await
    }

    pub async fn trigger_workflow_remote(
        &self,
        workflow_id: &str,
        idempotency_key: Option<String>,
        payload: Option<Value>,
    ) -> Result<WorkflowRunReceipt, String> {
        let idempotency_key = normalize_optional_text(idempotency_key)
            .ok_or_else(|| "Remote workflow triggers require an idempotency key.".to_string())?;
        let artifact = self.load_artifact(workflow_id)?;
        if artifact.trigger.trigger_type != WORKFLOW_TRIGGER_REMOTE {
            return Err(format!(
                "Workflow '{}' is not configured for remote triggers.",
                workflow_id
            ));
        }

        self.execute_workflow(
            workflow_id,
            WORKFLOW_TRIGGER_REMOTE,
            Some(idempotency_key),
            payload,
        )
        .await
    }

    pub async fn export_project(&self, workflow_id: &str) -> Result<WorkflowProjectFile, String> {
        let artifact = self.load_artifact(workflow_id)?;
        Ok(project_from_artifact(&artifact))
    }

    pub async fn import_workflow_from_artifact_path(
        &self,
        artifact_path: &Path,
    ) -> Result<InstalledWorkflowSummary, String> {
        let artifact = load_json::<WorkflowArtifact>(artifact_path)?;
        self.install_workflow(artifact, None).await
    }

    async fn spawn_worker_if_needed(&self, workflow_id: &str) -> Result<(), String> {
        let mut inner = self.inner.lock().await;
        let Some(record) = inner
            .registry
            .workflows
            .iter()
            .find(|record| record.workflow_id == workflow_id)
            .cloned()
        else {
            return Err(format!("Unknown workflow '{}'.", workflow_id));
        };
        if trigger_kind_for_record(&record) == WORKFLOW_TRIGGER_REMOTE {
            inner.workers.remove(workflow_id);
            return Ok(());
        }
        if inner
            .workers
            .get(workflow_id)
            .map(|handle| !handle.is_finished())
            .unwrap_or(false)
        {
            return Ok(());
        }
        let manager = self.clone();
        let worker_workflow_id = workflow_id.to_string();
        let handle = tokio::spawn(async move {
            manager.worker_loop(worker_workflow_id).await;
        });
        inner.workers.insert(workflow_id.to_string(), handle);
        Ok(())
    }

    async fn worker_loop(&self, workflow_id: String) {
        loop {
            let record = match self.get_record(&workflow_id).await {
                Ok(Some(record)) => record,
                _ => break,
            };
            if !matches!(
                record.status,
                WorkflowStatus::Active | WorkflowStatus::Degraded
            ) {
                break;
            }
            if trigger_kind_for_record(&record) == WORKFLOW_TRIGGER_REMOTE {
                break;
            }

            let Some(next_run_at_ms) = record.next_run_at_ms else {
                break;
            };
            let wait_ms = next_run_at_ms.saturating_sub(now());
            if wait_ms > 0 {
                sleep(Duration::from_millis(wait_ms)).await;
            }

            let trigger_kind = trigger_kind_for_record(&record);
            if let Err(error) = self
                .execute_workflow(&workflow_id, trigger_kind.as_str(), None, None)
                .await
            {
                eprintln!(
                    "[Autopilot] Workflow '{}' execution failed: {}",
                    workflow_id, error
                );
            }
        }

        let mut inner = self.inner.lock().await;
        inner.workers.remove(&workflow_id);
    }

    async fn execute_workflow(
        &self,
        workflow_id: &str,
        trigger_kind: &str,
        idempotency_key: Option<String>,
        remote_payload: Option<Value>,
    ) -> Result<WorkflowRunReceipt, String> {
        let run_lock = self.run_lock_for(workflow_id).await;
        let _guard = run_lock.lock().await;

        let record = self
            .get_record(workflow_id)
            .await?
            .ok_or_else(|| format!("Unknown workflow '{}'.", workflow_id))?;
        let artifact = self.load_artifact(workflow_id)?;
        let mut state = self.load_state(workflow_id)?;
        let run_id = Uuid::new_v4().to_string();
        let started_at_ms = now();

        let execution = self.run_monitor(&artifact, &mut state, &run_id).await;
        let completed_at_ms = now();
        let trigger_kind_value = artifact.trigger.trigger_type.clone();
        let next_run_at_ms = match trigger_kind_value.as_str() {
            WORKFLOW_TRIGGER_INTERVAL => Some(
                completed_at_ms
                    .saturating_add(artifact.trigger.every_seconds.max(60).saturating_mul(1000)),
            ),
            WORKFLOW_TRIGGER_REMOTE => None,
            WORKFLOW_TRIGGER_WAIT_UNTIL => None,
            _ => None,
        };
        let post_success_status = if trigger_kind_value == WORKFLOW_TRIGGER_WAIT_UNTIL {
            WorkflowStatus::Paused
        } else {
            WorkflowStatus::Active
        };

        let receipt = match execution {
            Ok(outcome) => {
                state.last_run_ms = Some(completed_at_ms);
                state.last_success_ms = Some(completed_at_ms);
                state.updated_at_ms = completed_at_ms;
                write_json_atomic(&state_path_for(&self.root_dir, workflow_id), &state)?;

                self.update_record(workflow_id, |record| {
                    record.status = post_success_status.clone();
                    record.last_error = None;
                    record.updated_at_ms = completed_at_ms;
                    record.last_run_at_ms = Some(completed_at_ms);
                    record.last_success_at_ms = Some(completed_at_ms);
                    record.last_run_id = Some(run_id.clone());
                    record.next_run_at_ms = next_run_at_ms;
                    record.run_count = record.run_count.saturating_add(1);
                })
                .await?;

                WorkflowRunReceipt {
                    receipt_version: AUTOMATION_RECEIPT_VERSION,
                    workflow_id: workflow_id.to_string(),
                    run_id,
                    trigger_kind: trigger_kind.to_string(),
                    status: "success".to_string(),
                    started_at_ms,
                    completed_at_ms,
                    artifact_hash: record.artifact_hash.clone(),
                    idempotency_key: idempotency_key.clone(),
                    settlement_refs: Vec::new(),
                    projection_only: true,
                    simulation_only: false,
                    workflow_status: post_success_status,
                    next_run_at_ms,
                    observation: json!({
                        "sourceUrl": artifact.monitor.source.url,
                        "triggerType": trigger_kind_value,
                        "totalTitles": outcome.total_titles,
                        "matchCount": outcome.match_count,
                        "matchedTitles": outcome.matched_titles,
                        "emittedCount": outcome.emitted_count,
                        "suppressedCount": outcome.suppressed_count,
                        "remotePayload": remote_payload,
                    }),
                    notification_ids: outcome.emitted_notification_ids,
                    error: None,
                }
            }
            Err(error) => {
                state.last_run_ms = Some(completed_at_ms);
                state.updated_at_ms = completed_at_ms;
                state.failure_count = state.failure_count.saturating_add(1);
                write_json_atomic(&state_path_for(&self.root_dir, workflow_id), &state)?;

                self.update_record(workflow_id, |record| {
                    record.status = WorkflowStatus::Degraded;
                    record.last_error = Some(error.clone());
                    record.updated_at_ms = completed_at_ms;
                    record.last_run_at_ms = Some(completed_at_ms);
                    record.last_run_id = Some(run_id.clone());
                    record.next_run_at_ms = next_run_at_ms;
                    record.run_count = record.run_count.saturating_add(1);
                    record.failure_count = record.failure_count.saturating_add(1);
                })
                .await?;

                WorkflowRunReceipt {
                    receipt_version: AUTOMATION_RECEIPT_VERSION,
                    workflow_id: workflow_id.to_string(),
                    run_id,
                    trigger_kind: trigger_kind.to_string(),
                    status: "error".to_string(),
                    started_at_ms,
                    completed_at_ms,
                    artifact_hash: record.artifact_hash.clone(),
                    idempotency_key: idempotency_key.clone(),
                    settlement_refs: Vec::new(),
                    projection_only: true,
                    simulation_only: false,
                    workflow_status: WorkflowStatus::Degraded,
                    next_run_at_ms,
                    observation: json!({
                        "sourceUrl": artifact.monitor.source.url,
                        "triggerType": trigger_kind_value,
                        "remotePayload": remote_payload,
                    }),
                    notification_ids: Vec::new(),
                    error: Some(error),
                }
            }
        };

        append_run_receipt(&self.root_dir, workflow_id, &receipt)?;
        self.emit_run(receipt.clone()).await;
        self.emit_change().await;
        if receipt.status == "success" {
            Ok(receipt)
        } else {
            Err(receipt
                .error
                .clone()
                .unwrap_or_else(|| "workflow run failed".to_string()))
        }
    }

    async fn run_monitor(
        &self,
        artifact: &WorkflowArtifact,
        state: &mut WorkflowRuntimeState,
        run_id: &str,
    ) -> Result<RunOutcome, String> {
        validate_artifact(artifact)?;
        let html = load_monitored_html(&artifact.monitor.source, &self.client).await?;
        let headlines = extract_hacker_news_titles(&html)?;
        let matched = filter_matching_titles(&headlines, &artifact.monitor.predicate)?;
        let total_match_count = matched.len();
        let seen = state.seen_keys.iter().cloned().collect::<HashSet<_>>();
        let new_matches = matched
            .iter()
            .filter(|item| !seen.contains(&item.state_key))
            .cloned()
            .collect::<Vec<_>>();
        let suppressed_count = total_match_count.saturating_sub(new_matches.len());

        let notification_ids = new_matches
            .iter()
            .map(|item| {
                let notification_id = Uuid::new_v4().to_string();
                let record = AssistantNotificationRecord {
                    item_id: notification_id.clone(),
                    rail: NotificationRail::Assistant,
                    notification_class: AssistantNotificationClass::Digest,
                    severity: NotificationSeverity::Informational,
                    title: format!("Hacker News match: {}", item.title),
                    summary: item.href.clone(),
                    reason: Some(format!(
                        "The installed monitor matched '{}' on the Hacker News front page.",
                        item.title
                    )),
                    recommended_action: Some(
                        "Open the story link and inspect the front page context.".to_string(),
                    ),
                    consequence_if_ignored: Some(
                        "Relevant front-page stories can fall off the page before you see them."
                            .to_string(),
                    ),
                    created_at_ms: now(),
                    updated_at_ms: now(),
                    dedupe_key: format!("workflow:{}:{}", artifact.workflow_id, item.state_key),
                    workflow_id: Some(artifact.workflow_id.clone()),
                    run_id: Some(run_id.to_string()),
                    delivery_state: NotificationDeliveryState {
                        toast_sent: false,
                        inbox_visible: true,
                        badge_counted: true,
                        pill_visible: true,
                        last_toast_at_ms: None,
                    },
                    privacy: NotificationPrivacy {
                        preview_mode: crate::models::NotificationPreviewMode::Compact,
                        contains_sensitive_data: false,
                        observation_tier: ObservationTier::WorkflowState,
                    },
                    source: NotificationSource {
                        service_name: "Hacker News".to_string(),
                        workflow_name: artifact.title.clone(),
                        step_name: "notification.send".to_string(),
                    },
                    ..AssistantNotificationRecord::default()
                };
                upsert_assistant_notification_record(&self.app, record);
                notification_id
            })
            .collect::<Vec<_>>();

        for item in new_matches.iter() {
            state.seen_keys.push(item.state_key.clone());
        }
        dedupe_seen_keys(&mut state.seen_keys);
        state.last_emission_hash = if new_matches.is_empty() {
            state.last_emission_hash.clone()
        } else {
            Some(hash_strings_hex(
                &new_matches
                    .iter()
                    .map(|item| item.state_key.clone())
                    .collect::<Vec<_>>(),
            )?)
        };

        Ok(RunOutcome {
            matched_titles: matched.into_iter().map(|item| item.title).collect(),
            match_count: total_match_count,
            emitted_notification_ids: notification_ids.clone(),
            emitted_count: notification_ids.len(),
            suppressed_count,
            total_titles: headlines.len(),
        })
    }

    async fn get_record(
        &self,
        workflow_id: &str,
    ) -> Result<Option<WorkflowRegistryRecord>, String> {
        let inner = self.inner.lock().await;
        Ok(inner
            .registry
            .workflows
            .iter()
            .find(|record| record.workflow_id == workflow_id)
            .cloned())
    }

    async fn update_record<F>(&self, workflow_id: &str, mut f: F) -> Result<(), String>
    where
        F: FnMut(&mut WorkflowRegistryRecord),
    {
        let mut inner = self.inner.lock().await;
        let record = inner
            .registry
            .workflows
            .iter_mut()
            .find(|record| record.workflow_id == workflow_id)
            .ok_or_else(|| format!("Unknown workflow '{}'.", workflow_id))?;
        f(record);
        persist_registry(&self.root_dir, &inner.registry)?;
        Ok(())
    }

    async fn run_lock_for(&self, workflow_id: &str) -> Arc<AsyncMutex<()>> {
        let mut inner = self.inner.lock().await;
        inner
            .run_locks
            .entry(workflow_id.to_string())
            .or_insert_with(|| Arc::new(AsyncMutex::new(())))
            .clone()
    }

    fn load_artifact(&self, workflow_id: &str) -> Result<WorkflowArtifact, String> {
        load_json(&artifact_path_for(&self.root_dir, workflow_id))
    }

    fn load_state(&self, workflow_id: &str) -> Result<WorkflowRuntimeState, String> {
        if !state_path_for(&self.root_dir, workflow_id).exists() {
            return Ok(WorkflowRuntimeState {
                schema_version: AUTOMATION_STATE_VERSION,
                workflow_id: workflow_id.to_string(),
                ..WorkflowRuntimeState::default()
            });
        }
        load_json(&state_path_for(&self.root_dir, workflow_id))
    }

    async fn emit_change(&self) {
        if let Ok(items) = self.list_workflows().await {
            let _ = self.app.emit(AUTOMATION_EVENT_NAME, items);
        }
    }

    async fn emit_run(&self, receipt: WorkflowRunReceipt) {
        let _ = self.app.emit(AUTOMATION_RUN_EVENT_NAME, receipt);
    }
}

pub fn root_path_for(data_dir: &Path) -> PathBuf {
    data_dir.join(AUTOMATION_ROOT_DIR)
}

pub fn registry_path_for(root_dir: &Path) -> PathBuf {
    root_dir.join(AUTOMATION_REGISTRY_FILE)
}

fn artifacts_dir_for(root_dir: &Path) -> PathBuf {
    root_dir.join("artifacts")
}

fn states_dir_for(root_dir: &Path) -> PathBuf {
    root_dir.join("state")
}

fn receipts_root_for(root_dir: &Path) -> PathBuf {
    root_dir.join("receipts")
}

fn receipt_dir_for(root_dir: &Path, workflow_id: &str) -> PathBuf {
    receipts_root_for(root_dir).join(workflow_id)
}

fn artifact_path_for(root_dir: &Path, workflow_id: &str) -> PathBuf {
    artifacts_dir_for(root_dir).join(format!("{}.json", workflow_id))
}

fn state_path_for(root_dir: &Path, workflow_id: &str) -> PathBuf {
    states_dir_for(root_dir).join(format!("{}.json", workflow_id))
}

fn ensure_runtime_dirs(root_dir: &Path) -> Result<(), String> {
    fs::create_dir_all(root_dir).map_err(|error| error.to_string())?;
    fs::create_dir_all(artifacts_dir_for(root_dir)).map_err(|error| error.to_string())?;
    fs::create_dir_all(states_dir_for(root_dir)).map_err(|error| error.to_string())?;
    fs::create_dir_all(receipts_root_for(root_dir)).map_err(|error| error.to_string())?;
    Ok(())
}

fn persist_registry(root_dir: &Path, registry: &WorkflowRegistry) -> Result<(), String> {
    write_json_atomic(&registry_path_for(root_dir), registry)
}

fn summary_from_record(record: &WorkflowRegistryRecord) -> InstalledWorkflowSummary {
    InstalledWorkflowSummary {
        workflow_id: record.workflow_id.clone(),
        kind: record.kind.clone(),
        status: record.status.clone(),
        trigger_kind: trigger_kind_for_record(record),
        trigger_label: trigger_label_for_record(record),
        remote_trigger_id: record.remote_trigger_id.clone(),
        wait_until_ms: record.wait_until_ms,
        title: record.title.clone(),
        description: record.description.clone(),
        artifact_hash: record.artifact_hash.clone(),
        spec_version: record.spec_version.clone(),
        poll_interval_seconds: record.poll_interval_seconds,
        source_label: record.source_label.clone(),
        keywords: record.keywords.clone(),
        installed_at_ms: record.installed_at_ms,
        updated_at_ms: record.updated_at_ms,
        next_run_at_ms: record.next_run_at_ms,
        last_run_at_ms: record.last_run_at_ms,
        last_success_at_ms: record.last_success_at_ms,
        last_error: record.last_error.clone(),
        run_count: record.run_count,
        failure_count: record.failure_count,
    }
}

fn write_json_atomic<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    let temp_path = path.with_extension("tmp");
    let bytes = serde_json::to_vec_pretty(value).map_err(|error| error.to_string())?;
    fs::write(&temp_path, bytes).map_err(|error| error.to_string())?;
    fs::rename(&temp_path, path).map_err(|error| error.to_string())?;
    Ok(())
}

fn load_json<T: DeserializeOwned>(path: &Path) -> Result<T, String> {
    let bytes = fs::read(path).map_err(|error| error.to_string())?;
    serde_json::from_slice(&bytes).map_err(|error| error.to_string())
}

fn remove_if_exists(path: &Path) -> Result<(), String> {
    if path.exists() {
        fs::remove_file(path).map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn remove_dir_if_exists(path: &Path) -> Result<(), String> {
    if path.exists() {
        fs::remove_dir_all(path).map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn append_install_receipt(
    root_dir: &Path,
    workflow_id: &str,
    receipt: &WorkflowInstallReceipt,
) -> Result<(), String> {
    let path = receipt_dir_for(root_dir, workflow_id).join("install.json");
    write_json_atomic(&path, receipt)
}

fn append_run_receipt(
    root_dir: &Path,
    workflow_id: &str,
    receipt: &WorkflowRunReceipt,
) -> Result<(), String> {
    let path = receipt_dir_for(root_dir, workflow_id).join(format!("{}.json", receipt.run_id));
    write_json_atomic(&path, receipt)?;
    prune_old_run_receipts(root_dir, workflow_id)
}

fn prune_old_run_receipts(root_dir: &Path, workflow_id: &str) -> Result<(), String> {
    let dir = receipt_dir_for(root_dir, workflow_id);
    fs::create_dir_all(&dir).map_err(|error| error.to_string())?;
    let mut items = fs::read_dir(&dir)
        .map_err(|error| error.to_string())?
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name() != "install.json")
        .filter_map(|entry| {
            let path = entry.path();
            let metadata = entry.metadata().ok()?;
            let modified = metadata.modified().ok()?;
            let modified_ms = modified
                .duration_since(std::time::UNIX_EPOCH)
                .ok()
                .map(|duration| duration.as_millis() as u64)
                .unwrap_or(0);
            Some((path, modified_ms))
        })
        .collect::<Vec<_>>();
    items.sort_by(|left, right| right.1.cmp(&left.1));
    for (path, _) in items.into_iter().skip(RUN_RECEIPT_LIMIT) {
        let _ = fs::remove_file(path);
    }
    Ok(())
}

fn load_recent_run_receipts(
    root_dir: &Path,
    workflow_id: &str,
) -> Result<Vec<WorkflowRunReceipt>, String> {
    let dir = receipt_dir_for(root_dir, workflow_id);
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut items = fs::read_dir(&dir)
        .map_err(|error| error.to_string())?
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name() != "install.json")
        .filter_map(|entry| {
            let path = entry.path();
            let receipt = load_json::<WorkflowRunReceipt>(&path).ok()?;
            Some(receipt)
        })
        .collect::<Vec<_>>();
    items.sort_by(|left, right| right.completed_at_ms.cmp(&left.completed_at_ms));
    items.truncate(RUN_RECEIPT_LIMIT);
    Ok(items)
}

fn normalize_monitored_url(raw: &str) -> Result<String, String> {
    let url = Url::parse(raw).map_err(|error| format!("Invalid workflow source URL: {}", error))?;
    Ok(url.to_string())
}

fn fixture_path_from_source_url(raw: &str) -> Result<PathBuf, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("Workflow fixture source URL cannot be empty.".to_string());
    }
    if trimmed.starts_with("file://") {
        let url = Url::parse(trimmed)
            .map_err(|error| format!("Invalid workflow fixture URL: {}", error))?;
        return url
            .to_file_path()
            .map_err(|_| format!("Workflow fixture URL '{}' is not a local file.", trimmed));
    }
    Ok(PathBuf::from(trimmed))
}

async fn load_monitored_html(source: &MonitorSource, client: &Client) -> Result<String, String> {
    match source.source_type.as_str() {
        HACKER_NEWS_SOURCE_KIND => {
            let normalized_url = normalize_monitored_url(&source.url)?;
            let response = client
                .get(normalized_url.clone())
                .send()
                .await
                .map_err(|error| format!("Failed to fetch monitored source: {}", error))?
                .error_for_status()
                .map_err(|error| format!("Monitored source returned an error status: {}", error))?;
            response
                .text()
                .await
                .map_err(|error| format!("Failed to read monitored source body: {}", error))
        }
        HACKER_NEWS_FIXTURE_SOURCE_KIND => {
            let path = fixture_path_from_source_url(&source.url)?;
            fs::read_to_string(&path).map_err(|error| {
                format!(
                    "Failed to read workflow fixture '{}': {}",
                    path.display(),
                    error
                )
            })
        }
        other => Err(format!("Unsupported workflow source '{}'.", other)),
    }
}

fn validate_artifact(artifact: &WorkflowArtifact) -> Result<(), String> {
    if artifact.spec_version != AUTOMATION_SPEC_VERSION {
        return Err(format!(
            "Unsupported workflow spec version '{}'.",
            artifact.spec_version
        ));
    }
    match artifact.trigger.trigger_type.as_str() {
        WORKFLOW_TRIGGER_INTERVAL => {
            if artifact.trigger.every_seconds < 60 {
                return Err("Workflow trigger interval must be at least 60 seconds.".to_string());
            }
        }
        WORKFLOW_TRIGGER_REMOTE => {
            if normalize_optional_text(artifact.trigger.remote_trigger_id.clone()).is_none() {
                return Err(
                    "Remote workflow triggers require a non-empty remote_trigger_id.".to_string(),
                );
            }
        }
        WORKFLOW_TRIGGER_WAIT_UNTIL => {
            if artifact.trigger.wait_until_ms.is_none() {
                return Err(
                    "Wait-until workflow triggers require a wait_until_ms timestamp.".to_string(),
                );
            }
        }
        other => {
            return Err(format!("Unsupported workflow trigger '{}'.", other));
        }
    }
    match artifact.monitor.source.source_type.as_str() {
        HACKER_NEWS_SOURCE_KIND => {
            if normalize_monitored_url(&artifact.monitor.source.url)? != HACKER_NEWS_FRONT_PAGE_URL
            {
                return Err(
                    "The current monitor runtime only supports the Hacker News front page URL."
                        .to_string(),
                );
            }
        }
        HACKER_NEWS_FIXTURE_SOURCE_KIND => {
            let path = fixture_path_from_source_url(&artifact.monitor.source.url)?;
            if !path.exists() {
                return Err(format!(
                    "Workflow fixture source '{}' does not exist.",
                    path.display()
                ));
            }
        }
        other => {
            return Err(format!("Unsupported workflow source '{}'.", other));
        }
    }
    if artifact.monitor.extractor.extractor_type != HACKER_NEWS_EXTRACTOR_KIND {
        return Err(format!(
            "Unsupported workflow extractor '{}'.",
            artifact.monitor.extractor.extractor_type
        ));
    }
    if artifact.monitor.predicate.predicate_type != CONTAINS_ANY_PREDICATE_KIND {
        return Err(format!(
            "Unsupported workflow predicate '{}'.",
            artifact.monitor.predicate.predicate_type
        ));
    }
    if artifact.monitor.predicate.keywords.is_empty() {
        return Err("Workflow predicates must include at least one keyword.".to_string());
    }
    if artifact.monitor.sink.sink_type != ASSISTANT_NOTIFICATION_SINK_KIND {
        return Err(format!(
            "Unsupported workflow sink '{}'.",
            artifact.monitor.sink.sink_type
        ));
    }
    let domain_allowed = artifact.policy.network_allowlist.iter().any(|entry| {
        let trimmed = entry.trim();
        trimmed.eq_ignore_ascii_case("news.ycombinator.com")
            || trimmed.eq_ignore_ascii_case("local_fixture")
    });
    if !domain_allowed {
        return Err(
            "Workflow policy must explicitly allow news.ycombinator.com or local_fixture."
                .to_string(),
        );
    }
    Ok(())
}

fn json_sha256_hex<T: Serialize>(value: &T) -> Result<String, String> {
    let bytes = serde_json::to_vec(value).map_err(|error| error.to_string())?;
    let digest = sha256(bytes).map_err(|error| error.to_string())?;
    Ok(hex::encode(digest))
}

fn hash_strings_hex(values: &[String]) -> Result<String, String> {
    let joined = values.join("|");
    let digest = sha256(joined.as_bytes()).map_err(|error| error.to_string())?;
    Ok(hex::encode(digest))
}

fn normalize_keywords(keywords: &[String]) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut normalized = keywords
        .iter()
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty())
        .filter(|value| seen.insert(value.clone()))
        .collect::<Vec<_>>();
    normalized.sort();
    normalized
}

fn monitor_workflow_id_from_keywords(keywords: &[String]) -> Result<String, String> {
    let digest = hash_strings_hex(
        &keywords
            .iter()
            .map(|value| value.to_ascii_lowercase())
            .collect::<Vec<_>>(),
    )?;
    Ok(format!("monitor_hacker_news_{}", &digest[..12]))
}

fn trigger_node_kind(trigger: &WorkflowTrigger) -> &'static str {
    match trigger.trigger_type.as_str() {
        WORKFLOW_TRIGGER_REMOTE => "trigger.remote",
        WORKFLOW_TRIGGER_WAIT_UNTIL => "trigger.wait_until",
        _ => "trigger.interval",
    }
}

fn trigger_node_config(trigger: &WorkflowTrigger) -> Value {
    match trigger.trigger_type.as_str() {
        WORKFLOW_TRIGGER_REMOTE => json!({
            "remoteTriggerId": trigger.remote_trigger_id,
        }),
        WORKFLOW_TRIGGER_WAIT_UNTIL => json!({
            "waitUntilMs": trigger.wait_until_ms,
        }),
        _ => json!({
            "everySeconds": trigger.every_seconds.max(60),
        }),
    }
}

fn project_trigger_name(trigger: &WorkflowTrigger) -> &'static str {
    match trigger.trigger_type.as_str() {
        WORKFLOW_TRIGGER_REMOTE => "Remote Trigger",
        WORKFLOW_TRIGGER_WAIT_UNTIL => "Durable Wait",
        _ => "Interval Trigger",
    }
}

fn project_trigger_logic(trigger: &WorkflowTrigger) -> Value {
    match trigger.trigger_type.as_str() {
        WORKFLOW_TRIGGER_REMOTE => json!({
            "remoteTriggerId": trigger.remote_trigger_id,
        }),
        WORKFLOW_TRIGGER_WAIT_UNTIL => json!({
            "waitUntilMs": trigger.wait_until_ms,
        }),
        _ => json!({
            "cronSchedule": format!("every {} seconds", trigger.every_seconds.max(60)),
        }),
    }
}

pub(crate) fn monitor_graph_for_keywords(
    keywords: &[String],
    trigger: &WorkflowTrigger,
    source_url: &str,
) -> WorkflowGraph {
    WorkflowGraph {
        nodes: vec![
            WorkflowNode {
                id: "trigger".to_string(),
                kind: trigger_node_kind(trigger).to_string(),
                config: trigger_node_config(trigger),
            },
            WorkflowNode {
                id: "fetch".to_string(),
                kind: "source.web.read".to_string(),
                config: json!({ "url": source_url }),
            },
            WorkflowNode {
                id: "extract".to_string(),
                kind: "extract.hacker_news_front_page".to_string(),
                config: json!({ "selector": "span.titleline > a" }),
            },
            WorkflowNode {
                id: "match".to_string(),
                kind: "predicate.contains_any".to_string(),
                config: json!({ "keywords": keywords }),
            },
            WorkflowNode {
                id: "dedupe".to_string(),
                kind: "state.seen_set".to_string(),
                config: json!({ "limit": SEEN_KEY_LIMIT }),
            },
            WorkflowNode {
                id: "notify".to_string(),
                kind: "sink.notification.send".to_string(),
                config: json!({ "rail": "assistant" }),
            },
        ],
        edges: vec![
            WorkflowEdge {
                from: "trigger".to_string(),
                to: "fetch".to_string(),
            },
            WorkflowEdge {
                from: "fetch".to_string(),
                to: "extract".to_string(),
            },
            WorkflowEdge {
                from: "extract".to_string(),
                to: "match".to_string(),
            },
            WorkflowEdge {
                from: "match".to_string(),
                to: "dedupe".to_string(),
            },
            WorkflowEdge {
                from: "dedupe".to_string(),
                to: "notify".to_string(),
            },
        ],
    }
}

fn project_from_artifact(artifact: &WorkflowArtifact) -> WorkflowProjectFile {
    let nodes = vec![
        json!({
            "id": "trigger",
            "type": "trigger",
            "name": project_trigger_name(&artifact.trigger),
            "x": 80,
            "y": 180,
            "config": { "logic": project_trigger_logic(&artifact.trigger), "law": {} },
            "outputs": ["out"],
        }),
        json!({
            "id": "fetch",
            "type": "web_read",
            "name": "Fetch Front Page",
            "x": 320,
            "y": 180,
            "config": { "logic": { "url": artifact.monitor.source.url, "max_chars": 20000 }, "law": { "networkAllowlist": artifact.policy.network_allowlist } },
            "outputs": ["out"],
        }),
        json!({
            "id": "extract",
            "type": "action",
            "name": "Extract Headlines",
            "x": 560,
            "y": 180,
            "config": { "logic": { "code": "extract Hacker News front-page title anchors", "language": "python" }, "law": {} },
            "outputs": ["out"],
        }),
        json!({
            "id": "match",
            "type": "gate",
            "name": "Match Keywords",
            "x": 800,
            "y": 180,
            "config": { "logic": { "conditionScript": format!("contains_any({:?})", artifact.monitor.predicate.keywords) }, "law": {} },
            "outputs": ["out"],
        }),
        json!({
            "id": "dedupe",
            "type": "action",
            "name": "Seen Set",
            "x": 1040,
            "y": 180,
            "config": { "logic": { "code": "persist dedupe keys in workflow state", "language": "python" }, "law": {} },
            "outputs": ["out"],
        }),
        json!({
            "id": "notify",
            "type": "tool",
            "name": "Assistant Notification",
            "x": 1280,
            "y": 180,
            "config": { "logic": { "tool_name": "notification.send", "arguments": { "rail": "assistant" } }, "law": {} },
            "outputs": ["out"],
        }),
    ];
    let edges = vec![
        json!({"id":"edge-trigger-fetch","from":"trigger","to":"fetch","fromPort":"out","toPort":"in","type":"control"}),
        json!({"id":"edge-fetch-extract","from":"fetch","to":"extract","fromPort":"out","toPort":"in","type":"data"}),
        json!({"id":"edge-extract-match","from":"extract","to":"match","fromPort":"out","toPort":"in","type":"data"}),
        json!({"id":"edge-match-dedupe","from":"match","to":"dedupe","fromPort":"out","toPort":"in","type":"data"}),
        json!({"id":"edge-dedupe-notify","from":"dedupe","to":"notify","fromPort":"out","toPort":"in","type":"data"}),
    ];
    WorkflowProjectFile {
        version: "1.0.0".to_string(),
        nodes,
        edges,
        global_config: json!({
            "env": "{}",
            "policy": {
                "maxBudget": 0.5,
                "maxSteps": 6,
                "timeoutMs": 30000,
            },
            "contract": {
                "developerBond": 0,
                "adjudicationRubric": "Installed automation workflow projection"
            },
            "meta": {
                "name": artifact.title,
                "description": artifact.description,
            }
        }),
    }
}

fn extract_hacker_news_titles(html: &str) -> Result<Vec<ExtractedHeadline>, String> {
    let document = Html::parse_document(html);
    let selector = Selector::parse("span.titleline > a")
        .map_err(|error| format!("Failed to parse workflow selector: {}", error))?;
    let base_url = Url::parse(HACKER_NEWS_FRONT_PAGE_URL)
        .map_err(|error| format!("Failed to parse workflow base URL: {}", error))?;
    let mut headlines = Vec::new();
    for anchor in document.select(&selector) {
        let title = anchor
            .text()
            .collect::<Vec<_>>()
            .join(" ")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        let href_raw = anchor
            .value()
            .attr("href")
            .map(str::trim)
            .unwrap_or_default()
            .to_string();
        if title.is_empty() || href_raw.is_empty() {
            continue;
        }
        let href = Url::parse(&href_raw)
            .or_else(|_| base_url.join(&href_raw))
            .map(|url| url.to_string())
            .unwrap_or(href_raw.clone());
        let state_key = if href.is_empty() {
            title.to_ascii_lowercase()
        } else {
            href.to_ascii_lowercase()
        };
        headlines.push(ExtractedHeadline {
            title,
            href,
            state_key,
        });
    }
    Ok(headlines)
}

fn filter_matching_titles(
    headlines: &[ExtractedHeadline],
    predicate: &MonitorPredicate,
) -> Result<Vec<ExtractedHeadline>, String> {
    let keywords = normalize_keywords(&predicate.keywords);
    if keywords.is_empty() {
        return Err("Monitor predicate has no keywords after normalization.".to_string());
    }
    Ok(headlines
        .iter()
        .filter(|headline| {
            let haystack = if predicate.case_sensitive {
                headline.title.clone()
            } else {
                headline.title.to_ascii_lowercase()
            };
            keywords.iter().any(|keyword| {
                if predicate.case_sensitive {
                    headline.title.contains(keyword)
                } else {
                    haystack.contains(keyword)
                }
            })
        })
        .cloned()
        .collect())
}

fn dedupe_seen_keys(seen_keys: &mut Vec<String>) {
    let mut deduped = Vec::with_capacity(seen_keys.len());
    let mut seen = HashSet::new();
    for key in seen_keys.drain(..) {
        if seen.insert(key.clone()) {
            deduped.push(key);
        }
    }
    if deduped.len() > SEEN_KEY_LIMIT {
        let drain_count = deduped.len() - SEEN_KEY_LIMIT;
        deduped.drain(0..drain_count);
    }
    *seen_keys = deduped;
}

pub(crate) fn compile_monitor_request(
    request: CreateMonitorRequest,
) -> Result<WorkflowArtifact, String> {
    let keywords = normalize_keywords(&request.keywords);
    if keywords.is_empty() {
        return Err("Monitor creation requires at least one keyword.".to_string());
    }
    let interval_seconds = request.interval_seconds.unwrap_or(300).max(60);
    let workflow_id = monitor_workflow_id_from_keywords(&keywords)?;
    let title = request.title.unwrap_or_else(|| {
        format!(
            "Monitor Hacker News for {}",
            keywords
                .iter()
                .map(|value| format!("\"{}\"", value))
                .collect::<Vec<_>>()
                .join(" or ")
        )
    });
    let description = request.description.unwrap_or_else(|| {
        format!(
            "Poll the Hacker News front page every {} seconds and notify on new matches.",
            interval_seconds
        )
    });
    let source_prompt_hash = request
        .source_prompt
        .as_ref()
        .map(|prompt| {
            sha256(prompt.as_bytes())
                .map(hex::encode)
                .map_err(|e| e.to_string())
        })
        .transpose()?;
    Ok(WorkflowArtifact {
        spec_version: AUTOMATION_SPEC_VERSION.to_string(),
        workflow_id,
        kind: WorkflowKind::Monitor,
        title,
        description,
        provenance: WorkflowProvenance {
            created_via: "chat".to_string(),
            authoring_tool: "automation.create_monitor".to_string(),
            source_prompt: request.source_prompt,
            source_prompt_hash,
            created_at_ms: now(),
        },
        trigger: WorkflowTrigger {
            trigger_type: WORKFLOW_TRIGGER_INTERVAL.to_string(),
            every_seconds: interval_seconds,
            remote_trigger_id: None,
            wait_until_ms: None,
        },
        graph: monitor_graph_for_keywords(
            &keywords,
            &WorkflowTrigger {
                trigger_type: WORKFLOW_TRIGGER_INTERVAL.to_string(),
                every_seconds: interval_seconds,
                remote_trigger_id: None,
                wait_until_ms: None,
            },
            HACKER_NEWS_FRONT_PAGE_URL,
        ),
        state_schema: WorkflowStateSchema {
            cursor: None,
            seen_keys: Vec::new(),
            last_run_ms: None,
            last_success_ms: None,
            last_emission_hash: None,
        },
        policy: WorkflowPolicy {
            network_allowlist: vec!["news.ycombinator.com".to_string()],
            notification_policy: "assistant".to_string(),
            human_gate_required: false,
        },
        monitor: MonitorDefinition {
            source: MonitorSource {
                source_type: HACKER_NEWS_SOURCE_KIND.to_string(),
                url: HACKER_NEWS_FRONT_PAGE_URL.to_string(),
                scope: Some("front_page".to_string()),
            },
            extractor: MonitorExtractor {
                extractor_type: HACKER_NEWS_EXTRACTOR_KIND.to_string(),
                selector: Some("span.titleline > a".to_string()),
            },
            predicate: MonitorPredicate {
                predicate_type: CONTAINS_ANY_PREDICATE_KIND.to_string(),
                keywords,
                case_sensitive: false,
            },
            dedupe: MonitorDedupe {
                strategy: "state.seen_set".to_string(),
                state_key: Some("href".to_string()),
            },
            sink: NotificationSink {
                sink_type: ASSISTANT_NOTIFICATION_SINK_KIND.to_string(),
                notification_class: "digest".to_string(),
                rail: "assistant".to_string(),
                severity: "informational".to_string(),
            },
        },
    })
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
