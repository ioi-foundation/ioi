use anyhow::{anyhow, Context, Result};
use axum::{
    extract::{Path, State},
    response::{Html, IntoResponse, Redirect},
    routing::{get, post},
    Form, Json, Router,
};
use serde::Deserialize;
use serde_json::json;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use super::types::{
    BridgeDomElement, BridgeField, BridgeInfo, BridgeInteractiveElement, BridgeScrollTarget,
    BridgeState, ComputerUseCase,
};

#[derive(Clone)]
pub(crate) struct WorkflowBridgeClient {
    base_url: String,
    sessions: Arc<Mutex<BTreeMap<String, WorkflowSession>>>,
}

pub(crate) struct WorkflowBridgeProcess {
    client: WorkflowBridgeClient,
    addr: SocketAddr,
    shutdown_tx: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<()>>,
}

pub(crate) struct WorkflowCreateResponse {
    pub(crate) session_id: String,
    pub(crate) url: String,
    pub(crate) state: BridgeState,
}

#[derive(Clone)]
struct WorkflowAppState {
    sessions: Arc<Mutex<BTreeMap<String, WorkflowSession>>>,
}

#[derive(Debug, Clone)]
enum WorkflowScenario {
    TicketRouting,
    QueueVerification,
    AuditHistory,
    MutationIsolation,
    StaleQueueReorder,
}

#[derive(Debug, Clone)]
struct WorkflowCaseSpec {
    case_id: String,
    scenario: WorkflowScenario,
    instruction: String,
    username: String,
    password: String,
    ticket_id: String,
    assignee: String,
    note: String,
    status: String,
    queue_search: String,
    queue_status_filter: String,
    queue_sort: String,
    post_confirm_queue_sort: String,
    distractor_ticket_id: String,
    distractor_assignee: String,
    distractor_status: String,
    distractor_note: String,
}

#[derive(Debug, Clone)]
enum WorkflowPage {
    Login,
    Queue,
    Detail { ticket_id: String },
    Review,
    Confirmation,
    History { ticket_id: String },
}

#[derive(Debug, Clone)]
struct WorkflowTicketRecord {
    ticket_id: String,
    title: String,
    suggested_team: String,
    current_status: String,
    current_assignee: String,
    current_note: String,
    updated_revision: u64,
}

#[derive(Debug, Clone)]
struct WorkflowHistoryEntry {
    ticket_id: String,
    actor: String,
    action: String,
    assignee: String,
    status: String,
    note: String,
}

#[derive(Debug, Clone)]
struct WorkflowQueueSnapshot {
    tickets: BTreeMap<String, WorkflowTicketRecord>,
    search: String,
    status_filter: String,
    sort: String,
}

#[derive(Debug, Clone)]
struct WorkflowSession {
    base_url: String,
    spec: WorkflowCaseSpec,
    tickets: BTreeMap<String, WorkflowTicketRecord>,
    stale_queue_snapshot: Option<WorkflowQueueSnapshot>,
    current_page: WorkflowPage,
    active_ticket_id: String,
    login_username: String,
    login_password: String,
    queue_search: String,
    queue_status_filter: String,
    queue_sort: String,
    queue_view_fresh: bool,
    draft_assignee: String,
    draft_status: String,
    draft_note: String,
    confirmation_seen: bool,
    queue_verified: bool,
    history_verified: bool,
    distractor_history_verified: bool,
    history_entries: Vec<WorkflowHistoryEntry>,
    next_update_revision: u64,
    reward: f32,
    terminated: bool,
    truncated: bool,
    bridge_state: BridgeState,
}

#[derive(Debug, Deserialize)]
struct WorkflowObservationPayload {
    page_url: String,
    focused_tag: Option<String>,
    focused_id: Option<String>,
    visible_text_excerpt: String,
    #[serde(default)]
    interactive_elements: Vec<BridgeInteractiveElement>,
    #[serde(default)]
    scroll_targets: Vec<BridgeScrollTarget>,
    #[serde(default)]
    dom_elements: Vec<BridgeDomElement>,
}

#[derive(Debug, Deserialize)]
struct LoginFormPayload {
    username: String,
    password: String,
}

#[derive(Debug, Deserialize)]
struct AssignFormPayload {
    assignee: String,
    #[serde(default)]
    status: String,
    note: String,
}

#[derive(Debug, Deserialize)]
struct QueueFilterFormPayload {
    #[serde(default)]
    search: String,
    #[serde(default)]
    status: String,
    #[serde(default)]
    sort: String,
}

impl WorkflowBridgeProcess {
    pub(crate) async fn start() -> Result<Self> {
        let sessions = Arc::new(Mutex::new(BTreeMap::new()));
        let state = WorkflowAppState {
            sessions: sessions.clone(),
        };
        let app = Router::new()
            .route(
                "/workflow/:session_id/login",
                get(login_page).post(login_submit),
            )
            .route("/workflow/:session_id/queue", get(queue_page))
            .route(
                "/workflow/:session_id/queue/filter",
                post(queue_filter_submit),
            )
            .route(
                "/workflow/:session_id/tickets/:ticket_id",
                get(ticket_detail_page),
            )
            .route(
                "/workflow/:session_id/tickets/:ticket_id/assign",
                post(ticket_assign_submit),
            )
            .route("/workflow/:session_id/review", get(review_page))
            .route(
                "/workflow/:session_id/review/edit",
                post(review_edit_submit),
            )
            .route(
                "/workflow/:session_id/review/confirm",
                post(review_confirm_submit),
            )
            .route(
                "/workflow/:session_id/review/cancel",
                post(review_cancel_submit),
            )
            .route("/workflow/:session_id/confirmation", get(confirmation_page))
            .route(
                "/workflow/:session_id/tickets/:ticket_id/history",
                get(ticket_history_page),
            )
            .route(
                "/workflow/:session_id/tickets/:ticket_id/reopen",
                post(ticket_reopen_submit),
            )
            .route("/workflow/:session_id/observe", post(observe_page))
            .with_state(state);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .context("bind workflow fixture server")?;
        let addr = listener.local_addr().context("workflow fixture addr")?;
        let base_url = format!("http://{}", addr);
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = shutdown_rx.await;
                })
                .await;
        });
        Ok(Self {
            client: WorkflowBridgeClient { base_url, sessions },
            addr,
            shutdown_tx: Some(shutdown_tx),
            task: Some(task),
        })
    }

    pub(crate) fn client(&self) -> WorkflowBridgeClient {
        self.client.clone()
    }

    pub(crate) async fn stop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }

    #[allow(dead_code)]
    pub(crate) fn addr(&self) -> SocketAddr {
        self.addr
    }
}

impl WorkflowBridgeClient {
    pub(crate) async fn create_session(
        &self,
        case: &ComputerUseCase,
    ) -> Result<WorkflowCreateResponse> {
        let spec = workflow_case_spec(case)?;
        let session_id = format!("workflow-{}-{}", sanitize_token(&case.id), now_ms());
        let url = format!("{}/workflow/{}/login", self.base_url, session_id);
        let mut session = WorkflowSession {
            base_url: self.base_url.clone(),
            spec: spec.clone(),
            tickets: workflow_initial_tickets(),
            stale_queue_snapshot: None,
            current_page: WorkflowPage::Login,
            active_ticket_id: spec.ticket_id.clone(),
            login_username: String::new(),
            login_password: String::new(),
            queue_search: spec.queue_search.clone(),
            queue_status_filter: spec.queue_status_filter.clone(),
            queue_sort: spec.queue_sort.clone(),
            queue_view_fresh: true,
            draft_assignee: String::new(),
            draft_status: String::new(),
            draft_note: String::new(),
            confirmation_seen: false,
            queue_verified: false,
            history_verified: false,
            distractor_history_verified: false,
            history_entries: workflow_initial_history_entries(),
            next_update_revision: 100,
            reward: 0.0,
            terminated: false,
            truncated: false,
            bridge_state: BridgeState {
                session_id: session_id.clone(),
                env_id: case.env_id.clone(),
                seed: case.seed,
                utterance: spec.instruction.clone(),
                reward: 0.0,
                terminated: false,
                truncated: false,
                episode_step: 0,
                generation: 0,
                last_sync_ms: Some(now_ms()),
                sync_history: Vec::new(),
                info: BridgeInfo {
                    reason: Some("workflow_fixture_bootstrap".to_string()),
                    raw_reward: Some(0.0),
                    query_text: Some(spec.instruction.clone()),
                    fields: Vec::new(),
                    page_url: Some(url.clone()),
                    task_ready: Some(false),
                    focused_tag: None,
                    focused_id: None,
                    last_event: None,
                    visible_text_excerpt: None,
                    interactive_elements: Vec::new(),
                    scroll_targets: Vec::new(),
                    dom_elements: Vec::new(),
                    trigger: None,
                },
            },
        };
        sync_bridge_state_from_synthesized_page(&mut session);
        let bridge_state = session.bridge_state.clone();
        self.sessions
            .lock()
            .map_err(|_| anyhow!("workflow sessions lock poisoned"))?
            .insert(session_id.clone(), session);
        Ok(WorkflowCreateResponse {
            session_id,
            url,
            state: bridge_state,
        })
    }

    pub(crate) async fn state(&self, session_id: &str) -> Result<BridgeState> {
        self.sessions
            .lock()
            .map_err(|_| anyhow!("workflow sessions lock poisoned"))?
            .get(session_id)
            .map(|session| session.bridge_state.clone())
            .ok_or_else(|| anyhow!("unknown workflow session '{}'", session_id))
    }

    pub(crate) async fn oracle_step(
        &self,
        session_id: &str,
        kind: &str,
        arguments: serde_json::Value,
    ) -> Result<()> {
        let mut guard = self
            .sessions
            .lock()
            .map_err(|_| anyhow!("workflow sessions lock poisoned"))?;
        let session = guard
            .get_mut(session_id)
            .ok_or_else(|| anyhow!("unknown workflow session '{}'", session_id))?;
        apply_oracle_step(session, kind, arguments)?;
        sync_bridge_state_from_synthesized_page(session);
        Ok(())
    }

    pub(crate) async fn close(&self, session_id: &str) -> Result<()> {
        let _ = self
            .sessions
            .lock()
            .map_err(|_| anyhow!("workflow sessions lock poisoned"))?
            .remove(session_id);
        Ok(())
    }
}

