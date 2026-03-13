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
struct WorkflowSession {
    base_url: String,
    spec: WorkflowCaseSpec,
    tickets: BTreeMap<String, WorkflowTicketRecord>,
    current_page: WorkflowPage,
    active_ticket_id: String,
    login_username: String,
    login_password: String,
    queue_search: String,
    queue_status_filter: String,
    draft_assignee: String,
    draft_status: String,
    draft_note: String,
    confirmation_seen: bool,
    queue_verified: bool,
    history_verified: bool,
    distractor_history_verified: bool,
    history_entries: Vec<WorkflowHistoryEntry>,
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
            current_page: WorkflowPage::Login,
            active_ticket_id: spec.ticket_id.clone(),
            login_username: String::new(),
            login_password: String::new(),
            queue_search: String::new(),
            queue_status_filter: String::new(),
            draft_assignee: String::new(),
            draft_status: String::new(),
            draft_note: String::new(),
            confirmation_seen: false,
            queue_verified: false,
            history_verified: false,
            distractor_history_verified: false,
            history_entries: workflow_initial_history_entries(),
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
                info: BridgeInfo {
                    reason: Some("workflow_fixture_bootstrap".to_string()),
                    raw_reward: Some(0.0),
                    query_text: Some(spec.instruction.clone()),
                    fields: Vec::new(),
                    page_url: Some(url.clone()),
                    task_ready: Some(false),
                    focused_tag: None,
                    focused_id: None,
                    visible_text_excerpt: None,
                    interactive_elements: Vec::new(),
                    scroll_targets: Vec::new(),
                    dom_elements: Vec::new(),
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

fn workflow_case_spec(case: &ComputerUseCase) -> Result<WorkflowCaseSpec> {
    match case.id.as_str() {
        "workflow_ticket_routing_network_ops" => Ok(WorkflowCaseSpec {
            case_id: case.id.clone(),
            scenario: WorkflowScenario::TicketRouting,
            instruction: "Sign in to the dispatch console with username \"dispatch.agent\" and password \"dispatch-204\". Open ticket T-204 from the queue, assign it to Network Ops, add the note \"Escalate fiber outage to on-call\", submit the update, and stop only after the confirmation page shows the saved assignment.".to_string(),
            username: "dispatch.agent".to_string(),
            password: "dispatch-204".to_string(),
            ticket_id: "T-204".to_string(),
            assignee: "Network Ops".to_string(),
            note: "Escalate fiber outage to on-call".to_string(),
            status: String::new(),
            queue_search: String::new(),
            queue_status_filter: String::new(),
            distractor_ticket_id: String::new(),
            distractor_assignee: String::new(),
            distractor_status: String::new(),
            distractor_note: String::new(),
        }),
        "workflow_ticket_routing_billing_review" => Ok(WorkflowCaseSpec {
            case_id: case.id.clone(),
            scenario: WorkflowScenario::TicketRouting,
            instruction: "Sign in to the dispatch console with username \"dispatch.agent\" and password \"billing-310\". Open ticket T-310 from the queue, assign it to Billing Review, add the note \"Validate recurring invoice delta\", submit the update, and stop only after the confirmation page shows the saved assignment.".to_string(),
            username: "dispatch.agent".to_string(),
            password: "billing-310".to_string(),
            ticket_id: "T-310".to_string(),
            assignee: "Billing Review".to_string(),
            note: "Validate recurring invoice delta".to_string(),
            status: String::new(),
            queue_search: String::new(),
            queue_status_filter: String::new(),
            distractor_ticket_id: String::new(),
            distractor_assignee: String::new(),
            distractor_status: String::new(),
            distractor_note: String::new(),
        }),
        "workflow_queue_verification_network_ops" => Ok(WorkflowCaseSpec {
            case_id: case.id.clone(),
            scenario: WorkflowScenario::QueueVerification,
            instruction: "Sign in to the dispatch console with username \"dispatch.agent\" and password \"dispatch-215\". Search the queue for \"fiber\", set the queue status filter to \"Awaiting Dispatch\", open ticket T-215, assign it to Network Ops, set the status to \"Escalated\", add the note \"Escalate fiber outage to on-call\", review the draft, confirm it, then return to the queue and stop only after the queue shows T-215 saved with assignee Network Ops and status Escalated.".to_string(),
            username: "dispatch.agent".to_string(),
            password: "dispatch-215".to_string(),
            ticket_id: "T-215".to_string(),
            assignee: "Network Ops".to_string(),
            note: "Escalate fiber outage to on-call".to_string(),
            status: "Escalated".to_string(),
            queue_search: "fiber".to_string(),
            queue_status_filter: "Awaiting Dispatch".to_string(),
            distractor_ticket_id: String::new(),
            distractor_assignee: String::new(),
            distractor_status: String::new(),
            distractor_note: String::new(),
        }),
        "workflow_queue_verification_billing_review" => Ok(WorkflowCaseSpec {
            case_id: case.id.clone(),
            scenario: WorkflowScenario::QueueVerification,
            instruction: "Sign in to the dispatch console with username \"dispatch.agent\" and password \"billing-318\". Search the queue for \"invoice\", set the queue status filter to \"Pending Review\", open ticket T-318, assign it to Billing Review, set the status to \"Pending Customer Reply\", add the note \"Validate recurring invoice delta\", review the draft, confirm it, then return to the queue and stop only after the queue shows T-318 saved with assignee Billing Review and status Pending Customer Reply.".to_string(),
            username: "dispatch.agent".to_string(),
            password: "billing-318".to_string(),
            ticket_id: "T-318".to_string(),
            assignee: "Billing Review".to_string(),
            note: "Validate recurring invoice delta".to_string(),
            status: "Pending Customer Reply".to_string(),
            queue_search: "invoice".to_string(),
            queue_status_filter: "Pending Review".to_string(),
            distractor_ticket_id: String::new(),
            distractor_assignee: String::new(),
            distractor_status: String::new(),
            distractor_note: String::new(),
        }),
        "workflow_audit_history_network_ops" => Ok(WorkflowCaseSpec {
            case_id: case.id.clone(),
            scenario: WorkflowScenario::AuditHistory,
            instruction: "Sign in to the dispatch console with username \"dispatch.agent\" and password \"dispatch-215\". Search the queue for \"fiber\", keep the queue status filter on \"Awaiting Dispatch\", open ticket T-215 even though other fiber tickets remain visible, assign it to Network Ops, set the status to \"Escalated\", add the note \"Escalate fiber outage to on-call\", review the draft, confirm it, open the audit history, and stop only after the audit history shows a saved dispatch update for T-215 with assignee Network Ops, status Escalated, and note \"Escalate fiber outage to on-call\". If the draft or saved history does not match, cancel or reopen the update and fix it before stopping.".to_string(),
            username: "dispatch.agent".to_string(),
            password: "dispatch-215".to_string(),
            ticket_id: "T-215".to_string(),
            assignee: "Network Ops".to_string(),
            note: "Escalate fiber outage to on-call".to_string(),
            status: "Escalated".to_string(),
            queue_search: "fiber".to_string(),
            queue_status_filter: "Awaiting Dispatch".to_string(),
            distractor_ticket_id: String::new(),
            distractor_assignee: String::new(),
            distractor_status: String::new(),
            distractor_note: String::new(),
        }),
        "workflow_audit_history_billing_review" => Ok(WorkflowCaseSpec {
            case_id: case.id.clone(),
            scenario: WorkflowScenario::AuditHistory,
            instruction: "Sign in to the dispatch console with username \"dispatch.agent\" and password \"billing-318\". Search the queue for \"invoice\", keep the queue status filter on \"Pending Review\", open ticket T-318 even though other invoice tickets remain visible, assign it to Billing Review, set the status to \"Pending Customer Reply\", add the note \"Validate recurring invoice delta\", review the draft, confirm it, open the audit history, and stop only after the audit history shows a saved dispatch update for T-318 with assignee Billing Review, status Pending Customer Reply, and note \"Validate recurring invoice delta\". If the draft or saved history does not match, cancel or reopen the update and fix it before stopping.".to_string(),
            username: "dispatch.agent".to_string(),
            password: "billing-318".to_string(),
            ticket_id: "T-318".to_string(),
            assignee: "Billing Review".to_string(),
            note: "Validate recurring invoice delta".to_string(),
            status: "Pending Customer Reply".to_string(),
            queue_search: "invoice".to_string(),
            queue_status_filter: "Pending Review".to_string(),
            distractor_ticket_id: String::new(),
            distractor_assignee: String::new(),
            distractor_status: String::new(),
            distractor_note: String::new(),
        }),
        "workflow_mutation_isolation_network_ops" => Ok(WorkflowCaseSpec {
            case_id: case.id.clone(),
            scenario: WorkflowScenario::MutationIsolation,
            instruction: "Sign in to the dispatch console with username \"dispatch.agent\" and password \"dispatch-215\". Search the queue for \"fiber\", keep the queue status filter on \"Awaiting Dispatch\" so multiple similar fiber tickets remain visible, open ticket T-215, assign it to Network Ops, keep the status at \"Awaiting Dispatch\", add the note \"Escalate fiber outage to on-call\", review the draft, confirm it, return to the queue, and stop only after typed verification shows T-215 changed while distractor ticket T-204 still shows assignee Unassigned and status Awaiting Dispatch. Then open audit history for T-215 and verify the saved dispatch update exists, open audit history for T-204 and verify no saved dispatch update was persisted there, and use cancel or reopen if the draft or saved state is wrong before stopping.".to_string(),
            username: "dispatch.agent".to_string(),
            password: "dispatch-215".to_string(),
            ticket_id: "T-215".to_string(),
            assignee: "Network Ops".to_string(),
            note: "Escalate fiber outage to on-call".to_string(),
            status: "Awaiting Dispatch".to_string(),
            queue_search: "fiber".to_string(),
            queue_status_filter: "Awaiting Dispatch".to_string(),
            distractor_ticket_id: "T-204".to_string(),
            distractor_assignee: String::new(),
            distractor_status: "Awaiting Dispatch".to_string(),
            distractor_note: String::new(),
        }),
        "workflow_mutation_isolation_billing_review" => Ok(WorkflowCaseSpec {
            case_id: case.id.clone(),
            scenario: WorkflowScenario::MutationIsolation,
            instruction: "Sign in to the dispatch console with username \"dispatch.agent\" and password \"billing-318\". Search the queue for \"invoice\", keep the queue status filter on \"Pending Review\" so multiple similar invoice tickets remain visible, open ticket T-318, assign it to Billing Review, keep the status at \"Pending Review\", add the note \"Validate recurring invoice delta\", review the draft, confirm it, return to the queue, and stop only after typed verification shows T-318 changed while distractor ticket T-310 still shows assignee Unassigned and status Pending Review. Then open audit history for T-318 and verify the saved dispatch update exists, open audit history for T-310 and verify no saved dispatch update was persisted there, and use cancel or reopen if the draft or saved state is wrong before stopping.".to_string(),
            username: "dispatch.agent".to_string(),
            password: "billing-318".to_string(),
            ticket_id: "T-318".to_string(),
            assignee: "Billing Review".to_string(),
            note: "Validate recurring invoice delta".to_string(),
            status: "Pending Review".to_string(),
            queue_search: "invoice".to_string(),
            queue_status_filter: "Pending Review".to_string(),
            distractor_ticket_id: "T-310".to_string(),
            distractor_assignee: String::new(),
            distractor_status: "Pending Review".to_string(),
            distractor_note: String::new(),
        }),
        other => Err(anyhow!(
            "no workflow benchmark spec is defined for case '{}'",
            other
        )),
    }
}

async fn login_page(
    Path(session_id): Path<String>,
    State(state): State<WorkflowAppState>,
) -> Html<String> {
    let Some(session) = with_session(&state.sessions, &session_id, |session| {
        session.current_page = WorkflowPage::Login;
        session.bridge_state.info.task_ready = Some(false);
        render_page_html(session, &WorkflowPage::Login)
    }) else {
        return Html("<h1>unknown workflow session</h1>".to_string());
    };
    Html(session)
}

async fn login_submit(
    Path(session_id): Path<String>,
    State(state): State<WorkflowAppState>,
    Form(form): Form<LoginFormPayload>,
) -> impl IntoResponse {
    let target = with_session(&state.sessions, &session_id, |session| {
        session.login_username = form.username.clone();
        session.login_password = form.password.clone();
        if session.login_username == session.spec.username
            && session.login_password == session.spec.password
        {
            session.current_page = WorkflowPage::Queue;
            format!("/workflow/{}/queue", session_id)
        } else {
            session.current_page = WorkflowPage::Login;
            format!("/workflow/{}/login", session_id)
        }
    })
    .unwrap_or_else(|| format!("/workflow/{}/login", session_id));
    Redirect::to(&target)
}

async fn queue_page(
    Path(session_id): Path<String>,
    State(state): State<WorkflowAppState>,
) -> Html<String> {
    let Some(session) = with_session(&state.sessions, &session_id, |session| {
        session.current_page = WorkflowPage::Queue;
        session.bridge_state.info.task_ready = Some(false);
        render_page_html(session, &WorkflowPage::Queue)
    }) else {
        return Html("<h1>unknown workflow session</h1>".to_string());
    };
    Html(session)
}

async fn queue_filter_submit(
    Path(session_id): Path<String>,
    State(state): State<WorkflowAppState>,
    Form(form): Form<QueueFilterFormPayload>,
) -> impl IntoResponse {
    let target = with_session(&state.sessions, &session_id, |session| {
        session.queue_search = form.search.trim().to_string();
        session.queue_status_filter = form.status.trim().to_string();
        session.current_page = WorkflowPage::Queue;
        format!("/workflow/{}/queue", session_id)
    })
    .unwrap_or_else(|| format!("/workflow/{}/queue", session_id));
    Redirect::to(&target)
}

async fn ticket_detail_page(
    Path((session_id, ticket_id)): Path<(String, String)>,
    State(state): State<WorkflowAppState>,
) -> Html<String> {
    let Some(session) = with_session(&state.sessions, &session_id, |session| {
        session.active_ticket_id = ticket_id.clone();
        if let Some(ticket) = session.tickets.get(&ticket_id) {
            session.draft_assignee = ticket.current_assignee.clone();
            session.draft_status = ticket.current_status.clone();
            session.draft_note = ticket.current_note.clone();
        }
        session.current_page = WorkflowPage::Detail {
            ticket_id: ticket_id.clone(),
        };
        session.bridge_state.info.task_ready = Some(false);
        render_page_html(
            session,
            &WorkflowPage::Detail {
                ticket_id: ticket_id.clone(),
            },
        )
    }) else {
        return Html("<h1>unknown workflow session</h1>".to_string());
    };
    Html(session)
}

async fn ticket_assign_submit(
    Path((session_id, ticket_id)): Path<(String, String)>,
    State(state): State<WorkflowAppState>,
    Form(form): Form<AssignFormPayload>,
) -> impl IntoResponse {
    let target = with_session(&state.sessions, &session_id, |session| {
        session.active_ticket_id = ticket_id.clone();
        session.draft_assignee = form.assignee.clone();
        session.draft_status = form.status.clone();
        session.draft_note = form.note.clone();
        match session.spec.scenario {
            WorkflowScenario::TicketRouting => {
                persist_ticket_update(session, &ticket_id);
                session.current_page = WorkflowPage::Confirmation;
                session.reward = if ticket_id == session.spec.ticket_id
                    && session.draft_assignee == session.spec.assignee
                    && session.draft_note == session.spec.note
                {
                    1.0
                } else {
                    0.0
                };
                session.terminated = true;
                session.truncated = false;
                format!("/workflow/{}/confirmation", session_id)
            }
            WorkflowScenario::QueueVerification
            | WorkflowScenario::AuditHistory
            | WorkflowScenario::MutationIsolation => {
                session.current_page = WorkflowPage::Review;
                session.queue_verified = false;
                session.history_verified = false;
                session.distractor_history_verified = false;
                session.reward = 0.0;
                session.terminated = false;
                session.truncated = false;
                format!("/workflow/{}/review", session_id)
            }
        }
    })
    .unwrap_or_else(|| format!("/workflow/{}/queue", session_id));
    Redirect::to(&target)
}

async fn review_page(
    Path(session_id): Path<String>,
    State(state): State<WorkflowAppState>,
) -> Html<String> {
    let Some(session) = with_session(&state.sessions, &session_id, |session| {
        session.current_page = WorkflowPage::Review;
        session.bridge_state.info.task_ready = Some(false);
        render_page_html(session, &WorkflowPage::Review)
    }) else {
        return Html("<h1>unknown workflow session</h1>".to_string());
    };
    Html(session)
}

async fn review_edit_submit(
    Path(session_id): Path<String>,
    State(state): State<WorkflowAppState>,
) -> impl IntoResponse {
    let target = with_session(&state.sessions, &session_id, |session| {
        let ticket_id = session.active_ticket_id.clone();
        session.current_page = WorkflowPage::Detail {
            ticket_id: ticket_id.clone(),
        };
        format!("/workflow/{}/tickets/{}", session_id, ticket_id)
    })
    .unwrap_or_else(|| format!("/workflow/{}/queue", session_id));
    Redirect::to(&target)
}

async fn review_confirm_submit(
    Path(session_id): Path<String>,
    State(state): State<WorkflowAppState>,
) -> impl IntoResponse {
    let target = with_session(&state.sessions, &session_id, |session| {
        let ticket_id = session.active_ticket_id.clone();
        persist_ticket_update(session, &ticket_id);
        if matches!(
            session.spec.scenario,
            WorkflowScenario::AuditHistory | WorkflowScenario::MutationIsolation
        ) {
            append_history_entry(session, &ticket_id);
        }
        session.current_page = WorkflowPage::Confirmation;
        session.confirmation_seen = true;
        session.queue_verified = false;
        session.history_verified = false;
        session.distractor_history_verified = false;
        session.reward = 0.0;
        session.terminated = false;
        session.truncated = false;
        format!("/workflow/{}/confirmation", session_id)
    })
    .unwrap_or_else(|| format!("/workflow/{}/queue", session_id));
    Redirect::to(&target)
}

async fn review_cancel_submit(
    Path(session_id): Path<String>,
    State(state): State<WorkflowAppState>,
) -> impl IntoResponse {
    let target = with_session(&state.sessions, &session_id, |session| {
        reset_draft_from_saved_ticket(session, &session.active_ticket_id.clone());
        session.current_page = WorkflowPage::Queue;
        session.queue_verified = false;
        session.history_verified = false;
        session.distractor_history_verified = false;
        session.reward = 0.0;
        session.terminated = false;
        session.truncated = false;
        format!("/workflow/{}/queue", session_id)
    })
    .unwrap_or_else(|| format!("/workflow/{}/queue", session_id));
    Redirect::to(&target)
}

async fn confirmation_page(
    Path(session_id): Path<String>,
    State(state): State<WorkflowAppState>,
) -> Html<String> {
    let Some(session) = with_session(&state.sessions, &session_id, |session| {
        session.current_page = WorkflowPage::Confirmation;
        session.bridge_state.info.task_ready = Some(false);
        render_page_html(session, &WorkflowPage::Confirmation)
    }) else {
        return Html("<h1>unknown workflow session</h1>".to_string());
    };
    Html(session)
}

async fn ticket_history_page(
    Path((session_id, ticket_id)): Path<(String, String)>,
    State(state): State<WorkflowAppState>,
) -> Html<String> {
    let Some(session) = with_session(&state.sessions, &session_id, |session| {
        session.active_ticket_id = ticket_id.clone();
        session.current_page = WorkflowPage::History {
            ticket_id: ticket_id.clone(),
        };
        session.bridge_state.info.task_ready = Some(false);
        render_page_html(
            session,
            &WorkflowPage::History {
                ticket_id: ticket_id.clone(),
            },
        )
    }) else {
        return Html("<h1>unknown workflow session</h1>".to_string());
    };
    Html(session)
}

async fn ticket_reopen_submit(
    Path((session_id, ticket_id)): Path<(String, String)>,
    State(state): State<WorkflowAppState>,
) -> impl IntoResponse {
    let target = with_session(&state.sessions, &session_id, |session| {
        session.active_ticket_id = ticket_id.clone();
        reset_draft_from_saved_ticket(session, &ticket_id);
        session.current_page = WorkflowPage::Detail {
            ticket_id: ticket_id.clone(),
        };
        session.queue_verified = false;
        session.history_verified = false;
        session.distractor_history_verified = false;
        session.reward = 0.0;
        session.terminated = false;
        session.truncated = false;
        format!("/workflow/{}/tickets/{}", session_id, ticket_id)
    })
    .unwrap_or_else(|| format!("/workflow/{}/queue", session_id));
    Redirect::to(&target)
}

async fn observe_page(
    Path(session_id): Path<String>,
    State(state): State<WorkflowAppState>,
    Json(payload): Json<WorkflowObservationPayload>,
) -> Json<serde_json::Value> {
    let _ = with_session(&state.sessions, &session_id, |session| {
        sync_bridge_state_from_observation(session, payload);
    });
    Json(json!({ "ok": true }))
}

fn with_session<T>(
    sessions: &Arc<Mutex<BTreeMap<String, WorkflowSession>>>,
    session_id: &str,
    f: impl FnOnce(&mut WorkflowSession) -> T,
) -> Option<T> {
    let mut guard = sessions.lock().ok()?;
    let session = guard.get_mut(session_id)?;
    Some(f(session))
}

fn apply_oracle_step(
    session: &mut WorkflowSession,
    kind: &str,
    arguments: serde_json::Value,
) -> Result<()> {
    match kind {
        "type_selector" => {
            let selector = arguments
                .get("selector")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            let text = arguments
                .get("text")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            match selector {
                "#username" => session.login_username = text.to_string(),
                "#password" => session.login_password = text.to_string(),
                "#queue-search" => session.queue_search = text.to_string(),
                "#note" => session.draft_note = text.to_string(),
                _ => {}
            }
        }
        "select_label" => {
            let selector = arguments
                .get("selector")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            let label = arguments
                .get("label")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            match selector {
                "#assignee" => session.draft_assignee = label.to_string(),
                "#status" => session.draft_status = label.to_string(),
                "#queue-status-filter" => session.queue_status_filter = label.to_string(),
                _ => {}
            }
        }
        "click_selector" => {
            let selector = arguments
                .get("selector")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            match selector {
                "#sign-in" => {
                    if session.login_username == session.spec.username
                        && session.login_password == session.spec.password
                    {
                        session.current_page = WorkflowPage::Queue;
                    }
                }
                "#apply-filters" => {
                    session.current_page = WorkflowPage::Queue;
                }
                "#submit-update" => {
                    let ticket_id = session.active_ticket_id.clone();
                    persist_ticket_update(session, &ticket_id);
                    session.current_page = WorkflowPage::Confirmation;
                    session.reward = if ticket_id == session.spec.ticket_id
                        && session.draft_assignee == session.spec.assignee
                        && session.draft_note == session.spec.note
                    {
                        1.0
                    } else {
                        0.0
                    };
                    session.terminated = true;
                    session.truncated = false;
                }
                "#review-update" => {
                    session.current_page = WorkflowPage::Review;
                    session.queue_verified = false;
                    session.history_verified = false;
                    session.distractor_history_verified = false;
                    session.reward = 0.0;
                    session.terminated = false;
                    session.truncated = false;
                }
                "#edit-update" => {
                    session.current_page = WorkflowPage::Detail {
                        ticket_id: session.active_ticket_id.clone(),
                    };
                }
                "#confirm-update" => {
                    let ticket_id = session.active_ticket_id.clone();
                    persist_ticket_update(session, &ticket_id);
                    if matches!(
                        session.spec.scenario,
                        WorkflowScenario::AuditHistory | WorkflowScenario::MutationIsolation
                    ) {
                        append_history_entry(session, &ticket_id);
                    }
                    session.current_page = WorkflowPage::Confirmation;
                    session.confirmation_seen = true;
                    session.queue_verified = false;
                    session.history_verified = false;
                    session.distractor_history_verified = false;
                    session.reward = 0.0;
                    session.terminated = false;
                    session.truncated = false;
                }
                "#cancel-update" => {
                    let ticket_id = session.active_ticket_id.clone();
                    reset_draft_from_saved_ticket(session, &ticket_id);
                    session.current_page = WorkflowPage::Queue;
                    session.queue_verified = false;
                    session.history_verified = false;
                    session.distractor_history_verified = false;
                    session.reward = 0.0;
                    session.terminated = false;
                    session.truncated = false;
                }
                "#history-link" => {
                    session.current_page = WorkflowPage::History {
                        ticket_id: session.active_ticket_id.clone(),
                    };
                }
                "#reopen-ticket" => {
                    let ticket_id = session.active_ticket_id.clone();
                    reset_draft_from_saved_ticket(session, &ticket_id);
                    session.current_page = WorkflowPage::Detail { ticket_id };
                    session.queue_verified = false;
                    session.history_verified = false;
                    session.distractor_history_verified = false;
                    session.reward = 0.0;
                    session.terminated = false;
                    session.truncated = false;
                }
                "#queue-link" => {
                    session.current_page = WorkflowPage::Queue;
                }
                _ if ticket_id_for_history_selector(session, selector).is_some() => {
                    let ticket_id =
                        ticket_id_for_history_selector(session, selector).unwrap_or_default();
                    session.active_ticket_id = ticket_id.clone();
                    session.current_page = WorkflowPage::History { ticket_id };
                }
                _ if ticket_id_for_selector(session, selector).is_some() => {
                    let ticket_id = ticket_id_for_selector(session, selector).unwrap_or_default();
                    session.active_ticket_id = ticket_id.clone();
                    if let Some(ticket) = session.tickets.get(&ticket_id) {
                        session.draft_assignee = ticket.current_assignee.clone();
                        session.draft_status = ticket.current_status.clone();
                        session.draft_note = ticket.current_note.clone();
                    }
                    session.current_page = WorkflowPage::Detail { ticket_id };
                }
                _ => {}
            }
        }
        other => {
            return Err(anyhow!(
                "workflow oracle step '{}' is not implemented",
                other
            ))
        }
    }
    Ok(())
}

fn sync_bridge_state_from_observation(
    session: &mut WorkflowSession,
    payload: WorkflowObservationPayload,
) {
    session.current_page =
        page_from_url(&payload.page_url).unwrap_or_else(|| session.current_page.clone());
    if let Some(ticket_id) = active_ticket_id_from_page(session) {
        session.active_ticket_id = ticket_id;
    }
    session.login_username = observation_value(&payload.interactive_elements, "#username")
        .unwrap_or_else(|| session.login_username.clone());
    session.login_password = observation_value(&payload.interactive_elements, "#password")
        .unwrap_or_else(|| session.login_password.clone());
    session.queue_search = observation_value(&payload.interactive_elements, "#queue-search")
        .unwrap_or_else(|| session.queue_search.clone());
    session.queue_status_filter =
        observation_selected_label(&payload.interactive_elements, "#queue-status-filter")
            .or_else(|| observation_value(&payload.interactive_elements, "#queue-status-filter"))
            .unwrap_or_else(|| session.queue_status_filter.clone());
    session.draft_assignee = observation_selected_label(&payload.interactive_elements, "#assignee")
        .or_else(|| observation_value(&payload.interactive_elements, "#assignee"))
        .unwrap_or_else(|| session.draft_assignee.clone());
    session.draft_status = observation_selected_label(&payload.interactive_elements, "#status")
        .or_else(|| observation_value(&payload.interactive_elements, "#status"))
        .unwrap_or_else(|| session.draft_status.clone());
    session.draft_note = observation_value(&payload.interactive_elements, "#note")
        .unwrap_or_else(|| session.draft_note.clone());
    maybe_complete_workflow_verification(session, Some(payload.visible_text_excerpt.as_str()));

    session.bridge_state.reward = session.reward;
    session.bridge_state.terminated = session.terminated;
    session.bridge_state.truncated = session.truncated;
    session.bridge_state.episode_step = session.bridge_state.episode_step.saturating_add(1);
    session.bridge_state.generation = session.bridge_state.generation.saturating_add(1);
    session.bridge_state.last_sync_ms = Some(now_ms());
    session.bridge_state.info = BridgeInfo {
        reason: Some("workflow_observation".to_string()),
        raw_reward: Some(session.reward),
        query_text: Some(session.spec.instruction.clone()),
        fields: workflow_fields(session),
        page_url: Some(payload.page_url),
        task_ready: Some(true),
        focused_tag: payload.focused_tag,
        focused_id: payload.focused_id,
        visible_text_excerpt: Some(payload.visible_text_excerpt),
        interactive_elements: payload.interactive_elements,
        scroll_targets: payload.scroll_targets,
        dom_elements: payload.dom_elements,
    };
}

fn sync_bridge_state_from_synthesized_page(session: &mut WorkflowSession) {
    let visible_text = workflow_visible_text(session, &session.current_page);
    maybe_complete_workflow_verification(session, Some(visible_text.as_str()));
    session.bridge_state.reward = session.reward;
    session.bridge_state.terminated = session.terminated;
    session.bridge_state.truncated = session.truncated;
    session.bridge_state.episode_step = session.bridge_state.episode_step.saturating_add(1);
    session.bridge_state.generation = session.bridge_state.generation.saturating_add(1);
    session.bridge_state.last_sync_ms = Some(now_ms());
    session.bridge_state.info = BridgeInfo {
        reason: Some("workflow_oracle".to_string()),
        raw_reward: Some(session.reward),
        query_text: Some(session.spec.instruction.clone()),
        fields: workflow_fields(session),
        page_url: Some(current_page_url(session)),
        task_ready: Some(true),
        focused_tag: None,
        focused_id: None,
        visible_text_excerpt: Some(visible_text),
        interactive_elements: synthesized_interactive_elements(session, &session.current_page),
        scroll_targets: Vec::new(),
        dom_elements: Vec::new(),
    };
}

fn render_page_html(session: &WorkflowSession, page: &WorkflowPage) -> String {
    let body = match page {
        WorkflowPage::Login => render_login_body(session),
        WorkflowPage::Queue => render_queue_body(session),
        WorkflowPage::Detail { ticket_id } => render_detail_body(session, ticket_id),
        WorkflowPage::Review => render_review_body(session),
        WorkflowPage::Confirmation => render_confirmation_body(session),
        WorkflowPage::History { ticket_id } => render_history_body(session, ticket_id),
    };
    format!(
        r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Dispatch Console</title>
  <style>
    body {{ font-family: ui-sans-serif, system-ui, sans-serif; margin: 0; background: #f4f6fb; color: #172033; }}
    main {{ max-width: 960px; margin: 32px auto; padding: 24px; }}
    .shell {{ background: #fff; border: 1px solid #d4dceb; border-radius: 16px; box-shadow: 0 8px 24px rgba(23, 32, 51, 0.08); overflow: hidden; }}
    .topbar {{ padding: 18px 24px; background: linear-gradient(135deg, #183153, #2855a1); color: #fff; }}
    .content {{ padding: 24px; }}
    .breadcrumbs {{ font-size: 14px; color: #516178; margin-bottom: 16px; }}
    .grid {{ display: grid; gap: 16px; }}
    .two-col {{ grid-template-columns: 1.2fr 0.8fr; }}
    .panel {{ border: 1px solid #d4dceb; border-radius: 12px; padding: 16px; background: #fbfcff; }}
    .inline-actions {{ display: flex; gap: 12px; flex-wrap: wrap; }}
    .inline-form {{ margin: 0; }}
    label {{ display: block; font-size: 14px; font-weight: 600; margin-bottom: 6px; }}
    input, textarea, select {{ width: 100%; box-sizing: border-box; margin-bottom: 14px; border: 1px solid #b9c6db; border-radius: 10px; padding: 10px 12px; font: inherit; }}
    textarea {{ min-height: 120px; resize: vertical; }}
    button, .button-link {{ display: inline-block; border: none; border-radius: 999px; padding: 10px 16px; background: #1f6feb; color: #fff; font: inherit; cursor: pointer; text-decoration: none; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ padding: 12px; border-bottom: 1px solid #e2e8f3; text-align: left; }}
    code {{ font-family: ui-monospace, SFMono-Regular, monospace; }}
    .status-pill {{ display: inline-block; padding: 4px 10px; border-radius: 999px; background: #e4eefc; color: #1f4f96; font-size: 12px; font-weight: 700; }}
    .success {{ background: #e7f8ee; color: #19663e; }}
    .muted {{ color: #607086; }}
  </style>
</head>
<body>
  <main>
    <section class="shell">
      <div class="topbar">
        <strong>Dispatch Console</strong>
        <div>Deterministic workflow benchmark fixture</div>
      </div>
      <div class="content">
        {body}
      </div>
    </section>
  </main>
  <script>{script}</script>
</body>
</html>"#,
        body = body,
        script = workflow_observer_script(&format!(
            "/workflow/{}/observe",
            session.bridge_state.session_id
        ))
    )
}

fn render_login_body(session: &WorkflowSession) -> String {
    format!(
        r#"<div class="breadcrumbs">Login</div>
<div class="grid two-col">
  <section class="panel">
    <h1>Sign in to continue</h1>
    <p>Use your dispatch credentials to continue to the ticket queue.</p>
    <form action="/workflow/{session_id}/login" method="post">
      <label for="username">Username</label>
      <input id="username" name="username" type="text" autocomplete="off" value="{username}">
      <label for="password">Password</label>
      <input id="password" name="password" type="password" autocomplete="off" value="{password}">
      <button id="sign-in" type="submit">Sign in</button>
    </form>
  </section>
  <aside class="panel">
    <h2>Task brief</h2>
    <p id="task-brief">{instruction}</p>
    <p><span class="status-pill">Step 1</span> Authenticate before opening the queue.</p>
  </aside>
</div>"#,
        session_id = session.bridge_state.session_id,
        username = escape_html(&session.login_username),
        password = escape_html(&session.login_password),
        instruction = escape_html(&session.spec.instruction),
    )
}

fn render_queue_body(session: &WorkflowSession) -> String {
    match session.spec.scenario {
        WorkflowScenario::TicketRouting => render_ticket_routing_queue_body(session),
        WorkflowScenario::QueueVerification | WorkflowScenario::AuditHistory => {
            render_queue_verification_queue_body(session)
        }
        WorkflowScenario::MutationIsolation => render_mutation_isolation_queue_body(session),
    }
}

fn render_ticket_routing_queue_body(session: &WorkflowSession) -> String {
    let rows = visible_queue_tickets(session)
        .into_iter()
        .map(|ticket| render_queue_row(session, ticket))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        r#"<div class="breadcrumbs">Login / Queue</div>
<div class="grid two-col">
  <section class="panel">
    <h1>Active dispatch queue</h1>
    <p>Open the ticket that matches the task brief, then update the assignment.</p>
    <table>
      <thead>
        <tr><th>Ticket</th><th>Summary</th><th>Status</th><th>Assignee</th><th>Suggested team</th></tr>
      </thead>
      <tbody>{rows}</tbody>
    </table>
  </section>
  <aside class="panel">
    <h2>Task brief</h2>
    <p id="task-brief">{instruction}</p>
    <p><span class="status-pill">Step 2</span> Open <code>{ticket_id}</code> from the queue.</p>
  </aside>
</div>"#,
        rows = rows,
        instruction = escape_html(&session.spec.instruction),
        ticket_id = escape_html(&session.spec.ticket_id),
    )
}

fn render_queue_verification_queue_body(session: &WorkflowSession) -> String {
    let visible_tickets = visible_queue_tickets(session);
    let rows = if visible_tickets.is_empty() {
        "<tr><td colspan=\"5\" class=\"muted\">No tickets matched the current queue search and filter.</td></tr>"
            .to_string()
    } else {
        visible_tickets
            .into_iter()
            .map(|ticket| render_queue_row(session, ticket))
            .collect::<Vec<_>>()
            .join("\n")
    };
    let queue_hint = if session.queue_search.trim().is_empty() {
        "Search is required to reveal the full queue; blank search only shows the first two filtered rows."
    } else if matches!(session.spec.scenario, WorkflowScenario::AuditHistory)
        && session.history_verified
    {
        "Audit history verification completed from typed saved-event state."
    } else if session.queue_verified {
        "Queue verification completed from typed queue state."
    } else {
        "Apply the queue search and filter before opening the target ticket."
    };
    let heading = if matches!(session.spec.scenario, WorkflowScenario::AuditHistory) {
        "Dispatch audit queue"
    } else {
        "Dispatch verification queue"
    };
    let description = if matches!(session.spec.scenario, WorkflowScenario::AuditHistory) {
        "Search and filter the queue to reveal the target ticket while distractors remain visible, then confirm the saved update on the audit history page."
    } else {
        "Search and filter the queue to reveal the target ticket, then confirm the saved update survives navigation back to the queue."
    };
    format!(
        r#"<div class="breadcrumbs">Login / Queue</div>
<div class="grid two-col">
  <section class="panel">
    <h1>{heading}</h1>
    <p>{description}</p>
    <form action="/workflow/{session_id}/queue/filter" method="post">
      <label for="queue-search">Queue search</label>
      <input id="queue-search" name="search" type="text" autocomplete="off" value="{search}">
      <label for="queue-status-filter">Queue status filter</label>
      <select id="queue-status-filter" name="status">
        {status_options}
      </select>
      <button id="apply-filters" type="submit">Apply filters</button>
    </form>
    <p class="muted">{queue_hint}</p>
    <table>
      <thead>
        <tr><th>Ticket</th><th>Summary</th><th>Status</th><th>Assignee</th><th>Suggested team</th></tr>
      </thead>
      <tbody>{rows}</tbody>
    </table>
  </section>
  <aside class="panel">
    <h2>Task brief</h2>
    <p id="task-brief">{instruction}</p>
    <p><span class="status-pill">Step 2</span> Search for <code>{queue_search}</code> and set the queue filter to <code>{queue_filter}</code> before opening <code>{ticket_id}</code>.</p>
  </aside>
</div>"#,
        session_id = session.bridge_state.session_id,
        heading = heading,
        description = description,
        search = escape_html(&session.queue_search),
        status_options = render_queue_status_filter_options(&session.queue_status_filter),
        queue_hint = escape_html(queue_hint),
        rows = rows,
        instruction = escape_html(&session.spec.instruction),
        queue_search = escape_html(&session.spec.queue_search),
        queue_filter = escape_html(&session.spec.queue_status_filter),
        ticket_id = escape_html(&session.spec.ticket_id),
    )
}

fn render_queue_row(session: &WorkflowSession, ticket: &WorkflowTicketRecord) -> String {
    format!(
        r#"<tr>
  <td><a id="{link_id}" href="/workflow/{session_id}/tickets/{ticket_id}">{ticket_id}</a></td>
  <td>{title}</td>
  <td>{status}</td>
  <td>{assignee}</td>
  <td>{owner}</td>
</tr>"#,
        link_id = ticket_link_id(&ticket.ticket_id),
        session_id = session.bridge_state.session_id,
        ticket_id = escape_html(&ticket.ticket_id),
        title = escape_html(&ticket.title),
        status = escape_html(&ticket.current_status),
        assignee = escape_html(&display_assignee(&ticket.current_assignee)),
        owner = escape_html(&ticket.suggested_team),
    )
}

fn render_mutation_queue_row(session: &WorkflowSession, ticket: &WorkflowTicketRecord) -> String {
    format!(
        r#"<tr>
  <td><a id="{detail_link_id}" href="/workflow/{session_id}/tickets/{ticket_id}">{ticket_id}</a></td>
  <td>{title}</td>
  <td>{status}</td>
  <td>{assignee}</td>
  <td>{owner}</td>
  <td><a id="{history_link_id}" href="/workflow/{session_id}/tickets/{ticket_id}/history">History</a></td>
</tr>"#,
        detail_link_id = ticket_link_id(&ticket.ticket_id),
        history_link_id = ticket_history_link_id(&ticket.ticket_id),
        session_id = session.bridge_state.session_id,
        ticket_id = escape_html(&ticket.ticket_id),
        title = escape_html(&ticket.title),
        status = escape_html(&ticket.current_status),
        assignee = escape_html(&display_assignee(&ticket.current_assignee)),
        owner = escape_html(&ticket.suggested_team),
    )
}

fn render_mutation_isolation_queue_body(session: &WorkflowSession) -> String {
    let visible_tickets = visible_queue_tickets(session);
    let rows = if visible_tickets.is_empty() {
        "<tr><td colspan=\"6\" class=\"muted\">No tickets matched the current queue search and filter.</td></tr>"
            .to_string()
    } else {
        visible_tickets
            .into_iter()
            .map(|ticket| render_mutation_queue_row(session, ticket))
            .collect::<Vec<_>>()
            .join("\n")
    };
    let queue_hint = if session.queue_search.trim().is_empty() {
        "Search is required to reveal the ambiguous target and distractor tickets."
    } else if session.queue_verified {
        "Typed queue verification confirmed the target changed and the distractor remained unchanged."
    } else {
        "Keep multiple similar tickets visible, then verify the target changed while the distractor did not."
    };
    format!(
        r#"<div class="breadcrumbs">Login / Queue</div>
<div class="grid two-col">
  <section class="panel">
    <h1>Dispatch mutation-isolation queue</h1>
    <p>Keep multiple similar tickets visible, mutate only the requested target, then verify target and distractor outcomes separately from queue and history state.</p>
    <form action="/workflow/{session_id}/queue/filter" method="post">
      <label for="queue-search">Queue search</label>
      <input id="queue-search" name="search" type="text" autocomplete="off" value="{search}">
      <label for="queue-status-filter">Queue status filter</label>
      <select id="queue-status-filter" name="status">
        {status_options}
      </select>
      <button id="apply-filters" type="submit">Apply filters</button>
    </form>
    <p class="muted">{queue_hint}</p>
    <table>
      <thead>
        <tr><th>Ticket</th><th>Summary</th><th>Status</th><th>Assignee</th><th>Suggested team</th><th>Audit</th></tr>
      </thead>
      <tbody>{rows}</tbody>
    </table>
  </section>
  <aside class="panel">
    <h2>Task brief</h2>
    <p id="task-brief">{instruction}</p>
    <p><span class="status-pill">Step 2</span> Search for <code>{queue_search}</code>, keep the queue filter on <code>{queue_filter}</code>, and leave both <code>{target_ticket}</code> and distractor <code>{distractor_ticket}</code> available for typed verification.</p>
  </aside>
</div>"#,
        session_id = session.bridge_state.session_id,
        search = escape_html(&session.queue_search),
        status_options = render_queue_status_filter_options(&session.queue_status_filter),
        queue_hint = escape_html(queue_hint),
        rows = rows,
        instruction = escape_html(&session.spec.instruction),
        queue_search = escape_html(&session.spec.queue_search),
        queue_filter = escape_html(&session.spec.queue_status_filter),
        target_ticket = escape_html(&session.spec.ticket_id),
        distractor_ticket = escape_html(&session.spec.distractor_ticket_id),
    )
}

fn render_detail_body(session: &WorkflowSession, ticket_id: &str) -> String {
    let ticket = session.tickets.get(ticket_id);
    let ticket_summary = ticket
        .map(|ticket| {
            format!(
                "{} / suggested team: {} / current status: {} / current assignee: {}",
                ticket.title,
                ticket.suggested_team,
                ticket.current_status,
                display_assignee(&ticket.current_assignee)
            )
        })
        .unwrap_or_else(|| "Untracked ticket".to_string());
    let submit_id = match session.spec.scenario {
        WorkflowScenario::TicketRouting => "submit-update",
        WorkflowScenario::QueueVerification
        | WorkflowScenario::AuditHistory
        | WorkflowScenario::MutationIsolation => "review-update",
    };
    let submit_text = match session.spec.scenario {
        WorkflowScenario::TicketRouting => "Submit update",
        WorkflowScenario::QueueVerification
        | WorkflowScenario::AuditHistory
        | WorkflowScenario::MutationIsolation => "Review update",
    };
    let step_text = match session.spec.scenario {
        WorkflowScenario::TicketRouting => {
            "Save the requested assignee and note."
        }
        WorkflowScenario::QueueVerification => {
            "Prepare the requested assignee, status, and note before review."
        }
        WorkflowScenario::AuditHistory => {
            "Prepare the requested assignee, status, and note before review, then verify the persisted audit event."
        }
        WorkflowScenario::MutationIsolation => {
            "Prepare the requested assignee, status, and note for the target ticket only. Cancel if the wrong ticket or a stale draft is open."
        }
    };
    format!(
        r#"<div class="breadcrumbs"><a id="queue-link" href="/workflow/{session_id}/queue">Queue</a> / Ticket {ticket_id}</div>
<div class="grid two-col">
  <section class="panel">
    <h1 id="ticket-title">Ticket {ticket_id}</h1>
    <p>{summary}</p>
    <form action="/workflow/{session_id}/tickets/{ticket_id}/assign" method="post">
      <label for="assignee">Assign team</label>
      <select id="assignee" name="assignee">
        {options}
      </select>
      <label for="status">Ticket status</label>
      <select id="status" name="status">
        {status_options}
      </select>
      <label for="note">Dispatch note</label>
      <textarea id="note" name="note">{note}</textarea>
      <button id="{submit_id}" type="submit">{submit_text}</button>
    </form>
  </section>
  <aside class="panel">
    <h2>Task brief</h2>
    <p id="task-brief">{instruction}</p>
    <p><span class="status-pill">Step 3</span> {step_text}</p>
  </aside>
</div>"#,
        session_id = session.bridge_state.session_id,
        ticket_id = escape_html(ticket_id),
        summary = escape_html(&ticket_summary),
        options = render_assignee_options(&session.draft_assignee),
        status_options = render_status_options(&session.draft_status),
        note = escape_html(&session.draft_note),
        submit_id = submit_id,
        submit_text = submit_text,
        instruction = escape_html(&session.spec.instruction),
        step_text = escape_html(step_text),
    )
}

fn render_review_body(session: &WorkflowSession) -> String {
    let ticket_id = session.active_ticket_id.clone();
    let recovery_actions = if matches!(
        session.spec.scenario,
        WorkflowScenario::AuditHistory | WorkflowScenario::MutationIsolation
    ) {
        format!(
            r#"
      <form class="inline-form" action="/workflow/{session_id}/review/cancel" method="post">
        <button id="cancel-update" type="submit">Cancel draft</button>
      </form>"#,
            session_id = session.bridge_state.session_id,
        )
    } else {
        String::new()
    };
    let step_text = match session.spec.scenario {
        WorkflowScenario::AuditHistory => {
            "Review the draft and confirm it only if the ticket, assignee, status, and note match the request. Cancel the draft if anything is stale or wrong."
        }
        WorkflowScenario::MutationIsolation => {
            "Review the draft and confirm it only if the target ticket, assignee, status, and note match the request. Cancel the draft if the wrong ticket is open or the draft is stale."
        }
        WorkflowScenario::TicketRouting | WorkflowScenario::QueueVerification => {
            "Review the draft and confirm it only if the ticket, assignee, status, and note match the request."
        }
    };
    format!(
        r#"<div class="breadcrumbs"><a id="queue-link" href="/workflow/{session_id}/queue">Queue</a> / Review draft</div>
<div class="grid two-col">
  <section class="panel">
    <h1>Review queued update</h1>
    <p id="review-ticket">Ticket <strong>{ticket_id}</strong></p>
    <p id="review-assignee">Draft assignee: <strong>{assignee}</strong></p>
    <p id="review-status">Draft status: <strong>{status}</strong></p>
    <p id="review-note">Draft note: {note}</p>
    <div class="inline-actions">
      <form class="inline-form" action="/workflow/{session_id}/review/edit" method="post">
        <button id="edit-update" type="submit">Edit draft</button>
      </form>
      <form class="inline-form" action="/workflow/{session_id}/review/confirm" method="post">
        <button id="confirm-update" type="submit">Confirm update</button>
      </form>
      {recovery_actions}
    </div>
  </section>
  <aside class="panel">
    <h2>Task brief</h2>
    <p id="task-brief">{instruction}</p>
    <p><span class="status-pill">Step 4</span> {step_text}</p>
  </aside>
</div>"#,
        session_id = session.bridge_state.session_id,
        ticket_id = escape_html(&ticket_id),
        assignee = escape_html(&session.draft_assignee),
        status = escape_html(&session.draft_status),
        note = escape_html(&session.draft_note),
        recovery_actions = recovery_actions,
        instruction = escape_html(&session.spec.instruction),
        step_text = escape_html(step_text),
    )
}

fn render_confirmation_body(session: &WorkflowSession) -> String {
    let saved_ticket = session
        .tickets
        .get(&session.active_ticket_id)
        .or_else(|| session.tickets.get(&session.spec.ticket_id));
    let saved_assignee = saved_ticket
        .map(|ticket| display_assignee(&ticket.current_assignee))
        .unwrap_or_else(|| "Unassigned".to_string());
    let saved_status = saved_ticket
        .map(|ticket| ticket.current_status.clone())
        .unwrap_or_else(|| "Unknown".to_string());
    let saved_note = saved_ticket
        .map(|ticket| ticket.current_note.clone())
        .unwrap_or_default();
    let success = match session.spec.scenario {
        WorkflowScenario::TicketRouting => (session.reward - 1.0).abs() < f32::EPSILON,
        WorkflowScenario::QueueVerification => session.queue_verified,
        WorkflowScenario::AuditHistory => session.history_verified,
        WorkflowScenario::MutationIsolation => {
            session.queue_verified
                && session.history_verified
                && session.distractor_history_verified
        }
    };
    let status_class = if success {
        "status-pill success"
    } else {
        "status-pill"
    };
    let status_text = match session.spec.scenario {
        WorkflowScenario::TicketRouting if success => "Saved and verified",
        WorkflowScenario::TicketRouting => "Saved with validation mismatch",
        WorkflowScenario::QueueVerification if success => "Saved and queue-verified",
        WorkflowScenario::QueueVerification => "Saved, queue verification pending",
        WorkflowScenario::AuditHistory if success => "Saved and audit-verified",
        WorkflowScenario::AuditHistory => "Saved, audit verification pending",
        WorkflowScenario::MutationIsolation if success => {
            "Saved and cross-ticket isolation verified"
        }
        WorkflowScenario::MutationIsolation => {
            "Saved, cross-ticket queue/history verification pending"
        }
    };
    let step_text = match session.spec.scenario {
        WorkflowScenario::TicketRouting => "Confirmation page reached.",
        WorkflowScenario::QueueVerification => {
            "Return to the queue and verify the persisted assignee and status."
        }
        WorkflowScenario::AuditHistory => {
            "Open the audit history and verify the persisted update. Reopen the ticket if the saved event is wrong."
        }
        WorkflowScenario::MutationIsolation => {
            "Verify the queue still isolates the target from the distractor, then verify target and distractor audit histories separately. Reopen or cancel if the draft or saved target state is wrong."
        }
    };
    let followup_actions = if matches!(
        session.spec.scenario,
        WorkflowScenario::AuditHistory | WorkflowScenario::MutationIsolation
    ) {
        format!(
            r#"
    <div class="inline-actions">
      <a id="history-link" class="button-link" href="/workflow/{session_id}/tickets/{ticket_id}/history">Open audit history</a>
      <form class="inline-form" action="/workflow/{session_id}/tickets/{ticket_id}/reopen" method="post">
        <button id="reopen-ticket" type="submit">Reopen ticket</button>
      </form>
    </div>"#,
            session_id = session.bridge_state.session_id,
            ticket_id = escape_html(&session.active_ticket_id),
        )
    } else {
        String::new()
    };
    format!(
        r#"<div class="breadcrumbs"><a id="queue-link" href="/workflow/{session_id}/queue">Queue</a> / Confirmation</div>
<div class="grid two-col">
  <section class="panel">
    <h1>Assignment confirmation</h1>
    <p><span id="save-status" class="{status_class}">{status_text}</span></p>
    <p id="assignment-banner">Ticket <strong>{ticket_id}</strong> was routed to <strong>{assignee}</strong>.</p>
    <p id="status-summary">Saved status: {status}</p>
    <p id="note-summary">Saved note: {note}</p>
    {followup_actions}
  </section>
  <aside class="panel">
    <h2>Task brief</h2>
    <p id="task-brief">{instruction}</p>
    <p><span class="status-pill">Step 5</span> {step_text}</p>
  </aside>
</div>"#,
        session_id = session.bridge_state.session_id,
        status_class = status_class,
        status_text = status_text,
        ticket_id = escape_html(&session.active_ticket_id),
        assignee = escape_html(&saved_assignee),
        status = escape_html(&saved_status),
        note = escape_html(&saved_note),
        followup_actions = followup_actions,
        instruction = escape_html(&session.spec.instruction),
        step_text = escape_html(step_text),
    )
}

fn render_history_body(session: &WorkflowSession, ticket_id: &str) -> String {
    let rows = history_entries_for_ticket(session, ticket_id)
        .into_iter()
        .map(|entry| {
            format!(
                r#"<tr>
  <td>{actor}</td>
  <td>{action}</td>
  <td>{assignee}</td>
  <td>{status}</td>
  <td>{note}</td>
</tr>"#,
                actor = escape_html(&entry.actor),
                action = escape_html(&entry.action),
                assignee = escape_html(&display_assignee(&entry.assignee)),
                status = escape_html(&entry.status),
                note = escape_html(&entry.note),
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let body_rows = if rows.is_empty() {
        "<tr><td colspan=\"5\" class=\"muted\">No persisted audit events are available for this ticket yet.</td></tr>"
            .to_string()
    } else {
        rows
    };
    let audit_status = if session.history_verified {
        "Typed audit verification complete."
    } else if matches!(session.spec.scenario, WorkflowScenario::MutationIsolation)
        && ticket_id == session.spec.distractor_ticket_id
    {
        "Verify that this distractor history still lacks a saved dispatch update."
    } else {
        "Verify that the saved dispatch event matches the requested ticket, assignee, status, and note."
    };
    let step_text = if matches!(session.spec.scenario, WorkflowScenario::MutationIsolation)
        && ticket_id == session.spec.distractor_ticket_id
    {
        format!(
            "Stop only after typed verification confirms ticket <code>{}</code> still has no saved dispatch update. Reopen the target if the saved target state is wrong.",
            escape_html(ticket_id)
        )
    } else {
        format!(
            "Stop only after this audit history shows the saved event for ticket <code>{}</code>. Reopen the ticket if the saved event is wrong.",
            escape_html(ticket_id)
        )
    };
    format!(
        r#"<div class="breadcrumbs"><a id="queue-link" href="/workflow/{session_id}/queue">Queue</a> / <a id="confirmation-link" href="/workflow/{session_id}/confirmation">Confirmation</a> / Audit history</div>
<div class="grid two-col">
  <section class="panel">
    <h1>Audit history for ticket {ticket_id}</h1>
    <p id="history-status" class="muted">{audit_status}</p>
    <table>
      <thead>
        <tr><th>Actor</th><th>Action</th><th>Assignee</th><th>Status</th><th>Note</th></tr>
      </thead>
      <tbody>{rows}</tbody>
    </table>
    <div class="inline-actions">
      <form class="inline-form" action="/workflow/{session_id}/tickets/{ticket_id}/reopen" method="post">
        <button id="reopen-ticket" type="submit">Reopen ticket</button>
      </form>
    </div>
  </section>
  <aside class="panel">
    <h2>Task brief</h2>
    <p id="task-brief">{instruction}</p>
    <p><span class="status-pill">Step 5</span> {step_text}</p>
  </aside>
</div>"#,
        session_id = session.bridge_state.session_id,
        ticket_id = escape_html(ticket_id),
        audit_status = escape_html(audit_status),
        rows = body_rows,
        instruction = escape_html(&session.spec.instruction),
        step_text = step_text,
    )
}

fn render_assignee_options(selected: &str) -> String {
    [
        "",
        "Facilities",
        "Network Ops",
        "Billing Review",
        "Customer Success",
    ]
    .into_iter()
    .map(|option| {
        let selected_attr = if option == selected { " selected" } else { "" };
        format!(
            r#"<option value="{value}"{selected}>{value}</option>"#,
            value = escape_html(option),
            selected = selected_attr
        )
    })
    .collect::<Vec<_>>()
    .join("\n")
}

fn render_status_options(selected: &str) -> String {
    [
        "",
        "New",
        "Awaiting Dispatch",
        "Escalated",
        "Pending Review",
        "Pending Customer Reply",
        "Resolved",
    ]
    .into_iter()
    .map(|option| {
        let selected_attr = if option == selected { " selected" } else { "" };
        let label = if option.is_empty() {
            "Select status"
        } else {
            option
        };
        format!(
            r#"<option value="{value}"{selected}>{label}</option>"#,
            value = escape_html(option),
            selected = selected_attr,
            label = escape_html(label),
        )
    })
    .collect::<Vec<_>>()
    .join("\n")
}

fn render_queue_status_filter_options(selected: &str) -> String {
    [
        "",
        "Awaiting Dispatch",
        "Pending Review",
        "Escalated",
        "Pending Customer Reply",
        "Resolved",
    ]
    .into_iter()
    .map(|option| {
        let selected_attr = if option == selected { " selected" } else { "" };
        let label = if option.is_empty() {
            "All statuses"
        } else {
            option
        };
        format!(
            r#"<option value="{value}"{selected}>{label}</option>"#,
            value = escape_html(option),
            selected = selected_attr,
            label = escape_html(label),
        )
    })
    .collect::<Vec<_>>()
    .join("\n")
}

fn workflow_observer_script(report_path: &str) -> String {
    format!(
        r##"(function () {{
  const reportUrl = "{report_path}";
  function selectorFor(el) {{
    if (!el.id) return null;
    return "#" + CSS.escape(el.id);
  }}
  function isVisible(el) {{
    const style = window.getComputedStyle(el);
    if (style.display === "none" || style.visibility === "hidden") {{
      return false;
    }}
    return el.getClientRects().length > 0 || el.tagName.toLowerCase() === "option";
  }}
  function textFor(el) {{
    const tag = el.tagName.toLowerCase();
    if (tag === "input" || tag === "textarea" || tag === "select") {{
      return "";
    }}
    return (el.innerText || el.textContent || "").trim();
  }}
  function collectInteractive() {{
    return Array.from(document.querySelectorAll("a[id],button[id],input[id],textarea[id],select[id]")).map((el) => {{
      const tag = el.tagName.toLowerCase();
      const selectedLabels = tag === "select"
        ? Array.from(el.selectedOptions || []).map((item) => (item.textContent || "").trim()).filter(Boolean)
        : [];
      const value = ("value" in el) ? String(el.value || "") : null;
      return {{
        tag,
        id: el.id || null,
        selector: selectorFor(el),
        center_x: null,
        center_y: null,
        name: el.getAttribute("name"),
        text: textFor(el),
        value,
        input_type: el.getAttribute("type"),
        checked: ("checked" in el) ? !!el.checked : null,
        selected_labels: selectedLabels,
        class_list: Array.from(el.classList || []),
        visible: isVisible(el),
        disabled: !!el.disabled
      }};
    }});
  }}
  function sendObservation() {{
    const active = document.activeElement;
    fetch(reportUrl, {{
      method: "POST",
      headers: {{ "content-type": "application/json" }},
      body: JSON.stringify({{
        page_url: window.location.href,
        focused_tag: active ? active.tagName.toLowerCase() : null,
        focused_id: active && active.id ? active.id : null,
        visible_text_excerpt: (document.body.innerText || "").trim().slice(0, 4000),
        interactive_elements: collectInteractive(),
        scroll_targets: [],
        dom_elements: []
      }})
    }}).catch(() => {{}});
  }}
  let timer = null;
  function scheduleObservation() {{
    if (timer !== null) {{
      window.clearTimeout(timer);
    }}
    timer = window.setTimeout(() => {{
      timer = null;
      sendObservation();
    }}, 30);
  }}
  document.addEventListener("DOMContentLoaded", scheduleObservation);
  window.addEventListener("load", scheduleObservation);
  document.addEventListener("input", scheduleObservation, true);
  document.addEventListener("change", scheduleObservation, true);
  document.addEventListener("focusin", scheduleObservation, true);
  document.addEventListener("click", () => window.setTimeout(scheduleObservation, 20), true);
  scheduleObservation();
}})();"##,
        report_path = report_path
    )
}

fn history_entries_for_ticket<'a>(
    session: &'a WorkflowSession,
    ticket_id: &str,
) -> Vec<&'a WorkflowHistoryEntry> {
    session
        .history_entries
        .iter()
        .rev()
        .filter(|entry| entry.ticket_id == ticket_id)
        .collect()
}

fn saved_update_entries_for_ticket<'a>(
    session: &'a WorkflowSession,
    ticket_id: &str,
) -> Vec<&'a WorkflowHistoryEntry> {
    history_entries_for_ticket(session, ticket_id)
        .into_iter()
        .filter(|entry| entry.action == "Saved dispatch update")
        .collect()
}

fn latest_saved_update_entry_for_ticket<'a>(
    session: &'a WorkflowSession,
    ticket_id: &str,
) -> Option<&'a WorkflowHistoryEntry> {
    saved_update_entries_for_ticket(session, ticket_id)
        .into_iter()
        .next()
}

fn latest_history_entry_for_ticket<'a>(
    session: &'a WorkflowSession,
    ticket_id: &str,
) -> Option<&'a WorkflowHistoryEntry> {
    history_entries_for_ticket(session, ticket_id)
        .into_iter()
        .next()
}

fn history_entry_matches_spec(session: &WorkflowSession, entry: &WorkflowHistoryEntry) -> bool {
    entry.ticket_id == session.spec.ticket_id
        && entry.actor == session.spec.username
        && entry.assignee == session.spec.assignee
        && entry.status == session.spec.status
        && entry.note == session.spec.note
}

fn target_history_entry(session: &WorkflowSession) -> Option<&WorkflowHistoryEntry> {
    latest_saved_update_entry_for_ticket(session, &session.spec.ticket_id)
        .filter(|entry| history_entry_matches_spec(session, entry))
}

fn distractor_saved_update_entry(session: &WorkflowSession) -> Option<&WorkflowHistoryEntry> {
    latest_saved_update_entry_for_ticket(session, &session.spec.distractor_ticket_id)
}

fn distractor_ticket_matches_spec(session: &WorkflowSession) -> bool {
    let Some(ticket) = session.tickets.get(&session.spec.distractor_ticket_id) else {
        return false;
    };
    ticket.current_assignee == session.spec.distractor_assignee
        && ticket.current_note == session.spec.distractor_note
        && ticket.current_status == session.spec.distractor_status
}

fn workflow_fields(session: &WorkflowSession) -> Vec<BridgeField> {
    let saved_target = session.tickets.get(&session.spec.ticket_id);
    let saved_distractor = session.tickets.get(&session.spec.distractor_ticket_id);
    let latest_history = latest_history_entry_for_ticket(session, &session.spec.ticket_id);
    let history_match = target_history_entry(session);
    let distractor_saved_update = distractor_saved_update_entry(session);
    vec![
        BridgeField {
            key: "workflow_case_id".to_string(),
            value: session.spec.case_id.clone(),
        },
        BridgeField {
            key: "workflow_scenario".to_string(),
            value: match session.spec.scenario {
                WorkflowScenario::TicketRouting => "ticket_routing".to_string(),
                WorkflowScenario::QueueVerification => "queue_verification".to_string(),
                WorkflowScenario::AuditHistory => "audit_history".to_string(),
                WorkflowScenario::MutationIsolation => "mutation_isolation".to_string(),
            },
        },
        BridgeField {
            key: "username".to_string(),
            value: session.spec.username.clone(),
        },
        BridgeField {
            key: "password".to_string(),
            value: session.spec.password.clone(),
        },
        BridgeField {
            key: "ticket_id".to_string(),
            value: session.spec.ticket_id.clone(),
        },
        BridgeField {
            key: "assignee".to_string(),
            value: session.spec.assignee.clone(),
        },
        BridgeField {
            key: "note".to_string(),
            value: session.spec.note.clone(),
        },
        BridgeField {
            key: "status".to_string(),
            value: session.spec.status.clone(),
        },
        BridgeField {
            key: "queue_search".to_string(),
            value: session.spec.queue_search.clone(),
        },
        BridgeField {
            key: "queue_status_filter".to_string(),
            value: session.spec.queue_status_filter.clone(),
        },
        BridgeField {
            key: "distractor_ticket_id".to_string(),
            value: session.spec.distractor_ticket_id.clone(),
        },
        BridgeField {
            key: "distractor_assignee".to_string(),
            value: session.spec.distractor_assignee.clone(),
        },
        BridgeField {
            key: "distractor_status".to_string(),
            value: session.spec.distractor_status.clone(),
        },
        BridgeField {
            key: "distractor_note".to_string(),
            value: session.spec.distractor_note.clone(),
        },
        BridgeField {
            key: "current_username".to_string(),
            value: session.login_username.clone(),
        },
        BridgeField {
            key: "current_password".to_string(),
            value: session.login_password.clone(),
        },
        BridgeField {
            key: "current_queue_search".to_string(),
            value: session.queue_search.clone(),
        },
        BridgeField {
            key: "current_queue_status_filter".to_string(),
            value: session.queue_status_filter.clone(),
        },
        BridgeField {
            key: "active_ticket_id".to_string(),
            value: session.active_ticket_id.clone(),
        },
        BridgeField {
            key: "current_assignee".to_string(),
            value: session.draft_assignee.clone(),
        },
        BridgeField {
            key: "current_status".to_string(),
            value: session.draft_status.clone(),
        },
        BridgeField {
            key: "current_note".to_string(),
            value: session.draft_note.clone(),
        },
        BridgeField {
            key: "saved_assignee".to_string(),
            value: saved_target
                .map(|ticket| ticket.current_assignee.clone())
                .unwrap_or_default(),
        },
        BridgeField {
            key: "saved_status".to_string(),
            value: saved_target
                .map(|ticket| ticket.current_status.clone())
                .unwrap_or_default(),
        },
        BridgeField {
            key: "saved_note".to_string(),
            value: saved_target
                .map(|ticket| ticket.current_note.clone())
                .unwrap_or_default(),
        },
        BridgeField {
            key: "confirmation_seen".to_string(),
            value: session.confirmation_seen.to_string(),
        },
        BridgeField {
            key: "queue_verified".to_string(),
            value: session.queue_verified.to_string(),
        },
        BridgeField {
            key: "history_verified".to_string(),
            value: session.history_verified.to_string(),
        },
        BridgeField {
            key: "distractor_history_verified".to_string(),
            value: session.distractor_history_verified.to_string(),
        },
        BridgeField {
            key: "history_event_exists".to_string(),
            value: history_match.is_some().to_string(),
        },
        BridgeField {
            key: "history_event_ticket_id".to_string(),
            value: latest_history
                .map(|entry| entry.ticket_id.clone())
                .unwrap_or_default(),
        },
        BridgeField {
            key: "history_event_actor".to_string(),
            value: latest_history
                .map(|entry| entry.actor.clone())
                .unwrap_or_default(),
        },
        BridgeField {
            key: "history_event_action".to_string(),
            value: latest_history
                .map(|entry| entry.action.clone())
                .unwrap_or_default(),
        },
        BridgeField {
            key: "history_event_assignee".to_string(),
            value: latest_history
                .map(|entry| entry.assignee.clone())
                .unwrap_or_default(),
        },
        BridgeField {
            key: "history_event_status".to_string(),
            value: latest_history
                .map(|entry| entry.status.clone())
                .unwrap_or_default(),
        },
        BridgeField {
            key: "history_event_note".to_string(),
            value: latest_history
                .map(|entry| entry.note.clone())
                .unwrap_or_default(),
        },
        BridgeField {
            key: "history_event_count".to_string(),
            value: saved_update_entries_for_ticket(session, &session.spec.ticket_id)
                .len()
                .to_string(),
        },
        BridgeField {
            key: "saved_target_matches".to_string(),
            value: target_ticket_matches_spec(session).to_string(),
        },
        BridgeField {
            key: "saved_distractor_assignee".to_string(),
            value: saved_distractor
                .map(|ticket| ticket.current_assignee.clone())
                .unwrap_or_default(),
        },
        BridgeField {
            key: "saved_distractor_status".to_string(),
            value: saved_distractor
                .map(|ticket| ticket.current_status.clone())
                .unwrap_or_default(),
        },
        BridgeField {
            key: "saved_distractor_note".to_string(),
            value: saved_distractor
                .map(|ticket| ticket.current_note.clone())
                .unwrap_or_default(),
        },
        BridgeField {
            key: "saved_distractor_matches".to_string(),
            value: distractor_ticket_matches_spec(session).to_string(),
        },
        BridgeField {
            key: "distractor_saved_update_exists".to_string(),
            value: distractor_saved_update.is_some().to_string(),
        },
        BridgeField {
            key: "distractor_saved_update_count".to_string(),
            value: saved_update_entries_for_ticket(session, &session.spec.distractor_ticket_id)
                .len()
                .to_string(),
        },
        BridgeField {
            key: "current_page_kind".to_string(),
            value: match session.current_page {
                WorkflowPage::Login => "login".to_string(),
                WorkflowPage::Queue => "queue".to_string(),
                WorkflowPage::Detail { .. } => "detail".to_string(),
                WorkflowPage::Review => "review".to_string(),
                WorkflowPage::Confirmation => "confirmation".to_string(),
                WorkflowPage::History { .. } => "history".to_string(),
            },
        },
    ]
}

fn workflow_visible_text(session: &WorkflowSession, page: &WorkflowPage) -> String {
    match page {
        WorkflowPage::Login => {
            format!(
                "Dispatch Console Sign in to continue. {}",
                session.spec.instruction
            )
        }
        WorkflowPage::Queue => {
            let rows = visible_queue_tickets(session)
                .into_iter()
                .map(|ticket| {
                    format!(
                        "{} {} {} {}",
                        ticket.ticket_id,
                        ticket.title,
                        ticket.current_status,
                        display_assignee(&ticket.current_assignee)
                    )
                })
                .collect::<Vec<_>>()
                .join(" ");
            format!(
                "Active dispatch queue. Search {}. Filter {}. Visible tickets {}. {}",
                session.queue_search,
                session.queue_status_filter,
                rows,
                session.spec.instruction
            )
        }
        WorkflowPage::Detail { ticket_id } => format!(
            "Ticket {}. Assign team {}. Ticket status {}. Dispatch note {}. {}",
            ticket_id, session.draft_assignee, session.draft_status, session.draft_note, session.spec.instruction
        ),
        WorkflowPage::Review => format!(
            "Review queued update. Ticket {}. Draft assignee {}. Draft status {}. Draft note {}. {}",
            session.active_ticket_id, session.draft_assignee, session.draft_status, session.draft_note, session.spec.instruction
        ),
        WorkflowPage::Confirmation => {
            let saved_ticket = session
                .tickets
                .get(&session.active_ticket_id)
                .or_else(|| session.tickets.get(&session.spec.ticket_id));
            let saved_assignee = saved_ticket
                .map(|ticket| display_assignee(&ticket.current_assignee))
                .unwrap_or_else(|| "Unassigned".to_string());
            let saved_status = saved_ticket
                .map(|ticket| ticket.current_status.clone())
                .unwrap_or_else(|| "Unknown".to_string());
            let saved_note = saved_ticket
                .map(|ticket| ticket.current_note.clone())
                .unwrap_or_default();
            format!(
                "Assignment confirmation. Ticket {} routed to {}. Saved status {}. Saved note {}. Queue verified {}. History verified {}. {}",
                session.active_ticket_id,
                saved_assignee,
                saved_status,
                saved_note,
                session.queue_verified,
                session.history_verified,
                session.spec.instruction
            )
        }
        WorkflowPage::History { ticket_id } => {
            let entries = history_entries_for_ticket(session, ticket_id)
                .into_iter()
                .map(|entry| {
                    format!(
                        "{} {} {} {} {}",
                        entry.ticket_id, entry.actor, entry.assignee, entry.status, entry.note
                    )
                })
                .collect::<Vec<_>>()
                .join(" ");
            format!(
                "Audit history for ticket {}. Entries {}. History verified {}. {}",
                ticket_id, entries, session.history_verified, session.spec.instruction
            )
        }
    }
}

fn synthesized_interactive_elements(
    session: &WorkflowSession,
    page: &WorkflowPage,
) -> Vec<BridgeInteractiveElement> {
    match page {
        WorkflowPage::Login => vec![
            text_input("#username", "username", &session.login_username),
            password_input("#password", "password", &session.login_password),
            button("#sign-in", "Sign in"),
        ],
        WorkflowPage::Queue => {
            let mut elements = match session.spec.scenario {
                WorkflowScenario::TicketRouting => Vec::new(),
                WorkflowScenario::QueueVerification
                | WorkflowScenario::AuditHistory
                | WorkflowScenario::MutationIsolation => vec![
                    text_input("#queue-search", "search", &session.queue_search),
                    select_input_named(
                        "#queue-status-filter",
                        "status",
                        &session.queue_status_filter,
                    ),
                    button("#apply-filters", "Apply filters"),
                ],
            };
            elements.extend(
                visible_queue_tickets(session)
                    .into_iter()
                    .flat_map(|ticket| {
                        let mut row_links = vec![link(
                            &ticket_link_selector(&ticket.ticket_id),
                            &ticket.ticket_id,
                        )];
                        if matches!(session.spec.scenario, WorkflowScenario::MutationIsolation) {
                            row_links.push(link(
                                &ticket_history_link_selector(&ticket.ticket_id),
                                "History",
                            ));
                        }
                        row_links
                    }),
            );
            elements
        }
        WorkflowPage::Detail { ticket_id } => vec![
            link("#queue-link", "Queue"),
            select_input("#assignee", &session.draft_assignee),
            select_input_named("#status", "status", &session.draft_status),
            text_area("#note", &session.draft_note),
            button(
                match session.spec.scenario {
                    WorkflowScenario::TicketRouting => "#submit-update",
                    WorkflowScenario::QueueVerification | WorkflowScenario::AuditHistory => {
                        "#review-update"
                    }
                    WorkflowScenario::MutationIsolation => "#review-update",
                },
                match session.spec.scenario {
                    WorkflowScenario::TicketRouting => "Submit update",
                    WorkflowScenario::QueueVerification | WorkflowScenario::AuditHistory => {
                        "Review update"
                    }
                    WorkflowScenario::MutationIsolation => "Review update",
                },
            ),
            link(&ticket_link_selector(ticket_id), ticket_id),
        ],
        WorkflowPage::Review => {
            let mut elements = vec![
                link("#queue-link", "Queue"),
                button("#edit-update", "Edit draft"),
                button("#confirm-update", "Confirm update"),
            ];
            if matches!(
                session.spec.scenario,
                WorkflowScenario::AuditHistory | WorkflowScenario::MutationIsolation
            ) {
                elements.push(button("#cancel-update", "Cancel draft"));
            }
            elements
        }
        WorkflowPage::Confirmation => {
            let mut elements = vec![link("#queue-link", "Queue")];
            if matches!(
                session.spec.scenario,
                WorkflowScenario::AuditHistory | WorkflowScenario::MutationIsolation
            ) {
                elements.push(link("#history-link", "Open audit history"));
                elements.push(button("#reopen-ticket", "Reopen ticket"));
            }
            elements
        }
        WorkflowPage::History { .. } => vec![
            link("#queue-link", "Queue"),
            link("#confirmation-link", "Confirmation"),
            button("#reopen-ticket", "Reopen ticket"),
        ],
    }
    .into_iter()
    .map(|mut element| {
        if matches!(page, WorkflowPage::Queue)
            && element.selector.as_deref()
                == Some(ticket_link_selector(&session.spec.ticket_id).as_str())
        {
            element.class_list.push("target-ticket".to_string());
        }
        element
    })
    .collect()
}

fn current_page_url(session: &WorkflowSession) -> String {
    match &session.current_page {
        WorkflowPage::Login => format!(
            "{}/workflow/{}/login",
            session.base_url, session.bridge_state.session_id
        ),
        WorkflowPage::Queue => format!(
            "{}/workflow/{}/queue",
            session.base_url, session.bridge_state.session_id
        ),
        WorkflowPage::Detail { ticket_id } => format!(
            "{}/workflow/{}/tickets/{}",
            session.base_url, session.bridge_state.session_id, ticket_id
        ),
        WorkflowPage::Review => format!(
            "{}/workflow/{}/review",
            session.base_url, session.bridge_state.session_id
        ),
        WorkflowPage::Confirmation => format!(
            "{}/workflow/{}/confirmation",
            session.base_url, session.bridge_state.session_id
        ),
        WorkflowPage::History { ticket_id } => format!(
            "{}/workflow/{}/tickets/{}/history",
            session.base_url, session.bridge_state.session_id, ticket_id
        ),
    }
}

fn page_from_url(url: &str) -> Option<WorkflowPage> {
    if url.contains("/login") {
        return Some(WorkflowPage::Login);
    }
    if url.contains("/queue") {
        return Some(WorkflowPage::Queue);
    }
    if url.contains("/review") {
        return Some(WorkflowPage::Review);
    }
    if url.contains("/confirmation") {
        return Some(WorkflowPage::Confirmation);
    }
    let marker = "/tickets/";
    let start = url.find(marker)? + marker.len();
    let ticket_id = url[start..]
        .split('/')
        .next()
        .filter(|value| !value.is_empty())?;
    if url.contains("/history") {
        return Some(WorkflowPage::History {
            ticket_id: ticket_id.to_string(),
        });
    }
    Some(WorkflowPage::Detail {
        ticket_id: ticket_id.to_string(),
    })
}

fn workflow_initial_tickets() -> BTreeMap<String, WorkflowTicketRecord> {
    [
        (
            "T-101",
            "Printer outage in west wing",
            "Facilities",
            "New",
            "Facilities",
            "",
        ),
        (
            "T-202",
            "Fiber handoff requires vendor logs",
            "Network Ops",
            "Awaiting Dispatch",
            "",
            "",
        ),
        (
            "T-204",
            "Metro fiber outage",
            "Network Ops",
            "Awaiting Dispatch",
            "",
            "",
        ),
        (
            "T-215",
            "Fiber maintenance escalation",
            "Network Ops",
            "Awaiting Dispatch",
            "",
            "",
        ),
        (
            "T-303",
            "Invoice reminder needs correction",
            "Billing Review",
            "Pending Review",
            "",
            "",
        ),
        (
            "T-310",
            "Recurring invoice delta",
            "Billing Review",
            "Pending Review",
            "",
            "",
        ),
        (
            "T-318",
            "Invoice adjustment awaiting callback",
            "Billing Review",
            "Pending Review",
            "",
            "",
        ),
    ]
    .into_iter()
    .map(
        |(ticket_id, title, suggested_team, current_status, current_assignee, current_note)| {
            (
                ticket_id.to_string(),
                WorkflowTicketRecord {
                    ticket_id: ticket_id.to_string(),
                    title: title.to_string(),
                    suggested_team: suggested_team.to_string(),
                    current_status: current_status.to_string(),
                    current_assignee: current_assignee.to_string(),
                    current_note: current_note.to_string(),
                },
            )
        },
    )
    .collect()
}

fn workflow_initial_history_entries() -> Vec<WorkflowHistoryEntry> {
    vec![
        WorkflowHistoryEntry {
            ticket_id: "T-204".to_string(),
            actor: "dispatch.agent".to_string(),
            action: "Queued vendor follow-up".to_string(),
            assignee: String::new(),
            status: "Awaiting Dispatch".to_string(),
            note: String::new(),
        },
        WorkflowHistoryEntry {
            ticket_id: "T-215".to_string(),
            actor: "dispatch.agent".to_string(),
            action: "Viewed ticket".to_string(),
            assignee: String::new(),
            status: "Awaiting Dispatch".to_string(),
            note: String::new(),
        },
        WorkflowHistoryEntry {
            ticket_id: "T-310".to_string(),
            actor: "dispatch.agent".to_string(),
            action: "Requested billing callback".to_string(),
            assignee: String::new(),
            status: "Pending Review".to_string(),
            note: "Awaiting customer callback".to_string(),
        },
        WorkflowHistoryEntry {
            ticket_id: "T-318".to_string(),
            actor: "dispatch.agent".to_string(),
            action: "Requested billing callback".to_string(),
            assignee: String::new(),
            status: "Pending Review".to_string(),
            note: "Awaiting customer callback".to_string(),
        },
    ]
}

fn display_assignee(value: &str) -> String {
    if value.trim().is_empty() {
        "Unassigned".to_string()
    } else {
        value.to_string()
    }
}

fn ticket_matches_search(ticket: &WorkflowTicketRecord, search: &str) -> bool {
    if search.is_empty() {
        return true;
    }
    let search = search.to_ascii_lowercase();
    ticket.ticket_id.to_ascii_lowercase().contains(&search)
        || ticket.title.to_ascii_lowercase().contains(&search)
        || ticket.suggested_team.to_ascii_lowercase().contains(&search)
}

fn visible_queue_tickets(session: &WorkflowSession) -> Vec<&WorkflowTicketRecord> {
    let mut tickets = session
        .tickets
        .values()
        .filter(|ticket| {
            (session.queue_status_filter.is_empty()
                || ticket.current_status == session.queue_status_filter)
                && ticket_matches_search(ticket, &session.queue_search)
        })
        .collect::<Vec<_>>();
    if matches!(
        session.spec.scenario,
        WorkflowScenario::QueueVerification | WorkflowScenario::AuditHistory
    ) && session.queue_search.trim().is_empty()
    {
        tickets.truncate(2);
    }
    tickets
}

fn reset_draft_from_saved_ticket(session: &mut WorkflowSession, ticket_id: &str) {
    if let Some(ticket) = session.tickets.get(ticket_id) {
        session.draft_assignee = ticket.current_assignee.clone();
        session.draft_status = ticket.current_status.clone();
        session.draft_note = ticket.current_note.clone();
    }
}

fn persist_ticket_update(session: &mut WorkflowSession, ticket_id: &str) {
    if let Some(ticket) = session.tickets.get_mut(ticket_id) {
        ticket.current_assignee = session.draft_assignee.clone();
        if !session.draft_status.is_empty() {
            ticket.current_status = session.draft_status.clone();
        }
        ticket.current_note = session.draft_note.clone();
    }
}

fn append_history_entry(session: &mut WorkflowSession, ticket_id: &str) {
    session.history_entries.push(WorkflowHistoryEntry {
        ticket_id: ticket_id.to_string(),
        actor: session.spec.username.clone(),
        action: "Saved dispatch update".to_string(),
        assignee: session.draft_assignee.clone(),
        status: session.draft_status.clone(),
        note: session.draft_note.clone(),
    });
}

fn target_ticket_matches_spec(session: &WorkflowSession) -> bool {
    let Some(ticket) = session.tickets.get(&session.spec.ticket_id) else {
        return false;
    };
    let status_matches =
        session.spec.status.is_empty() || ticket.current_status == session.spec.status;
    ticket.current_assignee == session.spec.assignee
        && ticket.current_note == session.spec.note
        && status_matches
}

fn maybe_complete_workflow_verification(session: &mut WorkflowSession, visible_text: Option<&str>) {
    maybe_complete_queue_verification(session, visible_text);
    maybe_complete_audit_history_verification(session, visible_text);
    maybe_complete_mutation_isolation_verification(session, visible_text);
}

fn maybe_complete_queue_verification(session: &mut WorkflowSession, visible_text: Option<&str>) {
    if !matches!(session.spec.scenario, WorkflowScenario::QueueVerification)
        || !session.confirmation_seen
        || !matches!(session.current_page, WorkflowPage::Queue)
    {
        return;
    }
    let target_visible = visible_queue_tickets(session)
        .into_iter()
        .any(|ticket| ticket.ticket_id == session.spec.ticket_id);
    let observed_match = visible_text.is_some_and(|text| {
        text.contains(&session.spec.ticket_id)
            && text.contains(&session.spec.assignee)
            && text.contains(&session.spec.status)
    });
    if target_visible && observed_match && target_ticket_matches_spec(session) {
        session.queue_verified = true;
        session.reward = 1.0;
        session.terminated = true;
        session.truncated = false;
    }
}

fn maybe_complete_audit_history_verification(
    session: &mut WorkflowSession,
    visible_text: Option<&str>,
) {
    if !matches!(session.spec.scenario, WorkflowScenario::AuditHistory)
        || !session.confirmation_seen
        || !matches!(session.current_page, WorkflowPage::History { .. })
    {
        return;
    }
    let history_match = target_history_entry(session);
    let observed_match = visible_text.is_some_and(|text| {
        text.contains(&session.spec.ticket_id)
            && text.contains(&session.spec.assignee)
            && text.contains(&session.spec.status)
            && text.contains(&session.spec.note)
    });
    if history_match.is_some() && observed_match && target_ticket_matches_spec(session) {
        session.history_verified = true;
        session.reward = 1.0;
        session.terminated = true;
        session.truncated = false;
    }
}

fn maybe_complete_mutation_isolation_verification(
    session: &mut WorkflowSession,
    visible_text: Option<&str>,
) {
    if !matches!(session.spec.scenario, WorkflowScenario::MutationIsolation)
        || !session.confirmation_seen
    {
        return;
    }

    if matches!(session.current_page, WorkflowPage::Queue) && !session.queue_verified {
        let visible_tickets = visible_queue_tickets(session);
        let target_visible = visible_tickets
            .iter()
            .any(|ticket| ticket.ticket_id == session.spec.ticket_id);
        let distractor_visible = visible_tickets
            .iter()
            .any(|ticket| ticket.ticket_id == session.spec.distractor_ticket_id);
        let observed_match = visible_text.is_some_and(|text| {
            text.contains(&session.spec.ticket_id)
                && text.contains(&session.spec.assignee)
                && text.contains(&session.spec.status)
                && text.contains(&session.spec.distractor_ticket_id)
                && text.contains(&display_assignee(&session.spec.distractor_assignee))
                && text.contains(&session.spec.distractor_status)
        });
        if target_visible
            && distractor_visible
            && observed_match
            && target_ticket_matches_spec(session)
            && distractor_ticket_matches_spec(session)
        {
            session.queue_verified = true;
        }
    }

    if matches!(
        session.current_page,
        WorkflowPage::History { ref ticket_id } if ticket_id == &session.spec.ticket_id
    ) && !session.history_verified
    {
        let observed_match = visible_text.is_some_and(|text| {
            text.contains(&session.spec.ticket_id)
                && text.contains(&session.spec.assignee)
                && text.contains(&session.spec.status)
                && text.contains(&session.spec.note)
        });
        if observed_match
            && target_history_entry(session).is_some()
            && target_ticket_matches_spec(session)
        {
            session.history_verified = true;
        }
    }

    if matches!(
        session.current_page,
        WorkflowPage::History { ref ticket_id } if ticket_id == &session.spec.distractor_ticket_id
    ) && !session.distractor_history_verified
    {
        let observed_match =
            visible_text.is_some_and(|text| text.contains(&session.spec.distractor_ticket_id));
        if observed_match
            && distractor_saved_update_entry(session).is_none()
            && distractor_ticket_matches_spec(session)
        {
            session.distractor_history_verified = true;
        }
    }

    if session.queue_verified
        && session.history_verified
        && session.distractor_history_verified
        && target_ticket_matches_spec(session)
        && distractor_ticket_matches_spec(session)
    {
        session.reward = 1.0;
        session.terminated = true;
        session.truncated = false;
    }
}

fn active_ticket_id_from_page(session: &WorkflowSession) -> Option<String> {
    match &session.current_page {
        WorkflowPage::Detail { ticket_id } => Some(ticket_id.clone()),
        WorkflowPage::History { ticket_id } => Some(ticket_id.clone()),
        WorkflowPage::Review | WorkflowPage::Confirmation => Some(session.active_ticket_id.clone()),
        WorkflowPage::Login | WorkflowPage::Queue => None,
    }
}

fn ticket_id_for_selector(session: &WorkflowSession, selector: &str) -> Option<String> {
    session
        .tickets
        .keys()
        .find(|ticket_id| selector == ticket_link_selector(ticket_id))
        .cloned()
}

fn ticket_id_for_history_selector(session: &WorkflowSession, selector: &str) -> Option<String> {
    session
        .tickets
        .keys()
        .find(|ticket_id| selector == ticket_history_link_selector(ticket_id))
        .cloned()
}

fn ticket_link_selector(ticket_id: &str) -> String {
    format!("#{}", ticket_link_id(ticket_id))
}

fn ticket_link_id(ticket_id: &str) -> String {
    format!("ticket-link-{}", sanitize_token(ticket_id))
}

fn ticket_history_link_selector(ticket_id: &str) -> String {
    format!("#{}", ticket_history_link_id(ticket_id))
}

fn ticket_history_link_id(ticket_id: &str) -> String {
    format!("ticket-history-link-{}", sanitize_token(ticket_id))
}

fn sanitize_token(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
}

fn observation_value(elements: &[BridgeInteractiveElement], selector: &str) -> Option<String> {
    elements
        .iter()
        .find(|element| element.selector.as_deref() == Some(selector))
        .and_then(|element| element.value.clone())
}

fn observation_selected_label(
    elements: &[BridgeInteractiveElement],
    selector: &str,
) -> Option<String> {
    elements
        .iter()
        .find(|element| element.selector.as_deref() == Some(selector))
        .and_then(|element| element.selected_labels.first().cloned())
}

fn link(selector: &str, text: &str) -> BridgeInteractiveElement {
    BridgeInteractiveElement {
        tag: "a".to_string(),
        id: selector.strip_prefix('#').map(str::to_string),
        selector: Some(selector.to_string()),
        center_x: None,
        center_y: None,
        name: None,
        text: text.to_string(),
        value: None,
        input_type: None,
        checked: None,
        selected_labels: Vec::new(),
        class_list: Vec::new(),
        visible: true,
        disabled: false,
    }
}

fn button(selector: &str, text: &str) -> BridgeInteractiveElement {
    BridgeInteractiveElement {
        tag: "button".to_string(),
        id: selector.strip_prefix('#').map(str::to_string),
        selector: Some(selector.to_string()),
        center_x: None,
        center_y: None,
        name: None,
        text: text.to_string(),
        value: None,
        input_type: None,
        checked: None,
        selected_labels: Vec::new(),
        class_list: Vec::new(),
        visible: true,
        disabled: false,
    }
}

fn text_input(selector: &str, name: &str, value: &str) -> BridgeInteractiveElement {
    BridgeInteractiveElement {
        tag: "input".to_string(),
        id: selector.strip_prefix('#').map(str::to_string),
        selector: Some(selector.to_string()),
        center_x: None,
        center_y: None,
        name: Some(name.to_string()),
        text: String::new(),
        value: Some(value.to_string()),
        input_type: Some("text".to_string()),
        checked: None,
        selected_labels: Vec::new(),
        class_list: Vec::new(),
        visible: true,
        disabled: false,
    }
}

fn password_input(selector: &str, name: &str, value: &str) -> BridgeInteractiveElement {
    BridgeInteractiveElement {
        input_type: Some("password".to_string()),
        ..text_input(selector, name, value)
    }
}

fn text_area(selector: &str, value: &str) -> BridgeInteractiveElement {
    BridgeInteractiveElement {
        tag: "textarea".to_string(),
        id: selector.strip_prefix('#').map(str::to_string),
        selector: Some(selector.to_string()),
        center_x: None,
        center_y: None,
        name: Some("note".to_string()),
        text: String::new(),
        value: Some(value.to_string()),
        input_type: None,
        checked: None,
        selected_labels: Vec::new(),
        class_list: Vec::new(),
        visible: true,
        disabled: false,
    }
}

fn select_input(selector: &str, selected: &str) -> BridgeInteractiveElement {
    select_input_named(selector, "assignee", selected)
}

fn select_input_named(selector: &str, name: &str, selected: &str) -> BridgeInteractiveElement {
    BridgeInteractiveElement {
        tag: "select".to_string(),
        id: selector.strip_prefix('#').map(str::to_string),
        selector: Some(selector.to_string()),
        center_x: None,
        center_y: None,
        name: Some(name.to_string()),
        text: String::new(),
        value: Some(selected.to_string()),
        input_type: None,
        checked: None,
        selected_labels: if selected.is_empty() {
            Vec::new()
        } else {
            vec![selected.to_string()]
        },
        class_list: Vec::new(),
        visible: true,
        disabled: false,
    }
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::computer_use_suite::types::{AllowedToolProfile, LocalJudge, RecipeId, TaskSet};

    fn field_value<'a>(state: &'a BridgeState, key: &str) -> Option<&'a str> {
        state.info.fields.iter().find_map(|field| {
            if field.key == key {
                Some(field.value.as_str())
            } else {
                None
            }
        })
    }

    fn workflow_case(
        case_id: &str,
        env_id: &str,
        task_set: TaskSet,
        recipe: RecipeId,
    ) -> ComputerUseCase {
        ComputerUseCase {
            id: case_id.to_string(),
            env_id: env_id.to_string(),
            seed: 7,
            task_set,
            max_steps: 12,
            timeout_seconds: 25,
            allowed_tool_profile: AllowedToolProfile::BrowserCoreWithSelect,
            expected_reward_floor: 1.0,
            expected_pass: true,
            local_judge: LocalJudge::BridgeReward,
            recipe,
        }
    }

    #[tokio::test]
    async fn workflow_oracle_progresses_to_confirmation() -> Result<()> {
        let mut process = WorkflowBridgeProcess::start().await?;
        let client = process.client();
        let created = client
            .create_session(&workflow_case(
                "workflow_ticket_routing_network_ops",
                "workflow-ticket-routing",
                TaskSet::Workflow,
                RecipeId::WorkflowTicketRouting,
            ))
            .await?;

        client
            .oracle_step(
                &created.session_id,
                "type_selector",
                json!({ "selector": "#username", "text": "dispatch.agent" }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "type_selector",
                json!({ "selector": "#password", "text": "dispatch-204" }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "click_selector",
                json!({ "selector": "#sign-in" }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "click_selector",
                json!({ "selector": ticket_link_selector("T-204") }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "select_label",
                json!({ "selector": "#assignee", "label": "Network Ops" }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "type_selector",
                json!({ "selector": "#note", "text": "Escalate fiber outage to on-call" }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "click_selector",
                json!({ "selector": "#submit-update" }),
            )
            .await?;

        let final_state = client.state(&created.session_id).await?;
        assert!(final_state.terminated);
        assert_eq!(final_state.reward, 1.0);
        assert!(final_state
            .info
            .page_url
            .as_deref()
            .is_some_and(|url| url.contains("/confirmation")));

        process.stop().await;
        Ok(())
    }

    #[tokio::test]
    async fn workflow_queue_verification_oracle_requires_queue_revisit() -> Result<()> {
        let mut process = WorkflowBridgeProcess::start().await?;
        let client = process.client();
        let created = client
            .create_session(&workflow_case(
                "workflow_queue_verification_network_ops",
                "workflow-queue-verification",
                TaskSet::WorkflowRich,
                RecipeId::WorkflowQueueVerification,
            ))
            .await?;

        client
            .oracle_step(
                &created.session_id,
                "type_selector",
                json!({ "selector": "#username", "text": "dispatch.agent" }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "type_selector",
                json!({ "selector": "#password", "text": "dispatch-215" }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "click_selector",
                json!({ "selector": "#sign-in" }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "type_selector",
                json!({ "selector": "#queue-search", "text": "fiber" }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "select_label",
                json!({ "selector": "#queue-status-filter", "label": "Awaiting Dispatch" }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "click_selector",
                json!({ "selector": "#apply-filters" }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "click_selector",
                json!({ "selector": ticket_link_selector("T-215") }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "select_label",
                json!({ "selector": "#assignee", "label": "Network Ops" }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "select_label",
                json!({ "selector": "#status", "label": "Escalated" }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "type_selector",
                json!({ "selector": "#note", "text": "Escalate fiber outage to on-call" }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "click_selector",
                json!({ "selector": "#review-update" }),
            )
            .await?;

        let review_state = client.state(&created.session_id).await?;
        assert!(!review_state.terminated);
        assert_eq!(
            field_value(&review_state, "active_ticket_id"),
            Some("T-215")
        );

        client
            .oracle_step(
                &created.session_id,
                "click_selector",
                json!({ "selector": "#confirm-update" }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "click_selector",
                json!({ "selector": "#queue-link" }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "select_label",
                json!({ "selector": "#queue-status-filter", "label": "Escalated" }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "click_selector",
                json!({ "selector": "#apply-filters" }),
            )
            .await?;

        let final_state = client.state(&created.session_id).await?;
        assert!(final_state.terminated);
        assert_eq!(final_state.reward, 1.0);
        assert_eq!(field_value(&final_state, "queue_verified"), Some("true"));
        assert!(final_state
            .info
            .page_url
            .as_deref()
            .is_some_and(|url| url.contains("/queue")));

        process.stop().await;
        Ok(())
    }

    #[tokio::test]
    async fn workflow_audit_history_oracle_requires_history_verification() -> Result<()> {
        let mut process = WorkflowBridgeProcess::start().await?;
        let client = process.client();
        let created = client
            .create_session(&workflow_case(
                "workflow_audit_history_network_ops",
                "workflow-audit-history",
                TaskSet::WorkflowAudit,
                RecipeId::WorkflowAuditHistory,
            ))
            .await?;

        client
            .oracle_step(
                &created.session_id,
                "type_selector",
                json!({ "selector": "#username", "text": "dispatch.agent" }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "type_selector",
                json!({ "selector": "#password", "text": "dispatch-215" }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "click_selector",
                json!({ "selector": "#sign-in" }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "type_selector",
                json!({ "selector": "#queue-search", "text": "fiber" }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "select_label",
                json!({ "selector": "#queue-status-filter", "label": "Awaiting Dispatch" }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "click_selector",
                json!({ "selector": "#apply-filters" }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "click_selector",
                json!({ "selector": ticket_link_selector("T-215") }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "select_label",
                json!({ "selector": "#assignee", "label": "Network Ops" }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "select_label",
                json!({ "selector": "#status", "label": "Escalated" }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "type_selector",
                json!({ "selector": "#note", "text": "Escalate fiber outage to on-call" }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "click_selector",
                json!({ "selector": "#review-update" }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "click_selector",
                json!({ "selector": "#confirm-update" }),
            )
            .await?;

        let confirmation_state = client.state(&created.session_id).await?;
        assert!(!confirmation_state.terminated);
        assert_eq!(
            field_value(&confirmation_state, "history_verified"),
            Some("false")
        );

        client
            .oracle_step(
                &created.session_id,
                "click_selector",
                json!({ "selector": "#history-link" }),
            )
            .await?;

        let final_state = client.state(&created.session_id).await?;
        assert!(final_state.terminated);
        assert_eq!(final_state.reward, 1.0);
        assert_eq!(field_value(&final_state, "history_verified"), Some("true"));
        assert_eq!(
            field_value(&final_state, "history_event_exists"),
            Some("true")
        );
        assert!(final_state
            .info
            .page_url
            .as_deref()
            .is_some_and(|url| url.contains("/history")));

        process.stop().await;
        Ok(())
    }

    #[tokio::test]
    async fn workflow_mutation_isolation_oracle_requires_target_and_distractor_history_checks(
    ) -> Result<()> {
        let mut process = WorkflowBridgeProcess::start().await?;
        let client = process.client();
        let created = client
            .create_session(&workflow_case(
                "workflow_mutation_isolation_network_ops",
                "workflow-mutation-isolation",
                TaskSet::WorkflowMutation,
                RecipeId::WorkflowMutationIsolation,
            ))
            .await?;

        client
            .oracle_step(
                &created.session_id,
                "type_selector",
                json!({ "selector": "#username", "text": "dispatch.agent" }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "type_selector",
                json!({ "selector": "#password", "text": "dispatch-215" }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "click_selector",
                json!({ "selector": "#sign-in" }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "type_selector",
                json!({ "selector": "#queue-search", "text": "fiber" }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "select_label",
                json!({ "selector": "#queue-status-filter", "label": "Awaiting Dispatch" }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "click_selector",
                json!({ "selector": "#apply-filters" }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "click_selector",
                json!({ "selector": ticket_link_selector("T-215") }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "select_label",
                json!({ "selector": "#assignee", "label": "Network Ops" }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "select_label",
                json!({ "selector": "#status", "label": "Awaiting Dispatch" }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "type_selector",
                json!({ "selector": "#note", "text": "Escalate fiber outage to on-call" }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "click_selector",
                json!({ "selector": "#review-update" }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "click_selector",
                json!({ "selector": "#confirm-update" }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "click_selector",
                json!({ "selector": "#queue-link" }),
            )
            .await?;

        let queue_state = client.state(&created.session_id).await?;
        assert_eq!(field_value(&queue_state, "queue_verified"), Some("true"));
        assert_eq!(field_value(&queue_state, "history_verified"), Some("false"));
        assert_eq!(
            field_value(&queue_state, "distractor_history_verified"),
            Some("false")
        );

        client
            .oracle_step(
                &created.session_id,
                "click_selector",
                json!({ "selector": ticket_history_link_selector("T-215") }),
            )
            .await?;

        let target_history_state = client.state(&created.session_id).await?;
        assert_eq!(
            field_value(&target_history_state, "history_verified"),
            Some("true")
        );
        assert_eq!(
            field_value(&target_history_state, "distractor_saved_update_exists"),
            Some("false")
        );

        client
            .oracle_step(
                &created.session_id,
                "click_selector",
                json!({ "selector": "#queue-link" }),
            )
            .await?;
        client
            .oracle_step(
                &created.session_id,
                "click_selector",
                json!({ "selector": ticket_history_link_selector("T-204") }),
            )
            .await?;

        let final_state = client.state(&created.session_id).await?;
        assert!(final_state.terminated);
        assert_eq!(final_state.reward, 1.0);
        assert_eq!(
            field_value(&final_state, "distractor_history_verified"),
            Some("true")
        );
        assert_eq!(
            field_value(&final_state, "distractor_saved_update_exists"),
            Some("false")
        );
        assert!(final_state
            .info
            .page_url
            .as_deref()
            .is_some_and(|url| url.contains("/tickets/T-204/history")));

        process.stop().await;
        Ok(())
    }
}
