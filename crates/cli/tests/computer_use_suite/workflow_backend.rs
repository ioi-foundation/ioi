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
struct WorkflowCaseSpec {
    case_id: String,
    instruction: String,
    username: String,
    password: String,
    ticket_id: String,
    assignee: String,
    note: String,
}

#[derive(Debug, Clone)]
enum WorkflowPage {
    Login,
    Queue,
    Detail { ticket_id: String },
    Confirmation,
}

#[derive(Debug, Clone)]
struct WorkflowSession {
    base_url: String,
    spec: WorkflowCaseSpec,
    current_page: WorkflowPage,
    login_username: String,
    login_password: String,
    selected_assignee: String,
    note_text: String,
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
    note: String,
}

const WORKFLOW_QUEUE_TICKETS: &[(&str, &str, &str)] = &[
    ("T-101", "Printer outage in west wing", "Facilities"),
    ("T-204", "Metro fiber outage", "Network Ops"),
    ("T-310", "Recurring invoice delta", "Billing Review"),
];

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
                "/workflow/:session_id/tickets/:ticket_id",
                get(ticket_detail_page),
            )
            .route(
                "/workflow/:session_id/tickets/:ticket_id/assign",
                post(ticket_assign_submit),
            )
            .route("/workflow/:session_id/confirmation", get(confirmation_page))
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
        let bridge_state = BridgeState {
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
                fields: workflow_fields(&spec, "", "", "", ""),
                page_url: Some(url.clone()),
                task_ready: Some(false),
                focused_tag: None,
                focused_id: None,
                visible_text_excerpt: Some(workflow_visible_text(
                    &spec,
                    &WorkflowPage::Login,
                    "",
                    "",
                )),
                interactive_elements: synthesized_interactive_elements(
                    &spec,
                    &WorkflowPage::Login,
                    "",
                    "",
                    "",
                    "",
                ),
                scroll_targets: Vec::new(),
                dom_elements: Vec::new(),
            },
        };

        let session = WorkflowSession {
            base_url: self.base_url.clone(),
            spec: spec.clone(),
            current_page: WorkflowPage::Login,
            login_username: String::new(),
            login_password: String::new(),
            selected_assignee: String::new(),
            note_text: String::new(),
            reward: 0.0,
            terminated: false,
            truncated: false,
            bridge_state: bridge_state.clone(),
        };
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
            instruction: "Sign in to the dispatch console with username \"dispatch.agent\" and password \"dispatch-204\". Open ticket T-204 from the queue, assign it to Network Ops, add the note \"Escalate fiber outage to on-call\", submit the update, and stop only after the confirmation page shows the saved assignment.".to_string(),
            username: "dispatch.agent".to_string(),
            password: "dispatch-204".to_string(),
            ticket_id: "T-204".to_string(),
            assignee: "Network Ops".to_string(),
            note: "Escalate fiber outage to on-call".to_string(),
        }),
        "workflow_ticket_routing_billing_review" => Ok(WorkflowCaseSpec {
            case_id: case.id.clone(),
            instruction: "Sign in to the dispatch console with username \"dispatch.agent\" and password \"billing-310\". Open ticket T-310 from the queue, assign it to Billing Review, add the note \"Validate recurring invoice delta\", submit the update, and stop only after the confirmation page shows the saved assignment.".to_string(),
            username: "dispatch.agent".to_string(),
            password: "billing-310".to_string(),
            ticket_id: "T-310".to_string(),
            assignee: "Billing Review".to_string(),
            note: "Validate recurring invoice delta".to_string(),
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

async fn ticket_detail_page(
    Path((session_id, ticket_id)): Path<(String, String)>,
    State(state): State<WorkflowAppState>,
) -> Html<String> {
    let Some(session) = with_session(&state.sessions, &session_id, |session| {
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
        session.selected_assignee = form.assignee.clone();
        session.note_text = form.note.clone();
        session.current_page = WorkflowPage::Confirmation;
        session.reward = if ticket_id == session.spec.ticket_id
            && session.selected_assignee == session.spec.assignee
            && session.note_text == session.spec.note
        {
            1.0
        } else {
            0.0
        };
        session.terminated = true;
        session.truncated = false;
        format!("/workflow/{}/confirmation", session_id)
    })
    .unwrap_or_else(|| format!("/workflow/{}/confirmation", session_id));
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
                "#note" => session.note_text = text.to_string(),
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
            if selector == "#assignee" {
                session.selected_assignee = label.to_string();
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
                "#submit-update" => {
                    session.current_page = WorkflowPage::Confirmation;
                    session.reward = if session.selected_assignee == session.spec.assignee
                        && session.note_text == session.spec.note
                    {
                        1.0
                    } else {
                        0.0
                    };
                    session.terminated = true;
                    session.truncated = false;
                }
                _ if selector == ticket_link_selector(&session.spec.ticket_id) => {
                    session.current_page = WorkflowPage::Detail {
                        ticket_id: session.spec.ticket_id.clone(),
                    };
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
    session.login_username = observation_value(&payload.interactive_elements, "#username")
        .unwrap_or_else(|| session.login_username.clone());
    session.login_password = observation_value(&payload.interactive_elements, "#password")
        .unwrap_or_else(|| session.login_password.clone());
    session.selected_assignee =
        observation_selected_label(&payload.interactive_elements, "#assignee")
            .or_else(|| observation_value(&payload.interactive_elements, "#assignee"))
            .unwrap_or_else(|| session.selected_assignee.clone());
    session.note_text = observation_value(&payload.interactive_elements, "#note")
        .unwrap_or_else(|| session.note_text.clone());

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
        fields: workflow_fields(
            &session.spec,
            &session.login_username,
            &session.login_password,
            &session.selected_assignee,
            &session.note_text,
        ),
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
        fields: workflow_fields(
            &session.spec,
            &session.login_username,
            &session.login_password,
            &session.selected_assignee,
            &session.note_text,
        ),
        page_url: Some(current_page_url(session)),
        task_ready: Some(true),
        focused_tag: None,
        focused_id: None,
        visible_text_excerpt: Some(workflow_visible_text(
            &session.spec,
            &session.current_page,
            &session.selected_assignee,
            &session.note_text,
        )),
        interactive_elements: synthesized_interactive_elements(
            &session.spec,
            &session.current_page,
            &session.login_username,
            &session.login_password,
            &session.selected_assignee,
            &session.note_text,
        ),
        scroll_targets: Vec::new(),
        dom_elements: Vec::new(),
    };
}

fn render_page_html(session: &WorkflowSession, page: &WorkflowPage) -> String {
    let body = match page {
        WorkflowPage::Login => render_login_body(session),
        WorkflowPage::Queue => render_queue_body(session),
        WorkflowPage::Detail { ticket_id } => render_detail_body(session, ticket_id),
        WorkflowPage::Confirmation => render_confirmation_body(session),
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
    label {{ display: block; font-size: 14px; font-weight: 600; margin-bottom: 6px; }}
    input, textarea, select {{ width: 100%; box-sizing: border-box; margin-bottom: 14px; border: 1px solid #b9c6db; border-radius: 10px; padding: 10px 12px; font: inherit; }}
    textarea {{ min-height: 120px; resize: vertical; }}
    button, .button-link {{ display: inline-block; border: none; border-radius: 999px; padding: 10px 16px; background: #1f6feb; color: #fff; font: inherit; cursor: pointer; text-decoration: none; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ padding: 12px; border-bottom: 1px solid #e2e8f3; text-align: left; }}
    code {{ font-family: ui-monospace, SFMono-Regular, monospace; }}
    .status-pill {{ display: inline-block; padding: 4px 10px; border-radius: 999px; background: #e4eefc; color: #1f4f96; font-size: 12px; font-weight: 700; }}
    .success {{ background: #e7f8ee; color: #19663e; }}
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
    let rows = WORKFLOW_QUEUE_TICKETS
        .iter()
        .map(|(ticket_id, title, owner)| {
            format!(
                r#"<tr>
  <td><a id="{link_id}" href="/workflow/{session_id}/tickets/{ticket_id}">{ticket_id}</a></td>
  <td>{title}</td>
  <td>{owner}</td>
</tr>"#,
                link_id = ticket_link_id(ticket_id),
                session_id = session.bridge_state.session_id,
                ticket_id = ticket_id,
                title = escape_html(title),
                owner = escape_html(owner),
            )
        })
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
        <tr><th>Ticket</th><th>Summary</th><th>Suggested team</th></tr>
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

fn render_detail_body(session: &WorkflowSession, ticket_id: &str) -> String {
    let ticket_summary = WORKFLOW_QUEUE_TICKETS
        .iter()
        .find(|(id, _, _)| *id == ticket_id)
        .map(|(_, title, owner)| format!("{} / suggested team: {}", title, owner))
        .unwrap_or_else(|| "Untracked ticket".to_string());
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
      <label for="note">Dispatch note</label>
      <textarea id="note" name="note">{note}</textarea>
      <button id="submit-update" type="submit">Submit update</button>
    </form>
  </section>
  <aside class="panel">
    <h2>Task brief</h2>
    <p id="task-brief">{instruction}</p>
    <p><span class="status-pill">Step 3</span> Save the requested assignee and note.</p>
  </aside>
</div>"#,
        session_id = session.bridge_state.session_id,
        ticket_id = escape_html(ticket_id),
        summary = escape_html(&ticket_summary),
        options = render_assignee_options(&session.selected_assignee),
        note = escape_html(&session.note_text),
        instruction = escape_html(&session.spec.instruction),
    )
}

fn render_confirmation_body(session: &WorkflowSession) -> String {
    let success = (session.reward - 1.0).abs() < f32::EPSILON;
    let status_class = if success {
        "status-pill success"
    } else {
        "status-pill"
    };
    let status_text = if success {
        "Saved and verified"
    } else {
        "Saved with validation mismatch"
    };
    format!(
        r#"<div class="breadcrumbs"><a id="queue-link" href="/workflow/{session_id}/queue">Queue</a> / Confirmation</div>
<div class="grid two-col">
  <section class="panel">
    <h1>Assignment confirmation</h1>
    <p><span id="save-status" class="{status_class}">{status_text}</span></p>
    <p id="assignment-banner">Ticket <strong>{ticket_id}</strong> was routed to <strong>{assignee}</strong>.</p>
    <p id="note-summary">Saved note: {note}</p>
  </section>
  <aside class="panel">
    <h2>Task brief</h2>
    <p id="task-brief">{instruction}</p>
    <p><span class="status-pill">Step 4</span> Confirmation page reached.</p>
  </aside>
</div>"#,
        session_id = session.bridge_state.session_id,
        status_class = status_class,
        status_text = status_text,
        ticket_id = escape_html(&session.spec.ticket_id),
        assignee = escape_html(&session.selected_assignee),
        note = escape_html(&session.note_text),
        instruction = escape_html(&session.spec.instruction),
    )
}

fn render_assignee_options(selected: &str) -> String {
    [
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

fn workflow_fields(
    spec: &WorkflowCaseSpec,
    current_username: &str,
    current_password: &str,
    current_assignee: &str,
    current_note: &str,
) -> Vec<BridgeField> {
    vec![
        BridgeField {
            key: "workflow_case_id".to_string(),
            value: spec.case_id.clone(),
        },
        BridgeField {
            key: "username".to_string(),
            value: spec.username.clone(),
        },
        BridgeField {
            key: "password".to_string(),
            value: spec.password.clone(),
        },
        BridgeField {
            key: "ticket_id".to_string(),
            value: spec.ticket_id.clone(),
        },
        BridgeField {
            key: "assignee".to_string(),
            value: spec.assignee.clone(),
        },
        BridgeField {
            key: "note".to_string(),
            value: spec.note.clone(),
        },
        BridgeField {
            key: "current_username".to_string(),
            value: current_username.to_string(),
        },
        BridgeField {
            key: "current_password".to_string(),
            value: current_password.to_string(),
        },
        BridgeField {
            key: "current_assignee".to_string(),
            value: current_assignee.to_string(),
        },
        BridgeField {
            key: "current_note".to_string(),
            value: current_note.to_string(),
        },
    ]
}

fn workflow_visible_text(
    spec: &WorkflowCaseSpec,
    page: &WorkflowPage,
    current_assignee: &str,
    current_note: &str,
) -> String {
    match page {
        WorkflowPage::Login => {
            format!("Dispatch Console Sign in to continue. {}", spec.instruction)
        }
        WorkflowPage::Queue => format!(
            "Active dispatch queue. Open {} from the queue. {}",
            spec.ticket_id, spec.instruction
        ),
        WorkflowPage::Detail { ticket_id } => format!(
            "Ticket {}. Assign team {}. Dispatch note {}. {}",
            ticket_id, current_assignee, current_note, spec.instruction
        ),
        WorkflowPage::Confirmation => format!(
            "Assignment confirmation. Ticket {} routed to {}. Saved note {}. {}",
            spec.ticket_id, current_assignee, current_note, spec.instruction
        ),
    }
}

fn synthesized_interactive_elements(
    spec: &WorkflowCaseSpec,
    page: &WorkflowPage,
    current_username: &str,
    current_password: &str,
    current_assignee: &str,
    current_note: &str,
) -> Vec<BridgeInteractiveElement> {
    match page {
        WorkflowPage::Login => vec![
            text_input("#username", "username", current_username),
            password_input("#password", "password", current_password),
            button("#sign-in", "Sign in"),
        ],
        WorkflowPage::Queue => WORKFLOW_QUEUE_TICKETS
            .iter()
            .map(|(ticket_id, _, _)| link(&ticket_link_selector(ticket_id), ticket_id))
            .collect(),
        WorkflowPage::Detail { ticket_id } => vec![
            link("#queue-link", "Queue"),
            select_input("#assignee", current_assignee),
            text_area("#note", current_note),
            button("#submit-update", "Submit update"),
            link(&ticket_link_selector(ticket_id), ticket_id),
        ],
        WorkflowPage::Confirmation => vec![link("#queue-link", "Queue")],
    }
    .into_iter()
    .map(|mut element| {
        if matches!(page, WorkflowPage::Queue)
            && element.selector.as_deref() == Some(ticket_link_selector(&spec.ticket_id).as_str())
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
        WorkflowPage::Confirmation => format!(
            "{}/workflow/{}/confirmation",
            session.base_url, session.bridge_state.session_id
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
    if url.contains("/confirmation") {
        return Some(WorkflowPage::Confirmation);
    }
    let marker = "/tickets/";
    let start = url.find(marker)? + marker.len();
    let ticket_id = url[start..]
        .split('/')
        .next()
        .filter(|value| !value.is_empty())?;
    Some(WorkflowPage::Detail {
        ticket_id: ticket_id.to_string(),
    })
}

fn ticket_link_selector(ticket_id: &str) -> String {
    format!("#{}", ticket_link_id(ticket_id))
}

fn ticket_link_id(ticket_id: &str) -> String {
    format!("ticket-link-{}", sanitize_token(ticket_id))
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
    BridgeInteractiveElement {
        tag: "select".to_string(),
        id: selector.strip_prefix('#').map(str::to_string),
        selector: Some(selector.to_string()),
        center_x: None,
        center_y: None,
        name: Some("assignee".to_string()),
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

    fn workflow_case(case_id: &str) -> ComputerUseCase {
        ComputerUseCase {
            id: case_id.to_string(),
            env_id: "workflow-ticket-routing".to_string(),
            seed: 7,
            task_set: TaskSet::Workflow,
            max_steps: 12,
            timeout_seconds: 25,
            allowed_tool_profile: AllowedToolProfile::BrowserCoreWithSelect,
            expected_reward_floor: 1.0,
            expected_pass: true,
            local_judge: LocalJudge::BridgeReward,
            recipe: RecipeId::WorkflowTicketRouting,
        }
    }

    #[tokio::test]
    async fn workflow_oracle_progresses_to_confirmation() -> Result<()> {
        let mut process = WorkflowBridgeProcess::start().await?;
        let client = process.client();
        let created = client
            .create_session(&workflow_case("workflow_ticket_routing_network_ops"))
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
}
