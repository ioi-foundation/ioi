#[derive(Decode, Encode)]
struct RemoteSessionSummary {
    pub session_id: [u8; 32],
    pub title: String,
    pub timestamp: u64,
}

fn workspace_root_from_task(task: &crate::models::AgentTask) -> Option<String> {
    task.build_session
        .as_ref()
        .map(|session| session.workspace_root.clone())
        .or_else(|| {
            task.renderer_session
                .as_ref()
                .map(|session| session.workspace_root.clone())
        })
        .or_else(|| {
            task.chat_session
                .as_ref()
                .and_then(|session| session.workspace_root.clone())
        })
}

fn enrich_local_session_summary(
    memory_runtime: &std::sync::Arc<ioi_memory::MemoryRuntime>,
    summary: SessionSummary,
) -> SessionSummary {
    let mut enriched = summary.clone();
    if enriched.workspace_root.is_none() {
        enriched.workspace_root = orchestrator::persisted_workspace_root_for_session(
            memory_runtime,
            Some(summary.session_id.as_str()),
        );
    }

    let Some(task) = orchestrator::load_local_task(memory_runtime, &summary.session_id) else {
        return enriched;
    };

    enriched = orchestrator::session_summary_from_task(&task, Some(&enriched));
    if enriched.workspace_root.is_none() {
        enriched.workspace_root = workspace_root_from_task(&task).or_else(|| {
            orchestrator::persisted_workspace_root_for_session(
                memory_runtime,
                Some(summary.session_id.as_str()),
            )
        });
    }
    enriched
}

fn local_session_history_snapshot(
    memory_runtime: Option<&Arc<ioi_memory::MemoryRuntime>>,
) -> Vec<SessionSummary> {
    memory_runtime
        .map(|memory_runtime| {
            orchestrator::get_local_sessions(memory_runtime)
                .into_iter()
                .map(|summary| enrich_local_session_summary(memory_runtime, summary))
                .collect()
        })
        .unwrap_or_default()
}

pub(crate) async fn fetch_remote_session_history(
    state: &State<'_, Mutex<AppState>>,
) -> Result<Vec<SessionSummary>, String> {
    let mut client = get_rpc_client(state)
        .await
        .map_err(|error| format!("RPC client unavailable for history: {}", error))?;
    let ns_prefix = ioi_api::state::service_namespace_prefix("desktop_agent");
    let key = [ns_prefix.as_slice(), b"agent::history"].concat();
    let req = tonic::Request::new(QueryRawStateRequest { key });

    let resp = timeout(
        Duration::from_millis(SESSION_HISTORY_RPC_TIMEOUT_MS),
        client.query_raw_state(req),
    )
    .await
    .map_err(|_| {
        format!(
            "Session history RPC timed out after {}ms",
            SESSION_HISTORY_RPC_TIMEOUT_MS
        )
    })?
    .map_err(|error| format!("Failed to query remote session history: {}", error))?
    .into_inner();

    if !resp.found || resp.value.is_empty() {
        return Ok(Vec::new());
    }

    codec::from_bytes_canonical::<Vec<RemoteSessionSummary>>(&resp.value)
        .map(|raw_history| {
            raw_history
                .into_iter()
                .map(|summary| SessionSummary {
                    session_id: hex::encode(summary.session_id),
                    title: summary.title,
                    timestamp: summary.timestamp,
                    phase: None,
                    current_step: None,
                    resume_hint: None,
                    workspace_root: None,
                })
                .collect()
        })
        .map_err(|error| format!("Failed to decode remote session history: {}", error))
}

pub(crate) fn merge_remote_session_history(
    all_sessions: &mut Vec<SessionSummary>,
    remote_sessions: Vec<SessionSummary>,
) -> usize {
    let mut overlap_count = 0;

    for remote in remote_sessions {
        if let Some(position) = all_sessions
            .iter()
            .position(|local| local.session_id == remote.session_id)
        {
            overlap_count += 1;
            let existing = all_sessions[position].clone();
            all_sessions[position] = SessionSummary {
                phase: existing.phase,
                current_step: existing.current_step,
                resume_hint: existing.resume_hint,
                workspace_root: existing.workspace_root,
                ..remote
            };
        } else {
            all_sessions.push(remote);
        }
    }

    overlap_count
}
