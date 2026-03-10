use super::*;

#[tauri::command]
pub async fn get_available_tools(
    state: State<'_, Mutex<AppState>>,
) -> Result<Vec<LlmToolDefinition>, String> {
    let mut tools = execution::get_active_mcp_tools().await;
    let mut existing = tools
        .iter()
        .map(|tool| tool.name.clone())
        .collect::<std::collections::HashSet<_>>();
    tools.extend(
        ioi_services::agentic::desktop::connectors::google_workspace::google_connector_tool_definitions()
            .into_iter()
            .filter(|tool| !existing.contains(&tool.name)),
    );
    existing.extend(tools.iter().map(|tool| tool.name.clone()));

    if let Ok(mut client) = get_rpc_client(&state).await {
        if let Ok(skill_catalog) = load_skill_catalog_entries(&mut client).await {
            for entry in skill_catalog {
                if entry.stale || entry.lifecycle_state == "Deprecated" {
                    continue;
                }
                if existing.insert(entry.definition.name.clone()) {
                    tools.push(entry.definition);
                }
            }
        }
    }

    Ok(tools)
}

#[tauri::command]
pub async fn get_skill_catalog(
    state: State<'_, Mutex<AppState>>,
) -> Result<Vec<SkillCatalogEntry>, String> {
    let mut client = get_rpc_client(&state).await?;
    load_skill_catalog_entries(&mut client).await
}

#[tauri::command]
pub async fn get_context_blob(
    state: State<'_, Mutex<AppState>>,
    hash: String,
) -> Result<ContextBlob, String> {
    let mut client = get_rpc_client(&state).await?;

    let request = tonic::Request::new(GetContextBlobRequest { blob_hash: hash });

    let response = match client.get_context_blob(request).await {
        Ok(resp) => resp.into_inner(),
        Err(status) if status.code() == Code::NotFound => {
            return Ok(ContextBlob {
                data_base64: String::new(),
                mime_type: CONTEXT_BLOB_UNAVAILABLE_MIME.to_string(),
            });
        }
        Err(status) => return Err(format!("RPC error: {}", status)),
    };

    let data_base64 = STANDARD.encode(&response.data);

    let mime_type = if response.mime_type == "application/octet-stream" {
        if response.data.starts_with(b"\x89PNG") {
            "image/png".to_string()
        } else if response.data.starts_with(b"<") || response.data.starts_with(b"<?xml") {
            "text/xml".to_string()
        } else if response.data.starts_with(b"{") || response.data.starts_with(b"[") {
            "application/json".to_string()
        } else {
            "text/plain".to_string()
        }
    } else {
        response.mime_type
    };

    Ok(ContextBlob {
        data_base64,
        mime_type,
    })
}

async fn query_raw_state(
    client: &mut PublicApiClient<Channel>,
    key: Vec<u8>,
) -> Result<Option<Vec<u8>>, String> {
    let response = client
        .query_raw_state(tonic::Request::new(QueryRawStateRequest { key }))
        .await
        .map_err(|status| format!("RPC error: {}", status))?
        .into_inner();
    if response.found {
        Ok(Some(response.value))
    } else {
        Ok(None)
    }
}

async fn load_skill_bundle(
    client: &mut PublicApiClient<Channel>,
    skill_hash: [u8; 32],
) -> Result<Option<SkillBundle>, String> {
    let Some(record_bytes) = query_raw_state(client, get_skill_record_key(&skill_hash)).await?
    else {
        return Ok(None);
    };
    let record = codec::from_bytes_canonical::<SkillRecord>(&record_bytes)
        .map_err(|e| format!("Failed to decode skill record: {}", e))?;
    let published_doc =
        if let Some(doc_bytes) = query_raw_state(client, get_skill_doc_key(&skill_hash)).await? {
            codec::from_bytes_canonical::<PublishedSkillDoc>(&doc_bytes).ok()
        } else {
            None
        };
    let evidence = if let Some(evidence_hash) = record.source_evidence_hash {
        if let Some(evidence_bytes) =
            query_raw_state(client, get_skill_external_evidence_key(&evidence_hash)).await?
        {
            codec::from_bytes_canonical::<ExternalSkillEvidence>(&evidence_bytes).ok()
        } else {
            None
        }
    } else {
        None
    };

    Ok(Some(SkillBundle {
        record,
        published_doc,
        evidence,
    }))
}

async fn load_skill_bundles(
    client: &mut PublicApiClient<Channel>,
) -> Result<Vec<SkillBundle>, String> {
    let index =
        if let Some(bytes) = query_raw_state(client, SKILL_CATALOG_INDEX_KEY.to_vec()).await? {
            codec::from_bytes_canonical::<SkillCatalogIndex>(&bytes)
                .map_err(|e| format!("Failed to decode skill catalog index: {}", e))?
        } else {
            SkillCatalogIndex::default()
        };

    let mut bundles = Vec::new();
    for skill_hash in index.skills {
        if let Some(bundle) = load_skill_bundle(client, skill_hash).await? {
            bundles.push(bundle);
        }
    }
    bundles.sort_by(|left, right| {
        left.record
            .macro_body
            .definition
            .name
            .cmp(&right.record.macro_body.definition.name)
    });
    Ok(bundles)
}

fn load_thread_events_for_session(
    state: &State<'_, Mutex<AppState>>,
    session_id: &str,
) -> Result<Vec<crate::models::AgentEvent>, String> {
    let scs = get_scs(state)?;
    Ok(orchestrator::load_events(&scs, session_id, None, None))
}

fn active_tool_items(active_bundles: &[SkillBundle]) -> Vec<ActiveContextItem> {
    let mut counts = HashMap::<String, usize>::new();
    for bundle in active_bundles {
        for tool_name in used_tools_for_record(&bundle.record) {
            *counts.entry(tool_name).or_insert(0) += 1;
        }
    }

    let mut tools = counts
        .into_iter()
        .map(|(tool_name, count)| ActiveContextItem {
            id: tool_focus_id(&tool_name),
            kind: "tool".to_string(),
            title: tool_name.clone(),
            summary: format!("Referenced by {} active skill(s)", count),
            badge: Some("tool".to_string()),
            secondary_badge: Some(format!(
                "{} skill{}",
                count,
                if count == 1 { "" } else { "s" }
            )),
            success_rate_bps: None,
            sample_size: None,
            focus_id: Some(tool_focus_id(&tool_name)),
            skill_hash: None,
            source_session_id: None,
            source_evidence_hash: None,
            relative_path: None,
            stale: None,
        })
        .collect::<Vec<_>>();
    tools.sort_by(|left, right| left.title.cmp(&right.title));
    tools
}

fn active_evidence_items(active_bundles: &[SkillBundle]) -> Vec<ActiveContextItem> {
    let mut items = Vec::new();
    for bundle in active_bundles {
        if let Some(doc) = bundle.published_doc.as_ref() {
            items.push(ActiveContextItem {
                id: doc_focus_id(&bundle.record.skill_hash),
                kind: "published_doc".to_string(),
                title: doc.name.clone(),
                summary: summary_text(&doc.markdown, 180),
                badge: Some("SKILL.md".to_string()),
                secondary_badge: Some(if doc.stale { "stale" } else { "fresh" }.to_string()),
                success_rate_bps: None,
                sample_size: None,
                focus_id: Some(doc_focus_id(&bundle.record.skill_hash)),
                skill_hash: Some(hex::encode(bundle.record.skill_hash)),
                source_session_id: bundle.record.source_session_id.map(hex::encode),
                source_evidence_hash: bundle.record.source_evidence_hash.map(hex::encode),
                relative_path: Some(doc.relative_path.clone()),
                stale: Some(doc.stale),
            });
        }
        if let (Some(evidence_hash), Some(evidence)) =
            (bundle.record.source_evidence_hash, bundle.evidence.as_ref())
        {
            items.push(ActiveContextItem {
                id: evidence_focus_id(&evidence_hash),
                kind: "evidence".to_string(),
                title: evidence
                    .title
                    .clone()
                    .or_else(|| evidence.source_uri.clone())
                    .unwrap_or_else(|| "External evidence".to_string()),
                summary: summary_text(&evidence.normalized_procedure, 180),
                badge: Some(format!("{:?}", evidence.source_type)),
                secondary_badge: evidence.source_uri.clone(),
                success_rate_bps: None,
                sample_size: None,
                focus_id: Some(evidence_focus_id(&evidence_hash)),
                skill_hash: Some(hex::encode(bundle.record.skill_hash)),
                source_session_id: evidence.source_session_id.map(hex::encode),
                source_evidence_hash: Some(hex::encode(evidence_hash)),
                relative_path: None,
                stale: None,
            });
        }
    }
    items.sort_by(|left, right| left.title.cmp(&right.title));
    items
}

fn active_constraints(agent_state: &DesktopAgentState) -> Vec<ContextConstraint> {
    let mut constraints = vec![
        ContextConstraint {
            id: "mode".to_string(),
            label: "Mode".to_string(),
            value: format!("{:?}", agent_state.mode),
            severity: "info".to_string(),
            summary: "Current orchestration mode".to_string(),
        },
        ContextConstraint {
            id: "tier".to_string(),
            label: "Execution tier".to_string(),
            value: format!("{:?}", agent_state.current_tier),
            severity: "info".to_string(),
            summary: "Current execution surface".to_string(),
        },
    ];

    if let Some(tool_name) = agent_state.pending_tool_call.as_ref() {
        constraints.push(ContextConstraint {
            id: "pending_tool_call".to_string(),
            label: "Pending tool call".to_string(),
            value: tool_name.clone(),
            severity: "medium".to_string(),
            summary: "Execution is paused on a queued tool call".to_string(),
        });
    }

    if let Some(token) = agent_state.pending_approval.as_ref() {
        constraints.push(ContextConstraint {
            id: "pending_approval".to_string(),
            label: "Pending approval".to_string(),
            value: hex::encode(token.request_hash),
            severity: "high".to_string(),
            summary: "User approval is required before execution can continue".to_string(),
        });
    }

    if agent_state.awaiting_intent_clarification {
        constraints.push(ContextConstraint {
            id: "awaiting_intent_clarification".to_string(),
            label: "Clarification".to_string(),
            value: "awaiting input".to_string(),
            severity: "medium".to_string(),
            summary: "The planner is waiting for intent clarification".to_string(),
        });
    }

    constraints
}

fn build_context_neighborhood(
    session_id: &str,
    agent_state: &DesktopAgentState,
    active_bundles: &[SkillBundle],
    constraints: &[ContextConstraint],
) -> AtlasNeighborhood {
    let mut nodes = Vec::new();
    let mut node_ids = HashSet::new();
    let mut edges = Vec::new();
    let mut edge_ids = HashSet::new();
    let focus_id = session_focus_id(session_id);

    add_node(
        &mut nodes,
        &mut node_ids,
        AtlasNode {
            id: focus_id.clone(),
            kind: "session".to_string(),
            label: format!("Session {}", &normalize_hex_id(session_id)[..12]),
            summary: summary_text(&agent_state.goal, 180),
            status: Some(format!("{:?}", agent_state.status)),
            emphasis: Some(1.0),
            metadata: json!({
                "mode": format!("{:?}", agent_state.mode),
                "current_tier": format!("{:?}", agent_state.current_tier),
                "step_count": agent_state.step_count,
                "max_steps": agent_state.max_steps,
            }),
        },
    );

    for bundle in active_bundles {
        let skill_id = skill_focus_id(&bundle.record.skill_hash);
        add_node(
            &mut nodes,
            &mut node_ids,
            AtlasNode {
                id: skill_id.clone(),
                kind: "skill".to_string(),
                label: bundle.record.macro_body.definition.name.clone(),
                summary: bundle.record.macro_body.definition.description.clone(),
                status: Some(format!("{:?}", bundle.record.lifecycle_state)),
                emphasis: Some(
                    if Some(bundle.record.skill_hash) == agent_state.active_skill_hash {
                        0.95
                    } else {
                        0.72
                    },
                ),
                metadata: json!({
                    "source_type": format!("{:?}", bundle.record.source_type),
                    "success_rate_bps": bundle.record.benchmark.clone().unwrap_or_default().success_rate_bps,
                }),
            },
        );
        add_edge(
            &mut edges,
            &mut edge_ids,
            AtlasEdge {
                id: format!("{}::uses_skill::{}", focus_id, skill_id),
                source_id: focus_id.clone(),
                target_id: skill_id.clone(),
                relation: "uses_skill".to_string(),
                summary: Some("Active or recently used skill in this session".to_string()),
                weight: 0.88,
            },
        );

        for tool_name in used_tools_for_record(&bundle.record) {
            let tool_id = tool_focus_id(&tool_name);
            add_node(
                &mut nodes,
                &mut node_ids,
                AtlasNode {
                    id: tool_id.clone(),
                    kind: "tool".to_string(),
                    label: tool_name.clone(),
                    summary: format!(
                        "Tool reachable from {}",
                        bundle.record.macro_body.definition.name
                    ),
                    status: None,
                    emphasis: Some(0.58),
                    metadata: json!({}),
                },
            );
            add_edge(
                &mut edges,
                &mut edge_ids,
                AtlasEdge {
                    id: format!("{}::uses_tool::{}", skill_id, tool_id),
                    source_id: skill_id.clone(),
                    target_id: tool_id,
                    relation: "uses_tool".to_string(),
                    summary: Some("Macro step uses this tool".to_string()),
                    weight: 0.7,
                },
            );
        }

        if let Some(doc) = bundle.published_doc.as_ref() {
            let doc_id = doc_focus_id(&bundle.record.skill_hash);
            add_node(
                &mut nodes,
                &mut node_ids,
                AtlasNode {
                    id: doc_id.clone(),
                    kind: "published_doc".to_string(),
                    label: doc.name.clone(),
                    summary: summary_text(&doc.markdown, 160),
                    status: Some(if doc.stale { "stale" } else { "fresh" }.to_string()),
                    emphasis: Some(0.42),
                    metadata: json!({ "relative_path": doc.relative_path }),
                },
            );
            add_edge(
                &mut edges,
                &mut edge_ids,
                AtlasEdge {
                    id: format!("{}::published_as::{}", skill_id, doc_id),
                    source_id: skill_id.clone(),
                    target_id: doc_id,
                    relation: "published_as".to_string(),
                    summary: Some("Derived human-facing publication".to_string()),
                    weight: 0.56,
                },
            );
        }

        if let (Some(evidence_hash), Some(evidence)) =
            (bundle.record.source_evidence_hash, bundle.evidence.as_ref())
        {
            let evidence_id = evidence_focus_id(&evidence_hash);
            add_node(
                &mut nodes,
                &mut node_ids,
                AtlasNode {
                    id: evidence_id.clone(),
                    kind: "evidence".to_string(),
                    label: evidence
                        .title
                        .clone()
                        .or_else(|| evidence.source_uri.clone())
                        .unwrap_or_else(|| "External evidence".to_string()),
                    summary: summary_text(&evidence.normalized_procedure, 160),
                    status: Some(format!("{:?}", evidence.source_type)),
                    emphasis: Some(0.46),
                    metadata: json!({ "source_uri": evidence.source_uri }),
                },
            );
            add_edge(
                &mut edges,
                &mut edge_ids,
                AtlasEdge {
                    id: format!("{}::derived_from::{}", skill_id, evidence_id),
                    source_id: skill_id,
                    target_id: evidence_id,
                    relation: "derived_from".to_string(),
                    summary: Some("External procedure evidence".to_string()),
                    weight: 0.6,
                },
            );
        }
    }

    for constraint in constraints {
        let constraint_id = constraint_focus_id(&constraint.id);
        add_node(
            &mut nodes,
            &mut node_ids,
            AtlasNode {
                id: constraint_id.clone(),
                kind: "constraint".to_string(),
                label: constraint.label.clone(),
                summary: constraint.summary.clone(),
                status: Some(constraint.severity.clone()),
                emphasis: Some(0.38),
                metadata: json!({ "value": constraint.value }),
            },
        );
        add_edge(
            &mut edges,
            &mut edge_ids,
            AtlasEdge {
                id: format!("{}::constrained_by::{}", focus_id, constraint_id),
                source_id: focus_id.clone(),
                target_id: constraint_id,
                relation: "constrained_by".to_string(),
                summary: Some("Current execution constraint".to_string()),
                weight: 0.44,
            },
        );
    }

    AtlasNeighborhood {
        lens: "context".to_string(),
        title: "Active Context".to_string(),
        summary: format!(
            "{} skill nodes, {} constraint nodes",
            active_bundles.len(),
            constraints.len()
        ),
        focus_id: Some(focus_id),
        nodes,
        edges,
    }
}

fn lexical_goal_matches<'a>(bundles: &'a [SkillBundle], goal: &str) -> Vec<&'a SkillBundle> {
    let goal_lower = goal.to_ascii_lowercase();
    if goal_lower.trim().is_empty() {
        return Vec::new();
    }
    bundles
        .iter()
        .filter(|bundle| {
            let name = bundle
                .record
                .macro_body
                .definition
                .name
                .to_ascii_lowercase();
            let description = bundle
                .record
                .macro_body
                .definition
                .description
                .to_ascii_lowercase();
            goal_lower.contains(&name)
                || name.contains(&goal_lower)
                || description.contains(&goal_lower)
        })
        .collect()
}

async fn load_active_context_snapshot(
    state: &State<'_, Mutex<AppState>>,
    client: &mut PublicApiClient<Channel>,
    session_id: &str,
) -> Result<ActiveContextSnapshot, String> {
    let normalized_session_id = normalize_hex_id(session_id);
    let session_key = get_state_key(&parse_hex_32(&normalized_session_id)?);
    let Some(agent_state_bytes) = query_raw_state(client, session_key).await? else {
        return Err(format!(
            "No agent state found for session {}",
            normalized_session_id
        ));
    };
    let agent_state = codec::from_bytes_canonical::<DesktopAgentState>(&agent_state_bytes)
        .map_err(|e| format!("Failed to decode agent state: {}", e))?;

    let mut trace_hashes = BTreeSet::new();
    for step_index in 0..=agent_state.step_count {
        let Some(trace_bytes) =
            query_raw_state(client, get_trace_key(&agent_state.session_id, step_index)).await?
        else {
            continue;
        };
        if let Ok(trace) = codec::from_bytes_canonical::<StepTrace>(&trace_bytes) {
            if let Some(skill_hash) = trace.skill_hash {
                trace_hashes.insert(skill_hash);
            }
        }
    }
    if let Some(skill_hash) = agent_state.active_skill_hash {
        trace_hashes.insert(skill_hash);
    }

    let bundles = load_skill_bundles(client).await?;
    let bundle_map = bundles
        .iter()
        .cloned()
        .map(|bundle| (bundle.record.skill_hash, bundle))
        .collect::<HashMap<_, _>>();

    if trace_hashes.is_empty() {
        for bundle in lexical_goal_matches(&bundles, &agent_state.goal)
            .into_iter()
            .take(4)
        {
            trace_hashes.insert(bundle.record.skill_hash);
        }
    }

    let mut active_bundles = trace_hashes
        .iter()
        .filter_map(|skill_hash| bundle_map.get(skill_hash).cloned())
        .collect::<Vec<_>>();
    active_bundles.sort_by(|left, right| {
        left.record
            .macro_body
            .definition
            .name
            .cmp(&right.record.macro_body.definition.name)
    });

    let mut skills = active_bundles
        .iter()
        .map(active_skill_item)
        .collect::<Vec<_>>();
    skills.sort_by(|left, right| left.title.cmp(&right.title));
    let tools = active_tool_items(&active_bundles);
    let evidence = active_evidence_items(&active_bundles);
    let constraints = active_constraints(&agent_state);
    let neighborhood = build_context_neighborhood(
        &normalized_session_id,
        &agent_state,
        &active_bundles,
        &constraints,
    );

    let recent_actions = agent_state
        .recent_actions
        .iter()
        .rev()
        .take(8)
        .cloned()
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<Vec<_>>();

    let substrate = load_thread_events_for_session(state, &normalized_session_id)
        .ok()
        .map(|events| build_substrate_receipts(&events))
        .filter(|receipts| !receipts.is_empty())
        .map(|receipts| {
            let index_roots = receipts
                .iter()
                .map(|receipt| receipt.index_root.clone())
                .filter(|value| !value.is_empty())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>();
            SubstrateProofView {
                session_id: Some(normalized_session_id.clone()),
                skill_hash: agent_state.active_skill_hash.map(|hash| hex::encode(hash)),
                summary: format!(
                    "{} substrate receipts attached to this session.",
                    receipts.len()
                ),
                index_roots,
                neighborhood: build_substrate_neighborhood(&receipts, Some(&normalized_session_id)),
                receipts,
            }
        });

    Ok(ActiveContextSnapshot {
        session_id: normalized_session_id.clone(),
        goal: agent_state.goal,
        status: format!("{:?}", agent_state.status),
        mode: format!("{:?}", agent_state.mode),
        current_tier: format!("{:?}", agent_state.current_tier),
        focus_id: session_focus_id(&normalized_session_id),
        active_skill_id: agent_state.active_skill_hash.as_ref().map(skill_focus_id),
        skills,
        tools,
        evidence,
        constraints,
        recent_actions,
        neighborhood,
        substrate,
    })
}

async fn load_skill_catalog_entries(
    client: &mut PublicApiClient<Channel>,
) -> Result<Vec<SkillCatalogEntry>, String> {
    let mut entries = load_skill_bundles(client)
        .await?
        .into_iter()
        .map(|bundle| skill_catalog_entry_from_bundle(&bundle))
        .collect::<Vec<_>>();

    entries.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(entries)
}

#[tauri::command]
pub async fn get_active_context(
    state: State<'_, Mutex<AppState>>,
    session_id: String,
) -> Result<ActiveContextSnapshot, String> {
    let mut client = get_rpc_client(&state).await?;
    load_active_context_snapshot(&state, &mut client, &session_id).await
}

#[tauri::command]
pub async fn get_skill_detail(
    state: State<'_, Mutex<AppState>>,
    skill_hash: String,
) -> Result<SkillDetailView, String> {
    let mut client = get_rpc_client(&state).await?;
    let skill_hash = parse_hex_32(&skill_hash)?;
    let bundles = load_skill_bundles(&mut client).await?;
    let Some(bundle) = bundles
        .iter()
        .find(|bundle| bundle.record.skill_hash == skill_hash)
    else {
        return Err(format!("Skill {} was not found", hex::encode(skill_hash)));
    };
    Ok(build_skill_detail(bundle, &bundles))
}

#[tauri::command]
pub async fn get_substrate_proof(
    state: State<'_, Mutex<AppState>>,
    session_id: Option<String>,
    skill_hash: Option<String>,
) -> Result<SubstrateProofView, String> {
    let mut client = get_rpc_client(&state).await?;
    let bundles = load_skill_bundles(&mut client).await?;

    let resolved_session_id = if let Some(session_id) = session_id {
        Some(normalize_hex_id(&session_id))
    } else if let Some(skill_hash) = skill_hash.as_deref() {
        let parsed_skill_hash = parse_hex_32(skill_hash)?;
        bundles
            .iter()
            .find(|bundle| bundle.record.skill_hash == parsed_skill_hash)
            .and_then(|bundle| bundle.record.source_session_id.map(hex::encode))
    } else {
        None
    };

    let Some(session_id) = resolved_session_id else {
        return Ok(SubstrateProofView {
            session_id: None,
            skill_hash,
            summary: "No session was provided for substrate proof lookup.".to_string(),
            index_roots: Vec::new(),
            receipts: Vec::new(),
            neighborhood: AtlasNeighborhood {
                lens: "substrate".to_string(),
                title: "Substrate".to_string(),
                summary: "No session was provided for substrate proof lookup.".to_string(),
                focus_id: None,
                nodes: Vec::new(),
                edges: Vec::new(),
            },
        });
    };

    let events = load_thread_events_for_session(&state, &session_id)?;
    let receipts = build_substrate_receipts(&events);
    let index_roots = receipts
        .iter()
        .map(|receipt| receipt.index_root.clone())
        .filter(|root| !root.is_empty())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let neighborhood = build_substrate_neighborhood(&receipts, Some(&session_id));

    Ok(SubstrateProofView {
        session_id: Some(session_id),
        skill_hash,
        summary: if receipts.is_empty() {
            "No substrate retrieval receipts captured for this scope.".to_string()
        } else {
            format!("{} substrate retrieval receipts captured.", receipts.len())
        },
        index_roots,
        receipts,
        neighborhood,
    })
}

#[tauri::command]
pub async fn get_atlas_neighborhood(
    state: State<'_, Mutex<AppState>>,
    session_id: Option<String>,
    focus_id: Option<String>,
    lens: Option<String>,
) -> Result<AtlasNeighborhood, String> {
    let resolved_lens = lens
        .unwrap_or_else(|| "skills".to_string())
        .trim()
        .to_ascii_lowercase();

    match resolved_lens.as_str() {
        "context" => {
            let target_session_id = session_id
                .or_else(|| focus_id.as_deref().and_then(parse_focus_session_id))
                .ok_or_else(|| "A session id is required for the context lens".to_string())?;
            let mut client = get_rpc_client(&state).await?;
            Ok(
                load_active_context_snapshot(&state, &mut client, &target_session_id)
                    .await?
                    .neighborhood,
            )
        }
        "substrate" => {
            let proof = get_substrate_proof(
                state,
                session_id,
                focus_id.and_then(|value| parse_focus_skill_hash(&value).map(hex::encode)),
            )
            .await?;
            Ok(proof.neighborhood)
        }
        _ => {
            let mut client = get_rpc_client(&state).await?;
            let bundles = load_skill_bundles(&mut client).await?;
            let focus_hash = focus_id
                .as_deref()
                .and_then(parse_focus_skill_hash)
                .or_else(|| bundles.first().map(|bundle| bundle.record.skill_hash))
                .ok_or_else(|| "No skills are available in the atlas".to_string())?;
            Ok(build_skill_neighborhood(&bundles, &focus_hash))
        }
    }
}

#[tauri::command]
pub async fn search_atlas(
    state: State<'_, Mutex<AppState>>,
    query: String,
    lens: Option<String>,
) -> Result<Vec<AtlasSearchResult>, String> {
    let normalized_query = query.trim().to_ascii_lowercase();
    if normalized_query.is_empty() {
        return Ok(Vec::new());
    }

    let resolved_lens = lens
        .unwrap_or_else(|| "skills".to_string())
        .trim()
        .to_ascii_lowercase();
    let mut client = get_rpc_client(&state).await?;
    let bundles = load_skill_bundles(&mut client).await?;

    let query_tokens = normalized_query
        .split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_')
        .filter(|token| !token.is_empty())
        .collect::<Vec<_>>();

    let score_text = |text: &str| -> f32 {
        let lower = text.to_ascii_lowercase();
        let mut score = if lower.contains(&normalized_query) {
            1.5
        } else {
            0.0
        };
        for token in &query_tokens {
            if lower.contains(token) {
                score += 0.35;
            }
        }
        score
    };

    let mut results = Vec::new();
    for bundle in bundles {
        if resolved_lens == "context" {
            continue;
        }

        let skill_score = score_text(&bundle.record.macro_body.definition.name)
            + score_text(&bundle.record.macro_body.definition.description)
            + used_tools_for_record(&bundle.record)
                .iter()
                .map(|tool_name| score_text(tool_name))
                .sum::<f32>();
        if skill_score > 0.0 {
            results.push(AtlasSearchResult {
                id: skill_focus_id(&bundle.record.skill_hash),
                kind: "skill".to_string(),
                title: bundle.record.macro_body.definition.name.clone(),
                summary: bundle.record.macro_body.definition.description.clone(),
                score: skill_score,
                lens: "skills".to_string(),
            });
        }

        if resolved_lens != "skills" {
            if let Some(doc) = bundle.published_doc.as_ref() {
                let doc_score = score_text(&doc.name) + score_text(&doc.markdown);
                if doc_score > 0.0 {
                    results.push(AtlasSearchResult {
                        id: doc_focus_id(&bundle.record.skill_hash),
                        kind: "published_doc".to_string(),
                        title: doc.name.clone(),
                        summary: summary_text(&doc.markdown, 180),
                        score: doc_score,
                        lens: "skills".to_string(),
                    });
                }
            }
            if let (Some(evidence_hash), Some(evidence)) =
                (bundle.record.source_evidence_hash, bundle.evidence.as_ref())
            {
                let mut evidence_score = score_text(&evidence.normalized_procedure);
                if let Some(title) = evidence.title.as_ref() {
                    evidence_score += score_text(title);
                }
                if let Some(source_uri) = evidence.source_uri.as_ref() {
                    evidence_score += score_text(source_uri);
                }
                if evidence_score > 0.0 {
                    results.push(AtlasSearchResult {
                        id: evidence_focus_id(&evidence_hash),
                        kind: "evidence".to_string(),
                        title: evidence
                            .title
                            .clone()
                            .or_else(|| evidence.source_uri.clone())
                            .unwrap_or_else(|| "External evidence".to_string()),
                        summary: summary_text(&evidence.normalized_procedure, 180),
                        score: evidence_score,
                        lens: "skills".to_string(),
                    });
                }
            }
        }
    }

    results.sort_by(|left, right| {
        right
            .score
            .partial_cmp(&left.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| left.title.cmp(&right.title))
    });
    results.truncate(24);
    Ok(results)
}
