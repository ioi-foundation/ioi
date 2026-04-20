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

#[cfg(test)]
#[path = "atlas/tests.rs"]
mod tests;
