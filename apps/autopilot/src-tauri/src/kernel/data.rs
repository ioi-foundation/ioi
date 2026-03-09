use crate::execution;
use crate::kernel::state::get_rpc_client;
use crate::models::{
    ActiveContextItem, ActiveContextSnapshot, AppState, AtlasEdge, AtlasNeighborhood, AtlasNode,
    AtlasSearchResult, ContextBlob, ContextConstraint, SkillBenchmarkView, SkillCatalogEntry,
    SkillDetailView, SkillMacroStepView, SubstrateProofReceipt, SubstrateProofView,
};
use crate::orchestrator;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ioi_ipc::blockchain::QueryRawStateRequest;
use ioi_ipc::public::public_api_client::PublicApiClient;
use ioi_ipc::public::GetContextBlobRequest;
use ioi_scs::SovereignContextStore;
use ioi_services::agentic::desktop::keys::{
    get_skill_doc_key, get_skill_external_evidence_key, get_skill_record_key, get_state_key,
    get_trace_key, SKILL_CATALOG_INDEX_KEY,
};
use ioi_services::agentic::desktop::AgentState as DesktopAgentState;
use ioi_types::app::agentic::{
    ExternalSkillEvidence, LlmToolDefinition, PublishedSkillDoc, SkillCatalogIndex, SkillRecord,
    StepTrace,
};
use ioi_types::codec;
use serde_json::{json, Value};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::{Arc, Mutex};
use tauri::State;
use tonic::transport::Channel;
use tonic::Code;

const CONTEXT_BLOB_UNAVAILABLE_MIME: &str = "application/x-ioi-context-unavailable";
const QUEUE_TOOL_NAME_KEY: &str = "__ioi_tool_name";

#[derive(Clone)]
struct SkillBundle {
    record: SkillRecord,
    published_doc: Option<PublishedSkillDoc>,
    evidence: Option<ExternalSkillEvidence>,
}

fn normalize_hex_id(input: &str) -> String {
    input
        .trim()
        .trim_start_matches("0x")
        .replace('-', "")
        .to_lowercase()
}

fn parse_hex_32(input: &str) -> Result<[u8; 32], String> {
    let normalized = normalize_hex_id(input);
    let bytes = hex::decode(&normalized).map_err(|e| format!("Invalid hex id: {}", e))?;
    if bytes.len() != 32 {
        return Err(format!(
            "Expected a 32-byte hex id but found {} bytes",
            bytes.len()
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn skill_focus_id(skill_hash: &[u8; 32]) -> String {
    format!("skill:{}", hex::encode(skill_hash))
}

fn session_focus_id(session_id: &str) -> String {
    format!("session:{}", normalize_hex_id(session_id))
}

fn tool_focus_id(tool_name: &str) -> String {
    format!("tool:{}", tool_name)
}

fn doc_focus_id(skill_hash: &[u8; 32]) -> String {
    format!("doc:{}", hex::encode(skill_hash))
}

fn evidence_focus_id(evidence_hash: &[u8; 32]) -> String {
    format!("evidence:{}", hex::encode(evidence_hash))
}

fn constraint_focus_id(id: &str) -> String {
    format!("constraint:{}", id)
}

fn parse_focus_skill_hash(focus_id: &str) -> Option<[u8; 32]> {
    let raw = focus_id.strip_prefix("skill:")?;
    parse_hex_32(raw).ok()
}

fn parse_focus_session_id(focus_id: &str) -> Option<String> {
    focus_id
        .strip_prefix("session:")
        .map(normalize_hex_id)
        .filter(|value| !value.is_empty())
}

fn to_optional_number(value: Option<&Value>) -> Option<u64> {
    match value {
        Some(Value::Number(number)) => number.as_u64(),
        Some(Value::String(text)) => text.trim().parse::<u64>().ok(),
        _ => None,
    }
}

fn to_optional_bool(value: Option<&Value>) -> Option<bool> {
    match value {
        Some(Value::Bool(value)) => Some(*value),
        Some(Value::String(text)) => match text.trim().to_ascii_lowercase().as_str() {
            "true" => Some(true),
            "false" => Some(false),
            _ => None,
        },
        _ => None,
    }
}

fn to_event_string(value: Option<&Value>) -> String {
    match value {
        Some(Value::String(text)) => text.clone(),
        Some(Value::Number(number)) => number.to_string(),
        Some(Value::Bool(value)) => value.to_string(),
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(|item| item.as_str().map(str::to_string))
            .collect::<Vec<_>>()
            .join(", "),
        Some(Value::Object(map)) => serde_json::to_string(map).unwrap_or_default(),
        _ => String::new(),
    }
}

fn summary_text(value: &str, max_chars: usize) -> String {
    let compact = value.split_whitespace().collect::<Vec<_>>().join(" ");
    if compact.chars().count() <= max_chars {
        return compact;
    }
    compact
        .chars()
        .take(max_chars.saturating_sub(1))
        .collect::<String>()
        + "…"
}

fn tool_name_for_step(record: &SkillRecord, step_index: usize) -> String {
    record
        .macro_body
        .steps
        .get(step_index)
        .and_then(|step| serde_json::from_slice::<Value>(&step.params).ok())
        .and_then(|params| {
            params
                .get(QUEUE_TOOL_NAME_KEY)
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .unwrap_or_else(|| record.macro_body.steps[step_index].target.canonical_label())
}

fn used_tools_for_record(record: &SkillRecord) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut tools = Vec::new();
    for index in 0..record.macro_body.steps.len() {
        let tool_name = tool_name_for_step(record, index);
        if seen.insert(tool_name.clone()) {
            tools.push(tool_name);
        }
    }
    tools
}

fn benchmark_view(record: &SkillRecord) -> SkillBenchmarkView {
    let benchmark = record.benchmark.clone().unwrap_or_default();
    SkillBenchmarkView {
        sample_size: benchmark.sample_size,
        success_rate_bps: benchmark.success_rate_bps,
        intervention_rate_bps: benchmark.intervention_rate_bps,
        policy_incident_rate_bps: benchmark.policy_incident_rate_bps,
        avg_cost: benchmark.avg_cost,
        avg_latency_ms: benchmark.avg_latency_ms,
        passed: benchmark.passed,
        last_evaluated_height: benchmark.last_evaluated_height,
    }
}

fn bundle_relative_path(bundle: &SkillBundle) -> Option<String> {
    bundle
        .published_doc
        .as_ref()
        .map(|doc| doc.relative_path.clone())
        .or_else(|| {
            bundle
                .record
                .publication
                .as_ref()
                .map(|publication| publication.relative_path.clone())
        })
}

fn bundle_stale(bundle: &SkillBundle) -> bool {
    bundle
        .published_doc
        .as_ref()
        .map(|doc| doc.stale)
        .or_else(|| {
            bundle
                .record
                .publication
                .as_ref()
                .map(|publication| publication.stale)
        })
        .unwrap_or(false)
}

fn skill_catalog_entry_from_bundle(bundle: &SkillBundle) -> SkillCatalogEntry {
    let benchmark = bundle.record.benchmark.clone().unwrap_or_default();
    SkillCatalogEntry {
        skill_hash: hex::encode(bundle.record.skill_hash),
        name: bundle.record.macro_body.definition.name.clone(),
        description: bundle.record.macro_body.definition.description.clone(),
        lifecycle_state: format!("{:?}", bundle.record.lifecycle_state),
        source_type: format!("{:?}", bundle.record.source_type),
        success_rate_bps: benchmark.success_rate_bps,
        sample_size: benchmark.sample_size,
        frame_id: bundle.record.frame_id,
        source_session_id: bundle.record.source_session_id.map(hex::encode),
        source_evidence_hash: bundle.record.source_evidence_hash.map(hex::encode),
        relative_path: bundle_relative_path(bundle),
        stale: bundle_stale(bundle),
        definition: bundle.record.macro_body.definition.clone(),
    }
}

fn skill_tokens(record: &SkillRecord) -> HashSet<String> {
    format!(
        "{} {} {}",
        record.macro_body.definition.name,
        record.macro_body.definition.description,
        used_tools_for_record(record).join(" ")
    )
    .split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_')
    .filter(|token| token.len() >= 3)
    .map(|token| token.to_ascii_lowercase())
    .collect()
}

fn skill_similarity(left: &SkillRecord, right: &SkillRecord) -> f32 {
    let left_tools = used_tools_for_record(left)
        .into_iter()
        .collect::<HashSet<_>>();
    let right_tools = used_tools_for_record(right)
        .into_iter()
        .collect::<HashSet<_>>();
    let shared_tools = left_tools.intersection(&right_tools).count() as f32;
    let total_tools = left_tools.union(&right_tools).count().max(1) as f32;
    let tool_score = shared_tools / total_tools;

    let left_tokens = skill_tokens(left);
    let right_tokens = skill_tokens(right);
    let shared_tokens = left_tokens.intersection(&right_tokens).count() as f32;
    let total_tokens = left_tokens.union(&right_tokens).count().max(1) as f32;
    let token_score = shared_tokens / total_tokens;

    let same_source_bonus = if left.source_type == right.source_type {
        0.1
    } else {
        0.0
    };
    (tool_score * 0.65) + (token_score * 0.25) + same_source_bonus
}

fn add_node(nodes: &mut Vec<AtlasNode>, seen: &mut HashSet<String>, node: AtlasNode) {
    if seen.insert(node.id.clone()) {
        nodes.push(node);
    }
}

fn add_edge(edges: &mut Vec<AtlasEdge>, seen: &mut HashSet<String>, edge: AtlasEdge) {
    if seen.insert(edge.id.clone()) {
        edges.push(edge);
    }
}

fn build_skill_neighborhood(bundles: &[SkillBundle], focus_hash: &[u8; 32]) -> AtlasNeighborhood {
    let mut nodes = Vec::new();
    let mut node_ids = HashSet::new();
    let mut edges = Vec::new();
    let mut edge_ids = HashSet::new();
    let mut title = "Skill graph".to_string();
    let mut summary = "No skill context available.".to_string();
    let focus_id = skill_focus_id(focus_hash);

    let Some(focus_bundle) = bundles
        .iter()
        .find(|bundle| bundle.record.skill_hash == *focus_hash)
    else {
        return AtlasNeighborhood {
            lens: "skills".to_string(),
            title,
            summary,
            focus_id: Some(focus_id),
            nodes,
            edges,
        };
    };

    title = focus_bundle.record.macro_body.definition.name.clone();
    summary = focus_bundle
        .record
        .macro_body
        .definition
        .description
        .clone();

    add_node(
        &mut nodes,
        &mut node_ids,
        AtlasNode {
            id: focus_id.clone(),
            kind: "skill".to_string(),
            label: focus_bundle.record.macro_body.definition.name.clone(),
            summary: focus_bundle
                .record
                .macro_body
                .definition
                .description
                .clone(),
            status: Some(format!("{:?}", focus_bundle.record.lifecycle_state)),
            emphasis: Some(1.0),
            metadata: json!({
                "lifecycle_state": format!("{:?}", focus_bundle.record.lifecycle_state),
                "source_type": format!("{:?}", focus_bundle.record.source_type),
                "success_rate_bps": focus_bundle.record.benchmark.clone().unwrap_or_default().success_rate_bps,
                "sample_size": focus_bundle.record.benchmark.clone().unwrap_or_default().sample_size,
            }),
        },
    );

    for tool_name in used_tools_for_record(&focus_bundle.record) {
        let tool_id = tool_focus_id(&tool_name);
        add_node(
            &mut nodes,
            &mut node_ids,
            AtlasNode {
                id: tool_id.clone(),
                kind: "tool".to_string(),
                label: tool_name.clone(),
                summary: format!(
                    "Capability used by {}",
                    focus_bundle.record.macro_body.definition.name
                ),
                status: None,
                emphasis: Some(0.72),
                metadata: json!({}),
            },
        );
        add_edge(
            &mut edges,
            &mut edge_ids,
            AtlasEdge {
                id: format!("{}::uses_tool::{}", focus_id, tool_id),
                source_id: focus_id.clone(),
                target_id: tool_id,
                relation: "uses_tool".to_string(),
                summary: Some("Macro step invokes this tool".to_string()),
                weight: 0.85,
            },
        );
    }

    if let Some(doc) = focus_bundle.published_doc.as_ref() {
        let doc_id = doc_focus_id(&focus_bundle.record.skill_hash);
        add_node(
            &mut nodes,
            &mut node_ids,
            AtlasNode {
                id: doc_id.clone(),
                kind: "published_doc".to_string(),
                label: doc.name.clone(),
                summary: summary_text(&doc.markdown, 180),
                status: Some(if doc.stale { "stale" } else { "fresh" }.to_string()),
                emphasis: Some(0.58),
                metadata: json!({
                    "relative_path": doc.relative_path,
                    "generator_version": doc.generator_version,
                }),
            },
        );
        add_edge(
            &mut edges,
            &mut edge_ids,
            AtlasEdge {
                id: format!("{}::published_as::{}", focus_id, doc_id),
                source_id: focus_id.clone(),
                target_id: doc_id,
                relation: "published_as".to_string(),
                summary: Some("Promoted human-facing documentation".to_string()),
                weight: 0.7,
            },
        );
    }

    if let (Some(evidence_hash), Some(evidence)) = (
        focus_bundle.record.source_evidence_hash,
        focus_bundle.evidence.as_ref(),
    ) {
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
                summary: summary_text(&evidence.normalized_procedure, 180),
                status: Some(format!("{:?}", evidence.source_type)),
                emphasis: Some(0.64),
                metadata: json!({
                    "source_uri": evidence.source_uri,
                    "source_type": format!("{:?}", evidence.source_type),
                }),
            },
        );
        add_edge(
            &mut edges,
            &mut edge_ids,
            AtlasEdge {
                id: format!("{}::derived_from::{}", focus_id, evidence_id),
                source_id: focus_id.clone(),
                target_id: evidence_id,
                relation: "derived_from".to_string(),
                summary: Some("Candidate procedure evidence".to_string()),
                weight: 0.74,
            },
        );
    }

    if let Some(session_id) = focus_bundle.record.source_session_id {
        let session_hex = hex::encode(session_id);
        let session_id = session_focus_id(&session_hex);
        add_node(
            &mut nodes,
            &mut node_ids,
            AtlasNode {
                id: session_id.clone(),
                kind: "session".to_string(),
                label: format!("Session {}", &session_hex[..12]),
                summary: "Source session for this skill".to_string(),
                status: None,
                emphasis: Some(0.5),
                metadata: json!({ "session_id": session_hex }),
            },
        );
        add_edge(
            &mut edges,
            &mut edge_ids,
            AtlasEdge {
                id: format!("{}::validated_by::{}", focus_id, session_id),
                source_id: focus_id.clone(),
                target_id: session_id,
                relation: "validated_by".to_string(),
                summary: Some("Session provenance or benchmark lineage".to_string()),
                weight: 0.55,
            },
        );
    }

    let mut related = bundles
        .iter()
        .filter(|bundle| bundle.record.skill_hash != *focus_hash)
        .map(|bundle| {
            (
                skill_similarity(&focus_bundle.record, &bundle.record),
                bundle,
            )
        })
        .filter(|(score, _)| *score >= 0.18)
        .collect::<Vec<_>>();
    related.sort_by(|left, right| {
        right
            .0
            .partial_cmp(&left.0)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    for (score, bundle) in related.into_iter().take(6) {
        let related_id = skill_focus_id(&bundle.record.skill_hash);
        add_node(
            &mut nodes,
            &mut node_ids,
            AtlasNode {
                id: related_id.clone(),
                kind: "skill".to_string(),
                label: bundle.record.macro_body.definition.name.clone(),
                summary: bundle.record.macro_body.definition.description.clone(),
                status: Some(format!("{:?}", bundle.record.lifecycle_state)),
                emphasis: Some(score.max(0.25)),
                metadata: json!({
                    "lifecycle_state": format!("{:?}", bundle.record.lifecycle_state),
                    "source_type": format!("{:?}", bundle.record.source_type),
                }),
            },
        );
        add_edge(
            &mut edges,
            &mut edge_ids,
            AtlasEdge {
                id: format!("{}::similar_to::{}", focus_id, related_id),
                source_id: focus_id.clone(),
                target_id: related_id,
                relation: "similar_to".to_string(),
                summary: Some(format!("Heuristic similarity score {:.2}", score)),
                weight: score.max(0.2),
            },
        );
    }

    AtlasNeighborhood {
        lens: "skills".to_string(),
        title,
        summary,
        focus_id: Some(focus_id),
        nodes,
        edges,
    }
}

fn build_substrate_receipts(events: &[crate::models::AgentEvent]) -> Vec<SubstrateProofReceipt> {
    let mut receipts = Vec::new();
    for event in events {
        if event.event_type != crate::models::EventType::Receipt {
            continue;
        }
        let digest = event.digest.as_object().cloned().unwrap_or_default();
        let kind = to_event_string(digest.get("kind")).to_ascii_lowercase();
        if kind != "scs_retrieve" {
            continue;
        }
        let payload = event
            .details
            .get("payload")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        receipts.push(SubstrateProofReceipt {
            event_id: event.event_id.clone(),
            timestamp: event.timestamp.clone(),
            step_index: event.step_index,
            tool_name: {
                let tool_name = to_event_string(digest.get("tool_name"));
                if tool_name.is_empty() {
                    "scs_retrieve".to_string()
                } else {
                    tool_name
                }
            },
            query_hash: to_event_string(digest.get("query_hash")),
            index_root: to_event_string(digest.get("index_root")),
            k: to_optional_number(digest.get("k")).unwrap_or(1) as u32,
            ef_search: to_optional_number(digest.get("ef_search")).unwrap_or(1) as u32,
            candidate_limit: to_optional_number(digest.get("candidate_limit")).unwrap_or(1) as u32,
            candidate_total: to_optional_number(digest.get("candidate_count_total")).unwrap_or(0)
                as u32,
            candidate_reranked: to_optional_number(digest.get("candidate_count_reranked"))
                .unwrap_or(0) as u32,
            candidate_truncated: to_optional_bool(digest.get("candidate_truncated"))
                .unwrap_or(false),
            distance_metric: {
                let metric = to_event_string(digest.get("distance_metric"));
                if metric.is_empty() {
                    "unknown".to_string()
                } else {
                    metric
                }
            },
            embedding_normalized: to_optional_bool(digest.get("embedding_normalized"))
                .unwrap_or(false),
            proof_hash: {
                let value = to_event_string(payload.get("proof_hash"));
                if value.is_empty() {
                    None
                } else {
                    Some(value)
                }
            },
            proof_ref: {
                let value = to_event_string(payload.get("proof_ref"));
                if value.is_empty() {
                    None
                } else {
                    Some(value)
                }
            },
            certificate_mode: {
                let value = to_event_string(payload.get("certificate_mode"));
                if value.is_empty() {
                    None
                } else {
                    Some(value)
                }
            },
            success: to_optional_bool(digest.get("success")).unwrap_or(true),
            error_class: {
                let value = to_event_string(digest.get("error_class"));
                if value.is_empty() {
                    None
                } else {
                    Some(value)
                }
            },
        });
    }
    receipts.sort_by(|left, right| left.timestamp.cmp(&right.timestamp));
    receipts
}

fn build_substrate_neighborhood(
    receipts: &[SubstrateProofReceipt],
    session_id: Option<&str>,
) -> AtlasNeighborhood {
    let mut nodes = Vec::new();
    let mut node_ids = HashSet::new();
    let mut edges = Vec::new();
    let mut edge_ids = HashSet::new();
    let focus_id = session_id.map(session_focus_id);

    if let Some(session_id) = session_id {
        add_node(
            &mut nodes,
            &mut node_ids,
            AtlasNode {
                id: session_focus_id(session_id),
                kind: "session".to_string(),
                label: format!("Session {}", &normalize_hex_id(session_id)[..12]),
                summary: "Substrate retrieval receipts for this session".to_string(),
                status: None,
                emphasis: Some(1.0),
                metadata: json!({ "session_id": normalize_hex_id(session_id) }),
            },
        );
    }

    for (index, receipt) in receipts.iter().enumerate() {
        let query_id = format!("query:{}", receipt.query_hash);
        let root_id = format!("root:{}", receipt.index_root);
        let proof_id = receipt
            .proof_hash
            .as_ref()
            .map(|proof_hash| format!("proof:{}", proof_hash))
            .unwrap_or_else(|| format!("proof:{}", index));

        add_node(
            &mut nodes,
            &mut node_ids,
            AtlasNode {
                id: query_id.clone(),
                kind: "query".to_string(),
                label: format!("Query {}", summary_text(&receipt.query_hash, 14)),
                summary: format!(
                    "{} · k={} · ef={}",
                    receipt.tool_name, receipt.k, receipt.ef_search
                ),
                status: Some(
                    if receipt.success {
                        "success"
                    } else {
                        "failure"
                    }
                    .to_string(),
                ),
                emphasis: Some(0.68),
                metadata: json!({
                    "candidate_total": receipt.candidate_total,
                    "candidate_reranked": receipt.candidate_reranked,
                }),
            },
        );
        add_node(
            &mut nodes,
            &mut node_ids,
            AtlasNode {
                id: root_id.clone(),
                kind: "index_root".to_string(),
                label: format!("Index {}", summary_text(&receipt.index_root, 14)),
                summary: "Committed retrieval index root".to_string(),
                status: receipt.certificate_mode.clone(),
                emphasis: Some(0.6),
                metadata: json!({
                    "distance_metric": receipt.distance_metric,
                    "embedding_normalized": receipt.embedding_normalized,
                }),
            },
        );
        add_node(
            &mut nodes,
            &mut node_ids,
            AtlasNode {
                id: proof_id.clone(),
                kind: "proof".to_string(),
                label: receipt
                    .proof_hash
                    .as_ref()
                    .map(|value| format!("Proof {}", summary_text(value, 14)))
                    .unwrap_or_else(|| "Receipt".to_string()),
                summary: receipt
                    .certificate_mode
                    .clone()
                    .unwrap_or_else(|| "Retrieval proof material".to_string()),
                status: receipt.certificate_mode.clone(),
                emphasis: Some(0.48),
                metadata: json!({
                    "proof_ref": receipt.proof_ref,
                    "certificate_mode": receipt.certificate_mode,
                }),
            },
        );

        if let Some(session_id) = session_id {
            let session_id = session_focus_id(session_id);
            add_edge(
                &mut edges,
                &mut edge_ids,
                AtlasEdge {
                    id: format!("{}::issued_query::{}", session_id, query_id),
                    source_id: session_id,
                    target_id: query_id.clone(),
                    relation: "issued_query".to_string(),
                    summary: Some("Session triggered this retrieval".to_string()),
                    weight: 0.82,
                },
            );
        }
        add_edge(
            &mut edges,
            &mut edge_ids,
            AtlasEdge {
                id: format!("{}::searched::{}", query_id, root_id),
                source_id: query_id.clone(),
                target_id: root_id.clone(),
                relation: "searched".to_string(),
                summary: Some("Receipt searched this committed index root".to_string()),
                weight: 0.74,
            },
        );
        add_edge(
            &mut edges,
            &mut edge_ids,
            AtlasEdge {
                id: format!("{}::proven_by::{}", query_id, proof_id),
                source_id: query_id,
                target_id: proof_id,
                relation: "proven_by".to_string(),
                summary: Some("Proof or certificate material for this retrieval".to_string()),
                weight: 0.62,
            },
        );
    }

    AtlasNeighborhood {
        lens: "substrate".to_string(),
        title: "Substrate".to_string(),
        summary: if receipts.is_empty() {
            "No substrate receipts captured for this scope.".to_string()
        } else {
            format!("{} retrieval receipts captured.", receipts.len())
        },
        focus_id,
        nodes,
        edges,
    }
}

fn active_skill_item(bundle: &SkillBundle) -> ActiveContextItem {
    let benchmark = bundle.record.benchmark.clone().unwrap_or_default();
    ActiveContextItem {
        id: skill_focus_id(&bundle.record.skill_hash),
        kind: "skill".to_string(),
        title: bundle.record.macro_body.definition.name.clone(),
        summary: bundle.record.macro_body.definition.description.clone(),
        badge: Some(format!("{:?}", bundle.record.lifecycle_state)),
        secondary_badge: Some(format!("{:?}", bundle.record.source_type)),
        success_rate_bps: Some(benchmark.success_rate_bps),
        sample_size: Some(benchmark.sample_size),
        focus_id: Some(skill_focus_id(&bundle.record.skill_hash)),
        skill_hash: Some(hex::encode(bundle.record.skill_hash)),
        source_session_id: bundle.record.source_session_id.map(hex::encode),
        source_evidence_hash: bundle.record.source_evidence_hash.map(hex::encode),
        relative_path: bundle_relative_path(bundle),
        stale: Some(bundle_stale(bundle)),
    }
}

fn build_skill_detail(bundle: &SkillBundle, all_bundles: &[SkillBundle]) -> SkillDetailView {
    let steps = bundle
        .record
        .macro_body
        .steps
        .iter()
        .enumerate()
        .map(|(index, step)| SkillMacroStepView {
            index: index as u32,
            tool_name: tool_name_for_step(&bundle.record, index),
            target: step.target.canonical_label(),
            params_json: serde_json::from_slice::<Value>(&step.params).unwrap_or(Value::Null),
        })
        .collect::<Vec<_>>();

    let benchmark = bundle.record.benchmark.clone().unwrap_or_default();
    SkillDetailView {
        skill_hash: hex::encode(bundle.record.skill_hash),
        name: bundle.record.macro_body.definition.name.clone(),
        description: bundle.record.macro_body.definition.description.clone(),
        lifecycle_state: format!("{:?}", bundle.record.lifecycle_state),
        source_type: format!("{:?}", bundle.record.source_type),
        frame_id: bundle.record.frame_id,
        success_rate_bps: benchmark.success_rate_bps,
        sample_size: benchmark.sample_size,
        source_session_id: bundle.record.source_session_id.map(hex::encode),
        source_evidence_hash: bundle.record.source_evidence_hash.map(hex::encode),
        relative_path: bundle_relative_path(bundle),
        stale: bundle_stale(bundle),
        used_tools: used_tools_for_record(&bundle.record),
        steps,
        benchmark: benchmark_view(&bundle.record),
        markdown: bundle
            .published_doc
            .as_ref()
            .map(|doc| doc.markdown.clone()),
        neighborhood: build_skill_neighborhood(all_bundles, &bundle.record.skill_hash),
    }
}

fn get_scs(
    state: &State<'_, Mutex<AppState>>,
) -> Result<Arc<Mutex<SovereignContextStore>>, String> {
    let guard = state
        .lock()
        .map_err(|_| "Failed to lock state".to_string())?;
    guard
        .studio_scs
        .clone()
        .ok_or_else(|| "Studio SCS is not available".to_string())
}

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
