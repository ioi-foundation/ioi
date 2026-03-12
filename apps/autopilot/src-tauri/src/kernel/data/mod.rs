mod commands;

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

pub use commands::*;

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
