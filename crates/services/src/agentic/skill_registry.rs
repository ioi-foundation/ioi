use crate::agentic::runtime::keys::{
    get_skill_doc_key, get_skill_record_key, SKILL_CATALOG_INDEX_KEY, SKILL_DOC_INDEX_KEY,
};
use ioi_api::state::StateAccess;
use ioi_crypto::algorithms::hash::sha256;
use ioi_memory::ArchivalMemoryRecord;
use ioi_types::app::agentic::{
    AgentMacro, LlmToolDefinition, PublishedSkillDoc, SkillBenchmarkReport, SkillCatalogIndex,
    SkillLifecycleState, SkillPublicationInfo, SkillRecord, SkillStats,
};
use ioi_types::codec;
use ioi_types::error::TransactionError;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

pub const SKILL_DOC_GENERATOR_VERSION: &str = "ioi-skill-docs-v1";
pub const SKILL_ARCHIVAL_SCOPE: &str = "desktop.skills";
pub const SKILL_ARCHIVAL_KIND: &str = "skill.macro";
const VALIDATED_MIN_SUCCESS_BPS: u32 = 8_000;
const VALIDATED_MIN_SAMPLE_SIZE: u32 = 1;
const PROMOTED_MIN_SUCCESS_BPS: u32 = 9_000;
const PROMOTED_MIN_SAMPLE_SIZE: u32 = 5;
const DEPRECATION_MAX_SUCCESS_BPS: u32 = 6_999;
const DEPRECATION_MIN_SAMPLE_SIZE: u32 = 3;

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

pub fn canonical_skill_hash(skill: &AgentMacro) -> Result<[u8; 32], TransactionError> {
    let skill_bytes = codec::to_bytes_canonical(skill).map_err(TransactionError::Serialization)?;
    let digest = sha256(&skill_bytes).map_err(|e| TransactionError::Invalid(e.to_string()))?;
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_ref());
    Ok(out)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillArchivalMetadata {
    pub skill_hash_hex: String,
    pub tool_name: String,
    pub skill_json: serde_json::Value,
}

pub fn skill_archival_content(definition: &LlmToolDefinition) -> String {
    format!("{}: {}", definition.name, definition.description)
}

pub fn build_skill_archival_metadata_json(
    skill_hash: [u8; 32],
    skill: &AgentMacro,
) -> Result<String, TransactionError> {
    let metadata = SkillArchivalMetadata {
        skill_hash_hex: hex::encode(skill_hash),
        tool_name: skill.definition.name.clone(),
        skill_json: serde_json::to_value(skill)
            .map_err(|e| TransactionError::Serialization(e.to_string()))?,
    };
    serde_json::to_string(&metadata).map_err(|e| TransactionError::Serialization(e.to_string()))
}

pub fn skill_hash_from_archival_metadata_json(metadata_json: &str) -> Option<[u8; 32]> {
    let metadata = serde_json::from_str::<SkillArchivalMetadata>(metadata_json).ok()?;
    let raw = hex::decode(metadata.skill_hash_hex).ok()?;
    if raw.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Some(out)
}

pub fn skill_hash_from_archival_record(record: &ArchivalMemoryRecord) -> Option<[u8; 32]> {
    skill_hash_from_archival_metadata_json(&record.metadata_json)
}

pub fn load_skill_catalog_index(
    state: &dyn StateAccess,
) -> Result<SkillCatalogIndex, TransactionError> {
    if let Some(bytes) = state.get(SKILL_CATALOG_INDEX_KEY)? {
        return Ok(codec::from_bytes_canonical(&bytes).unwrap_or_default());
    }
    Ok(SkillCatalogIndex::default())
}

pub fn load_doc_catalog_index(
    state: &dyn StateAccess,
) -> Result<SkillCatalogIndex, TransactionError> {
    if let Some(bytes) = state.get(SKILL_DOC_INDEX_KEY)? {
        return Ok(codec::from_bytes_canonical(&bytes).unwrap_or_default());
    }
    Ok(SkillCatalogIndex::default())
}

fn store_skill_catalog_index(
    state: &mut dyn StateAccess,
    index: &SkillCatalogIndex,
) -> Result<(), TransactionError> {
    state.insert(SKILL_CATALOG_INDEX_KEY, &codec::to_bytes_canonical(index)?)?;
    Ok(())
}

fn store_doc_catalog_index(
    state: &mut dyn StateAccess,
    index: &SkillCatalogIndex,
) -> Result<(), TransactionError> {
    state.insert(SKILL_DOC_INDEX_KEY, &codec::to_bytes_canonical(index)?)?;
    Ok(())
}

pub fn load_skill_record(
    state: &dyn StateAccess,
    skill_hash: &[u8; 32],
) -> Result<Option<SkillRecord>, TransactionError> {
    let key = get_skill_record_key(skill_hash);
    Ok(state
        .get(&key)?
        .and_then(|bytes| codec::from_bytes_canonical::<SkillRecord>(&bytes).ok()))
}

pub fn upsert_skill_record(
    state: &mut dyn StateAccess,
    record: &SkillRecord,
) -> Result<(), TransactionError> {
    let key = get_skill_record_key(&record.skill_hash);
    state.insert(&key, &codec::to_bytes_canonical(record)?)?;

    let mut index = load_skill_catalog_index(state)?;
    if !index.skills.iter().any(|hash| hash == &record.skill_hash) {
        index.skills.push(record.skill_hash);
        index.skills.sort();
        index.skills.dedup();
        store_skill_catalog_index(state, &index)?;
    }
    Ok(())
}

pub fn load_published_skill_doc(
    state: &dyn StateAccess,
    skill_hash: &[u8; 32],
) -> Result<Option<PublishedSkillDoc>, TransactionError> {
    let key = get_skill_doc_key(skill_hash);
    Ok(state
        .get(&key)?
        .and_then(|bytes| codec::from_bytes_canonical::<PublishedSkillDoc>(&bytes).ok()))
}

pub fn upsert_published_skill_doc(
    state: &mut dyn StateAccess,
    doc: &PublishedSkillDoc,
) -> Result<(), TransactionError> {
    let key = get_skill_doc_key(&doc.skill_hash);
    state.insert(&key, &codec::to_bytes_canonical(doc)?)?;

    let mut index = load_doc_catalog_index(state)?;
    if !index.skills.iter().any(|hash| hash == &doc.skill_hash) {
        index.skills.push(doc.skill_hash);
        index.skills.sort();
        index.skills.dedup();
        store_doc_catalog_index(state, &index)?;
    }
    Ok(())
}

pub fn build_benchmark_report(
    stats: &SkillStats,
    last_evaluated_height: u64,
) -> SkillBenchmarkReport {
    let sample_size = stats.uses;
    let success_rate_bps = stats.success_rate_bps();
    let passed =
        sample_size >= VALIDATED_MIN_SAMPLE_SIZE && success_rate_bps >= VALIDATED_MIN_SUCCESS_BPS;
    SkillBenchmarkReport {
        sample_size,
        success_rate_bps,
        intervention_rate_bps: 0,
        policy_incident_rate_bps: 0,
        avg_cost: stats.avg_cost,
        avg_latency_ms: 0,
        passed,
        last_evaluated_height,
    }
}

pub fn next_lifecycle_state(
    current: SkillLifecycleState,
    benchmark: &SkillBenchmarkReport,
) -> SkillLifecycleState {
    if current == SkillLifecycleState::Deprecated {
        return SkillLifecycleState::Deprecated;
    }

    if benchmark.sample_size >= PROMOTED_MIN_SAMPLE_SIZE
        && benchmark.success_rate_bps >= PROMOTED_MIN_SUCCESS_BPS
        && benchmark.policy_incident_rate_bps == 0
    {
        return SkillLifecycleState::Promoted;
    }

    if benchmark.sample_size >= VALIDATED_MIN_SAMPLE_SIZE
        && benchmark.success_rate_bps >= VALIDATED_MIN_SUCCESS_BPS
        && benchmark.policy_incident_rate_bps == 0
    {
        return SkillLifecycleState::Validated;
    }

    if current == SkillLifecycleState::Promoted
        && benchmark.sample_size >= DEPRECATION_MIN_SAMPLE_SIZE
        && benchmark.success_rate_bps <= DEPRECATION_MAX_SUCCESS_BPS
    {
        return SkillLifecycleState::Deprecated;
    }

    current
}

pub fn skill_is_runtime_eligible(record: &SkillRecord) -> bool {
    matches!(
        record.lifecycle_state,
        SkillLifecycleState::Validated | SkillLifecycleState::Promoted
    )
}

pub fn skill_reliability_score(
    benchmark: Option<&SkillBenchmarkReport>,
    stats: Option<&SkillStats>,
) -> f32 {
    if let Some(stats) = stats {
        return stats.reliability().clamp(0.0, 1.0);
    }
    if let Some(benchmark) = benchmark {
        if benchmark.sample_size == 0 {
            return 0.5;
        }
        return (benchmark.success_rate_bps as f32 / 10_000.0).clamp(0.0, 1.0);
    }
    0.5
}

pub fn adjusted_skill_discovery_score(hit_score: f32, reliability: f32) -> f32 {
    hit_score + (reliability.clamp(0.0, 1.0) * 0.2)
}

pub fn skill_guidance_markdown(
    record: &SkillRecord,
    published_doc: Option<&PublishedSkillDoc>,
) -> String {
    published_doc
        .map(|doc| doc.markdown.clone())
        .unwrap_or_else(|| render_skill_markdown(record))
}

pub fn skill_doc_relative_path(record: &SkillRecord) -> String {
    format!("skills/{}/SKILL.md", record.macro_body.definition.name)
}

pub fn render_skill_markdown(record: &SkillRecord) -> String {
    let benchmark = record.benchmark.clone().unwrap_or_default();
    let mut out = String::new();
    out.push_str("---\n");
    out.push_str(&format!("name: {}\n", record.macro_body.definition.name));
    out.push_str(&format!(
        "description: \"{}\"\n",
        record
            .macro_body
            .definition
            .description
            .replace('"', "\\\"")
    ));
    out.push_str(&format!(
        "source_macro_hash: {}\n",
        hex::encode(record.skill_hash)
    ));
    out.push_str(&format!(
        "generator_version: {}\n",
        SKILL_DOC_GENERATOR_VERSION
    ));
    out.push_str(&format!(
        "source_trace_hash: {}\n",
        hex::encode(record.macro_body.source_trace_hash)
    ));
    out.push_str(&format!("lifecycle_state: {:?}\n", record.lifecycle_state));
    out.push_str("---\n\n");

    out.push_str(&format!("# {}\n\n", record.macro_body.definition.name));
    out.push_str(&format!("{}\n\n", record.macro_body.definition.description));
    out.push_str("## Lifecycle\n\n");
    out.push_str(&format!(
        "- State: `{:?}`\n- Source Type: `{:?}`\n- Sample Size: `{}`\n- Success Rate: `{} bps`\n- Avg Cost: `{}`\n\n",
        record.lifecycle_state,
        record.source_type,
        benchmark.sample_size,
        benchmark.success_rate_bps,
        benchmark.avg_cost
    ));

    out.push_str("## Interface\n\n");
    out.push_str("```json\n");
    out.push_str(&record.macro_body.definition.parameters);
    out.push_str("\n```\n\n");

    out.push_str("## Steps\n\n");
    for (index, step) in record.macro_body.steps.iter().enumerate() {
        let params = serde_json::from_slice::<serde_json::Value>(&step.params)
            .unwrap_or(serde_json::Value::Null);
        out.push_str(&format!(
            "{}. `{}`\n\n```json\n{}\n```\n\n",
            index + 1,
            step.target.canonical_label(),
            serde_json::to_string_pretty(&params).unwrap_or_else(|_| "null".to_string())
        ));
    }

    out.push_str("## Provenance\n\n");
    out.push_str(&format!(
        "- Skill Hash: `0x{}`\n- Trace Hash: `0x{}`\n",
        hex::encode(record.skill_hash),
        hex::encode(record.macro_body.source_trace_hash),
    ));
    if let Some(evidence_hash) = record.source_evidence_hash {
        out.push_str(&format!(
            "- Evidence Hash: `0x{}`\n",
            hex::encode(evidence_hash)
        ));
    }
    out.push_str(&format!(
        "- Archival Record Id: `{}`\n",
        record.archival_record_id
    ));

    out
}

pub fn generate_published_skill_doc(
    record: &SkillRecord,
) -> Result<(PublishedSkillDoc, SkillPublicationInfo), TransactionError> {
    let markdown = render_skill_markdown(record);
    let digest =
        sha256(markdown.as_bytes()).map_err(|e| TransactionError::Invalid(e.to_string()))?;
    let mut doc_hash = [0u8; 32];
    doc_hash.copy_from_slice(digest.as_ref());
    let generated_at = now_ms();
    let relative_path = skill_doc_relative_path(record);

    let doc = PublishedSkillDoc {
        skill_hash: record.skill_hash,
        name: record.macro_body.definition.name.clone(),
        markdown,
        generator_version: SKILL_DOC_GENERATOR_VERSION.to_string(),
        generated_at,
        source_trace_hash: record.macro_body.source_trace_hash,
        source_evidence_hash: record.source_evidence_hash,
        lifecycle_state: record.lifecycle_state,
        doc_hash,
        relative_path: relative_path.clone(),
        stale: false,
    };
    let publication = SkillPublicationInfo {
        generator_version: SKILL_DOC_GENERATOR_VERSION.to_string(),
        generated_at,
        doc_hash,
        relative_path,
        stale: false,
    };
    Ok((doc, publication))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ioi_types::app::agentic::SkillSourceType;
    use ioi_types::app::{ActionContext, ActionRequest, ActionTarget};

    fn sample_record() -> SkillRecord {
        SkillRecord {
            skill_hash: [7u8; 32],
            archival_record_id: 42,
            macro_body: AgentMacro {
                definition: ioi_types::app::agentic::LlmToolDefinition {
                    name: "browser__open_dashboard".to_string(),
                    description: "Open the dashboard and confirm the account summary.".to_string(),
                    parameters: r#"{"type":"object","properties":{"url":{"type":"string"}}}"#
                        .to_string(),
                },
                steps: vec![ActionRequest {
                    target: ActionTarget::BrowserInteract,
                    params: br#"{"__ioi_tool_name":"browser__navigate","url":"{{url}}"}"#.to_vec(),
                    context: ActionContext {
                        agent_id: "macro".to_string(),
                        session_id: None,
                        window_id: None,
                    },
                    nonce: 0,
                }],
                source_trace_hash: [3u8; 32],
                fitness: 0.95,
            },
            lifecycle_state: SkillLifecycleState::Promoted,
            source_type: SkillSourceType::Video,
            source_session_id: Some([9u8; 32]),
            source_evidence_hash: Some([5u8; 32]),
            benchmark: Some(SkillBenchmarkReport {
                sample_size: 6,
                success_rate_bps: 9_500,
                intervention_rate_bps: 0,
                policy_incident_rate_bps: 0,
                avg_cost: 123,
                avg_latency_ms: 456,
                passed: true,
                last_evaluated_height: 77,
            }),
            publication: None,
            created_at: 1,
            updated_at: 2,
        }
    }

    #[test]
    fn next_lifecycle_state_promotes_and_deprecates_using_thresholds() {
        let promoted = next_lifecycle_state(
            SkillLifecycleState::Candidate,
            &SkillBenchmarkReport {
                sample_size: 5,
                success_rate_bps: 9_100,
                intervention_rate_bps: 0,
                policy_incident_rate_bps: 0,
                avg_cost: 0,
                avg_latency_ms: 0,
                passed: true,
                last_evaluated_height: 1,
            },
        );
        assert_eq!(promoted, SkillLifecycleState::Promoted);

        let deprecated = next_lifecycle_state(
            SkillLifecycleState::Promoted,
            &SkillBenchmarkReport {
                sample_size: 4,
                success_rate_bps: 6_000,
                intervention_rate_bps: 0,
                policy_incident_rate_bps: 0,
                avg_cost: 0,
                avg_latency_ms: 0,
                passed: false,
                last_evaluated_height: 2,
            },
        );
        assert_eq!(deprecated, SkillLifecycleState::Deprecated);
    }

    #[test]
    fn generated_skill_doc_is_deterministic_for_content() {
        let record = sample_record();
        let markdown = render_skill_markdown(&record);
        assert!(markdown.contains("# browser__open_dashboard"));
        assert!(markdown.contains("Evidence Hash"));
        assert!(markdown.contains("browser__navigate"));

        let (doc, publication) = generate_published_skill_doc(&record).expect("doc generation");
        assert_eq!(doc.markdown, markdown);
        assert_eq!(doc.relative_path, "skills/browser__open_dashboard/SKILL.md");
        assert_eq!(doc.source_evidence_hash, Some([5u8; 32]));
        assert_eq!(publication.relative_path, doc.relative_path);
        assert_eq!(publication.doc_hash, doc.doc_hash);
    }

    #[test]
    fn only_validated_and_promoted_skills_are_runtime_eligible() {
        let mut record = sample_record();
        record.lifecycle_state = SkillLifecycleState::Candidate;
        assert!(!skill_is_runtime_eligible(&record));
        record.lifecycle_state = SkillLifecycleState::Validated;
        assert!(skill_is_runtime_eligible(&record));
        record.lifecycle_state = SkillLifecycleState::Promoted;
        assert!(skill_is_runtime_eligible(&record));
        record.lifecycle_state = SkillLifecycleState::Deprecated;
        assert!(!skill_is_runtime_eligible(&record));
    }
}
