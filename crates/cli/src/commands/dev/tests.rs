use super::*;
use ioi_types::app::agentic::{SkillBenchmarkReport, SkillPublicationInfo, SkillSourceType};

fn sample_bundle() -> PublishedSkillBundle {
    let record = SkillRecord {
        skill_hash: [7u8; 32],
        archival_record_id: 11,
        macro_body: AgentMacro {
            definition: LlmToolDefinition {
                name: "browser__open_dashboard".to_string(),
                description: "Open the dashboard.".to_string(),
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
            fitness: 1.0,
        },
        lifecycle_state: SkillLifecycleState::Promoted,
        source_type: SkillSourceType::Imported,
        source_session_id: None,
        source_evidence_hash: Some([5u8; 32]),
        benchmark: Some(SkillBenchmarkReport {
            sample_size: 8,
            success_rate_bps: 9_250,
            intervention_rate_bps: 0,
            policy_incident_rate_bps: 0,
            avg_cost: 77,
            avg_latency_ms: 0,
            passed: true,
            last_evaluated_height: 9,
        }),
        publication: None,
        created_at: 1,
        updated_at: 2,
    };
    let markdown = render_skill_markdown(&record);
    let digest = sha256(markdown.as_bytes()).expect("hash");
    let mut doc_hash = [0u8; 32];
    doc_hash.copy_from_slice(digest.as_ref());
    let relative_path = skill_doc_relative_path(&record);
    let publication = SkillPublicationInfo {
        generator_version: SKILL_DOC_GENERATOR_VERSION.to_string(),
        generated_at: 123,
        doc_hash,
        relative_path: relative_path.clone(),
        stale: false,
    };
    let doc = PublishedSkillDoc {
        skill_hash: record.skill_hash,
        name: record.macro_body.definition.name.clone(),
        markdown,
        generator_version: SKILL_DOC_GENERATOR_VERSION.to_string(),
        generated_at: 123,
        source_trace_hash: record.macro_body.source_trace_hash,
        source_evidence_hash: record.source_evidence_hash,
        lifecycle_state: record.lifecycle_state,
        doc_hash,
        relative_path,
        stale: false,
    };
    PublishedSkillBundle {
        record: SkillRecord {
            publication: Some(publication),
            ..record
        },
        doc,
    }
}

#[test]
fn verify_state_publication_accepts_matching_bundle() {
    let bundle = sample_bundle();
    verify_state_publication(&bundle).expect("bundle should verify");
}

#[test]
fn render_skill_index_markdown_lists_promoted_docs() {
    let bundle = sample_bundle();
    let markdown = render_skill_index_markdown(&[bundle]);
    assert!(markdown.contains("browser__open_dashboard"));
    assert!(markdown.contains("skills/browser__open_dashboard/SKILL.md"));
    assert!(markdown.contains("success=`9250 bps`"));
}
