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
