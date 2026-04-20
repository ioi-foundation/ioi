use super::*;

#[test]
fn builtin_worker_catalog_contains_workload_specialists() {
    let templates = builtin_worker_templates();
    assert_eq!(templates.len(), 9);
    assert!(templates
        .iter()
        .any(|template| template.template_id == "context_worker"));
    assert!(templates
        .iter()
        .any(|template| template.template_id == "researcher"));
    assert!(templates
        .iter()
        .any(|template| template.template_id == "perception_worker"));
    assert!(templates
        .iter()
        .any(|template| template.template_id == "verifier"));
    assert!(templates
        .iter()
        .any(|template| template.template_id == "coder"));
    assert!(templates
        .iter()
        .any(|template| template.template_id == "patch_synthesizer"));
    assert!(templates
        .iter()
        .any(|template| template.template_id == "browser_specialist"));
    assert!(templates
        .iter()
        .any(|template| template.template_id == "browser_operator"));
    assert!(templates
        .iter()
        .any(|template| template.template_id == "artifact_builder"));
    let context_worker = templates
        .iter()
        .find(|template| template.template_id == "context_worker")
        .expect("context_worker template should exist");
    assert!(context_worker
        .allowed_tools
        .iter()
        .any(|tool| tool == "file__info"));
    assert!(context_worker
        .workflows
        .iter()
        .any(|workflow| workflow.workflow_id == "repo_context_brief"));
    assert!(context_worker
        .workflows
        .iter()
        .any(|workflow| workflow.workflow_id == "artifact_context_brief"));
    let repo_context = context_worker
        .workflows
        .iter()
        .find(|workflow| workflow.workflow_id == "repo_context_brief")
        .expect("repo context workflow should exist");
    assert!(repo_context
        .allowed_tools
        .iter()
        .any(|tool| tool == "file__info"));
    assert!(repo_context
        .allowed_tools
        .iter()
        .all(|tool| tool != "agent__delegate"));
    let artifact_context = context_worker
        .workflows
        .iter()
        .find(|workflow| workflow.workflow_id == "artifact_context_brief")
        .expect("artifact context workflow should exist");
    assert!(artifact_context
        .allowed_tools
        .iter()
        .any(|tool| tool == "file__info"));
    assert!(artifact_context
        .allowed_tools
        .iter()
        .all(|tool| tool != "agent__delegate"));
    let researcher = templates
        .iter()
        .find(|template| template.template_id == "researcher")
        .expect("researcher template should exist");
    assert!(researcher
        .workflows
        .iter()
        .any(|workflow| workflow.workflow_id == "live_research_brief"));
    let perception_worker = templates
        .iter()
        .find(|template| template.template_id == "perception_worker")
        .expect("perception_worker template should exist");
    let perception_workflow = perception_worker
        .workflows
        .iter()
        .find(|workflow| workflow.workflow_id == "ui_state_brief")
        .expect("perception workflow should exist");
    assert_eq!(perception_workflow.default_budget, Some(36));
    assert!(perception_workflow
        .allowed_tools
        .iter()
        .all(|tool| tool == "browser__inspect" || tool == "agent__complete"));
    let verifier = templates
        .iter()
        .find(|template| template.template_id == "verifier")
        .expect("verifier template should exist");
    let verifier_workflow = verifier
        .workflows
        .iter()
        .find(|workflow| workflow.workflow_id == "postcondition_audit")
        .expect("verifier workflow should exist");
    assert_eq!(verifier_workflow.default_budget, Some(48));
    assert_eq!(verifier_workflow.max_retries, Some(0));
    assert!(verifier_workflow
        .allowed_tools
        .iter()
        .any(|tool| tool == "model__rerank"));
    assert!(verifier_workflow
        .allowed_tools
        .iter()
        .all(|tool| tool != "model__responses"));
    let citation_audit = verifier
        .workflows
        .iter()
        .find(|workflow| workflow.workflow_id == "citation_audit")
        .expect("citation verifier workflow should exist");
    assert_eq!(citation_audit.default_budget, Some(48));
    assert_eq!(citation_audit.max_retries, Some(0));
    assert!(citation_audit
        .allowed_tools
        .iter()
        .all(|tool| tool != "memory__search"));
    assert!(citation_audit
        .allowed_tools
        .iter()
        .all(|tool| tool != "model__rerank"));
    assert!(citation_audit
        .completion_contract
        .as_ref()
        .and_then(|contract| contract.verification_hint.as_deref())
        .is_some_and(|hint| hint.contains("freshness")));
    let artifact_validation_audit = verifier
        .workflows
        .iter()
        .find(|workflow| workflow.workflow_id == "artifact_validation_audit")
        .expect("artifact validation workflow should exist");
    assert_eq!(artifact_validation_audit.default_budget, Some(52));
    assert_eq!(artifact_validation_audit.max_retries, Some(0));
    assert!(artifact_validation_audit
        .completion_contract
        .as_ref()
        .and_then(|contract| contract
            .expected_output
            .as_str()
            .strip_prefix("Artifact quality scorecard"))
        .is_some());
    let browser_postcondition_audit = verifier
        .workflows
        .iter()
        .find(|workflow| workflow.workflow_id == "browser_postcondition_audit")
        .expect("browser verifier workflow should exist");
    assert_eq!(browser_postcondition_audit.default_budget, Some(48));
    assert_eq!(browser_postcondition_audit.max_retries, Some(0));
    assert!(browser_postcondition_audit
        .completion_contract
        .as_ref()
        .and_then(|contract| contract
            .expected_output
            .as_str()
            .strip_prefix("Computer-use verifier scorecard"))
        .is_some());
    let targeted_test_audit = verifier
        .workflows
        .iter()
        .find(|workflow| workflow.workflow_id == "targeted_test_audit")
        .expect("coding verifier workflow should exist");
    assert_eq!(targeted_test_audit.default_budget, Some(56));
    assert_eq!(targeted_test_audit.max_retries, Some(0));
    assert!(targeted_test_audit
        .allowed_tools
        .iter()
        .any(|tool| tool == "shell__start"));
    let coder = templates
        .iter()
        .find(|template| template.template_id == "coder")
        .expect("coder template should exist");
    let coder_workflow = coder
        .workflows
        .iter()
        .find(|workflow| workflow.workflow_id == "patch_build_verify")
        .expect("coder workflow should exist");
    assert_eq!(coder_workflow.default_budget, Some(96));
    assert_eq!(coder_workflow.max_retries, Some(1));
    assert!(coder_workflow
        .allowed_tools
        .iter()
        .any(|tool| tool == "file__edit"));
    assert!(coder_workflow
        .allowed_tools
        .iter()
        .any(|tool| tool == "file__replace_line"));
    assert!(coder_workflow
        .allowed_tools
        .iter()
        .any(|tool| tool == "shell__start"));
    assert!(coder_workflow
        .allowed_tools
        .iter()
        .any(|tool| tool == "agent__complete"));
    let patch_synthesizer = templates
        .iter()
        .find(|template| template.template_id == "patch_synthesizer")
        .expect("patch_synthesizer template should exist");
    let patch_synth_workflow = patch_synthesizer
        .workflows
        .iter()
        .find(|workflow| workflow.workflow_id == "patch_synthesis_handoff")
        .expect("patch synthesis workflow should exist");
    assert_eq!(patch_synth_workflow.default_budget, Some(40));
    assert_eq!(patch_synth_workflow.max_retries, Some(0));
    assert!(patch_synth_workflow
        .completion_contract
        .as_ref()
        .and_then(|contract| contract.verification_hint.as_deref())
        .is_some_and(|hint| hint.contains("verifier verdict")));
    let browser_operator = templates
        .iter()
        .find(|template| template.template_id == "browser_operator")
        .expect("browser_operator template should exist");
    let browser_workflow = browser_operator
        .workflows
        .iter()
        .find(|workflow| workflow.workflow_id == "browser_postcondition_pass")
        .expect("browser workflow should exist");
    assert!(browser_workflow
        .allowed_tools
        .iter()
        .any(|tool| tool == "browser__inspect"));
    assert!(browser_workflow
        .allowed_tools
        .iter()
        .any(|tool| tool == "browser__click"));
    let browser_specialist = templates
        .iter()
        .find(|template| template.template_id == "browser_specialist")
        .expect("browser_specialist template should exist");
    let browser_specialist_workflow = browser_specialist
        .workflows
        .iter()
        .find(|workflow| workflow.workflow_id == "browser_subagent_session")
        .expect("browser specialist workflow should exist");
    assert!(browser_specialist_workflow
        .allowed_tools
        .iter()
        .all(|tool| !tool.starts_with("screen__")));
    assert!(browser_specialist_workflow
        .allowed_tools
        .iter()
        .any(|tool| tool == "browser__navigate"));
    assert!(browser_specialist_workflow
        .allowed_tools
        .iter()
        .any(|tool| tool == "browser__screenshot"));
    let artifact_builder = templates
        .iter()
        .find(|template| template.template_id == "artifact_builder")
        .expect("artifact_builder template should exist");
    let artifact_workflow = artifact_builder
        .workflows
        .iter()
        .find(|workflow| workflow.workflow_id == "artifact_generate_repair")
        .expect("artifact workflow should exist");
    assert!(artifact_workflow
        .allowed_tools
        .iter()
        .any(|tool| tool == "model__responses"));
    assert!(artifact_workflow
        .allowed_tools
        .iter()
        .any(|tool| tool == "file__write"));
}
