use super::*;

fn long_output(lines: usize) -> String {
    (0..lines)
        .map(|i| format!("line {i}"))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn search_flow_events_link_to_web_artifact_and_prior_step() {
    let web_ref = ArtifactRef {
        artifact_id: "web-1".to_string(),
        artifact_type: ArtifactType::Web,
    };

    let navigate = emit_browser_navigate(
        "thread-1",
        1,
        "browser__navigate",
        "https://example.com?q=rust",
        EventStatus::Success,
        vec![web_ref.clone()],
        vec![],
    );
    assert_eq!(navigate.event_type, EventType::BrowserNavigate);
    assert_eq!(navigate.artifact_refs.len(), 1);
    assert_eq!(navigate.artifact_refs[0].artifact_type, ArtifactType::Web);

    let snapshot = emit_browser_snapshot(
        "thread-1",
        2,
        "browser__inspect",
        "Top links https://example.com/a https://example.com/b",
        EventStatus::Success,
        vec![web_ref],
        vec![navigate.event_id.clone()],
    );
    assert_eq!(snapshot.event_type, EventType::BrowserSnapshot);
    assert_eq!(snapshot.input_refs[0], navigate.event_id);

    let completion = emit_command_run(
        "thread-1",
        3,
        "agent__complete",
        "Completed web synthesis",
        EventStatus::Success,
        snapshot.artifact_refs.clone(),
        vec![snapshot.event_id.clone()],
    );
    assert_eq!(completion.input_refs[0], snapshot.event_id);
    assert_eq!(completion.artifact_refs[0].artifact_type, ArtifactType::Web);
}

#[test]
fn large_command_output_plans_log_artifact() {
    let output = long_output(210);
    let planned = planned_artifact_types(&EventType::CommandRun, &output);
    assert_eq!(planned, vec![ArtifactType::Log]);
}

#[test]
fn large_diff_plans_diff_artifact() {
    let mut diff = String::new();
    for file in 0..4 {
        diff.push_str(&format!("diff --git a/f{file}.rs b/f{file}.rs\n"));
        diff.push_str("--- a/file\n+++ b/file\n");
        diff.push_str("-old\n+new\n");
    }
    let planned = planned_artifact_types(&EventType::FileEdit, &diff);
    assert_eq!(planned, vec![ArtifactType::Diff]);
}
