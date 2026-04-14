use super::*;
use std::fs;
use uuid::Uuid;

fn temp_workspace() -> std::path::PathBuf {
    let root = std::env::temp_dir().join(format!("workspace-workflow-tests-{}", Uuid::new_v4()));
    fs::create_dir_all(&root).expect("temp workspace root should exist");
    root
}

fn write_workflow(root: &Path, relative_path: &str, markdown: &str) {
    let path = root.join(relative_path);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("workflow parent should exist");
    }
    fs::write(path, markdown).expect("workflow fixture should write");
}

#[test]
fn parse_rendered_steps_tracks_turbo_scope() {
    let body = r#"
1. Review the diff
// turbo
2. Run tests
```bash
cargo test -p app
```
// turbo-all
3. Deploy
"#;

    let (steps, turbo_all) = parse_rendered_steps(body);
    assert!(turbo_all);
    assert_eq!(steps.len(), 4);
    assert!(steps[1].contains("| turbo]"));
    assert!(steps[2].contains("| turbo]"));
}

#[test]
fn parse_frontmatter_reads_description() {
    let markdown = "---\ndescription: Deploy the staging stack\n---\n1. Build";
    let (description, body) = parse_frontmatter_and_body(markdown);
    assert_eq!(description.as_deref(), Some("Deploy the staging stack"));
    assert_eq!(body, "1. Build");
}

#[test]
fn discover_workspace_workflows_prefers_higher_precedence_roots() {
    let root = temp_workspace();
    write_workflow(
        &root,
        "_agent/workflows/deploy.md",
        "---\ndescription: Lowest precedence deploy\n---\n1. Deploy old path",
    );
    write_workflow(
        &root,
        ".agent/workflows/deploy.md",
        "---\ndescription: Preferred deploy\n---\n1. Deploy preferred path",
    );
    write_workflow(
        &root,
        ".agents/workflows/review.md",
        "---\ndescription: Review workspace\n---\n1. Inspect diff",
    );

    let discovered =
        discover_workspace_workflows_from_root(&root).expect("workflow discovery should work");

    let deploy = discovered
        .iter()
        .find(|workflow| workflow.summary.workflow_id == "deploy")
        .expect("deploy workflow should exist");
    assert_eq!(deploy.summary.description, "Preferred deploy");
    assert_eq!(deploy.summary.source_root, ".agent/workflows");
    assert!(deploy.markdown.contains("Deploy preferred path"));

    let review = discovered
        .iter()
        .find(|workflow| workflow.summary.workflow_id == "review")
        .expect("review workflow should exist");
    assert_eq!(review.summary.source_root, ".agents/workflows");

    let _ = fs::remove_dir_all(root);
}

#[test]
fn expand_workspace_workflow_intent_uses_root_scoped_discovery_and_trailing_context() {
    let root = temp_workspace();
    write_workflow(
        &root,
        ".agents/workflows/deploy-staging.md",
        r#"---
description: Deploy staging safely
---
1. Confirm the release SHA
// turbo
2. Run the staging deploy command
```bash
pnpm deploy:staging
```"#,
    );

    let expansion = expand_workspace_workflow_intent_from_root(
        &root,
        "/deploy-staging use the canary shard first",
    )
    .expect("workflow expansion should succeed")
    .expect("workflow expansion should exist");

    assert_eq!(expansion.summary.workflow_id, "deploy-staging");
    assert_eq!(expansion.summary.description, "Deploy staging safely");
    assert!(expansion
        .expanded_intent
        .contains("ADDITIONAL USER CONTEXT AFTER THE SLASH COMMAND:\nuse the canary shard first"));
    assert!(expansion
        .expanded_intent
        .contains("1. [manual step] Confirm the release SHA"));
    assert!(expansion
        .expanded_intent
        .contains("2. [manual step | turbo] Run the staging deploy command"));
    assert!(expansion
        .expanded_intent
        .contains("3. [command step | turbo] pnpm deploy:staging"));
    assert!(expansion
        .announcement
        .contains("Loaded workspace workflow /deploy-staging"));

    let _ = fs::remove_dir_all(root);
}
