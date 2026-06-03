use super::*;

pub(super) fn semantic_impact_for_state(state: &AgentState) -> SemanticImpactAnalysis {
    let mut impact = SemanticImpactAnalysis::default();
    let mut changed_symbols = BTreeSet::new();
    let mut changed_apis = BTreeSet::new();
    let mut changed_schemas = BTreeSet::new();
    let mut changed_policies = BTreeSet::new();
    let mut affected_call_sites = BTreeSet::new();
    let mut affected_tests = BTreeSet::new();
    let mut affected_docs = BTreeSet::new();
    let mut generated_files_needing_refresh = BTreeSet::new();
    let mut migration_implications = BTreeSet::new();
    let mut unknowns = BTreeSet::new();

    let path_impacts = semantic_impact_paths_from_log(state);
    for observed in &path_impacts {
        if !observed.mutating {
            continue;
        }
        classify_changed_path_for_semantic_impact(
            &observed.path,
            &mut changed_symbols,
            &mut changed_apis,
            &mut changed_schemas,
            &mut changed_policies,
            &mut affected_call_sites,
            &mut affected_tests,
            &mut affected_docs,
            &mut generated_files_needing_refresh,
            &mut migration_implications,
            &mut unknowns,
        );
        impact.evidence_refs.push(EvidenceRef::new(
            "semantic_impact_path",
            format!(
                "{}:{}:{}",
                observed.evidence_key, observed.tool_name, observed.path
            ),
        ));
    }

    for (tool_name, status) in &state.tool_execution_log {
        let effective_tool_name = match status {
            ToolCallStatus::Executed(value) => {
                parse_receipt_tool(value).unwrap_or_else(|| normalize_tool_log_key(tool_name))
            }
            _ => normalize_tool_log_key(tool_name),
        };

        if is_mutating_file_tool(&effective_tool_name)
            && !path_impacts
                .iter()
                .any(|impact| impact.evidence_key == *tool_name && impact.mutating)
        {
            changed_symbols.insert("filesystem_object".to_string());
            affected_tests.insert(
                "targeted tests should be selected after recovering changed path metadata"
                    .to_string(),
            );
            unknowns.insert(format!(
                "mutating file tool lacks changed-path metadata: {effective_tool_name}"
            ));
        }

        if effective_tool_name.starts_with("connector__")
            || effective_tool_name.starts_with("memory__")
        {
            changed_schemas.insert("external_or_memory_state".to_string());
            affected_tests.insert(format!(
                "verify connector or memory contract touched by {effective_tool_name}"
            ));
        }

        if effective_tool_name.starts_with("shell__")
            || effective_tool_name == "software_install__execute_plan"
        {
            migration_implications
                .insert("host command may have changed local environment".to_string());
            if matches!(status, ToolCallStatus::Executed(_)) {
                affected_tests
                    .insert("rerun command-specific verification from shell receipt".to_string());
            } else {
                unknowns.insert(format!(
                    "shell/software install tool lacks execution receipt details: {effective_tool_name}"
                ));
            }
        }
    }

    impact.changed_symbols = changed_symbols.into_iter().collect();
    impact.changed_apis = changed_apis.into_iter().collect();
    impact.changed_schemas = changed_schemas.into_iter().collect();
    impact.changed_policies = changed_policies.into_iter().collect();
    impact.affected_call_sites = affected_call_sites.into_iter().collect();
    impact.affected_tests = affected_tests.into_iter().collect();
    impact.affected_docs = affected_docs.into_iter().collect();
    impact.generated_files_needing_refresh = generated_files_needing_refresh.into_iter().collect();
    impact.migration_implications = migration_implications.into_iter().collect();
    impact.unknowns = unknowns.into_iter().collect();

    impact.risk_class = if impact.changed_symbols.is_empty()
        && impact.changed_apis.is_empty()
        && impact.changed_schemas.is_empty()
        && impact.changed_policies.is_empty()
        && impact.affected_call_sites.is_empty()
        && impact.affected_docs.is_empty()
        && impact.generated_files_needing_refresh.is_empty()
        && impact.migration_implications.is_empty()
    {
        "none_observed".to_string()
    } else if !impact.changed_policies.is_empty() {
        "requires_independent_verification".to_string()
    } else {
        "requires_targeted_verification".to_string()
    };
    impact.evidence_refs.push(EvidenceRef::new(
        "tool_execution_log",
        format!("{} entries", state.tool_execution_log.len()),
    ));
    if impact.risk_class == "none_observed" && !state.tool_execution_log.is_empty() {
        impact
            .unknowns
            .push("tool log lacks object-level diff metadata".to_string());
    }
    impact
}

#[derive(Debug, Clone)]
struct SemanticImpactPathObservation {
    path: String,
    tool_name: String,
    evidence_key: String,
    mutating: bool,
}

fn semantic_impact_paths_from_log(state: &AgentState) -> Vec<SemanticImpactPathObservation> {
    let mut observed = Vec::new();
    let mut seen = BTreeSet::new();

    for (key, status) in &state.tool_execution_log {
        let ToolCallStatus::Executed(value) = status else {
            continue;
        };

        if let Ok(receipt) = serde_json::from_str::<StructuredWorkspaceFileObservation>(value) {
            push_semantic_impact_path(
                &mut observed,
                &mut seen,
                key,
                &receipt.tool_name,
                &receipt.requested_path,
            );
            continue;
        }

        if let Some(path) = parse_receipt_path(value) {
            let tool_name =
                parse_receipt_tool(value).unwrap_or_else(|| normalize_tool_log_key(key));
            push_semantic_impact_path(&mut observed, &mut seen, key, &tool_name, &path);
        }
    }

    observed
}

fn push_semantic_impact_path(
    observed: &mut Vec<SemanticImpactPathObservation>,
    seen: &mut BTreeSet<(String, String, String)>,
    evidence_key: &str,
    tool_name: &str,
    path: &str,
) {
    let path = path.trim();
    if path.is_empty() {
        return;
    }
    let tool_name = normalize_tool_log_key(tool_name);
    let mutating = is_mutating_file_tool(&tool_name)
        || evidence_key == "evidence::workspace_edit_applied=true"
        || evidence_key.starts_with("evidence::workspace_write")
        || evidence_key.starts_with("evidence::workspace_patch");
    let dedupe_key = (
        evidence_key.to_string(),
        tool_name.clone(),
        path.to_string(),
    );
    if !seen.insert(dedupe_key) {
        return;
    }
    observed.push(SemanticImpactPathObservation {
        path: path.to_string(),
        tool_name,
        evidence_key: evidence_key.to_string(),
        mutating,
    });
}

#[allow(clippy::too_many_arguments)]
fn classify_changed_path_for_semantic_impact(
    path: &str,
    changed_symbols: &mut BTreeSet<String>,
    changed_apis: &mut BTreeSet<String>,
    changed_schemas: &mut BTreeSet<String>,
    changed_policies: &mut BTreeSet<String>,
    affected_call_sites: &mut BTreeSet<String>,
    affected_tests: &mut BTreeSet<String>,
    affected_docs: &mut BTreeSet<String>,
    generated_files_needing_refresh: &mut BTreeSet<String>,
    migration_implications: &mut BTreeSet<String>,
    unknowns: &mut BTreeSet<String>,
) {
    let normalized = path.replace('\\', "/");
    let lower = normalized.to_ascii_lowercase();
    let file_name = std::path::Path::new(&normalized)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(&normalized);
    let stem = std::path::Path::new(file_name)
        .file_stem()
        .and_then(|name| name.to_str())
        .unwrap_or(file_name)
        .trim();
    let extension = std::path::Path::new(file_name)
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();

    if is_source_path(&lower, &extension) {
        if !stem.is_empty() {
            changed_symbols.insert(stem.to_string());
            affected_call_sites.insert(format!("call sites importing or invoking {stem}"));
        }
        affected_tests.insert(test_selection_hint_for_path(&normalized, &extension));
        if is_public_api_path(&lower, file_name) {
            changed_apis.insert(normalized.clone());
        }
    }

    if is_test_path(&lower) {
        affected_tests.insert(format!("direct changed test file: {normalized}"));
    }

    if is_schema_or_manifest_path(&lower, file_name, &extension) {
        changed_schemas.insert(normalized.clone());
        affected_tests.insert(format!(
            "contract/schema validation for changed manifest or schema: {normalized}"
        ));
    }

    if is_policy_path(&lower) {
        changed_policies.insert(normalized.clone());
        affected_tests.insert(format!("policy/security regression tests for {normalized}"));
    }

    if is_docs_path(&lower, &extension) {
        affected_docs.insert(normalized.clone());
    }

    if is_generated_path(&lower, file_name) {
        generated_files_needing_refresh.insert(normalized.clone());
        migration_implications.insert(format!(
            "generated or lock artifact changed; verify producer command for {normalized}"
        ));
    }

    if is_migration_path(&lower, file_name, &extension) {
        migration_implications.insert(format!("migration/dependency implication: {normalized}"));
    }

    let categorized = is_source_path(&lower, &extension)
        || is_test_path(&lower)
        || is_schema_or_manifest_path(&lower, file_name, &extension)
        || is_policy_path(&lower)
        || is_docs_path(&lower, &extension)
        || is_generated_path(&lower, file_name)
        || is_migration_path(&lower, file_name, &extension);
    if !categorized {
        changed_symbols.insert("filesystem_object".to_string());
        unknowns.insert(format!(
            "changed path has no semantic category; inspect manually: {normalized}"
        ));
    }
}

fn normalize_tool_log_key(value: &str) -> String {
    value
        .split_once(':')
        .map(|(head, _)| head)
        .unwrap_or(value)
        .trim()
        .to_string()
}

fn is_mutating_file_tool(tool_name: &str) -> bool {
    tool_name.starts_with("file__")
        && !matches!(
            tool_name,
            "file__read"
                | "file__view"
                | "file__list"
                | "file__search"
                | "file__info"
                | "file__stat"
                | "file__diff"
                | "file__history"
                | "file__validate_observation"
        )
}

fn is_source_path(lower: &str, extension: &str) -> bool {
    matches!(
        extension,
        "rs" | "ts"
            | "tsx"
            | "js"
            | "jsx"
            | "py"
            | "go"
            | "java"
            | "kt"
            | "swift"
            | "c"
            | "cc"
            | "cpp"
            | "h"
            | "hpp"
    ) && !is_test_path(lower)
}

fn is_test_path(lower: &str) -> bool {
    lower.starts_with("tests/")
        || lower.contains("/tests/")
        || lower.ends_with("_test.py")
        || lower.ends_with("_test.rs")
        || lower.ends_with(".spec.ts")
        || lower.ends_with(".spec.tsx")
        || lower.ends_with(".test.ts")
        || lower.ends_with(".test.tsx")
        || lower.ends_with(".test.js")
        || lower.ends_with(".test.jsx")
}

fn is_public_api_path(lower: &str, file_name: &str) -> bool {
    matches!(file_name, "lib.rs" | "mod.rs" | "main.rs")
        || lower.contains("/api/")
        || lower.contains("/types/")
        || lower.contains("/contracts/")
        || lower.contains("/runtime_contracts")
        || lower.contains("/workflow")
        || lower.contains("/connector")
}

fn is_schema_or_manifest_path(lower: &str, file_name: &str, extension: &str) -> bool {
    matches!(
        file_name,
        "Cargo.toml"
            | "Cargo.lock"
            | "package.json"
            | "package-lock.json"
            | "pnpm-lock.yaml"
            | "yarn.lock"
            | "tsconfig.json"
    ) || matches!(
        extension,
        "json" | "toml" | "yaml" | "yml" | "proto" | "graphql" | "sql"
    ) || lower.contains("/schema/")
        || lower.contains("/schemas/")
        || lower.contains("schema.")
}

fn is_policy_path(lower: &str) -> bool {
    lower.contains("policy")
        || lower.contains("permission")
        || lower.contains("approval")
        || lower.contains("firewall")
        || lower.contains("security")
        || lower.contains("sandbox")
        || lower.contains("authority")
}

fn is_docs_path(lower: &str, extension: &str) -> bool {
    matches!(extension, "md" | "mdx" | "rst" | "adoc") || lower.starts_with("docs/")
}

fn is_generated_path(lower: &str, file_name: &str) -> bool {
    matches!(
        file_name,
        "Cargo.lock" | "package-lock.json" | "pnpm-lock.yaml" | "yarn.lock"
    ) || lower.contains("/generated/")
        || lower.contains("/gen/")
        || lower.contains("/dist/")
        || lower.contains("/target/")
        || lower.ends_with(".tsbuildinfo")
}

fn is_migration_path(lower: &str, file_name: &str, extension: &str) -> bool {
    matches!(
        file_name,
        "Cargo.toml" | "package.json" | "Dockerfile" | "docker-compose.yml"
    ) || lower.contains("/migrations/")
        || extension == "sql"
}

fn test_selection_hint_for_path(path: &str, extension: &str) -> String {
    let lower = path.to_ascii_lowercase();
    if extension == "rs" {
        if let Some(crate_name) = path
            .strip_prefix("crates/")
            .and_then(|rest| rest.split('/').next())
        {
            return format!("targeted Rust tests for crate path crates/{crate_name}");
        }
        return "targeted Rust tests for changed module".to_string();
    }
    if matches!(extension, "ts" | "tsx" | "js" | "jsx") {
        if lower.starts_with("apps/") || lower.starts_with("packages/") {
            return format!("targeted TypeScript tests for package path {path}");
        }
        return "targeted TypeScript/JavaScript tests for changed module".to_string();
    }
    if extension == "py" {
        return "targeted Python tests for changed module".to_string();
    }
    format!("targeted tests for changed source path {path}")
}
