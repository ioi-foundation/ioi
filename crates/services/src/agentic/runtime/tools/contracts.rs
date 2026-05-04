use ioi_types::app::agentic::LlmToolDefinition;
use ioi_types::app::{RuntimeToolContract, RUNTIME_CONTRACT_SCHEMA_VERSION_V1};

const GENERIC_OUTPUT_SCHEMA: &str = r#"{"type":"object"}"#;

pub fn runtime_tool_contract_for_definition(tool: &LlmToolDefinition) -> RuntimeToolContract {
    let profile = ToolContractProfile::for_name(&tool.name);
    RuntimeToolContract {
        stable_tool_id: format!("tool:{}@{}", tool.name, RUNTIME_CONTRACT_SCHEMA_VERSION_V1),
        namespace: namespace_for_tool_name(&tool.name),
        display_name: tool.name.clone(),
        input_schema: tool.parameters.clone(),
        output_schema: GENERIC_OUTPUT_SCHEMA.to_string(),
        risk_domain: profile.risk_domain.to_string(),
        effect_class: profile.effect_class.to_string(),
        concurrency_class: profile.concurrency_class.to_string(),
        timeout_default_ms: profile.timeout_default_ms,
        timeout_max_ms: profile.timeout_max_ms,
        cancellation_behavior: profile.cancellation_behavior.to_string(),
        primitive_capabilities: profile.primitive_capabilities.clone(),
        authority_scope_requirements: profile.authority_scope_requirements.clone(),
        policy_target: profile.policy_target.clone(),
        approval_scope_fields: profile.approval_scope_fields,
        evidence_requirements: profile.evidence_requirements,
        replayability_classification: profile.replayability_classification.to_string(),
        redaction_policy: profile.redaction_policy.to_string(),
        owner_module: owner_module_for_tool_name(&tool.name).to_string(),
        version: RUNTIME_CONTRACT_SCHEMA_VERSION_V1.to_string(),
    }
}

pub fn runtime_tool_contracts_for_tools(tools: &[LlmToolDefinition]) -> Vec<RuntimeToolContract> {
    tools
        .iter()
        .map(runtime_tool_contract_for_definition)
        .collect()
}

#[derive(Debug, Clone)]
struct ToolContractProfile {
    risk_domain: &'static str,
    effect_class: &'static str,
    concurrency_class: &'static str,
    timeout_default_ms: u64,
    timeout_max_ms: u64,
    cancellation_behavior: &'static str,
    primitive_capabilities: Vec<String>,
    authority_scope_requirements: Vec<String>,
    policy_target: String,
    approval_scope_fields: Vec<String>,
    evidence_requirements: Vec<String>,
    replayability_classification: &'static str,
    redaction_policy: &'static str,
}

impl ToolContractProfile {
    fn for_name(name: &str) -> Self {
        let mut profile = match name {
            "file__read" | "file__view" | "file__list" | "file__search" | "file__info" => {
                Self::read_only("filesystem", "fs::read", &["path"], "deterministic")
            }
            "file__write" | "file__edit" | "file__multi_edit" => Self::write(
                "filesystem",
                "fs::write",
                &["path"],
                &["path_scope", "before_hash", "after_hash", "diff_summary"],
                "deterministic_mutation",
            ),
            "file__copy" | "file__move" | "file__create_dir" | "file__zip" => Self::write(
                "filesystem",
                name,
                &["source_path", "destination_path", "path"],
                &["path_scope", "before_hash", "after_hash"],
                "deterministic_mutation",
            ),
            "file__delete" => Self::destructive(
                "filesystem",
                "fs::write",
                &["path", "recursive"],
                &["path_scope", "pre_delete_hash", "post_delete_observation"],
            ),
            "shell__run" | "shell__start" | "shell__input" | "shell__terminate"
            | "shell__reset" | "shell__cd" => Self::external_effect(
                "system",
                "sys::exec",
                &["command", "args", "stdin", "path"],
                &["policy_verdict", "stdout_stderr_exit", "working_directory"],
                "non_replayable_external_effect",
            ),
            "software_install__resolve" => Self::read_only(
                "software_install",
                "software::install_resolve",
                &["request"],
                "resolver_discovery",
            ),
            "software_install__execute_plan" => Self::external_effect(
                "software_install",
                "software::install_execute",
                &["plan_ref"],
                &[
                    "policy_verdict",
                    "command_stream",
                    "verification",
                    "final_receipt",
                ],
                "approved_host_mutation",
            ),
            "shell__status" => Self::read_only(
                "system",
                "sys::exec",
                &["command_id"],
                "session_observation",
            ),
            "browser__inspect"
            | "browser__screenshot"
            | "browser__inspect_canvas"
            | "browser__find_text"
            | "browser__list_options"
            | "browser__list_tabs" => Self::read_only(
                "browser",
                "browser::inspect",
                &["selector", "query", "id"],
                "volatile_observation",
            ),
            "browser__navigate"
            | "browser__subagent"
            | "browser__click"
            | "browser__hover"
            | "browser__move_pointer"
            | "browser__pointer_down"
            | "browser__pointer_up"
            | "browser__click_at"
            | "browser__scroll"
            | "browser__type"
            | "browser__select"
            | "browser__press_key"
            | "browser__copy"
            | "browser__paste"
            | "browser__wait"
            | "browser__upload"
            | "browser__select_option"
            | "browser__back"
            | "browser__switch_tab"
            | "browser__close_tab" => Self::mutation(
                "browser",
                "browser::interact",
                &["url", "selector", "id", "text", "paths", "tab_id"],
                &[
                    "browser_snapshot_before",
                    "browser_snapshot_after",
                    "postcondition_observation",
                ],
                "session_mutation",
            ),
            "screen__inspect" | "screen__find" | "screen" => {
                Self::read_only("gui", "gui::inspect", &["query"], "volatile_observation")
            }
            "screen__click" | "screen__click_at" | "screen__type" | "screen__scroll"
            | "window__focus" | "app__launch" => Self::mutation(
                "gui",
                gui_policy_target(name),
                &["id", "x", "y", "text", "title", "app_name"],
                &[
                    "ui_snapshot_before",
                    "ui_snapshot_after",
                    "postcondition_observation",
                ],
                "session_mutation",
            ),
            "clipboard__copy" => Self::write(
                "clipboard",
                "clipboard::write",
                &["content"],
                &["clipboard_write_receipt"],
                "host_side_effect",
            ),
            "clipboard__paste" => {
                Self::read_only("clipboard", "clipboard::read", &[], "host_observation")
            }
            "web__search" | "web__read" => Self::read_only(
                "web",
                "web::retrieve",
                &["query", "url", "retrieval_contract"],
                "volatile_external_observation",
            ),
            "http__fetch" => Self::read_only(
                "network",
                "net::fetch",
                &["url"],
                "volatile_external_observation",
            ),
            "media__extract_transcript"
            | "media__extract_evidence"
            | "media__vision_read"
            | "media__transcribe_audio" => Self::read_only(
                "media",
                media_policy_target(name),
                &["url", "path", "language"],
                "volatile_external_observation",
            ),
            "media__generate_image"
            | "media__generate_video"
            | "media__synthesize_speech"
            | "media__edit_image"
            | "gallery__sync" => Self::mutation(
                "media",
                media_policy_target(name),
                &["prompt", "path", "asset_id"],
                &["asset_receipt", "content_policy_verdict", "output_hash"],
                "generated_asset",
            ),
            "model__embeddings" | "model__rerank" => Self::read_only(
                "model",
                if name == "model__embeddings" {
                    "model::embed"
                } else {
                    "model::rerank"
                },
                &["input", "model"],
                "model_output",
            ),
            "model_registry__load"
            | "model_registry__unload"
            | "model_registry__install"
            | "model_registry__apply"
            | "model_registry__delete"
            | "backend__start"
            | "backend__stop"
            | "backend__install"
            | "backend__apply"
            | "backend__delete" => Self::external_effect(
                "model_registry",
                name,
                &["model_id", "backend_id", "path"],
                &[
                    "policy_verdict",
                    "registry_state_before",
                    "registry_state_after",
                ],
                "host_side_effect",
            ),
            "backend__health" => Self::read_only(
                "model_registry",
                "backend__health",
                &["backend_id"],
                "volatile_observation",
            ),
            "memory__search" | "memory__read" => Self::read_only(
                "memory",
                if name == "memory__search" {
                    "memory::search"
                } else {
                    "memory::inspect"
                },
                &["query", "frame_id"],
                "deterministic_snapshot",
            ),
            "memory__replace" | "memory__append" | "memory__clear" => Self::write(
                "memory",
                memory_policy_target(name),
                &["section"],
                &["memory_quality_gate", "before_hash", "after_hash"],
                "governed_memory_mutation",
            ),
            "commerce__checkout" => Self::destructive(
                "commerce",
                "ucp::checkout",
                &[
                    "merchant_url",
                    "items",
                    "total_amount",
                    "currency",
                    "buyer_email",
                ],
                &["spend_policy_verdict", "approval_grant", "checkout_receipt"],
            ),
            "monitor__create" => Self::external_effect(
                "automation",
                "monitor__create",
                &["title", "keywords", "interval_seconds", "source_prompt"],
                &[
                    "workflow_receipt",
                    "schedule_receipt",
                    "postcondition_observation",
                ],
                "durable_host_side_effect",
            ),
            "agent__delegate" => Self::mutation(
                "agent",
                "agent__delegate",
                &["goal", "budget", "template_id", "workflow_id"],
                &[
                    "delegation_receipt",
                    "handoff_contract",
                    "child_session_ref",
                ],
                "runtime_mutation",
            ),
            "agent__await" => Self::read_only(
                "agent",
                "agent__await",
                &["child_session_id_hex"],
                "runtime_observation",
            ),
            "agent__pause" | "agent__complete" | "agent__escalate" | "chat__reply" => {
                Self::mutation(
                    "agent",
                    name,
                    &["reason", "result", "message", "missing_capability"],
                    &["runtime_event", "stop_condition"],
                    "runtime_mutation",
                )
            }
            "math__eval" => Self::read_only("math", "math::eval", &["expression"], "deterministic"),
            name if name.starts_with("connector__") => Self::external_effect(
                "connector",
                name,
                &["resource", "id", "query", "payload"],
                &[
                    "connector_auth_state",
                    "policy_verdict",
                    "connector_receipt",
                ],
                "external_connector_effect",
            ),
            _ => Self::external_effect(
                "extension",
                name,
                &["arguments"],
                &["policy_verdict", "extension_receipt"],
                "extension_defined",
            ),
        };
        profile.evidence_requirements = canonical_evidence(profile.evidence_requirements);
        profile.primitive_capabilities = primitive_capabilities_for(&profile.policy_target);
        profile.authority_scope_requirements =
            authority_scopes_for(name, &profile.policy_target, profile.effect_class);
        profile
    }

    fn read_only(
        risk_domain: &'static str,
        policy_target: impl Into<String>,
        scope_fields: &[&str],
        replayability_classification: &'static str,
    ) -> Self {
        Self {
            risk_domain,
            effect_class: "read",
            concurrency_class: "parallel_read",
            timeout_default_ms: 30_000,
            timeout_max_ms: 120_000,
            cancellation_behavior: "immediate",
            primitive_capabilities: Vec::new(),
            authority_scope_requirements: Vec::new(),
            policy_target: policy_target.into(),
            approval_scope_fields: strings(scope_fields),
            evidence_requirements: strings(&[
                "tool_call_receipt",
                "policy_verdict",
                "observation_receipt",
            ]),
            replayability_classification,
            redaction_policy: "apply_surface_redaction",
        }
    }

    fn write(
        risk_domain: &'static str,
        policy_target: impl Into<String>,
        scope_fields: &[&str],
        evidence: &[&str],
        replayability_classification: &'static str,
    ) -> Self {
        Self {
            risk_domain,
            effect_class: "write",
            concurrency_class: "serial_effect",
            timeout_default_ms: 30_000,
            timeout_max_ms: 120_000,
            cancellation_behavior: "cooperative",
            primitive_capabilities: Vec::new(),
            authority_scope_requirements: Vec::new(),
            policy_target: policy_target.into(),
            approval_scope_fields: strings(scope_fields),
            evidence_requirements: strings(evidence),
            replayability_classification,
            redaction_policy: "redact_sensitive_inputs_and_outputs",
        }
    }

    fn mutation(
        risk_domain: &'static str,
        policy_target: impl Into<String>,
        scope_fields: &[&str],
        evidence: &[&str],
        replayability_classification: &'static str,
    ) -> Self {
        Self {
            risk_domain,
            effect_class: "mutation",
            concurrency_class: "serial_session",
            timeout_default_ms: 30_000,
            timeout_max_ms: 180_000,
            cancellation_behavior: "cooperative",
            primitive_capabilities: Vec::new(),
            authority_scope_requirements: Vec::new(),
            policy_target: policy_target.into(),
            approval_scope_fields: strings(scope_fields),
            evidence_requirements: strings(evidence),
            replayability_classification,
            redaction_policy: "redact_sensitive_inputs_and_outputs",
        }
    }

    fn external_effect(
        risk_domain: &'static str,
        policy_target: impl Into<String>,
        scope_fields: &[&str],
        evidence: &[&str],
        replayability_classification: &'static str,
    ) -> Self {
        Self {
            risk_domain,
            effect_class: "external_effect",
            concurrency_class: "exclusive_effect",
            timeout_default_ms: 120_000,
            timeout_max_ms: 600_000,
            cancellation_behavior: "cooperative_with_retained_handle",
            primitive_capabilities: Vec::new(),
            authority_scope_requirements: Vec::new(),
            policy_target: policy_target.into(),
            approval_scope_fields: strings(scope_fields),
            evidence_requirements: strings(evidence),
            replayability_classification,
            redaction_policy: "redact_sensitive_inputs_and_outputs",
        }
    }

    fn destructive(
        risk_domain: &'static str,
        policy_target: impl Into<String>,
        scope_fields: &[&str],
        evidence: &[&str],
    ) -> Self {
        Self {
            risk_domain,
            effect_class: "destructive",
            concurrency_class: "exclusive_effect",
            timeout_default_ms: 30_000,
            timeout_max_ms: 120_000,
            cancellation_behavior: "cooperative_until_commit",
            primitive_capabilities: Vec::new(),
            authority_scope_requirements: Vec::new(),
            policy_target: policy_target.into(),
            approval_scope_fields: strings(scope_fields),
            evidence_requirements: strings(evidence),
            replayability_classification: "requires_fresh_approval_non_replayable",
            redaction_policy: "redact_sensitive_inputs_and_outputs",
        }
    }
}

fn canonical_evidence(mut evidence: Vec<String>) -> Vec<String> {
    for required in [
        "tool_call_receipt",
        "runtime_event",
        "policy_verdict",
        "trace_ref",
    ] {
        if !evidence.iter().any(|item| item == required) {
            evidence.push(required.to_string());
        }
    }
    evidence.sort();
    evidence.dedup();
    evidence
}

fn primitive_capabilities_for(policy_target: &str) -> Vec<String> {
    let mut capabilities = Vec::new();
    let primitive = match policy_target {
        "fs::read" => Some("prim:fs.read"),
        "fs::write" => Some("prim:fs.write"),
        _ if policy_target.starts_with("file__") => Some("prim:fs.write"),
        "sys::exec" | "software::install_execute" => Some("prim:sys.exec"),
        "browser::inspect" | "web::retrieve" | "net::fetch" => Some("prim:net.request"),
        "browser::interact" => Some("prim:browser.interact"),
        "gui::inspect" => Some("prim:ui.inspect"),
        "gui::click" | "gui::type" | "gui::scroll" | "os::focus" | "os::launch_app" => {
            Some("prim:ui.interact")
        }
        "clipboard::read" => Some("prim:clipboard.read"),
        "clipboard::write" => Some("prim:clipboard.write"),
        "model::embed" | "model::rerank" => Some("prim:model.invoke"),
        "memory::search" | "memory::inspect" => Some("prim:memory.read"),
        _ if policy_target.starts_with("memory::") => Some("prim:memory.write"),
        "monitor__create" => Some("prim:automation.schedule"),
        "ucp::checkout" | "ucp::discovery" => Some("prim:commerce.request"),
        _ if policy_target.starts_with("media::")
            || policy_target.starts_with("media__")
            || policy_target.starts_with("gallery__") =>
        {
            Some("prim:media.process")
        }
        _ if policy_target.starts_with("agent__") || policy_target.starts_with("chat__") => {
            Some("prim:runtime.control")
        }
        _ if policy_target.starts_with("connector__") => Some("prim:connector.invoke"),
        _ if policy_target.starts_with("model_registry__")
            || policy_target.starts_with("backend__") =>
        {
            Some("prim:model.registry")
        }
        _ => None,
    };
    if let Some(primitive) = primitive {
        capabilities.push(primitive.to_string());
    }
    capabilities.sort();
    capabilities.dedup();
    capabilities
}

fn authority_scopes_for(tool_name: &str, policy_target: &str, effect_class: &str) -> Vec<String> {
    let mut scopes = Vec::new();
    if effect_class != "read" {
        scopes.push(format!("scope:{}", policy_target));
    }
    if tool_name.starts_with("connector__") {
        scopes.push("scope:connector.session".to_string());
    }
    if matches!(
        tool_name,
        "shell__run"
            | "shell__start"
            | "shell__input"
            | "shell__terminate"
            | "software_install__execute_plan"
            | "app__launch"
    ) {
        scopes.push("scope:host.controlled_execution".to_string());
    }
    scopes.sort();
    scopes.dedup();
    scopes
}

fn namespace_for_tool_name(name: &str) -> String {
    name.split_once("__")
        .map(|(namespace, _)| namespace)
        .or_else(|| name.split_once("::").map(|(namespace, _)| namespace))
        .unwrap_or("extension")
        .to_string()
}

fn owner_module_for_tool_name(name: &str) -> &'static str {
    match namespace_for_tool_name(name).as_str() {
        "file" => "runtime.execution.filesystem",
        "shell" | "package" => "runtime.execution.system",
        "browser" => "runtime.execution.browser",
        "screen" | "window" | "app" | "clipboard" => "runtime.execution.screen",
        "web" | "http" => "runtime.execution.web",
        "media" | "gallery" => "runtime.execution.media",
        "model" | "model_registry" | "backend" => "runtime.model_registry",
        "memory" => "runtime.service.memory",
        "commerce" => "runtime.execution.commerce",
        "monitor" => "runtime.connectors.automation",
        "agent" | "chat" => "runtime.service.lifecycle",
        "connector" => "runtime.connectors",
        "math" => "runtime.execution.math",
        _ => "runtime.tools.extension",
    }
}

fn gui_policy_target(name: &str) -> &'static str {
    match name {
        "screen__type" => "gui::type",
        "screen__scroll" => "gui::scroll",
        "window__focus" => "os::focus",
        "app__launch" => "os::launch_app",
        _ => "gui::click",
    }
}

fn media_policy_target(name: &str) -> String {
    match name {
        "media__extract_transcript" => "media::extract_transcript".to_string(),
        "media__extract_evidence" | "media__vision_read" | "media__transcribe_audio" => {
            "media::extract_multimodal_evidence".to_string()
        }
        _ => name.to_string(),
    }
}

fn memory_policy_target(name: &str) -> String {
    match name {
        "memory__replace" => "memory::replace_core".to_string(),
        "memory__append" => "memory::append_core".to_string(),
        "memory__clear" => "memory::clear_core".to_string(),
        _ => name.to_string(),
    }
}

fn strings(values: &[&str]) -> Vec<String> {
    values
        .iter()
        .filter(|value| !value.trim().is_empty())
        .map(|value| (*value).to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tool(name: &str) -> LlmToolDefinition {
        LlmToolDefinition {
            name: name.to_string(),
            description: format!("{} test tool", name),
            parameters: r#"{"type":"object"}"#.to_string(),
        }
    }

    #[test]
    fn filesystem_write_contract_splits_runtime_primitive_from_authority_scope() {
        let contract = runtime_tool_contract_for_definition(&tool("file__edit"));
        assert_eq!(contract.policy_target, "fs::write");
        assert!(contract.is_effectful());
        assert_eq!(contract.primitive_capabilities, vec!["prim:fs.write"]);
        assert_eq!(
            contract.authority_scope_requirements,
            vec!["scope:fs::write"]
        );
        assert!(contract
            .evidence_requirements
            .iter()
            .any(|item| item == "diff_summary"));
        assert!(contract
            .approval_scope_fields
            .iter()
            .any(|item| item == "path"));
    }

    #[test]
    fn read_contract_is_parallel_and_not_effectful() {
        let contract = runtime_tool_contract_for_definition(&tool("web__read"));
        assert_eq!(contract.policy_target, "web::retrieve");
        assert_eq!(contract.effect_class, "read");
        assert_eq!(contract.concurrency_class, "parallel_read");
        assert!(!contract.is_effectful());
        assert_eq!(contract.primitive_capabilities, vec!["prim:net.request"]);
        assert!(contract.authority_scope_requirements.is_empty());
    }

    #[test]
    fn destructive_contract_requires_fresh_authority() {
        let contract = runtime_tool_contract_for_definition(&tool("file__delete"));
        assert_eq!(contract.effect_class, "destructive");
        assert_eq!(
            contract.replayability_classification,
            "requires_fresh_approval_non_replayable"
        );
        assert!(contract
            .evidence_requirements
            .iter()
            .any(|item| item == "pre_delete_hash"));
    }

    #[test]
    fn connector_contracts_use_common_external_effect_shape() {
        let contract = runtime_tool_contract_for_definition(&tool("connector__google__gmail_send"));
        assert_eq!(contract.namespace, "connector");
        assert_eq!(contract.policy_target, "connector__google__gmail_send");
        assert!(contract.is_effectful());
        assert_eq!(
            contract.primitive_capabilities,
            vec!["prim:connector.invoke"]
        );
        assert!(contract
            .authority_scope_requirements
            .iter()
            .any(|item| item == "scope:connector.session"));
    }
}
