use ioi_crypto::algorithms::hash::sha256;
use ioi_types::app::agentic::{AgentTool, LlmToolDefinition};
use ioi_types::app::{RuntimeToolContract, RUNTIME_CONTRACT_SCHEMA_VERSION_V1};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

const GENERIC_OUTPUT_SCHEMA: &str = r#"{"type":"object"}"#;
pub const CANONICAL_RUNTIME_TOOL_CONTRACT_SCHEMA_VERSION: &str =
    "ioi.components.connectors-tools.runtime-tool-contract.v1";

/// The immutable, content-addressed contract used by invocation admission.
///
/// `RuntimeToolContract` in `ioi_types::app::runtime_contracts` remains the
/// legacy discovery/catalog projection while callers migrate. This record is
/// deliberately shaped like the registered architecture contract and is the
/// execution truth consumed immediately before the final invoker.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdmittedRuntimeToolContract {
    pub schema_version: String,
    pub tool_id: String,
    pub revision_ref: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub predecessor_revision_ref: Option<String>,
    pub content_hash: String,
    pub namespace: String,
    pub display_name: String,
    pub version: String,
    pub input_schema: Value,
    pub output_schema: Value,
    pub risk_class: String,
    pub effect_class: String,
    pub concurrency_class: String,
    pub timeout: RuntimeToolTimeout,
    pub primitive_capabilities_required: Vec<String>,
    pub authority_scopes_required: Vec<String>,
    pub approval_required: bool,
    pub evidence_required: Vec<String>,
    pub redaction_policy: String,
    pub owner: String,
    pub data_class_allowlist: Vec<String>,
    pub egress_policy: RuntimeToolEgressPolicy,
    pub registry_lifecycle_ref: Option<String>,
    pub registry_status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeToolTimeout {
    pub default_ms: u64,
    pub max_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeToolEgressPolicy {
    pub default: String,
    pub allowed_destination_patterns: Vec<String>,
}

/// Runtime-only metadata that binds the immutable contract to the daemon's
/// policy target. Adapter dispatch does not get to redefine either value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedRuntimeToolContract {
    pub contract: AdmittedRuntimeToolContract,
    pub policy_target: String,
    pub action_target: String,
}

fn parse_schema(raw: &str) -> Value {
    serde_json::from_str(raw).unwrap_or_else(|_| json!({"type": "object"}))
}

fn tool_slug(name: &str) -> String {
    name.trim()
        .to_ascii_lowercase()
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '~' | '-' | '/') {
                ch
            } else {
                '-'
            }
        })
        .collect()
}

pub fn runtime_tool_id_for_name(name: &str) -> String {
    format!("tool://ioi/runtime/{}", tool_slug(name))
}

fn sha256_prefixed(bytes: &[u8]) -> Result<String, String> {
    sha256(bytes)
        .map(|digest| format!("sha256:{}", hex::encode(digest.as_ref())))
        .map_err(|error| format!("RuntimeToolContract hash failed: {error}"))
}

/// Return the exact immutable JCS bytes committed to by `content_hash`.
///
/// The self-referential hash and mutable registry lifecycle projection are
/// excluded by the registered architecture contract.
pub fn runtime_tool_contract_canonical_hash_material(
    contract: &AdmittedRuntimeToolContract,
) -> Result<Vec<u8>, String> {
    let mut value = serde_json::to_value(contract)
        .map_err(|error| format!("RuntimeToolContract serialization failed: {error}"))?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| "RuntimeToolContract did not serialize as an object".to_string())?;
    object.remove("content_hash");
    object.remove("registry_lifecycle_ref");
    object.remove("registry_status");
    serde_jcs::to_vec(&value)
        .map_err(|error| format!("RuntimeToolContract canonicalization failed: {error}"))
}

fn revision_seed(name: &str, input_schema: &Value, owner: &str) -> Result<String, String> {
    let bytes = serde_jcs::to_vec(&json!({
        "name": name,
        "input_schema": input_schema,
        "owner": owner,
        "generator": "ioi.runtime-tool-contract-admission.v1",
    }))
    .map_err(|error| format!("RuntimeToolContract revision seed failed: {error}"))?;
    let hash = sha256_prefixed(&bytes)?;
    Ok(hash.trim_start_matches("sha256:")[..16].to_string())
}

fn egress_policy_for(profile: &ToolContractProfile) -> RuntimeToolEgressPolicy {
    let destinations = match profile.policy_target.as_str() {
        "web::retrieve" | "net::fetch" => vec![
            "http://*".to_string(),
            "https://*".to_string(),
            "provider://web-retrieval/bound".to_string(),
        ],
        "browser::inspect" | "browser::interact" => vec![
            "browser-session://bound".to_string(),
            "file://*".to_string(),
            "http://*".to_string(),
            "https://*".to_string(),
        ],
        target if target.starts_with("model::") => {
            vec!["provider://model-runtime/bound".to_string()]
        }
        target
            if target.starts_with("media::")
                || target.starts_with("media__")
                || target.starts_with("gallery__") =>
        {
            vec![
                "provider://media-runtime/bound".to_string(),
                "http://*".to_string(),
                "https://*".to_string(),
            ]
        }
        "ucp::checkout" | "ucp::discovery" => {
            vec!["http://*".to_string(), "https://*".to_string()]
        }
        target if is_connector_tool_name(target) => {
            vec![format!("connector://{}/*", tool_slug(target))]
        }
        _ => vec!["local://daemon".to_string()],
    };
    RuntimeToolEgressPolicy {
        default: if profile
            .primitive_capabilities
            .iter()
            .any(|capability| capability == "prim:net.request")
            || is_connector_tool_name(&profile.policy_target)
            || profile.policy_target.starts_with("model::")
            || profile.policy_target.starts_with("media::")
            || profile.policy_target.starts_with("media__")
            || profile.policy_target.starts_with("gallery__")
            || profile.policy_target.starts_with("ucp::")
        {
            "allow_declared".to_string()
        } else {
            "deny".to_string()
        },
        allowed_destination_patterns: destinations,
    }
}

fn admitted_contract(
    name: &str,
    input_schema: Value,
    output_schema: Value,
    owner: String,
    action_target: String,
) -> Result<ResolvedRuntimeToolContract, String> {
    let mut profile = ToolContractProfile::for_name(name);
    if profile.primitive_capabilities.is_empty() && owner.contains("adapter://") {
        profile
            .primitive_capabilities
            .push("prim:connector.invoke".to_string());
    }
    let slug = tool_slug(name);
    if slug.is_empty() {
        return Err("RuntimeToolContract tool name is empty".to_string());
    }
    let revision = revision_seed(name, &input_schema, &owner)?;
    let tool_id = runtime_tool_id_for_name(&slug);
    let mut contract = AdmittedRuntimeToolContract {
        schema_version: CANONICAL_RUNTIME_TOOL_CONTRACT_SCHEMA_VERSION.to_string(),
        tool_id: tool_id.clone(),
        revision_ref: format!("{tool_id}/revision/{revision}"),
        predecessor_revision_ref: None,
        content_hash: String::new(),
        namespace: namespace_for_tool_name(name),
        display_name: name.to_string(),
        version: format!("1-{revision}"),
        input_schema,
        output_schema,
        risk_class: profile.risk_domain.to_string(),
        effect_class: profile.effect_class.to_string(),
        concurrency_class: match profile.concurrency_class {
            "parallel_read" => "safe_parallel",
            "serial_session" => "resource_scoped",
            "exclusive_effect" => "exclusive",
            _ => "serialized",
        }
        .to_string(),
        timeout: RuntimeToolTimeout {
            default_ms: profile.timeout_default_ms,
            max_ms: profile.timeout_max_ms,
        },
        primitive_capabilities_required: profile.primitive_capabilities.clone(),
        authority_scopes_required: profile
            .authority_scope_requirements
            .iter()
            .map(|scope| scope.replace("::", "."))
            .collect(),
        approval_required: tool_approval_required(
            profile.effect_class,
            &profile.authority_scope_requirements,
        ),
        evidence_required: profile.evidence_requirements.clone(),
        redaction_policy: if profile.redaction_policy.contains("hash") {
            "hash_only"
        } else if profile.redaction_policy.contains("private") {
            "full_private"
        } else {
            "redact_body"
        }
        .to_string(),
        owner,
        data_class_allowlist: vec![
            "public".to_string(),
            "internal".to_string(),
            "confidential".to_string(),
            "private".to_string(),
        ],
        egress_policy: egress_policy_for(&profile),
        registry_lifecycle_ref: Some(format!("agentgres://object/{tool_id}")),
        registry_status: "released".to_string(),
    };
    contract.content_hash =
        sha256_prefixed(&runtime_tool_contract_canonical_hash_material(&contract)?)?;
    validate_admitted_runtime_tool_contract(&contract)?;
    Ok(ResolvedRuntimeToolContract {
        contract,
        policy_target: profile.policy_target,
        action_target,
    })
}

pub fn admitted_runtime_tool_contract_for_native(
    tool: &AgentTool,
) -> Result<ResolvedRuntimeToolContract, String> {
    let name = tool.name_string();
    if !AgentTool::is_reserved_tool_name(&name) {
        return Err(format!(
            "no released native RuntimeToolContract owns tool '{name}'"
        ));
    }
    admitted_contract(
        &name,
        json!({"type": "object"}),
        json!({"type": "object"}),
        format!("module://{}", owner_module_for_tool_name(&name)),
        format!("{:?}", tool.target()),
    )
}

pub fn admitted_runtime_tool_contract_for_native_name(
    name: &str,
) -> Result<AdmittedRuntimeToolContract, String> {
    if !AgentTool::is_reserved_tool_name(name) {
        return Err(format!(
            "no released native RuntimeToolContract owns tool '{name}'"
        ));
    }
    admitted_contract(
        name,
        json!({"type": "object"}),
        json!({"type": "object"}),
        format!("module://{}", owner_module_for_tool_name(name)),
        "native-agent-tool".to_string(),
    )
    .map(|resolved| resolved.contract)
}

pub fn observed_runtime_tool_boundary(name: &str) -> Result<ResolvedRuntimeToolContract, String> {
    if name.trim().is_empty() {
        return Err("runtime tool name is empty".to_string());
    }
    let contract = admitted_contract(
        name,
        json!({"type": "object"}),
        json!({"type": "object"}),
        "runtime-boundary-observer://hypervisor-daemon".to_string(),
        "observed-final-invoker".to_string(),
    )?
    .contract;
    let profile = ToolContractProfile::for_name(name);
    Ok(ResolvedRuntimeToolContract {
        contract,
        policy_target: profile.policy_target,
        action_target: "native-agent-tool".to_string(),
    })
}

pub fn admitted_runtime_tool_contract_for_definition(
    tool: &LlmToolDefinition,
    owner: impl Into<String>,
    action_target: impl Into<String>,
) -> Result<ResolvedRuntimeToolContract, String> {
    admitted_contract(
        &tool.name,
        parse_schema(&tool.parameters),
        parse_schema(GENERIC_OUTPUT_SCHEMA),
        owner.into(),
        action_target.into(),
    )
}

pub fn validate_admitted_runtime_tool_contract(
    contract: &AdmittedRuntimeToolContract,
) -> Result<(), String> {
    if contract.schema_version != CANONICAL_RUNTIME_TOOL_CONTRACT_SCHEMA_VERSION {
        return Err("RuntimeToolContract schema version mismatch".to_string());
    }
    let value = serde_json::to_value(contract)
        .map_err(|error| format!("RuntimeToolContract projection failed: {error}"))?;
    let typed: ioi_types::app::generated::architecture_contracts::RuntimeToolContractV1 =
        serde_json::from_value(value.clone())
            .map_err(|error| format!("RuntimeToolContract registered schema rejected: {error}"))?;
    let projected = serde_json::to_value(typed)
        .map_err(|error| format!("RuntimeToolContract projection failed: {error}"))?;
    if projected != value {
        return Err("RuntimeToolContract generated projection changed supplied bytes".to_string());
    }
    if contract.registry_status != "released" {
        return Err("RuntimeToolContract revision is not released".to_string());
    }
    if !contract
        .revision_ref
        .starts_with(&format!("{}/revision/", contract.tool_id))
    {
        return Err("RuntimeToolContract revision_ref is not owned by tool_id".to_string());
    }
    if contract.timeout.default_ms == 0
        || contract.timeout.max_ms == 0
        || contract.timeout.default_ms > contract.timeout.max_ms
    {
        return Err("RuntimeToolContract timeout bounds are invalid".to_string());
    }
    if contract
        .primitive_capabilities_required
        .iter()
        .any(|value| !value.starts_with("prim:"))
    {
        return Err("RuntimeToolContract contains a non-prim capability".to_string());
    }
    if contract
        .authority_scopes_required
        .iter()
        .any(|value| !value.starts_with("scope:"))
    {
        return Err("RuntimeToolContract contains a non-scope authority requirement".to_string());
    }
    if contract.data_class_allowlist.is_empty()
        || contract
            .egress_policy
            .allowed_destination_patterns
            .is_empty()
    {
        return Err("RuntimeToolContract information-flow declarations are incomplete".to_string());
    }
    let expected_hash = sha256_prefixed(&runtime_tool_contract_canonical_hash_material(contract)?)?;
    if contract.content_hash != expected_hash {
        return Err("RuntimeToolContract content_hash mismatch".to_string());
    }
    Ok(())
}

pub fn runtime_tool_contract_for_definition(tool: &LlmToolDefinition) -> RuntimeToolContract {
    let profile = ToolContractProfile::for_name(&tool.name);
    let approval_required =
        tool_approval_required(profile.effect_class, &profile.authority_scope_requirements);
    let credential_readiness = tool_credential_readiness(&tool.name, &profile);
    let rate_limit_profile = tool_rate_limit_profile(profile.effect_class);
    let idempotency_behavior = tool_idempotency_behavior(profile.effect_class);
    let receipt_behavior = tool_receipt_behavior(&profile.evidence_requirements);
    let workflow_availability = tool_workflow_availability(&tool.name);
    let marketplace_exposure_eligible = tool_marketplace_exposure_eligible(
        approval_required,
        &credential_readiness,
        profile.effect_class,
    );
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
        credential_readiness,
        approval_required,
        rate_limit_profile,
        idempotency_behavior,
        receipt_behavior,
        workflow_availability,
        agent_availability: "available".to_string(),
        marketplace_exposure_eligible,
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

fn tool_approval_required(effect_class: &str, authority_scope_requirements: &[String]) -> bool {
    !matches!(effect_class, "read") || !authority_scope_requirements.is_empty()
}

fn tool_credential_readiness(tool_name: &str, profile: &ToolContractProfile) -> String {
    let haystack = format!(
        "{} {} {} {}",
        tool_name, profile.risk_domain, profile.effect_class, profile.policy_target
    )
    .to_ascii_lowercase();
    if haystack.contains("connector")
        || haystack.contains("oauth")
        || haystack.contains("model_registry")
    {
        "unknown".to_string()
    } else {
        "not_required".to_string()
    }
}

fn tool_rate_limit_profile(effect_class: &str) -> String {
    if matches!(effect_class, "read") {
        "unlimited_local_read".to_string()
    } else {
        "runtime_governed".to_string()
    }
}

fn tool_idempotency_behavior(effect_class: &str) -> String {
    match effect_class {
        "read" => "read_only".to_string(),
        "external_effect" | "destructive" => "caller_or_runtime_key".to_string(),
        _ => "runtime_key".to_string(),
    }
}

fn tool_receipt_behavior(evidence_requirements: &[String]) -> String {
    if evidence_requirements.is_empty() {
        "receipt_optional".to_string()
    } else {
        "receipt_required".to_string()
    }
}

fn tool_workflow_availability(tool_name: &str) -> String {
    if tool_name.starts_with("connector__") {
        "ConnectorNode".to_string()
    } else if tool_name.starts_with("browser__") || tool_name.starts_with("screen__") {
        "ComputerUseNode".to_string()
    } else if tool_name.starts_with("model__") || tool_name.starts_with("model_registry__") {
        "ModelCapabilityNode".to_string()
    } else {
        "ToolCapabilityNode".to_string()
    }
}

fn tool_marketplace_exposure_eligible(
    approval_required: bool,
    credential_readiness: &str,
    effect_class: &str,
) -> bool {
    !approval_required && credential_readiness != "missing" && matches!(effect_class, "read")
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
            "workspace_change__status" => Self::read_only(
                "filesystem",
                "workspace_change::status",
                &["change_id"],
                "session_checkpoint",
            ),
            "workspace_change__accept" => Self::write(
                "filesystem",
                "workspace_change::accept",
                &["change_id"],
                &["path_scope", "before_hash", "after_hash", "diff_summary"],
                "deterministic_mutation",
            ),
            "workspace_change__reject" => Self::write(
                "filesystem",
                "workspace_change::reject",
                &["change_id", "reason"],
                &["policy_verdict", "change_lifecycle", "trace_ref"],
                "session_lifecycle_transition",
            ),
            "workspace_change__rollback" => Self::write(
                "filesystem",
                "workspace_change::rollback",
                &["change_id"],
                &["path_scope", "before_hash", "after_hash", "diff_summary"],
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
            | "browser__find_text"
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
            "screen__inspect" | "screen__find" => {
                Self::read_only("gui", "gui::inspect", &["query"], "volatile_observation")
            }
            "screen" | "screen__click" | "screen__click_at" | "screen__type" | "screen__scroll"
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
            "model__responses" => Self::external_effect(
                "model",
                "model::respond",
                &["input", "model"],
                &["model_invocation_receipt", "provider_response"],
                "model_output",
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
            name if is_connector_tool_name(name) => Self::external_effect(
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
    if policy_target == "gui::sequence" {
        return vec![
            "prim:ui.inspect".to_string(),
            "prim:ui.interact".to_string(),
        ];
    }
    let mut capabilities = Vec::new();
    let primitive = match policy_target {
        "fs::read" => Some("prim:fs.read"),
        "fs::write" => Some("prim:fs.write"),
        _ if policy_target.starts_with("file__") => Some("prim:fs.write"),
        // Accepting a change writes the accepted content to the target path, the
        // same filesystem primitive as rollback restoring the prior content.
        "workspace_change::accept" => Some("prim:fs.write"),
        "workspace_change::rollback" => Some("prim:fs.write"),
        "workspace_change::reject" | "workspace_change__reject" => Some("prim:runtime.control"),
        "workspace_change::status" | "workspace_change__status" => Some("prim:fs.read"),
        "sys::exec" | "software::install_execute" => Some("prim:sys.exec"),
        "software::install_resolve" => Some("prim:software.resolve"),
        "browser::inspect" | "web::retrieve" | "net::fetch" => Some("prim:net.request"),
        "browser::interact" => Some("prim:browser.interact"),
        "gui::inspect" => Some("prim:ui.inspect"),
        "gui::click" | "gui::type" | "gui::scroll" | "gui::mouse_move" | "os::focus"
        | "os::launch_app" => Some("prim:ui.interact"),
        "gui::screenshot" | "screen::cursor" => Some("prim:ui.inspect"),
        "clipboard::read" => Some("prim:clipboard.read"),
        "clipboard::write" => Some("prim:clipboard.write"),
        "model::respond" | "model::embed" | "model::rerank" => Some("prim:model.invoke"),
        "memory::search" | "memory::inspect" => Some("prim:memory.read"),
        _ if policy_target.starts_with("memory::") => Some("prim:memory.write"),
        "monitor__create" => Some("prim:automation.schedule"),
        "ucp::checkout" | "ucp::discovery" => Some("prim:commerce.request"),
        "math::eval" => Some("prim:compute.eval"),
        _ if policy_target.starts_with("media::")
            || policy_target.starts_with("media__")
            || policy_target.starts_with("gallery__") =>
        {
            Some("prim:media.process")
        }
        _ if policy_target.starts_with("agent__") || policy_target.starts_with("chat__") => {
            Some("prim:runtime.control")
        }
        _ if is_connector_tool_name(policy_target) => Some("prim:connector.invoke"),
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

/// Resolve the physical primitive set named by the daemon's actual
/// `ActionTarget`, independently of the admitted tool-name profile.
pub fn observed_primitive_capabilities_for_action_target(action_target: &str) -> Vec<String> {
    primitive_capabilities_for(action_target)
}

fn authority_scopes_for(tool_name: &str, policy_target: &str, effect_class: &str) -> Vec<String> {
    let mut scopes = Vec::new();
    if effect_class != "read" {
        scopes.push(format!("scope:{}", policy_target));
    }
    if is_connector_tool_name(tool_name) {
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

fn is_connector_tool_name(name: &str) -> bool {
    name.starts_with("connector__")
        || name.starts_with("wallet_network__mail_")
        || name.starts_with("wallet_mail_")
        || name.starts_with("mail__")
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
        "screen" => "gui::sequence",
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
        "media__extract_evidence" => "media::extract_multimodal_evidence".to_string(),
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
        assert_eq!(contract.approval_required, true);
        assert_eq!(contract.credential_readiness, "not_required");
        assert_eq!(contract.idempotency_behavior, "runtime_key");
        assert_eq!(contract.receipt_behavior, "receipt_required");
        assert_eq!(contract.workflow_availability, "ToolCapabilityNode");
    }

    #[test]
    fn workspace_change_rollback_contract_is_filesystem_mutation_by_handle() {
        let contract = runtime_tool_contract_for_definition(&tool("workspace_change__rollback"));
        assert_eq!(contract.policy_target, "workspace_change::rollback");
        assert!(contract.is_effectful());
        assert_eq!(contract.primitive_capabilities, vec!["prim:fs.write"]);
        assert!(contract
            .approval_scope_fields
            .iter()
            .any(|item| item == "change_id"));
        assert!(contract
            .evidence_requirements
            .iter()
            .any(|item| item == "diff_summary"));
    }

    #[test]
    fn workspace_change_accept_contract_is_filesystem_mutation_by_handle() {
        let contract = runtime_tool_contract_for_definition(&tool("workspace_change__accept"));
        assert_eq!(contract.policy_target, "workspace_change::accept");
        assert!(contract.is_effectful());
        assert_eq!(contract.primitive_capabilities, vec!["prim:fs.write"]);
        assert!(contract
            .approval_scope_fields
            .iter()
            .any(|item| item == "change_id"));
        assert!(contract
            .evidence_requirements
            .iter()
            .any(|item| item == "diff_summary"));
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
        assert_eq!(contract.approval_required, false);
        assert_eq!(contract.rate_limit_profile, "unlimited_local_read");
        assert_eq!(contract.idempotency_behavior, "read_only");
        assert_eq!(contract.marketplace_exposure_eligible, true);
    }

    #[test]
    fn destructive_contract_requires_fresh_authority() {
        let contract = runtime_tool_contract_for_definition(&tool("file__delete"));
        assert_eq!(contract.effect_class, "destructive");
        assert_eq!(
            contract.replayability_classification,
            "requires_fresh_approval_non_replayable"
        );
        assert_eq!(contract.approval_required, true);
        assert_eq!(contract.idempotency_behavior, "caller_or_runtime_key");
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
        assert_eq!(contract.credential_readiness, "unknown");
        assert_eq!(contract.workflow_availability, "ConnectorNode");
        assert_eq!(contract.marketplace_exposure_eligible, false);
    }

    #[test]
    fn polymorphic_screen_contract_uses_its_maximum_effect_boundary() {
        let contract = admitted_runtime_tool_contract_for_native_name("screen").unwrap();
        assert_eq!(contract.effect_class, "mutation");
        assert_eq!(
            contract.primitive_capabilities_required,
            vec!["prim:ui.inspect", "prim:ui.interact"]
        );
        assert!(contract
            .authority_scopes_required
            .contains(&"scope:gui.sequence".to_string()));
    }
}
