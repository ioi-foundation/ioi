use crate::kernel::{connectors, data, lsp, skill_sources};
use crate::models::{
    AppState, CapabilityAuthorityDescriptor, CapabilityGovernanceProposal,
    CapabilityGovernanceRequest, CapabilityGovernanceRequestAction,
    CapabilityGovernanceTargetOption, CapabilityLeaseDescriptor, CapabilityRegistryEntry,
    CapabilityRegistrySnapshot, CapabilityRegistrySummary, ExtensionContributionRecord,
    ExtensionManifestRecord, LocalEngineBackendRecord, LocalEngineCapabilityFamily,
    LocalEngineModelRecord, LocalEngineRuntimeProfile, SkillCatalogEntry, SkillSourceRecord,
};
use chrono::Utc;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;
use tauri::{AppHandle, Emitter, State};

const CAPABILITY_GOVERNANCE_REQUEST_UPDATED_EVENT: &str = "capability-governance-request-updated";

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityGovernanceRequestPlanInput {
    #[serde(default)]
    pub request_id: Option<String>,
    pub capability_entry_id: String,
    pub action: CapabilityGovernanceRequestAction,
    #[serde(default)]
    pub governing_entry_id: Option<String>,
    #[serde(default)]
    pub connector_id: Option<String>,
    #[serde(default)]
    pub connector_label: Option<String>,
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityGovernanceProposalInput {
    pub capability_entry_id: String,
    pub action: CapabilityGovernanceRequestAction,
    #[serde(default)]
    pub comparison_entry_id: Option<String>,
}

fn humanize(value: &str) -> String {
    let normalized = value
        .trim()
        .replace("::", " ")
        .replace(['_', '-'], " ")
        .split_whitespace()
        .map(|segment| {
            let mut chars = segment.chars();
            match chars.next() {
                Some(first) => {
                    first.to_uppercase().collect::<String>() + &chars.as_str().to_ascii_lowercase()
                }
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ");
    if normalized.is_empty() {
        "Unknown".to_string()
    } else {
        normalized
    }
}

fn availability_for_status(status: &str, enabled: bool) -> String {
    if !enabled {
        return "disabled".to_string();
    }

    match status.trim().to_ascii_lowercase().as_str() {
        "connected" | "ready" | "active" | "healthy" | "running" | "installed" | "synced" => {
            "ready".to_string()
        }
        "degraded" | "warning" | "partial" => "degraded".to_string(),
        "failed" | "blocked" | "error" => "blocked".to_string(),
        "needs_auth" | "configured" | "idle" | "pending" | "queued" => "attention".to_string(),
        other if other.is_empty() => "unknown".to_string(),
        other => other.to_string(),
    }
}

fn availability_label(value: &str) -> String {
    match value {
        "ready" => "Ready".to_string(),
        "attention" => "Needs attention".to_string(),
        "degraded" => "Degraded".to_string(),
        "blocked" => "Blocked".to_string(),
        "disabled" => "Disabled".to_string(),
        "unknown" => "Unknown".to_string(),
        other => humanize(other),
    }
}

fn governed_profile_label(value: &str) -> String {
    match value {
        "workspace_template" => "Workspace planning template".to_string(),
        "observe_only_connector" => "Read-biased connector".to_string(),
        "governed_connector" => "Governed connector".to_string(),
        "automation_connector" => "Automation-capable connector".to_string(),
        "expert_connector" => "Expert-capable connector".to_string(),
        "blocked_connector" => "Blocked connector".to_string(),
        "governed_marketplace" => "Governed marketplace package".to_string(),
        "automation_bridge" => "Automation bridge".to_string(),
        "runtime_bridge" => "Runtime bridge".to_string(),
        "local_skill_bundle" => "Local skill bundle".to_string(),
        "local_manifest" => "Local manifest".to_string(),
        "disabled_source" => "Disabled source".to_string(),
        "tracked_source" => "Tracked source".to_string(),
        "managed_model" => "Managed model".to_string(),
        "managed_backend" => "Managed backend".to_string(),
        "native_family" => "Native tool family".to_string(),
        other => humanize(other),
    }
}

fn runtime_target_label(value: &str) -> String {
    match value {
        "live_local" => "Live connector lane".to_string(),
        "runtime_catalog" => "Runtime catalog".to_string(),
        "filesystem" => "Filesystem".to_string(),
        "runtime_bridge" => "Runtime bridge".to_string(),
        "local_manifest" => "Local manifest".to_string(),
        "local_engine" => "Local engine".to_string(),
        "inference" => "Inference".to_string(),
        "model_registry" => "Model registry".to_string(),
        other => humanize(other),
    }
}

fn lease_mode_label(value: &str) -> String {
    match value {
        "governed_session" => "Governed session".to_string(),
        "direct_access" => "Direct access".to_string(),
        "selection_only" => "Selection only".to_string(),
        "source_sync" => "Source sync".to_string(),
        "governed_extension" => "Governed extension".to_string(),
        "local_bundle" => "Local bundle".to_string(),
        "managed_runtime" => "Managed runtime".to_string(),
        other => humanize(other),
    }
}

fn connector_auth_mode_label(value: &str) -> String {
    match value {
        "wallet_capability" => "Wallet capability".to_string(),
        "wallet_network_session" => "Wallet session".to_string(),
        "oauth" => "OAuth".to_string(),
        "api_key" => "API key".to_string(),
        other => humanize(other),
    }
}

fn decision_label(value: &connectors::PolicyDecisionMode) -> &'static str {
    match value {
        connectors::PolicyDecisionMode::Auto => "Auto",
        connectors::PolicyDecisionMode::Confirm => "Confirm",
        connectors::PolicyDecisionMode::Block => "Block",
    }
}

fn automation_label(value: &connectors::AutomationPolicyMode) -> &'static str {
    match value {
        connectors::AutomationPolicyMode::ConfirmOnCreate => "Confirm on create",
        connectors::AutomationPolicyMode::ConfirmOnRun => "Confirm on run",
        connectors::AutomationPolicyMode::ManualOnly => "Manual only",
    }
}

fn data_handling_label(value: &connectors::DataHandlingMode) -> &'static str {
    match value {
        connectors::DataHandlingMode::LocalOnly => "Local only",
        connectors::DataHandlingMode::LocalRedacted => "Local redacted",
    }
}

fn connector_has_automation_surface(connector: &connectors::ConnectorCatalogEntry) -> bool {
    connector.scopes.iter().any(|scope| {
        let normalized = scope.to_ascii_lowercase();
        normalized.contains("workflow")
            || normalized.contains("event")
            || normalized.contains("automation")
            || normalized.contains("watch")
            || normalized.contains("subscribe")
    })
}

fn connector_has_expert_surface(connector: &connectors::ConnectorCatalogEntry) -> bool {
    connector.scopes.iter().any(|scope| {
        let normalized = scope.to_ascii_lowercase();
        normalized.contains("expert") || normalized.contains("raw")
    })
}

fn build_authority(
    tier_id: &str,
    tier_label: &str,
    governed_profile_id: Option<&str>,
    summary: impl Into<String>,
    detail: impl Into<String>,
    signals: Vec<String>,
) -> CapabilityAuthorityDescriptor {
    CapabilityAuthorityDescriptor {
        tier_id: tier_id.to_string(),
        tier_label: tier_label.to_string(),
        governed_profile_id: governed_profile_id.map(ToString::to_string),
        governed_profile_label: governed_profile_id.map(governed_profile_label),
        summary: summary.into(),
        detail: detail.into(),
        signals,
    }
}

fn build_lease(
    availability: String,
    runtime_target_id: Option<&str>,
    mode_id: Option<&str>,
    summary: impl Into<String>,
    detail: impl Into<String>,
    requires_auth: bool,
    signals: Vec<String>,
) -> CapabilityLeaseDescriptor {
    CapabilityLeaseDescriptor {
        availability_label: availability_label(&availability),
        availability,
        runtime_target_id: runtime_target_id.map(ToString::to_string),
        runtime_target_label: runtime_target_id.map(runtime_target_label),
        mode_id: mode_id.map(ToString::to_string),
        mode_label: mode_id.map(lease_mode_label),
        summary: summary.into(),
        detail: detail.into(),
        requires_auth,
        signals,
    }
}

fn normalize_governing_token(value: &str) -> Option<String> {
    let parts = value
        .trim()
        .replace('\\', "/")
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter(|segment| !segment.is_empty())
        .map(|segment| segment.to_ascii_lowercase())
        .collect::<Vec<_>>();
    if parts.is_empty() {
        None
    } else {
        Some(parts.join("-"))
    }
}

fn normalize_governing_relative_path(value: &str) -> Option<String> {
    let normalized = value
        .trim()
        .replace('\\', "/")
        .trim_start_matches("./")
        .trim_start_matches('/')
        .trim_end_matches('/')
        .to_ascii_lowercase();
    if normalized.is_empty() {
        None
    } else {
        Some(normalized)
    }
}

fn normalize_registry_relative_path(value: &str) -> Option<String> {
    let normalized = value
        .trim()
        .replace('\\', "/")
        .trim_start_matches("./")
        .trim_start_matches('/')
        .trim_end_matches('/')
        .to_string();
    if normalized.is_empty() {
        None
    } else {
        Some(normalized)
    }
}

fn push_governing_hint(hints: &mut BTreeSet<String>, prefix: &str, value: Option<String>) {
    if let Some(value) = value.filter(|value| !value.is_empty()) {
        hints.insert(format!("{prefix}:{value}"));
    }
}

fn push_native_family_alias_hints(hints: &mut BTreeSet<String>, family_id: &str) {
    let normalized = normalize_governing_token(family_id);
    push_governing_hint(hints, "native-family", normalized.clone());
    push_governing_hint(hints, "capability", normalized);
}

fn native_family_aliases_for_token(token: &str) -> &'static [&'static str] {
    match token {
        "interactive" | "chat" | "conversation" | "assistant" | "responses" => &["responses"],
        "knowledge" | "memory" | "retrieval" | "context" => &["knowledge"],
        "embedding" | "embeddings" => &["embeddings"],
        "rerank" | "ranking" | "rank" => &["rerank"],
        "transcription" | "transcribe" | "transcript" => &["transcription"],
        "speech" | "voice" | "tts" => &["speech"],
        "vision" | "ocr" => &["vision"],
        "image" | "images" | "image-generation" | "image-editing" | "image-studio" => &["image"],
        "video" | "video-generation" | "video-studio" => &["video"],
        "model-registry" | "models" | "registry" => &["model_registry"],
        "backend" | "backends" => &["backend"],
        "gallery" | "catalog" | "catalogs" => &["gallery"],
        "worker" | "workers" | "workflow" | "workflows" | "delegate" | "delegation" => &["workers"],
        _ => &[],
    }
}

fn contribution_kind_family_aliases(kind: &str) -> &'static [&'static str] {
    match kind {
        "hooks" | "mcp_servers" | "apps" => &["workers"],
        _ => &[],
    }
}

fn append_manifest_capability_hints(hints: &mut BTreeSet<String>, capability: &str) {
    let normalized = normalize_governing_token(capability);
    push_governing_hint(hints, "capability", normalized.clone());
    if let Some(token) = normalized.as_deref() {
        for family_id in native_family_aliases_for_token(token) {
            push_native_family_alias_hints(hints, family_id);
        }
    }
}

fn append_extension_contribution_hints(
    hints: &mut BTreeSet<String>,
    contribution: &ExtensionContributionRecord,
) {
    let normalized_kind = normalize_governing_token(&contribution.kind);
    push_governing_hint(hints, "contribution-kind", normalized_kind.clone());
    if let Some(kind) = normalized_kind.as_deref() {
        for family_id in contribution_kind_family_aliases(kind) {
            push_native_family_alias_hints(hints, family_id);
        }
    }
}

fn filesystem_skill_entry_id(owner_kind: &str, owner_id: &str, relative_path: &str) -> String {
    let normalized_path = normalize_registry_relative_path(relative_path)
        .unwrap_or_else(|| relative_path.to_string());
    format!("filesystem_skill:{owner_kind}:{owner_id}:{normalized_path}")
}

fn runtime_profile_backend_slug(runtime: &LocalEngineRuntimeProfile) -> Option<String> {
    normalize_governing_token(&runtime.mode)
        .or_else(|| normalize_governing_token(&runtime.endpoint))
        .filter(|value| !value.is_empty())
}

fn runtime_profile_is_local(runtime: &LocalEngineRuntimeProfile) -> bool {
    let mode = runtime.mode.to_ascii_lowercase();
    let endpoint = runtime.endpoint.to_ascii_lowercase();
    mode.contains("local")
        || endpoint.starts_with("http://127.0.0.1")
        || endpoint.starts_with("http://localhost")
        || endpoint.starts_with("https://127.0.0.1")
        || endpoint.starts_with("https://localhost")
}

fn append_discovered_skill_hints(
    hints: &mut BTreeSet<String>,
    skill: &crate::models::SkillSourceDiscoveredSkill,
) {
    push_governing_hint(hints, "skill-name", normalize_governing_token(&skill.name));
    push_governing_hint(
        hints,
        "skill-path",
        normalize_governing_relative_path(&skill.relative_path),
    );
}

fn connector_entry(
    connector: &connectors::ConnectorCatalogEntry,
    policy_manager: &connectors::ShieldPolicyManager,
) -> CapabilityRegistryEntry {
    let mut governing_family_hints = BTreeSet::new();
    push_governing_hint(
        &mut governing_family_hints,
        "connector",
        normalize_governing_token(&connector.id),
    );
    let availability = availability_for_status(&connector.status, true);
    let status_label = humanize(&connector.status);
    let policy = policy_manager.resolve_connector_policy(&connector.id);
    let has_automation_surface = connector_has_automation_surface(connector);
    let has_expert_surface = connector_has_expert_surface(connector);
    let why_selectable = if connector.status == "connected" {
        format!(
            "{} live scope{} available through {}.",
            connector.scopes.len(),
            if connector.scopes.len() == 1 { "" } else { "s" },
            connector_auth_mode_label(&connector.auth_mode)
        )
    } else {
        connector
            .notes
            .clone()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| {
                "Auth must be completed before the connector can execute.".to_string()
            })
    };
    let authority = if matches!(policy.reads, connectors::PolicyDecisionMode::Block)
        && matches!(policy.writes, connectors::PolicyDecisionMode::Block)
        && matches!(policy.admin, connectors::PolicyDecisionMode::Block)
    {
        build_authority(
            "blocked",
            "Blocked",
            Some("blocked_connector"),
            "Current policy blocks the connector's live read, write, and admin paths before execution starts.",
            "Operators would need to widen Shield policy before this connector can do meaningful work.",
            vec![
                format!("Reads {}", decision_label(&policy.reads)),
                format!("Writes {}", decision_label(&policy.writes)),
                format!("Admin {}", decision_label(&policy.admin)),
            ],
        )
    } else if has_expert_surface && !matches!(policy.expert, connectors::PolicyDecisionMode::Block)
    {
        build_authority(
            "expert",
            "Expert / raw",
            Some("expert_connector"),
            if matches!(policy.expert, connectors::PolicyDecisionMode::Auto) {
                "This connector can reach expert or raw actions without a per-run confirmation gate."
            } else {
                "This connector exposes expert or raw actions, but current policy still gates them before execution."
            },
            "Expert-capable connectors carry the widest authority class because they can bypass higher-level convenience affordances.",
            vec![
                format!("Expert {}", decision_label(&policy.expert)),
                format!("Auth path: {}", connector_auth_mode_label(&connector.auth_mode)),
                if connector.status == "connected" {
                    "Runtime auth attached".to_string()
                } else {
                    format!("Status: {}", status_label)
                },
            ],
        )
    } else if has_automation_surface {
        build_authority(
            "automation",
            "Durable automation",
            Some("automation_connector"),
            "This connector can host durable automation surfaces such as event- or workflow-driven execution.",
            "Shield policy still governs create/run posture, but the connector itself sits in the automation authority class.",
            vec![
                format!("Automations {}", automation_label(&policy.automations)),
                format!("Writes {}", decision_label(&policy.writes)),
                format!("Admin {}", decision_label(&policy.admin)),
            ],
        )
    } else if !matches!(policy.writes, connectors::PolicyDecisionMode::Block)
        || !matches!(policy.admin, connectors::PolicyDecisionMode::Block)
    {
        build_authority(
            "governed",
            "Governed write",
            Some("governed_connector"),
            "This connector can mutate state, but its write/admin paths remain explicitly governed by current policy.",
            "Use this class for reply drafts, file mutations, and other state-changing work that should remain operator-steerable.",
            vec![
                format!("Writes {}", decision_label(&policy.writes)),
                format!("Admin {}", decision_label(&policy.admin)),
                format!("Reads {}", decision_label(&policy.reads)),
            ],
        )
    } else {
        build_authority(
            "contained_local",
            "Observe / contained",
            Some("observe_only_connector"),
            "This connector is effectively constrained to read-biased or tightly governed access before execution starts.",
            "It can help the operator inspect context without opening broad write, automation, or expert authority.",
            vec![
                format!("Reads {}", decision_label(&policy.reads)),
                format!("Writes {}", decision_label(&policy.writes)),
                format!("Auth path: {}", connector_auth_mode_label(&connector.auth_mode)),
            ],
        )
    };
    let lease_mode = if connector.auth_mode.starts_with("wallet") {
        "governed_session"
    } else {
        "direct_access"
    };
    let requires_auth = connector.status != "connected";
    let lease = build_lease(
        availability.clone(),
        Some("live_local"),
        Some(lease_mode),
        if requires_auth {
            "This connector requires live auth before the runtime can lease it into a run."
        } else if lease_mode == "governed_session" {
            "Wallet-backed auth binds connector use to a governed session-style lease."
        } else {
            "This connector uses direct adapter access once credentials and policy permit the call."
        },
        format!(
            "Connector actions ride the {} lane with {} semantics. Current data handling posture is {}.",
            runtime_target_label("live_local"),
            lease_mode_label(lease_mode),
            data_handling_label(&policy.data_handling)
        ),
        requires_auth,
        vec![
            format!("Availability {}", availability_label(&availability)),
            format!("Auth path: {}", connector_auth_mode_label(&connector.auth_mode)),
            format!("Data handling {}", data_handling_label(&policy.data_handling)),
            format!("Automations {}", automation_label(&policy.automations)),
        ],
    );

    CapabilityRegistryEntry {
        entry_id: format!("connector:{}", connector.id),
        kind: "connector".to_string(),
        label: connector.name.clone(),
        summary: connector.description.clone(),
        source_kind: "connector_catalog".to_string(),
        source_label: "Governed connector catalog".to_string(),
        source_uri: None,
        trust_posture: if connector.auth_mode.starts_with("wallet") {
            "governed".to_string()
        } else {
            "operator_managed".to_string()
        },
        governed_profile: Some(connector.auth_mode.clone()),
        availability,
        status_label,
        why_selectable,
        governing_family_id: None,
        related_governing_entry_ids: Vec::new(),
        governing_family_hints: governing_family_hints.into_iter().collect(),
        runtime_target: Some("live_local".to_string()),
        lease_mode: Some(lease_mode.to_string()),
        authority,
        lease,
    }
}

fn skill_entry(skill: &SkillCatalogEntry) -> CapabilityRegistryEntry {
    let mut governing_family_hints = BTreeSet::new();
    push_governing_hint(
        &mut governing_family_hints,
        "skill-name",
        normalize_governing_token(&skill.name),
    );
    push_governing_hint(
        &mut governing_family_hints,
        "tool-name",
        normalize_governing_token(&skill.definition.name),
    );
    push_governing_hint(
        &mut governing_family_hints,
        "skill-path",
        skill
            .relative_path
            .as_deref()
            .and_then(normalize_governing_relative_path),
    );
    let sample_size = skill.sample_size;
    let availability = if skill.stale {
        "attention".to_string()
    } else {
        "ready".to_string()
    };
    let success_percent = format!("{}%", skill.success_rate_bps / 100);
    let why_selectable = if sample_size > 0 {
        format!(
            "Observed runtime skill with {} success across {} run{}.",
            success_percent,
            sample_size,
            if sample_size == 1 { "" } else { "s" }
        )
    } else {
        "Published runtime skill ready for future selection.".to_string()
    };
    let authority = build_authority(
        "selection_only",
        "Selection only",
        Some(skill.lifecycle_state.as_str()),
        "Runtime skills influence planner and worker behavior, but they do not carry standalone external authority.",
        "Execution authority is borrowed from the tools, connectors, and local-engine surfaces leased at run time, so the skill itself stays selection-scoped.",
        vec![
            format!("Lifecycle {}", humanize(&skill.lifecycle_state)),
            format!("Source {}", humanize(&skill.source_type)),
            if skill.stale {
                "Benchmark evidence is stale".to_string()
            } else {
                "Benchmark evidence is current".to_string()
            },
        ],
    );
    let lease = build_lease(
        availability.clone(),
        Some("runtime_catalog"),
        Some("selection_only"),
        "Selecting this skill changes routing and reusable procedure choice, not capability authority by itself.",
        "A run still needs leases from the underlying connectors, extensions, or local engine before the skill can do real work.",
        false,
        vec![
            format!("Availability {}", availability_label(&availability)),
            format!("Observed runs {}", sample_size),
            format!("Success {}", success_percent),
        ],
    );

    CapabilityRegistryEntry {
        entry_id: format!("skill:{}", skill.skill_hash),
        kind: "skill".to_string(),
        label: skill.name.clone(),
        summary: skill.description.clone(),
        source_kind: skill.source_type.clone(),
        source_label: humanize(&skill.source_type),
        source_uri: skill.relative_path.clone(),
        trust_posture: if skill.stale {
            "stale".to_string()
        } else {
            "benchmarked".to_string()
        },
        governed_profile: Some(skill.lifecycle_state.clone()),
        availability,
        status_label: humanize(&skill.lifecycle_state),
        why_selectable,
        governing_family_id: None,
        related_governing_entry_ids: Vec::new(),
        governing_family_hints: governing_family_hints.into_iter().collect(),
        runtime_target: Some("runtime_catalog".to_string()),
        lease_mode: Some("selection_only".to_string()),
        authority,
        lease,
    }
}

fn skill_source_entry(source: &SkillSourceRecord) -> CapabilityRegistryEntry {
    let mut governing_family_hints = BTreeSet::new();
    push_governing_hint(
        &mut governing_family_hints,
        "source-root",
        normalize_governing_source_uri(&source.uri),
    );
    for skill in &source.discovered_skills {
        append_discovered_skill_hints(&mut governing_family_hints, skill);
    }
    let discovered = source.discovered_skills.len();
    let availability = availability_for_status(&source.sync_status, source.enabled);
    let status_label = if source.enabled {
        humanize(&source.sync_status)
    } else {
        "Disabled".to_string()
    };
    let authority = if source.enabled {
        build_authority(
            "contained_local",
            "Contained local",
            Some("tracked_source"),
            "This tracked source widens or narrows what local filesystem skills the runtime can discover.",
            "Tracked roots stay in the lowest authority class because they contribute on-disk instructions rather than direct network or connector execution.",
            vec![
                format!("Kind {}", humanize(&source.kind)),
                format!("Discovered skills {}", discovered),
                format!("Sync {}", humanize(&source.sync_status)),
            ],
        )
    } else {
        build_authority(
            "blocked",
            "Disabled source",
            Some("disabled_source"),
            "This tracked source is present on disk, but it is currently disabled and excluded from runtime discovery.",
            "Re-enable the source before its filesystem skills can influence planner selection or worker attachment again.",
            vec![
                format!("Kind {}", humanize(&source.kind)),
                format!("Discovered skills {}", discovered),
                "Runtime discovery disabled".to_string(),
            ],
        )
    };
    let lease = build_lease(
        availability.clone(),
        Some("filesystem"),
        Some("source_sync"),
        if source.enabled {
            "Syncing this root updates the local filesystem skill lane that the runtime can index."
        } else {
            "Disabled roots do not publish new filesystem skills into the runtime-adjacent lane."
        },
        "The source itself never executes remote work; it only governs what reusable on-disk instructions are available for future attachment.",
        false,
        vec![
            format!("Availability {}", availability_label(&availability)),
            format!("Source {}", source.uri),
            format!("Tracked skills {}", discovered),
        ],
    );

    CapabilityRegistryEntry {
        entry_id: format!("skill_source:{}", source.source_id),
        kind: "skill_source".to_string(),
        label: source.label.clone(),
        summary: format!(
            "{} tracked filesystem skill{} discovered under {}.",
            discovered,
            if discovered == 1 { "" } else { "s" },
            source.uri
        ),
        source_kind: source.kind.clone(),
        source_label: source.label.clone(),
        source_uri: Some(source.uri.clone()),
        trust_posture: "local_only".to_string(),
        governed_profile: Some("tracked_source".to_string()),
        availability,
        status_label,
        why_selectable: if source.enabled {
            format!(
                "Feeds {} discovered skill{} into the runtime-adjacent filesystem lane.",
                discovered,
                if discovered == 1 { "" } else { "s" }
            )
        } else {
            "Currently disabled and excluded from runtime-backed discovery.".to_string()
        },
        governing_family_id: None,
        related_governing_entry_ids: Vec::new(),
        governing_family_hints: governing_family_hints.into_iter().collect(),
        runtime_target: Some("filesystem".to_string()),
        lease_mode: Some("source_sync".to_string()),
        authority,
        lease,
    }
}

fn source_backed_filesystem_skill_entry(
    source: &SkillSourceRecord,
    skill: &crate::models::SkillSourceDiscoveredSkill,
) -> CapabilityRegistryEntry {
    let mut governing_family_hints = BTreeSet::new();
    push_governing_hint(
        &mut governing_family_hints,
        "source-root",
        normalize_governing_source_uri(&source.uri),
    );
    append_discovered_skill_hints(&mut governing_family_hints, skill);

    let availability = availability_for_status(&source.sync_status, source.enabled);
    let status_label = if source.enabled {
        humanize(&source.sync_status)
    } else {
        "Disabled".to_string()
    };
    let summary = skill
        .description
        .clone()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| {
            format!(
                "Discovered filesystem skill at {} under {}.",
                skill.relative_path, source.label
            )
        });
    let authority = build_authority(
        "selection_only",
        "Selection only",
        Some(if source.enabled {
            "tracked_source"
        } else {
            "disabled_source"
        }),
        if source.enabled {
            "This discovered filesystem skill can shape planner and worker selection once the tracked source is attached."
        } else {
            "This discovered filesystem skill is present on disk, but the tracked source is currently disabled."
        },
        "The skill itself does not carry standalone external authority. Any real execution authority is still inherited from the leases of the tools, extensions, or connectors it eventually calls.",
        vec![
            format!("Tracked source {}", source.label),
            format!("Path {}", skill.relative_path),
            format!("Sync {}", humanize(&source.sync_status)),
        ],
    );
    let lease = build_lease(
        availability.clone(),
        Some("filesystem"),
        Some("selection_only"),
        if source.enabled {
            "Selecting this filesystem skill changes reusable procedure choice inside the tracked-source lane."
        } else {
            "Disabled sources do not publish this filesystem skill into the active selection lane."
        },
        "Runs still borrow execution authority from the governed substrates they call into, so this skill remains selection-scoped even when it becomes discoverable.",
        false,
        vec![
            format!("Availability {}", availability_label(&availability)),
            format!("Tracked source {}", source.label),
            format!("Relative path {}", skill.relative_path),
        ],
    );

    CapabilityRegistryEntry {
        entry_id: filesystem_skill_entry_id("source", &source.source_id, &skill.relative_path),
        kind: "filesystem_skill".to_string(),
        label: skill.name.clone(),
        summary,
        source_kind: source.kind.clone(),
        source_label: source.label.clone(),
        source_uri: Some(source.uri.clone()),
        trust_posture: if source.enabled {
            "local_only".to_string()
        } else {
            "blocked".to_string()
        },
        governed_profile: Some(if source.enabled {
            "tracked_source".to_string()
        } else {
            "disabled_source".to_string()
        }),
        availability,
        status_label,
        why_selectable: if source.enabled {
            format!(
                "Discovered at {} from tracked source {}.",
                skill.relative_path, source.label
            )
        } else {
            format!(
                "Present at {}, but the tracked source {} is disabled.",
                skill.relative_path, source.label
            )
        },
        governing_family_id: None,
        related_governing_entry_ids: Vec::new(),
        governing_family_hints: governing_family_hints.into_iter().collect(),
        runtime_target: Some("filesystem".to_string()),
        lease_mode: Some("selection_only".to_string()),
        authority,
        lease,
    }
}

fn extension_runtime_target(manifest: &ExtensionManifestRecord) -> String {
    if manifest
        .contributions
        .iter()
        .any(|item| matches!(item.kind.as_str(), "apps" | "mcp_servers" | "hooks"))
    {
        "runtime_bridge".to_string()
    } else if !manifest.filesystem_skills.is_empty() {
        "filesystem".to_string()
    } else {
        "local_manifest".to_string()
    }
}

fn extension_backed_filesystem_skill_entry(
    manifest: &ExtensionManifestRecord,
    skill: &crate::models::SkillSourceDiscoveredSkill,
) -> CapabilityRegistryEntry {
    let mut governing_family_hints = BTreeSet::new();
    push_governing_hint(
        &mut governing_family_hints,
        "source-root",
        normalize_governing_source_uri(&manifest.source_uri),
    );
    push_governing_hint(
        &mut governing_family_hints,
        "extension-root",
        normalize_governing_source_uri(&manifest.root_path),
    );
    for capability in &manifest.capabilities {
        append_manifest_capability_hints(&mut governing_family_hints, capability);
    }
    for contribution in &manifest.contributions {
        append_extension_contribution_hints(&mut governing_family_hints, contribution);
    }
    append_discovered_skill_hints(&mut governing_family_hints, skill);

    let availability = availability_for_status(
        if manifest.enabled {
            "ready"
        } else {
            "disabled"
        },
        manifest.enabled,
    );
    let display_name = manifest
        .display_name
        .clone()
        .unwrap_or_else(|| manifest.name.clone());
    let summary = skill
        .description
        .clone()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            manifest
                .description
                .clone()
                .filter(|value| !value.trim().is_empty())
        })
        .unwrap_or_else(|| {
            format!(
                "Packaged filesystem skill at {} inside {}.",
                skill.relative_path, display_name
            )
        });
    let authority = build_authority(
        "selection_only",
        "Selection only",
        Some(manifest.governed_profile.as_str()),
        if manifest.enabled {
            "This packaged filesystem skill is available through a manifest-backed extension."
        } else {
            "This packaged filesystem skill exists on disk, but its extension source is currently disabled."
        },
        "The packaged skill can change planner and worker behavior, but it still borrows execution authority from the governed runtime substrates it eventually uses.",
        vec![
            format!("Extension {}", display_name),
            format!("Path {}", skill.relative_path),
            format!("Source {}", manifest.source_label),
        ],
    );
    let lease = build_lease(
        availability.clone(),
        Some("filesystem"),
        Some("selection_only"),
        if manifest.enabled {
            "Selecting this packaged skill changes reusable procedure choice inside the extension-backed filesystem lane."
        } else {
            "Disabled extension sources do not publish this packaged skill into the active selection lane."
        },
        format!(
            "The packaged skill inherits provenance from {} and stays selection-scoped until a run also leases governed execution substrates.",
            display_name
        ),
        false,
        vec![
            format!("Availability {}", availability_label(&availability)),
            format!("Extension {}", display_name),
            format!("Relative path {}", skill.relative_path),
        ],
    );

    CapabilityRegistryEntry {
        entry_id: filesystem_skill_entry_id(
            "extension",
            &manifest.extension_id,
            &skill.relative_path,
        ),
        kind: "filesystem_skill".to_string(),
        label: skill.name.clone(),
        summary,
        source_kind: manifest.source_kind.clone(),
        source_label: manifest.source_label.clone(),
        source_uri: Some(manifest.source_uri.clone()),
        trust_posture: manifest.trust_posture.clone(),
        governed_profile: Some(manifest.governed_profile.clone()),
        availability,
        status_label: if manifest.enabled {
            "Packaged".to_string()
        } else {
            "Disabled".to_string()
        },
        why_selectable: if manifest.enabled {
            format!(
                "Packaged at {} inside extension {}.",
                skill.relative_path, display_name
            )
        } else {
            format!(
                "Packaged at {}, but extension {} is disabled.",
                skill.relative_path, display_name
            )
        },
        governing_family_id: None,
        related_governing_entry_ids: Vec::new(),
        governing_family_hints: governing_family_hints.into_iter().collect(),
        runtime_target: Some("filesystem".to_string()),
        lease_mode: Some("selection_only".to_string()),
        authority,
        lease,
    }
}

fn extension_entry(manifest: &ExtensionManifestRecord) -> CapabilityRegistryEntry {
    let mut governing_family_hints = BTreeSet::new();
    push_governing_hint(
        &mut governing_family_hints,
        "source-root",
        normalize_governing_source_uri(&manifest.source_uri),
    );
    push_governing_hint(
        &mut governing_family_hints,
        "extension-root",
        normalize_governing_source_uri(&manifest.root_path),
    );
    for capability in &manifest.capabilities {
        append_manifest_capability_hints(&mut governing_family_hints, capability);
    }
    for contribution in &manifest.contributions {
        append_extension_contribution_hints(&mut governing_family_hints, contribution);
    }
    for skill in &manifest.filesystem_skills {
        append_discovered_skill_hints(&mut governing_family_hints, skill);
    }
    let capability_count = manifest.capabilities.len();
    let skill_count = manifest.filesystem_skills.len();
    let contribution_count = manifest.contributions.len();
    let availability = availability_for_status(
        if manifest.enabled {
            "ready"
        } else {
            "disabled"
        },
        manifest.enabled,
    );
    let runtime_target = extension_runtime_target(manifest);
    let why_selectable = if skill_count > 0 {
        format!(
            "Contributes {} filesystem skill{} and {} declared contribution{}.",
            skill_count,
            if skill_count == 1 { "" } else { "s" },
            contribution_count,
            if contribution_count == 1 { "" } else { "s" }
        )
    } else if capability_count > 0 {
        format!(
            "Declares {} runtime capabilit{} via a manifest-backed extension.",
            capability_count,
            if capability_count == 1 { "y" } else { "ies" }
        )
    } else {
        "Manifest-backed extension visible from a tracked or ambient source root.".to_string()
    };
    let authority = if !manifest.enabled {
        build_authority(
            "blocked",
            "Disabled source",
            Some("disabled_source"),
            "This extension is present on disk, but its tracked source is currently disabled.",
            "Re-enable the source before its packaged skills or contributions can shape runtime behavior again.",
            vec![
                format!("Source {}", manifest.source_label),
                format!("Trust posture {}", humanize(&manifest.trust_posture)),
                format!(
                    "{} contribution{}",
                    contribution_count,
                    if contribution_count == 1 { "" } else { "s" }
                ),
            ],
        )
    } else {
        match manifest.governed_profile.as_str() {
            "governed_marketplace" => build_authority(
                "governed",
                "Governed package",
                Some(manifest.governed_profile.as_str()),
                "This extension carries explicit installation or authentication policy from the runtime catalog or marketplace layer.",
                "Operators should review marketplace policy before widening authority because this package already declares governance expectations.",
                vec![
                    manifest
                        .marketplace_installation_policy
                        .as_ref()
                        .map(|value| format!("Install {}", humanize(value)))
                        .unwrap_or_else(|| "Install policy inherited".to_string()),
                    manifest
                        .marketplace_authentication_policy
                        .as_ref()
                        .map(|value| format!("Auth {}", humanize(value)))
                        .unwrap_or_else(|| "Auth policy inherited".to_string()),
                    manifest
                        .marketplace_display_name
                        .clone()
                        .unwrap_or_else(|| manifest.source_label.clone()),
                ],
            ),
            "automation_bridge" => build_authority(
                "automation",
                "Automation bridge",
                Some(manifest.governed_profile.as_str()),
                "This extension contributes hooks or other automation-facing surfaces that can shape durable runtime behavior.",
                "Treat automation-capable extensions as higher-authority packages because they can influence behavior beyond a one-shot skill selection.",
                vec![
                    format!(
                        "{} contribution{}",
                        contribution_count,
                        if contribution_count == 1 { "" } else { "s" }
                    ),
                    format!(
                        "{} filesystem skill{}",
                        skill_count,
                        if skill_count == 1 { "" } else { "s" }
                    ),
                    format!("Source {}", humanize(&manifest.source_kind)),
                ],
            ),
            "runtime_bridge" => build_authority(
                "governed",
                "Runtime bridge",
                Some(manifest.governed_profile.as_str()),
                "This extension contributes runtime bridge surfaces such as MCP servers or apps in addition to local metadata.",
                "Bridge packages deserve policy review because they can expand what the runtime can call, not just what it can describe.",
                vec![
                    format!(
                        "{} contribution{}",
                        contribution_count,
                        if contribution_count == 1 { "" } else { "s" }
                    ),
                    manifest.source_label.clone(),
                    format!("Trust posture {}", humanize(&manifest.trust_posture)),
                ],
            ),
            "local_skill_bundle" => build_authority(
                "contained_local",
                "Contained local",
                Some(manifest.governed_profile.as_str()),
                "This extension is currently a local skill bundle without additional runtime bridge surfaces.",
                "Contained local bundles stay closest to the source registry and mostly expand reusable instructions rather than network-facing authority.",
                vec![
                    format!(
                        "{} filesystem skill{}",
                        skill_count,
                        if skill_count == 1 { "" } else { "s" }
                    ),
                    manifest.source_label.clone(),
                    format!("Trust posture {}", humanize(&manifest.trust_posture)),
                ],
            ),
            _ => build_authority(
                "contained_local",
                "Contained local",
                Some(manifest.governed_profile.as_str()),
                "This extension is a local manifest with limited packaged authority beyond its own files and metadata.",
                "It stays in the lowest extension-authority class until it adds governed marketplace posture or runtime bridge contributions.",
                vec![
                    format!(
                        "{} contribution{}",
                        contribution_count,
                        if contribution_count == 1 { "" } else { "s" }
                    ),
                    manifest.source_label.clone(),
                    format!("Trust posture {}", humanize(&manifest.trust_posture)),
                ],
            ),
        }
    };
    let lease_mode = if manifest.trust_posture == "policy_limited" {
        "governed_extension"
    } else {
        "local_bundle"
    };
    let lease = build_lease(
        availability.clone(),
        Some(runtime_target.as_str()),
        Some(lease_mode),
        if runtime_target == "runtime_bridge" {
            "This extension widens runtime-callable surfaces beyond local instructions alone."
        } else if runtime_target == "filesystem" {
            "This extension widens the local filesystem skill lane that planners and workers can attach."
        } else {
            "This manifest mostly contributes local package metadata and bundled defaults."
        },
        format!(
            "Its packaged authority rides the {} lane with {} semantics, and operators can trace it back to {}.",
            runtime_target_label(&runtime_target),
            lease_mode_label(lease_mode),
            manifest.source_label
        ),
        manifest.marketplace_authentication_policy.is_some(),
        vec![
            format!("Availability {}", availability_label(&availability)),
            format!(
                "{} contribution{}",
                contribution_count,
                if contribution_count == 1 { "" } else { "s" }
            ),
            format!(
                "{} filesystem skill{}",
                skill_count,
                if skill_count == 1 { "" } else { "s" }
            ),
        ],
    );

    CapabilityRegistryEntry {
        entry_id: format!("extension:{}", manifest.extension_id),
        kind: "extension".to_string(),
        label: manifest
            .display_name
            .clone()
            .unwrap_or_else(|| manifest.name.clone()),
        summary: manifest
            .description
            .clone()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| {
                "Manifest-backed extension discovered from the runtime sources.".to_string()
            }),
        source_kind: manifest.source_kind.clone(),
        source_label: manifest.source_label.clone(),
        source_uri: Some(manifest.source_uri.clone()),
        trust_posture: manifest.trust_posture.clone(),
        governed_profile: Some(manifest.governed_profile.clone()),
        availability,
        status_label: if manifest.enabled {
            humanize(&manifest.manifest_kind)
        } else {
            "Disabled".to_string()
        },
        why_selectable,
        governing_family_id: None,
        related_governing_entry_ids: Vec::new(),
        governing_family_hints: governing_family_hints.into_iter().collect(),
        runtime_target: Some(runtime_target),
        lease_mode: Some(lease_mode.to_string()),
        authority,
        lease,
    }
}

fn model_entry(
    model: &LocalEngineModelRecord,
    default_model_id: Option<&str>,
) -> CapabilityRegistryEntry {
    let mut governing_family_hints = BTreeSet::new();
    push_governing_hint(
        &mut governing_family_hints,
        "native-family",
        normalize_governing_token("model-registry"),
    );
    push_governing_hint(
        &mut governing_family_hints,
        "capability",
        normalize_governing_token("model-registry"),
    );
    push_governing_hint(
        &mut governing_family_hints,
        "backend",
        model
            .backend_id
            .as_deref()
            .and_then(normalize_governing_token),
    );
    push_governing_hint(
        &mut governing_family_hints,
        "source-root",
        model
            .source_uri
            .as_deref()
            .and_then(normalize_governing_source_uri),
    );
    if default_model_id.is_some_and(|default_model_id| default_model_id == model.model_id) {
        push_native_family_alias_hints(&mut governing_family_hints, "responses");
    }
    let availability = availability_for_status(&model.status, true);
    let authority = build_authority(
        "contained_local",
        if model.residency == "local" {
            "Contained local"
        } else {
            "Runtime managed"
        },
        Some("managed_model"),
        "This model is managed by the kernel-owned local engine rather than by an ad hoc shell-local binding.",
        "Runs borrow model access through the engine scheduler, so authority comes from the runtime envelope around the model rather than from the model record alone.",
        vec![
            format!("Residency {}", humanize(&model.residency)),
            model
                .backend_id
                .as_ref()
                .map(|value| format!("Backend {}", value))
                .unwrap_or_else(|| "Backend managed by kernel".to_string()),
            model
                .hardware_profile
                .as_ref()
                .map(|value| format!("Hardware {}", value))
                .unwrap_or_else(|| "Hardware profile unknown".to_string()),
        ],
    );
    let lease = build_lease(
        availability.clone(),
        Some("inference"),
        Some("managed_runtime"),
        "The kernel local-engine scheduler leases inference access to this model when a run needs it.",
        "Operators do not bind directly to the model record; they inherit it through managed runtime selection and health checks.",
        false,
        vec![
            format!("Availability {}", availability_label(&availability)),
            format!("Residency {}", humanize(&model.residency)),
            model
                .backend_id
                .as_ref()
                .map(|value| format!("Backend {}", value))
                .unwrap_or_else(|| "No backend assignment yet".to_string()),
        ],
    );

    CapabilityRegistryEntry {
        entry_id: format!("model:{}", model.model_id),
        kind: "model".to_string(),
        label: model.model_id.clone(),
        summary: format!(
            "{} model residency{}.",
            humanize(&model.status),
            model
                .hardware_profile
                .as_ref()
                .map(|profile| format!(" on {}", profile))
                .unwrap_or_default()
        ),
        source_kind: "local_engine".to_string(),
        source_label: "Kernel runtime".to_string(),
        source_uri: model.source_uri.clone(),
        trust_posture: if model.residency == "local" {
            "contained_local".to_string()
        } else {
            "runtime_managed".to_string()
        },
        governed_profile: Some("managed_model".to_string()),
        availability,
        status_label: humanize(&model.status),
        why_selectable: model
            .backend_id
            .as_ref()
            .map(|backend_id| format!("Ready behind backend {}.", backend_id))
            .unwrap_or_else(|| "Managed by the kernel-native runtime registry.".to_string()),
        governing_family_id: None,
        related_governing_entry_ids: Vec::new(),
        governing_family_hints: governing_family_hints.into_iter().collect(),
        runtime_target: Some("local_engine".to_string()),
        lease_mode: Some("managed_runtime".to_string()),
        authority,
        lease,
    }
}

fn backend_entry(
    backend: &LocalEngineBackendRecord,
    default_backend_id: Option<&str>,
) -> CapabilityRegistryEntry {
    let mut governing_family_hints = BTreeSet::new();
    push_governing_hint(
        &mut governing_family_hints,
        "backend",
        normalize_governing_token(&backend.backend_id),
    );
    push_governing_hint(
        &mut governing_family_hints,
        "backend",
        backend.alias.as_deref().and_then(normalize_governing_token),
    );
    push_governing_hint(
        &mut governing_family_hints,
        "native-family",
        normalize_governing_token("backends"),
    );
    push_governing_hint(
        &mut governing_family_hints,
        "capability",
        normalize_governing_token("backends"),
    );
    push_governing_hint(
        &mut governing_family_hints,
        "source-root",
        backend
            .source_uri
            .as_deref()
            .and_then(normalize_governing_source_uri),
    );
    if default_backend_id.is_some_and(|default_backend_id| default_backend_id == backend.backend_id)
    {
        push_native_family_alias_hints(&mut governing_family_hints, "responses");
    }
    let availability = availability_for_status(&backend.health, true);
    let authority = build_authority(
        "contained_local",
        "Contained local",
        Some("managed_backend"),
        "Managed backends are kernel-owned runtime infrastructure, not ad hoc operator shell state.",
        "They shape which local models and tool families can be leased, but the backend itself stays inside the contained local authority class.",
        vec![
            format!("Status {}", humanize(&backend.status)),
            format!("Health {}", humanize(&backend.health)),
            backend
                .hardware_profile
                .as_ref()
                .map(|value| format!("Hardware {}", value))
                .unwrap_or_else(|| "Hardware profile unknown".to_string()),
        ],
    );
    let lease = build_lease(
        availability.clone(),
        Some("model_registry"),
        Some("managed_runtime"),
        "The kernel leases backend use through the model registry and runtime control plane.",
        "Operators interact with this backend through managed model installs, health checks, and scheduler choices rather than by direct lease issuance.",
        false,
        vec![
            format!("Availability {}", availability_label(&availability)),
            backend
                .install_path
                .as_ref()
                .map(|value| format!("Install path {}", value))
                .unwrap_or_else(|| "Install path managed by kernel".to_string()),
            format!("Health {}", humanize(&backend.health)),
        ],
    );

    CapabilityRegistryEntry {
        entry_id: format!("backend:{}", backend.backend_id),
        kind: "backend".to_string(),
        label: backend
            .alias
            .clone()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| backend.backend_id.clone()),
        summary: format!(
            "{} backend with {} health.",
            humanize(&backend.status),
            humanize(&backend.health)
        ),
        source_kind: "local_engine".to_string(),
        source_label: "Kernel runtime".to_string(),
        source_uri: backend.source_uri.clone(),
        trust_posture: "contained_local".to_string(),
        governed_profile: Some("managed_backend".to_string()),
        availability,
        status_label: humanize(&backend.health),
        why_selectable: backend
            .install_path
            .as_ref()
            .map(|path| format!("Installed at {} and monitored by the kernel.", path))
            .unwrap_or_else(|| {
                "Managed backend surfaced through the absorbed local engine.".to_string()
            }),
        governing_family_id: None,
        related_governing_entry_ids: Vec::new(),
        governing_family_hints: governing_family_hints.into_iter().collect(),
        runtime_target: Some("local_engine".to_string()),
        lease_mode: Some("managed_runtime".to_string()),
        authority,
        lease,
    }
}

fn family_entry(family: &LocalEngineCapabilityFamily) -> CapabilityRegistryEntry {
    let mut governing_family_hints = BTreeSet::new();
    push_governing_hint(
        &mut governing_family_hints,
        "native-family",
        normalize_governing_token(&family.id),
    );
    push_governing_hint(
        &mut governing_family_hints,
        "capability",
        normalize_governing_token(&family.id),
    );
    push_governing_hint(
        &mut governing_family_hints,
        "capability",
        normalize_governing_token(&family.label),
    );
    for tool_name in &family.tool_names {
        push_governing_hint(
            &mut governing_family_hints,
            "tool-name",
            normalize_governing_token(tool_name),
        );
    }
    let availability = availability_for_status(&family.status, true);
    let authority = build_authority(
        "contained_local",
        "Contained local",
        Some("native_family"),
        "Native capability families expose kernel-owned tool groups that the absorbed local engine can lease into runs.",
        "These families stay in the contained local class because their execution stays inside the managed runtime boundary rather than jumping to an ungoverned external adapter.",
        vec![
            format!("Status {}", humanize(&family.status)),
            format!("Available tools {}", family.available_count),
            family.operator_summary.clone(),
        ],
    );
    let lease = build_lease(
        availability.clone(),
        Some("local_engine"),
        Some("managed_runtime"),
        "The runtime leases access to these tool families through the local engine control plane.",
        "Operators consume this surface by selecting tasks or workers that target the family, not by directly granting one-off shell-local permissions.",
        false,
        vec![
            format!("Availability {}", availability_label(&availability)),
            format!("Tool names {}", family.tool_names.len()),
            family.operator_summary.clone(),
        ],
    );

    CapabilityRegistryEntry {
        entry_id: format!("native_family:{}", family.id),
        kind: "native_family".to_string(),
        label: family.label.clone(),
        summary: family.description.clone(),
        source_kind: "local_engine".to_string(),
        source_label: "Kernel runtime".to_string(),
        source_uri: None,
        trust_posture: "contained_local".to_string(),
        governed_profile: Some("native_family".to_string()),
        availability,
        status_label: humanize(&family.status),
        why_selectable: if family.available_count > 0 {
            format!(
                "{} native tool{} available. {}",
                family.available_count,
                if family.available_count == 1 { "" } else { "s" },
                family.operator_summary
            )
        } else {
            family.operator_summary.clone()
        },
        governing_family_id: None,
        related_governing_entry_ids: Vec::new(),
        governing_family_hints: governing_family_hints.into_iter().collect(),
        runtime_target: Some("local_engine".to_string()),
        lease_mode: Some("managed_runtime".to_string()),
        authority,
        lease,
    }
}

fn runtime_profile_backend_entry(
    runtime: &LocalEngineRuntimeProfile,
) -> Option<CapabilityRegistryEntry> {
    if runtime.mode == "mock" || runtime.endpoint.trim().is_empty() {
        return None;
    }

    let backend_slug = runtime_profile_backend_slug(runtime)?;
    let mut governing_family_hints = BTreeSet::new();
    push_governing_hint(
        &mut governing_family_hints,
        "backend",
        Some(backend_slug.clone()),
    );
    push_native_family_alias_hints(&mut governing_family_hints, "backend");
    push_native_family_alias_hints(&mut governing_family_hints, "responses");
    push_governing_hint(
        &mut governing_family_hints,
        "source-root",
        normalize_governing_source_uri(&runtime.endpoint),
    );
    let availability = "ready".to_string();
    let local_runtime = runtime_profile_is_local(runtime);
    let authority = build_authority(
        if local_runtime {
            "contained_local"
        } else {
            "runtime_managed"
        },
        if local_runtime {
            "Contained local"
        } else {
            "Runtime managed"
        },
        Some("runtime_profile_backend"),
        "This backend record is synthesized from the active kernel runtime profile when no explicit managed backend entries have materialized yet.",
        "It gives operators a concrete runtime member to compare and govern on sparse profiles without pretending the runtime is only a category-level family node.",
        vec![
            format!("Mode {}", humanize(&runtime.mode)),
            format!("Endpoint {}", runtime.endpoint),
            format!("Default model {}", runtime.default_model),
        ],
    );
    let lease = build_lease(
        availability.clone(),
        Some("local_engine"),
        Some("managed_runtime"),
        "The runtime profile backend represents the active kernel-owned execution lane while richer backend records are still absent on the profile.",
        "Operators still govern the runtime through the same model/backend family surface even when the underlying profile has not yet emitted explicit managed backend records.",
        false,
        vec![
            format!("Availability {}", availability_label(&availability)),
            format!("Mode {}", humanize(&runtime.mode)),
            format!("Endpoint {}", runtime.endpoint),
        ],
    );
    let label = if local_runtime {
        "Kernel runtime backend".to_string()
    } else {
        format!("{} runtime backend", humanize(&runtime.mode))
    };

    Some(CapabilityRegistryEntry {
        entry_id: format!("backend:{backend_slug}"),
        kind: "backend".to_string(),
        label,
        summary: format!(
            "Runtime profile backend for {} at {}.",
            humanize(&runtime.mode),
            runtime.endpoint
        ),
        source_kind: "local_engine_runtime".to_string(),
        source_label: "Kernel runtime profile".to_string(),
        source_uri: Some(runtime.endpoint.clone()),
        trust_posture: if local_runtime {
            "contained_local".to_string()
        } else {
            "runtime_managed".to_string()
        },
        governed_profile: Some("runtime_profile_backend".to_string()),
        availability,
        status_label: humanize(&runtime.mode),
        why_selectable: format!(
            "Active runtime endpoint {} backing the kernel-owned default route.",
            runtime.endpoint
        ),
        governing_family_id: None,
        related_governing_entry_ids: Vec::new(),
        governing_family_hints: governing_family_hints.into_iter().collect(),
        runtime_target: Some("local_engine".to_string()),
        lease_mode: Some("managed_runtime".to_string()),
        authority,
        lease,
    })
}

fn runtime_profile_model_entry(
    runtime: &LocalEngineRuntimeProfile,
    backend_slug: Option<&str>,
) -> Option<CapabilityRegistryEntry> {
    let default_model = runtime.default_model.trim();
    if default_model.is_empty() || default_model == "none" || default_model == "mock" {
        return None;
    }

    let mut governing_family_hints = BTreeSet::new();
    push_native_family_alias_hints(&mut governing_family_hints, "model_registry");
    push_native_family_alias_hints(&mut governing_family_hints, "responses");
    push_governing_hint(
        &mut governing_family_hints,
        "backend",
        backend_slug.map(ToString::to_string),
    );
    push_governing_hint(
        &mut governing_family_hints,
        "source-root",
        normalize_governing_source_uri(&runtime.endpoint),
    );
    let availability = "ready".to_string();
    let local_runtime = runtime_profile_is_local(runtime);
    let authority = build_authority(
        if local_runtime {
            "contained_local"
        } else {
            "runtime_managed"
        },
        if local_runtime {
            "Contained local"
        } else {
            "Runtime managed"
        },
        Some("runtime_profile_model"),
        "This model record is synthesized from the active kernel runtime profile when the profile has a default model but has not yet emitted explicit managed model records.",
        "It lets operators compare the real default runtime model against related capabilities instead of only seeing the higher-level model registry family node.",
        vec![
            format!("Model {}", default_model),
            format!("Mode {}", humanize(&runtime.mode)),
            backend_slug
                .map(|value| format!("Backend {}", value))
                .unwrap_or_else(|| "Backend implied by runtime profile".to_string()),
        ],
    );
    let lease = build_lease(
        availability.clone(),
        Some("local_engine"),
        Some("managed_runtime"),
        "The runtime profile model stands in for the active kernel-selected default model until richer registry records are available.",
        "Runs still borrow inference authority through the kernel scheduler; this fallback record exists to make that runtime member inspectable and comparable in the capability fabric.",
        false,
        vec![
            format!("Availability {}", availability_label(&availability)),
            format!("Model {}", default_model),
            format!("Mode {}", humanize(&runtime.mode)),
        ],
    );

    Some(CapabilityRegistryEntry {
        entry_id: format!("model:{default_model}"),
        kind: "model".to_string(),
        label: default_model.to_string(),
        summary: format!("Default runtime model for {}.", humanize(&runtime.mode)),
        source_kind: "local_engine_runtime".to_string(),
        source_label: "Kernel runtime profile".to_string(),
        source_uri: Some(runtime.endpoint.clone()),
        trust_posture: if local_runtime {
            "contained_local".to_string()
        } else {
            "runtime_managed".to_string()
        },
        governed_profile: Some("runtime_profile_model".to_string()),
        availability,
        status_label: "Default".to_string(),
        why_selectable: format!(
            "Kernel runtime profile routes default responses through {}.",
            default_model
        ),
        governing_family_id: None,
        related_governing_entry_ids: Vec::new(),
        governing_family_hints: governing_family_hints.into_iter().collect(),
        runtime_target: Some("local_engine".to_string()),
        lease_mode: Some("managed_runtime".to_string()),
        authority,
        lease,
    })
}

fn normalize_governing_source_uri(uri: &str) -> Option<String> {
    let normalized = uri.trim().replace('\\', "/");
    let normalized = normalized.trim_end_matches('/').trim().to_string();
    if normalized.is_empty() {
        None
    } else {
        Some(normalized)
    }
}

fn governing_family_hints_for_entry(entry: &CapabilityRegistryEntry) -> Vec<String> {
    let mut hints = entry
        .governing_family_hints
        .iter()
        .filter_map(|hint| {
            let trimmed = hint.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        })
        .collect::<BTreeSet<_>>();

    match entry.kind.as_str() {
        "connector" => {
            if hints.is_empty() {
                hints.insert(format!("connector:{}", entry.entry_id));
            }
        }
        "skill_source" | "extension" => {
            if let Some(source_root) = entry
                .source_uri
                .as_deref()
                .and_then(normalize_governing_source_uri)
            {
                hints.insert(format!("source-root:{source_root}"));
            }
        }
        _ => {}
    }

    hints.into_iter().collect()
}

fn annotate_governing_relationships(entries: &mut [CapabilityRegistryEntry]) {
    let entry_hints = entries
        .iter()
        .map(|entry| {
            (
                entry.entry_id.clone(),
                governing_family_hints_for_entry(entry),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut family_members = BTreeMap::<String, BTreeSet<String>>::new();
    for (entry_id, hints) in &entry_hints {
        for hint in hints {
            family_members
                .entry(hint.clone())
                .or_default()
                .insert(entry_id.clone());
        }
    }

    for entry in entries.iter_mut() {
        let hints = entry_hints
            .get(&entry.entry_id)
            .cloned()
            .unwrap_or_default();
        entry.governing_family_id = hints
            .iter()
            .find(|hint| hint.starts_with("source-root:"))
            .cloned()
            .or_else(|| hints.first().cloned());
        entry.governing_family_hints = hints.clone();

        let mut related = BTreeSet::new();
        for hint in &hints {
            if let Some(members) = family_members.get(hint) {
                related.extend(
                    members
                        .iter()
                        .filter(|candidate_id| *candidate_id != &entry.entry_id)
                        .cloned(),
                );
            }
        }
        entry.related_governing_entry_ids = related.into_iter().collect();
    }
}

fn authoritative_source_count(
    entries: &[CapabilityRegistryEntry],
    connectors_present: bool,
    runtime_catalog_present: bool,
    local_engine_present: bool,
) -> usize {
    let mut keys = entries
        .iter()
        .filter(|entry| entry.kind == "skill_source" || entry.kind == "extension")
        .map(|entry| {
            format!(
                "{}:{}",
                entry.source_kind,
                entry
                    .source_uri
                    .as_deref()
                    .unwrap_or(entry.source_label.as_str())
            )
        })
        .collect::<BTreeSet<_>>();
    if connectors_present {
        keys.insert("connector_catalog:kernel".to_string());
    }
    if runtime_catalog_present {
        keys.insert("runtime_catalog:skills".to_string());
    }
    if local_engine_present {
        keys.insert("local_engine:kernel".to_string());
    }
    keys.len()
}

fn filesystem_skill_count(
    skill_sources: &[SkillSourceRecord],
    extension_manifests: &[ExtensionManifestRecord],
) -> usize {
    let mut keys = BTreeSet::new();
    for source in skill_sources {
        for skill in &source.discovered_skills {
            keys.insert(format!(
                "source:{}:{}",
                source.source_id, skill.relative_path
            ));
        }
    }
    for manifest in extension_manifests {
        for skill in &manifest.filesystem_skills {
            keys.insert(format!(
                "extension:{}:{}",
                manifest.extension_id, skill.relative_path
            ));
        }
    }
    keys.len()
}

fn emit_capability_governance_request(
    app: &AppHandle,
    request: &Option<CapabilityGovernanceRequest>,
) {
    let _ = app.emit(CAPABILITY_GOVERNANCE_REQUEST_UPDATED_EVENT, request);
}

fn action_key(action: &CapabilityGovernanceRequestAction) -> &'static str {
    match action {
        CapabilityGovernanceRequestAction::Widen => "widen",
        CapabilityGovernanceRequestAction::Baseline => "baseline",
    }
}

fn decision_strength(value: &connectors::PolicyDecisionMode) -> u8 {
    match value {
        connectors::PolicyDecisionMode::Block => 0,
        connectors::PolicyDecisionMode::Confirm => 1,
        connectors::PolicyDecisionMode::Auto => 2,
    }
}

fn automation_strength(value: &connectors::AutomationPolicyMode) -> u8 {
    match value {
        connectors::AutomationPolicyMode::ManualOnly => 0,
        connectors::AutomationPolicyMode::ConfirmOnRun => 1,
        connectors::AutomationPolicyMode::ConfirmOnCreate => 2,
    }
}

fn decision_for_strength(strength: u8) -> connectors::PolicyDecisionMode {
    match strength {
        2 => connectors::PolicyDecisionMode::Auto,
        1 => connectors::PolicyDecisionMode::Confirm,
        _ => connectors::PolicyDecisionMode::Block,
    }
}

fn automation_for_strength(strength: u8) -> connectors::AutomationPolicyMode {
    match strength {
        2 => connectors::AutomationPolicyMode::ConfirmOnCreate,
        1 => connectors::AutomationPolicyMode::ConfirmOnRun,
        _ => connectors::AutomationPolicyMode::ManualOnly,
    }
}

fn widen_decision_mode(
    current: &connectors::PolicyDecisionMode,
    floor: &connectors::PolicyDecisionMode,
) -> connectors::PolicyDecisionMode {
    decision_for_strength(decision_strength(current).max(decision_strength(floor)))
}

fn widen_automation_mode(
    current: &connectors::AutomationPolicyMode,
    floor: &connectors::AutomationPolicyMode,
) -> connectors::AutomationPolicyMode {
    automation_for_strength(automation_strength(current).max(automation_strength(floor)))
}

fn build_widened_global_policy_defaults(
    effective: &connectors::GlobalPolicyDefaults,
    entry: &CapabilityRegistryEntry,
) -> connectors::GlobalPolicyDefaults {
    let mut next = effective.clone();

    match entry.authority.tier_id.as_str() {
        "expert" => {
            next.reads = widen_decision_mode(&next.reads, &connectors::PolicyDecisionMode::Auto);
            next.writes =
                widen_decision_mode(&next.writes, &connectors::PolicyDecisionMode::Confirm);
            next.admin = widen_decision_mode(&next.admin, &connectors::PolicyDecisionMode::Confirm);
            next.expert =
                widen_decision_mode(&next.expert, &connectors::PolicyDecisionMode::Confirm);
        }
        "automation" => {
            next.reads = widen_decision_mode(&next.reads, &connectors::PolicyDecisionMode::Auto);
            next.writes =
                widen_decision_mode(&next.writes, &connectors::PolicyDecisionMode::Confirm);
            next.admin = widen_decision_mode(&next.admin, &connectors::PolicyDecisionMode::Confirm);
            next.automations = widen_automation_mode(
                &next.automations,
                &connectors::AutomationPolicyMode::ConfirmOnRun,
            );
        }
        "governed" => {
            next.reads = widen_decision_mode(&next.reads, &connectors::PolicyDecisionMode::Auto);
            next.writes =
                widen_decision_mode(&next.writes, &connectors::PolicyDecisionMode::Confirm);
        }
        "blocked" => {
            next.reads = widen_decision_mode(&next.reads, &connectors::PolicyDecisionMode::Confirm);
            next.writes =
                widen_decision_mode(&next.writes, &connectors::PolicyDecisionMode::Confirm);
        }
        _ => {
            next.reads = widen_decision_mode(&next.reads, &connectors::PolicyDecisionMode::Auto);
        }
    }

    next
}

fn build_baseline_global_policy_defaults(
    effective: &connectors::GlobalPolicyDefaults,
    entry: &CapabilityRegistryEntry,
) -> connectors::GlobalPolicyDefaults {
    let shipped_default = connectors::GlobalPolicyDefaults::default();
    let mut next = effective.clone();

    match entry.authority.tier_id.as_str() {
        "expert" => {
            next.reads = shipped_default.reads;
            next.writes = shipped_default.writes;
            next.admin = shipped_default.admin;
            next.expert = shipped_default.expert;
        }
        "automation" => {
            next.reads = shipped_default.reads;
            next.writes = shipped_default.writes;
            next.admin = shipped_default.admin;
            next.automations = shipped_default.automations;
        }
        "governed" | "blocked" => {
            next.reads = shipped_default.reads;
            next.writes = shipped_default.writes;
        }
        _ => {
            next.reads = shipped_default.reads;
        }
    }

    next
}

fn build_widened_connector_policy(
    effective: &connectors::GlobalPolicyDefaults,
    entry: &CapabilityRegistryEntry,
) -> connectors::ConnectorPolicyOverride {
    let widened = build_widened_global_policy_defaults(effective, entry);
    connectors::ConnectorPolicyOverride {
        inherit_global: false,
        reads: widened.reads,
        writes: widened.writes,
        admin: widened.admin,
        expert: widened.expert,
        automations: widened.automations,
        data_handling: widened.data_handling,
    }
}

fn effective_connector_policy_defaults(
    policy_state: &connectors::ShieldPolicyState,
    connector_id: &str,
) -> connectors::GlobalPolicyDefaults {
    policy_state
        .overrides
        .get(connector_id)
        .filter(|override_state| !override_state.inherit_global)
        .map(|override_state| connectors::GlobalPolicyDefaults {
            reads: override_state.reads.clone(),
            writes: override_state.writes.clone(),
            admin: override_state.admin.clone(),
            expert: override_state.expert.clone(),
            automations: override_state.automations.clone(),
            data_handling: override_state.data_handling.clone(),
        })
        .unwrap_or_else(|| policy_state.global.clone())
}

#[derive(Debug, Clone)]
enum GovernanceProposalTarget {
    RegistryEntry(CapabilityRegistryEntry),
    GlobalRuntimePosture,
}

fn resolve_connector_target(
    input: &CapabilityGovernanceRequestPlanInput,
    governing_entry: &CapabilityRegistryEntry,
    snapshot: &CapabilityRegistrySnapshot,
) -> (String, String, bool) {
    let requested_connector_id = input
        .connector_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let requested_connector_label = input
        .connector_label
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());

    if let Some(connector_id) = requested_connector_id {
        if connector_id.eq_ignore_ascii_case("global") {
            return (
                "global".to_string(),
                requested_connector_label
                    .unwrap_or("Global runtime posture")
                    .to_string(),
                true,
            );
        }

        let label = requested_connector_label
            .map(ToString::to_string)
            .or_else(|| {
                snapshot
                    .connectors
                    .iter()
                    .find(|connector| connector.id == connector_id)
                    .map(|connector| connector.name.clone())
            })
            .unwrap_or_else(|| humanize(connector_id));
        return (connector_id.to_string(), label, false);
    }

    if governing_entry.kind == "connector" {
        let connector_id = governing_entry
            .entry_id
            .strip_prefix("connector:")
            .unwrap_or(governing_entry.entry_id.as_str())
            .to_string();
        return (connector_id, governing_entry.label.clone(), false);
    }

    (
        "global".to_string(),
        "Global runtime posture".to_string(),
        true,
    )
}

fn policy_change_magnitude(
    current: &connectors::GlobalPolicyDefaults,
    next: &connectors::GlobalPolicyDefaults,
) -> u32 {
    let mut magnitude = 0;
    if current.reads != next.reads {
        magnitude += 1;
    }
    if current.writes != next.writes {
        magnitude += 1;
    }
    if current.admin != next.admin {
        magnitude += 1;
    }
    if current.expert != next.expert {
        magnitude += 1;
    }
    if current.automations != next.automations {
        magnitude += 1;
    }
    if current.data_handling != next.data_handling {
        magnitude += 1;
    }
    magnitude
}

fn requested_policy_defaults(
    request: &CapabilityGovernanceRequest,
) -> connectors::GlobalPolicyDefaults {
    if request.connector_id == "global" {
        request.requested_state.global.clone()
    } else {
        effective_connector_policy_defaults(&request.requested_state, &request.connector_id)
    }
}

fn policy_delta_summary(
    current: &connectors::GlobalPolicyDefaults,
    next: &connectors::GlobalPolicyDefaults,
) -> String {
    let mut deltas = Vec::new();
    if current.reads != next.reads {
        deltas.push(format!(
            "Reads {} -> {}",
            decision_label(&current.reads),
            decision_label(&next.reads)
        ));
    }
    if current.writes != next.writes {
        deltas.push(format!(
            "Writes {} -> {}",
            decision_label(&current.writes),
            decision_label(&next.writes)
        ));
    }
    if current.admin != next.admin {
        deltas.push(format!(
            "Admin {} -> {}",
            decision_label(&current.admin),
            decision_label(&next.admin)
        ));
    }
    if current.expert != next.expert {
        deltas.push(format!(
            "Expert {} -> {}",
            decision_label(&current.expert),
            decision_label(&next.expert)
        ));
    }
    if current.automations != next.automations {
        deltas.push(format!(
            "Automations {} -> {}",
            automation_label(&current.automations),
            automation_label(&next.automations)
        ));
    }
    if current.data_handling != next.data_handling {
        deltas.push(format!(
            "Data handling {} -> {}",
            data_handling_label(&current.data_handling),
            data_handling_label(&next.data_handling)
        ));
    }

    if deltas.is_empty() {
        "Already at requested posture.".to_string()
    } else {
        format!("Changes {}.", deltas.join(" · "))
    }
}

fn shares_governing_source_fallback(
    current_entry: &CapabilityRegistryEntry,
    candidate_entry: &CapabilityRegistryEntry,
) -> bool {
    let current_uri = current_entry
        .source_uri
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let candidate_uri = candidate_entry
        .source_uri
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());

    if let (Some(left), Some(right)) = (current_uri, candidate_uri) {
        return left == right;
    }

    current_entry.source_kind == candidate_entry.source_kind
        && current_entry.source_label == candidate_entry.source_label
}

fn shares_governing_provenance(
    current_entry: &CapabilityRegistryEntry,
    candidate_entry: &CapabilityRegistryEntry,
) -> bool {
    if current_entry
        .related_governing_entry_ids
        .iter()
        .any(|entry_id| entry_id == &candidate_entry.entry_id)
        || candidate_entry
            .related_governing_entry_ids
            .iter()
            .any(|entry_id| entry_id == &current_entry.entry_id)
    {
        return true;
    }

    if current_entry
        .governing_family_id
        .as_deref()
        .zip(candidate_entry.governing_family_id.as_deref())
        .is_some_and(|(left, right)| left == right)
    {
        return true;
    }

    if current_entry.governing_family_hints.iter().any(|hint| {
        candidate_entry
            .governing_family_hints
            .iter()
            .any(|candidate_hint| candidate_hint == hint)
    }) {
        return true;
    }

    shares_governing_source_fallback(current_entry, candidate_entry)
}

fn governance_target_specificity_rank(target: &GovernanceProposalTarget) -> u32 {
    match target {
        GovernanceProposalTarget::RegistryEntry(entry) => match entry.kind.as_str() {
            "connector" => 0,
            "extension" => 1,
            "skill_source" => 2,
            "native_family" => 3,
            "backend" => 4,
            "model" => 5,
            "skill" => 6,
            "filesystem_skill" => 7,
            _ => 8,
        },
        GovernanceProposalTarget::GlobalRuntimePosture => 9,
    }
}

fn governance_target_relation_rank(
    subject_entry: &CapabilityRegistryEntry,
    target: &GovernanceProposalTarget,
    compared_entry_id: Option<&str>,
) -> u32 {
    match target {
        GovernanceProposalTarget::RegistryEntry(entry) => {
            if entry.entry_id == subject_entry.entry_id {
                0
            } else if compared_entry_id.is_some_and(|value| value == entry.entry_id) {
                1
            } else if shares_governing_provenance(subject_entry, entry) {
                2
            } else if entry.kind == subject_entry.kind {
                3
            } else {
                4
            }
        }
        GovernanceProposalTarget::GlobalRuntimePosture => 5,
    }
}

fn governance_target_reason(
    subject_entry: &CapabilityRegistryEntry,
    target: &GovernanceProposalTarget,
    compared_entry_id: Option<&str>,
    compared_entry_label: Option<&str>,
) -> String {
    match target {
        GovernanceProposalTarget::RegistryEntry(entry) if entry.entry_id == subject_entry.entry_id => {
            format!(
                "{} stays on its own governing entry, which keeps widening scoped to the same authority class.",
                subject_entry.label
            )
        }
        GovernanceProposalTarget::RegistryEntry(entry)
            if compared_entry_id.is_some_and(|value| value == entry.entry_id) =>
        {
            format!(
                "{} matches the reviewed comparison target, so the runtime can propose that authority path directly.",
                compared_entry_label.unwrap_or(entry.label.as_str())
            )
        }
        GovernanceProposalTarget::RegistryEntry(entry)
            if shares_governing_provenance(subject_entry, entry) =>
        {
            format!(
                "{} is explicitly linked to {} through the same governing family, so the runtime can widen through the closest related authority path.",
                entry.label, subject_entry.label
            )
        }
        GovernanceProposalTarget::RegistryEntry(entry) => format!(
            "{} is the narrowest related governing entry the registry could propose for {}.",
            entry.label, subject_entry.label
        ),
        GovernanceProposalTarget::GlobalRuntimePosture => {
            "Global runtime posture is the broad fallback when no narrower governing target is required.".to_string()
        }
    }
}

fn governance_target_summary(target: &GovernanceProposalTarget) -> String {
    match target {
        GovernanceProposalTarget::RegistryEntry(entry) => entry.summary.clone(),
        GovernanceProposalTarget::GlobalRuntimePosture => {
            "Widen through the shipped global runtime posture instead of keeping a connector-specific override."
                .to_string()
        }
    }
}

fn entry_can_govern_subject(
    subject_entry: &CapabilityRegistryEntry,
    candidate_entry: &CapabilityRegistryEntry,
) -> bool {
    if candidate_entry.kind == "connector" {
        return false;
    }

    if (candidate_entry.kind == "skill" || candidate_entry.kind == "filesystem_skill")
        && candidate_entry.entry_id != subject_entry.entry_id
    {
        return false;
    }

    true
}

fn collect_governance_targets(
    subject_entry: &CapabilityRegistryEntry,
    comparison_entry: Option<&CapabilityRegistryEntry>,
    snapshot: &CapabilityRegistrySnapshot,
) -> Vec<GovernanceProposalTarget> {
    if subject_entry.kind == "connector" {
        return vec![
            GovernanceProposalTarget::RegistryEntry(subject_entry.clone()),
            GovernanceProposalTarget::GlobalRuntimePosture,
        ];
    }

    let mut seen = BTreeSet::new();
    let mut targets = Vec::new();
    let mut push_entry = |entry: &CapabilityRegistryEntry| {
        if seen.insert(entry.entry_id.clone()) {
            targets.push(GovernanceProposalTarget::RegistryEntry(entry.clone()));
        }
    };

    let entry_lookup = snapshot
        .entries
        .iter()
        .map(|entry| (entry.entry_id.as_str(), entry))
        .collect::<BTreeMap<_, _>>();

    if subject_entry.kind != "filesystem_skill" {
        push_entry(subject_entry);
    }

    if let Some(entry) = comparison_entry {
        if entry_can_govern_subject(subject_entry, entry) {
            push_entry(entry);
        }
    }

    let mut candidate_ids = subject_entry
        .related_governing_entry_ids
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();

    if let Some(entry) = comparison_entry {
        candidate_ids.extend(entry.related_governing_entry_ids.iter().cloned());
    }

    if let Some(family_id) = subject_entry.governing_family_id.as_deref() {
        for candidate in &snapshot.entries {
            if candidate.entry_id == subject_entry.entry_id
                || !entry_can_govern_subject(subject_entry, candidate)
            {
                continue;
            }
            if candidate.governing_family_id.as_deref() == Some(family_id) {
                candidate_ids.insert(candidate.entry_id.clone());
            }
        }
    } else {
        for candidate in &snapshot.entries {
            if candidate.entry_id == subject_entry.entry_id
                || !entry_can_govern_subject(subject_entry, candidate)
            {
                continue;
            }
            if shares_governing_provenance(subject_entry, candidate) {
                candidate_ids.insert(candidate.entry_id.clone());
            }
        }
    }

    for candidate_id in candidate_ids {
        if let Some(candidate) = entry_lookup.get(candidate_id.as_str()) {
            if entry_can_govern_subject(subject_entry, candidate) {
                push_entry(candidate);
            }
        }
    }

    targets.push(GovernanceProposalTarget::GlobalRuntimePosture);

    targets
}

fn plan_capability_governance_request_from_snapshot(
    snapshot: &CapabilityRegistrySnapshot,
    policy_state: &connectors::ShieldPolicyState,
    input: CapabilityGovernanceRequestPlanInput,
) -> Result<CapabilityGovernanceRequest, String> {
    let capability_entry_id = input.capability_entry_id.trim();
    if capability_entry_id.is_empty() {
        return Err("Capability entry id is required.".to_string());
    }

    let subject_entry = snapshot
        .entries
        .iter()
        .find(|entry| entry.entry_id == capability_entry_id)
        .cloned()
        .ok_or_else(|| {
            format!(
                "Capability entry {} is no longer present in the runtime registry.",
                capability_entry_id
            )
        })?;
    let governing_entry = input
        .governing_entry_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|governing_entry_id| {
            snapshot
                .entries
                .iter()
                .find(|entry| entry.entry_id == governing_entry_id)
                .cloned()
                .ok_or_else(|| {
                    format!(
                        "Governing entry {} is no longer present in the runtime registry.",
                        governing_entry_id
                    )
                })
        })
        .transpose()?
        .unwrap_or_else(|| subject_entry.clone());

    let created_at_ms = Utc::now().timestamp_millis().max(0) as u64;
    let request_id = input
        .request_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .unwrap_or_else(|| {
            format!(
                "{}:{}:{}:{}",
                subject_entry.entry_id,
                governing_entry.entry_id,
                action_key(&input.action),
                created_at_ms
            )
        });
    let (connector_id, connector_label, is_global_target) =
        resolve_connector_target(&input, &governing_entry, snapshot);
    let effective_policy = if is_global_target {
        policy_state.global.clone()
    } else {
        effective_connector_policy_defaults(policy_state, &connector_id)
    };

    let requested_state = if is_global_target {
        connectors::ShieldPolicyState {
            version: policy_state.version,
            global: match input.action {
                CapabilityGovernanceRequestAction::Baseline => {
                    build_baseline_global_policy_defaults(&policy_state.global, &governing_entry)
                }
                CapabilityGovernanceRequestAction::Widen => {
                    build_widened_global_policy_defaults(&policy_state.global, &governing_entry)
                }
            },
            overrides: policy_state.overrides.clone(),
        }
    } else {
        let mut next_state = policy_state.clone();
        match input.action {
            CapabilityGovernanceRequestAction::Baseline => {
                next_state.overrides.remove(&connector_id);
            }
            CapabilityGovernanceRequestAction::Widen => {
                next_state.overrides.insert(
                    connector_id.clone(),
                    build_widened_connector_policy(&effective_policy, &governing_entry),
                );
            }
        }
        next_state
    };
    let authority_target_label = governing_entry
        .authority
        .governed_profile_label
        .as_deref()
        .unwrap_or(governing_entry.authority.tier_label.as_str());
    let targets_same_entry = governing_entry.entry_id == subject_entry.entry_id;

    let headline = if is_global_target {
        match input.action {
            CapabilityGovernanceRequestAction::Baseline => {
                format!(
                    "Return {} to the shipped runtime baseline",
                    subject_entry.label
                )
            }
            CapabilityGovernanceRequestAction::Widen => {
                if targets_same_entry {
                    format!("Request wider lease for {}", subject_entry.label)
                } else {
                    format!(
                        "Request wider lease for {} via {}",
                        subject_entry.label, governing_entry.label
                    )
                }
            }
        }
    } else {
        match input.action {
            CapabilityGovernanceRequestAction::Baseline => {
                format!("Return {} to the global baseline", connector_label)
            }
            CapabilityGovernanceRequestAction::Widen => {
                format!("Request wider lease for {}", connector_label)
            }
        }
    };
    let detail = if is_global_target {
        match input.action {
            CapabilityGovernanceRequestAction::Baseline => format!(
                "Preview the global runtime posture after returning {} to the shipped baseline for its governing authority class.",
                subject_entry.label
            ),
            CapabilityGovernanceRequestAction::Widen => {
                if targets_same_entry {
                    format!(
                        "Preview the global runtime posture needed to widen {} toward {} before persisting the change.",
                        subject_entry.label, authority_target_label
                    )
                } else {
                    format!(
                        "Preview the global runtime posture needed to widen {} through {} so the runtime can borrow the narrowest matching authority class ({}) before persisting the change.",
                        subject_entry.label, governing_entry.label, authority_target_label
                    )
                }
            }
        }
    } else {
        match input.action {
            CapabilityGovernanceRequestAction::Baseline => format!(
                "Preview the effective posture after removing the connector-specific override that currently governs {}.",
                subject_entry.label
            ),
            CapabilityGovernanceRequestAction::Widen => format!(
                "Preview the connector-specific override needed to widen {} toward {} without persisting the change yet.",
                subject_entry.label, authority_target_label
            ),
        }
    };

    Ok(CapabilityGovernanceRequest {
        request_id,
        created_at_ms,
        status: "pending".to_string(),
        action: input.action,
        capability_entry_id: subject_entry.entry_id,
        capability_label: subject_entry.label,
        capability_kind: subject_entry.kind,
        governing_entry_id: Some(governing_entry.entry_id),
        governing_label: Some(governing_entry.label),
        governing_kind: Some(governing_entry.kind),
        connector_id,
        connector_label,
        source_label: subject_entry.source_label,
        authority_tier_label: subject_entry.authority.tier_label,
        governed_profile_label: subject_entry.authority.governed_profile_label,
        lease_mode_label: subject_entry
            .lease
            .mode_label
            .or_else(|| Some(subject_entry.lease.availability_label)),
        why_selectable: subject_entry.why_selectable,
        headline,
        detail,
        requested_state,
    })
}

fn plan_capability_governance_proposal_from_snapshot(
    snapshot: &CapabilityRegistrySnapshot,
    policy_state: &connectors::ShieldPolicyState,
    input: CapabilityGovernanceProposalInput,
) -> Result<CapabilityGovernanceProposal, String> {
    let capability_entry_id = input.capability_entry_id.trim();
    if capability_entry_id.is_empty() {
        return Err("Capability entry id is required.".to_string());
    }

    let subject_entry = snapshot
        .entries
        .iter()
        .find(|entry| entry.entry_id == capability_entry_id)
        .cloned()
        .ok_or_else(|| {
            format!(
                "Capability entry {} is no longer present in the runtime registry.",
                capability_entry_id
            )
        })?;
    let compared_entry = input
        .comparison_entry_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|entry_id| {
            snapshot
                .entries
                .iter()
                .find(|entry| entry.entry_id == entry_id)
                .cloned()
                .ok_or_else(|| {
                    format!(
                        "Comparison entry {} is no longer present in the runtime registry.",
                        entry_id
                    )
                })
        })
        .transpose()?;
    let compared_entry_id_value = compared_entry.as_ref().map(|entry| entry.entry_id.clone());
    let compared_entry_label_value = compared_entry.as_ref().map(|entry| entry.label.clone());

    let compared_entry_id = compared_entry.as_ref().map(|entry| entry.entry_id.as_str());
    let compared_entry_label = compared_entry.as_ref().map(|entry| entry.label.as_str());
    let mut targets = collect_governance_targets(&subject_entry, compared_entry.as_ref(), snapshot)
        .into_iter()
        .map(|target| {
            let (target_entry_id, target_label, target_kind, plan_input) = match &target {
                GovernanceProposalTarget::RegistryEntry(entry) => (
                    entry.entry_id.clone(),
                    entry.label.clone(),
                    entry.kind.clone(),
                    CapabilityGovernanceRequestPlanInput {
                        request_id: None,
                        capability_entry_id: subject_entry.entry_id.clone(),
                        action: input.action.clone(),
                        governing_entry_id: Some(entry.entry_id.clone()),
                        connector_id: None,
                        connector_label: None,
                    },
                ),
                GovernanceProposalTarget::GlobalRuntimePosture => (
                    "policy_target:global".to_string(),
                    "Global runtime posture".to_string(),
                    "policy_target".to_string(),
                    CapabilityGovernanceRequestPlanInput {
                        request_id: None,
                        capability_entry_id: subject_entry.entry_id.clone(),
                        action: input.action.clone(),
                        governing_entry_id: Some(subject_entry.entry_id.clone()),
                        connector_id: Some("global".to_string()),
                        connector_label: Some("Global runtime posture".to_string()),
                    },
                ),
            };
            let request = plan_capability_governance_request_from_snapshot(
                snapshot,
                policy_state,
                plan_input,
            )?;
            let current_policy = if request.connector_id == "global" {
                policy_state.global.clone()
            } else {
                effective_connector_policy_defaults(policy_state, &request.connector_id)
            };
            let next_policy = requested_policy_defaults(&request);
            let delta_magnitude = policy_change_magnitude(&current_policy, &next_policy);
            let option = CapabilityGovernanceTargetOption {
                target_entry_id,
                target_label,
                target_kind,
                target_summary: governance_target_summary(&target),
                recommendation_reason: governance_target_reason(
                    &subject_entry,
                    &target,
                    compared_entry_id,
                    compared_entry_label,
                ),
                delta_summary: policy_delta_summary(&current_policy, &next_policy),
                request,
                delta_magnitude,
            };
            Ok((
                option,
                governance_target_specificity_rank(&target),
                governance_target_relation_rank(&subject_entry, &target, compared_entry_id),
            ))
        })
        .collect::<Result<Vec<_>, String>>()?;

    targets.sort_by(
        |(left, left_specificity, left_relation), (right, right_specificity, right_relation)| {
            left.delta_magnitude
                .cmp(&right.delta_magnitude)
                .then_with(|| left_specificity.cmp(right_specificity))
                .then_with(|| left_relation.cmp(right_relation))
                .then_with(|| left.target_label.cmp(&right.target_label))
        },
    );

    let recommended_target_entry_id = targets
        .first()
        .map(|(option, _, _)| option.target_entry_id.clone())
        .unwrap_or_else(|| subject_entry.entry_id.clone());

    Ok(CapabilityGovernanceProposal {
        capability_entry_id: subject_entry.entry_id,
        capability_label: subject_entry.label,
        action: input.action,
        recommended_target_entry_id,
        targets: targets.into_iter().map(|(option, _, _)| option).collect(),
        compared_entry_id: compared_entry_id_value,
        compared_entry_label: compared_entry_label_value,
    })
}

async fn capability_registry_snapshot_inner(
    state: State<'_, Mutex<AppState>>,
    policy_manager: &connectors::ShieldPolicyManager,
) -> Result<CapabilityRegistrySnapshot, String> {
    let connectors = connectors::connector_list_catalog(state.clone()).await?;
    let skill_catalog = data::get_skill_catalog(state.clone()).await?;
    let skill_sources = skill_sources::get_skill_sources(state.clone()).await?;
    let extension_manifests = skill_sources::get_extension_manifests(state.clone()).await?;
    let local_engine = data::get_local_engine_snapshot(state).await?;
    let default_model_id = local_engine
        .control_plane
        .runtime
        .default_model
        .trim()
        .to_string();
    let default_model_id = if default_model_id.is_empty() || default_model_id == "none" {
        None
    } else {
        Some(default_model_id)
    };
    let default_backend_id = default_model_id
        .as_deref()
        .and_then(|default_model_id| {
            local_engine
                .registry_models
                .iter()
                .find(|record| record.model_id == default_model_id)
                .and_then(|record| record.backend_id.clone())
        })
        .or_else(|| {
            if local_engine.managed_backends.len() == 1 {
                local_engine
                    .managed_backends
                    .first()
                    .map(|record| record.backend_id.clone())
            } else {
                None
            }
        });

    let generated_at_ms = Utc::now().timestamp_millis().max(0) as u64;
    let mut entries = Vec::new();
    entries.extend(
        connectors
            .iter()
            .map(|connector| connector_entry(connector, policy_manager)),
    );
    entries.extend(skill_catalog.iter().map(skill_entry));
    entries.extend(skill_sources.iter().map(skill_source_entry));
    entries.extend(skill_sources.iter().flat_map(|source| {
        source
            .discovered_skills
            .iter()
            .map(move |skill| source_backed_filesystem_skill_entry(source, skill))
    }));
    entries.extend(extension_manifests.iter().map(extension_entry));
    entries.extend(extension_manifests.iter().flat_map(|manifest| {
        manifest
            .filesystem_skills
            .iter()
            .map(move |skill| extension_backed_filesystem_skill_entry(manifest, skill))
    }));
    entries.extend(
        local_engine
            .registry_models
            .iter()
            .map(|model| model_entry(model, default_model_id.as_deref())),
    );
    entries.extend(
        local_engine
            .managed_backends
            .iter()
            .map(|backend| backend_entry(backend, default_backend_id.as_deref())),
    );
    if local_engine.managed_backends.is_empty() {
        if let Some(runtime_backend_entry) =
            runtime_profile_backend_entry(&local_engine.control_plane.runtime)
        {
            entries.push(runtime_backend_entry);
        }
    }
    if local_engine.registry_models.is_empty() {
        let backend_slug = if local_engine.managed_backends.is_empty() {
            runtime_profile_backend_slug(&local_engine.control_plane.runtime)
        } else {
            default_backend_id
                .as_deref()
                .and_then(normalize_governing_token)
        };
        if let Some(runtime_model_entry) = runtime_profile_model_entry(
            &local_engine.control_plane.runtime,
            backend_slug.as_deref(),
        ) {
            entries.push(runtime_model_entry);
        }
    }
    entries.extend(local_engine.capabilities.iter().map(family_entry));
    entries.push(lsp::capability_registry_entry());
    entries.sort_by(|left, right| {
        left.kind
            .cmp(&right.kind)
            .then_with(|| left.label.cmp(&right.label))
            .then_with(|| left.entry_id.cmp(&right.entry_id))
    });
    annotate_governing_relationships(&mut entries);

    let summary = CapabilityRegistrySummary {
        generated_at_ms,
        total_entries: entries.len(),
        connector_count: connectors.len(),
        connected_connector_count: connectors
            .iter()
            .filter(|connector| connector.status == "connected")
            .count(),
        runtime_skill_count: skill_catalog.len(),
        tracked_source_count: skill_sources.len(),
        filesystem_skill_count: filesystem_skill_count(&skill_sources, &extension_manifests),
        extension_count: extension_manifests.len(),
        model_count: entries.iter().filter(|entry| entry.kind == "model").count(),
        backend_count: entries
            .iter()
            .filter(|entry| entry.kind == "backend")
            .count(),
        native_family_count: entries
            .iter()
            .filter(|entry| entry.kind == "native_family")
            .count(),
        pending_engine_control_count: local_engine.pending_control_count,
        active_issue_count: local_engine.active_issue_count,
        authoritative_source_count: authoritative_source_count(
            &entries,
            !connectors.is_empty(),
            !skill_catalog.is_empty(),
            true,
        ),
    };

    Ok(CapabilityRegistrySnapshot {
        generated_at_ms,
        summary,
        entries,
        connectors,
        skill_catalog,
        skill_sources,
        extension_manifests,
        local_engine,
    })
}

#[tauri::command]
pub async fn plan_capability_governance_request(
    state: State<'_, Mutex<AppState>>,
    policy_manager: State<'_, connectors::ShieldPolicyManager>,
    input: CapabilityGovernanceRequestPlanInput,
) -> Result<CapabilityGovernanceRequest, String> {
    let policy_state = policy_manager.current_state();
    let snapshot = capability_registry_snapshot_inner(state, policy_manager.inner()).await?;
    plan_capability_governance_request_from_snapshot(&snapshot, &policy_state, input)
}

#[tauri::command]
pub async fn plan_capability_governance_proposal(
    state: State<'_, Mutex<AppState>>,
    policy_manager: State<'_, connectors::ShieldPolicyManager>,
    input: CapabilityGovernanceProposalInput,
) -> Result<CapabilityGovernanceProposal, String> {
    let policy_state = policy_manager.current_state();
    let snapshot = capability_registry_snapshot_inner(state, policy_manager.inner()).await?;
    plan_capability_governance_proposal_from_snapshot(&snapshot, &policy_state, input)
}

#[tauri::command]
pub fn get_capability_governance_request(
    state: State<'_, Mutex<AppState>>,
) -> Result<Option<CapabilityGovernanceRequest>, String> {
    let state = state
        .lock()
        .map_err(|_| "App state is unavailable.".to_string())?;
    Ok(state.capability_governance_request.clone())
}

#[tauri::command]
pub fn set_capability_governance_request(
    app: tauri::AppHandle,
    state: State<'_, Mutex<AppState>>,
    request: CapabilityGovernanceRequest,
) -> Result<CapabilityGovernanceRequest, String> {
    let next_request = {
        let mut state = state
            .lock()
            .map_err(|_| "App state is unavailable.".to_string())?;
        state.capability_governance_request = Some(request.clone());
        state.capability_governance_request.clone()
    };

    emit_capability_governance_request(&app, &next_request);
    Ok(request)
}

#[tauri::command]
pub fn clear_capability_governance_request(
    app: tauri::AppHandle,
    state: State<'_, Mutex<AppState>>,
) -> Result<(), String> {
    {
        let mut state = state
            .lock()
            .map_err(|_| "App state is unavailable.".to_string())?;
        state.capability_governance_request = None;
    }

    emit_capability_governance_request(&app, &None);
    Ok(())
}

#[tauri::command]
pub async fn get_capability_registry_snapshot(
    state: State<'_, Mutex<AppState>>,
    policy_manager: State<'_, connectors::ShieldPolicyManager>,
) -> Result<CapabilityRegistrySnapshot, String> {
    capability_registry_snapshot_inner(state, policy_manager.inner()).await
}

#[cfg(test)]
#[path = "capabilities/tests.rs"]
mod tests;
