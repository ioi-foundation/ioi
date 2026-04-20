use super::*;
use crate::models::{
    CapabilityRegistrySummary, LocalEngineApiConfig, LocalEngineBackendPolicyConfig,
    LocalEngineControlPlane, LocalEngineMemoryConfig, LocalEngineResponseConfig,
    LocalEngineRuntimeProfile, LocalEngineSnapshot, LocalEngineStorageConfig,
    LocalEngineWatchdogConfig, SkillSourceDiscoveredSkill,
};

fn test_entry(
    entry_id: &str,
    kind: &str,
    label: &str,
    source_uri: Option<&str>,
) -> CapabilityRegistryEntry {
    CapabilityRegistryEntry {
        entry_id: entry_id.to_string(),
        kind: kind.to_string(),
        label: label.to_string(),
        summary: format!("{label} summary"),
        source_kind: "test".to_string(),
        source_label: "Test source".to_string(),
        source_uri: source_uri.map(ToString::to_string),
        trust_posture: "contained_local".to_string(),
        governed_profile: Some("local_skill_bundle".to_string()),
        availability: "ready".to_string(),
        status_label: "Ready".to_string(),
        why_selectable: format!("{label} is selectable."),
        governing_family_id: None,
        related_governing_entry_ids: Vec::new(),
        governing_family_hints: Vec::new(),
        runtime_target: Some("local_manifest".to_string()),
        lease_mode: Some("governed_extension".to_string()),
        authority: build_authority(
            "contained_local",
            "Contained local",
            Some("local_skill_bundle"),
            "Contained local authority",
            "Contained local authority detail",
            vec!["Test signal".to_string()],
        ),
        lease: build_lease(
            "ready".to_string(),
            Some("local_manifest"),
            Some("governed_extension"),
            "Ready for test execution",
            "Ready for test execution detail",
            false,
            vec!["Ready signal".to_string()],
        ),
    }
}

fn test_entry_with_hints(
    entry_id: &str,
    kind: &str,
    label: &str,
    source_uri: Option<&str>,
    governing_family_hints: &[&str],
) -> CapabilityRegistryEntry {
    let mut entry = test_entry(entry_id, kind, label, source_uri);
    entry.governing_family_hints = governing_family_hints
        .iter()
        .map(|hint| hint.to_string())
        .collect();
    entry
}

fn empty_local_engine_snapshot() -> LocalEngineSnapshot {
    LocalEngineSnapshot {
        generated_at_ms: 0,
        total_native_tools: 0,
        pending_control_count: 0,
        pending_approval_count: 0,
        active_issue_count: 0,
        capabilities: Vec::new(),
        compatibility_routes: Vec::new(),
        pending_controls: Vec::new(),
        jobs: Vec::new(),
        recent_activity: Vec::new(),
        registry_models: Vec::new(),
        managed_backends: Vec::new(),
        gallery_catalogs: Vec::new(),
        worker_templates: Vec::new(),
        agent_playbooks: Vec::new(),
        parent_playbook_runs: Vec::new(),
        control_plane_schema_version: 1,
        control_plane_profile_id: "test".to_string(),
        control_plane_migrations: Vec::new(),
        control_plane: LocalEngineControlPlane {
            runtime: LocalEngineRuntimeProfile {
                mode: "test".to_string(),
                endpoint: "local".to_string(),
                default_model: "none".to_string(),
                baseline_role: "operator".to_string(),
                kernel_authority: "contained_local".to_string(),
            },
            storage: LocalEngineStorageConfig {
                models_path: String::new(),
                backends_path: String::new(),
                artifacts_path: String::new(),
                cache_path: String::new(),
            },
            watchdog: LocalEngineWatchdogConfig {
                enabled: false,
                idle_check_enabled: false,
                idle_timeout: String::new(),
                busy_check_enabled: false,
                busy_timeout: String::new(),
                check_interval: String::new(),
                force_eviction_when_busy: false,
                lru_eviction_max_retries: 0,
                lru_eviction_retry_interval: String::new(),
            },
            memory: LocalEngineMemoryConfig {
                reclaimer_enabled: false,
                threshold_percent: 0,
                prefer_gpu: false,
                target_resource: "cpu".to_string(),
            },
            backend_policy: LocalEngineBackendPolicyConfig {
                max_concurrency: 0,
                max_queued_requests: 0,
                parallel_backend_loads: 0,
                allow_parallel_requests: false,
                health_probe_interval: String::new(),
                log_level: "info".to_string(),
                auto_shutdown_on_idle: false,
            },
            responses: LocalEngineResponseConfig {
                retain_receipts_days: 0,
                persist_artifacts: false,
                allow_streaming: false,
                store_request_previews: false,
            },
            api: LocalEngineApiConfig {
                bind_address: "127.0.0.1:0".to_string(),
                remote_access_enabled: false,
                expose_compat_routes: false,
                cors_mode: "deny".to_string(),
                auth_mode: "disabled".to_string(),
            },
            launcher: Default::default(),
            galleries: Vec::new(),
            environment: Vec::new(),
            notes: Vec::new(),
        },
        managed_settings: crate::models::LocalEngineManagedSettingsSnapshot {
            sync_status: "local_only".to_string(),
            summary: "No managed settings active.".to_string(),
            ..Default::default()
        },
        staged_operations: Vec::new(),
    }
}

fn test_extension_manifest(
    capabilities: &[&str],
    contributions: &[&str],
    filesystem_skills: &[&str],
) -> ExtensionManifestRecord {
    ExtensionManifestRecord {
        extension_id: "manifest:test-extension".to_string(),
        manifest_kind: "codex_plugin".to_string(),
        manifest_path: "/tmp/governed/family/extension-alpha/.codex-plugin/plugin.json".to_string(),
        root_path: "/tmp/governed/family/extension-alpha".to_string(),
        source_label: "Test source".to_string(),
        source_uri: "/tmp/governed/family".to_string(),
        source_kind: "tracked_source".to_string(),
        enabled: true,
        name: "test-extension".to_string(),
        display_name: Some("Test Extension".to_string()),
        version: Some("1.0.0".to_string()),
        description: Some("Test manifest".to_string()),
        developer_name: None,
        author_name: None,
        author_email: None,
        author_url: None,
        category: None,
        trust_posture: "local_only".to_string(),
        governed_profile: "local_skill_bundle".to_string(),
        homepage: None,
        repository: None,
        license: None,
        keywords: Vec::new(),
        capabilities: capabilities
            .iter()
            .map(|value| (*value).to_string())
            .collect(),
        default_prompts: Vec::new(),
        contributions: contributions
            .iter()
            .map(|kind| ExtensionContributionRecord {
                kind: (*kind).to_string(),
                label: humanize(kind),
                path: Some(format!("{kind}/")),
                item_count: Some(1),
                detail: Some(format!("{kind} contribution")),
            })
            .collect(),
        filesystem_skills: filesystem_skills
            .iter()
            .map(|relative_path| SkillSourceDiscoveredSkill {
                name: format!("Skill {}", relative_path),
                description: None,
                relative_path: (*relative_path).to_string(),
            })
            .collect(),
        marketplace_name: None,
        marketplace_display_name: None,
        marketplace_category: None,
        marketplace_installation_policy: None,
        marketplace_authentication_policy: None,
        marketplace_products: Vec::new(),
        marketplace_available_version: None,
        marketplace_catalog_issued_at_ms: None,
        marketplace_catalog_expires_at_ms: None,
        marketplace_catalog_refreshed_at_ms: None,
        marketplace_catalog_refresh_source: None,
        marketplace_catalog_channel: None,
        marketplace_catalog_source_id: None,
        marketplace_catalog_source_label: None,
        marketplace_catalog_source_uri: None,
        marketplace_package_url: None,
        marketplace_catalog_refresh_bundle_id: None,
        marketplace_catalog_refresh_bundle_label: None,
        marketplace_catalog_refresh_bundle_issued_at_ms: None,
        marketplace_catalog_refresh_bundle_expires_at_ms: None,
        marketplace_catalog_refresh_available_version: None,
        marketplace_verification_status: None,
        marketplace_signature_algorithm: None,
        marketplace_signer_identity: None,
        marketplace_publisher_id: None,
        marketplace_signing_key_id: None,
        marketplace_publisher_label: None,
        marketplace_publisher_trust_status: None,
        marketplace_publisher_trust_source: None,
        marketplace_publisher_root_id: None,
        marketplace_publisher_root_label: None,
        marketplace_authority_bundle_id: None,
        marketplace_authority_bundle_label: None,
        marketplace_authority_bundle_issued_at_ms: None,
        marketplace_authority_trust_bundle_id: None,
        marketplace_authority_trust_bundle_label: None,
        marketplace_authority_trust_bundle_issued_at_ms: None,
        marketplace_authority_trust_bundle_expires_at_ms: None,
        marketplace_authority_trust_bundle_status: None,
        marketplace_authority_trust_issuer_id: None,
        marketplace_authority_trust_issuer_label: None,
        marketplace_authority_id: None,
        marketplace_authority_label: None,
        marketplace_publisher_statement_issued_at_ms: None,
        marketplace_publisher_trust_detail: None,
        marketplace_publisher_revoked_at_ms: None,
        marketplace_verification_error: None,
        marketplace_verified_at_ms: None,
        marketplace_verification_source: None,
        marketplace_verified_digest_sha256: None,
        marketplace_trust_score_label: None,
        marketplace_trust_score_source: None,
        marketplace_trust_recommendation: None,
    }
}

fn test_runtime_profile() -> LocalEngineRuntimeProfile {
    LocalEngineRuntimeProfile {
        mode: "http_local_dev".to_string(),
        endpoint: "http://127.0.0.1:11434/api/tags".to_string(),
        default_model: "qwen2.5:7b".to_string(),
        baseline_role: "Test baseline".to_string(),
        kernel_authority: "Kernel test authority".to_string(),
    }
}

fn test_snapshot(entries: Vec<CapabilityRegistryEntry>) -> CapabilityRegistrySnapshot {
    CapabilityRegistrySnapshot {
        generated_at_ms: 0,
        summary: CapabilityRegistrySummary {
            generated_at_ms: 0,
            total_entries: entries.len(),
            connector_count: 0,
            connected_connector_count: 0,
            runtime_skill_count: 0,
            tracked_source_count: 0,
            filesystem_skill_count: 0,
            extension_count: entries
                .iter()
                .filter(|entry| entry.kind == "extension")
                .count(),
            model_count: 0,
            backend_count: 0,
            native_family_count: 0,
            pending_engine_control_count: 0,
            active_issue_count: 0,
            authoritative_source_count: 0,
        },
        entries,
        connectors: Vec::new(),
        skill_catalog: Vec::new(),
        skill_sources: Vec::new(),
        extension_manifests: Vec::new(),
        local_engine: empty_local_engine_snapshot(),
    }
}

fn target_ids(targets: &[GovernanceProposalTarget]) -> Vec<String> {
    targets
        .iter()
        .map(|target| match target {
            GovernanceProposalTarget::RegistryEntry(entry) => entry.entry_id.clone(),
            GovernanceProposalTarget::GlobalRuntimePosture => "policy_target:global".to_string(),
        })
        .collect()
}

#[test]
fn annotate_governing_relationships_groups_shared_source_roots() {
    let mut entries = vec![
        test_entry(
            "extension:alpha",
            "extension",
            "Alpha Extension",
            Some("/tmp/governed/family"),
        ),
        test_entry(
            "skill_source:alpha",
            "skill_source",
            "Alpha Source",
            Some("/tmp/governed/family/"),
        ),
        test_entry(
            "skill_source:other",
            "skill_source",
            "Other Source",
            Some("/tmp/other"),
        ),
    ];

    annotate_governing_relationships(&mut entries);

    let extension = entries
        .iter()
        .find(|entry| entry.entry_id == "extension:alpha")
        .expect("extension entry");
    let source = entries
        .iter()
        .find(|entry| entry.entry_id == "skill_source:alpha")
        .expect("source entry");
    let other = entries
        .iter()
        .find(|entry| entry.entry_id == "skill_source:other")
        .expect("other entry");

    assert_eq!(
        extension.governing_family_id.as_deref(),
        Some("source-root:/tmp/governed/family")
    );
    assert_eq!(
        extension.related_governing_entry_ids,
        vec!["skill_source:alpha"]
    );
    assert_eq!(source.related_governing_entry_ids, vec!["extension:alpha"]);
    assert_eq!(
        other.governing_family_id.as_deref(),
        Some("source-root:/tmp/other")
    );
    assert!(other.related_governing_entry_ids.is_empty());
}

#[test]
fn proposal_targets_include_related_family_entries_and_global_fallback() {
    let mut entries = vec![
        test_entry(
            "extension:alpha",
            "extension",
            "Alpha Extension",
            Some("/tmp/governed/family"),
        ),
        test_entry(
            "skill_source:alpha",
            "skill_source",
            "Alpha Source",
            Some("/tmp/governed/family"),
        ),
        test_entry(
            "extension:beta",
            "extension",
            "Beta Extension",
            Some("/tmp/governed/family"),
        ),
        test_entry("skill:loose", "skill", "Loose Skill", None),
    ];
    annotate_governing_relationships(&mut entries);
    let snapshot = test_snapshot(entries);
    let subject = snapshot
        .entries
        .iter()
        .find(|entry| entry.entry_id == "extension:alpha")
        .expect("subject entry")
        .clone();

    let targets = collect_governance_targets(&subject, None, &snapshot);
    let ids = target_ids(&targets);

    assert_eq!(ids.first().map(String::as_str), Some("extension:alpha"));
    assert!(ids.contains(&"skill_source:alpha".to_string()));
    assert!(ids.contains(&"extension:beta".to_string()));
    assert_eq!(ids.last().map(String::as_str), Some("policy_target:global"));
}

#[test]
fn proposal_reason_uses_explicit_governing_family_language() {
    let mut entries = vec![
        test_entry(
            "extension:alpha",
            "extension",
            "Alpha Extension",
            Some("/tmp/governed/family"),
        ),
        test_entry(
            "skill_source:alpha",
            "skill_source",
            "Alpha Source",
            Some("/tmp/governed/family"),
        ),
    ];
    annotate_governing_relationships(&mut entries);
    let snapshot = test_snapshot(entries);

    let proposal = plan_capability_governance_proposal_from_snapshot(
        &snapshot,
        &connectors::ShieldPolicyState::default(),
        CapabilityGovernanceProposalInput {
            capability_entry_id: "extension:alpha".to_string(),
            action: CapabilityGovernanceRequestAction::Widen,
            comparison_entry_id: None,
        },
    )
    .expect("proposal");

    let related_target = proposal
        .targets
        .iter()
        .find(|target| target.target_entry_id == "skill_source:alpha")
        .expect("related family target");

    assert!(related_target
        .recommendation_reason
        .contains("same governing family"));
    assert_eq!(proposal.recommended_target_entry_id, "extension:alpha");
}

#[test]
fn proposal_targets_include_native_family_related_by_capability_hints() {
    let mut entries = vec![
        test_entry_with_hints(
            "extension:alpha",
            "extension",
            "Alpha Extension",
            Some("/tmp/governed/family"),
            &[
                "source-root:/tmp/governed/family",
                "capability:responses",
                "capability:knowledge",
            ],
        ),
        test_entry_with_hints(
            "skill_source:alpha",
            "skill_source",
            "Alpha Source",
            Some("/tmp/governed/family"),
            &["source-root:/tmp/governed/family"],
        ),
        test_entry_with_hints(
            "native_family:responses",
            "native_family",
            "Responses",
            None,
            &["native-family:responses", "capability:responses"],
        ),
        test_entry_with_hints(
            "native_family:knowledge",
            "native_family",
            "Knowledge",
            None,
            &["native-family:knowledge", "capability:knowledge"],
        ),
    ];
    annotate_governing_relationships(&mut entries);
    let snapshot = test_snapshot(entries);
    let subject = snapshot
        .entries
        .iter()
        .find(|entry| entry.entry_id == "extension:alpha")
        .expect("subject entry")
        .clone();

    let targets = collect_governance_targets(&subject, None, &snapshot);
    let ids = target_ids(&targets);

    assert!(ids.contains(&"skill_source:alpha".to_string()));
    assert!(ids.contains(&"native_family:responses".to_string()));
    assert!(ids.contains(&"native_family:knowledge".to_string()));
    assert_eq!(ids.last().map(String::as_str), Some("policy_target:global"));
}

#[test]
fn extension_entry_maps_manifest_capability_aliases_to_native_families() {
    let entry = extension_entry(&test_extension_manifest(
        &["Interactive", "Knowledge"],
        &[],
        &[],
    ));

    assert!(entry
        .governing_family_hints
        .contains(&"capability:interactive".to_string()));
    assert!(entry
        .governing_family_hints
        .contains(&"capability:responses".to_string()));
    assert!(entry
        .governing_family_hints
        .contains(&"native-family:responses".to_string()));
    assert!(entry
        .governing_family_hints
        .contains(&"capability:knowledge".to_string()));
    assert!(entry
        .governing_family_hints
        .contains(&"native-family:knowledge".to_string()));
}

#[test]
fn extension_entry_maps_runtime_bridge_contributions_to_workers_family() {
    let entry = extension_entry(&test_extension_manifest(
        &[],
        &["hooks"],
        &["skills/a/SKILL.md"],
    ));

    assert!(entry
        .governing_family_hints
        .contains(&"contribution-kind:hooks".to_string()));
    assert!(entry
        .governing_family_hints
        .contains(&"capability:workers".to_string()));
    assert!(entry
        .governing_family_hints
        .contains(&"native-family:workers".to_string()));
}

#[test]
fn default_runtime_model_and_backend_join_responses_family() {
    let model = model_entry(
        &LocalEngineModelRecord {
            model_id: "qwen2.5:7b".to_string(),
            status: "ready".to_string(),
            residency: "local".to_string(),
            installed_at_ms: 0,
            updated_at_ms: 0,
            source_uri: Some("http://127.0.0.1:11434/api/tags".to_string()),
            backend_id: Some("ollama-openai-dev-runtime".to_string()),
            hardware_profile: None,
            job_id: None,
            bytes_transferred: None,
        },
        Some("qwen2.5:7b"),
    );
    let backend = backend_entry(
        &LocalEngineBackendRecord {
            backend_id: "ollama-openai-dev-runtime".to_string(),
            status: "ready".to_string(),
            health: "healthy".to_string(),
            installed_at_ms: 0,
            updated_at_ms: 0,
            source_uri: Some("http://127.0.0.1:11434/api/tags".to_string()),
            alias: Some("Ollama OpenAI Dev Runtime".to_string()),
            hardware_profile: None,
            job_id: None,
            install_path: None,
            entrypoint: None,
            health_endpoint: None,
            pid: None,
            last_started_at_ms: None,
            last_health_check_at_ms: None,
        },
        Some("ollama-openai-dev-runtime"),
    );

    assert!(model
        .governing_family_hints
        .contains(&"capability:responses".to_string()));
    assert!(model
        .governing_family_hints
        .contains(&"native-family:responses".to_string()));
    assert!(backend
        .governing_family_hints
        .contains(&"capability:responses".to_string()));
    assert!(backend
        .governing_family_hints
        .contains(&"native-family:responses".to_string()));
}

#[test]
fn runtime_profile_fallback_entries_link_interactive_extension_to_concrete_runtime_members() {
    let runtime = test_runtime_profile();
    let backend = runtime_profile_backend_entry(&runtime).expect("runtime backend entry");
    let backend_slug = backend
        .entry_id
        .strip_prefix("backend:")
        .expect("backend entry prefix")
        .to_string();
    let model =
        runtime_profile_model_entry(&runtime, Some(&backend_slug)).expect("runtime model entry");
    let mut entries = vec![
        extension_entry(&test_extension_manifest(&["Interactive"], &[], &[])),
        backend,
        model,
    ];
    annotate_governing_relationships(&mut entries);

    let extension = entries
        .iter()
        .find(|entry| entry.entry_id == "extension:manifest:test-extension")
        .expect("extension entry");

    assert!(extension
        .related_governing_entry_ids
        .iter()
        .any(|entry_id| entry_id.starts_with("backend:")));
    assert!(extension
        .related_governing_entry_ids
        .contains(&"model:qwen2.5:7b".to_string()));
}

#[test]
fn annotate_governing_relationships_links_filesystem_skills_into_extension_family() {
    let mut entries = vec![
        test_entry_with_hints(
            "extension:alpha",
            "extension",
            "Alpha Extension",
            Some("/tmp/governed/family"),
            &[
                "source-root:/tmp/governed/family",
                "extension-root:/tmp/governed/family/extension-alpha",
                "skill-path:skills/alpha/skill-md",
                "skill-name:alpha-skill",
            ],
        ),
        test_entry_with_hints(
            "skill_source:alpha",
            "skill_source",
            "Alpha Source",
            Some("/tmp/governed/family"),
            &[
                "source-root:/tmp/governed/family",
                "skill-path:skills/alpha/skill-md",
                "skill-name:alpha-skill",
            ],
        ),
        test_entry_with_hints(
            "filesystem_skill:extension:alpha:skills/alpha/SKILL.md",
            "filesystem_skill",
            "Alpha Skill",
            Some("/tmp/governed/family"),
            &[
                "source-root:/tmp/governed/family",
                "extension-root:/tmp/governed/family/extension-alpha",
                "skill-path:skills/alpha/skill-md",
                "skill-name:alpha-skill",
            ],
        ),
    ];

    annotate_governing_relationships(&mut entries);

    let extension = entries
        .iter()
        .find(|entry| entry.entry_id == "extension:alpha")
        .expect("extension entry");

    assert!(extension
        .related_governing_entry_ids
        .contains(&"skill_source:alpha".to_string()));
    assert!(extension
        .related_governing_entry_ids
        .contains(&"filesystem_skill:extension:alpha:skills/alpha/SKILL.md".to_string()));
}

#[test]
fn proposal_targets_skip_filesystem_skills_as_governing_targets() {
    let mut entries = vec![
        test_entry_with_hints(
            "extension:alpha",
            "extension",
            "Alpha Extension",
            Some("/tmp/governed/family"),
            &[
                "source-root:/tmp/governed/family",
                "extension-root:/tmp/governed/family/extension-alpha",
                "skill-path:skills/alpha/skill-md",
                "skill-name:alpha-skill",
            ],
        ),
        test_entry_with_hints(
            "skill_source:alpha",
            "skill_source",
            "Alpha Source",
            Some("/tmp/governed/family"),
            &[
                "source-root:/tmp/governed/family",
                "skill-path:skills/alpha/skill-md",
                "skill-name:alpha-skill",
            ],
        ),
        test_entry_with_hints(
            "filesystem_skill:extension:alpha:skills/alpha/SKILL.md",
            "filesystem_skill",
            "Alpha Skill",
            Some("/tmp/governed/family"),
            &[
                "source-root:/tmp/governed/family",
                "extension-root:/tmp/governed/family/extension-alpha",
                "skill-path:skills/alpha/skill-md",
                "skill-name:alpha-skill",
            ],
        ),
    ];
    annotate_governing_relationships(&mut entries);
    let snapshot = test_snapshot(entries);
    let subject = snapshot
        .entries
        .iter()
        .find(|entry| entry.entry_id == "extension:alpha")
        .expect("subject entry")
        .clone();

    let targets = collect_governance_targets(&subject, None, &snapshot);
    let ids = target_ids(&targets);

    assert!(ids.contains(&"skill_source:alpha".to_string()));
    assert!(!ids.contains(&"filesystem_skill:extension:alpha:skills/alpha/SKILL.md".to_string()));
}

#[test]
fn proposal_targets_include_backend_family_links_for_models() {
    let mut entries = vec![
        test_entry_with_hints(
            "model:phi",
            "model",
            "phi",
            Some("/tmp/runtime/models"),
            &[
                "native-family:model-registry",
                "capability:model-registry",
                "backend:ollama-openai-dev-runtime",
            ],
        ),
        test_entry_with_hints(
            "backend:ollama-openai-dev-runtime",
            "backend",
            "Ollama OpenAI Dev Runtime",
            Some("/tmp/runtime/backends"),
            &[
                "backend:ollama-openai-dev-runtime",
                "native-family:backends",
                "capability:backends",
            ],
        ),
        test_entry_with_hints(
            "native_family:model-registry",
            "native_family",
            "Model Registry",
            None,
            &["native-family:model-registry", "capability:model-registry"],
        ),
    ];
    annotate_governing_relationships(&mut entries);
    let snapshot = test_snapshot(entries);
    let subject = snapshot
        .entries
        .iter()
        .find(|entry| entry.entry_id == "model:phi")
        .expect("subject entry")
        .clone();

    let targets = collect_governance_targets(&subject, None, &snapshot);
    let ids = target_ids(&targets);

    assert!(ids.contains(&"backend:ollama-openai-dev-runtime".to_string()));
    assert!(ids.contains(&"native_family:model-registry".to_string()));
}

#[test]
fn filesystem_skill_subject_prefers_governing_family_targets_over_self() {
    let mut entries = vec![
        test_entry_with_hints(
            "extension:alpha",
            "extension",
            "Alpha Extension",
            Some("/tmp/governed/family"),
            &[
                "source-root:/tmp/governed/family",
                "extension-root:/tmp/governed/family/extension-alpha",
                "skill-path:skills/alpha/skill-md",
                "skill-name:alpha-skill",
            ],
        ),
        test_entry_with_hints(
            "skill_source:alpha",
            "skill_source",
            "Alpha Source",
            Some("/tmp/governed/family"),
            &[
                "source-root:/tmp/governed/family",
                "skill-path:skills/alpha/skill-md",
                "skill-name:alpha-skill",
            ],
        ),
        test_entry_with_hints(
            "filesystem_skill:extension:alpha:skills/alpha/SKILL.md",
            "filesystem_skill",
            "Alpha Skill",
            Some("/tmp/governed/family"),
            &[
                "source-root:/tmp/governed/family",
                "extension-root:/tmp/governed/family/extension-alpha",
                "skill-path:skills/alpha/skill-md",
                "skill-name:alpha-skill",
            ],
        ),
    ];
    annotate_governing_relationships(&mut entries);
    let snapshot = test_snapshot(entries);
    let subject = snapshot
        .entries
        .iter()
        .find(|entry| entry.entry_id == "filesystem_skill:extension:alpha:skills/alpha/SKILL.md")
        .expect("subject entry")
        .clone();

    let targets = collect_governance_targets(&subject, None, &snapshot);
    let ids = target_ids(&targets);

    assert!(ids.contains(&"extension:alpha".to_string()));
    assert!(ids.contains(&"skill_source:alpha".to_string()));
    assert!(!ids.contains(&"filesystem_skill:extension:alpha:skills/alpha/SKILL.md".to_string()));
}
