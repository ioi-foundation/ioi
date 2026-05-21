use super::*;

fn unique_temp_dir(name: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!("ioi-autopilot-skill-source-{}-{}", name, now_ms()));
    path
}

#[test]
fn parse_skill_manifest_prefers_frontmatter_name_and_description() {
    let markdown = r#"---
name: local-research
description: "A research skill"
---

# Ignored heading

Some body text.
"#;
    let parsed = parse_skill_manifest(markdown, "skills/local-research/SKILL.md");
    assert_eq!(parsed.name, "local-research");
    assert_eq!(parsed.description.as_deref(), Some("A research skill"));
}

#[test]
fn sync_source_discovers_nested_skill_docs() {
    let root = unique_temp_dir("discover");
    let nested = root.join("skills/research");
    fs::create_dir_all(&nested).expect("create nested dir");
    fs::write(
        nested.join("SKILL.md"),
        "# Research Skill\n\nInvestigate topics deeply.",
    )
    .expect("write skill file");
    fs::create_dir_all(root.join("node_modules/ignored")).expect("create ignored dir");
    fs::write(
        root.join("node_modules/ignored/SKILL.md"),
        "# Should Not Appear",
    )
    .expect("write ignored skill");

    let mut source = SkillSourceRecord {
        source_id: "source-1".to_string(),
        label: "Research".to_string(),
        uri: root.to_string_lossy().to_string(),
        kind: "directory".to_string(),
        enabled: true,
        sync_status: "configured".to_string(),
        last_synced_at_ms: None,
        last_error: None,
        discovered_skills: Vec::new(),
    };

    sync_source_record(&mut source).expect("sync source");
    assert_eq!(source.sync_status, "ready");
    assert_eq!(source.discovered_skills.len(), 1);
    assert_eq!(source.discovered_skills[0].name, "Research Skill");
    assert_eq!(
        source.discovered_skills[0].relative_path,
        "skills/research/SKILL.md"
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn load_extension_manifest_discovers_manifest_contributions_and_marketplace_policy() {
    let root = unique_temp_dir("extension-manifest");
    let plugin_root = root.join("plugins/research-companion");
    let manifest_dir = plugin_root.join(".codex-plugin");
    let skills_dir = plugin_root.join("skills/research");
    fs::create_dir_all(&manifest_dir).expect("create manifest dir");
    fs::create_dir_all(&skills_dir).expect("create skills dir");
    fs::create_dir_all(root.join(".agents/plugins")).expect("create marketplace dir");

    fs::write(
        skills_dir.join("SKILL.md"),
        "# Research Companion\n\nInvestigate with evidence.",
    )
    .expect("write plugin skill");
    fs::write(
        manifest_dir.join("plugin.json"),
        r#"{
  "name": "research-companion",
  "version": "1.2.0",
  "description": "Plugin detail",
  "skills": "./skills",
  "mcpServers": "./.mcp.json",
  "interface": {
    "displayName": "Research Companion",
    "shortDescription": "Helper for research work",
    "developerName": "IOI",
    "category": "Productivity",
    "capabilities": ["Interactive", "Write"],
    "defaultPrompt": [
      "Summarize the latest findings.",
      "Draft a follow-up note."
    ]
  }
}"#,
    )
    .expect("write plugin manifest");
    fs::write(
        root.join(".agents/plugins/marketplace.json"),
        r#"{
  "name": "ioi-marketplace",
  "interface": {
    "displayName": "IOI Marketplace"
  },
  "plugins": [
    {
      "name": "research-companion",
      "source": {
        "source": "local",
        "path": "./plugins/research-companion"
      },
      "policy": {
        "installation": "AVAILABLE",
        "authentication": "ON_USE",
        "products": ["autopilot"]
      },
      "category": "Productivity"
    }
  ]
}"#,
    )
    .expect("write marketplace manifest");

    let scan_root = ManifestScanRoot {
        root_path: root.clone(),
        source_label: "Workspace".to_string(),
        source_uri: root.to_string_lossy().to_string(),
        source_kind: "workspace".to_string(),
        enabled: true,
    };
    let marketplace = load_marketplace_plugins(&root).expect("load marketplace");
    let manifest =
        load_extension_manifest(&scan_root, &manifest_dir.join("plugin.json"), &marketplace)
            .expect("load extension manifest");

    assert_eq!(manifest.name, "research-companion");
    assert_eq!(manifest.display_name.as_deref(), Some("Research Companion"));
    assert_eq!(manifest.trust_posture, "policy_limited");
    assert_eq!(manifest.governed_profile, "governed_marketplace");
    assert_eq!(
        manifest.marketplace_authentication_policy.as_deref(),
        Some("ON_USE")
    );
    assert_eq!(manifest.filesystem_skills.len(), 1);
    assert_eq!(manifest.filesystem_skills[0].name, "Research Companion");
    assert_eq!(manifest.contributions.len(), 2);
    assert_eq!(manifest.contributions[0].kind, "skills");
    assert_eq!(manifest.contributions[0].item_count, Some(1));
    assert_eq!(manifest.capabilities, vec!["Interactive", "Write"]);
    assert_eq!(
        manifest.default_prompts,
        vec![
            "Summarize the latest findings.".to_string(),
            "Draft a follow-up note.".to_string()
        ]
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn sort_and_dedup_extension_manifests_prefers_tracked_sources() {
    let manifest_path = "/tmp/research-companion/.codex-plugin/plugin.json".to_string();
    let root_path = "/tmp/research-companion".to_string();
    let mut manifests = vec![
        ExtensionManifestRecord {
            extension_id: "workspace:/tmp/research-companion/.codex-plugin/plugin.json".to_string(),
            manifest_kind: "codex_plugin".to_string(),
            manifest_path: manifest_path.clone(),
            root_path: root_path.clone(),
            source_label: "Workspace".to_string(),
            source_uri: "/tmp".to_string(),
            source_kind: "workspace".to_string(),
            enabled: true,
            name: "research-companion".to_string(),
            display_name: Some("Research Companion".to_string()),
            version: Some("1.0.0".to_string()),
            description: Some("Workspace manifest".to_string()),
            developer_name: None,
            author_name: None,
            author_email: None,
            author_url: None,
            category: None,
            trust_posture: "local_only".to_string(),
            governed_profile: "local_manifest".to_string(),
            homepage: None,
            repository: None,
            license: None,
            keywords: Vec::new(),
            capabilities: vec!["Interactive".to_string()],
            default_prompts: Vec::new(),
            contributions: Vec::new(),
            filesystem_skills: Vec::new(),
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
        },
        ExtensionManifestRecord {
            extension_id: "skill_source:/tmp/research-companion/.codex-plugin/plugin.json"
                .to_string(),
            manifest_kind: "codex_plugin".to_string(),
            manifest_path: manifest_path.clone(),
            root_path,
            source_label: "Research Companion".to_string(),
            source_uri: "/tmp/research-companion".to_string(),
            source_kind: "skill_source".to_string(),
            enabled: true,
            name: "research-companion".to_string(),
            display_name: Some("Research Companion".to_string()),
            version: Some("1.0.0".to_string()),
            description: Some("Tracked manifest".to_string()),
            developer_name: None,
            author_name: None,
            author_email: None,
            author_url: None,
            category: None,
            trust_posture: "local_only".to_string(),
            governed_profile: "local_manifest".to_string(),
            homepage: None,
            repository: None,
            license: None,
            keywords: Vec::new(),
            capabilities: vec!["Interactive".to_string()],
            default_prompts: Vec::new(),
            contributions: Vec::new(),
            filesystem_skills: Vec::new(),
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
        },
    ];

    sort_and_dedup_extension_manifests(&mut manifests);

    assert_eq!(manifests.len(), 1);
    assert_eq!(manifests[0].source_kind, "skill_source");
    assert_eq!(manifests[0].source_label, "Research Companion");
}
