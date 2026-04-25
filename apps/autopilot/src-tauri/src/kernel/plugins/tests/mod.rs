use super::build_session_plugin_snapshot;
use super::*;
use crate::models::{
    CapabilityAuthorityDescriptor, CapabilityLeaseDescriptor, CapabilityRegistrySummary,
    ExtensionContributionRecord, LocalEngineApiConfig, LocalEngineBackendPolicyConfig,
    LocalEngineControlPlane, LocalEngineMemoryConfig, LocalEngineResponseConfig,
    LocalEngineRuntimeProfile, LocalEngineSnapshot, LocalEngineStorageConfig,
    LocalEngineWatchdogConfig, SkillSourceDiscoveredSkill,
};
use ioi_api::crypto::SigningKeyPair as _;
use ioi_crypto::sign::eddsa::Ed25519KeyPair;

fn empty_local_engine_snapshot() -> LocalEngineSnapshot {
    LocalEngineSnapshot {
        generated_at_ms: 0,
        total_native_tools: 0,
        pending_control_count: 0,
        pending_approval_count: 0,
        active_issue_count: 0,
        capabilities: Vec::new(),
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
                mode: "local".to_string(),
                endpoint: "http://127.0.0.1:11434/v1".to_string(),
                default_model: "none".to_string(),
                baseline_role: "operator".to_string(),
                kernel_authority: "contained_local".to_string(),
            },
            storage: LocalEngineStorageConfig {
                models_path: ".".to_string(),
                backends_path: ".".to_string(),
                artifacts_path: ".".to_string(),
                cache_path: ".".to_string(),
            },
            watchdog: LocalEngineWatchdogConfig {
                enabled: false,
                idle_check_enabled: false,
                idle_timeout: "0s".to_string(),
                busy_check_enabled: false,
                busy_timeout: "0s".to_string(),
                check_interval: "0s".to_string(),
                force_eviction_when_busy: false,
                lru_eviction_max_retries: 0,
                lru_eviction_retry_interval: "0s".to_string(),
            },
            memory: LocalEngineMemoryConfig {
                reclaimer_enabled: false,
                threshold_percent: 0,
                prefer_gpu: false,
                target_resource: "cpu".to_string(),
            },
            backend_policy: LocalEngineBackendPolicyConfig {
                max_concurrency: 1,
                max_queued_requests: 1,
                parallel_backend_loads: 1,
                allow_parallel_requests: false,
                health_probe_interval: "0s".to_string(),
                log_level: "info".to_string(),
                auto_shutdown_on_idle: false,
            },
            responses: LocalEngineResponseConfig {
                retain_receipts_days: 1,
                persist_artifacts: false,
                allow_streaming: false,
                store_request_previews: false,
            },
            api: LocalEngineApiConfig {
                bind_address: "127.0.0.1:0".to_string(),
                remote_access_enabled: false,
                cors_mode: "off".to_string(),
                auth_mode: "none".to_string(),
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

fn test_entry(entry_id: &str, label: &str) -> CapabilityRegistryEntry {
    CapabilityRegistryEntry {
        entry_id: entry_id.to_string(),
        kind: "extension".to_string(),
        label: label.to_string(),
        summary: format!("{label} summary"),
        source_kind: "tracked_source".to_string(),
        source_label: "Workspace source".to_string(),
        source_uri: Some("/workspace/plugin".to_string()),
        trust_posture: "contained_local".to_string(),
        governed_profile: Some("governed_extension".to_string()),
        availability: "ready".to_string(),
        status_label: "Ready".to_string(),
        why_selectable: format!("{label} is selectable in the runtime inventory."),
        governing_family_id: None,
        related_governing_entry_ids: Vec::new(),
        governing_family_hints: Vec::new(),
        runtime_target: Some("runtime_bridge".to_string()),
        lease_mode: Some("governed_extension".to_string()),
        authority: CapabilityAuthorityDescriptor {
            tier_id: "extension".to_string(),
            tier_label: "Governed extension".to_string(),
            governed_profile_id: Some("governed_extension".to_string()),
            governed_profile_label: Some("Governed extension".to_string()),
            summary: "summary".to_string(),
            detail: "detail".to_string(),
            signals: Vec::new(),
        },
        lease: CapabilityLeaseDescriptor {
            availability: "ready".to_string(),
            availability_label: "Ready".to_string(),
            runtime_target_id: Some("runtime_bridge".to_string()),
            runtime_target_label: Some("Runtime bridge".to_string()),
            mode_id: Some("governed_extension".to_string()),
            mode_label: Some("Governed extension".to_string()),
            summary: "summary".to_string(),
            detail: "detail".to_string(),
            requires_auth: false,
            signals: Vec::new(),
        },
    }
}

fn plugin_snapshot_fixture(
    manifest_path: &std::path::Path,
    plugin_root: &std::path::Path,
) -> CapabilityRegistrySnapshot {
    CapabilityRegistrySnapshot {
        generated_at_ms: 1,
        summary: CapabilityRegistrySummary {
            generated_at_ms: 1,
            total_entries: 1,
            connector_count: 0,
            connected_connector_count: 0,
            runtime_skill_count: 0,
            tracked_source_count: 1,
            filesystem_skill_count: 1,
            extension_count: 1,
            model_count: 0,
            backend_count: 0,
            native_family_count: 0,
            pending_engine_control_count: 0,
            active_issue_count: 0,
            authoritative_source_count: 1,
        },
        entries: vec![test_entry("extension:manifest:alpha", "Alpha Plugin")],
        connectors: Vec::new(),
        skill_catalog: Vec::new(),
        skill_sources: Vec::new(),
        extension_manifests: vec![ExtensionManifestRecord {
            extension_id: "manifest:alpha".to_string(),
            manifest_kind: "codex_plugin".to_string(),
            manifest_path: manifest_path.to_string_lossy().to_string(),
            root_path: plugin_root.to_string_lossy().to_string(),
            source_label: "Workspace source".to_string(),
            source_uri: plugin_root.to_string_lossy().to_string(),
            source_kind: "tracked_source".to_string(),
            enabled: true,
            name: "alpha-plugin".to_string(),
            display_name: Some("Alpha Plugin".to_string()),
            version: Some("1.0.0".to_string()),
            description: Some("Workspace plugin".to_string()),
            developer_name: None,
            author_name: None,
            author_email: None,
            author_url: None,
            category: Some("Automation".to_string()),
            trust_posture: "contained_local".to_string(),
            governed_profile: "governed_extension".to_string(),
            homepage: None,
            repository: None,
            license: None,
            keywords: Vec::new(),
            capabilities: vec!["hooks".to_string(), "runtime".to_string()],
            default_prompts: Vec::new(),
            contributions: vec![ExtensionContributionRecord {
                kind: "hooks".to_string(),
                label: "Hooks".to_string(),
                path: Some("hooks/main.ts".to_string()),
                item_count: Some(1),
                detail: Some("Hook contribution".to_string()),
            }],
            filesystem_skills: vec![SkillSourceDiscoveredSkill {
                name: "Skill".to_string(),
                description: None,
                relative_path: "skills/example/SKILL.md".to_string(),
            }],
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
        }],
        local_engine: empty_local_engine_snapshot(),
    }
}

fn write_test_plugin_manifest(
    root: &std::path::Path,
    name: &str,
    display_name: &str,
) -> std::path::PathBuf {
    let manifest_dir = root.join(".codex-plugin");
    std::fs::create_dir_all(&manifest_dir).expect("create plugin root");
    let manifest_path = manifest_dir.join("plugin.json");
    std::fs::write(
        &manifest_path,
        format!(
            r#"{{
  "name": "{name}",
  "version": "1.0.0",
  "interface": {{
"displayName": "{display_name}",
"category": "Validation",
"capabilities": ["Inspect", "Write"]
  }}
}}"#
        ),
    )
    .expect("write plugin manifest");
    std::fs::write(
        root.join("README.md"),
        format!("{display_name} packaged payload\n"),
    )
    .expect("write plugin readme");
    manifest_path
}

fn sign_plugin_package(root: &std::path::Path) -> (String, String, String) {
    let keypair = Ed25519KeyPair::generate().expect("generate ed25519 keypair");
    let digest_sha256 =
        compute_plugin_package_digest_sha256(root).expect("compute plugin package digest");
    let message = plugin_signature_message(&digest_sha256);
    let signature = keypair.sign(&message).expect("sign plugin package digest");
    (
        digest_sha256,
        hex::encode(keypair.public_key().to_bytes()),
        hex::encode(signature.to_bytes()),
    )
}

fn write_test_plugin_archive(source_root: &std::path::Path, archive_path: &std::path::Path) {
    let parent = archive_path.parent().expect("archive parent");
    std::fs::create_dir_all(parent).expect("create archive parent");
    let file = std::fs::File::create(archive_path).expect("create plugin archive");
    let mut writer = zip::ZipWriter::new(file);
    let options =
        zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Deflated);
    let mut relative_files = Vec::new();
    collect_plugin_package_files(source_root, source_root, &mut relative_files)
        .expect("collect plugin package files");
    relative_files.sort_by(|left, right| slash_path(left).cmp(&slash_path(right)));
    for relative_path in relative_files {
        let absolute_path = source_root.join(&relative_path);
        let bytes = std::fs::read(&absolute_path).expect("read archive source file");
        writer
            .start_file(slash_path(&relative_path), options)
            .expect("start archive file");
        use std::io::Write as _;
        writer.write_all(&bytes).expect("write archive file");
    }
    writer.finish().expect("finish plugin archive");
}

struct TestStaticHttpServer {
    base_url: String,
    shutdown: Option<std::sync::mpsc::Sender<()>>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl TestStaticHttpServer {
    fn url(&self, relative_path: &str) -> String {
        format!(
            "{}/{}",
            self.base_url,
            relative_path.trim_start_matches('/')
        )
    }
}

impl Drop for TestStaticHttpServer {
    fn drop(&mut self) {
        if let Some(sender) = self.shutdown.take() {
            let _ = sender.send(());
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn serve_static_http_response(
    root: &std::path::Path,
    stream: &mut std::net::TcpStream,
) -> Result<(), String> {
    use std::io::{Read as _, Write as _};

    let mut buffer = [0u8; 8192];
    let bytes_read = stream
        .read(&mut buffer)
        .map_err(|error| format!("read request: {}", error))?;
    let request = String::from_utf8_lossy(&buffer[..bytes_read]);
    let request_line = request
        .lines()
        .next()
        .ok_or_else(|| "request missing first line".to_string())?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("/");
    if method != "GET" {
        let response =
            "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        stream
            .write_all(response.as_bytes())
            .map_err(|error| format!("write 405 response: {}", error))?;
        return Ok(());
    }
    let relative_path = path.trim_start_matches('/');
    let requested_path = std::path::Path::new(relative_path);
    if requested_path
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        let response = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        stream
            .write_all(response.as_bytes())
            .map_err(|error| format!("write 400 response: {}", error))?;
        return Ok(());
    }
    let file_path = root.join(requested_path);
    if !file_path.exists() || !file_path.is_file() {
        let response = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        stream
            .write_all(response.as_bytes())
            .map_err(|error| format!("write 404 response: {}", error))?;
        return Ok(());
    }
    let body = std::fs::read(&file_path)
        .map_err(|error| format!("read {}: {}", file_path.display(), error))?;
    let content_type = match file_path.extension().and_then(|value| value.to_str()) {
        Some("json") => "application/json",
        Some("zip") => "application/zip",
        _ => "application/octet-stream",
    };
    let header = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: {}\r\nConnection: close\r\n\r\n",
        body.len(),
        content_type
    );
    stream
        .write_all(header.as_bytes())
        .and_then(|_| stream.write_all(&body))
        .map_err(|error| format!("write response: {}", error))?;
    Ok(())
}

fn spawn_static_http_server(root: std::path::PathBuf) -> TestStaticHttpServer {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind static HTTP server");
    listener
        .set_nonblocking(true)
        .expect("set server nonblocking");
    let address = listener.local_addr().expect("read server address");
    let (shutdown_tx, shutdown_rx) = std::sync::mpsc::channel::<()>();
    let handle = std::thread::spawn(move || loop {
        if shutdown_rx.try_recv().is_ok() {
            break;
        }
        match listener.accept() {
            Ok((mut stream, _)) => {
                let _ = serve_static_http_response(&root, &mut stream);
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Err(_) => break,
        }
    });
    TestStaticHttpServer {
        base_url: format!("http://{}", address),
        shutdown: Some(shutdown_tx),
        handle: Some(handle),
    }
}

fn rooted_publisher_fixture(
    root_id: &str,
    root_label: &str,
    root_status: Option<&str>,
    root_trust_source: &str,
    root_revoked_at_ms: Option<u64>,
    publisher_id: &str,
    publisher_label: &str,
    publisher_status: Option<&str>,
    publisher_trust_source: &str,
    publisher_revoked_at_ms: Option<u64>,
    signing_key_id: &str,
    signing_key_public_key: &str,
    signing_key_status: Option<&str>,
    signing_key_revoked_at_ms: Option<u64>,
    statement_issued_at_ms: u64,
) -> (PluginMarketplaceTrustRoot, PluginMarketplacePublisher) {
    let root_keypair = Ed25519KeyPair::generate().expect("generate marketplace root keypair");
    let mut publisher = PluginMarketplacePublisher {
        id: publisher_id.to_string(),
        label: Some(publisher_label.to_string()),
        trust_root_id: Some(root_id.to_string()),
        trust_status: publisher_status.map(str::to_string),
        trust_source: Some(publisher_trust_source.to_string()),
        revoked_at_ms: publisher_revoked_at_ms,
        statement_signature: None,
        statement_issued_at_ms: Some(statement_issued_at_ms),
        signing_keys: vec![PluginMarketplaceSigningKey {
            id: signing_key_id.to_string(),
            public_key: signing_key_public_key.to_string(),
            algorithm: Some("ed25519".to_string()),
            status: signing_key_status.map(str::to_string),
            revoked_at_ms: signing_key_revoked_at_ms,
        }],
    };
    let statement_message = plugin_publisher_statement_message(root_id, &publisher);
    let statement_signature = root_keypair
        .sign(&statement_message)
        .expect("sign marketplace root statement");
    publisher.statement_signature = Some(hex::encode(statement_signature.to_bytes()));

    (
        PluginMarketplaceTrustRoot {
            id: root_id.to_string(),
            label: Some(root_label.to_string()),
            public_key: hex::encode(root_keypair.public_key().to_bytes()),
            algorithm: Some("ed25519".to_string()),
            status: root_status.map(str::to_string),
            trust_source: Some(root_trust_source.to_string()),
            revoked_at_ms: root_revoked_at_ms,
        },
        publisher,
    )
}

fn authority_bundle_fixture(
    authority_id: &str,
    authority_label: &str,
    authority_status: Option<&str>,
    authority_trust_source: &str,
    bundle_id: &str,
    bundle_label: &str,
    roots: Vec<PluginMarketplaceTrustRoot>,
    publisher_revocations: Vec<PluginMarketplacePublisherRevocation>,
    issued_at_ms: u64,
) -> (
    PluginMarketplaceBundleAuthority,
    PluginMarketplaceAuthorityBundle,
) {
    let authority_keypair =
        Ed25519KeyPair::generate().expect("generate marketplace authority keypair");
    let mut bundle = PluginMarketplaceAuthorityBundle {
        id: bundle_id.to_string(),
        label: Some(bundle_label.to_string()),
        authority_id: authority_id.to_string(),
        issued_at_ms: Some(issued_at_ms),
        signature: None,
        signature_algorithm: Some("ed25519".to_string()),
        trust_source: Some("marketplace authority bundle verification".to_string()),
        roots,
        publisher_revocations,
    };
    let message = plugin_marketplace_authority_bundle_message(&bundle);
    let signature = authority_keypair
        .sign(&message)
        .expect("sign marketplace authority bundle");
    bundle.signature = Some(hex::encode(signature.to_bytes()));

    (
        PluginMarketplaceBundleAuthority {
            id: authority_id.to_string(),
            label: Some(authority_label.to_string()),
            public_key: hex::encode(authority_keypair.public_key().to_bytes()),
            algorithm: Some("ed25519".to_string()),
            status: authority_status.map(str::to_string),
            trust_source: Some(authority_trust_source.to_string()),
            revoked_at_ms: None,
        },
        bundle,
    )
}

fn authority_trust_bundle_fixture(
    root_id: &str,
    root_label: &str,
    root_status: Option<&str>,
    root_trust_source: &str,
    root_revoked_at_ms: Option<u64>,
    bundle_id: &str,
    bundle_label: &str,
    bundle_trust_source: &str,
    authorities: Vec<PluginMarketplaceBundleAuthority>,
    authority_revocations: Vec<PluginMarketplaceAuthorityRevocation>,
    issued_at_ms: u64,
    expires_at_ms: Option<u64>,
) -> (
    PluginMarketplaceTrustRoot,
    PluginMarketplaceAuthorityTrustBundle,
) {
    let root_keypair = Ed25519KeyPair::generate().expect("generate authority trust root keypair");
    let mut bundle = PluginMarketplaceAuthorityTrustBundle {
        id: bundle_id.to_string(),
        label: Some(bundle_label.to_string()),
        issuer_id: root_id.to_string(),
        issuer_label: Some(root_label.to_string()),
        issued_at_ms: Some(issued_at_ms),
        expires_at_ms,
        signature: None,
        signature_algorithm: Some("ed25519".to_string()),
        trust_source: Some(bundle_trust_source.to_string()),
        authorities,
        authority_revocations,
    };
    let message = plugin_marketplace_authority_trust_bundle_message(&bundle);
    let signature = root_keypair
        .sign(&message)
        .expect("sign marketplace authority trust bundle");
    bundle.signature = Some(hex::encode(signature.to_bytes()));

    (
        PluginMarketplaceTrustRoot {
            id: root_id.to_string(),
            label: Some(root_label.to_string()),
            public_key: hex::encode(root_keypair.public_key().to_bytes()),
            algorithm: Some("ed25519".to_string()),
            status: root_status.map(str::to_string),
            trust_source: Some(root_trust_source.to_string()),
            revoked_at_ms: root_revoked_at_ms,
        },
        bundle,
    )
}

fn catalog_refresh_bundle_fixture(
    root_id: &str,
    root_label: &str,
    bundle_id: &str,
    bundle_label: &str,
    catalog_id: &str,
    refresh_source: &str,
    channel: &str,
    plugins: Vec<PluginMarketplaceCatalogEntry>,
    issued_at_ms: u64,
    refreshed_at_ms: u64,
    expires_at_ms: Option<u64>,
    tamper_signature: bool,
) -> (
    PluginMarketplaceTrustRoot,
    PluginMarketplaceCatalogRefreshBundle,
) {
    let root_keypair = Ed25519KeyPair::generate().expect("generate catalog refresh root keypair");
    let mut bundle = PluginMarketplaceCatalogRefreshBundle {
        id: bundle_id.to_string(),
        label: Some(bundle_label.to_string()),
        catalog_id: catalog_id.to_string(),
        issuer_id: root_id.to_string(),
        issuer_label: Some(root_label.to_string()),
        issued_at_ms: Some(issued_at_ms),
        expires_at_ms,
        refreshed_at_ms: Some(refreshed_at_ms),
        refresh_source: Some(refresh_source.to_string()),
        channel: Some(channel.to_string()),
        signature: None,
        signature_algorithm: Some("ed25519".to_string()),
        plugins,
    };
    let message = plugin_marketplace_catalog_refresh_bundle_message(&bundle);
    let signature = root_keypair
        .sign(&message)
        .expect("sign plugin catalog refresh bundle");
    let mut signature_hex = hex::encode(signature.to_bytes());
    if tamper_signature {
        let replacement = if signature_hex.ends_with('0') {
            '1'
        } else {
            '0'
        };
        signature_hex.pop();
        signature_hex.push(replacement);
    }
    bundle.signature = Some(signature_hex);

    (
        PluginMarketplaceTrustRoot {
            id: root_id.to_string(),
            label: Some(root_label.to_string()),
            public_key: hex::encode(root_keypair.public_key().to_bytes()),
            algorithm: Some("ed25519".to_string()),
            status: Some("active".to_string()),
            trust_source: Some("signed catalog refresh verification".to_string()),
            revoked_at_ms: None,
        },
        bundle,
    )
}

fn catalog_refresh_entry(
    manifest_path: &std::path::Path,
    display_name: &str,
    description: &str,
    available_version: &str,
    digest_sha256: &str,
    signature_public_key: &str,
    package_signature: &str,
    publisher_id: &str,
    signing_key_id: &str,
    publisher_label: &str,
    signer_identity: &str,
) -> PluginMarketplaceCatalogEntry {
    PluginMarketplaceCatalogEntry {
        manifest_path: slash_path(manifest_path),
        package_url: None,
        display_name: Some(display_name.to_string()),
        description: Some(description.to_string()),
        category: Some("Validation".to_string()),
        installation_policy: Some("managed_copy".to_string()),
        authentication_policy: Some("operator_trust".to_string()),
        products: vec!["Autopilot".to_string()],
        available_version: Some(available_version.to_string()),
        package_digest_sha256: Some(digest_sha256.to_string()),
        signature_algorithm: Some("ed25519".to_string()),
        signature_public_key: Some(signature_public_key.to_string()),
        package_signature: Some(package_signature.to_string()),
        verification_status: None,
        signer_identity: Some(signer_identity.to_string()),
        publisher_id: Some(publisher_id.to_string()),
        signing_key_id: Some(signing_key_id.to_string()),
        publisher_label: Some(publisher_label.to_string()),
        verification_error: None,
        verified_at_ms: None,
        trust_score_label: None,
        trust_score_source: None,
        trust_recommendation: None,
    }
}

mod authority_snapshot;
mod catalog_snapshot;
mod install_blockers;
mod marketplace;
mod snapshot_lifecycle;
