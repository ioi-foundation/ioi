use crate::kernel::plugins::{
    build_session_plugin_snapshot_for_manifests_with_fixture_path,
    load_plugin_marketplace_catalog_refresh_target_from_path,
    load_plugin_marketplace_feed_manifests_from_path, plugin_runtime_state_path_for,
    PluginRuntimeManager,
};
use crate::models::ExtensionManifestRecord;
use serde::Serialize;
use serde_json::Value;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

fn env_text(key: &str) -> Option<String> {
    env::var(key)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn bool_env(key: &str) -> bool {
    env::var(key)
        .ok()
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

fn cli_data_dir() -> Result<PathBuf, String> {
    if let Some(override_path) = env_text("AUTOPILOT_DATA_DIR") {
        return Ok(PathBuf::from(override_path));
    }

    let home = env_text("HOME").ok_or_else(|| "HOME is not set.".to_string())?;
    let mut base = PathBuf::from(home);
    base.push(".local/share/ai.ioi.autopilot");

    let profile = env_text("AUTOPILOT_DATA_PROFILE").or_else(|| {
        if bool_env("AUTOPILOT_LOCAL_GPU_DEV") {
            Some("desktop-localgpu".to_string())
        } else {
            None
        }
    });

    if let Some(profile) = profile {
        Ok(base.join("profiles").join(profile))
    } else {
        Ok(base)
    }
}

fn slash_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn string_value(value: Option<&Value>) -> Option<String> {
    value
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(str::to_string)
}

fn string_array(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(str::to_string)
        .collect()
}

fn manifest_parent_root(manifest_path: &Path) -> Result<PathBuf, String> {
    manifest_path
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| {
            format!(
                "Plugin manifest '{}' does not live under '.codex-plugin/'.",
                manifest_path.display()
            )
        })
}

fn manifest_source_kind(root: &Path) -> String {
    let home_plugins = env_text("HOME")
        .map(PathBuf::from)
        .map(|home| home.join("plugins"));
    if let Some(home_plugins) = home_plugins {
        if root.starts_with(&home_plugins) {
            return "home_plugins".to_string();
        }
    }
    "proof_manifest".to_string()
}

fn manifest_source_label(root: &Path) -> String {
    match manifest_source_kind(root).as_str() {
        "home_plugins" => "Home plugins".to_string(),
        _ => "Proof manifest".to_string(),
    }
}

fn build_manifest_record(manifest_path: &Path) -> Result<ExtensionManifestRecord, String> {
    let raw = fs::read_to_string(manifest_path)
        .map_err(|error| format!("Failed to read {}: {}", manifest_path.display(), error))?;
    let parsed: Value = serde_json::from_str(&raw)
        .map_err(|error| format!("Failed to parse {}: {}", manifest_path.display(), error))?;
    let manifest_root = manifest_parent_root(manifest_path)?;
    let interface = parsed.get("interface").and_then(Value::as_object);
    let name = string_value(parsed.get("name")).unwrap_or_else(|| {
        manifest_root
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("unnamed-extension")
            .to_string()
    });
    let source_kind = manifest_source_kind(&manifest_root);
    let source_label = manifest_source_label(&manifest_root);
    let capabilities = interface
        .map(|value| string_array(value.get("capabilities")))
        .unwrap_or_default();
    let default_prompts = interface
        .map(|value| string_array(value.get("defaultPrompt")))
        .unwrap_or_default()
        .into_iter()
        .take(3)
        .collect::<Vec<_>>();
    let governed_profile = if parsed.get("skills").is_some() {
        "local_skill_bundle".to_string()
    } else {
        "local_manifest".to_string()
    };

    Ok(ExtensionManifestRecord {
        extension_id: format!("manifest:{}", slash_path(manifest_path)),
        manifest_kind: "codex_plugin".to_string(),
        manifest_path: slash_path(manifest_path),
        root_path: slash_path(&manifest_root),
        source_label,
        source_uri: slash_path(&manifest_root),
        source_kind,
        enabled: true,
        name,
        display_name: interface.and_then(|value| string_value(value.get("displayName"))),
        version: string_value(parsed.get("version")),
        description: string_value(parsed.get("description"))
            .or_else(|| interface.and_then(|value| string_value(value.get("shortDescription"))))
            .or_else(|| interface.and_then(|value| string_value(value.get("longDescription")))),
        developer_name: interface.and_then(|value| string_value(value.get("developerName"))),
        author_name: None,
        author_email: None,
        author_url: None,
        category: interface.and_then(|value| string_value(value.get("category"))),
        trust_posture: "local_only".to_string(),
        governed_profile,
        homepage: string_value(parsed.get("homepage")),
        repository: string_value(parsed.get("repository")),
        license: string_value(parsed.get("license")),
        keywords: string_array(parsed.get("keywords")),
        capabilities,
        default_prompts,
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
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProofOutput {
    state_path: String,
    exists: bool,
    state: Value,
}

fn read_state(state_path: &Path) -> Result<ProofOutput, String> {
    if !state_path.exists() {
        return Ok(ProofOutput {
            state_path: slash_path(state_path),
            exists: false,
            state: serde_json::json!({
                "plugins": [],
                "recentReceipts": [],
            }),
        });
    }

    let raw = fs::read_to_string(state_path)
        .map_err(|error| format!("Failed to read {}: {}", state_path.display(), error))?;
    let state: Value = serde_json::from_str(&raw)
        .map_err(|error| format!("Failed to parse {}: {}", state_path.display(), error))?;
    Ok(ProofOutput {
        state_path: slash_path(state_path),
        exists: true,
        state,
    })
}

fn print_json<T: Serialize>(value: &T) -> Result<(), String> {
    let text = serde_json::to_string_pretty(value)
        .map_err(|error| format!("JSON encode failed: {error}"))?;
    println!("{text}");
    Ok(())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CatalogProofOutput {
    fixture_path: String,
    snapshot: crate::models::SessionPluginSnapshot,
}

fn catalog_snapshot(
    fixture_path: &Path,
    manager: &PluginRuntimeManager,
) -> Result<CatalogProofOutput, String> {
    let manifests = load_plugin_marketplace_feed_manifests_from_path(fixture_path)?;
    Ok(CatalogProofOutput {
        fixture_path: slash_path(fixture_path),
        snapshot: build_session_plugin_snapshot_for_manifests_with_fixture_path(
            &manifests,
            manager.snapshot(),
            None,
            None,
            Some(fixture_path),
        ),
    })
}

fn find_catalog_manifest(
    fixture_path: &Path,
    plugin_id: &str,
) -> Result<ExtensionManifestRecord, String> {
    let manifests = load_plugin_marketplace_feed_manifests_from_path(fixture_path)?;
    manifests
        .into_iter()
        .find(|manifest| manifest.extension_id == plugin_id)
        .ok_or_else(|| {
            format!("Plugin '{plugin_id}' is not present in the plugin marketplace feed.")
        })
}

pub fn run_cli() -> Result<(), String> {
    let mut args = env::args().skip(1);
    let command = args.next().ok_or_else(|| {
        "Usage: autopilot_plugin_proof <show|install|mark-update|apply-update|remove|trust-enable|reload|disable|revoke> <manifest-path> [version]\n       autopilot_plugin_proof <catalog-show> <fixture-path>\n       autopilot_plugin_proof <catalog-install|catalog-update|catalog-trust-enable|catalog-remove|catalog-refresh> <fixture-path> <plugin-id>"
            .to_string()
    })?;

    let data_dir = cli_data_dir()?;
    let state_path = plugin_runtime_state_path_for(&data_dir);
    let manager = PluginRuntimeManager::new(state_path.clone());

    match command.as_str() {
        "catalog-show" => {
            let fixture_path = args
                .next()
                .ok_or_else(|| {
                    "Usage: autopilot_plugin_proof catalog-show <fixture-path>".to_string()
                })
                .map(PathBuf::from)?;
            return print_json(&catalog_snapshot(&fixture_path, &manager)?);
        }
        "catalog-install" => {
            let fixture_path = args
                .next()
                .ok_or_else(|| {
                    "Usage: autopilot_plugin_proof catalog-install <fixture-path> <plugin-id>"
                        .to_string()
                })
                .map(PathBuf::from)?;
            let plugin_id = args.next().ok_or_else(|| {
                "Usage: autopilot_plugin_proof catalog-install <fixture-path> <plugin-id>"
                    .to_string()
            })?;
            let manifest = find_catalog_manifest(&fixture_path, &plugin_id)?;
            manager.install_plugin_package(&manifest)?;
            return print_json(&catalog_snapshot(&fixture_path, &manager)?);
        }
        "catalog-update" => {
            let fixture_path = args
                .next()
                .ok_or_else(|| {
                    "Usage: autopilot_plugin_proof catalog-update <fixture-path> <plugin-id>"
                        .to_string()
                })
                .map(PathBuf::from)?;
            let plugin_id = args.next().ok_or_else(|| {
                "Usage: autopilot_plugin_proof catalog-update <fixture-path> <plugin-id>"
                    .to_string()
            })?;
            let manifest = find_catalog_manifest(&fixture_path, &plugin_id)?;
            manager.update_plugin_package(&manifest)?;
            return print_json(&catalog_snapshot(&fixture_path, &manager)?);
        }
        "catalog-trust-enable" => {
            let fixture_path = args
                .next()
                .ok_or_else(|| {
                    "Usage: autopilot_plugin_proof catalog-trust-enable <fixture-path> <plugin-id>"
                        .to_string()
                })
                .map(PathBuf::from)?;
            let plugin_id = args.next().ok_or_else(|| {
                "Usage: autopilot_plugin_proof catalog-trust-enable <fixture-path> <plugin-id>"
                    .to_string()
            })?;
            let manifest = find_catalog_manifest(&fixture_path, &plugin_id)?;
            manager.trust_plugin(&manifest, true)?;
            return print_json(&catalog_snapshot(&fixture_path, &manager)?);
        }
        "catalog-remove" => {
            let fixture_path = args
                .next()
                .ok_or_else(|| {
                    "Usage: autopilot_plugin_proof catalog-remove <fixture-path> <plugin-id>"
                        .to_string()
                })
                .map(PathBuf::from)?;
            let plugin_id = args.next().ok_or_else(|| {
                "Usage: autopilot_plugin_proof catalog-remove <fixture-path> <plugin-id>"
                    .to_string()
            })?;
            let manifest = find_catalog_manifest(&fixture_path, &plugin_id)?;
            manager.remove_plugin_package(&manifest)?;
            return print_json(&catalog_snapshot(&fixture_path, &manager)?);
        }
        "catalog-refresh" => {
            let fixture_path = args
                .next()
                .ok_or_else(|| {
                    "Usage: autopilot_plugin_proof catalog-refresh <fixture-path> <plugin-id>"
                        .to_string()
                })
                .map(PathBuf::from)?;
            let plugin_id = args.next().ok_or_else(|| {
                "Usage: autopilot_plugin_proof catalog-refresh <fixture-path> <plugin-id>"
                    .to_string()
            })?;
            let manifest = find_catalog_manifest(&fixture_path, &plugin_id)?;
            let refresh_target =
                load_plugin_marketplace_catalog_refresh_target_from_path(&fixture_path, &plugin_id);
            manager.refresh_plugin_catalog(&manifest, refresh_target)?;
            return print_json(&catalog_snapshot(&fixture_path, &manager)?);
        }
        "show" => {}
        "install" => {
            let manifest_path = args
                .next()
                .ok_or_else(|| "Usage: autopilot_plugin_proof install <manifest-path>".to_string())
                .map(PathBuf::from)?;
            let manifest = build_manifest_record(&manifest_path)?;
            manager.install_plugin_package(&manifest)?;
        }
        "mark-update" => {
            let manifest_path = args
                .next()
                .ok_or_else(|| {
                    "Usage: autopilot_plugin_proof mark-update <manifest-path> <version>"
                        .to_string()
                })
                .map(PathBuf::from)?;
            let manifest = build_manifest_record(&manifest_path)?;
            let version = args.next().ok_or_else(|| {
                "Usage: autopilot_plugin_proof mark-update <manifest-path> <version>".to_string()
            })?;
            manager.stage_plugin_update(&manifest, &version)?;
        }
        "apply-update" => {
            let manifest_path = args
                .next()
                .ok_or_else(|| {
                    "Usage: autopilot_plugin_proof apply-update <manifest-path>".to_string()
                })
                .map(PathBuf::from)?;
            let manifest = build_manifest_record(&manifest_path)?;
            manager.update_plugin_package(&manifest)?;
        }
        "remove" => {
            let manifest_path = args
                .next()
                .ok_or_else(|| "Usage: autopilot_plugin_proof remove <manifest-path>".to_string())
                .map(PathBuf::from)?;
            let manifest = build_manifest_record(&manifest_path)?;
            manager.remove_plugin_package(&manifest)?;
        }
        "trust-enable" => {
            let manifest_path = args
                .next()
                .ok_or_else(|| {
                    "Usage: autopilot_plugin_proof trust-enable <manifest-path>".to_string()
                })
                .map(PathBuf::from)?;
            let manifest = build_manifest_record(&manifest_path)?;
            manager.trust_plugin(&manifest, true)?;
        }
        "reload" => {
            let manifest_path = args
                .next()
                .ok_or_else(|| "Usage: autopilot_plugin_proof reload <manifest-path>".to_string())
                .map(PathBuf::from)?;
            let manifest = build_manifest_record(&manifest_path)?;
            manager.reload_plugin(&manifest)?;
        }
        "disable" => {
            let manifest_path = args
                .next()
                .ok_or_else(|| "Usage: autopilot_plugin_proof disable <manifest-path>".to_string())
                .map(PathBuf::from)?;
            let manifest = build_manifest_record(&manifest_path)?;
            manager.set_plugin_enabled(&manifest, false)?;
        }
        "revoke" => {
            let manifest_path = args
                .next()
                .ok_or_else(|| "Usage: autopilot_plugin_proof revoke <manifest-path>".to_string())
                .map(PathBuf::from)?;
            let manifest = build_manifest_record(&manifest_path)?;
            manager.revoke_plugin_trust(&manifest)?;
        }
        other => {
            return Err(format!(
                "Unknown command '{other}'. Usage: autopilot_plugin_proof <show|install|mark-update|apply-update|remove|trust-enable|reload|disable|revoke> <manifest-path> [version]\n       autopilot_plugin_proof <catalog-show> <fixture-path>\n       autopilot_plugin_proof <catalog-install|catalog-update|catalog-trust-enable|catalog-remove|catalog-refresh> <fixture-path> <plugin-id>"
            ));
        }
    }

    let state = read_state(&state_path)?;
    print_json(&state)
}
