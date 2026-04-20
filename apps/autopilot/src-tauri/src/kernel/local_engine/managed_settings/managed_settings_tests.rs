use super::{
    effective_control_plane_state, managed_settings_channel_message,
    refresh_local_engine_managed_settings, save_local_engine_control_plane_with_managed_settings,
    LOCAL_ENGINE_MANAGED_SETTINGS_FIXTURE_ENV,
};
use crate::kernel::data::default_local_engine_control_plane_document;
use crate::models::LocalEngineControlPlaneDocument;
use crate::open_or_create_memory_runtime;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use ioi_api::crypto::{SerializableKey, SigningKeyPair as _};
use ioi_crypto::sign::eddsa::Ed25519KeyPair;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use uuid::Uuid;

fn temp_dir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "autopilot-managed-settings-test-{}",
        Uuid::new_v4()
    ));
    fs::create_dir_all(&dir).expect("temp dir");
    dir
}

fn write_fixture(path: &Path, channels: &[serde_json::Value]) {
    fs::write(
        path,
        serde_json::to_vec_pretty(&serde_json::json!({ "channels": channels }))
            .expect("encode fixture"),
    )
    .expect("write fixture");
}

fn signed_channel(
    keypair: &Ed25519KeyPair,
    authority_id: &str,
    authority_label: &str,
    channel_id: &str,
    label: &str,
    source_uri: &str,
    precedence: i32,
    document: LocalEngineControlPlaneDocument,
    issued_at_ms: u64,
) -> serde_json::Value {
    let message = managed_settings_channel_message(
        authority_id,
        channel_id,
        label,
        source_uri,
        precedence,
        Some(issued_at_ms),
        None,
        &document,
    )
    .expect("message");
    let signature = keypair.sign(&message).expect("sign message");
    serde_json::json!({
        "authorityId": authority_id,
        "authorityLabel": authority_label,
        "channelId": channel_id,
        "label": label,
        "sourceUri": source_uri,
        "publicKey": BASE64_STANDARD.encode(keypair.public_key().to_bytes()),
        "signature": BASE64_STANDARD.encode(signature.to_bytes()),
        "signatureAlgorithm": "ed25519",
        "precedence": precedence,
        "issuedAtMs": issued_at_ms,
        "document": document,
    })
}

#[test]
fn refresh_selects_highest_precedence_verified_channel() {
    let data_dir = temp_dir();
    let fixture_dir = temp_dir();
    let fixture_path = fixture_dir.join("managed-settings.json");
    let memory_runtime =
        Arc::new(open_or_create_memory_runtime(&data_dir).expect("memory runtime"));
    let keypair = Ed25519KeyPair::generate().expect("keypair");

    let mut stable = default_local_engine_control_plane_document();
    stable.profile_id = "managed.settings.stable".to_string();
    stable.control_plane.runtime.default_model = "gpt-4o".to_string();

    let mut canary = stable.clone();
    canary.profile_id = "managed.settings.canary".to_string();
    canary.control_plane.runtime.default_model = "gpt-4.1-mini".to_string();

    write_fixture(
        &fixture_path,
        &[
            signed_channel(
                &keypair,
                "managed.settings.root",
                "Managed settings root",
                "stable",
                "Stable",
                "fixture://managed-settings/stable",
                10,
                stable,
                1_710_000_000_000,
            ),
            signed_channel(
                &keypair,
                "managed.settings.root",
                "Managed settings root",
                "canary",
                "Canary",
                "fixture://managed-settings/canary",
                20,
                canary,
                1_710_000_100_000,
            ),
        ],
    );

    std::env::set_var(
        LOCAL_ENGINE_MANAGED_SETTINGS_FIXTURE_ENV,
        fixture_path.display().to_string(),
    );
    let local_document = default_local_engine_control_plane_document();
    let snapshot = refresh_local_engine_managed_settings(&memory_runtime, &local_document)
        .expect("refresh snapshot");
    let effective = effective_control_plane_state(&memory_runtime, &local_document);

    assert_eq!(snapshot.sync_status, "managed");
    assert_eq!(snapshot.active_channel_id.as_deref(), Some("canary"));
    assert_eq!(
        effective.control_plane.runtime.default_model,
        "gpt-4.1-mini"
    );

    std::env::remove_var(LOCAL_ENGINE_MANAGED_SETTINGS_FIXTURE_ENV);
    let _ = fs::remove_dir_all(data_dir);
    let _ = fs::remove_dir_all(fixture_dir);
}

#[test]
fn save_persists_local_override_patch_over_managed_channel() {
    let data_dir = temp_dir();
    let fixture_dir = temp_dir();
    let fixture_path = fixture_dir.join("managed-settings.json");
    let memory_runtime =
        Arc::new(open_or_create_memory_runtime(&data_dir).expect("memory runtime"));
    let keypair = Ed25519KeyPair::generate().expect("keypair");

    let mut document = default_local_engine_control_plane_document();
    document.profile_id = "managed.settings.runtime".to_string();
    document.control_plane.runtime.default_model = "gpt-4o".to_string();

    write_fixture(
        &fixture_path,
        &[signed_channel(
            &keypair,
            "managed.settings.root",
            "Managed settings root",
            "runtime",
            "Runtime",
            "fixture://managed-settings/runtime",
            10,
            document.clone(),
            1_710_000_000_000,
        )],
    );

    std::env::set_var(
        LOCAL_ENGINE_MANAGED_SETTINGS_FIXTURE_ENV,
        fixture_path.display().to_string(),
    );
    let _ = refresh_local_engine_managed_settings(&memory_runtime, &document)
        .expect("refresh snapshot");

    let mut override_control_plane = document.control_plane.clone();
    override_control_plane.runtime.default_model = "gpt-4.1".to_string();
    override_control_plane.memory.threshold_percent = 88;
    save_local_engine_control_plane_with_managed_settings(
        &memory_runtime,
        override_control_plane,
    )
    .expect("save control plane");

    let effective = effective_control_plane_state(&memory_runtime, &document);
    assert_eq!(effective.managed_settings.local_override_count, 2);
    assert!(effective
        .managed_settings
        .local_override_fields
        .contains(&"runtime.defaultModel".to_string()));
    assert!(effective
        .managed_settings
        .local_override_fields
        .contains(&"memory.thresholdPercent".to_string()));
    assert_eq!(effective.control_plane.runtime.default_model, "gpt-4.1");
    assert_eq!(effective.control_plane.memory.threshold_percent, 88);

    std::env::remove_var(LOCAL_ENGINE_MANAGED_SETTINGS_FIXTURE_ENV);
    let _ = fs::remove_dir_all(data_dir);
    let _ = fs::remove_dir_all(fixture_dir);
}

#[test]
fn invalid_signature_falls_back_to_local_settings() {
    let data_dir = temp_dir();
    let fixture_dir = temp_dir();
    let fixture_path = fixture_dir.join("managed-settings.json");
    let memory_runtime =
        Arc::new(open_or_create_memory_runtime(&data_dir).expect("memory runtime"));
    let keypair = Ed25519KeyPair::generate().expect("keypair");

    let document = default_local_engine_control_plane_document();
    let mut channel = signed_channel(
        &keypair,
        "managed.settings.root",
        "Managed settings root",
        "runtime",
        "Runtime",
        "fixture://managed-settings/runtime",
        10,
        document.clone(),
        1_710_000_000_000,
    );
    channel["signature"] = serde_json::json!("invalid-signature");
    write_fixture(&fixture_path, &[channel]);

    std::env::set_var(
        LOCAL_ENGINE_MANAGED_SETTINGS_FIXTURE_ENV,
        fixture_path.display().to_string(),
    );
    let snapshot =
        refresh_local_engine_managed_settings(&memory_runtime, &document).expect("refresh");
    assert_eq!(snapshot.sync_status, "degraded");
    let effective = effective_control_plane_state(&memory_runtime, &document);
    assert_eq!(effective.managed_settings.sync_status, "degraded");
    assert_eq!(
        effective.control_plane.runtime.default_model,
        document.control_plane.runtime.default_model
    );

    std::env::remove_var(LOCAL_ENGINE_MANAGED_SETTINGS_FIXTURE_ENV);
    let _ = fs::remove_dir_all(data_dir);
    let _ = fs::remove_dir_all(fixture_dir);
}
