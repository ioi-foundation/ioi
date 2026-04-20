use crate::kernel::data::{
    normalize_local_engine_control_plane, normalize_local_engine_control_plane_document,
};
use crate::models::{
    LocalEngineControlPlaneDocument, LocalEngineManagedSettingsChannelRecord,
    LocalEngineManagedSettingsSnapshot,
};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use ioi_api::crypto::{SerializableKey, VerifyingKey};
use ioi_crypto::algorithms::hash::sha256;
use ioi_crypto::sign::eddsa::{Ed25519PublicKey, Ed25519Signature};
use serde_json::{Map, Value};

const LOCAL_ENGINE_MANAGED_SETTINGS_FIXTURE_ENV: &str = "IOI_MANAGED_SETTINGS_FIXTURE_PATH";
const LOCAL_ENGINE_MANAGED_SETTINGS_CHANNEL_DOMAIN: &str =
    "ioi-local-engine-managed-settings-channel-v1:";
const LOCAL_ENGINE_MANAGED_SETTINGS_STATE_CHECKPOINT_NAME: &str =
    "autopilot.local_engine_managed_settings.v1";
const LOCAL_ENGINE_MANAGED_SETTINGS_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LocalEngineManagedSettingsStateDocument {
    #[serde(default)]
    schema_version: u32,
    #[serde(default)]
    active_channel_id: Option<String>,
    #[serde(default)]
    remote_document: Option<LocalEngineControlPlaneDocument>,
    #[serde(default)]
    last_refreshed_at_ms: Option<u64>,
    #[serde(default)]
    last_successful_refresh_at_ms: Option<u64>,
    #[serde(default)]
    last_failed_refresh_at_ms: Option<u64>,
    #[serde(default)]
    refresh_error: Option<String>,
    #[serde(default)]
    channels: Vec<LocalEngineManagedSettingsChannelRecord>,
    #[serde(default)]
    local_override_patch: Value,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LocalEngineManagedSettingsFixture {
    #[serde(default)]
    channels: Vec<LocalEngineManagedSettingsChannelFixture>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LocalEngineManagedSettingsChannelFixture {
    authority_id: String,
    channel_id: String,
    label: String,
    source_uri: String,
    public_key: String,
    document: LocalEngineControlPlaneDocument,
    signature: String,
    #[serde(default)]
    signature_algorithm: Option<String>,
    #[serde(default)]
    authority_label: Option<String>,
    #[serde(default)]
    precedence: i32,
    #[serde(default)]
    issued_at_ms: Option<u64>,
    #[serde(default)]
    expires_at_ms: Option<u64>,
}

#[derive(Debug, Clone)]
pub(crate) struct LocalEngineEffectiveControlPlaneState {
    pub(crate) control_plane: LocalEngineControlPlane,
    pub(crate) managed_settings: LocalEngineManagedSettingsSnapshot,
}

#[derive(Debug, Clone)]
struct EvaluatedManagedSettingsChannel {
    record: LocalEngineManagedSettingsChannelRecord,
    remote_document: Option<LocalEngineControlPlaneDocument>,
    eligible: bool,
}

fn trim_or_empty(value: impl AsRef<str>) -> String {
    value.as_ref().trim().to_string()
}

fn managed_settings_now_ms() -> u64 {
    Utc::now().timestamp_millis().max(0) as u64
}

fn empty_patch() -> Value {
    Value::Object(Map::new())
}

fn patch_is_empty(value: &Value) -> bool {
    match value {
        Value::Object(map) => map.is_empty() || map.values().all(patch_is_empty),
        Value::Null => true,
        _ => false,
    }
}

fn normalize_patch(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut normalized = Map::new();
            for (key, entry) in map {
                let normalized_entry = normalize_patch(entry);
                if !patch_is_empty(&normalized_entry) {
                    normalized.insert(key, normalized_entry);
                }
            }
            Value::Object(normalized)
        }
        other => other,
    }
}

fn merge_patch(target: &mut Value, patch: &Value) {
    match patch {
        Value::Object(patch_map) => {
            if !target.is_object() {
                *target = Value::Object(Map::new());
            }
            let Some(target_map) = target.as_object_mut() else {
                return;
            };
            for (key, patch_value) in patch_map {
                if matches!(patch_value, Value::Null) {
                    target_map.remove(key);
                    continue;
                }
                let entry = target_map.entry(key.clone()).or_insert(Value::Null);
                merge_patch(entry, patch_value);
            }
        }
        other => {
            *target = other.clone();
        }
    }
}

fn diff_merge_patch(base: &Value, target: &Value) -> Value {
    if base == target {
        return empty_patch();
    }

    match (base, target) {
        (Value::Object(base_map), Value::Object(target_map)) => {
            let mut patch = Map::new();
            for key in base_map.keys() {
                if !target_map.contains_key(key) {
                    patch.insert(key.clone(), Value::Null);
                }
            }
            for (key, target_value) in target_map {
                match base_map.get(key) {
                    Some(base_value) => {
                        let nested = diff_merge_patch(base_value, target_value);
                        if !patch_is_empty(&nested) {
                            patch.insert(key.clone(), nested);
                        }
                    }
                    None => {
                        patch.insert(key.clone(), target_value.clone());
                    }
                }
            }
            Value::Object(patch)
        }
        _ => target.clone(),
    }
}

fn patch_field_paths(value: &Value, prefix: &str, output: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, entry) in map {
                let next_prefix = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{}.{}", prefix, key)
                };
                if entry.is_object() && !patch_is_empty(entry) {
                    patch_field_paths(entry, &next_prefix, output);
                } else if !patch_is_empty(entry) {
                    output.push(next_prefix);
                }
            }
        }
        _ => {
            if !prefix.is_empty() {
                output.push(prefix.to_string());
            }
        }
    }
}

fn local_override_fields(patch: &Value) -> Vec<String> {
    let mut fields = Vec::new();
    patch_field_paths(patch, "", &mut fields);
    fields.sort();
    fields.dedup();
    fields
}

fn managed_settings_fixture_path() -> Option<PathBuf> {
    std::env::var_os(LOCAL_ENGINE_MANAGED_SETTINGS_FIXTURE_ENV)
        .map(PathBuf::from)
        .filter(|path| !path.as_os_str().is_empty())
}

fn decode_signature_material(value: &str, subject: &str) -> Result<Vec<u8>, String> {
    BASE64_STANDARD
        .decode(trim_or_empty(value))
        .map_err(|error| format!("failed to decode {}: {}", subject, error))
}

fn managed_settings_state_from_disk(
    memory_runtime: &Arc<MemoryRuntime>,
) -> Option<LocalEngineManagedSettingsStateDocument> {
    crate::orchestrator::store::load_global_checkpoint_json(
        memory_runtime,
        LOCAL_ENGINE_MANAGED_SETTINGS_STATE_CHECKPOINT_NAME,
    )
    .map(normalize_managed_settings_state_document)
}

fn save_managed_settings_state(
    memory_runtime: &Arc<MemoryRuntime>,
    document: &LocalEngineManagedSettingsStateDocument,
) {
    crate::orchestrator::store::persist_global_checkpoint_json(
        memory_runtime,
        LOCAL_ENGINE_MANAGED_SETTINGS_STATE_CHECKPOINT_NAME,
        document,
    );
}

fn normalize_managed_settings_state_document(
    mut document: LocalEngineManagedSettingsStateDocument,
) -> LocalEngineManagedSettingsStateDocument {
    document.schema_version = document
        .schema_version
        .max(LOCAL_ENGINE_MANAGED_SETTINGS_SCHEMA_VERSION);
    document.active_channel_id = document
        .active_channel_id
        .map(trim_or_empty)
        .filter(|value| !value.is_empty());
    document.refresh_error = document
        .refresh_error
        .map(trim_or_empty)
        .filter(|value| !value.is_empty());
    document.remote_document = document
        .remote_document
        .map(normalize_local_engine_control_plane_document);
    document.channels = document
        .channels
        .into_iter()
        .map(|mut record| {
            record.channel_id = trim_or_empty(record.channel_id);
            record.label = trim_or_empty(record.label);
            record.source_uri = trim_or_empty(record.source_uri);
            record.status = trim_or_empty(record.status);
            record.verification_status = trim_or_empty(record.verification_status);
            record.summary = trim_or_empty(record.summary);
            record.authority_label = record
                .authority_label
                .map(trim_or_empty)
                .filter(|value| !value.is_empty());
            record.signature_algorithm = record
                .signature_algorithm
                .map(trim_or_empty)
                .filter(|value| !value.is_empty());
            record.profile_id = record
                .profile_id
                .map(trim_or_empty)
                .filter(|value| !value.is_empty());
            record.overridden_fields = record
                .overridden_fields
                .into_iter()
                .map(trim_or_empty)
                .filter(|value| !value.is_empty())
                .collect();
            record
        })
        .filter(|record| !record.channel_id.is_empty())
        .collect();
    document.local_override_patch = normalize_patch(document.local_override_patch);
    if patch_is_empty(&document.local_override_patch) {
        document.local_override_patch = empty_patch();
    }
    document
}

fn control_plane_document_digest(document: &LocalEngineControlPlaneDocument) -> Result<String, String> {
    let normalized = normalize_local_engine_control_plane_document(document.clone());
    let bytes = serde_json::to_vec(&normalized)
        .map_err(|error| format!("failed to encode managed settings document: {}", error))?;
    sha256(&bytes)
        .map(hex::encode)
        .map_err(|error| format!("failed to hash managed settings document: {}", error))
}

pub(crate) fn managed_settings_channel_message(
    authority_id: &str,
    channel_id: &str,
    label: &str,
    source_uri: &str,
    precedence: i32,
    issued_at_ms: Option<u64>,
    expires_at_ms: Option<u64>,
    document: &LocalEngineControlPlaneDocument,
) -> Result<Vec<u8>, String> {
    let digest = control_plane_document_digest(document)?;
    Ok(format!(
        "{LOCAL_ENGINE_MANAGED_SETTINGS_CHANNEL_DOMAIN}{}\nchannelId={}\nlabel={}\nsourceUri={}\nprecedence={}\nissuedAtMs={}\nexpiresAtMs={}\nprofileId={}\nschemaVersion={}\ndocumentSha256={}\n",
        trim_or_empty(authority_id),
        trim_or_empty(channel_id),
        trim_or_empty(label),
        trim_or_empty(source_uri),
        precedence,
        issued_at_ms.unwrap_or(0),
        expires_at_ms.unwrap_or(0),
        trim_or_empty(&document.profile_id),
        document.schema_version,
        digest,
    )
    .into_bytes())
}

fn managed_settings_channel_fixture_message(
    fixture: &LocalEngineManagedSettingsChannelFixture,
) -> Result<Vec<u8>, String> {
    managed_settings_channel_message(
        &fixture.authority_id,
        &fixture.channel_id,
        &fixture.label,
        &fixture.source_uri,
        fixture.precedence,
        fixture.issued_at_ms,
        fixture.expires_at_ms,
        &fixture.document,
    )
}

fn evaluate_managed_settings_channel(
    fixture: LocalEngineManagedSettingsChannelFixture,
    refreshed_at_ms: u64,
) -> EvaluatedManagedSettingsChannel {
    let normalized_document = normalize_local_engine_control_plane_document(fixture.document.clone());
    let mut record = LocalEngineManagedSettingsChannelRecord {
        channel_id: trim_or_empty(&fixture.channel_id),
        label: trim_or_empty(&fixture.label),
        source_uri: trim_or_empty(&fixture.source_uri),
        status: "invalid".to_string(),
        verification_status: "invalid".to_string(),
        summary: "Managed settings channel could not be verified.".to_string(),
        precedence: fixture.precedence,
        authority_label: fixture
            .authority_label
            .clone()
            .map(trim_or_empty)
            .filter(|value| !value.is_empty()),
        signature_algorithm: fixture
            .signature_algorithm
            .clone()
            .map(trim_or_empty)
            .filter(|value| !value.is_empty())
            .or(Some("ed25519".to_string())),
        profile_id: Some(normalized_document.profile_id.clone()),
        schema_version: Some(normalized_document.schema_version),
        issued_at_ms: fixture.issued_at_ms,
        expires_at_ms: fixture.expires_at_ms,
        refreshed_at_ms: Some(refreshed_at_ms),
        local_override_count: 0,
        overridden_fields: Vec::new(),
    };

    let signature_algorithm = record
        .signature_algorithm
        .clone()
        .unwrap_or_else(|| "ed25519".to_string());
    if !signature_algorithm.eq_ignore_ascii_case("ed25519") {
        record.verification_status = "unsupported_algorithm".to_string();
        record.summary = format!(
            "Managed settings channel '{}' uses unsupported signature algorithm '{}'.",
            record.label, signature_algorithm
        );
        return EvaluatedManagedSettingsChannel {
            record,
            remote_document: None,
            eligible: false,
        };
    }

    let public_key_bytes = match decode_signature_material(&fixture.public_key, "managed settings public key") {
        Ok(bytes) => bytes,
        Err(error) => {
            record.verification_status = "invalid_public_key".to_string();
            record.summary = error;
            return EvaluatedManagedSettingsChannel {
                record,
                remote_document: None,
                eligible: false,
            };
        }
    };
    let public_key =
        match <Ed25519PublicKey as SerializableKey>::from_bytes(&public_key_bytes) {
            Ok(public_key) => public_key,
            Err(error) => {
                record.verification_status = "invalid_public_key".to_string();
                record.summary = format!(
                    "Failed to parse managed settings public key: {}",
                    error
                );
                return EvaluatedManagedSettingsChannel {
                    record,
                    remote_document: None,
                    eligible: false,
                };
            }
        };

    let signature_bytes = match decode_signature_material(&fixture.signature, "managed settings signature") {
        Ok(bytes) => bytes,
        Err(error) => {
            record.verification_status = "invalid_signature".to_string();
            record.summary = error;
            return EvaluatedManagedSettingsChannel {
                record,
                remote_document: None,
                eligible: false,
            };
        }
    };
    let signature = match <Ed25519Signature as SerializableKey>::from_bytes(&signature_bytes) {
        Ok(signature) => signature,
        Err(error) => {
            record.verification_status = "invalid_signature".to_string();
            record.summary = format!("Failed to parse managed settings signature: {}", error);
            return EvaluatedManagedSettingsChannel {
                record,
                remote_document: None,
                eligible: false,
            };
        }
    };
    let message = match managed_settings_channel_fixture_message(&fixture) {
        Ok(message) => message,
        Err(error) => {
            record.verification_status = "invalid_payload".to_string();
            record.summary = error;
            return EvaluatedManagedSettingsChannel {
                record,
                remote_document: None,
                eligible: false,
            };
        }
    };
    if public_key.verify(&message, &signature).is_err() {
        record.verification_status = "invalid_signature".to_string();
        record.summary = format!(
            "Managed settings channel '{}' failed signature verification.",
            record.label
        );
        return EvaluatedManagedSettingsChannel {
            record,
            remote_document: None,
            eligible: false,
        };
    }

    if fixture
        .expires_at_ms
        .is_some_and(|expires_at_ms| expires_at_ms <= refreshed_at_ms)
    {
        record.status = "expired".to_string();
        record.verification_status = "expired".to_string();
        record.summary = format!(
            "Managed settings channel '{}' verified but is expired.",
            record.label
        );
        return EvaluatedManagedSettingsChannel {
            record,
            remote_document: None,
            eligible: false,
        };
    }

    record.status = "ready".to_string();
    record.verification_status = "verified".to_string();
    record.summary = format!(
        "Signed managed settings channel '{}' verified under '{}'.",
        record.label,
        record
            .authority_label
            .as_deref()
            .unwrap_or("managed settings authority")
    );
    EvaluatedManagedSettingsChannel {
        record,
        remote_document: Some(normalized_document),
        eligible: true,
    }
}

fn build_managed_settings_snapshot(
    state: &LocalEngineManagedSettingsStateDocument,
    local_override_fields: Vec<String>,
) -> LocalEngineManagedSettingsSnapshot {
    let active_channel = state
        .active_channel_id
        .as_deref()
        .and_then(|channel_id| {
            state
                .channels
                .iter()
                .find(|record| record.channel_id == channel_id)
        });
    let sync_status = if state.remote_document.is_some() {
        if state.refresh_error.is_some() {
            "degraded".to_string()
        } else {
            "managed".to_string()
        }
    } else if state.channels.is_empty() && state.refresh_error.is_none() {
        "local_only".to_string()
    } else {
        "degraded".to_string()
    };
    let summary = if let Some(active) = active_channel {
        if local_override_fields.is_empty() {
            format!(
                "Signed managed settings channel '{}' is active for the Local Engine control plane.",
                active.label
            )
        } else {
            format!(
                "Signed managed settings channel '{}' is active with {} local override{}.",
                active.label,
                local_override_fields.len(),
                if local_override_fields.len() == 1 { "" } else { "s" }
            )
        }
    } else if let Some(error) = state.refresh_error.as_deref() {
        error.to_string()
    } else {
        "No remote-managed settings channel is active; local settings remain authoritative."
            .to_string()
    };

    LocalEngineManagedSettingsSnapshot {
        sync_status,
        summary,
        active_channel_id: active_channel.map(|record| record.channel_id.clone()),
        active_channel_label: active_channel.map(|record| record.label.clone()),
        active_source_uri: active_channel.map(|record| record.source_uri.clone()),
        last_refreshed_at_ms: state.last_refreshed_at_ms,
        last_successful_refresh_at_ms: state.last_successful_refresh_at_ms,
        last_failed_refresh_at_ms: state.last_failed_refresh_at_ms,
        refresh_error: state.refresh_error.clone(),
        local_override_count: local_override_fields.len(),
        local_override_fields,
        channels: state.channels.clone(),
    }
}

fn load_or_initialize_managed_settings_state(
    memory_runtime: &Arc<MemoryRuntime>,
) -> LocalEngineManagedSettingsStateDocument {
    if let Some(document) = managed_settings_state_from_disk(memory_runtime) {
        return document;
    }

    if managed_settings_fixture_path().is_some() {
        return match refresh_managed_settings_state(memory_runtime) {
            Ok(document) => document,
            Err(error) => {
                let timestamp = managed_settings_now_ms();
                let document = normalize_managed_settings_state_document(
                    LocalEngineManagedSettingsStateDocument {
                        schema_version: LOCAL_ENGINE_MANAGED_SETTINGS_SCHEMA_VERSION,
                        last_refreshed_at_ms: Some(timestamp),
                        last_failed_refresh_at_ms: Some(timestamp),
                        refresh_error: Some(error),
                        local_override_patch: empty_patch(),
                        ..LocalEngineManagedSettingsStateDocument::default()
                    },
                );
                save_managed_settings_state(memory_runtime, &document);
                document
            }
        };
    }

    let document = normalize_managed_settings_state_document(
        LocalEngineManagedSettingsStateDocument {
            schema_version: LOCAL_ENGINE_MANAGED_SETTINGS_SCHEMA_VERSION,
            local_override_patch: empty_patch(),
            ..LocalEngineManagedSettingsStateDocument::default()
        },
    );
    save_managed_settings_state(memory_runtime, &document);
    document
}

fn refresh_managed_settings_state(
    memory_runtime: &Arc<MemoryRuntime>,
) -> Result<LocalEngineManagedSettingsStateDocument, String> {
    let fixture_path = managed_settings_fixture_path().ok_or_else(|| {
        format!(
            "{} is not configured for managed settings refresh.",
            LOCAL_ENGINE_MANAGED_SETTINGS_FIXTURE_ENV
        )
    })?;
    let raw = fs::read_to_string(&fixture_path).map_err(|error| {
        format!(
            "failed to read managed settings fixture '{}': {}",
            fixture_path.display(),
            error
        )
    })?;
    let fixture: LocalEngineManagedSettingsFixture = serde_json::from_str(&raw).map_err(|error| {
        format!(
            "failed to parse managed settings fixture '{}': {}",
            fixture_path.display(),
            error
        )
    })?;

    let refreshed_at_ms = managed_settings_now_ms();
    let mut existing = managed_settings_state_from_disk(memory_runtime).unwrap_or_default();
    existing = normalize_managed_settings_state_document(existing);
    let local_override_patch = existing.local_override_patch.clone();

    let mut evaluated = fixture
        .channels
        .into_iter()
        .map(|channel| evaluate_managed_settings_channel(channel, refreshed_at_ms))
        .collect::<Vec<_>>();
    evaluated.sort_by(|left, right| {
        right
            .record
            .precedence
            .cmp(&left.record.precedence)
            .then_with(|| {
                right
                    .record
                    .issued_at_ms
                    .unwrap_or(0)
                    .cmp(&left.record.issued_at_ms.unwrap_or(0))
            })
            .then_with(|| left.record.channel_id.cmp(&right.record.channel_id))
    });

    let active_channel_id = evaluated
        .iter()
        .find(|candidate| candidate.eligible)
        .map(|candidate| candidate.record.channel_id.clone());
    let remote_document = active_channel_id.as_deref().and_then(|channel_id| {
        evaluated
            .iter()
            .find(|candidate| candidate.record.channel_id == channel_id)
            .and_then(|candidate| candidate.remote_document.clone())
    });
    let override_fields = local_override_fields(&local_override_patch);
    let channels = evaluated
        .into_iter()
        .map(|mut candidate| {
            if active_channel_id
                .as_deref()
                .is_some_and(|channel_id| channel_id == candidate.record.channel_id)
            {
                candidate.record.status = "active".to_string();
                candidate.record.local_override_count = override_fields.len();
                candidate.record.overridden_fields = override_fields.clone();
                if !override_fields.is_empty() {
                    candidate.record.summary = format!(
                        "{} {} local override{} applied.",
                        candidate.record.summary,
                        override_fields.len(),
                        if override_fields.len() == 1 { " is" } else { "s are" }
                    );
                }
            } else if candidate.eligible {
                candidate.record.status = "shadowed".to_string();
                candidate.record.summary = format!(
                    "Managed settings channel '{}' verified but is shadowed by a higher-precedence channel.",
                    candidate.record.label
                );
            }
            candidate.record
        })
        .collect::<Vec<_>>();

    let mut next = LocalEngineManagedSettingsStateDocument {
        schema_version: LOCAL_ENGINE_MANAGED_SETTINGS_SCHEMA_VERSION,
        active_channel_id: existing.active_channel_id.clone(),
        remote_document: existing.remote_document.clone(),
        last_refreshed_at_ms: Some(refreshed_at_ms),
        last_successful_refresh_at_ms: existing.last_successful_refresh_at_ms,
        last_failed_refresh_at_ms: existing.last_failed_refresh_at_ms,
        refresh_error: None,
        channels,
        local_override_patch,
    };

    if let Some(active_channel_id) = active_channel_id {
        next.active_channel_id = Some(active_channel_id);
        next.remote_document = remote_document;
        next.last_successful_refresh_at_ms = Some(refreshed_at_ms);
        next.refresh_error = None;
    } else {
        next.last_failed_refresh_at_ms = Some(refreshed_at_ms);
        next.refresh_error = Some(
            "Managed settings refresh found no verified non-expired channels; retained the last known local or managed baseline."
                .to_string(),
        );
    }

    let next = normalize_managed_settings_state_document(next);
    save_managed_settings_state(memory_runtime, &next);
    Ok(next)
}

pub(crate) fn refresh_local_engine_managed_settings(
    memory_runtime: &Arc<MemoryRuntime>,
    local_document: &LocalEngineControlPlaneDocument,
) -> Result<LocalEngineManagedSettingsSnapshot, String> {
    let _ = refresh_managed_settings_state(memory_runtime)?;
    Ok(
        effective_control_plane_state(memory_runtime, local_document)
            .managed_settings,
    )
}

pub(crate) fn clear_local_engine_managed_settings_overrides(
    memory_runtime: &Arc<MemoryRuntime>,
    local_document: &LocalEngineControlPlaneDocument,
) -> Result<LocalEngineManagedSettingsSnapshot, String> {
    let mut state = load_or_initialize_managed_settings_state(memory_runtime);
    state.local_override_patch = empty_patch();
    for channel in &mut state.channels {
        channel.local_override_count = 0;
        channel.overridden_fields.clear();
        if channel.status == "active" && channel.summary.contains("local override") {
            channel.summary = format!(
                "Signed managed settings channel '{}' verified under '{}'.",
                channel.label,
                channel
                    .authority_label
                    .as_deref()
                    .unwrap_or("managed settings authority")
            );
        }
    }
    let state = normalize_managed_settings_state_document(state);
    save_managed_settings_state(memory_runtime, &state);
    Ok(
        effective_control_plane_state(memory_runtime, local_document)
            .managed_settings,
    )
}

pub(crate) fn save_local_engine_control_plane_with_managed_settings(
    memory_runtime: &Arc<MemoryRuntime>,
    control_plane: LocalEngineControlPlane,
) -> Result<LocalEngineControlPlane, String> {
    let normalized = normalize_local_engine_control_plane(control_plane);
    crate::orchestrator::save_local_engine_control_plane(memory_runtime, &normalized);

    let mut state = load_or_initialize_managed_settings_state(memory_runtime);
    if let Some(remote_document) = state.remote_document.clone() {
        let base = serde_json::to_value(normalize_local_engine_control_plane(
            remote_document.control_plane,
        ))
        .map_err(|error| format!("failed to encode managed settings base: {}", error))?;
        let target = serde_json::to_value(normalized.clone())
            .map_err(|error| format!("failed to encode managed settings target: {}", error))?;
        state.local_override_patch = normalize_patch(diff_merge_patch(&base, &target));
        let override_fields = local_override_fields(&state.local_override_patch);
        for channel in &mut state.channels {
            if state
                .active_channel_id
                .as_deref()
                .is_some_and(|channel_id| channel_id == channel.channel_id)
            {
                channel.local_override_count = override_fields.len();
                channel.overridden_fields = override_fields.clone();
            } else {
                channel.local_override_count = 0;
                channel.overridden_fields.clear();
            }
        }
    } else if !patch_is_empty(&state.local_override_patch) {
        state.local_override_patch = empty_patch();
        for channel in &mut state.channels {
            channel.local_override_count = 0;
            channel.overridden_fields.clear();
        }
    }

    let state = normalize_managed_settings_state_document(state);
    save_managed_settings_state(memory_runtime, &state);
    Ok(normalized)
}

fn effective_remote_control_plane(
    remote_document: &LocalEngineControlPlaneDocument,
    local_override_patch: &Value,
) -> Result<LocalEngineControlPlane, String> {
    let base = serde_json::to_value(normalize_local_engine_control_plane(
        remote_document.control_plane.clone(),
    ))
    .map_err(|error| format!("failed to encode managed settings base: {}", error))?;
    let mut merged = base;
    if !patch_is_empty(local_override_patch) {
        merge_patch(&mut merged, local_override_patch);
    }
    let control_plane: LocalEngineControlPlane = serde_json::from_value(merged).map_err(|error| {
        format!(
            "failed to decode effective managed settings control plane: {}",
            error
        )
    })?;
    Ok(normalize_local_engine_control_plane(control_plane))
}

pub(crate) fn effective_control_plane_state(
    memory_runtime: &Arc<MemoryRuntime>,
    local_document: &LocalEngineControlPlaneDocument,
) -> LocalEngineEffectiveControlPlaneState {
    let state = load_or_initialize_managed_settings_state(memory_runtime);
    let override_fields = local_override_fields(&state.local_override_patch);
    let mut managed_settings = build_managed_settings_snapshot(&state, override_fields.clone());

    let control_plane = match state.remote_document.as_ref() {
        Some(remote_document) => match effective_remote_control_plane(
            remote_document,
            &state.local_override_patch,
        ) {
            Ok(control_plane) => control_plane,
            Err(error) => {
                managed_settings.sync_status = "degraded".to_string();
                managed_settings.refresh_error = Some(error.clone());
                managed_settings.summary = error;
                local_document.control_plane.clone()
            }
        },
        None => local_document.control_plane.clone(),
    };

    LocalEngineEffectiveControlPlaneState {
        control_plane,
        managed_settings,
    }
}

#[cfg(test)]
#[path = "managed_settings/managed_settings_tests.rs"]
mod managed_settings_tests;
