use ioi_validator::common::GuardianContainer;
use std::path::{Path, PathBuf};
use tauri::AppHandle;

pub const GUARDIAN_PASS_ENV: &str = "IOI_GUARDIAN_KEY_PASS";

pub fn ensure_guardian_key_pass() {
    if std::env::var(GUARDIAN_PASS_ENV).is_err() {
        unsafe {
            std::env::set_var(GUARDIAN_PASS_ENV, "local-mode");
        }
    }
}

pub fn identity_key_path_for_app(app: &AppHandle) -> PathBuf {
    crate::autopilot_data_dir_for(app).join("identity.key")
}

pub fn load_identity_keypair_from_file(
    key_path: &Path,
) -> Result<libp2p::identity::Keypair, String> {
    ensure_guardian_key_pass();

    let raw = GuardianContainer::load_encrypted_file(key_path)
        .map_err(|e| format!("Failed to load identity key: {}", e))?;
    libp2p::identity::Keypair::from_protobuf_encoding(&raw)
        .map_err(|e| format!("Failed to decode identity key: {}", e))
}

pub fn ensure_identity_keypair_at_path(
    key_path: &Path,
) -> Result<libp2p::identity::Keypair, String> {
    if key_path.exists() {
        return load_identity_keypair_from_file(key_path);
    }

    ensure_guardian_key_pass();

    if let Some(parent) = key_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create identity key directory: {}", e))?;
    }

    let keypair = libp2p::identity::Keypair::generate_ed25519();
    let encoded = keypair
        .to_protobuf_encoding()
        .map_err(|e| format!("Failed to encode identity key: {}", e))?;
    GuardianContainer::save_encrypted_file(key_path, &encoded)
        .map_err(|e| format!("Failed to save identity key: {}", e))?;

    Ok(keypair)
}

pub fn ensure_identity_keypair_for_app(
    app: &AppHandle,
) -> Result<libp2p::identity::Keypair, String> {
    let key_path = identity_key_path_for_app(app);
    ensure_identity_keypair_at_path(&key_path)
}

pub fn load_identity_keypair_for_app(app: &AppHandle) -> Result<libp2p::identity::Keypair, String> {
    ensure_identity_keypair_for_app(app)
}

#[cfg(test)]
#[path = "identity/tests.rs"]
mod tests;
