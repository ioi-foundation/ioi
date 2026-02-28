use ioi_validator::common::GuardianContainer;
use std::path::{Path, PathBuf};
use tauri::{AppHandle, Manager};

pub const GUARDIAN_PASS_ENV: &str = "IOI_GUARDIAN_KEY_PASS";

pub fn ensure_guardian_key_pass() {
    if std::env::var(GUARDIAN_PASS_ENV).is_err() {
        unsafe {
            std::env::set_var(GUARDIAN_PASS_ENV, "local-mode");
        }
    }
}

pub fn identity_key_path_for_app(app: &AppHandle) -> PathBuf {
    app.path()
        .app_data_dir()
        .unwrap_or_else(|_| PathBuf::from("./ioi-data"))
        .join("identity.key")
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

pub fn load_identity_keypair_for_app(app: &AppHandle) -> Result<libp2p::identity::Keypair, String> {
    let key_path = identity_key_path_for_app(app);
    load_identity_keypair_from_file(&key_path)
}
