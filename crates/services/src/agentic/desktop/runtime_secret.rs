// Path: crates/services/src/agentic/desktop/runtime_secret.rs

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Debug)]
struct RuntimeSecretEntry {
    value: String,
    expires_at: u64,
    one_time: bool,
}

static RUNTIME_SECRETS: OnceLock<Mutex<HashMap<String, RuntimeSecretEntry>>> = OnceLock::new();

fn secret_store() -> &'static Mutex<HashMap<String, RuntimeSecretEntry>> {
    RUNTIME_SECRETS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn key_for(session_id_hex: &str, secret_kind: &str) -> String {
    format!(
        "{}::{}",
        session_id_hex.trim().to_ascii_lowercase(),
        secret_kind.trim().to_ascii_lowercase()
    )
}

fn purge_expired(secrets: &mut HashMap<String, RuntimeSecretEntry>, now: u64) {
    secrets.retain(|_, entry| entry.expires_at > now);
}

pub fn set_secret(
    session_id_hex: &str,
    secret_kind: &str,
    secret_value: String,
    one_time: bool,
    ttl_seconds: u64,
) -> Result<(), String> {
    if session_id_hex.trim().is_empty() {
        return Err("session_id_hex is required".to_string());
    }
    if secret_kind.trim().is_empty() {
        return Err("secret_kind is required".to_string());
    }
    if secret_value.is_empty() {
        return Err("secret_value is required".to_string());
    }
    if ttl_seconds == 0 {
        return Err("ttl_seconds must be > 0".to_string());
    }

    let now = now_secs();
    let expires_at = now.saturating_add(ttl_seconds);
    let mut guard = secret_store()
        .lock()
        .map_err(|_| "runtime secret store lock poisoned".to_string())?;
    purge_expired(&mut guard, now);

    guard.insert(
        key_for(session_id_hex, secret_kind),
        RuntimeSecretEntry {
            value: secret_value,
            expires_at,
            one_time,
        },
    );
    Ok(())
}

pub fn take_secret(session_id_hex: &str, secret_kind: &str) -> Option<String> {
    let now = now_secs();
    let mut guard = secret_store().lock().ok()?;
    purge_expired(&mut guard, now);

    let key = key_for(session_id_hex, secret_kind);
    if let Some(entry) = guard.get(&key).cloned() {
        if entry.one_time {
            guard.remove(&key);
        }
        return Some(entry.value);
    }
    None
}

pub fn has_secret(session_id_hex: &str, secret_kind: &str) -> bool {
    let now = now_secs();
    let mut guard = match secret_store().lock() {
        Ok(guard) => guard,
        Err(_) => return false,
    };
    purge_expired(&mut guard, now);
    guard.contains_key(&key_for(session_id_hex, secret_kind))
}

#[cfg(test)]
mod tests {
    use super::{has_secret, set_secret, take_secret};

    #[test]
    fn one_time_secret_is_consumed() {
        let session = "aa".repeat(32);
        set_secret(&session, "sudo_password", "pw1".to_string(), true, 60).expect("set secret");
        assert_eq!(
            take_secret(&session, "sudo_password").as_deref(),
            Some("pw1")
        );
        assert!(take_secret(&session, "sudo_password").is_none());
    }

    #[test]
    fn reusable_secret_is_retained() {
        let session = "bb".repeat(32);
        set_secret(&session, "sudo_password", "pw2".to_string(), false, 60).expect("set secret");
        assert!(has_secret(&session, "sudo_password"));
        assert_eq!(
            take_secret(&session, "sudo_password").as_deref(),
            Some("pw2")
        );
        assert!(has_secret(&session, "sudo_password"));
        assert_eq!(
            take_secret(&session, "sudo_password").as_deref(),
            Some("pw2")
        );
    }

    #[test]
    fn has_secret_tracks_one_time_consumption() {
        let session = "cc".repeat(32);
        set_secret(&session, "sudo_password", "pw3".to_string(), true, 60).expect("set secret");
        assert!(has_secret(&session, "sudo_password"));
        assert_eq!(
            take_secret(&session, "sudo_password").as_deref(),
            Some("pw3")
        );
        assert!(!has_secret(&session, "sudo_password"));
    }
}
