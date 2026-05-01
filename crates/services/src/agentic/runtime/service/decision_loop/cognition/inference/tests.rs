use super::*;
use std::sync::{Mutex, OnceLock};

fn with_env<F: FnOnce()>(entries: &[(&str, Option<&str>)], f: F) {
    static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    let _guard = ENV_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .expect("test env lock poisoned");
    let saved = entries
        .iter()
        .map(|(key, _)| ((*key).to_string(), std::env::var(key).ok()))
        .collect::<Vec<_>>();
    for (key, value) in entries {
        match value {
            Some(value) => std::env::set_var(key, value),
            None => std::env::remove_var(key),
        }
    }
    f();
    for (key, value) in saved {
        match value {
            Some(value) => std::env::set_var(&key, value),
            None => std::env::remove_var(&key),
        }
    }
}

#[test]
fn cognition_timeout_defaults_to_fifteen_seconds() {
    with_env(
        &[
            ("AUTOPILOT_LOCAL_GPU_DEV", None),
            ("IOI_COGNITION_INFERENCE_TIMEOUT_SECS", None),
        ],
        || {
            assert_eq!(cognition_inference_timeout(), Duration::from_secs(15));
        },
    );
}

#[test]
fn cognition_timeout_expands_in_local_gpu_dev_mode() {
    with_env(
        &[
            ("AUTOPILOT_LOCAL_GPU_DEV", Some("1")),
            ("IOI_COGNITION_INFERENCE_TIMEOUT_SECS", None),
        ],
        || {
            assert_eq!(cognition_inference_timeout(), Duration::from_secs(60));
        },
    );
}

#[test]
fn explicit_timeout_env_overrides_local_gpu_dev_default() {
    with_env(
        &[
            ("AUTOPILOT_LOCAL_GPU_DEV", Some("1")),
            ("IOI_COGNITION_INFERENCE_TIMEOUT_SECS", Some("23")),
        ],
        || {
            assert_eq!(cognition_inference_timeout(), Duration::from_secs(23));
        },
    );
}
