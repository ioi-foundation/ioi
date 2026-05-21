use super::*;

static LOCAL_GPU_DEV_TEST_ENV_GUARD: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

const LOCAL_GPU_ENV_KEYS: &[&str] = &[
    "AUTOPILOT_LOCAL_GPU_DEV",
    "AUTOPILOT_LOCAL_DEV_PRESET",
    "AUTOPILOT_LOCAL_HARDWARE_PROFILE",
    "AUTOPILOT_LOCAL_GPU_TOTAL_MEMORY_MIB",
    "AUTOPILOT_LOCAL_RUNTIME_URL",
    "AUTOPILOT_LOCAL_RUNTIME_HEALTH_URL",
    "AUTOPILOT_LOCAL_RUNTIME_MODEL",
    "AUTOPILOT_ACCEPTANCE_RUNTIME_URL",
    "AUTOPILOT_ACCEPTANCE_RUNTIME_HEALTH_URL",
    "AUTOPILOT_ACCEPTANCE_RUNTIME_MODEL",
    "AUTOPILOT_LOCAL_MODEL_ID",
    "AUTOPILOT_LOCAL_EMBEDDING_MODEL",
    "AUTOPILOT_LOCAL_BACKEND_SOURCE",
    "AUTOPILOT_LOCAL_BACKEND_ID",
    "AUTOPILOT_LOCAL_MODEL_CACHE_DIR",
    "AUTOPILOT_LOCAL_BACKEND_AUTOSTART",
    "LOCAL_LLM_URL",
    "LOCAL_LLM_EMBEDDING_MODEL",
    "OLLAMA_DEFAULT_MODEL",
    "OLLAMA_MAX_LOADED_MODELS",
    "OLLAMA_NUM_PARALLEL",
    "OLLAMA_CONTEXT_LENGTH",
    "OLLAMA_KEEP_ALIVE",
    "OPENAI_MODEL",
    "OPENAI_EMBEDDING_MODEL",
];

fn with_local_gpu_env(vars: &[(&str, Option<&str>)], test: impl FnOnce()) {
    let _guard = LOCAL_GPU_DEV_TEST_ENV_GUARD.lock().unwrap();
    let saved: Vec<(String, Option<String>)> = LOCAL_GPU_ENV_KEYS
        .iter()
        .map(|key| (key.to_string(), std::env::var(key).ok()))
        .collect();

    for key in LOCAL_GPU_ENV_KEYS {
        std::env::remove_var(key);
    }
    for (key, value) in vars {
        if let Some(value) = value {
            std::env::set_var(key, value);
        }
    }

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(test));

    for (key, value) in saved {
        match value {
            Some(value) => std::env::set_var(key, value),
            None => std::env::remove_var(key),
        }
    }

    result.unwrap();
}

#[test]
fn catalog_default_preset_matches_shipped_default() {
    assert_eq!(
        catalog_default_local_gpu_dev_preset_id(),
        LOCAL_GPU_DEV_DEFAULT_PRESET
    );
}

#[test]
fn catalog_backend_source_resolves_relative_paths() {
    let resolved =
        resolve_catalog_backend_source(Some("dev/local-backends/ollama-openai".to_string()))
            .expect("relative backend source should resolve");

    assert!(std::path::PathBuf::from(&resolved).is_absolute());
    assert!(resolved.ends_with("/dev/local-backends/ollama-openai"));
}

#[test]
fn resolve_local_gpu_dev_preset_uses_catalog_for_explicit_local_preset() {
    with_local_gpu_env(
        &[(
            "AUTOPILOT_LOCAL_DEV_PRESET",
            Some("coding-executor-local-oss"),
        )],
        || {
            let preset = resolve_local_gpu_dev_preset()
                .expect("explicit local catalog preset should resolve");

            assert_eq!(preset.preset_id, "coding-executor-local-oss");
            assert_eq!(preset.runtime_model.as_deref(), Some("qwen2.5:7b"));
            assert_eq!(preset.embedding_model.as_deref(), Some("nomic-embed-text"));
            assert_eq!(
                preset.runtime_url.as_deref(),
                Some(LOCAL_GPU_DEV_DEFAULT_RUNTIME_URL)
            );
            assert_eq!(preset.backend_id.as_deref(), Some("ollama-openai"));
            assert!(preset
                .backend_source
                .as_deref()
                .unwrap_or_default()
                .ends_with("/dev/local-backends/ollama-openai"));
        },
    );
}

#[test]
fn resolve_local_gpu_dev_preset_skips_remote_catalog_entries() {
    with_local_gpu_env(
        &[("AUTOPILOT_LOCAL_DEV_PRESET", Some("remote-multimodal-lane"))],
        || {
            assert!(resolve_local_gpu_dev_preset().is_none());
        },
    );
}

#[test]
fn resolve_local_gpu_dev_preset_autoselects_qwen3_5_for_8gb_class_gpu() {
    with_local_gpu_env(
        &[
            ("AUTOPILOT_LOCAL_GPU_DEV", Some("1")),
            ("AUTOPILOT_LOCAL_GPU_TOTAL_MEMORY_MIB", Some("8151")),
        ],
        || {
            let preset =
                resolve_local_gpu_dev_preset().expect("small-gpu local preset should resolve");

            assert_eq!(preset.preset_id, "planner-grade-local-oss-qwen3-8b");
            assert_eq!(
                preset.hardware_profile.as_deref(),
                Some(LOCAL_GPU_DEV_8GB_CLASS_PROFILE)
            );
            assert_eq!(preset.runtime_model.as_deref(), Some("qwen3.5:9b"));
            assert_eq!(
                preset
                    .backend_env
                    .get("OLLAMA_MAX_LOADED_MODELS")
                    .map(String::as_str),
                Some("1")
            );
            assert_eq!(
                preset
                    .backend_env
                    .get("OLLAMA_NUM_PARALLEL")
                    .map(String::as_str),
                Some("1")
            );
            assert_eq!(
                preset
                    .backend_env
                    .get("OLLAMA_CONTEXT_LENGTH")
                    .map(String::as_str),
                Some("4096")
            );
            assert_eq!(
                preset
                    .backend_env
                    .get("OLLAMA_KEEP_ALIVE")
                    .map(String::as_str),
                Some("10m")
            );
        },
    );
}

#[test]
fn apply_local_gpu_dev_preset_env_carries_runtime_model_and_backend_env() {
    with_local_gpu_env(&[], || {
        let mut backend_env = BTreeMap::new();
        backend_env.insert("OLLAMA_MAX_LOADED_MODELS".to_string(), "1".to_string());
        backend_env.insert("OLLAMA_NUM_PARALLEL".to_string(), "1".to_string());
        backend_env.insert("OLLAMA_KEEP_ALIVE".to_string(), "10m".to_string());
        let preset = LocalGpuDevPreset {
            preset_id: "planner-grade-local-oss-qwen3-8b".to_string(),
            hardware_profile: Some(LOCAL_GPU_DEV_8GB_CLASS_PROFILE.to_string()),
            runtime_url: Some(LOCAL_GPU_DEV_DEFAULT_RUNTIME_URL.to_string()),
            runtime_health_url: Some(LOCAL_GPU_DEV_DEFAULT_HEALTH_URL.to_string()),
            runtime_model: Some("qwen3.5:9b".to_string()),
            embedding_model: Some("nomic-embed-text".to_string()),
            backend_source: Some(LOCAL_GPU_DEV_DEFAULT_BACKEND_SOURCE.to_string()),
            backend_id: Some(LOCAL_GPU_DEV_DEFAULT_BACKEND_ID.to_string()),
            model_cache_dir: Some(default_local_gpu_dev_model_cache_dir()),
            backend_env,
            backend_autostart: true,
        };

        apply_local_gpu_dev_preset_env(&preset);

        assert_eq!(
            env_text("AUTOPILOT_LOCAL_HARDWARE_PROFILE").as_deref(),
            Some(LOCAL_GPU_DEV_8GB_CLASS_PROFILE)
        );
        assert_eq!(
            env_text("AUTOPILOT_LOCAL_RUNTIME_MODEL").as_deref(),
            Some("qwen3.5:9b")
        );
        assert_eq!(
            env_text("AUTOPILOT_ACCEPTANCE_RUNTIME_URL").as_deref(),
            Some(LOCAL_GPU_DEV_DEFAULT_RUNTIME_URL)
        );
        assert_eq!(
            env_text("AUTOPILOT_ACCEPTANCE_RUNTIME_HEALTH_URL").as_deref(),
            Some(LOCAL_GPU_DEV_DEFAULT_HEALTH_URL)
        );
        assert_eq!(
            env_text("AUTOPILOT_ACCEPTANCE_RUNTIME_MODEL").as_deref(),
            Some("qwen3.5:9b")
        );
        assert_eq!(
            env_text("OLLAMA_DEFAULT_MODEL").as_deref(),
            Some("qwen3.5:9b")
        );
        assert_eq!(env_text("OLLAMA_MAX_LOADED_MODELS").as_deref(), Some("1"));
        assert_eq!(env_text("OLLAMA_NUM_PARALLEL").as_deref(), Some("1"));
        assert_eq!(env_text("OLLAMA_KEEP_ALIVE").as_deref(), Some("10m"));
    });
}
