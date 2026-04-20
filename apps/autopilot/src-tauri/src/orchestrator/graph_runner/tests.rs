use super::resolve_node_execution_config;
use crate::models::{LocalEngineModelRecord, LocalEngineRegistryState};
use serde_json::json;

fn registry_with_model(model_id: &str, status: &str) -> LocalEngineRegistryState {
    LocalEngineRegistryState {
        registry_models: vec![LocalEngineModelRecord {
            model_id: model_id.to_string(),
            status: status.to_string(),
            residency: "cold".to_string(),
            installed_at_ms: 0,
            updated_at_ms: 0,
            source_uri: None,
            backend_id: None,
            hardware_profile: None,
            job_id: None,
            bytes_transferred: None,
        }],
        ..LocalEngineRegistryState::default()
    }
}

#[test]
fn resolve_node_execution_config_errors_when_binding_is_missing() {
    let config = json!({
        "logic": {
            "modelRef": "reasoning",
            "prompt": "hello"
        }
    });
    let globals = json!({
        "modelBindings": {
            "vision": {
                "modelId": "vision-fast"
            }
        }
    });

    let error = resolve_node_execution_config(
        "responses",
        &config,
        Some(&globals),
        Some(&LocalEngineRegistryState::default()),
    )
    .expect_err("binding lookup should fail");

    assert!(error.contains("reasoning"));
    assert!(error.contains("model bindings"));
}

#[test]
fn resolve_node_execution_config_injects_concrete_model_fields() {
    let config = json!({
        "logic": {
            "modelRef": "reasoning",
            "prompt": "hello"
        }
    });
    let globals = json!({
        "modelBindings": {
            "reasoning": {
                "modelId": "codex-oss-reasoner"
            }
        }
    });
    let registry = registry_with_model("codex-oss-reasoner", "installed");

    let resolved =
        resolve_node_execution_config("responses", &config, Some(&globals), Some(&registry))
            .expect("binding should resolve");

    assert_eq!(
        resolved["logic"]["modelId"].as_str(),
        Some("codex-oss-reasoner")
    );
    assert_eq!(
        resolved["logic"]["model"].as_str(),
        Some("codex-oss-reasoner")
    );
    let model_hash = resolved["logic"]["modelHash"]
        .as_str()
        .expect("model hash should be injected");
    assert_eq!(model_hash.len(), 64);
}

#[test]
fn resolve_node_execution_config_rejects_unrunnable_registry_status() {
    let config = json!({
        "logic": {
            "modelRef": "reasoning"
        }
    });
    let globals = json!({
        "modelBindings": {
            "reasoning": {
                "modelId": "codex-oss-reasoner"
            }
        }
    });
    let registry = registry_with_model("codex-oss-reasoner", "loading");

    let error =
        resolve_node_execution_config("responses", &config, Some(&globals), Some(&registry))
            .expect_err("loading models should not be treated as runnable");

    assert!(error.contains("loading"));
    assert!(error.contains("runnable"));
}
