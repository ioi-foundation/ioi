{
    // First-party kernel model/backend/gallery lifecycle controls.
    let allow_model_registry_control =
        is_tool_allowed_for_resolution(resolved_intent, "model_registry__load")
            || is_tool_allowed_for_resolution(resolved_intent, "model_registry__unload")
            || is_tool_allowed_for_resolution(resolved_intent, "model_registry__install")
            || is_tool_allowed_for_resolution(resolved_intent, "backend__install")
            || is_tool_allowed_for_resolution(resolved_intent, "gallery__sync");

    if allow_model_registry_control {
        let install_params = json!({
            "type": "object",
            "properties": {
                "model_id": {
                    "type": "string",
                    "description": "Canonical model identifier to install into the kernel registry."
                },
                "source_uri": {
                    "type": "string",
                    "description": "Gallery URI, OCI source, URL, or filesystem source for the install."
                },
                "backend_id": {
                    "type": "string",
                    "description": "Optional backend/runtime identifier associated with the install."
                },
                "hardware_profile": {
                    "type": "string",
                    "description": "Optional target hardware profile label."
                },
                "job_id": {
                    "type": "string",
                    "description": "Optional control-plane job identifier when resuming a staged install."
                }
            },
            "required": ["model_id", "source_uri"]
        });
        tools.push(LlmToolDefinition {
            name: "model_registry__install".to_string(),
            description:
                "Queue or submit a model install into the first-party kernel registry. Use this instead of shell-level downloads when the task is about local model lifecycle."
                    .to_string(),
            parameters: install_params.to_string(),
        });

        let apply_params = json!({
            "type": "object",
            "properties": {
                "model_id": {
                    "type": "string",
                    "description": "Canonical model identifier to activate or apply."
                },
                "backend_id": {
                    "type": "string",
                    "description": "Optional backend/runtime identifier to bind."
                },
                "hardware_profile": {
                    "type": "string",
                    "description": "Optional target hardware profile label."
                }
            },
            "required": ["model_id"]
        });
        tools.push(LlmToolDefinition {
            name: "model_registry__apply".to_string(),
            description:
                "Apply registry metadata or activation policy for an installed model inside the kernel control plane."
                    .to_string(),
            parameters: apply_params.to_string(),
        });

        let delete_params = json!({
            "type": "object",
            "properties": {
                "model_id": {
                    "type": "string",
                    "description": "Canonical model identifier to delete from the kernel registry."
                },
                "job_id": {
                    "type": "string",
                    "description": "Optional lifecycle job identifier associated with the deletion."
                }
            },
            "required": ["model_id"]
        });
        tools.push(LlmToolDefinition {
            name: "model_registry__delete".to_string(),
            description:
                "Delete or remove an installed model artifact through the first-party kernel registry."
                    .to_string(),
            parameters: delete_params.to_string(),
        });

        let load_params = json!({
            "type": "object",
            "properties": {
                "model_id": {
                    "type": "string",
                    "description": "Canonical model identifier to load into the kernel runtime."
                },
                "path": {
                    "type": "string",
                    "description": "Filesystem path to the installed model artifact to load."
                },
                "model_hash": {
                    "type": "string",
                    "description": "Optional deterministic model hash. If omitted, the kernel derives one from `model_id`."
                },
                "backend_id": {
                    "type": "string",
                    "description": "Optional backend/runtime identifier for observability."
                },
                "hardware_profile": {
                    "type": "string",
                    "description": "Optional target hardware profile label such as cpu, gpu, or metal."
                }
            },
            "required": ["model_id", "path"]
        });
        tools.push(LlmToolDefinition {
            name: "model_registry__load".to_string(),
            description:
                "Load or warm an already installed local model into the first-party kernel runtime. Use this instead of shell commands or package-manager flows when the task is about model residency."
                    .to_string(),
            parameters: load_params.to_string(),
        });

        let unload_params = json!({
            "type": "object",
            "properties": {
                "model_id": {
                    "type": "string",
                    "description": "Canonical model identifier to unload from the kernel runtime."
                },
                "model_hash": {
                    "type": "string",
                    "description": "Optional deterministic model hash if the model was addressed by hash rather than id."
                },
                "backend_id": {
                    "type": "string",
                    "description": "Optional backend/runtime identifier for observability."
                },
                "hardware_profile": {
                    "type": "string",
                    "description": "Optional hardware profile label associated with the loaded residency."
                }
            },
            "required": ["model_id"]
        });
        tools.push(LlmToolDefinition {
            name: "model_registry__unload".to_string(),
            description:
                "Unload or evict a currently resident local model from the first-party kernel runtime to free memory or VRAM. Use this instead of shell-level process control."
                    .to_string(),
            parameters: unload_params.to_string(),
        });

        let backend_install_params = json!({
            "type": "object",
            "properties": {
                "backend_id": {
                    "type": "string",
                    "description": "Canonical backend identifier to install."
                },
                "source_uri": {
                    "type": "string",
                    "description": "Gallery URI, OCI image, URL, or filesystem source for the backend."
                },
                "alias": {
                    "type": "string",
                    "description": "Optional alias to use when presenting the backend in Studio."
                },
                "job_id": {
                    "type": "string",
                    "description": "Optional lifecycle job identifier when resuming a staged backend install."
                }
            },
            "required": ["backend_id", "source_uri"]
        });
        tools.push(LlmToolDefinition {
            name: "backend__install".to_string(),
            description:
                "Queue or submit a backend install into the kernel control plane instead of using package managers or manual scripts."
                    .to_string(),
            parameters: backend_install_params.to_string(),
        });

        let backend_apply_params = json!({
            "type": "object",
            "properties": {
                "backend_id": {
                    "type": "string",
                    "description": "Canonical backend identifier to apply or activate."
                },
                "hardware_profile": {
                    "type": "string",
                    "description": "Optional target hardware profile label."
                }
            },
            "required": ["backend_id"]
        });
        tools.push(LlmToolDefinition {
            name: "backend__apply".to_string(),
            description:
                "Apply backend configuration or activation policy through the kernel control plane."
                    .to_string(),
            parameters: backend_apply_params.to_string(),
        });

        let backend_delete_params = json!({
            "type": "object",
            "properties": {
                "backend_id": {
                    "type": "string",
                    "description": "Canonical backend identifier to delete."
                }
            },
            "required": ["backend_id"]
        });
        tools.push(LlmToolDefinition {
            name: "backend__delete".to_string(),
            description:
                "Delete a managed backend from the kernel control plane."
                    .to_string(),
            parameters: backend_delete_params.to_string(),
        });

        let backend_start_stop_params = json!({
            "type": "object",
            "properties": {
                "backend_id": {
                    "type": "string",
                    "description": "Canonical backend identifier to supervise."
                },
                "hardware_profile": {
                    "type": "string",
                    "description": "Optional target hardware profile label."
                }
            },
            "required": ["backend_id"]
        });
        tools.push(LlmToolDefinition {
            name: "backend__start".to_string(),
            description:
                "Start a managed backend or sidecar under the kernel control plane."
                    .to_string(),
            parameters: backend_start_stop_params.to_string(),
        });
        tools.push(LlmToolDefinition {
            name: "backend__stop".to_string(),
            description:
                "Stop a managed backend or sidecar under the kernel control plane."
                    .to_string(),
            parameters: backend_start_stop_params.to_string(),
        });
        tools.push(LlmToolDefinition {
            name: "backend__health".to_string(),
            description:
                "Request a readiness or health probe for a managed backend through the kernel control plane."
                    .to_string(),
            parameters: backend_start_stop_params.to_string(),
        });

        let gallery_sync_params = json!({
            "type": "object",
            "properties": {
                "gallery_id": {
                    "type": "string",
                    "description": "Canonical gallery identifier to synchronize."
                },
                "source_uri": {
                    "type": "string",
                    "description": "Optional source URI or manifest location for gallery synchronization."
                },
                "job_id": {
                    "type": "string",
                    "description": "Optional lifecycle job identifier when resuming a staged gallery sync."
                }
            },
            "required": ["gallery_id"]
        });
        tools.push(LlmToolDefinition {
            name: "gallery__sync".to_string(),
            description:
                "Synchronize a model or backend gallery into the first-party kernel catalog."
                    .to_string(),
            parameters: gallery_sync_params.to_string(),
        });
    }
}
