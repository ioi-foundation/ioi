fn intervention_status_label(status: &InterventionStatus) -> &'static str {
    match status {
        InterventionStatus::New => "new",
        InterventionStatus::Seen => "seen",
        InterventionStatus::Pending => "pending",
        InterventionStatus::Responded => "responded",
        InterventionStatus::Resolved => "resolved",
        InterventionStatus::Expired => "expired",
        InterventionStatus::Cancelled => "cancelled",
    }
}

fn notification_severity_label(severity: &NotificationSeverity) -> &'static str {
    match severity {
        NotificationSeverity::Informational => "informational",
        NotificationSeverity::Low => "low",
        NotificationSeverity::Medium => "medium",
        NotificationSeverity::High => "high",
        NotificationSeverity::Critical => "critical",
    }
}

fn unresolved_intervention_status(status: &InterventionStatus) -> bool {
    !matches!(
        status,
        InterventionStatus::Resolved | InterventionStatus::Expired | InterventionStatus::Cancelled
    )
}

fn home_dir() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

fn trim_or_empty(value: impl AsRef<str>) -> String {
    value.as_ref().trim().to_string()
}

fn normalize_optional_text(value: Option<String>) -> Option<String> {
    value
        .map(|entry| trim_or_empty(entry))
        .filter(|entry| !entry.is_empty())
}

fn humanize_token(value: &str) -> String {
    value
        .split(['_', '-', '.'])
        .filter(|part| !part.trim().is_empty())
        .map(|part| {
            let mut chars = part.chars();
            match chars.next() {
                Some(first) => format!("{}{}", first.to_uppercase(), chars.as_str()),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

const LOCAL_ENGINE_CONTROL_PLANE_SCHEMA_VERSION: u32 = 1;
const LOCAL_ENGINE_CONTROL_PLANE_PROFILE_ID: &str = "local-engine.primary";

pub fn default_local_engine_runtime_profile() -> crate::models::LocalEngineRuntimeProfile {
    let openai_model = std::env::var("OPENAI_MODEL")
        .or_else(|_| std::env::var("AUTOPILOT_LOCAL_RUNTIME_MODEL"))
        .unwrap_or_else(|_| "gpt-4o".to_string());
    let local_bootstrap_model = std::env::var("AUTOPILOT_LOCAL_RUNTIME_MODEL")
        .or_else(|_| std::env::var("AUTOPILOT_LOCAL_MODEL_ID"))
        .or_else(|_| std::env::var("OLLAMA_DEFAULT_MODEL"))
        .unwrap_or_else(|_| "Kernel-managed".to_string());
    let local_runtime_url = std::env::var("LOCAL_LLM_URL")
        .ok()
        .or_else(|| std::env::var("AUTOPILOT_LOCAL_RUNTIME_URL").ok());
    if let Some(local_url) = local_runtime_url {
        crate::models::LocalEngineRuntimeProfile {
            mode: "http_local_dev".to_string(),
            endpoint: trim_or_empty(local_url),
            default_model: openai_model,
            baseline_role:
                "Bridged local HTTP runtime used for local GPU validation without restoring provider-first product posture."
                    .to_string(),
            kernel_authority:
                "Kernel owns policy, routing, and receipts above the temporary HTTP boundary."
                    .to_string(),
        }
    } else if std::env::var("OPENAI_API_KEY").is_ok() {
        crate::models::LocalEngineRuntimeProfile {
            mode: "openai_baseline".to_string(),
            endpoint: "https://api.openai.com/v1".to_string(),
            default_model: openai_model,
            baseline_role: "Baseline oracle for tool-use comparison while kernel-native planners mature."
                .to_string(),
            kernel_authority:
                "Kernel remains planner-of-record and receipt authority even when the baseline is remote."
                    .to_string(),
        }
    } else {
        crate::models::LocalEngineRuntimeProfile {
            mode: "local_asset_bootstrap".to_string(),
            endpoint: String::new(),
            default_model: local_bootstrap_model,
            baseline_role:
                "Local asset bootstrap profile for bringing a kernel-managed runtime online without claiming live inference before it is ready."
                    .to_string(),
            kernel_authority:
                "Kernel remains planner-of-record, receipt authority, and policy boundary while local runtime assets are provisioned."
                    .to_string(),
        }
    }
}

fn runtime_profile_uses_legacy_mock_surface(
    runtime: &crate::models::LocalEngineRuntimeProfile,
) -> bool {
    runtime.mode.eq_ignore_ascii_case("mock")
        || runtime.endpoint.eq_ignore_ascii_case("mock://reasoning-runtime")
        || runtime.default_model.eq_ignore_ascii_case("mock")
}

pub fn default_local_engine_control_plane() -> crate::models::LocalEngineControlPlane {
    let runtime = default_local_engine_runtime_profile();
    let base = home_dir().join(".ioi").join("local-engine");
    let huggingface_home = std::env::var("HF_HOME")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| {
            home_dir()
                .join(".cache")
                .join("huggingface")
                .display()
                .to_string()
        });

    crate::models::LocalEngineControlPlane {
        runtime,
        storage: crate::models::LocalEngineStorageConfig {
            models_path: base.join("models").display().to_string(),
            backends_path: base.join("backends").display().to_string(),
            artifacts_path: base.join("artifacts").display().to_string(),
            cache_path: base.join("cache").display().to_string(),
        },
        watchdog: crate::models::LocalEngineWatchdogConfig {
            enabled: true,
            idle_check_enabled: true,
            idle_timeout: "15m".to_string(),
            busy_check_enabled: true,
            busy_timeout: "5m".to_string(),
            check_interval: "2s".to_string(),
            force_eviction_when_busy: false,
            lru_eviction_max_retries: 30,
            lru_eviction_retry_interval: "1s".to_string(),
        },
        memory: crate::models::LocalEngineMemoryConfig {
            reclaimer_enabled: true,
            threshold_percent: 80,
            prefer_gpu: true,
            target_resource: "auto".to_string(),
        },
        backend_policy: crate::models::LocalEngineBackendPolicyConfig {
            max_concurrency: 4,
            max_queued_requests: 32,
            parallel_backend_loads: 2,
            allow_parallel_requests: true,
            health_probe_interval: "10s".to_string(),
            log_level: "info".to_string(),
            auto_shutdown_on_idle: true,
        },
        responses: crate::models::LocalEngineResponseConfig {
            retain_receipts_days: 7,
            persist_artifacts: true,
            allow_streaming: true,
            store_request_previews: true,
        },
        api: crate::models::LocalEngineApiConfig {
            bind_address: "127.0.0.1:8787".to_string(),
            remote_access_enabled: false,
            cors_mode: "local_only".to_string(),
            auth_mode: "kernel_leases".to_string(),
        },
        launcher: crate::models::LocalEngineLauncherConfig {
            auto_start_on_boot: false,
            reopen_chat_on_launch: true,
            auto_check_updates: true,
            release_channel: "stable".to_string(),
            show_kernel_console: false,
        },
        galleries: vec![
            crate::models::LocalEngineGallerySource {
                id: "kernel.models.primary".to_string(),
                kind: "model".to_string(),
                label: "Kernel model gallery".to_string(),
                uri: "kernel://gallery/models/primary".to_string(),
                enabled: true,
                sync_status: "ready".to_string(),
                compatibility_tier: "native".to_string(),
            },
            crate::models::LocalEngineGallerySource {
                id: "kernel.backends.primary".to_string(),
                kind: "backend".to_string(),
                label: "Kernel backend gallery".to_string(),
                uri: "kernel://gallery/backends/primary".to_string(),
                enabled: true,
                sync_status: "ready".to_string(),
                compatibility_tier: "native".to_string(),
            },
            crate::models::LocalEngineGallerySource {
                id: "import.localai.models".to_string(),
                kind: "model".to_string(),
                label: "LocalAI model gallery import".to_string(),
                uri: "github:mudler/LocalAI/gallery/index.yaml@master".to_string(),
                enabled: false,
                sync_status: "dormant".to_string(),
                compatibility_tier: "migration".to_string(),
            },
            crate::models::LocalEngineGallerySource {
                id: "import.localai.backends".to_string(),
                kind: "backend".to_string(),
                label: "LocalAI backend gallery import".to_string(),
                uri: "github:mudler/LocalAI/backend/index.yaml@master".to_string(),
                enabled: false,
                sync_status: "dormant".to_string(),
                compatibility_tier: "migration".to_string(),
            },
        ],
        environment: vec![
            crate::models::LocalEngineEnvironmentBinding {
                key: "OPENAI_MODEL".to_string(),
                value: std::env::var("OPENAI_MODEL")
                    .unwrap_or_else(|_| "gpt-4o".to_string()),
                secret: false,
            },
            crate::models::LocalEngineEnvironmentBinding {
                key: "LOCAL_LLM_URL".to_string(),
                value: std::env::var("LOCAL_LLM_URL").unwrap_or_default(),
                secret: false,
            },
            crate::models::LocalEngineEnvironmentBinding {
                key: "AUTOPILOT_LOCAL_RUNTIME_URL".to_string(),
                value: std::env::var("AUTOPILOT_LOCAL_RUNTIME_URL").unwrap_or_default(),
                secret: false,
            },
            crate::models::LocalEngineEnvironmentBinding {
                key: "AUTOPILOT_LOCAL_RUNTIME_MODEL".to_string(),
                value: std::env::var("AUTOPILOT_LOCAL_RUNTIME_MODEL").unwrap_or_default(),
                secret: false,
            },
            crate::models::LocalEngineEnvironmentBinding {
                key: "AUTOPILOT_LOCAL_EMBEDDING_MODEL".to_string(),
                value: std::env::var("AUTOPILOT_LOCAL_EMBEDDING_MODEL")
                    .unwrap_or_default(),
                secret: false,
            },
            crate::models::LocalEngineEnvironmentBinding {
                key: "AUTOPILOT_LOCAL_RUNTIME_HEALTH_URL".to_string(),
                value: std::env::var("AUTOPILOT_LOCAL_RUNTIME_HEALTH_URL")
                    .unwrap_or_default(),
                secret: false,
            },
            crate::models::LocalEngineEnvironmentBinding {
                key: "LOCAL_LLM_EMBEDDING_MODEL".to_string(),
                value: std::env::var("LOCAL_LLM_EMBEDDING_MODEL").unwrap_or_default(),
                secret: false,
            },
            crate::models::LocalEngineEnvironmentBinding {
                key: "OPENAI_EMBEDDING_MODEL".to_string(),
                value: std::env::var("OPENAI_EMBEDDING_MODEL").unwrap_or_default(),
                secret: false,
            },
            crate::models::LocalEngineEnvironmentBinding {
                key: "AUTOPILOT_LOCAL_MODEL_SOURCE".to_string(),
                value: std::env::var("AUTOPILOT_LOCAL_MODEL_SOURCE").unwrap_or_default(),
                secret: false,
            },
            crate::models::LocalEngineEnvironmentBinding {
                key: "AUTOPILOT_LOCAL_BACKEND_SOURCE".to_string(),
                value: std::env::var("AUTOPILOT_LOCAL_BACKEND_SOURCE").unwrap_or_default(),
                secret: false,
            },
            crate::models::LocalEngineEnvironmentBinding {
                key: "AUTOPILOT_LOCAL_BACKEND_ID".to_string(),
                value: std::env::var("AUTOPILOT_LOCAL_BACKEND_ID").unwrap_or_default(),
                secret: false,
            },
            crate::models::LocalEngineEnvironmentBinding {
                key: "AUTOPILOT_LOCAL_DEV_PRESET".to_string(),
                value: std::env::var("AUTOPILOT_LOCAL_DEV_PRESET").unwrap_or_default(),
                secret: false,
            },
            crate::models::LocalEngineEnvironmentBinding {
                key: "AUTOPILOT_LOCAL_MODEL_CACHE_DIR".to_string(),
                value: std::env::var("AUTOPILOT_LOCAL_MODEL_CACHE_DIR").unwrap_or_default(),
                secret: false,
            },
            crate::models::LocalEngineEnvironmentBinding {
                key: "AUTOPILOT_DATA_PROFILE".to_string(),
                value: std::env::var("AUTOPILOT_DATA_PROFILE").unwrap_or_default(),
                secret: false,
            },
            crate::models::LocalEngineEnvironmentBinding {
                key: "HF_HOME".to_string(),
                value: huggingface_home,
                secret: false,
            },
        ],
        notes: vec![
            "Absorbed LocalAI-class behavior lives under kernel authority; this control plane is first-party state."
                .to_string(),
            "Staged operations promote into durable kernel-native jobs that update the registry, galleries, and runtime deck."
                .to_string(),
            "Compatibility facades are no longer product control-plane contracts; kernel invocation envelopes own execution."
                .to_string(),
        ],
    }
}

pub fn default_local_engine_control_plane_document() -> crate::models::LocalEngineControlPlaneDocument {
    crate::models::LocalEngineControlPlaneDocument {
        schema_version: LOCAL_ENGINE_CONTROL_PLANE_SCHEMA_VERSION,
        profile_id: LOCAL_ENGINE_CONTROL_PLANE_PROFILE_ID.to_string(),
        migrations: Vec::new(),
        control_plane: default_local_engine_control_plane(),
    }
}

pub fn normalize_local_engine_control_plane(
    mut control_plane: crate::models::LocalEngineControlPlane,
) -> crate::models::LocalEngineControlPlane {
    control_plane.runtime.mode = trim_or_empty(control_plane.runtime.mode);
    control_plane.runtime.endpoint = trim_or_empty(control_plane.runtime.endpoint);
    control_plane.runtime.default_model = trim_or_empty(control_plane.runtime.default_model);
    control_plane.runtime.baseline_role = trim_or_empty(control_plane.runtime.baseline_role);
    control_plane.runtime.kernel_authority = trim_or_empty(control_plane.runtime.kernel_authority);

    control_plane.storage.models_path = trim_or_empty(control_plane.storage.models_path);
    control_plane.storage.backends_path = trim_or_empty(control_plane.storage.backends_path);
    control_plane.storage.artifacts_path = trim_or_empty(control_plane.storage.artifacts_path);
    control_plane.storage.cache_path = trim_or_empty(control_plane.storage.cache_path);

    control_plane.watchdog.idle_timeout = trim_or_empty(control_plane.watchdog.idle_timeout);
    control_plane.watchdog.busy_timeout = trim_or_empty(control_plane.watchdog.busy_timeout);
    control_plane.watchdog.check_interval = trim_or_empty(control_plane.watchdog.check_interval);
    control_plane.watchdog.lru_eviction_retry_interval =
        trim_or_empty(control_plane.watchdog.lru_eviction_retry_interval);
    control_plane.watchdog.lru_eviction_max_retries =
        control_plane.watchdog.lru_eviction_max_retries.max(1);

    control_plane.memory.threshold_percent = control_plane.memory.threshold_percent.clamp(50, 100);
    control_plane.memory.target_resource = trim_or_empty(control_plane.memory.target_resource);

    control_plane.backend_policy.max_concurrency =
        control_plane.backend_policy.max_concurrency.max(1);
    control_plane.backend_policy.max_queued_requests =
        control_plane.backend_policy.max_queued_requests.max(1);
    control_plane.backend_policy.parallel_backend_loads =
        control_plane.backend_policy.parallel_backend_loads.max(1);
    control_plane.backend_policy.health_probe_interval =
        trim_or_empty(control_plane.backend_policy.health_probe_interval);
    control_plane.backend_policy.log_level = trim_or_empty(control_plane.backend_policy.log_level);

    control_plane.responses.retain_receipts_days =
        control_plane.responses.retain_receipts_days.max(1);

    control_plane.api.bind_address = trim_or_empty(control_plane.api.bind_address);
    control_plane.api.cors_mode = trim_or_empty(control_plane.api.cors_mode);
    control_plane.api.auth_mode = trim_or_empty(control_plane.api.auth_mode);
    control_plane.launcher.release_channel = trim_or_empty(control_plane.launcher.release_channel);

    control_plane.galleries = control_plane
        .galleries
        .into_iter()
        .filter_map(|mut source| {
            source.id = trim_or_empty(source.id);
            source.kind = trim_or_empty(source.kind);
            source.label = trim_or_empty(source.label);
            source.uri = trim_or_empty(source.uri);
            source.sync_status = trim_or_empty(source.sync_status);
            source.compatibility_tier = trim_or_empty(source.compatibility_tier);
            if source.id.is_empty() || source.uri.is_empty() {
                None
            } else {
                Some(source)
            }
        })
        .collect();

    control_plane.environment = control_plane
        .environment
        .into_iter()
        .filter_map(|mut binding| {
            binding.key = trim_or_empty(binding.key);
            binding.value = trim_or_empty(binding.value);
            if binding.key.is_empty() {
                None
            } else {
                Some(binding)
            }
        })
        .collect();

    control_plane.notes = control_plane
        .notes
        .into_iter()
        .map(trim_or_empty)
        .filter(|note| !note.is_empty())
        .collect();

    if runtime_profile_uses_legacy_mock_surface(&control_plane.runtime) {
        control_plane.runtime = default_local_engine_runtime_profile();
    }
    if control_plane.galleries.is_empty() {
        control_plane.galleries = default_local_engine_control_plane().galleries;
    }
    if control_plane.notes.is_empty() {
        control_plane.notes = default_local_engine_control_plane().notes;
    }
    if control_plane.runtime.mode.is_empty() {
        control_plane.runtime = default_local_engine_runtime_profile();
    }
    if control_plane.launcher.release_channel.is_empty() {
        control_plane.launcher = default_local_engine_control_plane().launcher;
    }

    control_plane
}

pub fn normalize_local_engine_control_plane_document(
    mut document: crate::models::LocalEngineControlPlaneDocument,
) -> crate::models::LocalEngineControlPlaneDocument {
    document.schema_version = document
        .schema_version
        .max(LOCAL_ENGINE_CONTROL_PLANE_SCHEMA_VERSION);
    document.profile_id = trim_or_empty(document.profile_id);
    if document.profile_id.is_empty() {
        document.profile_id = LOCAL_ENGINE_CONTROL_PLANE_PROFILE_ID.to_string();
    }
    document.migrations = document
        .migrations
        .into_iter()
        .filter_map(|mut record| {
            record.migration_id = trim_or_empty(record.migration_id);
            record.summary = trim_or_empty(record.summary);
            record.details = record
                .details
                .into_iter()
                .map(trim_or_empty)
                .filter(|detail| !detail.is_empty())
                .collect();
            if record.migration_id.is_empty() || record.summary.is_empty() {
                None
            } else {
                Some(record)
            }
        })
        .collect();
    document.control_plane = normalize_local_engine_control_plane(document.control_plane);
    document
}

pub fn load_or_initialize_local_engine_control_plane(
    memory_runtime: &std::sync::Arc<ioi_memory::MemoryRuntime>,
) -> crate::models::LocalEngineControlPlane {
    load_or_initialize_effective_local_engine_control_plane_state(memory_runtime).control_plane
}

pub fn load_or_initialize_local_engine_control_plane_state(
    memory_runtime: &std::sync::Arc<ioi_memory::MemoryRuntime>,
) -> crate::models::LocalEngineControlPlaneDocument {
    let document = orchestrator::load_local_engine_control_plane_document(memory_runtime)
        .map(normalize_local_engine_control_plane_document)
        .unwrap_or_else(default_local_engine_control_plane_document);
    orchestrator::save_local_engine_control_plane_document(memory_runtime, &document);
    document
}

pub fn load_or_initialize_effective_local_engine_control_plane_state(
    memory_runtime: &std::sync::Arc<ioi_memory::MemoryRuntime>,
) -> crate::kernel::local_engine::LocalEngineEffectiveControlPlaneState {
    let document = load_or_initialize_local_engine_control_plane_state(memory_runtime);
    crate::kernel::local_engine::effective_control_plane_state(memory_runtime, &document)
}

fn default_worker_templates() -> Vec<crate::models::LocalEngineWorkerTemplateRecord> {
    builtin_worker_templates()
        .into_iter()
        .map(|template| crate::models::LocalEngineWorkerTemplateRecord {
            template_id: template.template_id,
            label: template.label,
            role: template.role,
            summary: template.summary,
            default_budget: template.default_budget,
            max_retries: template.max_retries,
            allowed_tools: template.allowed_tools,
            completion_contract: crate::models::LocalEngineWorkerCompletionContract {
                success_criteria: template.completion_contract.success_criteria,
                expected_output: template.completion_contract.expected_output,
                merge_mode: template
                    .completion_contract
                    .merge_mode
                    .as_label()
                    .to_string(),
                verification_hint: template.completion_contract.verification_hint,
            },
            workflows: template
                .workflows
                .into_iter()
                .map(|workflow| crate::models::LocalEngineWorkerWorkflowRecord {
                    workflow_id: workflow.workflow_id,
                    label: workflow.label,
                    summary: workflow.summary,
                    goal_template: workflow.goal_template,
                    trigger_intents: workflow.trigger_intents,
                    default_budget: workflow.default_budget,
                    max_retries: workflow.max_retries,
                    allowed_tools: workflow.allowed_tools,
                    completion_contract: workflow.completion_contract.map(|contract| {
                        crate::models::LocalEngineWorkerCompletionContract {
                            success_criteria: contract.success_criteria,
                            expected_output: contract.expected_output,
                            merge_mode: contract.merge_mode.as_label().to_string(),
                            verification_hint: contract.verification_hint,
                        }
                    }),
                })
                .collect(),
        })
        .collect()
}

fn load_or_initialize_worker_templates(
    memory_runtime: &std::sync::Arc<ioi_memory::MemoryRuntime>,
) -> Vec<crate::models::LocalEngineWorkerTemplateRecord> {
    let templates = orchestrator::load_worker_templates(memory_runtime);
    if templates.is_empty() {
        let defaults = default_worker_templates();
        orchestrator::save_worker_templates(memory_runtime, &defaults);
        defaults
    } else {
        templates
    }
}

pub(crate) fn default_agent_playbooks() -> Vec<crate::models::LocalEngineAgentPlaybookRecord> {
    builtin_agent_playbooks()
        .into_iter()
        .map(|playbook| {
            let route_contract = playbook_route_contract(&playbook.playbook_id);
            crate::models::LocalEngineAgentPlaybookRecord {
                playbook_id: playbook.playbook_id,
                label: playbook.label,
                summary: playbook.summary,
                goal_template: playbook.goal_template,
                route_family: route_contract.route_family.to_string(),
                topology: route_contract.topology.to_string(),
                trigger_intents: playbook.trigger_intents,
                recommended_for: playbook.recommended_for,
                default_budget: playbook.default_budget,
                completion_contract: crate::models::LocalEngineWorkerCompletionContract {
                    success_criteria: playbook.completion_contract.success_criteria,
                    expected_output: playbook.completion_contract.expected_output,
                    merge_mode: playbook
                        .completion_contract
                        .merge_mode
                        .as_label()
                        .to_string(),
                    verification_hint: playbook.completion_contract.verification_hint,
                },
                steps: playbook
                    .steps
                    .into_iter()
                    .map(|step| crate::models::LocalEngineAgentPlaybookStepRecord {
                        step_id: step.step_id,
                        label: step.label,
                        summary: step.summary,
                        worker_template_id: step.worker_template_id,
                        worker_workflow_id: step.worker_workflow_id,
                        goal_template: step.goal_template,
                        depends_on: step.depends_on,
                    })
                    .collect(),
            }
        })
        .collect()
}

fn stage_operation_title(subject_kind: &str, operation: &str, subject_id: Option<&str>) -> String {
    let operation_label = humanize_token(operation);
    let subject_label = humanize_token(subject_kind);
    match subject_id {
        Some(id) if !id.trim().is_empty() => {
            format!("{} {} {}", operation_label, subject_label, id)
        }
        _ => format!("{} {}", operation_label, subject_label),
    }
}

fn staged_operation_to_control_action(
    operation: &crate::models::LocalEngineStagedOperation,
) -> crate::models::LocalEngineControlAction {
    let mut summary = format!(
        "Staged {} plan for the {} control plane.",
        humanize_token(&operation.operation).to_ascii_lowercase(),
        humanize_token(&operation.subject_kind).to_ascii_lowercase()
    );
    if let Some(source_uri) = operation.source_uri.as_deref() {
        summary.push_str(&format!(" Source: {}.", source_uri));
    }
    if let Some(notes) = operation.notes.as_deref() {
        summary.push_str(&format!(" {}", notes));
    }

    crate::models::LocalEngineControlAction {
        item_id: operation.operation_id.clone(),
        title: operation.title.clone(),
        summary,
        status: operation.status.clone(),
        severity: "informational".to_string(),
        requested_at_ms: operation.created_at_ms,
        due_at_ms: None,
        approval_scope: Some("model::control".to_string()),
        sensitive_action_type: Some(format!("staged_{}", operation.subject_kind)),
        recommended_action: Some("Promote this staged plan into the live kernel queue.".to_string()),
        recovery_hint: Some(
            "Promoting a plan now seeds the registry state immediately, then leaves the job visible for operator-supervised execution."
                .to_string(),
        ),
        request_hash: None,
    }
}

fn local_engine_job_from_staged_operation(
    operation: &crate::models::LocalEngineStagedOperation,
    now_ms: u64,
) -> crate::models::LocalEngineJobRecord {
    let mut job = crate::models::LocalEngineJobRecord {
        job_id: operation.operation_id.clone(),
        title: operation.title.clone(),
        summary: String::new(),
        status: "queued".to_string(),
        origin: "staged_plan".to_string(),
        subject_kind: operation.subject_kind.clone(),
        operation: operation.operation.clone(),
        created_at_ms: operation.created_at_ms,
        updated_at_ms: now_ms,
        progress_percent: crate::kernel::local_engine::job_progress_for_status("queued"),
        source_uri: operation.source_uri.clone(),
        subject_id: operation.subject_id.clone(),
        backend_id: None,
        severity: Some("informational".to_string()),
        approval_scope: Some("model::control".to_string()),
    };
    job.summary = crate::kernel::local_engine::summary_for_job_status(&job, &job.status);
    job
}

fn is_local_engine_intervention(record: &InterventionRecord) -> bool {
    if record.approval_scope.as_deref() == Some("model::control") {
        return true;
    }

    let text = [
        record.title.as_str(),
        record.summary.as_str(),
        record.reason.as_deref().unwrap_or_default(),
        record.sensitive_action_type.as_deref().unwrap_or_default(),
        record.approval_scope.as_deref().unwrap_or_default(),
        record.recovery_hint.as_deref().unwrap_or_default(),
        record.dedupe_key.as_str(),
    ]
    .join(" ")
    .to_ascii_lowercase();

    text.contains("model_registry")
        || text.contains("model::control")
        || text.contains("local engine")
        || text.contains("backend__")
        || text.contains("gallery__")
        || text.contains("model control")
        || text.contains("backend control")
        || text.contains("gallery control")
}

fn engine_family_specs() -> [(&'static str, &'static str, &'static str, &'static str); 13] {
    [
        (
            "responses",
            "Responses",
            "Kernel-native text generation routed through the absorbed inference substrate.",
            "Chat and planner-facing completions stay inside the kernel trust boundary.",
        ),
        (
            "embeddings",
            "Embeddings",
            "Typed embedding generation for memory indexing, retrieval, and semantic joins.",
            "The same local engine powers retrieval and downstream operator tooling.",
        ),
        (
            "rerank",
            "Rerank",
            "Candidate scoring and reranking for memory, search, and tool result selection.",
            "Scoring stays auditable and can emit typed receipts for wave-collapse verification.",
        ),
        (
            "transcription",
            "Transcription",
            "Audio transcription and transcript extraction routed through kernel-native media workloads.",
            "Speech-to-text stays inside the kernel and emits typed receipts with evidence-ready metadata.",
        ),
        (
            "speech",
            "Speech",
            "Speech synthesis and voice artifact generation for operator and agent workflows.",
            "Local narration, previews, and voice outputs are governed by the same receipt boundary as every other kernel effect.",
        ),
        (
            "vision",
            "Vision",
            "Multimodal image and screenshot reading with kernel-native artifacts and typed outputs.",
            "Visual inspection no longer needs to masquerade as generic web retrieval or opaque adapter output.",
        ),
        (
            "image",
            "Image Chat",
            "Image generation and editing mapped into first-party kernel media jobs.",
            "Image workflows look like native Chat capabilities, not a separate product shell.",
        ),
        (
            "video",
            "Video Chat",
            "Video generation workloads routed through the absorbed local media substrate.",
            "Longer-running media generations surface as operator-visible workloads with typed receipts.",
        ),
        (
            "model_registry",
            "Model Registry",
            "Model install, load, unload, and residency control handled by kernel-native lifecycle tools.",
            "Registry mutations are approvalable operator actions with typed lifecycle receipts.",
        ),
        (
            "backend",
            "Backends",
            "Managed runtime backends and sidecars supervised by the same control plane.",
            "Backend process control will live beside model registry state, not behind adapters.",
        ),
        (
            "gallery",
            "Gallery",
            "Catalog synchronization and curated discovery for models and backends.",
            "Gallery sync becomes part of the kernel control plane rather than a separate product shell.",
        ),
        (
            "knowledge",
            "Knowledge",
            "Collections, retrieval, and memory convergence mapped into IOI-native memory and rerank surfaces.",
            "LocalAI collections become agent-usable knowledge assets with first-party memory semantics.",
        ),
        (
            "workers",
            "Workers",
            "Bounded child workers, delegation, and specialist execution mapped into kernel-native agent flows.",
            "LocalAI agents are absorbed as supervised workers rather than planners of record.",
        ),
    ]
}

fn tool_names_for_engine_family(family_id: &str, tools: &[LlmToolDefinition]) -> Vec<String> {
    let mut names = match family_id {
        "responses" => vec!["model__responses".to_string()],
        "embeddings" => vec!["model__embeddings".to_string()],
        "rerank" => vec!["model__rerank".to_string()],
        "transcription" => vec![
            "media__extract_transcript".to_string(),
            "media__transcribe_audio".to_string(),
        ],
        "speech" => vec!["media__synthesize_speech".to_string()],
        "vision" => vec![
            "media__extract_evidence".to_string(),
            "media__vision_read".to_string(),
        ],
        "image" => vec![
            "media__generate_image".to_string(),
            "media__edit_image".to_string(),
        ],
        "video" => vec!["media__generate_video".to_string()],
        "model_registry" => vec![
            "model_registry__install".to_string(),
            "model_registry__apply".to_string(),
            "model_registry__load".to_string(),
            "model_registry__unload".to_string(),
            "model_registry__delete".to_string(),
        ],
        "backend" => vec![
            "backend__install".to_string(),
            "backend__apply".to_string(),
            "backend__start".to_string(),
            "backend__stop".to_string(),
            "backend__health".to_string(),
            "backend__delete".to_string(),
        ],
        "gallery" => vec!["gallery__sync".to_string()],
        "knowledge" => vec![
            "memory__search".to_string(),
            "memory__read".to_string(),
            "model__embeddings".to_string(),
            "model__rerank".to_string(),
        ],
        "workers" => vec![
            "agent__delegate".to_string(),
            "agent__await".to_string(),
            "agent__pause".to_string(),
            "agent__complete".to_string(),
        ],
        _ => Vec::new(),
    };
    names.extend(
        tools
            .iter()
            .filter(|tool| match family_id {
                "responses" => tool.name == "model__responses",
                "embeddings" => tool.name == "model__embeddings",
                "rerank" => tool.name == "model__rerank",
                "transcription" => {
                    tool.name == "media__extract_transcript"
                        || tool.name == "media__transcribe_audio"
                }
                "speech" => tool.name == "media__synthesize_speech",
                "vision" => {
                    tool.name == "media__extract_evidence"
                        || tool.name == "media__vision_read"
                }
                "image" => tool.name == "media__generate_image" || tool.name == "media__edit_image",
                "video" => tool.name == "media__generate_video",
                "model_registry" => tool.name.starts_with("model_registry__"),
                "backend" => tool.name.starts_with("backend__"),
                "gallery" => tool.name.starts_with("gallery__"),
                "knowledge" => {
                    tool.name.starts_with("memory__")
                        || tool.name == "model__embeddings"
                        || tool.name == "model__rerank"
                }
                "workers" => tool.name.starts_with("agent__"),
                _ => false,
            })
            .map(|tool| tool.name.clone()),
    );
    names.sort();
    names.dedup();
    names
}

fn build_local_engine_capabilities(
    tools: &[LlmToolDefinition],
) -> Vec<crate::models::LocalEngineCapabilityFamily> {
    let observed_tool_names = tools
        .iter()
        .map(|tool| tool.name.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    engine_family_specs()
        .into_iter()
        .map(|(id, label, description, operator_summary)| {
            let tool_names = tool_names_for_engine_family(id, tools);
            let observed_count = tool_names
                .iter()
                .filter(|name| observed_tool_names.contains(name.as_str()))
                .count();
            crate::models::LocalEngineCapabilityFamily {
                id: id.to_string(),
                label: label.to_string(),
                description: description.to_string(),
                status: if tool_names.is_empty() {
                    "Developing".to_string()
                } else if observed_count == 0 {
                    "Surfaced".to_string()
                } else {
                    "Available".to_string()
                },
                available_count: tool_names.len(),
                tool_names,
                operator_summary: operator_summary.to_string(),
            }
        })
        .collect()
}

fn parse_event_timestamp_ms(event: &crate::models::AgentEvent) -> u64 {
    event
        .details
        .get("timestamp_ms")
        .and_then(Value::as_u64)
        .or_else(|| {
            DateTime::parse_from_rfc3339(&event.timestamp)
                .ok()
                .map(|timestamp| timestamp.timestamp_millis().max(0) as u64)
        })
        .unwrap_or_default()
}

fn event_status_label(status: &EventStatus) -> &'static str {
    match status {
        EventStatus::Success => "completed",
        EventStatus::Failure => "failed",
        EventStatus::Partial => "partial",
    }
}

fn json_string(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(str::to_string)
}
