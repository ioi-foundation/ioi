use super::*;
use crate::models::{EventStatus, InterventionRecord, InterventionStatus, NotificationSeverity};
use chrono::{DateTime, Utc};
use ioi_crypto::algorithms::hash::sha256;
use ioi_services::agentic::desktop::agent_playbooks::builtin_agent_playbooks;
use ioi_services::agentic::desktop::utils::load_agent_state_checkpoint;
use ioi_services::agentic::desktop::worker_templates::builtin_worker_templates;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::PathBuf;
use tauri::Manager;

fn app_memory_runtime(
    state: &State<'_, Mutex<AppState>>,
) -> Option<std::sync::Arc<ioi_memory::MemoryRuntime>> {
    state
        .lock()
        .ok()
        .and_then(|guard| guard.memory_runtime.clone())
}

#[tauri::command]
pub async fn get_available_tools(
    state: State<'_, Mutex<AppState>>,
) -> Result<Vec<LlmToolDefinition>, String> {
    collect_available_tools(&state).await
}

async fn collect_available_tools(
    state: &State<'_, Mutex<AppState>>,
) -> Result<Vec<LlmToolDefinition>, String> {
    let mut tools = execution::get_active_mcp_tools().await;
    let mut existing = tools
        .iter()
        .map(|tool| tool.name.clone())
        .collect::<std::collections::HashSet<_>>();
    tools.extend(
        ioi_services::agentic::desktop::connectors::google_workspace::google_connector_tool_definitions()
            .into_iter()
            .filter(|tool| !existing.contains(&tool.name)),
    );
    existing.extend(tools.iter().map(|tool| tool.name.clone()));

    if let Ok(mut client) = get_rpc_client(&state).await {
        if let Ok(skill_catalog) = load_skill_catalog_entries(&mut client).await {
            for entry in skill_catalog {
                if entry.stale || entry.lifecycle_state == "Deprecated" {
                    continue;
                }
                if existing.insert(entry.definition.name.clone()) {
                    tools.push(entry.definition);
                }
            }
        }
    }

    Ok(tools)
}

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

fn default_local_engine_runtime_profile() -> crate::models::LocalEngineRuntimeProfile {
    let openai_model = std::env::var("OPENAI_MODEL").unwrap_or_else(|_| "gpt-4o".to_string());
    if std::env::var("OPENAI_API_KEY").is_ok() {
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
    } else if let Ok(local_url) = std::env::var("LOCAL_LLM_URL") {
        crate::models::LocalEngineRuntimeProfile {
            mode: "http_local".to_string(),
            endpoint: trim_or_empty(local_url),
            default_model: openai_model,
            baseline_role:
                "Bridged local HTTP runtime used while absorbed first-party executors continue to land."
                    .to_string(),
            kernel_authority:
                "Kernel owns policy, routing, and receipts above the temporary HTTP boundary."
                    .to_string(),
        }
    } else {
        crate::models::LocalEngineRuntimeProfile {
            mode: "mock".to_string(),
            endpoint: "mock://reasoning-runtime".to_string(),
            default_model: "mock".to_string(),
            baseline_role:
                "Mock substrate for UX and receipt validation without live model weight execution."
                    .to_string(),
            kernel_authority:
                "Kernel semantics are active even when model execution falls back to mock mode."
                    .to_string(),
        }
    }
}

fn default_local_engine_control_plane() -> crate::models::LocalEngineControlPlane {
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
            expose_compat_routes: true,
            cors_mode: "local_only".to_string(),
            auth_mode: "kernel_leases".to_string(),
        },
        launcher: crate::models::LocalEngineLauncherConfig {
            auto_start_on_boot: false,
            reopen_studio_on_launch: true,
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
            "Compatibility routes remain optional facades; planner, approval, and receipts stay in the kernel."
                .to_string(),
        ],
    }
}

fn normalize_local_engine_control_plane(
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

fn local_engine_base_url(bind_address: &str) -> String {
    let normalized = trim_or_empty(bind_address);
    if normalized.starts_with("http://") || normalized.starts_with("https://") {
        normalized
    } else {
        format!("http://{}", normalized)
    }
}

fn build_local_engine_compatibility_routes(
    control_plane: &crate::models::LocalEngineControlPlane,
) -> Vec<crate::models::LocalEngineCompatRoute> {
    let base_url = local_engine_base_url(&control_plane.api.bind_address);
    let compat_enabled = control_plane.api.expose_compat_routes;
    vec![
        crate::models::LocalEngineCompatRoute {
            id: "kernel.responses".to_string(),
            label: "Kernel responses".to_string(),
            path: "/v1/responses".to_string(),
            url: format!("{}/v1/responses", base_url),
            enabled: true,
            compatibility_tier: "native".to_string(),
            notes: Some(
                "Canonical kernel-owned facade for absorbed response semantics and receipt-aware local execution."
                    .to_string(),
            ),
        },
        crate::models::LocalEngineCompatRoute {
            id: "compat.openai".to_string(),
            label: "OpenAI compatible".to_string(),
            path: "/v1/chat/completions".to_string(),
            url: format!("{}/v1/chat/completions", base_url),
            enabled: compat_enabled,
            compatibility_tier: "compatibility".to_string(),
            notes: Some(
                "Optional outer facade for OpenAI-compatible clients. The kernel remains planner and receipt authority."
                    .to_string(),
            ),
        },
        crate::models::LocalEngineCompatRoute {
            id: "compat.anthropic".to_string(),
            label: "Anthropic compatible".to_string(),
            path: "/v1/messages".to_string(),
            url: format!("{}/v1/messages", base_url),
            enabled: compat_enabled,
            compatibility_tier: "compatibility".to_string(),
            notes: Some(
                "Migration surface for Anthropic-style request payloads without restoring a LocalAI product boundary."
                    .to_string(),
            ),
        },
        crate::models::LocalEngineCompatRoute {
            id: "compat.elevenlabs".to_string(),
            label: "ElevenLabs compatible".to_string(),
            path: "/v1/audio/speech".to_string(),
            url: format!("{}/v1/audio/speech", base_url),
            enabled: compat_enabled,
            compatibility_tier: "compatibility".to_string(),
            notes: Some(
                "Speech facade for ecosystem compatibility over the kernel-owned media substrate."
                    .to_string(),
            ),
        },
        crate::models::LocalEngineCompatRoute {
            id: "compat.models".to_string(),
            label: "Model catalog facade".to_string(),
            path: "/v1/models".to_string(),
            url: format!("{}/v1/models", base_url),
            enabled: compat_enabled,
            compatibility_tier: "compatibility".to_string(),
            notes: Some(
                "Compatibility model listing for external clients while registry truth stays in the control plane."
                    .to_string(),
            ),
        },
    ]
}

fn load_or_initialize_local_engine_control_plane(
    memory_runtime: &std::sync::Arc<ioi_memory::MemoryRuntime>,
) -> crate::models::LocalEngineControlPlane {
    let control_plane = orchestrator::load_local_engine_control_plane(memory_runtime)
        .map(normalize_local_engine_control_plane)
        .unwrap_or_else(default_local_engine_control_plane);
    orchestrator::save_local_engine_control_plane(memory_runtime, &control_plane);
    control_plane
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

fn default_agent_playbooks() -> Vec<crate::models::LocalEngineAgentPlaybookRecord> {
    builtin_agent_playbooks()
        .into_iter()
        .map(|playbook| crate::models::LocalEngineAgentPlaybookRecord {
            playbook_id: playbook.playbook_id,
            label: playbook.label,
            summary: playbook.summary,
            goal_template: playbook.goal_template,
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
            "Image Studio",
            "Image generation and editing mapped into first-party kernel media jobs.",
            "Image workflows look like native Studio capabilities, not a separate product shell.",
        ),
        (
            "video",
            "Video Studio",
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
            "media__extract_multimodal_evidence".to_string(),
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
            "memory__inspect".to_string(),
            "model__embeddings".to_string(),
            "model__rerank".to_string(),
        ],
        "workers" => vec![
            "agent__delegate".to_string(),
            "agent__await_result".to_string(),
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
                    tool.name == "media__extract_multimodal_evidence"
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

fn seed_parent_playbook_step_records(
    playbook: Option<&crate::models::LocalEngineAgentPlaybookRecord>,
) -> Vec<crate::models::LocalEngineParentPlaybookStepRunRecord> {
    playbook
        .map(|playbook| {
            playbook
                .steps
                .iter()
                .map(
                    |step| crate::models::LocalEngineParentPlaybookStepRunRecord {
                        step_id: step.step_id.clone(),
                        label: step.label.clone(),
                        summary: step.summary.clone(),
                        status: "pending".to_string(),
                        child_session_id: None,
                        template_id: Some(step.worker_template_id.clone()),
                        workflow_id: Some(step.worker_workflow_id.clone()),
                        updated_at_ms: None,
                        completed_at_ms: None,
                        error_class: None,
                        receipts: Vec::new(),
                    },
                )
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

fn ensure_parent_playbook_step_index(
    run: &mut crate::models::LocalEngineParentPlaybookRunRecord,
    playbook: Option<&crate::models::LocalEngineAgentPlaybookRecord>,
    step_id: &str,
    step_label: Option<&str>,
    template_id: Option<&str>,
    workflow_id: Option<&str>,
) -> usize {
    if let Some(index) = run.steps.iter().position(|step| step.step_id == step_id) {
        return index;
    }

    if let Some(playbook) = playbook {
        if let Some(step) = playbook.steps.iter().find(|step| step.step_id == step_id) {
            run.steps
                .push(crate::models::LocalEngineParentPlaybookStepRunRecord {
                    step_id: step.step_id.clone(),
                    label: step.label.clone(),
                    summary: step.summary.clone(),
                    status: "pending".to_string(),
                    child_session_id: None,
                    template_id: Some(step.worker_template_id.clone()),
                    workflow_id: Some(step.worker_workflow_id.clone()),
                    updated_at_ms: None,
                    completed_at_ms: None,
                    error_class: None,
                    receipts: Vec::new(),
                });
            return run.steps.len().saturating_sub(1);
        }
    }

    run.steps
        .push(crate::models::LocalEngineParentPlaybookStepRunRecord {
            step_id: step_id.to_string(),
            label: step_label
                .map(str::to_string)
                .unwrap_or_else(|| humanize_token(step_id)),
            summary: "Observed runtime step".to_string(),
            status: "pending".to_string(),
            child_session_id: None,
            template_id: template_id.map(str::to_string),
            workflow_id: workflow_id.map(str::to_string),
            updated_at_ms: None,
            completed_at_ms: None,
            error_class: None,
            receipts: Vec::new(),
        });
    run.steps.len().saturating_sub(1)
}

fn ingest_parent_playbook_events(
    session_id: &str,
    events: &[crate::models::AgentEvent],
    playbook_specs: &BTreeMap<String, crate::models::LocalEngineAgentPlaybookRecord>,
    runs: &mut BTreeMap<String, crate::models::LocalEngineParentPlaybookRunRecord>,
) {
    let mut sorted_events = events.to_vec();
    sorted_events.sort_by(|left, right| {
        parse_event_timestamp_ms(left)
            .cmp(&parse_event_timestamp_ms(right))
            .then_with(|| left.event_id.cmp(&right.event_id))
    });

    for event in sorted_events {
        let Some(digest) = event.digest.as_object() else {
            continue;
        };
        if digest.get("kind").and_then(Value::as_str).map(str::trim) != Some("parent_playbook") {
            continue;
        }

        let Some(playbook_id) = digest
            .get("playbook_id")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
        else {
            continue;
        };

        let parent_session_id = json_string(&event.details, "parent_session_id")
            .unwrap_or_else(|| session_id.to_string());
        let playbook = playbook_specs.get(&playbook_id);
        let playbook_label = digest
            .get("playbook_label")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .or_else(|| playbook.map(|record| record.label.clone()))
            .unwrap_or_else(|| humanize_token(&playbook_id));
        let timestamp_ms = parse_event_timestamp_ms(&event);
        let run_id = format!("{}:{}", parent_session_id, playbook_id);
        let phase = digest
            .get("phase")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("observed");
        let status = digest
            .get("status")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| event_status_label(&event.status));
        let summary = json_string(&event.details, "summary").unwrap_or_else(|| event.title.clone());
        let step_id = json_string(&event.details, "step_id");
        let step_label = json_string(&event.details, "step_label");
        let child_session_id = json_string(&event.details, "child_session_id");
        let template_id = json_string(&event.details, "template_id");
        let workflow_id = json_string(&event.details, "workflow_id");
        let error_class = digest
            .get("error_class")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string);
        let success = digest
            .get("success")
            .and_then(Value::as_bool)
            .unwrap_or(matches!(event.status, EventStatus::Success));

        let run = runs.entry(run_id.clone()).or_insert_with(|| {
            crate::models::LocalEngineParentPlaybookRunRecord {
                run_id: run_id.clone(),
                parent_session_id: parent_session_id.clone(),
                playbook_id: playbook_id.clone(),
                playbook_label: playbook_label.clone(),
                status: status.to_string(),
                latest_phase: phase.to_string(),
                summary: playbook
                    .map(|record| record.summary.clone())
                    .unwrap_or_else(|| format!("Observed parent playbook '{}'.", playbook_label)),
                current_step_id: None,
                current_step_label: None,
                active_child_session_id: None,
                started_at_ms: timestamp_ms,
                updated_at_ms: timestamp_ms,
                completed_at_ms: None,
                error_class: None,
                steps: seed_parent_playbook_step_records(playbook),
            }
        });

        run.playbook_label = playbook_label;
        run.status = status.to_string();
        run.latest_phase = phase.to_string();
        run.summary = summary.clone();
        run.updated_at_ms = run.updated_at_ms.max(timestamp_ms);
        run.started_at_ms = run.started_at_ms.min(timestamp_ms);
        if let Some(error_class) = error_class.clone() {
            run.error_class = Some(error_class);
        }

        if phase == "completed" || matches!(status, "completed" | "failed") {
            run.completed_at_ms = Some(timestamp_ms);
            run.active_child_session_id = None;
        }

        if let Some(step_id) = step_id.as_deref() {
            let step_index = ensure_parent_playbook_step_index(
                run,
                playbook,
                step_id,
                step_label.as_deref(),
                template_id.as_deref(),
                workflow_id.as_deref(),
            );
            let step = &mut run.steps[step_index];
            step.summary = summary.clone();
            step.updated_at_ms = Some(timestamp_ms);
            if let Some(child_session_id) = child_session_id.clone() {
                step.child_session_id = Some(child_session_id);
            }
            if let Some(template_id) = template_id.clone() {
                step.template_id = Some(template_id);
            }
            if let Some(workflow_id) = workflow_id.clone() {
                step.workflow_id = Some(workflow_id);
            }
            if let Some(error_class) = error_class.clone() {
                step.error_class = Some(error_class);
            }

            match phase {
                "step_spawned" => {
                    step.status = "running".to_string();
                    run.current_step_id = Some(step.step_id.clone());
                    run.current_step_label = Some(step.label.clone());
                    run.active_child_session_id = child_session_id.clone();
                }
                "operator_retry_requested" | "operator_resume_requested" => {
                    step.status = "running".to_string();
                    step.completed_at_ms = None;
                    step.error_class = None;
                    run.status = "running".to_string();
                    run.current_step_id = Some(step.step_id.clone());
                    run.current_step_label = Some(step.label.clone());
                    run.active_child_session_id = child_session_id.clone();
                    run.completed_at_ms = None;
                    run.error_class = None;
                }
                "step_completed" => {
                    step.status = "completed".to_string();
                    step.completed_at_ms = Some(timestamp_ms);
                    run.current_step_id = Some(step.step_id.clone());
                    run.current_step_label = Some(step.label.clone());
                    if run.active_child_session_id == child_session_id {
                        run.active_child_session_id = None;
                    }
                }
                "blocked" => {
                    step.status = "blocked".to_string();
                    run.current_step_id = Some(step.step_id.clone());
                    run.current_step_label = Some(step.label.clone());
                    run.active_child_session_id = child_session_id.clone();
                }
                _ => {
                    if !success {
                        step.status = "failed".to_string();
                    } else if status == "running" && step.status == "pending" {
                        step.status = "running".to_string();
                    } else if matches!(status, "completed" | "failed") {
                        step.status = status.to_string();
                    }
                }
            }

            step.receipts
                .push(crate::models::LocalEngineParentPlaybookReceiptRecord {
                    event_id: event.event_id.clone(),
                    timestamp_ms,
                    phase: phase.to_string(),
                    status: status.to_string(),
                    success,
                    summary: summary.clone(),
                    receipt_ref: event.receipt_ref.clone(),
                    child_session_id,
                    template_id,
                    workflow_id,
                    error_class,
                    artifact_ids: event
                        .artifact_refs
                        .iter()
                        .map(|artifact| artifact.artifact_id.clone())
                        .collect(),
                });
        }
    }
}

fn build_parent_playbook_runs(
    memory_runtime: &std::sync::Arc<ioi_memory::MemoryRuntime>,
    sessions: &[crate::models::SessionSummary],
    playbooks: &[crate::models::LocalEngineAgentPlaybookRecord],
) -> Vec<crate::models::LocalEngineParentPlaybookRunRecord> {
    let playbook_specs = playbooks
        .iter()
        .map(|playbook| (playbook.playbook_id.clone(), playbook.clone()))
        .collect::<BTreeMap<_, _>>();
    let mut runs = BTreeMap::<String, crate::models::LocalEngineParentPlaybookRunRecord>::new();

    for session in sessions.iter().take(16) {
        let events = orchestrator::load_events(memory_runtime, &session.session_id, None, None);
        ingest_parent_playbook_events(&session.session_id, &events, &playbook_specs, &mut runs);
    }

    let mut projected = runs.into_values().collect::<Vec<_>>();
    for run in projected.iter_mut() {
        if run.current_step_id.is_none() {
            let selected_step = run
                .steps
                .iter()
                .find(|step| matches!(step.status.as_str(), "running" | "blocked" | "failed"))
                .or_else(|| run.steps.iter().find(|step| step.status == "pending"))
                .or_else(|| {
                    run.steps
                        .iter()
                        .rev()
                        .find(|step| step.status == "completed")
                });
            if let Some(step) = selected_step {
                run.current_step_id = Some(step.step_id.clone());
                run.current_step_label = Some(step.label.clone());
            }
        }
    }
    projected.sort_by(|left, right| {
        right
            .updated_at_ms
            .cmp(&left.updated_at_ms)
            .then_with(|| left.playbook_label.cmp(&right.playbook_label))
    });
    projected
}

fn visible_parent_playbook_runs(
    memory_runtime: &std::sync::Arc<ioi_memory::MemoryRuntime>,
    sessions: &[crate::models::SessionSummary],
    playbooks: &[crate::models::LocalEngineAgentPlaybookRecord],
) -> Vec<crate::models::LocalEngineParentPlaybookRunRecord> {
    let dismissed = orchestrator::load_local_engine_parent_playbook_dismissals(memory_runtime)
        .into_iter()
        .collect::<std::collections::HashSet<_>>();
    build_parent_playbook_runs(memory_runtime, sessions, playbooks)
        .into_iter()
        .filter(|run| !dismissed.contains(&run.run_id))
        .collect()
}

fn resolve_parent_playbook_run(
    memory_runtime: &std::sync::Arc<ioi_memory::MemoryRuntime>,
    run_id: &str,
) -> Option<crate::models::LocalEngineParentPlaybookRunRecord> {
    let playbooks = default_agent_playbooks();
    let sessions = orchestrator::get_local_sessions(memory_runtime);
    build_parent_playbook_runs(memory_runtime, &sessions, &playbooks)
        .into_iter()
        .find(|run| run.run_id == run_id)
}

fn select_parent_playbook_step<'a>(
    run: &'a crate::models::LocalEngineParentPlaybookRunRecord,
    step_id: Option<&str>,
) -> Option<&'a crate::models::LocalEngineParentPlaybookStepRunRecord> {
    if let Some(step_id) = step_id {
        let trimmed = step_id.trim();
        if !trimmed.is_empty() {
            if let Some(step) = run.steps.iter().find(|step| step.step_id == trimmed) {
                return Some(step);
            }
        }
    }

    run.current_step_id
        .as_deref()
        .and_then(|current| run.steps.iter().find(|step| step.step_id == current))
        .or_else(|| {
            run.steps
                .iter()
                .find(|step| matches!(step.status.as_str(), "blocked" | "failed" | "running"))
        })
        .or_else(|| run.steps.iter().find(|step| step.status == "pending"))
        .or_else(|| run.steps.last())
}

fn persist_parent_playbook_dismissal(
    memory_runtime: &std::sync::Arc<ioi_memory::MemoryRuntime>,
    run_id: &str,
    dismissed: bool,
) {
    let mut run_ids = orchestrator::load_local_engine_parent_playbook_dismissals(memory_runtime);
    if dismissed {
        if !run_ids.iter().any(|entry| entry == run_id) {
            run_ids.push(run_id.to_string());
        }
    } else {
        run_ids.retain(|entry| entry != run_id);
    }
    orchestrator::save_local_engine_parent_playbook_dismissals(memory_runtime, &run_ids);
}

fn parent_playbook_thread_step_index(app: &tauri::AppHandle, parent_session_id: &str) -> u32 {
    let state = app.state::<Mutex<AppState>>();
    state
        .lock()
        .ok()
        .and_then(|guard| guard.current_task.clone())
        .and_then(|task| {
            let task_session_id = task.session_id.clone().unwrap_or_else(|| task.id.clone());
            if task_session_id == parent_session_id {
                Some(task.progress)
            } else {
                None
            }
        })
        .unwrap_or_default()
}

fn register_parent_playbook_operator_event(
    app: &tauri::AppHandle,
    run: &crate::models::LocalEngineParentPlaybookRunRecord,
    phase: &str,
    status: &str,
    step: Option<&crate::models::LocalEngineParentPlaybookStepRunRecord>,
    summary: &str,
    target_session_id: Option<&str>,
) {
    let event = crate::kernel::events::build_event(
        &run.parent_session_id,
        parent_playbook_thread_step_index(app, &run.parent_session_id),
        crate::models::EventType::InfoNote,
        format!(
            "Operator {} {}",
            humanize_token(phase).to_lowercase(),
            run.playbook_label
        ),
        json!({
            "kind": "parent_playbook",
            "tool_name": "autopilot__parent_playbook_control",
            "phase": phase,
            "playbook_id": run.playbook_id,
            "playbook_label": run.playbook_label,
            "status": status,
            "success": true,
        }),
        json!({
            "timestamp_ms": Utc::now().timestamp_millis().max(0) as u64,
            "parent_session_id": run.parent_session_id,
            "step_id": step.map(|entry| entry.step_id.clone()),
            "step_label": step.map(|entry| entry.label.clone()),
            "child_session_id": step.and_then(|entry| entry.child_session_id.clone()),
            "template_id": step.and_then(|entry| entry.template_id.clone()),
            "workflow_id": step.and_then(|entry| entry.workflow_id.clone()),
            "operator_target_session_id": target_session_id,
            "summary": summary,
        }),
        EventStatus::Success,
        Vec::new(),
        None,
        Vec::new(),
        None,
    );
    crate::kernel::events::register_event(app, event);
}

fn mark_parent_playbook_operator_state(
    app: &tauri::AppHandle,
    run: &crate::models::LocalEngineParentPlaybookRunRecord,
    step: Option<&crate::models::LocalEngineParentPlaybookStepRunRecord>,
    summary: &str,
) {
    crate::kernel::state::update_task_state(app, |task| {
        let task_session_id = task.session_id.clone().unwrap_or_else(|| task.id.clone());
        if task_session_id == run.parent_session_id {
            task.phase = crate::models::AgentPhase::Running;
            task.current_step = summary.to_string();
        }

        if let Some(step) = step {
            if let Some(child_session_id) = step.child_session_id.as_deref() {
                if let Some(agent) = task
                    .swarm_tree
                    .iter_mut()
                    .find(|agent| agent.id == child_session_id)
                {
                    agent.status = "running".to_string();
                    agent.current_thought = Some(summary.to_string());
                }
            }
        }
    });
}

fn build_local_engine_activity_record(
    session_id: &str,
    event: &crate::models::AgentEvent,
) -> Option<crate::models::LocalEngineActivityRecord> {
    let digest = event.digest.as_object()?;
    let family = digest.get("kind")?.as_str()?.to_string();
    let tool_name = digest.get("tool_name")?.as_str()?.to_string();

    if family == "model_lifecycle"
        || family == "parent_playbook"
        || tool_name.starts_with("model__")
        || tool_name.starts_with("media__")
        || tool_name.starts_with("model_registry__")
        || tool_name.starts_with("backend__")
        || tool_name.starts_with("gallery__")
    {
        let payload = event
            .details
            .get("payload")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        let subject_kind = digest
            .get("subject_kind")
            .and_then(Value::as_str)
            .map(str::to_string);
        let subject_id = digest
            .get("subject_id")
            .or_else(|| digest.get("model_id"))
            .and_then(Value::as_str)
            .map(str::to_string);
        let operation = digest
            .get("operation")
            .and_then(Value::as_str)
            .map(str::to_string);
        let error_class = digest
            .get("error_class")
            .and_then(Value::as_str)
            .map(str::to_string);
        let backend_id = payload
            .get("backend_id")
            .and_then(Value::as_str)
            .map(str::to_string);
        let success = digest
            .get("success")
            .and_then(Value::as_bool)
            .unwrap_or(matches!(event.status, EventStatus::Success));

        let title = match family.as_str() {
            "model_lifecycle" => {
                let operation = operation
                    .clone()
                    .unwrap_or_else(|| "control".to_string())
                    .replace('_', " ");
                format!(
                    "{} {}",
                    operation,
                    subject_kind
                        .clone()
                        .unwrap_or_else(|| "subject".to_string())
                )
            }
            "inference" => "Run model workload".to_string(),
            "media" => "Run media workload".to_string(),
            "parent_playbook" => "Advance parent playbook".to_string(),
            _ => "Kernel-native workload".to_string(),
        };

        return Some(crate::models::LocalEngineActivityRecord {
            event_id: event.event_id.clone(),
            session_id: session_id.to_string(),
            family,
            title,
            tool_name,
            timestamp_ms: parse_event_timestamp_ms(event),
            success,
            operation,
            subject_kind,
            subject_id,
            backend_id,
            error_class,
        });
    }

    None
}

#[tauri::command]
pub async fn get_local_engine_snapshot(
    state: State<'_, Mutex<AppState>>,
) -> Result<crate::models::LocalEngineSnapshot, String> {
    let memory_runtime =
        app_memory_runtime(&state).ok_or_else(|| "Memory runtime unavailable".to_string())?;
    let tools = collect_available_tools(&state).await?;
    let capabilities = build_local_engine_capabilities(&tools);
    let control_plane = load_or_initialize_local_engine_control_plane(&memory_runtime);
    let worker_templates = load_or_initialize_worker_templates(&memory_runtime);
    let agent_playbooks = default_agent_playbooks();
    let registry_state = crate::kernel::local_engine::load_or_sync_registry_state(
        &memory_runtime,
        Some(&control_plane),
    );
    let compatibility_routes = build_local_engine_compatibility_routes(&control_plane);
    let mut staged_operations = orchestrator::load_local_engine_staged_operations(&memory_runtime);
    staged_operations.sort_by(|left, right| {
        right
            .created_at_ms
            .cmp(&left.created_at_ms)
            .then_with(|| left.title.cmp(&right.title))
    });
    let mut jobs = orchestrator::load_local_engine_jobs(&memory_runtime);
    jobs.sort_by(|left, right| {
        right
            .updated_at_ms
            .cmp(&left.updated_at_ms)
            .then_with(|| left.title.cmp(&right.title))
    });

    let interventions = orchestrator::load_interventions(&memory_runtime);
    let mut pending_controls = interventions
        .into_iter()
        .filter(is_local_engine_intervention)
        .filter(|record| unresolved_intervention_status(&record.status))
        .map(|record| crate::models::LocalEngineControlAction {
            item_id: record.item_id,
            title: record.title,
            summary: record.summary,
            status: intervention_status_label(&record.status).to_string(),
            severity: notification_severity_label(&record.severity).to_string(),
            requested_at_ms: record.created_at_ms,
            due_at_ms: record.due_at_ms,
            approval_scope: record.approval_scope,
            sensitive_action_type: record.sensitive_action_type,
            recommended_action: record.recommended_action,
            recovery_hint: record.recovery_hint,
            request_hash: record.request_hash,
        })
        .collect::<Vec<_>>();
    pending_controls.sort_by(|left, right| {
        right
            .requested_at_ms
            .cmp(&left.requested_at_ms)
            .then_with(|| left.title.cmp(&right.title))
    });
    pending_controls.extend(
        staged_operations
            .iter()
            .map(staged_operation_to_control_action)
            .collect::<Vec<_>>(),
    );
    pending_controls.sort_by(|left, right| {
        right
            .requested_at_ms
            .cmp(&left.requested_at_ms)
            .then_with(|| left.title.cmp(&right.title))
    });

    let sessions = orchestrator::get_local_sessions(&memory_runtime);
    let parent_playbook_runs =
        visible_parent_playbook_runs(&memory_runtime, &sessions, &agent_playbooks);
    let mut recent_activity = sessions
        .iter()
        .take(12)
        .flat_map(|session| {
            orchestrator::load_events(&memory_runtime, &session.session_id, None, None)
                .into_iter()
                .filter_map(|event| build_local_engine_activity_record(&session.session_id, &event))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    recent_activity =
        crate::kernel::local_engine::merge_recent_activity(recent_activity, &registry_state, 12);

    let pending_approval_count = pending_controls
        .iter()
        .filter(|record| {
            matches!(
                record.status.as_str(),
                "new" | "seen" | "pending" | "snoozed"
            )
        })
        .count();
    let active_issue_count = pending_controls
        .iter()
        .filter(|record| matches!(record.severity.as_str(), "critical" | "high"))
        .count()
        + jobs
            .iter()
            .filter(|job| matches!(job.status.as_str(), "failed"))
            .count()
        + registry_state
            .registry_models
            .iter()
            .filter(|record| matches!(record.status.as_str(), "failed"))
            .count()
        + registry_state
            .managed_backends
            .iter()
            .filter(|record| {
                matches!(record.status.as_str(), "failed") || record.health == "degraded"
            })
            .count()
        + registry_state
            .gallery_catalogs
            .iter()
            .filter(|record| matches!(record.sync_status.as_str(), "failed"))
            .count()
        + parent_playbook_runs
            .iter()
            .filter(|run| matches!(run.status.as_str(), "blocked" | "failed"))
            .count()
        + recent_activity
            .iter()
            .filter(|record| !record.success && record.family != "parent_playbook")
            .count();

    Ok(crate::models::LocalEngineSnapshot {
        generated_at_ms: Utc::now().timestamp_millis().max(0) as u64,
        total_native_tools: capabilities
            .iter()
            .flat_map(|family| family.tool_names.iter().cloned())
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        pending_control_count: pending_controls.len(),
        pending_approval_count,
        active_issue_count,
        capabilities,
        compatibility_routes,
        pending_controls,
        jobs,
        recent_activity,
        registry_models: registry_state.registry_models,
        managed_backends: registry_state.managed_backends,
        gallery_catalogs: registry_state.gallery_catalogs,
        worker_templates,
        agent_playbooks,
        parent_playbook_runs,
        control_plane,
        staged_operations,
    })
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalEngineOperationDraftInput {
    pub subject_kind: String,
    pub operation: String,
    pub source_uri: Option<String>,
    pub subject_id: Option<String>,
    pub notes: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalEngineJobStatusUpdateInput {
    pub job_id: String,
    pub status: String,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ParentPlaybookResumeInput {
    pub run_id: String,
    pub step_id: Option<String>,
}

#[tauri::command]
pub async fn save_local_engine_control_plane(
    state: State<'_, Mutex<AppState>>,
    control_plane: crate::models::LocalEngineControlPlane,
) -> Result<crate::models::LocalEngineControlPlane, String> {
    let memory_runtime =
        app_memory_runtime(&state).ok_or_else(|| "Memory runtime unavailable".to_string())?;
    let normalized = normalize_local_engine_control_plane(control_plane);
    orchestrator::save_local_engine_control_plane(&memory_runtime, &normalized);
    let _ = crate::kernel::local_engine::load_or_sync_registry_state(
        &memory_runtime,
        Some(&normalized),
    );
    Ok(normalized)
}

#[tauri::command]
pub async fn stage_local_engine_operation(
    state: State<'_, Mutex<AppState>>,
    draft: LocalEngineOperationDraftInput,
) -> Result<crate::models::LocalEngineStagedOperation, String> {
    let memory_runtime =
        app_memory_runtime(&state).ok_or_else(|| "Memory runtime unavailable".to_string())?;

    let subject_kind = trim_or_empty(draft.subject_kind).to_ascii_lowercase();
    let operation = trim_or_empty(draft.operation).to_ascii_lowercase();
    if subject_kind.is_empty() || operation.is_empty() {
        return Err("subject_kind and operation are required".to_string());
    }

    let subject_id = normalize_optional_text(draft.subject_id);
    let source_uri = normalize_optional_text(draft.source_uri);
    let notes = normalize_optional_text(draft.notes);
    let created_at_ms = Utc::now().timestamp_millis().max(0) as u64;
    let digest = sha256(
        format!(
            "{}|{}|{}|{}|{}",
            subject_kind,
            operation,
            source_uri.as_deref().unwrap_or_default(),
            subject_id.as_deref().unwrap_or_default(),
            created_at_ms
        )
        .as_bytes(),
    )
    .map_err(|error| format!("failed to stage local engine operation: {}", error))?;

    let mut staged_operations = orchestrator::load_local_engine_staged_operations(&memory_runtime);
    let staged = crate::models::LocalEngineStagedOperation {
        operation_id: hex::encode(digest),
        subject_kind: subject_kind.clone(),
        operation: operation.clone(),
        title: stage_operation_title(&subject_kind, &operation, subject_id.as_deref()),
        source_uri,
        subject_id,
        notes,
        created_at_ms,
        status: "staged".to_string(),
    };
    staged_operations.push(staged.clone());
    staged_operations.sort_by(|left, right| right.created_at_ms.cmp(&left.created_at_ms));
    orchestrator::save_local_engine_staged_operations(&memory_runtime, &staged_operations);
    Ok(staged)
}

#[tauri::command]
pub async fn remove_local_engine_operation(
    state: State<'_, Mutex<AppState>>,
    operation_id: String,
) -> Result<(), String> {
    let memory_runtime =
        app_memory_runtime(&state).ok_or_else(|| "Memory runtime unavailable".to_string())?;
    let mut staged_operations = orchestrator::load_local_engine_staged_operations(&memory_runtime);
    staged_operations.retain(|operation| operation.operation_id != operation_id);
    orchestrator::save_local_engine_staged_operations(&memory_runtime, &staged_operations);
    Ok(())
}

#[tauri::command]
pub async fn promote_local_engine_operation(
    state: State<'_, Mutex<AppState>>,
    operation_id: String,
) -> Result<crate::models::LocalEngineJobRecord, String> {
    let memory_runtime =
        app_memory_runtime(&state).ok_or_else(|| "Memory runtime unavailable".to_string())?;
    let mut staged_operations = orchestrator::load_local_engine_staged_operations(&memory_runtime);
    let Some(index) = staged_operations
        .iter()
        .position(|operation| operation.operation_id == operation_id)
    else {
        return Err("staged operation not found".to_string());
    };

    let operation = staged_operations.remove(index);
    orchestrator::save_local_engine_staged_operations(&memory_runtime, &staged_operations);

    let now_ms = Utc::now().timestamp_millis().max(0) as u64;
    let mut jobs = orchestrator::load_local_engine_jobs(&memory_runtime);
    let job = local_engine_job_from_staged_operation(&operation, now_ms);
    if let Some(existing_index) = jobs.iter().position(|entry| entry.job_id == job.job_id) {
        jobs[existing_index] = job.clone();
    } else {
        jobs.push(job.clone());
    }
    jobs.sort_by(|left, right| {
        right
            .updated_at_ms
            .cmp(&left.updated_at_ms)
            .then_with(|| left.title.cmp(&right.title))
    });
    orchestrator::save_local_engine_jobs(&memory_runtime, &jobs);
    let control_plane = load_or_initialize_local_engine_control_plane(&memory_runtime);
    crate::kernel::local_engine::record_promoted_job(&memory_runtime, Some(&control_plane), &job);
    Ok(job)
}

#[tauri::command]
pub async fn update_local_engine_job_status(
    state: State<'_, Mutex<AppState>>,
    input: LocalEngineJobStatusUpdateInput,
) -> Result<crate::models::LocalEngineJobRecord, String> {
    let memory_runtime =
        app_memory_runtime(&state).ok_or_else(|| "Memory runtime unavailable".to_string())?;
    let control_plane = load_or_initialize_local_engine_control_plane(&memory_runtime);
    crate::kernel::local_engine::update_job_status(
        &memory_runtime,
        Some(&control_plane),
        &input.job_id,
        &input.status,
    )
}

#[tauri::command]
pub async fn retry_local_engine_parent_playbook_run(
    state: State<'_, Mutex<AppState>>,
    app: tauri::AppHandle,
    run_id: String,
) -> Result<(), String> {
    let memory_runtime =
        app_memory_runtime(&state).ok_or_else(|| "Memory runtime unavailable".to_string())?;
    persist_parent_playbook_dismissal(&memory_runtime, &run_id, false);
    let run = resolve_parent_playbook_run(&memory_runtime, &run_id)
        .ok_or_else(|| "parent playbook run not found".to_string())?;
    let step = select_parent_playbook_step(&run, None)
        .ok_or_else(|| "no current step is available to retry".to_string())?;
    let target_session_id = step
        .child_session_id
        .as_deref()
        .unwrap_or(run.parent_session_id.as_str());
    let summary = format!(
        "Operator requested retry for '{}' in parent playbook '{}'.",
        step.label, run.playbook_label
    );
    let message = format!(
        "Operator request: retry the '{}' step for parent playbook '{}'. Re-evaluate the last failure, revise your work instead of restarting blindly when possible, and continue toward the existing success criteria.",
        step.label, run.playbook_label
    );
    crate::kernel::task::send_message_to_session(&app, target_session_id, message).await?;
    mark_parent_playbook_operator_state(&app, &run, Some(step), &summary);
    register_parent_playbook_operator_event(
        &app,
        &run,
        "operator_retry_requested",
        "running",
        Some(step),
        &summary,
        Some(target_session_id),
    );
    crate::kernel::local_engine::emit_local_engine_update(&app, "parent_playbook_retry_requested");
    Ok(())
}

#[tauri::command]
pub async fn resume_local_engine_parent_playbook_run(
    state: State<'_, Mutex<AppState>>,
    app: tauri::AppHandle,
    input: ParentPlaybookResumeInput,
) -> Result<(), String> {
    let memory_runtime =
        app_memory_runtime(&state).ok_or_else(|| "Memory runtime unavailable".to_string())?;
    persist_parent_playbook_dismissal(&memory_runtime, &input.run_id, false);
    let run = resolve_parent_playbook_run(&memory_runtime, &input.run_id)
        .ok_or_else(|| "parent playbook run not found".to_string())?;
    let step = select_parent_playbook_step(&run, input.step_id.as_deref())
        .ok_or_else(|| "no step is available to resume".to_string())?;
    let summary = format!(
        "Operator requested resume from '{}' in parent playbook '{}'.",
        step.label, run.playbook_label
    );
    let message = format!(
        "Operator request: resume the parent playbook '{}' from the '{}' step. Reopen that step, preserve prior evidence when it is still valid, redo dependent work when necessary, and continue the ordered sequence to completion.",
        run.playbook_label, step.label
    );
    crate::kernel::task::send_message_to_session(&app, &run.parent_session_id, message).await?;
    mark_parent_playbook_operator_state(&app, &run, Some(step), &summary);
    register_parent_playbook_operator_event(
        &app,
        &run,
        "operator_resume_requested",
        "running",
        Some(step),
        &summary,
        Some(run.parent_session_id.as_str()),
    );
    crate::kernel::local_engine::emit_local_engine_update(&app, "parent_playbook_resume_requested");
    Ok(())
}

#[tauri::command]
pub async fn dismiss_local_engine_parent_playbook_run(
    state: State<'_, Mutex<AppState>>,
    app: tauri::AppHandle,
    run_id: String,
) -> Result<(), String> {
    let memory_runtime =
        app_memory_runtime(&state).ok_or_else(|| "Memory runtime unavailable".to_string())?;
    let run = resolve_parent_playbook_run(&memory_runtime, &run_id)
        .ok_or_else(|| "parent playbook run not found".to_string())?;
    persist_parent_playbook_dismissal(&memory_runtime, &run_id, true);
    let summary = format!(
        "Operator dismissed parent playbook '{}' from the Runtime Deck.",
        run.playbook_label
    );
    register_parent_playbook_operator_event(
        &app,
        &run,
        "operator_dismissed",
        run.status.as_str(),
        select_parent_playbook_step(&run, run.current_step_id.as_deref()),
        &summary,
        Some(run.parent_session_id.as_str()),
    );
    crate::kernel::local_engine::emit_local_engine_update(&app, "parent_playbook_dismissed");
    Ok(())
}

#[tauri::command]
pub async fn get_skill_catalog(
    state: State<'_, Mutex<AppState>>,
) -> Result<Vec<SkillCatalogEntry>, String> {
    let mut client = get_rpc_client(&state).await?;
    load_skill_catalog_entries(&mut client).await
}

#[tauri::command]
pub async fn get_memory_runtime_session_status(
    state: State<'_, Mutex<AppState>>,
    session_id: String,
) -> Result<ioi_services::agentic::desktop::service::memory::MemorySessionStatus, String> {
    let parsed_session_id = parse_hex_32(&session_id)?;
    let memory_runtime =
        app_memory_runtime(&state).ok_or_else(|| "Memory runtime unavailable".to_string())?;
    ioi_services::agentic::desktop::service::memory::load_memory_session_status(
        memory_runtime.as_ref(),
        parsed_session_id,
    )
    .map_err(|error| error.to_string())
}

#[tauri::command]
pub async fn get_context_blob(
    state: State<'_, Mutex<AppState>>,
    hash: String,
) -> Result<ContextBlob, String> {
    let mut client = get_rpc_client(&state).await?;

    let request = tonic::Request::new(GetContextBlobRequest { blob_hash: hash });

    let response = match client.get_context_blob(request).await {
        Ok(resp) => resp.into_inner(),
        Err(status) if status.code() == Code::NotFound => {
            return Ok(ContextBlob {
                data_base64: String::new(),
                mime_type: CONTEXT_BLOB_UNAVAILABLE_MIME.to_string(),
            });
        }
        Err(status) => return Err(format!("RPC error: {}", status)),
    };

    let data_base64 = STANDARD.encode(&response.data);

    let mime_type = if response.mime_type == "application/octet-stream" {
        if response.data.starts_with(b"\x89PNG") {
            "image/png".to_string()
        } else if response.data.starts_with(b"<") || response.data.starts_with(b"<?xml") {
            "text/xml".to_string()
        } else if response.data.starts_with(b"{") || response.data.starts_with(b"[") {
            "application/json".to_string()
        } else {
            "text/plain".to_string()
        }
    } else {
        response.mime_type
    };

    Ok(ContextBlob {
        data_base64,
        mime_type,
    })
}

async fn query_raw_state(
    client: &mut PublicApiClient<Channel>,
    key: Vec<u8>,
) -> Result<Option<Vec<u8>>, String> {
    let response = client
        .query_raw_state(tonic::Request::new(QueryRawStateRequest { key }))
        .await
        .map_err(|status| format!("RPC error: {}", status))?
        .into_inner();
    if response.found {
        Ok(Some(response.value))
    } else {
        Ok(None)
    }
}

async fn load_skill_bundle(
    client: &mut PublicApiClient<Channel>,
    skill_hash: [u8; 32],
) -> Result<Option<SkillBundle>, String> {
    let Some(record_bytes) = query_raw_state(client, get_skill_record_key(&skill_hash)).await?
    else {
        return Ok(None);
    };
    let record = codec::from_bytes_canonical::<SkillRecord>(&record_bytes)
        .map_err(|e| format!("Failed to decode skill record: {}", e))?;
    let published_doc =
        if let Some(doc_bytes) = query_raw_state(client, get_skill_doc_key(&skill_hash)).await? {
            codec::from_bytes_canonical::<PublishedSkillDoc>(&doc_bytes).ok()
        } else {
            None
        };
    let evidence = if let Some(evidence_hash) = record.source_evidence_hash {
        if let Some(evidence_bytes) =
            query_raw_state(client, get_skill_external_evidence_key(&evidence_hash)).await?
        {
            codec::from_bytes_canonical::<ExternalSkillEvidence>(&evidence_bytes).ok()
        } else {
            None
        }
    } else {
        None
    };

    Ok(Some(SkillBundle {
        record,
        published_doc,
        evidence,
    }))
}

async fn load_skill_bundles(
    client: &mut PublicApiClient<Channel>,
) -> Result<Vec<SkillBundle>, String> {
    let index =
        if let Some(bytes) = query_raw_state(client, SKILL_CATALOG_INDEX_KEY.to_vec()).await? {
            codec::from_bytes_canonical::<SkillCatalogIndex>(&bytes)
                .map_err(|e| format!("Failed to decode skill catalog index: {}", e))?
        } else {
            SkillCatalogIndex::default()
        };

    let mut bundles = Vec::new();
    for skill_hash in index.skills {
        if let Some(bundle) = load_skill_bundle(client, skill_hash).await? {
            bundles.push(bundle);
        }
    }
    bundles.sort_by(|left, right| {
        left.record
            .macro_body
            .definition
            .name
            .cmp(&right.record.macro_body.definition.name)
    });
    Ok(bundles)
}

fn load_thread_events_for_session(
    state: &State<'_, Mutex<AppState>>,
    session_id: &str,
) -> Result<Vec<crate::models::AgentEvent>, String> {
    let memory_runtime = state
        .lock()
        .map_err(|_| "Failed to lock state".to_string())?
        .memory_runtime
        .clone()
        .ok_or_else(|| "Memory runtime unavailable".to_string())?;
    Ok(orchestrator::load_events(
        &memory_runtime,
        session_id,
        None,
        None,
    ))
}

fn active_tool_items(active_bundles: &[SkillBundle]) -> Vec<ActiveContextItem> {
    let mut counts = HashMap::<String, usize>::new();
    for bundle in active_bundles {
        for tool_name in used_tools_for_record(&bundle.record) {
            *counts.entry(tool_name).or_insert(0) += 1;
        }
    }

    let mut tools = counts
        .into_iter()
        .map(|(tool_name, count)| ActiveContextItem {
            id: tool_focus_id(&tool_name),
            kind: "tool".to_string(),
            title: tool_name.clone(),
            summary: format!("Referenced by {} active skill(s)", count),
            badge: Some("tool".to_string()),
            secondary_badge: Some(format!(
                "{} skill{}",
                count,
                if count == 1 { "" } else { "s" }
            )),
            success_rate_bps: None,
            sample_size: None,
            focus_id: Some(tool_focus_id(&tool_name)),
            skill_hash: None,
            source_session_id: None,
            source_evidence_hash: None,
            relative_path: None,
            stale: None,
        })
        .collect::<Vec<_>>();
    tools.sort_by(|left, right| left.title.cmp(&right.title));
    tools
}

fn active_evidence_items(active_bundles: &[SkillBundle]) -> Vec<ActiveContextItem> {
    let mut items = Vec::new();
    for bundle in active_bundles {
        if let Some(doc) = bundle.published_doc.as_ref() {
            items.push(ActiveContextItem {
                id: doc_focus_id(&bundle.record.skill_hash),
                kind: "published_doc".to_string(),
                title: doc.name.clone(),
                summary: summary_text(&doc.markdown, 180),
                badge: Some("SKILL.md".to_string()),
                secondary_badge: Some(if doc.stale { "stale" } else { "fresh" }.to_string()),
                success_rate_bps: None,
                sample_size: None,
                focus_id: Some(doc_focus_id(&bundle.record.skill_hash)),
                skill_hash: Some(hex::encode(bundle.record.skill_hash)),
                source_session_id: bundle.record.source_session_id.map(hex::encode),
                source_evidence_hash: bundle.record.source_evidence_hash.map(hex::encode),
                relative_path: Some(doc.relative_path.clone()),
                stale: Some(doc.stale),
            });
        }
        if let (Some(evidence_hash), Some(evidence)) =
            (bundle.record.source_evidence_hash, bundle.evidence.as_ref())
        {
            items.push(ActiveContextItem {
                id: evidence_focus_id(&evidence_hash),
                kind: "evidence".to_string(),
                title: evidence
                    .title
                    .clone()
                    .or_else(|| evidence.source_uri.clone())
                    .unwrap_or_else(|| "External evidence".to_string()),
                summary: summary_text(&evidence.normalized_procedure, 180),
                badge: Some(format!("{:?}", evidence.source_type)),
                secondary_badge: evidence.source_uri.clone(),
                success_rate_bps: None,
                sample_size: None,
                focus_id: Some(evidence_focus_id(&evidence_hash)),
                skill_hash: Some(hex::encode(bundle.record.skill_hash)),
                source_session_id: evidence.source_session_id.map(hex::encode),
                source_evidence_hash: Some(hex::encode(evidence_hash)),
                relative_path: None,
                stale: None,
            });
        }
    }
    items.sort_by(|left, right| left.title.cmp(&right.title));
    items
}

fn active_constraints(agent_state: &DesktopAgentState) -> Vec<ContextConstraint> {
    let mut constraints = vec![
        ContextConstraint {
            id: "mode".to_string(),
            label: "Mode".to_string(),
            value: format!("{:?}", agent_state.mode),
            severity: "info".to_string(),
            summary: "Current orchestration mode".to_string(),
        },
        ContextConstraint {
            id: "tier".to_string(),
            label: "Execution tier".to_string(),
            value: format!("{:?}", agent_state.current_tier),
            severity: "info".to_string(),
            summary: "Current execution surface".to_string(),
        },
    ];

    if let Some(tool_name) = agent_state.pending_tool_call.as_ref() {
        constraints.push(ContextConstraint {
            id: "pending_tool_call".to_string(),
            label: "Pending tool call".to_string(),
            value: tool_name.clone(),
            severity: "medium".to_string(),
            summary: "Execution is paused on a queued tool call".to_string(),
        });
    }

    if let Some(token) = agent_state.pending_approval.as_ref() {
        constraints.push(ContextConstraint {
            id: "pending_approval".to_string(),
            label: "Pending approval".to_string(),
            value: hex::encode(token.request_hash),
            severity: "high".to_string(),
            summary: "User approval is required before execution can continue".to_string(),
        });
    }

    if agent_state.awaiting_intent_clarification {
        constraints.push(ContextConstraint {
            id: "awaiting_intent_clarification".to_string(),
            label: "Clarification".to_string(),
            value: "awaiting input".to_string(),
            severity: "medium".to_string(),
            summary: "The planner is waiting for intent clarification".to_string(),
        });
    }

    constraints
}

fn build_context_neighborhood(
    session_id: &str,
    agent_state: &DesktopAgentState,
    active_bundles: &[SkillBundle],
    constraints: &[ContextConstraint],
) -> AtlasNeighborhood {
    let mut nodes = Vec::new();
    let mut node_ids = HashSet::new();
    let mut edges = Vec::new();
    let mut edge_ids = HashSet::new();
    let focus_id = session_focus_id(session_id);

    add_node(
        &mut nodes,
        &mut node_ids,
        AtlasNode {
            id: focus_id.clone(),
            kind: "session".to_string(),
            label: format!("Session {}", &normalize_hex_id(session_id)[..12]),
            summary: summary_text(&agent_state.goal, 180),
            status: Some(format!("{:?}", agent_state.status)),
            emphasis: Some(1.0),
            metadata: json!({
                "mode": format!("{:?}", agent_state.mode),
                "current_tier": format!("{:?}", agent_state.current_tier),
                "step_count": agent_state.step_count,
                "max_steps": agent_state.max_steps,
            }),
        },
    );

    for bundle in active_bundles {
        let skill_id = skill_focus_id(&bundle.record.skill_hash);
        add_node(
            &mut nodes,
            &mut node_ids,
            AtlasNode {
                id: skill_id.clone(),
                kind: "skill".to_string(),
                label: bundle.record.macro_body.definition.name.clone(),
                summary: bundle.record.macro_body.definition.description.clone(),
                status: Some(format!("{:?}", bundle.record.lifecycle_state)),
                emphasis: Some(
                    if Some(bundle.record.skill_hash) == agent_state.active_skill_hash {
                        0.95
                    } else {
                        0.72
                    },
                ),
                metadata: json!({
                    "source_type": format!("{:?}", bundle.record.source_type),
                    "success_rate_bps": bundle.record.benchmark.clone().unwrap_or_default().success_rate_bps,
                }),
            },
        );
        add_edge(
            &mut edges,
            &mut edge_ids,
            AtlasEdge {
                id: format!("{}::uses_skill::{}", focus_id, skill_id),
                source_id: focus_id.clone(),
                target_id: skill_id.clone(),
                relation: "uses_skill".to_string(),
                summary: Some("Active or recently used skill in this session".to_string()),
                weight: 0.88,
            },
        );

        for tool_name in used_tools_for_record(&bundle.record) {
            let tool_id = tool_focus_id(&tool_name);
            add_node(
                &mut nodes,
                &mut node_ids,
                AtlasNode {
                    id: tool_id.clone(),
                    kind: "tool".to_string(),
                    label: tool_name.clone(),
                    summary: format!(
                        "Tool reachable from {}",
                        bundle.record.macro_body.definition.name
                    ),
                    status: None,
                    emphasis: Some(0.58),
                    metadata: json!({}),
                },
            );
            add_edge(
                &mut edges,
                &mut edge_ids,
                AtlasEdge {
                    id: format!("{}::uses_tool::{}", skill_id, tool_id),
                    source_id: skill_id.clone(),
                    target_id: tool_id,
                    relation: "uses_tool".to_string(),
                    summary: Some("Macro step uses this tool".to_string()),
                    weight: 0.7,
                },
            );
        }

        if let Some(doc) = bundle.published_doc.as_ref() {
            let doc_id = doc_focus_id(&bundle.record.skill_hash);
            add_node(
                &mut nodes,
                &mut node_ids,
                AtlasNode {
                    id: doc_id.clone(),
                    kind: "published_doc".to_string(),
                    label: doc.name.clone(),
                    summary: summary_text(&doc.markdown, 160),
                    status: Some(if doc.stale { "stale" } else { "fresh" }.to_string()),
                    emphasis: Some(0.42),
                    metadata: json!({ "relative_path": doc.relative_path }),
                },
            );
            add_edge(
                &mut edges,
                &mut edge_ids,
                AtlasEdge {
                    id: format!("{}::published_as::{}", skill_id, doc_id),
                    source_id: skill_id.clone(),
                    target_id: doc_id,
                    relation: "published_as".to_string(),
                    summary: Some("Derived human-facing publication".to_string()),
                    weight: 0.56,
                },
            );
        }

        if let (Some(evidence_hash), Some(evidence)) =
            (bundle.record.source_evidence_hash, bundle.evidence.as_ref())
        {
            let evidence_id = evidence_focus_id(&evidence_hash);
            add_node(
                &mut nodes,
                &mut node_ids,
                AtlasNode {
                    id: evidence_id.clone(),
                    kind: "evidence".to_string(),
                    label: evidence
                        .title
                        .clone()
                        .or_else(|| evidence.source_uri.clone())
                        .unwrap_or_else(|| "External evidence".to_string()),
                    summary: summary_text(&evidence.normalized_procedure, 160),
                    status: Some(format!("{:?}", evidence.source_type)),
                    emphasis: Some(0.46),
                    metadata: json!({ "source_uri": evidence.source_uri }),
                },
            );
            add_edge(
                &mut edges,
                &mut edge_ids,
                AtlasEdge {
                    id: format!("{}::derived_from::{}", skill_id, evidence_id),
                    source_id: skill_id,
                    target_id: evidence_id,
                    relation: "derived_from".to_string(),
                    summary: Some("External procedure evidence".to_string()),
                    weight: 0.6,
                },
            );
        }
    }

    for constraint in constraints {
        let constraint_id = constraint_focus_id(&constraint.id);
        add_node(
            &mut nodes,
            &mut node_ids,
            AtlasNode {
                id: constraint_id.clone(),
                kind: "constraint".to_string(),
                label: constraint.label.clone(),
                summary: constraint.summary.clone(),
                status: Some(constraint.severity.clone()),
                emphasis: Some(0.38),
                metadata: json!({ "value": constraint.value }),
            },
        );
        add_edge(
            &mut edges,
            &mut edge_ids,
            AtlasEdge {
                id: format!("{}::constrained_by::{}", focus_id, constraint_id),
                source_id: focus_id.clone(),
                target_id: constraint_id,
                relation: "constrained_by".to_string(),
                summary: Some("Current execution constraint".to_string()),
                weight: 0.44,
            },
        );
    }

    AtlasNeighborhood {
        lens: "context".to_string(),
        title: "Active Context".to_string(),
        summary: format!(
            "{} skill nodes, {} constraint nodes",
            active_bundles.len(),
            constraints.len()
        ),
        focus_id: Some(focus_id),
        nodes,
        edges,
    }
}

fn lexical_goal_matches<'a>(bundles: &'a [SkillBundle], goal: &str) -> Vec<&'a SkillBundle> {
    let goal_lower = goal.to_ascii_lowercase();
    if goal_lower.trim().is_empty() {
        return Vec::new();
    }
    bundles
        .iter()
        .filter(|bundle| {
            let name = bundle
                .record
                .macro_body
                .definition
                .name
                .to_ascii_lowercase();
            let description = bundle
                .record
                .macro_body
                .definition
                .description
                .to_ascii_lowercase();
            goal_lower.contains(&name)
                || name.contains(&goal_lower)
                || description.contains(&goal_lower)
        })
        .collect()
}

async fn load_active_context_snapshot(
    state: &State<'_, Mutex<AppState>>,
    client: &mut PublicApiClient<Channel>,
    session_id: &str,
) -> Result<ActiveContextSnapshot, String> {
    let normalized_session_id = normalize_hex_id(session_id);
    let parsed_session_id = parse_hex_32(&normalized_session_id)?;
    let agent_state = if let Some(memory_runtime) = app_memory_runtime(state) {
        match load_agent_state_checkpoint(memory_runtime.as_ref(), parsed_session_id) {
            Ok(Some(agent_state)) => agent_state,
            Ok(None) => {
                let session_key = get_state_key(&parsed_session_id);
                let Some(agent_state_bytes) = query_raw_state(client, session_key).await? else {
                    return Err(format!(
                        "No agent state found for session {}",
                        normalized_session_id
                    ));
                };
                codec::from_bytes_canonical::<DesktopAgentState>(&agent_state_bytes)
                    .map_err(|e| format!("Failed to decode agent state: {}", e))?
            }
            Err(error) => {
                return Err(format!(
                    "Failed to load runtime agent state for session {}: {}",
                    normalized_session_id, error
                ));
            }
        }
    } else {
        let session_key = get_state_key(&parsed_session_id);
        let Some(agent_state_bytes) = query_raw_state(client, session_key).await? else {
            return Err(format!(
                "No agent state found for session {}",
                normalized_session_id
            ));
        };
        codec::from_bytes_canonical::<DesktopAgentState>(&agent_state_bytes)
            .map_err(|e| format!("Failed to decode agent state: {}", e))?
    };

    let mut trace_hashes = BTreeSet::new();
    for step_index in 0..=agent_state.step_count {
        let Some(trace_bytes) =
            query_raw_state(client, get_trace_key(&agent_state.session_id, step_index)).await?
        else {
            continue;
        };
        if let Ok(trace) = codec::from_bytes_canonical::<StepTrace>(&trace_bytes) {
            if let Some(skill_hash) = trace.skill_hash {
                trace_hashes.insert(skill_hash);
            }
        }
    }
    if let Some(skill_hash) = agent_state.active_skill_hash {
        trace_hashes.insert(skill_hash);
    }

    let bundles = load_skill_bundles(client).await?;
    let bundle_map = bundles
        .iter()
        .cloned()
        .map(|bundle| (bundle.record.skill_hash, bundle))
        .collect::<HashMap<_, _>>();

    if trace_hashes.is_empty() {
        for bundle in lexical_goal_matches(&bundles, &agent_state.goal)
            .into_iter()
            .take(4)
        {
            trace_hashes.insert(bundle.record.skill_hash);
        }
    }

    let mut active_bundles = trace_hashes
        .iter()
        .filter_map(|skill_hash| bundle_map.get(skill_hash).cloned())
        .collect::<Vec<_>>();
    active_bundles.sort_by(|left, right| {
        left.record
            .macro_body
            .definition
            .name
            .cmp(&right.record.macro_body.definition.name)
    });

    let mut skills = active_bundles
        .iter()
        .map(active_skill_item)
        .collect::<Vec<_>>();
    skills.sort_by(|left, right| left.title.cmp(&right.title));
    let tools = active_tool_items(&active_bundles);
    let evidence = active_evidence_items(&active_bundles);
    let constraints = active_constraints(&agent_state);
    let neighborhood = build_context_neighborhood(
        &normalized_session_id,
        &agent_state,
        &active_bundles,
        &constraints,
    );

    let recent_actions = agent_state
        .recent_actions
        .iter()
        .rev()
        .take(8)
        .cloned()
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<Vec<_>>();

    let substrate = load_thread_events_for_session(state, &normalized_session_id)
        .ok()
        .map(|events| build_substrate_receipts(&events))
        .filter(|receipts| !receipts.is_empty())
        .map(|receipts| {
            let index_roots = receipts
                .iter()
                .map(|receipt| receipt.index_root.clone())
                .filter(|value| !value.is_empty())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>();
            SubstrateProofView {
                session_id: Some(normalized_session_id.clone()),
                skill_hash: agent_state.active_skill_hash.map(|hash| hex::encode(hash)),
                summary: format!(
                    "{} substrate receipts attached to this session.",
                    receipts.len()
                ),
                index_roots,
                neighborhood: build_substrate_neighborhood(&receipts, Some(&normalized_session_id)),
                receipts,
            }
        });

    Ok(ActiveContextSnapshot {
        session_id: normalized_session_id.clone(),
        goal: agent_state.goal,
        status: format!("{:?}", agent_state.status),
        mode: format!("{:?}", agent_state.mode),
        current_tier: format!("{:?}", agent_state.current_tier),
        focus_id: session_focus_id(&normalized_session_id),
        active_skill_id: agent_state.active_skill_hash.as_ref().map(skill_focus_id),
        skills,
        tools,
        evidence,
        constraints,
        recent_actions,
        neighborhood,
        substrate,
    })
}

async fn load_skill_catalog_entries(
    client: &mut PublicApiClient<Channel>,
) -> Result<Vec<SkillCatalogEntry>, String> {
    let mut entries = load_skill_bundles(client)
        .await?
        .into_iter()
        .map(|bundle| skill_catalog_entry_from_bundle(&bundle))
        .collect::<Vec<_>>();

    entries.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(entries)
}

#[tauri::command]
pub async fn get_active_context(
    state: State<'_, Mutex<AppState>>,
    session_id: String,
) -> Result<ActiveContextSnapshot, String> {
    let mut client = get_rpc_client(&state).await?;
    load_active_context_snapshot(&state, &mut client, &session_id).await
}

#[tauri::command]
pub async fn get_skill_detail(
    state: State<'_, Mutex<AppState>>,
    skill_hash: String,
) -> Result<SkillDetailView, String> {
    let mut client = get_rpc_client(&state).await?;
    let skill_hash = parse_hex_32(&skill_hash)?;
    let bundles = load_skill_bundles(&mut client).await?;
    let Some(bundle) = bundles
        .iter()
        .find(|bundle| bundle.record.skill_hash == skill_hash)
    else {
        return Err(format!("Skill {} was not found", hex::encode(skill_hash)));
    };
    let mut detail = build_skill_detail(bundle, &bundles);
    if let Some(memory_runtime) = app_memory_runtime(&state) {
        let sources = crate::orchestrator::load_skill_sources(&memory_runtime);
        if let Some((source, discovered)) = match_skill_source_for_bundle(bundle, &sources) {
            detail.source_registry_id = Some(source.source_id.clone());
            detail.source_registry_label = Some(source.label.clone());
            detail.source_registry_uri = Some(source.uri.clone());
            detail.source_registry_kind = Some(source.kind.clone());
            detail.source_registry_sync_status = Some(source.sync_status.clone());
            detail.source_registry_relative_path = Some(discovered.relative_path.clone());
        }
    }
    Ok(detail)
}

#[tauri::command]
pub async fn get_substrate_proof(
    state: State<'_, Mutex<AppState>>,
    session_id: Option<String>,
    skill_hash: Option<String>,
) -> Result<SubstrateProofView, String> {
    let mut client = get_rpc_client(&state).await?;
    let bundles = load_skill_bundles(&mut client).await?;

    let resolved_session_id = if let Some(session_id) = session_id {
        Some(normalize_hex_id(&session_id))
    } else if let Some(skill_hash) = skill_hash.as_deref() {
        let parsed_skill_hash = parse_hex_32(skill_hash)?;
        bundles
            .iter()
            .find(|bundle| bundle.record.skill_hash == parsed_skill_hash)
            .and_then(|bundle| bundle.record.source_session_id.map(hex::encode))
    } else {
        None
    };

    let Some(session_id) = resolved_session_id else {
        return Ok(SubstrateProofView {
            session_id: None,
            skill_hash,
            summary: "No session was provided for substrate proof lookup.".to_string(),
            index_roots: Vec::new(),
            receipts: Vec::new(),
            neighborhood: AtlasNeighborhood {
                lens: "substrate".to_string(),
                title: "Substrate".to_string(),
                summary: "No session was provided for substrate proof lookup.".to_string(),
                focus_id: None,
                nodes: Vec::new(),
                edges: Vec::new(),
            },
        });
    };

    let events = load_thread_events_for_session(&state, &session_id)?;
    let receipts = build_substrate_receipts(&events);
    let index_roots = receipts
        .iter()
        .map(|receipt| receipt.index_root.clone())
        .filter(|root| !root.is_empty())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let neighborhood = build_substrate_neighborhood(&receipts, Some(&session_id));

    Ok(SubstrateProofView {
        session_id: Some(session_id),
        skill_hash,
        summary: if receipts.is_empty() {
            "No substrate retrieval receipts captured for this scope.".to_string()
        } else {
            format!("{} substrate retrieval receipts captured.", receipts.len())
        },
        index_roots,
        receipts,
        neighborhood,
    })
}

#[tauri::command]
pub async fn get_atlas_neighborhood(
    state: State<'_, Mutex<AppState>>,
    session_id: Option<String>,
    focus_id: Option<String>,
    lens: Option<String>,
) -> Result<AtlasNeighborhood, String> {
    let resolved_lens = lens
        .unwrap_or_else(|| "skills".to_string())
        .trim()
        .to_ascii_lowercase();

    match resolved_lens.as_str() {
        "context" => {
            let target_session_id = session_id
                .or_else(|| focus_id.as_deref().and_then(parse_focus_session_id))
                .ok_or_else(|| "A session id is required for the context lens".to_string())?;
            let mut client = get_rpc_client(&state).await?;
            Ok(
                load_active_context_snapshot(&state, &mut client, &target_session_id)
                    .await?
                    .neighborhood,
            )
        }
        "substrate" => {
            let proof = get_substrate_proof(
                state,
                session_id,
                focus_id.and_then(|value| parse_focus_skill_hash(&value).map(hex::encode)),
            )
            .await?;
            Ok(proof.neighborhood)
        }
        _ => {
            let mut client = get_rpc_client(&state).await?;
            let bundles = load_skill_bundles(&mut client).await?;
            let focus_hash = focus_id
                .as_deref()
                .and_then(parse_focus_skill_hash)
                .or_else(|| bundles.first().map(|bundle| bundle.record.skill_hash))
                .ok_or_else(|| "No skills are available in the atlas".to_string())?;
            Ok(build_skill_neighborhood(&bundles, &focus_hash))
        }
    }
}

#[tauri::command]
pub async fn search_atlas(
    state: State<'_, Mutex<AppState>>,
    query: String,
    lens: Option<String>,
) -> Result<Vec<AtlasSearchResult>, String> {
    let normalized_query = query.trim().to_ascii_lowercase();
    if normalized_query.is_empty() {
        return Ok(Vec::new());
    }

    let resolved_lens = lens
        .unwrap_or_else(|| "skills".to_string())
        .trim()
        .to_ascii_lowercase();
    let mut client = get_rpc_client(&state).await?;
    let bundles = load_skill_bundles(&mut client).await?;

    let query_tokens = normalized_query
        .split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_')
        .filter(|token| !token.is_empty())
        .collect::<Vec<_>>();

    let score_text = |text: &str| -> f32 {
        let lower = text.to_ascii_lowercase();
        let mut score = if lower.contains(&normalized_query) {
            1.5
        } else {
            0.0
        };
        for token in &query_tokens {
            if lower.contains(token) {
                score += 0.35;
            }
        }
        score
    };

    let mut results = Vec::new();
    for bundle in bundles {
        if resolved_lens == "context" {
            continue;
        }

        let skill_score = score_text(&bundle.record.macro_body.definition.name)
            + score_text(&bundle.record.macro_body.definition.description)
            + used_tools_for_record(&bundle.record)
                .iter()
                .map(|tool_name| score_text(tool_name))
                .sum::<f32>();
        if skill_score > 0.0 {
            results.push(AtlasSearchResult {
                id: skill_focus_id(&bundle.record.skill_hash),
                kind: "skill".to_string(),
                title: bundle.record.macro_body.definition.name.clone(),
                summary: bundle.record.macro_body.definition.description.clone(),
                score: skill_score,
                lens: "skills".to_string(),
            });
        }

        if resolved_lens != "skills" {
            if let Some(doc) = bundle.published_doc.as_ref() {
                let doc_score = score_text(&doc.name) + score_text(&doc.markdown);
                if doc_score > 0.0 {
                    results.push(AtlasSearchResult {
                        id: doc_focus_id(&bundle.record.skill_hash),
                        kind: "published_doc".to_string(),
                        title: doc.name.clone(),
                        summary: summary_text(&doc.markdown, 180),
                        score: doc_score,
                        lens: "skills".to_string(),
                    });
                }
            }
            if let (Some(evidence_hash), Some(evidence)) =
                (bundle.record.source_evidence_hash, bundle.evidence.as_ref())
            {
                let mut evidence_score = score_text(&evidence.normalized_procedure);
                if let Some(title) = evidence.title.as_ref() {
                    evidence_score += score_text(title);
                }
                if let Some(source_uri) = evidence.source_uri.as_ref() {
                    evidence_score += score_text(source_uri);
                }
                if evidence_score > 0.0 {
                    results.push(AtlasSearchResult {
                        id: evidence_focus_id(&evidence_hash),
                        kind: "evidence".to_string(),
                        title: evidence
                            .title
                            .clone()
                            .or_else(|| evidence.source_uri.clone())
                            .unwrap_or_else(|| "External evidence".to_string()),
                        summary: summary_text(&evidence.normalized_procedure, 180),
                        score: evidence_score,
                        lens: "skills".to_string(),
                    });
                }
            }
        }
    }

    results.sort_by(|left, right| {
        right
            .score
            .partial_cmp(&left.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| left.title.cmp(&right.title))
    });
    results.truncate(24);
    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use serde_json::json;
    use std::{fs, sync::Arc};
    use uuid::Uuid;

    fn parent_playbook_event(
        event_id: &str,
        timestamp_ms: u64,
        playbook: &crate::models::LocalEngineAgentPlaybookRecord,
        phase: &str,
        status: &str,
        success: bool,
        step: Option<&crate::models::LocalEngineAgentPlaybookStepRecord>,
        child_session_id: Option<&str>,
        summary: &str,
        artifact_ids: &[&str],
        error_class: Option<&str>,
    ) -> crate::models::AgentEvent {
        crate::models::AgentEvent {
            event_id: event_id.to_string(),
            timestamp: chrono::Utc
                .timestamp_millis_opt(timestamp_ms as i64)
                .single()
                .expect("timestamp should be valid")
                .to_rfc3339(),
            thread_id: "session-parent".to_string(),
            step_index: 1,
            event_type: crate::models::EventType::Receipt,
            title: format!("{} {}", phase, playbook.label.as_str()),
            digest: json!({
                "kind": "parent_playbook",
                "tool_name": if phase == "step_spawned" { "agent__delegate" } else { "agent__await_result" },
                "phase": phase,
                "playbook_id": playbook.playbook_id.clone(),
                "playbook_label": playbook.label.clone(),
                "status": status,
                "success": success,
                "error_class": error_class,
            }),
            details: json!({
                "timestamp_ms": timestamp_ms,
                "parent_session_id": "session-parent",
                "step_id": step.map(|entry| entry.step_id.clone()),
                "step_label": step.map(|entry| entry.label.clone()),
                "child_session_id": child_session_id,
                "template_id": step.map(|entry| entry.worker_template_id.clone()),
                "workflow_id": step.map(|entry| entry.worker_workflow_id.clone()),
                "summary": summary,
            }),
            artifact_refs: artifact_ids
                .iter()
                .map(|artifact_id| crate::models::ArtifactRef {
                    artifact_id: (*artifact_id).to_string(),
                    artifact_type: crate::models::ArtifactType::Report,
                })
                .collect(),
            receipt_ref: Some(format!("receipt::{}", event_id)),
            input_refs: Vec::new(),
            status: if success {
                crate::models::EventStatus::Success
            } else {
                crate::models::EventStatus::Failure
            },
            duration_ms: None,
        }
    }

    #[test]
    fn default_worker_templates_expose_researcher_contract() {
        let templates = default_worker_templates();
        assert_eq!(templates.len(), 3);
        let researcher = templates
            .iter()
            .find(|template| template.template_id == "researcher")
            .expect("researcher template should exist");
        assert_eq!(researcher.template_id, "researcher");
        assert_eq!(researcher.role, "Research Worker");
        assert_eq!(
            researcher.completion_contract.merge_mode,
            "append_summary_to_parent"
        );
        assert!(templates
            .iter()
            .any(|template| template.template_id == "verifier"));
        assert!(templates
            .iter()
            .any(|template| template.template_id == "coder"));
        assert!(researcher
            .allowed_tools
            .iter()
            .any(|tool| tool == "web__search"));
        assert!(researcher
            .completion_contract
            .expected_output
            .contains("research brief"));
        assert!(researcher
            .workflows
            .iter()
            .any(|workflow| workflow.workflow_id == "live_research_brief"));
        let verifier = templates
            .iter()
            .find(|template| template.template_id == "verifier")
            .expect("verifier template should exist");
        let verifier_workflow = verifier
            .workflows
            .iter()
            .find(|workflow| workflow.workflow_id == "postcondition_audit")
            .expect("verifier workflow should exist");
        assert_eq!(verifier_workflow.default_budget, Some(48));
        assert_eq!(verifier_workflow.max_retries, Some(0));
        assert!(verifier_workflow
            .allowed_tools
            .iter()
            .any(|tool| tool == "model__rerank"));
        let coder = templates
            .iter()
            .find(|template| template.template_id == "coder")
            .expect("coder template should exist");
        let coder_workflow = coder
            .workflows
            .iter()
            .find(|workflow| workflow.workflow_id == "patch_build_verify")
            .expect("coder workflow should exist");
        assert_eq!(coder_workflow.default_budget, Some(96));
        assert_eq!(coder_workflow.max_retries, Some(1));
        assert!(coder_workflow
            .allowed_tools
            .iter()
            .any(|tool| tool == "filesystem__patch"));
        assert!(coder_workflow
            .allowed_tools
            .iter()
            .any(|tool| tool == "sys__exec_session"));
        assert!(coder_workflow
            .allowed_tools
            .iter()
            .any(|tool| tool == "agent__complete"));
    }

    #[test]
    fn load_or_initialize_worker_templates_persists_defaults() {
        let data_dir = std::env::temp_dir().join(format!(
            "autopilot-worker-template-tests-{}",
            Uuid::new_v4()
        ));

        let result = (|| -> Result<(), String> {
            let runtime = Arc::new(crate::open_or_create_memory_runtime(&data_dir)?);
            let templates = load_or_initialize_worker_templates(&runtime);
            assert_eq!(templates.len(), 3);
            assert!(templates
                .iter()
                .any(|template| template.template_id == "researcher"));

            let persisted = orchestrator::load_worker_templates(&runtime);
            assert_eq!(persisted.len(), 3);
            assert!(persisted
                .iter()
                .any(|template| template.template_id == "researcher"));
            assert_eq!(
                persisted
                    .iter()
                    .find(|template| template.template_id == "researcher")
                    .expect("persisted researcher template should exist")
                    .completion_contract
                    .merge_mode,
                "append_summary_to_parent"
            );
            Ok(())
        })();

        let _ = fs::remove_dir_all(&data_dir);
        result.unwrap();
    }

    #[test]
    fn default_agent_playbooks_expose_evidence_audited_patch_contract() {
        let playbooks = default_agent_playbooks();
        assert_eq!(playbooks.len(), 1);
        let playbook = playbooks
            .iter()
            .find(|entry| entry.playbook_id == "evidence_audited_patch")
            .expect("evidence-audited patch playbook should exist");
        assert_eq!(playbook.default_budget, 196);
        assert_eq!(
            playbook.completion_contract.merge_mode,
            "append_summary_to_parent"
        );
        assert!(playbook
            .trigger_intents
            .iter()
            .any(|intent| intent == "workspace.ops"));
        assert_eq!(playbook.steps.len(), 3);
        assert_eq!(playbook.steps[0].worker_template_id, "researcher");
        assert_eq!(playbook.steps[1].worker_workflow_id, "patch_build_verify");
        assert_eq!(playbook.steps[2].worker_workflow_id, "postcondition_audit");
    }

    #[test]
    fn parent_playbook_projection_tracks_live_step_status_and_receipts() {
        let playbook = default_agent_playbooks()
            .into_iter()
            .find(|entry| entry.playbook_id == "evidence_audited_patch")
            .expect("expected evidence_audited_patch playbook");
        let playbook_specs = std::iter::once((playbook.playbook_id.clone(), playbook.clone()))
            .collect::<BTreeMap<_, _>>();
        let research_step = playbook
            .steps
            .first()
            .expect("research step should exist")
            .clone();
        let coder_step = playbook
            .steps
            .get(1)
            .expect("coder step should exist")
            .clone();

        let events = vec![
            parent_playbook_event(
                "receipt-1",
                1_000,
                &playbook,
                "started",
                "running",
                true,
                None,
                None,
                "Started evidence-audited patch run.",
                &[],
                None,
            ),
            parent_playbook_event(
                "receipt-2",
                1_100,
                &playbook,
                "step_spawned",
                "running",
                true,
                Some(&research_step),
                Some("child-research"),
                "Spawned research step.",
                &[],
                None,
            ),
            parent_playbook_event(
                "receipt-3",
                1_250,
                &playbook,
                "step_completed",
                "running",
                true,
                Some(&research_step),
                Some("child-research"),
                "Research brief merged into parent context.",
                &["artifact-research"],
                None,
            ),
            parent_playbook_event(
                "receipt-4",
                1_400,
                &playbook,
                "step_spawned",
                "running",
                true,
                Some(&coder_step),
                Some("child-coder"),
                "Spawned coder step.",
                &[],
                None,
            ),
        ];

        let mut runs = BTreeMap::new();
        ingest_parent_playbook_events("session-parent", &events, &playbook_specs, &mut runs);

        let projected = runs
            .remove("session-parent:evidence_audited_patch")
            .expect("projection should exist");
        assert_eq!(projected.status, "running");
        assert_eq!(projected.latest_phase, "step_spawned");
        assert_eq!(
            projected.current_step_id.as_deref(),
            Some(coder_step.step_id.as_str())
        );
        assert_eq!(
            projected.active_child_session_id.as_deref(),
            Some("child-coder")
        );
        assert_eq!(projected.steps.len(), 3);

        let projected_research = projected
            .steps
            .iter()
            .find(|step| step.step_id == research_step.step_id)
            .expect("projected research step should exist");
        assert_eq!(projected_research.status, "completed");
        assert_eq!(projected_research.receipts.len(), 2);
        assert_eq!(
            projected_research
                .receipts
                .last()
                .expect("latest research receipt should exist")
                .artifact_ids,
            vec!["artifact-research".to_string()]
        );

        let projected_coder = projected
            .steps
            .iter()
            .find(|step| step.step_id == coder_step.step_id)
            .expect("projected coder step should exist");
        assert_eq!(projected_coder.status, "running");
        assert_eq!(
            projected_coder.child_session_id.as_deref(),
            Some("child-coder")
        );
    }

    #[test]
    fn visible_parent_playbook_runs_hide_and_restore_dismissed_runs() {
        let data_dir = std::env::temp_dir().join(format!(
            "autopilot-parent-playbook-dismissal-tests-{}",
            Uuid::new_v4()
        ));

        let result = (|| -> Result<(), String> {
            let runtime = Arc::new(crate::open_or_create_memory_runtime(&data_dir)?);
            let playbook = default_agent_playbooks()
                .into_iter()
                .find(|entry| entry.playbook_id == "evidence_audited_patch")
                .expect("expected evidence_audited_patch playbook");
            let sessions = vec![crate::models::SessionSummary {
                session_id: "session-parent".to_string(),
                title: "Parent playbook session".to_string(),
                timestamp: 1_000,
            }];
            orchestrator::save_local_session_summary(&runtime, sessions[0].clone());
            orchestrator::append_event(
                &runtime,
                &parent_playbook_event(
                    "receipt-started",
                    1_000,
                    &playbook,
                    "started",
                    "running",
                    true,
                    None,
                    None,
                    "Started evidence-audited patch run.",
                    &[],
                    None,
                ),
            );

            let playbooks = vec![playbook];
            let visible_before = visible_parent_playbook_runs(&runtime, &sessions, &playbooks);
            assert_eq!(visible_before.len(), 1);

            persist_parent_playbook_dismissal(
                &runtime,
                "session-parent:evidence_audited_patch",
                true,
            );
            let visible_after_dismiss =
                visible_parent_playbook_runs(&runtime, &sessions, &playbooks);
            assert!(visible_after_dismiss.is_empty());

            persist_parent_playbook_dismissal(
                &runtime,
                "session-parent:evidence_audited_patch",
                false,
            );
            let visible_after_restore =
                visible_parent_playbook_runs(&runtime, &sessions, &playbooks);
            assert_eq!(visible_after_restore.len(), 1);
            Ok(())
        })();

        let _ = fs::remove_dir_all(&data_dir);
        result.unwrap();
    }

    #[test]
    fn parent_playbook_projection_reopens_step_on_operator_resume_request() {
        let playbook = default_agent_playbooks()
            .into_iter()
            .find(|entry| entry.playbook_id == "evidence_audited_patch")
            .expect("expected evidence_audited_patch playbook");
        let playbook_specs = std::iter::once((playbook.playbook_id.clone(), playbook.clone()))
            .collect::<BTreeMap<_, _>>();
        let coder_step = playbook
            .steps
            .get(1)
            .expect("coder step should exist")
            .clone();

        let events = vec![
            parent_playbook_event(
                "receipt-1",
                1_000,
                &playbook,
                "step_spawned",
                "running",
                true,
                Some(&coder_step),
                Some("child-coder"),
                "Spawned coder step.",
                &[],
                None,
            ),
            parent_playbook_event(
                "receipt-2",
                1_150,
                &playbook,
                "blocked",
                "blocked",
                false,
                Some(&coder_step),
                Some("child-coder"),
                "Coder step stalled on validation.",
                &[],
                Some("compile_error"),
            ),
            parent_playbook_event(
                "receipt-3",
                1_250,
                &playbook,
                "operator_resume_requested",
                "running",
                true,
                Some(&coder_step),
                Some("child-coder"),
                "Operator requested resume from the coder step.",
                &[],
                None,
            ),
        ];

        let mut runs = BTreeMap::new();
        ingest_parent_playbook_events("session-parent", &events, &playbook_specs, &mut runs);

        let projected = runs
            .remove("session-parent:evidence_audited_patch")
            .expect("projection should exist");
        let projected_coder = projected
            .steps
            .iter()
            .find(|step| step.step_id == coder_step.step_id)
            .expect("projected coder step should exist");

        assert_eq!(projected.status, "running");
        assert_eq!(projected.latest_phase, "operator_resume_requested");
        assert_eq!(
            projected.current_step_id.as_deref(),
            Some(coder_step.step_id.as_str())
        );
        assert_eq!(
            projected.active_child_session_id.as_deref(),
            Some("child-coder")
        );
        assert_eq!(projected_coder.status, "running");
        assert_eq!(projected_coder.error_class, None);
        assert_eq!(projected_coder.receipts.len(), 3);
    }
}
