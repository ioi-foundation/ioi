use serde_json::json;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tauri::{
    menu::{Menu, MenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    AppHandle, Manager, Runtime, State,
};
use tauri_plugin_global_shortcut::{Code, GlobalShortcutExt, Modifiers, Shortcut, ShortcutState};

pub mod chat_proof;
mod execution;
pub mod file_context_proof;
mod identity;
mod ingestion;
mod kernel;
mod models;
mod observability;
mod orchestrator;
pub mod plugin_proof;
mod project;
pub mod repl_cli;
pub mod repl_proof;
mod template;
mod windows;
pub mod workflow_proof;
mod workspace;
mod workspace_direct_webview;
mod workspace_ide;

use ioi_api::vm::inference::{HttpInferenceRuntime, InferenceRuntime, UnavailableInferenceRuntime};
use ioi_memory::MemoryRuntime;
use ioi_services::agentic::media_runtime::KernelMediaRuntime;
use ioi_types::app::{ChatRuntimeProvenance, ChatRuntimeProvenanceKind};
use models::AppState;
use std::time::Duration;

#[cfg(target_os = "linux")]
fn init_x11_threads() {
    let result = unsafe { x11::xlib::XInitThreads() };
    if result == 0 {
        eprintln!("[Autopilot] Warning: XInitThreads failed");
    } else {
        println!("[Autopilot] X11 threading initialized");
    }
}

#[cfg(not(target_os = "linux"))]
fn init_x11_threads() {}

fn is_env_var_truthy(key: &str) -> bool {
    std::env::var(key)
        .map(|v| {
            let s = v.trim().to_lowercase();
            s == "1" || s == "true" || s == "yes" || s == "on"
        })
        .unwrap_or(false)
}

fn env_text(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn should_enable_local_gpu_profile_by_default(
    local_gpu_dev_enabled: bool,
    data_profile: Option<&str>,
    explicit_local_preset: Option<&str>,
    explicit_local_runtime_url: Option<&str>,
    detected_hardware_profile: Option<&str>,
) -> bool {
    let normalized_profile = data_profile
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if local_gpu_dev_enabled || matches!(normalized_profile, Some("desktop-localgpu")) {
        return true;
    }
    if normalized_profile.is_some()
        || explicit_local_preset
            .map(str::trim)
            .is_some_and(|value| !value.is_empty())
        || explicit_local_runtime_url
            .map(str::trim)
            .is_some_and(|value| !value.is_empty())
    {
        return false;
    }
    detected_hardware_profile
        .map(str::trim)
        .is_some_and(|value| !value.is_empty())
}

fn apply_dev_profile_defaults() {
    let local_gpu_dev_enabled = is_env_var_truthy("AUTOPILOT_LOCAL_GPU_DEV");
    let data_profile = env_text("AUTOPILOT_DATA_PROFILE");
    let explicit_local_preset = env_text("AUTOPILOT_LOCAL_DEV_PRESET");
    let explicit_local_runtime_url =
        env_text("AUTOPILOT_LOCAL_RUNTIME_URL").or_else(|| env_text("LOCAL_LLM_URL"));
    let detected_hardware_profile =
        crate::kernel::local_engine::detect_local_gpu_hardware_profile();

    if should_enable_local_gpu_profile_by_default(
        local_gpu_dev_enabled,
        data_profile.as_deref(),
        explicit_local_preset.as_deref(),
        explicit_local_runtime_url.as_deref(),
        detected_hardware_profile.as_deref(),
    ) {
        std::env::set_var("AUTOPILOT_LOCAL_GPU_DEV", "1");
        if env_text("AUTOPILOT_DATA_PROFILE").is_none() {
            std::env::set_var("AUTOPILOT_DATA_PROFILE", "desktop-localgpu");
        }
        if env_text("AUTOPILOT_RESET_DATA_ON_BOOT").is_none() {
            std::env::set_var("AUTOPILOT_RESET_DATA_ON_BOOT", "1");
        }
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;

pub(crate) fn autopilot_data_dir_for<R: Runtime>(app: &AppHandle<R>) -> PathBuf {
    if let Some(override_path) = env_text("AUTOPILOT_DATA_DIR") {
        return PathBuf::from(override_path);
    }

    let base = app
        .path()
        .app_data_dir()
        .unwrap_or_else(|_| PathBuf::from("./ioi-data"));

    if let Some(profile) = env_text("AUTOPILOT_DATA_PROFILE") {
        return base.join("profiles").join(profile);
    }

    base
}

pub(crate) fn open_or_create_memory_runtime(data_dir: &Path) -> Result<MemoryRuntime, String> {
    let memory_path = data_dir.join("chat-memory.db");
    if !data_dir.exists() {
        std::fs::create_dir_all(data_dir)
            .map_err(|error| format!("Failed to create app data directory: {}", error))?;
    }
    MemoryRuntime::open_sqlite(&memory_path)
        .map_err(|error| format!("Failed to open memory runtime: {}", error))
}

fn wrap_kernel_runtime(runtime: Arc<dyn InferenceRuntime>) -> Arc<dyn InferenceRuntime> {
    Arc::new(KernelMediaRuntime::new(runtime))
}

fn runtime_provenance_matches(left: &ChatRuntimeProvenance, right: &ChatRuntimeProvenance) -> bool {
    fn normalized_runtime_endpoint(endpoint: Option<&str>) -> Option<String> {
        let endpoint = endpoint?.trim();
        if endpoint.is_empty() {
            return None;
        }

        let (without_fragment, fragment) = endpoint.split_once('#').unwrap_or((endpoint, ""));
        let Some((base, query)) = without_fragment.split_once('?') else {
            return Some(endpoint.to_string());
        };

        let filtered_pairs = query
            .split('&')
            .filter(|pair| {
                let key = pair
                    .split_once('=')
                    .map(|(key, _)| key)
                    .unwrap_or(*pair)
                    .trim();
                !key.is_empty() && !key.eq_ignore_ascii_case("lane")
            })
            .collect::<Vec<_>>();

        let mut normalized = base.to_string();
        if !filtered_pairs.is_empty() {
            normalized.push('?');
            normalized.push_str(&filtered_pairs.join("&"));
        }
        if !fragment.is_empty() {
            normalized.push('#');
            normalized.push_str(fragment);
        }

        Some(normalized)
    }

    left.kind == right.kind
        && left.label == right.label
        && left.model == right.model
        && normalized_runtime_endpoint(left.endpoint.as_deref())
            == normalized_runtime_endpoint(right.endpoint.as_deref())
}

pub(crate) fn create_inference_runtime() -> Arc<dyn InferenceRuntime> {
    let openai_key = std::env::var("OPENAI_API_KEY").ok();
    let local_url = env_text("LOCAL_LLM_URL").or_else(|| env_text("AUTOPILOT_LOCAL_RUNTIME_URL"));
    let local_health_url = env_text("AUTOPILOT_LOCAL_RUNTIME_HEALTH_URL").or_else(|| {
        local_url
            .as_deref()
            .and_then(derive_health_url_from_runtime_url)
    });
    let local_model = env_text("AUTOPILOT_LOCAL_RUNTIME_MODEL")
        .or_else(|| env_text("OPENAI_MODEL"))
        .unwrap_or_else(|| "llama3".to_string());
    let local_gpu_dev = is_env_var_truthy("AUTOPILOT_LOCAL_GPU_DEV");

    let runtime: Arc<dyn InferenceRuntime> = if let Some(url) = local_url.clone() {
        let local_ready = local_health_url
            .as_deref()
            .map(http_endpoint_healthy)
            .unwrap_or(true);
        if local_ready {
            Arc::new(HttpInferenceRuntime::new(url, "".to_string(), local_model))
        } else if local_gpu_dev {
            println!(
                "[Chat] Local GPU dev mode is enabled, but the local runtime at {} is not healthy yet. Chat will surface inference_unavailable until the runtime becomes healthy.",
                local_health_url
                    .as_deref()
                    .unwrap_or(url.as_str())
            );
            Arc::new(UnavailableInferenceRuntime::new(format!(
                "Inference is unavailable because the configured local runtime at {} is not healthy.",
                local_health_url.as_deref().unwrap_or(url.as_str())
            )))
        } else if let Some(key) = openai_key.clone() {
            let model = std::env::var("OPENAI_MODEL").unwrap_or_else(|_| "gpt-4o".to_string());
            let api_url = "https://api.openai.com/v1/chat/completions".to_string();
            Arc::new(HttpInferenceRuntime::new(api_url, key, model))
        } else {
            Arc::new(HttpInferenceRuntime::new(url, "".to_string(), local_model))
        }
    } else if let Some(key) = openai_key {
        let model = std::env::var("OPENAI_MODEL").unwrap_or_else(|_| "gpt-4o".to_string());
        let api_url = "https://api.openai.com/v1/chat/completions".to_string();
        Arc::new(HttpInferenceRuntime::new(api_url, key, model))
    } else {
        if local_gpu_dev {
            println!(
                "[Chat] Local GPU dev mode is enabled, but no LOCAL_LLM_URL/AUTOPILOT_LOCAL_RUNTIME_URL was provided. Chat will surface inference_unavailable until a runtime is configured."
            );
        }
        Arc::new(UnavailableInferenceRuntime::new(
            "Inference is unavailable because no Chat inference runtime is configured.",
        ))
    };

    wrap_kernel_runtime(runtime)
}

pub(crate) fn create_chat_routing_inference_runtime(
    production_runtime: &Arc<dyn InferenceRuntime>,
) -> Arc<dyn InferenceRuntime> {
    let routing_url = env_text("AUTOPILOT_STUDIO_ROUTING_RUNTIME_URL");
    let routing_health_url =
        env_text("AUTOPILOT_STUDIO_ROUTING_RUNTIME_HEALTH_URL").or_else(|| {
            routing_url
                .as_deref()
                .and_then(derive_health_url_from_runtime_url)
        });
    let routing_api_key = env_text("AUTOPILOT_STUDIO_ROUTING_RUNTIME_API_KEY");
    let routing_model = env_text("AUTOPILOT_STUDIO_ROUTING_RUNTIME_MODEL");
    let routing_openai_key = env_text("AUTOPILOT_STUDIO_ROUTING_OPENAI_API_KEY");
    let local_gpu_dev = is_env_var_truthy("AUTOPILOT_LOCAL_GPU_DEV");

    let runtime: Arc<dyn InferenceRuntime> = if let Some(url) = routing_url.clone() {
        let routing_ready = routing_health_url
            .as_deref()
            .map(http_endpoint_healthy)
            .unwrap_or(true);
        if routing_ready {
            Arc::new(HttpInferenceRuntime::new(
                url.clone(),
                routing_api_key.unwrap_or_default(),
                routing_model
                    .clone()
                    .or_else(|| production_runtime.chat_runtime_provenance().model.clone())
                    .unwrap_or_else(|| "chat-router".to_string()),
            ))
        } else if local_gpu_dev {
            println!(
                "[Chat] Local GPU dev mode is enabled, but the Chat routing runtime at {} is not healthy yet. Chat routing will surface inference_unavailable until it becomes healthy.",
                routing_health_url
                    .as_deref()
                    .unwrap_or(url.as_str())
            );
            Arc::new(UnavailableInferenceRuntime::new(format!(
                "Chat routing is unavailable because the configured runtime at {} is not healthy.",
                routing_health_url.as_deref().unwrap_or(url.as_str())
            )))
        } else if let Some(key) = routing_openai_key {
            Arc::new(HttpInferenceRuntime::new(
                "https://api.openai.com/v1/chat/completions".to_string(),
                key,
                routing_model.unwrap_or_else(|| "gpt-4o-mini".to_string()),
            ))
        } else {
            Arc::new(HttpInferenceRuntime::new(
                url,
                routing_api_key.unwrap_or_default(),
                routing_model.unwrap_or_else(|| "chat-router".to_string()),
            ))
        }
    } else if let Some(key) = routing_openai_key {
        Arc::new(HttpInferenceRuntime::new(
            "https://api.openai.com/v1/chat/completions".to_string(),
            key,
            routing_model.unwrap_or_else(|| "gpt-4o-mini".to_string()),
        ))
    } else {
        return Arc::clone(production_runtime);
    };

    wrap_kernel_runtime(runtime)
}

pub(crate) fn create_acceptance_inference_runtime(
    production_runtime: &Arc<dyn InferenceRuntime>,
) -> Arc<dyn InferenceRuntime> {
    let production_provenance = production_runtime.chat_runtime_provenance();
    let acceptance_url = env_text("AUTOPILOT_ACCEPTANCE_RUNTIME_URL");
    let acceptance_health_url = env_text("AUTOPILOT_ACCEPTANCE_RUNTIME_HEALTH_URL").or_else(|| {
        acceptance_url
            .as_deref()
            .and_then(derive_health_url_from_runtime_url)
    });
    let acceptance_api_key = env_text("AUTOPILOT_ACCEPTANCE_RUNTIME_API_KEY");
    let acceptance_model = env_text("AUTOPILOT_ACCEPTANCE_RUNTIME_MODEL")
        .or_else(|| env_text("AUTOPILOT_ACCEPTANCE_OPENAI_MODEL"));
    let acceptance_openai_key =
        env_text("AUTOPILOT_ACCEPTANCE_OPENAI_API_KEY").or_else(|| env_text("OPENAI_API_KEY"));

    let runtime: Arc<dyn InferenceRuntime> = if let Some(url) = acceptance_url.clone() {
        let runtime_ready = acceptance_health_url
            .as_deref()
            .map(http_endpoint_healthy)
            .unwrap_or(true);
        if runtime_ready {
            Arc::new(HttpInferenceRuntime::new(
                url.clone(),
                acceptance_api_key.unwrap_or_default(),
                acceptance_model
                    .clone()
                    .or_else(|| production_provenance.model.clone())
                    .unwrap_or_else(|| "acceptance-validation".to_string()),
            ))
        } else {
            Arc::new(UnavailableInferenceRuntime::new(format!(
                "Acceptance validation is unavailable because the configured runtime at {} is not healthy.",
                acceptance_health_url.as_deref().unwrap_or(url.as_str())
            )))
        }
    } else if production_provenance.kind == ChatRuntimeProvenanceKind::RealLocalRuntime
        || acceptance_model.is_some()
    {
        if let Some(key) = acceptance_openai_key {
            Arc::new(HttpInferenceRuntime::new(
                "https://api.openai.com/v1/chat/completions".to_string(),
                key,
                acceptance_model
                    .or_else(|| env_text("OPENAI_MODEL"))
                    .unwrap_or_else(|| "gpt-4o".to_string()),
            ))
        } else {
            Arc::new(UnavailableInferenceRuntime::new(
                "Acceptance validation requires a distinct configured runtime. Set AUTOPILOT_ACCEPTANCE_RUNTIME_URL or AUTOPILOT_ACCEPTANCE_OPENAI_API_KEY/AUTOPILOT_ACCEPTANCE_RUNTIME_MODEL.",
            ))
        }
    } else {
        Arc::new(UnavailableInferenceRuntime::new(
            "Acceptance validation requires a distinct configured runtime. Set AUTOPILOT_ACCEPTANCE_RUNTIME_URL or AUTOPILOT_ACCEPTANCE_OPENAI_API_KEY/AUTOPILOT_ACCEPTANCE_RUNTIME_MODEL.",
        ))
    };

    let acceptance_provenance = runtime.chat_runtime_provenance();
    if acceptance_provenance.kind != ChatRuntimeProvenanceKind::InferenceUnavailable
        && runtime_provenance_matches(&acceptance_provenance, &production_provenance)
    {
        return wrap_kernel_runtime(Arc::new(UnavailableInferenceRuntime::new(
            "Acceptance validation requires runtime provenance distinct from the production artifact runtime. Configure AUTOPILOT_ACCEPTANCE_RUNTIME_URL or AUTOPILOT_ACCEPTANCE_RUNTIME_MODEL so the acceptance validation does not collapse into production.",
        )));
    }

    wrap_kernel_runtime(runtime)
}

fn derive_health_url_from_runtime_url(runtime_url: &str) -> Option<String> {
    if runtime_url.trim().is_empty() {
        return None;
    }
    if runtime_url.contains("/v1/chat/completions") {
        return Some(runtime_url.replace("/v1/chat/completions", "/v1/models"));
    }
    Some(runtime_url.to_string())
}

fn http_endpoint_healthy(url: &str) -> bool {
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_millis(600))
        .build()
        .and_then(|client| client.get(url).send())
        .map(|response| response.status().is_success() || response.status().is_redirection())
        .unwrap_or(false)
}

fn configure_media_tool_home(data_dir: &Path) {
    let existing = std::env::var("IOI_MEDIA_TOOL_HOME")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    if existing.is_none() {
        std::env::set_var(
            "IOI_MEDIA_TOOL_HOME",
            data_dir.join("local-engine").join("media"),
        );
    }
}

fn reset_data_dir_on_boot_if_requested(data_dir: &Path) -> Result<(), String> {
    if !is_env_var_truthy("AUTOPILOT_RESET_DATA_ON_BOOT") {
        return Ok(());
    }

    if data_dir.exists() {
        std::fs::remove_dir_all(data_dir).map_err(|error| {
            format!(
                "Failed to reset Autopilot data directory '{}': {}",
                data_dir.display(),
                error
            )
        })?;
    }

    println!(
        "[Chat] Reset Autopilot data directory on boot: {}",
        data_dir.display()
    );
    Ok(())
}

#[cfg(target_os = "macos")]
const CHAT_SESSION_SHORTCUT_LABEL: &str = "Open Autopilot (Cmd+Space)";
#[cfg(not(target_os = "macos"))]
const CHAT_SESSION_SHORTCUT_LABEL: &str = "Open Autopilot (Ctrl+Space)";

#[cfg(target_os = "macos")]
fn chat_session_shortcut() -> Shortcut {
    Shortcut::new(Some(Modifiers::SUPER), Code::Space)
}

#[cfg(not(target_os = "macos"))]
fn chat_session_shortcut() -> Shortcut {
    Shortcut::new(Some(Modifiers::CONTROL), Code::Space)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    #[cfg(target_os = "linux")]
    if is_env_var_truthy("AUTOPILOT_FORCE_X11") {
        std::env::set_var("WINIT_UNIX_BACKEND", "x11");
    }

    init_x11_threads();

    #[cfg(target_os = "linux")]
    {
        let xdg_session_type = std::env::var("XDG_SESSION_TYPE").unwrap_or_default();
        let wayland_display = std::env::var("WAYLAND_DISPLAY").unwrap_or_default();
        let gdk_backend = std::env::var("GDK_BACKEND").unwrap_or_default();
        let winit_backend = std::env::var("WINIT_UNIX_BACKEND").unwrap_or_default();
        println!(
            "[Autopilot] Display env: XDG_SESSION_TYPE='{}' WAYLAND_DISPLAY='{}' GDK_BACKEND='{}' WINIT_UNIX_BACKEND='{}'",
            xdg_session_type, wayland_display, gdk_backend, winit_backend
        );
    }

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_global_shortcut::Builder::new().build())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_dialog::init())
        .manage(Mutex::new(models::AppState::default()))
        .manage(workspace_ide::WorkspaceIdeManager::default())
        .manage(workspace_direct_webview::WorkspaceDirectWebviewManager::default())
        .manage(workspace::WorkspaceTerminalManager::default())
        .setup(|app| {
            println!("[Autopilot] Initializing...");

            #[cfg(target_os = "linux")]
            {
                kernel::cosmic::ensure_cosmic_window_rules();
            }

            apply_dev_profile_defaults();
            let app_handle = app.handle();
            let data_dir = autopilot_data_dir_for(&app_handle);
            if let Err(error) = reset_data_dir_on_boot_if_requested(&data_dir) {
                eprintln!("[Chat] Failed to reset data directory on boot: {}", error);
            }
            if let Some(profile) = env_text("AUTOPILOT_DATA_PROFILE") {
                println!(
                    "[Chat] Using Autopilot data profile '{}' at {}",
                    profile,
                    data_dir.display()
                );
            }
            configure_media_tool_home(&data_dir);
            if let Err(error) = identity::ensure_identity_keypair_for_app(&app_handle) {
                eprintln!(
                    "[Chat] Failed to provision app identity for authenticated kernel sessions: {}",
                    error
                );
            }

            let memory_runtime = match open_or_create_memory_runtime(&data_dir) {
                Ok(runtime) => Some(Arc::new(runtime)),
                Err(error) => {
                    eprintln!("[Chat] Failed to initialize memory runtime: {}", error);
                    None
                }
            };

            {
                let state: State<Mutex<AppState>> = app_handle.state();
                let mut s = state.lock().expect("Failed to lock app state during init");
                s.memory_runtime = memory_runtime.clone();
            }

            if memory_runtime.is_some() {
                println!("[Chat] Initialized memory runtime.");
            } else {
                eprintln!("[Chat] Local persistence unavailable.");
            }

            if let Some(memory_runtime) = memory_runtime.as_ref() {
                if let Err(error) =
                    kernel::local_engine::bootstrap_local_engine_dev_support(memory_runtime)
                {
                    eprintln!(
                        "[Chat] Failed to bootstrap local engine dev support: {}",
                        error
                    );
                }
            }

            let google_automation_manager = kernel::connectors::GoogleAutomationManager::new(
                app.handle().clone(),
                kernel::connectors::registry_path_for(&data_dir),
            );
            let workflow_manager = kernel::workflows::WorkflowManager::new(
                app.handle().clone(),
                kernel::workflows::root_path_for(&data_dir),
            );
            std::env::set_var(
                "IOI_SHIELD_POLICY_PATH",
                kernel::connectors::policy_state_path_for(&data_dir),
            );
            std::env::set_var(
                "IOI_AUTOMATION_ROOT_PATH",
                kernel::workflows::root_path_for(&data_dir),
            );
            let _ = app.manage(google_automation_manager.clone());
            let _ = app.manage(workflow_manager.clone());
            let _ = app.manage(kernel::connectors::ShieldPolicyManager::new(
                kernel::connectors::policy_state_path_for(&data_dir),
            ));
            let _ = app.manage(kernel::plugins::PluginRuntimeManager::new(
                kernel::plugins::plugin_runtime_state_path_for(&data_dir),
            ));
            let wallet_auth_handle = app.handle().clone();
            let wallet_policy_handle = app.handle().clone();
            let workflow_handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                if let Err(error) = google_automation_manager.bootstrap().await {
                    eprintln!(
                        "[Autopilot] Failed to bootstrap Google automation manager: {}",
                        error
                    );
                }
            });
            tauri::async_runtime::spawn(async move {
                let manager: State<kernel::workflows::WorkflowManager> = workflow_handle.state();
                if let Err(error) = manager.bootstrap().await {
                    eprintln!(
                        "[Autopilot] Failed to bootstrap workflow manager: {}",
                        error
                    );
                }
            });
            if kernel::connectors::wallet_backed_bootstrap_enabled() {
                tauri::async_runtime::spawn(async move {
                    let state: State<Mutex<AppState>> = wallet_auth_handle.state();
                    if let Err(error) =
                        kernel::connectors::bootstrap_google_wallet_auth(&state).await
                    {
                        eprintln!(
                            "[Autopilot] Failed to bootstrap wallet-backed Google auth state: {}",
                            error
                        );
                    }
                });
                tauri::async_runtime::spawn(async move {
                    let state: State<Mutex<AppState>> = wallet_policy_handle.state();
                    let policy_manager: State<kernel::connectors::ShieldPolicyManager> =
                        wallet_policy_handle.state();
                    if let Err(error) =
                        kernel::connectors::bootstrap_wallet_policy_state(&state, &policy_manager)
                            .await
                    {
                        eprintln!(
                            "[Autopilot] Failed to bootstrap wallet-backed Shield policy state: {}",
                            error
                        );
                    }
                });
            } else {
                println!(
                    "[Chat] Skipping wallet-backed connector bootstrap for this local dev profile."
                );
            }
            kernel::notifications::bootstrap_notification_defaults(&app.handle());
            let notification_handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                kernel::notifications::spawn_notification_scheduler(notification_handle).await;
            });
            let local_engine_handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                kernel::local_engine::spawn_local_engine_executor(local_engine_handle).await;
            });

            let inference_runtime = create_inference_runtime();
            let chat_routing_inference_runtime =
                create_chat_routing_inference_runtime(&inference_runtime);
            let acceptance_inference_runtime =
                create_acceptance_inference_runtime(&inference_runtime);
            {
                let state: State<Mutex<AppState>> = app_handle.state();
                let mut s = state.lock().expect("Failed to lock app state");
                s.inference_runtime = Some(inference_runtime);
                s.chat_routing_inference_runtime = Some(chat_routing_inference_runtime);
                s.acceptance_inference_runtime = Some(acceptance_inference_runtime);
            }

            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                execution::init_mcp_servers(handle).await;
            });

            let show_chat_session_item = MenuItem::with_id(
                app,
                "chat-session",
                CHAT_SESSION_SHORTCUT_LABEL,
                true,
                None::<&str>,
            )?;
            let show_pill_item = MenuItem::with_id(app, "pill", "Show Pill", true, None::<&str>)?;
            let show_chat_item = MenuItem::with_id(app, "chat", "Open Chat", true, None::<&str>)?;
            let quit_item = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
            let menu = Menu::with_items(
                app,
                &[
                    &show_chat_session_item,
                    &show_pill_item,
                    &show_chat_item,
                    &quit_item,
                ],
            )?;

            if let Some(icon) = app.default_window_icon().cloned() {
                let _ = TrayIconBuilder::new()
                    .menu(&menu)
                    .icon(icon)
                    .icon_as_template(true)
                    .on_menu_event(|app, event| match event.id.as_ref() {
                        "chat-session" => windows::show_chat_session(app.clone()),
                        "pill" => windows::show_pill(app.clone()),
                        "chat" => windows::show_chat(app.clone()),
                        "quit" => std::process::exit(0),
                        _ => {}
                    })
                    .on_tray_icon_event(|tray, event| {
                        if let TrayIconEvent::Click {
                            button: MouseButton::Left,
                            button_state: MouseButtonState::Up,
                            ..
                        } = event
                        {
                            windows::show_chat_session(tray.app_handle().clone());
                        }
                    })
                    .build(app);
            }

            let shortcut = chat_session_shortcut();
            let app_handle = app.handle().clone();
            let _ = app
                .global_shortcut()
                .on_shortcut(shortcut, move |_app, _shortcut, event| {
                    if event.state == ShortcutState::Pressed {
                        if let Some(window) = app_handle.get_webview_window("chat-session") {
                            if window.is_visible().unwrap_or(false) {
                                windows::hide_chat_session(app_handle.clone());
                            } else {
                                windows::show_chat_session(app_handle.clone());
                            }
                        }
                    }
                });

            #[cfg(not(target_os = "macos"))]
            {
                let handle = app.handle().clone();
                tauri::async_runtime::spawn(async move {
                    tokio::time::sleep(std::time::Duration::from_millis(350)).await;
                    let chat_visible = handle
                        .get_webview_window("chat")
                        .and_then(|window| window.is_visible().ok())
                        .unwrap_or(false);
                    let chat_session_visible = handle
                        .get_webview_window("chat-session")
                        .and_then(|window| window.is_visible().ok())
                        .unwrap_or(false);
                    if !chat_visible && !chat_session_visible {
                        windows::show_chat(handle);
                    }
                });
            }

            #[cfg(not(target_os = "macos"))]
            {
                let handle = app.handle().clone();
                let start_surface = env_text("AUTOPILOT_DEV_START_SURFACE");
                let start_intent = env_text("AUTOPILOT_DEV_START_INTENT");
                let start_session_id = env_text("AUTOPILOT_DEV_START_SESSION_ID");
                tauri::async_runtime::spawn(async move {
                    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
                    match start_surface.as_deref() {
                        Some("chat") => {
                            if let Some(intent) = start_intent.as_deref() {
                                let _ = windows::show_chat_with_target(
                                    handle.clone(),
                                    json!({
                                        "kind": "autopilot-intent",
                                        "intent": intent,
                                        "sessionId": start_session_id.clone(),
                                    }),
                                );
                            } else {
                                windows::show_chat(handle);
                            }
                        }
                        Some("chat-session") => {
                            if let Some(window) = handle.get_webview_window("chat-session") {
                                if let Ok(visible) = window.is_visible() {
                                    if !visible {
                                        windows::show_chat_session(handle);
                                    }
                                }
                            }
                        }
                        Some("pill") => windows::show_pill(handle),
                        Some("gate") => windows::show_gate(handle),
                        _ => {
                            if let Some(intent) = start_intent.as_deref() {
                                let _ = windows::show_chat_with_target(
                                    handle.clone(),
                                    json!({
                                        "kind": "autopilot-intent",
                                        "intent": intent,
                                        "sessionId": start_session_id.clone(),
                                    }),
                                );
                            } else {
                                windows::show_chat(handle);
                            }
                        }
                    }
                });
            }

            let monitor_handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                kernel::monitor_kernel_events(monitor_handle).await;
            });
            let session_projection_monitor_handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                kernel::session::spawn_session_projection_monitor(
                    session_projection_monitor_handle,
                )
                .await;
            });

            println!("[Autopilot] Setup complete.");
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            windows::show_pill,
            windows::hide_pill,
            windows::show_chat_session,
            windows::hide_chat_session,
            windows::toggle_chat_session_sidebar,
            windows::toggle_chat_session_artifact_panel,
            windows::get_chat_session_layout,
            windows::show_gate,
            windows::hide_gate,
            windows::show_chat,
            windows::show_chat_with_target,
            windows::hide_chat,
            windows::set_pending_chat_launch,
            windows::clear_pending_chat_launch,
            windows::peek_pending_chat_launch,
            windows::ack_pending_chat_launch,
            windows::record_chat_launch_receipt,
            windows::get_chat_launch_receipts,
            workspace_ide::ensure_workspace_ide_session,
            workspace_ide::stop_workspace_ide_session,
            workspace_ide::write_workspace_ide_bridge_state,
            workspace_ide::enqueue_workspace_ide_bridge_command,
            workspace_ide::take_workspace_ide_bridge_requests,
            workspace_direct_webview::workspace_direct_webview_get_state,
            workspace_direct_webview::workspace_direct_webview_open_devtools,
            workspace_direct_webview::workspace_direct_webview_show,
            workspace_direct_webview::workspace_direct_webview_update_bounds,
            workspace_direct_webview::workspace_direct_webview_focus,
            workspace_direct_webview::workspace_direct_webview_hide,
            workspace_direct_webview::workspace_direct_webview_destroy,
            kernel::chat::chat_retry_renderer_session,
            kernel::chat::chat_attach_artifact_selection,
            kernel::chat::chat_attach_widget_state,
            kernel::chat::chat_compare_artifact_revisions,
            kernel::chat::chat_restore_artifact_revision,
            kernel::chat::chat_branch_artifact_revision,
            kernel::task::start_task,
            kernel::task::continue_task,
            kernel::task::update_task,
            kernel::task::complete_task,
            kernel::task::dismiss_task,
            kernel::task::cancel_task,
            kernel::task::get_current_task,
            kernel::governance::gate_respond,
            kernel::governance::get_gate_response,
            kernel::governance::clear_gate_response,
            kernel::governance::submit_runtime_password,
            kernel::connectors::wallet_mail_configure_account,
            kernel::connectors::wallet_mail_list_accounts,
            kernel::connectors::wallet_mail_read_latest,
            kernel::connectors::wallet_mail_list_recent,
            kernel::connectors::wallet_mail_delete_spam,
            kernel::connectors::wallet_mail_reply,
            kernel::connectors::connector_list_catalog,
            kernel::capabilities::get_capability_registry_snapshot,
            kernel::capabilities::plan_capability_governance_request,
            kernel::capabilities::plan_capability_governance_proposal,
            kernel::capabilities::get_capability_governance_request,
            kernel::capabilities::set_capability_governance_request,
            kernel::capabilities::clear_capability_governance_request,
            kernel::file_context::get_session_file_context,
            kernel::file_context::pin_session_file_context_path,
            kernel::file_context::include_session_file_context_path,
            kernel::file_context::exclude_session_file_context_path,
            kernel::file_context::remove_session_file_context_path,
            kernel::file_context::record_session_file_context_recent_path,
            kernel::file_context::clear_session_file_context,
            kernel::branches::get_session_branch_snapshot,
            kernel::branches::create_session_worktree,
            kernel::branches::switch_session_worktree,
            kernel::branches::remove_session_worktree,
            kernel::remote_env::get_session_remote_env_snapshot,
            kernel::server_mode::get_session_server_snapshot,
            kernel::voice::transcribe_voice_input,
            kernel::hooks::get_session_hook_snapshot,
            kernel::connectors::wallet_connector_auth_get,
            kernel::connectors::wallet_connector_auth_list,
            kernel::connectors::wallet_connector_auth_export,
            kernel::connectors::wallet_connector_auth_import,
            kernel::connectors::connector_list_actions,
            kernel::connectors::connector_configure,
            kernel::connectors::connector_run_action,
            kernel::connectors::connector_list_subscriptions,
            kernel::connectors::connector_stop_subscription,
            kernel::connectors::connector_resume_subscription,
            kernel::connectors::connector_renew_subscription,
            kernel::connectors::connector_get_subscription,
            kernel::connectors::connector_fetch_gmail_thread,
            kernel::connectors::connector_fetch_calendar_event,
            kernel::connectors::connector_policy_get,
            kernel::connectors::connector_policy_set,
            kernel::connectors::connector_policy_memory_get,
            kernel::connectors::connector_policy_memory_remember,
            kernel::connectors::connector_policy_memory_forget,
            kernel::connectors::connector_policy_memory_set_scope_mode,
            kernel::connectors::connector_policy_memory_set_expiry,
            kernel::notifications::notification_list_interventions,
            kernel::notifications::notification_list_assistant,
            kernel::notifications::notification_badge_count_get,
            kernel::notifications::notification_update_intervention_status,
            kernel::notifications::notification_update_assistant_status,
            kernel::notifications::assistant_attention_policy_get,
            kernel::notifications::assistant_attention_policy_set,
            kernel::notifications::assistant_attention_profile_get,
            kernel::notifications::assistant_user_profile_get,
            kernel::notifications::assistant_user_profile_set,
            kernel::notifications::assistant_attention_policy_apply_query,
            kernel::data::get_context_blob,
            kernel::data::get_available_tools,
            kernel::data::get_local_engine_snapshot,
            kernel::data::save_local_engine_control_plane,
            kernel::data::refresh_local_engine_managed_settings,
            kernel::data::clear_local_engine_managed_settings_overrides,
            kernel::data::stage_local_engine_operation,
            kernel::data::remove_local_engine_operation,
            kernel::data::promote_local_engine_operation,
            kernel::data::update_local_engine_job_status,
            kernel::data::retry_local_engine_parent_playbook_run,
            kernel::data::resume_local_engine_parent_playbook_run,
            kernel::data::dismiss_local_engine_parent_playbook_run,
            kernel::data::get_skill_catalog,
            kernel::data::get_memory_runtime_session_status,
            kernel::data::get_active_context,
            kernel::data::get_atlas_neighborhood,
            kernel::data::get_skill_detail,
            kernel::data::get_substrate_proof,
            kernel::data::search_atlas,
            kernel::knowledge::get_knowledge_collections,
            kernel::knowledge::create_knowledge_collection,
            kernel::knowledge::reset_knowledge_collection,
            kernel::knowledge::delete_knowledge_collection,
            kernel::knowledge::add_knowledge_text_entry,
            kernel::knowledge::import_knowledge_file,
            kernel::knowledge::remove_knowledge_collection_entry,
            kernel::knowledge::get_knowledge_collection_entry_content,
            kernel::knowledge::search_knowledge_collection,
            kernel::knowledge::add_knowledge_collection_source,
            kernel::knowledge::remove_knowledge_collection_source,
            kernel::workspace_workflows::list_workspace_workflows,
            kernel::skill_sources::get_skill_sources,
            kernel::skill_sources::get_extension_manifests,
            kernel::plugins::get_session_plugin_snapshot,
            kernel::plugins::trust_session_plugin,
            kernel::plugins::set_session_plugin_enabled,
            kernel::plugins::reload_session_plugin,
            kernel::plugins::refresh_session_plugin_catalog,
            kernel::plugins::revoke_session_plugin_trust,
            kernel::plugins::install_session_plugin_package,
            kernel::plugins::update_session_plugin_package,
            kernel::plugins::remove_session_plugin_package,
            kernel::skill_sources::add_skill_source,
            kernel::skill_sources::update_skill_source,
            kernel::skill_sources::remove_skill_source,
            kernel::skill_sources::set_skill_source_enabled,
            kernel::skill_sources::sync_skill_source,
            observability::get_local_benchmark_trace_feed,
            kernel::artifacts::get_thread_events,
            kernel::artifacts::get_thread_artifacts,
            kernel::artifacts::get_artifact_content,
            kernel::artifacts::save_artifact_content,
            kernel::artifacts::materialize_artifact_content_to_temp,
            kernel::artifacts::get_run_bundle,
            kernel::artifacts::get_trace_bundle,
            kernel::artifacts::compare_trace_bundles,
            kernel::artifacts::export_trace_bundle,
            kernel::artifacts::export_thread_bundle,
            kernel::artifacts::set_active_assistant_workbench_session,
            kernel::artifacts::get_active_assistant_workbench_session,
            kernel::artifacts::get_recent_assistant_workbench_activities,
            kernel::artifacts::record_assistant_workbench_activity,
            kernel::session::get_session_history,
            kernel::session::get_session_projection,
            kernel::session::get_session_rewind_snapshot,
            kernel::session::get_session_compaction_snapshot,
            kernel::session::compact_session,
            kernel::session::get_team_memory_snapshot,
            kernel::session::sync_team_memory,
            kernel::session::forget_team_memory_entry,
            kernel::session::load_session,
            kernel::session::delete_session,
            kernel::dev::reset_autopilot_data,
            kernel::graph::test_node_execution,
            kernel::graph::run_chat_graph,
            kernel::graph::check_node_cache,
            kernel::workflows::automation_create_monitor,
            kernel::workflows::workflow_install,
            kernel::workflows::workflow_list,
            kernel::workflows::workflow_get,
            kernel::workflows::workflow_pause,
            kernel::workflows::workflow_resume,
            kernel::workflows::workflow_delete,
            kernel::workflows::workflow_run_now,
            kernel::workflows::workflow_trigger_remote,
            kernel::workflows::workflow_export_project,
            ingestion::ingest_file,
            project::save_project,
            project::load_project,
            project::project_shell_inspect,
            project::project_initialize_repository,
            project::project_shell_list_directory,
            project::project_read_file,
            project::project_write_file,
            workspace::workspace_inspect,
            workspace::chat_workspace_inspect,
            workspace::workspace_list_directory,
            workspace::chat_workspace_list_directory,
            workspace::workspace_read_file,
            workspace::chat_workspace_read_file,
            workspace::workspace_lsp_snapshot,
            workspace::chat_workspace_lsp_snapshot,
            workspace::workspace_lsp_definition,
            workspace::chat_workspace_lsp_definition,
            workspace::workspace_lsp_references,
            workspace::chat_workspace_lsp_references,
            workspace::workspace_lsp_code_actions,
            workspace::chat_workspace_lsp_code_actions,
            workspace::workspace_write_file,
            workspace::chat_workspace_write_file,
            workspace::workspace_create_file,
            workspace::chat_workspace_create_file,
            workspace::workspace_create_directory,
            workspace::chat_workspace_create_directory,
            workspace::workspace_stat_path,
            workspace::chat_workspace_stat_path,
            workspace::workspace_rename_path,
            workspace::chat_workspace_rename_path,
            workspace::workspace_delete_path,
            workspace::chat_workspace_delete_path,
            workspace::workspace_search_text,
            workspace::chat_workspace_search_text,
            workspace::workspace_git_status,
            workspace::chat_workspace_git_status,
            workspace::workspace_git_diff,
            workspace::chat_workspace_git_diff,
            workspace::workspace_git_commit,
            workspace::chat_workspace_git_commit,
            workspace::workspace_git_stage,
            workspace::chat_workspace_git_stage,
            workspace::workspace_git_unstage,
            workspace::chat_workspace_git_unstage,
            workspace::workspace_git_discard,
            workspace::chat_workspace_git_discard,
            workspace::workspace_terminal_create,
            workspace::chat_workspace_terminal_create,
            workspace::workspace_terminal_read,
            workspace::chat_workspace_terminal_read,
            workspace::workspace_terminal_write,
            workspace::chat_workspace_terminal_write,
            workspace::workspace_terminal_resize,
            workspace::chat_workspace_terminal_resize,
            workspace::workspace_terminal_close,
            workspace::chat_workspace_terminal_close
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
