use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tauri::{
    menu::{Menu, MenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    AppHandle, Manager, State,
};
use tauri_plugin_global_shortcut::{Code, GlobalShortcutExt, Modifiers, Shortcut, ShortcutState};

mod execution;
mod identity;
mod ingestion;
mod kernel;
mod models;
mod orchestrator;
mod project;
mod template;
mod windows;

use ioi_api::vm::inference::{HttpInferenceRuntime, InferenceRuntime};
use ioi_scs::{SovereignContextStore, StoreConfig};
use ioi_types::app::{account_id_from_key_material, SignatureSuite};
use models::AppState;

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

fn derive_studio_scs_config(data_dir: &Path) -> StoreConfig {
    let mut config = StoreConfig {
        chain_id: 0,
        owner_id: [0u8; 32],
        identity_key: [0u8; 32],
    };

    let key_path = data_dir.join("identity.key");
    if !key_path.exists() {
        return config;
    }

    let keypair = match identity::load_identity_keypair_from_file(&key_path) {
        Ok(kp) => kp,
        Err(e) => {
            eprintln!(
                "[Autopilot] Failed to load identity key for SCS config (fallback active): {}",
                e
            );
            return config;
        }
    };

    if let Ok(ed_kp) = keypair.clone().try_into_ed25519() {
        config.identity_key.copy_from_slice(ed_kp.secret().as_ref());
    }

    if let Ok(owner_id) =
        account_id_from_key_material(SignatureSuite::ED25519, &keypair.public().encode_protobuf())
    {
        config.owner_id = owner_id;
    }

    config
}

pub(crate) fn autopilot_data_dir_for(app: &AppHandle) -> PathBuf {
    app.path()
        .app_data_dir()
        .unwrap_or_else(|_| PathBuf::from("./ioi-data"))
}

pub(crate) fn open_or_create_studio_scs(data_dir: &Path) -> Result<SovereignContextStore, String> {
    let scs_path = data_dir.join("studio.scs");
    let scs_config = derive_studio_scs_config(data_dir);

    if scs_path.exists() {
        SovereignContextStore::open_with_config(&scs_path, scs_config.clone())
            .map_err(|error| format!("Failed to open studio store: {}", error))
    } else {
        std::fs::create_dir_all(data_dir)
            .map_err(|error| format!("Failed to create app data directory: {}", error))?;
        SovereignContextStore::create(&scs_path, scs_config)
            .map_err(|error| format!("Failed to create studio store: {}", error))
    }
}

fn create_inference_runtime() -> Arc<dyn InferenceRuntime> {
    let openai_key = std::env::var("OPENAI_API_KEY").ok();
    let local_url = std::env::var("LOCAL_LLM_URL").ok();

    if let Some(key) = openai_key {
        let model = std::env::var("OPENAI_MODEL").unwrap_or_else(|_| "gpt-4o".to_string());
        let api_url = "https://api.openai.com/v1/chat/completions".to_string();
        Arc::new(HttpInferenceRuntime::new(api_url, key, model))
    } else if let Some(url) = local_url {
        Arc::new(HttpInferenceRuntime::new(
            url,
            "".to_string(),
            "llama3".to_string(),
        ))
    } else {
        Arc::new(ioi_api::vm::inference::mock::MockInferenceRuntime)
    }
}

#[cfg(target_os = "macos")]
const SPOTLIGHT_SHORTCUT_LABEL: &str = "Open Autopilot (Cmd+Space)";
#[cfg(not(target_os = "macos"))]
const SPOTLIGHT_SHORTCUT_LABEL: &str = "Open Autopilot (Ctrl+Space)";

#[cfg(target_os = "macos")]
fn spotlight_shortcut() -> Shortcut {
    Shortcut::new(Some(Modifiers::SUPER), Code::Space)
}

#[cfg(not(target_os = "macos"))]
fn spotlight_shortcut() -> Shortcut {
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
        .setup(|app| {
            println!("[Autopilot] Initializing...");

            #[cfg(target_os = "linux")]
            {
                kernel::cosmic::ensure_cosmic_window_rules();
            }

            let app_handle = app.handle();
            let data_dir = autopilot_data_dir_for(&app_handle);

            let studio_scs = open_or_create_studio_scs(&data_dir).ok();

            if let Some(scs) = studio_scs {
                let state: State<Mutex<AppState>> = app_handle.state();
                let mut s = state.lock().expect("Failed to lock app state during init");
                s.studio_scs = Some(Arc::new(Mutex::new(scs)));
            } else {
                eprintln!("[Studio] Failed to initialize SCS. Persistence disabled.");
            }

            let google_automation_manager = kernel::connectors::GoogleAutomationManager::new(
                app.handle().clone(),
                kernel::connectors::registry_path_for(&data_dir),
            );
            std::env::set_var(
                "IOI_SHIELD_POLICY_PATH",
                kernel::connectors::policy_state_path_for(&data_dir),
            );
            let _ = app.manage(google_automation_manager.clone());
            let _ = app.manage(kernel::connectors::ShieldPolicyManager::new(
                kernel::connectors::policy_state_path_for(&data_dir),
            ));
            let wallet_auth_handle = app.handle().clone();
            let wallet_policy_handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                if let Err(error) = google_automation_manager.bootstrap().await {
                    eprintln!(
                        "[Autopilot] Failed to bootstrap Google automation manager: {}",
                        error
                    );
                }
            });
            tauri::async_runtime::spawn(async move {
                let state: State<Mutex<AppState>> = wallet_auth_handle.state();
                if let Err(error) = kernel::connectors::bootstrap_google_wallet_auth(&state).await {
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
                    kernel::connectors::bootstrap_wallet_policy_state(&state, &policy_manager).await
                {
                    eprintln!(
                        "[Autopilot] Failed to bootstrap wallet-backed Shield policy state: {}",
                        error
                    );
                }
            });
            kernel::notifications::bootstrap_notification_defaults(&app.handle());
            let notification_handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                kernel::notifications::spawn_notification_scheduler(notification_handle).await;
            });

            let inference_runtime = create_inference_runtime();
            {
                let state: State<Mutex<AppState>> = app_handle.state();
                let mut s = state.lock().expect("Failed to lock app state");
                s.inference_runtime = Some(inference_runtime);
            }

            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                execution::init_mcp_servers(handle).await;
            });

            let show_spotlight_item = MenuItem::with_id(
                app,
                "spotlight",
                SPOTLIGHT_SHORTCUT_LABEL,
                true,
                None::<&str>,
            )?;
            let show_studio_item =
                MenuItem::with_id(app, "studio", "Open Studio", true, None::<&str>)?;
            let quit_item = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
            let menu =
                Menu::with_items(app, &[&show_spotlight_item, &show_studio_item, &quit_item])?;

            if let Some(icon) = app.default_window_icon().cloned() {
                let _ = TrayIconBuilder::new()
                    .menu(&menu)
                    .icon(icon)
                    .icon_as_template(true)
                    .on_menu_event(|app, event| match event.id.as_ref() {
                        "spotlight" => windows::show_spotlight(app.clone()),
                        "studio" => windows::show_studio(app.clone()),
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
                            windows::show_spotlight(tray.app_handle().clone());
                        }
                    })
                    .build(app);
            }

            let shortcut = spotlight_shortcut();
            let app_handle = app.handle().clone();
            let _ = app
                .global_shortcut()
                .on_shortcut(shortcut, move |_app, _shortcut, event| {
                    if event.state == ShortcutState::Pressed {
                        if let Some(window) = app_handle.get_webview_window("studio") {
                            if window.is_visible().unwrap_or(false) {
                                windows::hide_spotlight(app_handle.clone());
                            } else {
                                windows::show_spotlight(app_handle.clone());
                            }
                        }
                    }
                });

            #[cfg(not(target_os = "macos"))]
            {
                let handle = app.handle().clone();
                tauri::async_runtime::spawn(async move {
                    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
                    if let Some(window) = handle.get_webview_window("studio") {
                        if let Ok(visible) = window.is_visible() {
                            if !visible {
                                windows::show_spotlight(handle);
                            }
                        }
                    }
                });
            }

            let monitor_handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                kernel::monitor_kernel_events(monitor_handle).await;
            });

            println!("[Autopilot] Setup complete.");
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            windows::show_spotlight,
            windows::hide_spotlight,
            windows::toggle_spotlight_sidebar,
            windows::toggle_spotlight_artifact_panel,
            windows::get_spotlight_layout,
            windows::show_gate,
            windows::hide_gate,
            windows::show_studio,
            windows::hide_studio,
            kernel::task::start_task,
            kernel::task::continue_task,
            kernel::task::update_task,
            kernel::task::complete_task,
            kernel::task::dismiss_task,
            kernel::task::get_current_task,
            kernel::governance::gate_respond,
            kernel::governance::get_gate_response,
            kernel::governance::clear_gate_response,
            kernel::governance::submit_runtime_password,
            kernel::connectors::wallet_mail_configure_account,
            kernel::connectors::wallet_mail_read_latest,
            kernel::connectors::wallet_mail_list_recent,
            kernel::connectors::wallet_mail_delete_spam,
            kernel::connectors::wallet_mail_reply,
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
            kernel::data::get_skill_catalog,
            kernel::data::get_active_context,
            kernel::data::get_atlas_neighborhood,
            kernel::data::get_skill_detail,
            kernel::data::get_substrate_proof,
            kernel::data::search_atlas,
            kernel::artifacts::get_thread_events,
            kernel::artifacts::get_thread_artifacts,
            kernel::artifacts::get_artifact_content,
            kernel::artifacts::get_run_bundle,
            kernel::artifacts::export_thread_bundle,
            kernel::session::get_session_history,
            kernel::session::load_session,
            kernel::session::delete_session,
            kernel::dev::reset_autopilot_data,
            kernel::graph::test_node_execution,
            kernel::graph::run_studio_graph,
            kernel::graph::check_node_cache,
            ingestion::ingest_file,
            project::save_project,
            project::load_project
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
