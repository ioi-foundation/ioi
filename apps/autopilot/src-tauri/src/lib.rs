// apps/autopilot/src-tauri/src/lib.rs
use std::sync::{Arc, Mutex};
use tauri::{
    menu::{Menu, MenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    Emitter, Manager, State
};
use tauri_plugin_global_shortcut::{Code, GlobalShortcutExt, Modifiers, Shortcut, ShortcutState};

// Declare modules
mod models;
mod windows;
mod kernel;
mod execution;
mod orchestrator; 
mod project;
mod ingestion; 

use models::AppState;

// Import types for initialization
use ioi_scs::{SovereignContextStore, StoreConfig};
use ioi_api::vm::inference::{HttpInferenceRuntime, InferenceRuntime};

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_global_shortcut::Builder::new().build())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_dialog::init())
        .manage(Mutex::new(models::AppState::default()))
        .setup(|app| {
            println!("[Autopilot] Initializing...");
            
            let app_handle = app.handle();
            let data_dir = app_handle.path().app_data_dir().unwrap_or_else(|_| std::path::PathBuf::from("./ioi-data"));
            
            // 1. Initialize Studio SCS
            let scs_path = data_dir.join("studio.scs");
            let studio_scs = if scs_path.exists() {
                println!("[Studio] Opening existing execution store at {:?}", scs_path);
                SovereignContextStore::open(&scs_path).ok()
            } else {
                std::fs::create_dir_all(&data_dir).ok();
                println!("[Studio] Creating new execution store at {:?}", scs_path);
                SovereignContextStore::create(&scs_path, StoreConfig {
                    chain_id: 0,
                    owner_id: [0u8; 32], // Local Studio User
                }).ok()
            };

            if let Some(scs) = studio_scs {
                let state: State<Mutex<AppState>> = app_handle.state();
                // We use expect here because if we can't lock state at startup, we are in trouble.
                let mut s = state.lock().expect("Failed to lock app state during init");
                s.studio_scs = Some(Arc::new(Mutex::new(scs)));
            } else {
                eprintln!("[Studio] Failed to initialize SCS. Persistence disabled.");
            }

            // 2. Initialize Local Inference Runtime for Studio
            let openai_key = std::env::var("OPENAI_API_KEY").ok();
            let local_url = std::env::var("LOCAL_LLM_URL").ok();

            let inference_runtime: Arc<dyn InferenceRuntime> = if let Some(key) = openai_key {
                let model = std::env::var("OPENAI_MODEL").unwrap_or("gpt-4o".to_string());
                let api_url = "https://api.openai.com/v1/chat/completions".to_string();
                println!("[Studio] Using OpenAI Inference: {}", model);
                Arc::new(HttpInferenceRuntime::new(api_url, key, model))
            } else if let Some(url) = local_url {
                 println!("[Studio] Using Local Inference: {}", url);
                 let model = "llama3".to_string(); 
                 Arc::new(HttpInferenceRuntime::new(url, "".to_string(), model))
            } else {
                 println!("[Studio] Using Mock Inference (Set OPENAI_API_KEY for real embeddings)");
                 Arc::new(ioi_api::vm::inference::mock::MockInferenceRuntime)
            };

            // Store in AppState
            {
                let state: State<Mutex<AppState>> = app.handle().state();
                let mut s = state.lock().expect("Failed to lock app state");
                s.inference_runtime = Some(inference_runtime.clone());
            }

            // 3. Initialize Local MCP Runtime
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                execution::init_mcp_servers(handle).await;
            });
            
            // 4. Setup Menu and Tray
            let show_spotlight_item = MenuItem::with_id(
                app,
                "spotlight",
                "Open Spotlight (Ctrl+Space)",
                true,
                None::<&str>,
            )?;
            let show_studio_item =
                MenuItem::with_id(app, "studio", "Open Studio", true, None::<&str>)?;
            let quit_item = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;

            let menu = Menu::with_items(
                app,
                &[&show_spotlight_item, &show_studio_item, &quit_item],
            )?;

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

            // 5. Setup Global Shortcuts
            #[cfg(target_os = "macos")]
            let shortcut = Shortcut::new(Some(Modifiers::CONTROL), Code::Space);
            #[cfg(not(target_os = "macos"))]
            let shortcut = Shortcut::new(Some(Modifiers::CONTROL), Code::Space);

            let app_handle = app.handle().clone();
            let _ = app.global_shortcut().on_shortcut(shortcut, move |_app, _shortcut, event| {
                if event.state == ShortcutState::Pressed {
                    if let Some(window) = app_handle.get_webview_window("spotlight") {
                        if window.is_visible().unwrap_or(false) {
                            let _ = window.hide();
                        } else {
                            let _ = window.show();
                            let _ = window.set_focus();
                        }
                    }
                }
            });
            
            // 6. Startup Behavior (Show Spotlight after delay on non-mac)
            #[cfg(not(target_os = "macos"))]
            {
                let handle = app.handle().clone();
                tauri::async_runtime::spawn(async move {
                    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
                    if let Some(window) = handle.get_webview_window("spotlight") {
                        if let Ok(visible) = window.is_visible() {
                            if !visible {
                                windows::show_spotlight(handle);
                            }
                        }
                    }
                });
            }

            // 7. Start Kernel Event Monitor
            let monitor_handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                kernel::monitor_kernel_events(monitor_handle).await;
            });
            
            println!("[Autopilot] Setup complete.");
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            // Window Management
            windows::show_spotlight,
            windows::hide_spotlight,
            windows::set_spotlight_mode,
            windows::show_pill,
            windows::hide_pill,
            windows::resize_pill,
            windows::show_gate,
            windows::hide_gate,
            windows::show_studio,
            windows::hide_studio,
            
            // Kernel / Agent Logic
            kernel::task::start_task,
            kernel::task::update_task,
            kernel::task::complete_task,
            kernel::task::dismiss_task,
            kernel::task::get_current_task,
            
            // Governance
            kernel::governance::gate_respond,
            kernel::governance::get_gate_response,
            kernel::governance::clear_gate_response,
            
            // Data / Context
            kernel::data::get_context_blob,
            kernel::data::get_available_tools, 
            
            // Session
            kernel::session::get_session_history,
            kernel::session::load_session,
            kernel::session::delete_session, 
            
            // Studio Inspector & Execution
            kernel::graph::test_node_execution,
            kernel::graph::run_studio_graph, 
            kernel::graph::check_node_cache,
            
            // Ingestion
            ingestion::ingest_file,

            // Project Persistence
            project::save_project,
            project::load_project
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}