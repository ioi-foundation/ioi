// Path: apps/autopilot/src-tauri/src/lib.rs
use std::sync::Mutex;
use tauri::{
    menu::{Menu, MenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    Emitter, Manager,
};
use tauri_plugin_global_shortcut::{Code, GlobalShortcutExt, Modifiers, Shortcut, ShortcutState};

mod models;
mod windows;
mod kernel;

use models::{AppState, GateInfo, AgentPhase, AgentTask, GhostInputEvent, Receipt, ChatMessage};
use windows::{show_gate};

// Kernel Integration
use ioi_ipc::public::public_api_client::PublicApiClient;
use ioi_ipc::public::{
    chain_event::Event as ChainEventEnum, SubscribeEventsRequest
};

// Helper to get current timestamp
fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis() as u64
}

fn update_task_state_local<F>(app: &tauri::AppHandle, mut f: F)
where
    F: FnMut(&mut AgentTask),
{
    let state = app.state::<Mutex<AppState>>();
    let mut task_clone: Option<AgentTask> = None;

    if let Ok(mut s) = state.lock() {
        if let Some(ref mut task) = s.current_task {
            f(task);
            task_clone = Some(task.clone());
        }
    }

    if let Some(t) = task_clone {
        let event_name = match t.phase {
            AgentPhase::Complete => "task-completed",
            _ => "task-updated",
        };
        let _ = app.emit(event_name, &t);
    }
}

async fn monitor_kernel_events(app: tauri::AppHandle) {
    let mut client = loop {
        match PublicApiClient::connect("http://127.0.0.1:9000").await {
            Ok(c) => {
                println!("[Autopilot] Connected to Kernel Event Stream at :9000");
                break c;
            }
            Err(_) => {
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
        }
    };

    let request = tonic::Request::new(SubscribeEventsRequest {});
    let mut stream = match client.subscribe_events(request).await {
        Ok(s) => s.into_inner(),
        Err(e) => {
            eprintln!("[Autopilot] Failed to subscribe to events: {}", e);
            return;
        }
    };

    let state_handle = app.state::<Mutex<AppState>>();

    println!("[Autopilot] Listening for events...");
    while let Ok(Some(event_msg)) = stream.message().await {
        if let Some(event_enum) = event_msg.event {
            match event_enum {
                ChainEventEnum::Thought(thought) => {
                    update_task_state_local(&app, |t| {
                        t.current_step = thought.content.clone();
                        t.phase = AgentPhase::Running;
                        t.progress += 1;
                        if !thought.visual_hash.is_empty() {
                            t.visual_hash = Some(thought.visual_hash.clone());
                        }
                        if !thought.session_id.is_empty() {
                            t.session_id = Some(thought.session_id.clone());
                        }
                        
                        // Thoughts are ephemeral status updates. 
                        // We do NOT push them to history in Chat Mode to avoid duplication 
                        // with the final ActionResult.
                    });
                }
                ChainEventEnum::ActionResult(res) => {
                    update_task_state_local(&app, |t| {
                        // [FIX] Deduplication using Composite Key (Index + Tool)
                        // This ensures 'filesystem__write_file' (Step 0) AND 'system::auto_complete' (Step 0)
                        // are both processed, allowing the phase transition to Complete.
                        let dedup_key = format!("{}:{}", res.step_index, res.tool_name);

                        if t.processed_steps.contains(&dedup_key) {
                            return;
                        }
                        t.processed_steps.insert(dedup_key);

                        t.current_step = format!("Executed {}: {}", res.tool_name, res.output);
                        if !res.session_id.is_empty() {
                            t.session_id = Some(res.session_id.clone());
                        }
                        
                        // [FIX] Added system::auto_complete to the check
                        if res.tool_name == "agent__complete" || res.tool_name == "system::max_steps_reached" || res.tool_name == "system::auto_complete" {
                             t.phase = AgentPhase::Complete;
                             t.receipt = Some(Receipt {
                                 duration: "Done".to_string(), 
                                 actions: t.progress,
                                 cost: Some("$0.00".to_string()),
                             });
                             // Log completion if not redundant
                             let msg = format!("Task Completed: {}", res.output);
                             if t.history.last().map(|m| m.text != msg).unwrap_or(true) {
                                 t.history.push(ChatMessage { role: "system".into(), text: msg, timestamp: now() });
                             }
                        }
                        
                        // Chat Mode completion
                        if res.tool_name == "chat::reply" {
                             t.phase = AgentPhase::Complete;
                             t.current_step = res.output.clone(); 
                             t.receipt = Some(Receipt {
                                 duration: "Done".to_string(), 
                                 actions: 1,
                                 cost: Some("$0.00".to_string()),
                             });
                             
                             // DEDUPLICATION: Check last history item
                             let duplicate = t.history.last().map(|m| m.text == res.output).unwrap_or(false);
                             
                             if !duplicate {
                                 t.history.push(ChatMessage {
                                     role: "agent".to_string(),
                                     text: res.output.clone(),
                                     timestamp: now(),
                                 });
                             }
                        } else if res.tool_name != "agent__complete" && res.tool_name != "system::max_steps_reached" && res.tool_name != "system::auto_complete" {
                             // Log tool output for normal tools
                             t.history.push(ChatMessage {
                                 role: "tool".to_string(),
                                 text: format!("Tool Output ({}): {}", res.tool_name, res.output),
                                 timestamp: now(),
                             });
                        }
                    });
                }
                ChainEventEnum::Ghost(input) => {
                    let payload = GhostInputEvent {
                        device: input.device.clone(),
                        description: input.description.clone(),
                    };
                    let _ = app.emit("ghost-input", &payload);
                    update_task_state_local(&app, |t| {
                        if matches!(t.phase, AgentPhase::Running) {
                             t.current_step = format!("User Input: {}", input.description);
                             // [NEW] Log Ghost Input
                             t.history.push(ChatMessage {
                                 role: "user".to_string(),
                                 text: format!("[Ghost] {}", input.description),
                                 timestamp: now(),
                             });
                        }
                    });
                }
                ChainEventEnum::Action(action) => {
                    if action.verdict == "REQUIRE_APPROVAL" {
                        let already_gating = {
                            if let Ok(guard) = state_handle.lock() {
                                if let Some(task) = &guard.current_task {
                                    task.phase == AgentPhase::Gate && task.pending_request_hash.as_deref() == Some(action.reason.as_str())
                                } else {
                                    false
                                }
                            } else {
                                false
                            }
                        };

                        if !already_gating {
                            println!("[Autopilot] Policy Gate Triggered for {}", action.target);
                            
                            update_task_state_local(&app, |t| {
                                t.phase = AgentPhase::Gate;
                                t.current_step = "Policy Gate: Approval Required".to_string();
                                
                                t.gate_info = Some(GateInfo {
                                    title: "Restricted Action Intercepted".to_string(),
                                    description: format!("The agent is attempting to execute: {}", action.target),
                                    risk: "high".to_string(), 
                                });
                                
                                t.pending_request_hash = Some(action.reason.clone());

                                // [FIX] Capture session ID from event if present
                                if !action.session_id.is_empty() {
                                    t.session_id = Some(action.session_id.clone());
                                }
                                
                                // [NEW] Log Gate
                                t.history.push(ChatMessage {
                                    role: "system".to_string(),
                                    text: format!("🛑 Policy Gate triggered for action: {}", action.target),
                                    timestamp: now(),
                                });
                            });
                            
                            show_gate(app.clone());
                        }
                    } 
                    else if action.verdict == "BLOCK" {
                        update_task_state_local(&app, |t| {
                             t.current_step = format!("⛔ Action Blocked: {}", action.target);
                             t.phase = AgentPhase::Failed;
                             // [NEW] Log Block
                             t.history.push(ChatMessage {
                                 role: "system".to_string(),
                                 text: format!("⛔ Blocked action: {}", action.target),
                                 timestamp: now(),
                             });
                        });
                    }
                }
                _ => {}
            }
        }
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_global_shortcut::Builder::new().build())
        .plugin(tauri_plugin_notification::init())
        .manage(Mutex::new(AppState::default()))
        .setup(|app| {
            println!("[Autopilot] Initializing...");
            
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

            let monitor_handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                monitor_kernel_events(monitor_handle).await;
            });
            
            println!("[Autopilot] Setup complete.");
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
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
            kernel::start_task,
            kernel::update_task,
            kernel::complete_task,
            kernel::dismiss_task,
            kernel::get_current_task,
            kernel::gate_respond,
            kernel::get_gate_response,
            kernel::clear_gate_response,
            kernel::get_context_blob,
            kernel::get_session_history,
            kernel::load_session,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

pub fn run_lib() {
    run()
}