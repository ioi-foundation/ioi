// apps/autopilot/src-tauri/src/lib.rs
use std::sync::{Arc, Mutex};
use tauri::{
    menu::{Menu, MenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    Emitter, Manager, State
};
use tauri_plugin_global_shortcut::{Code, GlobalShortcutExt, Modifiers, Shortcut, ShortcutState};

mod models;
mod windows;
mod kernel;
mod execution;
mod orchestrator; 
mod project;

use models::{AppState, GateInfo, AgentPhase, AgentTask, GhostInputEvent, Receipt, ChatMessage, SwarmAgent};

// Kernel Integration
use ioi_ipc::public::public_api_client::PublicApiClient;
use ioi_ipc::public::{
    chain_event::Event as ChainEventEnum, SubscribeEventsRequest
};
use ioi_scs::{SovereignContextStore, StoreConfig}; // [NEW]

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
                        // Update specific agent's thought in the swarm tree if found
                        // We assume session_id maps to agent ID for simplicity in this flat structure,
                        // or we look up the agent associated with the session.
                        // For the MVP, session_id == agent_id for child agents.
                        if let Some(agent) = t.swarm_tree.iter_mut().find(|a| a.id == thought.session_id) {
                            agent.current_thought = Some(thought.content.clone());
                            agent.status = "running".to_string();
                        } else {
                            // If root or unknown, update global pill
                            t.current_step = thought.content.clone();
                        }
                        
                        t.phase = AgentPhase::Running;
                        t.progress += 1;
                        if !thought.visual_hash.is_empty() {
                            t.visual_hash = Some(thought.visual_hash.clone());
                        }
                        if !thought.session_id.is_empty() {
                            t.session_id = Some(thought.session_id.clone());
                        }
                    });
                }
                ChainEventEnum::ActionResult(res) => {
                    update_task_state_local(&app, |t| {
                        // Deduplication using Composite Key (Index + Tool)
                        let dedup_key = format!("{}:{}", res.step_index, res.tool_name);

                        if t.processed_steps.contains(&dedup_key) {
                            return;
                        }
                        t.processed_steps.insert(dedup_key);

                        t.current_step = format!("Executed {}: {}", res.tool_name, res.output);
                        if !res.session_id.is_empty() {
                            t.session_id = Some(res.session_id.clone());
                        }
                        
                        // Update swarm agent status/artifacts
                        if let Some(agent) = t.swarm_tree.iter_mut().find(|a| a.id == res.session_id) {
                            agent.artifacts_produced += 1;
                        }

                        // Check for completion signals
                        if res.tool_name == "agent__complete" || res.tool_name == "system::max_steps_reached" || res.tool_name == "system::auto_complete" {
                             t.phase = AgentPhase::Complete;
                             
                             // Mark specific agent as complete
                             if let Some(agent) = t.swarm_tree.iter_mut().find(|a| a.id == res.session_id) {
                                 agent.status = "completed".to_string();
                             }

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
                             // Log Ghost Input
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

                                if !action.session_id.is_empty() {
                                    t.session_id = Some(action.session_id.clone());
                                }
                                
                                // Log Gate
                                t.history.push(ChatMessage {
                                    role: "system".to_string(),
                                    text: format!("🛑 Policy Gate triggered for action: {}", action.target),
                                    timestamp: now(),
                                });

                                // Update agent status if identifiable
                                if let Some(agent) = t.swarm_tree.iter_mut().find(|a| a.id == action.session_id) {
                                    agent.status = "paused".to_string();
                                }
                            });
                            
                            // [REMOVED] show_gate(app.clone());
                            // Instead, ensure the main window or spotlight grabs focus if in background
                            if let Some(w) = app.get_webview_window("spotlight") {
                                if w.is_visible().unwrap_or(false) {
                                    let _ = w.set_focus();
                                }
                            }
                        }
                    } 
                    else if action.verdict == "BLOCK" {
                        update_task_state_local(&app, |t| {
                             t.current_step = format!("⛔ Action Blocked: {}", action.target);
                             t.phase = AgentPhase::Failed;
                             
                             if let Some(agent) = t.swarm_tree.iter_mut().find(|a| a.id == action.session_id) {
                                 agent.status = "failed".to_string();
                             }

                             // Log Block
                             t.history.push(ChatMessage {
                                 role: "system".to_string(),
                                 text: format!("⛔ Blocked action: {}", action.target),
                                 timestamp: now(),
                             });
                        });
                    }
                }
                // Handle AgentSpawn: Updates the swarm tree structure
                ChainEventEnum::Spawn(spawn) => {
                    update_task_state_local(&app, |t| {
                        let agent = SwarmAgent {
                            id: spawn.new_session_id.clone(),
                            parent_id: if spawn.parent_session_id.is_empty() { None } else { Some(spawn.parent_session_id.clone()) },
                            name: spawn.name.clone(),
                            role: spawn.role.clone(),
                            status: "running".to_string(), // Spawning implies immediate execution
                            budget_used: 0.0,
                            budget_cap: spawn.budget as f64,
                            current_thought: Some(format!("Initialized goal: {}", spawn.goal)),
                            artifacts_produced: 0,
                            estimated_cost: 0.0,
                            policy_hash: "".to_string(), // Populated if available
                        };
                        
                        // Upsert logic: Update if exists (e.g. from requisition -> running), else insert
                        if let Some(pos) = t.swarm_tree.iter().position(|a| a.id == agent.id) {
                            t.swarm_tree[pos] = agent;
                        } else {
                            t.swarm_tree.push(agent);
                        }
                    });
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
                // [FIX] Handle lock result safely without if let temporary
                let mut s = state.lock().expect("Failed to lock app state during init");
                s.studio_scs = Some(Arc::new(Mutex::new(scs)));
            } else {
                eprintln!("[Studio] Failed to initialize SCS. Persistence disabled.");
            }

            // 2. Initialize Local MCP Runtime
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                execution::init_mcp_servers(handle).await;
            });
            
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
            kernel::start_task,
            kernel::update_task,
            kernel::complete_task,
            kernel::dismiss_task,
            kernel::get_current_task,
            
            // Governance
            kernel::gate_respond,
            kernel::get_gate_response,
            kernel::clear_gate_response,
            
            // Data / Context
            kernel::get_context_blob,
            kernel::get_session_history,
            kernel::load_session,
            kernel::delete_session, 
            kernel::get_available_tools, 
            
            // Studio Inspector & Execution
            kernel::test_node_execution,
            kernel::run_studio_graph, 

            // Project Persistence
            project::save_project,
            project::load_project
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

pub fn run_lib() {
    run()
}