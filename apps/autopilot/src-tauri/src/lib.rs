// Path: apps/autopilot/src-tauri/src/lib.rs
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use std::time::Duration;
use tauri::{
    menu::{Menu, MenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    AppHandle, Emitter, Manager, State,
};
use tauri_plugin_global_shortcut::{Code, GlobalShortcutExt, Modifiers, Shortcut, ShortcutState};

// Imports for IOI Kernel Integration
use ioi_ipc::public::public_api_client::PublicApiClient;
use ioi_ipc::public::{
    chain_event::Event as ChainEventEnum, DraftTransactionRequest, GetContextBlobRequest,
    SubmitTransactionRequest, SubscribeEventsRequest,
};
use tonic::transport::Channel;

// ============================================
// State Types
// ============================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AgentPhase {
    Idle,
    Running,
    Gate,
    Complete,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateInfo {
    pub title: String,
    pub description: String,
    pub risk: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Receipt {
    pub duration: String,
    pub actions: u32,
    pub cost: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentTask {
    pub id: String,
    pub intent: String,
    pub agent: String,
    pub phase: AgentPhase,
    pub progress: u32,
    pub total_steps: u32,
    pub current_step: String,
    pub gate_info: Option<GateInfo>,
    pub receipt: Option<Receipt>,
    // [NEW] Store the current visual context hash
    pub visual_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateResponse {
    pub responded: bool,
    pub approved: bool,
}

// [NEW] Struct for Blob Response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextBlob {
    pub data_base64: String,
    pub mime_type: String,
}

// [NEW] Local serializable struct for GhostInput event
#[derive(Debug, Clone, Serialize, Deserialize)]
struct GhostInputEvent {
    device: String,
    description: String,
}

#[derive(Default)]
pub struct AppState {
    pub current_task: Option<AgentTask>,
    pub gate_response: Option<GateResponse>,
    pub is_simulating: bool,
    // [NEW] gRPC Client handle (cached to avoid reconnecting every request)
    // Wrapped in Arc<Mutex> because State must be Send+Sync and the Client is cloneable but needs mutability for some calls
    pub rpc_client: Option<PublicApiClient<Channel>>,
}

// ============================================
// Window Commands
// ============================================

#[tauri::command]
fn show_spotlight(app: AppHandle) {
    if let Some(window) = app.get_webview_window("spotlight") {
        let _ = window.show();
        let _ = window.set_focus();
    }
}

#[tauri::command]
fn hide_spotlight(app: AppHandle) {
    if let Some(window) = app.get_webview_window("spotlight") {
        let _ = window.hide();
    }
}

#[tauri::command]
fn set_spotlight_mode(app: AppHandle, mode: String) {
    if let Some(window) = app.get_webview_window("spotlight") {
        if let Ok(Some(monitor)) = window.primary_monitor() {
            let size = monitor.size();
            let scale = monitor.scale_factor();
            let screen_w = size.width as f64 / scale;
            let screen_h = size.height as f64 / scale;

            let _ = window.hide();
            let _ = window.set_decorations(true);
            let _ = window.set_shadow(true);
            let _ = window.set_always_on_top(true);

            if mode == "spotlight" {
                let _ = window.set_resizable(false);
                let width = 800.0;
                let height = 600.0;
                let x = (screen_w - width) / 2.0;
                let y = (screen_h - height) / 3.0;
                let _ = window.set_size(tauri::Size::Logical(tauri::LogicalSize { width, height }));
                let _ = window
                    .set_position(tauri::Position::Logical(tauri::LogicalPosition { x, y }));
            } else {
                let _ = window.set_resizable(true);
                let width = 450.0;
                let height = screen_h - 40.0;
                let x = screen_w - width;
                let y = 0.0;
                let _ = window.set_size(tauri::Size::Logical(tauri::LogicalSize { width, height }));
                let _ = window
                    .set_position(tauri::Position::Logical(tauri::LogicalPosition { x, y }));
            }

            let _ = window.show();
            let _ = window.set_focus();
        }
    }
}

#[tauri::command]
fn show_pill(app: AppHandle) {
    if let Some(window) = app.get_webview_window("pill") {
        if let Ok(Some(monitor)) = window.primary_monitor() {
            let size = monitor.size();
            let scale = monitor.scale_factor();
            let screen_w = size.width as f64 / scale;
            let screen_h = size.height as f64 / scale;
            let win_w = 310.0;
            let win_h = 60.0;
            let margin = 16.0;
            let taskbar = 48.0;
            let x = screen_w - win_w - margin;
            let y = screen_h - win_h - margin - taskbar;
            let _ = window.set_position(tauri::Position::Logical(tauri::LogicalPosition { x, y }));
            let _ = window.set_always_on_top(true);
        }
        let _ = window.show();
    }
}

#[tauri::command]
fn hide_pill(app: AppHandle) {
    if let Some(window) = app.get_webview_window("pill") {
        let _ = window.hide();
    }
}

#[tauri::command]
fn resize_pill(app: AppHandle, expanded: bool) {
    if let Some(window) = app.get_webview_window("pill") {
        let height = if expanded { 160.0 } else { 60.0 };
        let _ = window.set_size(tauri::Size::Logical(tauri::LogicalSize {
            width: 310.0,
            height,
        }));
    }
}

#[tauri::command]
fn show_gate(app: AppHandle) {
    if let Some(window) = app.get_webview_window("gate") {
        let _ = window.center();
        let _ = window.set_always_on_top(true);
        let _ = window.show();
        let _ = window.set_focus();
    }
}

#[tauri::command]
fn hide_gate(app: AppHandle) {
    if let Some(window) = app.get_webview_window("gate") {
        let _ = window.hide();
    }
}

#[tauri::command]
fn show_studio(app: AppHandle) {
    if let Some(window) = app.get_webview_window("studio") {
        let _ = window.show();
        let _ = window.set_focus();
    }
}

#[tauri::command]
fn hide_studio(app: AppHandle) {
    if let Some(window) = app.get_webview_window("studio") {
        let _ = window.hide();
    }
}

// ============================================
// Data Retrieval Commands
// ============================================

/// Retrieves a raw context slice (image, xml, text) from the Kernel's SCS by Hash.
#[tauri::command]
async fn get_context_blob(
    state: State<'_, Mutex<AppState>>,
    hash: String,
) -> Result<ContextBlob, String> {
    
    // Step 1: Check if we have a cached client. Use a scope to drop the lock immediately.
    let cached_client = {
        let s = state.lock().map_err(|_| "Failed to lock state")?;
        s.rpc_client.clone()
    };

    // Step 2: If we have a client, use it. If not, connect (async) and then cache it.
    let mut client = if let Some(c) = cached_client {
        c
    } else {
        let channel = Channel::from_static("http://127.0.0.1:9000")
            .connect()
            .await
            .map_err(|e| format!("Failed to connect to Kernel: {}", e))?;
        let new_client = PublicApiClient::new(channel);

        // Cache the new client
        {
            if let Ok(mut s) = state.lock() {
                if s.rpc_client.is_none() {
                    s.rpc_client = Some(new_client.clone());
                }
            }
        }
        new_client
    };

    // 3. Call gRPC (no lock held)
    let request = tonic::Request::new(GetContextBlobRequest { blob_hash: hash });

    let response = client
        .get_context_blob(request)
        .await
        .map_err(|e| format!("RPC error: {}", e))?
        .into_inner();

    // 4. Convert bytes to Base64 for frontend
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let data_base64 = STANDARD.encode(&response.data);

    // 5. Infer valid MIME type if kernel sent generic default
    let mime_type = if response.mime_type == "application/octet-stream" {
        if response.data.starts_with(b"\x89PNG") {
            "image/png".to_string()
        } else if response.data.starts_with(b"<") || response.data.starts_with(b"<?xml") {
            "text/xml".to_string() // Accessibility Tree
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

// ============================================
// Task Commands & Kernel Integration
// ============================================

fn update_task_state<F>(app: &AppHandle, mut f: F)
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

/// Connects to the local IOI Node and streams events to the UI.
async fn monitor_kernel_events(app: AppHandle) {
    // 1. Attempt connection (Retry loop)
    let mut client = loop {
        match PublicApiClient::connect("http://127.0.0.1:9000").await {
            Ok(c) => {
                println!("[Autopilot] Connected to Kernel Event Stream at :9000");
                break c;
            }
            Err(_) => {
                // If node isn't running, wait 2s and retry
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    };

    // 2. Subscribe to Event Stream
    let request = tonic::Request::new(SubscribeEventsRequest {});
    let mut stream = match client.subscribe_events(request).await {
        Ok(s) => s.into_inner(),
        Err(e) => {
            eprintln!("[Autopilot] Failed to subscribe to events: {}", e);
            return;
        }
    };

    // 3. Consume Stream
    while let Ok(Some(event_msg)) = stream.message().await {
        if let Some(event_enum) = event_msg.event {
            match event_enum {
                // Agent "Thinking" or Acting
                ChainEventEnum::Thought(thought) => {
                    update_task_state(&app, |t| {
                        // [FIX] Clone content because FnMut closure cannot consume outer variable
                        t.current_step = thought.content.clone();
                        t.phase = AgentPhase::Running;
                        t.progress += 1;
                        // [NEW] Update visual hash if present (non-empty string)
                        if !thought.visual_hash.is_empty() {
                            t.visual_hash = Some(thought.visual_hash.clone());
                        }
                    });
                }

                // [NEW] Agent Action Results (Outputs from tools)
                ChainEventEnum::ActionResult(res) => {
                    println!("[Autopilot] Action Result: {} -> {}", res.tool_name, res.output);
                    
                    update_task_state(&app, |t| {
                        // Append the output to the current step description for visibility
                        t.current_step = format!("Executed {}: {}", res.tool_name, res.output);
                        
                        // If it's a sys__exec, we treat it as progress towards completion
                        if res.tool_name == "sys__exec" && !res.output.is_empty() {
                             // Mark complete for this demo flow
                             t.phase = AgentPhase::Complete;
                             t.receipt = Some(Receipt {
                                 duration: "2s".to_string(), // Mock duration
                                 actions: 1,
                                 cost: Some("$0.00".to_string()),
                             });
                        }
                    });
                }

                // [NEW] Ghost Mode Inputs
                ChainEventEnum::Ghost(input) => {
                    println!("[Autopilot] Ghost Input: [{}] {}", input.device, input.description);
                    
                    // Create serializable payload
                    let payload = GhostInputEvent {
                        device: input.device.clone(),
                        description: input.description.clone(),
                    };

                    // Emit a specific event for the trace recorder UI (Store)
                    let _ = app.emit("ghost-input", &payload);
                    
                    // Optionally update a "Ghost Recording" task state here for visual feedback on the pill
                    update_task_state(&app, |t| {
                        if matches!(t.phase, AgentPhase::Running) {
                             t.current_step = format!("User Input: {}", input.description);
                        }
                    });
                }

                // Firewall Interception -> Open Gate
                ChainEventEnum::Action(action) => {
                    if action.verdict == "REQUIRE_APPROVAL" {
                        update_task_state(&app, |t| {
                            t.phase = AgentPhase::Gate;
                            t.current_step = "Policy Gate: Approval Required".to_string();
                            t.gate_info = Some(GateInfo {
                                title: "Restricted Action Intercepted".to_string(),
                                description: format!(
                                    "Agent attempting to perform: {}",
                                    action.target
                                ),
                                risk: "medium".to_string(), // Inferred
                            });
                        });
                        show_gate(app.clone());
                    } else if action.verdict == "BLOCK" {
                        update_task_state(&app, |t| {
                            t.phase = AgentPhase::Failed;
                            t.current_step = format!("Blocked by Firewall: {}", action.reason);
                        });
                    }
                }

                // Block Commit -> Confirm Progress
                ChainEventEnum::Block(block) => {
                    println!(
                        "[Autopilot] Block #{} Committed (Root: {})",
                        block.height, block.state_root
                    );
                }

                _ => {}
            }
        }
    }

    println!("[Autopilot] Event stream ended. Reconnecting...");
    // In production, we'd recursively call monitor_kernel_events here for auto-reconnect.
}

// Fallback simulation for dev/demo without running node
async fn run_simulation(app: AppHandle) {
    let steps = vec![
        "Parsing natural language...",
        "Identifying required tools...",
        "Searching knowledge base...",
        "GATE_TRIGGER",
        "Navigating to payments page...",
        "Clicking 'Pay Now' button...",
        "Verifying transaction results...",
    ];

    for (i, step_name) in steps.iter().enumerate() {
        if *step_name == "GATE_TRIGGER" {
            update_task_state(&app, |t| {
                t.phase = AgentPhase::Gate;
                t.current_step = "Policy Check Required".to_string();
                t.gate_info = Some(GateInfo {
                    title: "Sensitive Action Detected".to_string(),
                    description: "The agent attempts to authorize a payment of $42.00 via Stripe."
                        .to_string(),
                    risk: "medium".to_string(),
                });
            });
            show_gate(app.clone());

            // Wait for approval
            let mut approved = false;
            loop {
                tokio::time::sleep(Duration::from_millis(300)).await;
                let state_guard = app.state::<Mutex<AppState>>();
                let Ok(state) = state_guard.lock() else { break; };
                if state.current_task.is_none() {
                    return;
                }
                if let Some(response) = &state.gate_response {
                    approved = response.approved;
                    break;
                }
            }

            if !approved {
                update_task_state(&app, |t| {
                    t.phase = AgentPhase::Failed;
                    t.current_step = "Blocked by User".to_string();
                });
                return;
            }

            update_task_state(&app, |t| {
                t.phase = AgentPhase::Running;
                t.gate_info = None;
                t.current_step = "Gate Approved. Resuming...".to_string();
            });
            tokio::time::sleep(Duration::from_millis(800)).await;
            continue;
        }

        tokio::time::sleep(Duration::from_millis(1500)).await;
        if let Ok(state) = app.state::<Mutex<AppState>>().lock() {
            if state.current_task.is_none() {
                return;
            }
        }
        update_task_state(&app, |t| {
            t.current_step = step_name.to_string();
            t.progress = i as u32 + 1;
        });
    }

    update_task_state(&app, |t| {
        t.phase = AgentPhase::Complete;
        t.progress = 7;
        t.current_step = "Done".to_string();
        t.receipt = Some(Receipt {
            duration: "8.2s".to_string(),
            actions: 14,
            cost: Some("$0.02".to_string()),
        });
    });
}

#[tauri::command]
fn start_task(
    state: State<Mutex<AppState>>,
    app: AppHandle,
    intent: String,
) -> Result<AgentTask, String> {
    // 1. Initialize local UI state optimistically
    let task = AgentTask {
        id: uuid::Uuid::new_v4().to_string(),
        intent: intent.clone(),
        agent: "General Agent".to_string(),
        phase: AgentPhase::Running,
        progress: 0,
        total_steps: 10,
        current_step: "Transmitting intent to Kernel...".to_string(),
        gate_info: None,
        receipt: None,
        visual_hash: None, // [NEW] Initialize
    };

    {
        let mut app_state = state.lock().map_err(|_| "Failed to lock state")?;
        app_state.current_task = Some(task.clone());
        app_state.gate_response = None;
    }

    let _ = app.emit("task-started", &task);
    show_pill(app.clone());

    // 2. Spawn Logic: Try Kernel, Fallback to Simulation
    let app_clone = app.clone();
    let intent_clone = intent.clone();

    tauri::async_runtime::spawn(async move {
        // A. Attempt to connect to IOI Kernel
        let mut client = match PublicApiClient::connect("http://127.0.0.1:9000").await {
            Ok(c) => c,
            Err(_) => {
                println!("[Autopilot] Kernel offline (or not at :9000). Falling back to simulation.");
                run_simulation(app_clone).await;
                return;
            }
        };

        println!("[Autopilot] Connected to Kernel. Drafting intent: '{}'", intent_clone);

        // B. Draft Transaction
        let draft_req = tonic::Request::new(DraftTransactionRequest {
            intent: intent_clone,
            address_book: Default::default(),
        });

        match client.draft_transaction(draft_req).await {
            Ok(resp) => {
                let draft = resp.into_inner();
                // In production, we'd sign `draft.transaction_bytes`.
                // For dev "God Mode", we submit directly to trigger the flow.
                let submit_req = tonic::Request::new(SubmitTransactionRequest {
                    transaction_bytes: draft.transaction_bytes,
                });

                if let Err(e) = client.submit_transaction(submit_req).await {
                    eprintln!("[Autopilot] Submission failed: {}", e);
                    // Force a UI failure state
                    update_task_state(&app_clone, |t| {
                        t.phase = AgentPhase::Failed;
                        t.current_step = format!("Submission Error: {}", e);
                    });
                } else {
                    println!("[Autopilot] Intent submitted. Listening for events...");
                    // C. Listen for execution updates
                    monitor_kernel_events(app_clone).await;
                }
            }
            Err(e) => {
                eprintln!("[Autopilot] Drafting failed: {}. Falling back to simulation.", e);
                run_simulation(app_clone).await;
            }
        }
    });

    Ok(task)
}

#[tauri::command]
fn update_task(
    state: State<Mutex<AppState>>,
    app: AppHandle,
    task: AgentTask,
) -> Result<(), String> {
    let is_gate = matches!(task.phase, AgentPhase::Gate);
    if let Ok(mut app_state) = state.lock() {
        app_state.current_task = Some(task.clone());
        if is_gate {
            app_state.gate_response = None;
        }
    }
    if is_gate {
        show_gate(app.clone());
    }
    let _ = app.emit("task-updated", &task);
    Ok(())
}

#[tauri::command]
fn complete_task(
    state: State<Mutex<AppState>>,
    app: AppHandle,
    success: bool,
) -> Result<(), String> {
    if let Ok(mut app_state) = state.lock() {
        if let Some(ref mut task) = app_state.current_task {
            task.phase = if success {
                AgentPhase::Complete
            } else {
                AgentPhase::Failed
            };
            let _ = app.emit("task-completed", task.clone());
        }
    }
    Ok(())
}

#[tauri::command]
fn dismiss_task(state: State<Mutex<AppState>>, app: AppHandle) -> Result<(), String> {
    if let Ok(mut app_state) = state.lock() {
        app_state.current_task = None;
        app_state.gate_response = None;
    }
    hide_pill(app.clone());
    hide_gate(app.clone());
    let _ = app.emit("task-dismissed", ());
    Ok(())
}

#[tauri::command]
fn get_current_task(state: State<Mutex<AppState>>) -> Option<AgentTask> {
    state.lock().ok().and_then(|s| s.current_task.clone())
}

#[tauri::command]
fn gate_respond(
    state: State<Mutex<AppState>>,
    app: AppHandle,
    approved: bool,
) -> Result<(), String> {
    if let Ok(mut app_state) = state.lock() {
        app_state.gate_response = Some(GateResponse {
            responded: true,
            approved,
        });
    }
    hide_gate(app.clone());
    let _ = app.emit("gate-response", approved);
    Ok(())
}

#[tauri::command]
fn get_gate_response(state: State<Mutex<AppState>>) -> Option<GateResponse> {
    state.lock().ok().and_then(|s| s.gate_response.clone())
}

#[tauri::command]
fn clear_gate_response(state: State<Mutex<AppState>>) -> Result<(), String> {
    if let Ok(mut app_state) = state.lock() {
        app_state.gate_response = None;
    }
    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_global_shortcut::Builder::new().build())
        .plugin(tauri_plugin_notification::init())
        .manage(Mutex::new(AppState::default()))
        .setup(|app| {
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
                let tray_result = TrayIconBuilder::new()
                    .menu(&menu)
                    .icon(icon)
                    .icon_as_template(true)
                    .on_menu_event(|app, event| match event.id.as_ref() {
                        "spotlight" => show_spotlight(app.clone()),
                        "studio" => show_studio(app.clone()),
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
                            show_spotlight(tray.app_handle().clone());
                        }
                    })
                    .build(app);

                if let Err(e) = tray_result {
                    eprintln!(
                        "WARNING: Failed to initialize system tray: {}. App will continue without it.",
                        e
                    );
                }
            } else {
                eprintln!("WARNING: Failed to load default window icon. Tray icon will not be available.");
            }

            #[cfg(target_os = "macos")]
            let shortcut = Shortcut::new(Some(Modifiers::CONTROL), Code::Space);
            #[cfg(not(target_os = "macos"))]
            let shortcut = Shortcut::new(Some(Modifiers::CONTROL), Code::Space);

            let app_handle = app.handle().clone();
            match app.global_shortcut().on_shortcut(shortcut, move |_app, _shortcut, event| {
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
            }) {
                Ok(_) => println!("Global shortcut registered."),
                Err(e) => eprintln!("Global shortcut error: {}", e),
            }

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            show_spotlight,
            hide_spotlight,
            set_spotlight_mode,
            show_pill,
            hide_pill,
            resize_pill,
            show_gate,
            hide_gate,
            gate_respond,
            get_gate_response,
            clear_gate_response,
            show_studio,
            hide_studio,
            start_task,
            update_task,
            complete_task,
            dismiss_task,
            get_current_task,
            get_context_blob, // [NEW] Register the blob retrieval command
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

pub fn run_lib() {
    run()
}