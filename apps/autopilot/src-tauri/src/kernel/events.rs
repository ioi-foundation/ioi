// apps/autopilot/src-tauri/src/kernel/events.rs

use crate::kernel::state::{update_task_state};
use crate::models::{AgentPhase, AppState, ChatMessage, GateInfo, GhostInputEvent, Receipt, SwarmAgent};
use ioi_ipc::public::chain_event::Event as ChainEventEnum;
use ioi_ipc::public::public_api_client::PublicApiClient;
use ioi_ipc::public::SubscribeEventsRequest;
use std::sync::Mutex;
use tauri::{Manager, Emitter}; 

pub async fn monitor_kernel_events(app: tauri::AppHandle) {
    loop {
        let mut client = loop {
            match PublicApiClient::connect("http://127.0.0.1:9000").await {
                Ok(c) => {
                    println!("[Autopilot] Connected to Kernel Event Stream at :9000");
                    break c;
                }
                Err(_) => {
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
            }
        };

        let request = tonic::Request::new(SubscribeEventsRequest {});
        
        let mut stream = match client.subscribe_events(request).await {
            Ok(s) => s.into_inner(),
            Err(e) => {
                eprintln!("[Autopilot] Failed to subscribe to events (retrying in 2s): {}", e);
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                continue;
            }
        };

        let state_handle = app.state::<Mutex<AppState>>();

        println!("[Autopilot] Event Stream Active ✅");
        
        while let Ok(Some(event_msg)) = stream.message().await {
            if let Some(event_enum) = event_msg.event {
                match event_enum {
                    ChainEventEnum::Thought(thought) => {
                        update_task_state(&app, |t| {
                            if let Some(agent) = t.swarm_tree.iter_mut().find(|a| a.id == thought.session_id) {
                                if let Some(existing) = &agent.current_thought {
                                    agent.current_thought = Some(format!("{}{}", existing, thought.content));
                                } else {
                                    agent.current_thought = Some(thought.content.clone());
                                }
                                if agent.status != "paused" && agent.status != "requisition" {
                                    agent.status = "running".to_string();
                                }
                            } else {
                                if t.current_step == "Initializing..." || t.current_step.starts_with("Executed") {
                                     t.current_step = thought.content.clone();
                                } else {
                                     t.current_step.push_str(&thought.content);
                                }
                            }
                            
                            if t.phase != AgentPhase::Complete 
                                && t.phase != AgentPhase::Failed 
                                && t.phase != AgentPhase::Gate 
                            {
                                t.phase = AgentPhase::Running;
                            }

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
                        update_task_state(&app, |t| {
                            let dedup_key = format!("{}:{}", res.step_index, res.tool_name);

                            if t.processed_steps.contains(&dedup_key) {
                                return;
                            }
                            t.processed_steps.insert(dedup_key);

                            t.current_step = format!("Executed {}: {}", res.tool_name, res.output);
                            if !res.session_id.is_empty() {
                                t.session_id = Some(res.session_id.clone());
                            }
                            
                            if let Some(agent) = t.swarm_tree.iter_mut().find(|a| a.id == res.session_id) {
                                agent.artifacts_produced += 1;
                            }

                            // [FIX] STATE-BASED TRUTH
                            // We use the authoritative status from the Kernel event instead of parsing output strings.
                            match res.agent_status.as_str() {
                                "Completed" => {
                                    t.phase = AgentPhase::Complete;
                                    
                                    if let Some(agent) = t.swarm_tree.iter_mut().find(|a| a.id == res.session_id) {
                                        agent.status = "completed".to_string();
                                    }

                                    t.receipt = Some(Receipt {
                                        duration: "Done".to_string(), 
                                        actions: t.progress,
                                        cost: Some("$0.00".to_string()),
                                    });
                                    
                                    let msg = format!("Task Completed: {}", res.output);
                                    if t.history.last().map(|m| m.text != msg).unwrap_or(true) {
                                        t.history.push(ChatMessage { role: "system".into(), text: msg, timestamp: crate::kernel::state::now() });
                                    }
                                },
                                "Failed" => {
                                    t.phase = AgentPhase::Failed;
                                     if let Some(agent) = t.swarm_tree.iter_mut().find(|a| a.id == res.session_id) {
                                        agent.status = "failed".to_string();
                                    }
                                    
                                    // Log failure message
                                    t.history.push(ChatMessage {
                                        role: "system".to_string(),
                                        text: format!("Task Failed: {}", res.output),
                                        timestamp: crate::kernel::state::now(),
                                    });
                                },
                                "Paused" => {
                                     // ChatReply or AgentPause sets status to Paused.
                                     // UI should reflect this, potentially hiding spinner or showing "Waiting".
                                     // For now, we handle ChatReply specifically below for messages.
                                     
                                     if let Some(agent) = t.swarm_tree.iter_mut().find(|a| a.id == res.session_id) {
                                        agent.status = "paused".to_string();
                                     }
                                },
                                _ => {
                                    // Default to Running
                                    if t.phase != AgentPhase::Gate {
                                        t.phase = AgentPhase::Running;
                                    }
                                }
                            }
                            
                            // Log chat messages for specific tools
                            if res.tool_name == "chat::reply" || res.tool_name == "chat__reply" {
                                 // Chat reply implies completion of that turn or pause for input.
                                 // If status is Paused, we show the input bar.
                                 // If status is Completed, we show checkmark.
                                 
                                 // For UI: if Paused, we treat as "Ready for Input" visually (Complete phase hides spinner)
                                 if res.agent_status == "Paused" {
                                     t.phase = AgentPhase::Complete; 
                                     t.current_step = "Ready for input".to_string();
                                 }
                                 
                                 let duplicate = t.history.last().map(|m| m.text == res.output).unwrap_or(false);
                                 if !duplicate {
                                     t.history.push(ChatMessage {
                                         role: "agent".to_string(),
                                         text: res.output.clone(),
                                         timestamp: crate::kernel::state::now(),
                                     });
                                 }
                            } else if res.tool_name == "system::refusal" {
                                 t.history.push(ChatMessage {
                                     role: "system".to_string(),
                                     text: format!("⚠️ Agent Paused: {}", res.output),
                                     timestamp: crate::kernel::state::now(),
                                 });
                            } else if res.agent_status == "Running" && res.tool_name != "agent__complete" {
                                 // Log standard tool output if running
                                 t.history.push(ChatMessage {
                                     role: "tool".to_string(),
                                     text: format!("Tool Output ({}): {}", res.tool_name, res.output),
                                     timestamp: crate::kernel::state::now(),
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
                        update_task_state(&app, |t| {
                            if matches!(t.phase, AgentPhase::Running) {
                                 t.current_step = format!("User Input: {}", input.description);
                                 t.history.push(ChatMessage {
                                     role: "user".to_string(),
                                     text: format!("[Ghost] {}", input.description),
                                     timestamp: crate::kernel::state::now(),
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
                                
                                update_task_state(&app, |t| {
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
                                    
                                    t.history.push(ChatMessage {
                                        role: "system".to_string(),
                                        text: format!("🛑 Policy Gate triggered for action: {}", action.target),
                                        timestamp: crate::kernel::state::now(),
                                    });

                                    if let Some(agent) = t.swarm_tree.iter_mut().find(|a| a.id == action.session_id) {
                                        agent.status = "paused".to_string();
                                    }
                                });
                                
                                if let Some(w) = app.get_webview_window("spotlight") {
                                    if w.is_visible().unwrap_or(false) {
                                        let _ = w.set_focus();
                                    }
                                }
                            }
                        } 
                        else if action.verdict == "BLOCK" {
                            update_task_state(&app, |t| {
                                 t.current_step = format!("⛔ Action Blocked: {}", action.target);
                                 t.phase = AgentPhase::Failed;
                                 
                                 if let Some(agent) = t.swarm_tree.iter_mut().find(|a| a.id == action.session_id) {
                                     agent.status = "failed".to_string();
                                 }

                                 t.history.push(ChatMessage {
                                     role: "system".to_string(),
                                     text: format!("⛔ Blocked action: {}", action.target),
                                     timestamp: crate::kernel::state::now(),
                                 });
                            });
                        }
                    }
                    ChainEventEnum::Spawn(spawn) => {
                        update_task_state(&app, |t| {
                            let agent = SwarmAgent {
                                id: spawn.new_session_id.clone(),
                                parent_id: if spawn.parent_session_id.is_empty() { None } else { Some(spawn.parent_session_id.clone()) },
                                name: spawn.name.clone(),
                                role: spawn.role.clone(),
                                status: "running".to_string(), 
                                budget_used: 0.0,
                                budget_cap: spawn.budget as f64,
                                current_thought: Some(format!("Initialized goal: {}", spawn.goal)),
                                artifacts_produced: 0,
                                estimated_cost: 0.0,
                                policy_hash: "".to_string(), 
                            };
                            
                            if let Some(pos) = t.swarm_tree.iter().position(|a| a.id == agent.id) {
                                t.swarm_tree[pos] = agent;
                            } else {
                                t.swarm_tree.push(agent);
                            }
                        });
                    }
                    ChainEventEnum::System(update) => {
                         update_task_state(&app, |t| {
                             t.history.push(ChatMessage {
                                 role: "system".to_string(),
                                 text: format!("⚙️ {}: {}", update.component, update.status),
                                 timestamp: crate::kernel::state::now(),
                             });
                         });
                    }
                    ChainEventEnum::Block(block) => {
                         #[cfg(debug_assertions)]
                         println!("[Autopilot] Block #{} committed (Tx: {})", block.height, block.tx_count);
                    }
                }
            }
        }
        
        eprintln!("[Autopilot] Event Stream Disconnected. Attempting reconnection...");
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}