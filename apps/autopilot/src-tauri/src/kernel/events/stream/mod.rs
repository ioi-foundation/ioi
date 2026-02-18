use ioi_ipc::public::chain_event::Event as ChainEventEnum;
use ioi_ipc::public::public_api_client::PublicApiClient;
use ioi_ipc::public::SubscribeEventsRequest;

mod action;
mod action_result;
mod fetch_pii;
mod ghost;
mod process_activity;
mod routing_receipt;
mod spawn;
mod system;
mod thought;

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
                eprintln!(
                    "[Autopilot] Failed to subscribe to events (retrying in 2s): {}",
                    e
                );
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                continue;
            }
        };

        println!("[Autopilot] Event Stream Active ✅");

        while let Ok(Some(event_msg)) = stream.message().await {
            if let Some(event_enum) = event_msg.event {
                match event_enum {
                    ChainEventEnum::Thought(thought) => {
                        thought::handle_thought(&app, thought).await;
                    }
                    ChainEventEnum::ActionResult(res) => {
                        action_result::handle_action_result(&app, res).await;
                    }
                    ChainEventEnum::WorkloadActivity(activity) => {
                        process_activity::handle_workload_activity(&app, activity).await;
                    }
                    ChainEventEnum::WorkloadReceipt(_receipt) => {
                        // Receipt details are handled via ActionResult and RoutingReceipt paths.
                    }
                    ChainEventEnum::RoutingReceipt(receipt) => {
                        routing_receipt::handle_routing_receipt(&app, receipt).await;
                    }
                    ChainEventEnum::Ghost(input) => {
                        ghost::handle_ghost(&app, input).await;
                    }
                    ChainEventEnum::Action(action) => {
                        action::handle_action(&app, action).await;
                    }
                    ChainEventEnum::Spawn(spawn) => {
                        spawn::handle_spawn(&app, spawn).await;
                    }
                    ChainEventEnum::System(update) => {
                        system::handle_system(&app, update).await;
                    }
                    ChainEventEnum::Block(block) => {
                        #[cfg(debug_assertions)]
                        println!(
                            "[Autopilot] Block #{} committed (Tx: {})",
                            block.height, block.tx_count
                        );
                    }
                }
            }
        }

        eprintln!("[Autopilot] Event Stream Disconnected. Attempting reconnection...");
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}
