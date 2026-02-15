use super::*;
use ioi_ipc::public::{
    chain_event::Event as ChainEventEnum, BlockCommitted, ChainEvent, SubscribeEventsRequest,
};

fn map_kernel_event(
    kernel_event: ioi_types::app::KernelEvent,
    receipt_signing_keypair: &libp2p::identity::Keypair,
    receipt_signer_pubkey: &str,
) -> Option<ChainEventEnum> {
    match kernel_event {
        ioi_types::app::KernelEvent::AgentThought { session_id, token } => {
            Some(ChainEventEnum::Thought(ioi_ipc::public::AgentThought {
                session_id: hex::encode(session_id),
                content: token,
                is_final: false,
                visual_hash: String::new(),
            }))
        }
        ioi_types::app::KernelEvent::AgentStep(step) => {
            Some(ChainEventEnum::Thought(ioi_ipc::public::AgentThought {
                session_id: hex::encode(step.session_id),
                content: step.raw_output,
                is_final: true,
                visual_hash: hex::encode(step.visual_hash),
            }))
        }
        ioi_types::app::KernelEvent::BlockCommitted { height, tx_count } => {
            Some(ChainEventEnum::Block(ioi_ipc::public::BlockCommitted {
                height,
                state_root: String::new(),
                tx_count: tx_count as u64,
            }))
        }
        ioi_types::app::KernelEvent::GhostInput {
            device,
            description,
        } => Some(ChainEventEnum::Ghost(ioi_ipc::public::GhostInput {
            device,
            description,
        })),
        ioi_types::app::KernelEvent::FirewallInterception {
            verdict,
            target,
            request_hash,
            session_id,
        } => Some(ChainEventEnum::Action(ioi_ipc::public::ActionIntercepted {
            session_id: session_id.map(hex::encode).unwrap_or_default(),
            target,
            verdict,
            reason: hex::encode(request_hash),
        })),
        ioi_types::app::KernelEvent::AgentActionResult {
            session_id,
            step_index,
            tool_name,
            output,
            agent_status,
        } => Some(ChainEventEnum::ActionResult(
            ioi_ipc::public::AgentActionResult {
                session_id: hex::encode(session_id),
                step_index,
                tool_name,
                output,
                agent_status,
            },
        )),
        ioi_types::app::KernelEvent::AgentSpawn {
            parent_session_id,
            new_session_id,
            name,
            role,
            budget,
            goal,
        } => Some(ChainEventEnum::Spawn(ioi_ipc::public::AgentSpawn {
            parent_session_id: hex::encode(parent_session_id),
            new_session_id: hex::encode(new_session_id),
            name,
            role,
            budget,
            goal,
        })),
        ioi_types::app::KernelEvent::ProcessActivity {
            session_id,
            step_index,
            tool_name,
            stream_id,
            channel,
            chunk,
            seq,
            is_final,
            exit_code,
            command_preview,
        } => Some(ChainEventEnum::ProcessActivity(
            ioi_ipc::public::ProcessActivity {
                session_id: hex::encode(session_id),
                step_index,
                tool_name,
                stream_id,
                channel,
                chunk,
                seq,
                is_final,
                exit_code: exit_code.unwrap_or_default(),
                has_exit_code: exit_code.is_some(),
                command_preview,
            },
        )),
        ioi_types::app::KernelEvent::RoutingReceipt(receipt) => {
            Some(ChainEventEnum::RoutingReceipt(map_routing_receipt(
                receipt,
                Some((receipt_signing_keypair, receipt_signer_pubkey)),
            )))
        }
        ioi_types::app::KernelEvent::SystemUpdate { component, status } => {
            Some(ChainEventEnum::System(ioi_ipc::public::SystemUpdate {
                component,
                status,
            }))
        }
    }
}

impl<CS, ST, CE, V> PublicApiImpl<CS, ST, CE, V>
where
    CS: CommitmentScheme + Clone + Send + Sync + 'static,
    ST: StateManager<Commitment = CS::Commitment, Proof = CS::Proof>
        + Send
        + Sync
        + 'static
        + Debug
        + Clone,
    <CS as CommitmentScheme>::Commitment: Send + Sync + Debug,
    CE: ioi_api::consensus::ConsensusEngine<ChainTransaction> + Send + Sync + 'static,
    V: ioi_api::state::Verifier<Commitment = CS::Commitment, Proof = CS::Proof>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug,
    <CS as CommitmentScheme>::Proof: Serialize
        + for<'de> serde::Deserialize<'de>
        + Clone
        + Send
        + Sync
        + 'static
        + Debug
        + Encode
        + Decode,
{
    pub(super) async fn handle_subscribe_events(
        &self,
        _request: Request<SubscribeEventsRequest>,
    ) -> Result<Response<ReceiverStream<Result<ChainEvent, Status>>>, Status> {
        let ctx_arc = self.get_context().await?;
        let (tx, rx) = mpsc::channel(128);
        let ctx_clone = ctx_arc.clone();

        tokio::spawn(async move {
            let mut tip_rx = {
                let ctx = ctx_clone.lock().await;
                ctx.tip_sender.subscribe()
            };

            let mut event_rx = {
                let ctx = ctx_clone.lock().await;
                ctx.event_broadcaster.subscribe()
            };

            let (receipt_signing_keypair, receipt_signer_pubkey) = {
                let ctx = ctx_clone.lock().await;
                (
                    ctx.local_keypair.clone(),
                    hex::encode(ctx.local_keypair.public().encode_protobuf()),
                )
            };

            loop {
                tokio::select! {
                    Ok(_) = tip_rx.changed() => {
                        let tip = tip_rx.borrow().clone();
                        let event = ChainEvent {
                            event: Some(ChainEventEnum::Block(
                                BlockCommitted {
                                    height: tip.height,
                                    state_root: hex::encode(&tip.state_root),
                                    tx_count: 0,
                                }
                            )),
                        };
                        if tx.send(Ok(event)).await.is_err() {
                            break;
                        }
                    }
                    Ok(kernel_event) = event_rx.recv() => {
                        tracing::info!(
                            target: "rpc",
                            "PublicAPI processing KernelEvent: {:?}",
                            kernel_event
                        );

                        if let Some(event_enum) = map_kernel_event(
                            kernel_event,
                            &receipt_signing_keypair,
                            receipt_signer_pubkey.as_str(),
                        ) {
                            let event = ChainEvent {
                                event: Some(event_enum),
                            };
                            if tx.send(Ok(event)).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            }
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }
}
