use super::*;
use ioi_crypto::algorithms::hash::sha256;
use ioi_ipc::public::{
    chain_event::Event as ChainEventEnum, BlockCommitted, ChainEvent, SubscribeEventsRequest,
};

fn env_truthy(key: &str) -> bool {
    std::env::var(key)
        .ok()
        .map(|value| {
            let normalized = value.trim().to_ascii_lowercase();
            normalized == "1" || normalized == "true" || normalized == "yes"
        })
        .unwrap_or(false)
}

fn should_log_raw_kernel_event_payloads() -> bool {
    env_truthy("IOI_LOG_RAW_KERNEL_EVENTS") || env_truthy("IOI_LOG_RAW_PROMPTS")
}

fn prefix_hex_4(bytes: &[u8; 32]) -> String {
    hex::encode(&bytes[..4])
}

fn text_fingerprint(text: &str) -> String {
    let hash_hex = sha256(text.as_bytes())
        .map(|digest| hex::encode(digest.as_ref()))
        .unwrap_or_else(|_| "sha256_error".to_string());
    format!(
        "chars={} lines={} hash={}",
        text.chars().count(),
        text.lines().count(),
        hash_hex
    )
}

fn summarize_kernel_event(kernel_event: &ioi_types::app::KernelEvent) -> String {
    use ioi_types::app::KernelEvent as Ev;

    match kernel_event {
        Ev::AgentThought { session_id, token } => format!(
            "AgentThought session={} {}",
            prefix_hex_4(session_id),
            text_fingerprint(token)
        ),
        Ev::AgentStep(step) => format!(
            "AgentStep session={} step_index={} visual_hash={} raw_output_{} full_prompt_{}",
            prefix_hex_4(&step.session_id),
            step.step_index,
            hex::encode(&step.visual_hash[..4]),
            text_fingerprint(&step.raw_output),
            text_fingerprint(&step.full_prompt)
        ),
        Ev::BlockCommitted { height, tx_count } => {
            format!("BlockCommitted height={} tx_count={}", height, tx_count)
        }
        Ev::GhostInput {
            device,
            description,
        } => format!(
            "GhostInput device={} {}",
            device,
            text_fingerprint(description)
        ),
        Ev::FirewallInterception {
            verdict,
            target,
            request_hash,
            session_id,
        } => format!(
            "FirewallInterception session={} verdict={} target={} request_hash={}",
            session_id
                .as_ref()
                .map(prefix_hex_4)
                .unwrap_or_else(|| "none".to_string()),
            verdict,
            target,
            hex::encode(request_hash)
        ),
        Ev::AgentActionResult {
            session_id,
            step_index,
            tool_name,
            output,
            agent_status,
        } => format!(
            "AgentActionResult session={} step_index={} tool_name={} agent_status={} output_{}",
            prefix_hex_4(session_id),
            step_index,
            tool_name,
            agent_status,
            text_fingerprint(output)
        ),
        Ev::AgentSpawn {
            parent_session_id,
            new_session_id,
            name,
            role,
            budget,
            goal,
        } => format!(
            "AgentSpawn parent_session={} new_session={} name={} role={} budget={} goal_{}",
            prefix_hex_4(parent_session_id),
            prefix_hex_4(new_session_id),
            name,
            role,
            budget,
            text_fingerprint(goal)
        ),
        Ev::ProcessActivity {
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
        } => format!(
            "ProcessActivity session={} step_index={} tool_name={} stream_id={} channel={} seq={} is_final={} exit_code={} command_preview_{} chunk_{}",
            prefix_hex_4(session_id),
            step_index,
            tool_name,
            stream_id,
            channel,
            seq,
            is_final,
            exit_code.map(|v| v.to_string()).unwrap_or_else(|| "none".to_string()),
            text_fingerprint(command_preview),
            text_fingerprint(chunk)
        ),
        Ev::RoutingReceipt(receipt) => format!(
            "RoutingReceipt session={} step_index={} tool_name={} policy_decision={} success={} action_json_{}",
            prefix_hex_4(&receipt.session_id),
            receipt.step_index,
            receipt.tool_name,
            receipt.policy_decision,
            receipt.post_state.success,
            text_fingerprint(&receipt.action_json)
        ),
        Ev::SystemUpdate { component, status } => format!(
            "SystemUpdate component={} status_{}",
            component,
            text_fingerprint(status)
        ),
        Ev::PiiDecisionReceipt(receipt) => format!(
            "PiiDecisionReceipt session={} target={} risk_surface={} decision={:?} decision_hash={} span_count={} ambiguous={}",
            receipt
                .session_id
                .as_ref()
                .map(prefix_hex_4)
                .unwrap_or_else(|| "none".to_string()),
            receipt.target,
            receipt.risk_surface,
            receipt.decision,
            hex::encode(receipt.decision_hash),
            receipt.span_count,
            receipt.ambiguous
        ),
        Ev::PiiReviewRequested {
            decision_hash,
            summary,
            session_id,
            ..
        } => format!(
            "PiiReviewRequested session={} decision_hash={} target={} span_summary_{}",
            session_id
                .as_ref()
                .map(prefix_hex_4)
                .unwrap_or_else(|| "none".to_string()),
            hex::encode(decision_hash),
            summary.target_label,
            text_fingerprint(&summary.span_summary)
        ),
        Ev::IntentResolutionReceipt(receipt) => format!(
            "IntentResolutionReceipt session={} intent_id={} scope={:?} band={:?} score={:.3} constrained={} receipt_hash={}",
            receipt
                .session_id
                .as_ref()
                .map(prefix_hex_4)
                .unwrap_or_else(|| "none".to_string()),
            receipt.intent_id,
            receipt.scope,
            receipt.band,
            receipt.score,
            receipt.constrained,
            hex::encode(receipt.receipt_hash)
        ),
    }
}

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
        ioi_types::app::KernelEvent::PiiDecisionReceipt(receipt) => {
            Some(ChainEventEnum::Action(ioi_ipc::public::ActionIntercepted {
                session_id: receipt.session_id.map(hex::encode).unwrap_or_default(),
                target: receipt.target,
                verdict: "PII_DECISION".to_string(),
                reason: format!(
                    "{}:{}",
                    receipt.risk_surface,
                    hex::encode(receipt.decision_hash)
                ),
            }))
        }
        ioi_types::app::KernelEvent::PiiReviewRequested {
            decision_hash,
            material: _,
            summary,
            session_id,
            ..
        } => Some(ChainEventEnum::Action(ioi_ipc::public::ActionIntercepted {
            session_id: session_id.map(hex::encode).unwrap_or_default(),
            target: summary.target_label,
            verdict: "PII_REVIEW_REQUESTED".to_string(),
            reason: hex::encode(decision_hash),
        })),
        ioi_types::app::KernelEvent::IntentResolutionReceipt(receipt) => {
            Some(ChainEventEnum::System(ioi_ipc::public::SystemUpdate {
                component: "IntentResolver".to_string(),
                status: format!(
                    "intent_id={} band={:?} score={:.3} constrained={} hash={}",
                    receipt.intent_id,
                    receipt.band,
                    receipt.score,
                    receipt.constrained,
                    hex::encode(receipt.receipt_hash)
                ),
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
                        if should_log_raw_kernel_event_payloads() {
                            tracing::info!(
                                target: "rpc",
                                "PublicAPI processing KernelEvent: {:?}",
                                kernel_event
                            );
                        } else {
                            tracing::info!(
                                target: "rpc",
                                "PublicAPI processing KernelEvent: {}",
                                summarize_kernel_event(&kernel_event)
                            );
                        }

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
