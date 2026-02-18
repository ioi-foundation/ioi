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
        Ev::WorkloadActivity(activity) => match &activity.kind {
            ioi_types::app::WorkloadActivityKind::Lifecycle { phase, exit_code } => format!(
                "WorkloadActivity(Lifecycle) session={} step_index={} workload_id={} phase={} exit_code={}",
                prefix_hex_4(&activity.session_id),
                activity.step_index,
                activity.workload_id,
                phase,
                exit_code
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "none".to_string())
            ),
            ioi_types::app::WorkloadActivityKind::Stdio {
                stream,
                chunk,
                seq,
                is_final,
                exit_code,
            } => format!(
                "WorkloadActivity(Stdio) session={} step_index={} workload_id={} stream={} seq={} is_final={} exit_code={} chunk_{}",
                prefix_hex_4(&activity.session_id),
                activity.step_index,
                activity.workload_id,
                stream,
                seq,
                is_final,
                exit_code
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "none".to_string()),
                text_fingerprint(chunk)
            ),
        },
        Ev::WorkloadReceipt(receipt) => match &receipt.receipt {
            ioi_types::app::WorkloadReceipt::Exec(exec) => format!(
                "WorkloadReceipt(Exec) session={} step_index={} workload_id={} tool_name={} command_preview_{} success={} exit_code={} error_class={}",
                prefix_hex_4(&receipt.session_id),
                receipt.step_index,
                receipt.workload_id,
                exec.tool_name,
                text_fingerprint(&exec.command_preview),
                exec.success,
                exec.exit_code
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "none".to_string()),
                exec.error_class.as_deref().unwrap_or("none")
            ),
        },
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
        ioi_types::app::KernelEvent::WorkloadActivity(activity) => {
            let kind = match activity.kind {
                ioi_types::app::WorkloadActivityKind::Lifecycle { phase, exit_code } => {
                    Some(ioi_ipc::public::workload_activity::Kind::Lifecycle(
                        ioi_ipc::public::WorkloadLifecycle {
                            phase,
                            exit_code: exit_code.unwrap_or_default(),
                            has_exit_code: exit_code.is_some(),
                        },
                    ))
                }
                ioi_types::app::WorkloadActivityKind::Stdio {
                    stream,
                    chunk,
                    seq,
                    is_final,
                    exit_code,
                } => Some(ioi_ipc::public::workload_activity::Kind::Stdio(
                    ioi_ipc::public::WorkloadStdio {
                        stream,
                        chunk,
                        seq,
                        is_final,
                        exit_code: exit_code.unwrap_or_default(),
                        has_exit_code: exit_code.is_some(),
                    },
                )),
            };

            Some(ChainEventEnum::WorkloadActivity(
                ioi_ipc::public::WorkloadActivity {
                    session_id: hex::encode(activity.session_id),
                    step_index: activity.step_index,
                    workload_id: activity.workload_id,
                    timestamp_ms: activity.timestamp_ms,
                    kind,
                },
            ))
        }
        ioi_types::app::KernelEvent::WorkloadReceipt(receipt) => match receipt.receipt {
            ioi_types::app::WorkloadReceipt::Exec(exec) => Some(ChainEventEnum::WorkloadReceipt(
                ioi_ipc::public::WorkloadReceipt {
                    session_id: hex::encode(receipt.session_id),
                    step_index: receipt.step_index,
                    workload_id: receipt.workload_id,
                    timestamp_ms: receipt.timestamp_ms,
                    receipt: Some(ioi_ipc::public::workload_receipt::Receipt::Exec(
                        ioi_ipc::public::WorkloadExecReceipt {
                            tool_name: exec.tool_name,
                            command: exec.command,
                            args: exec.args,
                            cwd: exec.cwd,
                            detach: exec.detach,
                            timeout_ms: exec.timeout_ms,
                            success: exec.success,
                            exit_code: exec.exit_code.unwrap_or_default(),
                            has_exit_code: exec.exit_code.is_some(),
                            error_class: exec.error_class.clone().unwrap_or_default(),
                            has_error_class: exec.error_class.is_some(),
                            command_preview: exec.command_preview,
                        },
                    )),
                },
            )),
        },
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

#[cfg(test)]
mod workload_event_mapping_tests {
    use super::map_kernel_event;
    use ioi_ipc::public::chain_event::Event as ChainEventEnum;
    use ioi_types::app::{
        KernelEvent, WorkloadActivityEvent, WorkloadActivityKind, WorkloadExecReceipt,
        WorkloadReceipt, WorkloadReceiptEvent,
    };

    #[test]
    fn workload_activity_and_receipt_map_to_chain_event_payloads() {
        let keypair = libp2p::identity::Keypair::generate_ed25519();
        let signer_pk = hex::encode(keypair.public().encode_protobuf());

        let activity = KernelEvent::WorkloadActivity(WorkloadActivityEvent {
            session_id: [7u8; 32],
            step_index: 42,
            workload_id: "wid".to_string(),
            timestamp_ms: 123,
            kind: WorkloadActivityKind::Lifecycle {
                phase: "started".to_string(),
                exit_code: None,
            },
        });
        let mapped = map_kernel_event(activity, &keypair, signer_pk.as_str())
            .expect("workload activity should map");
        match mapped {
            ChainEventEnum::WorkloadActivity(payload) => {
                assert_eq!(payload.session_id, hex::encode([7u8; 32]));
                assert_eq!(payload.step_index, 42);
                assert_eq!(payload.workload_id, "wid");
                assert_eq!(payload.timestamp_ms, 123);
                match payload.kind {
                    Some(ioi_ipc::public::workload_activity::Kind::Lifecycle(lifecycle)) => {
                        assert_eq!(lifecycle.phase, "started");
                        assert!(!lifecycle.has_exit_code);
                    }
                    other => panic!("expected lifecycle kind, got: {:?}", other),
                }
            }
            other => panic!("expected workload activity chain event, got: {:?}", other),
        }

        let receipt = KernelEvent::WorkloadReceipt(WorkloadReceiptEvent {
            session_id: [7u8; 32],
            step_index: 42,
            workload_id: "wid".to_string(),
            timestamp_ms: 124,
            receipt: WorkloadReceipt::Exec(WorkloadExecReceipt {
                tool_name: "sys__exec".to_string(),
                command: "echo".to_string(),
                args: vec!["hi".to_string()],
                cwd: "/tmp".to_string(),
                detach: false,
                timeout_ms: 120_000,
                success: true,
                exit_code: Some(0),
                error_class: None,
                command_preview: "echo hi".to_string(),
            }),
        });
        let mapped = map_kernel_event(receipt, &keypair, signer_pk.as_str())
            .expect("workload receipt should map");
        match mapped {
            ChainEventEnum::WorkloadReceipt(payload) => match payload.receipt {
                Some(ioi_ipc::public::workload_receipt::Receipt::Exec(exec)) => {
                    assert_eq!(exec.tool_name, "sys__exec");
                    assert_eq!(exec.command, "echo");
                    assert_eq!(exec.args, vec!["hi".to_string()]);
                    assert_eq!(exec.cwd, "/tmp");
                    assert!(!exec.detach);
                    assert_eq!(exec.timeout_ms, 120_000);
                    assert!(exec.success);
                    assert!(exec.has_exit_code);
                    assert_eq!(exec.exit_code, 0);
                    assert_eq!(exec.command_preview, "echo hi");
                    assert!(!exec.has_error_class);
                }
                other => panic!("expected exec receipt, got: {:?}", other),
            },
            other => panic!("expected workload receipt chain event, got: {:?}", other),
        }
    }
}
