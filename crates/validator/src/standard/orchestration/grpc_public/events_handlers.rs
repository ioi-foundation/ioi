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
            error_class,
            agent_status,
        } => format!(
            "AgentActionResult session={} step_index={} tool_name={} agent_status={} error_class={} output_{}",
            prefix_hex_4(session_id),
            step_index,
            tool_name,
            agent_status,
            error_class.as_deref().unwrap_or("none"),
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
            ioi_types::app::WorkloadReceipt::FsWrite(fs) => format!(
                "WorkloadReceipt(FsWrite) session={} step_index={} workload_id={} tool_name={} operation={} target_path_{} has_destination_path={} destination_path_{} has_bytes_written={} bytes_written={} success={} error_class={}",
                prefix_hex_4(&receipt.session_id),
                receipt.step_index,
                receipt.workload_id,
                fs.tool_name,
                fs.operation,
                text_fingerprint(&fs.target_path),
                fs.destination_path.is_some(),
                text_fingerprint(fs.destination_path.as_deref().unwrap_or("")),
                fs.bytes_written.is_some(),
                fs.bytes_written
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "none".to_string()),
                fs.success,
                fs.error_class.as_deref().unwrap_or("none")
            ),
            ioi_types::app::WorkloadReceipt::NetFetch(net) => format!(
                "WorkloadReceipt(NetFetch) session={} step_index={} workload_id={} method={} has_status_code={} status_code={} truncated={} success={} requested_url_{} has_final_url={} final_url_{} error_class={}",
                prefix_hex_4(&receipt.session_id),
                receipt.step_index,
                receipt.workload_id,
                net.method,
                net.status_code.is_some(),
                net.status_code
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "none".to_string()),
                net.truncated,
                net.success,
                text_fingerprint(&net.requested_url),
                net.final_url.is_some(),
                text_fingerprint(net.final_url.as_deref().unwrap_or("")),
                net.error_class.as_deref().unwrap_or("none")
            ),
            ioi_types::app::WorkloadReceipt::WebRetrieve(web) => format!(
                "WorkloadReceipt(WebRetrieve) session={} step_index={} workload_id={} tool_name={} backend={} has_query={} query_{} has_url={} url_{} sources_count={} documents_count={} success={} error_class={}",
                prefix_hex_4(&receipt.session_id),
                receipt.step_index,
                receipt.workload_id,
                web.tool_name,
                web.backend,
                web.query.is_some(),
                text_fingerprint(web.query.as_deref().unwrap_or("")),
                web.url.is_some(),
                text_fingerprint(web.url.as_deref().unwrap_or("")),
                web.sources_count,
                web.documents_count,
                web.success,
                web.error_class.as_deref().unwrap_or("none")
            ),
            ioi_types::app::WorkloadReceipt::ScsRetrieve(scs) => format!(
                "WorkloadReceipt(ScsRetrieve) session={} step_index={} workload_id={} tool_name={} backend={} query_hash={} index_root={} k={} ef_search={} candidate_limit={} candidate_count_total={} candidate_count_reranked={} candidate_truncated={} metric={} embedding_normalized={} success={} error_class={}",
                prefix_hex_4(&receipt.session_id),
                receipt.step_index,
                receipt.workload_id,
                scs.tool_name,
                scs.backend,
                scs.query_hash,
                scs.index_root,
                scs.k,
                scs.ef_search,
                scs.candidate_limit,
                scs.candidate_count_total,
                scs.candidate_count_reranked,
                scs.candidate_truncated,
                scs.distance_metric,
                scs.embedding_normalized,
                scs.success,
                scs.error_class.as_deref().unwrap_or("none")
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
        Ev::ExecutionContractReceipt(receipt) => format!(
            "ExecutionContractReceipt session={} step_index={} intent_id={} stage={} key={} satisfied={} evidence_commit_hash={}",
            prefix_hex_4(&receipt.session_id),
            receipt.step_index,
            receipt.intent_id,
            receipt.stage,
            receipt.key,
            receipt.satisfied,
            receipt.evidence_commit_hash
        ),
        Ev::PlanReceipt(receipt) => format!(
            "PlanReceipt session={} selected_route={} plan_hash={} worker_count={} policy_bindings={}",
            receipt
                .session_id
                .as_ref()
                .map(prefix_hex_4)
                .unwrap_or_else(|| "none".to_string()),
            receipt.selected_route,
            hex::encode(receipt.plan_hash),
            receipt.worker_graph.len(),
            receipt.policy_bindings.len()
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
            error_class,
            agent_status,
        } => Some(ChainEventEnum::ActionResult(
            ioi_ipc::public::AgentActionResult {
                session_id: hex::encode(session_id),
                step_index,
                tool_name,
                output,
                agent_status,
                error_class: error_class.clone().unwrap_or_default(),
                has_error_class: error_class.is_some(),
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
            ioi_types::app::WorkloadReceipt::FsWrite(fs) => Some(ChainEventEnum::WorkloadReceipt(
                ioi_ipc::public::WorkloadReceipt {
                    session_id: hex::encode(receipt.session_id),
                    step_index: receipt.step_index,
                    workload_id: receipt.workload_id,
                    timestamp_ms: receipt.timestamp_ms,
                    receipt: Some(ioi_ipc::public::workload_receipt::Receipt::FsWrite(
                        ioi_ipc::public::WorkloadFsWriteReceipt {
                            tool_name: fs.tool_name,
                            operation: fs.operation,
                            target_path: fs.target_path,
                            destination_path: fs.destination_path.clone().unwrap_or_default(),
                            has_destination_path: fs.destination_path.is_some(),
                            bytes_written: fs.bytes_written.unwrap_or_default(),
                            has_bytes_written: fs.bytes_written.is_some(),
                            success: fs.success,
                            error_class: fs.error_class.clone().unwrap_or_default(),
                            has_error_class: fs.error_class.is_some(),
                        },
                    )),
                },
            )),
            ioi_types::app::WorkloadReceipt::NetFetch(net) => Some(
                ChainEventEnum::WorkloadReceipt(ioi_ipc::public::WorkloadReceipt {
                    session_id: hex::encode(receipt.session_id),
                    step_index: receipt.step_index,
                    workload_id: receipt.workload_id,
                    timestamp_ms: receipt.timestamp_ms,
                    receipt: Some(ioi_ipc::public::workload_receipt::Receipt::NetFetch(
                        ioi_ipc::public::WorkloadNetFetchReceipt {
                            tool_name: net.tool_name,
                            method: net.method,
                            requested_url: net.requested_url,
                            final_url: net.final_url.clone().unwrap_or_default(),
                            has_final_url: net.final_url.is_some(),
                            status_code: net.status_code.unwrap_or_default(),
                            has_status_code: net.status_code.is_some(),
                            content_type: net.content_type.clone().unwrap_or_default(),
                            has_content_type: net.content_type.is_some(),
                            max_chars: net.max_chars,
                            max_bytes: net.max_bytes,
                            bytes_read: net.bytes_read,
                            truncated: net.truncated,
                            timeout_ms: net.timeout_ms,
                            success: net.success,
                            error_class: net.error_class.clone().unwrap_or_default(),
                            has_error_class: net.error_class.is_some(),
                        },
                    )),
                }),
            ),
            ioi_types::app::WorkloadReceipt::WebRetrieve(web) => Some(
                ChainEventEnum::WorkloadReceipt(ioi_ipc::public::WorkloadReceipt {
                    session_id: hex::encode(receipt.session_id),
                    step_index: receipt.step_index,
                    workload_id: receipt.workload_id,
                    timestamp_ms: receipt.timestamp_ms,
                    receipt: Some(ioi_ipc::public::workload_receipt::Receipt::WebRetrieve(
                        ioi_ipc::public::WorkloadWebRetrieveReceipt {
                            tool_name: web.tool_name,
                            backend: web.backend,
                            query: web.query.clone().unwrap_or_default(),
                            has_query: web.query.is_some(),
                            url: web.url.clone().unwrap_or_default(),
                            has_url: web.url.is_some(),
                            limit: web.limit.unwrap_or_default(),
                            has_limit: web.limit.is_some(),
                            max_chars: web.max_chars.unwrap_or_default(),
                            has_max_chars: web.max_chars.is_some(),
                            sources_count: web.sources_count,
                            documents_count: web.documents_count,
                            success: web.success,
                            error_class: web.error_class.clone().unwrap_or_default(),
                            has_error_class: web.error_class.is_some(),
                        },
                    )),
                }),
            ),
            ioi_types::app::WorkloadReceipt::ScsRetrieve(scs) => Some(
                ChainEventEnum::WorkloadReceipt(ioi_ipc::public::WorkloadReceipt {
                    session_id: hex::encode(receipt.session_id),
                    step_index: receipt.step_index,
                    workload_id: receipt.workload_id,
                    timestamp_ms: receipt.timestamp_ms,
                    receipt: Some(ioi_ipc::public::workload_receipt::Receipt::ScsRetrieve(
                        ioi_ipc::public::WorkloadScsRetrieveReceipt {
                            tool_name: scs.tool_name,
                            backend: scs.backend,
                            query_hash: scs.query_hash,
                            index_root: scs.index_root,
                            k: scs.k,
                            ef_search: scs.ef_search,
                            candidate_limit: scs.candidate_limit,
                            candidate_count_total: scs.candidate_count_total,
                            candidate_count_reranked: scs.candidate_count_reranked,
                            candidate_truncated: scs.candidate_truncated,
                            distance_metric: scs.distance_metric,
                            embedding_normalized: scs.embedding_normalized,
                            proof_ref: scs.proof_ref.clone().unwrap_or_default(),
                            has_proof_ref: scs.proof_ref.is_some(),
                            proof_hash: scs.proof_hash.clone().unwrap_or_default(),
                            has_proof_hash: scs.proof_hash.is_some(),
                            certificate_mode: scs.certificate_mode.clone().unwrap_or_default(),
                            has_certificate_mode: scs.certificate_mode.is_some(),
                            success: scs.success,
                            error_class: scs.error_class.clone().unwrap_or_default(),
                            has_error_class: scs.error_class.is_some(),
                        },
                    )),
                }),
            ),
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
        ioi_types::app::KernelEvent::ExecutionContractReceipt(receipt) => {
            Some(ChainEventEnum::System(ioi_ipc::public::SystemUpdate {
                component: "ExecutionContract".to_string(),
                status: format!(
                    "intent_id={} stage={} key={} satisfied={} evidence_commit_hash={}",
                    receipt.intent_id,
                    receipt.stage,
                    receipt.key,
                    receipt.satisfied,
                    receipt.evidence_commit_hash
                ),
            }))
        }
        ioi_types::app::KernelEvent::PlanReceipt(receipt) => {
            Some(ChainEventEnum::System(ioi_ipc::public::SystemUpdate {
                component: "Planner".to_string(),
                status: format!(
                    "selected_route={} plan_hash={} worker_count={} policy_bindings={}",
                    receipt.selected_route,
                    hex::encode(receipt.plan_hash),
                    receipt.worker_graph.len(),
                    receipt.policy_bindings.len()
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
        WorkloadFsWriteReceipt, WorkloadNetFetchReceipt, WorkloadReceipt, WorkloadReceiptEvent,
        WorkloadScsRetrieveReceipt, WorkloadWebRetrieveReceipt,
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

        let receipt = KernelEvent::WorkloadReceipt(WorkloadReceiptEvent {
            session_id: [7u8; 32],
            step_index: 42,
            workload_id: "wid-fs".to_string(),
            timestamp_ms: 124,
            receipt: WorkloadReceipt::FsWrite(WorkloadFsWriteReceipt {
                tool_name: "filesystem__write_file".to_string(),
                operation: "write_file".to_string(),
                target_path: "/tmp/file.txt".to_string(),
                destination_path: None,
                bytes_written: Some(17),
                success: true,
                error_class: None,
            }),
        });
        let mapped = map_kernel_event(receipt, &keypair, signer_pk.as_str())
            .expect("fs-write workload receipt should map");
        match mapped {
            ChainEventEnum::WorkloadReceipt(payload) => match payload.receipt {
                Some(ioi_ipc::public::workload_receipt::Receipt::FsWrite(fs)) => {
                    assert_eq!(fs.tool_name, "filesystem__write_file");
                    assert_eq!(fs.operation, "write_file");
                    assert_eq!(fs.target_path, "/tmp/file.txt");
                    assert!(!fs.has_destination_path);
                    assert_eq!(fs.destination_path, "");
                    assert!(fs.has_bytes_written);
                    assert_eq!(fs.bytes_written, 17);
                    assert!(fs.success);
                    assert!(!fs.has_error_class);
                    assert_eq!(fs.error_class, "");
                }
                other => panic!("expected fs_write receipt, got: {:?}", other),
            },
            other => panic!("expected workload receipt chain event, got: {:?}", other),
        }

        let receipt = KernelEvent::WorkloadReceipt(WorkloadReceiptEvent {
            session_id: [7u8; 32],
            step_index: 42,
            workload_id: "wid-net".to_string(),
            timestamp_ms: 125,
            receipt: WorkloadReceipt::NetFetch(WorkloadNetFetchReceipt {
                tool_name: "net__fetch".to_string(),
                method: "GET".to_string(),
                requested_url: "https://example.com/".to_string(),
                final_url: None,
                status_code: Some(404),
                content_type: Some("text/html".to_string()),
                max_chars: 123,
                max_bytes: 456,
                bytes_read: 111,
                truncated: false,
                timeout_ms: 30_000,
                success: true,
                error_class: None,
            }),
        });
        let mapped = map_kernel_event(receipt, &keypair, signer_pk.as_str())
            .expect("net-fetch workload receipt should map");
        match mapped {
            ChainEventEnum::WorkloadReceipt(payload) => match payload.receipt {
                Some(ioi_ipc::public::workload_receipt::Receipt::NetFetch(net)) => {
                    assert_eq!(net.tool_name, "net__fetch");
                    assert_eq!(net.method, "GET");
                    assert_eq!(net.requested_url, "https://example.com/");
                    assert!(!net.has_final_url);
                    assert_eq!(net.final_url, "");
                    assert!(net.has_status_code);
                    assert_eq!(net.status_code, 404);
                    assert!(net.has_content_type);
                    assert_eq!(net.content_type, "text/html");
                    assert_eq!(net.max_chars, 123);
                    assert_eq!(net.max_bytes, 456);
                    assert_eq!(net.bytes_read, 111);
                    assert!(!net.truncated);
                    assert_eq!(net.timeout_ms, 30_000);
                    assert!(net.success);
                    assert!(!net.has_error_class);
                }
                other => panic!("expected net_fetch receipt, got: {:?}", other),
            },
            other => panic!("expected workload receipt chain event, got: {:?}", other),
        }

        let receipt = KernelEvent::WorkloadReceipt(WorkloadReceiptEvent {
            session_id: [7u8; 32],
            step_index: 42,
            workload_id: "wid-web".to_string(),
            timestamp_ms: 126,
            receipt: WorkloadReceipt::WebRetrieve(WorkloadWebRetrieveReceipt {
                tool_name: "web__search".to_string(),
                backend: "edge:ddg".to_string(),
                query: Some("query".to_string()),
                url: None,
                limit: Some(5),
                max_chars: None,
                sources_count: 2,
                documents_count: 0,
                success: true,
                error_class: None,
            }),
        });
        let mapped = map_kernel_event(receipt, &keypair, signer_pk.as_str())
            .expect("web-retrieve workload receipt should map");
        match mapped {
            ChainEventEnum::WorkloadReceipt(payload) => match payload.receipt {
                Some(ioi_ipc::public::workload_receipt::Receipt::WebRetrieve(web)) => {
                    assert_eq!(web.tool_name, "web__search");
                    assert_eq!(web.backend, "edge:ddg");
                    assert!(web.has_query);
                    assert_eq!(web.query, "query");
                    assert!(!web.has_url);
                    assert_eq!(web.url, "");
                    assert!(web.has_limit);
                    assert_eq!(web.limit, 5);
                    assert!(!web.has_max_chars);
                    assert_eq!(web.max_chars, 0);
                    assert_eq!(web.sources_count, 2);
                    assert_eq!(web.documents_count, 0);
                    assert!(web.success);
                    assert!(!web.has_error_class);
                    assert_eq!(web.error_class, "");
                }
                other => panic!("expected web_retrieve receipt, got: {:?}", other),
            },
            other => panic!("expected workload receipt chain event, got: {:?}", other),
        }

        let receipt = KernelEvent::WorkloadReceipt(WorkloadReceiptEvent {
            session_id: [7u8; 32],
            step_index: 42,
            workload_id: "wid-scs".to_string(),
            timestamp_ms: 127,
            receipt: WorkloadReceipt::ScsRetrieve(WorkloadScsRetrieveReceipt {
                tool_name: "memory__search".to_string(),
                backend: "scs:mhnsw".to_string(),
                query_hash: "abcd".to_string(),
                index_root: "beef".to_string(),
                k: 5,
                ef_search: 64,
                candidate_limit: 32,
                candidate_count_total: 18,
                candidate_count_reranked: 18,
                candidate_truncated: false,
                distance_metric: "cosine_distance".to_string(),
                embedding_normalized: false,
                proof_ref: Some("scs://proof/123".to_string()),
                proof_hash: Some("deadbeef".to_string()),
                certificate_mode: Some("single_level_lb".to_string()),
                success: true,
                error_class: None,
            }),
        });
        let mapped = map_kernel_event(receipt, &keypair, signer_pk.as_str())
            .expect("scs-retrieve workload receipt should map");
        match mapped {
            ChainEventEnum::WorkloadReceipt(payload) => match payload.receipt {
                Some(ioi_ipc::public::workload_receipt::Receipt::ScsRetrieve(scs)) => {
                    assert_eq!(scs.tool_name, "memory__search");
                    assert_eq!(scs.backend, "scs:mhnsw");
                    assert_eq!(scs.query_hash, "abcd");
                    assert_eq!(scs.index_root, "beef");
                    assert_eq!(scs.k, 5);
                    assert_eq!(scs.ef_search, 64);
                    assert_eq!(scs.candidate_limit, 32);
                    assert_eq!(scs.candidate_count_total, 18);
                    assert_eq!(scs.candidate_count_reranked, 18);
                    assert!(!scs.candidate_truncated);
                    assert_eq!(scs.distance_metric, "cosine_distance");
                    assert!(!scs.embedding_normalized);
                    assert!(scs.has_proof_ref);
                    assert_eq!(scs.proof_ref, "scs://proof/123");
                    assert!(scs.has_proof_hash);
                    assert_eq!(scs.proof_hash, "deadbeef");
                    assert!(scs.has_certificate_mode);
                    assert_eq!(scs.certificate_mode, "single_level_lb");
                    assert!(scs.success);
                    assert!(!scs.has_error_class);
                }
                other => panic!("expected scs_retrieve receipt, got: {:?}", other),
            },
            other => panic!("expected workload receipt chain event, got: {:?}", other),
        }
    }
}
