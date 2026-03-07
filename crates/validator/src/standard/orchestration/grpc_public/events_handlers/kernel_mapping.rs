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
