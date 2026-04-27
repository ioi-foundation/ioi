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
            ioi_types::app::WorkloadReceipt::MemoryRetrieve(scs) => Some(
                ChainEventEnum::WorkloadReceipt(ioi_ipc::public::WorkloadReceipt {
                    session_id: hex::encode(receipt.session_id),
                    step_index: receipt.step_index,
                    workload_id: receipt.workload_id,
                    timestamp_ms: receipt.timestamp_ms,
                    receipt: Some(ioi_ipc::public::workload_receipt::Receipt::MemoryRetrieve(
                        ioi_ipc::public::WorkloadMemoryRetrieveReceipt {
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
            ioi_types::app::WorkloadReceipt::Inference(inference) => Some(
                ChainEventEnum::WorkloadReceipt(ioi_ipc::public::WorkloadReceipt {
                    session_id: hex::encode(receipt.session_id),
                    step_index: receipt.step_index,
                    workload_id: receipt.workload_id,
                    timestamp_ms: receipt.timestamp_ms,
                    receipt: Some(ioi_ipc::public::workload_receipt::Receipt::Inference(
                        ioi_ipc::public::WorkloadInferenceReceipt {
                            tool_name: inference.tool_name,
                            operation: inference.operation.as_label().to_string(),
                            backend: inference.backend,
                            model_id: inference.model_id,
                            model_family: inference.model_family.clone().unwrap_or_default(),
                            has_model_family: inference.model_family.is_some(),
                            prompt_token_count: inference.prompt_token_count.unwrap_or_default(),
                            has_prompt_token_count: inference.prompt_token_count.is_some(),
                            completion_token_count: inference
                                .completion_token_count
                                .unwrap_or_default(),
                            has_completion_token_count: inference.completion_token_count.is_some(),
                            total_token_count: inference.total_token_count.unwrap_or_default(),
                            has_total_token_count: inference.total_token_count.is_some(),
                            vector_dimensions: inference.vector_dimensions.unwrap_or_default(),
                            has_vector_dimensions: inference.vector_dimensions.is_some(),
                            result_item_count: inference.result_item_count,
                            candidate_count_total: inference
                                .candidate_count_total
                                .unwrap_or_default(),
                            has_candidate_count_total: inference.candidate_count_total.is_some(),
                            candidate_count_scored: inference
                                .candidate_count_scored
                                .unwrap_or_default(),
                            has_candidate_count_scored: inference.candidate_count_scored.is_some(),
                            streaming: inference.streaming,
                            latency_ms: inference.latency_ms.unwrap_or_default(),
                            has_latency_ms: inference.latency_ms.is_some(),
                            success: inference.success,
                            error_class: inference.error_class.clone().unwrap_or_default(),
                            has_error_class: inference.error_class.is_some(),
                        },
                    )),
                }),
            ),
            ioi_types::app::WorkloadReceipt::Media(media) => Some(ChainEventEnum::WorkloadReceipt(
                ioi_ipc::public::WorkloadReceipt {
                    session_id: hex::encode(receipt.session_id),
                    step_index: receipt.step_index,
                    workload_id: receipt.workload_id,
                    timestamp_ms: receipt.timestamp_ms,
                    receipt: Some(ioi_ipc::public::workload_receipt::Receipt::Media(
                        ioi_ipc::public::WorkloadMediaReceipt {
                            tool_name: media.tool_name,
                            operation: media.operation.as_label().to_string(),
                            backend: media.backend,
                            model_id: media.model_id.clone().unwrap_or_default(),
                            has_model_id: media.model_id.is_some(),
                            source_uri: media.source_uri.clone().unwrap_or_default(),
                            has_source_uri: media.source_uri.is_some(),
                            input_artifact_count: media.input_artifact_count,
                            output_artifact_count: media.output_artifact_count,
                            output_bytes: media.output_bytes.unwrap_or_default(),
                            has_output_bytes: media.output_bytes.is_some(),
                            duration_ms: media.duration_ms.unwrap_or_default(),
                            has_duration_ms: media.duration_ms.is_some(),
                            output_mime_types: media.output_mime_types,
                            success: media.success,
                            error_class: media.error_class.clone().unwrap_or_default(),
                            has_error_class: media.error_class.is_some(),
                        },
                    )),
                },
            )),
            ioi_types::app::WorkloadReceipt::ModelLifecycle(lifecycle) => Some(
                ChainEventEnum::WorkloadReceipt(ioi_ipc::public::WorkloadReceipt {
                    session_id: hex::encode(receipt.session_id),
                    step_index: receipt.step_index,
                    workload_id: receipt.workload_id,
                    timestamp_ms: receipt.timestamp_ms,
                    receipt: Some(ioi_ipc::public::workload_receipt::Receipt::ModelLifecycle(
                        ioi_ipc::public::WorkloadModelLifecycleReceipt {
                            tool_name: lifecycle.tool_name,
                            operation: lifecycle.operation.as_label().to_string(),
                            subject_kind: lifecycle.subject_kind.as_label().to_string(),
                            subject_id: lifecycle.subject_id,
                            backend_id: lifecycle.backend_id.clone().unwrap_or_default(),
                            has_backend_id: lifecycle.backend_id.is_some(),
                            source_uri: lifecycle.source_uri.clone().unwrap_or_default(),
                            has_source_uri: lifecycle.source_uri.is_some(),
                            job_id: lifecycle.job_id.clone().unwrap_or_default(),
                            has_job_id: lifecycle.job_id.is_some(),
                            bytes_transferred: lifecycle.bytes_transferred.unwrap_or_default(),
                            has_bytes_transferred: lifecycle.bytes_transferred.is_some(),
                            hardware_profile: lifecycle
                                .hardware_profile
                                .clone()
                                .unwrap_or_default(),
                            has_hardware_profile: lifecycle.hardware_profile.is_some(),
                            success: lifecycle.success,
                            error_class: lifecycle.error_class.clone().unwrap_or_default(),
                            has_error_class: lifecycle.error_class.is_some(),
                        },
                    )),
                }),
            ),
            ioi_types::app::WorkloadReceipt::Worker(worker) => Some(
                ChainEventEnum::WorkloadReceipt(ioi_ipc::public::WorkloadReceipt {
                    session_id: hex::encode(receipt.session_id),
                    step_index: receipt.step_index,
                    workload_id: receipt.workload_id,
                    timestamp_ms: receipt.timestamp_ms,
                    receipt: Some(ioi_ipc::public::workload_receipt::Receipt::Worker(
                        ioi_ipc::public::WorkloadWorkerReceipt {
                            tool_name: worker.tool_name,
                            phase: worker.phase,
                            child_session_id: worker.child_session_id,
                            parent_session_id: worker.parent_session_id,
                            role: worker.role,
                            template_id: worker.template_id.clone().unwrap_or_default(),
                            has_template_id: worker.template_id.is_some(),
                            workflow_id: worker.workflow_id.clone().unwrap_or_default(),
                            has_workflow_id: worker.workflow_id.is_some(),
                            merge_mode: worker.merge_mode,
                            status: worker.status,
                            success: worker.success,
                            summary: worker.summary,
                            verification_hint: worker.verification_hint.clone().unwrap_or_default(),
                            has_verification_hint: worker.verification_hint.is_some(),
                            error_class: worker.error_class.clone().unwrap_or_default(),
                            has_error_class: worker.error_class.is_some(),
                            playbook_id: worker.playbook_id.clone().unwrap_or_default(),
                            has_playbook_id: worker.playbook_id.is_some(),
                        },
                    )),
                }),
            ),
            ioi_types::app::WorkloadReceipt::ParentPlaybook(playbook) => Some(
                ChainEventEnum::WorkloadReceipt(ioi_ipc::public::WorkloadReceipt {
                    session_id: hex::encode(receipt.session_id),
                    step_index: receipt.step_index,
                    workload_id: receipt.workload_id,
                    timestamp_ms: receipt.timestamp_ms,
                    receipt: Some(ioi_ipc::public::workload_receipt::Receipt::ParentPlaybook(
                        ioi_ipc::public::WorkloadParentPlaybookReceipt {
                            tool_name: playbook.tool_name,
                            phase: playbook.phase,
                            parent_session_id: playbook.parent_session_id,
                            playbook_id: playbook.playbook_id,
                            playbook_label: playbook.playbook_label,
                            status: playbook.status,
                            success: playbook.success,
                            step_id: playbook.step_id.clone().unwrap_or_default(),
                            has_step_id: playbook.step_id.is_some(),
                            step_label: playbook.step_label.clone().unwrap_or_default(),
                            has_step_label: playbook.step_label.is_some(),
                            child_session_id: playbook.child_session_id.clone().unwrap_or_default(),
                            has_child_session_id: playbook.child_session_id.is_some(),
                            template_id: playbook.template_id.clone().unwrap_or_default(),
                            has_template_id: playbook.template_id.is_some(),
                            workflow_id: playbook.workflow_id.clone().unwrap_or_default(),
                            has_workflow_id: playbook.workflow_id.is_some(),
                            route_family: playbook.route_family,
                            topology: playbook.topology,
                            verifier_state: playbook.verifier_state,
                            planner_authority: playbook.planner_authority,
                            verifier_role: playbook.verifier_role,
                            verifier_outcome: playbook.verifier_outcome,
                            selected_skills: playbook.selected_skills,
                            prep_summary: playbook.prep_summary.clone().unwrap_or_default(),
                            has_prep_summary: playbook.prep_summary.is_some(),
                            artifact_generation: playbook.artifact_generation.as_ref().map(
                                |summary| ioi_ipc::public::ArtifactGenerationSummary {
                                    status: summary.status.clone(),
                                    produced_file_count: summary.produced_file_count,
                                    verification_signal_status: summary
                                        .verification_signal_status
                                        .clone(),
                                    presentation_status: summary.presentation_status.clone(),
                                    notes: summary.notes.clone().unwrap_or_default(),
                                    has_notes: summary.notes.is_some(),
                                },
                            ),
                            has_artifact_generation: playbook.artifact_generation.is_some(),
                            computer_use_perception: playbook.computer_use_perception.as_ref().map(
                                |summary| ioi_ipc::public::ComputerUsePerceptionSummary {
                                    surface_status: summary.surface_status.clone(),
                                    ui_state: summary.ui_state.clone(),
                                    target: summary.target.clone().unwrap_or_default(),
                                    has_target: summary.target.is_some(),
                                    approval_risk: summary.approval_risk.clone(),
                                    next_action: summary.next_action.clone().unwrap_or_default(),
                                    has_next_action: summary.next_action.is_some(),
                                    notes: summary.notes.clone().unwrap_or_default(),
                                    has_notes: summary.notes.is_some(),
                                },
                            ),
                            has_computer_use_perception: playbook.computer_use_perception.is_some(),
                            research_scorecard: playbook.research_scorecard.as_ref().map(
                                |scorecard| ioi_ipc::public::ResearchVerificationScorecard {
                                    verdict: scorecard.verdict.clone(),
                                    source_count: scorecard.source_count,
                                    distinct_domain_count: scorecard.distinct_domain_count,
                                    source_count_floor_met: scorecard.source_count_floor_met,
                                    source_independence_floor_met: scorecard
                                        .source_independence_floor_met,
                                    freshness_status: scorecard.freshness_status.clone(),
                                    quote_grounding_status: scorecard
                                        .quote_grounding_status
                                        .clone(),
                                    notes: scorecard.notes.clone().unwrap_or_default(),
                                    has_notes: scorecard.notes.is_some(),
                                },
                            ),
                            has_research_scorecard: playbook.research_scorecard.is_some(),
                            artifact_quality: playbook.artifact_quality.as_ref().map(|scorecard| {
                                ioi_ipc::public::ArtifactQualityScorecard {
                                    verdict: scorecard.verdict.clone(),
                                    fidelity_status: scorecard.fidelity_status.clone(),
                                    presentation_status: scorecard.presentation_status.clone(),
                                    repair_status: scorecard.repair_status.clone(),
                                    notes: scorecard.notes.clone().unwrap_or_default(),
                                    has_notes: scorecard.notes.is_some(),
                                }
                            }),
                            has_artifact_quality: playbook.artifact_quality.is_some(),
                            computer_use_verification: playbook
                                .computer_use_verification
                                .as_ref()
                                .map(|scorecard| {
                                    ioi_ipc::public::ComputerUseVerificationScorecard {
                                        verdict: scorecard.verdict.clone(),
                                        postcondition_status: scorecard
                                            .postcondition_status
                                            .clone(),
                                        approval_state: scorecard.approval_state.clone(),
                                        recovery_status: scorecard.recovery_status.clone(),
                                        observed_postcondition: scorecard
                                            .observed_postcondition
                                            .clone()
                                            .unwrap_or_default(),
                                        has_observed_postcondition: scorecard
                                            .observed_postcondition
                                            .is_some(),
                                        notes: scorecard.notes.clone().unwrap_or_default(),
                                        has_notes: scorecard.notes.is_some(),
                                    }
                                }),
                            has_computer_use_verification: playbook
                                .computer_use_verification
                                .is_some(),
                            coding_scorecard: playbook.coding_scorecard.as_ref().map(|scorecard| {
                                ioi_ipc::public::CodingVerificationScorecard {
                                    verdict: scorecard.verdict.clone(),
                                    targeted_command_count: scorecard.targeted_command_count,
                                    targeted_pass_count: scorecard.targeted_pass_count,
                                    widening_status: scorecard.widening_status.clone(),
                                    regression_status: scorecard.regression_status.clone(),
                                    notes: scorecard.notes.clone().unwrap_or_default(),
                                    has_notes: scorecard.notes.is_some(),
                                }
                            }),
                            has_coding_scorecard: playbook.coding_scorecard.is_some(),
                            patch_synthesis: playbook.patch_synthesis.as_ref().map(|summary| {
                                ioi_ipc::public::PatchSynthesisSummary {
                                    status: summary.status.clone(),
                                    touched_file_count: summary.touched_file_count,
                                    verification_ready: summary.verification_ready,
                                    notes: summary.notes.clone().unwrap_or_default(),
                                    has_notes: summary.notes.is_some(),
                                }
                            }),
                            has_patch_synthesis: playbook.patch_synthesis.is_some(),
                            artifact_repair: playbook.artifact_repair.as_ref().map(|summary| {
                                ioi_ipc::public::ArtifactRepairSummary {
                                    status: summary.status.clone(),
                                    reason: summary.reason.clone().unwrap_or_default(),
                                    has_reason: summary.reason.is_some(),
                                    next_step: summary.next_step.clone().unwrap_or_default(),
                                    has_next_step: summary.next_step.is_some(),
                                }
                            }),
                            has_artifact_repair: playbook.artifact_repair.is_some(),
                            computer_use_recovery: playbook.computer_use_recovery.as_ref().map(
                                |summary| ioi_ipc::public::ComputerUseRecoverySummary {
                                    status: summary.status.clone(),
                                    reason: summary.reason.clone().unwrap_or_default(),
                                    has_reason: summary.reason.is_some(),
                                    next_step: summary.next_step.clone().unwrap_or_default(),
                                    has_next_step: summary.next_step.is_some(),
                                },
                            ),
                            has_computer_use_recovery: playbook.computer_use_recovery.is_some(),
                            summary: playbook.summary,
                            error_class: playbook.error_class.clone().unwrap_or_default(),
                            has_error_class: playbook.error_class.is_some(),
                        },
                    )),
                }),
            ),
            ioi_types::app::WorkloadReceipt::Adapter(adapter) => Some(
                ChainEventEnum::WorkloadReceipt(ioi_ipc::public::WorkloadReceipt {
                    session_id: hex::encode(receipt.session_id),
                    step_index: receipt.step_index,
                    workload_id: receipt.workload_id,
                    timestamp_ms: receipt.timestamp_ms,
                    receipt: Some(ioi_ipc::public::workload_receipt::Receipt::Adapter(
                        ioi_ipc::public::WorkloadAdapterReceipt {
                            adapter_id: adapter.adapter_id,
                            tool_name: adapter.tool_name,
                            adapter_kind: adapter.kind.as_label().to_string(),
                            invocation_id: adapter.invocation_id,
                            idempotency_key: adapter.idempotency_key,
                            action_target: adapter.action_target,
                            request_hash: adapter.request_hash,
                            response_hash: adapter.response_hash.clone().unwrap_or_default(),
                            has_response_hash: adapter.response_hash.is_some(),
                            success: adapter.success,
                            error_class: adapter.error_class.clone().unwrap_or_default(),
                            has_error_class: adapter.error_class.is_some(),
                            replay_classification: adapter
                                .replay_classification
                                .map(|classification| classification.as_label().to_string())
                                .unwrap_or_default(),
                            has_replay_classification: adapter.replay_classification.is_some(),
                            artifact_pointers: adapter
                                .artifact_pointers
                                .into_iter()
                                .map(|pointer| ioi_ipc::public::AdapterArtifactPointer {
                                    uri: pointer.uri,
                                    media_type: pointer.media_type.clone().unwrap_or_default(),
                                    has_media_type: pointer.media_type.is_some(),
                                    sha256: pointer.sha256.clone().unwrap_or_default(),
                                    has_sha256: pointer.sha256.is_some(),
                                    label: pointer.label.clone().unwrap_or_default(),
                                    has_label: pointer.label.is_some(),
                                })
                                .collect(),
                            redacted_fields: adapter
                                .redaction
                                .as_ref()
                                .map(|redaction| redaction.redacted_fields.clone())
                                .unwrap_or_default(),
                            redaction_count: adapter
                                .redaction
                                .as_ref()
                                .map(|redaction| redaction.redaction_count)
                                .unwrap_or_default(),
                            redaction_version: adapter
                                .redaction
                                .as_ref()
                                .map(|redaction| redaction.redaction_version.clone())
                                .unwrap_or_default(),
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
                    "intent_id={} band={:?} score={:.3} constrained={} evidence_requirements_hash={}",
                    receipt.intent_id,
                    receipt.band,
                    receipt.score,
                    receipt.constrained,
                    hex::encode(receipt.evidence_requirements_hash)
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
