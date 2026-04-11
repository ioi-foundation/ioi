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

include!("events_handlers/kernel_summary.rs");

include!("events_handlers/kernel_mapping.rs");

include!("events_handlers/subscription.rs");

#[cfg(test)]
mod workload_event_mapping_tests {
    use super::map_kernel_event;
    use ioi_ipc::public::chain_event::Event as ChainEventEnum;
    use ioi_types::app::{
        AdapterArtifactPointer, AdapterKind, AdapterReceipt, AdapterRedactionSummary,
        InferenceOperationKind, KernelEvent, MediaOperationKind, ModelLifecycleOperationKind,
        RegistrySubjectKind, WorkloadActivityEvent, WorkloadActivityKind, WorkloadExecReceipt,
        WorkloadFsWriteReceipt, WorkloadInferenceReceipt, WorkloadMediaReceipt,
        WorkloadMemoryRetrieveReceipt, WorkloadModelLifecycleReceipt, WorkloadNetFetchReceipt,
        WorkloadReceipt, WorkloadReceiptEvent, WorkloadWebRetrieveReceipt,
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
                tool_name: "shell__run".to_string(),
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
                    assert_eq!(exec.tool_name, "shell__run");
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
                tool_name: "file__write".to_string(),
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
                    assert_eq!(fs.tool_name, "file__write");
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
                tool_name: "http__fetch".to_string(),
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
                    assert_eq!(net.tool_name, "http__fetch");
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
            receipt: WorkloadReceipt::MemoryRetrieve(WorkloadMemoryRetrieveReceipt {
                tool_name: "memory__search".to_string(),
                backend: "memory:sqlite+semantic".to_string(),
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
                proof_ref: Some("memory://proof/123".to_string()),
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
                Some(ioi_ipc::public::workload_receipt::Receipt::MemoryRetrieve(scs)) => {
                    assert_eq!(scs.tool_name, "memory__search");
                    assert_eq!(scs.backend, "memory:sqlite+semantic");
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
                    assert_eq!(scs.proof_ref, "memory://proof/123");
                    assert!(scs.has_proof_hash);
                    assert_eq!(scs.proof_hash, "deadbeef");
                    assert!(scs.has_certificate_mode);
                    assert_eq!(scs.certificate_mode, "single_level_lb");
                    assert!(scs.success);
                    assert!(!scs.has_error_class);
                }
                other => panic!("expected memory_retrieve receipt, got: {:?}", other),
            },
            other => panic!("expected workload receipt chain event, got: {:?}", other),
        }

        let receipt = KernelEvent::WorkloadReceipt(WorkloadReceiptEvent {
            session_id: [7u8; 32],
            step_index: 42,
            workload_id: "wid-inference".to_string(),
            timestamp_ms: 129,
            receipt: WorkloadReceipt::Inference(WorkloadInferenceReceipt {
                tool_name: "model__responses".to_string(),
                operation: InferenceOperationKind::TextGeneration,
                backend: "inference:local".to_string(),
                model_id: "qwen3-8b".to_string(),
                model_family: Some("qwen3".to_string()),
                prompt_token_count: Some(128),
                completion_token_count: Some(64),
                total_token_count: Some(192),
                vector_dimensions: None,
                result_item_count: 1,
                candidate_count_total: None,
                candidate_count_scored: None,
                streaming: true,
                latency_ms: Some(850),
                success: true,
                error_class: None,
            }),
        });
        let mapped = map_kernel_event(receipt, &keypair, signer_pk.as_str())
            .expect("inference workload receipt should map");
        match mapped {
            ChainEventEnum::WorkloadReceipt(payload) => match payload.receipt {
                Some(ioi_ipc::public::workload_receipt::Receipt::Inference(inference)) => {
                    assert_eq!(inference.tool_name, "model__responses");
                    assert_eq!(inference.operation, "text_generation");
                    assert_eq!(inference.backend, "inference:local");
                    assert_eq!(inference.model_id, "qwen3-8b");
                    assert!(inference.has_model_family);
                    assert_eq!(inference.model_family, "qwen3");
                    assert!(inference.has_prompt_token_count);
                    assert_eq!(inference.prompt_token_count, 128);
                    assert!(inference.has_completion_token_count);
                    assert_eq!(inference.completion_token_count, 64);
                    assert!(inference.has_total_token_count);
                    assert_eq!(inference.total_token_count, 192);
                    assert_eq!(inference.result_item_count, 1);
                    assert!(inference.streaming);
                    assert!(inference.has_latency_ms);
                    assert_eq!(inference.latency_ms, 850);
                    assert!(inference.success);
                    assert!(!inference.has_error_class);
                }
                other => panic!("expected inference receipt, got: {:?}", other),
            },
            other => panic!("expected workload receipt chain event, got: {:?}", other),
        }

        let receipt = KernelEvent::WorkloadReceipt(WorkloadReceiptEvent {
            session_id: [7u8; 32],
            step_index: 42,
            workload_id: "wid-media".to_string(),
            timestamp_ms: 130,
            receipt: WorkloadReceipt::Media(WorkloadMediaReceipt {
                tool_name: "media__extract_transcript".to_string(),
                operation: MediaOperationKind::Transcription,
                backend: "audio:whisper".to_string(),
                model_id: Some("whisper-large-v3".to_string()),
                source_uri: Some("https://example.test/audio".to_string()),
                input_artifact_count: 1,
                output_artifact_count: 1,
                output_bytes: Some(2048),
                duration_ms: Some(1_250),
                output_mime_types: vec!["text/plain".to_string()],
                success: true,
                error_class: None,
            }),
        });
        let mapped = map_kernel_event(receipt, &keypair, signer_pk.as_str())
            .expect("media workload receipt should map");
        match mapped {
            ChainEventEnum::WorkloadReceipt(payload) => match payload.receipt {
                Some(ioi_ipc::public::workload_receipt::Receipt::Media(media)) => {
                    assert_eq!(media.tool_name, "media__extract_transcript");
                    assert_eq!(media.operation, "transcription");
                    assert_eq!(media.backend, "audio:whisper");
                    assert!(media.has_model_id);
                    assert_eq!(media.model_id, "whisper-large-v3");
                    assert!(media.has_source_uri);
                    assert_eq!(media.source_uri, "https://example.test/audio");
                    assert_eq!(media.input_artifact_count, 1);
                    assert_eq!(media.output_artifact_count, 1);
                    assert!(media.has_output_bytes);
                    assert_eq!(media.output_bytes, 2048);
                    assert!(media.has_duration_ms);
                    assert_eq!(media.duration_ms, 1_250);
                    assert_eq!(media.output_mime_types, vec!["text/plain".to_string()]);
                    assert!(media.success);
                    assert!(!media.has_error_class);
                }
                other => panic!("expected media receipt, got: {:?}", other),
            },
            other => panic!("expected workload receipt chain event, got: {:?}", other),
        }

        let receipt = KernelEvent::WorkloadReceipt(WorkloadReceiptEvent {
            session_id: [7u8; 32],
            step_index: 42,
            workload_id: "wid-model".to_string(),
            timestamp_ms: 131,
            receipt: WorkloadReceipt::ModelLifecycle(WorkloadModelLifecycleReceipt {
                tool_name: "model_registry__install".to_string(),
                operation: ModelLifecycleOperationKind::Install,
                subject_kind: RegistrySubjectKind::Model,
                subject_id: "qwen3-8b".to_string(),
                backend_id: Some("llama-cpp".to_string()),
                source_uri: Some("oci://localai/qwen3:8b".to_string()),
                job_id: Some("job-123".to_string()),
                bytes_transferred: Some(1_024),
                hardware_profile: Some("cpu-only".to_string()),
                success: true,
                error_class: None,
            }),
        });
        let mapped = map_kernel_event(receipt, &keypair, signer_pk.as_str())
            .expect("model lifecycle workload receipt should map");
        match mapped {
            ChainEventEnum::WorkloadReceipt(payload) => match payload.receipt {
                Some(ioi_ipc::public::workload_receipt::Receipt::ModelLifecycle(model)) => {
                    assert_eq!(model.tool_name, "model_registry__install");
                    assert_eq!(model.operation, "install");
                    assert_eq!(model.subject_kind, "model");
                    assert_eq!(model.subject_id, "qwen3-8b");
                    assert!(model.has_backend_id);
                    assert_eq!(model.backend_id, "llama-cpp");
                    assert!(model.has_source_uri);
                    assert_eq!(model.source_uri, "oci://localai/qwen3:8b");
                    assert!(model.has_job_id);
                    assert_eq!(model.job_id, "job-123");
                    assert!(model.has_bytes_transferred);
                    assert_eq!(model.bytes_transferred, 1_024);
                    assert!(model.has_hardware_profile);
                    assert_eq!(model.hardware_profile, "cpu-only");
                    assert!(model.success);
                    assert!(!model.has_error_class);
                }
                other => panic!("expected model lifecycle receipt, got: {:?}", other),
            },
            other => panic!("expected workload receipt chain event, got: {:?}", other),
        }

        let receipt = KernelEvent::WorkloadReceipt(WorkloadReceiptEvent {
            session_id: [7u8; 32],
            step_index: 42,
            workload_id: "wid-adapter".to_string(),
            timestamp_ms: 128,
            receipt: WorkloadReceipt::Adapter(AdapterReceipt {
                adapter_id: "mcp::echo_server".to_string(),
                tool_name: "echo_server__echo".to_string(),
                kind: AdapterKind::Mcp,
                invocation_id: "invoke-1".to_string(),
                idempotency_key: "idem-1".to_string(),
                action_target: "custom:echo_server__echo".to_string(),
                request_hash: "sha256:req".to_string(),
                response_hash: Some("sha256:resp".to_string()),
                success: true,
                error_class: None,
                artifact_pointers: vec![AdapterArtifactPointer {
                    uri: "file:///tmp/report.json".to_string(),
                    media_type: Some("application/json".to_string()),
                    sha256: Some("sha256:artifact".to_string()),
                    label: Some("report".to_string()),
                }],
                redaction: Some(AdapterRedactionSummary {
                    redacted_fields: vec!["arguments.token".to_string()],
                    redaction_count: 1,
                    redaction_version: "adapter_receipt.redaction.v1".to_string(),
                }),
                replay_classification: Some(
                    ioi_types::app::AdapterReplayClassification::ReplaySafe,
                ),
            }),
        });
        let mapped = map_kernel_event(receipt, &keypair, signer_pk.as_str())
            .expect("adapter workload receipt should map");
        match mapped {
            ChainEventEnum::WorkloadReceipt(payload) => match payload.receipt {
                Some(ioi_ipc::public::workload_receipt::Receipt::Adapter(adapter)) => {
                    assert_eq!(adapter.adapter_id, "mcp::echo_server");
                    assert_eq!(adapter.tool_name, "echo_server__echo");
                    assert_eq!(adapter.adapter_kind, "mcp");
                    assert_eq!(adapter.invocation_id, "invoke-1");
                    assert_eq!(adapter.idempotency_key, "idem-1");
                    assert_eq!(adapter.action_target, "custom:echo_server__echo");
                    assert_eq!(adapter.request_hash, "sha256:req");
                    assert!(adapter.has_response_hash);
                    assert_eq!(adapter.response_hash, "sha256:resp");
                    assert!(adapter.success);
                    assert!(!adapter.has_error_class);
                    assert!(adapter.has_replay_classification);
                    assert_eq!(adapter.replay_classification, "replay_safe");
                    assert_eq!(adapter.artifact_pointers.len(), 1);
                    assert_eq!(adapter.artifact_pointers[0].uri, "file:///tmp/report.json");
                    assert!(adapter.artifact_pointers[0].has_media_type);
                    assert_eq!(adapter.artifact_pointers[0].media_type, "application/json");
                    assert_eq!(adapter.redacted_fields, vec!["arguments.token".to_string()]);
                    assert_eq!(adapter.redaction_count, 1);
                    assert_eq!(adapter.redaction_version, "adapter_receipt.redaction.v1");
                }
                other => panic!("expected adapter receipt, got: {:?}", other),
            },
            other => panic!("expected workload receipt chain event, got: {:?}", other),
        }
    }
}
