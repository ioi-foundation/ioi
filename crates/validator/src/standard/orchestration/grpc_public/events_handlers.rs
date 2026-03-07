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
