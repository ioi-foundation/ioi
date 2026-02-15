use super::*;
use ioi_ipc::public::chain_event::Event as ChainEventEnum;
use ioi_types::app::RoutingReceiptEvent;

#[test]
fn routing_receipt_chain_event_payload_is_complete() {
    let keypair = libp2p::identity::Keypair::generate_ed25519();
    let signer_pk = hex::encode(keypair.public().encode_protobuf());

    let receipt = RoutingReceiptEvent {
        session_id: [7u8; 32],
        step_index: 42,
        intent_hash: "abcd1234".to_string(),
        policy_decision: "allowed".to_string(),
        tool_name: "sys__exec".to_string(),
        tool_version: "1.0.0".to_string(),
        pre_state: ioi_types::app::RoutingStateSummary {
            agent_status: "Running".to_string(),
            tier: "ToolFirst".to_string(),
            step_index: 42,
            consecutive_failures: 0,
            target_hint: Some("terminal".to_string()),
        },
        action_json: "{\"name\":\"sys__exec\"}".to_string(),
        post_state: ioi_types::app::RoutingPostStateSummary {
            agent_status: "Running".to_string(),
            tier: "ToolFirst".to_string(),
            step_index: 43,
            consecutive_failures: 0,
            success: true,
            verification_checks: vec!["policy_decision=allowed".to_string()],
        },
        artifacts: vec!["trace://agent_step/42".to_string()],
        failure_class: None,
        failure_class_name: String::new(),
        intent_class: "generic".to_string(),
        incident_id: String::new(),
        incident_stage: String::new(),
        strategy_name: String::new(),
        strategy_node: String::new(),
        gate_state: "none".to_string(),
        resolution_action: String::new(),
        stop_condition_hit: false,
        escalation_path: None,
        scs_lineage_ptr: Some("scs://skill/abc".to_string()),
        mutation_receipt_ptr: Some("scs://mutation-receipt/def".to_string()),
        policy_binding_hash: String::new(),
        policy_binding_sig: None,
        policy_binding_signer: None,
    };

    let mapped = map_routing_receipt(receipt.clone(), Some((&keypair, signer_pk.as_str())));
    let event = ChainEvent {
        event: Some(ChainEventEnum::RoutingReceipt(mapped.clone())),
    };

    match event.event {
        Some(ChainEventEnum::RoutingReceipt(payload)) => {
            assert_eq!(payload.session_id, hex::encode(receipt.session_id));
            assert_eq!(payload.step_index, receipt.step_index);
            assert_eq!(payload.intent_hash, receipt.intent_hash);
            assert_eq!(payload.policy_decision, receipt.policy_decision);
            assert_eq!(payload.tool_name, receipt.tool_name);
            assert_eq!(payload.tool_version, receipt.tool_version);
            assert_eq!(payload.action_json, receipt.action_json);
            assert_eq!(payload.artifacts, receipt.artifacts);
            assert_eq!(
                payload.pre_state.as_ref().map(|s| s.tier.as_str()),
                Some("ToolFirst")
            );
            assert_eq!(
                payload
                    .post_state
                    .as_ref()
                    .map(|s| s.verification_checks.len())
                    .unwrap_or_default(),
                1
            );
            assert!(!payload.policy_binding_hash.is_empty());
            assert!(!payload.policy_binding_sig.is_empty());
            assert_eq!(payload.policy_binding_signer, signer_pk);

            let signer_bytes =
                hex::decode(&payload.policy_binding_signer).expect("valid signer hex");
            let signature = hex::decode(&payload.policy_binding_sig).expect("valid signature hex");
            let signer_key = libp2p::identity::PublicKey::try_decode_protobuf(&signer_bytes)
                .expect("decode signer key");
            assert!(signer_key.verify(payload.policy_binding_hash.as_bytes(), &signature));
        }
        other => panic!("expected routing receipt chain event, got: {:?}", other),
    }
}
