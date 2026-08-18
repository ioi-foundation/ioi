// AFT-CB R5 stage 3 gates: the ring membership plane's service wiring —
// bonded registration into the PUBLIC queue, the genesis configuration
// exactly once, and the handover ceremony verified against the STORED
// live configuration with D_act and the churn cap enforced.

#[test]
fn ring_registration_queues_and_refuses_duplicates_and_zero_bonds() {
    let registry = production_registry();
    let mut state = MockState::default();
    let registration = RingMemberRegistration {
        account_id: AccountId([31u8; 32]),
        bond_amount: 1_000,
        constituency_id: 1,
        registered_at_event: 999, // overwritten by the plane's own counter
    };
    with_ctx(|ctx| {
        run_async(registry.handle_service_call(
            &mut state,
            "register_ring_member@v1",
            &codec::to_bytes_canonical(&registration).unwrap(),
            ctx,
        ))
        .unwrap();
        // Duplicate: refused.
        let err = run_async(registry.handle_service_call(
            &mut state,
            "register_ring_member@v1",
            &codec::to_bytes_canonical(&registration).unwrap(),
            ctx,
        ))
        .unwrap_err();
        assert!(err.to_string().contains("already queued"));
        // Zero bond: refused.
        let zero_bond = RingMemberRegistration {
            account_id: AccountId([32u8; 32]),
            bond_amount: 0,
            constituency_id: 1,
            registered_at_event: 0,
        };
        let err = run_async(registry.handle_service_call(
            &mut state,
            "register_ring_member@v1",
            &codec::to_bytes_canonical(&zero_bond).unwrap(),
            ctx,
        ))
        .unwrap_err();
        assert!(err.to_string().contains("non-zero bond"));
    });
    let queue: RingActivationQueue = codec::from_bytes_canonical(
        &state
            .get(ioi_types::app::GUARDIAN_RING_QUEUE_KEY)
            .unwrap()
            .expect("queue persisted"),
    )
    .unwrap();
    assert_eq!(queue.entries.len(), 1);
    assert_eq!(queue.entries[0].registered_at_event, 1, "plane-stamped ordinal");
}

#[test]
fn ring_genesis_publishes_once_and_handover_enforces_queue_depth_and_churn() {
    let registry = production_registry();
    let mut state = MockState::default();
    let member = |b: u8| AccountId([b; 32]);
    let genesis = BoundaryRingConfig {
        version: 1,
        members: vec![member(1), member(2), member(3)],
        member_bonds: Default::default(),
        activated_at_event: 0,
        closed_by: None,
    };

    with_ctx(|ctx| {
        run_async(registry.handle_service_call(
            &mut state,
            "publish_ring_genesis_config@v1",
            &codec::to_bytes_canonical(&genesis).unwrap(),
            ctx,
        ))
        .unwrap();
        // A second genesis: refused.
        let err = run_async(registry.handle_service_call(
            &mut state,
            "publish_ring_genesis_config@v1",
            &codec::to_bytes_canonical(&genesis).unwrap(),
            ctx,
        ))
        .unwrap_err();
        assert!(err.to_string().contains("already exists"));

        // Register the prospective joiner (member 4).
        let registration = RingMemberRegistration {
            account_id: member(4),
            bond_amount: 500,
            constituency_id: 0,
            registered_at_event: 0,
        };
        run_async(registry.handle_service_call(
            &mut state,
            "register_ring_member@v1",
            &codec::to_bytes_canonical(&registration).unwrap(),
            ctx,
        ))
        .unwrap();

        let new_config = BoundaryRingConfig {
            version: 2,
            members: vec![member(2), member(3), member(4)],
            member_bonds: Default::default(),
            activated_at_event: 0,
            closed_by: None,
        };
        let approvals: Vec<HandoverApproval> = [1u8, 2, 3]
            .iter()
            .map(|m| HandoverApproval {
                member: member(*m),
                old_version: 1,
                new_version: 2,
                signature_bytes: vec![*m],
            })
            .collect();
        let acceptances: Vec<HandoverAcceptance> = [2u8, 3, 4]
            .iter()
            .map(|m| HandoverAcceptance {
                member: member(*m),
                new_version: 2,
                signature_bytes: vec![*m],
            })
            .collect();
        let publication = RingHandoverPublication {
            new_config: new_config.clone(),
            approvals: approvals.clone(),
            acceptances: acceptances.clone(),
        };

        // Too early: the joiner has not aged D_act events in the queue.
        let err = run_async(registry.handle_service_call(
            &mut state,
            "publish_ring_handover@v1",
            &codec::to_bytes_canonical(&publication).unwrap(),
            ctx,
        ))
        .unwrap_err();
        assert!(err.to_string().contains("D_act"), "got: {err}");

        // Age the queue: two more ring events via two more registrations.
        for b in [5u8, 6] {
            run_async(registry.handle_service_call(
                &mut state,
                "register_ring_member@v1",
                &codec::to_bytes_canonical(&RingMemberRegistration {
                    account_id: member(b),
                    bond_amount: 500,
                    constituency_id: 0,
                    registered_at_event: 0,
                })
                .unwrap(),
                ctx,
            ))
            .unwrap();
        }

        // (n-1) approvals: refused by the ceremony builder.
        let thin = RingHandoverPublication {
            new_config: new_config.clone(),
            approvals: approvals[..2].to_vec(),
            acceptances: acceptances.clone(),
        };
        let err = run_async(registry.handle_service_call(
            &mut state,
            "publish_ring_handover@v1",
            &codec::to_bytes_canonical(&thin).unwrap(),
            ctx,
        ))
        .unwrap_err();
        assert!(err.to_string().contains("UNANIMITY"), "got: {err}");

        // The full ceremony lands.
        run_async(registry.handle_service_call(
            &mut state,
            "publish_ring_handover@v1",
            &codec::to_bytes_canonical(&publication).unwrap(),
            ctx,
        ))
        .unwrap();
    });

    // v2 live; v1 closed naming its successor; joiner left the queue.
    let live_version: u64 = codec::from_bytes_canonical(
        &state
            .get(ioi_types::app::GUARDIAN_RING_LIVE_VERSION_KEY)
            .unwrap()
            .expect("live version"),
    )
    .unwrap();
    assert_eq!(live_version, 2);
    let closed: BoundaryRingConfig = codec::from_bytes_canonical(
        &state
            .get(&guardian_ring_config_key(1))
            .unwrap()
            .expect("closed config persisted"),
    )
    .unwrap();
    assert_eq!(closed.closed_by.expect("closed").successor_version, 2);
    let queue: RingActivationQueue = codec::from_bytes_canonical(
        &state
            .get(ioi_types::app::GUARDIAN_RING_QUEUE_KEY)
            .unwrap()
            .expect("queue persisted"),
    )
    .unwrap();
    assert!(
        !queue
            .entries
            .iter()
            .any(|entry| entry.account_id == AccountId([4u8; 32])),
        "joiner consumed from the queue"
    );
}

#[test]
fn ring_handover_refuses_churn_over_cap_and_unqueued_joiners() {
    let registry = production_registry();
    let mut state = MockState::default();
    let member = |b: u8| AccountId([b; 32]);
    let genesis = BoundaryRingConfig {
        version: 1,
        members: vec![member(1), member(2), member(3), member(4)],
        member_bonds: Default::default(),
        activated_at_event: 0,
        closed_by: None,
    };
    with_ctx(|ctx| {
        run_async(registry.handle_service_call(
            &mut state,
            "publish_ring_genesis_config@v1",
            &codec::to_bytes_canonical(&genesis).unwrap(),
            ctx,
        ))
        .unwrap();

        // THREE joiners (5, 6, 7) exceed the churn cap of 2 regardless
        // of queue state.
        let over_cap = BoundaryRingConfig {
            version: 2,
            members: vec![member(4), member(5), member(6), member(7)],
            member_bonds: Default::default(),
            activated_at_event: 0,
            closed_by: None,
        };
        let approvals: Vec<HandoverApproval> = [1u8, 2, 3, 4]
            .iter()
            .map(|m| HandoverApproval {
                member: member(*m),
                old_version: 1,
                new_version: 2,
                signature_bytes: vec![*m],
            })
            .collect();
        let acceptances: Vec<HandoverAcceptance> = [4u8, 5, 6, 7]
            .iter()
            .map(|m| HandoverAcceptance {
                member: member(*m),
                new_version: 2,
                signature_bytes: vec![*m],
            })
            .collect();
        let err = run_async(registry.handle_service_call(
            &mut state,
            "publish_ring_handover@v1",
            &codec::to_bytes_canonical(&RingHandoverPublication {
                new_config: over_cap,
                approvals: approvals.clone(),
                acceptances,
            })
            .unwrap(),
            ctx,
        ))
        .unwrap_err();
        assert!(err.to_string().contains("churn cap"), "got: {err}");

        // One joiner, but NEVER registered: refused at the queue check.
        let unqueued = BoundaryRingConfig {
            version: 2,
            members: vec![member(2), member(3), member(4), member(9)],
            member_bonds: Default::default(),
            activated_at_event: 0,
            closed_by: None,
        };
        let acceptances: Vec<HandoverAcceptance> = [2u8, 3, 4, 9]
            .iter()
            .map(|m| HandoverAcceptance {
                member: member(*m),
                new_version: 2,
                signature_bytes: vec![*m],
            })
            .collect();
        let err = run_async(registry.handle_service_call(
            &mut state,
            "publish_ring_handover@v1",
            &codec::to_bytes_canonical(&RingHandoverPublication {
                new_config: unqueued,
                approvals,
                acceptances,
            })
            .unwrap(),
            ctx,
        ))
        .unwrap_err();
        assert!(err.to_string().contains("activatable"), "got: {err}");
    });
}
