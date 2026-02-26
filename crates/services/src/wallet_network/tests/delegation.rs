use super::*;

#[test]
fn session_subgrant_must_be_narrower_than_parent() {
    let service = WalletNetworkService;
    let mut state = MockState::default();
    let root = make_session_grant(
        [1u8; 32],
        vec![ActionTarget::WebRetrieve, ActionTarget::NetFetch],
        Some(10),
        Some(1_000),
        1_850_000_000_000,
    );
    let child = make_session_grant(
        [2u8; 32],
        vec![ActionTarget::WebRetrieve],
        Some(3),
        Some(400),
        1_800_000_000_000,
    );

    with_ctx(|ctx| {
        let root_params = codec::to_bytes_canonical(&IssueSessionGrantParams {
            grant: root,
            parent_session_id: None,
            delegation_rules: None,
        })
        .expect("encode");
        run_async(service.handle_service_call(
            &mut state,
            "issue_session_grant@v1",
            &root_params,
            ctx,
        ))
        .expect("root session grant");

        let child_params = codec::to_bytes_canonical(&IssueSessionGrantParams {
            grant: child.clone(),
            parent_session_id: Some([1u8; 32]),
            delegation_rules: None,
        })
        .expect("encode");
        run_async(service.handle_service_call(
            &mut state,
            "issue_session_grant@v1",
            &child_params,
            ctx,
        ))
        .expect("child session grant");
    });

    let stored: SessionGrant = codec::from_bytes_canonical(
        &state
            .get(&session_key(&[2u8; 32]))
            .expect("state")
            .expect("session present"),
    )
    .expect("decode");
    assert_eq!(stored.session_id, [2u8; 32]);
    assert_eq!(stored.scope.max_actions, Some(3));
}

#[test]
fn session_grant_delegation_enforces_depth_and_budget() {
    let service = WalletNetworkService;
    let mut state = MockState::default();
    let root = make_session_grant(
        [0x71u8; 32],
        vec![ActionTarget::WebRetrieve, ActionTarget::NetFetch],
        Some(10),
        Some(1_000),
        1_850_000_000_000,
    );
    let child_one = make_session_grant(
        [0x72u8; 32],
        vec![ActionTarget::WebRetrieve],
        Some(5),
        Some(500),
        1_840_000_000_000,
    );
    let child_two = make_session_grant(
        [0x73u8; 32],
        vec![ActionTarget::WebRetrieve],
        Some(4),
        Some(400),
        1_830_000_000_000,
    );
    let grandchild = make_session_grant(
        [0x74u8; 32],
        vec![ActionTarget::WebRetrieve],
        Some(2),
        Some(200),
        1_820_000_000_000,
    );

    with_ctx(|ctx| {
        let root_params = codec::to_bytes_canonical(&IssueSessionGrantParams {
            grant: root,
            parent_session_id: None,
            delegation_rules: Some(
                ioi_types::app::wallet_network::SessionChannelDelegationRules {
                    max_depth: 1,
                    can_redelegate: true,
                    issuance_budget: Some(1),
                },
            ),
        })
        .expect("encode");
        run_async(service.handle_service_call(
            &mut state,
            "issue_session_grant@v1",
            &root_params,
            ctx,
        ))
        .expect("root session grant");

        let child_one_params = codec::to_bytes_canonical(&IssueSessionGrantParams {
            grant: child_one,
            parent_session_id: Some([0x71u8; 32]),
            delegation_rules: None,
        })
        .expect("encode");
        run_async(service.handle_service_call(
            &mut state,
            "issue_session_grant@v1",
            &child_one_params,
            ctx,
        ))
        .expect("child one grant");

        let child_two_params = codec::to_bytes_canonical(&IssueSessionGrantParams {
            grant: child_two,
            parent_session_id: Some([0x71u8; 32]),
            delegation_rules: None,
        })
        .expect("encode");
        let budget_err = run_async(service.handle_service_call(
            &mut state,
            "issue_session_grant@v1",
            &child_two_params,
            ctx,
        ))
        .expect_err("root issuance budget should be exhausted");
        let budget_err_lc = budget_err.to_string().to_ascii_lowercase();
        assert!(budget_err_lc.contains("budget") || budget_err_lc.contains("re-delegation"));

        let depth_root = make_session_grant(
            [0x91u8; 32],
            vec![ActionTarget::WebRetrieve],
            Some(5),
            Some(500),
            1_850_000_000_000,
        );
        let depth_child = make_session_grant(
            [0x92u8; 32],
            vec![ActionTarget::WebRetrieve],
            Some(4),
            Some(400),
            1_840_000_000_000,
        );
        let depth_root_params = codec::to_bytes_canonical(&IssueSessionGrantParams {
            grant: depth_root,
            parent_session_id: None,
            delegation_rules: Some(
                ioi_types::app::wallet_network::SessionChannelDelegationRules {
                    max_depth: 1,
                    can_redelegate: true,
                    issuance_budget: None,
                },
            ),
        })
        .expect("encode");
        run_async(service.handle_service_call(
            &mut state,
            "issue_session_grant@v1",
            &depth_root_params,
            ctx,
        ))
        .expect("depth root");

        let depth_child_params = codec::to_bytes_canonical(&IssueSessionGrantParams {
            grant: depth_child,
            parent_session_id: Some([0x91u8; 32]),
            delegation_rules: None,
        })
        .expect("encode");
        run_async(service.handle_service_call(
            &mut state,
            "issue_session_grant@v1",
            &depth_child_params,
            ctx,
        ))
        .expect("depth child");

        let grandchild_params = codec::to_bytes_canonical(&IssueSessionGrantParams {
            grant: grandchild,
            parent_session_id: Some([0x92u8; 32]),
            delegation_rules: None,
        })
        .expect("encode");
        let depth_err = run_async(service.handle_service_call(
            &mut state,
            "issue_session_grant@v1",
            &grandchild_params,
            ctx,
        ))
        .expect_err("max depth=1 should reject grandchild");
        let depth_err_lc = depth_err.to_string().to_ascii_lowercase();
        assert!(depth_err_lc.contains("depth") || depth_err_lc.contains("re-delegation"));
    });

    let root_state: SessionDelegationState =
        load_typed(&state, &session_delegation_key(&[0x71u8; 32]))
            .expect("load")
            .expect("root state");
    assert_eq!(root_state.depth, 0);
    assert_eq!(root_state.max_depth, 1);
    assert_eq!(root_state.remaining_issuance_budget, Some(0));
    assert_eq!(root_state.children_issued, 1);
    assert!(!root_state.can_redelegate);

    let child_state: SessionDelegationState =
        load_typed(&state, &session_delegation_key(&[0x72u8; 32]))
            .expect("load")
            .expect("child state");
    assert_eq!(child_state.root_session_id, [0x71u8; 32]);
    assert_eq!(child_state.depth, 1);
}

#[test]
fn session_subgrant_requires_existing_parent_delegation_state() {
    let service = WalletNetworkService;
    let mut state = MockState::default();
    let root = make_session_grant(
        [0x61u8; 32],
        vec![ActionTarget::WebRetrieve, ActionTarget::NetFetch],
        Some(10),
        Some(1_000),
        1_850_000_000_000,
    );
    let child = make_session_grant(
        [0x62u8; 32],
        vec![ActionTarget::WebRetrieve],
        Some(5),
        Some(500),
        1_840_000_000_000,
    );

    with_ctx(|ctx| {
        let root_params = codec::to_bytes_canonical(&IssueSessionGrantParams {
            grant: root,
            parent_session_id: None,
            delegation_rules: None,
        })
        .expect("encode");
        run_async(service.handle_service_call(
            &mut state,
            "issue_session_grant@v1",
            &root_params,
            ctx,
        ))
        .expect("root session grant");
    });

    state
        .delete(&session_delegation_key(&[0x61u8; 32]))
        .expect("delete parent delegation state");

    with_ctx(|ctx| {
        let child_params = codec::to_bytes_canonical(&IssueSessionGrantParams {
            grant: child,
            parent_session_id: Some([0x61u8; 32]),
            delegation_rules: None,
        })
        .expect("encode");
        let err = run_async(service.handle_service_call(
            &mut state,
            "issue_session_grant@v1",
            &child_params,
            ctx,
        ))
        .expect_err("missing parent delegation state should fail");
        assert!(err.to_string().to_ascii_lowercase().contains("delegation"));
    });

    assert!(state
        .get(&session_key(&[0x62u8; 32]))
        .expect("state")
        .is_none());
}

#[test]
fn invalid_child_delegation_rules_do_not_consume_parent_budget() {
    let service = WalletNetworkService;
    let mut state = MockState::default();
    let root = make_session_grant(
        [0x63u8; 32],
        vec![ActionTarget::WebRetrieve, ActionTarget::NetFetch],
        Some(10),
        Some(1_000),
        1_850_000_000_000,
    );
    let child = make_session_grant(
        [0x64u8; 32],
        vec![ActionTarget::WebRetrieve],
        Some(5),
        Some(500),
        1_840_000_000_000,
    );

    with_ctx(|ctx| {
        let root_params = codec::to_bytes_canonical(&IssueSessionGrantParams {
            grant: root,
            parent_session_id: None,
            delegation_rules: Some(
                ioi_types::app::wallet_network::SessionChannelDelegationRules {
                    max_depth: 2,
                    can_redelegate: true,
                    issuance_budget: Some(1),
                },
            ),
        })
        .expect("encode");
        run_async(service.handle_service_call(
            &mut state,
            "issue_session_grant@v1",
            &root_params,
            ctx,
        ))
        .expect("root session grant");

        let invalid_child_params = codec::to_bytes_canonical(&IssueSessionGrantParams {
            grant: child,
            parent_session_id: Some([0x63u8; 32]),
            delegation_rules: Some(
                ioi_types::app::wallet_network::SessionChannelDelegationRules {
                    max_depth: 3,
                    can_redelegate: true,
                    issuance_budget: Some(1),
                },
            ),
        })
        .expect("encode");
        let err = run_async(service.handle_service_call(
            &mut state,
            "issue_session_grant@v1",
            &invalid_child_params,
            ctx,
        ))
        .expect_err("invalid child delegation rules should fail");
        assert!(err.to_string().to_ascii_lowercase().contains("max_depth"));
    });

    let root_state: SessionDelegationState =
        load_typed(&state, &session_delegation_key(&[0x63u8; 32]))
            .expect("load")
            .expect("root state");
    assert_eq!(root_state.remaining_issuance_budget, Some(1));
    assert_eq!(root_state.children_issued, 0);
    assert!(root_state.can_redelegate);
    assert!(state
        .get(&session_key(&[0x64u8; 32]))
        .expect("state")
        .is_none());
}
