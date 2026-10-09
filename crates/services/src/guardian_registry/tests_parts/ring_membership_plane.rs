// AFT-CB R5 stage 3 and SCQ-8.10 (OBS-6; build Ruling 12, P7, with SCQ-8.10a-e): the ring
// membership plane's service wiring. Registration needs the configured selection parameters (D1
// bond floor, D3 D_act, D2 lock); the GENESIS ring is the selector's draw from a committed genesis
// snapshot and a beacon the registry derives itself (no configuration chooses it), with balanced
// tenure offsets; each handover is drawn by vacated-seat sortition, an exit the churn cap cannot
// refill leaves a vacancy the next handover refills first, and the old ring's approval cannot
// choose the successor. The tenure rule is INHERITED PHASE: a joiner inherits its seat's phase, a
// joiner in a seat the draw did not assign it is refused, and a ledger holding a member off its
// seat's phase is refused at the next snapshot.

/// Fixture parameters only (the production numbers are the numbers author's): n=3, T=4, c=2,
/// b=100, W = 4×4+3 = 19, D_act = the beacon interval = 2. The balanced genesis offsets are
/// {0, 1, 2}, so the genesis seats rotate at handovers 4, 3 and 2 (T − o) and none at the first.
/// Rulings 2026-10-08 Q1 (C) and Q4: the ring plane's tests draw with the REFERENCE-UNBOUNDED
/// beacon and use R >= 1 fixtures, which only the explicit TEST admission admits (every chain
/// configuration refuses both: the `..._refused_in_every_chain_configuration` tests). The paths that
/// need it: this file's ring tests, and no other (no local, single-node or Alpha path draws a ring).
struct RingTestRegistry {
    registry: GuardianRegistry,
    _admission: super::ring_selection::RingSelectionTestAdmission,
}

impl std::ops::Deref for RingTestRegistry {
    type Target = GuardianRegistry;
    fn deref(&self) -> &GuardianRegistry {
        &self.registry
    }
}

/// A production-configured registry whose ring plane runs, for this test's thread and while the
/// returned value lives, under the TEST-only admission (REFERENCE-UNBOUNDED).
fn ring_test_registry() -> RingTestRegistry {
    RingTestRegistry {
        registry: production_registry(),
        _admission: super::ring_selection::RingSelectionTestAdmission::hold(),
    }
}

fn ring_params() -> ioi_types::app::RingSelectionParams {
    ioi_types::app::RingSelectionParams {
        ring_seats: 3,
        tenure_handovers: 4,
        churn_cap: 2,
        bond_floor: 100,
        bond_lock_events: 4 * 4 + 3,
        handover_interval_events: 4,
        exit_challenge_window_events: 3,
        activation_depth_events: 2,
        snapshot_to_beacon_events: 2,
        acceptance_window_events: 1,
        floors: vec![],
    }
}

fn call(
    registry: &GuardianRegistry,
    state: &mut MockState,
    ctx: &mut TxContext<'_>,
    method: &str,
    params: &[u8],
) -> Result<(), TransactionError> {
    run_async(registry.handle_service_call(state, method, params, ctx))
}

fn ring_member(b: u8) -> AccountId {
    AccountId([b; 32])
}

fn register(
    registry: &GuardianRegistry,
    state: &mut MockState,
    ctx: &mut TxContext<'_>,
    b: u8,
    bond: u128,
) -> Result<(), TransactionError> {
    let registration = RingMemberRegistration {
        account_id: ring_member(b),
        bond_amount: bond,
        constituency_id: 0,
        registered_at_event: 0,
    };
    call(
        registry,
        state,
        ctx,
        "register_ring_member@v1",
        &codec::to_bytes_canonical(&registration).unwrap(),
    )
}

fn publish_params(registry: &GuardianRegistry, state: &mut MockState, ctx: &mut TxContext<'_>) {
    call(
        registry,
        state,
        ctx,
        "publish_ring_selection_params@v1",
        &codec::to_bytes_canonical(&ring_params()).unwrap(),
    )
    .unwrap();
}

fn pending(state: &MockState) -> ioi_types::app::RingPendingHandover {
    codec::from_bytes_canonical(
        &state
            .get(ioi_types::app::GUARDIAN_RING_HANDOVER_SNAPSHOT_KEY)
            .unwrap()
            .expect("pending handover"),
    )
    .unwrap()
}

fn beacon_request(state: &MockState) -> Vec<u8> {
    codec::to_bytes_canonical(&ioi_types::app::RingBeaconRecordRequest {
        snapshot_commitment: pending(state).commitment,
        source: ioi_types::app::RingBeaconSource::Reference,
    })
    .unwrap()
}

fn stored<T: parity_scale_codec::Decode>(state: &MockState, key: &[u8]) -> T {
    codec::from_bytes_canonical(&state.get(key).unwrap().expect("stored")).unwrap()
}

fn live_config(state: &MockState) -> BoundaryRingConfig {
    let version: u64 = stored(state, GUARDIAN_RING_LIVE_VERSION_KEY);
    stored(state, &guardian_ring_config_key(version))
}

fn publication_for(
    old: &BoundaryRingConfig,
    members: Vec<AccountId>,
    vacancies: Vec<ioi_types::app::RingVacancy>,
    bonds: BTreeMap<AccountId, u128>,
) -> RingHandoverPublication {
    let new_version = old.version + 1;
    RingHandoverPublication {
        new_config: BoundaryRingConfig {
            version: new_version,
            members: members.clone(),
            member_bonds: bonds,
            activated_at_event: 0,
            closed_by: None,
            vacant_seats: vacancies,
        },
        approvals: old
            .members
            .iter()
            .map(|m| HandoverApproval {
                member: *m,
                old_version: old.version,
                new_version,
                signature_bytes: m.0[..1].to_vec(),
            })
            .collect(),
        acceptances: members
            .iter()
            .map(|m| HandoverAcceptance {
                member: *m,
                new_version,
                signature_bytes: m.0[..1].to_vec(),
            })
            .collect(),
    }
}

fn bonds_for(ring: &BoundaryRingConfig, members: &[AccountId]) -> BTreeMap<AccountId, u128> {
    members
        .iter()
        .map(|m| (*m, ring.member_bonds.get(m).copied().unwrap_or(150)))
        .collect()
}

fn drawn_publication(
    ring: &BoundaryRingConfig,
    draw: &ioi_types::app::RingSeatDraw,
) -> RingHandoverPublication {
    publication_for(
        ring,
        draw.successor_members.clone(),
        draw.successor_vacancies.clone(),
        bonds_for(ring, &draw.successor_members),
    )
}

/// Commits the snapshot, waits the beacon interval with a filler registration, records the
/// beacon; returns the pending draw and its beacon.
fn snapshot_and_beacon_raw(
    registry: &GuardianRegistry,
    state: &mut MockState,
    ctx: &mut TxContext<'_>,
    filler: u8,
) -> (ioi_types::app::RingPendingHandover, [u8; 32]) {
    call(registry, state, ctx, "commit_ring_handover_snapshot@v1", &[]).unwrap();
    register(registry, state, ctx, filler, 150).unwrap();
    let request = beacon_request(state);
    call(registry, state, ctx, "record_ring_handover_beacon@v1", &request).unwrap();
    let pending_handover = pending(state);
    let (beacon, _, _) = pending_handover.beacon.expect("beacon recorded");
    (pending_handover, beacon)
}

/// Snapshot, one filler ring event, beacon; returns the handover draw the registry will accept.
fn snapshot_and_beacon(
    registry: &GuardianRegistry,
    state: &mut MockState,
    ctx: &mut TxContext<'_>,
    filler: u8,
) -> ioi_types::app::RingSeatDraw {
    let (pending_handover, beacon) = snapshot_and_beacon_raw(registry, state, ctx, filler);
    let draw = ioi_types::app::draw_vacated_seats(&pending_handover.snapshot, &beacon).unwrap();
    // Q2: every drawn joiner accepts on chain (B3: this never changes the draw).
    let signer = ctx.signer_account_id;
    let commitment = codec::to_bytes_canonical(&pending_handover.commitment).unwrap();
    for joiner in &draw.joiners {
        ctx.signer_account_id = *joiner;
        call(registry, state, ctx, "accept_ring_handover_seat@v1", &commitment).unwrap();
    }
    ctx.signer_account_id = signer;
    draw
}

/// The parameters; registrants 1..=3 (bonds 100), the only ones activatable at the genesis
/// snapshot (4 registers one event before it); the genesis snapshot, a filler (5) and the beacon;
/// the genesis ring published as the draw (its seat order is the beacon's); then registrants
/// 6..=9 (bonds 150), so 4..=8 are activatable at the first handover snapshot.
fn setup_ring(
    registry: &GuardianRegistry,
    state: &mut MockState,
    ctx: &mut TxContext<'_>,
) -> BoundaryRingConfig {
    publish_params(registry, state, ctx);
    for b in 1u8..=3 {
        register(registry, state, ctx, b, 100).unwrap();
    }
    register(registry, state, ctx, 4, 150).unwrap();
    let (genesis_pending, beacon) = snapshot_and_beacon_raw(registry, state, ctx, 5);
    let draw = ioi_types::app::draw_genesis_ring(&genesis_pending.snapshot, &beacon).unwrap();
    let mut drawn: Vec<AccountId> = draw.successor_members.clone();
    drawn.sort();
    assert_eq!(drawn, vec![ring_member(1), ring_member(2), ring_member(3)]);
    let genesis = BoundaryRingConfig {
        version: 1,
        members: draw.successor_members.clone(),
        member_bonds: draw.successor_members.iter().map(|m| (*m, 100)).collect(),
        activated_at_event: 0,
        closed_by: None,
        vacant_seats: vec![],
    };
    call(
        registry,
        state,
        ctx,
        "publish_ring_genesis_config@v1",
        &codec::to_bytes_canonical(&genesis).unwrap(),
    )
    .unwrap();
    for b in 6u8..=9 {
        register(registry, state, ctx, b, 150).unwrap();
    }
    genesis
}

#[test]
fn ring_registration_needs_parameters_the_bond_floor_and_refuses_duplicates() {
    let registry = ring_test_registry();
    let mut state = MockState::default();
    with_ctx(|ctx| {
        // No parameters: no default values exist.
        let err = register(&registry, &mut state, ctx, 31, 1_000).unwrap_err();
        assert!(err.to_string().contains("not configured"), "{err}");
        publish_params(&registry, &mut state, ctx);
        register(&registry, &mut state, ctx, 31, 1_000).unwrap();
        let err = register(&registry, &mut state, ctx, 31, 1_000).unwrap_err();
        assert!(err.to_string().contains("already queued"));
        // D1: below the floor b=100 (and zero) is refused.
        let err = register(&registry, &mut state, ctx, 32, 99).unwrap_err();
        assert!(err.to_string().contains("D1"), "{err}");
        assert!(register(&registry, &mut state, ctx, 33, 0).is_err());
        register(&registry, &mut state, ctx, 34, 100).unwrap();
    });
    let queue: RingActivationQueue = stored(&state, ioi_types::app::GUARDIAN_RING_QUEUE_KEY);
    assert_eq!(queue.entries.len(), 2);
    assert_eq!(
        queue.activation_depth_events, 2,
        "D_act from the parameters (D3)"
    );
}

#[test]
fn ring_parameters_are_set_once_and_enforce_d3_at_configuration() {
    let registry = ring_test_registry();
    let mut state = MockState::default();
    with_ctx(|ctx| {
        let mut too_shallow = ring_params();
        too_shallow.activation_depth_events = too_shallow.snapshot_to_beacon_events - 1;
        let err = call(
            &registry,
            &mut state,
            ctx,
            "publish_ring_selection_params@v1",
            &codec::to_bytes_canonical(&too_shallow).unwrap(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("D3"), "{err}");
        publish_params(&registry, &mut state, ctx);
        assert!(call(
            &registry,
            &mut state,
            ctx,
            "publish_ring_selection_params@v1",
            &codec::to_bytes_canonical(&ring_params()).unwrap(),
        )
        .unwrap_err()
        .to_string()
        .contains("already set"));
    });
}

/// SCQ-8.10c (v) and SCQ-8.10b (2): the genesis ring is EXACTLY the selector's draw from the
/// genesis snapshot and its beacon; any configured ring (another member, another seat order,
/// other bonds, a vacancy) is refused; the registry starts each member at its balanced offset and
/// records the offsets.
#[test]
fn the_genesis_ring_is_the_selector_draw_and_no_configuration_chooses_it() {
    let registry = ring_test_registry();
    let mut state = MockState::default();
    let mut drawn_members = Vec::new();
    let mut genesis_beacon = [0u8; 32];
    with_ctx(|ctx| {
        publish_params(&registry, &mut state, ctx);
        for b in 1u8..=4 {
            register(&registry, &mut state, ctx, b, 100).unwrap();
        }
        register(&registry, &mut state, ctx, 5, 100).unwrap();
        let configured = |members: Vec<AccountId>| BoundaryRingConfig {
            version: 1,
            member_bonds: members.iter().map(|m| (*m, 100)).collect(),
            members,
            activated_at_event: 0,
            closed_by: None,
            vacant_seats: vec![],
        };
        let publish = |state: &mut MockState, ctx: &mut TxContext<'_>, config: &BoundaryRingConfig| {
            call(
                &registry,
                state,
                ctx,
                "publish_ring_genesis_config@v1",
                &codec::to_bytes_canonical(config).unwrap(),
            )
        };
        // No snapshot yet: a configured genesis ring is refused.
        let err = publish(
            &mut state,
            ctx,
            &configured(vec![ring_member(1), ring_member(2), ring_member(3)]),
        )
        .unwrap_err();
        assert!(err.to_string().contains("snapshot"), "{err}");

        let (genesis_pending, beacon) = snapshot_and_beacon_raw(&registry, &mut state, ctx, 6);
        genesis_beacon = beacon;
        assert!(genesis_pending.snapshot.is_genesis());
        assert_eq!(genesis_pending.snapshot.seat_count, 3);
        assert_eq!(genesis_pending.snapshot.vacancies.len(), 3);
        assert_eq!(genesis_pending.snapshot.candidates.len(), 4);
        let draw = ioi_types::app::draw_genesis_ring(&genesis_pending.snapshot, &beacon).unwrap();
        drawn_members = draw.successor_members.clone();
        let excluded = (1u8..=4)
            .map(ring_member)
            .find(|m| !drawn_members.contains(m))
            .unwrap();

        // Another member in a drawn seat: refused.
        let mut swapped = drawn_members.clone();
        swapped[0] = excluded;
        assert!(publish(&mut state, ctx, &configured(swapped))
            .unwrap_err()
            .to_string()
            .contains("genesis ring differs"));
        // The drawn members in another seat order: refused.
        let mut reordered = drawn_members.clone();
        reordered.rotate_left(1);
        assert!(publish(&mut state, ctx, &configured(reordered))
            .unwrap_err()
            .to_string()
            .contains("genesis ring differs"));
        // Other bonds: refused.
        let mut rebonded = configured(drawn_members.clone());
        rebonded.member_bonds.insert(drawn_members[0], 1);
        assert!(publish(&mut state, ctx, &rebonded)
            .unwrap_err()
            .to_string()
            .contains("bonds"));
        // A vacancy: refused.
        let mut with_vacancy = configured(drawn_members.clone());
        with_vacancy.vacant_seats = vec![ioi_types::app::RingVacancy::default()];
        assert!(publish(&mut state, ctx, &with_vacancy).is_err());
        // The draw lands, once.
        publish(&mut state, ctx, &configured(drawn_members.clone())).unwrap();
        assert!(publish(&mut state, ctx, &configured(drawn_members.clone()))
            .unwrap_err()
            .to_string()
            .contains("already exists"));
    });

    assert_eq!(live_config(&state).members, drawn_members);
    let offsets = ioi_types::app::genesis_tenure_offsets(
        &genesis_beacon,
        &drawn_members,
        ring_params().tenure_handovers,
    );
    let record: ioi_types::app::RingHandoverRecord =
        stored(&state, &ioi_types::app::guardian_ring_handover_record_key(1));
    assert_eq!(record.tenure_counters, offsets);
    let mut values: Vec<u32> = offsets.iter().map(|(_, o)| *o).collect();
    values.sort();
    assert_eq!(values, vec![0, 1, 2], "⌊k·T/n⌋ for n=3, T=4");
    let ledger: ioi_types::app::RingSeatLedger =
        stored(&state, ioi_types::app::GUARDIAN_RING_SEAT_LEDGER_KEY);
    assert_eq!(ledger.version, 1);
    assert_eq!(ledger.handover_index, 0);
    assert_eq!(
        ledger.seat_offsets,
        offsets.iter().map(|(_, o)| *o).collect::<Vec<_>>(),
        "the offsets are kept as the seats' phases, in seat order"
    );
    assert_eq!(
        ledger.tenure,
        offsets.into_iter().collect::<BTreeMap<_, _>>()
    );
    let queue: RingActivationQueue = stored(&state, ioi_types::app::GUARDIAN_RING_QUEUE_KEY);
    assert!(queue
        .entries
        .iter()
        .all(|entry| !drawn_members.contains(&entry.account_id)));
    assert!(state
        .get(ioi_types::app::GUARDIAN_RING_HANDOVER_SNAPSHOT_KEY)
        .unwrap()
        .is_none());
}

#[test]
fn the_handover_is_the_recomputed_draw_and_the_old_ring_cannot_choose() {
    let registry = ring_test_registry();
    let mut state = MockState::default();
    let mut joiner = ring_member(0);
    let mut genesis_members = Vec::new();
    with_ctx(|ctx| {
        let genesis = setup_ring(&registry, &mut state, ctx);
        genesis_members = genesis.members.clone();
        // Only member 2 may declare member 2's exit.
        assert!(call(
            &registry,
            &mut state,
            ctx,
            "declare_ring_exit@v1",
            &codec::to_bytes_canonical(&ring_member(2)).unwrap(),
        )
        .is_err());
        ctx.signer_account_id = ring_member(2);
        call(
            &registry,
            &mut state,
            ctx,
            "declare_ring_exit@v1",
            &codec::to_bytes_canonical(&ring_member(2)).unwrap(),
        )
        .unwrap();
        call(&registry, &mut state, ctx, "commit_ring_handover_snapshot@v1", &[]).unwrap();
        // No genesis seat's counter reaches T = 4 at the first handover (offsets 0, 1, 2 rotate
        // at T − o ≥ 2): only the exit vacates.
        assert_eq!(pending(&state).snapshot.vacated_set, vec![ring_member(2)]);
        assert!(pending(&state).snapshot.forced_rotations.is_empty());

        // No beacon yet: no handover.
        let early = publication_for(&genesis, genesis.members.clone(), vec![], Default::default());
        assert!(call(
            &registry,
            &mut state,
            ctx,
            "publish_ring_handover@v1",
            &codec::to_bytes_canonical(&early).unwrap()
        )
        .unwrap_err()
        .to_string()
        .contains("beacon"));
        // A beacon claimed from old-ring signatures: refused (grinding).
        let grinding = codec::to_bytes_canonical(&ioi_types::app::RingBeaconRecordRequest {
            snapshot_commitment: pending(&state).commitment,
            source: ioi_types::app::RingBeaconSource::OldRingSignatures,
        })
        .unwrap();
        assert!(call(&registry, &mut state, ctx, "record_ring_handover_beacon@v1", &grinding)
            .unwrap_err()
            .to_string()
            .contains("old-ring signatures"));
        // Too soon after the snapshot (the interval is two ring events).
        let request = beacon_request(&state);
        assert!(call(&registry, &mut state, ctx, "record_ring_handover_beacon@v1", &request)
            .unwrap_err()
            .to_string()
            .contains("ring events after the snapshot"));
        register(&registry, &mut state, ctx, 20, 150).unwrap();
        call(&registry, &mut state, ctx, "record_ring_handover_beacon@v1", &request).unwrap();

        let pending_handover = pending(&state);
        let (beacon, _, _) = pending_handover.beacon.expect("beacon recorded");
        let draw = ioi_types::app::draw_vacated_seats(&pending_handover.snapshot, &beacon).unwrap();
        assert_eq!(draw.joiners.len(), 1);
        joiner = draw.joiners[0];
        // The old ring picks a DIFFERENT activatable registrant: refused, whatever its approvals.
        let other = [4u8, 5, 6, 7]
            .iter()
            .map(|b| ring_member(*b))
            .find(|m| *m != joiner)
            .unwrap();
        let chosen_members: Vec<AccountId> = draw
            .successor_members
            .iter()
            .map(|m| if *m == joiner { other } else { *m })
            .collect();
        let chosen = publication_for(
            &genesis,
            chosen_members.clone(),
            vec![],
            bonds_for(&genesis, &chosen_members),
        );
        assert!(call(
            &registry,
            &mut state,
            ctx,
            "publish_ring_handover@v1",
            &codec::to_bytes_canonical(&chosen).unwrap()
        )
        .unwrap_err()
        .to_string()
        .contains("recomputed"));
        // The drawn successor with (n-1) approvals: refused by the ceremony.
        let drawn = drawn_publication(&genesis, &draw);
        let thin = RingHandoverPublication {
            approvals: drawn.approvals[..2].to_vec(),
            ..drawn.clone()
        };
        assert!(call(
            &registry,
            &mut state,
            ctx,
            "publish_ring_handover@v1",
            &codec::to_bytes_canonical(&thin).unwrap()
        )
        .unwrap_err()
        .to_string()
        .contains("UNANIMITY"));
        // RED CONTROL (inherited phase): the drawn joiner in a seat the draw did not assign it
        // (swapped with a kept member, so it would take that seat's phase): refused.
        let joiner_seat = draw
            .successor_members
            .iter()
            .position(|m| *m == joiner)
            .unwrap();
        let mut swapped_members = draw.successor_members.clone();
        let neighbour = (joiner_seat + 1) % swapped_members.len();
        swapped_members.swap(joiner_seat, neighbour);
        let swapped = publication_for(
            &genesis,
            swapped_members.clone(),
            vec![],
            bonds_for(&genesis, &swapped_members),
        );
        assert!(call(
            &registry,
            &mut state,
            ctx,
            "publish_ring_handover@v1",
            &codec::to_bytes_canonical(&swapped).unwrap()
        )
        .unwrap_err()
        .to_string()
        .contains("recomputed"));
        // Rewritten bonds: refused.
        let mut rewritten = drawn.clone();
        rewritten.new_config.member_bonds.insert(joiner, 1);
        assert!(call(
            &registry,
            &mut state,
            ctx,
            "publish_ring_handover@v1",
            &codec::to_bytes_canonical(&rewritten).unwrap()
        )
        .is_err());
        // The drawn successor lands, the exited seat taken in place.
        call(
            &registry,
            &mut state,
            ctx,
            "publish_ring_handover@v1",
            &codec::to_bytes_canonical(&drawn).unwrap(),
        )
        .unwrap();
        let expected: Vec<AccountId> = genesis
            .members
            .iter()
            .map(|m| if *m == ring_member(2) { joiner } else { *m })
            .collect();
        assert_eq!(draw.successor_members, expected);
    });

    let record: ioi_types::app::RingHandoverRecord =
        stored(&state, &ioi_types::app::guardian_ring_handover_record_key(2));
    assert_eq!(record.vacated_set, vec![ring_member(2)]);
    assert!(record.alarms.is_empty() && record.successor_vacancies.is_empty());
    assert_eq!(
        record.beacon_source,
        ioi_types::app::RingBeaconSource::Reference
    );
    assert!(state
        .get(ioi_types::app::GUARDIAN_RING_HANDOVER_SNAPSHOT_KEY)
        .unwrap()
        .is_none());
    let locks: Vec<ioi_types::app::RingBondLock> =
        stored(&state, ioi_types::app::GUARDIAN_RING_BOND_LOCKS_KEY);
    assert_eq!(locks.len(), 1);
    assert_eq!(locks[0].member, ring_member(2));
    assert_eq!(locks[0].amount, 100);
    // The joiner inherits the exited seat's phase: member 2's genesis offset advanced by one
    // handover, mod T.
    let genesis_record: ioi_types::app::RingHandoverRecord =
        stored(&state, &ioi_types::app::guardian_ring_handover_record_key(1));
    let offset_of_2 = genesis_record
        .tenure_counters
        .iter()
        .find(|(m, _)| *m == ring_member(2))
        .unwrap()
        .1;
    let ledger: ioi_types::app::RingSeatLedger =
        stored(&state, ioi_types::app::GUARDIAN_RING_SEAT_LEDGER_KEY);
    assert_eq!(ledger.handover_index, 1);
    assert_eq!(
        ledger.tenure[&joiner],
        ioi_types::app::seat_phase(offset_of_2, 1, 4),
        "the joiner holds member 2's seat's phase after the handover, never a fresh counter"
    );
    assert_ne!(ledger.tenure[&joiner], 0);
    assert_eq!(genesis_members.len(), 3);
    // The closed configuration names its successor.
    let closed: BoundaryRingConfig = stored(&state, &guardian_ring_config_key(1));
    assert_eq!(closed.closed_by.expect("closed").successor_version, 2);
}

/// RED CONTROL (inherited phase, at the registry): a seat ledger in which a joiner does not hold
/// its seat's phase (a fresh or other non-assigned counter) is refused at the next snapshot, so no
/// handover can proceed from it.
#[test]
fn a_ledger_holding_a_joiner_off_its_seats_phase_is_refused_at_the_next_snapshot() {
    let registry = ring_test_registry();
    let mut state = MockState::default();
    with_ctx(|ctx| {
        let genesis = setup_ring(&registry, &mut state, ctx);
        ctx.signer_account_id = ring_member(2);
        call(
            &registry,
            &mut state,
            ctx,
            "declare_ring_exit@v1",
            &codec::to_bytes_canonical(&ring_member(2)).unwrap(),
        )
        .unwrap();
        let draw = snapshot_and_beacon(&registry, &mut state, ctx, 20);
        call(
            &registry,
            &mut state,
            ctx,
            "publish_ring_handover@v1",
            &codec::to_bytes_canonical(&drawn_publication(&genesis, &draw)).unwrap(),
        )
        .unwrap();
        let joiner = draw.joiners[0];
        let honest: ioi_types::app::RingSeatLedger =
            stored(&state, ioi_types::app::GUARDIAN_RING_SEAT_LEDGER_KEY);
        let assigned = honest.tenure[&joiner];
        for wrong in [0u32, 1, 2, 3, 4].into_iter().filter(|t| *t != assigned) {
            let mut tampered = honest.clone();
            tampered.tenure.insert(joiner, wrong);
            state
                .insert(
                    ioi_types::app::GUARDIAN_RING_SEAT_LEDGER_KEY,
                    &codec::to_bytes_canonical(&tampered).unwrap(),
                )
                .unwrap();
            let err = call(&registry, &mut state, ctx, "commit_ring_handover_snapshot@v1", &[])
                .unwrap_err();
            assert!(err.to_string().contains("assigned phase"), "tenure {wrong}: {err}");
        }
        // The honest ledger: the snapshot is taken.
        state
            .insert(
                ioi_types::app::GUARDIAN_RING_SEAT_LEDGER_KEY,
                &codec::to_bytes_canonical(&honest).unwrap(),
            )
            .unwrap();
        call(&registry, &mut state, ctx, "commit_ring_handover_snapshot@v1", &[]).unwrap();
    });
}

/// SCQ-8.10d: all three members exit at once; the churn cap (2) refills two seats and the third
/// stays VACANT (n is still 3). The publication must name the vacancy. The next handover refills
/// the oldest vacancy first.
#[test]
fn an_exit_the_cap_cannot_refill_leaves_a_vacancy_the_next_handover_refills_first() {
    let registry = ring_test_registry();
    let mut state = MockState::default();
    with_ctx(|ctx| {
        let genesis = setup_ring(&registry, &mut state, ctx);
        for member in &genesis.members {
            ctx.signer_account_id = *member;
            call(
                &registry,
                &mut state,
                ctx,
                "declare_ring_exit@v1",
                &codec::to_bytes_canonical(member).unwrap(),
            )
            .unwrap();
        }
        let draw = snapshot_and_beacon(&registry, &mut state, ctx, 21);
        assert_eq!(draw.departed.len(), 3);
        assert_eq!(draw.joiners.len(), 2);
        assert_eq!(draw.successor_vacancies.len(), 1);
        assert_eq!(draw.successor_vacancies[0].seat, 2, "exits refill in seat order");
        // A publication without the vacancy (the seated members only): refused.
        let hidden = publication_for(
            &genesis,
            draw.successor_members.clone(),
            vec![],
            bonds_for(&genesis, &draw.successor_members),
        );
        assert!(call(
            &registry,
            &mut state,
            ctx,
            "publish_ring_handover@v1",
            &codec::to_bytes_canonical(&hidden).unwrap()
        )
        .unwrap_err()
        .to_string()
        .contains("recomputed"));
        let with_vacancy = drawn_publication(&genesis, &draw);
        call(
            &registry,
            &mut state,
            ctx,
            "publish_ring_handover@v1",
            &codec::to_bytes_canonical(&with_vacancy).unwrap(),
        )
        .unwrap();
        let ring = live_config(&state);
        assert_eq!(ring.seat_count(), 3, "a vacancy never reduces n");
        assert_eq!(ring.seats().unwrap()[2], None);
        let record: ioi_types::app::RingHandoverRecord =
            stored(&state, &ioi_types::app::guardian_ring_handover_record_key(2));
        assert_eq!(record.successor_vacancies, draw.successor_vacancies);

        // Keep the pool stocked past D_act, then the next handover refills seat 2 first.
        for b in 30u8..33 {
            register(&registry, &mut state, ctx, b, 150).unwrap();
        }
        let next = snapshot_and_beacon(&registry, &mut state, ctx, 33);
        assert!(next.successor_vacancies.is_empty(), "{:?}", next.successor_vacancies);
        assert!(next.alarms.is_empty(), "{:?}", next.alarms);
        call(
            &registry,
            &mut state,
            ctx,
            "publish_ring_handover@v1",
            &codec::to_bytes_canonical(&drawn_publication(&ring, &next)).unwrap(),
        )
        .unwrap();
        let refilled = live_config(&state);
        assert!(refilled.vacant_seats.is_empty());
        assert_eq!(refilled.seat_count(), 3);
    });
}

/// The seat ledger carries the balanced phases: a handover snapshot refuses a ledger that does
/// not describe the live ring (it is never re-created at tenure 0, which would synchronize every
/// seat's rotation).
#[test]
fn a_handover_snapshot_refuses_a_seat_ledger_that_does_not_describe_the_live_ring() {
    let registry = ring_test_registry();
    let mut state = MockState::default();
    with_ctx(|ctx| {
        setup_ring(&registry, &mut state, ctx);
        let honest: ioi_types::app::RingSeatLedger =
            stored(&state, ioi_types::app::GUARDIAN_RING_SEAT_LEDGER_KEY);
        // A ledger for another version: refused.
        let mut stale = honest.clone();
        stale.version += 1;
        state
            .insert(
                ioi_types::app::GUARDIAN_RING_SEAT_LEDGER_KEY,
                &codec::to_bytes_canonical(&stale).unwrap(),
            )
            .unwrap();
        let err = call(&registry, &mut state, ctx, "commit_ring_handover_snapshot@v1", &[])
            .unwrap_err();
        assert!(err.to_string().contains("seat ledger"), "{err}");
        // No ledger: refused.
        state
            .delete(ioi_types::app::GUARDIAN_RING_SEAT_LEDGER_KEY)
            .unwrap();
        let err = call(&registry, &mut state, ctx, "commit_ring_handover_snapshot@v1", &[])
            .unwrap_err();
        assert!(err.to_string().contains("seat ledger"), "{err}");
    });
}

/// INHERITED PHASE at settlement: a draw whose joiner does not hold its seat's phase is refused
/// by `settle_ring_handover`, which checks the new ledger BEFORE writing anything (no record, no
/// ledger change, the pending snapshot kept).
#[test]
fn settlement_refuses_a_joiner_off_its_seats_phase_and_writes_nothing() {
    let registry = ring_test_registry();
    let mut state = MockState::default();
    with_ctx(|ctx| {
        let genesis = setup_ring(&registry, &mut state, ctx);
        ctx.signer_account_id = ring_member(2);
        call(
            &registry,
            &mut state,
            ctx,
            "declare_ring_exit@v1",
            &codec::to_bytes_canonical(&ring_member(2)).unwrap(),
        )
        .unwrap();
        let (pending_handover, beacon) = snapshot_and_beacon_raw(&registry, &mut state, ctx, 20);
        let mut draw =
            ioi_types::app::draw_vacated_seats(&pending_handover.snapshot, &beacon).unwrap();
        assert_eq!(draw.joiner_tenure.len(), 1);
        draw.joiner_tenure[0].1 = (draw.joiner_tenure[0].1 + 1) % 4;
        let new_config = drawn_publication(&genesis, &draw).new_config;
        let ledger_before = state
            .get(ioi_types::app::GUARDIAN_RING_SEAT_LEDGER_KEY)
            .unwrap();
        let err = GuardianRegistry::settle_ring_handover(
            &mut state,
            &genesis,
            &new_config,
            &pending_handover,
            &draw,
            0,
        )
        .unwrap_err();
        assert!(err.to_string().contains("assigned phase"), "{err}");
        assert_eq!(
            state
                .get(ioi_types::app::GUARDIAN_RING_SEAT_LEDGER_KEY)
                .unwrap(),
            ledger_before
        );
        assert!(state
            .get(&ioi_types::app::guardian_ring_handover_record_key(2))
            .unwrap()
            .is_none());
        assert!(state
            .get(ioi_types::app::GUARDIAN_RING_HANDOVER_SNAPSHOT_KEY)
            .unwrap()
            .is_some());
    });
}

/// D2: the departed member's bond is locked for W ring events, its re-entry is blocked meanwhile,
/// and the release needs the lock's expiry AND custody succession.
#[test]
fn a_departed_members_bond_is_locked_for_w_and_its_re_entry_waits() {
    let registry = ring_test_registry();
    let mut state = MockState::default();
    with_ctx(|ctx| {
        let genesis = setup_ring(&registry, &mut state, ctx);
        ctx.signer_account_id = ring_member(2);
        call(
            &registry,
            &mut state,
            ctx,
            "declare_ring_exit@v1",
            &codec::to_bytes_canonical(&ring_member(2)).unwrap(),
        )
        .unwrap();
        let draw = snapshot_and_beacon(&registry, &mut state, ctx, 20);
        call(
            &registry,
            &mut state,
            ctx,
            "publish_ring_handover@v1",
            &codec::to_bytes_canonical(&drawn_publication(&genesis, &draw)).unwrap(),
        )
        .unwrap();

        // Re-entry within W: blocked by the lock.
        let err = register(&registry, &mut state, ctx, 2, 150).unwrap_err();
        assert!(err.to_string().contains("D2"), "{err}");
        let receipt = ioi_types::app::CustodyHandoverReceipt {
            member: ring_member(2),
            config_version: 1,
            reconstructed_surface_root: [9u8; 32],
            successor_acknowledgement_bytes: vec![1],
        };
        let release = codec::to_bytes_canonical(&ioi_types::app::RingBondReleaseRequest {
            member: ring_member(2),
            departed_version: 1,
            custody_receipt: receipt.clone(),
        })
        .unwrap();
        let err = call(&registry, &mut state, ctx, "release_ring_bond@v1", &release).unwrap_err();
        assert!(err.to_string().contains("locked until"), "{err}");
        // W = 19 ring events pass (registrations are ring events).
        for b in 40u8..60 {
            register(&registry, &mut state, ctx, b, 150).unwrap();
        }
        // Custody succession still gates the release after W.
        let unacknowledged = codec::to_bytes_canonical(&ioi_types::app::RingBondReleaseRequest {
            member: ring_member(2),
            departed_version: 1,
            custody_receipt: ioi_types::app::CustodyHandoverReceipt {
                successor_acknowledgement_bytes: vec![],
                ..receipt
            },
        })
        .unwrap();
        assert!(call(
            &registry,
            &mut state,
            ctx,
            "release_ring_bond@v1",
            &unacknowledged
        )
        .is_err());
        call(&registry, &mut state, ctx, "release_ring_bond@v1", &release).unwrap();
        // The lock is gone: re-entry is allowed again, with a fresh bond at the floor.
        register(&registry, &mut state, ctx, 2, 100).unwrap();
    });
}

/// The tenure cap with balanced genesis offsets (n=3, T=4: offsets {0, 1, 2}), in the analysed
/// model's convention (B1-R v1, M7 (vi)): nobody exits, and each genesis member rotates at
/// handover T − o, so the member at offset 2 rotates at the second handover, offset 1 at the
/// third and offset 0 at the fourth; no handover rotates more than ⌈n/T⌉ = 1, and every genesis
/// member rotates exactly once.
#[test]
fn members_rotate_at_the_tenure_cap_in_their_balanced_phases() {
    let registry = ring_test_registry();
    let mut state = MockState::default();
    with_ctx(|ctx| {
        let mut ring = setup_ring(&registry, &mut state, ctx);
        let genesis_members = ring.members.clone();
        let genesis_record: ioi_types::app::RingHandoverRecord =
            stored(&state, &ioi_types::app::guardian_ring_handover_record_key(1));
        let mut vacated_by_handover = Vec::new();
        for (round, filler) in [60u8, 61, 62, 63].into_iter().enumerate() {
            let draw = snapshot_and_beacon(&registry, &mut state, ctx, filler);
            assert!(draw.alarms.is_empty(), "{:?}", draw.alarms);
            vacated_by_handover.push(draw.departed.clone());
            let publication = drawn_publication(&ring, &draw);
            call(
                &registry,
                &mut state,
                ctx,
                "publish_ring_handover@v1",
                &codec::to_bytes_canonical(&publication).unwrap(),
            )
            .unwrap();
            ring = publication.new_config;
            // Keep the pool stocked past D_act.
            for b in 0..3u8 {
                register(&registry, &mut state, ctx, 100 + 10 * round as u8 + b, 150).unwrap();
            }
        }
        assert!(vacated_by_handover[0].is_empty());
        for (member, offset) in &genesis_record.tenure_counters {
            let handover = (4 - *offset) as usize;
            assert_eq!(
                vacated_by_handover[handover - 1],
                vec![*member],
                "the genesis member at offset {offset} rotates at handover T − o = {handover}"
            );
        }
        let mut rotated: Vec<AccountId> = vacated_by_handover.concat();
        rotated.sort();
        let mut expected = genesis_members.clone();
        expected.sort();
        assert_eq!(rotated, expected, "each genesis member rotated exactly once");
    });
}

/// Review r1 MAJOR-2: a GENESIS snapshot over a pool the genesis draw cannot fill (fewer than n
/// activatable registrants, or a floor its pool cannot meet) is REFUSED and writes nothing. Before,
/// it was taken, the draw could never succeed, and no later snapshot could replace it (a pending
/// snapshot leaves only through a successful settlement): the ring could never start. After the
/// refusal, once n registrants are activatable, the genesis proceeds.
#[test]
fn an_infeasible_genesis_snapshot_is_refused_writes_nothing_and_the_ring_can_still_start() {
    let registry = ring_test_registry();
    let mut state = MockState::default();
    with_ctx(|ctx| {
        publish_params(&registry, &mut state, ctx);
        register(&registry, &mut state, ctx, 1, 100).unwrap();
        register(&registry, &mut state, ctx, 2, 100).unwrap();
        let counter_before = state
            .get(ioi_types::app::GUARDIAN_RING_EVENT_COUNTER_KEY)
            .unwrap();
        let err = call(&registry, &mut state, ctx, "commit_ring_handover_snapshot@v1", &[])
            .unwrap_err();
        assert!(err.to_string().contains("genesis draw"), "{err}");
        assert!(
            state
                .get(ioi_types::app::GUARDIAN_RING_HANDOVER_SNAPSHOT_KEY)
                .unwrap()
                .is_none(),
            "no snapshot is pending"
        );
        assert_eq!(
            state
                .get(ioi_types::app::GUARDIAN_RING_EVENT_COUNTER_KEY)
                .unwrap(),
            counter_before,
            "a refused snapshot writes nothing"
        );
        // Later registrants: 1..=4 are activatable at the next snapshot (D_act = 2).
        register(&registry, &mut state, ctx, 3, 100).unwrap();
        register(&registry, &mut state, ctx, 4, 150).unwrap();
        register(&registry, &mut state, ctx, 5, 150).unwrap();
        let (genesis_pending, beacon) = snapshot_and_beacon_raw(&registry, &mut state, ctx, 6);
        assert!(genesis_pending.snapshot.is_genesis());
        assert!(genesis_pending.snapshot.candidates.len() >= 3);
        let draw = ioi_types::app::draw_genesis_ring(&genesis_pending.snapshot, &beacon).unwrap();
        let genesis = BoundaryRingConfig {
            version: 1,
            members: draw.successor_members.clone(),
            member_bonds: genesis_pending
                .snapshot
                .candidates
                .iter()
                .filter(|c| draw.successor_members.contains(&c.account_id))
                .map(|c| (c.account_id, c.bond_amount))
                .collect(),
            activated_at_event: 0,
            closed_by: None,
            vacant_seats: vec![],
        };
        call(
            &registry,
            &mut state,
            ctx,
            "publish_ring_genesis_config@v1",
            &codec::to_bytes_canonical(&genesis).unwrap(),
        )
        .unwrap();
        assert_eq!(live_config(&state).members, draw.successor_members);
    });
}

/// Review r1 MAJOR-3 (the trunk's "joiner consumed from the queue", lost in the replacement): a
/// handover takes its joiners out of the activation queue, so a joiner that later departs is never
/// a candidate again while its bond is locked (D2: re-entry needs a new registration, refused
/// during the lock). The reviewer's probe, kept as a pin.
#[test]
fn a_handover_takes_its_joiners_out_of_the_queue_so_a_departed_joiner_is_not_redrawn() {
    let registry = ring_test_registry();
    let mut state = MockState::default();
    with_ctx(|ctx| {
        let genesis = setup_ring(&registry, &mut state, ctx);
        ctx.signer_account_id = ring_member(2);
        call(
            &registry,
            &mut state,
            ctx,
            "declare_ring_exit@v1",
            &codec::to_bytes_canonical(&ring_member(2)).unwrap(),
        )
        .unwrap();
        let draw = snapshot_and_beacon(&registry, &mut state, ctx, 20);
        call(
            &registry,
            &mut state,
            ctx,
            "publish_ring_handover@v1",
            &codec::to_bytes_canonical(&drawn_publication(&genesis, &draw)).unwrap(),
        )
        .unwrap();
        assert_eq!(draw.joiners.len(), 1);
        let joiner = draw.joiners[0];
        let queue: RingActivationQueue = stored(&state, ioi_types::app::GUARDIAN_RING_QUEUE_KEY);
        assert!(
            queue.entries.iter().all(|entry| entry.account_id != joiner),
            "the handover consumed its joiner's queue entry"
        );
        let ring1 = live_config(&state);
        ctx.signer_account_id = joiner;
        call(
            &registry,
            &mut state,
            ctx,
            "declare_ring_exit@v1",
            &codec::to_bytes_canonical(&joiner).unwrap(),
        )
        .unwrap();
        let draw2 = snapshot_and_beacon(&registry, &mut state, ctx, 21);
        assert!(draw2.departed.contains(&joiner), "the joiner departs at the second handover");
        call(
            &registry,
            &mut state,
            ctx,
            "publish_ring_handover@v1",
            &codec::to_bytes_canonical(&drawn_publication(&ring1, &draw2)).unwrap(),
        )
        .unwrap();
        assert!(
            register(&registry, &mut state, ctx, joiner.0[0], 150).is_err(),
            "re-entry waits for the D2 lock"
        );
        call(&registry, &mut state, ctx, "commit_ring_handover_snapshot@v1", &[]).unwrap();
        assert!(
            pending(&state)
                .snapshot
                .candidates
                .iter()
                .all(|c| c.account_id != joiner),
            "the departed joiner (bond locked, D2) is never a candidate again"
        );
    });
}

/// Review r1 MINOR-2: a handover refused at SETTLEMENT (here a kept member whose ledger counter was
/// moved off its seat's phase after the snapshot) writes nothing: not the ring-event counter, not
/// the activation queue, not the ledger, and the pending snapshot stays. Before, the counter and
/// the queue were written before settlement's checks ran.
#[test]
fn a_handover_refused_at_settlement_writes_nothing() {
    let registry = ring_test_registry();
    let mut state = MockState::default();
    with_ctx(|ctx| {
        let genesis = setup_ring(&registry, &mut state, ctx);
        ctx.signer_account_id = ring_member(2);
        call(
            &registry,
            &mut state,
            ctx,
            "declare_ring_exit@v1",
            &codec::to_bytes_canonical(&ring_member(2)).unwrap(),
        )
        .unwrap();
        let draw = snapshot_and_beacon(&registry, &mut state, ctx, 20);
        let kept = *draw
            .successor_members
            .iter()
            .find(|m| !draw.joiners.contains(m))
            .expect("a kept member");
        let mut ledger: ioi_types::app::RingSeatLedger =
            stored(&state, ioi_types::app::GUARDIAN_RING_SEAT_LEDGER_KEY);
        let served = ledger.tenure[&kept];
        ledger
            .tenure
            .insert(kept, if served > 0 { served - 1 } else { served + 1 });
        state
            .insert(
                ioi_types::app::GUARDIAN_RING_SEAT_LEDGER_KEY,
                &codec::to_bytes_canonical(&ledger).unwrap(),
            )
            .unwrap();
        let keys: Vec<Vec<u8>> = vec![
            ioi_types::app::GUARDIAN_RING_EVENT_COUNTER_KEY.to_vec(),
            ioi_types::app::GUARDIAN_RING_QUEUE_KEY.to_vec(),
            ioi_types::app::GUARDIAN_RING_SEAT_LEDGER_KEY.to_vec(),
            ioi_types::app::GUARDIAN_RING_HANDOVER_SNAPSHOT_KEY.to_vec(),
            ioi_types::app::GUARDIAN_RING_LIVE_VERSION_KEY.to_vec(),
        ];
        let before: Vec<Option<Vec<u8>>> = keys.iter().map(|k| state.get(k).unwrap()).collect();
        let err = call(
            &registry,
            &mut state,
            ctx,
            "publish_ring_handover@v1",
            &codec::to_bytes_canonical(&drawn_publication(&genesis, &draw)).unwrap(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("phase"), "refused at settlement: {err}");
        let after: Vec<Option<Vec<u8>>> = keys.iter().map(|k| state.get(k).unwrap()).collect();
        assert_eq!(after, before, "a handover refused at settlement writes nothing");
    });
}

/// Q1 (C) (rulings 2026-10-08 14:54): the REFERENCE handover beacon is predictable at snapshot time
/// and recorder-choosable (REFERENCE-UNBOUNDED: no grinding bound exists for it), so EVERY chain
/// configuration refuses it and fails closed: the production registry, and a registry built from a
/// chain configuration that names a test admission (no configuration key admits it). No beacon is
/// recorded, so no draw can be made until a bounded source lands (R11's VDF, or OBS-6b). The
/// parameters are R = 0 (every chain configuration refuses R >= 1).
#[test]
fn the_reference_handover_beacon_is_refused_in_every_chain_configuration() {
    let mut named = serde_json::to_value(GuardianRegistryParams {
        enabled: true,
        ..Default::default()
    })
    .unwrap();
    named["ring_reference_beacon"] = serde_json::json!("reference_unbounded_for_tests");
    named["ring_selection_admission"] = serde_json::json!("test_only");
    named["reference_unbounded"] = serde_json::json!(true);
    let from_chain_config = GuardianRegistry::new(serde_json::from_value(named).unwrap());
    let mut r0 = ring_params();
    r0.floors = vec![ioi_types::app::ConstituencyFloor { constituency_id: 0, min_seats: 3 }];
    for registry in [production_registry(), from_chain_config] {
        let mut state = MockState::default();
        with_ctx(|ctx| {
            call(
                &registry,
                &mut state,
                ctx,
                "publish_ring_selection_params@v1",
                &codec::to_bytes_canonical(&r0).unwrap(),
            )
            .unwrap();
            for b in 1u8..=4 {
                register(&registry, &mut state, ctx, b, 100).unwrap();
            }
            register(&registry, &mut state, ctx, 5, 150).unwrap();
            call(&registry, &mut state, ctx, "commit_ring_handover_snapshot@v1", &[]).unwrap();
            register(&registry, &mut state, ctx, 6, 150).unwrap();
            let request = beacon_request(&state);
            let err = call(&registry, &mut state, ctx, "record_ring_handover_beacon@v1", &request)
                .unwrap_err();
            assert!(err.to_string().contains("REFERENCE-UNBOUNDED"), "{err}");
            assert!(pending(&state).beacon.is_none(), "no beacon is recorded");
        });
    }
}

/// Q2 (rulings 2026-10-08, PROVISIONAL), with NET's conditions (a)-(d) and B3. A handover publishes
/// the EXACT draw, with no joiner's acceptance in it (the joiners accept ON CHAIN, by the deadline
/// s_h + Δ_b + W_acc); an acceptance never changes the draw or the fill (B3). A joiner that has not
/// accepted is ABSENT (its seat is held, it is never a vote, n never shrinks) and, once its window
/// has closed, it is a DEPARTURE fixed at the next snapshot, refilled in the same capped fill order
/// and counted in the liveness budget. The next snapshot waits for every acceptance window.
#[test]
fn a_drawn_joiner_accepts_on_chain_or_is_absent_and_departs_at_the_next_handover() {
    let registry = ring_test_registry();
    let mut state = MockState::default();
    with_ctx(|ctx| {
        let mut p = ring_params();
        p.handover_interval_events = 12;
        p.bond_lock_events = 4 * 12 + 3;
        p.acceptance_window_events = 6;
        call(
            &registry,
            &mut state,
            ctx,
            "publish_ring_selection_params@v1",
            &codec::to_bytes_canonical(&p).unwrap(),
        )
        .unwrap();
        for b in 1u8..=3 {
            register(&registry, &mut state, ctx, b, 100).unwrap();
        }
        register(&registry, &mut state, ctx, 4, 150).unwrap();
        let (genesis_pending, beacon) = snapshot_and_beacon_raw(&registry, &mut state, ctx, 5);
        let gdraw = ioi_types::app::draw_genesis_ring(&genesis_pending.snapshot, &beacon).unwrap();
        let genesis = BoundaryRingConfig {
            version: 1,
            members: gdraw.successor_members.clone(),
            member_bonds: gdraw.successor_members.iter().map(|m| (*m, 100)).collect(),
            activated_at_event: 0,
            closed_by: None,
            vacant_seats: vec![],
        };
        call(
            &registry,
            &mut state,
            ctx,
            "publish_ring_genesis_config@v1",
            &codec::to_bytes_canonical(&genesis).unwrap(),
        )
        .unwrap();
        for b in 6u8..=9 {
            register(&registry, &mut state, ctx, b, 150).unwrap();
        }
        for member in [ring_member(2), ring_member(3)] {
            ctx.signer_account_id = member;
            call(
                &registry,
                &mut state,
                ctx,
                "declare_ring_exit@v1",
                &codec::to_bytes_canonical(&member).unwrap(),
            )
            .unwrap();
        }
        let (pending_handover, beacon) = snapshot_and_beacon_raw(&registry, &mut state, ctx, 20);
        let draw = ioi_types::app::draw_vacated_seats(&pending_handover.snapshot, &beacon).unwrap();
        assert_eq!(draw.joiners.len(), 2, "two exits, c = 2: two joiners");
        let (accepting, silent) = (draw.joiners[0], draw.joiners[1]);
        let commitment = codec::to_bytes_canonical(&pending_handover.commitment).unwrap();
        // Only a drawn joiner accepts, for itself; an acceptance changes nothing in the draw (B3).
        ctx.signer_account_id = ring_member(1);
        assert!(call(&registry, &mut state, ctx, "accept_ring_handover_seat@v1", &commitment).is_err());
        ctx.signer_account_id = accepting;
        call(&registry, &mut state, ctx, "accept_ring_handover_seat@v1", &commitment).unwrap();
        assert_eq!(
            ioi_types::app::draw_vacated_seats(&pending(&state).snapshot, &beacon).unwrap(),
            draw
        );
        // The publication is the EXACT draw, carrying the old ring's approvals and the KEPT
        // members' acceptances only (a silent joiner can no longer stall it).
        let mut publication = drawn_publication(&genesis, &draw);
        publication
            .acceptances
            .retain(|a| !draw.joiners.contains(&a.member));
        call(
            &registry,
            &mut state,
            ctx,
            "publish_ring_handover@v1",
            &codec::to_bytes_canonical(&publication).unwrap(),
        )
        .unwrap();
        let ring1 = live_config(&state);
        assert_eq!(ring1.members, draw.successor_members, "the fill is the draw's (B3)");
        assert_eq!(ring1.seat_count(), 3, "n never shrinks");
        // While the silent joiner's window is open, the next snapshot is refused (B3: its decision
        // is fixed before that snapshot).
        assert!(call(&registry, &mut state, ctx, "commit_ring_handover_snapshot@v1", &[]).is_err());
        for b in 40u8..50 {
            register(&registry, &mut state, ctx, b, 150).unwrap();
        }
        ctx.signer_account_id = silent;
        assert!(
            call(&registry, &mut state, ctx, "accept_ring_handover_seat@v1", &commitment).is_err(),
            "no acceptance after the deadline"
        );
        // The next handover: the silent joiner is a DEPARTURE, the accepting joiner is not.
        call(&registry, &mut state, ctx, "commit_ring_handover_snapshot@v1", &[]).unwrap();
        let snapshot2 = pending(&state).snapshot;
        assert!(snapshot2.vacated_set.contains(&silent), "{snapshot2:?}");
        assert!(!snapshot2.vacated_set.contains(&accepting));
        register(&registry, &mut state, ctx, 51, 150).unwrap();
        let request = beacon_request(&state);
        call(&registry, &mut state, ctx, "record_ring_handover_beacon@v1", &request).unwrap();
        let pending2 = pending(&state);
        let (beacon2, _, _) = pending2.beacon.unwrap();
        let draw2 = ioi_types::app::draw_vacated_seats(&pending2.snapshot, &beacon2).unwrap();
        assert!(draw2.departed.contains(&silent));
        let silent_seat = ring1.members.iter().position(|m| *m == silent).unwrap();
        let seats2 =
            ioi_types::app::seat_layout(&draw2.successor_members, &draw2.successor_vacancies)
                .unwrap();
        assert!(
            matches!(seats2[silent_seat], Some(next) if next != silent),
            "the seat is refilled within the cap: {seats2:?}"
        );
    });
}

/// Q2 (a) (NET's condition: a joiner that has not accepted is ABSENT and never votes), at the NEXT
/// handover: the old ring's unanimity is over its PRESENT members. A joiner that never accepted (its
/// window closed; it departs at this handover) need not approve, so its silence cannot stall the
/// next handover (review r1 MINOR-1's stall, moved one handover later, is closed); every present
/// member's approval stays required.
#[test]
fn an_absent_joiner_never_votes_so_its_silence_cannot_stall_the_next_handover() {
    let registry = ring_test_registry();
    let mut state = MockState::default();
    with_ctx(|ctx| {
        let mut p = ring_params();
        p.handover_interval_events = 12;
        p.bond_lock_events = 4 * 12 + 3;
        p.acceptance_window_events = 6;
        call(
            &registry,
            &mut state,
            ctx,
            "publish_ring_selection_params@v1",
            &codec::to_bytes_canonical(&p).unwrap(),
        )
        .unwrap();
        for b in 1u8..=3 {
            register(&registry, &mut state, ctx, b, 100).unwrap();
        }
        register(&registry, &mut state, ctx, 4, 150).unwrap();
        let (genesis_pending, beacon) = snapshot_and_beacon_raw(&registry, &mut state, ctx, 5);
        let gdraw = ioi_types::app::draw_genesis_ring(&genesis_pending.snapshot, &beacon).unwrap();
        let genesis = BoundaryRingConfig {
            version: 1,
            members: gdraw.successor_members.clone(),
            member_bonds: gdraw.successor_members.iter().map(|m| (*m, 100)).collect(),
            activated_at_event: 0,
            closed_by: None,
            vacant_seats: vec![],
        };
        call(
            &registry,
            &mut state,
            ctx,
            "publish_ring_genesis_config@v1",
            &codec::to_bytes_canonical(&genesis).unwrap(),
        )
        .unwrap();
        for b in 6u8..=9 {
            register(&registry, &mut state, ctx, b, 150).unwrap();
        }
        for member in [ring_member(2), ring_member(3)] {
            ctx.signer_account_id = member;
            call(
                &registry,
                &mut state,
                ctx,
                "declare_ring_exit@v1",
                &codec::to_bytes_canonical(&member).unwrap(),
            )
            .unwrap();
        }
        let (pending_handover, beacon) = snapshot_and_beacon_raw(&registry, &mut state, ctx, 20);
        let draw = ioi_types::app::draw_vacated_seats(&pending_handover.snapshot, &beacon).unwrap();
        assert_eq!(draw.joiners.len(), 2);
        let (accepting, silent) = (draw.joiners[0], draw.joiners[1]);
        let commitment = codec::to_bytes_canonical(&pending_handover.commitment).unwrap();
        ctx.signer_account_id = accepting;
        call(&registry, &mut state, ctx, "accept_ring_handover_seat@v1", &commitment).unwrap();
        let mut publication = drawn_publication(&genesis, &draw);
        publication
            .acceptances
            .retain(|a| !draw.joiners.contains(&a.member));
        call(
            &registry,
            &mut state,
            ctx,
            "publish_ring_handover@v1",
            &codec::to_bytes_canonical(&publication).unwrap(),
        )
        .unwrap();
        let ring1 = live_config(&state);
        assert!(ring1.members.contains(&silent) && ring1.members.contains(&accepting));
        // The silent joiner's window closes; the next handover is drawn with it as a departure.
        for b in 40u8..50 {
            register(&registry, &mut state, ctx, b, 150).unwrap();
        }
        call(&registry, &mut state, ctx, "commit_ring_handover_snapshot@v1", &[]).unwrap();
        register(&registry, &mut state, ctx, 51, 150).unwrap();
        let request = beacon_request(&state);
        call(&registry, &mut state, ctx, "record_ring_handover_beacon@v1", &request).unwrap();
        let pending2 = pending(&state);
        let (beacon2, _, _) = pending2.beacon.unwrap();
        let draw2 = ioi_types::app::draw_vacated_seats(&pending2.snapshot, &beacon2).unwrap();
        assert!(draw2.departed.contains(&silent));
        // Every PRESENT old member approves; the absent joiner does not; the joiners accept on chain.
        let mut publication2 = drawn_publication(&ring1, &draw2);
        publication2.approvals.retain(|a| a.member != silent);
        publication2
            .acceptances
            .retain(|a| !draw2.joiners.contains(&a.member));
        // A PRESENT member's approval stays required (old-ring unanimity over the present members).
        let mut missing_present = publication2.clone();
        missing_present.approvals.retain(|a| a.member != accepting);
        let err = call(
            &registry,
            &mut state,
            ctx,
            "publish_ring_handover@v1",
            &codec::to_bytes_canonical(&missing_present).unwrap(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("UNANIMITY"), "{err}");
        call(
            &registry,
            &mut state,
            ctx,
            "publish_ring_handover@v1",
            &codec::to_bytes_canonical(&publication2).unwrap(),
        )
        .unwrap();
        assert_eq!(live_config(&state).members, draw2.successor_members);
        assert!(!live_config(&state).members.contains(&silent), "the absent joiner departed");
    });
}

fn register_in(
    registry: &GuardianRegistry,
    state: &mut MockState,
    ctx: &mut TxContext<'_>,
    b: u8,
    constituency: u32,
    bond: u128,
) {
    let registration = RingMemberRegistration {
        account_id: ring_member(b),
        bond_amount: bond,
        constituency_id: constituency,
        registered_at_event: 0,
    };
    call(
        registry,
        state,
        ctx,
        "register_ring_member@v1",
        &codec::to_bytes_canonical(&registration).unwrap(),
    )
    .unwrap();
}

/// Q4 (rulings 2026-10-08 14:54; B1-R v1 M7 (i)): at R = 0 (the floors sum to n) every seat is
/// labelled with its constituency, and a fill seat is refilled ONLY from its own constituency. Here
/// constituency 2 (floor 1, listed first) loses its seat to an exit when its pool is empty (the seat
/// goes vacant); later a constituency-1 seat is FORCED while that vacancy waits beyond the fill set
/// (c = 1). The forced seat is refilled from constituency 1, never from constituency 2's newcomer.
#[test]
fn at_r_0_a_vacated_seat_is_refilled_only_from_its_own_constituency() {
    let registry = ring_test_registry();
    let mut state = MockState::default();
    with_ctx(|ctx| {
        let mut p = ring_params();
        p.churn_cap = 1;
        p.floors = vec![
            ioi_types::app::ConstituencyFloor { constituency_id: 2, min_seats: 1 },
            ioi_types::app::ConstituencyFloor { constituency_id: 1, min_seats: 2 },
        ];
        call(
            &registry,
            &mut state,
            ctx,
            "publish_ring_selection_params@v1",
            &codec::to_bytes_canonical(&p).unwrap(),
        )
        .unwrap();
        register_in(&registry, &mut state, ctx, 1, 1, 100);
        register_in(&registry, &mut state, ctx, 2, 1, 100);
        register_in(&registry, &mut state, ctx, 3, 2, 100);
        register_in(&registry, &mut state, ctx, 10, 1, 150);
        register_in(&registry, &mut state, ctx, 11, 1, 150);
        let (genesis_pending, beacon) = snapshot_and_beacon_raw(&registry, &mut state, ctx, 5);
        let draw = ioi_types::app::draw_genesis_ring(&genesis_pending.snapshot, &beacon).unwrap();
        assert_eq!(draw.successor_members[0], ring_member(3), "constituency 2's floor fills seat 0");
        let genesis = BoundaryRingConfig {
            version: 1,
            members: draw.successor_members.clone(),
            member_bonds: genesis_pending
                .snapshot
                .candidates
                .iter()
                .filter(|c| draw.successor_members.contains(&c.account_id))
                .map(|c| (c.account_id, c.bond_amount))
                .collect(),
            activated_at_event: 0,
            closed_by: None,
            vacant_seats: vec![],
        };
        call(
            &registry,
            &mut state,
            ctx,
            "publish_ring_genesis_config@v1",
            &codec::to_bytes_canonical(&genesis).unwrap(),
        )
        .unwrap();
        let ledger: ioi_types::app::RingSeatLedger =
            stored(&state, ioi_types::app::GUARDIAN_RING_SEAT_LEDGER_KEY);
        // The first handover at which a constituency-1 seat (1 or 2) is forced: T - offset.
        let first_forced = (1..=2usize)
            .map(|seat| u64::from(p.tenure_handovers - ledger.seat_offsets[seat]))
            .min()
            .unwrap();
        assert!((2..=4).contains(&first_forced), "{first_forced}");
        // Handover 1: constituency 2's member exits; its pool is empty, so its seat goes vacant.
        ctx.signer_account_id = ring_member(3);
        call(
            &registry,
            &mut state,
            ctx,
            "declare_ring_exit@v1",
            &codec::to_bytes_canonical(&ring_member(3)).unwrap(),
        )
        .unwrap();
        let mut ring = genesis;
        for h in 1..first_forced {
            call(&registry, &mut state, ctx, "commit_ring_handover_snapshot@v1", &[]).unwrap();
            // Before the handover that precedes the forced one, constituency 2 gains a newcomer,
            // too late for this snapshot and activatable at the next.
            if h + 1 == first_forced {
                register_in(&registry, &mut state, ctx, 30, 2, 150);
            } else {
                register(&registry, &mut state, ctx, 60 + h as u8, 150).unwrap();
            }
            let request = beacon_request(&state);
            call(&registry, &mut state, ctx, "record_ring_handover_beacon@v1", &request).unwrap();
            let pending_handover = pending(&state);
            let (beacon, _, _) = pending_handover.beacon.unwrap();
            let step = ioi_types::app::draw_vacated_seats(&pending_handover.snapshot, &beacon).unwrap();
            assert!(step.joiners.is_empty(), "h={h}: constituency 2's pool is empty");
            assert!(step.successor_vacancies.iter().any(|v| v.seat == 0));
            call(
                &registry,
                &mut state,
                ctx,
                "publish_ring_handover@v1",
                &codec::to_bytes_canonical(&drawn_publication(&ring, &step)).unwrap(),
            )
            .unwrap();
            ring = live_config(&state);
        }
        // The forced handover: the fill set is the forced constituency-1 seat (c = 1); seat 0's
        // vacancy waits beyond it.
        let draw = snapshot_and_beacon(&registry, &mut state, ctx, 70);
        assert_eq!(draw.joiners.len(), 1);
        let joined = draw.joiners[0];
        assert_ne!(joined, ring_member(30), "constituency 2's newcomer never fills a constituency-1 seat");
        assert!(
            [1u8, 2, 10, 11].iter().any(|b| ring_member(*b) == joined),
            "refilled from constituency 1: {joined:?}"
        );
        assert!(draw.successor_vacancies.iter().any(|v| v.seat == 0), "seat 0 still waits");
        call(
            &registry,
            &mut state,
            ctx,
            "publish_ring_handover@v1",
            &codec::to_bytes_canonical(&drawn_publication(&ring, &draw)).unwrap(),
        )
        .unwrap();
    });
}

/// Q4 (rulings 2026-10-08 15:16): every chain configuration REFUSES ring parameters with non-floor
/// seats (R >= 1): no checker family covers them yet (NET's queue), so they fail closed. R = 0
/// parameters (the floors sum to n) are taken.
#[test]
fn ring_parameters_with_non_floor_seats_are_refused_in_every_chain_configuration() {
    let chain_registry = production_registry();
    let mut state = MockState::default();
    with_ctx(|ctx| {
        let err = call(
            &chain_registry,
            &mut state,
            ctx,
            "publish_ring_selection_params@v1",
            &codec::to_bytes_canonical(&ring_params()).unwrap(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("R >= 1"), "R = 3: {err}");
        let mut one_free = ring_params();
        one_free.floors = vec![ioi_types::app::ConstituencyFloor { constituency_id: 0, min_seats: 2 }];
        let err = call(
            &chain_registry,
            &mut state,
            ctx,
            "publish_ring_selection_params@v1",
            &codec::to_bytes_canonical(&one_free).unwrap(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("R >= 1"), "R = 1: {err}");
        let mut r0 = ring_params();
        r0.floors = vec![ioi_types::app::ConstituencyFloor { constituency_id: 0, min_seats: 3 }];
        call(
            &chain_registry,
            &mut state,
            ctx,
            "publish_ring_selection_params@v1",
            &codec::to_bytes_canonical(&r0).unwrap(),
        )
        .unwrap();
    });
}

/// B3 (NET's B1-R R1 finding): every exit decision that affects a handover is fixed at its committed
/// snapshot, BEFORE the beacon. An exit declared after the beacon changes neither that handover's
/// draw nor its fill (a publication honouring it is refused); it is planned at the next snapshot.
#[test]
fn an_exit_declared_after_the_beacon_changes_neither_the_draw_nor_the_fill() {
    let registry = ring_test_registry();
    let mut state = MockState::default();
    with_ctx(|ctx| {
        let genesis = setup_ring(&registry, &mut state, ctx);
        ctx.signer_account_id = ring_member(2);
        call(
            &registry,
            &mut state,
            ctx,
            "declare_ring_exit@v1",
            &codec::to_bytes_canonical(&ring_member(2)).unwrap(),
        )
        .unwrap();
        let (_, beacon) = snapshot_and_beacon_raw(&registry, &mut state, ctx, 20);
        let draw = ioi_types::app::draw_vacated_seats(&pending(&state).snapshot, &beacon).unwrap();
        // After the beacon, member 1 declares its exit.
        ctx.signer_account_id = ring_member(1);
        call(
            &registry,
            &mut state,
            ctx,
            "declare_ring_exit@v1",
            &codec::to_bytes_canonical(&ring_member(1)).unwrap(),
        )
        .unwrap();
        assert_eq!(
            ioi_types::app::draw_vacated_seats(&pending(&state).snapshot, &beacon).unwrap(),
            draw,
            "the draw is the snapshot's"
        );
        let honouring = {
            let seats = ioi_types::app::seat_layout(&draw.successor_members, &draw.successor_vacancies)
                .unwrap();
            let gone = seats.iter().position(|m| *m == Some(ring_member(1))).unwrap() as u32;
            let members: Vec<AccountId> = draw
                .successor_members
                .iter()
                .copied()
                .filter(|m| *m != ring_member(1))
                .collect();
            let mut vacancies = draw.successor_vacancies.clone();
            vacancies.push(ioi_types::app::RingVacancy { seat: gone, since_version: genesis.version });
            vacancies.sort_by_key(|v| v.seat);
            let bonds = bonds_for(&genesis, &members);
            publication_for(&genesis, members, vacancies, bonds)
        };
        assert!(call(
            &registry,
            &mut state,
            ctx,
            "publish_ring_handover@v1",
            &codec::to_bytes_canonical(&honouring).unwrap(),
        )
        .is_err());
        call(
            &registry,
            &mut state,
            ctx,
            "publish_ring_handover@v1",
            &codec::to_bytes_canonical(&drawn_publication(&genesis, &draw)).unwrap(),
        )
        .unwrap();
        assert!(live_config(&state).members.contains(&ring_member(1)), "member 1 stays this handover");
        for b in 40u8..50 {
            register(&registry, &mut state, ctx, b, 150).unwrap();
        }
        // The late exit is CARRIED to the next snapshot (never dropped by this handover).
        let carried: BTreeSet<AccountId> =
            stored(&state, ioi_types::app::GUARDIAN_RING_PENDING_EXITS_KEY);
        assert!(carried.contains(&ring_member(1)), "the late exit is kept for the next snapshot");
        call(&registry, &mut state, ctx, "commit_ring_handover_snapshot@v1", &[]).unwrap();
        // It is planned there: member 1 departs at the next handover, as an exit, or as a forced
        // rotation when its seat's phase point falls there (a forced rotation subsumes an exit;
        // which one holds depends on the beacon, so the pin covers both).
        let next = pending(&state).snapshot;
        let forced = next.forced_rotations.contains(&ring_member(1));
        println!("B3 pin: member 1 forced at the next handover: {forced}");
        assert!(
            next.vacated_set.contains(&ring_member(1)),
            "the late exit is planned at the next snapshot: {next:?}"
        );
        assert!(
            forced || next.exits.contains(&ring_member(1)),
            "unforced, the late exit is an exit of the next snapshot: {next:?}"
        );
    });
}
