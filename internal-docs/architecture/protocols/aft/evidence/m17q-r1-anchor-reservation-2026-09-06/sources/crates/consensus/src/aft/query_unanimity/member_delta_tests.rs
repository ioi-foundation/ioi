mod journal_replay_tests {
    use super::*;
    use crate::aft::query_unanimity::journal::member_store::JournalMemberStore;
    use crate::aft::query_unanimity::journal::{JournalLimits, MemberJournal};
    use crate::aft::query_unanimity::member_delta::{apply_member_delta, MemberDelta};

    fn assert_same_retained_state(actual: &QuvStoreStateV0, expected: &QuvStoreStateV0) {
        assert_eq!(actual.generation, expected.generation);
        assert_eq!(actual.provisioning_root, expected.provisioning_root);
        assert_eq!(actual.domains, expected.domains);
        assert_eq!(actual.slots, expected.slots);
        assert_eq!(actual.preparation_attempts, expected.preparation_attempts);
    }

    fn limits() -> JournalLimits {
        JournalLimits {
            max_record_bytes: 16_384,
            max_total_bytes: 16_777_216,
            max_records: 2048,
        }
    }

    #[test]
    fn typed_journal_replay_matches_live_member_across_three_slots_and_reopens() {
        for mode in [QuvAuthorityModeV0::Owned, QuvAuthorityModeV0::Unowned] {
            let temp = TempDir::new().unwrap();
            let (mut candidate, policy) = preparation_fixture(mode);
            let mut member = open_member_at(&temp, candidate.slot.clone());
            let initial = member.state.clone();
            let bootstrap = codec::to_bytes_canonical(&initial).unwrap();
            let directory = temp.path().join("journal");
            let anchor = temp.path().join("journal.anchor");
            let mut journal = MemberJournal::open(
                &directory,
                &anchor,
                [8; 32],
                [6; 32],
                limits(),
                &bootstrap,
                |_, _| panic!("fresh journal has no transitions"),
            )
            .unwrap();
            let mut replayed = initial.clone();
            let replacement_directory = temp.path().join("member-journal");
            let replacement_anchor = temp.path().join("member-journal.anchor");
            let mut replacement = JournalMemberStore::open(
                &replacement_directory,
                &replacement_anchor,
                [8; 32],
                [6; 32],
                initial.domains.clone(),
                limits(),
            )
            .unwrap();
            for slot_index in 0..3 {
                let grant = authorize_stored_candidate(&mut member, candidate.clone());
                let insert = MemberDelta::InsertCandidate(candidate.clone());
                journal
                    .append(&codec::to_bytes_canonical(&insert).unwrap())
                    .unwrap();
                apply_member_delta(&mut replayed, member.generation(), &insert).unwrap();
                assert_same_retained_state(&replayed, &member.state);
                replacement.commit(&insert, || Ok(())).unwrap();
                assert_same_retained_state(replacement.state().unwrap(), &member.state);
                assert_eq!(
                    replacement.cached_logical_size(),
                    replacement.state().unwrap().encoded_size()
                );
                for used in 1..=2 {
                    assert_eq!(
                        member
                            .reserve_preparation_attempt(&candidate, &policy)
                            .unwrap(),
                        used
                    );
                    let reserve = MemberDelta::ReservePreparation {
                        candidate: candidate.clone(),
                        used,
                        policy: (&policy).into(),
                    };
                    journal
                        .append(&codec::to_bytes_canonical(&reserve).unwrap())
                        .unwrap();
                    apply_member_delta(&mut replayed, member.generation(), &reserve).unwrap();
                    assert_same_retained_state(&replayed, &member.state);
                    replacement.commit(&reserve, || Ok(())).unwrap();
                    assert_same_retained_state(replacement.state().unwrap(), &member.state);
                    assert_eq!(
                        replacement.cached_logical_size(),
                        replacement.state().unwrap().encoded_size()
                    );
                }
                assert!(member.advance_accepted_history(&grant).unwrap());
                let advance = MemberDelta::AcceptHead {
                    slot: candidate.slot.clone(),
                    candidate_hash: grant.candidate_hash(),
                };
                journal
                    .append_with_prewrite_check(
                        &codec::to_bytes_canonical(&advance).unwrap(),
                        || {
                            if Instant::now() >= grant.expires_at {
                                Err(QuvError::ExpiredAuthorization)
                            } else {
                                Ok(())
                            }
                        },
                    )
                    .unwrap();
                apply_member_delta(&mut replayed, member.generation(), &advance).unwrap();
                assert_same_retained_state(&replayed, &member.state);
                replacement
                    .commit(&advance, || {
                        if Instant::now() >= grant.expires_at {
                            Err(QuvError::ExpiredAuthorization)
                        } else {
                            Ok(())
                        }
                    })
                    .unwrap();
                assert_same_retained_state(replacement.state().unwrap(), &member.state);
                assert_eq!(
                    replacement.cached_logical_size(),
                    replacement.state().unwrap().encoded_size()
                );
                assert!(replayed.preparation_attempts.is_empty());
                drop(journal);
                let mut recovered = initial.clone();
                journal = MemberJournal::open(
                    &directory,
                    &anchor,
                    [8; 32],
                    [6; 32],
                    limits(),
                    &bootstrap,
                    |generation, payload| {
                        apply_member_delta(
                            &mut recovered,
                            generation,
                            &codec::from_bytes_canonical::<MemberDelta>(payload)
                                .map_err(QuvError::Codec)?,
                        )
                    },
                )
                .unwrap();
                assert_same_retained_state(&recovered, &member.state);
                drop(replacement);
                replacement = JournalMemberStore::open(
                    &replacement_directory,
                    &replacement_anchor,
                    [8; 32],
                    [6; 32],
                    initial.domains.clone(),
                    limits(),
                )
                .unwrap();
                assert_same_retained_state(replacement.state().unwrap(), &member.state);
                assert_eq!(
                    replacement.cached_logical_size(),
                    replacement.state().unwrap().encoded_size()
                );
                assert_eq!(recovered.generation, (slot_index + 1) * 4);
                candidate.slot.slot += 1;
                candidate.slot.predecessor = grant.candidate_hash();
                candidate.payload_hash[0] += 1;
            }
        }
    }

    #[test]
    fn typed_replay_refuses_invalid_order_scope_and_counters_without_mutation() {
        let temp = TempDir::new().unwrap();
        let (candidate, policy) = preparation_fixture(QuvAuthorityModeV0::Owned);
        let member = open_member_at(&temp, candidate.slot.clone());
        let mut state = member.state.clone();
        let missing = MemberDelta::AcceptHead {
            slot: candidate.slot.clone(),
            candidate_hash: quv_candidate_hash(&candidate).unwrap(),
        };
        let before = state.clone();
        assert!(matches!(
            apply_member_delta(&mut state, 1, &missing),
            Err(QuvError::InvalidAcceptedHistory)
        ));
        assert_eq!(state, before);
        let mut wrong = candidate.clone();
        wrong.slot.predecessor = [99; 32];
        assert!(matches!(
            apply_member_delta(&mut state, 1, &MemberDelta::InsertCandidate(wrong)),
            Err(QuvError::UnexpectedHead)
        ));
        assert_eq!(state, before);
        let insert = MemberDelta::InsertCandidate(candidate.clone());
        assert!(matches!(
            apply_member_delta(&mut state, 2, &insert),
            Err(QuvError::RollbackOrFork)
        ));
        assert_eq!(state, before);
        apply_member_delta(&mut state, 1, &insert).unwrap();
        let before = state.clone();
        assert!(matches!(
            apply_member_delta(&mut state, 2, &insert),
            Err(QuvError::CorruptStore)
        ));
        assert_eq!(state, before);
        for used in [0, 2, u16::MAX] {
            let reserve = MemberDelta::ReservePreparation {
                candidate: candidate.clone(),
                used,
                policy: (&policy).into(),
            };
            assert!(matches!(
                apply_member_delta(&mut state, 2, &reserve),
                Err(QuvError::CorruptStore)
            ));
            assert_eq!(state, before);
        }
        apply_member_delta(
            &mut state,
            2,
            &MemberDelta::ReservePreparation {
                candidate: candidate.clone(),
                used: 1,
                policy: (&policy).into(),
            },
        )
        .unwrap();
        apply_member_delta(&mut state, 3, &missing).unwrap();
        let before = state.clone();
        assert!(matches!(
            apply_member_delta(&mut state, 4, &missing),
            Err(QuvError::InvalidAcceptedHistory)
        ));
        assert_eq!(state, before);
        assert!(matches!(
            apply_member_delta(
                &mut state,
                4,
                &MemberDelta::ReservePreparation {
                    candidate,
                    used: 1,
                    policy: (&policy).into()
                }
            ),
            Err(QuvError::UnexpectedHead)
        ));
        assert_eq!(state, before);
    }

    #[test]
    fn typed_replay_refuses_owned_conflict_reservation_but_retains_both_candidates() {
        let temp = TempDir::new().unwrap();
        let (candidate, policy) = preparation_fixture(QuvAuthorityModeV0::Owned);
        let member = open_member_at(&temp, candidate.slot.clone());
        let mut state = member.state.clone();
        let mut other = candidate.clone();
        other.payload_hash = [44; 32];
        apply_member_delta(
            &mut state,
            1,
            &MemberDelta::InsertCandidate(candidate.clone()),
        )
        .unwrap();
        apply_member_delta(&mut state, 2, &MemberDelta::InsertCandidate(other)).unwrap();
        let before = state.clone();
        assert!(matches!(
            apply_member_delta(
                &mut state,
                3,
                &MemberDelta::ReservePreparation {
                    candidate,
                    used: 1,
                    policy: (&policy).into()
                }
            ),
            Err(QuvError::ConflictDisclosed)
        ));
        assert_eq!(state, before);
        assert_eq!(state.slots.values().next().unwrap().len(), 2);
    }

    #[test]
    fn authenticated_pending_record_cannot_advance_anchor_if_typed_replay_refuses() {
        let temp = TempDir::new().unwrap();
        let (candidate, _) = preparation_fixture(QuvAuthorityModeV0::Owned);
        let member = open_member_at(&temp, candidate.slot.clone());
        let initial = member.state.clone();
        let bootstrap = codec::to_bytes_canonical(&initial).unwrap();
        let directory = temp.path().join("journal");
        let anchor = temp.path().join("journal.anchor");
        let mut journal = MemberJournal::open(
            &directory,
            &anchor,
            [8; 32],
            [6; 32],
            limits(),
            &bootstrap,
            |_, _| Ok(()),
        )
        .unwrap();
        let initial_anchor = std::fs::read(&anchor).unwrap();
        // Synthetic authenticated state with an impossible transition order.
        // Recovery must validate semantics in addition to storage authentication.
        let advance = MemberDelta::AcceptHead {
            slot: candidate.slot,
            candidate_hash: [55; 32],
        };
        journal
            .append(&codec::to_bytes_canonical(&advance).unwrap())
            .unwrap();
        drop(journal);
        std::fs::write(&anchor, &initial_anchor).unwrap();
        let mut recovered = initial.clone();
        assert!(matches!(
            MemberJournal::open(
                &directory,
                &anchor,
                [8; 32],
                [6; 32],
                limits(),
                &bootstrap,
                |generation, payload| apply_member_delta(
                    &mut recovered,
                    generation,
                    &codec::from_bytes_canonical::<MemberDelta>(payload)
                        .map_err(QuvError::Codec)?
                )
            ),
            Err(QuvError::InvalidAcceptedHistory)
        ));
        assert_eq!(std::fs::read(&anchor).unwrap(), initial_anchor);
        assert_eq!(recovered, initial);
    }
    #[test]
    fn journal_member_commit_refusal_and_anchor_failure_do_not_publish_memory() {
        let temp = TempDir::new().unwrap();
        let (candidate, _) = preparation_fixture(QuvAuthorityModeV0::Owned);
        let directory = temp.path().join("journal");
        let anchor = temp.path().join("journal.anchor");
        let domains = test_domains(candidate.slot.clone());
        let mut store = JournalMemberStore::open(
            &directory,
            &anchor,
            [8; 32],
            [6; 32],
            domains.clone(),
            limits(),
        )
        .unwrap();
        let before = store.state().unwrap().clone();
        let delta = MemberDelta::InsertCandidate(candidate.clone());
        assert!(matches!(
            store.commit(&delta, || Err(QuvError::ExpiredAuthorization)),
            Err(QuvError::ExpiredAuthorization)
        ));
        assert_eq!(store.state().unwrap(), &before);
        assert!(!directory.join("00000000000000000001.quv").exists());
        store.fail_next_anchor_commit();
        assert!(matches!(
            store.commit(&delta, || Ok(())),
            Err(QuvError::Io(_))
        ));
        assert!(matches!(store.state(), Err(QuvError::StoreRequiresReopen)));
        assert!(matches!(
            store.commit(&delta, || Ok(())),
            Err(QuvError::StoreRequiresReopen)
        ));
        drop(store);
        let recovered =
            JournalMemberStore::open(&directory, &anchor, [8; 32], [6; 32], domains, limits())
                .unwrap();
        assert_eq!(recovered.state().unwrap().generation, 1);
        assert_eq!(
            recovered.state().unwrap().slots.values().next().unwrap(),
            &vec![candidate]
        );
        assert_eq!(
            recovered.cached_logical_size(),
            recovered.state().unwrap().encoded_size()
        );
    }

    #[test]
    fn journal_member_cached_size_matches_compact_history_boundaries() {
        let temp = TempDir::new().unwrap();
        let (mut candidate, policy) = preparation_fixture(QuvAuthorityModeV0::Unowned);
        let directory = temp.path().join("journal");
        let anchor = temp.path().join("journal.anchor");
        let domains = test_domains(candidate.slot.clone());
        let mut quota = limits();
        quota.max_records = 2048;
        let mut store = JournalMemberStore::open(
            &directory,
            &anchor,
            [8; 32],
            [6; 32],
            domains.clone(),
            quota,
        )
        .unwrap();
        // Component arithmetic over 65 retained positions crosses SCALE's
        // compact-length boundary for both slot maps and accepted history.
        for _ in 0..65 {
            let hash = quv_candidate_hash(&candidate).unwrap();
            for delta in [
                MemberDelta::InsertCandidate(candidate.clone()),
                MemberDelta::ReservePreparation {
                    candidate: candidate.clone(),
                    used: 1,
                    policy: (&policy).into(),
                },
                MemberDelta::AcceptHead {
                    slot: candidate.slot.clone(),
                    candidate_hash: hash,
                },
            ] {
                store.commit(&delta, || Ok(())).unwrap();
                assert_eq!(
                    store.cached_logical_size(),
                    store.state().unwrap().encoded_size()
                );
            }
            candidate.slot.slot += 1;
            candidate.slot.predecessor = hash;
            candidate.payload_hash[0] += 1;
        }
        // Every transition kind has the same physical record size at the
        // first and 65th retained positions; old history is not rewritten.
        for offset in 1..=3 {
            let first = directory.join(format!("{offset:020}.quv"));
            let last = directory.join(format!("{:020}.quv", 192 + offset));
            assert_eq!(
                std::fs::metadata(first).unwrap().len(),
                std::fs::metadata(last).unwrap().len()
            );
        }
        let expected = store.state().unwrap().clone();
        drop(store);
        let recovered =
            JournalMemberStore::open(&directory, &anchor, [8; 32], [6; 32], domains, quota)
                .unwrap();
        assert_same_retained_state(recovered.state().unwrap(), &expected);
        assert_eq!(
            recovered.cached_logical_size(),
            recovered.state().unwrap().encoded_size()
        );
    }
    #[test]
    fn preparation_policy_is_rechecked_on_replay_and_exhaustion_survives_reopen() {
        for mode in [QuvAuthorityModeV0::Owned, QuvAuthorityModeV0::Unowned] {
            let temp = TempDir::new().unwrap();
            let (candidate, policy) = preparation_fixture(mode);
            let directory = temp.path().join("journal");
            let anchor = temp.path().join("journal.anchor");
            let domains = test_domains(candidate.slot.clone());
            let mut store = JournalMemberStore::open(
                &directory,
                &anchor,
                [8; 32],
                [6; 32],
                domains.clone(),
                limits(),
            )
            .unwrap();
            store
                .commit(&MemberDelta::InsertCandidate(candidate.clone()), || Ok(()))
                .unwrap();
            for used in 1..=2 {
                store
                    .commit(
                        &MemberDelta::ReservePreparation {
                            candidate: candidate.clone(),
                            used,
                            policy: (&policy).into(),
                        },
                        || Ok(()),
                    )
                    .unwrap();
            }
            drop(store);
            let mut store =
                JournalMemberStore::open(&directory, &anchor, [8; 32], [6; 32], domains, limits())
                    .unwrap();
            let before = store.state().unwrap().clone();
            let disk_before = read_test_store(&directory).unwrap();
            let anchor_before = std::fs::read(&anchor).unwrap();
            let reserve = MemberDelta::ReservePreparation {
                candidate: candidate.clone(),
                used: 3,
                policy: (&policy).into(),
            };
            assert!(matches!(
                store.commit(&reserve, || panic!("refuse before writes")),
                Err(QuvError::PreparationAttemptsExhausted)
            ));
            // A policy preimage must match the independently enrolled commitment;
            // a higher attempt limit cannot be supplied during replay.
            let mut changed = policy.clone();
            changed.preparation = ioi_types::app::QuvPreparationPolicyV0::Independent {
                max_attempts_per_slot: 3,
                service_millis: 20,
                readiness_millis: 60,
            };
            let reserve = MemberDelta::ReservePreparation {
                candidate,
                used: 3,
                policy: (&changed).into(),
            };
            assert!(matches!(
                store.commit(&reserve, || panic!("refuse before writes")),
                Err(QuvError::InvalidRootedContext)
            ));
            assert_eq!(store.state().unwrap(), &before);
            assert_eq!(read_test_store(&directory).unwrap(), disk_before);
            assert_eq!(std::fs::read(&anchor).unwrap(), anchor_before);
        }
    }

    #[test]
    fn rooted_preparation_format_refuses_schema_seven_without_mutation() {
        for old_schema in [7, 8] {
            let temp = TempDir::new().unwrap();
            let (candidate, _) = preparation_fixture(QuvAuthorityModeV0::Owned);
            let member = open_member_at(&temp, candidate.slot.clone());
            let mut old = member.state.clone();
            old.schema = old_schema;
            let directory = temp.path().join("old-journal");
            let anchor = temp.path().join("old-journal.anchor");
            let old_domains = BTreeMap::from([(
                candidate.slot.domain_id,
                (0_u8, candidate.slot.clone(), Vec::<QuvHash>::new()),
            )]);
            let bootstrap = codec::to_bytes_canonical(&(
                old.magic,
                old.schema,
                old.generation,
                old.previous_head,
                old.provisioning_root,
                old_domains,
                old.preparation_attempts,
                old.slots,
                old.authentication_tag,
            ))
            .unwrap();
            let old_journal = MemberJournal::open(
                &directory,
                &anchor,
                [8; 32],
                [6; 32],
                limits(),
                &bootstrap,
                |_, _| panic!("empty old journal"),
            )
            .unwrap();
            drop(old_journal);
            let before = read_test_store(&directory).unwrap();
            let anchor_before = std::fs::read(&anchor).unwrap();
            assert!(matches!(
                JournalMemberStore::open(
                    &directory,
                    &anchor,
                    [8; 32],
                    [6; 32],
                    test_domains(candidate.slot),
                    limits(),
                ),
                Err(QuvError::ProvisioningMismatch)
            ));
            assert_eq!(read_test_store(&directory).unwrap(), before);
            assert_eq!(std::fs::read(&anchor).unwrap(), anchor_before);
        }
    }
    #[test]
    fn startup_reserves_complete_rooted_lifetime_before_creating_a_journal() {
        let temp = TempDir::new().unwrap();
        let (mut candidate, mut policy) = preparation_fixture(QuvAuthorityModeV0::Unowned);
        policy.authority_slots = 1;
        let domain = QuvMemberDomainV0::from_provisioned_policy(
            candidate.slot.configuration_root,
            candidate.slot.network_id,
            &policy,
        )
        .unwrap();
        candidate.slot.policy_root = domain.initial().policy_root;
        let domains = BTreeMap::from([(policy.domain_id, domain)]);
        let directory = temp.path().join("records");
        let anchor = temp.path().join("anchor");
        let mut quota = limits();
        // One slot needs room for two inserts, two reservations, one head and
        // the bootstrap. A short journal must be rejected at enrollment.
        quota.max_records = 5;
        assert!(matches!(
            JournalMemberStore::open(
                &directory,
                &anchor,
                [8; 32],
                [6; 32],
                domains.clone(),
                quota
            ),
            Err(QuvError::StoreCapacityExceeded)
        ));
        assert!(!directory.exists());
        assert!(!anchor.exists());
        quota.max_records = 6;
        quota.max_record_bytes = 8192;
        quota.max_total_bytes = 8192;
        assert!(matches!(
            JournalMemberStore::open(
                &directory,
                &anchor,
                [8; 32],
                [6; 32],
                domains.clone(),
                quota
            ),
            Err(QuvError::StoreCapacityExceeded)
        ));
        assert!(!directory.exists());
        assert!(!anchor.exists());
        quota.max_total_bytes = 65_536;
        quota.max_record_bytes = 8191;
        assert!(matches!(
            JournalMemberStore::open(
                &directory,
                &anchor,
                [8; 32],
                [6; 32],
                domains.clone(),
                quota
            ),
            Err(QuvError::StoreCapacityExceeded)
        ));
        assert!(!directory.exists());
        assert!(!anchor.exists());
        quota.max_record_bytes = 8192;
        let mut store = JournalMemberStore::open(
            &directory,
            &anchor,
            [8; 32],
            [6; 32],
            domains.clone(),
            quota,
        )
        .unwrap();
        let mut other = candidate.clone();
        other.payload_hash = [99; 32];
        for delta in [
            MemberDelta::InsertCandidate(candidate.clone()),
            MemberDelta::InsertCandidate(other),
            MemberDelta::ReservePreparation {
                candidate: candidate.clone(),
                used: 1,
                policy: (&policy).into(),
            },
            MemberDelta::ReservePreparation {
                candidate: candidate.clone(),
                used: 2,
                policy: (&policy).into(),
            },
            MemberDelta::AcceptHead {
                slot: candidate.slot.clone(),
                candidate_hash: quv_candidate_hash(&candidate).unwrap(),
            },
        ] {
            store.commit(&delta, || Ok(())).unwrap();
        }
        assert_eq!(store.state().unwrap().generation, 5);
        drop(store);
        let store = JournalMemberStore::open(&directory, &anchor, [8; 32], [6; 32], domains, quota)
            .unwrap();
        assert_eq!(store.state().unwrap().generation, 5);
        assert!(store.state().unwrap().domains[&policy.domain_id]
            .next_query_slot()
            .is_none());
    }
}
