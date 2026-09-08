mod journal_replay_tests {
    use super::*;
    use crate::aft::query_unanimity::journal::{JournalLimits, MemberJournal};
    use crate::aft::query_unanimity::member_delta::{replay_member_delta, MemberDelta};

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
            max_total_bytes: 1_048_576,
            max_records: 128,
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
            for slot_index in 0..3 {
                let grant = authorize_stored_candidate(&mut member, candidate.clone());
                let insert = MemberDelta::InsertCandidate(candidate.clone());
                journal
                    .append(&codec::to_bytes_canonical(&insert).unwrap())
                    .unwrap();
                replay_member_delta(&mut replayed, member.generation(), &insert).unwrap();
                assert_same_retained_state(&replayed, &member.state);
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
                    };
                    journal
                        .append(&codec::to_bytes_canonical(&reserve).unwrap())
                        .unwrap();
                    replay_member_delta(&mut replayed, member.generation(), &reserve).unwrap();
                    assert_same_retained_state(&replayed, &member.state);
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
                replay_member_delta(&mut replayed, member.generation(), &advance).unwrap();
                assert_same_retained_state(&replayed, &member.state);
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
                        replay_member_delta(
                            &mut recovered,
                            generation,
                            &codec::from_bytes_canonical::<MemberDelta>(payload)
                                .map_err(QuvError::Codec)?,
                        )
                    },
                )
                .unwrap();
                assert_same_retained_state(&recovered, &member.state);
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
        let (candidate, _) = preparation_fixture(QuvAuthorityModeV0::Owned);
        let member = open_member_at(&temp, candidate.slot.clone());
        let mut state = member.state.clone();
        let missing = MemberDelta::AcceptHead {
            slot: candidate.slot.clone(),
            candidate_hash: quv_candidate_hash(&candidate).unwrap(),
        };
        let before = state.clone();
        assert!(matches!(
            replay_member_delta(&mut state, 1, &missing),
            Err(QuvError::InvalidAcceptedHistory)
        ));
        assert_eq!(state, before);
        let mut wrong = candidate.clone();
        wrong.slot.predecessor = [99; 32];
        assert!(matches!(
            replay_member_delta(&mut state, 1, &MemberDelta::InsertCandidate(wrong)),
            Err(QuvError::UnexpectedHead)
        ));
        assert_eq!(state, before);
        let insert = MemberDelta::InsertCandidate(candidate.clone());
        assert!(matches!(
            replay_member_delta(&mut state, 2, &insert),
            Err(QuvError::RollbackOrFork)
        ));
        assert_eq!(state, before);
        replay_member_delta(&mut state, 1, &insert).unwrap();
        let before = state.clone();
        assert!(matches!(
            replay_member_delta(&mut state, 2, &insert),
            Err(QuvError::CorruptStore)
        ));
        assert_eq!(state, before);
        for used in [0, 2, u16::MAX] {
            let reserve = MemberDelta::ReservePreparation {
                candidate: candidate.clone(),
                used,
            };
            assert!(matches!(
                replay_member_delta(&mut state, 2, &reserve),
                Err(QuvError::CorruptStore)
            ));
            assert_eq!(state, before);
        }
        replay_member_delta(
            &mut state,
            2,
            &MemberDelta::ReservePreparation {
                candidate: candidate.clone(),
                used: 1,
            },
        )
        .unwrap();
        replay_member_delta(&mut state, 3, &missing).unwrap();
        let before = state.clone();
        assert!(matches!(
            replay_member_delta(&mut state, 4, &missing),
            Err(QuvError::InvalidAcceptedHistory)
        ));
        assert_eq!(state, before);
        assert!(matches!(
            replay_member_delta(
                &mut state,
                4,
                &MemberDelta::ReservePreparation { candidate, used: 1 }
            ),
            Err(QuvError::UnexpectedHead)
        ));
        assert_eq!(state, before);
    }

    #[test]
    fn typed_replay_refuses_owned_conflict_reservation_but_retains_both_candidates() {
        let temp = TempDir::new().unwrap();
        let (candidate, _) = preparation_fixture(QuvAuthorityModeV0::Owned);
        let member = open_member_at(&temp, candidate.slot.clone());
        let mut state = member.state.clone();
        let mut other = candidate.clone();
        other.payload_hash = [44; 32];
        replay_member_delta(
            &mut state,
            1,
            &MemberDelta::InsertCandidate(candidate.clone()),
        )
        .unwrap();
        replay_member_delta(&mut state, 2, &MemberDelta::InsertCandidate(other)).unwrap();
        let before = state.clone();
        assert!(matches!(
            replay_member_delta(
                &mut state,
                3,
                &MemberDelta::ReservePreparation { candidate, used: 1 }
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
                |generation, payload| replay_member_delta(
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
}
