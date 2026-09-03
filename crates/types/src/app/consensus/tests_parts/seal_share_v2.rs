fn seal_scope(member_index: u32) -> SealKeyScopeV1 {
    SealKeyScopeV1 {
        network_id: [1; 32],
        configuration_id: [2; 32],
        epoch: 3,
        conflict_domain_id: [4; 32],
        member_id: AccountId([member_index as u8 + 10; 32]),
        member_index,
    }
}

fn seal_binding(
    member_index: u32,
    key_index: u64,
    predecessor: [u8; 32],
) -> SealKeyBindingV1 {
    SealKeyBindingV1 {
        scope: seal_scope(member_index),
        key_index,
        signature_suite: SignatureSuite::SLH_DSA_SHA2_128S,
        public_key: vec![member_index as u8 + key_index as u8 + 20; 32],
        predecessor_key_commitment: predecessor,
    }
}

#[test]
fn seal_manifest_is_canonical_and_owns_initial_authentication() {
    let first = seal_binding(0, 0, [9; 32]);
    let second = seal_binding(1, 0, [8; 32]);
    let manifest = SealKeyManifestV1 {
        schema_version: AFT_SEAL_KEY_MANIFEST_SCHEMA_V1,
        entries: vec![
            SealKeyManifestEntryV1 {
                initial_key_commitment: first.commitment().unwrap(),
                initial_key: first.clone(),
            },
            SealKeyManifestEntryV1 {
                initial_key_commitment: second.commitment().unwrap(),
                initial_key: second,
            },
        ],
    };
    manifest.validate().unwrap();
    assert_eq!(
        manifest
            .initial_key_for_scope(&first.scope)
            .unwrap()
            .initial_key,
        first
    );
    assert_ne!(manifest.commitment().unwrap(), [0; 32]);
}

#[test]
fn seal_manifest_rejects_reordering_duplicates_and_false_commitments() {
    let first = seal_binding(0, 0, [9; 32]);
    let second = seal_binding(1, 0, [8; 32]);
    let entry = |key: SealKeyBindingV1| SealKeyManifestEntryV1 {
        initial_key_commitment: key.commitment().unwrap(),
        initial_key: key,
    };

    let reversed = SealKeyManifestV1 {
        schema_version: 1,
        entries: vec![entry(second), entry(first.clone())],
    };
    assert!(reversed.validate().is_err());

    let duplicate = SealKeyManifestV1 {
        schema_version: 1,
        entries: vec![entry(first.clone()), entry(first.clone())],
    };
    assert!(duplicate.validate().is_err());

    let mut false_commitment = SealKeyManifestV1 {
        schema_version: 1,
        entries: vec![entry(first)],
    };
    false_commitment.entries[0].initial_key_commitment[0] ^= 1;
    assert!(false_commitment.validate().is_err());
}

#[test]
fn seal_share_signing_bytes_bind_every_replay_scope_and_successor() {
    let key = seal_binding(0, 7, [6; 32]);
    let share = SealShareV2 {
        protocol_version: 2,
        schema_version: 2,
        current_key: key,
        seal_slot: 7,
        seal_root: [5; 32],
        next_key_commitment: [7; 32],
        signature: vec![0; SLH_DSA_SHA2_128S_SIGNATURE_BYTES],
    };
    let baseline = share.signing_bytes().unwrap();

    let mut mutations = Vec::new();
    let mut network = share.clone();
    network.current_key.scope.network_id[0] ^= 1;
    mutations.push(network);
    let mut configuration = share.clone();
    configuration.current_key.scope.configuration_id[0] ^= 1;
    mutations.push(configuration);
    let mut epoch = share.clone();
    epoch.current_key.scope.epoch += 1;
    mutations.push(epoch);
    let mut domain = share.clone();
    domain.current_key.scope.conflict_domain_id[0] ^= 1;
    mutations.push(domain);
    let mut identity = share.clone();
    identity.current_key.scope.member_id.0[0] ^= 1;
    mutations.push(identity);
    let mut member_index = share.clone();
    member_index.current_key.scope.member_index += 1;
    mutations.push(member_index);
    let mut root = share.clone();
    root.seal_root[0] ^= 1;
    mutations.push(root);
    let mut next = share.clone();
    next.next_key_commitment[0] ^= 1;
    mutations.push(next);

    for mutation in mutations {
        assert_ne!(mutation.signing_bytes().unwrap(), baseline);
    }
}

#[test]
fn seal_share_shape_and_anchor_checks_fail_closed() {
    let key = seal_binding(0, 2, [6; 32]);
    let expected = key.commitment().unwrap();
    let mut share = SealShareV2 {
        protocol_version: 2,
        schema_version: 2,
        current_key: key,
        seal_slot: 2,
        seal_root: [5; 32],
        next_key_commitment: [7; 32],
        signature: vec![0; SLH_DSA_SHA2_128S_SIGNATURE_BYTES],
    };
    share.verify_anchor(expected).unwrap();
    assert!(share.verify_anchor([0; 32]).is_err());

    share.seal_slot += 1;
    assert!(share.validate_shape().is_err());
    share.seal_slot -= 1;
    share.signature.pop();
    assert!(share.validate_shape().is_err());
}

#[test]
fn signature_suite_classifies_slh_dsa_as_post_quantum() {
    assert!(SignatureSuite::SLH_DSA_SHA2_128S.is_post_quantum());
    assert!(!SignatureSuite::BLS12_381.is_post_quantum());
}
