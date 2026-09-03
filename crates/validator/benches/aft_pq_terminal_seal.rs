use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ioi_types::app::{
    AccountId, SealKeyBindingV1, SealKeyScopeV1, SignatureSuite, SLH_DSA_SHA2_128S_SIGNATURE_BYTES,
};
use ioi_validator::common::guardian::seal_signer::{verify_seal_share_v2, SlhDsaSealKeyPair};
use std::time::Duration;

fn aft_pq_terminal_seal(criterion: &mut Criterion) {
    let keypair = SlhDsaSealKeyPair::from_seed_material([1; 16], [2; 16], [3; 16]);
    let current_key = SealKeyBindingV1 {
        scope: SealKeyScopeV1 {
            network_id: [4; 32],
            configuration_id: [5; 32],
            epoch: 6,
            conflict_domain_id: [7; 32],
            member_id: AccountId([8; 32]),
            member_index: 9,
        },
        key_index: 10,
        signature_suite: SignatureSuite::SLH_DSA_SHA2_128S,
        public_key: keypair.public_key_bytes(),
        predecessor_key_commitment: [11; 32],
    };
    let expected_commitment = current_key.commitment().expect("terminal key commitment");
    let share = keypair
        .sign_share(current_key.clone(), 10, [12; 32], [13; 32])
        .expect("terminal seal signing");

    eprintln!(
        "AFT_M1_SIZE suite=SLH-DSA-SHA2-128s public_key_bytes={} signature_bytes={} share_signature_bytes={}",
        current_key.public_key.len(),
        SLH_DSA_SHA2_128S_SIGNATURE_BYTES,
        share.signature.len()
    );

    criterion.bench_function("aft_slhdsa_sha2_128s_terminal_sign", |bencher| {
        bencher.iter(|| {
            black_box(
                keypair
                    .sign_share(current_key.clone(), 10, [12; 32], [13; 32])
                    .expect("terminal seal signing"),
            )
        })
    });
    criterion.bench_function("aft_slhdsa_sha2_128s_terminal_verify", |bencher| {
        bencher.iter(|| {
            verify_seal_share_v2(black_box(&share), expected_commitment)
                .expect("terminal seal verification")
        })
    });
}

fn config() -> Criterion {
    Criterion::default()
        .sample_size(10)
        .measurement_time(Duration::from_secs(5))
        .warm_up_time(Duration::from_secs(1))
}

criterion_group! {
    name = benches;
    config = config();
    targets = aft_pq_terminal_seal
}
criterion_main!(benches);
