use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use ioi_api::crypto::{SerializableKey, SigningKeyPair, VerifyingKey};
use ioi_crypto::{
    security::SecurityLevel,
    sign::dilithium::{MldsaKeyPair, MldsaScheme},
    transport::pq_authenticated_channel::{
        accept_pq_channel, complete_pq_channel, finish_pq_channel, start_pq_channel,
        PqChannelContentTypeV1, PqChannelDirectionV1, PqChannelRecordOpener, PqChannelRecordSealer,
        PqChannelScopeV1,
    },
};
use ioi_types::app::{account_id_from_key_material, AccountId, SignatureSuite};
use std::time::Duration;

fn key_hash(keypair: &MldsaKeyPair) -> [u8; 32] {
    account_id_from_key_material(SignatureSuite::ML_DSA_44, &keypair.public_key().to_bytes())
        .expect("ML-DSA account binding")
}

fn channel_scope(initiator: AccountId, responder: AccountId) -> PqChannelScopeV1 {
    PqChannelScopeV1 {
        network_id: [0x11; 32],
        configuration_hash: [0x22; 32],
        epoch: 7,
        initiator,
        responder,
        initiator_transport_binding: [0x33; 32],
        responder_transport_binding: [0x44; 32],
    }
}

fn aft_pq_crypto(criterion: &mut Criterion) {
    let scheme = MldsaScheme::new(SecurityLevel::Level2);
    let keypair = scheme.generate_keypair().expect("ML-DSA key generation");
    let public_key = keypair.public_key();
    let message = b"AFT/benchmark/live-vote/v1";
    let signature = keypair.sign(message).expect("ML-DSA signing");

    eprintln!(
        "AFT_M1_SIZE suite=ML-DSA-44 public_key_bytes={} signature_bytes={}",
        public_key.to_bytes().len(),
        signature.to_bytes().len()
    );

    criterion.bench_function("aft_mldsa44_keygen", |bencher| {
        bencher.iter(|| black_box(scheme.generate_keypair().expect("ML-DSA key generation")))
    });
    criterion.bench_function("aft_mldsa44_live_vote_sign", |bencher| {
        bencher.iter(|| black_box(keypair.sign(black_box(message)).expect("ML-DSA signing")))
    });
    criterion.bench_function("aft_mldsa44_live_vote_verify", |bencher| {
        bencher.iter(|| {
            public_key
                .verify(black_box(message), black_box(&signature))
                .expect("ML-DSA verification")
        })
    });

    let responder = scheme.generate_keypair().expect("responder identity");
    let initiator_hash = key_hash(&keypair);
    let responder_hash = key_hash(&responder);
    let scope = channel_scope(AccountId(initiator_hash), AccountId(responder_hash));
    criterion.bench_function("aft_pq_channel_full_authenticated_handshake", |bencher| {
        bencher.iter(|| {
            let (initiator_state, hello) =
                start_pq_channel(scope.clone(), &keypair, responder_hash).unwrap();
            let (responder_state, server) =
                accept_pq_channel(&scope, initiator_hash, responder_hash, &responder, hello)
                    .unwrap();
            let (finish, initiator_keys) = finish_pq_channel(initiator_state, server).unwrap();
            let responder_keys = complete_pq_channel(responder_state, finish).unwrap();
            black_box((initiator_keys, responder_keys))
        })
    });

    let (initiator_state, hello) =
        start_pq_channel(scope.clone(), &keypair, responder_hash).unwrap();
    let (responder_state, server) =
        accept_pq_channel(&scope, initiator_hash, responder_hash, &responder, hello).unwrap();
    let (finish, initiator_keys) = finish_pq_channel(initiator_state, server).unwrap();
    let responder_keys = complete_pq_channel(responder_state, finish).unwrap();
    for size in [1_024usize, 65_536] {
        let payload = vec![0x5a; size];
        let benchmark = format!("aft_pq_channel_record_seal_open_{size}_bytes");
        criterion.bench_function(&benchmark, |bencher| {
            bencher.iter_batched(
                || {
                    (
                        PqChannelRecordSealer::new(
                            initiator_keys.transcript_hash(),
                            PqChannelDirectionV1::InitiatorToResponder,
                            initiator_keys.initiator_to_responder(),
                        ),
                        PqChannelRecordOpener::new(
                            responder_keys.transcript_hash(),
                            PqChannelDirectionV1::InitiatorToResponder,
                            responder_keys.initiator_to_responder(),
                        ),
                    )
                },
                |(mut sealer, mut opener)| {
                    let record = sealer
                        .seal(PqChannelContentTypeV1::AsynchronousConsensus, &payload)
                        .unwrap();
                    black_box(opener.open(&record).unwrap())
                },
                BatchSize::SmallInput,
            )
        });
    }
}

fn config() -> Criterion {
    Criterion::default()
        .sample_size(20)
        .measurement_time(Duration::from_secs(5))
        .warm_up_time(Duration::from_secs(1))
}

criterion_group! {
    name = benches;
    config = config();
    targets = aft_pq_crypto
}
criterion_main!(benches);
