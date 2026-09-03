#![no_main]

use bincode::Options;
use ioi_api::crypto::SerializableKey;
use ioi_crypto::{
    sign::dilithium::{MldsaPrivateKey, MldsaPublicKey, MldsaSignature},
    transport::pq_authenticated_channel::{
        PqChannelClientFinishV1, PqChannelClientHelloV1, PqChannelRecordV1,
        PqChannelServerHelloV1,
    },
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&selector, payload)) = data.split_first() else {
        return;
    };
    match selector % 7 {
        0 => {
            let _ = MldsaPublicKey::from_bytes(payload);
        }
        1 => {
            let _ = MldsaPrivateKey::from_bytes(payload);
        }
        2 => {
            let _ = MldsaSignature::from_bytes(payload);
        }
        3 => {
            let _: Result<PqChannelClientHelloV1, _> =
                bincode::DefaultOptions::new().with_limit(1 << 20).deserialize(payload);
        }
        4 => {
            let _: Result<PqChannelServerHelloV1, _> =
                bincode::DefaultOptions::new().with_limit(1 << 20).deserialize(payload);
        }
        5 => {
            let _: Result<PqChannelClientFinishV1, _> =
                bincode::DefaultOptions::new().with_limit(1 << 20).deserialize(payload);
        }
        _ => {
            let _: Result<PqChannelRecordV1, _> =
                bincode::DefaultOptions::new().with_limit(1 << 20).deserialize(payload);
        }
    }
});
