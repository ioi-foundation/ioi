use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use dcrypt::{
    api::Signature as DcryptSignature,
    sign::mldsa::{
        MlDsa44 as DcryptMlDsa44, MlDsaPublicKey as DcryptPublicKey,
        MlDsaSecretKey as DcryptSecretKey, MlDsaSignature as DcryptSignatureData,
    },
};
use ml_dsa::{
    Keypair, MlDsa44, Signature as RustCryptoSignature, SigningKey, Verifier, VerifyingKey, B32,
};
use slh_dsa::{
    signature::Signer as SlhSigner, Sha2_128s, Signature as SlhSignature,
    SigningKey as SlhSigningKey, VerifyingKey as SlhVerifyingKey,
};

const MESSAGE: &[u8] = b"AFT/FIPS204/ML-DSA-44/cross-implementation/v1";

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("verify-ml-dsa-44") {
        if args.len() != 5 {
            eprintln!("usage: aft-pq-interop verify-ml-dsa-44 <public-key-base64> <signature-base64> <message-base64>");
            std::process::exit(2);
        }
        let public = BASE64.decode(&args[2]).expect("public key base64");
        let signature = BASE64.decode(&args[3]).expect("signature base64");
        let message = BASE64.decode(&args[4]).expect("message base64");
        let public = ml_dsa::EncodedVerifyingKey::<MlDsa44>::try_from(public.as_slice())
            .map(|encoded| VerifyingKey::<MlDsa44>::decode(&encoded))
            .expect("ML-DSA-44 public key length");
        let signature = RustCryptoSignature::<MlDsa44>::try_from(signature.as_slice())
            .expect("ML-DSA-44 signature length");
        if public.verify(&message, &signature).is_err() {
            eprintln!("ML-DSA-44 signature invalid");
            std::process::exit(1);
        }
        println!("ML-DSA-44 receipt signature ok (independent RustCrypto verifier)");
        return;
    }
    if args.get(1).map(String::as_str) == Some("verify-slh-dsa-sha2-128s") {
        if args.len() != 5 {
            eprintln!("usage: aft-pq-interop verify-slh-dsa-sha2-128s <public-key-base64> <signature-base64> <message-base64>");
            std::process::exit(2);
        }
        use fips205::{
            slh_dsa_sha2_128s as independent,
            traits::{SerDes, Verifier as IndependentVerifier},
        };
        let public: [u8; 32] = BASE64
            .decode(&args[2])
            .expect("public key base64")
            .try_into()
            .expect("SLH-DSA-SHA2-128s public key length");
        let signature: [u8; 7_856] = BASE64
            .decode(&args[3])
            .expect("signature base64")
            .try_into()
            .expect("SLH-DSA-SHA2-128s signature length");
        let message = BASE64.decode(&args[4]).expect("message base64");
        let public = independent::PublicKey::try_from_bytes(&public)
            .expect("SLH-DSA-SHA2-128s public key encoding");
        if !public.verify(&message, &signature, &[]) {
            eprintln!("SLH-DSA-SHA2-128s signature invalid");
            std::process::exit(1);
        }
        println!("SLH-DSA-SHA2-128s signature ok (independent fips205 verifier)");
        return;
    }
    check_mldsa44();
    check_slhdsa_sha2_128s();
}

fn check_mldsa44() {
    let signing_key = SigningKey::<MlDsa44>::from_seed(&B32::from([0x42; 32]));
    let rustcrypto_secret = signing_key.expanded_key();
    let rustcrypto_public = signing_key.verifying_key();
    #[allow(deprecated)]
    let secret_bytes = rustcrypto_secret.to_expanded();
    let public_bytes = rustcrypto_public.encode();

    let dcrypt_public = DcryptPublicKey::from_bytes(public_bytes.as_slice())
        .expect("dcrypt must import RustCrypto public encoding");
    let dcrypt_secret =
        DcryptSecretKey::from_bytes_with_public_key(secret_bytes.as_slice(), &dcrypt_public)
            .expect("dcrypt must import and validate RustCrypto expanded key encoding");

    let rustcrypto_signature = rustcrypto_secret
        .sign_deterministic(MESSAGE, &[])
        .expect("RustCrypto deterministic signing must succeed");
    let rustcrypto_signature_bytes = rustcrypto_signature.encode();
    let imported_rustcrypto_signature =
        DcryptSignatureData::from_bytes(rustcrypto_signature_bytes.as_slice())
            .expect("dcrypt must import RustCrypto signature encoding");
    DcryptMlDsa44::verify(MESSAGE, &imported_rustcrypto_signature, &dcrypt_public)
        .expect("dcrypt must verify RustCrypto signature");

    let dcrypt_signature = DcryptMlDsa44::sign_deterministic(MESSAGE, &dcrypt_secret)
        .expect("dcrypt deterministic signing must succeed");
    let imported_dcrypt_signature =
        RustCryptoSignature::<MlDsa44>::try_from(dcrypt_signature.as_ref())
            .expect("RustCrypto must import dcrypt signature encoding");
    assert!(
        VerifyingKey::<MlDsa44>::decode(&public_bytes)
            .verify(MESSAGE, &imported_dcrypt_signature)
            .is_ok(),
        "RustCrypto must verify dcrypt signature"
    );

    assert_eq!(
        rustcrypto_signature_bytes.as_slice(),
        dcrypt_signature.as_ref(),
        "deterministic FIPS 204 signatures must agree byte-for-byte"
    );
    println!(
        "ML-DSA-44 interop ok: pk={} sk={} sig={} deterministic_match=true",
        public_bytes.len(),
        secret_bytes.len(),
        dcrypt_signature.as_ref().len()
    );
}

fn check_slhdsa_sha2_128s() {
    use fips205::{
        slh_dsa_sha2_128s as independent,
        traits::{KeyGen, SerDes, Signer as IndependentSigner, Verifier as IndependentVerifier},
    };

    const SK_SEED: [u8; 16] = [0x11; 16];
    const SK_PRF: [u8; 16] = [0x22; 16];
    const PK_SEED: [u8; 16] = [0x33; 16];

    let production_secret =
        SlhSigningKey::<Sha2_128s>::slh_keygen_internal(&SK_SEED, &SK_PRF, &PK_SEED);
    let production_public = production_secret.verifying_key();
    let production_public_bytes = production_public.to_bytes();
    let (independent_public, independent_secret) =
        independent::KG::keygen_with_seeds(&SK_SEED, &SK_PRF, &PK_SEED);
    let independent_public_bytes = independent_public.clone().into_bytes();
    assert_eq!(
        production_public_bytes.as_slice(),
        independent_public_bytes.as_slice(),
        "independent SLH-DSA key generation must agree byte-for-byte"
    );

    let production_signature: SlhSignature<Sha2_128s> = production_secret
        .try_sign(MESSAGE)
        .expect("production SLH-DSA deterministic signing must succeed");
    let production_signature_bytes: [u8; 7_856] = production_signature
        .to_vec()
        .try_into()
        .expect("production signature has the FIPS 205 fixed size");
    assert!(
        independent_public.verify(MESSAGE, &production_signature_bytes, &[]),
        "independent implementation must verify production SLH-DSA signature"
    );

    let independent_signature = independent_secret
        .try_sign(MESSAGE, &[], false)
        .expect("independent deterministic SLH-DSA signing must succeed");
    let imported_independent_signature =
        SlhSignature::<Sha2_128s>::try_from(independent_signature.as_slice())
            .expect("production implementation must import independent signature");
    let imported_independent_public =
        SlhVerifyingKey::<Sha2_128s>::try_from(independent_public_bytes.as_slice())
            .expect("production implementation must import independent public key");
    imported_independent_public
        .verify(MESSAGE, &imported_independent_signature)
        .expect("production implementation must verify independent SLH-DSA signature");

    assert_eq!(
        production_signature_bytes.as_slice(),
        independent_signature.as_slice(),
        "deterministic FIPS 205 signatures must agree byte-for-byte"
    );
    println!(
        "SLH-DSA-SHA2-128s interop ok: pk={} sig={} deterministic_match=true",
        independent_public_bytes.len(),
        independent_signature.len()
    );
}
