//! AFT terminal-share signing and verification.
//!
//! The Ed25519 R9 implementation in this file is retained only as a legacy
//! conformance reference. Production migration targets [`SealShareV2`], whose
//! SLH-DSA key must match an enrolled configuration/key-root manifest.
//!
//! Every seal share is INDIVIDUALLY verifiable (the P2.6 wire
//! discipline): a share carries its own per-seal public key and
//! signature, so a certificate is a bitmap of attributable statements —
//! never an opaque aggregate — and forensic extraction can name every
//! participant of a staged conflict from the shares alone.
//!
//! KEY EVOLUTION (everlasting safety): the signer derives one Ed25519
//! keypair per seal index from a ratcheting seed
//! (`seed_{i+1} = H(seed_i || seal_hash_i)`) and ERASES the spent seed
//! in the same call that completes the share — overwrite-then-ratchet,
//! no deferred cleanup. After seal `i`, no bytes of `seed_i` exist in
//! the signer's state and the signer structurally cannot produce a
//! second share for slot `i`. Compromise after seal `i` therefore
//! yields only future seeds: past seals stay unforgeable.
//!
//! HONEST-PUBLICATION DUTY (C7 rider): completing a share RETURNS the
//! publication record — emitting and publishing are one act at this
//! API, so withholding requires deliberately discarding the record the
//! signer already handed back. (T5d itself is withdrawn for this cycle;
//! the DUTY is the mechanism that survives in the signer.)
//!
//! PQ MIGRATION (C7): the ratchet is hash-only (already PQ-friendly);
//! the per-seal signature scheme is Ed25519 today and the migration
//! path — swap the leaf scheme for a hash-based one-time signature
//! under the SAME ratchet — is documented in the AFT corpus. The seed
//! ratchet needs no change for that swap.

use dcrypt::algorithms::hash::{HashFunction, Sha256};
use ioi_api::crypto::{SerializableKey, SigningKeyPair, VerifyingKey};
use ioi_crypto::sign::eddsa::{
    Ed25519KeyPair, Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature,
};
use ioi_types::app::consensus::{
    SealKeyBindingV1, SealKeyManifestV1, SealShareV2, AFT_SEAL_PROTOCOL_VERSION_V2,
    AFT_SEAL_SHARE_SCHEMA_V2,
};
use ioi_types::error::CryptoError as TypesCryptoError;
use rand::RngCore;
use slh_dsa::signature::Signer;
use slh_dsa::{Sha2_128s, Signature as SlhDsaSignature, SigningKey as SlhDsaSigningKey};
use zeroize::Zeroizing;

/// One attribution-preserving seal share: individually verifiable from
/// its own contents plus the seal hash — no aggregate, no context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealShare {
    /// The member's stable account identity (bitmap position owner).
    pub member_index: u32,
    /// The seal index this share signs.
    pub seal_index: u64,
    /// The seal hash signed.
    pub seal_hash: [u8; 32],
    /// The per-seal public key (published WITH the share).
    pub public_key_bytes: Vec<u8>,
    /// The Ed25519 signature over the domain-separated seal tuple.
    pub signature_bytes: Vec<u8>,
}

/// The publication record handed back by share emission: the share plus
/// its duty statement. Emitting IS publishing at this API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharePublicationRecord {
    /// The share to publish.
    pub share: SealShare,
    /// The ratchet commitment for the NEXT seal (verifiers can pin the
    /// signer's forward chain without learning any seed).
    pub next_key_commitment: [u8; 32],
}

fn domain_separated_message(seal_index: u64, seal_hash: &[u8; 32]) -> Vec<u8> {
    let mut message = Vec::with_capacity(b"aft::seal-share::v1".len() + 8 + seal_hash.len());
    message.extend_from_slice(b"aft::seal-share::v1");
    message.extend_from_slice(&seal_index.to_be_bytes());
    message.extend_from_slice(seal_hash);
    message
}

fn sha256_fixed(material: &[u8]) -> Result<[u8; 32], String> {
    let digest = Sha256::digest(material).map_err(|e| format!("{e:?}"))?;
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_ref());
    Ok(out)
}

/// Verifies one share against a seal hash: the share's OWN public key
/// and signature suffice — attribution needs nothing else.
pub fn verify_seal_share(share: &SealShare) -> Result<(), String> {
    let public_key = Ed25519PublicKey::from_bytes(&share.public_key_bytes)
        .map_err(|e: TypesCryptoError| e.to_string())?;
    let signature = Ed25519Signature::from_bytes(&share.signature_bytes)
        .map_err(|e: TypesCryptoError| e.to_string())?;
    let message = domain_separated_message(share.seal_index, &share.seal_hash);
    public_key
        .verify(&message, &signature)
        .map_err(|e| e.to_string())
}

/// In-memory SLH-DSA key material used by the v2 signer state machine.
///
/// The selected provider zeroizes its secret seed and PRF material on drop.
/// This type is deliberately not `Clone`; durable reservation and clone
/// detection are implemented by the state store rather than by duplicating
/// secret-bearing values.
pub struct SlhDsaSealKeyPair {
    signing_key: SlhDsaSigningKey<Sha2_128s>,
}

impl SlhDsaSealKeyPair {
    /// Generates a fresh FIPS 205 SLH-DSA-SHA2-128s key using three
    /// independently sampled 128-bit seeds.
    pub fn generate() -> Self {
        let mut sk_seed = [0u8; 16];
        let mut sk_prf = [0u8; 16];
        let mut pk_seed = [0u8; 16];
        let mut rng = rand::rngs::OsRng;
        rng.fill_bytes(&mut sk_seed);
        rng.fill_bytes(&mut sk_prf);
        rng.fill_bytes(&mut pk_seed);
        let signing_key =
            SlhDsaSigningKey::<Sha2_128s>::slh_keygen_internal(&sk_seed, &sk_prf, &pk_seed);
        sk_seed.fill(0);
        sk_prf.fill(0);
        pk_seed.fill(0);
        Self { signing_key }
    }

    /// Deterministically constructs key material for FIPS known-answer and
    /// independent interoperability vectors.
    pub fn from_seed_material(sk_seed: [u8; 16], sk_prf: [u8; 16], pk_seed: [u8; 16]) -> Self {
        Self {
            signing_key: SlhDsaSigningKey::<Sha2_128s>::slh_keygen_internal(
                &sk_seed, &sk_prf, &pk_seed,
            ),
        }
    }

    /// Exact FIPS 205 public-key encoding committed by the configuration.
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.signing_key.as_ref().to_vec()
    }

    /// Reconstructs provider key material from the encrypted durable state.
    pub fn from_secret_key_bytes(bytes: &[u8]) -> Result<Self, String> {
        let signing_key = SlhDsaSigningKey::<Sha2_128s>::try_from(bytes)
            .map_err(|_| "invalid SLH-DSA-SHA2-128s secret key".to_string())?;
        Ok(Self { signing_key })
    }

    /// Serializes secret material only for immediate encrypted persistence.
    /// The returned allocation zeroizes on drop.
    pub fn secret_key_bytes(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.signing_key.to_vec())
    }

    /// Constructs and signs one identity-, configuration-, domain-, slot-,
    /// root-, suite-, and successor-bound v2 terminal share.
    pub fn sign_share(
        &self,
        current_key: SealKeyBindingV1,
        seal_slot: u64,
        seal_root: [u8; 32],
        next_key_commitment: [u8; 32],
    ) -> Result<SealShareV2, String> {
        if current_key.public_key != self.public_key_bytes() {
            return Err("v2 signing key does not match the scheduled public key".into());
        }
        let mut share = SealShareV2 {
            protocol_version: AFT_SEAL_PROTOCOL_VERSION_V2,
            schema_version: AFT_SEAL_SHARE_SCHEMA_V2,
            current_key,
            seal_slot,
            seal_root,
            next_key_commitment,
            signature: Vec::new(),
        };
        let message = share.signing_bytes()?;
        let signature: SlhDsaSignature<Sha2_128s> = self
            .signing_key
            .try_sign(&message)
            .map_err(|_| "SLH-DSA terminal signing failed".to_string())?;
        share.signature = signature.to_vec();
        share.validate_shape()?;
        Ok(share)
    }
}

mod state;
pub use state::*;

/// Verifies a v2 share only after its current public key matches the exact
/// enrolled or predecessor-provided commitment supplied by the caller.
pub fn verify_seal_share_v2(
    share: &SealShareV2,
    expected_key_commitment: [u8; 32],
) -> Result<(), String> {
    ioi_crypto::sign::slh_dsa::verify_seal_share_v2(share, expected_key_commitment)
}

/// Verifies the first v2 share for a scope against configuration-owned
/// enrollment. There is intentionally no fallback to a key carried by an
/// otherwise unrecognized share.
pub fn verify_initial_seal_share_v2(
    share: &SealShareV2,
    manifest: &SealKeyManifestV1,
) -> Result<(), String> {
    ioi_crypto::sign::slh_dsa::verify_initial_seal_share_v2(share, manifest)
}

/// The forensic result of examining two certificates for one slot:
/// every member whose shares sign CONFLICTING roots, named individually.
pub fn extract_double_signers(left: &[SealShare], right: &[SealShare]) -> Result<Vec<u32>, String> {
    let mut offenders = Vec::new();
    for share in left {
        verify_seal_share(share)?;
    }
    for share in right {
        verify_seal_share(share)?;
    }
    for l in left {
        for r in right {
            if l.member_index == r.member_index
                && l.seal_index == r.seal_index
                && l.seal_hash != r.seal_hash
                && !offenders.contains(&l.member_index)
            {
                offenders.push(l.member_index);
            }
        }
    }
    offenders.sort_unstable();
    Ok(offenders)
}

/// The evolving seal signer: one ratcheting seed, one keypair per seal,
/// spent seeds erased in the emitting call.
pub struct EvolvingSealSigner {
    member_index: u32,
    seal_index: u64,
    /// The CURRENT seed. Spent seeds are overwritten with zeros and then
    /// replaced — no historical seed survives in this struct, and the
    /// erasure test pins that at the byte level.
    seed: [u8; 32],
}

impl EvolvingSealSigner {
    /// Creates a signer from an initial seed (provisioned once per
    /// member; the estate's key-custody plane owns HOW the initial seed
    /// arrives).
    pub fn new(member_index: u32, initial_seed: [u8; 32]) -> Self {
        Self {
            member_index,
            seal_index: 0,
            seed: initial_seed,
        }
    }

    /// The signer's current seal index (the next share it will emit).
    pub fn seal_index(&self) -> u64 {
        self.seal_index
    }

    /// The commitment to the current key (H(seed)): verifiers can pin
    /// the forward chain without learning the seed.
    pub fn current_key_commitment(&self) -> Result<[u8; 32], String> {
        sha256_fixed(&self.seed)
    }

    fn keypair_for_current_seed(&self) -> Result<Ed25519KeyPair, String> {
        let private = Ed25519PrivateKey::from_bytes(&self.seed).map_err(|e| e.to_string())?;
        Ed25519KeyPair::from_private_key(&private).map_err(|e| e.to_string())
    }

    /// Emits the share for the CURRENT seal index over `seal_hash`,
    /// then — in this same call — erases the spent seed (overwrite with
    /// zeros) and ratchets forward. Returns the publication record:
    /// emitting is publishing.
    ///
    /// After this returns, the signer cannot produce a second share for
    /// the spent index: the key material no longer exists.
    pub fn emit_share(&mut self, seal_hash: [u8; 32]) -> Result<SharePublicationRecord, String> {
        let keypair = self.keypair_for_current_seed()?;
        let message = domain_separated_message(self.seal_index, &seal_hash);
        let signature = keypair.sign(&message).map_err(|e| e.to_string())?;
        let share = SealShare {
            member_index: self.member_index,
            seal_index: self.seal_index,
            seal_hash,
            public_key_bytes: keypair.public_key().to_bytes(),
            signature_bytes: signature.to_bytes(),
        };

        // Ratchet: next_seed = H(spent_seed || seal_hash), then ERASE
        // the spent seed by overwriting before replacing — the spent
        // bytes never outlive this call.
        let mut material = Vec::with_capacity(32 + 32);
        material.extend_from_slice(&self.seed);
        material.extend_from_slice(&seal_hash);
        let next_seed = sha256_fixed(&material)?;
        material.fill(0);
        self.seed.fill(0);
        self.seed = next_seed;
        self.seal_index += 1;

        let next_key_commitment = self.current_key_commitment()?;
        Ok(SharePublicationRecord {
            share,
            next_key_commitment,
        })
    }

    /// The signer's serialized state — exactly what would persist. The
    /// erasure gate searches this for spent-seed bytes and must find
    /// none.
    pub fn state_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(4 + 8 + 32);
        bytes.extend_from_slice(&self.member_index.to_be_bytes());
        bytes.extend_from_slice(&self.seal_index.to_be_bytes());
        bytes.extend_from_slice(&self.seed);
        bytes
    }
}

#[cfg(test)]
#[path = "seal_signer/tests.rs"]
mod tests;
