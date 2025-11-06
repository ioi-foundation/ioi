// Path: crates/relayer/src/handshake.rs
use crate::gateway::Gateway;
use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use depin_sdk_crypto::algorithms::hash::sha256;
use depin_sdk_types::codec as scodec;
use ibc_core_host_types::path::{
    ChannelEndPath, ClientConsensusStatePath, ClientStatePath, ConnectionPath,
    NextChannelSequencePath, NextConnectionSequencePath,
};
use ibc_proto::{
    google::protobuf::Any as PbAny,
    ibc::core::{
        channel::v1 as pbchan,
        client::v1 as pbclient,
        client::v1::Height as PbHeight,
        commitment::v1::{MerklePrefix, MerkleProof as PbMerkleProof},
        connection::v1 as pbconn,
    },
    ics23 as pb_ics23,
};
use ics23::HostFunctionsManager;
use prost::Message;
use serde::Deserialize;
use serde_json::Value as JsonValue;
use std::str;
use tendermint_proto::crypto::{ProofOp as TmProofOp, ProofOps as TmProofOps};
use tokio::time::{sleep, Duration};

/// Canonical IBC key prefix used in Merkle proofs (ICS‑24).
pub const IBC_PREFIX: &[u8] = b"ibc";

/// Safety cap for nested `google.protobuf.Any` envelopes.
const ANY_MAX_DEPTH: usize = 32;

// ---------- DEBUG helpers ----------
#[inline]
fn hex_prefix(bytes: &[u8], n: usize) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(n * 2);
    for &b in bytes.iter().take(n) {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Try to interpret `inner` as a non‑SCALE length‑prefixed blob:
/// [u32/u64 (LE or BE) length] + [payload].
#[inline]
fn tail_as_len_prefixed(inner: &[u8]) -> Option<&[u8]> {
    // u32 LE / BE
    if inner.len() >= 4 {
        let (p4, rest) = inner.split_at(4);
        let n_le = u32::from_le_bytes([p4[0], p4[1], p4[2], p4[3]]) as usize;
        if n_le <= rest.len() {
            return Some(&rest[..n_le]);
        }
        let n_be = u32::from_be_bytes([p4[0], p4[1], p4[2], p4[3]]) as usize;
        if n_be <= rest.len() {
            return Some(&rest[..n_be]);
        }
    }
    // u64 LE / BE
    if inner.len() >= 8 {
        let (p8, rest) = inner.split_at(8);
        let n_le = u64::from_le_bytes(p8.try_into().ok()?) as usize;
        if n_le <= rest.len() {
            return Some(&rest[..n_le]);
        }
        let n_be = u64::from_be_bytes(p8.try_into().ok()?) as usize;
        if n_be <= rest.len() {
            return Some(&rest[..n_be]);
        }
    }
    None
}

// --------------------------------------------------------------------------------------
// Local SCALE wire types for IAVL proofs (mirror of commitment/src/tree/iavl/proof.rs).
// This avoids importing the private `proof` module across crate boundaries.
// Keep field and variant order exactly in sync with the canonical types.
// --------------------------------------------------------------------------------------
mod iavl_wire {
    use parity_scale_codec::Decode;

    #[derive(Decode, Debug, Clone, PartialEq, Eq)]
    pub enum IavlProof {
        Existence(ExistenceProof),
        NonExistence(NonExistenceProof),
    }

    #[derive(Decode, Debug, Clone, PartialEq, Eq)]
    pub struct ExistenceProof {
        pub key: Vec<u8>,
        pub value: Vec<u8>,
        pub leaf: LeafOp,
        pub path: Vec<InnerOp>,
    }

    #[derive(Decode, Debug, Clone, PartialEq, Eq)]
    pub struct NonExistenceProof {
        pub missing_key: Vec<u8>,
        pub left: Option<ExistenceProof>,
        pub right: Option<ExistenceProof>,
    }

    #[derive(Decode, Debug, Clone, PartialEq, Eq)]
    pub struct LeafOp {
        pub version: u64,
    }

    #[derive(Decode, Debug, Clone, PartialEq, Eq)]
    pub enum Side {
        Left,
        Right,
    }

    #[derive(Decode, Debug, Clone, PartialEq, Eq)]
    pub struct InnerOp {
        pub version: u64,
        pub height: i32,
        pub size: u64,
        pub split_key: Vec<u8>,
        pub side: Side,
        pub sibling_hash: [u8; 32],
    }
}
use iavl_wire::{ExistenceProof, IavlProof, InnerOp, LeafOp, NonExistenceProof, Side};

/// Lightweight classifier: does a proof byte blob indicate **membership** (existence) vs non‑membership?
/// Returns Some(true) for membership, Some(false) for explicit non‑membership, None if undecidable.
fn proof_indicates_membership(proof_bytes: &[u8]) -> Option<bool> {
    // SCALE IAVL
    if let Some(p) = decode_scale_iavl_proof(proof_bytes) {
        return Some(matches!(p, IavlProof::Existence(_)));
    }
    // ICS‑23 CommitmentProof (protobuf)
    if let Ok(cp) = decode_pb::<pb_ics23::CommitmentProof>(proof_bytes) {
        let has_exist = match cp.proof {
            Some(pb_ics23::commitment_proof::Proof::Exist(_)) => true,
            Some(pb_ics23::commitment_proof::Proof::Batch(batch)) => batch
                .entries
                .iter()
                .any(|e| matches!(e.proof, Some(pb_ics23::batch_entry::Proof::Exist(_)))),
            Some(pb_ics23::commitment_proof::Proof::Compressed(compr)) => {
                compr.entries.iter().any(|e| {
                    matches!(
                        e.proof,
                        Some(pb_ics23::compressed_batch_entry::Proof::Exist(_))
                    )
                })
            }
            _ => false,
        };
        return Some(has_exist);
    }
    // ICS‑23 MerkleProof wrapper
    if let Ok(mp) = decode_pb::<PbMerkleProof>(proof_bytes) {
        for cp in mp.proofs {
            if let Some(proof_variant) = cp.proof {
                match proof_variant {
                    pb_ics23::commitment_proof::Proof::Exist(_) => return Some(true),
                    pb_ics23::commitment_proof::Proof::Batch(b) => {
                        if b.entries.iter().any(|e| {
                            matches!(e.proof, Some(pb_ics23::batch_entry::Proof::Exist(_)))
                        }) {
                            return Some(true);
                        }
                    }
                    pb_ics23::commitment_proof::Proof::Compressed(c) => {
                        if c.entries.iter().any(|e| {
                            matches!(
                                e.proof,
                                Some(pb_ics23::compressed_batch_entry::Proof::Exist(_))
                            )
                        }) {
                            return Some(true);
                        }
                    }
                    _ => {} // Continue loop if this cp doesn't prove existence
                }
            }
        }
        return Some(false);
    }
    // Tendermint ProofOps
    if let Ok(ops) = decode_pb::<TmProofOps>(proof_bytes) {
        for op in ops.ops {
            if let Ok(cp) = decode_pb::<pb_ics23::CommitmentProof>(&op.data) {
                return proof_indicates_membership(&cp.encode_to_vec());
            }
        }
        return None;
    }
    if let Ok(op) = decode_pb::<TmProofOp>(proof_bytes) {
        if let Ok(cp) = decode_pb::<pb_ics23::CommitmentProof>(&op.data) {
            return proof_indicates_membership(&cp.encode_to_vec());
        }
        return None;
    }
    None
}

// -------------------------------
// [SCALE‑IAVL] specific decoders for gateway envelopes
// -------------------------------

/// Try to derive a root from a textual envelope (JSON/base64/hex).
fn root_from_string_envelope(s: &str) -> Option<Vec<u8>> {
    let st = s.trim();
    // base64 → raw → ICS‑23 / ProofOps / Any / JSON
    if is_ascii_base64(st) {
        if let Some(raw) = b64_decode_any(st) {
            return root_from_any_ics23_like_bytes(&raw)
                .or_else(|| root_from_json_proofops_bytes(&raw))
                .or_else(|| root_from_json_any_like_bytes(&raw))
                .or_else(|| scan_for_embedded_ics23_or_tm(&raw));
        }
    }
    // 0x… or bare hex
    if let Some(hex_str) = st.strip_prefix("0x").or_else(|| st.strip_prefix("0X")) {
        if let Ok(raw) = hex::decode(hex_str) {
            return root_from_any_ics23_like_bytes(&raw)
                .or_else(|| scan_for_embedded_ics23_or_tm(&raw));
        }
    } else if is_ascii_hex(st.as_bytes()) {
        if let Ok(raw) = hex::decode(st) {
            return root_from_any_ics23_like_bytes(&raw)
                .or_else(|| scan_for_embedded_ics23_or_tm(&raw));
        }
    }
    // JSON strings
    if st.starts_with('{') || st.starts_with('[') {
        return root_from_json_proofops_bytes(st.as_bytes())
            .or_else(|| root_from_json_any_like_bytes(st.as_bytes()));
    }
    None
}

/// Try to compute a root from a *tail* that may begin with:
///  - SCALE(IavlProof),
///  - SCALE(Vec<u8>) containing SCALE(IavlProof) (possibly nested),
///  - Any ICS‑23 form (protobuf Any / CommitmentProof / ProofOps, or JSON).
fn root_from_scale_tail_any_proof(mut tail: &[u8]) -> Option<Vec<u8>> {
    // (a) Direct SCALE(IavlProof) at the tail
    if let Ok(p) = <IavlProof as parity_scale_codec::Decode>::decode(&mut tail) {
        let root = match p {
            IavlProof::Existence(ex) => compute_iavl_root_from_existence(&ex),
            IavlProof::NonExistence(ne) => compute_iavl_root_from_nonexistence(&ne),
        }
        .ok()?;
        return Some(root.to_vec());
    }

    // (b) Tail starts with SCALE(Vec<u8>) — *not necessarily canonical-length matched*.
    // Use parity's Decode (consumes prefix only), then peel repeated SCALE(Vec<u8>) and decode.
    {
        let mut t = tail;
        if let Ok(inner) = <Vec<u8> as parity_scale_codec::Decode>::decode(&mut t) {
            // Peel any nested SCALE(Vec<u8>) wrappers we might find inside
            let inner = peel_all_scale_vec(inner);
            // Try SCALE(IavlProof)
            if let Ok(p) = <IavlProof as parity_scale_codec::Decode>::decode(&mut &*inner) {
                let root = match p {
                    IavlProof::Existence(ex) => compute_iavl_root_from_existence(&ex),
                    IavlProof::NonExistence(ne) => compute_iavl_root_from_nonexistence(&ne),
                }
                .ok()?;
                return Some(root.to_vec());
            }
            // Try ICS‑23 / Any / ProofOps on the peeled inner bytes
            if let Some(root) = root_from_any_ics23_like_bytes(&inner)
                .or_else(|| root_from_json_proofops_bytes(&inner))
                .or_else(|| root_from_json_any_like_bytes(&inner))
            {
                return Some(root);
            }
        }
    }

    // (c.1) Tail starts with a NON‑SCALE len prefix: [u32/u64 (LE/BE)] + payload
    if let Some(inner) = tail_as_len_prefixed(tail) {
        // Some stacks put another SCALE(Vec<u8>) around the payload; peel if present.
        let peeled = peel_all_scale_vec(inner.to_vec());

        // Try SCALE(IavlProof) first on peeled bytes
        if let Ok(p) = <IavlProof as parity_scale_codec::Decode>::decode(&mut &*peeled) {
            let root = match p {
                IavlProof::Existence(ex) => compute_iavl_root_from_existence(&ex),
                IavlProof::NonExistence(ne) => compute_iavl_root_from_nonexistence(&ne),
            }
            .ok()?;
            return Some(root.to_vec());
        }

        // ICS‑23 / Any / ProofOps on peeled bytes
        if let Some(root) = root_from_any_ics23_like_bytes(&peeled)
            .or_else(|| root_from_json_proofops_bytes(&peeled))
            .or_else(|| root_from_json_any_like_bytes(&peeled))
        {
            return Some(root);
        }

        // Or directly on the raw payload
        if let Some(root) = root_from_any_ics23_like_bytes(inner)
            .or_else(|| root_from_json_proofops_bytes(inner))
            .or_else(|| root_from_json_any_like_bytes(inner))
        {
            return Some(root);
        }
    }

    // (c) Some gateways encode the whole tail as canonical SCALE(Vec<u8>) with no trailing bytes.
    if let Ok(inner) = scodec::from_bytes_canonical::<Vec<u8>>(tail) {
        let inner = peel_all_scale_vec(inner);
        if let Ok(p) = <IavlProof as parity_scale_codec::Decode>::decode(&mut &*inner) {
            let root = match p {
                IavlProof::Existence(ex) => compute_iavl_root_from_existence(&ex),
                IavlProof::NonExistence(ne) => compute_iavl_root_from_nonexistence(&ne),
            }
            .ok()?;
            return Some(root.to_vec());
        }
        if let Some(root) = root_from_any_ics23_like_bytes(&inner)
            .or_else(|| root_from_json_proofops_bytes(&inner))
            .or_else(|| root_from_json_any_like_bytes(&inner))
        {
            return Some(root);
        }
    }

    // (b2) Tail starts with SCALE(Option<Vec<u8>>)
    {
        let mut t = tail;
        if let Ok(opt) = <Option<Vec<u8>> as parity_scale_codec::Decode>::decode(&mut t) {
            if let Some(inner0) = opt {
                let inner = peel_all_scale_vec(inner0);
                if let Ok(p) = <IavlProof as parity_scale_codec::Decode>::decode(&mut &*inner) {
                    let root = match p {
                        IavlProof::Existence(ex) => compute_iavl_root_from_existence(&ex),
                        IavlProof::NonExistence(ne) => compute_iavl_root_from_nonexistence(&ne),
                    }
                    .ok()?;
                    return Some(root.to_vec());
                }
                if let Some(root) = root_from_any_ics23_like_bytes(&inner)
                    .or_else(|| root_from_json_proofops_bytes(&inner))
                    .or_else(|| root_from_json_any_like_bytes(&inner))
                {
                    return Some(root);
                }
            }
        }
    }

    // (b3) Tail starts with SCALE(Option<String>) or SCALE(String)
    {
        let mut t = tail;
        if let Ok(opt) = <Option<String> as parity_scale_codec::Decode>::decode(&mut t) {
            if let Some(s) = opt {
                if let Some(root) = root_from_string_envelope(&s) {
                    return Some(root);
                }
            }
        }
    }
    {
        let mut t = tail;
        if let Ok(s) = <String as parity_scale_codec::Decode>::decode(&mut t) {
            if let Some(root) = root_from_string_envelope(&s) {
                return Some(root);
            }
        }
    }

    // (d) Finally, the tail itself might be ICS‑23/Any/ProofOps/JSON, or they may be embedded
    //     at a non-zero offset inside a larger SCALE blob.
    root_from_any_ics23_like_bytes(tail)
        .or_else(|| root_from_json_proofops_bytes(tail))
        .or_else(|| root_from_json_any_like_bytes(tail))
        .or_else(|| scan_for_embedded_ics23_or_tm(tail))
}

/// Decodes SCALE(Compact<u32> selector + Option<String> path + IavlProof) and computes the root.
fn root_from_scale_selector_then_opt_path_then_iavl(bytes: &[u8]) -> Option<Vec<u8>> {
    let mut cur = &*bytes;

    // 0) Leading selector/version/tag as SCALE Compact<u32> (discarded)
    let _selector: parity_scale_codec::Compact<u32> =
        <parity_scale_codec::Compact<u32> as parity_scale_codec::Decode>::decode(&mut cur).ok()?;

    // 1) Optional path String (Some(path) -> 0x01 + SCALE(String))
    let _path_opt: Option<String> =
        <Option<String> as parity_scale_codec::Decode>::decode(&mut cur).ok()?;

    // 2) Tail may be SCALE(IavlProof), SCALE(Vec<u8>→…),
    //    or ICS‑23 (protobuf/Any/ProofOps) — try them in a robust order.
    root_from_scale_tail_any_proof(cur)
}

/// Decodes SCALE(u8 tag + String(path) + IavlProof) and computes the root.
/// (kept for other chains/versions that emit this shape)
fn root_from_scale_path_then_iavl(bytes: &[u8]) -> Option<Vec<u8>> {
    let mut cur = &*bytes;

    // 1) Leading tag/variant byte (ignored but required to advance)
    let _tag: u8 = <u8 as parity_scale_codec::Decode>::decode(&mut cur).ok()?;

    // 2) Path as SCALE String (ignored for hashing)
    let _path: String = <String as parity_scale_codec::Decode>::decode(&mut cur).ok()?; // e.g. "nextConnectionSequence"

    // 3) Tail may be SCALE(IavlProof) or wrapped/ICS‑23; handle generically.
    root_from_scale_tail_any_proof(cur)
}

// -------------------------------
// [SCALE‑IAVL] precise decoder & root calculator
// -------------------------------

/// Decode the gateway payload which is:
///   SCALE(Vec<u8>) where the Vec<u8> is SCALE(IavlProof).
fn decode_scale_iavl_proof(bytes: &[u8]) -> Option<IavlProof> {
    // 1) Try the expected outer Vec<u8> wrapper (canonical codec)
    if let Ok(inner) = scodec::from_bytes_canonical::<Vec<u8>>(bytes) {
        if let Ok(p) = <IavlProof as parity_scale_codec::Decode>::decode(&mut &*inner) {
            return Some(p);
        }
    }
    // 2) Some call sites might already hand the inner bytes (SCALE(IavlProof))
    if let Ok(p) = <IavlProof as parity_scale_codec::Decode>::decode(&mut &*bytes) {
        return Some(p);
    }
    None
}

#[inline]
fn hash_leaf_canonical(leaf: &LeafOp, key: &[u8], value: &[u8]) -> Result<[u8; 32]> {
    // Matches crates/commitment/src/tree/iavl/proof.rs::hash_leaf
    let mut data = Vec::with_capacity(1 + 8 + 4 + 8 + 4 + key.len() + 4 + value.len());
    data.push(0x00);
    data.extend_from_slice(&leaf.version.to_le_bytes());
    data.extend_from_slice(&0i32.to_le_bytes()); // height
    data.extend_from_slice(&1u64.to_le_bytes()); // size
    data.extend_from_slice(&(key.len() as u32).to_le_bytes());
    data.extend_from_slice(key);
    data.extend_from_slice(&(value.len() as u32).to_le_bytes());
    data.extend_from_slice(value);
    sha256(&data).map_err(|e| anyhow!("sha256: {e}"))
}

#[inline]
fn hash_inner_canonical(op: &InnerOp, left: &[u8; 32], right: &[u8; 32]) -> Result<[u8; 32]> {
    // Matches crates/commitment/src/tree/iavl/proof.rs::hash_inner
    let mut data = Vec::with_capacity(1 + 8 + 4 + 8 + 4 + op.split_key.len() + 32 + 32);
    data.push(0x01);
    data.extend_from_slice(&op.version.to_le_bytes());
    data.extend_from_slice(&op.height.to_le_bytes());
    data.extend_from_slice(&op.size.to_le_bytes());
    data.extend_from_slice(&(op.split_key.len() as u32).to_le_bytes());
    data.extend_from_slice(&op.split_key);
    data.extend_from_slice(left);
    data.extend_from_slice(right);
    sha256(&data).map_err(|e| anyhow!("sha256: {e}"))
}

fn compute_iavl_root_from_existence(p: &ExistenceProof) -> Result<[u8; 32]> {
    if p.key.as_slice().is_empty() {
        return Err(anyhow!("existence proof: empty key"));
    }
    let mut acc = hash_leaf_canonical(&p.leaf, &p.key, &p.value)?;
    for step in &p.path {
        let (left, right) = match step.side {
            Side::Left => (acc, step.sibling_hash),
            Side::Right => (step.sibling_hash, acc),
        };
        acc = hash_inner_canonical(step, &left, &right)?;
    }
    Ok(acc)
}

fn compute_iavl_root_from_nonexistence(p: &NonExistenceProof) -> Result<[u8; 32]> {
    // Non-membership proofs include at least one neighbor existence proof.
    match (&p.left, &p.right) {
        (Some(l), None) => compute_iavl_root_from_existence(l),
        (None, Some(r)) => compute_iavl_root_from_existence(r),
        (Some(l), Some(r)) => {
            let rl = compute_iavl_root_from_existence(l)?;
            let rr = compute_iavl_root_from_existence(r)?;
            if rl != rr {
                return Err(anyhow!("non-existence neighbors yield different roots"));
            }
            Ok(rl)
        }
        (None, None) => Err(anyhow!("non-existence proof has no neighbors")),
    }
}

/// Try SCALE/IAVL first; return the root if successful.
fn root_from_scale_iavl_bytes(proof_bytes: &[u8]) -> Option<Vec<u8>> {
    let p = decode_scale_iavl_proof(proof_bytes)?;
    let root = match p {
        IavlProof::Existence(ex) => compute_iavl_root_from_existence(&ex),
        IavlProof::NonExistence(nex) => compute_iavl_root_from_nonexistence(&nex),
    }
    .ok()?;
    Some(root.to_vec())
}

/// Small helper to try both standard and length-delimited protobuf decoding.
fn decode_pb<T: Message + Default>(bytes: &[u8]) -> Result<T, prost::DecodeError> {
    T::decode(bytes).or_else(|_| T::decode_length_delimited(bytes))
}

/// Brute-force scan for embedded proofs at non-zero offsets.
/// Looks for:
///   • SCALE-encoded IAVL proofs (Existence/NonExistence), possibly wrapped in Vec<u8> / Option<Vec<u8>>
///   • Protobuf ICS-23 (CommitmentProof, MerkleProof)
///   • Tendermint ProofOps / ProofOp (protobuf)
fn scan_for_embedded_ics23_or_tm(bytes: &[u8]) -> Option<Vec<u8>> {
    // Limit the scan for safety/perf; 4096 is plenty for our use cases
    let n = bytes.len().min(4096);
    for i in 0..n {
        let s = &bytes[i..n];

        // --- [0] Try IAVL directly at this offset (SCALE)
        if let Ok(p) = <IavlProof as parity_scale_codec::Decode>::decode(&mut &*s) {
            let root_res = match p {
                IavlProof::Existence(ex) => compute_iavl_root_from_existence(&ex),
                IavlProof::NonExistence(ne) => compute_iavl_root_from_nonexistence(&ne),
            };
            if let Ok(root) = root_res {
                return Some(root.to_vec());
            }
        }
        // --- [0b] Common wrappers: SCALE(Vec<u8>) / SCALE(Option<Vec<u8>>)
        if let Ok(inner) = <Vec<u8> as parity_scale_codec::Decode>::decode(&mut &*s) {
            // peel nested SCALE(Vec<u8>) and try IAVL again
            let inner = peel_all_scale_vec(inner);
            if let Ok(p) = <IavlProof as parity_scale_codec::Decode>::decode(&mut &*inner) {
                let root_res = match p {
                    IavlProof::Existence(ex) => compute_iavl_root_from_existence(&ex),
                    IavlProof::NonExistence(ne) => compute_iavl_root_from_nonexistence(&ne),
                };
                if let Ok(root) = root_res {
                    return Some(root.to_vec());
                }
            }
            // If not IAVL, try ICS‑23/TM on the peeled inner too.
            if let Some(root) =
                root_from_ics23_family_bytes(&inner).or_else(|| root_from_tm_proofops_bytes(&inner))
            {
                return Some(root);
            }
        }
        if let Ok(opt_inner) = <Option<Vec<u8>> as parity_scale_codec::Decode>::decode(&mut &*s) {
            if let Some(inner0) = opt_inner {
                let inner = peel_all_scale_vec(inner0);
                if let Ok(p) = <IavlProof as parity_scale_codec::Decode>::decode(&mut &*inner) {
                    let root_res = match p {
                        IavlProof::Existence(ex) => compute_iavl_root_from_existence(&ex),
                        IavlProof::NonExistence(ne) => compute_iavl_root_from_nonexistence(&ne),
                    };
                    if let Ok(root) = root_res {
                        return Some(root.to_vec());
                    }
                }
                if let Some(root) = root_from_ics23_family_bytes(&inner)
                    .or_else(|| root_from_tm_proofops_bytes(&inner))
                {
                    return Some(root);
                }
            }
        }

        // Try ICS‑23 CommitmentProof / MerkleProof
        if let Ok(cp) = decode_pb::<pb_ics23::CommitmentProof>(s) {
            if let Ok(root) = root_from_commitment_proof_pb(cp) {
                return Some(root);
            }
        }
        if let Ok(mp) = decode_pb::<PbMerkleProof>(s) {
            for cp in mp.proofs {
                if let Ok(root) = root_from_commitment_proof_pb(cp) {
                    return Some(root);
                }
            }
        }
        // Try Tendermint ProofOps / ProofOp
        if let Ok(ops) = decode_pb::<TmProofOps>(s) {
            for op in ops.ops {
                if let Some(root) = root_from_any_ics23_like_bytes(&op.data) {
                    return Some(root);
                }
            }
        }
        if let Ok(op) = decode_pb::<TmProofOp>(s) {
            if let Some(root) = root_from_any_ics23_like_bytes(&op.data) {
                return Some(root);
            }
        }
    }
    None
}

fn is_ascii_hex(bytes: &[u8]) -> bool {
    if bytes.len() % 2 != 0 {
        return false;
    }
    bytes.iter().all(|&b| {
        (b'0'..=b'9').contains(&b) || (b'a'..=b'f').contains(&b) || (b'A'..=b'F').contains(&b)
    })
}

// Detect if UTF‑8 text looks like base64 (std or URL‑safe), ignoring whitespace/newlines.
fn is_ascii_base64(s: &str) -> bool {
    let s = s.chars().filter(|c| !c.is_whitespace()).collect::<String>();
    if s.len() < 16 || s.len() % 4 != 0 {
        return false;
    }
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '-' | '_' | '='))
}

// Decode base64 string (try standard first, then URL‑safe normalization).
fn b64_decode_any(s: &str) -> Option<Vec<u8>> {
    let clean = s.chars().filter(|c| !c.is_whitespace()).collect::<String>();
    if let Ok(v) = BASE64.decode(&clean) {
        return Some(v);
    }
    // normalize URL-safe -> standard and retry
    let norm = clean.replace('-', "+").replace('_', "/");
    BASE64.decode(norm).ok()
}

/// Extract the root from an ICS‑23 CommitmentProof (including Batch and Compressed variants).
fn root_from_commitment_proof_pb(cp: pb_ics23::CommitmentProof) -> Result<Vec<u8>> {
    match cp.proof {
        // A single ExistenceProof
        Some(pb_ics23::commitment_proof::Proof::Exist(ex)) => {
            let ex_native: ics23::ExistenceProof = ex
                .try_into()
                .map_err(|_| anyhow!("convert ExistenceProof -> native ics23 failed"))?;
            let root = ics23::calculate_existence_root::<HostFunctionsManager>(&ex_native)
                .map_err(|e| anyhow!("calculate_existence_root (Existence): {e}"))?;
            Ok(root.to_vec())
        }
        // First Existence in the BatchProof
        Some(pb_ics23::commitment_proof::Proof::Batch(batch)) => {
            for entry in batch.entries {
                if let Some(pb_ics23::batch_entry::Proof::Exist(ex)) = entry.proof {
                    let ex_native: ics23::ExistenceProof = ex
                        .try_into()
                        .map_err(|_| anyhow!("convert Batch.Existence -> native ics23 failed"))?;
                    let root = ics23::calculate_existence_root::<HostFunctionsManager>(&ex_native)
                        .map_err(|e| anyhow!("calculate_existence_root (Batch): {e}"))?;
                    return Ok(root.to_vec());
                }
            }
            Err(anyhow!("no existence proof in BatchProof"))
        }
        // Compressed batch: rebuild the first ExistenceProof using lookup_inners
        Some(pb_ics23::commitment_proof::Proof::Compressed(compr)) => {
            let inners = compr.lookup_inners;
            for entry in compr.entries {
                if let Some(pb_ics23::compressed_batch_entry::Proof::Exist(ex)) = entry.proof {
                    let key = ex.key;
                    let value = ex.value;
                    let leaf = ex.leaf;
                    let mut path: Vec<pb_ics23::InnerOp> = Vec::with_capacity(ex.path.len());
                    for idx in ex.path {
                        let inner = inners.get(idx as usize).ok_or_else(|| {
                            anyhow!("compressed proof: path index {} out of range", idx)
                        })?;
                        path.push(inner.clone());
                    }
                    // Build a normal (uncompressed) pb ExistenceProof, then convert to native.
                    let ex_pb = pb_ics23::ExistenceProof {
                        key,
                        value,
                        leaf,
                        path,
                    };
                    let ex_native: ics23::ExistenceProof = ex_pb.try_into().map_err(|_| {
                        anyhow!("decompress: convert ExistenceProof -> native failed")
                    })?;
                    let root = ics23::calculate_existence_root::<HostFunctionsManager>(&ex_native)
                        .map_err(|e| anyhow!("calculate_existence_root (Compressed): {e}"))?;
                    return Ok(root.to_vec());
                }
            }
            Err(anyhow!("no existence proof in CompressedBatchProof"))
        }
        _ => Err(anyhow!(
            "unsupported ICS‑23 proof variant for root derivation"
        )),
    }
}

/// Peel consecutive `google.protobuf.Any` wrappers iteratively (bounded).
#[inline]
fn peel_any_iteratively(bytes: &[u8]) -> (Vec<u8>, usize) {
    let mut cur: Vec<u8> = bytes.to_vec();
    let mut depth: usize = 0;
    loop {
        if depth >= ANY_MAX_DEPTH {
            break;
        }
        match decode_pb::<PbAny>(&cur) {
            Ok(any) => {
                // Ensure strict forward progress (defense against degenerate loops).
                let val = any.value;
                if val.is_empty() || val.len() >= cur.len() {
                    break;
                }
                cur = val;
                depth += 1;
            }
            Err(_) => break,
        }
    }
    (cur, depth)
}

/// Decode ICS‑23 family messages (no `Any`, no ProofOps) and compute a root.
#[inline]
fn root_from_ics23_family_bytes(bytes: &[u8]) -> Option<Vec<u8>> {
    // IBC MerkleProof wrapping CommitmentProofs
    if let Ok(mp) = decode_pb::<PbMerkleProof>(bytes) {
        for cp in mp.proofs {
            if let Ok(root) = root_from_commitment_proof_pb(cp) {
                return Some(root);
            }
        }
    }
    // Bare ICS‑23 CommitmentProof
    if let Ok(cp) = decode_pb::<pb_ics23::CommitmentProof>(bytes) {
        if let Ok(root) = root_from_commitment_proof_pb(cp) {
            return Some(root);
        }
    }
    // Bare ICS‑23 ExistenceProof
    if let Ok(ex_pb) = decode_pb::<pb_ics23::ExistenceProof>(bytes) {
        let ex_native: ics23::ExistenceProof = ex_pb.into();
        if let Ok(root) = ics23::calculate_existence_root::<HostFunctionsManager>(&ex_native) {
            return Some(root.to_vec());
        }
    }
    None
}

/// Decode Tendermint ProofOps/ProofOp (protobuf) and compute a root.
/// This also peels `Any` inside each `op.data` iteratively.
#[inline]
fn root_from_tm_proofops_bytes(bytes: &[u8]) -> Option<Vec<u8>> {
    // ProofOps
    if let Ok(mut ops) = decode_pb::<TmProofOps>(bytes) {
        // Prefer ops whose type hints ICS‑23 to speed things up.
        ops.ops
            .sort_by_key(|op| !op.r#type.to_ascii_lowercase().starts_with("ics23"));
        for op in ops.ops {
            let (payload, _) = peel_any_iteratively(&op.data);
            if let Some(root) = root_from_ics23_family_bytes(&payload) {
                return Some(root);
            }
        }
        return None;
    }
    // Single ProofOp
    if let Ok(op) = decode_pb::<TmProofOp>(bytes) {
        let (payload, _) = peel_any_iteratively(&op.data);
        return root_from_ics23_family_bytes(&payload);
    }
    None
}

/// Compute a root from bytes that might be ICS‑23 (CommitmentProof, MerkleProof, ExistenceProof),
/// optionally wrapped in `google.protobuf.Any`, `ProofOps`/`ProofOp`, etc. **Fully iterative**.
fn root_from_any_ics23_like_bytes(bytes: &[u8]) -> Option<Vec<u8>> {
    // Peel Any wrappers iteratively (bounded), then try ProofOps and ICS‑23 family.
    let (peeled, _depth) = peel_any_iteratively(bytes);
    root_from_tm_proofops_bytes(&peeled).or_else(|| root_from_ics23_family_bytes(&peeled))
}

/// JSON fallback structures for Tendermint ProofOps as JSON.
#[derive(Deserialize)]
struct JsonOp {
    #[serde(rename = "type")]
    t: String,
    data: String, // base64
}
#[derive(Deserialize)]
struct JsonOpsOnly {
    ops: Vec<JsonOp>,
}
#[derive(Deserialize)]
struct JsonProofWrapper {
    proof: JsonOpsOnly,
}

fn root_from_json_proofops_bytes(bytes: &[u8]) -> Option<Vec<u8>> {
    let s = str::from_utf8(bytes).ok()?;

    // Try top-level {"ops":[...]}
    if let Ok(j) = serde_json::from_str::<JsonOpsOnly>(s) {
        let mut ops = j.ops;
        ops.sort_by_key(|op| !op.t.to_ascii_lowercase().starts_with("ics23"));
        for op in ops {
            if let Some(inner) = b64_decode_any(&op.data) {
                let (payload, _) = peel_any_iteratively(&inner);
                if let Some(root) = root_from_tm_proofops_bytes(&payload)
                    .or_else(|| root_from_ics23_family_bytes(&payload))
                {
                    return Some(root);
                }
            }
        }
        return None;
    }

    // Try {"proof":{"ops":[...]}}
    if let Ok(j) = serde_json::from_str::<JsonProofWrapper>(s) {
        let mut ops = j.proof.ops;
        ops.sort_by_key(|op| !op.t.to_ascii_lowercase().starts_with("ics23"));
        for op in ops {
            if let Some(inner) = b64_decode_any(&op.data) {
                let (payload, _) = peel_any_iteratively(&inner);
                if let Some(root) = root_from_tm_proofops_bytes(&payload)
                    .or_else(|| root_from_ics23_family_bytes(&payload))
                {
                    return Some(root);
                }
            }
        }
        return None;
    }

    None
}

// NEW: Handle JSON Any or generic JSON blobs that contain base64 payloads.
fn root_from_json_any_like_bytes(bytes: &[u8]) -> Option<Vec<u8>> {
    let s = str::from_utf8(bytes).ok()?;
    let v: JsonValue = serde_json::from_str(s).ok()?;

    // Common Any shapes: {"@type": "...", "value": "<b64>"} or {"type_url":"...","value":"<b64>"}
    if let Some(obj) = v.as_object() {
        if let Some(val_s) = obj.get("value").and_then(|x| x.as_str()) {
            if is_ascii_base64(val_s) {
                if let Some(raw) = b64_decode_any(val_s) {
                    let (payload, _) = peel_any_iteratively(&raw);
                    if let Some(root) = root_from_tm_proofops_bytes(&payload)
                        .or_else(|| root_from_ics23_family_bytes(&payload))
                    {
                        return Some(root);
                    }
                    if let Ok(ops) = decode_pb::<TmProofOps>(&payload) {
                        let mut candidates = ops.ops.clone();
                        candidates
                            .sort_by_key(|op| !op.r#type.to_ascii_lowercase().starts_with("ics23"));
                        for op in candidates {
                            let (inner, _) = peel_any_iteratively(&op.data);
                            if let Some(root) = root_from_ics23_family_bytes(&inner) {
                                return Some(root);
                            }
                        }
                    }
                }
            } else if let Ok(raw) = hex::decode(val_s) {
                let (payload, _) = peel_any_iteratively(&raw);
                if let Some(root) = root_from_tm_proofops_bytes(&payload)
                    .or_else(|| root_from_ics23_family_bytes(&payload))
                {
                    return Some(root);
                }
            }
        }

        // If there is a nested "proof" with "ops", reuse the ProofOps JSON handler
        if obj.contains_key("proof") && s.contains("\"ops\"") {
            if let Some(root) = root_from_json_proofops_bytes(bytes) {
                return Some(root);
            }
        }
    }

    // Generic scan: walk all strings; try base64‑looking ones as candidate payloads.
    fn collect_strings<'a>(v: &'a JsonValue, out: &mut Vec<&'a str>) {
        match v {
            JsonValue::String(s) => out.push(s),
            JsonValue::Array(a) => a.iter().for_each(|x| collect_strings(x, out)),
            JsonValue::Object(m) => m.values().for_each(|x| collect_strings(x, out)),
            _ => {}
        }
    }

    let mut all_strings = Vec::new();
    collect_strings(&v, &mut all_strings);
    for s in all_strings {
        if !is_ascii_base64(s) {
            continue;
        }
        if let Some(raw) = b64_decode_any(s) {
            let (payload, _) = peel_any_iteratively(&raw);
            if let Some(root) = root_from_tm_proofops_bytes(&payload)
                .or_else(|| root_from_ics23_family_bytes(&payload))
            {
                return Some(root);
            }
            if let Ok(ops) = decode_pb::<TmProofOps>(&payload) {
                let mut candidates = ops.ops.clone();
                candidates.sort_by_key(|op| !op.r#type.to_ascii_lowercase().starts_with("ics23"));
                for op in candidates {
                    let (inner, _) = peel_any_iteratively(&op.data);
                    if let Some(root) = root_from_ics23_family_bytes(&inner) {
                        return Some(root);
                    }
                }
            }
        }
    }

    None
}

#[inline]
fn peel_all_scale_vec(mut bytes: Vec<u8>) -> Vec<u8> {
    // Put a hard cap and enforce strict shrink to prevent degenerate loops.
    for _ in 0..32 {
        if let Ok(inner) = scodec::from_bytes_canonical::<Vec<u8>>(&bytes) {
            if inner.len() >= bytes.len() {
                break;
            }
            bytes = inner;
        } else {
            break;
        }
    }
    bytes
}

/// Compute the commitment root from proof bytes.
/// Accepts IBC MerkleProof, bare ICS‑23 proofs, Tendermint ProofOps (protobuf),
/// optional ASCII‑hex wrapper, nested/URL‑safe base64, JSON ProofOps, and JSON Any.
pub fn existence_root_from_proof_bytes(proof_pb: &[u8]) -> Result<Vec<u8>> {
    tracing::debug!(
        target: "relayer",
        "existence_root: input_len={}, head={}",
        proof_pb.len(),
        hex_prefix(proof_pb, 24)
    );

    // A helper closure that attempts all non-recursive, non-peeling decoders.
    let try_decoders = |bytes: &[u8]| {
        root_from_scale_selector_then_opt_path_then_iavl(bytes)
            .or_else(|| root_from_scale_path_then_iavl(bytes))
            .or_else(|| root_from_scale_iavl_bytes(bytes))
            .or_else(|| root_from_any_ics23_like_bytes(bytes))
            .or_else(|| root_from_json_proofops_bytes(bytes))
            .or_else(|| root_from_json_any_like_bytes(bytes))
    };

    // ---- First attempt: peel outer SCALE(Vec<u8>) layers, then decode.
    // 1. First, peel any SCALE(Vec<u8>) wrappers from the initial input.
    let peeled_initial = peel_all_scale_vec(proof_pb.to_vec());
    if let Some(root) = try_decoders(&peeled_initial) {
        tracing::debug!(
            target: "relayer",
            "existence_root: matched after initial peel"
        );
        return Ok(root);
    }

    // 2. If that fails, try to interpret the input as text (hex, base64, json).
    if let Ok(s) = std::str::from_utf8(proof_pb) {
        let raw_from_text =
            if let Some(stripped) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                hex::decode(stripped).ok()
            } else if is_ascii_hex(s.as_bytes()) {
                hex::decode(s).ok()
            } else if is_ascii_base64(s) {
                b64_decode_any(s)
            } else {
                None
            };

        if let Some(raw) = raw_from_text {
            // After decoding the text wrapper, peel any *inner* SCALE wrappers.
            let peeled_inner = peel_all_scale_vec(raw);
            if let Some(root) = try_decoders(&peeled_inner) {
                tracing::debug!(
                    target: "relayer",
                    "existence_root: matched after peeling text wrapper"
                );
                return Ok(root);
            }
        }

        // Handle JSON separately since it's already text
        if let Some(root) = root_from_json_proofops_bytes(s.as_bytes())
            .or_else(|| root_from_json_any_like_bytes(s.as_bytes()))
        {
            tracing::debug!(
                target: "relayer",
                "existence_root: matched as direct JSON"
            );
            return Ok(root);
        }
    }

    // 3. As a last resort, scan for embedded proofs at arbitrary offsets.
    if let Some(root) = scan_for_embedded_ics23_or_tm(proof_pb) {
        tracing::debug!(
            target: "relayer",
            "existence_root: matched embedded ICS‑23/TM proof"
        );
        return Ok(root);
    }

    // ---- If all attempts fail, return an error.
    let mut tail = String::new();
    if proof_pb.len() > 24 {
        tail = hex_prefix(&proof_pb[proof_pb.len().saturating_sub(16)..], 16);
    }
    tracing::error!(
        "RELAYER decode FAIL: len={}, head={}, tail={}",
        proof_pb.len(),
        hex_prefix(proof_pb, 24),
        tail
    );
    Err(anyhow!(
        "unrecognized proof bytes (len={}, head={}, tail={}): \
         not SCALE(IavlProof or Vec<u8>→IavlProof), nor MerkleProof, CommitmentProof, \
         ExistenceProof, Tendermint ProofOps, hex‑wrapped, nested base64, JSON ProofOps, or JSON Any",
        proof_pb.len(),
        hex_prefix(proof_pb, 24),
        tail
    ))
}

// =======================
// Append below this line:
// =======================

/// Decode a `u64` that might be stored in various formats:
///   • raw 8‑byte big‑endian (Cosmos/ICS‑24 canonical)
///   • raw 8‑byte little‑endian (rare; we don’t prefer this)
///   • SCALE Compact<u64> or SCALE<u64>
///   • SCALE(Vec<u8>) wrapping one of the above
///   • ASCII decimal or ASCII hex ("0x…")
/// If multiple apply, we prefer big‑endian first, then SCALE compact, then others.
fn parse_store_u64(bytes: &[u8]) -> Result<u64> {
    // Some gateways return an empty buffer for "missing" keys.
    if bytes.is_empty() {
        return Ok(0);
    }
    // Fast path: canonical 8‑byte big‑endian
    if bytes.len() == 8 {
        let mut be = [0u8; 8];
        be.copy_from_slice(bytes);
        return Ok(u64::from_be_bytes(be));
    }
    // Try SCALE Compact<u64> and SCALE<u64>
    {
        let mut t = bytes;
        if let Ok(parity_scale_codec::Compact(n)) =
            <parity_scale_codec::Compact<u64> as parity_scale_codec::Decode>::decode(&mut t)
        {
            return Ok(n);
        }
        let mut t = bytes;
        if let Ok(n) = <u64 as parity_scale_codec::Decode>::decode(&mut t) {
            return Ok(n);
        }
    }
    // Try canonical SCALE Vec<u8> wrapper(s)
    if let Ok(inner) = scodec::from_bytes_canonical::<Vec<u8>>(bytes) {
        return parse_store_u64(&inner);
    }
    // Try ASCII (decimal or hex)
    if let Ok(s) = std::str::from_utf8(bytes) {
        let s = s.trim();
        if s.starts_with("0x") || s.starts_with("0X") {
            if let Ok(v) = hex::decode(&s[2..]) {
                return parse_store_u64(&v);
            }
        }
        if !s.is_empty() && s.chars().all(|c| c.is_ascii_digit()) {
            return s
                .parse::<u64>()
                .map_err(|e| anyhow!("bad decimal u64: {e}"));
        }
    }
    // Last resort: short raw buffers (<= 8) → big‑endian zero‑padded
    if !bytes.is_empty() && bytes.len() < 8 {
        let mut be = [0u8; 8];
        be[8 - bytes.len()..].copy_from_slice(bytes);
        return Ok(u64::from_be_bytes(be));
    }
    Err(anyhow!(
        "unrecognized u64 store format (len={}, head={})",
        bytes.len(),
        hex_prefix(bytes, 16)
    ))
}

/// Query raw proof bytes for an ICS‑24 path at a given height from the gateway.
pub async fn query_proof_bytes_at(gw: &Gateway, path: &str, height: u64) -> Result<Vec<u8>> {
    const RETRIES: usize = 10;
    const BASE_BACKOFF_MS: u64 = 50;
    fn backoff(attempt: usize) -> Duration {
        Duration::from_millis((BASE_BACKOFF_MS.saturating_mul(1u64 << attempt)).min(800))
    }
    fn looks_like_ascii_error(b: &[u8]) -> bool {
        if b.is_empty() || b.len() > 256 {
            return false;
        }
        let ascii = b
            .iter()
            .all(|&c| c == b'\n' || c == b'\r' || c == b'\t' || (c >= 0x20 && c < 0x7f));
        if !ascii {
            return false;
        }
        let s = String::from_utf8_lossy(b).to_ascii_lowercase();
        s.contains("too many requests")
            || s.contains("rate limit")
            || s.contains("429")
            || s.starts_with("<!doctype html")
            || s.contains("error")
    }

    for attempt in 0..=RETRIES {
        match gw.query_at_height(path, height).await {
            Ok((_v, proof_opt, _h)) => {
                if let Some(proof_bytes) = proof_opt {
                    if looks_like_ascii_error(&proof_bytes) {
                        if attempt < RETRIES {
                            tracing::debug!(
                                target = "relayer",
                                "proof fetch got ASCII error for '{}' @{} (attempt {}), retrying",
                                path,
                                height,
                                attempt
                            );
                            sleep(backoff(attempt)).await;
                            continue;
                        } else {
                            let s = String::from_utf8_lossy(&proof_bytes);
                            return Err(anyhow!(
                                "gateway returned error text for '{}': {}",
                                path,
                                s
                            ));
                        }
                    }
                    // Lightweight classification (log once, on success path).
                    let shape = if decode_pb::<TmProofOps>(&proof_bytes).is_ok() {
                        "Tendermint ProofOps (protobuf)"
                    } else if decode_pb::<pb_ics23::CommitmentProof>(&proof_bytes).is_ok() {
                        "ICS‑23 CommitmentProof (protobuf)"
                    } else if scodec::from_bytes_canonical::<Vec<u8>>(&proof_bytes).is_ok() {
                        "SCALE(Vec<u8>) (inner opaque)"
                    } else {
                        "unknown"
                    };
                    eprintln!(
                        "RELAYER probe: path='{}' @{} → len={}, head={}, shape≈{}",
                        path,
                        height,
                        proof_bytes.len(),
                        hex_prefix(&proof_bytes, 24),
                        shape
                    );
                    return Ok(proof_bytes);
                } else {
                    if attempt < RETRIES {
                        tracing::debug!(
                            target = "relayer",
                            "no proof bytes for '{}' @{} (attempt {}), retrying",
                            path,
                            height,
                            attempt
                        );
                        sleep(backoff(attempt)).await;
                        continue;
                    } else {
                        return Err(anyhow!("no proof bytes for path '{}' @{}", path, height));
                    }
                }
            }
            Err(e) => {
                if attempt < RETRIES {
                    tracing::debug!(
                        target = "relayer",
                        "query_at_height error for '{}' @{} (attempt {}): {} — retrying",
                        path,
                        height,
                        attempt,
                        e
                    );
                    sleep(backoff(attempt)).await;
                    continue;
                } else {
                    return Err(anyhow!(
                        "query_at_height failed for '{}' @{}: {}",
                        path,
                        height,
                        e
                    ));
                }
            }
        }
    }
    unreachable!()
}

/// Compute allocated `connection-{n}` after an Init/Try committed.
pub async fn infer_allocated_connection_id(gw: &Gateway) -> Result<(String, u64)> {
    const RETRIES: usize = 20;
    const SLEEP_MS: u64 = 50;
    const SCAN_CAP: u64 = 128;

    // Helper: try to read "nextConnectionSequence" across canonical and alt keys.
    async fn read_next_seq_any(gw: &Gateway) -> Result<(u64, u64, &'static str)> {
        let primary = NextConnectionSequencePath.to_string();
        let (raw, _pr, h) = gw.query_latest(&primary).await?;
        let n = parse_store_u64(&raw)?;
        if n > 0 {
            return Ok((n, h, "canonical"));
        }
        for (alt, tag) in [
            ("connections/nextSequence", "alt1"),
            ("ibc/nextConnectionSequence", "alt2"),
            ("ibc/connections/nextSequence", "alt3"),
        ] {
            let (r, _p, hh) = gw.query_latest(alt).await?;
            let m = parse_store_u64(&r)?;
            if m > 0 {
                return Ok((m, hh, tag));
            }
        }
        Ok((0, h, "none"))
    }

    // Helper: does "connections/connection-{i}" exist at this height?
    async fn connection_exists_at(gw: &Gateway, i: u64, h: u64) -> Result<bool> {
        for path in [
            format!("connections/connection-{i}"),
            format!("ibc/connections/connection-{i}"),
        ] {
            let (val, proof, _hh) = match gw.query_at_height(&path, h).await {
                Ok(ok) => ok,
                Err(e) => {
                    tracing::debug!(
                        target = "relayer",
                        "scan: '{}' @{} → query error ({}) — treating as not found",
                        path,
                        h,
                        e
                    );
                    continue;
                }
            };
            let exist = if !val.is_empty() {
                true
            } else if let Some(pb) = &proof {
                // Prefer precise classification; fall back to "non-empty proof bytes" as existence.
                proof_indicates_membership(pb).unwrap_or(!pb.is_empty())
            } else {
                false
            };
            if exist {
                return Ok(true);
            }
        }
        Ok(false)
    }

    for attempt in 0..RETRIES {
        let (n, h, tag) = read_next_seq_any(gw).await?;
        tracing::debug!(target: "relayer", "conn/nextSequence attempt={} tag={} → n={} @{}", attempt, tag, n, h);

        if n > 0 {
            let allocated = n
                .checked_sub(1)
                .ok_or_else(|| anyhow!("nextConnectionSequence=0 unexpected"))?;
            // Ensure the allocated key actually exists at this (latest) height.
            if connection_exists_at(gw, allocated, h).await? {
                return Ok((format!("connection-{}", allocated), h));
            }
            tracing::debug!(target: "relayer", "allocated conn-{} not visible at @{} yet; retrying", allocated, h);
        } else {
            // If the counter isn't visible, try to infer via a scan (first missing index) at the latest height.
            let mut i: u64 = 0;
            while i < SCAN_CAP {
                if connection_exists_at(gw, i, h).await? {
                    i += 1;
                } else {
                    break;
                }
            }
            if i > 0 {
                let allocated = i - 1;
                tracing::debug!(target: "relayer", "scan inferred last allocated conn index={} @{}", allocated, h);
                return Ok((format!("connection-{}", allocated), h));
            }
            tracing::debug!(target: "relayer", "no connections found by scan @{}; retrying", h);
        }

        if attempt + 1 < RETRIES {
            sleep(Duration::from_millis(SLEEP_MS)).await;
            continue;
        }
    }

    Err(anyhow!(
        "connection allocation not observable yet after {} retries; chain may be lagging",
        RETRIES
    ))
}

/// Compute allocated `channel-{n}` after ChannelOpen{Init,Try} commits.
pub async fn infer_allocated_channel_id(gw: &Gateway) -> Result<(String, u64)> {
    const RETRIES: usize = 20;
    const SLEEP_MS: u64 = 50;
    const SCAN_CAP: u64 = 128;

    async fn read_next_seq_any(gw: &Gateway) -> Result<(u64, u64, &'static str)> {
        let primary = NextChannelSequencePath.to_string();
        let (raw, _pr, h) = gw.query_latest(&primary).await?;
        let n = parse_store_u64(&raw)?;
        if n > 0 {
            return Ok((n, h, "canonical"));
        }
        for (alt, tag) in [
            ("channels/nextSequence", "alt1"),
            ("ibc/nextChannelSequence", "alt2"),
            ("ibc/channels/nextSequence", "alt3"),
        ] {
            let (r, _p, hh) = gw.query_latest(alt).await?;
            let m = parse_store_u64(&r)?;
            if m > 0 {
                return Ok((m, hh, tag));
            }
        }
        Ok((0, h, "none"))
    }

    async fn channel_exists_at(gw: &Gateway, port: &str, id: u64, h: u64) -> Result<bool> {
        for path in [
            format!("channels/channel-{}", id),             // some hosts
            format!("ibc/channels/channel-{}", id),         // ibc/ prefixed
            format!("channelEnds/{}/channel-{}", port, id), // rare variants
        ] {
            let (val, proof, _hh) = match gw.query_at_height(&path, h).await {
                Ok(ok) => ok,
                Err(e) => {
                    tracing::debug!(
                        target = "relayer",
                        "scan: '{}' @{} → query error ({}) — treating as not found",
                        path,
                        h,
                        e
                    );
                    continue;
                }
            };
            let exist = if !val.is_empty() {
                true
            } else if let Some(pb) = &proof {
                proof_indicates_membership(pb).unwrap_or(!pb.is_empty())
            } else {
                false
            };
            if exist {
                return Ok(true);
            }
        }
        Ok(false)
    }

    // We don’t know the port id here; scanning can still infer by presence across common paths.
    for attempt in 0..RETRIES {
        let (n, h, tag) = read_next_seq_any(gw).await?;
        tracing::debug!(target: "relayer", "chan/nextSequence attempt={} tag={} → n={} @{}", attempt, tag, n, h);
        if n > 0 {
            let allocated = n
                .checked_sub(1)
                .ok_or_else(|| anyhow!("nextChannelSequence=0 unexpected"))?;
            // Best-effort presence check without knowing the exact port id.
            if channel_exists_at(gw, "transfer", allocated, h)
                .await
                .unwrap_or(false)
            {
                return Ok((format!("channel-{}", allocated), h));
            }
        } else {
            // crude scan over ids to see if anything exists @ latest h
            let mut i: u64 = 0;
            while i < SCAN_CAP {
                if channel_exists_at(gw, "transfer", i, h)
                    .await
                    .unwrap_or(false)
                {
                    i += 1;
                } else {
                    break;
                }
            }
            if i > 0 {
                return Ok((format!("channel-{}", i - 1), h));
            }
        }
        if attempt + 1 < RETRIES {
            sleep(Duration::from_millis(SLEEP_MS)).await;
            continue;
        }
    }
    Err(anyhow!(
        "channel allocation not observable yet after {} retries",
        RETRIES
    ))
}

// ---------------------------
// IBC message builders (pub)
// ---------------------------

pub fn build_create_client_any(
    client_state_any: PbAny,
    consensus_state_any: PbAny,
    signer: &str,
) -> Result<PbAny> {
    let msg = pbclient::MsgCreateClient {
        client_state: Some(client_state_any),
        consensus_state: Some(consensus_state_any),
        signer: signer.to_string(),
    };
    Ok(PbAny {
        type_url: "/ibc.core.client.v1.MsgCreateClient".into(),
        value: msg.encode_to_vec(),
    })
}

pub fn build_update_client_any(
    client_id: &str,
    client_message_any: PbAny,
    signer: &str,
) -> Result<PbAny> {
    let msg = pbclient::MsgUpdateClient {
        client_id: client_id.to_string(),
        client_message: Some(client_message_any),
        signer: signer.to_string(),
    };
    Ok(PbAny {
        type_url: "/ibc.core.client.v1.MsgUpdateClient".into(),
        value: msg.encode_to_vec(),
    })
}

pub fn build_conn_open_init_any(
    client_id_a: &str,
    counterparty_client_b: &str,
    signer: &str,
) -> Result<PbAny> {
    let cp = pbconn::Counterparty {
        client_id: counterparty_client_b.to_string(),
        connection_id: "".to_string(),
        prefix: Some(MerklePrefix {
            key_prefix: IBC_PREFIX.to_vec(),
        }),
    };
    let version = Some(pbconn::Version {
        identifier: "1".into(),
        features: vec!["ORDER_ORDERED".into(), "ORDER_UNORDERED".into()],
    });
    let msg = pbconn::MsgConnectionOpenInit {
        client_id: client_id_a.to_string(),
        counterparty: Some(cp),
        version,
        delay_period: 0,
        signer: signer.to_string(),
    };
    Ok(PbAny {
        type_url: "/ibc.core.connection.v1.MsgConnectionOpenInit".into(),
        value: msg.encode_to_vec(),
    })
}

pub async fn build_conn_open_try_any(
    gw_a: &Gateway,
    client_id_b: &str,
    client_a_on_b: &str,
    conn_id_a: &str,
    counterparty_client_a: &str,
    proof_height_on_a: u64,
    signer_b: &str,
) -> Result<PbAny> {
    // ConnectionEnd on A (proof of Init)
    let conn_path_a = ConnectionPath::new(&conn_id_a.parse()?).to_string();
    let proof_init = query_proof_bytes_at(gw_a, &conn_path_a, proof_height_on_a).await?;

    // ClientState(A) on A + proof
    let cs_path_on_a = ClientStatePath::new(counterparty_client_a.parse()?).to_string();
    let (client_state_any_bytes, _proof_cs, _h_cs) = gw_a
        .query_at_height(&cs_path_on_a, proof_height_on_a)
        .await?;
    // Disambiguate (prost vs SCALE)
    let client_state_any = <ibc_proto::google::protobuf::Any as prost::Message>::decode(
        client_state_any_bytes.as_slice(),
    )?;
    let proof_client = query_proof_bytes_at(gw_a, &cs_path_on_a, proof_height_on_a).await?;

    // ConsensusState(A@h=1) on A + proof  (your tests use 0/1 height)
    let consensus_height = PbHeight {
        revision_number: 0,
        revision_height: 1,
    };
    let ccs_path = ClientConsensusStatePath::new(counterparty_client_a.parse()?, 0, 1).to_string();
    let proof_consensus = query_proof_bytes_at(gw_a, &ccs_path, proof_height_on_a).await?;

    let cp = pbconn::Counterparty {
        client_id: client_a_on_b.to_string(),
        connection_id: conn_id_a.to_string(),
        prefix: Some(MerklePrefix {
            key_prefix: IBC_PREFIX.to_vec(),
        }),
    };
    let versions = vec![pbconn::Version {
        identifier: "1".into(),
        features: vec!["ORDER_ORDERED".into(), "ORDER_UNORDERED".into()],
    }];

    #[allow(deprecated)]
    let msg = pbconn::MsgConnectionOpenTry {
        client_id: client_id_b.to_string(),
        client_state: Some(client_state_any),
        counterparty: Some(cp),
        delay_period: 0,
        previous_connection_id: String::new(),
        counterparty_versions: versions,
        proof_height: Some(PbHeight {
            revision_number: 0,
            revision_height: proof_height_on_a,
        }),
        consensus_height: Some(consensus_height),
        proof_init,
        proof_client,
        proof_consensus,
        host_consensus_state_proof: vec![],
        signer: signer_b.to_string(),
    };

    Ok(PbAny {
        type_url: "/ibc.core.connection.v1.MsgConnectionOpenTry".into(),
        value: msg.encode_to_vec(),
    })
}

pub async fn build_conn_open_ack_any(
    gw_b: &Gateway,
    conn_id_a: &str,
    conn_id_b: &str,
    client_a_on_b: &str,
    proof_height_on_b: u64,
    signer_a: &str,
) -> Result<PbAny> {
    // ConnectionEnd on B (proof of TryOpen)
    let conn_path_b = ConnectionPath::new(&conn_id_b.parse()?).to_string();
    let proof_try = query_proof_bytes_at(gw_b, &conn_path_b, proof_height_on_b).await?;

    // ClientState(A) as stored on B + proof
    let cs_path_b = ClientStatePath::new(client_a_on_b.parse()?).to_string();
    let proof_client = query_proof_bytes_at(gw_b, &cs_path_b, proof_height_on_b).await?;
    let (client_state_any_bytes, _proof_cs, _h_cs) =
        gw_b.query_at_height(&cs_path_b, proof_height_on_b).await?;
    let client_state_any = <ibc_proto::google::protobuf::Any as prost::Message>::decode(
        client_state_any_bytes.as_slice(),
    )?;

    // ConsensusState(A@1) on B + proof
    let consensus_height = PbHeight {
        revision_number: 0,
        revision_height: 1,
    };
    let ccs_path = ClientConsensusStatePath::new(client_a_on_b.parse()?, 0, 1).to_string();
    let proof_consensus = query_proof_bytes_at(gw_b, &ccs_path, proof_height_on_b).await?;

    let version = Some(pbconn::Version {
        identifier: "1".into(),
        features: vec!["ORDER_ORDERED".into(), "ORDER_UNORDERED".into()],
    });

    let msg = pbconn::MsgConnectionOpenAck {
        connection_id: conn_id_a.to_string(),
        counterparty_connection_id: conn_id_b.to_string(),
        version,
        client_state: Some(client_state_any),
        proof_height: Some(PbHeight {
            revision_number: 0,
            revision_height: proof_height_on_b,
        }),
        consensus_height: Some(consensus_height),
        proof_try,
        proof_client,
        proof_consensus,
        host_consensus_state_proof: vec![],
        signer: signer_a.to_string(),
    };

    Ok(PbAny {
        type_url: "/ibc.core.connection.v1.MsgConnectionOpenAck".into(),
        value: msg.encode_to_vec(),
    })
}

pub async fn build_conn_open_confirm_any(
    gw_a: &Gateway,
    conn_id_b: &str,
    conn_id_a: &str,
    proof_height_on_a: u64,
    signer_b: &str,
) -> Result<PbAny> {
    let conn_path_a = ConnectionPath::new(&conn_id_a.parse()?).to_string();
    let proof_ack = query_proof_bytes_at(gw_a, &conn_path_a, proof_height_on_a).await?;

    let msg = pbconn::MsgConnectionOpenConfirm {
        connection_id: conn_id_b.to_string(),
        proof_ack,
        proof_height: Some(PbHeight {
            revision_number: 0,
            revision_height: proof_height_on_a,
        }),
        signer: signer_b.to_string(),
    };

    Ok(PbAny {
        type_url: "/ibc.core.connection.v1.MsgConnectionOpenConfirm".into(),
        value: msg.encode_to_vec(),
    })
}

pub fn build_chan_open_init_any(
    port_id_a: &str,
    connection_id_a: &str,
    counterparty_port_b: &str,
    version: &str,
    ordering: i32,
    signer_a: &str,
) -> Result<PbAny> {
    let channel = pbchan::Channel {
        state: pbchan::State::Init as i32,
        ordering,
        counterparty: Some(pbchan::Counterparty {
            port_id: counterparty_port_b.to_string(),
            channel_id: "".to_string(),
        }),
        connection_hops: vec![connection_id_a.to_string()],
        version: version.to_string(),
        upgrade_sequence: 0,
    };
    let msg = pbchan::MsgChannelOpenInit {
        port_id: port_id_a.to_string(),
        channel: Some(channel),
        signer: signer_a.to_string(),
    };
    Ok(PbAny {
        type_url: "/ibc.core.channel.v1.MsgChannelOpenInit".into(),
        value: msg.encode_to_vec(),
    })
}

pub async fn build_chan_open_try_any(
    gw_a: &Gateway,
    port_id_b: &str,
    connection_id_b: &str,
    counterparty_port_a: &str,
    channel_id_a: &str,
    version: &str,
    ordering: i32,
    proof_height_on_a: u64,
    signer_b: &str,
) -> Result<PbAny> {
    let cp = pbchan::Counterparty {
        port_id: counterparty_port_a.to_string(),
        channel_id: channel_id_a.to_string(),
    };
    let channel = pbchan::Channel {
        state: pbchan::State::Tryopen as i32,
        ordering,
        counterparty: Some(cp),
        connection_hops: vec![connection_id_b.to_string()],
        version: version.to_string(),
        upgrade_sequence: 0,
    };

    // ChannelEnd on A (INIT) proof
    let ch_path_a =
        ChannelEndPath::new(&counterparty_port_a.parse()?, &channel_id_a.parse()?).to_string();
    let proof_init = query_proof_bytes_at(gw_a, &ch_path_a, proof_height_on_a).await?;

    #[allow(deprecated)]
    let msg = pbchan::MsgChannelOpenTry {
        port_id: port_id_b.to_string(),
        channel: Some(channel),
        counterparty_version: version.to_string(),
        previous_channel_id: String::new(),
        proof_init,
        proof_height: Some(PbHeight {
            revision_number: 0,
            revision_height: proof_height_on_a,
        }),
        signer: signer_b.to_string(),
    };

    Ok(PbAny {
        type_url: "/ibc.core.channel.v1.MsgChannelOpenTry".into(),
        value: msg.encode_to_vec(),
    })
}

pub async fn build_chan_open_ack_any(
    gw_b: &Gateway,
    port_id_a: &str,
    channel_id_a: &str,
    counterparty_port_b: &str,
    channel_id_b: &str,
    version: &str,
    proof_height_on_b: u64,
    signer_a: &str,
) -> Result<PbAny> {
    let ch_path_b =
        ChannelEndPath::new(&counterparty_port_b.parse()?, &channel_id_b.parse()?).to_string();
    let proof_try = query_proof_bytes_at(gw_b, &ch_path_b, proof_height_on_b).await?;

    let msg = pbchan::MsgChannelOpenAck {
        port_id: port_id_a.to_string(),
        channel_id: channel_id_a.to_string(),
        counterparty_channel_id: channel_id_b.to_string(),
        counterparty_version: version.to_string(),
        proof_height: Some(PbHeight {
            revision_number: 0,
            revision_height: proof_height_on_b,
        }),
        proof_try,
        signer: signer_a.to_string(),
    };

    Ok(PbAny {
        type_url: "/ibc.core.channel.v1.MsgChannelOpenAck".into(),
        value: msg.encode_to_vec(),
    })
}

pub async fn build_chan_open_confirm_any(
    gw_a: &Gateway,
    port_id_b: &str,
    channel_id_b: &str,
    counterparty_port_a: &str,
    channel_id_a: &str,
    proof_height_on_a: u64,
    signer_b: &str,
) -> Result<PbAny> {
    let ch_path_a =
        ChannelEndPath::new(&counterparty_port_a.parse()?, &channel_id_a.parse()?).to_string();
    let proof_ack = query_proof_bytes_at(gw_a, &ch_path_a, proof_height_on_a).await?;

    let msg = pbchan::MsgChannelOpenConfirm {
        port_id: port_id_b.to_string(),
        channel_id: channel_id_b.to_string(),
        proof_height: Some(PbHeight {
            revision_number: 0,
            revision_height: proof_height_on_a,
        }),
        proof_ack,
        signer: signer_b.to_string(),
    };

    Ok(PbAny {
        type_url: "/ibc.core.channel.v1.MsgChannelOpenConfirm".into(),
        value: msg.encode_to_vec(),
    })
}
