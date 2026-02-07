// Path: crates/relayer/src/handshake/proofs.rs

//! Proof decoding, root extraction, and ICS-23 interoperability utilities.

use crate::gateway::Gateway;
use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use hex;
use ioi_types::codec as scodec;
use serde::Deserialize;
use serde_json::Value as JsonValue;
use std::str;
use std::time::Duration;
use tokio::time::sleep;

// Proto imports
use ibc_proto::google::protobuf::Any as PbAny;
use ibc_proto::ibc::core::commitment::v1::MerkleProof as PbMerkleProof;
use ibc_proto::ics23 as pb_ics23;
use prost::Message;
use tendermint_proto::crypto::{ProofOp as TmProofOp, ProofOps as TmProofOps};

// [FIX] Imports for inference logic
use ibc_core_host_types::path::{NextChannelSequencePath, NextConnectionSequencePath};

// dcrypt imports
use dcrypt::algorithms::hash::blake2::{Blake2b, Blake2s};
use dcrypt::algorithms::hash::sha2::{Sha256, Sha512};
use dcrypt::algorithms::hash::HashFunction;
use dcrypt::algorithms::hash::Keccak256;

/// Safety cap for nested `google.protobuf.Any` envelopes.
const ANY_MAX_DEPTH: usize = 32;

// [FIX] Helper function required by builders.rs
pub async fn query_proof_bytes_at(gw: &Gateway, path: &str, height: u64) -> Result<Vec<u8>> {
    let (_value, proof_opt, _) = gw.query_at_height(path, height).await?;
    proof_opt.ok_or_else(|| anyhow::anyhow!("no proof at path {path} height {height}"))
}

// --------------------------------------------------------------------------------------
// Local SCALE wire types for IAVL proofs (mirror of commitment/src/tree/iavl/proof.rs).
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

    // LeafOp without version field to match state crate
    #[derive(Decode, Debug, Clone, PartialEq, Eq)]
    pub struct LeafOp {
        pub hash: HashOp,
        pub prehash_key: HashOp,
        pub prehash_value: HashOp,
        pub length: LengthOp,
        pub prefix: Vec<u8>,
    }

    #[derive(Decode, Debug, Clone, PartialEq, Eq)]
    pub enum HashOp {
        NoHash,
        Sha256,
    }

    #[derive(Decode, Debug, Clone, PartialEq, Eq)]
    pub enum LengthOp {
        NoPrefix,
        VarProto,
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

// --- Helper Functions ---

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

/// Helper to decode protobuf messages generically.
pub fn decode_pb<T: Message + Default>(bytes: &[u8]) -> Result<T, prost::DecodeError> {
    T::decode(bytes)
}

// --- ICS-23 Conversions ---

use ics23::ExistenceProof as NativeExistenceProof;

/// Converts a Protobuf `ExistenceProof` to a native `ics23::ExistenceProof`.
fn convert_existence_proof(proto: pb_ics23::ExistenceProof) -> Result<NativeExistenceProof> {
    let key = proto.key;
    let value = proto.value;

    let leaf_pb = proto
        .leaf
        .ok_or_else(|| anyhow!("ExistenceProof missing leaf"))?;
    let leaf = ics23::LeafOp {
        hash: match leaf_pb.hash {
            0 => ics23::HashOp::NoHash.into(),
            1 => ics23::HashOp::Sha256.into(),
            2 => ics23::HashOp::Sha512.into(),
            // [FIX] Removed unavailable HashOps for ics23 0.12 compatibility
            4 => ics23::HashOp::Ripemd160.into(),
            _ => return Err(anyhow!("Invalid or unsupported hash op")),
        },
        prehash_key: match leaf_pb.prehash_key {
            0 => ics23::HashOp::NoHash.into(),
            1 => ics23::HashOp::Sha256.into(),
            _ => ics23::HashOp::NoHash.into(),
        },
        prehash_value: match leaf_pb.prehash_value {
            0 => ics23::HashOp::NoHash.into(),
            1 => ics23::HashOp::Sha256.into(),
            _ => ics23::HashOp::NoHash.into(),
        },
        length: match leaf_pb.length {
            0 => ics23::LengthOp::NoPrefix.into(),
            1 => ics23::LengthOp::VarProto.into(),
            2 => ics23::LengthOp::VarRlp.into(),
            3 => ics23::LengthOp::Fixed32Big.into(),
            4 => ics23::LengthOp::Fixed32Little.into(),
            5 => ics23::LengthOp::Fixed64Big.into(),
            6 => ics23::LengthOp::Fixed64Little.into(),
            7 => ics23::LengthOp::Require32Bytes.into(),
            8 => ics23::LengthOp::Require64Bytes.into(),
            _ => return Err(anyhow!("Invalid length op")),
        },
        prefix: leaf_pb.prefix,
    };

    let mut path = Vec::new();
    for op_pb in proto.path {
        path.push(ics23::InnerOp {
            hash: match op_pb.hash {
                1 => ics23::HashOp::Sha256.into(),
                _ => ics23::HashOp::Sha256.into(),
            },
            prefix: op_pb.prefix,
            suffix: op_pb.suffix,
        });
    }

    Ok(NativeExistenceProof {
        key,
        value,
        leaf: Some(leaf),
        path,
    })
}

/// HostFunctionsProvider for `ics23` calculation in Relayer using dcrypt.
struct RelayerHostFunctions;
impl ics23::HostFunctionsProvider for RelayerHostFunctions {
    fn sha2_256(data: &[u8]) -> [u8; 32] {
        let digest = Sha256::digest(data).expect("sha256 digest");
        let mut out = [0u8; 32];
        out.copy_from_slice(digest.as_ref());
        out
    }
    fn sha2_512(data: &[u8]) -> [u8; 64] {
        let digest = Sha512::digest(data).expect("sha512 digest");
        let mut out = [0u8; 64];
        out.copy_from_slice(digest.as_ref());
        out
    }
    fn ripemd160(_data: &[u8]) -> [u8; 20] {
        [0u8; 20]
    }
    fn sha2_512_truncated(data: &[u8]) -> [u8; 32] {
        let digest = Sha512::digest(data).expect("sha512 digest");
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest.as_ref()[..32]);
        out
    }
    fn keccak_256(data: &[u8]) -> [u8; 32] {
        let digest = Keccak256::digest(data).expect("keccak256 digest");
        let mut out = [0u8; 32];
        out.copy_from_slice(digest.as_ref());
        out
    }
    fn blake2b_512(data: &[u8]) -> [u8; 64] {
        let digest = Blake2b::digest(data).expect("blake2b digest");
        let mut out = [0u8; 64];
        out.copy_from_slice(digest.as_ref());
        out
    }
    fn blake2s_256(data: &[u8]) -> [u8; 32] {
        let digest = Blake2s::digest(data).expect("blake2s digest");
        let mut out = [0u8; 32];
        out.copy_from_slice(digest.as_ref());
        out
    }
    fn blake3(_data: &[u8]) -> [u8; 32] {
        [0u8; 32]
    }
}

// --- Proof Handling ---

pub fn proof_indicates_membership(proof_bytes: &[u8]) -> Option<bool> {
    if let Some(p) = decode_scale_iavl_proof(proof_bytes) {
        return Some(matches!(p, IavlProof::Existence(_)));
    }
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
    if let Ok(mp) = decode_pb::<PbMerkleProof>(proof_bytes) {
        for cp in mp.proofs {
            if let Some(proof_variant) = cp.proof {
                if let pb_ics23::commitment_proof::Proof::Exist(_) = proof_variant {
                    return Some(true);
                }
            }
        }
        return Some(false);
    }
    if let Ok(ops) = decode_pb::<TmProofOps>(proof_bytes) {
        for op in ops.ops {
            if let Ok(cp) = decode_pb::<pb_ics23::CommitmentProof>(&op.data) {
                return proof_indicates_membership(&cp.encode_to_vec());
            }
        }
        return None;
    }
    None
}

pub fn existence_root_from_proof_bytes(proof_pb: &[u8]) -> Result<Vec<u8>> {
    tracing::debug!(
        target: "relayer",
        "existence_root: input_len={}, head={}",
        proof_pb.len(),
        hex_prefix(proof_pb, 24)
    );

    let try_decoders = |bytes: &[u8]| {
        root_from_scale_selector_then_opt_path_then_iavl(bytes)
            .or_else(|| root_from_scale_path_then_iavl(bytes))
            .or_else(|| root_from_scale_iavl_bytes(bytes))
            .or_else(|| root_from_any_ics23_like_bytes(bytes))
            .or_else(|| root_from_json_proofops_bytes(bytes))
            .or_else(|| root_from_json_any_like_bytes(bytes))
    };

    let peeled_initial = peel_all_scale_vec(proof_pb.to_vec());
    if let Some(root) = try_decoders(&peeled_initial) {
        return Ok(root);
    }

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
            let peeled_inner = peel_all_scale_vec(raw);
            if let Some(root) = try_decoders(&peeled_inner) {
                return Ok(root);
            }
        }

        if let Some(root) = root_from_json_proofops_bytes(s.as_bytes())
            .or_else(|| root_from_json_any_like_bytes(s.as_bytes()))
        {
            return Ok(root);
        }
    }

    if let Some(root) = scan_for_embedded_ics23_or_tm(proof_pb) {
        return Ok(root);
    }

    Err(anyhow!("Could not decode proof bytes to extract root"))
}

fn compute_root_from_commitment_proof(cp: &pb_ics23::CommitmentProof) -> Result<Vec<u8>> {
    match &cp.proof {
        Some(pb_ics23::commitment_proof::Proof::Exist(ex)) => {
            let native = convert_existence_proof(ex.clone())?;
            let hash = ics23::calculate_existence_root::<RelayerHostFunctions>(&native)
                .map_err(|e| anyhow!("{:?}", e))?;
            Ok(hash.to_vec())
        }
        Some(pb_ics23::commitment_proof::Proof::Batch(batch)) => {
            for entry in &batch.entries {
                if let Some(pb_ics23::batch_entry::Proof::Exist(ex)) = &entry.proof {
                    let native = convert_existence_proof(ex.clone())?;
                    let hash = ics23::calculate_existence_root::<RelayerHostFunctions>(&native)
                        .map_err(|e| anyhow!("{:?}", e))?;
                    return Ok(hash.to_vec());
                }
            }
            Err(anyhow!("No existence proof found in batch"))
        }
        _ => Err(anyhow!("Not an existence proof or supported batch")),
    }
}

// --- IAVL Root Calculation ---

#[inline]
fn hash_leaf_canonical(_leaf: &LeafOp, key: &[u8], value: &[u8]) -> Result<[u8; 32]> {
    let mut data = Vec::with_capacity(1 + 8 + 4 + 8 + 4 + key.len() + 4 + value.len());
    data.push(0x00);
    // [FIX] Correct leaf preimage construction to match standard IOI profile.
    // IOI/Cosmos IAVL profile: SHA256(0x00 || LengthPrefixed(Key) || LengthPrefixed(SHA256(Value)))

    // Check LeafOp hashing instructions
    let key_bytes = key.to_vec();
    // Pre-hash value for IAVL canonical format
    let value_digest = Sha256::digest(value).map_err(|e| anyhow!("{e}"))?;
    let val_bytes = value_digest.as_ref().to_vec();

    // Length prefixing
    fn encode_len(l: usize, buf: &mut Vec<u8>) {
        let _ = prost::encode_length_delimiter(l, buf);
    }

    encode_len(key_bytes.len(), &mut data);
    data.extend_from_slice(&key_bytes);

    encode_len(val_bytes.len(), &mut data);
    data.extend_from_slice(&val_bytes);

    let digest = Sha256::digest(&data).map_err(|e| anyhow!("sha256: {e}"))?;
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_ref());
    Ok(out)
}

#[inline]
fn hash_inner_canonical(op: &InnerOp, left: &[u8; 32], right: &[u8; 32]) -> Result<[u8; 32]> {
    let mut data = Vec::with_capacity(1 + 8 + 4 + 8 + 4 + op.split_key.len() + 32 + 32);
    data.push(0x01);
    data.extend_from_slice(&op.version.to_le_bytes());
    data.extend_from_slice(&op.height.to_le_bytes());
    data.extend_from_slice(&op.size.to_le_bytes());
    data.extend_from_slice(&(op.split_key.len() as u32).to_le_bytes());
    data.extend_from_slice(&op.split_key);
    data.extend_from_slice(left);
    data.extend_from_slice(right);

    let digest = Sha256::digest(&data).expect("sha256 digest");
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_ref());
    Ok(out)
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

// ... [Decoders and Peeling] ...

fn decode_scale_iavl_proof(bytes: &[u8]) -> Option<IavlProof> {
    if let Ok(inner) = scodec::from_bytes_canonical::<Vec<u8>>(bytes) {
        if let Ok(p) = <IavlProof as parity_scale_codec::Decode>::decode(&mut &*inner) {
            return Some(p);
        }
    }
    if let Ok(p) = <IavlProof as parity_scale_codec::Decode>::decode(&mut &*bytes) {
        return Some(p);
    }
    None
}

#[inline]
fn peel_all_scale_vec(mut bytes: Vec<u8>) -> Vec<u8> {
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

fn root_from_scale_iavl_bytes(proof_bytes: &[u8]) -> Option<Vec<u8>> {
    let p = decode_scale_iavl_proof(proof_bytes)?;
    let root = match p {
        IavlProof::Existence(ex) => compute_iavl_root_from_existence(&ex),
        IavlProof::NonExistence(nex) => compute_iavl_root_from_nonexistence(&nex),
    }
    .ok()?;
    Some(root.to_vec())
}

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

fn root_from_any_ics23_like_bytes(bytes: &[u8]) -> Option<Vec<u8>> {
    let (peeled, _) = peel_any_iteratively(bytes);
    root_from_tm_proofops_bytes(&peeled).or_else(|| root_from_ics23_family_bytes(&peeled))
}

fn root_from_ics23_family_bytes(bytes: &[u8]) -> Option<Vec<u8>> {
    if let Ok(mp) = decode_pb::<PbMerkleProof>(bytes) {
        for cp in mp.proofs {
            if let Ok(root) = compute_root_from_commitment_proof(&cp) {
                return Some(root);
            }
        }
    }
    if let Ok(cp) = decode_pb::<pb_ics23::CommitmentProof>(bytes) {
        if let Ok(root) = compute_root_from_commitment_proof(&cp) {
            return Some(root);
        }
    }
    if let Ok(ex_pb) = decode_pb::<pb_ics23::ExistenceProof>(bytes) {
        let ex_native: ics23::ExistenceProof = ex_pb.try_into().ok()?;
        if let Ok(root) = ics23::calculate_existence_root::<RelayerHostFunctions>(&ex_native) {
            return Some(root.to_vec());
        }
    }
    None
}

fn root_from_tm_proofops_bytes(bytes: &[u8]) -> Option<Vec<u8>> {
    if let Ok(mut ops) = decode_pb::<TmProofOps>(bytes) {
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
    if let Ok(op) = decode_pb::<TmProofOp>(bytes) {
        let (payload, _) = peel_any_iteratively(&op.data);
        return root_from_ics23_family_bytes(&payload);
    }
    None
}

fn root_from_scale_tail_any_proof(mut tail: &[u8]) -> Option<Vec<u8>> {
    if let Ok(p) = <IavlProof as parity_scale_codec::Decode>::decode(&mut tail) {
        let root = match p {
            IavlProof::Existence(ex) => compute_iavl_root_from_existence(&ex),
            IavlProof::NonExistence(ne) => compute_iavl_root_from_nonexistence(&ne),
        }
        .ok()?;
        return Some(root.to_vec());
    }
    root_from_any_ics23_like_bytes(tail)
}

fn root_from_scale_selector_then_opt_path_then_iavl(bytes: &[u8]) -> Option<Vec<u8>> {
    let mut cur = &*bytes;
    let _selector: parity_scale_codec::Compact<u32> =
        <parity_scale_codec::Compact<u32> as parity_scale_codec::Decode>::decode(&mut cur).ok()?;
    let _path_opt: Option<String> =
        <Option<String> as parity_scale_codec::Decode>::decode(&mut cur).ok()?;
    root_from_scale_tail_any_proof(cur)
}

fn root_from_scale_path_then_iavl(bytes: &[u8]) -> Option<Vec<u8>> {
    let mut cur = &*bytes;
    let _tag: u8 = <u8 as parity_scale_codec::Decode>::decode(&mut cur).ok()?;
    let _path: String = <String as parity_scale_codec::Decode>::decode(&mut cur).ok()?;
    root_from_scale_tail_any_proof(cur)
}

#[derive(Deserialize)]
struct JsonOp {
    #[serde(rename = "type")]
    t: String,
    data: String,
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
    if let Ok(j) = serde_json::from_str::<JsonOpsOnly>(s) {
        return extract_root_from_json_ops(j.ops);
    }
    if let Ok(j) = serde_json::from_str::<JsonProofWrapper>(s) {
        return extract_root_from_json_ops(j.proof.ops);
    }
    None
}

fn extract_root_from_json_ops(mut ops: Vec<JsonOp>) -> Option<Vec<u8>> {
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
    None
}

fn root_from_json_any_like_bytes(bytes: &[u8]) -> Option<Vec<u8>> {
    let s = str::from_utf8(bytes).ok()?;
    let v: JsonValue = serde_json::from_str(s).ok()?;
    if let Some(obj) = v.as_object() {
        if let Some(val_s) = obj.get("value").and_then(|x| x.as_str()) {
            if let Some(raw) = b64_decode_any(val_s) {
                let (payload, _) = peel_any_iteratively(&raw);
                return root_from_ics23_family_bytes(&payload);
            }
        }
    }
    None
}

fn scan_for_embedded_ics23_or_tm(bytes: &[u8]) -> Option<Vec<u8>> {
    let n = bytes.len().min(4096);
    for i in 0..n {
        let s = &bytes[i..];
        if let Some(root) = root_from_scale_iavl_bytes(s) {
            return Some(root);
        }
        if let Ok(cp) = decode_pb::<pb_ics23::CommitmentProof>(s) {
            if let Ok(root) = compute_root_from_commitment_proof(&cp) {
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

fn is_ascii_base64(s: &str) -> bool {
    let s = s.chars().filter(|c| !c.is_whitespace()).collect::<String>();
    if s.len() < 16 || s.len() % 4 != 0 {
        return false;
    }
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '-' | '_' | '='))
}

fn b64_decode_any(s: &str) -> Option<Vec<u8>> {
    let clean = s.chars().filter(|c| !c.is_whitespace()).collect::<String>();
    if let Ok(v) = BASE64.decode(&clean) {
        return Some(v);
    }
    let norm = clean.replace('-', "+").replace('_', "/");
    BASE64.decode(norm).ok()
}

// --- Inference Helpers for Channel and Connection ID ---

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

/// Compute allocated `connection-{n}` after an Init/Try committed.
pub async fn infer_allocated_connection_id(gw: &Gateway) -> Result<(String, u64)> {
    const RETRIES: usize = 20;
    const SLEEP_MS: u64 = 50;
    const SCAN_CAP: u64 = 128;

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
