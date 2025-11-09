// Path: crates/http-rpc-gateway/src/proof_converter.rs

use anyhow::{anyhow, Result};
use ibc_proto::{
    ibc::core::commitment::v1::MerkleProof as PbMerkleProof,
    ics23::{
        commitment_proof::Proof as PbProofVariant, CommitmentProof as PbCommitmentProof,
        ExistenceProof as PbExistenceProof, HashOp as PbHashOp, InnerOp as PbInnerOp,
        LeafOp as PbLeafOp, LengthOp as PbLengthOp, NonExistenceProof as PbNonExistenceProof,
    },
};
use ioi_state::primitives::hash::HashProof;
use ioi_state::tree::iavl::{ExistenceProof, IavlProof, NonExistenceProof, Side};
use parity_scale_codec::Decode; // enables IavlProof::decode
use prost::Message;
use hex;
use tendermint_proto::crypto::{ProofOp, ProofOps};

/// The target Protobuf format for the converted proof.
#[derive(Clone, Copy, Debug)]
pub enum ProofFormat {
    /// An `ibc.core.commitment.v1.MerkleProof` containing one or more `ics23.CommitmentProof`s.
    Ics23,
    /// A `tendermint.crypto.ProofOps` structure wrapping the `Ics23` format.
    ProofOps,
}

impl std::str::FromStr for ProofFormat {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, ()> {
        match s.to_ascii_lowercase().as_str() {
            "ics23" => Ok(ProofFormat::Ics23),
            "proofops" => Ok(ProofFormat::ProofOps),
            _ => Err(()),
        }
    }
}

/// Converts a raw, native proof from the Workload into a canonical IBC Protobuf format.
pub fn convert_proof(raw_proof_bytes: &[u8], format: ProofFormat) -> Result<Vec<u8>> {
    // 1) Parse the native proof, tolerating common wrappers (HashProof, Vec<u8>, 0x-hex).
    let iavl_proof = decode_iavl_proof_flex(raw_proof_bytes)?;

    // 2) Convert the native proof into a standard ICS‑23 CommitmentProof (protobuf).
    let commitment_proof = convert_iavl_to_ics23(&iavl_proof)?;

    // 3) Package and serialize according to the requested format.
    match format {
        ProofFormat::Ics23 => {
            let merkle_proof = PbMerkleProof {
                proofs: vec![commitment_proof],
            };
            Ok(merkle_proof.encode_to_vec())
        }
        ProofFormat::ProofOps => {
            // Tendermint ProofOps wrapper carrying a MerkleProof.
            let merkle_proof = PbMerkleProof {
                proofs: vec![commitment_proof],
            };
            let proof_op = ProofOp {
                r#type: "ics23:iavl".to_string(),
                key: Vec::new(),
                data: merkle_proof.encode_to_vec(),
            };
            let proof_ops = ProofOps { ops: vec![proof_op] };
            Ok(proof_ops.encode_to_vec())
        }
    }
}

/// Try to decode an `IavlProof`, peeling common wrappers used by the workload:
///  - ioi_state::primitives::hash::HashProof { value: Vec<u8> }
///  - SCALE `Vec<u8>` indirection
///  - ASCII "0x..." hex wrapper
fn decode_iavl_proof_flex(input: &[u8]) -> Result<IavlProof> {
    // Work on an owned buffer we can mutate as we peel.
    let mut buf: Vec<u8> = input.to_vec();
    // Limit peeling attempts to avoid loops on malformed inputs.
    for _ in 0..6 {
        // Direct attempt: SCALE-decode IavlProof
        if let Ok(proof) = IavlProof::decode(&mut &*buf) {
            return Ok(proof);
        }
        // Peel HashProof wrapper (extract .value)
        if let Ok(hp) = HashProof::decode(&mut &*buf) {
            buf = hp.value;
            continue;
        }
        // Peel SCALE Vec<u8> indirection
        if let Ok(inner) = <Vec<u8> as parity_scale_codec::Decode>::decode(&mut &*buf) {
            buf = inner;
            continue;
        }
        // Peel 0x-hex textual encoding
        if let Ok(s) = std::str::from_utf8(&buf) {
            if let Some(hexstr) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                if hexstr.len() % 2 == 0 && hexstr.chars().all(|c| c.is_ascii_hexdigit()) {
                    if let Ok(raw) = hex::decode(hexstr) {
                        buf = raw;
                        continue;
                    }
                }
            }
        }
        // Nothing matched; stop peeling.
        break;
    }
    // Final attempt as IavlProof; if this fails, report a clear error.
    IavlProof::decode(&mut &*buf)
        .map_err(|e| anyhow!("unsupported proof encoding (IAVL/SCALE wrappers): {e}"))
}


/// Converts a native IAVL proof into a standard ICS‑23 `CommitmentProof` (protobuf).
fn convert_iavl_to_ics23(iavl_proof: &IavlProof) -> Result<PbCommitmentProof> {
    Ok(match iavl_proof {
        IavlProof::Existence(ex) => PbCommitmentProof {
            proof: Some(PbProofVariant::Exist(build_ics23_existence(ex)?)),
        },
        IavlProof::NonExistence(nex) => PbCommitmentProof {
            proof: Some(PbProofVariant::Nonexist(build_ics23_non_existence(nex)?)),
        },
    })
}

/// Constructs a protobuf ICS‑23 `ExistenceProof` from a native IAVL `ExistenceProof`.
fn build_ics23_existence(ex: &ExistenceProof) -> Result<PbExistenceProof> {
    // Use typical Cosmos IAVL settings for hash/length ops.
    // These are protobuf enum values; we do not verify here, only format the proof.
    let leaf = PbLeafOp {
        hash: PbHashOp::Sha256 as i32,
        prehash_key: PbHashOp::NoHash as i32,
        prehash_value: PbHashOp::Sha256 as i32,
        length: PbLengthOp::VarProto as i32,
        // Many Cosmos implementations leave leaf prefix empty for IAVL membership proofs.
        // Adjust if your native preimage includes a fixed leaf prefix.
        prefix: Vec::new(),
    };

    // Build the InnerOp path. The "header" encodes the native step metadata;
    // the sibling hash is placed on the left (prefix) or right (suffix) by step.side.
    let mut path: Vec<PbInnerOp> = Vec::with_capacity(ex.path.len());
    for step in &ex.path {
        // Constant header that your native IAVL encoding uses prior to the child value.
        let mut header = Vec::new();
        header.push(0x01); // inner node tag used by the native preimage
        header.extend_from_slice(&step.version.to_le_bytes());
        header.extend_from_slice(&step.height.to_le_bytes());
        header.extend_from_slice(&step.size.to_le_bytes());
        header.extend_from_slice(&(step.split_key.len() as u32).to_le_bytes());
        header.extend_from_slice(&step.split_key);

        // Ensure both arms return (Vec<u8>, Vec<u8>) to satisfy the compiler.
        let (prefix_bytes, suffix_bytes): (Vec<u8>, Vec<u8>) = match step.side {
            Side::Left => (header, step.sibling_hash.to_vec()),
            Side::Right => {
                let mut p = header;
                p.extend_from_slice(&step.sibling_hash);
                (p, Vec::new())
            }
        };

        path.push(PbInnerOp {
            hash: PbHashOp::Sha256 as i32,
            prefix: prefix_bytes,
            suffix: suffix_bytes,
        });
    }

    Ok(PbExistenceProof {
        key: ex.key.clone(),
        value: ex.value.clone(),
        leaf: Some(leaf),
        path,
    })
}

/// Constructs a protobuf ICS‑23 `NonExistenceProof` from a native IAVL `NonExistenceProof`.
fn build_ics23_non_existence(nex: &NonExistenceProof) -> Result<PbNonExistenceProof> {
    let left = nex.left.as_ref().map(build_ics23_existence).transpose()?;
    let right = nex.right.as_ref().map(build_ics23_existence).transpose()?;
    Ok(PbNonExistenceProof {
        key: nex.missing_key.clone(),
        left,
        right,
    })
}