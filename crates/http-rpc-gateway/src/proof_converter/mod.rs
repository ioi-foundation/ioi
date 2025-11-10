// Path: crates/http-rpc-gateway/src/proof_converter/mod.rs

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
pub fn convert_proof(
    raw_proof_bytes: &[u8],
    format: ProofFormat,
    path_hint: Option<&str>,
) -> Result<Vec<u8>> {
    let t0 = std::time::Instant::now();
    let buf_in_len = raw_proof_bytes.len();

    // In a multi-tree system, we would first detect the proof type here.
    // For now, we assume IAVL.
    
    // Example of how Verkle would be handled:
    // if is_verkle_proof(raw_proof_bytes) {
    //     let commitment_proof = convert_verkle_to_ics23(raw_proof_bytes)?;
    //     ... (package and serialize as below) ...
    // }

    // 1) Parse the native IAVL proof, tolerating common wrappers.
    let (iavl_proof, steps_applied, parsed_format) = decode_iavl_proof_flex(raw_proof_bytes)?;

    // 2) Convert the native IAVL proof into a standard ICS‑23 CommitmentProof (protobuf).
    let commitment_proof = convert_iavl_to_ics23(&iavl_proof)?;

    // 3) Package and serialize according to the requested format.
    let out = match format {
        ProofFormat::Ics23 => {
            let merkle_proof = PbMerkleProof {
                proofs: vec![commitment_proof],
            };
            merkle_proof.encode_to_vec()
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
            proof_ops.encode_to_vec()
        }
    };

    tracing::debug!(
        target: "ibc.proof", event = "convert", parsed_format = %parsed_format, steps_applied = ?steps_applied,
        proof_len_in = buf_in_len, proof_len_out = out.len(), convert_ms = t0.elapsed().as_millis(), path = %path_hint.unwrap_or("?"),
    );

    Ok(out)
}

/// Try to decode an `IavlProof`, peeling common wrappers used by the workload:
///  - ioi_state::primitives::hash::HashProof { value: Vec<u8> }
///  - SCALE `Vec<u8>` indirection
///  - ASCII "0x..." hex wrapper
fn decode_iavl_proof_flex(input: &[u8]) -> Result<(IavlProof, Vec<&'static str>, &'static str)> {
    let mut steps_applied = Vec::new();
    let mut buf: Vec<u8> = input.to_vec();

    for _ in 0..6 {
        // Try to decode as IavlProof directly. If it works, we're done.
        // This handles the case where the input is already the correct format, or we've finished peeling.
        if let Ok(proof) = IavlProof::decode(&mut &*buf) {
            return Ok((proof, steps_applied, "scale_iavl"));
        }

        // Try peeling wrappers, from most specific/unambiguous to least.

        // 1. Peel 0x-hex textual encoding first, as it's unambiguous.
        if let Ok(s) = std::str::from_utf8(&buf) {
            if let Some(hexstr) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                if let Ok(raw) = hex::decode(hexstr) {
                    buf = raw;
                    steps_applied.push("hex");
                    continue; // Restart loop with the raw bytes.
                }
            }
        }

        // 2. Peel HashProof wrapper (contains proof in `.value`). This is a specific struct.
        if let Ok(hp) = HashProof::decode(&mut &*buf) {
            buf = hp.value;
            steps_applied.push("hashproof");
            continue; // Restart loop with the inner bytes.
        }

        // 3. Peel generic SCALE Vec<u8> wrapper. This is ambiguous, so it's last.
        // We use a temporary cursor and check if the *entire* buffer is consumed as a single Vec<u8>.
        // This is a strong indicator of a `Vec<u8>` wrapper.
        let mut temp_cursor = &buf[..];
        if let Ok(inner) = <Vec<u8> as parity_scale_codec::Decode>::decode(&mut temp_cursor) {
            if temp_cursor.is_empty() {
                // <-- This check is key to avoid false positives
                buf = inner;
                steps_applied.push("scale_vec");
                continue; // Restart loop with the inner bytes.
            }
        }

        // If we tried all peels and none matched, break the loop. The buffer is in its final form.
        break;
    }

    // Perform a final decode attempt on whatever bytes are left after peeling.
    // If this fails, the input format is truly unsupported.
    IavlProof::decode(&mut &*buf)
        .map(|p| (p, steps_applied, "scale_iavl"))
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
    // The native `LeafOp` now has all the fields we need. Just copy them.
    let leaf = PbLeafOp {
        hash: match ex.leaf.hash {
            ioi_state::tree::iavl::proof::HashOp::Sha256 => PbHashOp::Sha256 as i32,
            ioi_state::tree::iavl::proof::HashOp::NoHash => PbHashOp::NoHash as i32,
        },
        prehash_key: match ex.leaf.prehash_key {
            ioi_state::tree::iavl::proof::HashOp::Sha256 => PbHashOp::Sha256 as i32,
            ioi_state::tree::iavl::proof::HashOp::NoHash => PbHashOp::NoHash as i32,
        },
        prehash_value: match ex.leaf.prehash_value {
            ioi_state::tree::iavl::proof::HashOp::Sha256 => PbHashOp::Sha256 as i32,
            ioi_state::tree::iavl::proof::HashOp::NoHash => PbHashOp::NoHash as i32,
        },
        length: match ex.leaf.length {
            ioi_state::tree::iavl::proof::LengthOp::NoPrefix => PbLengthOp::NoPrefix as i32,
            ioi_state::tree::iavl::proof::LengthOp::VarProto => PbLengthOp::VarProto as i32,
        },
        prefix: ex.leaf.prefix.clone(),
    };
    
    // Build the InnerOp path. The "header" encodes the native step metadata;
    // the sibling hash is placed on the left (prefix) or right (suffix) by step.side.
    let mut path: Vec<PbInnerOp> = Vec::with_capacity(ex.path.len());
    for step in &ex.path {
        let mut header = Vec::new();
        header.push(0x01); // inner node tag used by the native preimage
        header.extend_from_slice(&step.version.to_le_bytes());
        header.extend_from_slice(&step.height.to_le_bytes());
        header.extend_from_slice(&step.size.to_le_bytes());
        header.extend_from_slice(&(step.split_key.len() as u32).to_le_bytes());
        header.extend_from_slice(&step.split_key);

        let (prefix_bytes, suffix_bytes) = match step.side {
            Side::Left => {
                let mut p = header;
                p.extend_from_slice(&step.sibling_hash);
                (p, Vec::new())
            }
            Side::Right => (header, step.sibling_hash.to_vec()),
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

/// Placeholder for converting a Verkle proof to an ICS-23 CommitmentProof.
/// This is a complex cryptographic task and is not implemented here.
#[allow(dead_code)]
fn convert_verkle_to_ics23(_proof_bytes: &[u8]) -> Result<PbCommitmentProof> {
    // A real implementation would involve:
    // 1. Deserializing the native VerklePathProof.
    // 2. Synthesizing a series of `InnerOp`s and a `LeafOp` that, when applied in a
    //    Merkle-style verification, would result in the same root hash.
    // 3. This may involve embedding KZG commitments or other data within the `prefix`
    //    or `suffix` fields of the ICS-23 operations.
    // This is a highly non-trivial task.
    Err(anyhow!(
        "Verkle-to-ICS23 proof conversion is not yet implemented"
    ))
}


#[cfg(test)]
mod tests;