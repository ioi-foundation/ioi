//! Fail-closed operator ceremony for Q-EA7 candidate inputs.
//!
//! These helpers only validate, sign, and atomically publish replayable input
//! bytes. They never contact members, create a `QuvOnlineAuthorizationV0`, or
//! establish finality. Every successor must still execute and consume its own
//! live QUV operation.

use anyhow::{anyhow, Context, Result};
use ioi_api::crypto::{SerializableKey, SigningKeyPair, VerifyingKey};
use ioi_consensus::aft::query_unanimity::{
    quv_candidate_authority_signing_bytes, quv_candidate_hash, quv_handoff_payload_hash,
    validate_quv_handoff_candidate,
};
use ioi_crypto::sign::dilithium::{MldsaKeyPair, MldsaPublicKey, MldsaSignature};
use ioi_types::app::{
    account_id_from_key_material, canonical_validator_set_hash, QuvConfigurationHandoffEnvelopeV0,
    SignatureSuite,
};
use ioi_types::codec;
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

const MAX_HANDOFF_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, Clone, Serialize)]
pub struct QuvHandoffCeremonyAuditV0 {
    pub schema: &'static str,
    pub disposition: &'static str,
    pub candidate_hash: String,
    pub payload_hash: String,
    pub network_id: String,
    pub old_configuration_root: String,
    pub successor_configuration_root: String,
    pub activation_height: u64,
    pub old_authority_expiry_height: u64,
    pub state_height: u64,
    pub state_block_hash: String,
    pub owner: String,
    pub owner_signature_present: bool,
    pub portable_final_receipt: bool,
    pub process_local_authorization_present: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PqcKeyFile {
    public: String,
    #[serde(default)]
    private: Option<String>,
}

pub fn inspect_handoff(path: &Path) -> Result<QuvHandoffCeremonyAuditV0> {
    let envelope = read_envelope(path)?;
    inspect_envelope(&envelope)
}

pub fn sign_handoff_draft(
    draft: &Path,
    owner_key_file: &Path,
    output: &Path,
    replace: bool,
) -> Result<QuvHandoffCeremonyAuditV0> {
    let mut envelope = read_envelope(draft)?;
    inspect_envelope(&envelope)?;
    if !envelope.candidate.authority_signature.is_empty() {
        return Err(anyhow!("QUV handoff draft is already signed"));
    }
    let key_file = read_key_file(owner_key_file)?;
    let private = key_file.private.as_deref().ok_or_else(|| {
        anyhow!("owner key file has no private key; signing requires both public and private")
    })?;
    let public = decode_hex(&key_file.public, "owner public key")?;
    let private = decode_hex(private, "owner private key")?;
    require_owner(&envelope, &public)?;
    let keypair = MldsaKeyPair::from_bytes(&public, &private)
        .map_err(|error| anyhow!("invalid ML-DSA-44 owner keypair: {error}"))?;
    envelope.candidate.authority_signature = keypair
        .sign(&quv_candidate_authority_signing_bytes(&envelope.candidate)?)?
        .to_bytes();
    verify_owner_signature(&envelope, &public)?;
    persist_envelope(output, &envelope, replace)?;
    inspect_envelope(&envelope)
}

pub fn verify_signed_handoff(
    input: &Path,
    owner_public_key_file: &Path,
) -> Result<QuvHandoffCeremonyAuditV0> {
    let envelope = read_envelope(input)?;
    let public = decode_hex(
        &read_key_file(owner_public_key_file)?.public,
        "owner public key",
    )?;
    verify_owner_signature(&envelope, &public)?;
    inspect_envelope(&envelope)
}

pub fn install_signed_handoff(
    input: &Path,
    owner_public_key_file: &Path,
    destination: &Path,
    replace: bool,
) -> Result<QuvHandoffCeremonyAuditV0> {
    if input == destination {
        return Err(anyhow!("QUV handoff input and destination must differ"));
    }
    let envelope = read_envelope(input)?;
    let public = decode_hex(
        &read_key_file(owner_public_key_file)?.public,
        "owner public key",
    )?;
    verify_owner_signature(&envelope, &public)?;
    persist_envelope(destination, &envelope, replace)?;
    inspect_envelope(&envelope)
}

fn inspect_envelope(
    envelope: &QuvConfigurationHandoffEnvelopeV0,
) -> Result<QuvHandoffCeremonyAuditV0> {
    let successor_configuration_root =
        validate_quv_handoff_candidate(&envelope.candidate, &envelope.handoff)?;
    let canonical_successor_root = canonical_validator_set_hash(&envelope.handoff.successor_set)
        .map_err(anyhow::Error::msg)?;
    if successor_configuration_root != canonical_successor_root {
        return Err(anyhow!("QUV successor commitment mismatch"));
    }
    let candidate_hash = quv_candidate_hash(&envelope.candidate)?;
    let payload_hash = quv_handoff_payload_hash(&envelope.handoff)?;
    Ok(QuvHandoffCeremonyAuditV0 {
        schema: "ioi.aft.quv-handoff-ceremony-audit.v0",
        disposition: "candidate_input_only",
        candidate_hash: hex::encode(candidate_hash),
        payload_hash: hex::encode(payload_hash),
        network_id: hex::encode(envelope.handoff.network_id),
        old_configuration_root: hex::encode(envelope.handoff.old_configuration_root),
        successor_configuration_root: hex::encode(successor_configuration_root),
        activation_height: envelope.handoff.activation_height,
        old_authority_expiry_height: envelope.handoff.old_authority_expiry_height,
        state_height: envelope.handoff.state_height,
        state_block_hash: hex::encode(envelope.handoff.state_block_hash),
        owner: hex::encode(envelope.candidate.authorizer.as_ref()),
        owner_signature_present: !envelope.candidate.authority_signature.is_empty(),
        portable_final_receipt: false,
        process_local_authorization_present: false,
    })
}

fn verify_owner_signature(
    envelope: &QuvConfigurationHandoffEnvelopeV0,
    public: &[u8],
) -> Result<()> {
    inspect_envelope(envelope)?;
    require_owner(envelope, public)?;
    if envelope.candidate.authority_signature.is_empty() {
        return Err(anyhow!("QUV handoff source has no owner signature"));
    }
    let public_key = MldsaPublicKey::from_bytes(public)
        .map_err(|error| anyhow!("invalid ML-DSA-44 owner public key: {error}"))?;
    let signature = MldsaSignature::from_bytes(&envelope.candidate.authority_signature)
        .map_err(|error| anyhow!("invalid ML-DSA-44 owner signature bytes: {error}"))?;
    public_key
        .verify(
            &quv_candidate_authority_signing_bytes(&envelope.candidate)?,
            &signature,
        )
        .map_err(|error| anyhow!("QUV handoff owner signature verification failed: {error}"))
}

fn require_owner(envelope: &QuvConfigurationHandoffEnvelopeV0, public: &[u8]) -> Result<()> {
    let owner = account_id_from_key_material(SignatureSuite::ML_DSA_44, public)
        .map_err(anyhow::Error::msg)?;
    if owner != envelope.candidate.authorizer.0 {
        return Err(anyhow!(
            "ML-DSA-44 key does not belong to the rooted QUV handoff owner"
        ));
    }
    Ok(())
}

fn read_key_file(path: &Path) -> Result<PqcKeyFile> {
    let bytes = read_bounded(path, MAX_HANDOFF_BYTES)?;
    serde_json::from_slice(&bytes)
        .with_context(|| format!("invalid PQ key JSON at {}", path.display()))
}

fn read_envelope(path: &Path) -> Result<QuvConfigurationHandoffEnvelopeV0> {
    codec::from_bytes_canonical(&read_bounded(path, MAX_HANDOFF_BYTES)?).map_err(|error| {
        anyhow!(
            "invalid canonical QUV handoff at {}: {error}",
            path.display()
        )
    })
}

fn read_bounded(path: &Path, max_bytes: u64) -> Result<Vec<u8>> {
    let metadata =
        std::fs::metadata(path).with_context(|| format!("failed to stat {}", path.display()))?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > max_bytes {
        return Err(anyhow!(
            "{} must be a nonempty regular file no larger than {} bytes",
            path.display(),
            max_bytes
        ));
    }
    std::fs::read(path).with_context(|| format!("failed to read {}", path.display()))
}

fn persist_envelope(
    destination: &Path,
    envelope: &QuvConfigurationHandoffEnvelopeV0,
    replace: bool,
) -> Result<()> {
    let bytes = codec::to_bytes_canonical(envelope).map_err(anyhow::Error::msg)?;
    if destination.exists() {
        let existing = read_bounded(destination, MAX_HANDOFF_BYTES)?;
        if existing == bytes {
            return Ok(());
        }
        if !replace {
            return Err(anyhow!(
                "refusing to replace different QUV handoff destination {} without --replace",
                destination.display()
            ));
        }
    }
    let parent = destination
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)
        .with_context(|| format!("failed to create {}", parent.display()))?;
    let file_name = destination
        .file_name()
        .ok_or_else(|| anyhow!("QUV handoff destination has no file name"))?
        .to_string_lossy();
    let temporary: PathBuf = parent.join(format!(".{file_name}.tmp.{}", std::process::id()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let install = (|| -> Result<()> {
        let mut file = options
            .open(&temporary)
            .with_context(|| format!("failed to create {}", temporary.display()))?;
        file.write_all(&bytes)
            .and_then(|_| file.sync_all())
            .with_context(|| format!("failed to persist {}", temporary.display()))?;
        std::fs::rename(&temporary, destination).with_context(|| {
            format!(
                "failed to atomically install QUV handoff at {}",
                destination.display()
            )
        })?;
        Ok(())
    })();
    if let Err(error) = install {
        let _ = std::fs::remove_file(&temporary);
        return Err(error);
    }
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .with_context(|| format!("failed to sync {}", parent.display()))?;
    Ok(())
}

fn decode_hex(value: &str, label: &str) -> Result<Vec<u8>> {
    hex::decode(value.strip_prefix("0x").unwrap_or(value))
        .with_context(|| format!("{label} is not valid hex"))
}
