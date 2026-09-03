use ioi_types::app::{
    aft_async_proposal_payload_hash, AftAsyncExecutedBlockCertificateV1,
    AftAsyncExecutedBlockDecisionV1, AftAsyncExecutedBlockVoteV1, AftAsyncInstanceV1,
    AftAsyncOrderingCertificateV1, AftAsyncProposalAvailabilityCertificateV1,
    AftAsyncProposalDescriptorV1, AftAsyncProposalRefV1, AftAsyncSelectedBatchWitnessV1,
    AFT_ASYNC_MAX_INLINE_PROPOSAL_BYTES_V1, AFT_ASYNC_PROTOCOL_VERSION_V1,
    AFT_ASYNC_SCHEMA_VERSION_V1,
};
use ioi_types::codec;
use parity_scale_codec::{Decode, Encode};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
struct StoredProposalV1 {
    protocol_version: u16,
    schema_version: u16,
    descriptor: AftAsyncProposalDescriptorV1,
    payload: Vec<u8>,
}

/// Crash-safe content-addressed storage used by the validate-and-hold signing
/// discipline. A node may issue an availability vote only after `retain`
/// returns successfully. Proposal bytes are public consensus inputs, but files
/// are still created owner-only to avoid widening local disclosure.
#[derive(Clone, Debug)]
pub struct DurableAsyncProposalStore {
    root: PathBuf,
    instance: AftAsyncInstanceV1,
}

impl DurableAsyncProposalStore {
    /// Opens one instance-scoped content-addressed proposal store.
    pub fn open(root: &Path, instance: AftAsyncInstanceV1) -> Result<Self, String> {
        instance.validate()?;
        let scoped = root.join(hex::encode(instance.instance_hash()?));
        std::fs::create_dir_all(&scoped)
            .map_err(|error| format!("failed to create {}: {error}", scoped.display()))?;
        sync_directory(&scoped)?;
        Ok(Self {
            root: scoped,
            instance,
        })
    }

    /// Builds and durably retains a locally proposed payload.
    pub fn retain_local(
        &self,
        proposer: u16,
        parent_root: [u8; 32],
        payload: &[u8],
    ) -> Result<AftAsyncProposalDescriptorV1, String> {
        let descriptor = AftAsyncProposalDescriptorV1 {
            instance_hash: self.instance.instance_hash()?,
            proposer,
            proposal_hash: aft_async_proposal_payload_hash(payload)?,
            payload_len: u64::try_from(payload.len())
                .map_err(|_| "AFT asynchronous proposal length is not representable")?,
            parent_root,
        };
        self.retain(&descriptor, payload)?;
        let local_path = self.root.join("local-proposal.scale");
        if local_path.exists() {
            let previous = codec::from_bytes_canonical::<AftAsyncProposalDescriptorV1>(
                &std::fs::read(&local_path)
                    .map_err(|error| format!("failed to read {}: {error}", local_path.display()))?,
            )?;
            if previous != descriptor {
                return Err("AFT asynchronous local proposal is already frozen".into());
            }
        } else {
            persist_atomic(&local_path, &codec::to_bytes_canonical(&descriptor)?)?;
        }
        Ok(descriptor)
    }

    /// Returns the durably frozen local descriptor, if proposal issuance had
    /// completed before restart.
    pub fn local_descriptor(&self) -> Result<Option<AftAsyncProposalDescriptorV1>, String> {
        let path = self.root.join("local-proposal.scale");
        if !path.exists() {
            return Ok(None);
        }
        let descriptor = codec::from_bytes_canonical::<AftAsyncProposalDescriptorV1>(
            &std::fs::read(&path)
                .map_err(|error| format!("failed to read {}: {error}", path.display()))?,
        )?;
        descriptor.validate_for(&self.instance)?;
        self.load(&descriptor)?;
        Ok(Some(descriptor))
    }

    /// Hash-checks and atomically retains bytes received from any proposer.
    /// Exact duplicate storage is idempotent; path or content rebinding fails.
    pub fn retain(
        &self,
        descriptor: &AftAsyncProposalDescriptorV1,
        payload: &[u8],
    ) -> Result<(), String> {
        self.validate_payload(descriptor, payload)?;
        let stored = StoredProposalV1 {
            protocol_version: AFT_ASYNC_PROTOCOL_VERSION_V1,
            schema_version: AFT_ASYNC_SCHEMA_VERSION_V1,
            descriptor: descriptor.clone(),
            payload: payload.to_vec(),
        };
        let path = self.path_for(descriptor);
        if path.exists() {
            let existing = self.read(&path)?;
            if existing == stored {
                return Ok(());
            }
            return Err("AFT asynchronous proposal store refuses content rebinding".into());
        }
        persist_atomic(&path, &codec::to_bytes_canonical(&stored)?)
    }

    /// Loads a proposal and revalidates every commitment before returning it.
    pub fn load(&self, descriptor: &AftAsyncProposalDescriptorV1) -> Result<Vec<u8>, String> {
        descriptor.validate_for(&self.instance)?;
        let stored = self.read(&self.path_for(descriptor))?;
        if stored.descriptor != *descriptor {
            return Err("AFT asynchronous stored proposal descriptor is rebound".into());
        }
        self.validate_payload(descriptor, &stored.payload)?;
        Ok(stored.payload)
    }

    /// Persists a fully rooted, signature-verified availability certificate.
    /// Verification is a caller obligation; this layer repeats all portable
    /// shape and instance bindings before making the evidence durable.
    pub fn retain_verified_availability_certificate(
        &self,
        certificate: &AftAsyncProposalAvailabilityCertificateV1,
    ) -> Result<[u8; 32], String> {
        let certificate_hash = certificate.certificate_hash(&self.instance)?;
        self.load(&certificate.descriptor)?;
        persist_idempotent_canonical(
            &self.availability_certificate_path(certificate_hash),
            certificate,
        )?;
        Ok(certificate_hash)
    }

    /// Reloads one availability certificate by the exact commitment carried
    /// in an agreed proposal reference and rechecks that commitment.
    pub fn load_availability_certificate(
        &self,
        reference: &AftAsyncProposalRefV1,
    ) -> Result<AftAsyncProposalAvailabilityCertificateV1, String> {
        reference.validate_for(&self.instance)?;
        let path = self.availability_certificate_path(reference.availability_certificate_hash);
        let certificate = codec::from_bytes_canonical::<AftAsyncProposalAvailabilityCertificateV1>(
            &read_bounded(&path, 32 * 1024 * 1024)?,
        )?;
        if certificate.certificate_hash(&self.instance)? != reference.availability_certificate_hash
        {
            return Err("stored AFT availability certificate commitment is invalid".into());
        }
        reference.validate_availability_binding(&self.instance, &certificate)?;
        Ok(certificate)
    }

    /// Persists the fully verified terminal ordering evidence for this
    /// instance. A second, byte-distinct decision is always refused.
    pub fn retain_verified_ordering_certificate(
        &self,
        certificate: &AftAsyncOrderingCertificateV1,
    ) -> Result<(), String> {
        certificate.validate_shape()?;
        if !certificate
            .decision
            .instance
            .consensus_equivalent(&self.instance)?
        {
            return Err("ordering certificate crossed its durable proposal instance".into());
        }
        persist_idempotent_canonical(&self.root.join("final-ordering.scale"), certificate)
    }

    /// Reloads the terminal ordering evidence, when one was durably accepted.
    pub fn finalized_ordering_certificate(
        &self,
    ) -> Result<Option<AftAsyncOrderingCertificateV1>, String> {
        let path = self.root.join("final-ordering.scale");
        if !path.exists() {
            return Ok(None);
        }
        let certificate = codec::from_bytes_canonical::<AftAsyncOrderingCertificateV1>(
            &read_bounded(&path, 64 * 1024 * 1024)?,
        )?;
        certificate.validate_shape()?;
        if !certificate
            .decision
            .instance
            .consensus_equivalent(&self.instance)?
        {
            return Err("stored ordering certificate crossed its durable proposal instance".into());
        }
        Ok(Some(certificate))
    }

    /// Persists the compact post-execution decision before the shared
    /// cross-path fence is entered or any local vote is signed. The selected
    /// payload witness remains content-addressed in this store and is
    /// re-derived and checked by callers on every restart.
    pub fn retain_executed_decision(
        &self,
        decision: &AftAsyncExecutedBlockDecisionV1,
        ordering: &AftAsyncOrderingCertificateV1,
        witness: &AftAsyncSelectedBatchWitnessV1,
    ) -> Result<(), String> {
        decision.validate_bindings(ordering, witness)?;
        if !decision.instance.consensus_equivalent(&self.instance)? {
            return Err("executed-block decision crossed its durable proposal instance".into());
        }
        persist_idempotent_canonical(&self.root.join("executed-decision.scale"), decision)
    }

    /// Reloads a frozen post-execution decision and rechecks all ordering and
    /// payload commitments supplied from the durable proposal store.
    pub fn executed_decision(
        &self,
        ordering: &AftAsyncOrderingCertificateV1,
        witness: &AftAsyncSelectedBatchWitnessV1,
    ) -> Result<Option<AftAsyncExecutedBlockDecisionV1>, String> {
        let path = self.root.join("executed-decision.scale");
        if !path.exists() {
            return Ok(None);
        }
        let decision = codec::from_bytes_canonical::<AftAsyncExecutedBlockDecisionV1>(
            &read_bounded(&path, 1024 * 1024)?,
        )?;
        decision.validate_bindings(ordering, witness)?;
        if !decision.instance.consensus_equivalent(&self.instance)? {
            return Err("stored executed-block decision crossed its durable instance".into());
        }
        Ok(Some(decision))
    }

    /// Persists the local executed-block vote before it can be broadcast.
    pub fn retain_local_executed_vote(
        &self,
        vote: &AftAsyncExecutedBlockVoteV1,
        decision: &AftAsyncExecutedBlockDecisionV1,
    ) -> Result<(), String> {
        vote.validate_for(decision)?;
        persist_idempotent_canonical(&self.root.join("local-executed-vote.scale"), vote)
    }

    /// Reloads and commitment-checks the local executed-block vote.
    pub fn local_executed_vote(
        &self,
        decision: &AftAsyncExecutedBlockDecisionV1,
    ) -> Result<Option<AftAsyncExecutedBlockVoteV1>, String> {
        let path = self.root.join("local-executed-vote.scale");
        if !path.exists() {
            return Ok(None);
        }
        let vote = codec::from_bytes_canonical::<AftAsyncExecutedBlockVoteV1>(&read_bounded(
            &path,
            1024 * 1024,
        )?)?;
        vote.validate_for(decision)?;
        Ok(Some(vote))
    }

    /// Persists fully verified terminal executed-block evidence before it is
    /// exposed to canonical admission. Rooted signature verification remains
    /// a caller obligation; this layer repeats every portable binding.
    pub fn retain_verified_executed_certificate(
        &self,
        certificate: &AftAsyncExecutedBlockCertificateV1,
        witness: &AftAsyncSelectedBatchWitnessV1,
    ) -> Result<(), String> {
        certificate.validate_with_witness(witness)?;
        if !certificate
            .decision
            .instance
            .consensus_equivalent(&self.instance)?
        {
            return Err("executed-block certificate crossed its durable proposal instance".into());
        }
        persist_idempotent_canonical(&self.root.join("final-executed-block.scale"), certificate)
    }

    /// Reloads terminal executed-block evidence and rechecks its external
    /// payload witness before returning it.
    pub fn finalized_executed_certificate(
        &self,
        witness: &AftAsyncSelectedBatchWitnessV1,
    ) -> Result<Option<AftAsyncExecutedBlockCertificateV1>, String> {
        let path = self.root.join("final-executed-block.scale");
        if !path.exists() {
            return Ok(None);
        }
        let maximum = u64::from(self.instance.geometry.n)
            .saturating_mul(16 * 1024 * 1024)
            .saturating_add(64 * 1024 * 1024);
        let certificate = codec::from_bytes_canonical::<AftAsyncExecutedBlockCertificateV1>(
            &read_bounded(&path, maximum)?,
        )?;
        certificate.validate_with_witness(witness)?;
        if !certificate
            .decision
            .instance
            .consensus_equivalent(&self.instance)?
        {
            return Err("stored executed-block certificate crossed its durable instance".into());
        }
        Ok(Some(certificate))
    }

    fn validate_payload(
        &self,
        descriptor: &AftAsyncProposalDescriptorV1,
        payload: &[u8],
    ) -> Result<(), String> {
        descriptor.validate_for(&self.instance)?;
        if payload.is_empty()
            || u64::try_from(payload.len()).ok() != Some(descriptor.payload_len)
            || payload.len() > AFT_ASYNC_MAX_INLINE_PROPOSAL_BYTES_V1
            || aft_async_proposal_payload_hash(payload)? != descriptor.proposal_hash
        {
            return Err(
                "AFT asynchronous proposal payload is empty, oversized, or mismatched".into(),
            );
        }
        Ok(())
    }

    fn path_for(&self, descriptor: &AftAsyncProposalDescriptorV1) -> PathBuf {
        self.root.join(format!(
            "{:05}-{}.scale",
            descriptor.proposer,
            hex::encode(descriptor.proposal_hash)
        ))
    }

    fn availability_certificate_path(&self, certificate_hash: [u8; 32]) -> PathBuf {
        self.root.join(format!(
            "availability-{}.scale",
            hex::encode(certificate_hash)
        ))
    }

    fn read(&self, path: &Path) -> Result<StoredProposalV1, String> {
        let metadata = std::fs::metadata(path)
            .map_err(|error| format!("failed to inspect {}: {error}", path.display()))?;
        if metadata.len()
            > u64::try_from(AFT_ASYNC_MAX_INLINE_PROPOSAL_BYTES_V1)
                .unwrap_or(u64::MAX)
                .saturating_add(64 * 1024)
        {
            return Err("AFT asynchronous stored proposal exceeds its byte limit".into());
        }
        let bytes = std::fs::read(path)
            .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
        let stored = codec::from_bytes_canonical::<StoredProposalV1>(&bytes)?;
        if stored.protocol_version != AFT_ASYNC_PROTOCOL_VERSION_V1
            || stored.schema_version != AFT_ASYNC_SCHEMA_VERSION_V1
        {
            return Err("unsupported stored AFT asynchronous proposal version".into());
        }
        Ok(stored)
    }
}

fn persist_idempotent_canonical<T>(path: &Path, value: &T) -> Result<(), String>
where
    T: Encode + Decode + PartialEq,
{
    let bytes = codec::to_bytes_canonical(value)?;
    if path.exists() {
        let existing = codec::from_bytes_canonical::<T>(&read_bounded(
            path,
            u64::try_from(bytes.len())
                .unwrap_or(u64::MAX)
                .saturating_add(64 * 1024),
        )?)?;
        if existing == *value {
            return Ok(());
        }
        return Err(format!(
            "AFT asynchronous evidence path {} refuses rebinding",
            path.display()
        ));
    }
    persist_atomic(path, &bytes)
}

fn read_bounded(path: &Path, maximum: u64) -> Result<Vec<u8>, String> {
    let metadata = std::fs::metadata(path)
        .map_err(|error| format!("failed to inspect {}: {error}", path.display()))?;
    if metadata.len() > maximum {
        return Err(format!(
            "AFT asynchronous evidence {} is oversized",
            path.display()
        ));
    }
    std::fs::read(path).map_err(|error| format!("failed to read {}: {error}", path.display()))
}

fn persist_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut staged = path.as_os_str().to_os_string();
    staged.push(".tmp");
    let staged = PathBuf::from(staged);
    let mut options = OpenOptions::new();
    options.create(true).write(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&staged)
        .map_err(|error| format!("failed to open {}: {error}", staged.display()))?;
    file.write_all(bytes)
        .map_err(|error| format!("failed to write {}: {error}", staged.display()))?;
    file.sync_all()
        .map_err(|error| format!("failed to sync {}: {error}", staged.display()))?;
    std::fs::rename(&staged, path)
        .map_err(|error| format!("failed to commit {}: {error}", path.display()))?;
    sync_directory(
        path.parent()
            .ok_or_else(|| "AFT asynchronous proposal path lacks a parent".to_string())?,
    )
}

fn sync_directory(path: &Path) -> Result<(), String> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("failed to sync {}: {error}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aft::hash_async::node::tests_support::test_instance;

    #[test]
    fn retain_is_durable_idempotent_and_commitment_checked() {
        let directory = tempfile::tempdir().unwrap();
        let instance = test_instance();
        let store = DurableAsyncProposalStore::open(directory.path(), instance.clone()).unwrap();
        let payload = b"immutable fallback proposal";
        let descriptor = store
            .retain_local(0, instance.locked_root, payload)
            .unwrap();
        store.retain(&descriptor, payload).unwrap();
        assert_eq!(store.load(&descriptor).unwrap(), payload);

        let mut rebound = descriptor.clone();
        rebound.payload_len += 1;
        assert!(store.retain(&rebound, payload).is_err());
        let mut corrupt = payload.to_vec();
        corrupt[0] ^= 1;
        assert!(store.retain(&descriptor, &corrupt).is_err());
    }

    #[test]
    fn restart_revalidates_storage_corruption() {
        let directory = tempfile::tempdir().unwrap();
        let instance = test_instance();
        let store = DurableAsyncProposalStore::open(directory.path(), instance.clone()).unwrap();
        let descriptor = store
            .retain_local(1, instance.locked_root, b"payload")
            .unwrap();
        let path = store.path_for(&descriptor);
        let mut bytes = std::fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        std::fs::write(path, bytes).unwrap();
        let reopened = DurableAsyncProposalStore::open(directory.path(), instance).unwrap();
        assert!(reopened.load(&descriptor).is_err());
    }
}
