use super::SlhDsaSealKeyPair;
use dcrypt::algorithms::hash::{HashFunction, Sha256};
use fs2::FileExt;
use ioi_crypto::key_store::{decrypt_key, encrypt_key};
use ioi_types::app::consensus::{
    seal_key_exhaustion_commitment, SealKeyBindingV1, SealKeyManifestEntryV1, SealKeyScopeV1,
};
use ioi_types::app::SignatureSuite;
use parity_scale_codec::{Decode, Encode};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const SIGNER_STATE_SCHEMA_V1: u16 = 1;
const ANCHOR_SCHEMA_V1: u16 = 1;
const STATE_COMMITMENT_DOMAIN: &[u8] = b"ioi.aft.seal-signer-state.v1\0";
const SCOPE_COMMITMENT_DOMAIN: &[u8] = b"ioi.aft.seal-signer-scope.v1\0";

fn hash_domain(domain: &[u8], payload: &[u8]) -> Result<[u8; 32], String> {
    let mut material = Vec::with_capacity(domain.len() + payload.len());
    material.extend_from_slice(domain);
    material.extend_from_slice(payload);
    let digest = Sha256::digest(&material).map_err(|error| format!("{error:?}"))?;
    material.zeroize();
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_ref());
    Ok(out)
}

fn scope_commitment(scope: &SealKeyScopeV1) -> Result<[u8; 32], String> {
    hash_domain(SCOPE_COMMITMENT_DOMAIN, &scope.encode())
}

#[derive(Debug, Encode, Decode, Zeroize, ZeroizeOnDrop)]
struct ScheduledSealSecretV1 {
    #[zeroize(skip)]
    binding: SealKeyBindingV1,
    secret_key: Vec<u8>,
}

#[derive(Debug, Encode, Decode, Zeroize, ZeroizeOnDrop)]
struct PersistedSealSignerStateV1 {
    #[zeroize(skip)]
    schema_version: u16,
    #[zeroize(skip)]
    manifest_commitment: [u8; 32],
    #[zeroize(skip)]
    custody_instance_id: [u8; 32],
    #[zeroize(skip)]
    generation: u64,
    keys: Vec<ScheduledSealSecretV1>,
}

impl PersistedSealSignerStateV1 {
    fn validate(&self) -> Result<(), String> {
        if self.schema_version != SIGNER_STATE_SCHEMA_V1 {
            return Err(format!(
                "unsupported seal signer state version {}",
                self.schema_version
            ));
        }
        let Some(first) = self.keys.first() else {
            return Ok(());
        };
        if first.binding.key_index != self.generation {
            return Err("seal signer generation does not match the current key index".into());
        }
        let scope = &first.binding.scope;
        let mut prior_commitment = first.binding.predecessor_key_commitment;
        for (offset, scheduled) in self.keys.iter().enumerate() {
            scheduled.binding.validate()?;
            if &scheduled.binding.scope != scope {
                return Err("seal signer schedule crosses an authorization scope".into());
            }
            if scheduled.binding.key_index != self.generation + offset as u64 {
                return Err("seal signer key schedule is not contiguous".into());
            }
            if scheduled.binding.predecessor_key_commitment != prior_commitment {
                return Err("seal signer key predecessor chain is invalid".into());
            }
            let key = SlhDsaSealKeyPair::from_secret_key_bytes(&scheduled.secret_key)?;
            if key.public_key_bytes() != scheduled.binding.public_key {
                return Err("seal signer secret does not match its scheduled public key".into());
            }
            prior_commitment = scheduled.binding.commitment()?;
        }
        Ok(())
    }

    fn commitment(&self) -> Result<[u8; 32], String> {
        self.validate()?;
        hash_domain(STATE_COMMITMENT_DOMAIN, &self.encode())
    }

    fn advanced(&self) -> Result<Self, String> {
        if self.keys.is_empty() {
            return Err("terminal seal key schedule is exhausted".into());
        }
        let encoded = Zeroizing::new(self.encode());
        let mut cloned = Self::decode(&mut encoded.as_slice())
            .map_err(|_| "failed to clone seal signer state canonically".to_string())?;
        cloned.keys.remove(0);
        cloned.generation = cloned
            .generation
            .checked_add(1)
            .ok_or_else(|| "seal signer generation overflow".to_string())?;
        cloned.validate()?;
        Ok(cloned)
    }

    fn next_key_commitment(&self) -> Result<[u8; 32], String> {
        let current = self
            .keys
            .first()
            .ok_or_else(|| "terminal seal key schedule is exhausted".to_string())?;
        if let Some(next) = self.keys.get(1) {
            next.binding.commitment()
        } else {
            seal_key_exhaustion_commitment(&current.binding.scope, current.binding.key_index)
        }
    }
}

/// Durable external compare-and-swap record. The predecessor permits safe
/// recovery when the anchor commit succeeded but the encrypted signer-state
/// replacement did not.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct SealStateAnchorRecordV1 {
    /// Anchor schema version.
    pub schema_version: u16,
    /// Exact signer authorization-scope commitment.
    pub scope_commitment: [u8; 32],
    /// Platform/custody identity that owns this single-writer state.
    pub custody_instance_id: [u8; 32],
    /// Consumed-key generation.
    pub generation: u64,
    /// State commitment before this reservation.
    pub predecessor_state_commitment: [u8; 32],
    /// Current encrypted-state plaintext commitment.
    pub state_commitment: [u8; 32],
}

/// Compare-and-swap anchor kept outside the clonable encrypted signer blob.
pub trait SealStateAnchor: Send {
    /// Loads the current anchor record.
    fn load(&self) -> Result<Option<SealStateAnchorRecordV1>, String>;
    /// Creates the anchor exactly once.
    fn initialize(&self, initial: &SealStateAnchorRecordV1) -> Result<(), String>;
    /// Replaces `expected` with `next` atomically or refuses on any mismatch.
    fn compare_and_swap(
        &self,
        expected: &SealStateAnchorRecordV1,
        next: &SealStateAnchorRecordV1,
    ) -> Result<(), String>;
}

/// Single-writer anchor backed by a strongly consistent shared filesystem.
///
/// The lock is held for this object's lifetime. The anchor directory must be
/// external to signer snapshots; copying it with the signer defeats the clone
/// boundary and is not a production profile.
pub struct SharedFileSealStateAnchor {
    record_path: PathBuf,
    _lifetime_lock: File,
}

impl SharedFileSealStateAnchor {
    /// Acquires the exclusive lifetime lock for one signer scope.
    pub fn acquire(root: impl AsRef<Path>, scope: &SealKeyScopeV1) -> Result<Self, String> {
        std::fs::create_dir_all(root.as_ref())
            .map_err(|error| format!("create seal anchor directory: {error}"))?;
        let scope_hash = scope_commitment(scope)?;
        let stem = hex::encode(scope_hash);
        let lock_path = root.as_ref().join(format!("{stem}.lock"));
        let record_path = root.as_ref().join(format!("{stem}.anchor"));
        let lock = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(&lock_path)
            .map_err(|error| format!("open seal anchor lock: {error}"))?;
        lock.try_lock_exclusive()
            .map_err(|_| "another seal signer instance already owns this scope".to_string())?;
        Ok(Self {
            record_path,
            _lifetime_lock: lock,
        })
    }

    fn read_record(&self) -> Result<Option<SealStateAnchorRecordV1>, String> {
        let bytes = match std::fs::read(&self.record_path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(format!("read seal state anchor: {error}")),
        };
        SealStateAnchorRecordV1::decode(&mut bytes.as_slice())
            .map(Some)
            .map_err(|_| "decode seal state anchor".to_string())
    }
}

impl SealStateAnchor for SharedFileSealStateAnchor {
    fn load(&self) -> Result<Option<SealStateAnchorRecordV1>, String> {
        self.read_record()
    }

    fn initialize(&self, initial: &SealStateAnchorRecordV1) -> Result<(), String> {
        if self.read_record()?.is_some() {
            return Err("seal state anchor is already initialized".into());
        }
        atomic_write(&self.record_path, &initial.encode())
    }

    fn compare_and_swap(
        &self,
        expected: &SealStateAnchorRecordV1,
        next: &SealStateAnchorRecordV1,
    ) -> Result<(), String> {
        let current = self
            .read_record()?
            .ok_or_else(|| "seal state anchor is not initialized".to_string())?;
        if &current != expected {
            return Err("seal state anchor compare-and-swap mismatch".into());
        }
        if next.schema_version != ANCHOR_SCHEMA_V1
            || next.scope_commitment != expected.scope_commitment
            || next.custody_instance_id != expected.custody_instance_id
            || next.generation != expected.generation + 1
            || next.predecessor_state_commitment != expected.state_commitment
        {
            return Err("invalid successor seal state anchor".into());
        }
        atomic_write(&self.record_path, &next.encode())
    }
}

/// Advance-before-sign v2 terminal signer.
pub struct DurableSealSignerV2<A: SealStateAnchor> {
    state_path: PathBuf,
    passphrase: Zeroizing<String>,
    custody_instance_id: [u8; 32],
    anchor: A,
}

impl<A: SealStateAnchor> DurableSealSignerV2<A> {
    /// Provisions a finite per-slot key schedule and returns the initial entry
    /// that configuration enrollment must authenticate.
    pub fn provision(
        state_path: impl AsRef<Path>,
        passphrase: String,
        custody_instance_id: [u8; 32],
        scope: SealKeyScopeV1,
        initial_chain_anchor: [u8; 32],
        manifest_commitment: [u8; 32],
        key_count: usize,
        anchor: A,
    ) -> Result<(Self, SealKeyManifestEntryV1), String> {
        if key_count == 0 {
            return Err("terminal seal key schedule must contain at least one key".into());
        }
        let keys = (0..key_count)
            .map(|_| SlhDsaSealKeyPair::generate())
            .collect::<Vec<_>>();
        Self::provision_with_keys(
            state_path,
            passphrase,
            custody_instance_id,
            scope,
            initial_chain_anchor,
            manifest_commitment,
            keys,
            anchor,
        )
    }

    fn provision_with_keys(
        state_path: impl AsRef<Path>,
        passphrase: String,
        custody_instance_id: [u8; 32],
        scope: SealKeyScopeV1,
        initial_chain_anchor: [u8; 32],
        manifest_commitment: [u8; 32],
        keys: Vec<SlhDsaSealKeyPair>,
        anchor: A,
    ) -> Result<(Self, SealKeyManifestEntryV1), String> {
        if keys.is_empty() {
            return Err("terminal seal key schedule must contain at least one key".into());
        }
        if state_path.as_ref().exists() {
            return Err("seal signer state already exists".into());
        }

        let mut predecessor = initial_chain_anchor;
        let mut scheduled = Vec::with_capacity(keys.len());
        for (key_index, key) in keys.into_iter().enumerate() {
            let binding = SealKeyBindingV1 {
                scope: scope.clone(),
                key_index: key_index as u64,
                signature_suite: SignatureSuite::SLH_DSA_SHA2_128S,
                public_key: key.public_key_bytes(),
                predecessor_key_commitment: predecessor,
            };
            predecessor = binding.commitment()?;
            scheduled.push(ScheduledSealSecretV1 {
                binding,
                secret_key: key.secret_key_bytes().to_vec(),
            });
        }
        let initial_binding = scheduled[0].binding.clone();
        let initial_key_commitment = initial_binding.commitment()?;
        let state = PersistedSealSignerStateV1 {
            schema_version: SIGNER_STATE_SCHEMA_V1,
            manifest_commitment,
            custody_instance_id,
            generation: 0,
            keys: scheduled,
        };
        state.validate()?;
        let state_commitment = state.commitment()?;
        save_encrypted_state(state_path.as_ref(), &passphrase, &state)?;
        let initial_anchor = SealStateAnchorRecordV1 {
            schema_version: ANCHOR_SCHEMA_V1,
            scope_commitment: scope_commitment(&scope)?,
            custody_instance_id,
            generation: 0,
            predecessor_state_commitment: [0u8; 32],
            state_commitment,
        };
        anchor.initialize(&initial_anchor)?;
        Ok((
            Self {
                state_path: state_path.as_ref().to_path_buf(),
                passphrase: Zeroizing::new(passphrase),
                custody_instance_id,
                anchor,
            },
            SealKeyManifestEntryV1 {
                initial_key: initial_binding,
                initial_key_commitment,
            },
        ))
    }

    /// Opens existing state and completes a crash-interrupted reservation.
    /// Returns the burned key index, if recovery had to advance the local
    /// encrypted state to an already-committed anchor.
    pub fn open(
        state_path: impl AsRef<Path>,
        passphrase: String,
        custody_instance_id: [u8; 32],
        anchor: A,
    ) -> Result<(Self, Option<u64>), String> {
        let signer = Self {
            state_path: state_path.as_ref().to_path_buf(),
            passphrase: Zeroizing::new(passphrase),
            custody_instance_id,
            anchor,
        };
        let burned = signer.recover_if_needed()?;
        Ok((signer, burned))
    }

    fn load_state(&self) -> Result<PersistedSealSignerStateV1, String> {
        let encrypted = std::fs::read(&self.state_path)
            .map_err(|error| format!("read encrypted seal signer state: {error}"))?;
        let decrypted = decrypt_key(&encrypted, &self.passphrase)
            .map_err(|error| format!("decrypt seal signer state: {error}"))?;
        let state = PersistedSealSignerStateV1::decode(&mut decrypted.0.as_slice())
            .map_err(|_| "decode seal signer state".to_string())?;
        state.validate()?;
        if state.custody_instance_id != self.custody_instance_id {
            return Err("seal signer custody-instance mismatch".into());
        }
        Ok(state)
    }

    fn recover_if_needed(&self) -> Result<Option<u64>, String> {
        let state = self.load_state()?;
        let state_commitment = state.commitment()?;
        let anchor = self
            .anchor
            .load()?
            .ok_or_else(|| "seal state anchor is missing".to_string())?;
        if anchor.custody_instance_id != self.custody_instance_id {
            return Err("seal state anchor custody-instance mismatch".into());
        }
        if anchor.state_commitment == state_commitment && anchor.generation == state.generation {
            return Ok(None);
        }
        if anchor.generation == state.generation + 1
            && anchor.predecessor_state_commitment == state_commitment
        {
            let burned = state.generation;
            let advanced = state.advanced()?;
            if advanced.commitment()? != anchor.state_commitment {
                return Err("seal state recovery commitment mismatch".into());
            }
            save_encrypted_state(&self.state_path, &self.passphrase, &advanced)?;
            return Ok(Some(burned));
        }
        Err("seal signer rollback or detached clone detected".into())
    }

    /// Atomically reserves the current key in the external anchor and local
    /// encrypted state before producing a signature.
    pub fn sign(
        &self,
        seal_root: [u8; 32],
    ) -> Result<ioi_types::app::consensus::SealShareV2, String> {
        if self.recover_if_needed()?.is_some() {
            return Err(
                "a crash-recovered seal slot was burned; retry explicitly at the next slot".into(),
            );
        }
        let state = self.load_state()?;
        let current = state
            .keys
            .first()
            .ok_or_else(|| "terminal seal key schedule is exhausted".to_string())?;
        let current_key = SlhDsaSealKeyPair::from_secret_key_bytes(&current.secret_key)?;
        let current_binding = current.binding.clone();
        let next_key_commitment = state.next_key_commitment()?;
        let current_state_commitment = state.commitment()?;
        let current_anchor = self
            .anchor
            .load()?
            .ok_or_else(|| "seal state anchor is missing".to_string())?;
        if current_anchor.state_commitment != current_state_commitment
            || current_anchor.generation != state.generation
        {
            return Err("seal signer state changed before reservation".into());
        }
        let advanced = state.advanced()?;
        let next_anchor = SealStateAnchorRecordV1 {
            schema_version: ANCHOR_SCHEMA_V1,
            scope_commitment: current_anchor.scope_commitment,
            custody_instance_id: self.custody_instance_id,
            generation: current_anchor.generation + 1,
            predecessor_state_commitment: current_state_commitment,
            state_commitment: advanced.commitment()?,
        };
        self.anchor
            .compare_and_swap(&current_anchor, &next_anchor)?;
        save_encrypted_state(&self.state_path, &self.passphrase, &advanced)?;
        current_key.sign_share(
            current_binding.clone(),
            current_binding.key_index,
            seal_root,
            next_key_commitment,
        )
    }

    #[cfg(test)]
    fn reserve_without_local_commit_for_test(&self) -> Result<u64, String> {
        let state = self.load_state()?;
        let current_commitment = state.commitment()?;
        let current_anchor = self.anchor.load()?.ok_or("missing anchor")?;
        let advanced = state.advanced()?;
        let next_anchor = SealStateAnchorRecordV1 {
            schema_version: ANCHOR_SCHEMA_V1,
            scope_commitment: current_anchor.scope_commitment,
            custody_instance_id: self.custody_instance_id,
            generation: current_anchor.generation + 1,
            predecessor_state_commitment: current_commitment,
            state_commitment: advanced.commitment()?,
        };
        self.anchor
            .compare_and_swap(&current_anchor, &next_anchor)?;
        Ok(state.generation)
    }

    #[cfg(test)]
    fn reserve_with_local_commit_without_sign_for_test(&self) -> Result<u64, String> {
        let state = self.load_state()?;
        let current_commitment = state.commitment()?;
        let current_anchor = self.anchor.load()?.ok_or("missing anchor")?;
        let advanced = state.advanced()?;
        let next_anchor = SealStateAnchorRecordV1 {
            schema_version: ANCHOR_SCHEMA_V1,
            scope_commitment: current_anchor.scope_commitment,
            custody_instance_id: self.custody_instance_id,
            generation: current_anchor.generation + 1,
            predecessor_state_commitment: current_commitment,
            state_commitment: advanced.commitment()?,
        };
        self.anchor
            .compare_and_swap(&current_anchor, &next_anchor)?;
        save_encrypted_state(&self.state_path, &self.passphrase, &advanced)?;
        Ok(state.generation)
    }
}

fn save_encrypted_state(
    path: &Path,
    passphrase: &str,
    state: &PersistedSealSignerStateV1,
) -> Result<(), String> {
    let mut plaintext = Zeroizing::new(state.encode());
    let encrypted = encrypt_key(&plaintext, passphrase)
        .map_err(|error| format!("encrypt seal signer state: {error}"))?;
    plaintext.zeroize();
    atomic_write(path, &encrypted)
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "seal state path has no parent".to_string())?;
    std::fs::create_dir_all(parent)
        .map_err(|error| format!("create seal state directory: {error}"))?;
    let file_name = path
        .file_name()
        .ok_or_else(|| "seal state path has no file name".to_string())?
        .to_string_lossy();
    let temp = parent.join(format!(".{file_name}.tmp.{}", std::process::id()));
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temp)
        .map_err(|error| format!("open temporary seal state: {error}"))?;
    file.write_all(bytes)
        .map_err(|error| format!("write temporary seal state: {error}"))?;
    file.sync_all()
        .map_err(|error| format!("fsync temporary seal state: {error}"))?;
    std::fs::rename(&temp, path).map_err(|error| format!("replace seal state: {error}"))?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("fsync seal state directory: {error}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ioi_types::app::AccountId;

    fn scope() -> SealKeyScopeV1 {
        SealKeyScopeV1 {
            network_id: [1; 32],
            configuration_id: [2; 32],
            epoch: 3,
            conflict_domain_id: [4; 32],
            member_id: AccountId([5; 32]),
            member_index: 0,
        }
    }

    fn deterministic_keys(count: usize) -> Vec<SlhDsaSealKeyPair> {
        (0..count)
            .map(|index| {
                let byte = index as u8 * 3;
                SlhDsaSealKeyPair::from_seed_material(
                    [byte + 1; 16],
                    [byte + 2; 16],
                    [byte + 3; 16],
                )
            })
            .collect()
    }

    #[test]
    fn advance_before_sign_survives_restart_and_exhausts_closed() {
        let temp = tempfile::tempdir().unwrap();
        let state_path = temp.path().join("signer.state");
        let anchor_root = temp.path().join("external-anchor");
        let anchor = SharedFileSealStateAnchor::acquire(&anchor_root, &scope()).unwrap();
        let (signer, enrollment) = DurableSealSignerV2::provision_with_keys(
            &state_path,
            "test passphrase".into(),
            [8; 32],
            scope(),
            [9; 32],
            [10; 32],
            deterministic_keys(2),
            anchor,
        )
        .unwrap();
        let first = signer.sign([0xAA; 32]).unwrap();
        super::super::verify_seal_share_v2(&first, enrollment.initial_key_commitment).unwrap();
        drop(signer);

        let anchor = SharedFileSealStateAnchor::acquire(&anchor_root, &scope()).unwrap();
        let (signer, burned) =
            DurableSealSignerV2::open(&state_path, "test passphrase".into(), [8; 32], anchor)
                .unwrap();
        assert_eq!(burned, None);
        let second = signer.sign([0xBB; 32]).unwrap();
        super::super::verify_seal_share_v2(&second, first.next_key_commitment).unwrap();
        assert!(signer.sign([0xCC; 32]).is_err());
    }

    #[test]
    fn crash_after_anchor_reservation_burns_slot_without_reuse() {
        let temp = tempfile::tempdir().unwrap();
        let state_path = temp.path().join("signer.state");
        let anchor_root = temp.path().join("external-anchor");
        let anchor = SharedFileSealStateAnchor::acquire(&anchor_root, &scope()).unwrap();
        let (signer, _) = DurableSealSignerV2::provision_with_keys(
            &state_path,
            "test passphrase".into(),
            [8; 32],
            scope(),
            [9; 32],
            [10; 32],
            deterministic_keys(2),
            anchor,
        )
        .unwrap();
        assert_eq!(signer.reserve_without_local_commit_for_test().unwrap(), 0);
        drop(signer);

        let anchor = SharedFileSealStateAnchor::acquire(&anchor_root, &scope()).unwrap();
        let (signer, burned) =
            DurableSealSignerV2::open(&state_path, "test passphrase".into(), [8; 32], anchor)
                .unwrap();
        assert_eq!(burned, Some(0));
        let next = signer.sign([0xBB; 32]).unwrap();
        assert_eq!(next.seal_slot, 1);
    }

    #[test]
    fn concurrent_clone_and_wrong_custody_identity_are_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let state_path = temp.path().join("signer.state");
        let anchor_root = temp.path().join("external-anchor");
        let anchor = SharedFileSealStateAnchor::acquire(&anchor_root, &scope()).unwrap();
        let (signer, _) = DurableSealSignerV2::provision_with_keys(
            &state_path,
            "test passphrase".into(),
            [8; 32],
            scope(),
            [9; 32],
            [10; 32],
            deterministic_keys(1),
            anchor,
        )
        .unwrap();
        assert!(SharedFileSealStateAnchor::acquire(&anchor_root, &scope()).is_err());
        drop(signer);

        let anchor = SharedFileSealStateAnchor::acquire(&anchor_root, &scope()).unwrap();
        assert!(
            DurableSealSignerV2::open(&state_path, "test passphrase".into(), [7; 32], anchor)
                .is_err()
        );
    }

    #[test]
    fn crash_after_local_commit_does_not_reuse_reserved_slot() {
        let temp = tempfile::tempdir().unwrap();
        let state_path = temp.path().join("signer.state");
        let anchor_root = temp.path().join("external-anchor");
        let anchor = SharedFileSealStateAnchor::acquire(&anchor_root, &scope()).unwrap();
        let (signer, _) = DurableSealSignerV2::provision_with_keys(
            &state_path,
            "test passphrase".into(),
            [8; 32],
            scope(),
            [9; 32],
            [10; 32],
            deterministic_keys(2),
            anchor,
        )
        .unwrap();
        assert!(std::fs::read(&state_path).unwrap().starts_with(b"IOI-GKEY"));
        assert_eq!(
            signer
                .reserve_with_local_commit_without_sign_for_test()
                .unwrap(),
            0
        );
        drop(signer);

        let anchor = SharedFileSealStateAnchor::acquire(&anchor_root, &scope()).unwrap();
        let (signer, burned) =
            DurableSealSignerV2::open(&state_path, "test passphrase".into(), [8; 32], anchor)
                .unwrap();
        assert_eq!(burned, None);
        let next = signer.sign([0xBB; 32]).unwrap();
        assert_eq!(next.seal_slot, 1);
    }

    #[test]
    fn rollback_beyond_one_recoverable_reservation_fails_closed() {
        let temp = tempfile::tempdir().unwrap();
        let state_path = temp.path().join("signer.state");
        let anchor_root = temp.path().join("external-anchor");
        let anchor = SharedFileSealStateAnchor::acquire(&anchor_root, &scope()).unwrap();
        let (signer, _) = DurableSealSignerV2::provision_with_keys(
            &state_path,
            "test passphrase".into(),
            [8; 32],
            scope(),
            [9; 32],
            [10; 32],
            deterministic_keys(3),
            anchor,
        )
        .unwrap();
        let stale_snapshot = std::fs::read(&state_path).unwrap();
        signer
            .reserve_with_local_commit_without_sign_for_test()
            .unwrap();
        signer
            .reserve_with_local_commit_without_sign_for_test()
            .unwrap();
        std::fs::write(&state_path, stale_snapshot).unwrap();
        drop(signer);

        let anchor = SharedFileSealStateAnchor::acquire(&anchor_root, &scope()).unwrap();
        assert!(
            DurableSealSignerV2::open(&state_path, "test passphrase".into(), [8; 32], anchor)
                .is_err()
        );
    }
}
