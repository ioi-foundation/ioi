use super::CrossPathDecision;
use fs2::FileExt;
use ioi_types::app::{AccountId, AftFallbackScopeV1};
use ioi_types::codec;
use parity_scale_codec::{Decode, Encode};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

const FENCE_VERSION_V1: u16 = 1;
const FENCE_KEY_DOMAIN_V1: &[u8] = b"ioi/aft/cross-path-signing-fence-key/v1";
const FENCE_STATE_DOMAIN_V1: &[u8] = b"ioi/aft/cross-path-signing-fence-state/v1";
const FENCE_ANCHOR_DOMAIN_V1: &[u8] = b"ioi/aft/cross-path-signing-fence-anchor/v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
enum PersistedDecisionPathV1 {
    Optimistic,
    HashAsync,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
struct PersistedDecisionV1 {
    path: PersistedDecisionPathV1,
    root: [u8; 32],
}

impl From<CrossPathDecision> for PersistedDecisionV1 {
    fn from(value: CrossPathDecision) -> Self {
        match value {
            CrossPathDecision::Optimistic(root) => Self {
                path: PersistedDecisionPathV1::Optimistic,
                root,
            },
            CrossPathDecision::HashAsync(root) => Self {
                path: PersistedDecisionPathV1::HashAsync,
                root,
            },
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
struct FenceStateV1 {
    version: u16,
    scope: AftFallbackScopeV1,
    member: AccountId,
    generation: u64,
    decisions: BTreeMap<u64, PersistedDecisionV1>,
    authentication_tag: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
struct FenceAnchorV1 {
    version: u16,
    scope: AftFallbackScopeV1,
    member: AccountId,
    generation: u64,
    state_hash: [u8; 32],
    authentication_tag: [u8; 32],
}

/// Rollback- and clone-detecting signer fence shared by optimistic and
/// hash-asynchronous decision paths. Authorization is persisted before it is
/// returned to a signing caller. `anchor_path` must be held outside clonable
/// node snapshots.
pub struct DurableCrossPathSigningFence {
    state_path: PathBuf,
    anchor_path: PathBuf,
    _anchor_lock: File,
    key: [u8; 32],
    state: FenceStateV1,
}

impl std::fmt::Debug for DurableCrossPathSigningFence {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DurableCrossPathSigningFence")
            .field("state_path", &self.state_path)
            .field("anchor_path", &self.anchor_path)
            .field("generation", &self.state.generation)
            .field("decisions", &self.state.decisions.len())
            .field("key", &"<redacted>")
            .finish()
    }
}

impl Drop for DurableCrossPathSigningFence {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl DurableCrossPathSigningFence {
    /// Opens or initializes one configuration/member fence.
    pub fn open(
        state_path: &Path,
        anchor_path: &Path,
        scope: AftFallbackScopeV1,
        member: AccountId,
        custody_key: &[u8; 32],
    ) -> Result<Self, String> {
        scope.validate()?;
        if *custody_key == [0; 32] {
            return Err("cross-path signing fence refuses an empty custody key".into());
        }
        create_parent(state_path)?;
        create_parent(anchor_path)?;
        let lock_path = suffixed(anchor_path, ".lock");
        let anchor_lock = open_private(&lock_path, false)?;
        anchor_lock.try_lock_exclusive().map_err(|error| {
            format!(
                "cross-path signing-fence anchor {} is already owned: {error}",
                anchor_path.display()
            )
        })?;
        let key = derive_key(custody_key, scope, member)?;
        let state_exists = state_path.exists();
        let anchor_exists = anchor_path.exists();
        if state_exists != anchor_exists {
            return Err("cross-path signing-fence state/anchor presence differs".into());
        }
        let state = if state_exists {
            let state = read_state(state_path)?;
            validate_state(&state, scope, member, &key)?;
            let anchor = read_anchor(anchor_path)?;
            validate_anchor(&anchor, &state, &key)?;
            if anchor.generation > state.generation {
                return Err("cross-path signing-fence rollback detected".into());
            }
            if state.generation > anchor.generation.saturating_add(1) {
                return Err("cross-path signing-fence generation gap is invalid".into());
            }
            state
        } else {
            let mut state = FenceStateV1 {
                version: FENCE_VERSION_V1,
                scope,
                member,
                generation: 0,
                decisions: BTreeMap::new(),
                authentication_tag: [0; 32],
            };
            state.authentication_tag = state_tag(&key, &state)?;
            state
        };
        let fence = Self {
            state_path: state_path.to_path_buf(),
            anchor_path: anchor_path.to_path_buf(),
            _anchor_lock: anchor_lock,
            key,
            state,
        };
        if !state_exists {
            fence.persist_state()?;
            fence.persist_anchor()?;
        } else {
            let anchor = read_anchor(anchor_path)?;
            if fence.state.generation == anchor.generation.saturating_add(1) {
                fence.persist_anchor()?;
            }
        }
        Ok(fence)
    }

    /// Persists first authorization and refuses every later root conflict,
    /// regardless of which path asks. Same-root replay is idempotent.
    pub fn authorize(&mut self, height: u64, decision: CrossPathDecision) -> Result<bool, String> {
        let decision = PersistedDecisionV1::from(decision);
        if height == 0 || decision.root == [0; 32] {
            return Err("cross-path signing fence refuses an empty height/root".into());
        }
        match self.state.decisions.get(&height) {
            Some(previous) if previous.root == decision.root => return Ok(false),
            Some(_) => return Err("cross-path signing fence refuses a conflicting root".into()),
            None => {}
        }
        self.state.decisions.insert(height, decision);
        self.state.generation = self
            .state
            .generation
            .checked_add(1)
            .ok_or_else(|| "cross-path signing-fence generation exhausted".to_string())?;
        self.state.authentication_tag = state_tag(&self.key, &self.state)?;
        self.persist_state()?;
        self.persist_anchor()?;
        Ok(true)
    }

    fn persist_state(&self) -> Result<(), String> {
        persist_atomic(&self.state_path, &codec::to_bytes_canonical(&self.state)?)
    }

    fn persist_anchor(&self) -> Result<(), String> {
        let state_hash = state_hash(&self.state)?;
        let mut anchor = FenceAnchorV1 {
            version: FENCE_VERSION_V1,
            scope: self.state.scope,
            member: self.state.member,
            generation: self.state.generation,
            state_hash,
            authentication_tag: [0; 32],
        };
        anchor.authentication_tag = anchor_tag(&self.key, &anchor)?;
        persist_atomic(&self.anchor_path, &codec::to_bytes_canonical(&anchor)?)
    }
}

fn derive_key(
    custody_key: &[u8; 32],
    scope: AftFallbackScopeV1,
    member: AccountId,
) -> Result<[u8; 32], String> {
    hash(&codec::to_bytes_canonical(&(
        FENCE_KEY_DOMAIN_V1.to_vec(),
        custody_key,
        scope,
        member,
    ))?)
}

fn state_hash(state: &FenceStateV1) -> Result<[u8; 32], String> {
    hash(&codec::to_bytes_canonical(&(
        FENCE_STATE_DOMAIN_V1.to_vec(),
        state,
    ))?)
}

fn state_tag(key: &[u8; 32], state: &FenceStateV1) -> Result<[u8; 32], String> {
    hash(&codec::to_bytes_canonical(&(
        FENCE_STATE_DOMAIN_V1.to_vec(),
        key,
        state.version,
        state.scope,
        state.member,
        state.generation,
        &state.decisions,
    ))?)
}

fn anchor_tag(key: &[u8; 32], anchor: &FenceAnchorV1) -> Result<[u8; 32], String> {
    hash(&codec::to_bytes_canonical(&(
        FENCE_ANCHOR_DOMAIN_V1.to_vec(),
        key,
        anchor.version,
        anchor.scope,
        anchor.member,
        anchor.generation,
        anchor.state_hash,
    ))?)
}

fn hash(bytes: &[u8]) -> Result<[u8; 32], String> {
    ioi_crypto::algorithms::hash::sha256(bytes).map_err(|error| error.to_string())
}

fn validate_state(
    state: &FenceStateV1,
    scope: AftFallbackScopeV1,
    member: AccountId,
    key: &[u8; 32],
) -> Result<(), String> {
    if state.version != FENCE_VERSION_V1
        || state.scope != scope
        || state.member != member
        || state.authentication_tag != state_tag(key, state)?
    {
        return Err("cross-path signing-fence state is invalid or out of scope".into());
    }
    if state
        .decisions
        .iter()
        .any(|(height, decision)| *height == 0 || decision.root == [0; 32])
    {
        return Err("cross-path signing-fence state contains an invalid decision".into());
    }
    Ok(())
}

fn validate_anchor(
    anchor: &FenceAnchorV1,
    state: &FenceStateV1,
    key: &[u8; 32],
) -> Result<(), String> {
    if anchor.version != FENCE_VERSION_V1
        || anchor.scope != state.scope
        || anchor.member != state.member
        || anchor.authentication_tag != anchor_tag(key, anchor)?
    {
        return Err("cross-path signing-fence anchor authentication failed".into());
    }
    if anchor.generation == state.generation && anchor.state_hash != state_hash(state)? {
        return Err("cross-path signing-fence state hash does not match its anchor".into());
    }
    Ok(())
}

fn read_state(path: &Path) -> Result<FenceStateV1, String> {
    codec::from_bytes_canonical(
        &std::fs::read(path)
            .map_err(|error| format!("failed to read {}: {error}", path.display()))?,
    )
}

fn read_anchor(path: &Path) -> Result<FenceAnchorV1, String> {
    codec::from_bytes_canonical(
        &std::fs::read(path)
            .map_err(|error| format!("failed to read {}: {error}", path.display()))?,
    )
}

fn create_parent(path: &Path) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "cross-path signing-fence path requires a parent".to_string())?;
    std::fs::create_dir_all(parent)
        .map_err(|error| format!("failed to create {}: {error}", parent.display()))
}

fn open_private(path: &Path, truncate: bool) -> Result<File, String> {
    let mut options = OpenOptions::new();
    options
        .create(true)
        .read(true)
        .write(true)
        .truncate(truncate);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(path)
        .map_err(|error| format!("failed to open {}: {error}", path.display()))
}

fn persist_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let staged = suffixed(path, ".tmp");
    let mut file = open_private(&staged, true)?;
    file.write_all(bytes)
        .map_err(|error| format!("failed to write {}: {error}", staged.display()))?;
    file.sync_all()
        .map_err(|error| format!("failed to sync {}: {error}", staged.display()))?;
    std::fs::rename(&staged, path)
        .map_err(|error| format!("failed to commit {}: {error}", path.display()))?;
    if let Some(parent) = path.parent() {
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| format!("failed to sync {}: {error}", parent.display()))?;
    }
    Ok(())
}

fn suffixed(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope() -> AftFallbackScopeV1 {
        AftFallbackScopeV1 {
            network_id: [1; 32],
            configuration_hash: [2; 32],
            epoch: 3,
        }
    }

    #[test]
    fn durable_fence_survives_restart_and_refuses_cross_path_conflict() {
        let directory = tempfile::tempdir().unwrap();
        let state = directory.path().join("node/fence.scale");
        let anchor = directory.path().join("external/fence.anchor");
        let key = [8; 32];
        let member = AccountId([9; 32]);
        let mut fence =
            DurableCrossPathSigningFence::open(&state, &anchor, scope(), member, &key).unwrap();
        assert!(fence
            .authorize(7, CrossPathDecision::Optimistic([10; 32]))
            .unwrap());
        drop(fence);
        let mut fence =
            DurableCrossPathSigningFence::open(&state, &anchor, scope(), member, &key).unwrap();
        assert!(!fence
            .authorize(7, CrossPathDecision::HashAsync([10; 32]))
            .unwrap());
        assert!(fence
            .authorize(7, CrossPathDecision::HashAsync([11; 32]))
            .is_err());
    }

    #[test]
    fn rollback_and_clone_are_refused() {
        let directory = tempfile::tempdir().unwrap();
        let state = directory.path().join("node/fence.scale");
        let anchor = directory.path().join("external/fence.anchor");
        let key = [12; 32];
        let member = AccountId([13; 32]);
        let mut fence =
            DurableCrossPathSigningFence::open(&state, &anchor, scope(), member, &key).unwrap();
        let old_state = std::fs::read(&state).unwrap();
        fence
            .authorize(9, CrossPathDecision::HashAsync([14; 32]))
            .unwrap();
        assert!(
            DurableCrossPathSigningFence::open(&state, &anchor, scope(), member, &key).is_err()
        );
        drop(fence);
        std::fs::write(&state, old_state).unwrap();
        let error =
            DurableCrossPathSigningFence::open(&state, &anchor, scope(), member, &key).unwrap_err();
        assert!(error.contains("rollback") || error.contains("hash"));
    }

    #[test]
    fn crash_after_state_commit_heals_one_generation_stale_anchor() {
        let directory = tempfile::tempdir().unwrap();
        let state = directory.path().join("node/fence.scale");
        let anchor = directory.path().join("external/fence.anchor");
        let key = [15; 32];
        let member = AccountId([16; 32]);
        let mut fence =
            DurableCrossPathSigningFence::open(&state, &anchor, scope(), member, &key).unwrap();
        let generation_zero_anchor = std::fs::read(&anchor).unwrap();
        assert!(fence
            .authorize(11, CrossPathDecision::HashAsync([17; 32]))
            .unwrap());
        drop(fence);

        // Model power loss after the state rename/fsync and before the matching
        // anchor rename. Opening the fence must complete that exact pending
        // commit, never discard it or authorize a different root.
        std::fs::write(&anchor, generation_zero_anchor).unwrap();
        let mut recovered =
            DurableCrossPathSigningFence::open(&state, &anchor, scope(), member, &key).unwrap();
        let healed_anchor = read_anchor(&anchor).unwrap();
        assert_eq!(healed_anchor.generation, 1);
        assert_eq!(
            healed_anchor.state_hash,
            state_hash(&recovered.state).unwrap()
        );
        assert!(!recovered
            .authorize(11, CrossPathDecision::Optimistic([17; 32]))
            .unwrap());
        assert!(recovered
            .authorize(11, CrossPathDecision::Optimistic([18; 32]))
            .is_err());
    }
}
