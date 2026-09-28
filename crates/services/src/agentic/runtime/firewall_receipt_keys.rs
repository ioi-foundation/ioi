//! The signing key for `FirewallDecisionReceipt`s, held by the host and never derived.
//!
//! G7 / W0.7. The runtime-host lane used to sign every firewall decision receipt with an ed25519
//! seed that was sha256 of public values (the chain id and the signer account id), and it kept that
//! seed in execution state. Anyone could compute the key and forge a receipt. This store replaces it:
//!
//! - a key is generated once from the OS CSPRNG and persisted under the host's data dir, at
//!   `firewall-receipt-keys/<key_id>.ed25519` (mode 0600, directory 0700); no public value is an
//!   input to it, and it never enters execution state;
//! - a key file whose mode lets anyone but the owner read it is refused, never used;
//! - each receipt's signature envelope records the key id (a digest of the public key), and
//!   `ACTIVE` names the key that signs now. `rotate` mints a new key and repoints `ACTIVE`; every
//!   earlier key's public half stays at `<key_id>.pub`, so receipts signed before a rotation still
//!   verify against the key that signed them.
//!
//! Tests and fixtures open the store over a temp dir, never over a real data dir.

use ioi_api::crypto::{SerializableKey, SigningKeyPair};
use ioi_crypto::sign::eddsa::{Ed25519KeyPair, Ed25519PrivateKey};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::sync::RwLock;

/// The directory, under the host's data dir, that holds the receipt signing keys.
pub const FIREWALL_RECEIPT_KEY_DIR: &str = "firewall-receipt-keys";
/// Every key id starts with this prefix, followed by 32 hex digits of sha256(public key).
pub const FIREWALL_RECEIPT_KEY_ID_PREFIX: &str = "fwk_";

const ACTIVE_FILE: &str = "ACTIVE";
const SEED_EXTENSION: &str = "ed25519";
const PUBLIC_EXTENSION: &str = "pub";
const SEED_LEN: usize = 32;

/// Why the receipt key store refused to open, sign or rotate.
#[derive(Debug, thiserror::Error)]
pub enum FirewallReceiptKeyError {
    #[error("firewall receipt key store I/O failed at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error(
        "firewall receipt key file {path} has mode {mode:o}; it must be readable by its owner only (0600)"
    )]
    Permissions { path: PathBuf, mode: u32 },
    #[error("firewall receipt key store is malformed: {0}")]
    Malformed(String),
    #[error("firewall receipt key cryptography failed: {0}")]
    Crypto(String),
}

/// A signature made by the store's active key, with the id and public half of that key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirewallReceiptSignature {
    pub key_id: String,
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
}

struct LoadedKey {
    key_id: String,
    public_key: Vec<u8>,
    keypair: Ed25519KeyPair,
}

/// The host-held receipt signing keys. See the module docs.
pub struct FirewallReceiptKeyStore {
    dir: PathBuf,
    active: RwLock<LoadedKey>,
}

impl std::fmt::Debug for FirewallReceiptKeyStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FirewallReceiptKeyStore")
            .field("dir", &self.dir)
            .field("active_key_id", &self.active_key_id())
            .finish_non_exhaustive()
    }
}

/// The key id for a public key: `fwk_` + the first 16 bytes of sha256(public key), in hex.
pub fn firewall_receipt_key_id(public_key: &[u8]) -> String {
    let digest = Sha256::digest(public_key);
    format!(
        "{FIREWALL_RECEIPT_KEY_ID_PREFIX}{}",
        hex::encode(&digest[..16])
    )
}

fn is_well_formed_key_id(key_id: &str) -> bool {
    key_id
        .strip_prefix(FIREWALL_RECEIPT_KEY_ID_PREFIX)
        .is_some_and(|rest| {
            rest.len() == 32 && rest.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        })
}

fn io_error(path: &Path) -> impl FnOnce(std::io::Error) -> FirewallReceiptKeyError + '_ {
    move |source| FirewallReceiptKeyError::Io {
        path: path.to_path_buf(),
        source,
    }
}

fn ensure_private_dir(dir: &Path) -> Result<(), FirewallReceiptKeyError> {
    fs::create_dir_all(dir).map_err(io_error(dir))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).map_err(io_error(dir))?;
    }
    Ok(())
}

/// Create `path` exclusively with owner-only permissions and write `bytes` to it durably.
fn write_new_private_file(path: &Path, bytes: &[u8]) -> Result<(), FirewallReceiptKeyError> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(io_error(path))?;
    file.write_all(bytes).map_err(io_error(path))?;
    file.sync_all().map_err(io_error(path))?;
    Ok(())
}

fn check_owner_only(path: &Path) -> Result<(), FirewallReceiptKeyError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(path)
            .map_err(io_error(path))?
            .permissions()
            .mode()
            & 0o777;
        if mode & 0o077 != 0 {
            return Err(FirewallReceiptKeyError::Permissions {
                path: path.to_path_buf(),
                mode,
            });
        }
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn keypair_from_seed(seed: &[u8]) -> Result<Ed25519KeyPair, FirewallReceiptKeyError> {
    let private_key = Ed25519PrivateKey::from_bytes(seed)
        .map_err(|e| FirewallReceiptKeyError::Crypto(e.to_string()))?;
    Ed25519KeyPair::from_private_key(&private_key)
        .map_err(|e| FirewallReceiptKeyError::Crypto(e.to_string()))
}

impl FirewallReceiptKeyStore {
    /// Open the store at `<data_dir>/firewall-receipt-keys`, minting its first key if it has none.
    pub fn open_in_data_dir(data_dir: impl AsRef<Path>) -> Result<Self, FirewallReceiptKeyError> {
        Self::open(data_dir.as_ref().join(FIREWALL_RECEIPT_KEY_DIR))
    }

    /// Open the store at `dir`, minting its first key if it has none.
    ///
    /// Two hosts opening the same empty dir at once converge on one key: `ACTIVE` is claimed
    /// with an exclusive create, and the loser adopts the winner's key.
    pub fn open(dir: impl Into<PathBuf>) -> Result<Self, FirewallReceiptKeyError> {
        let dir = dir.into();
        ensure_private_dir(&dir)?;
        let active = match read_active_key_id(&dir)? {
            Some(key_id) => load_key(&dir, &key_id)?,
            None => {
                let minted = mint_key(&dir)?;
                if claim_active(&dir, &minted.key_id)? {
                    minted
                } else {
                    // Another opener claimed ACTIVE first. Discard the unused key and adopt theirs.
                    let _ = fs::remove_file(seed_path(&dir, &minted.key_id));
                    let _ = fs::remove_file(public_path(&dir, &minted.key_id));
                    let key_id = read_active_key_id(&dir)?.ok_or_else(|| {
                        FirewallReceiptKeyError::Malformed(
                            "ACTIVE vanished while it was being claimed".to_string(),
                        )
                    })?;
                    load_key(&dir, &key_id)?
                }
            }
        };
        Ok(Self {
            dir,
            active: RwLock::new(active),
        })
    }

    /// The directory the keys live in.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The id of the key that signs now.
    pub fn active_key_id(&self) -> String {
        self.read_active().key_id.clone()
    }

    /// The public half of the key that signs now.
    pub fn active_public_key(&self) -> Vec<u8> {
        self.read_active().public_key.clone()
    }

    /// Sign `message` with the active key.
    pub fn sign(
        &self,
        message: &[u8],
    ) -> Result<FirewallReceiptSignature, FirewallReceiptKeyError> {
        let active = self.read_active();
        let signature = active
            .keypair
            .sign(message)
            .map_err(|e| FirewallReceiptKeyError::Crypto(e.to_string()))?;
        Ok(FirewallReceiptSignature {
            key_id: active.key_id.clone(),
            public_key: active.public_key.clone(),
            signature: signature.to_bytes(),
        })
    }

    /// Mint a new key and make it the active one. Earlier keys stay on disk, so receipts they
    /// signed keep verifying. Returns the new key id.
    pub fn rotate(&self) -> Result<String, FirewallReceiptKeyError> {
        let minted = mint_key(&self.dir)?;
        let key_id = minted.key_id.clone();
        let staged = self
            .dir
            .join(format!("{ACTIVE_FILE}.{}.{}", std::process::id(), key_id));
        write_new_private_file(&staged, format!("{key_id}\n").as_bytes())?;
        let active_path = self.dir.join(ACTIVE_FILE);
        fs::rename(&staged, &active_path).map_err(io_error(&active_path))?;
        *self
            .active
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = minted;
        Ok(key_id)
    }

    /// The public key this store holds for `key_id`, active or retired. `None` when the store has
    /// never held that key.
    pub fn public_key_for(&self, key_id: &str) -> Result<Option<Vec<u8>>, FirewallReceiptKeyError> {
        if !is_well_formed_key_id(key_id) {
            return Ok(None);
        }
        let path = public_path(&self.dir, key_id);
        let public_key = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(io_error(&path)(error)),
        };
        if firewall_receipt_key_id(&public_key) != key_id {
            return Err(FirewallReceiptKeyError::Malformed(format!(
                "{} does not hold the public key for {key_id}",
                path.display()
            )));
        }
        Ok(Some(public_key))
    }

    fn read_active(&self) -> std::sync::RwLockReadGuard<'_, LoadedKey> {
        self.active
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

fn seed_path(dir: &Path, key_id: &str) -> PathBuf {
    dir.join(format!("{key_id}.{SEED_EXTENSION}"))
}

fn public_path(dir: &Path, key_id: &str) -> PathBuf {
    dir.join(format!("{key_id}.{PUBLIC_EXTENSION}"))
}

fn read_active_key_id(dir: &Path) -> Result<Option<String>, FirewallReceiptKeyError> {
    let path = dir.join(ACTIVE_FILE);
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(io_error(&path)(error)),
    };
    let key_id = text.trim();
    if !is_well_formed_key_id(key_id) {
        // A truncated or edited ACTIVE is an error, never a reason to mint a fresh key.
        return Err(FirewallReceiptKeyError::Malformed(format!(
            "{} does not name a key id",
            path.display()
        )));
    }
    Ok(Some(key_id.to_string()))
}

fn claim_active(dir: &Path, key_id: &str) -> Result<bool, FirewallReceiptKeyError> {
    match write_new_private_file(&dir.join(ACTIVE_FILE), format!("{key_id}\n").as_bytes()) {
        Ok(()) => Ok(true),
        Err(FirewallReceiptKeyError::Io { source, .. })
            if source.kind() == ErrorKind::AlreadyExists =>
        {
            Ok(false)
        }
        Err(error) => Err(error),
    }
}

fn load_key(dir: &Path, key_id: &str) -> Result<LoadedKey, FirewallReceiptKeyError> {
    let path = seed_path(dir, key_id);
    check_owner_only(&path)?;
    let mut seed = fs::read(&path).map_err(io_error(&path))?;
    if seed.len() != SEED_LEN {
        let len = seed.len();
        seed.fill(0);
        return Err(FirewallReceiptKeyError::Malformed(format!(
            "{} holds {len} bytes, not a {SEED_LEN}-byte ed25519 seed",
            path.display()
        )));
    }
    let keypair = keypair_from_seed(&seed);
    seed.fill(0);
    let keypair = keypair?;
    let public_key = keypair.public_key().to_bytes();
    if firewall_receipt_key_id(&public_key) != key_id {
        return Err(FirewallReceiptKeyError::Malformed(format!(
            "{} does not hold the key {key_id}",
            path.display()
        )));
    }
    Ok(LoadedKey {
        key_id: key_id.to_string(),
        public_key,
        keypair,
    })
}

/// Generate a key from the OS CSPRNG and persist it (seed 0600, public half beside it).
fn mint_key(dir: &Path) -> Result<LoadedKey, FirewallReceiptKeyError> {
    let keypair =
        Ed25519KeyPair::generate().map_err(|e| FirewallReceiptKeyError::Crypto(e.to_string()))?;
    let public_key = keypair.public_key().to_bytes();
    let key_id = firewall_receipt_key_id(&public_key);
    let mut seed = keypair.private_key().to_bytes();
    let written = write_new_private_file(&seed_path(dir, &key_id), &seed);
    seed.fill(0);
    written?;
    let public = public_path(dir, &key_id);
    fs::write(&public, &public_key).map_err(io_error(&public))?;
    Ok(LoadedKey {
        key_id,
        public_key,
        keypair,
    })
}

/// One receipt key store per test process, over a temp dir (never a real data dir), for test
/// fixtures whose services execute actions against state.
#[cfg(test)]
pub(crate) fn test_firewall_receipt_keys() -> std::sync::Arc<FirewallReceiptKeyStore> {
    static KEYS: std::sync::OnceLock<(tempfile::TempDir, std::sync::Arc<FirewallReceiptKeyStore>)> =
        std::sync::OnceLock::new();
    KEYS.get_or_init(|| {
        let dir = tempfile::tempdir().expect("temp dir for test firewall receipt keys");
        let keys = FirewallReceiptKeyStore::open_in_data_dir(dir.path())
            .expect("test firewall receipt keys");
        (dir, std::sync::Arc::new(keys))
    })
    .1
    .clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ioi_api::crypto::VerifyingKey;
    use ioi_crypto::sign::eddsa::{Ed25519PublicKey, Ed25519Signature};

    fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
        let public_key = Ed25519PublicKey::from_bytes(public_key).expect("public key");
        let signature = Ed25519Signature::from_bytes(signature).expect("signature");
        public_key.verify(message, &signature).is_ok()
    }

    #[test]
    fn a_key_is_minted_once_and_reopened_from_disk() {
        let dir = tempfile::tempdir().expect("tempdir");
        let first = FirewallReceiptKeyStore::open_in_data_dir(dir.path()).expect("open");
        let reopened = FirewallReceiptKeyStore::open_in_data_dir(dir.path()).expect("reopen");
        assert_eq!(first.active_key_id(), reopened.active_key_id());
        assert_eq!(first.active_public_key(), reopened.active_public_key());
        assert!(is_well_formed_key_id(&first.active_key_id()));
        assert_eq!(
            firewall_receipt_key_id(&first.active_public_key()),
            first.active_key_id()
        );
    }

    #[cfg(unix)]
    #[test]
    fn the_seed_file_is_owner_only_and_a_readable_one_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let store = FirewallReceiptKeyStore::open_in_data_dir(dir.path()).expect("open");
        let seed = seed_path(store.dir(), &store.active_key_id());
        let mode = fs::metadata(&seed).expect("seed").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "seed file mode");
        let dir_mode = fs::metadata(store.dir()).expect("dir").permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700, "key dir mode");
        assert_eq!(fs::read(&seed).expect("seed").len(), SEED_LEN);

        fs::set_permissions(&seed, fs::Permissions::from_mode(0o644)).expect("chmod");
        let error = FirewallReceiptKeyStore::open_in_data_dir(dir.path())
            .expect_err("a group/world-readable seed must be refused");
        assert!(
            matches!(
                error,
                FirewallReceiptKeyError::Permissions { mode: 0o644, .. }
            ),
            "{error}"
        );
    }

    #[test]
    fn a_damaged_active_pointer_is_an_error_not_a_new_key() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = FirewallReceiptKeyStore::open_in_data_dir(dir.path()).expect("open");
        fs::write(store.dir().join(ACTIVE_FILE), "garbage\n").expect("damage ACTIVE");
        let error = FirewallReceiptKeyStore::open_in_data_dir(dir.path())
            .expect_err("damaged ACTIVE must refuse");
        assert!(
            matches!(error, FirewallReceiptKeyError::Malformed(_)),
            "{error}"
        );
    }

    #[test]
    fn rotation_keeps_retired_public_keys_for_verification() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = FirewallReceiptKeyStore::open_in_data_dir(dir.path()).expect("open");
        let old = store.sign(b"before rotation").expect("sign");
        let new_id = store.rotate().expect("rotate");
        assert_ne!(new_id, old.key_id);
        assert_eq!(store.active_key_id(), new_id);
        let new = store.sign(b"after rotation").expect("sign");
        assert_eq!(new.key_id, new_id);

        let reopened = FirewallReceiptKeyStore::open_in_data_dir(dir.path()).expect("reopen");
        assert_eq!(
            reopened.active_key_id(),
            new_id,
            "ACTIVE follows the rotation"
        );
        let old_public = reopened
            .public_key_for(&old.key_id)
            .expect("lookup")
            .expect("retired key still known");
        assert_eq!(old_public, old.public_key);
        assert!(verify(&old_public, b"before rotation", &old.signature));
        assert!(reopened
            .public_key_for("fwk_00000000000000000000000000000000")
            .expect("lookup")
            .is_none());
    }
}
