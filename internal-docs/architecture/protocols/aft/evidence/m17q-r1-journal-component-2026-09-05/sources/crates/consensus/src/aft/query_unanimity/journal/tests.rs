use super::*;

struct Fixture {
    _root: tempfile::TempDir,
    directory: PathBuf,
    anchor: PathBuf,
    limits: JournalLimits,
}
impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        Self {
            directory: root.path().join("records"),
            anchor: root.path().join("custody.anchor"),
            _root: root,
            limits: JournalLimits {
                max_record_bytes: 512,
                max_total_bytes: 4096,
                max_records: 8,
            },
        }
    }
    fn open(&self) -> Result<MemberJournal, QuvError> {
        self.replay(|_, _| Ok(()))
    }
    fn replay(
        &self,
        replay: impl FnMut(u64, &[u8]) -> Result<(), QuvError>,
    ) -> Result<MemberJournal, QuvError> {
        MemberJournal::open(
            &self.directory,
            &self.anchor,
            [1; 32],
            [2; 32],
            self.limits,
            b"bootstrap",
            replay,
        )
    }
    fn snapshot(&self) -> BTreeMap<PathBuf, Vec<u8>> {
        let mut result = BTreeMap::new();
        result.insert(self.anchor.clone(), std::fs::read(&self.anchor).unwrap());
        for entry in std::fs::read_dir(&self.directory).unwrap() {
            let path = entry.unwrap().path();
            result.insert(path.clone(), std::fs::read(path).unwrap());
        }
        result
    }
}

#[test]
fn append_retains_prior_records_and_replays_in_order() {
    let f = Fixture::new();
    let mut journal = f.open().unwrap();
    let first = std::fs::read(record_path(&f.directory, 0)).unwrap();
    #[cfg(unix)]
    let original_inode = {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata(record_path(&f.directory, 0))
            .unwrap()
            .ino()
    };
    journal.append(b"transition one").unwrap();
    let second = std::fs::read(record_path(&f.directory, 1)).unwrap();
    journal.append(b"transition two").unwrap();
    assert_eq!(std::fs::read(record_path(&f.directory, 0)).unwrap(), first);
    assert_eq!(std::fs::read(record_path(&f.directory, 1)).unwrap(), second);
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        assert_eq!(
            std::fs::metadata(record_path(&f.directory, 0))
                .unwrap()
                .ino(),
            original_inode
        );
    }
    let bytes = journal.bytes;
    drop(journal);
    let mut replayed = Vec::new();
    let reopened = f
        .replay(|n, payload| {
            replayed.push((n, payload.to_vec()));
            Ok(())
        })
        .unwrap();
    assert_eq!(
        replayed,
        vec![
            (1, b"transition one".to_vec()),
            (2, b"transition two".to_vec())
        ]
    );
    assert_eq!(reopened.generation, 2);
    assert_eq!(reopened.bytes, bytes);
}

#[test]
fn pending_record_requires_successful_semantic_replay_before_anchor_advance() {
    let f = Fixture::new();
    let mut journal = f.open().unwrap();
    let old_anchor = std::fs::read(&f.anchor).unwrap();
    journal.append(b"pending transition").unwrap();
    let new_anchor = std::fs::read(&f.anchor).unwrap();
    drop(journal);
    // Model interruption between durable record and durable anchor replacement.
    std::fs::write(&f.anchor, &old_anchor).unwrap();
    let before = f.snapshot();
    let mut calls = 0;
    assert!(matches!(
        f.replay(|n, payload| {
            calls += 1;
            assert_eq!((n, payload), (1, b"pending transition".as_slice()));
            Err(QuvError::InvalidOperation)
        }),
        Err(QuvError::InvalidOperation)
    ));
    assert_eq!(calls, 1);
    assert_eq!(f.snapshot(), before);
    let recovered = f.open().unwrap();
    assert_eq!(recovered.generation, 1);
    assert_eq!(std::fs::read(&f.anchor).unwrap(), new_anchor);
}

#[test]
fn bootstrap_interruption_recovers_only_the_provisioned_initial_record() {
    let f = Fixture::new();
    drop(f.open().unwrap());
    let anchor = std::fs::read(&f.anchor).unwrap();
    std::fs::remove_dir_all(&f.directory).unwrap();
    assert!(MemberJournal::open(
        &f.directory,
        &f.anchor,
        [1; 32],
        [2; 32],
        f.limits,
        b"different bootstrap",
        |_, _| Ok(())
    )
    .is_err());
    assert_eq!(std::fs::read(&f.anchor).unwrap(), anchor);
    assert!(!f.directory.exists());
    let journal = f.open().unwrap();
    assert_eq!(journal.generation, 0);
    assert_eq!(std::fs::read(&f.anchor).unwrap(), anchor);
}

#[test]
fn capacity_refusal_preserves_disk_and_keeps_store_usable() {
    let mut f = Fixture::new();
    f.limits.max_records = 2;
    let mut journal = f.open().unwrap();
    let before = f.snapshot();
    assert!(matches!(
        journal.append(&[0; 513]),
        Err(QuvError::StoreCapacityExceeded)
    ));
    assert_eq!(f.snapshot(), before);
    journal.append(b"last permitted record").unwrap();
    let before = f.snapshot();
    assert!(matches!(
        journal.append(b"excess record"),
        Err(QuvError::StoreCapacityExceeded)
    ));
    assert_eq!(f.snapshot(), before);
    assert!(!journal.failed);
}

#[test]
fn exclusive_open_and_complete_chain_validation_precede_replay() {
    let f = Fixture::new();
    let mut journal = f.open().unwrap();
    assert!(matches!(f.open(), Err(QuvError::StoreBusy)));
    journal.append(b"one").unwrap();
    journal.append(b"two").unwrap();
    drop(journal);
    let path = record_path(&f.directory, 2);
    let mut bytes = std::fs::read(&path).unwrap();
    bytes[0] ^= 1;
    std::fs::write(path, bytes).unwrap();
    let before = f.snapshot();
    let mut calls = 0;
    assert!(matches!(
        f.replay(|_, _| {
            calls += 1;
            Ok(())
        }),
        Err(QuvError::CorruptStore)
    ));
    assert_eq!(calls, 0);
    assert_eq!(f.snapshot(), before);
}

#[test]
fn recovery_cleans_only_unacknowledged_next_temporary_record() {
    let f = Fixture::new();
    drop(f.open().unwrap());
    let scratch = suffixed(&record_path(&f.directory, 1), ".tmp");
    std::fs::write(&scratch, b"interrupted write").unwrap();
    let mut journal = f.open().unwrap();
    assert!(!scratch.exists());
    journal.append(b"complete next record").unwrap();
    assert_eq!(
        journal.bytes,
        std::fs::read_dir(&f.directory)
            .unwrap()
            .map(|e| e.unwrap().metadata().unwrap().len())
            .sum::<u64>()
    );
}

#[test]
fn total_byte_limit_is_checked_before_disk_mutation() {
    let mut f = Fixture::new();
    f.limits.max_record_bytes = 256;
    f.limits.max_total_bytes = 256;
    let mut journal = f.open().unwrap();
    let before = f.snapshot();
    assert!(matches!(
        journal.append(&[3; 100]),
        Err(QuvError::StoreCapacityExceeded)
    ));
    assert_eq!(f.snapshot(), before);
    assert!(!journal.failed);
}
