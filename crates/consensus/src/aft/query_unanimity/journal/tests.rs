use super::*;
use std::collections::BTreeMap;

struct Fixture {
    _root: tempfile::TempDir,
    directory: PathBuf,
    anchor: PathBuf,
    limits: JournalLimits,
}
impl Fixture {
    fn reserved(
        &self,
        replay: impl FnMut(u64, &[u8]) -> Result<(), QuvError>,
    ) -> Result<MemberJournal, QuvError> {
        MemberJournal::open_reserved(
            &self.directory,
            &self.anchor,
            [1; 32],
            [2; 32],
            self.limits,
            ReservationLimits {
                records: self.limits.max_records,
                record_bytes: self.limits.max_record_bytes,
            },
            b"bootstrap",
            replay,
        )
    }
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
        let inactive = suffixed(&self.anchor, ".tmp");
        if inactive.is_file() {
            result.insert(inactive.clone(), std::fs::read(inactive).unwrap());
        }
        for entry in std::fs::read_dir(&self.directory).unwrap() {
            let path = entry.unwrap().path();
            result.insert(path.clone(), std::fs::read(path).unwrap());
        }
        let pool = reservation::directory(&self.directory);
        if pool.exists() {
            for entry in std::fs::read_dir(pool).unwrap() {
                let path = entry.unwrap().path();
                result.insert(path.clone(), std::fs::read(path).unwrap());
            }
        }
        result
    }
}

#[cfg(target_os = "linux")]
#[test]
fn reserved_records_preserve_allocation_and_inode_through_complete_lifetime() {
    use std::os::unix::fs::MetadataExt;
    let mut f = Fixture::new();
    f.limits.max_record_bytes = 8192;
    f.limits.max_total_bytes = 65536;
    let mut journal = f.reserved(|_, _| Ok(())).unwrap();
    let pool = reservation::directory(&f.directory);
    let anchor_inode = |path: &Path| {
        let file = File::open(path).unwrap();
        assert_eq!(file.allocated_size().unwrap(), 4096);
        assert_eq!(file.metadata().unwrap().len(), 114);
        file.metadata().unwrap().ino()
    };
    let inactive = suffixed(&f.anchor, ".tmp");
    let anchors = [anchor_inode(&f.anchor), anchor_inode(&inactive)];
    assert_ne!(anchors[0], anchors[1]);
    let mut inodes = Vec::new();
    for generation in 1..f.limits.max_records {
        let file = File::open(reservation::slot(&pool, generation)).unwrap();
        assert_eq!(file.metadata().unwrap().len(), 0);
        assert!(file.allocated_size().unwrap() >= f.limits.max_record_bytes);
        inodes.push(file.metadata().unwrap().ino());
    }
    let before = f.snapshot();
    assert!(matches!(
        journal.append_with_prewrite_check(b"refused", || Err(QuvError::InvalidOperation)),
        Err(QuvError::InvalidOperation)
    ));
    assert!(!journal.failed);
    assert_eq!(f.snapshot(), before);
    for generation in 1..f.limits.max_records {
        journal.append(&[generation as u8]).unwrap();
        assert_eq!(anchor_inode(&f.anchor), anchors[generation as usize % 2]);
        assert_eq!(
            anchor_inode(&inactive),
            anchors[(generation as usize + 1) % 2]
        );
        let file = File::open(record_path(&f.directory, generation)).unwrap();
        assert_eq!(
            file.metadata().unwrap().ino(),
            inodes[generation as usize - 1]
        );
        assert!(file.allocated_size().unwrap() >= f.limits.max_record_bytes);
        assert!(!reservation::slot(&pool, generation).exists());
    }
    assert!(matches!(
        journal.append(b"exhausted"),
        Err(QuvError::StoreCapacityExceeded)
    ));
    assert!(!journal.failed);
    drop(journal);
    let mut seen = Vec::new();
    let recovered = f
        .reserved(|g, raw| {
            seen.push((g, raw.to_vec()));
            Ok(())
        })
        .unwrap();
    assert_eq!(recovered.generation, f.limits.max_records - 1);
    assert_eq!(
        seen,
        (1..f.limits.max_records)
            .map(|g| (g, vec![g as u8]))
            .collect::<Vec<_>>()
    );
}

#[cfg(target_os = "linux")]
#[test]
fn partial_or_unallocated_reserved_records_require_authenticated_restart() {
    for partial in [false, true] {
        let f = Fixture::new();
        let mut journal = f.reserved(|_, _| Ok(())).unwrap();
        let next = reservation::slot(&reservation::directory(&f.directory), 1);
        if partial {
            std::fs::write(&next, b"unacknowledged partial record").unwrap();
        } else {
            std::fs::remove_file(&next).unwrap();
            File::create(&next).unwrap();
            assert_eq!(File::open(&next).unwrap().allocated_size().unwrap(), 0);
        }
        let before = f.snapshot();
        assert!(matches!(
            journal.append_with_prewrite_check(b"one", || panic!(
                "lost reservation must precede continuation check"
            )),
            Err(QuvError::StoreRequiresReopen)
        ));
        assert!(journal.failed);
        assert_eq!(f.snapshot(), before);
        drop(journal);
        let mut recovered = f
            .reserved(|_, _| panic!("partial reserved bytes cannot become a transition"))
            .unwrap();
        assert_eq!(std::fs::metadata(&next).unwrap().len(), 0);
        assert!(File::open(&next).unwrap().allocated_size().unwrap() >= f.limits.max_record_bytes);
        recovered.append(b"after authenticated restart").unwrap();
        assert_eq!(recovered.generation, 1);
    }
}

#[cfg(target_os = "linux")]
#[test]
fn reserved_record_anchor_failure_requires_semantic_replay_before_recovery() {
    let f = Fixture::new();
    let mut journal = f.reserved(|_, _| Ok(())).unwrap();
    let anchor = std::fs::read(&f.anchor).unwrap();
    journal.fail_anchor_at = Some(anchor_reservation::AnchorPhase::InactiveDurable);
    assert!(matches!(
        journal.append(b"durable pending"),
        Err(QuvError::Io(_))
    ));
    assert!(journal.failed);
    assert_eq!(std::fs::read(&f.anchor).unwrap(), anchor);
    assert!(record_path(&f.directory, 1).exists());
    assert!(!reservation::slot(&reservation::directory(&f.directory), 1).exists());
    drop(journal);
    let before = f.snapshot();
    assert!(matches!(
        f.reserved(|_, _| Err(QuvError::InvalidOperation)),
        Err(QuvError::InvalidOperation)
    ));
    assert_eq!(f.snapshot(), before);
    let mut seen = Vec::new();
    let recovered = f
        .reserved(|g, raw| {
            seen.push((g, raw.to_vec()));
            Ok(())
        })
        .unwrap();
    assert_eq!(recovered.generation, 1);
    assert_eq!(seen, vec![(1, b"durable pending".to_vec())]);
}

#[cfg(target_os = "linux")]
#[test]
fn reserved_anchor_boundaries_never_publish_memory_before_durability() {
    use anchor_reservation::AnchorPhase;
    for phase in [
        AnchorPhase::InactiveDurable,
        AnchorPhase::Exchanged,
        AnchorPhase::DirectoryDurable,
    ] {
        let f = Fixture::new();
        let mut journal = f.reserved(|_, _| Ok(())).unwrap();
        let previous = std::fs::read(&f.anchor).unwrap();
        journal.fail_anchor_at = Some(phase);
        assert!(matches!(journal.append(b"pending"), Err(QuvError::Io(_))));
        assert!(journal.failed);
        assert_eq!(journal.generation, 0);
        assert!(record_path(&f.directory, 1).exists());
        let observed = std::fs::read(&f.anchor).unwrap();
        assert_eq!(observed == previous, phase == AnchorPhase::InactiveDurable);
        assert!(matches!(
            journal.append(b"retry"),
            Err(QuvError::StoreRequiresReopen)
        ));
        drop(journal);
        let before = f.snapshot();
        assert!(matches!(
            f.reserved(|_, _| Err(QuvError::InvalidOperation)),
            Err(QuvError::InvalidOperation)
        ));
        assert_eq!(f.snapshot(), before);
        let mut replayed = Vec::new();
        let recovered = f
            .reserved(|g, raw| {
                replayed.push((g, raw.to_vec()));
                Ok(())
            })
            .unwrap();
        assert_eq!(recovered.generation, 1);
        assert_eq!(replayed, vec![(1, b"pending".to_vec())]);
    }
}

#[cfg(target_os = "linux")]
#[test]
fn anchor_capacity_failure_precedes_continuation_and_record_mutation() {
    let f = Fixture::new();
    let mut journal = f.reserved(|_, _| Ok(())).unwrap();
    let inactive = suffixed(&f.anchor, ".tmp");
    std::fs::remove_file(&inactive).unwrap();
    File::create(&inactive).unwrap();
    let before = f.snapshot();
    assert!(matches!(
        journal.append_with_prewrite_check(b"one", || panic!(
            "anchor capacity must precede continuation"
        )),
        Err(QuvError::StoreRequiresReopen)
    ));
    assert!(journal.failed);
    assert_eq!(f.snapshot(), before);
    assert!(!record_path(&f.directory, 1).exists());
    drop(journal);
    let mut recovered = f
        .reserved(|_, _| panic!("no transition was committed"))
        .unwrap();
    recovered.append(b"after reserved-anchor recovery").unwrap();
}

#[cfg(target_os = "linux")]
#[test]
fn corrupt_active_anchor_cannot_fall_back_to_valid_reserved_copy() {
    let f = Fixture::new();
    let mut journal = f.reserved(|_, _| Ok(())).unwrap();
    journal.append(b"retained transition").unwrap();
    drop(journal);
    let good = std::fs::read(&f.anchor).unwrap();
    let inactive = std::fs::read(suffixed(&f.anchor, ".tmp")).unwrap();
    let old: Anchor = decode_authenticated(&inactive, ANCHOR_MAC, &[1; 32]).unwrap();
    assert_eq!(old.generation, 0);
    let mut bad = good.clone();
    bad[0] ^= 1;
    std::fs::write(&f.anchor, bad).unwrap();
    let before = f.snapshot();
    assert!(matches!(
        f.reserved(|_, _| panic!("invalid active anchor must precede replay")),
        Err(QuvError::InvalidAnchor)
    ));
    assert_eq!(f.snapshot(), before);
    std::fs::write(&f.anchor, good).unwrap();
    assert_eq!(f.reserved(|_, _| Ok(())).unwrap().generation, 1);
}

#[cfg(target_os = "linux")]
#[test]
fn corrupt_reservation_root_preserves_pending_bytes_and_anchor() {
    let f = Fixture::new();
    drop(f.reserved(|_, _| Ok(())).unwrap());
    let pool = reservation::directory(&f.directory);
    let root = pool.join("root");
    let good = std::fs::read(&root).unwrap();
    let mut bad = good.clone();
    bad[0] ^= 1;
    std::fs::write(&root, bad).unwrap();
    std::fs::write(reservation::slot(&pool, 1), b"partial").unwrap();
    let before = f.snapshot();
    assert!(f.reserved(|_, _| Ok(())).is_err());
    assert_eq!(f.snapshot(), before);
    std::fs::write(root, good).unwrap();
    assert!(f.reserved(|_, _| Ok(())).is_ok());
}

#[cfg(target_os = "linux")]
#[test]
fn overallocated_reserved_record_quarantines_before_continuation() {
    use std::os::fd::AsRawFd;
    let f = Fixture::new();
    let mut journal = f.reserved(|_, _| Ok(())).unwrap();
    let next = reservation::slot(&reservation::directory(&f.directory), 1);
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&next)
        .unwrap();
    // Defensive removed-bound control: encoded length is still zero, but
    // allocated data blocks now exceed this fixture's rooted physical charge.
    // SAFETY: this live descriptor refers only to the test's temporary file.
    assert_eq!(
        unsafe { libc::fallocate(file.as_raw_fd(), libc::FALLOC_FL_KEEP_SIZE, 0, 8192) },
        0
    );
    assert_eq!(file.metadata().unwrap().len(), 0);
    assert!(
        file.allocated_size().unwrap()
            > reservation::allocation_charge(f.limits.max_record_bytes).unwrap()
    );
    let before = f.snapshot();
    assert!(matches!(
        journal.append_with_prewrite_check(b"one", || panic!(
            "physical profile refusal must precede continuation"
        )),
        Err(QuvError::StoreRequiresReopen)
    ));
    assert!(journal.failed);
    assert_eq!(f.snapshot(), before);
    assert!(file.allocated_size().unwrap() >= 8192);
    drop(journal);
    assert!(matches!(
        f.reserved(|_, _| Ok(())),
        Err(QuvError::StoreCapacityExceeded)
    ));
    assert_eq!(f.snapshot(), before);
    // Restore only the non-authorizing fixture reservation; authenticated
    // reopen must still precede another successful member record append.
    drop(file);
    std::fs::remove_file(&next).unwrap();
    File::create(&next).unwrap();
    let mut recovered = f.reserved(|_, _| Ok(())).unwrap();
    recovered.append(b"after profile restoration").unwrap();
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

#[test]
fn final_continuation_refusal_is_nonmutating_and_precedes_any_write() {
    let f = Fixture::new();
    let mut journal = f.open().unwrap();
    let before = f.snapshot();
    let mut observed = false;
    assert!(matches!(
        journal.append_with_prewrite_check(b"head transition", || {
            observed = true;
            assert_eq!(f.snapshot(), before);
            Err(QuvError::ExpiredAuthorization)
        }),
        Err(QuvError::ExpiredAuthorization)
    ));
    assert!(observed);
    assert!(!journal.failed);
    assert_eq!(f.snapshot(), before);
    assert_eq!(journal.generation, 0);
    journal
        .append_with_prewrite_check(b"freshly authorized transition", || Ok(()))
        .unwrap();
    assert_eq!(journal.generation, 1);
}

#[test]
fn capacity_admission_precedes_the_final_continuation_check() {
    let f = Fixture::new();
    let mut journal = f.open().unwrap();
    assert!(matches!(
        journal.append_with_prewrite_check(&[0; 513], || {
            panic!("capacity refusal must occur before the final continuation check")
        }),
        Err(QuvError::StoreCapacityExceeded)
    ));
}

#[test]
fn interrupted_record_write_quarantines_until_authenticated_reopen() {
    let f = Fixture::new();
    let mut journal = f.open().unwrap();
    let scratch = suffixed(&record_path(&f.directory, 1), ".tmp");
    // A directory at the staging path produces a deterministic local I/O error
    // without relying on permission bits (tests can run with privileged UIDs).
    std::fs::create_dir(&scratch).unwrap();
    let original_anchor = std::fs::read(&f.anchor).unwrap();
    assert!(matches!(journal.append(b"one"), Err(QuvError::Io(_))));
    assert!(journal.failed);
    assert_eq!(journal.generation, 0);
    assert_eq!(std::fs::read(&f.anchor).unwrap(), original_anchor);
    std::fs::remove_dir(&scratch).unwrap();
    assert!(matches!(
        journal.append(b"retry"),
        Err(QuvError::StoreRequiresReopen)
    ));
    drop(journal);
    let mut recovered = f.open().unwrap();
    recovered.append(b"after reopen").unwrap();
    assert_eq!(recovered.generation, 1);
}

#[test]
fn interrupted_anchor_write_recovers_the_durable_pending_record() {
    let f = Fixture::new();
    let mut journal = f.open().unwrap();
    let original_anchor = std::fs::read(&f.anchor).unwrap();
    let scratch = suffixed(&f.anchor, ".tmp");
    std::fs::create_dir(&scratch).unwrap();
    assert!(matches!(
        journal.append(b"durable pending"),
        Err(QuvError::Io(_))
    ));
    assert!(record_path(&f.directory, 1).is_file());
    assert_eq!(std::fs::read(&f.anchor).unwrap(), original_anchor);
    assert_eq!(journal.generation, 0);
    assert!(matches!(
        journal.append(b"retry"),
        Err(QuvError::StoreRequiresReopen)
    ));
    drop(journal);
    std::fs::remove_dir(&scratch).unwrap();
    let mut replayed = Vec::new();
    let recovered = f
        .replay(|generation, bytes| {
            replayed.push((generation, bytes.to_vec()));
            Ok(())
        })
        .unwrap();
    assert_eq!(recovered.generation, 1);
    assert_eq!(replayed, vec![(1, b"durable pending".to_vec())]);
    assert_ne!(std::fs::read(&f.anchor).unwrap(), original_anchor);
}

#[test]
fn semantic_refusal_preserves_partial_next_record_for_inspection() {
    let f = Fixture::new();
    let mut journal = f.open().unwrap();
    journal.append(b"retained transition").unwrap();
    drop(journal);
    let scratch = suffixed(&record_path(&f.directory, 2), ".tmp");
    std::fs::write(&scratch, b"partial next record").unwrap();
    let before = f.snapshot();
    assert!(matches!(
        f.replay(|_, _| Err(QuvError::InvalidOperation)),
        Err(QuvError::InvalidOperation)
    ));
    assert_eq!(f.snapshot(), before);
    drop(f.open().unwrap());
    assert!(!scratch.exists());
}

#[test]
fn streaming_recovery_reauthenticates_records_and_preserves_pending_anchor() {
    for valid_replacement in [false, true] {
        let f = Fixture::new();
        let mut journal = f.open().unwrap();
        journal.append(b"one").unwrap();
        let anchored = std::fs::read(&f.anchor).unwrap();
        journal.append(b"two").unwrap();
        let scope = journal.scope;
        drop(journal);
        std::fs::write(&f.anchor, &anchored).unwrap();
        let path = record_path(&f.directory, 2);
        let original = std::fs::read(&path).unwrap();
        let mut changed = original.clone();
        if valid_replacement {
            // Simulate a faulty authorized writer changing the unanchored tail
            // between passes. Even a valid MAC cannot change the selected head.
            let record: Record = decode_authenticated(&original, RECORD_MAC, &[1; 32]).unwrap();
            changed = make_record(scope, 2, record.previous, b"new", &[1; 32], f.limits).unwrap();
        } else {
            changed[0] ^= 1;
        }
        let mut calls = 0;
        let result = f.replay(|generation, _| {
            calls += 1;
            if generation == 1 {
                std::fs::write(&path, &changed).unwrap();
            }
            Ok(())
        });
        if valid_replacement {
            assert!(matches!(result, Err(QuvError::RollbackOrFork)));
            assert_eq!(calls, 2);
        } else {
            assert!(matches!(result, Err(QuvError::CorruptStore)));
            assert_eq!(calls, 1);
        }
        assert_eq!(std::fs::read(&f.anchor).unwrap(), anchored);
        std::fs::write(&path, &original).unwrap();
        assert_eq!(f.open().unwrap().generation, 2);
    }
}

#[test]
fn streaming_recovery_refuses_missing_or_noncanonical_record_indices() {
    for noncanonical in [false, true] {
        let f = Fixture::new();
        let mut journal = f.open().unwrap();
        journal.append(b"one").unwrap();
        journal.append(b"two").unwrap();
        drop(journal);
        let path = record_path(&f.directory, 1);
        if noncanonical {
            std::fs::rename(&path, f.directory.join("1.quv")).unwrap();
        } else {
            std::fs::remove_file(&path).unwrap();
        }
        let before = f.snapshot();
        let result = f.replay(|_, _| panic!("invalid indices must precede replay"));
        if noncanonical {
            assert!(matches!(result, Err(QuvError::CorruptStore)));
        } else {
            assert!(matches!(result, Err(QuvError::RollbackOrFork)));
        }
        assert_eq!(f.snapshot(), before);
    }
}

/// Head of the fixture's provisioned generation-0 record and the scope it was
/// sealed under, as recovered from disk.
fn initial_record_head_and_scope(f: &Fixture) -> (QuvHash, QuvHash) {
    let raw = std::fs::read(record_path(&f.directory, 0)).unwrap();
    let record: Record = decode_authenticated(&raw, RECORD_MAC, &[1; 32]).unwrap();
    (record_head(&raw).unwrap(), record.scope)
}

/// R1 QUV-M17Q-002 member-side field negative: a generation-1 record with a
/// valid custody-key MAC that was sealed under a different scope (another
/// provisioning root, or the same root under different limits) is refused
/// with the typed provisioning refusal before any replay callback, and the
/// pending generation-0 anchor is not advanced.
#[test]
fn valid_mac_record_with_foreign_scope_is_refused_before_replay() {
    let f = Fixture::new();
    drop(f.open().unwrap());
    let (initial_head, scope) = initial_record_head_and_scope(&f);
    let mut foreign_limits = f.limits;
    foreign_limits.max_records += 1;
    let foreign_scopes = [
        hash_canonical(&(b"ioi/aft/quv-journal-scope/v1".to_vec(), [3; 32], f.limits)).unwrap(),
        hash_canonical(&(
            b"ioi/aft/quv-journal-scope/v1".to_vec(),
            [2; 32],
            foreign_limits,
        ))
        .unwrap(),
    ];
    for foreign in foreign_scopes {
        assert_ne!(foreign, scope);
        let raw = make_record(foreign, 1, initial_head, b"foreign", &[1; 32], f.limits).unwrap();
        // The bytes authenticate under the custody key; only the scope differs.
        let decoded: Record = decode_authenticated(&raw, RECORD_MAC, &[1; 32]).unwrap();
        assert_eq!(decoded.scope, foreign);
        assert_eq!(decoded.previous, initial_head);
        std::fs::write(record_path(&f.directory, 1), &raw).unwrap();
        let before = f.snapshot();
        let mut calls = 0;
        assert!(matches!(
            f.replay(|_, _| {
                calls += 1;
                Ok(())
            }),
            Err(QuvError::ProvisioningMismatch)
        ));
        assert_eq!(calls, 0);
        assert_eq!(f.snapshot(), before);
        let anchor: Anchor =
            decode_authenticated(&std::fs::read(&f.anchor).unwrap(), ANCHOR_MAC, &[1; 32]).unwrap();
        assert_eq!(anchor.generation, 0);
        assert_eq!(anchor.head, initial_head);
        std::fs::remove_file(record_path(&f.directory, 1)).unwrap();
    }
    // Control: the same payload sealed under the provisioned scope recovers.
    let raw = make_record(scope, 1, initial_head, b"foreign", &[1; 32], f.limits).unwrap();
    std::fs::write(record_path(&f.directory, 1), &raw).unwrap();
    let mut replayed = Vec::new();
    let recovered = f
        .replay(|generation, payload| {
            replayed.push((generation, payload.to_vec()));
            Ok(())
        })
        .unwrap();
    assert_eq!(recovered.generation, 1);
    assert_eq!(replayed, vec![(1, b"foreign".to_vec())]);
}

/// A valid-MAC record whose internal generation field disagrees with its
/// canonical filename is corrupt, not a pending transition: it is refused
/// before replay and the anchor is not advanced.
#[test]
fn valid_mac_record_with_mismatched_generation_field_is_refused() {
    let f = Fixture::new();
    drop(f.open().unwrap());
    let (initial_head, scope) = initial_record_head_and_scope(&f);
    for internal_generation in [0_u64, 2, u64::MAX] {
        let raw = make_record(
            scope,
            internal_generation,
            initial_head,
            b"mislabelled",
            &[1; 32],
            f.limits,
        )
        .unwrap();
        let decoded: Record = decode_authenticated(&raw, RECORD_MAC, &[1; 32]).unwrap();
        assert_eq!(decoded.generation, internal_generation);
        std::fs::write(record_path(&f.directory, 1), &raw).unwrap();
        let before = f.snapshot();
        assert!(matches!(
            f.replay(|_, _| panic!("a mislabelled record must never be replayed")),
            Err(QuvError::CorruptStore)
        ));
        assert_eq!(f.snapshot(), before);
        let anchor: Anchor =
            decode_authenticated(&std::fs::read(&f.anchor).unwrap(), ANCHOR_MAC, &[1; 32]).unwrap();
        assert_eq!(anchor.generation, 0);
        std::fs::remove_file(record_path(&f.directory, 1)).unwrap();
    }
    assert_eq!(f.open().unwrap().generation, 0);
}

/// A completely valid next record left at the `.quv.tmp` scratch name was
/// never acknowledged: recovery deletes it, never replays it, and leaves the
/// anchor at the acknowledged generation. The next append then reuses that
/// generation with its own contents.
#[test]
fn fully_valid_record_at_scratch_name_is_deleted_not_replayed() {
    let f = Fixture::new();
    drop(f.open().unwrap());
    let (initial_head, scope) = initial_record_head_and_scope(&f);
    let anchor_before = std::fs::read(&f.anchor).unwrap();
    let raw = make_record(
        scope,
        1,
        initial_head,
        b"never acknowledged",
        &[1; 32],
        f.limits,
    )
    .unwrap();
    // Under the canonical name these bytes would be a recoverable pending
    // transition; the scratch name is the only difference.
    let decoded: Record = decode_authenticated(&raw, RECORD_MAC, &[1; 32]).unwrap();
    assert_eq!((decoded.generation, decoded.previous), (1, initial_head));
    let scratch = suffixed(&record_path(&f.directory, 1), ".tmp");
    std::fs::write(&scratch, &raw).unwrap();
    let mut journal = f
        .replay(|_, _| panic!("scratch bytes must never be replayed"))
        .unwrap();
    assert_eq!(journal.generation, 0);
    assert_eq!(journal.head, initial_head);
    assert!(!scratch.exists());
    assert!(!record_path(&f.directory, 1).exists());
    assert_eq!(std::fs::read(&f.anchor).unwrap(), anchor_before);
    journal.append(b"acknowledged").unwrap();
    assert_eq!(journal.generation, 1);
    drop(journal);
    let mut replayed = Vec::new();
    let recovered = f
        .replay(|generation, payload| {
            replayed.push((generation, payload.to_vec()));
            Ok(())
        })
        .unwrap();
    assert_eq!(recovered.generation, 1);
    assert_eq!(replayed, vec![(1, b"acknowledged".to_vec())]);
}
