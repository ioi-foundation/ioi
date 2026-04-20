use super::*;
use tempfile::tempdir;

#[test]
fn test_wal_write_read() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("test.wal");

    let writer = WalWriter::new(&path).unwrap();

    let diff1 = StateDiff {
        new_nodes: vec![([1u8; 32], vec![0xAA])],
        touched_nodes: vec![[1u8; 32]],
    };

    let diff2 = StateDiff {
        new_nodes: vec![([2u8; 32], vec![0xBB])],
        touched_nodes: vec![[2u8; 32]],
    };

    writer.append_block(10, [0xA0; 32], &diff1).unwrap();
    writer.append_block(11, [0xA1; 32], &diff2).unwrap();

    let mut iter = WalIterator::new(&path).unwrap();

    let (h1, r1, d1) = iter.next().unwrap().unwrap();
    assert_eq!(h1, 10);
    assert_eq!(r1, [0xA0; 32]);
    assert_eq!(d1.new_nodes[0].1, vec![0xAA]);

    let (h2, r2, d2) = iter.next().unwrap().unwrap();
    assert_eq!(h2, 11);
    assert_eq!(r2, [0xA1; 32]);
    assert_eq!(d2.new_nodes[0].1, vec![0xBB]);

    assert!(iter.next().is_none());
}

#[test]
fn test_wal_compaction() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("compact.wal");
    let writer = WalWriter::new(&path).unwrap();

    // Write heights 10, 11, 12, 13
    for h in 10..14 {
        let diff = StateDiff {
            new_nodes: vec![],
            touched_nodes: vec![],
        };
        writer.append_block(h, [0u8; 32], &diff).unwrap();
    }

    // Check pre-compaction
    {
        let iter = WalIterator::new(&path).unwrap();
        assert_eq!(iter.count(), 4);
    }

    // Compact: Keep >= 12
    writer.compact(12).unwrap();

    // Check post-compaction
    {
        let mut iter = WalIterator::new(&path).unwrap();
        let (h1, _, _) = iter.next().unwrap().unwrap();
        assert_eq!(h1, 12);
        let (h2, _, _) = iter.next().unwrap().unwrap();
        assert_eq!(h2, 13);
        assert!(iter.next().is_none());
    }

    // Ensure we can still write after compaction
    let diff = StateDiff {
        new_nodes: vec![],
        touched_nodes: vec![],
    };
    writer.append_block(14, [0u8; 32], &diff).unwrap();

    {
        let iter = WalIterator::new(&path).unwrap();
        assert_eq!(iter.count(), 3); // 12, 13, 14
    }
}
