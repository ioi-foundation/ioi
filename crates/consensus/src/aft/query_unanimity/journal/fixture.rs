//! Test fixtures for the journal format. Never compiled into production.
use super::*;
use crate::aft::query_unanimity::member_delta::MemberDelta;

pub(in crate::aft::query_unanimity) fn deltas(directory: &Path, key: &QuvHash) -> Vec<MemberDelta> {
    let mut paths: Vec<_> = std::fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    paths.sort();
    paths
        .into_iter()
        .skip(1)
        .map(|path| {
            let record: Record =
                decode_authenticated(&std::fs::read(path).unwrap(), RECORD_MAC, key).unwrap();
            codec::from_bytes_canonical(&record.payload).unwrap()
        })
        .collect()
}

pub(in crate::aft::query_unanimity) fn replace_payload_without_tag(
    directory: &Path,
    generation: u64,
    key: &QuvHash,
    delta: &MemberDelta,
) {
    let path = record_path(directory, generation);
    let mut record: Record =
        decode_authenticated(&std::fs::read(&path).unwrap(), RECORD_MAC, key).unwrap();
    record.payload = codec::to_bytes_canonical(delta).unwrap();
    std::fs::write(path, codec::to_bytes_canonical(&record).unwrap()).unwrap();
}

/// Re-authenticate a synthetic transition sequence so semantic recovery checks,
/// rather than a MAC or generation-gap refusal, are exercised by local tests.
pub(in crate::aft::query_unanimity) fn rebuild(
    directory: &Path,
    anchor: &Path,
    key: &QuvHash,
    deltas: &[MemberDelta],
    pending: bool,
) {
    assert!(!deltas.is_empty());
    let initial = std::fs::read(record_path(directory, 0)).unwrap();
    let bootstrap: Record = decode_authenticated(&initial, RECORD_MAC, key).unwrap();
    let mut paths: Vec<_> = std::fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    paths.sort();
    for (generation, path) in paths.iter().enumerate() {
        assert_eq!(*path, record_path(directory, generation as u64));
        assert!(path.is_file());
    }
    for path in paths.into_iter().skip(1) {
        std::fs::remove_file(path).unwrap();
    }
    let limits = JournalLimits {
        max_record_bytes: STORE_MAX_BYTES,
        max_total_bytes: STORE_MAX_BYTES,
        max_records: STORE_MAX_BYTES / 128,
    };
    let mut heads = vec![record_head(&initial).unwrap()];
    for (offset, delta) in deltas.iter().enumerate() {
        let generation = offset as u64 + 1;
        let raw = make_record(
            bootstrap.scope,
            generation,
            *heads.last().unwrap(),
            &codec::to_bytes_canonical(delta).unwrap(),
            key,
            limits,
        )
        .unwrap();
        std::fs::write(record_path(directory, generation), &raw).unwrap();
        heads.push(record_head(&raw).unwrap());
    }
    let generation = deltas.len() - usize::from(pending);
    persist_anchor(
        anchor,
        bootstrap.scope,
        generation as u64,
        heads[generation],
        key,
    )
    .unwrap();
}
