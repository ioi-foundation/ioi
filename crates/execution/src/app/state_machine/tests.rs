use super::ParallelReplayStatsSnapshot;

#[test]
fn replay_stats_only_fallback_on_internal_errors() {
    assert_eq!(
        ParallelReplayStatsSnapshot {
            validation_aborts: 7,
            validation_errors: 0,
            validation_rewinds: 3,
            execution_errors: 0,
        }
        .fallback_gate(),
        None
    );
    assert_eq!(
        ParallelReplayStatsSnapshot {
            validation_aborts: 0,
            validation_errors: 1,
            validation_rewinds: 0,
            execution_errors: 0,
        }
        .fallback_gate(),
        Some("parallel_validation_error_fallback")
    );
    assert_eq!(
        ParallelReplayStatsSnapshot {
            validation_aborts: 4,
            validation_errors: 2,
            validation_rewinds: 1,
            execution_errors: 9,
        }
        .fallback_gate(),
        Some("parallel_execution_error_fallback")
    );
}
