use super::*;
use std::thread::sleep;

#[test]
fn test_pacemaker_timeout() {
    let mut pm = Pacemaker::new(Duration::from_millis(100));
    assert!(!pm.check_timeout());
    sleep(Duration::from_millis(150));
    assert!(pm.check_timeout());
}

#[test]
fn test_advance_view_resets_timer() {
    let mut pm = Pacemaker::new(Duration::from_millis(100));
    sleep(Duration::from_millis(150));
    assert!(pm.check_timeout());

    pm.advance_view(1);
    assert!(!pm.check_timeout());
    assert_eq!(pm.current_view, 1);
}

#[test]
fn test_advance_view_monotonicity() {
    let mut pm = Pacemaker::new(Duration::from_millis(100));
    pm.advance_view(5);
    assert_eq!(pm.current_view, 5);

    // Should ignore lower view
    pm.advance_view(3);
    assert_eq!(pm.current_view, 5);
}

// AFT-CB RES-R10 D1 — adaptive backoff.

#[test]
fn steady_state_timeout_equals_base() {
    let pm = Pacemaker::new(Duration::from_millis(100));
    assert_eq!(pm.consecutive_timeouts(), 0);
    assert_eq!(pm.timeout_for_view(), Duration::from_millis(100));
}

#[test]
fn consecutive_advances_widen_the_timeout_geometrically() {
    let mut pm = Pacemaker::new(Duration::from_millis(100));
    let base = pm.timeout_for_view();

    pm.advance_view(1);
    assert_eq!(pm.consecutive_timeouts(), 1);
    let after_one = pm.timeout_for_view();
    assert!(after_one > base, "one failed view widens the window");

    pm.advance_view(2);
    let after_two = pm.timeout_for_view();
    assert!(
        after_two > after_one,
        "a second failed view widens it further"
    );

    // Exactly base * factor^2.
    let expected = Duration::from_millis(100).mul_f64(1.2_f64.powi(2));
    assert_eq!(after_two, expected);
}

#[test]
fn progress_resets_the_backoff_to_base() {
    let mut pm = Pacemaker::new(Duration::from_millis(100));
    pm.advance_view(1);
    pm.advance_view(2);
    pm.advance_view(3);
    assert_eq!(pm.consecutive_timeouts(), 3);
    assert!(pm.timeout_for_view() > Duration::from_millis(100));

    pm.observe_progress(3);
    assert_eq!(
        pm.consecutive_timeouts(),
        0,
        "progress clears the failure streak"
    );
    assert_eq!(pm.timeout_for_view(), Duration::from_millis(100));
}

#[test]
fn backoff_exponent_is_capped() {
    let mut pm = Pacemaker::new(Duration::from_millis(10));
    for v in 1..=(MAX_BACKOFF_EXPONENT as u64 + 20) {
        pm.advance_view(v);
    }
    // The applied exponent is capped even though the raw counter is higher.
    assert!(pm.consecutive_timeouts() > MAX_BACKOFF_EXPONENT);
    let capped = Duration::from_millis(10).mul_f64(1.2_f64.powi(MAX_BACKOFF_EXPONENT as i32));
    assert_eq!(
        pm.timeout_for_view(),
        capped,
        "timeout holds flat at the cap"
    );
}

#[test]
fn relayed_view_adoption_advances_and_counts_as_a_failed_view() {
    let mut pm = Pacemaker::new(Duration::from_millis(100));
    pm.adopt_relayed_view(4);
    assert_eq!(
        pm.current_view, 4,
        "adopts the relayed view without waiting out the timer"
    );
    assert_eq!(
        pm.consecutive_timeouts(),
        1,
        "the superseded views count toward backoff"
    );
    // A stale relayed view is ignored (monotonicity preserved).
    pm.adopt_relayed_view(2);
    assert_eq!(pm.current_view, 4);
}

#[test]
fn adaptive_backoff_lets_a_slow_view_complete_that_a_flat_timeout_would_miss() {
    // The R10 pathology: a base timeout shorter than the real post-partition
    // delay means a flat timeout can never let a view finish. With backoff,
    // after enough failed views the window exceeds the delay.
    let base = Duration::from_millis(50);
    let real_delay = Duration::from_millis(200);
    let mut pm = Pacemaker::new(base);
    assert!(
        pm.timeout_for_view() < real_delay,
        "flat base cannot cover the delay"
    );
    let mut advances = 0;
    while pm.timeout_for_view() <= real_delay && advances < 100 {
        pm.advance_view(pm.current_view + 1);
        advances += 1;
    }
    assert!(
        pm.timeout_for_view() > real_delay,
        "adaptive backoff eventually covers the real delay ({advances} views)"
    );
}
