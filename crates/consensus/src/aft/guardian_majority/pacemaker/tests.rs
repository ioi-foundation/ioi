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
