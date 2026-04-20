use super::{has_secret, set_secret, take_secret};

#[test]
fn one_time_secret_is_consumed() {
    let session = "aa".repeat(32);
    set_secret(&session, "sudo_password", "pw1".to_string(), true, 60).expect("set secret");
    assert_eq!(
        take_secret(&session, "sudo_password").as_deref(),
        Some("pw1")
    );
    assert!(take_secret(&session, "sudo_password").is_none());
}

#[test]
fn reusable_secret_is_retained() {
    let session = "bb".repeat(32);
    set_secret(&session, "sudo_password", "pw2".to_string(), false, 60).expect("set secret");
    assert!(has_secret(&session, "sudo_password"));
    assert_eq!(
        take_secret(&session, "sudo_password").as_deref(),
        Some("pw2")
    );
    assert!(has_secret(&session, "sudo_password"));
    assert_eq!(
        take_secret(&session, "sudo_password").as_deref(),
        Some("pw2")
    );
}

#[test]
fn has_secret_tracks_one_time_consumption() {
    let session = "cc".repeat(32);
    set_secret(&session, "sudo_password", "pw3".to_string(), true, 60).expect("set secret");
    assert!(has_secret(&session, "sudo_password"));
    assert_eq!(
        take_secret(&session, "sudo_password").as_deref(),
        Some("pw3")
    );
    assert!(!has_secret(&session, "sudo_password"));
}
