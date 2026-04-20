use super::*;
use std::time::Duration;

#[test]
fn test_pin_and_unpin() {
    let pins = StateVersionPins::new();
    let height_to_pin = 42;

    pins.pin(height_to_pin);
    let snapshot = pins.snapshot();
    assert!(snapshot.contains(&height_to_pin));

    pins.unpin(height_to_pin);
    let snapshot = pins.snapshot();
    assert!(!snapshot.contains(&height_to_pin));
}

#[test]
fn test_pinguard_lifecycle() {
    let pins = Arc::new(StateVersionPins::new());
    let height_to_pin = 84;

    {
        let _guard = PinGuard::new(pins.clone(), height_to_pin);
        let snapshot = pins.snapshot();
        assert!(snapshot.contains(&height_to_pin));
    } // _guard is dropped here, calling sync unpin.

    let snapshot = pins.snapshot();
    assert!(!snapshot.contains(&height_to_pin));
}

#[test]
fn test_pinguard_drop_no_runtime() {
    let pins = Arc::new(StateVersionPins::new());
    let height_to_pin = 42;

    {
        let _guard = PinGuard::new(pins.clone(), height_to_pin);
        let snapshot = pins.snapshot();
        assert!(snapshot.contains(&height_to_pin));
    } // _guard is dropped here, calling synchronous, lock-free unpin.

    let snapshot = pins.snapshot();
    assert!(!snapshot.contains(&height_to_pin));
}

#[test]
fn test_multiple_pins() {
    let pins = Arc::new(StateVersionPins::new());
    let height = 100;

    let g1 = PinGuard::new(pins.clone(), height);
    let g2 = PinGuard::new(pins.clone(), height);

    assert!(pins.snapshot().contains(&height));

    drop(g1);
    // Still pinned by g2
    assert!(pins.snapshot().contains(&height));

    drop(g2);
    // All guards dropped, no longer pinned
    assert!(!pins.snapshot().contains(&height));
}

#[tokio::test]
async fn test_concurrent_pinning() {
    let pins = Arc::new(StateVersionPins::new());
    let height = 200;
    let num_tasks = 100;

    let mut handles = Vec::new();

    for _ in 0..num_tasks {
        let pins_clone = pins.clone();
        handles.push(tokio::spawn(async move {
            let _guard = PinGuard::new(pins_clone, height);
            // Hold the guard for a short, random time
            tokio::time::sleep(Duration::from_micros(rand::random::<u64>() % 1000)).await;
        }));
    }

    // Wait for all tasks to complete (and their guards to be dropped)
    futures_util::future::join_all(handles).await;

    // The final count should be zero, and the snapshot should be empty
    assert!(!pins.snapshot().contains(&height));
    assert!(
        pins.inner.get(&height).is_none()
            || pins.inner.get(&height).unwrap().load(Ordering::Acquire) == 0
    );
}
