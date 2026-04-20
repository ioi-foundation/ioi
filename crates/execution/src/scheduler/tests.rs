use super::{Scheduler, Task};

#[test]
fn abort_keeps_inflight_higher_tx_from_being_reissued() {
    let scheduler = Scheduler::new(3);

    assert_eq!(scheduler.next_task(), Task::Execute(0));
    assert_eq!(scheduler.next_task(), Task::Execute(1));

    scheduler.finish_execution(0);
    assert_eq!(scheduler.next_task(), Task::Validate(0));

    scheduler.abort_tx(0);

    // The aborted transaction should restart first, but tx 1 must not be handed out again
    // until its in-flight execution completes and transitions back to Ready.
    assert_eq!(scheduler.next_task(), Task::Execute(0));
    assert_eq!(scheduler.next_task(), Task::RetryLater);

    scheduler.finish_execution(1);
    scheduler.finish_execution(0);

    assert_eq!(scheduler.next_task(), Task::Validate(0));
    scheduler.finish_validation(0);
    assert_eq!(scheduler.next_task(), Task::Execute(1));
}

#[test]
fn stale_validation_completion_requeues_pending_tx() {
    let scheduler = Scheduler::new(2);

    assert_eq!(scheduler.next_task(), Task::Execute(0));
    assert_eq!(scheduler.next_task(), Task::Execute(1));
    scheduler.finish_execution(0);
    scheduler.finish_execution(1);

    assert_eq!(scheduler.next_task(), Task::Validate(0));
    scheduler.finish_validation(0);
    assert_eq!(scheduler.next_task(), Task::Validate(1));

    scheduler.abort_tx(0);
    scheduler.finish_validation(1);

    assert_eq!(scheduler.next_task(), Task::Execute(0));
    scheduler.finish_execution(0);
    assert_eq!(scheduler.next_task(), Task::Validate(0));
}
