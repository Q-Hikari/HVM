use hvm::runtime::scheduler::{ThreadScheduler, WAIT_OBJECT_0, WAIT_TIMEOUT};

#[test]
fn event_wait_times_out_then_wakes_after_signal() {
    let mut scheduler = ThreadScheduler::for_tests();
    let event = scheduler.create_event(false, false).unwrap();

    assert_eq!(
        scheduler.wait_for_single_object(event.handle, 50),
        WAIT_TIMEOUT
    );
    scheduler.set_event(event.handle).unwrap();
    scheduler.poll_blocked_threads(50);
    assert_eq!(
        scheduler.wait_for_single_object(event.handle, 50),
        WAIT_OBJECT_0
    );
}
