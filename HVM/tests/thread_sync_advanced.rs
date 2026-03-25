use hvm::runtime::scheduler::{ThreadScheduler, WAIT_IO_COMPLETION};

#[test]
fn alertable_wait_returns_io_completion_after_apc() {
    let mut scheduler = ThreadScheduler::for_tests();
    let thread = scheduler.register_main_thread(0x401000).unwrap();
    let event = scheduler.create_event(false, false).unwrap();

    assert!(scheduler
        .begin_alertable_wait(thread.tid, event.handle, 100)
        .is_timeout());
    scheduler
        .queue_user_apc(thread.handle, 0x402000, 0x5151)
        .unwrap();
    scheduler.poll_blocked_threads(100);
    assert_eq!(
        scheduler.resume_wait_result(thread.tid).unwrap(),
        WAIT_IO_COMPLETION
    );
}
