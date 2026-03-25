use hvm::runtime::scheduler::{ThreadScheduler, WAIT_OBJECT_0, WAIT_TIMEOUT};
use hvm::runtime::thread_context::ThreadContext;
use hvm::runtime::windows_env::WindowsProcessEnvironment;

#[test]
fn create_thread_registers_ready_thread_and_tid() {
    let mut scheduler = ThreadScheduler::for_tests();
    let thread = scheduler
        .create_virtual_thread(0x401000, 0x4141, false)
        .unwrap();

    assert_eq!(thread.state, "ready");
    assert_eq!(thread.parameter, 0x4141);
    assert!(thread.tid != 0);
}

#[test]
fn run_slice_terminates_main_thread_and_records_exit_code() {
    let mut scheduler = ThreadScheduler::for_tests();
    let thread = scheduler.register_main_thread(0x401000).unwrap();
    let ready = scheduler.next_ready_thread().unwrap();

    assert_eq!(ready.tid, thread.tid);

    let consumed = scheduler.run_slice(thread.tid, 32).unwrap();

    assert_eq!(consumed, 32);
    assert_eq!(scheduler.thread_state(thread.tid).unwrap(), "terminated");
    assert_eq!(scheduler.thread_exit_code(thread.tid), Some(Some(0)));
}

#[test]
fn initialize_x86_thread_context_sets_entry_stack_and_flags() {
    let mut scheduler = ThreadScheduler::for_tests();
    let thread = scheduler
        .create_virtual_thread(0x401000, 0x4141, false)
        .unwrap();

    scheduler
        .initialize_x86_thread_context(
            thread.tid,
            ThreadContext {
                teb_base: 0x7000_0000,
                stack_base: 0x7020_0000,
                stack_limit: 0x7000_0000,
            },
            0x701F_F000,
            0xDEAD_C0DE,
        )
        .unwrap();

    let snapshot = scheduler.thread_snapshot(thread.tid).unwrap();

    assert_eq!(snapshot.registers.get("eip"), Some(&0x401000));
    assert_eq!(snapshot.registers.get("eflags"), Some(&0x202));
    assert_eq!(snapshot.registers.get("esp"), Some(&(0x701F_F000 - 8)));
    assert_eq!(snapshot.exit_address, 0xDEAD_C0DE);
    assert_eq!(snapshot.teb_base, 0x7000_0000);
    assert_eq!(snapshot.stack_base, 0x7020_0000);
    assert_eq!(snapshot.stack_limit, 0x7000_0000);
    assert_eq!(snapshot.stack_top, 0x701F_F000);
}

#[test]
fn switch_to_binds_current_thread_teb_in_process_environment() {
    let mut scheduler = ThreadScheduler::for_tests();
    let mut env = WindowsProcessEnvironment::for_tests_x86();
    let first = scheduler.register_main_thread(0x401000).unwrap();
    let second = scheduler
        .create_virtual_thread(0x402000, 0x5151, false)
        .unwrap();
    let first_ctx = env.allocate_thread_teb(0x7020_0000, 0x7000_0000).unwrap();
    let second_ctx = env.allocate_thread_teb(0x7040_0000, 0x7020_0000).unwrap();

    scheduler
        .initialize_x86_thread_context(first.tid, first_ctx, 0x701F_F000, 0xDEAD_C0DE)
        .unwrap();
    scheduler
        .initialize_x86_thread_context(second.tid, second_ctx, 0x703F_F000, 0xDEAD_C0DF)
        .unwrap();
    scheduler.switch_to(second.tid, &mut env).unwrap();

    assert_eq!(scheduler.current_tid(), Some(second.tid));
    assert_eq!(env.current_teb(), second_ctx.teb_base);
}

#[test]
fn wait_for_multiple_objects_returns_matching_index_and_resets_auto_event() {
    let mut scheduler = ThreadScheduler::for_tests();
    let first = scheduler.create_event(false, false).unwrap();
    let second = scheduler.create_event(false, true).unwrap();

    assert_eq!(
        scheduler.wait_for_multiple_objects(&[first.handle, second.handle], false, 0),
        WAIT_OBJECT_0 + 1
    );
    assert_eq!(
        scheduler.wait_for_single_object(second.handle, 0),
        WAIT_TIMEOUT
    );
}

#[test]
fn timed_wait_resumes_with_timeout_when_object_never_signals() {
    let mut scheduler = ThreadScheduler::for_tests();
    let thread = scheduler.register_main_thread(0x401000).unwrap();
    let event = scheduler.create_event(false, false).unwrap();

    assert!(scheduler
        .begin_wait_for_single_object(thread.tid, event.handle, 10, 25, false)
        .is_timeout());
    scheduler.poll_blocked_threads(34);
    assert_eq!(scheduler.thread_state(thread.tid), Some("waiting"));
    scheduler.poll_blocked_threads(35);
    assert_eq!(scheduler.resume_wait_result(thread.tid), Some(WAIT_TIMEOUT));
}
