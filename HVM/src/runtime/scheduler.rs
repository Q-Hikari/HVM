use std::collections::{BTreeMap, VecDeque};

use crate::managers::handle_table::HandleTable;
use crate::runtime::thread_context::ThreadContext;
use crate::runtime::windows_env::WindowsProcessEnvironment;

/// Returned when a waited object is signaled.
pub const WAIT_OBJECT_0: u32 = 0;

/// Returned when a mutex was abandoned by its previous owner.
pub const WAIT_ABANDONED_0: u32 = 0x80;

/// Returned when a wait times out.
pub const WAIT_TIMEOUT: u32 = 0x102;

/// Returned when an alertable wait resumes to deliver queued APC work.
pub const WAIT_IO_COMPLETION: u32 = 0xC0;

/// Returned when the wait request itself fails.
pub const WAIT_FAILED: u32 = u32::MAX;

/// Models one dispatcher object such as a thread, event, mutex, or semaphore.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispatcherObject {
    pub handle: u32,
    pub kind: &'static str,
    pub signaled: bool,
    pub manual_reset: bool,
}

/// Stores the state tracked for one emulated thread.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreadRecord {
    pub tid: u32,
    pub handle: u32,
    pub start_address: u64,
    pub parameter: u64,
    pub teb_base: u64,
    pub stack_base: u64,
    pub stack_limit: u64,
    pub stack_top: u64,
    pub state: &'static str,
    pub exit_code: Option<u32>,
    pub exit_address: u64,
    pub registers: BTreeMap<String, u64>,
    pub instruction_count: u64,
    pub wake_tick: u64,
    pub wait_result: Option<u32>,
    pub wait_handles: Vec<u32>,
    pub wait_all: bool,
    pub alertable_wait: bool,
    pub apc_pending: bool,
}

/// Captures the immediate result of beginning a wait operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WaitOutcome(u32);

impl WaitOutcome {
    /// Returns whether the wait started in a timed-out state that still requires polling.
    pub fn is_timeout(self) -> bool {
        self.0 == WAIT_TIMEOUT
    }

    /// Returns the raw wait status.
    pub fn raw(self) -> u32 {
        self.0
    }
}

/// Schedules virtual threads and tracks their ready-state lifecycle.
#[derive(Debug)]
pub struct ThreadScheduler {
    next_tid: u32,
    handles: HandleTable,
    ready_queue: VecDeque<u32>,
    threads: BTreeMap<u32, ThreadRecord>,
    objects: BTreeMap<u32, DispatcherObject>,
    main_tid: Option<u32>,
    current_tid: Option<u32>,
    time_slice_instructions: u64,
    time_slice_ms: u64,
}

impl ThreadScheduler {
    /// Builds a test-only scheduler with the same base IDs as the Python runtime.
    pub fn for_tests() -> Self {
        Self {
            next_tid: 0x1001,
            handles: HandleTable::new(0x8000),
            ready_queue: VecDeque::new(),
            threads: BTreeMap::new(),
            objects: BTreeMap::new(),
            main_tid: None,
            current_tid: None,
            time_slice_instructions: 4_000,
            time_slice_ms: 1,
        }
    }

    /// Registers a new virtual thread and enqueues it when not suspended.
    pub fn create_virtual_thread(
        &mut self,
        start_address: u64,
        parameter: u64,
        suspended: bool,
    ) -> Option<ThreadRecord> {
        let tid = self.next_tid;
        self.next_tid = self.next_tid.saturating_add(1);
        let handle = self.handles.allocate("thread", ());
        let state = if suspended { "suspended" } else { "ready" };
        let thread = ThreadRecord {
            tid,
            handle,
            start_address,
            parameter,
            teb_base: 0,
            stack_base: 0,
            stack_limit: 0,
            stack_top: 0,
            state,
            exit_code: None,
            exit_address: 0,
            registers: BTreeMap::new(),
            instruction_count: 0,
            wake_tick: 0,
            wait_result: None,
            wait_handles: Vec::new(),
            wait_all: false,
            alertable_wait: false,
            apc_pending: false,
        };
        self.objects.insert(
            handle,
            DispatcherObject {
                handle,
                kind: "thread",
                signaled: false,
                manual_reset: true,
            },
        );
        if state == "ready" {
            self.ready_queue.push_back(tid);
        }
        self.threads.insert(tid, thread.clone());
        Some(thread)
    }

    /// Registers the primary thread used by future alertable-wait tests.
    pub fn register_main_thread(&mut self, start_address: u64) -> Option<ThreadRecord> {
        self.register_main_thread_with_parameter(start_address, 0)
    }

    /// Registers the primary thread with one explicit thread-parameter value.
    pub fn register_main_thread_with_parameter(
        &mut self,
        start_address: u64,
        parameter: u64,
    ) -> Option<ThreadRecord> {
        let thread = self.create_virtual_thread(start_address, parameter, false)?;
        self.main_tid = Some(thread.tid);
        self.current_tid = Some(thread.tid);
        Some(thread)
    }

    /// Returns the current state string for a thread identifier.
    pub fn thread_state(&self, tid: u32) -> Option<&'static str> {
        self.threads.get(&tid).map(|thread| thread.state)
    }

    /// Returns the recorded exit code for one thread when it exists.
    pub fn thread_exit_code(&self, tid: u32) -> Option<Option<u32>> {
        self.threads.get(&tid).map(|thread| thread.exit_code)
    }

    /// Returns a cloned thread snapshot for tests and runtime inspection.
    pub fn thread_snapshot(&self, tid: u32) -> Option<ThreadRecord> {
        self.threads.get(&tid).cloned()
    }

    /// Returns cloned snapshots for all currently tracked threads.
    pub fn thread_snapshots(&self) -> Vec<ThreadRecord> {
        self.threads.values().cloned().collect()
    }

    /// Returns the thread identifier associated with one thread handle.
    pub fn thread_tid_for_handle(&self, handle: u32) -> Option<u32> {
        self.threads
            .values()
            .find(|thread| thread.handle == handle)
            .map(|thread| thread.tid)
    }

    /// Returns the registered dispatcher-object kind for one handle when it exists.
    pub fn object_kind(&self, handle: u32) -> Option<&'static str> {
        self.objects.get(&handle).map(|object| object.kind)
    }

    /// Returns the main thread identifier tracked by the scheduler.
    pub fn main_tid(&self) -> Option<u32> {
        self.main_tid
    }

    /// Returns the currently selected thread identifier.
    pub fn current_tid(&self) -> Option<u32> {
        self.current_tid
    }

    /// Returns the fixed time-slice budget used by the Rust scaffold scheduler.
    pub fn time_slice_instructions(&self) -> u64 {
        self.time_slice_instructions
    }

    /// Returns the virtual milliseconds advanced after one completed scheduler slice.
    pub fn time_slice_ms(&self) -> u64 {
        self.time_slice_ms
    }

    /// Returns whether any thread remains live enough to keep the scheduler loop running.
    pub fn has_live_threads(&self) -> bool {
        self.threads
            .values()
            .any(|thread| thread.state != "terminated")
    }

    /// Dequeues the next runnable thread and marks it as current.
    pub fn next_ready_thread(&mut self) -> Option<ThreadRecord> {
        while let Some(tid) = self.ready_queue.pop_front() {
            let thread = self.threads.get_mut(&tid)?;
            if thread.state != "ready" {
                continue;
            }
            thread.state = "running";
            self.current_tid = Some(tid);
            return Some(thread.clone());
        }
        None
    }

    /// Switches the active runtime binding to one thread and rebinds its current TEB mirror.
    pub fn switch_to(
        &mut self,
        tid: u32,
        process_env: &mut WindowsProcessEnvironment,
    ) -> Option<()> {
        let teb_base = self.threads.get(&tid)?.teb_base;
        process_env.bind_current_thread(teb_base).ok()?;
        self.current_tid = Some(tid);
        Some(())
    }

    /// Initializes the x86 register frame for one thread after the engine has allocated its stack.
    pub fn initialize_x86_thread_context(
        &mut self,
        tid: u32,
        thread_context: ThreadContext,
        stack_top: u64,
        exit_address: u64,
    ) -> Option<()> {
        let stack_pointer = stack_top.checked_sub(8)?;
        let thread = self.threads.get_mut(&tid)?;
        thread.teb_base = thread_context.teb_base;
        thread.stack_base = thread_context.stack_base;
        thread.stack_limit = thread_context.stack_limit;
        thread.stack_top = stack_top;
        thread.exit_address = exit_address;
        thread.registers = BTreeMap::from([
            ("eip".to_string(), thread.start_address),
            ("esp".to_string(), stack_pointer),
            ("eflags".to_string(), 0x202),
        ]);
        Some(())
    }

    /// Initializes the x64 register frame for one thread after the engine has allocated its stack.
    pub fn initialize_x64_thread_context(
        &mut self,
        tid: u32,
        thread_context: ThreadContext,
        stack_top: u64,
        exit_address: u64,
    ) -> Option<()> {
        let stack_pointer = stack_top.checked_sub(0x28)?;
        let thread = self.threads.get_mut(&tid)?;
        thread.teb_base = thread_context.teb_base;
        thread.stack_base = thread_context.stack_base;
        thread.stack_limit = thread_context.stack_limit;
        thread.stack_top = stack_top;
        thread.exit_address = exit_address;
        thread.registers = BTreeMap::from([
            ("rax".to_string(), 0),
            ("rbx".to_string(), 0),
            ("rcx".to_string(), thread.parameter),
            ("rdx".to_string(), 0),
            ("rsi".to_string(), 0),
            ("rdi".to_string(), 0),
            ("rbp".to_string(), 0),
            ("rsp".to_string(), stack_pointer),
            ("rip".to_string(), thread.start_address),
            ("r8".to_string(), 0),
            ("r9".to_string(), 0),
            ("r10".to_string(), 0),
            ("r11".to_string(), 0),
            ("r12".to_string(), 0),
            ("r13".to_string(), 0),
            ("r14".to_string(), 0),
            ("r15".to_string(), 0),
            ("rflags".to_string(), 0x202),
        ]);
        Some(())
    }

    /// Updates the saved entrypoint metadata for one tracked thread.
    pub fn set_thread_start_address(&mut self, tid: u32, start_address: u64) -> Option<()> {
        let thread = self.threads.get_mut(&tid)?;
        thread.start_address = start_address;
        Some(())
    }

    /// Updates the saved parameter metadata for one tracked thread.
    pub fn set_thread_parameter(&mut self, tid: u32, parameter: u64) -> Option<()> {
        let thread = self.threads.get_mut(&tid)?;
        thread.parameter = parameter;
        Some(())
    }

    /// Updates the saved exit sentinel for one tracked thread.
    pub fn set_thread_exit_address(&mut self, tid: u32, exit_address: u64) -> Option<()> {
        let thread = self.threads.get_mut(&tid)?;
        thread.exit_address = exit_address;
        Some(())
    }

    /// Replaces the saved CPU register frame for one tracked thread.
    pub fn set_thread_registers(
        &mut self,
        tid: u32,
        registers: BTreeMap<String, u64>,
    ) -> Option<()> {
        let thread = self.threads.get_mut(&tid)?;
        thread.registers = registers;
        Some(())
    }

    /// Marks one live thread as ready for another scheduler slice.
    pub fn mark_thread_ready(&mut self, tid: u32) -> Option<()> {
        self.remove_ready_thread(tid);
        let thread = self.threads.get_mut(&tid)?;
        if thread.state == "terminated" {
            return Some(());
        }
        thread.state = "ready";
        self.ready_queue.push_back(tid);
        Some(())
    }

    /// Simulates one time slice for the selected thread and terminates it with a zero exit code.
    pub fn run_slice(&mut self, tid: u32, instruction_budget: u64) -> Option<u64> {
        let consumed = instruction_budget.max(1);
        let thread = self.threads.get_mut(&tid)?;
        if !matches!(thread.state, "running" | "ready") {
            return None;
        }
        thread.instruction_count = thread.instruction_count.saturating_add(consumed);
        thread.state = "running";
        self.current_tid = Some(tid);
        self.exit_current_thread(0)?;
        Some(consumed)
    }

    /// Marks the current thread as terminated and signals any waiters on its thread handle.
    pub fn exit_current_thread(&mut self, exit_code: u32) -> Option<()> {
        let tid = self.current_tid?;
        let handle = {
            let thread = self.threads.get_mut(&tid)?;
            thread.state = "terminated";
            thread.exit_code = Some(exit_code);
            thread.wake_tick = 0;
            thread.wait_handles.clear();
            thread.wait_result = None;
            thread.wait_all = false;
            thread.alertable_wait = false;
            thread.apc_pending = false;
            thread.handle
        };
        if let Some(object) = self.objects.get_mut(&handle) {
            object.signaled = true;
        }
        self.current_tid = None;
        self.notify_waitable_state(handle);
        Some(())
    }

    /// Creates an event object with the requested reset mode and initial state.
    pub fn create_event(
        &mut self,
        manual_reset: bool,
        initial_state: bool,
    ) -> Option<DispatcherObject> {
        let handle = self.handles.allocate("event", ());
        let event = DispatcherObject {
            handle,
            kind: "event",
            signaled: initial_state,
            manual_reset,
        };
        self.objects.insert(handle, event.clone());
        Some(event)
    }

    /// Registers one externally allocated dispatcher object so wait APIs can observe it.
    pub fn register_external_object(
        &mut self,
        handle: u32,
        kind: &'static str,
        signaled: bool,
        manual_reset: bool,
    ) -> DispatcherObject {
        let object = DispatcherObject {
            handle,
            kind,
            signaled,
            manual_reset,
        };
        self.objects.insert(handle, object.clone());
        object
    }

    /// Waits on a single dispatcher object, returning immediately for the supported event semantics.
    pub fn wait_for_single_object(&mut self, handle: u32, _timeout_ms: u32) -> u32 {
        self.wait_for_multiple_objects(&[handle], false, _timeout_ms)
    }

    /// Waits on multiple dispatcher objects and returns the first satisfied index or timeout.
    pub fn wait_for_multiple_objects(
        &mut self,
        handles: &[u32],
        wait_all: bool,
        _timeout_ms: u32,
    ) -> u32 {
        let Some(status) = self.evaluate_wait(handles, wait_all) else {
            return WAIT_TIMEOUT;
        };
        self.consume_wait_status(handles, wait_all, status);
        status
    }

    /// Begins an alertable wait for one specific thread and object handle.
    pub fn begin_alertable_wait(&mut self, tid: u32, handle: u32, timeout_ms: u32) -> WaitOutcome {
        self.begin_wait_for_multiple_objects(tid, &[handle], false, 0, timeout_ms, true)
    }

    /// Begins a scheduler-visible wait on one specific handle.
    pub fn begin_wait_for_single_object(
        &mut self,
        tid: u32,
        handle: u32,
        now_tick: u64,
        timeout_ms: u32,
        alertable: bool,
    ) -> WaitOutcome {
        self.begin_wait_for_multiple_objects(tid, &[handle], false, now_tick, timeout_ms, alertable)
    }

    /// Begins a scheduler-visible wait on one or more handles.
    pub fn begin_wait_for_multiple_objects(
        &mut self,
        tid: u32,
        handles: &[u32],
        wait_all: bool,
        now_tick: u64,
        timeout_ms: u32,
        alertable: bool,
    ) -> WaitOutcome {
        if let Some(status) = self.evaluate_wait(handles, wait_all) {
            self.consume_wait_status(handles, wait_all, status);
            return WaitOutcome(status);
        }
        if timeout_ms == 0 {
            return WaitOutcome(WAIT_TIMEOUT);
        }
        self.remove_ready_thread(tid);
        let Some(thread) = self.threads.get_mut(&tid) else {
            return WaitOutcome(WAIT_TIMEOUT);
        };
        thread.state = "waiting";
        thread.wake_tick = if timeout_ms == u32::MAX {
            0
        } else {
            now_tick.saturating_add(timeout_ms as u64)
        };
        thread.wait_handles = handles.to_vec();
        thread.wait_result = None;
        thread.wait_all = wait_all;
        thread.alertable_wait = alertable;
        WaitOutcome(WAIT_TIMEOUT)
    }

    /// Begins a scheduler-visible sleep that completes when the virtual wake tick is reached.
    pub fn sleep_current_thread(
        &mut self,
        now_tick: u64,
        milliseconds: u32,
        alertable: bool,
    ) -> Option<()> {
        let tid = self.current_tid?;
        self.remove_ready_thread(tid);
        let thread = self.threads.get_mut(&tid)?;
        thread.state = "sleeping";
        thread.wake_tick = now_tick.saturating_add(milliseconds as u64);
        thread.wait_handles.clear();
        thread.wait_result = None;
        thread.wait_all = false;
        thread.alertable_wait = alertable;
        Some(())
    }

    /// Marks the current running thread as ready again and enqueues it for later execution.
    pub fn yield_current_thread(&mut self) -> Option<()> {
        let tid = self.current_tid?;
        let thread = self.threads.get_mut(&tid)?;
        if thread.state == "running" {
            thread.state = "ready";
            self.ready_queue.push_back(tid);
        }
        Some(())
    }

    /// Returns and clears the stored wait result for the currently selected thread.
    pub fn consume_wait_result(&mut self) -> Option<u32> {
        let tid = self.current_tid?;
        let thread = self.threads.get_mut(&tid)?;
        let result = thread.wait_result.take()?;
        thread.wake_tick = 0;
        thread.wait_handles.clear();
        Some(result)
    }

    /// Returns the earliest virtual wake tick for any sleeping thread.
    pub fn next_wake_tick(&self) -> Option<u64> {
        self.threads
            .values()
            .filter(|thread| {
                (thread.state == "sleeping" || thread.state == "waiting") && thread.wake_tick != 0
            })
            .map(|thread| thread.wake_tick)
            .min()
    }

    /// Queues one APC for the thread referenced by the given thread handle.
    pub fn queue_user_apc(
        &mut self,
        thread_handle: u32,
        _routine: u64,
        _parameter: u64,
    ) -> Option<()> {
        let tid = self
            .threads
            .values()
            .find(|thread| thread.handle == thread_handle)
            .map(|thread| thread.tid)?;
        let thread = self.threads.get_mut(&tid)?;
        thread.apc_pending = true;
        Some(())
    }

    /// Sets an event to the signaled state.
    pub fn set_event(&mut self, handle: u32) -> Option<()> {
        let object = self.objects.get_mut(&handle)?;
        if object.kind != "event" {
            return None;
        }
        object.signaled = true;
        self.notify_waitable_state(handle);
        Some(())
    }

    /// Resets an event to the non-signaled state.
    pub fn reset_event(&mut self, handle: u32) -> Option<()> {
        let object = self.objects.get_mut(&handle)?;
        if object.kind != "event" {
            return None;
        }
        object.signaled = false;
        Some(())
    }

    /// Marks one dispatcher object as signaled and wakes any waiting threads.
    pub fn signal_object(&mut self, handle: u32) -> Option<()> {
        let object = self.objects.get_mut(&handle)?;
        object.signaled = true;
        self.notify_waitable_state(handle);
        Some(())
    }

    /// Marks one dispatcher object as non-signaled without waking waiters.
    pub fn clear_object_signal(&mut self, handle: u32) -> Option<()> {
        let object = self.objects.get_mut(&handle)?;
        object.signaled = false;
        Some(())
    }

    /// Polls blocked threads and returns any awakened thread identifiers.
    pub fn poll_blocked_threads(&mut self, _now_tick: u64) -> Vec<u32> {
        let mut awakened = Vec::new();
        let tids: Vec<u32> = self.threads.keys().copied().collect();
        for tid in tids {
            let Some(thread) = self.threads.get(&tid).cloned() else {
                continue;
            };
            if thread.state == "sleeping" && thread.alertable_wait && thread.apc_pending {
                self.finish_sleep_or_wait(tid, WAIT_IO_COMPLETION);
                awakened.push(tid);
            } else if thread.state == "sleeping" && thread.wake_tick <= _now_tick {
                self.finish_sleep_or_wait(tid, WAIT_OBJECT_0);
                awakened.push(tid);
            } else if thread.state == "waiting" && thread.alertable_wait && thread.apc_pending {
                self.finish_sleep_or_wait(tid, WAIT_IO_COMPLETION);
                awakened.push(tid);
            } else if thread.state == "waiting" {
                if let Some(status) = self.evaluate_wait(&thread.wait_handles, thread.wait_all) {
                    self.finish_wait(tid, status);
                    awakened.push(tid);
                } else if thread.wake_tick != 0 && thread.wake_tick <= _now_tick {
                    self.finish_wait(tid, WAIT_TIMEOUT);
                    awakened.push(tid);
                }
            }
        }
        awakened
    }

    /// Wakes blocked waiters when a dispatcher object changes state.
    pub fn notify_waitable_state(&mut self, handle: u32) -> Vec<u32> {
        let mut awakened = Vec::new();
        let signal_state = self.objects.get(&handle).map(|object| object.signaled);
        if signal_state != Some(true) {
            return awakened;
        }

        let tids: Vec<u32> = self
            .threads
            .iter()
            .filter(|(_, thread)| {
                thread.state == "waiting" && thread.wait_handles.contains(&handle)
            })
            .map(|(tid, _)| *tid)
            .collect();
        for tid in tids {
            let Some(thread) = self.threads.get(&tid).cloned() else {
                continue;
            };
            if let Some(status) = self.evaluate_wait(&thread.wait_handles, thread.wait_all) {
                self.finish_wait(tid, status);
                awakened.push(tid);
            }
        }
        awakened
    }

    /// Returns and clears the stored wait result for a thread that has resumed.
    pub fn resume_wait_result(&mut self, tid: u32) -> Option<u32> {
        let thread = self.threads.get_mut(&tid)?;
        let result = thread.wait_result.take()?;
        thread.wake_tick = 0;
        thread.wait_handles.clear();
        Some(result)
    }

    /// Resumes a suspended thread and returns the previous suspend count.
    pub fn resume_thread(&mut self, handle: u32) -> Option<u32> {
        let tid = self.thread_tid_for_handle(handle)?;
        let thread = self.threads.get_mut(&tid)?;
        if thread.state == "suspended" {
            thread.state = "ready";
            self.ready_queue.push_back(tid);
            Some(1)
        } else {
            Some(0)
        }
    }

    fn remove_ready_thread(&mut self, tid: u32) {
        self.ready_queue = self
            .ready_queue
            .drain(..)
            .filter(|queued| *queued != tid)
            .collect();
    }

    fn evaluate_wait(&self, handles: &[u32], wait_all: bool) -> Option<u32> {
        if handles.is_empty() {
            return None;
        }
        if wait_all {
            handles
                .iter()
                .all(|handle| self.object_signaled(*handle))
                .then_some(WAIT_OBJECT_0)
        } else {
            handles
                .iter()
                .position(|handle| self.object_signaled(*handle))
                .map(|index| WAIT_OBJECT_0 + index as u32)
        }
    }

    fn object_signaled(&self, handle: u32) -> bool {
        self.objects
            .get(&handle)
            .map(|object| object.signaled)
            .unwrap_or(false)
    }

    fn consume_wait_status(&mut self, handles: &[u32], wait_all: bool, status: u32) {
        if status < WAIT_OBJECT_0 {
            return;
        }
        if wait_all {
            for handle in handles {
                self.consume_object_signal(*handle);
            }
            return;
        }
        let index = status.saturating_sub(WAIT_OBJECT_0) as usize;
        if let Some(handle) = handles.get(index) {
            self.consume_object_signal(*handle);
        }
    }

    fn consume_object_signal(&mut self, handle: u32) {
        let Some(object) = self.objects.get_mut(&handle) else {
            return;
        };
        if object.signaled && !object.manual_reset {
            object.signaled = false;
        }
    }

    fn finish_sleep_or_wait(&mut self, tid: u32, result: u32) {
        let Some(thread) = self.threads.get_mut(&tid) else {
            return;
        };
        thread.state = "ready";
        thread.wake_tick = 0;
        thread.wait_result = Some(result);
        thread.wait_handles.clear();
        thread.wait_all = false;
        thread.alertable_wait = false;
        thread.apc_pending = false;
        self.ready_queue.push_back(thread.tid);
    }

    fn finish_wait(&mut self, tid: u32, result: u32) {
        let Some(snapshot) = self.threads.get(&tid).cloned() else {
            return;
        };
        if result != WAIT_TIMEOUT && result != WAIT_IO_COMPLETION {
            self.consume_wait_status(&snapshot.wait_handles, snapshot.wait_all, result);
        }
        self.finish_sleep_or_wait(tid, result);
    }
}
