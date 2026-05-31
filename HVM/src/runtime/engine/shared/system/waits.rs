use super::*;

impl VirtualExecutionEngine {
    pub(in crate::runtime::engine) fn read_wait_handles(
        &self,
        count: usize,
        handles_ptr: u64,
    ) -> Result<Vec<u32>, VmError> {
        (0..count)
            .map(|index| {
                let slot = handles_ptr + index as u64 * self.core.arch.pointer_size as u64;
                Ok(if self.core.arch.is_x86() {
                    self.read_u32(slot)?
                } else {
                    u64::from_le_bytes(self.read_bytes_from_memory(slot, 8)?.try_into().unwrap())
                        as u32
                })
            })
            .collect()
    }

    pub(in crate::runtime::engine) fn wait_for_objects(
        &mut self,
        handles: &[u32],
        wait_all: bool,
        timeout_ms: u32,
        alertable: bool,
    ) -> Result<u64, VmError> {
        if handles.len() == 1 && self.mutex_owned_by_current_thread(handles[0]) {
            if let Some(owner_tid) = self.core.scheduler.current_tid() {
                let _ = self.acquire_mutex_handle(handles[0], owner_tid);
            }
            return Ok(crate::runtime::scheduler::WAIT_OBJECT_0 as u64);
        }

        if let Some(result) = self.core.scheduler.consume_wait_result() {
            let finalized = self.finalize_wait_result_object_acquisition(handles, wait_all, result);
            // Yield if other threads are ready so a thread waking from a
            // blocking wait does not starve other runnable threads.
            if timeout_ms != 0 && self.core.scheduler.has_ready_threads() {
                self.request_thread_yield("wait_consume", false);
            }
            return Ok(finalized as u64);
        }

        let normalized_handles = self.normalize_wait_handles(handles);
        if normalized_handles
            .iter()
            .any(|handle| !self.waitable_object_exists(*handle))
        {
            self.set_last_error(ERROR_INVALID_HANDLE as u32);
            return Ok(crate::runtime::scheduler::WAIT_FAILED as u64);
        }

        let immediate =
            self.core
                .scheduler
                .wait_for_multiple_objects(&normalized_handles, wait_all, 0);
        if immediate != WAIT_TIMEOUT as u32
            || timeout_ms == 0
            || self.core.scheduler.current_tid().is_none()
        {
            // When the wait is immediately satisfied but the caller intended to
            // block (timeout != 0) and other threads are ready, yield so that a
            // busy-waiting thread cannot monopolize the interpreter.
            if immediate != WAIT_TIMEOUT as u32
                && timeout_ms != 0
                && self.core.scheduler.has_ready_threads()
            {
                self.request_thread_yield("wait_immediate", false);
            }
            let finalized =
                self.finalize_wait_result_object_acquisition(handles, wait_all, immediate);
            return Ok(finalized as u64);
        }

        // When all waited handles are thread objects, use infinite timeout so the
        // child thread gets enough virtual time to complete its work.  Finite
        // timeouts are measured in virtual wall-clock time which advances 1 ms
        // per scheduler tick regardless of how many instructions the child
        // actually executed, so short timeouts can expire before the child
        // thread finishes.  The thread will still wake on WAIT_OBJECT_0 when
        // the child thread terminates.
        let effective_timeout = if normalized_handles
            .iter()
            .all(|h| self.core.scheduler.object_kind(*h) == Some("thread"))
        {
            u32::MAX
        } else {
            timeout_ms
        };

        let tid = self
            .core
            .scheduler
            .current_tid()
            .ok_or(VmError::RuntimeInvariant(
                "current thread missing during wait",
            ))?;
        let outcome = self.core.scheduler.begin_wait_for_multiple_objects(
            tid,
            &normalized_handles,
            wait_all,
            self.dispatch.time.current().tick_ms,
            effective_timeout,
            alertable,
        );
        if outcome.is_timeout() {
            self.request_thread_yield("wait", true);
        }
        Ok(outcome.raw() as u64)
    }

    pub(in crate::runtime::engine) fn signal_object_and_wait(
        &mut self,
        signal_handle: u32,
        wait_handle: u32,
        timeout_ms: u32,
        alertable: bool,
    ) -> Result<u64, VmError> {
        if let Some(result) = self.core.scheduler.consume_wait_result() {
            let finalized =
                self.finalize_wait_result_object_acquisition(&[wait_handle], false, result);
            return Ok(finalized as u64);
        }
        if let Err(error) = self.signal_waitable_object(signal_handle) {
            self.set_last_error(error);
            return Ok(crate::runtime::scheduler::WAIT_FAILED as u64);
        }
        self.wait_for_objects(&[wait_handle], false, timeout_ms, alertable)
    }

    pub(in crate::runtime::engine) fn create_mutex_handle(
        &mut self,
        raw_name: &str,
        initial_owner: bool,
    ) -> u64 {
        let name = raw_name.trim().to_ascii_lowercase();
        if !name.is_empty() {
            if let Some(&canonical) = self.sync.named_mutexes.get(&name) {
                let alias = self.handles.next_object_handle;
                self.handles.next_object_handle = self.handles.next_object_handle.saturating_add(4);
                self.sync.mutex_handles.insert(alias);
                self.sync.mutex_handle_targets.insert(alias, canonical);
                self.set_last_error(ERROR_ALREADY_EXISTS as u32);
                return alias as u64;
            }
        }

        let handle = self.handles.next_object_handle;
        self.handles.next_object_handle = self.handles.next_object_handle.saturating_add(4);
        self.sync.mutex_handles.insert(handle);
        self.sync.mutex_handle_targets.insert(handle, handle);
        let owner_tid = if initial_owner {
            self.core.scheduler.current_tid()
        } else {
            None
        };
        self.sync.mutex_states.insert(
            handle,
            MutexState {
                owner_tid,
                recursion_count: if owner_tid.is_some() { 1 } else { 0 },
                abandoned: false,
            },
        );
        self.core
            .scheduler
            .register_external_object(handle, "mutex", owner_tid.is_none(), false);
        if !name.is_empty() {
            self.sync.named_mutexes.insert(name, handle);
        }
        self.set_last_error(ERROR_SUCCESS as u32);
        handle as u64
    }

    pub(in crate::runtime::engine) fn open_mutex_handle(&mut self, raw_name: &str) -> u64 {
        let name = raw_name.trim().to_ascii_lowercase();
        let Some(&canonical) = self.sync.named_mutexes.get(&name) else {
            self.set_last_error(ERROR_FILE_NOT_FOUND as u32);
            return 0;
        };

        let alias = self.handles.next_object_handle;
        self.handles.next_object_handle = self.handles.next_object_handle.saturating_add(4);
        self.sync.mutex_handles.insert(alias);
        self.sync.mutex_handle_targets.insert(alias, canonical);
        self.set_last_error(ERROR_SUCCESS as u32);
        alias as u64
    }

    pub(in crate::runtime::engine) fn create_semaphore_handle(
        &mut self,
        raw_name: &str,
        initial_count: u32,
        maximum_count: u32,
    ) -> u64 {
        if maximum_count == 0 || initial_count > maximum_count {
            self.set_last_error(ERROR_INVALID_PARAMETER as u32);
            return 0;
        }

        let name = raw_name.trim().to_ascii_lowercase();
        if !name.is_empty() {
            if let Some(&canonical) = self.sync.named_semaphores.get(&name) {
                let alias = self.handles.next_object_handle;
                self.handles.next_object_handle = self.handles.next_object_handle.saturating_add(4);
                self.sync.semaphore_handles.insert(alias);
                self.sync.semaphore_handle_targets.insert(alias, canonical);
                self.set_last_error(ERROR_ALREADY_EXISTS as u32);
                return alias as u64;
            }
        }

        let handle = self.handles.next_object_handle;
        self.handles.next_object_handle = self.handles.next_object_handle.saturating_add(4);
        self.sync.semaphore_handles.insert(handle);
        self.sync.semaphore_handle_targets.insert(handle, handle);
        self.sync.semaphore_states.insert(
            handle,
            SemaphoreState {
                current_count: initial_count,
                maximum_count,
            },
        );
        self.core.scheduler.register_external_object(
            handle,
            "semaphore",
            initial_count != 0,
            false,
        );
        if !name.is_empty() {
            self.sync.named_semaphores.insert(name, handle);
        }
        self.set_last_error(ERROR_SUCCESS as u32);
        handle as u64
    }

    pub(in crate::runtime::engine) fn open_semaphore_handle(&mut self, raw_name: &str) -> u64 {
        let name = raw_name.trim().to_ascii_lowercase();
        let Some(&canonical) = self.sync.named_semaphores.get(&name) else {
            self.set_last_error(ERROR_FILE_NOT_FOUND as u32);
            return 0;
        };

        let alias = self.handles.next_object_handle;
        self.handles.next_object_handle = self.handles.next_object_handle.saturating_add(4);
        self.sync.semaphore_handles.insert(alias);
        self.sync.semaphore_handle_targets.insert(alias, canonical);
        self.set_last_error(ERROR_SUCCESS as u32);
        alias as u64
    }

    pub(in crate::runtime::engine) fn resolve_wait_handle(&self, handle: u32) -> u32 {
        self.sync
            .mutex_handle_targets
            .get(&handle)
            .copied()
            .or_else(|| self.sync.semaphore_handle_targets.get(&handle).copied())
            .unwrap_or(handle)
    }

    pub(in crate::runtime::engine) fn normalize_wait_handles(&self, handles: &[u32]) -> Vec<u32> {
        handles
            .iter()
            .map(|handle| self.resolve_wait_handle(*handle))
            .collect()
    }

    pub(in crate::runtime::engine) fn waitable_object_exists(&self, handle: u32) -> bool {
        self.core
            .scheduler
            .object_kind(self.resolve_wait_handle(handle))
            .is_some()
    }

    pub(in crate::runtime::engine) fn mutex_owned_by_current_thread(&self, handle: u32) -> bool {
        let Some(current_tid) = self.core.scheduler.current_tid() else {
            return false;
        };
        let canonical = self.resolve_wait_handle(handle);
        self.sync
            .mutex_states
            .get(&canonical)
            .and_then(|state| state.owner_tid)
            == Some(current_tid)
    }

    pub(in crate::runtime::engine) fn finalize_wait_result_object_acquisition(
        &mut self,
        handles: &[u32],
        wait_all: bool,
        result: u32,
    ) -> u32 {
        if result < crate::runtime::scheduler::WAIT_OBJECT_0
            || result == crate::runtime::scheduler::WAIT_TIMEOUT
            || result == crate::runtime::scheduler::WAIT_IO_COMPLETION
            || result == crate::runtime::scheduler::WAIT_FAILED
        {
            return result;
        }
        let Some(owner_tid) = self.core.scheduler.current_tid() else {
            return result;
        };
        if wait_all {
            let mut abandoned = false;
            for handle in handles {
                if let Some(acquired_abandoned) =
                    self.acquire_mutex_handle_with_state(*handle, owner_tid)
                {
                    abandoned |= acquired_abandoned;
                } else if self
                    .core
                    .scheduler
                    .object_kind(self.resolve_wait_handle(*handle))
                    == Some("semaphore")
                {
                    let _ = self.acquire_semaphore_handle(*handle);
                }
            }
            return if abandoned {
                crate::runtime::scheduler::WAIT_ABANDONED_0
            } else {
                result
            };
        }
        let index = result.saturating_sub(crate::runtime::scheduler::WAIT_OBJECT_0) as usize;
        if let Some(handle) = handles.get(index) {
            if self
                .acquire_mutex_handle_with_state(*handle, owner_tid)
                .unwrap_or(false)
            {
                return crate::runtime::scheduler::WAIT_ABANDONED_0 + index as u32;
            }
            let _ = self.acquire_semaphore_handle(*handle);
        }
        result
    }

    pub(in crate::runtime::engine) fn acquire_mutex_handle(
        &mut self,
        handle: u32,
        owner_tid: u32,
    ) -> bool {
        self.acquire_mutex_handle_with_state(handle, owner_tid)
            .is_some()
    }

    pub(in crate::runtime::engine) fn acquire_mutex_handle_with_state(
        &mut self,
        handle: u32,
        owner_tid: u32,
    ) -> Option<bool> {
        let canonical = self.resolve_wait_handle(handle);
        let Some(state) = self.sync.mutex_states.get_mut(&canonical) else {
            return None;
        };
        if state.owner_tid == Some(owner_tid) {
            state.recursion_count = state.recursion_count.saturating_add(1);
            return Some(false);
        }
        if state.owner_tid.is_some() {
            return None;
        }
        let abandoned = state.abandoned;
        state.abandoned = false;
        state.owner_tid = Some(owner_tid);
        state.recursion_count = 1;
        let _ = self.core.scheduler.clear_object_signal(canonical);
        Some(abandoned)
    }

    pub(in crate::runtime::engine) fn release_mutex_handle(&mut self, handle: u32) -> bool {
        let Some(owner_tid) = self.core.scheduler.current_tid() else {
            return false;
        };
        let canonical = self.resolve_wait_handle(handle);
        let Some(state) = self.sync.mutex_states.get_mut(&canonical) else {
            return false;
        };
        if state.owner_tid != Some(owner_tid) || state.recursion_count == 0 {
            return false;
        }
        state.recursion_count -= 1;
        if state.recursion_count == 0 {
            state.owner_tid = None;
            state.abandoned = false;
            let _ = self.core.scheduler.signal_object(canonical);
        }
        true
    }

    pub(in crate::runtime::engine) fn acquire_semaphore_handle(&mut self, handle: u32) -> bool {
        let canonical = self.resolve_wait_handle(handle);
        let Some(state) = self.sync.semaphore_states.get_mut(&canonical) else {
            return false;
        };
        if state.current_count == 0 {
            let _ = self.core.scheduler.clear_object_signal(canonical);
            return false;
        }
        state.current_count -= 1;
        if state.current_count == 0 {
            let _ = self.core.scheduler.clear_object_signal(canonical);
        } else {
            let _ = self.core.scheduler.signal_object(canonical);
        }
        true
    }

    pub(in crate::runtime::engine) fn release_semaphore_handle(
        &mut self,
        handle: u32,
        release_count: u32,
        previous_count_ptr: u64,
    ) -> Result<bool, VmError> {
        if release_count == 0 {
            self.set_last_error(ERROR_INVALID_PARAMETER as u32);
            return Ok(false);
        }

        let canonical = self.resolve_wait_handle(handle);
        let Some((previous_count, next_count)) =
            self.sync.semaphore_states.get(&canonical).map(|state| {
                (
                    state.current_count,
                    state.current_count.saturating_add(release_count),
                )
            })
        else {
            self.set_last_error(ERROR_INVALID_HANDLE as u32);
            return Ok(false);
        };
        let maximum_count = self
            .sync
            .semaphore_states
            .get(&canonical)
            .map(|state| state.maximum_count)
            .unwrap_or(0);
        if next_count > maximum_count {
            self.set_last_error(ERROR_TOO_MANY_POSTS as u32);
            return Ok(false);
        }
        if previous_count_ptr != 0 {
            self.write_u32(previous_count_ptr, previous_count)?;
        }
        if let Some(state) = self.sync.semaphore_states.get_mut(&canonical) {
            state.current_count = next_count;
        }
        let _ = self.core.scheduler.signal_object(canonical);
        self.set_last_error(ERROR_SUCCESS as u32);
        Ok(true)
    }

    pub(in crate::runtime::engine) fn abandon_mutexes_owned_by_thread(&mut self, owner_tid: u32) {
        let owned: Vec<u32> = self
            .sync
            .mutex_states
            .iter()
            .filter_map(|(handle, state)| {
                (state.owner_tid == Some(owner_tid) && state.recursion_count != 0)
                    .then_some(*handle)
            })
            .collect();
        for handle in owned {
            if let Some(state) = self.sync.mutex_states.get_mut(&handle) {
                state.owner_tid = None;
                state.recursion_count = 0;
                state.abandoned = true;
            }
            let _ = self.core.scheduler.signal_object(handle);
        }
    }

    pub(in crate::runtime::engine) fn signal_waitable_object(
        &mut self,
        handle: u32,
    ) -> Result<(), u32> {
        let canonical = self.resolve_wait_handle(handle);
        match self.core.scheduler.object_kind(canonical) {
            Some("event") => {
                let _ = self.core.scheduler.signal_object(canonical);
                Ok(())
            }
            Some("mutex") => {
                if self.release_mutex_handle(handle) {
                    Ok(())
                } else {
                    Err(ERROR_NOT_OWNER as u32)
                }
            }
            Some(_) => Err(ERROR_INVALID_HANDLE as u32),
            None => Err(ERROR_INVALID_HANDLE as u32),
        }
    }

    pub(in crate::runtime::engine) fn terminate_current_thread(&mut self, exit_code: u32) -> bool {
        let Some(tid) = self.core.scheduler.current_tid() else {
            return false;
        };
        self.abandon_mutexes_owned_by_thread(tid);
        let terminated = self.core.scheduler.exit_current_thread(exit_code).is_some();
        if terminated && (unicorn_context_active() || !self.objects.started_threads.contains(&tid))
        {
            let _ = self.release_terminated_thread_stack(tid);
        }
        terminated
    }

    pub(in crate::runtime::engine) fn terminate_thread_handle(
        &mut self,
        thread_handle: u64,
        exit_code: u32,
    ) -> bool {
        if self.is_current_thread_handle(thread_handle) {
            return self.terminate_current_thread(exit_code);
        }

        let Some(tid) = self
            .core
            .scheduler
            .thread_tid_for_handle((thread_handle & 0xFFFF_FFFF) as u32)
        else {
            return false;
        };
        self.abandon_mutexes_owned_by_thread(tid);
        let terminated = self
            .core
            .scheduler
            .terminate_thread(tid, exit_code)
            .is_some();
        if terminated {
            let _ = self.finalize_terminated_thread(tid);
        }
        terminated
    }
}
