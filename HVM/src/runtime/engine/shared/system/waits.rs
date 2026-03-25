use super::*;

impl VirtualExecutionEngine {
    pub(in crate::runtime::engine) fn read_wait_handles(
        &self,
        count: usize,
        handles_ptr: u64,
    ) -> Result<Vec<u32>, VmError> {
        (0..count)
            .map(|index| {
                let slot = handles_ptr + index as u64 * self.arch.pointer_size as u64;
                Ok(if self.arch.is_x86() {
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
            if let Some(owner_tid) = self.scheduler.current_tid() {
                let _ = self.acquire_mutex_handle(handles[0], owner_tid);
            }
            return Ok(crate::runtime::scheduler::WAIT_OBJECT_0 as u64);
        }

        if let Some(result) = self.scheduler.consume_wait_result() {
            let finalized = self.finalize_wait_result_object_acquisition(handles, wait_all, result);
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

        let immediate = self
            .scheduler
            .wait_for_multiple_objects(&normalized_handles, wait_all, 0);
        if immediate != WAIT_TIMEOUT as u32
            || timeout_ms == 0
            || self.scheduler.current_tid().is_none()
        {
            let finalized =
                self.finalize_wait_result_object_acquisition(handles, wait_all, immediate);
            return Ok(finalized as u64);
        }

        let tid = self
            .scheduler
            .current_tid()
            .ok_or(VmError::RuntimeInvariant(
                "current thread missing during wait",
            ))?;
        let outcome = self.scheduler.begin_wait_for_multiple_objects(
            tid,
            &normalized_handles,
            wait_all,
            self.time.current().tick_ms,
            timeout_ms,
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
        if let Some(result) = self.scheduler.consume_wait_result() {
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
            if let Some(&canonical) = self.named_mutexes.get(&name) {
                let alias = self.next_object_handle;
                self.next_object_handle = self.next_object_handle.saturating_add(4);
                self.mutex_handles.insert(alias);
                self.mutex_handle_targets.insert(alias, canonical);
                self.set_last_error(ERROR_ALREADY_EXISTS as u32);
                return alias as u64;
            }
        }

        let handle = self.next_object_handle;
        self.next_object_handle = self.next_object_handle.saturating_add(4);
        self.mutex_handles.insert(handle);
        self.mutex_handle_targets.insert(handle, handle);
        let owner_tid = if initial_owner {
            self.scheduler.current_tid()
        } else {
            None
        };
        self.mutex_states.insert(
            handle,
            MutexState {
                owner_tid,
                recursion_count: if owner_tid.is_some() { 1 } else { 0 },
                abandoned: false,
            },
        );
        self.scheduler
            .register_external_object(handle, "mutex", owner_tid.is_none(), false);
        if !name.is_empty() {
            self.named_mutexes.insert(name, handle);
        }
        self.set_last_error(ERROR_SUCCESS as u32);
        handle as u64
    }

    pub(in crate::runtime::engine) fn open_mutex_handle(&mut self, raw_name: &str) -> u64 {
        let name = raw_name.trim().to_ascii_lowercase();
        let Some(&canonical) = self.named_mutexes.get(&name) else {
            self.set_last_error(ERROR_FILE_NOT_FOUND as u32);
            return 0;
        };

        let alias = self.next_object_handle;
        self.next_object_handle = self.next_object_handle.saturating_add(4);
        self.mutex_handles.insert(alias);
        self.mutex_handle_targets.insert(alias, canonical);
        self.set_last_error(ERROR_SUCCESS as u32);
        alias as u64
    }

    pub(in crate::runtime::engine) fn resolve_wait_handle(&self, handle: u32) -> u32 {
        self.mutex_handle_targets
            .get(&handle)
            .copied()
            .unwrap_or(handle)
    }

    pub(in crate::runtime::engine) fn normalize_wait_handles(&self, handles: &[u32]) -> Vec<u32> {
        handles
            .iter()
            .map(|handle| self.resolve_wait_handle(*handle))
            .collect()
    }

    pub(in crate::runtime::engine) fn waitable_object_exists(&self, handle: u32) -> bool {
        self.scheduler
            .object_kind(self.resolve_wait_handle(handle))
            .is_some()
    }

    pub(in crate::runtime::engine) fn mutex_owned_by_current_thread(&self, handle: u32) -> bool {
        let Some(current_tid) = self.scheduler.current_tid() else {
            return false;
        };
        let canonical = self.resolve_wait_handle(handle);
        self.mutex_states
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
        let Some(owner_tid) = self.scheduler.current_tid() else {
            return result;
        };
        if wait_all {
            let mut abandoned = false;
            for handle in handles {
                if let Some(acquired_abandoned) =
                    self.acquire_mutex_handle_with_state(*handle, owner_tid)
                {
                    abandoned |= acquired_abandoned;
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
        let Some(state) = self.mutex_states.get_mut(&canonical) else {
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
        let _ = self.scheduler.clear_object_signal(canonical);
        Some(abandoned)
    }

    pub(in crate::runtime::engine) fn release_mutex_handle(&mut self, handle: u32) -> bool {
        let Some(owner_tid) = self.scheduler.current_tid() else {
            return false;
        };
        let canonical = self.resolve_wait_handle(handle);
        let Some(state) = self.mutex_states.get_mut(&canonical) else {
            return false;
        };
        if state.owner_tid != Some(owner_tid) || state.recursion_count == 0 {
            return false;
        }
        state.recursion_count -= 1;
        if state.recursion_count == 0 {
            state.owner_tid = None;
            state.abandoned = false;
            let _ = self.scheduler.signal_object(canonical);
        }
        true
    }

    pub(in crate::runtime::engine) fn abandon_mutexes_owned_by_thread(&mut self, owner_tid: u32) {
        let owned: Vec<u32> = self
            .mutex_states
            .iter()
            .filter_map(|(handle, state)| {
                (state.owner_tid == Some(owner_tid) && state.recursion_count != 0)
                    .then_some(*handle)
            })
            .collect();
        for handle in owned {
            if let Some(state) = self.mutex_states.get_mut(&handle) {
                state.owner_tid = None;
                state.recursion_count = 0;
                state.abandoned = true;
            }
            let _ = self.scheduler.signal_object(handle);
        }
    }

    pub(in crate::runtime::engine) fn signal_waitable_object(
        &mut self,
        handle: u32,
    ) -> Result<(), u32> {
        let canonical = self.resolve_wait_handle(handle);
        match self.scheduler.object_kind(canonical) {
            Some("event") => {
                let _ = self.scheduler.signal_object(canonical);
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
        let Some(tid) = self.scheduler.current_tid() else {
            return false;
        };
        self.abandon_mutexes_owned_by_thread(tid);
        self.scheduler.exit_current_thread(exit_code).is_some()
    }
}
